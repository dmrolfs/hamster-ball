// ABOUTME: The `hb __guard` watchdog: ends the child and the log stream if hb dies without cleaning up (a SIGKILL).
// ABOUTME: hb holds the write end of a pipe; when it closes without a release, the guard terminates what was registered.
//! Cleaning up after an `hb` that was killed (design D66).
//!
//! `SIGKILL` cannot be handled, so nothing in `hb` itself can end the agent or the `log stream`
//! helper when it arrives. `hb` therefore starts a second process, `hb __guard`, in a session of
//! its own, and keeps the write end of a pipe to it. Each process `hb` starts is registered with
//! the guard. When `hb` finishes normally it sends `release` and the guard exits. If the pipe
//! closes without one, `hb` is gone, and the guard sends what is still running SIGTERM and then,
//! after the grace period, SIGKILL.
//!
//! The guard watches every registered process with a kernel exit notification, so a process that
//! has ended is forgotten at once and its number, which the system may hand to an unrelated
//! program, is never signalled.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
use nix::sys::signal::Signal;
use nix::sys::time::TimeSpec;
use nix::unistd::Pid;
use rustix::process::setsid;
use rustix::termios::{LocalModes, Termios, tcgetattr};
use snafu::{OptionExt, ResultExt, Snafu};

use super::signals::{SignalError, Target, clear_mask};

/// How long the guard lets processes end after SIGTERM before it sends SIGKILL.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(2);

/// How many processes the guard will watch: the agent, the log stream and the broker's running commands.
const MAX_WATCHED: usize = 16;
/// The longest command line the guard accepts.
const MAX_LINE: usize = 160;
/// How many sockets the guard will remember (`hb` registers one).
const MAX_SOCKETS: usize = 2;
/// How long `release` waits for the guard to exit before it stops waiting.
const RELEASE_WAIT: Duration = Duration::from_secs(2);

/// Why the guard could not be started or told something, on `hb`'s side.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum GuardianError {
    /// The guard process could not be started.
    #[snafu(display("the cleanup guard could not be started"))]
    Spawn {
        /// The underlying error.
        source: io::Error,
    },

    /// The guard rejected a required kernel watch.
    #[snafu(display("the cleanup guard refused process protection"))]
    Refused,

    /// The guard could not be told about a process, so it would not be cleaned up.
    #[snafu(display("the cleanup guard could not be told about a process"))]
    Tell {
        /// The underlying error.
        source: io::Error,
    },
}

/// Why the guard process itself failed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum GuardError {
    /// The signal mask could not be cleared.
    #[snafu(display("the guard's signal mask could not be cleared"))]
    Mask {
        /// The underlying error.
        source: SignalError,
    },

    /// The kernel event queue could not be used.
    #[snafu(display("the guard's kernel event queue failed"))]
    Queue {
        /// The underlying error.
        source: Errno,
    },

    /// The command pipe could not be read.
    #[snafu(display("the guard could not read its commands"))]
    Read {
        /// The underlying error.
        source: io::Error,
    },
}

/// One line the guard understands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum GuardCommand {
    /// Clean up this target if `hb` dies.
    Watch(Target),
    /// Register a live launch target and acknowledge kernel acceptance.
    Protect(Target),
    /// `hb` finished normally: exit and touch nothing.
    Release,
    /// The user's terminal, which `hb` is about to put in raw mode.
    Terminal(PathBuf),
    /// The `hb ctl` socket: remove it if `hb` dies, since a killed `hb` cannot.
    Socket(PathBuf),
}

/// Why a line sent to the guard was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
pub(super) enum LineError {
    /// The line was not `watch group <pid>`, `watch process <pid>` or `release`.
    #[snafu(display("not a guard command"))]
    Unknown,
    /// The number was not a process number the guard may signal.
    #[snafu(display("not a process number the guard may signal"))]
    BadPid,
}

/// The lowest process number the guard will signal. 0 is the guard's own group, 1 is `init`, and
/// a negative number names a group or every process the guard may signal.
const FIRST_SIGNALLABLE_PID: i32 = 2;

pub(super) fn parse_line(line: &str) -> Result<GuardCommand, LineError> {
    let words: Vec<&str> = line.split_whitespace().collect();
    match words.as_slice() {
        ["release"] => Ok(GuardCommand::Release),
        ["tty", path] => terminal_device(path).map(GuardCommand::Terminal),
        ["socket", path] => ctl_socket(path).map(GuardCommand::Socket),
        [
            verb @ ("watch" | "protect"),
            kind @ ("group" | "process"),
            pid,
        ] => {
            let pid: i32 = pid.parse().ok().context(BadPidSnafu)?;
            if pid < FIRST_SIGNALLABLE_PID {
                return BadPidSnafu.fail();
            }
            let pid = Pid::from_raw(pid);
            let target = if *kind == "group" {
                Target::Group(pid)
            } else {
                Target::Child(pid)
            };
            Ok(if *verb == "protect" {
                GuardCommand::Protect(target)
            } else {
                GuardCommand::Watch(target)
            })
        }
        _ => UnknownSnafu.fail(),
    }
}

/// A path the guard will write to: a terminal device and nothing else.
fn terminal_device(path: &str) -> Result<PathBuf, LineError> {
    let path = Path::new(path);
    let name = path.strip_prefix("/dev/").map_err(|_| LineError::Unknown)?;
    let plain = name.components().count() == 1
        && name.to_string_lossy().starts_with("tty")
        && !name.to_string_lossy().contains("..");
    if plain {
        Ok(path.to_path_buf())
    } else {
        UnknownSnafu.fail()
    }
}

/// A path the guard will unlink: an absolute path whose last name is `ctl.sock`, and nothing else.
fn ctl_socket(path: &str) -> Result<PathBuf, LineError> {
    let path = Path::new(path);
    let plain = path.is_absolute()
        && path.file_name().is_some_and(|n| n == CTL_SOCKET_NAME)
        && !path
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir));
    if plain {
        Ok(path.to_path_buf())
    } else {
        UnknownSnafu.fail()
    }
}

/// The only file name the guard will remove.
pub const CTL_SOCKET_NAME: &str = "ctl.sock";

/// Removes `path` if it is still a unix socket. Anything else at that name is left alone.
fn remove_socket(path: &Path) {
    use std::os::unix::fs::FileTypeExt;
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket()) {
        let _ = std::fs::remove_file(path);
    }
}

/// The text `hb` sends to register `target`.
fn watch_line(target: Target) -> String {
    match target {
        Target::Group(pid) => format!("watch group {pid}\n"),
        Target::Child(pid) => format!("watch process {pid}\n"),
    }
}

// ====================================================================================
// The terminal
// ====================================================================================

/// What the guard says when `hb` was killed while it held the user's terminal in raw mode.
///
/// It cannot put the terminal back: zsh reads the settings when it reaps a job and applies them
/// to every later command, so any repair from outside is undone (measured; the same is true of
/// every raw-mode program). It can say what happened and what to type.
const HINT: &[u8] =
    b"\r\n[hb was killed while it held your terminal in raw mode. If the terminal misbehaves, type: reset]\r\n";

/// Whether `settings` are what `hb`'s raw mode leaves: signal keys off. A shell that has already
/// switched line editing back on (zsh does) still shows it.
fn looks_raw(settings: &Termios) -> bool {
    !settings.local_modes.contains(LocalModes::ISIG)
}

/// The user's terminal, opened so the guard can tell whether a killed `hb` left it raw.
struct TerminalWatch {
    terminal: File,
}

impl TerminalWatch {
    /// Opens the terminal at `path` without making it the guard's controlling terminal.
    fn open(path: &Path) -> Option<Self> {
        let terminal = File::options()
            .read(true)
            .write(true)
            .custom_flags(nix::libc::O_NOCTTY | nix::libc::O_NONBLOCK)
            .open(path)
            .ok()?;
        tcgetattr(&terminal).ok()?;
        Some(Self::from_file(terminal))
    }

    fn from_file(terminal: File) -> Self {
        Self { terminal }
    }

    /// Writes the hint if the terminal is raw. Returns whether it did.
    fn hint_if_raw(&self) -> bool {
        let raw = tcgetattr(&self.terminal).is_ok_and(|settings| looks_raw(&settings));
        if raw {
            let mut terminal = &self.terminal;
            let _ = terminal.write_all(HINT);
        }
        raw
    }
}

/// How long the guard waits after `hb` has gone before it looks at the terminal, so a shell that
/// puts the terminal back itself (bash does) has done so and no hint is printed for nothing.
const HINT_DELAY: Duration = Duration::from_millis(300);

// ====================================================================================
// hb's side
// ====================================================================================

/// The guard process, seen from `hb`.
///
/// Dropping it without [`Guardian::release`] closes the pipe, which tells the guard `hb` is gone.
#[derive(Debug)]
pub struct Guardian {
    process: Child,
    commands: Arc<Mutex<UnixStream>>,
}

/// A clone of the guard's command pipe, so other threads (the `hb ctl` broker's runner) can
/// register the process groups they start. It does not keep the guard alive: `release` ends it.
#[derive(Debug, Clone)]
pub struct GuardHandle {
    commands: Arc<Mutex<UnixStream>>,
}

fn tell(commands: &Mutex<UnixStream>, text: &str) -> Result<(), GuardianError> {
    let mut pipe = commands.lock().map_err(|_| GuardianError::Tell {
        source: io::Error::other("the guard's command pipe is poisoned"),
    })?;
    pipe.write_all(text.as_bytes())
        .and_then(|()| pipe.flush())
        .context(TellSnafu)
}

fn protect(commands: &Mutex<UnixStream>, target: Target) -> Result<(), GuardianError> {
    let mut pipe = commands.lock().map_err(|_| GuardianError::Tell {
        source: io::Error::other("the guard's command pipe is poisoned"),
    })?;
    let result = (|| {
        let text = watch_line(target).replacen("watch", "protect", 1);
        pipe.write_all(text.as_bytes()).context(TellSnafu)?;
        let mut reply = [0];
        pipe.read_exact(&mut reply).context(TellSnafu)?;
        if reply != [1] {
            return RefusedSnafu.fail();
        }
        Ok(())
    })();
    if result.is_err() {
        // A late reply must never authorize a later target after a timed-out transaction.
        let _ = pipe.shutdown(std::net::Shutdown::Both);
    }
    result
}

impl GuardHandle {
    /// Asks the guard to end `target` if `hb` dies before the guard is released.
    ///
    /// # Errors
    /// [`GuardianError::Tell`] if the guard cannot be written to.
    pub fn watch(&self, target: Target) -> Result<(), GuardianError> {
        tell(&self.commands, &watch_line(target))
    }
}

impl Guardian {
    /// Starts `hb_exe __guard`.
    ///
    /// # Errors
    /// [`GuardianError::Spawn`] if it cannot be started.
    pub fn start(hb_exe: &Path) -> Result<Self, GuardianError> {
        Self::start_with(hb_exe, DEFAULT_GRACE)
    }

    /// Like [`Guardian::start`] with a chosen grace period.
    ///
    /// # Errors
    /// [`GuardianError::Spawn`] if it cannot be started.
    pub fn start_with(hb_exe: &Path, grace: Duration) -> Result<Self, GuardianError> {
        let mut command = Command::new(hb_exe);
        command
            .arg("__guard")
            .arg("--grace-ms")
            .arg(grace.as_millis().to_string());
        let (commands, remote) = UnixStream::pair().context(SpawnSnafu)?;
        commands
            .set_read_timeout(Some(RELEASE_WAIT))
            .context(SpawnSnafu)?;
        commands
            .set_write_timeout(Some(RELEASE_WAIT))
            .context(SpawnSnafu)?;
        let output = remote.try_clone().context(SpawnSnafu)?;
        let process = command
            .env_clear()
            .stdin(Stdio::from(OwnedFd::from(remote)))
            .stdout(Stdio::from(OwnedFd::from(output)))
            .stderr(Stdio::null())
            .spawn()
            .context(SpawnSnafu)?;
        Ok(Self {
            process,
            commands: Arc::new(Mutex::new(commands)),
        })
    }

    /// The guard's process number.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.process.id()
    }

    /// Tells the guard which terminal `hb` is about to put in raw mode, so that if `hb` is killed
    /// it can say so.
    ///
    /// # Errors
    /// [`GuardianError::Tell`] if the guard cannot be written to.
    pub fn terminal(&mut self, path: &Path) -> Result<(), GuardianError> {
        tell(
            &self.commands,
            &format!(
                "tty {}
",
                path.display()
            ),
        )
    }

    /// Asks the guard to remove the `hb ctl` socket at `path` if `hb` dies before [`Guardian::release`].
    ///
    /// # Errors
    /// [`GuardianError::Tell`] if the guard cannot be written to.
    pub fn socket(&mut self, path: &Path) -> Result<(), GuardianError> {
        tell(
            &self.commands,
            &format!(
                "socket {}
",
                path.display()
            ),
        )
    }

    /// A handle other threads can use to register what they start.
    #[must_use]
    pub fn handle(&self) -> GuardHandle {
        GuardHandle {
            commands: self.commands.clone(),
        }
    }

    /// Asks the guard to end `target` if `hb` dies before [`Guardian::release`].
    ///
    /// # Errors
    /// [`GuardianError::Tell`] if the guard cannot be written to.
    pub fn watch(&mut self, target: Target) -> Result<(), GuardianError> {
        tell(&self.commands, &watch_line(target))
    }

    /// Requires a kernel watch before the waiting launch helper may execute its agent.
    ///
    /// # Errors
    /// A timeout, broken channel, or rejected watch prevents launch authorization.
    pub fn protect(&mut self, target: Target) -> Result<(), GuardianError> {
        protect(&self.commands, target)
    }

    /// Tells the guard `hb` has cleaned up and waits (briefly) for it to exit.
    pub fn release(mut self) {
        let _ = tell(&self.commands, "release\n");
        drop(self.commands);
        let deadline = Instant::now() + RELEASE_WAIT;
        while Instant::now() < deadline {
            match self.process.try_wait() {
                Ok(Some(_)) | Err(_) => return,
                Ok(None) => thread::sleep(Duration::from_millis(5)),
            }
        }
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

// ====================================================================================
// The guard process
// ====================================================================================

/// What the guard does with a read event or a process ending.
#[derive(Debug, PartialEq, Eq)]
enum Next {
    Keep,
    Release,
}

/// Runs the guard until `hb` releases it or has gone and its processes are dealt with.
///
/// Reads commands from standard input.
///
/// # Errors
/// [`GuardError`] if it cannot set itself up. It never returns an error after it has started
/// ending processes.
pub fn run_guard(grace: Duration) -> Result<(), GuardError> {
    let (ended, terminal) = guard_loop(grace)?;
    if ended == Ended::HbGone
        && let Some(terminal) = terminal
    {
        // Give a shell that puts the terminal back itself time to do it.
        thread::sleep(HINT_DELAY);
        terminal.hint_if_raw();
    }
    Ok(())
}

/// How the guard's loop ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ended {
    /// `hb` sent `release`.
    Released,
    /// `hb` is gone without one, and what it left running has been dealt with.
    HbGone,
}

/// The guard's loop: reads orders, watches processes, and ends them if `hb` goes away.
fn guard_loop(grace: Duration) -> Result<(Ended, Option<TerminalWatch>), GuardError> {
    clear_mask().context(MaskSnafu)?;
    // A session of its own: no terminal signal (Ctrl-C, hangup) reaches the guard. It is
    // already a leader when started by hand, which is fine.
    let _ = setsid();
    let queue = Kqueue::new().context(QueueSnafu)?;
    let stdin = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context(ReadSnafu)?;
    let mut commands = File::from(stdin);
    let read_event = KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD,
        FilterFlag::empty(),
        0,
        0,
    );
    queue
        .kevent(&[read_event], &mut [], Some(zero()))
        .context(QueueSnafu)?;

    let mut watched: HashMap<i32, Target> = HashMap::new();
    let mut terminal: Option<TerminalWatch> = None;
    let mut sockets: Vec<PathBuf> = Vec::new();
    let mut buffered: Vec<u8> = Vec::new();
    let mut pipe_open = true;
    let mut terminating: Option<Instant> = None;
    let blank = KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    );
    let mut events = [blank; 8];
    loop {
        if !pipe_open && terminating.is_none() {
            // `hb` is gone and did not release: end what is left.
            for socket in &sockets {
                remove_socket(socket);
            }
            if watched.is_empty() {
                return Ok((Ended::HbGone, terminal));
            }
            send_all(&watched, Signal::SIGTERM);
            terminating = Some(Instant::now() + grace);
        }
        if terminating.is_some() && watched.is_empty() {
            return Ok((Ended::HbGone, terminal));
        }
        let timeout = terminating.map(|deadline| {
            TimeSpec::from_duration(deadline.saturating_duration_since(Instant::now()))
        });
        let ready = match queue.kevent(&[], &mut events, timeout.as_ref().map(|t| *t.as_ref())) {
            Ok(n) => n,
            Err(Errno::EINTR) => continue,
            Err(source) => return Err(GuardError::Queue { source }),
        };
        if ready == 0 {
            if terminating.is_some_and(|deadline| Instant::now() >= deadline) {
                send_all(&watched, Signal::SIGKILL);
                return Ok((Ended::HbGone, terminal));
            }
            continue;
        }
        for event in &events[..ready] {
            match event.filter() {
                Ok(EventFilter::EVFILT_READ) if pipe_open => {
                    let (next, open) = read_commands(
                        &mut commands,
                        &mut buffered,
                        &mut watched,
                        &mut terminal,
                        &mut sockets,
                        &queue,
                    )?;
                    pipe_open = open;
                    if !open {
                        // End of input stays readable; stop being told about it.
                        let done = KEvent::new(
                            0,
                            EventFilter::EVFILT_READ,
                            EvFlags::EV_DELETE,
                            FilterFlag::empty(),
                            0,
                            0,
                        );
                        let _ = queue.kevent(&[done], &mut [], Some(zero()));
                    }
                    if next == Next::Release {
                        return Ok((Ended::Released, None));
                    }
                }
                Ok(EventFilter::EVFILT_PROC) => {
                    // The process has ended; its number may be reused from now on.
                    watched.remove(&i32::try_from(event.ident()).unwrap_or(0));
                }
                _ => {}
            }
        }
    }
}

fn zero() -> nix::libc::timespec {
    *TimeSpec::from_duration(Duration::ZERO).as_ref()
}

fn send_all(watched: &HashMap<i32, Target>, signal: Signal) {
    for target in watched.values() {
        target.send(signal);
    }
}

/// Reads what is available, runs the complete lines, and reports whether to stop and whether the
/// pipe is still open.
fn read_commands(
    commands: &mut File,
    buffered: &mut Vec<u8>,
    watched: &mut HashMap<i32, Target>,
    terminal: &mut Option<TerminalWatch>,
    sockets: &mut Vec<PathBuf>,
    queue: &Kqueue,
) -> Result<(Next, bool), GuardError> {
    let mut chunk = [0u8; 256];
    let n = match commands.read(&mut chunk) {
        Ok(n) => n,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok((Next::Keep, true)),
        // A socket peer can reset when it dies with an unread acknowledgement.
        Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {
            return Ok((Next::Keep, false));
        }
        Err(source) => return Err(GuardError::Read { source }),
    };
    buffered.extend_from_slice(&chunk[..n]);
    while let Some(end) = buffered.iter().position(|b| *b == b'\n') {
        let line: Vec<u8> = buffered.drain(..=end).collect();
        let text = String::from_utf8_lossy(&line[..line.len() - 1]);
        if line.len() > MAX_LINE {
            continue;
        }
        match parse_line(&text) {
            Ok(GuardCommand::Release) => return Ok((Next::Release, true)),
            Ok(GuardCommand::Watch(target)) => {
                let _ = watch(target, watched, queue);
            }
            Ok(GuardCommand::Protect(target)) => {
                let accepted = watch(target, watched, queue);
                // A broken reply channel means parent loss, not permission to abandon targets.
                if io::stdout()
                    .write_all(&[u8::from(accepted)])
                    .and_then(|()| io::stdout().flush())
                    .is_err()
                {
                    return Ok((Next::Keep, false));
                }
            }
            Ok(GuardCommand::Terminal(path)) => *terminal = TerminalWatch::open(&path),
            Ok(GuardCommand::Socket(path)) if sockets.len() < MAX_SOCKETS => sockets.push(path),
            Ok(GuardCommand::Socket(_)) => {}
            // A line the guard does not understand protects nothing; the next one may.
            Err(_) => {}
        }
    }
    if buffered.len() > MAX_LINE {
        buffered.clear();
    }
    Ok((Next::Keep, n != 0))
}

/// Starts watching `target`, unless it has already ended or there are too many.
fn watch(target: Target, watched: &mut HashMap<i32, Target>, queue: &Kqueue) -> bool {
    let pid = match target {
        Target::Group(pid) | Target::Child(pid) => pid,
    };
    if watched.len() >= MAX_WATCHED {
        return false;
    }
    let exit = KEvent::new(
        pid.as_raw() as usize,
        EventFilter::EVFILT_PROC,
        EvFlags::EV_ADD | EvFlags::EV_ONESHOT,
        FilterFlag::NOTE_EXIT,
        0,
        0,
    );
    // ESRCH: it ended before it could be watched, so there is nothing to clean up.
    if queue.kevent(&[exit], &mut [], Some(zero())).is_ok() {
        watched.insert(pid.as_raw(), target);
        true
    } else {
        false
    }
}

#[cfg(test)]
mod transaction_tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use std::io::{BufRead, BufReader};
    use std::sync::mpsc;

    #[test]
    fn protection_waits_for_reply_and_serializes_other_writers() {
        let (local, remote) = assert_ok!(UnixStream::pair());
        assert_ok!(local.set_read_timeout(Some(Duration::from_secs(2))));
        let commands = Arc::new(Mutex::new(local));
        let tx_commands = Arc::clone(&commands);
        let (done, result) = mpsc::channel();
        let protect_thread = thread::spawn(move || {
            let _ = done.send(protect(&tx_commands, Target::Child(Pid::from_raw(4242))));
        });
        let mut reader = BufReader::new(remote);
        assert_ok!(
            reader
                .get_ref()
                .set_read_timeout(Some(Duration::from_millis(100)))
        );
        let mut line = String::new();
        assert_ok!(reader.read_line(&mut line));
        assert_eq!(line, "protect process 4242\n");
        assert!(
            result.try_recv().is_err(),
            "protection returned without a reply"
        );
        let handle = GuardHandle { commands };
        let writer = thread::spawn(move || handle.watch(Target::Child(Pid::from_raw(4243))));
        line.clear();
        assert_err!(reader.read_line(&mut line));
        assert_ok!(reader.get_mut().write_all(&[1]));
        assert_ok!(assert_ok!(result.recv_timeout(Duration::from_secs(2))));
        assert_ok!(reader.read_line(&mut line));
        assert_eq!(line, "watch process 4243\n");
        assert_ok!(protect_thread.join());
        assert_ok!(assert_ok!(writer.join()));
    }

    #[test]
    fn a_full_guardian_refuses_protection_instead_of_acknowledging_it() {
        let queue = assert_ok!(Kqueue::new());
        let mut watched = HashMap::new();
        for pid in 2..(2 + MAX_WATCHED as i32) {
            watched.insert(pid, Target::Child(Pid::from_raw(pid)));
        }
        assert!(!watch(Target::Child(Pid::this()), &mut watched, &queue));
        assert_eq!(watched.len(), MAX_WATCHED);
    }

    #[test]
    fn timeout_or_refusal_prevents_reusing_a_late_reply() {
        for response in [None, Some(0), Some(2)] {
            let (local, mut remote) = assert_ok!(UnixStream::pair());
            assert_ok!(local.set_read_timeout(Some(Duration::from_millis(50))));
            let commands = Mutex::new(local);
            if let Some(byte) = response {
                assert_ok!(remote.write_all(&[byte]));
            }
            assert_err!(protect(&commands, Target::Child(Pid::from_raw(4242))));
            let _ = remote.write_all(&[1]);
            assert_err!(protect(&commands, Target::Child(Pid::from_raw(4243))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    #[test]
    fn a_watch_line_names_a_group_or_a_single_process() {
        assert_eq!(
            assert_ok!(parse_line("watch group 4242")),
            GuardCommand::Watch(Target::Group(Pid::from_raw(4242)))
        );
        assert_eq!(
            assert_ok!(parse_line("watch process 77")),
            GuardCommand::Watch(Target::Child(Pid::from_raw(77)))
        );
    }

    #[test]
    fn a_socket_line_names_an_absolute_ctl_sock_and_nothing_else() {
        assert_eq!(
            assert_ok!(parse_line("socket /var/folders/x/T/hb-1-2-3/ctl.sock")),
            GuardCommand::Socket(PathBuf::from("/var/folders/x/T/hb-1-2-3/ctl.sock"))
        );
        for bad in [
            "socket",
            "socket ctl.sock",
            "socket /etc/passwd",
            "socket /a/other.sock",
            "socket /a/../etc/ctl.sock",
            "socket /a/ctl.sock/x",
        ] {
            assert_err!(parse_line(bad), "{bad}");
        }
    }

    #[test]
    fn only_a_unix_socket_is_removed_not_a_file_or_a_directory_or_a_link_target() {
        use std::os::unix::net::UnixListener;
        let dir = assert_ok!(tempfile::Builder::new().prefix("hb-g").tempdir_in("/tmp"));
        let sock = dir.path().join("ctl.sock");
        let _listener = assert_ok!(UnixListener::bind(&sock));
        remove_socket(&sock);
        assert!(!sock.exists());
        assert_ok!(std::fs::write(&sock, "not a socket"));
        remove_socket(&sock);
        assert!(sock.exists(), "a regular file must be left alone");
        assert_ok!(std::fs::remove_file(&sock));
        let target = dir.path().join("target.sock");
        let _t = assert_ok!(UnixListener::bind(&target));
        assert_ok!(std::os::unix::fs::symlink(&target, &sock));
        remove_socket(&sock);
        assert!(
            target.exists(),
            "a link must not make the guard remove its target"
        );
        assert_ok!(std::fs::remove_file(&sock));
        assert_ok!(std::fs::create_dir(&sock));
        remove_socket(&sock);
        assert!(sock.is_dir());
    }

    #[test]
    fn release_is_a_command_of_its_own() {
        assert_eq!(assert_ok!(parse_line("release")), GuardCommand::Release);
    }

    #[test]
    fn the_lines_hb_writes_are_the_lines_the_guard_reads() {
        for target in [
            Target::Group(Pid::from_raw(12345)),
            Target::Child(Pid::from_raw(2)),
        ] {
            assert_eq!(
                assert_ok!(parse_line(&watch_line(target))),
                GuardCommand::Watch(target)
            );
        }
    }

    #[test]
    fn numbers_that_could_mean_more_than_one_process_are_refused() {
        for pid in ["0", "1", "-1", "-4242", "abc", "99999999999"] {
            for kind in ["group", "process"] {
                assert_eq!(
                    assert_err!(parse_line(&format!("watch {kind} {pid}"))),
                    LineError::BadPid,
                    "watch {kind} {pid}"
                );
            }
        }
    }

    #[test]
    fn anything_else_is_not_a_command() {
        for line in [
            "",
            "watch",
            "watch group",
            "watch thread 5",
            "kill 5",
            "release now",
            "watch group 5 6",
        ] {
            assert_eq!(
                assert_err!(parse_line(line)),
                LineError::Unknown,
                "{line:?}"
            );
        }
    }

    fn a_terminal() -> (crate::session::pty::Pty, File) {
        let pty = assert_ok!(crate::session::pty::Pty::open());
        let slave = assert_ok!(
            File::options()
                .read(true)
                .write(true)
                .open(pty.slave_path().as_str())
        );
        (pty, slave)
    }

    #[test]
    fn a_tty_line_names_a_terminal_device_and_nothing_else() {
        assert_eq!(
            assert_ok!(parse_line("tty /dev/ttys004")),
            GuardCommand::Terminal(std::path::PathBuf::from("/dev/ttys004"))
        );
        for bad in [
            "tty",
            "tty /etc/passwd",
            "tty /dev/null",
            "tty /dev/../etc/passwd",
            "tty /dev/ttys004 /dev/ttys005",
            "tty relative/tty",
        ] {
            assert!(parse_line(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn a_terminal_is_raw_when_signal_keys_are_off_and_cooked_when_they_are_on() {
        let (_pty, slave) = a_terminal();
        let cooked = assert_ok!(tcgetattr(&slave));
        assert!(!looks_raw(&cooked));
        let mut raw = cooked.clone();
        raw.make_raw();
        assert!(looks_raw(&raw));
        // What zsh leaves after adopting hb's settings: line editing back on, signal keys still off.
        let mut hybrid = raw.clone();
        hybrid
            .local_modes
            .insert(LocalModes::ICANON | LocalModes::ECHO);
        assert!(looks_raw(&hybrid));
    }

    #[test]
    fn the_hint_is_written_to_a_raw_terminal_and_not_to_a_cooked_one() {
        let (pty, slave) = a_terminal();
        let mut screen = assert_ok!(pty.clone_master());
        let watch = TerminalWatch::from_file(assert_ok!(slave.try_clone()));
        assert!(!watch.hint_if_raw(), "a cooked terminal got a hint");
        let mut raw = assert_ok!(tcgetattr(&slave));
        raw.make_raw();
        assert_ok!(tcsetattr(&slave, OptionalActions::Now, &raw));
        assert!(watch.hint_if_raw());
        let mut seen = vec![0u8; 512];
        let n = assert_ok!(std::io::Read::read(&mut screen, &mut seen));
        let text = String::from_utf8_lossy(&seen[..n]).into_owned();
        assert!(text.contains("hb was killed"), "{text:?}");
        assert!(text.contains("reset"), "{text:?}");
        assert!(text.starts_with("\r\n"), "{text:?}");
    }

    #[test]
    fn line_errors_follow_the_display_convention() {
        for error in [LineError::Unknown, LineError::BadPid] {
            crate::error::conventions::assert_display_excludes_sources(&error);
        }
    }
}
