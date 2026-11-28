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
//! The guard retains process identities and rechecks them before signalling.
//! This avoids signalling a known replacement, but the final check and signal are separate
//! syscalls. Cleanup is best effort and never establishes that no descendants remain.

use super::launch_end::{EndPhase, EndStatus, Launches};
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
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

use super::guard_channel::Channel;
use super::identity::{Identity, IdentityError};
use super::signals::{SignalError, Target, clear_mask};
use super::sweep::{LaunchToken, holders_of, holds_entry, listing, owned_by_token};
use super::tracker::{Tracker, TrackerError};

/// How long the guard lets processes end after SIGTERM before it sends SIGKILL.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(2);

/// How many processes the guard will watch: the agent, the log stream and the broker's running commands.
const MAX_WATCHED: usize = 16;
/// Slots kept for the agent and log stream so broker commands cannot exhaust them.
const RESERVED_CORE: usize = 2;
/// The longest command line the guard accepts.
const MAX_LINE: usize = super::guard_channel::MAX_FRAME;
/// How many sockets the guard will remember (`hb` registers one).
const MAX_SOCKETS: usize = 2;
/// How long `release` waits for the guard to exit before it stops waiting.
const RELEASE_WAIT: Duration = Duration::from_secs(2);

/// Why the guard could not be started or told something, on `hb`'s side.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum GuardianError {
    /// Child cleanup ownership could not be reserved.
    #[snafu(display("the guardian has no cleanup owner"))]
    Custody {
        /// Why reservation failed.
        source: super::CustodyError,
    },
    /// The guard process could not be started.
    #[snafu(display("the cleanup guard could not be started"))]
    Spawn {
        /// The underlying error.
        source: io::Error,
    },

    /// The guard could not be told about a process, so it would not be cleaned up.
    #[snafu(display("the cleanup guard could not be told about a process"))]
    Tell {
        /// The underlying error.
        source: io::Error,
    },

    /// The command channel was busy past the transaction deadline.
    #[snafu(display("the cleanup guard did not accept the command in time"))]
    Deadline,

    /// The command is too long to send; nothing was sent.
    #[snafu(display("the cleanup guard command is too long"))]
    TooLong,

    /// The guard sent an unexpected reply; its channel has been shut down.
    #[snafu(display("the cleanup guard sent an invalid reply"))]
    Protocol,

    /// The guard refused to watch a process.
    #[snafu(display("the cleanup guard refused to watch the process: {reason}"))]
    Refused {
        /// Why it refused.
        reason: WatchRefusal,
    },
}

/// Why the guard refused a watch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum WatchRefusal {
    /// The request was malformed.
    Invalid,
    /// No slot was available.
    Capacity,
    /// The kernel would not install the exit watch.
    Kernel,
}

/// A kernel exit watch was armed, or the target was already gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum WatchOutcome {
    /// The guard will clean up the target.
    Armed,
    /// The process did not exist; nothing is protected.
    Gone,
}

/// Which capacity pool a watch uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub(super) enum WatchRole {
    Core,
    Broker,
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
    /// An acknowledged watch request.
    AckWatch {
        id: u64,
        role: WatchRole,
        target: Target,
    },
    AckLaunch {
        id: u64,
        pid: i32,
    },
    AckEnd {
        id: u64,
        ticket: u64,
        phase: EndPhase,
    },
    /// An acknowledged release.
    AckRelease(u64),
    /// An acknowledged terminal registration.
    AckTerminal(u64, PathBuf),
    /// An acknowledged socket registration.
    AckSocket(u64, PathBuf),
    /// An acknowledged launch token: what the teardown sweep looks for in processes' environments.
    AckToken(u64, String),
    /// An acknowledged session directory: where the teardown sweep looks for processes still using it.
    AckSessionDir(u64, PathBuf),
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
        ["ack", id, "launch", pid] => {
            let Target::Group(pid) = parse_target("group", pid)? else {
                return UnknownSnafu.fail();
            };
            Ok(GuardCommand::AckLaunch {
                id: id.parse().map_err(|_| LineError::Unknown)?,
                pid: pid.as_raw(),
            })
        }
        ["ack", id, "end", ticket, phase] => Ok(GuardCommand::AckEnd {
            id: id.parse().map_err(|_| LineError::Unknown)?,
            ticket: ticket.parse().map_err(|_| LineError::Unknown)?,
            phase: phase.parse().map_err(|_| LineError::Unknown)?,
        }),
        ["ack", id, "watch", role, kind @ ("group" | "process"), pid] => {
            let id = id.parse().map_err(|_| LineError::Unknown)?;
            let role = role.parse().map_err(|_| LineError::Unknown)?;
            let target = parse_target(kind, pid)?;
            Ok(GuardCommand::AckWatch { id, role, target })
        }
        ["ack", id, "release"] => Ok(GuardCommand::AckRelease(
            id.parse().map_err(|_| LineError::Unknown)?,
        )),
        ["ack", id, "tty", path] => Ok(GuardCommand::AckTerminal(
            id.parse().map_err(|_| LineError::Unknown)?,
            terminal_device(path)?,
        )),
        ["ack", id, "socket", path] => Ok(GuardCommand::AckSocket(
            id.parse().map_err(|_| LineError::Unknown)?,
            ctl_socket(path)?,
        )),
        ["ack", id, "token", value] => {
            LaunchToken::parse(value).ok_or(LineError::Unknown)?;
            Ok(GuardCommand::AckToken(
                id.parse().map_err(|_| LineError::Unknown)?,
                (*value).to_owned(),
            ))
        }
        ["ack", id, "sessiondir", path] => Ok(GuardCommand::AckSessionDir(
            id.parse().map_err(|_| LineError::Unknown)?,
            session_dir(path)?,
        )),
        ["release"] => Ok(GuardCommand::Release),
        ["tty", path] => terminal_device(path).map(GuardCommand::Terminal),
        ["socket", path] => ctl_socket(path).map(GuardCommand::Socket),
        ["watch", kind @ ("group" | "process"), pid] => {
            parse_target(kind, pid).map(GuardCommand::Watch)
        }
        _ => UnknownSnafu.fail(),
    }
}

fn parse_target(kind: &str, pid: &str) -> Result<Target, LineError> {
    let pid: i32 = pid.parse().ok().context(BadPidSnafu)?;
    if pid < FIRST_SIGNALLABLE_PID {
        return BadPidSnafu.fail();
    }
    let pid = Pid::from_raw(pid);
    Ok(if kind == "group" {
        Target::Group(pid)
    } else {
        Target::Child(pid)
    })
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

/// A directory the guard will only look in: absolute, no `..`, and not the root of anything big.
fn session_dir(path: &str) -> Result<PathBuf, LineError> {
    let path = Path::new(path);
    let plain = path.is_absolute()
        && path.components().count() >= 3
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

fn target_words(target: Target) -> String {
    match target {
        Target::Group(pid) => format!("group {pid}"),
        Target::Child(pid) => format!("process {pid}"),
    }
}

fn watch_outcome(reply: &str) -> Result<WatchOutcome, GuardianError> {
    match reply {
        "armed" => Ok(WatchOutcome::Armed),
        "gone" => Ok(WatchOutcome::Gone),
        other => {
            let reason = other
                .strip_prefix("refused ")
                .and_then(|r| r.parse().ok())
                .ok_or(GuardianError::Protocol)?;
            Err(GuardianError::Refused { reason })
        }
    }
}

fn expect_ok(reply: &str) -> Result<(), GuardianError> {
    (reply == "ok").then_some(()).ok_or(GuardianError::Protocol)
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
/// Dropping it without [`Guardian::release`] shuts down the private socket, which tells the guard
/// `hb` is gone even when broker handles still exist.
#[derive(Debug)]
pub struct Guardian {
    process: super::custody::Lease,
    channel: Arc<Channel>,
}

/// A clone of the guard's command channel, so other threads (the `hb ctl` broker's runner) can
/// register the process groups they start. It does not keep the guard alive.
#[derive(Debug, Clone)]
pub struct GuardHandle {
    channel: Arc<Channel>,
}

/// A launch ticket belongs to the channel that acknowledged it, not to a reusable PID.
#[derive(Debug)]
pub(crate) struct LaunchHandle {
    channel: Arc<Channel>,
    ticket: u64,
}

impl LaunchHandle {
    pub(crate) fn end(&self, phase: EndPhase, by: Instant) -> Result<EndStatus, GuardianError> {
        let reply = self
            .channel
            .request_until(&format!("end {} {phase}", self.ticket), by)?;
        reply.parse().map_err(|_| GuardianError::Protocol)
    }
}

impl GuardHandle {
    pub(crate) fn launch(&self, pid: i32) -> Result<LaunchHandle, GuardianError> {
        let reply = self.channel.request(&format!("launch {pid}"))?;
        if reply == "gone" {
            return Err(GuardianError::Refused {
                reason: WatchRefusal::Invalid,
            });
        }
        if reply.starts_with("refused ") {
            let _ = watch_outcome(&reply)?;
        }
        let ticket = reply
            .strip_prefix("armed ")
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|ticket| *ticket != 0)
            .ok_or(GuardianError::Protocol)?;
        Ok(LaunchHandle {
            channel: self.channel.clone(),
            ticket,
        })
    }

    /// Asks the guard to end `target` if `hb` dies before the guard is released.
    ///
    /// # Errors
    /// [`GuardianError`] when the guard did not arm or report the target gone.
    pub fn watch(&self, target: Target) -> Result<WatchOutcome, GuardianError> {
        watch_with(&self.channel, WatchRole::Broker, target)
    }
}

fn watch_with(
    channel: &Channel,
    role: WatchRole,
    target: Target,
) -> Result<WatchOutcome, GuardianError> {
    watch_outcome(&channel.request(&format!("watch {role} {}", target_words(target)))?)
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
        let permit = super::custody::Group::new(1)
            .reserve()
            .context(CustodySnafu)?;
        let (ours, theirs) = UnixStream::pair().context(SpawnSnafu)?;
        let output = theirs.try_clone().context(SpawnSnafu)?;
        let mut command = Command::new(hb_exe);
        command
            .arg("__guard")
            .arg("--grace-ms")
            .arg(grace.as_millis().to_string());
        let mut process = permit.install(
            command
                .env_clear()
                .stdin(Stdio::from(OwnedFd::from(theirs)))
                .stdout(Stdio::from(OwnedFd::from(output)))
                .stderr(Stdio::null())
                .spawn()
                .context(SpawnSnafu)?,
        );
        // EOF must let the guardian finish independent cleanup; custody only reaps it.
        process.allow_cleanup_after_drop();
        let channel = Channel::new(ours).context(SpawnSnafu)?;
        Ok(Self {
            process,
            channel: Arc::new(channel),
        })
    }

    /// The guard's process number.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.process.id()
    }

    /// Tells the guard which terminal `hb` is about to put in raw mode.
    ///
    /// # Errors
    /// [`GuardianError`] if the guard does not acknowledge it.
    pub fn terminal(&mut self, path: &Path) -> Result<(), GuardianError> {
        expect_ok(&self.channel.request(&format!("tty {}", path.display()))?)
    }

    /// Tells the guard the token this run's processes carry in their environment, so a teardown can
    /// look for leftovers the process tracker missed.
    ///
    /// # Errors
    /// [`GuardianError`] if the guard does not acknowledge it.
    pub fn token(&mut self, token: &str) -> Result<(), GuardianError> {
        expect_ok(&self.channel.request(&format!("token {token}"))?)
    }

    /// Tells the guard the per-run directory, so a teardown can look for processes still using it.
    ///
    /// # Errors
    /// [`GuardianError`] if the guard does not acknowledge it.
    pub fn session_dir(&mut self, path: &Path) -> Result<(), GuardianError> {
        expect_ok(
            &self
                .channel
                .request(&format!("sessiondir {}", path.display()))?,
        )
    }

    /// Asks the guard to remove the `hb ctl` socket at `path` if `hb` dies first.
    ///
    /// # Errors
    /// [`GuardianError`] if the guard does not acknowledge it.
    pub fn socket(&mut self, path: &Path) -> Result<(), GuardianError> {
        expect_ok(
            &self
                .channel
                .request(&format!("socket {}", path.display()))?,
        )
    }

    /// A handle other threads can use to register what they start.
    #[must_use]
    pub fn handle(&self) -> GuardHandle {
        GuardHandle {
            channel: self.channel.clone(),
        }
    }

    /// Asks the guard to end `target` if `hb` dies before [`Guardian::release`].
    ///
    /// # Errors
    /// [`GuardianError`] when the guard did not arm or report the target gone.
    pub fn watch(&mut self, target: Target) -> Result<WatchOutcome, GuardianError> {
        watch_with(&self.channel, WatchRole::Core, target)
    }

    /// Tells the guard `hb` has cleaned up and waits (briefly) for it to exit.
    pub fn release(self) {
        let _ = self.release_checked();
    }

    pub(crate) fn release_checked(mut self) -> Result<(), GuardianError> {
        let released = self
            .channel
            .request("release")
            .and_then(|reply| expect_ok(&reply));
        self.channel.close();
        released?;
        let deadline = Instant::now() + RELEASE_WAIT;
        while Instant::now() < deadline {
            match self.process.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(_)) => return Err(GuardianError::Protocol),
                Err(source) => return Err(GuardianError::Spawn { source }),
                Ok(None) => thread::sleep(Duration::from_millis(5)),
            }
        }
        let _ = self.process.kill();
        Err(GuardianError::Deadline)
    }
}

impl Drop for Guardian {
    fn drop(&mut self) {
        self.channel.close();
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
    let stdin = io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context(ReadSnafu)?;
    let commands = File::from(stdin);
    let replies = File::from(
        io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .context(ReadSnafu)?,
    );
    run_loop(grace, commands, replies, |_| {})
}

/// The actual loop, with owned I/O and a one-shot observation seam after initial recovery.
/// Process-wide setup stays in `guard_loop`; tests can drive this loop without changing their session.
fn run_loop(
    grace: Duration,
    mut commands: File,
    mut replies: File,
    after_first_sweep: impl FnOnce(Swept),
) -> Result<(Ended, Option<TerminalWatch>), GuardError> {
    let queue = Kqueue::new().context(QueueSnafu)?;
    let command_fd = commands.as_raw_fd() as usize;
    let mut after_first_sweep = Some(after_first_sweep);
    let read_event = KEvent::new(
        command_fd,
        EventFilter::EVFILT_READ,
        EvFlags::EV_ADD,
        FilterFlag::empty(),
        0,
        0,
    );
    queue
        .kevent(&[read_event], &mut [], Some(zero()))
        .context(QueueSnafu)?;

    let mut watched = Watched::new();
    let mut tracker = Tracker::default();
    let mut registered = Registered::default();
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
            for socket in &registered.sockets {
                remove_socket(socket);
            }
            // What is already known gets TERM first: the sweeps below run `ps` and `lsof`, which can be
            // slow, and nothing should wait for them. The grace period starts here, so the sweeps
            // come out of it rather than extending it.
            // shortcut: a signalling error is not reported (the guard has no output channel once hb is
            // gone); a member that cannot be signalled is retried with KILL at the deadline.
            let _ = tracker.signal(Signal::SIGTERM);
            terminating = Some(Instant::now() + grace);
            // Leftovers the tracker missed are adopted and get the same TERM and the same deadline.
            let by = sweep_budget(grace, terminating);
            let swept = sweep_for_leftovers(&mut tracker, &queue, &registered, by);
            if let Some(observe) = after_first_sweep.take() {
                observe(swept);
            }
            if swept.adopted > 0 && terminating.is_some_and(|deadline| Instant::now() < deadline) {
                let _ = tracker.term_until(terminating.unwrap_or_else(Instant::now));
            }
        }
        // Overdue KILL takes priority over the empty-registry recovery pass.
        if terminating.is_some_and(|deadline| Instant::now() >= deadline) {
            kill_then_sweep(&mut tracker, |tracker| {
                sweep_for_leftovers(tracker, &queue, &registered, Instant::now() + SWEEP_FLOOR)
            });
            return Ok((Ended::HbGone, registered.terminal));
        }
        tracker.discovery_until(terminating);
        if terminating.is_some() && tracker.is_empty() {
            // Nothing tracked is left, but a leftover can still exist: look once more before
            // concluding. Anything found is ended under the original deadline.
            if !registered.final_sweep_done {
                // Its own budget, up to the deadline: the first sweep's is already spent.
                let by = terminating.unwrap_or_else(Instant::now);
                let swept = sweep_for_leftovers(&mut tracker, &queue, &registered, by);
                // A sweep that could not finish proves nothing, so it is not final: the guard waits
                // for the deadline, where the sweep after KILL gets a fresh budget.
                registered.final_sweep_done = swept.is_final_empty();
                if swept.adopted > 0
                    && terminating.is_some_and(|deadline| Instant::now() < deadline)
                {
                    let _ = tracker.term_until(terminating.unwrap_or_else(Instant::now));
                }
            }
            if tracker.is_empty() && registered.final_sweep_done {
                return Ok((Ended::HbGone, registered.terminal));
            }
        }
        // The deadline is checked on every pass, so a busy stream of fork events cannot defer it.
        if terminating.is_some_and(|deadline| Instant::now() >= deadline) {
            // What is known is killed first, so a slow sweep never delays it. Then one last look: work
            // that left every tie since the first sweep is still a leftover, and gets KILL too.
            kill_then_sweep(&mut tracker, |tracker| {
                sweep_for_leftovers(tracker, &queue, &registered, Instant::now() + SWEEP_FLOOR)
            });
            return Ok((Ended::HbGone, registered.terminal));
        }
        let timeout = terminating
            .map(|deadline| {
                TimeSpec::from_duration(deadline.saturating_duration_since(Instant::now()))
            })
            .or_else(|| {
                registered
                    .launches
                    .active()
                    .then(|| TimeSpec::from_duration(Duration::from_millis(5)))
            });
        let ready = match queue.kevent(&[], &mut events, timeout.as_ref().map(|t| *t.as_ref())) {
            Ok(n) => n,
            Err(Errno::EINTR) => continue,
            Err(source) => return Err(GuardError::Queue { source }),
        };
        if ready == 0 {
            progress_launches(&mut tracker, &queue, &mut registered.launches);
            continue;
        }
        for event in &events[..ready] {
            if terminating.is_some_and(|deadline| Instant::now() >= deadline) {
                break;
            }
            match event.filter() {
                Ok(EventFilter::EVFILT_READ) if pipe_open => {
                    let (next, open) = read_commands(
                        &mut commands,
                        &mut replies,
                        &mut buffered,
                        &mut watched,
                        &mut tracker,
                        &mut registered,
                        &queue,
                    )?;
                    pipe_open = open;
                    if !open {
                        // End of input stays readable; stop being told about it.
                        let done = KEvent::new(
                            command_fd,
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
                    // shortcut: a discovery error (full registry, kernel refusal) leaves that branch
                    // untracked and is not reported; the sweep and the documented residual cover it.
                    let exited = tracker.event(&queue, event).unwrap_or(false);
                    if exited {
                        // The root's slot is free again; its descendants stay in the tracker.
                        watched.remove(&i32::try_from(event.ident()).unwrap_or(0));
                    }
                    if terminating.is_some_and(|deadline| Instant::now() < deadline) {
                        // A process forked during the grace period is ended under the same deadline.
                        let _ = tracker.term_until(terminating.unwrap_or_else(Instant::now));
                    }
                }
                _ => {}
            }
        }
        progress_launches(&mut tracker, &queue, &mut registered.launches);
    }
}

fn register_launch(
    pid: i32,
    watched: &mut Watched,
    tracker: &mut Tracker,
    launches: &mut Launches,
    queue: &Kqueue,
) -> String {
    let root = match Identity::of(pid) {
        Ok(root) => root,
        Err(_) => return "refused invalid".into(),
    };
    if tracker.owned_by_other(root) {
        return "refused invalid".into();
    }
    if let Some((ticket, _)) = launches
        .records
        .iter()
        .find(|(_, record)| record.root == root)
    {
        return format!("armed {ticket}");
    }
    let Some(ticket) = launches.insert(root) else {
        return "refused capacity".into();
    };
    match watch(
        Target::Group(Pid::from_raw(pid)),
        WatchRole::Broker,
        watched,
        tracker,
        queue,
    ) {
        Ok(WatchOutcome::Armed) => format!("armed {ticket}"),
        outcome => {
            if tracker.root_count(root) == 0 {
                launches.records.remove(&ticket);
            } else {
                launches.failed = true;
                if let Some(record) = launches.records.get_mut(&ticket) {
                    record.failed = true;
                    record.internal = true;
                    record.deadline = Some(Instant::now() + super::launch_end::CLEANUP_BUDGET);
                }
            }
            match outcome {
                Err(reason) => format!("refused {reason}"),
                _ => "refused invalid".into(),
            }
        }
    }
}

fn end_launch(
    ticket: u64,
    phase: EndPhase,
    tracker: &mut Tracker,
    launches: &mut Launches,
    queue: &Kqueue,
) -> String {
    let Some(status) = launches.request(ticket, phase, Instant::now()) else {
        return "refused invalid".into();
    };
    let record = launches
        .records
        .get_mut(&ticket)
        .unwrap_or_else(|| unreachable!());
    if phase == EndPhase::Pinned && record.ready {
        tracker.discovery_until(record.deadline);
        if tracker.discover_pinned_root(queue, record.root).is_err() {
            record.failed = true;
            launches.failed = true;
        }
        tracker.discovery_until(None);
    }
    if phase == EndPhase::Pinned && record.revision != tracker.revision(record.root) {
        record.ready = false;
        record.cursor = None;
        record.revision = tracker.revision(record.root);
        return EndStatus::Pending.to_string();
    }
    if phase == EndPhase::Reaped {
        tracker.root_reaped(record.root);
    }
    if phase == EndPhase::Reaped && tracker.root_count(record.root) == 0 {
        let failed = record.failed || tracker.failed(record.root);
        tracker.forget_failure(record.root);
        launches.records.remove(&ticket);
        launches.failed |= failed;
        return if failed {
            EndStatus::Incomplete
        } else {
            EndStatus::Complete
        }
        .to_string();
    }
    status.to_string()
}

fn progress_launches(tracker: &mut Tracker, queue: &Kqueue, launches: &mut Launches) {
    for record in launches.records.values_mut() {
        let Some(deadline) = record.deadline else {
            continue;
        };
        if Instant::now() >= deadline {
            record.failed = true;
            launches.failed = true;
            tracker.kill_root_step(record.root, &mut record.cursor);
            continue;
        }
        if record.revision != tracker.revision(record.root) {
            record.ready = false;
            record.cursor = None;
            record.revision = tracker.revision(record.root);
        }
        tracker.discovery_until(Some(deadline));
        if record.phase == EndPhase::Pinned
            && !record.ready
            && record.cursor.is_none()
            && tracker.discover_pinned_root(queue, record.root).is_err()
        {
            record.failed = true;
            launches.failed = true;
        }
        match tracker.end_step(
            queue,
            record.root,
            record.phase == EndPhase::Pinned,
            &mut record.cursor,
        ) {
            Ok(true) => {
                let before = tracker.revision(record.root);
                if record.phase == EndPhase::Pinned
                    && tracker.discover_pinned_root(queue, record.root).is_err()
                {
                    record.failed = true;
                }
                record.ready = before == tracker.revision(record.root);
                record.revision = tracker.revision(record.root);
            }
            Ok(false) => {}
            Err(_) => {
                record.failed = true;
                launches.failed = true;
            }
        }
        record.failed |= tracker.failed(record.root);
        launches.failed |= record.failed;
    }
    launches
        .records
        .retain(|_, record| !record.internal || tracker.root_count(record.root) != 0);
    tracker.discovery_until(None);
}

fn zero() -> nix::libc::timespec {
    *TimeSpec::from_duration(Duration::ZERO).as_ref()
}

/// The deadline step: KILL everything known, and only then look for leftovers, which get KILL too.
/// The order matters: a sweep can be slow, and must never delay the kill of what is already known.
/// The second pass always runs: a member that could not be read the first time may be readable now,
/// whether or not the sweep adopted anything new.
fn kill_then_sweep(tracker: &mut Tracker, sweep: impl FnOnce(&mut Tracker) -> Swept) {
    let _ = tracker.signal(Signal::SIGKILL);
    let _ = sweep(tracker);
    let _ = tracker.signal(Signal::SIGKILL);
}

/// The time the sweep after KILL gets. Known members are already dead by then, so this delays nothing
/// that was known; it only bounds how long the guard lingers.
const SWEEP_FLOOR: Duration = Duration::from_secs(1);

/// When the first sweep must finish: half the grace period, counted from when it began. It comes out
/// of the grace period, so it never postpones the KILL; with a short grace it may not finish, and the
/// sweep after KILL is the backstop.
fn sweep_budget(grace: Duration, terminating: Option<Instant>) -> Instant {
    let start = terminating.map_or_else(Instant::now, |end| end - grace);
    start + grace / 2
}

/// Finds leftovers the process tracker missed and adopts them, so they are signalled with the rest.
///
/// Two sources, neither of which proves anything: processes whose environment holds the run's
/// token (found by comparing two `ps` listings, so a token in an argument does not count), and
/// processes still using the per-run directory. Every candidate is re-read and must be the same
/// user and no older than the earliest root before it is adopted. A source that cannot be read is
/// skipped; the tracker stays the primary mechanism. Returns how many leftovers were adopted.
fn sweep_for_leftovers(
    tracker: &mut Tracker,
    queue: &Kqueue,
    registered: &Registered,
    by: Instant,
) -> Swept {
    tracker.discovery_until(Some(by));
    let own = i32::try_from(std::process::id()).unwrap_or(0);
    let mut candidates: Vec<Identity> = Vec::new();
    let mut complete = true;
    if let Some(token) = &registered.token {
        let listings = listing(true, by)
            .and_then(|with_env| listing(false, by).map(|plain| (with_env, plain)));
        if let Ok((with_env, plain)) = listings {
            let entry = token.entry();
            let found = owned_by_token(&with_env, &plain, &entry);
            complete &= found.unreadable.is_empty();
            for pid in found.pids {
                if Instant::now() >= by {
                    complete = false;
                    break;
                }
                let identity = match Identity::of(pid) {
                    Ok(identity) => identity,
                    Err(IdentityError::Gone { .. }) => continue,
                    Err(_) => {
                        complete = false;
                        continue;
                    }
                };
                if holds_entry(pid, &entry) {
                    // Registration rechecks this same identity after confirmation.
                    candidates.push(identity);
                } else {
                    // sysinfo cannot distinguish a hidden/unreadable environment from no match.
                    complete = false;
                }
            }
        } else {
            complete = false;
        }
    }
    if let Some(dir) = &registered.session_dir {
        // Capture identities before lsof reads relationships. Its PID-only output can only
        // nominate an identity from this snapshot, never a replacement read afterward.
        let (snapshot, readable) = identity_snapshot(by);
        complete &= readable;
        match holders_of(dir, by) {
            Ok(holders) => {
                complete &= holders.complete;
                for pid in holders.pids {
                    if let Some(identity) = snapshot.get(&pid) {
                        candidates.push(*identity);
                    } else {
                        complete = false;
                    }
                }
            }
            Err(_) => complete = false,
        }
    }
    let mut swept = Swept {
        adopted: 0,
        complete,
    };
    for identity in candidates {
        if Instant::now() >= by {
            swept.complete = false;
            break;
        }
        swept.record(tracker.adopt_candidate(queue, identity, own));
    }
    swept.complete &= Instant::now() < by;
    swept
}

/// Capture identities before a PID-only directory listing, bounded between kernel queries.
fn identity_snapshot(by: Instant) -> (HashMap<i32, Identity>, bool) {
    let mut snapshot = HashMap::new();
    if Instant::now() >= by {
        return (snapshot, false);
    }
    let Ok(pids) = super::identity::all_pids() else {
        return (snapshot, false);
    };
    for pid in pids {
        if Instant::now() >= by {
            return (snapshot, false);
        }
        if let Ok(identity) = Identity::of(pid) {
            snapshot.insert(pid, identity);
        }
    }
    (snapshot, true)
}

/// What a sweep found. `complete` is false when a source could not be read in time, so "nothing
/// adopted" must not be taken for "nothing there".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Swept {
    adopted: usize,
    complete: bool,
}

impl Swept {
    fn is_final_empty(&self) -> bool {
        self.complete && self.adopted == 0
    }

    fn record(&mut self, adoption: Result<bool, TrackerError>) {
        match adoption {
            Ok(true) => self.adopted += 1,
            Ok(false) => {}
            Err(_) => self.complete = false,
        }
    }
}

/// What `hb` has told the guard to remember besides the processes: files to remove, the terminal to
/// check, and where to look for leftovers.
#[derive(Default)]
struct Registered {
    terminal: Option<TerminalWatch>,
    sockets: Vec<PathBuf>,
    token: Option<LaunchToken>,
    session_dir: Option<PathBuf>,
    /// Whether the look made after the tracked processes ended has been done.
    final_sweep_done: bool,
    launches: Launches,
}

/// Reads what is available, runs the complete lines, and reports whether to stop and whether the
/// pipe is still open.
fn read_commands(
    commands: &mut File,
    replies: &mut File,
    buffered: &mut Vec<u8>,
    watched: &mut Watched,
    tracker: &mut Tracker,
    registered: &mut Registered,
    queue: &Kqueue,
) -> Result<(Next, bool), GuardError> {
    let mut chunk = [0u8; 256];
    let n = match commands.read(&mut chunk) {
        Ok(n) => n,
        Err(error) if error.kind() == io::ErrorKind::Interrupted => return Ok((Next::Keep, true)),
        Err(source) => return Err(GuardError::Read { source }),
    };
    buffered.extend_from_slice(&chunk[..n]);
    while let Some(end) = buffered.iter().position(|b| *b == b'\n') {
        let line: Vec<u8> = buffered.drain(..=end).collect();
        if line.len() > MAX_LINE {
            continue;
        }
        let text = String::from_utf8_lossy(&line[..line.len() - 1]);
        let parsed = parse_line(&text);
        let reply = |replies: &mut File, id: u64, body: &str| {
            reply_line(replies, id, body);
        };
        match parsed {
            Ok(GuardCommand::AckLaunch { id, pid }) => {
                let body = register_launch(pid, watched, tracker, &mut registered.launches, queue);
                reply(replies, id, &body);
            }
            Ok(GuardCommand::AckEnd { id, ticket, phase }) => {
                let body = end_launch(ticket, phase, tracker, &mut registered.launches, queue);
                reply(replies, id, &body);
            }
            Ok(GuardCommand::Release) => {
                if registered.launches.records.is_empty() && !registered.launches.failed {
                    return Ok((Next::Release, true));
                }
            }
            Ok(GuardCommand::AckRelease(id)) => {
                if !registered.launches.records.is_empty() || registered.launches.failed {
                    reply(replies, id, "refused invalid");
                } else {
                    reply(replies, id, "ok");
                    return Ok((Next::Release, true));
                }
            }
            Ok(GuardCommand::Watch(target)) => {
                let _ = watch(target, WatchRole::Broker, watched, tracker, queue);
            }
            Ok(GuardCommand::AckWatch { id, role, target }) => {
                let body = match watch(target, role, watched, tracker, queue) {
                    Ok(WatchOutcome::Armed) => "armed".to_owned(),
                    Ok(WatchOutcome::Gone) => "gone".to_owned(),
                    Err(reason) => format!("refused {reason}"),
                };
                reply(replies, id, &body);
            }
            Ok(GuardCommand::Terminal(path)) => registered.terminal = TerminalWatch::open(&path),
            Ok(GuardCommand::AckTerminal(id, path)) => {
                registered.terminal = TerminalWatch::open(&path);
                reply(replies, id, "ok");
            }
            Ok(GuardCommand::Socket(path)) if registered.sockets.len() < MAX_SOCKETS => {
                registered.sockets.push(path);
            }
            Ok(GuardCommand::Socket(_)) => {}
            Ok(GuardCommand::AckSocket(id, path)) if registered.sockets.len() < MAX_SOCKETS => {
                registered.sockets.push(path);
                reply(replies, id, "ok");
            }
            Ok(GuardCommand::AckToken(id, value)) => {
                registered.token = LaunchToken::parse(&value);
                reply(replies, id, "ok");
            }
            Ok(GuardCommand::AckSessionDir(id, path)) => {
                registered.session_dir = Some(path);
                reply(replies, id, "ok");
            }
            Ok(GuardCommand::AckSocket(id, _)) => reply(replies, id, "refused capacity"),
            // A raw compatibility line the guard does not understand protects nothing.
            Err(_) => {
                if let Some(id) = request_id(&text) {
                    reply(replies, id, "refused invalid");
                }
            }
        }
    }
    if buffered.len() > MAX_LINE {
        buffered.clear();
    }
    Ok((Next::Keep, n != 0))
}

fn request_id(text: &str) -> Option<u64> {
    let mut words = text.split_whitespace();
    (words.next() == Some("ack")).then(|| words.next()?.parse().ok())?
}

/// A failed reply ends the transaction on hb's side, which shuts the channel and starts cleanup.
fn reply_line(replies: &mut File, id: u64, body: &str) {
    let _ = replies.write_all(format!("{id} {body}\n").as_bytes());
}

/// What the guard watches: each target with the capacity pool it came from.
type Watched = HashMap<i32, (Target, WatchRole, Identity)>;

/// Starts watching `target`, unless it has already ended or there is no capacity.
///
/// Root admission (the slots) is counted here; the kernel watch and the descendants it leads to
/// belong to the [`Tracker`].
fn watch(
    target: Target,
    role: WatchRole,
    watched: &mut Watched,
    tracker: &mut Tracker,
    queue: &Kqueue,
) -> Result<WatchOutcome, WatchRefusal> {
    let pid = match target {
        Target::Group(pid) | Target::Child(pid) => pid,
    };
    if let Some((existing, existing_role, identity)) = watched.get(&pid.as_raw()).copied() {
        let current = identity.is_current().map_err(|_| WatchRefusal::Kernel)?;
        if current && tracker.contains(identity) {
            return if existing == target && existing_role == role {
                Ok(WatchOutcome::Armed)
            } else {
                Err(WatchRefusal::Invalid)
            };
        }
        // An undelivered EXIT or a removed tracker entry cannot acknowledge a new launch.
        watched.remove(&pid.as_raw());
    }
    let brokers = watched
        .values()
        .filter(|(_, r, _)| *r == WatchRole::Broker)
        .count();
    let full = watched.len() >= MAX_WATCHED
        || (role == WatchRole::Broker && brokers >= MAX_WATCHED - RESERVED_CORE);
    if full {
        return Err(WatchRefusal::Capacity);
    }
    // Group discovery needs the original leader still present (including an unreaped zombie).
    // Already-owned members remain tracked after it disappears. Shared terminal groups are not scanned.
    let armed = tracker.arm(queue, pid.as_raw(), matches!(target, Target::Group(_)));
    record(armed, target, role, watched)
}

/// Turns the tracker's answer into an outcome, keeping only a root the kernel really watches.
fn record(
    armed: Result<Identity, TrackerError>,
    target: Target,
    role: WatchRole,
    watched: &mut Watched,
) -> Result<WatchOutcome, WatchRefusal> {
    let pid = match target {
        Target::Group(pid) | Target::Child(pid) => pid,
    };
    match armed {
        Ok(identity) => {
            watched.insert(pid.as_raw(), (target, role, identity));
            Ok(WatchOutcome::Armed)
        }
        Err(TrackerError::Identity {
            source: IdentityError::Gone { .. },
        }) => Ok(WatchOutcome::Gone),
        Err(TrackerError::Watch {
            source: Errno::ESRCH,
        }) => Ok(WatchOutcome::Gone),
        Err(TrackerError::Capacity) => Err(WatchRefusal::Capacity),
        Err(_) => Err(WatchRefusal::Kernel),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    #[test]
    fn parent_group_kill_covers_late_members_when_zombie_identity_is_unreadable() {
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        let (client, server) = assert_ok!(UnixStream::pair());
        let commands = File::from(OwnedFd::from(assert_ok!(server.try_clone())));
        let replies = File::from(OwnedFd::from(server));
        let worker = thread::spawn(move || run_loop(DEFAULT_GRACE, commands, replies, |_| {}));
        let channel = Arc::new(assert_ok!(Channel::new(client)));
        let guard = GuardHandle {
            channel: channel.clone(),
        };
        let group = super::super::custody::Group::new(2);
        let mut root = assert_ok!(group.reserve()).install(assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
        ));
        let launch = assert_ok!(guard.launch(root.id() as i32));
        let by = Instant::now() + Duration::from_secs(5);
        while assert_ok!(launch.end(EndPhase::Pinned, by)) == EndStatus::Pending {
            thread::sleep(Duration::from_millis(2));
        }
        let pid = claims::assert_some!(rustix::process::Pid::from_raw(root.id() as i32));
        while assert_ok!(rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOHANG
                | rustix::process::WaitIdOptions::NOWAIT
        ))
        .is_none()
        {
            assert!(Instant::now() < by);
            thread::sleep(Duration::from_millis(2));
        }
        // libproc may no longer describe a zombie; the parent's unreaped Child still pins the group.
        let mut late = assert_ok!(group.reserve()).install(assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(root.id() as i32)
                .spawn()
        ));
        assert_ok!(nix::sys::signal::killpg(
            Pid::from_raw(root.id() as i32),
            Signal::SIGKILL
        ));
        while assert_ok!(launch.end(EndPhase::Pinned, by)) == EndStatus::Pending {
            thread::sleep(Duration::from_millis(2));
        }
        let late_status = loop {
            if let Some(status) = assert_ok!(late.try_wait()) {
                break status;
            }
            assert!(
                Instant::now() < by,
                "late group member never received cleanup"
            );
            thread::sleep(Duration::from_millis(2));
        };
        assert_eq!(late_status.signal(), Some(nix::libc::SIGKILL));
        assert_ok!(root.wait());
        while assert_ok!(launch.end(EndPhase::Reaped, by)) == EndStatus::Pending {
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(assert_ok!(channel.request("release")), "ok");
        assert_ok!(assert_ok!(worker.join()));
    }

    #[test]
    fn ticket_loop_kills_an_adopted_detached_child_before_reporting_complete() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::process::CommandExt;
        let (client, server) = assert_ok!(UnixStream::pair());
        let commands = File::from(OwnedFd::from(assert_ok!(server.try_clone())));
        let replies = File::from(OwnedFd::from(server));
        let worker = thread::spawn(move || run_loop(DEFAULT_GRACE, commands, replies, |_| {}));
        let channel = Arc::new(assert_ok!(Channel::new(client)));
        let guard = GuardHandle {
            channel: channel.clone(),
        };
        let group = super::super::custody::Group::new(1);
        let mut root = assert_ok!(group.reserve()).install(assert_ok!(Command::new("/usr/bin/perl")
            .args(["-e", "use POSIX; $|=1; my $p=fork(); die unless defined $p; if (!$p) { setsid(); print qq($$\\n); sleep 20; exit 0; } scalar <STDIN>; waitpid($p,0);"])
            .process_group(0).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn()));
        let mut line = String::new();
        assert_ok!(BufReader::new(claims::assert_some!(root.stdout.take())).read_line(&mut line));
        let detached: i32 = assert_ok!(line.trim().parse());
        let identity = assert_ok!(Identity::of(detached));
        let launch = assert_ok!(guard.launch(root.id() as i32));
        let by = Instant::now() + Duration::from_secs(5);
        while assert_ok!(launch.end(EndPhase::Pinned, by)) == EndStatus::Pending {
            thread::sleep(Duration::from_millis(2));
        }
        assert_ok!(root.wait());
        loop {
            match assert_ok!(launch.end(EndPhase::Reaped, by)) {
                EndStatus::Complete => break,
                EndStatus::Pending => thread::sleep(Duration::from_millis(2)),
                other => assert_eq!(other, EndStatus::Complete),
            }
        }
        // Identity::of treats an exited zombie as Gone, unlike signal(pid, 0).
        assert!(
            !assert_ok!(identity.is_current()),
            "detached owned child still runs"
        );
        assert_eq!(assert_ok!(channel.request("release")), "ok");
        assert_ok!(assert_ok!(worker.join()));
    }

    #[test]
    fn ticket_loop_ends_one_launch_and_keeps_another_alive() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::process::CommandExt;
        let (client, server) = assert_ok!(UnixStream::pair());
        let commands = File::from(OwnedFd::from(assert_ok!(server.try_clone())));
        let replies = File::from(OwnedFd::from(server));
        let worker = thread::spawn(move || run_loop(DEFAULT_GRACE, commands, replies, |_| {}));
        let channel = Arc::new(assert_ok!(Channel::new(client)));
        let guard = GuardHandle {
            channel: channel.clone(),
        };
        let mut a = assert_ok!(
            Command::new("/bin/sh")
                .args(["-c", "echo ready; read done"])
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
        );
        let mut b = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
        );
        let mut ready = String::new();
        assert_ok!(BufReader::new(claims::assert_some!(a.stdout.take())).read_line(&mut ready));
        let launch_a = assert_ok!(guard.launch(a.id() as i32));
        let launch_b = assert_ok!(guard.launch(b.id() as i32));
        let by = Instant::now() + Duration::from_secs(5);
        while assert_ok!(launch_a.end(EndPhase::Pinned, by)) == EndStatus::Pending {
            assert!(Instant::now() < by);
            thread::sleep(Duration::from_millis(2));
        }
        assert_ok!(a.wait());
        loop {
            match assert_ok!(launch_a.end(EndPhase::Reaped, by)) {
                EndStatus::Complete => break,
                EndStatus::Pending => thread::sleep(Duration::from_millis(2)),
                other => assert_eq!(other, EndStatus::Complete),
            }
        }
        assert!(assert_ok!(b.try_wait()).is_none());
        assert!(launch_a.end(EndPhase::Pinned, by).is_err());
        loop {
            match assert_ok!(launch_b.end(EndPhase::Pinned, by)) {
                EndStatus::ReapReady => break,
                EndStatus::Pending => thread::sleep(Duration::from_millis(2)),
                other => assert_eq!(other, EndStatus::ReapReady),
            }
        }
        assert_ok!(b.wait());
        while assert_ok!(launch_b.end(EndPhase::Reaped, by)) == EndStatus::Pending {
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(assert_ok!(channel.request("release")), "ok");
        assert_ok!(assert_ok!(worker.join()));
    }

    #[test]
    fn the_second_sweep_finds_a_holder_created_after_the_first_completed() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::process::{CommandExt, ExitStatusExt};
        use std::sync::mpsc;

        let dir = assert_ok!(tempfile::tempdir());
        let real = assert_ok!(dir.path().canonicalize());
        let (mut client, server) = assert_ok!(UnixStream::pair());
        assert_ok!(client.set_read_timeout(Some(Duration::from_secs(30))));
        let commands = File::from(OwnedFd::from(assert_ok!(server.try_clone())));
        let replies = File::from(OwnedFd::from(server));
        let (swept_tx, swept_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let (ended_tx, ended_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let result = run_loop(Duration::from_secs(20), commands, replies, |swept| {
                let _ = swept_tx.send(swept);
                let _ = resume_rx.recv_timeout(Duration::from_secs(30));
            });
            let _ = ended_tx.send(result);
        });
        let mut root = sleeper();
        let mut response = BufReader::new(assert_ok!(client.try_clone()));
        assert_ok!(writeln!(client, "ack 1 watch core process {}", root.id()));
        let mut line = String::new();
        assert_ok!(response.read_line(&mut line));
        assert_eq!(line, "1 armed\n");
        assert_ok!(writeln!(client, "ack 2 sessiondir {}", real.display()));
        line.clear();
        assert_ok!(response.read_line(&mut line));
        assert_eq!(line, "2 ok\n");
        let _ = root.kill();
        let _ = root.wait();
        drop(response);
        drop(client);
        let first = assert_ok!(swept_rx.recv_timeout(Duration::from_secs(30)));
        assert_eq!(first.adopted, 0);
        assert!(first.complete);
        let mut holder = assert_ok!(
            Command::new("/bin/sleep")
                .arg("60")
                .current_dir(&real)
                .process_group(0)
                .spawn()
        );
        assert_ok!(resume_tx.send(()));
        let ended = ended_rx.recv_timeout(Duration::from_secs(30));
        let status = assert_ok!(holder.try_wait());
        // Always clean our child before assertions, including mutant failures.
        let _ = holder.kill();
        let _ = holder.wait();
        assert_eq!(assert_ok!(assert_ok!(ended)).0, Ended::HbGone);
        assert!(worker.join().is_ok());
        // The deadline backstop sends KILL. TERM proves the empty-tracker recovery pass found it.
        assert_eq!(
            claims::assert_some!(status).signal(),
            Some(Signal::SIGTERM as i32)
        );
    }

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
    fn cleanup_failure_refuses_release_even_after_all_ticket_records_retire() {
        let (mut client, server) = assert_ok!(UnixStream::pair());
        let mut commands = File::from(OwnedFd::from(assert_ok!(server.try_clone())));
        let mut replies = File::from(OwnedFd::from(server));
        let queue = assert_ok!(Kqueue::new());
        let mut registered = Registered::default();
        registered.launches.failed = true;
        assert_ok!(writeln!(client, "ack 7 release"));
        let result = assert_ok!(read_commands(
            &mut commands,
            &mut replies,
            &mut Vec::new(),
            &mut Watched::new(),
            &mut Tracker::default(),
            &mut registered,
            &queue
        ));
        assert_eq!(result, (Next::Keep, true));
        use std::io::{BufRead, BufReader};
        let mut reply = String::new();
        assert_ok!(BufReader::new(client).read_line(&mut reply));
        assert_eq!(reply, "7 refused invalid\n");
    }

    #[test]
    fn an_expired_launch_still_signals_known_work_and_keeps_failure() {
        let queue = assert_ok!(Kqueue::new());
        let mut child = sleeper();
        let mut tracker = Tracker::default();
        let root = assert_ok!(tracker.arm(&queue, child.id() as i32, false));
        let mut launches = Launches::default();
        let ticket = claims::assert_some!(launches.insert(root));
        claims::assert_some!(launches.records.get_mut(&ticket)).deadline = Some(Instant::now());
        progress_launches(&mut tracker, &queue, &mut launches);
        let status = assert_ok!(child.wait());
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(nix::libc::SIGKILL));
        assert!(launches.failed);
        assert!(launches.records[&ticket].failed);
    }

    #[test]
    fn duplicate_ticket_does_not_rearm_or_reset_an_ending_launch() {
        let queue = assert_ok!(Kqueue::new());
        let mut child = sleeper();
        let mut tracker = Tracker::default();
        let mut watched = Watched::new();
        let mut launches = Launches::default();
        let first = register_launch(
            child.id() as i32,
            &mut watched,
            &mut tracker,
            &mut launches,
            &queue,
        );
        let ticket = claims::assert_some!(launches.records.keys().next().copied());
        let _ = launches.request(ticket, EndPhase::Pinned, Instant::now());
        let deadline = launches.records[&ticket].deadline;
        let root = launches.records[&ticket].root;
        let revision = tracker.revision(root);
        let duplicate = register_launch(
            child.id() as i32,
            &mut watched,
            &mut tracker,
            &mut launches,
            &queue,
        );
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(first, duplicate);
        assert_eq!(launches.records[&ticket].deadline, deadline);
        assert_eq!(tracker.revision(root), revision);
    }

    #[test]
    fn release_is_a_command_of_its_own() {
        assert_eq!(assert_ok!(parse_line("release")), GuardCommand::Release);
    }

    #[test]
    fn the_frames_hb_writes_are_the_frames_the_guard_reads() {
        for (role, target) in [
            (WatchRole::Core, Target::Group(Pid::from_raw(12345))),
            (WatchRole::Broker, Target::Child(Pid::from_raw(2))),
        ] {
            let line = format!("ack 9 watch {role} {}", target_words(target));
            assert_eq!(
                assert_ok!(parse_line(&line)),
                GuardCommand::AckWatch {
                    id: 9,
                    role,
                    target
                }
            );
        }
        assert_eq!(
            assert_ok!(parse_line("ack 3 release")),
            GuardCommand::AckRelease(3)
        );
        assert_err!(parse_line("ack x release"));
        assert_err!(parse_line("ack 1 watch admin group 42"));
    }

    #[test]
    fn replies_map_to_typed_outcomes_and_anything_else_is_a_protocol_error() {
        assert_eq!(assert_ok!(watch_outcome("armed")), WatchOutcome::Armed);
        assert_eq!(assert_ok!(watch_outcome("gone")), WatchOutcome::Gone);
        for (reply, reason) in [
            ("refused capacity", WatchRefusal::Capacity),
            ("refused kernel", WatchRefusal::Kernel),
            ("refused invalid", WatchRefusal::Invalid),
        ] {
            assert!(
                matches!(watch_outcome(reply), Err(GuardianError::Refused { reason: r }) if r == reason),
                "{reply}"
            );
        }
        for bad in ["ok", "refused", "refused other", "armed extra", ""] {
            assert!(
                matches!(watch_outcome(bad), Err(GuardianError::Protocol)),
                "{bad}"
            );
        }
    }

    fn sleeper() -> std::process::Child {
        assert_ok!(Command::new("/bin/sleep").arg("30").spawn())
    }

    /// A stalled sweep must not delay the kill of what is already known: the sweep stand-in checks,
    /// when it runs, that the known process is already dead.
    #[test]
    fn the_known_members_are_killed_before_the_sweep_runs() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut child = sleeper();
        let pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
        assert_ok!(tracker.arm(&queue, pid, false));
        let mut dead_when_swept = None;
        kill_then_sweep(&mut tracker, |_| {
            // Reaping here is the only way to see the kill: a killed child is a zombie until waited on.
            dead_when_swept = Some(matches!(child.wait(), Ok(status) if !status.success()));
            Swept {
                adopted: 0,
                complete: true,
            }
        });
        assert_eq!(dead_when_swept, Some(true));
    }

    /// A member that could not be signalled before the sweep gets its second chance after it, even
    /// when the sweep adopts nothing: here the stand-in sweep spawns the process the first pass could
    /// not have known about, adopts it itself, and reports zero new adoptions.
    #[test]
    fn the_second_kill_pass_runs_even_when_the_sweep_adopts_nothing() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut late = sleeper();
        let late_pid = i32::try_from(late.id()).unwrap_or(i32::MAX);
        let mut early = sleeper();
        assert_ok!(tracker.arm(&queue, i32::try_from(early.id()).unwrap_or(i32::MAX), false));
        kill_then_sweep(&mut tracker, |tracker| {
            // Joined during the sweep, but not counted as a new adoption.
            let _ = tracker.arm(&queue, late_pid, false);
            Swept {
                adopted: 0,
                complete: true,
            }
        });
        assert!(matches!(late.wait(), Ok(status) if !status.success()));
        let _ = early.wait();
    }

    /// A sweep that ran out of time says so, so the guard does not take "nothing adopted" for "nothing
    /// there" and conclude.
    #[test]
    fn a_sweep_that_ran_out_of_time_says_it_is_incomplete() {
        let tracker_queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let registered = Registered {
            session_dir: Some(std::env::temp_dir()),
            ..Registered::default()
        };
        let swept = sweep_for_leftovers(&mut tracker, &tracker_queue, &registered, Instant::now());
        assert!(!swept.complete, "{swept:?}");
        assert_eq!(swept.adopted, 0);
    }

    #[test]
    fn failed_adoption_cannot_make_a_final_look_complete() {
        let mut swept = Swept {
            adopted: 0,
            complete: true,
        };
        swept.record(Ok(false));
        assert!(swept.is_final_empty());
        swept.record(Ok(true));
        assert_eq!(swept.adopted, 1);
        assert!(!swept.is_final_empty());
        swept.record(Err(TrackerError::Capacity));
        assert!(!swept.complete);
        swept.record(Ok(false));
        assert!(!swept.complete);
    }

    /// The budget is part of the grace period, never more than half of it, and never under the floor.
    #[test]
    fn the_sweeps_budget_comes_out_of_the_grace_period() {
        let now = Instant::now();
        let grace = Duration::from_secs(10);
        let by = sweep_budget(grace, Some(now + grace));
        assert!(by >= now + Duration::from_millis(4990) && by <= now + Duration::from_millis(5100));
        // A short grace gets a short budget: the sweep never pushes the KILL past its deadline.
        let short = sweep_budget(
            Duration::from_millis(100),
            Some(now + Duration::from_millis(100)),
        );
        assert!(short <= now + Duration::from_millis(60));
    }

    #[test]
    fn broker_watches_get_their_slots_even_after_the_core_slots_are_used() {
        let queue = assert_ok!(Kqueue::new());
        let mut watched = Watched::new();
        let mut tracker = Tracker::default();
        let mut children: Vec<_> = (0..MAX_WATCHED + 1).map(|_| sleeper()).collect();
        let pid =
            |c: &std::process::Child| Pid::from_raw(i32::try_from(c.id()).unwrap_or(i32::MAX));
        let mut arm = |c: &std::process::Child, role, w: &mut Watched| {
            watch(Target::Child(pid(c)), role, w, &mut tracker, &queue)
        };
        for child in &children[..RESERVED_CORE] {
            assert_eq!(
                assert_ok!(arm(child, WatchRole::Core, &mut watched)),
                WatchOutcome::Armed
            );
        }
        let broker_slots = MAX_WATCHED - RESERVED_CORE;
        for child in &children[RESERVED_CORE..RESERVED_CORE + broker_slots] {
            assert_eq!(
                assert_ok!(arm(child, WatchRole::Broker, &mut watched)),
                WatchOutcome::Armed
            );
        }
        assert_eq!(watched.len(), MAX_WATCHED);
        assert_eq!(
            arm(&children[MAX_WATCHED], WatchRole::Broker, &mut watched),
            Err(WatchRefusal::Capacity)
        );
        assert_eq!(
            arm(&children[MAX_WATCHED], WatchRole::Core, &mut watched),
            Err(WatchRefusal::Capacity)
        );
        for child in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn brokers_cannot_take_the_reserved_core_slots() {
        let queue = assert_ok!(Kqueue::new());
        let mut watched = Watched::new();
        let mut tracker = Tracker::default();
        let mut children: Vec<_> = (0..MAX_WATCHED).map(|_| sleeper()).collect();
        let pid =
            |c: &std::process::Child| Pid::from_raw(i32::try_from(c.id()).unwrap_or(i32::MAX));
        let broker_slots = MAX_WATCHED - RESERVED_CORE;
        for child in &children[..broker_slots] {
            assert_eq!(
                assert_ok!(watch(
                    Target::Group(pid(child)),
                    WatchRole::Broker,
                    &mut watched,
                    &mut tracker,
                    &queue
                )),
                WatchOutcome::Armed
            );
        }
        assert_eq!(
            watch(
                Target::Group(pid(&children[broker_slots])),
                WatchRole::Broker,
                &mut watched,
                &mut tracker,
                &queue
            ),
            Err(WatchRefusal::Capacity)
        );
        for child in &children[broker_slots..] {
            assert_eq!(
                assert_ok!(watch(
                    Target::Child(pid(child)),
                    WatchRole::Core,
                    &mut watched,
                    &mut tracker,
                    &queue
                )),
                WatchOutcome::Armed
            );
        }
        for child in &mut children {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn a_tracker_refusal_is_reported_and_nothing_is_recorded() {
        let target = Target::Child(Pid::from_raw(4242));
        let mut watched = Watched::new();
        let gone = || {
            Err(TrackerError::Identity {
                source: IdentityError::Gone { pid: 4242 },
            })
        };
        let denied = || {
            Err(TrackerError::Watch {
                source: Errno::EPERM,
            })
        };
        assert_eq!(
            record(denied(), target, WatchRole::Core, &mut watched),
            Err(WatchRefusal::Kernel)
        );
        assert_eq!(
            record(gone(), target, WatchRole::Core, &mut watched),
            Ok(WatchOutcome::Gone)
        );
        assert_eq!(
            record(
                Err(TrackerError::Capacity),
                target,
                WatchRole::Core,
                &mut watched
            ),
            Err(WatchRefusal::Capacity)
        );
        assert!(watched.is_empty());
        let identity = assert_ok!(Identity::of(
            i32::try_from(std::process::id()).unwrap_or(i32::MAX)
        ));
        assert_eq!(
            record(Ok(identity), target, WatchRole::Broker, &mut watched),
            Ok(WatchOutcome::Armed)
        );
        assert_eq!(
            watched.get(&4242),
            Some(&(target, WatchRole::Broker, identity))
        );
    }

    #[test]
    fn a_duplicate_is_armed_once_a_conflict_is_refused_and_a_gone_target_is_reported() {
        let queue = assert_ok!(Kqueue::new());
        let mut watched = Watched::new();
        let mut tracker = Tracker::default();
        let mut child = sleeper();
        let pid = Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX));
        assert_eq!(
            assert_ok!(watch(
                Target::Group(pid),
                WatchRole::Core,
                &mut watched,
                &mut tracker,
                &queue
            )),
            WatchOutcome::Armed
        );
        assert_eq!(
            assert_ok!(watch(
                Target::Group(pid),
                WatchRole::Core,
                &mut watched,
                &mut tracker,
                &queue
            )),
            WatchOutcome::Armed
        );
        assert_eq!(watched.len(), 1);
        assert_eq!(
            watch(
                Target::Child(pid),
                WatchRole::Core,
                &mut watched,
                &mut tracker,
                &queue
            ),
            Err(WatchRefusal::Invalid)
        );
        let _ = child.kill();
        let _ = child.wait();
        // Reuse the admission map before draining the old exit event.
        assert_eq!(
            assert_ok!(watch(
                Target::Group(pid),
                WatchRole::Core,
                &mut watched,
                &mut tracker,
                &queue
            )),
            WatchOutcome::Gone
        );
        assert!(watched.is_empty());
        // A fresh queue: the first queue still holds the undelivered exit event for this pid.
        let fresh_queue = assert_ok!(Kqueue::new());
        let mut fresh = Watched::new();
        let mut fresh_tracker = Tracker::default();
        assert_eq!(
            assert_ok!(watch(
                Target::Child(pid),
                WatchRole::Core,
                &mut fresh,
                &mut fresh_tracker,
                &fresh_queue
            )),
            WatchOutcome::Gone
        );
        assert!(fresh.is_empty());
    }

    #[test]
    fn a_duplicate_without_a_tracker_registration_is_armed_again() {
        let queue = assert_ok!(Kqueue::new());
        let mut watched = Watched::new();
        let mut tracker = Tracker::default();
        let mut child = sleeper();
        let pid = Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX));
        let target = Target::Child(pid);
        assert_eq!(
            assert_ok!(watch(
                target,
                WatchRole::Core,
                &mut watched,
                &mut tracker,
                &queue
            )),
            WatchOutcome::Armed
        );
        let identity = watched[&pid.as_raw()].2;
        // Simulate a tracker entry removed independently of the admission map.
        tracker = Tracker::default();
        assert_eq!(
            assert_ok!(watch(
                target,
                WatchRole::Core,
                &mut watched,
                &mut tracker,
                &queue
            )),
            WatchOutcome::Armed
        );
        assert!(tracker.contains(identity));
        let _ = child.kill();
        let _ = child.wait();
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
