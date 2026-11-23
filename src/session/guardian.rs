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
use std::os::fd::AsFd;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
use nix::sys::signal::Signal;
use nix::sys::time::TimeSpec;
use nix::unistd::Pid;
use rustix::process::setsid;
use snafu::{OptionExt, ResultExt, Snafu};

use super::signals::{SignalError, Target, clear_mask};

/// How long the guard lets processes end after SIGTERM before it sends SIGKILL.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(2);

/// How many processes the guard will watch. `hb` registers two.
const MAX_WATCHED: usize = 16;
/// The longest command line the guard accepts.
const MAX_LINE: usize = 128;
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GuardCommand {
    /// Clean up this target if `hb` dies.
    Watch(Target),
    /// `hb` finished normally: exit and touch nothing.
    Release,
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
        ["watch", kind @ ("group" | "process"), pid] => {
            let pid: i32 = pid.parse().ok().context(BadPidSnafu)?;
            if pid < FIRST_SIGNALLABLE_PID {
                return BadPidSnafu.fail();
            }
            let pid = Pid::from_raw(pid);
            Ok(GuardCommand::Watch(if *kind == "group" {
                Target::Group(pid)
            } else {
                Target::Child(pid)
            }))
        }
        _ => UnknownSnafu.fail(),
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
// hb's side
// ====================================================================================

/// The guard process, seen from `hb`.
///
/// Dropping it without [`Guardian::release`] closes the pipe, which tells the guard `hb` is gone.
#[derive(Debug)]
pub struct Guardian {
    process: Child,
    commands: ChildStdin,
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
        let mut process = command
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context(SpawnSnafu)?;
        let Some(commands) = process.stdin.take() else {
            let _ = process.kill();
            let _ = process.wait();
            return Err(GuardianError::Spawn {
                source: io::Error::other("the guard has no command pipe"),
            });
        };
        Ok(Self { process, commands })
    }

    /// The guard's process number.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.process.id()
    }

    /// Asks the guard to end `target` if `hb` dies before [`Guardian::release`].
    ///
    /// # Errors
    /// [`GuardianError::Tell`] if the guard cannot be written to.
    pub fn watch(&mut self, target: Target) -> Result<(), GuardianError> {
        self.commands
            .write_all(watch_line(target).as_bytes())
            .and_then(|()| self.commands.flush())
            .context(TellSnafu)
    }

    /// Tells the guard `hb` has cleaned up and waits (briefly) for it to exit.
    pub fn release(mut self) {
        let _ = self
            .commands
            .write_all(b"release\n")
            .and_then(|()| self.commands.flush());
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
            if watched.is_empty() {
                return Ok(());
            }
            send_all(&watched, Signal::SIGTERM);
            terminating = Some(Instant::now() + grace);
        }
        if terminating.is_some() && watched.is_empty() {
            return Ok(());
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
                return Ok(());
            }
            continue;
        }
        for event in &events[..ready] {
            match event.filter() {
                Ok(EventFilter::EVFILT_READ) if pipe_open => {
                    let (next, open) =
                        read_commands(&mut commands, &mut buffered, &mut watched, &queue)?;
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
                        return Ok(());
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
        let text = String::from_utf8_lossy(&line[..line.len() - 1]);
        if line.len() > MAX_LINE {
            continue;
        }
        match parse_line(&text) {
            Ok(GuardCommand::Release) => return Ok((Next::Release, true)),
            Ok(GuardCommand::Watch(target)) => watch(target, watched, queue),
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
fn watch(target: Target, watched: &mut HashMap<i32, Target>, queue: &Kqueue) {
    let pid = match target {
        Target::Group(pid) | Target::Child(pid) => pid,
    };
    if watched.len() >= MAX_WATCHED {
        return;
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

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

    #[test]
    fn line_errors_follow_the_display_convention() {
        for error in [LineError::Unknown, LineError::BadPid] {
            crate::error::conventions::assert_display_excludes_sources(&error);
        }
    }
}
