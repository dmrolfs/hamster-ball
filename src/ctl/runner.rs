// ABOUTME: Runs one host command with an absolute deadline, a cancel flag, a combined output tail and a process-group kill.
// ABOUTME: Replaces `sys::run_bounded` for the broker: that one drops stderr, keeps a prefix, and can wait on a pipe a descendant holds.
//! The bounded runner (hb-ghd.8.1).

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use snafu::{ResultExt, Snafu};

use crate::session::GuardHandle;
use crate::session::guardian::{GuardianError, WatchOutcome, WatchRefusal};
use crate::session::signals::Target;

/// How the output of a command is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capture {
    /// stdout and stderr interleaved, keeping the last `n` bytes (for text shown to the agent).
    Tail(usize),
    /// stdout only, which must fit in `n` bytes or the run fails (for metadata that is parsed).
    Whole(usize),
}

/// What a finished command left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finished {
    /// Whether it exited with status 0.
    pub success: bool,
    /// The exit code, or `None` if a signal ended it.
    pub code: Option<i32>,
    /// The captured bytes.
    pub bytes: Vec<u8>,
    /// Whether bytes were dropped to fit the limit (always false for [`Capture::Whole`]).
    pub truncated: bool,
}

/// Why a command produced no result.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RunError {
    /// The program could not be started.
    #[snafu(display("could not start {}", program.display()))]
    Spawn {
        /// The program.
        program: PathBuf,
        /// The OS error.
        source: std::io::Error,
    },
    /// The cleanup guard did not protect the command, so it was killed before its result was used.
    #[snafu(display("the cleanup guard did not protect the command"))]
    Guard {
        /// Why the guard did not arm.
        source: GuardianError,
    },
    /// The deadline passed; the process group was killed. The command may still have taken effect.
    #[snafu(display("timed out after {} s", limit.as_secs()))]
    TimedOut {
        /// The limit that was set.
        limit: Duration,
    },
    /// The session is ending; the process group was killed.
    #[snafu(display("cancelled"))]
    Cancelled,
    /// Metadata did not fit its limit, so it was not used.
    #[snafu(display("output was larger than {limit} bytes"))]
    TooLarge {
        /// The limit.
        limit: usize,
    },
    /// Waiting for the process failed.
    #[snafu(display("could not wait for the process"))]
    Wait {
        /// The OS error.
        source: std::io::Error,
    },
}

/// A flag the broker sets when the run is ending.
#[derive(Debug, Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);

impl Cancel {
    /// Asks every command using this flag to stop.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    /// Whether it has been asked.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// What the broker needs to run host commands; a fake in the handler's tests.
pub trait Execute: Send + Sync {
    /// Runs `program` with `argv`.
    ///
    /// # Errors
    /// [`RunError`].
    fn run(
        &self,
        program: &Path,
        argv: &[OsString],
        capture: Capture,
        timeout: Duration,
        cancel: &Cancel,
    ) -> Result<Finished, RunError>;
}

/// The real thing.
#[derive(Debug, Clone)]
pub struct Host {
    env: Vec<(OsString, OsString)>,
    guard: Option<GuardHandle>,
}

/// Variables from `hb`'s own environment that host commands may see: where the user's podman
/// configuration is, and nothing else. The agent's environment never reaches here.
const KEPT: [&str; 6] = [
    "HOME",
    "USER",
    "TMPDIR",
    "CONTAINER_HOST",
    "CONTAINER_CONNECTION",
    "XDG_CONFIG_HOME",
];

impl Host {
    /// A runner whose commands get `PATH` and the kept variables from `vars`.
    pub fn new(path: &str, vars: impl Fn(&str) -> Option<OsString>) -> Self {
        let mut env: Vec<(OsString, OsString)> = KEPT
            .iter()
            .filter_map(|k| vars(k).map(|v| (OsString::from(*k), v)))
            .collect();
        env.push(("PATH".into(), path.into()));
        Self { env, guard: None }
    }

    /// Registers every command's process group with the cleanup guard, so a killed `hb` does not
    /// leave one running. A command the guard does not arm is killed and reported as
    /// [`RunError::Guard`].
    ///
    /// shortcut: the group is registered just after it starts, not before; an `hb` killed in those
    /// microseconds leaves that one command to finish or time out by itself. The launch gate in
    /// hb-9lu closes this.
    #[must_use]
    pub fn with_guard(mut self, guard: GuardHandle) -> Self {
        self.guard = Some(guard);
        self
    }
}

const POLL: Duration = Duration::from_millis(5);
/// After the leader has exited, how long output may still be arriving before the group is killed.
const DRAIN_GRACE: Duration = Duration::from_millis(500);

struct Tail {
    buf: VecDeque<u8>,
    limit: usize,
    truncated: bool,
    whole: bool,
}

impl Tail {
    fn push(&mut self, chunk: &[u8]) {
        if self.whole {
            let room = self.limit.saturating_sub(self.buf.len());
            if chunk.len() > room {
                self.truncated = true;
            }
            self.buf.extend(chunk.iter().take(room));
            return;
        }
        self.buf.extend(chunk);
        let over = self.buf.len().saturating_sub(self.limit);
        if over > 0 {
            self.buf.drain(..over);
            self.truncated = true;
        }
    }
}

fn reader(mut pipe: impl Read + Send + 'static, tail: Option<Arc<Mutex<Tail>>>) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            match pipe.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Some(tail) = &tail {
                        if let Ok(mut t) = tail.lock() {
                            t.push(&chunk[..n]);
                        }
                    }
                }
            }
        }
    })
}

fn kill_group(child: &Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = killpg(Pid::from_raw(pid), Signal::SIGKILL);
    }
}

impl Execute for Host {
    fn run(
        &self,
        program: &Path,
        argv: &[OsString],
        capture: Capture,
        timeout: Duration,
        cancel: &Cancel,
    ) -> Result<Finished, RunError> {
        let (limit, whole) = match capture {
            Capture::Tail(n) => (n, false),
            Capture::Whole(n) => (n, true),
        };
        let mut command = Command::new(program);
        command
            .args(argv)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        let mut child = command.spawn().context(SpawnSnafu { program })?;
        if let Some(guard) = &self.guard {
            let protected = match i32::try_from(child.id()) {
                Ok(pid) => match guard.watch(Target::Group(Pid::from_raw(pid))) {
                    Ok(WatchOutcome::Armed) => Ok(()),
                    // Gone is acceptable only when the leader really exited; the group is killed below.
                    Ok(WatchOutcome::Gone) if matches!(child.try_wait(), Ok(Some(_))) => Ok(()),
                    Ok(WatchOutcome::Gone) => Err(GuardianError::Refused {
                        reason: WatchRefusal::Invalid,
                    }),
                    Err(error) => Err(error),
                },
                Err(_) => Err(GuardianError::Protocol),
            };
            if let Err(source) = protected {
                // Unregistered means unprotected: do not run it.
                kill_group(&child);
                let _ = child.wait();
                return Err(RunError::Guard { source });
            }
        }
        let tail = Arc::new(Mutex::new(Tail {
            buf: VecDeque::new(),
            limit,
            truncated: false,
            whole,
        }));
        let mut readers = Vec::new();
        if let Some(out) = child.stdout.take() {
            readers.push(reader(out, Some(tail.clone())));
        }
        if let Some(err) = child.stderr.take() {
            readers.push(reader(err, (!whole).then(|| tail.clone())));
        }
        let outcome = wait(&mut child, timeout, cancel);
        // Whatever happened, nothing of this command may outlive the call.
        kill_group(&child);
        let reaped = child.wait();
        join_all(readers, Instant::now() + DRAIN_GRACE);
        let status = outcome?;
        reaped.context(WaitSnafu)?;
        let tail = tail.lock().map_err(|_| RunError::Wait {
            source: std::io::Error::other("output buffer poisoned"),
        })?;
        if whole && tail.truncated {
            return Err(RunError::TooLarge { limit });
        }
        Ok(finished(status, &tail))
    }
}

fn finished(status: ExitStatus, tail: &Tail) -> Finished {
    Finished {
        success: status.success(),
        code: status.code(),
        bytes: tail.buf.iter().copied().collect(),
        truncated: tail.truncated,
    }
}

fn wait(child: &mut Child, timeout: Duration, cancel: &Cancel) -> Result<ExitStatus, RunError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().context(WaitSnafu)? {
            return Ok(status);
        }
        if cancel.is_cancelled() {
            return Err(RunError::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(RunError::TimedOut { limit: timeout });
        }
        thread::sleep(POLL);
    }
}

/// Waits for the reader threads until `by`. The group has been killed, so every pipe a group
/// member held is closed; a reader still running holds a pipe from a process that left the group.
///
/// shortcut: such a reader is abandoned (it ends when that process does), upgrade if a
/// real command is ever seen to do that.
fn join_all(readers: Vec<JoinHandle<()>>, by: Instant) {
    for handle in readers {
        while !handle.is_finished() && Instant::now() < by {
            thread::sleep(POLL);
        }
        if handle.is_finished() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn host() -> Host {
        Host::new("/usr/bin:/bin", |_| None)
    }

    fn sh(script: &str, capture: Capture, timeout: Duration) -> Result<Finished, RunError> {
        host().run(
            Path::new("/bin/sh"),
            &["-c".into(), script.into()],
            capture,
            timeout,
            &Cancel::default(),
        )
    }

    const SECOND: Duration = Duration::from_secs(1);

    #[test]
    fn test_stdout_and_stderr_are_both_kept_and_the_exit_code_is_reported() {
        let done = assert_ok!(sh(
            "echo out; echo err >&2; exit 3",
            Capture::Tail(1000),
            SECOND
        ));
        assert!(!done.success);
        assert_eq!(done.code, Some(3));
        let text = String::from_utf8_lossy(&done.bytes).into_owned();
        assert!(text.contains("out") && text.contains("err"), "{text}");
        assert!(!done.truncated);
    }

    #[test]
    fn test_tail_keeps_the_end_and_keeps_draining_far_past_the_limit() {
        let done = assert_ok!(sh(
            "yes abcdefghij | head -c 2000000; echo THE-END",
            Capture::Tail(50),
            Duration::from_secs(20)
        ));
        assert!(done.truncated);
        assert_eq!(done.bytes.len(), 50);
        assert!(String::from_utf8_lossy(&done.bytes).ends_with("THE-END\n"));
        assert!(
            done.success,
            "the writer must not be killed by a closed pipe"
        );
    }

    #[test]
    fn test_whole_mode_fails_closed_when_the_metadata_does_not_fit() {
        let err = assert_err!(sh("yes abc | head -c 5000", Capture::Whole(1000), SECOND));
        assert!(matches!(err, RunError::TooLarge { limit: 1000 }), "{err:?}");
        let ok = assert_ok!(sh(
            "printf '[]'; echo noise >&2",
            Capture::Whole(1000),
            SECOND
        ));
        assert_eq!(ok.bytes, b"[]");
    }

    #[test]
    fn test_a_command_past_its_deadline_is_killed_with_its_children() {
        let start = Instant::now();
        let err = assert_err!(sh(
            "sleep 30 & sleep 30",
            Capture::Tail(100),
            Duration::from_millis(200)
        ));
        assert!(matches!(err, RunError::TimedOut { .. }), "{err:?}");
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn test_a_descendant_that_keeps_the_pipe_open_cannot_hang_the_call() {
        let start = Instant::now();
        let done = assert_ok!(sh(
            "(sleep 30 &) ; echo done",
            Capture::Tail(100),
            Duration::from_secs(10)
        ));
        assert!(done.success);
        assert!(String::from_utf8_lossy(&done.bytes).contains("done"));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "{:?}",
            start.elapsed()
        );
    }

    #[test]
    fn test_cancel_stops_a_running_command_promptly() {
        let cancel = Cancel::default();
        let flag = cancel.clone();
        let t = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            flag.cancel();
        });
        let start = Instant::now();
        let err = assert_err!(host().run(
            Path::new("/bin/sleep"),
            &["30".into()],
            Capture::Tail(10),
            Duration::from_secs(30),
            &cancel
        ));
        assert!(matches!(err, RunError::Cancelled));
        assert!(start.elapsed() < Duration::from_secs(5));
        assert_ok!(t.join());
    }

    #[test]
    fn test_a_missing_program_is_a_spawn_error_and_the_environment_is_only_the_kept_names() {
        assert!(matches!(
            assert_err!(host().run(
                Path::new("/nonexistent/prog"),
                &[],
                Capture::Tail(10),
                SECOND,
                &Cancel::default()
            )),
            RunError::Spawn { .. }
        ));
        let h = Host::new("/usr/bin:/bin", |k| (k == "HOME").then(|| "/h".into()));
        let done = assert_ok!(h.run(
            Path::new("/usr/bin/env"),
            &[],
            Capture::Tail(1000),
            SECOND,
            &Cancel::default()
        ));
        let text = String::from_utf8_lossy(&done.bytes).into_owned();
        let mut lines: Vec<&str> = text
            .lines()
            .filter(|l| {
                !l.starts_with("__CF")
                    && !l.starts_with("PWD")
                    && !l.starts_with("SHLVL")
                    && !l.starts_with("_=")
            })
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, ["HOME=/h", "PATH=/usr/bin:/bin"]);
    }
}
