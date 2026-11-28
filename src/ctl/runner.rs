// ABOUTME: Runs one host command with an absolute deadline, a cancel flag, a combined output tail and a process-group kill.
// ABOUTME: Replaces `sys::run_bounded` for the broker: that one drops stderr, keeps a prefix, and can wait on a pipe a descendant holds.
//! The bounded runner (hb-ghd.8.1).

use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::os::fd::AsFd;
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
use crate::session::custody::{Group, Lease, Permit};
use crate::session::guardian::{GuardianError, LaunchHandle};
use crate::session::launch::{GateError, prepare_launch};
use crate::session::launch_end::{CLEANUP_BUDGET, EndPhase, EndStatus};

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
    /// No child was spawned because cleanup capacity or its worker was unavailable.
    #[snafu(display("child cleanup could not be reserved"))]
    Custody {
        /// The allocation or worker failure.
        source: crate::session::custody::CustodyError,
    },
    /// The command ended without confirmed cleanup.
    #[snafu(display("command cleanup did not finish"))]
    Cleanup,
    /// Cleanup failed as well as, or after, the command operation.
    #[snafu(display("command cleanup failed after the command operation"))]
    Finalize {
        /// The command failure, if any, retained independently of cleanup.
        command_error: Option<Box<RunError>>,
        /// Observed exit code, if the command was reaped.
        code: Option<i32>,
    },
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
    /// The launch gate did not open, so the command never ran.
    #[snafu(display("the launch gate did not open"))]
    Gate {
        /// Why.
        source: GateError,
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
    /// `hb` itself, which runs `__exec` so the command waits at the gate until it is protected.
    helper: Option<PathBuf>,
    custody: Group,
    cleanup_failed: Arc<AtomicBool>,
    stop: Option<Arc<crate::session::signals::StopSignal>>,
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
        Self {
            env,
            guard: None,
            helper: None,
            custody: Group::new(14),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
            stop: None,
        }
    }

    pub(crate) fn with_stop(mut self, stop: Arc<crate::session::signals::StopSignal>) -> Self {
        self.stop = Some(stop);
        self
    }

    fn fail_cleanup(&self) {
        self.cleanup_failed.store(true, Ordering::Release);
        if let Some(stop) = &self.stop {
            stop.request();
        }
    }

    pub(crate) fn cleanup_failed(&self) -> bool {
        self.cleanup_failed.load(Ordering::Acquire)
    }

    /// Registers every command's process group with the cleanup guard, so a killed `hb` does not
    /// leave one running. The command starts as `helper __exec`, waits at the launch gate until the
    /// guard has armed its group, and only then execs, so no host command runs unprotected. A
    /// command the guard does not arm never runs and is reported as [`RunError::Guard`].
    #[must_use]
    pub fn with_guard(mut self, guard: GuardHandle, helper: PathBuf) -> Self {
        self.guard = Some(guard);
        self.helper = Some(helper);
        self
    }
}

const POLL: Duration = Duration::from_millis(5);

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

fn reader(
    mut pipe: impl Read + AsFd + Send + 'static,
    tail: Option<Arc<Mutex<Tail>>>,
    stop: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    let flags = rustix::fs::fcntl_getfl(&pipe)?;
    rustix::fs::fcntl_setfl(&pipe, flags | rustix::fs::OFlags::NONBLOCK)?;
    thread::Builder::new().spawn(move || {
        let mut chunk = [0u8; 4096];
        loop {
            if stop.load(Ordering::Acquire) {
                return;
            }
            match pipe.read(&mut chunk) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if let Some(tail) = &tail
                        && let Ok(mut t) = tail.lock()
                    {
                        t.push(&chunk[..n]);
                    }
                }
            }
        }
    })
}

fn kill_group(child: &Child) -> std::io::Result<()> {
    let pid = i32::try_from(child.id()).map_err(std::io::Error::other)?;
    let wait_pid = rustix::process::Pid::from_raw(pid)
        .ok_or_else(|| std::io::Error::other("invalid child pid"))?;
    // ECHILD means a foreign waiter released our ownership; never signal that number.
    let observed = rustix::process::waitid(
        rustix::process::WaitId::Pid(wait_pid),
        rustix::process::WaitIdOptions::EXITED
            | rustix::process::WaitIdOptions::NOWAIT
            | rustix::process::WaitIdOptions::NOHANG,
    )?;
    match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
        Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
        Err(nix::errno::Errno::EPERM)
            if observed.is_some()
                && crate::session::identity::group_members(pid)
                    .is_ok_and(|members| members.iter().all(|member| *member == pid)) =>
        {
            Ok(())
        }
        Err(error) => Err(error.into()),
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
        if self.cleanup_failed() {
            return Err(RunError::Cleanup);
        }
        let permit = self.custody.reserve().context(CustodySnafu)?;
        let (limit, whole) = match capture {
            Capture::Tail(n) => (n, false),
            Capture::Whole(n) => (n, true),
        };
        let gated = self.guard.as_ref().zip(self.helper.as_ref());
        let mut command = match gated {
            Some((_, helper)) => {
                let mut command = Command::new(helper);
                command.arg("__exec").arg(program);
                command
            }
            None => Command::new(program),
        };
        command
            .args(argv)
            .env_clear()
            .envs(self.env.iter().map(|(k, v)| (k, v)))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Its own group from the first instruction, so a Ctrl-C aimed at hb's foreground group
            // cannot kill a helper that is still parked at the gate.
            .process_group(0);
        let (mut child, launch, gate) = match gated {
            Some((guard, _)) => {
                let (child, launch, gate) = gated_start(&mut command, guard, program, permit)?;
                (child, Some(launch), Some(gate))
            }
            None => {
                command.stdin(Stdio::null());
                (
                    permit.install(command.spawn().context(SpawnSnafu { program })?),
                    None,
                    None,
                )
            }
        };
        let tail = Arc::new(Mutex::new(Tail {
            buf: VecDeque::new(),
            limit,
            truncated: false,
            whole,
        }));
        let stop_readers = Arc::new(AtomicBool::new(false));
        let outcome = (|| {
            if let Some(out) = child.stdout.take() {
                child.adopt_reader(
                    reader(out, Some(tail.clone()), stop_readers.clone()).context(WaitSnafu)?,
                );
            }
            if let Some(err) = child.stderr.take() {
                child.adopt_reader(
                    reader(err, (!whole).then(|| tail.clone()), stop_readers.clone())
                        .context(WaitSnafu)?,
                );
            }
            if let Some(gate) = gate {
                gate.release().context(GateSnafu)?;
            }
            wait(&mut child, timeout, cancel)
        })();
        let cleanup_by = Instant::now() + CLEANUP_BUDGET;
        let handover = launch
            .as_ref()
            .map(|launch| end_until(launch, EndPhase::Pinned, cleanup_by));
        // Whatever happened, signal while this parent still owns the unreaped leader.
        let signalled = kill_group(&child);
        let final_handover = launch
            .as_ref()
            .map(|launch| end_until(launch, EndPhase::Pinned, cleanup_by));
        let reaped = reap_until(&mut child, cleanup_by);
        let ended = if reaped.is_ok() {
            launch
                .as_ref()
                .map(|launch| end_until(launch, EndPhase::Reaped, cleanup_by))
        } else {
            None
        };
        child.join_readers(cleanup_by);
        stop_readers.store(true, Ordering::Release);
        let transferred = child.settle();
        if transferred
            || reaped.is_err()
            || signalled.is_err()
            || handover.is_some_and(|r| r.is_err())
            || final_handover.is_some_and(|r| r.is_err())
            || ended.is_some_and(|r| r.is_err())
        {
            self.fail_cleanup();
            cancel.cancel();
            return Err(RunError::Finalize {
                command_error: outcome.err().map(Box::new),
                code: reaped.as_ref().ok().and_then(ExitStatus::code),
            });
        }
        let status = reaped?;
        outcome?;
        let tail = tail.lock().map_err(|_| RunError::Wait {
            source: std::io::Error::other("output buffer poisoned"),
        })?;
        if whole && tail.truncated {
            return Err(RunError::TooLarge { limit });
        }
        Ok(finished(status, &tail))
    }
}

/// Starts `hb __exec` with the gate on stdin, sends it `/dev/null` as the command's stdin, arms
/// the guard on the group it reports, then releases it. On any failure the helper is killed while
/// it is still waiting, so the command never ran.
fn gated_start(
    command: &mut Command,
    guard: &GuardHandle,
    program: &Path,
    permit: Permit,
) -> Result<(Lease, LaunchHandle, crate::session::launch::ParentGate), RunError> {
    let spawn_error = |source| RunError::Spawn {
        program: program.to_path_buf(),
        source,
    };
    // Everything fallible is acquired before spawning, so a failure never leaves a helper unreaped.
    let null = File::open("/dev/null").map_err(spawn_error)?;
    let (child, gate, launch) = prepare_launch(
        command,
        &null,
        |child| permit.install(child),
        |lease| &mut **lease,
        |pid| guard.launch(pid).context(GuardSnafu),
        spawn_error,
        |source| RunError::Gate { source },
    )?;
    Ok((child, launch, gate))
}

fn end_until(launch: &LaunchHandle, phase: EndPhase, by: Instant) -> Result<(), RunError> {
    loop {
        match launch.end(phase, by).context(GuardSnafu)? {
            EndStatus::ReapReady if phase == EndPhase::Pinned => return Ok(()),
            EndStatus::Complete if phase == EndPhase::Reaped => return Ok(()),
            EndStatus::Pending if Instant::now() < by => thread::sleep(POLL),
            _ => return Err(RunError::Cleanup),
        }
    }
}

fn reap_until(child: &mut Child, by: Instant) -> Result<ExitStatus, RunError> {
    loop {
        if let Some(status) = child.try_wait().context(WaitSnafu)? {
            return Ok(status);
        }
        if Instant::now() >= by {
            return Err(RunError::Cleanup);
        }
        thread::sleep(POLL);
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

fn wait(child: &mut Child, timeout: Duration, cancel: &Cancel) -> Result<(), RunError> {
    let deadline = Instant::now() + timeout;
    let pid = rustix::process::Pid::from_raw(child.id() as i32).ok_or_else(|| RunError::Wait {
        source: std::io::Error::other("invalid child process number"),
    })?;
    loop {
        let observed = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED
                | rustix::process::WaitIdOptions::NOWAIT
                | rustix::process::WaitIdOptions::NOHANG,
        )
        .map_err(std::io::Error::from)
        .context(WaitSnafu)?;
        if observed.is_some() {
            return Ok(());
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
    fn a_zombie_only_group_is_resolved_but_a_reaped_number_is_not_signal_authority() {
        let mut child = assert_ok!(
            Command::new("/bin/sh")
                .args(["-c", "exit 0"])
                .process_group(0)
                .spawn()
        );
        assert_ok!(wait(&mut child, Duration::from_secs(5), &Cancel::default()));
        let pinned = kill_group(&child);
        let status = child.wait();
        assert_ok!(pinned);
        assert_ok!(status);
        let error = assert_err!(kill_group(&child));
        assert_eq!(error.raw_os_error(), Some(nix::libc::ECHILD));
    }

    #[test]
    fn observing_a_finished_command_keeps_it_unreaped_until_group_cleanup() {
        use rustix::process::{WaitId, WaitIdOptions, waitid};

        let mut child = assert_ok!(
            Command::new("/bin/sh")
                .args(["-c", "exit 7"])
                .process_group(0)
                .spawn()
        );
        let observed = wait(&mut child, SECOND, &Cancel::default());
        let pid = claims::assert_some!(rustix::process::Pid::from_raw(child.id() as i32));
        let pinned = waitid(
            WaitId::Pid(pid),
            WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT,
        );
        // Always collect the fixture before an assertion can fail.
        let reaped = child.wait();
        assert_ok!(observed);
        assert!(claims::assert_some!(assert_ok!(pinned)).exited());
        assert_eq!(assert_ok!(reaped).code(), Some(7));
    }

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
