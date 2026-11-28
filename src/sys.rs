// ABOUTME: Small operating-system helpers shared by the modules that touch the filesystem.
// ABOUTME: One place for symlink-loop detection, file-kind names and bounded path text in errors.
//! Shared filesystem helpers. Crate-private: nothing here is part of the public API.

use std::fs::Metadata;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use nix::libc;

use crate::text::EscapedBounded;

/// How much of a path is echoed in an error message.
const PATH_PREVIEW_CHARS: usize = 200;

/// Reports whether `error` is the OS saying "too many levels of symbolic links".
///
/// `std::io::ErrorKind::FilesystemLoop` is still unstable (library feature `io_error_more`),
/// so the raw errno is compared instead.
pub(crate) fn is_symlink_loop(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

/// A path as bounded, escaped text for an error message.
pub(crate) fn path_preview(path: &Path) -> EscapedBounded<'_> {
    EscapedBounded::new(
        path.to_str().unwrap_or("<non-UTF-8 path>"),
        PATH_PREVIEW_CHARS,
    )
}

/// A short name for what `metadata` describes, for "X is a {kind}, not a regular file".
///
/// `metadata` must come from `symlink_metadata` (or an open descriptor) for `"symlink"` to be
/// reported.
pub(crate) fn file_kind(metadata: &Metadata) -> &'static str {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_fifo() {
        "fifo"
    } else if file_type.is_char_device() || file_type.is_block_device() {
        "device"
    } else if file_type.is_socket() {
        "socket"
    } else if file_type.is_file() {
        "file"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    #[test]
    fn symlink_loop_is_recognised_by_errno() {
        assert!(is_symlink_loop(&io::Error::from_raw_os_error(libc::ELOOP)));
        assert!(!is_symlink_loop(&io::Error::from_raw_os_error(
            libc::ENOENT
        )));
        assert!(!is_symlink_loop(&io::Error::other("no errno")));
    }

    #[test]
    fn file_kind_names_every_kind_this_crate_distinguishes() {
        let dir = assert_ok!(tempfile::TempDir::new());
        let file = dir.path().join("f");
        assert_ok!(fs::write(&file, b""));
        let link = dir.path().join("l");
        assert_ok!(symlink(&file, &link));
        let fifo = dir.path().join("p");
        let status = assert_ok!(std::process::Command::new("mkfifo").arg(&fifo).status());
        assert!(status.success());
        let socket = dir.path().join("s");
        let _listener = assert_ok!(UnixListener::bind(&socket));

        let kind = |path: &Path| file_kind(&assert_ok!(fs::symlink_metadata(path)));
        assert_eq!(kind(&file), "file");
        assert_eq!(kind(dir.path()), "directory");
        assert_eq!(kind(&link), "symlink");
        assert_eq!(kind(&fifo), "fifo");
        assert_eq!(kind(&socket), "socket");
        assert_eq!(kind(Path::new("/dev/null")), "device");
    }

    #[test]
    fn file_kind_does_not_report_a_symlink_for_followed_metadata() {
        let dir = assert_ok!(tempfile::TempDir::new());
        let file = dir.path().join("f");
        assert_ok!(fs::write(&file, b""));
        let link = dir.path().join("l");
        assert_ok!(symlink(&file, &link));
        assert_eq!(file_kind(&assert_ok!(fs::metadata(&link))), "file");
    }

    #[test]
    fn path_preview_escapes_and_bounds() {
        let hostile = format!("/a\u{1b}[2J{}", "b".repeat(500));
        let shown = path_preview(Path::new(&hostile)).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.ends_with("..."), "{shown:?}");
        assert!(shown.chars().count() < 300, "{}", shown.len());
    }
}

/// Why [`run_bounded`] gave no output.
#[derive(Debug)]
pub(crate) enum BoundedError {
    /// The program could not be started.
    Spawn(io::Error),
    /// It ran past the time allowed and its process group was killed.
    TimedOut,
    /// The caller's cancel flag was set and its process group was killed.
    Cancelled,
}

/// What a program that ended on its own left behind.
#[derive(Debug)]
pub(crate) struct Finished {
    /// How it ended.
    pub(crate) status: std::process::ExitStatus,
    /// What it wrote to standard output, up to the limit.
    pub(crate) stdout: Vec<u8>,
    /// Whether it wrote more than the limit, so `stdout` is a prefix.
    pub(crate) truncated: bool,
}

/// Runs `command` with no input, its standard output captured (up to `max_bytes`) and its
/// standard error dropped, in a process group of its own that is killed at `timeout`.
///
/// The reader of the output is not waited for after a timeout: a program that escaped the group
/// could still hold the pipe, and the reader ends by itself when the pipe closes. After the program
/// ends on its own the reader gets the rest of the deadline, and a descendant that still holds the
/// pipe past it is killed with the group and reported as a timeout.
pub(crate) fn run_bounded(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
    max_bytes: u64,
) -> Result<Finished, BoundedError> {
    run_cancellable(command, timeout, max_bytes, None)
}

/// [`run_bounded`] with cancellation checked during both execution and output draining.
/// Checks are spaced about 5 ms apart; process reaping is not a hard real-time operation.
pub(crate) fn run_cancellable(
    command: &mut std::process::Command,
    timeout: std::time::Duration,
    max_bytes: u64,
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Finished, BoundedError> {
    use std::io::Read;
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    let mut child = command.spawn().map_err(BoundedError::Spawn)?;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err(BoundedError::Spawn(io::Error::other(
            "no pipe for standard output",
        )));
    };
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        // One byte more than allowed tells a full read from a cut one.
        let _ = stdout
            .take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes);
        let _ = sender.send(bytes);
    });
    let deadline = Instant::now() + timeout;
    let mut status = None;
    let mut output = None;
    let status = loop {
        let wait_failed = if status.is_none() {
            match child.try_wait() {
                Ok(observed) => {
                    status = observed;
                    false
                }
                Err(_) => true,
            }
        } else {
            false
        };
        if output.is_none() {
            match receiver.try_recv() {
                Ok(bytes) => output = Some(bytes),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    kill_bounded_group(&mut child);
                    return Err(BoundedError::Spawn(io::Error::other(
                        "the output reader failed",
                    )));
                }
            }
        }
        if let Some(status) = status
            && output.is_some()
        {
            break status;
        }
        let cancelled = cancel.is_some_and(|flag| flag.load(Ordering::SeqCst));
        if cancelled || wait_failed || Instant::now() >= deadline {
            kill_bounded_group(&mut child);
            return Err(if cancelled {
                BoundedError::Cancelled
            } else {
                BoundedError::TimedOut
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    };
    let mut stdout = output.unwrap_or_default();
    let truncated = u64::try_from(stdout.len()).is_ok_and(|len| len > max_bytes);
    stdout.truncate(usize::try_from(max_bytes).unwrap_or(usize::MAX));
    Ok(Finished {
        status,
        stdout,
        truncated,
    })
}

fn kill_bounded_group(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    let _ = child.wait();
}

#[cfg(test)]
mod bounded_tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::process::Command;
    use std::time::{Duration, Instant};

    fn sh(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        command
    }

    #[test]
    fn a_program_that_ends_gives_its_status_and_its_output() {
        let done = assert_ok!(run_bounded(
            &mut sh("echo out; echo err >&2; exit 3"),
            Duration::from_secs(10),
            1024
        ));
        assert_eq!(done.status.code(), Some(3));
        assert_eq!(done.stdout, b"out\n");
    }

    #[test]
    fn output_beyond_the_limit_is_cut_and_the_program_is_not_blocked() {
        let done = assert_ok!(run_bounded(
            &mut sh("yes | head -c 100000"),
            Duration::from_secs(10),
            100
        ));
        assert_eq!(done.stdout.len(), 100);
        assert!(done.truncated);
    }

    #[test]
    fn output_of_exactly_the_limit_is_not_truncated() {
        let done = assert_ok!(run_bounded(
            &mut sh("printf abcd"),
            Duration::from_secs(10),
            4
        ));
        assert_eq!(done.stdout, b"abcd");
        assert!(!done.truncated);
    }

    #[test]
    fn a_descendant_that_holds_the_pipe_after_the_program_ends_is_a_timeout_not_a_hang() {
        let started = Instant::now();
        let result = run_bounded(
            &mut sh("sleep 20 & exit 0"),
            Duration::from_millis(300),
            1024,
        );
        assert!(matches!(result, Err(BoundedError::TimedOut)), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_program_that_runs_too_long_is_killed_with_what_it_started() {
        let started = Instant::now();
        let result = run_bounded(&mut sh("sleep 20 & wait"), Duration::from_millis(300), 1024);
        assert!(matches!(result, Err(BoundedError::TimedOut)), "{result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_timeout_kills_the_descendants_not_only_the_leader() {
        let dir = assert_ok!(tempfile::tempdir());
        let pid_file = dir.path().join("pid");
        let script = format!("sleep 60 & echo $! > '{}'; wait", pid_file.display());
        // Long enough that a loaded machine has written the pid file before the kill; the test
        // still ends at the timeout, not when the sleeping child does.
        let result = run_bounded(&mut sh(&script), Duration::from_secs(3), 1024);
        assert!(matches!(result, Err(BoundedError::TimedOut)), "{result:?}");
        let pid: i32 = assert_ok!(
            assert_ok!(std::fs::read_to_string(&pid_file))
                .trim()
                .parse()
        );
        let pid = nix::unistd::Pid::from_raw(pid);
        // The kill is delivered before run_bounded returns; allow the kernel a moment to reap it.
        let gone = (0..50).any(|_| {
            std::thread::sleep(Duration::from_millis(20));
            nix::sys::signal::kill(pid, None).is_err()
        });
        if !gone {
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
        }
        assert!(gone, "the descendant outlived the timeout");
    }

    #[test]
    fn a_cancelled_program_is_killed_with_what_it_started_and_reported_as_cancelled() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let flag = Arc::new(AtomicBool::new(false));
        let setter = Arc::clone(&flag);
        let timer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            setter.store(true, Ordering::SeqCst);
        });
        let started = Instant::now();
        let result = run_cancellable(
            &mut sh("sleep 20 & wait"),
            Duration::from_secs(60),
            1024,
            Some(&flag),
        );
        assert!(matches!(result, Err(BoundedError::Cancelled)), "{result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
        assert_ok!(timer.join());
    }

    #[test]
    fn timeout_still_applies_after_the_leader_exits_with_stdout_held_open() {
        let result = run_bounded(
            &mut sh("sleep 2 & exit 3"),
            Duration::from_millis(100),
            1024,
        );
        assert!(matches!(result, Err(BoundedError::TimedOut)), "{result:?}");
    }

    #[test]
    fn cancellation_still_applies_after_the_leader_has_been_reaped() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = assert_ok!(tempfile::TempDir::new());
        let marker = dir.path().join("leader");
        let flag = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let timer = scope.spawn(|| {
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if let Some(pid) = std::fs::read_to_string(&marker)
                        .ok()
                        .and_then(|s| s.trim().parse::<i32>().ok())
                        .filter(|pid| *pid > 1)
                        && nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None)
                            == Err(nix::errno::Errno::ESRCH)
                    {
                        flag.store(true, Ordering::SeqCst);
                        return;
                    }
                    assert!(Instant::now() < deadline, "leader was never reaped");
                    std::thread::sleep(Duration::from_millis(5));
                }
            });
            let result = run_cancellable(
                &mut sh(&format!(
                    "sleep 2 & echo $$ > '{}'; exit 3",
                    marker.display()
                )),
                Duration::from_secs(10),
                1024,
                Some(&flag),
            );
            assert_ok!(timer.join());
            assert!(matches!(result, Err(BoundedError::Cancelled)), "{result:?}");
        });
    }

    #[test]
    fn output_arriving_after_leader_exit_is_preserved_with_its_exit_status() {
        let done = assert_ok!(run_bounded(
            &mut sh("(sleep 0.1; printf late) & exit 3"),
            Duration::from_secs(10),
            1024,
        ));
        assert_eq!(done.status.code(), Some(3));
        assert_eq!(done.stdout, b"late");
    }

    #[test]
    fn a_cancel_flag_that_is_never_set_changes_nothing() {
        let flag = std::sync::atomic::AtomicBool::new(false);
        let done = assert_ok!(run_cancellable(
            &mut sh("echo ok"),
            Duration::from_secs(10),
            64,
            Some(&flag)
        ));
        assert_eq!(done.stdout, b"ok\n");
    }

    #[test]
    fn a_program_that_cannot_start_is_a_spawn_error() {
        let result = run_bounded(
            &mut Command::new("/nonexistent/program"),
            Duration::from_secs(1),
            1,
        );
        assert!(matches!(result, Err(BoundedError::Spawn(_))), "{result:?}");
    }

    #[test]
    fn standard_input_is_closed() {
        let done = assert_ok!(run_bounded(
            &mut sh("cat; echo done"),
            Duration::from_secs(5),
            64
        ));
        assert_eq!(done.stdout, b"done\n");
    }
}
