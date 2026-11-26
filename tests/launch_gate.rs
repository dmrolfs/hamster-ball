// ABOUTME: The launch gate end to end: nothing runs before the guard arms, and stdin survives the gate.
// ABOUTME: Uses hb-testdrive with a [ctl] config, which always starts the guardian and the gated helper.
//! hb-9lu black-box tests.

#![cfg(target_os = "macos")]

mod common;

use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use claims::assert_ok;
use common::{World, sandbox_available};
use hamster_ball::ctl::runner::{Cancel, Capture, Execute, Finished, Host, RunError};
use hamster_ball::session::pty::Pty;
use hamster_ball::session::{Guardian, GuardianError, WatchRefusal};
use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
/// `[ctl]` makes every run supervised, so the helper is always gated.
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n[ctl]\ncontainers = [\"db\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

fn world() -> World {
    World::under_symlinked_tmp("[fs]\nwrite = [\".\"]\n", PROJECT)
}

#[test]
fn binary_stdin_from_a_pipe_reaches_the_target_unchanged() {
    sandboxed!();
    let w = world();
    let mut child = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/usr/bin/od", "-An", "-tx1"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    );
    let bytes: Vec<u8> = vec![0x00, 0xff, 0x0a, 0x1b, 0x03, 0x7f];
    if let Some(mut stdin) = child.stdin.take() {
        assert_ok!(stdin.write_all(&bytes));
    }
    let out = assert_ok!(child.wait_with_output());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    let shown: String = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .collect();
    assert_eq!(shown, "00ff0a1b037f", "{stderr}");
}

#[test]
fn a_null_stdin_and_a_fast_command_still_work() {
    sandboxed!();
    let w = world();
    let out = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/bin/echo", "fast"])
            .stdin(Stdio::null())
            .output()
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"fast\n");
}

/// Starts the real helper by hand, gated, with a canary command, and returns it with our end.
fn helper(marker: &std::path::Path) -> (std::process::Child, UnixStream) {
    let (ours, theirs) = assert_ok!(UnixStream::pair());
    let child = assert_ok!(
        Command::new(DRIVE)
            .args(["__exec", "/usr/bin/touch"])
            .arg(marker)
            .stdin(Stdio::from(OwnedFd::from(theirs)))
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
    );
    (child, ours)
}

#[test]
fn nothing_runs_before_release_and_everything_runs_after() {
    let dir = assert_ok!(tempfile::tempdir());
    let marker = dir.path().join("ran");
    let (mut child, ours) = helper(&marker);
    let mut gate = hamster_ball::session::launch::ParentGate::new(ours);
    let null = assert_ok!(std::fs::File::open("/dev/null"));
    let pid = assert_ok!(gate.prepare(&null));
    assert_eq!(u32::try_from(pid).ok(), Some(child.id()));
    // Prepared, but not released: the target must not have run.
    std::thread::sleep(Duration::from_millis(300));
    assert!(!marker.exists(), "the target ran before release");
    assert!(
        assert_ok!(child.try_wait()).is_none(),
        "the helper exited early"
    );
    assert_ok!(gate.release());
    let status = assert_ok!(child.wait());
    assert!(status.success(), "{status:?}");
    assert!(marker.exists(), "the target did not run after release");
}

#[test]
fn a_parent_that_dies_before_release_leaves_nothing_run() {
    let dir = assert_ok!(tempfile::tempdir());
    let marker = dir.path().join("ran");
    let (child, ours) = helper(&marker);
    let mut gate = hamster_ball::session::launch::ParentGate::new(ours);
    let null = assert_ok!(std::fs::File::open("/dev/null"));
    assert_ok!(gate.prepare(&null));
    // Dropping our end is what a killed parent's kernel does: the helper sees end of input.
    let started = Instant::now();
    drop(gate);
    let out = assert_ok!(child.wait_with_output());
    assert!(!out.status.success());
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
    assert!(!marker.exists(), "the target ran without a release");
    assert!(String::from_utf8_lossy(&out.stderr).contains("launch gate"));
}

#[test]
fn a_silent_parent_times_out_and_nothing_runs() {
    let dir = assert_ok!(tempfile::tempdir());
    let marker = dir.path().join("ran");
    let (child, _ours) = helper(&marker);
    let started = Instant::now();
    let out = assert_ok!(child.wait_with_output());
    assert!(!out.status.success());
    let waited = started.elapsed();
    assert!(waited < Duration::from_secs(8), "{waited:?}");
    assert!(!marker.exists());
}

/// Lists every open descriptor up to the process limit, with whether it is a socket.
const ALL_FDS: &str = "use POSIX; my $max = POSIX::sysconf(POSIX::_SC_OPEN_MAX) || 1024; $max = 65536 if $max > 65536; for my $n (0..$max) { if (open(my $fh, \"<&=$n\")) { print \"$n:\", (-S $fh ? \"socket\" : \"other\"), \"\\n\" } }";

#[test]
fn only_the_three_standard_descriptors_reach_the_target_and_none_is_a_socket() {
    sandboxed!();
    let w = world();
    // A high-numbered descriptor open in the launcher must not survive either.
    let mut cmd = Command::new("/bin/sh");
    cmd.args([
        "-c",
        &format!("exec 97</dev/null; exec '{DRIVE}' run -- /usr/bin/perl -e '{ALL_FDS}'"),
    ])
    .stdin(Stdio::null());
    w.approve();
    w.drive_env_unapproved(&mut cmd);
    let out = assert_ok!(cmd.output());
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fds: Vec<u32> = text
        .lines()
        .filter_map(|l| l.split(':').next()?.parse().ok())
        .collect();
    assert_eq!(fds, vec![0, 1, 2], "{text}");
    assert!(!text.contains("socket"), "{text}");
}

#[test]
fn a_redirected_file_keeps_its_read_offset_through_the_gate() {
    sandboxed!();
    let w = world();
    let input = w.project.join("input.txt");
    common::write(&input, "skip-this\nKEEP-THIS\n");
    let mut cmd = Command::new("/bin/sh");
    // `read` consumes the first line in the launcher, so the target must start at line two.
    cmd.args([
        "-c",
        &format!(
            "exec <'{}'; read _first; exec '{DRIVE}' run -- /bin/cat",
            input.display()
        ),
    ]);
    w.approve();
    w.drive_env_unapproved(&mut cmd);
    let out = assert_ok!(cmd.output());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"KEEP-THIS\n");
}

#[test]
fn a_silent_parent_after_prepared_times_out_and_nothing_runs() {
    let dir = assert_ok!(tempfile::tempdir());
    let marker = dir.path().join("ran");
    let (child, ours) = helper(&marker);
    let mut gate = hamster_ball::session::launch::ParentGate::new(ours);
    let null = assert_ok!(std::fs::File::open("/dev/null"));
    assert_ok!(gate.prepare(&null));
    // Keep our end open and say nothing: the helper must give up within its deadline.
    let started = Instant::now();
    let out = assert_ok!(child.wait_with_output());
    let waited = started.elapsed();
    assert!(!out.status.success());
    assert!(waited < Duration::from_secs(8), "{waited:?}");
    assert!(!marker.exists(), "the target ran without a release");
    drop(gate);
}

/// A python driver for the gate protocol: start `<hb> __exec /bin/cat <file>` with the gate on
/// stdin, send /dev/null by SCM_RIGHTS, wait for prepared, release, print what cat printed.
fn exec_driver(hb: &str, file: &std::path::Path) -> String {
    format!(
        r#"import os, socket, subprocess, array
a, b = socket.socketpair()
p = subprocess.Popen(["{hb}", "__exec", "/bin/cat", "{file}"], stdin=b.fileno(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
b.close()
null = os.open("/dev/null", os.O_RDONLY)
a.sendmsg([b"stdin\n"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [null]))])
a.settimeout(5)
line = b""
while not line.endswith(b"\n"):
    c = a.recv(1)
    if not c: break
    line += c
a.sendall(b"release\n")
out = p.communicate(timeout=10)[0]
print("helper=" + line.decode().strip() + " out=[" + out.decode() + "] rc=" + str(p.returncode))
"#,
        hb = hb,
        file = file.display()
    )
}

#[test]
fn the_exec_helper_inside_the_ball_adds_no_access() {
    sandboxed!();
    let w = world();
    let canary = w.base.join("outside-canary");
    common::write(&canary, "EXEC-HELPER-CANARY");
    // Control: outside the ball, the same driver and helper read the canary.
    let outside = assert_ok!(
        Command::new("/usr/bin/python3")
            .args(["-c", &exec_driver(DRIVE, &canary)])
            .output()
    );
    let text = String::from_utf8_lossy(&outside.stdout).into_owned();
    assert!(
        text.contains("out=[EXEC-HELPER-CANARY]"),
        "control failed: {text}"
    );
    // Inside the ball, the wrapper's hb runs the same protocol under the ball's profile.
    let out = assert_ok!(
        w.drive(
            DRIVE,
            &[
                "run",
                "--",
                "/usr/bin/python3",
                "-c",
                &exec_driver("hb", &canary)
                    .replace("[\"hb\"", "[os.environ.get(\"HB_SELF\", \"hb\")"),
            ]
        )
        .stdin(Stdio::null())
        .output()
    );
    let inside = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!inside.contains("EXEC-HELPER-CANARY"), "{inside}");
    // The helper really ran inside and reported its process, so the denial is the sandbox's.
    assert!(
        inside.contains("helper=prepared "),
        "the inner driver did not reach the helper: {inside}"
    );
}

// ====================================================================================
// A guardian that refuses, and a pty agent
// ====================================================================================

/// A stand-in for `hb __guard` that answers every watch with `reply` and records the pid it was
/// asked to watch. The transport is the real one; only the answer is fixed, which is the one way
/// to get a deterministic `gone` for a helper that is parked at the gate.
fn fake_guardian(dir: &Path, reply: &str) -> (Guardian, PathBuf) {
    let log = dir.join("watched");
    let script = dir.join("fake-guard");
    let text = format!(
        r#"#!/usr/bin/python3
import os, sys
while True:
    line = sys.stdin.buffer.readline()
    if not line:
        break
    words = line.decode().split()
    if len(words) < 3 or words[0] != "ack":
        continue
    if words[2] == "watch":
        with open("{log}", "a") as f:
            f.write(words[-1] + "\n")
        out = "{reply}"
    else:
        out = "ok"
    os.write(1, (words[1] + " " + out + "\n").encode())
"#,
        log = log.display(),
    );
    common::write(&script, &text);
    assert_ok!(std::fs::set_permissions(
        &script,
        std::fs::Permissions::from_mode(0o755)
    ));
    (assert_ok!(Guardian::start(&script)), log)
}

/// Runs `touch marker` as a broker command through the gate, guarded by `guard`.
fn touch_through_gate(guard: &Guardian, marker: &Path) -> Result<Finished, RunError> {
    Host::new("/usr/bin:/bin", |_| None)
        .with_guard(guard.handle(), DRIVE.into())
        .run(
            Path::new("/usr/bin/touch"),
            &[marker.as_os_str().to_owned()],
            Capture::Tail(1024),
            Duration::from_secs(10),
            &Cancel::default(),
        )
}

/// The pid of the helper the guardian was asked to watch.
fn watched_pid(log: &Path) -> i32 {
    let text = assert_ok!(std::fs::read_to_string(log));
    let last = text.lines().last().unwrap_or("");
    assert_ok!(last.parse::<i32>())
}

fn assert_helper_reaped(pid: i32) {
    // A zombie still answers signal 0, so ESRCH means the helper was killed and waited for.
    assert_eq!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH));
}

#[test]
fn a_command_the_guard_refuses_or_reports_gone_never_runs_and_its_helper_is_reaped() {
    let cases = [
        (
            "refused kernel",
            GuardianError::Refused {
                reason: WatchRefusal::Kernel,
            },
        ),
        (
            "gone",
            // The helper is parked at the gate, so a gone answer is turned into a refusal.
            GuardianError::Refused {
                reason: WatchRefusal::Invalid,
            },
        ),
    ];
    for (reply, expected) in cases {
        let dir = assert_ok!(tempfile::tempdir());
        let marker = dir.path().join("ran");
        let (guard, log) = fake_guardian(dir.path(), reply);
        let result = touch_through_gate(&guard, &marker);
        assert!(
            matches!(&result, Err(RunError::Guard { source }) if format!("{source:?}") == format!("{expected:?}")),
            "{reply}: {result:?}"
        );
        assert_helper_reaped(watched_pid(&log));
        assert!(!marker.exists(), "{reply}: the refused command ran");
    }
}

#[test]
fn the_same_command_runs_when_the_guard_arms_it() {
    let dir = assert_ok!(tempfile::tempdir());
    let marker = dir.path().join("ran");
    let (guard, log) = fake_guardian(dir.path(), "armed");
    let done = assert_ok!(touch_through_gate(&guard, &marker));
    assert!(done.success);
    assert!(marker.exists(), "the armed command did not run");
    // The reported process is the one that ran, and it has been reaped by now.
    assert_helper_reaped(watched_pid(&log));
}

/// What the target prints on the pty: its terminal, its group and the foreground group.
const WHO: &str = "use POSIX; $|=1; \
    my $tty = POSIX::ttyname(0) // 'none'; \
    my $ctty = open(my $t, '<', '/dev/tty') ? 1 : 0; \
    print 'pid=', $$, ' tty=', $tty, ' ctty=', $ctty, \
          ' leader=', (getpgrp() == $$ ? 1 : 0), \
          ' fg=', (POSIX::tcgetpgrp(0) == getpgrp() ? 1 : 0), \"\\n\";";

/// `ps` shows a process's controlling terminal as `ttysNNN`, or `??` when it has none.
fn controlling_tty_of(pid: i32) -> String {
    let out = assert_ok!(
        Command::new("/bin/ps")
            .args(["-o", "tty=", "-p", &pid.to_string()])
            .output()
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

#[test]
fn a_pty_agent_leads_its_session_and_owns_the_terminal_before_prepared_and_in_the_foreground_after()
{
    sandboxed!();
    let pty = assert_ok!(Pty::open());
    let slave_name = pty
        .slave_path()
        .as_str()
        .trim_start_matches("/dev/")
        .to_owned();
    let (ours, theirs) = assert_ok!(UnixStream::pair());
    let (_, out, err) = assert_ok!(pty.child_stdio());
    let mut command = Command::new(DRIVE);
    // No process_group: the helper's setsid needs a process that does not lead a group.
    command
        .args(["__child", "--gate", "--controlling-tty", "--", "-p"])
        .arg("(version 1)(allow default)")
        .args(["--", "/usr/bin/perl", "-e", WHO])
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(out)
        .stderr(err);
    let mut child = assert_ok!(command.spawn());
    // The command holds copies of the slave; drop it so the master sees the end of output.
    drop(command);
    let stdin = assert_ok!(pty.slave_fd());
    let mut gate = hamster_ball::session::launch::ParentGate::new(ours);
    let pid = assert_ok!(gate.prepare(&stdin));
    drop(stdin);
    assert_eq!(u32::try_from(pid).ok(), Some(child.id()));
    // setsid ran before Prepared: the helper leads a group of its own, which it did not at spawn.
    assert_eq!(
        assert_ok!(rustix::process::getpgid(rustix::process::Pid::from_raw(
            pid
        )))
        .as_raw_nonzero()
        .get(),
        pid,
        "the helper does not lead its own group before Prepared"
    );
    // The slave is its controlling terminal before Prepared, not only after the exec.
    assert_eq!(controlling_tty_of(pid), slave_name);
    let mut master = assert_ok!(pty.clone_master());
    drop(pty.release_slave());
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut seen = Vec::new();
        let mut buf = [0u8; 256];
        // macOS ends a pty master with EIO once the last slave descriptor closes.
        while let Ok(n) = master.read(&mut buf) {
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buf[..n]);
        }
        let _ = tx.send(seen);
    });
    assert_ok!(gate.release());
    let seen = assert_ok!(rx.recv_timeout(Duration::from_secs(15)));
    let status = assert_ok!(child.wait());
    let text = String::from_utf8_lossy(&seen).replace('\r', "");
    assert!(status.success(), "{status:?} {text}");
    // Same pid all the way through the exec chain, and the slave is still its terminal.
    assert!(text.contains(&format!("pid={pid} ")), "{text}");
    assert!(text.contains(&format!("tty=/dev/{slave_name} ")), "{text}");
    assert!(text.contains("ctty=1 leader=1 fg=1"), "{text}");
}
