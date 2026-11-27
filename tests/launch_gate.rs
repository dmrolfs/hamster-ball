// ABOUTME: Tests the trusted helper's guardian barrier with real processes and a Unix socket.
// ABOUTME: Agent execution requires a permit from the expected parent; parent loss and wrong identity fail closed.
//! Pre-execution registration boundary tests.
#![cfg(target_os = "macos")]
mod common;

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use claims::{assert_err, assert_ok, assert_some};
use hamster_ball::session::{Guardian, signals::Target};
use nix::unistd::Pid;
use pretty_assertions::assert_eq;

const HB: &str = env!("CARGO_BIN_EXE_hb");
const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn wait(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = assert_ok!(child.try_wait()) {
            return status;
        }
        assert!(Instant::now() < deadline, "helper did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn listener(path: &std::path::Path) -> UnixListener {
    let listener = assert_ok!(UnixListener::bind(path));
    assert_ok!(listener.set_nonblocking(true));
    listener
}

fn accept(listener: &UnixListener) -> std::os::unix::net::UnixStream {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => {
                assert_ok!(Err::<(), _>(error));
            }
        }
        assert!(Instant::now() < deadline, "helper did not connect");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn helper(path: &std::path::Path, marker: &std::path::Path, parent: u32) -> OwnedChild {
    OwnedChild(assert_ok!(
        Command::new(HB)
            .arg("__child")
            .arg("--launch-gate")
            .arg(path)
            .arg("--gate-parent")
            .arg(parent.to_string())
            .args(["--", "-p", "(version 1)(allow default)", "/usr/bin/touch"])
            .arg(marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    ))
}

#[test]
fn helper_executes_only_after_guardian_registration_and_permission() {
    if !common::sandbox_available() {
        return;
    }
    let dir = assert_ok!(tempfile::tempdir_in("/private/tmp"));
    let path = dir.path().join("gate");
    let marker = dir.path().join("ran");
    let listener = listener(&path);
    let mut child = helper(&path, &marker, std::process::id());
    let mut stream = accept(&listener);
    assert_ok!(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut ready = [0];
    assert_ok!(stream.read_exact(&mut ready));
    assert_eq!(ready, [1]);
    assert!(!marker.exists());
    let mut guard = assert_ok!(Guardian::start(std::path::Path::new(HB)));
    assert_ok!(guard.protect(Target::Child(Pid::from_raw(child.0.id() as i32))));
    assert!(!marker.exists());
    assert_ok!(std::fs::remove_file(&path));
    assert_ok!(stream.write_all(&[1]));
    assert!(wait(&mut child.0).success());
    assert!(marker.exists());
    guard.release();
}

#[test]
fn disconnected_parent_never_authorizes_agent_execution() {
    let dir = assert_ok!(tempfile::tempdir_in("/private/tmp"));
    let path = dir.path().join("gate");
    let marker = dir.path().join("ran");
    let listener = listener(&path);
    let mut child = helper(&path, &marker, std::process::id());
    let mut stream = accept(&listener);
    assert_ok!(stream.set_read_timeout(Some(Duration::from_secs(5))));
    let mut ready = [0];
    assert_ok!(stream.read_exact(&mut ready));
    drop(stream);
    assert!(!wait(&mut child.0).success());
    assert!(!marker.exists());
}

#[test]
fn wrong_parent_and_invalid_permit_never_authorize_agent_execution() {
    for wrong_parent in [true, false] {
        let dir = assert_ok!(tempfile::tempdir_in("/private/tmp"));
        let path = dir.path().join("gate");
        let marker = dir.path().join("ran");
        let listener = listener(&path);
        let parent = if wrong_parent {
            std::process::id() + 1
        } else {
            std::process::id()
        };
        let mut child = helper(&path, &marker, parent);
        let mut stream = accept(&listener);
        // A valid permit from the wrong process must not override peer authentication.
        let sent = stream.write_all(&[u8::from(wrong_parent)]);
        if !wrong_parent {
            assert_ok!(sent);
        }
        assert!(!wait(&mut child.0).success());
        assert!(!marker.exists());
    }
}

#[test]
fn guardian_rejects_a_process_that_has_already_been_reaped() {
    let mut child = OwnedChild(assert_ok!(Command::new("/usr/bin/true").spawn()));
    let pid = child.0.id();
    assert!(wait(&mut child.0).success());
    let mut guard = assert_ok!(Guardian::start(std::path::Path::new(HB)));
    assert_err!(guard.protect(Target::Child(Pid::from_raw(pid as i32))));
    guard.release();
}

#[test]
fn killing_hb_while_its_helper_waits_never_runs_the_agent() {
    parent_boundary("ready", false);
    parent_boundary("protected", false);
}

#[test]
fn production_launch_waits_for_registration_before_authorizing() {
    parent_boundary("ready", true);
    parent_boundary("protected", true);
}

fn parent_boundary(stage: &str, proceed: bool) {
    if !common::sandbox_available() {
        return;
    }
    let world = common::World::new("[fs]\nwrite = [\".\"]\n");
    let marker = world.project.join("ran");
    let ready = world.base.join("gate-ready");
    let mut command = world.drive(
        DRIVE,
        &["run", "/usr/bin/touch", assert_some!(marker.to_str())],
    );
    let mut hb = OwnedChild(assert_ok!(
        command
            .env("HB_TEST_GATE_READY", &ready)
            .env("HB_TEST_GATE_STAGE", stage)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    ));
    let deadline = Instant::now() + Duration::from_secs(15);
    while !ready.exists() {
        assert!(
            assert_ok!(hb.0.try_wait()).is_none(),
            "hb exited before the gate"
        );
        assert!(Instant::now() < deadline, "hb did not reach the gate");
        std::thread::sleep(Duration::from_millis(10));
    }
    let helper: i32 = assert_ok!(assert_ok!(std::fs::read_to_string(&ready)).trim().parse());
    // Keep the real production launch held long enough for an erroneously released agent to run.
    std::thread::sleep(Duration::from_millis(150));
    assert!(
        !marker.exists(),
        "agent ran at the {stage} boundary before authorization"
    );
    if proceed {
        assert_ok!(std::fs::write(ready.with_extension("continue"), b"go"));
        assert!(wait(&mut hb.0).success());
        assert!(marker.exists());
        return;
    }
    assert_ok!(hb.0.kill());
    assert_ok!(hb.0.wait());
    while nix::sys::signal::kill(Pid::from_raw(helper), None).is_ok() {
        assert!(
            Instant::now() < deadline,
            "waiting helper survived parent death"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!marker.exists());
}
