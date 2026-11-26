// ABOUTME: The supervisor binary on a real pty: the owner's terminal is restored after quit, panic and SIGTERM, a review is handed the terminal, and agents never outlive the supervisor.
// ABOUTME: A pty master stands in for the owner; its output is read raw, so the mode resets can be seen as bytes. Every wait has a deadline.
//! `hb-supervise` end to end (hb-q9o).

#![cfg(target_os = "macos")]

mod common;

use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use claims::{assert_ok, assert_some};
use common::{World, sandbox_available};
use hamster_ball::session::{Pty, Winsize};
use hamster_ball::supervise::terminal::SessionScreen;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use pretty_assertions::assert_eq;

const SUPERVISE: &str = env!("CARGO_BIN_EXE_hb-supervise");
const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

/// Makes the pty on stdin the controlling terminal, as a terminal emulator does, then execs.
const LAUNCHER: &str = "use POSIX; POSIX::setsid(); ioctl(STDIN, 0x20007461, 0); \
$ENV{TERM}=q(xterm-256color); exec @ARGV or die qq(exec: $!)";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// The supervisor running on a pty that this test is the terminal for.
struct Owner {
    child: Child,
    master: File,
    bytes: Arc<Mutex<Vec<u8>>>,
    /// What the owner would see: the same bytes through a terminal emulator.
    seen: Arc<Mutex<SessionScreen>>,
}

impl Owner {
    fn start(w: &World, extra: &[(&str, &str)]) -> Self {
        w.approve();
        let pty = assert_ok!(Pty::open());
        assert_ok!(pty.set_size(Winsize {
            ws_row: 30,
            ws_col: 120,
            ws_xpixel: 0,
            ws_ypixel: 0
        }));
        let (stdin, stdout, stderr) = assert_ok!(pty.child_stdio());
        let mut cmd = Command::new("/usr/bin/perl");
        cmd.args(["-e", LAUNCHER, SUPERVISE])
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HB_SUPERVISE_HB", DRIVE)
            .env("HB_TD_HOME", w.home_dir())
            .env("HB_TD_CWD", &w.project)
            .env("HB_TD_PATH", w.base.join("bin"))
            .env("HB_TD_TMP", w.base.join("tmp"))
            .env("HB_TD_GRACE_MS", "2000")
            .current_dir(&w.project)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr);
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let child = assert_ok!(cmd.spawn());
        let mut reading = assert_ok!(pty.clone_master());
        let master = pty.release_slave();
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&bytes);
        let seen = Arc::new(Mutex::new(SessionScreen::new(30, 120)));
        let feed = Arc::clone(&seen);
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = reading.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if let Ok(mut all) = sink.lock() {
                    all.extend_from_slice(&buffer[..n]);
                }
                if let Ok(mut screen) = feed.lock() {
                    screen.process(&buffer[..n]);
                }
            }
        });
        Self {
            child,
            master,
            bytes,
            seen,
        }
    }

    fn text(&self) -> String {
        self.bytes
            .lock()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    }

    fn send(&mut self, bytes: &[u8]) {
        assert_ok!(self.master.write_all(bytes));
    }

    /// The screen as the owner sees it.
    fn screen(&self) -> String {
        self.seen.lock().map(|s| s.text()).unwrap_or_default()
    }

    fn wait_for(&self, needle: &str, secs: u64) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.screen().contains(needle) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_ok!(Err::<(), String>(format!(
            "never saw {needle:?}; the screen was:\n{}",
            self.screen()
        )));
    }

    /// Waits for the supervisor to end and returns its exit code.
    fn exit_code(&mut self, secs: u64) -> Option<i32> {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if let Some(status) = assert_ok!(self.child.try_wait()) {
                return status.code();
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        assert_ok!(Err::<(), String>(format!(
            "the supervisor did not end; output:\n{:?}",
            self.text()
        )));
        None
    }

    /// The text after the first time the alternate screen was left.
    fn after_leaving(&self) -> Option<String> {
        let text = self.text();
        text.find("\x1b[?1049l")
            .map(|at| text[at + "\x1b[?1049l".len()..].to_owned())
    }
}

impl Drop for Owner {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Every mode the supervisor turned on has been turned off again.
fn assert_restored(owner: &Owner) {
    let text = owner.text();
    for (on, off) in [
        ("\x1b[?1049h", "\x1b[?1049l"),
        ("\x1b[?2004h", "\x1b[?2004l"),
        ("\x1b[?1004h", "\x1b[?1004l"),
        ("\x1b[?25l", "\x1b[?25h"),
    ] {
        let turned_on = assert_some!(text.rfind(on), "{on:?} never set; {text:?}");
        let turned_off = assert_some!(text.rfind(off), "{off:?} never reset; {text:?}");
        assert!(
            turned_off > turned_on,
            "{off:?} came before {on:?}: {text:?}"
        );
    }
}

fn alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

#[test]
fn quitting_with_nothing_running_restores_every_terminal_mode_and_exits_cleanly() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut owner = Owner::start(&w, &[]);
    owner.wait_for("Sessions", 30);
    owner.send(b"q");
    assert_eq!(owner.exit_code(30), Some(0));
    assert_restored(&owner);
}

#[test]
fn a_panic_while_drawing_restores_the_terminal_before_the_message_and_ends_nonzero() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut owner = Owner::start(&w, &[("HB_SUPERVISE_TEST_PANIC", "1")]);
    assert_eq!(owner.exit_code(30), Some(1));
    assert_restored(&owner);
    let after = assert_some!(owner.after_leaving());
    assert!(
        after.contains("test panic while drawing"),
        "the message must come after the terminal is back: {after:?}"
    );
}

#[test]
fn a_session_does_not_outlive_a_supervisor_that_is_killed() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.project.join("agent.pid");
    // The form splits on spaces and does not quote, so the agent is a script file.
    let script = w.project.join("agent.sh");
    common::write(
        &script,
        &format!("echo $$ > '{}'\nsleep 300\n", marker.display()),
    );
    let mut owner = Owner::start(&w, &[]);
    owner.wait_for("Sessions", 30);
    // Launch through the form: n, the command, Enter.
    owner.send(b"n");
    owner.wait_for("Launch a session", 10);
    for key in format!("/bin/sh {}\r", script.display()).bytes() {
        owner.send(&[key]);
    }
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        marker.exists(),
        "no agent started; the screen was:\n{}",
        owner.screen()
    );
    let pid: i32 = assert_some!(
        std::fs::read_to_string(&marker)
            .ok()
            .and_then(|t| t.trim().parse().ok())
    );
    assert!(alive(pid));
    assert_ok!(kill(
        Pid::from_raw(owner.child.id() as i32),
        Signal::SIGKILL
    ));
    let deadline = Instant::now() + Duration::from_secs(30);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!alive(pid), "the agent outlived a killed supervisor");
}
