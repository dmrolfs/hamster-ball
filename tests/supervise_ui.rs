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
///
/// It also puts INT, QUIT, HUP and TERM back to their defaults: a process started from a background
/// job or under `nohup` has some of them ignored, an ignored signal stays ignored through exec, and
/// this test run may itself have been started that way (as `common::drive` also guards against).
const LAUNCHER: &str = "use POSIX; $SIG{$_}='DEFAULT' for qw(INT QUIT HUP TERM); \
POSIX::setsid(); ioctl(STDIN, 0x20007461, 0); \
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
        Self::start_unapproved(w, extra)
    }

    /// Like [`Owner::start`] without approving the project's config first.
    fn start_unapproved(w: &World, extra: &[(&str, &str)]) -> Self {
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

#[test]
fn sigterm_and_sighup_restore_the_terminal_and_stop_the_agent_before_exiting() {
    sandboxed!();
    for signal in [Signal::SIGTERM, Signal::SIGHUP] {
        let w = World::new(PROJECT);
        let marker = w.project.join("agent.pid");
        let script = w.project.join("agent.sh");
        common::write(
            &script,
            &format!("echo $$ > '{}'\nsleep 300\n", marker.display()),
        );
        let mut owner = Owner::start(&w, &[]);
        owner.wait_for("Sessions", 30);
        owner.send(b"n");
        owner.wait_for("Launch a session", 10);
        for key in format!("/bin/sh {}\r", script.display()).bytes() {
            owner.send(&[key]);
        }
        let deadline = Instant::now() + Duration::from_secs(60);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(marker.exists(), "{signal:?}: no agent; {}", owner.screen());
        let pid: i32 = assert_some!(
            std::fs::read_to_string(&marker)
                .ok()
                .and_then(|t| t.trim().parse().ok())
        );
        assert_ok!(kill(Pid::from_raw(owner.child.id() as i32), signal));
        // Not 0: the owner did not ask for this. Not a signal death either: it ended itself.
        assert_eq!(owner.exit_code(60), Some(0), "{signal:?}");
        assert_restored(&owner);
        assert!(!alive(pid), "{signal:?}: the agent outlived the supervisor");
    }
}

/// Waits until `path` exists, or `secs` pass.
fn appears(path: &std::path::Path, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !path.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    path.exists()
}

#[test]
fn keys_typed_behind_the_review_key_act_on_nothing_and_a_fresh_answer_starts_the_agent() {
    sandboxed!();
    let w = World::new(PROJECT);
    let ran = w.project.join("ran");
    let script = w.project.join("agent.sh");
    common::write(&script, &format!("touch '{}'\nsleep 300\n", ran.display()));
    let mut owner = Owner::start_unapproved(&w, &[]);
    owner.wait_for("Sessions", 30);
    owner.send(b"n");
    owner.wait_for("Launch a session", 10);
    for key in format!("/bin/sh {}\r", script.display()).bytes() {
        owner.send(&[key]);
    }
    owner.wait_for("Approve", 60);
    assert!(!ran.exists(), "the agent ran without approval");
    // `a` asks for the review. The `q` typed right behind it is stale by the time the review
    // ends: if it were applied to the UI afterwards, the supervisor would quit.
    owner.send(b"aq");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !owner.text().contains("Approve this config?") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        owner.text().contains("Approve this config?"),
        "{:?}",
        owner.text()
    );
    assert!(
        owner.text().contains("\x1b[?1049l"),
        "the review must run on the real screen"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert!(!ran.exists(), "the review was answered by itself");
    assert_eq!(
        assert_ok!(owner.child.try_wait()),
        None,
        "the supervisor quit on a stale key"
    );
    // A fresh answer approves, and the same session starts again.
    owner.send(b"y\n");
    assert!(
        appears(&ran, 20),
        "approved, but the agent never started; the screen:\n{}\nraw tail: {:?}",
        owner.screen(),
        owner
            .text()
            .chars()
            .rev()
            .take(1500)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    );
    owner.wait_for("Running", 30);
    // The stale `q` did nothing; the UI is back and takes a fresh one.
    assert_eq!(
        assert_ok!(owner.child.try_wait()),
        None,
        "a stale key quit the UI"
    );
    owner.send(b"q");
    owner.send(b"y");
    assert_eq!(owner.exit_code(60), Some(0));
    assert_restored(&owner);
}

/// Starts an unapproved session and asks for its review, leaving the prompt on screen unanswered.
fn start_review(w: &World) -> Owner {
    let script = w.project.join("agent.sh");
    common::write(&script, "sleep 300\n");
    let mut owner = Owner::start_unapproved(w, &[]);
    owner.wait_for("Sessions", 30);
    owner.send(b"n");
    owner.wait_for("Launch a session", 10);
    for key in format!("/bin/sh {}\r", script.display()).bytes() {
        owner.send(&[key]);
    }
    owner.wait_for("Approve", 60);
    owner.send(b"a");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !owner.text().contains("Approve this config?") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        owner.text().contains("Approve this config?"),
        "{:?}",
        owner.text()
    );
    owner
}

#[test]
fn sigterm_during_a_review_ends_the_supervisor_instead_of_only_the_review() {
    sandboxed!();
    for signal in [Signal::SIGTERM, Signal::SIGHUP] {
        let w = World::new(PROJECT);
        let mut owner = start_review(&w);
        assert_ok!(kill(Pid::from_raw(owner.child.id() as i32), signal));
        assert_eq!(owner.exit_code(60), Some(0), "{signal:?}");
        assert_restored(&owner);
    }
}

#[test]
fn ctrl_c_during_a_review_cancels_the_review_and_returns_to_the_ui_with_the_row_unchanged() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut owner = start_review(&w);
    // The review runs with the terminal cooked, so Ctrl-C is a signal to the foreground group.
    owner.send(&[0x03]);
    owner.wait_for("Approve", 30);
    owner.wait_for("OVERVIEW", 30);
    assert_eq!(
        assert_ok!(owner.child.try_wait()),
        None,
        "Ctrl-C ended the supervisor"
    );
    assert!(!w.project.join("ran").exists());
    owner.send(b"q");
    assert_eq!(owner.exit_code(60), Some(0));
    assert_restored(&owner);
}

#[test]
fn an_agent_that_never_reads_cannot_freeze_the_ui_and_quit_still_stops_it() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.project.join("agent.pid");
    let script = w.project.join("agent.sh");
    // Raw mode and no reading: the pty fills instead of discarding what it is sent.
    common::write(
        &script,
        &format!(
            "echo $$ > '{}'\nstty raw -echo\nsleep 300\n",
            marker.display()
        ),
    );
    let mut owner = Owner::start(&w, &[]);
    owner.wait_for("Sessions", 30);
    owner.send(b"n");
    owner.wait_for("Launch a session", 10);
    for key in format!("/bin/sh {}\r", script.display()).bytes() {
        owner.send(&[key]);
    }
    assert!(appears(&marker, 60), "no agent; {}", owner.screen());
    // The file exists as soon as the shell opens it; wait until the pid is in it.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut pid = None;
    while pid.is_none() && Instant::now() < deadline {
        pid = std::fs::read_to_string(&marker)
            .ok()
            .and_then(|t| t.trim().parse::<i32>().ok());
        std::thread::sleep(Duration::from_millis(20));
    }
    let pid = assert_some!(pid, "the agent never wrote its pid");
    owner.wait_for("Running", 30);
    // Interact, then type far more than a pty holds, as a stream of pastes.
    owner.send(b"\r");
    owner.wait_for("INTERACT", 10);
    // Pastes as a terminal sends them (bracketed paste is on): 64 x 16 KiB. Raw bytes would be one
    // key press each, which says nothing about writing to the agent.
    let mut paste = b"\x1b[200~".to_vec();
    paste.extend(std::iter::repeat_n(b'x', 16 * 1024));
    paste.extend_from_slice(b"\x1b[201~");
    let sending = Instant::now();
    for _ in 0..64 {
        owner.send(&paste);
    }
    // Sending is the test's own cost; the supervisor must not make it wait on the agent.
    assert!(
        sending.elapsed() < Duration::from_secs(10),
        "sending took {:?}",
        sending.elapsed()
    );
    // Leave Interact. The loop must still answer keys (the status bar changes) within a few
    // seconds, which it could not if it were stuck writing to the agent.
    let started = Instant::now();
    owner.send(&[0x07]);
    owner.wait_for("OVERVIEW", 5);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "the UI stalled for {:?}",
        started.elapsed()
    );
    // Quit confirms and stops the agent although its terminal is full.
    owner.send(b"q");
    owner.send(b"y");
    assert_eq!(owner.exit_code(60), Some(0));
    assert_restored(&owner);
    let deadline = Instant::now() + Duration::from_secs(20);
    while alive(pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(!alive(pid), "the agent outlived quit");
}

#[test]
fn a_panic_in_a_session_thread_restores_the_terminal_stops_the_agent_and_ends_nonzero() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.project.join("agent.pid");
    let script = w.project.join("agent.sh");
    common::write(
        &script,
        &format!("echo $$ > '{}'\nsleep 300\n", marker.display()),
    );
    // The variable is set for the supervisor and so for its threads; the sessions it starts are
    // separate processes and unaffected. Only the first session's reader thread panics.
    let mut owner = Owner::start(&w, &[("HB_SUPERVISE_TEST_WORKER_PANIC", "1")]);
    owner.wait_for("Sessions", 30);
    owner.send(b"n");
    owner.wait_for("Launch a session", 10);
    for key in format!("/bin/sh {}\r", script.display()).bytes() {
        owner.send(&[key]);
    }
    // The panic happens as the session starts: the supervisor ends, nonzero, terminal restored.
    assert_eq!(owner.exit_code(60), Some(1), "{}", owner.screen());
    assert_restored(&owner);
    let after = assert_some!(owner.after_leaving());
    assert!(after.contains("test panic in a worker thread"), "{after:?}");
    // Whatever agent was started is gone.
    if let Some(pid) = std::fs::read_to_string(&marker)
        .ok()
        .and_then(|t| t.trim().parse::<i32>().ok())
    {
        let deadline = Instant::now() + Duration::from_secs(20);
        while alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        assert!(!alive(pid), "the agent outlived a worker panic");
    }
}

/// The pid of the `hb approve` the supervisor started, if there is one.
fn approve_pid(supervisor: u32) -> Option<i32> {
    let out = std::process::Command::new("/bin/ps")
        .args(["-o", "pid=,ppid=,command=", "-ax"])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            let pid: i32 = parts.next()?.parse().ok()?;
            let ppid: u32 = parts.next()?.parse().ok()?;
            let command: Vec<&str> = parts.collect();
            (ppid == supervisor && command.contains(&"approve")).then_some(pid)
        })
}

#[test]
fn hb_approve_started_by_the_supervisor_can_be_ended_by_sigterm_and_sigint_on_its_own() {
    sandboxed!();
    for signal in [Signal::SIGTERM, Signal::SIGINT] {
        let w = World::new(PROJECT);
        let owner = start_review(&w);
        let pid = assert_some!(approve_pid(owner.child.id()), "no approve process found");
        // The signal goes to the review alone, as `kill <pid>` from another terminal would.
        assert_ok!(kill(Pid::from_raw(pid), signal));
        let deadline = Instant::now() + Duration::from_secs(10);
        while alive(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            !alive(pid),
            "{signal:?} did not end hb approve: the signal is blocked in it"
        );
    }
}
