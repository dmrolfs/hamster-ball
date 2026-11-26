// ABOUTME: SessionScreen and the input encoder against real programs on a real pty: typing, modes, paste, resize, side effects, exit.
// ABOUTME: Scripted programs only; the opt-in real-agent checks live in tests/supervise_agents.rs. No sandbox is involved, so these never skip.
//! The terminal pane against a live pty (hb-skf).

#![cfg(target_os = "macos")]

use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use claims::assert_ok;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use hamster_ball::session::{Pty, Winsize};
use hamster_ball::supervise::input::{encode_key, encode_paste};
use hamster_ball::supervise::terminal::{SessionScreen, Suppressed};
use pretty_assertions::assert_eq;

/// Starts a new session and makes the pty on stdin its controlling terminal, as a terminal
/// emulator does, then runs the command.
const LAUNCHER: &str = "use POSIX; POSIX::setsid(); \
require q(sys/ioctl.ph) if 0; ioctl(STDIN, 0x20007461, 0); \
$ENV{TERM}=q(xterm-256color); exec @ARGV or die qq(exec: $!)";

/// A program running on a pty, its output going into a [`SessionScreen`].
struct Live {
    child: Child,
    master: File,
    screen: Arc<Mutex<SessionScreen>>,
    /// Set by the reader when the pty reports the end of the program's output.
    ended: Arc<Mutex<bool>>,
}

fn size(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

impl Live {
    fn start(rows: u16, cols: u16, argv: &[&str]) -> Self {
        let pty = assert_ok!(Pty::open());
        assert_ok!(pty.set_size(size(rows, cols)));
        let (stdin, stdout, stderr) = assert_ok!(pty.child_stdio());
        let mut cmd = Command::new("/usr/bin/perl");
        cmd.args(["-e", LAUNCHER]).args(argv);
        cmd.env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr);
        let child = assert_ok!(cmd.spawn());
        let mut reading = assert_ok!(pty.clone_master());
        let master = pty.release_slave();
        let screen = Arc::new(Mutex::new(SessionScreen::new(rows, cols)));
        let ended = Arc::new(Mutex::new(false));
        let (feed, done) = (Arc::clone(&screen), Arc::clone(&ended));
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            // Reads of any size, as a pty gives them.
            while let Ok(n) = reading.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if let Ok(mut screen) = feed.lock() {
                    screen.process(&buffer[..n]);
                }
            }
            if let Ok(mut done) = done.lock() {
                *done = true;
            }
        });
        Self {
            child,
            master,
            screen,
            ended,
        }
    }

    fn text(&self) -> String {
        self.screen.lock().map(|s| s.text()).unwrap_or_default()
    }

    /// The screen text with each run of white space made one space, for output that is padded.
    fn squeezed(&self) -> String {
        self.text().split_whitespace().collect::<Vec<_>>().join(" ")
    }

    fn suppressed(&self) -> Suppressed {
        self.screen
            .lock()
            .map(|s| s.suppressed())
            .unwrap_or_default()
    }

    fn send(&mut self, bytes: &[u8]) {
        assert_ok!(self.master.write_all(bytes));
    }

    fn key(&mut self, code: KeyCode, modifiers: KeyModifiers) {
        let modes = self.screen.lock().map(|s| s.modes()).unwrap_or_default();
        let event = KeyEvent {
            code,
            modifiers,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        };
        if let Some(bytes) = encode_key(event, modes) {
            self.send(&bytes);
        }
    }

    fn type_text(&mut self, text: &str) {
        for c in text.chars() {
            self.key(
                if c == '\n' {
                    KeyCode::Enter
                } else {
                    KeyCode::Char(c)
                },
                KeyModifiers::NONE,
            );
        }
    }

    fn paste(&mut self, text: &str) {
        let modes = self.screen.lock().map(|s| s.modes()).unwrap_or_default();
        self.send(&encode_paste(text, modes));
    }

    /// Resizes the pty and the emulator together, as the supervisor does.
    fn resize(&mut self, rows: u16, cols: u16) {
        assert_ok!(rustix::termios::tcsetwinsize(
            &self.master,
            size(rows, cols)
        ));
        if let Ok(mut screen) = self.screen.lock() {
            screen.resize(rows, cols);
        }
    }

    /// Waits until the screen text contains `needle`; fails the test with the screen after `secs`.
    fn wait_for(&self, needle: &str, secs: u64) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.text().contains(needle) || self.squeezed().contains(needle) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_ok!(Err::<(), String>(format!(
            "never saw {needle:?}; the screen was:\n{}",
            self.text()
        )));
    }

    /// Waits for the program to end and the pty to report it.
    fn finish(mut self, secs: u64) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let status = loop {
            if let Some(status) = assert_ok!(self.child.try_wait()) {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                assert_ok!(Err::<(), String>(format!(
                    "the program did not end; the screen was:\n{}",
                    self.text()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        while !self.ended.lock().map(|e| *e).unwrap_or(true) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        status
    }
}

#[test]
fn typing_into_a_shell_shows_the_command_and_its_output() {
    let mut live = Live::start(24, 80, &["/bin/sh", "-c", "PS1='$ ' exec sh -i"]);
    live.wait_for("$", 10);
    live.type_text("echo hello-from-$((6*7))\n");
    live.wait_for("hello-from-42", 10);
    live.key(KeyCode::Char('d'), KeyModifiers::CONTROL);
    assert!(live.finish(10).success());
}

#[test]
fn a_resize_reaches_the_program_and_the_emulator_together() {
    let mut live = Live::start(24, 80, &["/bin/sh", "-c", "PS1='$ ' exec sh -i"]);
    live.wait_for("$", 10);
    live.type_text("stty size\n");
    live.wait_for("24 80", 10);
    live.resize(40, 120);
    live.type_text("stty size\n");
    live.wait_for("40 120", 10);
    assert_eq!(
        live.screen.lock().map(|s| s.size()).unwrap_or_default(),
        (40, 120)
    );
    live.key(KeyCode::Char('d'), KeyModifiers::CONTROL);
    assert!(live.finish(10).success());
}

#[test]
fn bracketed_paste_markers_are_sent_only_after_the_program_asks_and_cannot_be_ended_early() {
    // The program shows each byte it receives as hex, one per line, until it has seen a newline.
    // Reads exactly `count` bytes, so no end of input is needed, and prints them as hex.
    let show =
        |count: u32| format!("stty raw -echo; dd bs=1 count={count} 2>/dev/null | od -An -v -tx1");
    // Without the mode on: the text arrives as it is.
    let mut plain = Live::start(
        40,
        20,
        &["/bin/sh", "-c", &format!("echo ready; {}", show(2))],
    );
    plain.wait_for("ready", 10);
    plain.paste("a\n");
    plain.wait_for("61 0a", 10);
    assert!(
        !plain.text().contains("1b"),
        "no markers were asked for:\n{}",
        plain.text()
    );
    // With the mode on: one start marker, the text, one end marker; the text's own end marker is gone.
    let mut asked = Live::start(
        60,
        20,
        &[
            "/bin/sh",
            "-c",
            &format!("printf '\\033[?2004h'; echo ready; {}", show(15)),
        ],
    );
    asked.wait_for("ready", 10);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !asked
        .screen
        .lock()
        .map(|s| s.modes().bracketed_paste)
        .unwrap_or(false)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    asked.paste("a\x1b[201~b\n");
    asked.wait_for("7e", 10);
    std::thread::sleep(Duration::from_millis(300));
    let joined = asked
        .text()
        .lines()
        .skip_while(|l| l.trim() != "ready")
        .skip(1)
        .collect::<Vec<_>>()
        .join(" ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    // ESC [ 2 0 0 ~  a  b  \n  ESC [ 2 0 1 ~, with the injected end marker removed.
    assert!(
        joined.starts_with("1b 5b 32 30 30 7e 61 62 0a 1b 5b 32 30 31 7e"),
        "{joined}"
    );
    assert_eq!(joined.matches("30 31 7e").count(), 1, "{joined}");
}

#[test]
fn clipboard_title_and_bell_from_a_program_are_counted_and_never_shown() {
    let live = Live::start(
        5,
        60,
        &[
            "/bin/sh",
            "-c",
            "printf '\\033]52;c;aGVsbG8=\\007\\033]0;owned\\007\\007visible\\n'; sleep 0.3",
        ],
    );
    live.wait_for("visible", 10);
    let seen = live.suppressed();
    assert_eq!(seen.clipboard_writes, 1, "{seen:?}");
    // OSC 0 sets both the icon name and the title, which the emulator reports separately.
    assert_eq!(seen.title_changes, 2, "{seen:?}");
    assert_eq!(seen.bells, 1, "{seen:?}");
    assert!(!live.text().contains("aGVsbG8"), "{}", live.text());
    assert!(!live.text().contains("owned"), "{}", live.text());
    assert!(live.finish(10).success());
}

#[test]
fn arrow_keys_follow_the_programs_cursor_mode() {
    // `cat -v` shows what arrives: `^[[A` normally, `^[OA` once the program asks for application mode.
    let mut live = Live::start(
        6,
        60,
        &[
            "/bin/sh",
            "-c",
            "stty -icanon -echo; printf '\\033[?1h'; echo go; cat -v",
        ],
    );
    live.wait_for("go", 10);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !live
        .screen
        .lock()
        .map(|s| s.modes().application_cursor)
        .unwrap_or(false)
        && Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(10));
    }
    live.key(KeyCode::Up, KeyModifiers::NONE);
    live.key(KeyCode::Char('x'), KeyModifiers::NONE);
    live.wait_for("^[OAx", 10);
    live.send(&[4]);
}

#[test]
fn a_program_that_ends_is_seen_to_end_with_its_status_and_its_last_output() {
    let live = Live::start(5, 40, &["/bin/sh", "-c", "echo last words; exit 7"]);
    live.wait_for("last words", 10);
    let status = live.finish(10);
    assert_eq!(status.code(), Some(7));
}

#[test]
fn a_flood_from_one_program_keeps_the_screen_responsive_and_bounded() {
    let live = Live::start(
        24,
        80,
        &[
            "/bin/sh",
            "-c",
            "yes 'a long line of output to fill the screen and scrollback' | head -c 20000000; echo FLOOD-OVER",
        ],
    );
    live.wait_for("FLOOD-OVER", 60);
    let scrolled = live.screen.lock().map(|mut s| {
        s.scroll_to(usize::MAX);
        s.scrolled()
    });
    assert!(scrolled.is_ok_and(|n| n <= hamster_ball::supervise::terminal::SCROLLBACK_LINES));
    assert!(live.finish(10).success());
}
