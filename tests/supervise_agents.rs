// ABOUTME: Opt-in: starts each installed agent CLI on a pty, renders it through SessionScreen, types, resizes, and exits it.
// ABOUTME: Nothing runs unless HB_SUPERVISE_AGENTS=1. It is not sandboxed: it checks the emulator, not enforcement. Output records what each agent did.
//! Run with `HB_SUPERVISE_AGENTS=1 cargo test --all-features --test supervise_agents -- --nocapture --test-threads=1`.
//!
//! Each agent is started in a throwaway directory with no prompt sent, so no model request is
//! made: the check is that the agent's start-up screen renders, that typed text and a resize
//! reach it, and that it ends when asked. What each agent showed is printed so a failure can be
//! read, and the screen is dumped on failure.

#![cfg(all(target_os = "macos", feature = "supervise"))]

use std::fs::File;
use std::io::{Read, Write};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use claims::assert_ok;
use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
use hamster_ball::session::{Pty, Winsize};
use hamster_ball::supervise::input::encode_key;
use hamster_ball::supervise::terminal::{SessionScreen, Suppressed};

const LAUNCHER: &str = "use POSIX; POSIX::setsid(); ioctl(STDIN, 0x20007461, 0); \
exec @ARGV or die qq(exec $ARGV[0]: $!)";

fn enabled() -> bool {
    let on = std::env::var_os("HB_SUPERVISE_AGENTS").is_some_and(|v| v == "1");
    if !on {
        eprintln!("SKIP: HB_SUPERVISE_AGENTS is not 1");
    }
    on
}

fn size(rows: u16, cols: u16) -> Winsize {
    Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

struct Agent {
    child: Child,
    master: File,
    screen: Arc<Mutex<SessionScreen>>,
    bytes: Arc<Mutex<u64>>,
}

impl Agent {
    fn start(program: &str, args: &[&str], dir: &std::path::Path) -> Option<Self> {
        let pty = Pty::open().ok()?;
        pty.set_size(size(40, 120)).ok()?;
        let (stdin, stdout, stderr) = pty.child_stdio().ok()?;
        let mut cmd = Command::new("/usr/bin/perl");
        cmd.args(["-e", LAUNCHER, program]).args(args);
        cmd.current_dir(dir)
            .env("TERM", "xterm-256color")
            .env("NO_COLOR", "")
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr);
        let child = cmd.spawn().ok()?;
        let mut reading = pty.clone_master().ok()?;
        let master = pty.release_slave();
        let screen = Arc::new(Mutex::new(SessionScreen::new(40, 120)));
        let bytes = Arc::new(Mutex::new(0u64));
        let (feed, count) = (Arc::clone(&screen), Arc::clone(&bytes));
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = reading.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if let Ok(mut screen) = feed.lock() {
                    screen.process(&buffer[..n]);
                }
                if let Ok(mut total) = count.lock() {
                    *total += n as u64;
                }
            }
        });
        Some(Self {
            child,
            master,
            screen,
            bytes,
        })
    }

    fn text(&self) -> String {
        self.screen.lock().map(|s| s.text()).unwrap_or_default()
    }

    fn received(&self) -> u64 {
        self.bytes.lock().map(|b| *b).unwrap_or(0)
    }

    fn suppressed(&self) -> Suppressed {
        self.screen
            .lock()
            .map(|s| s.suppressed())
            .unwrap_or_default()
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
            assert_ok!(self.master.write_all(&bytes));
        }
    }

    /// Waits until the screen has changed from `before` or `secs` pass; true if it changed.
    fn wait_for_change(&self, before: &str, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.text() != before {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    /// Waits until output has started and then stopped arriving for `quiet`, or `secs` pass.
    /// An agent behind a slow launcher sends nothing at first, which is not yet quiet.
    fn settle(&self, quiet: Duration, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while self.received() == 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let mut last = self.received();
        let mut since = Instant::now();
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
            let now = self.received();
            if now != last {
                last = now;
                since = Instant::now();
            } else if since.elapsed() >= quiet {
                return true;
            }
        }
        false
    }

    fn ended(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(Some(_)))
    }

    fn wait_end(&mut self, secs: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if self.ended() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        if let Ok(pid) = i32::try_from(self.child.id()) {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Runs the check for one agent and prints what it did.
fn exercise(
    name: &str,
    program: &str,
    args: &[&str],
    probe: &[(KeyCode, KeyModifiers)],
    quit: &[(KeyCode, KeyModifiers)],
) {
    if !enabled() {
        return;
    }
    assert!(
        std::path::Path::new(program).exists(),
        "{name}: {program} is not installed"
    );
    let version = assert_ok!(Command::new(program).arg("--version").output());
    assert!(version.status.success(), "{name}: version command failed");
    eprintln!(
        "{name}: version {}",
        String::from_utf8_lossy(&version.stdout).trim()
    );
    let dir = assert_ok!(tempfile::TempDir::new());
    let Some(mut agent) = Agent::start(program, args, dir.path()) else {
        assert_ok!(Err::<(), String>(format!("{name}: could not start")));
        return;
    };
    assert!(
        agent.settle(
            Duration::from_secs(if name == "opencode" { 1 } else { 4 }),
            40
        ),
        "{name}: startup never settled"
    );
    let first = agent.text();
    eprintln!(
        "{name}: start-up screen, {} bytes received, suppressed {:?}\n{first}\n---",
        agent.received(),
        agent.suppressed()
    );
    assert!(
        first.trim().len() > 10,
        "{name}: nothing rendered:\n{first}"
    );

    let quiet_bytes = agent.received();
    std::thread::sleep(Duration::from_secs(2));
    if name == "opencode" {
        // opencode 2.4.2 keeps a live status line (a counter that ticks, plugin and MCP notices)
        // and redraws it with no input: measured 84 bytes per tick, 658 to 1,650 for a notice, every
        // few seconds. The check for this agent is that the background output is small and bounded,
        // not that there is none, so a loop in the pipeline would still fail it.
        let extra = agent.received() - quiet_bytes;
        assert!(
            extra <= 4096,
            "{name}: {extra} bytes arrived in 2 s with no input"
        );
        eprintln!(
            "{name}: background output in 2 s with no input: {extra} bytes (live status line)"
        );
    } else {
        assert_eq!(
            agent.received(),
            quiet_bytes,
            "{name}: output arrives without input"
        );
        assert_eq!(agent.text(), first, "{name}: screen changes without input");
    }
    let first = agent.text();
    // Keys the agent reacts to by changing its screen: text in an input box, or a menu move.
    for (code, mods) in probe {
        agent.key(*code, *mods);
    }
    let typed = agent.wait_for_change(&first, 10);
    assert!(typed, "{name}: input did not change the screen");
    assert!(
        agent.settle(Duration::from_secs(1), 10),
        "{name}: input never settled"
    );
    eprintln!("{name}: typing changed the screen: {typed}");
    if matches!(name, "pi" | "opencode") {
        assert!(
            agent.text().contains("hbprobe"),
            "{name}: typed token missing: {}",
            agent.text()
        );
        for _ in "hbprobe".chars() {
            agent.key(KeyCode::Backspace, KeyModifiers::NONE);
        }
        assert!(agent.settle(Duration::from_secs(1), 10));
        assert!(
            !agent.text().contains("hbprobe"),
            "{name}: input was not cleared"
        );
    } else {
        let down = agent.text();
        agent.key(KeyCode::Up, KeyModifiers::NONE);
        assert!(
            agent.wait_for_change(&down, 10),
            "{name}: Up did not move the menu"
        );
        assert!(agent.settle(Duration::from_secs(1), 10));
    }

    // Resize: both sides change, and the agent redraws for the new width.
    let bytes_before = agent.received();
    assert_ok!(rustix::termios::tcsetwinsize(&agent.master, size(30, 80)));
    if let Ok(mut screen) = agent.screen.lock() {
        screen.resize(30, 80);
    }
    assert!(
        agent.settle(Duration::from_secs(1), 10),
        "{name}: resize never settled"
    );
    let redrew = agent.received() > bytes_before;
    assert!(redrew, "{name}: no output after resize");
    eprintln!(
        "{name}: resize to 30x80 made the agent redraw: {redrew}\n{}\n---",
        agent.text()
    );
    assert_eq!(
        agent.screen.lock().map(|s| s.size()).unwrap_or_default(),
        (30, 80)
    );

    // Exit: the keys the agent documents, then, failing that, Ctrl-C twice and Ctrl-D.
    for (code, mods) in quit {
        agent.key(*code, *mods);
    }
    let mut ended = agent.wait_end(15);
    if !ended {
        for _ in 0..2 {
            agent.key(KeyCode::Char('c'), KeyModifiers::CONTROL);
            std::thread::sleep(Duration::from_millis(300));
        }
        ended = agent.wait_end(10);
    }
    if !ended {
        agent.key(KeyCode::Char('d'), KeyModifiers::CONTROL);
        ended = agent.wait_end(10);
    }
    eprintln!("{name}: ended after the quit keys: {ended}");
    assert!(
        ended,
        "{name}: did not end; the screen was:\n{}",
        agent.text()
    );
}

const CTRL: KeyModifiers = KeyModifiers::CONTROL;
const NONE: KeyModifiers = KeyModifiers::NONE;

#[test]
fn claude_renders_accepts_typing_resizes_and_exits() {
    exercise(
        "claude",
        "/Users/rolfs/.local/bin/claude",
        &[],
        // The first screen is a trust question, which takes keys as menu moves and is not answered
        // here: answering it would record the throwaway directory in the user's Claude settings.
        &[(KeyCode::Down, NONE)],
        &[(KeyCode::Char('c'), CTRL), (KeyCode::Char('c'), CTRL)],
    );
}

#[test]
fn pi_renders_accepts_typing_resizes_and_exits() {
    exercise(
        "pi",
        "/Users/rolfs/.pi/agent/bin/pi",
        &[],
        &"hbprobe"
            .chars()
            .map(|c| (KeyCode::Char(c), NONE))
            .collect::<Vec<_>>(),
        &[(KeyCode::Char('c'), CTRL), (KeyCode::Char('c'), CTRL)],
    );
}

#[test]
fn kiro_renders_accepts_typing_resizes_and_exits() {
    exercise(
        "kiro-cli",
        "/Users/rolfs/.local/bin/kiro-cli",
        &[],
        // A trust menu, like claude's, and left unanswered for the same reason.
        &[(KeyCode::Down, NONE)],
        &[(KeyCode::Char('c'), CTRL), (KeyCode::Char('c'), CTRL)],
    );
}

#[test]
fn opencode_renders_accepts_typing_resizes_and_exits() {
    exercise(
        "opencode",
        "/opt/homebrew/bin/opencode",
        &[],
        &"hbprobe"
            .chars()
            .map(|c| (KeyCode::Char(c), NONE))
            .collect::<Vec<_>>(),
        &[(KeyCode::Char('c'), CTRL), (KeyCode::Char('c'), CTRL)],
    );
}
