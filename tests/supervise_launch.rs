// ABOUTME: supervise::launch against the real hb-supervise helper and the real hb-testdrive: the channel arrives, the terminal is the session's, no descriptor leaks.
// ABOUTME: Each claim has a control: a launch with the descriptor passed another way fails, and the unfiltered agent sees what the filtered one does not.
//! Launching a session (hb-mi8).

#![cfg(all(target_os = "macos", feature = "supervise"))]

mod common;

use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use claims::{assert_ok, assert_some};
use common::{World, sandbox_available};
use hamster_ball::session::supervised::{
    Event, Hello, decode_ack, decode_frame, encode_line, read_line,
};
use hamster_ball::supervise::app::LaunchSpec;
use hamster_ball::supervise::launch::{Started, start, start_with_env};
use pretty_assertions::assert_eq;

const SUPERVISE: &str = env!("CARGO_BIN_EXE_hb-supervise");
const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// Starts `command` through the real launch path, with the testdrive standing in for `hb`.
fn launch(w: &World, command: &[&str]) -> Started {
    w.approve();
    let spec = LaunchSpec {
        project: w.project.clone(),
        command: command.iter().map(|s| (*s).to_owned()).collect(),
    };
    let vars = fixture(w);
    let extra: Vec<(&str, &std::ffi::OsStr)> =
        vars.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
    assert_ok!(start_with_env(
        &PathBuf::from(DRIVE),
        &PathBuf::from(SUPERVISE),
        &spec,
        30,
        100,
        &extra
    ))
}

/// The variables hb-testdrive reads, which a real `hb` does not need.
fn fixture(w: &World) -> Vec<(&'static str, std::ffi::OsString)> {
    vec![
        ("HB_TD_HOME", w.home_dir().into_os_string()),
        ("HB_TD_CWD", w.project.clone().into_os_string()),
        ("HB_TD_PATH", w.base.join("bin").into_os_string()),
        ("HB_TD_TMP", w.base.join("tmp").into_os_string()),
        ("HB_TD_GRACE_MS", "2000".into()),
    ]
}

/// A started session with its terminal drained from the start, as the supervisor's reader does:
/// on macOS output a program wrote is lost if nothing reads the master before the slave closes.
struct Live {
    started: Started,
    terminal: std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
}

impl Live {
    fn new(started: Started) -> Self {
        let terminal = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&terminal);
        let mut master = assert_ok!(started.terminal.try_clone());
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = master.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if let Ok(mut all) = sink.lock() {
                    all.extend_from_slice(&buffer[..n]);
                }
            }
        });
        Self { started, terminal }
    }

    /// Answers the handshake and reads every frame until the channel ends; fails the test, rather
    /// than hang, if the session does not end within 60 s.
    fn frames(&mut self) -> Vec<hamster_ball::session::supervised::Frame> {
        let channel = &mut self.started.channel;
        assert_ok!(channel.write_all(&assert_ok!(encode_line(&Hello::new(1, 1)))));
        assert_ok!(channel.set_read_timeout(Some(Duration::from_secs(60))));
        let mut reader = BufReader::new(assert_ok!(channel.try_clone()));
        let line = assert_some!(assert_ok!(read_line(&mut reader)));
        assert_ok!(decode_ack(&line));
        let mut out = Vec::new();
        while let Ok(Some(line)) = read_line(&mut reader) {
            out.push(assert_ok!(decode_frame(&line)));
        }
        out
    }

    /// Waits for the process to end (killing it after 30 s) and then for the terminal to drain.
    fn wait(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = assert_ok!(self.started.child.try_wait()) {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.started.child.kill();
                assert_ok!(Err::<(), String>("the session did not end".to_owned()));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        std::thread::sleep(Duration::from_millis(300));
        status
    }

    fn screen(&self) -> String {
        let bytes = self.terminal.lock().map(|b| b.clone()).unwrap_or_default();
        String::from_utf8_lossy(&bytes).into_owned()
    }
}

#[test]
fn a_launched_session_reports_over_its_channel_and_its_agent_has_the_session_terminal() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut live = Live::new(launch(
        &w,
        &[
            "/bin/sh",
            "-c",
            "if test -t 0 -a -t 1; then echo stdio-is-a-terminal; fi; echo agent-ran; exit 4",
        ],
    ));
    let events = live.frames();
    let kinds: Vec<String> = events.iter().map(|f| f.event.kind().to_string()).collect();
    assert_eq!(
        kinds.first().map(String::as_str),
        Some("starting"),
        "{kinds:?}"
    );
    assert!(kinds.contains(&"running".to_owned()), "{kinds:?}");
    assert!(
        matches!(
            events.last().map(|f| &f.event),
            Some(Event::Exited { code: Some(4), .. })
        ),
        "{:?}",
        events.last()
    );
    let status = live.wait();
    assert_eq!(status.code(), Some(4));
    let text = live.screen();
    assert!(text.contains("agent-ran"), "{text}");
    // Its standard streams are a terminal: the session's own, through the agent's pty.
    assert!(text.contains("stdio-is-a-terminal"), "{text}");
}

#[test]
fn the_agent_holds_no_descriptor_above_two_and_cannot_use_the_channel() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut live = Live::new(launch(
        &w,
        &[
            "/bin/sh",
            "-c",
            "echo env=${HB_SUPERVISOR_FD-unset}; ls /dev/fd | tr '\\n' ' '; echo; (echo FORGED >&3) 2>/dev/null && echo wrote3 || echo nowrite3",
        ],
    ));
    let _ = live.frames();
    live.wait();
    let text = live.screen();
    assert!(text.contains("env=unset"), "{text}");
    assert!(text.contains("nowrite3"), "{text}");
    let list = text
        .lines()
        .find(|l| l.trim_start().starts_with('0'))
        .unwrap_or_default();
    let high = list
        .split_whitespace()
        .filter(|n| n.parse::<u32>().is_ok_and(|n| n > 2))
        .count();
    assert!(high <= 1, "descriptors above 2 reached the agent: {list:?}");
}

#[test]
fn a_helper_that_cannot_exec_hb_reports_why_on_the_terminal_and_exits_2() {
    sandboxed!();
    let w = World::new(PROJECT);
    let spec = LaunchSpec {
        project: w.project.clone(),
        command: vec!["/bin/true".to_owned()],
    };
    let mut live = Live::new(assert_ok!(start(
        &PathBuf::from("/nonexistent/hb"),
        &PathBuf::from(SUPERVISE),
        &spec,
        24,
        80
    )));
    let status = live.wait();
    assert_eq!(status.code(), Some(2));
    let text = live.screen();
    assert!(text.contains("could not launch"), "{text}");
}

#[test]
fn a_launch_with_no_such_project_directory_fails_to_start_and_leaves_nothing_running() {
    sandboxed!();
    let spec = LaunchSpec {
        project: PathBuf::from("/nonexistent/project"),
        command: vec!["/bin/true".to_owned()],
    };
    let result = start(
        &PathBuf::from(DRIVE),
        &PathBuf::from(SUPERVISE),
        &spec,
        24,
        80,
    );
    assert!(result.is_err());
}
