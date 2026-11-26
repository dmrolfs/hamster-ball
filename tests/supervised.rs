// ABOUTME: `hb run --supervised` through hb-testdrive with a real inherited channel: events, approval, descriptor isolation, stop on disconnect.
// ABOUTME: Each security claim has a control where the attack works (the descriptor leaked on purpose) next to the case where it must fail.
//! Black-box tests of the supervised mode (hb-5yx).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::io::{BufReader, Read, Write};
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use claims::{assert_ok, assert_some};
use common::{World, sandbox_available, write};
use hamster_ball::session::supervised::{
    Event, Frame, Hello, decode_ack, decode_frame, encode_line, read_line,
};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";
/// Duplicates the channel (stdin) to descriptor 9 *without* close-on-exec, which is how a
/// launcher hands a descriptor down, then gives the program an empty stdin.
const LAUNCHER: &str = "use POSIX; use Fcntl; POSIX::dup2(0, 9) or die qq(dup2: $!); \
open(my $fh, q(+<&=), 9) or die qq(fdopen: $!); fcntl($fh, F_SETFD, 0) or die; \
open(STDIN, q(<), q(/dev/null)) or die; $SIG{$_}=q(DEFAULT) for qw(INT QUIT HUP TERM); \
$ENV{HB_SUPERVISOR_FD}=9; exec @ARGV or die qq(exec: $!)";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// A running `hb`, the supervisor's end of its channel, and what it has sent so far.
struct Session {
    child: Child,
    peer: UnixStream,
    frames: Receiver<Frame>,
    seen: Vec<Frame>,
    out: Receiver<String>,
    err: Receiver<String>,
}

fn collect<R: Read + Send + 'static>(mut from: R) -> Receiver<String> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = from.read_to_string(&mut text);
        let _ = tx.send(text);
    });
    rx
}

/// `argv` started by the launcher with the channel on descriptor 9 and an unapproved or
/// approved world; returns the child and the supervisor's end.
fn launch(w: &World, argv: &[&str], approved: bool) -> (Child, UnixStream) {
    let (ours, theirs) = assert_ok!(UnixStream::pair());
    let mut cmd = Command::new("/usr/bin/perl");
    cmd.args(["-e", LAUNCHER]).args(argv);
    cmd.env_clear().current_dir(&w.project);
    if approved {
        w.drive_env(&mut cmd);
    } else {
        w.drive_env_unapproved(&mut cmd);
    }
    cmd.env("HB_TD_GRACE_MS", "2000");
    cmd.stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = assert_ok!(cmd.spawn());
    // `cmd` holds the other end until it is dropped, and it must be closed here so that closing
    // `ours` is seen as a close.
    drop(cmd);
    (child, ours)
}

impl Session {
    /// `hb run --supervised -- words`, with the supervisor handshake already sent.
    fn start(w: &World, extra: &[&str], words: &[&str], approved: bool) -> Self {
        let mut argv = vec![DRIVE, "run", "--supervised"];
        argv.extend_from_slice(extra);
        argv.push("--");
        argv.extend_from_slice(words);
        Self::attach(launch(w, &argv, approved), Hello::new(1, 1))
    }

    fn attach((mut child, peer): (Child, UnixStream), hello: Hello) -> Self {
        let mut writer = assert_ok!(peer.try_clone());
        assert_ok!(writer.write_all(&assert_ok!(encode_line(&hello))));
        let out = collect(assert_some!(child.stdout.take()));
        let err = collect(assert_some!(child.stderr.take()));
        let (tx, frames) = channel();
        let reading = assert_ok!(peer.try_clone());
        std::thread::spawn(move || {
            let mut reader = BufReader::new(reading);
            let Ok(Some(line)) = read_line(&mut reader) else {
                return;
            };
            let Ok(ack) = decode_ack(&line) else { return };
            assert_eq!(
                (ack.launch, ack.generation),
                (hello.launch, hello.generation)
            );
            while let Ok(Some(line)) = read_line(&mut reader) {
                let Ok(frame) = decode_frame(&line) else {
                    return;
                };
                if tx.send(frame).is_err() {
                    return;
                }
            }
        });
        Self {
            child,
            peer,
            frames,
            seen: Vec::new(),
            out,
            err,
        }
    }

    /// Waits for an event of `kind`; fails the test after `secs`.
    fn wait_for(&mut self, kind: &str, secs: u64) -> Frame {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.frames.recv_timeout(left) {
                Ok(frame) => {
                    self.seen.push(frame.clone());
                    if frame.event.kind().to_string() == kind {
                        return frame;
                    }
                }
                Err(_) => {
                    let _ = self.child.kill();
                    assert_ok!(Err::<(), String>(format!(
                        "no `{kind}` event; saw {:?}",
                        self.seen
                    )));
                    return Frame {
                        seq: 0,
                        event: Event::Starting {},
                    };
                }
            }
        }
    }

    /// Simulates the supervisor going away.
    fn close_channel(&self) {
        let _ = self.peer.shutdown(Shutdown::Both);
    }

    /// Waits for `hb` to end (killing it after `secs`) and gathers everything it sent.
    fn finish(mut self, secs: u64) -> Ended {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let started = Instant::now();
        let status = loop {
            if let Some(status) = assert_ok!(self.child.try_wait()) {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                assert_ok!(Err::<(), String>(format!(
                    "hb did not end in {secs}s; saw {:?}",
                    self.seen
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let took = started.elapsed();
        while let Ok(frame) = self.frames.recv_timeout(Duration::from_millis(500)) {
            self.seen.push(frame);
        }
        Ended {
            status,
            took,
            frames: self.seen,
            stdout: self
                .out
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_default(),
            stderr: self
                .err
                .recv_timeout(Duration::from_secs(5))
                .unwrap_or_default(),
        }
    }
}

struct Ended {
    status: ExitStatus,
    took: Duration,
    frames: Vec<Frame>,
    stdout: String,
    stderr: String,
}

impl Ended {
    fn kinds(&self) -> Vec<String> {
        self.frames
            .iter()
            .map(|f| f.event.kind().to_string())
            .collect()
    }
}

fn tool(w: &World, name: &str, body: &str) -> PathBuf {
    let path = w.home_dir().join("tools").join(name);
    write(&path, &format!("#!/bin/sh\n{body}\n"));
    assert_ok!(fs::set_permissions(
        &path,
        fs::Permissions::from_mode(0o755)
    ));
    path
}

fn with_base(w: &World, text: &str) {
    write(&w.home_dir().join(".config/hamster-ball/base.toml"), text);
}

fn alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

fn wait_for_file(path: &std::path::Path, secs: u64) -> String {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if let Ok(text) = fs::read_to_string(path)
            && !text.is_empty()
        {
            return text;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    String::new()
}

#[test]
fn a_run_reports_its_whole_life_in_order_with_contiguous_numbers() {
    sandboxed!();
    let w = World::new(PROJECT);
    let session = Session::start(&w, &[], &["/bin/sh", "-c", "echo hello; exit 3"], true);
    let ended = session.finish(60);
    assert_eq!(ended.status.code(), Some(3), "{}", ended.stderr);
    let kinds = ended.kinds();
    assert_eq!(
        kinds.first().map(String::as_str),
        Some("starting"),
        "{kinds:?}"
    );
    assert!(kinds.iter().any(|k| k == "running"), "{kinds:?}");
    assert_eq!(
        &kinds[kinds.len() - 2..],
        ["stopping", "exited"],
        "{kinds:?}"
    );
    let seqs: Vec<u64> = ended.frames.iter().map(|f| f.seq).collect();
    let expected: Vec<u64> = (1..=u64::try_from(seqs.len()).unwrap_or(0)).collect();
    assert_eq!(seqs, expected);
    assert!(
        matches!(
            ended.frames.last().map(|f| &f.event),
            Some(Event::Exited { code: Some(3), .. })
        ),
        "{:?}",
        ended.frames.last()
    );
    assert!(ended.stdout.contains("hello"), "{}", ended.stdout);
}

#[test]
fn an_unapproved_config_is_reported_not_asked_about_and_nothing_runs() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.project.join("ran");
    let session = Session::start(
        &w,
        &[],
        &["/bin/sh", "-c", &format!("touch '{}'", marker.display())],
        false,
    );
    let ended = session.finish(60);
    assert_eq!(ended.status.code(), Some(78), "{}", ended.stderr);
    assert!(
        ended
            .frames
            .iter()
            .any(|f| matches!(f.event, Event::ApprovalRequired { .. })),
        "{:?}",
        ended.kinds()
    );
    assert!(!ended.kinds().iter().any(|k| k == "running"));
    assert!(!marker.exists(), "the agent ran");
    assert!(
        !ended.stdout.contains("Approve this config"),
        "a prompt was written: {}",
        ended.stdout
    );
}

#[test]
fn the_agent_cannot_see_or_use_the_channel_and_the_control_shows_the_attack_works() {
    sandboxed!();
    let probe = "echo env=${HB_SUPERVISOR_FD-unset}; \
                 if echo FORGED-BY-AGENT >&9 2>/dev/null; then echo wrote; else echo nowrite; fi; \
                 ls /dev/fd | tr '\\n' ' '";
    // Control: the same program started with the descriptor leaked on purpose reaches the channel.
    let w = World::new(PROJECT);
    let (mut child, mut peer) = launch(&w, &["/bin/sh", "-c", probe], true);
    let mut forged = String::new();
    assert_ok!(peer.set_read_timeout(Some(Duration::from_secs(10))));
    let _ = peer.read_to_string(&mut forged);
    let _ = child.wait();
    assert!(
        forged.contains("FORGED-BY-AGENT"),
        "the control cannot write to the channel, so this test proves nothing: {forged:?}"
    );
    // Under hb: nothing reaches the channel, no variable, and no descriptor above 2.
    let w = World::new(PROJECT);
    let session = Session::start(&w, &[], &["/bin/sh", "-c", probe], true);
    let ended = session.finish(60);
    assert!(ended.stdout.contains("env=unset"), "{}", ended.stdout);
    assert!(ended.stdout.contains("nowrite"), "{}", ended.stdout);
    let fds = ended.stdout.lines().last().unwrap_or_default().to_owned();
    let high: Vec<&str> = fds
        .split_whitespace()
        .filter(|n| n.parse::<u32>().is_ok_and(|n| n > 2))
        .collect();
    assert!(
        high.len() <= 1,
        "descriptors above 2 reached the agent: {fds}"
    );
    assert!(
        !ended
            .frames
            .iter()
            .any(|f| format!("{:?}", f.event).contains("FORGED")),
        "{:?}",
        ended.frames
    );
}

#[test]
fn closing_the_channel_stops_the_agent_and_the_session_directory_is_removed() {
    sandboxed!();
    let w = World::new(PROJECT);
    let pid_file = w.project.join("agent.pid");
    let script = format!(
        "echo $$ > '{}'; echo tmp=$TMPDIR; sleep 120",
        pid_file.display()
    );
    let mut session = Session::start(&w, &[], &["/bin/sh", "-c", &script], true);
    session.wait_for("running", 60);
    let pid: i32 = wait_for_file(&pid_file, 20).trim().parse().unwrap_or(0);
    assert!(pid > 0 && alive(pid), "the agent did not start");
    session.close_channel();
    let ended = session.finish(30);
    assert!(ended.took < Duration::from_secs(25), "{:?}", ended.took);
    assert!(!alive(pid), "the agent {pid} survived the supervisor");
    let tmp = ended
        .stdout
        .lines()
        .find_map(|l| l.strip_prefix("tmp="))
        .unwrap_or_default()
        .to_owned();
    assert!(
        tmp.contains("/hb-") && !PathBuf::from(&tmp).exists(),
        "session directory {tmp:?} left behind"
    );
}

#[test]
fn the_stop_command_stops_the_agent_and_exited_is_reported() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut session = Session::start(&w, &[], &["/bin/sh", "-c", "sleep 120"], true);
    session.wait_for("running", 60);
    let mut writer = assert_ok!(session.peer.try_clone());
    assert_ok!(writer.write_all(b"{\"cmd\":\"stop\"}\n"));
    let ended = session.finish(30);
    assert!(ended.status.code() != Some(0), "{:?}", ended.status);
    assert!(
        ended
            .kinds()
            .ends_with(&["stopping".to_owned(), "exited".to_owned()]),
        "{:?}",
        ended.kinds()
    );
}

#[test]
fn closing_the_channel_during_a_slow_hook_kills_the_hook_and_never_starts_the_agent() {
    sandboxed!();
    let w = World::new(PROJECT);
    let started = w.base.join("hook-started");
    let finished = w.base.join("hook-finished");
    let hook = tool(
        &w,
        "slow",
        &format!(
            "touch '{}'; sleep 30 & wait; touch '{}'",
            started.display(),
            finished.display()
        ),
    );
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.slow]\ncommand = [\"{}\"]\ntimeout_secs = 60\n",
            hook.display()
        ),
    );
    let marker = w.project.join("ran");
    let session = Session::start(
        &w,
        &[],
        &["/bin/sh", "-c", &format!("touch '{}'", marker.display())],
        true,
    );
    assert!(
        !wait_for_file(&started, 30).is_empty() || started.exists(),
        "the hook never started"
    );
    let sent = Instant::now();
    session.close_channel();
    let ended = session.finish(30);
    assert!(
        sent.elapsed() < Duration::from_secs(15),
        "{:?}",
        sent.elapsed()
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(!finished.exists(), "the hook ran to its end");
    assert!(!marker.exists(), "the agent started");
    assert!(ended.status.code() != Some(0));
}

#[test]
fn a_handshake_of_another_version_ends_the_run_before_anything_starts() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.project.join("ran");
    let words = ["/bin/sh", "-c", &format!("touch '{}'", marker.display())];
    let mut argv = vec![DRIVE, "run", "--supervised", "--"];
    argv.extend_from_slice(&words);
    let (mut child, mut peer) = launch(&w, &argv, true);
    assert_ok!(peer.write_all(b"{\"v\":9,\"launch\":1,\"generation\":1}\n"));
    let status = assert_ok!(child.wait());
    assert_eq!(status.code(), Some(2));
    assert!(!marker.exists());
}

#[test]
fn supervised_without_a_channel_and_a_channel_without_supervised_both_fail_closed() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.project.join("ran");
    let touch = format!("touch '{}'", marker.display());
    // --supervised, no channel: the ordinary launcher passes none.
    let out = assert_ok!(
        w.drive(
            DRIVE,
            &["run", "--supervised", "--", "/bin/sh", "-c", &touch]
        )
        .stdin(Stdio::null())
        .output()
    );
    assert_eq!(out.status.code(), Some(2), "{}", common::stderr(&out));
    assert!(!marker.exists());
    // A channel, no --supervised.
    let (mut child, _peer) = launch(&w, &[DRIVE, "run", "--", "/bin/sh", "-c", &touch], true);
    let status = assert_ok!(child.wait());
    assert_eq!(status.code(), Some(2));
    assert!(!marker.exists());
}

#[test]
fn an_unusable_descriptor_variable_ends_the_process_and_is_reported() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut cmd = w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", "true"]);
    cmd.env("HB_SUPERVISOR_FD", "nonsense").stdin(Stdio::null());
    let out = assert_ok!(cmd.output());
    assert_eq!(out.status.code(), Some(2));
    assert!(
        common::stderr(&out).contains("supervisor channel"),
        "{}",
        common::stderr(&out)
    );
}
