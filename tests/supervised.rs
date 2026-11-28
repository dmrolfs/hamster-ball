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

impl Drop for Session {
    fn drop(&mut self) {
        self.close_channel();
        let deadline = Instant::now() + Duration::from_secs(3);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
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
            frames: std::mem::take(&mut self.seen),
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
fn a_session_start_error_reports_unconfirmed_cleanup_not_a_clean_exit() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut session = Session::start(&w, &[], &["/does-not-exist/hb-test-agent"], true);
    let ended = session.wait_for("exited", 30);
    assert!(
        matches!(
            ended.event,
            Event::Exited {
                code: None,
                signal: None,
                cleanup: hamster_ball::session::supervised::Cleanup::Failed { .. },
            }
        ),
        "{:?}",
        ended.event
    );
    session.finish(10);
}

#[test]
fn an_unapproved_config_is_reported_not_asked_about_and_nothing_runs() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.project.join("ran");
    let hook_marker = w.base.join("hook-ran");
    let hook = tool(
        &w,
        "approval-hook",
        &format!("touch '{}'", hook_marker.display()),
    );
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.check]\ncommand = [\"{}\"]\n",
            hook.display()
        ),
    );
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
    assert!(!hook_marker.exists(), "host hook ran before approval");
    assert!(
        !ended.stdout.contains("Approve this config"),
        "a prompt was written: {}",
        ended.stdout
    );
    let approved = Session::start(
        &w,
        &[],
        &["/bin/sh", "-c", &format!("touch '{}'", marker.display())],
        true,
    )
    .finish(60);
    assert_eq!(approved.status.code(), Some(0), "{}", approved.stderr);
    assert!(
        hook_marker.exists() && marker.exists(),
        "approved control must execute both"
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
fn stopping_is_reported_before_a_term_trapping_agent_finishes() {
    sandboxed!();
    for os_signal in [false, true] {
        let w = World::new(PROJECT);
        let ready = w.project.join("ready");
        let release = w.project.join("release");
        let script = format!(
            "trap 'while [ ! -f \"{release}\" ]; do sleep 0.02; done; exit 0' TERM; \
             echo $$ > '{ready}.tmp'; mv '{ready}.tmp' '{ready}'; while :; do sleep 0.02; done",
            release = release.display(),
            ready = ready.display(),
        );
        let mut session = Session::start(&w, &[], &["/bin/sh", "-c", &script], true);
        session.wait_for("running", 60);
        let pid: i32 = assert_ok!(wait_for_file(&ready, 20).trim().parse());
        assert!(pid > 1 && alive(pid));
        if os_signal {
            assert_ok!(kill(
                Pid::from_raw(session.child.id() as i32),
                nix::sys::signal::Signal::SIGTERM
            ));
        } else {
            assert_ok!(session.peer.write_all(b"{\"cmd\":\"stop\"}\n"));
        }
        session.wait_for("stopping", 10);
        let still_alive = alive(pid);
        // Release even on the old implementation's late report, before checking the observation.
        write(&release, "done");
        let ended = session.finish(30);
        assert!(
            still_alive,
            "Stopping arrived only after agent exit (os_signal={os_signal})"
        );
        assert_eq!(
            ended
                .frames
                .iter()
                .filter(|f| matches!(f.event, Event::Stopping {}))
                .count(),
            1
        );
    }
}

#[test]
fn closing_the_channel_stops_the_agent_and_the_session_directory_is_removed() {
    sandboxed!();
    let w = World::new(PROJECT);
    let pid_file = w.project.join("agent.pid");
    let script = format!(
        "printf '%s\\n%s\\n' \"$$\" \"$TMPDIR\" > '{0}.tmp'; mv '{0}.tmp' '{0}'; sleep 120",
        pid_file.display()
    );
    let mut session = Session::start(&w, &[], &["/bin/sh", "-c", &script], true);
    session.wait_for("running", 60);
    let ready = wait_for_file(&pid_file, 20);
    let mut lines = ready.lines();
    let pid: i32 = assert_ok!(assert_some!(lines.next()).parse());
    let tmp = assert_some!(lines.next()).to_owned();
    assert!(
        tmp.contains("/hb-") && PathBuf::from(&tmp).is_dir(),
        "invalid readiness {ready:?}"
    );
    assert!(pid > 1 && alive(pid), "the agent did not start");
    session.close_channel();
    let ended = session.finish(30);
    assert!(ended.took < Duration::from_secs(25), "{:?}", ended.took);
    assert!(!alive(pid), "the agent {pid} survived the supervisor");
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
    for leader_exits in [false, true] {
        let w = World::new(PROJECT);
        let started = w.base.join("hook-started");
        let hook_dir = w.base.join("hook-dir");
        let finished = w.base.join("hook-finished");
        let body = if leader_exits {
            format!(
                "sleep 30 & echo $! > '{0}.tmp'; mv '{0}.tmp' '{0}'; exit 0",
                started.display()
            )
        } else {
            format!(
                "echo $$ > '{0}.tmp'; mv '{0}.tmp' '{0}'; sleep 30 & wait; touch '{1}'",
                started.display(),
                finished.display()
            )
        };
        let hook = tool(
            &w,
            "slow",
            &format!("pwd > '{}'; {body}", hook_dir.display()),
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
        let pid: i32 = assert_ok!(wait_for_file(&started, 10).trim().parse());
        assert!(pid > 1);
        assert_ok!(kill(Pid::from_raw(pid), None));
        assert!(!finished.exists(), "hook finished before disconnect");
        let session_dir = PathBuf::from(wait_for_file(&hook_dir, 10).trim());
        assert!(session_dir.is_dir());
        // Without disconnect, the hook or its output-holding child must remain live.
        std::thread::sleep(Duration::from_millis(100));
        assert_ok!(kill(Pid::from_raw(pid), None));
        let sent = Instant::now();
        session.close_channel();
        let ended = session.finish(30);
        assert!(
            sent.elapsed() < Duration::from_secs(15),
            "{:?}",
            sent.elapsed()
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while kill(Pid::from_raw(pid), None).is_ok() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            kill(Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH),
            "hook process {pid} survived (leader_exits={leader_exits}); {}",
            ended.stderr
        );
        assert!(!finished.exists(), "the hook ran to its end");
        assert!(!marker.exists(), "the agent started");
        assert!(ended.status.code() != Some(0));
        assert!(
            !session_dir.exists(),
            "session directory survived hook cancellation"
        );
    }
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

/// A background child of the agent that ignores TERM and HUP, started by a shell that then waits.
/// The leader dies of TERM at once; the child stays in the agent's group.
fn term_ignoring_child_script(pid_file: &std::path::Path) -> String {
    format!(
        "(trap '' TERM HUP; exec sleep 90) </dev/null >/dev/null 2>&1 & echo $! > '{0}.tmp'; mv '{0}.tmp' '{0}'; sleep 120",
        pid_file.display()
    )
}

/// hb-807 review A, HIGH 1: closing the channel must end descendants too, not only the leader.
/// The leader exits on TERM inside the grace period, which used to disarm the SIGKILL that was
/// meant for the rest of the group.
#[test]
fn closing_the_channel_also_ends_a_term_ignoring_descendant_of_a_leader_that_exits() {
    sandboxed!();
    let w = World::new(PROJECT);
    let pid_file = w.project.join("child.pid");
    let script = term_ignoring_child_script(&pid_file);
    let mut session = Session::start(&w, &[], &["/bin/sh", "-c", &script], true);
    session.wait_for("running", 60);
    let child: i32 = assert_ok!(wait_for_file(&pid_file, 20).trim().parse());
    assert!(alive(child), "the descendant did not start");
    session.close_channel();
    let ended = session.finish(40);
    let deadline = Instant::now() + Duration::from_secs(5);
    while alive(child) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let survived = alive(child);
    if survived {
        let _ = kill(Pid::from_raw(child), nix::sys::signal::Signal::SIGKILL);
    }
    assert!(!survived, "the TERM-ignoring descendant {child} survived");
    // It is ended at the end of the grace period (2 s here), not instantly and not never.
    assert!(ended.took < Duration::from_secs(25), "{:?}", ended.took);
}

/// The control: nothing asked to stop, the leader just finishes, and hb leaves the background
/// child alone as before. This is what keeps the fix from becoming a kill-everything-at-exit rule.
#[test]
fn a_leader_that_simply_exits_leaves_its_background_child_alone() {
    sandboxed!();
    let w = World::new(PROJECT);
    let pid_file = w.project.join("child.pid");
    let script = format!(
        "(exec sleep 90) </dev/null >/dev/null 2>&1 & echo $! > '{0}.tmp'; mv '{0}.tmp' '{0}'",
        pid_file.display()
    );
    let mut session = Session::start(&w, &[], &["/bin/sh", "-c", &script], true);
    session.wait_for("running", 60);
    let child: i32 = assert_ok!(wait_for_file(&pid_file, 20).trim().parse());
    let _ended = session.finish(40);
    std::thread::sleep(Duration::from_millis(500));
    let alive_after = alive(child);
    let _ = kill(Pid::from_raw(child), nix::sys::signal::Signal::SIGKILL);
    assert!(
        alive_after,
        "a normal exit now kills background children; that is a behaviour change"
    );
}
