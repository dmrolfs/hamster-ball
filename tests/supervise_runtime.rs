// ABOUTME: Runtime end to end with real hb: several sessions launched, watched, restarted and stopped through the pure app and the real workers.
// ABOUTME: Every loop has a deadline, so a hang fails the test instead of stalling it; processes left behind are checked for.
//! The runtime driving real sessions (hb-mi8).

#![cfg(all(target_os = "macos", feature = "supervise"))]

mod common;

use std::path::PathBuf;
use std::time::{Duration, Instant};

use claims::assert_some;
use common::{World, sandbox_available};
use hamster_ball::supervise::app::{LaunchSpec, MAX_SESSIONS, Msg, Phase, SessionId};
use hamster_ball::supervise::runtime::{Paths, Runtime};
use nix::sys::signal::kill;
use nix::unistd::Pid;
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

fn runtime(w: &World) -> Runtime {
    w.approve();
    Runtime::new(Paths {
        hb: PathBuf::from(DRIVE),
        me: PathBuf::from(SUPERVISE),
        env: vec![
            ("HB_TD_HOME".into(), w.home_dir().into_os_string()),
            ("HB_TD_CWD".into(), w.project.clone().into_os_string()),
            ("HB_TD_PATH".into(), w.base.join("bin").into_os_string()),
            ("HB_TD_TMP".into(), w.base.join("tmp").into_os_string()),
            ("HB_TD_GRACE_MS".into(), "2000".into()),
        ],
    })
}

fn launch(w: &World, command: &[&str]) -> Msg {
    Msg::Launch(LaunchSpec {
        logging: Default::default(),
        project: w.project.clone(),
        command: command.iter().map(|s| (*s).to_owned()).collect(),
    })
}

/// Steps the runtime until `done` or `secs` pass.
fn run_until(runtime: &mut Runtime, secs: u64, done: impl Fn(&Runtime) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        runtime.step();
        if done(runtime) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    done(runtime)
}

fn phase(runtime: &Runtime, id: u32) -> Phase {
    assert_some!(
        runtime
            .app
            .sessions()
            .iter()
            .find(|s| s.id == SessionId(id))
    )
    .phase
    .clone()
}

fn agent_pid(runtime: &Runtime, id: u32) -> Option<i32> {
    runtime
        .app
        .sessions()
        .iter()
        .find(|s| s.id == SessionId(id))
        .and_then(|s| s.agent_pid)
        .and_then(|p| i32::try_from(p).ok())
}

fn alive(pid: i32) -> bool {
    kill(Pid::from_raw(pid), None).is_ok()
}

#[test]
fn malformed_wire_data_triggers_stop_and_reaping_through_the_real_reader() {
    use std::os::unix::fs::PermissionsExt;
    let w = World::new(PROJECT);
    let fake = w.project.join("fake-hb");
    let stopped = w.project.join("stopped");
    claims::assert_ok!(std::fs::write(
        &fake,
        r#"#!/usr/bin/python3
import json, os, socket
s = socket.socket(fileno=int(os.environ['HB_SUPERVISOR_FD']))
f = s.makefile('rb')
hello = json.loads(f.readline())
hello['pid'] = os.getpid()
s.sendall((json.dumps(hello)+'\n').encode())
s.sendall(b'{"seq":1,"event":"starting"}\n')
s.sendall(b'garbage\n')
command = json.loads(f.readline())
if command == {'cmd': 'stop'}:
    open('stopped', 'w').close()
"#
    ));
    claims::assert_ok!(std::fs::set_permissions(
        &fake,
        std::fs::Permissions::from_mode(0o700)
    ));
    let mut rt = Runtime::new(Paths {
        hb: fake,
        me: SUPERVISE.into(),
        env: vec![],
    });
    rt.send(launch(&w, &["/bin/true"]));
    let failed = run_until(&mut rt, 10, |rt| phase(rt, 1) == Phase::Failed);
    let clean = rt.shut_down(Duration::from_secs(15));
    assert!(
        failed && stopped.exists(),
        "malformed peer was not stopped via its channel"
    );
    assert!(!clean, "broken channel authorized clean completion");
}

#[test]
fn a_broken_live_channel_stops_the_process_and_keeps_restart_blocked() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 60"]));
    assert!(run_until(&mut rt, 10, |rt| phase(rt, 1) == Phase::Running));
    let pid = assert_some!(agent_pid(&rt, 1));
    rt.send(Msg::ChannelBroken {
        id: SessionId(1),
        generation: 1,
        reason: "malformed frame".into(),
    });
    assert_eq!(phase(&rt, 1), Phase::Lost);
    assert_eq!(rt.app.live_count(), 1);
    let stopped = run_until(&mut rt, 15, |rt| {
        phase(rt, 1) == Phase::Failed && !alive(pid)
    });
    rt.send(Msg::AskRestart);
    let refused = run_until(&mut rt, 15, |rt| phase(rt, 1) == Phase::Failed);
    assert!(
        refused && agent_pid(&rt, 1).is_none(),
        "untrusted generation allowed a replacement"
    );
    let clean = rt.shut_down(Duration::from_secs(15));
    assert!(stopped, "broken channel left an agent running");
    assert!(!clean, "negative channel evidence was lost");
}

#[test]
fn a_flooding_session_does_not_starve_the_shared_runtime_or_other_session() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    // Keep pressure on the reader until shutdown instead of benchmarking 30 MB of debug parsing.
    rt.send(launch(&w, &["/usr/bin/yes", "flood"]));
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 1; echo QUIET-DONE"]));
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut frames = 0;
    let mut max_step = Duration::ZERO;
    let mut finished = false;
    while Instant::now() < deadline {
        let start = Instant::now();
        let step = rt.step();
        max_step = max_step.max(start.elapsed());
        assert!(
            step.applied
                <= hamster_ball::supervise::runtime::MAX_PER_STEP
                    + hamster_ball::supervise::runtime::INBOX
        );
        if rt.frame_due(step.applied > 0, Instant::now()) {
            frames += 1;
        }
        if phase(&rt, 2) == Phase::Exited {
            finished = true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let bounded = rt.screen(SessionId(1)).is_some_and(|shared| {
        let mut screen = claims::assert_ok!(shared.screen.lock());
        screen.scroll_to(usize::MAX);
        screen.scrolled() == hamster_ball::supervise::terminal::SCROLLBACK_LINES
    });
    let flooding = phase(&rt, 1) == Phase::Running;
    let before_shutdown = format!("{:?}", rt.app.sessions());
    let clean = rt.shut_down(Duration::from_secs(15));
    assert!(
        finished && clean && flooding,
        "quiet_finished={finished}, clean={clean}, flooding={flooding}, frames={frames}, max_step={max_step:?}; before shutdown: {before_shutdown}"
    );
    assert!(
        bounded && frames > 1,
        "flood must fill but not exceed scrollback and allow redraws"
    );
    assert!(
        max_step < Duration::from_millis(250),
        "step stalled: {max_step:?}"
    );
}

#[test]
fn shared_inbox_flood_preserves_quiet_session_progress_and_frame_turns() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 60"]));
    assert!(run_until(&mut rt, 10, |rt| phase(rt, 1) == Phase::Running));
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 1; echo quiet"]));
    let sender = rt.event_sender_for_test();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stopping = stop.clone();
    let producer = std::thread::spawn(move || {
        let mut seq = 3;
        while !stopping.load(std::sync::atomic::Ordering::Relaxed) {
            let msg = Msg::Channel {
                id: SessionId(1),
                generation: 1,
                seq,
                event: hamster_ball::session::supervised::Event::Denial {
                    text: "flood".into(),
                },
            };
            if sender.try_send(msg).is_ok() {
                seq += 1;
            } else {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut frames = 0;
    let mut last_frame = Instant::now();
    let mut max_gap = Duration::ZERO;
    while Instant::now() < deadline && phase(&rt, 2) != Phase::Exited {
        let step = rt.step();
        let now = Instant::now();
        if rt.frame_due(step.applied > 0, now) {
            max_gap = max_gap.max(now.duration_since(last_frame));
            last_frame = now;
            frames += 1;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    claims::assert_ok!(producer.join());
    let quiet_finished = phase(&rt, 2) == Phase::Exited;
    let ring = &rt.app.sessions()[0].denials;
    let bounded = ring.len() <= hamster_ball::supervise::app::DENIAL_RING && ring.evicted > 0;
    let _ = rt.shut_down(Duration::from_secs(15));
    assert!(
        quiet_finished && bounded,
        "shared inbox flood starved progress or did not exercise eviction"
    );
    assert!(
        frames > 1 && max_gap < Duration::from_millis(250),
        "frame gap {max_gap:?}"
    );
}

#[test]
fn several_sessions_run_side_by_side_and_each_reports_its_own_exit() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 1; exit 1"]));
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 1; exit 2"]));
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 1; exit 0"]));
    assert_eq!(rt.app.live_count(), 3);
    assert!(
        run_until(&mut rt, 90, |r| (1..=3)
            .all(|i| phase(r, i) == Phase::Exited)),
        "{:?}",
        rt.app
            .sessions()
            .iter()
            .map(|s| s.phase.clone())
            .collect::<Vec<_>>()
    );
    let codes: Vec<Option<i32>> = rt
        .app
        .sessions()
        .iter()
        .map(|s| s.exit.as_ref().and_then(|e| e.code))
        .collect();
    assert_eq!(codes, [Some(1), Some(2), Some(0)]);
    assert!(
        rt.shut_down(Duration::from_secs(15)),
        "{rt:?}; {:?}",
        rt.app
    );
}

#[test]
fn the_ninth_session_is_refused_with_a_message_and_starts_nothing() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    for _ in 0..MAX_SESSIONS {
        rt.send(launch(&w, &["/bin/sh", "-c", "sleep 60"]));
    }
    assert_eq!(rt.app.live_count(), MAX_SESSIONS);
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 60"]));
    assert_eq!(rt.app.sessions().len(), MAX_SESSIONS);
    assert_eq!(
        rt.app.notice.as_deref(),
        Some("8 sessions are already running; stop one first")
    );
    // Exercise capacity and ordinary shutdown separately from unconfirmed setup cancellation.
    assert!(run_until(&mut rt, 90, |r| r
        .app
        .sessions()
        .iter()
        .all(|s| s.phase == Phase::Running)));
    // Leave: ask to quit, confirm, and every session ends.
    rt.send(Msg::AskQuit);
    let quit = rt.send(Msg::Answer(true));
    assert!(quit);
    assert!(
        run_until(&mut rt, 90, |r| r.app.live_count() == 0),
        "{:?}",
        rt.app
            .sessions()
            .iter()
            .map(|s| s.phase.clone())
            .collect::<Vec<_>>()
    );
    assert!(rt.shut_down(Duration::from_secs(20)));
}

#[test]
fn unconfirmed_cleanup_refuses_restart_and_marks_shutdown_unclean() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    rt.send(launch(&w, &["/does-not-exist/hb-test-agent"]));
    assert!(run_until(&mut rt, 30, |r| phase(r, 1) == Phase::Exited));
    rt.send(Msg::AskRestart);
    assert!(run_until(&mut rt, 30, |r| r.app.sessions()[0]
        .failure
        .as_deref()
        .is_some_and(|f| f.contains("could not be confirmed"))));
    assert!(!rt.shut_down(Duration::from_secs(1)));
}

#[test]
fn restarting_a_running_session_stops_the_old_agent_and_the_new_generation_runs() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 120"]));
    assert!(run_until(&mut rt, 60, |r| phase(r, 1) == Phase::Running));
    let first_pid = assert_some!(agent_pid(&rt, 1));
    rt.send(Msg::AskRestart);
    rt.send(Msg::Answer(true));
    assert_eq!(assert_some!(rt.app.sessions().first()).generation, 2);
    assert!(
        run_until(&mut rt, 60, |r| {
            phase(r, 1) == Phase::Running && agent_pid(r, 1) != Some(first_pid)
        }),
        "{:?}",
        phase(&rt, 1)
    );
    // The first agent is gone, and its exit did not mark the new generation as exited.
    assert!(
        run_until(&mut rt, 30, |_| !alive(first_pid)),
        "the old agent {first_pid} is still running"
    );
    assert_eq!(phase(&rt, 1), Phase::Running);
    let second_pid = assert_some!(agent_pid(&rt, 1));
    assert!(alive(second_pid));
    rt.send(Msg::AskStop);
    rt.send(Msg::Answer(true));
    assert!(run_until(&mut rt, 60, |r| phase(r, 1) == Phase::Exited));
    assert!(!alive(second_pid));
    assert!(rt.shut_down(Duration::from_secs(15)));
}

#[test]
fn a_session_that_asks_for_approval_is_shown_as_approve_and_nothing_ran() {
    sandboxed!();
    let w = World::new(PROJECT);
    // Not approved: the world is built without the approval `runtime` would record.
    let mut rt = Runtime::new(Paths {
        hb: PathBuf::from(DRIVE),
        me: PathBuf::from(SUPERVISE),
        env: vec![
            ("HB_TD_HOME".into(), w.home_dir().into_os_string()),
            ("HB_TD_CWD".into(), w.project.clone().into_os_string()),
            ("HB_TD_PATH".into(), w.base.join("bin").into_os_string()),
            ("HB_TD_TMP".into(), w.base.join("tmp").into_os_string()),
        ],
    });
    let marker = w.project.join("ran");
    rt.send(launch(
        &w,
        &["/bin/sh", "-c", &format!("touch '{}'", marker.display())],
    ));
    assert!(
        run_until(&mut rt, 60, |r| phase(r, 1) == Phase::Approve),
        "{:?}",
        phase(&rt, 1)
    );
    // The process ending afterwards does not move the row off Approve.
    run_until(&mut rt, 5, |_| false);
    assert_eq!(phase(&rt, 1), Phase::Approve);
    assert!(!marker.exists());
    assert_eq!(rt.app.alerts().len(), 1);
    // The owner's review request reaches the caller, once, naming the generation and project.
    rt.send(Msg::ReviewApproval);
    let asked = rt.take_approvals();
    assert_eq!(asked.len(), 1, "{asked:?}");
    assert_eq!((asked[0].id, asked[0].generation), (SessionId(1), 1));
    assert_eq!(asked[0].project, w.project);
    assert!(rt.take_approvals().is_empty());
    assert!(rt.shut_down(Duration::from_secs(10)));
}

#[test]
fn shutting_down_with_unread_reports_waiting_ends_every_process() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    // shortcut: this does not fill the inbox (hb rate-limits denial reports, so it holds a few
    // messages); a test that blocks a worker on a full inbox needs a source of many proxy events.
    rt.send(launch(
        &w,
        &[
            "/bin/sh",
            "-c",
            "i=0; while [ $i -lt 100000 ]; do cat /etc/master.passwd 2>/dev/null; i=$((i+1)); done; sleep 120",
        ],
    ));
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 120"]));
    assert!(run_until(&mut rt, 60, |r| phase(r, 2) == Phase::Running));
    let pids: Vec<i32> = [1, 2].iter().filter_map(|id| agent_pid(&rt, *id)).collect();
    // Do not step: reports pile up unread, and shut_down must read them as it waits.
    std::thread::sleep(Duration::from_secs(2));
    assert!(rt.shut_down(Duration::from_secs(30)));
    assert!(!rt.is_retiring());
    for pid in pids {
        assert!(!alive(pid), "agent {pid} outlived shut_down");
    }
}

#[test]
fn a_restart_starts_the_new_generation_only_after_the_old_one_has_ended() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 120"]));
    assert!(run_until(&mut rt, 60, |r| phase(r, 1) == Phase::Running));
    let first = assert_some!(agent_pid(&rt, 1));
    rt.send(Msg::AskRestart);
    rt.send(Msg::Answer(true));
    // At no step may both agents be alive.
    let mut second = None;
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        rt.step();
        second = agent_pid(&rt, 1).filter(|p| *p != first);
        if let Some(p) = second {
            assert!(!alive(first), "generation 1 still alive when 2 ran as {p}");
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(second.is_some(), "the new generation never ran");
    assert!(rt.shut_down(Duration::from_secs(20)));
}

#[test]
fn an_agent_that_never_reads_its_input_does_not_freeze_the_loop_and_can_still_be_stopped() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    // `stty raw -echo` makes the pty fill instead of discarding; the agent then never reads.
    rt.send(launch(&w, &["/bin/sh", "-c", "stty raw -echo; sleep 300"]));
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 300"]));
    assert!(run_until(&mut rt, 60, |r| {
        phase(r, 1) == Phase::Running && phase(r, 2) == Phase::Running
    }));
    let pids: Vec<i32> = [1, 2].iter().filter_map(|id| agent_pid(&rt, *id)).collect();
    // Far more than a pty holds, sent as many pastes, each of which must return at once.
    let started = Instant::now();
    for _ in 0..40 {
        rt.send(Msg::Input {
            id: SessionId(1),
            generation: 1,
            bytes: vec![b'x'; 64 * 1024],
        });
        rt.step();
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "the loop waited {:?} on an agent that does not read",
        started.elapsed()
    );
    // The other session is unaffected, and stopping the stuck one (the first row) works.
    assert_eq!(phase(&rt, 2), Phase::Running);
    rt.send(Msg::Jump(1));
    rt.send(Msg::AskStop);
    rt.send(Msg::Answer(true));
    assert!(run_until(&mut rt, 60, |r| phase(r, 1) != Phase::Running));
    assert!(rt.shut_down(Duration::from_secs(20)));
    for pid in pids {
        assert!(!alive(pid), "agent {pid} outlived shut_down");
    }
}

#[test]
fn a_restart_waiting_for_the_old_generation_is_never_started_once_shutdown_begins() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut rt = runtime(&w);
    rt.send(launch(&w, &["/bin/sh", "-c", "sleep 300"]));
    assert!(run_until(&mut rt, 60, |r| phase(r, 1) == Phase::Running));
    let first_screen = assert_some!(rt.screen(SessionId(1))).clone();
    // The restart is asked for; the old generation is still ending, so the new one waits.
    rt.send(Msg::AskRestart);
    rt.send(Msg::Answer(true));
    assert!(
        rt.is_retiring(),
        "the old generation should still be ending"
    );
    // Shutdown begins before the old generation has finished.
    assert!(rt.shut_down(Duration::from_secs(30)));
    // A started generation would have replaced the session's screen; it was never started.
    let screen_now = assert_some!(rt.screen(SessionId(1)));
    assert!(
        std::sync::Arc::ptr_eq(&first_screen, screen_now),
        "a new generation was started after shutdown began"
    );
}

/// Starts `rt` with a guardian grace of `grace_ms`, so a stubborn agent outlives its `hb` that long.
fn runtime_with_grace(w: &World, grace_ms: &str) -> Runtime {
    w.approve();
    Runtime::new(Paths {
        hb: PathBuf::from(DRIVE),
        me: PathBuf::from(SUPERVISE),
        env: vec![
            ("HB_TD_HOME".into(), w.home_dir().into_os_string()),
            ("HB_TD_CWD".into(), w.project.clone().into_os_string()),
            ("HB_TD_PATH".into(), w.base.join("bin").into_os_string()),
            ("HB_TD_TMP".into(), w.base.join("tmp").into_os_string()),
            ("HB_TD_GRACE_MS".into(), grace_ms.into()),
        ],
    })
}

/// An agent that ignores TERM, HUP and INT, and on start records its own pid and whether the
/// previous agent in the log is still alive: that is the overlap, seen from inside the new agent.
fn stubborn_agent(w: &World) -> (std::path::PathBuf, std::path::PathBuf) {
    let log = w.project.join("agents.log");
    let script = w.project.join("agent.sh");
    common::write(
        &script,
        &format!(
            "trap '' TERM HUP INT\n\
             echo \"$$\" >> '{log}'\n\
             while :; do sleep 1; done\n",
            log = log.display()
        ),
    );
    (script, log)
}

fn log_lines(log: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(log)
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn kill_logged(log: &std::path::Path) {
    for line in log_lines(log) {
        if let Some(pid) = line.split(' ').next().and_then(|p| p.parse::<i32>().ok()) {
            let _ = kill(Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
        }
    }
}

#[test]
fn an_abandoned_generation_cannot_authorize_a_restart_from_incomplete_reports() {
    sandboxed!();
    let w = World::new(PROJECT);
    // The guardian waits 8 s before it kills what ignores TERM, far longer than a start takes.
    let mut rt = runtime_with_grace(&w, "8000");
    let (script, log) = stubborn_agent(&w);
    rt.send(launch(&w, &["/bin/sh", &script.to_string_lossy()]));
    assert!(run_until(&mut rt, 60, |r| phase(r, 1) == Phase::Running));
    // Running is reported when the agent is started, not when its script has run.
    assert!(run_until(&mut rt, 30, |_| log_lines(&log).len() == 1));
    // The old generation's hb is killed, not asked: its agent is left to the guardian's grace.
    rt.send(Msg::AskRestart);
    rt.send(Msg::Answer(true));
    rt.abandon_for_test(SessionId(1));
    assert!(run_until(&mut rt, 30, |r| phase(r, 1) == Phase::Failed));
    assert_eq!(
        log_lines(&log).len(),
        1,
        "an abandoned generation authorized a new agent"
    );
    // Even after the known leader goes away, discarded terminal reports cannot be recovered.
    kill_logged(&log);
    rt.send(Msg::AskRestart);
    assert!(run_until(&mut rt, 30, |r| phase(r, 1) == Phase::Failed));
    assert_eq!(log_lines(&log).len(), 1);
    assert!(!rt.shut_down(Duration::from_secs(1)));
}
