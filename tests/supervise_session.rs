// ABOUTME: The session workers with a real hb: events reach the App in order, the exit is reported last, a stop works, and a flooding session does not starve another.
// ABOUTME: Real processes and real threads; every wait has a deadline so a hang fails the test instead of stalling it.
//! Session workers end to end (hb-mi8).

#![cfg(all(target_os = "macos", feature = "supervise"))]

mod common;

use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError, sync_channel};
use std::time::{Duration, Instant};

use claims::{assert_ok, assert_some};
use common::{World, sandbox_available};
use hamster_ball::supervise::app::{App, Effect, LaunchSpec, Msg, Phase, SessionId};
use hamster_ball::supervise::launch::start_with_env;
use hamster_ball::supervise::session::{FAIL_AT, Shared, Step, Worker, spawn};
use pretty_assertions::assert_eq;

const SUPERVISE: &str = env!("CARGO_BIN_EXE_hb-supervise");
const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";
const INBOX: usize = 64;

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

fn spec(w: &World, command: &[&str]) -> LaunchSpec {
    LaunchSpec {
        logging: Default::default(),
        project: w.project.clone(),
        command: command.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// Launches `spec` and starts its workers, for session `id` in `app`.
fn start(
    w: &World,
    app: &mut App,
    command: &[&str],
) -> (SessionId, Worker, std::sync::Arc<Shared>) {
    w.approve();
    let launch = spec(w, command);
    let effects = app.update(Msg::Launch(launch.clone()));
    let Some(Effect::Spawn { id, generation, .. }) = effects.first().cloned() else {
        assert_ok!(Err::<(), String>(format!("no spawn: {effects:?}")));
        std::process::abort();
    };
    let vars: Vec<(&str, std::ffi::OsString)> = vec![
        ("HB_TD_HOME", w.home_dir().into_os_string()),
        ("HB_TD_CWD", w.project.clone().into_os_string()),
        ("HB_TD_PATH", w.base.join("bin").into_os_string()),
        ("HB_TD_TMP", w.base.join("tmp").into_os_string()),
        ("HB_TD_GRACE_MS", "2000".into()),
    ];
    let extra: Vec<(&str, &std::ffi::OsStr)> =
        vars.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
    let started = assert_ok!(start_with_env(
        &PathBuf::from(DRIVE),
        &PathBuf::from(SUPERVISE),
        &launch,
        30,
        100,
        &extra
    ));
    let shared = Shared::new(30, 100);
    let (tx, rx) = sync_channel(INBOX);
    INBOXES.with(|slot| slot.borrow_mut().push((id, rx)));
    let worker = assert_ok!(spawn(
        id,
        generation,
        started,
        std::sync::Arc::clone(&shared),
        tx
    ));
    (id, worker, shared)
}

thread_local! {
    static INBOXES: std::cell::RefCell<Vec<(SessionId, Receiver<Msg>)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

/// Applies every message that arrives for `id` until `done(app)` or `secs` pass.
fn pump(app: &mut App, id: SessionId, secs: u64, done: impl Fn(&App) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done(app) {
            return true;
        }
        let received = INBOXES.with(|slot| {
            let slot = slot.borrow();
            let (_, rx) = assert_some!(slot.iter().find(|(i, _)| *i == id));
            rx.recv_timeout(Duration::from_millis(50))
        });
        match received {
            Ok(msg) => {
                app.update(msg);
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return done(app),
        }
    }
    done(app)
}

fn phase(app: &App, id: SessionId) -> Phase {
    assert_some!(app.sessions().iter().find(|s| s.id == id))
        .phase
        .clone()
}

#[test]
fn a_session_runs_to_its_exit_and_the_exit_is_seen_before_the_process_is_reported_gone() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut app = App::new();
    let (id, worker, shared) = start(
        &w,
        &mut app,
        &["/bin/sh", "-c", "echo agent-output; exit 5"],
    );
    assert!(
        pump(&mut app, id, 60, |a| phase(a, id) == Phase::Exited),
        "ended in {:?}",
        phase(&app, id)
    );
    let session = assert_some!(app.sessions().first());
    let exit = assert_some!(session.exit.as_ref());
    assert_eq!(exit.code, Some(5));
    assert!(session.agent_pid.is_some());
    // The process is reaped afterwards and that does not turn a clean Exited into a failure.
    pump(&mut app, id, 5, |_| false);
    assert_eq!(phase(&app, id), Phase::Exited);
    let text = shared.screen.lock().map(|s| s.text()).unwrap_or_default();
    assert!(text.contains("agent-output"), "{text}");
    assert!(worker.shut_down(Duration::from_secs(10)));
}

#[test]
fn stopping_a_running_session_ends_it_through_hb_and_reports_the_exit() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut app = App::new();
    let (id, worker, _shared) = start(&w, &mut app, &["/bin/sh", "-c", "sleep 120"]);
    assert!(pump(&mut app, id, 60, |a| phase(a, id) == Phase::Running));
    app.update(Msg::AskStop);
    let effects = app.update(Msg::Answer(true));
    assert!(
        matches!(effects.first(), Some(Effect::Stop { .. })),
        "{effects:?}"
    );
    worker.stop();
    assert!(
        pump(&mut app, id, 30, |a| phase(a, id) == Phase::Exited),
        "ended in {:?}",
        phase(&app, id)
    );
    assert!(worker.shut_down(Duration::from_secs(10)));
}

#[test]
fn closing_the_supervisor_side_of_a_running_session_ends_it_and_the_workers_finish() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut app = App::new();
    let (id, worker, _shared) = start(&w, &mut app, &["/bin/sh", "-c", "sleep 120"]);
    assert!(pump(&mut app, id, 60, |a| phase(a, id) == Phase::Running));
    let started = Instant::now();
    assert!(
        worker.shut_down(Duration::from_secs(30)),
        "the workers did not end"
    );
    assert!(started.elapsed() < Duration::from_secs(30));
}

#[test]
fn a_session_that_prints_without_pause_does_not_starve_another_and_memory_stays_bounded() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut app = App::new();
    let (flood_id, flood, flood_shared) = start(
        &w,
        &mut app,
        &[
            "/bin/sh",
            "-c",
            "yes 'flooding output line to fill everything' | head -c 30000000",
        ],
    );
    let (quiet_id, quiet, _qs) = start(
        &w,
        &mut app,
        &["/bin/sh", "-c", "sleep 1; echo quiet-done; exit 0"],
    );
    // Both must finish, and the quiet one must not wait for the flood to end.
    let started = Instant::now();
    let quiet_done = pump_two(&mut app, quiet_id, flood_id, 60, |a| {
        phase(a, quiet_id) == Phase::Exited
    });
    let quiet_took = started.elapsed();
    assert!(quiet_done, "the quiet session never finished");
    // Alone it takes about two seconds; the flood runs for much longer than that, so a quiet
    // session that waited for it would take many times as long.
    assert!(
        quiet_took < Duration::from_secs(15),
        "the quiet session waited {quiet_took:?}"
    );
    assert!(pump_two(&mut app, flood_id, quiet_id, 120, |a| phase(
        a, flood_id
    )
        == Phase::Exited));
    // The flood left the screen at its size and the history at its cap.
    let scrolled = flood_shared.screen.lock().map(|mut s| {
        s.scroll_to(usize::MAX);
        (s.size(), s.scrolled())
    });
    let (size, back) = assert_ok!(scrolled);
    assert_eq!(size, (30, 100));
    assert!(back <= hamster_ball::supervise::terminal::SCROLLBACK_LINES);
    assert!(flood.shut_down(Duration::from_secs(10)));
    assert!(quiet.shut_down(Duration::from_secs(10)));
}

/// Like [`pump`], draining both sessions' inboxes so neither blocks the other.
fn pump_two(
    app: &mut App,
    first: SessionId,
    second: SessionId,
    secs: u64,
    done: impl Fn(&App) -> bool,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if done(app) {
            return true;
        }
        for id in [first, second] {
            let batch: Vec<Msg> = INBOXES.with(|slot| {
                let slot = slot.borrow();
                let (_, rx) = assert_some!(slot.iter().find(|(i, _)| *i == id));
                rx.try_iter().take(256).collect()
            });
            for msg in batch {
                app.update(msg);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    done(app)
}

#[test]
fn a_spawn_that_fails_leaves_no_process_behind_and_returns_the_error() {
    sandboxed!();
    let w = World::new(PROJECT);
    w.approve();
    let launch = spec(&w, &["/bin/sh", "-c", "sleep 300"]);
    let vars: Vec<(&str, std::ffi::OsString)> = vec![
        ("HB_TD_HOME", w.home_dir().into_os_string()),
        ("HB_TD_CWD", w.project.clone().into_os_string()),
        ("HB_TD_PATH", w.base.join("bin").into_os_string()),
        ("HB_TD_TMP", w.base.join("tmp").into_os_string()),
    ];
    let extra: Vec<(&str, &std::ffi::OsStr)> =
        vars.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
    let started = assert_ok!(start_with_env(
        &PathBuf::from(DRIVE),
        &PathBuf::from(SUPERVISE),
        &launch,
        30,
        100,
        &extra
    ));
    let pid = assert_ok!(i32::try_from(started.child.id()));
    // A channel that is already closed: the handshake cannot be written, so spawn fails after the
    // process exists and before any thread runs. Everything must be undone on that path.
    assert_ok!(started.channel.shutdown(std::net::Shutdown::Both));
    let (tx, _rx) = sync_channel(INBOX);
    let result = spawn(SessionId(1), 1, started, Shared::new(30, 100), tx);
    assert!(result.is_err(), "spawn went on with a closed channel");
    // The process was killed and reaped by spawn itself: nothing is left to signal.
    assert!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err(),
        "hb ({pid}) is still there after a failed spawn"
    );
}

/// This process's kernel thread census, used only in the isolated failure test.
fn session_threads() -> Vec<String> {
    let out = assert_ok!(
        std::process::Command::new("/bin/ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
    );
    assert!(
        out.status.success(),
        "thread census failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<_> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_owned)
        .collect();
    assert!(lines.len() > 1, "thread census is empty");
    lines
}

#[test]
fn a_spawn_that_fails_at_any_step_leaves_no_process_and_ends_every_thread_it_started() {
    use strum::IntoEnumIterator;
    const ISOLATED: &str = "HB_ISOLATED_SPAWN_FAILURE_TEST";
    if std::env::var_os(ISOLATED).is_none() {
        let output = assert_ok!(std::process::Command::new(assert_ok!(std::env::current_exe()))
            .args(["--exact", "a_spawn_that_fails_at_any_step_leaves_no_process_and_ends_every_thread_it_started", "--nocapture"])
            .env(ISOLATED, "1").output());
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        return;
    }
    sandboxed!();
    for (index, step) in Step::iter().enumerate() {
        let w = World::new(PROJECT);
        w.approve();
        let launch = spec(&w, &["/bin/sh", "-c", "sleep 300"]);
        let vars: Vec<(&str, std::ffi::OsString)> = vec![
            ("HB_TD_HOME", w.home_dir().into_os_string()),
            ("HB_TD_CWD", w.project.clone().into_os_string()),
            ("HB_TD_PATH", w.base.join("bin").into_os_string()),
            ("HB_TD_TMP", w.base.join("tmp").into_os_string()),
        ];
        let extra: Vec<(&str, &std::ffi::OsStr)> =
            vars.iter().map(|(k, v)| (*k, v.as_os_str())).collect();
        let started = assert_ok!(start_with_env(
            &PathBuf::from(DRIVE),
            &PathBuf::from(SUPERVISE),
            &launch,
            30,
            100,
            &extra
        ));
        let pid = assert_ok!(i32::try_from(started.child.id()));
        // A full inbox that nobody reads, so a started reader that sends would stay blocked on
        // it unless cancelling really reaches it.
        let (tx, rx) = sync_channel(1);
        // Filled now, so that every message a reader tries to deliver has nowhere to go until
        // someone reads; nobody will.
        assert_ok!(tx.send(Msg::Notice("filler".into())));
        let threads_before = session_threads().len();
        FAIL_AT.store(index, std::sync::atomic::Ordering::SeqCst);
        let result = spawn(SessionId(1), 1, started, Shared::new(30, 100), tx);
        FAIL_AT.store(usize::MAX, std::sync::atomic::Ordering::SeqCst);
        assert!(
            result.is_err(),
            "{step}: spawn went on after the injected failure"
        );
        // The process was killed and reaped by spawn itself.
        assert!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None).is_err(),
            "{step}: hb ({pid}) is still there"
        );
        // Every thread that was started ends, whatever it was doing.
        let deadline = Instant::now() + Duration::from_secs(10);
        while session_threads().len() > threads_before && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(
            session_threads().len().saturating_sub(threads_before),
            0,
            "{step}: a thread outlived a failed spawn"
        );
        drop(rx);
    }
}
