// ABOUTME: The supervisor's loop: one thread owns the keyboard, the drawing and the hand-over of the terminal to `hb approve`, and keeps reading session messages throughout.
// ABOUTME: Keys go through the pure Router and App; this file only does I/O: poll, draw, resize, run the review, and shut the sessions down after the terminal is restored.
//! The supervisor's main loop (epic hb-b6q).
//!
//! The loop never waits on a session: a review runs as a child process that the loop watches
//! with `try_wait` while it goes on reading the inbox, so a slow review cannot make `hb` give up
//! on a busy session whose telemetry nobody reads.

use std::collections::HashMap;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as Key};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;

use super::app::{ApprovalOutcome, Generation, Msg, SessionId};
use super::keys::{Context, Router};
use super::runtime::{Approval, FRAME, Paths, Runtime};
use super::terminal_guard::{TerminalGuard, fatal, flush_input, install_panic_hook};
use super::view::{self, Layout, Look};

/// How long the sessions get to end after the owner quits, before they are killed.
pub const QUIT_LIMIT: Duration = Duration::from_secs(20);
/// The most terminal events handled in one turn, so a held key cannot starve the inbox.
const EVENTS_PER_TURN: usize = 64;

type Screen = Terminal<CrosstermBackend<io::Stdout>>;

/// How the supervisor ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The owner quit and every session ended in time.
    Clean,
    /// A session did not end in time and was killed, or the loop failed or panicked.
    Unclean,
}

/// Runs the supervisor on the owner's terminal until the owner quits.
///
/// The terminal is restored before the sessions are shut down, so the owner sees the shell
/// again at once, and any failure or panic is printed readably.
///
/// # Errors
/// The OS error if the terminal cannot be taken.
pub fn run(paths: Paths, cwd: &std::path::Path) -> io::Result<Ended> {
    let hb = paths.hb.clone();
    let env = paths.env.clone();
    let mut runtime = Runtime::new(paths);
    let mut guard = TerminalGuard::enter()?;
    install_panic_hook();
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut screen = Terminal::new(CrosstermBackend::new(io::stdout()))?;
        event_loop(
            &mut guard,
            &mut screen,
            &mut runtime,
            cwd,
            &Reviewer { hb, env },
        )
    }));
    // The owner has the shell back before the (bounded) wait for the sessions.
    let restored = guard.suspend();
    let stopped = runtime.shut_down(QUIT_LIMIT);
    match outcome {
        Ok(Ok(())) if stopped && restored.is_ok() => Ok(Ended::Clean),
        Ok(Ok(())) => Ok(Ended::Unclean),
        Ok(Err(error)) => {
            eprintln!("hb-supervise: {error}");
            Ok(Ended::Unclean)
        }
        // The hook has already restored the terminal and printed the panic.
        Err(_) => Ok(Ended::Unclean),
    }
}

/// How `hb approve` is run.
struct Reviewer {
    hb: std::path::PathBuf,
    env: Vec<(String, std::ffi::OsString)>,
}

fn event_loop(
    guard: &mut TerminalGuard,
    screen: &mut Screen,
    runtime: &mut Runtime,
    cwd: &std::path::Path,
    reviewer: &Reviewer,
) -> io::Result<()> {
    let look = Look::from_no_color(std::env::var_os("NO_COLOR").as_deref());
    let mut router = Router::new();
    let mut sized: HashMap<(SessionId, Generation), (u16, u16)> = HashMap::new();
    let mut changed = true;
    loop {
        let stepped = runtime.step();
        changed |= stepped.applied > 0;
        let mut quit = stepped.quit;
        for approval in runtime.take_approvals() {
            review(guard, screen, runtime, &mut router, reviewer, &approval)?;
            changed = true;
        }
        if fatal() {
            return Ok(());
        }
        fit(screen, runtime, &mut sized)?;
        if runtime.frame_due(changed, Instant::now()) {
            draw(screen, runtime, look)?;
        }
        changed = false;
        let mut handled = 0;
        while handled < EVENTS_PER_TURN && event::poll(poll_wait(handled))? {
            handled += 1;
            changed = true;
            quit |= handle(event::read()?, screen, runtime, &mut router, cwd)?;
        }
        if quit {
            return Ok(());
        }
    }
}

/// Wait up to one frame for the first event of a turn, and none for the rest.
fn poll_wait(handled: usize) -> Duration {
    if handled == 0 { FRAME } else { Duration::ZERO }
}

fn draw(screen: &mut Screen, runtime: &Runtime, look: Look) -> io::Result<()> {
    let lookup = |id: SessionId| runtime.screen(id).cloned();
    screen.draw(|frame| {
        #[cfg(feature = "test-support")]
        test_panic();
        view::draw(frame, &runtime.app, &lookup, look);
    })?;
    Ok(())
}

/// A panic on demand, for the test that checks the terminal is restored after one.
#[cfg(feature = "test-support")]
#[allow(clippy::panic)]
fn test_panic() {
    if std::env::var_os("HB_SUPERVISE_TEST_PANIC").is_some() {
        panic!("test panic while drawing");
    }
}

/// Gives the selected session's terminal the size the layout leaves it, once per size.
fn fit(
    screen: &Screen,
    runtime: &mut Runtime,
    sized: &mut HashMap<(SessionId, Generation), (u16, u16)>,
) -> io::Result<()> {
    let size = screen.size()?;
    let Some((rows, cols)) = view::terminal_size(Rect::new(0, 0, size.width, size.height)) else {
        return Ok(());
    };
    let Some((id, generation)) = runtime.app.selected().map(|s| (s.id, s.generation)) else {
        return Ok(());
    };
    if rows == 0 || cols == 0 || sized.get(&(id, generation)) == Some(&(rows, cols)) {
        return Ok(());
    }
    // A session that has ended has no worker; it keeps the size it had.
    if runtime
        .worker(id)
        .is_some_and(|worker| worker.resize(rows, cols).is_ok())
    {
        sized.insert((id, generation), (rows, cols));
    }
    Ok(())
}

/// Applies one terminal event; true when the owner confirmed a quit.
fn handle(
    event: Key,
    screen: &Screen,
    runtime: &mut Runtime,
    router: &mut Router,
    cwd: &std::path::Path,
) -> io::Result<bool> {
    let size = screen.size()?;
    let modes = runtime
        .app
        .selected()
        .and_then(|s| runtime.screen(s.id))
        .and_then(|shared| shared.screen.lock().ok().map(|s| s.modes()))
        .unwrap_or_default();
    let ctx = Context {
        layout: Layout::for_size(size.width, size.height),
        modes,
        cwd,
    };
    // Releases go to the router too: it ignores them, and that is how a release between the two
    // presses of `Ctrl-g Ctrl-g` is known not to cancel the pair.
    let msgs = match event {
        Key::Key(key) => router.route(&runtime.app, key, &ctx),
        Key::Paste(text) => router.paste(&runtime.app, &text, &ctx),
        _ => Vec::new(),
    };
    let mut quit = false;
    for msg in msgs {
        quit |= runtime.send(msg);
    }
    Ok(quit)
}

/// Gives the real terminal to `hb approve` for one session, and takes it back.
///
/// Nothing the owner typed before reaches the review: pending events are dropped and the
/// terminal's input queue is flushed, both before the review starts and after it ends. The
/// supervisor types nothing into the review and never reads its answer; it sees only the exit
/// status. The inbox keeps being read the whole time.
fn review(
    guard: &mut TerminalGuard,
    screen: &mut Screen,
    runtime: &mut Runtime,
    router: &mut Router,
    reviewer: &Reviewer,
    approval: &Approval,
) -> io::Result<()> {
    *router = Router::new();
    drain_events()?;
    let outcome = match guard.suspend() {
        Ok(()) => run_review(runtime, reviewer, approval),
        Err(error) => {
            ApprovalOutcome::Failed(format!("the terminal could not be given back: {error}"))
        }
    };
    drain_events()?;
    flush_input();
    guard.resume()?;
    screen.clear()?;
    *router = Router::new();
    runtime.send(Msg::ApprovalFinished {
        id: approval.id,
        generation: approval.generation,
        outcome,
    });
    Ok(())
}

fn run_review(runtime: &mut Runtime, reviewer: &Reviewer, approval: &Approval) -> ApprovalOutcome {
    flush_input();
    let mut command = Command::new(&reviewer.hb);
    command
        .arg("approve")
        .current_dir(&approval.project)
        // The review is not a session: it must not see a supervisor channel.
        .env_remove(crate::session::supervised::SUPERVISOR_FD_VAR)
        .envs(reviewer.env.iter().map(|(k, v)| (k, v)));
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => return ApprovalOutcome::Failed(error.to_string()),
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return ApprovalOutcome::Approved,
            Ok(Some(_)) => return ApprovalOutcome::NotApproved,
            Ok(None) => {}
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return ApprovalOutcome::Failed(error.to_string());
            }
        }
        // Other sessions go on being read while the owner answers.
        runtime.step();
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Drops terminal events already read or waiting, without waiting for more.
fn drain_events() -> io::Result<()> {
    let mut dropped = 0;
    while event::poll(Duration::ZERO)? {
        let _ = event::read()?;
        dropped += 1;
        // Continuous input would never end this; the flush after it drops the rest.
        if dropped >= 10_000 {
            break;
        }
    }
    Ok(())
}
