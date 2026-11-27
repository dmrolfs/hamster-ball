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
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use crossterm::event::{self, Event as Key};
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
use nix::sys::signal::{SigSet, Signal};
use nix::sys::time::TimeSpec;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use snafu::{ResultExt, Snafu};

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

/// Why the supervisor's loop ended in failure. Whatever the cause, the terminal is restored and
/// the sessions are stopped before this is reported.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum UiError {
    /// The owner's terminal could not be read, drawn on or handed over.
    #[snafu(display("the terminal failed"))]
    Terminal {
        /// The OS error.
        source: io::Error,
    },
    /// The kernel's signal queue could not be set up or read, so a stop could go unseen.
    #[snafu(display("the signal queue failed"))]
    Signals {
        /// The OS error.
        source: io::Error,
    },
    /// A thread of the supervisor panicked.
    #[snafu(display("a supervisor thread panicked"))]
    Panicked,
}

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
/// [`UiError`] if the terminal or the signal queue cannot be set up. A failure after that is
/// reported on stderr and as [`Ended::Unclean`].
pub fn run(paths: Paths, cwd: &std::path::Path) -> Result<Ended, UiError> {
    // Before any thread exists, so every thread has them blocked and only the loop sees them.
    let mut stop = StopSignals::watch()?;
    let hb = paths.hb.clone();
    let me = paths.me.clone();
    let env = paths.env.clone();
    let mut runtime = Runtime::new(paths);
    let mut guard = TerminalGuard::enter().context(TerminalSnafu)?;
    install_panic_hook();
    // The review child lives here, outside the closure that may unwind, so a panic cannot leave it
    // running: it is killed and reaped below, with the sessions.
    let mut review_child: Option<Child> = None;
    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let mut screen =
            Terminal::new(CrosstermBackend::new(io::stdout())).context(TerminalSnafu)?;
        event_loop(
            &mut guard,
            &mut screen,
            &mut runtime,
            cwd,
            &Reviewer { hb, me, env },
            &mut stop,
            &mut review_child,
        )
    }));
    // The owner has the shell back before the (bounded) wait for the sessions.
    let restored = guard.suspend();
    if let Some(mut child) = review_child.take() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let stopped = runtime.shut_down(QUIT_LIMIT);
    if let Err(error) = &restored {
        eprintln!("hb-supervise: the terminal may not be fully restored: {error}");
    }
    match outcome {
        Ok(Ok(())) if stopped && restored.is_ok() && !fatal() => Ok(Ended::Clean),
        Ok(Ok(())) => Ok(Ended::Unclean),
        Ok(Err(error)) => {
            eprintln!("hb-supervise: {}", snafu::Report::from_error(error));
            Ok(Ended::Unclean)
        }
        // The hook has already restored the terminal and printed the panic.
        Err(_) => Ok(Ended::Unclean),
    }
}

/// The signals that end or interrupt the supervisor.
///
/// SIGTERM and SIGHUP end it through the normal path (terminal restored, sessions stopped)
/// instead of killing it where it stands, and once seen they stay seen: a review that consumed
/// one must not let the supervisor carry on. SIGINT only arrives while the owner's terminal is
/// cooked, which is during a review (raw mode makes Ctrl-C a key for the agent): it cancels that
/// review. They are blocked, so their default action never runs, and read from a kernel queue.
///
/// The queue is the supervisor's only way to see a stop, so a failure to read it is an error,
/// not "no signal".
struct StopSignals {
    queue: Kqueue,
    terminate: bool,
    interrupt: bool,
}

impl StopSignals {
    const WATCHED: [Signal; 3] = [Signal::SIGTERM, Signal::SIGHUP, Signal::SIGINT];

    fn watch() -> Result<Self, UiError> {
        let mut set = SigSet::empty();
        for signal in Self::WATCHED {
            set.add(signal);
        }
        set.thread_block()
            .map_err(io::Error::from)
            .context(SignalsSnafu)?;
        let queue = Kqueue::new()
            .map_err(io::Error::from)
            .context(SignalsSnafu)?;
        let changes: Vec<KEvent> = Self::WATCHED
            .iter()
            .map(|signal| {
                KEvent::new(
                    *signal as usize,
                    EventFilter::EVFILT_SIGNAL,
                    EvFlags::EV_ADD | EvFlags::EV_ENABLE,
                    FilterFlag::empty(),
                    0,
                    0,
                )
            })
            .collect();
        queue
            .kevent(&changes, &mut [], None)
            .map_err(io::Error::from)
            .context(SignalsSnafu)?;
        Ok(Self {
            queue,
            terminate: false,
            interrupt: false,
        })
    }

    /// Reads what has arrived and remembers it.
    fn poll(&mut self) -> Result<(), UiError> {
        let blank = KEvent::new(
            0,
            EventFilter::EVFILT_SIGNAL,
            EvFlags::empty(),
            FilterFlag::empty(),
            0,
            0,
        );
        let mut events = [blank; 4];
        let now = TimeSpec::new(0, 0);
        let n = self
            .queue
            .kevent(&[], &mut events, Some(*now.as_ref()))
            .map_err(io::Error::from)
            .context(SignalsSnafu)?;
        for event in &events[..n] {
            if event.ident() == Signal::SIGINT as usize {
                self.interrupt = true;
            } else {
                self.terminate = true;
            }
        }
        Ok(())
    }

    /// Whether SIGTERM or SIGHUP has been seen. Stays true.
    const fn terminated(&self) -> bool {
        self.terminate
    }

    /// Whether SIGINT has been seen since the last call.
    fn take_interrupt(&mut self) -> bool {
        std::mem::take(&mut self.interrupt)
    }
}

/// How `hb approve` is run.
struct Reviewer {
    hb: std::path::PathBuf,
    /// This supervisor, started again as the review helper that clears the signal mask.
    me: std::path::PathBuf,
    env: Vec<(String, std::ffi::OsString)>,
}

/// What the loop's pieces share: the terminal, the sessions, the signals and the review child.
struct Loop<'a> {
    guard: &'a mut TerminalGuard,
    screen: &'a mut Screen,
    runtime: &'a mut Runtime,
    stop: &'a mut StopSignals,
    review_child: &'a mut Option<Child>,
    reviewer: &'a Reviewer,
    cwd: &'a std::path::Path,
    router: Router,
}

fn event_loop(
    guard: &mut TerminalGuard,
    screen: &mut Screen,
    runtime: &mut Runtime,
    cwd: &std::path::Path,
    reviewer: &Reviewer,
    stop: &mut StopSignals,
    review_child: &mut Option<Child>,
) -> Result<(), UiError> {
    let look = Look::from_no_color(std::env::var_os("NO_COLOR").as_deref());
    let mut ui = Loop {
        guard,
        screen,
        runtime,
        stop,
        review_child,
        reviewer,
        cwd,
        router: Router::new(),
    };
    let mut sized: HashMap<(SessionId, Generation), (u16, u16)> = HashMap::new();
    let mut changed = true;
    loop {
        let stepped = ui.runtime.step();
        changed |= stepped.applied > 0;
        let mut quit = stepped.quit;
        for approval in ui.runtime.take_approvals() {
            if !ui.review(&approval)? {
                return Ok(());
            }
            changed = true;
        }
        ui.stop.poll()?;
        if fatal() {
            return Err(UiError::Panicked);
        }
        if ui.stop.terminated() {
            return Ok(());
        }
        fit(ui.screen, ui.runtime, &mut sized)?;
        if ui.runtime.frame_due(changed, Instant::now()) {
            draw(ui.screen, ui.runtime, look)?;
        }
        changed = false;
        let mut handled = 0;
        while handled < EVENTS_PER_TURN && event::poll(poll_wait(handled)).context(TerminalSnafu)? {
            handled += 1;
            changed = true;
            quit |= ui.handle(event::read().context(TerminalSnafu)?)?;
            // Whatever was typed after the key that asked for a review is not for the supervisor
            // and not for the review: it is dropped when the review starts.
            if ui.runtime.has_approvals() {
                break;
            }
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

fn draw(screen: &mut Screen, runtime: &Runtime, look: Look) -> Result<(), UiError> {
    let lookup = |id: SessionId| runtime.screen(id).cloned();
    screen
        .draw(|frame| {
            #[cfg(feature = "test-support")]
            test_panic();
            view::draw(frame, &runtime.app, &lookup, look);
        })
        .context(TerminalSnafu)?;
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
) -> Result<(), UiError> {
    let size = screen.size().context(TerminalSnafu)?;
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

impl Loop<'_> {
    /// Applies one terminal event; true when the owner confirmed a quit.
    fn handle(&mut self, event: Key) -> Result<bool, UiError> {
        let size = self.screen.size().context(TerminalSnafu)?;
        let modes = self
            .runtime
            .app
            .selected()
            .and_then(|s| self.runtime.screen(s.id))
            .and_then(|shared| shared.screen.lock().ok().map(|s| s.modes()))
            .unwrap_or_default();
        let ctx = Context {
            layout: Layout::for_size(size.width, size.height),
            modes,
            cwd: self.cwd,
        };
        // Releases go to the router too: it ignores them, and that is how a release between the
        // two presses of `Ctrl-g Ctrl-g` is known not to cancel the pair.
        let msgs = match event {
            Key::Key(key) => self.router.route(&self.runtime.app, key, &ctx),
            Key::Paste(text) => self.router.paste(&self.runtime.app, &text, &ctx),
            _ => Vec::new(),
        };
        let mut quit = false;
        for msg in msgs {
            quit |= self.runtime.send(msg);
        }
        Ok(quit)
    }

    /// Gives the real terminal to `hb approve` for one session, and takes it back. False when the
    /// supervisor was told to stop meanwhile, in which case the UI is not resumed.
    ///
    /// Nothing the owner typed before reaches the review: pending events are dropped and the
    /// terminal's input queue is flushed, both before the review starts and after it ends, and
    /// if the flush fails the review is not started. The supervisor types nothing into the review
    /// and never reads its answer; it sees only the exit status. The inbox keeps being read the
    /// whole time.
    fn review(&mut self, approval: &Approval) -> Result<bool, UiError> {
        self.router = Router::new();
        drain_events()?;
        let outcome = match self.guard.suspend() {
            Ok(()) => match flush_input() {
                Ok(()) => self.run_review(approval),
                Err(error) => ApprovalOutcome::Failed(format!(
                    "the terminal's pending input could not be dropped, so no review was started: {error}"
                )),
            },
            Err(error) => {
                ApprovalOutcome::Failed(format!("the terminal could not be given back: {error}"))
            }
        };
        // A stop that arrived while the review was ending is seen now, before the UI is resumed or
        // the result applied. Defence in depth: a restart already waits for the old worker and the
        // loop polls again before it starts, so no way to start a session after a stop was found;
        // this keeps that from depending on the order of those two. `poll` fails only if the queue
        // itself is broken, which is a stop we cannot see and is treated as one.
        if self.stop.poll().is_err() || self.stop.terminated() || fatal() {
            return Ok(false);
        }
        drain_events()?;
        // A flush that fails here leaves possible stale keys for the UI; say so, stay in the UI.
        let flushed = flush_input();
        self.guard.resume().context(TerminalSnafu)?;
        // `clear` would ask the terminal where the cursor is and wait for the reply, which fails
        // right after a hand-over; `resize` clears the same area and forgets what was drawn.
        let size = self.screen.size().context(TerminalSnafu)?;
        self.screen
            .resize(Rect::new(0, 0, size.width, size.height))
            .context(TerminalSnafu)?;
        self.router = Router::new();
        self.runtime.send(Msg::ApprovalFinished {
            id: approval.id,
            generation: approval.generation,
            outcome,
        });
        if let Err(error) = flushed {
            self.runtime.send(Msg::Notice(format!(
                "pending keys could not be dropped after the review: {error}"
            )));
        }
        Ok(true)
    }

    fn run_review(&mut self, approval: &Approval) -> ApprovalOutcome {
        // Through the review helper, which clears the signal mask first: the supervisor blocks
        // INT, TERM and HUP in every thread and `Command` would hand that to the review, which
        // could then not be ended by Ctrl-C or `kill`.
        let mut command = Command::new(&self.reviewer.me);
        command
            .arg(crate::supervise::launch::REVIEW_ARG)
            .arg(&self.reviewer.hb)
            .arg("approve")
            .current_dir(&approval.project)
            .envs(self.reviewer.env.iter().map(|(k, v)| (k, v)))
            // After the extra variables, so nothing can put the channel back: the review is not
            // a session and must not see a supervisor channel.
            .env_remove(crate::session::supervised::SUPERVISOR_FD_VAR);
        match command.spawn() {
            Ok(child) => *self.review_child = Some(child),
            Err(error) => return ApprovalOutcome::Failed(error.to_string()),
        }
        let outcome = self.wait_for_review();
        // Ended or cancelled, the child is reaped before anything else happens.
        if let Some(mut child) = self.review_child.take() {
            if outcome.is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
        outcome.unwrap_or(ApprovalOutcome::NotApproved)
    }

    /// `None` when the review was cut short (a stop or Ctrl-C); the child is then still there.
    fn wait_for_review(&mut self) -> Option<ApprovalOutcome> {
        loop {
            let child = self.review_child.as_mut()?;
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Some(ApprovalOutcome::Approved),
                Ok(Some(_)) => return Some(ApprovalOutcome::NotApproved),
                Ok(None) => {}
                Err(error) => return Some(ApprovalOutcome::Failed(error.to_string())),
            }
            // Other sessions go on being read while the owner answers.
            self.runtime.step();
            // A signal the queue could not report is a stop we cannot see: treat it as one.
            if self.stop.poll().is_err()
                || self.stop.terminated()
                || self.stop.take_interrupt()
                || fatal()
            {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Drops terminal events already read or waiting, without waiting for more.
fn drain_events() -> Result<(), UiError> {
    let mut dropped = 0;
    while event::poll(Duration::ZERO).context(TerminalSnafu)? {
        let _ = event::read().context(TerminalSnafu)?;
        dropped += 1;
        // Continuous input would never end this; the flush after it drops the rest.
        if dropped >= 10_000 {
            break;
        }
    }
    Ok(())
}
