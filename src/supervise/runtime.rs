// ABOUTME: Runtime: executes the app's effects (spawn, stop), owns each session's worker and screen, and drains one bounded inbox into the pure update.
// ABOUTME: Also the frame cap: a render is due only when something changed and 1/30 s has passed, so output floods cost one redraw per frame, not per read.
//! The runtime around [`App`] (epic hb-b6q).
//!
//! [`Runtime::step`] is one turn of the loop the UI will run: take what workers have sent (at
//! most [`MAX_PER_STEP`] messages, so a flood cannot keep the loop from drawing or reading keys),
//! apply each with [`App::update`], carry out the effects, and say whether a redraw is due.
//! It reads no keys and draws nothing; the screens in a later task call it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::time::{Duration, Instant};

use super::app::{App, Effect, Generation, LaunchSpec, Msg, SessionId};
use super::launch::start_with_env;
use super::session::{Shared, Worker, spawn};

/// Frames per second at most.
pub const MAX_FPS: u32 = 30;
/// The smallest gap between two redraws.
pub const FRAME: Duration = Duration::from_micros(1_000_000 / MAX_FPS as u64);
/// The most messages applied in one step.
pub const MAX_PER_STEP: usize = 512;
/// Messages the inbox holds before workers block.
pub const INBOX: usize = 256;
/// The size a session's terminal starts with, before the layout says otherwise.
pub const START_SIZE: (u16, u16) = (24, 80);

/// Where the binaries are, and extra variables for the session (for a test double of `hb`).
#[derive(Debug, Clone)]
pub struct Paths {
    /// The `hb` binary.
    pub hb: PathBuf,
    /// This supervisor, started again as the launch helper.
    pub me: PathBuf,
    /// Variables added to each session's environment.
    pub env: Vec<(String, std::ffi::OsString)>,
}

struct Live {
    generation: Generation,
    worker: Worker,
}

/// How long an old generation gets to end before it is abandoned (killed) and its replacement
/// is refused: the stop grace, plus time for the kill and the last reports.
const RETIRE_LIMIT: Duration = Duration::from_secs(15);

/// A worker that was asked to stop and is still ending. It stays here, and the inbox stays
/// drained, until every thread has finished; nothing waits on it with the inbox unread.
struct Retiring {
    id: SessionId,
    worker: Worker,
    since: Instant,
    abandoned: bool,
}

/// A review the owner asked for. The loop that owns the real terminal carries it out and answers
/// with [`Msg::ApprovalFinished`]; the runtime never touches the terminal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The session.
    pub id: SessionId,
    /// The generation that asked.
    pub generation: Generation,
    /// The project directory to run `hb approve` in.
    pub project: PathBuf,
}

/// What a step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stepped {
    /// Messages applied.
    pub applied: usize,
    /// Whether the supervisor should now leave.
    pub quit: bool,
}

/// The app, its workers and its inbox.
pub struct Runtime {
    /// The state the screens draw.
    pub app: App,
    paths: Paths,
    inbox: Receiver<Msg>,
    outbox: SyncSender<Msg>,
    live: HashMap<SessionId, Live>,
    retiring: Vec<Retiring>,
    /// The newest start asked for while the session's old worker is still ending.
    waiting: HashMap<SessionId, (Generation, LaunchSpec)>,
    screens: HashMap<SessionId, Arc<Shared>>,
    last_frame: Option<Instant>,
    /// A change that has not been drawn yet; kept until a frame is drawn, so one that lands
    /// inside the frame interval is drawn on the next eligible call and not lost.
    redraw_pending: bool,
    approvals: Vec<Approval>,
}

impl Runtime {
    /// A runtime with no sessions.
    #[must_use]
    pub fn new(paths: Paths) -> Self {
        let (outbox, inbox) = sync_channel(INBOX);
        Self {
            app: App::new(),
            paths,
            inbox,
            outbox,
            live: HashMap::new(),
            retiring: Vec::new(),
            waiting: HashMap::new(),
            screens: HashMap::new(),
            last_frame: None,
            redraw_pending: false,
            approvals: Vec::new(),
        }
    }

    /// The screen of a session, for drawing; it outlives the process so the last output stays.
    #[must_use]
    pub fn screen(&self, id: SessionId) -> Option<&Arc<Shared>> {
        self.screens.get(&id)
    }

    /// The running session's worker, for input, resize and stop.
    pub fn worker(&mut self, id: SessionId) -> Option<&mut Worker> {
        self.live.get_mut(&id).map(|l| &mut l.worker)
    }

    /// Applies a message from the keyboard side, then carries out its effects.
    pub fn send(&mut self, msg: Msg) -> bool {
        let effects = self.app.update(msg);
        self.run(effects)
    }

    /// One turn: apply what workers sent, carry out the effects, and report.
    pub fn step(&mut self) -> Stepped {
        let mut applied = 0;
        let mut quit = false;
        while applied < MAX_PER_STEP {
            let Ok(msg) = self.inbox.try_recv() else {
                break;
            };
            applied += 1;
            let effects = self.app.update(msg);
            quit |= self.run(effects);
        }
        self.advance(Instant::now());
        Stepped { applied, quit }
    }

    /// Whether a redraw is due: something changed (a message, or a dirty screen) and a frame has
    /// passed since the last one. A change is remembered until a frame is drawn. Returning `true`
    /// records the frame.
    pub fn frame_due(&mut self, changed: bool, now: Instant) -> bool {
        // Every screen's flag is cleared, so this must not stop at the first one that was set.
        let mut dirty = false;
        for shared in self.screens.values() {
            dirty |= shared.take_dirty();
        }
        let ready = self
            .last_frame
            .is_none_or(|at| now.duration_since(at) >= FRAME);
        self.redraw_pending |= changed || dirty;
        let due = self.redraw_pending && ready;
        if due {
            self.last_frame = Some(now);
            self.redraw_pending = false;
        }
        due
    }

    /// Stops every worker and waits, for at most `limit` in all, reading the inbox as it waits.
    /// Returns whether every worker ended in time; the rest are killed.
    pub fn shut_down(&mut self, limit: Duration) -> bool {
        self.waiting.clear();
        let ids: Vec<SessionId> = self.live.keys().copied().collect();
        for id in ids {
            self.retire(id);
        }
        let deadline = Instant::now() + limit;
        loop {
            self.step();
            if self.retiring.is_empty() {
                return true;
            }
            if Instant::now() >= deadline {
                for old in &mut self.retiring {
                    old.worker.abandon();
                }
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The reviews asked for since the last call, oldest first.
    pub fn take_approvals(&mut self) -> Vec<Approval> {
        std::mem::take(&mut self.approvals)
    }

    /// Whether any worker is still ending.
    #[must_use]
    pub fn is_retiring(&self) -> bool {
        !self.retiring.is_empty()
    }

    /// Asks the session's worker to stop, and tracks it until it has ended.
    fn retire(&mut self, id: SessionId) {
        if let Some(mut live) = self.live.remove(&id) {
            live.worker.stop();
            self.retiring.push(Retiring {
                id,
                worker: live.worker,
                since: Instant::now(),
                abandoned: false,
            });
        }
    }

    /// Reaps workers that have ended, abandons ones that have not ended in time, and starts the
    /// replacements that were waiting for an old worker to end.
    fn advance(&mut self, now: Instant) {
        let mut i = 0;
        while i < self.retiring.len() {
            if self.retiring[i].worker.is_finished() {
                self.retiring.swap_remove(i).worker.join();
            } else {
                let old = &mut self.retiring[i];
                if !old.abandoned && now.duration_since(old.since) >= RETIRE_LIMIT {
                    old.abandoned = true;
                    old.worker.abandon();
                    let id = old.id;
                    self.refuse_replacement(id);
                }
                i += 1;
            }
        }
        let ready: Vec<SessionId> = self
            .waiting
            .keys()
            .copied()
            .filter(|id| !self.retiring.iter().any(|r| r.id == *id))
            .collect();
        for id in ready {
            if let Some((generation, spec)) = self.waiting.remove(&id) {
                self.start(id, generation, &spec);
            }
        }
    }

    /// The old generation did not end, so the new one is not started: two would overlap.
    fn refuse_replacement(&mut self, id: SessionId) {
        if let Some((generation, _)) = self.waiting.remove(&id) {
            let effects = self.app.update(Msg::SpawnFailed {
                id,
                generation,
                reason: "the previous run did not end in time, so this one was not started"
                    .to_owned(),
            });
            if !effects.is_empty() {
                let _ = self.run(effects);
            }
        }
    }

    /// Carries out effects; true when one of them was `Quit`.
    fn run(&mut self, effects: Vec<Effect>) -> bool {
        let mut quit = false;
        for effect in effects {
            match effect {
                Effect::Spawn {
                    id,
                    generation,
                    spec,
                } => self.spawn(id, generation, &spec),
                Effect::Stop { id, generation } => {
                    if let Some(live) = self.live.get_mut(&id)
                        && live.generation == generation
                    {
                        live.worker.stop();
                    }
                }
                Effect::Write {
                    id,
                    generation,
                    bytes,
                } => {
                    if let Some(live) = self.live.get_mut(&id)
                        && live.generation == generation
                    {
                        // A failed write means the terminal is closing; the reaper reports it.
                        let _ = live.worker.write_input(&bytes);
                    }
                }
                Effect::SuspendForApproval {
                    id,
                    generation,
                    project,
                } => self.approvals.push(Approval {
                    id,
                    generation,
                    project,
                }),
                Effect::Quit => quit = true,
            }
        }
        quit
    }

    /// Starts the session, and tells the app how it went. A failure becomes a message, so the
    /// app shows it; nothing here decides what a failure means.
    fn spawn(&mut self, id: SessionId, generation: Generation, spec: &LaunchSpec) {
        // A restart replaces the worker, but only once the old one has ended: its late messages
        // carry the old generation and the app drops them. Until then the newest start waits.
        self.retire(id);
        if self.retiring.iter().any(|r| r.id == id) {
            self.waiting.insert(id, (generation, spec.clone()));
            return;
        }
        self.start(id, generation, spec);
    }

    /// Starts the session, and tells the app how it went.
    fn start(&mut self, id: SessionId, generation: Generation, spec: &LaunchSpec) {
        let (rows, cols) = START_SIZE;
        let extra: Vec<(&str, &std::ffi::OsStr)> = self
            .paths
            .env
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_os_str()))
            .collect();
        let outcome = start_with_env(&self.paths.hb, &self.paths.me, spec, rows, cols, &extra)
            .map_err(|e| e.to_string());
        let shared = Shared::new(rows, cols);
        let outcome = outcome.and_then(|started| {
            spawn(
                id,
                generation,
                started,
                Arc::clone(&shared),
                self.outbox.clone(),
            )
            .map_err(|e| format!("the session's threads could not start: {e}"))
        });
        let msg = match outcome {
            Ok(worker) => {
                self.screens.insert(id, shared);
                self.live.insert(id, Live { generation, worker });
                Msg::Spawned { id, generation }
            }
            Err(reason) => Msg::SpawnFailed {
                id,
                generation,
                reason,
            },
        };
        let effects = self.app.update(msg);
        // A spawn message produces no effects; if that ever changes this still runs them.
        if !effects.is_empty() {
            let _ = self.run(effects);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::supervised::Event;
    use crate::supervise::app::{Phase, Session};
    use claims::assert_some;
    use pretty_assertions::assert_eq;

    fn paths() -> Paths {
        Paths {
            hb: PathBuf::from("/nonexistent/hb"),
            me: PathBuf::from("/nonexistent/hb-supervise"),
            env: Vec::new(),
        }
    }

    fn spec() -> LaunchSpec {
        LaunchSpec {
            project: PathBuf::from("/nonexistent/project"),
            command: vec!["agent".to_owned()],
        }
    }

    fn first(runtime: &Runtime) -> &Session {
        assert_some!(runtime.app.sessions().first())
    }

    #[test]
    fn a_session_that_cannot_be_started_becomes_a_failed_row_with_the_reason() {
        let mut runtime = Runtime::new(paths());
        assert!(!runtime.send(Msg::Launch(spec())));
        let session = first(&runtime);
        assert_eq!(session.phase, Phase::Failed);
        assert!(
            session.failure.as_deref().is_some_and(|f| !f.is_empty()),
            "{:?}",
            session.failure
        );
        assert!(runtime.screen(session.id).is_none());
        assert_eq!(runtime.app.alerts().len(), 1);
    }

    #[test]
    fn restarting_a_failed_session_tries_again_as_a_new_generation() {
        let mut runtime = Runtime::new(paths());
        runtime.send(Msg::Launch(spec()));
        runtime.send(Msg::AskRestart);
        let session = first(&runtime);
        assert_eq!(session.generation, 2);
        assert_eq!(session.phase, Phase::Failed);
    }

    #[test]
    fn a_review_of_a_session_not_waiting_for_approval_hands_the_caller_nothing() {
        let mut runtime = Runtime::new(paths());
        runtime.send(Msg::Launch(spec()));
        let (id, generation) = (first(&runtime).id, first(&runtime).generation);
        runtime.send(Msg::Channel {
            id,
            generation,
            seq: 1,
            event: Event::ApprovalRequired {
                root: "/nonexistent/project".into(),
            },
        });
        // The launch failed (no hb), so the row is Failed and a review is refused.
        runtime.send(Msg::ReviewApproval);
        assert_eq!(runtime.take_approvals(), vec![]);
    }

    #[test]
    fn quit_with_nothing_running_is_reported_to_the_caller() {
        let mut runtime = Runtime::new(paths());
        assert!(runtime.send(Msg::AskQuit));
        assert!(runtime.app.is_quitting());
    }

    #[test]
    fn the_inbox_is_bounded_and_a_step_applies_at_most_the_per_step_limit() {
        let mut runtime = Runtime::new(paths());
        runtime.send(Msg::Launch(spec()));
        let id = first(&runtime).id;
        let generation = first(&runtime).generation;
        let warning = |seq: u64| Msg::Channel {
            id,
            generation,
            seq,
            event: Event::Warning { text: "w".into() },
        };
        for seq in 1..=INBOX as u64 {
            assert!(runtime.outbox.try_send(warning(seq)).is_ok());
        }
        assert!(
            runtime.outbox.try_send(Msg::Select(0)).is_err(),
            "a full inbox refuses more, so a worker would block, not grow it"
        );
        assert_eq!(runtime.step().applied, INBOX);
        assert_eq!(runtime.step().applied, 0);
    }

    #[test]
    fn a_step_never_applies_more_than_the_limit_even_when_more_is_waiting() {
        // The limit is what keeps a flood from holding the loop; it is only reachable when it is
        // below the inbox size, so check the relation the design depends on rather than a number.
        const { assert!(MAX_PER_STEP >= INBOX, "one step can empty a full inbox") };
        let mut runtime = Runtime::new(paths());
        let mut sent = 0;
        let refill = |runtime: &Runtime, sent: &mut u64| {
            while runtime.outbox.try_send(Msg::Select(0)).is_ok() {
                *sent += 1;
            }
        };
        refill(&runtime, &mut sent);
        let mut applied = 0u64;
        for _ in 0..4 {
            let step = runtime.step();
            assert!(step.applied <= MAX_PER_STEP);
            applied += step.applied as u64;
            refill(&runtime, &mut sent);
        }
        assert!(applied >= INBOX as u64, "each step drained what was there");
    }

    #[test]
    fn a_frame_is_due_only_when_something_changed_and_a_frame_has_passed() {
        let mut runtime = Runtime::new(paths());
        let t0 = Instant::now();
        assert!(!runtime.frame_due(false, t0), "nothing changed");
        assert!(
            runtime.frame_due(true, t0),
            "the first change draws at once"
        );
        assert!(!runtime.frame_due(true, t0 + FRAME / 2), "too soon");
        assert!(runtime.frame_due(true, t0 + FRAME), "a frame later");
        assert!(
            !runtime.frame_due(false, t0 + FRAME * 10),
            "still nothing to draw"
        );
    }

    #[test]
    fn a_change_inside_the_frame_interval_is_drawn_at_the_next_frame_without_another_change() {
        let mut runtime = Runtime::new(paths());
        let shared = Shared::new(5, 20);
        runtime.screens.insert(SessionId(1), Arc::clone(&shared));
        let t0 = Instant::now();
        assert!(runtime.frame_due(true, t0));
        // The screen changes once, too soon after the last frame, and then nothing else happens.
        shared
            .dirty
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(!runtime.frame_due(false, t0 + FRAME / 2));
        assert!(runtime.frame_due(false, t0 + FRAME), "the change was kept");
        assert!(!runtime.frame_due(false, t0 + FRAME * 3), "and drawn once");
    }

    #[test]
    fn a_dirty_screen_makes_a_frame_due_once_and_clears_the_flag() {
        let mut runtime = Runtime::new(paths());
        let shared = Shared::new(5, 20);
        runtime.screens.insert(SessionId(1), Arc::clone(&shared));
        let t0 = Instant::now();
        assert!(!runtime.frame_due(false, t0));
        shared
            .dirty
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(runtime.frame_due(false, t0));
        assert!(!shared.take_dirty(), "the check cleared it");
        assert!(!runtime.frame_due(false, t0 + FRAME * 2));
    }

    #[test]
    fn the_frame_cap_is_thirty_per_second() {
        assert_eq!(MAX_FPS, 30);
        assert!(FRAME >= Duration::from_millis(33) && FRAME <= Duration::from_millis(34));
    }
}
