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
use super::outbox::InputError;
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
    generation: Generation,
    worker: Worker,
    since: Instant,
    abandoned: bool,
}

/// What a generation's `hb` has reported, kept by the runtime itself. The session row cannot be
/// the source: a restart replaces the row before the old worker is retired, and the late reports of
/// an old generation are dropped by the app.
#[derive(Debug, Default, Clone, Copy)]
struct Evidence {
    /// The agent's process id, as reported by `Running`. Never 0, 1 or out of range.
    agent: Option<u32>,
    /// A valid no-run report or normal leader-exit/teardown report, not a descendant census.
    settled: bool,
    last_seq: u64,
    started: bool,
    approval: bool,
    stopping: bool,
    exited: bool,
    invalid: bool,
    cleanup_failed: bool,
}

impl Evidence {
    fn observe(&mut self, seq: u64, event: &crate::session::supervised::Event) {
        use crate::session::supervised::{Cleanup, Event};
        if self.invalid {
            return;
        }
        if self.last_seq.checked_add(1) != Some(seq) || self.exited {
            self.invalid = true;
            self.settled = false;
            return;
        }
        self.last_seq = seq;
        match event {
            Event::Starting {} if !self.started => self.started = true,
            Event::ApprovalRequired { .. }
                if self.started && self.agent.is_none() && !self.approval && !self.stopping =>
            {
                self.approval = true;
                self.settled = true;
            }
            Event::Running { agent_pid }
                if self.started
                    && self.agent.is_none()
                    && !self.approval
                    && !self.stopping
                    && usable_pid(*agent_pid) =>
            {
                self.agent = Some(*agent_pid);
            }
            Event::Stopping {} if self.started && !self.stopping => self.stopping = true,
            Event::Exited {
                code,
                signal,
                cleanup,
            } if self.started && !(code.is_some() && signal.is_some()) => {
                self.exited = true;
                self.cleanup_failed = matches!(cleanup, Cleanup::Failed { .. });
                self.settled = !self.cleanup_failed;
            }
            Event::Starting {}
            | Event::ApprovalRequired { .. }
            | Event::Running { .. }
            | Event::Stopping {}
            | Event::Exited { .. } => self.invalid = true,
            _ if !self.started => self.invalid = true,
            _ => {}
        }
        if self.invalid {
            self.settled = false;
        }
    }

    fn after_delivery(mut self, reliable: bool, now: Instant) -> Option<Blocker> {
        self.invalid |= !reliable;
        self.blocker(now)
    }

    fn blocker(self, now: Instant) -> Option<Blocker> {
        if self.invalid || self.cleanup_failed {
            return Some(Blocker::Unknown);
        }
        if self.settled {
            return None;
        }
        match self.agent {
            Some(pid) if process_exists(pid) => Some(Blocker::Agent { pid, since: now }),
            Some(_) => None,
            None => Some(Blocker::Unknown),
        }
    }
}

/// Why a session's next run may not start yet. Ending `hb` is not ending its agent: when `hb` is
/// killed its guardian stops the agent afterwards, after a grace period (measured: a stubborn
/// agent lived 2.0 s after `hb` was reaped in 60 ms).
#[derive(Debug, Clone, Copy)]
enum Blocker {
    /// This agent may still be running. Waited for, and re-checked for as long as it exists.
    Agent { pid: u32, since: Instant },
    /// `hb` ended without reporting an agent or a clean finish, so whether one was started is not
    /// known. Nothing in the supervisor can find out, so this one never clears.
    Unknown,
}

impl Blocker {
    /// Whether waiting any longer is pointless: the replacement is refused, not queued.
    fn expired(self, now: Instant) -> bool {
        match self {
            Self::Agent { since, .. } => now.duration_since(since) >= AGENT_LIMIT,
            Self::Unknown => true,
        }
    }

    fn reason(self) -> String {
        match self {
            Self::Agent { pid, .. } => format!(
                "the previous run's agent (process {pid}) is still running, so this run was not started"
            ),
            Self::Unknown => "whether the previous run's agent ended could not be confirmed, so this run was not started"
                .to_owned(),
        }
    }
}

/// How long an agent that outlived its `hb` is waited for before a replacement is refused. The
/// guardian's grace is 2 s and then SIGKILL; this is several times that.
const AGENT_LIMIT: Duration = Duration::from_secs(15);

/// Whether a process with this id exists. A process id can be reused, so a "yes" after a long
/// time could be a stranger: the wait ends in a refusal, never in a start, and nothing is ever
/// signalled with a stored id.
fn process_exists(pid: u32) -> bool {
    i32::try_from(pid).is_ok_and(|pid| {
        // Signal 0 only asks whether the process could be signalled; EPERM means it exists.
        !matches!(
            nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
            Err(nix::errno::Errno::ESRCH)
        )
    })
}

/// An agent id that can be asked about: 0 means "my own process group" to `kill` and 1 is init.
fn usable_pid(pid: u32) -> bool {
    pid > 1 && i32::try_from(pid).is_ok()
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

impl std::fmt::Debug for Runtime {
    /// Without the configured environment, which can hold anything the caller put there.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Runtime")
            .field("sessions", &self.app.sessions().len())
            .field("live", &self.live.len())
            .field("retiring", &self.retiring.len())
            .field("waiting", &self.waiting.len())
            .finish_non_exhaustive()
    }
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
    /// What each started generation has reported, until its worker has been dealt with.
    evidence: HashMap<(SessionId, Generation), Evidence>,
    /// Sessions whose previous agent may still exist.
    blocked: HashMap<SessionId, Blocker>,
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
            evidence: HashMap::new(),
            blocked: HashMap::new(),
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
        self.observe(&msg);
        let effects = self.app.update(msg);
        self.run(effects)
    }

    /// Lifecycle reports belong to their generation even after the app has replaced its row.
    fn observe(&mut self, msg: &Msg) {
        match msg {
            Msg::Channel {
                id,
                generation,
                seq,
                event,
            } => {
                if let Some(evidence) = self.evidence.get_mut(&(*id, *generation)) {
                    evidence.observe(*seq, event);
                }
            }
            Msg::SessionLost { id, generation, .. } => {
                if let Some(evidence) = self.evidence.get_mut(&(*id, *generation)) {
                    evidence.invalid = true;
                    evidence.settled = false;
                }
            }
            _ => {}
        }
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
            quit |= self.send(msg);
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
            let agents_pending = self
                .blocked
                .values()
                .any(|b| matches!(b, Blocker::Agent { pid, .. } if process_exists(*pid)));
            if self.retiring.is_empty() && !agents_pending {
                // An agent that could not be confirmed gone is not a clean end.
                return self.blocked.is_empty();
            }
            if Instant::now() >= deadline {
                for old in &mut self.retiring {
                    old.abandoned = true;
                    old.worker.abandon();
                }
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Abandons the session's retiring worker at once, as happens when it has not ended in time:
    /// `hb` is killed at the reaper's next look and its agent is left to the guardian. For tests,
    /// which need that state without waiting out the retirement deadline.
    #[cfg(feature = "test-support")]
    pub fn abandon_for_test(&mut self, id: SessionId) {
        for old in &mut self.retiring {
            if old.id == id {
                old.abandoned = true;
                old.worker.abandon();
            }
        }
    }

    /// Whether a review has been asked for and not yet taken.
    #[must_use]
    pub fn has_approvals(&self) -> bool {
        !self.approvals.is_empty()
    }

    /// The reviews asked for since the last call, oldest first.
    pub fn take_approvals(&mut self) -> Vec<Approval> {
        std::mem::take(&mut self.approvals)
    }

    /// Whether any worker is still ending.
    #[must_use]
    pub fn is_retiring(&self) -> bool {
        !self.retiring.is_empty() || !self.blocked.is_empty()
    }

    /// Asks the session's worker to stop, and tracks it until it has ended.
    fn retire(&mut self, id: SessionId) {
        if let Some(live) = self.live.remove(&id) {
            // A late Stop can fail against the closed peer and abandon otherwise clean reports.
            let exited = self
                .evidence
                .get(&(id, live.generation))
                .is_some_and(|e| e.exited && e.settled && !e.invalid && !e.cleanup_failed);
            if !exited {
                live.worker.stop();
            }
            self.retiring.push(Retiring {
                id,
                generation: live.generation,
                worker: live.worker,
                since: Instant::now(),
                abandoned: false,
            });
        }
    }

    /// Reaps workers that have ended, abandons ones that have not ended in time, waits for the
    /// agents of workers that ended, and starts the replacements that were waiting.
    fn advance(&mut self, now: Instant) {
        self.collect_finished(now);
        self.check_blocked(now);
        let ready: Vec<SessionId> = self
            .waiting
            .keys()
            .copied()
            .filter(|id| {
                !self.retiring.iter().any(|r| r.id == *id) && !self.blocked.contains_key(id)
            })
            .collect();
        for id in ready {
            if let Some((generation, spec)) = self.waiting.remove(&id) {
                self.start(id, generation, &spec);
            }
        }
    }

    /// A worker whose threads have all ended is joined. If its `hb` reported an agent that still
    /// exists, the agent is waited for as well, because the guardian stops it only after `hb` is
    /// gone and a stubborn agent can outlast `hb` by its whole grace period.
    fn collect_finished(&mut self, now: Instant) {
        // Freeze the set before draining: a worker finishing during the drain belongs to
        // the next pass, after its own final reports have been consumed.
        let finished: Vec<_> = self
            .retiring
            .iter()
            .filter(|r| r.worker.is_finished())
            .map(|r| (r.id, r.generation))
            .collect();
        if !finished.is_empty() {
            for _ in 0..INBOX {
                let Ok(msg) = self.inbox.try_recv() else {
                    break;
                };
                self.send(msg);
            }
        }
        let mut i = 0;
        while i < self.retiring.len() {
            if finished.contains(&(self.retiring[i].id, self.retiring[i].generation)) {
                let done = self.retiring.swap_remove(i);
                let reliable = done.worker.join();
                let evidence = self
                    .evidence
                    .remove(&(done.id, done.generation))
                    .unwrap_or_default();
                // Either source of abandonment can discard failures after an earlier Complete.
                if let Some(blocker) = evidence.after_delivery(reliable && !done.abandoned, now) {
                    self.blocked.insert(done.id, blocker);
                }
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
    }

    /// A start still waiting behind the old run is dropped when the owner stops it, and its row says
    /// so: nothing else would ever move a row that never got a worker.
    fn cancel_waiting(&mut self, id: SessionId, generation: Generation) {
        if self.waiting.get(&id).is_some_and(|(g, _)| *g == generation) {
            self.waiting.remove(&id);
            let effects = self.app.update(Msg::SpawnFailed {
                id,
                generation,
                reason: "stopped before it started".to_owned(),
            });
            if !effects.is_empty() {
                let _ = self.run(effects);
            }
        }
    }

    /// Refusing a launch does not prove the old agent gone. Keep its exclusion across retries.
    fn check_blocked(&mut self, now: Instant) {
        self.blocked.retain(
            |_, blocker| !matches!(*blocker, Blocker::Agent { pid, .. } if !process_exists(pid)),
        );
        let refused: Vec<_> = self
            .blocked
            .iter()
            .filter(|(_, blocker)| blocker.expired(now))
            .map(|(id, _)| *id)
            .collect();
        for id in refused {
            self.refuse_replacement(id);
        }
    }

    /// The old generation did not end, so the new one is not started: two would overlap.
    fn refuse_replacement(&mut self, id: SessionId) {
        if let Some((generation, _)) = self.waiting.remove(&id) {
            let effects = self.app.update(Msg::SpawnFailed {
                id,
                generation,
                reason: self.blocked.get(&id).map_or_else(
                    || {
                        "the previous run did not end in time, so this one was not started"
                            .to_owned()
                    },
                    |blocker| blocker.reason(),
                ),
            });
            if !effects.is_empty() {
                let _ = self.run(effects);
            }
        }
    }

    /// Carries out effects; true when one of them was `Quit`.
    fn run(&mut self, effects: Vec<Effect>) -> bool {
        let mut quit = false;
        let mut notices: Vec<String> = Vec::new();
        for effect in effects {
            match effect {
                Effect::Spawn {
                    id,
                    generation,
                    spec,
                } => self.spawn(id, generation, &spec),
                Effect::Stop { id, generation } => {
                    self.cancel_waiting(id, generation);
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
                        // Closed means the session is already stopping, which the row shows.
                        if let Err(error) = live.worker.enqueue_input(bytes)
                            && matches!(error, InputError::Full { .. })
                        {
                            notices.push(error.to_string());
                        }
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
        // Input the agent did not take is told to the owner, last one wins: the alert line holds one.
        if let Some(text) = notices.pop() {
            let _ = self.app.update(Msg::Notice(text));
        }
        quit
    }

    /// Starts the session, and tells the app how it went. A failure becomes a message, so the
    /// app shows it; nothing here decides what a failure means.
    fn spawn(&mut self, id: SessionId, generation: Generation, spec: &LaunchSpec) {
        // A restart replaces the worker, but only once the old one has ended: its late messages
        // carry the old generation and the app drops them. Until then the newest start waits.
        self.retire(id);
        if self.retiring.iter().any(|r| r.id == id) || self.blocked.contains_key(&id) {
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
                self.evidence.insert((id, generation), Evidence::default());
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
mod evidence_tests {
    use super::*;
    use crate::session::supervised::{Cleanup, Event};

    fn complete() -> Event {
        Event::Exited {
            code: Some(0),
            signal: None,
            cleanup: Cleanup::Complete {},
        }
    }

    #[test]
    fn a_complete_prefix_cannot_clear_abandoned_delivery() {
        let mut evidence = Evidence::default();
        evidence.observe(1, &Event::Starting {});
        evidence.observe(2, &complete());
        assert!(evidence.after_delivery(true, Instant::now()).is_none());
        assert!(matches!(
            evidence.after_delivery(false, Instant::now()),
            Some(Blocker::Unknown)
        ));
    }

    #[test]
    fn contradictions_and_sequence_errors_cannot_authorize_restart() {
        for stream in [
            vec![(1, Event::Starting {}), (3, complete())],
            vec![(1, Event::Starting {}), (1, complete())],
            vec![
                (1, Event::Starting {}),
                (2, Event::Running { agent_pid: 0 }),
                (3, complete()),
            ],
            vec![
                (1, Event::Starting {}),
                (2, Event::ApprovalRequired { root: "/p".into() }),
                (3, Event::Running { agent_pid: 42 }),
                (4, complete()),
            ],
            vec![
                (1, Event::Starting {}),
                (2, complete()),
                (3, Event::Running { agent_pid: 42 }),
            ],
            vec![
                (1, Event::Starting {}),
                (
                    2,
                    Event::Exited {
                        code: None,
                        signal: None,
                        cleanup: Cleanup::Failed {
                            what: "unknown".into(),
                        },
                    },
                ),
                (3, complete()),
            ],
        ] {
            let mut evidence = Evidence::default();
            for (seq, event) in stream {
                evidence.observe(seq, &event);
            }
            assert!(
                matches!(evidence.blocker(Instant::now()), Some(Blocker::Unknown)),
                "{evidence:?}"
            );
        }
    }

    #[test]
    fn failed_cleanup_is_sticky_even_when_the_agent_pid_is_absent() {
        let mut evidence = Evidence::default();
        evidence.observe(1, &Event::Starting {});
        evidence.observe(
            2,
            &Event::Running {
                agent_pid: i32::MAX as u32,
            },
        );
        evidence.observe(
            3,
            &Event::Exited {
                code: Some(0),
                signal: None,
                cleanup: Cleanup::Failed {
                    what: "unconfirmed".into(),
                },
            },
        );
        assert!(matches!(
            evidence.blocker(Instant::now()),
            Some(Blocker::Unknown)
        ));
    }

    #[test]
    fn approval_stopping_exit_is_valid_without_running_an_agent() {
        let mut evidence = Evidence::default();
        evidence.observe(1, &Event::Starting {});
        evidence.observe(2, &Event::ApprovalRequired { root: "/p".into() });
        evidence.observe(3, &Event::Stopping {});
        evidence.observe(
            4,
            &Event::Exited {
                code: None,
                signal: None,
                cleanup: Cleanup::Complete {},
            },
        );
        assert!(evidence.blocker(Instant::now()).is_none());
    }

    #[test]
    fn reader_failure_invalidates_an_earlier_complete_report_for_a_retired_generation() {
        let mut runtime = Runtime::new(Paths {
            hb: "/missing".into(),
            me: "/missing".into(),
            env: vec![],
        });
        runtime
            .evidence
            .insert((SessionId(1), 1), Evidence::default());
        runtime.send(Msg::Channel {
            id: SessionId(1),
            generation: 1,
            seq: 1,
            event: Event::Starting {},
        });
        runtime.send(Msg::Channel {
            id: SessionId(1),
            generation: 1,
            seq: 2,
            event: complete(),
        });
        runtime.send(Msg::SessionLost {
            id: SessionId(1),
            generation: 1,
            reason: "malformed suffix".into(),
        });
        assert!(matches!(
            runtime.evidence[&(SessionId(1), 1)].blocker(Instant::now()),
            Some(Blocker::Unknown)
        ));
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
    fn retiring_a_cleanly_exited_generation_does_not_send_stop_to_its_closed_channel() {
        use crate::session::supervised::{
            Cleanup, Frame, HelloAck, decode_hello, encode_line, read_line,
        };
        use crate::supervise::{launch, session};
        use claims::assert_ok;
        use std::io::{BufReader, Write};
        use std::os::unix::net::UnixStream;
        use std::process::{Command, Stdio};

        let mut runtime = Runtime::new(paths());
        runtime.app.update(Msg::Launch(spec()));
        let id = SessionId(1);
        let (channel, mut peer) = assert_ok!(UnixStream::pair());
        assert_ok!(peer.set_read_timeout(Some(Duration::from_secs(5))));
        let mut child = assert_ok!(
            Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
        );
        let input = assert_some!(child.stdin.take());
        let worker = assert_ok!(session::spawn(
            id,
            1,
            launch::Started {
                child,
                channel,
                terminal: assert_ok!(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open("/dev/null")
                ),
            },
            Shared::new(2, 2),
            runtime.outbox.clone()
        ));
        runtime.evidence.insert((id, 1), Evidence::default());
        runtime.live.insert(
            id,
            Live {
                generation: 1,
                worker,
            },
        );
        let hello = assert_ok!(decode_hello(&assert_some!(assert_ok!(read_line(
            &mut BufReader::new(assert_ok!(peer.try_clone()))
        )))));
        assert_ok!(peer.write_all(&assert_ok!(encode_line(&HelloAck {
            v: hello.v,
            launch: hello.launch,
            generation: hello.generation,
            pid: 1,
        }))));
        for (seq, event) in [
            (1, Event::Starting {}),
            (
                2,
                Event::Exited {
                    code: Some(0),
                    signal: None,
                    cleanup: Cleanup::Complete {},
                },
            ),
        ] {
            assert_ok!(peer.write_all(&assert_ok!(encode_line(&Frame { seq, event }))));
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        while !runtime.evidence.get(&(id, 1)).is_some_and(|e| e.exited) {
            assert!(Instant::now() < deadline, "completion never arrived");
            runtime.step();
            std::thread::sleep(Duration::from_millis(5));
        }
        drop(peer);
        runtime.retire(id);
        // Stop refuses input synchronously; keeping cat alive prevents reaper cancellation.
        assert_ok!(runtime.retiring[0].worker.enqueue_input(vec![1]));
        drop(input);
        assert!(runtime.shut_down(Duration::from_secs(5)));
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

    #[test]
    fn debug_shows_counts_and_never_the_environment() {
        let mut runtime = Runtime::new(Paths {
            hb: PathBuf::from("/nonexistent/hb"),
            me: PathBuf::from("/nonexistent/hb-supervise"),
            env: vec![("SECRET_TOKEN".into(), "hunter2".into())],
        });
        runtime.send(Msg::Launch(spec()));
        let text = format!("{runtime:?}");
        assert!(text.contains("sessions: 1"), "{text}");
        assert!(
            !text.contains("hunter2") && !text.contains("SECRET_TOKEN"),
            "{text}"
        );
    }

    // ========================================================================
    // A replacement waits for the old agent, not only for the old hb
    // ========================================================================

    /// A runtime with a session waiting to be restarted and a lingering agent, as is left when
    /// `hb` has been reaped but its agent has not yet been stopped by the guardian.
    fn waiting_behind(agent: u32) -> Runtime {
        let mut runtime = Runtime::new(paths());
        runtime.send(Msg::Launch(spec()));
        let id = first(&runtime).id;
        runtime.blocked.insert(
            id,
            Blocker::Agent {
                pid: agent,
                since: Instant::now(),
            },
        );
        // The generation the session is on, as the app's restart would have given it.
        let generation = first(&runtime).generation;
        runtime.waiting.insert(id, (generation, spec()));
        runtime
    }

    #[test]
    fn a_replacement_waits_while_the_old_agent_is_alive_and_starts_when_it_is_gone() {
        use claims::assert_ok;
        let mut sleeper = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let mut runtime = waiting_behind(sleeper.id());
        let id = first(&runtime).id;
        runtime.advance(Instant::now());
        assert!(
            runtime.waiting.contains_key(&id),
            "started beside a live agent"
        );
        assert!(runtime.is_retiring());
        // The agent ends (and is reaped, so its pid is really gone).
        assert_ok!(sleeper.kill());
        assert_ok!(sleeper.wait());
        runtime.advance(Instant::now());
        assert!(
            !runtime.waiting.contains_key(&id),
            "never started after the agent ended"
        );
        assert!(!runtime.is_retiring());
    }

    #[test]
    fn a_replacement_is_refused_not_started_when_the_old_agent_will_not_go() {
        use claims::assert_ok;
        let mut sleeper = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let mut runtime = waiting_behind(sleeper.id());
        let id = first(&runtime).id;
        // Past the limit: the start is refused and the row says why; no second agent.
        runtime.advance(Instant::now() + AGENT_LIMIT + Duration::from_secs(1));
        assert!(!runtime.waiting.contains_key(&id));
        let session = first(&runtime);
        assert_eq!(session.phase, Phase::Failed);
        assert!(
            session
                .failure
                .as_deref()
                .is_some_and(|f| f.contains("still running")),
            "{:?}",
            session.failure
        );
        assert_ok!(sleeper.kill());
        assert_ok!(sleeper.wait());
    }

    #[test]
    fn a_refused_restart_does_not_free_the_next_one_while_the_old_agent_still_runs() {
        use claims::assert_ok;
        let mut sleeper = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let mut runtime = waiting_behind(sleeper.id());
        let id = first(&runtime).id;
        runtime.advance(Instant::now() + AGENT_LIMIT + Duration::from_secs(1));
        assert_eq!(first(&runtime).phase, Phase::Failed);
        // The owner tries again at once: the old agent is still there, so the answer is the same.
        let generation = first(&runtime).generation + 1;
        runtime.spawn(id, generation, &spec());
        assert!(
            runtime.waiting.contains_key(&id) || first(&runtime).phase == Phase::Failed,
            "started beside a live agent: {:?}",
            first(&runtime).phase
        );
        assert!(
            runtime.blocked.contains_key(&id),
            "the exclusion was forgotten"
        );
        assert!(runtime.live.is_empty(), "a worker was started");
        assert_ok!(sleeper.kill());
        assert_ok!(sleeper.wait());
    }

    #[test]
    fn an_unknown_agent_blocks_every_start_and_says_so() {
        let mut runtime = Runtime::new(paths());
        runtime.send(Msg::Launch(spec()));
        let id = first(&runtime).id;
        runtime.blocked.insert(id, Blocker::Unknown);
        let generation = first(&runtime).generation;
        runtime.waiting.insert(id, (generation, spec()));
        runtime.advance(Instant::now());
        assert!(runtime.live.is_empty());
        assert!(
            runtime.blocked.contains_key(&id),
            "an unknown agent was cleared by waiting"
        );
        assert!(
            first(&runtime)
                .failure
                .as_deref()
                .is_some_and(|f| f.contains("could not be confirmed")),
            "{:?}",
            first(&runtime).failure
        );
    }

    #[test]
    fn stopping_a_start_that_is_waiting_cancels_it() {
        use claims::assert_ok;
        let mut sleeper = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let mut runtime = waiting_behind(sleeper.id());
        let id = first(&runtime).id;
        let generation = first(&runtime).generation;
        runtime.run(vec![Effect::Stop { id, generation }]);
        assert!(
            !runtime.waiting.contains_key(&id),
            "the queued start survived Stop"
        );
        assert_eq!(first(&runtime).phase, Phase::Failed);
        assert_ok!(sleeper.kill());
        assert_ok!(sleeper.wait());
        runtime.advance(Instant::now());
        assert!(
            runtime.live.is_empty(),
            "a stopped start ran after the old agent ended"
        );
    }

    #[test]
    fn a_stop_for_an_older_generation_does_not_cancel_the_newer_start() {
        use claims::assert_ok;
        let mut sleeper = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let mut runtime = waiting_behind(sleeper.id());
        let id = first(&runtime).id;
        let generation = first(&runtime).generation;
        runtime.run(vec![Effect::Stop {
            id,
            generation: generation - 1,
        }]);
        assert!(runtime.waiting.contains_key(&id));
        assert_ok!(sleeper.kill());
        assert_ok!(sleeper.wait());
    }

    #[test]
    fn shutting_down_is_not_clean_while_an_agent_cannot_be_confirmed_gone() {
        use claims::assert_ok;
        let mut sleeper = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let mut runtime = waiting_behind(sleeper.id());
        assert!(
            !runtime.shut_down(Duration::from_millis(100)),
            "reported clean beside a live agent"
        );
        assert_ok!(sleeper.kill());
        assert_ok!(sleeper.wait());
        let mut gone = waiting_behind(0);
        gone.blocked.clear();
        assert!(gone.shut_down(Duration::from_millis(100)));
    }

    #[test]
    fn shutting_down_is_not_clean_when_whether_the_agent_ended_is_unknown() {
        let mut runtime = Runtime::new(paths());
        runtime.send(Msg::Launch(spec()));
        let id = first(&runtime).id;
        runtime.blocked.insert(id, Blocker::Unknown);
        assert!(!runtime.shut_down(Duration::from_millis(100)));
    }

    #[test]
    fn pids_that_mean_something_else_are_not_evidence() {
        assert!(
            !usable_pid(0),
            "0 is the caller's own process group to kill()"
        );
        assert!(!usable_pid(1));
        assert!(!usable_pid(u32::MAX));
        assert!(usable_pid(4242));
    }
}
