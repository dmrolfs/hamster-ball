// ABOUTME: The supervisor's state and its pure update function: sessions, generations, modes, alerts and per-session bounded event rings.
// ABOUTME: update(&mut App, Msg) -> Vec<Effect> does no I/O, so every transition is a plain unit test; workers and the view live elsewhere.
//! Supervisor state (epic hb-b6q).
//!
//! [`App`] owns everything the screen shows. Workers send [`Msg`]s; [`App::update`] changes the
//! state and returns the [`Effect`]s the caller must carry out (start a process, stop one, write
//! input). Nothing here touches a terminal, a process or a file.
//!
//! Every session has a `generation`. A restart creates a new one, and a message carrying an old
//! generation is dropped, so the exit of the process that was just replaced cannot mark the new
//! one as exited.

use std::collections::VecDeque;
use std::path::PathBuf;

use snafu::Snafu;
use strum::{Display, IntoStaticStr};

use crate::session::supervised::{Cleanup, Event};

/// Most sessions at once.
pub const MAX_SESSIONS: usize = 8;
/// The most alerts kept; the screen shows the newest.
pub const MAX_ALERTS: usize = 64;
/// Most denial lines kept per session.
pub const DENIAL_RING: usize = 1_000;
/// Most proxy events kept per session.
pub const PROXY_RING: usize = 1_000;

/// One session's number in this run of the supervisor. It does not change across restarts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(pub u32);

/// Which start of a session this is; a restart raises it.
pub type Generation = u32;

/// What the owner asked to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// The project directory `hb` runs in.
    pub project: PathBuf,
    /// The agent command and its arguments, after `--`.
    pub command: Vec<String>,
}

/// Where a session is in its life. The words are what the row shows.
#[derive(Debug, Clone, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Phase {
    /// `hb` was started and has not reported yet.
    Starting,
    /// The config is not approved; nothing ran.
    Approve,
    /// The agent is running under the sandbox.
    Running,
    /// A stop was asked for and has not finished.
    Stopping,
    /// `hb` ended; the exit is in [`Session::exit`].
    Exited,
    /// `hb` could not be started, or ended without a final report.
    Failed,
    /// The channel broke while the session was live; its true state is not known.
    Lost,
}

impl Phase {
    /// Whether the session still has a process. `Approve` does not: `hb` has already exited 78
    /// and nothing runs until the owner reviews the config and restarts the session.
    #[must_use]
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Starting | Self::Running | Self::Stopping)
    }
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// The agent's exit code, when it exited.
    pub code: Option<i32>,
    /// The signal that ended it, when one did.
    pub signal: Option<i32>,
    /// What cleanup left behind, if anything.
    pub cleanup: Cleanup,
}

/// One proxy connection, as shown in the Proxy tab.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyRow {
    /// `host:port`, or `-` when the request named none.
    pub target: String,
    /// Served or refused, with the refusal code.
    pub verdict: String,
    /// Bytes sent and received.
    pub up: u64,
    /// See `up`.
    pub down: u64,
}

/// A bounded list that keeps the newest entries and counts the ones it let go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ring<T> {
    items: VecDeque<T>,
    capacity: usize,
    /// How many entries were pushed out by newer ones.
    pub evicted: u64,
}

impl<T> Ring<T> {
    /// An empty ring holding at most `capacity` entries.
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        Self {
            items: VecDeque::new(),
            capacity,
            evicted: 0,
        }
    }

    /// Adds an entry, pushing out the oldest when full.
    pub fn push(&mut self, item: T) {
        if self.items.len() >= self.capacity {
            self.items.pop_front();
            self.evicted += 1;
        }
        self.items.push_back(item);
    }

    /// The entries, oldest first.
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    /// How many are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether none are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// One supervised session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// Its number.
    pub id: SessionId,
    /// Which start this is.
    pub generation: Generation,
    /// What it was asked to run.
    pub spec: LaunchSpec,
    /// Where it is in its life.
    pub phase: Phase,
    /// How it ended, once it has.
    pub exit: Option<Exit>,
    /// The agent's process id, once running.
    pub agent_pid: Option<u32>,
    /// Denials, newest last.
    pub denials: Ring<String>,
    /// Proxy connections, newest last.
    pub proxy: Ring<ProxyRow>,
    /// Denials seen since the owner last looked at this session.
    pub unread_denials: u64,
    /// Telemetry `hb` dropped under load, as it reported.
    pub dropped_denials: u64,
    /// See `dropped_denials`.
    pub dropped_proxy: u64,
    /// Warnings `hb` reported, newest last.
    pub warnings: Ring<String>,
    /// The failure shown for [`Phase::Failed`].
    pub failure: Option<String>,
    /// The next event number expected from `hb`.
    expected_seq: u64,
}

impl Session {
    fn new(id: SessionId, generation: Generation, spec: LaunchSpec) -> Self {
        Self {
            id,
            generation,
            spec,
            phase: Phase::Starting,
            exit: None,
            agent_pid: None,
            denials: Ring::new(DENIAL_RING),
            proxy: Ring::new(PROXY_RING),
            unread_denials: 0,
            dropped_denials: 0,
            dropped_proxy: 0,
            warnings: Ring::new(100),
            failure: None,
            expected_seq: 1,
        }
    }
}

/// Where keys go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Mode {
    /// Watching; keys are the supervisor's.
    Overview,
    /// Typing to one agent; every key but `Ctrl-g` goes to it.
    Interact,
    /// The help screen.
    Help,
    /// A yes or no question about a destructive action.
    Confirm,
    /// The launch form.
    Launch,
}

/// Which lower tab is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Tab {
    /// Sandbox and proxy denials.
    Denials,
    /// Every proxy connection.
    Proxy,
}

/// Which panel has the owner's attention. A wide terminal shows them all, and the last two pick
/// the lower tab; a narrow one shows just this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Panel {
    /// The list of sessions.
    Sessions,
    /// The selected session's terminal.
    Terminal,
    /// The denials of the selected session.
    Denials,
    /// The proxy connections of the selected session.
    Proxy,
}

impl Panel {
    const ORDER: [Self; 4] = [Self::Sessions, Self::Terminal, Self::Denials, Self::Proxy];

    fn shifted(self, forward: bool) -> Self {
        let at = Self::ORDER.iter().position(|p| *p == self).unwrap_or(0);
        let len = Self::ORDER.len();
        Self::ORDER[if forward {
            (at + 1) % len
        } else {
            (at + len - 1) % len
        }]
    }
}

/// Which launch field takes typing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Field {
    /// The project directory.
    Project,
    /// The agent command.
    Command,
}

/// One edit of the launch form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormEdit {
    /// Type a character into the current field.
    Char(char),
    /// Delete the last character of the current field.
    Backspace,
    /// Move to the other field.
    SwitchField,
    /// Pick a recent project: `true` for an older one, `false` for a newer one.
    Recent(bool),
}

/// The launch form: two single-line fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchForm {
    /// The project directory, as typed.
    pub project: String,
    /// The agent command, as typed; split on whitespace when started.
    pub command: String,
    /// Which field takes typing.
    pub field: Field,
    /// Which entry of [`App::recent_projects`] the fields were last filled from.
    pub recent: Option<usize>,
}

impl LaunchForm {
    fn empty() -> Self {
        Self {
            project: String::new(),
            command: String::new(),
            field: Field::Project,
            recent: None,
        }
    }
}

/// A destructive action waiting for a yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pending {
    /// Stop this session.
    Stop(SessionId),
    /// Stop this session and start it again as a new generation.
    Restart(SessionId),
    /// Stop everything and leave.
    Quit,
}

/// Why a request was refused. The text is shown to the owner.
#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
#[non_exhaustive]
pub enum Refusal {
    /// All [`MAX_SESSIONS`] slots are in use.
    #[snafu(display("{MAX_SESSIONS} sessions are already running; stop one first"))]
    TooManySessions,
    /// There is no command to run.
    #[snafu(display("the agent command is empty"))]
    EmptyCommand,
    /// The terminal is too small to show the agent, so keys must not be sent to it unseen.
    #[snafu(display("the terminal is too small to interact; make it larger"))]
    TerminalTooSmall,
    /// The project directory field is empty.
    #[snafu(display("the project directory is empty"))]
    EmptyProject,
    /// The action needs a live session and the selected one has ended.
    #[snafu(display("that session is not running"))]
    NotRunning,
    /// There is no such session.
    #[snafu(display("there is no such session"))]
    NoSuchSession,
    /// The session is not waiting for approval.
    #[snafu(display("that session is not waiting for approval"))]
    NotWaitingForApproval,
}

/// A line in the alert area.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    /// The session it is about.
    pub session: SessionId,
    /// The words shown.
    pub text: String,
}

/// What a worker or the keyboard tells the app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    /// The owner asked to launch a session.
    Launch(LaunchSpec),
    /// `hb` for this session and generation was started.
    Spawned {
        /// The session.
        id: SessionId,
        /// The generation that was started.
        generation: Generation,
    },
    /// `hb` could not be started.
    SpawnFailed {
        /// The session.
        id: SessionId,
        /// The generation that failed.
        generation: Generation,
        /// Why, in one line.
        reason: String,
    },
    /// An event arrived on the session's channel, with its number.
    Channel {
        /// The session.
        id: SessionId,
        /// The generation it came from.
        generation: Generation,
        /// Its number in the session.
        seq: u64,
        /// What it said.
        event: Event,
    },
    /// The channel ended: end of input, or a frame that could not be read.
    ChannelLost {
        /// The session.
        id: SessionId,
        /// The generation.
        generation: Generation,
    },
    /// The session's process could not be observed to end, or its reports may be incomplete: it
    /// was killed, and nothing is known about how it ended.
    SessionLost {
        /// The session.
        id: SessionId,
        /// The generation.
        generation: Generation,
        /// Why, with the causes.
        reason: String,
    },
    /// The `hb` process was reaped.
    ProcessExited {
        /// The session.
        id: SessionId,
        /// The generation.
        generation: Generation,
        /// Its status code, when it exited.
        code: Option<i32>,
        /// The signal that ended it, when one did.
        signal: Option<i32>,
    },
    /// The owner moved the selection by this many rows.
    Select(i32),
    /// The owner jumped to this session by position, from 1.
    Jump(usize),
    /// The owner asked for a mode.
    EnterInteract,
    /// Back to Overview.
    LeaveInteract,
    /// The owner deliberately pressed a key after Interact ended by itself: keys are the
    /// supervisor's again.
    ReleaseKeys,
    /// Bytes for one session's agent, from the keyboard or a paste.
    Input {
        /// The session.
        id: SessionId,
        /// The generation the owner was looking at when typing.
        generation: Generation,
        /// What to write to the agent's terminal.
        bytes: Vec<u8>,
    },
    /// The owner tried to interact where the terminal pane is not shown.
    TooSmall,
    /// Switch the lower tab.
    NextTab,
    /// Move to the next (`true`) or previous panel; for terminals too small to show them all.
    NextPanel(bool),
    /// Open the launch form; `cwd` is where the supervisor was started, the default project.
    OpenLaunch {
        /// The default project directory.
        cwd: PathBuf,
    },
    /// The owner edited the launch form.
    Form(FormEdit),
    /// The owner pressed Enter in the launch form.
    SubmitLaunch,
    /// The owner left the launch form.
    CancelLaunch,
    /// Open or close help.
    ToggleHelp,
    /// The owner asked to stop the selected session.
    AskStop,
    /// The owner asked to restart the selected session.
    AskRestart,
    /// The owner asked to quit.
    AskQuit,
    /// The owner answered a confirmation.
    Answer(bool),
    /// The owner asked to review approval for the selected session.
    ReviewApproval,
    /// Something the owner should be told that is not about one session: a line in the alert
    /// area until the next owner action.
    Notice(String),
    /// `hb approve` ended for this session and generation.
    ApprovalFinished {
        /// The session.
        id: SessionId,
        /// The generation that asked for the review.
        generation: Generation,
        /// How it went.
        outcome: ApprovalOutcome,
    },
}

/// How a review with `hb approve` ended, as far as the supervisor can tell. It never reads
/// the answer: it sees only whether the command succeeded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// `hb approve` exited 0: the config is approved now (or already was).
    Approved,
    /// `hb approve` ended without approving; the row stays on Approve.
    NotApproved,
    /// `hb approve` could not be run; the reason, in one line.
    Failed(String),
}

/// What the caller must do after an update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Start `hb` for this session and generation.
    Spawn {
        /// The session.
        id: SessionId,
        /// The generation to start.
        generation: Generation,
        /// What to run.
        spec: LaunchSpec,
    },
    /// Send the `Stop` command to this session's `hb`.
    Stop {
        /// The session.
        id: SessionId,
        /// The generation to stop.
        generation: Generation,
    },
    /// Write these bytes to the agent's terminal.
    Write {
        /// The session.
        id: SessionId,
        /// The generation they are for.
        generation: Generation,
        /// What to write.
        bytes: Vec<u8>,
    },
    /// Give the real terminal back and run `hb approve` in this project.
    SuspendForApproval {
        /// The session.
        id: SessionId,
        /// The generation that asked, so the result is applied to it and no other.
        generation: Generation,
        /// Where to run it.
        project: PathBuf,
    },
    /// Stop everything and leave.
    Quit,
}

/// Everything the screen shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct App {
    sessions: Vec<Session>,
    next_id: u32,
    /// The selected row, as a position in [`App::sessions`].
    selected: usize,
    /// Where keys go.
    pub mode: Mode,
    /// The lower tab.
    pub tab: Tab,
    /// The panel shown when only one fits.
    pub panel: Panel,
    /// The launch form, in [`Mode::Launch`].
    pub form: LaunchForm,
    /// The action waiting for a yes, in [`Mode::Confirm`].
    pub pending: Option<Pending>,
    /// What the owner was last told about a refused request.
    pub notice: Option<String>,
    /// Set when Interact ended by itself because the agent stopped, while the owner was probably
    /// still typing to it. Until they release it, no key is a supervisor command: `r`, `q` and
    /// `n` followed by text would otherwise restart, quit or launch from keys meant for the agent
    /// (hb-807 review B, MEDIUM 1).
    keys_held: bool,
    alerts: Vec<Alert>,
    quitting: bool,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    /// An app with no sessions.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: Vec::new(),
            next_id: 1,
            selected: 0,
            mode: Mode::Overview,
            tab: Tab::Denials,
            panel: Panel::Sessions,
            form: LaunchForm::empty(),
            pending: None,
            notice: None,
            keys_held: false,
            alerts: Vec::new(),
            quitting: false,
        }
    }

    /// Whether keys are being held back after Interact ended by itself.
    #[must_use]
    pub fn keys_held(&self) -> bool {
        self.keys_held
    }

    /// The sessions, in the order they were launched.
    #[must_use]
    pub fn sessions(&self) -> &[Session] {
        &self.sessions
    }

    /// The selected session, if there is one.
    #[must_use]
    pub fn selected(&self) -> Option<&Session> {
        self.sessions.get(self.selected)
    }

    /// The selected position.
    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// The alerts, oldest first.
    #[must_use]
    pub fn alerts(&self) -> &[Alert] {
        &self.alerts
    }

    /// Whether a quit was confirmed and the sessions are being stopped.
    #[must_use]
    pub fn is_quitting(&self) -> bool {
        self.quitting
    }

    /// How many sessions still have a process.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.sessions.iter().filter(|s| s.phase.is_live()).count()
    }

    fn find(&mut self, id: SessionId) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|s| s.id == id)
    }

    /// The session `id` if `generation` is its current one: a message from an older start is
    /// not about the session as it is now.
    fn current(&mut self, id: SessionId, generation: Generation) -> Option<&mut Session> {
        self.find(id).filter(|s| s.generation == generation)
    }

    fn alert(&mut self, session: SessionId, text: impl Into<String>) {
        self.alerts.push(Alert {
            session,
            text: text.into(),
        });
        // Only the newest are shown; a long session must not collect them without end.
        if self.alerts.len() > MAX_ALERTS {
            self.alerts.remove(0);
        }
    }

    fn refuse(&mut self, refusal: &Refusal) {
        self.notice = Some(refusal.to_string());
    }

    /// Applies one message and returns what the caller must now do.
    pub fn update(&mut self, msg: Msg) -> Vec<Effect> {
        // Retired workers still report to Runtime, but cannot dismiss this generation's UI notice.
        if let Msg::Spawned { id, generation }
        | Msg::SpawnFailed { id, generation, .. }
        | Msg::Channel { id, generation, .. }
        | Msg::ChannelLost { id, generation }
        | Msg::SessionLost { id, generation, .. }
        | Msg::ProcessExited { id, generation, .. }
        | Msg::Input { id, generation, .. }
        | Msg::ApprovalFinished { id, generation, .. } = &msg
            && self.current(*id, *generation).is_none()
        {
            return Vec::new();
        }
        if !matches!(
            msg,
            Msg::Spawned { .. }
                | Msg::SpawnFailed { .. }
                | Msg::Channel { .. }
                | Msg::ChannelLost { .. }
                | Msg::SessionLost { .. }
                | Msg::ProcessExited { .. }
        ) {
            self.notice = None;
        }
        let effects = self.apply_msg(msg);
        // Keys must never keep going to an agent that is no longer running; leave Interact so the
        // status bar says so.
        if self.mode == Mode::Interact && self.selected().is_none_or(|s| s.phase != Phase::Running)
        {
            self.mode = Mode::Overview;
            self.keys_held = true;
            self.notice = Some(
                "the session ended while you were typing: keys are held, press Esc or Ctrl-g to continue"
                    .to_owned(),
            );
        }
        effects
    }

    fn apply_msg(&mut self, msg: Msg) -> Vec<Effect> {
        match msg {
            Msg::Launch(spec) => self.launch(spec),
            Msg::Spawned { id, generation } => {
                // Nothing to change: the first report from `hb` moves the phase. Kept as a
                // message so a stale one is visibly ignored.
                let _ = self.current(id, generation);
                Vec::new()
            }
            Msg::SpawnFailed {
                id,
                generation,
                reason,
            } => self.spawn_failed(id, generation, reason),
            Msg::Channel {
                id,
                generation,
                seq,
                event,
            } => self.channel(id, generation, seq, event),
            Msg::ChannelLost { id, generation } => self.channel_lost(id, generation),
            Msg::SessionLost {
                id,
                generation,
                reason,
            } => self.session_lost(id, generation, &reason),
            Msg::ProcessExited {
                id,
                generation,
                code,
                signal,
            } => self.process_exited(id, generation, code, signal),
            Msg::Select(delta) => self.select(delta),
            Msg::Jump(position) => self.jump(position),
            Msg::EnterInteract => self.enter_interact(),
            Msg::LeaveInteract => {
                if self.mode == Mode::Interact {
                    self.mode = Mode::Overview;
                }
                Vec::new()
            }
            Msg::ReleaseKeys => {
                self.keys_held = false;
                Vec::new()
            }
            Msg::NextTab => {
                self.tab = match self.tab {
                    Tab::Denials => Tab::Proxy,
                    Tab::Proxy => Tab::Denials,
                };
                Vec::new()
            }
            Msg::Input {
                id,
                generation,
                bytes,
            } => match self.current(id, generation) {
                // Bytes for a process that is no longer there, or an older start, are dropped.
                Some(session) if session.phase == Phase::Running => vec![Effect::Write {
                    id,
                    generation,
                    bytes,
                }],
                _ => Vec::new(),
            },
            Msg::TooSmall => {
                self.refuse(&Refusal::TerminalTooSmall);
                Vec::new()
            }
            Msg::NextPanel(forward) => self.next_panel(forward),
            Msg::OpenLaunch { cwd } => self.open_launch(&cwd),
            Msg::Form(edit) => self.edit_form(edit),
            Msg::SubmitLaunch => self.submit_launch(),
            Msg::CancelLaunch => {
                if self.mode == Mode::Launch {
                    self.mode = Mode::Overview;
                }
                Vec::new()
            }
            Msg::ToggleHelp => {
                self.mode = match self.mode {
                    Mode::Help => Mode::Overview,
                    Mode::Overview => Mode::Help,
                    other => other,
                };
                Vec::new()
            }
            Msg::AskStop => self.ask(Pending::Stop),
            Msg::AskRestart => self.ask(Pending::Restart),
            Msg::AskQuit => self.ask_quit(),
            Msg::Answer(yes) => self.answer(yes),
            Msg::ReviewApproval => self.review_approval(),
            Msg::Notice(text) => {
                self.notice = Some(text);
                Vec::new()
            }
            Msg::ApprovalFinished {
                id,
                generation,
                outcome,
            } => self.approval_finished(id, generation, &outcome),
        }
    }
}

impl App {
    fn launch(&mut self, spec: LaunchSpec) -> Vec<Effect> {
        if spec.command.is_empty() {
            self.refuse(&Refusal::EmptyCommand);
            return Vec::new();
        }
        if self.live_count() >= MAX_SESSIONS || self.sessions.len() >= MAX_SESSIONS * 4 {
            self.refuse(&Refusal::TooManySessions);
            return Vec::new();
        }
        let id = SessionId(self.next_id);
        self.next_id += 1;
        self.sessions.push(Session::new(id, 1, spec.clone()));
        self.selected = self.sessions.len() - 1;
        vec![Effect::Spawn {
            id,
            generation: 1,
            spec,
        }]
    }

    fn spawn_failed(
        &mut self,
        id: SessionId,
        generation: Generation,
        reason: String,
    ) -> Vec<Effect> {
        let Some(session) = self.current(id, generation) else {
            return Vec::new();
        };
        session.phase = Phase::Failed;
        session.failure = Some(reason.clone());
        self.alert(id, format!("could not start: {reason}"));
        Vec::new()
    }

    fn channel(
        &mut self,
        id: SessionId,
        generation: Generation,
        seq: u64,
        event: Event,
    ) -> Vec<Effect> {
        let Some(session) = self.current(id, generation) else {
            return Vec::new();
        };
        if !session.phase.is_live() {
            // `hb` sends nothing after Exited; whatever this is, it is not about a live session.
            return Vec::new();
        }
        if seq != session.expected_seq {
            // A gap or repeat means the channel cannot be trusted: say so and stop reading it.
            return self.break_session(id, "the channel skipped an event");
        }
        session.expected_seq += 1;
        self.apply(id, event)
    }

    /// Marks a live session Lost and asks it to stop, because what it reports is no longer known.
    fn break_session(&mut self, id: SessionId, why: &str) -> Vec<Effect> {
        let Some(session) = self.find(id) else {
            return Vec::new();
        };
        let generation = session.generation;
        session.phase = Phase::Lost;
        session.failure = Some(why.to_owned());
        self.alert(id, format!("lost contact: {why}"));
        vec![Effect::Stop { id, generation }]
    }

    fn apply(&mut self, id: SessionId, event: Event) -> Vec<Effect> {
        let selected_id = self.selected().map(|s| s.id);
        let Some(session) = self.find(id) else {
            return Vec::new();
        };
        match event {
            Event::Starting {} => {}
            Event::ApprovalRequired { .. } => {
                session.phase = Phase::Approve;
                self.alert(id, "needs approval");
            }
            Event::Running { agent_pid } => {
                session.phase = Phase::Running;
                session.agent_pid = Some(agent_pid);
            }
            Event::Denial { text } => {
                session.denials.push(text);
                if selected_id != Some(id) {
                    session.unread_denials += 1;
                }
            }
            Event::Proxy {
                host,
                port,
                decision,
                up,
                down,
            } => {
                let target = match (host, port) {
                    (Some(host), Some(port)) => format!("{host}:{port}"),
                    _ => "-".to_owned(),
                };
                let verdict = match decision {
                    crate::session::supervised::Verdict::Allowed {} => "allowed".to_owned(),
                    crate::session::supervised::Verdict::Refused { code, .. } => {
                        format!("refused {code}")
                    }
                };
                session.proxy.push(ProxyRow {
                    target,
                    verdict,
                    up,
                    down,
                });
            }
            Event::Dropped { denials, proxy } => {
                session.dropped_denials += denials;
                session.dropped_proxy += proxy;
            }
            Event::Warning { text } => session.warnings.push(text),
            Event::Stopping {} => {
                // `hb` reports Stopping on its way out after ApprovalRequired too; that session
                // has no process left to stop and stays on Approve.
                if session.phase != Phase::Approve {
                    session.phase = Phase::Stopping;
                }
            }
            Event::Exited {
                code,
                signal,
                cleanup,
            } => {
                let unclean = matches!(cleanup, Cleanup::Failed { .. });
                let approval = session.phase == Phase::Approve;
                session.exit = Some(Exit {
                    code,
                    signal,
                    cleanup,
                });
                // A session that asked for approval stays on that row: it did not run, and the
                // owner's next step is to review it, not to read an exit code.
                if !approval {
                    session.phase = Phase::Exited;
                }
                if unclean {
                    self.alert(id, "cleanup did not finish");
                } else if !approval && (code != Some(0)) && selected_id != Some(id) {
                    self.alert(id, "exited unexpectedly");
                }
            }
        }
        Vec::new()
    }

    fn channel_lost(&mut self, id: SessionId, generation: Generation) -> Vec<Effect> {
        let Some(session) = self.current(id, generation) else {
            return Vec::new();
        };
        // End of input after the final report is the normal close, not a loss; so is the close
        // after ApprovalRequired, where `hb` exits with nothing running.
        if matches!(
            session.phase,
            Phase::Exited | Phase::Failed | Phase::Lost | Phase::Approve
        ) || session.exit.is_some()
        {
            return Vec::new();
        }
        self.break_session(id, "the channel closed before the session reported its end")
    }

    /// The process was killed because it could not be observed. A session that had already
    /// reported its end keeps that report; any other becomes Failed, never Exited.
    fn session_lost(&mut self, id: SessionId, generation: Generation, reason: &str) -> Vec<Effect> {
        let Some(session) = self.current(id, generation) else {
            return Vec::new();
        };
        if session.exit.is_some() || session.phase == Phase::Approve {
            return Vec::new();
        }
        session.phase = Phase::Failed;
        session.failure = Some(reason.to_owned());
        self.alert(id, format!("lost: {reason}"));
        Vec::new()
    }

    fn process_exited(
        &mut self,
        id: SessionId,
        generation: Generation,
        code: Option<i32>,
        signal: Option<i32>,
    ) -> Vec<Effect> {
        let Some(session) = self.current(id, generation) else {
            return Vec::new();
        };
        if session.phase == Phase::Approve {
            // `hb` reported ApprovalRequired and exited 78: the row stays on Approve, which is
            // where the owner's next step is. Nothing ran, so there is no exit to report.
        } else if session.phase.is_live() {
            // The process is gone and never said how it ended.
            session.phase = Phase::Failed;
            session.failure = Some(match (code, signal) {
                (_, Some(signal)) => format!("hb was killed by signal {signal}"),
                (Some(code), None) => format!("hb ended with status {code} without a final report"),
                (None, None) => "hb ended without a final report".to_owned(),
            });
            self.alert(id, "ended without a final report");
        } else if session.phase == Phase::Lost {
            session.phase = Phase::Failed;
        }
        Vec::new()
    }
}

impl App {
    /// Moves the selection, clamped to the rows there are, and clears what it was waiting to show.
    fn select(&mut self, delta: i32) -> Vec<Effect> {
        if self.mode != Mode::Overview || self.sessions.is_empty() {
            return Vec::new();
        }
        let last = self.sessions.len() - 1;
        let moved = i64::try_from(self.selected).unwrap_or(0) + i64::from(delta);
        let target = usize::try_from(moved.clamp(0, i64::try_from(last).unwrap_or(0))).unwrap_or(0);
        self.focus(target);
        Vec::new()
    }

    fn jump(&mut self, position: usize) -> Vec<Effect> {
        if self.mode != Mode::Overview || position == 0 || position > self.sessions.len() {
            return Vec::new();
        }
        self.focus(position - 1);
        Vec::new()
    }

    /// Selects a row. Looking at a session reads its denials and clears its alerts, and the
    /// selection never moves on its own.
    fn focus(&mut self, index: usize) {
        self.selected = index;
        if let Some(session) = self.sessions.get_mut(index) {
            session.unread_denials = 0;
            let id = session.id;
            self.alerts.retain(|a| a.session != id);
        }
    }

    fn enter_interact(&mut self) -> Vec<Effect> {
        if self.mode != Mode::Overview {
            return Vec::new();
        }
        match self.selected() {
            Some(session) if session.phase == Phase::Running => {
                self.mode = Mode::Interact;
                // A terminal too narrow for every panel must show this one.
                self.panel = Panel::Terminal;
            }
            Some(_) => self.refuse(&Refusal::NotRunning),
            None => self.refuse(&Refusal::NoSuchSession),
        }
        Vec::new()
    }

    /// Opens a confirmation for the selected session, if it has a process to act on.
    fn ask(&mut self, action: fn(SessionId) -> Pending) -> Vec<Effect> {
        if self.mode != Mode::Overview {
            return Vec::new();
        }
        match self.selected() {
            Some(session) if session.phase.is_live() => {
                self.pending = Some(action(session.id));
                self.mode = Mode::Confirm;
            }
            Some(session) if matches!(action(session.id), Pending::Restart(_)) => {
                // A session that has ended is restarted without asking: there is nothing to stop.
                return self.restart(session.id);
            }
            Some(_) => self.refuse(&Refusal::NotRunning),
            None => self.refuse(&Refusal::NoSuchSession),
        }
        Vec::new()
    }

    fn ask_quit(&mut self) -> Vec<Effect> {
        if self.mode != Mode::Overview {
            return Vec::new();
        }
        if self.live_count() == 0 {
            self.quitting = true;
            return vec![Effect::Quit];
        }
        self.pending = Some(Pending::Quit);
        self.mode = Mode::Confirm;
        Vec::new()
    }

    fn answer(&mut self, yes: bool) -> Vec<Effect> {
        if self.mode != Mode::Confirm {
            return Vec::new();
        }
        self.mode = Mode::Overview;
        let Some(pending) = self.pending.take() else {
            return Vec::new();
        };
        if !yes {
            return Vec::new();
        }
        match pending {
            Pending::Stop(id) => self.stop(id),
            Pending::Restart(id) => self.restart(id),
            Pending::Quit => self.quit(),
        }
    }

    fn stop(&mut self, id: SessionId) -> Vec<Effect> {
        let Some(session) = self.find(id) else {
            return Vec::new();
        };
        if !session.phase.is_live() {
            return Vec::new();
        }
        let generation = session.generation;
        session.phase = Phase::Stopping;
        vec![Effect::Stop { id, generation }]
    }

    /// Starts the session again as a new generation. A live one is stopped first; its late
    /// messages carry the old generation and are dropped.
    fn restart(&mut self, id: SessionId) -> Vec<Effect> {
        if self.live_count() >= MAX_SESSIONS
            && self
                .sessions
                .iter()
                .any(|s| s.id == id && !s.phase.is_live())
        {
            self.refuse(&Refusal::TooManySessions);
            return Vec::new();
        }
        let Some(session) = self.find(id) else {
            return Vec::new();
        };
        let mut effects = Vec::new();
        if session.phase.is_live() {
            effects.push(Effect::Stop {
                id,
                generation: session.generation,
            });
        }
        let spec = session.spec.clone();
        let generation = session.generation + 1;
        *session = Session::new(id, generation, spec.clone());
        self.alerts.retain(|a| a.session != id);
        effects.push(Effect::Spawn {
            id,
            generation,
            spec,
        });
        effects
    }

    fn quit(&mut self) -> Vec<Effect> {
        self.quitting = true;
        let mut effects: Vec<Effect> = self
            .sessions
            .iter_mut()
            .filter(|s| s.phase.is_live())
            .map(|s| {
                s.phase = Phase::Stopping;
                Effect::Stop {
                    id: s.id,
                    generation: s.generation,
                }
            })
            .collect();
        effects.push(Effect::Quit);
        effects
    }

    /// Applies a review's result. Only the generation that asked, and only while it is still
    /// waiting on approval, may be started again: the owner may have restarted or moved on.
    fn approval_finished(
        &mut self,
        id: SessionId,
        generation: Generation,
        outcome: &ApprovalOutcome,
    ) -> Vec<Effect> {
        let waiting = self
            .sessions
            .iter()
            .any(|s| s.id == id && s.generation == generation && s.phase == Phase::Approve);
        if !waiting {
            return Vec::new();
        }
        match outcome {
            ApprovalOutcome::Approved => self.restart(id),
            ApprovalOutcome::NotApproved => {
                self.alert(id, "the config was not approved".to_owned());
                Vec::new()
            }
            ApprovalOutcome::Failed(reason) => {
                self.alert(id, format!("could not run hb approve: {reason}"));
                Vec::new()
            }
        }
    }

    fn review_approval(&mut self) -> Vec<Effect> {
        if self.mode != Mode::Overview {
            return Vec::new();
        }
        match self.selected() {
            Some(session) if session.phase == Phase::Approve => {
                vec![Effect::SuspendForApproval {
                    id: session.id,
                    generation: session.generation,
                    project: session.spec.project.clone(),
                }]
            }
            Some(_) => {
                self.refuse(&Refusal::NotWaitingForApproval);
                Vec::new()
            }
            None => {
                self.refuse(&Refusal::NoSuchSession);
                Vec::new()
            }
        }
    }
}

impl App {
    /// Moves to another panel. The lower tab follows, so a wide terminal shows what the owner
    /// last chose too.
    fn next_panel(&mut self, forward: bool) -> Vec<Effect> {
        if self.mode != Mode::Overview {
            return Vec::new();
        }
        self.panel = self.panel.shifted(forward);
        match self.panel {
            Panel::Denials => self.tab = Tab::Denials,
            Panel::Proxy => self.tab = Tab::Proxy,
            Panel::Sessions | Panel::Terminal => {}
        }
        Vec::new()
    }

    /// The projects sessions were started in, newest first, each once.
    #[must_use]
    pub fn recent_projects(&self) -> Vec<&PathBuf> {
        let mut seen: Vec<&PathBuf> = Vec::new();
        for session in self.sessions.iter().rev() {
            if !seen.contains(&&session.spec.project) {
                seen.push(&session.spec.project);
            }
        }
        seen
    }

    /// The command last used in `project`, joined with spaces.
    fn last_command(&self, project: &std::path::Path) -> String {
        self.sessions
            .iter()
            .rev()
            .find(|s| s.spec.project == project)
            .map(|s| s.spec.command.join(" "))
            .unwrap_or_default()
    }

    fn open_launch(&mut self, cwd: &std::path::Path) -> Vec<Effect> {
        if self.mode != Mode::Overview {
            return Vec::new();
        }
        self.form = LaunchForm {
            project: cwd.display().to_string(),
            command: self.last_command(cwd),
            field: Field::Command,
            recent: None,
        };
        self.mode = Mode::Launch;
        Vec::new()
    }

    fn edit_form(&mut self, edit: FormEdit) -> Vec<Effect> {
        if self.mode != Mode::Launch {
            return Vec::new();
        }
        match edit {
            FormEdit::SwitchField => {
                self.form.field = match self.form.field {
                    Field::Project => Field::Command,
                    Field::Command => Field::Project,
                };
            }
            FormEdit::Char(c) if !c.is_control() => self.field_mut().push(c),
            FormEdit::Char(_) => {}
            FormEdit::Backspace => {
                self.field_mut().pop();
            }
            FormEdit::Recent(older) => self.pick_recent(older),
        }
        Vec::new()
    }

    fn field_mut(&mut self) -> &mut String {
        match self.form.field {
            Field::Project => &mut self.form.project,
            Field::Command => &mut self.form.command,
        }
    }

    /// Fills both fields from a recent project: the first press picks the newest, then each
    /// moves one along, stopping at the ends.
    fn pick_recent(&mut self, older: bool) {
        let recent: Vec<PathBuf> = self.recent_projects().into_iter().cloned().collect();
        let Some(last) = recent.len().checked_sub(1) else {
            return;
        };
        let target = match (self.form.recent, older) {
            (None, _) => 0,
            (Some(at), true) => (at + 1).min(last),
            (Some(at), false) => at.saturating_sub(1),
        };
        self.form.recent = Some(target);
        self.form.command = self.last_command(&recent[target]);
        self.form.project = recent[target].display().to_string();
    }

    /// Starts the session the form describes. A refusal leaves the form open with the reason, so
    /// the owner can fix a field instead of retyping both.
    fn submit_launch(&mut self) -> Vec<Effect> {
        if self.mode != Mode::Launch {
            return Vec::new();
        }
        let project = self.form.project.trim();
        if project.is_empty() {
            self.refuse(&Refusal::EmptyProject);
            return Vec::new();
        }
        let spec = LaunchSpec {
            project: PathBuf::from(project),
            command: self
                .form
                .command
                .split_whitespace()
                .map(str::to_owned)
                .collect(),
        };
        let effects = self.launch(spec);
        if !effects.is_empty() {
            self.mode = Mode::Overview;
        }
        effects
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::supervised::Verdict;
    use claims::{assert_none, assert_some};
    use pretty_assertions::assert_eq;

    fn spec(name: &str) -> LaunchSpec {
        LaunchSpec {
            project: PathBuf::from(format!("/work/{name}")),
            command: vec!["claude".to_owned()],
        }
    }

    /// An app with one launched session (id 1, generation 1).
    fn one() -> App {
        let mut app = App::new();
        app.update(Msg::Launch(spec("shop")));
        app
    }

    fn channel(id: u32, generation: Generation, seq: u64, event: Event) -> Msg {
        Msg::Channel {
            id: SessionId(id),
            generation,
            seq,
            event,
        }
    }

    /// Feeds numbered events to session 1, generation 1.
    fn feed(app: &mut App, events: Vec<Event>) {
        for (i, event) in events.into_iter().enumerate() {
            app.update(channel(1, 1, i as u64 + 1, event));
        }
    }

    fn running() -> App {
        let mut app = one();
        feed(
            &mut app,
            vec![Event::Starting {}, Event::Running { agent_pid: 42 }],
        );
        app
    }

    fn only(app: &App) -> &Session {
        assert_some!(app.sessions().first())
    }

    #[test]
    fn launch_adds_a_starting_session_selects_it_and_asks_for_a_spawn() {
        let mut app = App::new();
        let effects = app.update(Msg::Launch(spec("shop")));
        assert_eq!(
            effects,
            vec![Effect::Spawn {
                id: SessionId(1),
                generation: 1,
                spec: spec("shop")
            }]
        );
        assert_eq!(only(&app).phase, Phase::Starting);
        let effects = app.update(Msg::Launch(spec("billing")));
        assert_eq!(effects.len(), 1);
        assert_eq!(app.selected_index(), 1, "the new session is selected");
        assert_eq!(app.sessions().len(), 2);
    }

    #[test]
    fn launch_refuses_an_empty_command_and_the_ninth_live_session_with_a_clear_message() {
        let mut app = App::new();
        let mut empty = spec("x");
        empty.command.clear();
        assert_eq!(app.update(Msg::Launch(empty)), vec![]);
        assert_eq!(app.notice.as_deref(), Some("the agent command is empty"));
        for n in 0..MAX_SESSIONS {
            assert_eq!(app.update(Msg::Launch(spec(&n.to_string()))).len(), 1);
        }
        assert_eq!(app.update(Msg::Launch(spec("ninth"))), vec![]);
        assert_eq!(
            app.notice.as_deref(),
            Some("8 sessions are already running; stop one first")
        );
        assert_eq!(app.sessions().len(), MAX_SESSIONS);
        // Background failure frees a slot, but only the owner's next action dismisses notice.
        let notice = app.notice.clone();
        app.update(Msg::SpawnFailed {
            id: SessionId(1),
            generation: 1,
            reason: "x".into(),
        });
        assert_eq!(app.notice, notice);
        assert_eq!(app.update(Msg::Launch(spec("ninth"))).len(), 1);
        assert_none!(app.notice.as_ref());
    }

    #[test]
    fn events_move_a_session_through_its_life_and_record_what_they_carry() {
        let mut app = running();
        assert_eq!(only(&app).phase, Phase::Running);
        assert_eq!(only(&app).agent_pid, Some(42));
        feed_from(&mut app, 3, vec![Event::Warning { text: "w".into() }]);
        assert_eq!(only(&app).warnings.len(), 1);
        feed_from(&mut app, 4, vec![Event::Stopping {}]);
        assert_eq!(only(&app).phase, Phase::Stopping);
        feed_from(
            &mut app,
            5,
            vec![Event::Exited {
                code: Some(0),
                signal: None,
                cleanup: Cleanup::Complete {},
            }],
        );
        assert_eq!(only(&app).phase, Phase::Exited);
        assert_eq!(assert_some!(only(&app).exit.as_ref()).code, Some(0));
        assert!(app.alerts().is_empty(), "a clean exit raises nothing");
    }

    fn feed_from(app: &mut App, first: u64, events: Vec<Event>) {
        for (i, event) in events.into_iter().enumerate() {
            app.update(channel(1, 1, first + i as u64, event));
        }
    }

    #[test]
    fn an_event_out_of_sequence_loses_the_session_and_asks_it_to_stop() {
        let mut app = one();
        feed(&mut app, vec![Event::Starting {}]);
        let effects = app.update(channel(1, 1, 3, Event::Running { agent_pid: 1 }));
        assert_eq!(
            effects,
            vec![Effect::Stop {
                id: SessionId(1),
                generation: 1
            }]
        );
        assert_eq!(only(&app).phase, Phase::Lost);
        assert_eq!(app.alerts().len(), 1);
        // A repeat is also a break.
        let mut app = one();
        feed(&mut app, vec![Event::Starting {}]);
        app.update(channel(1, 1, 1, Event::Starting {}));
        assert_eq!(only(&app).phase, Phase::Lost);
    }

    #[test]
    fn restarting_an_inactive_row_cannot_exceed_live_capacity() {
        for phase in [Phase::Exited, Phase::Approve] {
            let mut app = one();
            app.sessions[0].phase = phase.clone();
            for n in 0..MAX_SESSIONS {
                app.update(Msg::Launch(spec(&format!("live-{n}"))));
            }
            assert_eq!(app.live_count(), MAX_SESSIONS);
            let original = app.sessions[0].clone();
            let effects = if phase == Phase::Approve {
                app.update(Msg::ApprovalFinished {
                    id: original.id,
                    generation: original.generation,
                    outcome: ApprovalOutcome::Approved,
                })
            } else {
                app.update(Msg::Jump(1));
                app.update(Msg::AskRestart)
            };
            assert!(effects.is_empty(), "over-capacity spawn: {effects:?}");
            assert_eq!(app.sessions[0], original);
            assert_eq!(app.live_count(), MAX_SESSIONS);
            assert!(app.notice.is_some());
        }
    }

    #[test]
    fn worker_traffic_does_not_dismiss_an_unread_owner_notice() {
        let mut app = running();
        app.update(Msg::Notice("input refused".into()));
        let notice = app.notice.clone();
        assert_eq!(notice.as_deref(), Some("input refused"));
        app.update(channel(1, 1, 3, Event::denial("background denial")));
        assert_eq!(app.notice, notice);
        app.update(Msg::Spawned {
            id: SessionId(1),
            generation: 1,
        });
        assert_eq!(app.notice, notice);
        app.update(Msg::NextTab);
        assert!(app.notice.is_none(), "owner action dismisses the notice");
    }

    #[test]
    fn messages_from_an_older_generation_change_nothing() {
        let mut app = running();
        app.update(Msg::AskRestart);
        let effects = app.update(Msg::Answer(true));
        assert_eq!(effects.len(), 2, "stop the old, start the new: {effects:?}");
        assert_eq!(only(&app).generation, 2);
        assert_eq!(only(&app).phase, Phase::Starting);
        app.update(Msg::Notice("current generation warning".into()));
        let before = app.clone();
        // Everything the replaced process can still say.
        for msg in [
            channel(1, 1, 1, Event::Running { agent_pid: 9 }),
            channel(
                1,
                1,
                2,
                Event::Exited {
                    code: Some(1),
                    signal: None,
                    cleanup: Cleanup::Complete {},
                },
            ),
            Msg::ChannelLost {
                id: SessionId(1),
                generation: 1,
            },
            Msg::ProcessExited {
                id: SessionId(1),
                generation: 1,
                code: Some(0),
                signal: None,
            },
            Msg::SpawnFailed {
                id: SessionId(1),
                generation: 1,
                reason: "old".into(),
            },
            Msg::Spawned {
                id: SessionId(1),
                generation: 1,
            },
            Msg::SessionLost {
                id: SessionId(1),
                generation: 1,
                reason: "old".into(),
            },
            Msg::Input {
                id: SessionId(1),
                generation: 1,
                bytes: vec![b'y'],
            },
            Msg::ApprovalFinished {
                id: SessionId(1),
                generation: 1,
                outcome: ApprovalOutcome::Approved,
            },
        ] {
            assert_eq!(app.update(msg), vec![]);
            assert_eq!(app, before, "the old generation changed the state");
        }
    }

    #[test]
    fn a_message_for_a_session_that_does_not_exist_is_ignored() {
        let mut app = one();
        app.update(Msg::Notice("current warning".into()));
        let before = app.clone();
        assert_eq!(app.update(channel(7, 1, 1, Event::Starting {})), vec![]);
        assert_eq!(
            app.update(Msg::ProcessExited {
                id: SessionId(7),
                generation: 1,
                code: None,
                signal: None
            }),
            vec![]
        );
        assert_eq!(app, before);
    }

    #[test]
    fn child_exit_channel_loss_and_spawn_failure_give_the_right_states() {
        // hb exits after its final report: Exited, and the channel closing afterwards is normal.
        let mut app = running();
        feed_from(
            &mut app,
            3,
            vec![Event::Exited {
                code: Some(3),
                signal: None,
                cleanup: Cleanup::Complete {},
            }],
        );
        app.update(Msg::ChannelLost {
            id: SessionId(1),
            generation: 1,
        });
        app.update(Msg::ProcessExited {
            id: SessionId(1),
            generation: 1,
            code: Some(0),
            signal: None,
        });
        assert_eq!(only(&app).phase, Phase::Exited);

        // The channel breaks while live: Lost, and a stop is asked for.
        let mut app = running();
        let effects = app.update(Msg::ChannelLost {
            id: SessionId(1),
            generation: 1,
        });
        assert_eq!(only(&app).phase, Phase::Lost);
        assert_eq!(effects.len(), 1);
        // The process is later reaped: the loss becomes a failure.
        app.update(Msg::ProcessExited {
            id: SessionId(1),
            generation: 1,
            code: None,
            signal: Some(9),
        });
        assert_eq!(only(&app).phase, Phase::Failed);

        // hb dies with no final report: Failed, with the signal named.
        let mut app = running();
        app.update(Msg::ProcessExited {
            id: SessionId(1),
            generation: 1,
            code: None,
            signal: Some(9),
        });
        assert_eq!(only(&app).phase, Phase::Failed);
        assert_eq!(
            only(&app).failure.as_deref(),
            Some("hb was killed by signal 9")
        );

        // hb could not be started at all.
        let mut app = one();
        app.update(Msg::SpawnFailed {
            id: SessionId(1),
            generation: 1,
            reason: "no such file".into(),
        });
        assert_eq!(only(&app).phase, Phase::Failed);
        assert_eq!(only(&app).failure.as_deref(), Some("no such file"));
        assert_eq!(app.alerts().len(), 1);
    }

    #[test]
    fn approval_required_keeps_the_row_on_approve_even_after_hb_exits_78() {
        let mut app = one();
        feed(
            &mut app,
            vec![
                Event::Starting {},
                Event::approval_required("/work/shop"),
                Event::Stopping {},
                Event::Exited {
                    code: None,
                    signal: None,
                    cleanup: Cleanup::Complete {},
                },
            ],
        );
        assert_eq!(only(&app).phase, Phase::Approve);
        assert_eq!(app.alerts().len(), 1);
        app.update(Msg::ProcessExited {
            id: SessionId(1),
            generation: 1,
            code: Some(78),
            signal: None,
        });
        assert_eq!(only(&app).phase, Phase::Approve);
        assert_eq!(
            app.update(Msg::ReviewApproval),
            vec![Effect::SuspendForApproval {
                id: SessionId(1),
                generation: 1,
                project: PathBuf::from("/work/shop")
            }]
        );
    }

    fn finished(id: u32, generation: Generation, outcome: ApprovalOutcome) -> Msg {
        Msg::ApprovalFinished {
            id: SessionId(id),
            generation,
            outcome,
        }
    }

    #[test]
    fn an_approved_review_starts_the_same_session_again_as_a_new_generation() {
        let mut app = App::new();
        app.update(Msg::Launch(spec("shop")));
        app.update(Msg::Channel {
            id: SessionId(1),
            generation: 1,
            seq: 1,
            event: Event::ApprovalRequired {
                root: "/work/shop".into(),
            },
        });
        assert_eq!(only(&app).phase, Phase::Approve);
        let effects = app.update(finished(1, 1, ApprovalOutcome::Approved));
        assert!(matches!(effects[..], [Effect::Spawn { generation: 2, .. }]));
        // A second, late result for generation 1 starts nothing.
        assert_eq!(
            app.update(finished(1, 1, ApprovalOutcome::Approved)),
            vec![]
        );
    }

    #[test]
    fn a_review_that_did_not_approve_or_could_not_run_leaves_the_row_and_says_so() {
        for (outcome, words) in [
            (ApprovalOutcome::NotApproved, "not approved"),
            (
                ApprovalOutcome::Failed("no such file".into()),
                "no such file",
            ),
        ] {
            let mut app = App::new();
            app.update(Msg::Launch(spec("shop")));
            app.update(Msg::Channel {
                id: SessionId(1),
                generation: 1,
                seq: 1,
                event: Event::ApprovalRequired {
                    root: "/work/shop".into(),
                },
            });
            assert_eq!(app.update(finished(1, 1, outcome)), vec![]);
            assert_eq!(only(&app).phase, Phase::Approve);
            assert!(app.alerts().last().is_some_and(|a| a.text.contains(words)));
        }
    }

    fn lost(id: u32, generation: Generation) -> Msg {
        Msg::SessionLost {
            id: SessionId(id),
            generation,
            reason: "the process's state could not be read, so it was killed".into(),
        }
    }

    #[test]
    fn a_session_lost_is_failed_never_exited_and_says_why() {
        let mut app = running();
        assert_eq!(app.update(lost(1, 1)), vec![]);
        let session = only(&app);
        assert_eq!(session.phase, Phase::Failed);
        assert_none!(session.exit.as_ref());
        assert!(
            session
                .failure
                .as_deref()
                .is_some_and(|f| f.contains("killed"))
        );
        assert!(app.alerts().last().is_some_and(|a| a.text.contains("lost")));
    }

    #[test]
    fn a_session_lost_after_the_session_reported_its_end_or_for_an_old_generation_changes_nothing()
    {
        let mut app = running();
        app.update(Msg::Channel {
            id: SessionId(1),
            generation: 1,
            seq: 3,
            event: Event::Exited {
                code: Some(0),
                signal: None,
                cleanup: crate::session::supervised::Cleanup::Complete {},
            },
        });
        let before = only(&app).clone();
        assert_eq!(app.update(lost(1, 1)), vec![]);
        assert_eq!(only(&app), &before);
        assert_eq!(app.update(lost(1, 9)), vec![]);
        assert_eq!(only(&app), &before);
    }

    #[test]
    fn alerts_are_capped_and_the_newest_are_kept() {
        let mut app = running();
        for n in 0..(MAX_ALERTS + 10) {
            app.update(Msg::ApprovalFinished {
                id: SessionId(1),
                generation: 1,
                outcome: ApprovalOutcome::Failed(format!("n{n}")),
            });
        }
        // Not waiting for approval: nothing is raised.
        assert_eq!(app.alerts().len(), 0);
        for n in 0..(MAX_ALERTS + 10) {
            app.alert(SessionId(1), format!("n{n}"));
        }
        assert_eq!(app.alerts().len(), MAX_ALERTS);
        assert_eq!(
            app.alerts().last().map(|a| a.text.as_str()),
            Some(format!("n{}", MAX_ALERTS + 9).as_str())
        );
        assert_eq!(app.alerts().first().map(|a| a.text.as_str()), Some("n10"));
    }

    #[test]
    fn a_notice_is_shown_until_the_next_owner_action_and_changes_nothing_else() {
        let mut app = running();
        let before = only(&app).clone();
        assert_eq!(app.update(Msg::Notice("keys dropped".into())), vec![]);
        assert_eq!(app.notice.as_deref(), Some("keys dropped"));
        assert_eq!(only(&app), &before);
        app.update(Msg::Select(0));
        assert_eq!(app.notice, None);
    }

    #[test]
    fn a_review_result_for_an_old_generation_or_a_session_not_waiting_is_ignored() {
        let mut app = running();
        assert_eq!(
            app.update(finished(1, 1, ApprovalOutcome::Approved)),
            vec![]
        );
        assert_eq!(
            app.update(finished(9, 1, ApprovalOutcome::Approved)),
            vec![]
        );
        assert_eq!(only(&app).generation, 1);
    }

    #[test]
    fn the_exact_events_hb_sends_for_an_unapproved_config_leave_the_row_on_approve() {
        // As `hb run --supervised` sends them: Starting, ApprovalRequired, Stopping, Exited;
        // then the channel closes and the process is reaped.
        let mut app = one();
        let sent = [
            Event::Starting {},
            Event::approval_required("/work/shop"),
            Event::Stopping {},
            Event::Exited {
                code: None,
                signal: None,
                cleanup: Cleanup::Complete {},
            },
        ];
        for (i, event) in sent.into_iter().enumerate() {
            assert_eq!(app.update(channel(1, 1, i as u64 + 1, event)), vec![]);
            let expected = if i == 0 {
                Phase::Starting
            } else {
                Phase::Approve
            };
            assert_eq!(only(&app).phase, expected, "after event {}", i + 1);
        }
        assert_eq!(
            app.update(Msg::ChannelLost {
                id: SessionId(1),
                generation: 1
            }),
            vec![],
            "the close after ApprovalRequired is normal"
        );
        app.update(Msg::ProcessExited {
            id: SessionId(1),
            generation: 1,
            code: Some(78),
            signal: None,
        });
        assert_eq!(only(&app).phase, Phase::Approve);
        assert_none!(only(&app).failure.as_ref());
    }

    #[test]
    fn a_session_waiting_for_approval_has_no_process_so_it_holds_no_slot_and_quit_does_not_ask() {
        let mut app = one();
        feed(
            &mut app,
            vec![Event::Starting {}, Event::approval_required("/work/shop")],
        );
        assert_eq!(only(&app).phase, Phase::Approve);
        assert_eq!(app.live_count(), 0);
        assert_eq!(app.update(Msg::AskQuit), vec![Effect::Quit]);
        // Restarting it (after the owner reviewed) starts a new generation without a question.
        let mut app = one();
        feed(
            &mut app,
            vec![Event::Starting {}, Event::approval_required("/work/shop")],
        );
        let effects = app.update(Msg::AskRestart);
        assert_eq!(effects.len(), 1);
        assert!(matches!(effects[0], Effect::Spawn { generation: 2, .. }));
    }

    #[test]
    fn review_approval_is_refused_for_a_session_that_is_not_waiting() {
        let mut app = running();
        assert_eq!(app.update(Msg::ReviewApproval), vec![]);
        assert_eq!(
            app.notice.as_deref(),
            Some("that session is not waiting for approval")
        );
        assert_eq!(App::new().update(Msg::ReviewApproval), vec![]);
    }

    #[test]
    fn denials_and_proxy_rows_are_kept_in_bounded_rings_and_unread_counts_follow_selection() {
        let mut app = one();
        app.update(Msg::Launch(spec("second")));
        // Session 1 is not selected (2 is), so its denials are unread.
        for n in 0..(DENIAL_RING + 5) {
            app.update(channel(
                1,
                1,
                n as u64 + 1,
                Event::Denial {
                    text: format!("d{n}"),
                },
            ));
        }
        let first = assert_some!(app.sessions().first());
        assert_eq!(first.denials.len(), DENIAL_RING);
        assert_eq!(first.denials.evicted, 5);
        assert_eq!(assert_some!(first.denials.iter().next()), "d5");
        assert_eq!(first.unread_denials, (DENIAL_RING + 5) as u64);
        app.update(Msg::Select(-1));
        assert_eq!(assert_some!(app.selected()).unread_denials, 0);
        let seq = (DENIAL_RING + 6) as u64;
        app.update(channel(
            1,
            1,
            seq,
            Event::Proxy {
                host: Some("api.example.com".into()),
                port: Some(443),
                decision: Verdict::Refused {
                    code: "not_allowed".into(),
                    reason: "r".into(),
                },
                up: 1,
                down: 2,
            },
        ));
        let row = assert_some!(assert_some!(app.selected()).proxy.iter().next());
        assert_eq!(row.target, "api.example.com:443");
        assert_eq!(row.verdict, "refused not_allowed");
        app.update(channel(
            1,
            1,
            seq + 1,
            Event::Dropped {
                denials: 4,
                proxy: 2,
            },
        ));
        assert_eq!(assert_some!(app.selected()).dropped_denials, 4);
        assert_eq!(assert_some!(app.selected()).dropped_proxy, 2);
    }

    #[test]
    fn selection_is_clamped_alerts_clear_on_looking_and_nothing_moves_it_by_itself() {
        let mut app = App::new();
        for n in 0..3 {
            app.update(Msg::Launch(spec(&n.to_string())));
        }
        assert_eq!(app.selected_index(), 2);
        app.update(Msg::Select(5));
        assert_eq!(app.selected_index(), 2);
        app.update(Msg::Jump(1));
        assert_eq!(app.selected_index(), 0);
        app.update(Msg::Jump(0));
        app.update(Msg::Jump(9));
        assert_eq!(app.selected_index(), 0);
        app.update(Msg::Select(-4));
        assert_eq!(app.selected_index(), 0);
        // A failure in session 3 raises an alert and does not move the selection.
        app.update(Msg::SpawnFailed {
            id: SessionId(3),
            generation: 1,
            reason: "x".into(),
        });
        assert_eq!(app.selected_index(), 0);
        assert_eq!(app.alerts().len(), 1);
        app.update(Msg::Jump(3));
        assert!(app.alerts().is_empty(), "looking at it clears its alert");
    }

    #[test]
    fn interact_needs_a_running_session_and_ctrl_g_returns() {
        let mut app = one();
        app.update(Msg::EnterInteract);
        assert_eq!(app.mode, Mode::Overview);
        assert_eq!(app.notice.as_deref(), Some("that session is not running"));
        let mut app = running();
        app.update(Msg::EnterInteract);
        assert_eq!(app.mode, Mode::Interact);
        // Selection keys do nothing while interacting: they belong to the agent.
        app.update(Msg::Select(1));
        app.update(Msg::AskQuit);
        assert_eq!(app.mode, Mode::Interact);
        app.update(Msg::LeaveInteract);
        assert_eq!(app.mode, Mode::Overview);
        assert_eq!(App::new().update(Msg::EnterInteract), vec![]);
    }

    #[test]
    fn stop_and_restart_ask_first_and_a_no_changes_nothing() {
        let mut app = running();
        app.update(Msg::AskStop);
        assert_eq!(app.mode, Mode::Confirm);
        assert_eq!(app.pending, Some(Pending::Stop(SessionId(1))));
        let before = only(&app).phase.clone();
        assert_eq!(app.update(Msg::Answer(false)), vec![]);
        assert_eq!((app.mode, app.pending.clone()), (Mode::Overview, None));
        assert_eq!(only(&app).phase, before);
        app.update(Msg::AskStop);
        assert_eq!(
            app.update(Msg::Answer(true)),
            vec![Effect::Stop {
                id: SessionId(1),
                generation: 1
            }]
        );
        assert_eq!(only(&app).phase, Phase::Stopping);
        // An answer with no question is ignored.
        assert_eq!(app.update(Msg::Answer(true)), vec![]);
    }

    #[test]
    fn restarting_an_ended_session_needs_no_question_and_makes_a_new_clean_generation() {
        let mut app = one();
        app.update(Msg::SpawnFailed {
            id: SessionId(1),
            generation: 1,
            reason: "x".into(),
        });
        let effects = app.update(Msg::AskRestart);
        assert_eq!(
            effects,
            vec![Effect::Spawn {
                id: SessionId(1),
                generation: 2,
                spec: spec("shop")
            }]
        );
        assert_eq!(app.mode, Mode::Overview);
        let session = only(&app);
        assert_eq!(
            (session.generation, session.phase.clone()),
            (2, Phase::Starting)
        );
        assert_none!(session.failure.as_ref());
        assert!(app.alerts().is_empty());
        // Stopping what has ended is refused.
        let mut app = one();
        app.update(Msg::SpawnFailed {
            id: SessionId(1),
            generation: 1,
            reason: "x".into(),
        });
        app.update(Msg::AskStop);
        assert_eq!(app.notice.as_deref(), Some("that session is not running"));
    }

    #[test]
    fn quit_with_nothing_live_leaves_at_once_and_otherwise_asks_then_stops_every_live_session() {
        let mut app = App::new();
        assert_eq!(app.update(Msg::AskQuit), vec![Effect::Quit]);
        assert!(app.is_quitting());

        let mut app = running();
        app.update(Msg::Launch(spec("second")));
        app.update(Msg::SpawnFailed {
            id: SessionId(2),
            generation: 1,
            reason: "x".into(),
        });
        assert_eq!(app.live_count(), 1);
        assert_eq!(app.update(Msg::AskQuit), vec![]);
        assert_eq!(app.pending, Some(Pending::Quit));
        let effects = app.update(Msg::Answer(true));
        assert_eq!(
            effects,
            vec![
                Effect::Stop {
                    id: SessionId(1),
                    generation: 1
                },
                Effect::Quit
            ]
        );
        assert!(app.is_quitting());
        // Declining leaves everything as it was.
        let mut app = running();
        app.update(Msg::AskQuit);
        assert_eq!(app.update(Msg::Answer(false)), vec![]);
        assert!(!app.is_quitting());
        assert_eq!(app.live_count(), 1);
    }

    #[test]
    fn help_toggles_only_from_overview_and_tab_cycles() {
        let mut app = running();
        app.update(Msg::ToggleHelp);
        assert_eq!(app.mode, Mode::Help);
        app.update(Msg::ToggleHelp);
        assert_eq!(app.mode, Mode::Overview);
        app.update(Msg::EnterInteract);
        app.update(Msg::ToggleHelp);
        assert_eq!(app.mode, Mode::Interact);
        assert_eq!(app.tab, Tab::Denials);
        app.update(Msg::NextTab);
        assert_eq!(app.tab, Tab::Proxy);
        app.update(Msg::NextTab);
        assert_eq!(app.tab, Tab::Denials);
    }

    #[test]
    fn phase_and_mode_names_are_the_words_the_screen_shows() {
        assert_eq!(Phase::Running.to_string(), "running");
        assert_eq!(Phase::Approve.to_string(), "approve");
        assert_eq!(Mode::Interact.to_string(), "interact");
        assert_eq!(Tab::Proxy.to_string(), "proxy");
        let name: &'static str = Phase::Lost.into();
        assert_eq!(name, "lost");
    }
    // ========================================================================
    // Launch form, panels, input (hb-2hh)
    // ========================================================================

    fn open_form(app: &mut App, cwd: &str) {
        app.update(Msg::OpenLaunch {
            cwd: PathBuf::from(cwd),
        });
        assert_eq!(app.mode, Mode::Launch);
    }

    fn type_text(app: &mut App, text: &str) {
        for c in text.chars() {
            app.update(Msg::Form(FormEdit::Char(c)));
        }
    }

    #[test]
    fn the_form_starts_on_the_command_with_the_cwd_and_that_projects_last_command() {
        let mut app = App::new();
        open_form(&mut app, "/work/new");
        assert_eq!(app.form.project, "/work/new");
        assert_eq!(app.form.command, "");
        assert_eq!(app.form.field, Field::Command);
        app.update(Msg::CancelLaunch);
        assert_eq!(app.mode, Mode::Overview);
        // After a session ran there, the form offers the same command again.
        app.update(Msg::Launch(spec("shop")));
        open_form(&mut app, "/work/shop");
        assert_eq!(app.form.command, "claude");
    }

    #[test]
    fn typing_edits_the_current_field_and_ignores_control_characters() {
        let mut app = App::new();
        open_form(&mut app, "/p");
        type_text(&mut app, "pi --x\u{7}");
        assert_eq!(app.form.command, "pi --x");
        app.update(Msg::Form(FormEdit::Backspace));
        assert_eq!(app.form.command, "pi --");
        app.update(Msg::Form(FormEdit::SwitchField));
        type_text(&mut app, "/q");
        assert_eq!(app.form.project, "/p/q");
        // Backspace on an empty field is harmless.
        app.form.command.clear();
        app.update(Msg::Form(FormEdit::SwitchField));
        app.update(Msg::Form(FormEdit::Backspace));
        assert_eq!(app.form.command, "");
    }

    #[test]
    fn submitting_splits_the_command_launches_selects_and_closes_the_form() {
        let mut app = App::new();
        open_form(&mut app, "/work/shop");
        type_text(&mut app, "  claude   --resume ");
        let effects = app.update(Msg::SubmitLaunch);
        assert_eq!(
            effects,
            vec![Effect::Spawn {
                id: SessionId(1),
                generation: 1,
                spec: LaunchSpec {
                    project: PathBuf::from("/work/shop"),
                    command: vec!["claude".into(), "--resume".into()],
                },
            }]
        );
        assert_eq!(app.mode, Mode::Overview);
    }

    #[test]
    fn a_refused_submit_keeps_the_form_open_with_what_was_typed_and_says_why() {
        let mut app = App::new();
        open_form(&mut app, "/work/shop");
        assert_eq!(app.update(Msg::SubmitLaunch), vec![]);
        assert_eq!(app.mode, Mode::Launch);
        assert_eq!(app.notice.as_deref(), Some("the agent command is empty"));
        app.update(Msg::Form(FormEdit::SwitchField));
        for _ in 0..10 {
            app.update(Msg::Form(FormEdit::Backspace));
        }
        app.update(Msg::Form(FormEdit::SwitchField));
        type_text(&mut app, "pi");
        app.update(Msg::Form(FormEdit::SwitchField));
        for _ in 0..20 {
            app.update(Msg::Form(FormEdit::Backspace));
        }
        assert_eq!(app.update(Msg::SubmitLaunch), vec![]);
        assert_eq!(
            app.notice.as_deref(),
            Some("the project directory is empty")
        );
        assert_eq!(app.form.command, "pi");
        assert_eq!(app.mode, Mode::Launch);
    }

    #[test]
    fn the_recent_projects_are_newest_first_and_each_once() {
        let mut app = App::new();
        for name in ["a", "b", "a", "c"] {
            app.update(Msg::Launch(spec(name)));
        }
        let names: Vec<String> = app
            .recent_projects()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        assert_eq!(names, ["/work/c", "/work/a", "/work/b"]);
    }

    #[test]
    fn picking_a_recent_project_fills_both_fields_and_stops_at_the_ends() {
        let mut app = App::new();
        for (name, cmd) in [("a", "claude"), ("b", "pi")] {
            app.update(Msg::Launch(LaunchSpec {
                project: PathBuf::from(format!("/work/{name}")),
                command: vec![cmd.to_owned()],
            }));
        }
        open_form(&mut app, "/elsewhere");
        app.update(Msg::Form(FormEdit::Recent(true)));
        assert_eq!(
            (app.form.project.as_str(), app.form.command.as_str()),
            ("/work/b", "pi")
        );
        app.update(Msg::Form(FormEdit::Recent(true)));
        assert_eq!(app.form.project, "/work/a");
        app.update(Msg::Form(FormEdit::Recent(true)));
        assert_eq!(app.form.project, "/work/a", "stops at the oldest");
        app.update(Msg::Form(FormEdit::Recent(false)));
        app.update(Msg::Form(FormEdit::Recent(false)));
        assert_eq!(app.form.project, "/work/b", "stops at the newest");
        // With nothing to pick from, the fields are left alone.
        let mut empty = App::new();
        open_form(&mut empty, "/x");
        empty.update(Msg::Form(FormEdit::Recent(true)));
        assert_eq!(empty.form.project, "/x");
    }

    #[test]
    fn form_messages_outside_the_form_do_nothing() {
        let mut app = App::new();
        assert_eq!(app.update(Msg::Form(FormEdit::Char('x'))), vec![]);
        assert_eq!(app.update(Msg::SubmitLaunch), vec![]);
        assert_eq!(app.form, LaunchForm::empty());
        // And opening it from another mode is refused.
        app.update(Msg::ToggleHelp);
        app.update(Msg::OpenLaunch {
            cwd: PathBuf::from("/x"),
        });
        assert_eq!(app.mode, Mode::Help);
    }

    #[test]
    fn panels_cycle_both_ways_and_the_lower_tab_follows() {
        let mut app = one();
        assert_eq!(app.panel, Panel::Sessions);
        app.update(Msg::NextPanel(true));
        assert_eq!(app.panel, Panel::Terminal);
        app.update(Msg::NextPanel(true));
        assert_eq!((app.panel, app.tab), (Panel::Denials, Tab::Denials));
        app.update(Msg::NextPanel(true));
        assert_eq!((app.panel, app.tab), (Panel::Proxy, Tab::Proxy));
        app.update(Msg::NextPanel(true));
        assert_eq!(app.panel, Panel::Sessions);
        app.update(Msg::NextPanel(false));
        assert_eq!(app.panel, Panel::Proxy);
    }

    #[test]
    fn entering_interact_shows_the_terminal_panel() {
        let mut app = running();
        app.update(Msg::EnterInteract);
        assert_eq!(app.panel, Panel::Terminal);
    }

    #[test]
    fn interact_ends_by_itself_when_the_session_stops_running() {
        let mut app = running();
        app.update(Msg::EnterInteract);
        assert_eq!(app.mode, Mode::Interact);
        feed_from(&mut app, 3, vec![Event::Stopping {}]);
        assert_eq!(app.mode, Mode::Overview);
    }

    #[test]
    fn input_becomes_a_write_only_for_the_current_running_generation() {
        let mut app = running();
        let input = |generation| Msg::Input {
            id: SessionId(1),
            generation,
            bytes: b"x".to_vec(),
        };
        assert_eq!(
            app.update(input(1)),
            vec![Effect::Write {
                id: SessionId(1),
                generation: 1,
                bytes: b"x".to_vec()
            }]
        );
        assert_eq!(app.update(input(2)), vec![]);
        assert_eq!(
            app.update(Msg::Input {
                id: SessionId(9),
                generation: 1,
                bytes: b"x".to_vec()
            }),
            vec![]
        );
        feed_from(&mut app, 3, vec![Event::Stopping {}]);
        assert_eq!(app.update(input(1)), vec![]);
    }

    #[test]
    fn too_small_sets_the_notice_the_owner_reads() {
        let mut app = running();
        app.update(Msg::TooSmall);
        assert_eq!(
            app.notice.as_deref(),
            Some("the terminal is too small to interact; make it larger")
        );
    }
}
