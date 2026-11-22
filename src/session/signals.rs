// ABOUTME: Signal supervision for `hb run`: the escalation rule (pure) and, below it, the kqueue thread that applies it.
// ABOUTME: INT, TERM and HUP are blocked in hb and received through kqueue, then forwarded to the child (design 7.2, D53, D60).
//! Forwarding INT, TERM and HUP to the child, and escalating to SIGKILL.
//!
//! The rule lives in [`Escalation`], which takes the time as an argument so it can be tested
//! without signals or sleeping. The thread that applies it is [`Supervisor`].

use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
use nix::sys::signal::{SigSet, Signal, kill, killpg};
use nix::sys::time::TimeSpec;
use nix::unistd::Pid;
use snafu::{ResultExt, Snafu, ensure};

/// The signals `hb` blocks and forwards.
pub const SUPERVISED: [Signal; 3] = [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP];

/// Why signal supervision could not be set up.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SignalError {
    /// The signal mask could not be changed.
    #[snafu(display("the signal mask could not be changed"))]
    Mask {
        /// The underlying error.
        source: Errno,
    },

    /// INT, TERM and HUP are not all blocked in the calling thread, so one could kill hb before it cleans up.
    #[snafu(display("SIGINT, SIGTERM and SIGHUP must be blocked before the child is started"))]
    NotBlocked,

    /// The kernel event queue could not be set up.
    #[snafu(display("the kernel event queue for signals could not be set up"))]
    Kqueue {
        /// The underlying error.
        source: Errno,
    },

    /// The supervising thread could not be started.
    #[snafu(display("the signal supervising thread could not be started"))]
    Thread {
        /// The underlying error.
        source: std::io::Error,
    },
}

fn supervised_set() -> SigSet {
    let mut set = SigSet::empty();
    for signal in SUPERVISED {
        set.add(signal);
    }
    set
}

/// Blocks INT, TERM and HUP in the calling thread, and so in every thread it starts afterwards.
///
/// Call it first thing in the main thread, before any other thread exists.
///
/// # Errors
/// [`SignalError::Mask`] if the mask cannot be changed.
pub fn block_supervised() -> Result<(), SignalError> {
    supervised_set().thread_block().context(MaskSnafu)
}

/// Unblocks INT, TERM and HUP in the calling thread, so their default action can run again.
///
/// # Errors
/// [`SignalError::Mask`] if the mask cannot be changed.
pub fn unblock_supervised() -> Result<(), SignalError> {
    supervised_set().thread_unblock().context(MaskSnafu)
}

/// Whether INT, TERM and HUP are all blocked in the calling thread.
#[must_use]
pub fn supervised_blocked() -> bool {
    SigSet::thread_get_mask().is_ok_and(|mask| SUPERVISED.iter().all(|s| mask.contains(*s)))
}

/// Empties the calling thread's blocked set. The `hb __child` helper does this before it execs,
/// because Rust's `Command` hands the parent's mask to the child.
///
/// # Errors
/// [`SignalError::Mask`] if the mask cannot be changed.
pub fn clear_mask() -> Result<(), SignalError> {
    SigSet::empty().thread_set_mask().context(MaskSnafu)
}

/// Who a forwarded signal is sent to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The child's whole process group (the child leads it).
    Group(Pid),
    /// Only the child. Used when the child shares hb's group, which also holds hb.
    Child(Pid),
}

impl Target {
    fn send(self, signal: Signal) {
        // ESRCH only means the child is already gone.
        let _ = match self {
            Self::Group(pgid) => killpg(pgid, signal),
            Self::Child(pid) => kill(pid, signal),
        };
    }
}

/// Signals registered with the kernel, before the child exists.
///
/// Registering first means a signal that arrives while the child is starting is queued for the
/// thread, not lost.
#[derive(Debug)]
pub struct Watch {
    queue: Arc<Kqueue>,
}

/// The identifier of the "stop" event.
const STOP_ID: usize = 0;

impl Watch {
    /// Registers INT, TERM and HUP with a new kernel event queue.
    ///
    /// # Errors
    /// [`SignalError::NotBlocked`] unless the three are blocked in this thread;
    /// [`SignalError::Kqueue`] if the queue cannot be set up.
    pub fn prepare() -> Result<Self, SignalError> {
        ensure!(supervised_blocked(), NotBlockedSnafu);
        let queue = Kqueue::new().context(KqueueSnafu)?;
        let mut changes: Vec<KEvent> = SUPERVISED
            .iter()
            .map(|signal| {
                KEvent::new(
                    *signal as usize,
                    EventFilter::EVFILT_SIGNAL,
                    EvFlags::EV_ADD.union(EvFlags::EV_ENABLE),
                    FilterFlag::empty(),
                    0,
                    0,
                )
            })
            .collect();
        changes.push(KEvent::new(
            STOP_ID,
            EventFilter::EVFILT_USER,
            EvFlags::EV_ADD.union(EvFlags::EV_CLEAR),
            FilterFlag::empty(),
            0,
            0,
        ));
        queue.kevent(&changes, &mut [], None).context(KqueueSnafu)?;
        Ok(Self {
            queue: Arc::new(queue),
        })
    }

    /// Starts forwarding to `target`, with the escalation rule `rule`.
    ///
    /// # Errors
    /// [`SignalError::Thread`] if the thread cannot be started.
    pub fn start(self, target: Target, rule: Escalation) -> Result<Supervisor, SignalError> {
        let queue = Arc::clone(&self.queue);
        let handle = thread::Builder::new()
            .name("hb-signals".to_owned())
            .spawn(move || supervise(&queue, target, rule))
            .context(ThreadSnafu)?;
        Ok(Supervisor {
            queue: self.queue,
            handle,
        })
    }
}

/// The running thread. Call [`Supervisor::finish`] once the child has been waited for.
#[derive(Debug)]
pub struct Supervisor {
    queue: Arc<Kqueue>,
    handle: JoinHandle<()>,
}

impl Supervisor {
    /// Stops the thread and waits for it.
    pub fn finish(self) {
        let stop = KEvent::new(
            STOP_ID,
            EventFilter::EVFILT_USER,
            EvFlags::empty(),
            FilterFlag::NOTE_TRIGGER,
            0,
            0,
        );
        // If this fails the thread would wait forever, so do not join it then; it ends with the process.
        if self.queue.kevent(&[stop], &mut [], None).is_ok() {
            let _ = self.handle.join();
        }
    }
}

/// The thread body: wait for a signal or the escalation deadline, and act.
fn supervise(queue: &Kqueue, target: Target, mut rule: Escalation) {
    let blank = KEvent::new(
        0,
        EventFilter::EVFILT_USER,
        EvFlags::empty(),
        FilterFlag::empty(),
        0,
        0,
    );
    let mut events = [blank; 4];
    loop {
        let timeout = rule.deadline().map(|deadline| {
            TimeSpec::from_duration(deadline.saturating_duration_since(Instant::now()))
        });
        let ready = match queue.kevent(&[], &mut events, timeout.as_ref().map(|t| *t.as_ref())) {
            Ok(n) => n,
            Err(Errno::EINTR) => continue,
            Err(_) => return,
        };
        if ready == 0 {
            apply(rule.on_tick(Instant::now()), target);
            continue;
        }
        for event in &events[..ready] {
            match event.filter() {
                Ok(EventFilter::EVFILT_USER) => return,
                Ok(EventFilter::EVFILT_SIGNAL) => {
                    let Ok(signal) = i32::try_from(event.ident())
                        .map_err(|_| ())
                        .and_then(|n| Signal::try_from(n).map_err(|_| ()))
                    else {
                        continue;
                    };
                    // Several signals can arrive before the thread looks; two is enough to escalate.
                    for _ in 0..event.data().clamp(1, 2) {
                        apply(rule.on_signal(signal, Instant::now()), target);
                    }
                }
                _ => {}
            }
        }
    }
}

fn apply(step: Step, target: Target) {
    match step {
        Step::Ignore => {}
        Step::Forward(signal) => target.send(signal),
        Step::Kill => target.send(Signal::SIGKILL),
    }
}

/// What to do about one signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Nothing: the signal is not hb's to deal with, or the child is already being killed.
    Ignore,
    /// Pass this signal to the child.
    Forward(Signal),
    /// Send SIGKILL to the child.
    Kill,
}

/// The forward-then-kill rule (hb-ghd.2.3b decision 3).
///
/// The first signal is forwarded and starts a clock. A second signal, or the clock reaching
/// `grace`, kills the child. When the child shares hb's process group and stdin is a terminal
/// (`terminal_shared`), the terminal itself sends INT and HUP to the child, so hb takes no part:
/// it neither forwards them nor starts the clock, which would kill an agent that is handling
/// its own Ctrl-C.
#[derive(Debug, Clone)]
pub struct Escalation {
    grace: Duration,
    terminal_shared: bool,
    first: Option<Instant>,
    killed: bool,
}

impl Escalation {
    /// A rule with the given grace period.
    #[must_use]
    pub fn new(grace: Duration, terminal_shared: bool) -> Self {
        Self {
            grace,
            terminal_shared,
            first: None,
            killed: false,
        }
    }

    /// What to do about `signal`, received at `now`.
    pub fn on_signal(&mut self, signal: Signal, now: Instant) -> Step {
        if self.killed {
            return Step::Ignore;
        }
        if self.terminal_shared && matches!(signal, Signal::SIGINT | Signal::SIGHUP) {
            return Step::Ignore;
        }
        if self.first.is_none() {
            self.first = Some(now);
            return Step::Forward(signal);
        }
        self.killed = true;
        Step::Kill
    }

    /// What to do when nothing arrived by `now`: kill once the grace period has run out.
    pub fn on_tick(&mut self, now: Instant) -> Step {
        match self.deadline() {
            Some(deadline) if now >= deadline => {
                self.killed = true;
                Step::Kill
            }
            _ => Step::Ignore,
        }
    }

    /// When the child is to be killed if it has not exited by then.
    #[must_use]
    pub fn deadline(&self) -> Option<Instant> {
        if self.killed {
            return None;
        }
        self.first.map(|first| first + self.grace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_mask_helpers_block_check_and_unblock_in_this_thread_only() {
        // A fresh thread, so the test harness's own threads keep their masks.
        let ok = thread::spawn(|| {
            let before = supervised_blocked();
            block_supervised().is_ok()
                && !before
                && supervised_blocked()
                && unblock_supervised().is_ok()
                && !supervised_blocked()
        })
        .join();
        assert!(ok.unwrap_or(false));
    }

    #[test]
    fn a_partly_blocked_mask_does_not_count_as_blocked() {
        let ok = thread::spawn(|| {
            let mut one = SigSet::empty();
            one.add(Signal::SIGINT);
            let _ = one.thread_block();
            !supervised_blocked()
        })
        .join();
        assert!(ok.unwrap_or(false));
    }

    #[test]
    fn clear_mask_empties_the_blocked_set() {
        let ok = thread::spawn(|| {
            let _ = block_supervised();
            let blocked = supervised_blocked();
            let cleared = clear_mask().is_ok();
            blocked
                && cleared
                && SigSet::thread_get_mask().is_ok_and(|m| !m.contains(Signal::SIGTERM))
        })
        .join();
        assert!(ok.unwrap_or(false));
    }

    #[test]
    fn preparing_a_watch_needs_the_signals_blocked_first() {
        let outcome =
            thread::spawn(|| matches!(Watch::prepare(), Err(SignalError::NotBlocked))).join();
        assert!(outcome.unwrap_or(false));
    }

    #[test]
    fn a_prepared_watch_starts_and_finishes_without_any_signal() {
        let ok = thread::spawn(|| {
            let _ = block_supervised();
            let Ok(watch) = Watch::prepare() else {
                return false;
            };
            let rule = Escalation::new(Duration::from_secs(5), false);
            // Not a real child: the thread must end on the stop event alone.
            match watch.start(Target::Child(Pid::from_raw(i32::MAX)), rule) {
                Ok(supervisor) => {
                    supervisor.finish();
                    true
                }
                Err(_) => false,
            }
        })
        .join();
        assert!(ok.unwrap_or(false));
    }

    const GRACE: Duration = Duration::from_secs(5);

    fn rule(terminal_shared: bool) -> (Escalation, Instant) {
        (Escalation::new(GRACE, terminal_shared), Instant::now())
    }

    #[test]
    fn the_first_signal_is_forwarded_and_starts_the_clock() {
        let (mut rule, t0) = rule(false);
        assert_eq!(rule.deadline(), None);
        assert_eq!(
            rule.on_signal(Signal::SIGTERM, t0),
            Step::Forward(Signal::SIGTERM)
        );
        assert_eq!(rule.deadline(), Some(t0 + GRACE));
    }

    #[test]
    fn a_second_signal_of_any_kind_kills_at_once() {
        for second in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
            let (mut rule, t0) = rule(false);
            rule.on_signal(Signal::SIGTERM, t0);
            assert_eq!(
                rule.on_signal(second, t0 + Duration::from_millis(10)),
                Step::Kill
            );
        }
    }

    #[test]
    fn nothing_more_happens_after_the_kill() {
        let (mut rule, t0) = rule(false);
        rule.on_signal(Signal::SIGINT, t0);
        rule.on_signal(Signal::SIGINT, t0);
        assert_eq!(rule.on_signal(Signal::SIGTERM, t0), Step::Ignore);
        assert_eq!(rule.on_tick(t0 + GRACE * 2), Step::Ignore);
        assert_eq!(rule.deadline(), None);
    }

    #[test]
    fn the_clock_kills_exactly_at_the_grace_and_not_before() {
        let (mut rule, t0) = rule(false);
        rule.on_signal(Signal::SIGHUP, t0);
        assert_eq!(
            rule.on_tick(t0 + GRACE - Duration::from_millis(1)),
            Step::Ignore
        );
        assert_eq!(rule.on_tick(t0 + GRACE), Step::Kill);
        assert_eq!(rule.on_tick(t0 + GRACE + GRACE), Step::Ignore);
    }

    #[test]
    fn a_tick_with_no_signal_yet_does_nothing() {
        let (mut rule, t0) = rule(false);
        assert_eq!(rule.on_tick(t0 + GRACE * 10), Step::Ignore);
    }

    #[test]
    fn a_terminal_shared_child_leaves_int_and_hup_to_the_terminal() {
        let (mut rule, t0) = rule(true);
        for _ in 0..3 {
            assert_eq!(rule.on_signal(Signal::SIGINT, t0), Step::Ignore);
            assert_eq!(rule.on_signal(Signal::SIGHUP, t0), Step::Ignore);
        }
        assert_eq!(
            rule.deadline(),
            None,
            "no clock may start, or hb would kill a handled Ctrl-C"
        );
        assert_eq!(rule.on_tick(t0 + GRACE * 3), Step::Ignore);
    }

    #[test]
    fn a_terminal_shared_child_still_gets_term_forwarded_and_escalated() {
        let (mut rule, t0) = rule(true);
        rule.on_signal(Signal::SIGINT, t0);
        assert_eq!(
            rule.on_signal(Signal::SIGTERM, t0),
            Step::Forward(Signal::SIGTERM)
        );
        assert_eq!(rule.deadline(), Some(t0 + GRACE));
        assert_eq!(rule.on_signal(Signal::SIGTERM, t0), Step::Kill);
    }

    #[test]
    fn a_zero_grace_kills_on_the_first_tick() {
        let mut rule = Escalation::new(Duration::ZERO, false);
        let t0 = Instant::now();
        rule.on_signal(Signal::SIGTERM, t0);
        assert_eq!(rule.on_tick(t0), Step::Kill);
    }
}
