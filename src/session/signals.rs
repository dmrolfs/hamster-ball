// ABOUTME: Signal supervision for `hb run`: the escalation rule (pure) and, below it, the kqueue thread that applies it.
// ABOUTME: INT, TERM and HUP are blocked in hb and received through kqueue, then forwarded to the child (design 7.2, D53, D60).
//! Forwarding INT, TERM and HUP to the child, and escalating to SIGKILL.
//!
//! The rule lives in [`Escalation`], which takes the time as an argument so it can be tested
//! without signals or sleeping. The thread that applies it is [`Supervisor`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

/// The window-size signal. It is received through the same kqueue (a `sigwait` never sees it on
/// macOS) and tells `hb` to copy the new size to the child's pty.
pub const WINCH: Signal = Signal::SIGWINCH;

/// The signals `hb` blocks: the three it forwards, and the window-size one.
fn supervised_set() -> SigSet {
    let mut set = SigSet::empty();
    for signal in SUPERVISED {
        set.add(signal);
    }
    set.add(WINCH);
    set
}

/// Blocks INT, TERM, HUP and WINCH in the calling thread, and so in every thread it starts afterwards.
///
/// Call it first thing in the main thread, before any other thread exists.
///
/// # Errors
/// [`SignalError::Mask`] if the mask cannot be changed.
pub fn block_supervised() -> Result<(), SignalError> {
    supervised_set().thread_block().context(MaskSnafu)
}

/// Unblocks INT, TERM, HUP and WINCH in the calling thread, so their default action can run again.
///
/// # Errors
/// [`SignalError::Mask`] if the mask cannot be changed.
pub fn unblock_supervised() -> Result<(), SignalError> {
    supervised_set().thread_unblock().context(MaskSnafu)
}

/// Whether INT, TERM, HUP and WINCH are all blocked in the calling thread.
#[must_use]
pub fn supervised_blocked() -> bool {
    SigSet::thread_get_mask()
        .is_ok_and(|mask| SUPERVISED.iter().chain([&WINCH]).all(|s| mask.contains(*s)))
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
    pub(super) fn send(self, signal: Signal) {
        // ESRCH only means the child is already gone.
        let _ = match self {
            Self::Group(pgid) => killpg(pgid, signal),
            Self::Child(pid) => kill(pid, signal),
        };
    }
}

/// Notification that shutdown has begun. Must return promptly; may be called more than once.
#[derive(Clone)]
pub struct OnStopping(pub Arc<dyn Fn() + Send + Sync>);

impl std::fmt::Debug for OnStopping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnStopping(..)")
    }
}

impl OnStopping {
    pub(crate) fn notify(callback: Option<&Self>) {
        if let Some(callback) = callback {
            (callback.0)();
        }
    }
}

/// Signals registered before the child exists, so startup signals are queued rather than lost.
#[derive(Debug)]
pub struct Watch {
    queue: Arc<Kqueue>,
    on_stopping: Option<OnStopping>,
}

/// The identifier of the "stop" event.
const STOP_ID: usize = 0;
/// The identifier of the "the supervisor is gone or said stop" event.
const DISCONNECT_ID: usize = 1;

impl Watch {
    /// Registers INT, TERM and HUP (and WINCH when `window` is set) with a new kernel event queue.
    ///
    /// # Errors
    /// [`SignalError::NotBlocked`] unless they are blocked in this thread;
    /// [`SignalError::Kqueue`] if the queue cannot be set up.
    pub fn prepare(window: bool) -> Result<Self, SignalError> {
        ensure!(supervised_blocked(), NotBlockedSnafu);
        let queue = Kqueue::new().context(KqueueSnafu)?;
        let watched = SUPERVISED.iter().chain(window.then_some(&WINCH));
        let mut changes: Vec<KEvent> = watched
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
        changes.push(KEvent::new(
            DISCONNECT_ID,
            EventFilter::EVFILT_USER,
            EvFlags::EV_ADD.union(EvFlags::EV_CLEAR),
            FilterFlag::empty(),
            0,
            0,
        ));
        queue.kevent(&changes, &mut [], None).context(KqueueSnafu)?;
        Ok(Self {
            queue: Arc::new(queue),
            on_stopping: None,
        })
    }

    /// Installs a prompt notification before accepted shutdown actions.
    #[must_use]
    pub fn on_stopping(mut self, callback: Option<OnStopping>) -> Self {
        self.on_stopping = callback;
        self
    }

    /// A handle that makes the thread treat a stop as if SIGTERM had arrived.
    #[must_use]
    pub fn trigger(&self) -> Trigger {
        Trigger {
            queue: Arc::clone(&self.queue),
        }
    }

    /// Starts a thread that, until it is finished, turns INT, TERM, HUP and a [`Trigger`] into a
    /// flag, so work that runs before the child exists (the pre-run hooks) can be stopped.
    ///
    /// Events it reads are not seen by the thread [`Watch::start`] makes later, which is why a
    /// run that was stopped must not go on to start a child. Events that arrive after it ends
    /// stay queued for that thread.
    ///
    /// # Errors
    /// [`SignalError::Thread`] if the thread cannot be started.
    pub fn guard_setup(&self) -> Result<Setup, SignalError> {
        let queue = Arc::clone(&self.queue);
        let stopped = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stopped);
        let on_stopping = self.on_stopping.clone();
        let handle = thread::Builder::new()
            .name("hb-setup-signals".to_owned())
            .spawn(move || await_stop(&queue, &flag, on_stopping.as_ref()))
            .context(ThreadSnafu)?;
        Ok(Setup {
            queue: Arc::clone(&self.queue),
            stopped,
            handle: Some(handle),
        })
    }

    /// Starts forwarding to `target`, with the escalation rule `rule`. `on_winch` is called for each
    /// window-size signal (only if the watch was prepared for it).
    ///
    /// # Errors
    /// [`SignalError::Thread`] if the thread cannot be started.
    pub fn start(
        self,
        target: Target,
        rule: Escalation,
        on_winch: Option<Arc<dyn Fn() + Send + Sync>>,
    ) -> Result<Supervisor, SignalError> {
        let queue = Arc::clone(&self.queue);
        let on_stopping = self.on_stopping;
        let handle = thread::Builder::new()
            .name("hb-signals".to_owned())
            .spawn(move || {
                supervise(
                    &queue,
                    target,
                    rule,
                    on_winch.as_deref(),
                    on_stopping.as_ref(),
                )
            })
            .context(ThreadSnafu)?;
        Ok(Supervisor {
            queue: self.queue,
            handle,
        })
    }
}

/// Fires the "stop" event of a [`Watch`].
#[derive(Debug, Clone)]
pub struct Trigger {
    queue: Arc<Kqueue>,
}

impl Trigger {
    fn fire(&self) {
        let event = KEvent::new(
            DISCONNECT_ID,
            EventFilter::EVFILT_USER,
            EvFlags::empty(),
            FilterFlag::NOTE_TRIGGER,
            0,
            0,
        );
        // A failure leaves a watch that will not see the stop; there is nothing better to do.
        let _ = self.queue.kevent(&[event], &mut [], None);
    }
}

/// A stop that can be asked for before the run has a watch, and is not lost if it is.
///
/// The channel reader holds one and calls [`StopSignal::request`]; `run` attaches the watch's
/// trigger once it exists. Whichever comes second makes the stop happen.
#[derive(Debug, Default)]
pub struct StopSignal {
    requested: AtomicBool,
    trigger: Mutex<Option<Trigger>>,
}

impl StopSignal {
    /// A signal nobody has asked for yet.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Asks the run to stop as SIGTERM would. Can be called from any thread, any number of times.
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
        if let Ok(trigger) = self.trigger.lock()
            && let Some(trigger) = trigger.as_ref()
        {
            trigger.fire();
        }
    }

    /// Whether a stop has been asked for.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }

    /// Connects the watch. A stop asked for earlier fires now.
    pub fn attach(&self, trigger: Trigger) {
        if let Ok(mut slot) = self.trigger.lock() {
            *slot = Some(trigger.clone());
        }
        if self.is_requested() {
            trigger.fire();
        }
    }
}

/// The thread [`Watch::guard_setup`] starts. Dropping it stops the thread.
#[derive(Debug)]
pub struct Setup {
    queue: Arc<Kqueue>,
    stopped: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Setup {
    /// The flag the thread sets when a stop arrives, for [`run_pre_run`](super::hooks::run_pre_run).
    #[must_use]
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stopped)
    }

    /// Stops the thread and says whether a stop arrived while it ran.
    #[must_use]
    pub fn finish(mut self) -> bool {
        self.end();
        self.stopped.load(Ordering::SeqCst)
    }

    fn end(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        let stop = KEvent::new(
            STOP_ID,
            EventFilter::EVFILT_USER,
            EvFlags::empty(),
            FilterFlag::NOTE_TRIGGER,
            0,
            0,
        );
        // As in `Supervisor::finish`: do not join a thread that was not told to stop.
        if self.queue.kevent(&[stop], &mut [], None).is_ok() {
            let _ = handle.join();
        }
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.end();
    }
}

/// The setup thread's body: any signal or the disconnect event sets `stopped`.
fn await_stop(queue: &Kqueue, stopped: &AtomicBool, on_stopping: Option<&OnStopping>) {
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
        let ready = match queue.kevent(&[], &mut events, None) {
            Ok(n) => n,
            Err(Errno::EINTR) => continue,
            Err(_) => return,
        };
        let mut ended = false;
        for event in &events[..ready] {
            match (event.filter(), event.ident()) {
                (Ok(EventFilter::EVFILT_USER), STOP_ID) => ended = true,
                (Ok(EventFilter::EVFILT_USER), DISCONNECT_ID) => {
                    OnStopping::notify(on_stopping);
                    stopped.store(true, Ordering::SeqCst)
                }
                (Ok(EventFilter::EVFILT_SIGNAL), ident) if ident != WINCH as usize => {
                    OnStopping::notify(on_stopping);
                    stopped.store(true, Ordering::SeqCst);
                }
                _ => {}
            }
        }
        if ended {
            return;
        }
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
fn supervise(
    queue: &Kqueue,
    target: Target,
    mut rule: Escalation,
    on_winch: Option<&(dyn Fn() + Send + Sync)>,
    on_stopping: Option<&OnStopping>,
) {
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
            apply(rule.on_tick(Instant::now()), target, on_stopping);
            continue;
        }
        for event in &events[..ready] {
            match event.filter() {
                Ok(EventFilter::EVFILT_USER) if event.ident() == DISCONNECT_ID => {
                    apply(
                        rule.on_signal(Signal::SIGTERM, Instant::now()),
                        target,
                        on_stopping,
                    );
                }
                Ok(EventFilter::EVFILT_USER) => return,
                Ok(EventFilter::EVFILT_SIGNAL) => {
                    let Ok(signal) = i32::try_from(event.ident())
                        .map_err(|_| ())
                        .and_then(|n| Signal::try_from(n).map_err(|_| ()))
                    else {
                        continue;
                    };
                    if signal == WINCH {
                        if let Some(callback) = on_winch {
                            callback();
                        }
                        continue;
                    }
                    // Several signals can arrive before the thread looks; two is enough to escalate.
                    for _ in 0..event.data().clamp(1, 2) {
                        apply(rule.on_signal(signal, Instant::now()), target, on_stopping);
                    }
                }
                _ => {}
            }
        }
    }
}

fn apply(step: Step, target: Target, on_stopping: Option<&OnStopping>) {
    if step != Step::Ignore {
        OnStopping::notify(on_stopping);
    }
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
    use claims::assert_ok;
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
            thread::spawn(|| matches!(Watch::prepare(false), Err(SignalError::NotBlocked))).join();
        assert!(outcome.unwrap_or(false));
    }

    /// Runs `body` in a fresh thread with the supervised signals blocked, as `hb` has them.
    fn blocked<T: Send + 'static>(body: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        thread::spawn(move || {
            let _ = block_supervised();
            body()
        })
        .join()
        .ok()
    }

    #[test]
    fn setup_notifies_before_publishing_cancellation() {
        let got = blocked(|| {
            let notified = Arc::new(AtomicBool::new(false));
            let called = Arc::clone(&notified);
            let watch = Watch::prepare(false)
                .ok()?
                .on_stopping(Some(OnStopping(Arc::new(move || {
                    called.store(true, Ordering::SeqCst);
                }))));
            let setup = watch.guard_setup().ok()?;
            let flag = setup.flag();
            watch.trigger().fire();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
                thread::yield_now();
            }
            let observed = flag.load(Ordering::SeqCst) && notified.load(Ordering::SeqCst);
            Some(observed && setup.finish())
        });
        assert_eq!(got, Some(Some(true)));
    }

    #[test]
    fn ignored_shared_terminal_signals_do_not_notify_or_signal_the_child() {
        use claims::assert_ok;
        use std::sync::atomic::AtomicUsize;
        let count = Arc::new(AtomicUsize::new(0));
        let called = Arc::clone(&count);
        let callback = OnStopping(Arc::new(move || {
            called.fetch_add(1, Ordering::SeqCst);
        }));
        let mut child = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let target = Target::Child(Pid::from_raw(child.id() as i32));
        let (mut rule, now) = rule(true);
        for signal in [Signal::SIGINT, Signal::SIGHUP] {
            apply(rule.on_signal(signal, now), target, Some(&callback));
        }
        assert_eq!(count.load(Ordering::SeqCst), 0);
        let alive = assert_ok!(child.try_wait()).is_none();
        apply(
            rule.on_signal(Signal::SIGTERM, now),
            target,
            Some(&callback),
        );
        let _ = child.kill();
        assert_ok!(child.wait());
        assert!(alive);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn the_setup_thread_sets_its_flag_for_a_stop_request_and_ends_cleanly() {
        let got = blocked(|| {
            let watch = Watch::prepare(false).ok()?;
            let stop = StopSignal::new();
            stop.attach(watch.trigger());
            let setup = watch.guard_setup().ok()?;
            let flag = setup.flag();
            let before = flag.load(Ordering::SeqCst);
            stop.request();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            Some((before, setup.finish()))
        });
        assert_eq!(got, Some(Some((false, true))));
    }

    #[test]
    fn a_stop_asked_for_before_the_watch_exists_fires_when_it_is_attached() {
        let got = blocked(|| {
            let stop = StopSignal::new();
            stop.request();
            let watch = Watch::prepare(false).ok()?;
            let setup = watch.guard_setup().ok()?;
            stop.attach(watch.trigger());
            let flag = setup.flag();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !flag.load(Ordering::SeqCst) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            Some(setup.finish())
        });
        assert_eq!(got, Some(Some(true)));
    }

    #[test]
    fn a_setup_thread_that_saw_nothing_reports_no_stop_and_a_dropped_one_ends() {
        let got = blocked(|| {
            let watch = Watch::prepare(false).ok()?;
            let setup = watch.guard_setup().ok()?;
            let quiet = setup.finish();
            let again = watch.guard_setup().ok()?;
            drop(again);
            Some(quiet)
        });
        assert_eq!(got, Some(Some(false)));
    }

    #[test]
    fn a_stop_request_after_the_setup_thread_ended_is_left_for_the_watch_thread() {
        // A live child, started from an unblocked thread so it can receive SIGTERM.
        let mut child = assert_ok!(std::process::Command::new("/bin/sleep").arg("30").spawn());
        let pid = Pid::from_raw(i32::try_from(child.id()).unwrap_or(0));
        let got = blocked(move || {
            let watch = Watch::prepare(false).ok()?;
            let stop = StopSignal::new();
            stop.attach(watch.trigger());
            let setup = watch.guard_setup().ok()?;
            let _ = setup.finish();
            let rule = Escalation::new(Duration::from_secs(10), false);
            let supervisor = watch.start(Target::Child(pid), rule, None).ok()?;
            stop.request();
            thread::sleep(Duration::from_millis(500));
            supervisor.finish();
            Some(())
        });
        let status = assert_ok!(child.wait());
        let got = got.map(|_| std::os::unix::process::ExitStatusExt::signal(&status));
        assert_eq!(got, Some(Some(15)));
    }

    #[test]
    fn a_prepared_watch_starts_and_finishes_without_any_signal() {
        let ok = thread::spawn(|| {
            let _ = block_supervised();
            let Ok(watch) = Watch::prepare(false) else {
                return false;
            };
            let rule = Escalation::new(Duration::from_secs(5), false);
            // Not a real child: the thread must end on the stop event alone.
            match watch.start(Target::Child(Pid::from_raw(i32::MAX)), rule, None) {
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

    #[test]
    fn a_window_size_signal_is_reported_to_the_callback_and_nothing_else_is_forwarded() {
        let ok = thread::spawn(|| {
            let _ = block_supervised();
            let Ok(watch) = Watch::prepare(true) else {
                return false;
            };
            let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let seen = Arc::clone(&count);
            let on_winch: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
                seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
            let rule = Escalation::new(Duration::from_secs(5), false);
            let Ok(supervisor) =
                watch.start(Target::Child(Pid::from_raw(i32::MAX)), rule, Some(on_winch))
            else {
                return false;
            };
            let _ = kill(nix::unistd::getpid(), Signal::SIGWINCH);
            let deadline = Instant::now() + Duration::from_secs(5);
            while count.load(std::sync::atomic::Ordering::Relaxed) == 0 && Instant::now() < deadline
            {
                thread::sleep(Duration::from_millis(10));
            }
            supervisor.finish();
            count.load(std::sync::atomic::Ordering::Relaxed) >= 1
        })
        .join();
        assert!(ok.unwrap_or(false));
    }

    #[test]
    fn without_the_window_option_the_watch_does_not_need_it_blocked_or_registered() {
        let ok = thread::spawn(|| {
            let _ = block_supervised();
            Watch::prepare(false).is_ok()
        })
        .join();
        assert!(ok.unwrap_or(false));
    }

    #[test]
    fn the_window_signal_counts_as_part_of_the_blocked_set() {
        let ok = thread::spawn(|| {
            let mut three = SigSet::empty();
            for signal in SUPERVISED {
                three.add(signal);
            }
            let _ = three.thread_block();
            let without_winch = supervised_blocked();
            let _ = block_supervised();
            !without_winch && supervised_blocked()
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
