// ABOUTME: Relay: one thread that copies the user's input to the pty master and the master's output to the user's terminal.
// ABOUTME: It polls with a short timeout, so it can be stopped when the child ends, and then drains what the child last wrote.
//! The byte relay between the user's terminal and the child's pty (design 7.3).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use super::fence::{open_for_nonblocking_write, write_until};
use super::sanitize::{ClipboardPolicy, ClipboardUse, Sanitizer};

/// How often the thread looks at the stop flag when nothing arrives.
pub(super) const TICK_MS: u8 = 50;
/// After the child has ended, how long the master may stay silent before the relay stops.
pub(super) const DRAIN_QUIET: Duration = Duration::from_millis(150);
/// The most time spent draining.
pub(super) const DRAIN_MAX: Duration = Duration::from_secs(2);
pub(super) const BUFFER: usize = 8192;

/// How long a relay keeps draining after the child has ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Drain {
    /// How long the master may stay silent before the relay stops.
    pub(super) quiet: Duration,
    /// The most time spent draining.
    pub(super) max: Duration,
}

impl Default for Drain {
    fn default() -> Self {
        Self {
            quiet: DRAIN_QUIET,
            max: DRAIN_MAX,
        }
    }
}

/// Where the relay thread is with respect to a pause request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Gate {
    Open,
    /// Asked to stop touching the terminal; the thread has not yet said it has.
    Closing,
    /// The thread is idle and holds no read or write in progress.
    Closed,
}

/// What the relay thread and its owner share.
#[derive(Debug)]
struct Shared {
    stop: AtomicBool,
    /// A stop has begun (a signal, or the supervisor going away): output the terminal will not take
    /// is dropped from here on, so the child's pty keeps draining and the child can exit.
    hurry: AtomicBool,
    gate: Mutex<Gate>,
    changed: Condvar,
}

impl Shared {
    fn gate(&self) -> MutexGuard<'_, Gate> {
        self.gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A running relay. Call [`Relay::finish`] after the child has ended.
#[derive(Debug)]
pub struct Relay {
    shared: Arc<Shared>,
    handle: JoinHandle<ClipboardUse>,
}

impl Relay {
    /// Starts relaying `input` (the user's keystrokes) to `master` and `master` to `output`.
    ///
    /// # Errors
    /// [`io::Error`] if the thread cannot be started.
    pub fn start(input: OwnedFd, master: File, output: OwnedFd) -> io::Result<Self> {
        Self::start_with(input, master, output, ClipboardPolicy::default())
    }

    /// Like [`Relay::start`], with a policy for the agent's clipboard writes.
    ///
    /// # Errors
    /// [`io::Error`] if the thread cannot be started.
    pub fn start_with(
        input: OwnedFd,
        master: File,
        output: OwnedFd,
        clipboard: ClipboardPolicy,
    ) -> io::Result<Self> {
        Self::spawn(input, master, output, clipboard, Drain::default())
    }

    fn spawn(
        input: OwnedFd,
        master: File,
        output: OwnedFd,
        clipboard: ClipboardPolicy,
        drain: Drain,
    ) -> io::Result<Self> {
        let flags = rustix::fs::fcntl_getfl(&master).map_err(io::Error::from)?;
        rustix::fs::fcntl_setfl(&master, flags | rustix::fs::OFlags::NONBLOCK)
            .map_err(io::Error::from)?;
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            hurry: AtomicBool::new(false),
            gate: Mutex::new(Gate::Open),
            changed: Condvar::new(),
        });
        let theirs = Arc::clone(&shared);
        // Started here, so a failure to start it is the relay's failure, not a quieter relay.
        let mut sink = Sink::new(&output, Arc::clone(&shared))?;
        let handle = thread::Builder::new()
            .name("hb-relay".to_owned())
            .spawn(move || {
                let mut filter = Sanitizer::with_clipboard(clipboard);
                run(
                    File::from(input),
                    master,
                    &mut sink,
                    &theirs,
                    &mut filter,
                    drain,
                );
                filter.clipboard_use()
            })?;
        Ok(Self { shared, handle })
    }

    /// What to call when a stop begins, before the child has ended: output the terminal does not
    /// take is dropped from then on instead of holding the relay (and so the child) back.
    pub fn stopping_hook(&self) -> Arc<dyn Fn() + Send + Sync> {
        Self::stopping_hook_for(&self.shared)
    }

    fn stopping_hook_for(shared: &Arc<Shared>) -> Arc<dyn Fn() + Send + Sync> {
        let shared = Arc::clone(shared);
        Arc::new(move || shared.hurry.store(true, Ordering::Relaxed))
    }

    /// Stops the relay touching the terminal and returns once it no longer is.
    ///
    /// Needed before the terminal's input queue is flushed. A read the relay had decided to
    /// make would otherwise block for good when the flush discarded its bytes.
    pub fn pause(&self) {
        let mut gate = self.shared.gate();
        *gate = Gate::Closing;
        while *gate == Gate::Closing && !self.handle.is_finished() {
            gate = self
                .shared
                .changed
                .wait_timeout(gate, Duration::from_millis(u64::from(TICK_MS)))
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .0;
        }
    }

    /// Lets a paused relay carry on.
    pub fn resume(&self) {
        *self.shared.gate() = Gate::Open;
        self.shared.changed.notify_all();
    }

    /// Tells the relay the child has ended, lets it drain the last output, and waits for it.
    ///
    /// Returns what the agent did with the clipboard: writes let through, and writes removed.
    pub fn finish(self) -> ClipboardUse {
        self.shared.stop.store(true, Ordering::Relaxed);
        *self.shared.gate() = Gate::Open;
        self.shared.changed.notify_all();
        self.handle.join().unwrap_or_default()
    }
}

/// How long the terminal may take no output at all, once a stop has begun, before the relay stops
/// waiting for it and drops what it still holds.
const STALL: Duration = Duration::from_secs(2);

/// The user's terminal, written by the relay thread itself without ever blocking.
///
/// A write to a terminal that nobody reads blocks for good, and the relay cannot be the one that
/// blocks: while it is stuck it reads nothing from the child's pty, the child cannot finish
/// closing a pty that is full, and `hb` waits for that child. A supervisor that stops draining its
/// terminal would then keep a session alive after its channel closed (hb-807 review A, HIGH 3).
///
/// The output is a second, non-blocking open of the same terminal, so a full terminal returns
/// "would block" and the relay can look at the stop flag. A write never leaves the relay thread:
/// when `finish` returns, everything the relay was going to write has been written, or has been
/// given up on, so what runs next (the exit fence, the settings restore) cannot be interleaved with
/// it. Output is never dropped because a queue is full or because a stop began: only when the
/// terminal has taken no byte at all for [`STALL`] after a stop (a terminal that is slow but
/// reading keeps resetting that clock).
struct Sink {
    terminal: Option<File>,
    shared: Arc<Shared>,
    /// What has not been written yet.
    pending: Vec<u8>,
}

impl Sink {
    fn new(terminal: &OwnedFd, shared: Arc<Shared>) -> io::Result<Self> {
        Ok(Self {
            terminal: Some(open_for_nonblocking_write(terminal)?),
            shared,
            pending: Vec::new(),
        })
    }

    /// Writes `pending`, waiting for room. Gives up only on a terminal that has taken nothing for
    /// [`STALL`] while a stop is under way, and then abandons the rest.
    fn drain(&mut self) {
        let Some(terminal) = self.terminal.as_mut() else {
            self.pending.clear();
            return;
        };
        let mut idle_since: Option<Instant> = None;
        while !self.pending.is_empty() {
            // No write is in flight here. Pause keeps the suffix for resume, not a second writer.
            hold_while_paused(&self.shared);
            let stopping = self.shared.hurry.load(Ordering::Relaxed)
                || self.shared.stop.load(Ordering::Relaxed);
            // One short wait for room at a time, so the stop flag is looked at between them.
            let wait = Instant::now() + Duration::from_millis(u64::from(TICK_MS));
            let wrote = write_until(terminal, &self.pending, wait);
            if wrote > 0 {
                self.pending.drain(..wrote);
                idle_since = None;
                continue;
            }
            if !stopping {
                // Not stopping: this is back-pressure from a slow terminal, as it always was.
                idle_since = None;
                continue;
            }
            let since = *idle_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= STALL {
                self.pending.clear();
                self.terminal = None;
                return;
            }
        }
    }
}

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(bytes);
        self.drain();
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.drain();
        Ok(())
    }
}

/// Copies one chunk from `from` to `to`, through `filter` if there is one. `false` means `from`
/// has ended or failed.
fn copy_chunk(from: &mut File, to: &mut impl Write, filter: Option<&mut Sanitizer>) -> bool {
    let mut buffer = [0u8; BUFFER];
    match from.read(&mut buffer) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) =>
        {
            true
        }
        Ok(0) | Err(_) => false,
        Ok(n) => {
            // The other side may be gone (the child ended); nothing useful to do about that here.
            match filter {
                Some(filter) => {
                    let mut clean = Vec::with_capacity(n);
                    filter.feed(&buffer[..n], &mut clean);
                    let _ = to.write_all(&clean);
                }
                None => {
                    let _ = to.write_all(&buffer[..n]);
                }
            }
            let _ = to.flush();
            true
        }
    }
}

/// Tells the terminal the agent's output is over: a sequence the agent left open is cancelled.
pub(super) fn end_of_output(filter: &mut Sanitizer, output: &mut impl Write) {
    let mut tail = Vec::new();
    filter.finish(&mut tail);
    if !tail.is_empty() {
        let _ = output.write_all(&tail);
        let _ = output.flush();
    }
}

/// Idles while the owner has the terminal. Returns when the relay may carry on.
fn hold_while_paused(shared: &Shared) {
    let mut gate = shared.gate();
    if *gate != Gate::Open {
        *gate = Gate::Closed;
        shared.changed.notify_all();
    }
    while *gate == Gate::Closed {
        gate = shared
            .changed
            .wait(gate)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
}

fn run(
    mut input: File,
    mut master: File,
    output: &mut Sink,
    shared: &Shared,
    filter: &mut Sanitizer,
    drain: Drain,
) {
    let mut input_open = true;
    let mut pending_input = Vec::new();
    let mut draining_since: Option<Instant> = None;
    let mut quiet_since = Instant::now();
    loop {
        hold_while_paused(shared);
        let stopping = shared.stop.load(Ordering::Relaxed);
        if stopping || shared.hurry.load(Ordering::Relaxed) {
            pending_input.clear();
            input_open = false;
        }
        if !pending_input.is_empty() {
            match master.write(&pending_input) {
                Ok(n) => {
                    pending_input.drain(..n);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => {
                    pending_input.clear();
                    input_open = false;
                }
            }
        }
        if stopping && draining_since.is_none() {
            draining_since = Some(Instant::now());
        }
        let (master_ready, input_ready) = {
            let mut fds = vec![PollFd::new(master.as_fd(), PollFlags::POLLIN)];
            if input_open && pending_input.is_empty() && !stopping {
                fds.push(PollFd::new(input.as_fd(), PollFlags::POLLIN));
            }
            if poll(&mut fds, PollTimeout::from(TICK_MS)).is_err() {
                continue;
            }
            let ready = |fd: &PollFd<'_>| {
                fd.revents().is_some_and(|r| {
                    r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
                })
            };
            (ready(&fds[0]), fds.get(1).is_some_and(ready))
        };
        if master_ready {
            let delivery_started = Instant::now();
            let open = copy_chunk(&mut master, output, Some(filter));
            // Source admission is bounded independently of time spent delivering accepted bytes.
            if let Some(since) = &mut draining_since {
                *since += delivery_started.elapsed();
            }
            quiet_since = Instant::now();
            if !open {
                end_of_output(filter, output);
                return;
            }
        }
        if input_ready {
            // Output delivery may have acknowledged a pause and allowed input to be flushed.
            // No pause can be acknowledged between this fresh poll and the following read.
            let mut ready = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
            if poll(&mut ready, PollTimeout::ZERO).unwrap_or(0) == 0 {
                continue;
            }
            let mut bytes = [0; BUFFER];
            match input.read(&mut bytes) {
                Ok(0) => input_open = false,
                Ok(n) => pending_input.extend_from_slice(&bytes[..n]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => input_open = false,
            }
        }
        if let Some(since) = draining_since
            && (!master_ready && quiet_since.elapsed() >= drain.quiet
                || since.elapsed() >= drain.max)
        {
            end_of_output(filter, output);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::pty::Pty;
    use crate::session::terminal::RawMode;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::fs::OpenOptions;

    /// The user's terminal (outer) and the child's (inner), both as ptys, in raw mode so nothing
    /// is echoed or translated.
    struct Rig {
        user: File,  // what the user types into, and reads the screen from
        child: File, // what the child reads and writes
        relay: Relay,
        _outer: Pty,
        _inner: Pty,
    }

    fn open_slave(pty: &Pty) -> File {
        assert_ok!(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(pty.slave_path().as_str())
        )
    }

    #[test]
    fn pause_acknowledges_backpressure_and_resume_keeps_the_pending_suffix() {
        let rig = rig();
        let Rig {
            mut user,
            mut child,
            relay,
            _outer,
            _inner,
        } = rig;
        let payload = vec![b'x'; 60_000];
        let expected = payload.clone();
        let producer = std::thread::spawn(move || {
            let flags = assert_ok!(rustix::fs::fcntl_getfl(&child));
            assert_ok!(rustix::fs::fcntl_setfl(
                &child,
                flags | rustix::fs::OFlags::NONBLOCK
            ));
            let until = Instant::now() + Duration::from_secs(5);
            let mut sent = 0;
            while sent < payload.len() && Instant::now() < until {
                match child.write(&payload[sent..]) {
                    Ok(n) => sent += n,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
            child
        });
        std::thread::sleep(Duration::from_millis(100));
        let shared = Arc::clone(&relay.shared);
        let pausing = std::thread::spawn(move || {
            relay.pause();
            relay
        });
        let until = Instant::now() + Duration::from_secs(2);
        while !pausing.is_finished() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        let acknowledged = pausing.is_finished();
        // Unblock only this fixture on failure, so the regression reports instead of hanging.
        shared.hurry.store(true, Ordering::Relaxed);
        if !acknowledged {
            *shared.gate() = Gate::Open;
            shared.changed.notify_all();
        }
        let relay = assert_ok!(pausing.join());
        relay.resume();
        let mut got = Vec::new();
        let until = Instant::now() + Duration::from_secs(5);
        while got.len() < expected.len() && Instant::now() < until {
            let mut fds = [PollFd::new(user.as_fd(), PollFlags::POLLIN)];
            if assert_ok!(poll(&mut fds, PollTimeout::from(50u8))) > 0 {
                let mut bytes = [0; 4096];
                let n = assert_ok!(user.read(&mut bytes));
                got.extend_from_slice(&bytes[..n]);
            }
        }
        let child = assert_ok!(producer.join());
        relay.finish();
        drop(child);
        assert!(acknowledged, "pause waited behind terminal backpressure");
        assert_eq!(got, expected);
    }

    #[test]
    fn slow_final_delivery_does_not_consume_the_source_drain_budget() {
        let rig = rig_draining(Drain {
            quiet: Duration::from_millis(30),
            max: Duration::from_millis(80),
        });
        let Rig {
            mut user,
            mut child,
            relay,
            _outer,
            _inner,
        } = rig;
        let expected = vec![b'x'; 60_000];
        let payload = expected.clone();
        let producer = std::thread::spawn(move || {
            let flags = assert_ok!(rustix::fs::fcntl_getfl(&child));
            assert_ok!(rustix::fs::fcntl_setfl(
                &child,
                flags | rustix::fs::OFlags::NONBLOCK
            ));
            let until = Instant::now() + Duration::from_secs(3);
            let mut sent = 0;
            while sent < payload.len() && Instant::now() < until {
                match child.write(&payload[sent..]) {
                    Ok(n) => sent += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5))
                    }
                    Err(_) => break,
                }
            }
            child
        });
        std::thread::sleep(Duration::from_millis(100));
        let finishing = std::thread::spawn(move || relay.finish());
        let until = Instant::now() + Duration::from_secs(8);
        let mut got = Vec::new();
        while got.len() < expected.len() && Instant::now() < until {
            let mut fds = [PollFd::new(user.as_fd(), PollFlags::POLLIN)];
            if assert_ok!(poll(&mut fds, PollTimeout::from(50u8))) > 0 {
                let mut bytes = [0; 512];
                let n = assert_ok!(user.read(&mut bytes));
                got.extend_from_slice(&bytes[..n]);
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        // Keep the slave alive, so success cannot depend on EOF bypassing the drain path.
        let child = assert_ok!(producer.join());
        assert_ok!(finishing.join());
        drop(child);
        assert_eq!(got, expected);
    }

    #[test]
    fn unread_child_input_cannot_block_pause_or_finish() {
        let rig = rig();
        let flags = assert_ok!(rustix::fs::fcntl_getfl(&rig.user));
        assert_ok!(rustix::fs::fcntl_setfl(
            &rig.user,
            flags | rustix::fs::OFlags::NONBLOCK
        ));
        let mut user = rig.user;
        let until = Instant::now() + Duration::from_millis(300);
        while Instant::now() < until {
            let _ = user.write(&[b'x'; 4096]);
            std::thread::sleep(Duration::from_millis(1));
        }
        let shared = Arc::clone(&rig.relay.shared);
        let thread = std::thread::spawn(move || {
            rig.relay.pause();
            rig.relay.resume();
            rig.relay.finish()
        });
        let until = Instant::now() + Duration::from_secs(2);
        while !thread.is_finished() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(10));
        }
        let finished = thread.is_finished();
        // A broken blocking writer is released by draining this fixture's slave only.
        shared.stop.store(true, Ordering::Relaxed);
        *shared.gate() = Gate::Open;
        shared.changed.notify_all();
        let mut child = rig.child;
        let flags = assert_ok!(rustix::fs::fcntl_getfl(&child));
        assert_ok!(rustix::fs::fcntl_setfl(
            &child,
            flags | rustix::fs::OFlags::NONBLOCK
        ));
        let until = Instant::now() + Duration::from_secs(3);
        while !thread.is_finished() && Instant::now() < until {
            let _ = child.read(&mut [0; 4096]);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            thread.is_finished(),
            "relay did not end after fixture drain"
        );
        assert_ok!(thread.join());
        assert!(finished, "input write blocked pause/finish");
    }

    fn rig() -> Rig {
        rig_draining(Drain::default())
    }

    fn rig_draining(drain: Drain) -> Rig {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let outer_slave = open_slave(&outer);
        let inner_slave = open_slave(&inner);
        // Left raw on purpose. Restoring a pty's mode waits for its unread output, so a test that
        // failed with bytes in flight would hang in its destructor instead of reporting.
        for slave in [&outer_slave, &inner_slave] {
            std::mem::forget(assert_ok!(RawMode::enter(
                assert_ok!(slave.try_clone()).into()
            )));
        }
        let relay = assert_ok!(Relay::spawn(
            assert_ok!(outer_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
            outer_slave.into(),
            ClipboardPolicy::default(),
            drain,
        ));
        Rig {
            user: assert_ok!(outer.clone_master()),
            child: inner_slave,
            relay,
            _outer: outer,
            _inner: inner,
        }
    }

    fn read_some(file: &mut File, want: &[u8]) -> Vec<u8> {
        let mut seen = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut buffer = [0u8; 256];
        while !seen.windows(want.len()).any(|w| w == want) && Instant::now() < deadline {
            let mut fds = [PollFd::new(file.as_fd(), PollFlags::POLLIN)];
            if assert_ok!(poll(&mut fds, PollTimeout::from(100u8))) > 0 {
                let n = assert_ok!(file.read(&mut buffer));
                seen.extend_from_slice(&buffer[..n]);
            }
        }
        seen
    }

    #[test]
    fn what_the_user_types_reaches_the_child_byte_for_byte_including_control_keys() {
        let mut rig = rig();
        assert_ok!(rig.user.write_all(b"ab\x03\x1ac\x1b[A"));
        let got = read_some(&mut rig.child, b"\x1b[A");
        assert_eq!(got, b"ab\x03\x1ac\x1b[A");
        rig.relay.finish();
    }

    #[test]
    fn input_typed_in_separate_bursts_keeps_reaching_the_child() {
        let mut rig = rig();
        assert_ok!(rig.user.write_all(b"first"));
        assert_eq!(read_some(&mut rig.child, b"first"), b"first");
        assert_ok!(rig.user.write_all(b"second"));
        assert_eq!(read_some(&mut rig.child, b"second"), b"second");
        rig.relay.finish();
    }

    #[test]
    fn what_the_child_writes_reaches_the_users_screen() {
        let mut rig = rig();
        assert_ok!(rig.child.write_all(b"hello \x1b[31mred\x1b[0m\n"));
        let got = read_some(&mut rig.user, b"red");
        assert!(got.windows(4).any(|w| w == b"hell"), "{got:?}");
        assert!(
            got.windows(5).any(|w| w == b"\x1b[31m"),
            "escape sequences must pass untouched: {got:?}"
        );
        rig.relay.finish();
    }

    #[test]
    fn a_query_whose_reply_the_agent_could_shape_never_reaches_the_screen() {
        let mut rig = rig();
        assert_ok!(rig.child.write_all(b"a\x1b[21tb\x1b]52;c;?\x07c\xc2\x9bd"));
        let got = read_some(&mut rig.user, b"cd");
        assert_eq!(got, b"abcd");
        rig.relay.finish();
    }

    #[test]
    fn finishing_reports_how_many_clipboard_writes_went_through() {
        let mut rig = rig();
        assert_ok!(
            rig.child
                .write_all(b"\x1b]52;c;aGk=\x07mid\x1b]52;c;?\x07\x1b]52;p;aGk=\x07end")
        );
        assert!(!read_some(&mut rig.user, b"end").is_empty());
        assert_eq!(
            rig.relay.finish().allowed,
            2,
            "two writes, and a read that was removed"
        );
    }

    #[test]
    fn with_clipboard_writes_denied_none_reaches_the_screen_and_finish_counts_them_as_blocked() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let outer_slave = open_slave(&outer);
        let mut child = open_slave(&inner);
        std::mem::forget(assert_ok!(RawMode::enter(
            assert_ok!(outer_slave.try_clone()).into()
        )));
        std::mem::forget(assert_ok!(RawMode::enter(
            assert_ok!(child.try_clone()).into()
        )));
        let relay = assert_ok!(Relay::start_with(
            assert_ok!(outer_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
            outer_slave.into(),
            ClipboardPolicy::Deny,
        ));
        let mut user = assert_ok!(outer.clone_master());
        assert_ok!(child.write_all(b"a\x1b]52;c;aGk=\x07b\x1b]52;p;aGk=\x07end"));
        assert_eq!(read_some(&mut user, b"end"), b"abend");
        assert_eq!(
            relay.finish(),
            ClipboardUse {
                allowed: 0,
                blocked: 2
            }
        );
    }

    #[test]
    fn a_sequence_split_between_two_reads_is_filtered_all_the_same() {
        let mut rig = rig();
        assert_ok!(rig.child.write_all(b"x\x1b[2"));
        thread::sleep(Duration::from_millis(120));
        assert_ok!(rig.child.write_all(b"1ty"));
        assert_eq!(read_some(&mut rig.user, b"xy"), b"xy");
        rig.relay.finish();
    }

    #[test]
    fn the_end_of_the_run_cancels_a_sequence_the_agent_left_open() {
        let mut rig = rig();
        assert_ok!(rig.child.write_all(b"\x1b]0;a title with no end"));
        thread::sleep(Duration::from_millis(120));
        rig.relay.finish();
        let got = read_some(&mut rig.user, b"\x18");
        assert!(
            got.ends_with(b"\x18"),
            "no cancel after an open title: {got:?}"
        );
    }

    #[test]
    fn the_last_output_before_the_child_ends_is_drained_not_lost() {
        let mut rig = rig();
        assert_ok!(rig.child.write_all(b"final words"));
        drop(rig.child);
        rig.relay.finish();
        let got = read_some(&mut rig.user, b"final words");
        assert_eq!(got, b"final words");
    }

    #[test]
    fn finishing_with_nothing_happening_returns_promptly() {
        let rig = rig();
        let started = Instant::now();
        rig.relay.finish();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_closed_input_does_not_stop_the_childs_output_from_being_relayed() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let outer_slave = open_slave(&outer);
        let mut child = open_slave(&inner);
        let _raw = assert_ok!(RawMode::enter(assert_ok!(outer_slave.try_clone()).into()));
        let _raw_child = assert_ok!(RawMode::enter(assert_ok!(child.try_clone()).into()));
        let no_input = OwnedFd::from(assert_ok!(File::open("/dev/null")));
        let relay = assert_ok!(Relay::start(
            no_input,
            assert_ok!(inner.clone_master()),
            outer_slave.into(),
        ));
        let mut user = assert_ok!(outer.clone_master());
        assert_ok!(child.write_all(b"still here"));
        assert_eq!(read_some(&mut user, b"still here"), b"still here");
        relay.finish();
    }

    /// Lets the relay thread get into its poll, so a pause finds it mid-wait and not still starting.
    fn settle() {
        thread::sleep(Duration::from_millis(150));
    }

    fn nothing_arrives_within(file: &mut File, wait: Duration) -> bool {
        let mut fds = [PollFd::new(file.as_fd(), PollFlags::POLLIN)];
        let millis = u16::try_from(wait.as_millis()).unwrap_or(u16::MAX);
        assert_ok!(poll(&mut fds, PollTimeout::from(millis))) == 0
    }

    #[test]
    fn a_paused_relay_leaves_the_users_input_unread_until_it_resumes() {
        let mut rig = rig();
        settle();
        rig.relay.pause();
        assert_ok!(rig.user.write_all(b"typed while paused"));
        assert!(
            nothing_arrives_within(&mut rig.child, Duration::from_millis(300)),
            "input must not be copied while the relay is paused"
        );
        rig.relay.resume();
        assert_eq!(read_some(&mut rig.child, b"paused"), b"typed while paused");
        rig.relay.finish();
    }

    #[test]
    fn a_paused_relay_holds_the_childs_output_until_it_resumes() {
        let mut rig = rig();
        settle();
        rig.relay.pause();
        assert_ok!(rig.child.write_all(b"printed while paused"));
        assert!(
            nothing_arrives_within(&mut rig.user, Duration::from_millis(300)),
            "output must not reach the screen while the relay is paused"
        );
        rig.relay.resume();
        assert_eq!(read_some(&mut rig.user, b"paused"), b"printed while paused");
        rig.relay.finish();
    }

    #[test]
    fn the_relay_keeps_working_after_the_input_queue_is_flushed_during_a_pause() {
        // The race that hung `fg`: bytes the relay saw as readable were flushed away by the
        // terminal restore, and the next blocking read never returned.
        let mut rig = rig();
        for _ in 0..20 {
            rig.relay.pause();
            assert_ok!(rig.user.write_all(b"x"));
            let outer = open_slave(&rig._outer);
            drop(assert_ok!(RawMode::enter(outer.into())));
            rig.relay.resume();
        }
        assert_ok!(rig.child.write_all(b"still relaying"));
        assert_eq!(read_some(&mut rig.user, b"relaying"), b"still relaying");
        rig.relay.finish();
    }

    #[test]
    fn a_finished_relay_has_ended_and_copies_nothing_more() {
        let mut rig = rig();
        rig.relay.finish();
        assert_ok!(rig.child.write_all(b"too late"));
        assert!(
            nothing_arrives_within(&mut rig.user, Duration::from_millis(300)),
            "the relay was still running after finish"
        );
        // Take the bytes off the pty, or restoring its terminal mode would wait for them.
        let mut leftover = assert_ok!(rig._inner.clone_master());
        assert_eq!(read_some(&mut leftover, b"too late"), b"too late");
    }

    #[test]
    fn output_that_arrives_shortly_after_the_child_ended_is_still_drained() {
        let mut rig = rig();
        let mut child = assert_ok!(rig.child.try_clone());
        let writer = thread::spawn(move || {
            thread::sleep(Duration::from_millis(60));
            let _ = child.write_all(b"just in time");
        });
        rig.relay.finish();
        assert_ok!(writer.join().map_err(|_| "writer panicked"));
        assert_eq!(read_some(&mut rig.user, b"in time"), b"just in time");
    }

    #[test]
    fn a_child_that_never_stops_writing_cannot_keep_the_relay_from_finishing() {
        // A quiet limit far above any scheduling pause in this test's writer thread: the relay
        // ends a drain when the master has been silent for `quiet`, so a writer that is merely
        // slow to be scheduled under a busy test run must not look like a silent child.
        let drain = Drain {
            quiet: Duration::from_millis(900),
            max: Duration::from_millis(1500),
        };
        let rig = rig_draining(drain);
        let mut child = assert_ok!(rig.child.try_clone());
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let writer = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                let _ = child.write_all(b"noise");
                thread::sleep(Duration::from_millis(20));
            }
        });
        // Keep the screen side drained so the writer is not what ends the relay.
        let mut user = assert_ok!(rig._outer.clone_master());
        let reader = thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            let end = Instant::now() + Duration::from_secs(4);
            while Instant::now() < end {
                let mut fds = [PollFd::new(user.as_fd(), PollFlags::POLLIN)];
                if poll(&mut fds, PollTimeout::from(50u8)).is_ok_and(|n| n > 0) {
                    let _ = user.read(&mut buffer);
                }
            }
        });
        let started = Instant::now();
        rig.relay.finish();
        let took = started.elapsed();
        done.store(true, Ordering::Relaxed);
        let _ = writer.join();
        let _ = reader.join();
        assert!(took >= drain.max - Duration::from_millis(200), "{took:?}");
        assert!(took < drain.max + Duration::from_secs(1), "{took:?}");
    }

    /// A terminal under test: its slave (what the relay writes to) and its master (the far end).
    fn terminal_pair() -> (OwnedFd, File, Pty) {
        let pty = assert_ok!(Pty::open());
        let slave = open_slave(&pty);
        let master = assert_ok!(pty.clone_master());
        (OwnedFd::from(slave), master, pty)
    }

    fn shared() -> Arc<Shared> {
        Arc::new(Shared {
            stop: AtomicBool::new(false),
            hurry: AtomicBool::new(false),
            gate: Mutex::new(Gate::Open),
            changed: Condvar::new(),
        })
    }

    fn fill(slave: &OwnedFd) {
        let mut screen = assert_ok!(open_for_nonblocking_write(slave));
        while screen.write(&[b'x'; 1024]).is_ok() {}
    }

    fn read_until(master: &mut File, tail: &[u8], secs: u64) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut buf = [0_u8; 4096];
        let end = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < end && !seen.ends_with(tail) {
            if let Ok(n) = std::io::Read::read(master, &mut buf) {
                seen.extend_from_slice(&buf[..n]);
            }
        }
        seen
    }

    #[test]
    fn a_slow_reader_gets_every_byte_even_after_a_stop_begins() {
        // The terminal is full when the stop begins and drains a moment later: nothing may be
        // dropped just because a stop is under way (hb-807 re-review, HIGH).
        let (slave, master, _pty) = terminal_pair();
        fill(&slave);
        let shared = shared();
        let mut sink = assert_ok!(Sink::new(&slave, Arc::clone(&shared)));
        shared.hurry.store(true, Ordering::Relaxed);
        shared.stop.store(true, Ordering::Relaxed);
        let reader = thread::spawn(move || {
            thread::sleep(Duration::from_millis(400));
            let mut master = master;
            read_until(&mut master, b"THE-END", 5)
        });
        assert_ok!(sink.write(b"THE-END"));
        let seen = assert_ok!(reader.join());
        assert!(seen.ends_with(b"THE-END"), "the last bytes were dropped");
    }

    #[test]
    fn a_terminal_that_takes_nothing_is_given_up_on_after_the_stall_once_a_stop_is_under_way() {
        let (slave, _master, _pty) = terminal_pair();
        fill(&slave);
        let shared = shared();
        let mut sink = assert_ok!(Sink::new(&slave, Arc::clone(&shared)));
        shared.hurry.store(true, Ordering::Relaxed);
        let started = Instant::now();
        assert_ok!(sink.write(b"never delivered"));
        let took = started.elapsed();
        assert!(
            took >= STALL - Duration::from_millis(200),
            "gave up too early: {took:?}"
        );
        assert!(took < STALL + Duration::from_secs(3), "{took:?}");
        // Once abandoned it stays abandoned: later writes return at once.
        let again = Instant::now();
        assert_ok!(sink.write(b"x"));
        assert!(again.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn a_full_terminal_is_waited_for_when_no_stop_is_under_way() {
        let (slave, master, _pty) = terminal_pair();
        fill(&slave);
        let shared = shared();
        let mut sink = assert_ok!(Sink::new(&slave, Arc::clone(&shared)));
        let writer = thread::spawn(move || {
            let started = Instant::now();
            assert_ok!(sink.write(b"after the wait"));
            started.elapsed()
        });
        thread::sleep(Duration::from_secs(3));
        assert!(
            !writer.is_finished(),
            "gave up on a terminal with no stop under way"
        );
        let mut master = master;
        let seen = read_until(&mut master, b"after the wait", 5);
        assert!(seen.ends_with(b"after the wait"));
        assert_ok!(writer.join());
    }

    #[test]
    fn finish_is_a_barrier_final_output_is_written_before_it_returns() {
        // The exit fence runs after `finish`. If a writer outlived it, the fence could be
        // interleaved with agent output (hb-807 re-review, HIGH). A terminal's queue holds about a
        // kilobyte, so when `finish` returns the reader must already have most of the output; a
        // detached writer would still be holding it in memory.
        use std::sync::atomic::AtomicUsize;
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let inner_slave = open_slave(&inner);
        let outer_slave = open_slave(&outer);
        let mut outer_master = assert_ok!(outer.clone_master());
        let relay = assert_ok!(Relay::spawn(
            assert_ok!(outer_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
            OwnedFd::from(outer_slave),
            ClipboardPolicy::default(),
            Drain::default(),
        ));
        let received = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&received);
        let reader = thread::spawn(move || {
            // A slow terminal: nothing reads for a while.
            thread::sleep(Duration::from_millis(600));
            let mut seen = Vec::new();
            let mut buf = [0_u8; 4096];
            let end = Instant::now() + Duration::from_secs(10);
            while Instant::now() < end && !seen.ends_with(b"<END>") {
                if let Ok(n) = std::io::Read::read(&mut outer_master, &mut buf) {
                    seen.extend_from_slice(&buf[..n]);
                    counter.store(seen.len(), Ordering::SeqCst);
                }
            }
            seen
        });
        let payload = "x".repeat(60_000);
        let total = payload.len() + 5;
        let mut child = assert_ok!(inner_slave.try_clone());
        let writer = thread::spawn(move || {
            assert_ok!(child.write_all(payload.as_bytes()));
            assert_ok!(child.write_all(b"<END>"));
        });
        assert_ok!(writer.join().map_err(|_| "child writer panicked"));
        relay.finish();
        let at_finish = received.load(Ordering::SeqCst);
        assert!(
            at_finish + 4096 >= total,
            "finish returned with {at_finish} of {total} bytes delivered: a writer outlived it"
        );
        let seen = assert_ok!(reader.join());
        assert_eq!(seen.len(), total);
        assert!(seen.ends_with(b"<END>"));
    }

    #[test]
    fn the_relay_ends_by_itself_when_the_childs_side_is_gone() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let outer_slave = open_slave(&outer);
        let child = open_slave(&inner);
        let no_input = OwnedFd::from(assert_ok!(File::open("/dev/null")));
        // As in a real run, hb keeps no copy of the child's slave, so the end shows on the master.
        let master = inner.release_slave();
        let relay = assert_ok!(Relay::start(no_input, master, outer_slave.into()));
        drop(child);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !relay.handle.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(relay.handle.is_finished());
        relay.finish();
    }

    #[test]
    fn pausing_a_relay_that_has_already_ended_does_not_wait_forever() {
        let rig = rig();
        drop(rig.child);
        // The master's output ends once the child side closes and the relay returns on its own.
        thread::sleep(Duration::from_millis(500));
        let started = Instant::now();
        rig.relay.pause();
        rig.relay.resume();
        assert!(started.elapsed() < Duration::from_secs(2));
        rig.relay.finish();
    }
}
