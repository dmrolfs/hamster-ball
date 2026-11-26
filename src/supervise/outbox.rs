// ABOUTME: A session's outgoing bytes: a byte-bounded input queue and a Stop request, drained by one writer thread that can always be cancelled.
// ABOUTME: The UI loop only enqueues (never blocks); Stop goes ahead of queued input; a write that makes no progress for a while fails instead of hanging.
//! Writing to a session without ever blocking the supervisor's loop (epic hb-b6q).
//!
//! The agent's terminal and the control channel can both stop accepting bytes: an agent that does
//! not read its input fills the PTY, and an `hb` that does not read fills the socket. A write on
//! the loop thread then freezes every session. So the loop only calls [`Outbox::push`] and
//! [`Outbox::request_stop`], which take a short lock and return, and one writer thread per
//! session does the I/O.
//!
//! The terminal descriptor is non-blocking and every wait is a bounded `poll`, so the writer
//! looks at the cancel and stop flags at least every [`POLL`], and gives up on a write that has
//! made no progress for [`STALL`]. Input is queued whole: an input that does not fit is refused
//! entire, never cut, because half a bracketed paste would leave the agent in paste mode.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::Errno;
use snafu::{ResultExt, Snafu};

/// The most input bytes that may wait. A large paste is a few hundred KiB at most.
pub const MAX_PENDING_BYTES: usize = 1 << 20;
/// The longest the writer waits before looking at its flags again.
pub const POLL: Duration = Duration::from_millis(50);
/// A write that makes no progress for this long has failed.
pub const STALL: Duration = Duration::from_secs(5);

/// Why input was not accepted.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[non_exhaustive]
pub enum InputError {
    /// The agent is not reading its input and the queue is full.
    #[snafu(display("the agent is not reading its input: {pending} bytes are waiting"))]
    Full {
        /// Bytes already waiting.
        pending: usize,
    },
    /// The session is stopping, ended, or its terminal failed.
    #[snafu(display("the session no longer takes input"))]
    Closed,
}

/// Why the writer stopped.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum WriterError {
    /// The terminal did not take input for [`STALL`].
    #[snafu(display("the agent's terminal took no input for {} seconds", STALL.as_secs()))]
    Stalled,
    /// The terminal could not be written.
    #[snafu(display("the agent's terminal could not be written"))]
    Terminal {
        /// The OS error.
        source: io::Error,
    },
    /// The control channel could not be written.
    #[snafu(display("the control channel could not be written"))]
    Channel {
        /// The OS error.
        source: io::Error,
    },
}

#[derive(Debug, Default)]
struct State {
    queue: VecDeque<Vec<u8>>,
    pending: usize,
    stop: bool,
    /// Input is refused from here on: stopping, ended, or failed.
    refusing: bool,
}

/// The queue between the loop and one session's writer thread.
#[derive(Debug, Default)]
pub struct Outbox {
    state: Mutex<State>,
    wake: Condvar,
    cancelled: AtomicBool,
}

impl Outbox {
    /// An empty outbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // A poisoned lock means the writer panicked; the state is still plain data, and refusing
    // input is the safe reading of it, so the guard is taken anyway.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Queues `bytes` whole, or refuses them. Never blocks.
    ///
    /// # Errors
    /// [`InputError::Full`] if they do not fit; [`InputError::Closed`] once stopping or ended.
    pub fn push(&self, bytes: Vec<u8>) -> Result<(), InputError> {
        let mut state = self.lock();
        if state.refusing {
            return Err(InputError::Closed);
        }
        if state.pending + bytes.len() > MAX_PENDING_BYTES {
            return Err(InputError::Full {
                pending: state.pending,
            });
        }
        state.pending += bytes.len();
        state.queue.push_back(bytes);
        drop(state);
        self.wake.notify_one();
        Ok(())
    }

    /// Asks for the Stop command to be sent ahead of any waiting input, which is dropped.
    pub fn request_stop(&self) {
        let mut state = self.lock();
        state.stop = true;
        state.refusing = true;
        state.queue.clear();
        state.pending = 0;
        drop(state);
        self.wake.notify_one();
    }

    /// Ends the writer at its next look, and refuses further input.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.lock().refusing = true;
        self.wake.notify_one();
    }

    /// Whether [`Outbox::cancel`] was called.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    /// The writer thread's body: sends Stop and input until cancelled, or until a write fails.
    ///
    /// `stop_line` is the encoded Stop command. The channel is written with a timeout set on it
    /// by the caller, so a full socket fails the write instead of hanging it.
    ///
    /// # Errors
    /// [`WriterError`] for the failure that ended it. The outbox then refuses input.
    pub fn run(
        &self,
        terminal: &File,
        channel: &mut impl Write,
        stop_line: &[u8],
    ) -> Result<(), WriterError> {
        let result = self.run_inner(terminal, channel, stop_line);
        if result.is_err() {
            let mut state = self.lock();
            state.refusing = true;
            state.queue.clear();
            state.pending = 0;
        }
        result
    }

    fn run_inner(
        &self,
        terminal: &File,
        channel: &mut impl Write,
        stop_line: &[u8],
    ) -> Result<(), WriterError> {
        loop {
            if self.is_cancelled() {
                return Ok(());
            }
            let next = {
                let mut state = self.lock();
                if state.stop {
                    Next::Stop
                } else if let Some(bytes) = state.queue.pop_front() {
                    state.pending -= bytes.len();
                    Next::Input(bytes)
                } else {
                    let _ = self.wake.wait_timeout(state, POLL);
                    continue;
                }
            };
            match next {
                Next::Stop => {
                    channel
                        .write_all(stop_line)
                        .and_then(|()| channel.flush())
                        .context(ChannelSnafu)?;
                    // Nothing is sent after Stop: the writer's work is done.
                    return Ok(());
                }
                Next::Input(bytes) => self.write_input(terminal, &bytes)?,
            }
        }
    }

    /// Writes all of `bytes`, or stops early (without error) if a stop or cancel arrives.
    fn write_input(&self, terminal: &File, bytes: &[u8]) -> Result<(), WriterError> {
        let mut sent = 0;
        let mut progress = Instant::now();
        while sent < bytes.len() {
            if self.is_cancelled() || self.lock().stop {
                return Ok(());
            }
            match rustix::io::write(terminal, &bytes[sent..]) {
                Ok(0) => return Err(WriterError::Stalled),
                Ok(n) => {
                    sent += n;
                    progress = Instant::now();
                }
                Err(Errno::INTR) => {}
                Err(Errno::AGAIN) => {
                    if progress.elapsed() >= STALL {
                        return Err(WriterError::Stalled);
                    }
                    wait_writable(terminal).context(TerminalSnafu)?;
                }
                Err(errno) => return Err(io::Error::from(errno)).context(TerminalSnafu),
            }
        }
        Ok(())
    }
}

enum Next {
    Stop,
    Input(Vec<u8>),
}

/// Waits up to [`POLL`] for `fd` to take bytes.
fn wait_writable(fd: &impl AsFd) -> io::Result<()> {
    let mut fds = [PollFd::new(fd, PollFlags::OUT)];
    let timeout = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: i64::try_from(POLL.as_nanos()).unwrap_or(50_000_000),
    };
    match poll(&mut fds, Some(&timeout)) {
        Ok(_) | Err(Errno::INTR) => Ok(()),
        Err(errno) => Err(io::Error::from(errno)),
    }
}

/// Puts `fd` in non-blocking mode. Shared by every descriptor duplicated from it, so the reader
/// of the same terminal must wait with `poll` too (see [`wait_readable`]).
///
/// # Errors
/// The OS error if the flags cannot be changed.
pub fn set_nonblocking(fd: &impl AsFd) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(io::Error::from)
}

/// Waits up to [`POLL`] for `fd` to have bytes to read, or end.
///
/// # Errors
/// The OS error if the wait fails.
pub fn wait_readable(fd: &impl AsFd) -> io::Result<()> {
    let mut fds = [PollFd::new(fd, PollFlags::IN)];
    let timeout = rustix::event::Timespec {
        tv_sec: 0,
        tv_nsec: i64::try_from(POLL.as_nanos()).unwrap_or(50_000_000),
    };
    match poll(&mut fds, Some(&timeout)) {
        Ok(_) | Err(Errno::INTR) => Ok(()),
        Err(errno) => Err(io::Error::from(errno)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Pty;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::io::Read;
    use std::sync::Arc;
    use std::thread;

    /// A PTY whose master the writer fills, and the slave end that must stay open and unread for
    /// the test's life. The slave is in raw mode: in line mode the terminal throws input away
    /// instead of filling up, and the master would never stall.
    fn stalled_terminal() -> (File, File) {
        let pty = assert_ok!(Pty::open());
        let master = assert_ok!(pty.clone_master());
        assert_ok!(set_nonblocking(&master));
        let slave = assert_ok!(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(pty.slave_path().as_str())
        );
        let mut modes = assert_ok!(rustix::termios::tcgetattr(&slave));
        modes.make_raw();
        assert_ok!(rustix::termios::tcsetattr(
            &slave,
            rustix::termios::OptionalActions::Now,
            &modes
        ));
        // The pty itself must outlive the test too, or the master reports an error.
        std::mem::forget(pty);
        (master, slave)
    }

    /// A channel that records what is written.
    #[derive(Clone, Default)]
    struct Sink(Arc<Mutex<Vec<u8>>>);

    impl Write for Sink {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().map(|mut v| v.extend_from_slice(bytes)).ok();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn within(secs: u64, mut done: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            if done() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        done()
    }

    #[test]
    fn push_never_blocks_and_refuses_what_does_not_fit_whole() {
        let outbox = Outbox::new();
        let big = vec![0u8; MAX_PENDING_BYTES - 10];
        let started = Instant::now();
        assert_ok!(outbox.push(big));
        assert_eq!(
            outbox.push(vec![1; 11]),
            Err(InputError::Full {
                pending: MAX_PENDING_BYTES - 10
            }),
            "one byte too many is refused entire"
        );
        assert_ok!(outbox.push(vec![1; 10]));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn stop_drops_waiting_input_and_closes_the_queue() {
        let outbox = Outbox::new();
        assert_ok!(outbox.push(b"typed".to_vec()));
        outbox.request_stop();
        assert_eq!(outbox.push(b"more".to_vec()), Err(InputError::Closed));
        assert_eq!(outbox.lock().pending, 0);
    }

    #[test]
    fn input_reaches_the_terminal_in_order_and_whole() {
        let pty = assert_ok!(Pty::open());
        let master = assert_ok!(pty.clone_master());
        assert_ok!(set_nonblocking(&master));
        // Reading the slave: the pty's own descriptor, which the test holds open.
        let mut slave = assert_ok!(File::open(pty.slave_path().as_str()));
        let outbox = Arc::new(Outbox::new());
        let writer = {
            let outbox = Arc::clone(&outbox);
            thread::spawn(move || outbox.run(&master, &mut Sink::default(), b"STOP\n"))
        };
        assert_ok!(outbox.push(b"ab".to_vec()));
        assert_ok!(outbox.push(b"cd\n".to_vec()));
        let mut got = Vec::new();
        let mut buffer = [0u8; 16];
        // The slave is a terminal in line mode: the line arrives when it ends in a newline.
        while !got.ends_with(b"\n") {
            let n = assert_ok!(slave.read(&mut buffer));
            got.extend_from_slice(&buffer[..n]);
        }
        assert_eq!(String::from_utf8_lossy(&got).replace('\r', ""), "abcd\n");
        outbox.cancel();
        assert_ok!(assert_ok!(writer.join()));
    }

    #[test]
    fn a_terminal_that_takes_no_input_is_cancelled_within_a_poll_and_the_loop_never_waits() {
        let (master, _slave) = stalled_terminal();
        let outbox = Arc::new(Outbox::new());
        let writer = {
            let outbox = Arc::clone(&outbox);
            thread::spawn(move || outbox.run(&master, &mut Sink::default(), b"STOP\n"))
        };
        // Far more than a PTY buffers: the writer ends up blocked in the middle of it.
        let started = Instant::now();
        assert_ok!(outbox.push(vec![b'x'; 512 * 1024]));
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "push waited"
        );
        thread::sleep(Duration::from_millis(300));
        let cancelled = Instant::now();
        outbox.cancel();
        assert!(within(2, || writer.is_finished()), "the writer did not end");
        assert!(cancelled.elapsed() < Duration::from_secs(1));
        assert_ok!(assert_ok!(writer.join()));
    }

    #[test]
    fn stop_goes_ahead_of_a_stuck_paste_and_is_sent() {
        let (master, _slave) = stalled_terminal();
        let outbox = Arc::new(Outbox::new());
        let sink = Sink::default();
        let writer = {
            let outbox = Arc::clone(&outbox);
            let mut channel = sink.clone();
            thread::spawn(move || outbox.run(&master, &mut channel, b"STOP\n"))
        };
        assert_ok!(outbox.push(vec![b'x'; 512 * 1024]));
        thread::sleep(Duration::from_millis(300));
        outbox.request_stop();
        assert!(
            within(2, || sink.0.lock().is_ok_and(|v| v.as_slice() == b"STOP\n")),
            "Stop waited behind the paste"
        );
        outbox.cancel();
        assert_ok!(assert_ok!(writer.join()));
    }

    #[test]
    fn a_terminal_that_stays_full_fails_the_writer_with_stalled_and_refuses_input() {
        let (master, _slave) = stalled_terminal();
        let outbox = Arc::new(Outbox::new());
        let writer = {
            let outbox = Arc::clone(&outbox);
            thread::spawn(move || outbox.run(&master, &mut Sink::default(), b"STOP\n"))
        };
        assert_ok!(outbox.push(vec![b'x'; 512 * 1024]));
        let error = assert_err!(assert_ok!(writer.join()));
        assert!(matches!(error, WriterError::Stalled), "{error:?}");
        assert_eq!(outbox.push(b"more".to_vec()), Err(InputError::Closed));
    }

    #[test]
    fn a_channel_that_cannot_be_written_fails_the_writer_with_a_channel_error() {
        struct Broken;
        impl Write for Broken {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (master, _slave) = stalled_terminal();
        let outbox = Outbox::new();
        outbox.request_stop();
        let error = assert_err!(outbox.run(&master, &mut Broken, b"STOP\n"));
        assert!(matches!(error, WriterError::Channel { .. }), "{error:?}");
    }
}
