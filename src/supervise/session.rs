// ABOUTME: One running session's threads: a PTY reader that feeds the emulator, a channel reader that sends typed events, and a reaper that reports the exit last.
// ABOUTME: Every queue is bounded; the PTY reader never sends per byte, and the exit is only reported after the channel reader has delivered everything it will.
//! A session's workers (epic hb-b6q).
//!
//! Three threads per session, each with one job:
//!
//! - The PTY reader reads the session's terminal and feeds [`SessionScreen`] directly, then sets
//!   a dirty flag. It sends the app no message per read, so a session that prints without pause
//!   costs the app one flag, not a queue of messages.
//! - The channel reader decodes frames and sends each as a [`Msg::Channel`] on a bounded
//!   channel, blocking when it is full. Blocking is right here: it stops reading the socket, the
//!   socket fills, and `hb`'s writer thread (which never blocks the agent) counts and drops
//!   telemetry. Lifecycle events still arrive in order.
//! - The reaper waits for the `hb` process, then for the channel reader to finish, and only
//!   then sends [`Msg::ProcessExited`]. The `Exited` event is the last frame `hb` writes and is
//!   already in the socket when `hb` exits, so waiting for the reader means the app sees it first.
//!
//! Stopping a session sends the `Stop` command on the channel. If the process is still there
//! after a grace period it is killed, which `hb`'s guardian turns into the agent's cleanup.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use snafu::Snafu;

use super::app::{Generation, Msg, SessionId};
use super::launch::Started;
use super::outbox::{self, InputError, Outbox, STALL};
use super::terminal::SessionScreen;
use crate::session::supervised::{
    Command, Hello, decode_ack, decode_frame, encode_line, read_line,
};

/// How long a stopping session gets before its process is killed.
pub const STOP_GRACE: Duration = Duration::from_secs(10);
/// How often the reaper looks for the process to have ended.
const REAP_POLL: Duration = Duration::from_millis(20);

/// What the render loop shares with a session's PTY reader.
#[derive(Debug)]
pub struct Shared {
    /// The emulated terminal.
    pub screen: Mutex<SessionScreen>,
    /// Set by the PTY reader when the screen changed; cleared by the renderer.
    pub dirty: AtomicBool,
}

impl Shared {
    /// A blank screen of `rows` by `cols`.
    #[must_use]
    pub fn new(rows: u16, cols: u16) -> Arc<Self> {
        Arc::new(Self {
            screen: Mutex::new(SessionScreen::new(rows, cols)),
            dirty: AtomicBool::new(false),
        })
    }

    /// Whether the screen changed since the last call, and clears the flag.
    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::AcqRel)
    }
}

/// The handles of one running session.
pub struct Worker {
    /// The screen the PTY reader feeds.
    pub shared: Arc<Shared>,
    /// The session's terminal master, kept for its size. Nothing is written through it here: input
    /// and Stop go through `outbox`, so the loop never waits on a full terminal or socket.
    terminal: File,
    /// The supervisor's end of the channel, kept to close it. `Stop` is written by the writer.
    channel: UnixStream,
    /// What the writer thread sends: queued input and the Stop request.
    outbox: Arc<Outbox>,
    /// When a stop was asked for, so the reaper can kill a process that does not end.
    stop_asked: Arc<Mutex<Option<Instant>>>,
    /// Set to make the reaper kill the process now, without waiting out the grace period.
    kill: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Drop for Worker {
    /// A worker that is dropped is abandoned: the process must not outlive the supervisor's
    /// interest in it. Harmless after `shut_down`, which has already done the same.
    fn drop(&mut self) {
        self.abandon();
    }
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Worker(..)")
    }
}

/// Starts the four threads for a launched session and sends `hb` its handshake.
///
/// `messages` is the app's bounded inbox.
///
/// # Errors
/// An [`io::Error`] if a descriptor cannot be duplicated or a thread cannot start. Nothing is left
/// behind: the channel is closed, which ends every thread already started, and the process is
/// killed and reaped.
pub fn spawn(
    id: SessionId,
    generation: Generation,
    started: Started,
    shared: Arc<Shared>,
    messages: SyncSender<Msg>,
) -> io::Result<Worker> {
    let Started {
        child,
        channel,
        terminal,
    } = started;
    let outbox = Arc::new(Outbox::new());
    let kill = Arc::new(AtomicBool::new(false));
    // The child is held in a cell, so that whichever step fails it is still here to be killed
    // rather than lost in a closure that never ran.
    let cell = Arc::new(Mutex::new(Some(child)));
    let built = build(
        &Wiring {
            id,
            generation,
            outbox: &outbox,
            kill: &kill,
        },
        &Parts {
            channel: &channel,
            terminal: &terminal,
            shared: &shared,
            messages: &messages,
            cell: &cell,
        },
    );
    match built {
        Ok((threads, stop_asked)) => Ok(Worker {
            shared,
            terminal,
            channel,
            outbox,
            stop_asked,
            kill,
            threads,
        }),
        Err(error) => {
            // One way out for every failure: ends the writer and the readers already running (the
            // channel closing wakes the channel reader, cancel wakes the others), then the process.
            // `kill` as well: a reader already waiting to hand over a message sees only that, not
            // the socket closing, and there is no `Worker` whose drop would set it.
            kill.store(true, Ordering::SeqCst);
            outbox.cancel();
            let _ = channel.shutdown(Shutdown::Both);
            if let Some(mut child) = cell.lock().ok().and_then(|mut slot| slot.take()) {
                let _ = child.kill();
                let _ = child.wait();
            }
            Err(error)
        }
    }
}

/// The descriptors and shared state a worker is built from.
struct Parts<'a> {
    channel: &'a UnixStream,
    terminal: &'a File,
    shared: &'a Arc<Shared>,
    messages: &'a SyncSender<Msg>,
    cell: &'a Arc<Mutex<Option<std::process::Child>>>,
}

type Built = (Vec<JoinHandle<()>>, Arc<Mutex<Option<Instant>>>);

/// Starts every thread. On error some may be running; [`spawn`] ends them.
fn build(wiring: &Wiring<'_>, parts: &Parts<'_>) -> io::Result<Built> {
    let (mut threads, channel_reader) = spawn_threads(
        wiring,
        parts.channel,
        parts.terminal,
        parts.shared,
        parts.messages,
    )?;
    let stop_asked = Arc::new(Mutex::new(None));
    let handle = spawn_reaper(wiring, parts, channel_reader, &stop_asked)?;
    threads.push(handle);
    Ok((threads, stop_asked))
}

fn spawn_reaper(
    wiring: &Wiring<'_>,
    parts: &Parts<'_>,
    channel_reader: JoinHandle<()>,
    stop_asked: &Arc<Mutex<Option<Instant>>>,
) -> io::Result<JoinHandle<()>> {
    fault(Step::Reaper)?;
    let (id, generation) = (wiring.id, wiring.generation);
    let asked = Arc::clone(stop_asked);
    let kill = Arc::clone(wiring.kill);
    let outbox = Arc::clone(wiring.outbox);
    let channel = parts.channel.try_clone()?;
    let inbox = parts.messages.clone();
    let cell = Arc::clone(parts.cell);
    thread::Builder::new()
        .name(format!("hb-reap-{}", id.0))
        .spawn(move || {
            let taken = cell.lock().ok().and_then(|mut slot| slot.take());
            if let Some(mut child) = taken {
                reap(
                    id,
                    generation,
                    &mut child,
                    channel_reader,
                    &Stopping {
                        asked: &asked,
                        kill: &kill,
                        outbox: &outbox,
                        channel: &channel,
                    },
                    &inbox,
                );
            }
        })
}

/// The construction steps, in order, at which a test can make [`spawn`] fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::EnumIter, strum::Display)]
#[strum(serialize_all = "snake_case")]
pub enum Step {
    /// Making the terminal non-blocking and setting the socket's write timeout.
    Prepare,
    /// Writing the handshake.
    Handshake,
    /// Starting the PTY reader.
    PtyReader,
    /// Starting the writer.
    Writer,
    /// Starting the channel reader.
    ChannelReader,
    /// Starting the reaper.
    Reaper,
}

/// Which step is to fail, for tests (an index into [`Step`], or `usize::MAX` for none). Only
/// read in a test-support build; a release build has no way to ask for a failure.
pub static FAIL_AT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(usize::MAX);

/// Fails with an error if a test asked for `step` to fail. Always `Ok` in a release build.
#[cfg(feature = "test-support")]
fn fault(step: Step) -> io::Result<()> {
    use strum::IntoEnumIterator;
    let wanted = FAIL_AT.load(Ordering::SeqCst);
    if Step::iter().position(|s| s == step) == Some(wanted) {
        return Err(io::Error::other(format!("injected failure at {step}")));
    }
    Ok(())
}

#[cfg(not(feature = "test-support"))]
#[allow(clippy::unnecessary_wraps)]
const fn fault(_: Step) -> io::Result<()> {
    Ok(())
}

/// What the threads of one session share besides their descriptors.
struct Wiring<'a> {
    id: SessionId,
    generation: Generation,
    outbox: &'a Arc<Outbox>,
    kill: &'a Arc<AtomicBool>,
}

/// The PTY reader, the writer and the channel reader; the channel reader's handle is returned
/// separately so the reaper can wait for it.
fn spawn_threads(
    wiring: &Wiring<'_>,
    channel: &UnixStream,
    terminal: &File,
    shared: &Arc<Shared>,
    messages: &SyncSender<Msg>,
) -> io::Result<(Vec<JoinHandle<()>>, JoinHandle<()>)> {
    let Wiring {
        id,
        generation,
        outbox,
        kill,
    } = *wiring;
    // The flag is on the open file, so it covers every descriptor duplicated from this one: the
    // PTY reader below must therefore wait with `poll` and treat "would block" as "not yet".
    fault(Step::Prepare)?;
    outbox::set_nonblocking(terminal)?;
    // A socket that stays full fails a write after this long instead of hanging it. It covers the
    // handshake, and Stop, and applies to writes only.
    channel.set_write_timeout(Some(STALL))?;
    let line = encode_line(&Hello::new(u64::from(id.0), generation)).map_err(io::Error::other)?;
    fault(Step::Handshake)?;
    channel.try_clone()?.write_all(&line)?;
    let reader = channel.try_clone()?;
    fault(Step::PtyReader)?;
    let pty_thread = spawn_pty_reader(id, terminal.try_clone()?, shared, outbox)?;
    fault(Step::Writer)?;
    let writer_thread = spawn_writer(
        id,
        terminal.try_clone()?,
        channel.try_clone()?,
        wiring,
        messages,
    )?;
    let inbox = messages.clone();
    let for_reader = Arc::clone(kill);
    fault(Step::ChannelReader)?;
    let channel_thread = thread::Builder::new()
        .name(format!("hb-chan-{}", id.0))
        .spawn(move || read_channel(id, generation, reader, &inbox, &for_reader))?;
    let _ = kill;
    Ok((vec![pty_thread, writer_thread], channel_thread))
}

fn spawn_pty_reader(
    id: SessionId,
    mut terminal: File,
    shared: &Arc<Shared>,
    outbox: &Arc<Outbox>,
) -> io::Result<JoinHandle<()>> {
    let feed = Arc::clone(shared);
    let outbox = Arc::clone(outbox);
    thread::Builder::new()
        .name(format!("hb-pty-{}", id.0))
        .spawn(move || {
            let mut buffer = [0u8; super::terminal::READ_SIZE];
            #[cfg(feature = "test-support")]
            crash_for_test();
            // Ends on end of output or error, or within a poll of the session being abandoned.
            while !outbox.is_cancelled() {
                match terminal.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        if let Ok(mut screen) = feed.screen.lock() {
                            screen.process(&buffer[..n]);
                        }
                        feed.dirty.store(true, Ordering::Release);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        if outbox::wait_readable(&terminal).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    // The slave closing is reported as an I/O error on the master.
                    Err(_) => break,
                }
            }
        })
}

/// Makes the calling thread panic if a test asked for it, to show that a panic in a worker thread
/// ends the whole supervisor cleanly. Only in test-support builds.
#[cfg(feature = "test-support")]
#[allow(clippy::panic)]
fn crash_for_test() {
    if std::env::var_os("HB_SUPERVISE_TEST_WORKER_PANIC").is_some() {
        panic!("test panic in a worker thread");
    }
}

/// The writer thread: sends queued input and Stop. If it fails the session cannot be steered, so
/// the process is stopped hard (killed at the reaper's next look, channel closed) and the owner
/// is told why.
fn spawn_writer(
    id: SessionId,
    terminal: File,
    mut channel: UnixStream,
    wiring: &Wiring<'_>,
    messages: &SyncSender<Msg>,
) -> io::Result<JoinHandle<()>> {
    let outbox = Arc::clone(wiring.outbox);
    let kill = Arc::clone(wiring.kill);
    let inbox = messages.clone();
    let stop_line = encode_line(&Command::Stop {}).map_err(io::Error::other)?;
    thread::Builder::new()
        .name(format!("hb-write-{}", id.0))
        .spawn(move || {
            if let Err(error) = outbox.run(&terminal, &mut channel, &stop_line) {
                kill.store(true, Ordering::Release);
                let _ = channel.shutdown(Shutdown::Both);
                // Not `send`: a full inbox must not hold this thread, and the reaper reports the
                // end of the session anyway. The notice only says why.
                let _ = inbox.try_send(Msg::Notice(format!(
                    "session {} was stopped: {}",
                    id.0,
                    snafu::Report::from_error(error)
                )));
            }
        })
}

/// What tells the reaper to kill a process that does not end.
struct Stopping<'a> {
    asked: &'a Mutex<Option<Instant>>,
    kill: &'a AtomicBool,
    /// Cancelled once the process has ended, so the writer does not outlive it.
    outbox: &'a Outbox,
    /// The supervisor's end of the channel, to close it if the process cannot be waited for.
    channel: &'a UnixStream,
}

impl Stopping<'_> {
    fn close_channel(&self) {
        let _ = self.channel.shutdown(Shutdown::Both);
    }
}

/// What the reaper needs of a process: so a failing one can be put in its place in a test, since
/// a real child cannot be made to fail `try_wait`.
trait Process {
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>>;
    fn kill(&mut self) -> io::Result<()>;
    fn wait(&mut self) -> io::Result<std::process::ExitStatus>;
}

impl Process for std::process::Child {
    fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
        Self::try_wait(self)
    }
    fn kill(&mut self) -> io::Result<()> {
        Self::kill(self)
    }
    fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
        Self::wait(self)
    }
}

/// How a session's process ended, as far as the reaper could tell.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ReapError {
    /// The operating system would not say whether the process had ended. It is killed, and the
    /// session is reported as lost, never as having exited: nothing was observed.
    #[snafu(display("the process's state could not be read, so it was killed"))]
    Wait {
        /// The OS error.
        source: io::Error,
    },
    /// The channel reader panicked, so `hb`'s last reports may not have arrived.
    #[snafu(display("the channel reader panicked"))]
    ReaderPanicked,
}

/// Waits for `hb`, then for the channel reader, then reports the exit.
///
/// The `Exited` event is the last frame `hb` writes and is in the socket before `hb` exits, so
/// once the reader has seen the end of the channel the app has been sent everything `hb` said.
/// A process that is still there a grace period after a stop is killed.
///
/// An exit is reported only when it was seen. If the process cannot be waited for, or the reader
/// panicked, the child is killed and reaped (when it can be) and the session is reported lost.
fn reap(
    id: SessionId,
    generation: Generation,
    child: &mut impl Process,
    channel_reader: JoinHandle<()>,
    stopping: &Stopping<'_>,
    inbox: &SyncSender<Msg>,
) {
    let waited = wait_for_exit(child, stopping);
    // Nothing more can be sent to a process that has ended.
    stopping.outbox.cancel();
    if waited.is_err() {
        // Closing the channel is `hb`'s cue to stop, and it ends the reader below.
        stopping.close_channel();
    }
    // The reader ends when `hb` closes its end, which it does as it exits; a descendant that kept
    // the channel open is not a case: `hb` closes it close-on-exec and the agent never held it.
    let reader = channel_reader.join();
    let outcome = match (waited, reader) {
        (Ok(status), Ok(())) => Ok(status),
        (Err(source), _) => Err(ReapError::Wait { source }),
        (Ok(_), Err(_)) => Err(ReapError::ReaderPanicked),
    };
    let msg = match outcome {
        Ok(status) => Msg::ProcessExited {
            id,
            generation,
            code: status.code(),
            signal: std::os::unix::process::ExitStatusExt::signal(&status),
        },
        Err(error) => Msg::SessionLost {
            id,
            generation,
            reason: snafu::Report::from_error(error).to_string(),
        },
    };
    // The last message of a session is not dropped for a full inbox while the app still
    // listens. It is given up on when the session is abandoned (`kill`), which is what a shutdown
    // past its deadline and a dropped worker do, so this thread can always be joined.
    deliver(inbox, stopping.kill, msg);
}

/// Polls until the process has ended, killing it when asked to or when its stop is overdue.
/// An error from the operating system is not an exit: the child is killed and the error returned.
fn wait_for_exit(
    child: &mut impl Process,
    stopping: &Stopping<'_>,
) -> io::Result<std::process::ExitStatus> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(error) => {
                // Still ours to clean up: kill it and try once more to reap it.
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
        let overdue = stopping.kill.load(Ordering::Acquire)
            || stopping
                .asked
                .lock()
                .ok()
                .and_then(|asked| *asked)
                .is_some_and(|at| at.elapsed() >= STOP_GRACE);
        if overdue {
            let _ = child.kill();
        }
        thread::sleep(REAP_POLL);
    }
}

impl Worker {
    /// Queues `bytes` for the agent's terminal, whole or not at all. Never waits.
    ///
    /// # Errors
    /// [`InputError::Full`] if the agent is not reading its input; [`InputError::Closed`] once the
    /// session is stopping or its writer failed.
    pub fn enqueue_input(&self, bytes: Vec<u8>) -> Result<(), InputError> {
        self.outbox.push(bytes)
    }

    /// Sets the terminal's size for the agent and the emulator, together.
    ///
    /// # Errors
    /// The OS error if the size cannot be set.
    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), rustix::io::Errno> {
        rustix::termios::tcsetwinsize(
            &self.terminal,
            rustix::termios::Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )?;
        if let Ok(mut screen) = self.shared.screen.lock() {
            screen.resize(rows, cols);
        }
        self.shared.dirty.store(true, Ordering::Release);
        Ok(())
    }

    /// Asks `hb` to stop the session, and starts the clock after which the process is killed.
    /// Waiting input is dropped and the Stop goes first. Never waits.
    pub fn stop(&self) {
        self.start_clock();
        self.outbox.request_stop();
    }

    fn start_clock(&self) {
        if let Ok(mut asked) = self.stop_asked.lock() {
            asked.get_or_insert_with(Instant::now);
        }
    }

    /// Whether every thread of the session has ended: the process is reaped and everything it
    /// said has been delivered.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.threads.iter().all(JoinHandle::is_finished)
    }

    /// Gives up waiting: closes both ends of the channel, which `hb` treats as a stop and which
    /// also ends the channel reader, and has the process killed at the reaper's next look.
    pub fn abandon(&self) {
        self.start_clock();
        self.kill.store(true, Ordering::Release);
        self.outbox.cancel();
        let _ = self.channel.shutdown(Shutdown::Both);
    }

    /// Closes the channel, which `hb` treats as a stop, and waits for the threads to end, for at
    /// most `limit` in all. Returns whether all of them did.
    ///
    /// The process is killed if it has not ended by then. Nothing here reads the app's inbox, so
    /// a caller that holds the inbox must keep it drained, or the reader can block on a full
    /// inbox and never finish; [`Runtime::shut_down`](super::runtime::Runtime::shut_down) does.
    pub fn shut_down(mut self, limit: Duration) -> bool {
        self.start_clock();
        self.outbox.cancel();
        let _ = self.channel.shutdown(Shutdown::Both);
        let deadline = Instant::now() + limit;
        for handle in std::mem::take(&mut self.threads) {
            while !handle.is_finished() {
                if Instant::now() > deadline {
                    self.kill.store(true, Ordering::Release);
                    return false;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let _ = handle.join();
        }
        true
    }

    /// Waits for threads that have already finished. Call it only when [`Worker::is_finished`].
    /// Returns whether report delivery remained reliable, before Drop abandons the worker.
    pub fn join(mut self) -> bool {
        for handle in std::mem::take(&mut self.threads) {
            let _ = handle.join();
        }
        !self.kill.load(Ordering::Acquire)
    }
}

/// How long a send to a full inbox waits before looking at the cancel flag again.
const SEND_RETRY: Duration = Duration::from_millis(5);

/// Sends `msg` to the app, in order, waiting while the inbox is full, but giving up when the
/// session is abandoned (`kill`) or the app has gone: a thread blocked here forever would never
/// end, and the worker that owns it could never be joined. Returns whether it was delivered.
///
/// It does not give up when the process has merely exited or the writer was cancelled: what `hb`
/// reported before it exited (an approval request, a final failure) is the owner's to see, and
/// the exit is reported only after all of it. The reaper joins this thread first for that reason.
fn deliver(inbox: &SyncSender<Msg>, kill: &AtomicBool, mut msg: Msg) -> bool {
    loop {
        match inbox.try_send(msg) {
            Ok(()) => return true,
            Err(TrySendError::Disconnected(_)) => return false,
            Err(TrySendError::Full(back)) => {
                if kill.load(Ordering::Acquire) {
                    return false;
                }
                msg = back;
                thread::sleep(SEND_RETRY);
            }
        }
    }
}

/// Reads frames until the channel ends and sends each to the app, in order.
fn read_channel(
    id: SessionId,
    generation: Generation,
    stream: UnixStream,
    inbox: &SyncSender<Msg>,
    kill: &AtomicBool,
) {
    // Only an `hb` that answers for this launch and generation speaks for this session.
    let expected = Hello::new(u64::from(id.0), generation);
    let mut reader = BufReader::new(stream);
    // The acknowledgement comes first; anything else, or none, is a lost channel.
    let acknowledged = matches!(
        read_line(&mut reader),
        Ok(Some(line)) if decode_ack(&line).is_ok_and(|ack| expected.check(&ack).is_ok())
    );
    if acknowledged {
        loop {
            let line = match read_line(&mut reader) {
                Ok(Some(line)) => line,
                Ok(None) => break,
                Err(error) => {
                    deliver(
                        inbox,
                        kill,
                        Msg::ChannelBroken {
                            id,
                            generation,
                            reason: error.to_string(),
                        },
                    );
                    let _ = io::copy(&mut reader, &mut io::sink());
                    return;
                }
            };
            let frame = match decode_frame(&line) {
                Ok(frame) => frame,
                Err(error) => {
                    deliver(
                        inbox,
                        kill,
                        Msg::ChannelBroken {
                            id,
                            generation,
                            reason: error.to_string(),
                        },
                    );
                    let _ = io::copy(&mut reader, &mut io::sink());
                    return;
                }
            };
            let msg = Msg::Channel {
                id,
                generation,
                seq: frame.seq,
                event: frame.event,
            };
            // Waits when the app is behind: the socket then fills and `hb` drops telemetry.
            if !deliver(inbox, kill, msg) {
                return;
            }
        }
    }
    deliver(inbox, kill, Msg::ChannelLost { id, generation });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::supervised::HelloAck;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::sync::mpsc::sync_channel;
    use std::thread;

    #[test]
    fn writer_failure_marks_dropped_failure_reports_unreliable_before_join_drops_the_worker() {
        for fail_writer in [false, true] {
            let (channel, _peer) = assert_ok!(UnixStream::pair());
            let outbox = Arc::new(Outbox::new());
            let kill = Arc::new(AtomicBool::new(false));
            let (tx, rx) = sync_channel(1);
            assert_ok!(tx.send(Msg::Notice("earlier completion fills inbox".into())));
            let terminal = assert_ok!(File::open("/dev/null"));
            let mut threads = Vec::new();
            if fail_writer {
                // Read-only descriptor makes the production writer fail without test-only hooks.
                assert_ok!(outbox.push(vec![1]));
                threads.push(assert_ok!(spawn_writer(
                    SessionId(7),
                    assert_ok!(terminal.try_clone()),
                    assert_ok!(channel.try_clone()),
                    &Wiring {
                        id: SessionId(7),
                        generation: 3,
                        outbox: &outbox,
                        kill: &kill
                    },
                    &tx
                )));
                let deadline = Instant::now() + Duration::from_secs(5);
                while !kill.load(Ordering::Acquire) {
                    assert!(Instant::now() < deadline, "writer did not fail");
                    thread::sleep(Duration::from_millis(5));
                }
                assert!(!deliver(
                    &tx,
                    &kill,
                    Msg::SessionLost {
                        id: SessionId(7),
                        generation: 3,
                        reason: "malformed suffix after completion".into()
                    }
                ));
            }
            let worker = Worker {
                shared: Shared::new(2, 2),
                terminal,
                channel,
                outbox,
                stop_asked: Arc::new(Mutex::new(None)),
                kill: Arc::clone(&kill),
                threads,
            };
            let reliable = worker.join();
            assert_eq!(reliable, !fail_writer);
            assert!(
                kill.load(Ordering::Acquire),
                "Drop should abandon only after sampling"
            );
            assert!(matches!(assert_ok!(rx.try_recv()), Msg::Notice(_)));
        }
    }

    #[test]
    fn a_broken_channel_keeps_draining_until_the_peer_closes() {
        let (ours, mut theirs) = assert_ok!(UnixStream::pair());
        assert_ok!(theirs.set_write_timeout(Some(Duration::from_secs(5))));
        let (tx, rx) = sync_channel(4);
        let worker = thread::spawn(move || {
            read_channel(SessionId(7), 3, ours, &tx, &AtomicBool::new(false))
        });
        let ack = HelloAck {
            v: Hello::new(7, 3).v,
            launch: 7,
            generation: 3,
            pid: 1,
        };
        assert_ok!(theirs.write_all(&assert_ok!(encode_line(&ack))));
        assert_ok!(theirs.write_all(b"not a frame\n"));
        assert!(matches!(
            assert_ok!(rx.recv_timeout(Duration::from_secs(5))),
            Msg::ChannelBroken { .. }
        ));
        let drained = theirs.write_all(&vec![b'x'; 1024 * 1024]);
        drop(theirs);
        assert_ok!(worker.join());
        assert_ok!(drained);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn malformed_suffix_is_not_normal_eof_after_a_complete_report() {
        use crate::session::supervised::{Cleanup, Event, Frame};
        let (ours, mut theirs) = assert_ok!(UnixStream::pair());
        let ack = HelloAck {
            v: Hello::new(7, 3).v,
            launch: 7,
            generation: 3,
            pid: 1,
        };
        assert_ok!(theirs.write_all(&assert_ok!(encode_line(&ack))));
        let frame = Frame {
            seq: 1,
            event: Event::Exited {
                code: Some(0),
                signal: None,
                cleanup: Cleanup::Complete {},
            },
        };
        assert_ok!(theirs.write_all(&assert_ok!(encode_line(&frame))));
        assert_ok!(theirs.write_all(b"not a frame\n"));
        assert_ok!(theirs.shutdown(Shutdown::Write));
        let (tx, rx) = sync_channel(4);
        read_channel(SessionId(7), 3, ours, &tx, &AtomicBool::new(false));
        assert!(matches!(assert_ok!(rx.try_recv()), Msg::Channel { .. }));
        assert!(matches!(
            assert_ok!(rx.try_recv()),
            Msg::ChannelBroken { .. }
        ));
    }

    /// What the app would be sent when `hb` answers the handshake with `ack` and then says
    /// nothing more and closes.
    fn after_ack(ack: &HelloAck) -> Vec<Msg> {
        let (ours, mut theirs) = assert_ok!(UnixStream::pair());
        let (tx, rx) = sync_channel(8);
        let line = assert_ok!(encode_line(ack));
        assert_ok!(theirs.write_all(&line));
        drop(theirs);
        read_channel(SessionId(7), 3, ours, &tx, &AtomicBool::new(false));
        drop(tx);
        rx.iter().collect()
    }

    #[test]
    fn an_answer_for_this_launch_and_generation_is_accepted_and_the_close_is_a_loss() {
        let ack = HelloAck {
            v: Hello::new(7, 3).v,
            launch: 7,
            generation: 3,
            pid: 1,
        };
        assert_eq!(
            after_ack(&ack),
            vec![Msg::ChannelLost {
                id: SessionId(7),
                generation: 3
            }]
        );
    }

    #[test]
    fn an_answer_for_another_generation_or_launch_is_not_accepted_and_nothing_follows_it() {
        // The frame after a wrong handshake must never reach the app, only the loss.
        for (launch, generation) in [(7, 2), (8, 3)] {
            let (ours, mut theirs) = assert_ok!(UnixStream::pair());
            let (tx, rx) = sync_channel(8);
            let ack = HelloAck {
                v: Hello::new(7, 3).v,
                launch,
                generation,
                pid: 1,
            };
            assert_ok!(theirs.write_all(&assert_ok!(encode_line(&ack))));
            let frame = assert_ok!(encode_line(&crate::session::supervised::Frame {
                seq: 1,
                event: crate::session::supervised::Event::Starting {},
            }));
            assert_ok!(theirs.write_all(&frame));
            drop(theirs);
            read_channel(SessionId(7), 3, ours, &tx, &AtomicBool::new(false));
            drop(tx);
            let got: Vec<Msg> = rx.iter().collect();
            assert_eq!(
                got,
                vec![Msg::ChannelLost {
                    id: SessionId(7),
                    generation: 3
                }],
                "launch {launch} generation {generation}"
            );
        }
    }

    #[test]
    fn a_reader_blocked_on_a_full_inbox_ends_when_its_worker_is_abandoned() {
        let (ours, mut theirs) = assert_ok!(UnixStream::pair());
        // An inbox of one that nobody reads: the second frame has nowhere to go.
        let (tx, rx) = sync_channel(1);
        let kill = Arc::new(AtomicBool::new(false));
        let ack = HelloAck {
            v: Hello::new(7, 3).v,
            launch: 7,
            generation: 3,
            pid: 1,
        };
        assert_ok!(theirs.write_all(&assert_ok!(encode_line(&ack))));
        for seq in 1..=3 {
            let frame = assert_ok!(encode_line(&crate::session::supervised::Frame {
                seq,
                event: crate::session::supervised::Event::Starting {},
            }));
            assert_ok!(theirs.write_all(&frame));
        }
        let reader = {
            let kill = Arc::clone(&kill);
            thread::spawn(move || read_channel(SessionId(7), 3, ours, &tx, &kill))
        };
        thread::sleep(Duration::from_millis(200));
        assert!(
            !reader.is_finished(),
            "it should be waiting on the full inbox"
        );
        kill.store(true, Ordering::Release);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !reader.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            reader.is_finished(),
            "a cancelled reader must not stay blocked on the inbox"
        );
        drop(rx);
    }

    // ========================================================================
    // The reaper never reports an exit it did not see
    // ========================================================================

    /// A process whose `try_wait` fails, and which records being killed and waited for.
    #[derive(Default)]
    struct Broken {
        killed: bool,
        waited: bool,
    }

    impl Process for Broken {
        fn try_wait(&mut self) -> io::Result<Option<std::process::ExitStatus>> {
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
        fn kill(&mut self) -> io::Result<()> {
            self.killed = true;
            Ok(())
        }
        fn wait(&mut self) -> io::Result<std::process::ExitStatus> {
            self.waited = true;
            Err(io::Error::from(io::ErrorKind::PermissionDenied))
        }
    }

    fn reap_with(
        child: &mut impl Process,
        reader: JoinHandle<()>,
    ) -> (Vec<Msg>, Arc<Outbox>, bool) {
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        let (tx, rx) = sync_channel(8);
        let outbox = Arc::new(Outbox::new());
        let asked = Mutex::new(None);
        let kill = AtomicBool::new(false);
        reap(
            SessionId(4),
            2,
            child,
            reader,
            &Stopping {
                asked: &asked,
                kill: &kill,
                outbox: &outbox,
                channel: &ours,
            },
            &tx,
        );
        drop(tx);
        // The channel was closed by the reaper: the far end sees the end of the stream.
        let mut far = theirs;
        far.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let closed = std::io::Read::read(&mut far, &mut [0u8; 1]).is_ok_and(|n| n == 0);
        (rx.iter().collect(), outbox, closed)
    }

    #[test]
    fn a_process_that_cannot_be_waited_for_is_killed_and_reported_lost_never_exited() {
        let mut child = Broken::default();
        let reader = thread::spawn(|| {});
        let (messages, outbox, channel_closed) = reap_with(&mut child, reader);
        assert!(child.killed && child.waited, "it must be killed and reaped");
        assert!(channel_closed, "the channel must be closed so hb stops too");
        assert!(outbox.is_cancelled());
        assert_eq!(messages.len(), 1, "{messages:?}");
        match &messages[0] {
            Msg::SessionLost {
                id,
                generation,
                reason,
            } => {
                assert_eq!((*id, *generation), (SessionId(4), 2));
                assert!(reason.contains("could not be read"), "{reason}");
            }
            other => assert_ok!(Err::<(), String>(format!(
                "expected SessionLost, got {other:?}"
            ))),
        }
    }

    #[test]
    fn a_reader_that_panicked_is_reported_lost_even_though_the_process_exited() {
        let mut child = assert_ok!(std::process::Command::new("/usr/bin/true").spawn());
        let reader = thread::spawn(|| std::panic::resume_unwind(Box::new("boom")));
        // The hook would print the panic; this one is expected.
        let (messages, _, _) = reap_with(&mut child, reader);
        assert_eq!(messages.len(), 1, "{messages:?}");
        assert!(
            matches!(&messages[0], Msg::SessionLost { reason, .. } if reason.contains("panicked")),
            "{messages:?}"
        );
    }

    #[test]
    fn an_exit_that_was_seen_is_reported_with_its_code() {
        let mut child = assert_ok!(
            std::process::Command::new("/bin/sh")
                .args(["-c", "exit 7"])
                .spawn()
        );
        let (messages, _, _) = reap_with(&mut child, thread::spawn(|| {}));
        assert_eq!(
            messages,
            vec![Msg::ProcessExited {
                id: SessionId(4),
                generation: 2,
                code: Some(7),
                signal: None
            }]
        );
    }

    #[test]
    fn frames_waiting_on_a_full_inbox_are_still_delivered_when_hb_exits_normally() {
        // hb wrote its last reports and exited; the app is slow to read them. The reaper must not
        // cancel delivery of reports that hb already sent, or an ApprovalRequired or a final
        // failure can be lost while the exit is still reported.
        let (ours, mut theirs) = assert_ok!(UnixStream::pair());
        let (tx, rx) = sync_channel(1);
        let outbox = Arc::new(Outbox::new());
        let ack = HelloAck {
            v: Hello::new(4, 2).v,
            launch: 4,
            generation: 2,
            pid: 1,
        };
        assert_ok!(theirs.write_all(&assert_ok!(encode_line(&ack))));
        for seq in 1..=3 {
            let frame = assert_ok!(encode_line(&crate::session::supervised::Frame {
                seq,
                event: crate::session::supervised::Event::Starting {},
            }));
            assert_ok!(theirs.write_all(&frame));
        }
        // hb has exited: its end of the channel is closed after the three frames.
        drop(theirs);
        let reader_kill = Arc::new(AtomicBool::new(false));
        let reader_tx = tx.clone();
        let reader = thread::spawn(move || {
            read_channel(SessionId(4), 2, ours, &reader_tx, &reader_kill);
        });
        // The reader delivers frame 1 into the inbox of one and waits on frame 2.
        thread::sleep(Duration::from_millis(150));
        let mut child = assert_ok!(std::process::Command::new("/usr/bin/true").spawn());
        let (ours2, _theirs2) = assert_ok!(UnixStream::pair());
        let asked = Mutex::new(None);
        let kill = AtomicBool::new(false);
        // The app drains slowly, after the reaper has already seen hb exit.
        let drain = thread::spawn(move || {
            thread::sleep(Duration::from_millis(400));
            let mut got = Vec::new();
            while let Ok(msg) = rx.recv_timeout(Duration::from_secs(3)) {
                got.push(msg);
                if matches!(
                    got.last(),
                    Some(Msg::ProcessExited { .. } | Msg::SessionLost { .. })
                ) {
                    break;
                }
            }
            got
        });
        reap(
            SessionId(4),
            2,
            &mut child,
            reader,
            &Stopping {
                asked: &asked,
                kill: &kill,
                outbox: &outbox,
                channel: &ours2,
            },
            &tx,
        );
        drop(tx);
        let got = assert_ok!(drain.join());
        let seqs: Vec<u64> = got
            .iter()
            .filter_map(|m| match m {
                Msg::Channel { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect();
        assert_eq!(seqs, vec![1, 2, 3], "frames hb sent were lost: {got:?}");
        assert!(
            matches!(got.last(), Some(Msg::ProcessExited { .. })),
            "the exit comes last: {got:?}"
        );
    }
}
