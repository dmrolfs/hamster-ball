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
use std::io::{BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use super::app::{Generation, Msg, SessionId};
use super::launch::Started;
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
    /// The session's terminal master: keys and pastes are written here.
    terminal: File,
    /// The supervisor's end of the channel: `Stop` is written here.
    channel: UnixStream,
    /// When a stop was asked for, so the reaper can kill a process that does not end.
    stop_asked: Arc<Mutex<Option<Instant>>>,
    threads: Vec<JoinHandle<()>>,
}

impl std::fmt::Debug for Worker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Worker(..)")
    }
}

/// Starts the three threads for a launched session and sends `hb` its handshake.
///
/// `messages` is the app's bounded inbox.
///
/// # Errors
/// An [`std::io::Error`] if a descriptor cannot be duplicated or a thread cannot start; the
/// process is killed and reaped in that case.
pub fn spawn(
    id: SessionId,
    generation: Generation,
    started: Started,
    shared: Arc<Shared>,
    messages: SyncSender<Msg>,
) -> std::io::Result<Worker> {
    let Started {
        mut child,
        channel,
        terminal,
    } = started;
    match spawn_threads(id, generation, &channel, &terminal, &shared, &messages) {
        Ok((mut threads, channel_reader)) => {
            let stop_asked = Arc::new(Mutex::new(None));
            let asked = Arc::clone(&stop_asked);
            let inbox = messages.clone();
            // The child is shared with the reaper through a cell, so that if the thread cannot
            // start the child is still here to be killed rather than lost in an unrun closure.
            let cell = Arc::new(Mutex::new(Some(child)));
            let for_reaper = Arc::clone(&cell);
            let reaper = thread::Builder::new()
                .name(format!("hb-reap-{}", id.0))
                .spawn(move || {
                    let taken = for_reaper.lock().ok().and_then(|mut slot| slot.take());
                    if let Some(mut child) = taken {
                        reap(id, generation, &mut child, channel_reader, &asked, &inbox);
                    }
                });
            match reaper {
                Ok(handle) => threads.push(handle),
                Err(error) => {
                    if let Some(mut child) = cell.lock().ok().and_then(|mut slot| slot.take()) {
                        let _ = child.kill();
                        let _ = child.wait();
                    }
                    return Err(error);
                }
            }
            Ok(Worker {
                shared,
                terminal,
                channel,
                stop_asked,
                threads,
            })
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error)
        }
    }
}

/// The PTY reader and the channel reader; the channel reader's handle is returned separately so
/// the reaper can wait for it.
fn spawn_threads(
    id: SessionId,
    generation: Generation,
    channel: &UnixStream,
    terminal: &File,
    shared: &Arc<Shared>,
    messages: &SyncSender<Msg>,
) -> std::io::Result<(Vec<JoinHandle<()>>, JoinHandle<()>)> {
    let mut hello = channel.try_clone()?;
    let line =
        encode_line(&Hello::new(u64::from(id.0), generation)).map_err(std::io::Error::other)?;
    hello.write_all(&line)?;
    let reader = channel.try_clone()?;
    let mut terminal = terminal.try_clone()?;
    let feed = Arc::clone(shared);
    let pty_thread = thread::Builder::new()
        .name(format!("hb-pty-{}", id.0))
        .spawn(move || {
            let mut buffer = [0u8; 8192];
            while let Ok(n) = terminal.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if let Ok(mut screen) = feed.screen.lock() {
                    screen.process(&buffer[..n]);
                }
                feed.dirty.store(true, Ordering::Release);
            }
        })?;
    let inbox = messages.clone();
    let channel_thread = thread::Builder::new()
        .name(format!("hb-chan-{}", id.0))
        .spawn(move || read_channel(id, generation, reader, &inbox))?;
    Ok((vec![pty_thread], channel_thread))
}

/// Waits for `hb`, then for the channel reader, then reports the exit.
///
/// The `Exited` event is the last frame `hb` writes and is in the socket before `hb` exits, so
/// once the reader has seen the end of the channel the app has been sent everything `hb` said.
/// A process that is still there a grace period after a stop is killed.
fn reap(
    id: SessionId,
    generation: Generation,
    child: &mut std::process::Child,
    channel_reader: JoinHandle<()>,
    stop_asked: &Mutex<Option<Instant>>,
    inbox: &SyncSender<Msg>,
) {
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
        let overdue = stop_asked
            .lock()
            .ok()
            .and_then(|asked| *asked)
            .is_some_and(|at| at.elapsed() >= STOP_GRACE);
        if overdue {
            let _ = child.kill();
        }
        thread::sleep(REAP_POLL);
    };
    // The reader ends when `hb` closes its end, which it does as it exits; a descendant that kept
    // the channel open is not a case: `hb` closes it close-on-exec and the agent never held it.
    let _ = channel_reader.join();
    let (code, signal) = match status {
        Some(status) => (
            status.code(),
            std::os::unix::process::ExitStatusExt::signal(&status),
        ),
        None => (None, None),
    };
    let _ = inbox.send(Msg::ProcessExited {
        id,
        generation,
        code,
        signal,
    });
}

impl Worker {
    /// Writes `bytes` to the agent's terminal.
    ///
    /// # Errors
    /// An [`std::io::Error`] if the terminal is gone.
    pub fn write_input(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.terminal.write_all(bytes)
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
    pub fn stop(&mut self) {
        if let Ok(mut asked) = self.stop_asked.lock() {
            asked.get_or_insert_with(Instant::now);
        }
        if let Ok(line) = encode_line(&Command::Stop {}) {
            let _ = self.channel.write_all(&line);
        }
    }

    /// Closes the channel, which `hb` treats as a stop, and waits for the threads to end, for at
    /// most `limit` in all. Returns whether all of them did.
    pub fn shut_down(self, limit: Duration) -> bool {
        let _ = self.channel.shutdown(Shutdown::Both);
        let deadline = Instant::now() + limit;
        for handle in self.threads {
            while !handle.is_finished() {
                if Instant::now() > deadline {
                    return false;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let _ = handle.join();
        }
        true
    }
}

/// Reads frames until the channel ends and sends each to the app, in order.
fn read_channel(
    id: SessionId,
    generation: Generation,
    stream: UnixStream,
    inbox: &SyncSender<Msg>,
) {
    let mut reader = BufReader::new(stream);
    // The acknowledgement comes first; anything else, or none, is a lost channel.
    let acknowledged =
        matches!(read_line(&mut reader), Ok(Some(line)) if decode_ack(&line).is_ok());
    if acknowledged {
        while let Ok(Some(line)) = read_line(&mut reader) {
            let Ok(frame) = decode_frame(&line) else {
                break;
            };
            let msg = Msg::Channel {
                id,
                generation,
                seq: frame.seq,
                event: frame.event,
            };
            // Blocks when the app is behind: the socket then fills and `hb` drops telemetry.
            if inbox.send(msg).is_err() {
                return;
            }
        }
    }
    let _ = inbox.send(Msg::ChannelLost { id, generation });
}
