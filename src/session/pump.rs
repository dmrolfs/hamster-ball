// ABOUTME: Copies one of the agent's output streams to the user's terminal through the sanitizer, when there is no pty.
// ABOUTME: One thread per stream; it ends when the stream does, or soon after the agent has, so a lingering writer cannot hang a run.
//! The output filter for a run without a pty (design 7.3, D67).
//!
//! With no pty the agent would write straight to the user's terminal, past the filter. When a
//! stream is a terminal, the agent is given a pipe instead, and this copies the pipe to the
//! terminal through the same [`Sanitizer`] the relay uses. The agent then sees a stdout that is
//! not a terminal, which is what a batch or print-mode run expects.

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Instant;

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use super::relay::{BUFFER, Drain, TICK_MS, end_of_output};
use super::sanitize::{ClipboardPolicy, ClipboardUse, Sanitizer};

/// A running copy of one stream to the terminal. Call [`Pump::finish`] after the agent has ended.
#[derive(Debug)]
pub struct Pump {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<ClipboardUse>,
}

impl Pump {
    /// Starts copying `source` (the agent's end of a stream) to `sink` (the user's terminal).
    ///
    /// # Errors
    /// [`io::Error`] if the thread cannot be started.
    pub fn start(source: OwnedFd, sink: OwnedFd) -> io::Result<Self> {
        Self::start_with(source, sink, ClipboardPolicy::default())
    }

    /// Like [`Pump::start`], with a policy for the agent's clipboard writes.
    ///
    /// # Errors
    /// [`io::Error`] if the thread cannot be started.
    pub fn start_with(
        source: OwnedFd,
        sink: OwnedFd,
        clipboard: ClipboardPolicy,
    ) -> io::Result<Self> {
        Self::spawn(source, sink, clipboard, Drain::default())
    }

    fn spawn(
        source: OwnedFd,
        sink: OwnedFd,
        clipboard: ClipboardPolicy,
        drain: Drain,
    ) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("hb-pump".to_owned())
            .spawn(move || {
                run(
                    File::from(source),
                    File::from(sink),
                    &flag,
                    clipboard,
                    drain,
                )
            })?;
        Ok(Self { stop, handle })
    }

    /// Tells the pump the agent has ended, lets it drain what is left, and waits for it.
    ///
    /// Returns what the agent did with the clipboard: writes let through, and writes removed.
    pub fn finish(self) -> ClipboardUse {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap_or_default()
    }
}

#[derive(Clone, Copy)]
struct DrainClock {
    started: Instant,
    last_output: Instant,
}

impl DrainClock {
    fn expired(self, now: Instant, ready: bool, drain: Drain) -> bool {
        (!ready && now.duration_since(self.last_output) >= drain.quiet)
            || now.duration_since(self.started) >= drain.max
    }
}

fn run(
    mut source: File,
    mut sink: File,
    stop: &AtomicBool,
    clipboard: ClipboardPolicy,
    drain: Drain,
) -> ClipboardUse {
    let mut filter = Sanitizer::with_clipboard(clipboard);
    let mut draining: Option<DrainClock> = None;
    let mut buffer = [0u8; BUFFER];
    loop {
        if stop.load(Ordering::Relaxed) && draining.is_none() {
            let now = Instant::now();
            draining = Some(DrainClock {
                started: now,
                last_output: now,
            });
        }
        let mut fds = [PollFd::new(source.as_fd(), PollFlags::POLLIN)];
        let ready = match poll(&mut fds, PollTimeout::from(TICK_MS)) {
            Ok(_) => fds[0].revents().is_some_and(|r| {
                r.intersects(PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR)
            }),
            Err(_) => false,
        };
        if ready {
            match source.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let delivery_started = Instant::now();
                    let mut clean = Vec::with_capacity(n);
                    filter.feed(&buffer[..n], &mut clean);
                    // The terminal may be gone; nothing useful to do about that here.
                    let _ = sink.write_all(&clean);
                    let _ = sink.flush();
                    if let Some(clock) = &mut draining {
                        // Terminal backpressure is not silence from the agent.
                        clock.started += delivery_started.elapsed();
                        clock.last_output = Instant::now();
                    }
                }
            }
        }
        if let Some(clock) = draining
            && clock.expired(Instant::now(), ready, drain)
        {
            break;
        }
    }
    end_of_output(&mut filter, &mut sink);
    filter.clipboard_use()
}

#[cfg(test)]
mod tests {
    use super::super::relay::{DRAIN_MAX, DRAIN_QUIET};
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    /// The agent's end, and what the terminal receives.
    struct Rig {
        agent: UnixStream,
        screen: UnixStream,
        pump: Pump,
    }

    fn rig() -> Rig {
        rig_draining(Drain::default())
    }

    fn rig_draining(drain: Drain) -> Rig {
        let (agent, theirs) = assert_ok!(UnixStream::pair());
        let (screen, sink) = assert_ok!(UnixStream::pair());
        assert_ok!(screen.set_read_timeout(Some(Duration::from_millis(300))));
        let pump = assert_ok!(Pump::spawn(
            OwnedFd::from(theirs),
            OwnedFd::from(sink),
            ClipboardPolicy::default(),
            drain
        ));
        Rig {
            agent,
            screen,
            pump,
        }
    }

    fn read_all(screen: &mut UnixStream) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut buffer = [0u8; 256];
        while let Ok(n) = screen.read(&mut buffer) {
            if n == 0 {
                break;
            }
            seen.extend_from_slice(&buffer[..n]);
        }
        seen
    }

    #[test]
    fn recent_output_restarts_quiet_time_without_extending_the_maximum() {
        let start = Instant::now();
        let clock = DrainClock {
            started: start,
            last_output: start + DRAIN_QUIET,
        };
        assert!(!clock.expired(
            start + DRAIN_QUIET + Duration::from_millis(1),
            false,
            Drain::default()
        ));
        assert!(clock.expired(start + DRAIN_QUIET * 2, false, Drain::default()));
        let busy = DrainClock {
            started: start,
            last_output: start + DRAIN_MAX,
        };
        assert!(busy.expired(start + DRAIN_MAX, true, Drain::default()));
    }

    #[test]
    fn plain_output_reaches_the_terminal_unchanged() {
        let mut rig = rig();
        let text = "line one\r\n\u{1b}[31mred\u{1b}[0m \u{4e16}\u{754c}\n".as_bytes();
        assert_ok!(rig.agent.write_all(text));
        drop(rig.agent);
        assert_eq!(read_all(&mut rig.screen), text);
        assert_eq!(rig.pump.finish(), ClipboardUse::default());
    }

    #[test]
    fn a_query_whose_reply_the_agent_could_shape_never_reaches_the_terminal() {
        let mut rig = rig();
        assert_ok!(
            rig.agent
                .write_all(b"a\x1b]0;t\x07\x1b[21tb\x1b]52;c;?\x07c")
        );
        drop(rig.agent);
        assert_eq!(read_all(&mut rig.screen), b"a\x1b]0;t\x07bc");
        rig.pump.finish();
    }

    #[test]
    fn a_sequence_split_between_reads_is_filtered_all_the_same() {
        let mut rig = rig();
        assert_ok!(rig.agent.write_all(b"x\x1b[2"));
        thread::sleep(Duration::from_millis(120));
        assert_ok!(rig.agent.write_all(b"1ty"));
        drop(rig.agent);
        assert_eq!(read_all(&mut rig.screen), b"xy");
        rig.pump.finish();
    }

    #[test]
    fn clipboard_writes_are_counted_and_a_sequence_left_open_is_cancelled() {
        let mut rig = rig();
        assert_ok!(rig.agent.write_all(b"\x1b]52;c;aGk=\x07\x1b]0;never ends"));
        drop(rig.agent);
        let seen = read_all(&mut rig.screen);
        assert!(seen.ends_with(b"\x18"), "{seen:?}");
        assert_eq!(rig.pump.finish().allowed, 1);
    }

    // Test scheduling slack; production limits are checked separately by the clock test.
    const SLOW_RUNNER: Drain = Drain {
        quiet: Duration::from_millis(900),
        max: Duration::from_millis(1500),
    };

    #[test]
    fn output_that_arrives_shortly_after_the_agent_ended_is_still_copied() {
        let mut rig = rig_draining(SLOW_RUNNER);
        let mut agent = assert_ok!(rig.agent.try_clone());
        let writer = thread::spawn(move || {
            // Exercise idle polls before the output arrives, within the test quiet window.
            thread::sleep(Duration::from_millis(250));
            let _ = agent.write_all(b"just in time");
        });
        assert_ok!(rig.screen.set_read_timeout(Some(Duration::from_secs(2))));
        rig.pump.finish();
        assert_ok!(writer.join().map_err(|_| "writer panicked"));
        assert_eq!(read_all(&mut rig.screen), b"just in time");
    }

    #[test]
    fn with_clipboard_writes_denied_none_reaches_the_terminal_and_finish_counts_the_blocked() {
        let (mut agent, theirs) = assert_ok!(UnixStream::pair());
        let (mut screen, sink) = assert_ok!(UnixStream::pair());
        assert_ok!(screen.set_read_timeout(Some(Duration::from_millis(300))));
        let pump = assert_ok!(Pump::start_with(
            OwnedFd::from(theirs),
            OwnedFd::from(sink),
            ClipboardPolicy::Deny
        ));
        assert_ok!(agent.write_all(b"a\x1b]52;c;aGk=\x07b"));
        drop(agent);
        assert_eq!(read_all(&mut screen), b"ab");
        assert_eq!(
            pump.finish(),
            ClipboardUse {
                allowed: 0,
                blocked: 1
            }
        );
    }

    #[test]
    fn a_writer_that_lingers_after_the_agent_ended_cannot_hang_the_end_of_the_run() {
        // A background process of the agent still holds the stream open and is quiet.
        let rig = rig();
        let started = Instant::now();
        rig.pump.finish();
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
        drop(rig.agent);
    }

    #[test]
    fn a_writer_that_never_stops_still_lets_the_run_end() {
        let mut rig = rig_draining(SLOW_RUNNER);
        let mut agent = assert_ok!(rig.agent.try_clone());
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let writer = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                if agent.write_all(b"noise").is_err() {
                    break;
                }
                // Leave idle polls between writes, without reaching the quiet limit.
                thread::sleep(Duration::from_millis(120));
            }
        });
        assert_ok!(rig.screen.set_read_timeout(Some(Duration::from_millis(20))));
        let drain = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(3);
            let mut buffer = [0u8; 256];
            while Instant::now() < end {
                let _ = rig.screen.read(&mut buffer);
            }
        });
        let started = Instant::now();
        rig.pump.finish();
        let took = started.elapsed();
        done.store(true, Ordering::Relaxed);
        let _ = writer.join();
        let _ = drain.join();
        assert!(
            took >= SLOW_RUNNER.max,
            "stream was cut off while still writing: {took:?}"
        );
        assert!(took < SLOW_RUNNER.max + Duration::from_secs(1), "{took:?}");
    }
}
