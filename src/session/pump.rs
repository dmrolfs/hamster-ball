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

use super::relay::{BUFFER, DRAIN_MAX, DRAIN_QUIET, TICK_MS, end_of_output};
use super::sanitize::Sanitizer;

/// A running copy of one stream to the terminal. Call [`Pump::finish`] after the agent has ended.
#[derive(Debug)]
pub struct Pump {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<usize>,
}

impl Pump {
    /// Starts copying `source` (the agent's end of a stream) to `sink` (the user's terminal).
    ///
    /// # Errors
    /// [`io::Error`] if the thread cannot be started.
    pub fn start(source: OwnedFd, sink: OwnedFd) -> io::Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("hb-pump".to_owned())
            .spawn(move || run(File::from(source), File::from(sink), &flag))?;
        Ok(Self { stop, handle })
    }

    /// Tells the pump the agent has ended, lets it drain what is left, and waits for it.
    ///
    /// Returns how many clipboard writes went through.
    pub fn finish(self) -> usize {
        self.stop.store(true, Ordering::Relaxed);
        self.handle.join().unwrap_or(0)
    }
}

fn run(mut source: File, mut sink: File, stop: &AtomicBool) -> usize {
    let mut filter = Sanitizer::new();
    let mut draining_since: Option<Instant> = None;
    let mut buffer = [0u8; BUFFER];
    loop {
        if stop.load(Ordering::Relaxed) && draining_since.is_none() {
            draining_since = Some(Instant::now());
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
                    let mut clean = Vec::with_capacity(n);
                    filter.feed(&buffer[..n], &mut clean);
                    // The terminal may be gone; nothing useful to do about that here.
                    let _ = sink.write_all(&clean);
                    let _ = sink.flush();
                }
            }
        }
        if let Some(since) = draining_since {
            if !ready && since.elapsed() >= DRAIN_QUIET || since.elapsed() >= DRAIN_MAX {
                break;
            }
        }
    }
    end_of_output(&mut filter, &mut sink);
    filter.clipboard_writes()
}

#[cfg(test)]
mod tests {
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
        let (agent, theirs) = assert_ok!(UnixStream::pair());
        let (screen, sink) = assert_ok!(UnixStream::pair());
        assert_ok!(screen.set_read_timeout(Some(Duration::from_millis(300))));
        let pump = assert_ok!(Pump::start(OwnedFd::from(theirs), OwnedFd::from(sink)));
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
    fn plain_output_reaches_the_terminal_unchanged() {
        let mut rig = rig();
        let text = "line one\r\n\u{1b}[31mred\u{1b}[0m \u{4e16}\u{754c}\n".as_bytes();
        assert_ok!(rig.agent.write_all(text));
        drop(rig.agent);
        assert_eq!(read_all(&mut rig.screen), text);
        assert_eq!(rig.pump.finish(), 0);
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
        assert_eq!(rig.pump.finish(), 1);
    }

    #[test]
    fn output_that_arrives_shortly_after_the_agent_ended_is_still_copied() {
        let mut rig = rig();
        let mut agent = assert_ok!(rig.agent.try_clone());
        let writer = thread::spawn(move || {
            // After the pump's first idle poll of the drain (50 ms) and inside its quiet window (150 ms).
            thread::sleep(Duration::from_millis(110));
            let _ = agent.write_all(b"just in time");
        });
        assert_ok!(
            rig.screen
                .set_read_timeout(Some(Duration::from_millis(600)))
        );
        rig.pump.finish();
        assert_ok!(writer.join().map_err(|_| "writer panicked"));
        assert_eq!(read_all(&mut rig.screen), b"just in time");
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
        let mut rig = rig();
        let mut agent = assert_ok!(rig.agent.try_clone());
        let done = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&done);
        let writer = thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                if agent.write_all(b"noise").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
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
        assert!(took < DRAIN_MAX + Duration::from_secs(1), "{took:?}");
    }
}
