// ABOUTME: Bounded, serialized request/reply transport for the cleanup guardian.
// ABOUTME: A failed admitted transaction shuts down every clone so stale replies cannot be reused.
//! Private guardian transport; the owner retains a shutdown capability outside the lock.

use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Mutex, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use super::guardian::GuardianError;

pub(super) const DEADLINE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(5);
/// The longest frame either side sends, newline included.
pub(super) const MAX_FRAME: usize = 160;

#[derive(Debug)]
struct Transaction {
    stream: UnixStream,
    next: u64,
}

#[derive(Debug)]
pub(super) struct Channel {
    transaction: Mutex<Transaction>,
    shutdown: UnixStream,
}

impl Channel {
    pub(super) fn new(stream: UnixStream) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
        Ok(Self {
            shutdown: stream.try_clone()?,
            transaction: Mutex::new(Transaction { stream, next: 1 }),
        })
    }

    pub(super) fn close(&self) {
        let _ = self.shutdown.shutdown(Shutdown::Both);
    }

    pub(super) fn request(&self, command: &str) -> Result<String, GuardianError> {
        self.request_until(command, Instant::now() + DEADLINE)
    }

    pub(super) fn request_until(
        &self,
        command: &str,
        by: Instant,
    ) -> Result<String, GuardianError> {
        let deadline = by.min(Instant::now() + DEADLINE);
        if Instant::now() >= deadline {
            return Err(GuardianError::Deadline);
        }
        let mut state = loop {
            match self.transaction.try_lock() {
                Ok(state) => break state,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => thread::sleep(POLL),
                Err(TryLockError::WouldBlock) => return Err(GuardianError::Deadline),
                Err(TryLockError::Poisoned(_)) => {
                    self.close();
                    return Err(GuardianError::Protocol);
                }
            }
        };
        let id = state.next;
        let frame = format!("ack {id} {command}\n");
        // Refused before anything is written, so the channel stays usable for other callers.
        if frame.len() > MAX_FRAME {
            return Err(GuardianError::TooLong);
        }
        let result = (|| {
            state.next = id.checked_add(1).ok_or(GuardianError::Protocol)?;
            write_bounded(&mut state.stream, frame.as_bytes(), deadline)
                .map_err(|source| GuardianError::Tell { source })?;
            let reply = read_bounded(&mut state.stream, deadline)
                .map_err(|source| GuardianError::Tell { source })?;
            let (reply_id, outcome) = reply.split_once(' ').ok_or(GuardianError::Protocol)?;
            if reply_id.parse::<u64>().ok() != Some(id) {
                return Err(GuardianError::Protocol);
            }
            Ok(outcome.to_owned())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}

fn write_bounded(writer: &mut impl Write, mut bytes: &[u8], deadline: Instant) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match writer.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn read_bounded(reader: &mut impl Read, deadline: Instant) -> io::Result<String> {
    let mut frame = Vec::new();
    let mut byte = [0];
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        match reader.read(&mut byte) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(_) if byte[0] == b'\n' => return String::from_utf8(frame).map_err(io::Error::other),
            Ok(_) if frame.len() < MAX_FRAME => frame.push(byte[0]),
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::io::{BufRead, BufReader};

    /// A fake guard that answers each request with `reply(id)`.
    fn fake(reply: impl Fn(u64) -> String + Send + 'static) -> (Channel, thread::JoinHandle<()>) {
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        let worker = thread::spawn(move || {
            let mut writer = match theirs.try_clone() {
                Ok(writer) => writer,
                Err(_) => return,
            };
            for line in BufReader::new(theirs).lines().map_while(Result::ok) {
                let id = line
                    .split_whitespace()
                    .nth(1)
                    .and_then(|i| i.parse().ok())
                    .unwrap_or(0);
                if writer.write_all(reply(id).as_bytes()).is_err() {
                    return;
                }
            }
        });
        (assert_ok!(Channel::new(ours)), worker)
    }

    #[test]
    fn a_matching_reply_is_returned_and_ids_advance() {
        let (channel, worker) = fake(|id| format!("{id} ok\n"));
        assert_eq!(assert_ok!(channel.request("release")), "ok");
        assert_eq!(assert_ok!(channel.request("release")), "ok");
        channel.close();
        let _ = worker.join();
    }

    #[test]
    fn a_reply_for_another_request_closes_the_channel_for_every_caller() {
        let (channel, worker) = fake(|id| format!("{} armed\n", id + 1));
        assert!(matches!(
            channel.request("release"),
            Err(GuardianError::Protocol)
        ));
        // The channel is shut down, so no later caller can read a stale reply.
        assert_err!(channel.request("release"));
        let _ = worker.join();
    }

    #[test]
    fn an_oversized_reply_is_rejected() {
        let (channel, worker) = fake(|_| format!("{}\n", "x".repeat(MAX_FRAME * 2)));
        assert!(matches!(
            channel.request("release"),
            Err(GuardianError::Tell { .. })
        ));
        let _ = worker.join();
    }

    #[test]
    fn a_silent_guard_is_a_deadline_error_not_a_hang() {
        let (ours, _theirs) = assert_ok!(UnixStream::pair());
        let channel = assert_ok!(Channel::new(ours));
        let started = Instant::now();
        assert!(matches!(
            channel.request("release"),
            Err(GuardianError::Tell { .. })
        ));
        assert!(started.elapsed() < DEADLINE + Duration::from_secs(1));
    }

    #[test]
    fn a_too_long_command_is_refused_without_closing_the_channel() {
        let (channel, worker) = fake(|id| format!("{id} ok\n"));
        let long = "x".repeat(MAX_FRAME);
        assert!(matches!(
            channel.request(&long),
            Err(GuardianError::TooLong)
        ));
        assert_eq!(assert_ok!(channel.request("release")), "ok");
        channel.close();
        let _ = worker.join();
    }
}
