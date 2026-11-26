// ABOUTME: The hb side of the supervisor channel: handshake, a writer thread with a reserved lifecycle queue and a bounded telemetry queue, and stop on disconnect.
// ABOUTME: No caller ever blocks on the supervisor: telemetry overflow is counted, a stalled or closed channel stops the run.
//! Reporting to `hb-supervise` (epic hb-b6q).
//!
//! [`Reporter::connect`] answers the supervisor's handshake, then starts two threads: one that
//! writes frames and one that reads commands. Everything else only pushes onto queues:
//!
//! - Lifecycle events ([`Reporter::lifecycle`]) have a small queue of their own that telemetry
//!   cannot fill. If even that fills, the writer is stalled and the run is stopped, because a
//!   supervisor that cannot learn what its session is doing must not be left running it.
//! - Telemetry ([`Telemetry`], the denial and proxy callbacks) has a bounded queue. When it is
//!   full the event is counted, and the next frame sent is an [`Event::Dropped`] with the counts.
//!   Pushing never waits, so [`crate::proxy::AuditSink::record`] and the denial callbacks never
//!   block on the supervisor.
//! - A write that fails or takes longer than the write timeout, end of input, or a malformed
//!   command all call [`StopSignal::request`]. That is the same path as SIGTERM, including
//!   during the pre-run hooks.

use std::collections::VecDeque;
use std::io::{BufReader, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use snafu::{ResultExt, Snafu};

use super::signals::StopSignal;
use super::supervised::{
    Command, Event, HelloAck, ProtocolError, decode_command, decode_hello, encode_frame,
    encode_line, read_line,
};
use crate::proxy::AuditEvent;

/// How long a write may take before the supervisor is treated as gone.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(2);
/// How long the supervisor has to send its handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// The most lifecycle events waiting for the writer.
const LIFECYCLE_CAPACITY: usize = 32;
/// The most telemetry events waiting for the writer.
pub const TELEMETRY_CAPACITY: usize = 256;
/// Telemetry written between looks at the lifecycle queue.
const BATCH: usize = 64;

/// Why the channel could not be set up.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ChannelError {
    /// The supervisor's handshake was missing, late or wrong.
    #[snafu(display("the supervisor's handshake was not accepted"))]
    Handshake {
        /// What was wrong with it.
        source: ProtocolError,
    },
    /// The handshake could not be read, or its answer written.
    #[snafu(display("the supervisor channel could not be used"))]
    Io {
        /// The OS error.
        source: std::io::Error,
    },
    /// The handshake answer could not be built.
    #[snafu(display("the handshake answer could not be built"))]
    Answer {
        /// The encoder's error.
        source: ProtocolError,
    },
    /// A thread could not be started.
    #[snafu(display("a channel thread could not be started"))]
    Thread {
        /// The OS error.
        source: std::io::Error,
    },
}

#[derive(Default)]
struct Queues {
    lifecycle: VecDeque<Event>,
    telemetry: VecDeque<Event>,
    dropped_denials: u64,
    dropped_proxy: u64,
    /// The closing event, sent after everything else.
    last: Option<Event>,
    closing: bool,
    broken: bool,
}

struct Shared {
    queues: Mutex<Queues>,
    wake: Condvar,
    stop: Arc<StopSignal>,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queues> {
        // A poisoned lock means a thread panicked while queuing; the data is still consistent.
        self.queues.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn break_channel(&self) {
        self.lock().broken = true;
        self.wake.notify_all();
        self.stop.request();
    }
}

/// What the writer takes next.
struct Batch {
    events: Vec<Event>,
    /// Nothing more will come: the closing event, if any, is the last of `events`.
    finished: bool,
}

impl Shared {
    /// Waits for work. Lifecycle first, then the drop counts, then up to [`BATCH`] telemetry; the
    /// closing event only once everything else has been taken.
    fn next_batch(&self) -> Option<Batch> {
        let mut q = self.lock();
        loop {
            if q.broken {
                return None;
            }
            let mut events: Vec<Event> = q.lifecycle.drain(..).collect();
            if q.dropped_denials > 0 || q.dropped_proxy > 0 {
                events.push(Event::Dropped {
                    denials: std::mem::take(&mut q.dropped_denials),
                    proxy: std::mem::take(&mut q.dropped_proxy),
                });
            }
            let take = q.telemetry.len().min(BATCH);
            events.extend(q.telemetry.drain(..take));
            let finished = q.closing && q.telemetry.is_empty();
            if finished {
                events.extend(q.last.take());
            }
            if finished || !events.is_empty() {
                return Some(Batch { events, finished });
            }
            q = self.wake.wait(q).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// A cheap handle for the threads that produce telemetry.
#[derive(Clone)]
pub struct Telemetry(Arc<Shared>);

impl Telemetry {
    fn push(&self, event: Event, denial: bool) {
        let mut q = self.0.lock();
        if q.broken || q.closing {
            return;
        }
        if q.telemetry.len() >= TELEMETRY_CAPACITY {
            if denial {
                q.dropped_denials += 1;
            } else {
                q.dropped_proxy += 1;
            }
        } else {
            q.telemetry.push_back(event);
        }
        drop(q);
        self.0.wake.notify_one();
    }

    /// Reports one sandbox or proxy denial line. Never waits.
    pub fn denial(&self, line: &str) {
        self.push(Event::denial(line), true);
    }

    /// Reports one finished proxy connection. Never waits.
    pub fn proxy(&self, audit: &AuditEvent) {
        self.push(Event::proxy(audit), false);
    }
}

/// The connection to the supervisor. Dropping it without [`Reporter::finish`] closes it.
pub struct Reporter {
    shared: Arc<Shared>,
    stream: UnixStream,
    writer: Option<JoinHandle<()>>,
    reader: Option<JoinHandle<()>>,
}

impl Reporter {
    /// Answers the supervisor's handshake on `stream` and starts the channel threads.
    ///
    /// # Errors
    /// [`ChannelError`] if the handshake is missing, late, of another version or malformed.
    pub fn connect(stream: UnixStream, stop: Arc<StopSignal>) -> Result<Self, ChannelError> {
        Self::connect_with(stream, stop, WRITE_TIMEOUT)
    }

    /// [`Reporter::connect`] with the write timeout spelled out.
    ///
    /// # Errors
    /// As [`Reporter::connect`].
    pub fn connect_with(
        stream: UnixStream,
        stop: Arc<StopSignal>,
        write_timeout: Duration,
    ) -> Result<Self, ChannelError> {
        stream
            .set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .context(IoSnafu)?;
        stream
            .set_write_timeout(Some(write_timeout))
            .context(IoSnafu)?;
        let mut reader = BufReader::new(stream.try_clone().context(IoSnafu)?);
        let line = read_line(&mut reader)
            .context(HandshakeSnafu)?
            .ok_or(ProtocolError::Truncated)
            .context(HandshakeSnafu)?;
        let hello = decode_hello(&line).context(HandshakeSnafu)?;
        let ack = HelloAck {
            v: hello.v,
            launch: hello.launch,
            generation: hello.generation,
            pid: std::process::id(),
        };
        let mut writer_end = stream.try_clone().context(IoSnafu)?;
        writer_end
            .write_all(&encode_line(&ack).context(AnswerSnafu)?)
            .context(IoSnafu)?;
        // Commands may come at any time after this, so the read has no timeout.
        stream.set_read_timeout(None).context(IoSnafu)?;
        let shared = Arc::new(Shared {
            queues: Mutex::new(Queues::default()),
            wake: Condvar::new(),
            stop,
        });
        let writer = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("hb-report-write".to_owned())
                .spawn(move || write_loop(&mut writer_end, &shared))
                .context(ThreadSnafu)?
        };
        let reader = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("hb-report-read".to_owned())
                .spawn(move || read_loop(&mut reader, &shared))
                .context(ThreadSnafu)?
        };
        Ok(Self {
            shared,
            stream,
            writer: Some(writer),
            reader: Some(reader),
        })
    }

    /// A handle for the denial and proxy callbacks.
    #[must_use]
    pub fn telemetry(&self) -> Telemetry {
        Telemetry(Arc::clone(&self.shared))
    }

    /// Reports a lifecycle event. Never waits; if the writer is so far behind that even this
    /// queue is full, the run is stopped.
    pub fn lifecycle(&self, event: Event) {
        let mut q = self.shared.lock();
        if q.broken || q.closing {
            return;
        }
        if q.lifecycle.len() >= LIFECYCLE_CAPACITY {
            drop(q);
            self.shared.break_channel();
            return;
        }
        q.lifecycle.push_back(event);
        drop(q);
        self.shared.wake.notify_one();
    }

    /// Sends what is queued, then `exited`, and closes the channel. Waits at most about one write
    /// timeout, because the writer gives up on a supervisor that does not read.
    pub fn finish(mut self, exited: Event) {
        {
            let mut q = self.shared.lock();
            q.last = Some(exited);
            q.closing = true;
        }
        self.shared.wake.notify_all();
        self.close();
    }

    fn close(&mut self) {
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
        // Wakes the reader, which sees the end of input and, being closed, does not ask for a stop.
        self.shared.lock().closing = true;
        let _ = self.stream.shutdown(Shutdown::Both);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Reporter {
    fn drop(&mut self) {
        {
            let mut q = self.shared.lock();
            q.closing = true;
        }
        self.shared.wake.notify_all();
        self.close();
    }
}

fn write_loop(stream: &mut UnixStream, shared: &Shared) {
    let mut sent = 0u64;
    while let Some(batch) = shared.next_batch() {
        for event in batch.events {
            // An event that cannot be encoded is not sent and does not use a number.
            let Ok(line) = encode_frame(sent + 1, event) else {
                continue;
            };
            if stream.write_all(&line).is_err() {
                shared.break_channel();
                return;
            }
            sent += 1;
        }
        if batch.finished {
            return;
        }
    }
}

fn read_loop(reader: &mut BufReader<UnixStream>, shared: &Shared) {
    loop {
        let stopping = match read_line(reader) {
            Ok(Some(line)) => match decode_command(&line) {
                Ok(Command::Stop {}) => true,
                // A command that is not understood is not obeyed, and the channel is not trusted.
                Err(_) => true,
            },
            Ok(None) | Err(_) => true,
        };
        if stopping {
            if !shared.lock().closing {
                shared.stop.request();
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::supervised::{Frame, Hello, PROTOCOL_VERSION, decode_ack, decode_frame};
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::io::Read;
    use std::time::Instant;

    /// The supervisor's end, after a successful handshake.
    struct Peer {
        stream: UnixStream,
        reader: BufReader<UnixStream>,
    }

    impl Peer {
        fn frame(&mut self) -> Option<Frame> {
            let line = read_line(&mut self.reader).ok()??;
            Some(assert_ok!(decode_frame(&line)))
        }

        fn frames_until_end(&mut self) -> Vec<Frame> {
            std::iter::from_fn(|| self.frame()).collect()
        }
    }

    fn connect(write_timeout: Duration) -> (Reporter, Peer, Arc<StopSignal>) {
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        let mut peer_stream = assert_ok!(theirs.try_clone());
        assert_ok!(peer_stream.write_all(&assert_ok!(encode_line(&Hello::new(7, 2)))));
        let stop = StopSignal::new();
        let reporter = assert_ok!(Reporter::connect_with(
            ours,
            Arc::clone(&stop),
            write_timeout
        ));
        let mut reader = BufReader::new(theirs);
        let ack = assert_ok!(decode_ack(
            &assert_ok!(read_line(&mut reader)).unwrap_or_default()
        ));
        assert_eq!((ack.launch, ack.generation), (7, 2));
        assert_eq!(ack.pid, std::process::id());
        (
            reporter,
            Peer {
                stream: peer_stream,
                reader,
            },
            stop,
        )
    }

    #[test]
    fn events_arrive_in_order_with_rising_numbers_and_the_exit_is_last() {
        let (reporter, mut peer, stop) = connect(WRITE_TIMEOUT);
        reporter.lifecycle(Event::Starting {});
        reporter.lifecycle(Event::Running { agent_pid: 5 });
        reporter.telemetry().denial("deny a\u{1b}[2J");
        reporter.finish(Event::Stopping {});
        let frames = peer.frames_until_end();
        let kinds: Vec<_> = frames.iter().map(|f| f.event.kind().to_string()).collect();
        assert_eq!(kinds, ["starting", "running", "denial", "stopping"]);
        let seqs: Vec<_> = frames.iter().map(|f| f.seq).collect();
        assert_eq!(seqs, [1, 2, 3, 4]);
        assert!(!stop.is_requested(), "a normal finish must not ask to stop");
        assert_eq!(frames[2].event, Event::denial("deny a\u{1b}[2J"));
    }

    #[test]
    fn a_handshake_of_another_version_is_refused_and_nothing_is_sent() {
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        let mut theirs = theirs;
        assert_ok!(theirs.write_all(b"{\"v\":9,\"launch\":1,\"generation\":1}\n"));
        let result = Reporter::connect(ours, StopSignal::new());
        assert!(matches!(result, Err(ChannelError::Handshake { .. })));
        let mut rest = Vec::new();
        // `ours` was dropped with the failed connect, so this reads to the end at once.
        let _ = theirs.read_to_end(&mut rest);
        assert_eq!(rest, b"");
        assert_eq!(PROTOCOL_VERSION, 1);
    }

    #[test]
    fn a_supervisor_that_sends_no_handshake_is_not_waited_for_forever() {
        // Closing the peer is the quick form of "no handshake".
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        drop(theirs);
        assert!(Reporter::connect(ours, StopSignal::new()).is_err());
    }

    #[test]
    fn closing_the_channel_asks_the_run_to_stop() {
        let (_reporter, peer, stop) = connect(WRITE_TIMEOUT);
        drop(peer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stop.is_requested() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(stop.is_requested());
    }

    #[test]
    fn the_stop_command_and_a_command_that_is_not_understood_both_ask_the_run_to_stop() {
        for bytes in [
            &b"{\"cmd\":\"stop\"}\n"[..],
            &b"{\"cmd\":\"approve\"}\n"[..],
        ] {
            let (_reporter, mut peer, stop) = connect(WRITE_TIMEOUT);
            assert_ok!(peer.stream.write_all(bytes));
            let deadline = Instant::now() + Duration::from_secs(5);
            while !stop.is_requested() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(5));
            }
            assert!(stop.is_requested(), "{bytes:?}");
        }
    }

    #[test]
    fn telemetry_that_does_not_fit_is_counted_and_the_count_is_reported() {
        let shared = Shared {
            queues: Mutex::new(Queues::default()),
            wake: Condvar::new(),
            stop: StopSignal::new(),
        };
        let shared = Arc::new(shared);
        let telemetry = Telemetry(Arc::clone(&shared));
        for _ in 0..(TELEMETRY_CAPACITY + 5) {
            telemetry.denial("d");
        }
        for _ in 0..3 {
            telemetry.push(Event::warning("p"), false);
        }
        // The queue holds what fit; the rest is counted, split by kind.
        let mut events = Vec::new();
        while let Some(batch) = {
            let mut q = shared.lock();
            q.closing = true;
            drop(q);
            shared.next_batch()
        } {
            let done = batch.finished;
            events.extend(batch.events);
            if done {
                break;
            }
        }
        let dropped = events.iter().find_map(|e| match e {
            Event::Dropped { denials, proxy } => Some((*denials, *proxy)),
            _ => None,
        });
        assert_eq!(dropped, Some((5, 3)));
        let kept = events
            .iter()
            .filter(|e| matches!(e, Event::Denial { .. }))
            .count();
        assert_eq!(kept, TELEMETRY_CAPACITY);
    }

    #[test]
    fn a_supervisor_that_stops_reading_never_blocks_the_callers_and_ends_the_run() {
        let (reporter, _peer, stop) = connect(Duration::from_millis(300));
        let telemetry = reporter.telemetry();
        let big = "x".repeat(1500);
        let started = Instant::now();
        // Far more than the socket buffer and the queue hold.
        for _ in 0..20_000 {
            telemetry.denial(&big);
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "callers waited {:?}",
            started.elapsed()
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop.is_requested() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            stop.is_requested(),
            "a stalled supervisor must stop the run"
        );
    }

    #[test]
    fn more_lifecycle_events_than_the_queue_holds_stop_the_run_instead_of_waiting() {
        let (reporter, _peer, stop) = connect(Duration::from_millis(300));
        let big = Event::Warning {
            text: "w".repeat(1500),
        };
        let started = Instant::now();
        for _ in 0..(LIFECYCLE_CAPACITY * 400) {
            reporter.lifecycle(big.clone());
        }
        assert!(started.elapsed() < Duration::from_secs(2));
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop.is_requested() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(stop.is_requested());
    }
}
