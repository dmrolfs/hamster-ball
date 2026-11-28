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
use std::io::{self, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

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
    /// Includes lifecycle events already taken by the writer but not completely written.
    deadlines: VecDeque<Instant>,
    close_deadline: Option<Instant>,
    telemetry: VecDeque<Event>,
    dropped_denials: u64,
    dropped_proxy: u64,
    /// The closing event, sent after everything else.
    last: Option<Event>,
    closing: bool,
    stopping: bool,
    broken: bool,
}

struct Shared {
    queues: Mutex<Queues>,
    wake: Condvar,
    stop: Arc<StopSignal>,
    write_timeout: Duration,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queues> {
        // A poisoned lock means a thread panicked while queuing; the data is still consistent.
        self.queues.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn deadline(&self, frame_deadline: Instant) -> Instant {
        let q = self.lock();
        q.deadlines
            .front()
            .copied()
            .into_iter()
            .chain(q.close_deadline)
            .fold(frame_deadline, Instant::min)
    }

    fn break_channel(&self) {
        let mut q = self.lock();
        if q.broken {
            return;
        }
        q.broken = true;
        drop(q);
        self.wake.notify_all();
        self.stop.request();
    }
}

/// What the writer takes next.
struct Batch {
    events: Vec<Event>,
    lifecycle: usize,
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
            let lifecycle = events.len();
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
                return Some(Batch {
                    events,
                    lifecycle,
                    finished,
                });
            }
            q = self.wake.wait(q).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// A cheap handle for the threads that produce telemetry.
#[derive(Clone)]
pub struct Telemetry(Arc<Shared>);

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Telemetry(..)")
    }
}

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

/// A cheap handle for reporting lifecycle events from other threads.
#[derive(Clone)]
pub struct Lifecycle(Arc<Shared>);

impl std::fmt::Debug for Lifecycle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Lifecycle(..)")
    }
}

impl Lifecycle {
    /// Reports a lifecycle event. Never waits; if the writer is so far behind that even this
    /// queue is full, the run is stopped.
    pub fn send(&self, event: Event) {
        let mut q = self.0.lock();
        if q.broken || q.closing {
            return;
        }
        match event {
            Event::Stopping {} if q.stopping => return,
            Event::Running { .. } if q.stopping => return,
            Event::Stopping {} => q.stopping = true,
            _ => {}
        }
        if q.deadlines.len() >= LIFECYCLE_CAPACITY {
            drop(q);
            self.0.break_channel();
            return;
        }
        q.deadlines.push_back(Instant::now() + self.0.write_timeout);
        q.lifecycle.push_back(event);
        drop(q);
        self.0.wake.notify_one();
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
        Self::connect_spawning(stream, stop, write_timeout, |body| {
            thread::Builder::new()
                .name("hb-report-read".to_owned())
                .spawn(body)
        })
    }

    fn connect_spawning(
        stream: UnixStream,
        stop: Arc<StopSignal>,
        write_timeout: Duration,
        spawn_reader: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>,
    ) -> Result<Self, ChannelError> {
        let handshake_deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut reader = BufReader::new(HandshakeReader {
            stream: stream.try_clone().context(IoSnafu)?,
            deadline: Some(handshake_deadline),
            lease: None,
        });
        let line = read_line(&mut reader)
            .context(HandshakeSnafu)?
            .ok_or(ProtocolError::Truncated)
            .context(HandshakeSnafu)?;
        let hello = decode_hello(&line).context(HandshakeSnafu)?;
        reader.get_mut().lease = Some(
            super::lease::Lease::new(
                super::lease::Progress::now()
                    .map_err(io::Error::other)
                    .context(IoSnafu)?,
                super::lease::TIMEOUT,
            )
            .map_err(io::Error::other)
            .context(IoSnafu)?,
        );
        let ack = HelloAck {
            v: hello.v,
            launch: hello.launch,
            generation: hello.generation,
            pid: std::process::id(),
        };
        let mut writer_end = stream.try_clone().context(IoSnafu)?;
        let ack_deadline = handshake_deadline.min(Instant::now() + write_timeout);
        write_before(
            &mut writer_end,
            &encode_line(&ack).context(AnswerSnafu)?,
            || ack_deadline,
        )
        .context(IoSnafu)?;
        // Preserve read-ahead commands while removing only the handshake deadline.
        reader.get_mut().deadline = None;
        stream.set_read_timeout(None).context(IoSnafu)?;
        let shared = Arc::new(Shared {
            queues: Mutex::new(Queues::default()),
            wake: Condvar::new(),
            stop,
            write_timeout,
        });
        let writer = {
            let shared = Arc::clone(&shared);
            thread::Builder::new()
                .name("hb-report-write".to_owned())
                .spawn(move || write_loop(&mut writer_end, &shared))
                .context(ThreadSnafu)?
        };
        let reader = {
            let reading_shared = Arc::clone(&shared);
            match spawn_reader(Box::new(move || read_loop(&mut reader, &reading_shared))) {
                Ok(reader) => reader,
                Err(source) => {
                    shared.lock().broken = true;
                    shared.wake.notify_all();
                    let _ = stream.shutdown(Shutdown::Both);
                    let _ = writer.join();
                    return Err(ChannelError::Thread { source });
                }
            }
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

    /// A handle for reporting lifecycle events from other threads.
    #[must_use]
    pub fn lifecycle_handle(&self) -> Lifecycle {
        Lifecycle(Arc::clone(&self.shared))
    }

    /// Reports a lifecycle event. See [`Lifecycle::send`].
    pub fn lifecycle(&self, event: Event) {
        self.lifecycle_handle().send(event);
    }

    /// Sends queued events and then `exited` within one absolute write-timeout budget.
    /// Older lifecycle deadlines still apply. Scheduler stalls are not a hard real-time bound.
    pub fn finish(mut self, exited: Event) {
        {
            let mut q = self.shared.lock();
            q.last = Some(exited);
            q.close_deadline = Some(Instant::now() + self.shared.write_timeout);
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
            q.broken = true;
        }
        self.shared.wake.notify_all();
        let _ = self.stream.shutdown(Shutdown::Both);
        self.close();
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "supervisor channel deadline expired",
            )
        })
}

/// Retains BufReader read-ahead when the handshake becomes the command stream.
struct HandshakeReader {
    stream: UnixStream,
    deadline: Option<Instant>,
    lease: Option<super::lease::Lease>,
}

impl HandshakeReader {
    fn lease_remaining(&self) -> io::Result<Option<Duration>> {
        self.lease
            .as_ref()
            .map(|lease| {
                let now = super::lease::Progress::now().map_err(io::Error::other)?;
                lease.remaining(now).map_err(io::Error::other)
            })
            .transpose()
    }
}

impl Read for HandshakeReader {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if let Some(deadline) = self.deadline {
            self.stream.set_read_timeout(Some(remaining(deadline)?))?;
        }
        loop {
            if let Some(left) = self.lease_remaining()? {
                self.stream
                    .set_read_timeout(Some(left.min(Duration::from_secs(1))))?;
            }
            let read = self.stream.read(bytes);
            self.lease_remaining()?;
            match read {
                Err(ref error)
                    if self.lease.is_some()
                        && matches!(
                            error.kind(),
                            io::ErrorKind::TimedOut
                                | io::ErrorKind::WouldBlock
                                | io::ErrorKind::Interrupted
                        ) =>
                {
                    continue;
                }
                other => {
                    if let Some(deadline) = self.deadline {
                        remaining(deadline)?;
                    }
                    return other;
                }
            }
        }
    }
}

fn write_before(
    stream: &mut UnixStream,
    bytes: &[u8],
    deadline: impl Fn() -> Instant,
) -> io::Result<()> {
    write_timed(bytes, deadline, |bytes, left| {
        stream.set_write_timeout(Some(left))?;
        stream.write(bytes)
    })
}

fn write_timed(
    mut bytes: &[u8],
    deadline: impl Fn() -> Instant,
    mut write: impl FnMut(&[u8], Duration) -> io::Result<usize>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        match write(bytes, remaining(deadline())?) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
        remaining(deadline())?;
    }
    Ok(())
}

fn write_loop(stream: &mut UnixStream, shared: &Shared) {
    if write_batches(shared, |line, deadline| {
        write_before(stream, line, || shared.deadline(deadline))
    })
    .is_err()
    {
        shared.break_channel();
        let _ = stream.shutdown(Shutdown::Both);
    }
}

fn write_batches(
    shared: &Shared,
    mut write: impl FnMut(&[u8], Instant) -> io::Result<()>,
) -> io::Result<()> {
    let mut sent = 0u64;
    while let Some(batch) = shared.next_batch() {
        for (index, event) in batch.events.into_iter().enumerate() {
            let deadline = Instant::now() + shared.write_timeout;
            let line = encode_frame(sent + 1, event);
            let result = match line {
                Ok(line) => write(&line, shared.deadline(deadline)),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid lifecycle or telemetry frame",
                )),
            };
            result?;
            if index < batch.lifecycle {
                shared.lock().deadlines.pop_front();
            }
            sent += 1;
        }
        if batch.finished {
            return Ok(());
        }
    }
    Ok(())
}

fn read_loop(reader: &mut BufReader<HandshakeReader>, shared: &Shared) {
    loop {
        let command = (|| {
            reader.get_ref().lease_remaining()?;
            let line = read_line(reader).map_err(io::Error::other)?;
            reader.get_ref().lease_remaining()?;
            line.map(|line| decode_command(&line).map_err(io::Error::other))
                .transpose()
        })();
        let stopping = match command {
            Ok(Some(Command::Heartbeat { progress_ns })) => {
                let reading = reader.get_mut();
                match (reading.lease.as_mut(), super::lease::Progress::now()) {
                    (Some(lease), Ok(now)) => lease
                        .renew(super::lease::Progress(progress_ns), now)
                        .is_err(),
                    _ => true,
                }
            }
            Ok(Some(Command::Stop {})) | Ok(None) | Err(_) => true,
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

    #[test]
    fn an_expired_lease_rejects_a_complete_buffered_heartbeat() {
        use super::super::lease::{Lease, Progress};
        let (mut peer, stream) = assert_ok!(UnixStream::pair());
        let now = assert_ok!(Progress::now());
        let line = assert_ok!(encode_line(&Command::Heartbeat { progress_ns: now.0 }));
        assert_ok!(peer.write_all(&line));
        let mut reader = BufReader::new(HandshakeReader {
            stream,
            deadline: None,
            lease: None,
        });
        assert!(!assert_ok!(std::io::BufRead::fill_buf(&mut reader)).is_empty());
        reader.get_mut().lease = Some(assert_ok!(Lease::new(now, Duration::ZERO)));
        let stop = StopSignal::new();
        let shared = Shared {
            queues: Mutex::new(Queues::default()),
            wake: Condvar::new(),
            stop: Arc::clone(&stop),
            write_timeout: Duration::from_secs(1),
        };
        read_loop(&mut reader, &shared);
        assert!(stop.is_requested());
    }

    #[test]
    fn partial_bytes_do_not_extend_the_lease_and_idle_reads_expire() {
        use super::super::lease::{Lease, Progress};
        for bytes in [b"".as_slice(), b"{\"cmd\":\"heart"] {
            let (mut peer, stream) = assert_ok!(UnixStream::pair());
            assert_ok!(peer.write_all(bytes));
            let lease = assert_ok!(Lease::new(
                assert_ok!(Progress::now()),
                Duration::from_millis(30)
            ));
            let mut reader = BufReader::new(HandshakeReader {
                stream,
                deadline: None,
                lease: Some(lease),
            });
            let start = Instant::now();
            assert!(read_line(&mut reader).is_err());
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    }

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
    fn racing_running_and_stopping_never_publish_running_after_stopping() {
        for _ in 0..32 {
            let shared = queued();
            let lifecycle = Lifecycle(Arc::clone(&shared));
            lifecycle.send(Event::Starting {});
            let barrier = Arc::new(std::sync::Barrier::new(2));
            thread::scope(|scope| {
                let ready = Arc::clone(&barrier);
                let starting = lifecycle.clone();
                scope.spawn(move || {
                    ready.wait();
                    starting.send(Event::Running { agent_pid: 5 });
                });
                barrier.wait();
                lifecycle.send(Event::Stopping {});
            });
            lifecycle.send(Event::Stopping {});
            lifecycle.send(Event::Running { agent_pid: 5 });
            let q = shared.lock();
            assert!(matches!(q.lifecycle.front(), Some(Event::Starting {})));
            assert!(matches!(q.lifecycle.back(), Some(Event::Stopping {})));
            assert_eq!(
                q.lifecycle
                    .iter()
                    .filter(|e| matches!(e, Event::Stopping {}))
                    .count(),
                1
            );
            assert_eq!(q.deadlines.len(), q.lifecycle.len());
        }
    }

    #[test]
    fn partial_writes_retry_only_unsent_bytes_and_preserve_io_errors() {
        let deadline = Instant::now() + WRITE_TIMEOUT;
        let mut calls = 0;
        let mut received = Vec::new();
        assert_ok!(write_timed(
            b"frame",
            || deadline,
            |bytes, _| {
                calls += 1;
                if calls == 2 {
                    return Err(io::ErrorKind::Interrupted.into());
                }
                received.push(bytes[0]);
                Ok(1)
            }
        ));
        assert_eq!(received, b"frame");
        for kind in [io::ErrorKind::WriteZero, io::ErrorKind::BrokenPipe] {
            let error = claims::assert_err!(write_timed(
                b"frame",
                || deadline,
                |_, _| {
                    if kind == io::ErrorKind::WriteZero {
                        Ok(0)
                    } else {
                        Err(kind.into())
                    }
                }
            ));
            assert_eq!(error.kind(), kind);
        }
    }

    #[test]
    fn full_frame_progress_after_expiry_is_still_a_timeout() {
        use std::cell::Cell;
        let deadline = Cell::new(Instant::now() + WRITE_TIMEOUT);
        let error = claims::assert_err!(write_timed(
            b"frame",
            || deadline.get(),
            |bytes, _| {
                deadline.set(Instant::now() - WRITE_TIMEOUT);
                Ok(bytes.len())
            }
        ));
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    fn queued() -> Arc<Shared> {
        Arc::new(Shared {
            queues: Mutex::new(Queues::default()),
            wake: Condvar::new(),
            stop: StopSignal::new(),
            write_timeout: WRITE_TIMEOUT,
        })
    }

    #[test]
    fn writer_retires_only_written_lifecycle_deadlines_and_preserves_the_close_budget() {
        let shared = queued();
        let lifecycle = Lifecycle(Arc::clone(&shared));
        lifecycle.send(Event::Starting {});
        for _ in 0..BATCH + 2 {
            Telemetry(Arc::clone(&shared)).denial("queued");
        }
        let first_deadline = shared.lock().deadlines[0];
        let mut written = 0;
        let mut final_written = false;
        let result = write_batches(&shared, |line, deadline| {
            remaining(deadline)?;
            final_written |= String::from_utf8_lossy(line).contains("last");
            if written == 0 {
                assert_eq!(deadline, first_deadline);
                // Enqueue while the first lifecycle entry is in flight.
                lifecycle.send(Event::Stopping {});
                assert_eq!(shared.lock().deadlines.len(), 2);
            } else if written == 1 {
                let mut q = shared.lock();
                assert_eq!(q.deadlines.len(), 1);
                q.closing = true;
                q.last = Some(Event::warning("last"));
                q.close_deadline = Some(first_deadline + WRITE_TIMEOUT);
                assert_eq!(deadline, q.deadlines[0]);
            } else if written == BATCH {
                shared.lock().close_deadline = Some(Instant::now() - WRITE_TIMEOUT);
            }
            written += 1;
            Ok(())
        });
        assert_eq!(claims::assert_err!(result).kind(), io::ErrorKind::TimedOut);
        assert_eq!(written, BATCH + 1);
        assert!(!final_written, "final frame must not be delivered");
        assert_eq!(
            shared.lock().deadlines.len(),
            1,
            "unsent lifecycle must remain pending"
        );
    }

    #[test]
    fn one_unchanged_close_deadline_bounds_successful_frames_across_batches() {
        let shared = queued();
        for _ in 0..BATCH * 2 {
            Telemetry(Arc::clone(&shared)).denial("queued");
        }
        let close_deadline = Instant::now() + Duration::from_secs(1);
        {
            let mut q = shared.lock();
            q.closing = true;
            q.close_deadline = Some(close_deadline);
            q.last = Some(Event::warning("last"));
        }
        let mut written = 0;
        let result = write_batches(&shared, |line, deadline| {
            assert_eq!(deadline, close_deadline);
            if written == BATCH + 1 {
                thread::sleep(
                    close_deadline.saturating_duration_since(Instant::now())
                        + Duration::from_millis(1),
                );
            }
            remaining(deadline)?;
            assert!(!String::from_utf8_lossy(line).contains("last"));
            written += 1;
            Ok(())
        });
        assert_eq!(claims::assert_err!(result).kind(), io::ErrorKind::TimedOut);
        assert_eq!(
            written,
            BATCH + 1,
            "must pass the batch boundary before expiry"
        );
        assert_eq!(shared.lock().close_deadline, Some(close_deadline));
    }

    #[test]
    fn expired_lifecycle_stops_the_actual_writer_without_sending_a_prefix() {
        let shared = queued();
        Lifecycle(Arc::clone(&shared)).send(Event::Starting {});
        shared.lock().deadlines[0] = Instant::now() - WRITE_TIMEOUT;
        let (mut stream, mut peer) = assert_ok!(UnixStream::pair());
        write_loop(&mut stream, &shared);
        assert!(shared.stop.is_requested());
        let mut bytes = Vec::new();
        assert_ok!(peer.read_to_end(&mut bytes));
        assert!(bytes.is_empty());
        assert_eq!(shared.lock().deadlines.len(), 1);
    }

    #[test]
    fn intentional_drop_during_an_active_writer_does_not_request_stop() {
        let shared = queued();
        Lifecycle(Arc::clone(&shared)).send(Event::Starting {});
        let (stream, mut peer) = assert_ok!(UnixStream::pair());
        let mut writer_end = assert_ok!(stream.try_clone());
        assert_ok!(writer_end.set_read_timeout(Some(Duration::from_secs(5))));
        let writing = Arc::clone(&shared);
        let (entered, waiting) = std::sync::mpsc::sync_channel(1);
        let (completed, outcome) = std::sync::mpsc::sync_channel(1);
        let writer = thread::spawn(move || {
            let result = write_batches(&writing, |line, _| {
                assert_ok!(entered.send(()));
                // Observe Drop's abort before allowing the pending write to fail.
                let deadline = Instant::now() + Duration::from_secs(5);
                while !writing.lock().broken {
                    assert!(Instant::now() < deadline);
                    thread::yield_now();
                }
                // The peer stays open; only Drop's shutdown releases this read.
                assert_eq!(assert_ok!(writer_end.read(&mut [0])), 0);
                writer_end.write_all(line)
            });
            writing.break_channel();
            assert_ok!(completed.send(result.is_err()));
        });
        let reporter = Reporter {
            shared: Arc::clone(&shared),
            stream,
            writer: Some(writer),
            reader: None,
        };
        assert_ok!(waiting.recv_timeout(Duration::from_secs(5)));
        drop(reporter);
        assert!(assert_ok!(outcome.recv_timeout(Duration::from_secs(5))));
        assert!(!shared.stop.is_requested());
        assert_eq!(assert_ok!(peer.read(&mut [0])), 0);
    }

    #[test]
    fn progress_and_interruption_do_not_reset_the_write_deadline() {
        use std::cell::Cell;
        for interrupted in [false, true] {
            let deadline = Cell::new(Instant::now() + Duration::from_secs(10));
            let mut calls = 0;
            let error = claims::assert_err!(write_timed(
                b"frame",
                || deadline.get(),
                |_, _| {
                    calls += 1;
                    deadline.set(Instant::now() - Duration::from_secs(1));
                    if interrupted {
                        Err(io::ErrorKind::Interrupted.into())
                    } else {
                        Ok(1)
                    }
                }
            ));
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(calls, 1);
        }
    }

    #[test]
    fn lifecycle_deadline_survives_dequeue_and_bounds_intervening_telemetry() {
        let shared = Arc::new(Shared {
            queues: Mutex::new(Queues::default()),
            wake: Condvar::new(),
            stop: StopSignal::new(),
            write_timeout: WRITE_TIMEOUT,
        });
        Telemetry(Arc::clone(&shared)).denial("waiting telemetry");
        let telemetry = claims::assert_some!(shared.next_batch());
        Lifecycle(Arc::clone(&shared)).send(Event::Starting {});
        let expired = Instant::now() - Duration::from_secs(1);
        shared.lock().deadlines[0] = expired;
        assert_eq!(telemetry.lifecycle, 0);
        assert_eq!(shared.deadline(Instant::now() + WRITE_TIMEOUT), expired);
        let lifecycle = claims::assert_some!(shared.next_batch());
        assert_eq!(lifecycle.lifecycle, 1);
        assert_eq!(shared.deadline(Instant::now() + WRITE_TIMEOUT), expired);
    }

    #[test]
    fn expired_final_drain_stops_even_when_the_socket_is_writable() {
        let shared = Shared {
            queues: Mutex::new(Queues {
                closing: true,
                close_deadline: Some(Instant::now() - Duration::from_secs(1)),
                last: Some(Event::Stopping {}),
                ..Queues::default()
            }),
            wake: Condvar::new(),
            stop: StopSignal::new(),
            write_timeout: WRITE_TIMEOUT,
        };
        let (mut stream, mut peer) = assert_ok!(UnixStream::pair());
        write_loop(&mut stream, &shared);
        assert!(shared.stop.is_requested());
        let mut received = Vec::new();
        assert_ok!(peer.read_to_end(&mut received));
        assert!(received.is_empty());
    }

    #[test]
    fn a_command_buffered_with_the_handshake_is_not_lost() {
        let (ours, mut peer) = assert_ok!(UnixStream::pair());
        let mut bytes = assert_ok!(encode_line(&Hello::new(7, 2)));
        bytes.extend_from_slice(b"{\"cmd\":\"stop\"}\n");
        assert_ok!(peer.write_all(&bytes));
        let stop = StopSignal::new();
        let _reporter = assert_ok!(Reporter::connect(ours, Arc::clone(&stop)));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !stop.is_requested() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(stop.is_requested());
    }

    #[test]
    fn reader_spawn_failure_closes_the_already_started_writer_channel() {
        let (ours, mut peer) = assert_ok!(UnixStream::pair());
        assert_ok!(peer.set_read_timeout(Some(Duration::from_millis(200))));
        assert_ok!(peer.write_all(&assert_ok!(encode_line(&Hello::new(7, 2)))));
        let result = Reporter::connect_spawning(ours, StopSignal::new(), WRITE_TIMEOUT, |_| {
            Err(std::io::Error::other("injected reader spawn failure"))
        });
        assert!(matches!(result, Err(ChannelError::Thread { .. })));
        let mut received = Vec::new();
        assert_ok!(peer.read_to_end(&mut received));
        assert!(String::from_utf8_lossy(&received).contains("generation"));
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
        assert_eq!(PROTOCOL_VERSION, 2);
    }

    #[test]
    fn handshake_progress_does_not_renew_its_total_deadline() {
        let (ours, mut peer) = assert_ok!(UnixStream::pair());
        let sender = thread::spawn(move || {
            for _ in 0..7 {
                if peer.write_all(b" ").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(900));
            }
            let _ = peer.write_all(&assert_ok!(encode_line(&Hello::new(7, 2))));
            let _ = peer.read(&mut [0u8; 256]);
        });
        let result = Reporter::connect(ours, StopSignal::new());
        let refused = result.is_err();
        drop(result);
        assert_ok!(sender.join());
        assert!(refused, "trickled handshake outlived its absolute deadline");
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
    fn real_proxy_audit_callbacks_report_exact_split_drops_on_the_wire() {
        use crate::proxy::{AuditSink, Decision};
        use crate::session::{DenialSink, proxy::ProxyTrail};
        let shared = queued();
        let telemetry = Telemetry(Arc::clone(&shared));
        let sink = telemetry.clone();
        let denial = DenialSink::Stream(Arc::new(move |line| sink.denial(line)));
        let trail = ProxyTrail::new(Some(&denial), None).with_telemetry(Some(telemetry.clone()));
        let mut event = AuditEvent {
            host: None,
            port: None,
            decision: Decision::Allowed,
            bytes_up: 1,
            bytes_down: 2,
        };
        trail.record(&event);
        assert!(matches!(
            shared.lock().telemetry.front(),
            Some(Event::Proxy { .. })
        ));
        for _ in 1..TELEMETRY_CAPACITY {
            telemetry.denial("fill");
        }
        event.decision = Decision::Refused {
            code: "not_allowed",
            reason: "no grant".into(),
        };
        for _ in 0..3 {
            trail.record(&event);
        }
        assert_eq!(trail.report().refusals, 3);
        let (mut stream, peer) = assert_ok!(UnixStream::pair());
        shared.lock().closing = true;
        let writer = thread::spawn(move || write_loop(&mut stream, &shared));
        let mut reader = BufReader::new(peer);
        let mut dropped = None;
        while let Some(line) = assert_ok!(read_line(&mut reader)) {
            if let Event::Dropped { denials, proxy } = assert_ok!(decode_frame(&line)).event {
                dropped = Some((denials, proxy));
            }
        }
        assert_ok!(writer.join());
        assert_eq!(dropped, Some((3, 3)));
    }

    #[test]
    fn stalled_peer_does_not_block_the_real_proxy_audit_callback() {
        use crate::proxy::{AuditSink, Decision};
        use crate::session::{DenialSink, proxy::ProxyTrail};
        let (reporter, _peer, stop) = connect(Duration::from_millis(300));
        let telemetry = reporter.telemetry();
        let sink = telemetry.clone();
        let denial = DenialSink::Stream(Arc::new(move |line| sink.denial(line)));
        let trail = ProxyTrail::new(Some(&denial), None).with_telemetry(Some(telemetry));
        let event = AuditEvent {
            host: None,
            port: None,
            decision: Decision::Refused {
                code: "not_allowed",
                reason: "x".repeat(1500),
            },
            bytes_up: 0,
            bytes_down: 0,
        };
        let mut longest = Duration::ZERO;
        for _ in 0..20_000 {
            let before = Instant::now();
            trail.record(&event);
            longest = longest.max(before.elapsed());
        }
        assert!(
            longest < Duration::from_millis(250),
            "callback waited {longest:?}"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop.is_requested() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(stop.is_requested());
    }

    #[test]
    fn telemetry_that_does_not_fit_is_counted_and_the_count_is_reported() {
        let shared = Shared {
            queues: Mutex::new(Queues::default()),
            wake: Condvar::new(),
            stop: StopSignal::new(),
            write_timeout: WRITE_TIMEOUT,
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
        // Far more than the socket buffer and the queue hold. A caller that waited on the peer
        // would wait out the write timeout (300 ms), so the longest single call is the measure;
        // the total would also count this machine's scheduling.
        let mut longest = Duration::ZERO;
        for _ in 0..20_000 {
            let before = Instant::now();
            telemetry.denial(&big);
            longest = longest.max(before.elapsed());
        }
        assert!(
            longest < Duration::from_millis(250),
            "a caller waited {longest:?}"
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
        let mut longest = Duration::ZERO;
        for _ in 0..(LIFECYCLE_CAPACITY * 400) {
            let before = Instant::now();
            reporter.lifecycle(big.clone());
            longest = longest.max(before.elapsed());
        }
        assert!(
            longest < Duration::from_millis(250),
            "a caller waited {longest:?}"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !stop.is_requested() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(stop.is_requested());
    }
}
