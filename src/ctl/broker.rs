// ABOUTME: The unix-socket listener: at most four connections, one 4 KiB request line, absolute deadlines, one response, then close.
// ABOUTME: Synchronous threads (no new runtime); owned by the run and stopped, joined and unlinked when the child ends.
//! The broker socket (hb-ghd.8.1, design from `history/hb-ghd.8_oracle-broker-architecture.md`).

use std::fs;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use snafu::{ResultExt, Snafu};

use super::op::{MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Response};
use super::runner::Cancel;

/// Connections served at once; a fifth is told to try again.
pub const MAX_CONNECTIONS: usize = 4;
/// From accept to a complete request line.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(5);
/// To write the response.
pub const RESPONSE_DEADLINE: Duration = Duration::from_secs(5);
/// A unix socket path must fit `sockaddr_un.sun_path` on macOS (104 bytes including the NUL).
pub const MAX_SOCKET_PATH_BYTES: usize = 103;

const TICK: Duration = Duration::from_millis(20);

/// Why the broker could not start or stop.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum BrokerError {
    /// The socket path does not fit.
    #[snafu(display("the socket path is {len} bytes; the limit is {MAX_SOCKET_PATH_BYTES}"))]
    PathTooLong {
        /// Its length.
        len: usize,
    },
    /// The socket could not be created.
    #[snafu(display("could not create the socket {}", path.display()))]
    Bind {
        /// Where.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },
    /// Its mode could not be set.
    #[snafu(display("could not restrict the socket {}", path.display()))]
    Mode {
        /// Where.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },
    /// The listener could not be made non-blocking.
    #[snafu(display("could not configure the listener"))]
    Configure {
        /// The OS error.
        source: io::Error,
    },
}

/// A running broker. Dropping it stops it; [`Broker::finish`] does so and reports.
#[derive(Debug)]
pub struct Broker {
    path: PathBuf,
    cancel: Cancel,
    accept: Option<JoinHandle<()>>,
}

/// What a connection thread needs; shared and read-only.
pub trait Serve: Send + Sync + 'static {
    /// Answers one request line.
    fn serve(&self, line: &str) -> Response;
}

impl<F: Fn(&str) -> Response + Send + Sync + 'static> Serve for F {
    fn serve(&self, line: &str) -> Response {
        self(line)
    }
}

impl Broker {
    /// Binds `path` (mode 0600) and starts accepting.
    ///
    /// # Errors
    /// [`BrokerError`] if the path is too long or the socket cannot be made.
    pub fn start(path: &Path, serve: Arc<dyn Serve>, cancel: Cancel) -> Result<Self, BrokerError> {
        let len = path.as_os_str().len();
        if len > MAX_SOCKET_PATH_BYTES {
            return Err(BrokerError::PathTooLong { len });
        }
        let listener = UnixListener::bind(path).context(BindSnafu { path })?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).context(ModeSnafu { path })?;
        listener.set_nonblocking(true).context(ConfigureSnafu)?;
        let flag = cancel.clone();
        let accept = thread::spawn(move || accept_loop(&listener, &serve, &flag));
        Ok(Self {
            path: path.to_path_buf(),
            cancel,
            accept: Some(accept),
        })
    }

    /// The socket path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Stops accepting, cancels running commands, waits for the threads and removes the socket.
    pub fn finish(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        let _ = fs::remove_file(&self.path);
    }
}

impl Drop for Broker {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(listener: &UnixListener, serve: &Arc<dyn Serve>, cancel: &Cancel) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    while !cancel.is_cancelled() {
        workers.retain(|w| !w.is_finished());
        match listener.accept() {
            Ok((stream, _)) => {
                if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                    busy(stream);
                    continue;
                }
                active.fetch_add(1, Ordering::SeqCst);
                let (serve, cancel, active) = (serve.clone(), cancel.clone(), active.clone());
                workers.push(thread::spawn(move || {
                    connection(stream, serve.as_ref(), &cancel);
                    active.fetch_sub(1, Ordering::SeqCst);
                }));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(TICK),
            Err(_) => thread::sleep(TICK),
        }
    }
    for worker in workers {
        let _ = worker.join();
    }
}

/// A best-effort reply that can never block the accept loop.
fn busy(stream: UnixStream) {
    let reply = Response {
        ok: false,
        out: String::new(),
        err: "hb ctl is busy; try again".into(),
        truncated: false,
    };
    let _ = stream.set_nonblocking(true);
    let mut stream = stream;
    let _ = write_line(&mut stream, &reply);
}

fn connection(stream: UnixStream, serve: &dyn Serve, cancel: &Cancel) {
    let reply = match read_request(&stream, cancel) {
        Ok(line) => serve.serve(&line),
        Err(message) => Response {
            ok: false,
            out: String::new(),
            err: message.to_owned(),
            truncated: false,
        },
    };
    let _ = stream.set_write_timeout(Some(RESPONSE_DEADLINE));
    let mut stream = stream;
    let _ = write_line(&mut stream, &reply);
}

/// One line of at most [`MAX_REQUEST_BYTES`], all of it within [`REQUEST_DEADLINE`] of now.
fn read_request(stream: &UnixStream, cancel: &Cancel) -> Result<String, &'static str> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|_| "could not read the request")?
            .take(MAX_REQUEST_BYTES as u64),
    );
    let mut line = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("the request was too slow");
        }
        if cancel.is_cancelled() {
            return Err("hb is shutting down");
        }
        stream
            .set_read_timeout(Some(left.min(TICK * 5)))
            .map_err(|_| "could not read the request")?;
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => return Err("the request was empty or cut off"),
            Ok(_) if line.ends_with(b"\n") => break,
            // The limit was reached without a newline.
            Ok(_) if line.len() >= MAX_REQUEST_BYTES => return Err("the request was too long"),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Err("could not read the request"),
        }
    }
    line.pop();
    String::from_utf8(line).map_err(|_| "the request was not text")
}

fn write_line(stream: &mut UnixStream, reply: &Response) -> io::Result<()> {
    let mut text = serde_json::to_string(reply).map_err(io::Error::other)?;
    if text.len() + 1 > MAX_RESPONSE_BYTES {
        let short = Response {
            ok: false,
            out: String::new(),
            err: "the response was too large".into(),
            truncated: true,
        };
        text = serde_json::to_string(&short).map_err(io::Error::other)?;
    }
    text.push('\n');
    stream.write_all(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;

    fn dir() -> tempfile::TempDir {
        assert_ok!(tempfile::Builder::new().prefix("hb-b").tempdir_in("/tmp"))
    }

    fn echo() -> Arc<dyn Serve> {
        Arc::new(|line: &str| Response {
            ok: true,
            out: format!("got:{line}"),
            err: String::new(),
            truncated: false,
        })
    }

    fn ask(path: &Path, text: &[u8]) -> Response {
        let mut s = assert_ok!(UnixStream::connect(path));
        assert_ok!(s.set_read_timeout(Some(Duration::from_secs(10))));
        assert_ok!(s.write_all(text));
        let mut reply = String::new();
        assert_ok!(BufReader::new(s).read_line(&mut reply));
        assert_ok!(serde_json::from_str(&reply))
    }

    #[test]
    fn test_a_request_line_is_answered_and_the_socket_is_private_and_removed_at_the_end() {
        let d = dir();
        let path = d.path().join("ctl.sock");
        let broker = assert_ok!(Broker::start(&path, echo(), Cancel::default()));
        assert_eq!(
            assert_ok!(fs::metadata(&path)).permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(ask(&path, b"hello\n").out, "got:hello");
        broker.finish();
        assert!(!path.exists(), "the socket must be removed");
    }

    #[test]
    fn test_oversize_empty_and_slow_requests_get_an_error_and_never_reach_the_handler() {
        let d = dir();
        let path = d.path().join("ctl.sock");
        let reached = Arc::new(AtomicBool::new(false));
        let flag = reached.clone();
        let serve: Arc<dyn Serve> = Arc::new(move |_: &str| {
            flag.store(true, Ordering::SeqCst);
            Response {
                ok: true,
                out: String::new(),
                err: String::new(),
                truncated: false,
            }
        });
        let _broker = assert_ok!(Broker::start(&path, serve, Cancel::default()));
        let long = vec![b'a'; MAX_REQUEST_BYTES + 10];
        assert!(ask(&path, &long).err.contains("too long"));
        let just_over: Vec<u8> = std::iter::repeat_n(b'a', MAX_REQUEST_BYTES).collect();
        assert!(
            ask(&path, &just_over).err.contains("too long"),
            "4096 bytes with no newline is over the limit"
        );
        let s = assert_ok!(UnixStream::connect(&path));
        assert_ok!(s.shutdown(std::net::Shutdown::Write));
        let mut reply = String::new();
        assert_ok!(BufReader::new(s).read_line(&mut reply));
        assert!(reply.contains("empty or cut off"), "{reply}");
        assert!(!reached.load(Ordering::SeqCst));
    }

    #[test]
    fn test_a_client_that_trickles_bytes_is_cut_off_at_the_absolute_deadline() {
        let d = dir();
        let path = d.path().join("ctl.sock");
        let _broker = assert_ok!(Broker::start(&path, echo(), Cancel::default()));
        let mut s = assert_ok!(UnixStream::connect(&path));
        let start = Instant::now();
        let mut reply = String::new();
        let reader = assert_ok!(s.try_clone());
        assert_ok!(reader.set_read_timeout(Some(Duration::from_secs(15))));
        let writer = thread::spawn(move || {
            for _ in 0..40 {
                if s.write_all(b"x").is_err() {
                    return;
                }
                thread::sleep(Duration::from_millis(250));
            }
        });
        assert_ok!(BufReader::new(reader).read_line(&mut reply));
        assert!(reply.contains("too slow"), "{reply}");
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "{:?}",
            start.elapsed()
        );
        assert_ok!(writer.join());
    }

    #[test]
    fn test_a_fifth_simultaneous_connection_is_told_busy_and_workers_are_reclaimed() {
        let d = dir();
        let path = d.path().join("ctl.sock");
        let gate = Arc::new(Mutex::new(()));
        let held = gate.clone();
        let serve: Arc<dyn Serve> = Arc::new(move |_: &str| {
            let _wait = held.lock();
            Response {
                ok: true,
                out: "done".into(),
                err: String::new(),
                truncated: false,
            }
        });
        let _broker = assert_ok!(Broker::start(&path, serve, Cancel::default()));
        let block = assert_ok!(gate.lock());
        let mut clients: Vec<UnixStream> = (0..MAX_CONNECTIONS)
            .map(|_| {
                let mut s = assert_ok!(UnixStream::connect(&path));
                assert_ok!(s.write_all(b"x\n"));
                s
            })
            .collect();
        thread::sleep(Duration::from_millis(300));
        assert!(ask(&path, b"y\n").err.contains("busy"));
        drop(block);
        for c in &mut clients {
            let mut reply = String::new();
            assert_ok!(BufReader::new(&*c).read_line(&mut reply));
            assert!(reply.contains("done"), "{reply}");
        }
        thread::sleep(Duration::from_millis(200));
        assert_eq!(
            ask(&path, b"z\n").ok,
            true,
            "capacity is back once the work is done"
        );
    }

    #[test]
    fn test_a_path_that_does_not_fit_sockaddr_is_refused_and_a_second_bind_fails() {
        let d = dir();
        let long = d.path().join("x".repeat(120));
        assert!(matches!(
            assert_err!(Broker::start(&long, echo(), Cancel::default())),
            BrokerError::PathTooLong { .. }
        ));
        let path = d.path().join("ctl.sock");
        let _first = assert_ok!(Broker::start(&path, echo(), Cancel::default()));
        assert!(matches!(
            assert_err!(Broker::start(&path, echo(), Cancel::default())),
            BrokerError::Bind { .. }
        ));
    }

    #[test]
    fn test_dropping_the_broker_stops_it_even_with_a_connected_idle_client() {
        let d = dir();
        let path = d.path().join("ctl.sock");
        let broker = assert_ok!(Broker::start(&path, echo(), Cancel::default()));
        let _idle = assert_ok!(UnixStream::connect(&path));
        let start = Instant::now();
        drop(broker);
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "{:?}",
            start.elapsed()
        );
        assert!(!path.exists());
    }
}
