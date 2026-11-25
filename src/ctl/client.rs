// ABOUTME: `hb ctl` inside the ball: builds one request from the command line, sends it to HB_CTL_SOCKET, prints the reply.
// ABOUTME: Needs no config, no home and no project; the host re-validates everything, so this only has to be convenient.
//! The client (hb-ghd.8.1).

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use snafu::{ResultExt, Snafu};

use super::op::{ContainerOp, LaunchdOp, MAX_RESPONSE_BYTES, Request, Response};

/// The variable `hb run` sets in the agent's environment.
pub const SOCKET_VAR: &str = "HB_CTL_SOCKET";

/// How long the client waits for an answer (longer than the slowest host command).
const WAIT: Duration = Duration::from_secs(90);

/// Why the client could not get an answer.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ClientError {
    /// The run has no `hb ctl` endpoint.
    #[snafu(display(
        "hb ctl is not available here: this run has no [ctl] containers, launchd jobs or label"
    ))]
    NoSocket,
    /// Connecting failed.
    #[snafu(display("could not reach the hb ctl broker"))]
    Connect {
        /// The OS error.
        source: io::Error,
    },
    /// Sending or receiving failed.
    #[snafu(display("the hb ctl broker did not answer"))]
    Exchange {
        /// The OS error.
        source: io::Error,
    },
    /// The reply was not understood.
    #[snafu(display("the hb ctl broker's answer was not understood"))]
    Reply {
        /// The decoding error.
        source: serde_json::Error,
    },
}

/// What was typed after `hb ctl`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// A container operation.
    Container {
        /// Which.
        op: ContainerOp,
        /// Which container (only `ps` may leave it out).
        name: Option<String>,
        /// `logs --tail N`.
        tail: Option<u64>,
    },
    /// A launchd operation.
    Launchd {
        /// Which.
        op: LaunchdOp,
        /// Which job.
        label: String,
    },
}

impl From<Command> for Request {
    fn from(command: Command) -> Self {
        match command {
            Command::Container { op, name, tail } => Request::Container { op, name, tail },
            Command::Launchd { op, label } => Request::Launchd { op, label },
        }
    }
}

/// Sends `command` over the socket at `socket`.
///
/// # Errors
/// [`ClientError`].
pub fn send(socket: Option<&Path>, command: Command) -> Result<Response, ClientError> {
    let socket = socket.ok_or(ClientError::NoSocket)?;
    let mut line = serde_json::to_string(&Request::from(command))
        .map_err(|source| ClientError::Reply { source })?;
    line.push('\n');
    let mut stream = UnixStream::connect(socket).context(ConnectSnafu)?;
    stream.set_read_timeout(Some(WAIT)).context(ExchangeSnafu)?;
    stream.write_all(line.as_bytes()).context(ExchangeSnafu)?;
    let mut reply = String::new();
    let mut reader = BufReader::new(io::Read::take(&stream, (MAX_RESPONSE_BYTES + 1) as u64));
    reader.read_line(&mut reply).context(ExchangeSnafu)?;
    serde_json::from_str(&reply).context(ReplySnafu)
}

/// Writes the response the way a command would: output on stdout, a refusal on stderr.
/// Returns the process exit code: 0 for success, 1 for a refusal or failure.
pub fn show(response: &Response, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let _ = out.write_all(response.out.as_bytes());
    if response.truncated {
        let _ = writeln!(err, "hb ctl: output was shortened");
    }
    if response.ok {
        0
    } else {
        let _ = writeln!(err, "hb ctl: {}", response.err);
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::os::unix::net::UnixListener;
    use std::thread;

    #[test]
    fn test_without_the_variable_the_message_says_nothing_is_configured() {
        let err = assert_err!(send(
            None,
            Command::Container {
                op: ContainerOp::Ps,
                name: None,
                tail: None
            }
        ));
        assert!(matches!(err, ClientError::NoSocket));
        assert!(err.to_string().contains("no [ctl]"));
    }

    #[test]
    fn test_a_command_becomes_exactly_one_json_line_and_the_reply_is_decoded() {
        let dir = assert_ok!(tempfile::Builder::new().prefix("hb-c").tempdir_in("/tmp"));
        let path = dir.path().join("s");
        let listener = assert_ok!(UnixListener::bind(&path));
        let server =
            thread::spawn(move || {
                let (stream, _) = assert_ok!(listener.accept());
                let mut line = String::new();
                assert_ok!(BufReader::new(&stream).read_line(&mut line));
                let mut stream = stream;
                assert_ok!(stream.write_all(
                    b"{\"ok\":true,\"out\":\"x\\n\",\"err\":\"\",\"truncated\":false}\n"
                ));
                line
            });
        let reply = assert_ok!(send(
            Some(&path),
            Command::Container {
                op: ContainerOp::Logs,
                name: Some("db".into()),
                tail: Some(5)
            }
        ));
        assert_eq!(
            server.join().ok().as_deref(),
            Some("{\"target\":\"container\",\"op\":\"logs\",\"name\":\"db\",\"tail\":5}\n")
        );
        assert_eq!(
            reply,
            Response {
                ok: true,
                out: "x\n".into(),
                err: String::new(),
                truncated: false
            }
        );
    }

    #[test]
    fn test_show_writes_output_to_stdout_and_a_refusal_to_stderr_with_exit_one() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let ok = Response {
            ok: true,
            out: "hi\n".into(),
            err: String::new(),
            truncated: true,
        };
        assert_eq!(show(&ok, &mut out, &mut err), 0);
        assert_eq!(String::from_utf8_lossy(&out), "hi\n");
        assert!(String::from_utf8_lossy(&err).contains("shortened"));
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let no = Response {
            ok: false,
            out: String::new(),
            err: "refused".into(),
            truncated: false,
        };
        assert_eq!(show(&no, &mut out, &mut err), 1);
        assert_eq!(String::from_utf8_lossy(&err), "hb ctl: refused\n");
    }

    #[test]
    fn test_a_missing_socket_is_a_connect_error() {
        let err = assert_err!(send(
            Some(Path::new("/nonexistent/s")),
            Command::Container {
                op: ContainerOp::Ps,
                name: None,
                tail: None
            }
        ));
        assert!(matches!(err, ClientError::Connect { .. }));
    }
}
