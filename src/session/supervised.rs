// ABOUTME: The private channel between `hb run --supervised` and `hb-supervise`: typed events, one Stop command, bounded framing.
// ABOUTME: Status travels here and never in terminal bytes, so an agent cannot forge it; every text field is escaped and size-limited.
//! The supervisor channel (epic hb-b6q).
//!
//! `hb-supervise` starts each session as `hb run --supervised`. Terminal bytes travel over a
//! PTY; everything the supervisor trusts (state, denials, proxy activity, exit) travels on a
//! separate socket carrying one JSON object per line, defined here. This module is only the
//! wire format: it opens no socket and knows nothing about queues or deadlines.
//!
//! The rules the format enforces:
//!
//! - A frame is at most [`MAX_FRAME_BYTES`] including its newline, and a reader never buffers
//!   more than that.
//! - Every object rejects unknown fields. The handshake carries a version, and a mismatch is
//!   reported before any other field is looked at.
//! - Events carry a `seq` that starts at 1 and rises by exactly 1 ([`Sequence`]). Dropped
//!   telemetry is reported by [`Event::Dropped`], never by a gap.
//! - Free text is escaped by [`escape_text`] when an event is built, and a frame whose text
//!   still holds a control character is refused on both the write and the read side, so text
//!   from the sandbox cannot move the cursor, set a title or write the clipboard of the
//!   terminal that shows it.
//! - The only command is [`Command::Stop`]. Nothing here can approve, widen a policy or grant
//!   access.

use std::io::{self, BufRead, Read};

use serde_json::Value;

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu, ensure};
use strum::{Display, EnumDiscriminants, EnumString, IntoStaticStr};

use crate::proxy::{AuditEvent, Decision};

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;
/// The most bytes in one frame, including the newline.
pub const MAX_FRAME_BYTES: usize = 16 * 1024;
/// The most bytes in one text field.
pub const MAX_TEXT_BYTES: usize = 2 * 1024;

/// Why a frame could not be written, read or accepted.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ProtocolError {
    /// A frame is longer than [`MAX_FRAME_BYTES`].
    #[snafu(display("a frame exceeds the {MAX_FRAME_BYTES} byte limit"))]
    FrameTooLarge,
    /// The peer closed the channel in the middle of a frame.
    #[snafu(display("the channel closed in the middle of a frame"))]
    Truncated,
    /// A frame was empty.
    #[snafu(display("an empty frame"))]
    EmptyFrame,
    /// A frame holds a newline before its end.
    #[snafu(display("a frame holds a newline before its end"))]
    EmbeddedNewline,
    /// A frame is not a valid object of the expected type, or has an unknown field.
    #[snafu(display("a frame is malformed"))]
    Malformed {
        /// The parser's error.
        source: serde_json::Error,
    },
    /// A value could not be turned into JSON.
    #[snafu(display("a frame could not be encoded"))]
    Encode {
        /// The serializer's error.
        source: serde_json::Error,
    },
    /// The peer speaks another protocol version.
    #[snafu(display("the peer speaks protocol version {found}, this build speaks {expected}"))]
    WrongVersion {
        /// The version the peer sent.
        found: u64,
        /// The version this build speaks.
        expected: u32,
    },
    /// The acknowledgement does not echo the handshake it answers.
    #[snafu(display("the acknowledgement does not match the handshake"))]
    HandshakeMismatch,
    /// A text field holds a control character or is too long.
    #[snafu(display(
        "the {field} text holds a control character or exceeds {MAX_TEXT_BYTES} bytes"
    ))]
    UnsafeText {
        /// The field that failed.
        field: &'static str,
    },
    /// An event's sequence number is not the next one.
    #[snafu(display("expected event {expected}, found {found}"))]
    SequenceGap {
        /// The number that should have come.
        expected: u64,
        /// The number that did.
        found: u64,
    },
    /// The channel could not be read.
    #[snafu(display("the channel could not be read"))]
    Read {
        /// The underlying error.
        source: io::Error,
    },
}

/// Whether `c` could change what a terminal or a reader sees beyond its own glyph.
fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        )
}

/// Whether `text` is within the limit and holds nothing [`escape_text`] would change.
fn is_safe(text: &str) -> bool {
    text.len() <= MAX_TEXT_BYTES && !text.chars().any(is_unsafe)
}

/// Makes `text` safe to show and small enough to send.
///
/// Control characters (including escape and the C1 range) and characters that reorder or end
/// lines are replaced by their `\u{..}` form, which is for a person to read and is not meant
/// to be reversed. Text over [`MAX_TEXT_BYTES`] is cut at a character boundary and ends in `…`.
#[must_use]
pub fn escape_text(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if is_unsafe(c) {
            out.push_str(&c.escape_unicode().to_string());
        } else {
            out.push(c);
        }
        if out.len() > MAX_TEXT_BYTES {
            break;
        }
    }
    if out.len() > MAX_TEXT_BYTES {
        let mut cut = MAX_TEXT_BYTES - '…'.len_utf8();
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push('…');
    }
    out
}

/// Fails with [`ProtocolError::UnsafeText`] unless `text` is safe.
fn check_text(field: &'static str, text: &str) -> Result<(), ProtocolError> {
    ensure!(is_safe(text), UnsafeTextSnafu { field });
    Ok(())
}

/// How the proxy settled one connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "snake_case", deny_unknown_fields)]
pub enum Verdict {
    /// The connection was served.
    Allowed {},
    /// The connection was refused.
    Refused {
        /// The stable refusal code.
        code: String,
        /// The reason in one line.
        reason: String,
    },
}

/// Whether `hb`'s cleanup finished.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum Cleanup {
    /// Everything the session started is gone.
    Complete {},
    /// Something was left behind.
    Failed {
        /// What failed, in one line.
        what: String,
    },
}

/// What `hb run --supervised` reports. Text fields are escaped by the constructors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, EnumDiscriminants)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
#[strum_discriminants(
    name(EventKind),
    derive(Display, EnumString, IntoStaticStr),
    strum(serialize_all = "snake_case")
)]
pub enum Event {
    /// The project is loaded; hooks and setup are about to run.
    Starting {},
    /// The configuration is not approved; nothing ran and `hb` exits 78.
    ApprovalRequired {
        /// The project root that needs approval.
        root: String,
    },
    /// The agent started under the sandbox.
    Running {
        /// The agent's process id.
        agent_pid: u32,
    },
    /// One sandbox denial line.
    Denial {
        /// The line, escaped and bounded.
        text: String,
    },
    /// One finished proxy connection.
    Proxy {
        /// The host asked for, when the request named a valid one.
        host: Option<String>,
        /// The port asked for, when the request named a valid one.
        port: Option<u16>,
        /// Served or refused.
        decision: Verdict,
        /// Bytes from the agent to the upstream.
        up: u64,
        /// Bytes from the upstream to the agent.
        down: u64,
    },
    /// Telemetry dropped since the last report.
    Dropped {
        /// Denial events dropped.
        denials: u64,
        /// Proxy events dropped.
        proxy: u64,
    },
    /// A warning `hb run` would have printed.
    Warning {
        /// The warning, escaped and bounded.
        text: String,
    },
    /// Shutdown has begun.
    Stopping {},
    /// The final state.
    Exited {
        /// The agent's exit code, when it exited.
        code: Option<i32>,
        /// The signal that ended it, when one did.
        signal: Option<i32>,
        /// Whether cleanup finished.
        cleanup: Cleanup,
    },
}

impl Event {
    /// A denial line, escaped.
    #[must_use]
    pub fn denial(text: &str) -> Self {
        Self::Denial {
            text: escape_text(text),
        }
    }

    /// A warning, escaped.
    #[must_use]
    pub fn warning(text: &str) -> Self {
        Self::Warning {
            text: escape_text(text),
        }
    }

    /// An approval request for `root`, escaped.
    #[must_use]
    pub fn approval_required(root: &str) -> Self {
        Self::ApprovalRequired {
            root: escape_text(root),
        }
    }

    /// The event for one proxy audit record.
    #[must_use]
    pub fn proxy(audit: &AuditEvent) -> Self {
        let decision = match &audit.decision {
            Decision::Allowed => Verdict::Allowed {},
            Decision::Refused { code, reason } => Verdict::Refused {
                code: escape_text(code),
                reason: escape_text(reason),
            },
        };
        Self::Proxy {
            host: audit.host.as_ref().map(|h| escape_text(h.as_str())),
            port: audit.port.map(u16::from),
            decision,
            up: audit.bytes_up,
            down: audit.bytes_down,
        }
    }

    /// The kind of this event.
    #[must_use]
    pub fn kind(&self) -> EventKind {
        EventKind::from(self)
    }

    /// Fails unless every text field is within the limit and free of control characters.
    ///
    /// # Errors
    /// [`ProtocolError::UnsafeText`] naming the first field that fails.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::ApprovalRequired { root } => check_text("root", root),
            Self::Denial { text } | Self::Warning { text } => check_text("text", text),
            Self::Proxy { host, decision, .. } => {
                if let Some(host) = host {
                    check_text("host", host)?;
                }
                match decision {
                    Verdict::Allowed {} => Ok(()),
                    Verdict::Refused { code, reason } => {
                        check_text("code", code)?;
                        check_text("reason", reason)
                    }
                }
            }
            Self::Exited {
                cleanup: Cleanup::Failed { what },
                ..
            } => check_text("what", what),
            Self::Starting {}
            | Self::Running { .. }
            | Self::Dropped { .. }
            | Self::Stopping {}
            | Self::Exited { .. } => Ok(()),
        }
    }
}

/// One event on the wire: its sequence number and the event.
///
/// Read with [`decode_frame`]: `flatten` would stop `deny_unknown_fields` from working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Frame {
    /// The event's place in the session, from 1.
    pub seq: u64,
    /// The event.
    #[serde(flatten)]
    pub event: Event,
}

/// What the supervisor may ask of `hb`. There is one command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Shut the session down as SIGTERM would.
    Stop {},
}

/// The supervisor's first frame: the version and which launch this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// The protocol version.
    pub v: u32,
    /// The supervisor's number for this launch.
    pub launch: u64,
    /// Which start of the session this is; a restart raises it.
    pub generation: u32,
}

/// `hb`'s answer: the same three fields and its process id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloAck {
    /// The protocol version.
    pub v: u32,
    /// Echo of [`Hello::launch`].
    pub launch: u64,
    /// Echo of [`Hello::generation`].
    pub generation: u32,
    /// The `hb` process id.
    pub pid: u32,
}

impl Hello {
    /// A handshake for this build's version.
    #[must_use]
    pub fn new(launch: u64, generation: u32) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            launch,
            generation,
        }
    }

    /// Fails unless `ack` echoes this handshake.
    ///
    /// # Errors
    /// [`ProtocolError::HandshakeMismatch`] when the version, launch or generation differ.
    pub fn check(&self, ack: &HelloAck) -> Result<(), ProtocolError> {
        ensure!(
            ack.v == self.v && ack.launch == self.launch && ack.generation == self.generation,
            HandshakeMismatchSnafu
        );
        Ok(())
    }
}

/// Counts events: the sender numbers them, the receiver checks the numbers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Sequence(u64);

impl Sequence {
    /// The number for the next event to send, starting at 1.
    pub fn advance(&mut self) -> u64 {
        self.0 += 1;
        self.0
    }

    /// Accepts `found` when it is the next number.
    ///
    /// # Errors
    /// [`ProtocolError::SequenceGap`] otherwise; the counter does not move.
    pub fn accept(&mut self, found: u64) -> Result<(), ProtocolError> {
        let expected = self.0 + 1;
        ensure!(found == expected, SequenceGapSnafu { expected, found });
        self.0 = found;
        Ok(())
    }
}

/// Serializes `value` as one frame: JSON and a newline, within [`MAX_FRAME_BYTES`].
///
/// # Errors
/// [`ProtocolError::Encode`] or [`ProtocolError::FrameTooLarge`].
pub fn encode_line<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let mut line = serde_json::to_vec(value).context(EncodeSnafu)?;
    line.push(b'\n');
    ensure!(line.len() <= MAX_FRAME_BYTES, FrameTooLargeSnafu);
    Ok(line)
}

/// The frame for `event` as number `seq`.
///
/// # Errors
/// [`ProtocolError::UnsafeText`] when a text field was not escaped, then as [`encode_line`].
pub fn encode_frame(seq: u64, event: Event) -> Result<Vec<u8>, ProtocolError> {
    event.validate()?;
    encode_line(&Frame { seq, event })
}

/// Reads one frame's bytes, without the newline; `None` at a clean end of input.
///
/// Never buffers more than [`MAX_FRAME_BYTES`], so a peer that never sends a newline cannot
/// grow memory.
///
/// # Errors
/// [`ProtocolError::FrameTooLarge`], [`ProtocolError::Truncated`], [`ProtocolError::EmptyFrame`]
/// or [`ProtocolError::Read`].
pub fn read_line<R: BufRead>(reader: &mut R) -> Result<Option<Vec<u8>>, ProtocolError> {
    let mut line = Vec::new();
    let limit = u64::try_from(MAX_FRAME_BYTES).unwrap_or(u64::MAX);
    let read = reader
        .by_ref()
        .take(limit)
        .read_until(b'\n', &mut line)
        .context(ReadSnafu)?;
    if read == 0 {
        return Ok(None);
    }
    if line.pop() != Some(b'\n') {
        ensure!(read < MAX_FRAME_BYTES, FrameTooLargeSnafu);
        return TruncatedSnafu.fail();
    }
    ensure!(!line.is_empty(), EmptyFrameSnafu);
    Ok(Some(line))
}

/// Parses one frame's bytes into a JSON object, refusing an embedded newline.
fn parse_object(line: &[u8]) -> Result<Value, ProtocolError> {
    ensure!(!line.contains(&b'\n'), EmbeddedNewlineSnafu);
    serde_json::from_slice(line).context(MalformedSnafu)
}

/// Checks the `v` field before anything else is looked at.
fn check_version(object: &Value) -> Result<(), ProtocolError> {
    let found = object.get("v").and_then(Value::as_u64);
    match found {
        Some(found) if found == u64::from(PROTOCOL_VERSION) => Ok(()),
        // A missing or non-numeric version is reported as 0, which no build speaks.
        other => WrongVersionSnafu {
            found: other.unwrap_or(0),
            expected: PROTOCOL_VERSION,
        }
        .fail(),
    }
}

fn decode_versioned<T: serde::de::DeserializeOwned>(line: &[u8]) -> Result<T, ProtocolError> {
    let object = parse_object(line)?;
    check_version(&object)?;
    serde_json::from_value(object).context(MalformedSnafu)
}

/// Decodes the supervisor's handshake.
///
/// # Errors
/// [`ProtocolError::WrongVersion`] before anything else about the contents, then
/// [`ProtocolError::Malformed`].
pub fn decode_hello(line: &[u8]) -> Result<Hello, ProtocolError> {
    decode_versioned(line)
}

/// Decodes `hb`'s handshake answer.
///
/// # Errors
/// As [`decode_hello`].
pub fn decode_ack(line: &[u8]) -> Result<HelloAck, ProtocolError> {
    decode_versioned(line)
}

/// Decodes a command.
///
/// # Errors
/// [`ProtocolError::Malformed`], including for an unknown command or field.
pub fn decode_command(line: &[u8]) -> Result<Command, ProtocolError> {
    serde_json::from_value(parse_object(line)?).context(MalformedSnafu)
}

/// Decodes an event frame and checks its text.
///
/// # Errors
/// [`ProtocolError::Malformed`] (including an unknown field or a missing or non-numeric `seq`)
/// or [`ProtocolError::UnsafeText`].
pub fn decode_frame(line: &[u8]) -> Result<Frame, ProtocolError> {
    let mut object = parse_object(line)?;
    let seq = object
        .as_object_mut()
        .and_then(|fields| fields.remove("seq"))
        .and_then(|seq| seq.as_u64());
    let seq = seq
        .ok_or_else(|| <serde_json::Error as serde::de::Error>::missing_field("seq"))
        .context(MalformedSnafu)?;
    let event: Event = serde_json::from_value(object).context(MalformedSnafu)?;
    event.validate()?;
    Ok(Frame { seq, event })
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_matches, assert_ok};
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    fn every_event() -> Vec<Event> {
        vec![
            Event::Starting {},
            Event::approval_required("/work/shop"),
            Event::Running { agent_pid: 4242 },
            Event::denial("cat(26029) deny(1) file-read-data /Users/me/.ssh/id_rsa"),
            Event::Proxy {
                host: Some("api.example.com".into()),
                port: Some(443),
                decision: Verdict::Allowed {},
                up: 10,
                down: 20,
            },
            Event::Proxy {
                host: None,
                port: None,
                decision: Verdict::Refused {
                    code: "not_allowed".into(),
                    reason: "host is not allowed".into(),
                },
                up: 0,
                down: 0,
            },
            Event::Dropped {
                denials: 3,
                proxy: 4,
            },
            Event::warning("a warning"),
            Event::Stopping {},
            Event::Exited {
                code: Some(0),
                signal: None,
                cleanup: Cleanup::Complete {},
            },
            Event::Exited {
                code: None,
                signal: Some(15),
                cleanup: Cleanup::Failed {
                    what: "a socket remained".into(),
                },
            },
        ]
    }

    #[test]
    fn every_event_round_trips_with_its_sequence_number() {
        for (i, event) in every_event().into_iter().enumerate() {
            let seq = u64::try_from(i).unwrap_or(0) + 1;
            let line = assert_ok!(encode_frame(seq, event.clone()));
            assert_eq!(line.last(), Some(&b'\n'));
            let got = assert_ok!(decode_frame(&line[..line.len() - 1]));
            assert_eq!(got, Frame { seq, event });
        }
    }

    #[test]
    fn every_event_kind_has_a_snake_case_name_matching_its_wire_tag() {
        for event in every_event() {
            let line = assert_ok!(encode_frame(1, event.clone()));
            let value: Value = assert_ok!(serde_json::from_slice(&line));
            assert_eq!(value["event"], event.kind().to_string());
        }
    }

    #[test]
    fn the_stop_command_and_the_handshake_round_trip() {
        let line = assert_ok!(encode_line(&Command::Stop {}));
        assert_eq!(
            assert_ok!(decode_command(&line[..line.len() - 1])),
            Command::Stop {}
        );

        let hello = Hello::new(7, 2);
        let line = assert_ok!(encode_line(&hello));
        assert_eq!(assert_ok!(decode_hello(&line[..line.len() - 1])), hello);

        let ack = HelloAck {
            v: PROTOCOL_VERSION,
            launch: 7,
            generation: 2,
            pid: 99,
        };
        let line = assert_ok!(encode_line(&ack));
        let got = assert_ok!(decode_ack(&line[..line.len() - 1]));
        assert_ok!(hello.check(&got));
    }

    #[test]
    fn an_acknowledgement_for_another_launch_or_generation_is_refused() {
        let hello = Hello::new(7, 2);
        for (launch, generation) in [(8, 2), (7, 3)] {
            let ack = HelloAck {
                v: PROTOCOL_VERSION,
                launch,
                generation,
                pid: 1,
            };
            assert_matches!(hello.check(&ack), Err(ProtocolError::HandshakeMismatch));
        }
    }

    #[test]
    fn a_wrong_or_missing_version_is_reported_before_any_other_field() {
        for bad in [
            &br#"{"v":2,"launch":1,"generation":1}"#[..],
            &br#"{"v":2,"nonsense":true}"#[..],
            &br#"{"launch":1,"generation":1}"#[..],
        ] {
            assert_matches!(decode_hello(bad), Err(ProtocolError::WrongVersion { .. }));
        }
        assert_matches!(
            decode_hello(br#"{"v":1,"launch":1,"generation":1,"x":1}"#),
            Err(ProtocolError::Malformed { .. })
        );
    }

    #[test]
    fn unknown_fields_and_unknown_kinds_are_malformed() {
        for bad in [
            &br#"{"seq":1,"event":"starting","extra":1}"#[..],
            &br#"{"seq":1,"event":"running","agent_pid":1,"extra":1}"#[..],
            &br#"{"seq":1,"event":"grant_access"}"#[..],
            &br#"{"seq":1,"event":"running"}"#[..],
            &br#"{"event":"starting"}"#[..],
            &br#"{"seq":"1","event":"starting"}"#[..],
            &br#"[1]"#[..],
            &br#"not json"#[..],
        ] {
            assert_matches!(
                decode_frame(bad),
                Err(ProtocolError::Malformed { .. }),
                "{bad:?}"
            );
        }
        for bad in [
            &br#"{"cmd":"stop","extra":1}"#[..],
            &br#"{"cmd":"approve"}"#[..],
        ] {
            assert_matches!(decode_command(bad), Err(ProtocolError::Malformed { .. }));
        }
    }

    #[test]
    fn a_frame_is_refused_when_it_holds_a_newline_inside() {
        assert_matches!(
            decode_frame(b"{\"seq\":1,\n\"event\":\"starting\"}"),
            Err(ProtocolError::EmbeddedNewline)
        );
    }

    #[test]
    fn the_reader_stops_at_the_limit_and_does_not_buffer_a_frame_without_a_newline() {
        let endless = vec![b'a'; MAX_FRAME_BYTES * 4];
        assert_matches!(
            read_line(&mut io::Cursor::new(endless)),
            Err(ProtocolError::FrameTooLarge)
        );
        let mut at_limit = vec![b'a'; MAX_FRAME_BYTES - 1];
        at_limit.push(b'\n');
        assert_eq!(
            assert_ok!(read_line(&mut io::Cursor::new(at_limit))).map(|l| l.len()),
            Some(MAX_FRAME_BYTES - 1)
        );
        let mut over = vec![b'a'; MAX_FRAME_BYTES];
        over.push(b'\n');
        assert_matches!(
            read_line(&mut io::Cursor::new(over)),
            Err(ProtocolError::FrameTooLarge)
        );
    }

    #[test]
    fn the_reader_reports_truncation_empty_frames_and_a_clean_end() {
        assert_matches!(
            read_line(&mut io::Cursor::new(b"{\"seq\"".to_vec())),
            Err(ProtocolError::Truncated)
        );
        assert_matches!(
            read_line(&mut io::Cursor::new(b"\n".to_vec())),
            Err(ProtocolError::EmptyFrame)
        );
        assert_eq!(
            assert_ok!(read_line(&mut io::Cursor::new(Vec::new()))),
            None
        );
        let mut two = io::Cursor::new(b"a\nb\n".to_vec());
        assert_eq!(assert_ok!(read_line(&mut two)), Some(b"a".to_vec()));
        assert_eq!(assert_ok!(read_line(&mut two)), Some(b"b".to_vec()));
        assert_eq!(assert_ok!(read_line(&mut two)), None);
    }

    #[test]
    fn an_event_that_does_not_fit_in_a_frame_is_not_encoded() {
        let big = Event::Denial {
            text: "a".repeat(MAX_TEXT_BYTES + 1),
        };
        assert_matches!(encode_frame(1, big), Err(ProtocolError::UnsafeText { .. }));
        let wide = Value::String("a".repeat(MAX_FRAME_BYTES));
        assert_matches!(encode_line(&wide), Err(ProtocolError::FrameTooLarge));
    }

    #[test]
    fn escaped_text_holds_no_control_or_line_reordering_character() {
        let hostile =
            "a\u{1b}]52;c;ZXZpbA==\u{7}b\u{1b}]0;title\u{7}\r\n\u{85}\u{202e}c\u{2028}d\u{0}";
        let safe = escape_text(hostile);
        assert!(!safe.chars().any(is_unsafe), "{safe:?}");
        assert!(safe.contains("\\u{1b}"));
        assert!(is_safe(&safe));
        assert_ok!(encode_frame(1, Event::denial(hostile)));
    }

    #[test]
    fn hostile_text_that_was_not_escaped_is_refused_on_both_sides() {
        let raw = Event::Denial {
            text: "x\u{1b}]52;c;AAAA\u{7}".into(),
        };
        assert_matches!(
            encode_frame(1, raw),
            Err(ProtocolError::UnsafeText { field: "text" })
        );
        // A peer that skips the encoder: JSON escapes spell the control characters.
        let forged = br#"{"seq":1,"event":"denial","text":"x\u001b]52;c;AAAA\u0007"}"#;
        assert_matches!(
            decode_frame(forged),
            Err(ProtocolError::UnsafeText { field: "text" })
        );
        let forged = br#"{"seq":1,"event":"approval_required","root":"/a\u001b[2J"}"#;
        assert_matches!(
            decode_frame(forged),
            Err(ProtocolError::UnsafeText { field: "root" })
        );
    }

    #[test]
    fn escaping_cuts_long_text_on_a_character_boundary_within_the_limit() {
        let long = "é".repeat(MAX_TEXT_BYTES);
        let cut = escape_text(&long);
        assert!(cut.len() <= MAX_TEXT_BYTES);
        assert!(cut.ends_with('…'));
        assert!(is_safe(&cut));
        let escapes = "\u{1b}".repeat(MAX_TEXT_BYTES);
        assert!(escape_text(&escapes).len() <= MAX_TEXT_BYTES);
        assert_eq!(escape_text("plain text"), "plain text");
    }

    #[test]
    fn sequence_numbers_start_at_one_and_a_gap_or_repeat_is_an_error() {
        let mut sender = Sequence::default();
        assert_eq!((sender.advance(), sender.advance()), (1, 2));
        let mut receiver = Sequence::default();
        assert_ok!(receiver.accept(1));
        assert_matches!(
            receiver.accept(3),
            Err(ProtocolError::SequenceGap {
                expected: 2,
                found: 3
            })
        );
        assert_matches!(receiver.accept(1), Err(ProtocolError::SequenceGap { .. }));
        assert_ok!(receiver.accept(2));
    }

    #[test]
    fn a_proxy_audit_event_becomes_a_proxy_event() {
        use crate::policy::{HostName, Port};
        let audit = AuditEvent {
            host: Some(assert_ok!(HostName::parse("api.example.com"))),
            port: Some(Port::HTTPS),
            decision: Decision::Allowed,
            bytes_up: 5,
            bytes_down: 6,
        };
        assert_eq!(
            Event::proxy(&audit),
            Event::Proxy {
                host: Some("api.example.com".into()),
                port: Some(443),
                decision: Verdict::Allowed {},
                up: 5,
                down: 6,
            }
        );
        let none = AuditEvent {
            host: None,
            port: None,
            decision: Decision::Refused {
                code: "bad\u{1b}",
                reason: "no\u{7}".into(),
            },
            bytes_up: 0,
            bytes_down: 0,
        };
        assert_ok!(Event::proxy(&none).validate());
    }

    fn arb_text() -> impl Strategy<Value = String> {
        // Any characters, including controls and bidi marks, run through the escaper.
        proptest::collection::vec(any::<char>(), 0..64)
            .prop_map(|c| escape_text(&c.into_iter().collect::<String>()))
    }

    fn arb_event() -> impl Strategy<Value = Event> {
        prop_oneof![
            Just(Event::Starting {}),
            arb_text().prop_map(|root| Event::ApprovalRequired { root }),
            any::<u32>().prop_map(|agent_pid| Event::Running { agent_pid }),
            arb_text().prop_map(|text| Event::Denial { text }),
            arb_text().prop_map(|text| Event::Warning { text }),
            (any::<u64>(), any::<u64>())
                .prop_map(|(denials, proxy)| Event::Dropped { denials, proxy }),
            (
                proptest::option::of(arb_text()),
                proptest::option::of(any::<u16>()),
                prop_oneof![
                    Just(Verdict::Allowed {}),
                    (arb_text(), arb_text())
                        .prop_map(|(code, reason)| Verdict::Refused { code, reason }),
                ],
                any::<u64>(),
                any::<u64>(),
            )
                .prop_map(|(host, port, decision, up, down)| Event::Proxy {
                    host,
                    port,
                    decision,
                    up,
                    down
                }),
            Just(Event::Stopping {}),
            (
                proptest::option::of(any::<i32>()),
                proptest::option::of(any::<i32>()),
                prop_oneof![
                    Just(Cleanup::Complete {}),
                    arb_text().prop_map(|what| Cleanup::Failed { what }),
                ],
            )
                .prop_map(|(code, signal, cleanup)| Event::Exited {
                    code,
                    signal,
                    cleanup
                }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        #[test]
        fn encoder_output_always_decodes_to_the_same_value(seq in 1u64.., event in arb_event()) {
            let line = encode_frame(seq, event.clone()).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert!(line.len() <= MAX_FRAME_BYTES);
            prop_assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
            let got = read_line(&mut io::Cursor::new(line))
                .map_err(|e| TestCaseError::fail(e.to_string()))?
                .ok_or_else(|| TestCaseError::fail("no frame"))?;
            let frame = decode_frame(&got).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(frame, Frame { seq, event });
        }

        #[test]
        fn escaped_text_is_always_safe_and_within_the_limit(text in any::<String>()) {
            let safe = escape_text(&text);
            prop_assert!(is_safe(&safe));
        }

        #[test]
        fn the_decoder_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = decode_frame(&bytes);
            let _ = decode_hello(&bytes);
            let _ = decode_command(&bytes);
            let _ = assert_err!(decode_frame(b"").map(|_| ()));
        }
    }
}
