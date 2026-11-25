// ABOUTME: Closed one-line request protocol for the container and launchd broker, validated again on the host.
// ABOUTME: The pure operation table defines required targets, tail limits, mutation exclusion and mount-gate requirements.
//! The wire protocol and its validated requests.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu, ensure};
use strum::{AsRefStr, Display, EnumString};

use crate::policy::{ContainerName, ContainerNameError, LaunchdLabel, LaunchdLabelError};

/// Maximum request line length, including its newline.
pub const MAX_REQUEST_BYTES: usize = 4096;
/// Maximum retained command output (bytes, before JSON escaping).
pub const MAX_OUTPUT_BYTES: usize = 20_000;
/// Maximum encoded response, including its newline (JSON escaping can expand bytes sixfold).
pub const MAX_RESPONSE_BYTES: usize = MAX_OUTPUT_BYTES * 6 + 4096;
/// Default log tail, with no client option.
pub const DEFAULT_TAIL: u16 = 100;
/// Largest permitted log tail.
pub const MAX_TAIL: u16 = 2000;

/// Supported container operations. No arbitrary command or argument list exists in the protocol.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Display, AsRefStr, EnumString,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum ContainerOp {
    /// List vetted containers in the approved scope.
    Ps,
    /// Read a bounded log tail.
    Logs,
    /// Read one non-streaming stats sample.
    Stats,
    /// Start one existing container, without attaching.
    Start,
    /// Stop one existing container.
    Stop,
    /// Restart one existing container.
    Restart,
}

impl ContainerOp {
    /// Whether two simultaneous operations on this target must be refused.
    #[must_use]
    pub fn mutates(self) -> bool {
        matches!(self, Self::Start | Self::Stop | Self::Restart)
    }

    /// Whether this operation re-resolves mounts and requires runtime isolation and startup pins.
    #[must_use]
    pub fn needs_pin_gate(self) -> bool {
        matches!(self, Self::Start | Self::Restart)
    }

    /// Total execution budget, including metadata queries.
    #[must_use]
    pub fn timeout(self) -> Duration {
        Duration::from_secs(if self.mutates() { 60 } else { 30 })
    }
}

/// Supported operations on one owner-listed launchd job.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, Display, AsRefStr, EnumString,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum LaunchdOp {
    /// Show only state, pid, runs and last exit code, never raw launchctl output.
    Status,
    /// Ask launchd to start a loaded job.
    Kickstart,
    /// Kill and start a loaded job (`kickstart -k`).
    Restart,
}

impl LaunchdOp {
    /// Whether this operation changes a job.
    #[must_use]
    pub fn mutates(self) -> bool {
        !matches!(self, Self::Status)
    }
}

/// An untrusted request, decoded from one bounded JSON line.
///
/// Serde rejects unknown operations and fields; validation below rejects invalid names and
/// combinations. The client cannot supply a UID, executable, domain, environment or argv.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "target", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// A container operation. Only ps may omit its name; ps may also name one container.
    Container {
        /// Operation.
        op: ContainerOp,
        /// Name, not a container ID supplied by the client.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// Logs only; capped by the broker.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tail: Option<u64>,
    },
    /// A launchd operation in the broker user's GUI domain.
    Launchd {
        /// Operation.
        op: LaunchdOp,
        /// Exact owner-listed label.
        label: String,
    },
}

/// Why a syntactically valid request is refused.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RequestError {
    /// A named container operation has no name.
    #[snafu(display("this operation requires a container name"))]
    MissingName,
    /// A name could be an option or is otherwise invalid.
    #[snafu(display("invalid container name"))]
    Name {
        /// Underlying validation failure.
        source: ContainerNameError,
    },
    /// A label could change the launchd target or is otherwise invalid.
    #[snafu(display("invalid launchd label"))]
    Label {
        /// Underlying validation failure.
        source: LaunchdLabelError,
    },
    /// Tail was given for an operation other than logs.
    #[snafu(display("tail is only permitted for logs"))]
    UnexpectedTail,
}

/// A request that has passed the host's pure validation. Constructed only by [`Request::validate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedRequest(Validated);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Validated {
    Container {
        op: ContainerOp,
        name: Option<ContainerName>,
        tail: u16,
    },
    Launchd {
        op: LaunchdOp,
        label: LaunchdLabel,
    },
}

impl Request {
    /// Validate names and operation-specific parameters on the broker, not just in clap.
    ///
    /// # Errors
    /// [`RequestError`] for a missing or malformed target, or a tail on a non-log operation.
    pub fn validate(self) -> Result<ValidatedRequest, RequestError> {
        let validated = match self {
            Self::Container { op, name, tail } => {
                ensure!(
                    tail.is_none() || op == ContainerOp::Logs,
                    UnexpectedTailSnafu
                );
                ensure!(name.is_some() || op == ContainerOp::Ps, MissingNameSnafu);
                let name = name
                    .map(|s| ContainerName::parse(&s).context(NameSnafu))
                    .transpose()?;
                let tail = tail
                    .unwrap_or(u64::from(DEFAULT_TAIL))
                    .min(u64::from(MAX_TAIL));
                Validated::Container {
                    op,
                    name,
                    tail: u16::try_from(tail).unwrap_or(MAX_TAIL),
                }
            }
            Self::Launchd { op, label } => Validated::Launchd {
                op,
                label: LaunchdLabel::parse(&label).context(LabelSnafu)?,
            },
        };
        Ok(ValidatedRequest(validated))
    }
}

impl ValidatedRequest {
    pub(crate) fn command(&self) -> &Validated {
        &self.0
    }

    /// Whether this request changes a service and must reserve its target.
    #[must_use]
    pub fn mutates(&self) -> bool {
        match &self.0 {
            Validated::Container { op, .. } => op.mutates(),
            Validated::Launchd { op, .. } => op.mutates(),
        }
    }

    /// Whether this request needs the isolated-runtime and startup-source gate.
    #[must_use]
    pub fn needs_pin_gate(&self) -> bool {
        matches!(&self.0, Validated::Container { op, .. } if op.needs_pin_gate())
    }

    /// Total execution budget, including preflight.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        match &self.0 {
            Validated::Container { op, .. } => op.timeout(),
            Validated::Launchd { .. } => Duration::from_secs(10),
        }
    }
}

/// One response; raw inspect and launchctl metadata never enter this envelope.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    /// Whether the command succeeded (not a claim that the service is healthy).
    pub ok: bool,
    /// Bounded user-visible output.
    pub out: String,
    /// A refusal or sanitized failure message.
    pub err: String,
    /// Whether command output was truncated.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn parse(s: &str) -> Request {
        assert_ok!(serde_json::from_str(s))
    }

    #[test]
    fn test_protocol_rejects_forbidden_ops_and_extra_authority() {
        for op in [
            "run", "exec", "cp", "rm", "build", "compose", "kube", "inspect",
        ] {
            let json = format!(r#"{{"target":"container","op":"{op}","name":"db"}}"#);
            assert_err!(serde_json::from_str::<Request>(&json));
        }
        for json in [
            r#"{"target":"container","op":"ps","argv":["--all"]}"#,
            r#"{"target":"container","op":"ps","uid":0}"#,
            r#"{"target":"launchd","op":"restart","label":"job","domain":"system"}"#,
            r#"{"target":"launchd","op":"bootout","label":"job"}"#,
            r#"{"target":"launchd","op":"restart","label":"job","tail":1}"#,
        ] {
            assert_err!(serde_json::from_str::<Request>(json));
        }
    }

    #[test]
    fn test_protocol_requires_names_and_rejects_injection() {
        for op in ["logs", "stats", "start", "stop", "restart"] {
            assert_err!(parse(&format!(r#"{{"target":"container","op":"{op}"}}"#)).validate());
        }
        for name in ["--help", "a;id", "a/b", "", &"a".repeat(65)] {
            let req = Request::Container {
                op: ContainerOp::Restart,
                name: Some(name.into()),
                tail: None,
            };
            assert_err!(req.validate());
        }
        for label in ["system/job", "-k", "a;id", ""] {
            assert_err!(
                Request::Launchd {
                    op: LaunchdOp::Restart,
                    label: label.into()
                }
                .validate()
            );
        }
        assert_ok!(parse(r#"{"target":"container","op":"ps"}"#).validate());
        assert_ok!(parse(r#"{"target":"container","op":"ps","name":"db"}"#).validate());
    }

    #[test]
    fn test_protocol_caps_log_tail_and_rejects_tail_on_other_ops() {
        for (input, expected) in [
            (None, 100),
            (Some(0), 0),
            (Some(10), 10),
            (Some(u64::MAX), 2000),
        ] {
            let req = assert_ok!(
                Request::Container {
                    op: ContainerOp::Logs,
                    name: Some("db".into()),
                    tail: input
                }
                .validate()
            );
            assert!(matches!(&req.0, Validated::Container { tail, .. } if *tail == expected));
        }
        assert_err!(parse(r#"{"target":"container","op":"ps","tail":1}"#).validate());
        assert_err!(serde_json::from_str::<Request>(
            r#"{"target":"container","op":"logs","name":"db","tail":-1}"#
        ));
    }

    #[test]
    fn test_operation_table_keeps_mount_gate_separate_from_mutation_lock() {
        for op in [
            ContainerOp::Ps,
            ContainerOp::Logs,
            ContainerOp::Stats,
            ContainerOp::Start,
            ContainerOp::Stop,
            ContainerOp::Restart,
        ] {
            assert_eq!(
                op.mutates(),
                matches!(
                    op,
                    ContainerOp::Start | ContainerOp::Stop | ContainerOp::Restart
                )
            );
            assert_eq!(
                op.needs_pin_gate(),
                matches!(op, ContainerOp::Start | ContainerOp::Restart)
            );
            assert_eq!(assert_ok!(op.to_string().parse::<ContainerOp>()), op);
        }
        assert!(!LaunchdOp::Status.mutates());
        assert!(LaunchdOp::Kickstart.mutates());
        assert!(LaunchdOp::Restart.mutates());
    }
}
