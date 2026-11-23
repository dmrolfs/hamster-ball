// ABOUTME: Audit events: one per connection with host, port, decision and byte counts, and the sink that receives them.
// ABOUTME: Events carry no headers, no bodies and no token; what to do with them (stream, summarise, keep) is the caller's.
//! The proxy's audit trail (design 12).
//!
//! Each connection ends in one [`AuditEvent`]: where it went, whether it was served or refused,
//! why, and how many bytes crossed in each direction. Nothing from the request other than the
//! validated host and port is recorded, so the event cannot carry a secret.

use std::fmt;

use crate::policy::{HostName, Port};

/// What became of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The connection was served.
    Allowed,
    /// The connection was refused.
    Refused {
        /// The stable refusal code (the `X-Hb-Refusal` header).
        code: &'static str,
        /// The reason in one line.
        reason: String,
    },
}

impl Decision {
    /// The decision for a connection refused with `refusal`.
    #[must_use]
    pub fn refused(refusal: &super::Refusal) -> Self {
        Self::Refused {
            code: refusal.code(),
            reason: refusal.reason(),
        }
    }
}

/// One connection's record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// The host asked for, when the request named a valid one.
    pub host: Option<HostName>,
    /// The port asked for, when the request named a valid one.
    pub port: Option<Port>,
    /// Served or refused.
    pub decision: Decision,
    /// Bytes sent from the agent to the upstream.
    pub bytes_up: u64,
    /// Bytes sent from the upstream to the agent.
    pub bytes_down: u64,
}

impl AuditEvent {
    /// The target as `host:port`, or `-` when the request named none.
    #[must_use]
    pub fn target(&self) -> String {
        match (&self.host, self.port) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            _ => "-".to_owned(),
        }
    }
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.decision {
            Decision::Allowed => write!(
                f,
                "allowed {} up={} down={}",
                self.target(),
                self.bytes_up,
                self.bytes_down
            ),
            Decision::Refused { code, reason } => {
                write!(f, "refused {} {code} ({reason})", self.target())
            }
        }
    }
}

/// Receives audit events.
///
/// `record` runs on the proxy's thread: it must not block.
pub trait AuditSink: Send + Sync + 'static {
    /// Takes one event.
    fn record(&self, event: &AuditEvent);
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    fn event(decision: Decision) -> AuditEvent {
        AuditEvent {
            host: Some(assert_ok!(HostName::parse("app.kiro.dev"))),
            port: Some(assert_ok!(Port::try_from(443))),
            decision,
            bytes_up: 12,
            bytes_down: 3400,
        }
    }

    #[test]
    fn an_allowed_event_shows_the_target_and_both_byte_counts() {
        assert_eq!(
            event(Decision::Allowed).to_string(),
            "allowed app.kiro.dev:443 up=12 down=3400"
        );
    }

    #[test]
    fn a_refused_event_shows_the_code_and_the_reason_and_no_counts() {
        let shown = event(Decision::Refused {
            code: "not_allowed",
            reason: "app.kiro.dev is not on the allowlist".to_owned(),
        })
        .to_string();
        assert_eq!(
            shown,
            "refused app.kiro.dev:443 not_allowed (app.kiro.dev is not on the allowlist)"
        );
    }

    #[test]
    fn a_request_without_a_valid_target_is_shown_with_a_dash() {
        let mut e = event(Decision::Allowed);
        e.host = None;
        e.port = None;
        assert!(e.to_string().starts_with("allowed - up="));
        assert_eq!(e.target(), "-");
    }
}
