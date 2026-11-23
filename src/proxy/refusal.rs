// ABOUTME: Refusal: why the proxy answers a connection with an error instead of serving it, and the HTTP reply that says so.
// ABOUTME: Every refusal has a status, a stable code in the X-Hb-Refusal header and a plain-text reason for the person reading the agent's error.
//! Refusing a connection.
//!
//! The agent sees only an HTTP error from its proxy, so the reply says why in one line of plain
//! text. The reply is built from validated values (a [`HostName`], a port) and escaped error
//! text, never from raw request bytes.

use snafu::{Report, Snafu};

use super::authority::AuthorityError;
use super::request::RequestError;
use crate::policy::{HostName, Port};

/// Why a connection is not served.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Refusal {
    /// The request head could not be accepted.
    #[snafu(transparent)]
    BadRequest {
        /// Why.
        source: RequestError,
    },

    /// The host is not on the allowlist.
    #[snafu(display("{host} is not on the allowlist"))]
    NotAllowed {
        /// The host that was asked for.
        host: HostName,
    },

    /// The client did not finish its request in time.
    #[snafu(display("the request head did not arrive in time"))]
    HeadTimeout,

    /// The name did not resolve.
    #[snafu(display("{host} did not resolve"))]
    Unresolved {
        /// The host.
        host: HostName,
    },

    /// Resolving or connecting took too long.
    #[snafu(display("{host}:{port} did not answer in time"))]
    TimedOut {
        /// The host.
        host: HostName,
        /// The port.
        port: Port,
    },

    /// Every address of the host refused or failed.
    #[snafu(display("could not connect to {host}:{port}"))]
    Unreachable {
        /// The host.
        host: HostName,
        /// The port.
        port: Port,
    },

    /// Too many connections are open.
    #[snafu(display("too many open connections; try again"))]
    Busy,
}

impl Refusal {
    /// The HTTP status code and reason phrase.
    #[must_use]
    pub fn status(&self) -> (u16, &'static str) {
        match self {
            Self::BadRequest { source } => match source {
                RequestError::TooLarge => (431, "Request Header Fields Too Large"),
                RequestError::BadTarget {
                    source: AuthorityError::IpLiteral { .. },
                } => (403, "Forbidden"),
                _ => (400, "Bad Request"),
            },
            Self::NotAllowed { .. } => (403, "Forbidden"),
            Self::HeadTimeout => (408, "Request Timeout"),
            Self::Unresolved { .. } | Self::Unreachable { .. } => (502, "Bad Gateway"),
            Self::TimedOut { .. } => (504, "Gateway Timeout"),
            Self::Busy => (503, "Service Unavailable"),
        }
    }

    /// A short stable name for the refusal, sent as `X-Hb-Refusal`.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::BadRequest { source } => match source {
                RequestError::Malformed => "malformed",
                RequestError::TooLarge => "too_large",
                RequestError::UnsupportedScheme { .. } => "unsupported_scheme",
                RequestError::NotAProxyRequest => "not_a_proxy_request",
                RequestError::BadTarget {
                    source: AuthorityError::IpLiteral { .. },
                } => "ip_literal",
                RequestError::BadTarget { .. } => "bad_target",
            },
            Self::NotAllowed { .. } => "not_allowed",
            Self::HeadTimeout => "head_timeout",
            Self::Unresolved { .. } => "unresolved",
            Self::TimedOut { .. } => "timed_out",
            Self::Unreachable { .. } => "unreachable",
            Self::Busy => "busy",
        }
    }

    /// The reason as one line of text, with the causes after it.
    #[must_use]
    pub fn reason(&self) -> String {
        Report::from_error(self).to_string().replace('\n', " ")
    }

    /// The complete HTTP/1.1 reply, ending the connection.
    #[must_use]
    pub fn response(&self) -> Vec<u8> {
        let (code, phrase) = self.status();
        let body = format!("hb proxy: {}\n", self.reason());
        format!(
            "HTTP/1.1 {code} {phrase}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nX-Hb-Refusal: {}\r\n\r\n{body}",
            body.len(),
            self.code()
        )
        .into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::request::parse_head;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn host(text: &str) -> HostName {
        assert_ok!(HostName::parse(text))
    }

    #[test]
    fn a_denied_host_is_a_403_that_names_the_host_and_the_code() {
        let refusal = Refusal::NotAllowed {
            host: host("evil.example.com"),
        };
        let text = String::from_utf8_lossy(&refusal.response()).into_owned();
        assert!(text.starts_with("HTTP/1.1 403 Forbidden\r\n"), "{text}");
        assert!(text.contains("X-Hb-Refusal: not_allowed\r\n"), "{text}");
        assert!(
            text.contains("evil.example.com is not on the allowlist"),
            "{text}"
        );
        assert!(text.contains("Connection: close\r\n"));
    }

    #[test]
    fn content_length_matches_the_body() {
        let refusal = Refusal::Busy;
        let bytes = refusal.response();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let (head, body) = assert_some_split(&text);
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .and_then(|n| n.parse().ok())
            .unwrap_or(usize::MAX);
        assert_eq!(declared, body.len());
    }

    fn assert_some_split(text: &str) -> (&str, &str) {
        match text.split_once("\r\n\r\n") {
            Some(parts) => parts,
            None => {
                assert_ok!(Err::<(), _>("no blank line"));
                ("", "")
            }
        }
    }

    #[test]
    fn statuses_follow_the_kind_of_refusal() {
        let cases: [(Refusal, u16, &str); 6] = [
            (Refusal::HeadTimeout, 408, "head_timeout"),
            (Refusal::Busy, 503, "busy"),
            (
                Refusal::Unresolved {
                    host: host("a.example.com"),
                },
                502,
                "unresolved",
            ),
            (
                Refusal::Unreachable {
                    host: host("a.example.com"),
                    port: assert_ok!(Port::try_from(443)),
                },
                502,
                "unreachable",
            ),
            (
                Refusal::TimedOut {
                    host: host("a.example.com"),
                    port: assert_ok!(Port::try_from(443)),
                },
                504,
                "timed_out",
            ),
            (
                Refusal::NotAllowed {
                    host: host("a.example.com"),
                },
                403,
                "not_allowed",
            ),
        ];
        for (refusal, status, code) in cases {
            assert_eq!(refusal.status().0, status, "{refusal:?}");
            assert_eq!(refusal.code(), code);
        }
    }

    #[test]
    fn bad_requests_map_by_cause_and_an_address_literal_is_a_403() {
        let cases = [
            ("GET /x HTTP/1.1\r\n\r\n", 400, "not_a_proxy_request"),
            (
                "GET https://a.example.com/ HTTP/1.1\r\n\r\n",
                400,
                "unsupported_scheme",
            ),
            ("CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", 403, "ip_literal"),
            ("CONNECT example.com HTTP/1.1\r\n\r\n", 400, "bad_target"),
            ("\x16\x03\x01\r\n\r\n", 400, "malformed"),
        ];
        for (head, status, code) in cases {
            let error = assert_err!(parse_head(head.as_bytes()));
            let refusal = Refusal::from(error);
            assert_eq!(
                (refusal.status().0, refusal.code()),
                (status, code),
                "{head:?}"
            );
        }
    }

    #[test]
    fn the_reason_is_one_line_and_never_contains_a_control_character_from_the_request() {
        let error = assert_err!(parse_head(
            b"CONNECT exa\x1b[2Jmple.com:443 HTTP/1.1\r\n\r\n"
        ));
        let reply = String::from_utf8_lossy(&Refusal::from(error).response()).into_owned();
        let (_, body) = reply.split_once("\r\n\r\n").unwrap_or_default();
        assert!(!body.contains('\u{1b}'), "{body:?}");
        assert_eq!(body.lines().count(), 1, "{body:?}");
    }
}
