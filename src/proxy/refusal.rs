// ABOUTME: Refusal: why the proxy answers a connection with an error instead of serving it, and the HTTP reply that says so.
// ABOUTME: Every refusal has a status, a stable code in the X-Hb-Refusal header and a plain-text reason for the person reading the agent's error.
//! Refusing a connection.
//!
//! The agent sees only an HTTP error from its proxy, so the reply says why in one line of plain
//! text. The reply is built from validated values (a [`HostName`], a port) and escaped error
//! text, never from raw request bytes.

use snafu::{Report, Snafu};

use std::net::IpAddr;

use super::address::{AddressRefusal, Internal, Never};
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

    /// The request carried no valid proxy credentials.
    #[snafu(display("proxy authentication required"))]
    ProxyAuthRequired,

    /// The host is not on the allowlist.
    #[snafu(display("{host} is not on the allowlist"))]
    NotAllowed {
        /// The host that was asked for.
        host: HostName,
    },

    /// The host is on the allowlist, but not for this port.
    #[snafu(display(
        "{host} is allowed on other ports but not on {port}; to allow it, add \"{host}:{port}\" to net.allow"
    ))]
    PortNotAllowed {
        /// The host.
        host: HostName,
        /// The port that was asked for.
        port: Port,
    },

    /// The host resolved only to addresses that are never allowed.
    #[snafu(display("{host} resolved to {address}, which is {kind}; that is never allowed"))]
    ForbiddenAddress {
        /// The host.
        host: HostName,
        /// The address it resolved to.
        address: IpAddr,
        /// What the address is.
        kind: Never,
    },

    /// The host resolved only to private or tunnel addresses and is not an internal host.
    #[snafu(display(
        "{host} resolved to {address}, which is {kind}; to allow it, add \"{host}\" to net.internal_hosts in your own config"
    ))]
    InternalAddress {
        /// The host.
        host: HostName,
        /// The address it resolved to.
        address: IpAddr,
        /// What the address is.
        kind: Internal,
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
    /// The refusal for the addresses of `host` that `refusal` rejected.
    #[must_use]
    pub fn for_address(host: HostName, refusal: AddressRefusal) -> Self {
        match refusal {
            AddressRefusal::Never { address, kind } => Self::ForbiddenAddress {
                host,
                address,
                kind,
            },
            AddressRefusal::Internal { address, kind } => Self::InternalAddress {
                host,
                address,
                kind,
            },
        }
    }

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
            Self::ProxyAuthRequired => (407, "Proxy Authentication Required"),
            Self::NotAllowed { .. }
            | Self::PortNotAllowed { .. }
            | Self::ForbiddenAddress { .. }
            | Self::InternalAddress { .. } => (403, "Forbidden"),
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
            Self::ProxyAuthRequired => "proxy_auth_required",
            Self::NotAllowed { .. } => "not_allowed",
            Self::PortNotAllowed { .. } => "port_not_allowed",
            Self::ForbiddenAddress { .. } => "address_refused",
            Self::InternalAddress { .. } => "internal_address",
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
        let challenge = if code == 407 {
            "Proxy-Authenticate: Basic realm=\"hb\"\r\n"
        } else {
            ""
        };
        format!(
            "HTTP/1.1 {code} {phrase}\r\n{challenge}Content-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nX-Hb-Refusal: {}\r\n\r\n{body}",
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
    fn a_407_challenges_with_basic_and_no_other_refusal_does() {
        let text = String::from_utf8_lossy(&Refusal::ProxyAuthRequired.response()).into_owned();
        assert!(
            text.starts_with("HTTP/1.1 407 Proxy Authentication Required\r\n"),
            "{text}"
        );
        assert!(
            text.contains("Proxy-Authenticate: Basic realm=\"hb\"\r\n"),
            "{text}"
        );
        assert!(text.contains("X-Hb-Refusal: proxy_auth_required\r\n"));
        let other = String::from_utf8_lossy(&Refusal::Busy.response()).into_owned();
        assert!(!other.contains("Proxy-Authenticate"));
    }

    #[test]
    fn the_port_and_address_refusals_say_what_to_write_in_the_config() {
        let port = Refusal::PortNotAllowed {
            host: host("api.example.com"),
            port: assert_ok!(Port::try_from(8443)),
        };
        assert_eq!(port.status().0, 403);
        assert_eq!(port.code(), "port_not_allowed");
        assert!(
            port.reason()
                .contains("add \"api.example.com:8443\" to net.allow"),
            "{}",
            port.reason()
        );
        let internal = Refusal::for_address(
            host("github.com"),
            AddressRefusal::Internal {
                address: assert_ok!("100.64.1.3".parse::<IpAddr>()),
                kind: Internal::SharedAddressSpace,
            },
        );
        assert_eq!(internal.code(), "internal_address");
        let reason = internal.reason();
        assert!(reason.contains("100.64.1.3"), "{reason}");
        assert!(
            reason.contains("tunnel or shared address space"),
            "{reason}"
        );
        assert!(
            reason.contains("add \"github.com\" to net.internal_hosts"),
            "{reason}"
        );
        let never = Refusal::for_address(
            host("a.example.com"),
            AddressRefusal::Never {
                address: assert_ok!("127.0.0.1".parse::<IpAddr>()),
                kind: Never::Loopback,
            },
        );
        assert_eq!(never.code(), "address_refused");
        assert!(
            never.reason().contains("never allowed"),
            "{}",
            never.reason()
        );
        assert!(!never.reason().contains("net.internal_hosts"));
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
