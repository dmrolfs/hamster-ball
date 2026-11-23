// ABOUTME: Authority: the host and port a proxy request names, parsed from `host:port`, never from an address literal.
// ABOUTME: Pure; the host goes through HostName, so a name the allowlist could never match is refused here with a reason.
//! The target of a proxy request.
//!
//! A `CONNECT` names its target as `host:port`; a plain request names it in an absolute URI,
//! where the port is optional. Either way the host must be a name: an address literal would
//! bypass the allowlist (an allowed entry is a host name) and the address checks that follow
//! name resolution (decision D2 of hb-ghd.3: literals are always refused in v1).

use std::net::IpAddr;

use snafu::{ResultExt, Snafu};

use crate::policy::{HostName, HostNameError, Port};
use crate::text::EscapedBounded;

/// How much of a hostile input is echoed back in an error message.
const ERROR_PREVIEW_CHARS: usize = 64;

/// A host name and a port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authority {
    /// The target host, lowercase, without a trailing dot.
    pub host: HostName,
    /// The target port.
    pub port: Port,
}

impl Authority {
    /// Parses `host:port`, or `host` when `default_port` is given.
    ///
    /// # Errors
    /// See [`AuthorityError`].
    pub fn parse(text: &str, default_port: Option<Port>) -> Result<Self, AuthorityError> {
        if text.is_empty() {
            return Err(AuthorityError::Empty);
        }
        if text.starts_with('[') {
            return Err(AuthorityError::IpLiteral {
                text: text.to_owned(),
            });
        }
        let (host_text, port_text) = match text.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (text, None),
        };
        if host_text.parse::<IpAddr>().is_ok() {
            return Err(AuthorityError::IpLiteral {
                text: text.to_owned(),
            });
        }
        let host = HostName::parse(host_text).context(BadHostSnafu)?;
        let port = match (port_text, default_port) {
            (Some(port), _) => parse_port(port)?,
            (None, Some(port)) => port,
            (None, None) => return Err(AuthorityError::MissingPort),
        };
        Ok(Self { host, port })
    }
}

fn parse_port(text: &str) -> Result<Port, AuthorityError> {
    let bad = || AuthorityError::BadPort {
        text: text.to_owned(),
    };
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let number: i64 = text.parse().map_err(|_| bad())?;
    Port::try_from(number).map_err(|_| bad())
}

/// Why a request's target is not acceptable.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum AuthorityError {
    /// There is no target.
    #[snafu(display("the request names no host"))]
    Empty,

    /// The target is an IP address, not a name.
    #[snafu(display(
        "the target {} is an address, not a name; only host names can be allowed",
        EscapedBounded::new(text, ERROR_PREVIEW_CHARS)
    ))]
    IpLiteral {
        /// The target as written.
        text: String,
    },

    /// A `CONNECT` target without a port.
    #[snafu(display("the target has no port"))]
    MissingPort,

    /// The port is not a number from 1 to 65535.
    #[snafu(display(
        "the port {} is not a number from 1 to 65535",
        EscapedBounded::new(text, ERROR_PREVIEW_CHARS)
    ))]
    BadPort {
        /// The port as written.
        text: String,
    },

    /// The host is not an acceptable name.
    #[snafu(display("the host is not acceptable"))]
    BadHost {
        /// Why.
        source: HostNameError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn port(n: i64) -> Port {
        assert_ok!(Port::try_from(n))
    }

    #[test]
    fn a_host_and_port_are_split_and_the_host_is_normalised() {
        let a = assert_ok!(Authority::parse("Example.COM.:443", None));
        assert_eq!(a.host.as_str(), "example.com");
        assert_eq!(a.port, port(443));
    }

    #[test]
    fn a_default_port_applies_only_when_none_is_written() {
        let a = assert_ok!(Authority::parse("example.com", Some(port(80))));
        assert_eq!(a.port, port(80));
        let b = assert_ok!(Authority::parse("example.com:8080", Some(port(80))));
        assert_eq!(b.port, port(8080));
        assert!(matches!(
            assert_err!(Authority::parse("example.com", None)),
            AuthorityError::MissingPort
        ));
    }

    #[test]
    fn address_literals_are_refused_in_every_spelling_we_can_parse() {
        for text in [
            "127.0.0.1:443",
            "10.1.2.3:443",
            "[::1]:443",
            "[2001:db8::1]:443",
            "[::ffff:127.0.0.1]:443",
            "::1:443",
            "169.254.169.254:80",
        ] {
            assert!(
                matches!(
                    assert_err!(Authority::parse(text, None)),
                    AuthorityError::IpLiteral { .. }
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn numeric_spellings_of_an_address_are_refused_as_bad_hosts() {
        for text in [
            "2130706433:443",
            "0x7f.1:443",
            "0177.0.0.1:443",
            "1.2.3:443",
        ] {
            assert!(
                matches!(
                    assert_err!(Authority::parse(text, None)),
                    AuthorityError::BadHost { .. }
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn userinfo_paths_whitespace_and_localhost_are_bad_hosts() {
        for text in [
            "user@example.com:443",
            "example.com/x:443",
            "exa mple.com:443",
            "localhost:443",
            "foo.localhost:443",
            "under_score.example.com:443",
            ":443",
        ] {
            let error = assert_err!(Authority::parse(text, None));
            assert!(
                matches!(
                    error,
                    AuthorityError::BadHost { .. } | AuthorityError::Empty
                ),
                "{text}: {error:?}"
            );
        }
    }

    #[test]
    fn ports_must_be_plain_numbers_from_1_to_65535() {
        for text in [
            "example.com:0",
            "example.com:65536",
            "example.com:-1",
            "example.com:+443",
            "example.com:0x1bb",
            "example.com:44 3",
            "example.com:",
            "example.com:99999999999999999999",
            "example.com:000443",
        ] {
            assert!(
                matches!(
                    assert_err!(Authority::parse(text, None)),
                    AuthorityError::BadPort { .. }
                ),
                "{text}"
            );
        }
        assert_eq!(
            assert_ok!(Authority::parse("a.example.com:65535", None)).port,
            port(65535)
        );
    }

    #[test]
    fn an_empty_target_is_refused_and_errors_never_echo_control_characters() {
        assert!(matches!(
            assert_err!(Authority::parse("", None)),
            AuthorityError::Empty
        ));
        let shown = assert_err!(Authority::parse("[\u{1b}[2J]:443", None)).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        let shown = assert_err!(Authority::parse("example.com:4\u{1b}", None)).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }
}
