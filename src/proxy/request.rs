// ABOUTME: Parses a proxy request head into a CONNECT target or a rewritten plain-HTTP request; pure over bytes.
// ABOUTME: A plain request is forwarded once per connection with Connection: close, so no body framing is ever parsed.
//! The first request on a proxy connection.
//!
//! Only the head is parsed ([`httparse`]); a body is never framed. A plain request is rewritten
//! to origin form with `Connection: close` and sent upstream as the only request on that
//! connection, then bytes are copied both ways until either side ends (decision D4 of
//! hb-ghd.3). A client that pipelines a second request has it forwarded to the same upstream
//! host as body bytes, so it cannot reach another host. `CONNECT` is never framed at all.

use snafu::{ResultExt, Snafu};

use super::authority::{Authority, AuthorityError};
use crate::policy::Port;
use crate::text::EscapedBounded;

/// The most bytes read before the head must be complete.
pub const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The most header lines accepted.
const MAX_HEADERS: usize = 64;
/// How much of a hostile method or scheme is echoed back in an error message.
const ERROR_PREVIEW_CHARS: usize = 32;

/// The request line and headers of the first request, understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// `CONNECT host:port`: open a tunnel.
    Connect(Authority),
    /// An absolute-URI request: forward `head` upstream, then copy.
    Forward {
        /// Where it goes.
        authority: Authority,
        /// The request line and headers, rewritten for the origin server.
        head: Vec<u8>,
    },
}

/// Headers a proxy must not pass on, or that this proxy replaces.
const DROPPED_HEADERS: [&str; 8] = [
    "host",
    "connection",
    "proxy-connection",
    "proxy-authorization",
    "proxy-authenticate",
    "keep-alive",
    "te",
    "upgrade",
];

/// Parses the head in `buf`.
///
/// Returns `Ok(None)` when more bytes are needed, and otherwise the request and how many bytes
/// of `buf` the head took (the rest belong to the body or the tunnel).
///
/// # Errors
/// See [`RequestError`].
pub fn parse_head(buf: &[u8]) -> Result<Option<(Request, usize)>, RequestError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut parsed = httparse::Request::new(&mut headers);
    let used = match parsed.parse(buf) {
        Ok(httparse::Status::Complete(used)) => used,
        Ok(httparse::Status::Partial) => {
            return if buf.len() >= MAX_HEAD_BYTES {
                Err(RequestError::TooLarge)
            } else {
                Ok(None)
            };
        }
        Err(httparse::Error::TooManyHeaders) => return Err(RequestError::TooLarge),
        Err(_) => return Err(RequestError::Malformed),
    };
    if used > MAX_HEAD_BYTES {
        return Err(RequestError::TooLarge);
    }
    let (Some(method), Some(target)) = (parsed.method, parsed.path) else {
        return Err(RequestError::Malformed);
    };
    if method == "CONNECT" {
        let authority = Authority::parse(target, None).context(BadTargetSnafu)?;
        return Ok(Some((Request::Connect(authority), used)));
    }
    let forward = forward(method, target, parsed.headers)?;
    Ok(Some((forward, used)))
}

fn forward(
    method: &str,
    target: &str,
    headers: &[httparse::Header<'_>],
) -> Result<Request, RequestError> {
    let after_scheme = absolute_http(target)?;
    let end = after_scheme.find(['/', '?']).unwrap_or(after_scheme.len());
    let (authority_text, rest) = after_scheme.split_at(end);
    let default = Port::try_from(80).map_err(|_| RequestError::Malformed)?;
    let authority = Authority::parse(authority_text, Some(default)).context(BadTargetSnafu)?;
    let path = if rest.starts_with('/') {
        rest.to_owned()
    } else {
        format!("/{rest}")
    };

    let named_in_connection: Vec<String> = headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("connection"))
        .flat_map(|h| connection_tokens(h.value))
        .collect();
    let has = |name: &str| headers.iter().any(|h| h.name.eq_ignore_ascii_case(name));
    if has("content-length") && has("transfer-encoding") {
        return Err(RequestError::Malformed);
    }

    let host_header = if authority.port.get() == 80 {
        authority.host.to_string()
    } else {
        format!("{}:{}", authority.host, authority.port)
    };
    let mut head = Vec::with_capacity(512);
    head.extend_from_slice(
        format!("{method} {path} HTTP/1.1\r\nHost: {host_header}\r\n").as_bytes(),
    );
    for header in headers {
        let lower = header.name.to_ascii_lowercase();
        if DROPPED_HEADERS.contains(&lower.as_str()) || named_in_connection.contains(&lower) {
            continue;
        }
        head.extend_from_slice(header.name.as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(header.value);
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(Request::Forward { authority, head })
}

/// The header names a `Connection` value lists (they are hop-by-hop too), lowercase.
fn connection_tokens(value: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(value)
        .split(',')
        .map(|token| token.trim().to_ascii_lowercase())
        .filter(|token| !token.is_empty())
        .collect()
}

/// The part of an absolute `http://` URI after the scheme.
fn absolute_http(target: &str) -> Result<&str, RequestError> {
    if let Some(rest) = strip_prefix_ignore_case(target, "http://") {
        return Ok(rest);
    }
    if target.contains("://") {
        let scheme = target.split("://").next().unwrap_or_default();
        return Err(RequestError::UnsupportedScheme {
            scheme: scheme.to_owned(),
        });
    }
    Err(RequestError::NotAProxyRequest)
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &text[prefix.len()..])
}

/// Why a request head is refused.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RequestError {
    /// The head is not valid HTTP, or is ambiguous about its body.
    #[snafu(display("the request is not valid HTTP/1.x"))]
    Malformed,

    /// The head is longer than the limit or has too many headers.
    #[snafu(display(
        "the request head is larger than {MAX_HEAD_BYTES} bytes or has more than {MAX_HEADERS} headers"
    ))]
    TooLarge,

    /// An absolute URI with a scheme other than `http`.
    #[snafu(display(
        "the scheme {} cannot be forwarded; use CONNECT for https",
        EscapedBounded::new(scheme, ERROR_PREVIEW_CHARS)
    ))]
    UnsupportedScheme {
        /// The scheme as written.
        scheme: String,
    },

    /// A request for a path on this proxy rather than a proxy request.
    #[snafu(display("this is a proxy; send an absolute http:// URI or CONNECT"))]
    NotAProxyRequest,

    /// The target is not acceptable.
    #[snafu(display("the target is not acceptable"))]
    BadTarget {
        /// Why.
        source: AuthorityError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    fn parse(text: &str) -> (Request, usize) {
        assert_some!(assert_ok!(parse_head(text.as_bytes())))
    }

    #[test]
    fn a_connect_names_its_target_and_leaves_what_follows_the_head() {
        let text = "CONNECT Example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n\x16\x03";
        let (request, used) = parse(text);
        let Request::Connect(authority) = request else {
            assert_ok!(Err::<(), _>("not a connect"));
            return;
        };
        assert_eq!(authority.host.as_str(), "example.com");
        assert_eq!(authority.port.get(), 443);
        assert_eq!(&text.as_bytes()[used..], b"\x16\x03");
    }

    #[test]
    fn an_incomplete_head_asks_for_more_and_a_huge_one_is_refused() {
        assert_none!(assert_ok!(parse_head(b"CONNECT example.com:443 HTT")));
        assert_none!(assert_ok!(parse_head(
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n"
        )));
        let mut big = b"GET http://example.com/ HTTP/1.1\r\nX: ".to_vec();
        big.resize(MAX_HEAD_BYTES + 1, b'a');
        assert!(matches!(
            assert_err!(parse_head(&big)),
            RequestError::TooLarge
        ));
    }

    /// A plain request whose head is exactly `size` bytes long.
    fn head_of_size(size: usize) -> Vec<u8> {
        let prefix = "GET http://example.com/ HTTP/1.1\r\nX: ";
        let suffix = "\r\n\r\n";
        let mut head = prefix.as_bytes().to_vec();
        head.resize(size - suffix.len(), b'a');
        head.extend_from_slice(suffix.as_bytes());
        assert_eq!(head.len(), size);
        head
    }

    #[test]
    fn a_head_up_to_the_limit_is_accepted_and_one_byte_more_is_refused() {
        for size in [2_000, MAX_HEAD_BYTES - 1, MAX_HEAD_BYTES] {
            let head = head_of_size(size);
            let (_, used) = assert_some!(assert_ok!(parse_head(&head)), "{size}");
            assert_eq!(used, size);
        }
        assert!(matches!(
            assert_err!(parse_head(&head_of_size(MAX_HEAD_BYTES + 1))),
            RequestError::TooLarge
        ));
    }

    #[test]
    fn too_many_headers_and_garbage_are_refused() {
        let mut many = String::from("GET http://example.com/ HTTP/1.1\r\n");
        for i in 0..=MAX_HEADERS {
            many.push_str(&format!("X-{i}: v\r\n"));
        }
        many.push_str("\r\n");
        assert!(matches!(
            assert_err!(parse_head(many.as_bytes())),
            RequestError::TooLarge
        ));
        for bad in [
            "\x16\x03\x01\x02\x00\x01\x00\r\n\r\n",
            "GET\r\n\r\n",
            "GET http://a.example.com/ HTTP/9.9\r\n\r\n",
        ] {
            assert!(
                matches!(
                    assert_err!(parse_head(bad.as_bytes())),
                    RequestError::Malformed
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_plain_request_is_rewritten_to_origin_form_with_our_own_host_and_connection() {
        let text = "GET http://Example.com/a/b?q=1 HTTP/1.1\r\nHost: evil.test\r\nProxy-Authorization: Basic eDp5\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive, X-Secret\r\nX-Secret: 1\r\nKeep-Alive: 5\r\nUpgrade: websocket\r\nAccept: */*\r\n\r\n";
        let (request, used) = parse(text);
        assert_eq!(used, text.len());
        let Request::Forward { authority, head } = request else {
            assert_ok!(Err::<(), _>("not a forward"));
            return;
        };
        assert_eq!(authority.host.as_str(), "example.com");
        assert_eq!(authority.port.get(), 80);
        assert_eq!(
            String::from_utf8_lossy(&head),
            "GET /a/b?q=1 HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn a_port_other_than_80_stays_in_the_host_header_and_a_bare_authority_gets_a_slash() {
        let (request, _) =
            parse("POST http://api.example.com:8080?x=1 HTTP/1.1\r\nContent-Length: 3\r\n\r\nabc");
        let Request::Forward { authority, head } = request else {
            assert_ok!(Err::<(), _>("not a forward"));
            return;
        };
        assert_eq!(authority.port.get(), 8080);
        assert_eq!(
            String::from_utf8_lossy(&head),
            "POST /?x=1 HTTP/1.1\r\nHost: api.example.com:8080\r\nContent-Length: 3\r\nConnection: close\r\n\r\n"
        );
    }

    #[test]
    fn requests_that_are_not_proxy_requests_are_refused_with_a_reason() {
        let origin = parse_head(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
        assert!(matches!(
            assert_err!(origin),
            RequestError::NotAProxyRequest
        ));
        let tls = parse_head(b"GET https://example.com/ HTTP/1.1\r\n\r\n");
        assert!(matches!(
            assert_err!(tls),
            RequestError::UnsupportedScheme { .. }
        ));
        let ftp = parse_head(b"GET ftp://example.com/ HTTP/1.1\r\n\r\n");
        assert!(matches!(
            assert_err!(ftp),
            RequestError::UnsupportedScheme { .. }
        ));
    }

    #[test]
    fn address_literal_and_userinfo_targets_are_refused() {
        for target in [
            "http://127.0.0.1/",
            "http://[::1]:80/",
            "http://user:pw@example.com/",
            "http://2130706433/",
        ] {
            let text = format!("GET {target} HTTP/1.1\r\n\r\n");
            assert!(
                matches!(
                    assert_err!(parse_head(text.as_bytes())),
                    RequestError::BadTarget { .. }
                ),
                "{target}"
            );
        }
    }

    #[test]
    fn a_request_with_both_content_length_and_transfer_encoding_is_refused() {
        let text = "POST http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(matches!(
            assert_err!(parse_head(text.as_bytes())),
            RequestError::Malformed
        ));
    }

    #[test]
    fn an_http_one_zero_request_is_accepted_and_sent_as_one_one() {
        let (request, _) = parse("GET http://example.com/ HTTP/1.0\r\n\r\n");
        let Request::Forward { head, .. } = request else {
            assert_ok!(Err::<(), _>("not a forward"));
            return;
        };
        assert!(String::from_utf8_lossy(&head).starts_with("GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn a_connect_with_a_bad_target_names_the_problem() {
        for target in ["example.com", "example.com:0", "127.0.0.1:443", "x"] {
            let text = format!("CONNECT {target} HTTP/1.1\r\n\r\n");
            assert!(
                matches!(
                    assert_err!(parse_head(text.as_bytes())),
                    RequestError::BadTarget { .. }
                ),
                "{target}"
            );
        }
    }
}
