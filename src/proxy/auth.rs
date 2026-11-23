// ABOUTME: The per-session proxy credential: a random token, its Basic header form and a constant-time check.
// ABOUTME: Keeps other local processes from using the proxy; the agent itself holds the token, so it is not a secret from the agent.
//! Proxy authentication (design 12).
//!
//! The proxy URL the agent gets is `http://hb:<token>@127.0.0.1:<port>`. Any other process on
//! the machine can connect to the loopback port, so without a credential it could use the
//! user's allowlist. The token is 128 random bits from the operating system, written as 32 hex
//! digits. The agent can read it (it is in its environment), so it protects against other
//! processes, not against the agent.

use std::fmt;
use std::fs::File;
use std::io::{self, Read};

/// The user name in the proxy URL.
pub const USER: &str = "hb";
/// How many random bytes a token has.
const TOKEN_BYTES: usize = 16;

/// A per-session proxy token. Its `Debug` output never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// A new random token.
    ///
    /// # Errors
    /// When the operating system's random source cannot be read.
    pub fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; TOKEN_BYTES];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes.iter().map(|b| format!("{b:02x}")).collect()))
    }

    /// The token as 32 hex digits. It is a secret: put it only where the agent must read it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// The value of a `Proxy-Authorization` header that carries this token.
    #[must_use]
    pub fn authorization_value(&self) -> String {
        format!("Basic {}", base64(format!("{USER}:{}", self.0).as_bytes()))
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// A proxy URL with the token in it. Its `Debug` output never shows it.
#[derive(Clone, PartialEq, Eq)]
pub struct ProxyUrl(String);

impl ProxyUrl {
    pub(crate) fn new(port: u16, token: &Token) -> Self {
        Self(format!("http://{USER}:{}@127.0.0.1:{port}", token.expose()))
    }

    /// The URL, `http://hb:<token>@127.0.0.1:<port>`. It is a secret: put it only where the
    /// agent must read it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ProxyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProxyUrl(<redacted>)")
    }
}

/// Checks `Proxy-Authorization` headers against one token.
#[derive(Clone)]
pub struct Authorizer {
    expected: Vec<u8>,
}

impl Authorizer {
    /// An authorizer that accepts exactly `token`.
    #[must_use]
    pub fn new(token: &Token) -> Self {
        Self {
            expected: base64(format!("{USER}:{}", token.expose()).as_bytes()).into_bytes(),
        }
    }

    /// Whether `header` (the value of the only `Proxy-Authorization` header) carries the token.
    #[must_use]
    pub fn accepts(&self, header: &[u8]) -> bool {
        let header = header.trim_ascii();
        let Some(split) = header.iter().position(u8::is_ascii_whitespace) else {
            return false;
        };
        let (scheme, credentials) = header.split_at(split);
        scheme.eq_ignore_ascii_case(b"basic")
            && constant_time_eq(credentials.trim_ascii(), &self.expected)
    }
}

impl fmt::Debug for Authorizer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authorizer(<redacted>)")
    }
}

/// Compares without stopping at the first difference. The lengths are public (a token has a
/// fixed length), so a difference in length returns at once.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Standard base64 with padding (RFC 4648).
fn base64(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let index = |shift: u32| ALPHABET[((n >> shift) & 0x3f) as usize] as char;
        out.push(index(18));
        out.push(index(12));
        out.push(if chunk.len() > 1 { index(6) } else { '=' });
        out.push(if chunk.len() > 2 { index(0) } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    #[test]
    fn base64_matches_the_rfc_4648_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
            ("Aladdin:open sesame", "QWxhZGRpbjpvcGVuIHNlc2FtZQ=="),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded, "{plain:?}");
        }
    }

    #[test]
    fn a_token_is_32_hex_digits_and_two_tokens_differ() {
        let a = assert_ok!(Token::generate());
        let b = assert_ok!(Token::generate());
        assert_eq!(a.expose().len(), 32);
        assert!(a.expose().bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn debug_output_never_shows_the_token_or_the_expected_header() {
        let token = assert_ok!(Token::generate());
        let url = ProxyUrl::new(8080, &token);
        for shown in [
            format!("{token:?}"),
            format!("{:?}", Authorizer::new(&token)),
            format!("{url:?}"),
        ] {
            assert!(!shown.contains(token.expose()), "{shown}");
            assert!(!shown.contains(&token.authorization_value()), "{shown}");
            assert!(shown.contains("redacted"), "{shown}");
        }
        assert!(
            url.expose().starts_with("http://hb:") && url.expose().ends_with("@127.0.0.1:8080")
        );
    }

    #[test]
    fn the_authorizer_accepts_the_tokens_own_header_in_any_case_and_spacing() {
        let token = assert_ok!(Token::generate());
        let authorizer = Authorizer::new(&token);
        let value = token.authorization_value();
        assert!(authorizer.accepts(value.as_bytes()));
        let credentials = value.strip_prefix("Basic ").unwrap_or_default();
        assert!(authorizer.accepts(format!("bAsIc {credentials}").as_bytes()));
        let spaced = value.replacen("Basic ", "  bASIC \t ", 1);
        assert!(authorizer.accepts(spaced.as_bytes()));
        assert!(authorizer.accepts(format!("{value}  ").as_bytes()));
    }

    #[test]
    fn the_authorizer_refuses_everything_else() {
        let token = assert_ok!(Token::generate());
        let other = assert_ok!(Token::generate());
        let authorizer = Authorizer::new(&token);
        let value = token.authorization_value();
        let credentials = value.strip_prefix("Basic ").unwrap_or_default().to_owned();
        let cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            b"Basic".to_vec(),
            b"Basic ".to_vec(),
            other.authorization_value().into_bytes(),
            format!("Bearer {credentials}").into_bytes(),
            credentials.clone().into_bytes(),
            format!("Basic {}", &credentials[..credentials.len() - 1]).into_bytes(),
            format!("Basic {credentials}x").into_bytes(),
            format!("Basic {credentials} extra").into_bytes(),
            format!("Basicc {credentials}").into_bytes(),
        ];
        for case in cases {
            assert!(
                !authorizer.accepts(&case),
                "{:?}",
                String::from_utf8_lossy(&case)
            );
        }
    }

    #[test]
    fn the_comparison_is_exact_for_equal_lengths_and_refuses_unequal_ones() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
        // Differences must not cancel: two bytes that each differ by the same bits.
        assert!(!constant_time_eq(&[1, 1], &[0, 0]));
        assert!(!constant_time_eq(&[0xff, 0xff, 0xff], &[0, 0, 0]));
    }
}
