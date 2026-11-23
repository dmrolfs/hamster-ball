// ABOUTME: HostName, HostPattern and the protected-suffix wildcard rule, backed by the generated Public Suffix List tables.
// ABOUTME: The network allowlist's exfiltration boundary: a wildcard over a public suffix is rejected at config time.
//! Validated network hostnames and allowlist patterns.

use std::fmt;

use snafu::{Snafu, ensure};

use super::port::Port;
use crate::text::EscapedBounded;

include!(concat!(env!("OUT_DIR"), "/psl_generated.rs"));

/// Longest accepted host, in bytes (253 plus one optional trailing dot).
pub const MAX_HOST_BYTES: usize = 254;
/// Longest accepted label, in bytes.
pub const MAX_LABEL_BYTES: usize = 63;
/// How much of a hostile input is echoed back in an error message.
const ERROR_PREVIEW_CHARS: usize = 64;

/// Why a string is not an acceptable hostname.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HostNameError {
    /// The host is empty.
    #[snafu(display("host name is empty"))]
    Empty,

    /// The host is longer than [`MAX_HOST_BYTES`].
    #[snafu(display("host name is {len} bytes long; the limit is {MAX_HOST_BYTES}"))]
    TooLong {
        /// Length in bytes.
        len: usize,
    },

    /// The host contains a control character. (Text-reordering characters are non-ASCII and
    /// are reported as [`HostNameError::NonAscii`].)
    #[snafu(display(
        "host name contains a control character: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    ControlCharacter {
        /// The offending host as written.
        host: String,
    },

    /// The host contains whitespace.
    #[snafu(display(
        "host name contains whitespace: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    Whitespace {
        /// The offending host as written.
        host: String,
    },

    /// The host includes a URI scheme (`https://...`).
    #[snafu(display(
        "expected a host name, not a URL: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    Scheme {
        /// The offending host as written.
        host: String,
    },

    /// The host includes userinfo (`user@host`).
    #[snafu(display(
        "host name must not include a username: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    Userinfo {
        /// The offending host as written.
        host: String,
    },

    /// The host includes a path, query or fragment.
    #[snafu(display(
        "expected a host name, not a path: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    Path {
        /// The offending host as written.
        host: String,
    },

    /// The host is a bracketed IPv6 literal.
    #[snafu(display(
        "expected a host name, not an address literal: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    BracketedIpv6 {
        /// The offending host as written.
        host: String,
    },

    /// The host includes a port number.
    #[snafu(display(
        "host name must not include a port: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    Port {
        /// The offending host as written.
        host: String,
    },

    /// The host contains a character outside ASCII (punycode is accepted, raw Unicode is not).
    #[snafu(display(
        "host name must be ASCII (use its punycode form): {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    NonAscii {
        /// The offending host as written.
        host: String,
    },

    /// A label is empty (consecutive dots, or a dot at the start).
    #[snafu(display(
        "host name has an empty label: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    EmptyLabel {
        /// The offending host as written.
        host: String,
    },

    /// A label is longer than [`MAX_LABEL_BYTES`].
    #[snafu(display(
        "label {} is longer than {MAX_LABEL_BYTES} bytes",
        EscapedBounded::new(label, ERROR_PREVIEW_CHARS)
    ))]
    LabelTooLong {
        /// The offending label.
        label: String,
    },

    /// A label contains a character other than an ASCII letter, digit or hyphen.
    #[snafu(display(
        "label {} may contain only letters, digits and hyphens",
        EscapedBounded::new(label, ERROR_PREVIEW_CHARS)
    ))]
    InvalidCharacter {
        /// The offending label.
        label: String,
    },

    /// A label contains an underscore, which is rejected for an HTTP proxy allowlist.
    #[snafu(display(
        "label {} contains `_`, which is rejected here; list the exact host without it if this is not a DNS-level name (such as an SRV or _dmarc record)",
        EscapedBounded::new(label, ERROR_PREVIEW_CHARS)
    ))]
    Underscore {
        /// The offending label.
        label: String,
    },

    /// A label starts or ends with a hyphen.
    #[snafu(display(
        "label {} may not start or end with a hyphen",
        EscapedBounded::new(label, ERROR_PREVIEW_CHARS)
    ))]
    HyphenAtLabelEdge {
        /// The offending label.
        label: String,
    },

    /// A label has `--` at positions 3-4 but does not start with the `xn--` punycode prefix.
    #[snafu(display(
        "label {} has `--` reserved for a punycode prefix (`xn--`) but is not one",
        EscapedBounded::new(label, ERROR_PREVIEW_CHARS)
    ))]
    ReservedHyphenPosition {
        /// The offending label.
        label: String,
    },

    /// The last label does not start with a letter (rejects dotted-quad and numeric-only hosts).
    #[snafu(display(
        "host name's last label must start with a letter: {}",
        EscapedBounded::new(host, ERROR_PREVIEW_CHARS)
    ))]
    LastLabelNotAlphabetic {
        /// The offending host as written.
        host: String,
    },

    /// The host is `localhost` or a subdomain of it.
    #[snafu(display(
        "`localhost` is not a network host; use `net.loopback_ports` for local services"
    ))]
    Localhost,
}

/// A validated, normalized hostname: lowercase ASCII, at most 253 bytes (plus an optional
/// trailing dot, which is dropped), no control characters, no scheme, userinfo, path, port or
/// address literal.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostName(String);

impl HostName {
    /// Parses a hostname.
    ///
    /// Checks length before any other work, so a very long hostile input is rejected in
    /// constant extra work rather than after a full character scan.
    ///
    /// # Errors
    /// See [`HostNameError`].
    pub fn parse(host: &str) -> Result<Self, HostNameError> {
        ensure!(!host.is_empty(), EmptySnafu);
        ensure!(
            host.len() <= MAX_HOST_BYTES,
            TooLongSnafu { len: host.len() }
        );
        ensure!(
            !host.chars().any(char::is_control),
            ControlCharacterSnafu { host }
        );
        ensure!(
            !host.chars().any(char::is_whitespace),
            WhitespaceSnafu { host }
        );
        ensure!(!host.contains("://"), SchemeSnafu { host });
        ensure!(!host.contains('@'), UserinfoSnafu { host });
        ensure!(!host.contains(['/', '?', '#']), PathSnafu { host });
        ensure!(!host.starts_with('['), BracketedIpv6Snafu { host });
        ensure!(!host.contains(':'), PortSnafu { host });

        let trimmed = host.strip_suffix('.').unwrap_or(host);
        ensure!(trimmed.is_ascii(), NonAsciiSnafu { host });
        let lower = trimmed.to_ascii_lowercase();

        let labels: Vec<&str> = lower.split('.').collect();
        for label in &labels {
            validate_label(label, &lower)?;
        }
        let last = labels.last().copied().unwrap_or_default();
        ensure!(
            last.as_bytes().first().is_some_and(u8::is_ascii_alphabetic),
            LastLabelNotAlphabeticSnafu { host: &lower }
        );
        ensure!(
            lower != "localhost" && !lower.ends_with(".localhost"),
            LocalhostSnafu
        );

        Ok(Self(lower))
    }

    /// The hostname as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HostName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validates one already-lowercased label; `host` is the whole host, for error messages.
fn validate_label(label: &str, host: &str) -> Result<(), HostNameError> {
    ensure!(!label.is_empty(), EmptyLabelSnafu { host });
    ensure!(label.len() <= MAX_LABEL_BYTES, LabelTooLongSnafu { label });
    ensure!(!label.contains('_'), UnderscoreSnafu { label });
    ensure!(
        label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        InvalidCharacterSnafu { label }
    );
    ensure!(
        !label.starts_with('-') && !label.ends_with('-'),
        HyphenAtLabelEdgeSnafu { label }
    );

    // RFC 5891 section 4.2.3.1: a hyphen at both label positions 3 and 4 is reserved for an
    // ACE prefix such as `xn--`. Elsewhere in the label, repeated hyphens are ordinary DNS
    // syntax (for example AWS S3 Express bucket hostnames use them mid-label).
    let bytes = label.as_bytes();
    if bytes.len() >= 4 && bytes[2] == b'-' && bytes[3] == b'-' {
        ensure!(
            label.starts_with("xn--"),
            ReservedHyphenPositionSnafu { label }
        );
    }
    Ok(())
}

/// The vendored Public Suffix List's own `VERSION` header, verbatim.
///
/// Exposed so `hb --version` (added in a later task) can report which list was built in.
#[must_use]
pub fn protected_suffix_list_version() -> &'static str {
    LIST_VERSION
}

/// Reports whether `suffix` is protected: a public suffix (or a supplement entry), an ancestor
/// of one, or the unlisted direct child of a wildcard-rule parent.
fn is_protected_suffix(suffix: &str) -> bool {
    if PROTECTED.binary_search(&suffix).is_ok() {
        return true;
    }
    match suffix.split_once('.') {
        Some((_, parent)) => {
            WILDCARD_PARENTS.binary_search(&parent).is_ok()
                && EXCEPTIONS.binary_search(&suffix).is_err()
        }
        None => false,
    }
}

/// Why a string is not an acceptable network allowlist pattern.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HostPatternError {
    /// The host part of the pattern is invalid.
    #[snafu(transparent)]
    Name {
        /// The underlying error.
        source: HostNameError,
    },

    /// A `*` appears somewhere other than as a single leading `*.` wildcard.
    #[snafu(display(
        "`*` may only appear as a single leading `*.`: {}",
        EscapedBounded::new(pattern, ERROR_PREVIEW_CHARS)
    ))]
    WildcardPlacement {
        /// The offending pattern as written.
        pattern: String,
    },

    /// A wildcard's suffix has fewer than two labels (for example `*.com`).
    #[snafu(display("`*.{suffix}` is too broad; a wildcard needs at least two labels after it"))]
    WildcardTooShort {
        /// The offending suffix.
        suffix: HostName,
    },

    /// A wildcard's suffix is a public suffix, or contains one, so it would match
    /// attacker-registerable tenants.
    #[snafu(display(
        "`*.{suffix}` would also match hosts that other parties can register under {suffix} \
         (it is, or contains, a public suffix); list the exact hosts you need instead"
    ))]
    ProtectedSuffix {
        /// The offending suffix.
        suffix: HostName,
    },
}

/// A network allowlist entry: an exact host, or a wildcard over a suffix with at least two
/// labels that is not a public suffix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum HostPattern {
    /// Matches exactly one host.
    Exact(HostName),
    /// Matches any direct or indirect subdomain of `suffix`, but never `suffix` itself.
    Wildcard {
        /// The suffix every match must end with.
        suffix: HostName,
    },
}

impl HostPattern {
    /// Parses an allowlist entry.
    ///
    /// # Errors
    /// See [`HostPatternError`].
    pub fn parse(pattern: &str) -> Result<Self, HostPatternError> {
        if let Some(rest) = pattern.strip_prefix("*.") {
            ensure!(!rest.contains('*'), WildcardPlacementSnafu { pattern });
            let suffix = HostName::parse(rest)?;
            ensure!(
                suffix.as_str().contains('.'),
                WildcardTooShortSnafu { suffix }
            );
            ensure!(
                !is_protected_suffix(suffix.as_str()),
                ProtectedSuffixSnafu { suffix }
            );
            Ok(Self::Wildcard { suffix })
        } else {
            ensure!(!pattern.contains('*'), WildcardPlacementSnafu { pattern });
            Ok(Self::Exact(HostName::parse(pattern)?))
        }
    }

    /// Reports whether `host` matches this pattern.
    ///
    /// A wildcard matches only a proper subdomain of its suffix (label-boundary safe): it
    /// never matches the suffix itself, and `evil-example.com` does not match `*.example.com`.
    #[must_use]
    pub fn matches(&self, host: &HostName) -> bool {
        match self {
            Self::Exact(exact) => exact == host,
            Self::Wildcard { suffix } => host
                .as_str()
                .strip_suffix(suffix.as_str())
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.')),
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(host) => write!(f, "{host}"),
            Self::Wildcard { suffix } => write!(f, "*.{suffix}"),
        }
    }
}

/// Why an allowlist entry is not a valid `host` or `host:port` rule.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HostRuleError {
    /// The host part is not a valid pattern.
    #[snafu(transparent)]
    Pattern {
        /// Why.
        source: HostPatternError,
    },

    /// The part after the last colon is not a port.
    #[snafu(display(
        "the port {} is not a number from 1 to 65535",
        EscapedBounded::new(text, ERROR_PREVIEW_CHARS)
    ))]
    BadPort {
        /// The port as written.
        text: String,
    },
}

/// One allowlist rule: hosts matching a pattern, on one port.
///
/// Written `host` (port 443) or `host:port`, for example `*.kiro.dev` or
/// `registry.corp.example.com:8443`. Several entries for one pattern allow several ports.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HostRule {
    /// The hosts the rule covers.
    pub pattern: HostPattern,
    /// The one port it allows on them.
    pub port: Port,
}

impl HostRule {
    /// The port an entry without one allows.
    #[must_use]
    pub fn default_port() -> Port {
        Port::HTTPS
    }

    /// Parses `host` or `host:port`.
    ///
    /// # Errors
    /// See [`HostRuleError`].
    pub fn parse(entry: &str) -> Result<Self, HostRuleError> {
        let (pattern_text, port) = match entry.rsplit_once(':') {
            Some((pattern, port_text)) => {
                let port = Port::from_decimal(port_text).ok_or_else(|| HostRuleError::BadPort {
                    text: port_text.to_owned(),
                })?;
                (pattern, port)
            }
            None => (entry, Self::default_port()),
        };
        Ok(Self {
            pattern: HostPattern::parse(pattern_text)?,
            port,
        })
    }

    /// Whether the rule covers `host`, whatever the port.
    #[must_use]
    pub fn covers_host(&self, host: &HostName) -> bool {
        self.pattern.matches(host)
    }

    /// Whether the rule allows `host` on `port`.
    #[must_use]
    pub fn allows(&self, host: &HostName, port: Port) -> bool {
        self.port == port && self.pattern.matches(host)
    }
}

impl fmt::Display for HostRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.port == Self::default_port() {
            write!(f, "{}", self.pattern)
        } else {
            write!(f, "{}:{}", self.pattern, self.port)
        }
    }
}

#[cfg(test)]
mod rule_tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn port(n: i64) -> Port {
        assert_ok!(Port::try_from(n))
    }

    fn host(text: &str) -> HostName {
        assert_ok!(HostName::parse(text))
    }

    #[test]
    fn an_entry_without_a_port_allows_443_and_one_with_a_port_allows_that_port() {
        let plain = assert_ok!(HostRule::parse("api.kiro.dev"));
        assert_eq!(plain.port, port(443));
        let odd = assert_ok!(HostRule::parse("registry.corp.example.com:8443"));
        assert_eq!(odd.port, port(8443));
        let wild = assert_ok!(HostRule::parse("*.kiro.dev:8080"));
        assert_eq!(wild.port, port(8080));
        assert_eq!(wild.pattern, assert_ok!(HostPattern::parse("*.kiro.dev")));
    }

    #[test]
    fn a_rule_allows_its_own_port_only_and_covers_the_host_on_any_port() {
        let rule = assert_ok!(HostRule::parse("*.kiro.dev:8080"));
        assert!(rule.allows(&host("a.kiro.dev"), port(8080)));
        assert!(!rule.allows(&host("a.kiro.dev"), port(443)));
        assert!(!rule.allows(&host("kiro.dev"), port(8080)));
        assert!(rule.covers_host(&host("a.b.kiro.dev")));
        assert!(!rule.covers_host(&host("evil-kiro.dev")));
    }

    #[test]
    fn bad_ports_and_bad_hosts_are_refused_with_the_part_that_is_wrong() {
        for entry in [
            "a.kiro.dev:0",
            "a.kiro.dev:65536",
            "a.kiro.dev:",
            "a.kiro.dev:+1",
            "a.kiro.dev:44 3",
            "a.kiro.dev:000443",
        ] {
            assert!(
                matches!(
                    assert_err!(HostRule::parse(entry)),
                    HostRuleError::BadPort { .. }
                ),
                "{entry}"
            );
        }
        for entry in [
            "",
            ":443",
            "127.0.0.1:443",
            "*.com:443",
            "https://a.kiro.dev",
            "a.kiro.dev:443:443",
            "*.*.kiro.dev",
        ] {
            assert!(
                matches!(
                    assert_err!(HostRule::parse(entry)),
                    HostRuleError::Pattern { .. } | HostRuleError::BadPort { .. }
                ),
                "{entry}"
            );
        }
    }

    #[test]
    fn display_omits_443_and_round_trips() {
        for (entry, shown) in [
            ("a.kiro.dev", "a.kiro.dev"),
            ("a.kiro.dev:443", "a.kiro.dev"),
            ("*.kiro.dev:8443", "*.kiro.dev:8443"),
        ] {
            let rule = assert_ok!(HostRule::parse(entry));
            assert_eq!(rule.to_string(), shown);
            assert_eq!(assert_ok!(HostRule::parse(&rule.to_string())), rule);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    fn host(h: &str) -> HostName {
        assert_ok!(HostName::parse(h), "{h}")
    }

    // ====================================================================================
    // HostName: accepted forms
    // ====================================================================================

    #[test]
    fn accepts_ordinary_hosts_and_normalizes_case_and_trailing_dot() {
        assert_eq!(host("Example.COM").as_str(), "example.com");
        assert_eq!(host("example.com.").as_str(), "example.com");
    }

    #[test]
    fn accepts_a_single_label_host() {
        assert_eq!(host("localtest").as_str(), "localtest");
    }

    #[test]
    fn accepts_a_punycode_label() {
        assert_eq!(host("xn--caf-dma.example").as_str(), "xn--caf-dma.example");
    }

    #[test]
    fn accepts_double_hyphen_away_from_label_positions_three_and_four() {
        // The real AWS S3 Express One Zone hostname shape.
        assert_eq!(
            host("bucket--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com").as_str(),
            "bucket--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com"
        );
    }

    #[test]
    fn rejects_double_hyphen_at_label_positions_three_and_four_unless_punycode() {
        assert_ok!(HostName::parse("xn--ab--cd.example"));
        let err = assert_err!(HostName::parse("ab--cd.example"));
        assert!(
            matches!(err, HostNameError::ReservedHyphenPosition { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_a_bare_xn_prefix_with_nothing_after_it() {
        // "xn--" is exactly 4 bytes and necessarily ends in a hyphen, so the ordinary
        // trailing-hyphen rule already rejects it; no separate "empty payload" check is needed.
        let err = assert_err!(HostName::parse("xn--.example"));
        assert!(
            matches!(err, HostNameError::HyphenAtLabelEdge { .. }),
            "{err:?}"
        );
    }

    // ====================================================================================
    // HostName: rejected forms
    // ====================================================================================

    #[test]
    fn rejects_empty_and_overlong() {
        assert!(matches!(
            assert_err!(HostName::parse("")),
            HostNameError::Empty
        ));
        let long = format!("{}.com", "a".repeat(MAX_HOST_BYTES));
        assert!(matches!(
            assert_err!(HostName::parse(&long)),
            HostNameError::TooLong { .. }
        ));
    }

    #[test]
    fn rejects_urls_userinfo_paths_brackets_ports_and_whitespace() {
        for (bad, kind) in [
            ("https://host", "scheme"),
            ("user@host", "userinfo"),
            ("host/path", "path"),
            ("host?q=1", "path"),
            ("[::1]", "bracket"),
            ("host:443", "port"),
            ("ho st", "whitespace"),
            ("ho\nst", "control"),
        ] {
            assert_err!(HostName::parse(bad), "{bad} ({kind})");
        }
    }

    #[test]
    fn rejects_raw_unicode_and_control_characters() {
        assert!(matches!(
            assert_err!(HostName::parse("café.example")),
            HostNameError::NonAscii { .. }
        ));
        assert!(matches!(
            assert_err!(HostName::parse("a\u{1b}[2j.example")),
            HostNameError::ControlCharacter { .. }
        ));
    }

    #[test]
    fn rejects_empty_labels_overlong_labels_and_bad_characters() {
        for bad in [
            ".example.com",
            "example..com",
            "example.com.",
            "a.",
            "..",
            "example.com",
        ] {
            let _ = bad; // sanity placeholder; trailing single dot is valid and tested separately
        }
        assert!(matches!(
            assert_err!(HostName::parse("example..com")),
            HostNameError::EmptyLabel { .. }
        ));
        assert!(matches!(
            assert_err!(HostName::parse(".example.com")),
            HostNameError::EmptyLabel { .. }
        ));
        let long_label = format!("{}.com", "a".repeat(MAX_LABEL_BYTES + 1));
        assert!(matches!(
            assert_err!(HostName::parse(&long_label)),
            HostNameError::LabelTooLong { .. }
        ));
        assert!(matches!(
            assert_err!(HostName::parse("a_b.com")),
            HostNameError::Underscore { .. }
        ));
        assert!(matches!(
            assert_err!(HostName::parse("a!b.com")),
            HostNameError::InvalidCharacter { .. }
        ));
        assert!(matches!(
            assert_err!(HostName::parse("-a.com")),
            HostNameError::HyphenAtLabelEdge { .. }
        ));
        assert!(matches!(
            assert_err!(HostName::parse("a-.com")),
            HostNameError::HyphenAtLabelEdge { .. }
        ));
    }

    #[test]
    fn rejects_numeric_last_label_and_dotted_quads() {
        for bad in ["example.123", "2130706433", "127.0.0.1", "0x7f.1"] {
            let err = assert_err!(HostName::parse(bad), "{bad}");
            assert!(
                matches!(err, HostNameError::LastLabelNotAlphabetic { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_localhost_and_its_subdomains() {
        assert!(matches!(
            assert_err!(HostName::parse("localhost")),
            HostNameError::Localhost
        ));
        assert!(matches!(
            assert_err!(HostName::parse("foo.localhost")),
            HostNameError::Localhost
        ));
    }

    #[test]
    fn error_display_truncates_and_escapes_a_long_hostile_host() {
        let input = format!("{}\u{1b}[2j", "a".repeat(500));
        let shown = assert_err!(HostName::parse(&input)).to_string();
        assert!(shown.len() < 200, "{} chars", shown.len());
        assert!(!shown.contains('\u{1b}'));
    }

    // ====================================================================================
    // HostName: equality, ordering, proptest
    // ====================================================================================

    #[test]
    fn equality_and_hash_use_the_normalized_form() {
        assert_eq!(host("Example.com"), host("example.com."));
    }

    proptest! {
        #[test]
        fn parse_never_panics(s in ".*") {
            let _ = HostName::parse(&s);
        }

        #[test]
        fn accepted_hosts_round_trip_through_display(s in "[a-z0-9]{1,10}(\\.[a-z0-9]{1,10}){0,4}") {
            if let Ok(h) = HostName::parse(&s) {
                prop_assert_eq!(h.to_string(), s);
            }
        }
    }

    // ====================================================================================
    // HostPattern: matching semantics
    // ====================================================================================

    fn pattern(p: &str) -> HostPattern {
        assert_ok!(HostPattern::parse(p), "{p}")
    }

    #[test]
    fn exact_pattern_matches_only_that_host() {
        let p = pattern("example.com");
        assert!(p.matches(&host("example.com")));
        assert!(!p.matches(&host("a.example.com")));
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_the_apex() {
        let p = pattern("*.kiro.dev");
        assert!(p.matches(&host("a.kiro.dev")));
        assert!(p.matches(&host("a.b.kiro.dev")));
        assert!(!p.matches(&host("kiro.dev")));
    }

    #[test]
    fn wildcard_is_label_boundary_safe() {
        let p = pattern("*.example.com");
        assert!(!p.matches(&host("evil-example.com")));
        assert!(!p.matches(&host("notexample.com")));
        assert!(!p.matches(&host("a.example.com.evil.net")));
    }

    #[test]
    fn display_round_trips_both_forms() {
        assert_eq!(pattern("example.com").to_string(), "example.com");
        assert_eq!(pattern("*.kiro.dev").to_string(), "*.kiro.dev");
    }

    #[test]
    fn host_pattern_ord_and_hash_use_the_normalized_form() {
        assert_eq!(pattern("Example.COM."), pattern("example.com"));
        let mut patterns = vec![
            pattern("*.kiro.dev"),
            pattern("example.com"),
            pattern("*.example.com"),
        ];
        patterns.sort();
        let sorted_again = {
            let mut copy = patterns.clone();
            copy.sort();
            copy
        };
        assert_eq!(patterns, sorted_again);
    }

    // ====================================================================================
    // HostPattern: rejected wildcard shapes
    // ====================================================================================

    #[test]
    fn rejects_malformed_wildcard_placement() {
        for bad in [
            "*",
            "*.",
            "a*b.com",
            "*.*.com",
            "foo.*.com",
            "**.example.com",
        ] {
            let err = assert_err!(HostPattern::parse(bad), "{bad}");
            assert!(
                matches!(
                    err,
                    HostPatternError::WildcardPlacement { .. } | HostPatternError::Name { .. }
                ),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_a_wildcard_with_too_few_labels() {
        let err = assert_err!(HostPattern::parse("*.com"));
        assert!(matches!(err, HostPatternError::WildcardTooShort { .. }));
    }

    // ====================================================================================
    // HostPattern: the protected-suffix rule (the point of this task)
    // ====================================================================================

    #[test]
    fn rejects_wildcards_over_public_suffixes() {
        for bad in [
            "*.co.uk",
            "*.github.io",
            "*.cloudfront.net",
            "*.githubusercontent.com",
        ] {
            let err = assert_err!(HostPattern::parse(bad), "{bad}");
            assert!(
                matches!(err, HostPatternError::ProtectedSuffix { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_wildcards_over_ancestors_of_public_suffixes() {
        for bad in [
            "*.amazonaws.com",
            "*.us-east-1.amazonaws.com",
            "*.windows.net",
            "*.run.app",
        ] {
            let err = assert_err!(HostPattern::parse(bad), "{bad}");
            assert!(
                matches!(err, HostPatternError::ProtectedSuffix { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn accepts_wildcards_over_ordinary_registrable_domains() {
        for good in [
            "*.kiro.dev",
            "*.example.com",
            "*.github.com",
            "*.npmjs.org",
            "*.pypi.org",
        ] {
            assert_ok!(HostPattern::parse(good), "{good}");
        }
    }

    #[test]
    fn rejects_wildcards_over_unlisted_children_of_a_wildcard_rule() {
        // `ck` has a wildcard rule (`*.ck`), so any direct child such as `foo.ck` is itself a
        // public suffix, and a wildcard over it would match unrelated registrants.
        let err = assert_err!(HostPattern::parse("*.foo.ck"));
        assert!(matches!(err, HostPatternError::ProtectedSuffix { .. }));
    }

    #[test]
    fn accepts_wildcards_over_exception_names() {
        // `!www.ck` removes `www.ck` from the suffix set even though its parent `ck` has a
        // wildcard rule, so it is an ordinary registrable domain.
        assert_ok!(HostPattern::parse("*.www.ck"));
    }

    #[test]
    fn accepts_a_wildcard_over_a_tenant_below_a_public_suffix() {
        assert_ok!(HostPattern::parse("*.example.github.io"));
    }

    #[test]
    fn rejects_wildcards_over_the_hand_maintained_supplement_entries() {
        for bad in [
            "*.storage.googleapis.com",
            "*.googleusercontent.com",
            "*.cloudapp.azure.com",
        ] {
            let err = assert_err!(HostPattern::parse(bad), "{bad}");
            assert!(
                matches!(err, HostPatternError::ProtectedSuffix { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn an_exact_host_that_is_itself_a_public_suffix_is_still_allowed() {
        assert_ok!(HostPattern::parse("github.io"));
    }

    #[test]
    fn the_protected_suffix_list_version_is_the_vendored_lists_own_header() {
        let version = protected_suffix_list_version();
        assert!(!version.is_empty());
        assert!(!version.contains('\n'), "{version:?}");
        assert!(version.chars().any(|c| c.is_ascii_digit()), "{version:?}");
        assert_eq!(version, LIST_VERSION);
    }

    #[test]
    fn protected_tables_are_generated_and_sorted() {
        assert!(!PROTECTED.is_empty());
        assert!(PROTECTED.is_sorted());
        assert!(WILDCARD_PARENTS.is_sorted());
        assert!(EXCEPTIONS.is_sorted());
        assert!(!protected_suffix_list_version().is_empty());
    }
}
