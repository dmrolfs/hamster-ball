// ABOUTME: EnvName and EnvValue: validated environment variable names and values for the child environment.
// ABOUTME: Syntax only; which names are reserved or forbidden is policy and lives with the floor and session builder.
//! Environment variable names and values.

use std::fmt;

use snafu::{Snafu, ensure};

use crate::text::{Escaped, EscapedBounded};

/// Longest accepted tool name, in bytes (the longest file name on macOS).
pub const MAX_TOOL_NAME_BYTES: usize = 255;
/// How much of a rejected tool name is echoed.
const TOOL_PREVIEW_CHARS: usize = 64;

/// Names `hb` sets itself.
const RESERVED_NAMES: &[&str] = &[
    "HOME",
    "PATH",
    "TMPDIR",
    "TERM",
    "HTTP_PROXY",
    "http_proxy",
    "HTTPS_PROXY",
    "https_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_USE_SYSTEM_CA",
    "NODE_EXTRA_CA_CERTS",
];
/// Prefixes that are never the config's to set: `hb`'s own, and the loader's.
const RESERVED_PREFIXES: &[&str] = &["HB_", "DYLD_", "LD_"];

/// Longest accepted variable name, in bytes.
pub const MAX_ENV_NAME_BYTES: usize = 256;

/// Why a string is not an acceptable environment variable name.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EnvNameError {
    /// The name is empty.
    #[snafu(display("environment variable name is empty"))]
    Empty,

    /// The name is longer than [`MAX_ENV_NAME_BYTES`].
    #[snafu(display("environment variable name is {len} bytes long; the limit is {max}"))]
    TooLong {
        /// Length in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// The name is one `hb` sets itself, so a config may not pass or set it.
    #[snafu(display(
        "environment variable {} is set by hb and cannot be passed or set",
        Escaped(name)
    ))]
    Reserved {
        /// The rejected name.
        name: String,
    },

    /// The first character is not an ASCII letter or underscore.
    #[snafu(display(
        "environment variable name must start with a letter or underscore: {} (found {})",
        Escaped(name),
        character.escape_default()
    ))]
    InvalidStart {
        /// The rejected name.
        name: String,
        /// The offending first character.
        character: char,
    },

    /// A later character is not an ASCII letter, digit or underscore.
    #[snafu(display(
        "environment variable name may contain only letters, digits and underscores: {} (found {})",
        Escaped(name),
        character.escape_default()
    ))]
    InvalidCharacter {
        /// The rejected name.
        name: String,
        /// The first offending character.
        character: char,
    },
}

/// Why a string is not an acceptable tool name.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ToolNameError {
    /// The name is not a bare program name.
    #[snafu(display(
        "tool `{}` is not a bare program name: use a name like `node`, not a path, and nothing longer than {max} bytes",
        EscapedBounded::new(name, TOOL_PREVIEW_CHARS)
    ))]
    NotBare {
        /// The rejected name.
        name: String,
        /// The length limit.
        max: usize,
    },
}

/// Why a string is not an acceptable environment variable value.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EnvValueError {
    /// The value contains NUL, which cannot appear in a process environment.
    #[snafu(display("environment variable value contains a NUL character"))]
    ContainsNul,
}

/// An environment variable name: `[A-Za-z_][A-Za-z0-9_]*`, ASCII only, case-sensitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnvName(String);

impl EnvName {
    /// Parses a variable name.
    ///
    /// # Errors
    /// [`EnvNameError`] for an empty, over-long or malformed name.
    pub fn parse(name: &str) -> Result<Self, EnvNameError> {
        ensure!(!name.is_empty(), EmptySnafu);
        ensure!(
            name.len() <= MAX_ENV_NAME_BYTES,
            TooLongSnafu {
                len: name.len(),
                max: MAX_ENV_NAME_BYTES
            }
        );
        let mut chars = name.chars();
        if let Some(first) = chars.next() {
            ensure!(
                first.is_ascii_alphabetic() || first == '_',
                InvalidStartSnafu {
                    name,
                    character: first
                }
            );
        }
        if let Some(bad) = chars.find(|c| !(c.is_ascii_alphanumeric() || *c == '_')) {
            return InvalidCharacterSnafu {
                name,
                character: bad,
            }
            .fail();
        }
        Ok(Self(name.to_owned()))
    }

    /// Parses a name from a config's `pass` or `set`, which may not be one `hb` sets itself.
    ///
    /// # Errors
    /// [`EnvNameError`] for a malformed name, or [`EnvNameError::Reserved`].
    pub fn parse_user(name: &str) -> Result<Self, EnvNameError> {
        let parsed = Self::parse(name)?;
        ensure!(!parsed.is_reserved(), ReservedSnafu { name });
        Ok(parsed)
    }

    /// Whether `hb` sets this name itself (design 7.2, D59).
    #[must_use]
    pub fn is_reserved(&self) -> bool {
        RESERVED_NAMES.contains(&self.0.as_str())
            || RESERVED_PREFIXES.iter().any(|p| self.0.starts_with(p))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a program `[env] tools` makes findable: a bare file name, never a path.
///
/// It is only ever looked up in the invoking shell's `PATH`, so a `/` would turn the lookup
/// into a path and a leading `-` could be read as an option by a later command.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ToolName(String);

impl ToolName {
    /// Parses a tool name.
    ///
    /// # Errors
    /// [`ToolNameError::NotBare`] for an empty, over-long, dotted, slashed, dash-led,
    /// control-character or space-containing name.
    pub fn parse(name: &str) -> Result<Self, ToolNameError> {
        let bad = name.is_empty()
            || name.len() > MAX_TOOL_NAME_BYTES
            || name == "."
            || name == ".."
            || name.starts_with('-')
            || name.chars().any(|c| c == '/' || c == ' ' || c.is_control());
        ensure!(
            !bad,
            NotBareSnafu {
                name,
                max: MAX_TOOL_NAME_BYTES
            }
        );
        Ok(Self(name.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ToolName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An environment variable value: any text without NUL.
///
/// There is no per-value length limit here; a value is bounded only by the config file's size
/// cap. The session builder must check the total size of the child environment against the
/// OS argument limit (`ARG_MAX`, 1 MiB on macOS) before `exec`.
///
/// TOML's `\u0000` escape parses to a real NUL, so this check must happen explicitly.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct EnvValue(String);

impl EnvValue {
    /// Parses a variable value.
    ///
    /// # Errors
    /// [`EnvValueError::ContainsNul`] if the value contains NUL.
    pub fn parse(value: &str) -> Result<Self, EnvValueError> {
        ensure!(!value.contains('\0'), ContainsNulSnafu);
        Ok(Self(value.to_owned()))
    }

    /// The value as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Values may be secrets (`pass` copies tokens), so `Debug` never prints them.
impl fmt::Debug for EnvValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EnvValue(<{} bytes>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    #[test]
    fn env_name_displays_as_its_text() {
        let name = assert_ok!(EnvName::parse("RUST_LOG"));
        assert_eq!(name.to_string(), "RUST_LOG");
        assert_eq!(name.as_str(), "RUST_LOG");
    }

    #[test]
    fn env_value_debug_reports_only_the_length_and_as_str_returns_the_text() {
        let value = assert_ok!(EnvValue::parse("s3cr3t-token"));
        assert_eq!(format!("{value:?}"), "EnvValue(<12 bytes>)");
        assert_eq!(value.as_str(), "s3cr3t-token");
    }

    #[test]
    fn env_name_accepts_posix_names() {
        for good in [
            "PATH",
            "HOME",
            "_",
            "_x",
            "a1",
            "NODE_USE_SYSTEM_CA",
            "lower_case",
            "A",
        ] {
            assert_eq!(assert_ok!(EnvName::parse(good), "{good}").as_str(), good);
        }
    }

    #[test]
    fn env_name_rejects_empty() {
        assert!(matches!(
            assert_err!(EnvName::parse("")),
            EnvNameError::Empty
        ));
    }

    #[test]
    fn env_name_rejects_a_leading_digit_or_symbol() {
        for bad in ["1A", "-A", ".A", " A", "=A"] {
            let err = assert_err!(EnvName::parse(bad), "{bad}");
            assert!(
                matches!(err, EnvNameError::InvalidStart { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn env_name_rejects_equals_space_dash_unicode_and_nul_inside() {
        for bad in ["A=B", "A B", "A-B", "A.B", "A\u{e9}", "A\0B", "A\nB"] {
            let err = assert_err!(EnvName::parse(bad), "{bad:?}");
            assert!(
                matches!(err, EnvNameError::InvalidCharacter { .. }),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn env_name_rejects_overlong_names_and_accepts_the_limit() {
        assert_ok!(EnvName::parse(&"A".repeat(MAX_ENV_NAME_BYTES)));
        let err = assert_err!(EnvName::parse(&"A".repeat(MAX_ENV_NAME_BYTES + 1)));
        assert!(
            matches!(err, EnvNameError::TooLong { len, max } if len == MAX_ENV_NAME_BYTES + 1 && max == MAX_ENV_NAME_BYTES)
        );
    }

    #[test]
    fn env_name_is_case_sensitive() {
        assert!(assert_ok!(EnvName::parse("path")) != assert_ok!(EnvName::parse("PATH")));
    }

    #[test]
    fn env_name_error_display_escapes_the_name() {
        let shown = assert_err!(EnvName::parse("A\u{1b}[2J")).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }

    #[test]
    fn env_value_accepts_text_including_newlines_and_unicode() {
        for good in ["", "plain", "multi\nline", "caf\u{e9}", "a=b"] {
            assert_eq!(assert_ok!(EnvValue::parse(good), "{good:?}").as_str(), good);
        }
    }

    #[test]
    fn env_value_rejects_nul() {
        assert!(matches!(
            assert_err!(EnvValue::parse("a\0b")),
            EnvValueError::ContainsNul
        ));
    }

    #[test]
    fn env_value_debug_never_prints_the_value() {
        let shown = format!("{:?}", assert_ok!(EnvValue::parse("super-secret-token")));
        assert!(!shown.contains("super-secret"), "{shown}");
    }

    #[test]
    fn reserved_names_are_the_ones_hb_sets_itself() {
        for name in [
            "HOME",
            "PATH",
            "TMPDIR",
            "TERM",
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
            "NODE_USE_SYSTEM_CA",
            "NODE_EXTRA_CA_CERTS",
            "HB_ANYTHING",
            "HB_",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ] {
            assert!(assert_ok!(EnvName::parse(name)).is_reserved(), "{name}");
        }
    }

    #[test]
    fn near_misses_are_not_reserved() {
        for name in [
            "Home",
            "HOMEBREW_PREFIX",
            "PATHEXT",
            "HBX",
            "hb_x",
            "LDFLAGS",
            "DYLDX",
            "NODE_OPTIONS",
            "SSL_CERT_FILE",
        ] {
            assert!(!assert_ok!(EnvName::parse(name)).is_reserved(), "{name}");
        }
    }

    #[test]
    fn parse_user_accepts_ordinary_names_and_rejects_reserved_ones_naming_the_variable() {
        assert_eq!(
            assert_ok!(EnvName::parse_user("RUST_LOG")).as_str(),
            "RUST_LOG"
        );
        let err = assert_err!(EnvName::parse_user("DYLD_LIBRARY_PATH"));
        assert!(matches!(err, EnvNameError::Reserved { .. }), "{err}");
        assert_eq!(
            err.to_string(),
            "environment variable DYLD_LIBRARY_PATH is set by hb and cannot be passed or set"
        );
    }

    #[test]
    fn parse_user_still_reports_syntax_errors_first() {
        assert!(matches!(
            assert_err!(EnvName::parse_user("1HOME")),
            EnvNameError::InvalidStart { .. }
        ));
    }

    #[test]
    fn tool_name_accepts_bare_program_names() {
        for good in [
            "node",
            "npx",
            "python3.12",
            "g++",
            "cargo-nextest",
            "a_b",
            "7z",
        ] {
            assert_eq!(assert_ok!(ToolName::parse(good), "{good}").as_str(), good);
        }
    }

    #[test]
    fn tool_name_displays_as_its_text() {
        assert_eq!(assert_ok!(ToolName::parse("node")).to_string(), "node");
    }

    #[test]
    fn tool_name_rejects_anything_that_is_not_a_bare_name() {
        for bad in [
            "",
            ".",
            "..",
            "a/b",
            "/usr/bin/node",
            "./node",
            "-x",
            "a\0b",
            "a\nb",
            "a b",
        ] {
            assert!(ToolName::parse(bad).is_err(), "{bad:?}");
        }
        assert!(ToolName::parse(&"x".repeat(MAX_TOOL_NAME_BYTES)).is_ok());
        assert!(ToolName::parse(&"x".repeat(MAX_TOOL_NAME_BYTES + 1)).is_err());
    }

    #[test]
    fn tool_name_error_escapes_the_name_and_says_why() {
        let shown = assert_err!(ToolName::parse("a/\u{1b}[2J")).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.contains("bare program name"), "{shown}");
    }
}
