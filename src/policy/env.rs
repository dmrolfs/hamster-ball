// ABOUTME: EnvName and EnvValue: validated environment variable names and values for the child environment.
// ABOUTME: Syntax only; which names are reserved or forbidden is policy and lives with the floor and session builder.
//! Environment variable names and values.

use std::fmt;

use snafu::{Snafu, ensure};

use crate::text::Escaped;

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

/// An environment variable value: any text without NUL.
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
}
