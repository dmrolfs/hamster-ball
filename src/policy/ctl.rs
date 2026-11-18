// ABOUTME: ContainerName: a validated container name for `hb ctl`, safe to pass as one argv element.
// ABOUTME: Grammar from the design: ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ (no leading dash, so it cannot become a flag).
//! The [`ContainerName`] value type.

use std::fmt;

use snafu::{Snafu, ensure};

use crate::text::Escaped;

/// Longest accepted container name, in bytes.
pub const MAX_CONTAINER_NAME_BYTES: usize = 64;

/// Why a string is not an acceptable container name.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ContainerNameError {
    /// The name is empty.
    #[snafu(display("container name is empty"))]
    Empty,

    /// The name is longer than [`MAX_CONTAINER_NAME_BYTES`].
    #[snafu(display("container name is {len} bytes long; the limit is {max}"))]
    TooLong {
        /// Length in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// The first character is not an ASCII letter or digit.
    #[snafu(display("container name must start with a letter or digit: {}", Escaped(name)))]
    InvalidStart {
        /// The rejected name.
        name: String,
    },

    /// A later character is not an ASCII letter, digit, `_`, `.` or `-`.
    #[snafu(display(
        "container name may contain only letters, digits, `_`, `.` and `-`: {} (found {})",
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

/// A container name matching `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerName(String);

impl ContainerName {
    /// Parses a container name.
    ///
    /// # Errors
    /// [`ContainerNameError`] for an empty, over-long or malformed name.
    pub fn parse(name: &str) -> Result<Self, ContainerNameError> {
        ensure!(!name.is_empty(), EmptySnafu);
        ensure!(
            name.len() <= MAX_CONTAINER_NAME_BYTES,
            TooLongSnafu {
                len: name.len(),
                max: MAX_CONTAINER_NAME_BYTES
            }
        );
        let mut chars = name.chars();
        if let Some(first) = chars.next() {
            ensure!(first.is_ascii_alphanumeric(), InvalidStartSnafu { name });
        }
        if let Some(bad) =
            chars.find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')))
        {
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

impl fmt::Display for ContainerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    #[test]
    fn container_name_matches_the_design_grammar() {
        for good in [
            "a",
            "0",
            "lgw-ledger-pg",
            "icehouse_postgres_1",
            "a.b-c_d",
            &"a".repeat(MAX_CONTAINER_NAME_BYTES),
        ] {
            assert_eq!(
                assert_ok!(ContainerName::parse(good), "{good}").as_str(),
                good
            );
        }
    }

    #[test]
    fn container_name_rejects_empty() {
        assert!(matches!(
            assert_err!(ContainerName::parse("")),
            ContainerNameError::Empty
        ));
    }

    #[test]
    fn container_name_rejects_a_leading_dash_dot_or_underscore() {
        for bad in ["--help", "-x", ".hidden", "_x"] {
            let err = assert_err!(ContainerName::parse(bad), "{bad}");
            assert!(
                matches!(err, ContainerNameError::InvalidStart { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn container_name_rejects_injection_characters() {
        for bad in ["a;id", "a b", "a/b", "a\nb", "a$b", "a`b", "a\u{e9}", "a:b"] {
            let err = assert_err!(ContainerName::parse(bad), "{bad:?}");
            assert!(
                matches!(err, ContainerNameError::InvalidCharacter { .. }),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn container_name_rejects_over_the_limit() {
        let err = assert_err!(ContainerName::parse(
            &"a".repeat(MAX_CONTAINER_NAME_BYTES + 1)
        ));
        assert!(
            matches!(err, ContainerNameError::TooLong { len, max } if len == MAX_CONTAINER_NAME_BYTES + 1 && max == MAX_CONTAINER_NAME_BYTES)
        );
    }

    #[test]
    fn container_name_error_display_escapes_the_name() {
        let shown = assert_err!(ContainerName::parse("a\u{1b}[2J")).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }
}
