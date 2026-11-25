// ABOUTME: ContainerName, ContainerLabel and LaunchdLabel: validated selectors for `hb ctl`, each safe as one argv element.
// ABOUTME: Name grammar from the design: ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ (no leading dash, so it cannot become a flag).
//! The [`ContainerName`], [`ContainerLabel`] and [`LaunchdLabel`] value types.

use std::fmt;

use snafu::{OptionExt, Snafu, ensure};

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

/// Longest accepted label key, in bytes.
pub const MAX_LABEL_KEY_BYTES: usize = 128;
/// Longest accepted label value, in bytes.
pub const MAX_LABEL_VALUE_BYTES: usize = 128;

/// Why a string is not an acceptable container label selector.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ContainerLabelError {
    /// The selector is empty.
    #[snafu(display("container label is empty; expected `key=value`"))]
    EmptyLabel,

    /// The selector has no `=`, so it would match every container that merely carries the key.
    #[snafu(display(
        "container label must be `key=value` (a bare key would match every container with that label): {}",
        Escaped(label)
    ))]
    MissingValue {
        /// The rejected selector.
        label: String,
    },

    /// The key is empty, too long, or has a character outside `[A-Za-z0-9_.-]`.
    #[snafu(display(
        "container label key must start with a letter or digit, use only letters, digits, `_`, `.` and `-`, and be at most {MAX_LABEL_KEY_BYTES} bytes: {}",
        Escaped(label)
    ))]
    InvalidKey {
        /// The rejected selector.
        label: String,
    },

    /// The value is empty, too long, or has a character outside `[A-Za-z0-9_.:/@+-]`.
    #[snafu(display(
        "container label value must be non-empty, use only letters, digits and `_ . : / @ + -`, and be at most {MAX_LABEL_VALUE_BYTES} bytes: {}",
        Escaped(label)
    ))]
    InvalidValue {
        /// The rejected selector.
        label: String,
    },
}

/// A container label selector `key=value`, used to scope which containers `hb ctl` may touch.
///
/// A value is required: a bare key would select every container that carries it, and an empty
/// selector would select all of them. Both are rejected so a typo cannot widen the scope.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerLabel {
    key: String,
    value: String,
}

impl ContainerLabel {
    /// Parses a `key=value` selector.
    ///
    /// # Errors
    /// See [`ContainerLabelError`].
    pub fn parse(label: &str) -> Result<Self, ContainerLabelError> {
        ensure!(!label.is_empty(), EmptyLabelSnafu);
        let (key, value) = label.split_once('=').context(MissingValueSnafu { label })?;
        let key_ok = !key.is_empty()
            && key.len() <= MAX_LABEL_KEY_BYTES
            && key.starts_with(|c: char| c.is_ascii_alphanumeric())
            && key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        ensure!(key_ok, InvalidKeySnafu { label });
        let value_ok = !value.is_empty()
            && value.len() <= MAX_LABEL_VALUE_BYTES
            && value.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '/' | '@' | '+' | '-')
            });
        ensure!(value_ok, InvalidValueSnafu { label });
        Ok(Self {
            key: key.to_owned(),
            value: value.to_owned(),
        })
    }

    /// The label key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The label value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl fmt::Display for ContainerLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.key, self.value)
    }
}

/// Longest accepted launchd label, in bytes.
pub const MAX_LAUNCHD_LABEL_BYTES: usize = 128;

/// Why a string is not an acceptable launchd label.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum LaunchdLabelError {
    /// The label is empty.
    #[snafu(display("launchd label is empty"))]
    EmptyLaunchd,

    /// The label is longer than [`MAX_LAUNCHD_LABEL_BYTES`].
    #[snafu(display("launchd label is {len} bytes long; the limit is {max}"))]
    LaunchdTooLong {
        /// Length in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// The label starts with something other than a letter or digit, or has a character outside `[A-Za-z0-9_.-]`.
    #[snafu(display(
        "launchd label must start with a letter or digit and use only letters, digits, `_`, `.` and `-`: {}",
        Escaped(label)
    ))]
    InvalidLaunchd {
        /// The rejected label.
        label: String,
    },
}

/// The label of a launchd job in the user's login session, such as `com.example.postgres`.
///
/// `hb ctl launchd` may start or restart only the jobs a config lists. The grammar keeps the
/// label one plain argv word (it cannot start with `-` or hold `/`, so it cannot change the
/// `gui/<uid>/<label>` target into another domain).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LaunchdLabel(String);

impl LaunchdLabel {
    /// Parses a launchd label.
    ///
    /// # Errors
    /// [`LaunchdLabelError`] for an empty, over-long or malformed label.
    pub fn parse(label: &str) -> Result<Self, LaunchdLabelError> {
        ensure!(!label.is_empty(), EmptyLaunchdSnafu);
        ensure!(
            label.len() <= MAX_LAUNCHD_LABEL_BYTES,
            LaunchdTooLongSnafu {
                len: label.len(),
                max: MAX_LAUNCHD_LABEL_BYTES
            }
        );
        let ok = label.starts_with(|c: char| c.is_ascii_alphanumeric())
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        ensure!(ok, InvalidLaunchdSnafu { label });
        Ok(Self(label.to_owned()))
    }

    /// The label as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LaunchdLabel {
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
            "app-db",
            "myapp_postgres_1",
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

    // ====================================================================================
    // ContainerLabel
    // ====================================================================================

    #[test]
    fn container_label_accepts_key_equals_value() {
        let label = assert_ok!(ContainerLabel::parse("com.docker.compose.project=myapp"));
        assert_eq!(label.key(), "com.docker.compose.project");
        assert_eq!(label.value(), "myapp");
        assert_eq!(label.to_string(), "com.docker.compose.project=myapp");
    }

    #[test]
    fn container_label_accepts_the_value_alphabet_and_the_length_limits() {
        assert_ok!(ContainerLabel::parse("a=b_c.d:e/f@g+h-i"));
        let key = "k".repeat(MAX_LABEL_KEY_BYTES);
        let value = "v".repeat(MAX_LABEL_VALUE_BYTES);
        assert_ok!(ContainerLabel::parse(&format!("{key}={value}")));
    }

    #[test]
    fn container_label_rejects_empty() {
        let err = assert_err!(ContainerLabel::parse(""));
        assert!(matches!(err, ContainerLabelError::EmptyLabel), "{err:?}");
    }

    #[test]
    fn container_label_rejects_a_bare_key_because_it_would_match_too_much() {
        let err = assert_err!(ContainerLabel::parse("com.docker.compose.project"));
        assert!(
            matches!(err, ContainerLabelError::MissingValue { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn container_label_rejects_an_empty_value() {
        let err = assert_err!(ContainerLabel::parse("a="));
        assert!(
            matches!(err, ContainerLabelError::InvalidValue { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn container_label_rejects_bad_keys() {
        for bad in ["=v", "-a=v", ".a=v", "a b=v", "a\0b=v", "é=v", "a\n=v"] {
            let err = assert_err!(ContainerLabel::parse(bad), "{bad:?}");
            assert!(
                matches!(err, ContainerLabelError::InvalidKey { .. }),
                "{bad:?}: {err:?}"
            );
        }
        let long = format!("{}=v", "k".repeat(MAX_LABEL_KEY_BYTES + 1));
        assert!(matches!(
            assert_err!(ContainerLabel::parse(&long)),
            ContainerLabelError::InvalidKey { .. }
        ));
    }

    #[test]
    fn container_label_rejects_bad_values() {
        for bad in [
            "a=b c", "a=b\0c", "a=b\nc", "a=\"x\"", "a=x,y", "a=é", "a=b=c",
        ] {
            let err = assert_err!(ContainerLabel::parse(bad), "{bad:?}");
            assert!(
                matches!(err, ContainerLabelError::InvalidValue { .. }),
                "{bad:?}: {err:?}"
            );
        }
        let long = format!("a={}", "v".repeat(MAX_LABEL_VALUE_BYTES + 1));
        assert!(matches!(
            assert_err!(ContainerLabel::parse(&long)),
            ContainerLabelError::InvalidValue { .. }
        ));
    }

    #[test]
    fn container_label_error_display_escapes_and_names_the_rule() {
        let shown = assert_err!(ContainerLabel::parse("a=\u{1b}[2J")).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.contains("value"), "{shown:?}");
        let shown = assert_err!(ContainerLabel::parse("k")).to_string();
        assert!(shown.contains("key=value"), "{shown:?}");
    }

    // ====================================================================================
    // Display
    // ====================================================================================

    #[test]
    fn container_name_displays_as_its_text() {
        let name = assert_ok!(ContainerName::parse("pg-1.db"));
        assert_eq!(name.to_string(), "pg-1.db");
        assert_eq!(name.as_str(), "pg-1.db");
    }

    #[test]
    fn launchd_label_accepts_reverse_dns_names() {
        let longest = "a".repeat(MAX_LAUNCHD_LABEL_BYTES);
        for good in [
            "a",
            "com.example.postgres",
            "homebrew.mxcl.postgresql-16",
            &longest,
        ] {
            assert_eq!(
                assert_ok!(LaunchdLabel::parse(good), "{good}").as_str(),
                good
            );
        }
    }

    #[test]
    fn launchd_label_rejects_what_could_change_the_target_or_become_a_flag() {
        for bad in [
            "",
            "-k",
            ".x",
            "a/b",
            "a b",
            "a;id",
            "gui/501/x",
            "a\nb",
            "a\u{e9}",
            "a:b",
            "a@b",
        ] {
            assert_err!(LaunchdLabel::parse(bad), "{bad:?}");
        }
        assert!(matches!(
            assert_err!(LaunchdLabel::parse(
                &"a".repeat(MAX_LAUNCHD_LABEL_BYTES + 1)
            )),
            LaunchdLabelError::LaunchdTooLong { .. }
        ));
    }
}
