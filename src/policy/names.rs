// ABOUTME: ExtendRef and GuardException: validated text for config values whose meaning later milestones define.
// ABOUTME: Only form is checked here (non-empty, no control characters, bounded); matching and loading come later.
//! Reference-like text values from the config file.

use std::fmt;

use snafu::{Snafu, ensure};

use crate::text::EscapedBounded;

/// Longest accepted reference, in bytes.
pub const MAX_REF_BYTES: usize = 1024;
/// How much of a rejected value is echoed in an error message.
const ERROR_PREVIEW_CHARS: usize = 64;

/// Why a string is not an acceptable reference.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RefTextError {
    /// The value is empty.
    #[snafu(display("value is empty"))]
    Empty,

    /// The value is longer than [`MAX_REF_BYTES`].
    #[snafu(display("value is {len} bytes long; the limit is {max}"))]
    TooLong {
        /// Length in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// A guard exception that is neither absolute nor under the home directory.
    #[snafu(display(
        "a guard exception must start with `/` or `~/`: a relative one would switch the guard off in every project (got {})",
        EscapedBounded::new(text, ERROR_PREVIEW_CHARS)
    ))]
    NotAbsolute {
        /// The rejected value as written.
        text: String,
    },

    /// The value contains NUL or another control character.
    #[snafu(display(
        "value contains a control character: {}",
        EscapedBounded::new(text, ERROR_PREVIEW_CHARS)
    ))]
    ControlCharacter {
        /// The rejected value as written.
        text: String,
    },
}

fn check(text: &str) -> Result<(), RefTextError> {
    ensure!(!text.is_empty(), EmptySnafu);
    ensure!(
        text.len() <= MAX_REF_BYTES,
        TooLongSnafu {
            len: text.len(),
            max: MAX_REF_BYTES
        }
    );
    ensure!(
        !text.chars().any(char::is_control),
        ControlCharacterSnafu { text }
    );
    Ok(())
}

macro_rules! ref_text_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Parses the value.
            ///
            /// # Errors
            /// See [`RefTextError`].
            pub fn parse(text: &str) -> Result<Self, RefTextError> {
                check(text)?;
                Ok(Self(text.to_owned()))
            }

            /// The value as text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

ref_text_type!(
    /// One entry of a file's top-level `extends`: a preset name or a path.
    ///
    /// Only the form is checked here; deciding whether it names a built-in preset, a user
    /// preset or a file, and loading it, belongs to the merge milestone.
    ExtendRef
);

/// One entry of `guard.exceptions`: where the secrets guard is switched off.
///
/// An absolute path or one under `~/`, with the glob tail `fs.deny_read` accepts. A relative entry
/// is refused: the entry lives in the user's base config, so a relative one would apply to every
/// project. What the pattern matches is decided when the guard is prepared for a run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GuardException(String);

impl GuardException {
    /// Parses the value.
    ///
    /// # Errors
    /// See [`RefTextError`]; [`RefTextError::NotAbsolute`] for a relative entry.
    pub fn parse(text: &str) -> Result<Self, RefTextError> {
        check(text)?;
        ensure!(
            text.starts_with('/') || text.starts_with("~/"),
            NotAbsoluteSnafu { text }
        );
        Ok(Self(text.to_owned()))
    }

    /// The value as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GuardException {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Longest accepted MCP server name, in bytes.
pub const MAX_MCP_NAME_BYTES: usize = 64;

/// Why a string is not an acceptable MCP server name.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum McpNameError {
    /// The name is empty.
    #[snafu(display("MCP server name is empty"))]
    EmptyName,

    /// The name is longer than [`MAX_MCP_NAME_BYTES`].
    #[snafu(display("MCP server name is {len} bytes long; the limit is {max}"))]
    NameTooLong {
        /// Length in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// The first character is not an ASCII letter or digit.
    #[snafu(display(
        "MCP server name must start with a letter or digit: {}",
        EscapedBounded::new(name, ERROR_PREVIEW_CHARS)
    ))]
    InvalidStart {
        /// The rejected name.
        name: String,
    },

    /// A later character is not an ASCII letter, digit, `_` or `-`.
    #[snafu(display(
        "MCP server name may contain only letters, digits, `_` and `-`: {}",
        EscapedBounded::new(name, ERROR_PREVIEW_CHARS)
    ))]
    InvalidCharacter {
        /// The rejected name.
        name: String,
    },
}

/// The name of an `[mcp.<name>]` server: `[A-Za-z0-9][A-Za-z0-9_-]{0,63}`.
///
/// The name identifies the server in later profiles and logs, so it cannot carry a path
/// separator, a dot, whitespace or any shell-significant character.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct McpName(String);

impl McpName {
    /// Parses a server name.
    ///
    /// # Errors
    /// See [`McpNameError`].
    pub fn parse(name: &str) -> Result<Self, McpNameError> {
        ensure!(!name.is_empty(), EmptyNameSnafu);
        ensure!(
            name.len() <= MAX_MCP_NAME_BYTES,
            NameTooLongSnafu {
                len: name.len(),
                max: MAX_MCP_NAME_BYTES
            }
        );
        ensure!(
            name.starts_with(|c: char| c.is_ascii_alphanumeric()),
            InvalidStartSnafu { name }
        );
        ensure!(
            name.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-')),
            InvalidCharacterSnafu { name }
        );
        Ok(Self(name.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for McpName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for McpName {
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
    fn accepts_a_preset_name_a_path_and_a_glob_like_exception() {
        assert_eq!(
            assert_ok!(ExtendRef::parse("agent/kiro")).as_str(),
            "agent/kiro"
        );
        assert_ok!(ExtendRef::parse("~/presets/mine.toml"));
        assert_ok!(GuardException::parse("~/work/proj/config/*.secrets.yaml"));
        assert_ok!(GuardException::parse("/srv/proj/.env"));
    }

    #[test]
    fn a_relative_guard_exception_is_refused_because_it_would_apply_to_every_project() {
        for bad in [
            ".env",
            "config/*.secrets.yaml",
            "./.env",
            "../x/.env",
            "~",
            "~user/.env",
        ] {
            assert!(
                matches!(
                    assert_err!(GuardException::parse(bad), "{bad}"),
                    RefTextError::NotAbsolute { .. }
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            assert_err!(ExtendRef::parse("")),
            RefTextError::Empty
        ));
        assert!(matches!(
            assert_err!(GuardException::parse("")),
            RefTextError::Empty
        ));
    }

    #[test]
    fn rejects_control_characters_including_nul_and_newline() {
        for bad in ["a\0b", "a\nb", "a\tb", "a\u{1b}[2Jb", "a\u{7f}b"] {
            let err = assert_err!(ExtendRef::parse(bad), "{bad:?}");
            assert!(
                matches!(err, RefTextError::ControlCharacter { .. }),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn accepts_the_length_limit_and_rejects_one_over() {
        assert_ok!(ExtendRef::parse(&"a".repeat(MAX_REF_BYTES)));
        let err = assert_err!(ExtendRef::parse(&"a".repeat(MAX_REF_BYTES + 1)));
        assert!(
            matches!(err, RefTextError::TooLong { len, max } if len == MAX_REF_BYTES + 1 && max == MAX_REF_BYTES),
            "{err:?}"
        );
    }

    #[test]
    fn error_display_escapes_and_bounds_the_value() {
        let shown =
            assert_err!(ExtendRef::parse(&format!("\u{1b}[2J{}", "x".repeat(300)))).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.len() < 200, "{}", shown.len());
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(ExtendRef::parse(
            ""
        )));
    }

    // ====================================================================================
    // McpName
    // ====================================================================================

    #[test]
    fn mcp_name_accepts_the_names_real_servers_use() {
        for good in [
            "serena",
            "sequential-thinking",
            "lean-ctx",
            "context7",
            "a",
            "A_b-9",
        ] {
            assert_eq!(assert_ok!(McpName::parse(good)).as_str(), good);
        }
    }

    #[test]
    fn mcp_name_accepts_the_length_limit_and_rejects_one_over() {
        assert_ok!(McpName::parse(&"a".repeat(MAX_MCP_NAME_BYTES)));
        let err = assert_err!(McpName::parse(&"a".repeat(MAX_MCP_NAME_BYTES + 1)));
        assert!(
            matches!(err, McpNameError::NameTooLong { len, max } if len == MAX_MCP_NAME_BYTES + 1 && max == MAX_MCP_NAME_BYTES),
            "{err:?}"
        );
    }

    #[test]
    fn mcp_name_rejects_empty() {
        assert!(matches!(
            assert_err!(McpName::parse("")),
            McpNameError::EmptyName
        ));
    }

    #[test]
    fn mcp_name_rejects_a_leading_dash_or_underscore() {
        for bad in ["-a", "_a"] {
            let err = assert_err!(McpName::parse(bad), "{bad:?}");
            assert!(
                matches!(err, McpNameError::InvalidStart { .. }),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn mcp_name_rejects_path_and_shell_shaped_names() {
        for bad in [
            "a b", "../x", "a/b", "a.b", "a\0b", "a\nb", "é", "a;b", "a$b",
        ] {
            let err = assert_err!(McpName::parse(bad), "{bad:?}");
            assert!(
                matches!(
                    err,
                    McpNameError::InvalidCharacter { .. } | McpNameError::InvalidStart { .. }
                ),
                "{bad:?}: {err:?}"
            );
        }
    }

    #[test]
    fn mcp_name_error_display_escapes_and_names_the_rule() {
        let shown = assert_err!(McpName::parse("a\u{1b}[2J")).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.contains("letters, digits"), "{shown:?}");
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(McpName::parse(
            ""
        )));
    }

    #[test]
    fn mcp_name_displays_as_its_text() {
        assert_eq!(assert_ok!(McpName::parse("serena")).to_string(), "serena");
    }

    #[test]
    fn mcp_name_borrows_as_str_so_a_map_can_be_looked_up_by_text() {
        let mut map = std::collections::BTreeMap::new();
        map.insert(assert_ok!(McpName::parse("serena")), 1);
        assert_eq!(map.get("serena"), Some(&1));
        assert_eq!(map.get("other"), None);
    }

    #[test]
    fn displays_as_its_text() {
        assert_eq!(
            assert_ok!(GuardException::parse("~/.env")).to_string(),
            "~/.env"
        );
    }
}
