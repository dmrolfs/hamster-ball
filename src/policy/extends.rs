// ABOUTME: PresetName and ExtendTarget: how one `extends` entry is classified, as a preset name or a file path.
// ABOUTME: Pure classification only; finding and reading the file is config::extends.
//! Classifying `extends` entries.
//!
//! An entry is a **path** if it starts with `/`, `~/`, `./` or `../`; otherwise it is a
//! preset **name**. The two never overlap, so `extends = ["rust"]` can never be read as a file
//! in the current directory, and `extends = ["./rust"]` can never be read as the built-in.

use snafu::{ResultExt, Snafu, ensure};

use super::names::ExtendRef;
use crate::text::EscapedBounded;

/// Longest accepted preset name, in bytes.
pub const MAX_PRESET_NAME_BYTES: usize = 64;
/// How much of a rejected value is echoed in an error message.
const ERROR_PREVIEW_CHARS: usize = 64;

/// Why a string is not an acceptable preset name.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PresetNameError {
    /// The name is empty.
    #[snafu(display("preset name is empty"))]
    Empty,

    /// The name is longer than [`MAX_PRESET_NAME_BYTES`].
    #[snafu(display("preset name is {len} bytes long; the limit is {max}"))]
    TooLong {
        /// Length in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// The name ends in `.toml`, so it was most likely meant as a file.
    #[snafu(display("{}", looks_like_file_message(name)))]
    LooksLikeFile {
        /// The rejected value.
        name: String,
    },

    /// The name is outside `[a-z0-9][a-z0-9_-]*(/[a-z0-9][a-z0-9_-]*)*`.
    #[snafu(display(
        "preset name must be lowercase letters, digits, `_` and `-`, in segments separated by `/`: {}",
        EscapedBounded::new(name, ERROR_PREVIEW_CHARS)
    ))]
    Invalid {
        /// The rejected value.
        name: String,
    },
}

/// The name of a preset: segments of `[a-z0-9][a-z0-9_-]*` joined by `/`, at most 64 bytes.
///
/// There is no `.` and no `..`, so a name cannot name a path outside the presets directory.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PresetName(String);

impl PresetName {
    /// Parses a preset name.
    ///
    /// # Errors
    /// See [`PresetNameError`].
    pub fn parse(name: &str) -> Result<Self, PresetNameError> {
        ensure!(!name.is_empty(), EmptySnafu);
        ensure!(
            name.len() <= MAX_PRESET_NAME_BYTES,
            TooLongSnafu {
                len: name.len(),
                max: MAX_PRESET_NAME_BYTES
            }
        );
        ensure!(!name.ends_with(".toml"), LooksLikeFileSnafu { name });
        ensure!(name.split('/').all(valid_segment), InvalidSnafu { name });
        Ok(Self(name.to_owned()))
    }

    /// The name as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for PresetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn valid_segment(segment: &str) -> bool {
    segment.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && segment
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'))
}

fn looks_like_file_message(name: &str) -> String {
    let shown = EscapedBounded::new(name, ERROR_PREVIEW_CHARS);
    format!(
        "{shown} looks like a file name, not a preset name; write a file as a path, for example `./{shown}`"
    )
}

/// Why an `extends` entry could not be classified.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ExtendTargetError {
    /// The entry starts with `~` but is not `~/...`.
    #[snafu(display(
        "`~` is only supported as `~/...` (your own home directory); `~user` is not: {}",
        EscapedBounded::new(text, ERROR_PREVIEW_CHARS)
    ))]
    Tilde {
        /// The rejected entry.
        text: String,
    },

    /// The entry is not a path, and is not a valid preset name.
    #[snafu(display(
        "{} is neither a path (starting with `/`, `~/`, `./` or `../`) nor a valid preset name",
        EscapedBounded::new(text, ERROR_PREVIEW_CHARS)
    ))]
    Name {
        /// The rejected entry.
        text: String,
        /// Why it is not a preset name.
        source: PresetNameError,
    },
}

/// What an `extends` entry refers to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendTarget {
    /// A preset, looked up among the built-ins and the user's presets directory.
    Name(PresetName),
    /// A file, spelled as written (`/`, `~/`, `./` or `../` prefix).
    Path(String),
}

impl ExtendRef {
    /// Classifies this entry as a preset name or a path.
    ///
    /// # Errors
    /// See [`ExtendTargetError`].
    pub fn target(&self) -> Result<ExtendTarget, ExtendTargetError> {
        let text = self.as_str();
        if ["/", "~/", "./", "../"]
            .iter()
            .any(|prefix| text.starts_with(prefix))
        {
            return Ok(ExtendTarget::Path(text.to_owned()));
        }
        ensure!(!text.starts_with('~'), TildeSnafu { text });
        PresetName::parse(text)
            .map(ExtendTarget::Name)
            .context(NameSnafu { text })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    // ====================================================================================
    // PresetName and ExtendRef::target
    // ====================================================================================

    #[test]
    fn preset_names_accept_the_documented_grammar() {
        for good in ["rust", "git", "agent/kiro", "agent/pi", "a-b_c/d9", "x"] {
            assert_eq!(assert_ok!(PresetName::parse(good)).as_str(), good);
        }
    }

    #[test]
    fn preset_names_reject_everything_outside_the_grammar() {
        for bad in [
            "", "Rust", "foo.toml", "a.b", "a//b", "/a", "a/", "a/..", "../a", "a b", "-a", "_a",
            "a/-b", "é", "a\0b", "a\\b", "a:b",
        ] {
            assert_err!(PresetName::parse(bad), "{bad:?}");
        }
    }

    #[test]
    fn preset_names_accept_the_length_limit_and_reject_one_over() {
        assert_ok!(PresetName::parse(&"a".repeat(MAX_PRESET_NAME_BYTES)));
        let err = assert_err!(PresetName::parse(&"a".repeat(MAX_PRESET_NAME_BYTES + 1)));
        assert!(matches!(err, PresetNameError::TooLong { .. }), "{err:?}");
    }

    #[test]
    fn a_name_that_looks_like_a_file_name_suggests_the_path_spelling() {
        let shown = assert_err!(PresetName::parse("mine.toml")).to_string();
        assert!(shown.contains("./mine.toml"), "{shown:?}");
    }

    #[test]
    fn extend_targets_with_a_path_prefix_are_paths() {
        for (text, spelling) in [
            ("/abs/x.toml", "/abs/x.toml"),
            ("~/presets/x.toml", "~/presets/x.toml"),
            ("./x.toml", "./x.toml"),
            ("../shared/x.toml", "../shared/x.toml"),
        ] {
            let target = assert_ok!(assert_ok!(ExtendRef::parse(text)).target());
            assert_eq!(target, ExtendTarget::Path(spelling.to_owned()), "{text}");
        }
    }

    #[test]
    fn extend_targets_without_a_path_prefix_are_preset_names() {
        let target = assert_ok!(assert_ok!(ExtendRef::parse("agent/kiro")).target());
        assert_eq!(
            target,
            ExtendTarget::Name(assert_ok!(PresetName::parse("agent/kiro")))
        );
    }

    #[test]
    fn extend_targets_reject_tilde_forms_other_than_tilde_slash() {
        for bad in ["~", "~user/x.toml", "~x"] {
            let err = assert_err!(assert_ok!(ExtendRef::parse(bad)).target());
            assert!(
                matches!(err, ExtendTargetError::Tilde { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn extend_targets_reject_a_bare_dot_or_dotdot_and_bad_names() {
        for bad in [".", "..", "Foo", "a.toml", "-x"] {
            let err = assert_err!(assert_ok!(ExtendRef::parse(bad)).target());
            assert!(
                matches!(err, ExtendTargetError::Name { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn extend_target_errors_escape_and_follow_the_display_convention() {
        // A right-to-left override is not a control character, so `ExtendRef` accepts it;
        // the classifier must still escape it when it rejects the name.
        let err = assert_err!(assert_ok!(ExtendRef::parse("A\u{202e}b")).target());
        assert!(!err.to_string().contains('\u{202e}'), "{err}");
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
