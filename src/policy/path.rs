// ABOUTME: CanonicalPath: an absolute, normalized, UTF-8 path that is safe to hand to Seatbelt as a parameter.
// ABOUTME: Pure form check only (no I/O); resolving a spelling against the filesystem lives in a later module.
//! The [`CanonicalPath`] value type.

use std::fmt;
use std::path::{Path, PathBuf};

use snafu::{OptionExt, Snafu, ensure};

use crate::text::Escaped;

/// Longest accepted path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Why a string is not an acceptable canonical path.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PathError {
    /// The path does not start with `/`.
    #[snafu(display("path is not absolute: {}", Escaped(path)))]
    NotAbsolute {
        /// The offending path as written.
        path: String,
    },

    /// The path is not valid UTF-8.
    #[snafu(display("path is not valid UTF-8: {}", Escaped(&path.to_string_lossy())))]
    NotUtf8 {
        /// The offending path.
        path: PathBuf,
    },

    /// The path is longer than [`MAX_PATH_BYTES`].
    #[snafu(display("path is {len} bytes long; the limit is {max}"))]
    TooLong {
        /// Length of the path in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// The path contains NUL or another control character.
    #[snafu(display("path contains a control character: {}", Escaped(path)))]
    ControlCharacter {
        /// The offending path as written.
        path: String,
    },

    /// The path has an empty, `.` or `..` segment, or a trailing slash.
    #[snafu(display(
        "path is not normalized (empty, `.` or `..` segment, or trailing slash): {}",
        Escaped(path)
    ))]
    NotNormalized {
        /// The offending path as written.
        path: String,
    },
}

/// An absolute, normalized, UTF-8 path with no control characters.
///
/// "Canonical" describes the form, which this type guarantees, not that the filesystem was
/// consulted: construction performs no I/O. The filesystem-resolving code in a later module
/// is the only producer of values that were also resolved through symlinks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CanonicalPath(String);

impl CanonicalPath {
    /// Wraps a path that is already in canonical form, checking only the form.
    ///
    /// # Errors
    /// - [`PathError::NotUtf8`]: the path is not valid UTF-8.
    /// - [`PathError::TooLong`]: the path is longer than [`MAX_PATH_BYTES`].
    /// - [`PathError::ControlCharacter`]: the path contains NUL or another control character.
    /// - [`PathError::NotAbsolute`]: the path does not start with `/`.
    /// - [`PathError::NotNormalized`]: the path has an empty, `.` or `..` segment or a trailing slash.
    pub fn from_canonical(path: impl AsRef<Path>) -> Result<Self, PathError> {
        let path = path.as_ref();
        let text = path.to_str().context(NotUtf8Snafu {
            path: path.to_path_buf(),
        })?;
        // Length first, so the messages below can safely echo a bounded amount of text.
        ensure!(
            text.len() <= MAX_PATH_BYTES,
            TooLongSnafu {
                len: text.len(),
                max: MAX_PATH_BYTES
            }
        );
        ensure!(
            !text.chars().any(char::is_control),
            ControlCharacterSnafu { path: text }
        );
        ensure!(text.starts_with('/'), NotAbsoluteSnafu { path: text });
        if text != "/" {
            for segment in text[1..].split('/') {
                ensure!(
                    !matches!(segment, "" | "." | ".."),
                    NotNormalizedSnafu { path: text }
                );
            }
        }
        Ok(Self(text.to_owned()))
    }

    /// The path as a [`Path`].
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// The path as text; always valid because construction requires UTF-8.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `self` equals `other` or is one of its ancestors, compared component by component.
    ///
    /// `/Users/rolfs` is not an ancestor of `/Users/rolfs2`.
    #[must_use]
    pub fn is_same_or_ancestor_of(&self, other: &CanonicalPath) -> bool {
        other.as_path().starts_with(self.as_path())
    }

    /// Number of components below the filesystem root (`/` is 0, `/Users` is 1).
    #[must_use]
    pub fn depth(&self) -> usize {
        // The root directory is one component; everything after it is a named segment.
        self.as_path().components().count().saturating_sub(1)
    }
}

impl AsRef<Path> for CanonicalPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl fmt::Display for CanonicalPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Control characters cannot occur in a constructed value; escaping is defence in depth.
        write!(f, "{}", Escaped(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    fn path(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    // ====================================================================================
    // Accepted forms
    // ====================================================================================

    #[test]
    fn accepts_root_and_ordinary_paths() {
        assert_eq!(path("/").as_str(), "/");
        assert_eq!(path("/Users/rolfs/.ssh").as_str(), "/Users/rolfs/.ssh");
    }

    #[test]
    fn accepts_unicode_and_spaces() {
        assert_eq!(
            path("/Users/rolfs/caf\u{e9} dir").as_str(),
            "/Users/rolfs/caf\u{e9} dir"
        );
    }

    #[test]
    fn accepts_quote_and_parenthesis_because_params_never_interpolate_paths() {
        // The old `sb` broke on these because it pasted paths into profile text.
        assert_eq!(path("/a/b\"c)d").as_str(), "/a/b\"c)d");
    }

    #[test]
    fn accepts_exactly_the_length_limit() {
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES - 1));
        assert_eq!(long.len(), MAX_PATH_BYTES);
        assert_ok!(CanonicalPath::from_canonical(&long));
    }

    // ====================================================================================
    // Rejected forms
    // ====================================================================================

    #[test]
    fn rejects_relative_paths() {
        let err = assert_err!(CanonicalPath::from_canonical("a/b"));
        assert!(matches!(err, PathError::NotAbsolute { .. }));
        assert!(matches!(
            assert_err!(CanonicalPath::from_canonical("")),
            PathError::NotAbsolute { .. }
        ));
    }

    #[test]
    fn rejects_nul_and_control_characters() {
        for bad in ["/a\0b", "/a\nb", "/a\tb", "/a\u{1b}[2Jb", "/a\u{7f}b"] {
            let err = assert_err!(CanonicalPath::from_canonical(bad), "{bad:?}");
            assert!(
                matches!(err, PathError::ControlCharacter { .. }),
                "{bad:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn rejects_dot_dotdot_double_slash_and_trailing_slash() {
        for bad in ["/a/./b", "/a/../b", "/..", "/a//b", "//", "/a/", "/."] {
            let err = assert_err!(CanonicalPath::from_canonical(bad), "{bad:?}");
            assert!(
                matches!(err, PathError::NotNormalized { .. }),
                "{bad:?} gave {err:?}"
            );
        }
    }

    #[test]
    fn rejects_paths_over_the_length_limit() {
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        let err = assert_err!(CanonicalPath::from_canonical(&long));
        assert!(
            matches!(err, PathError::TooLong { len, max } if len == MAX_PATH_BYTES + 1 && max == MAX_PATH_BYTES)
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_paths() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let bytes = OsStr::from_bytes(b"/a/\xff\xfe");
        let err = assert_err!(CanonicalPath::from_canonical(Path::new(bytes)));
        assert!(matches!(err, PathError::NotUtf8 { .. }));
    }

    // ====================================================================================
    // Comparison and shape
    // ====================================================================================

    #[test]
    fn ancestor_comparison_is_component_wise() {
        let home = path("/Users/rolfs");
        assert!(home.is_same_or_ancestor_of(&path("/Users/rolfs")));
        assert!(home.is_same_or_ancestor_of(&path("/Users/rolfs/work")));
        assert!(!home.is_same_or_ancestor_of(&path("/Users/rolfs2")));
        assert!(!home.is_same_or_ancestor_of(&path("/Users")));
        assert!(path("/").is_same_or_ancestor_of(&home));
    }

    #[test]
    fn depth_counts_components_below_root() {
        assert_eq!(path("/").depth(), 0);
        assert_eq!(path("/Users").depth(), 1);
        assert_eq!(path("/Users/rolfs").depth(), 2);
    }

    #[test]
    fn as_path_and_as_ref_agree() {
        let p = path("/a/b");
        assert_eq!(p.as_path(), Path::new("/a/b"));
        let as_ref: &Path = p.as_ref();
        assert_eq!(as_ref, Path::new("/a/b"));
    }

    // ====================================================================================
    // Error display hygiene
    // ====================================================================================

    #[test]
    fn error_display_escapes_control_characters() {
        let err = assert_err!(CanonicalPath::from_canonical("/a\u{1b}[2J\nb"));
        let shown = err.to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(!shown.contains('\n'), "{shown:?}");
        assert!(shown.contains("\\u{1b}"), "{shown:?}");
    }

    #[test]
    fn error_display_for_long_path_does_not_echo_the_path() {
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        let shown = assert_err!(CanonicalPath::from_canonical(&long)).to_string();
        assert!(shown.len() < 100, "{} bytes", shown.len());
    }

    // ====================================================================================
    // Properties
    // ====================================================================================

    proptest! {
        #[test]
        fn form_check_never_panics(s in ".*") {
            let _ = CanonicalPath::from_canonical(&s);
        }

        #[test]
        fn accepted_paths_are_absolute_normalized_and_control_free(s in "(/[a-zA-Z0-9._ -]{1,8}){0,6}") {
            if let Ok(p) = CanonicalPath::from_canonical(&s) {
                let text = p.as_str();
                prop_assert!(text.starts_with('/'));
                prop_assert!(!text.contains("//"));
                prop_assert!(text == "/" || !text.ends_with('/'));
                prop_assert!(!text.chars().any(char::is_control));
                prop_assert!(text.split('/').all(|seg| seg != "." && seg != ".."));
            }
        }
    }
}
