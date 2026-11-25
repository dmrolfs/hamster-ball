// ABOUTME: CanonicalPath: an absolute, normalized, UTF-8 path that is safe to hand to Seatbelt as a parameter.
// ABOUTME: CanonicalPath (a pure form check, no I/O) and PathError, which also carries PathResolver's resolution errors.
//! The [`CanonicalPath`] value type.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use snafu::{OptionExt, Snafu, ensure};
use strum::Display;

use crate::text::Escaped;

/// Why a path is too broad to be a project root or a read/write grant.
///
/// `Display` gives a phrase suitable for an error message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum BroadRoot {
    /// The filesystem root, `/`.
    #[strum(to_string = "the filesystem root")]
    Filesystem,
    /// The user's home directory itself.
    #[strum(to_string = "your home directory")]
    Home,
    /// A directory that contains the user's home directory, such as `/Users`.
    #[strum(to_string = "a parent of your home directory")]
    HomeAncestor,
    /// A top-level system directory with fewer than two components, such as `/private`.
    #[strum(to_string = "a top-level system directory")]
    TooShallow,
}

/// Longest accepted path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// Why a string is not an acceptable canonical path.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
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

    // ------------------------------------------------------------------------------------
    // Resolution errors: produced only by `PathResolver` (policy::resolve), which is the
    // crate's one module that touches the filesystem. Everything above this point is a pure
    // form check with no I/O.
    // ------------------------------------------------------------------------------------
    /// The spelling is empty.
    #[snafu(display("path spelling is empty"))]
    EmptySpelling,

    /// The spelling is longer than [`MAX_PATH_BYTES`].
    #[snafu(display("path spelling is {len} bytes long; the limit is {MAX_PATH_BYTES}"))]
    SpellingTooLong {
        /// Length in bytes.
        len: usize,
    },

    /// The spelling contains NUL or another control character.
    #[snafu(display("path spelling contains a control character: {}", Escaped(spelling)))]
    SpellingControlCharacter {
        /// The offending spelling as written.
        spelling: String,
    },

    /// The spelling uses the `~user` form, which is not supported (only `~` and `~/...`).
    #[snafu(display(
        "`~user` is not supported; use `~/...` for your own home directory: {}",
        Escaped(spelling)
    ))]
    TildeUser {
        /// The offending spelling as written.
        spelling: String,
    },

    /// A path popped into an unresolved tail was `..`, which is rejected rather than collapsed.
    #[snafu(display(
        "{} has `..` in a part that does not exist yet, which is rejected rather than guessed at",
        Escaped(spelling)
    ))]
    DotDotInTail {
        /// The spelling that produced this tail.
        spelling: String,
    },

    /// The path does not exist (used by `existing`, which never tolerates a missing path).
    #[snafu(display("{} does not exist", Escaped(spelling)))]
    Missing {
        /// The spelling that was resolved.
        spelling: String,
    },

    /// The path, or an ancestor of it, is an existing symlink whose target does not exist.
    /// A deny rule treats this as an error rather than a skip, because a deny rule that
    /// silently covers nothing is a fail-open bug, not a fail-closed one.
    #[snafu(display(
        "{} is a symlink with no target (or has one in its path)",
        Escaped(spelling)
    ))]
    Dangling {
        /// The spelling that was resolved.
        spelling: String,
    },

    /// An allow rule could not be resolved because a directory in its path denies access.
    /// A deny rule never produces this: it falls through and keeps the rule in force instead.
    #[snafu(display("{} is not readable", Escaped(spelling)))]
    PathUnreadable {
        /// The spelling that was resolved.
        spelling: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// A non-final component of the path is a regular file, not a directory.
    #[snafu(display("{} has a file where a directory was expected", Escaped(spelling)))]
    NotADirectoryAncestor {
        /// The spelling that was resolved.
        spelling: String,
    },

    /// Resolving the path required following more symlinks than the OS allows.
    #[snafu(display("{} has a symlink loop", Escaped(spelling)))]
    SymlinkLoop {
        /// The spelling that was resolved.
        spelling: String,
    },

    /// An I/O error occurred that does not fit a more specific variant above.
    #[snafu(display("{} could not be resolved", Escaped(spelling)))]
    Io {
        /// The spelling that was resolved.
        spelling: String,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// An `fs.read` or `fs.write` allow rule is too broad to grant.
    #[snafu(display("{path} is too broad to grant as a read/write rule: it is {reason}"))]
    TooBroad {
        /// The rejected path.
        path: CanonicalPath,
        /// Why it is too broad.
        reason: BroadRoot,
    },

    /// A relative `fs.read`/`fs.write` grant resolved to somewhere outside the project.
    #[snafu(display(
        "{} resolves to {resolved}, outside the project ({project_root}); relative paths must \
         stay inside the project, so use an absolute path to reach outside it",
        Escaped(spelling)
    ))]
    RelativeEscapesProject {
        /// The spelling as written.
        spelling: String,
        /// Where it actually resolved to.
        resolved: CanonicalPath,
        /// The project root it escaped.
        project_root: CanonicalPath,
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
    /// `/Users/me` is not an ancestor of `/Users/me2`.
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
        assert_eq!(path("/Users/me/.ssh").as_str(), "/Users/me/.ssh");
    }

    #[test]
    fn accepts_unicode_and_spaces() {
        assert_eq!(
            path("/Users/me/caf\u{e9} dir").as_str(),
            "/Users/me/caf\u{e9} dir"
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
        let home = path("/Users/me");
        assert!(home.is_same_or_ancestor_of(&path("/Users/me")));
        assert!(home.is_same_or_ancestor_of(&path("/Users/me/work")));
        assert!(!home.is_same_or_ancestor_of(&path("/Users/me2")));
        assert!(!home.is_same_or_ancestor_of(&path("/Users")));
        assert!(path("/").is_same_or_ancestor_of(&home));
    }

    #[test]
    fn depth_counts_components_below_root() {
        assert_eq!(path("/").depth(), 0);
        assert_eq!(path("/Users").depth(), 1);
        assert_eq!(path("/Users/me").depth(), 2);
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
