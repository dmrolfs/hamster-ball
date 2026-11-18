// ABOUTME: HomeDir, ProjectRoot and the single "too broad" predicate that guards roots and read/write grants.
// ABOUTME: Pure: the passwd lookup that produces a HomeDir from the environment lives in a later task (hb-ghd.1.1.5).
//! Home directory, project root, and the rule for what is too broad to grant.

use snafu::Snafu;
use strum::Display;

use super::path::CanonicalPath;

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

/// Why a path cannot be a project root.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RootError {
    /// The path is too broad to be a project root.
    #[snafu(display("{path} is too broad to use as a project root: it is {reason}"))]
    TooBroad {
        /// The rejected path.
        path: CanonicalPath,
        /// Why it is too broad.
        reason: BroadRoot,
    },
}

/// The user's home directory.
///
/// Constructed from an already-validated path. Reading it from the passwd database, and
/// refusing a mismatch with `$HOME`, is the job of the discovery task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HomeDir(CanonicalPath);

impl HomeDir {
    /// Wraps the user's home directory.
    #[must_use]
    pub fn new(path: CanonicalPath) -> Self {
        Self(path)
    }

    /// The home directory path.
    #[must_use]
    pub fn path(&self) -> &CanonicalPath {
        &self.0
    }
}

/// A project root proven not to be too broad.
///
/// Holding one is evidence that the path is not `/`, a top-level directory, the home
/// directory, or a directory that contains the home directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectRoot(CanonicalPath);

impl ProjectRoot {
    /// Accepts `path` as a project root unless it is too broad.
    ///
    /// # Errors
    /// [`RootError::TooBroad`] when [`broadness`] reports a reason.
    pub fn new(path: CanonicalPath, home: &HomeDir) -> Result<Self, RootError> {
        match broadness(&path, home) {
            Some(reason) => TooBroadSnafu { path, reason }.fail(),
            None => Ok(Self(path)),
        }
    }

    /// The project root path.
    #[must_use]
    pub fn path(&self) -> &CanonicalPath {
        &self.0
    }
}

/// Reports why `path` is too broad to grant, or `None` if it is acceptable.
///
/// The same predicate guards the project root and every `fs.read` and `fs.write` grant, so
/// a rule such as `write = ["~"]` cannot bypass the project-root check. Comparison is by path
/// component, so `/Users/rolfs2` is not confused with `/Users/rolfs`.
#[must_use]
pub fn broadness(path: &CanonicalPath, home: &HomeDir) -> Option<BroadRoot> {
    if path.depth() == 0 {
        Some(BroadRoot::Filesystem)
    } else if path == home.path() {
        Some(BroadRoot::Home)
    } else if path.is_same_or_ancestor_of(home.path()) {
        Some(BroadRoot::HomeAncestor)
    } else if path.depth() < 2 {
        Some(BroadRoot::TooShallow)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn path(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    fn home() -> HomeDir {
        HomeDir::new(path("/Users/rolfs"))
    }

    // ====================================================================================
    // broadness
    // ====================================================================================

    #[test]
    fn broadness_flags_the_filesystem_root() {
        assert_eq!(broadness(&path("/"), &home()), Some(BroadRoot::Filesystem));
    }

    #[test]
    fn broadness_flags_the_home_directory_itself() {
        assert_eq!(
            broadness(&path("/Users/rolfs"), &home()),
            Some(BroadRoot::Home)
        );
    }

    #[test]
    fn broadness_flags_ancestors_of_home() {
        assert_eq!(
            broadness(&path("/Users"), &home()),
            Some(BroadRoot::HomeAncestor)
        );
    }

    #[test]
    fn broadness_flags_single_component_system_directories() {
        for p in ["/private", "/Volumes", "/opt", "/tmp"] {
            assert_eq!(
                broadness(&path(p), &home()),
                Some(BroadRoot::TooShallow),
                "{p}"
            );
        }
    }

    #[test]
    fn broadness_allows_subdirectories_of_home() {
        for p in [
            "/Users/rolfs/work",
            "/Users/rolfs/work/app/src",
            "/Users/rolfs/.config",
        ] {
            assert_eq!(broadness(&path(p), &home()), None, "{p}");
        }
    }

    #[test]
    fn broadness_allows_a_sibling_whose_name_starts_with_the_home_name() {
        assert_eq!(broadness(&path("/Users/rolfs2"), &home()), None);
        assert_eq!(broadness(&path("/Users/rolfs2/work"), &home()), None);
    }

    #[test]
    fn broadness_allows_two_component_paths_outside_home() {
        assert_eq!(broadness(&path("/opt/homebrew"), &home()), None);
        assert_eq!(broadness(&path("/private/tmp"), &home()), None);
    }

    #[test]
    fn broadness_uses_the_supplied_home_not_a_fixed_one() {
        let other = HomeDir::new(path("/home/dev"));
        assert_eq!(
            broadness(&path("/home"), &other),
            Some(BroadRoot::HomeAncestor)
        );
        assert_eq!(broadness(&path("/home/dev"), &other), Some(BroadRoot::Home));
        assert_eq!(broadness(&path("/Users/rolfs"), &other), None);
    }

    // ====================================================================================
    // ProjectRoot
    // ====================================================================================

    #[test]
    fn project_root_new_rejects_broad_roots() {
        for p in ["/", "/Users", "/Users/rolfs", "/private"] {
            let err = assert_err!(ProjectRoot::new(path(p), &home()), "{p}");
            assert!(matches!(err, RootError::TooBroad { .. }), "{p}: {err:?}");
        }
    }

    #[test]
    fn project_root_new_accepts_a_project_directory() {
        let root = assert_ok!(ProjectRoot::new(path("/Users/rolfs/work/app"), &home()));
        assert_eq!(root.path().as_str(), "/Users/rolfs/work/app");
    }

    #[test]
    fn project_root_error_names_the_path_and_the_reason() {
        let shown = assert_err!(ProjectRoot::new(path("/Users"), &home())).to_string();
        assert_eq!(
            shown,
            "/Users is too broad to use as a project root: it is a parent of your home directory"
        );
    }

    // ====================================================================================
    // BroadRoot strum forms
    // ====================================================================================

    #[test]
    fn broad_root_display_is_a_phrase_for_error_messages() {
        assert_eq!(BroadRoot::Filesystem.to_string(), "the filesystem root");
        assert_eq!(BroadRoot::Home.to_string(), "your home directory");
        assert_eq!(
            BroadRoot::HomeAncestor.to_string(),
            "a parent of your home directory"
        );
        assert_eq!(
            BroadRoot::TooShallow.to_string(),
            "a top-level system directory"
        );
    }

    #[test]
    fn home_dir_exposes_its_path() {
        assert_eq!(home().path().as_str(), "/Users/rolfs");
    }
}
