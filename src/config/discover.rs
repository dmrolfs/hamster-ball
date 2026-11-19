// ABOUTME: discover() walks up from the current directory to find hamster-ball.toml, never falling back to the cwd.
// ABOUTME: Refuses a broad cwd or root, and a config or root directory that is not yours or is world-writable.
//! Finds the project root by walking up from the current directory, refusing to fall back to
//! the current directory when nothing is found, refusing a root that is too broad, and
//! refusing a project whose config file or directory another user could have written.

use std::fs::{self, Metadata};
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use nix::unistd::getuid;
use snafu::{ResultExt, Snafu};
use strum::Display;

use crate::policy::{
    BroadRoot, CanonicalPath, HomeDir, PathError, ProjectRoot, RootError, broadness,
};
use crate::sys::{file_kind, path_preview};

/// The name of a project's config file, looked for in every ancestor of the current directory.
const CONFIG_FILE_NAME: &str = "hamster-ball.toml";

/// Mode bit for "writable by anyone".
const WORLD_WRITABLE: u32 = 0o002;

/// The project root [`discover`] found, and the `hamster-ball.toml` inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Discovery {
    /// The project root.
    pub root: ProjectRoot,
    /// The config file found inside it, spelled from the canonical root directory.
    pub config: PathBuf,
}

/// What [`DiscoverError::Untrusted`] is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Subject {
    /// The `hamster-ball.toml` file.
    #[strum(to_string = "config file")]
    ConfigFile,
    /// The directory that contains it.
    #[strum(to_string = "project directory")]
    ProjectDirectory,
}

/// Why a config file or project directory is not trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display)]
pub enum Untrusted {
    /// It belongs to another user.
    #[strum(to_string = "owned by another user")]
    NotOwnedByYou,
    /// Any user can write to it.
    #[strum(to_string = "writable by every user")]
    WorldWritable,
}

/// Why [`discover`] could not find a usable project root.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DiscoverError {
    /// The starting directory could not be resolved (for example, it was deleted).
    #[snafu(display("the current directory, {}, could not be resolved", path_preview(path)))]
    CwdUnreadable {
        /// The path that was passed in.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The current directory itself is too broad to run `hb` from.
    #[snafu(display(
        "{path} is too broad to run hb from: it is {reason}. cd into your project directory and run hb again."
    ))]
    CwdTooBroad {
        /// The rejected directory.
        path: CanonicalPath,
        /// Why it is too broad.
        reason: BroadRoot,
    },

    /// A directory along the walk could not be checked for `hamster-ball.toml`.
    #[snafu(display("{} could not be checked for {CONFIG_FILE_NAME}", path_preview(path)))]
    ConfigUnreadable {
        /// The directory that could not be checked.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// Something named `hamster-ball.toml` exists but is not a regular file.
    #[snafu(display("{} is a {kind}, not a regular file", path_preview(path)))]
    ConfigNotARegularFile {
        /// The path that was found.
        path: PathBuf,
        /// What it is instead: `"symlink"`, `"directory"`, `"fifo"`, `"device"`, or `"other"`.
        kind: &'static str,
    },

    /// No `hamster-ball.toml` exists in `from` or any of its ancestors, up to `/`.
    #[snafu(display(
        "no {CONFIG_FILE_NAME} found in {} or any parent directory up to /; create one in your \
         project's root directory, or run hb from inside a project that already has one.",
        path_preview(from.as_path())
    ))]
    NoProjectConfig {
        /// Where the walk started.
        from: CanonicalPath,
    },

    /// A `hamster-ball.toml` was found, but its directory is too broad to use as a project root.
    #[snafu(display(
        "found {CONFIG_FILE_NAME} in {path}, but {path} is too broad to use as a project root: \
         it is {reason}. Move {CONFIG_FILE_NAME} into your actual project directory instead."
    ))]
    RootTooBroad {
        /// The rejected directory.
        path: CanonicalPath,
        /// Why it is too broad.
        reason: BroadRoot,
    },

    /// The config file or its directory belongs to someone else, or anyone can write it.
    ///
    /// A shared directory such as `/tmp` would otherwise let any local user, or a process
    /// confined in a hamster ball with write access there, plant a config that becomes
    /// the project root for everything below it.
    #[snafu(display(
        "the {subject} {} is {problem}; hb only uses a project that belongs to you and that \
         other users cannot write. Move the project into a directory you own, or fix it with \
         `chown` or `chmod o-w`.",
        path_preview(path)
    ))]
    Untrusted {
        /// The config file or directory.
        path: PathBuf,
        /// Which of the two it is.
        subject: Subject,
        /// What is wrong with it.
        problem: Untrusted,
    },

    /// A resolved path was not a usable canonical path.
    #[snafu(transparent)]
    Path {
        /// The underlying error.
        source: PathError,
    },
}

/// Finds the project root by walking up from `cwd`, and the `hamster-ball.toml` inside it.
///
/// Never falls back to `cwd` when nothing is found: see [`DiscoverError::NoProjectConfig`].
/// `cwd` itself is checked against the same breadth predicate as the discovered root, so
/// running `hb` directly in `$HOME` is refused immediately with an actionable message instead
/// of walking all the way to `/` first.
///
/// The discovered config file and root directory must belong to the real uid and must not be
/// writable by every user. Group write is allowed: macOS gives every user the shared `staff`
/// group and some users keep project trees group-writable on purpose. The approval hash is
/// the control for what the file says; this check is about who could have put it there.
///
/// # Errors
/// See [`DiscoverError`].
pub fn discover(cwd: &Path, home: &HomeDir) -> Result<Discovery, DiscoverError> {
    walk(cwd, home, getuid().as_raw(), None)
}

/// [`discover`] with the owner to trust and an optional directory at which to stop walking
/// up, so tests need neither another user nor an environment free of stray config files above
/// the temp directory.
fn walk(
    cwd: &Path,
    home: &HomeDir,
    uid: u32,
    ceiling: Option<&Path>,
) -> Result<Discovery, DiscoverError> {
    let canonical_cwd = fs::canonicalize(cwd).context(CwdUnreadableSnafu {
        path: cwd.to_path_buf(),
    })?;
    let start = CanonicalPath::from_canonical(canonical_cwd)?;

    if let Some(reason) = broadness(&start, home) {
        return CwdTooBroadSnafu {
            path: start,
            reason,
        }
        .fail();
    }

    let mut dir = start.as_path().to_path_buf();
    loop {
        let candidate = dir.join(CONFIG_FILE_NAME);
        match fs::symlink_metadata(&candidate) {
            Ok(metadata) if metadata.is_file() => {
                return found(&dir, candidate, &metadata, home, uid);
            }
            Ok(metadata) => {
                return ConfigNotARegularFileSnafu {
                    path: candidate,
                    kind: file_kind(&metadata),
                }
                .fail();
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Keep walking: a missing hamster-ball.toml here says nothing about an ancestor.
            }
            Err(error) => {
                return Err(error).context(ConfigUnreadableSnafu { path: candidate });
            }
        }

        let at_ceiling = ceiling.is_some_and(|ceiling| ceiling == dir);
        match dir.parent() {
            Some(parent) if !at_ceiling => dir = parent.to_path_buf(),
            _ => return NoProjectConfigSnafu { from: start }.fail(),
        }
    }
}

/// Accepts `dir` as the project root if it is not too broad and neither it nor its config
/// file is untrusted.
fn found(
    dir: &Path,
    config: PathBuf,
    config_metadata: &Metadata,
    home: &HomeDir,
    uid: u32,
) -> Result<Discovery, DiscoverError> {
    let root = match ProjectRoot::new(CanonicalPath::from_canonical(dir)?, home) {
        Ok(root) => root,
        Err(RootError::TooBroad { path, reason }) => {
            return RootTooBroadSnafu { path, reason }.fail();
        }
    };
    let dir_metadata = fs::metadata(dir).context(ConfigUnreadableSnafu {
        path: dir.to_path_buf(),
    })?;
    ensure_trusted(dir, Subject::ProjectDirectory, &dir_metadata, uid)?;
    ensure_trusted(&config, Subject::ConfigFile, config_metadata, uid)?;
    Ok(Discovery { root, config })
}

fn ensure_trusted(
    path: &Path,
    subject: Subject,
    metadata: &Metadata,
    uid: u32,
) -> Result<(), DiscoverError> {
    match untrusted(metadata.uid(), metadata.mode(), uid) {
        None => Ok(()),
        Some(problem) => UntrustedSnafu {
            path: path.to_path_buf(),
            subject,
            problem,
        }
        .fail(),
    }
}

/// Why a file with this owner and mode is not trusted by the user `uid`, if it is not.
pub(crate) fn untrusted(owner: u32, mode: u32, uid: u32) -> Option<Untrusted> {
    if owner != uid {
        Some(Untrusted::NotOwnedByYou)
    } else if mode & WORLD_WRITABLE != 0 {
        Some(Untrusted::WorldWritable)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ModeGuard, Tree, mkfifo};
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::fs as stdfs;
    use std::os::unix::fs::symlink;

    fn me() -> u32 {
        getuid().as_raw()
    }

    /// `walk` as the real user, stopping at the tree's base so a stray config file above the
    /// OS temp directory cannot change the result.
    fn discover_in(tree: &Tree, cwd: &Path) -> Result<Discovery, DiscoverError> {
        walk(cwd, tree.home(), me(), Some(tree.base()))
    }

    fn write_config(dir: &Path) {
        assert_ok!(stdfs::write(
            dir.join(CONFIG_FILE_NAME),
            b"fs.write = [\".\"]\n"
        ));
    }

    // ====================================================================================
    // Finds the config
    // ====================================================================================

    #[test]
    fn finds_config_in_cwd() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let discovery = assert_ok!(discover_in(&tree, &project));
        assert_eq!(discovery.root.path().as_path(), project);
        assert_eq!(discovery.config, project.join(CONFIG_FILE_NAME));
    }

    #[test]
    fn finds_config_in_ancestor_nearest_wins() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let nested = project.join("src").join("inner");
        assert_ok!(stdfs::create_dir_all(&nested));
        // A nearer config must win over the outer one.
        write_config(&project.join("src"));

        let discovery = assert_ok!(discover_in(&tree, &nested));
        assert_eq!(discovery.root.path().as_path(), project.join("src"));
    }

    #[test]
    fn finds_an_ancestor_config_from_a_deep_subdirectory() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let deep = project.join("a/b/c/d");
        assert_ok!(stdfs::create_dir_all(&deep));
        let discovery = assert_ok!(discover_in(&tree, &deep));
        assert_eq!(discovery.root.path().as_path(), project);
    }

    #[test]
    fn no_config_returns_no_project_config_naming_where_it_started() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        let err = assert_err!(discover_in(&tree, &project));
        assert!(
            matches!(&err, DiscoverError::NoProjectConfig { from } if from.as_path() == project),
            "{err:?}"
        );
    }

    #[test]
    fn no_project_config_error_tells_the_user_what_to_do() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        let shown = assert_err!(discover_in(&tree, &project)).to_string();
        assert!(shown.contains("create one"), "{shown:?}");
    }

    #[test]
    fn the_walk_checks_the_ceiling_itself_but_never_reads_above_it() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        let ceiling = tree.base().join("outside");
        // A config above the ceiling must not be found...
        write_config(tree.base());
        let err = assert_err!(walk(&project, tree.home(), me(), Some(&ceiling)));
        assert!(
            matches!(err, DiscoverError::NoProjectConfig { .. }),
            "{err:?}"
        );

        // ...but one in the ceiling directory itself is.
        write_config(&ceiling);
        let discovery = assert_ok!(walk(&project, tree.home(), me(), Some(&ceiling)));
        assert_eq!(discovery.root.path().as_path(), ceiling);
    }

    #[test]
    fn the_walk_terminates_at_the_filesystem_root() {
        // Environmental by nature: it walks the real ancestors of the OS temp directory. It
        // asserts only that the walk ends with a typed result (found, or no config) and never
        // loops or panics.
        let tree = Tree::new();
        let project = tree.outside("proj/deeply/nested/path");
        let result = discover(&project, tree.home());
        assert!(
            matches!(
                result,
                Ok(_)
                    | Err(DiscoverError::NoProjectConfig { .. }
                        | DiscoverError::RootTooBroad { .. }
                        | DiscoverError::Untrusted { .. })
            ),
            "{result:?}"
        );
    }

    // ====================================================================================
    // cwd breadth
    // ====================================================================================

    #[test]
    fn refuses_cwd_equal_to_home_even_with_a_toml_present() {
        let tree = Tree::new();
        write_config(tree.home_path());
        let err = assert_err!(discover_in(&tree, tree.home_path()));
        assert!(matches!(err, DiscoverError::CwdTooBroad { .. }), "{err:?}");
    }

    #[test]
    fn cwd_too_broad_error_tells_the_user_what_to_do() {
        let tree = Tree::new();
        let shown = assert_err!(discover_in(&tree, tree.home_path())).to_string();
        assert!(shown.contains("cd into your project"), "{shown:?}");
    }

    #[test]
    fn refuses_cwd_that_is_a_home_ancestor() {
        let tree = Tree::new();
        let err = assert_err!(discover_in(&tree, tree.base()));
        assert!(matches!(err, DiscoverError::CwdTooBroad { .. }), "{err:?}");
    }

    #[test]
    fn refuses_the_filesystem_root_and_a_top_level_system_directory_as_cwd() {
        let tree = Tree::new();
        for cwd in ["/", "/private", "/Users"] {
            let err = assert_err!(discover_in(&tree, Path::new(cwd)), "{cwd}");
            assert!(
                matches!(err, DiscoverError::CwdTooBroad { .. }),
                "{cwd}: {err:?}"
            );
        }
    }

    #[test]
    fn allows_cwd_inside_home() {
        let tree = Tree::new();
        let project = tree.inside_home("work/app");
        write_config(&project);
        let discovery = assert_ok!(discover_in(&tree, &project));
        assert_eq!(discovery.root.path().as_path(), project);
    }

    #[test]
    fn sibling_prefix_of_home_is_allowed() {
        let tree = Tree::new();
        let sibling = tree.base().join("home2").join("proj");
        assert_ok!(stdfs::create_dir_all(&sibling));
        write_config(&sibling);
        let discovery = assert_ok!(discover_in(&tree, &sibling));
        assert_eq!(discovery.root.path().as_path(), sibling);
    }

    #[test]
    fn refuses_root_in_home_when_cwd_is_subdir() {
        let tree = Tree::new();
        write_config(tree.home_path());
        let subdir = tree.inside_home("work/app");
        let err = assert_err!(discover_in(&tree, &subdir));
        assert!(matches!(err, DiscoverError::RootTooBroad { .. }), "{err:?}");
    }

    #[test]
    fn root_too_broad_error_tells_the_user_what_to_do() {
        let tree = Tree::new();
        write_config(tree.home_path());
        let subdir = tree.inside_home("work/app");
        let shown = assert_err!(discover_in(&tree, &subdir)).to_string();
        assert!(shown.contains("Move"), "{shown:?}");
    }

    #[test]
    fn symlinked_cwd_into_home_is_canonicalized_and_refused() {
        let tree = Tree::new();
        let link = tree.base().join("link-to-home");
        assert_ok!(symlink(tree.home_path(), &link));
        let err = assert_err!(discover_in(&tree, &link));
        assert!(matches!(err, DiscoverError::CwdTooBroad { .. }), "{err:?}");
    }

    // ====================================================================================
    // Fatal, not skip-and-keep-walking
    // ====================================================================================

    #[test]
    fn config_that_is_a_directory_is_fatal() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        assert_ok!(stdfs::create_dir_all(project.join(CONFIG_FILE_NAME)));
        let err = assert_err!(discover_in(&tree, &project));
        assert!(
            matches!(
                err,
                DiscoverError::ConfigNotARegularFile {
                    kind: "directory",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn config_that_is_a_symlink_is_fatal_even_when_it_points_at_a_regular_file() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        let real = tree.outside("elsewhere");
        assert_ok!(stdfs::write(real.join("real.toml"), b""));
        assert_ok!(symlink(
            real.join("real.toml"),
            project.join(CONFIG_FILE_NAME)
        ));
        let err = assert_err!(discover_in(&tree, &project));
        assert!(
            matches!(
                err,
                DiscoverError::ConfigNotARegularFile {
                    kind: "symlink",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn config_that_is_a_fifo_is_fatal_and_does_not_block() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        mkfifo(&project.join(CONFIG_FILE_NAME));
        let err = assert_err!(discover_in(&tree, &project));
        assert!(
            matches!(
                err,
                DiscoverError::ConfigNotARegularFile { kind: "fifo", .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn unreadable_dir_is_fatal_not_skipped_upward() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        let nested = project.join("nested");
        assert_ok!(stdfs::create_dir_all(&nested));
        // An outer config exists; if the permission error were skipped upward instead of
        // being fatal, the walk would wrongly find it.
        write_config(&project);
        let _guard = ModeGuard::set(&nested, 0o000);
        let err = assert_err!(discover_in(&tree, &nested));
        // The cwd itself cannot be canonicalized or listed; either way the outer config must
        // not be applied.
        assert!(
            matches!(
                err,
                DiscoverError::ConfigUnreadable { .. } | DiscoverError::CwdUnreadable { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn unreadable_ancestor_is_fatal_not_skipped_upward() {
        let tree = Tree::new();
        let outer = tree.outside("outer");
        write_config(&outer);
        let middle = outer.join("middle");
        let cwd = middle.join("cwd");
        assert_ok!(stdfs::create_dir_all(&cwd));
        // `middle` cannot be searched, so `middle/hamster-ball.toml` cannot be checked.
        let _guard = ModeGuard::set(&middle, 0o600);
        let err = assert_err!(discover_in(&tree, &cwd));
        assert!(
            matches!(
                err,
                DiscoverError::ConfigUnreadable { .. } | DiscoverError::CwdUnreadable { .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn deleted_cwd_is_a_typed_error() {
        let tree = Tree::new();
        let gone = tree.outside("proj").join("gone");
        let err = assert_err!(discover_in(&tree, &gone));
        assert!(
            matches!(err, DiscoverError::CwdUnreadable { .. }),
            "{err:?}"
        );
    }

    // ====================================================================================
    // Trust: owner and world-writable
    // ====================================================================================

    #[test]
    fn untrusted_classifies_owner_before_mode() {
        assert_eq!(untrusted(501, 0o644, 501), None);
        assert_eq!(untrusted(501, 0o664, 501), None, "group write is allowed");
        assert_eq!(untrusted(501, 0o666, 501), Some(Untrusted::WorldWritable));
        assert_eq!(untrusted(501, 0o1777, 501), Some(Untrusted::WorldWritable));
        assert_eq!(untrusted(0, 0o755, 501), Some(Untrusted::NotOwnedByYou));
        // The shape of /private/tmp: root-owned, world-writable and sticky.
        assert_eq!(untrusted(0, 0o41777, 501), Some(Untrusted::NotOwnedByYou));
    }

    #[test]
    fn a_project_owned_by_another_user_is_refused() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let err = assert_err!(walk(&project, tree.home(), me() + 1, Some(tree.base())));
        assert!(
            matches!(
                err,
                DiscoverError::Untrusted {
                    subject: Subject::ProjectDirectory,
                    problem: Untrusted::NotOwnedByYou,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_world_writable_project_directory_is_refused() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let _guard = ModeGuard::set(&project, 0o777);
        let err = assert_err!(discover_in(&tree, &project));
        assert!(
            matches!(
                err,
                DiscoverError::Untrusted {
                    subject: Subject::ProjectDirectory,
                    problem: Untrusted::WorldWritable,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_world_writable_config_file_is_refused() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let _guard = ModeGuard::set(&project.join(CONFIG_FILE_NAME), 0o666);
        let err = assert_err!(discover_in(&tree, &project));
        assert!(
            matches!(
                err,
                DiscoverError::Untrusted {
                    subject: Subject::ConfigFile,
                    problem: Untrusted::WorldWritable,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_group_writable_project_is_accepted() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let _dir = ModeGuard::set(&project, 0o775);
        let _file = ModeGuard::set(&project.join(CONFIG_FILE_NAME), 0o664);
        assert_ok!(discover_in(&tree, &project));
    }

    #[test]
    fn untrusted_error_names_the_subject_the_problem_and_the_fix() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        write_config(&project);
        let _guard = ModeGuard::set(&project, 0o777);
        let shown = assert_err!(discover_in(&tree, &project)).to_string();
        assert!(shown.contains("project directory"), "{shown:?}");
        assert!(shown.contains("writable by every user"), "{shown:?}");
        assert!(shown.contains("chmod o-w"), "{shown:?}");
    }

    #[test]
    fn breadth_is_checked_before_trust() {
        // A config in a too-broad directory is reported as too broad even if it is also
        // foreign-owned, because "move it" is the more useful advice.
        let tree = Tree::new();
        write_config(tree.home_path());
        let subdir = tree.inside_home("work/app");
        let err = assert_err!(walk(&subdir, tree.home(), me() + 1, Some(tree.base())));
        assert!(matches!(err, DiscoverError::RootTooBroad { .. }), "{err:?}");
    }

    // ====================================================================================
    // Error text
    // ====================================================================================

    #[test]
    fn discover_errors_follow_the_display_convention() {
        let tree = Tree::new();
        let project = tree.outside("proj");
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(discover_in(
            &tree, &project
        )));
        let gone = project.join("gone");
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(discover_in(
            &tree, &gone
        )));
    }

    #[test]
    fn subject_and_problem_have_phrase_displays() {
        assert_eq!(Subject::ConfigFile.to_string(), "config file");
        assert_eq!(Subject::ProjectDirectory.to_string(), "project directory");
        assert_eq!(
            Untrusted::NotOwnedByYou.to_string(),
            "owned by another user"
        );
        assert_eq!(
            Untrusted::WorldWritable.to_string(),
            "writable by every user"
        );
    }
}
