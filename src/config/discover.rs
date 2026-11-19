// ABOUTME: discover() walks up from the current directory to find hamster-ball.toml, never falling back to the cwd.
// ABOUTME: Refuses a broad cwd or a broad discovered root, reusing the same predicate as fs.read/fs.write grants.
//! Finds the project root by walking up from the current directory, refusing to fall back to
//! the current directory when nothing is found, and refusing a root that is too broad.

use std::fs;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use snafu::{ResultExt, Snafu};

use crate::policy::{
    BroadRoot, CanonicalPath, HomeDir, PathError, ProjectRoot, RootError, broadness,
};
use crate::text::EscapedBounded;

/// The name of a project's config file, looked for in every ancestor of the current directory.
const CONFIG_FILE_NAME: &str = "hamster-ball.toml";

/// How much of a path is echoed in an error message.
const ERROR_PREVIEW_CHARS: usize = 200;

fn path_preview(path: &Path) -> EscapedBounded<'_> {
    EscapedBounded::new(
        path.to_str().unwrap_or("<non-UTF-8 path>"),
        ERROR_PREVIEW_CHARS,
    )
}

/// The project root [`discover`] found, and the `hamster-ball.toml` inside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The project root.
    pub root: ProjectRoot,
    /// The config file found inside it.
    pub config: PathBuf,
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
/// # Errors
/// See [`DiscoverError`].
pub fn discover(cwd: &Path, home: &HomeDir) -> Result<Discovery, DiscoverError> {
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
                let root_canonical = CanonicalPath::from_canonical(&dir)?;
                return match ProjectRoot::new(root_canonical, home) {
                    Ok(root) => Ok(Discovery {
                        root,
                        config: candidate,
                    }),
                    Err(RootError::TooBroad { path, reason }) => {
                        RootTooBroadSnafu { path, reason }.fail()
                    }
                };
            }
            Ok(metadata) => {
                return ConfigNotARegularFileSnafu {
                    path: candidate,
                    kind: classify(&metadata),
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

        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => return NoProjectConfigSnafu { from: start }.fail(),
        }
    }
}

/// What `symlink_metadata` found, when it was not a regular file.
fn classify(metadata: &fs::Metadata) -> &'static str {
    if metadata.is_symlink() {
        "symlink"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.file_type().is_fifo() {
        "fifo"
    } else if metadata.file_type().is_char_device() || metadata.file_type().is_block_device() {
        "device"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::fs as stdfs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    /// A throwaway `home` and `project` tree, so a test never touches the real filesystem
    /// outside it. `home` and `project` are siblings by default; call `nest` to make `project`
    /// a real descendant of `home` instead, for the tests that need that shape.
    struct Fixture {
        _dir: TempDir,
        home: HomeDir,
        home_path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = assert_ok!(TempDir::new());
            let home_path = dir.path().join("home");
            assert_ok!(stdfs::create_dir_all(&home_path));
            let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(assert_ok!(
                stdfs::canonicalize(&home_path)
            ))));
            Self {
                _dir: dir,
                home,
                home_path,
            }
        }

        fn home(&self) -> &HomeDir {
            &self.home
        }

        fn canonical_home_path(&self) -> PathBuf {
            assert_ok!(stdfs::canonicalize(&self.home_path))
        }

        /// A directory outside `home`, at `/tmp/<rand>/outside/<rel>`.
        fn outside(&self, rel: &str) -> PathBuf {
            let path = self._dir.path().join("outside").join(rel);
            assert_ok!(stdfs::create_dir_all(&path));
            path
        }

        /// A directory inside `home`, at `<home>/<rel>`.
        fn inside_home(&self, rel: &str) -> PathBuf {
            let path = self.home_path.join(rel);
            assert_ok!(stdfs::create_dir_all(&path));
            path
        }

        fn write_config(&self, dir: &Path) {
            assert_ok!(stdfs::write(
                dir.join(CONFIG_FILE_NAME),
                b"fs.write = [\".\"]\n"
            ));
        }
    }

    // ====================================================================================
    // Finds the config
    // ====================================================================================

    #[test]
    fn finds_config_in_cwd() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        fx.write_config(&project);
        let discovery = assert_ok!(discover(&project, fx.home()));
        assert_eq!(
            discovery.root.path().as_path(),
            assert_ok!(stdfs::canonicalize(&project))
        );
        assert_eq!(
            discovery.config,
            assert_ok!(stdfs::canonicalize(&project)).join(CONFIG_FILE_NAME)
        );
    }

    #[test]
    fn finds_config_in_ancestor_nearest_wins() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        fx.write_config(&project);
        let nested = assert_ok!({
            let path = project.join("src").join("inner");
            stdfs::create_dir_all(&path).map(|_| path)
        });
        // A second, nearer config must win over the outer one.
        let inner_config = project.join("src");
        fx.write_config(&inner_config);

        let discovery = assert_ok!(discover(&nested, fx.home()));
        assert_eq!(
            discovery.root.path().as_path(),
            assert_ok!(stdfs::canonicalize(&inner_config))
        );
    }

    #[test]
    fn no_config_returns_no_project_config() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        let err = assert_err!(discover(&project, fx.home()));
        assert!(
            matches!(err, DiscoverError::NoProjectConfig { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn no_project_config_error_tells_the_user_what_to_do() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        let shown = assert_err!(discover(&project, fx.home())).to_string();
        assert!(shown.contains("create one"), "{shown:?}");
    }

    // ====================================================================================
    // cwd breadth
    // ====================================================================================

    #[test]
    fn refuses_cwd_equal_to_home_even_with_a_toml_present() {
        let fx = Fixture::new();
        fx.write_config(&fx.canonical_home_path());
        let err = assert_err!(discover(&fx.home_path, fx.home()));
        assert!(matches!(err, DiscoverError::CwdTooBroad { .. }), "{err:?}");
    }

    #[test]
    fn cwd_too_broad_error_tells_the_user_what_to_do() {
        let fx = Fixture::new();
        let shown = assert_err!(discover(&fx.home_path, fx.home())).to_string();
        assert!(shown.contains("cd into your project"), "{shown:?}");
    }

    #[test]
    fn refuses_cwd_that_is_root_users_or_home_ancestor() {
        let fx = Fixture::new();
        let ancestor = assert_ok!(
            fx.home_path
                .parent()
                .map(Path::to_path_buf)
                .ok_or("no parent")
        );
        let err = assert_err!(discover(&ancestor, fx.home()));
        assert!(matches!(err, DiscoverError::CwdTooBroad { .. }), "{err:?}");
    }

    #[test]
    fn allows_cwd_inside_home() {
        let fx = Fixture::new();
        let project = fx.inside_home("work/app");
        fx.write_config(&project);
        let discovery = assert_ok!(discover(&project, fx.home()));
        assert_eq!(
            discovery.root.path().as_path(),
            assert_ok!(stdfs::canonicalize(&project))
        );
    }

    #[test]
    fn sibling_prefix_of_home_is_allowed() {
        let fx = Fixture::new();
        let sibling_name = format!(
            "{}2",
            assert_ok!(fx.home_path.file_name().ok_or("no name")).to_string_lossy()
        );
        let sibling = assert_ok!(fx.home_path.parent().ok_or("no parent"))
            .join(sibling_name)
            .join("proj");
        assert_ok!(stdfs::create_dir_all(&sibling));
        fx.write_config(&sibling);
        let discovery = assert_ok!(discover(&sibling, fx.home()));
        assert_eq!(
            discovery.root.path().as_path(),
            assert_ok!(stdfs::canonicalize(&sibling))
        );
    }

    #[test]
    fn refuses_root_in_home_when_cwd_is_subdir() {
        let fx = Fixture::new();
        fx.write_config(&fx.canonical_home_path());
        let subdir = fx.inside_home("work/app");
        let err = assert_err!(discover(&subdir, fx.home()));
        assert!(matches!(err, DiscoverError::RootTooBroad { .. }), "{err:?}");
    }

    #[test]
    fn root_too_broad_error_tells_the_user_what_to_do() {
        let fx = Fixture::new();
        fx.write_config(&fx.canonical_home_path());
        let subdir = fx.inside_home("work/app");
        let shown = assert_err!(discover(&subdir, fx.home())).to_string();
        assert!(shown.contains("Move"), "{shown:?}");
    }

    #[test]
    fn symlinked_cwd_into_home_is_canonicalized_and_refused() {
        let fx = Fixture::new();
        let link = fx._dir.path().join("link-to-home");
        assert_ok!(symlink(&fx.home_path, &link));
        let err = assert_err!(discover(&link, fx.home()));
        assert!(matches!(err, DiscoverError::CwdTooBroad { .. }), "{err:?}");
    }

    // ====================================================================================
    // Fatal, not skip-and-keep-walking
    // ====================================================================================

    #[test]
    fn config_that_is_a_directory_is_fatal() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        assert_ok!(stdfs::create_dir_all(project.join(CONFIG_FILE_NAME)));
        let err = assert_err!(discover(&project, fx.home()));
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
    fn config_that_is_a_fifo_is_fatal_and_does_not_block() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        let status = assert_ok!(
            std::process::Command::new("mkfifo")
                .arg(project.join(CONFIG_FILE_NAME))
                .status()
        );
        assert!(status.success(), "mkfifo failed: {status:?}");
        let err = assert_err!(discover(&project, fx.home()));
        assert!(
            matches!(
                err,
                DiscoverError::ConfigNotARegularFile { kind: "fifo", .. }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn discover_errors_follow_the_display_convention() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(discover(
            &project,
            fx.home()
        )));
        let gone = project.join("gone");
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(discover(
            &gone,
            fx.home()
        )));
    }

    #[test]
    fn config_that_is_a_symlink_is_fatal() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        let real = fx.outside("elsewhere");
        assert_ok!(stdfs::write(real.join("real.toml"), b""));
        assert_ok!(symlink(
            real.join("real.toml"),
            project.join(CONFIG_FILE_NAME)
        ));
        let err = assert_err!(discover(&project, fx.home()));
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
    fn unreadable_dir_is_fatal_not_skipped_upward() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        let nested = project.join("nested");
        assert_ok!(stdfs::create_dir_all(&nested));
        // An outer config exists; if the permission error were skipped upward instead of being
        // fatal, this test would wrongly "succeed" by finding it.
        fx.write_config(&project);
        assert_ok!(stdfs::set_permissions(
            &nested,
            stdfs::Permissions::from_mode(0o000)
        ));
        let result = discover(&nested, fx.home());
        assert_ok!(stdfs::set_permissions(
            &nested,
            stdfs::Permissions::from_mode(0o755)
        ));
        let err = assert_err!(result);
        assert!(
            matches!(err, DiscoverError::ConfigUnreadable { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn deleted_cwd_is_a_typed_error() {
        let fx = Fixture::new();
        let project = fx.outside("proj");
        let gone = project.join("gone");
        assert_ok!(stdfs::create_dir_all(&gone));
        assert_ok!(stdfs::remove_dir(&gone));
        let err = assert_err!(discover(&gone, fx.home()));
        assert!(
            matches!(err, DiscoverError::CwdUnreadable { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn walk_stops_at_the_filesystem_root() {
        // No config anywhere under a throwaway tree; the walk must terminate at "/" with
        // NoProjectConfig rather than looping or panicking.
        let fx = Fixture::new();
        let project = fx.outside("proj/deeply/nested/path");
        let err = assert_err!(discover(&project, fx.home()));
        assert!(
            matches!(err, DiscoverError::NoProjectConfig { .. }),
            "{err:?}"
        );
    }
}
