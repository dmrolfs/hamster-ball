// ABOUTME: HomeDir, ProjectRoot and the single "too broad" predicate that guards roots and read/write grants.
// ABOUTME: Mostly pure; HomeDir::from_environment is the one constructor that reads the passwd database and $HOME.
//! Home directory, project root, and the rule for what is too broad to grant.
//!
//! # Verified and unverified setups for [`HomeDir::from_environment`]
//!
//! Checked on a developer macOS machine: a normal shell, a launchd job, `env -i`, a
//! trailing-slash `HOME`, and a poisoned `HOME` all give the expected result (the passwd
//! entry is unaffected by `HOME`).
//!
//! **Not tested:** `sudo -E` (needs a password; reasoned instead: root's passwd home is
//! `/var/root` while `HOME` stays the invoking user's, which is why `hb` refuses uid 0 before
//! any comparison) and nix `--pure` shells (could not be built offline).

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::PathBuf;

use nix::errno::Errno;
use nix::unistd::{Uid, User, getuid};
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use strum::Display;

use super::path::{CanonicalPath, PathError};

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
/// refusing a mismatch with `$HOME`, is [`HomeDir::from_environment`]'s job.
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

    /// Establishes the home directory from the OS's own passwd entry for the real uid,
    /// cross-checked against `$HOME`.
    ///
    /// The floor (section 6 of the design doc) is built from this value, not from `$HOME`
    /// directly: `$HOME` is just an environment variable any launcher can set, and trusting it
    /// would let `HOME=/tmp/x hb …` silently relocate every floor rule. `$HOME` being unset is
    /// fine; the passwd entry wins. `$HOME` disagreeing with the passwd entry is a hard error,
    /// not a choice of one over the other, because there is no safe way to guess which one the
    /// user meant. `hb` also refuses to run as uid 0 before any of this, because under
    /// `sudo -E` the passwd entry (`/var/root`) and `$HOME` (the invoking user's) would
    /// otherwise disagree for a reason that has nothing to do with a real misconfiguration.
    ///
    /// The only production constructor that reads the environment; tests inject a `HomeDir`
    /// via [`HomeDir::new`] instead.
    ///
    /// # Errors
    /// See [`HomeError`].
    pub fn from_environment() -> Result<Self, HomeError> {
        let uid = getuid();
        refuse_if_root(uid)?;

        let user = User::from_uid(uid)
            .context(PasswdLookupFailedSnafu { uid: uid.as_raw() })?
            .context(NoPasswdEntrySnafu { uid: uid.as_raw() })?;

        let canonical_dir = fs::canonicalize(&user.dir).context(PasswdHomeUnresolvableSnafu {
            path: user.dir.clone(),
        })?;
        let passwd_home = CanonicalPath::from_canonical(canonical_dir)?;

        home_matches_env(&passwd_home, env::var_os("HOME").as_deref())?;
        Ok(Self(passwd_home))
    }
}

/// Why `hb` refuses to continue, or why [`HomeDir::from_environment`] could not establish a
/// trustworthy home directory.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HomeError {
    /// `hb` was started as uid 0.
    #[snafu(display(
        "hb refuses to run as root: the floor denies root's own sensitive paths the same way \
         it denies any other user's, and `sudo -E` leaves $HOME set to your normal account \
         while root's own passwd entry says /var/root, which would otherwise look like a \
         confusing mismatch rather than what it is. Run hb as your normal user instead."
    ))]
    RunningAsRoot,

    /// The passwd database has no entry for the running user.
    #[snafu(display("no passwd entry exists for uid {uid}"))]
    NoPasswdEntry {
        /// The uid that was looked up.
        uid: u32,
    },

    /// The passwd lookup itself failed.
    #[snafu(display("could not read the passwd database for uid {uid}"))]
    PasswdLookupFailed {
        /// The uid that was looked up.
        uid: u32,
        /// The underlying error.
        source: Errno,
    },

    /// The passwd entry's home directory could not be resolved on disk.
    #[snafu(display(
        "the passwd entry's home directory, {}, could not be resolved",
        crate::text::EscapedBounded::new(&path.to_string_lossy(), 200)
    ))]
    PasswdHomeUnresolvable {
        /// The passwd entry's home directory, as reported by the passwd database.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// `$HOME` disagrees with the passwd database's home directory.
    #[snafu(display(
        "$HOME ({}) disagrees with the passwd database's home directory ({passwd}); hb refuses \
         to guess which one is right",
        crate::text::EscapedBounded::new(&env.to_string_lossy(), 200)
    ))]
    Mismatch {
        /// The home directory from the passwd database.
        passwd: CanonicalPath,
        /// The value `$HOME` was set to, verbatim, even if it could not itself be resolved.
        env: PathBuf,
    },

    /// The passwd entry's home directory, once resolved, was not a usable canonical path.
    #[snafu(transparent)]
    Path {
        /// The underlying error.
        source: PathError,
    },
}

/// Refuses to continue if `uid` is root.
///
/// Pulled out of [`HomeDir::from_environment`] so a test can exercise this check without
/// actually running the test process as root.
fn refuse_if_root(uid: Uid) -> Result<(), HomeError> {
    ensure!(!uid.is_root(), RunningAsRootSnafu);
    Ok(())
}

/// Checks `home_env` (the raw `$HOME` value, if set) against `passwd_home`.
///
/// Pulled out of [`HomeDir::from_environment`] so a test can exercise the comparison --
/// including trailing-slash and symlink normalization -- against an injected, throwaway
/// `passwd_home` instead of the real passwd database and the real `$HOME`.
fn home_matches_env(
    passwd_home: &CanonicalPath,
    home_env: Option<&OsStr>,
) -> Result<(), HomeError> {
    let Some(home_env) = home_env else {
        return Ok(());
    };
    let home_env_path = PathBuf::from(home_env);
    let matches = fs::canonicalize(&home_env_path)
        .is_ok_and(|canonical| canonical.as_path() == passwd_home.as_path());
    if matches {
        Ok(())
    } else {
        MismatchSnafu {
            passwd: passwd_home.clone(),
            env: home_env_path,
        }
        .fail()
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

    // ====================================================================================
    // refuse_if_root
    //
    // A unit test of the check, not a real root run: `refuse_if_root` takes a `Uid` instead of
    // calling `getuid()` itself, exactly so this does not need to run as root to exercise.
    // ====================================================================================

    #[test]
    fn refuses_to_run_as_root() {
        let err = assert_err!(refuse_if_root(Uid::from_raw(0)));
        assert!(matches!(err, HomeError::RunningAsRoot));
    }

    #[test]
    fn allows_a_non_root_uid() {
        assert_ok!(refuse_if_root(Uid::from_raw(502)));
    }

    #[test]
    fn running_as_root_error_explains_why() {
        let shown = assert_err!(refuse_if_root(Uid::from_raw(0))).to_string();
        assert!(shown.contains("root"), "{shown:?}");
    }

    // ====================================================================================
    // home_matches_env
    //
    // Exercises the exact comparison `HomeDir::from_environment` uses, against an injected,
    // throwaway `passwd_home` and a crafted `$HOME` value -- never the real passwd database or
    // the real `$HOME`, so these tests are hermetic and can run in parallel with everything else.
    // ====================================================================================

    struct EnvFixture {
        _dir: tempfile::TempDir,
        passwd_home: CanonicalPath,
    }

    impl EnvFixture {
        fn new() -> Self {
            let dir = assert_ok!(tempfile::TempDir::new());
            let passwd_home = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
                fs::canonicalize(dir.path())
            )));
            Self {
                _dir: dir,
                passwd_home,
            }
        }
    }

    #[test]
    fn home_from_passwd_ignores_unset_home() {
        let fx = EnvFixture::new();
        assert_ok!(home_matches_env(&fx.passwd_home, None));
    }

    #[test]
    fn home_from_passwd_rejects_mismatching_home_env() {
        let fx = EnvFixture::new();
        let other = assert_ok!(tempfile::TempDir::new());
        let err = assert_err!(home_matches_env(
            &fx.passwd_home,
            Some(other.path().as_os_str())
        ));
        assert!(matches!(err, HomeError::Mismatch { .. }), "{err:?}");
    }

    #[test]
    fn home_from_passwd_rejects_a_poisoned_home_env_rather_than_treating_it_as_unset() {
        let fx = EnvFixture::new();
        let poisoned = std::ffi::OsStr::new("/this-path-does-not-exist-hb-test-xyz");
        let err = assert_err!(home_matches_env(&fx.passwd_home, Some(poisoned)));
        assert!(matches!(err, HomeError::Mismatch { .. }), "{err:?}");
    }

    #[test]
    fn home_trailing_slash_and_symlink_forms_compare_equal() {
        let fx = EnvFixture::new();

        let trailing_slash = format!("{}/", fx.passwd_home.as_str());
        assert_ok!(home_matches_env(
            &fx.passwd_home,
            Some(std::ffi::OsStr::new(&trailing_slash))
        ));

        let symlink_dir = assert_ok!(tempfile::TempDir::new());
        let link = symlink_dir.path().join("home-link");
        assert_ok!(std::os::unix::fs::symlink(fx.passwd_home.as_path(), &link));
        assert_ok!(home_matches_env(&fx.passwd_home, Some(link.as_os_str())));
    }

    #[test]
    fn home_errors_follow_the_display_convention() {
        let fx = EnvFixture::new();
        let other = assert_ok!(tempfile::TempDir::new());
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(home_matches_env(
            &fx.passwd_home,
            Some(other.path().as_os_str())
        )));
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(refuse_if_root(
            Uid::from_raw(0)
        )));
        let unresolvable = HomeError::PasswdHomeUnresolvable {
            path: PathBuf::from("/nope"),
            source: io::Error::from(io::ErrorKind::NotFound),
        };
        crate::error::conventions::assert_display_excludes_sources(&unresolvable);
    }

    #[test]
    fn mismatch_error_names_both_paths_and_explains_the_refusal() {
        let fx = EnvFixture::new();
        let other = assert_ok!(tempfile::TempDir::new());
        let shown = assert_err!(home_matches_env(
            &fx.passwd_home,
            Some(other.path().as_os_str())
        ))
        .to_string();
        assert!(shown.contains("$HOME"), "{shown:?}");
        assert!(shown.contains(fx.passwd_home.as_str()), "{shown:?}");
    }
}
