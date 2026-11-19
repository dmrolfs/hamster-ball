// ABOUTME: HomeDir::from_environment: the home directory from the passwd database, cross-checked against $HOME.
// ABOUTME: Also the root refusal; the only code that reads the passwd database and the HOME variable.
//! Establishing the home directory from the operating system.
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

use crate::policy::{CanonicalPath, HomeDir, PathError};

impl HomeDir {
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
        Self::from_uid_and_env(getuid(), env::var_os("HOME").as_deref())
    }

    /// [`HomeDir::from_environment`] with the uid and `$HOME` passed in, so a test can use the
    /// real passwd database with a crafted `$HOME` without touching the process environment.
    fn from_uid_and_env(uid: Uid, home_env: Option<&OsStr>) -> Result<Self, HomeError> {
        refuse_if_root(uid)?;

        let user = User::from_uid(uid)
            .context(PasswdLookupFailedSnafu { uid: uid.as_raw() })?
            .context(NoPasswdEntrySnafu { uid: uid.as_raw() })?;

        let canonical_dir = fs::canonicalize(&user.dir).context(PasswdHomeUnresolvableSnafu {
            path: user.dir.clone(),
        })?;
        let passwd_home = CanonicalPath::from_canonical(canonical_dir)?;

        home_matches_env(&passwd_home, home_env)?;
        Ok(Self::new(passwd_home))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::path::Path;

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

    #[test]
    fn home_from_passwd_ignores_unset_home() {
        let tree = Tree::new();
        let passwd_home = tree.home().path().clone();
        assert_ok!(home_matches_env(&passwd_home, None));
    }

    #[test]
    fn home_from_passwd_rejects_mismatching_home_env() {
        let tree = Tree::new();
        let passwd_home = tree.home().path().clone();
        let other = tree.outside("other");
        let err = assert_err!(home_matches_env(&passwd_home, Some(other.as_os_str())));
        assert!(matches!(err, HomeError::Mismatch { .. }), "{err:?}");
    }

    #[test]
    fn home_from_passwd_rejects_a_poisoned_home_env_rather_than_treating_it_as_unset() {
        let tree = Tree::new();
        let passwd_home = tree.home().path().clone();
        let poisoned = OsStr::new("/this-path-does-not-exist-hb-test-xyz");
        let err = assert_err!(home_matches_env(&passwd_home, Some(poisoned)));
        assert!(matches!(err, HomeError::Mismatch { .. }), "{err:?}");
    }

    #[test]
    fn home_trailing_slash_and_symlink_forms_compare_equal() {
        let tree = Tree::new();
        let passwd_home = tree.home().path().clone();

        let trailing_slash = format!("{}/", passwd_home.as_str());
        assert_ok!(home_matches_env(
            &passwd_home,
            Some(OsStr::new(&trailing_slash))
        ));

        let link = tree.outside("links").join("home-link");
        assert_ok!(std::os::unix::fs::symlink(passwd_home.as_path(), &link));
        assert_ok!(home_matches_env(&passwd_home, Some(link.as_os_str())));
    }

    // ====================================================================================
    // from_uid_and_env: the real passwd database with an injected $HOME
    // ====================================================================================

    /// A uid no real account has. (Not `u32::MAX - 1`: macOS maps that to `nobody`.)
    const UNASSIGNED_UID: u32 = 987_654_321;

    /// The current user's passwd home, derived here independently of the code under test.
    fn passwd_home_of_current_user() -> Option<CanonicalPath> {
        let user = assert_ok!(User::from_uid(getuid()));
        let dir = assert_ok!(fs::canonicalize(assert_some!(user).dir));
        Some(assert_ok!(CanonicalPath::from_canonical(dir)))
    }

    #[test]
    fn from_uid_and_env_uses_the_passwd_home_when_home_is_unset() {
        if getuid().is_root() {
            let err = assert_err!(HomeDir::from_uid_and_env(getuid(), None));
            assert!(matches!(err, HomeError::RunningAsRoot), "{err:?}");
            return;
        }
        let home = assert_ok!(HomeDir::from_uid_and_env(getuid(), None));
        assert_eq!(Some(home.path().clone()), passwd_home_of_current_user());
    }

    #[test]
    fn from_uid_and_env_accepts_a_home_that_agrees_with_passwd() {
        if getuid().is_root() {
            return;
        }
        let expected = assert_some!(passwd_home_of_current_user());
        let with_slash = format!("{}/", expected.as_str());
        let home = assert_ok!(HomeDir::from_uid_and_env(
            getuid(),
            Some(OsStr::new(&with_slash))
        ));
        assert_eq!(home.path(), &expected);
    }

    #[test]
    fn from_uid_and_env_rejects_a_poisoned_home() {
        if getuid().is_root() {
            return;
        }
        let err = assert_err!(HomeDir::from_uid_and_env(
            getuid(),
            Some(OsStr::new("/tmp/hb-poisoned-home-that-does-not-exist"))
        ));
        assert!(
            matches!(&err, HomeError::Mismatch { env, .. } if env == Path::new("/tmp/hb-poisoned-home-that-does-not-exist")),
            "{err:?}"
        );
    }

    #[test]
    fn from_uid_and_env_refuses_root_before_it_compares_anything() {
        // Root has a passwd entry whose home (`/var/root`) disagrees with this HOME. If the
        // comparison ran first, this would be a confusing `Mismatch`, not `RunningAsRoot`.
        let err = assert_err!(HomeDir::from_uid_and_env(
            Uid::from_raw(0),
            Some(OsStr::new("/Users/someone-else"))
        ));
        assert!(matches!(err, HomeError::RunningAsRoot), "{err:?}");
    }

    #[test]
    fn from_uid_and_env_reports_a_uid_with_no_passwd_entry() {
        let err = assert_err!(HomeDir::from_uid_and_env(
            Uid::from_raw(UNASSIGNED_UID),
            None
        ));
        assert!(
            matches!(err, HomeError::NoPasswdEntry { uid } if uid == UNASSIGNED_UID),
            "{err:?}"
        );
    }

    #[test]
    fn home_errors_follow_the_display_convention() {
        let tree = Tree::new();
        let passwd_home = tree.home().path().clone();
        let other = tree.outside("other");
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(home_matches_env(
            &passwd_home,
            Some(other.as_os_str())
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
        let tree = Tree::new();
        let passwd_home = tree.home().path().clone();
        let other = tree.outside("other");
        let shown =
            assert_err!(home_matches_env(&passwd_home, Some(other.as_os_str()))).to_string();
        assert!(shown.contains("$HOME"), "{shown:?}");
        assert!(shown.contains(passwd_home.as_str()), "{shown:?}");
    }
}
