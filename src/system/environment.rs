// ABOUTME: Environment: everything `hb` reads from the process once (cwd, home, PATH, temp dir, own path).
// ABOUTME: Code below this layer takes an Environment, so tests supply a fixture and nothing re-reads the process.
//! The process environment, read once.
//!
//! The home directory comes from the passwd database ([`HomeDir::from_environment`]), not
//! `$HOME`. `PATH` is read here and handed to the floor builder as data; a hostile `PATH` can
//! only weaken the coverage derived from it, never move a fixed rule. `XDG_STATE_HOME` is kept
//! only so `hb explain` can say it was ignored (see [`crate::system::StateDir`]).

use std::env;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use snafu::{ResultExt, Snafu};

use super::floor::FloorEnvironment;
use super::home::HomeError;
use crate::policy::HomeDir;

/// Where `getconf` is on macOS; an absolute path, so `PATH` cannot substitute it.
const GETCONF: &str = "/usr/bin/getconf";

/// What `hb` knows about the process it runs in.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Environment {
    /// The current directory.
    pub cwd: PathBuf,
    /// The home directory, from the passwd database.
    pub home: HomeDir,
    /// What the floor builder reads: `PATH`, the temp directory and `hb`'s own path.
    pub floor: FloorEnvironment,
    /// `XDG_STATE_HOME`, which `hb` ignores.
    pub xdg_state_home: Option<OsString>,
}

/// Why the environment could not be read.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EnvironmentError {
    /// The home directory could not be established.
    #[snafu(display("the home directory could not be established"))]
    Home {
        /// The underlying error.
        source: HomeError,
    },

    /// The current directory could not be read.
    #[snafu(display("the current directory could not be read"))]
    Cwd {
        /// The underlying error.
        source: io::Error,
    },
}

impl Environment {
    /// An environment for `cwd` and `home` with nothing else set. For tests and for callers that
    /// fill the rest in.
    #[must_use]
    pub fn new(cwd: impl Into<PathBuf>, home: HomeDir) -> Self {
        Self {
            cwd: cwd.into(),
            home,
            floor: FloorEnvironment::new(),
            xdg_state_home: None,
        }
    }

    /// Reads the current process.
    ///
    /// # Errors
    /// [`EnvironmentError`] if the home directory cannot be established (including when `hb` is
    /// run as root, or `$HOME` disagrees with the passwd database) or the current directory is
    /// unreadable.
    pub fn from_process() -> Result<Self, EnvironmentError> {
        let home = HomeDir::from_environment().context(HomeSnafu)?;
        let cwd = env::current_dir().context(CwdSnafu)?;
        let mut floor = FloorEnvironment::new();
        floor.path_var = env::var_os("PATH");
        floor.hb_exe = env::current_exe().ok();
        floor.user_temp_dir = user_temp_dir();
        Ok(Self {
            cwd,
            home,
            floor,
            xdg_state_home: env::var_os("XDG_STATE_HOME"),
        })
    }
}

/// The per-user temporary directory, which macOS keeps under `/var/folders` and does not derive
/// from `$TMPDIR`.
///
/// Asks `getconf DARWIN_USER_TEMP_DIR` (the `confstr` value), because this crate forbids
/// `unsafe` and `nix` does not expose `confstr`. `None` if that fails.
fn user_temp_dir() -> Option<PathBuf> {
    let output = Command::new(GETCONF)
        .arg("DARWIN_USER_TEMP_DIR")
        .env_clear()
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let text = text.trim_end_matches(['\n', '/']);
    text.starts_with('/').then(|| PathBuf::from(text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;
    use pretty_assertions::assert_eq;

    #[test]
    fn a_new_environment_has_nothing_but_cwd_and_home() {
        let tree = Tree::new();
        let env = Environment::new(tree.home_path(), tree.home().clone());
        assert_eq!(env.cwd, tree.home_path());
        assert_eq!(env.floor, FloorEnvironment::new());
        assert_eq!(env.xdg_state_home, None);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn the_user_temp_dir_is_an_absolute_existing_directory_under_var_folders() {
        let dir = user_temp_dir();
        let dir = dir.as_deref().unwrap_or(std::path::Path::new("/missing"));
        assert!(
            dir.starts_with("/var/folders") || dir.starts_with("/private/var/folders"),
            "{dir:?}"
        );
        assert!(dir.is_dir());
        assert!(!dir.to_string_lossy().ends_with('/'));
    }
}
