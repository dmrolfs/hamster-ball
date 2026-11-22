// ABOUTME: SessionDir: the run's private 0700 directory, removed on drop, plus a sweep of dirs a killed hb left behind.
// ABOUTME: Names are hb-<pid>-<nanos>-<counter>; the sweep removes only such names owned by us whose pid is dead.
//! The per-run directory (design 7.2, 7.4).
//!
//! It holds what a run needs to share with its child and nothing else: later the proxy socket,
//! the CA bundle and hook output. It is created under the canonical per-user temporary
//! directory, because Seatbelt matches resolved paths, and mode 0700 so no other user can reach it.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::{Pid, geteuid};
use snafu::{ResultExt, Snafu};

use crate::policy::{CanonicalPath, PathError};

/// Name prefix of every session directory.
const PREFIX: &str = "hb-";
/// Attempts at a free name before giving up.
const NAME_ATTEMPTS: u32 = 16;
static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Why the session directory could not be created.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SessionDirError {
    /// The directory could not be created.
    #[snafu(display("the session directory could not be created in {parent}"))]
    Create {
        /// The temporary directory it was to be created in.
        parent: String,
        /// The underlying error.
        source: io::Error,
    },

    /// Every name tried was already taken.
    #[snafu(display("no free session directory name in {parent} after {attempts} attempts"))]
    NoFreeName {
        /// The temporary directory.
        parent: String,
        /// How many names were tried.
        attempts: u32,
    },

    /// The directory's path is not a clean canonical path.
    #[snafu(display("the session directory path is not usable"))]
    NotCanonical {
        /// The underlying error.
        source: PathError,
    },
}

/// A run's private directory. Removed, with everything in it, when dropped.
#[derive(Debug)]
pub struct SessionDir {
    path: CanonicalPath,
}

impl SessionDir {
    /// Creates a new 0700 directory under `parent`.
    ///
    /// # Errors
    /// [`SessionDirError`] if `parent` is not writable or no name is free.
    pub fn create(parent: &CanonicalPath) -> Result<Self, SessionDirError> {
        Self::create_named(parent, fresh_name)
    }

    /// [`SessionDir::create`] with the names supplied by `next_name`, so a collision can be tested.
    fn create_named(
        parent: &CanonicalPath,
        mut next_name: impl FnMut() -> String,
    ) -> Result<Self, SessionDirError> {
        for _ in 0..NAME_ATTEMPTS {
            let candidate = parent.as_path().join(next_name());
            match DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => {
                    let path =
                        CanonicalPath::from_canonical(&candidate).context(NotCanonicalSnafu)?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(source).context(CreateSnafu {
                        parent: parent.as_str().to_owned(),
                    });
                }
            }
        }
        NoFreeNameSnafu {
            parent: parent.as_str().to_owned(),
            attempts: NAME_ATTEMPTS,
        }
        .fail()
    }

    /// The directory.
    #[must_use]
    pub fn path(&self) -> &CanonicalPath {
        &self.path
    }
}

impl Drop for SessionDir {
    fn drop(&mut self) {
        // Best effort: a child may have left a directory it made unreadable. The next start's
        // sweep tries again once this process is gone.
        let _ = fs::remove_dir_all(self.path.as_path());
    }
}

fn fresh_name() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{PREFIX}{}-{nanos}-{counter}", std::process::id())
}

/// What a sweep did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SweepReport {
    /// Directories removed.
    pub removed: usize,
    /// Session directories left alone because their process is alive or they are not ours.
    pub kept: usize,
    /// Directories that could not be removed.
    pub failed: usize,
}

/// Removes session directories under `parent` that a dead `hb` left behind.
///
/// Only a real directory (never a symlink) owned by this user, named exactly
/// `hb-<pid>-<nanos>-<counter>`, whose pid is no longer running. A pid that was reused by
/// another process makes its directory look alive, which is the safe side.
pub fn sweep_stale(parent: &Path) -> SweepReport {
    let mut report = SweepReport::default();
    let Ok(entries) = fs::read_dir(parent) else {
        return report;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(owner_pid) else {
            continue;
        };
        let path: PathBuf = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if !meta.is_dir() || meta.uid() != geteuid().as_raw() || is_alive(pid) {
            report.kept += 1;
            continue;
        }
        match fs::remove_dir_all(&path) {
            Ok(()) => report.removed += 1,
            Err(_) => report.failed += 1,
        }
    }
    report
}

/// The pid in `hb-<pid>-<nanos>-<counter>`, or `None` if `name` is not of that exact form.
fn owner_pid(name: &str) -> Option<i32> {
    let rest = name.strip_prefix(PREFIX)?;
    let mut parts = rest.split('-');
    let (pid, nanos, counter) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() {
        return None;
    }
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    if !(digits(pid) && digits(nanos) && digits(counter)) {
        return None;
    }
    pid.parse().ok().filter(|p| *p > 0)
}

/// Whether a process with this pid exists. `EPERM` means it exists but is not ours.
fn is_alive(pid: i32) -> bool {
    match kill(Pid::from_raw(pid), None) {
        Ok(()) | Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;
    use tempfile::TempDir;

    fn parent() -> (TempDir, CanonicalPath) {
        let dir = assert_ok!(TempDir::new());
        let real = assert_ok!(fs::canonicalize(dir.path()));
        let parent = assert_ok!(CanonicalPath::from_canonical(real));
        (dir, parent)
    }

    /// A pid that has just exited and been reaped.
    fn dead_pid() -> u32 {
        let mut child = assert_ok!(Command::new("/usr/bin/true").spawn());
        let pid = child.id();
        assert_ok!(child.wait());
        pid
    }

    fn mkdir(path: &Path) {
        assert_ok!(fs::create_dir_all(path));
    }

    #[test]
    fn a_session_dir_is_0700_inside_the_parent_and_named_with_this_pid() {
        let (_guard, parent) = parent();
        let dir = assert_ok!(SessionDir::create(&parent));
        let path = dir.path().as_path();
        assert_eq!(path.parent(), Some(parent.as_path()));
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        assert_eq!(owner_pid(name), i32::try_from(std::process::id()).ok());
        let mode = assert_ok!(fs::metadata(path)).permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn a_taken_name_is_skipped_and_the_next_one_is_used() {
        let (_guard, parent) = parent();
        mkdir(&parent.as_path().join("hb-1-1-1"));
        let mut names = ["hb-1-1-1", "hb-1-1-2"].into_iter();
        let dir = assert_ok!(SessionDir::create_named(&parent, || names
            .next()
            .unwrap_or("hb-9-9-9")
            .to_owned()));
        assert_eq!(dir.path().as_path(), parent.as_path().join("hb-1-1-2"));
    }

    #[test]
    fn running_out_of_free_names_is_a_typed_error_after_the_attempt_limit() {
        let (_guard, parent) = parent();
        mkdir(&parent.as_path().join("hb-1-1-1"));
        let mut tried = 0;
        let err = assert_err!(SessionDir::create_named(&parent, || {
            tried += 1;
            "hb-1-1-1".to_owned()
        }));
        assert!(
            matches!(err, SessionDirError::NoFreeName { attempts, .. } if attempts == NAME_ATTEMPTS),
            "{err}"
        );
        assert_eq!(tried, NAME_ATTEMPTS);
    }

    #[test]
    fn a_stale_directory_that_cannot_be_removed_is_counted_as_failed_not_removed() {
        let (_guard, parent) = parent();
        let stale = parent.as_path().join(format!("hb-{}-1-1", dead_pid()));
        let locked = stale.join("locked");
        mkdir(&locked.join("inner"));
        assert_ok!(fs::set_permissions(
            &locked,
            fs::Permissions::from_mode(0o000)
        ));
        let report = sweep_stale(parent.as_path());
        // Restore access first so the temporary directory can be cleaned up whatever happens.
        assert_ok!(fs::set_permissions(
            &locked,
            fs::Permissions::from_mode(0o700)
        ));
        assert_eq!(
            report,
            SweepReport {
                removed: 0,
                kept: 0,
                failed: 1
            }
        );
    }

    #[test]
    fn two_session_dirs_never_share_a_name() {
        let (_guard, parent) = parent();
        let a = assert_ok!(SessionDir::create(&parent));
        let b = assert_ok!(SessionDir::create(&parent));
        assert!(a.path() != b.path());
    }

    #[test]
    fn dropping_removes_the_directory_and_everything_in_it() {
        let (_guard, parent) = parent();
        let dir = assert_ok!(SessionDir::create(&parent));
        let path = dir.path().as_path().to_path_buf();
        mkdir(&path.join("a/b"));
        assert_ok!(fs::write(path.join("a/b/file"), "x"));
        drop(dir);
        assert!(!path.exists());
    }

    #[test]
    fn a_panic_still_removes_the_directory() {
        let (_guard, parent) = parent();
        let seen = std::sync::Mutex::new(PathBuf::new());
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let dir = assert_ok!(SessionDir::create(&parent));
            if let Ok(mut slot) = seen.lock() {
                *slot = dir.path().as_path().to_path_buf();
            }
            std::panic::resume_unwind(Box::new("boom"));
        }));
        assert!(result.is_err());
        let path = assert_ok!(seen.lock()).clone();
        assert!(!path.as_os_str().is_empty() && !path.exists());
    }

    #[test]
    fn a_missing_parent_is_a_typed_error_that_does_not_echo_the_io_error() {
        let (guard, parent) = parent();
        let gone = parent.as_path().join("nowhere");
        let gone = CanonicalPath::from_canonical(&gone);
        // `from_canonical` only checks the text, so a path that does not exist is accepted.
        let gone = assert_ok!(gone);
        let err = assert_err!(SessionDir::create(&gone));
        assert!(matches!(err, SessionDirError::Create { .. }), "{err}");
        crate::error::conventions::assert_display_excludes_sources(&err);
        drop(guard);
    }

    #[test]
    fn the_sweep_removes_a_dead_pids_directory_and_keeps_a_live_ones() {
        let (_guard, parent) = parent();
        let stale = parent.as_path().join(format!("hb-{}-1-1", dead_pid()));
        mkdir(&stale.join("inner"));
        let live = assert_ok!(SessionDir::create(&parent));
        let report = sweep_stale(parent.as_path());
        assert_eq!(report.removed, 1);
        assert_eq!(report.kept, 1);
        assert!(!stale.exists());
        assert!(live.path().as_path().exists());
    }

    #[test]
    fn the_sweep_ignores_names_that_are_not_exactly_a_session_dir_name() {
        let (_guard, parent) = parent();
        let dead = dead_pid();
        let names = [
            format!("hb-{dead}"),
            format!("hb-{dead}-1"),
            format!("hb-{dead}-1-1-1"),
            format!("hb-{dead}-x-1"),
            format!("hbx-{dead}-1-1"),
            format!("HB-{dead}-1-1"),
            "hb--1-1".to_owned(),
            "hb-0-1-1".to_owned(),
            "notes".to_owned(),
        ];
        for name in &names {
            mkdir(&parent.as_path().join(name));
        }
        let report = sweep_stale(parent.as_path());
        assert_eq!(report, SweepReport::default());
        for name in &names {
            assert!(parent.as_path().join(name).exists(), "{name} was removed");
        }
    }

    #[test]
    fn the_sweep_never_follows_or_removes_a_symlink_or_a_plain_file() {
        let (_guard, parent) = parent();
        let victim = parent.as_path().join("victim");
        mkdir(&victim);
        assert_ok!(fs::write(victim.join("keep"), "x"));
        let link = parent.as_path().join(format!("hb-{}-1-1", dead_pid()));
        assert_ok!(symlink(&victim, &link));
        let file = parent.as_path().join(format!("hb-{}-2-2", dead_pid()));
        assert_ok!(fs::write(&file, "x"));
        let report = sweep_stale(parent.as_path());
        assert_eq!(report.removed, 0);
        assert!(victim.join("keep").exists());
        assert!(fs::symlink_metadata(&link).is_ok());
        assert!(file.exists());
    }

    #[test]
    fn the_sweep_of_a_missing_directory_does_nothing() {
        let (_guard, parent) = parent();
        let report = sweep_stale(&parent.as_path().join("nowhere"));
        assert_eq!(report, SweepReport::default());
    }

    #[test]
    fn owner_pid_parses_only_the_exact_form() {
        assert_eq!(owner_pid("hb-123-456-7"), Some(123));
        for bad in [
            "hb-123-456",
            "hb-123-456-7-8",
            "hb-a-1-1",
            "hb-0-1-1",
            "x-1-1-1",
            "hb--1-1",
            "hb-1-1-",
        ] {
            assert_eq!(owner_pid(bad), None, "{bad}");
        }
    }
}
