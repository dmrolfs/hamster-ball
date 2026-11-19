// ABOUTME: Shared test fixtures: a throwaway home/project tree, a mode guard and a mkfifo helper.
// ABOUTME: Compiled only for tests; keeps the per-module fixtures from drifting apart.
//! Test-only helpers shared by several modules' unit tests.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use claims::assert_ok;
use tempfile::TempDir;

use crate::policy::{CanonicalPath, HomeDir, ProjectRoot};

/// A canonical, throwaway directory tree with a `home` directory in it.
///
/// Everything lives under one [`TempDir`], so dropping the tree removes it, even if a test
/// panics. Paths handed out are already canonical (macOS temp dirs sit behind `/var` ->
/// `/private/var`).
pub(crate) struct Tree {
    _dir: TempDir,
    base: PathBuf,
    home: HomeDir,
}

impl Tree {
    pub(crate) fn new() -> Self {
        let dir = assert_ok!(TempDir::new());
        let base = assert_ok!(fs::canonicalize(dir.path()));
        let home_path = base.join("home");
        assert_ok!(fs::create_dir_all(&home_path));
        let home = HomeDir::new(canonical(&home_path));
        Self {
            _dir: dir,
            base,
            home,
        }
    }

    /// The tree's root; everything else is below it.
    pub(crate) fn base(&self) -> &Path {
        &self.base
    }

    pub(crate) fn home(&self) -> &HomeDir {
        &self.home
    }

    pub(crate) fn home_path(&self) -> &Path {
        self.home.path().as_path()
    }

    /// Creates and returns `<base>/outside/<rel>`, a directory outside the home directory.
    pub(crate) fn outside(&self, rel: &str) -> PathBuf {
        let path = self.base.join("outside").join(rel);
        assert_ok!(fs::create_dir_all(&path));
        path
    }

    /// Creates and returns `<home>/<rel>`.
    pub(crate) fn inside_home(&self, rel: &str) -> PathBuf {
        let path = self.home_path().join(rel);
        assert_ok!(fs::create_dir_all(&path));
        path
    }

    /// A project root at `<home>/<rel>`.
    pub(crate) fn project_root(&self, rel: &str) -> ProjectRoot {
        let path = self.inside_home(rel);
        assert_ok!(ProjectRoot::new(canonical(&path), &self.home))
    }
}

/// Wraps an existing path, canonicalized, as a [`CanonicalPath`].
pub(crate) fn canonical(path: &Path) -> CanonicalPath {
    assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
        path
    ))))
}

/// Sets a file mode and restores the previous one on drop, so a panicking test cannot leave
/// an unreadable directory behind for [`TempDir`] to fail to delete.
pub(crate) struct ModeGuard {
    path: PathBuf,
    previous: u32,
}

impl ModeGuard {
    pub(crate) fn set(path: &Path, mode: u32) -> Self {
        let previous = assert_ok!(fs::metadata(path)).permissions().mode();
        assert_ok!(fs::set_permissions(path, fs::Permissions::from_mode(mode)));
        Self {
            path: path.to_path_buf(),
            previous,
        }
    }
}

impl Drop for ModeGuard {
    fn drop(&mut self) {
        // Best effort: failing here would only mask the test's own failure.
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.previous));
    }
}

/// Creates a FIFO at `path` using the system `mkfifo`, since this crate forbids `unsafe`.
pub(crate) fn mkfifo(path: &Path) {
    let status = assert_ok!(std::process::Command::new("mkfifo").arg(path).status());
    assert!(status.success(), "mkfifo failed: {status:?}");
}
