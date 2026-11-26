// ABOUTME: Finds the git-tracked files whose names the guard would deny, so they can be left readable: the agent can `git show` them.
// ABOUTME: Runs git on the host with config, hooks and fsmonitor off and a time limit; no git means nothing is skipped.
//! Git-tracked files (design section 8).

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use super::patterns::{is_guarded, is_template};
use crate::policy::CanonicalPath;
use crate::sys::{BoundedError, run_bounded};

/// Where git is looked for: the system one, never something found through `PATH`.
pub const SYSTEM_GIT: &str = "/usr/bin/git";
/// Longest wait for `git ls-files`.
const GIT_TIMEOUT: Duration = Duration::from_secs(5);
/// Most output read from git (a repository of a million files is about 60 MB).
const MAX_OUTPUT_BYTES: u64 = 67_108_864;

/// How the listing went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Listing {
    /// git listed the files.
    Listed,
    /// git ran and said this is not a repository (or would not look at it).
    NotARepository,
    /// There is no git to run.
    Unavailable,
    /// git took too long and was stopped.
    TimedOut,
}

/// The tracked files with guarded names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tracked {
    /// How the listing went.
    pub listing: Listing,
    /// The files, sorted, up to the limit.
    pub files: Vec<CanonicalPath>,
    /// How many more there were than the limit; they stay denied.
    pub beyond_limit: usize,
}

impl Tracked {
    fn none(listing: Listing) -> Self {
        Self {
            listing,
            files: Vec::new(),
            beyond_limit: 0,
        }
    }
}

/// The files `git` tracks below `root` that the guard would deny.
///
/// Symbolic links are left out: a link is read through to its target, which is not a tracked
/// file of this name.
#[must_use]
pub fn tracked_guarded(root: &CanonicalPath, git: &Path, limit: usize) -> Tracked {
    tracked_guarded_within(root, git, limit, GIT_TIMEOUT)
}

fn tracked_guarded_within(
    root: &CanonicalPath,
    git: &Path,
    limit: usize,
    timeout: Duration,
) -> Tracked {
    let output = match list(root, git, timeout) {
        Ok(output) => output,
        Err(listing) => return Tracked::none(listing),
    };
    let mut found: Vec<CanonicalPath> = output
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
        .filter_map(|entry| {
            let relative = Path::new(OsStr::from_bytes(entry));
            let name = relative.file_name()?.to_str()?;
            if !is_guarded(name) || is_template(name) {
                return None;
            }
            let path = root.as_path().join(relative);
            let metadata = std::fs::symlink_metadata(&path).ok()?;
            if !metadata.is_file() {
                return None;
            }
            CanonicalPath::from_canonical(path).ok()
        })
        .collect();
    found.sort();
    found.dedup();
    let beyond_limit = found.len().saturating_sub(limit);
    found.truncate(limit);
    Tracked {
        listing: Listing::Listed,
        files: found,
        beyond_limit,
    }
}

/// `git ls-files -z`, run so that nothing in the repository can make it run a program.
fn list(root: &CanonicalPath, git: &Path, timeout: Duration) -> Result<Vec<u8>, Listing> {
    let mut command = Command::new(git);
    command
        .arg("-C")
        .arg(root.as_path())
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
            "ls-files",
            "-z",
            "--cached",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    if let Some(home) = std::env::var_os("HOME") {
        command.env("HOME", home);
    }
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        command.env("TMPDIR", tmp);
    }
    match run_bounded(&mut command, timeout, MAX_OUTPUT_BYTES) {
        Ok(done) if done.status.success() => Ok(done.stdout),
        Ok(_) => Err(Listing::NotARepository),
        // Cancelled cannot happen: no cancel flag is passed.
        Err(BoundedError::TimedOut | BoundedError::Cancelled) => Err(Listing::TimedOut),
        Err(BoundedError::Spawn(_)) => Err(Listing::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::process::Stdio;
    use std::time::Instant;
    use tempfile::TempDir;

    fn git_available() -> bool {
        Path::new(SYSTEM_GIT).exists()
    }

    fn repo() -> (TempDir, CanonicalPath) {
        let dir = assert_ok!(tempfile::tempdir());
        let root = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
            std::fs::canonicalize(dir.path())
        )));
        git(&root, &["init", "-q"]);
        (dir, root)
    }

    fn git(root: &CanonicalPath, args: &[&str]) {
        let status = assert_ok!(
            Command::new(SYSTEM_GIT)
                .arg("-C")
                .arg(root.as_path())
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        );
        assert!(status.success(), "git {args:?}");
    }

    fn write(root: &CanonicalPath, relative: &str) {
        let path = root.as_path().join(relative);
        if let Some(parent) = path.parent() {
            assert_ok!(std::fs::create_dir_all(parent));
        }
        assert_ok!(std::fs::write(path, "x"));
    }

    fn names(root: &CanonicalPath, tracked: &Tracked) -> Vec<String> {
        tracked
            .files
            .iter()
            .map(|f| {
                f.as_str()
                    .strip_prefix(root.as_str())
                    .unwrap_or(f.as_str())
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn tracked_files_with_guarded_names_are_listed_and_untracked_ones_are_not() {
        if !git_available() {
            return;
        }
        let (_dir, root) = repo();
        for file in [
            ".env",
            "cfg/server.pem",
            "cfg/.env.example",
            "src/main.rs",
            "other.key",
        ] {
            write(&root, file);
        }
        git(
            &root,
            &[
                "add",
                "-f",
                ".env",
                "cfg/server.pem",
                "cfg/.env.example",
                "src/main.rs",
            ],
        );
        let tracked = tracked_guarded(&root, Path::new(SYSTEM_GIT), 100);
        assert_eq!(tracked.listing, Listing::Listed);
        assert_eq!(names(&root, &tracked), ["/.env", "/cfg/server.pem"]);
        assert_eq!(tracked.beyond_limit, 0);
    }

    #[test]
    fn a_directory_that_is_not_a_repository_has_nothing_tracked() {
        if !git_available() {
            return;
        }
        let dir = assert_ok!(tempfile::tempdir());
        let root = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
            std::fs::canonicalize(dir.path())
        )));
        write(&root, ".env");
        let tracked = tracked_guarded(&root, Path::new(SYSTEM_GIT), 100);
        assert_eq!(
            (tracked.listing, tracked.files.len()),
            (Listing::NotARepository, 0)
        );
    }

    #[test]
    fn a_missing_git_means_nothing_is_skipped() {
        let (_dir, root) = {
            let dir = assert_ok!(tempfile::tempdir());
            let root = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
                std::fs::canonicalize(dir.path())
            )));
            (dir, root)
        };
        let tracked = tracked_guarded(&root, Path::new("/nonexistent/git"), 100);
        assert_eq!(
            (tracked.listing, tracked.files.len()),
            (Listing::Unavailable, 0)
        );
    }

    #[test]
    fn files_beyond_the_limit_are_counted_and_left_denied() {
        if !git_available() {
            return;
        }
        let (_dir, root) = repo();
        for i in 0..5 {
            write(&root, &format!("k{i}.key"));
        }
        git(&root, &["add", "-f", "."]);
        let tracked = tracked_guarded(&root, Path::new(SYSTEM_GIT), 3);
        assert_eq!((tracked.files.len(), tracked.beyond_limit), (3, 2));
    }

    #[test]
    fn a_tracked_symbolic_link_with_a_guarded_name_is_not_listed() {
        if !git_available() {
            return;
        }
        let (_dir, root) = repo();
        write(&root, "real.txt");
        assert_ok!(std::os::unix::fs::symlink(
            "real.txt",
            root.as_path().join("link.key")
        ));
        git(&root, &["add", "-f", "."]);
        assert_eq!(
            tracked_guarded(&root, Path::new(SYSTEM_GIT), 10)
                .files
                .len(),
            0
        );
    }

    #[test]
    fn a_git_that_hangs_is_stopped_and_nothing_is_skipped() {
        let dir = assert_ok!(tempfile::tempdir());
        let root = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
            std::fs::canonicalize(dir.path())
        )));
        let fake = dir.path().join("git");
        assert_ok!(std::fs::write(&fake, "#!/bin/sh\nsleep 20\n"));
        assert_ok!(std::fs::set_permissions(
            &fake,
            std::os::unix::fs::PermissionsExt::from_mode(0o755)
        ));
        let started = Instant::now();
        let tracked = tracked_guarded_within(&root, &fake, 10, Duration::from_millis(300));
        assert_eq!(
            (tracked.listing, tracked.files.len()),
            (Listing::TimedOut, 0)
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn the_repositorys_own_config_cannot_make_the_listing_run_a_program() {
        if !git_available() {
            return;
        }
        let (dir, root) = repo();
        write(&root, ".env");
        git(&root, &["add", "-f", ".env"]);
        let marker = dir.path().join("ran");
        let config = root.as_path().join(".git/config");
        let mut text = assert_ok!(std::fs::read_to_string(&config));
        text.push_str(&format!(
            "[core]\n\tfsmonitor = touch {}\n[alias]\n\tls-files = !touch {}\n",
            marker.display(),
            marker.display()
        ));
        assert_ok!(std::fs::write(&config, text));
        // The control: a plain git run in this repository does run the program, so the marker
        // below is evidence about `tracked_guarded` and not about a config git ignores.
        git(&root, &["status", "-s"]);
        assert!(
            marker.exists(),
            "the control did not run the configured program"
        );
        assert_ok!(std::fs::remove_file(&marker));
        let tracked = tracked_guarded(&root, Path::new(SYSTEM_GIT), 10);
        assert_eq!(tracked.files.len(), 1);
        assert!(
            !marker.exists(),
            "a program from the repository's config ran"
        );
    }
}
