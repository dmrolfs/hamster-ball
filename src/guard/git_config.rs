// ABOUTME: Reads effective Git hook settings inside a read-confined Seatbelt inspector, never ordinary host Git.
// ABOUTME: Git owns precedence and includes; denied inputs, special files, malformed output and time limits are explicit failures.
//! Bounded Git configuration inspection for the doctor.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use snafu::{ResultExt, Snafu, ensure};

use crate::policy::HomeDir;
use crate::sys::{BoundedError, run_bounded};

const MAX_OUTPUT: u64 = 64 * 1024;
/// Most directories above a repository whose `.git` the inspector may read.
const MAX_ANCESTORS: usize = 32;

/// Why a confined query did not establish the setting.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
#[non_exhaustive]
pub(crate) enum QueryError {
    #[snafu(display("the Git inspector could not be started"))]
    Start { source: std::io::Error },
    #[snafu(display("the Git inspector ran past its time limit"))]
    TimedOut,
    #[snafu(display("the Git inspector refused or could not read its configuration"))]
    Refused,
    #[snafu(display("the Git inspector output exceeded its limit"))]
    Overflow,
    #[snafu(display("the Git inspector returned malformed output"))]
    Malformed,
    #[snafu(display("the Git inspector returned non-UTF-8 output"))]
    Encoding { source: std::str::Utf8Error },
}

/// A configuration value, with the file Git says supplied it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookSetting {
    /// The repository directory inspected.
    pub repository: PathBuf,
    /// The Git directory (default hooks live below this).
    pub git_dir: PathBuf,
    /// The directory a relative `core.hooksPath` is relative to.
    pub hooks_cwd: PathBuf,
    /// The configured value, or `None` when unset within the declared scope.
    pub value: Option<String>,
    /// Scope and source file of a configured value.
    pub origin: Option<String>,
}

/// The fixed inspector profile and its path parameters.
/// No path is interpolated into the Scheme source.
pub(crate) struct Inspector {
    text: String,
    params: Vec<(String, PathBuf)>,
}

impl Inspector {
    /// A profile that reads `repo`'s own `.git`, the `.git` of every directory above it (git finds
    /// an enclosing repository there), and, when `owner` is given, the owner's global git config.
    pub(crate) fn new(repo: &Path, owner: Option<(&HomeDir, Option<&OsStr>)>) -> Self {
        let mut result = Self {
            text: String::from(PROFILE),
            params: Vec::new(),
        };
        // Not the work tree: it can be all of HOME when the owner keeps dotfiles in a repository,
        // and git does not need it to read configuration or the index.
        result.grant(repo, "literal");
        for dir in repo.ancestors().take(MAX_ANCESTORS) {
            // Git walks up through each directory looking for `.git`, so each must open as a
            // directory. Only that: no file inside a work tree is readable.
            result.grant_directory(dir);
            result.grant(&dir.join(".git"), "subpath");
        }
        if let Some((home, xdg)) = owner {
            result.grant(&home.path().as_path().join(".gitconfig"), "literal");
            let config = xdg.map_or_else(|| home.path().as_path().join(".config"), PathBuf::from);
            if config.is_absolute() {
                result.grant(&config.join("git/config"), "literal");
            }
        }
        result
    }

    fn grant_directory(&mut self, path: &Path) {
        let name = format!("R{}", self.params.len());
        self.text.push_str(&format!(
            "(allow file-read* (require-all (literal (param \"{name}\")) (vnode-type DIRECTORY)))\n"
        ));
        self.params.push((name, path.to_owned()));
    }

    fn grant(&mut self, path: &Path, kind: &str) {
        let name = format!("R{}", self.params.len());
        self.text.push_str(&format!(
            "(allow file-read* (require-all ({kind} (param \"{name}\")) (vnode-type REGULAR-FILE)))\n\
             (allow file-read* (require-all ({kind} (param \"{name}\")) (vnode-type DIRECTORY)))\n"
        ));
        self.params.push((name, path.to_owned()));
    }

    /// A confined `git -C repo` command with a cleared, fixed environment; the caller adds the
    /// subcommand and `HOME`.
    pub(crate) fn command(&self, repo: &Path) -> Command {
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command.arg("-p").arg(&self.text);
        for (name, path) in &self.params {
            let mut define = std::ffi::OsString::from(format!("{name}="));
            define.push(path);
            command.arg("-D").arg(define);
        }
        command
            .args(["--", "/usr/bin/git", "--no-pager", "-C"])
            .arg(repo)
            .args(["-c", "core.fsmonitor=false"])
            .current_dir(repo)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0");
        command
    }
}

/// The owner's global `core.hooksPath`, read with no repository at all.
///
/// A global setting applies to every repository the owner uses, including ones the agent creates
/// later, so it is reported even when the survey found no repository.
pub(crate) fn inspect_global(
    home: &HomeDir,
    xdg: Option<&OsStr>,
    timeout: Duration,
) -> Result<(Option<String>, Option<String>), QueryError> {
    let cwd = home.path().as_path();
    let mut command = Inspector::new(cwd, Some((home, xdg))).command(cwd);
    command.env("HOME", cwd);
    if let Some(xdg) = xdg {
        command.env("XDG_CONFIG_HOME", xdg);
    }
    command.args([
        "config",
        "--global",
        "--null",
        "--show-origin",
        "--show-scope",
        "--type=path",
        "--get",
        "core.hooksPath",
    ]);
    let done = run(&mut command, timeout)?;
    ensure!(!done.truncated, OverflowSnafu);
    if done.status.code() == Some(1) && done.stdout.is_empty() {
        return Ok((None, None));
    }
    ensure!(done.status.success(), RefusedSnafu);
    let (value, origin) = parse(&done.stdout)?;
    Ok((Some(value), Some(origin)))
}

/// `git ls-files -z --cached` under the same read-confined profile as [`inspect`], for the guard's
/// list of tracked files. The owner's global config is deliberately not readable here.
///
/// A config include that leaves the repository, a FIFO or a link is refused by the profile, so a
/// hostile repository cannot steer a host read or stall the listing.
pub(crate) fn list_tracked(
    repo: &Path,
    timeout: Duration,
    max_bytes: u64,
) -> Result<crate::sys::Finished, BoundedError> {
    let mut command = Inspector::new(repo, None).command(repo);
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("HOME", repo)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "ls-files",
            "-z",
            "--cached",
        ]);
    run_bounded(&mut command, timeout, max_bytes)
}

// System runtime reads are fixed, not grants discovered from include text.
// system.sb supplies dyld/platform IPC; override its writes and network access.
// shortcut: developer tools outside these Apple locations are unavailable, add a measured trusted chain when supporting them.
const PROFILE: &str = r#"(version 1)
(deny default)
(import "system.sb")
(deny network*)
(deny file-write*)
(allow file-write-data (literal "/dev/null"))
(allow process-fork)
(allow process-exec (literal "/usr/bin/git")
 (literal "/Library/Developer/CommandLineTools/usr/bin/git")
 (literal "/Applications/Xcode.app/Contents/Developer/usr/bin/git"))
(allow file-read-metadata)
(allow file-read* (subpath "/usr/lib") (subpath "/usr/share")
 (subpath "/Library/Developer/CommandLineTools")
 (subpath "/Applications/Xcode.app/Contents/Developer")
 (subpath "/private/var/select") (literal "/usr/bin/git")
 (regex #"^/private/var/folders/[^/]+/[^/]+/T/xcrun_db$"))
"#;

fn run(command: &mut Command, timeout: Duration) -> Result<crate::sys::Finished, QueryError> {
    run_bounded(command, timeout, MAX_OUTPUT).map_err(|error| match error {
        BoundedError::Spawn(source) => QueryError::Start { source },
        BoundedError::TimedOut => QueryError::TimedOut,
    })
}

pub(crate) fn inspect(
    repo: &Path,
    home: &HomeDir,
    xdg: Option<&OsStr>,
    timeout: Duration,
) -> Result<HookSetting, QueryError> {
    let inspector = Inspector::new(repo, Some((home, xdg)));
    let started = std::time::Instant::now();
    let mut command = inspector.command(repo);
    command.env("HOME", home.path().as_path());
    if let Some(xdg) = xdg {
        command.env("XDG_CONFIG_HOME", xdg);
    }
    // Two answers, one per line: the git directory, then whether it is bare. Paths with a newline
    // cannot be framed this way and are refused, not guessed at.
    command.args(["rev-parse", "--absolute-git-dir", "--is-bare-repository"]);
    let discovery = run(&mut command, timeout)?;
    ensure!(!discovery.truncated, OverflowSnafu);
    ensure!(discovery.status.success(), RefusedSnafu);
    let text = std::str::from_utf8(&discovery.stdout).context(EncodingSnafu)?;
    let mut lines = text.lines();
    let (Some(dir), Some(bare), None) = (lines.next(), lines.next(), lines.next()) else {
        return MalformedSnafu.fail();
    };
    ensure!(
        Path::new(dir).is_absolute() && !dir.contains('\r') && matches!(bare, "true" | "false"),
        MalformedSnafu
    );
    let bare = bare == "true";
    // Git runs hooks from the top of the work tree, or from the git directory when there is none.
    let git_dir = PathBuf::from(dir);
    let hooks_cwd = if bare {
        git_dir.clone()
    } else {
        let remaining = timeout.saturating_sub(started.elapsed());
        ensure!(!remaining.is_zero(), TimedOutSnafu);
        let mut command = inspector.command(repo);
        command.env("HOME", home.path().as_path());
        command.args(["rev-parse", "--show-toplevel"]);
        let top = run(&mut command, remaining)?;
        ensure!(!top.truncated, OverflowSnafu);
        ensure!(top.status.success(), RefusedSnafu);
        let top = std::str::from_utf8(&top.stdout).context(EncodingSnafu)?;
        let top = top.strip_suffix('\n').unwrap_or(top);
        ensure!(
            Path::new(top).is_absolute() && !top.contains(['\n', '\r']),
            MalformedSnafu
        );
        PathBuf::from(top)
    };
    let remaining = timeout.saturating_sub(started.elapsed());
    ensure!(!remaining.is_zero(), TimedOutSnafu);
    let mut command = inspector.command(repo);
    command.env("HOME", home.path().as_path());
    if let Some(xdg) = xdg {
        command.env("XDG_CONFIG_HOME", xdg);
    }
    command.args([
        "config",
        "--includes",
        "--null",
        "--show-origin",
        "--show-scope",
        "--type=path",
        "--get",
        "core.hooksPath",
    ]);
    let done = run(&mut command, remaining)?;
    ensure!(!done.truncated, OverflowSnafu);
    let (value, origin) = if done.status.code() == Some(1) && done.stdout.is_empty() {
        (None, None)
    } else {
        ensure!(done.status.success(), RefusedSnafu);
        let (value, origin) = parse(&done.stdout)?;
        (Some(value), Some(origin))
    };
    Ok(HookSetting {
        repository: repo.to_owned(),
        git_dir,
        hooks_cwd,
        value,
        origin,
    })
}

fn parse(bytes: &[u8]) -> Result<(String, String), QueryError> {
    let text = std::str::from_utf8(bytes).context(EncodingSnafu)?;
    let fields: Vec<_> = text.split('\0').collect();
    ensure!(fields.len() == 4 && fields[3].is_empty(), MalformedSnafu);
    ensure!(
        matches!(fields[0], "global" | "local" | "worktree") && fields[1].starts_with("file:"),
        MalformedSnafu
    );
    Ok((fields[2].to_owned(), format!("{} {}", fields[0], fields[1])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    #[test]
    fn test_nul_protocol_preserves_newlines_and_empty_values() {
        assert_eq!(
            assert_ok!(parse(b"local\0file:.git/config\0a\nb\0")).0,
            "a\nb"
        );
        assert_eq!(assert_ok!(parse(b"global\0file:/h/.gitconfig\0\0")).0, "");
        assert_err!(parse(b"local\0file:.git/config\0value"));
        assert_err!(parse(b"local\0file:x\0a\0b\0"));
    }
}

#[cfg(test)]
mod real_git {
    use super::*;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::os::unix::fs::symlink;

    const WAIT: Duration = Duration::from_secs(8);

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        home: HomeDir,
    }

    fn fixture() -> Fixture {
        let dir = assert_ok!(tempfile::tempdir());
        let root = assert_ok!(fs::canonicalize(dir.path()));
        let home_path = root.join("home");
        let repo = root.join("repo");
        assert_ok!(fs::create_dir_all(&home_path));
        assert_ok!(fs::create_dir_all(repo.join(".git/hooks")));
        assert_ok!(fs::write(repo.join(".git/HEAD"), "ref: refs/heads/main\n"));
        assert_ok!(fs::create_dir_all(repo.join(".git/refs")));
        assert_ok!(fs::create_dir_all(repo.join(".git/objects")));
        assert_ok!(fs::write(
            repo.join(".git/config"),
            "[core]\n\trepositoryformatversion = 0\n"
        ));
        let home = HomeDir::new(assert_ok!(crate::policy::CanonicalPath::from_canonical(
            &home_path
        )));
        Fixture {
            _dir: dir,
            root,
            home,
        }
    }

    impl Fixture {
        fn repo(&self) -> PathBuf {
            self.root.join("repo")
        }
        fn config(&self, text: &str) {
            assert_ok!(fs::write(self.repo().join(".git/config"), text));
        }
        fn query(&self) -> Result<HookSetting, QueryError> {
            inspect(&self.repo(), &self.home, None, WAIT)
        }
    }

    /// Whether a sandbox can be applied here. When it cannot (this process is already sandboxed),
    /// the test is skipped, unless `HB_REQUIRE_SANDBOX` says that would hide a real failure.
    fn sandbox_ready() -> bool {
        let nested = crate::session::is_nested();
        if nested {
            assert!(
                std::env::var_os("HB_REQUIRE_SANDBOX").is_none(),
                "HB_REQUIRE_SANDBOX is set but sandbox-exec is unavailable"
            );
            eprintln!("SKIP: sandbox-exec is unavailable (already sandboxed?)");
        }
        !nested
    }

    #[test]
    fn test_effective_value_is_the_last_assignment_with_its_origin() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        f.config("[core]\n\thooksPath = first\n\thooksPath = last/wins\n");
        let got = assert_ok!(f.query());
        assert_eq!(got.value.as_deref(), Some("last/wins"));
        assert!(assert_ok!(got.origin.ok_or("no origin")).starts_with("local file:"),);
    }

    #[test]
    fn test_an_include_in_the_worktree_outside_dot_git_is_refused() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let include = f.repo().join("worktree.cfg");
        assert_ok!(fs::write(&include, "[core]\n\thooksPath = from/worktree\n"));
        f.config(&format!("[include]\n\tpath = {}\n", include.display()));
        assert!(matches!(f.query(), Err(QueryError::Refused)));
    }

    #[test]
    fn test_unset_is_reported_as_unset_not_as_failure() {
        if !sandbox_ready() {
            return;
        }
        let got = assert_ok!(fixture().query());
        assert_eq!(got.value, None);
    }

    #[test]
    fn test_global_config_is_read_without_opening_the_rest_of_home() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        assert_ok!(fs::write(
            f.home.path().as_path().join(".gitconfig"),
            "[core]\n\thooksPath = /owner/hooks\n"
        ));
        let got = assert_ok!(f.query());
        assert_eq!(got.value.as_deref(), Some("/owner/hooks"));
        assert!(assert_ok!(got.origin.ok_or("no origin")).starts_with("global file:"));
    }

    #[test]
    fn test_an_include_inside_the_repository_is_followed() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let include = f.repo().join(".git/inc.cfg");
        assert_ok!(fs::write(&include, "[core]\n\thooksPath = from/include\n"));
        f.config(&format!("[include]\n\tpath = {}\n", include.display()));
        assert_eq!(assert_ok!(f.query()).value.as_deref(), Some("from/include"));
    }

    #[test]
    fn test_an_include_outside_the_repository_is_refused_not_read() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let outside = f.root.join("outside.cfg");
        assert_ok!(fs::write(&outside, "[core]\n\thooksPath = LEAKED\n"));
        f.config(&format!("[include]\n\tpath = {}\n", outside.display()));
        assert!(matches!(f.query(), Err(QueryError::Refused)));
    }

    #[test]
    fn test_a_symlinked_include_that_leaves_the_repository_is_refused() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let outside = f.root.join("outside.cfg");
        assert_ok!(fs::write(&outside, "[core]\n\thooksPath = LEAKED\n"));
        let link = f.repo().join(".git/link.cfg");
        assert_ok!(symlink(&outside, &link));
        f.config(&format!("[include]\n\tpath = {}\n", link.display()));
        assert!(matches!(f.query(), Err(QueryError::Refused)));
    }

    fn mkfifo(path: &Path) {
        assert!(assert_ok!(Command::new("/usr/bin/mkfifo").arg(path).status()).success());
    }

    #[test]
    fn test_a_fifo_include_fails_fast_instead_of_hanging() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let fifo = f.repo().join(".git/fifo.cfg");
        mkfifo(&fifo);
        f.config(&format!("[include]\n\tpath = {}\n", fifo.display()));
        let started = std::time::Instant::now();
        assert_err!(f.query());
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn test_a_fifo_as_the_repository_config_fails_fast_instead_of_hanging() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let config = f.repo().join(".git/config");
        assert_ok!(fs::remove_file(&config));
        mkfifo(&config);
        let started = std::time::Instant::now();
        assert_err!(f.query());
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn test_hook_and_fsmonitor_canaries_never_run() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let hook_marker = f.root.join("hook-ran");
        let fsmonitor_marker = f.root.join("fsmonitor-ran");
        let script = |marker: &Path| format!("#!/bin/sh\ntouch '{}'\n", marker.display());
        let hook = f.repo().join(".git/hooks/post-checkout");
        let monitor = f.root.join("fsmonitor.sh");
        assert_ok!(fs::write(&hook, script(&hook_marker)));
        assert_ok!(fs::write(&monitor, script(&fsmonitor_marker)));
        for path in [&hook, &monitor] {
            let mut mode = assert_ok!(fs::metadata(path)).permissions();
            std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
            assert_ok!(fs::set_permissions(path, mode));
        }
        f.config(&format!(
            "[core]\n\tfsmonitor = {}\n\thooksPath = {}\n",
            monitor.display(),
            f.repo().join(".git/hooks").display()
        ));
        // The control: the query saw the canary's directory, so the settings were not masked.
        let got = assert_ok!(f.query());
        assert_eq!(
            got.value,
            Some(f.repo().join(".git/hooks").display().to_string())
        );
        assert!(!hook_marker.exists() && !fsmonitor_marker.exists());
    }

    #[test]
    fn test_a_tilde_value_is_expanded_by_git() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        f.config("[core]\n\thooksPath = ~/hk\n");
        let got = assert_ok!(f.query());
        assert_eq!(got.value, Some(format!("{}/hk", f.home.path().as_str())));
    }

    #[test]
    fn test_a_relative_value_is_relative_to_the_work_tree_not_the_inspected_directory() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        f.config("[core]\n\thooksPath = rel/hooks\n");
        let got = assert_ok!(f.query());
        assert_eq!(got.value.as_deref(), Some("rel/hooks"));
        assert_eq!(got.hooks_cwd, f.repo());
        // From a subdirectory of the work tree, the answer is still the top of the work tree.
        let sub = f.repo().join("a/b");
        assert_ok!(fs::create_dir_all(&sub));
        let from_sub = assert_ok!(inspect(&sub, &f.home, None, WAIT));
        assert_eq!(from_sub.hooks_cwd, f.repo());
    }

    #[test]
    fn test_the_global_config_alone_is_queried_without_any_repository() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        assert_eq!(
            assert_ok!(inspect_global(&f.home, None, WAIT)),
            (None, None)
        );
        assert_ok!(fs::write(
            f.home.path().as_path().join(".gitconfig"),
            "[core]\n\thooksPath = ~/gh\n"
        ));
        let (value, origin) = assert_ok!(inspect_global(&f.home, None, WAIT));
        assert_eq!(value, Some(format!("{}/gh", f.home.path().as_str())));
        assert!(assert_ok!(origin.ok_or("no origin")).starts_with("global file:"));
    }

    #[test]
    fn test_a_denied_global_include_is_a_failure_not_unset() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let outside = f.root.join("outside.cfg");
        assert_ok!(fs::write(&outside, "[core]\n\thooksPath = LEAKED\n"));
        assert_ok!(fs::write(
            f.home.path().as_path().join(".gitconfig"),
            format!("[include]\n\tpath = {}\n", outside.display())
        ));
        assert!(matches!(
            inspect_global(&f.home, None, WAIT),
            Err(QueryError::Refused)
        ));
        assert!(matches!(f.query(), Err(QueryError::Refused)));
    }

    #[test]
    fn test_an_enclosing_repository_is_found_from_a_subdirectory() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        f.config("[core]\n\thooksPath = from/outer\n");
        let sub = f.repo().join("work/app");
        assert_ok!(fs::create_dir_all(&sub));
        let got = assert_ok!(inspect(&sub, &f.home, None, WAIT));
        assert_eq!(got.value.as_deref(), Some("from/outer"));
    }

    #[test]
    fn test_a_pointer_file_to_a_git_directory_outside_the_grants_is_refused_not_guessed() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let elsewhere = f.root.join("elsewhere.git");
        assert_ok!(fs::rename(f.repo().join(".git"), &elsewhere));
        assert_ok!(fs::write(
            f.repo().join(".git"),
            format!("gitdir: {}\n", elsewhere.display())
        ));
        assert!(matches!(f.query(), Err(QueryError::Refused)));
    }

    #[test]
    fn test_budget_spent_between_the_runs_is_a_timeout() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        assert!(matches!(
            inspect(&f.repo(), &f.home, None, Duration::from_nanos(1)),
            Err(QueryError::TimedOut)
        ));
    }

    #[test]
    fn test_exit_one_with_output_is_a_failure_and_only_empty_output_is_unset() {
        // The classifier is `inspect`'s `done.status.code() == Some(1) && stdout.is_empty()`;
        // `parse` is what keeps any other shape from reaching it as a value.
        assert!(parse(b"").is_err());
        assert!(parse(b"local\0file:x\0v\0extra\0").is_err());
    }

    #[test]
    fn test_opening_the_directories_above_a_repository_does_not_expose_files_in_them() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        // A sibling file next to the repository, in a directory the walk up must be able to open.
        let sibling = f.root.join("sibling.cfg");
        assert_ok!(fs::write(&sibling, "[core]\n\thooksPath = LEAKED\n"));
        f.config(&format!("[include]\n\tpath = {}\n", sibling.display()));
        assert!(matches!(f.query(), Err(QueryError::Refused)));
        // And a file in the work tree itself, outside `.git`.
        let tree_file = f.repo().join("tree.cfg");
        assert_ok!(fs::write(&tree_file, "[core]\n\thooksPath = LEAKED\n"));
        f.config(&format!("[include]\n\tpath = {}\n", tree_file.display()));
        assert!(matches!(f.query(), Err(QueryError::Refused)));
    }

    fn script(path: &Path, marker: &Path) {
        assert_ok!(fs::write(
            path,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display())
        ));
        let mut mode = assert_ok!(fs::metadata(path)).permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut mode, 0o755);
        assert_ok!(fs::set_permissions(path, mode));
    }

    #[test]
    fn test_the_inspector_profile_refuses_to_run_a_hook_script_that_works_unconfined() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let marker = f.root.join("marker");
        let hook = f.repo().join(".git/hooks/post-checkout");
        script(&hook, &marker);
        // The control: unconfined, the script does what it says.
        assert!(assert_ok!(Command::new(&hook).status()).success());
        assert!(
            marker.exists(),
            "the canary script does not work, so the test proves nothing"
        );
        assert_ok!(fs::remove_file(&marker));
        // Under the production profile and environment the same program cannot start or write.
        let inspector = Inspector::new(&f.repo(), Some((&f.home, None)));
        let mut run = Command::new("/usr/bin/sandbox-exec");
        run.arg("-p").arg(&inspector.text);
        for (name, path) in &inspector.params {
            let mut define = std::ffi::OsString::from(format!("{name}="));
            define.push(path);
            run.arg("-D").arg(define);
        }
        let status = assert_ok!(run.arg("--").arg(&hook).env_clear().status());
        assert!(!status.success(), "the profile let a hook script run");
        assert!(!marker.exists());
    }

    #[test]
    fn test_the_production_argv_overrides_fsmonitor_and_runs_only_read_only_subcommands() {
        let f = fixture();
        let command = Inspector::new(&f.repo(), None).command(&f.repo());
        let args: Vec<String> = command
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        let at = assert_some!(args.iter().position(|a| a == "core.fsmonitor=false"));
        assert_eq!(args[at - 1], "-c");
        assert!(args.iter().any(|a| a == "/usr/bin/git"));
        assert!(
            !args
                .iter()
                .any(|a| matches!(a.as_str(), "status" | "checkout" | "commit" | "add"))
        );
        assert!(
            command
                .get_envs()
                .any(|(k, v)| k == "GIT_CONFIG_NOSYSTEM" && v.is_some())
        );
    }

    #[test]
    fn test_only_git_may_be_executed_inside_the_inspector() {
        if !sandbox_ready() {
            return;
        }
        let f = fixture();
        let inspector = Inspector::new(&f.repo(), Some((&f.home, None)));
        let exec = |program: &str| {
            let mut run = Command::new("/usr/bin/sandbox-exec");
            run.arg("-p").arg(&inspector.text);
            for (name, path) in &inspector.params {
                let mut define = std::ffi::OsString::from(format!("{name}="));
                define.push(path);
                run.arg("-D").arg(define);
            }
            assert_ok!(
                run.args(["--", program, "-c", "exit 0"])
                    .env_clear()
                    .status()
            )
            .success()
        };
        // Programs the system provides and a hook or an include-driven config could name.
        for program in [
            "/bin/sh",
            "/bin/bash",
            "/usr/bin/env",
            "/usr/bin/perl",
            "/usr/bin/true",
        ] {
            assert!(!exec(program), "the inspector may run {program}");
        }
    }
}
