// ABOUTME: What `hb doctor` finds about git outside the floor's reach: repositories nested below a write grant and git hook managers.
// ABOUTME: Reads directory entry names and one config key, on the host; nothing is written and no hook is run.
//! Git that the floor does not protect (design section 6, D46, open item 11).
//!
//! The floor write-denies `.git/hooks` and `.git/config` of the project and of the repositories
//! above it. A repository below a write grant is not covered (protecting it would break `git init`
//! and `git clone` in subdirectories), and a hook manager moves the hooks to a directory the agent
//! can write. In both cases the agent can plant code that git runs outside the ball, so the
//! doctor names them and the owner decides what to deny.

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::git_config::{self, HookSetting};
use crate::config::{FsDecision, Policy};
use crate::diagnostic::{Check, CheckGap, DiagnosticCode, Gaps, SafePath};
use crate::policy::{CanonicalPath, FsAccess, HomeDir};

/// Directories not walked: dependencies and build output, as in the guard's own scan. Each one that
/// exists is reported as a gap, so a result that skipped a repository inside one is never clean.
const SKIPPED_DIRS: &[&str] = &["node_modules", "site-packages", ".venv", "venv", "target"];

/// Names that belong to a git hook manager, and what each is.
const MANAGER_NAMES: &[(&str, &str)] = &[
    (".husky", "husky"),
    (".githooks", "a hooks directory"),
    (".git-hooks", "a hooks directory"),
    ("lefthook.yml", "lefthook"),
    ("lefthook.yaml", "lefthook"),
    (".lefthook.yml", "lefthook"),
    (".lefthook.yaml", "lefthook"),
    ("lefthook-local.yml", "lefthook"),
    (".pre-commit-config.yaml", "pre-commit"),
];

/// Most repositories whose hook settings are queried (the project's first), up to three git runs each.
const MAX_QUERIES: usize = 32;
/// Longest one repository's two git runs may take together.
const QUERY_TIMEOUT: Duration = Duration::from_secs(4);
/// Longest all the queries may take together.
const QUERY_BUDGET: Duration = Duration::from_secs(10);

/// What the sandbox policy says about writing a hooks directory.
///
/// Advisory, from [`Policy::decide`]: it is not a probe of the file system and not a promise about
/// what is inside the directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteAssessment {
    /// A write grant covers it and nothing denies it.
    Permitted,
    /// A floor rule or a configured deny covers it.
    Denied,
    /// No write grant covers it.
    NotGranted,
    /// The target could not be resolved well enough to ask.
    Unknown,
}

/// One repository's hook setting and whether the agent could write where hooks run from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookObservation {
    /// The repository directory that was inspected.
    pub repository: String,
    /// The directory hooks are read from.
    pub hooks_dir: String,
    /// The configured `core.hooksPath`, or `None` when it is unset in the inspected scopes.
    pub configured: Option<String>,
    /// The scope and file that set it.
    pub origin: Option<String>,
    /// Whether the policy lets the agent write the directory.
    pub write: WriteAssessment,
}

/// What the survey found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepoFindings {
    /// Repositories (a `.git` directory or file) that are not the project's own.
    pub nested: Vec<String>,
    /// Hook manager files and directories, with the manager's name.
    pub managers: Vec<(String, &'static str)>,
    /// The effective hook setting of the project's repository and of each nested one.
    pub hooks: Vec<HookObservation>,
}

/// What the survey needs to ask git and the policy.
#[derive(Debug, Clone, Copy)]
pub struct GitContext<'a> {
    /// The loaded policy, for the write assessment.
    pub policy: &'a Policy,
    /// The owner's home directory, where the global git config is.
    pub home: &'a HomeDir,
    /// `XDG_CONFIG_HOME` if the owner set it.
    pub xdg_config_home: Option<&'a OsStr>,
}

/// What the file-system walk found, before git is asked anything.
#[derive(Debug, Default)]
struct Tree {
    nested: Vec<(PathBuf, String)>,
    managers: Vec<(String, &'static str)>,
}

/// Walks `roots` (symbolic links are not followed) for repositories other than the project's and
/// the ones above it, which the floor protects, then asks git for each repository's hook setting.
///
/// `max_entries` bounds the walk over all roots. Every directory that could not be read, every
/// name that was skipped and every limit reached becomes a gap, so a partial result is never
/// returned as a clean one. The system git configuration is never read, and a gap says so.
#[must_use]
pub fn survey_repos(
    roots: &[CanonicalPath],
    project: &CanonicalPath,
    max_entries: usize,
    git: &GitContext<'_>,
) -> Check<RepoFindings> {
    let mut gaps = Gaps::new();
    let tree = walk(roots, project, max_entries, &mut gaps);
    let mut found = RepoFindings {
        nested: tree.nested.iter().map(|(_, shown)| shown.clone()).collect(),
        managers: tree.managers,
        hooks: Vec::new(),
    };
    let mut repos: Vec<PathBuf> = enclosing_repository(project.as_path())
        .into_iter()
        .collect();
    repos.extend(tree.nested.into_iter().map(|(dir, _)| dir));
    // The system git configuration is never read, so every answer here leaves it out.
    gaps.push(CheckGap {
        code: DiagnosticCode::ConfigScopeOmitted,
        subject: None,
    });
    let started = Instant::now();
    observe_global(git, &mut found, &mut gaps);
    for (index, repo) in repos.iter().enumerate() {
        let left = QUERY_BUDGET.saturating_sub(started.elapsed());
        if index >= MAX_QUERIES || left.is_zero() {
            gaps.push(CheckGap {
                code: DiagnosticCode::InspectionLimitReached,
                subject: Some(SafePath::from_path(repo)),
            });
            continue;
        }
        match git_config::inspect(repo, git.home, git.xdg_config_home, left.min(QUERY_TIMEOUT)) {
            Ok(setting) => found.hooks.push(observe(setting, git.policy, &mut gaps)),
            Err(error) => gaps.push(failure_gap(&error, repo)),
        }
    }
    Check::from_parts(found, gaps)
}

/// What a failed query becomes: a spent budget is a limit, anything else is unavailable.
fn failure_gap(error: &git_config::QueryError, repo: &Path) -> CheckGap {
    let code = match error {
        git_config::QueryError::TimedOut => DiagnosticCode::InspectionLimitReached,
        _ => DiagnosticCode::GitConfigUnavailable,
    };
    gap(code, repo)
}

/// The owner's global `core.hooksPath`, which applies to every repository, present or future.
fn observe_global(git: &GitContext<'_>, found: &mut RepoFindings, gaps: &mut Gaps) {
    let home = git.home.path().as_path();
    match git_config::inspect_global(git.home, git.xdg_config_home, QUERY_TIMEOUT) {
        Ok((None, _)) => {}
        Ok((Some(value), origin)) => {
            // A relative global value is relative to each repository's own work tree, so there is no
            // one directory to ask the policy about.
            let dir = Path::new(&value);
            let (hooks_dir, write) = if dir.is_absolute() {
                (shown(dir), assess(dir, git.policy))
            } else {
                (value.clone(), WriteAssessment::Unknown)
            };
            if write == WriteAssessment::Unknown {
                gaps.push(gap(DiagnosticCode::WriteAccessUnknown, dir));
            }
            found.hooks.push(HookObservation {
                repository: "every repository (global git config)".to_owned(),
                hooks_dir,
                configured: Some(value),
                origin,
                write,
            });
        }
        Err(error) => gaps.push(failure_gap(&error, home)),
    }
}

/// The nearest directory at or above `project` with a `.git` entry, found by metadata only.
fn enclosing_repository(project: &Path) -> Option<PathBuf> {
    project
        .ancestors()
        .find(|dir| fs::symlink_metadata(dir.join(".git")).is_ok())
        .map(Path::to_path_buf)
}

fn walk(
    roots: &[CanonicalPath],
    project: &CanonicalPath,
    max_entries: usize,
    gaps: &mut Gaps,
) -> Tree {
    let mut found = Tree::default();
    let mut entries = 0;
    'roots: for root in roots {
        let mut stack = vec![root.as_path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            let listing = match fs::read_dir(&dir) {
                Ok(listing) => listing,
                Err(_) => {
                    gaps.push(gap(DiagnosticCode::DirectoryUnreadable, &dir));
                    continue;
                }
            };
            for entry in listing {
                let Ok(entry) = entry else {
                    gaps.push(gap(DiagnosticCode::DirectoryUnreadable, &dir));
                    continue;
                };
                entries += 1;
                if entries > max_entries {
                    gaps.push(CheckGap {
                        code: DiagnosticCode::EntryLimitReached,
                        subject: None,
                    });
                    break 'roots;
                }
                let path = entry.path();
                let Ok(kind) = entry.file_type() else {
                    gaps.push(gap(DiagnosticCode::EntryUnavailable, &path));
                    continue;
                };
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    gaps.push(gap(DiagnosticCode::NameNotUtf8, &path));
                    continue;
                };
                if name == ".git" {
                    // The project's own repository and the ones above it are the floor's.
                    if !project.as_path().starts_with(&dir) {
                        found.nested.push((dir.clone(), shown(&dir)));
                    }
                    continue;
                }
                if let Some((_, manager)) = MANAGER_NAMES.iter().find(|(n, _)| *n == name) {
                    found.managers.push((shown(&path), manager));
                }
                if kind.is_dir() {
                    if SKIPPED_DIRS.contains(&name) {
                        gaps.push(gap(DiagnosticCode::DirectoryNotInspected, &path));
                    } else {
                        stack.push(path);
                    }
                }
            }
        }
    }
    found.nested.sort();
    found.nested.dedup();
    found.managers.sort();
    found.managers.dedup();
    found
}

fn gap(code: DiagnosticCode, path: &Path) -> CheckGap {
    CheckGap {
        code,
        subject: Some(SafePath::from_path(path)),
    }
}

fn shown(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Turns git's answer into an observation: where hooks are read from, and whether the policy lets
/// the agent write there.
fn observe(setting: HookSetting, policy: &Policy, gaps: &mut Gaps) -> HookObservation {
    // A relative path is relative to where git runs hooks from: the top of the work tree, or the
    // git directory of a bare repository. Git has already expanded `~` (`--type=path`).
    let dir = match &setting.value {
        Some(value) => {
            let path = Path::new(value);
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                setting.hooks_cwd.join(path)
            }
        }
        None => setting.git_dir.join("hooks"),
    };
    let write = assess(&dir, policy);
    if write == WriteAssessment::Unknown {
        gaps.push(gap(DiagnosticCode::WriteAccessUnknown, &dir));
    }
    HookObservation {
        repository: shown(&setting.repository),
        hooks_dir: shown(&dir),
        configured: setting.value,
        origin: setting.origin,
        write,
    }
}

fn assess(dir: &Path, policy: &Policy) -> WriteAssessment {
    let Some(target) = resolve_with_missing_tail(dir) else {
        return WriteAssessment::Unknown;
    };
    let by_target = match policy.decide(&target, FsAccess::Write) {
        FsDecision::Allowed { .. } => WriteAssessment::Permitted,
        FsDecision::NotGranted => WriteAssessment::NotGranted,
        FsDecision::DeniedByFloor { .. } | FsDecision::Denied { .. } => WriteAssessment::Denied,
    };
    // A link on the way can be repointed by anyone who may write the directory that holds it, so
    // where it points today says little about where hooks will run from tomorrow.
    if by_target != WriteAssessment::Permitted && link_in_writable_parent(dir, policy) {
        return WriteAssessment::Permitted;
    }
    by_target
}

/// Whether some component of `dir` is a symbolic link that the policy lets the agent replace.
///
/// The question is about the link's own path, not its directory: a pin that stops the directory
/// itself being renamed or deleted does not stop an entry inside it being replaced.
fn link_in_writable_parent(dir: &Path, policy: &Policy) -> bool {
    let mut so_far = PathBuf::new();
    for component in dir.components() {
        so_far.push(component);
        if !fs::symlink_metadata(&so_far).is_ok_and(|m| m.file_type().is_symlink()) {
            continue;
        }
        let replaceable = so_far
            .parent()
            .zip(so_far.file_name())
            .and_then(|(parent, name)| {
                Some(resolve_with_missing_tail(parent)?.as_path().join(name))
            })
            .and_then(|link| CanonicalPath::from_canonical(link).ok())
            .is_some_and(|link| {
                matches!(
                    policy.decide(&link, FsAccess::Write),
                    FsDecision::Allowed { .. }
                )
            });
        if replaceable {
            return true;
        }
    }
    false
}

/// The real path of `dir`, or of its nearest existing ancestor with the missing names appended: an
/// absent hooks directory is still one the agent could create and fill. `..` and symbolic links
/// in the missing part cannot be resolved, so they give `None`.
fn resolve_with_missing_tail(dir: &Path) -> Option<CanonicalPath> {
    let mut tail = Vec::new();
    let mut at = dir;
    let base = loop {
        match fs::canonicalize(at) {
            Ok(real) => break real,
            Err(_) => {
                tail.push(at.file_name()?);
                at = at.parent()?;
            }
        }
    };
    let full = tail.iter().rev().fold(base, |path, name| path.join(name));
    CanonicalPath::from_canonical(full).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::DiagnosticCode;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn canonical(path: &Path) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
            path
        ))))
    }

    fn project() -> (TempDir, CanonicalPath) {
        let dir = assert_ok!(tempfile::tempdir());
        let root = canonical(dir.path());
        assert_ok!(fs::create_dir(root.as_path().join(".git")));
        (dir, root)
    }

    fn touch(path: &Path) {
        if let Some(parent) = path.parent() {
            assert_ok!(fs::create_dir_all(parent));
        }
        assert_ok!(fs::write(path, ""));
    }

    fn walked(roots: &[CanonicalPath], project: &CanonicalPath, max: usize) -> (Tree, Gaps) {
        let mut gaps = Gaps::new();
        let tree = walk(roots, project, max, &mut gaps);
        (tree, gaps)
    }

    fn codes(gaps: &Gaps) -> Vec<DiagnosticCode> {
        gaps.shown().iter().map(|gap| gap.code).collect()
    }

    #[test]
    fn the_projects_own_git_is_not_reported_and_a_clean_walk_has_no_gaps() {
        let (_dir, root) = project();
        let (tree, gaps) = walked(std::slice::from_ref(&root), &root, 1000);
        assert!(tree.nested.is_empty() && tree.managers.is_empty());
        assert!(gaps.is_empty());
    }

    #[test]
    fn a_repository_below_the_root_is_reported_by_its_directory_whether_git_is_a_directory_or_a_file()
     {
        let (_dir, root) = project();
        let base = root.as_path();
        assert_ok!(fs::create_dir_all(base.join("vendor/lib/.git")));
        touch(&base.join("sub/module/.git"));
        let (tree, _) = walked(std::slice::from_ref(&root), &root, 1000);
        let shown: Vec<String> = tree.nested.into_iter().map(|(_, shown)| shown).collect();
        assert_eq!(
            shown,
            vec![
                base.join("sub/module").to_string_lossy().into_owned(),
                base.join("vendor/lib").to_string_lossy().into_owned(),
            ]
        );
    }

    #[test]
    fn a_git_directory_at_another_write_root_is_reported_and_dependency_directories_are_skipped() {
        let (_dir, root) = project();
        let other_dir = assert_ok!(tempfile::tempdir());
        let other = canonical(other_dir.path());
        assert_ok!(fs::create_dir(other.as_path().join(".git")));
        assert_ok!(fs::create_dir_all(
            root.as_path().join("node_modules/dep/.git")
        ));
        assert_ok!(fs::create_dir_all(root.as_path().join("target/x/.git")));
        let (tree, _) = walked(&[root.clone(), other.clone()], &root, 1000);
        let shown: Vec<String> = tree.nested.into_iter().map(|(_, shown)| shown).collect();
        assert_eq!(shown, vec![other.as_path().to_string_lossy().into_owned()]);
    }

    #[test]
    fn hook_managers_are_named_wherever_they_are_below_a_root() {
        let (_dir, root) = project();
        let base = root.as_path();
        assert_ok!(fs::create_dir(base.join(".husky")));
        touch(&base.join("lefthook.yml"));
        touch(&base.join("app/.pre-commit-config.yaml"));
        assert_ok!(fs::create_dir(base.join(".githooks")));
        let (tree, _) = walked(std::slice::from_ref(&root), &root, 1000);
        let kinds: Vec<&str> = tree.managers.iter().map(|(_, m)| *m).collect();
        assert_eq!(
            kinds,
            vec!["a hooks directory", "husky", "pre-commit", "lefthook"]
        );
    }

    #[test]
    fn a_repository_above_the_project_is_the_floors_and_is_not_reported() {
        let (_dir, outer) = project();
        let inner = outer.as_path().join("work/app");
        assert_ok!(fs::create_dir_all(&inner));
        let inner = canonical(&inner);
        let (tree, _) = walked(std::slice::from_ref(&outer), &inner, 1000);
        assert!(tree.nested.is_empty());
    }

    #[test]
    fn a_walk_that_hits_the_limit_has_a_gap_for_it() {
        let (_dir, root) = project();
        for i in 0..10 {
            touch(&root.as_path().join(format!("d{i}/f")));
        }
        let (_, gaps) = walked(std::slice::from_ref(&root), &root, 5);
        assert_eq!(codes(&gaps), vec![DiagnosticCode::EntryLimitReached]);
    }

    #[test]
    fn an_unreadable_subdirectory_is_a_gap_and_its_readable_sibling_is_still_walked() {
        let (_dir, root) = project();
        let base = root.as_path();
        assert_ok!(fs::create_dir_all(base.join("locked/inner/.git")));
        assert_ok!(fs::create_dir_all(base.join("open/repo/.git")));
        let locked = base.join("locked");
        assert_ok!(fs::set_permissions(
            &locked,
            fs::Permissions::from_mode(0o000)
        ));
        let (tree, gaps) = walked(std::slice::from_ref(&root), &root, 1000);
        // Restore first so the temp directory can be removed whatever the assertions say.
        assert_ok!(fs::set_permissions(
            &locked,
            fs::Permissions::from_mode(0o755)
        ));
        if fs::read_dir(&locked).is_err() {
            // Not running as root: the denial was real.
        }
        assert_eq!(codes(&gaps), vec![DiagnosticCode::DirectoryUnreadable]);
        let shown: Vec<String> = tree.nested.into_iter().map(|(_, shown)| shown).collect();
        assert_eq!(
            shown,
            vec![base.join("open/repo").to_string_lossy().into_owned()]
        );
    }

    #[test]
    fn a_skipped_dependency_directory_is_a_gap_so_a_clean_result_never_hides_it() {
        let (_dir, root) = project();
        let base = root.as_path();
        assert_ok!(fs::create_dir_all(base.join("node_modules/dep/.git")));
        assert_ok!(fs::create_dir_all(base.join("target")));
        let (tree, gaps) = walked(std::slice::from_ref(&root), &root, 1000);
        // Not walked, so its repository is not reported, and the gap says so.
        assert!(tree.nested.is_empty());
        assert_eq!(
            codes(&gaps),
            vec![
                DiagnosticCode::DirectoryNotInspected,
                DiagnosticCode::DirectoryNotInspected
            ]
        );
    }

    #[test]
    fn a_failed_query_is_unavailable_and_a_spent_budget_is_a_limit() {
        use git_config::QueryError;
        let repo = Path::new("/p");
        assert_eq!(
            failure_gap(&QueryError::TimedOut, repo).code,
            DiagnosticCode::InspectionLimitReached
        );
        assert_eq!(
            failure_gap(&QueryError::Refused, repo).code,
            DiagnosticCode::GitConfigUnavailable
        );
    }

    fn setting(value: Option<&str>, repository: &str, hooks_cwd: &str) -> HookSetting {
        HookSetting {
            repository: PathBuf::from(repository),
            git_dir: PathBuf::from(repository).join(".git"),
            hooks_cwd: PathBuf::from(hooks_cwd),
            value: value.map(str::to_owned),
            origin: None,
        }
    }

    fn hooks_dir_of(setting: HookSetting) -> String {
        let mut gaps = Gaps::new();
        // Only the directory is under test, not the policy's answer about it.
        let policy = assert_ok!(crate::config::merge(&[], crate::policy::Floor::empty()));
        observe(setting, &policy, &mut gaps).hooks_dir
    }

    #[test]
    fn a_relative_hooks_path_is_joined_to_the_work_tree_top_not_the_inspected_directory() {
        assert_eq!(
            hooks_dir_of(setting(Some("rel/hooks"), "/r/sub/dir", "/r")),
            "/r/rel/hooks"
        );
        assert_eq!(
            hooks_dir_of(setting(Some("/abs/hooks"), "/r/sub/dir", "/r")),
            "/abs/hooks"
        );
        assert_eq!(
            hooks_dir_of(setting(None, "/r/sub/dir", "/r")),
            "/r/sub/dir/.git/hooks"
        );
    }

    #[test]
    fn a_missing_hooks_directory_resolves_through_its_nearest_existing_parent() {
        let (_dir, root) = project();
        let want = root.as_path().join("a/b");
        let got = resolve_with_missing_tail(&want);
        assert_eq!(
            got.map(|p| p.as_str().to_owned()),
            Some(want.to_string_lossy().into_owned())
        );
        assert!(resolve_with_missing_tail(&root.as_path().join("a/../b")).is_none());
    }

    #[test]
    fn many_unreadable_directories_are_counted_not_listed_without_bound() {
        let (_dir, root) = project();
        let base = root.as_path();
        let mut locked = Vec::new();
        for i in 0..(crate::diagnostic::MAX_GAPS + 3) {
            let dir = base.join(format!("d{i}"));
            assert_ok!(fs::create_dir(&dir));
            assert_ok!(fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)));
            locked.push(dir);
        }
        let (_, gaps) = walked(std::slice::from_ref(&root), &root, 10_000);
        for dir in &locked {
            assert_ok!(fs::set_permissions(dir, fs::Permissions::from_mode(0o755)));
        }
        assert_eq!(gaps.shown().len(), crate::diagnostic::MAX_GAPS);
        assert_eq!(gaps.omitted(), 3);
    }
}
