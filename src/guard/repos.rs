// ABOUTME: What `hb doctor` finds about git outside the floor's reach: repositories nested below a write grant and git hook managers.
// ABOUTME: Reads directory entry names and one config key, on the host; nothing is written and no hook is run.
//! Git that the floor does not protect (design section 6, D46, open item 11).
//!
//! The floor write-denies `.git/hooks` and `.git/config` of the project and of the repositories
//! above it. A repository below a write grant is not covered (protecting it would break `git init`
//! and `git clone` in subdirectories), and a hook manager moves the hooks to a directory the agent
//! can write. In both cases the agent can plant code that git runs outside the ball, so the
//! doctor names them and the owner decides what to deny.

use std::fs;
use std::io::Read as _;
use std::path::Path;

use crate::policy::CanonicalPath;

/// Directories not walked: dependencies and build output, as in the guard's own scan.
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

/// The most bytes of `.git/config` that are read.
const CONFIG_LIMIT: u64 = 256 * 1024;

/// What the survey found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoFindings {
    /// Repositories (a `.git` directory or file) that are not the project's own.
    pub nested: Vec<String>,
    /// Hook manager files and directories, with the manager's name.
    pub managers: Vec<(String, &'static str)>,
    /// `core.hooksPath` from the project's `.git/config`, if set.
    pub hooks_path: Option<String>,
    /// Whether the walk covered everything.
    pub complete: bool,
}

impl Default for RepoFindings {
    /// Nothing found, and nothing left unlooked at.
    fn default() -> Self {
        Self {
            nested: Vec::new(),
            managers: Vec::new(),
            hooks_path: None,
            complete: true,
        }
    }
}

/// Walks `roots` (symbolic links are not followed) for repositories other than the project's and
/// the ones above it, which the floor protects.
///
/// `max_entries` bounds the work over all roots.
#[must_use]
pub fn survey_repos(
    roots: &[CanonicalPath],
    project: &CanonicalPath,
    max_entries: usize,
) -> RepoFindings {
    let mut found = RepoFindings::default();
    let mut entries = 0;
    'roots: for root in roots {
        let mut stack = vec![root.as_path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(listing) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in listing.flatten() {
                entries += 1;
                if entries > max_entries {
                    found.complete = false;
                    break 'roots;
                }
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    found.complete = false;
                    continue;
                };
                let path = entry.path();
                if name == ".git" {
                    // The project's own repository and the ones above it are the floor's.
                    if !project.as_path().starts_with(&dir) {
                        found.nested.push(shown(&dir));
                    }
                    continue;
                }
                if let Some((_, manager)) = MANAGER_NAMES.iter().find(|(n, _)| *n == name) {
                    found.managers.push((shown(&path), manager));
                }
                if kind.is_dir() && !SKIPPED_DIRS.contains(&name) {
                    stack.push(path);
                }
            }
        }
    }
    found.nested.sort();
    found.nested.dedup();
    found.managers.sort();
    found.managers.dedup();
    found.hooks_path = hooks_path(project.as_path());
    found
}

fn shown(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `core.hooksPath` from `<project>/.git/config` when `.git` is a directory and the key is set.
fn hooks_path(project: &Path) -> Option<String> {
    let mut text = String::new();
    fs::File::open(project.join(".git/config"))
        .ok()?
        .take(CONFIG_LIMIT)
        .read_to_string(&mut text)
        .ok()?;
    parse_hooks_path(&text)
}

/// The value of `hooksPath` in the `[core]` section of git config text.
///
/// Only the first assignment in `[core]` is looked at, and the value is trimmed of quotes and a
/// trailing comment is not interpreted: the doctor shows the text as written.
#[must_use]
pub fn parse_hooks_path(config: &str) -> Option<String> {
    let mut in_core = false;
    for line in config.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            // `[core "x"]` is a different section from `[core]`.
            in_core = line
                .trim_start_matches('[')
                .trim_end_matches(']')
                .trim()
                .eq_ignore_ascii_case("core");
            continue;
        }
        if !in_core {
            continue;
        }
        if let Some((key, value)) = line.split_once('=')
            && key.trim().eq_ignore_ascii_case("hookspath")
        {
            let value = value.trim().trim_matches('"').trim();
            return (!value.is_empty()).then(|| value.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
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

    #[test]
    fn the_projects_own_git_is_not_reported_and_a_clean_project_has_nothing() {
        let (_dir, root) = project();
        let found = survey_repos(std::slice::from_ref(&root), &root, 1000);
        assert_eq!(found.nested, Vec::<String>::new());
        assert_eq!(found.managers, Vec::new());
        assert_eq!(found.hooks_path, None);
        assert!(found.complete);
    }

    #[test]
    fn a_repository_below_the_root_is_reported_by_its_directory_whether_git_is_a_directory_or_a_file()
     {
        let (_dir, root) = project();
        let base = root.as_path();
        assert_ok!(fs::create_dir_all(base.join("vendor/lib/.git")));
        touch(&base.join("sub/module/.git"));
        let found = survey_repos(std::slice::from_ref(&root), &root, 1000);
        assert_eq!(
            found.nested,
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
        let found = survey_repos(&[root.clone(), other.clone()], &root, 1000);
        assert_eq!(
            found.nested,
            vec![other.as_path().to_string_lossy().into_owned()]
        );
    }

    #[test]
    fn hook_managers_are_named_wherever_they_are_below_a_root() {
        let (_dir, root) = project();
        let base = root.as_path();
        assert_ok!(fs::create_dir(base.join(".husky")));
        touch(&base.join("lefthook.yml"));
        touch(&base.join("app/.pre-commit-config.yaml"));
        assert_ok!(fs::create_dir(base.join(".githooks")));
        let found = survey_repos(std::slice::from_ref(&root), &root, 1000);
        let kinds: Vec<&str> = found.managers.iter().map(|(_, m)| *m).collect();
        assert_eq!(
            kinds,
            vec!["a hooks directory", "husky", "pre-commit", "lefthook"]
        );
    }

    #[test]
    fn the_hooks_path_of_the_projects_config_is_read() {
        let (_dir, root) = project();
        assert_ok!(fs::write(
            root.as_path().join(".git/config"),
            "[core]\n\tbare = false\n\thooksPath = .husky/_\n[remote \"origin\"]\n\turl = x\n"
        ));
        let found = survey_repos(std::slice::from_ref(&root), &root, 1000);
        assert_eq!(found.hooks_path.as_deref(), Some(".husky/_"));
    }

    #[test]
    fn only_the_core_section_counts_and_an_empty_value_is_not_a_path() {
        assert_eq!(parse_hooks_path("[alias]\n\thookspath = nope\n"), None);
        assert_eq!(parse_hooks_path("[core]\n\thooksPath =\n"), None);
        assert_eq!(
            parse_hooks_path("[Core]\n\tHOOKSPATH = \"/x/hooks\"\n").as_deref(),
            Some("/x/hooks")
        );
        assert_eq!(parse_hooks_path("[core \"sub\"]\nhooksPath = a\n"), None);
        assert_eq!(parse_hooks_path(""), None);
    }

    #[test]
    fn a_repository_above_the_project_is_the_floors_and_is_not_reported() {
        let (_dir, outer) = project();
        let inner = outer.as_path().join("work/app");
        assert_ok!(fs::create_dir_all(&inner));
        let inner = canonical(&inner);
        let found = survey_repos(std::slice::from_ref(&outer), &inner, 1000);
        assert_eq!(found.nested, Vec::<String>::new());
    }

    #[test]
    fn a_walk_that_hits_the_limit_says_it_is_incomplete() {
        let (_dir, root) = project();
        for i in 0..10 {
            touch(&root.as_path().join(format!("d{i}/f")));
        }
        let found = survey_repos(std::slice::from_ref(&root), &root, 5);
        assert!(!found.complete);
    }
}
