// ABOUTME: Warns when a git config file exists that the ball cannot read, because git then fails every command with a message that never mentions hb.
// ABOUTME: Measured: an unreadable `~/.gitconfig` or `~/.config/git/config` is fatal (git tolerates a missing file, not EPERM); `~/.config/git/ignore` alone only warns.
//! Unreadable git configuration (design 6 and 10, hb-ghd.7.3).

use std::fs;

use crate::config::Policy;
use crate::policy::{CanonicalPath, HomeDir};

/// The git files whose absence git tolerates and whose unreadability it does not, relative to home.
const FILES: [(&str, &str); 2] = [
    ("~/.gitconfig", ".gitconfig"),
    ("~/.config/git/config", ".config/git/config"),
];

/// The git config files that exist under `home` and that no read or write grant covers, as
/// `~/...` paths, in a fixed order.
#[must_use]
pub fn unreadable(policy: &Policy, home: &HomeDir) -> Vec<String> {
    FILES
        .iter()
        .filter(|(_, relative)| {
            let Ok(resolved) = fs::canonicalize(home.path().as_path().join(relative)) else {
                return false;
            };
            let Ok(file) = CanonicalPath::from_canonical(&resolved) else {
                return false;
            };
            !policy
                .fs
                .read
                .iter()
                .chain(&policy.fs.write)
                .any(|grant| grant.value.is_same_or_ancestor_of(&file))
        })
        .map(|(shown, _)| (*shown).to_owned())
        .collect()
}

/// One warning for [`unreadable`], or `None` when git can read all its config.
#[must_use]
pub fn warning(policy: &Policy, home: &HomeDir) -> Option<String> {
    let files = unreadable(policy, home);
    (!files.is_empty()).then(|| {
        format!(
            "git inside the ball will fail with `unable to access`: {} exist but the ball cannot read {}; add {} to [fs] read in your base config (`hb init` writes it)",
            files.join(" and "),
            if files.len() == 1 { "it" } else { "them" },
            files
                .iter()
                .map(|f| format!("\"{f}\""))
                .collect::<Vec<_>>()
                .join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;
    use crate::config::merge;
    use crate::origin::{FileId, Source, Sourced};
    use crate::policy::{CanonicalPath, Floor, HomeDir};

    struct Fixture {
        _tmp: TempDir,
        home: HomeDir,
        path: std::path::PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = assert_ok!(TempDir::new());
        let path = assert_ok!(fs::canonicalize(tmp.path())).join("home");
        assert_ok!(fs::create_dir_all(&path));
        let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(&path)));
        Fixture {
            _tmp: tmp,
            home,
            path,
        }
    }

    fn policy_reading(paths: &[&Path], writing: &[&Path]) -> crate::config::Policy {
        let source = Source::value(FileId::new(0));
        let mut policy = assert_ok!(merge(&[], Floor::empty()));
        let grant = |p: &&Path| {
            Sourced::new(
                assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
                    p
                )))),
                source,
            )
        };
        policy.fs.read = paths.iter().map(grant).collect();
        policy.fs.write = writing.iter().map(grant).collect();
        policy
    }

    #[test]
    fn a_machine_with_no_git_config_has_nothing_to_warn_about() {
        let f = fixture();
        assert_eq!(
            unreadable(&policy_reading(&[], &[]), &f.home),
            Vec::<String>::new()
        );
        assert!(warning(&policy_reading(&[], &[]), &f.home).is_none());
    }

    #[test]
    fn an_existing_git_config_with_no_grant_is_named_and_the_warning_says_what_to_add() {
        let f = fixture();
        assert_ok!(fs::write(f.path.join(".gitconfig"), "[user]\n"));
        assert_ok!(fs::create_dir_all(f.path.join(".config/git")));
        assert_ok!(fs::write(f.path.join(".config/git/config"), "[core]\n"));
        let policy = policy_reading(&[], &[]);
        assert_eq!(
            unreadable(&policy, &f.home),
            ["~/.gitconfig", "~/.config/git/config"]
        );
        let text = assert_ok!(warning(&policy, &f.home).ok_or("no warning"));
        assert!(
            text.contains("~/.gitconfig") && text.contains("~/.config/git/config"),
            "{text}"
        );
        assert!(text.contains("[fs] read"), "{text}");
    }

    #[test]
    fn a_read_grant_of_the_file_or_a_directory_above_it_or_a_write_grant_covers_it() {
        let f = fixture();
        assert_ok!(fs::write(f.path.join(".gitconfig"), "[user]\n"));
        assert_ok!(fs::create_dir_all(f.path.join(".config/git")));
        assert_ok!(fs::write(f.path.join(".config/git/config"), "[core]\n"));
        let gitconfig = f.path.join(".gitconfig");
        let xdg = f.path.join(".config/git");
        let config = f.path.join(".config");
        for policy in [
            policy_reading(&[&gitconfig, &xdg], &[]),
            policy_reading(&[&gitconfig], &[&config]),
            policy_reading(&[], &[&gitconfig, &xdg]),
        ] {
            assert_eq!(unreadable(&policy, &f.home), Vec::<String>::new());
        }
        assert_eq!(
            unreadable(&policy_reading(&[&gitconfig], &[]), &f.home),
            ["~/.config/git/config"]
        );
    }

    #[test]
    fn an_ignore_file_alone_is_not_reported_because_git_only_warns() {
        let f = fixture();
        assert_ok!(fs::create_dir_all(f.path.join(".config/git")));
        assert_ok!(fs::write(f.path.join(".config/git/ignore"), "x\n"));
        assert_eq!(
            unreadable(&policy_reading(&[], &[]), &f.home),
            Vec::<String>::new()
        );
    }

    #[test]
    fn a_symlinked_gitconfig_is_covered_by_a_grant_of_its_target() {
        let f = fixture();
        let dotfiles = f.path.join("dotfiles");
        assert_ok!(fs::create_dir_all(&dotfiles));
        assert_ok!(fs::write(dotfiles.join("gitconfig"), "[user]\n"));
        assert_ok!(symlink(
            dotfiles.join("gitconfig"),
            f.path.join(".gitconfig")
        ));
        let target = dotfiles.join("gitconfig");
        assert_eq!(
            unreadable(&policy_reading(&[], &[]), &f.home),
            ["~/.gitconfig"]
        );
        assert_eq!(
            unreadable(&policy_reading(&[&target], &[]), &f.home),
            Vec::<String>::new()
        );
    }
}
