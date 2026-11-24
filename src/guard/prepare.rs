// ABOUTME: Gathers the host-side facts one run's guard rules need: pins from a scan, the tracked files, and notes about what fell short.
// ABOUTME: Any shortfall makes the guard stricter (no exemption, nothing skipped), never looser.
//! Preparing the guard for a run (design section 8).

use std::collections::BTreeSet;
use std::path::Path;

use strum::Display;

use super::GuardInputs;
use super::scan::{ScanLimits, scan};
use super::tracked::{Listing, tracked_guarded};
use crate::policy::CanonicalPath;

/// Most tracked files re-allowed in one profile. Each is a filter, and compile time follows the
/// filter count (design 7.1).
const MAX_TRACKED: usize = 128;

/// Something the guard could not do in full, and what that costs.
#[derive(Debug, Clone, PartialEq, Eq, Display)]
#[non_exhaustive]
pub enum GuardNote {
    /// The project is too large to scan, so the dependency exemption is off.
    #[strum(
        to_string = "the secrets guard could not scan the project in full, so key and certificate files \
        inside node_modules and site-packages stay denied: installing a package that ships one fails until \
        you add a [guard] exceptions entry for it"
    )]
    ScanIncomplete,
    /// There is no usable git, so no tracked file is left readable.
    #[strum(
        to_string = "git could not list the tracked files, so files with secret-like names stay denied even \
        when git tracks them"
    )]
    GitFailed,
    /// More tracked files than a profile can carry.
    #[strum(
        to_string = "{count} tracked files with secret-like names stay denied: the guard re-allows at most 128"
    )]
    TrackedBeyondLimit {
        /// How many were left out.
        count: usize,
    },
}

/// What the run's guard rules need beyond the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    /// Pins and the dependency exemption.
    pub inputs: GuardInputs,
    /// Tracked files with guarded names, to leave readable.
    pub tracked: Vec<CanonicalPath>,
    /// What fell short.
    pub notes: Vec<GuardNote>,
}

/// Prepares the guard for `roots` (the writable grants).
#[must_use]
pub fn prepare(roots: &[CanonicalPath], git: &Path) -> Prepared {
    let mut notes = Vec::new();
    let found = scan(roots, ScanLimits::default());
    let inputs = if found.complete {
        GuardInputs {
            pins: found.pins,
            dependency_exemption: true,
        }
    } else {
        notes.push(GuardNote::ScanIncomplete);
        GuardInputs::default()
    };

    let mut tracked: BTreeSet<CanonicalPath> = BTreeSet::new();
    let mut beyond = 0;
    let mut git_failed = false;
    for root in roots {
        let room = MAX_TRACKED.saturating_sub(tracked.len());
        let listed = tracked_guarded(root, git, room);
        // A directory that is simply not a repository is not a failure.
        git_failed |= matches!(listed.listing, Listing::Unavailable | Listing::TimedOut);
        beyond += listed.beyond_limit;
        tracked.extend(listed.files);
    }
    if git_failed {
        notes.push(GuardNote::GitFailed);
    }
    if beyond > 0 {
        notes.push(GuardNote::TrackedBeyondLimit { count: beyond });
    }
    Prepared {
        inputs,
        tracked: tracked.into_iter().collect(),
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guard::tracked::SYSTEM_GIT;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    fn root() -> (tempfile::TempDir, CanonicalPath) {
        let dir = assert_ok!(tempfile::tempdir());
        let path = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
            std::fs::canonicalize(dir.path())
        )));
        (dir, path)
    }

    #[test]
    fn a_project_with_a_secret_directory_gets_pins_and_the_exemption() {
        let (_dir, root) = root();
        assert_ok!(std::fs::create_dir(root.as_path().join("certs")));
        assert_ok!(std::fs::write(root.as_path().join("certs/server.key"), "x"));
        let prepared = prepare(std::slice::from_ref(&root), Path::new(SYSTEM_GIT));
        assert!(prepared.inputs.dependency_exemption);
        assert_eq!(prepared.inputs.pins.len(), 2);
        assert_eq!(prepared.notes, Vec::<GuardNote>::new());
    }

    #[test]
    fn a_missing_git_is_a_note_and_nothing_is_tracked() {
        let (_dir, root) = root();
        let prepared = prepare(&[root], Path::new("/nonexistent/git"));
        assert_eq!(prepared.notes, [GuardNote::GitFailed]);
        assert!(prepared.tracked.is_empty());
    }

    #[test]
    fn a_directory_that_is_not_a_repository_is_not_a_note() {
        if !Path::new(SYSTEM_GIT).exists() {
            return;
        }
        let (_dir, root) = root();
        assert_eq!(
            prepare(&[root], Path::new(SYSTEM_GIT)).notes,
            Vec::<GuardNote>::new()
        );
    }

    #[test]
    fn tracked_files_beyond_what_a_profile_can_carry_are_counted_in_a_note() {
        if !Path::new(SYSTEM_GIT).exists() {
            return;
        }
        let (_dir, root) = root();
        let git = |args: &[&str]| {
            assert_ok!(
                std::process::Command::new(SYSTEM_GIT)
                    .arg("-C")
                    .arg(root.as_path())
                    .args(args)
                    .env("GIT_CONFIG_GLOBAL", "/dev/null")
                    .env("GIT_CONFIG_SYSTEM", "/dev/null")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
            );
        };
        git(&["init", "-q"]);
        for i in 0..130 {
            assert_ok!(std::fs::write(
                root.as_path().join(format!("k{i:03}.key")),
                "x"
            ));
        }
        git(&["add", "-f", "."]);
        let prepared = prepare(std::slice::from_ref(&root), Path::new(SYSTEM_GIT));
        assert_eq!(prepared.tracked.len(), 128);
        assert_eq!(prepared.notes, [GuardNote::TrackedBeyondLimit { count: 2 }]);
    }

    #[test]
    fn the_notes_say_what_it_costs() {
        assert!(
            GuardNote::ScanIncomplete
                .to_string()
                .contains("node_modules")
        );
        assert!(GuardNote::GitFailed.to_string().contains("stay denied"));
        assert_eq!(
            GuardNote::TrackedBeyondLimit { count: 3 }.to_string(),
            "3 tracked files with secret-like names stay denied: the guard re-allows at most 128"
        );
    }
}
