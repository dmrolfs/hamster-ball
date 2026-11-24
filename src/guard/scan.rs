// ABOUTME: Walks the guard roots on the host and finds the directories that hold guarded files, so they can be pinned.
// ABOUTME: Skips dependency and build directories and stops at a cap; an incomplete scan switches the dependency exemption off.
//! The host-side scan (design section 8).
//!
//! The dependency-directory exemption lets an agent install packages whose files have guarded
//! names, but a directory rename is not stopped by a deny on the files inside it: without more,
//! `mv certs node_modules/x/certs` would put a key where the exemption reads it. So every
//! directory that holds a guarded file, and every directory above it up to its root, is pinned
//! against rename and delete. A directory that gains its first guarded file after the scan is
//! not pinned; that is the residual the design states.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use super::patterns::{is_guarded, is_template};
use crate::policy::CanonicalPath;

/// Directories not walked: dependencies and build output. The walk would otherwise cost seconds
/// in a large tree (2.6 s over 105,000 files with `target`, 26 ms without).
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "site-packages",
    ".venv",
    "venv",
    "target",
];

/// How much a scan may do before it gives up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanLimits {
    /// Most directory entries looked at, over all roots.
    pub max_entries: usize,
    /// Most directories pinned.
    pub max_pins: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_pins: 256,
        }
    }
}

/// What the scan found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scan {
    /// Directories to pin, sorted: each holds a guarded file or is above one that does.
    pub pins: Vec<CanonicalPath>,
    /// How many guarded files were found outside the skipped directories.
    pub matches: usize,
    /// Whether the walk covered everything. Pins are only trustworthy when it did.
    pub complete: bool,
}

/// Calls `visit(directory, name)` for each regular file below `roots`, skipping the dependency and
/// build directories and not following symbolic links. `false` when it stopped at `max_entries`
/// or met a name that is not text, so the visit was not complete.
pub(crate) fn walk_files(
    roots: &[CanonicalPath],
    max_entries: usize,
    mut visit: impl FnMut(&CanonicalPath, &Path, &str) -> bool,
) -> bool {
    let mut entries = 0;
    for root in roots {
        let mut stack = vec![root.as_path().to_path_buf()];
        while let Some(dir) = stack.pop() {
            let Ok(listing) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in listing.flatten() {
                entries += 1;
                if entries > max_entries {
                    return false;
                }
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                let name = entry.file_name();
                let Some(name) = name.to_str() else {
                    // A name that is not text cannot be matched here, and could be a secret.
                    return false;
                };
                if kind.is_dir() {
                    if !SKIPPED_DIRS.contains(&name) {
                        stack.push(entry.path());
                    }
                } else if kind.is_file() && !visit(root, &dir, name) {
                    return false;
                }
            }
        }
    }
    true
}

/// Walks each of `roots` (symbolic links are not followed).
#[must_use]
pub fn scan(roots: &[CanonicalPath], limits: ScanLimits) -> Scan {
    let mut pins: BTreeSet<PathBuf> = BTreeSet::new();
    let mut matches = 0;
    let mut room = true;
    let walked = walk_files(roots, limits.max_entries, |root, dir, name| {
        if is_guarded(name) && !is_template(name) {
            matches += 1;
            for ancestor in dir.ancestors() {
                pins.insert(ancestor.to_path_buf());
                if ancestor == root.as_path() {
                    break;
                }
            }
            room = pins.len() <= limits.max_pins;
        }
        room
    });
    Scan {
        pins: pins
            .into_iter()
            .filter_map(|path| CanonicalPath::from_canonical(path).ok())
            .collect(),
        matches,
        complete: walked && room,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn root() -> (TempDir, CanonicalPath) {
        let dir = assert_ok!(tempfile::tempdir());
        let path = assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
            dir.path()
        ))));
        (dir, path)
    }

    fn touch(root: &CanonicalPath, relative: &str) {
        let path = root.as_path().join(relative);
        if let Some(parent) = path.parent() {
            assert_ok!(fs::create_dir_all(parent));
        }
        assert_ok!(fs::write(path, "x"));
    }

    fn shown(root: &CanonicalPath, scan: &Scan) -> Vec<String> {
        scan.pins
            .iter()
            .map(|p| {
                p.as_str()
                    .strip_prefix(root.as_str())
                    .unwrap_or(p.as_str())
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn a_tree_with_nothing_guarded_has_no_pins_and_is_complete() {
        let (_dir, root) = root();
        touch(&root, "src/main.rs");
        touch(&root, "README.md");
        let scan = scan(&[root], ScanLimits::default());
        assert_eq!(scan.pins, Vec::<CanonicalPath>::new());
        assert_eq!((scan.matches, scan.complete), (0, true));
    }

    #[test]
    fn a_guarded_file_pins_its_directory_and_every_directory_above_it_up_to_the_root() {
        let (_dir, root) = root();
        touch(&root, "a/b/c/prod.secrets.yaml");
        touch(&root, "certs/server.key");
        touch(&root, "plain/readme.txt");
        let scan = scan(std::slice::from_ref(&root), ScanLimits::default());
        assert_eq!(shown(&root, &scan), ["", "/a", "/a/b", "/a/b/c", "/certs"]);
        assert_eq!((scan.matches, scan.complete), (2, true));
    }

    #[test]
    fn a_guarded_file_directly_in_the_root_pins_the_root() {
        let (_dir, root) = root();
        touch(&root, ".env");
        let scan = scan(std::slice::from_ref(&root), ScanLimits::default());
        assert_eq!(shown(&root, &scan), [""]);
    }

    #[test]
    fn templates_are_not_matches() {
        let (_dir, root) = root();
        touch(&root, "cfg/.env.example");
        touch(&root, "cfg/server.pem.sample");
        let scan = scan(&[root], ScanLimits::default());
        assert_eq!((scan.matches, scan.pins.len()), (0, 0));
    }

    #[test]
    fn dependency_and_build_directories_are_not_walked() {
        let (_dir, root) = root();
        for dir in [
            "node_modules",
            "x/site-packages",
            ".venv",
            "venv",
            "target",
            ".git",
        ] {
            touch(&root, &format!("{dir}/pkg/cert.pem"));
        }
        let scan = scan(&[root], ScanLimits::default());
        assert_eq!((scan.matches, scan.pins.len(), scan.complete), (0, 0, true));
    }

    #[test]
    fn a_symbolic_link_to_a_directory_is_not_followed() {
        let (_dir, root) = root();
        touch(&root, "real/k.key");
        assert_ok!(symlink(
            root.as_path().join("real"),
            root.as_path().join("link")
        ));
        let scan = scan(std::slice::from_ref(&root), ScanLimits::default());
        assert_eq!(shown(&root, &scan), ["", "/real"]);
        assert_eq!(scan.matches, 1);
    }

    #[test]
    fn a_walk_over_the_entry_limit_is_incomplete() {
        let (_dir, root) = root();
        for i in 0..20 {
            touch(&root, &format!("d{i}/f.txt"));
        }
        let limits = ScanLimits {
            max_entries: 10,
            max_pins: 256,
        };
        assert!(!scan(&[root], limits).complete);
    }

    #[test]
    fn a_walk_of_exactly_the_entry_limit_is_complete() {
        let (_dir, root) = root();
        touch(&root, "a.txt");
        touch(&root, "b.txt");
        touch(&root, "c.txt");
        let at = |max_entries| ScanLimits {
            max_entries,
            max_pins: 256,
        };
        assert!(scan(std::slice::from_ref(&root), at(3)).complete);
        assert!(!scan(&[root], at(2)).complete);
    }

    #[test]
    fn exactly_the_pin_limit_is_complete() {
        let (_dir, root) = root();
        touch(&root, "a/k.key");
        let at = |max_pins| ScanLimits {
            max_entries: 1000,
            max_pins,
        };
        // The root and `a`.
        assert!(scan(std::slice::from_ref(&root), at(2)).complete);
        assert!(!scan(&[root], at(1)).complete);
    }

    #[test]
    fn more_pins_than_the_limit_is_incomplete() {
        let (_dir, root) = root();
        for i in 0..6 {
            touch(&root, &format!("d{i}/k.key"));
        }
        let limits = ScanLimits {
            max_entries: 1000,
            max_pins: 3,
        };
        assert!(!scan(&[root], limits).complete);
    }

    #[test]
    fn several_roots_are_each_walked_and_a_missing_one_is_skipped() {
        let (_a, one) = root();
        let (_b, two) = root();
        touch(&one, "x/a.pem");
        touch(&two, "y/b.p12");
        let gone = assert_ok!(CanonicalPath::from_canonical(two.as_path().join("missing")));
        let scan = scan(&[one.clone(), two.clone(), gone], ScanLimits::default());
        assert_eq!(scan.matches, 2);
        assert!(scan.pins.contains(&one) && scan.pins.contains(&two));
    }
}
