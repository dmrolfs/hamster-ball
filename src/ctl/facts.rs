// ABOUTME: The filesystem side of preflight: a no-follow component walk of each bind source, and podman volume lookups.
// ABOUTME: Strict by design: the exact bytes podman stores must be a real, non-symlink path inside the project.
//! Real [`Facts`] (hb-ghd.8.2).

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use super::preflight::{Facts, MountSource, SourceKind, SourceProblem, VolumeFacts};
use crate::policy::CanonicalPath;

/// Looks at the real filesystem; volumes come from a callback so the broker owns the podman call.
pub struct Disk<V> {
    volume: V,
}

impl<V: Fn(&str) -> Result<VolumeFacts, String>> Disk<V> {
    /// Facts from the disk, and `volume` to inspect one volume.
    pub fn new(volume: V) -> Self {
        Self { volume }
    }
}

impl<V: Fn(&str) -> Result<VolumeFacts, String>> Facts for Disk<V> {
    fn bind_source(
        &self,
        path: &str,
        project: &CanonicalPath,
    ) -> Result<MountSource, SourceProblem> {
        examine(path, project)
    }

    fn volume(&self, name: &str) -> Result<VolumeFacts, String> {
        (self.volume)(name)
    }
}

fn unreadable(error: &io::Error) -> SourceProblem {
    SourceProblem::Examine {
        detail: error.to_string(),
    }
}

/// Walk `path` one component at a time without following links, then compare the OS's own
/// resolution with the exact spelling (a case, Unicode or firmlink difference is a refusal).
pub(crate) fn examine(path: &str, project: &CanonicalPath) -> Result<MountSource, SourceProblem> {
    let canonical = CanonicalPath::from_canonical(path).map_err(|_| SourceProblem::Malformed)?;
    if !project.is_same_or_ancestor_of(&canonical) {
        return Err(SourceProblem::OutsideProject);
    }
    let mut walked = PathBuf::from("/");
    let mut last = None;
    for component in Path::new(path).components() {
        if let Component::Normal(part) = component {
            walked.push(part);
            let meta = match fs::symlink_metadata(&walked) {
                Ok(m) => m,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    return Err(SourceProblem::Missing);
                }
                Err(e) => return Err(unreadable(&e)),
            };
            if meta.file_type().is_symlink() {
                return Err(SourceProblem::Symlink {
                    at: walked.to_string_lossy().into_owned(),
                });
            }
            last = Some(meta);
        }
    }
    let meta = last.ok_or(SourceProblem::Malformed)?;
    let kind = if meta.is_dir() {
        SourceKind::Directory
    } else if meta.is_file() {
        if meta.nlink() > 1 {
            return Err(SourceProblem::HardLinked);
        }
        SourceKind::File
    } else {
        return Err(SourceProblem::SpecialFile);
    };
    let real = fs::canonicalize(path).map_err(|e| unreadable(&e))?;
    if real != Path::new(path) {
        return Err(SourceProblem::Respelled {
            real: real.to_string_lossy().into_owned(),
        });
    }
    Ok(MountSource {
        path: canonical,
        kind,
    })
}

/// Reads `podman volume inspect --format json` output for one volume.
///
/// # Errors
/// A short reason when the text is not exactly one volume record.
pub fn parse_volume(json: &str) -> Result<VolumeFacts, String> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Raw {
        name: String,
        driver: String,
        #[serde(default)]
        options: Option<std::collections::BTreeMap<String, String>>,
    }
    let mut raw: Vec<Raw> = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if raw.len() != 1 {
        return Err(format!("expected one volume, found {}", raw.len()));
    }
    let raw = raw.remove(0);
    Ok(VolumeFacts {
        name: raw.name,
        driver: raw.driver,
        has_options: raw.options.is_some_and(|o| !o.is_empty()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Tree, canonical};
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::symlink;

    fn world() -> (Tree, CanonicalPath, PathBuf) {
        let tree = Tree::new();
        let root = tree.inside_home("proj");
        assert_ok!(fs::create_dir_all(root.join("var/data")));
        assert_ok!(fs::write(root.join("cfg.yaml"), "a"));
        let project = canonical(&root);
        let base = PathBuf::from(project.as_str());
        (tree, project, base)
    }

    fn s(p: &Path) -> String {
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn test_real_files_and_directories_inside_the_project_are_accepted_with_their_kind() {
        let (_t, project, base) = world();
        let dir = assert_ok!(examine(&s(&base.join("var/data")), &project));
        assert_eq!(dir.kind, SourceKind::Directory);
        let file = assert_ok!(examine(&s(&base.join("cfg.yaml")), &project));
        assert_eq!(file.kind, SourceKind::File);
        assert_eq!(
            assert_ok!(examine(&s(&base), &project)).kind,
            SourceKind::Directory
        );
    }

    #[test]
    fn test_a_symlink_anywhere_in_the_path_is_refused_and_named() {
        let (_t, project, base) = world();
        assert_ok!(symlink(base.join("var"), base.join("alias")));
        let err = assert_err!(examine(&s(&base.join("alias/data")), &project));
        assert!(
            matches!(&err, SourceProblem::Symlink { at } if at.ends_with("/alias")),
            "{err:?}"
        );
        assert_ok!(symlink("/etc", base.join("etc-link")));
        assert!(matches!(
            assert_err!(examine(&s(&base.join("etc-link")), &project)),
            SourceProblem::Symlink { .. }
        ));
    }

    #[test]
    fn test_outside_missing_special_and_hard_linked_sources_are_refused() {
        let (tree, project, base) = world();
        let outside = tree.outside("o");
        assert_eq!(
            assert_err!(examine(&s(&outside), &project)),
            SourceProblem::OutsideProject
        );
        assert_eq!(
            assert_err!(examine(&s(&base.join("nope")), &project)),
            SourceProblem::Missing
        );
        assert_eq!(
            assert_err!(examine("relative/x", &project)),
            SourceProblem::Malformed
        );
        assert_ok!(fs::hard_link(
            base.join("cfg.yaml"),
            base.join("alias.yaml")
        ));
        assert_eq!(
            assert_err!(examine(&s(&base.join("cfg.yaml")), &project)),
            SourceProblem::HardLinked
        );
        assert_eq!(
            assert_err!(examine("/dev/null", &project)),
            SourceProblem::OutsideProject
        );
        // a sibling that only shares a string prefix with the project is outside it
        let sibling = PathBuf::from(format!("{}2", project.as_str()));
        assert_ok!(fs::create_dir_all(&sibling));
        assert_eq!(
            assert_err!(examine(&s(&sibling), &project)),
            SourceProblem::OutsideProject
        );
    }

    #[test]
    fn test_a_spelling_that_differs_from_the_real_path_is_refused_with_the_real_one() {
        let (_t, project, base) = world();
        // APFS is case-insensitive here, so a differently cased name opens the same directory;
        // podman would store the odd spelling, and a pin on it would not match the real name.
        let odd = base.join("VAR/Data");
        let real = base.join("var/data");
        if !odd.exists() {
            return; // a case-sensitive volume: no such alias can exist
        }
        let err = assert_err!(examine(&s(&odd), &project));
        assert!(
            matches!(&err, SourceProblem::Respelled { real: r } if r == &s(&real)),
            "{err:?}"
        );
        // a firmlink spelling of an existing directory is another name for it
        let firm = format!("/System/Volumes/Data{}", s(&real));
        if Path::new(&firm).exists() {
            assert_err!(examine(&firm, &project), "{firm}");
        }
    }

    #[test]
    fn test_a_socket_inside_the_project_is_special() {
        let (_t, project, base) = world();
        let sock = base.join("s.sock");
        let _listener = assert_ok!(std::os::unix::net::UnixListener::bind(&sock));
        assert_eq!(
            assert_err!(examine(&s(&sock), &project)),
            SourceProblem::SpecialFile
        );
    }

    #[test]
    fn test_volume_json_is_read_as_driver_and_whether_it_has_options() {
        let plain = r#"[{"Name":"v","Driver":"local","Options":{}}]"#;
        assert_eq!(
            assert_ok!(parse_volume(plain)),
            VolumeFacts {
                name: "v".into(),
                driver: "local".into(),
                has_options: false
            }
        );
        let null = r#"[{"Name":"v","Driver":"local","Options":null}]"#;
        assert!(!assert_ok!(parse_volume(null)).has_options);
        let device = r#"[{"Name":"v","Driver":"local","Options":{"device":"/Users/x","o":"bind","type":"none"}}]"#;
        assert!(assert_ok!(parse_volume(device)).has_options);
        for bad in ["", "[]", "{}", "[{},{}]"] {
            assert_err!(parse_volume(bad));
        }
    }
}
