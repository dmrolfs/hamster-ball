// ABOUTME: The approval store: one owner-only record per project root under the state directory.
// ABOUTME: A record that cannot be trusted (wrong owner, writable by others, unreadable, malformed) counts as no approval.
//! The approval store (design section 5).
//!
//! `<state>/approvals/<sha256 of the canonical root>.toml`, mode 0600, in a directory of mode 0700.
//! The floor keeps the hamster ball out of the state directory; the checks here are for a record
//! some other process put there. They fail closed: the answer is "not approved, because ...",
//! never a skipped check.

use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::libc;
use nix::unistd::getuid;
use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu, ensure};

use super::digest::{Digest, FileDigest, Fingerprint};
use crate::policy::CanonicalPath;
use crate::system::StateDir;

/// The record layout this version writes and reads.
const FORMAT: u32 = 1;
/// A record larger than this is not one of ours.
const MAX_RECORD_BYTES: u64 = 256 * 1024;
/// Group and other write bits.
const OTHERS_WRITE: u32 = 0o022;

/// Whether the config closure of a project is approved.
#[derive(Debug)]
#[non_exhaustive]
pub enum Standing {
    /// The stored closure digest equals the current one.
    Approved,
    /// It is not, and why.
    Unapproved(Why),
}

/// Why a closure is not approved.
#[derive(Debug)]
#[non_exhaustive]
pub enum Why {
    /// No record for this project root.
    NeverApproved,
    /// A record exists and the files differ from it.
    Changed(Changes),
    /// A record or the store could not be trusted.
    Unusable(RecordProblem),
}

impl fmt::Display for Why {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NeverApproved => f.write_str("this project's config has not been approved"),
            Self::Changed(changes) => write!(
                f,
                "this project's config changed since it was approved ({changes})"
            ),
            Self::Unusable(problem) => write!(
                f,
                "this project's approval cannot be used, so it counts as not approved: {problem}"
            ),
        }
    }
}

/// What differs between an approved closure and the current one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Files that were not there when approved.
    pub added: Vec<String>,
    /// Files whose bytes differ.
    pub changed: Vec<String>,
    /// Files that were approved and are no longer in the closure.
    pub removed: Vec<String>,
}

impl Changes {
    fn between(approved: &[FileDigest], now: &[FileDigest]) -> Self {
        let digest_of = |files: &[FileDigest], path: &str| {
            files.iter().find(|f| f.path == path).map(|f| f.sha256)
        };
        let mut changes = Self::default();
        for file in now {
            match digest_of(approved, &file.path) {
                None => changes.added.push(file.path.clone()),
                Some(old) if old != file.sha256 => changes.changed.push(file.path.clone()),
                Some(_) => {}
            }
        }
        for file in approved {
            if digest_of(now, &file.path).is_none() {
                changes.removed.push(file.path.clone());
            }
        }
        changes
    }
}

impl fmt::Display for Changes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        for (label, paths) in [
            ("changed", &self.changed),
            ("new", &self.added),
            ("removed", &self.removed),
        ] {
            if !paths.is_empty() {
                parts.push(format!("{label}: {}", paths.join(", ")));
            }
        }
        if parts.is_empty() {
            f.write_str("the order of the files changed")
        } else {
            f.write_str(&parts.join("; "))
        }
    }
}

/// Why a stored record or the store directory cannot be trusted.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RecordProblem {
    /// It could not be read.
    #[snafu(display("{} could not be read", path.display()))]
    Unreadable {
        /// The path.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// It is not a plain file or directory of the expected kind (a link, for example).
    #[snafu(display("{} is not a regular {expected}", path.display()))]
    WrongKind {
        /// The path.
        path: PathBuf,
        /// `file` or `directory`.
        expected: &'static str,
    },

    /// Someone else owns it.
    #[snafu(display("{} is owned by user {owner}, not by you", path.display()))]
    NotYours {
        /// The path.
        path: PathBuf,
        /// The owning uid.
        owner: u32,
    },

    /// Others could write it.
    #[snafu(display("{} is writable by others (mode {mode:o})", path.display()))]
    Writable {
        /// The path.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },

    /// It is far larger than any record.
    #[snafu(display("{} is larger than {MAX_RECORD_BYTES} bytes", path.display()))]
    TooLarge {
        /// The path.
        path: PathBuf,
    },

    /// It is not valid TOML of the record's shape.
    #[snafu(display("{} is not a valid approval record", path.display()))]
    Malformed {
        /// The path.
        path: PathBuf,
        /// The parse error.
        source: toml::de::Error,
    },

    /// A format this version does not know.
    #[snafu(display("{} has format {format}, and this version reads format {FORMAT}", path.display()))]
    UnknownFormat {
        /// The path.
        path: PathBuf,
        /// The format it names.
        format: u32,
    },

    /// A digest that is not 64 hex digits.
    #[snafu(display("{} has a malformed digest", path.display()))]
    BadDigest {
        /// The path.
        path: PathBuf,
    },

    /// It belongs to another project root.
    #[snafu(display("{} records another project: {recorded}", path.display()))]
    OtherRoot {
        /// The path.
        path: PathBuf,
        /// The root the record names.
        recorded: String,
    },
}

/// Why the store could not be changed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum StoreError {
    /// A directory could not be created.
    #[snafu(display("cannot create {}", path.display()))]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// The store directory exists and cannot be trusted.
    #[snafu(display("the approval store cannot be used"))]
    Untrusted {
        /// What is wrong with it.
        source: RecordProblem,
    },

    /// The record could not be written.
    #[snafu(display("cannot write {}", path.display()))]
    Write {
        /// The file.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// The record could not be put in place.
    #[snafu(display("cannot move the new record to {}", path.display()))]
    Replace {
        /// The final path.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// The record could not be removed.
    #[snafu(display("cannot remove {}", path.display()))]
    Remove {
        /// The file.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// The record could not be serialized.
    #[snafu(display("cannot serialize the approval record"))]
    Serialize {
        /// The serializer's error.
        source: toml::ser::Error,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    format: u32,
    root: String,
    closure_sha256: String,
    files: Vec<RecordFile>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecordFile {
    path: String,
    sha256: String,
}

/// The approvals kept under one state directory.
#[derive(Debug, Clone)]
pub struct ApprovalStore {
    state: PathBuf,
    dir: PathBuf,
}

impl ApprovalStore {
    /// The store under `state`. Performs no I/O.
    #[must_use]
    pub fn new(state: &StateDir) -> Self {
        Self {
            state: state.dir().to_path_buf(),
            dir: state.dir().join("approvals"),
        }
    }

    fn record_path(&self, root: &CanonicalPath) -> PathBuf {
        self.dir
            .join(format!("{}.toml", Digest::of(root.as_str().as_bytes())))
    }

    /// Whether `now` is what was approved for `root`.
    #[must_use]
    pub fn standing(&self, root: &CanonicalPath, now: &Fingerprint) -> Standing {
        match fs::symlink_metadata(&self.dir) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Standing::Unapproved(Why::NeverApproved);
            }
            Err(source) => {
                return unusable(RecordProblem::Unreadable {
                    path: self.dir.clone(),
                    source,
                });
            }
            Ok(_) => {}
        }
        if let Err(problem) = check_dir(&self.dir) {
            return unusable(problem);
        }
        let path = self.record_path(root);
        let stored = match read_record(&path, root) {
            Ok(Some(stored)) => stored,
            Ok(None) => return Standing::Unapproved(Why::NeverApproved),
            Err(problem) => return unusable(problem),
        };
        if stored.closure() == now.closure() {
            Standing::Approved
        } else {
            Standing::Unapproved(Why::Changed(Changes::between(stored.files(), now.files())))
        }
    }

    /// Records `now` as approved for `root`, replacing any earlier record.
    ///
    /// # Errors
    /// See [`StoreError`].
    pub fn approve(&self, root: &CanonicalPath, now: &Fingerprint) -> Result<(), StoreError> {
        self.ensure_dir()?;
        let record = Record {
            format: FORMAT,
            root: root.as_str().to_owned(),
            closure_sha256: now.closure().to_string(),
            files: now
                .files()
                .iter()
                .map(|f| RecordFile {
                    path: f.path.clone(),
                    sha256: f.sha256.to_string(),
                })
                .collect(),
        };
        let text = toml::to_string(&record).context(SerializeSnafu)?;
        let path = self.record_path(root);
        let temp = self.dir.join(format!(
            ".{}.{}",
            std::process::id(),
            Digest::of(text.as_bytes())
        ));
        write_new(&temp, text.as_bytes()).context(WriteSnafu { path: temp.clone() })?;
        fs::rename(&temp, &path).with_context(|_| {
            let _ = fs::remove_file(&temp);
            ReplaceSnafu { path: path.clone() }
        })
    }

    /// Removes the record for `root`. `true` if there was one.
    ///
    /// # Errors
    /// See [`StoreError`].
    pub fn revoke(&self, root: &CanonicalPath) -> Result<bool, StoreError> {
        let path = self.record_path(root);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(StoreError::Remove { path, source }),
        }
    }

    fn ensure_dir(&self) -> Result<(), StoreError> {
        if let Some(parent) = self.state.parent() {
            fs::create_dir_all(parent).context(CreateDirSnafu { path: parent })?;
        }
        for dir in [&self.state, &self.dir] {
            match DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(StoreError::CreateDir {
                        path: dir.clone(),
                        source,
                    });
                }
            }
        }
        check_dir(&self.dir).context(UntrustedSnafu)
    }
}

fn unusable(problem: RecordProblem) -> Standing {
    Standing::Unapproved(Why::Unusable(problem))
}

/// The directory is ours, a real directory, and not writable by others.
fn check_dir(path: &Path) -> Result<(), RecordProblem> {
    let metadata = fs::symlink_metadata(path).context(UnreadableSnafu { path })?;
    ensure!(
        metadata.is_dir(),
        WrongKindSnafu {
            path,
            expected: "directory"
        }
    );
    check_owner_and_mode(path, &metadata)
}

fn check_owner_and_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), RecordProblem> {
    ensure!(
        metadata.uid() == getuid().as_raw(),
        NotYoursSnafu {
            path,
            owner: metadata.uid()
        }
    );
    ensure!(
        metadata.mode() & OTHERS_WRITE == 0,
        WritableSnafu {
            path,
            mode: metadata.mode() & 0o7777
        }
    );
    Ok(())
}

/// The record at `path`, `None` when there is none.
fn read_record(path: &Path, root: &CanonicalPath) -> Result<Option<Fingerprint>, RecordProblem> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(RecordProblem::Unreadable {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let metadata = file.metadata().context(UnreadableSnafu { path })?;
    ensure!(
        metadata.is_file(),
        WrongKindSnafu {
            path,
            expected: "file"
        }
    );
    check_owner_and_mode(path, &metadata)?;
    ensure!(metadata.len() <= MAX_RECORD_BYTES, TooLargeSnafu { path });
    let mut text = String::new();
    file.take(MAX_RECORD_BYTES)
        .read_to_string(&mut text)
        .context(UnreadableSnafu { path })?;
    let record: Record = toml::from_str(&text).context(MalformedSnafu { path })?;
    ensure!(
        record.format == FORMAT,
        UnknownFormatSnafu {
            path,
            format: record.format
        }
    );
    ensure!(
        record.root == root.as_str(),
        OtherRootSnafu {
            path,
            recorded: record.root.clone()
        }
    );
    let bad = || RecordProblem::BadDigest {
        path: path.to_path_buf(),
    };
    let closure = Digest::from_hex(&record.closure_sha256).ok_or_else(bad)?;
    let files = record
        .files
        .iter()
        .map(|f| {
            Digest::from_hex(&f.sha256).map(|sha256| FileDigest {
                path: f.path.clone(),
                sha256,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(bad)?;
    Ok(Some(Fingerprint::from_parts(files, closure)))
}

/// Writes `bytes` to a new file of mode 0600 and syncs it.
///
/// `create_new` is `O_EXCL`, which also refuses a link planted at `path`.
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file: File = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HomeDir;
    use claims::{assert_err, assert_matches, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        store: ApprovalStore,
        root: CanonicalPath,
    }

    fn canonical(path: &Path) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
            path
        ))))
    }

    fn fixture() -> Fixture {
        let dir = assert_ok!(tempfile::tempdir());
        let home = HomeDir::new(canonical(dir.path()));
        Fixture {
            store: ApprovalStore::new(&StateDir::locate(&home)),
            root: canonical(dir.path()),
            _dir: dir,
        }
    }

    fn print(files: &[(&str, &str)]) -> Fingerprint {
        Fingerprint::from_files(files.iter().map(|(p, b)| ((*p).to_owned(), b.as_bytes())))
    }

    fn mode(path: &Path) -> u32 {
        assert_ok!(fs::metadata(path)).permissions().mode() & 0o7777
    }

    fn record_file(f: &Fixture) -> PathBuf {
        f.store.record_path(&f.root)
    }

    fn assert_unusable(standing: Standing) -> Option<RecordProblem> {
        match standing {
            Standing::Unapproved(Why::Unusable(problem)) => Some(problem),
            _ => None,
        }
    }

    fn changes_of(standing: Standing) -> Option<Changes> {
        match standing {
            Standing::Unapproved(Why::Changed(changes)) => Some(changes),
            _ => None,
        }
    }

    #[test]
    fn with_no_record_a_project_was_never_approved() {
        let f = fixture();
        assert_matches!(
            f.store.standing(&f.root, &print(&[("/p/a.toml", "x")])),
            Standing::Unapproved(Why::NeverApproved)
        );
    }

    #[test]
    fn an_approved_closure_stays_approved_for_the_same_bytes() {
        let f = fixture();
        let now = print(&[("/p/a.toml", "x"), ("/p/b.toml", "y")]);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_matches!(
            f.store
                .standing(&f.root, &print(&[("/p/a.toml", "x"), ("/p/b.toml", "y")])),
            Standing::Approved
        );
    }

    #[test]
    fn a_closure_with_no_approval_files_can_be_approved() {
        let f = fixture();
        assert_ok!(f.store.approve(&f.root, &print(&[])));
        assert_matches!(f.store.standing(&f.root, &print(&[])), Standing::Approved);
    }

    #[test]
    fn a_change_names_the_files_that_changed_were_added_or_were_removed() {
        let f = fixture();
        assert_ok!(f.store.approve(
            &f.root,
            &print(&[("/p/a.toml", "x"), ("/p/b.toml", "y"), ("/p/c.toml", "z")])
        ));
        let now = print(&[("/p/a.toml", "x2"), ("/p/c.toml", "z"), ("/p/d.toml", "w")]);
        let changes = assert_some!(changes_of(f.store.standing(&f.root, &now)));
        assert_eq!(
            changes,
            Changes {
                added: vec!["/p/d.toml".into()],
                changed: vec!["/p/a.toml".into()],
                removed: vec!["/p/b.toml".into()],
            }
        );
        assert_eq!(
            changes.to_string(),
            "changed: /p/a.toml; new: /p/d.toml; removed: /p/b.toml"
        );
    }

    #[test]
    fn a_reordered_closure_is_not_approved_and_says_so() {
        let f = fixture();
        assert_ok!(
            f.store
                .approve(&f.root, &print(&[("/p/a", "x"), ("/p/b", "y")]))
        );
        let changes = assert_some!(changes_of(
            f.store
                .standing(&f.root, &print(&[("/p/b", "y"), ("/p/a", "x")]))
        ));
        assert_eq!(changes.to_string(), "the order of the files changed");
    }

    #[test]
    fn approval_belongs_to_the_project_root() {
        let f = fixture();
        let now = print(&[("/p/a.toml", "x")]);
        assert_ok!(f.store.approve(&f.root, &now));
        let moved = canonical(&assert_ok!(
            fs::create_dir(f._dir.path().join("moved")).map(|()| f._dir.path().join("moved"))
        ));
        assert_matches!(
            f.store.standing(&moved, &now),
            Standing::Unapproved(Why::NeverApproved)
        );
    }

    #[test]
    fn approving_again_replaces_the_record() {
        let f = fixture();
        assert_ok!(f.store.approve(&f.root, &print(&[("/p/a", "x")])));
        assert_ok!(f.store.approve(&f.root, &print(&[("/p/a", "y")])));
        assert_matches!(
            f.store.standing(&f.root, &print(&[("/p/a", "y")])),
            Standing::Approved
        );
        assert_matches!(
            f.store.standing(&f.root, &print(&[("/p/a", "x")])),
            Standing::Unapproved(Why::Changed(_))
        );
    }

    #[test]
    fn revoking_removes_the_approval_and_says_whether_there_was_one() {
        let f = fixture();
        let now = print(&[("/p/a", "x")]);
        assert_eq!(assert_ok!(f.store.revoke(&f.root)), false);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_eq!(assert_ok!(f.store.revoke(&f.root)), true);
        assert_eq!(assert_ok!(f.store.revoke(&f.root)), false);
        assert_matches!(
            f.store.standing(&f.root, &now),
            Standing::Unapproved(Why::NeverApproved)
        );
    }

    #[test]
    fn the_store_is_owner_only_and_leaves_no_temporary_files() {
        let f = fixture();
        assert_ok!(f.store.approve(&f.root, &print(&[("/p/a", "x")])));
        assert_eq!(mode(&f.store.dir), 0o700);
        assert_eq!(mode(&f.store.state), 0o700);
        assert_eq!(mode(&record_file(&f)), 0o600);
        let names: Vec<_> = assert_ok!(fs::read_dir(&f.store.dir))
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
    }

    #[test]
    fn a_record_that_is_not_toml_counts_as_no_approval() {
        let f = fixture();
        let now = print(&[("/p/a", "x")]);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_ok!(fs::write(record_file(&f), "not = [valid"));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::Malformed { .. })
        );
    }

    fn rewrite(f: &Fixture, edit: impl Fn(String) -> String) {
        let path = record_file(f);
        let text = assert_ok!(fs::read_to_string(&path));
        assert_ok!(fs::write(&path, edit(text)));
    }

    #[test]
    fn a_record_of_an_unknown_format_or_with_a_bad_digest_or_for_another_root_is_refused() {
        let f = fixture();
        let now = print(&[("/p/a", "x")]);
        assert_ok!(f.store.approve(&f.root, &now));
        let good = assert_ok!(fs::read_to_string(record_file(&f)));

        rewrite(&f, |t| t.replace("format = 1", "format = 2"));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::UnknownFormat { format: 2, .. })
        );

        assert_ok!(fs::write(record_file(&f), &good));
        rewrite(&f, |t| t.replace(&now.closure().to_string(), "zz"));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::BadDigest { .. })
        );

        assert_ok!(fs::write(record_file(&f), &good));
        rewrite(&f, |t| t.replace(f.root.as_str(), "/elsewhere"));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::OtherRoot { .. })
        );
    }

    #[test]
    fn a_record_others_can_write_counts_as_no_approval() {
        let f = fixture();
        let now = print(&[("/p/a", "x")]);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_ok!(fs::set_permissions(
            record_file(&f),
            fs::Permissions::from_mode(0o666)
        ));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::Writable { .. })
        );
    }

    #[test]
    fn a_record_that_is_a_symlink_counts_as_no_approval() {
        let f = fixture();
        let now = print(&[("/p/a", "x")]);
        assert_ok!(f.store.approve(&f.root, &now));
        let real = f.store.dir.join("real");
        assert_ok!(fs::rename(record_file(&f), &real));
        assert_ok!(symlink(&real, record_file(&f)));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::Unreadable { .. })
        );
    }

    #[test]
    fn a_store_directory_others_can_write_counts_as_no_approval_and_cannot_be_approved_into() {
        let f = fixture();
        let now = print(&[("/p/a", "x")]);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_ok!(fs::set_permissions(
            &f.store.dir,
            fs::Permissions::from_mode(0o775)
        ));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::Writable { .. })
        );
        assert_matches!(
            assert_err!(f.store.approve(&f.root, &now)),
            StoreError::Untrusted { .. }
        );
    }

    #[test]
    fn a_store_directory_that_is_a_symlink_counts_as_no_approval() {
        let f = fixture();
        let elsewhere = f._dir.path().join("elsewhere");
        assert_ok!(fs::create_dir_all(&f.store.state));
        assert_ok!(fs::create_dir(&elsewhere));
        assert_ok!(symlink(&elsewhere, &f.store.dir));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &print(&[]))),
            Some(RecordProblem::WrongKind { .. })
        );
    }

    #[test]
    fn a_record_with_many_long_paths_is_still_read() {
        let f = fixture();
        let long = "d".repeat(200);
        let paths: Vec<String> = (0..16).map(|i| format!("/{long}/{i}.toml")).collect();
        let now = Fingerprint::from_files(paths.iter().map(|p| (p.clone(), b"x".as_slice())));
        assert_ok!(f.store.approve(&f.root, &now));
        assert!(assert_ok!(fs::metadata(record_file(&f))).len() > 4096);
        assert_matches!(f.store.standing(&f.root, &now), Standing::Approved);
    }

    #[test]
    fn a_record_that_is_a_fifo_is_refused_at_once_instead_of_waiting_for_a_writer() {
        let f = fixture();
        let now = print(&[]);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_ok!(fs::remove_file(record_file(&f)));
        let made = assert_ok!(
            std::process::Command::new("/usr/bin/mkfifo")
                .arg(record_file(&f))
                .status()
        );
        assert!(made.success());
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::WrongKind { .. })
        );
    }

    #[test]
    fn a_state_directory_that_cannot_be_looked_into_is_unusable_not_a_missing_approval() {
        let f = fixture();
        let now = print(&[]);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_ok!(fs::set_permissions(
            &f.store.state,
            fs::Permissions::from_mode(0o000)
        ));
        let standing = f.store.standing(&f.root, &now);
        assert_ok!(fs::set_permissions(
            &f.store.state,
            fs::Permissions::from_mode(0o700)
        ));
        assert_matches!(
            assert_unusable(standing),
            Some(RecordProblem::Unreadable { .. })
        );
    }

    #[test]
    fn revoking_where_the_record_cannot_be_removed_is_an_error_not_a_denial_that_it_existed() {
        let f = fixture();
        assert_ok!(f.store.approve(&f.root, &print(&[])));
        assert_ok!(fs::set_permissions(
            &f.store.dir,
            fs::Permissions::from_mode(0o500)
        ));
        let result = f.store.revoke(&f.root);
        assert_ok!(fs::set_permissions(
            &f.store.dir,
            fs::Permissions::from_mode(0o700)
        ));
        assert_matches!(assert_err!(result), StoreError::Remove { .. });
        assert_eq!(assert_ok!(f.store.revoke(&f.root)), true);
    }

    #[test]
    fn approving_where_the_store_cannot_be_created_says_so() {
        let f = fixture();
        let local = f._dir.path().join(".local/state");
        assert_ok!(fs::create_dir_all(&local));
        assert_ok!(fs::set_permissions(
            &local,
            fs::Permissions::from_mode(0o500)
        ));
        let result = f.store.approve(&f.root, &print(&[]));
        assert_ok!(fs::set_permissions(
            &local,
            fs::Permissions::from_mode(0o700)
        ));
        assert_matches!(assert_err!(result), StoreError::CreateDir { .. });
    }

    #[test]
    fn a_record_of_any_size_beyond_the_cap_is_refused_without_reading_it() {
        let f = fixture();
        let now = print(&[]);
        assert_ok!(f.store.approve(&f.root, &now));
        assert_ok!(fs::write(
            record_file(&f),
            vec![b'#'; (MAX_RECORD_BYTES + 1) as usize]
        ));
        assert_matches!(
            assert_unusable(f.store.standing(&f.root, &now)),
            Some(RecordProblem::TooLarge { .. })
        );
    }
}
