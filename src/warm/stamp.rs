// ABOUTME: Warm stamps: a record per project and server that its command was warmed, kept in the state directory the ball cannot read.
// ABOUTME: `hb run` and `hb explain` compare a server's command and arguments with the stamp to say never, warmed or changed.
//! Warm stamps (design 10, hb-ghd.7.3).
//!
//! A stamp is advisory: it only decides whether `hb run` prints a warning. The state directory is
//! denied to the ball, so the agent cannot forge one, and a stamp that cannot be read as one counts
//! as never recorded.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};

use crate::approval::Digest;
use crate::policy::CanonicalPath;
use crate::system::StateDir;

/// The stamp file format.
const FORMAT: u32 = 1;
/// The most a stamp file may hold: it has a handful of short fields.
const MAX_STAMP_BYTES: u64 = 16 * 1024;

/// What the store knows about one server of one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Warmed with this command and these arguments.
    Warmed,
    /// Warmed once, but the command or an argument has changed since.
    Changed,
    /// Never warmed, or the record cannot be used.
    Never,
}

/// Why a stamp could not be written.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum StampError {
    /// The directory could not be created.
    #[snafu(display("could not create {}: {source}", path.display()))]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The stamp could not be serialised.
    #[snafu(display("could not serialise a warm stamp: {source}"))]
    Serialize {
        /// The underlying error.
        source: toml::ser::Error,
    },

    /// The stamp file could not be written.
    #[snafu(display("could not write {}: {source}", path.display()))]
    Write {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Stamp {
    format: u32,
    root: String,
    server: String,
    digest: String,
    warmed_at: u64,
    hb_version: String,
}

/// The digest of a server's command and arguments: SHA-256 over length-prefixed words, so
/// `["a b"]` and `["a", "b"]` differ.
#[must_use]
pub fn digest(command: &str, args: &[&str]) -> String {
    let mut bytes = Vec::new();
    for word in std::iter::once(command).chain(args.iter().copied()) {
        bytes.extend_from_slice(&(word.len() as u64).to_be_bytes());
        bytes.extend_from_slice(word.as_bytes());
    }
    Digest::of(&bytes).to_string()
}

/// The stamps under `<state>/warm`.
#[derive(Debug, Clone)]
pub struct WarmStore {
    state: PathBuf,
    dir: PathBuf,
}

impl WarmStore {
    /// The store under `state`. Performs no I/O.
    #[must_use]
    pub fn new(state: &StateDir) -> Self {
        Self {
            state: state.dir().to_path_buf(),
            dir: state.dir().join("warm"),
        }
    }

    /// The directory the stamps are in.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    fn path(&self, root: &CanonicalPath, server: &str) -> PathBuf {
        let key = format!("{}\0{server}", root.as_str());
        self.dir
            .join(format!("{}.toml", Digest::of(key.as_bytes())))
    }

    /// Records that `server` of the project at `root` was warmed with `digest` at `when`.
    ///
    /// # Errors
    /// [`StampError`] when the directory or the file cannot be written.
    pub fn record(
        &self,
        root: &CanonicalPath,
        server: &str,
        digest: &str,
        when: SystemTime,
    ) -> Result<(), StampError> {
        self.ensure_dir()?;
        let stamp = Stamp {
            format: FORMAT,
            root: root.as_str().to_owned(),
            server: server.to_owned(),
            digest: digest.to_owned(),
            warmed_at: when
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
            hb_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let text = toml::to_string(&stamp).context(SerializeSnafu)?;
        let path = self.path(root, server);
        let temp = self.dir.join(format!(
            ".{}.{}",
            std::process::id(),
            Digest::of(text.as_bytes())
        ));
        write_new(&temp, text.as_bytes()).context(WriteSnafu { path: temp.clone() })?;
        fs::rename(&temp, &path).with_context(|_| {
            let _ = fs::remove_file(&temp);
            WriteSnafu { path: path.clone() }
        })
    }

    /// Removes the stamp of `server` in the project at `root`. `true` if there was one.
    ///
    /// # Errors
    /// [`StampError::Write`] when the file exists and cannot be removed.
    pub fn forget(&self, root: &CanonicalPath, server: &str) -> Result<bool, StampError> {
        let path = self.path(root, server);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(StampError::Write { path, source }),
        }
    }

    /// Whether `server` of the project at `root` was warmed with `digest`.
    #[must_use]
    pub fn standing(&self, root: &CanonicalPath, server: &str, digest: &str) -> Standing {
        let Some(stamp) = self.read(&self.path(root, server)) else {
            return Standing::Never;
        };
        if stamp.format != FORMAT || stamp.root != root.as_str() || stamp.server != server {
            return Standing::Never;
        }
        if stamp.digest == digest {
            Standing::Warmed
        } else {
            Standing::Changed
        }
    }

    fn read(&self, path: &Path) -> Option<Stamp> {
        let metadata = fs::symlink_metadata(path).ok()?;
        if !metadata.is_file() || metadata.len() > MAX_STAMP_BYTES {
            return None;
        }
        let mut text = String::new();
        fs::File::open(path).ok()?.read_to_string(&mut text).ok()?;
        toml::from_str(&text).ok()
    }

    fn ensure_dir(&self) -> Result<(), StampError> {
        if let Some(parent) = self.state.parent() {
            fs::create_dir_all(parent).context(CreateDirSnafu { path: parent })?;
        }
        for dir in [&self.state, &self.dir] {
            match DirBuilder::new().mode(0o700).create(dir) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(StampError::CreateDir {
                        path: dir.clone(),
                        source,
                    });
                }
            }
        }
        Ok(())
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, UNIX_EPOCH};

    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;
    use crate::policy::{CanonicalPath, HomeDir};
    use crate::system::StateDir;

    struct Fixture {
        _tmp: TempDir,
        store: WarmStore,
        root: CanonicalPath,
    }

    fn fixture() -> Fixture {
        let tmp = assert_ok!(TempDir::new());
        let base = assert_ok!(fs::canonicalize(tmp.path()));
        let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(&base)));
        let store = WarmStore::new(&StateDir::locate(&home));
        let root = assert_ok!(CanonicalPath::from_canonical(&base));
        Fixture {
            _tmp: tmp,
            store,
            root,
        }
    }

    fn at(secs: u64) -> std::time::SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn the_digest_depends_on_the_command_each_argument_and_their_order() {
        let base = digest("uvx", &["--from", "x", "tool"]);
        assert_eq!(base, digest("uvx", &["--from", "x", "tool"]));
        for other in [
            digest("npx", &["--from", "x", "tool"]),
            digest("uvx", &["--from", "y", "tool"]),
            digest("uvx", &["tool", "--from", "x"]),
            digest("uvx", &["--from", "x"]),
            digest("uvx", &["--from", "x", "tool", ""]),
        ] {
            assert_ne!(base, other);
        }
        assert_ne!(digest("uvx", &["a b"]), digest("uvx", &["a", "b"]));
        assert_ne!(digest("ab", &["c"]), digest("a", &["bc"]));
    }

    #[test]
    fn a_server_that_was_never_recorded_is_never() {
        let f = fixture();
        assert_eq!(
            f.store.standing(&f.root, "time", &digest("uvx", &["t"])),
            Standing::Never
        );
    }

    #[test]
    fn a_recorded_server_is_warmed_until_its_command_changes() {
        let f = fixture();
        let d = digest("uvx", &["mcp-server-time"]);
        assert_ok!(f.store.record(&f.root, "time", &d, at(1_700_000_000)));
        assert_eq!(f.store.standing(&f.root, "time", &d), Standing::Warmed);
        assert_eq!(
            f.store
                .standing(&f.root, "time", &digest("uvx", &["mcp-server-fetch"])),
            Standing::Changed
        );
    }

    #[test]
    fn a_stamp_belongs_to_one_project_and_one_server() {
        let f = fixture();
        let d = digest("uvx", &["t"]);
        assert_ok!(f.store.record(&f.root, "time", &d, at(1)));
        assert_eq!(f.store.standing(&f.root, "other", &d), Standing::Never);
        let elsewhere = assert_ok!(CanonicalPath::from_canonical("/private/tmp"));
        assert_eq!(f.store.standing(&elsewhere, "time", &d), Standing::Never);
    }

    #[test]
    fn recording_again_replaces_the_stamp() {
        let f = fixture();
        let old = digest("uvx", &["old"]);
        let new = digest("uvx", &["new"]);
        assert_ok!(f.store.record(&f.root, "s", &old, at(1)));
        assert_ok!(f.store.record(&f.root, "s", &new, at(2)));
        assert_eq!(f.store.standing(&f.root, "s", &new), Standing::Warmed);
        assert_eq!(f.store.standing(&f.root, "s", &old), Standing::Changed);
    }

    #[test]
    fn the_store_is_private_and_leaves_no_temporary_files() {
        let f = fixture();
        assert_ok!(f.store.record(&f.root, "s", &digest("uvx", &[]), at(1)));
        let dir = f.store.dir().to_owned();
        assert_eq!(
            assert_ok!(fs::metadata(&dir)).permissions().mode() & 0o777,
            0o700
        );
        let entries: Vec<_> = assert_ok!(fs::read_dir(&dir))
            .filter_map(Result::ok)
            .collect();
        assert_eq!(entries.len(), 1, "{entries:?}");
        let mode = assert_ok!(entries[0].metadata()).permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(!entries[0].file_name().to_string_lossy().starts_with('.'));
    }

    #[test]
    fn a_stamp_that_cannot_be_read_as_one_counts_as_never() {
        let f = fixture();
        let d = digest("uvx", &["t"]);
        assert_ok!(f.store.record(&f.root, "s", &d, at(1)));
        let file = assert_ok!(fs::read_dir(f.store.dir()))
            .filter_map(Result::ok)
            .next();
        let file = file.map(|e| e.path()).unwrap_or_default();
        for bad in ["not toml {{{", "format = 99\nroot = \"x\"\n", ""] {
            assert_ok!(fs::write(&file, bad));
            assert_eq!(
                f.store.standing(&f.root, "s", &d),
                Standing::Never,
                "{bad:?}"
            );
        }
    }

    #[test]
    fn forgetting_removes_one_stamp_and_says_whether_there_was_one() {
        let f = fixture();
        let d = digest("uvx", &["t"]);
        assert_ok!(f.store.record(&f.root, "a", &d, at(1)));
        assert_ok!(f.store.record(&f.root, "b", &d, at(1)));
        assert!(assert_ok!(f.store.forget(&f.root, "a")));
        assert_eq!(f.store.standing(&f.root, "a", &d), Standing::Never);
        assert_eq!(f.store.standing(&f.root, "b", &d), Standing::Warmed);
        assert!(!assert_ok!(f.store.forget(&f.root, "a")), "already gone");
        let empty = fixture();
        assert!(
            !assert_ok!(empty.store.forget(&empty.root, "x")),
            "no store at all"
        );
    }

    #[test]
    fn a_stamp_that_cannot_be_removed_is_an_error_and_not_a_missing_stamp() {
        let f = fixture();
        assert_ok!(f.store.record(&f.root, "other", &digest("uvx", &[]), at(1)));
        // A directory where the stamp file would be: removing it fails for a reason other than "not found".
        assert_ok!(fs::create_dir(f.store.path(&f.root, "stuck")));
        assert_err!(f.store.forget(&f.root, "stuck"));
    }

    #[test]
    fn a_stamp_is_read_up_to_its_size_cap_and_not_beyond() {
        let f = fixture();
        let d = digest("uvx", &["t"]);
        assert_ok!(f.store.record(&f.root, "s", &d, at(1)));
        let file = assert_ok!(fs::read_dir(f.store.dir()))
            .filter_map(Result::ok)
            .next();
        let file = file.map(|e| e.path()).unwrap_or_default();
        let text = assert_ok!(fs::read_to_string(&file));
        assert_ok!(fs::write(
            &file,
            format!("{text}\n# {}\n", "x".repeat(5_000))
        ));
        assert_eq!(
            f.store.standing(&f.root, "s", &d),
            Standing::Warmed,
            "5 KB is fine"
        );
        assert_ok!(fs::write(
            &file,
            format!("{text}\n# {}\n", "x".repeat(20_000))
        ));
        assert_eq!(
            f.store.standing(&f.root, "s", &d),
            Standing::Never,
            "20 KB is not a stamp"
        );
        let padded = |total: u64| {
            let filler = usize::try_from(total).unwrap_or(0) - text.len() - 4;
            format!("{text}\n# {}\n", "x".repeat(filler))
        };
        assert_ok!(fs::write(&file, padded(MAX_STAMP_BYTES)));
        assert_eq!(assert_ok!(fs::metadata(&file)).len(), MAX_STAMP_BYTES);
        assert_eq!(
            f.store.standing(&f.root, "s", &d),
            Standing::Warmed,
            "exactly the cap is read"
        );
        assert_ok!(fs::write(&file, padded(MAX_STAMP_BYTES + 1)));
        assert_eq!(
            f.store.standing(&f.root, "s", &d),
            Standing::Never,
            "one byte over is not"
        );
    }

    #[test]
    fn a_stamp_for_another_root_under_the_same_name_is_not_trusted() {
        let f = fixture();
        let d = digest("uvx", &["t"]);
        assert_ok!(f.store.record(&f.root, "s", &d, at(1)));
        let file = assert_ok!(fs::read_dir(f.store.dir()))
            .filter_map(Result::ok)
            .next();
        let file = file.map(|e| e.path()).unwrap_or_default();
        let text = assert_ok!(fs::read_to_string(&file));
        assert_ok!(fs::write(
            &file,
            text.replace(f.root.as_str(), "/somewhere/else")
        ));
        assert_eq!(f.store.standing(&f.root, "s", &d), Standing::Never);
    }
}
