// ABOUTME: ConfigText: a bounded, single-read, symlink-aware open of one config file, keeping the exact bytes.
// ABOUTME: The only place a config file is read; approval hashes ConfigText::bytes(), so no second read may differ.
//! Reads one config file exactly once, with the checks an untrusted file needs before anything
//! parses it: no following a symlink unless explicitly allowed, no blocking on a FIFO, a size
//! cap enforced before the file is read, and UTF-8 validation.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::libc;
use snafu::Snafu;

use crate::origin::Layer;
use crate::policy::{CanonicalPath, PathError};
use crate::sys::{file_kind, is_symlink_loop, path_preview};

/// Longest accepted config file, in bytes.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Whether [`ConfigText::read_with`] may follow a symlink at the file's own path.
///
/// `Refuse` guards only the final path component (`O_NOFOLLOW`); a symlinked parent directory
/// still opens. Where a file really lives is decided afterwards, from its canonical path, not
/// by this flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SymlinkPolicy {
    /// A symlink at the path is an error.
    Refuse,
    /// A symlink at the path is followed.
    Follow,
}

/// How a config file was reached, which decides its layer and whether a symlink may be followed.
///
/// Deriving the policy from the role removes a footgun: a caller cannot pass "follow" for a
/// project file. The policy cannot be derived from where the file turns out to be, because
/// that is only known after the open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileRole {
    /// The user's `~/.config/hamster-ball/base.toml`.
    UserBase,
    /// A preset named in `extends` and found in `~/.config/hamster-ball/presets/`.
    UserPresetByName,
    /// The project's `hamster-ball.toml`.
    Project,
    /// A file named by an `extends` path (`/`, `~/`, `./`, `../`).
    ReferencedByPath,
}

impl FileRole {
    /// The layer files in this role belong to.
    pub(crate) fn layer(self) -> Layer {
        match self {
            Self::UserBase => Layer::UserBase,
            Self::Project => Layer::Project,
            Self::UserPresetByName | Self::ReferencedByPath => Layer::Preset,
        }
    }

    /// Whether a symlink at the file's own path is followed.
    ///
    /// Only files under the user's own config directory may be symlinks (dotfile managers
    /// create them); anything a project can name must not be.
    pub(crate) fn symlinks(self) -> SymlinkPolicy {
        match self {
            Self::UserBase | Self::UserPresetByName => SymlinkPolicy::Follow,
            Self::Project | Self::ReferencedByPath => SymlinkPolicy::Refuse,
        }
    }
}

/// Which file on disk a [`ConfigText`] came from, from the open file descriptor.
///
/// Two paths name the same file exactly when their device and inode match, which holds for
/// case, symlink and hard-link aliases alike (a canonical path does not: hard links and
/// firmlinks have different canonical paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    /// The device the file is on.
    pub dev: u64,
    /// The file's inode number.
    pub ino: u64,
    /// How many directory entries name the file. Above 1, another path (possibly one the
    /// agent can write) names the same bytes.
    pub nlink: u64,
    /// The owning user id.
    pub uid: u32,
    /// The file's mode bits, including the file type.
    pub mode: u32,
}

/// Why a config file could not be read.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ConfigTextError {
    /// The path does not exist.
    #[snafu(display("{} does not exist", path_preview(path)))]
    Missing {
        /// The path that was opened.
        path: PathBuf,
    },

    /// The path is a symlink, and this file is not allowed to be one.
    #[snafu(display("{} is a symlink, which is not allowed here", path_preview(path)))]
    SymlinkRejected {
        /// The path that was opened.
        path: PathBuf,
    },

    /// A directory denies traversal, or the file itself denies reading.
    #[snafu(display("{} is not readable", path_preview(path)))]
    PermissionDenied {
        /// The path that was opened.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// The path could not be opened for a reason not covered by a more specific variant.
    #[snafu(display("{} could not be opened", path_preview(path)))]
    Open {
        /// The path that was opened.
        path: PathBuf,
        /// The underlying I/O error.
        source: io::Error,
    },

    /// The path is not a regular file.
    #[snafu(display("{} is a {kind}, not a regular file", path_preview(path)))]
    NotARegularFile {
        /// The path that was opened.
        path: PathBuf,
        /// What it is instead: `"directory"`, `"fifo"`, `"device"`, `"socket"` or `"other"`.
        kind: &'static str,
    },

    /// The file is larger than [`MAX_CONFIG_BYTES`].
    #[snafu(display(
        "{} is {size} bytes, over the {MAX_CONFIG_BYTES}-byte limit",
        path_preview(path)
    ))]
    TooLarge {
        /// The path that was opened.
        path: PathBuf,
        /// The size seen: the reported size, or the bytes read if the file grew mid-read.
        size: u64,
    },

    /// The file's contents are not valid UTF-8.
    #[snafu(display("{} is not valid UTF-8", path_preview(path)))]
    NotUtf8 {
        /// The path that was opened.
        path: PathBuf,
    },

    /// The path no longer names the file that was read.
    #[snafu(display("{} changed while hb was loading it; run hb again", path_preview(path)))]
    ChangedWhileLoading {
        /// The path that was opened.
        path: PathBuf,
    },

    /// The text is built into `hb`, so there is no file to check.
    #[snafu(display("{} is built into hb and has no file on disk", path_preview(path)))]
    NotOnDisk {
        /// The built-in text's name.
        path: PathBuf,
    },

    /// The canonical form of the file's path is not usable.
    #[snafu(display("{} has an unusable canonical path", path_preview(path)))]
    CanonicalPath {
        /// The path that was opened.
        path: PathBuf,
        /// The underlying error.
        source: PathError,
    },
}

/// The exact bytes of one config file, read once.
///
/// `bytes()` is what approval hashes, and [`ConfigText::as_str`] is the
/// same buffer viewed as text, so there is nothing else to re-read later that could disagree
/// with what was approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigText {
    text: String,
    path: PathBuf,
    layer: Layer,
    identity: Option<FileIdentity>,
}

impl ConfigText {
    /// Reads `path` as one config file in `role`.
    ///
    /// # Errors
    /// See [`ConfigTextError`].
    pub(crate) fn read(path: impl AsRef<Path>, role: FileRole) -> Result<Self, ConfigTextError> {
        Self::read_with(path, role.layer(), role.symlinks())
    }

    /// Reads `path` as one config file, with an explicit layer and symlink policy.
    ///
    /// Prefer [`ConfigText::read`], which derives both from the file's role.
    ///
    /// # Errors
    /// See [`ConfigTextError`]. The file is never read past [`MAX_CONFIG_BYTES`]: its size is
    /// checked from the open file descriptor before any read, and the read itself is bounded.
    pub(crate) fn read_with(
        path: impl AsRef<Path>,
        layer: Layer,
        symlinks: SymlinkPolicy,
    ) -> Result<Self, ConfigTextError> {
        let path = path.as_ref();
        let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
        if symlinks == SymlinkPolicy::Refuse {
            flags |= libc::O_NOFOLLOW;
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .map_err(|error| open_error(path, error))?;

        let metadata = file.metadata().map_err(|error| open_error(path, error))?;
        if !metadata.is_file() {
            return Err(ConfigTextError::NotARegularFile {
                path: path.to_path_buf(),
                kind: file_kind(&metadata),
            });
        }
        let size = metadata.len();
        if size > MAX_CONFIG_BYTES {
            return Err(ConfigTextError::TooLarge {
                path: path.to_path_buf(),
                size,
            });
        }

        let bytes = read_bounded(file, size).map_err(|error| open_error(path, error))?;
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            // The file grew between the fstat above and the read.
            return Err(ConfigTextError::TooLarge {
                path: path.to_path_buf(),
                size: bytes.len() as u64,
            });
        }

        let text = String::from_utf8(bytes).map_err(|_| ConfigTextError::NotUtf8 {
            path: path.to_path_buf(),
        })?;
        Ok(Self {
            text,
            path: path.to_path_buf(),
            layer,
            identity: Some(FileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
                nlink: metadata.nlink(),
                uid: metadata.uid(),
                mode: metadata.mode(),
            }),
        })
    }

    /// Text built into `hb` under `name`, as a preset.
    ///
    /// It has no file on disk, so it has no identity and cannot be verified.
    #[must_use]
    pub(crate) fn builtin(name: &str, text: &str) -> Self {
        Self {
            text: text.to_owned(),
            path: PathBuf::from(format!("builtin:{name}")),
            layer: Layer::Preset,
            identity: None,
        }
    }

    /// Checks that the path still names the file that was read, and returns its canonical path.
    ///
    /// Resolves the path with `realpath`, then compares the device and inode of what it names
    /// with the open descriptor's. A mismatch means the path was swapped (or a parent
    /// directory was) after the read. Never re-reads: the bytes in this value are what is
    /// parsed and what is hashed.
    ///
    /// # Errors
    /// [`ConfigTextError::ChangedWhileLoading`] if the path now names another file,
    /// [`ConfigTextError::NotOnDisk`] for built-in text, or an open error if the path can no
    /// longer be resolved.
    pub(crate) fn verify(&self) -> Result<CanonicalPath, ConfigTextError> {
        let identity = self.identity.ok_or_else(|| ConfigTextError::NotOnDisk {
            path: self.path.clone(),
        })?;
        let canonical =
            fs::canonicalize(&self.path).map_err(|error| open_error(&self.path, error))?;
        let named = fs::metadata(&canonical).map_err(|error| open_error(&self.path, error))?;
        if (named.dev(), named.ino()) != (identity.dev, identity.ino) {
            return Err(ConfigTextError::ChangedWhileLoading {
                path: self.path.clone(),
            });
        }
        CanonicalPath::from_canonical(canonical).map_err(|source| ConfigTextError::CanonicalPath {
            path: self.path.clone(),
            source,
        })
    }

    /// Which file on disk this text was read from, or `None` for built-in text.
    #[must_use]
    pub fn identity(&self) -> Option<FileIdentity> {
        self.identity
    }

    /// The exact bytes read from disk.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.text.as_bytes()
    }

    /// The file's contents, as UTF-8 text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The path this file was read from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The layer this file belongs to.
    #[must_use]
    pub fn layer(&self) -> Layer {
        self.layer
    }
}

/// Reads at most [`MAX_CONFIG_BYTES`] + 1 bytes: one past the cap, so the caller can tell
/// "exactly at the cap" from "over it" without ever reading an unbounded stream.
fn read_bounded(reader: impl Read, size_hint: u64) -> io::Result<Vec<u8>> {
    let capacity = usize::try_from(size_hint.min(MAX_CONFIG_BYTES)).unwrap_or_default();
    let mut bytes = Vec::with_capacity(capacity);
    reader.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Classifies a failed open (or later metadata or read) of `path`.
///
/// `ELOOP` is ambiguous: with `O_NOFOLLOW` it means the final component is a symlink, but a
/// loop of symlinks in a parent directory reports the same errno. Only the former is
/// "a symlink where a file was expected".
fn open_error(path: &Path, error: io::Error) -> ConfigTextError {
    let path = path.to_path_buf();
    if is_symlink_loop(&error) && fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_symlink()) {
        ConfigTextError::SymlinkRejected { path }
    } else if error.kind() == io::ErrorKind::NotFound {
        ConfigTextError::Missing { path }
    } else if error.kind() == io::ErrorKind::PermissionDenied {
        ConfigTextError::PermissionDenied {
            path,
            source: error,
        }
    } else {
        ConfigTextError::Open {
            path,
            source: error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{ModeGuard, Tree, mkfifo};
    use claims::{assert_err, assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::symlink;
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    const REFUSE: SymlinkPolicy = SymlinkPolicy::Refuse;
    const FOLLOW: SymlinkPolicy = SymlinkPolicy::Follow;

    fn dir() -> TempDir {
        assert_ok!(TempDir::new())
    }

    // ====================================================================================
    // Accepted forms
    // ====================================================================================

    #[test]
    fn reads_a_regular_file_and_keeps_the_exact_bytes() {
        let dir = dir();
        let path = dir.path().join("hamster-ball.toml");
        assert_ok!(fs::write(&path, b"fs.write = [\".\"]\n"));
        let text = assert_ok!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        assert_eq!(text.bytes(), b"fs.write = [\".\"]\n");
        assert_eq!(text.as_str(), "fs.write = [\".\"]\n");
        assert_eq!(text.layer(), Layer::Project);
        assert_eq!(text.path(), path);
    }

    #[test]
    fn bytes_are_the_exact_file_bytes_including_a_bom() {
        let dir = dir();
        let path = dir.path().join("bom.toml");
        let content = "\u{feff}x = 1\n".as_bytes();
        assert_ok!(fs::write(&path, content));
        let text = assert_ok!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        assert_eq!(text.bytes(), content);
    }

    #[test]
    fn accepts_a_file_at_exactly_the_size_limit() {
        let dir = dir();
        let path = dir.path().join("big.toml");
        let content = vec![b'a'; MAX_CONFIG_BYTES as usize];
        assert_ok!(fs::write(&path, &content));
        let text = assert_ok!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        assert_eq!(text.bytes().len() as u64, MAX_CONFIG_BYTES);
    }

    #[test]
    fn accepts_a_symlink_when_the_policy_follows() {
        let dir = dir();
        let real = dir.path().join("real.toml");
        let link = dir.path().join("link.toml");
        assert_ok!(fs::write(&real, b"x = 1\n"));
        assert_ok!(symlink(&real, &link));
        let text = assert_ok!(ConfigText::read_with(&link, Layer::UserBase, FOLLOW));
        assert_eq!(text.as_str(), "x = 1\n");
    }

    #[test]
    fn accepts_a_path_given_as_a_string() {
        let dir = dir();
        let path = dir.path().join("a.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        assert_ok!(ConfigText::read_with(
            path.to_string_lossy().as_ref(),
            Layer::Project,
            REFUSE
        ));
    }

    // ====================================================================================
    // Rejected forms
    // ====================================================================================

    #[test]
    fn rejects_a_missing_file() {
        let dir = dir();
        let err = assert_err!(ConfigText::read_with(
            dir.path().join("nope.toml"),
            Layer::Project,
            REFUSE
        ));
        assert!(matches!(err, ConfigTextError::Missing { .. }), "{err:?}");
    }

    #[test]
    fn rejects_a_symlink_when_the_policy_refuses() {
        let dir = dir();
        let real = dir.path().join("real.toml");
        let link = dir.path().join("link.toml");
        assert_ok!(fs::write(&real, b"x = 1\n"));
        assert_ok!(symlink(&real, &link));
        let err = assert_err!(ConfigText::read_with(&link, Layer::Project, REFUSE));
        assert!(
            matches!(err, ConfigTextError::SymlinkRejected { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn a_symlink_loop_in_a_parent_directory_is_not_reported_as_a_rejected_symlink() {
        let dir = dir();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        assert_ok!(symlink(&b, &a));
        assert_ok!(symlink(&a, &b));
        let err = assert_err!(ConfigText::read_with(
            a.join("hamster-ball.toml"),
            Layer::Project,
            REFUSE
        ));
        assert!(matches!(err, ConfigTextError::Open { .. }), "{err:?}");
    }

    #[test]
    fn rejects_a_directory() {
        let dir = dir();
        let err = assert_err!(ConfigText::read_with(dir.path(), Layer::Project, REFUSE));
        assert!(
            matches!(
                err,
                ConfigTextError::NotARegularFile {
                    kind: "directory",
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_a_device() {
        let err = assert_err!(ConfigText::read_with("/dev/null", Layer::Project, REFUSE));
        assert!(
            matches!(err, ConfigTextError::NotARegularFile { kind: "device", .. }),
            "{err:?}"
        );
    }

    /// A blocking `open` would hang the test thread forever, so the read runs on its own
    /// thread and the test fails by timeout instead of by never finishing.
    #[test]
    fn rejects_a_fifo_without_blocking() {
        let dir = dir();
        let fifo = dir.path().join("afifo");
        mkfifo(&fifo);

        let (sender, receiver) = mpsc::channel();
        let path = fifo.clone();
        std::thread::spawn(move || {
            let _ = sender.send(ConfigText::read_with(&path, Layer::Project, REFUSE));
        });
        let result = assert_ok!(receiver.recv_timeout(Duration::from_secs(5)));
        let err = assert_err!(result);
        assert!(
            matches!(err, ConfigTextError::NotARegularFile { kind: "fifo", .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_a_file_over_the_size_limit_without_reading_it() {
        let dir = dir();
        let path = dir.path().join("huge.toml");
        let file = assert_ok!(fs::File::create(&path));
        // A sparse file: its reported size is over the cap, but no data blocks exist, so a
        // real read would be slow if this path were ever reached.
        assert_ok!(file.set_len(MAX_CONFIG_BYTES + 1));
        let started = Instant::now();
        let err = assert_err!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "took {:?}",
            started.elapsed()
        );
        assert!(
            matches!(err, ConfigTextError::TooLarge { size, .. } if size == MAX_CONFIG_BYTES + 1),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_invalid_utf8() {
        let dir = dir();
        let path = dir.path().join("bad.toml");
        assert_ok!(fs::write(&path, [b'a', 0xff, 0xfe, b'b']));
        let err = assert_err!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        assert!(matches!(err, ConfigTextError::NotUtf8 { .. }), "{err:?}");
    }

    #[test]
    fn permission_denied_is_its_own_variant_not_missing() {
        let tree = Tree::new();
        let path = tree.outside("p").join("secret.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        let _guard = ModeGuard::set(&path, 0o000);
        let err = assert_err!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        assert!(
            matches!(err, ConfigTextError::PermissionDenied { .. }),
            "{err:?}"
        );
    }

    // ====================================================================================
    // The bounded read itself
    // ====================================================================================

    #[test]
    fn read_bounded_stops_one_byte_past_the_cap_on_an_endless_source() {
        // `io::repeat` never ends, so this only returns because the read is bounded; reading
        // exactly one byte past the cap is what lets `read` tell "at the cap" from "over it".
        let bytes = assert_ok!(read_bounded(io::repeat(b'a'), 0));
        assert_eq!(bytes.len() as u64, MAX_CONFIG_BYTES + 1);
    }

    #[test]
    fn read_bounded_returns_a_short_source_unchanged() {
        let bytes = assert_ok!(read_bounded(&b"abc"[..], 3));
        assert_eq!(bytes, b"abc");
    }

    // ====================================================================================
    // FileRole: how a file was reached decides its layer and whether a symlink is followed
    // ====================================================================================

    #[test]
    fn file_role_decides_layer_and_symlink_policy() {
        assert_eq!(FileRole::UserBase.layer(), Layer::UserBase);
        assert_eq!(FileRole::UserPresetByName.layer(), Layer::Preset);
        assert_eq!(FileRole::ReferencedByPath.layer(), Layer::Preset);
        assert_eq!(FileRole::Project.layer(), Layer::Project);

        assert_eq!(FileRole::UserBase.symlinks(), SymlinkPolicy::Follow);
        assert_eq!(FileRole::UserPresetByName.symlinks(), SymlinkPolicy::Follow);
        assert_eq!(FileRole::Project.symlinks(), SymlinkPolicy::Refuse);
        assert_eq!(FileRole::ReferencedByPath.symlinks(), SymlinkPolicy::Refuse);
    }

    #[test]
    fn read_by_role_applies_the_roles_symlink_policy_and_layer() {
        let dir = dir();
        let real = dir.path().join("real.toml");
        let link = dir.path().join("link.toml");
        assert_ok!(fs::write(&real, b"x = 1\n"));
        assert_ok!(symlink(&real, &link));

        let followed = assert_ok!(ConfigText::read(&link, FileRole::UserBase));
        assert_eq!(followed.layer(), Layer::UserBase);
        let err = assert_err!(ConfigText::read(&link, FileRole::Project));
        assert!(
            matches!(err, ConfigTextError::SymlinkRejected { .. }),
            "{err:?}"
        );
        let err = assert_err!(ConfigText::read(&link, FileRole::ReferencedByPath));
        assert!(
            matches!(err, ConfigTextError::SymlinkRejected { .. }),
            "{err:?}"
        );
    }

    // ====================================================================================
    // Identity and verification
    // ====================================================================================

    #[test]
    fn identity_is_the_open_files_device_inode_and_link_count() {
        use std::os::unix::fs::MetadataExt;
        let dir = dir();
        let path = dir.path().join("a.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        let text = assert_ok!(ConfigText::read(&path, FileRole::Project));
        let meta = assert_ok!(fs::metadata(&path));
        let identity = assert_some!(text.identity());
        assert_eq!(identity.dev, meta.dev());
        assert_eq!(identity.ino, meta.ino());
        assert_eq!(identity.nlink, 1);
        assert_eq!(identity.uid, meta.uid());
        assert_eq!(identity.mode, meta.mode());
    }

    #[test]
    fn a_hard_link_has_the_same_identity_and_a_link_count_above_one() {
        let dir = dir();
        let first = dir.path().join("a.toml");
        let second = dir.path().join("b.toml");
        assert_ok!(fs::write(&first, b"x = 1\n"));
        assert_ok!(fs::hard_link(&first, &second));
        let a = assert_ok!(ConfigText::read(&first, FileRole::Project));
        let b = assert_ok!(ConfigText::read(&second, FileRole::Project));
        let (ia, ib) = (assert_some!(a.identity()), assert_some!(b.identity()));
        assert_eq!((ia.dev, ia.ino), (ib.dev, ib.ino));
        assert_eq!(ia.nlink, 2);
    }

    #[test]
    fn verify_returns_the_canonical_path_for_an_aliased_spelling() {
        let tree = Tree::new();
        let real_dir = tree.outside("real");
        let alias_dir = tree.base().join("alias");
        assert_ok!(symlink(&real_dir, &alias_dir));
        assert_ok!(fs::write(real_dir.join("a.toml"), b"x = 1\n"));

        // A symlinked parent directory passes the leaf-only O_NOFOLLOW check ...
        let text = assert_ok!(ConfigText::read(
            alias_dir.join("a.toml"),
            FileRole::Project
        ));
        // ... and verify reports where the file really is.
        let canonical = assert_ok!(text.verify());
        assert_eq!(canonical.as_path(), real_dir.join("a.toml"));
    }

    #[test]
    fn verify_detects_a_file_swapped_after_it_was_read() {
        let dir = dir();
        let path = dir.path().join("a.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        let text = assert_ok!(ConfigText::read(&path, FileRole::Project));

        // Replace the path with a different file (new inode) after the read.
        let other = dir.path().join("other.toml");
        assert_ok!(fs::write(&other, b"x = 2\n"));
        assert_ok!(fs::rename(&other, &path));

        let err = assert_err!(text.verify());
        assert!(
            matches!(err, ConfigTextError::ChangedWhileLoading { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verify_accepts_an_untouched_file() {
        let dir = dir();
        let path = dir.path().join("a.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        let text = assert_ok!(ConfigText::read(&path, FileRole::Project));
        assert_ok!(text.verify());
    }

    // ====================================================================================
    // Built-in text
    // ====================================================================================

    #[test]
    fn a_builtin_text_has_a_preset_layer_a_named_path_and_no_disk_identity() {
        let text = ConfigText::builtin("agent/kiro", "[net]\nallow = []\n");
        assert_eq!(text.layer(), Layer::Preset);
        assert_eq!(text.as_str(), "[net]\nallow = []\n");
        assert_eq!(text.bytes(), b"[net]\nallow = []\n");
        assert_eq!(text.path(), Path::new("builtin:agent/kiro"));
        assert_none!(text.identity());
    }

    #[test]
    fn verifying_a_builtin_text_is_an_error_because_there_is_no_file() {
        let text = ConfigText::builtin("rust", "");
        let err = assert_err!(text.verify());
        assert!(matches!(err, ConfigTextError::NotOnDisk { .. }), "{err:?}");
    }

    // ====================================================================================
    // Error text
    // ====================================================================================

    #[test]
    fn error_display_escapes_and_bounds_hostile_paths() {
        let dir = dir();
        let hostile_name = format!("{}\u{1b}[2j.toml", "a".repeat(400));
        let path = dir.path().join(hostile_name);
        let err = assert_err!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        let shown = err.to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.len() < 400, "{} chars", shown.len());
    }

    #[test]
    fn display_never_contains_source_text() {
        let tree = Tree::new();
        let path = tree.outside("p").join("secret.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        let _guard = ModeGuard::set(&path, 0o000);
        let err = assert_err!(ConfigText::read_with(&path, Layer::Project, REFUSE));
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
