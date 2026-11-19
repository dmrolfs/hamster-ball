// ABOUTME: ConfigText: a bounded, single-read, symlink-aware open of one config file, keeping the exact bytes.
// ABOUTME: The only place a config file is read; a later milestone hashes ConfigText::bytes(), so no second read may differ.
//! Reads one config file exactly once, with the checks an untrusted file needs before anything
//! parses it: no following a symlink unless explicitly allowed, no blocking on a FIFO, a size
//! cap enforced before the file is read, and UTF-8 validation.

use std::fs::{self, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::libc;
use snafu::Snafu;

use crate::origin::Layer;
use crate::sys::{file_kind, is_symlink_loop, path_preview};

/// Longest accepted config file, in bytes.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// Whether [`ConfigText::read`] may follow a symlink at the file's own path.
///
/// A user-level file may be a symlink (dotfile managers create them); a project file, or a
/// file reached through `extends` inside the project, must never be one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymlinkPolicy {
    /// A symlink at the path is an error.
    Refuse,
    /// A symlink at the path is followed.
    Follow,
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
}

/// The exact bytes of one config file, read once.
///
/// `bytes()` is what a later milestone hashes for approval, and [`ConfigText::as_str`] is the
/// same buffer viewed as text, so there is nothing else to re-read later that could disagree
/// with what was approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigText {
    text: String,
    path: PathBuf,
    layer: Layer,
}

impl ConfigText {
    /// Reads `path` as one config file.
    ///
    /// Pass [`SymlinkPolicy::Follow`] only for a user-level file.
    ///
    /// # Errors
    /// See [`ConfigTextError`]. The file is never read past [`MAX_CONFIG_BYTES`]: its size is
    /// checked from the open file descriptor before any read, and the read itself is bounded.
    pub fn read(
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
        })
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
    use claims::{assert_err, assert_ok};
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
        let text = assert_ok!(ConfigText::read(&path, Layer::Project, REFUSE));
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
        let text = assert_ok!(ConfigText::read(&path, Layer::Project, REFUSE));
        assert_eq!(text.bytes(), content);
    }

    #[test]
    fn accepts_a_file_at_exactly_the_size_limit() {
        let dir = dir();
        let path = dir.path().join("big.toml");
        let content = vec![b'a'; MAX_CONFIG_BYTES as usize];
        assert_ok!(fs::write(&path, &content));
        let text = assert_ok!(ConfigText::read(&path, Layer::Project, REFUSE));
        assert_eq!(text.bytes().len() as u64, MAX_CONFIG_BYTES);
    }

    #[test]
    fn accepts_a_symlink_when_the_policy_follows() {
        let dir = dir();
        let real = dir.path().join("real.toml");
        let link = dir.path().join("link.toml");
        assert_ok!(fs::write(&real, b"x = 1\n"));
        assert_ok!(symlink(&real, &link));
        let text = assert_ok!(ConfigText::read(&link, Layer::UserBase, FOLLOW));
        assert_eq!(text.as_str(), "x = 1\n");
    }

    #[test]
    fn accepts_a_path_given_as_a_string() {
        let dir = dir();
        let path = dir.path().join("a.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        assert_ok!(ConfigText::read(
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
        let err = assert_err!(ConfigText::read(
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
        let err = assert_err!(ConfigText::read(&link, Layer::Project, REFUSE));
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
        let err = assert_err!(ConfigText::read(
            a.join("hamster-ball.toml"),
            Layer::Project,
            REFUSE
        ));
        assert!(matches!(err, ConfigTextError::Open { .. }), "{err:?}");
    }

    #[test]
    fn rejects_a_directory() {
        let dir = dir();
        let err = assert_err!(ConfigText::read(dir.path(), Layer::Project, REFUSE));
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
        let err = assert_err!(ConfigText::read("/dev/null", Layer::Project, REFUSE));
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
            let _ = sender.send(ConfigText::read(&path, Layer::Project, REFUSE));
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
        let err = assert_err!(ConfigText::read(&path, Layer::Project, REFUSE));
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
        let err = assert_err!(ConfigText::read(&path, Layer::Project, REFUSE));
        assert!(matches!(err, ConfigTextError::NotUtf8 { .. }), "{err:?}");
    }

    #[test]
    fn permission_denied_is_its_own_variant_not_missing() {
        let tree = Tree::new();
        let path = tree.outside("p").join("secret.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        let _guard = ModeGuard::set(&path, 0o000);
        let err = assert_err!(ConfigText::read(&path, Layer::Project, REFUSE));
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
    // Error text
    // ====================================================================================

    #[test]
    fn error_display_escapes_and_bounds_hostile_paths() {
        let dir = dir();
        let hostile_name = format!("{}\u{1b}[2j.toml", "a".repeat(400));
        let path = dir.path().join(hostile_name);
        let err = assert_err!(ConfigText::read(&path, Layer::Project, REFUSE));
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
        let err = assert_err!(ConfigText::read(&path, Layer::Project, REFUSE));
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
