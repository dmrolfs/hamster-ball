// ABOUTME: ConfigText: a bounded, single-read, symlink-aware open of one config file, keeping the exact bytes.
// ABOUTME: The only place a config file is read; a later milestone hashes ConfigText::bytes(), so no second read may differ.
//! Reads one config file exactly once, with the checks an untrusted file needs before anything
//! parses it: no following a symlink unless explicitly allowed, no blocking on a FIFO, a size
//! cap enforced before the file is read, and UTF-8 validation.

use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use snafu::Snafu;

use crate::origin::Layer;
use crate::text::EscapedBounded;

/// Longest accepted config file, in bytes.
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// How much of a path is echoed in an error message.
const ERROR_PREVIEW_CHARS: usize = 200;

/// `ELOOP`'s errno value. Matches the one in `policy::resolve`; kept local because this is a
/// three-line, self-contained check that does not warrant cross-module coupling.
#[cfg(target_os = "macos")]
const ELOOP: i32 = 62;
#[cfg(not(target_os = "macos"))]
const ELOOP: i32 = 40;

fn is_symlink_loop(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ELOOP)
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
        /// What it is instead: `"directory"`, `"fifo"`, `"device"`, or `"other"`.
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
        /// The file's reported size.
        size: u64,
    },

    /// The file's contents are not valid UTF-8.
    #[snafu(display("{} is not valid UTF-8", path_preview(path)))]
    NotUtf8 {
        /// The path that was opened.
        path: PathBuf,
    },
}

fn path_preview(path: &Path) -> EscapedBounded<'_> {
    EscapedBounded::new(
        path.to_str().unwrap_or("<non-UTF-8 path>"),
        ERROR_PREVIEW_CHARS,
    )
}

/// The exact bytes of one config file, read once.
///
/// `bytes()` is what a later milestone hashes for approval, and what [`ConfigText::as_str`]
/// is derived from; both come from this one read, so there is nothing else to re-read later
/// that could disagree with what was approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigText {
    bytes: Vec<u8>,
    text: String,
    path: PathBuf,
    layer: Layer,
}

impl ConfigText {
    /// Reads `path` as one config file.
    ///
    /// `follow_symlinks` must be `true` only for a user-level file (dotfile managers symlink
    /// those); a project file or a file reached through `extends` inside the project must
    /// never be a symlink, so `follow_symlinks` is `false` there.
    ///
    /// # Errors
    /// See [`ConfigTextError`]. The file is never read past [`MAX_CONFIG_BYTES`]: its size is
    /// checked from the open file descriptor before any read is attempted.
    pub fn read(path: &Path, layer: Layer, follow_symlinks: bool) -> Result<Self, ConfigTextError> {
        let mut flags = libc::O_NONBLOCK | libc::O_CLOEXEC;
        if !follow_symlinks {
            flags |= libc::O_NOFOLLOW;
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(path)
            .map_err(|error| {
                if is_symlink_loop(&error) {
                    ConfigTextError::SymlinkRejected {
                        path: path.to_path_buf(),
                    }
                } else if error.kind() == io::ErrorKind::NotFound {
                    ConfigTextError::Missing {
                        path: path.to_path_buf(),
                    }
                } else if error.kind() == io::ErrorKind::PermissionDenied {
                    ConfigTextError::PermissionDenied {
                        path: path.to_path_buf(),
                        source: error,
                    }
                } else {
                    ConfigTextError::Open {
                        path: path.to_path_buf(),
                        source: error,
                    }
                }
            })?;

        let metadata = file.metadata().map_err(|error| ConfigTextError::Open {
            path: path.to_path_buf(),
            source: error,
        })?;
        if !metadata.is_file() {
            let kind = if metadata.is_dir() {
                "directory"
            } else if metadata.file_type().is_fifo() {
                "fifo"
            } else if metadata.file_type().is_char_device()
                || metadata.file_type().is_block_device()
            {
                "device"
            } else {
                "other"
            };
            return Err(ConfigTextError::NotARegularFile {
                path: path.to_path_buf(),
                kind,
            });
        }
        let size = metadata.len();
        if size > MAX_CONFIG_BYTES {
            return Err(ConfigTextError::TooLarge {
                path: path.to_path_buf(),
                size,
            });
        }

        let mut bytes = Vec::with_capacity(size as usize);
        io::Read::read_to_end(&mut io::Read::take(file, MAX_CONFIG_BYTES + 1), &mut bytes)
            .map_err(|error| ConfigTextError::Open {
                path: path.to_path_buf(),
                source: error,
            })?;
        // A defensive re-check closes a race where the file grew between the fstat above and
        // this read; `Read::take` already bounds the read itself to one byte past the cap.
        if bytes.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ConfigTextError::TooLarge {
                path: path.to_path_buf(),
                size: bytes.len() as u64,
            });
        }

        let text = String::from_utf8(bytes.clone()).map_err(|_| ConfigTextError::NotUtf8 {
            path: path.to_path_buf(),
        })?;

        Ok(Self {
            bytes,
            text,
            path: path.to_path_buf(),
            layer,
        })
    }

    /// The exact bytes read from disk.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
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

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

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
        let text = assert_ok!(ConfigText::read(&path, Layer::Project, false));
        assert_eq!(text.bytes(), b"fs.write = [\".\"]\n");
        assert_eq!(text.as_str(), "fs.write = [\".\"]\n");
        assert_eq!(text.layer(), Layer::Project);
        assert_eq!(text.path(), path);
    }

    #[test]
    fn accepts_a_file_at_exactly_the_size_limit() {
        let dir = dir();
        let path = dir.path().join("big.toml");
        let content = vec![b'a'; MAX_CONFIG_BYTES as usize];
        assert_ok!(fs::write(&path, &content));
        let text = assert_ok!(ConfigText::read(&path, Layer::Project, false));
        assert_eq!(text.bytes().len() as u64, MAX_CONFIG_BYTES);
    }

    #[test]
    fn accepts_a_symlink_when_follow_symlinks_is_true() {
        let dir = dir();
        let real = dir.path().join("real.toml");
        let link = dir.path().join("link.toml");
        assert_ok!(fs::write(&real, b"x = 1\n"));
        assert_ok!(symlink(&real, &link));
        let text = assert_ok!(ConfigText::read(&link, Layer::UserBase, true));
        assert_eq!(text.as_str(), "x = 1\n");
    }

    // ====================================================================================
    // Rejected forms
    // ====================================================================================

    #[test]
    fn rejects_a_missing_file() {
        let dir = dir();
        let err = assert_err!(ConfigText::read(
            &dir.path().join("nope.toml"),
            Layer::Project,
            false
        ));
        assert!(matches!(err, ConfigTextError::Missing { .. }), "{err:?}");
    }

    #[test]
    fn rejects_a_symlink_without_follow_symlinks() {
        let dir = dir();
        let real = dir.path().join("real.toml");
        let link = dir.path().join("link.toml");
        assert_ok!(fs::write(&real, b"x = 1\n"));
        assert_ok!(symlink(&real, &link));
        let err = assert_err!(ConfigText::read(&link, Layer::Project, false));
        assert!(
            matches!(err, ConfigTextError::SymlinkRejected { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_a_directory() {
        let dir = dir();
        let err = assert_err!(ConfigText::read(dir.path(), Layer::Project, false));
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
    fn rejects_a_fifo_without_blocking() {
        let dir = dir();
        let fifo = dir.path().join("afifo");
        let status = assert_ok!(std::process::Command::new("mkfifo").arg(&fifo).status());
        assert!(status.success(), "mkfifo failed: {status:?}");

        let started = Instant::now();
        let err = assert_err!(ConfigText::read(&fifo, Layer::Project, false));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}, may have blocked",
            started.elapsed()
        );
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
        // A sparse file: its reported size is huge, but no data blocks are allocated, so a
        // real read would be slow if this path were ever reached; the fstat-before-read gate
        // means it should not be.
        assert_ok!(file.set_len(MAX_CONFIG_BYTES + 1));
        let started = Instant::now();
        let err = assert_err!(ConfigText::read(&path, Layer::Project, false));
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
        let err = assert_err!(ConfigText::read(&path, Layer::Project, false));
        assert!(matches!(err, ConfigTextError::NotUtf8 { .. }), "{err:?}");
    }

    #[test]
    fn permission_denied_is_its_own_variant_not_missing() {
        let dir = dir();
        let path = dir.path().join("secret.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        assert_ok!(fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o000)
        ));
        let result = ConfigText::read(&path, Layer::Project, false);
        assert_ok!(fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o644)
        ));
        let err = assert_err!(result);
        assert!(
            matches!(err, ConfigTextError::PermissionDenied { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn error_display_escapes_and_bounds_hostile_paths() {
        let dir = dir();
        let hostile_name = format!("{}\u{1b}[2j.toml", "a".repeat(400));
        let path = dir.path().join(hostile_name);
        let err = assert_err!(ConfigText::read(&path, Layer::Project, false));
        let shown = err.to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.len() < 400, "{} chars", shown.len());
    }

    #[test]
    fn display_never_contains_source_text() {
        let dir = dir();
        let path = dir.path().join("secret.toml");
        assert_ok!(fs::write(&path, b"x = 1\n"));
        assert_ok!(fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o000)
        ));
        let result = ConfigText::read(&path, Layer::Project, false);
        assert_ok!(fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o644)
        ));
        crate::error::conventions::assert_display_excludes_sources(&assert_err!(result));
    }
}
