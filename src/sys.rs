// ABOUTME: Small operating-system helpers shared by the modules that touch the filesystem.
// ABOUTME: One place for symlink-loop detection, file-kind names and bounded path text in errors.
//! Shared filesystem helpers. Crate-private: nothing here is part of the public API.

use std::fs::Metadata;
use std::io;
use std::os::unix::fs::FileTypeExt;
use std::path::Path;

use nix::libc;

use crate::text::EscapedBounded;

/// How much of a path is echoed in an error message.
const PATH_PREVIEW_CHARS: usize = 200;

/// Reports whether `error` is the OS saying "too many levels of symbolic links".
///
/// `std::io::ErrorKind::FilesystemLoop` is still unstable (library feature `io_error_more`),
/// so the raw errno is compared instead.
pub(crate) fn is_symlink_loop(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::ELOOP)
}

/// A path as bounded, escaped text for an error message.
pub(crate) fn path_preview(path: &Path) -> EscapedBounded<'_> {
    EscapedBounded::new(
        path.to_str().unwrap_or("<non-UTF-8 path>"),
        PATH_PREVIEW_CHARS,
    )
}

/// A short name for what `metadata` describes, for "X is a {kind}, not a regular file".
///
/// `metadata` must come from `symlink_metadata` (or an open descriptor) for `"symlink"` to be
/// reported.
pub(crate) fn file_kind(metadata: &Metadata) -> &'static str {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_fifo() {
        "fifo"
    } else if file_type.is_char_device() || file_type.is_block_device() {
        "device"
    } else if file_type.is_socket() {
        "socket"
    } else if file_type.is_file() {
        "file"
    } else {
        "other"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    #[test]
    fn symlink_loop_is_recognised_by_errno() {
        assert!(is_symlink_loop(&io::Error::from_raw_os_error(libc::ELOOP)));
        assert!(!is_symlink_loop(&io::Error::from_raw_os_error(
            libc::ENOENT
        )));
        assert!(!is_symlink_loop(&io::Error::other("no errno")));
    }

    #[test]
    fn file_kind_names_every_kind_this_crate_distinguishes() {
        let dir = assert_ok!(tempfile::TempDir::new());
        let file = dir.path().join("f");
        assert_ok!(fs::write(&file, b""));
        let link = dir.path().join("l");
        assert_ok!(symlink(&file, &link));
        let fifo = dir.path().join("p");
        let status = assert_ok!(std::process::Command::new("mkfifo").arg(&fifo).status());
        assert!(status.success());
        let socket = dir.path().join("s");
        let _listener = assert_ok!(UnixListener::bind(&socket));

        let kind = |path: &Path| file_kind(&assert_ok!(fs::symlink_metadata(path)));
        assert_eq!(kind(&file), "file");
        assert_eq!(kind(dir.path()), "directory");
        assert_eq!(kind(&link), "symlink");
        assert_eq!(kind(&fifo), "fifo");
        assert_eq!(kind(&socket), "socket");
        assert_eq!(kind(Path::new("/dev/null")), "device");
    }

    #[test]
    fn file_kind_does_not_report_a_symlink_for_followed_metadata() {
        let dir = assert_ok!(tempfile::TempDir::new());
        let file = dir.path().join("f");
        assert_ok!(fs::write(&file, b""));
        let link = dir.path().join("l");
        assert_ok!(symlink(&file, &link));
        assert_eq!(file_kind(&assert_ok!(fs::metadata(&link))), "file");
    }

    #[test]
    fn path_preview_escapes_and_bounds() {
        let hostile = format!("/a\u{1b}[2J{}", "b".repeat(500));
        let shown = path_preview(Path::new(&hostile)).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
        assert!(shown.ends_with("..."), "{shown:?}");
        assert!(shown.chars().count() < 300, "{}", shown.len());
    }
}
