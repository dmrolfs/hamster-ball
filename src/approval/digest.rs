// ABOUTME: SHA-256 values and the fingerprint of the config files the sandbox could write.
// ABOUTME: Hashes exact bytes and paths, never times; any byte, name, order or membership change moves the closure digest.
//! The fingerprint of an approvable closure.
//!
//! The decision whether a project is approved rests on one [`Digest`], the closure digest, taken
//! over length-prefixed (path, bytes) pairs in closure order. The per-file digests exist only so
//! the prompt can say which file changed.

use std::fmt;

use sha2::{Digest as _, Sha256};

use crate::config::{Closure, FileSource};

/// Names the framing, so a digest of this shape cannot equal one of any other shape.
const DOMAIN: &[u8] = b"hamster-ball approval v1\0";

/// A SHA-256 value.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    /// The digest of `bytes`.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Parses 64 lower-case or upper-case hex digits.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != 64 || !text.is_ascii() {
            return None;
        }
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).ok()?;
            *byte = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

/// One approved file: where it is and what it held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDigest {
    /// The canonical path.
    pub path: String,
    /// The digest of its exact bytes.
    pub sha256: Digest,
}

/// What an approval is about: the files the sandbox could write, in closure order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fingerprint {
    files: Vec<FileDigest>,
    closure: Digest,
}

impl Fingerprint {
    /// The fingerprint of `closure`'s approval files.
    #[must_use]
    pub fn of(closure: &Closure) -> Self {
        Self::from_files(closure.approval_files().map(|file| {
            let path = match &file.source {
                FileSource::Disk { canonical, .. } => canonical.as_str().to_owned(),
                FileSource::Builtin { name } => name.to_string(),
            };
            (path, file.text.bytes())
        }))
    }

    /// The fingerprint of `files`, each a path and its exact bytes, in order.
    #[must_use]
    pub fn from_files<'a>(files: impl IntoIterator<Item = (String, &'a [u8])>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN);
        let files: Vec<FileDigest> = files
            .into_iter()
            .map(|(path, bytes)| {
                for part in [path.as_bytes(), bytes] {
                    hasher.update((part.len() as u64).to_be_bytes());
                    hasher.update(part);
                }
                FileDigest {
                    sha256: Digest::of(bytes),
                    path,
                }
            })
            .collect();
        Self {
            files,
            closure: Digest(hasher.finalize().into()),
        }
    }

    /// Rebuilds a fingerprint from stored parts, without checking they agree.
    ///
    /// Only for comparison with a stored record: [`Fingerprint::closure`] is the stored value,
    /// which is what a record is trusted for.
    #[must_use]
    pub(crate) fn from_parts(files: Vec<FileDigest>, closure: Digest) -> Self {
        Self { files, closure }
    }

    /// The digest the approval decision rests on.
    #[must_use]
    pub fn closure(&self) -> Digest {
        self.closure
    }

    /// The files, in closure order.
    #[must_use]
    pub fn files(&self) -> &[FileDigest] {
        &self.files
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_none, assert_some};
    use pretty_assertions::assert_eq;

    fn print(files: &[(&str, &str)]) -> Fingerprint {
        Fingerprint::from_files(files.iter().map(|(p, b)| ((*p).to_owned(), b.as_bytes())))
    }

    #[test]
    fn the_same_files_give_the_same_digest() {
        let a = print(&[("/p/hamster-ball.toml", "[fs]\n")]);
        let b = print(&[("/p/hamster-ball.toml", "[fs]\n")]);
        assert_eq!(a.closure(), b.closure());
    }

    #[test]
    fn any_single_byte_change_moves_the_digest() {
        let base = print(&[("/p/hamster-ball.toml", "[fs]\nwrite = [\".\"]\n")]);
        for changed in [
            "[fs]\nwrite = [\".\"]",
            "[fs]\nwrite = [\"x\"]\n",
            "[fs]\nwrite = [\".\"]\n ",
            "[fs]\r\nwrite = [\".\"]\r\n",
        ] {
            let other = print(&[("/p/hamster-ball.toml", changed)]);
            assert_ne!(base.closure(), other.closure(), "{changed:?}");
        }
    }

    #[test]
    fn a_renamed_added_removed_or_reordered_file_moves_the_digest() {
        let one = print(&[("/p/a.toml", "x"), ("/p/b.toml", "y")]);
        assert_ne!(
            one.closure(),
            print(&[("/q/a.toml", "x"), ("/p/b.toml", "y")]).closure()
        );
        assert_ne!(one.closure(), print(&[("/p/a.toml", "x")]).closure());
        assert_ne!(
            one.closure(),
            print(&[("/p/a.toml", "x"), ("/p/b.toml", "y"), ("/p/c.toml", "")]).closure()
        );
        assert_ne!(
            one.closure(),
            print(&[("/p/b.toml", "y"), ("/p/a.toml", "x")]).closure()
        );
    }

    #[test]
    fn moving_bytes_between_the_path_and_the_content_moves_the_digest() {
        let a = print(&[("/p/ab", "c")]);
        let b = print(&[("/p/a", "bc")]);
        assert_ne!(a.closure(), b.closure());
    }

    #[test]
    fn no_files_has_a_digest_of_its_own() {
        assert_ne!(print(&[]).closure(), Digest::of(b""));
        assert_eq!(print(&[]).files(), &[]);
    }

    #[test]
    fn each_file_keeps_its_own_digest_in_order() {
        let fp = print(&[("/p/a.toml", "x"), ("/p/b.toml", "y")]);
        let shown: Vec<(&str, String)> = fp
            .files()
            .iter()
            .map(|f| (f.path.as_str(), f.sha256.to_string()))
            .collect();
        assert_eq!(
            shown,
            [
                ("/p/a.toml", Digest::of(b"x").to_string()),
                ("/p/b.toml", Digest::of(b"y").to_string())
            ]
        );
    }

    #[test]
    fn a_digest_is_sha256_in_lower_case_hex() {
        assert_eq!(
            Digest::of(b"abc").to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn a_digest_prints_its_hex_in_debug_output_too() {
        assert_eq!(
            format!("{:?}", Digest::of(b"abc")),
            "Digest(ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad)"
        );
    }

    #[test]
    fn hex_round_trips_and_bad_hex_is_refused() {
        let digest = Digest::of(b"abc");
        assert_eq!(assert_some!(Digest::from_hex(&digest.to_string())), digest);
        assert_some!(Digest::from_hex(&digest.to_string().to_uppercase()));
        assert_none!(Digest::from_hex("abc"));
        assert_none!(Digest::from_hex(&"g".repeat(64)));
        assert_none!(Digest::from_hex(&format!("é{}", "0".repeat(62))));
    }
}
