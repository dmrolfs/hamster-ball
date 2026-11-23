// ABOUTME: Builds the per-session CA bundle that NODE_EXTRA_CA_CERTS points at, from the config's tls.extra_ca_files.
// ABOUTME: Copies only the PEM certificate blocks, refuses a file with none, and writes the bundle 0600 into the session dir.
//! The extra CA bundle (design 4.5).
//!
//! `hb` reads each file outside the sandbox, takes the certificates out of it, and writes one
//! bundle inside the session directory. Two reasons not to point Node at the files themselves:
//! several files must become one path, and Node ignores an unreadable or certificate-less file
//! with only a warning (`Ignoring extra certs`), so a mistake would look like "system trust
//! only". A file with no certificate is therefore an error before the agent starts.
//!
//! Only the `CERTIFICATE` blocks are copied. A file that also holds a private key or notes does
//! not carry them into the session directory.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;

use snafu::{ResultExt, Snafu, ensure};

use crate::policy::{CanonicalPath, PathError};
use crate::text::Escaped;

/// The bundle's file name inside the session directory.
pub const BUNDLE_NAME: &str = "ca-bundle.pem";
/// The largest CA file `hb` will read.
pub const MAX_FILE_BYTES: u64 = 1 << 20;
/// The largest bundle `hb` will write.
pub const MAX_BUNDLE_BYTES: usize = 4 << 20;

const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const END: &str = "-----END CERTIFICATE-----";

/// Why the bundle could not be built.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum CaBundleError {
    /// A CA file could not be read.
    #[snafu(display("the CA file {} could not be read", Escaped(path)))]
    Read {
        /// The file.
        path: String,
        /// The underlying error.
        source: io::Error,
    },

    /// A CA file is bigger than any certificate bundle should be.
    #[snafu(display("the CA file {} is larger than {limit} bytes", Escaped(path)))]
    FileTooLarge {
        /// The file.
        path: String,
        /// The limit.
        limit: u64,
    },

    /// A CA file holds no PEM certificate.
    #[snafu(display(
        "the CA file {} holds no PEM certificate (a `-----BEGIN CERTIFICATE-----` block)",
        Escaped(path)
    ))]
    NoCertificate {
        /// The file.
        path: String,
    },

    /// The certificates together are bigger than the limit.
    #[snafu(display("the CA files together hold more than {limit} bytes of certificates"))]
    BundleTooLarge {
        /// The limit.
        limit: usize,
    },

    /// The bundle could not be written.
    #[snafu(display("the CA bundle could not be written"))]
    Write {
        /// The underlying error.
        source: io::Error,
    },

    /// The bundle's path is not a clean canonical path.
    #[snafu(display("the CA bundle's path is not usable"))]
    NotCanonical {
        /// The underlying error.
        source: PathError,
    },
}

/// Writes `files` as one bundle in `session` and returns its path, or `None` if there are no files.
///
/// # Errors
/// [`CaBundleError`] if a file cannot be read, is too large, or holds no certificate, or if the
/// bundle cannot be written.
pub fn write_bundle(
    session: &CanonicalPath,
    files: &[CanonicalPath],
) -> Result<Option<CanonicalPath>, CaBundleError> {
    if files.is_empty() {
        return Ok(None);
    }
    let mut bundle = String::new();
    for file in files {
        let path = file.as_str();
        let size = fs::metadata(file.as_path())
            .context(ReadSnafu { path })?
            .len();
        ensure!(
            size <= MAX_FILE_BYTES,
            FileTooLargeSnafu {
                path,
                limit: MAX_FILE_BYTES
            }
        );
        let text = fs::read(file.as_path()).context(ReadSnafu { path })?;
        let certificates = certificates_in(&String::from_utf8_lossy(&text));
        ensure!(!certificates.is_empty(), NoCertificateSnafu { path });
        for certificate in certificates {
            bundle.push_str(&certificate);
            bundle.push('\n');
        }
        ensure!(
            bundle.len() <= MAX_BUNDLE_BYTES,
            BundleTooLargeSnafu {
                limit: MAX_BUNDLE_BYTES
            }
        );
    }
    let target = session.as_path().join(BUNDLE_NAME);
    let mut out = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&target)
        .context(WriteSnafu)?;
    out.write_all(bundle.as_bytes()).context(WriteSnafu)?;
    out.flush().context(WriteSnafu)?;
    CanonicalPath::from_canonical(&target)
        .map(Some)
        .context(NotCanonicalSnafu)
}

/// The certificate blocks in `text`, each from its `BEGIN` line to its `END` line.
fn certificates_in(text: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(BEGIN) {
        let after = &rest[start..];
        let Some(end) = after.find(END) else {
            break;
        };
        let block_end = end + END.len();
        found.push(after[..block_end].replace("\r\n", "\n"));
        rest = &after[block_end..];
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    const CERT_A: &str = "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----";
    const CERT_B: &str = "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----";

    struct Rig {
        dir: TempDir,
        session: CanonicalPath,
    }

    fn rig() -> Rig {
        let dir = assert_ok!(TempDir::new());
        let root = assert_ok!(fs::canonicalize(dir.path()));
        let session_path = root.join("session");
        assert_ok!(fs::create_dir(&session_path));
        let session = assert_ok!(CanonicalPath::from_canonical(&session_path));
        Rig { dir, session }
    }

    impl Rig {
        fn file(&self, name: &str, text: &str) -> CanonicalPath {
            let path = assert_ok!(fs::canonicalize(self.dir.path())).join(name);
            assert_ok!(fs::write(&path, text));
            assert_ok!(CanonicalPath::from_canonical(&path))
        }

        fn bundle_text(&self, path: &CanonicalPath) -> String {
            assert_ok!(fs::read_to_string(path.as_path()))
        }
    }

    #[test]
    fn no_files_means_no_bundle_and_nothing_is_written() {
        let rig = rig();
        assert_eq!(assert_ok!(write_bundle(&rig.session, &[])), None);
        assert_eq!(assert_ok!(fs::read_dir(rig.session.as_path())).count(), 0);
    }

    #[test]
    fn one_file_becomes_a_private_bundle_inside_the_session_directory() {
        let rig = rig();
        let ca = rig.file("ca.pem", &format!("{CERT_A}\n"));
        let bundle = assert_some!(assert_ok!(write_bundle(&rig.session, &[ca])));
        assert_eq!(bundle.as_path(), rig.session.as_path().join(BUNDLE_NAME));
        assert_eq!(rig.bundle_text(&bundle), format!("{CERT_A}\n"));
        let mode = assert_ok!(fs::metadata(bundle.as_path()))
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn several_files_are_joined_in_the_order_given_with_a_newline_between() {
        let rig = rig();
        let first = rig.file("a.pem", CERT_A); // no trailing newline
        let second = rig.file("b.pem", &format!("{CERT_B}\n"));
        let bundle = assert_some!(assert_ok!(write_bundle(&rig.session, &[second, first])));
        assert_eq!(
            rig.bundle_text(&bundle),
            format!("{CERT_B}\n{CERT_A}\n"),
            "the order of the config, one certificate per block, a newline after each"
        );
    }

    #[test]
    fn only_the_certificates_are_copied_not_a_key_or_notes_in_the_same_file() {
        let rig = rig();
        let text = format!(
            "# corporate root\n-----BEGIN PRIVATE KEY-----\nSECRETKEY\n-----END PRIVATE KEY-----\n{CERT_A}\nnotes\n{CERT_B}\n"
        );
        let ca = rig.file("mixed.pem", &text);
        let bundle = assert_some!(assert_ok!(write_bundle(&rig.session, &[ca])));
        let written = rig.bundle_text(&bundle);
        assert_eq!(written, format!("{CERT_A}\n{CERT_B}\n"));
        assert!(!written.contains("SECRETKEY"));
    }

    #[test]
    fn windows_line_endings_are_normalised() {
        let rig = rig();
        let ca = rig.file("crlf.pem", &CERT_A.replace('\n', "\r\n"));
        let bundle = assert_some!(assert_ok!(write_bundle(&rig.session, &[ca])));
        assert_eq!(rig.bundle_text(&bundle), format!("{CERT_A}\n"));
    }

    #[test]
    fn a_file_with_no_certificate_is_an_error_that_names_it() {
        let rig = rig();
        let good = rig.file("good.pem", CERT_A);
        for (name, text) in [
            ("der.pem", "\u{0}\u{1}binary"),
            ("empty.pem", ""),
            (
                "key.pem",
                "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n",
            ),
            ("cut.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n"),
        ] {
            let bad = rig.file(name, text);
            let error = assert_err!(write_bundle(&rig.session, &[good.clone(), bad]));
            assert!(
                matches!(error, CaBundleError::NoCertificate { .. }),
                "{name}"
            );
            assert!(error.to_string().contains(name), "{error}");
        }
        assert!(
            !rig.session.as_path().join(BUNDLE_NAME).exists(),
            "a failed build must leave no bundle"
        );
    }

    #[test]
    fn a_file_that_cannot_be_read_names_the_file() {
        let rig = rig();
        let ca = rig.file("gone.pem", CERT_A);
        assert_ok!(fs::remove_file(ca.as_path()));
        let error = assert_err!(write_bundle(&rig.session, &[ca]));
        assert!(matches!(error, CaBundleError::Read { .. }));
        assert!(error.to_string().contains("gone.pem"));
    }

    #[test]
    fn the_size_limits_are_enforced_per_file_and_in_total() {
        let rig = rig();
        let padding = "x".repeat(usize::try_from(MAX_FILE_BYTES).unwrap_or(0) + 1);
        let big = rig.file("big.pem", &format!("{CERT_A}\n{padding}"));
        assert!(matches!(
            assert_err!(write_bundle(&rig.session, &[big])),
            CaBundleError::FileTooLarge { .. }
        ));
        // Many small files that together pass the bundle limit.
        let block = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            "A".repeat(1000)
        );
        let body = block.repeat(900); // about 0.9 MiB each, under the per-file limit
        let files: Vec<CanonicalPath> = (0..6)
            .map(|i| rig.file(&format!("m{i}.pem"), &body))
            .collect();
        assert!(matches!(
            assert_err!(write_bundle(&rig.session, &files)),
            CaBundleError::BundleTooLarge { .. }
        ));
    }

    #[test]
    fn a_second_bundle_in_the_same_session_directory_is_refused_not_overwritten() {
        let rig = rig();
        let ca = rig.file("ca.pem", CERT_A);
        assert_some!(assert_ok!(write_bundle(
            &rig.session,
            std::slice::from_ref(&ca)
        )));
        let error = assert_err!(write_bundle(&rig.session, &[ca]));
        assert!(matches!(error, CaBundleError::Write { .. }));
    }

    #[test]
    fn errors_follow_the_display_convention_and_escape_what_a_path_can_hold() {
        for error in [
            CaBundleError::NoCertificate {
                path: "/x/\u{1b}[31mred.pem".to_owned(),
            },
            CaBundleError::FileTooLarge {
                path: "/x/a\nb".to_owned(),
                limit: 1,
            },
            CaBundleError::BundleTooLarge { limit: 1 },
        ] {
            crate::error::conventions::assert_display_excludes_sources(&error);
            let text = error.to_string();
            assert!(text.chars().all(|c| !c.is_control()), "{text:?}");
        }
    }
}
