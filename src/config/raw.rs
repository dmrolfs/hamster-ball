// ABOUTME: pub(crate) raw TOML schema: string-typed, deny_unknown_fields, no validation beyond shape.
// ABOUTME: Never exported; `resolve_file` is the only consumer, converting each entry into a validated type.
//! The raw shape of a `hamster-ball.toml` file, before any entry is resolved against the
//! filesystem or validated against a newtype.
//!
//! Every field here is deliberately a plain string, integer or bool: resolving `"8080"` into a
//! [`crate::policy::Port`], say, is `resolve_file`'s job, not `serde`'s, so a bad value produces
//! a typed resolution error with full context instead of a bare serde message.

use std::collections::HashMap;

use serde::Deserialize;

/// The top-level shape of one config file.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawConfig {
    pub(crate) extends: Vec<String>,
    pub(crate) fs: RawFs,
    pub(crate) net: RawNet,
    pub(crate) env: RawEnv,
    pub(crate) tls: RawTls,
    pub(crate) ctl: RawCtl,
    pub(crate) mcp: HashMap<String, RawMcpServer>,
    pub(crate) hooks: Vec<Vec<String>>,
    pub(crate) guard: RawGuard,
}

/// `[fs]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawFs {
    pub(crate) read: Vec<String>,
    pub(crate) write: Vec<String>,
    pub(crate) deny_read: Vec<String>,
    pub(crate) deny_write: Vec<String>,
}

/// `[net]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawNet {
    pub(crate) allow: Vec<String>,
    pub(crate) loopback_ports: Vec<i64>,
}

/// `[env]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawEnv {
    pub(crate) pass: Vec<String>,
    pub(crate) set: HashMap<String, String>,
}

/// `[tls]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawTls {
    pub(crate) system_trust: Option<bool>,
    pub(crate) extra_ca_files: Vec<String>,
}

/// `[ctl]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawCtl {
    pub(crate) label: Option<String>,
    pub(crate) containers: Vec<String>,
}

/// One `[mcp.<name>]` entry.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawMcpServer {
    pub(crate) command: Option<String>,
    pub(crate) args: Vec<String>,
    pub(crate) net: Vec<String>,
    pub(crate) bind_loopback: Option<bool>,
}

/// `[guard]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawGuard {
    pub(crate) exceptions: Vec<String>,
}

/// Why a raw TOML document could not be parsed.
///
/// Built from the TOML library's structured `.span()` and `.message()`, never its `Display`,
/// which embeds the raw source line verbatim (confirmed directly: `toml::de::Error`'s own
/// `Display` prints the offending line with a `^^^` marker). Printing that would bypass every
/// escaping this crate does elsewhere and leak untrusted file content.
#[derive(Debug, snafu::Snafu)]
#[snafu(display(
    "{}:{line}:{column}: {}",
    crate::text::Escaped(&file.to_string_lossy()),
    crate::text::Escaped(message)
))]
pub(crate) struct ParseError {
    pub(crate) file: std::path::PathBuf,
    pub(crate) line: u32,
    pub(crate) column: u32,
    pub(crate) message: String,
    pub(crate) key: crate::origin::KeyPath,
}

/// Parses `text` into [`RawConfig`], reporting the exact key path on failure.
pub(crate) fn parse(text: &crate::config::ConfigText) -> Result<RawConfig, ParseError> {
    let deserializer = match toml::Deserializer::parse(text.as_str()) {
        Ok(deserializer) => deserializer,
        Err(error) => {
            return Err(build_parse_error(
                text,
                &error,
                crate::origin::KeyPath::root(),
            ));
        }
    };
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let key = convert_path(error.path());
        build_parse_error(text, error.inner(), key)
    })
}

/// Converts a `serde_path_to_error::Path` into this crate's own [`crate::origin::KeyPath`].
fn convert_path(path: &serde_path_to_error::Path) -> crate::origin::KeyPath {
    use serde_path_to_error::Segment;
    let mut key = crate::origin::KeyPath::root();
    for segment in path.iter() {
        key = match segment {
            Segment::Seq { index } => key.index(*index),
            Segment::Map { key: name } => key.key(name.clone()),
            Segment::Enum { variant } => key.field(variant.clone()),
            Segment::Unknown => key.field("?"),
        };
    }
    key
}

/// Builds a [`ParseError`] from a `toml::de::Error`'s structured accessors, converting its byte
/// span into a 1-based line and column by counting newlines in the already-resident bytes.
fn build_parse_error(
    text: &crate::config::ConfigText,
    error: &toml::de::Error,
    key: crate::origin::KeyPath,
) -> ParseError {
    let (line, column) = error
        .span()
        .map_or((1, 1), |span| line_column_at(text.as_str(), span.start));
    ParseError {
        file: text.path().to_path_buf(),
        line,
        column,
        message: error.message().to_owned(),
        key,
    }
}

/// 1-based line and column of byte offset `at` in `text`.
fn line_column_at(text: &str, at: usize) -> (u32, u32) {
    let before = &text[..at.min(text.len())];
    let line = u32::try_from(before.matches('\n').count()).unwrap_or(u32::MAX) + 1;
    let column =
        u32::try_from(before.rsplit('\n').next().map_or(0, str::len)).unwrap_or(u32::MAX) + 1;
    (line, column)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::fs;

    fn parsed(toml_text: &str) -> Result<RawConfig, ParseError> {
        let dir = assert_ok!(tempfile::TempDir::new());
        let path = dir.path().join("hamster-ball.toml");
        assert_ok!(fs::write(&path, toml_text));
        let text = assert_ok!(crate::config::ConfigText::read(
            &path,
            crate::origin::Layer::Project,
            false
        ));
        parse(&text)
    }

    // ====================================================================================
    // Accepted shapes
    // ====================================================================================

    #[test]
    fn parses_the_design_sample() {
        let config = assert_ok!(parsed(
            "extends = [\"rust\", \"git\"]\n\
             [fs]\n\
             read = [\"~/work/shared-fixtures\"]\n\
             write = [\".\"]\n\
             [net]\n\
             allow = [\"crates.io\"]\n\
             loopback_ports = [3030]\n\
             [env]\n\
             pass = [\"TERM\"]\n\
             [env.set]\n\
             RUST_BACKTRACE = \"1\"\n\
             [tls]\n\
             system_trust = true\n\
             [ctl]\n\
             label = \"com.docker.compose.project=icehouse\"\n\
             [mcp.serena]\n\
             command = \"uvx\"\n\
             args = [\"start-mcp-server\"]\n\
             bind_loopback = true\n"
        ));
        assert_eq!(config.extends, vec!["rust", "git"]);
        assert_eq!(config.fs.write, vec!["."]);
        assert_eq!(config.net.loopback_ports, vec![3030]);
        assert_eq!(config.env.set.get("RUST_BACKTRACE"), Some(&"1".to_owned()));
        assert_eq!(config.tls.system_trust, Some(true));
        let serena = assert_some!(config.mcp.get("serena"));
        assert_eq!(serena.command, Some("uvx".to_owned()));
    }

    #[test]
    fn hooks_and_guard_parse_with_deny_unknown_fields() {
        let config = assert_ok!(parsed(
            "hooks = [[\"echo\", \"hi\"]]\n[guard]\nexceptions = [\".env\"]\n"
        ));
        assert_eq!(config.hooks, vec![vec!["echo".to_owned(), "hi".to_owned()]]);
        assert_eq!(config.guard.exceptions, vec![".env"]);
    }

    #[test]
    fn empty_file_parses_to_defaults() {
        let config = assert_ok!(parsed(""));
        assert!(config.fs.write.is_empty());
    }

    // ====================================================================================
    // Rejected shapes
    // ====================================================================================

    #[test]
    fn unknown_top_level_key_reports_the_file_and_key() {
        let err = assert_err!(parsed("bogus_field = 1\n"));
        assert_eq!(err.key.to_string(), "bogus_field");
        assert!(err.message.contains("unknown field"), "{}", err.message);
    }

    #[test]
    fn unknown_nested_key_reports_fs_wrte() {
        let err = assert_err!(parsed("[fs]\nwrte = [\"x\"]\n"));
        assert_eq!(err.key.to_string(), "fs.wrte");
    }

    #[test]
    fn unknown_field_inside_an_mcp_entry_reports_the_full_path() {
        let err = assert_err!(parsed("[mcp.serena]\nbogus = 1\n"));
        assert_eq!(err.key.to_string(), "mcp.serena.bogus");
    }

    #[test]
    fn wrong_type_reports_fs_write_without_spanned_private_segment() {
        let err = assert_err!(parsed("[fs]\nwrite = \"not-a-list\"\n"));
        assert_eq!(err.key.to_string(), "fs.write");
        assert!(
            !err.key.to_string().contains("$__serde_spanned_private"),
            "{}",
            err.key
        );
    }

    #[test]
    fn duplicate_table_reports_file_and_line() {
        let err = assert_err!(parsed("[fs]\nwrite = [\".\"]\n[fs]\nwrite = [\"x\"]\n"));
        assert!(err.line >= 1, "{err:?}");
    }

    #[test]
    fn syntax_error_carries_the_file() {
        let dir = assert_ok!(tempfile::TempDir::new());
        let path = dir.path().join("hamster-ball.toml");
        assert_ok!(fs::write(&path, "fs = [this is not valid toml\n"));
        let text = assert_ok!(crate::config::ConfigText::read(
            &path,
            crate::origin::Layer::Project,
            false
        ));
        let err = assert_err!(parse(&text));
        assert_eq!(err.file, path);
    }

    #[test]
    fn nul_escape_in_a_string_survives_into_the_parsed_value() {
        let config = assert_ok!(parsed("[fs]\nwrite = [\"a\\u0000b\"]\n"));
        assert_eq!(config.fs.write[0].as_bytes(), b"a\0b");
    }

    #[test]
    fn display_never_contains_the_source_excerpt_box() {
        let dir = assert_ok!(tempfile::TempDir::new());
        let path = dir.path().join("hamster-ball.toml");
        assert_ok!(fs::write(&path, "[fs]\nwrite = \"not-a-list\"\n"));
        let text = assert_ok!(crate::config::ConfigText::read(
            &path,
            crate::origin::Layer::Project,
            false
        ));
        let err = assert_err!(parse(&text));
        let shown = err.to_string();
        // The message legitimately names the bad value (ordinary, useful error reporting);
        // what must never appear is the multi-line "2 | write = ..." excerpt box with its
        // `^^^` marker that `toml::de::Error`'s own `Display` embeds.
        assert!(!shown.contains('\n'), "{shown:?}");
        assert!(!shown.contains("write ="), "{shown:?}");
    }

    #[test]
    fn error_never_echoes_the_source_excerpt() {
        // Regression for the Display-leak finding: toml::de::Error's own Display embeds the
        // raw file line with a ^^^ marker; this crate's ParseError must never call it.
        let err = assert_err!(parsed("[fs]\nwrite = \"not-a-list\"\n"));
        assert!(!err.to_string().contains('^'), "{}", err);
    }
}
