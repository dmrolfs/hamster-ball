// ABOUTME: pub(crate) raw TOML schema: string-typed, deny_unknown_fields, no validation beyond shape.
// ABOUTME: Never exported; `resolve_file` is the only consumer, converting each entry into a validated type.
//! The raw shape of a `hamster-ball.toml` file, before any entry is resolved against the
//! filesystem or validated against a newtype.
//!
//! Every field here is deliberately a plain string, integer or bool: resolving `"8080"` into a
//! [`crate::policy::Port`], say, is `resolve_file`'s job, not `serde`'s, so a bad value produces
//! a typed resolution error with full context instead of a bare serde message.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::origin::KeyPath;

/// The top-level shape of one config file.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawConfig {
    pub(crate) extends: Vec<String>,
    pub(crate) fs: RawFs,
    pub(crate) net: RawNet,
    pub(crate) env: RawEnv,
    pub(crate) tls: RawTls,
    pub(crate) terminal: RawTerminal,
    pub(crate) ctl: RawCtl,
    pub(crate) mcp: BTreeMap<String, RawMcpServer>,
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
    pub(crate) set: BTreeMap<String, String>,
    pub(crate) tools: Vec<String>,
}

/// `[tls]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawTls {
    pub(crate) system_trust: Option<bool>,
    pub(crate) extra_ca_files: Vec<String>,
}

/// `[terminal]`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub(crate) struct RawTerminal {
    pub(crate) clipboard_write: Option<bool>,
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
    pub(crate) bind_ports: Vec<i64>,
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
    pub(crate) file: PathBuf,
    pub(crate) line: u32,
    pub(crate) column: u32,
    pub(crate) message: String,
    pub(crate) key: KeyPath,
}

/// Parses `text` into [`RawConfig`], reporting the exact key path on failure.
pub(crate) fn parse(text: &crate::config::ConfigText) -> Result<RawConfig, ParseError> {
    parse_str(text.as_str(), text.path())
}

/// Parses `source`, which was read from `file`, into [`RawConfig`].
///
/// The pure core of [`parse`]: `file` is used only to label an error.
pub(crate) fn parse_str(source: &str, file: &Path) -> Result<RawConfig, ParseError> {
    let deserializer = match toml::Deserializer::parse(source) {
        Ok(deserializer) => deserializer,
        Err(error) => return Err(build_parse_error(source, file, &error, KeyPath::root())),
    };
    serde_path_to_error::deserialize(deserializer).map_err(|error| {
        let key = convert_path(error.path());
        build_parse_error(source, file, error.inner(), key)
    })
}

/// Which user-only sections a file mentions, whatever their value.
///
/// `hooks` run unsandboxed on the host and `guard.exceptions` switch secret protection off, so
/// only files the user controls may carry them (see `closure`). This probe answers "does the
/// key appear" without depending on the sections' shape, so it keeps working when the hooks
/// schema changes, and it sees `hooks = []` that the typed schema cannot tell from absence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct UserOnlySections {
    /// `hooks` appears in any TOML spelling.
    pub(crate) hooks: bool,
    /// `guard.exceptions` appears in any TOML spelling.
    pub(crate) guard_exceptions: bool,
}

impl UserOnlySections {
    /// Whether any user-only section is present.
    pub(crate) fn any(self) -> bool {
        self.hooks || self.guard_exceptions
    }
}

#[derive(Deserialize, Default)]
struct UserOnlyProbe {
    hooks: Option<serde::de::IgnoredAny>,
    guard: Option<GuardProbe>,
}

#[derive(Deserialize, Default)]
struct GuardProbe {
    exceptions: Option<serde::de::IgnoredAny>,
}

/// Probes `source` for user-only sections.
///
/// A document that does not parse reports none: it will fail the real parse next, so nothing
/// in it can take effect.
pub(crate) fn user_only_sections(source: &str) -> UserOnlySections {
    let probe: UserOnlyProbe = toml::from_str(source).unwrap_or_default();
    UserOnlySections {
        hooks: probe.hooks.is_some(),
        guard_exceptions: probe.guard.is_some_and(|guard| guard.exceptions.is_some()),
    }
}

/// Converts a `serde_path_to_error::Path` into this crate's own [`KeyPath`].
fn convert_path(path: &serde_path_to_error::Path) -> KeyPath {
    use serde_path_to_error::Segment;
    let mut key = KeyPath::root();
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
/// span into a 1-based line and column by counting newlines in the already-resident text.
fn build_parse_error(
    source: &str,
    file: &Path,
    error: &toml::de::Error,
    key: KeyPath,
) -> ParseError {
    let (line, column) = error
        .span()
        .map_or((1, 1), |span| line_column_at(source, span.start));
    ParseError {
        file: file.to_path_buf(),
        line,
        column,
        message: error.message().to_owned(),
        key,
    }
}

/// 1-based line and column (in characters) of byte offset `at` in `text`.
///
/// An offset past the end is clamped, and one inside a multibyte character is moved back to
/// that character's start, so hostile input can never make this slice mid-character.
fn line_column_at(text: &str, at: usize) -> (u32, u32) {
    let mut at = at.min(text.len());
    while !text.is_char_boundary(at) {
        at -= 1;
    }
    let before = &text[..at];
    let line = before.matches('\n').count();
    let column = before
        .rsplit('\n')
        .next()
        .map_or(0, |last| last.chars().count());
    (saturating_u32(line) + 1, saturating_u32(column) + 1)
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    const FILE: &str = "/p/hamster-ball.toml";

    fn parsed(toml_text: &str) -> Result<RawConfig, ParseError> {
        parse_str(toml_text, Path::new(FILE))
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
             bind_ports = [24282]\n"
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

    #[test]
    fn a_leading_byte_order_mark_is_accepted() {
        // Pinned behavior: the toml crate skips a BOM, so a file saved by an editor that adds
        // one still parses. The exact bytes (BOM included) are what approval hashes.
        let config = assert_ok!(parsed("\u{feff}[fs]\nwrite = [\"x\"]\n"));
        assert_eq!(config.fs.write, vec!["x"]);
    }

    // ====================================================================================
    // Rejected shapes
    // ====================================================================================

    #[test]
    fn unknown_top_level_key_reports_the_file_and_key() {
        let err = assert_err!(parsed("bogus_field = 1\n"));
        assert_eq!(err.key.to_string(), "bogus_field");
        assert_eq!(err.file, Path::new(FILE));
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
    fn wrong_element_type_reports_the_index() {
        let err = assert_err!(parsed("[fs]\nwrite = [\"a\", 2]\n"));
        assert_eq!(err.key.to_string(), "fs.write[1]");
    }

    #[test]
    fn duplicate_table_reports_the_line_of_the_second_table() {
        let err = assert_err!(parsed("[fs]\nwrite = [\".\"]\n[fs]\nwrite = [\"x\"]\n"));
        assert_eq!(err.line, 3);
    }

    #[test]
    fn syntax_error_carries_the_file_line_and_column() {
        let err = assert_err!(parsed("a = 1\nfs = [this is not valid toml\n"));
        assert_eq!(err.file, Path::new(FILE));
        assert_eq!(err.line, 2);
        assert!(err.column > 1, "{err:?}");
    }

    #[test]
    fn wrong_type_reports_line_and_column_of_the_value() {
        let err = assert_err!(parsed("[fs]\nwrite = \"not-a-list\"\n"));
        assert_eq!((err.line, err.column), (2, 9));
    }

    #[test]
    fn column_counts_characters_not_bytes() {
        // Two multibyte strings precede the error, so a byte column would be larger.
        let err = assert_err!(parsed("[fs]\nwrite = [\"héllo\", \"日本語\" \"x\"]\n"));
        assert_eq!((err.line, err.column), (2, 25));
    }

    #[test]
    fn nul_escape_in_a_string_survives_into_the_parsed_value() {
        let config = assert_ok!(parsed("[fs]\nwrite = [\"a\\u0000b\"]\n"));
        assert_eq!(config.fs.write[0].as_bytes(), b"a\0b");
    }

    #[test]
    fn hostile_nesting_is_a_clean_error_not_a_stack_overflow() {
        // Runs on a test thread, whose stack is smaller than the main thread's.
        let arrays = format!("a = {}{}\n", "[".repeat(100_000), "]".repeat(100_000));
        let err = assert_err!(parsed(&arrays));
        assert!(err.message.contains("recurse"), "{}", err.message);

        let tables = format!("a = {}1{}\n", "{b=".repeat(30_000), "}".repeat(30_000));
        assert_err!(parsed(&tables));
    }

    // ====================================================================================
    // User-only section probe
    // ====================================================================================

    fn probe(toml_text: &str) -> UserOnlySections {
        user_only_sections(toml_text)
    }

    #[test]
    fn the_probe_flags_every_spelling_of_a_hooks_key() {
        for spelling in [
            "[hooks]\n",
            "[hooks.a.b]\nx = 1\n",
            "[[hooks]]\n",
            "hooks = []\n",
            "hooks.x = 1\n",
            "hooks = {}\n",
            "\"hooks\" = []\n",
            "'hooks' = []\n",
            "\"h\\u006foks\" = []\n",
            "  hooks   =   []\n",
            "hooks = [[\"echo\"]]\n",
            "a = 1\n[hooks.pre_run.x]\ncommand = [\"echo\"]\n",
        ] {
            assert!(probe(spelling).hooks, "{spelling:?} was not flagged");
        }
    }

    #[test]
    fn the_probe_does_not_flag_look_alikes() {
        for innocent in [
            "# hooks = []\n",
            "x = \"hooks\"\n",
            "[fs]\nwrite = [\"hooks\"]\n",
            "extends = [\"hooks\"]\n",
            "",
        ] {
            assert!(!probe(innocent).hooks, "{innocent:?} was flagged");
        }
    }

    #[test]
    fn the_probe_flags_guard_exceptions_but_not_an_empty_guard_table() {
        for spelling in [
            "[guard]\nexceptions = []\n",
            "guard.exceptions = [\".env\"]\n",
            "guard = { exceptions = [] }\n",
            "[guard]\n\"exceptions\" = [\"x\"]\n",
        ] {
            assert!(
                probe(spelling).guard_exceptions,
                "{spelling:?} was not flagged"
            );
        }
        assert!(!probe("[guard]\n").guard_exceptions);
        assert!(!probe("guard = {}\n").guard_exceptions);
    }

    #[test]
    fn the_probe_reports_each_section_independently() {
        let both = probe("hooks = []\n[guard]\nexceptions = []\n");
        assert!(both.hooks && both.guard_exceptions);
        assert!(!probe("hooks = []\n").guard_exceptions);
        assert!(!probe("[guard]\nexceptions = []\n").hooks);
    }

    #[test]
    fn the_probe_gives_no_false_alarm_on_a_syntax_error_because_resolve_reports_it() {
        assert_eq!(probe("hooks = [\n"), UserOnlySections::default());
    }

    #[test]
    fn the_probe_is_independent_of_the_hooks_value_shape() {
        // hb-ghd.6.1 will change the hooks schema; the rule must not depend on it.
        assert!(probe("[hooks.pre_run.cred]\ncommand = [\"x\"]\ntimeout = 5\n").hooks);
    }

    // ====================================================================================
    // Error text
    // ====================================================================================

    #[test]
    fn display_never_contains_the_source_excerpt_box() {
        let err = assert_err!(parsed("[fs]\nwrite = \"not-a-list\"\n"));
        let shown = err.to_string();
        // The message legitimately names the bad value; what must never appear is the
        // multi-line "2 | write = ..." excerpt box with its `^^^` marker that
        // `toml::de::Error`'s own `Display` embeds.
        assert!(!shown.contains('\n'), "{shown:?}");
        assert!(!shown.contains('^'), "{shown:?}");
        assert!(!shown.contains("write ="), "{shown:?}");
    }

    #[test]
    fn display_is_file_line_column_message() {
        let err = assert_err!(parsed("[fs]\nwrite = \"x\"\n"));
        assert!(
            err.to_string().starts_with("/p/hamster-ball.toml:2:9: "),
            "{err}"
        );
    }

    #[test]
    fn display_escapes_a_hostile_file_name() {
        let err = assert_err!(parse_str("a = [", Path::new("/p/\u{1b}[2J.toml")));
        assert!(!err.to_string().contains('\u{1b}'), "{err}");
    }

    // ====================================================================================
    // line_column_at
    // ====================================================================================

    #[test]
    fn line_column_at_is_one_based_and_counts_newlines() {
        assert_eq!(line_column_at("abc", 0), (1, 1));
        assert_eq!(line_column_at("abc", 2), (1, 3));
        assert_eq!(line_column_at("a\nbc", 2), (2, 1));
        assert_eq!(line_column_at("a\nbc", 3), (2, 2));
        assert_eq!(line_column_at("a\nb\nc", 4), (3, 1));
    }

    #[test]
    fn line_column_at_treats_crlf_as_one_line_break() {
        assert_eq!(line_column_at("a\r\nb", 3), (2, 1));
    }

    #[test]
    fn line_column_at_clamps_an_offset_past_the_end() {
        assert_eq!(line_column_at("ab", 99), (1, 3));
        assert_eq!(line_column_at("", 5), (1, 1));
    }

    #[test]
    fn line_column_at_never_slices_inside_a_multibyte_character() {
        let text = "é\nñx";
        // Byte 1 is the middle of `é`; every offset must be safe.
        for at in 0..=text.len() + 2 {
            let _ = line_column_at(text, at);
        }
        assert_eq!(line_column_at(text, 1), (1, 1));
    }

    #[test]
    fn line_column_at_counts_characters_in_the_current_line() {
        assert_eq!(line_column_at("é\nñx", "é\nñ".len()), (2, 2));
    }

    proptest::proptest! {
        #[test]
        fn line_column_at_never_panics_and_stays_in_range(text in "\\PC{0,40}", at in 0usize..200) {
            let (line, column) = line_column_at(&text, at);
            proptest::prop_assert!(line >= 1);
            proptest::prop_assert!(column >= 1);
            proptest::prop_assert!(line as usize <= text.matches('\n').count() + 1);
        }

        #[test]
        fn parse_str_never_panics_on_arbitrary_text(text in "\\PC{0,200}") {
            let _ = parse_str(&text, Path::new(FILE));
        }
    }
}
