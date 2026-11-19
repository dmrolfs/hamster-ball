// ABOUTME: Where a config value came from: layer, file, key path and line, plus Located<T> to carry it with the value.
// ABOUTME: Lets errors and `hb explain` say "fs.write[2] in /proj/hamster-ball.toml:12" without later signature changes.
//! Provenance for configuration values.

use std::fmt;
use std::path::{Path, PathBuf};

use strum::{Display, IntoStaticStr};

use crate::text::{Escaped, needs_escaping};

/// The layer a config file belongs to, ordered from lowest to highest precedence.
///
/// `Display` and `IntoStaticStr` give the lowercase snake_case name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Layer {
    /// Rules compiled into `hb`; nothing can override them.
    Floor,
    /// The user's base config, always applied.
    UserBase,
    /// A preset named in `extends`.
    Preset,
    /// The project's `hamster-ball.toml`.
    Project,
}

/// One step in a key path.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// A schema field name such as `fs` or `write`; always printed bare.
    Field(String),
    /// A user-chosen map key such as an MCP server name; quoted when it is not a plain word.
    Key(String),
    /// A list index.
    Index(usize),
}

/// A path to a value inside a config file, printed like `fs.write[2]` or `mcp."a.b".command`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyPath(Vec<Segment>);

impl KeyPath {
    /// An empty path, meaning the whole file.
    #[must_use]
    pub fn root() -> Self {
        Self(Vec::new())
    }

    /// Appends a schema field name.
    #[must_use]
    pub fn field(mut self, name: impl Into<String>) -> Self {
        self.0.push(Segment::Field(name.into()));
        self
    }

    /// Appends a user-chosen map key; it is quoted and escaped when printed if it is not a plain word.
    #[must_use]
    pub fn key(mut self, key: impl Into<String>) -> Self {
        self.0.push(Segment::Key(key.into()));
        self
    }

    /// Appends a list index.
    #[must_use]
    pub fn index(mut self, index: usize) -> Self {
        self.0.push(Segment::Index(index));
        self
    }
}

/// Whether a map key can be printed without quotes (a TOML bare key).
fn is_bare_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Writes `key` in double quotes, escaping quotes, backslashes and control characters.
fn write_quoted(f: &mut fmt::Formatter<'_>, key: &str) -> fmt::Result {
    f.write_str("\"")?;
    for c in key.chars() {
        match c {
            '"' => f.write_str("\\\"")?,
            '\\' => f.write_str("\\\\")?,
            c if needs_escaping(c) => write!(f, "{}", c.escape_default())?,
            c => write!(f, "{c}")?,
        }
    }
    f.write_str("\"")
}

impl fmt::Display for KeyPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("(file)");
        }
        for (position, segment) in self.0.iter().enumerate() {
            match segment {
                Segment::Index(index) => write!(f, "[{index}]")?,
                Segment::Field(name) | Segment::Key(name) if is_bare_key(name) => {
                    if position > 0 {
                        f.write_str(".")?;
                    }
                    f.write_str(name)?;
                }
                Segment::Field(name) | Segment::Key(name) => {
                    if position > 0 {
                        f.write_str(".")?;
                    }
                    write_quoted(f, name)?;
                }
            }
        }
        Ok(())
    }
}

/// Where a value was declared: layer, file, key path, and the line when known.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Origin {
    /// The layer the file belongs to.
    pub layer: Layer,
    /// The file the value came from.
    pub file: PathBuf,
    /// The key path inside the file.
    pub key: KeyPath,
    /// The 1-based line, when known.
    pub line: Option<u32>,
}

impl Origin {
    /// An origin without a line number.
    #[must_use]
    pub fn new(layer: Layer, file: impl AsRef<Path>, key: KeyPath) -> Self {
        Self {
            layer,
            file: file.as_ref().to_path_buf(),
            key,
            line: None,
        }
    }

    /// Adds a 1-based line number.
    #[must_use]
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Escaped(&self.file.to_string_lossy()))?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        write!(f, " ({})", self.key)
    }
}

/// A validated value together with the place it was declared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located<T> {
    /// The value.
    pub value: T,
    /// Where it was declared.
    pub origin: Origin,
}

impl<T> Located<T> {
    /// Pairs a value with its origin.
    #[must_use]
    pub fn new(value: T, origin: Origin) -> Self {
        Self { value, origin }
    }
}

/// Which file of a loaded closure a value came from: an index into the closure's file list.
///
/// A `u16` because a closure is capped at a few dozen files; it keeps provenance records small.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(u16);

impl FileId {
    /// Wraps an index into the closure's file list.
    #[must_use]
    pub fn new(index: u16) -> Self {
        Self(index)
    }

    /// The index into the closure's file list.
    #[must_use]
    pub fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// Where one merged value came from, compactly.
///
/// A full [`Origin`] costs about 300 bytes (path and key path); this is a few bytes. The
/// closure turns a `Source` back into an `Origin` on demand, for errors and `hb explain`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Source {
    /// A value declared in a loaded file.
    File {
        /// The file.
        file: FileId,
        /// The entry's index in its list in that file, when it came from a list.
        index: Option<u32>,
    },
}

impl Source {
    /// A source for a list entry at `index` in `file`.
    #[must_use]
    pub fn entry(file: FileId, index: u32) -> Self {
        Self::File {
            file,
            index: Some(index),
        }
    }

    /// A source for a value with no list position (a map entry or a scalar) in `file`.
    #[must_use]
    pub fn value(file: FileId) -> Self {
        Self::File { file, index: None }
    }

    /// The file this value came from.
    #[must_use]
    pub fn file(self) -> FileId {
        match self {
            Self::File { file, .. } => file,
        }
    }
}

/// A merged value and every place it was declared.
///
/// Equal values from several files collapse into one `Sourced` that keeps all their sources,
/// so `hb explain` can say "base and project both grant this" and the approval summary can tell
/// a genuine addition from a restatement of something the base already gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sourced<T> {
    /// The value.
    pub value: T,
    /// Every declaration of this value, sorted, never empty.
    pub sources: Vec<Source>,
}

impl<T> Sourced<T> {
    /// A value declared once.
    #[must_use]
    pub fn new(value: T, source: Source) -> Self {
        Self {
            value,
            sources: vec![source],
        }
    }

    /// A value declared in several places; `sources` is sorted and deduplicated.
    ///
    /// Returns `None` if `sources` is empty, since a value with no declaration cannot exist.
    #[must_use]
    pub fn from_sources(value: T, mut sources: Vec<Source>) -> Option<Self> {
        sources.sort_unstable();
        sources.dedup();
        if sources.is_empty() {
            None
        } else {
            Some(Self { value, sources })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_none, assert_some};
    use pretty_assertions::assert_eq;

    // ====================================================================================
    // Layer
    // ====================================================================================

    #[test]
    fn layers_order_from_lowest_to_highest_precedence() {
        assert!(Layer::Floor < Layer::UserBase);
        assert!(Layer::UserBase < Layer::Preset);
        assert!(Layer::Preset < Layer::Project);
    }

    #[test]
    fn layer_display_and_static_str_are_snake_case() {
        assert_eq!(Layer::UserBase.to_string(), "user_base");
        let name: &'static str = Layer::Project.into();
        assert_eq!(name, "project");
    }

    // ====================================================================================
    // KeyPath
    // ====================================================================================

    #[test]
    fn key_path_prints_fields_and_indexes() {
        assert_eq!(
            KeyPath::root()
                .field("fs")
                .field("write")
                .index(2)
                .to_string(),
            "fs.write[2]"
        );
    }

    #[test]
    fn key_path_root_prints_as_the_whole_file() {
        assert_eq!(KeyPath::root().to_string(), "(file)");
    }

    #[test]
    fn key_path_prints_plain_keys_bare_and_other_keys_quoted() {
        assert_eq!(
            KeyPath::root()
                .field("mcp")
                .key("serena")
                .field("command")
                .to_string(),
            "mcp.serena.command"
        );
        assert_eq!(
            KeyPath::root()
                .field("mcp")
                .key("a.b")
                .field("command")
                .to_string(),
            "mcp.\"a.b\".command"
        );
    }

    #[test]
    fn key_path_escapes_hostile_keys() {
        let shown = KeyPath::root()
            .field("mcp")
            .key("a\"b\n\u{1b}[2J\\")
            .to_string();
        assert!(
            !shown.contains('\n') && !shown.contains('\u{1b}'),
            "{shown:?}"
        );
        assert_eq!(shown, "mcp.\"a\\\"b\\n\\u{1b}[2J\\\\\"");
    }

    #[test]
    fn key_path_quotes_a_non_bare_first_segment_without_a_leading_dot() {
        assert_eq!(KeyPath::root().key("a.b").to_string(), "\"a.b\"");
    }

    #[test]
    fn key_path_keeps_ordinary_non_ascii_keys_readable() {
        assert_eq!(
            KeyPath::root().field("mcp").key("é.x").to_string(),
            "mcp.\"é.x\""
        );
    }

    #[test]
    fn key_path_escapes_text_reordering_and_invisible_characters_in_keys() {
        // Right-to-left override, zero-width space, line separator and BOM are not `Cc`
        // control characters, but each can disguise a key in terminal output.
        for hostile in ["\u{202e}", "\u{200b}", "\u{2028}", "\u{feff}", "\u{2066}"] {
            let shown = KeyPath::root()
                .field("mcp")
                .key(format!("a{hostile}b"))
                .to_string();
            assert!(
                !shown.contains(hostile),
                "{hostile:?} reached the output: {shown:?}"
            );
        }
    }

    #[test]
    fn key_path_root_equals_default() {
        assert_eq!(KeyPath::root(), KeyPath::default());
    }

    #[test]
    fn key_path_consecutive_indexes_have_no_dot() {
        assert_eq!(
            KeyPath::root().field("a").index(0).index(1).to_string(),
            "a[0][1]"
        );
    }

    // ====================================================================================
    // Origin and Located
    // ====================================================================================

    #[test]
    fn origin_display_without_line() {
        let origin = Origin::new(
            Layer::Project,
            "/p/hamster-ball.toml",
            KeyPath::root().field("fs").field("write").index(2),
        );
        assert_eq!(origin.to_string(), "/p/hamster-ball.toml (fs.write[2])");
    }

    #[test]
    fn origin_display_with_line() {
        let origin = Origin::new(
            Layer::UserBase,
            "/h/base.toml",
            KeyPath::root().field("net"),
        )
        .with_line(12);
        assert_eq!(origin.to_string(), "/h/base.toml:12 (net)");
    }

    #[test]
    fn origin_display_escapes_a_hostile_file_name() {
        let origin = Origin::new(Layer::Project, "/p/a\n\u{1b}[2J.toml", KeyPath::root());
        let shown = origin.to_string();
        assert!(
            !shown.contains('\n') && !shown.contains('\u{1b}'),
            "{shown:?}"
        );
    }

    #[test]
    fn origin_keeps_its_parts() {
        let origin =
            Origin::new(Layer::Preset, "/x.toml", KeyPath::root().field("tls")).with_line(3);
        assert_eq!(origin.layer, Layer::Preset);
        assert_eq!(origin.file, PathBuf::from("/x.toml"));
        assert_eq!(origin.line, Some(3));
    }

    #[test]
    fn located_pairs_a_value_with_its_origin() {
        let origin = Origin::new(
            Layer::Project,
            "/p/hamster-ball.toml",
            KeyPath::root().field("net").field("allow").index(0),
        );
        let located = Located::new(443_u16, origin.clone());
        assert_eq!(located.value, 443);
        assert_eq!(located.origin, origin);
    }

    // ====================================================================================
    // FileId, Source, Sourced
    // ====================================================================================

    #[test]
    fn file_id_round_trips_its_index_and_orders_by_it() {
        assert_eq!(FileId::new(7).index(), 7);
        assert!(FileId::new(1) < FileId::new(2));
    }

    #[test]
    fn source_constructors_set_the_index_only_for_list_entries() {
        let file = FileId::new(3);
        assert_eq!(
            Source::entry(file, 5),
            Source::File {
                file,
                index: Some(5)
            }
        );
        assert_eq!(Source::value(file), Source::File { file, index: None });
        assert_eq!(Source::entry(file, 5).file(), file);
    }

    #[test]
    fn sources_sort_by_file_then_index() {
        let (a, b) = (FileId::new(1), FileId::new(2));
        let mut sources = vec![
            Source::entry(b, 0),
            Source::entry(a, 9),
            Source::entry(a, 1),
        ];
        sources.sort();
        assert_eq!(
            sources,
            vec![
                Source::entry(a, 1),
                Source::entry(a, 9),
                Source::entry(b, 0)
            ]
        );
    }

    #[test]
    fn sourced_from_sources_sorts_dedups_and_refuses_an_empty_list() {
        let (a, b) = (FileId::new(1), FileId::new(2));
        let sourced = assert_some!(Sourced::from_sources(
            "v",
            vec![Source::value(b), Source::value(a), Source::value(b)]
        ));
        assert_eq!(sourced.sources, vec![Source::value(a), Source::value(b)]);
        assert_none!(Sourced::from_sources("v", Vec::new()));
    }

    #[test]
    fn sourced_new_has_exactly_one_source() {
        let sourced = Sourced::new(1_u8, Source::value(FileId::new(0)));
        assert_eq!(sourced.sources.len(), 1);
    }

    #[test]
    fn a_source_is_a_few_bytes_where_an_origin_is_hundreds() {
        // An Origin owns a PathBuf and a key path on the heap; a Source is plain data.
        assert!(std::mem::size_of::<Source>() <= 16);
    }
}
