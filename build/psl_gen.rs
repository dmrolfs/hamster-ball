// ABOUTME: Shared parser/generator for the protected-suffix table: compiled by build.rs AND under cfg(test) in the lib.
// ABOUTME: std-only, no crate:: references (build.rs cannot see the crate), so the exact generator logic is unit-testable.
//! Parses the vendored Public Suffix List and the hand-kept supplement into the sorted,
//! deduplicated tables that `policy::host` looks up at run time.
//!
//! This module is included twice: once by `build.rs` (via `#[path]`) to generate
//! `OUT_DIR/psl_generated.rs`, and once by the library crate under `#[cfg(test)]` so unit tests
//! exercise the exact code the build uses, not a reimplementation of it.

use std::collections::BTreeSet;
use std::fmt;

/// Longest accepted vendored-file size, in bytes.
pub const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
/// Longest accepted line count in the vendored file.
pub const MAX_LINES: usize = 20_000;
/// Longest accepted rule, in bytes, before punycode conversion.
pub const MAX_RULE_BYTES: usize = 253;
/// Most labels accepted in one rule (the real list's maximum is 7, including a leading `*.`).
pub const MAX_RULE_LABELS: usize = 12;
/// Longest a single DNS label may be after punycode conversion.
pub const MAX_LABEL_BYTES: usize = 63;

/// Why the vendored list, the supplement file, or a single rule could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PslError {
    /// The file is larger than [`MAX_FILE_BYTES`].
    FileTooLarge { bytes: usize },
    /// The file has more lines than [`MAX_LINES`].
    TooManyLines { lines: usize },
    /// A required section marker was not found.
    MissingMarker { marker: &'static str },
    /// The file contained no rules at all.
    NoRules,
    /// A rule line could not be parsed, with the 1-based line number and the text.
    MalformedRule { line: usize, text: String },
    /// A rule was longer than [`MAX_RULE_BYTES`].
    RuleTooLong { line: usize, bytes: usize },
    /// A rule had more labels than [`MAX_RULE_LABELS`].
    TooManyLabels { line: usize, labels: usize },
    /// A punycode-encoded label would exceed [`MAX_LABEL_BYTES`].
    LabelTooLong { line: usize, label: String },
    /// Encoding overflowed (unreachable for any real DNS label; present so the encoder never panics).
    PunycodeOverflow { line: usize },
    /// An exception rule's parent is not a wildcard parent from the same input.
    ExceptionWithoutWildcardParent { name: String },
}

impl fmt::Display for PslError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileTooLarge { bytes } => {
                write!(f, "file is {bytes} bytes, over the {MAX_FILE_BYTES} limit")
            }
            Self::TooManyLines { lines } => {
                write!(f, "file has {lines} lines, over the {MAX_LINES} limit")
            }
            Self::MissingMarker { marker } => write!(f, "missing required marker: {marker}"),
            Self::NoRules => write!(f, "file contains no rules"),
            Self::MalformedRule { line, text } => write!(f, "line {line}: malformed rule {text:?}"),
            Self::RuleTooLong { line, bytes } => write!(
                f,
                "line {line}: rule is {bytes} bytes, over the {MAX_RULE_BYTES} limit"
            ),
            Self::TooManyLabels { line, labels } => write!(
                f,
                "line {line}: rule has {labels} labels, over the {MAX_RULE_LABELS} limit"
            ),
            Self::LabelTooLong { line, label } => write!(
                f,
                "line {line}: encoded label {label:?} is over {MAX_LABEL_BYTES} bytes"
            ),
            Self::PunycodeOverflow { line } => {
                write!(f, "line {line}: punycode encoding overflowed")
            }
            Self::ExceptionWithoutWildcardParent { name } => {
                write!(
                    f,
                    "exception rule !{name} has no matching wildcard parent rule"
                )
            }
        }
    }
}

impl std::error::Error for PslError {}

/// The three rule sets a parsed Public Suffix List contributes.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PslData {
    /// Plain rule names (ASCII, punycode-converted), "N" in the design notes.
    pub names: BTreeSet<String>,
    /// Parents of a wildcard rule (`*.p` contributes `p`), "W".
    pub wildcard_parents: BTreeSet<String>,
    /// Names an exception rule (`!x`) removes from the suffix set, "E".
    pub exceptions: BTreeSet<String>,
}

/// The generated lookup tables, ready to render as Rust source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectedSet {
    /// Every protected suffix: names, wildcard parents, and all their proper ancestors.
    pub protected: BTreeSet<String>,
    /// Wildcard parents, kept separately so a direct child can be checked against exceptions.
    pub wildcard_parents: BTreeSet<String>,
    /// Exception names, which are never themselves protected.
    pub exceptions: BTreeSet<String>,
    /// The vendored list's own `VERSION` line, verbatim.
    pub version: String,
}

/// Encodes one DNS label as punycode (RFC 3492), prefixed with `xn--`.
///
/// Returns the label unchanged if it is already ASCII. The caller is responsible for lowercasing
/// and otherwise validating an ASCII label; this function only transforms non-ASCII content.
///
/// # Errors
/// [`PslError::PunycodeOverflow`] if the input is pathological enough to overflow `u32`
/// arithmetic; unreachable for any realistic DNS label.
pub fn punycode_encode_label(label: &str, line: usize) -> Result<String, PslError> {
    if label.is_ascii() {
        return Ok(label.to_owned());
    }
    const BASE: u32 = 36;
    const T_MIN: u32 = 1;
    const T_MAX: u32 = 26;
    const SKEW: u32 = 38;
    const DAMP: u32 = 700;
    const INITIAL_BIAS: u32 = 72;
    const INITIAL_N: u32 = 0x80;

    fn encode_digit(d: u32) -> char {
        (if d < 26 {
            b'a' + d as u8
        } else {
            b'0' + (d - 26) as u8
        }) as char
    }

    fn adapt(mut delta: u32, num_points: u32, first_time: bool) -> u32 {
        delta = if first_time { delta / DAMP } else { delta / 2 };
        delta += delta / num_points;
        let mut k = 0u32;
        while delta > ((BASE - T_MIN) * T_MAX) / 2 {
            delta /= BASE - T_MIN;
            k += BASE;
        }
        k + (((BASE - T_MIN + 1) * delta) / (delta + SKEW))
    }

    let input: Vec<u32> = label.chars().map(|c| c as u32).collect();
    let basic: Vec<u32> = input.iter().copied().filter(|&cp| cp < 0x80).collect();
    let mut output = String::new();
    for &cp in &basic {
        output.push(char::from_u32(cp).unwrap_or('?'));
    }
    let b = basic.len();
    if b > 0 {
        output.push('-');
    }

    let mut h = b;
    let n = input.len();
    let mut code_point = INITIAL_N;
    let mut delta: u32 = 0;
    let mut bias = INITIAL_BIAS;
    let overflow = || PslError::PunycodeOverflow { line };

    while h < n {
        let m = input
            .iter()
            .copied()
            .filter(|&cp| cp >= code_point)
            .min()
            .ok_or_else(overflow)?;
        delta = delta
            .checked_add(
                (m - code_point)
                    .checked_mul(h as u32 + 1)
                    .ok_or_else(overflow)?,
            )
            .ok_or_else(overflow)?;
        code_point = m;
        for &cp in &input {
            if cp < code_point {
                delta = delta.checked_add(1).ok_or_else(overflow)?;
            }
            if cp == code_point {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias + T_MIN {
                        T_MIN
                    } else if k >= bias + T_MAX {
                        T_MAX
                    } else {
                        k - bias
                    };
                    if q < t {
                        break;
                    }
                    let digit = t + (q - t) % (BASE - t);
                    output.push(encode_digit(digit));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                output.push(encode_digit(q));
                bias = adapt(delta, h as u32 + 1, h == b);
                delta = 0;
                h += 1;
            }
        }
        delta = delta.checked_add(1).ok_or_else(overflow)?;
        code_point = code_point.checked_add(1).ok_or_else(overflow)?;
    }

    let encoded = format!("xn--{output}");
    if encoded.len() > MAX_LABEL_BYTES {
        return Err(PslError::LabelTooLong {
            line,
            label: encoded,
        });
    }
    Ok(encoded)
}

/// Normalizes one rule's dotted name: lowercases ASCII labels, punycode-encodes non-ASCII ones,
/// and checks label and total length limits.
fn normalize_name(name: &str, line: usize) -> Result<String, PslError> {
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() > MAX_RULE_LABELS {
        return Err(PslError::TooManyLabels {
            line,
            labels: labels.len(),
        });
    }
    let mut out = Vec::with_capacity(labels.len());
    for label in labels {
        if label.is_empty() {
            return Err(PslError::MalformedRule {
                line,
                text: name.to_owned(),
            });
        }
        if label.is_ascii() {
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(PslError::MalformedRule {
                    line,
                    text: name.to_owned(),
                });
            }
            out.push(label.to_owned());
        } else {
            out.push(punycode_encode_label(label, line)?);
        }
    }
    let joined = out.join(".");
    if joined.len() > MAX_RULE_BYTES {
        return Err(PslError::RuleTooLong {
            line,
            bytes: joined.len(),
        });
    }
    Ok(joined)
}

/// Parses one non-comment, non-blank line of the Public Suffix List into the set it affects.
fn parse_rule_line(text: &str, line: usize, data: &mut PslData) -> Result<(), PslError> {
    if text.contains(char::is_whitespace) {
        return Err(PslError::MalformedRule {
            line,
            text: text.to_owned(),
        });
    }
    if let Some(rest) = text.strip_prefix('!') {
        let name = normalize_name(rest, line)?;
        data.exceptions.insert(name);
    } else if let Some(rest) = text.strip_prefix("*.") {
        if rest.contains('*') {
            return Err(PslError::MalformedRule {
                line,
                text: text.to_owned(),
            });
        }
        let name = normalize_name(rest, line)?;
        data.wildcard_parents.insert(name);
    } else if text.contains('*') {
        return Err(PslError::MalformedRule {
            line,
            text: text.to_owned(),
        });
    } else {
        let name = normalize_name(text, line)?;
        data.names.insert(name);
    }
    Ok(())
}

/// Parses the vendored Public Suffix List text.
///
/// # Errors
/// See [`PslError`]. The file must contain both section markers and at least one rule.
pub fn parse_psl(text: &str) -> Result<(PslData, String), PslError> {
    if text.len() > MAX_FILE_BYTES {
        return Err(PslError::FileTooLarge { bytes: text.len() });
    }
    let lines: Vec<&str> = text.lines().collect();
    if lines.len() > MAX_LINES {
        return Err(PslError::TooManyLines { lines: lines.len() });
    }
    let version = lines
        .iter()
        .find_map(|l| l.strip_prefix("// VERSION:"))
        .map(|v| v.trim().to_owned())
        .ok_or(PslError::MissingMarker {
            marker: "// VERSION:",
        })?;
    for marker in [
        "// ===BEGIN ICANN DOMAINS===",
        "// ===BEGIN PRIVATE DOMAINS===",
    ] {
        if !lines.iter().any(|l| l.trim() == marker) {
            return Err(PslError::MissingMarker { marker });
        }
    }

    let mut data = PslData::default();
    for (index, raw) in lines.iter().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with("//") {
            continue;
        }
        parse_rule_line(trimmed, line, &mut data)?;
    }
    if data.names.is_empty() && data.wildcard_parents.is_empty() {
        return Err(PslError::NoRules);
    }
    for exception in &data.exceptions {
        let parent = parent_of(exception).unwrap_or("");
        if !data.wildcard_parents.contains(parent) {
            return Err(PslError::ExceptionWithoutWildcardParent {
                name: exception.clone(),
            });
        }
    }
    Ok((data, version))
}

/// Parses the hand-maintained supplement file: one plain dotted name per non-comment line.
///
/// # Errors
/// [`PslError::MalformedRule`] for a line that is not a valid dotted name.
pub fn parse_supplement(text: &str) -> Result<BTreeSet<String>, PslError> {
    let mut names = BTreeSet::new();
    for (index, raw) in text.lines().enumerate() {
        let line = index + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        names.insert(normalize_name(trimmed, line)?);
    }
    Ok(names)
}

/// The dotted parent of `name`, or `None` for a single-label name.
fn parent_of(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, rest)| rest)
}

/// Every proper ancestor of `name` (its parent, grandparent, and so on, but not itself).
fn ancestors_of(name: &str) -> impl Iterator<Item = &str> {
    let mut current = name;
    std::iter::from_fn(move || {
        let parent = parent_of(current)?;
        current = parent;
        Some(parent)
    })
}

/// Builds the final protected-suffix tables from a parsed list and the supplement names.
#[must_use]
pub fn build_protected_set(psl: &PslData, version: &str, extra: &BTreeSet<String>) -> ProtectedSet {
    let mut protected: BTreeSet<String> = BTreeSet::new();
    for name in psl
        .names
        .iter()
        .chain(psl.wildcard_parents.iter())
        .chain(extra.iter())
    {
        protected.insert(name.clone());
        for ancestor in ancestors_of(name) {
            protected.insert(ancestor.to_owned());
        }
    }
    ProtectedSet {
        protected,
        wildcard_parents: psl.wildcard_parents.clone(),
        exceptions: psl.exceptions.clone(),
        version: version.to_owned(),
    }
}

/// Reports whether `suffix` is protected: itself a public suffix, an ancestor of one, or the
/// direct child of a wildcard parent that is not listed as an exception.
///
/// Used only by this module's own tests; production lookups use the generated static slices
/// directly (see `policy::host::is_protected_suffix`), which is why this is `cfg(test)`-only:
/// `build.rs` compiles this file too, and never calls it.
#[cfg(test)]
#[must_use]
pub fn is_protected(set: &ProtectedSet, suffix: &str) -> bool {
    if set.protected.contains(suffix) {
        return true;
    }
    match parent_of(suffix) {
        Some(parent) => set.wildcard_parents.contains(parent) && !set.exceptions.contains(suffix),
        None => false,
    }
}

/// Renders the generated tables as a Rust source fragment.
#[must_use]
pub fn render(set: &ProtectedSet) -> String {
    fn slice(name: &str, items: &BTreeSet<String>) -> String {
        let mut out = format!("pub(crate) static {name}: &[&str] = &[\n");
        for item in items {
            out.push_str("    \"");
            out.push_str(item);
            out.push_str("\",\n");
        }
        out.push_str("];\n");
        out
    }
    format!(
        "{}{}{}pub(crate) const LIST_VERSION: &str = \"{}\";\n",
        slice("PROTECTED", &set.protected),
        slice("WILDCARD_PARENTS", &set.wildcard_parents),
        slice("EXCEPTIONS", &set.exceptions),
        set.version.replace('\\', "\\\\").replace('"', "\\\""),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    const HEADER: &str = "// Mozilla Public License\n// VERSION: 2026-01-01_00-00-00_UTC\n";

    fn minimal_list(body: &str) -> String {
        format!(
            "{HEADER}// ===BEGIN ICANN DOMAINS===\n{body}\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n"
        )
    }

    // ====================================================================================
    // Punycode encoder, against vectors generated independently by Python's stdlib codec
    // ====================================================================================

    #[test]
    fn punycode_matches_known_vectors() {
        let cases = [
            ("bücher", "bcher-kva"),
            ("münchen", "mnchen-3ya"),
            ("mañana", "maana-pta"),
            ("café", "caf-dma"),
            ("日本語", "wgv71a119e"),
            ("ドメイン名例", "eckwd4c7cu47r2wf"),
            ("aéroport", "aroport-bya"),
            ("公司", "55qx5d"),
            ("é", "9ca"),
        ];
        for (input, expected) in cases {
            let encoded = assert_ok!(punycode_encode_label(input, 1), "{input}");
            assert_eq!(encoded, format!("xn--{expected}"), "{input}");
        }
    }

    #[test]
    fn punycode_leaves_ascii_unchanged() {
        assert_eq!(assert_ok!(punycode_encode_label("example", 1)), "example");
        assert_eq!(assert_ok!(punycode_encode_label("a", 1)), "a");
    }

    #[test]
    fn punycode_rejects_a_label_that_would_be_over_the_limit() {
        // 60 distinct, widely-spaced code points: punycode compresses repeated or nearby code
        // points well, so the input must vary a lot to force a long encoded label.
        let huge: String = (0..60)
            .map(|i| char::from_u32(0x3000 + i * 37).unwrap_or('?'))
            .collect();
        let err = assert_err!(punycode_encode_label(&huge, 7));
        assert!(
            matches!(err, PslError::LabelTooLong { line: 7, .. }),
            "{err:?}"
        );
    }

    // ====================================================================================
    // parse_psl: structure
    // ====================================================================================

    #[test]
    fn parses_a_minimal_well_formed_list() {
        let (data, version) = assert_ok!(parse_psl(&minimal_list("com\nco.uk\n*.ck\n!www.ck\n")));
        assert!(data.names.contains("com") && data.names.contains("co.uk"));
        assert!(data.wildcard_parents.contains("ck"));
        assert!(data.exceptions.contains("www.ck"));
        assert_eq!(version, "2026-01-01_00-00-00_UTC");
    }

    #[test]
    fn rejects_missing_version_or_section_markers() {
        assert!(matches!(
            assert_err!(parse_psl(
                "// ===BEGIN ICANN DOMAINS===\ncom\n// ===END ICANN DOMAINS===\n// ===BEGIN PRIVATE DOMAINS===\n// ===END PRIVATE DOMAINS===\n"
            )),
            PslError::MissingMarker {
                marker: "// VERSION:"
            }
        ));
        assert!(matches!(
            assert_err!(parse_psl(&format!("{HEADER}com\n"))),
            PslError::MissingMarker { .. }
        ));
    }

    #[test]
    fn rejects_a_file_with_no_rules() {
        assert!(matches!(
            assert_err!(parse_psl(&minimal_list(""))),
            PslError::NoRules
        ));
    }

    #[test]
    fn rejects_an_exception_whose_parent_is_not_a_wildcard() {
        let err = assert_err!(parse_psl(&minimal_list("com\n!www.com\n")));
        assert!(matches!(
            err,
            PslError::ExceptionWithoutWildcardParent { .. }
        ));
    }

    #[test]
    fn rejects_malformed_rule_shapes() {
        for bad in ["a*b", "**.x", "foo.*.com", "*com", "a..b", "ABC"] {
            let err = assert_err!(parse_psl(&minimal_list(bad)), "{bad}");
            assert!(
                matches!(err, PslError::MalformedRule { .. }),
                "{bad}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_a_rule_with_too_many_labels() {
        let long = (0..MAX_RULE_LABELS + 1)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(".");
        let err = assert_err!(parse_psl(&minimal_list(&long)));
        assert!(matches!(err, PslError::TooManyLabels { .. }));
    }

    #[test]
    fn rejects_an_oversized_file() {
        let huge = "a".repeat(MAX_FILE_BYTES + 1);
        assert!(matches!(
            assert_err!(parse_psl(&huge)),
            PslError::FileTooLarge { .. }
        ));
    }

    #[test]
    fn converts_non_ascii_rules_to_punycode() {
        let (data, _) = assert_ok!(parse_psl(&minimal_list("aéroport.ci\n公司.cn\n")));
        assert!(data.names.contains("xn--aroport-bya.ci"));
        assert!(data.names.contains("xn--55qx5d.cn"));
    }

    // ====================================================================================
    // parse_supplement
    // ====================================================================================

    #[test]
    fn parses_the_supplement_file_skipping_comments_and_blanks() {
        let names = assert_ok!(parse_supplement(
            "# comment\n\nstorage.googleapis.com\nglitch.me\n"
        ));
        assert_eq!(names.len(), 2);
        assert!(names.contains("storage.googleapis.com"));
    }

    #[test]
    fn supplement_rejects_a_malformed_name() {
        assert_err!(parse_supplement("a*b\n"));
    }

    // ====================================================================================
    // Protected(S): the formula under test
    // ====================================================================================

    fn set_from(rules: &str, extra: &[&str]) -> ProtectedSet {
        let (data, version) = assert_ok!(parse_psl(&minimal_list(rules)));
        let extra: BTreeSet<String> = extra.iter().map(|s| s.to_string()).collect();
        build_protected_set(&data, &version, &extra)
    }

    #[test]
    fn protects_a_plain_rule_and_its_ancestors() {
        let set = set_from("co.uk\n", &[]);
        assert!(is_protected(&set, "co.uk"));
        // "uk" is a proper ancestor of the listed rule "co.uk", so it is protected too, the same
        // way "amazonaws.com" is protected below despite never being a rule by itself.
        assert!(is_protected(&set, "uk"));
        assert!(!is_protected(&set, "ie")); // an unrelated TLD is not protected by this rule
    }

    #[test]
    fn protects_an_ancestor_that_is_not_itself_a_rule() {
        // s3.amazonaws.com is a rule; amazonaws.com (its ancestor) is protected even though it is
        // not a rule itself, reproducing the real amazonaws.com gap this task exists to close.
        let set = set_from("s3.amazonaws.com\n", &[]);
        assert!(is_protected(&set, "amazonaws.com"));
        assert!(is_protected(&set, "s3.amazonaws.com"));
    }

    #[test]
    fn protects_a_wildcard_parent_itself() {
        let set = set_from("*.ck\n", &[]);
        assert!(is_protected(&set, "ck"));
    }

    #[test]
    fn protects_an_unlisted_direct_child_of_a_wildcard_parent() {
        let set = set_from("*.ck\n", &[]);
        assert!(is_protected(&set, "foo.ck"));
    }

    #[test]
    fn an_exception_child_of_a_wildcard_parent_is_not_protected() {
        let set = set_from("*.ck\n!www.ck\n", &[]);
        assert!(!is_protected(&set, "www.ck"));
        // the parent itself, and an unrelated child, stay protected
        assert!(is_protected(&set, "ck"));
        assert!(is_protected(&set, "other.ck"));
    }

    #[test]
    fn a_grandchild_of_a_wildcard_parent_is_not_itself_protected_by_the_direct_child_rule() {
        // foo.ck is protected (direct child of the wildcard parent ck), so bar.foo.ck is a
        // normal registrable domain under it and must NOT be protected.
        let set = set_from("*.ck\n", &[]);
        assert!(!is_protected(&set, "bar.foo.ck"));
    }

    #[test]
    fn supplement_names_and_their_ancestors_are_protected() {
        let set = set_from("com\n", &["storage.googleapis.com"]);
        assert!(is_protected(&set, "storage.googleapis.com"));
        assert!(is_protected(&set, "googleapis.com"));
    }

    #[test]
    fn a_registrable_domain_is_not_protected() {
        let set = set_from("com\n", &[]);
        assert!(!is_protected(&set, "example.com"));
        assert!(!is_protected(&set, "kiro.dev")); // dev is not even a rule in this minimal set
    }

    #[test]
    fn rendered_slices_are_sorted_and_include_the_version() {
        let set = set_from("co.uk\ncom\n", &[]);
        let text = render(&set);
        assert!(text.contains("pub(crate) static PROTECTED: &[&str] = &["));
        assert!(text.contains("\"co.uk\""));
        assert!(text.contains(&format!("LIST_VERSION: &str = \"{}\"", set.version)));
        let start = assert_some!(text.find("PROTECTED"));
        let end = assert_some!(text.find("];"));
        let body = &text[start..end];
        let mut lines: Vec<&str> = body.lines().filter(|l| l.trim().starts_with('"')).collect();
        let sorted_copy = {
            let mut s = lines.clone();
            s.sort_unstable();
            s
        };
        assert_eq!(lines, sorted_copy);
        lines.dedup();
        assert_eq!(
            lines.len(),
            body.lines().filter(|l| l.trim().starts_with('"')).count()
        );
    }

    // ====================================================================================
    // Cross-check against the `idna` crate (dev-dependency only) and the real vendored file
    // ====================================================================================

    #[test]
    fn punycode_matches_idna_for_every_non_ascii_rule_in_the_vendored_list() {
        let text = include_str!("../data/public_suffix_list.dat");
        let (data, _version) = assert_ok!(parse_psl(text));
        let mut checked = 0usize;
        for raw_name in text.lines().filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                return None;
            }
            let name = trimmed.trim_start_matches('!').trim_start_matches("*.");
            (!name.is_ascii()).then(|| name.to_owned())
        }) {
            let ours = raw_name
                .split('.')
                .map(|label| punycode_encode_label(label, 0).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()
                .map(|labels| labels.join("."));
            let theirs = idna::domain_to_ascii(&raw_name);
            assert_eq!(
                ours.is_ok(),
                theirs.is_ok(),
                "{raw_name}: ours={ours:?} idna={theirs:?}"
            );
            if let (Ok(ours), Ok(theirs)) = (ours, theirs) {
                assert_eq!(ours, theirs, "{raw_name}");
            }
            checked += 1;
        }
        assert!(
            checked > 400,
            "expected over 400 non-ASCII rules, found {checked}"
        );
        assert!(!data.names.is_empty());
    }
}
