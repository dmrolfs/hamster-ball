// ABOUTME: PathPattern and GlobTail: the validated form of an fs.deny_read/fs.deny_write entry that may contain globs.
// ABOUTME: Pure types; PathResolver (system::resolver) builds a PathPattern by resolving its literal base.
//! Deny-rule patterns: a resolved literal base plus a validated glob tail.

use snafu::{Snafu, ensure};

use super::path::{CanonicalPath, PathError};

/// Why a glob tail component is not acceptable.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum GlobTailError {
    /// A component is `..`.
    #[snafu(display("glob pattern must not contain `..`"))]
    DotDot,
    /// A component is empty (consecutive or leading/trailing slash in the tail).
    #[snafu(display("glob pattern has an empty segment"))]
    EmptySegment,
    /// A component contains `[` or `{`, which this grammar does not support.
    #[snafu(display("glob pattern may only use `*`, `?` and `**`, not `[` or `{{`"))]
    UnsupportedMetacharacter,
    /// `**` is combined with other characters in the same segment.
    #[snafu(display("`**` must be its own path segment, not combined with other text"))]
    DoubleStarMixedWithText,
}

/// One segment of a glob tail: `**` (any number of path segments), or a segment that may mix
/// literal characters with `*` and `?` (an ordinary shell-style glob within one segment).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GlobSegment {
    /// Matches any number of path segments, including zero.
    AnyDepth,
    /// A pattern to match within exactly one path segment.
    Segment(String),
}

/// The non-literal tail of an `fs.deny_read`/`fs.deny_write` glob pattern.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GlobTail(Vec<GlobSegment>);

impl GlobTail {
    /// Parses the glob segments after a `PathPattern`'s literal base.
    ///
    /// # Errors
    /// See [`GlobTailError`].
    pub fn parse(segments: &[&str]) -> Result<Self, GlobTailError> {
        let mut parsed = Vec::with_capacity(segments.len());
        for segment in segments {
            ensure!(!segment.is_empty(), EmptySegmentSnafu);
            if *segment == "**" {
                parsed.push(GlobSegment::AnyDepth);
                continue;
            }
            ensure!(*segment != "..", DotDotSnafu);
            ensure!(!segment.contains(['[', '{']), UnsupportedMetacharacterSnafu);
            ensure!(!segment.contains("**"), DoubleStarMixedWithTextSnafu);
            parsed.push(GlobSegment::Segment((*segment).to_owned()));
        }
        Ok(Self(parsed))
    }

    /// The parsed segments, in order.
    #[must_use]
    pub fn segments(&self) -> &[GlobSegment] {
        &self.0
    }
}

/// An `fs.deny_read`/`fs.deny_write` entry: a resolved literal base, and an optional glob tail.
///
/// `config/*.secrets.yaml` has base `config` and a tail of one segment, `*.secrets.yaml`. A
/// plain literal entry such as `~/.ssh` has no glob metacharacter anywhere, so `tail` is
/// `None` and `base` is the whole thing. The base is resolved with deny semantics (a glob
/// target does not exist yet as a literal path, so a missing base is not an error).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PathPattern {
    /// The longest glob-free prefix, resolved as a deny rule.
    pub base: CanonicalPath,
    /// The base symlink's own location, when the base was reached by following a final-component
    /// symlink: `base` is what it points to, so both the link name and its target are covered.
    pub alias: Option<CanonicalPath>,
    /// The glob segments after the base, or `None` for a plain literal entry.
    pub tail: Option<GlobTail>,
}

/// Whether a deny rule covers a path, as far as the Rust query can tell.
///
/// Ordered `No < Yes < YesFolded` so results combine with `max`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Coverage {
    /// The rule does not cover the path.
    No,
    /// The rule covers the path, comparing names exactly.
    Yes,
    /// The rule covers the path only under case-insensitive or Unicode-conservative
    /// comparison, which is how the filesystem and Seatbelt compare names.
    YesFolded,
}

/// The Data volume firmlink prefix: `/System/Volumes/Data/Users/x` and `/Users/x` are the same
/// place, and Seatbelt treats both spellings alike while `realpath` keeps them distinct.
const DATA_VOLUME_PREFIX: &str = "/System/Volumes/Data";

/// How names are compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Compare {
    /// Byte for byte.
    Exact,
    /// Case-insensitively for ASCII, and "maybe equal" whenever either side has non-ASCII text.
    ///
    /// APFS compares names case-insensitively and NFC/NFD-insensitively. Reproducing its exact
    /// equivalence classes would need tables this crate does not carry, and a near miss would
    /// be a silent under-deny. Treating any non-ASCII name as possibly equal can only over-deny.
    Lenient,
}

fn names_may_match(pattern: &str, candidate: &str, compare: Compare) -> bool {
    match compare {
        Compare::Exact => pattern == candidate,
        Compare::Lenient => {
            pattern.eq_ignore_ascii_case(candidate) || !pattern.is_ascii() || !candidate.is_ascii()
        }
    }
}

/// Matches one glob segment (`*` any run, `?` any one character) against one name.
fn segment_matches(pattern: &str, candidate: &str, compare: Compare) -> bool {
    if compare == Compare::Lenient && (!pattern.is_ascii() || !candidate.is_ascii()) {
        return true;
    }
    let fold = |c: char| match compare {
        Compare::Exact => c,
        Compare::Lenient => c.to_ascii_lowercase(),
    };
    let pattern: Vec<char> = pattern.chars().map(fold).collect();
    let candidate: Vec<char> = candidate.chars().map(fold).collect();
    let (mut p, mut c) = (0, 0);
    let (mut star, mut resume) = (None, 0);
    while c < candidate.len() {
        if p < pattern.len()
            && (pattern[p] == '?' || pattern[p] == candidate[c])
            && pattern[p] != '*'
        {
            p += 1;
            c += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            resume = c;
            p += 1;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            resume += 1;
            c = resume;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|&ch| ch == '*')
}

/// Whether `tail` matches a prefix of `rest` (anything beneath the match is covered too).
///
/// Dynamic programming over (tail index, rest index), so a pattern with many `**` segments
/// costs `tail.len() * rest.len()` rather than exponential time.
fn tail_matches(tail: &GlobTail, rest: &[&str], compare: Compare) -> bool {
    let segments = tail.segments();
    let (t, n) = (segments.len(), rest.len());
    // `reach[i][j]`: segments[i..] match some prefix of rest[j..].
    let mut reach = vec![vec![false; n + 1]; t + 1];
    reach[t].iter_mut().for_each(|cell| *cell = true);
    for i in (0..t).rev() {
        for j in (0..=n).rev() {
            reach[i][j] = match &segments[i] {
                GlobSegment::AnyDepth => reach[i + 1][j] || (j < n && reach[i][j + 1]),
                GlobSegment::Segment(pattern) => {
                    j < n && segment_matches(pattern, rest[j], compare) && reach[i + 1][j + 1]
                }
            };
        }
    }
    reach[0][0]
}

fn components(path: &CanonicalPath) -> Vec<&str> {
    let text = path.as_str();
    let text = match text.strip_prefix(DATA_VOLUME_PREFIX) {
        Some("") => "/",
        Some(rest) if rest.starts_with('/') => rest,
        _ => text,
    };
    text.split('/').filter(|part| !part.is_empty()).collect()
}

impl PathPattern {
    /// Reports whether this deny rule covers `path`, erring toward "covers".
    ///
    /// This is advisory, for tests and for `hb explain`. Seatbelt is the enforcement, and a
    /// miss here cannot become an enforcement hole. It covers the base, the symlink alias, and
    /// everything beneath either; with a glob tail, everything beneath a match.
    #[must_use]
    pub fn covers(&self, path: &CanonicalPath) -> Coverage {
        let candidate = components(path);
        let bases = std::iter::once(&self.base).chain(self.alias.as_ref());
        let covers_with = |compare: Compare| {
            bases.clone().any(|base| {
                let base = components(base);
                base.len() <= candidate.len()
                    && base
                        .iter()
                        .zip(&candidate)
                        .all(|(b, c)| names_may_match(b, c, compare))
                    && self
                        .tail
                        .as_ref()
                        .is_none_or(|tail| tail_matches(tail, &candidate[base.len()..], compare))
            })
        };
        if !covers_with(Compare::Lenient) {
            Coverage::No
        } else if covers_with(Compare::Exact) {
            Coverage::Yes
        } else {
            Coverage::YesFolded
        }
    }
}

/// Why a glob pattern spelling could not be parsed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PathPatternError {
    /// The base, or the whole spelling for a literal entry, could not be resolved.
    #[snafu(transparent)]
    Base {
        /// The underlying error.
        source: PathError,
    },
    /// The glob tail was malformed.
    #[snafu(transparent)]
    Tail {
        /// The underlying error.
        source: GlobTailError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    #[test]
    fn pattern_rejects_dotdot_absolute_brackets_and_braces_in_the_tail() {
        assert!(matches!(
            assert_err!(GlobTail::parse(&[".."])),
            GlobTailError::DotDot
        ));
        assert!(matches!(
            assert_err!(GlobTail::parse(&["[abc]"])),
            GlobTailError::UnsupportedMetacharacter
        ));
        assert!(matches!(
            assert_err!(GlobTail::parse(&["{a,b}"])),
            GlobTailError::UnsupportedMetacharacter
        ));
    }

    #[test]
    fn pattern_rejects_double_star_mixed_with_other_text() {
        assert!(matches!(
            assert_err!(GlobTail::parse(&["**x"])),
            GlobTailError::DoubleStarMixedWithText
        ));
    }

    #[test]
    fn pattern_rejects_an_empty_segment() {
        assert!(matches!(
            assert_err!(GlobTail::parse(&[""])),
            GlobTailError::EmptySegment
        ));
    }

    #[test]
    fn pattern_double_star_is_its_own_segment() {
        let tail = assert_ok!(GlobTail::parse(&["logs", "**", "*.log"]));
        assert_eq!(
            tail.segments(),
            &[
                GlobSegment::Segment("logs".to_owned()),
                GlobSegment::AnyDepth,
                GlobSegment::Segment("*.log".to_owned())
            ]
        );
    }

    #[test]
    fn pattern_allows_star_and_question_mark_mixed_with_literal_text_in_one_segment() {
        let tail = assert_ok!(GlobTail::parse(&["*.secrets.yaml", "a?b.env"]));
        assert_eq!(
            tail.segments(),
            &[
                GlobSegment::Segment("*.secrets.yaml".to_owned()),
                GlobSegment::Segment("a?b.env".to_owned())
            ]
        );
    }

    // ====================================================================================
    // covers: an advisory, over-approximating "would this deny rule apply to this path?"
    //
    // Seatbelt decides. These tests pin the Rust query's own contract: it never says "No" for a
    // path Seatbelt would deny (case, Unicode, firmlink and symlink-alias spellings included).
    // ====================================================================================

    fn path(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    fn literal(base: &str) -> PathPattern {
        PathPattern {
            base: path(base),
            alias: None,
            tail: None,
        }
    }

    fn glob(base: &str, tail: &[&str]) -> PathPattern {
        PathPattern {
            base: path(base),
            alias: None,
            tail: Some(assert_ok!(GlobTail::parse(tail))),
        }
    }

    #[test]
    fn a_literal_deny_covers_its_base_and_everything_beneath_it() {
        let deny = literal("/Users/me/.ssh");
        assert_eq!(deny.covers(&path("/Users/me/.ssh")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/Users/me/.ssh/id_rsa")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/Users/me/.ssh/a/b/c")), Coverage::Yes);
    }

    #[test]
    fn a_literal_deny_does_not_cover_siblings_ancestors_or_prefix_lookalikes() {
        let deny = literal("/Users/me/.ssh");
        assert_eq!(deny.covers(&path("/Users/me")), Coverage::No);
        assert_eq!(deny.covers(&path("/Users/me/.ssh2")), Coverage::No);
        assert_eq!(deny.covers(&path("/Users/me/.sshx/key")), Coverage::No);
        assert_eq!(deny.covers(&path("/Users/other/.ssh")), Coverage::No);
    }

    #[test]
    fn the_filesystem_root_covers_every_path() {
        assert_eq!(
            literal("/").covers(&path("/anything/at/all")),
            Coverage::Yes
        );
        assert_eq!(literal("/").covers(&path("/")), Coverage::Yes);
    }

    #[test]
    fn case_variants_are_covered_but_marked_folded() {
        let deny = literal("/Users/me/.ssh");
        assert_eq!(
            deny.covers(&path("/Users/me/.SSH/id_rsa")),
            Coverage::YesFolded
        );
        assert_eq!(deny.covers(&path("/USERS/ME/.ssh")), Coverage::YesFolded);
    }

    #[test]
    fn a_non_ascii_name_is_covered_conservatively_and_marked_folded() {
        // NFC and NFD spellings of the same name differ in bytes, and the Rust query carries no
        // normalization table, so it cannot tell them apart. It errs toward deny.
        let deny = literal("/Users/me/caf\u{e9}");
        assert_eq!(
            deny.covers(&path("/Users/me/cafe\u{301}/x")),
            Coverage::YesFolded
        );
        assert_eq!(deny.covers(&path("/Users/me/caf\u{e9}/x")), Coverage::Yes);
    }

    #[test]
    fn a_non_ascii_name_may_match_any_sibling_which_is_the_documented_cost_of_being_sound() {
        // Over-approximation, deliberately: with no table to prove two names unequal, any name
        // with non-ASCII text in the same position may be the same file. Seatbelt decides what
        // is really denied; this only means `hb explain` can over-report a deny.
        let deny = literal("/Users/me/caf\u{e9}");
        assert_eq!(
            deny.covers(&path("/Users/me/cafeteria")),
            Coverage::YesFolded
        );
        // Names with no non-ASCII text on either side are compared precisely.
        let ascii = literal("/Users/me/cafe");
        assert_eq!(ascii.covers(&path("/Users/me/cafeteria")), Coverage::No);
    }

    #[test]
    fn a_non_ascii_name_elsewhere_still_widens_only_its_own_position() {
        let deny = literal("/Users/me/.ssh");
        // The non-ASCII name sits where `.ssh` would, so it may be `.ssh` in another spelling.
        assert_eq!(
            deny.covers(&path("/Users/me/caf\u{e9}/x")),
            Coverage::YesFolded
        );
        // A non-ASCII name in a different position does not make an unrelated path match.
        assert_eq!(deny.covers(&path("/Users/other/caf\u{e9}")), Coverage::No);
    }

    #[test]
    fn a_glob_over_a_non_ascii_name_may_match_so_it_is_covered_and_folded() {
        // Non-ASCII on the candidate side: the segment cannot be proven different.
        let deny = glob("/p", &["*.pem"]);
        assert_eq!(deny.covers(&path("/p/caf\u{e9}.txt")), Coverage::YesFolded);
        // Non-ASCII on the pattern side likewise.
        let deny = glob("/p", &["caf\u{e9}*"]);
        assert_eq!(deny.covers(&path("/p/cafe.txt")), Coverage::YesFolded);
        // Pure ASCII on both sides is compared precisely.
        let deny = glob("/p", &["cafe*"]);
        assert_eq!(deny.covers(&path("/p/other.txt")), Coverage::No);
    }

    #[test]
    fn a_multi_segment_tail_matches_one_segment_per_pattern_segment() {
        let deny = glob("/p", &["x", "*.pem"]);
        assert_eq!(deny.covers(&path("/p/x/a.pem")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/x/a.txt")), Coverage::No);
        assert_eq!(deny.covers(&path("/p/y/a.pem")), Coverage::No);
        assert_eq!(deny.covers(&path("/p/a.pem")), Coverage::No);
        let deny = glob("/p", &["a", "b", "c"]);
        assert_eq!(deny.covers(&path("/p/a/b/c/d")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/a/b")), Coverage::No);
    }

    #[test]
    fn the_data_volume_root_itself_is_treated_as_the_filesystem_root() {
        // `/System/Volumes/Data` is where `/` lands on the Data volume, so denying it denies
        // everything, and a path at it is the root.
        assert_eq!(
            literal("/System/Volumes/Data").covers(&path("/Users/x")),
            Coverage::Yes
        );
        assert_eq!(
            literal("/").covers(&path("/System/Volumes/Data")),
            Coverage::Yes
        );
        // A sibling whose name merely starts with `Data` is not the firmlink prefix.
        assert_eq!(
            literal("/base").covers(&path("/System/Volumes/Database")),
            Coverage::No
        );
    }

    #[test]
    fn the_data_volume_firmlink_spelling_is_the_same_path() {
        let deny = literal("/Users/me/.ssh");
        assert_eq!(
            deny.covers(&path("/System/Volumes/Data/Users/me/.ssh/id_rsa")),
            Coverage::Yes
        );
        let deny_via_data = literal("/System/Volumes/Data/Users/me/.ssh");
        assert_eq!(deny_via_data.covers(&path("/Users/me/.ssh")), Coverage::Yes);
        // Only a whole leading component is the firmlink prefix.
        assert_eq!(
            literal("/Users/x").covers(&path("/System/Volumes/Database/Users/x")),
            Coverage::No
        );
    }

    #[test]
    fn a_symlink_alias_is_covered_as_well_as_the_target() {
        let deny = PathPattern {
            base: path("/Users/me/real-secret"),
            alias: Some(path("/Users/me/link-secret")),
            tail: None,
        };
        assert_eq!(deny.covers(&path("/Users/me/real-secret")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/Users/me/link-secret")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/Users/me/other")), Coverage::No);
    }

    #[test]
    fn a_glob_tail_matches_within_one_segment() {
        let deny = glob("/p/config", &["*.secrets.yaml"]);
        assert_eq!(
            deny.covers(&path("/p/config/prod.secrets.yaml")),
            Coverage::Yes
        );
        assert_eq!(
            deny.covers(&path("/p/config/.secrets.yaml")),
            Coverage::Yes,
            "`*` matches a leading dot"
        );
        assert_eq!(deny.covers(&path("/p/config/prod.txt")), Coverage::No);
        assert_eq!(deny.covers(&path("/p/config")), Coverage::No);
        assert_eq!(
            deny.covers(&path("/p/other/prod.secrets.yaml")),
            Coverage::No
        );
    }

    #[test]
    fn a_glob_match_covers_everything_beneath_the_match() {
        let deny = glob("/p/config", &["*.secrets.yaml"]);
        assert_eq!(
            deny.covers(&path("/p/config/prod.secrets.yaml/inner")),
            Coverage::Yes
        );
    }

    #[test]
    fn a_glob_does_not_reach_across_segments_with_a_single_star() {
        let deny = glob("/p", &["*.pem"]);
        assert_eq!(deny.covers(&path("/p/a.pem")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/dir/a.pem")), Coverage::No);
    }

    #[test]
    fn question_mark_matches_exactly_one_character() {
        let deny = glob("/p", &["key?.pem"]);
        assert_eq!(deny.covers(&path("/p/key1.pem")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/key.pem")), Coverage::No);
        assert_eq!(deny.covers(&path("/p/key12.pem")), Coverage::No);
    }

    #[test]
    fn double_star_matches_zero_or_more_whole_segments() {
        let deny = glob("/p", &["**", "id_rsa"]);
        assert_eq!(deny.covers(&path("/p/id_rsa")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/a/id_rsa")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/a/b/c/id_rsa")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/a/id_rsa.pub")), Coverage::No);
    }

    #[test]
    fn a_trailing_double_star_covers_the_base_itself_and_everything_below() {
        let deny = glob("/p/secret", &["**"]);
        assert_eq!(deny.covers(&path("/p/secret")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p/secret/a/b")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/p")), Coverage::No);
    }

    #[test]
    fn a_glob_under_the_filesystem_root_works() {
        let deny = glob("/", &["*.key"]);
        assert_eq!(deny.covers(&path("/server.key")), Coverage::Yes);
        assert_eq!(deny.covers(&path("/etc/server.key")), Coverage::No);
    }

    #[test]
    fn glob_segments_match_case_insensitively_but_report_folded() {
        let deny = glob("/p", &["*.PEM"]);
        assert_eq!(deny.covers(&path("/p/a.pem")), Coverage::YesFolded);
        assert_eq!(deny.covers(&path("/p/a.PEM")), Coverage::Yes);
    }

    #[test]
    fn many_double_stars_do_not_blow_up() {
        // A hostile pattern with hundreds of `**` must not take exponential time.
        let mut tail: Vec<&str> = vec!["**"; 200];
        tail.push("never");
        let deny = glob("/p", &tail);
        let deep = format!("/p/{}", vec!["d"; 60].join("/"));
        let started = std::time::Instant::now();
        assert_eq!(deny.covers(&path(&deep)), Coverage::No);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn coverage_orders_no_below_yes_below_folded_for_combining() {
        assert!(Coverage::No < Coverage::Yes);
        assert!(Coverage::Yes < Coverage::YesFolded);
        assert!(Coverage::No.max(Coverage::Yes) == Coverage::Yes);
    }

    proptest::proptest! {
        #[test]
        fn covers_never_panics_on_arbitrary_components(
            base in "(/[a-zA-Z0-9._-]{1,6}){0,4}",
            candidate in "(/[a-zA-Z0-9._é-]{1,6}){0,6}",
            tail in proptest::collection::vec("[a-z*?]{1,5}|\\*\\*", 0..4),
        ) {
            let base = if base.is_empty() { "/".to_owned() } else { base };
            let candidate = if candidate.is_empty() { "/".to_owned() } else { candidate };
            if let (Ok(base), Ok(candidate)) = (CanonicalPath::from_canonical(&base), CanonicalPath::from_canonical(&candidate)) {
                let refs: Vec<&str> = tail.iter().map(String::as_str).collect();
                let pattern = match GlobTail::parse(&refs) {
                    Ok(tail) if !refs.is_empty() => PathPattern { base, alias: None, tail: Some(tail) },
                    _ => PathPattern { base, alias: None, tail: None },
                };
                let _ = pattern.covers(&candidate);
            }
        }

        #[test]
        fn a_literal_deny_covers_every_path_beneath_its_base_in_any_case(
            base in "(/[a-z]{1,5}){1,3}",
            below in "(/[a-z]{1,5}){0,3}",
        ) {
            let deny = literal(&base);
            let candidate = format!("{}{}", base.to_ascii_uppercase(), below);
            proptest::prop_assert_ne!(deny.covers(&path(&candidate)), Coverage::No);
        }
    }
}
