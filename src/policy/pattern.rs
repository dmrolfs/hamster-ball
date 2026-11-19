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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobSegment {
    /// Matches any number of path segments, including zero.
    AnyDepth,
    /// A pattern to match within exactly one path segment.
    Segment(String),
}

/// The non-literal tail of an `fs.deny_read`/`fs.deny_write` glob pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    /// The longest glob-free prefix, resolved as a deny rule.
    pub base: CanonicalPath,
    /// The glob segments after the base, or `None` for a plain literal entry.
    pub tail: Option<GlobTail>,
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
}
