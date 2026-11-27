// ABOUTME: The shared vocabulary for checks that can be complete, partial or unavailable, and the doctor's versioned report.
// ABOUTME: "Could not look" must never serialize like "looked and found nothing"; every string a report holds is escaped when rendered.
//! Check outcomes and the `hb doctor` report shape (bead hb-szd).
//!
//! An inspector returns a [`Check`]: [`Check::Complete`] (it looked everywhere),
//! [`Check::Partial`] (it looked, with named [`CheckGap`]s) or [`Check::Unavailable`] (it could not
//! look at all). The report projects each outcome into a [`CheckReport`], and [`DoctorReport`] is
//! what text and JSON render. Only the report types and the escaping live here; the inspectors
//! (git, proxy, secrets survey) adopt [`Check`] in their own beads.
//!
//! # Schema version 1: what a consumer must do
//!
//! The JSON carries `schema_version`. A rename or removal bumps it; an added field does not.
//! A consumer of version 1 follows these rules, all of which fail closed:
//!
//! 1. Ignore fields it does not know.
//! 2. Show a `code` it does not know as written (escaped for the terminal), and treat it as a finding.
//! 3. Treat a `severity` it does not know as `error`.
//! 4. Treat a `state` it does not know, or a missing `state`, as not complete.
//! 5. Treat a check `id` it does not know as a check whose `state` still counts toward completeness.
//! 6. Treat a `remedy` it does not know as `review_manually`.
//! 7. If `schema_version` is higher than it supports, it cannot attest that the inspection was complete.
//! 8. If a required field is missing or has the wrong type, it cannot attest completion. Required:
//!    `schema_version` and `checks` on the report; `id` and `result` on a check; `state` on a result,
//!    plus `value` for `complete` and `partial`, `gaps` (with `shown` and `omitted`) for `partial`,
//!    and `gap` for `unavailable`. `subject` is always present; `null` means no subject.
//!
//! A report with no checks is complete over the checks it holds and says nothing about which checks
//! should have run. Whoever builds a report must include an `unavailable` result for every check
//! it was asked for and could not run.
//!
//! A parsed string is the original text: the JSON escapes control and bidirectional characters as
//! `\uXXXX`, and a parser decodes them again. A consumer that prints a parsed `subject` to a terminal
//! must escape it again.

use std::fmt;
use std::path::Path;

use serde::Serialize;
use strum::{AsRefStr, Display};

use crate::text::Escaped;

/// The version of the doctor's JSON shape (see the module rules).
pub const SCHEMA_VERSION: u32 = 1;

/// The exit code of `hb doctor --strict` when any check is not complete.
pub const EXIT_INCOMPLETE: u8 = 3;

/// Most gaps a [`Gaps`] keeps; the rest are counted.
pub const MAX_GAPS: usize = 32;

/// Most characters of a [`SafePath`] kept.
const MAX_SUBJECT_CHARS: usize = 512;

/// How an inspection ended, with the value it found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Check<T> {
    /// It looked everywhere it was asked to.
    Complete {
        /// What it found; empty means nothing was there.
        value: T,
    },
    /// It found `value` but could not look everywhere.
    Partial {
        /// What it found.
        value: T,
        /// Where it could not look.
        gaps: Gaps,
    },
    /// It could not look at all, so there is no value.
    Unavailable {
        /// Why.
        gap: CheckGap,
    },
}

impl<T> Check<T> {
    /// [`Check::Complete`] when `gaps` is empty, otherwise [`Check::Partial`].
    ///
    /// Build outcomes with this: a `Partial` with no gaps would say "incomplete" with no reason.
    #[must_use]
    pub fn from_parts(value: T, gaps: Gaps) -> Self {
        if gaps.is_empty() {
            Self::Complete { value }
        } else {
            Self::Partial { value, gaps }
        }
    }

    /// Whether the inspection looked everywhere.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
}

/// One place an inspection could not look, or one reason it stopped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckGap {
    /// What went wrong.
    pub code: DiagnosticCode,
    /// Where, if it is a place.
    pub subject: Option<SafePath>,
}

/// The gaps of a partial result: the first [`MAX_GAPS`], and how many more there were.
///
/// A project with many unreadable directories must not grow the report without bound, and the count
/// keeps the result incomplete however many are dropped.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct Gaps {
    shown: Vec<CheckGap>,
    omitted: u64,
}

impl Gaps {
    /// No gaps.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a gap; past [`MAX_GAPS`] it is only counted.
    pub fn push(&mut self, gap: CheckGap) {
        if self.shown.len() < MAX_GAPS {
            self.shown.push(gap);
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }

    /// The gaps kept.
    #[must_use]
    pub fn shown(&self) -> &[CheckGap] {
        &self.shown
    }

    /// How many gaps were counted and not kept.
    #[must_use]
    pub fn omitted(&self) -> u64 {
        self.omitted
    }

    /// Whether nothing was missed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.shown.is_empty() && self.omitted == 0
    }
}

/// A stable name for a finding or a gap. New codes may be added without a schema bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum DiagnosticCode {
    /// A directory could not be read.
    DirectoryUnreadable,
    /// A name is not valid UTF-8 and was not examined.
    NameNotUtf8,
    /// The walk stopped at its entry limit.
    EntryLimitReached,
    /// The inspection could not run at all.
    InspectionUnavailable,
    /// An entry's type could not be read, so it was not examined.
    EntryUnavailable,
    /// Git's configuration for a repository could not be established.
    GitConfigUnavailable,
    /// Whether the sandbox lets the agent write a path could not be established.
    WriteAccessUnknown,
    /// A configuration scope was left out of the answer on purpose.
    ConfigScopeOmitted,
    /// An inspection stopped at its count or time budget.
    InspectionLimitReached,
    /// A directory was left out of the inspection on purpose, for example dependency output.
    DirectoryNotInspected,
}

/// How much a finding matters. It says nothing about completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum Severity {
    /// For information.
    Info,
    /// Worth the owner's attention.
    Warning,
    /// The owner should act.
    Error,
}

/// What the owner can do about a finding. The renderer owns the wording; there is no free text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum Remedy {
    /// Nothing to do.
    None,
    /// Look at the subject by hand.
    ReviewManually,
}

/// Which check a [`CheckReport`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum CheckId {
    /// Look-alike secret files.
    SecretsSurvey,
    /// Git outside the floor's reach.
    Git,
    /// System proxy settings.
    Proxy,
}

/// One finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    /// What was found.
    pub code: DiagnosticCode,
    /// How much it matters.
    pub severity: Severity,
    /// Where.
    pub subject: Option<SafePath>,
    /// What to do.
    pub remedy: Remedy,
}

/// Path-like text that is bounded and never printed raw.
///
/// It holds the text as given, cut at 512 characters with a `...` marker, converted with
/// `to_string_lossy`: it is for display, not a key and not a path to open. `Display` and `Debug`
/// escape; the JSON renderer escapes when it writes.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct SafePath(String);

impl SafePath {
    /// Bounds `text` (see the type's rules).
    #[must_use]
    pub fn new(text: &str) -> Self {
        match text.char_indices().nth(MAX_SUBJECT_CHARS) {
            Some((end, _)) => Self(format!("{}...", &text[..end])),
            None => Self(text.to_owned()),
        }
    }

    /// Bounds `path`.
    #[must_use]
    pub fn from_path(path: &Path) -> Self {
        Self::new(&path.to_string_lossy())
    }
}

impl fmt::Display for SafePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Escaped(&self.0).fmt(f)
    }
}

impl fmt::Debug for SafePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SafePath(\"{self}\")")
    }
}

/// One check's outcome as the report shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CheckReport {
    /// Which check.
    pub id: CheckId,
    /// How it ended and what it found.
    pub result: Check<Vec<Diagnostic>>,
}

/// What `hb doctor` reports, in one shape for text and JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Every check that ran.
    pub checks: Vec<CheckReport>,
}

impl DoctorReport {
    /// A report of `checks` at the current schema version.
    #[must_use]
    pub fn new(checks: Vec<CheckReport>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            checks,
        }
    }

    /// Whether every check looked everywhere.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.checks.iter().all(|check| check.result.is_complete())
    }

    /// `0`, or [`EXIT_INCOMPLETE`] when `strict` and a check is not complete.
    ///
    /// The default keeps the doctor's exit code as it was. This never returns 78, which is
    /// for a config that is not approved.
    #[must_use]
    pub fn exit_code(&self, strict: bool) -> u8 {
        if strict && !self.is_complete() {
            EXIT_INCOMPLETE
        } else {
            0
        }
    }

    /// The report as JSON with control and bidirectional characters escaped.
    ///
    /// # Errors
    /// [`serde_json::Error`] if serialization fails, which a report cannot cause.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        crate::safe_json::to_safe_json(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use serde_json::{Value, json};

    fn gap(code: DiagnosticCode, subject: &str) -> CheckGap {
        CheckGap {
            code,
            subject: Some(SafePath::new(subject)),
        }
    }

    fn report(result: Check<Vec<Diagnostic>>) -> DoctorReport {
        DoctorReport::new(vec![CheckReport {
            id: CheckId::Git,
            result,
        }])
    }

    fn parse(report: &DoctorReport) -> Value {
        assert_ok!(serde_json::from_str(&assert_ok!(report.to_json())))
    }

    fn diagnostic() -> Diagnostic {
        Diagnostic {
            code: DiagnosticCode::DirectoryUnreadable,
            severity: Severity::Warning,
            subject: Some(SafePath::new("/p/found")),
            remedy: Remedy::ReviewManually,
        }
    }

    #[test]
    fn test_clean_empty_and_unavailable_serialize_differently() {
        let clean = parse(&report(Check::from_parts(Vec::new(), Gaps::new())));
        let unavailable = parse(&report(Check::Unavailable {
            gap: gap(DiagnosticCode::InspectionUnavailable, "/usr/sbin/scutil"),
        }));
        assert_eq!(
            clean["checks"][0]["result"],
            json!({"state": "complete", "value": []})
        );
        assert_eq!(
            unavailable["checks"][0]["result"],
            json!({
                "state": "unavailable",
                "gap": {"code": "inspection_unavailable", "subject": "/usr/sbin/scutil"}
            })
        );
    }

    #[test]
    fn test_partial_carries_its_gaps_and_the_value() {
        let mut gaps = Gaps::new();
        gaps.push(gap(DiagnosticCode::DirectoryUnreadable, "/p/secret"));
        let json = parse(&report(Check::from_parts(vec![diagnostic()], gaps)));
        assert_eq!(
            json["checks"][0]["result"],
            json!({
                "state": "partial",
                "value": [{
                    "code": "directory_unreadable",
                    "severity": "warning",
                    "subject": "/p/found",
                    "remedy": "review_manually"
                }],
                "gaps": {
                    "shown": [{"code": "directory_unreadable", "subject": "/p/secret"}],
                    "omitted": 0
                }
            })
        );
    }

    #[test]
    fn test_gaps_past_the_cap_are_counted_and_keep_the_result_incomplete() {
        assert_eq!(MAX_GAPS, 32);
        for pushed in [MAX_GAPS - 1, MAX_GAPS, MAX_GAPS + 1, MAX_GAPS + 5] {
            let mut gaps = Gaps::new();
            for _ in 0..pushed {
                gaps.push(gap(DiagnosticCode::DirectoryUnreadable, "/p"));
            }
            assert_eq!(gaps.shown().len(), pushed.min(MAX_GAPS));
            assert_eq!(gaps.omitted(), pushed.saturating_sub(MAX_GAPS) as u64);
            assert!(!Check::from_parts((), gaps).is_complete());
        }
    }

    #[test]
    fn test_the_omitted_count_saturates() {
        let mut gaps = Gaps::new();
        for _ in 0..MAX_GAPS {
            gaps.push(gap(DiagnosticCode::DirectoryUnreadable, "/p"));
        }
        gaps.omitted = u64::MAX;
        gaps.push(gap(DiagnosticCode::DirectoryUnreadable, "/p"));
        assert_eq!(gaps.omitted(), u64::MAX);
    }

    #[test]
    fn test_gaps_with_only_an_omitted_count_are_not_empty() {
        let gaps = Gaps {
            shown: Vec::new(),
            omitted: 1,
        };
        assert!(!gaps.is_empty());
        assert!(!Check::from_parts((), gaps).is_complete());
    }

    #[test]
    fn test_control_and_bidi_characters_never_render_raw() {
        // C0, ESC, DEL, C1, a bidi override, a zero-width space and a tag character.
        let hostile = "/p/\u{1b}[2J\nx\u{7f}\u{85}\u{202e}y\u{200b}\u{e0041}";
        let raw = [
            '\u{1b}',
            '\n',
            '\u{7f}',
            '\u{85}',
            '\u{202e}',
            '\u{200b}',
            '\u{e0041}',
        ];
        let subject = SafePath::new(hostile);
        let finding = Diagnostic {
            subject: Some(subject.clone()),
            ..diagnostic()
        };
        for text in [
            subject.to_string(),
            format!("{subject:?}"),
            format!("{finding:?}"),
        ] {
            assert!(!text.contains(raw), "{text:?}");
        }
        let mut gaps = Gaps::new();
        gaps.push(gap(DiagnosticCode::DirectoryUnreadable, hostile));
        let reports = [
            report(Check::Unavailable {
                gap: gap(DiagnosticCode::InspectionUnavailable, hostile),
            }),
            report(Check::from_parts(vec![finding.clone()], Gaps::new())),
            report(Check::from_parts(vec![finding], gaps)),
        ];
        for report in &reports {
            let json = assert_ok!(report.to_json());
            // Pretty printing adds newlines and indentation between values; none is inside a string.
            assert!(!json.contains(&raw[2..]), "{json:?}");
            assert!(!json.contains('\u{1b}'), "{json:?}");
            assert!(
                json.contains("\\u001b") && json.contains("\\u202e"),
                "{json}"
            );
            assert!(json.contains("\\n"), "{json}");
        }
        assert_eq!(parse_subject(&assert_ok!(reports[0].to_json())), hostile);
    }

    fn parse_subject(json: &str) -> String {
        let value: Value = assert_ok!(serde_json::from_str(json));
        let subject = assert_some!(value["checks"][0]["result"]["gap"]["subject"].as_str());
        subject.to_owned()
    }

    #[test]
    fn test_subject_is_bounded_on_a_character_boundary() {
        assert_eq!(MAX_SUBJECT_CHARS, 512);
        let kept = |n: usize, ch: char| SafePath::new(&ch.to_string().repeat(n)).0;
        for ch in ['a', 'é', '\u{1f600}'] {
            assert_eq!(kept(511, ch), ch.to_string().repeat(511));
            assert_eq!(kept(512, ch), ch.to_string().repeat(512));
            assert_eq!(kept(513, ch), format!("{}...", ch.to_string().repeat(512)));
        }
    }

    #[test]
    fn test_exit_code_is_zero_by_default_and_three_only_when_strict_and_incomplete() {
        let unavailable = || Check::Unavailable {
            gap: gap(DiagnosticCode::InspectionUnavailable, "x"),
        };
        let mut gaps = Gaps::new();
        gaps.push(gap(DiagnosticCode::DirectoryUnreadable, "x"));
        let partial = Check::from_parts(Vec::new(), gaps);
        let complete = || Check::from_parts(vec![diagnostic()], Gaps::new());
        let all = |results: Vec<Check<Vec<Diagnostic>>>| {
            DoctorReport::new(
                results
                    .into_iter()
                    .map(|result| CheckReport {
                        id: CheckId::Git,
                        result,
                    })
                    .collect(),
            )
        };
        assert_eq!(EXIT_INCOMPLETE, 3);
        // Findings, even errors, are not incompleteness.
        assert_eq!(all(vec![complete()]).exit_code(true), 0);
        assert_eq!(all(vec![unavailable()]).exit_code(false), 0);
        assert_eq!(all(vec![unavailable()]).exit_code(true), 3);
        assert_eq!(all(vec![partial.clone()]).exit_code(true), 3);
        assert_eq!(all(vec![partial.clone(), complete()]).exit_code(true), 3);
        assert_eq!(all(vec![complete(), partial]).exit_code(true), 3);
        assert_eq!(all(vec![complete(), unavailable()]).exit_code(false), 0);
        // An empty report is complete over the checks it holds (see the module docs).
        assert_eq!(all(Vec::new()).exit_code(true), 0);
    }

    #[test]
    fn test_enum_tokens_are_the_documented_strings() {
        fn token<T: Serialize + AsRef<str> + fmt::Display>(value: T, expected: &str) {
            assert_eq!(assert_ok!(serde_json::to_value(&value)), expected);
            assert_eq!(value.as_ref(), expected);
            assert_eq!(value.to_string(), expected);
        }
        token(DiagnosticCode::DirectoryUnreadable, "directory_unreadable");
        token(DiagnosticCode::NameNotUtf8, "name_not_utf8");
        token(DiagnosticCode::EntryLimitReached, "entry_limit_reached");
        token(
            DiagnosticCode::InspectionUnavailable,
            "inspection_unavailable",
        );
        token(Severity::Info, "info");
        token(Severity::Warning, "warning");
        token(Severity::Error, "error");
        token(Remedy::None, "none");
        token(Remedy::ReviewManually, "review_manually");
        token(CheckId::SecretsSurvey, "secrets_survey");
        token(CheckId::Git, "git");
        token(CheckId::Proxy, "proxy");
    }

    #[test]
    fn test_schema_version_is_pinned() {
        // A shape change that is not additive must bump this, and the rules in the module docs.
        assert_eq!(SCHEMA_VERSION, 1);
        assert_eq!(
            parse(&DoctorReport::new(Vec::new())),
            json!({"schema_version": 1, "checks": []})
        );
    }
}
