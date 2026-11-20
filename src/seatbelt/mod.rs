// ABOUTME: Seatbelt profile generation: Policy and RenderInputs to a checked, ordered rule list, then text plus -D params.
// ABOUTME: Pure: plan builds typed rules, check enforces invariants, emit writes text; config text never enters the profile.
//! The Seatbelt backend (design 7.1).
//!
//! [`render`] is a pure function of `(Policy, RenderInputs)`:
//!
//! 1. `plan` builds the sorted typed rule list (baseline, grants, TLS, network, denies, floor).
//! 2. [`check`] verifies the invariants that close the traps measured in the analysis.
//! 3. [`emit`] writes it as text, with every path, regex and endpoint as a `-D` parameter.
//!
//! Nothing derived from configuration appears in the text. Run the result with
//! `sandbox-exec -p <text> <-D name=value>... -- <command>`.

pub mod check;
pub mod emit;
pub mod inputs;
mod pattern;
mod plan;
pub mod rule;

use snafu::{ResultExt, Snafu, ensure};

pub use check::InvariantViolation;
pub use emit::{LogTag, LogTagError, Profile, RenderWarning};
pub use inputs::{ProxyEndpoint, RenderInputs};

use crate::config::Policy;
use crate::policy::FloorRule;

/// The filter count from which a profile is reported as large.
pub const WARN_FILTERS: usize = 600;
/// The filter count above which a profile is refused. Compile time is roughly quadratic:
/// about 0.06 s at 131, 1.5 s at 600 and 36 s at 4096 (measured).
pub const MAX_FILTERS: usize = 1500;

/// Why a profile could not be rendered.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RenderError {
    /// The rule list broke an invariant: a bug in this crate, never a user mistake.
    #[snafu(display("the generated profile is not valid"))]
    Invalid {
        /// The invariant that failed.
        source: InvariantViolation,
    },

    /// The profile would take too long to compile.
    #[snafu(display(
        "the profile has {weight} filters; the limit is {max}. Remove grants or denies"
    ))]
    TooLarge {
        /// The number of filters.
        weight: usize,
        /// The limit.
        max: usize,
    },
}

/// Renders `policy` and `inputs` as a profile.
///
/// # Errors
/// [`RenderError`] if the rule list breaks an invariant or is too large.
pub fn render(policy: &Policy, inputs: &RenderInputs) -> Result<Profile, RenderError> {
    render_with(policy, inputs, &|_| true)
}

/// [`render`] with only the floor rules `keep` accepts, for tests that need a control profile
/// without part of the floor or a golden that leaves out machine-dependent rules.
///
/// Compiled only for tests (`cfg(test)` or the `test-support` feature): a release build has no
/// way to render a profile without the whole floor (design D48).
///
/// # Errors
/// See [`render`].
#[cfg(any(test, feature = "test-support"))]
pub fn render_filtered(
    policy: &Policy,
    inputs: &RenderInputs,
    keep: &dyn Fn(&FloorRule) -> bool,
) -> Result<Profile, RenderError> {
    render_with(policy, inputs, keep)
}

fn render_with(
    policy: &Policy,
    inputs: &RenderInputs,
    keep: &dyn Fn(&FloorRule) -> bool,
) -> Result<Profile, RenderError> {
    let rules = plan::plan(policy, inputs, keep);
    check::check(&rules).context(InvalidSnafu)?;
    let weight = plan::weight(&rules);
    ensure!(
        weight <= MAX_FILTERS,
        TooLargeSnafu {
            weight,
            max: MAX_FILTERS
        }
    );
    let mut profile = emit::emit(&rules, inputs.log_tag.as_ref());
    if weight >= WARN_FILTERS {
        profile.warnings.push(RenderWarning::LargeProfile {
            weight,
            warn_at: WARN_FILTERS,
        });
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::merge;
    use crate::origin::{FileId, Source, Sourced};
    use crate::policy::{CanonicalPath, Extent, Floor, FloorEffect, PathPattern};
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn cp(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    fn policy_with_denies(count: usize) -> Policy {
        let rules = (0..count)
            .map(|i| {
                FloorRule::new(
                    format!("r{i}"),
                    FloorEffect::DenyWrite,
                    Extent::Subtree,
                    PathPattern {
                        base: cp(&format!("/Users/me/d{i:05}")),
                        alias: None,
                        tail: None,
                    },
                    "test",
                )
            })
            .collect();
        assert_ok!(merge(&[], assert_ok!(Floor::new(rules))))
    }

    #[test]
    fn render_is_deterministic_and_starts_with_the_header() {
        let policy = policy_with_denies(3);
        let a = assert_ok!(render(&policy, &RenderInputs::new()));
        let b = assert_ok!(render(&policy, &RenderInputs::new()));
        assert_eq!(a, b);
        assert!(
            a.text
                .starts_with("(version 1)\n(deny default)\n(import \"system.sb\")\n")
        );
        assert!(a.warnings.is_empty());
    }

    #[test]
    fn no_path_from_the_policy_appears_in_the_text() {
        let mut policy = policy_with_denies(2);
        policy.fs.write = vec![Sourced::new(
            cp("/Users/me/proj"),
            Source::value(FileId::new(0)),
        )];
        let profile = assert_ok!(render(&policy, &RenderInputs::new()));
        assert!(!profile.text.contains("/Users/me"), "{}", profile.text);
        assert!(profile.params.iter().any(|(_, v)| v == "/Users/me/proj"));
        assert!(profile.params.iter().any(|(_, v)| v == "/Users/me/d00000"));
    }

    #[test]
    fn a_large_profile_warns_and_an_enormous_one_is_refused() {
        let at_warning = assert_ok!(render(&policy_with_denies(700), &RenderInputs::new()));
        assert!(
            matches!(
                at_warning.warnings[..],
                [RenderWarning::LargeProfile { .. }]
            ),
            "{:?}",
            at_warning.warnings
        );
        assert!(
            at_warning.warnings[0]
                .to_string()
                .contains("warning from 600")
        );
        let err = assert_err!(render(
            &policy_with_denies(MAX_FILTERS + 100),
            &RenderInputs::new()
        ));
        assert!(matches!(err, RenderError::TooLarge { .. }), "{err:?}");
        assert!(err.to_string().contains("limit is 1500"));
    }

    #[test]
    fn render_filtered_can_drop_floor_rules_for_a_control_profile() {
        let rules = vec![FloorRule::new(
            "pin",
            FloorEffect::PinUnlink,
            Extent::Node,
            PathPattern {
                base: cp("/Users/me/p"),
                alias: None,
                tail: None,
            },
            "test",
        )];
        let policy = assert_ok!(merge(&[], assert_ok!(Floor::new(rules))));
        let with = assert_ok!(render(&policy, &RenderInputs::new()));
        let without = assert_ok!(render_filtered(&policy, &RenderInputs::new(), &|r| {
            r.effect != FloorEffect::PinUnlink
        }));
        assert!(with.text.contains("file-write-unlink"));
        assert!(!without.text.contains("file-write-unlink"));
    }

    #[test]
    fn the_invalid_error_is_a_bug_message_and_does_not_repeat_its_source() {
        let error = RenderError::Invalid {
            source: InvariantViolation::NoOperations { index: 0 },
        };
        crate::error::conventions::assert_display_excludes_sources(&error);
        assert_eq!(error.to_string(), "the generated profile is not valid");
    }

    // ----- properties over arbitrary policies -----

    use proptest::prelude::*;

    /// A path whose components may contain every character a path may: quotes, parentheses,
    /// semicolons, backslashes, spaces, `#`, and non-ASCII text.
    fn hostile_path() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z0-9 \"();#\\\\\u{e9}\u{1f600}.*?+\\[\\]|^$]{1,8}", 1..4)
            .prop_map(|parts| format!("/zzmark/{}", parts.join("/")))
    }

    fn glob_tail() -> impl Strategy<Value = Option<crate::policy::GlobTail>> {
        proptest::option::of(
            proptest::collection::vec("[a-z*?.]{1,5}", 1..3).prop_filter_map(
                "valid tail",
                |segments| {
                    let refs: Vec<&str> = segments.iter().map(String::as_str).collect();
                    crate::policy::GlobTail::parse(&refs).ok()
                },
            ),
        )
    }

    fn arbitrary_policy() -> impl Strategy<Value = Policy> {
        (
            proptest::collection::vec(hostile_path(), 0..6),
            proptest::collection::vec(hostile_path(), 0..6),
            proptest::collection::vec((hostile_path(), glob_tail()), 0..6),
            proptest::collection::vec((hostile_path(), glob_tail()), 0..6),
            proptest::collection::vec(1u16..=65535, 0..5),
            proptest::collection::vec(1u16..=65535, 0..5),
            any::<bool>(),
        )
            .prop_map(|(reads, writes, deny_r, deny_w, loopback, bind, trust)| {
                let src = Source::value(FileId::new(0));
                let mut policy = assert_ok!(merge(&[], Floor::empty()));
                let paths = |v: Vec<String>| {
                    v.into_iter()
                        .filter_map(|p| CanonicalPath::from_canonical(p).ok())
                        .map(|p| Sourced::new(p, src))
                        .collect::<Vec<_>>()
                };
                let patterns = |v: Vec<(String, Option<crate::policy::GlobTail>)>| {
                    v.into_iter()
                        .filter_map(|(p, tail)| {
                            Some(Sourced::new(
                                PathPattern {
                                    base: CanonicalPath::from_canonical(p).ok()?,
                                    alias: None,
                                    tail,
                                },
                                src,
                            ))
                        })
                        .collect::<Vec<_>>()
                };
                let ports = |v: Vec<u16>| {
                    v.into_iter()
                        .filter_map(|p| crate::policy::Port::try_from(i64::from(p)).ok())
                        .collect::<Vec<_>>()
                };
                policy.fs.read = paths(reads);
                policy.fs.write = paths(writes);
                policy.fs.deny_read = patterns(deny_r);
                policy.fs.deny_write = patterns(deny_w);
                policy.net.loopback_ports = ports(loopback.clone())
                    .into_iter()
                    .map(|p| Sourced::new(p, src))
                    .collect();
                policy.tls.system_trust = Some(Sourced::new(trust, src));
                policy.mcp.insert(
                    assert_ok!(crate::policy::McpName::parse("s")),
                    Sourced::new(
                        crate::config::ResolvedMcpServer {
                            bind_ports: bind
                                .into_iter()
                                .filter_map(|p| {
                                    crate::policy::BindPort::try_from(i64::from(p)).ok()
                                })
                                .collect(),
                            ..crate::config::ResolvedMcpServer::default()
                        },
                        src,
                    ),
                );
                policy
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(200))]

        #[test]
        fn no_policy_makes_an_invalid_profile_and_no_param_value_reaches_the_text(
            policy in arbitrary_policy(),
            proxy in any::<bool>(),
        ) {
            let inputs = if proxy {
                RenderInputs::new().with_proxy(ProxyEndpoint::Placeholder)
            } else {
                RenderInputs::new()
            };
            let profile = render(&policy, &inputs).map_err(|e| TestCaseError::fail(format!("{e:?}")))?;
            for (name, value) in &profile.params {
                // Paths from the policy all carry the marker; none may appear in the text.
                if value.contains("zzmark") {
                    prop_assert!(!profile.text.contains(value.as_str()), "{name}={value:?} leaked");
                }
                prop_assert!(profile.text.contains(&format!("(param \"{name}\")")), "{name} unused");
            }
            // Every denial comes after every allow.
            let lines: Vec<&str> = profile.text.lines().collect();
            let last_allow = lines.iter().rposition(|l| l.starts_with("(allow "));
            let first_deny = lines.iter().position(|l| l.starts_with("(deny ") && !l.starts_with("(deny default"));
            if let (Some(a), Some(d)) = (last_allow, first_deny) {
                prop_assert!(a < d);
            }
            // The network section is only ever filtered by remote or local ip, or a unix socket.
            for line in profile.text.lines().filter(|l| l.contains("network-")) {
                prop_assert!(line.contains("(remote ip (param") || line.contains("(local ip (param") || line.contains("(remote unix-socket"), "{line}");
            }
            prop_assert!(!profile.text.contains("localhost:*") && !profile.text.contains("hid-control"));
        }

        #[test]
        fn the_order_grants_were_declared_in_does_not_change_the_profile(
            mut policy in arbitrary_policy(),
        ) {
            let before = assert_ok!(render(&policy, &RenderInputs::new()));
            policy.fs.read.reverse();
            policy.fs.write.reverse();
            policy.fs.deny_read.reverse();
            policy.fs.deny_write.reverse();
            policy.net.loopback_ports.reverse();
            let after = assert_ok!(render(&policy, &RenderInputs::new()));
            prop_assert_eq!(before, after);
        }
    }
}
