// ABOUTME: Invariants every rule list must satisfy before it is written as text, checked on typed rules.
// ABOUTME: Each one closes a trap measured in the analysis: operation-level precedence, order, unfiltered operations.
//! Invariants over the typed rule list (design 7.1).
//!
//! 1. Sections are non-decreasing, so the floor and pins really come last.
//! 2. Each section allows or denies, not both: the host-services, guard, policy-deny, floor and
//!    pin sections only deny. An allow of `file-write-unlink`, or of any specific write operation, would
//!    override a `file-write*` deny regardless of order, so none is accepted.
//! 3. A deny never uses the `file-read*` wildcard, and a deny of any specific read operation
//!    names all four. Seatbelt resolves the most specific operation first, so a wildcard deny
//!    does not override a specific allow such as the global `file-read-metadata`.
//! 4. A specific read allow appears only in the metadata section (where every later deny lists
//!    the full read set) and the template re-allow (which names the operations of the guard deny
//!    it reopens). A floor or policy deny that names reads names `file-write*` too.
//! 5. `mach-lookup`, `file-ioctl` and the network operations are never allowed unfiltered, and
//!    only with the filter kind that belongs to them.
//! 6. Every parameter is non-empty and absolute (a relative path is accepted by Seatbelt and
//!    then never matches); endpoints are `localhost:<port>` with a non-zero port.
//! 7. Static text contains no quote or control character.

use snafu::Snafu;

use super::rule::{Action, Filter, Op, ParamKind, Rule, Section};

/// A rule list that must not be emitted.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvariantViolation {
    /// A rule names no operation.
    #[snafu(display("rule {index} names no operation"))]
    NoOperations {
        /// The rule's position.
        index: usize,
    },

    /// A rule is in an earlier section than the one before it.
    #[snafu(display("rule {index} is in section {found} after section {previous}"))]
    SectionOrder {
        /// The rule's position.
        index: usize,
        /// The section of the rule before it.
        previous: Section,
        /// Its own section.
        found: Section,
    },

    /// An allow in a deny-only section, or a deny in an allow-only one.
    #[snafu(display("rule {index} may not {action} in the {section} section"))]
    ActionNotAllowed {
        /// The rule's position.
        index: usize,
        /// Its section.
        section: Section,
        /// What it does.
        action: Action,
    },

    /// A specific write operation allowed.
    #[snafu(display(
        "rule {index} allows `{op}`, which would override a `file-write*` deny regardless of order"
    ))]
    SpecificWriteAllow {
        /// The rule's position.
        index: usize,
        /// The operation.
        op: Op,
    },

    /// A deny that names reads but not the write class.
    #[snafu(display("rule {index} denies reads but not `file-write*`"))]
    DenyMissesWrite {
        /// The rule's position.
        index: usize,
    },

    /// A parameter whose kind does not belong to its filter.
    #[snafu(display("rule {index} puts a {kind} parameter in a filter that takes another kind"))]
    WrongParameterKind {
        /// The rule's position.
        index: usize,
        /// The parameter name prefix of the kind found.
        kind: &'static str,
    },

    /// A deny uses the `file-read*` wildcard.
    #[snafu(display("rule {index} denies `file-read*`; a deny must list the read operations"))]
    DenyUsesReadWildcard {
        /// The rule's position.
        index: usize,
    },

    /// A deny lists some specific read operations but not all of them.
    #[snafu(display("rule {index} denies only some read operations; `stat` would still work"))]
    DenyMissesReadOperations {
        /// The rule's position.
        index: usize,
    },

    /// A specific read allow outside the metadata section.
    #[snafu(display("rule {index} allows a specific read operation in the {section} section"))]
    SpecificReadAllowOutsideMetadata {
        /// The rule's position.
        index: usize,
        /// Its section.
        section: Section,
    },

    /// A dangerous operation allowed without a filter.
    #[snafu(display("rule {index} allows `{op}` without a filter"))]
    UnfilteredOperation {
        /// The rule's position.
        index: usize,
        /// The operation.
        op: Op,
    },

    /// A filter that does not belong to the operation.
    #[snafu(display("rule {index} uses a filter that does not fit `{op}`"))]
    WrongFilterForOperation {
        /// The rule's position.
        index: usize,
        /// The operation.
        op: Op,
    },

    /// A parameter that is empty, relative or malformed.
    #[snafu(display("rule {index} has a malformed {what} parameter"))]
    BadParameter {
        /// The rule's position.
        index: usize,
        /// What kind of value it was.
        what: &'static str,
    },

    /// Static text with a quote or control character.
    #[snafu(display("rule {index} has static text that is not plain"))]
    BadStaticText {
        /// The rule's position.
        index: usize,
    },
}

/// Checks `rules`.
///
/// # Errors
/// The first [`InvariantViolation`] found, in rule order.
pub fn check(rules: &[Rule]) -> Result<(), InvariantViolation> {
    let mut previous: Option<Section> = None;
    for (index, rule) in rules.iter().enumerate() {
        if rule.ops.is_empty() {
            return Err(InvariantViolation::NoOperations { index });
        }
        if let Some(previous) = previous
            && rule.section < previous
        {
            return Err(InvariantViolation::SectionOrder {
                index,
                previous,
                found: rule.section,
            });
        }
        previous = Some(rule.section);
        check_action(index, rule)?;
        check_filters(index, rule)?;
    }
    Ok(())
}

/// Whether `section` holds allows (true) or denies (false).
fn section_allows(section: Section) -> bool {
    !matches!(
        section,
        Section::HostServices
            | Section::Guard
            | Section::PolicyDeny
            | Section::Floor
            | Section::Pins
    )
}

fn check_action(index: usize, rule: &Rule) -> Result<(), InvariantViolation> {
    if (rule.action == Action::Allow) != section_allows(rule.section) {
        return Err(InvariantViolation::ActionNotAllowed {
            index,
            section: rule.section,
            action: rule.action,
        });
    }
    match rule.action {
        Action::Allow => {
            if let Some(&op) = rule
                .ops
                .iter()
                .find(|op| matches!(op, Op::FileWriteUnlink | Op::FileLink))
            {
                return Err(InvariantViolation::SpecificWriteAllow { index, op });
            }
            // A specific read allow is safe only where every later deny lists the same
            // operations: the global metadata allow, and the template re-allow of a guard deny.
            let specific_ok = matches!(rule.section, Section::Metadata | Section::TemplateAllow);
            if rule.ops.iter().any(|op| op.is_specific_read()) && !specific_ok {
                return Err(InvariantViolation::SpecificReadAllowOutsideMetadata {
                    index,
                    section: rule.section,
                });
            }
            if let Some(&op) = rule
                .ops
                .iter()
                .find(|op| op.needs_filter() && rule.filters.is_empty())
            {
                return Err(InvariantViolation::UnfilteredOperation { index, op });
            }
        }
        Action::Deny => {
            if rule.ops.contains(&Op::FileReadAll) {
                return Err(InvariantViolation::DenyUsesReadWildcard { index });
            }
            let listed = Op::READ_SET
                .iter()
                .filter(|op| rule.ops.contains(op))
                .count();
            // The guard deliberately leaves file names visible, so it may name a subset.
            if listed != 0 && listed != Op::READ_SET.len() && rule.section != Section::Guard {
                return Err(InvariantViolation::DenyMissesReadOperations { index });
            }
            if listed != 0 && !rule.ops.contains(&Op::FileWriteAll) {
                return Err(InvariantViolation::DenyMissesWrite { index });
            }
        }
    }
    Ok(())
}

/// Whether `filter` is one `op` may be used with.
fn fits(op: Op, filter: &Filter) -> bool {
    match op {
        Op::NetworkOutbound => matches!(
            filter,
            Filter::RemoteIp(_) | Filter::RemoteUnixSocket(_) | Filter::RemoteUnixSocketLiteral(_)
        ),
        Op::NetworkBind | Op::NetworkInbound => matches!(filter, Filter::LocalIp(_)),
        Op::MachLookup => matches!(filter, Filter::GlobalName(_)),
        Op::UserPreferenceRead => matches!(filter, Filter::PreferenceDomain(_)),
        Op::Signal => matches!(filter, Filter::TargetSameSandbox),
        Op::FileIoctl => matches!(filter, Filter::Literal(_)),
        Op::FileReadAll
        | Op::FileWriteAll
        | Op::FileWriteUnlink
        | Op::FileLink
        | Op::FileReadData
        | Op::FileReadMetadata
        | Op::FileReadXattr
        | Op::FileTestExistence
        | Op::FileMapExecutable => matches!(
            filter,
            Filter::Subpath(_)
                | Filter::Literal(_)
                | Filter::Regex(_)
                | Filter::PathAncestors(_)
                | Filter::StaticSubpath(_)
                | Filter::StaticLiteral(_)
                | Filter::StaticRegex(_)
        ),
        Op::ProcessExec => matches!(filter, Filter::StaticLiteral(_)),
        Op::ProcessFork | Op::IpcPosixShm | Op::IpcPosixSem => false,
    }
}

/// Whether a parameter of `kind` belongs in `filter`.
fn kind_fits(filter: &Filter, kind: ParamKind) -> bool {
    match filter {
        Filter::RemoteIp(_) => matches!(kind, ParamKind::Proxy | ParamKind::Loopback),
        Filter::LocalIp(_) => kind == ParamKind::Bind,
        Filter::RemoteUnixSocket(_) | Filter::RemoteUnixSocketLiteral(_) => {
            kind == ParamKind::Socket
        }
        Filter::Regex(_) => kind == ParamKind::Regex,
        Filter::PathAncestors(_) => kind == ParamKind::Ancestor,
        Filter::Subpath(_) | Filter::Literal(_) => {
            !kind.is_endpoint()
                && !matches!(
                    kind,
                    ParamKind::Regex | ParamKind::Ancestor | ParamKind::Socket
                )
        }
        _ => true,
    }
}

fn check_filters(index: usize, rule: &Rule) -> Result<(), InvariantViolation> {
    for filter in &rule.filters {
        if let Some(&op) = rule.ops.iter().find(|&&op| !fits(op, filter)) {
            return Err(InvariantViolation::WrongFilterForOperation { index, op });
        }
        if let Some(param) = filter.param() {
            if !kind_fits(filter, param.kind) {
                return Err(InvariantViolation::WrongParameterKind {
                    index,
                    kind: param.kind.prefix(),
                });
            }
            check_param(index, param.kind, &param.text)?;
        }
        if let Some(text) = filter.static_text()
            && text
                .chars()
                .any(|c| c == '"' || c == '\\' || c.is_control())
        {
            return Err(InvariantViolation::BadStaticText { index });
        }
    }
    Ok(())
}

fn check_param(index: usize, kind: ParamKind, text: &str) -> Result<(), InvariantViolation> {
    let bad = |what| Err(InvariantViolation::BadParameter { index, what });
    if text.is_empty() {
        return bad("empty");
    }
    if kind.is_endpoint() {
        let port_ok = text
            .strip_prefix("localhost:")
            .and_then(|port| port.parse::<u16>().ok())
            .is_some_and(|port| port != 0);
        return if port_ok { Ok(()) } else { bad("endpoint") };
    }
    let expected = if kind == ParamKind::Regex { "^/" } else { "/" };
    if text.starts_with(expected) {
        Ok(())
    } else {
        bad(if kind == ParamKind::Regex {
            "regex"
        } else {
            "relative path"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seatbelt::rule::ParamValue;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn sub(kind: ParamKind, text: &str) -> Filter {
        Filter::Subpath(ParamValue::new(kind, text))
    }

    fn deny_full(section: Section, filter: Filter) -> Rule {
        let mut ops = Op::READ_SET.to_vec();
        ops.push(Op::FileWriteAll);
        Rule::deny(section, &ops, vec![filter])
    }

    #[test]
    fn a_well_formed_list_passes() {
        let rules = [
            Rule::allow(Section::Process, &[Op::ProcessExec], vec![]),
            Rule::allow(Section::Metadata, &[Op::FileReadMetadata], vec![]),
            Rule::allow(
                Section::Grants,
                &[Op::FileReadAll],
                vec![sub(ParamKind::Read, "/a")],
            ),
            deny_full(Section::Floor, sub(ParamKind::Deny, "/a/b")),
            Rule::deny(
                Section::Pins,
                &[Op::FileWriteUnlink],
                vec![Filter::Literal(ParamValue::new(ParamKind::Deny, "/a"))],
            ),
        ];
        assert_ok!(check(&rules));
        assert_ok!(check(&[]));
    }

    #[test]
    fn a_rule_without_operations_is_refused() {
        let rule = Rule {
            section: Section::Process,
            action: Action::Allow,
            ops: vec![],
            filters: vec![],
            label: None,
        };
        assert_eq!(
            assert_err!(check(&[rule])),
            InvariantViolation::NoOperations { index: 0 }
        );
    }

    #[test]
    fn sections_must_not_go_backwards() {
        let rules = [
            Rule::allow(
                Section::Grants,
                &[Op::FileReadAll],
                vec![sub(ParamKind::Read, "/a")],
            ),
            Rule::allow(Section::Process, &[Op::ProcessExec], vec![]),
        ];
        assert!(matches!(
            assert_err!(check(&rules)),
            InvariantViolation::SectionOrder { index: 1, .. }
        ));
    }

    #[test]
    fn an_allow_after_the_floor_is_refused_even_in_the_right_section() {
        let rules = [Rule::allow(
            Section::Floor,
            &[Op::FileReadAll],
            vec![sub(ParamKind::Read, "/a")],
        )];
        assert!(matches!(
            assert_err!(check(&rules)),
            InvariantViolation::ActionNotAllowed {
                index: 0,
                section: Section::Floor,
                action: Action::Allow
            }
        ));
    }

    #[test]
    fn a_deny_may_not_use_the_read_wildcard_or_list_only_some_read_operations() {
        let wildcard = Rule::deny(
            Section::Floor,
            &[Op::FileReadAll, Op::FileWriteAll],
            vec![sub(ParamKind::Deny, "/a")],
        );
        assert_eq!(
            assert_err!(check(&[wildcard])),
            InvariantViolation::DenyUsesReadWildcard { index: 0 }
        );
        let partial = Rule::deny(
            Section::Floor,
            &[Op::FileReadData, Op::FileWriteAll],
            vec![sub(ParamKind::Deny, "/a")],
        );
        assert_eq!(
            assert_err!(check(&[partial])),
            InvariantViolation::DenyMissesReadOperations { index: 0 }
        );
        // A write-only deny is fine: it makes no claim about reads.
        assert_ok!(check(&[Rule::deny(
            Section::Floor,
            &[Op::FileWriteAll],
            vec![sub(ParamKind::Deny, "/a")]
        )]));
    }

    #[test]
    fn a_specific_read_allow_is_only_for_the_metadata_section() {
        let rule = Rule::allow(
            Section::Grants,
            &[Op::FileReadData],
            vec![sub(ParamKind::Read, "/a")],
        );
        assert!(matches!(
            assert_err!(check(&[rule])),
            InvariantViolation::SpecificReadAllowOutsideMetadata { index: 0, .. }
        ));
    }

    #[test]
    fn dangerous_operations_need_a_filter_of_the_right_kind() {
        for op in [
            Op::MachLookup,
            Op::FileIoctl,
            Op::NetworkOutbound,
            Op::NetworkBind,
            Op::NetworkInbound,
        ] {
            let section = if op == Op::MachLookup {
                Section::Tls
            } else {
                Section::Network
            };
            let rule = Rule::allow(section, &[op], vec![]);
            assert_eq!(
                assert_err!(check(&[rule])),
                InvariantViolation::UnfilteredOperation { index: 0, op }
            );
        }
        let wrong = Rule::allow(
            Section::Network,
            &[Op::NetworkOutbound],
            vec![sub(ParamKind::Read, "/a")],
        );
        assert!(matches!(
            assert_err!(check(&[wrong])),
            InvariantViolation::WrongFilterForOperation { index: 0, .. }
        ));
        let bind_with_remote = Rule::allow(
            Section::Network,
            &[Op::NetworkBind],
            vec![Filter::RemoteIp(ParamValue::new(
                ParamKind::Proxy,
                "localhost:1",
            ))],
        );
        assert!(matches!(
            assert_err!(check(&[bind_with_remote])),
            InvariantViolation::WrongFilterForOperation { .. }
        ));
    }

    #[test]
    fn parameters_must_be_absolute_non_empty_and_well_formed() {
        let relative = Rule::allow(
            Section::Grants,
            &[Op::FileReadAll],
            vec![sub(ParamKind::Read, "rel/path")],
        );
        assert!(matches!(
            assert_err!(check(&[relative])),
            InvariantViolation::BadParameter {
                what: "relative path",
                ..
            }
        ));
        let empty = Rule::allow(
            Section::Grants,
            &[Op::FileReadAll],
            vec![sub(ParamKind::Read, "")],
        );
        assert!(matches!(
            assert_err!(check(&[empty])),
            InvariantViolation::BadParameter { what: "empty", .. }
        ));
        for endpoint in [
            "localhost:*",
            "localhost:0",
            "localhost:70000",
            "example.com:80",
            "localhost:",
        ] {
            let rule = Rule::allow(
                Section::Network,
                &[Op::NetworkOutbound],
                vec![Filter::RemoteIp(ParamValue::new(
                    ParamKind::Loopback,
                    endpoint,
                ))],
            );
            assert!(
                matches!(
                    assert_err!(check(&[rule])),
                    InvariantViolation::BadParameter {
                        what: "endpoint",
                        ..
                    }
                ),
                "{endpoint}"
            );
        }
        let regex = Rule::deny(
            Section::Floor,
            &[Op::FileWriteAll],
            vec![Filter::Regex(ParamValue::new(ParamKind::Regex, ".*"))],
        );
        assert!(matches!(
            assert_err!(check(&[regex])),
            InvariantViolation::BadParameter { what: "regex", .. }
        ));
    }

    #[test]
    fn static_text_may_not_carry_a_quote_or_control_character() {
        for text in ["/a\"b", "/a\nb"] {
            let rule = Rule::allow(
                Section::SystemRead,
                &[Op::FileReadAll],
                vec![Filter::StaticSubpath(text)],
            );
            assert_eq!(
                assert_err!(check(&[rule])),
                InvariantViolation::BadStaticText { index: 0 }
            );
        }
    }

    #[test]
    fn an_exec_rule_may_name_only_a_literal_written_in_this_crate() {
        let literal = Rule::deny(
            Section::HostServices,
            &[Op::ProcessExec],
            vec![Filter::StaticLiteral("/bin/launchctl")],
        );
        assert_ok!(check(&[literal]));
        // A path from the policy is never an exec target.
        let from_policy = Rule::deny(
            Section::HostServices,
            &[Op::ProcessExec],
            vec![sub(ParamKind::Read, "/bin/launchctl")],
        );
        assert_eq!(
            assert_err!(check(&[from_policy])),
            InvariantViolation::WrongFilterForOperation {
                index: 0,
                op: Op::ProcessExec
            }
        );
    }

    #[test]
    fn each_section_allows_or_denies_but_not_both() {
        for section in [
            Section::HostServices,
            Section::Guard,
            Section::PolicyDeny,
            Section::Floor,
            Section::Pins,
        ] {
            let rule = Rule::allow(
                section,
                &[Op::FileReadAll],
                vec![sub(ParamKind::Read, "/a")],
            );
            assert!(
                matches!(
                    assert_err!(check(&[rule])),
                    InvariantViolation::ActionNotAllowed {
                        action: Action::Allow,
                        ..
                    }
                ),
                "{section}"
            );
        }
        for section in [
            Section::Process,
            Section::Metadata,
            Section::SystemRead,
            Section::Grants,
            Section::Tls,
            Section::Network,
            Section::TemplateAllow,
        ] {
            let rule = Rule::deny(
                section,
                &[Op::FileWriteAll],
                vec![sub(ParamKind::Deny, "/a")],
            );
            assert!(
                matches!(
                    assert_err!(check(&[rule])),
                    InvariantViolation::ActionNotAllowed {
                        action: Action::Deny,
                        ..
                    }
                ),
                "{section}"
            );
        }
    }

    #[test]
    fn an_allow_of_unlink_is_refused_because_a_specific_write_allow_beats_a_wildcard_deny() {
        let rule = Rule::allow(
            Section::Grants,
            &[Op::FileWriteUnlink],
            vec![sub(ParamKind::Write, "/a")],
        );
        assert_eq!(
            assert_err!(check(&[rule])),
            InvariantViolation::SpecificWriteAllow {
                index: 0,
                op: Op::FileWriteUnlink
            }
        );
    }

    #[test]
    fn a_floor_or_policy_deny_that_names_reads_must_also_name_the_write_class() {
        for section in [Section::PolicyDeny, Section::Floor] {
            let reads_only = Rule::deny(section, &Op::READ_SET, vec![sub(ParamKind::Deny, "/a")]);
            assert_eq!(
                assert_err!(check(&[reads_only])),
                InvariantViolation::DenyMissesWrite { index: 0 },
                "{section}"
            );
        }
    }

    #[test]
    fn a_guard_deny_may_name_a_subset_of_reads_so_file_names_stay_visible_but_must_name_writes() {
        let guard = Rule::deny(
            Section::Guard,
            &[Op::FileReadData, Op::FileReadXattr, Op::FileWriteAll],
            vec![Filter::Regex(ParamValue::new(
                ParamKind::Regex,
                "^/p/\\.env$",
            ))],
        );
        assert_ok!(check(&[guard]));
        let without_write = Rule::deny(
            Section::Guard,
            &[Op::FileReadData, Op::FileReadXattr],
            vec![Filter::Regex(ParamValue::new(
                ParamKind::Regex,
                "^/p/\\.env$",
            ))],
        );
        assert_eq!(
            assert_err!(check(&[without_write])),
            InvariantViolation::DenyMissesWrite { index: 0 }
        );
    }

    #[test]
    fn the_template_reallow_may_name_the_specific_reads_the_guard_deny_names() {
        let guard = Rule::deny(
            Section::Guard,
            &[Op::FileReadData, Op::FileReadXattr, Op::FileWriteAll],
            vec![Filter::Regex(ParamValue::new(
                ParamKind::Regex,
                "^/p/\\.env.*$",
            ))],
        );
        let reallow = Rule::allow(
            Section::TemplateAllow,
            &[Op::FileReadData, Op::FileReadXattr, Op::FileWriteAll],
            vec![Filter::Literal(ParamValue::new(
                ParamKind::Write,
                "/p/.env.example",
            ))],
        );
        assert_ok!(check(&[guard, reallow]));
    }

    #[test]
    fn a_filter_must_carry_the_kind_of_parameter_that_belongs_to_it() {
        let cases = [
            Filter::RemoteIp(ParamValue::new(ParamKind::Read, "/")),
            Filter::LocalIp(ParamValue::new(ParamKind::Proxy, "localhost:1")),
            Filter::RemoteUnixSocket(ParamValue::new(ParamKind::Deny, "/s")),
            Filter::Regex(ParamValue::new(ParamKind::Read, "^/x")),
            Filter::Subpath(ParamValue::new(ParamKind::Regex, "^/x")),
            Filter::Subpath(ParamValue::new(ParamKind::Loopback, "localhost:5")),
            Filter::PathAncestors(ParamValue::new(ParamKind::Write, "/a")),
        ];
        for filter in cases {
            let op = match filter {
                Filter::RemoteIp(_) | Filter::RemoteUnixSocket(_) => Op::NetworkOutbound,
                Filter::LocalIp(_) => Op::NetworkBind,
                _ => Op::FileReadAll,
            };
            let section = if op == Op::FileReadAll {
                Section::Grants
            } else {
                Section::Network
            };
            let rule = Rule::allow(section, &[op], vec![filter.clone()]);
            let text = format!("{filter:?}");
            assert!(
                matches!(
                    assert_err!(check(&[rule])),
                    InvariantViolation::WrongParameterKind { .. }
                ),
                "{text}"
            );
        }
    }

    #[test]
    fn static_text_may_not_end_in_a_backslash_that_would_escape_the_closing_quote() {
        let rule = Rule::allow(
            Section::SystemRead,
            &[Op::FileReadAll],
            vec![Filter::StaticSubpath("/a\\")],
        );
        assert_eq!(
            assert_err!(check(&[rule])),
            InvariantViolation::BadStaticText { index: 0 }
        );
    }

    #[test]
    fn messages_name_the_rule_and_do_not_repeat_a_source() {
        let error = InvariantViolation::SectionOrder {
            index: 3,
            previous: Section::Floor,
            found: Section::Grants,
        };
        assert_eq!(
            error.to_string(),
            "rule 3 is in section grants after section floor"
        );
        crate::error::conventions::assert_display_excludes_sources(&error);
    }
}
