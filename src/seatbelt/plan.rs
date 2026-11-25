// ABOUTME: Turns a Policy and RenderInputs into the ordered, typed rule list: the one place that decides what is emitted.
// ABOUTME: Floor rules become explicit-operation denies last; everything else is a wildcard allow in design 7.1 order.
//! Planning.
//!
//! [`plan`] is a pure function from `(Policy, RenderInputs)` to a sorted `Vec<Rule>`. Nothing
//! here writes text; [`super::check`] verifies the list and [`super::emit`] writes it. Sorting is
//! by value, so the same inputs always give the same list.

use std::collections::BTreeSet;

use super::inputs::RenderInputs;
use super::pattern::{children_regex, tail_regex};
use super::rule::{Filter, Op, ParamKind, ParamValue, Rule, Section};
use crate::config::Policy;
use crate::guard::patterns;
use crate::policy::floor::pin_ancestors;
use crate::policy::{BindPort, CanonicalPath, Extent, FloorEffect, FloorRule, PathPattern, Port};

/// Directories every program needs to start (design 7.1 step 3). `/Library` is not here: it
/// contains `/Library/Keychains`, which only the TLS section may grant.
const SYSTEM_READ: &[&str] = &[
    "/usr",
    "/bin",
    "/sbin",
    "/private/etc",
    "/private/var/select",
    "/Library/Developer/CommandLineTools",
];

/// Device nodes shells use for process substitution and redirection.
const DEV_NODES: &[&str] = &["/dev/stdin", "/dev/stdout", "/dev/stderr"];
const DEV_FD_REGEX: &str = "^/dev/fd/[0-9]+$";

/// The `xcrun` tool-path cache in the user temp directory (`<T>/xcrun_db`).
///
/// `/usr/bin/git` and the other developer-tool shims read it to find the real binary. Without
/// the read they print two `couldn't create cache file` lines on every call. Read only: the
/// user's own unsandboxed `xcrun` trusts this file, so a write grant would let the agent point
/// `git` at its own binary. The regex matches the per-user `/private/var/folders/xx/yyyy/T`
/// layout without asking the OS for the directory (another user's copy is unreadable anyway).
const XCRUN_DB_REGEX: &str = "^/private/var/folders/[^/]+/[^/]+/T/xcrun_db$";

/// The trust services (design 4.5, D62).
///
/// Only what a measured client needed. `trustd` and `trustd.agent` are already in `system.sb`.
/// `SecurityServer` and the `System.keychain` read are what Node's `NODE_USE_SYSTEM_CA` needs;
/// `configd` is what `uv` needs (it panics without it). `TrustEvaluationAgent` is what curl and
/// git (SecureTransport) need to verify a host whose certificate is signed by a root in the
/// system store: against a real TLS-inspected host curl fails with it missing and works with it
/// (D68). `securityd.xpc` is left out because it is also the route to the data-protection
/// keychain. `System.keychain-db` is the name a newer macOS may use; the Security framework
/// already probes it.
const TLS_SERVICES: &[&str] = &[
    "com.apple.SecurityServer",
    "com.apple.SystemConfiguration.configd",
    "com.apple.TrustEvaluationAgent",
];
const TLS_READ: &[&str] = &[
    "/Library/Keychains/System.keychain",
    "/Library/Keychains/System.keychain-db",
];

fn pv(kind: ParamKind, path: &CanonicalPath) -> ParamValue {
    ParamValue::new(kind, path.as_str())
}

fn endpoint(kind: ParamKind, port: Port) -> ParamValue {
    ParamValue::new(kind, format!("localhost:{}", port.get()))
}

/// Unique values, sorted.
fn sorted_paths<'a>(paths: impl IntoIterator<Item = &'a CanonicalPath>) -> Vec<&'a CanonicalPath> {
    paths
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Builds the rule list for `policy` and `inputs`, keeping only the floor rules `keep_floor` accepts.
pub(crate) fn plan(
    policy: &Policy,
    inputs: &RenderInputs,
    keep_floor: &dyn Fn(&FloorRule) -> bool,
) -> Vec<Rule> {
    let mut rules = Vec::new();
    process(&mut rules);
    metadata(&mut rules, policy, inputs);
    system_read(&mut rules);
    grants(&mut rules, policy, inputs);
    tls(&mut rules, policy);
    network(&mut rules, policy, inputs);
    guard(&mut rules, policy);
    template_allow(&mut rules, policy, inputs);
    host_services(&mut rules, policy);
    policy_denies(&mut rules, policy);
    floor(&mut rules, policy, inputs, keep_floor);
    rules
}

/// The one program that talks to launchd, `/bin/launchctl` (design 4.6).
///
/// Measured: launchd refuses a sandboxed caller anything that creates a job or touches a running
/// process, but it lets the caller start, unload and disable jobs that are not running, and print
/// the whole service list. No profile rule can separate those requests (they go over the
/// bootstrap port and nothing is logged), so the profile denies running the program. A copy in
/// the project is killed at exec: macOS kills a platform-signed binary that is not on the system
/// volume (checked for a plain copy, a re-signed one and thinned x86_64 and arm64e copies).
const LAUNCHCTL: &str = "/bin/launchctl";

/// Denies the host services the policy has not turned on.
fn host_services(rules: &mut Vec<Rule>, policy: &Policy) {
    if !policy.system.effective_launchctl() {
        rules.push(
            Rule::deny(
                Section::HostServices,
                &[Op::ProcessExec],
                vec![Filter::StaticLiteral(LAUNCHCTL)],
            )
            .labelled("launchctl"),
        );
    }
}

fn process(rules: &mut Vec<Rule>) {
    for op in [
        Op::ProcessExec,
        Op::ProcessFork,
        Op::IpcPosixShm,
        Op::IpcPosixSem,
    ] {
        rules.push(Rule::allow(Section::Process, &[op], vec![]));
    }
    rules.push(Rule::allow(
        Section::Process,
        &[Op::Signal],
        vec![Filter::TargetSameSandbox],
    ));
}

/// Every path the agent can read or write, whose ancestors must be listable.
fn grant_roots<'a>(policy: &'a Policy, inputs: &'a RenderInputs) -> Vec<&'a CanonicalPath> {
    sorted_paths(
        policy
            .fs
            .read
            .iter()
            .map(|g| &g.value)
            .chain(policy.fs.write.iter().map(|g| &g.value))
            .chain(policy.tls.extra_ca_files.iter().map(|g| &g.value))
            .chain(inputs.exec_dirs.iter())
            .chain(inputs.session_dir.iter())
            .chain(inputs.cache_dir.iter()),
    )
}

fn metadata(rules: &mut Vec<Rule>, policy: &Policy, inputs: &RenderInputs) {
    rules.push(Rule::allow(
        Section::Metadata,
        &[Op::FileReadMetadata],
        vec![],
    ));
    let ancestors: Vec<Filter> = grant_roots(policy, inputs)
        .into_iter()
        .map(|p| Filter::PathAncestors(pv(ParamKind::Ancestor, p)))
        .collect();
    if !ancestors.is_empty() {
        rules.push(Rule::allow(
            Section::Metadata,
            &[Op::FileReadData],
            ancestors,
        ));
    }
}

fn system_read(rules: &mut Vec<Rule>) {
    rules.push(Rule::allow(
        Section::SystemRead,
        &[Op::FileReadAll],
        SYSTEM_READ
            .iter()
            .map(|p| Filter::StaticSubpath(p))
            .collect(),
    ));
    let mut nodes: Vec<Filter> = vec![Filter::StaticRegex(DEV_FD_REGEX)];
    nodes.extend(DEV_NODES.iter().map(|p| Filter::StaticLiteral(p)));
    rules.push(Rule::allow(
        Section::SystemRead,
        &[Op::FileReadAll, Op::FileWriteAll],
        nodes,
    ));
    rules.push(Rule::allow(
        Section::SystemRead,
        &[Op::FileReadAll],
        vec![Filter::StaticRegex(XCRUN_DB_REGEX)],
    ));
}

fn grants(rules: &mut Vec<Rule>, policy: &Policy, inputs: &RenderInputs) {
    let reads = sorted_paths(
        policy
            .fs
            .read
            .iter()
            .map(|g| &g.value)
            .chain(inputs.exec_dirs.iter()),
    );
    if !reads.is_empty() {
        rules.push(Rule::allow(
            Section::Grants,
            &[Op::FileReadAll],
            reads
                .into_iter()
                .map(|p| Filter::Subpath(pv(ParamKind::Read, p)))
                .collect(),
        ));
    }
    let writes = sorted_paths(policy.fs.write.iter().map(|g| &g.value));
    if !writes.is_empty() {
        rules.push(Rule::allow(
            Section::Grants,
            &[Op::FileReadAll, Op::FileWriteAll],
            writes
                .into_iter()
                .map(|p| Filter::Subpath(pv(ParamKind::Write, p)))
                .collect(),
        ));
    }
    if let Some(session) = &inputs.session_dir {
        rules.push(Rule::allow(
            Section::Grants,
            &[Op::FileReadAll, Op::FileWriteAll],
            vec![Filter::Subpath(pv(ParamKind::Session, session))],
        ));
    }
    if let Some(cache) = &inputs.cache_dir {
        rules.push(Rule::allow(
            Section::Grants,
            &[Op::FileReadAll, Op::FileWriteAll],
            vec![Filter::Subpath(pv(ParamKind::Cache, cache))],
        ));
    }
    if let Some(tty) = &inputs.tty {
        rules.push(Rule::allow(
            Section::Grants,
            &[Op::FileIoctl],
            vec![Filter::Literal(pv(ParamKind::Tty, tty))],
        ));
    }
}

fn tls(rules: &mut Vec<Rule>, policy: &Policy) {
    if policy.tls.effective_system_trust() {
        rules.push(Rule::allow(
            Section::Tls,
            &[Op::MachLookup],
            TLS_SERVICES.iter().map(|n| Filter::GlobalName(n)).collect(),
        ));
        rules.push(Rule::allow(
            Section::Tls,
            &[Op::FileReadAll],
            TLS_READ.iter().map(|p| Filter::StaticLiteral(p)).collect(),
        ));
    }
    let files = sorted_paths(policy.tls.extra_ca_files.iter().map(|g| &g.value));
    if !files.is_empty() {
        rules.push(Rule::allow(
            Section::Tls,
            &[Op::FileReadAll],
            files
                .into_iter()
                .map(|p| Filter::Literal(pv(ParamKind::Read, p)))
                .collect(),
        ));
    }
}

fn network(rules: &mut Vec<Rule>, policy: &Policy, inputs: &RenderInputs) {
    if let Some(proxy) = inputs.proxy {
        rules.push(Rule::allow(
            Section::Network,
            &[Op::NetworkOutbound],
            vec![Filter::RemoteIp(ParamValue::new(
                ParamKind::Proxy,
                proxy.text(),
            ))],
        ));
    }
    let ports: BTreeSet<Port> = policy.net.loopback_ports.iter().map(|p| p.value).collect();
    if !ports.is_empty() {
        rules.push(Rule::allow(
            Section::Network,
            &[Op::NetworkOutbound],
            ports
                .into_iter()
                .map(|p| Filter::RemoteIp(endpoint(ParamKind::Loopback, p)))
                .collect(),
        ));
    }
    // Profile-wide: the agent spawns its MCP servers, so every process shares one profile.
    let bind: BTreeSet<BindPort> = policy
        .mcp
        .values()
        .flat_map(|server| server.value.bind_ports.iter().copied())
        .collect();
    if !bind.is_empty() {
        let filters = |kind| {
            bind.iter()
                .map(|p| Filter::LocalIp(endpoint(kind, p.port())))
                .collect::<Vec<_>>()
        };
        rules.push(Rule::allow(
            Section::Network,
            &[Op::NetworkBind],
            filters(ParamKind::Bind),
        ));
        rules.push(Rule::allow(
            Section::Network,
            &[Op::NetworkInbound],
            filters(ParamKind::Bind),
        ));
    }
    if let Some(socket) = &inputs.ctl_socket {
        rules.push(Rule::allow(
            Section::Network,
            &[Op::NetworkOutbound],
            vec![Filter::RemoteUnixSocketLiteral(pv(
                ParamKind::Socket,
                socket,
            ))],
        ));
    }
}

/// What the secrets guard denies and re-allows share: content and writes, never metadata.
const GUARD_OPS: [Op; 3] = [Op::FileReadData, Op::FileReadXattr, Op::FileWriteAll];

/// The directories the secrets guard covers: every writable grant (design 8).
///
/// Read-only grants are left out on purpose: toolchains carry CA bundles in `*.pem` files that
/// TLS needs, and nothing there is the project's own secret.
fn guard_roots(policy: &Policy) -> Vec<&CanonicalPath> {
    sorted_paths(policy.fs.write.iter().map(|g| &g.value))
}

fn regex_filter(text: String) -> Filter {
    Filter::Regex(ParamValue::new(ParamKind::Regex, text))
}

/// The secrets guard's deny (design 8): content and writes of guarded names below each root, so
/// reading, writing, deleting, renaming and hard-linking are all refused and `ls` still works.
fn guard(rules: &mut Vec<Rule>, policy: &Policy) {
    let filters: Vec<Filter> = guard_roots(policy)
        .into_iter()
        .map(|root| regex_filter(patterns::deny_regex(root.as_str())))
        .collect();
    if !filters.is_empty() {
        rules.push(Rule::deny(Section::Guard, &GUARD_OPS, filters).labelled("guard"));
    }
}

/// What reopens after the guard, before every floor and policy deny: templates, the dependency
/// exemption, the user's exceptions and the tracked files.
fn template_allow(rules: &mut Vec<Rule>, policy: &Policy, inputs: &RenderInputs) {
    let roots = guard_roots(policy);
    let mut filters: Vec<Filter> = roots
        .iter()
        .map(|root| regex_filter(patterns::template_regex(root.as_str())))
        .collect();
    if inputs.guard.dependency_exemption {
        filters.extend(
            roots
                .iter()
                .map(|root| regex_filter(patterns::dependency_regex(root.as_str()))),
        );
    }
    for exception in &policy.guard_exceptions {
        filters.extend(exception_filters(&exception.value));
    }
    filters.extend(
        sorted_paths(inputs.guard_allow.iter())
            .into_iter()
            .map(|p| Filter::Literal(pv(ParamKind::Write, p))),
    );
    if !filters.is_empty() {
        // The same operations the guard denies (design 8), so the re-allow reopens them.
        rules.push(Rule::allow(Section::TemplateAllow, &GUARD_OPS, filters));
    }
}

/// An exception as allow filters: a literal file, or a regex for a glob tail, for the path and
/// for its symbolic-link alias.
fn exception_filters(pattern: &PathPattern) -> Vec<Filter> {
    std::iter::once(&pattern.base)
        .chain(pattern.alias.as_ref())
        .map(|path| match &pattern.tail {
            Some(tail) => regex_filter(tail_regex(path.as_str(), tail)),
            None => Filter::Literal(pv(ParamKind::Write, path)),
        })
        .collect()
}

/// The filters that select what `pattern` covers, at `extent`, for a deny of `kind` paths.
fn matchers(pattern: &PathPattern, extent: Extent) -> Vec<Filter> {
    let paths = std::iter::once(&pattern.base).chain(pattern.alias.as_ref());
    paths
        .enumerate()
        .map(|(position, path)| {
            let is_alias = position == 1;
            match (&pattern.tail, extent) {
                (Some(tail), _) => Filter::Regex(ParamValue::new(
                    ParamKind::Regex,
                    tail_regex(path.as_str(), tail),
                )),
                (None, Extent::Subtree) if is_alias => Filter::Literal(pv(ParamKind::Deny, path)),
                (None, Extent::Subtree) => Filter::Subpath(pv(ParamKind::Deny, path)),
                (None, Extent::Node) => Filter::Literal(pv(ParamKind::Deny, path)),
                (None, Extent::Children) => Filter::Regex(ParamValue::new(
                    ParamKind::Regex,
                    children_regex(path.as_str()),
                )),
            }
        })
        .collect()
}

fn read_write_ops() -> Vec<Op> {
    let mut ops = Op::READ_SET.to_vec();
    ops.push(Op::FileWriteAll);
    ops
}

/// A sort key that depends only on what the rule says.
fn sort_key(rule: &Rule) -> (String, Vec<String>) {
    let ops = rule
        .ops
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ");
    let filters = rule
        .filters
        .iter()
        .map(|f| f.param().map_or_else(String::new, |p| p.text.clone()))
        .collect();
    (ops, filters)
}

fn policy_denies(rules: &mut Vec<Rule>, policy: &Policy) {
    let mut denies: Vec<Rule> = Vec::new();
    for rule in &policy.fs.deny_read {
        denies.push(
            Rule::deny(
                Section::PolicyDeny,
                &read_write_ops(),
                matchers(&rule.value, Extent::Subtree),
            )
            .labelled("policy"),
        );
    }
    for rule in &policy.fs.deny_write {
        denies.push(
            Rule::deny(
                Section::PolicyDeny,
                &[Op::FileWriteAll],
                matchers(&rule.value, Extent::Subtree),
            )
            .labelled("policy"),
        );
    }
    denies.sort_by_key(sort_key);
    denies.dedup();
    rules.extend(denies);
}

/// Unlink pins for the user's own `deny_read` and `deny_write` entries.
///
/// Without them `mv secrets secrets-old` moves a file denied by `secrets/*.yaml` somewhere no
/// rule covers (found in review of hb-ghd.2.1). The same computation as the floor's own pins.
fn user_pins(policy: &Policy, inputs: &RenderInputs) -> Vec<Rule> {
    let writable: Vec<&CanonicalPath> = policy
        .fs
        .write
        .iter()
        .map(|g| &g.value)
        .chain(inputs.session_dir.iter())
        .collect();
    policy
        .fs
        .deny_read
        .iter()
        .chain(policy.fs.deny_write.iter())
        .flat_map(|deny| pin_ancestors(&deny.value, Extent::Subtree, &writable))
        .map(|path| {
            Rule::deny(
                Section::Pins,
                &[Op::FileWriteUnlink],
                vec![Filter::Literal(pv(ParamKind::Deny, &path))],
            )
            .labelled("pin")
        })
        .collect()
}

/// Pins for the bind-mount sources of containers `hb ctl` may restart (design 9.3).
///
/// `podman restart` resolves a source path again, so a mounted directory swapped for a symlink
/// would be followed. Each source gets an unlink and a link deny (the link deny stops a hard link
/// being made from it). Each ancestor a write grant reaches gets an unlink deny, so renaming the
/// directory above a source fails too. The ancestors stop where the write grants stop: nothing
/// above that can be renamed by the agent anyway.
fn mount_pins(policy: &Policy, inputs: &RenderInputs) -> Vec<Rule> {
    let writable: Vec<&CanonicalPath> = policy
        .fs
        .write
        .iter()
        .map(|g| &g.value)
        .chain(inputs.session_dir.iter())
        .collect();
    let deny = |op: Op, path: &CanonicalPath| {
        Rule::deny(
            Section::Pins,
            &[op],
            vec![Filter::Literal(pv(ParamKind::Deny, path))],
        )
        .labelled("mount-pin")
    };
    let mut rules = Vec::new();
    for source in &inputs.mount_pins {
        rules.push(deny(Op::FileWriteUnlink, source));
        rules.push(deny(Op::FileLink, source));
        let pattern = PathPattern {
            base: source.clone(),
            alias: None,
            tail: None,
        };
        rules.extend(
            pin_ancestors(&pattern, Extent::Node, &writable)
                .iter()
                .map(|ancestor| deny(Op::FileWriteUnlink, ancestor)),
        );
    }
    rules
}

fn floor(
    rules: &mut Vec<Rule>,
    policy: &Policy,
    inputs: &RenderInputs,
    keep: &dyn Fn(&FloorRule) -> bool,
) {
    let mut floor_rules: Vec<Rule> = Vec::new();
    let mut pins: Vec<Rule> = Vec::new();
    for rule in policy.floor().rules().iter().filter(|r| keep(r)) {
        match rule.effect {
            FloorEffect::DenyReadWrite => floor_rules.push(
                Rule::deny(
                    Section::Floor,
                    &read_write_ops(),
                    matchers(&rule.pattern, rule.extent),
                )
                .labelled("floor"),
            ),
            FloorEffect::DenyWrite => floor_rules.push(
                Rule::deny(
                    Section::Floor,
                    &[Op::FileWriteAll],
                    matchers(&rule.pattern, rule.extent),
                )
                .labelled("floor"),
            ),
            FloorEffect::DenyConnect => {
                let paths = std::iter::once(&rule.pattern.base).chain(rule.pattern.alias.as_ref());
                floor_rules.push(
                    Rule::deny(
                        Section::Floor,
                        &[Op::NetworkOutbound],
                        paths
                            .map(|p| Filter::RemoteUnixSocket(pv(ParamKind::Socket, p)))
                            .collect(),
                    )
                    .labelled("floor"),
                );
            }
            FloorEffect::PinUnlink => pins.push(
                Rule::deny(
                    Section::Pins,
                    &[Op::FileWriteUnlink],
                    vec![Filter::Literal(pv(ParamKind::Deny, &rule.pattern.base))],
                )
                .labelled("pin"),
            ),
        }
    }
    pins.extend(user_pins(policy, inputs));
    pins.extend(mount_pins(policy, inputs));
    pins.extend(inputs.guard.pins.iter().map(|path| {
        Rule::deny(
            Section::Pins,
            &[Op::FileWriteUnlink],
            vec![Filter::Literal(pv(ParamKind::Deny, path))],
        )
        .labelled("pin")
    }));
    floor_rules.sort_by_key(sort_key);
    floor_rules.dedup();
    pins.sort_by_key(sort_key);
    pins.dedup();
    rules.extend(floor_rules);
    rules.extend(pins);
}

/// The number of filters across `rules`, which is what profile compile time follows.
pub(crate) fn weight(rules: &[Rule]) -> usize {
    rules.iter().map(|r| r.filters.len().max(1)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ResolvedMcpServer;
    use crate::config::merge;
    use crate::origin::{FileId, Source, Sourced};
    use crate::policy::{ArgWord, BindPort, Floor, GlobTail, McpName, PathPattern, Port};
    use crate::seatbelt::check::check;
    use crate::seatbelt::rule::Action;
    use claims::{assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    fn cp(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    fn src() -> Source {
        Source::value(FileId::new(0))
    }

    fn pattern(base: &str) -> PathPattern {
        PathPattern {
            base: cp(base),
            alias: None,
            tail: None,
        }
    }

    fn frule(
        name: &'static str,
        effect: FloorEffect,
        extent: Extent,
        pattern: PathPattern,
    ) -> FloorRule {
        FloorRule::new(name, effect, extent, pattern, "test")
    }

    fn policy_with(floor_rules: Vec<FloorRule>) -> Policy {
        assert_ok!(merge(&[], assert_ok!(Floor::new(floor_rules))))
    }

    fn is_allow(rule: &Rule) -> bool {
        rule.action == Action::Allow
    }

    fn keep_all(_: &FloorRule) -> bool {
        true
    }

    fn rendered(policy: &Policy, inputs: &RenderInputs) -> Vec<Rule> {
        plan(policy, inputs, &keep_all)
    }

    fn filter_texts(rule: &Rule) -> Vec<String> {
        rule.filters
            .iter()
            .filter_map(|f| f.param().map(|p| p.text.clone()))
            .collect()
    }

    fn find(rules: &[Rule], section: Section, op: Op) -> Vec<&Rule> {
        rules
            .iter()
            .filter(|r| r.section == section && r.ops.contains(&op))
            .collect()
    }

    #[test]
    fn an_empty_policy_still_has_the_baseline_and_passes_every_invariant() {
        let policy = policy_with(vec![]);
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        for op in [
            Op::ProcessExec,
            Op::ProcessFork,
            Op::IpcPosixShm,
            Op::IpcPosixSem,
            Op::Signal,
        ] {
            assert_eq!(find(&rules, Section::Process, op).len(), 1, "{op}");
        }
        assert_eq!(
            find(&rules, Section::Metadata, Op::FileReadMetadata).len(),
            1
        );
        // No grants, so no ancestors, no network, no TLS.
        assert!(find(&rules, Section::Metadata, Op::FileReadData).is_empty());
        assert!(
            rules
                .iter()
                .all(|r| r.section != Section::Network && r.section != Section::Tls)
        );
    }

    #[test]
    fn system_directories_exclude_library_as_a_whole() {
        let rules = rendered(&policy_with(vec![]), &RenderInputs::new());
        let system = find(&rules, Section::SystemRead, Op::FileReadAll);
        let texts: Vec<&str> = system[0]
            .filters
            .iter()
            .filter_map(Filter::static_text)
            .collect();
        assert!(texts.contains(&"/usr") && texts.contains(&"/private/var/select"));
        assert!(texts.contains(&"/Library/Developer/CommandLineTools"));
        assert!(!texts.contains(&"/Library"));
    }

    #[test]
    fn launchctl_cannot_be_executed_unless_a_user_file_turned_it_on() {
        let mut policy = policy_with(vec![]);
        let denies = |policy: &Policy| {
            let rules = rendered(policy, &RenderInputs::new());
            assert_ok!(check(&rules));
            find(&rules, Section::HostServices, Op::ProcessExec)
                .into_iter()
                .map(|rule| {
                    let texts: Vec<String> =
                        static_texts(rule).into_iter().map(str::to_owned).collect();
                    (rule.action, texts)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            denies(&policy),
            [(Action::Deny, vec!["/bin/launchctl".to_owned()])],
            "off by default"
        );
        policy.system.launchctl = Some(Sourced::new(true, src()));
        assert!(denies(&policy).is_empty(), "turned on");
        policy.system.launchctl = Some(Sourced::new(false, src()));
        assert_eq!(denies(&policy).len(), 1, "refused again");
    }

    #[test]
    fn the_launchctl_deny_comes_after_the_exec_allow_it_overrides() {
        let rules = rendered(&policy_with(vec![]), &RenderInputs::new());
        let allow = assert_some!(
            rules
                .iter()
                .position(|r| { r.section == Section::Process && r.ops == [Op::ProcessExec] })
        );
        let deny = assert_some!(
            rules
                .iter()
                .position(|r| r.section == Section::HostServices)
        );
        assert!(allow < deny);
    }

    #[test]
    fn xcrun_cache_is_readable_and_never_writable() {
        let rules = rendered(&policy_with(vec![]), &RenderInputs::new());
        let cache = |op| {
            find(&rules, Section::SystemRead, op)
                .into_iter()
                .filter(|r| {
                    r.filters
                        .iter()
                        .any(|f| f.static_text().is_some_and(|t| t.ends_with("/xcrun_db$")))
                })
                .count()
        };
        assert_eq!(cache(Op::FileReadAll), 1);
        assert_eq!(cache(Op::FileWriteAll), 0);
    }

    #[test]
    fn device_nodes_cover_fd_and_the_standard_streams() {
        let rules = rendered(&policy_with(vec![]), &RenderInputs::new());
        let nodes = find(&rules, Section::SystemRead, Op::FileWriteAll);
        let texts: Vec<&str> = nodes[0]
            .filters
            .iter()
            .filter_map(Filter::static_text)
            .collect();
        assert_eq!(
            texts,
            [
                "^/dev/fd/[0-9]+$",
                "/dev/stdin",
                "/dev/stdout",
                "/dev/stderr"
            ]
        );
    }

    #[test]
    fn grants_become_wildcard_allows_sorted_and_unique_with_a_write_grant_also_readable() {
        let mut policy = policy_with(vec![]);
        policy.fs.read = vec![
            Sourced::new(cp("/Users/me/b"), src()),
            Sourced::new(cp("/Users/me/a"), src()),
        ];
        policy.fs.write = vec![Sourced::new(cp("/Users/me/proj"), src())];
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        let reads = find(&rules, Section::Grants, Op::FileReadAll);
        assert_eq!(filter_texts(reads[0]), ["/Users/me/a", "/Users/me/b"]);
        assert!(!reads[0].ops.contains(&Op::FileWriteAll));
        let writes = reads[1];
        assert_eq!(filter_texts(writes), ["/Users/me/proj"]);
        assert!(writes.ops.contains(&Op::FileWriteAll));
    }

    #[test]
    fn every_grant_gets_an_ancestor_listing_rule_in_the_metadata_section() {
        let mut policy = policy_with(vec![]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/proj"), src())];
        policy.fs.read = vec![Sourced::new(cp("/Users/me/ref"), src())];
        let rules = rendered(&policy, &RenderInputs::new());
        let ancestors = find(&rules, Section::Metadata, Op::FileReadData);
        assert_eq!(
            filter_texts(ancestors[0]),
            ["/Users/me/proj", "/Users/me/ref"]
        );
        assert!(matches!(ancestors[0].filters[0], Filter::PathAncestors(_)));
    }

    #[test]
    fn the_session_dir_tty_and_tool_dirs_are_granted_narrowly() {
        let inputs = RenderInputs::new()
            .with_session_dir(cp("/private/var/folders/x/T/hb-1"))
            .with_tty(cp("/dev/ttys004"))
            .with_exec_dirs(vec![cp("/Users/me/.nvm/versions/node/v24/bin")]);
        let rules = rendered(&policy_with(vec![]), &inputs);
        assert_ok!(check(&rules));
        let ioctl = find(&rules, Section::Grants, Op::FileIoctl);
        assert_eq!(filter_texts(ioctl[0]), ["/dev/ttys004"]);
        assert!(matches!(ioctl[0].filters[0], Filter::Literal(_)));
        let all: Vec<String> = rules.iter().flat_map(filter_texts).collect();
        assert!(all.contains(&"/private/var/folders/x/T/hb-1".to_owned()));
        assert!(all.contains(&"/Users/me/.nvm/versions/node/v24/bin".to_owned()));
    }

    #[test]
    fn the_cache_dir_is_granted_read_and_write_and_is_not_a_write_grant_of_the_policy() {
        let none = rendered(&policy_with(vec![]), &RenderInputs::new());
        let all = |rules: &[Rule]| -> Vec<String> { rules.iter().flat_map(filter_texts).collect() };
        assert!(!all(&none).iter().any(|t| t.contains("hamster-ball")));
        let inputs = RenderInputs::new().with_cache_dir(cp("/Users/me/.cache/hamster-ball"));
        let rules = rendered(&policy_with(vec![]), &inputs);
        assert_ok!(check(&rules));
        let grant = rules
            .iter()
            .find(|r| {
                r.section == Section::Grants
                    && r.filters
                        .iter()
                        .any(|f| matches!(f, Filter::Subpath(p) if p.kind == ParamKind::Cache))
            })
            .map(|r| (r.ops.clone(), filter_texts(r)));
        let (ops, texts) = assert_some!(grant);
        assert_eq!(texts, ["/Users/me/.cache/hamster-ball"]);
        assert!(
            ops.contains(&Op::FileReadAll) && ops.contains(&Op::FileWriteAll),
            "{ops:?}"
        );
        let ancestors = find(&rules, Section::Metadata, Op::FileReadData);
        assert!(
            filter_texts(ancestors[0]).contains(&"/Users/me/.cache/hamster-ball".to_owned()),
            "the cache's ancestors are listable"
        );
    }

    #[test]
    fn tls_rules_appear_only_when_system_trust_is_on() {
        let mut policy = policy_with(vec![]);
        assert!(
            find(
                &rendered(&policy, &RenderInputs::new()),
                Section::Tls,
                Op::MachLookup
            )
            .is_empty()
        );
        policy.tls.system_trust = Some(Sourced::new(true, src()));
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        let mach = find(&rules, Section::Tls, Op::MachLookup);
        assert_eq!(mach[0].filters.len(), TLS_SERVICES.len());
        policy.tls.system_trust = Some(Sourced::new(false, src()));
        assert!(
            find(
                &rendered(&policy, &RenderInputs::new()),
                Section::Tls,
                Op::MachLookup
            )
            .is_empty()
        );
    }

    fn static_texts(rule: &Rule) -> Vec<&str> {
        rule.filters
            .iter()
            .filter_map(Filter::static_text)
            .collect()
    }

    /// Design 4.5, D62 and D68: the measured minimum (history/hb-ghd.2.1_oracle-tls-ports-keychain.md,
    /// history/hb-ghd.2.2_analysis-and-plan.md). `trustd` is already in `system.sb`;
    /// `TrustEvaluationAgent` is what curl and git need to verify a TLS-inspected host;
    /// `securityd.xpc` would also reach the data-protection keychain; no tested client needed
    /// `securityd`, `/private/var/db/mds`, the global preference domain or `networkd.plist`.
    #[test]
    fn system_trust_grants_exactly_the_measured_minimum() {
        let mut policy = policy_with(vec![]);
        policy.tls.system_trust = Some(Sourced::new(true, src()));
        let rules = rendered(&policy, &RenderInputs::new());
        let tls: Vec<&Rule> = rules.iter().filter(|r| r.section == Section::Tls).collect();
        assert_eq!(tls.len(), 2, "{tls:?}");
        let mach = find(&rules, Section::Tls, Op::MachLookup);
        assert_eq!(
            static_texts(mach[0]),
            [
                "com.apple.SecurityServer",
                "com.apple.SystemConfiguration.configd",
                "com.apple.TrustEvaluationAgent"
            ]
        );
        let reads = find(&rules, Section::Tls, Op::FileReadAll);
        assert_eq!(
            static_texts(reads[0]),
            [
                "/Library/Keychains/System.keychain",
                "/Library/Keychains/System.keychain-db"
            ]
        );
        assert!(
            reads[0]
                .filters
                .iter()
                .all(|f| matches!(f, Filter::StaticLiteral(_))),
            "a literal grant, never the whole /Library/Keychains directory"
        );
        assert!(find(&rules, Section::Tls, Op::UserPreferenceRead).is_empty());
    }

    #[test]
    fn extra_ca_files_are_read_grants_even_without_system_trust() {
        let mut policy = policy_with(vec![]);
        policy.tls.extra_ca_files = vec![Sourced::new(cp("/Users/me/ca/corp.pem"), src())];
        let rules = rendered(&policy, &RenderInputs::new());
        let reads = find(&rules, Section::Tls, Op::FileReadAll);
        assert_eq!(filter_texts(reads[0]), ["/Users/me/ca/corp.pem"]);
        assert!(matches!(reads[0].filters[0], Filter::Literal(_)));
    }

    #[test]
    fn network_allows_only_the_proxy_and_listed_loopback_ports() {
        let mut policy = policy_with(vec![]);
        assert!(
            rendered(&policy, &RenderInputs::new())
                .iter()
                .all(|r| r.section != Section::Network)
        );
        policy.net.loopback_ports = vec![
            Sourced::new(assert_ok!(Port::try_from(5432)), src()),
            Sourced::new(assert_ok!(Port::try_from(3030)), src()),
        ];
        let inputs = RenderInputs::new().with_proxy(crate::seatbelt::ProxyEndpoint::Placeholder);
        let rules = rendered(&policy, &inputs);
        assert_ok!(check(&rules));
        let outbound = find(&rules, Section::Network, Op::NetworkOutbound);
        assert_eq!(filter_texts(outbound[0]), ["localhost:1"]);
        assert_eq!(
            filter_texts(outbound[1]),
            ["localhost:3030", "localhost:5432"]
        );
        let all: Vec<String> = rules.iter().flat_map(filter_texts).collect();
        assert!(!all.iter().any(|t| t.contains('*')));
    }

    #[test]
    fn mcp_bind_ports_become_bind_and_inbound_rules_for_exactly_those_ports() {
        let mut policy = policy_with(vec![]);
        let server = |ports: &[u16]| {
            Sourced::new(
                ResolvedMcpServer {
                    command: Some(assert_ok!(ArgWord::parse_program("uvx"))),
                    bind_ports: ports
                        .iter()
                        .map(|p| assert_ok!(BindPort::try_from(i64::from(*p))))
                        .collect(),
                    ..ResolvedMcpServer::default()
                },
                src(),
            )
        };
        policy.mcp.insert(
            assert_ok!(McpName::parse("serena")),
            server(&[24283, 24282]),
        );
        policy
            .mcp
            .insert(assert_ok!(McpName::parse("other")), server(&[24282]));
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        let bind = find(&rules, Section::Network, Op::NetworkBind);
        let inbound = find(&rules, Section::Network, Op::NetworkInbound);
        assert_eq!(
            filter_texts(bind[0]),
            ["localhost:24282", "localhost:24283"]
        );
        assert_eq!(
            filter_texts(inbound[0]),
            ["localhost:24282", "localhost:24283"]
        );
    }

    #[test]
    fn a_server_without_bind_ports_opens_nothing() {
        let mut policy = policy_with(vec![]);
        policy.mcp.insert(
            assert_ok!(McpName::parse("quiet")),
            Sourced::new(ResolvedMcpServer::default(), src()),
        );
        let rules = rendered(&policy, &RenderInputs::new());
        assert!(find(&rules, Section::Network, Op::NetworkBind).is_empty());
        assert!(find(&rules, Section::Network, Op::NetworkInbound).is_empty());
    }

    #[test]
    fn the_ctl_socket_is_the_only_unix_socket_allowed() {
        let inputs = RenderInputs::new().with_ctl_socket(cp("/private/tmp/hb/ctl.sock"));
        let rules = rendered(&policy_with(vec![]), &inputs);
        assert_ok!(check(&rules));
        let allowed: Vec<&Rule> = rules
            .iter()
            .filter(|r| {
                is_allow(r)
                    && r.filters.iter().any(|f| {
                        matches!(
                            f,
                            Filter::RemoteUnixSocket(_) | Filter::RemoteUnixSocketLiteral(_)
                        )
                    })
            })
            .collect();
        assert_eq!(allowed.len(), 1);
        assert_eq!(filter_texts(allowed[0]), ["/private/tmp/hb/ctl.sock"]);
        // An allow names exactly one socket, never a directory of them.
        assert!(matches!(
            allowed[0].filters[0],
            Filter::RemoteUnixSocketLiteral(_)
        ));
    }

    #[test]
    fn floor_effects_map_to_their_operations_and_sections() {
        let floor = vec![
            frule(
                "a",
                FloorEffect::DenyReadWrite,
                Extent::Subtree,
                pattern("/Users/me/.ssh"),
            ),
            frule(
                "b",
                FloorEffect::DenyWrite,
                Extent::Subtree,
                pattern("/Users/me/.zshrc"),
            ),
            frule(
                "c",
                FloorEffect::DenyConnect,
                Extent::Subtree,
                pattern("/var/run/docker.sock"),
            ),
            frule(
                "d",
                FloorEffect::PinUnlink,
                Extent::Node,
                pattern("/Users/me/p/.git"),
            ),
        ];
        let rules = rendered(&policy_with(floor), &RenderInputs::new());
        assert_ok!(check(&rules));
        let in_floor = |op| find(&rules, Section::Floor, op);
        let rw = in_floor(Op::FileReadData);
        assert_eq!(rw.len(), 1);
        for op in Op::READ_SET {
            assert!(rw[0].ops.contains(&op));
        }
        assert!(rw[0].ops.contains(&Op::FileWriteAll) && !rw[0].ops.contains(&Op::FileReadAll));
        assert_eq!(filter_texts(rw[0]), ["/Users/me/.ssh"]);
        let write_only: Vec<_> = in_floor(Op::FileWriteAll)
            .into_iter()
            .filter(|r| !r.ops.contains(&Op::FileReadData))
            .collect();
        assert_eq!(filter_texts(write_only[0]), ["/Users/me/.zshrc"]);
        let connect = in_floor(Op::NetworkOutbound);
        assert!(matches!(connect[0].filters[0], Filter::RemoteUnixSocket(_)));
        let pin = find(&rules, Section::Pins, Op::FileWriteUnlink);
        assert!(matches!(pin[0].filters[0], Filter::Literal(_)));
        assert_eq!(filter_texts(pin[0]), ["/Users/me/p/.git"]);
    }

    #[test]
    fn extents_aliases_and_tails_pick_the_matcher() {
        let alias = PathPattern {
            base: cp("/Users/me/dotfiles/zshrc"),
            alias: Some(cp("/Users/me/.zshrc")),
            tail: None,
        };
        let tail = PathPattern {
            base: cp("/Users/me/p/.git"),
            alias: None,
            tail: Some(assert_ok!(GlobTail::parse(&["modules", "**", "hooks"]))),
        };
        let floor = vec![
            frule("alias", FloorEffect::DenyWrite, Extent::Subtree, alias),
            frule("tail", FloorEffect::DenyWrite, Extent::Subtree, tail),
            frule(
                "children",
                FloorEffect::DenyWrite,
                Extent::Children,
                pattern("/Users/me/bin"),
            ),
            frule(
                "node",
                FloorEffect::DenyWrite,
                Extent::Node,
                pattern("/Users/me/p/.git/x"),
            ),
            frule(
                "root-children",
                FloorEffect::DenyWrite,
                Extent::Children,
                pattern("/"),
            ),
        ];
        let rules = rendered(&policy_with(floor), &RenderInputs::new());
        assert_ok!(check(&rules));
        let floor_rules: Vec<&Rule> = rules
            .iter()
            .filter(|r| r.section == Section::Floor)
            .collect();
        let kinds: Vec<Vec<&str>> = floor_rules
            .iter()
            .map(|r| {
                r.filters
                    .iter()
                    .map(|f| match f {
                        Filter::Subpath(_) => "subpath",
                        Filter::Literal(_) => "literal",
                        Filter::Regex(_) => "regex",
                        _ => "other",
                    })
                    .collect()
            })
            .collect();
        // Sorted by the first parameter value: `/Users/me/bin` regex, `.../.git/x` node, ...
        assert!(
            kinds.contains(&vec!["subpath", "literal"]),
            "alias: {kinds:?}"
        );
        assert_eq!(
            kinds.iter().filter(|k| **k == vec!["regex"]).count(),
            3,
            "{kinds:?}"
        );
        assert_eq!(
            kinds.iter().filter(|k| **k == vec!["literal"]).count(),
            1,
            "{kinds:?}"
        );
        let regexes: Vec<String> = rules
            .iter()
            .flat_map(filter_texts)
            .filter(|t| t.starts_with('^'))
            .collect();
        assert!(regexes.contains(&"^/Users/me/bin/[^/]+$".to_owned()));
        assert!(regexes.contains(&"^/[^/]+$".to_owned()));
        assert!(regexes.contains(&"^/Users/me/p/\\.git/modules(/[^/]+)*/hooks(/.*)?$".to_owned()));
    }

    #[test]
    fn policy_denies_come_before_the_floor_and_a_read_deny_also_denies_writing() {
        let mut policy = policy_with(vec![frule(
            "ssh",
            FloorEffect::DenyReadWrite,
            Extent::Subtree,
            pattern("/Users/me/.ssh"),
        )]);
        policy.fs.deny_read = vec![Sourced::new(pattern("/Users/me/proj/secrets"), src())];
        policy.fs.deny_write = vec![Sourced::new(pattern("/Users/me/proj/frozen"), src())];
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        let sections: Vec<Section> = rules.iter().map(|r| r.section).collect();
        let policy_at = assert_some!(sections.iter().position(|s| *s == Section::PolicyDeny));
        let floor_at = assert_some!(sections.iter().position(|s| *s == Section::Floor));
        assert!(policy_at < floor_at);
        let deny_read = find(&rules, Section::PolicyDeny, Op::FileReadData);
        assert!(deny_read[0].ops.contains(&Op::FileWriteAll));
        let deny_write: Vec<_> = find(&rules, Section::PolicyDeny, Op::FileWriteAll)
            .into_iter()
            .filter(|r| !r.ops.contains(&Op::FileReadData))
            .collect();
        assert_eq!(filter_texts(deny_write[0]), ["/Users/me/proj/frozen"]);
    }

    fn pin_paths(rules: &[Rule]) -> Vec<String> {
        rules
            .iter()
            .filter(|r| r.section == Section::Pins)
            .flat_map(filter_texts)
            .collect()
    }

    #[test]
    fn user_denies_are_pinned_so_renaming_a_parent_cannot_move_them_aside() {
        let mut policy = policy_with(vec![]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/p"), src())];
        policy.fs.deny_read = vec![Sourced::new(
            PathPattern {
                tail: Some(assert_ok!(GlobTail::parse(&["*.yaml"]))),
                ..pattern("/Users/me/p/secrets")
            },
            src(),
        )];
        policy.fs.deny_write = vec![Sourced::new(pattern("/Users/me/p/vend/secret.txt"), src())];
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        assert_eq!(
            pin_paths(&rules),
            ["/Users/me/p", "/Users/me/p/secrets", "/Users/me/p/vend"]
        );
    }

    #[test]
    fn a_user_deny_outside_every_write_grant_needs_no_pin_and_a_subtree_deny_does_not_pin_itself() {
        let mut policy = policy_with(vec![]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/p"), src())];
        policy.fs.deny_read = vec![
            Sourced::new(pattern("/Users/me/elsewhere/x"), src()),
            Sourced::new(pattern("/Users/me/p/secrets"), src()),
        ];
        let rules = rendered(&policy, &RenderInputs::new());
        assert_eq!(pin_paths(&rules), ["/Users/me/p"]);
    }

    #[test]
    fn a_floor_pin_and_a_user_pin_for_the_same_directory_are_emitted_once() {
        let mut policy = policy_with(vec![frule(
            "pin",
            FloorEffect::PinUnlink,
            Extent::Node,
            pattern("/Users/me/p"),
        )]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/p"), src())];
        policy.fs.deny_write = vec![Sourced::new(pattern("/Users/me/p/vend"), src())];
        let rules = rendered(&policy, &RenderInputs::new());
        assert_eq!(pin_paths(&rules), ["/Users/me/p"]);
    }

    fn mount_pin_rules(rules: &[Rule], op: Op) -> Vec<String> {
        let mut paths: Vec<String> = rules
            .iter()
            .filter(|r| r.section == Section::Pins && r.ops == [op])
            .flat_map(filter_texts)
            .collect();
        paths.sort();
        paths
    }

    #[test]
    fn mount_sources_and_the_ancestors_a_write_grant_reaches_get_unlink_and_link_denies() {
        let mut policy = policy_with(vec![]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/p"), src())];
        let inputs = RenderInputs::new().with_mount_pins(vec![
            cp("/Users/me/p/var/data"),
            cp("/Users/me/p/cfg/app.yaml"),
        ]);
        let rules = rendered(&policy, &inputs);
        assert_ok!(check(&rules));
        let expected = [
            "/Users/me/p",
            "/Users/me/p/cfg",
            "/Users/me/p/cfg/app.yaml",
            "/Users/me/p/var",
            "/Users/me/p/var/data",
        ];
        assert_eq!(mount_pin_rules(&rules, Op::FileWriteUnlink), expected);
        // The link deny is for the sources themselves; ancestors may gain a hard link.
        assert_eq!(
            mount_pin_rules(&rules, Op::FileLink),
            ["/Users/me/p/cfg/app.yaml", "/Users/me/p/var/data"]
        );
    }

    #[test]
    fn a_write_grant_above_the_project_pulls_the_pins_up_to_it_and_never_past_it() {
        let mut policy = policy_with(vec![]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/work"), src())];
        let inputs = RenderInputs::new().with_mount_pins(vec![cp("/Users/me/work/p/data")]);
        let pins = mount_pin_rules(&rendered(&policy, &inputs), Op::FileWriteUnlink);
        assert_eq!(
            pins,
            [
                "/Users/me/work",
                "/Users/me/work/p",
                "/Users/me/work/p/data"
            ]
        );
    }

    #[test]
    fn a_source_outside_every_write_grant_is_pinned_itself_but_no_ancestor_is() {
        let mut policy = policy_with(vec![]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/other"), src())];
        let inputs = RenderInputs::new().with_mount_pins(vec![cp("/Users/me/p/data")]);
        let rules = rendered(&policy, &inputs);
        assert_eq!(
            mount_pin_rules(&rules, Op::FileWriteUnlink),
            ["/Users/me/p/data"]
        );
    }

    #[test]
    fn mount_pins_are_unique_deny_only_and_come_after_every_allow() {
        let mut policy = policy_with(vec![]);
        policy.fs.write = vec![Sourced::new(cp("/Users/me/p"), src())];
        let inputs = RenderInputs::new()
            .with_mount_pins(vec![cp("/Users/me/p/data"), cp("/Users/me/p/data")]);
        let rules = rendered(&policy, &inputs);
        assert_ok!(check(&rules));
        assert_eq!(
            mount_pin_rules(&rules, Op::FileWriteUnlink),
            ["/Users/me/p", "/Users/me/p/data"]
        );
        assert!(
            rules
                .iter()
                .filter(|r| r.ops.contains(&Op::FileLink))
                .all(|r| r.action == Action::Deny && r.section == Section::Pins)
        );
        assert!(
            rendered(&policy, &RenderInputs::new())
                .iter()
                .all(|r| !r.ops.contains(&Op::FileLink))
        );
    }

    fn guarded_policy(roots: &[&str]) -> Policy {
        let mut policy = policy_with(vec![]);
        policy.fs.write = roots.iter().map(|r| Sourced::new(cp(r), src())).collect();
        policy
    }

    fn section_rules(rules: &[Rule], section: Section) -> Vec<&Rule> {
        rules.iter().filter(|r| r.section == section).collect()
    }

    #[test]
    fn every_write_root_gets_a_guard_deny_that_names_content_and_writes_but_not_metadata() {
        let policy = guarded_policy(&["/Users/me/a", "/Users/me/b"]);
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        let guard = section_rules(&rules, Section::Guard);
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].action, Action::Deny);
        assert_eq!(
            guard[0].ops,
            [Op::FileReadData, Op::FileReadXattr, Op::FileWriteAll]
        );
        assert_eq!(
            filter_texts(guard[0]),
            [
                crate::guard::patterns::deny_regex("/Users/me/a"),
                crate::guard::patterns::deny_regex("/Users/me/b")
            ]
        );
    }

    #[test]
    fn a_read_only_grant_is_not_guarded() {
        let mut policy = guarded_policy(&["/Users/me/a"]);
        policy.fs.read = vec![Sourced::new(cp("/opt/homebrew"), src())];
        let rules = rendered(&policy, &RenderInputs::new());
        let guard = section_rules(&rules, Section::Guard);
        assert_eq!(
            filter_texts(guard[0]),
            [crate::guard::patterns::deny_regex("/Users/me/a")]
        );
    }

    #[test]
    fn with_no_write_grant_there_is_no_guard() {
        let rules = rendered(&policy_with(vec![]), &RenderInputs::new());
        assert!(section_rules(&rules, Section::Guard).is_empty());
        assert!(section_rules(&rules, Section::TemplateAllow).is_empty());
    }

    #[test]
    fn templates_are_reallowed_inside_each_root_only_and_after_the_guard() {
        let policy = guarded_policy(&["/Users/me/a"]);
        let rules = rendered(&policy, &RenderInputs::new());
        let template = section_rules(&rules, Section::TemplateAllow);
        assert_eq!(template.len(), 1);
        assert_eq!(template[0].action, Action::Allow);
        assert_eq!(
            template[0].ops,
            [Op::FileReadData, Op::FileReadXattr, Op::FileWriteAll]
        );
        assert_eq!(
            filter_texts(template[0]),
            [crate::guard::patterns::template_regex("/Users/me/a")]
        );
        let guard_at = assert_some!(rules.iter().position(|r| r.section == Section::Guard));
        let template_at = assert_some!(
            rules
                .iter()
                .position(|r| r.section == Section::TemplateAllow)
        );
        assert!(guard_at < template_at);
    }

    #[test]
    fn the_dependency_exemption_is_emitted_only_when_asked_for() {
        let policy = guarded_policy(&["/Users/me/a"]);
        let without = rendered(&policy, &RenderInputs::new());
        assert_eq!(section_rules(&without, Section::TemplateAllow).len(), 1);
        let inputs = RenderInputs::new().with_guard(crate::guard::GuardInputs {
            pins: Vec::new(),
            dependency_exemption: true,
        });
        let with = rendered(&policy, &inputs);
        assert_ok!(check(&with));
        let texts: Vec<String> = section_rules(&with, Section::TemplateAllow)
            .iter()
            .flat_map(|r| filter_texts(r))
            .collect();
        assert!(
            texts.contains(&crate::guard::patterns::dependency_regex("/Users/me/a")),
            "{texts:?}"
        );
    }

    #[test]
    fn guard_pins_are_unlink_pins_and_sorted_with_the_others() {
        let policy = guarded_policy(&["/Users/me/a"]);
        let inputs = RenderInputs::new().with_guard(crate::guard::GuardInputs {
            pins: vec![cp("/Users/me/a/certs"), cp("/Users/me/a")],
            dependency_exemption: true,
        });
        let rules = rendered(&policy, &inputs);
        assert_ok!(check(&rules));
        assert_eq!(pin_paths(&rules), ["/Users/me/a", "/Users/me/a/certs"]);
    }

    #[test]
    fn a_policy_exception_is_reallowed_as_a_literal_or_a_regex_inside_the_template_section() {
        let mut policy = guarded_policy(&["/Users/me/a"]);
        policy.guard_exceptions = vec![
            Sourced::new(pattern("/Users/me/a/.env.active"), src()),
            Sourced::new(
                PathPattern {
                    base: cp("/Users/me/a/config"),
                    alias: None,
                    tail: Some(assert_ok!(GlobTail::parse(&["*.secrets.yaml"]))),
                },
                src(),
            ),
        ];
        let rules = rendered(&policy, &RenderInputs::new());
        assert_ok!(check(&rules));
        let template = section_rules(&rules, Section::TemplateAllow);
        let texts: Vec<String> = template.iter().flat_map(|r| filter_texts(r)).collect();
        assert!(
            texts.contains(&"/Users/me/a/.env.active".to_owned()),
            "{texts:?}"
        );
        assert!(
            texts
                .iter()
                .any(|t| t.starts_with("^/Users/me/a/config/") && t.contains("secrets")),
            "{texts:?}"
        );
    }

    #[test]
    fn the_guard_reallow_sits_after_the_guard_section_and_before_every_deny() {
        let inputs = RenderInputs::new().with_guard_allow(vec![cp("/Users/me/proj/.env.example")]);
        let policy = policy_with(vec![frule(
            "x",
            FloorEffect::DenyWrite,
            Extent::Subtree,
            pattern("/Users/me/.zshrc"),
        )]);
        let rules = rendered(&policy, &inputs);
        assert_ok!(check(&rules));
        let last_allow = assert_some!(rules.iter().rposition(is_allow));
        let first_deny = assert_some!(rules.iter().position(|r| r.action == Action::Deny));
        assert!(last_allow < first_deny);
        assert_eq!(rules[last_allow].section, Section::TemplateAllow);
        // The same operations a guard deny names (design 8), so the re-allow can reopen them:
        // a wildcard `file-read*` allow would not override a specific-operation deny.
        assert_eq!(
            rules[last_allow].ops,
            [Op::FileReadData, Op::FileReadXattr, Op::FileWriteAll]
        );
    }

    #[test]
    fn floor_denies_are_unique_and_sorted_so_the_input_order_does_not_matter() {
        let a = frule(
            "a",
            FloorEffect::DenyWrite,
            Extent::Subtree,
            pattern("/Users/me/a"),
        );
        let b = frule(
            "b",
            FloorEffect::DenyWrite,
            Extent::Subtree,
            pattern("/Users/me/b"),
        );
        let forward = rendered(
            &policy_with(vec![a.clone(), b.clone(), a.clone()]),
            &RenderInputs::new(),
        );
        let backward = rendered(&policy_with(vec![b, a]), &RenderInputs::new());
        assert_eq!(forward, backward);
    }

    #[test]
    fn a_kept_filter_can_drop_floor_rules() {
        let floor = vec![
            frule(
                "pin",
                FloorEffect::PinUnlink,
                Extent::Node,
                pattern("/Users/me/p"),
            ),
            frule(
                "w",
                FloorEffect::DenyWrite,
                Extent::Subtree,
                pattern("/Users/me/w"),
            ),
        ];
        let policy = policy_with(floor);
        let no_pins = plan(&policy, &RenderInputs::new(), &|r: &FloorRule| {
            r.effect != FloorEffect::PinUnlink
        });
        assert!(no_pins.iter().all(|r| r.section != Section::Pins));
        assert_eq!(find(&no_pins, Section::Floor, Op::FileWriteAll).len(), 1);
    }

    #[test]
    fn weight_counts_filters_and_at_least_one_per_rule() {
        let rules = [
            Rule::allow(Section::Process, &[Op::ProcessExec], vec![]),
            Rule::allow(
                Section::Grants,
                &[Op::FileReadAll],
                vec![Filter::StaticSubpath("/a"), Filter::StaticSubpath("/b")],
            ),
        ];
        assert_eq!(weight(&rules), 3);
    }
}
