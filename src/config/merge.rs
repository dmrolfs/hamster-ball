// ABOUTME: Merges the closure's files into one Policy: add-only unions, keyed equal-or-error, scalar lattice.
// ABOUTME: Pure and order-insensitive for values; every deny from every file is kept; every value keeps all its sources.
//! Merging the closure into one policy.
//!
//! The merge is a join: lists union, keyed maps must agree, and the few scalars combine toward
//! the stricter value. There is no syntax to remove or narrow anything a lower layer added, so
//! precedence only affects the order sources are listed in, never what is allowed. Every deny
//! from every file is kept; an allow never cancels one. Each merged value keeps every place it
//! was declared (a [`Sourced`]), so `hb explain` can show them and the approval summary can
//! tell a genuine addition from a restatement of the base.
//!
//! Whether a path is finally denied is decided by Seatbelt rule order (M2.1); the advisory
//! query for tests and `explain` is [`Policy::decide`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use snafu::Snafu;

use super::closure::ClosureFile;
use super::location::FileLocation;
use super::resolve::{ResolvedConfig, ResolvedMcpServer};
use crate::origin::{KeyPath, Layer, Origin, Source, Sourced};
use crate::policy::{
    BindPort, CanonicalPath, ContainerLabel, ContainerName, EnvName, EnvValue, Floor, Hook,
    HookName, HostPattern, HostRule, McpName, PathPattern, Port, ToolName,
};
use crate::sys::path_preview;

/// Most merge errors collected before the rest are summarized as truncated.
pub const MAX_MERGE_ERRORS: usize = 64;

/// The most distinct ports all MCP servers together may listen on.
///
/// Every server shares one profile, so each port is a LAN-visible listener the agent may open
/// (design 7.1, D58). A real server needs one or two.
pub const MAX_BIND_PORTS_TOTAL: usize = 64;

/// The merged `[fs]` rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergedFs {
    /// Read-only grants.
    pub read: Vec<Sourced<CanonicalPath>>,
    /// Write grants.
    pub write: Vec<Sourced<CanonicalPath>>,
    /// Read-deny patterns. A read-deny also denies writes.
    pub deny_read: Vec<Sourced<PathPattern>>,
    /// Write-deny patterns.
    pub deny_write: Vec<Sourced<PathPattern>>,
}

/// The merged `[net]` rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergedNet {
    /// Allowed hosts, each with the one port it allows.
    pub allow: Vec<Sourced<HostRule>>,
    /// Hosts that may resolve to private, unique-local and tunnel addresses (design 12.1).
    pub internal_hosts: Vec<Sourced<HostPattern>>,
    /// Reachable loopback ports.
    pub loopback_ports: Vec<Sourced<Port>>,
}

/// The merged `[env]` rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergedEnv {
    /// Variables copied from the invoking shell.
    pub pass: Vec<Sourced<EnvName>>,
    /// Variables set to a fixed value, in sorted name order.
    pub set: BTreeMap<EnvName, Sourced<EnvValue>>,
    /// Programs to find on the child's `PATH`, sorted by name so the result does not depend on
    /// the order of the files.
    pub tools: Vec<Sourced<ToolName>>,
}

/// The merged `[tls]` rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergedTls {
    /// `Some(false)` if any file says `false` (the stricter value), else `Some(true)` if any
    /// says `true`, else `None`. The sources are the files that gave the winning value.
    pub system_trust: Option<Sourced<bool>>,
    /// Extra CA bundle files.
    pub extra_ca_files: Vec<Sourced<CanonicalPath>>,
}

impl MergedTls {
    /// Whether the system trust store is reachable: the merged value, or `false` if no file
    /// set it. The stricter default is deliberate (decision D35); the base template written by
    /// `hb init` sets `true`.
    #[must_use]
    pub fn effective_system_trust(&self) -> bool {
        self.system_trust.as_ref().is_some_and(|trust| trust.value)
    }
}

/// The merged `[terminal]` rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergedTerminal {
    /// `Some(false)` if any file says `false` (the stricter value), else `Some(true)` if any
    /// says `true`, else `None`. The sources are the files that gave the winning value.
    pub clipboard_write: Option<Sourced<bool>>,
}

impl MergedTerminal {
    /// Whether the agent may set the user's clipboard: unless some file says `false`. The
    /// default is to allow, because under `hb` the terminal's `OSC 52` is the agent's only clipboard path.
    #[must_use]
    pub fn effective_clipboard_write(&self) -> bool {
        self.clipboard_write
            .as_ref()
            .is_none_or(|setting| setting.value)
    }
}

/// The merged `[system]` rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergedSystem {
    /// `Some(false)` if any file says `false` (the stricter value), else `Some(true)` if any
    /// says `true`, else `None`. Only the user's own files can say `true`.
    pub launchctl: Option<Sourced<bool>>,
}

impl MergedSystem {
    /// Whether the agent may run `launchctl`: only if a user-owned file says so and no file
    /// refuses. The default is no, because `launchctl` lets the agent start, unload and disable
    /// the user's launchd jobs (design 4.6).
    #[must_use]
    pub fn effective_launchctl(&self) -> bool {
        self.launchctl.as_ref().is_some_and(|setting| setting.value)
    }
}

/// The merged `[ctl]` rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct MergedCtl {
    /// The container label selector; every file that sets one must agree.
    pub label: Option<Sourced<ContainerLabel>>,
    /// Container names `hb ctl` may operate on.
    pub containers: Vec<Sourced<ContainerName>>,
}

/// The merged policy of a whole closure, and the floor it can never loosen.
///
/// There is no `Default`: a policy without a [`Floor`] is not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Policy {
    /// `[fs]`.
    pub fs: MergedFs,
    /// `[net]`.
    pub net: MergedNet,
    /// `[env]`.
    pub env: MergedEnv,
    /// `[tls]`.
    pub tls: MergedTls,
    /// `[terminal]`.
    pub terminal: MergedTerminal,
    /// `[ctl]`.
    pub ctl: MergedCtl,
    /// `[system]`.
    pub system: MergedSystem,
    /// `[mcp.<name>]`, in sorted name order; every file naming a server must agree on it.
    pub mcp: BTreeMap<McpName, Sourced<ResolvedMcpServer>>,
    /// `[hooks.pre_run.<name>]`, in name order; every file naming a hook must agree on it.
    pub hooks: BTreeMap<HookName, Sourced<Hook>>,
    /// Secrets-guard exceptions.
    pub guard_exceptions: Vec<Sourced<PathPattern>>,
    /// The floor: no layer can narrow it, and it is the same one `merge` was given.
    floor: Floor,
}

impl Policy {
    /// The floor this policy was built on.
    #[must_use]
    pub fn floor(&self) -> &Floor {
        &self.floor
    }
}

/// Why a closure could not be merged.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum MergeError {
    /// Two files define the same keyed value differently.
    ///
    /// The values are not echoed: an environment value can be a secret.
    #[snafu(display(
        "`{key}` is defined differently in {} and {}; a project can add, but cannot change what a lower layer set",
        path_preview(&first.file),
        path_preview(&second.file)
    ))]
    Conflict {
        /// The key.
        key: KeyPath,
        /// The first definition, in closure order.
        first: Origin,
        /// The conflicting definition.
        second: Origin,
    },

    /// A file that may not define a user-only section does.
    #[snafu(display(
        "`{section}` is only allowed in your own files and built-in presets, but {} ({location}) defines it",
        path_preview(&origin.file)
    ))]
    UserOnlySection {
        /// The file.
        origin: Origin,
        /// The section: `hooks`, `guard.exceptions`, `system.launchctl = true` or
        /// `net.internal_hosts`.
        section: &'static str,
        /// Where the file is.
        location: FileLocation,
    },

    /// The MCP servers together may listen on more ports than the profile allows.
    #[snafu(display(
        "the MCP servers bind {count} distinct ports in total, more than the {max} allowed; remove `bind_ports` entries"
    ))]
    TooManyBindPorts {
        /// The distinct ports across every server.
        count: usize,
        /// The limit, `MAX_BIND_PORTS_TOTAL`.
        max: usize,
    },
}

/// The merge errors found, in closure order, capped at [`MAX_MERGE_ERRORS`].
#[derive(Debug)]
#[non_exhaustive]
pub struct MergeErrors {
    /// The errors.
    pub errors: Vec<MergeError>,
    /// Whether more existed beyond the cap.
    pub truncated: bool,
}

impl fmt::Display for MergeErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} merge error(s)", self.errors.len())?;
        if self.truncated {
            write!(f, " (more exist past the first {MAX_MERGE_ERRORS})")?;
        }
        Ok(())
    }
}

impl std::error::Error for MergeErrors {}

#[derive(Default)]
struct Collected {
    errors: Vec<MergeError>,
    truncated: bool,
}

impl Collected {
    fn push(&mut self, error: MergeError) {
        if self.errors.len() >= MAX_MERGE_ERRORS {
            self.truncated = true;
        } else {
            self.errors.push(error);
        }
    }
}

/// Merges `files`, which must be in closure order, into one policy on top of `floor`.
///
/// The floor is stored as given. No file can add to, remove from or narrow it.
///
/// # Errors
/// [`MergeErrors`] if a keyed value conflicts or a file defines a user-only section it may not.
pub fn merge(files: &[ClosureFile], floor: Floor) -> Result<Policy, MergeErrors> {
    let mut collected = Collected::default();
    reassert_user_only(files, &mut collected);

    let policy = Policy {
        fs: MergedFs {
            read: union(files, |c| indexed(&c.fs.read)),
            write: union(files, |c| indexed(&c.fs.write)),
            deny_read: union(files, |c| positions(&c.fs.deny_read)),
            deny_write: union(files, |c| positions(&c.fs.deny_write)),
        },
        net: MergedNet {
            allow: union(files, |c| positions(&c.net.allow)),
            internal_hosts: union(files, |c| positions(&c.net.internal_hosts)),
            loopback_ports: union(files, |c| positions(&c.net.loopback_ports)),
        },
        env: MergedEnv {
            pass: union(files, |c| positions(&c.env.pass)),
            tools: union(files, |c| positions(&c.env.tools)),
            set: keyed(
                files,
                &mut collected,
                |c| {
                    c.env
                        .set
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                },
                |name| KeyPath::root().field("env").field("set").key(name.as_str()),
            ),
        },
        tls: MergedTls {
            system_trust: system_trust(files),
            extra_ca_files: union(files, |c| positions(&c.tls.extra_ca_files)),
        },
        terminal: MergedTerminal {
            clipboard_write: stricter_flag(files, |c| c.terminal.clipboard_write),
        },
        system: MergedSystem {
            launchctl: stricter_flag(files, |c| c.system.launchctl),
        },
        ctl: MergedCtl {
            label: label(files, &mut collected),
            containers: union(files, |c| positions(&c.ctl.containers)),
        },
        mcp: keyed(
            files,
            &mut collected,
            |c| c.mcp.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
            |name| KeyPath::root().field("mcp").key(name.as_str()),
        ),
        hooks: keyed(
            files,
            &mut collected,
            |c| {
                c.hooks
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect()
            },
            |name| {
                KeyPath::root()
                    .field("hooks")
                    .field("pre_run")
                    .key(name.as_str())
            },
        ),
        guard_exceptions: union(files, |c| positions(&c.guard.exceptions)),
        floor,
    };
    check_bind_port_total(&policy, &mut collected);
    if collected.errors.is_empty() {
        Ok(policy)
    } else {
        Err(MergeErrors {
            errors: collected.errors,
            truncated: collected.truncated,
        })
    }
}

/// Records [`MergeError::TooManyBindPorts`] if the servers together bind too many distinct ports.
fn check_bind_port_total(policy: &Policy, collected: &mut Collected) {
    let distinct: BTreeSet<BindPort> = policy
        .mcp
        .values()
        .flat_map(|server| server.value.bind_ports.iter().copied())
        .collect();
    if distinct.len() > MAX_BIND_PORTS_TOTAL {
        collected.push(MergeError::TooManyBindPorts {
            count: distinct.len(),
            max: MAX_BIND_PORTS_TOTAL,
        });
    }
}

fn index_of(position: usize) -> u32 {
    u32::try_from(position).unwrap_or(u32::MAX)
}

/// Entries of a plain list, each at its position.
fn positions<T: Clone>(items: &[T]) -> Vec<(T, u32)> {
    items
        .iter()
        .enumerate()
        .map(|(position, item)| (item.clone(), index_of(position)))
        .collect()
}

/// Entries that remember their own file index.
fn indexed(items: &[super::resolve::Indexed<CanonicalPath>]) -> Vec<(CanonicalPath, u32)> {
    items
        .iter()
        .map(|entry| (entry.value.clone(), entry.index))
        .collect()
}

/// Unions a list field over all files: equal values collapse and keep every source; the
/// result is sorted by value, which also makes it independent of file order.
fn union<T: Ord>(
    files: &[ClosureFile],
    pick: impl Fn(&super::resolve::ResolvedConfig) -> Vec<(T, u32)>,
) -> Vec<Sourced<T>> {
    let mut grouped: BTreeMap<T, Vec<Source>> = BTreeMap::new();
    for file in files {
        for (value, index) in pick(&file.resolved) {
            grouped
                .entry(value)
                .or_default()
                .push(Source::entry(file.id, index));
        }
    }
    grouped
        .into_iter()
        .filter_map(|(value, sources)| Sourced::from_sources(value, sources))
        .collect()
}

/// Merges a keyed map: equal values from several files combine; a different value for a key
/// that is already set is a conflict naming both files.
fn keyed<K: Ord + Clone, V: PartialEq + Clone>(
    files: &[ClosureFile],
    collected: &mut Collected,
    pick: impl Fn(&super::resolve::ResolvedConfig) -> Vec<(K, V)>,
    key_path: impl Fn(&K) -> KeyPath,
) -> BTreeMap<K, Sourced<V>> {
    let mut merged: BTreeMap<K, (Sourced<V>, usize)> = BTreeMap::new();
    for (position, file) in files.iter().enumerate() {
        for (key, value) in pick(&file.resolved) {
            match merged.get_mut(&key) {
                None => {
                    merged.insert(key, (Sourced::new(value, Source::value(file.id)), position));
                }
                Some((existing, _)) if existing.value == value => {
                    existing.sources.push(Source::value(file.id));
                }
                Some((_, first_position)) => {
                    let path = key_path(&key);
                    collected.push(MergeError::Conflict {
                        key: path.clone(),
                        first: files[*first_position].origin(path.clone()),
                        second: file.origin(path),
                    });
                }
            }
        }
    }
    merged
        .into_iter()
        .map(|(key, (sourced, _))| (key, sourced))
        .collect()
}

/// `false` beats `true`: any file that says `false` wins, so a file can only tighten a setting.
fn stricter_flag(
    files: &[ClosureFile],
    get: impl Fn(&ResolvedConfig) -> Option<bool>,
) -> Option<Sourced<bool>> {
    let sources_saying = |wanted: bool| -> Vec<Source> {
        files
            .iter()
            .filter(|file| get(&file.resolved) == Some(wanted))
            .map(|file| Source::value(file.id))
            .collect()
    };
    Sourced::from_sources(false, sources_saying(false))
        .or_else(|| Sourced::from_sources(true, sources_saying(true)))
}

/// `tls.system_trust`: any file that distrusts the system store wins.
fn system_trust(files: &[ClosureFile]) -> Option<Sourced<bool>> {
    stricter_flag(files, |c| c.tls.system_trust)
}

/// Every file that sets a label must set the same one.
fn label(files: &[ClosureFile], collected: &mut Collected) -> Option<Sourced<ContainerLabel>> {
    let mut found: Option<(Sourced<ContainerLabel>, usize)> = None;
    for (position, file) in files.iter().enumerate() {
        let Some(value) = &file.resolved.ctl.label else {
            continue;
        };
        match &mut found {
            None => {
                found = Some((
                    Sourced::new(value.clone(), Source::value(file.id)),
                    position,
                ))
            }
            Some((existing, _)) if &existing.value == value => {
                existing.sources.push(Source::value(file.id));
            }
            Some((_, first_position)) => {
                let key = KeyPath::root().field("ctl").field("label");
                collected.push(MergeError::Conflict {
                    key: key.clone(),
                    first: files[*first_position].origin(key.clone()),
                    second: file.origin(key),
                });
            }
        }
    }
    found.map(|(sourced, _)| sourced)
}

/// Defence in depth: the loader refuses these before resolving, but merge must hold the
/// invariant on its own, so a caller that builds a closure by hand cannot smuggle hooks in.
fn reassert_user_only(files: &[ClosureFile], collected: &mut Collected) {
    for file in files {
        let eligible =
            file.location.may_define_user_only_sections() && file.layer != Layer::Project;
        if eligible {
            continue;
        }
        for (section, present) in [
            ("hooks", !file.resolved.hooks.is_empty()),
            (
                "system.launchctl = true",
                file.resolved.system.launchctl == Some(true),
            ),
            (
                "net.internal_hosts",
                !file.resolved.net.internal_hosts.is_empty(),
            ),
            (
                "guard.exceptions",
                !file.resolved.guard.exceptions.is_empty(),
            ),
        ] {
            if present {
                collected.push(MergeError::UserOnlySection {
                    origin: file.origin(KeyPath::root().field(section)),
                    section,
                    location: file.location,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ClosureFile, FileLocation, FileSource};
    use crate::config::{ConfigText, Diagnostics};
    use crate::config::{Indexed, ResolvedConfig, ResolvedMcpServer};
    use crate::origin::{FileId, Layer, Source};
    use crate::policy::{
        ArgWord, Argv, BindPort, CanonicalPath, ContainerLabel, ContainerName, EnvName, EnvValue,
        GlobTail, HostPattern, McpName, PathPattern, Port, PresetName,
    };
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    fn cpath(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    fn host(h: &str) -> HostRule {
        assert_ok!(HostRule::parse(h))
    }

    fn argv(words: &[&str]) -> Argv {
        let owned: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
        assert_ok!(Argv::parse(&owned))
    }

    fn deny(base: &str) -> PathPattern {
        PathPattern {
            base: cpath(base),
            alias: None,
            tail: None,
        }
    }

    /// A closure file named `name` (its origin path is `builtin:<name>`).
    fn file(
        name: &str,
        layer: Layer,
        location: FileLocation,
        config: ResolvedConfig,
    ) -> ClosureFile {
        ClosureFile {
            id: FileId::new(0),
            source: FileSource::Builtin {
                name: assert_ok!(PresetName::parse(name)),
            },
            layer,
            location,
            from_base: false,
            text: ConfigText::builtin(name, ""),
            resolved: config,
            diagnostics: Diagnostics::default(),
        }
    }

    /// Numbers the files by position, as the loader does.
    fn closure(mut files: Vec<ClosureFile>) -> Vec<ClosureFile> {
        for (index, f) in files.iter_mut().enumerate() {
            f.id = FileId::new(u16::try_from(index).unwrap_or(0));
        }
        files
    }

    fn user(name: &str, config: ResolvedConfig) -> ClosureFile {
        file(name, Layer::Preset, FileLocation::UserConfig, config)
    }

    fn project(config: ResolvedConfig) -> ClosureFile {
        file("project", Layer::Project, FileLocation::InProject, config)
    }

    fn merged(files: Vec<ClosureFile>) -> Policy {
        assert_ok!(merge(&closure(files), Floor::empty()))
    }

    fn values<T: Clone>(items: &[Sourced<T>]) -> Vec<T> {
        items.iter().map(|s| s.value.clone()).collect()
    }

    fn with_net(hosts: &[&str]) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.net.allow = hosts.iter().map(|h| host(h)).collect();
        config
    }

    // ====================================================================================
    // Lists union, keep every source, and are value-sorted
    // ====================================================================================

    #[test]
    fn lists_from_every_file_are_unioned_and_sorted_by_value() {
        let policy = merged(vec![
            user("base", with_net(&["zeta.example.com", "alpha.example.com"])),
            project(with_net(&["mid.example.com"])),
        ]);
        assert_eq!(
            values(&policy.net.allow),
            vec![
                host("alpha.example.com"),
                host("mid.example.com"),
                host("zeta.example.com")
            ]
        );
    }

    #[test]
    fn an_equal_value_in_two_files_is_one_entry_that_keeps_both_sources() {
        let policy = merged(vec![
            user("base", with_net(&["crates.io"])),
            project(with_net(&["crates.io", "extra.example.com"])),
        ]);
        let crates = assert_some!(
            policy
                .net
                .allow
                .iter()
                .find(|s| s.value == host("crates.io"))
        );
        assert_eq!(
            crates.sources,
            vec![
                Source::entry(FileId::new(0), 0),
                Source::entry(FileId::new(1), 0)
            ]
        );
        let extra = assert_some!(
            policy
                .net
                .allow
                .iter()
                .find(|s| s.value == host("extra.example.com"))
        );
        assert_eq!(extra.sources, vec![Source::entry(FileId::new(1), 1)]);
    }

    #[test]
    fn a_value_listed_twice_in_one_file_keeps_both_indexes() {
        let policy = merged(vec![project(with_net(&["a.example.com", "a.example.com"]))]);
        assert_eq!(policy.net.allow.len(), 1);
        assert_eq!(policy.net.allow[0].sources.len(), 2);
    }

    #[test]
    fn fs_grants_keep_their_original_file_index_after_skips() {
        let mut config = ResolvedConfig::default();
        config.fs.read = vec![
            Indexed {
                value: cpath("/p/a"),
                index: 1,
            },
            Indexed {
                value: cpath("/p/b"),
                index: 3,
            },
        ];
        let policy = merged(vec![project(config)]);
        assert_eq!(
            policy.fs.read[0].sources,
            vec![Source::entry(FileId::new(0), 1)]
        );
        assert_eq!(
            policy.fs.read[1].sources,
            vec![Source::entry(FileId::new(0), 3)]
        );
    }

    #[test]
    fn every_list_section_is_merged() {
        let mut a = ResolvedConfig::default();
        a.fs.write = vec![Indexed {
            value: cpath("/p/w"),
            index: 0,
        }];
        a.fs.deny_read = vec![deny("/p/r")];
        a.fs.deny_write = vec![deny("/p/w2")];
        a.net.loopback_ports = vec![assert_ok!(Port::try_from(3030))];
        a.env.pass = vec![assert_ok!(EnvName::parse("TERM"))];
        a.env.tools = vec![assert_ok!(ToolName::parse("node"))];
        a.tls.extra_ca_files = vec![cpath("/p/ca.pem")];
        a.ctl.containers = vec![assert_ok!(ContainerName::parse("pg"))];
        a.guard.exceptions = vec![deny("/p/.env.example")];
        let policy = merged(vec![user("base", a)]);
        assert_eq!(policy.fs.write.len(), 1);
        assert_eq!(policy.fs.deny_read.len(), 1);
        assert_eq!(policy.fs.deny_write.len(), 1);
        assert_eq!(policy.net.loopback_ports.len(), 1);
        assert_eq!(policy.env.pass.len(), 1);
        assert_eq!(policy.env.tools.len(), 1);
        assert_eq!(policy.tls.extra_ca_files.len(), 1);
        assert_eq!(policy.ctl.containers.len(), 1);
        assert_eq!(policy.guard_exceptions.len(), 1);
    }

    #[test]
    fn a_tool_named_in_two_files_is_one_entry_with_both_sources_in_closure_order() {
        let tools = |names: &[&str]| {
            let mut config = ResolvedConfig::default();
            config.env.tools = names
                .iter()
                .map(|n| assert_ok!(ToolName::parse(n)))
                .collect();
            config
        };
        let policy = merged(vec![
            user("base", tools(&["node", "npx"])),
            project(tools(&["npx", "uvx"])),
        ]);
        let names: Vec<&str> = policy.env.tools.iter().map(|t| t.value.as_str()).collect();
        assert_eq!(names, vec!["node", "npx", "uvx"]);
        assert_eq!(policy.env.tools[1].sources.len(), 2);
    }

    #[test]
    fn merging_nothing_gives_an_empty_policy() {
        assert_eq!(merged(Vec::new()), assert_ok!(merge(&[], Floor::empty())));
    }

    // ====================================================================================
    // Denies are never lost
    // ====================================================================================

    #[test]
    fn every_deny_from_every_file_is_kept() {
        let mut base = ResolvedConfig::default();
        base.fs.deny_read = vec![deny("/Users/me/.ssh")];
        let mut preset = ResolvedConfig::default();
        preset.fs.deny_read = vec![deny("/Users/me/.aws")];
        preset.fs.deny_write = vec![deny("/p/.git/hooks")];
        let mut proj = ResolvedConfig::default();
        proj.fs.deny_read = vec![deny("/p/secrets")];
        let policy = merged(vec![
            user("base", base),
            user("preset", preset),
            project(proj),
        ]);
        assert_eq!(policy.fs.deny_read.len(), 3);
        assert_eq!(policy.fs.deny_write.len(), 1);
    }

    #[test]
    fn a_project_allow_never_removes_a_base_deny_from_the_policy() {
        let mut base = ResolvedConfig::default();
        base.fs.deny_read = vec![deny("/Users/me/.ssh")];
        let mut proj = ResolvedConfig::default();
        proj.fs.read = vec![Indexed {
            value: cpath("/Users/me/.ssh"),
            index: 0,
        }];
        proj.fs.write = vec![Indexed {
            value: cpath("/Users/me/.ssh"),
            index: 0,
        }];
        let policy = merged(vec![user("base", base), project(proj)]);
        assert_eq!(values(&policy.fs.deny_read), vec![deny("/Users/me/.ssh")]);
        assert_eq!(
            policy.fs.read.len(),
            1,
            "the allow is retained too; the deny wins at decision time"
        );
    }

    // ====================================================================================
    // Keyed maps: equal values merge, different values are an error naming both files
    // ====================================================================================

    fn with_env(name: &str, value: &str) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.env.set.insert(
            assert_ok!(EnvName::parse(name)),
            assert_ok!(EnvValue::parse(value)),
        );
        config
    }

    #[test]
    fn an_env_key_with_equal_values_in_two_files_merges_and_keeps_both_sources() {
        let policy = merged(vec![
            user("base", with_env("RUST_LOG", "info")),
            project(with_env("RUST_LOG", "info")),
        ]);
        let entry = assert_some!(policy.env.set.get(&assert_ok!(EnvName::parse("RUST_LOG"))));
        assert_eq!(entry.value.as_str(), "info");
        assert_eq!(
            entry.sources,
            vec![Source::value(FileId::new(0)), Source::value(FileId::new(1))]
        );
    }

    #[test]
    fn an_env_key_with_different_values_is_an_error_naming_both_files_and_not_the_values() {
        let files = closure(vec![
            user("base", with_env("TOKEN", "secret-one")),
            project(with_env("TOKEN", "secret-two")),
        ]);
        let errors = assert_err!(merge(&files, Floor::empty()));
        assert_eq!(errors.errors.len(), 1);
        let shown = errors.errors[0].to_string();
        assert!(shown.contains("env.set.TOKEN"), "{shown}");
        assert!(
            shown.contains("builtin:base") && shown.contains("builtin:project"),
            "{shown}"
        );
        assert!(
            !shown.contains("secret-one") && !shown.contains("secret-two"),
            "values must not be echoed: {shown}"
        );
    }

    fn with_mcp(name: &str, server: ResolvedMcpServer) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.mcp.insert(assert_ok!(McpName::parse(name)), server);
        config
    }

    fn server(command: &str, args: &[&str]) -> ResolvedMcpServer {
        ResolvedMcpServer {
            command: Some(assert_ok!(ArgWord::parse_program(command))),
            args: args.iter().map(|a| assert_ok!(ArgWord::parse(a))).collect(),
            ..ResolvedMcpServer::default()
        }
    }

    #[test]
    fn an_identical_mcp_server_in_two_files_merges() {
        let policy = merged(vec![
            user("base", with_mcp("serena", server("uvx", &["a"]))),
            project(with_mcp("serena", server("uvx", &["a"]))),
        ]);
        let name = assert_ok!(McpName::parse("serena"));
        assert_eq!(assert_some!(policy.mcp.get(&name)).sources.len(), 2);
    }

    #[test]
    fn an_mcp_server_that_differs_in_any_field_is_a_conflict() {
        for other in [
            server("npx", &["a"]),
            server("uvx", &["b"]),
            ResolvedMcpServer {
                bind_ports: vec![assert_ok!(BindPort::try_from(24282))],
                ..server("uvx", &["a"])
            },
            ResolvedMcpServer {
                net: vec![assert_ok!(HostPattern::parse("x.example.com"))],
                ..server("uvx", &["a"])
            },
        ] {
            let files = closure(vec![
                user("base", with_mcp("serena", server("uvx", &["a"]))),
                project(with_mcp("serena", other)),
            ]);
            let errors = assert_err!(merge(&files, Floor::empty()));
            assert!(
                errors.errors[0].to_string().contains("mcp.serena"),
                "{}",
                errors.errors[0]
            );
        }
    }

    #[test]
    fn a_new_mcp_server_name_from_the_project_is_an_addition_not_a_conflict() {
        let policy = merged(vec![
            user("base", with_mcp("serena", server("uvx", &[]))),
            project(with_mcp("other", server("npx", &[]))),
        ]);
        assert_eq!(policy.mcp.len(), 2);
    }

    fn binding(first: i64, count: i64) -> ResolvedMcpServer {
        ResolvedMcpServer {
            bind_ports: (first..first + count)
                .map(|p| assert_ok!(BindPort::try_from(p)))
                .collect(),
            ..ResolvedMcpServer::default()
        }
    }

    fn with_servers(servers: Vec<(&str, ResolvedMcpServer)>) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        for (name, server) in servers {
            config.mcp.insert(assert_ok!(McpName::parse(name)), server);
        }
        config
    }

    #[test]
    fn the_profile_wide_bind_port_total_may_reach_the_maximum() {
        let config = with_servers(
            ["a", "b", "c", "d"]
                .iter()
                .enumerate()
                .map(|(i, name)| (*name, binding(20_000 + 16 * i as i64, 16)))
                .collect(),
        );
        assert_eq!(MAX_BIND_PORTS_TOTAL, 64);
        let _ = merged(vec![project(config)]);
    }

    #[test]
    fn one_distinct_bind_port_over_the_total_is_an_error_naming_the_limit() {
        let config = with_servers(vec![
            ("a", binding(20_000, 16)),
            ("b", binding(20_100, 16)),
            ("c", binding(20_200, 16)),
            ("d", binding(20_300, 16)),
            ("e", binding(20_400, 1)),
        ]);
        let errors = assert_err!(merge(&closure(vec![project(config)]), Floor::empty()));
        assert_eq!(errors.errors.len(), 1);
        assert!(matches!(
            errors.errors[0],
            MergeError::TooManyBindPorts { count: 65, max: 64 }
        ));
        let message = errors.errors[0].to_string();
        assert!(
            message.contains("65") && message.contains("64"),
            "{message}"
        );
    }

    #[test]
    fn a_port_shared_by_two_servers_counts_once_toward_the_total() {
        let config = with_servers(vec![
            ("a", binding(20_000, 16)),
            ("b", binding(20_100, 16)),
            ("c", binding(20_200, 16)),
            ("d", binding(20_300, 16)),
            ("e", binding(20_000, 16)),
        ]);
        let _ = merged(vec![project(config)]);
    }

    // ====================================================================================
    // Scalars
    // ====================================================================================

    fn with_trust(value: Option<bool>) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.tls.system_trust = value;
        config
    }

    #[test]
    fn system_trust_false_beats_true_from_any_file_and_names_the_files_that_said_false() {
        let policy = merged(vec![
            user("base", with_trust(Some(true))),
            user("preset", with_trust(Some(false))),
            project(with_trust(Some(true))),
        ]);
        let trust = assert_some!(policy.tls.system_trust);
        assert!(!trust.value);
        assert_eq!(trust.sources, vec![Source::value(FileId::new(1))]);
    }

    #[test]
    fn a_project_setting_system_trust_false_only_tightens() {
        let policy = merged(vec![
            user("base", with_trust(Some(true))),
            project(with_trust(Some(false))),
        ]);
        assert!(!assert_some!(policy.tls.system_trust).value);
    }

    #[test]
    fn unset_system_trust_is_effectively_false_the_stricter_default() {
        let unset = merged(vec![user("base", with_trust(None))]);
        assert!(!unset.tls.effective_system_trust());
        let on = merged(vec![user("base", with_trust(Some(true)))]);
        assert!(on.tls.effective_system_trust());
        let off = merged(vec![
            user("base", with_trust(Some(true))),
            project(with_trust(Some(false))),
        ]);
        assert!(!off.tls.effective_system_trust());
    }

    #[test]
    fn system_trust_true_alone_stays_true_and_unset_everywhere_stays_unset() {
        let policy = merged(vec![
            user("base", with_trust(Some(true))),
            project(with_trust(None)),
        ]);
        assert!(assert_some!(policy.tls.system_trust).value);
        let policy = merged(vec![
            user("base", with_trust(None)),
            project(with_trust(None)),
        ]);
        assert_eq!(policy.tls.system_trust, None);
    }

    fn with_clipboard(value: Option<bool>) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.terminal.clipboard_write = value;
        config
    }

    #[test]
    fn clipboard_write_false_beats_true_from_any_file_and_a_project_can_only_tighten_it() {
        let policy = merged(vec![
            user("base", with_clipboard(Some(true))),
            project(with_clipboard(Some(false))),
        ]);
        let setting = assert_some!(policy.terminal.clipboard_write.clone());
        assert!(!setting.value);
        assert_eq!(setting.sources, vec![Source::value(FileId::new(1))]);
        assert!(!policy.terminal.effective_clipboard_write());
        // A project cannot turn back on what the user turned off.
        let policy = merged(vec![
            user("base", with_clipboard(Some(false))),
            project(with_clipboard(Some(true))),
        ]);
        assert!(!policy.terminal.effective_clipboard_write());
    }

    #[test]
    fn clipboard_write_is_allowed_unless_some_file_says_false() {
        let unset = merged(vec![user("base", with_clipboard(None))]);
        assert_eq!(unset.terminal.clipboard_write, None);
        assert!(unset.terminal.effective_clipboard_write());
        let on = merged(vec![
            user("base", with_clipboard(Some(true))),
            project(with_clipboard(None)),
        ]);
        assert!(assert_some!(on.terminal.clipboard_write.clone()).value);
        assert!(on.terminal.effective_clipboard_write());
    }

    fn with_internal_hosts(hosts: &[&str]) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.net.internal_hosts = hosts
            .iter()
            .map(|h| assert_ok!(HostPattern::parse(h)))
            .collect();
        config
    }

    #[test]
    fn internal_hosts_are_unioned_across_user_files_and_keep_their_origins() {
        let policy = merged(vec![
            user(
                "base",
                with_internal_hosts(&["github.com", "*.in.example.com"]),
            ),
            user("preset", with_internal_hosts(&["github.com"])),
        ]);
        assert_eq!(policy.net.internal_hosts.len(), 2);
        let github = assert_some!(
            policy
                .net
                .internal_hosts
                .iter()
                .find(|h| h.value.to_string() == "github.com")
        );
        assert_eq!(github.sources.len(), 2);
    }

    #[test]
    fn a_project_file_that_lists_internal_hosts_is_a_merge_error_naming_the_file() {
        let files = closure(vec![
            user("base", with_internal_hosts(&[])),
            project(with_internal_hosts(&["evil.example.com"])),
        ]);
        let errors = assert_err!(merge(&files, Floor::empty()));
        assert!(
            errors.errors.iter().any(|error| matches!(
                error,
                MergeError::UserOnlySection { section, .. } if *section == "net.internal_hosts"
            )),
            "{errors:?}"
        );
    }

    fn with_launchctl(value: Option<bool>) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.system.launchctl = value;
        config
    }

    #[test]
    fn launchctl_is_off_unless_a_user_file_says_true_and_no_file_says_false() {
        let unset = merged(vec![user("base", with_launchctl(None))]);
        assert_eq!(unset.system.launchctl, None);
        assert!(!unset.system.effective_launchctl());
        let on = merged(vec![
            user("base", with_launchctl(Some(true))),
            project(with_launchctl(None)),
        ]);
        assert!(on.system.effective_launchctl());
        let refused = merged(vec![
            user("base", with_launchctl(Some(true))),
            project(with_launchctl(Some(false))),
        ]);
        let setting = assert_some!(refused.system.launchctl.clone());
        assert!(!setting.value);
        assert_eq!(setting.sources, vec![Source::value(FileId::new(1))]);
        assert!(!refused.system.effective_launchctl());
    }

    #[test]
    fn a_project_file_that_says_launchctl_true_is_a_merge_error_naming_the_file() {
        let files = closure(vec![
            user("base", with_launchctl(None)),
            project(with_launchctl(Some(true))),
        ]);
        let errors = assert_err!(merge(&files, Floor::empty()));
        assert!(
            errors.errors.iter().any(|error| matches!(
                error,
                MergeError::UserOnlySection { section, .. } if *section == "system.launchctl = true"
            )),
            "{errors:?}"
        );
    }

    #[test]
    fn a_project_file_that_says_launchctl_false_is_fine() {
        let policy = merged(vec![
            user("base", with_launchctl(Some(true))),
            project(with_launchctl(Some(false))),
        ]);
        assert!(!policy.system.effective_launchctl());
    }

    fn with_label(label: Option<&str>) -> ResolvedConfig {
        let mut config = ResolvedConfig::default();
        config.ctl.label = label.map(|l| assert_ok!(ContainerLabel::parse(l)));
        config
    }

    #[test]
    fn an_equal_ctl_label_in_two_files_merges_and_one_label_alone_is_kept() {
        let policy = merged(vec![
            user("base", with_label(Some("app=icehouse"))),
            project(with_label(Some("app=icehouse"))),
        ]);
        assert_eq!(assert_some!(policy.ctl.label).sources.len(), 2);
        let policy = merged(vec![
            user("base", with_label(None)),
            project(with_label(Some("app=x"))),
        ]);
        assert_eq!(assert_some!(policy.ctl.label).value.to_string(), "app=x");
    }

    #[test]
    fn a_differing_ctl_label_is_a_conflict_so_a_project_cannot_override_the_base_scope() {
        let files = closure(vec![
            user("base", with_label(Some("app=icehouse"))),
            project(with_label(Some("app=other"))),
        ]);
        let errors = assert_err!(merge(&files, Floor::empty()));
        assert!(
            errors.errors[0].to_string().contains("ctl.label"),
            "{}",
            errors.errors[0]
        );
    }

    // ====================================================================================
    // Hooks are named
    // ====================================================================================

    fn hook(words: &[&str]) -> Hook {
        assert_ok!(Hook::new(
            argv(words),
            crate::policy::HookTimeout::default(),
            None,
            None,
            BTreeMap::new()
        ))
    }

    fn hooks_of(entries: &[(&str, &[&str])]) -> BTreeMap<HookName, Hook> {
        entries
            .iter()
            .map(|(name, words)| (assert_ok!(HookName::parse(name)), hook(words)))
            .collect()
    }

    #[test]
    fn hooks_are_in_name_order_and_equal_ones_from_two_files_keep_both_sources() {
        let a = ResolvedConfig {
            hooks: hooks_of(&[("20-zeta", &["/z"]), ("10-alpha", &["/a"])]),
            ..ResolvedConfig::default()
        };
        let b = ResolvedConfig {
            hooks: hooks_of(&[("10-alpha", &["/a"]), ("15-mid", &["/m"])]),
            ..ResolvedConfig::default()
        };
        let policy = merged(vec![user("base", a), user("preset", b)]);
        let order: Vec<&str> = policy.hooks.keys().map(HookName::as_str).collect();
        assert_eq!(order, vec!["10-alpha", "15-mid", "20-zeta"]);
        let alpha = assert_some!(policy.hooks.get(&assert_ok!(HookName::parse("10-alpha"))));
        assert_eq!(alpha.sources.len(), 2);
    }

    #[test]
    fn two_files_that_define_the_same_hook_differently_conflict() {
        let a = ResolvedConfig {
            hooks: hooks_of(&[("bedrock", &["/one"])]),
            ..ResolvedConfig::default()
        };
        let b = ResolvedConfig {
            hooks: hooks_of(&[("bedrock", &["/two"])]),
            ..ResolvedConfig::default()
        };
        let errors = assert_err!(merge(
            &closure(vec![user("base", a), user("preset", b)]),
            Floor::empty()
        ));
        assert!(
            errors.errors[0]
                .to_string()
                .contains("hooks.pre_run.bedrock"),
            "{}",
            errors.errors[0]
        );
    }

    // ====================================================================================
    // User-only sections, re-asserted
    // ====================================================================================

    fn with_hooks() -> ResolvedConfig {
        ResolvedConfig {
            hooks: hooks_of(&[("h", &["/echo"])]),
            ..ResolvedConfig::default()
        }
    }

    #[test]
    fn hooks_from_an_ineligible_file_are_refused_even_if_the_loader_was_bypassed() {
        for location in [FileLocation::InProject, FileLocation::Other] {
            let files = closure(vec![file("evil", Layer::Preset, location, with_hooks())]);
            let errors = assert_err!(merge(&files, Floor::empty()));
            assert!(
                matches!(errors.errors[0], MergeError::UserOnlySection { .. }),
                "{location:?}"
            );
        }
    }

    #[test]
    fn a_project_layer_file_may_not_define_hooks_whatever_its_location() {
        let files = closure(vec![file(
            "p",
            Layer::Project,
            FileLocation::UserConfig,
            with_hooks(),
        )]);
        assert!(matches!(
            assert_err!(merge(&files, Floor::empty())).errors[0],
            MergeError::UserOnlySection { .. }
        ));
    }

    #[test]
    fn guard_exceptions_from_an_ineligible_file_are_refused() {
        let mut config = ResolvedConfig::default();
        config.guard.exceptions = vec![deny("/p/.env")];
        let files = closure(vec![project(config)]);
        let errors = assert_err!(merge(&files, Floor::empty()));
        assert!(
            errors.errors[0].to_string().contains("guard.exceptions"),
            "{}",
            errors.errors[0]
        );
    }

    #[test]
    fn hooks_from_user_files_and_builtins_are_accepted() {
        for location in [FileLocation::UserConfig, FileLocation::Builtin] {
            let policy = merged(vec![file("ok", Layer::Preset, location, with_hooks())]);
            assert_eq!(policy.hooks.len(), 1);
        }
    }

    // ====================================================================================
    // Error collection
    // ====================================================================================

    #[test]
    fn conflicts_are_reported_in_a_stable_order_and_capped() {
        let mut a = ResolvedConfig::default();
        let mut b = ResolvedConfig::default();
        for i in 0..100 {
            let name = assert_ok!(EnvName::parse(&format!("VAR{i:03}")));
            a.env
                .set
                .insert(name.clone(), assert_ok!(EnvValue::parse("1")));
            b.env.set.insert(name, assert_ok!(EnvValue::parse("2")));
        }
        let errors = assert_err!(merge(
            &closure(vec![user("a", a), project(b)]),
            Floor::empty()
        ));
        assert_eq!(errors.errors.len(), MAX_MERGE_ERRORS);
        assert!(errors.truncated);
        assert!(
            errors.errors[0].to_string().contains("env.set.VAR000"),
            "{}",
            errors.errors[0]
        );
        assert!(
            errors.errors[MAX_MERGE_ERRORS - 1]
                .to_string()
                .contains("VAR063")
        );
    }

    #[test]
    fn merge_errors_follow_the_display_convention() {
        let files = closure(vec![
            user("base", with_label(Some("app=a"))),
            project(with_label(Some("app=b"))),
        ]);
        let errors = assert_err!(merge(&files, Floor::empty()));
        crate::error::conventions::assert_display_excludes_sources(&errors.errors[0]);
        assert_eq!(errors.to_string(), "1 merge error(s)");
    }

    #[test]
    fn a_glob_tail_deny_survives_the_merge_unchanged() {
        let pattern = PathPattern {
            base: cpath("/p/config"),
            alias: None,
            tail: Some(assert_ok!(GlobTail::parse(&["*.secrets.yaml"]))),
        };
        let mut config = ResolvedConfig::default();
        config.fs.deny_read = vec![pattern.clone()];
        let policy = merged(vec![project(config)]);
        assert_eq!(values(&policy.fs.deny_read), vec![pattern]);
    }
}
