// ABOUTME: The `hb explain` report model: every effective rule with its origins, built purely from a loaded policy.
// ABOUTME: Secrets are redacted here, before any renderer sees them; renderers only escape and lay out.
//! The report model.
//!
//! [`build_report`] turns a [`Loaded`] closure and policy into a [`Report`]: plain data, in a
//! fixed group order, with every list in a stable order. Nothing here does I/O.
//!
//! **Redaction.** `env.set` values are never put in the report. `mcp` and hook arguments are
//! counted, not shown, unless [`ReportOptions::show_args`] is set; then each is bounded.
//! Values that can carry a secret therefore cannot reach a renderer by accident.
//!
//! **Ordering.** Groups are fixed: `files`, `fs`, `deny`, `net`, `env`, `tls`, `ctl`, `mcp`,
//! `hooks`, `guard_exceptions`, `warnings`. `files` is in closure order (a later file has
//! higher precedence). Sets are value-sorted, which is the order [`Sourced`] lists already
//! have. `deny` lists floor rules first (in floor order), then `deny_read`, then `deny_write`.
//! `hooks` keep first-seen order, which is meaningful. A value's origins are in closure order.

use std::path::Path;

use serde::Serialize;

use crate::config::{Closure, FileSource, FsAccess, FsDecision, Loaded, Policy};
use crate::origin::{KeyPath, Layer, Located, Origin, Source, Sourced};
use crate::policy::{
    Argv, CanonicalPath, FloorEffect, FloorGroup, FloorRule, GlobSegment, HomeDir, PathPattern,
};

/// The version of the JSON shape. Additive fields keep it; a rename or removal bumps it.
pub const SCHEMA_VERSION: u32 = 1;

/// Most characters of a program word shown.
const MAX_PROGRAM_CHARS: usize = 128;
/// Most characters of an argument shown, with `--show-args`.
const MAX_ARG_CHARS: usize = 256;
/// Most floor rules named in one shadowed-grant warning.
const MAX_SHADOW_NAMES: usize = 8;

/// What to include and how to label it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReportOptions<'a> {
    /// The home directory, for `~` display.
    pub home: &'a HomeDir,
    /// The project root.
    pub root: &'a CanonicalPath,
    /// The project's config file.
    pub config: &'a Path,
    /// Show `mcp` and hook arguments instead of only counting them.
    pub show_args: bool,
    /// Whether `XDG_STATE_HOME` is set (and so was ignored).
    pub xdg_state_home_set: bool,
    /// A path to explain, as typed, and its canonical form.
    pub query: Option<(&'a str, &'a CanonicalPath, Option<&'a CanonicalPath>)>,
}

impl<'a> ReportOptions<'a> {
    /// Options with nothing optional enabled.
    #[must_use]
    pub fn new(home: &'a HomeDir, root: &'a CanonicalPath, config: &'a Path) -> Self {
        Self {
            home,
            root,
            config,
            show_args: false,
            xdg_state_home_set: false,
            query: None,
        }
    }
}

/// Where a value came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OriginRow {
    /// `floor`, `user_base`, `preset` or `project`.
    pub layer: String,
    /// The file's position in the report's `files` group.
    pub file_index: Option<usize>,
    /// The preset name, for a preset reached by name.
    pub name: Option<String>,
    /// The file's canonical path; none for a built-in preset and for the floor.
    pub file: Option<String>,
    /// The key in the file, such as `fs.write[0]`.
    pub key: Option<String>,
    /// The floor rule's name, for a floor origin.
    pub floor_rule: Option<String>,
}

/// A value and where it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Row<T> {
    /// The value.
    pub value: T,
    /// Every place it was declared, in closure order.
    pub origins: Vec<OriginRow>,
}

/// The project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectRow {
    /// The canonical project root.
    pub root: String,
    /// The project's config file.
    pub config: String,
    /// The home directory.
    pub home: String,
}

/// One config file of the closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileRow {
    /// Position in closure order; later takes precedence.
    pub index: usize,
    /// `user_base`, `preset` or `project`.
    pub layer: String,
    /// `builtin` or `file`.
    pub source: String,
    /// The preset name, if it was reached by name.
    pub name: Option<String>,
    /// The canonical path; none for a built-in preset.
    pub file: Option<String>,
    /// Where the file physically is.
    pub location: String,
}

/// `fs.read` and `fs.write`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FsReport {
    /// `fs.read` grants.
    pub read: Vec<Row<String>>,
    /// `fs.write` grants.
    pub write: Vec<Row<String>>,
}

/// One deny rule, from the floor or from a config file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DenyRow {
    /// `floor` or `config`.
    pub source: String,
    /// The floor rule's name.
    pub rule: Option<String>,
    /// The floor rule's group: `table`, `project`, `path` or `pin`.
    pub group: Option<String>,
    /// `deny_read_write`, `deny_write`, `deny_connect` or `pin_unlink`.
    pub effect: String,
    /// `subtree`, `node` or `children`.
    pub extent: String,
    /// The canonical path.
    pub path: String,
    /// The symlink's own location, when the path is reached through one.
    pub alias: Option<String>,
    /// The glob below the path, if any.
    pub tail: Option<String>,
    /// Why the floor has it.
    pub reason: Option<String>,
    /// Where the rule is declared.
    pub origins: Vec<OriginRow>,
}

/// `[net]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NetReport {
    /// Allowed hosts.
    pub hosts: Vec<Row<String>>,
    /// Reachable loopback ports.
    pub loopback_ports: Vec<Row<u16>>,
}

/// One `env.set` entry, without its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvSetRow {
    /// The variable's name.
    pub name: String,
    /// Always `false`: the value is never shown.
    pub value_shown: bool,
    /// Where it is set.
    pub origins: Vec<OriginRow>,
}

/// `[env]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnvReport {
    /// Variables copied from the invoking shell.
    pub pass: Vec<Row<String>>,
    /// Variables set to a fixed value, by name.
    pub set: Vec<EnvSetRow>,
}

/// `[tls]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TlsReport {
    /// Whether the system trust store is reachable, and who said so.
    pub system_trust: Row<bool>,
    /// Extra CA files, which are read grants.
    pub extra_ca_files: Vec<Row<String>>,
}

/// `[ctl]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CtlReport {
    /// The container label scope, if set.
    pub label: Option<Row<String>>,
    /// Named containers.
    pub containers: Vec<Row<String>>,
}

/// One MCP server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct McpRow {
    /// Its name.
    pub name: String,
    /// The program, shortened.
    pub command: Option<String>,
    /// How many arguments it has.
    pub arg_count: usize,
    /// The arguments, only with `--show-args`.
    pub args: Option<Vec<String>>,
    /// Hosts it needs.
    pub net: Vec<String>,
    /// Loopback ports it may listen on. The rule is profile-wide and does not confine the listener to loopback.
    pub bind_ports: Vec<u16>,
    /// Where it is declared.
    pub origins: Vec<OriginRow>,
}

/// One host-side hook.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookRow {
    /// The program, shortened.
    pub program: String,
    /// How many arguments it has.
    pub arg_count: usize,
    /// The arguments, only with `--show-args`.
    pub args: Option<Vec<String>>,
    /// Where it is declared.
    pub origins: Vec<OriginRow>,
}

/// Something worth knowing that is not an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WarningRow {
    /// A stable machine-readable kind.
    pub kind: String,
    /// A sentence for a person.
    pub message: String,
    /// Where it comes from, when it has a place.
    pub origins: Vec<OriginRow>,
}

/// The answer for one access to one path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccessRow {
    /// `denied_by_floor`, `denied`, `allowed` or `not_granted`.
    pub decision: String,
    /// The floor rule that decided it.
    pub rule: Option<String>,
    /// That rule's effect.
    pub effect: Option<String>,
    /// Whether it matched only under case-insensitive or Unicode-conservative comparison.
    pub folded: bool,
    /// The rule or grant that decided it.
    pub origins: Vec<OriginRow>,
}

/// Why one path can or cannot be reached.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PathQuery {
    /// The path as typed.
    pub spelling: String,
    /// Its canonical form.
    pub path: String,
    /// Reading it.
    pub read: AccessRow,
    /// Writing, creating, deleting or renaming it.
    pub write: AccessRow,
    /// Connecting to it as a unix socket.
    pub connect: AccessRow,
    /// What this answer leaves out.
    pub note: String,
}

/// What `hb explain` reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// The JSON shape's version.
    pub schema_version: u32,
    /// The project.
    pub project: ProjectRow,
    /// The config files, in closure order.
    pub files: Vec<FileRow>,
    /// Filesystem grants.
    pub fs: FsReport,
    /// Every deny rule: the floor first.
    pub deny: Vec<DenyRow>,
    /// Network.
    pub net: NetReport,
    /// Environment.
    pub env: EnvReport,
    /// TLS.
    pub tls: TlsReport,
    /// `hb ctl`.
    pub ctl: CtlReport,
    /// MCP servers.
    pub mcp: Vec<McpRow>,
    /// Host-side hooks.
    pub hooks: Vec<HookRow>,
    /// Secrets-guard exceptions.
    pub guard_exceptions: Vec<Row<String>>,
    /// Warnings.
    pub warnings: Vec<WarningRow>,
    /// The `--path` answer, when asked for.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<PathQuery>,
}

/// Builds the report for `loaded`.
#[must_use]
pub fn build_report(loaded: &Loaded, options: &ReportOptions<'_>) -> Report {
    let closure = &loaded.closure;
    let policy = &loaded.policy;
    let b = Builder { closure };
    let floor_origin = |rule: &FloorRule| OriginRow {
        layer: Layer::Floor.to_string(),
        file_index: None,
        name: None,
        file: None,
        key: None,
        floor_rule: Some(rule.name.to_string()),
    };

    let mut deny: Vec<DenyRow> = policy
        .floor()
        .rules()
        .iter()
        .map(|rule| DenyRow {
            source: "floor".to_owned(),
            rule: Some(rule.name.to_string()),
            group: Some(rule.group.to_string()),
            effect: rule.effect.to_string(),
            extent: extent_name(rule.extent).to_owned(),
            path: rule.pattern.base.as_str().to_owned(),
            alias: rule.pattern.alias.as_ref().map(|a| a.as_str().to_owned()),
            tail: tail_text(&rule.pattern),
            reason: Some(rule.reason.to_owned()),
            origins: vec![floor_origin(rule)],
        })
        .collect();
    deny.extend(
        policy
            .fs
            .deny_read
            .iter()
            .enumerate()
            .map(|(i, rule)| b.deny_row(FloorEffect::DenyReadWrite, rule, "fs.deny_read", i)),
    );
    deny.extend(
        policy
            .fs
            .deny_write
            .iter()
            .enumerate()
            .map(|(i, rule)| b.deny_row(FloorEffect::DenyWrite, rule, "fs.deny_write", i)),
    );

    let mut warnings: Vec<WarningRow> = loaded
        .floor_diagnostics
        .iter()
        .map(|d| WarningRow {
            kind: d.kind().to_owned(),
            message: d.to_string(),
            origins: Vec::new(),
        })
        .collect();
    warnings.extend(b.skipped_allows());
    warnings.extend(b.shadowed_grants(policy, options.root));
    if options.xdg_state_home_set {
        warnings.push(WarningRow {
            kind: "state_dir_env_ignored".to_owned(),
            message: "XDG_STATE_HOME is set and ignored: approvals always live in ~/.local/state/hamster-ball"
                .to_owned(),
            origins: Vec::new(),
        });
    }

    Report {
        schema_version: SCHEMA_VERSION,
        project: ProjectRow {
            root: options.root.as_str().to_owned(),
            config: options.config.to_string_lossy().into_owned(),
            home: options.home.path().as_str().to_owned(),
        },
        files: b.files(),
        fs: FsReport {
            read: b.rows(&policy.fs.read, "fs.read", |p| p.as_str().to_owned()),
            write: b.rows(&policy.fs.write, "fs.write", |p| p.as_str().to_owned()),
        },
        deny,
        net: NetReport {
            hosts: b.rows(&policy.net.allow, "net.allow", ToString::to_string),
            loopback_ports: b.rows(&policy.net.loopback_ports, "net.loopback_ports", |p| {
                p.get()
            }),
        },
        env: EnvReport {
            pass: b.rows(&policy.env.pass, "env.pass", |n| n.as_str().to_owned()),
            set: policy
                .env
                .set
                .iter()
                .map(|(name, value)| EnvSetRow {
                    name: name.as_str().to_owned(),
                    value_shown: false,
                    origins: b.origins(&value.sources, &format!("env.set.{}", name.as_str())),
                })
                .collect(),
        },
        tls: TlsReport {
            system_trust: policy.tls.system_trust.as_ref().map_or_else(
                || Row {
                    value: false,
                    origins: Vec::new(),
                },
                |trust| Row {
                    value: trust.value,
                    origins: b.origins(&trust.sources, "tls.system_trust"),
                },
            ),
            extra_ca_files: b.rows(&policy.tls.extra_ca_files, "tls.extra_ca_files", |p| {
                p.as_str().to_owned()
            }),
        },
        ctl: CtlReport {
            label: policy.ctl.label.as_ref().map(|label| Row {
                value: label.value.to_string(),
                origins: b.origins(&label.sources, "ctl.label"),
            }),
            containers: b.rows(&policy.ctl.containers, "ctl.containers", |c| {
                c.as_str().to_owned()
            }),
        },
        mcp: policy
            .mcp
            .iter()
            .map(|(name, server)| McpRow {
                name: name.as_str().to_owned(),
                command: server
                    .value
                    .command
                    .as_ref()
                    .map(|c| bounded(c.as_str(), MAX_PROGRAM_CHARS)),
                arg_count: server.value.args.len(),
                args: options.show_args.then(|| {
                    server
                        .value
                        .args
                        .iter()
                        .map(|a| bounded(a.as_str(), MAX_ARG_CHARS))
                        .collect()
                }),
                net: server.value.net.iter().map(ToString::to_string).collect(),
                bind_ports: server.value.bind_ports.iter().map(|p| p.get()).collect(),
                origins: b.origins(&server.sources, &format!("mcp.{}", name.as_str())),
            })
            .collect(),
        hooks: policy
            .hooks
            .iter()
            .map(|hook| b.hook_row(hook, options.show_args))
            .collect(),
        guard_exceptions: b.rows(&policy.guard_exceptions, "guard.exceptions", |g| {
            g.as_str().to_owned()
        }),
        warnings,
        query: options
            .query
            .map(|(spelling, path, alias)| b.query(policy, spelling, path, alias)),
    }
}

fn extent_name(extent: crate::policy::Extent) -> &'static str {
    match extent {
        crate::policy::Extent::Subtree => "subtree",
        crate::policy::Extent::Node => "node",
        crate::policy::Extent::Children => "children",
    }
}

fn tail_text(pattern: &PathPattern) -> Option<String> {
    pattern.tail.as_ref().map(|tail| {
        tail.segments()
            .iter()
            .map(|segment| match segment {
                GlobSegment::AnyDepth => "**",
                GlobSegment::Segment(text) => text.as_str(),
            })
            .collect::<Vec<_>>()
            .join("/")
    })
}

/// `text`, shortened to `max` characters with `...`.
fn bounded(text: &str, max: usize) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(max).collect();
    if chars.next().is_some() {
        format!("{head}...")
    } else {
        head
    }
}

fn layer_name(layer: Layer) -> String {
    layer.to_string()
}

/// Reads the closure; holds nothing else.
struct Builder<'a> {
    closure: &'a Closure,
}

impl Builder<'_> {
    fn files(&self) -> Vec<FileRow> {
        self.closure
            .files()
            .iter()
            .enumerate()
            .map(|(index, file)| {
                let (source, name, path) = file_identity(&file.source);
                FileRow {
                    index,
                    layer: layer_name(file.layer),
                    source: source.to_owned(),
                    name,
                    file: path,
                    location: file.location.to_string(),
                }
            })
            .collect()
    }

    fn origins(&self, sources: &[Source], key: &str) -> Vec<OriginRow> {
        sources
            .iter()
            .map(|source| {
                let Source::File { file, index } = *source;
                let position = file.index();
                let closure_file = &self.closure.files()[position];
                let (_, name, path) = file_identity(&closure_file.source);
                OriginRow {
                    layer: layer_name(closure_file.layer),
                    file_index: Some(position),
                    name,
                    file: path,
                    key: Some(index.map_or_else(|| key.to_owned(), |i| format!("{key}[{i}]"))),
                    floor_rule: None,
                }
            })
            .collect()
    }

    fn rows<T, U>(&self, items: &[Sourced<T>], key: &str, value: impl Fn(&T) -> U) -> Vec<Row<U>> {
        items
            .iter()
            .map(|item| Row {
                value: value(&item.value),
                origins: self.origins(&item.sources, key),
            })
            .collect()
    }

    fn deny_row(
        &self,
        effect: FloorEffect,
        rule: &Sourced<PathPattern>,
        key: &str,
        _position: usize,
    ) -> DenyRow {
        DenyRow {
            source: "config".to_owned(),
            rule: None,
            group: None,
            effect: effect.to_string(),
            extent: "subtree".to_owned(),
            path: rule.value.base.as_str().to_owned(),
            alias: rule.value.alias.as_ref().map(|a| a.as_str().to_owned()),
            tail: tail_text(&rule.value),
            reason: None,
            origins: self.origins(&rule.sources, key),
        }
    }

    fn hook_row(&self, hook: &Sourced<Argv>, show_args: bool) -> HookRow {
        let words = hook.value.words();
        HookRow {
            program: bounded(hook.value.program().as_str(), MAX_PROGRAM_CHARS),
            arg_count: words.len().saturating_sub(1),
            args: show_args.then(|| {
                words
                    .iter()
                    .skip(1)
                    .map(|w| bounded(w.as_str(), MAX_ARG_CHARS))
                    .collect()
            }),
            origins: self.origins(&hook.sources, "hooks"),
        }
    }

    /// An origin built from a [`Located`] value's own [`Origin`].
    fn located_origin(&self, origin: &Origin) -> OriginRow {
        let position = self
            .closure
            .files()
            .iter()
            .position(|file| file.origin(KeyPath::root()).file == origin.file);
        OriginRow {
            layer: layer_name(origin.layer),
            file_index: position,
            name: position.and_then(|p| file_identity(&self.closure.files()[p].source).1),
            file: Some(origin.file.to_string_lossy().into_owned()),
            key: Some(origin.key.to_string()),
            floor_rule: None,
        }
    }

    fn skipped_allows(&self) -> Vec<WarningRow> {
        self.closure
            .files()
            .iter()
            .flat_map(|file| file.diagnostics.skipped.iter())
            .map(|skipped: &Located<_>| WarningRow {
                kind: "skipped_allow".to_owned(),
                message: format!(
                    "`{}` was not granted: {}",
                    skipped.value.spelling,
                    skipped.value.reason.to_string().to_lowercase()
                ),
                origins: vec![self.located_origin(&skipped.origin)],
            })
            .collect()
    }

    /// Grants that the floor overrides, in whole or in part.
    ///
    /// A grant of the project root, or of a directory above it, always contains the project's own
    /// protected files (its config, its git hooks), so those rules are not reported for it. A
    /// grant strictly inside the project that hits one (`.git/hooks`, an approval file) is
    /// exactly the mistake worth reporting. Pins are never reported: they protect a name, not
    /// the contents.
    fn shadowed_grants(&self, policy: &Policy, root: &CanonicalPath) -> Vec<WarningRow> {
        let grants = policy
            .fs
            .read
            .iter()
            .map(|g| (g, FsAccess::Read, "fs.read"))
            .chain(
                policy
                    .tls
                    .extra_ca_files
                    .iter()
                    .map(|g| (g, FsAccess::Read, "tls.extra_ca_files")),
            )
            .chain(
                policy
                    .fs
                    .write
                    .iter()
                    .map(|g| (g, FsAccess::Write, "fs.write")),
            );
        let mut out = Vec::new();
        for (grant, access, key) in grants {
            let path = &grant.value;
            let mut names: Vec<String> = Vec::new();
            let mut whole = false;
            for rule in policy.floor().rules() {
                let counts = match rule.group {
                    FloorGroup::Table | FloorGroup::Path => true,
                    FloorGroup::Project => !path.is_same_or_ancestor_of(root),
                    _ => false,
                };
                if !counts || !rule.effect.forbids(access) {
                    continue;
                }
                let covers = rule.covers(path) == crate::policy::Coverage::Yes;
                let inside = path.is_same_or_ancestor_of(&rule.pattern.base);
                if covers {
                    whole = true;
                    names.insert(0, rule.name.to_string());
                } else if inside {
                    names.push(rule.name.to_string());
                }
            }
            if names.is_empty() {
                continue;
            }
            let shown = names
                .iter()
                .take(MAX_SHADOW_NAMES)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let more = names.len().saturating_sub(MAX_SHADOW_NAMES);
            let message = if whole {
                format!("`{}` is denied by floor rule {}", path.as_str(), names[0])
            } else {
                format!(
                    "`{}` contains paths the floor still denies: {shown}{}",
                    path.as_str(),
                    if more > 0 {
                        format!(" and {more} more")
                    } else {
                        String::new()
                    }
                )
            };
            out.push(WarningRow {
                kind: "grant_shadowed_by_floor".to_owned(),
                message,
                origins: self.origins(&grant.sources, key),
            });
        }
        out
    }

    fn query(
        &self,
        policy: &Policy,
        spelling: &str,
        path: &CanonicalPath,
        alias: Option<&CanonicalPath>,
    ) -> PathQuery {
        let access = |which: FsAccess| {
            let mut answers: Vec<AccessRow> = std::iter::once(path)
                .chain(alias)
                .map(|p| self.access_row(policy, p, which))
                .collect();
            // A denial at either spelling of a symlinked path is the answer.
            let denied = answers
                .iter()
                .position(|a| a.decision.starts_with("denied"));
            answers.swap_remove(denied.unwrap_or(0))
        };
        PathQuery {
            spelling: spelling.to_owned(),
            path: path.as_str().to_owned(),
            read: access(FsAccess::Read),
            write: access(FsAccess::Write),
            connect: access(FsAccess::Connect),
            note: "advisory: this reflects the merged config and the floor only; the system \
                   allows and the secrets guard are not included. A `pin_unlink` hit means the \
                   path itself cannot be renamed or deleted; writing inside it is not affected"
                .to_owned(),
        }
    }

    fn access_row(&self, policy: &Policy, path: &CanonicalPath, access: FsAccess) -> AccessRow {
        let key = match access {
            FsAccess::Read => "fs.read",
            FsAccess::Write => "fs.write",
            FsAccess::Connect => "",
        };
        match policy.decide(path, access) {
            FsDecision::DeniedByFloor { rule, folded, .. } => AccessRow {
                decision: "denied_by_floor".to_owned(),
                rule: Some(rule.name.to_string()),
                effect: Some(rule.effect.to_string()),
                folded,
                origins: vec![OriginRow {
                    layer: Layer::Floor.to_string(),
                    file_index: None,
                    name: None,
                    file: None,
                    key: None,
                    floor_rule: Some(rule.name.to_string()),
                }],
            },
            FsDecision::Denied { by, folded } => AccessRow {
                decision: "denied".to_owned(),
                rule: None,
                effect: None,
                folded,
                origins: self.origins(&by.sources, "fs.deny"),
            },
            FsDecision::Allowed { by } => AccessRow {
                decision: "allowed".to_owned(),
                rule: None,
                effect: None,
                folded: false,
                origins: self.origins(&by.sources, key),
            },
            _ => AccessRow {
                decision: "not_granted".to_owned(),
                rule: None,
                effect: None,
                folded: false,
                origins: Vec::new(),
            },
        }
    }
}

/// `(source, preset name, canonical path)` for a file.
fn file_identity(source: &FileSource) -> (&'static str, Option<String>, Option<String>) {
    match source {
        FileSource::Builtin { name } => ("builtin", Some(name.as_str().to_owned()), None),
        FileSource::Disk {
            canonical, preset, ..
        } => (
            "file",
            preset.as_ref().map(|name| name.as_str().to_owned()),
            Some(canonical.as_str().to_owned()),
        ),
    }
}
