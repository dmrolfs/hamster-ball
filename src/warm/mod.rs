// ABOUTME: `hb warm`: starts each declared uvx/npx MCP server once in the ball, with the registries open, to fill hb's offline cache.
// ABOUTME: Warm hosts, the MCP probe, and the stamps that let `hb run` say which servers were never warmed.
//! `hb warm` (design 10, hb-ghd.7.3).
//!
//! Only servers whose `command` is a bare `uvx` or `npx` are warmed: those are the two names the
//! offline launchers replace, so they are the only servers whose start reaches a registry. Another
//! command fetches nothing, so there is nothing to warm and no warning.

pub mod doctor;
pub mod hosts;
pub mod probe;
pub mod stamp;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime};

use snafu::Snafu;

use crate::config::{Loaded, Policy};
use crate::policy::{CanonicalPath, HostRule};
use crate::session::cache::{
    CacheError, CacheGeneration, CacheLimits, CacheStore, WarmLock, expected_inputs_for,
    remove_tree, seed_python,
};
use crate::session::offline::{Launcher, cache_root};
use crate::session::{DenialSink, ExitKind, Outcome, RunError, RunSpec, SignalMode, WarmSpec, run};
use crate::system::{Environment, StateDir, ToolLookup};
use stamp::{Standing, WarmStore, digest};

/// One server `hb warm` can warm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Server {
    /// The `[mcp.<name>]` name.
    pub name: String,
    /// The program: `uvx` or `npx`.
    pub command: String,
    /// Its arguments.
    pub args: Vec<String>,
    /// The hosts the proxy allows while it is warmed.
    pub allowlist: Vec<HostRule>,
}

impl Server {
    /// The digest a stamp holds for this server.
    #[must_use]
    pub fn digest(&self) -> String {
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        digest(&self.command, &args)
    }
}

/// What `hb warm NAME...` was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Selection {
    /// The servers to warm, in name order.
    pub warm: Vec<Server>,
    /// Named servers that have nothing to warm (their command is not `uvx` or `npx`).
    pub nothing_to_warm: Vec<String>,
}

/// A name that is not a declared server.
#[derive(Debug, Snafu)]
#[snafu(display(
    "there is no server `{name}` with a command in [mcp.*]; {}",
    if known.is_empty() { "none is declared".to_owned() } else { format!("declared: {}", known.join(", ")) }
))]
pub struct UnknownServer {
    /// What was asked for.
    pub name: String,
    /// The declared servers that have a command.
    pub known: Vec<String>,
}

fn launcher_of(command: &str) -> Option<Launcher> {
    Launcher::from_str(command).ok()
}

/// Every declared server that `hb warm` can warm, in name order.
#[must_use]
pub fn servers(policy: &Policy) -> Vec<Server> {
    policy
        .mcp
        .iter()
        .filter_map(|(name, server)| {
            let command = server.value.command.as_ref()?.as_str();
            launcher_of(command)?;
            Some(Server {
                name: name.as_str().to_owned(),
                command: command.to_owned(),
                args: server
                    .value
                    .args
                    .iter()
                    .map(|a| a.as_str().to_owned())
                    .collect(),
                allowlist: hosts::allowlist(&server.value),
            })
        })
        .collect()
}

/// The servers `names` select, or all of them when `names` is empty.
///
/// # Errors
/// [`UnknownServer`] for a name that no `[mcp.*]` with a command has.
pub fn select(policy: &Policy, names: &[String]) -> Result<Selection, UnknownServer> {
    let all = servers(policy);
    if names.is_empty() {
        return Ok(Selection {
            warm: all,
            nothing_to_warm: Vec::new(),
        });
    }
    let with_command: BTreeSet<String> = policy
        .mcp
        .iter()
        .filter(|(_, server)| server.value.command.is_some())
        .map(|(name, _)| name.as_str().to_owned())
        .collect();
    let mut selection = Selection::default();
    for name in names.iter().collect::<BTreeSet<_>>() {
        if let Some(server) = all.iter().find(|s| &s.name == name) {
            selection.warm.push(server.clone());
        } else if with_command.contains(name) {
            selection.nothing_to_warm.push(name.clone());
        } else {
            return Err(UnknownServer {
                name: name.clone(),
                known: with_command.iter().cloned().collect(),
            });
        }
    }
    selection.warm.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(selection)
}

/// What the stamps say about `server` in the project at `root`.
#[must_use]
pub fn standing(store: &WarmStore, root: &CanonicalPath, server: &Server) -> Standing {
    store.standing(root, &server.name, &server.digest())
}

/// One warning for each server that was never warmed or whose command changed since.
#[must_use]
pub fn cold_warnings(policy: &Policy, store: &WarmStore, root: &CanonicalPath) -> Vec<String> {
    servers(policy)
        .iter()
        .filter(|server| standing(store, root, server) != Standing::Warmed)
        .map(|server| {
            format!(
                "mcp server {} has not been warmed (or its command changed): run hb warm",
                server.name
            )
        })
        .collect()
}

/// How warming one server ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warmed {
    /// The server answered `initialize`, in `took`.
    Answered {
        /// How long it took.
        took: Duration,
    },
    /// It did not; `why` is what the probe and the server said.
    Failed {
        /// The server's last stderr lines and the reason, as the probe printed them.
        why: String,
    },
}

/// Where the denials and proxy connections of a warm run go, as for `hb run`.
#[derive(Debug, Default)]
pub struct Logging {
    /// Where denial lines go.
    pub denials: Option<DenialSink>,
    /// Where one line per proxy connection goes.
    pub proxy_log: Option<DenialSink>,
}

/// Why a server could not even be tried.
#[derive(Debug, Snafu)]
#[snafu(display("could not run the warm probe for {name}: {source}"))]
pub struct StartError {
    /// The server.
    pub name: String,
    /// The underlying error.
    #[snafu(source(from(RunError, Box::new)))]
    pub source: Box<RunError>,
}

/// Warms `server` once, in the ball `loaded` describes, building into `workspace`.
///
/// Nothing is recorded here: the generation is published only after every selected server
/// answered, by [`publish`].
///
/// # Errors
/// [`StartError`] when the run could not start at all; a server that starts and does not answer
/// is [`Warmed::Failed`].
pub fn warm_server(
    env: &Environment,
    loaded: &Loaded,
    server: &Server,
    workspace: &Path,
    limit: Duration,
    signals: SignalMode,
    logging: Logging,
) -> Result<(Warmed, Outcome), StartError> {
    let mut spec = RunSpec::new(probe::argv(limit, &server.command, &server.args))
        .signals(signals)
        .warm(WarmSpec {
            allowlist: server.allowlist.clone(),
            workspace: workspace.to_path_buf(),
        })
        .proxy_summary(false);
    spec.denials = logging.denials;
    spec.proxy_log = logging.proxy_log;
    let started = std::time::Instant::now();
    let outcome = run(env, loaded, &spec).map_err(|source| StartError {
        name: server.name.clone(),
        source: Box::new(source),
    })?;
    let result = if outcome.exit == ExitKind::Exited(0) {
        Warmed::Answered {
            took: started.elapsed(),
        }
    } else {
        Warmed::Failed {
            why: String::from_utf8_lossy(&outcome.stderr)
                .trim_end()
                .to_owned(),
        }
    };
    Ok((result, outcome))
}

/// A warm in progress: the project's lock and the empty workspace the ball builds in.
///
/// Dropping it without calling [`publish`] removes the workspace and publishes nothing, so a
/// failed or interrupted warm leaves the previous generation current and no complete-looking tree.
#[derive(Debug)]
pub struct WarmBuild {
    store: CacheStore,
    workspace: PathBuf,
    _lock: WarmLock,
}

impl WarmBuild {
    /// The directory the warm ball builds in.
    #[must_use]
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
}

impl Drop for WarmBuild {
    fn drop(&mut self) {
        // Best effort: a published build was already removed by `publish`, and an unpublished
        // leftover is never selected, whatever happens here.
        let _ = remove_tree(&self.workspace);
    }
}

/// Takes the project's warm lock and makes an empty workspace seeded with the user's own
/// uv-managed interpreter, so the generation holds its Python.
///
/// # Errors
/// [`CacheError::WarmBusy`] if another warm of this project is running, or another
/// [`CacheError`] if the workspace or the interpreter copy fails.
pub fn begin(
    env: &Environment,
    selected: &[Server],
    tools: &ToolLookup,
    root: &CanonicalPath,
) -> Result<WarmBuild, CacheError> {
    let store = CacheStore::new(cache_root(&env.home));
    let inputs = expected_inputs_for(root, selected, tools)?;
    let lock = store.lock_warm(&inputs.project_key)?;
    let temp = env
        .floor
        .user_temp_dir
        .as_deref()
        .ok_or(CacheError::NoTempDir)?;
    let temp = std::fs::canonicalize(temp).map_err(|source| CacheError::Read {
        path: temp.to_path_buf(),
        source,
    })?;
    let workspace = store.begin_build(&temp)?;
    let build = WarmBuild {
        store,
        workspace,
        _lock: lock,
    };
    let uv_python = env.home.path().as_path().join(".local/share/uv/python");
    seed_python(&uv_python, &build.workspace, CacheLimits::default())?;
    Ok(build)
}

/// Seals the finished workspace and publishes it as the project's current generation, then
/// records the advisory stamps. Called once, after every selected server answered.
///
/// # Errors
/// [`CacheError`] if sealing or publishing fails; the previous generation stays current.
pub fn publish(
    env: &Environment,
    build: WarmBuild,
    root: &CanonicalPath,
    selected: &[Server],
    tools: &ToolLookup,
) -> Result<CacheGeneration, CacheError> {
    let inputs = expected_inputs_for(root, selected, tools)?;
    let old_root = build.workspace.clone();
    let made = build.store.seal_and_publish(
        &build.workspace,
        &inputs,
        Some(&old_root),
        CacheLimits::default(),
    )?;
    let stamps = WarmStore::new(&StateDir::locate(&env.home));
    for server in selected {
        // Advisory display state only; a failed stamp never undoes a committed generation.
        let _ = stamps.record(root, &server.name, &server.digest(), SystemTime::now());
    }
    Ok(made)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;
    use crate::config::{ResolvedMcpServer, merge};
    use crate::origin::{FileId, Source, Sourced};
    use crate::policy::{ArgWord, Floor, HomeDir, McpName};

    fn policy(servers: &[(&str, &str, &[&str])]) -> Policy {
        let source = Source::value(FileId::new(0));
        let mut policy = assert_ok!(merge(&[], Floor::empty()));
        for (name, command, args) in servers {
            policy.mcp.insert(
                assert_ok!(McpName::parse(name)),
                Sourced::new(
                    ResolvedMcpServer {
                        command: Some(assert_ok!(ArgWord::parse_program(command))),
                        args: args.iter().map(|a| assert_ok!(ArgWord::parse(a))).collect(),
                        ..ResolvedMcpServer::default()
                    },
                    source,
                ),
            );
        }
        policy
    }

    fn names(servers: &[Server]) -> Vec<&str> {
        servers.iter().map(|s| s.name.as_str()).collect()
    }

    const SERVERS: [(&str, &str, &[&str]); 4] = [
        ("time", "uvx", &["mcp-server-time"]),
        ("ripgrep", "npx", &["-y", "mcp-ripgrep@latest"]),
        ("lean-ctx", "/opt/homebrew/bin/lean-ctx", &[]),
        ("abs", "/Users/me/.local/bin/uvx", &["x"]),
    ];

    #[test]
    fn only_a_bare_uvx_or_npx_server_can_be_warmed_and_they_come_in_name_order() {
        let found = servers(&policy(&SERVERS));
        assert_eq!(names(&found), ["ripgrep", "time"]);
        assert_eq!(found[1].command, "uvx");
        assert_eq!(found[1].args, ["mcp-server-time"]);
        assert!(
            found[1]
                .allowlist
                .iter()
                .any(|r| r.pattern.to_string() == "pypi.org")
        );
    }

    #[test]
    fn no_names_selects_every_warmable_server() {
        let selection = assert_ok!(select(&policy(&SERVERS), &[]));
        assert_eq!(names(&selection.warm), ["ripgrep", "time"]);
        assert!(selection.nothing_to_warm.is_empty());
    }

    #[test]
    fn a_named_server_is_selected_and_a_named_one_that_starts_something_else_has_nothing_to_warm() {
        let selection = assert_ok!(select(
            &policy(&SERVERS),
            &["time".into(), "lean-ctx".into(), "time".into()]
        ));
        assert_eq!(names(&selection.warm), ["time"]);
        assert_eq!(selection.nothing_to_warm, ["lean-ctx"]);
    }

    #[test]
    fn an_unknown_name_is_refused_and_the_message_lists_the_declared_servers() {
        let error = assert_err!(select(&policy(&SERVERS), &["nosuch".into()]));
        let text = error.to_string();
        assert!(
            text.contains("nosuch") && text.contains("time") && text.contains("lean-ctx"),
            "{text}"
        );
        let none = assert_err!(select(&policy(&[]), &["x".into()])).to_string();
        assert!(none.contains("none is declared"), "{none}");
    }

    #[test]
    fn the_digest_follows_the_command_and_the_arguments() {
        let found = servers(&policy(&SERVERS));
        let time = &found[1];
        assert_eq!(time.digest(), digest("uvx", &["mcp-server-time"]));
        assert_ne!(time.digest(), found[0].digest());
    }

    #[test]
    fn cold_servers_are_named_in_one_warning_each_and_a_warmed_one_is_not() {
        let tmp = assert_ok!(TempDir::new());
        let base = assert_ok!(fs::canonicalize(tmp.path()));
        let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(&base)));
        let store = WarmStore::new(&StateDir::locate(&home));
        let root = assert_ok!(CanonicalPath::from_canonical(&base));
        let p = policy(&SERVERS);
        let warnings = cold_warnings(&p, &store, &root);
        assert_eq!(
            warnings,
            [
                "mcp server ripgrep has not been warmed (or its command changed): run hb warm",
                "mcp server time has not been warmed (or its command changed): run hb warm"
            ]
        );
        let found = servers(&p);
        assert_ok!(store.record(&root, "time", &found[1].digest(), SystemTime::now()));
        assert_eq!(cold_warnings(&p, &store, &root).len(), 1);
        assert_ok!(store.record(
            &root,
            "ripgrep",
            &digest("npx", &["-y", "other"]),
            SystemTime::now()
        ));
        assert_eq!(
            cold_warnings(&p, &store, &root).len(),
            1,
            "a changed command is cold again"
        );
    }
}
