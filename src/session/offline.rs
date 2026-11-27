// ABOUTME: The `uvx` and `npx` launchers that start MCP servers from hb's own cache, with no registry reachable.
// ABOUTME: Planned from the policy and the found tools, written into the session directory, first on the child's PATH.
//! Offline MCP launchers (design 10, hb-ghd.7.2).
//!
//! An agent starts its MCP servers with `uvx` and `npx`, which download packages at every start.
//! When a config declares a server with a command, hb writes a script named `uvx` and one named
//! `npx` into `<session>/bin`, first on the child's `PATH`. Each script points the tool at hb's own
//! cache (never the user's: uv writes to its cache even offline, so a shared one would be
//! agent-writable) and runs it with `--offline`. The script `exec`s the tool, so stdin, stdout,
//! signals and the process identity are the tool's own; an MCP server speaks over stdin and stdout.
//!
//! Only these two names are affected. `uv sync`, `npm install` and a call by absolute path are not.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use snafu::{ResultExt, Snafu};
use strum::{AsRefStr, Display, EnumIter, EnumString, IntoEnumIterator};

use crate::config::Policy;
use crate::policy::{CanonicalPath, EnvName, HomeDir, PathError};
use crate::system::ToolLookup;

/// The directory under the home that holds hb's own caches.
const CACHE_DIR: &str = ".cache/hamster-ball";
/// The cache's subdirectories.
pub const CACHE_SUBDIRS: [&str; 4] = ["uv", "uv-tools", "npm", "python"];

/// Where hb's cache store lives: `~/.cache/hamster-ball`. A run never reads or writes it; it
/// holds the sealed generations that each run copies from.
#[must_use]
pub fn cache_root(home: &HomeDir) -> PathBuf {
    home.path().as_path().join(CACHE_DIR)
}

/// The launchers hb replaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr, EnumIter, EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum Launcher {
    /// `uvx`, which runs a Python package.
    Uvx,
    /// `npx`, which runs an npm package.
    Npx,
}

/// One launcher to write, and the real tool it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLauncher {
    kind: Launcher,
    real: PathBuf,
}

impl PlannedLauncher {
    /// Which launcher it is.
    #[must_use]
    pub fn kind(&self) -> Launcher {
        self.kind
    }

    /// The real tool the script runs.
    #[must_use]
    pub fn real(&self) -> &Path {
        &self.real
    }
}

/// What a run does about `uvx` and `npx`, decided from the policy alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfflinePlan {
    launchers: Vec<PlannedLauncher>,
    cache_root: PathBuf,
    warnings: Vec<String>,
}

/// Why the launchers could not be written.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum OfflineError {
    /// A directory could not be created.
    #[snafu(display("could not create {}: {source}", path.display()))]
    CreateDir {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// A directory could not be resolved to a canonical path.
    #[snafu(display("could not resolve {}: {source}", path.display()))]
    Resolve {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// A resolved directory is not an acceptable canonical path.
    #[snafu(display("{} is not a usable cache location: {source}", path.display()))]
    NotCanonical {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: PathError,
    },

    /// A launcher script could not be written.
    #[snafu(display("could not write the {kind} launcher {}: {source}", path.display()))]
    WriteLauncher {
        /// Which launcher.
        kind: Launcher,
        /// The script's path.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

/// What [`OfflinePlan::install`] made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    bin_dir: CanonicalPath,
    cache_root: CanonicalPath,
}

impl Installed {
    /// The directory with the scripts, to put first on `PATH`.
    #[must_use]
    pub fn bin_dir(&self) -> &CanonicalPath {
        &self.bin_dir
    }

    /// The cache directory, which the ball may read and write.
    #[must_use]
    pub fn cache_root(&self) -> &CanonicalPath {
        &self.cache_root
    }
}

impl OfflinePlan {
    /// The plan for `policy`, or `None` when no declared server has a command.
    ///
    /// A launcher is planned for each of `uvx` and `npx` that `[env] tools` found. A declared
    /// server that starts one of them by its bare name without `[env] tools` naming it gets a
    /// warning: there is no real tool to run.
    #[must_use]
    pub fn plan(policy: &Policy, tools: &ToolLookup, home: &HomeDir) -> Option<Self> {
        let commands: Vec<(&str, &str)> = policy
            .mcp
            .iter()
            .filter_map(|(name, server)| {
                Some((name.as_str(), server.value.command.as_ref()?.as_str()))
            })
            .collect();
        if commands.is_empty() {
            return None;
        }
        let launchers = Launcher::iter()
            .filter_map(|kind| {
                let tool = tools
                    .found
                    .iter()
                    .find(|t| t.name.as_str() == kind.as_ref())?;
                Some(PlannedLauncher {
                    kind,
                    real: tool.dir.as_path().join(kind.as_ref()),
                })
            })
            .collect();
        let warnings = commands
            .iter()
            .filter_map(|(server, command)| {
                let kind = Launcher::iter().find(|k| k.as_ref() == *command)?;
                let listed = policy
                    .env
                    .tools
                    .iter()
                    .any(|t| t.value.as_str() == kind.as_ref());
                (!listed).then(|| {
                    format!(
                        "[mcp.{server}] starts `{kind}`, which is not in [env] tools, so hb cannot start it from its offline cache; add \"{kind}\" to [env] tools"
                    )
                })
            })
            .collect();
        Some(Self {
            launchers,
            cache_root: cache_root(home),
            warnings,
        })
    }

    /// The launchers to write.
    #[must_use]
    pub fn launchers(&self) -> &[PlannedLauncher] {
        &self.launchers
    }

    /// Where the cache lives (before it is created and resolved).
    #[must_use]
    pub fn cache_root(&self) -> &Path {
        &self.cache_root
    }

    /// Things the user should know, such as a launcher that cannot be written.
    #[must_use]
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Writes the scripts under `session`, pointing at the run's own `cache` (already copied
    /// there from a published generation).
    ///
    /// # Errors
    /// [`OfflineError`] when a directory or a script cannot be made.
    pub fn install(
        &self,
        session: &CanonicalPath,
        cache: &CanonicalPath,
    ) -> Result<Installed, OfflineError> {
        let bin = session.as_path().join("bin");
        private_dir(&bin)?;
        for launcher in &self.launchers {
            let path = bin.join(launcher.kind.as_ref());
            let text = script(
                launcher.kind,
                &launcher.real.to_string_lossy(),
                cache.as_str(),
            );
            write_script(&path, &text).context(WriteLauncherSnafu {
                kind: launcher.kind,
                path: path.clone(),
            })?;
        }
        let bin_dir =
            CanonicalPath::from_canonical(&bin).context(NotCanonicalSnafu { path: bin })?;
        Ok(Installed {
            bin_dir,
            cache_root: cache.clone(),
        })
    }
}

/// The variables that point `uv` and `npm` at the cache under `cache_root`, as `hb warm` sets
/// them for the server it starts (a run sets them inside the launcher scripts instead).
///
/// `UV_PYTHON_INSTALL_DIR` and the settings in [`PRIVATE_PYTHON`] keep uv on the interpreter
/// inside the cache, so no link points at the user's own `~/.local/share/uv/python`.
#[must_use]
pub fn cache_vars(cache_root: &CanonicalPath) -> Vec<(EnvName, CanonicalPath)> {
    [
        ("UV_CACHE_DIR", "uv"),
        ("UV_TOOL_DIR", "uv-tools"),
        ("npm_config_cache", "npm"),
        ("UV_PYTHON_INSTALL_DIR", "python"),
    ]
    .into_iter()
    .filter_map(|(name, sub)| {
        let dir = CanonicalPath::from_canonical(cache_root.as_path().join(sub)).ok()?;
        Some((EnvName::parse(name).ok()?, dir))
    })
    .collect()
}

/// The fixed (non-path) variables a warm run sets so uv builds a closed tree: see [`PRIVATE_PYTHON`].
#[must_use]
pub fn private_python_vars() -> Vec<(&'static str, &'static str)> {
    PRIVATE_PYTHON.to_vec()
}

/// Creates `path` (and missing parents) private to the user; an existing directory is left alone.
fn private_dir(path: &Path) -> Result<(), OfflineError> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .context(CreateDirSnafu { path })
}

fn write_script(path: &Path, text: &str) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(path)?;
    file.write_all(text.as_bytes())
}

/// `text` as one shell word in single quotes.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The uv settings that keep it on the interpreter inside the run's cache: managed Python only,
/// no download, and copied (not linked) files, so nothing resolves outside the cache.
const PRIVATE_PYTHON: [(&str, &str); 3] = [
    ("UV_PYTHON_PREFERENCE", "only-managed"),
    ("UV_PYTHON_DOWNLOADS", "never"),
    ("UV_LINK_MODE", "copy"),
];

/// The script for `kind`, which runs `real` from the run's own cache under `cache_root`.
///
/// There is no "not warmed" hint: a run with no usable cache generation never starts (it stops
/// before any launcher exists), so a launcher that runs always has a cache to read.
#[must_use]
pub fn script(kind: Launcher, real: &str, cache_root: &str) -> String {
    let cache = |sub: &str| quoted(&format!("{cache_root}/{sub}"));
    let env = match kind {
        Launcher::Uvx => {
            let fixed: String = PRIVATE_PYTHON
                .iter()
                .map(|(k, v)| format!("{k}={}\n", quoted(v)))
                .collect();
            let names: String = PRIVATE_PYTHON
                .iter()
                .map(|(k, _)| format!(" {k}"))
                .collect();
            format!(
                "UV_CACHE_DIR={}\nUV_TOOL_DIR={}\nUV_PYTHON_INSTALL_DIR={}\n{fixed}export UV_CACHE_DIR UV_TOOL_DIR UV_PYTHON_INSTALL_DIR{names}\n",
                cache("uv"),
                cache("uv-tools"),
                cache("python")
            )
        }
        Launcher::Npx => format!(
            "npm_config_cache={}\nexport npm_config_cache\n",
            cache("npm")
        ),
    };
    format!(
        "#!/bin/sh\n\
         # Written by hb for this run: starts {kind} from this run's own copy of hb's offline cache, with no registry.\n\
         {env}\
         exec {} --offline \"$@\"\n",
        quoted(real)
    )
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use claims::{assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    use super::*;
    use crate::config::{Policy, ResolvedMcpServer, merge};
    use crate::origin::{FileId, Source, Sourced};
    use crate::policy::{ArgWord, CanonicalPath, Floor, HomeDir, McpName, ToolName};
    use crate::system::{FoundTool, ToolLookup};

    fn canon(path: &Path) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
            path
        ))))
    }

    /// A policy with one server per `(name, command)`; `tools` become `[env] tools`.
    fn policy(servers: &[(&str, Option<&str>)], tools: &[&str]) -> Policy {
        let source = Source::value(FileId::new(0));
        let mut policy = assert_ok!(merge(&[], Floor::empty()));
        for (name, command) in servers {
            policy.mcp.insert(
                assert_ok!(McpName::parse(name)),
                Sourced::new(
                    ResolvedMcpServer {
                        command: command.map(|c| assert_ok!(ArgWord::parse_program(c))),
                        ..ResolvedMcpServer::default()
                    },
                    source,
                ),
            );
        }
        policy.env.tools = tools
            .iter()
            .map(|t| Sourced::new(assert_ok!(ToolName::parse(t)), source))
            .collect();
        policy
    }

    fn found(dir: &CanonicalPath, names: &[&str]) -> ToolLookup {
        ToolLookup {
            found: names
                .iter()
                .map(|n| FoundTool {
                    name: assert_ok!(ToolName::parse(n)),
                    dir: dir.clone(),
                })
                .collect(),
            missing: Vec::new(),
        }
    }

    #[test]
    fn nothing_is_planned_without_a_server_that_has_a_command() {
        let tmp = assert_ok!(tempfile::tempdir());
        let dir = canon(tmp.path());
        let home = HomeDir::new(dir.clone());
        let tools = found(&dir, &["uvx", "npx"]);
        for servers in [vec![], vec![("remote", None)]] {
            let p = policy(&servers, &["uvx", "npx"]);
            assert_none!(OfflinePlan::plan(&p, &tools, &home), "{servers:?}");
        }
    }

    #[test]
    fn a_launcher_is_planned_for_each_found_tool_and_only_those() {
        let tmp = assert_ok!(tempfile::tempdir());
        let dir = canon(tmp.path());
        let home = HomeDir::new(dir.clone());
        let p = policy(&[("time", Some("uvx"))], &["uvx"]);
        let plan = assert_some!(OfflinePlan::plan(&p, &found(&dir, &["uvx"]), &home));
        let names: Vec<String> = plan
            .launchers()
            .iter()
            .map(|l| l.kind().to_string())
            .collect();
        assert_eq!(names, ["uvx"]);
        assert_eq!(
            plan.cache_root(),
            home.path().as_path().join(".cache/hamster-ball")
        );
        assert!(plan.warnings().is_empty(), "{:?}", plan.warnings());
    }

    #[test]
    fn a_declared_bare_launcher_that_is_not_in_env_tools_is_warned_about_by_server_and_tool() {
        let tmp = assert_ok!(tempfile::tempdir());
        let dir = canon(tmp.path());
        let home = HomeDir::new(dir.clone());
        let p = policy(&[("ripgrep", Some("npx")), ("time", Some("uvx"))], &["uvx"]);
        let plan = assert_some!(OfflinePlan::plan(&p, &found(&dir, &["uvx"]), &home));
        let warnings = plan.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("[mcp.ripgrep]")
                && warnings[0].contains("`npx`")
                && warnings[0].contains("[env] tools"),
            "{warnings:?}"
        );
    }

    #[test]
    fn a_server_started_by_absolute_path_needs_no_launcher_and_no_warning() {
        let tmp = assert_ok!(tempfile::tempdir());
        let dir = canon(tmp.path());
        let home = HomeDir::new(dir.clone());
        let p = policy(&[("obscura", Some("/Users/me/.local/bin/obscura"))], &[]);
        let plan = assert_some!(OfflinePlan::plan(&p, &ToolLookup::default(), &home));
        assert!(plan.launchers().is_empty());
        assert!(plan.warnings().is_empty());
    }

    #[test]
    fn the_uvx_script_sets_the_uv_cache_variables_for_the_call_and_execs_offline() {
        let text = script(Launcher::Uvx, "/opt/uv/uvx", "/run/cache");
        assert!(text.starts_with("#!/bin/sh\n"), "{text}");
        for line in [
            "UV_CACHE_DIR='/run/cache/uv'",
            "UV_TOOL_DIR='/run/cache/uv-tools'",
            "UV_PYTHON_INSTALL_DIR='/run/cache/python'",
            "UV_PYTHON_PREFERENCE='only-managed'",
            "UV_PYTHON_DOWNLOADS='never'",
            "UV_LINK_MODE='copy'",
        ] {
            assert!(text.contains(line), "{line} missing: {text}");
        }
        assert!(!text.contains("npm_config_cache"), "{text}");
        assert!(
            text.ends_with("exec '/opt/uv/uvx' --offline \"$@\"\n"),
            "{text}"
        );
        assert!(
            !text.contains("hb warm") && !text.contains("warmed"),
            "a launcher only exists when a generation was copied, so there is no hint: {text}"
        );
    }

    #[test]
    fn the_npx_script_sets_the_npm_cache_for_the_call() {
        let text = script(Launcher::Npx, "/n/bin/npx", "/c");
        assert!(text.contains("npm_config_cache='/c/npm'"), "{text}");
        assert!(!text.contains("UV_CACHE_DIR"), "{text}");
        assert!(
            text.ends_with("exec '/n/bin/npx' --offline \"$@\"\n"),
            "{text}"
        );
    }

    #[test]
    fn a_path_with_a_quote_is_quoted_so_it_cannot_end_the_string() {
        let text = script(Launcher::Npx, "/n/it's/npx", "/c");
        assert!(text.contains("exec '/n/it'\\''s/npx' --offline"), "{text}");
    }

    #[test]
    fn installing_writes_private_executable_scripts_pointing_at_the_given_cache() {
        let tmp = assert_ok!(tempfile::tempdir());
        let base = canon(tmp.path());
        let home_dir = base.as_path().join("home");
        assert_ok!(fs::create_dir_all(&home_dir));
        let home = HomeDir::new(canon(&home_dir));
        let session = base.as_path().join("session");
        assert_ok!(fs::create_dir_all(&session));
        let tools_dir = base.as_path().join("tools");
        assert_ok!(fs::create_dir_all(&tools_dir));
        let p = policy(&[("time", Some("uvx"))], &["uvx", "npx"]);
        let plan = assert_some!(OfflinePlan::plan(
            &p,
            &found(&canon(&tools_dir), &["uvx", "npx"]),
            &home
        ));
        let cache = base.as_path().join("cache");
        for sub in CACHE_SUBDIRS {
            assert_ok!(fs::create_dir_all(cache.join(sub)));
        }
        let installed = assert_ok!(plan.install(&canon(&session), &canon(&cache)));
        let bin = installed.bin_dir().as_path().to_owned();
        assert_eq!(bin, canon(&session).as_path().join("bin"));
        for tool in ["uvx", "npx"] {
            let meta = assert_ok!(fs::metadata(bin.join(tool)));
            assert_eq!(meta.permissions().mode() & 0o777, 0o700, "{tool}");
        }
        assert_eq!(installed.cache_root().as_path(), canon(&cache).as_path());
        let uvx = assert_ok!(fs::read_to_string(bin.join("uvx")));
        assert!(
            uvx.contains(&format!("exec '{}/uvx' --offline", tools_dir.display())),
            "{uvx}"
        );
        assert!(
            uvx.contains(&format!("UV_CACHE_DIR='{}/uv'", canon(&cache).as_str())),
            "{uvx}"
        );
    }
}
