// ABOUTME: Opt-in: warms real MCP servers with `hb warm`'s code, then starts each in the ball offline and checks it answers `initialize`.
// ABOUTME: Nothing runs unless HB_MCP=1. Uses the real home, toolchain and hb's real cache (first run downloads), and the network.
//! Run with `HB_MCP=1 cargo test --features test-support --test mcp_offline -- --nocapture`.
//!
//! Variables: `HB_MCP_SERVERS` (comma-separated names, default all), `HB_MCP_BASE` (a file appended to the
//! private base config: `net.internal_hosts` for a corporate network), `HB_MCP_PROJECT` (appended to the project
//! config), `HB_MCP_TIMEOUT` (seconds per server, default 300), `HB_MCP_SERENA_REV` (a full git revision for
//! serena; default: HEAD, resolved with `git ls-remote`).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use claims::assert_ok;
use hamster_ball::config::{LoadRequest, Loaded, discover, load};
use hamster_ball::policy::CanonicalPath;
use hamster_ball::session::{DenialSink, ExitKind, RunSpec, SignalMode, run};
use hamster_ball::system::{Environment, StateDir, UserConfigDir};
use hamster_ball::warm::stamp::WarmStore;
use hamster_ball::warm::{self, Logging, Warmed, probe};

/// The measured servers: name, launcher, arguments.
const SERVERS: &[(&str, &str, &[&str])] = &[
    ("time", "uvx", &["mcp-server-time"]),
    ("fetch", "uvx", &["mcp-server-fetch"]),
    ("reddit", "npx", &["-y", "reddit-mcp-buddy"]),
    ("ripgrep", "npx", &["-y", "mcp-ripgrep@latest"]),
    ("browsermap", "npx", &["@browsermcp/mcp@latest"]),
    (
        "sequential-thinking",
        "npx",
        &["-y", "@modelcontextprotocol/server-sequential-thinking"],
    ),
];
/// A server that is never warmed, to see what a cold one says.
const COLD: (&str, &str, &[&str]) = ("cold-sample", "uvx", &["hb-mcp-test-no-such-package"]);
/// serena's dashboard listens on the first free port from 24282.
const SERENA_PORTS: [u16; 8] = [24282, 24283, 24284, 24285, 24286, 24287, 24288, 24289];
const SERENA_URL: &str = "https://github.com/oraios/serena";

/// One server to declare.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Declared {
    name: String,
    command: String,
    args: Vec<String>,
    bind_ports: Vec<u16>,
}

fn declared(name: &str, command: &str, args: &[&str]) -> Declared {
    Declared {
        name: name.to_owned(),
        command: command.to_owned(),
        args: args.iter().map(|a| (*a).to_owned()).collect(),
        bind_ports: Vec::new(),
    }
}

fn serena(revision: &str) -> Declared {
    Declared {
        bind_ports: SERENA_PORTS.to_vec(),
        ..declared(
            "serena",
            "uvx",
            &[
                "--from",
                &format!("git+{SERENA_URL}@{revision}"),
                "serena",
                "start-mcp-server",
            ],
        )
    }
}

/// The `[mcp.*]` tables for `servers`.
fn project_config(servers: &[Declared], extra: &str) -> String {
    let mut text = String::new();
    for server in servers {
        text.push_str(&format!("[mcp.{}]\n", server.name));
        text.push_str(&format!(
            "command = {}\n",
            common::toml_string(&server.command)
        ));
        let args: Vec<String> = server.args.iter().map(|a| common::toml_string(a)).collect();
        text.push_str(&format!("args = [{}]\n", args.join(", ")));
        if !server.bind_ports.is_empty() {
            let ports: Vec<String> = server.bind_ports.iter().map(u16::to_string).collect();
            text.push_str(&format!("bind_ports = [{}]\n", ports.join(", ")));
        }
        text.push('\n');
    }
    text.push_str(extra);
    text
}

/// What the machine has, as a preset the private base extends: the launchers, their runtimes and the git config.
fn defaults_preset(home: &Path) -> String {
    let reads: Vec<String> = [
        ".nvm",
        ".local/share/uv/python",
        ".gitconfig",
        ".config/git",
    ]
    .iter()
    .filter(|rel| home.join(rel).exists())
    .map(|rel| common::toml_string(&format!("~/{rel}")))
    .collect();
    let mut writes = vec![common::toml_string(".")];
    if home.join(".serena").exists() {
        writes.push(common::toml_string("~/.serena"));
    }
    format!(
        "[tls]\nsystem_trust = true\n[env]\ntools = [\"uvx\", \"npx\", \"node\"]\n[fs]\nread = [{}]\nwrite = [{}]\n",
        reads.join(", "),
        writes.join(", ")
    )
}

fn on_path(program: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join(program).is_file()))
}

struct Settings {
    enabled: bool,
    only: Option<Vec<String>>,
    base_extra: String,
    project_extra: String,
    limit: Duration,
    serena_rev: Option<String>,
}

fn read_var_file(name: &str) -> String {
    std::env::var_os(name)
        .map(|path| fs::read_to_string(PathBuf::from(path)).unwrap_or_default())
        .unwrap_or_default()
}

fn settings() -> Settings {
    let var = |name: &str| std::env::var(name).ok();
    Settings {
        enabled: var("HB_MCP").as_deref() == Some("1"),
        only: var("HB_MCP_SERVERS").map(|list| {
            list.split(',')
                .map(|name| name.trim().to_owned())
                .filter(|name| !name.is_empty())
                .collect()
        }),
        base_extra: read_var_file("HB_MCP_BASE"),
        project_extra: read_var_file("HB_MCP_PROJECT"),
        limit: Duration::from_secs(
            var("HB_MCP_TIMEOUT")
                .and_then(|text| text.parse().ok())
                .unwrap_or(300),
        ),
        serena_rev: var("HB_MCP_SERENA_REV"),
    }
}

fn private_dir(path: &Path) {
    assert_ok!(fs::create_dir_all(path));
    assert_ok!(fs::set_permissions(path, fs::Permissions::from_mode(0o700)));
}

fn private_file(path: &Path, text: &str) {
    assert_ok!(fs::write(path, text));
    assert_ok!(fs::set_permissions(path, fs::Permissions::from_mode(0o600)));
}

/// HEAD of serena, from the network, when no revision was given.
fn serena_head() -> Option<String> {
    let out = std::process::Command::new("/usr/bin/git")
        .args(["ls-remote", SERENA_URL, "HEAD"])
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let revision = text.split_whitespace().next()?.to_owned();
    (revision.len() == 40).then_some(revision)
}

/// Removes the stamps this test made, whatever happens.
struct Forget {
    store: WarmStore,
    root: CanonicalPath,
    names: Vec<String>,
}

impl Drop for Forget {
    fn drop(&mut self) {
        for name in &self.names {
            let _ = self.store.forget(&self.root, name);
        }
    }
}

fn line(label: &str, text: &str) {
    eprintln!("{label:<22} {text}");
}

#[test]
fn the_generated_config_is_valid_and_declares_every_server() {
    let servers: Vec<Declared> = SERVERS
        .iter()
        .map(|(n, c, a)| declared(n, c, a))
        .chain([declared(COLD.0, COLD.1, COLD.2), serena(&"a".repeat(40))])
        .collect();
    let base = format!(
        "{}[mcp.extra]\ncommand = \"uvx\"\n",
        defaults_preset(Path::new("/nonexistent"))
    );
    let w = common::World::with_base(&base, &project_config(&servers, ""));
    let loaded = w.loaded();
    let found = warm::servers(&loaded.policy);
    let names: Vec<&str> = found.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "browsermap",
            "cold-sample",
            "extra",
            "fetch",
            "reddit",
            "ripgrep",
            "sequential-thinking",
            "serena",
            "time"
        ]
    );
    let serena = found.iter().find(|s| s.name == "serena");
    assert!(
        serena.is_some_and(|s| s
            .allowlist
            .iter()
            .any(|r| r.pattern.to_string() == "github.com")),
        "serena's git source adds github to its warm hosts"
    );
}

#[test]
fn measured_mcp_servers_start_offline_after_hb_warm() {
    let settings = settings();
    if !settings.enabled {
        eprintln!("SKIP: set HB_MCP=1 to warm and run the real MCP servers");
        return;
    }
    let env = assert_ok!(Environment::from_process());
    let home = env.home.path().as_path().to_owned();
    let mut skipped = Vec::new();
    let mut servers: Vec<Declared> = Vec::new();
    for (name, command, args) in SERVERS {
        let wanted = settings
            .only
            .as_ref()
            .is_none_or(|only| only.iter().any(|o| o == name));
        let runtime_ok = on_path(command) && (*command == "uvx" || on_path("node"));
        match (wanted, runtime_ok) {
            (false, _) => {}
            (true, false) => skipped.push(format!("{name}: {command} or node is not on PATH")),
            (true, true) => servers.push(declared(name, command, args)),
        }
    }
    let wants_serena = settings
        .only
        .as_ref()
        .is_none_or(|only| only.iter().any(|o| o == "serena"));
    if wants_serena {
        match (home.join(".serena").exists(), on_path("uvx")) {
            (false, _) => skipped.push("serena: ~/.serena does not exist".to_owned()),
            (_, false) => skipped.push("serena: uvx is not on PATH".to_owned()),
            _ => match settings.serena_rev.clone().or_else(serena_head) {
                Some(revision) => servers.push(serena(&revision)),
                None => skipped.push("serena: no revision (set HB_MCP_SERENA_REV)".to_owned()),
            },
        }
    }
    for note in &skipped {
        line("skipped", note);
    }
    if servers.is_empty() {
        eprintln!("SKIP: nothing to check");
        return;
    }
    servers.push(declared(COLD.0, COLD.1, COLD.2));

    let work = assert_ok!(tempfile::tempdir());
    let project = work.path().join("project");
    let user = work.path().join("user");
    private_dir(&project);
    private_dir(&user.join("presets"));
    private_file(
        &user.join("presets/mcp-defaults.toml"),
        &defaults_preset(&home),
    );
    private_file(
        &user.join("base.toml"),
        &format!("extends = [\"mcp-defaults\"]\n{}", settings.base_extra),
    );
    private_file(
        &project.join("hamster-ball.toml"),
        &project_config(&servers, &settings.project_extra),
    );
    let mut env = env;
    env.cwd = assert_ok!(fs::canonicalize(&project));
    let discovery = assert_ok!(discover(&env.cwd, &env.home));
    let loaded: Loaded = assert_ok!(load(&LoadRequest::new(
        &env.home,
        &discovery,
        &UserConfigDir::at(&user),
        &env.floor
    )));
    let root = assert_ok!(CanonicalPath::from_canonical(&env.cwd));
    let store = WarmStore::new(&StateDir::locate(&env.home));
    let _forget = Forget {
        store: store.clone(),
        root: root.clone(),
        names: servers.iter().map(|s| s.name.clone()).collect(),
    };
    let mut problems: Vec<String> = Vec::new();

    // 1. Before warming, every server is cold and the warning says what to do.
    let cold = warm::cold_warnings(&loaded.policy, &store, &root);
    if cold.len() != servers.len() || !cold.iter().all(|w| w.contains("run hb warm")) {
        problems.push(format!(
            "expected one `run hb warm` warning per server: {cold:?}"
        ));
    }

    // 2. hb warm, for every server but the cold sample.
    let selected = warm::servers(&loaded.policy);
    let mut warmed: Vec<String> = Vec::new();
    for server in selected.iter().filter(|s| s.name != COLD.0) {
        let started = Instant::now();
        match warm::warm_server(
            &env,
            &loaded,
            server,
            settings.limit,
            SignalMode::Off,
            Logging::default(),
        ) {
            Ok((Warmed::Answered { .. }, _)) => match warm::record_success(&env, &root, server) {
                Ok(()) => {
                    warmed.push(server.name.clone());
                    line(
                        &format!("warm {}", server.name),
                        &format!("answered in {} s", started.elapsed().as_secs()),
                    );
                }
                Err(message) => problems.push(format!("warm {}: {message}", server.name)),
            },
            Ok((Warmed::Failed { why }, _)) => {
                problems.push(format!("warm {} failed:\n{why}", server.name))
            }
            Err(error) => problems.push(format!("warm {}: {error}", server.name)),
        }
    }

    // 3. Only the cold sample is still cold.
    let still = warm::cold_warnings(&loaded.policy, &store, &root);
    let only_cold =
        still.len() == 1 && still[0].contains(COLD.0) && still[0].contains("run hb warm");
    if problems.is_empty() && !only_cold {
        problems.push(format!(
            "after warming only {} should be cold: {still:?}",
            COLD.0
        ));
    }

    // 4. Each warmed server answers initialize in a run, with the registries closed.
    for server in selected.iter().filter(|s| warmed.contains(&s.name)) {
        let spec = RunSpec::new(probe::argv(settings.limit, &server.command, &server.args))
            .proxy_log(DenialSink::Collect)
            .proxy_summary(false);
        let started = Instant::now();
        match run(&env, &loaded, &spec) {
            Err(error) => problems.push(format!("run {}: {error}", server.name)),
            Ok(outcome) => {
                let stderr = String::from_utf8_lossy(&outcome.stderr).into_owned();
                let connections = &outcome.proxy_log.lines;
                let allowed: Vec<&String> = connections
                    .iter()
                    .filter(|l| l.starts_with("allowed "))
                    .collect();
                line(
                    &format!("run {}", server.name),
                    &format!(
                        "{:?} in {} s, {} proxy line(s)",
                        outcome.exit,
                        started.elapsed().as_secs(),
                        connections.len()
                    ),
                );
                for refused in connections.iter().filter(|l| !l.starts_with("allowed ")) {
                    line("  refused", refused);
                }
                if outcome.exit != ExitKind::Exited(0) {
                    problems.push(format!("run {} did not answer:\n{stderr}", server.name));
                }
                let strict = server.name != "serena";
                if (strict && !connections.is_empty()) || !allowed.is_empty() {
                    problems.push(format!(
                        "run {} used the network: {connections:?}",
                        server.name
                    ));
                }
            }
        }
    }

    // 5. A package that was never cached fails offline with the tool's own words.
    if let Some(cold_server) = selected.iter().find(|s| s.name == COLD.0) {
        let spec = RunSpec::new(probe::argv(
            Duration::from_secs(60),
            &cold_server.command,
            &cold_server.args,
        ))
        .proxy_log(DenialSink::Collect)
        .proxy_summary(false);
        match run(&env, &loaded, &spec) {
            Err(error) => problems.push(format!("run {}: {error}", cold_server.name)),
            Ok(outcome) => {
                let stderr = String::from_utf8_lossy(&outcome.stderr).into_owned();
                line(
                    &format!("cold {}", cold_server.name),
                    &format!("{:?}", outcome.exit),
                );
                if outcome.exit == ExitKind::Exited(0) || !stderr.contains("network was disabled") {
                    problems.push(format!(
                        "the cold server should fail with uv's own text:\n{stderr}"
                    ));
                }
            }
        }
    }

    assert!(problems.is_empty(), "\n{}", problems.join("\n\n"));
}
