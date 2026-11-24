// ABOUTME: What each built-in agent preset grants once merged with a base config: its own state, no provider hosts.
// ABOUTME: Offline and agent-free; the opt-in conformance run (tests/conformance.rs) proves a preset against the real agent.
//! The merged policy of each shipped agent preset.

#![cfg(target_os = "macos")]

mod common;

use std::fs;

use claims::assert_ok;
use common::World;
use hamster_ball::config::{EmbeddedPresets, LoadRequest, Loaded, discover, load};
use hamster_ball::system::UserConfigDir;
use pretty_assertions::assert_eq;

/// Merges `extends = ["agent/<name>"]` with a base that turns system trust on, after creating `dirs`
/// under the world's home (an allow rule for a path that does not exist is skipped). An entry that
/// ends in `.json` is made a file.
fn merged(name: &str, dirs: &[&str]) -> (World, Loaded) {
    let world = World::with_base(
        "[tls]\nsystem_trust = true\n",
        &format!("extends = [\"agent/{name}\"]\n"),
    );
    for dir in dirs {
        let path = world.home_dir().join(dir);
        if dir.ends_with(".json") {
            assert_ok!(fs::write(path, "{}"));
        } else {
            assert_ok!(fs::create_dir_all(path));
        }
    }
    let discovery = assert_ok!(discover(&world.project, &world.home));
    let user = UserConfigDir::locate(&world.home);
    let loaded = assert_ok!(load(
        &LoadRequest::new(&world.home, &discovery, &user, &world.env.floor)
            .with_builtins(&EmbeddedPresets)
    ));
    (world, loaded)
}

fn write_grants(world: &World, loaded: &Loaded) -> Vec<String> {
    let home = world.home.path().as_str().to_owned();
    loaded
        .policy
        .fs
        .write
        .iter()
        .map(|w| w.value.as_str().replace(&home, "~"))
        .filter(|w| w.starts_with('~'))
        .collect()
}

#[test]
fn the_kiro_preset_writes_its_own_state_not_its_programs_and_reaches_only_its_own_hosts() {
    let (world, loaded) = merged("kiro", &[".kiro", "Library/Application Support/kiro-cli"]);
    assert_eq!(
        write_grants(&world, &loaded),
        ["~/.kiro", "~/Library/Application Support/kiro-cli"]
    );
    let hosts: Vec<String> = loaded
        .policy
        .net
        .allow
        .iter()
        .map(|rule| format!("{}:{}", rule.value.pattern, rule.value.port.get()))
        .collect();
    let denied: Vec<String> = loaded
        .policy
        .fs
        .deny_write
        .iter()
        .map(|d| format!("{:?}", d.value))
        .collect();
    for program in [
        "/kiro-cli/node",
        "/kiro-cli/bun",
        "/kiro-cli/tui.js",
        "/kiro-cli/kas",
    ] {
        assert!(
            denied.iter().any(|d| d.contains(program)),
            "{program}: {denied:?}"
        );
    }
    assert_eq!(hosts.len(), 6, "{hosts:?}");
    assert!(
        hosts
            .iter()
            .all(|h| h.ends_with(":443") && !h.contains('*'))
    );
    assert!(hosts.iter().any(|h| h == "app.kiro.dev:443"), "{hosts:?}");
}

#[test]
fn the_pi_preset_writes_its_state_but_not_the_launcher_and_names_no_provider() {
    let (world, loaded) = merged("pi", &[".pi/agent"]);
    assert_eq!(write_grants(&world, &loaded), ["~/.pi/agent"]);
    let denied: Vec<String> = loaded
        .policy
        .fs
        .deny_write
        .iter()
        .map(|d| format!("{:?}", d.value))
        .collect();
    for path in ["/.pi/agent/bin", "/.pi/agent/install"] {
        assert!(
            denied.iter().any(|d| d.contains(path)),
            "{path}: {denied:?}"
        );
    }
    assert!(loaded.policy.net.allow.is_empty());
    assert!(loaded.policy.net.loopback_ports.is_empty());
    let tools: Vec<&str> = loaded
        .policy
        .env
        .tools
        .iter()
        .map(|t| t.value.as_str())
        .collect();
    assert_eq!(tools, ["node"]);
}

#[test]
fn the_claude_preset_writes_its_state_reaches_three_bedrock_hosts_and_has_no_hook() {
    let (world, loaded) = merged(
        "claude",
        &[
            ".claude",
            ".claude.json",
            ".cache/claude",
            ".local/state/claude",
        ],
    );
    let mut writes = write_grants(&world, &loaded);
    writes.sort();
    assert_eq!(
        writes,
        [
            "~/.cache/claude",
            "~/.claude",
            "~/.claude.json",
            "~/.local/state/claude"
        ]
    );
    let hosts: Vec<String> = loaded
        .policy
        .net
        .allow
        .iter()
        .map(|rule| format!("{}:{}", rule.value.pattern, rule.value.port.get()))
        .collect();
    assert_eq!(
        hosts,
        [
            "bedrock-runtime.us-east-1.amazonaws.com:443",
            "bedrock.us-east-1.amazonaws.com:443",
            "sts.us-east-1.amazonaws.com:443"
        ]
    );
    let set: Vec<(&str, &str)> = loaded
        .policy
        .env
        .set
        .iter()
        .map(|(name, value)| (name.as_str(), value.value.as_str()))
        .collect();
    assert!(
        set.contains(&("CLAUDE_CODE_TMPDIR", "{session_dir}")),
        "{set:?}"
    );
    assert!(set.contains(&("DISABLE_AUTOUPDATER", "1")), "{set:?}");
    assert!(
        loaded.policy.hooks.is_empty(),
        "the credential command is the user's, not the preset's"
    );
    let tmp_grants = loaded
        .policy
        .fs
        .write
        .iter()
        .filter(|w| w.value.as_str().starts_with("/private/tmp") || w.value.as_str() == "/tmp")
        .count();
    assert_eq!(tmp_grants, 0);
}

#[test]
fn the_opencode_preset_reads_its_config_and_program_writes_its_state_and_not_what_it_executes() {
    let (world, loaded) = merged(
        "opencode",
        &[
            ".config/opencode",
            ".local/share/opencode",
            ".cache/opencode",
            ".local/state/opencode",
        ],
    );
    let mut writes = write_grants(&world, &loaded);
    writes.sort();
    assert_eq!(
        writes,
        [
            "~/.cache/opencode",
            "~/.local/share/opencode",
            "~/.local/state/opencode"
        ]
    );
    let home = world.home.path().as_str().to_owned();
    let reads: Vec<String> = loaded
        .policy
        .fs
        .read
        .iter()
        .map(|r| r.value.as_str().replace(&home, "~"))
        .collect();
    assert!(reads.iter().any(|r| r == "~/.config/opencode"), "{reads:?}");
    assert!(
        !reads
            .iter()
            .any(|r| r == "/opt/homebrew" || r.contains(".bun")),
        "{reads:?}"
    );
    let denied: Vec<String> = loaded
        .policy
        .fs
        .deny_write
        .iter()
        .map(|d| format!("{:?}", d.value))
        .collect();
    for path in [
        "/.cache/opencode/node_modules",
        "/.cache/opencode/package.json",
        "/.cache/opencode/bun.lock",
        "/.local/share/opencode/bin",
    ] {
        assert!(
            denied.iter().any(|d| d.contains(path)),
            "{path}: {denied:?}"
        );
    }
    let hosts: Vec<String> = loaded
        .policy
        .net
        .allow
        .iter()
        .map(|rule| format!("{}:{}", rule.value.pattern, rule.value.port.get()))
        .collect();
    assert_eq!(hosts, ["models.dev:443", "opencode.ai:443"]);
    assert!(loaded.policy.hooks.is_empty());
}
