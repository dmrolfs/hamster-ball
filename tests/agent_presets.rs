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
/// under the world's home (an allow rule for a path that does not exist is skipped).
fn merged(name: &str, dirs: &[&str]) -> (World, Loaded) {
    let world = World::with_base(
        "[tls]\nsystem_trust = true\n",
        &format!("extends = [\"agent/{name}\"]\n"),
    );
    for dir in dirs {
        assert_ok!(fs::create_dir_all(world.home_dir().join(dir)));
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
