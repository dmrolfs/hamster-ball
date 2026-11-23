// ABOUTME: Opt-in: runs each installed agent CLI under its built-in preset with the real proxy and checks it worked.
// ABOUTME: Nothing runs unless HB_CONFORMANCE=1; an agent that is not installed, or has no preset yet, is skipped.
//! Run with `HB_CONFORMANCE=1 cargo test --features test-support --test conformance -- --nocapture`.
//!
//! This spends real requests on the agents' models. See `presets/README.md` for the variables that
//! give a check what its preset leaves to you (`HB_CONFORMANCE_PROJECT`, `HB_CONFORMANCE_BASE`,
//! `HB_CONFORMANCE_TIMEOUT`, `HB_CONFORMANCE_ARGS_<AGENT>`).

#![cfg(target_os = "macos")]

use claims::{assert_ok, assert_some};
use hamster_ball::config::EmbeddedPresets;
use hamster_ball::conformance::{AGENTS, Context, Settings, run_agent};
use hamster_ball::system::Environment;

fn check(name: &str) {
    let settings = assert_ok!(Settings::from_process());
    let agent = assert_some!(AGENTS.iter().find(|a| a.name == name));
    let env = assert_ok!(Environment::from_process());
    let verdict = run_agent(
        agent,
        &Context {
            env: &env,
            builtins: &EmbeddedPresets,
            settings: &settings,
        },
    );
    eprintln!("{verdict}");
    assert!(!verdict.is_failure(), "{name} did not conform");
}

#[test]
fn claude_conforms_to_its_preset() {
    check("claude");
}

#[test]
fn kiro_conforms_to_its_preset() {
    check("kiro");
}

#[test]
fn opencode_conforms_to_its_preset() {
    check("opencode");
}

#[test]
fn pi_conforms_to_its_preset() {
    check("pi");
}
