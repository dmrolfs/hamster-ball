// ABOUTME: What the approval prompt lists: the project's additions beyond the base, and nothing the base also gives.
// ABOUTME: Real config loading with the built-in presets; no sandbox and no agent.
//! The grant summary of a project.

#![cfg(target_os = "macos")]

mod common;

use claims::{assert_ok, assert_some_eq};
use common::World;
use hamster_ball::approval::GrantSummary;
use hamster_ball::config::{EmbeddedPresets, LoadRequest, discover, load};
use hamster_ball::system::UserConfigDir;
use pretty_assertions::assert_eq;

fn summary(base: &str, project: &str) -> GrantSummary {
    let world = World::with_base(base, project);
    let discovery = assert_ok!(discover(&world.project, &world.home));
    let user = UserConfigDir::locate(&world.home);
    let loaded = assert_ok!(load(
        &LoadRequest::new(&world.home, &discovery, &user, &world.env.floor)
            .with_builtins(&EmbeddedPresets)
    ));
    GrantSummary::for_project(&world.env, &discovery, &loaded)
}

/// `setting value (from ...)` for each addition, as the prompt shows them.
fn shown(summary: &GrantSummary) -> Vec<String> {
    summary
        .additions()
        .iter()
        .map(|a| format!("{} {} ({})", a.setting, a.value, a.from))
        .collect()
}

#[test]
fn a_project_that_adds_nothing_says_so() {
    let summary = summary("", "");
    assert!(summary.is_empty(), "{:?}", shown(&summary));
    assert_eq!(
        summary.to_string(),
        "This project adds nothing beyond your base config.\n"
    );
}

#[test]
fn what_the_project_declares_is_listed_with_the_file_that_declares_it() {
    let summary = summary(
        "",
        "[net]\nallow = [\"api.example.com\"]\nloopback_ports = [3030]\n[env]\nset = { MODE = \"fast\" }\n",
    );
    assert_eq!(
        shown(&summary),
        [
            "net.allow api.example.com:443 (hamster-ball.toml)",
            "net.loopback_ports 3030 (hamster-ball.toml)",
            "env.set MODE=fast (hamster-ball.toml)",
        ]
    );
}

#[test]
fn a_value_the_base_also_gives_is_not_an_addition() {
    let summary = summary(
        "[net]\nallow = [\"a.example.com\", \"shared.example.com\"]\n",
        "[net]\nallow = [\"shared.example.com\", \"b.example.com\"]\n",
    );
    assert_eq!(
        shown(&summary),
        ["net.allow b.example.com:443 (hamster-ball.toml)"]
    );
}

#[test]
fn what_a_named_preset_grants_is_an_addition_unless_the_base_extends_it_too() {
    let by_project = summary("", "extends = [\"agent/kiro\"]\n");
    let hosts: Vec<&str> = by_project
        .additions()
        .iter()
        .filter(|a| a.setting == "net.allow")
        .map(|a| a.value.as_str())
        .collect();
    assert!(hosts.contains(&"app.kiro.dev:443"), "{hosts:?}");
    assert!(
        by_project
            .additions()
            .iter()
            .all(|a| a.from == "agent/kiro"),
        "{:?}",
        shown(&by_project)
    );

    let by_base = summary(
        "extends = [\"agent/kiro\"]\n",
        "extends = [\"agent/kiro\"]\n",
    );
    assert!(by_base.is_empty(), "{:?}", shown(&by_base));
}

#[test]
fn an_mcp_servers_arguments_and_hosts_are_shown_because_they_decide_what_runs() {
    let summary = summary(
        "",
        "[mcp.docs]\ncommand = \"uvx\"\nargs = [\"--from\", \"git+https://example.com/x\", \"serve\"]\nnet = [\"example.com\"]\nbind_ports = [8123]\n",
    );
    assert!(!summary.is_empty());
    let line = shown(&summary)
        .into_iter()
        .find(|l| l.starts_with("mcp "))
        .unwrap_or_default();
    assert!(
        line.contains("docs = uvx --from git+https://example.com/x serve")
            && line.contains("net: example.com")
            && line.contains("listens on: 8123"),
        "{line}"
    );
}

#[test]
fn a_server_with_no_hosts_or_ports_is_shown_without_empty_clauses() {
    let summary = summary("", "[mcp.local]\ncommand = \"tool\"\n");
    let line = shown(&summary)
        .into_iter()
        .find(|l| l.starts_with("mcp "))
        .unwrap_or_default();
    assert_eq!(line, "mcp local = tool (hamster-ball.toml)");
}

#[test]
fn the_projects_own_denies_are_listed_and_the_floors_are_not() {
    let plain = summary("", "");
    assert!(plain.additions().iter().all(|a| a.setting != "deny"));
    let with = summary("", "[fs]\ndeny_read = [\"config/*.secrets.yaml\"]\n");
    let denies: Vec<&str> = with
        .additions()
        .iter()
        .filter(|a| a.setting == "deny")
        .map(|a| a.value.as_str())
        .collect();
    assert_eq!(denies.len(), 1, "{denies:?}");
    assert!(
        denies[0].starts_with("deny_read_write ") && denies[0].ends_with("/config/*.secrets.yaml"),
        "{denies:?}"
    );
}

#[test]
fn terminal_control_characters_in_a_value_are_escaped_in_what_is_printed() {
    let summary = summary("", "[env]\nset = { X = \"a\\u001b[31mred\\nnext\" }\n");
    let text = summary.to_string();
    assert!(!text.contains('\u{1b}'), "{text:?}");
    assert!(text.contains("\\u{1b}"), "{text:?}");
    assert_eq!(text.lines().count(), 2, "{text:?}");
}

#[test]
fn a_long_value_is_printed_whole_so_a_suffix_cannot_hide() {
    // Over the old 300-character cut, under the review limit: the end must be on screen.
    let long = format!("{}EVIL-SUFFIX", "x".repeat(1500));
    let summary = summary("", &format!("[env]\nset = {{ X = \"{long}\" }}\n"));
    let line = summary.to_string();
    assert!(line.contains("EVIL-SUFFIX"), "{line}");
    assert!(!line.contains("..."), "{line}");
    assert_eq!(summary.too_long(), None);
}

#[test]
fn a_value_past_the_review_limit_is_not_offered_for_approval() {
    let long = "x".repeat(hamster_ball::approval::MAX_VALUE_CHARS + 1);
    let summary = summary("", &format!("[env]\nset = {{ X = \"{long}\" }}\n"));
    assert_some_eq!(summary.too_long(), "env.set");
}

#[test]
fn arguments_keep_their_boundaries_so_one_argument_cannot_pass_for_two() {
    let one = summary(
        "",
        "[mcp.a]\ncommand = \"tool\"\nargs = [\"-c\", \"echo hi; rm -rf x\"]\n",
    );
    let two = summary(
        "",
        "[mcp.a]\ncommand = \"tool\"\nargs = [\"-c\", \"echo\", \"hi;\", \"rm\", \"-rf\", \"x\"]\n",
    );
    let value = |s: &GrantSummary| {
        s.additions()
            .iter()
            .find(|a| a.setting == "mcp")
            .map(|a| a.value.clone())
            .unwrap_or_default()
    };
    assert_eq!(value(&one), "a = tool -c 'echo hi; rm -rf x'");
    assert_eq!(value(&two), "a = tool -c echo 'hi;' rm -rf x");
}

#[test]
fn a_hook_the_project_selects_by_extending_a_user_preset_is_listed_for_approval() {
    let world = World::new("extends = [\"tool\"]\n");
    common::write(
        &world
            .home_dir()
            .join(".config/hamster-ball/presets/tool.toml"),
        "[hooks.pre_run.fetch]\ncommand = [\"/usr/local/bin/fetch\", \"--fast\"]\n",
    );
    let discovery = assert_ok!(discover(&world.project, &world.home));
    let user = UserConfigDir::locate(&world.home);
    let loaded = assert_ok!(load(
        &LoadRequest::new(&world.home, &discovery, &user, &world.env.floor)
            .with_builtins(&EmbeddedPresets)
    ));
    let summary = GrantSummary::for_project(&world.env, &discovery, &loaded);
    assert_eq!(
        shown(&summary),
        ["hooks fetch: /usr/local/bin/fetch --fast (tool)"]
    );
}
