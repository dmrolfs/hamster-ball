// ABOUTME: `hb warm` end to end through hb-testdrive with a fake `uvx` that acts as an MCP server and records how it was started.
// ABOUTME: Real sandbox: the registries-only allowlist, the cache and no `--offline`, stamps and the marker, failures, refusals, and the `hb run` warning.
//! `hb warm` (hb-ghd.7.3).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;

use claims::assert_ok;
use common::{World, sandbox_available, write};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const BASE: &str =
    "[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\"]\n[net]\nallow = [\"run-only.invalid\"]\n";
const PROJECT: &str = "[mcp.time]\ncommand = \"uvx\"\nargs = [\"mcp-server-time\"]\nwarm_net = [\"mcp-warm.invalid\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// A fake `uvx` that records its start in `seen.txt`, touches both hosts, then answers `initialize`.
fn fake_uvx(w: &World, answer: bool) {
    let path = w.base.join("bin/uvx");
    let body = if answer {
        "read line\necho '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}'\nsleep 20\n"
    } else {
        "echo 'boom: no such package' >&2\nexit 3\n"
    };
    write(
        &path,
        &format!(
            "#!/bin/sh\n\
             {{ echo \"args=$*\"; echo \"uv_cache=${{UV_CACHE_DIR:-unset}}\"; echo \"tool_dir=${{UV_TOOL_DIR:-unset}}\"; echo \"npm=${{npm_config_cache:-unset}}\"; }} >> seen.txt\n\
             /usr/bin/curl -sS -m 5 https://mcp-warm.invalid/ >/dev/null 2>&1\n\
             /usr/bin/curl -sS -m 5 https://run-only.invalid/ >/dev/null 2>&1\n\
             {body}"
        ),
    );
    assert_ok!(fs::set_permissions(
        &path,
        fs::Permissions::from_mode(0o755)
    ));
}

fn world(project: &str, answer: bool) -> World {
    let w = World::with_base(BASE, project);
    fake_uvx(&w, answer);
    w
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn hb(w: &World, args: &[&str]) -> Ran {
    let out = assert_ok!(w.drive(DRIVE, args).stdin(Stdio::null()).output());
    ran(&out)
}

fn ran(out: &std::process::Output) -> Ran {
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn cache(w: &World) -> PathBuf {
    w.home_dir().join(".cache/hamster-ball")
}

fn stamps(w: &World) -> usize {
    fs::read_dir(w.home_dir().join(".local/state/hamster-ball/warm"))
        .map(|d| d.filter_map(Result::ok).count())
        .unwrap_or(0)
}

fn seen(w: &World) -> String {
    fs::read_to_string(w.project.join("seen.txt")).unwrap_or_default()
}

#[test]
fn warming_starts_the_server_online_with_hbs_cache_stamps_it_and_marks_the_cache() {
    sandboxed!();
    let w = world(PROJECT, true);
    let out = hb(&w, &["warm"]);
    assert_eq!(out.code, Some(0), "{}{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("warmed time"), "{}", out.stdout);
    let seen = seen(&w);
    let root = fs::canonicalize(cache(&w)).unwrap_or_else(|_| cache(&w));
    assert!(
        seen.contains("args=mcp-server-time\n"),
        "no --offline: {seen}"
    );
    assert!(
        seen.contains(&format!("uv_cache={}/uv\n", root.display())),
        "{seen}"
    );
    assert!(
        seen.contains(&format!("tool_dir={}/uv-tools\n", root.display())),
        "{seen}"
    );
    assert!(
        seen.contains(&format!("npm={}/npm\n", root.display())),
        "{seen}"
    );
    assert!(
        cache(&w).join("warmed").exists(),
        "the marker the launchers test"
    );
    assert_eq!(stamps(&w), 1);
}

#[test]
fn the_warm_session_allows_the_servers_warm_hosts_and_not_the_runs_and_a_run_does_the_reverse() {
    sandboxed!();
    let w = world(PROJECT, true);
    let warm = hb(&w, &["warm", "--log-proxy"]);
    let about = |text: &str, host: &str| -> String {
        text.lines()
            .filter(|l| l.contains("proxy:") && l.contains(host))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        !about(&warm.stderr, "mcp-warm.invalid").contains("not_allowed"),
        "{}",
        warm.stderr
    );
    assert!(
        !about(&warm.stderr, "mcp-warm.invalid").is_empty(),
        "{}",
        warm.stderr
    );
    assert!(
        about(&warm.stderr, "run-only.invalid").contains("not_allowed"),
        "{}",
        warm.stderr
    );
    let run = hb(
        &w,
        &[
            "run",
            "--log-proxy",
            "--",
            "/bin/sh",
            "-c",
            "/usr/bin/curl -sS -m 5 https://mcp-warm.invalid/ >/dev/null 2>&1; /usr/bin/curl -sS -m 5 https://run-only.invalid/ >/dev/null 2>&1",
        ],
    );
    assert!(
        about(&run.stderr, "mcp-warm.invalid").contains("not_allowed"),
        "{}",
        run.stderr
    );
    assert!(
        !about(&run.stderr, "run-only.invalid").contains("not_allowed"),
        "{}",
        run.stderr
    );
}

#[test]
fn a_server_that_fails_prints_its_own_words_and_leaves_no_stamp_or_marker() {
    sandboxed!();
    let w = world(PROJECT, false);
    let out = hb(&w, &["warm"]);
    assert_eq!(out.code, Some(1), "{}{}", out.stdout, out.stderr);
    let all = format!("{}{}", out.stdout, out.stderr);
    assert!(all.contains("FAILED time"), "{all}");
    assert!(all.contains("boom: no such package"), "{all}");
    assert_eq!(stamps(&w), 0);
    assert!(!cache(&w).join("warmed").exists());
}

#[test]
fn run_warns_until_the_server_is_warmed_and_again_when_its_command_changes() {
    sandboxed!();
    let w = world(PROJECT, true);
    let cold = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert!(
        cold.stderr.contains(
            "warning: mcp server time has not been warmed (or its command changed): run hb warm"
        ),
        "{}",
        cold.stderr
    );
    assert_eq!(hb(&w, &["warm"]).code, Some(0));
    let warm = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert!(
        !warm.stderr.contains("has not been warmed"),
        "{}",
        warm.stderr
    );
    w.set_project(&PROJECT.replace("mcp-server-time", "mcp-server-fetch"));
    let changed = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert!(
        changed
            .stderr
            .contains("mcp server time has not been warmed"),
        "{}",
        changed.stderr
    );
}

#[test]
fn only_uvx_and_npx_servers_are_warmed_or_warned_about() {
    sandboxed!();
    let w = world("[mcp.local]\ncommand = \"/usr/bin/true\"\n", true);
    let run = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert!(
        !run.stderr.contains("has not been warmed"),
        "{}",
        run.stderr
    );
    let warm = hb(&w, &["warm", "local"]);
    assert_eq!(warm.code, Some(0), "{}{}", warm.stdout, warm.stderr);
    assert!(warm.stdout.contains("nothing to warm"), "{}", warm.stdout);
    assert_eq!(stamps(&w), 0);
}

#[test]
fn an_unknown_server_name_is_an_error_that_lists_what_can_be_warmed() {
    sandboxed!();
    let w = world(PROJECT, true);
    let out = hb(&w, &["warm", "nosuch"]);
    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("nosuch") && out.stderr.contains("time"),
        "{}",
        out.stderr
    );
}

#[test]
fn warm_needs_an_approved_config_and_refuses_inside_a_ball() {
    sandboxed!();
    let w = world(PROJECT, true);
    let mut unapproved = w.drive_unapproved(DRIVE, &["warm"]);
    let out = ran(&assert_ok!(unapproved.stdin(Stdio::null()).output()));
    assert_eq!(out.code, Some(78), "{}", out.stderr);
    let mut inside = w.drive(DRIVE, &["warm"]);
    let out = ran(&assert_ok!(
        inside.env("HB_SESSION", "1").stdin(Stdio::null()).output()
    ));
    assert_eq!(out.code, Some(1), "{}", out.stderr);
    assert!(out.stderr.contains("outside the ball"), "{}", out.stderr);
    assert_eq!(stamps(&w), 0);
}

#[test]
fn a_declaration_with_no_servers_says_there_is_nothing_to_warm() {
    sandboxed!();
    let w = world("", true);
    let out = hb(&w, &["warm"]);
    assert_eq!(out.code, Some(0), "{}{}", out.stdout, out.stderr);
    assert!(out.stdout.contains("nothing to warm"), "{}", out.stdout);
}

fn explain_json(w: &World) -> serde_json::Value {
    let out = assert_ok!(w.drive(DRIVE, &["explain", "--format", "json"]).output());
    assert_ok!(serde_json::from_slice(&out.stdout))
}

fn status_of(json: &serde_json::Value, name: &str) -> String {
    json["offline"]["servers"]
        .as_array()
        .and_then(|all| all.iter().find(|s| s["name"] == name))
        .and_then(|s| s["status"].as_str())
        .unwrap_or("missing")
        .to_owned()
}

#[test]
fn explain_shows_each_servers_warm_status_as_it_changes() {
    sandboxed!();
    let w = world(PROJECT, true);
    assert_eq!(status_of(&explain_json(&w), "time"), "not warmed");
    assert_eq!(hb(&w, &["warm"]).code, Some(0));
    assert_eq!(status_of(&explain_json(&w), "time"), "warmed");
    w.set_project(&PROJECT.replace("mcp-server-time", "mcp-server-fetch"));
    assert_eq!(status_of(&explain_json(&w), "time"), "changed");
    let text = assert_ok!(w.drive(DRIVE, &["explain"]).output());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("time") && text.contains("changed"), "{text}");
}

#[test]
fn a_git_config_the_ball_cannot_read_is_warned_about_by_run_and_explain_until_it_is_granted() {
    sandboxed!();
    let w = World::with_base("[fs]\nwrite = [\".\"]\n", "");
    write(&w.home_dir().join(".gitconfig"), "[user]\n\tname = t\n");
    let run = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert!(
        run.stderr.contains("git inside the ball will fail") && run.stderr.contains("~/.gitconfig"),
        "{}",
        run.stderr
    );
    let json = explain_json(&w);
    let kinds: Vec<&str> = json["warnings"]
        .as_array()
        .map(|all| all.iter().filter_map(|x| x["kind"].as_str()).collect())
        .unwrap_or_default();
    assert!(kinds.contains(&"git_config_unreadable"), "{json}");
    let granted = World::with_base("[fs]\nwrite = [\".\"]\nread = [\"~/.gitconfig\"]\n", "");
    write(
        &granted.home_dir().join(".gitconfig"),
        "[user]\n\tname = t\n",
    );
    let run = hb(&granted, &["run", "--", "/usr/bin/true"]);
    assert!(
        !run.stderr.contains("git inside the ball"),
        "{}",
        run.stderr
    );
}

#[test]
fn with_the_template_grant_git_works_inside_the_ball() {
    sandboxed!();
    let w = World::with_base("[fs]\nwrite = [\".\"]\nread = [\"~/.gitconfig\"]\n", "");
    write(
        &w.home_dir().join(".gitconfig"),
        "[user]\n\tname = t\n\temail = t@example.com\n",
    );
    // The ball cannot create `.git` (the floor keeps the name from being planted), so the repository
    // is made on the host first.
    let init = assert_ok!(
        std::process::Command::new("/usr/bin/git")
            .args(["init", "-q"])
            .current_dir(&w.project)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
    );
    assert!(init.status.success());
    let out = hb(
        &w,
        &["run", "--", "/bin/sh", "-c", "git status -s && echo git-ok"],
    );
    assert!(
        out.stdout.contains("git-ok"),
        "{}{}",
        out.stdout,
        out.stderr
    );
}
