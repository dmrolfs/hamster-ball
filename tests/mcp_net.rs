// ABOUTME: `[mcp.<name>] net` reaches the run allowlist and `warm_net` does not; explain and the approval summary show both.
// ABOUTME: Hosts that cannot resolve are used on purpose: a refusal says `not_allowed`, an allowed host fails later as `unresolved`.
//! `[mcp.*]` hosts, end to end through hb-testdrive (hb-ghd.7.1).

#![cfg(target_os = "macos")]

mod common;

use claims::assert_ok;
use common::{World, sandbox_available};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n\
[mcp.remote]\nnet = [\"mcp-run.invalid\"]\nwarm_net = [\"mcp-warm.invalid\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

#[test]
fn a_servers_net_host_is_allowed_at_run_time_and_its_warm_net_host_is_not() {
    sandboxed!();
    let w = World::new(PROJECT);
    let script = "/usr/bin/curl -sS -m 10 https://mcp-run.invalid/ >/dev/null 2>&1; \
                  /usr/bin/curl -sS -m 10 https://mcp-warm.invalid/ >/dev/null 2>&1; echo done";
    let out = assert_ok!(
        w.drive(
            DRIVE,
            &["run", "--log-proxy", "--", "/bin/sh", "-c", script]
        )
        .output()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let lines: Vec<&str> = stderr.lines().filter(|l| l.contains("proxy:")).collect();
    let about = |host: &str| -> String {
        lines
            .iter()
            .filter(|l| l.contains(host))
            .copied()
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        !about("mcp-run.invalid").contains("not_allowed"),
        "{stderr}"
    );
    assert!(!about("mcp-run.invalid").is_empty(), "{stderr}");
    assert!(
        about("mcp-warm.invalid").contains("not_allowed"),
        "{stderr}"
    );
}

#[test]
fn explain_lists_the_hosts_in_the_allowlist_with_the_servers_origin_and_the_warm_hosts_apart() {
    let w = World::new(PROJECT);
    let out = assert_ok!(w.drive(DRIVE, &["explain", "--format", "json"]).output());
    let json: serde_json::Value = assert_ok!(serde_json::from_slice(&out.stdout));
    let hosts = json["net"]["hosts"].as_array().cloned().unwrap_or_default();
    let run_host = hosts
        .iter()
        .find(|h| h["value"] == "mcp-run.invalid:443")
        .cloned();
    let run_host = run_host.unwrap_or_default();
    assert!(
        run_host["origins"][0]["key"]
            .as_str()
            .is_some_and(|k| k.starts_with("mcp.remote.net")),
        "{json}"
    );
    assert!(
        !hosts.iter().any(|h| h["value"] == "mcp-warm.invalid:443"),
        "warm_net is not an allowed host: {json}"
    );
    let server = &json["mcp"][0];
    assert_eq!(server["net"][0], "mcp-run.invalid:443", "{json}");
    assert_eq!(server["warm_net"][0], "mcp-warm.invalid:443", "{json}");
}

#[test]
fn the_text_report_and_the_approval_summary_show_both_host_lists() {
    let w = World::new(PROJECT);
    let text = assert_ok!(w.drive(DRIVE, &["explain"]).output());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("mcp-run.invalid:443"), "{text}");
    assert!(text.contains("warm: mcp-warm.invalid:443"), "{text}");
    let discovery = assert_ok!(hamster_ball::config::discover(&w.project, &w.home));
    let summary =
        hamster_ball::approval::GrantSummary::for_project(&w.env, &discovery, &w.loaded())
            .to_string();
    assert!(summary.contains("net: mcp-run.invalid:443"), "{summary}");
    assert!(
        summary.contains("warm_net: mcp-warm.invalid:443"),
        "{summary}"
    );
}
