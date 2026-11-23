// ABOUTME: Opt-in check that each installed agent CLI sends the proxy credentials from the proxy URL (hb-ghd.3.2, design 15.2).
// ABOUTME: The proxy refuses everything, so no request leaves the machine; the agent also runs where only loopback is reachable.
//! Run with `cargo test --features test-support --test proxy_agents -- --ignored --nocapture`.
//!
//! For each agent found on `PATH`, the real proxy runs with an empty allowlist and the agent is
//! started with `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lowercase forms set to the
//! proxy URL. A request that carries the right credentials is refused as `not_allowed`; one
//! without them as `proxy_auth_required`. The test needs at least one request of the first kind
//! from each agent that ran and prints what it saw.

#![cfg(target_os = "macos")]

mod common;

use std::collections::BTreeMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::proxy::{Collect, config, start};
use hamster_ball::proxy::Decision;

/// No direct connection can leave: only loopback is reachable.
const LOOPBACK_ONLY: &str = "(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote ip \"localhost:*\"))";

fn on_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(program))
        .find(|p| p.is_file())
}

fn agents() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("claude", vec!["claude", "-p", "say hi", "--max-turns", "1"]),
        ("pi", vec!["pi", "-p", "say hi"]),
        ("opencode", vec!["opencode", "run", "say hi"]),
        (
            "kiro-cli",
            vec!["kiro-cli", "chat", "--no-interactive", "say hi"],
        ),
    ]
}

#[test]
#[ignore = "runs the installed agent CLIs"]
fn each_installed_agent_sends_the_proxy_credentials_from_the_url() {
    if !common::sandbox_available() {
        return;
    }
    let mut checked = 0;
    for (name, argv) in agents() {
        if on_path(argv[0]).is_none() {
            eprintln!("SKIP {name}: not installed");
            continue;
        }
        let sink = Collect::new();
        let proxy = start(config(&[], &[]).with_audit(Arc::clone(&sink) as _));
        let url = proxy.url();
        let dir = std::env::temp_dir().join(format!("hb-agent-{name}-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let mut command = Command::new("/usr/bin/sandbox-exec");
        command
            .args(["-p", LOOPBACK_ONLY, "--"])
            .args(&argv)
            .current_dir(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        for var in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            command.env(var, url.expose());
        }
        command.env("NO_PROXY", "").env("no_proxy", "");
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                eprintln!("SKIP {name}: {error}");
                continue;
            }
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
            std::thread::sleep(Duration::from_millis(200));
        }
        if matches!(child.try_wait(), Ok(None)) {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", &format!("-{}", child.id())])
                .status();
            std::thread::sleep(Duration::from_secs(1));
            let _ = Command::new("/bin/kill")
                .args(["-KILL", &format!("-{}", child.id())])
                .status();
        }
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(500));
        let events = sink.events();
        let mut counts: BTreeMap<(String, &'static str), usize> = BTreeMap::new();
        for event in &events {
            let code = match &event.decision {
                Decision::Allowed => "allowed",
                Decision::Refused { code, .. } => code,
            };
            *counts.entry((event.target(), code)).or_default() += 1;
        }
        eprintln!("== {name}: {} requests", events.len());
        for ((target, code), n) in &counts {
            eprintln!("   {n}x {target}  {code}");
        }
        let authenticated = events
            .iter()
            .filter(|e| {
                matches!(&e.decision, Decision::Refused { code, .. } if *code != "proxy_auth_required")
            })
            .count();
        assert!(
            authenticated > 0,
            "{name} made no request that carried the proxy credentials ({} events)",
            events.len()
        );
        let _ = std::fs::remove_dir_all(&dir);
        checked += 1;
    }
    eprintln!("agents checked: {checked}");
}
