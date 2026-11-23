// ABOUTME: Opt-in: system trust against real hosts, including ones a TLS-inspecting proxy re-signs (run with --ignored).
// ABOUTME: A host counts as inspected when Node's own roots cannot verify it, so nothing here names a vendor; with the inspector off every host passes.
//! Real-network checks of `tls.system_trust` (design 4.5, hb-ghd.2.2).
//!
//! `cargo test --test tls_inspection -- --ignored --nocapture`. The hosts come from
//! `HB_TLS_HOSTS` (comma separated; default `example.com,kiro.dev,opencode.ai,context7.com`).
//!
//! hb has no proxy yet, so the profile used here is the generated one plus an outbound-network
//! allow. That is a test scaffold only: the trust grants are what is under test.

#![cfg(target_os = "macos")]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use claims::assert_ok;
use common::{World, run, sandbox_available};
use hamster_ball::seatbelt::{Profile, RenderInputs};

fn hosts() -> Vec<String> {
    std::env::var("HB_TLS_HOSTS")
        .unwrap_or_else(|_| "example.com,kiro.dev,opencode.ai,context7.com".to_owned())
        .split(',')
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .collect()
}

fn find(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| std::fs::canonicalize(candidate).ok())
}

fn install_tree(binary: &Path) -> PathBuf {
    if binary.starts_with("/opt/homebrew") {
        return PathBuf::from("/opt/homebrew");
    }
    binary
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| binary.to_path_buf(), Path::to_path_buf)
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

const CHECK_JS: &str = "const https = require('https');\n\
    https.get({ host: process.argv[2], path: '/', timeout: 8000 }, (res) => { res.resume(); console.log('VERIFIED'); process.exit(0); })\n\
      .on('error', (e) => { console.log('FAIL ' + (e.code || e.message)); process.exit(1); });\n";

/// The profile this run needs: the generated one, and the network scaffold.
fn profile_for(world: &World) -> Profile {
    let mut profile = world.render(&RenderInputs::new());
    profile
        .text
        .push_str("\n(allow network-outbound)\n(allow system-socket)\n");
    profile
}

/// Whether Node, with nothing but its own roots and outside any sandbox, fails to verify `host`.
/// That is what a re-signed host looks like to a client that cannot see the system store.
fn is_resigned(node: &Path, host: &str, script: &Path) -> Option<bool> {
    let out = Command::new(node)
        .arg(script)
        .arg(host)
        .env_clear()
        .output()
        .ok()?;
    let said = text(&out);
    if said.contains("VERIFIED") {
        Some(false)
    } else if said.contains("UNABLE_TO_GET_ISSUER_CERT_LOCALLY")
        || said.contains("UNABLE_TO_VERIFY_LEAF_SIGNATURE")
        || said.contains("SELF_SIGNED_CERT_IN_CHAIN")
    {
        Some(true)
    } else {
        None
    }
}

#[test]
#[ignore = "uses the network; run with --ignored"]
fn system_trust_verifies_every_host_whether_or_not_a_proxy_re_signs_it_and_without_it_only_the_re_signed_ones_fail()
 {
    if !sandbox_available() {
        eprintln!("SKIP: no sandbox-exec");
        return;
    }
    let Some(node) = find("node") else {
        eprintln!("SKIP: no node");
        return;
    };
    let on = World::with_base(
        "[tls]\nsystem_trust = true\n",
        &format!(
            "[fs]\nread = [{}]\nwrite = [\".\"]\n",
            common::toml_string(&install_tree(&node).to_string_lossy())
        ),
    );
    let off = World::with_base(
        "[tls]\nsystem_trust = false\n",
        &format!(
            "[fs]\nread = [{}]\nwrite = [\".\"]\n",
            common::toml_string(&install_tree(&node).to_string_lossy())
        ),
    );
    for world in [&on, &off] {
        common::write(&world.project.join("check.js"), CHECK_JS);
    }
    let script = on.project.join("check.js");
    let mut checked = 0;
    for host in hosts() {
        let Some(resigned) = is_resigned(&node, &host, &script) else {
            eprintln!("SKIP {host}: not reachable, or failed for another reason");
            continue;
        };
        checked += 1;
        let node_cmd =
            |trust_env: &str| format!("{trust_env} '{}' check.js {host}", node.display());
        // With system trust: Node told to use the system store, and curl, verify every host.
        let trusting = profile_for(&on);
        let verdict = text(&run(
            &trusting,
            &on.home_dir(),
            &on.project,
            &node_cmd("NODE_USE_SYSTEM_CA=1"),
        ));
        assert!(
            verdict.contains("VERIFIED"),
            "{host} (re-signed={resigned}), system_trust on, node: {verdict}"
        );
        let curl = run(
            &trusting,
            &on.home_dir(),
            &on.project,
            &format!("/usr/bin/curl -sS --max-time 8 -o /dev/null https://{host}/"),
        );
        assert!(
            curl.status.success(),
            "{host} (re-signed={resigned}), system_trust on, curl: {}",
            text(&curl)
        );
        // Without it: a host the proxy re-signs fails, and one it does not still passes.
        let distrusting = profile_for(&off);
        let without = text(&run(
            &distrusting,
            &off.home_dir(),
            &off.project,
            &node_cmd(""),
        ));
        assert_eq!(
            without.contains("VERIFIED"),
            !resigned,
            "{host} (re-signed={resigned}), system_trust off, node: {without}"
        );
        eprintln!(
            "{host}: re-signed={resigned}: verified with system trust, {} without",
            if resigned { "fails" } else { "passes" }
        );
    }
    assert_ok!(if checked > 0 {
        Ok(())
    } else {
        Err("no host could be reached")
    });
}
