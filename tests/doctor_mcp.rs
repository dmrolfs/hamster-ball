// ABOUTME: `hb doctor` and MCP servers that cannot start offline, through hb-testdrive: never warmed, a moving tag, an unpinned git source, a missing launcher.
// ABOUTME: Names the server and the one flagged argument; a token in another argument is never printed.
//! `hb doctor`'s MCP section (hb-ghd.7.4).

#![cfg(target_os = "macos")]

mod common;

use std::process::Stdio;
use std::time::SystemTime;

use claims::assert_ok;
use common::{World, canonical};
use hamster_ball::system::StateDir;
use hamster_ball::warm::stamp::{WarmStore, digest};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const BASE: &str = "[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\"]\n";
const SHA: &str = "23c06ff715409b2e9dc9be7ca26b7b2fbf356b7c";

fn doctor(w: &World) -> (Option<i32>, String) {
    let out = assert_ok!(w.drive(DRIVE, &["doctor"]).stdin(Stdio::null()).output());
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn doctor_names_each_server_that_cannot_start_offline_and_the_fix() {
    let w = World::with_base(
        BASE,
        "[mcp.time]\ncommand = \"uvx\"\nargs = [\"mcp-server-time\"]\n\
         [mcp.ripgrep]\ncommand = \"npx\"\nargs = [\"-y\", \"mcp-ripgrep@latest\", \"--token=SECRET-ARG-VALUE\"]\n\
         [mcp.serena]\ncommand = \"uvx\"\nargs = [\"--from\", \"git+https://deploy:CRED-IN-URL@github.com/oraios/serena\", \"serena\"]\n\
         [mcp.local]\ncommand = \"/bin/true\"\nargs = [\"x@latest\"]\n",
    );
    let (code, text) = doctor(&w);
    assert_eq!(code, Some(0), "findings are advice, not failure: {text}");
    assert!(text.contains("mcp servers"), "{text}");
    assert!(text.contains("time: has not been warmed"), "{text}");
    assert!(
        text.contains("ripgrep: `mcp-ripgrep@latest` moves"),
        "{text}"
    );
    assert!(
        text.contains("ripgrep: starts `npx`, which is not in [env] tools"),
        "{text}"
    );
    assert!(
        text.contains("serena: git source `git+https://github.com/oraios/serena`"),
        "{text}"
    );
    assert!(
        !text.contains("local:"),
        "a server that is not uvx or npx is not looked at: {text}"
    );
    for secret in ["SECRET-ARG-VALUE", "CRED-IN-URL", "deploy"] {
        assert!(!text.contains(secret), "{secret} leaked: {text}");
    }
}

#[test]
fn a_warmed_pinned_server_with_its_launcher_listed_has_no_problem() {
    let w = World::with_base(
        BASE,
        &format!(
            "[mcp.serena]\ncommand = \"uvx\"\nargs = [\"--from\", \"git+https://github.com/oraios/serena@{SHA}\", \"serena\"]\n"
        ),
    );
    let args = [
        "--from",
        &format!("git+https://github.com/oraios/serena@{SHA}"),
        "serena",
    ];
    let store = WarmStore::new(&StateDir::locate(&w.home));
    assert_ok!(store.record(
        &canonical(&w.project),
        "serena",
        &digest("uvx", &args),
        SystemTime::now()
    ));
    let (code, text) = doctor(&w);
    assert_eq!(code, Some(0));
    assert!(text.contains("no problems found"), "{text}");
}

#[test]
fn a_project_with_no_such_server_says_so_and_the_secrets_sections_are_still_there() {
    let w = World::with_base(BASE, "");
    let (_, text) = doctor(&w);
    assert!(text.contains("none starts uvx or npx"), "{text}");
    assert!(text.contains("secrets guard covers"), "{text}");
}
