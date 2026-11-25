// ABOUTME: The offline `uvx` and `npx` launchers end to end through hb-testdrive, with fake tools that print what they were given.
// ABOUTME: Real sandbox: first on PATH, `--offline` first, hb's cache variables for the call only, a writable cache, the hint, no change without a server.
//! Offline MCP launchers (hb-ghd.7.2).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use claims::assert_ok;
use common::{World, sandbox_available, write};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const BASE: &str = "[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\", \"npx\"]\n";
const SERVER: &str = "[mcp.time]\ncommand = \"uvx\"\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// A fake tool that says what it was started with.
fn fake(world: &World, name: &str) -> PathBuf {
    let path = world.base.join("bin").join(name);
    write(
        &path,
        &format!(
            "#!/bin/sh\necho \"fake-{name} args=$* uv_cache=${{UV_CACHE_DIR:-unset}} uv_tools=${{UV_TOOL_DIR:-unset}} npm_cache=${{npm_config_cache:-unset}}\"\n\
             if [ -n \"$UV_CACHE_DIR\" ]; then mkdir -p \"$UV_CACHE_DIR/pkg\" && echo x > \"$UV_CACHE_DIR/pkg/cacert.pem\" && echo wrote-cacert; fi\n"
        ),
    );
    assert_ok!(fs::set_permissions(
        &path,
        fs::Permissions::from_mode(0o755)
    ));
    path
}

fn world(project: &str) -> World {
    let w = World::with_base(BASE, project);
    fake(&w, "uvx");
    fake(&w, "npx");
    w
}

struct Ran {
    stdout: String,
    stderr: String,
}

fn run(w: &World, script: &str) -> Ran {
    let out = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", script])
            .output()
    );
    Ran {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn cache(w: &World) -> PathBuf {
    w.home_dir().join(".cache/hamster-ball")
}

#[test]
fn with_a_declared_server_uvx_and_npx_run_offline_from_hbs_cache_for_that_call_only() {
    sandboxed!();
    let w = world(SERVER);
    let ran = run(
        &w,
        "uvx --from x serena; npx -y pkg; echo \"outside: ${UV_CACHE_DIR:-unset} ${npm_config_cache:-unset}\"",
    );
    let root = fs::canonicalize(cache(&w)).unwrap_or_else(|_| cache(&w));
    let root = root.display();
    assert!(
        ran.stdout.contains(&format!(
            "fake-uvx args=--offline --from x serena uv_cache={root}/uv uv_tools={root}/uv-tools npm_cache=unset"
        )),
        "{}{}",
        ran.stdout,
        ran.stderr
    );
    assert!(
        ran.stdout.contains(&format!(
            "fake-npx args=--offline -y pkg uv_cache=unset uv_tools=unset npm_cache={root}/npm"
        )),
        "{}{}",
        ran.stdout,
        ran.stderr
    );
    assert!(
        ran.stdout.contains("outside: unset unset"),
        "{}",
        ran.stdout
    );
}

#[test]
fn the_cache_is_writable_by_the_launcher_and_the_guard_still_guards_the_project() {
    sandboxed!();
    let w = world(SERVER);
    let ran = run(
        &w,
        "uvx a; echo secret > ./key.pem 2>/dev/null && echo project-pem-written",
    );
    assert!(
        ran.stdout.contains("wrote-cacert"),
        "{}{}",
        ran.stdout,
        ran.stderr
    );
    assert!(
        !ran.stdout.contains("project-pem-written"),
        "the guard denies a .pem in the project: {}",
        ran.stdout
    );
    assert!(cache(&w).join("uv/pkg/cacert.pem").exists());
    let mode = assert_ok!(fs::metadata(cache(&w).join("uv")))
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn the_hint_names_hb_warm_until_the_cache_is_marked_warmed() {
    sandboxed!();
    let w = world(SERVER);
    let cold = run(&w, "uvx a");
    assert!(
        cold.stderr
            .contains("hb has not warmed its offline cache; run `hb warm`"),
        "{}",
        cold.stderr
    );
    assert!(
        cold.stdout.contains("fake-uvx"),
        "the tool still runs: {}",
        cold.stdout
    );
    write(&cache(&w).join("warmed"), "");
    let warm = run(&w, "uvx a");
    assert!(
        !warm.stderr.contains("hb has not warmed its offline cache"),
        "{}",
        warm.stderr
    );
}

#[test]
fn a_call_by_absolute_path_and_a_run_without_a_server_are_unchanged() {
    sandboxed!();
    let w = world(SERVER);
    let real = w.base.join("bin/uvx");
    let ran = run(&w, &format!("{} direct", real.display()));
    assert!(
        ran.stdout.contains("fake-uvx args=direct uv_cache=unset"),
        "{}{}",
        ran.stdout,
        ran.stderr
    );
    let none = world("");
    let ran = run(&none, "uvx plain");
    assert!(
        ran.stdout.contains("fake-uvx args=plain uv_cache=unset"),
        "no declared server, no launcher: {}{}",
        ran.stdout,
        ran.stderr
    );
    assert!(
        !cache(&none).exists(),
        "no cache directory is made without a server"
    );
}

#[test]
fn a_declared_launcher_that_env_tools_does_not_list_is_warned_about() {
    sandboxed!();
    let w = World::with_base(
        "[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\"]\n",
        "[mcp.ripgrep]\ncommand = \"npx\"\n",
    );
    fake(&w, "uvx");
    let ran = run(&w, "true");
    assert!(
        ran.stderr.contains("[mcp.ripgrep] starts `npx`") && ran.stderr.contains("[env] tools"),
        "{}",
        ran.stderr
    );
}

fn explain_json(w: &World) -> serde_json::Value {
    let out = assert_ok!(w.drive(DRIVE, &["explain", "--format", "json"]).output());
    assert_ok!(serde_json::from_slice(&out.stdout))
}

#[test]
fn explain_lists_the_launchers_with_the_real_tool_and_the_cache_root() {
    let w = world(SERVER);
    let json = explain_json(&w);
    let offline = &json["offline"];
    assert_eq!(offline["enabled"], true, "{json}");
    let tools: Vec<&str> = offline["launchers"]
        .as_array()
        .map(|all| all.iter().filter_map(|l| l["tool"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(tools, ["uvx", "npx"], "{json}");
    assert!(
        offline["launchers"][0]["runs"]
            .as_str()
            .is_some_and(|runs| runs.ends_with("/bin/uvx")),
        "{json}"
    );
    assert!(
        offline["cache_root"]
            .as_str()
            .is_some_and(|root| root.ends_with(".cache/hamster-ball")),
        "{json}"
    );
    let text = assert_ok!(w.drive(DRIVE, &["explain"]).output());
    let text = String::from_utf8_lossy(&text.stdout);
    assert!(text.contains("offline launchers"), "{text}");
    assert!(text.contains("uvx"), "{text}");
}

#[test]
fn explain_says_off_without_a_declared_server_and_warns_about_a_launcher_it_cannot_make() {
    let off = explain_json(&world(""));
    assert_eq!(off["offline"]["enabled"], false, "{off}");
    assert!(
        off["offline"]["launchers"]
            .as_array()
            .is_some_and(Vec::is_empty),
        "{off}"
    );
    let w = World::with_base(
        "[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\"]\n",
        "[mcp.ripgrep]\ncommand = \"npx\"\n",
    );
    fake(&w, "uvx");
    let json = explain_json(&w);
    let kinds: Vec<&str> = json["warnings"]
        .as_array()
        .map(|all| all.iter().filter_map(|x| x["kind"].as_str()).collect())
        .unwrap_or_default();
    assert!(kinds.contains(&"offline_launcher_unavailable"), "{json}");
}
