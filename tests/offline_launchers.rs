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
            "#!/bin/sh\necho \"fake-{name} args=$* uv_cache=${{UV_CACHE_DIR:-unset}} uv_tools=${{UV_TOOL_DIR:-unset}} npm_cache=${{npm_config_cache:-unset}} py=${{UV_PYTHON_INSTALL_DIR:-unset}}|${{UV_PYTHON_PREFERENCE:-unset}}|${{UV_PYTHON_DOWNLOADS:-unset}}|${{UV_LINK_MODE:-unset}}\"\n\
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
    if !project.is_empty() {
        w.publish_cache(&[
            ("uv/seed", "published"),
            ("uv-tools/seed", "published"),
            ("npm/seed", "published"),
            ("python/seed", "published"),
        ]);
    }
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
fn with_a_declared_server_uvx_and_npx_run_offline_from_the_runs_own_cache_copy_for_that_call_only()
{
    sandboxed!();
    let w = world(SERVER);
    let ran = run(
        &w,
        "uvx --from x serena; npx -y pkg; echo \"outside: ${UV_CACHE_DIR:-unset} ${npm_config_cache:-unset}\"",
    );
    let line = |tool: &str| {
        ran.stdout
            .lines()
            .find(|l| l.starts_with(tool))
            .unwrap_or_default()
            .to_owned()
    };
    let (uvx, npx) = (line("fake-uvx"), line("fake-npx"));
    assert!(
        uvx.starts_with("fake-uvx args=--offline --from x serena uv_cache="),
        "{}{}",
        ran.stdout,
        ran.stderr
    );
    assert!(
        npx.starts_with("fake-npx args=--offline -y pkg "),
        "{}{}",
        ran.stdout,
        ran.stderr
    );
    let uv_cache = uvx
        .split("uv_cache=")
        .nth(1)
        .and_then(|r| r.split(' ').next())
        .unwrap_or("");
    let root = uv_cache.strip_suffix("/uv").unwrap_or(uv_cache);
    assert!(
        root.ends_with("/cache"),
        "the run's own copy is <session>/cache: {uvx}"
    );
    assert!(
        !root.contains(".cache/hamster-ball"),
        "never the shared store: {uvx}"
    );
    assert!(uvx.contains(&format!("uv_tools={root}/uv-tools")), "{uvx}");
    assert!(
        uvx.contains(&format!("py={root}/python|only-managed|never|copy")),
        "{uvx}"
    );
    assert!(npx.contains(&format!("npm_cache={root}/npm")), "{npx}");
    assert!(
        ran.stdout.contains("outside: unset unset"),
        "{}",
        ran.stdout
    );
}

#[test]
fn a_run_writes_only_its_own_copy_and_the_published_generation_and_the_next_run_stay_clean() {
    sandboxed!();
    let w = world(SERVER);
    let first = run(
        &w,
        "uvx a; echo secret > ./key.pem 2>/dev/null && echo project-pem-written; \
         echo poisoned > \"$TMPDIR/cache/uv/seed\"",
    );
    assert!(
        first.stdout.contains("wrote-cacert"),
        "{}{}",
        first.stdout,
        first.stderr
    );
    assert!(
        !first.stdout.contains("project-pem-written"),
        "the guard still denies a .pem in the project: {}",
        first.stdout
    );
    let published = assert_ok!(fs::read_dir(cache(&w).join("generations")))
        .flatten()
        .next()
        .map(|e| e.path().join("data"))
        .unwrap_or_default();
    assert_eq!(
        assert_ok!(fs::read_to_string(published.join("uv/seed"))),
        "published"
    );
    assert!(
        !published.join("uv/pkg").exists(),
        "the run's write did not reach the generation"
    );
    let second = run(&w, "cat \"$TMPDIR/cache/uv/seed\"; ls \"$TMPDIR/cache/uv\"");
    assert!(
        second.stdout.starts_with("published"),
        "a later run starts from the generation: {}{}",
        second.stdout,
        second.stderr
    );
    assert!(
        !second.stdout.contains("pkg"),
        "and sees nothing the first run wrote: {}",
        second.stdout
    );
    let mode = assert_ok!(fs::metadata(published.join("uv")))
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o700);
}

fn refused(w: &World) -> (bool, String, String) {
    let out = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", "echo ran"])
            .output()
    );
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn a_run_with_no_published_generation_does_not_start_and_says_to_run_hb_warm() {
    sandboxed!();
    let w = World::with_base(BASE, SERVER);
    fake(&w, "uvx");
    let (ok, stdout, stderr) = refused(&w);
    assert!(!ok, "{stdout}{stderr}");
    assert!(!stdout.contains("ran"), "the agent never started: {stdout}");
    assert!(stderr.contains("hb warm"), "{stderr}");
}

#[test]
fn only_the_old_shared_cache_is_refused_and_left_untouched() {
    sandboxed!();
    let w = World::with_base(BASE, SERVER);
    fake(&w, "uvx");
    write(&cache(&w).join("uv/old"), "legacy bytes");
    let (ok, stdout, stderr) = refused(&w);
    assert!(!ok && !stdout.contains("ran"), "{stdout}{stderr}");
    assert!(
        stderr.contains("old shared cache") && stderr.contains("hb warm"),
        "{stderr}"
    );
    assert_eq!(
        assert_ok!(fs::read_to_string(cache(&w).join("uv/old"))),
        "legacy bytes"
    );
}

#[test]
fn a_changed_tool_makes_the_generation_stale_and_the_run_refuses() {
    sandboxed!();
    let w = world(SERVER);
    let path = w.base.join("bin/uvx");
    write(&path, "#!/bin/sh\necho a different, longer uvx\n");
    assert_ok!(fs::set_permissions(
        &path,
        fs::Permissions::from_mode(0o755)
    ));
    let (ok, stdout, stderr) = refused(&w);
    assert!(!ok && !stdout.contains("ran"), "{stdout}{stderr}");
    assert!(
        stderr.contains("stale") && stderr.contains("tool"),
        "{stderr}"
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
    w.publish_cache(&[("uv/seed", "published")]);
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
