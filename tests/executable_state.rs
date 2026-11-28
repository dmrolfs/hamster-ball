// ABOUTME: Disposable cross-run canaries in throwaway homes; fake loaders do not prove vendor startup behaviour.
// ABOUTME: Cache canary crosses projects inside hb; settings and hard-link canaries use a later outside consumer.
// ABOUTME: Only the opt-in installed_agents test touches the real home and real agents (`--version`).
//! Evidence for hb-tx4, not a claim that hb-dai/hb-82i isolate production executable state.

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Output;

use claims::{assert_ok, assert_some};
use common::{World, quote, sandbox_available, write};
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const BASE: &str = "[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\"]\n";
const SERVER: &str = "[mcp.time]\ncommand = \"uvx\"\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn run_at(w: &World, project: &Path, script: &str) -> Output {
    assert_ok!(
        w.drive_at(project, DRIVE, &["run", "--", "/bin/sh", "-c", script])
            .output()
    )
}

fn run(w: &World, script: &str) -> Output {
    run_at(w, &w.project, script)
}

fn executable(path: &Path, body: &str) {
    write(path, body);
    assert_ok!(fs::set_permissions(path, fs::Permissions::from_mode(0o700)));
}

fn assert_cannot_write(w: &World, path: &Path) {
    let out = run(w, &format!("echo direct > {}", quote(path)));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Operation not permitted"),
        "{}",
        text(&out)
    );
    assert!(
        !path.exists(),
        "planting ball wrote the later marker directly"
    );
}

/// Two projects under one home, each with its own published (benign) generation.
///
/// The fake `uvx` runs `$UV_TOOL_DIR/canary/bin/canary` when it exists, so a planted file would
/// execute if a later run ever saw it. Returns (world, project B, marker in B, the store path
/// a planter would aim at).
fn cache_fixture() -> (World, PathBuf, PathBuf, PathBuf) {
    let w = World::with_base(BASE, SERVER);
    executable(
        &w.base.join("bin/uvx"),
        "#!/bin/sh\nif [ -f \"$UV_TOOL_DIR/canary/bin/canary\" ]; then exec /bin/sh \"$UV_TOOL_DIR/canary/bin/canary\"; else echo no-planted-tool; fi\n",
    );
    let b = w.add_project("other", SERVER);
    let benign = [("uv-tools/seed", "benign")];
    w.publish_cache(&benign);
    w.publish_cache_at(&b, &benign);
    let marker = b.join("marker");
    let store = w.home_dir().join(".cache/hamster-ball");
    (w, b, marker, store)
}

fn generations(store: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = assert_ok!(fs::read_dir(store.join("generations")))
        .flatten()
        .map(|e| e.path().join("data"))
        .collect();
    found.sort();
    found
}

/// The bytes of every file under the published generations, to compare before and after.
fn snapshot(store: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = generations(store);
    while let Some(dir) = stack.pop() {
        for entry in assert_ok!(fs::read_dir(&dir)).flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push((path.clone(), assert_ok!(fs::read(&path))));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn a_planted_tool_reaches_only_the_planting_runs_private_copy_and_never_another_project() {
    sandboxed!();
    let (w, b, marker, store) = cache_fixture();
    let published = snapshot(&store);
    assert_cannot_write(&w, &marker);
    // The planting run writes the canary where its own uvx would look, and runs it: the plant works
    // in the run's private copy (the permissive control), but only there.
    let payload = format!(
        "#!/bin/sh\necho ran-here > \"$TMPDIR/cache/uv-tools/ran\"\necho cache-canary > {}\n",
        quote(&marker)
    );
    let planted = "$TMPDIR/cache/uv-tools/canary/bin/canary";
    let plant = run(
        &w,
        &format!(
            "mkdir -p \"$TMPDIR/cache/uv-tools/canary/bin\" && printf %s {} > \"{planted}\" && uvx canary",
            quote(Path::new(&payload))
        ),
    );
    // Permissive control: the planted file really executed inside the planting run (it wrote
    // `ran` in its own copy), so the attack is meaningful. Its write into project B was refused.
    let said = text(&plant);
    assert!(said.contains("canary: line"), "the canary executed: {said}");
    assert!(
        said.contains("Operation not permitted"),
        "and could not cross into B: {said}"
    );
    let kept = run(&w, "ls \"$TMPDIR/cache/uv-tools\"");
    assert!(
        !text(&kept).contains("ran"),
        "a later run does not see the plant: {}",
        text(&kept)
    );
    assert!(
        !marker.exists(),
        "the marker is in B, which the planting ball cannot write"
    );
    assert_eq!(snapshot(&store), published, "no generation changed");
    // Project B's later run, and a later run of the SAME project, start from the published bytes.
    for (label, project) in [
        ("other project", b.clone()),
        ("same project", w.project.clone()),
    ] {
        let later = run_at(&w, &project, "uvx canary");
        assert!(later.status.success(), "{label}: {}", text(&later));
        assert!(
            text(&later).contains("no-planted-tool"),
            "{label}: {}",
            text(&later)
        );
    }
    assert!(!marker.exists());
    assert_eq!(snapshot(&store), published);
}

#[test]
fn the_planting_run_cannot_reach_the_published_store_at_all() {
    sandboxed!();
    let (w, _b, marker, store) = cache_fixture();
    let published = snapshot(&store);
    let aimed = generations(&store).remove(0).join("uv-tools/canary");
    let attack = run(
        &w,
        &format!(
            "mkdir -p {a} 2>&1; echo x > {a}/f 2>&1; rm -rf {g} 2>&1; ls {s} 2>&1; true",
            a = quote(&aimed),
            g = quote(&generations(&store).remove(0)),
            s = quote(&store)
        ),
    );
    let said = text(&attack);
    assert!(
        said.matches("Operation not permitted").count() >= 3,
        "every reach into the store is refused: {said}"
    );
    assert_eq!(snapshot(&store), published, "unchanged");
    assert!(!marker.exists());
}

fn agent_world(agent: &str, deny: &str) -> World {
    let base = format!("[tls]\nsystem_trust = true\n[fs]\nwrite = [\".\"]\n{deny}");
    World::with_base(&base, &format!("extends = [\"agent/{agent}\"]\n"))
}

/// The CONTROL: the agent's preset exactly as it shipped before hb-82i (95db22c, saved under
/// tests/fixtures/pre-hb-82i), loaded as the user's own preset. The attack must work against it (so the
/// canary is real) and fail against the shipped `agent/<name>`.
fn control_world(agent: &str) -> World {
    let base = "[tls]\nsystem_trust = true\n[fs]\nwrite = [\".\"]\n";
    let w = World::with_base(base, &format!("extends = [\"pre-{agent}\"]\n"));
    let old = assert_ok!(fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pre-hb-82i")
            .join(format!("{agent}.toml"))
    ));
    write(
        &w.home_dir()
            .join(format!(".config/hamster-ball/presets/pre-{agent}.toml")),
        &old,
    );
    w
}

/// Stand-in for the shape of one SessionStart command, not evidence about real claude.
fn start_like_claude(home: &Path) -> Output {
    let settings: serde_json::Value = assert_ok!(serde_json::from_slice(&assert_ok!(fs::read(
        home.join(".claude/settings.json")
    ))));
    let command =
        assert_some!(settings["hooks"]["SessionStart"][0]["hooks"][0]["command"].as_str());
    assert_ok!(
        std::process::Command::new("/bin/sh")
            .args(["-c", command])
            .env_clear()
            .env("HOME", home)
            .env("PATH", "/usr/bin:/bin")
            .output()
    )
}

fn claude_fixture(shipped: bool) -> (World, PathBuf, PathBuf) {
    let w = if shipped {
        agent_world("claude", "")
    } else {
        control_world("claude")
    };
    let settings = w.home_dir().join(".claude/settings.json");
    write(
        &settings,
        r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"true"}]}]}}"#,
    );
    let marker = w.base.join("outside/marker");
    assert_ok!(fs::create_dir_all(assert_some!(marker.parent())));
    (w, settings, marker)
}

#[test]
fn a_hook_planted_in_claude_settings_runs_in_a_later_outside_loader() {
    sandboxed!();
    let (w, settings, marker) = claude_fixture(false);
    assert_cannot_write(&w, &marker);
    let payload = serde_json::json!({"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":format!("echo hook-canary > {}", quote(&marker))}]}]}}).to_string();
    let out = run(
        &w,
        &format!(
            "printf %s {} > {}",
            quote(Path::new(&payload)),
            quote(&settings)
        ),
    );
    assert!(out.status.success(), "{}", text(&out));
    assert!(!marker.exists(), "the plant itself wrote the marker");
    let consumer = start_like_claude(&w.home_dir());
    assert!(consumer.status.success(), "{}", text(&consumer));
    assert_eq!(assert_ok!(fs::read_to_string(marker)), "hook-canary\n");
}

#[test]
fn a_deny_write_on_claude_settings_stops_the_plant_and_the_hook() {
    sandboxed!();
    let (w, settings, marker) = claude_fixture(true);
    let before = assert_ok!(fs::read(&settings));
    let out = run(&w, &format!("echo poisoned > {}", quote(&settings)));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Operation not permitted"),
        "{}",
        text(&out)
    );
    let dir = assert_some!(settings.parent());
    let swap = run(
        &w,
        &format!(
            "echo poisoned > {d}/new.json; mv {d}/new.json {s} 2>&1; rm {s} 2>&1; true",
            d = quote(dir),
            s = quote(&settings)
        ),
    );
    assert!(
        text(&swap).contains("Operation not permitted"),
        "{}",
        text(&swap)
    );
    assert_eq!(assert_ok!(fs::read(settings)), before);
    let consumer = start_like_claude(&w.home_dir());
    assert!(consumer.status.success(), "{}", text(&consumer));
    assert!(!marker.exists());
}

fn kiro_fixture(shipped: bool) -> (World, PathBuf, PathBuf, PathBuf) {
    let w = if shipped {
        agent_world("kiro", "")
    } else {
        control_world("kiro")
    };
    let program = w.home_dir().join(".local/bin/kiro-cli");
    let alias = w
        .home_dir()
        .join("Library/Application Support/kiro-cli/run/chat-cli-0.0.0");
    executable(&program, "#!/bin/sh\necho benign\n");
    assert_ok!(fs::create_dir_all(assert_some!(alias.parent())));
    assert_ok!(fs::hard_link(&program, &alias));
    let marker = w.base.join("outside/marker");
    assert_ok!(fs::create_dir_all(assert_some!(marker.parent())));
    (w, program, alias, marker)
}

#[test]
fn a_write_through_kiros_hard_linked_run_copy_changes_the_program() {
    sandboxed!();
    let (w, program, alias, marker) = kiro_fixture(false);
    let inode = assert_ok!(fs::metadata(&program)).ino();
    assert_cannot_write(&w, &marker);
    let direct = run(&w, &format!("echo direct > {}", quote(&program)));
    assert!(!direct.status.success(), "{}", text(&direct));
    assert!(
        text(&direct).contains("Operation not permitted"),
        "{}",
        text(&direct)
    );
    let payload = format!("#!/bin/sh\necho linked-canary > {}\n", quote(&marker));
    let out = run(
        &w,
        &format!(
            "printf %s {} > {}",
            quote(Path::new(&payload)),
            quote(&alias)
        ),
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(assert_ok!(fs::metadata(&program)).ino(), inode);
    assert_eq!(assert_ok!(fs::metadata(&alias)).ino(), inode);
    assert!(!marker.exists(), "the plant itself wrote the marker");
    let consumer = assert_ok!(std::process::Command::new(program).env_clear().output());
    assert!(consumer.status.success(), "{}", text(&consumer));
    assert_eq!(assert_ok!(fs::read_to_string(marker)), "linked-canary\n");
}

#[test]
fn a_deny_write_on_kiros_run_directory_keeps_the_linked_program() {
    sandboxed!();
    let (w, program, alias, marker) = kiro_fixture(true);
    let before = assert_ok!(fs::read(&program));
    let out = run(&w, &format!("echo poisoned > {}", quote(&alias)));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Operation not permitted"),
        "{}",
        text(&out)
    );
    let swap = run(&w, &format!("rm {a} 2>&1; true", a = quote(&alias)));
    assert!(
        text(&swap).contains("Operation not permitted"),
        "{}",
        text(&swap)
    );
    assert_eq!(assert_ok!(fs::read(program.clone())), before);
    assert_eq!(assert_ok!(fs::read(alias)), before);
    let consumer = assert_ok!(std::process::Command::new(program).env_clear().output());
    assert!(consumer.status.success(), "{}", text(&consumer));
    assert!(text(&consumer).contains("benign"));
    assert!(!marker.exists());
}

// ---- hb-82i probe: deny_write on paths that do not exist yet (a fresh home has no hooks/ or plugins/).
#[test]
fn a_deny_write_on_an_absent_directory_and_an_absent_file_blocks_creating_them() {
    sandboxed!();
    let w = agent_world(
        "claude",
        "deny_write = [\"~/.claude/hooks\", \"~/.claude/settings.json\", \"~/.claude.json\"]\n",
    );
    let home = w.home_dir();
    assert_ok!(fs::create_dir_all(home.join(".claude")));
    let mk = run(
        &w,
        &format!(
            "mkdir {h}/.claude/hooks 2>&1; echo '{{}}' > {h}/.claude/settings.json 2>&1; echo '{{}}' > {h}/.claude.json 2>&1; true",
            h = quote(&home)
        ),
    );
    assert_eq!(
        text(&mk).matches("Operation not permitted").count(),
        3,
        "{}",
        text(&mk)
    );
    assert!(!home.join(".claude/hooks").exists());
    assert!(!home.join(".claude/settings.json").exists());
    assert!(!home.join(".claude.json").exists());
    // The rest of the directory still takes ordinary writes (history).
    let ok = run(
        &w,
        &format!(
            "mkdir -p {h}/.claude/projects && echo t > {h}/.claude/projects/s.jsonl",
            h = quote(&home)
        ),
    );
    assert!(ok.status.success(), "{}", text(&ok));
}

/// hb-82i probe: the oracle asked whether a file that an agent rewrites by temp-file-plus-rename can be protected.
/// Each operation is run on its own so one refusal cannot hide another that succeeded.
#[test]
fn each_way_to_replace_a_denied_file_fails_on_its_own() {
    sandboxed!();
    let (w, settings, _marker) = claude_fixture(true);
    let before = assert_ok!(fs::read(&settings));
    let dir = quote(assert_some!(settings.parent()));
    let s = quote(&settings);
    for (what, script) in [
        ("truncate", format!(": > {s}")),
        ("append", format!("echo x >> {s}")),
        (
            "temp then rename over it",
            format!("echo x > {dir}/t.json && mv -f {dir}/t.json {s}"),
        ),
        ("unlink", format!("rm -f {s}")),
        ("move aside", format!("mv {s} {dir}/aside.json")),
        (
            "link over",
            format!("echo x > {dir}/t2.json && ln -f {dir}/t2.json {s}"),
        ),
        ("chmod", format!("chmod 666 {s}")),
        // The parent directory cannot be moved aside to make room for a planted copy (ancestor pin).
        ("rename the parent", format!("mv {dir} {dir}-aside")),
    ] {
        let out = run(&w, &script);
        assert!(!out.status.success(), "{what} succeeded: {}", text(&out));
        assert_eq!(
            assert_ok!(fs::read(&settings)),
            before,
            "{what} changed the file"
        );
    }
    assert!(!assert_some!(settings.parent()).join("aside.json").exists());
}

// ---- hb-82i review: project-local executable settings, per shipped preset, absent and present.
/// What each preset must keep read-only inside the PROJECT, and what must stay writable beside it.
const PROJECT_LOCAL: &[(&str, &[&str], &[&str])] = &[
    (
        "claude",
        &[
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".mcp.json",
            ".claude/hooks/h.sh",
            ".claude/plugins/p.json",
            ".claude/commands/c.md",
            ".claude/agents/a.md",
        ],
        &[".claude/skills/s.md", ".claude/rules/r.md", "CLAUDE.md"],
    ),
    (
        "pi",
        &[
            ".pi/settings.json",
            ".pi/extensions/e.ts",
            ".pi/npm/n.json",
            ".pi/git/g.json",
            ".pi/agents/a.md",
        ],
        &[".pi/skills/s.md", ".pi/prompts/p.md"],
    ),
    (
        "kiro",
        &[
            ".kiro/settings/mcp.json",
            ".kiro/agents/a.json",
            ".kiro/hooks/h.sh",
        ],
        &[".kiro/steering/s.md", ".kiro/skills/s.md"],
    ),
    (
        "opencode",
        &[".opencode/plugin/p.js", "opencode.json", "opencode.jsonc"],
        &[".opencode-notes.md"],
    ),
];

#[test]
fn every_shipped_preset_denies_project_local_executable_settings_and_leaves_instructions_writable()
{
    sandboxed!();
    for (name, denied, open) in PROJECT_LOCAL {
        let w = agent_world(name, "");
        // `.opencode-notes.md` also proves `.opencode` is matched as a directory, not as a prefix.
        for path in *denied {
            let target = w.project.join(path);
            let dir = quote(assert_some!(target.parent()));
            let script = format!("mkdir -p {dir} 2>&1; echo x > {t} 2>&1", t = quote(&target));
            let out = run(&w, &script);
            assert!(
                !target.exists(),
                "{name}: {path} was written under the shipped preset: {}",
                text(&out)
            );
        }
        for path in *open {
            let target = w.project.join(path);
            let dir = quote(assert_some!(target.parent()));
            let out = run(
                &w,
                &format!("mkdir -p {dir} && echo x > {t}", t = quote(&target)),
            );
            assert!(
                out.status.success() && target.exists(),
                "{name}: {path} should stay writable: {}",
                text(&out)
            );
        }
    }
}

/// hb-82i criterion 3 and 2: a project that extends a SHIPPED agent preset (so with its denies) and declares an
/// offline server still gets a working warm-then-run, where the tool uses the run's own cache copy, and an
/// ordinary history write next to the denied files works. The preset's denies must not touch the session cache.
#[test]
fn a_project_extending_each_shipped_preset_runs_its_offline_tool_from_its_own_cache_copy() {
    sandboxed!();
    for agent in ["claude", "pi", "kiro", "opencode"] {
        let base = "[tls]\nsystem_trust = true\n[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\"]\n";
        let project = format!(
            "extends = [\"agent/{agent}\"]\n[mcp.time]\ncommand = \"uvx\"\nargs = [\"mcp-server-time\"]\n"
        );
        let w = World::with_base(base, &project);
        executable(
            &w.base.join("bin/uvx"),
            "#!/bin/sh\necho \"uvx-ran cache=$UV_CACHE_DIR\"\ncat \"$UV_CACHE_DIR/seed\"\n",
        );
        w.publish_cache(&[("uv/seed", "published")]);
        let out = run(
            &w,
            "uvx anything; echo written > \"$TMPDIR/cache/uv/own\" && echo own-copy-writable",
        );
        let all = text(&out);
        assert!(
            all.contains("uvx-ran"),
            "{agent}: the tool did not run: {all}"
        );
        assert!(
            all.contains("published"),
            "{agent}: the tool did not see the published cache: {all}"
        );
        assert!(
            all.contains("own-copy-writable"),
            "{agent}: the run's own copy is not writable: {all}"
        );
        assert!(
            !all.contains(".cache/hamster-ball"),
            "{agent}: the tool was pointed at the shared store: {all}"
        );
    }
}

// ---- hb-82i round 3: a denied project-local path cannot be bypassed by moving, replacing or linking around it.
#[test]
fn a_denied_project_path_cannot_be_bypassed_by_rename_symlink_or_hard_link() {
    sandboxed!();
    let w = agent_world("claude", "");
    let p = quote(&w.project);
    // Each script must FAIL and leave no denied path behind; each is its own run so one refusal cannot hide another.
    for (what, script, leftover) in [
        (
            "write into a directory the ball made",
            format!("cd {p} && mkdir -p .claude && echo x > .claude/settings.json"),
            ".claude/settings.json",
        ),
        (
            "rename a protected-ancestor aside",
            format!("cd {p} && mkdir -p .claude && mv .claude .claude-old"),
            ".claude-old",
        ),
        (
            "replace the directory by a symlink to a writable one",
            format!(
                "cd {p} && mkdir -p elsewhere .claude && rm -rf .claude && ln -s elsewhere .claude && echo x > .claude/settings.json"
            ),
            "elsewhere/settings.json",
        ),
        (
            "rename a temp file over a denied file",
            format!("cd {p} && echo x > t.json && mv -f t.json .mcp.json"),
            ".mcp.json",
        ),
        (
            "create a denied file as a symlink",
            format!("cd {p} && ln -s /tmp/x .mcp.json"),
            ".mcp.json",
        ),
        (
            "hard-link a writable file to a denied name",
            format!("cd {p} && echo x > h.json && ln h.json .mcp.json"),
            ".mcp.json",
        ),
    ] {
        let out = run(&w, &script);
        assert!(!out.status.success(), "{what} succeeded: {}", text(&out));
        assert!(
            fs::symlink_metadata(w.project.join(leftover)).is_err(),
            "{what}: {leftover} exists afterwards"
        );
    }
}

// ---- Versioned inventory (hb-tx4 criteria 1 and 3). Test-only table; shortcut: move to src/ when hb-82i makes presets consume it.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// What hb-82i is asked to do with a mixed file; nothing here isolates anything yet.
enum Disposition {
    RequiresIsolation,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Executable,
    Instruction,
    SessionData,
    /// Holds code and data in one file; hb-82i must isolate or refuse it, never call it supported.
    Mixed(Disposition),
}

struct Entry {
    path: &'static str,
    class: Class,
    /// Why the class is believed: "read" means seen on disk or in the install; anything else is an unmeasured assumption.
    evidence: &'static str,
}

struct AgentInventory {
    preset: &'static str,
    binary: &'static str,
    /// Version the entries were inventoried against.
    version: &'static str,
    /// Version the preset's own header names.
    preset_version: &'static str,
    /// Why `preset_version` may differ from `version`; `None` means they must be equal.
    accepted_drift: Option<&'static str>,
    /// The reviewed `[fs] write` and `deny_write` sets; a preset edit must update them and the rows.
    write: &'static [&'static str],
    deny: &'static [&'static str],
    preset_toml: &'static str,
    entries: &'static [Entry],
}

use Class::{Executable, Instruction, Mixed, SessionData};
use Disposition::{RequiresIsolation, Unsupported};

const fn e(path: &'static str, class: Class, evidence: &'static str) -> Entry {
    Entry {
        path,
        class,
        evidence,
    }
}

const INVENTORY: &[AgentInventory] = &[
    AgentInventory {
        preset: "claude",
        binary: "claude",
        version: "2.1.328",
        preset_version: "2.1.328",
        accepted_drift: None,
        write: &[
            "~/.claude",
            "~/.claude.json",
            "~/.cache/claude",
            "~/.local/state/claude",
        ],
        deny: &[
            "~/.claude/settings.json",
            "~/.claude.json",
            "~/.claude/hooks",
            "~/.claude/plugins",
            "~/.claude/commands",
            "~/.claude/agents",
            "~/.claude/shell-snapshots",
            ".claude/settings.json",
            ".claude/settings.local.json",
            ".mcp.json",
            ".claude/hooks",
            ".claude/plugins",
            ".claude/commands",
            ".claude/agents",
        ],
        preset_toml: include_str!("../presets/agent/claude.toml"),
        entries: &[
            e(
                "~/.claude/settings.json",
                Mixed(RequiresIsolation),
                "read: hooks, awsAuthRefresh, otelHeadersHelper, env, enabledPlugins",
            ),
            e(
                "~/.claude.json",
                Mixed(RequiresIsolation),
                "read keys; whether isolation breaks OAuth refresh is unmeasured",
            ),
            e("~/.claude/hooks", Executable, "read"),
            e("~/.claude/plugins", Executable, "read"),
            e("~/.claude/commands", Executable, "assumed: vendor docs"),
            e("~/.claude/agents", Executable, "assumed: vendor docs"),
            e(
                "~/.claude/shell-snapshots",
                Executable,
                "assumed: sourced by the Bash tool, unmeasured",
            ),
            e("~/.claude/CLAUDE.md", Instruction, "read"),
            e("~/.claude/skills", Instruction, "read"),
            e("~/.claude/rules", Instruction, "read"),
            e("~/.claude/projects", SessionData, "read"),
            e("~/.claude/sessions", SessionData, "read"),
            e("~/.claude/history.jsonl", SessionData, "read"),
            e("~/.cache/claude", SessionData, "read"),
            e("~/.local/state/claude", SessionData, "read"),
        ],
    },
    AgentInventory {
        preset: "pi",
        binary: "pi",
        version: "1.7.0",
        preset_version: "1.7.0",
        accepted_drift: None,
        write: &["~/.pi/agent"],
        deny: &[
            "~/.pi/agent/bin",
            "~/.pi/agent/install",
            "~/.pi/agent/settings.json",
            "~/.pi/agent/models.json",
            "~/.pi/agent/models-store.json",
            "~/.pi/agent/trust.json",
            "~/.pi/agent/extensions",
            "~/.pi/agent/npm",
            "~/.pi/agent/git",
            "~/.pi/agent/agents",
            "~/.pi/agent/tmp/extensions",
            ".pi/settings.json",
            ".pi/extensions",
            ".pi/npm",
            ".pi/git",
            ".pi/agents",
        ],
        preset_toml: include_str!("../presets/agent/pi.toml"),
        entries: &[
            e("~/.pi/agent/extensions", Executable, "read"),
            e("~/.pi/agent/npm", Executable, "read"),
            e("~/.pi/agent/git", Executable, "read"),
            e("~/.pi/agent/agents", Executable, "read"),
            e(
                "~/.pi/agent/settings.json",
                Mixed(RequiresIsolation),
                "read: `packages` lists code to load",
            ),
            e(
                "~/.pi/agent/models.json",
                Mixed(RequiresIsolation),
                "assumed: provider URLs redirect traffic",
            ),
            e(
                "~/.pi/agent/trust.json",
                Executable,
                "assumed: records what pi trusts",
            ),
            e(
                "~/.pi/agent/tmp/extensions",
                Executable,
                "read in pi 1.7.0 source (package-manager.js getExtensionTempFolder): created on demand, stable hashed names, reused; absent on this machine",
            ),
            e(
                "~/.pi/agent/models-store.json",
                Mixed(RequiresIsolation),
                "read: provider routing (key names only); denied with models.json",
            ),
            e(
                "~/.pi/agent/auth.json",
                SessionData,
                "read: pi's login, kept writable so a refresh can work; whether pi runs it is unmeasured",
            ),
            e(
                "~/.pi/agent/bead-goals",
                SessionData,
                "read: markdown goal files (names only)",
            ),
            e(
                "~/.pi/agent/web-search-cache",
                SessionData,
                "read: cache dir, empty here",
            ),
            e("~/.pi/agent/AGENTS.md", Instruction, "read"),
            e("~/.pi/agent/skills", Instruction, "read"),
            e("~/.pi/agent/prompts", Instruction, "read"),
            e("~/.pi/agent/sessions", SessionData, "read"),
            e("~/.pi/agent/bin", Executable, "read: preset denies writes"),
            e(
                "~/.pi/agent/install",
                Executable,
                "read: preset denies writes",
            ),
        ],
    },
    AgentInventory {
        preset: "kiro",
        binary: "kiro-cli",
        version: "3.6.2",
        preset_version: "3.6.2",
        accepted_drift: None,
        write: &["~/.kiro", "~/Library/Application Support/kiro-cli"],
        deny: &[
            "~/Library/Application Support/kiro-cli/bun",
            "~/Library/Application Support/kiro-cli/bunfig.toml",
            "~/Library/Application Support/kiro-cli/kas",
            "~/Library/Application Support/kiro-cli/node",
            "~/Library/Application Support/kiro-cli/tui.js",
            "~/Library/Application Support/kiro-cli/run/chat-cli-*",
            "~/Library/Application Support/kiro-cli/shell-integration-backup",
            "~/.kiro/settings",
            "~/.kiro/agents",
            ".kiro/settings",
            ".kiro/agents",
            ".kiro/hooks",
        ],
        preset_toml: include_str!("../presets/agent/kiro.toml"),
        entries: &[
            e(
                "~/Library/Application Support/kiro-cli/run/chat-cli-3.6.2",
                Executable,
                "read: chat-cli-<v> was a hard link to ~/.local/bin/kiro-cli; the preset denies the glob chat-cli-*",
            ),
            e(
                "~/Library/Application Support/kiro-cli/run/turn-markers",
                SessionData,
                "read: written on every chat; a deny cost one refusal",
            ),
            e(
                "~/Library/Application Support/kiro-cli/shell-integration-backup",
                Executable,
                "assumed: restore trigger unmeasured",
            ),
            e(
                "~/Library/Application Support/kiro-cli/data.sqlite3",
                Mixed(Unsupported),
                "read: login token and state share one file",
            ),
            e(
                "~/Library/Application Support/kiro-cli/bun",
                Executable,
                "read: preset denies writes",
            ),
            e(
                "~/Library/Application Support/kiro-cli/node",
                Executable,
                "read: preset denies writes",
            ),
            e(
                "~/Library/Application Support/kiro-cli/tui.js",
                Executable,
                "read: preset denies writes",
            ),
            e(
                "~/Library/Application Support/kiro-cli/kas",
                Executable,
                "read: preset denies writes",
            ),
            e(
                "~/Library/Application Support/kiro-cli/bunfig.toml",
                Executable,
                "read: preset denies writes",
            ),
            e("~/.kiro/settings", Executable, "read: MCP commands"),
            e(
                "~/.kiro/agents",
                Executable,
                "assumed: hooks and MCP in agent configs",
            ),
            e("~/.kiro/steering", Instruction, "read"),
            e("~/.kiro/skills", Instruction, "read"),
            e("~/.kiro/sessions", SessionData, "read"),
        ],
    },
    AgentInventory {
        preset: "opencode",
        binary: "opencode",
        version: "1.2.0",
        preset_version: "1.2.0",
        accepted_drift: None,
        write: &[
            "~/.cache/opencode",
            "~/.local/share/opencode",
            "~/.local/state/opencode",
        ],
        deny: &[
            "~/.config/opencode",
            ".opencode",
            "opencode.json",
            "opencode.jsonc",
            "~/.cache/opencode/bun.lock",
            "~/.cache/opencode/node_modules",
            "~/.cache/opencode/package.json",
            "~/.local/share/opencode/bin",
        ],
        preset_toml: include_str!("../presets/agent/opencode.toml"),
        entries: &[
            e(
                "~/.local/share/opencode/bin",
                Executable,
                "read: preset denies writes",
            ),
            e(
                "~/.cache/opencode/node_modules",
                Executable,
                "assumed: layout is version dependent; absent here",
            ),
            e(
                "~/.cache/opencode/package.json",
                Executable,
                "assumed: layout is version dependent; absent here",
            ),
            e(
                "~/.cache/opencode/bun.lock",
                Executable,
                "assumed: layout is version dependent; absent here",
            ),
            e(
                "~/.config/opencode",
                Executable,
                "read: preset grants read only",
            ),
            e("~/.local/share/opencode/storage", SessionData, "read"),
            e("~/.local/state/opencode", SessionData, "read"),
            e("~/.cache/opencode/version", SessionData, "read"),
        ],
    },
];

fn grants(inv: &AgentInventory, key: &str) -> Vec<String> {
    let doc: toml::Table = assert_ok!(inv.preset_toml.parse());
    doc.get("fs")
        .and_then(|fs| fs.get(key))
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn under(path: &str, root: &str) -> bool {
    // `dir/prefix*` covers the entries of `dir` whose name starts with `prefix` (and what is under
    // them), and nothing else: not `dir` itself and not a differently named sibling.
    if let Some(star) = root.strip_suffix('*') {
        return path.starts_with(star);
    }
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Raw preset inventory only: rows a listed write grant overlaps and no listed deny covers.
/// It ignores existence, canonicalization, inherited policy and the floor, so it is grant-change
/// detection, not proof of what a run can write.
fn exposed(inv: &AgentInventory) -> Vec<&Entry> {
    let (write, deny) = (grants(inv, "write"), grants(inv, "deny_write"));
    inv.entries
        .iter()
        .filter(|en| matches!(en.class, Executable | Mixed(_)))
        .filter(|en| write.iter().any(|w| under(en.path, w)))
        .filter(|en| !deny.iter().any(|d| under(en.path, d)))
        .collect()
}

fn agent(name: &str) -> &'static AgentInventory {
    assert_some!(INVENTORY.iter().find(|a| a.preset == name))
}

#[test]
fn every_write_grant_of_a_shipped_preset_has_inventory_rows_and_every_deny_names_executable_state()
{
    for inv in INVENTORY {
        for grant in grants(inv, "write") {
            assert!(
                inv.entries
                    .iter()
                    .any(|en| under(en.path, &grant) || under(&grant, en.path)),
                "{}: write grant {grant} has no inventory row; classify it before shipping the preset",
                inv.preset
            );
        }
        // Project-relative denies (no `~`) are proven by real writes in
        // every_shipped_preset_denies_project_local_..., and the inventory only lists home paths.
        for deny in grants(inv, "deny_write")
            .iter()
            .filter(|d| d.starts_with('~'))
        {
            assert!(
                inv.entries
                    .iter()
                    .any(|en| matches!(en.class, Executable | Mixed(_)) && under(en.path, deny)),
                "{}: deny_write {deny} protects no inventoried executable state",
                inv.preset
            );
        }
    }
}

/// The version token after `agent/<name>: <binary> ` in a preset's first line.
fn header_version(header: &str) -> Option<&str> {
    let rest = header.split_once(": ")?.1;
    rest.split_whitespace()
        .nth(1)?
        .strip_suffix(',')
        .or_else(|| rest.split_whitespace().nth(1))
}

#[test]
fn preset_headers_match_the_recorded_version_and_drift_is_explicit() {
    for inv in INVENTORY {
        let header = inv.preset_toml.lines().next().unwrap_or_default();
        assert_eq!(
            header_version(header),
            Some(inv.preset_version),
            "{}: preset header `{header}` no longer names the recorded version",
            inv.preset
        );
        assert_eq!(
            inv.preset_version != inv.version,
            inv.accepted_drift.is_some(),
            "{}: preset {} vs inventory {}: record or remove accepted_drift",
            inv.preset,
            inv.preset_version,
            inv.version
        );
        if let Some(why) = inv.accepted_drift {
            eprintln!(
                "DRIFT {}: preset {} vs inventory {}: {why}",
                inv.preset, inv.preset_version, inv.version
            );
        }
    }
}

#[test]
fn the_reviewed_grant_sets_equal_the_shipped_presets_and_cover_every_agent_preset() {
    for inv in INVENTORY {
        assert_eq!(
            grants(inv, "write"),
            inv.write,
            "{}: write grants changed; reclassify the rows",
            inv.preset
        );
        assert_eq!(
            grants(inv, "deny_write"),
            inv.deny,
            "{}: deny_write changed; reclassify the rows",
            inv.preset
        );
    }
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("presets/agent");
    let mut shipped: Vec<String> = assert_ok!(fs::read_dir(dir))
        .filter_map(|f| f.ok()?.path().file_stem()?.to_str().map(str::to_owned))
        .collect();
    shipped.sort();
    let mut known: Vec<String> = INVENTORY.iter().map(|a| a.preset.to_owned()).collect();
    known.sort();
    assert_eq!(shipped, known, "a shipped agent preset has no inventory");
}

/// hb-82i gate: every Executable or Mixed row the inventory lists under a write grant is denied by
/// the shipped preset, except the rows this bead decided to leave open and named (below).
#[test]
fn shipped_presets_deny_every_executable_and_mixed_row_except_the_named_residuals() {
    // path -> why it is left writable; a new entry here needs the same written reason in the preset header.
    const RESIDUAL: &[(&str, &str)] = &[(
        "~/Library/Application Support/kiro-cli/data.sqlite3",
        "login token shares the file with sessions; a refresh over a denied write is unmeasured (kiro.toml header)",
    )];
    for inv in INVENTORY {
        let open: Vec<&str> = exposed(inv)
            .iter()
            .map(|en| en.path)
            .filter(|path| !RESIDUAL.iter().any(|(r, _)| r == path))
            .collect();
        assert!(
            open.is_empty(),
            "{}: executable or mixed rows still writable: {open:?}",
            inv.preset
        );
    }
    // The residual set is pinned by value, not only by the list above: widening it needs an edit
    // here AND an owner decision recorded in hb-82i, so one more entry in RESIDUAL cannot hide a hole.
    let mut all_open: Vec<(&str, &str)> = INVENTORY
        .iter()
        .flat_map(|inv| {
            exposed(inv)
                .into_iter()
                .map(move |en| (inv.preset, en.path))
        })
        .collect();
    all_open.sort_unstable();
    assert_eq!(
        all_open,
        [(
            "kiro",
            "~/Library/Application Support/kiro-cli/data.sqlite3"
        )],
        "the rows left writable changed; that is an owner decision (hb-82i), not a test edit"
    );
    assert_eq!(RESIDUAL.len(), 1, "RESIDUAL grew without an owner decision");
}

/// hb-82i criterion 2, stated structurally: hb promises that session history stays writable, so no
/// shipped preset may deny (or fail to grant) a row the inventory calls SessionData. This does not
/// prove an agent resumes a session; the measured evidence for that is in history/hb-82i_probe-facts.md
/// (claude wrote its transcript, kiro a session, pi's `sessions` is outside every deny).
#[test]
fn no_shipped_preset_denies_or_withholds_a_session_data_row_it_promises() {
    // The rows each agent's history promise names (presets/README.md, State, login and persistence).
    const PROMISED: &[(&str, &[&str])] = &[
        (
            "claude",
            &[
                "~/.claude/projects",
                "~/.claude/sessions",
                "~/.claude/history.jsonl",
            ],
        ),
        ("pi", &["~/.pi/agent/sessions"]),
        ("kiro", &["~/.kiro/sessions"]),
        (
            "opencode",
            &["~/.local/share/opencode/storage", "~/.local/state/opencode"],
        ),
    ];
    for (name, rows) in PROMISED {
        let inv = agent(name);
        let (write, deny) = (grants(inv, "write"), grants(inv, "deny_write"));
        for row in *rows {
            assert!(
                inv.entries
                    .iter()
                    .any(|en| en.path == *row && en.class == SessionData),
                "{name}: {row} is promised but not inventoried as SessionData"
            );
            assert!(
                write.iter().any(|w| under(row, w)),
                "{name}: promised history {row} is not writable"
            );
            assert!(
                !deny.iter().any(|d| under(row, d) || under(d, row)),
                "{name}: promised history {row} is denied or sits above a deny"
            );
        }
    }
}

/// A report, not a gate: run with `-- --nocapture` to list rows no measurement backs yet.
#[test]
fn unmeasured_and_mixed_rows_are_reported() {
    for inv in INVENTORY {
        for en in inv.entries {
            if en.evidence.starts_with("assumed") || en.evidence.contains("unmeasured") {
                eprintln!("UNMEASURED {} {}: {}", inv.preset, en.path, en.evidence);
            }
            if let Mixed(d) = en.class {
                eprintln!("MIXED {} {} {d:?}", inv.preset, en.path);
            }
        }
    }
}

/// Why a real-install probe did not yield a version.
enum Probe {
    Absent,
    Failed(String),
}

fn installed_version(binary: &str) -> Result<(PathBuf, String), Probe> {
    let path = std::env::var_os("PATH").ok_or(Probe::Absent)?;
    let program = std::env::split_paths(&path)
        .map(|d| d.join(binary))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
        .ok_or(Probe::Absent)?;
    let fail = |why: String| Probe::Failed(format!("{}: {why}", program.display()));
    let home = std::env::var_os("HOME").ok_or_else(|| fail("HOME unset".into()))?;
    let mut child = std::process::Command::new(&program)
        .arg("--version")
        .env_clear()
        .env("PATH", path)
        .env("HOME", home)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| fail(e.to_string()))?;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    // shortcut: --version output is tiny, so the pipe cannot fill before exit; a chatty agent needs a reader thread.
    while child.try_wait().map_err(|e| fail(e.to_string()))?.is_none() {
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(fail("--version timed out".into()));
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let out = child.wait_with_output().map_err(|e| fail(e.to_string()))?;
    if !out.status.success() {
        return Err(fail(format!("--version exited {}", out.status)));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let version = regex::Regex::new(r"\b\d+\.\d+\.\d+\b")
        .map_err(|e| fail(e.to_string()))?
        .find(&text)
        .map(|m| m.as_str().to_owned())
        .ok_or_else(|| fail(format!("no version in `{}`", text.trim())))?;
    Ok((program, version))
}

/// Runs the real installed agents (`--version` only, with the real HOME), so it is opt-in:
/// HB_INSPECT_AGENTS=1 enables it, and HB_REQUIRE_AGENTS=1 additionally fails on a missing agent.
#[test]
fn installed_agents_match_the_inventoried_versions() {
    if std::env::var_os("HB_INSPECT_AGENTS").is_none() {
        eprintln!("SKIP: installed-agent version check is opt-in (HB_INSPECT_AGENTS=1)");
        return;
    }
    let required = std::env::var_os("HB_REQUIRE_AGENTS").is_some();
    for inv in INVENTORY {
        match installed_version(inv.binary) {
            Ok((program, v)) => assert_eq!(
                v,
                inv.version,
                "{}: {} reports {v}, the inventory pins {}; re-run the measurements before trusting it",
                inv.preset,
                program.display(),
                inv.version
            ),
            Err(Probe::Failed(why)) => {
                assert!(why.is_empty(), "{}: probe failed: {why}", inv.preset);
            }
            Err(Probe::Absent) => {
                assert!(
                    !required,
                    "HB_REQUIRE_AGENTS is set but {} is not installed",
                    inv.binary
                );
                eprintln!(
                    "SKIP: {} not installed; inventory pinned {} unchecked",
                    inv.binary, inv.version
                );
            }
        }
    }
}

#[test]
fn under_treats_a_sibling_with_a_shared_prefix_as_a_different_path() {
    assert!(under("~/.claude/settings.json", "~/.claude"));
    assert!(under("~/.claude", "~/.claude"));
    assert!(!under("~/.claude.json", "~/.claude"));
    assert!(!under("~/.claude-other/x", "~/.claude"));
}

#[test]
fn a_glob_covers_only_the_names_it_matches_and_what_is_under_them() {
    let glob = "~/K/run/chat-cli-*";
    assert!(under("~/K/run/chat-cli-3.6.2", glob), "a matching name");
    assert!(under("~/K/run/chat-cli-9.9.9", glob), "a name made later");
    assert!(under("~/K/run/chat-cli-3.6.2/inner", glob), "under a match");
    assert!(
        !under("~/K/run", glob),
        "the parent directory is not covered"
    );
    assert!(
        !under("~/K/run/turn-markers", glob),
        "a sibling is not covered"
    );
    assert!(
        !under("~/K/run/chat-cl", glob),
        "a shorter name is not covered"
    );
    assert!(!under("~/K/other/chat-cli-1", glob), "another directory");
}
