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

fn cache_fixture(with_server: bool) -> (World, PathBuf, PathBuf, PathBuf) {
    let w = World::with_base(BASE, if with_server { SERVER } else { "" });
    executable(
        &w.base.join("bin/uvx"),
        "#!/bin/sh\nif [ -f \"$UV_TOOL_DIR/canary/bin/canary\" ]; then exec /bin/sh \"$UV_TOOL_DIR/canary/bin/canary\"; else echo no-planted-tool; fi\n",
    );
    let b = w.add_project("other", SERVER);
    let marker = b.join("marker");
    let planted = w
        .home_dir()
        .join(".cache/hamster-ball/uv-tools/canary/bin/canary");
    write(&planted, "#!/bin/sh\necho benign\n");
    (w, b, marker, planted)
}

#[test]
fn a_planted_tool_in_hbs_cache_runs_in_another_projects_ball() {
    sandboxed!();
    let (w, b, marker, planted) = cache_fixture(true);
    assert_cannot_write(&w, &marker);
    let payload = format!("#!/bin/sh\necho cache-canary > {}\n", quote(&marker));
    let out = run(
        &w,
        &format!(
            "printf %s {} > {}",
            quote(Path::new(&payload)),
            quote(&planted)
        ),
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(assert_ok!(fs::read_to_string(&planted)), payload);
    assert!(!marker.exists(), "the plant itself wrote the marker");
    let consumer = run_at(&w, &b, "uvx canary");
    assert!(consumer.status.success(), "{}", text(&consumer));
    assert_eq!(assert_ok!(fs::read_to_string(marker)), "cache-canary\n");
}

#[test]
fn a_run_that_is_not_granted_hbs_cache_cannot_plant_in_it() {
    sandboxed!();
    let (w, b, marker, planted) = cache_fixture(false);
    let before = assert_ok!(fs::read(&planted));
    let out = run(&w, &format!("echo poisoned > {}", quote(&planted)));
    assert!(!out.status.success(), "{}", text(&out));
    assert!(
        text(&out).contains("Operation not permitted"),
        "{}",
        text(&out)
    );
    assert_eq!(assert_ok!(fs::read(planted)), before);
    let consumer = run_at(&w, &b, "uvx canary");
    assert!(consumer.status.success(), "{}", text(&consumer));
    assert!(text(&consumer).contains("benign"), "{}", text(&consumer));
    assert!(!marker.exists());
}

fn agent_world(agent: &str, deny: &str) -> World {
    let base = format!("[tls]\nsystem_trust = true\n[fs]\nwrite = [\".\"]\n{deny}");
    World::with_base(&base, &format!("extends = [\"agent/{agent}\"]\n"))
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

fn claude_fixture(deny: bool) -> (World, PathBuf, PathBuf) {
    let w = agent_world(
        "claude",
        if deny {
            "deny_write = [\"~/.claude/settings.json\"]\n"
        } else {
            ""
        },
    );
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

fn kiro_fixture(deny: bool) -> (World, PathBuf, PathBuf, PathBuf) {
    let w = agent_world(
        "kiro",
        if deny {
            "deny_write = [\"~/Library/Application Support/kiro-cli/run\"]\n"
        } else {
            ""
        },
    );
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
        deny: &[],
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
        preset_version: "1.6.0",
        accepted_drift: Some("hb-82i re-measures the preset against the installed agent"),
        write: &["~/.pi/agent"],
        deny: &["~/.pi/agent/bin", "~/.pi/agent/install"],
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
        preset_version: "3.5.0",
        accepted_drift: Some("hb-82i re-measures the preset against the installed agent"),
        write: &["~/.kiro", "~/Library/Application Support/kiro-cli"],
        deny: &[
            "~/Library/Application Support/kiro-cli/bun",
            "~/Library/Application Support/kiro-cli/bunfig.toml",
            "~/Library/Application Support/kiro-cli/kas",
            "~/Library/Application Support/kiro-cli/node",
            "~/Library/Application Support/kiro-cli/tui.js",
        ],
        preset_toml: include_str!("../presets/agent/kiro.toml"),
        entries: &[
            e(
                "~/Library/Application Support/kiro-cli/run",
                Executable,
                "read: chat-cli-<v> was a hard link to ~/.local/bin/kiro-cli",
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
        .filter(|en| en.class != SessionData)
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
        for deny in grants(inv, "deny_write") {
            assert!(
                inv.entries
                    .iter()
                    .any(|en| en.class == Executable && under(&deny, en.path)),
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

#[test]
fn shipped_presets_leave_the_attacked_paths_writable_today() {
    let claude = exposed(agent("claude"))
        .iter()
        .map(|en| en.path)
        .collect::<Vec<_>>();
    assert!(
        claude.contains(&"~/.claude/settings.json") && claude.contains(&"~/.claude/hooks"),
        "{claude:?}"
    );
    let kiro = exposed(agent("kiro"))
        .iter()
        .map(|en| en.path)
        .collect::<Vec<_>>();
    assert!(
        kiro.contains(&"~/Library/Application Support/kiro-cli/run"),
        "{kiro:?}"
    );
    assert!(
        kiro.contains(&"~/Library/Application Support/kiro-cli/data.sqlite3"),
        "{kiro:?}"
    );
    // pi, opencode: the preset denies its own binaries; the rest stays exposed until hb-82i.
    assert!(
        exposed(agent("pi"))
            .iter()
            .any(|en| en.path == "~/.pi/agent/extensions")
    );
    assert!(
        !exposed(agent("opencode"))
            .iter()
            .any(|en| en.path == "~/.local/share/opencode/bin")
    );
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
