// ABOUTME: Black-box tests of `hb explain`: golden text and JSON, redaction, escaping, ordering, warnings and floor attribution.
// ABOUTME: Goldens normalise the fixture root to <FIX> and drop machine-dependent absolute floor rows; UPDATE_GOLDEN=1 rewrites them.
//! `hb explain`, end to end through the public API.

use std::fs;
use std::path::{Path, PathBuf};

use claims::{assert_ok, assert_some};
use hamster_ball::config::{LoadRequest, Loaded, StaticPresets, discover, load};
use hamster_ball::explain::{
    ExplainRequest, Format, Report, ReportOptions, build_report, explain, render_json, render_text,
};
use hamster_ball::policy::{CanonicalPath, HomeDir};
use hamster_ball::system::{Environment, FloorEnvironment, UserConfigDir};
use pretty_assertions::assert_eq;
use proptest::prelude::*;
use tempfile::TempDir;

const BASE: &str = r#"
hooks = [["notify", "--token", "s3cret-hook-arg"]]

[tls]
system_trust = true

[env]
pass = ["COLORTERM", "LANG"]
tools = ["mytool", "ghost"]

[fs]
read = ["~/ref"]

[net]
allow = ["api.example.com"]
"#;

const RUST: &str = r#"
[net]
allow = ["crates.io"]

[fs]
read = ["~/.cargo/registry"]
"#;

const PROJECT: &str = r#"
extends = ["rust"]

[fs]
read = ["~/ref", "~/missing"]
write = ["."]
deny_read = ["~/ref/private"]
deny_write = ["secrets/*.yaml"]

[net]
allow = ["github.com", "crates.io"]
loopback_ports = [5432]

[env.set]
API_TOKEN = "hunter2-value"

[ctl]
label = "com.docker.compose.project=demo"

[mcp.serena]
command = "uvx"
args = ["--from", "git+https://example.invalid/serena", "start"]
bind_ports = [24282]
"#;

const BUILTINS: StaticPresets<'static> = StaticPresets(&[("rust", RUST)]);

// ----- the fixture -----

struct World {
    _dir: TempDir,
    base: PathBuf,
    home: HomeDir,
    project: PathBuf,
    env: Environment,
}

impl World {
    fn new(project_config: &str) -> Self {
        let dir = assert_ok!(TempDir::new());
        let base = assert_ok!(fs::canonicalize(dir.path()));
        let home_path = base.join("home");
        let project = home_path.join("work/proj");
        assert_ok!(fs::create_dir_all(&project));
        assert_ok!(fs::create_dir_all(home_path.join("ref/private")));
        assert_ok!(fs::create_dir_all(base.join("bin")));
        assert_ok!(fs::write(base.join("bin/mytool"), "#!/bin/sh\n"));
        assert_ok!(fs::set_permissions(
            base.join("bin/mytool"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755)
        ));
        assert_ok!(fs::create_dir_all(base.join("tmp")));
        assert_ok!(fs::create_dir_all(base.join("install")));
        assert_ok!(fs::write(base.join("install/hb"), ""));
        let home = HomeDir::new(canonical(&home_path));

        let config_dir = home_path.join(".config/hamster-ball");
        assert_ok!(fs::create_dir_all(&config_dir));
        assert_ok!(fs::write(config_dir.join("base.toml"), BASE));
        assert_ok!(fs::write(project.join("hamster-ball.toml"), project_config));

        let mut env = Environment::new(&project, home.clone());
        env.floor = FloorEnvironment::new()
            .with_path_var(base.join("bin").into_os_string())
            .with_user_temp_dir(base.join("tmp"))
            .with_hb_exe(base.join("install/hb"));
        Self {
            _dir: dir,
            base,
            home,
            project,
            env,
        }
    }

    /// Adds `text` to the user's base config.
    fn append_to_base(&self, text: &str) {
        let path = self.home.path().as_str().to_owned() + "/.config/hamster-ball/base.toml";
        let mut current = assert_ok!(fs::read_to_string(&path));
        current.push_str(text);
        assert_ok!(fs::write(&path, current));
    }

    fn load(&self) -> (Loaded, hamster_ball::config::Discovery) {
        let discovery = assert_ok!(discover(&self.project, &self.home));
        let user = UserConfigDir::locate(&self.home);
        let loaded = assert_ok!(load(
            &LoadRequest::new(&self.home, &discovery, &user, &self.env.floor)
                .with_builtins(&BUILTINS)
        ));
        (loaded, discovery)
    }

    /// The report, without floor rules that depend on this machine (absolute paths outside the fixture).
    fn report(&self, show_args: bool, query: Option<&str>) -> Report {
        let (loaded, discovery) = self.load();
        let resolved = query.map(|spelling| {
            let resolver = hamster_ball::system::PathResolver::new(&self.home, &discovery.root);
            (spelling, assert_ok!(resolver.deny(spelling)))
        });
        let mut options = ReportOptions::new(
            &self.home,
            discovery.root.path(),
            Path::new(&discovery.config),
        );
        options.show_args = show_args;
        options.path_var = self.env.floor.path_var.as_deref();
        options.query = resolved
            .as_ref()
            .map(|(spelling, r)| (*spelling, &r.target, r.alias.as_ref()));
        let mut report = build_report(&loaded, &options);
        let prefix = self.base.to_string_lossy().into_owned();
        report
            .deny
            .retain(|row| row.source != "floor" || row.path.starts_with(&prefix));
        report
            .warnings
            .retain(|w| !w.kind.starts_with("path_") && w.kind != "user_temp_dir_unknown");
        report
    }

    fn home_dir(&self) -> PathBuf {
        PathBuf::from(self.home.path().as_str())
    }

    fn normalise(&self, text: &str) -> String {
        text.replace(self.base.to_string_lossy().as_ref(), "<FIX>")
    }
}

fn canonical(path: &Path) -> CanonicalPath {
    assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
        path
    ))))
}

fn golden(name: &str, actual: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        assert_ok!(fs::create_dir_all(assert_some!(path.parent())));
        assert_ok!(fs::write(&path, actual));
        return;
    }
    let expected = assert_ok!(fs::read_to_string(&path));
    assert_eq!(
        expected, actual,
        "golden {name} differs; rerun with UPDATE_GOLDEN=1 if intended"
    );
}

// ====================================================================================
// Golden output
// ====================================================================================

#[test]
fn the_basic_report_matches_its_golden_text() {
    let w = World::new(PROJECT);
    golden(
        "explain_basic.txt",
        &w.normalise(&render_text(&w.report(false, None))),
    );
}

#[test]
fn the_basic_report_matches_its_golden_json() {
    let w = World::new(PROJECT);
    let json = assert_ok!(render_json(&w.report(false, None)));
    golden("explain_basic.json", &w.normalise(&json));
}

#[test]
fn a_path_query_matches_its_golden_text_and_json() {
    let w = World::new(PROJECT);
    let report = w.report(false, Some("~/.ssh/id_ed25519"));
    golden("explain_query.txt", &w.normalise(&render_text(&report)));
    golden(
        "explain_query.json",
        &w.normalise(&assert_ok!(render_json(&report))),
    );
}

/// A worktree project, a symlinked `PATH` entry, and a skipped grant whose name hides a bidi override.
fn worktree_world() -> World {
    let mut w = World::new("[fs]\nread = [\"~/ref\", \"~/gone\\u202e\"]\nwrite = [\".\"]\n");
    let gitdir = w.base.join("main/.git/worktrees/wt");
    assert_ok!(fs::create_dir_all(w.base.join("main/.git/hooks")));
    assert_ok!(fs::create_dir_all(&gitdir));
    assert_ok!(fs::write(gitdir.join("commondir"), "../..\n"));
    assert_ok!(fs::write(
        w.project.join(".git"),
        format!("gitdir: {}\n", gitdir.display())
    ));
    let store = w.base.join("store/bin");
    assert_ok!(fs::create_dir_all(&store));
    let link = w.base.join("link-bin");
    assert_ok!(std::os::unix::fs::symlink(&store, &link));
    w.env.floor.path_var = Some(link.into_os_string());
    w
}

#[test]
fn a_worktree_project_with_a_symlinked_path_entry_matches_its_golden_text_and_json() {
    let w = worktree_world();
    let report = w.report(false, None);
    golden("explain_worktree.txt", &w.normalise(&render_text(&report)));
    golden(
        "explain_worktree.json",
        &w.normalise(&assert_ok!(render_json(&report))),
    );
    // The hostile name is escaped in the text and the JSON, never raw.
    assert!(!has_raw_hazard(&render_text(&report)));
}

#[test]
fn each_tool_is_listed_with_its_directory_and_a_missing_one_says_so() {
    let w = World::new(PROJECT);
    let report = w.report(false, None);
    let by_name = |name: &str| assert_some!(report.env.tools.iter().find(|t| t.name == name));
    let found = by_name("mytool");
    assert_eq!(
        found.dir.as_deref(),
        Some(w.base.join("bin").to_string_lossy().as_ref())
    );
    assert_eq!(by_name("ghost").dir, None);
    let text = w.normalise(&render_text(&report));
    assert!(text.contains("mytool  <FIX>/bin"), "{text}");
    assert!(text.contains("ghost  (not found on PATH)"), "{text}");
}

#[test]
fn the_json_parses_and_has_a_schema_version_and_the_groups_in_order() {
    let w = World::new(PROJECT);
    let json = assert_ok!(render_json(&w.report(false, None)));
    let value: serde_json::Value = assert_ok!(serde_json::from_str(&json));
    assert_eq!(value["schema_version"], 1);
    // `Value` sorts keys, so check the order in the text: the top-level keys are the lines
    // indented by exactly two spaces.
    let keys: Vec<&str> = json
        .lines()
        .filter(|line| line.starts_with("  \""))
        .filter_map(|line| line.trim_start().split('"').nth(1))
        .collect();
    assert_eq!(
        keys,
        [
            "schema_version",
            "project",
            "files",
            "fs",
            "deny",
            "net",
            "env",
            "tls",
            "terminal",
            "system",
            "ctl",
            "mcp",
            "hooks",
            "guard_exceptions",
            "warnings"
        ]
    );
}

#[test]
fn the_terminal_group_says_clipboard_writes_are_allowed_until_a_file_denies_them() {
    let w = World::new(PROJECT);
    let report = w.report(false, None);
    assert!(report.terminal.clipboard_write.value);
    assert!(report.terminal.clipboard_write.origins.is_empty());
    let denied = World::new("[terminal]\nclipboard_write = false\n");
    let report = denied.report(false, None);
    assert!(!report.terminal.clipboard_write.value);
    assert_eq!(report.terminal.clipboard_write.origins.len(), 1);
    let text = denied.normalise(&render_text(&report));
    assert!(
        text.contains("terminal\n  clipboard_write = false"),
        "{text}"
    );
    assert!(text.contains("terminal.clipboard_write"), "{text}");
}

#[test]
fn the_system_group_says_launchctl_is_off_until_a_user_file_turns_it_on() {
    let off = World::new(PROJECT);
    let report = off.report(false, None);
    assert!(!report.system.launchctl.value);
    assert!(report.system.launchctl.origins.is_empty());
    let on = World::new(PROJECT);
    on.append_to_base("\n[system]\nlaunchctl = true\n");
    let report = on.report(false, None);
    assert!(report.system.launchctl.value);
    assert_eq!(report.system.launchctl.origins.len(), 1);
    assert_eq!(
        report.system.launchctl.origins[0].layer.as_str(),
        "user_base"
    );
    let text = on.normalise(&render_text(&report));
    assert!(text.contains("system\n  launchctl = true"), "{text}");
    assert!(text.contains("system.launchctl"), "{text}");
    // The text view says so for the default too, so the setting is never invisible.
    let text = off.normalise(&render_text(&off.report(false, None)));
    assert!(text.contains("system\n  launchctl = false"), "{text}");
}

// ====================================================================================
// Origins, attribution and warnings
// ====================================================================================

#[test]
fn a_value_declared_twice_lists_both_origins_in_closure_order() {
    let w = World::new(PROJECT);
    let report = w.report(false, None);
    let row = assert_some!(report.net.hosts.iter().find(|r| r.value == "crates.io"));
    let layers: Vec<&str> = row.origins.iter().map(|o| o.layer.as_str()).collect();
    assert_eq!(layers, ["preset", "project"]);
    let ref_row = assert_some!(report.fs.read.iter().find(|r| r.value.ends_with("/ref")));
    let layers: Vec<&str> = ref_row.origins.iter().map(|o| o.layer.as_str()).collect();
    assert_eq!(layers, ["user_base", "project"]);
}

#[test]
fn a_built_in_preset_has_a_name_and_no_file() {
    let w = World::new(PROJECT);
    let report = w.report(false, None);
    let rust = assert_some!(
        report
            .files
            .iter()
            .find(|f| f.name.as_deref() == Some("rust"))
    );
    assert_eq!(rust.source, "builtin");
    assert_eq!(rust.file, None);
}

#[test]
fn a_project_allow_of_a_floor_path_is_attributed_to_the_floor_by_path_query() {
    let config = "[fs]\nread = [\"~/ref\"]\nwrite = [\".\"]\n";
    let w = World::new(config);
    assert_ok!(fs::create_dir_all(w.home_dir().join(".ssh")));
    let config = "[fs]\nread = [\"~/.ssh\"]\nwrite = [\".\", \"~/.ssh\"]\n";
    assert_ok!(fs::write(w.project.join("hamster-ball.toml"), config));
    let report = w.report(false, Some("~/.ssh/id_ed25519"));
    let query = assert_some!(report.query);
    for access in [&query.read, &query.write] {
        assert_eq!(access.decision, "denied_by_floor");
        assert_eq!(access.rule.as_deref(), Some("ssh"));
    }
    let warning = assert_some!(
        report
            .warnings
            .iter()
            .find(|w| w.kind == "grant_shadowed_by_floor")
    );
    assert!(warning.message.contains("ssh"), "{}", warning.message);
}

#[test]
fn a_path_a_config_deny_covers_is_reported_denied_with_that_files_origin() {
    let w = World::new(PROJECT);
    let report = w.report(false, Some("~/ref/private/notes.txt"));
    let query = assert_some!(report.query);
    assert_eq!(query.read.decision, "denied");
    assert_eq!(query.write.decision, "denied");
    assert_eq!(assert_some!(query.read.origins.first()).layer, "project");
    assert_eq!(query.read.rule, None);
}

#[test]
fn json_is_exactly_serde_json_pretty_output_when_no_string_needs_escaping_beyond_json() {
    let w = World::new(PROJECT);
    let mut report = w.report(true, None);
    report.warnings.push(hamster_ball::explain::WarningRow {
        kind: "k".to_owned(),
        message: "quote \" backslash \\ tab \t newline \n".to_owned(),
        origins: Vec::new(),
    });
    let ours = assert_ok!(render_json(&report));
    let theirs = format!("{}\n", assert_ok!(serde_json::to_string_pretty(&report)));
    assert_eq!(ours, theirs);
}

#[test]
fn a_path_the_config_grants_is_reported_allowed_with_its_origin() {
    let w = World::new(PROJECT);
    let report = w.report(false, Some("~/ref/notes.txt"));
    let query = assert_some!(report.query);
    assert_eq!(query.read.decision, "allowed");
    assert_eq!(query.write.decision, "not_granted");
    assert_eq!(assert_some!(query.read.origins.first()).layer, "user_base");
}

#[test]
fn a_skipped_allow_is_a_warning_with_its_reason_and_origin() {
    let w = World::new(PROJECT);
    let report = w.report(false, None);
    let skipped: Vec<_> = report
        .warnings
        .iter()
        .filter(|w| w.kind == "skipped_allow")
        .collect();
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert!(
        skipped
            .iter()
            .any(|w| w.message.contains("~/missing") && w.message.contains("missing"))
    );
    assert!(
        skipped
            .iter()
            .any(|w| w.message.contains("~/.cargo/registry"))
    );
    let origin = &skipped[0].origins[0];
    assert!(
        origin.key.as_deref().unwrap_or("").starts_with("fs.read"),
        "{origin:?}"
    );
}

#[test]
fn a_grant_strictly_inside_the_project_that_hits_a_project_rule_is_reported() {
    let w = World::new("[fs]\nread = [\"~/ref\"]\nwrite = [\".\", \".git/hooks\"]\n");
    assert_ok!(fs::create_dir_all(w.project.join(".git/hooks")));
    let report = w.report(false, None);
    let warning = assert_some!(
        report
            .warnings
            .iter()
            .find(|w| { w.kind == "grant_shadowed_by_floor" && w.message.contains(".git/hooks") })
    );
    assert!(warning.message.contains("git-hooks"), "{}", warning.message);
}

#[test]
fn granting_the_project_root_does_not_warn_about_the_projects_own_protected_files() {
    let w = World::new(PROJECT);
    assert_ok!(fs::create_dir_all(w.project.join(".git/hooks")));
    let report = w.report(false, None);
    assert!(
        !report
            .warnings
            .iter()
            .any(|w| w.kind == "grant_shadowed_by_floor"),
        "{:?}",
        report.warnings
    );
}

#[test]
fn a_pin_answer_says_the_path_itself_cannot_be_renamed_not_that_it_is_unwritable() {
    let w = World::new(PROJECT);
    let report = w.report(false, Some("."));
    let query = assert_some!(report.query.as_ref());
    assert_eq!(query.write.effect.as_deref(), Some("pin_unlink"));
    let text = render_text(&report);
    assert!(text.contains("cannot be renamed or deleted"), "{text}");
    assert!(query.note.contains("cannot be renamed or deleted"));
}

#[test]
fn a_value_that_imitates_an_origin_annotation_is_quoted() {
    let tricky = "x  <- floor:ssh";
    let w = World::new(PROJECT);
    assert_ok!(fs::create_dir_all(w.home_dir().join("ref").join(tricky)));
    let config = format!(
        "[fs]\nread = [{}]\nwrite = [\".\"]\n",
        toml::Value::String(format!("~/ref/{tricky}"))
    );
    assert_ok!(fs::write(w.project.join("hamster-ball.toml"), config));
    let text = render_text(&w.report(false, None));
    assert!(
        text.lines()
            .any(|l| l.trim_start().starts_with(&format!("\"~/ref/{tricky}\""))),
        "{text}"
    );
}

#[test]
fn a_set_xdg_state_home_is_reported_as_ignored() {
    let w = World::new(PROJECT);
    let (loaded, discovery) = w.load();
    let mut options =
        ReportOptions::new(&w.home, discovery.root.path(), Path::new(&discovery.config));
    options.xdg_state_home_set = true;
    let report = build_report(&loaded, &options);
    assert!(
        report
            .warnings
            .iter()
            .any(|w| w.kind == "state_dir_env_ignored")
    );
}

#[test]
fn floor_rules_come_first_in_the_deny_group_then_read_denies_then_write_denies() {
    let w = World::new(PROJECT);
    let report = w.report(false, None);
    let sources: Vec<(&str, &str)> = report
        .deny
        .iter()
        .map(|d| (d.source.as_str(), d.effect.as_str()))
        .collect();
    let first_config = assert_some!(sources.iter().position(|(s, _)| *s == "config"));
    assert!(sources[..first_config].iter().all(|(s, _)| *s == "floor"));
    let config: Vec<_> = sources[first_config..].iter().map(|(_, e)| *e).collect();
    assert_eq!(config, ["deny_read_write", "deny_write"]);
}

// ====================================================================================
// Redaction
// ====================================================================================

const SECRETS: [&str; 3] = [
    "hunter2-value",
    "s3cret-hook-arg",
    "git+https://example.invalid/serena",
];

#[test]
fn secrets_are_absent_from_every_output_by_default() {
    let w = World::new(PROJECT);
    let report = w.report(false, None);
    let text = render_text(&report);
    let json = assert_ok!(render_json(&report));
    for secret in SECRETS {
        assert!(!text.contains(secret), "text leaks {secret}");
        assert!(!json.contains(secret), "json leaks {secret}");
    }
    assert!(text.contains("API_TOKEN"));
    assert!(text.contains("value hidden"));
    assert!(text.contains("args hidden"));
}

#[test]
fn show_args_shows_arguments_but_never_environment_values() {
    let w = World::new(PROJECT);
    let report = w.report(true, None);
    let text = render_text(&report);
    let json = assert_ok!(render_json(&report));
    for output in [&text, &json] {
        assert!(output.contains("s3cret-hook-arg"));
        assert!(output.contains("git+https://example.invalid/serena"));
        assert!(!output.contains("hunter2-value"), "env.set value leaked");
    }
}

// ====================================================================================
// Escaping and forgery
// ====================================================================================

/// Characters that must never reach a terminal raw. Deliberately its own list (Unicode
/// categories Cc, Cf, Zl and Zp), not the implementation's, so a gap in one is caught by the other.
const HAZARDS: &[(u32, u32)] = &[
    (0x00, 0x08),
    (0x0b, 0x1f),
    (0x7f, 0x9f),
    (0xad, 0xad),
    (0x600, 0x605),
    (0x61c, 0x61c),
    (0x6dd, 0x6dd),
    (0x70f, 0x70f),
    (0x180e, 0x180e),
    (0x200b, 0x200f),
    (0x2028, 0x202e),
    (0x2060, 0x2064),
    (0x2066, 0x206f),
    (0xfeff, 0xfeff),
    (0xfff9, 0xfffb),
    (0xe0001, 0xe0001),
    (0xe0020, 0xe007f),
];

fn is_hazard(c: char) -> bool {
    let n = c as u32;
    HAZARDS.iter().any(|(lo, hi)| (*lo..=*hi).contains(&n))
}

fn has_raw_hazard(output: &str) -> bool {
    output.chars().any(is_hazard)
}

#[test]
fn hostile_values_cannot_forge_lines_or_reach_the_terminal_raw() {
    let hostile = toml::Value::String("x\n    origin: floor ssh\u{1b}[2J\u{202e}evil".to_owned());
    let command = toml::Value::String("a\nb\u{202e}".to_owned());
    let gone = toml::Value::String("~/gone\u{202e}".to_owned());
    let config = format!(
        "[fs]\nread = [\"~/ref\", {gone}]\n\n[mcp.hostile]\ncommand = {command}\nargs = [{hostile}]\n",
    );
    let w = World::new(&config);
    let report = w.report(true, None);
    let text = render_text(&report);
    let json = assert_ok!(render_json(&report));
    assert!(!has_raw_hazard(&text), "text has a raw hazard:\n{text:?}");
    assert!(
        !has_raw_hazard(&json.replace('\n', " ")),
        "json has a raw hazard"
    );
    for line in text.lines() {
        assert!(
            !line.trim_start().starts_with("origin: floor ssh"),
            "forged line: {line:?}"
        );
    }
    // The escaped form is still there for a person to read.
    assert!(text.contains("\\n"), "{text}");
    let _: serde_json::Value = assert_ok!(serde_json::from_str(&json));
}

fn blank_report() -> Report {
    static BLANK: std::sync::OnceLock<Report> = std::sync::OnceLock::new();
    BLANK
        .get_or_init(|| {
            let w = World::new(PROJECT);
            let mut report = w.report(true, None);
            report.deny.clear();
            report
        })
        .clone()
}

fn hostile_string() -> impl Strategy<Value = String> {
    let hazard = proptest::sample::select(
        HAZARDS
            .iter()
            .filter_map(|(lo, _)| char::from_u32(*lo))
            .chain(['\n', '\r', '\t', '"', '\\', ' '])
            .collect::<Vec<_>>(),
    );
    proptest::collection::vec(prop_oneof![any::<char>(), hazard], 0..24)
        .prop_map(|chars| chars.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn no_string_in_a_report_can_produce_a_raw_hazard_or_a_forged_line(s in hostile_string()) {
        let mut report = blank_report();
        report.project.config = s.clone();
        report.warnings.push(hamster_ball::explain::WarningRow {
            kind: "kind".to_owned(),
            message: s.clone(),
            origins: Vec::new(),
        });
        if let Some(server) = report.mcp.first_mut() {
            server.command = Some(s.clone());
            server.args = Some(vec![s.clone()]);
        }
        if let Some(row) = report.fs.read.first_mut() {
            row.value = s.clone();
        }
        let text = render_text(&report);
        let json = render_json(&report).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert!(!has_raw_hazard(&text.replace('\n', " ")));
        prop_assert!(!has_raw_hazard(&json.replace('\n', " ")));
        prop_assert!(serde_json::from_str::<serde_json::Value>(&json).is_ok());
        // No string adds a line: the layout of the whole report is unchanged.
        let lines = |t: &str| t.lines().count();
        prop_assert_eq!(lines(&text), lines(&render_text(&blank_report())) + 1);
    }
}

// ====================================================================================
// Stability
// ====================================================================================

#[test]
fn repeated_runs_produce_identical_output() {
    let w = World::new(PROJECT);
    let a = (
        render_text(&w.report(false, None)),
        assert_ok!(render_json(&w.report(false, None))),
    );
    let b = (
        render_text(&w.report(false, None)),
        assert_ok!(render_json(&w.report(false, None))),
    );
    assert_eq!(a, b);
}

#[test]
fn hooks_keep_their_closure_order_and_everything_else_is_sorted() {
    let base =
        "hooks = [[\"zzz\"], [\"aaa\"]]\n[net]\nallow = [\"z.example.com\", \"a.example.com\"]\n";
    let w = World::new(PROJECT);
    assert_ok!(fs::write(
        w.home_dir().join(".config/hamster-ball/base.toml"),
        base
    ));
    let report = w.report(false, None);
    let hooks: Vec<&str> = report.hooks.iter().map(|h| h.program.as_str()).collect();
    assert_eq!(hooks, ["zzz", "aaa"]);
    let hosts: Vec<&str> = report.net.hosts.iter().map(|h| h.value.as_str()).collect();
    let mut sorted = hosts.clone();
    sorted.sort_unstable();
    assert_eq!(hosts, sorted);
}

// ====================================================================================
// The entry point
// ====================================================================================

#[test]
fn explain_runs_end_to_end_on_an_unapproved_project_in_both_formats() {
    let w = World::new("[fs]\nread = [\"~/ref\"]\nwrite = [\".\"]\n");
    let text = assert_ok!(explain(&ExplainRequest::new(&w.env)));
    assert!(text.starts_with("hb explain\n"));
    assert!(text.contains("fs.write"));
    let json = assert_ok!(explain(&ExplainRequest::new(&w.env).format(Format::Json)));
    let value: serde_json::Value = assert_ok!(serde_json::from_str(&json));
    assert_eq!(value["schema_version"], 1);
}

#[test]
fn explain_without_a_project_is_an_error_not_a_guess() {
    let w = World::new(PROJECT);
    let elsewhere = w.base.join("nowhere");
    assert_ok!(fs::create_dir_all(&elsewhere));
    let mut env = w.env.clone();
    env.cwd = elsewhere;
    assert!(explain(&ExplainRequest::new(&env)).is_err());
}

#[test]
fn explain_with_a_path_query_includes_the_answer() {
    let w = World::new("[fs]\nread = [\"~/ref\"]\n");
    let text = assert_ok!(explain(&ExplainRequest::new(&w.env).path("~/.ssh/id_rsa")));
    assert!(text.contains("denied_by_floor"), "{text}");
    assert!(text.contains("ssh"), "{text}");
}
