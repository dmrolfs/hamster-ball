// ABOUTME: Golden-file tests of render() on four fixtures: minimal, rust project, agent preset and deny-heavy.
// ABOUTME: Goldens keep only floor rules inside the fixture tree and normalise its root to <FIX>; UPDATE_GOLDEN=1 rewrites them.
//! Golden profiles.
//!
//! The text and the parameter list of each fixture are pinned, so any change to the baseline,
//! the rule order, the operation lists or the parameter naming is a visible diff. Floor rules
//! that depend on the machine (`/var/run/docker.sock`, `/opt/homebrew/bin`, the real `PATH`)
//! are left out of the golden by filtering on the fixture root; the real-sandbox tests in
//! `seatbelt_render.rs` cover those.

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::path::Path;

use claims::{assert_ok, assert_some};
use common::{World, canonical, run, sandbox_available, stderr, succeeds, toml_string, write};
use hamster_ball::policy::Port;
use hamster_ball::seatbelt::{LogTag, Profile, ProxyEndpoint, RenderInputs, render_filtered};
use pretty_assertions::assert_eq;

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

/// The profile for `w`, keeping only floor rules inside the fixture tree.
fn render_for(w: &World, inputs: &RenderInputs) -> Profile {
    let base = w.base.to_string_lossy().into_owned();
    let loaded = w.loaded();
    assert_ok!(render_filtered(&loaded.policy, inputs, &|rule| {
        rule.pattern.base.as_str().starts_with(&base)
    }))
}

/// `text` with regex metacharacters backslash-escaped, as a regex parameter spells a path.
fn regex_quoted(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if "\\^$.|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Text, then the parameters, with the fixture root replaced in both its plain and its
/// regex-quoted spelling (the temporary directory's name is random and contains a dot).
fn normalised(w: &World, profile: &Profile) -> String {
    let root = w.base.to_string_lossy().into_owned();
    let quoted = regex_quoted(&root);
    let mut out = profile.text.clone();
    out.push_str("\n;; parameters\n");
    for (name, value) in &profile.params {
        out.push_str(&format!(
            ";; {name}={}\n",
            value.replace(&quoted, "<FIX>").replace(&root, "<FIX>")
        ));
    }
    out
}

/// Proves the golden text compiles: `/usr/bin/true` runs under the filtered profile (the one
/// pinned) and under the full unfiltered one for this machine.
fn compiles_and_runs_true(w: &World, filtered: &Profile, inputs: &RenderInputs) {
    if !sandbox_available() {
        return;
    }
    let full = w.render(inputs);
    for (label, profile) in [("golden", filtered), ("full", &full)] {
        let out = run(profile, &w.home_dir(), &w.project, "/usr/bin/true");
        assert!(
            succeeds(&out),
            "{label} profile failed to run /usr/bin/true: {}",
            stderr(&out)
        );
    }
}

#[test]
fn minimal() {
    let w = World::new("[fs]\nwrite = [\".\"]\n");
    let profile = render_for(&w, &RenderInputs::new());
    golden("seatbelt_minimal.sb", &normalised(&w, &profile));
    compiles_and_runs_true(&w, &profile, &RenderInputs::new());
}

#[test]
fn rust_project() {
    let w = World::with_base(
        "[tls]\nsystem_trust = true\n",
        "[fs]\nwrite = [\".\"]\nread = [\"~/.cargo/registry\"]\n\n[net]\nallow = [\"crates.io\"]\nloopback_ports = [5432, 3030]\n",
    );
    write(&w.home_dir().join(".cargo/registry/.keep"), "");
    let profile = render_for(
        &w,
        &RenderInputs::new().with_proxy(ProxyEndpoint::Placeholder),
    );
    golden("seatbelt_rust_project.sb", &normalised(&w, &profile));
}

#[test]
fn agent_preset() {
    let w = World::with_base(
        "[tls]\nsystem_trust = true\n",
        "[fs]\nwrite = [\".\", \"~/.pi/agent\"]\nread = [\"~/.nvm/versions/node\"]\n\n[mcp.serena]\ncommand = \"uvx\"\nbind_ports = [24283, 24282]\n",
    );
    let home = w.home_dir();
    write(&home.join(".pi/agent/.keep"), "");
    write(&home.join(".nvm/versions/node/v24/bin/node"), "");
    let ca = w.base.join("ca/corp.pem");
    write(&ca, "");
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", \"~/.pi/agent\"]\nread = [\"~/.nvm/versions/node\"]\n\n[tls]\nextra_ca_files = [{}]\n\n[mcp.serena]\ncommand = \"uvx\"\nbind_ports = [24283, 24282]\n",
        toml_string(&ca.to_string_lossy())
    ));
    let session = w.base.join("tmp/hb-1-2-3");
    assert_ok!(fs::create_dir_all(&session));
    let inputs = RenderInputs::new()
        .with_proxy(ProxyEndpoint::Port(assert_ok!(Port::try_from(41234))))
        .with_session_dir(canonical(&session))
        .with_tty(assert_ok!(
            hamster_ball::policy::CanonicalPath::from_canonical("/dev/ttys004")
        ))
        .with_exec_dirs(vec![canonical(&home.join(".nvm/versions/node/v24/bin"))])
        .with_log_tag(assert_ok!(LogTag::new("0123abcd")));
    let profile = render_for(&w, &inputs);
    golden("seatbelt_agent_preset.sb", &normalised(&w, &profile));
    compiles_and_runs_true(&w, &profile, &inputs);
}

#[test]
fn deny_heavy() {
    let w = World::new(
        "[fs]\nwrite = [\".\", \"~/Library\"]\ndeny_read = [\"secrets/*.yaml\", \".env\", \"~/.config/gh\"]\ndeny_write = [\"vendor\", \"**/*.lock\"]\n",
    );
    let home = w.home_dir();
    let proj = w.project.clone();
    write(&home.join("dotfiles/LaunchAgents/keep"), "");
    write(&home.join("Library/other/.keep"), "");
    assert_ok!(std::os::unix::fs::symlink(
        "../dotfiles/LaunchAgents",
        home.join("Library/LaunchAgents")
    ));
    // A worktree-style `.git` file, so the floor protects the pointed-to git directory.
    let gitdir = w.base.join("main/.git/worktrees/wt");
    write(&gitdir.join("commondir"), "../..\n");
    write(
        &proj.join(".git"),
        &format!("gitdir: {}\n", gitdir.display()),
    );
    write(&proj.join("secrets/.keep"), "");
    let guard = canonical(&{
        write(&proj.join(".env.example"), "");
        proj.join(".env.example")
    });
    let inputs = RenderInputs::new().with_guard_allow(vec![guard]);
    let profile = render_for(&w, &inputs);
    golden("seatbelt_deny_heavy.sb", &normalised(&w, &profile));
    compiles_and_runs_true(&w, &profile, &inputs);
}
