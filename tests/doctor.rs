// ABOUTME: `hb doctor` end to end: look-alike secret files, tracked secrets and the guard's state, names only.
// ABOUTME: In-process through cli::run with a fixture Environment; the launchd section reads the real launchd and is only checked for shape.
//! Black-box tests of `hb doctor`.

#![cfg(target_os = "macos")]

mod common;

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use claims::assert_ok;
use common::{World, write};
use hamster_ball::cli::run;
use pretty_assertions::assert_eq;

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

fn doctor(w: &World) -> (ExitCode, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(["hb", "doctor"], Some(&w.env), &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

fn section<'a>(text: &'a str, title: &str) -> &'a str {
    let start = text.find(title).unwrap_or(0);
    let rest = &text[start..];
    let end = rest[title.len()..]
        .find("\n\n")
        .map_or(rest.len(), |i| i + title.len());
    &rest[..end]
}

#[test]
fn doctor_lists_look_alike_files_by_name_and_never_their_contents() {
    let w = World::new(PROJECT);
    write(
        &w.project.join("config/credentials.json"),
        "CONTENTS-MUST-NOT-APPEAR",
    );
    write(
        &w.project.join("deploy/terraform.tfvars"),
        "CONTENTS-MUST-NOT-APPEAR",
    );
    write(&w.project.join(".env"), "CONTENTS-MUST-NOT-APPEAR");
    write(&w.project.join("src/token.rs"), "fn main() {}");
    let (code, out, err) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    let suspects = section(&out, "files that look like secrets");
    assert!(suspects.contains("config/credentials.json"), "{out}");
    assert!(suspects.contains("deploy/terraform.tfvars"), "{out}");
    assert!(
        !suspects.contains(".env"),
        "a guarded file is not a look-alike: {out}"
    );
    assert!(!suspects.contains("token.rs"), "{out}");
    assert!(!out.contains("CONTENTS-MUST-NOT-APPEAR"));
}

#[test]
fn doctor_says_how_the_guard_stands() {
    let w = World::new(PROJECT);
    write(&w.project.join("certs/server.key"), "PRIVATE");
    let (_, out, _) = doctor(&w);
    assert!(out.contains("secrets guard covers"), "{out}");
    assert!(out.contains(&w.project.display().to_string()), "{out}");
    assert!(out.contains("dependency exemption: on"), "{out}");
    assert!(
        out.contains("directories holding secrets are pinned"),
        "{out}"
    );
    assert!(
        out.contains("limit: a directory that gets its first key"),
        "{out}"
    );
}

#[test]
fn doctor_lists_tracked_files_the_guard_would_deny() {
    if !Path::new("/usr/bin/git").exists() {
        return;
    }
    let w = World::new(PROJECT);
    write(&w.project.join(".env"), "T=1");
    write(&w.project.join(".env.local"), "T=2");
    for args in [vec!["init", "-q"], vec!["add", "-f", ".env"]] {
        assert_ok!(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&w.project)
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        );
    }
    let (_, out, _) = doctor(&w);
    let tracked = section(&out, "tracked files the guard would deny");
    assert!(tracked.contains("/.env"), "{out}");
    assert!(!tracked.contains(".env.local"), "{out}");
}

#[test]
fn doctor_has_a_launchd_section_and_a_clean_project_says_none() {
    let w = World::new(PROJECT);
    let (code, out, _) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(
        out.contains("secret-looking names in the launchd environment"),
        "{out}"
    );
    let suspects = section(&out, "files that look like secrets");
    assert!(suspects.contains("(none)"), "{out}");
}

#[test]
fn doctor_outside_a_project_is_an_error_that_prints_nothing_to_stdout() {
    let mut w = World::new(PROJECT);
    w.env.cwd = w.home_dir();
    let (code, out, err) = doctor(&w);
    assert_ne!(code, ExitCode::SUCCESS);
    assert_eq!(out, "");
    assert!(!err.is_empty());
}
