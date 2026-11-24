// ABOUTME: A project the config never grants cannot be read by the agent; hb says so in `explain` and before `run`.
// ABOUTME: Covers which grants count (write, read, a parent) and which do not (a directory inside the project).
//! The warning for a project directory that no `fs` grant covers (hb-ghd.6.3, design 4.3 and 4.4).

#![cfg(target_os = "macos")]

mod common;

use std::process::Stdio;

use claims::{assert_none, assert_ok, assert_some};
use common::{World, canonical, sandbox_available};
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");

fn warning(world: &World) -> Option<&'static str> {
    let loaded = world.loaded();
    loaded
        .policy
        .project_grant_warning(&canonical(&world.project))
}

#[test]
fn a_project_with_no_grant_gets_the_warning_that_says_what_to_add() {
    let w = World::new("");
    let text = assert_some!(warning(&w));
    assert!(text.contains("write = [\".\"]"), "{text}");
    assert!(text.contains("hb init"), "{text}");
}

#[test]
fn a_write_grant_a_read_grant_and_a_parent_grant_each_cover_the_project() {
    for (base, project) in [
        ("[fs]\nwrite = [\".\"]\n", ""),
        ("", "[fs]\nwrite = [\".\"]\n"),
        ("", "[fs]\nread = [\".\"]\n"),
        ("[fs]\nwrite = [\"~/work\"]\n", ""),
    ] {
        let w = World::with_base(base, project);
        assert_none!(warning(&w), "base {base:?} project {project:?}");
    }
}

#[test]
fn a_grant_inside_the_project_or_beside_it_does_not_cover_it() {
    for fs in [
        "write = [\"sub\"]",
        "read = [\"~/ref\"]",
        "write = [\"~/other\"]",
    ] {
        let w = World::new(&format!("[fs]\n{fs}\n"));
        for dir in [
            w.project.join("sub"),
            w.home_dir().join("ref"),
            w.home_dir().join("other"),
        ] {
            assert_ok!(std::fs::create_dir_all(dir));
        }
        assert_some!(warning(&w), "{fs}");
    }
}

#[test]
fn explain_lists_the_warning_in_json_and_a_granted_project_has_none() {
    let kinds = |w: &World| -> Vec<String> {
        let out = assert_ok!(
            w.drive(DRIVE, &["explain", "--format", "json"])
                .stdin(Stdio::null())
                .output()
        );
        let json: serde_json::Value = assert_ok!(serde_json::from_slice(&out.stdout));
        json["warnings"]
            .as_array()
            .map(|all| {
                all.iter()
                    .filter_map(|w| w["kind"].as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    };
    assert!(kinds(&World::new("")).contains(&"project_not_granted".to_owned()));
    assert!(
        !kinds(&World::new("[fs]\nwrite = [\".\"]\n")).contains(&"project_not_granted".to_owned())
    );
}

#[test]
fn run_warns_before_the_command_starts_only_when_the_project_is_not_granted() {
    if !sandbox_available() {
        return;
    }
    let run = |w: &World| {
        let out = assert_ok!(
            w.drive(DRIVE, &["run", "--", "/usr/bin/true"])
                .stdin(Stdio::null())
                .output()
        );
        String::from_utf8_lossy(&out.stderr).into_owned()
    };
    let ungranted = run(&World::new(""));
    assert!(
        ungranted.contains("warning: the project directory is not granted"),
        "{ungranted}"
    );
    let granted = run(&World::new("[fs]\nwrite = [\".\"]\n"));
    assert_eq!(
        granted.contains("project directory is not granted"),
        false,
        "{granted}"
    );
}
