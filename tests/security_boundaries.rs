// ABOUTME: Approval snapshots and closure path swaps tested across loading, approval and real Seatbelt execution.
// ABOUTME: Disposable canaries and granted controls distinguish confinement from a broken command or fixture.
//! Cross-boundary regressions for hb-dvf; no owner configuration or services are touched.

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::symlink;

use claims::assert_ok;
use common::{World, sandbox_available, write};
use hamster_ball::approval::{ApprovalStore, Candidate, NoTerminal, require};
use hamster_ball::config::discover;
use hamster_ball::session::{RunSpec, run};
use hamster_ball::system::StateDir;
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");

#[test]
fn loaded_policy_and_approval_keep_the_same_snapshot_after_disk_replacement() {
    if !sandbox_available() {
        return;
    }
    let w = World::new("[fs]\nwrite = [\".\"]\n");
    let canary = w.base.join("snapshot-canary");
    write(&canary, "SNAPSHOT-SECRET");
    w.approve();
    let loaded = w.loaded();
    let discovery = assert_ok!(discover(&w.project, &w.home));
    let store = ApprovalStore::new(&StateDir::locate(&w.home));
    w.set_project(&format!(
        "[fs]\nwrite = [\".\"]\nread = [\"{}\"]\n",
        canary.display()
    ));
    let candidate = Candidate::new(&w.env, &discovery, &loaded);
    let verdict = assert_ok!(require(
        &candidate,
        &store,
        &mut NoTerminal,
        &mut Vec::new()
    ));
    assert!(verdict.allows_run(), "original snapshot remains approved");
    let spec = RunSpec::new(["/bin/cat", assert_ok!(canary.to_str().ok_or("UTF-8 path"))]);
    let denied = assert_ok!(run(&w.env, &loaded, &spec));
    assert!(
        !common::hb_succeeds(&denied),
        "old policy read newly granted canary"
    );
    assert!(!common::hb_text(&denied).contains("SNAPSHOT-SECRET"));
    let changed = w.loaded();
    let next = Candidate::new(&w.env, &discovery, &changed);
    assert!(!assert_ok!(require(&next, &store, &mut NoTerminal, &mut Vec::new())).allows_run());
    w.approve();
    let control = assert_ok!(run(&w.env, &changed, &spec));
    assert!(common::hb_succeeds(&control));
    assert_eq!(control.stdout, b"SNAPSHOT-SECRET");
}

#[test]
fn identical_closure_bytes_do_not_allow_a_symlink_replacement() {
    if !sandbox_available() {
        return;
    }
    let w = World::new("extends = [\"./shared.toml\"]\n[fs]\nwrite = [\".\"]\n");
    let shared = w.project.join("shared.toml");
    write(&shared, "[fs]\nread = [\"/usr/share\"]\n");
    w.approve();
    let args = ["run", "--", "/bin/echo", "APPROVED-EXECUTED"];
    let control = assert_ok!(w.drive_unapproved(DRIVE, &args).output());
    assert!(control.status.success(), "{control:?}");
    assert_eq!(control.stdout, b"APPROVED-EXECUTED\n");
    let outside = w.base.join("same-bytes.toml");
    assert_ok!(fs::copy(&shared, &outside));
    assert_ok!(fs::remove_file(&shared));
    assert_ok!(symlink(&outside, &shared));
    let denied = assert_ok!(w.drive_unapproved(DRIVE, &args).output());
    assert_eq!(denied.status.code(), Some(1), "{denied:?}");
    assert!(String::from_utf8_lossy(&denied.stderr).contains("is a symlink"));
    assert!(!String::from_utf8_lossy(&denied.stdout).contains("APPROVED-EXECUTED"));
}
