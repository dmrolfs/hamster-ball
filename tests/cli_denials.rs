// ABOUTME: `hb run --log-denials` end to end through hb-testdrive: live lines when stderr is redirected, a summary after exit on a terminal.
// ABOUTME: Each case reads a file the floor denies, several times, because the system log is not complete.
//! Black-box tests of `--log-denials`.

#![cfg(target_os = "macos")]

mod common;

use std::process::Command;

use claims::assert_ok;
use common::{EXPECT_GUARD, World, assert_no_expect_timeout, quote, sandbox_available};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// A fixture world with a file the floor denies, and a script that reads it five times.
fn world_and_script() -> (World, String) {
    let w = World::new(PROJECT);
    let secret = w.home_dir().join(".ssh/id_denied_by_the_floor");
    common::write(&secret, "key\n");
    let script = format!(
        "for i in 1 2 3 4 5; do /bin/cat {} > /dev/null 2>&1; done; echo child-done",
        quote(&secret)
    );
    (w, script)
}

#[test]
fn with_stderr_redirected_each_denial_is_written_live_as_a_hb_denied_line() {
    sandboxed!();
    let (w, script) = world_and_script();
    let out = assert_ok!(
        w.drive(
            DRIVE,
            &["run", "--log-denials", "--", "/bin/sh", "-c", &script]
        )
        .output()
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(String::from_utf8_lossy(&out.stdout).contains("child-done"));
    assert!(
        err.lines().any(|l| l.starts_with("hb: denied: ")
            && l.contains("deny(1) file-")
            && l.contains("id_denied_by_the_floor")
            && l.contains("[floor]")),
        "{err}"
    );
}

#[test]
fn without_the_flag_nothing_about_denials_is_printed() {
    sandboxed!();
    let (w, script) = world_and_script();
    let out = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", &script])
            .output()
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains("denied"));
}

#[test]
fn on_a_terminal_the_denials_are_printed_after_the_child_ends_not_in_the_middle_of_its_output() {
    sandboxed!();
    if !std::path::Path::new("/usr/bin/expect").exists() {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    }
    let (w, script) = world_and_script();
    let exp = w.base.join("deny.exp");
    let body = format!(
        "set env(HB_TD_HOME) {home}\nset env(HB_TD_CWD) {cwd}\nset env(HB_TD_PATH) {path}\nset env(HB_TD_TMP) {tmp}\n\
         set timeout 30\n{guard}spawn {drive} run --log-denials -- /bin/sh -c {script}\nexpect eof\n",
        home = w.home_dir().display(),
        cwd = w.project.display(),
        path = w.base.join("bin").display(),
        tmp = w.base.join("tmp").display(),
        drive = DRIVE,
        script = tcl_quote(&script),
        guard = EXPECT_GUARD,
    );
    common::write(&exp, &body);
    let out = assert_ok!(Command::new("/usr/bin/expect").arg(&exp).output());
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert_no_expect_timeout(&text);
    let done = text.find("child-done");
    let first = text.find("hb: denied: ");
    assert!(done.is_some() && first.is_some(), "{text}");
    assert!(
        done < first,
        "a denial was printed before the child finished: {text}"
    );
    assert!(
        text.contains("not complete"),
        "the summary must say the log is incomplete: {text}"
    );
}

/// A Tcl brace-quoted word (the script has no braces).
fn tcl_quote(text: &str) -> String {
    format!("{{{text}}}")
}
