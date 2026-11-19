// ABOUTME: Smoke test that the `hb` binary builds, runs and identifies itself.
// ABOUTME: Integration test: it exercises the compiled binary as a black box, so it lives in tests/.
//! Black-box check of the `hb` executable.

use std::process::Command;

use claims::assert_ok;
use pretty_assertions::assert_eq;

#[test]
fn hb_prints_its_name_and_version_and_succeeds() {
    let output = assert_ok!(Command::new(env!("CARGO_BIN_EXE_hb")).output());
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hamster-ball"), "{stdout}");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "{stdout}");
}

#[test]
fn an_unknown_command_prints_usage_and_exits_2() {
    let output = assert_ok!(Command::new(env!("CARGO_BIN_EXE_hb")).arg("bogus").output());
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("usage: hb"), "{stderr}");
    assert!(stderr.contains("init"), "{stderr}");
}

#[test]
fn init_with_a_home_that_disagrees_with_passwd_refuses_and_writes_nothing() {
    // `hb init` takes the home directory from the passwd database and refuses a mismatching
    // $HOME. Pointing HOME at a fresh temp directory proves both that and that nothing is
    // written there (or anywhere), without ever touching the real home directory.
    let dir = assert_ok!(tempfile::TempDir::new());
    let output = assert_ok!(
        Command::new(env!("CARGO_BIN_EXE_hb"))
            .arg("init")
            .env("HOME", dir.path())
            .output()
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("disagrees"), "{stderr}");
    assert!(
        !dir.path().join(".config").exists(),
        "init must not create anything"
    );
}
