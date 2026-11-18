// ABOUTME: Smoke test that the `hb` binary builds, runs and identifies itself.
// ABOUTME: Integration test: it exercises the compiled binary as a black box, so it lives in tests/.
//! Black-box check of the `hb` executable.

use std::process::Command;

use claims::assert_ok;

#[test]
fn hb_prints_its_name_and_version_and_succeeds() {
    let output = assert_ok!(Command::new(env!("CARGO_BIN_EXE_hb")).output());
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hamster-ball"), "{stdout}");
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")), "{stdout}");
}
