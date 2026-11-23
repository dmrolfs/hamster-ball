// ABOUTME: `hb run` and the proxy end to end through hb-testdrive: refusals as denials, the connection log and the end-of-run summary.
// ABOUTME: The child asks for a host that is not allowed, so the proxy refuses before any lookup and nothing leaves the machine.
//! Black-box tests of `--log-denials`, `--log-proxy` and `--no-proxy-summary` for the proxy.

#![cfg(target_os = "macos")]

mod common;

use claims::assert_ok;
use common::{World, sandbox_available};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";
/// Asks for a host nobody allowed, twice, through the proxy the child was given.
const SCRIPT: &str = "for i in 1 2; do /usr/bin/curl -sS -m 10 https://refused.example.org/ >/dev/null 2>&1; done; echo child-done";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run_with(flags: &[&str]) -> Ran {
    let w = World::new(PROJECT);
    let mut args = vec!["run"];
    args.extend_from_slice(flags);
    args.extend_from_slice(&["--", "/bin/sh", "-c", SCRIPT]);
    let out = assert_ok!(w.drive(DRIVE, &args).output());
    Ran {
        code: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

#[test]
fn a_run_that_had_refusals_ends_with_one_warning_that_counts_them_and_names_the_flag() {
    sandboxed!();
    let ran = run_with(&[]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert!(ran.stdout.contains("child-done"));
    let warnings: Vec<&str> = ran
        .stderr
        .lines()
        .filter(|l| l.contains("the proxy refused"))
        .collect();
    assert_eq!(warnings.len(), 1, "{}", ran.stderr);
    assert!(
        warnings[0].starts_with("warning: the proxy refused 2 connections to 1 host;"),
        "{}",
        warnings[0]
    );
    assert!(warnings[0].contains("--log-denials"), "{}", warnings[0]);
}

#[test]
fn the_summary_can_be_switched_off() {
    sandboxed!();
    let ran = run_with(&["--no-proxy-summary"]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert!(!ran.stderr.contains("the proxy refused"), "{}", ran.stderr);
}

#[test]
fn log_denials_shows_each_refusal_live_and_leaves_out_the_summary() {
    sandboxed!();
    let ran = run_with(&["--log-denials"]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    let lines: Vec<&str> = ran
        .stderr
        .lines()
        .filter(|l| l.starts_with("hb: denied: proxy refused refused.example.org:443 not_allowed"))
        .collect();
    assert_eq!(lines.len(), 2, "{}", ran.stderr);
    assert!(!ran.stderr.contains("the proxy refused"), "{}", ran.stderr);
}

#[test]
fn log_proxy_shows_every_connection_and_nothing_without_the_flag() {
    sandboxed!();
    let ran = run_with(&["--log-proxy", "--no-proxy-summary"]);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    let lines: Vec<&str> = ran
        .stderr
        .lines()
        .filter(|l| l.starts_with("hb: proxy: refused refused.example.org:443 not_allowed"))
        .collect();
    assert_eq!(lines.len(), 2, "{}", ran.stderr);
    let quiet = run_with(&["--no-proxy-summary"]);
    assert!(!quiet.stderr.contains("hb: proxy:"), "{}", quiet.stderr);
}
