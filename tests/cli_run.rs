// ABOUTME: `hb run` end to end: exit codes, warnings, usage errors, and the nesting message from the real binary.
// ABOUTME: The in-process cases call cli::run with a fixture Environment; the nesting case runs the built hb inside sandbox-exec.
//! Black-box tests of `hb run`.

#![cfg(target_os = "macos")]

mod common;

use std::process::{Command, ExitCode};

use claims::assert_ok;
use common::{World, sandbox_available};
use hamster_ball::cli::run;
use pretty_assertions::assert_eq;

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// Runs `hb <args>` in the fixture world and returns the exit code and what it wrote to stderr.
fn hb(w: &World, args: &[&str]) -> (ExitCode, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let argv = std::iter::once("hb").chain(args.iter().copied());
    let code = run(argv, Some(&w.env), &mut out, &mut err);
    (code, String::from_utf8_lossy(&err).into_owned())
}

#[test]
fn hb_run_returns_the_childs_exit_code_with_or_without_a_double_dash() {
    sandboxed!();
    let w = World::new(PROJECT);
    assert_eq!(
        hb(&w, &["run", "--", "/bin/sh", "-c", "exit 3"]).0,
        ExitCode::from(3)
    );
    assert_eq!(
        hb(&w, &["run", "/bin/sh", "-c", "exit 5"]).0,
        ExitCode::from(5)
    );
    assert_eq!(hb(&w, &["run", "--", "/usr/bin/true"]).0, ExitCode::SUCCESS);
}

#[test]
fn hb_run_passes_dashed_arguments_to_the_command_not_to_hb() {
    sandboxed!();
    let w = World::new(PROJECT);
    let (code, err) = hb(
        &w,
        &[
            "run",
            "/bin/sh",
            "-c",
            "test \"$1\" = --version",
            "sh",
            "--version",
        ],
    );
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
}

#[test]
fn a_signal_killed_child_exits_128_plus_the_signal_until_the_reraise_of_2_3b() {
    sandboxed!();
    let w = World::new(PROJECT);
    assert_eq!(
        hb(&w, &["run", "/bin/sh", "-c", "kill -TERM $$"]).0,
        ExitCode::from(143)
    );
}

#[test]
fn a_missing_command_exits_1_and_says_which_command() {
    sandboxed!();
    let w = World::new(PROJECT);
    let (code, err) = hb(&w, &["run", "--", "no-such-command-xyz"]);
    assert_eq!(code, ExitCode::FAILURE);
    assert!(
        err.contains("no-such-command-xyz") && err.contains("[env] tools"),
        "{err}"
    );
}

#[test]
fn a_tool_that_is_not_on_path_is_a_warning_on_stderr_and_the_run_goes_on() {
    sandboxed!();
    let w = World::new("[fs]\nwrite = [\".\"]\n[env]\ntools = [\"ghost\"]\n");
    let (code, err) = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    assert!(err.contains("ghost") && err.contains("warning"), "{err}");
}

#[test]
fn an_allow_rule_that_was_skipped_is_a_warning_naming_the_entry_and_the_reason() {
    sandboxed!();
    let w = World::new("[fs]\nwrite = [\".\", \"~/no-such-dir\"]\n");
    let (code, err) = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    let line = err
        .lines()
        .find(|l| l.contains("no-such-dir"))
        .unwrap_or_default();
    assert!(line.starts_with("warning: "), "{err}");
    assert!(
        line.contains("fs.write[1]"),
        "the entry is not named: {line}"
    );
    assert!(line.contains("missing"), "the reason is not given: {line}");
    assert!(
        !err.contains("fs.write[0]"),
        "the granted entry was reported: {err}"
    );
}

#[test]
fn a_rejected_config_names_each_bad_entry_and_why() {
    sandboxed!();
    let w = World::new("[fs]\nwrite = [\".\"]\nread = [\"/\"]\n[net]\nallow = [\"not a host\"]\n");
    let (code, err) = hb(&w, &["run", "--", "/usr/bin/true"]);
    assert_eq!(code, ExitCode::from(1), "{err}");
    assert!(err.contains("2 configuration error(s)"), "{err}");
    assert!(
        err.contains("fs.read[0]") && err.contains("too broad"),
        "{err}"
    );
    assert!(
        err.contains("net.allow[0]") && err.contains("not a host"),
        "{err}"
    );
}

#[test]
fn hb_run_without_a_command_is_a_usage_error() {
    let w = World::new(PROJECT);
    assert_eq!(hb(&w, &["run"]).0, ExitCode::from(2));
}

/// The case the design describes (7.4): hb started inside another sandbox says so plainly.
#[test]
fn hb_inside_another_sandbox_fails_with_the_nesting_message() {
    let w = World::new(PROJECT);
    let output = assert_ok!(
        Command::new("/usr/bin/sandbox-exec")
            .args(["-p", "(version 1)(allow default)", env!("CARGO_BIN_EXE_hb")])
            .args(["run", "--", "/usr/bin/true"])
            .current_dir(&w.project)
            .output()
    );
    let err = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "{err}");
    assert!(err.contains("cannot run inside another sandbox"), "{err}");
    assert!(err.contains("not sandboxed"), "{err}");
}

const STDIN_CHILD: &str = "HB_CLI_STDIN_CHILD";

/// Runs `hb run /bin/cat` in-process with whatever stdin the re-executed test binary was given.
#[test]
fn inherit_stdin_child() {
    if std::env::var_os(STDIN_CHILD).is_none() {
        return;
    }
    let w = World::new(PROJECT);
    let (code, err) = hb(&w, &["run", "--", "/bin/cat"]);
    println!("\nSTDINCODE:{}", code == ExitCode::SUCCESS);
    eprintln!("{err}");
}

/// An interactive agent reads the user's keyboard: `hb run` must hand its stdin to the child.
#[test]
fn hb_run_hands_its_own_stdin_to_the_child() {
    sandboxed!();
    use std::io::Write;
    use std::process::Stdio;
    let exe = assert_ok!(std::env::current_exe());
    let mut child = assert_ok!(
        Command::new(exe)
            .args(["--exact", "inherit_stdin_child", "--nocapture"])
            .env(STDIN_CHILD, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    );
    if let Some(mut stdin) = child.stdin.take() {
        assert_ok!(stdin.write_all(b"typed-by-the-user\n"));
    }
    let output = assert_ok!(child.wait_with_output());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("typed-by-the-user"), "{text}");
    assert!(text.contains("STDINCODE:true"), "{text}");
}
