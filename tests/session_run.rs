// ABOUTME: session::run under the real sandbox-exec: the empty environment, session directory, exit codes and tools.
// ABOUTME: Each scenario that blocks something has a paired case that works; all skip when hb itself is sandboxed.
//! Black-box tests of [`hamster_ball::session::run`].

#![cfg(target_os = "macos")]

mod common;

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

use claims::{assert_err, assert_ok};
use common::{World, sandbox_available};
use hamster_ball::session::{ExitKind, Outcome, RunError, RunSpec, run};
use hamster_ball::system::ParentVars;
use pretty_assertions::assert_eq;

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

fn sh(world: &World, script: &str) -> Outcome {
    let spec = RunSpec::new(["/bin/sh", "-c", script]);
    assert_ok!(run(&world.env, &world.loaded(), &spec))
}

fn stdout(outcome: &Outcome) -> String {
    String::from_utf8_lossy(&outcome.stdout).into_owned()
}

fn vars(pairs: &[(&str, &str)]) -> ParentVars {
    ParentVars::from_pairs(
        pairs
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v))),
    )
}

// ====================================================================================
// The environment
// ====================================================================================

#[test]
fn the_child_environment_is_exactly_the_allowed_set_and_no_parent_token_reaches_it() {
    sandboxed!();
    let mut w = World::with_base(
        "[env]\npass = [\"LANG\", \"NOT_SET_IN_PARENT\"]\n",
        "[fs]\nwrite = [\".\"]\n[env.set]\nRUST_LOG = \"debug\"\n",
    );
    w.env.vars = vars(&[
        ("GITHUB_TOKEN", "ghp_secret"),
        ("AWS_SECRET_ACCESS_KEY", "aws_secret"),
        ("LANG", "en_US.UTF-8"),
        ("RUST_LOG", "from-parent"),
        ("TERM", "xterm"),
    ]);
    let out = sh(&w, "/usr/bin/env");
    assert_eq!(
        out.exit,
        ExitKind::Exited(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    let names: BTreeSet<&str> = text
        .lines()
        .filter_map(|l| l.split_once('=').map(|(k, _)| k))
        .collect();
    let allowed: BTreeSet<&str> = [
        "HB_SESSION",
        "HOME",
        "LANG",
        "PATH",
        "RUST_LOG",
        "TERM",
        "TMPDIR",
        // The shell adds these itself when it starts.
        "PWD",
        "SHLVL",
        "_",
        "OLDPWD",
    ]
    .into_iter()
    .collect();
    assert!(
        names.is_subset(&allowed),
        "unexpected: {:?}",
        names.difference(&allowed)
    );
    for must in [
        "HOME",
        "PATH",
        "TMPDIR",
        "TERM",
        "LANG",
        "RUST_LOG",
        "HB_SESSION",
    ] {
        assert!(names.contains(must), "{must} missing from {text}");
    }
    assert!(!text.contains("ghp_secret") && !text.contains("aws_secret"));
    assert!(
        text.contains("RUST_LOG=debug"),
        "set must win over the parent's value"
    );
    assert!(text.contains("TERM=dumb"), "stdin is not a tty here");
    assert!(
        text.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin\n"),
        "{text}"
    );
    assert!(text.contains(&format!("HOME={}", w.home_dir().display())));
}

#[test]
fn the_child_starts_in_the_project_directory() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = sh(&w, "pwd -P");
    assert_eq!(stdout(&out).trim(), w.project.to_string_lossy());
}

// ====================================================================================
// The session directory
// ====================================================================================

fn temp_dir(w: &World) -> std::path::PathBuf {
    let dir = w.env.floor.user_temp_dir.clone().unwrap_or_default();
    assert_ok!(fs::canonicalize(dir))
}

#[test]
fn tmpdir_is_a_private_0700_directory_the_child_can_use_and_it_is_gone_afterwards() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = sh(
        &w,
        "echo \"$TMPDIR\"; stat -f %Lp \"$TMPDIR\"; echo hi > \"$TMPDIR/note\" && cat \"$TMPDIR/note\"",
    );
    assert_eq!(
        out.exit,
        ExitKind::Exited(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(&lines[1..], ["700", "hi"], "{text}");
    let session = std::path::Path::new(lines[0]);
    assert_eq!(session.parent(), Some(temp_dir(&w).as_path()));
    assert!(
        session
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("hb-")),
        "{session:?}"
    );
    assert!(!session.exists(), "the session directory outlived the run");
}

#[test]
fn a_stale_session_directory_of_a_dead_process_is_swept_at_the_next_start() {
    sandboxed!();
    let w = World::new(PROJECT);
    let parent = temp_dir(&w);
    let mut child = assert_ok!(Command::new("/usr/bin/true").spawn());
    let dead = child.id();
    assert_ok!(child.wait());
    let stale = parent.join(format!("hb-{dead}-1-1"));
    assert_ok!(fs::create_dir_all(stale.join("left-over")));
    let live = parent.join(format!("hb-{}-1-1", std::process::id()));
    assert_ok!(fs::create_dir_all(&live));
    let out = sh(&w, "true");
    assert_eq!(out.exit, ExitKind::Exited(0));
    assert!(!stale.exists(), "a dead process's directory must be swept");
    assert!(live.exists(), "a live process's directory must be kept");
}

#[test]
fn two_runs_use_different_session_directories() {
    sandboxed!();
    let w = World::new(PROJECT);
    let first = stdout(&sh(&w, "echo \"$TMPDIR\""));
    let second = stdout(&sh(&w, "echo \"$TMPDIR\""));
    assert!(!first.trim().is_empty() && first != second);
}

// ====================================================================================
// Exit status and streams
// ====================================================================================

#[test]
fn the_childs_exit_code_and_both_streams_come_back() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = sh(&w, "echo out; echo err >&2; exit 42");
    assert_eq!(out.exit, ExitKind::Exited(42));
    assert_eq!(stdout(&out), "out\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "err\n");
}

#[test]
fn a_child_killed_by_a_signal_is_reported_as_signalled() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = sh(&w, "kill -TERM $$");
    assert_eq!(out.exit, ExitKind::Signalled(15));
    assert_eq!(out.exit.code(), 143);
}

#[test]
fn stdin_is_closed_in_capture_mode() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = sh(&w, "cat; echo done");
    assert_eq!(stdout(&out), "done\n");
}

// ====================================================================================
// The command
// ====================================================================================

#[test]
fn an_empty_command_and_a_missing_command_are_errors_with_clear_messages() {
    sandboxed!();
    let w = World::new(PROJECT);
    let none = assert_err!(run(
        &w.env,
        &w.loaded(),
        &RunSpec::new(Vec::<OsString>::new())
    ));
    assert!(matches!(none, RunError::EmptyCommand));
    let missing = assert_err!(run(
        &w.env,
        &w.loaded(),
        &RunSpec::new(["definitely-not-a-command"])
    ));
    let text = missing.to_string();
    assert!(
        matches!(missing, RunError::CommandNotFound { .. }),
        "{text}"
    );
    assert!(
        text.contains("definitely-not-a-command") && text.contains("[env] tools"),
        "{text}"
    );
}

#[test]
fn a_tool_directory_is_on_the_childs_path_readable_and_runs_by_bare_name() {
    sandboxed!();
    let mut w = World::new("[fs]\nwrite = [\".\"]\n[env]\ntools = [\"mytool\", \"ghost\"]\n");
    let bin = w.base.join("toolbin");
    assert_ok!(fs::create_dir_all(&bin));
    let tool = bin.join("mytool");
    assert_ok!(fs::write(&tool, "#!/bin/sh\necho from-mytool\n"));
    assert_ok!(fs::set_permissions(
        &tool,
        fs::Permissions::from_mode(0o755)
    ));
    let path = format!("{}:{}", bin.display(), w.base.join("bin").display());
    w.env.floor = w.env.floor.clone().with_path_var(OsString::from(path));
    let loaded = w.loaded();
    let out = assert_ok!(run(&w.env, &loaded, &RunSpec::new(["mytool"])));
    assert_eq!(
        stdout(&out),
        "from-mytool\n",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.warnings.iter().any(|m| m.contains("ghost")),
        "a missing tool is a warning: {:?}",
        out.warnings
    );
    let show = assert_ok!(run(
        &w.env,
        &loaded,
        &RunSpec::new(["/bin/sh", "-c", "echo $PATH"])
    ));
    assert_eq!(
        stdout(&show).trim(),
        format!("/usr/bin:/bin:/usr/sbin:/sbin:{}", bin.display())
    );
}

#[test]
fn without_the_tools_entry_the_same_script_is_not_found() {
    sandboxed!();
    let mut w = World::new(PROJECT);
    let bin = w.base.join("toolbin");
    assert_ok!(fs::create_dir_all(&bin));
    let tool = bin.join("mytool");
    assert_ok!(fs::write(&tool, "#!/bin/sh\necho x\n"));
    assert_ok!(fs::set_permissions(
        &tool,
        fs::Permissions::from_mode(0o755)
    ));
    w.env.floor = w.env.floor.clone().with_path_var(bin.into_os_string());
    let err = assert_err!(run(&w.env, &w.loaded(), &RunSpec::new(["mytool"])));
    assert!(matches!(err, RunError::CommandNotFound { .. }));
}

// ====================================================================================
// Descriptors the launching shell left open
// ====================================================================================

const FD_MODE: &str = "HB_FD_TEST_MODE";
const FD_PROBE: &str = "print <STDIN> if open(STDIN, \"<&=3\");";

/// Runs inside a re-executed copy of this test binary that inherited fd 3 from a shell.
/// In `close` mode it does what the `hb` binary does at start; in `keep` mode it does not.
#[test]
fn fd_probe_child() {
    let Some(mode) = std::env::var_os(FD_MODE) else {
        return;
    };
    if mode == "close" || mode == "close-list" {
        let _ = hamster_ball::session::close_inherited_fds();
    }
    let w = World::new(PROJECT);
    if mode == "close-list" {
        let out = sh(&w, OPEN_FDS);
        println!(
            "FDLIST:[{}]",
            stdout(&out)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(",")
        );
        return;
    }
    let spec = RunSpec::new(["/usr/bin/perl", "-e", FD_PROBE]);
    let out = assert_ok!(run(&w.env, &w.loaded(), &spec));
    println!("FDPROBE:{}", stdout(&out).trim());
}

/// What the child under `hb` can read through descriptor 3, given how the launcher started.
fn fd_probe(mode: &str) -> String {
    let secret_dir = assert_ok!(tempfile::TempDir::new());
    let secret = secret_dir.path().join("id_test");
    assert_ok!(fs::write(&secret, "TOP-SECRET-KEY\n"));
    let exe = assert_ok!(std::env::current_exe());
    let script = format!(
        "exec 3<{}; exec {} --exact fd_probe_child --nocapture",
        common::quote(&secret),
        common::quote(&exe)
    );
    let out = assert_ok!(
        Command::new("/bin/sh")
            .args(["-c", &script])
            .env(FD_MODE, mode)
            .output()
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        text.contains("FDPROBE:") || text.contains("FDLIST:"),
        "the probe did not run ({:?}): {text}\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    text
}

#[test]
fn a_descriptor_the_launcher_left_open_reaches_the_child_unless_hb_closes_it_at_start() {
    sandboxed!();
    // Control: without the close, the child reads a file the profile does not grant, through fd 3.
    assert!(
        fd_probe("keep").contains("FDPROBE:TOP-SECRET-KEY"),
        "the control must show the leak, or the next assertion proves nothing"
    );
    let closed = fd_probe("close");
    assert!(
        closed.contains("FDPROBE:\n") || closed.trim_end().ends_with("FDPROBE:"),
        "{closed}"
    );
    assert!(!closed.contains("TOP-SECRET"), "{closed}");
}

/// A script that prints each descriptor from 3 to 30 that is open. perl is used because bash keeps
/// a descriptor of its own (10), and `/dev/fd` cannot be listed under the profile.
const OPEN_FDS: &str =
    "/usr/bin/perl -e 'for my $n (3..30) { print \"$n\\n\" if open(my $fh, \"<&=$n\"); }'";

#[test]
fn after_the_close_the_child_has_only_the_three_standard_descriptors() {
    sandboxed!();
    // The launcher leaves 3 open; after the close nothing above 2 is left for the child.
    let text = fd_probe("close-list");
    assert!(text.contains("FDLIST:[]"), "{text}");
}

#[test]
fn the_descriptor_probe_does_see_a_descriptor_the_child_opens_itself() {
    sandboxed!();
    let w = World::new(PROJECT);
    let control = sh(&w, &format!("exec 7</dev/null; {OPEN_FDS}"));
    assert!(
        stdout(&control).lines().any(|l| l == "7"),
        "the probe cannot see descriptors: {}",
        stdout(&control)
    );
}

// ====================================================================================
// Process group and stdin
// ====================================================================================

#[test]
fn a_capture_run_without_a_terminal_puts_the_child_in_its_own_process_group() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = sh(&w, "/usr/bin/perl -e 'print \"$$ \", getpgrp()'");
    let text = stdout(&out);
    let mut words = text.split_whitespace();
    let (pid, group) = (words.next(), words.next());
    assert!(
        pid.is_some() && pid == group,
        "pid and group differ: {text}"
    );
    let own = nix::unistd::getpgrp().as_raw().to_string();
    assert_ne!(
        group,
        Some(own.as_str()),
        "the child shares the test's group"
    );
}

const STDIN_MODE: &str = "HB_STDIN_TEST_CHILD";

/// Re-executed with a stdin that stays open and silent: a captured child must still see EOF.
#[test]
fn capture_stdin_child() {
    if std::env::var_os(STDIN_MODE).is_none() {
        return;
    }
    let w = World::new(PROJECT);
    println!("STDINPROBE:{}", stdout(&sh(&w, "cat; echo done")).trim());
}

#[test]
fn a_capture_run_gives_the_child_a_closed_stdin_even_when_ours_is_an_open_pipe() {
    sandboxed!();
    let exe = assert_ok!(std::env::current_exe());
    let mut child = assert_ok!(
        Command::new(exe)
            .args(["--exact", "capture_stdin_child", "--nocapture"])
            .env(STDIN_MODE, "1")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
    );
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = assert_ok!(child.try_wait()) {
            break Some(status);
        }
        if started.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    let mut text = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = std::io::Read::read_to_string(&mut out, &mut text);
    }
    let _ = child.wait();
    assert!(
        status.is_some(),
        "the captured child waited on our open stdin"
    );
    assert!(text.contains("STDINPROBE:done"), "{text}");
}
