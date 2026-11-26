// ABOUTME: Pre-run hooks end to end through hb-testdrive: run on the host, never from a project, bounded, cleaned up with the session.
// ABOUTME: The agent sees a hook's files by path, cannot run the hook's program, and a failing hook ends the run before the agent starts.
//! Black-box tests of host-side hooks (design sections 4.2 and 11).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};
use std::time::{Duration, Instant};

use claims::assert_ok;
use common::{World, sandbox_available, write};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

fn base_path(w: &World) -> PathBuf {
    w.home_dir().join(".config/hamster-ball/base.toml")
}

/// An executable under the world's home, so the agent cannot read or run it.
fn tool(w: &World, name: &str, body: &str) -> PathBuf {
    let path = w.home_dir().join("tools").join(name);
    write(&path, &format!("#!/bin/sh\n{body}\n"));
    assert_ok!(fs::set_permissions(
        &path,
        fs::Permissions::from_mode(0o755)
    ));
    path
}

fn with_base(w: &World, text: &str) {
    write(&base_path(w), text);
}

fn run(w: &World, words: &[&str]) -> Output {
    let mut args = vec!["run", "--"];
    args.extend_from_slice(words);
    let mut cmd = w.drive(DRIVE, &args);
    cmd.stdin(Stdio::null());
    assert_ok!(cmd.output())
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn code(out: &Output) -> i32 {
    out.status.code().unwrap_or(-1)
}

fn marker(w: &World) -> PathBuf {
    w.project.join("ran")
}

#[test]
fn a_hook_in_the_project_file_never_runs_and_the_run_does_not_start() {
    sandboxed!();
    let w = World::new(PROJECT);
    let evil = tool(&w, "evil", &format!("touch '{}'", marker(&w).display()));
    w.set_project(&format!(
        "{PROJECT}[hooks.pre_run.evil]\ncommand = [\"{}\"]\n",
        evil.display()
    ));
    let out = run(
        &w,
        &[
            "/bin/sh",
            "-c",
            &format!("touch '{}'", marker(&w).display()),
        ],
    );
    assert_ne!(code(&out), 0, "{}", stderr(&out));
    assert!(stderr(&out).contains("hooks"), "{}", stderr(&out));
    assert!(!marker(&w).exists(), "the hook or the command ran");
}

#[test]
fn a_hook_in_the_users_base_runs_before_the_agent_and_its_file_is_given_by_path() {
    sandboxed!();
    let w = World::new(PROJECT);
    let hook = tool(&w, "make", "echo 'from the hook' > note.txt");
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.make]\ncommand = [\"{}\"]\n[hooks.pre_run.make.outputs]\nHOOK_NOTE = \"note.txt\"\n",
            hook.display()
        ),
    );
    let out = run(
        &w,
        &["/bin/sh", "-c", "cat \"$HOOK_NOTE\"; echo \"$HOOK_NOTE\""],
    );
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.starts_with("from the hook\n"), "{text}");
    assert!(text.contains("/hooks/make/note.txt"), "{text}");
}

#[test]
fn the_agent_cannot_run_the_hooks_program_or_read_the_home_it_came_from() {
    sandboxed!();
    let w = World::new(PROJECT);
    let hook = tool(&w, "secret-tool", "true");
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.t]\ncommand = [\"{}\"]\n",
            hook.display()
        ),
    );
    let out = run(
        &w,
        &[
            "/bin/sh",
            "-c",
            &format!("'{}'; echo status=$?", hook.display()),
        ],
    );
    assert!(
        stdout(&out).contains("status=126") || stdout(&out).contains("status=1"),
        "{}{}",
        stdout(&out),
        stderr(&out)
    );
    let read = run(
        &w,
        &[
            "/bin/sh",
            "-c",
            &format!("cat '{}' > /dev/null", hook.display()),
        ],
    );
    assert_ne!(code(&read), 0);
}

#[test]
fn a_failing_hook_ends_the_run_before_the_agent_starts_and_says_which_hook() {
    sandboxed!();
    let w = World::new(PROJECT);
    let hook = tool(
        &w,
        "bad",
        "echo SENTINEL-OUT; echo SENTINEL-ERR >&2; exit 4",
    );
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.bad]\ncommand = [\"{}\"]\n",
            hook.display()
        ),
    );
    let out = run(
        &w,
        &[
            "/bin/sh",
            "-c",
            &format!("touch '{}'", marker(&w).display()),
        ],
    );
    assert_ne!(code(&out), 0);
    let text = stderr(&out);
    assert!(text.contains("hook `bad` failed (exit status 4)"), "{text}");
    assert!(
        !text.contains("SENTINEL") && !stdout(&out).contains("SENTINEL"),
        "output shown: {text}"
    );
    assert!(!marker(&w).exists(), "the agent started");
}

#[test]
fn a_hook_that_runs_past_its_timeout_aborts_the_run() {
    sandboxed!();
    let w = World::new(PROJECT);
    let hook = tool(&w, "slow", "sleep 30");
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.slow]\ncommand = [\"{}\"]\ntimeout_secs = 1\n",
            hook.display()
        ),
    );
    let started = Instant::now();
    let out = run(
        &w,
        &[
            "/bin/sh",
            "-c",
            &format!("touch '{}'", marker(&w).display()),
        ],
    );
    assert_ne!(code(&out), 0);
    assert!(
        stderr(&out).contains("took more than 1 s"),
        "{}",
        stderr(&out)
    );
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    assert!(!marker(&w).exists());
}

/// A slow hook that records its process group's survivors; SIGTERM to `hb` must end it at once.
#[test]
fn a_signal_to_hb_during_a_slow_hook_kills_the_hook_and_never_starts_the_agent() {
    sandboxed!();
    for signal in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP] {
        let w = World::new(PROJECT);
        let started = w.base.join("hook-started");
        let leftover = w.base.join("hook-finished");
        let hook = tool(
            &w,
            "slow",
            &format!(
                "touch '{}'; sleep 30 & wait; touch '{}'",
                started.display(),
                leftover.display()
            ),
        );
        with_base(
            &w,
            &format!(
                "[fs]\nwrite = [\".\"]\n[hooks.pre_run.slow]\ncommand = [\"{}\"]\ntimeout_secs = 60\n",
                hook.display()
            ),
        );
        let mut cmd = w.drive(
            DRIVE,
            &[
                "run",
                "--",
                "/bin/sh",
                "-c",
                &format!("touch '{}'", marker(&w).display()),
            ],
        );
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let child = assert_ok!(cmd.spawn());
        let deadline = Instant::now() + Duration::from_secs(30);
        while !started.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(started.exists(), "the hook never started");
        let sent = Instant::now();
        assert_ok!(kill(
            Pid::from_raw(i32::try_from(child.id()).unwrap_or(0)),
            signal
        ));
        let out = assert_ok!(child.wait_with_output());
        assert!(
            sent.elapsed() < Duration::from_secs(10),
            "{signal:?}: the stop took {:?}",
            sent.elapsed()
        );
        assert_ne!(code(&out), 0, "{signal:?}");
        assert!(
            stderr(&out).contains("stopped"),
            "{signal:?}: {}",
            stderr(&out)
        );
        std::thread::sleep(Duration::from_millis(300));
        assert!(!leftover.exists(), "{signal:?}: the hook ran to its end");
        assert!(!marker(&w).exists(), "{signal:?}: the agent started");
    }
}

const CREDENTIALS: &str = r#"{"Version":1,"AccessKeyId":"AKIAEXAMPLE","SecretAccessKey":"sEcr3t/value+x=","SessionToken":"tok/en+==","Expiration":"2030-01-01T00:00:00Z"}"#;

#[test]
fn the_aws_format_gives_the_agent_a_credentials_pair_and_the_real_aws_directory_stays_closed() {
    sandboxed!();
    let w = World::new(PROJECT);
    write(
        &w.home_dir().join(".aws/credentials"),
        "[real]\naws_secret_access_key = REAL-SECRET\n",
    );
    let hook = tool(&w, "cred", &format!("cat <<'EOF'\n{CREDENTIALS}\nEOF"));
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.bedrock]\ncommand = [\"{}\", \"--profile\", \"p\"]\nformat = \"aws_credential_process\"\nprofile = \"p\"\n",
            hook.display()
        ),
    );
    let script = "cat \"$AWS_SHARED_CREDENTIALS_FILE\"; cat \"$AWS_CONFIG_FILE\"; \
                  cat \"$HOME/.aws/credentials\" 2>/dev/null && echo REAL-READ-OK";
    let out = run(&w, &["/bin/sh", "-c", script]);
    let text = stdout(&out);
    assert!(
        text.contains("aws_access_key_id = AKIAEXAMPLE"),
        "{text}{}",
        stderr(&out)
    );
    assert!(text.contains("[profile p]"), "{text}");
    assert!(
        !text.contains("REAL-READ-OK") && !text.contains("REAL-SECRET"),
        "{text}"
    );
    assert!(
        !stderr(&out).contains("sEcr3t"),
        "a credential reached stderr: {}",
        stderr(&out)
    );
}

#[test]
fn under_the_claude_preset_the_agent_gets_session_credentials_and_a_private_tmp_but_not_the_real_ones()
 {
    sandboxed!();
    let w = World::new("extends = [\"agent/claude\"]\n[fs]\nwrite = [\".\"]\n");
    write(
        &w.home_dir().join(".aws/credentials"),
        "[real]\naws_secret_access_key = REAL-SECRET\n",
    );
    let hook = tool(&w, "cred", &format!("cat <<'EOF'\n{CREDENTIALS}\nEOF"));
    with_base(
        &w,
        &format!(
            "[tls]\nsystem_trust = true\n[hooks.pre_run.bedrock]\ncommand = [\"{}\", \"--profile\", \"p\"]\nformat = \"aws_credential_process\"\nprofile = \"p\"\n",
            hook.display()
        ),
    );
    let script = format!(
        "grep -c AKIAEXAMPLE \"$AWS_SHARED_CREDENTIALS_FILE\"; \
         cat \"$HOME/.aws/credentials\" 2>/dev/null && echo REAL-READ-OK; \
         '{tool}' 2>/dev/null && echo TOOL-RAN; \
         echo \"tmpdir=$CLAUDE_CODE_TMPDIR session=$TMPDIR updater=$DISABLE_AUTOUPDATER\"; \
         mkdir \"$CLAUDE_CODE_TMPDIR/claude-502\" && echo OWN-TMP-OK; \
         mkdir /private/tmp/claude-502 2>/dev/null && echo SHARED-TMP-OK; \
         mkdir /private/tmp/cc-socks 2>/dev/null && echo SHARED-SOCKS-OK; true",
        tool = hook.display()
    );
    let out = run(&w, &["/bin/sh", "-c", &script]);
    let text = stdout(&out);
    assert!(text.starts_with("1\n"), "{text}{}", stderr(&out));
    assert!(text.contains("OWN-TMP-OK"), "{text}{}", stderr(&out));
    assert!(text.contains("updater=1"), "{text}");
    let line = text
        .lines()
        .find(|l| l.starts_with("tmpdir="))
        .unwrap_or("");
    let session = line
        .split("session=")
        .nth(1)
        .and_then(|r| r.split(' ').next());
    assert_eq!(
        line.strip_prefix("tmpdir=")
            .and_then(|r| r.split(' ').next()),
        session,
        "{text}"
    );
    for leak in [
        "REAL-READ-OK",
        "REAL-SECRET",
        "TOOL-RAN",
        "SHARED-TMP-OK",
        "SHARED-SOCKS-OK",
    ] {
        assert!(!text.contains(leak), "{leak}: {text}");
    }
}

#[test]
fn a_placeholder_in_set_names_the_sessions_private_directory() {
    sandboxed!();
    let w = World::new(&format!(
        "{PROJECT}[env.set]\nMY_TMP = \"{{session_dir}}/work\"\n"
    ));
    let out = run(&w, &["/bin/sh", "-c", "echo \"$MY_TMP\"; echo \"$TMPDIR\""]);
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text}{}", stderr(&out));
    assert_eq!(lines[0], format!("{}/work", lines[1]));
}

#[test]
fn hook_files_are_private_and_gone_after_the_run_ends_normally_or_by_sigterm() {
    sandboxed!();
    let w = World::new(PROJECT);
    let hook = tool(&w, "files", "echo data > out.txt");
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.files]\ncommand = [\"{}\"]\n[hooks.pre_run.files.outputs]\nOUT = \"out.txt\"\n",
            hook.display()
        ),
    );
    let seen = w.project.join("seen");
    let script = format!("echo \"$OUT\" > '{}'; sleep 60", seen.display());
    let mut cmd = w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", &script]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = assert_ok!(cmd.spawn());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !seen.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let file = PathBuf::from(assert_ok!(fs::read_to_string(&seen)).trim());
    assert!(file.is_file(), "{}", file.display());
    assert_eq!(assert_ok!(fs::metadata(&file)).mode() & 0o7777, 0o600);
    let dir = assert_ok!(file.parent().ok_or("no parent"));
    assert_eq!(assert_ok!(fs::metadata(dir)).mode() & 0o7777, 0o700);
    let session = dir.parent().and_then(Path::parent).map(Path::to_path_buf);
    let session = assert_ok!(session.ok_or("no session directory"));
    assert!(session.is_dir());
    assert_ok!(kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap_or(0)),
        Signal::SIGTERM
    ));
    let status = assert_ok!(child.wait());
    assert!(!status.success());
    assert!(!file.exists(), "the hook's file survived SIGTERM");
    assert!(!session.exists(), "the session directory survived SIGTERM");
}

#[test]
fn hb_explain_lists_hooks_with_their_origin() {
    sandboxed!();
    let w = World::new(PROJECT);
    let hook = tool(&w, "x", "true");
    with_base(
        &w,
        &format!(
            "[fs]\nwrite = [\".\"]\n[hooks.pre_run.listed]\ncommand = [\"{}\", \"arg\"]\ntimeout_secs = 12\n",
            hook.display()
        ),
    );
    w.approve();
    let mut cmd = w.drive_unapproved(DRIVE, &["explain"]);
    cmd.stdin(Stdio::null());
    let out = assert_ok!(cmd.output());
    let text = stdout(&out);
    assert!(text.contains("listed:"), "{text}");
    assert!(text.contains("(12s)"), "{text}");
    assert!(text.contains("hooks.pre_run.listed"), "{text}");
}
