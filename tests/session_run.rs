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
    common::sh_in_hb(world, script)
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
        // The proxy the child must use, and what bypasses it.
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
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
        "HTTP_PROXY",
        "NO_PROXY",
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

// ====================================================================================
// TLS trust (design 4.5)
// ====================================================================================

const CERT: &str = "-----BEGIN CERTIFICATE-----\nQUFBQQ==\n-----END CERTIFICATE-----\n";

#[test]
fn system_trust_sets_node_use_system_ca_and_turning_it_off_removes_it() {
    sandboxed!();
    let on = World::with_base("[tls]\nsystem_trust = true\n", PROJECT);
    let out = sh(&on, "echo \"[$NODE_USE_SYSTEM_CA][$NODE_EXTRA_CA_CERTS]\"");
    assert_eq!(stdout(&out).trim(), "[1][]");
    let off = World::with_base(
        "[tls]\nsystem_trust = true\n",
        &format!("{PROJECT}[tls]\nsystem_trust = false\n"),
    );
    let out = sh(&off, "echo \"[$NODE_USE_SYSTEM_CA]\"");
    assert_eq!(stdout(&out).trim(), "[]", "false from any file wins");
    let unset = World::new(PROJECT);
    assert_eq!(
        stdout(&sh(&unset, "echo \"[$NODE_USE_SYSTEM_CA]\"")).trim(),
        "[]"
    );
}

#[test]
fn extra_ca_files_become_one_bundle_in_the_session_directory_that_the_child_can_read() {
    sandboxed!();
    let w = World::new(PROJECT);
    let first = w.project.join("one.pem");
    let second = w.project.join("two.pem");
    common::write(&first, &format!("junk\n{CERT}"));
    common::write(&second, &CERT.replace("QUFBQQ==", "QkJCQg=="));
    w.set_project(&format!(
        "{PROJECT}[tls]\nextra_ca_files = [{}, {}]\n",
        common::toml_string(&first.to_string_lossy()),
        common::toml_string(&second.to_string_lossy())
    ));
    let out = sh(
        &w,
        "echo \"$NODE_EXTRA_CA_CERTS\"; stat -f %Lp \"$NODE_EXTRA_CA_CERTS\"; cat \"$NODE_EXTRA_CA_CERTS\"",
    );
    assert_eq!(
        out.exit,
        ExitKind::Exited(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = stdout(&out);
    let mut lines = text.lines();
    let bundle = std::path::Path::new(lines.next().unwrap_or_default());
    assert_eq!(lines.next(), Some("600"), "{text}");
    assert_eq!(
        bundle.file_name().and_then(|n| n.to_str()),
        Some("ca-bundle.pem")
    );
    assert_eq!(
        bundle.parent().and_then(|p| p.parent()),
        Some(temp_dir(&w).as_path())
    );
    let body: Vec<&str> = lines.collect();
    assert_eq!(
        body,
        [
            "-----BEGIN CERTIFICATE-----",
            "QUFBQQ==",
            "-----END CERTIFICATE-----",
            "-----BEGIN CERTIFICATE-----",
            "QkJCQg==",
            "-----END CERTIFICATE-----"
        ],
        "only the certificates, in the order of the config"
    );
    assert!(
        !bundle.exists(),
        "the bundle went with the session directory"
    );
}

#[test]
fn a_ca_file_with_no_certificate_stops_the_run_before_the_child_starts() {
    sandboxed!();
    let w = World::new(PROJECT);
    let bad = w.project.join("not-a-cert.pem");
    common::write(&bad, "this is not a certificate\n");
    w.set_project(&format!(
        "{PROJECT}[tls]\nextra_ca_files = [{}]\n",
        common::toml_string(&bad.to_string_lossy())
    ));
    let marker = w.project.join("child-ran");
    let spec = RunSpec::new(["/usr/bin/touch", &marker.to_string_lossy()]);
    let error = assert_err!(run(&w.env, &w.loaded(), &spec));
    assert!(matches!(error, RunError::CaBundle { .. }), "{error}");
    assert!(error.to_string().contains("not-a-cert.pem"), "{error}");
    assert!(
        !marker.exists(),
        "the child ran although the CA file was bad"
    );
    assert_eq!(
        assert_ok!(fs::read_dir(temp_dir(&w))).count(),
        0,
        "no session directory is left behind"
    );
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

// ====================================================================================
// --log-denials
// ====================================================================================

use hamster_ball::session::DenialSink;

/// Reads `path` several times: the log is not complete, so one read could be one of the missed ones.
fn read_repeatedly(path: &std::path::Path) -> String {
    let p = common::quote(path);
    format!("for i in 1 2 3 4 5; do /bin/cat {p} > /dev/null 2>&1; done; true")
}

#[test]
fn a_denied_read_shows_up_with_its_path_and_a_denial_from_another_sandbox_does_not() {
    sandboxed!();
    let w = World::new(PROJECT);
    let secret = w.home_dir().join(".ssh/id_denied_by_the_floor");
    common::write(&secret, "key\n");
    let other_dir = assert_ok!(tempfile::TempDir::new());
    let other_file = other_dir.path().join("unrelated_denied_file");
    common::write(&other_file, "x\n");

    let spec =
        RunSpec::new(["/bin/sh", "-c", &read_repeatedly(&secret)]).denials(DenialSink::Collect);
    // An unrelated sandbox, with its own tag, denies a read at the same time.
    let unrelated = {
        let profile = "(version 1)(deny default (with message \"other-tool\"))(import \"system.sb\")(allow process-exec*)(allow file-read* (subpath \"/bin\") (subpath \"/usr\"))".to_owned();
        let file = other_file.clone();
        std::thread::spawn(move || {
            for _ in 0..8 {
                let _ = Command::new("/usr/bin/sandbox-exec")
                    .args(["-p", &profile, "/bin/cat"])
                    .arg(&file)
                    .output();
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        })
    };
    let out = assert_ok!(run(&w.env, &w.loaded(), &spec));
    let _ = unrelated.join();
    assert_eq!(out.exit, ExitKind::Exited(0));
    let all = out.denials.lines.join("\n");
    assert!(
        all.contains("id_denied_by_the_floor") && all.contains("file-read-data"),
        "the denied read is missing: {:?}",
        out.denials
    );
    assert!(
        all.contains("[floor]"),
        "the rule's label is missing: {all}"
    );
    assert!(
        !all.contains("unrelated_denied_file"),
        "a denial from another sandbox leaked in: {all}"
    );
    assert_eq!(out.denials.dropped, 0);
}

#[test]
fn without_the_option_nothing_is_collected() {
    sandboxed!();
    let w = World::new(PROJECT);
    let secret = w.home_dir().join(".ssh/id_denied_by_the_floor");
    common::write(&secret, "key\n");
    let spec = RunSpec::new(["/bin/sh", "-c", &read_repeatedly(&secret)]);
    let out = assert_ok!(run(&w.env, &w.loaded(), &spec));
    assert!(out.denials.lines.is_empty() && out.denials.dropped == 0);
}

#[test]
fn a_stream_sink_receives_each_denial_as_it_is_complete_and_nothing_is_kept() {
    sandboxed!();
    let w = World::new(PROJECT);
    let secret = w.home_dir().join(".ssh/id_denied_by_the_floor");
    common::write(&secret, "key\n");
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = {
        let seen = std::sync::Arc::clone(&seen);
        DenialSink::Stream(std::sync::Arc::new(move |line: &str| {
            if let Ok(mut seen) = seen.lock() {
                seen.push(line.to_owned());
            }
        }))
    };
    let spec = RunSpec::new(["/bin/sh", "-c", &read_repeatedly(&secret)]).denials(sink);
    let out = assert_ok!(run(&w.env, &w.loaded(), &spec));
    assert!(
        out.denials.lines.is_empty(),
        "a streamed denial must not also be kept"
    );
    let seen = assert_ok!(seen.lock()).join("\n");
    assert!(seen.contains("id_denied_by_the_floor"), "{seen}");
}

// ====================================================================================
// The proxy (design 12, hb-ghd.3.3)
// ====================================================================================

mod proxy {
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::thread;

    use super::{ExitKind, Outcome, RunSpec, World, run, sandbox_available, sh, stdout};
    use crate::common::proxy::{Table, to_loopback};
    use claims::assert_ok;
    use hamster_ball::session::{DenialSink, ProxyTuning};
    use pretty_assertions::assert_eq;

    const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

    fn run_spec(world: &World, spec: &RunSpec) -> Outcome {
        assert_ok!(run(&world.env, &world.loaded(), spec))
    }

    /// An HTTP upstream on loopback that answers every request with `HELLO`.
    fn upstream() -> u16 {
        let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
        let port = assert_ok!(listener.local_addr()).port();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf);
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO",
                    );
                });
            }
        });
        port
    }

    /// Resolves `allowed.test` to a public address and dials the upstream on loopback instead.
    fn allowed_test_tuning() -> ProxyTuning {
        ProxyTuning::new(|config| {
            config
                .with_resolver(Table::of(&["allowed.test"]))
                .with_dial_map(to_loopback())
        })
    }

    #[test]
    fn the_child_gets_all_six_proxy_variables_with_the_same_credentialed_url_and_a_loopback_no_proxy()
     {
        sandboxed!();
        let w = World::new(PROJECT);
        let out = sh(&w, "/usr/bin/env");
        let text = stdout(&out);
        let value = |name: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("{name}=")))
                .unwrap_or_default()
                .to_owned()
        };
        let url = value("HTTPS_PROXY");
        assert!(
            url.starts_with("http://hb:") && url.contains("@127.0.0.1:"),
            "{url}"
        );
        for name in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert_eq!(value(name), url, "{name}");
        }
        assert_eq!(value("NO_PROXY"), "localhost,127.0.0.1");
        assert_eq!(value("no_proxy"), "localhost,127.0.0.1");
        // Two runs get two tokens.
        assert_ne!(stdout(&sh(&w, "echo $HTTPS_PROXY")).trim(), url);
    }

    #[test]
    fn an_allowed_host_is_reached_through_the_proxy_and_not_around_it() {
        sandboxed!();
        let port = upstream();
        let w = World::new(&format!(
            "[fs]\nwrite = [\".\"]\n[net]\nallow = [\"allowed.test:{port}\"]\n"
        ));
        let url = format!("http://allowed.test:{port}/x");
        let spec = RunSpec::new(["/bin/sh", "-c", &format!(
            "/usr/bin/curl -sS -m 10 {url}; echo \" rc=$?\"; /usr/bin/curl -sS -m 5 --noproxy '*' {url}; echo \" direct rc=$?\""
        )])
        .proxy_tuning(allowed_test_tuning());
        let out = run_spec(&w, &spec);
        let text = format!("{}{}", stdout(&out), String::from_utf8_lossy(&out.stderr));
        assert!(text.contains("HELLO rc=0"), "through the proxy: {text}");
        assert!(
            text.contains("direct rc=") && !text.contains("HELLO direct"),
            "around the proxy: {text}"
        );
        assert!(!text.contains("direct rc=0"), "{text}");
        assert!(
            out.warnings.iter().all(|w| !w.contains("proxy refused")),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn a_host_that_is_not_allowed_is_a_403_from_the_proxy_a_summary_and_a_denial_line() {
        sandboxed!();
        let w = World::new(PROJECT);
        let script = "/usr/bin/curl -sS -m 10 https://refused.example.org/ 2>&1; echo rc=$?";
        let out = run_spec(&w, &RunSpec::new(["/bin/sh", "-c", script]));
        let text = stdout(&out);
        assert!(
            text.contains("403") || text.contains("refused.example.org"),
            "{text}"
        );
        let summary: Vec<&String> = out
            .warnings
            .iter()
            .filter(|w| w.contains("proxy refused"))
            .collect();
        assert_eq!(summary.len(), 1, "{:?}", out.warnings);
        assert!(
            summary[0].contains("1 connection to 1 host"),
            "{}",
            summary[0]
        );
        assert!(summary[0].contains("--log-denials"));
        assert!(
            out.denials.lines.is_empty(),
            "no denial sink, nothing collected"
        );

        // With the denial log on, the lines are shown and the summary is not repeated.
        let spec = RunSpec::new(["/bin/sh", "-c", script]).denials(DenialSink::Collect);
        let out = run_spec(&w, &spec);
        assert!(
            out.denials
                .lines
                .iter()
                .any(|l| l.starts_with("proxy refused refused.example.org:443 not_allowed")),
            "{:?}",
            out.denials
        );
        assert!(
            out.warnings.iter().all(|w| !w.contains("proxy refused")),
            "{:?}",
            out.warnings
        );

        // The summary can be switched off.
        let spec = RunSpec::new(["/bin/sh", "-c", script]).proxy_summary(false);
        let out = run_spec(&w, &spec);
        assert!(
            out.warnings.iter().all(|w| !w.contains("proxy refused")),
            "{:?}",
            out.warnings
        );
    }

    #[test]
    fn the_proxy_log_has_one_line_per_connection_with_bytes_for_the_ones_served() {
        sandboxed!();
        let port = upstream();
        let w = World::new(&format!(
            "[fs]\nwrite = [\".\"]\n[net]\nallow = [\"allowed.test:{port}\"]\n"
        ));
        let script = format!(
            "/usr/bin/curl -sS -m 10 http://allowed.test:{port}/x >/dev/null; /usr/bin/curl -sS -m 10 https://refused.example.org/ >/dev/null 2>&1; true"
        );
        let spec = RunSpec::new(["/bin/sh", "-c", &script])
            .proxy_tuning(allowed_test_tuning())
            .proxy_log(DenialSink::Collect);
        let out = run_spec(&w, &spec);
        let lines = &out.proxy_log.lines;
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with(&format!("allowed allowed.test:{port} up="))),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("refused refused.example.org:443 not_allowed")),
            "{lines:?}"
        );
        // Without the sink the log is empty.
        let out = run_spec(&w, &RunSpec::new(["/bin/sh", "-c", "true"]));
        assert!(out.proxy_log.lines.is_empty());
    }

    #[test]
    fn a_listed_loopback_port_is_reached_directly_and_an_unlisted_one_is_not() {
        sandboxed!();
        let listed = upstream();
        let unlisted = upstream();
        let w = World::new(&format!(
            "[fs]\nwrite = [\".\"]\n[net]\nloopback_ports = [{listed}]\n"
        ));
        let script = format!(
            "/usr/bin/curl -sS -m 5 http://127.0.0.1:{listed}/; echo \" listed rc=$?\"; /usr/bin/curl -sS -m 5 http://127.0.0.1:{unlisted}/; echo \" unlisted rc=$?\""
        );
        let out = run_spec(&w, &RunSpec::new(["/bin/sh", "-c", &script]));
        let text = stdout(&out);
        assert!(text.contains("HELLO listed rc=0"), "{text}");
        assert!(
            text.contains("unlisted rc=") && !text.contains("unlisted rc=0"),
            "{text}"
        );
        assert!(!text.contains("HELLO unlisted"), "{text}");
    }

    #[test]
    fn a_loopback_port_nobody_listens_on_is_a_warning_and_a_listening_one_is_not() {
        sandboxed!();
        let open = upstream();
        let closed = {
            let l = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
            assert_ok!(l.local_addr()).port()
        };
        let w = World::new(&format!(
            "[fs]\nwrite = [\".\"]\n[net]\nloopback_ports = [{open}, {closed}]\n"
        ));
        let out = sh(&w, "true");
        assert_eq!(out.exit, ExitKind::Exited(0));
        let warning: Vec<&String> = out
            .warnings
            .iter()
            .filter(|w| w.contains("not listening"))
            .collect();
        assert_eq!(warning.len(), 1, "{:?}", out.warnings);
        assert!(warning[0].contains(&closed.to_string()), "{}", warning[0]);
        assert!(!warning[0].contains(&open.to_string()), "{}", warning[0]);
    }
}

/// Runs inside a re-executed copy of this test binary, as `hb` does at start. A failing sweep
/// cannot be provoked in a real process, so that is covered in the library's own tests; this
/// checks what only a real process can: after `start_up`, no descriptor above 2 is left.
#[test]
fn start_up_probe_child() {
    let Some(_) = std::env::var_os("HB_START_UP_PROBE") else {
        return;
    };
    let start = hamster_ball::session::start_up();
    let open: Vec<String> = fs::read_dir("/dev/fd")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n.parse::<i32>().is_ok_and(|fd| fd > 2))
                .collect()
        })
        .unwrap_or_default();
    // The directory listing holds one descriptor of its own, already closed when it is read.
    println!(
        "STARTUP problem={} channel={} open={}",
        start.problem.is_some(),
        start.channel.is_some(),
        open.len()
    );
}

#[test]
fn start_up_leaves_no_inherited_descriptor_open_and_a_bad_channel_variable_is_reported() {
    if !sandbox_available() {
        return;
    }
    let exe = assert_ok!(std::env::current_exe());
    let run = |extra: &str| {
        let script = format!(
            "exec 3</etc/hosts; exec 4</etc/hosts; {extra} exec {} --exact start_up_probe_child --nocapture",
            common::quote(&exe)
        );
        let out = assert_ok!(
            Command::new("/bin/sh")
                .args(["-c", &script])
                .env("HB_START_UP_PROBE", "1")
                .stdin(std::process::Stdio::null())
                .output()
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    };
    // No supervisor: every descriptor the shell left is closed, and nothing is reported.
    let plain = run("");
    assert!(
        plain.contains("STARTUP problem=false channel=false open=1")
            || plain.contains("STARTUP problem=false channel=false open=0"),
        "{plain}"
    );
    // A variable that names a descriptor that is not a socket is reported, and still swept.
    let bad = run("HB_SUPERVISOR_FD=3");
    assert!(bad.contains("problem=true"), "{bad}");
    assert!(
        bad.contains("open=1") || bad.contains("open=0"),
        "a refused channel must not leave descriptors behind: {bad}"
    );
}
