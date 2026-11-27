// ABOUTME: `hb run` and `hb approve` end to end: no terminal and no approval is exit 78, a yes at a terminal approves, a change asks again.
// ABOUTME: Runs hb-testdrive as a process (stdin closed, or under expect for a terminal); also shows the sandbox cannot read or change the store.
//! The approval gate as a user meets it (design section 5).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::process::{Command, Output, Stdio};

use claims::assert_ok;
use common::{
    EXPECT_GUARD, World, assert_no_expect_timeout, hb_succeeds, hb_text, sandbox_available,
    sh_in_hb,
};
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";
const NOT_APPROVED: i32 = 78;

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// `hb <args>` in the world as it is, with no terminal.
fn hb(w: &World, args: &[&str]) -> Output {
    let mut cmd = w.drive_unapproved(DRIVE, args);
    cmd.stdin(Stdio::null());
    assert_ok!(cmd.output())
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn marker_script(w: &World) -> String {
    format!("touch '{}'", w.project.join("ran").display())
}

fn ran(w: &World) -> bool {
    w.project.join("ran").exists()
}

fn approvals_dir(w: &World) -> std::path::PathBuf {
    w.home_dir().join(".local/state/hamster-ball/approvals")
}

fn records(w: &World) -> usize {
    fs::read_dir(approvals_dir(w)).map_or(0, |d| d.flatten().count())
}

/// Runs `hb <args>` under expect so it has a terminal, types `answer` at the prompt, and returns
/// what was printed and the exit code.
fn at_a_terminal(w: &World, args: &[&str], answer: &str) -> (String, i32) {
    if !std::path::Path::new("/usr/bin/expect").exists() {
        return (String::new(), -2);
    }
    let exp = w.base.join("approve.exp");
    let args: Vec<String> = args.iter().map(|a| format!("{{{a}}}")).collect();
    let body = format!(
        "set env(HB_TD_HOME) {home}\nset env(HB_TD_CWD) {cwd}\nset env(HB_TD_PATH) {path}\nset env(HB_TD_TMP) {tmp}\n\
         set timeout 30\n{guard}spawn {drive} {args}\n\
         expect -re {{Type `approve ([0-9a-f]+)` to approve: }}\nset code $expect_out(1,string)\n\
         send \"{answer}\"\nsend \"\\r\"\n\
         expect eof\ncatch wait result\nputs \"EXIT=[lindex $result 3]\"\n",
        home = w.home_dir().display(),
        cwd = w.project.display(),
        path = w.base.join("bin").display(),
        tmp = w.base.join("tmp").display(),
        drive = DRIVE,
        args = args.join(" "),
        guard = EXPECT_GUARD,
    );
    common::write(&exp, &body);
    let out = assert_ok!(Command::new("/usr/bin/expect").arg(&exp).output());
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert_no_expect_timeout(&text);
    let exit = text
        .rsplit_once("EXIT=")
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(-1);
    (text, exit)
}

/// Runs the shell line `line` under expect, never typing anything, and returns what was printed and
/// the shell's exit code. `None` when there is no expect.
fn shell_at_a_terminal(w: &World, line: &str) -> Option<(String, i32)> {
    if !std::path::Path::new("/usr/bin/expect").exists() {
        return None;
    }
    let exp = w.base.join("shell.exp");
    let body = format!(
        "set env(HB_TD_HOME) {home}\nset env(HB_TD_CWD) {cwd}\nset env(HB_TD_PATH) {path}\nset env(HB_TD_TMP) {tmp}\n\
         set timeout 20\n{guard}spawn /bin/sh -c {{{line}}}\n\
         expect eof\ncatch wait result\nputs \"EXIT=[lindex $result 3]\"\n",
        home = w.home_dir().display(),
        cwd = w.project.display(),
        path = w.base.join("bin").display(),
        tmp = w.base.join("tmp").display(),
        guard = EXPECT_GUARD,
    );
    common::write(&exp, &body);
    let out = assert_ok!(Command::new("/usr/bin/expect").arg(&exp).output());
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert_no_expect_timeout(&text);
    let exit = text
        .rsplit_once("EXIT=")
        .and_then(|(_, n)| n.trim().parse().ok())
        .unwrap_or(-1);
    Some((text, exit))
}

#[test]
fn without_a_terminal_an_unapproved_config_is_exit_78_and_nothing_runs() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = hb(&w, &["run", "/bin/sh", "-c", &marker_script(&w)]);
    assert_eq!(code(&out), NOT_APPROVED, "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("has not been approved"), "{text}");
    assert!(text.contains("hb approve"), "{text}");
    assert!(!ran(&w), "the command ran");
    assert_eq!(records(&w), 0);
}

#[test]
fn an_approved_config_runs_without_a_question_and_the_childs_exit_code_comes_back() {
    sandboxed!();
    let w = World::new(PROJECT);
    w.approve();
    let out = hb(&w, &["run", "/bin/sh", "-c", "exit 7"]);
    assert_eq!(code(&out), 7, "{}", stderr(&out));
    assert!(!stderr(&out).contains("approved"), "{}", stderr(&out));
}

#[test]
fn a_config_changed_after_approval_is_exit_78_again_and_the_message_names_the_file() {
    sandboxed!();
    let w = World::new(PROJECT);
    w.approve();
    assert_eq!(code(&hb(&w, &["run", "/usr/bin/true"])), 0);
    w.set_project("[fs]\nwrite = [\".\"]\n[net]\nallow = [\"example.com\"]\n");
    let out = hb(&w, &["run", "/bin/sh", "-c", &marker_script(&w)]);
    assert_eq!(code(&out), NOT_APPROVED, "{}", stderr(&out));
    let text = stderr(&out);
    assert!(text.contains("changed since it was approved"), "{text}");
    assert!(text.contains("hamster-ball.toml"), "{text}");
    assert!(!ran(&w));
}

#[test]
fn touching_the_file_without_changing_a_byte_keeps_the_approval() {
    sandboxed!();
    let w = World::new(PROJECT);
    w.approve();
    let config = w.project.join("hamster-ball.toml");
    let text = assert_ok!(fs::read(&config));
    assert_ok!(fs::write(&config, &text));
    assert_eq!(code(&hb(&w, &["run", "/usr/bin/true"])), 0);
}

#[test]
fn hb_approve_without_a_terminal_is_exit_78_and_stores_nothing() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = hb(&w, &["approve"]);
    assert_eq!(code(&out), NOT_APPROVED, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("needs a terminal"),
        "{}",
        stderr(&out)
    );
    assert_eq!(records(&w), 0);
}

#[test]
fn the_typed_approval_at_the_terminal_approves_and_the_next_run_needs_no_terminal() {
    sandboxed!();
    let w = World::new(PROJECT);
    let (text, exit) = at_a_terminal(&w, &["approve"], "approve $code");
    if exit == -2 {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    }
    assert_eq!(exit, 0, "{text}");
    assert!(text.contains("This project adds"), "{text}");
    assert!(text.contains("approved "), "{text}");
    assert_eq!(records(&w), 1);
    assert_eq!(code(&hb(&w, &["run", "/usr/bin/true"])), 0);
}

#[test]
fn anything_but_the_typed_approval_at_the_terminal_leaves_the_config_unapproved() {
    sandboxed!();
    let w = World::new(PROJECT);
    let (text, exit) = at_a_terminal(&w, &["approve"], "no");
    if exit == -2 {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    }
    assert_eq!(exit, NOT_APPROVED, "{text}");
    assert_eq!(records(&w), 0);
}

#[test]
fn a_plain_y_or_yes_or_a_made_up_code_at_the_terminal_no_longer_approves() {
    sandboxed!();
    for answer in [
        "y",
        "yes",
        "approve",
        "approve 000000",
        "approve $code extra",
    ] {
        let w = World::new(PROJECT);
        let (text, exit) = at_a_terminal(&w, &["approve"], answer);
        if exit == -2 {
            eprintln!("SKIP: no expect to provide a terminal");
            return;
        }
        assert_eq!(exit, NOT_APPROVED, "{answer:?}: {text}");
        assert_eq!(records(&w), 0, "{answer:?}");
    }
}

#[test]
fn hb_run_at_a_terminal_asks_then_runs_the_command_on_the_typed_approval() {
    sandboxed!();
    let w = World::new(PROJECT);
    let (text, exit) = at_a_terminal(
        &w,
        &["run", "/bin/sh", "-c", &marker_script(&w)],
        "approve $code",
    );
    if exit == -2 {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    }
    assert_eq!(exit, 0, "{text}");
    assert!(ran(&w), "{text}");
    assert_eq!(records(&w), 1);
}

#[test]
fn hb_run_at_a_terminal_does_not_run_the_command_on_a_no() {
    sandboxed!();
    let w = World::new(PROJECT);
    let (text, exit) = at_a_terminal(&w, &["run", "/bin/sh", "-c", &marker_script(&w)], "n");
    if exit == -2 {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    }
    assert_eq!(exit, NOT_APPROVED, "{text}");
    assert!(!ran(&w), "{text}");
    assert!(text.contains("Nothing was run"), "{text}");
}

#[test]
fn revoking_takes_the_approval_back_without_a_terminal_and_says_so_twice() {
    sandboxed!();
    let w = World::new(PROJECT);
    w.approve();
    assert_eq!(records(&w), 1);
    let out = hb(&w, &["approve", "--revoke"]);
    assert_eq!(code(&out), 0, "{}", stderr(&out));
    assert!(
        stdout(&out).contains("revoked the approval of"),
        "{}",
        stdout(&out)
    );
    assert_eq!(records(&w), 0);
    let again = hb(&w, &["approve", "--revoke"]);
    assert_eq!(code(&again), 0);
    assert!(
        stdout(&again).contains("was not approved"),
        "{}",
        stdout(&again)
    );
    assert_eq!(code(&hb(&w, &["run", "/usr/bin/true"])), NOT_APPROVED);
}

#[test]
fn hb_approve_inside_a_hamster_ball_refuses() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut cmd = w.drive_unapproved(DRIVE, &["approve"]);
    cmd.env("HB_SESSION", "1").stdin(Stdio::null());
    let out = assert_ok!(cmd.output());
    assert_eq!(code(&out), 1, "{}", stderr(&out));
    assert!(
        stderr(&out).contains("inside a hamster ball"),
        "{}",
        stderr(&out)
    );
    assert_eq!(records(&w), 0);
}

#[test]
fn hb_explain_says_when_the_config_is_not_approved_and_stops_saying_it_once_it_is() {
    sandboxed!();
    let w = World::new(PROJECT);
    let before = stdout(&hb(&w, &["explain"]));
    assert!(before.contains("has not been approved"), "{before}");
    w.approve();
    let after = stdout(&hb(&w, &["explain"]));
    assert!(!after.contains("has not been approved"), "{after}");
}

#[test]
fn the_agent_cannot_read_list_or_change_the_approval_store_or_its_own_config() {
    sandboxed!();
    let w = World::new(PROJECT);
    w.approve();
    let dir = approvals_dir(&w);
    let record = assert_ok!(fs::read_dir(&dir))
        .flatten()
        .next()
        .map(|e| e.path())
        .unwrap_or_default();
    let before = assert_ok!(fs::read(&record));
    let config = w.project.join("hamster-ball.toml");
    let config_before = assert_ok!(fs::read(&config));
    let control = sh_in_hb(
        &w,
        "echo writable > plain.txt; mv plain.txt moved.txt; cat moved.txt; rm moved.txt",
    );
    assert!(hb_succeeds(&control) && hb_text(&control).contains("writable"));

    // The control: the same commands work outside the ball, so the sandbox is what stops them.
    for script in [
        format!("cat '{}'", record.display()),
        format!("ls '{}'", dir.display()),
    ] {
        let outside = assert_ok!(Command::new("/bin/sh").args(["-c", &script]).output());
        assert!(
            outside.status.success(),
            "{script} fails outside the ball too"
        );
    }

    for (what, script) in [
        ("read the record", format!("cat '{}'", record.display())),
        ("list the store", format!("ls '{}'", dir.display())),
        (
            "overwrite the record",
            format!("echo x > '{}'", record.display()),
        ),
        (
            "add a record",
            format!("echo x > '{}/new.toml'", dir.display()),
        ),
        ("delete the record", format!("rm -f '{}'", record.display())),
        (
            "rename the store",
            format!("mv '{0}' '{0}.moved'", dir.display()),
        ),
        (
            "overwrite the config",
            format!("echo x > '{}'", config.display()),
        ),
        (
            "replace the config",
            format!("mv '{0}' '{0}.old'", config.display()),
        ),
    ] {
        let outcome = sh_in_hb(&w, &script);
        assert!(
            !hb_succeeds(&outcome),
            "the agent could {what}: {}",
            hb_text(&outcome)
        );
    }
    assert_eq!(assert_ok!(fs::read(&record)), before);
    assert_eq!(assert_ok!(fs::read(&config)), config_before);
    assert_eq!(records(&w), 1);
}

#[test]
fn a_yes_piped_into_hb_approve_is_not_an_approval_even_with_a_terminal_for_the_output() {
    sandboxed!();
    let w = World::new(PROJECT);
    let Some((text, exit)) = shell_at_a_terminal(&w, &format!("echo y | {DRIVE} approve")) else {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    };
    assert_eq!(exit, NOT_APPROVED, "{text}");
    assert!(text.contains("needs a terminal"), "{text}");
    assert!(!text.contains("Approve this config?"), "{text}");
    assert_eq!(records(&w), 0);
}

#[test]
fn a_terminal_for_input_alone_is_not_enough_when_the_questions_would_go_to_a_file() {
    sandboxed!();
    let w = World::new(PROJECT);
    let Some((text, exit)) = shell_at_a_terminal(&w, &format!("{DRIVE} approve 2>/dev/null"))
    else {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    };
    assert_eq!(exit, NOT_APPROVED, "{text}");
    assert_eq!(records(&w), 0);
}

#[test]
fn a_value_too_long_to_review_is_refused_before_any_question_and_a_yes_does_nothing() {
    sandboxed!();
    let long = "x".repeat(hamster_ball::approval::MAX_VALUE_CHARS + 1);
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\"]\n[env]\nset = {{ BIG = \"{long}\" }}\n"
    ));
    if !std::path::Path::new("/usr/bin/expect").exists() {
        return;
    }
    // At a terminal, `y` typed right away: if a question were put, this would approve.
    let exp = w.base.join("long.exp");
    let body = format!(
        "set env(HB_TD_HOME) {home}\nset env(HB_TD_CWD) {cwd}\nset env(HB_TD_PATH) {path}\nset env(HB_TD_TMP) {tmp}\n\
         set timeout 30\n{guard}spawn {drive} approve\nsend \"y\\r\"\n\
         expect eof\ncatch wait result\nputs \"EXIT=[lindex $result 3]\"\n",
        home = w.home_dir().display(),
        cwd = w.project.display(),
        path = w.base.join("bin").display(),
        tmp = w.base.join("tmp").display(),
        drive = DRIVE,
        guard = EXPECT_GUARD,
    );
    common::write(&exp, &body);
    let out = assert_ok!(Command::new("/usr/bin/expect").arg(&exp).output());
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert_no_expect_timeout(&text);
    assert!(text.contains("too long to review in full"), "{text}");
    assert!(!text.contains("Approve this config?"), "{text}");
    assert!(text.contains("EXIT=78"), "{text}");
    assert_eq!(records(&w), 0, "nothing may be stored");
}
