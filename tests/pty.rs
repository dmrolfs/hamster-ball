// ABOUTME: `hb run` on a terminal: the agent's own pty, the relay, resize, restore, suspend and keystroke injection.
// ABOUTME: Each case runs hb-testdrive under expect, so hb sees a real terminal; injection runs on sacrificial ptys only.
//! Black-box tests of terminal isolation (hb-ghd.2.4).

#![cfg(target_os = "macos")]

mod common;

use std::process::Command;

use claims::assert_ok;
use common::{EXPECT_GUARD, World, assert_no_expect_timeout, sandbox_available};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() || !std::path::Path::new("/usr/bin/expect").exists() {
            eprintln!("SKIP: no sandbox-exec or no expect");
            return;
        }
    };
}

/// Tcl that answers `CSI c` the way a terminal does, and lets the test carry on.
const ANSWER_DEVICE_ATTRIBUTES: &str =
    "expect_before -i any_spawn_id -re {\\x1b\\[c} {send -- \"\\033\\[?62;c\"; exp_continue}\n";

/// Quotes a word for Tcl.
fn tcl(word: &str) -> String {
    format!("{{{word}}}")
}

/// Runs `body` (Tcl) after setting up the world's variables, with `spawn` available as
/// `spawn_hb ARGS...`, and returns what expect printed.
fn expect(w: &World, extra_env: &[(&str, &str)], body: &str) -> String {
    expect_with(w, extra_env, true, body)
}

/// Like [`expect`]. With `answer_queries` false the script answers terminal queries itself.
fn expect_with(w: &World, extra_env: &[(&str, &str)], answer_queries: bool, body: &str) -> String {
    let mut script = format!(
        "set env(HB_TD_HOME) {home}\nset env(HB_TD_CWD) {cwd}\nset env(HB_TD_PATH) {path}\nset env(HB_TD_TMP) {tmp}\n\
         set env(HB_TD_GRACE_MS) 500\nset env(TERM) xterm-256color\nset timeout 20\nset stty_init {{rows 24 columns 80}}\n",
        home = tcl(&w.home_dir().to_string_lossy()),
        cwd = tcl(&w.project.to_string_lossy()),
        path = tcl(&w.base.join("bin").to_string_lossy()),
        tmp = tcl(&w.base.join("tmp").to_string_lossy()),
    );
    for (k, v) in extra_env {
        script.push_str(&format!("set env({k}) {}\n", tcl(v)));
    }
    script.push_str(EXPECT_GUARD);
    // A terminal answers a primary device attributes query. hb asks one before it gives the
    // terminal back, so a harness that stands in for the terminal has to answer it.
    if answer_queries {
        script.push_str(ANSWER_DEVICE_ATTRIBUTES);
    }
    script.push_str(&format!("set drive {}\n", tcl(DRIVE)));
    script.push_str(body);
    let file = w.base.join("case.exp");
    common::write(&file, &script);
    let out = assert_ok!(Command::new("/usr/bin/expect").arg(&file).output());
    let mut text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    assert_no_expect_timeout(&text);
    text
}

/// A perl program written into the project, so the sandboxed child can run it.
fn program(w: &World, name: &str, source: &str) -> String {
    let path = w.project.join(name);
    common::write(&path, source);
    path.to_string_lossy().into_owned()
}

// ====================================================================================
// The child's terminal
// ====================================================================================

#[test]
fn the_child_has_a_terminal_of_its_own_and_leads_its_own_session() {
    sandboxed!();
    let w = World::new(PROJECT);
    let prog = program(
        &w,
        "who.pl",
        "use POSIX; $|=1;\n\
         my @t = (-t STDIN ? 1:0, -t STDOUT ? 1:0, -t STDERR ? 1:0);\n\
         my $me = POSIX::ttyname(0) // 'unknown';\n\
         print \"tty=@t leader=\", (getpgrp() == $$ ? 1:0), \" fg=\", (POSIX::tcgetpgrp(0) == getpgrp() ? 1:0), \" term=$ENV{TERM}\\n\";\n\
         print \"childtty=$me\\n\";\n",
    );
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho $drive run -- /usr/bin/perl {}\nexpect eof\nputs \"\\nusertty=$spawn_out(slave,name)\"\n",
            tcl(&prog)
        ),
    );
    assert!(
        out.contains("tty=1 1 1 leader=1 fg=1 term=xterm-256color"),
        "{out}"
    );
    let user = out
        .lines()
        .find_map(|l| l.strip_prefix("usertty="))
        .unwrap_or("");
    let child = out
        .lines()
        .find_map(|l| l.strip_prefix("childtty="))
        .unwrap_or("");
    assert!(user.starts_with("/dev/ttys"), "{out}");
    assert!(
        child.is_empty() || child == "unknown" || child != user,
        "the child was given the user's own terminal: {out}"
    );
}

#[test]
fn the_child_sees_the_users_window_size_and_every_resize() {
    sandboxed!();
    let w = World::new(PROJECT);
    let prog = program(
        &w,
        "winch.pl",
        "$|=1; $SIG{INT}=sub{exit 0};\n\
         my $s=`/bin/stty size`; chomp $s; print \"start $s\\n\";\n\
         $SIG{WINCH}=sub{ my $s=`/bin/stty size`; chomp $s; print \"winch $s\\n\" };\n\
         print \"ready\\n\"; sleep 1 for 1..60;\n",
    );
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho $drive run -- /usr/bin/perl {}\nexpect \"ready\"\n\
             exec /bin/stty rows 33 columns 101 < $spawn_out(slave,name)\nexpect \"winch 33 101\"\n\
             exec /bin/stty rows 20 columns 70 < $spawn_out(slave,name)\nexpect \"winch 20 70\"\n\
             send \"\\003\"\nexpect eof\n",
            tcl(&prog)
        ),
    );
    assert!(
        out.contains("start 24 80"),
        "the initial size was not copied: {out}"
    );
    assert!(
        out.contains("winch 33 101") && out.contains("winch 20 70"),
        "{out}"
    );
}

#[test]
fn no_descriptor_above_two_reaches_the_child_and_that_includes_the_pty_master() {
    sandboxed!();
    let w = World::new(PROJECT);
    let prog = program(
        &w,
        "fds.pl",
        "$|=1; my @open = grep { open(my $fh, \"<&=$_\") } 3..40; print \"open=[@open]\\n\";\n",
    );
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho $drive run -- /usr/bin/perl {}\nexpect eof\n",
            tcl(&prog)
        ),
    );
    assert!(out.contains("open=[]"), "{out}");
}

#[test]
fn one_ctrl_c_typed_on_the_terminal_reaches_the_child_once_through_the_relay() {
    sandboxed!();
    let w = World::new(PROJECT);
    let prog = program(
        &w,
        "int.pl",
        "$|=1; my $n=0; $SIG{INT}=sub{ $n++; print \"int-$n\\n\" };\n\
         print \"ready\\n\"; select(undef,undef,undef,0.1) for 1..30; print \"finished-$n\\n\";\n",
    );
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho $drive run -- /usr/bin/perl {}\nexpect \"ready\"\nsleep 0.5\nsend \"\\003\"\nexpect eof\n",
            tcl(&prog)
        ),
    );
    assert!(out.contains("int-1") && !out.contains("int-2"), "{out}");
    assert!(
        out.contains("finished-1"),
        "hb killed a child that handled its own Ctrl-C: {out}"
    );
}

// ====================================================================================
// The user's terminal after the run
// ====================================================================================

/// Starts an interactive bash whose prompt carries the command number (`<2>PROMPT> `), so a wait
/// for "the next prompt" cannot be satisfied by an earlier one, then runs `body` and exits.
///
/// In `body`, `cmd LINE` runs a line and waits for the prompt after it; `next_prompt` only waits
/// (for a command already sent, or one that was stopped).
fn in_a_shell(w: &World, body: &str) -> String {
    let preamble = "spawn -noecho /bin/bash --norc --noprofile -i\nexpect {$ }\n\
                    send {PS1='<\\#>PROMPT> '}\nsend \"\\r\"\nset n 2\nexpect \"<2>PROMPT> \"\n\
                    proc next_prompt {} { global n; incr n; expect \"<$n>PROMPT> \" }\n\
                    proc cmd {line} { send \"$line\\r\"; next_prompt }\n";
    expect(
        w,
        &[],
        &format!("{preamble}{body}\nsend \"exit\\r\"\nexpect eof\n"),
    )
}

/// The Tcl that has the shell print the terminal's settings as one `STATE:` line. It must be a
/// command the shell runs: while bash waits at its prompt, readline itself puts the terminal in
/// raw mode, so reading the settings from outside would say nothing about `hb`.
const SHOW_STATE: &str = "cmd {stty -a | tr '\\n' ' ' | sed 's/^/STATE:/'; echo}";

/// Whether a `STATE:` line from `stty -a` describes a normal (cooked) terminal.
fn cooked(state: &str) -> bool {
    let words: Vec<&str> = state.split_whitespace().collect();
    ["icanon", "echo", "isig"]
        .iter()
        .all(|flag| words.contains(flag))
}

#[test]
fn the_terminal_is_cooked_again_after_a_normal_exit_a_child_sigkill_and_a_term_to_hb() {
    sandboxed!();
    let w = World::new(PROJECT);
    let killed = program(
        &w,
        "kill9.pl",
        "$|=1; print \"child up\\n\"; kill 9, $$; sleep 5;\n",
    );
    let waits = program(
        &w,
        "wait.pl",
        "$|=1; print \"hbpid=\", getppid(), \"\\nready\\n\"; sleep 1 for 1..60;\n",
    );
    let body = format!(
        "cmd \"$drive run -- /usr/bin/true\"\n{show}\n\
         cmd \"$drive run -- /usr/bin/perl {killed}\"\n{show}\n\
         send \"$drive run -- /usr/bin/perl {waits}\\r\"\nexpect -re {{hbpid=([0-9]+)}}\nset hbpid $expect_out(1,string)\nexpect \"ready\"\n\
         exec /bin/kill -TERM $hbpid\nnext_prompt\n{show}",
        show = SHOW_STATE,
    );
    let out = in_a_shell(&w, &body);
    let states: Vec<&str> = out
        .lines()
        .filter_map(|l| l.strip_prefix("STATE:"))
        .collect();
    assert_eq!(states.len(), 3, "{out}");
    for (i, state) in states.iter().enumerate() {
        assert!(
            cooked(state),
            "case {i}: the terminal was left raw: {state}"
        );
    }
}

#[test]
fn everything_the_child_wrote_before_it_exited_reaches_the_screen() {
    // A lot of output right before exit: if `hb` returned before the relay had drained the pty,
    // the tail would be lost.
    sandboxed!();
    let w = World::new(PROJECT);
    let prog = program(
        &w,
        "burst.pl",
        "$|=1; for my $i (1..4000) { printf \"line-%04d %s\\n\", $i, 'x' x 60 } print \"END-MARKER\\n\";\n",
    );
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho $drive run -- /usr/bin/perl {}\nexpect eof\n",
            tcl(&prog)
        ),
    );
    assert_eq!(out.matches("line-").count(), 4000, "lines were lost");
    assert!(out.contains("END-MARKER"), "the tail was lost");
}

// ====================================================================================
// Replies the user's terminal sends after the child's output
// ====================================================================================

/// Tcl that makes the spawned shell's terminal answer queries the way a terminal emulator does,
/// each `delay_ms` after it sees the query: a title report (`CSI 21 t`) is answered with
/// `payload` (what a "full echo-back" terminal types into the shell: CVE-2003-0063,
/// CVE-2022-45872, CVE-2024-56803; a cursor position report `CSI 6n` gets it too, standing in for
/// a terminal bug in a query the filter lets through) and a primary device attributes query (`CSI c`) the way every
/// terminal does. `serve_terminal PROMPT EXTRA_MS` then reads the screen until `PROMPT` and keeps
/// answering for `EXTRA_MS` after it, which is how long a late reply has to arrive.
fn emulator(payload: &str, delay_ms: u32) -> String {
    format!(
        r#"
proc reply {{id text}} {{ catch {{send -i $id -- $text}} }}
proc serve_terminal {{prompt extra_ms}} {{
    global spawn_id settled
    set id $spawn_id
    expect {{
        -re {{\x1b\[(21t|6n)}} {{ after {delay_ms} [list reply $id "{payload}\r"]; exp_continue }}
        -re {{\x1b\[c}} {{ after {delay_ms} [list reply $id "\033\[?62;c"]; exp_continue }}
        $prompt {{ }}
    }}
    after $extra_ms {{set settled 1}}
    vwait settled
    unset settled
}}
"#
    )
}

#[test]
fn a_reply_the_terminal_sends_after_the_agent_ended_is_never_typed_into_the_shell() {
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.base.join("typed-into-the-shell");
    // The agent sets a title it chose, asks the terminal to report it, and ends at once.
    let agent = program(
        &w,
        "echo.pl",
        "$|=1; print \"\\e]0;payload\\a\\e[21t\"; print \"agent-done\\n\";\n",
    );
    let body = format!(
        "{emulator}\n\
         spawn -noecho /bin/bash --norc --noprofile -i\n\
         expect {{$ }}\nsend {{PS1='<\\#>PROMPT> '}}\nsend \"\\r\"\nexpect \"<2>PROMPT> \"\n\
         send \"$drive run -- /usr/bin/perl {agent}\\r\"\n\
         serve_terminal \"<3>PROMPT> \" 1200\n\
         send \"\\r\"\nexpect -re {{<[0-9]+>PROMPT> }}\n\
         send \"printf 'VERDICT=%s\\\\n' \\$(test -e {marker} && echo typed || echo clean)\\r\"\n\
         expect -re {{VERDICT=(typed|clean)\\r}}\n\
         puts \"RESULT:$expect_out(1,string)\"\n\
         send \"exit\\r\"\nexpect eof\n",
        emulator = emulator(&format!("touch {}", marker.display()), 400),
        agent = agent,
        marker = marker.display(),
    );
    let out = expect_with(&w, &[], false, &body);
    assert!(
        out.contains("RESULT:clean"),
        "the terminal's late reply ran in the user's shell: {out}"
    );
    assert!(!marker.exists());
}

#[test]
fn a_late_reply_to_a_query_the_filter_lets_through_is_swallowed_too() {
    // Defence in depth: the filter removes the queries whose answers an agent can shape, but a
    // terminal bug in any other query would be the same attack. The reply is caught at the end.
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.base.join("typed-into-the-shell");
    let agent = program(
        &w,
        "position.pl",
        "$|=1; print \"\\e[6n\"; print \"agent-done\\n\";\n",
    );
    let body = format!(
        "{emulator}\n\
         spawn -noecho /bin/bash --norc --noprofile -i\n\
         expect {{$ }}\nsend {{PS1='<\\#>PROMPT> '}}\nsend \"\\r\"\nexpect \"<2>PROMPT> \"\n\
         send \"$drive run -- /usr/bin/perl {agent}\\r\"\n\
         serve_terminal \"<3>PROMPT> \" 1200\n\
         send \"\\r\"\nexpect -re {{<[0-9]+>PROMPT> }}\n\
         send \"printf 'VERDICT=%s\\\\n' \\$(test -e {marker} && echo typed || echo clean)\\r\"\n\
         expect -re {{VERDICT=(typed|clean)\\r}}\n\
         puts \"RESULT:$expect_out(1,string)\"\n\
         send \"exit\\r\"\nexpect eof\n",
        emulator = emulator(&format!("touch {}", marker.display()), 400),
        agent = agent,
        marker = marker.display(),
    );
    let out = expect_with(&w, &[], false, &body);
    assert!(
        out.contains("RESULT:clean"),
        "a late reply to an ordinary query ran in the user's shell: {out}"
    );
    assert!(!marker.exists());
}

#[test]
fn the_emulator_does_type_a_late_reply_into_a_shell_that_nothing_protects() {
    // The control for the test above: with the agent run straight in the shell, the reply is typed.
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.base.join("typed-into-the-shell");
    let agent = program(
        &w,
        "echo.pl",
        "$|=1; print \"\\e]0;payload\\a\\e[21t\"; print \"agent-done\\n\";\n",
    );
    let body = format!(
        "{emulator}\n\
         spawn -noecho /bin/bash --norc --noprofile -i\n\
         expect {{$ }}\nsend {{PS1='<\\#>PROMPT> '}}\nsend \"\\r\"\nexpect \"<2>PROMPT> \"\n\
         send \"/usr/bin/perl {agent}\\r\"\n\
         serve_terminal \"<3>PROMPT> \" 1200\n\
         send \"\\r\"\nexpect -re {{<[0-9]+>PROMPT> }}\n\
         send \"printf 'VERDICT=%s\\\\n' \\$(test -e {marker} && echo typed || echo clean)\\r\"\n\
         expect -re {{VERDICT=(typed|clean)\\r}}\n\
         puts \"RESULT:$expect_out(1,string)\"\n\
         send \"exit\\r\"\nexpect eof\n",
        emulator = emulator(&format!("touch {}", marker.display()), 400),
        agent = agent,
        marker = marker.display(),
    );
    let out = expect_with(&w, &[], false, &body);
    assert!(
        out.contains("RESULT:typed"),
        "the emulator did not deliver the reply, so the test above proves nothing: {out}"
    );
}

// ====================================================================================
// No pty: stdin is a file but the output goes to a terminal
// ====================================================================================

#[test]
fn a_late_reply_is_never_typed_into_the_shell_when_the_run_has_no_pty() {
    // The agent's stdin is a file, so hb gives it no pty, and its output used to go straight to the
    // user's terminal with nothing between. The same emulator as above shows the reply typed.
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.base.join("typed-into-the-shell");
    let agent = program(
        &w,
        "echo.pl",
        "$|=1; print \"\\e]0;payload\\a\\e[21t\"; print \"agent-done\\n\";\n",
    );
    let body = format!(
        "{emulator}\n\
         spawn -noecho /bin/bash --norc --noprofile -i\n\
         expect {{$ }}\nsend {{PS1='<\\#>PROMPT> '}}\nsend \"\\r\"\nexpect \"<2>PROMPT> \"\n\
         send \"$drive run -- /usr/bin/perl {agent} < /dev/null\\r\"\n\
         serve_terminal \"<3>PROMPT> \" 1200\n\
         send \"\\r\"\nexpect -re {{<[0-9]+>PROMPT> }}\n\
         send \"printf 'VERDICT=%s\\\\n' \\$(test -e {marker} && echo typed || echo clean)\\r\"\n\
         expect -re {{VERDICT=(typed|clean)\\r}}\n\
         puts \"RESULT:$expect_out(1,string)\"\n\
         send \"exit\\r\"\nexpect eof\n",
        emulator = emulator(&format!("touch {}", marker.display()), 400),
        agent = agent,
        marker = marker.display(),
    );
    let out = expect_with(&w, &[], false, &body);
    assert!(
        out.contains("RESULT:clean"),
        "a reply to a query from an agent with no pty ran in the user's shell: {out}"
    );
    assert!(!marker.exists());
}

#[test]
fn with_no_pty_a_late_reply_to_an_ordinary_query_and_a_mode_left_on_do_not_reach_the_shell() {
    // The filter lets cursor-position queries and mouse-mode requests through. A buggy terminal's
    // reply to one, or a mouse mode left on, would be typed into the shell once hb is gone.
    sandboxed!();
    let w = World::new(PROJECT);
    let marker = w.base.join("typed-into-the-shell");
    let agent = program(
        &w,
        "position.pl",
        "$|=1; print \"\\e[6n\\e[?1000h\\e[?1004h\"; print \"agent-done\\n\";\n",
    );
    let body = format!(
        "{emulator}\n\
         spawn -noecho /bin/bash --norc --noprofile -i\n\
         expect {{$ }}\nsend {{PS1='<\\#>PROMPT> '}}\nsend \"\\r\"\nexpect \"<2>PROMPT> \"\n\
         send \"$drive run -- /usr/bin/perl {agent} < /dev/null\\r\"\n\
         serve_terminal \"<3>PROMPT> \" 1200\n\
         send \"\\r\"\nexpect -re {{<[0-9]+>PROMPT> }}\n\
         send \"printf 'VERDICT=%s\\\\n' \\$(test -e {marker} && echo typed || echo clean)\\r\"\n\
         expect -re {{VERDICT=(typed|clean)\\r}}\n\
         puts \"RESULT:$expect_out(1,string)\"\n\
         send \"exit\\r\"\nexpect eof\n",
        emulator = emulator(&format!("touch {}", marker.display()), 400),
        agent = agent,
        marker = marker.display(),
    );
    let out = expect_with(&w, &[], false, &body);
    assert!(
        out.contains("RESULT:clean"),
        "a late reply with no pty ran in the user's shell: {out}"
    );
    assert!(!marker.exists());
    for mode in ["\u{1b}[?1000l", "\u{1b}[?1004l"] {
        assert!(out.contains(mode), "{mode:?} was not switched off: {out}");
    }
}

#[test]
fn with_no_pty_the_agents_output_is_a_pipe_but_arrives_unchanged() {
    sandboxed!();
    let w = World::new(PROJECT);
    let agent = program(
        &w,
        "streams.pl",
        "$|=1; print \"stdout-tty=\", (-t STDOUT ? 1 : 0), \" stdin-tty=\", (-t STDIN ? 1 : 0), \"\\n\";\n\
         print STDERR \"to-stderr \\e[31mred\\e[0m\\n\"; print \"after \\x{4e16}\\n\";\n",
    );
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho /bin/sh -c \"$drive run -- /usr/bin/perl {agent} < /dev/null\"\nexpect eof\n"
        ),
    );
    assert!(out.contains("stdout-tty=0 stdin-tty=0"), "{out}");
    assert!(out.contains("to-stderr \u{1b}[31mred\u{1b}[0m"), "{out}");
    assert!(out.contains("after \u{4e16}"), "{out}");
}

// ====================================================================================
// The clipboard notice
// ====================================================================================

fn clipboard_agent(w: &World) -> String {
    program(
        w,
        "clip.pl",
        "$|=1; print \"\\e]52;c;aGVsbG8=\\a\"; print \"\\e]52;c;?\\a\"; print \"\\e]52;p;d29ybGQ=\\a\"; print \"copied\\n\";\n",
    )
}

#[test]
fn a_run_on_a_pty_says_how_many_times_the_agent_set_the_clipboard() {
    sandboxed!();
    let w = World::new(PROJECT);
    let agent = clipboard_agent(&w);
    let out = expect(
        &w,
        &[],
        &format!("spawn -noecho $drive run -- /usr/bin/perl {agent}\nexpect eof\n"),
    );
    assert!(
        out.contains("warning: the agent set your clipboard 2 times"),
        "{out}"
    );
}

#[test]
fn a_run_with_no_pty_says_it_too_and_says_nothing_when_the_clipboard_was_not_touched() {
    sandboxed!();
    let w = World::new(PROJECT);
    let agent = clipboard_agent(&w);
    let quiet = program(&w, "quiet.pl", "print \"nothing to see\\n\";\n");
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho /bin/sh -c \"$drive run -- /usr/bin/perl {agent} < /dev/null\"\nexpect eof\n"
        ),
    );
    assert!(
        out.contains("warning: the agent set your clipboard 2 times"),
        "{out}"
    );
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho /bin/sh -c \"$drive run -- /usr/bin/perl {quiet} < /dev/null\"\nexpect eof\n"
        ),
    );
    assert!(out.contains("nothing to see"), "{out}");
    assert!(!out.contains("clipboard"), "{out}");
}

const REFUSED: &str = "warning: the agent tried to set your clipboard 2 times; terminal.clipboard_write = false stopped it";

#[test]
fn with_clipboard_writes_denied_a_run_on_a_pty_removes_them_and_says_so() {
    sandboxed!();
    let w = World::new(&format!("{PROJECT}[terminal]\nclipboard_write = false\n"));
    let agent = clipboard_agent(&w);
    let out = expect(
        &w,
        &[],
        &format!("spawn -noecho $drive run -- /usr/bin/perl {agent}\nexpect eof\n"),
    );
    assert!(out.contains("copied"), "{out}");
    assert!(
        !out.contains("\u{1b}]52;"),
        "an OSC 52 reached the terminal: {out:?}"
    );
    assert!(out.contains(REFUSED), "{out}");
    assert!(!out.contains("the agent set your clipboard"), "{out}");
}

#[test]
fn with_clipboard_writes_denied_a_run_with_no_pty_does_the_same() {
    sandboxed!();
    let w = World::new(&format!("{PROJECT}[terminal]\nclipboard_write = false\n"));
    let agent = clipboard_agent(&w);
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho /bin/sh -c \"$drive run -- /usr/bin/perl {agent} < /dev/null\"\nexpect eof\n"
        ),
    );
    assert!(out.contains("copied"), "{out}");
    assert!(
        !out.contains("\u{1b}]52;"),
        "an OSC 52 reached the terminal: {out:?}"
    );
    assert!(out.contains(REFUSED), "{out}");
}

#[test]
fn a_project_cannot_turn_clipboard_writes_back_on_after_the_users_base_denied_them() {
    sandboxed!();
    let w = World::with_base(
        "[terminal]\nclipboard_write = false\n",
        &format!("{PROJECT}[terminal]\nclipboard_write = true\n"),
    );
    let agent = clipboard_agent(&w);
    let out = expect(
        &w,
        &[],
        &format!("spawn -noecho $drive run -- /usr/bin/perl {agent}\nexpect eof\n"),
    );
    assert!(!out.contains("\u{1b}]52;"), "{out:?}");
    assert!(out.contains(REFUSED), "{out}");
}

#[test]
fn a_single_clipboard_write_is_reported_in_the_singular() {
    sandboxed!();
    let w = World::new(PROJECT);
    let agent = program(&w, "one.pl", "print \"\\e]52;c;aGk=\\a\";\n");
    let out = expect(
        &w,
        &[],
        &format!("spawn -noecho $drive run -- /usr/bin/perl {agent}\nexpect eof\n"),
    );
    assert!(
        out.contains("warning: the agent set your clipboard 1 time\n")
            || out.contains("warning: the agent set your clipboard 1 time\r"),
        "{out}"
    );
}

/// The Tcl that starts `hb` under `shell`, kills it with SIGKILL, and waits a moment.
fn kill_hb_in_a_shell(w: &World, shell_command: &str, prompt_pattern: &str, tail: &str) -> String {
    let waits = program(
        w,
        "wait.pl",
        "$|=1; print \"hbpid=\", getppid(), \"\\nready\\n\"; sleep 1 for 1..60;\n",
    );
    let body = format!(
        "spawn -noecho {shell_command}\nexpect -re {{{prompt_pattern}}}\nsend \"PS1='PROMPT> '\\r\"\nexpect \"PROMPT> \"\n\
         send \"$drive run -- /usr/bin/perl {waits}\\r\"\nexpect -re {{hbpid=([0-9]+)}}\nset hbpid $expect_out(1,string)\nexpect \"ready\"\n\
         exec /bin/kill -9 $hbpid\nexpect \"PROMPT> \"\n{tail}\nsend \"exit\\r\"\nexpect eof\n"
    );
    expect(w, &[], &body)
}

#[test]
fn a_sigkilled_hb_that_left_a_zsh_terminal_raw_says_so_and_names_reset() {
    // zsh adopts the raw settings of a job that was killed, and no repair from outside survives
    // that, so the guard cannot fix the terminal. It can say what happened.
    sandboxed!();
    if !std::path::Path::new("/bin/zsh").exists() {
        eprintln!("SKIP: no zsh");
        return;
    }
    let w = World::new(PROJECT);
    let out = kill_hb_in_a_shell(
        &w,
        "/bin/zsh -f -i",
        "[%#] ",
        "expect -re {type: reset\\]}\nputs \"\\nHINT-SEEN\"",
    );
    assert!(out.contains("HINT-SEEN"), "{out}");
    assert!(
        out.contains("hb was killed while it held your terminal in raw mode"),
        "{out}"
    );
}

#[test]
fn a_sigkilled_hb_under_bash_prints_no_hint_because_bash_puts_the_terminal_back() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = kill_hb_in_a_shell(
        &w,
        "/bin/bash --norc --noprofile -i",
        "[$] ",
        "sleep 1.5\nsend \"echo AFTER-THE-WAIT\\r\"\nexpect -re {AFTER-THE-WAIT\\r}",
    );
    assert!(out.contains("AFTER-THE-WAIT"), "{out}");
    assert!(
        !out.contains("hb was killed"),
        "a hint was printed for a cooked terminal: {out}"
    );
}

// ====================================================================================
// Ctrl-Z
// ====================================================================================

#[test]
fn ctrl_z_in_an_agent_that_stops_itself_suspends_the_job_and_fg_resumes_it() {
    sandboxed!();
    let w = World::new(PROJECT);
    let tui = program(
        &w,
        "tui.pl",
        "$|=1; $SIG{TSTP}=sub{ print \"got-TSTP\\n\"; kill 'STOP', $$ };\n\
         $SIG{CONT}=sub{ print \"got-CONT\\n\" };\n\
         print \"ready\\n\"; for my $i (1..40) { select(undef,undef,undef,0.25); print \"tick-$i\\n\" if $i % 10 == 0 } print \"tui-finished\\n\";\n",
    );
    let body = format!(
        "send \"$drive run -- /usr/bin/perl {tui}\\r\"\nexpect \"ready\"\nsleep 0.6\nsend \"\\032\"\nexpect \"Stopped\"\nnext_prompt\n{show}\n\
         send \"fg\\r\"\nexpect \"tui-finished\"\nnext_prompt",
        show = SHOW_STATE,
    );
    let out = in_a_shell(&w, &body);
    assert!(
        out.contains("got-TSTP"),
        "the agent never saw Ctrl-Z: {out}"
    );
    assert!(
        out.contains("Stopped"),
        "the shell did not show a suspended job: {out}"
    );
    assert!(
        out.contains("got-CONT") && out.contains("tui-finished"),
        "the agent did not continue after fg: {out}"
    );
    let states: Vec<&str> = out
        .lines()
        .filter_map(|l| l.strip_prefix("STATE:"))
        .collect();
    // While suspended the shell has the terminal and it is cooked. (That it is cooked again after
    // the run ends is the restore test above.)
    assert_eq!(states.len(), 1, "{out}");
    assert!(
        cooked(states[0]),
        "the terminal stayed raw while hb was suspended: {states:?}"
    );
}

#[test]
fn fg_typed_the_instant_the_prompt_appears_still_resumes_the_agent() {
    // Regression: input typed right after the prompt was flushed away under the relay's pending
    // read, which then blocked and left the child unable to finish its output.
    sandboxed!();
    let w = World::new(PROJECT);
    let tui = program(
        &w,
        "tui.pl",
        "$|=1; $SIG{TSTP}=sub{ print \"got-TSTP\\n\"; kill 'STOP', $$ };\n\
         $SIG{CONT}=sub{ print \"got-CONT\\n\" };\n\
         print \"ready\\n\"; for my $i (1..12) { select(undef,undef,undef,0.25); print \"tick-$i\\n\" } print \"tui-finished\\n\";\n",
    );
    let round =
        "send \"\\032\"\nexpect \"Stopped\"\nnext_prompt\nsend \"fg\\r\"\nexpect \"got-CONT\"\n";
    let body = format!(
        "send \"$drive run -- /usr/bin/perl {tui}\\r\"\nexpect \"ready\"\nsleep 0.6\n{round}{round}{round}expect \"tui-finished\"\nnext_prompt",
    );
    let out = in_a_shell(&w, &body);
    assert_eq!(out.matches("got-CONT").count(), 3, "{out}");
    assert!(out.contains("tui-finished"), "{out}");
}

// ====================================================================================
// Keystroke injection (TIOCSTI)
// ====================================================================================

/// Tries to push a byte into the terminal's input queue three ways: through descriptor 0, through
/// the terminal's own path, and through `/dev/tty`. Prints one line for each. The ioctl number is
/// the macOS value of `TIOCSTI`.
///
/// The path is built from the device number of descriptor 0 (`/dev/ttysNNN`), because `ttyname`
/// needs to read `/dev`, which a sandbox may not allow. A last line says how many *other*
/// terminals the program can open. It only opens them; it never injects into them, so running
/// the control on a developer's machine cannot type into their other windows.
const INJECT_PROBE: &str = "use strict; use warnings;\n\
    $| = 1;\n\
    my $TIOCSTI = 0x80017472;\n\
    sub inject { my ($fh) = @_; my $c = 'Z'; return ioctl($fh, $TIOCSTI, $c) ? 'injected' : \"refused($!)\"; }\n\
    my $rdev = (stat(STDIN))[6];\n\
    my $own = sprintf('/dev/ttys%03d', $rdev & 0xffffff);\n\
    print \"own=$own\\n\";\n\
    print 'fd0=', inject(\\*STDIN), \"\\n\";\n\
    if (open(my $p, '+<', $own)) { print 'path=', inject($p), \"\\n\"; } else { print \"path=open-refused($!)\\n\"; }\n\
    if (open(my $d, '+<', '/dev/tty')) { print 'devtty=', inject($d), \"\\n\"; } else { print \"devtty=open-refused($!)\\n\"; }\n\
    my $others = 0;\n\
    for my $t (glob('/dev/ttys[0-9]*')) { next if $t eq $own; if (open(my $o, '+<', $t)) { $others++; close $o; } }\n\
    print \"others-openable=$others\\n\";\n\
    print \"probe-done\\n\";\n";

/// The three result lines of the probe, as `(name, result)`.
fn probe_results(out: &str) -> Vec<(String, String)> {
    ["fd0", "path", "devtty"]
        .iter()
        .map(|name| {
            let line = out
                .lines()
                .find_map(|l| l.find(&format!("{name}=")).map(|i| &l[i..]))
                .unwrap_or("missing");
            ((*name).to_owned(), line.trim().to_owned())
        })
        .collect()
}

#[test]
fn the_probe_injects_on_a_pty_when_nothing_stops_it() {
    // The control: without it, a "refused" below could mean the probe is broken.
    sandboxed!();
    let w = World::new(PROJECT);
    let probe = program(&w, "inject.pl", INJECT_PROBE);
    let out = expect(
        &w,
        &[],
        &format!("spawn -noecho /usr/bin/perl {}\nexpect eof\n", tcl(&probe)),
    );
    for (name, result) in probe_results(&out) {
        assert_eq!(result, format!("{name}=injected"), "{out}");
    }
}

#[test]
fn a_profile_without_hid_control_still_allows_injection_and_one_that_denies_it_does_not() {
    // The probe tells the two apart, and the permission that matters is `hid-control`.
    sandboxed!();
    let w = World::new(PROJECT);
    let probe = program(&w, "inject.pl", INJECT_PROBE);
    for (profile, expected) in [
        ("(version 1)(allow default)", "injected"),
        (
            "(version 1)(allow default)(deny hid-control)",
            "refused(Operation not permitted)",
        ),
    ] {
        let out = expect(
            &w,
            &[],
            &format!(
                "spawn -noecho /usr/bin/sandbox-exec -p {} /usr/bin/perl {}\nexpect eof\n",
                tcl(profile),
                tcl(&probe)
            ),
        );
        for (name, result) in probe_results(&out) {
            assert_eq!(result, format!("{name}={expected}"), "{profile}: {out}");
        }
    }
}

#[test]
fn an_agent_under_hb_cannot_inject_keystrokes_through_any_route_to_its_terminal() {
    sandboxed!();
    let w = World::new(PROJECT);
    let probe = program(&w, "inject.pl", INJECT_PROBE);
    let out = expect(
        &w,
        &[],
        &format!(
            "spawn -noecho $drive run -- /usr/bin/perl {}\nexpect eof\n",
            tcl(&probe)
        ),
    );
    assert!(out.contains("probe-done"), "the probe did not run: {out}");
    // The path route must have been tried against a real terminal path, not a name that does not
    // exist, or "refused" would prove nothing.
    assert!(out.contains("own=/dev/ttys"), "{out}");
    for (name, result) in probe_results(&out) {
        assert!(
            result.starts_with(&format!("{name}=refused"))
                || result.starts_with(&format!("{name}=open-refused(Operation not permitted")),
            "{name} was not refused: {result}\n{out}"
        );
    }
    assert!(
        out.contains("others-openable=0"),
        "the agent could open other terminals: {out}"
    );
}
