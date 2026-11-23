// ABOUTME: Signals and exit status of `hb run`, through the test-only hb-testdrive binary as a separate process.
// ABOUTME: SIGINT, SIGTERM and SIGHUP are forwarded and cleaned up after; a child's death by signal is re-raised (D60).
//! Black-box tests of signal supervision (hb-ghd.2.3b).

#![cfg(target_os = "macos")]

mod common;

use std::io::{BufRead, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

use claims::assert_ok;
use common::{EXPECT_GUARD, World, assert_no_expect_timeout, sandbox_available};
use nix::sys::signal::{Signal, kill, killpg};
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

/// Fails the test with `message` (a plain `assert!(false)` would trip a lint).
fn fail(message: String) {
    assert_ok!(Result::<(), String>::Err(message));
}

/// A running driver with its stdout lines arriving on a channel.
struct Driver {
    child: Child,
    lines: Receiver<String>,
    seen: Vec<String>,
}

impl Driver {
    fn start(w: &World, grace_ms: u64, script: &str) -> Self {
        Self::start_words(w, grace_ms, &["/bin/sh", "-c", script])
    }

    fn start_words(w: &World, grace_ms: u64, words: &[&str]) -> Self {
        let mut args = vec!["run", "--"];
        args.extend_from_slice(words);
        let mut cmd = w.drive(DRIVE, &args);
        cmd.env("HB_TD_GRACE_MS", grace_ms.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = assert_ok!(cmd.spawn());
        let stdout = child.stdout.take();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            if let Some(out) = stdout {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            }
        });
        Self {
            child,
            lines,
            seen: Vec::new(),
        }
    }

    fn pid(&self) -> Pid {
        Pid::from_raw(i32::try_from(self.child.id()).unwrap_or(0))
    }

    /// Waits for a line containing `needle`; fails the test after `secs`.
    fn wait_for(&mut self, needle: &str, secs: u64) -> String {
        let deadline = Instant::now() + Duration::from_secs(secs);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    self.seen.push(line.clone());
                    if line.contains(needle) {
                        return line;
                    }
                }
                Err(_) => {
                    let _ = self.child.kill();
                    fail(format!("no line with {needle:?}; saw {:?}", self.seen));
                    return String::new();
                }
            }
        }
    }

    /// Waits for the driver to end (killing it after `secs`) and returns how.
    fn finish(mut self, secs: u64) -> (std::process::ExitStatus, Vec<String>, Duration) {
        let start = Instant::now();
        let deadline = start + Duration::from_secs(secs);
        let status = loop {
            if let Some(status) = assert_ok!(self.child.try_wait()) {
                break status;
            }
            if Instant::now() > deadline {
                let _ = self.child.kill();
                fail(format!(
                    "the driver did not end in {secs}s; saw {:?}",
                    self.seen
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let took = start.elapsed();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_millis(200)) {
            self.seen.push(line);
        }
        (status, self.seen, took)
    }
}

/// A child that reports its session directory, says it is ready, and runs until told otherwise.
fn waiting_child(on_signal: &str) -> String {
    format!(
        "echo tmp=$TMPDIR; {on_signal}; echo ready; i=0; while [ $i -lt 300 ]; do sleep 0.1; i=$((i+1)); done; echo timed-out"
    )
}

/// A perl child that handles `name` by printing it and exiting 7. Perl sets the handler even when
/// the signal was ignored at start (as it is in a background job), which `sh` cannot do.
fn perl_catcher(name: &str) -> Vec<String> {
    let program = format!(
        "$|=1; $SIG{{{name}}}=sub{{print \"got-{name}\\n\"; exit 7}}; print \"tmp=$ENV{{TMPDIR}}\\nready\\n\"; sleep 1 for 1..300;"
    );
    vec!["/usr/bin/perl".to_owned(), "-e".to_owned(), program]
}

fn session_dir_of(lines: &[String]) -> std::path::PathBuf {
    let line = lines
        .iter()
        .find_map(|l| l.strip_prefix("tmp="))
        .unwrap_or_default();
    std::path::PathBuf::from(line)
}

// ====================================================================================
// Forwarding and cleanup
// ====================================================================================

#[test]
fn each_of_int_term_and_hup_sent_to_hb_reaches_the_child_and_the_session_dir_is_removed() {
    sandboxed!();
    for (signal, name) in [
        (Signal::SIGINT, "INT"),
        (Signal::SIGTERM, "TERM"),
        (Signal::SIGHUP, "HUP"),
    ] {
        let w = World::new(PROJECT);
        let words = perl_catcher(name);
        let refs: Vec<&str> = words.iter().map(String::as_str).collect();
        let mut d = Driver::start_words(&w, 5000, &refs);
        d.wait_for("ready", 20);
        assert_ok!(kill(d.pid(), signal));
        let (status, lines, _) = d.finish(20);
        assert!(
            lines.iter().any(|l| l == &format!("got-{name}")),
            "{name}: {lines:?}"
        );
        assert_eq!(
            status.code(),
            Some(7),
            "{name}: the child's own exit code comes back"
        );
        let dir = session_dir_of(&lines);
        assert!(
            dir.to_string_lossy().contains("/hb-") && !dir.exists(),
            "{name}: the session directory {dir:?} was left behind"
        );
    }
}

// ====================================================================================
// Escalation
// ====================================================================================

#[test]
fn a_child_that_ignores_term_is_killed_when_the_grace_runs_out() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut d = Driver::start(&w, 500, &waiting_child("trap '' TERM"));
    d.wait_for("ready", 20);
    assert_ok!(kill(d.pid(), Signal::SIGTERM));
    let (status, lines, took) = d.finish(20);
    assert!(
        took >= Duration::from_millis(400),
        "killed before the grace: {took:?}"
    );
    assert!(
        took < Duration::from_secs(8),
        "the kill came too late: {took:?}"
    );
    // The child died of SIGKILL, but the TERM sent to hb is still pending, and it ends hb the
    // moment the mask is lifted: hb dies of the signal its caller sent.
    assert_eq!(status.signal(), Some(15), "{lines:?}");
    assert!(
        !session_dir_of(&lines).exists(),
        "the session directory was left behind"
    );
}

#[test]
fn a_second_signal_kills_at_once_without_waiting_for_the_grace() {
    sandboxed!();
    let w = World::new(PROJECT);
    let mut d = Driver::start(&w, 30_000, &waiting_child("trap '' TERM"));
    d.wait_for("ready", 20);
    assert_ok!(kill(d.pid(), Signal::SIGTERM));
    std::thread::sleep(Duration::from_millis(400));
    assert_ok!(kill(d.pid(), Signal::SIGTERM));
    let (status, _, took) = d.finish(20);
    assert!(
        took < Duration::from_secs(5),
        "the second signal did not kill: {took:?}"
    );
    assert_eq!(
        status.signal(),
        Some(15),
        "the signal the caller sent ends hb"
    );
}

// ====================================================================================
// The child's signal mask
// ====================================================================================

/// Prints the blocked signals of the process running it, as numbers.
const BLOCKED_SET: &str = "use POSIX qw(:signal_h); my $none = POSIX::SigSet->new; my $old = POSIX::SigSet->new; \
     POSIX::sigprocmask(SIG_BLOCK, $none, $old); print join(',', grep { $old->ismember($_) } 1..31), \"\\n\";";

#[test]
fn the_probe_sees_a_blocked_set_when_there_is_one() {
    // Control: a child started the plain way from a thread that blocked the signals inherits them.
    let seen = std::thread::spawn(|| {
        let _ = hamster_ball::session::signals::block_supervised();
        Command::new("/usr/bin/perl")
            .args(["-e", BLOCKED_SET])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
            .unwrap_or_default()
    })
    .join()
    .unwrap_or_default();
    // INT, HUP and TERM for the supervisor, and WINCH for the window-size relay of a pty run.
    assert_eq!(
        seen, "1,2,15,28",
        "std's Command passes the parent's mask on"
    );
}

#[test]
fn the_child_under_hb_has_an_empty_blocked_set_although_hb_blocked_its_signals() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/usr/bin/perl", "-e", BLOCKED_SET])
            .output()
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "");
}

// ====================================================================================
// What the caller sees (D60)
// ====================================================================================

fn run_script(w: &World, script: &str) -> std::process::Output {
    assert_ok!(
        w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", script])
            .output()
    )
}

#[test]
fn a_child_killed_by_int_term_or_hup_makes_hb_die_of_that_signal_after_cleaning_up() {
    sandboxed!();
    for (n, name) in [(2, "INT"), (15, "TERM"), (1, "HUP")] {
        let w = World::new(PROJECT);
        let program = format!(
            "$SIG{{{name}}}='DEFAULT'; print \"tmp=$ENV{{TMPDIR}}\\n\"; $|=1; kill '{name}', $$; sleep 5;"
        );
        let out = assert_ok!(
            w.drive(DRIVE, &["run", "--", "/usr/bin/perl", "-e", &program])
                .output()
        );
        assert_eq!(out.status.signal(), Some(n), "{name}: {:?}", out.status);
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let dir = text
            .lines()
            .find_map(|l| l.strip_prefix("tmp="))
            .unwrap_or_default();
        assert!(
            !dir.is_empty() && !std::path::Path::new(dir).exists(),
            "{name}: {dir:?} was left"
        );
    }
}

#[test]
fn a_child_killed_by_any_other_signal_gives_128_plus_the_number_and_hb_exits_normally() {
    sandboxed!();
    let w = World::new(PROJECT);
    let out = run_script(&w, "kill -SEGV $$");
    assert_eq!(out.status.code(), Some(128 + 11), "{:?}", out.status);
    assert_eq!(out.status.signal(), None);
    let ok = run_script(&w, "exit 3");
    assert_eq!(ok.status.code(), Some(3));
}

#[test]
fn a_bash_loop_around_hb_stops_on_ctrl_c_which_an_exit_130_would_not() {
    sandboxed!();
    let w = World::new(PROJECT);
    let script = format!(
        "for i in 1 2 3; do {} run -- /bin/sh -c 'echo started; sleep 30'; echo after-$i; done; echo FINISHED",
        common::quote(std::path::Path::new(DRIVE))
    );
    let mut bash = Command::new("/bin/bash");
    bash.args(["-c", &script])
        .env_clear()
        .current_dir(&w.project)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    w.drive_env(&mut bash);
    let mut child = assert_ok!(bash.spawn());
    let pgid = Pid::from_raw(i32::try_from(child.id()).unwrap_or(0));
    let stdout = child.stdout.take();
    let (tx, lines) = channel();
    std::thread::spawn(move || {
        if let Some(out) = stdout {
            for line in BufReader::new(out).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        }
    });
    let first = assert_ok!(lines.recv_timeout(Duration::from_secs(20)));
    assert_eq!(first, "started");
    // What a terminal does on Ctrl-C: SIGINT to the whole foreground group, here bash and hb.
    assert_ok!(killpg(pgid, Signal::SIGINT));
    let status = assert_ok!(child.wait());
    let rest: Vec<String> = lines.try_iter().collect();
    assert!(
        !rest
            .iter()
            .any(|l| l.starts_with("after-") || l == "FINISHED"),
        "the loop went on after Ctrl-C: {rest:?}"
    );
    assert_eq!(
        status.signal(),
        Some(2),
        "bash itself dies of SIGINT, as a shell does: {status:?}"
    );
}

// ====================================================================================
// A terminal and no pty (`HB_TD_PTY=off`): the child shares hb's process group (decision 3)
// ====================================================================================

/// Runs `hb run` under `expect` so stdin is a real terminal, types one Ctrl-C, and returns the output.
fn on_a_terminal(w: &World, script_name: &str, child_script: &str, ctrl_c_after_ms: u32) -> String {
    let script = w.project.join(script_name);
    common::write(&script, child_script);
    let td = w.base.join("drive.exp");
    let body = format!(
        "set env(HB_TD_HOME) {home}\nset env(HB_TD_CWD) {cwd}\nset env(HB_TD_PATH) {path}\nset env(HB_TD_TMP) {tmp}\n\
         set env(HB_TD_GRACE_MS) 500\nset env(HB_TD_PTY) off\nset timeout 20\n{guard}\
         spawn {drive} run -- /usr/bin/perl {script}\n\
         sleep {delay}\nsend \"\\003\"\nexpect eof\n",
        home = w.home_dir().display(),
        cwd = w.project.display(),
        path = w.base.join("bin").display(),
        tmp = w.base.join("tmp").display(),
        drive = DRIVE,
        script = script.display(),
        delay = f64::from(ctrl_c_after_ms) / 1000.0,
        guard = EXPECT_GUARD,
    );
    common::write(&td, &body);
    let out = assert_ok!(Command::new("/usr/bin/expect").arg(&td).output());
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert_no_expect_timeout(&text);
    text
}

#[test]
fn one_ctrl_c_on_a_terminal_reaches_the_child_once_and_hb_does_not_kill_a_child_that_handles_it() {
    sandboxed!();
    if !std::path::Path::new("/usr/bin/expect").exists() {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    }
    let w = World::new(PROJECT);
    // The child counts SIGINTs, keeps going, and reports at the end. Longer than the grace period
    // (500 ms), so a kill clock started by hb would show up as a missing "finished" line.
    let child = "$|=1; my $n=0; $SIG{INT}=sub{ $n++; print \"int-$n\\n\" };\n\
                 print \"ready\\n\"; select(undef,undef,undef,0.1) for 1..30; print \"finished-$n\\n\";\n";
    let text = on_a_terminal(&w, "catch.pl", child, 1200);
    assert!(
        text.contains("int-1"),
        "the child never saw the Ctrl-C: {text}"
    );
    assert!(
        !text.contains("int-2"),
        "the child saw the Ctrl-C twice (forwarded as well): {text}"
    );
    assert!(
        text.contains("finished-1"),
        "hb killed a child that handled its own Ctrl-C: {text}"
    );
}

// ====================================================================================
// Descriptors on the supervised path
// ====================================================================================

#[test]
fn the_child_of_a_supervised_run_has_only_the_three_standard_descriptors() {
    sandboxed!();
    let w = World::new(PROJECT);
    let probe = "for my $n (3..40) { print \"$n\\n\" if open(my $fh, \"<&=$n\"); }";
    let out = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/usr/bin/perl", "-e", probe])
            .output()
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "",
        "descriptors leaked into the child: hb's own kqueue, a pipe, or one from the launcher"
    );
}

// ====================================================================================
// Supervised runs clean up after themselves
// ====================================================================================

const LEAK_MODE: &str = "HB_SIGNALS_LEAK_CHILD";

fn open_descriptors() -> usize {
    std::fs::read_dir("/dev/fd").map_or(0, |d| d.count())
}

/// Re-executed: does several supervised runs in a thread that blocked the signals, as the `hb`
/// binary does, and reports how many descriptors the process had before and after.
#[test]
fn supervised_runs_child() {
    if std::env::var_os(LEAK_MODE).is_none() {
        return;
    }
    let w = World::new(PROJECT);
    let mut env = w.env.clone();
    env.floor = env.floor.with_hb_exe(std::path::PathBuf::from(DRIVE));
    let loaded = w.loaded();
    let counts = std::thread::spawn(move || {
        let _ = hamster_ball::session::signals::block_supervised();
        let spec = hamster_ball::session::RunSpec::new(["/usr/bin/true"]).signals(
            hamster_ball::session::SignalMode::Forward {
                grace: Duration::from_secs(5),
            },
        );
        let before = open_descriptors();
        for _ in 0..4 {
            let _ = hamster_ball::session::run(&env, &loaded, &spec);
        }
        (before, open_descriptors())
    })
    .join()
    .unwrap_or((0, 0));
    println!("LEAKCOUNT:{}:{}", counts.0, counts.1);
}

#[test]
fn repeated_supervised_runs_leave_no_descriptor_behind() {
    sandboxed!();
    let exe = assert_ok!(std::env::current_exe());
    let out = assert_ok!(
        Command::new(exe)
            .args(["--exact", "supervised_runs_child", "--nocapture"])
            .env(LEAK_MODE, "1")
            .output()
    );
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let line = text
        .lines()
        .find_map(|l| l.strip_prefix("LEAKCOUNT:"))
        .unwrap_or("");
    let (before, after) = line.split_once(':').unwrap_or(("x", "y"));
    assert!(
        before.parse::<usize>().is_ok(),
        "the child did not report: {text}"
    );
    assert_eq!(before, after, "descriptors grew over four supervised runs");
}
