// ABOUTME: The cleanup guard: it ends what hb started when hb is killed, and leaves everything alone when hb finishes.
// ABOUTME: Part one drives `hb __guard` by hand; part two kills a real `hb run` with SIGKILL and looks at what survives.
//! Black-box tests of the `hb __guard` process (design D66).

#![cfg(target_os = "macos")]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use claims::assert_ok;
use common::{EXPECT_GUARD, World, assert_no_expect_timeout, sandbox_available};
use hamster_ball::session::Guardian;
use hamster_ball::session::signals::Target;
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;

const HB: &str = env!("CARGO_BIN_EXE_hb");
const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            eprintln!("SKIP: no sandbox-exec");
            return;
        }
    };
}

/// Whether the process exists. A process that belongs to someone else (`init`) answers EPERM.
fn alive(pid: i32) -> bool {
    !matches!(
        kill(Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH)
    )
}

/// Waits up to `limit` for `done` to be true.
fn within(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(20));
    }
    done()
}

// ====================================================================================
// The guard by hand
// ====================================================================================

fn guard(grace_ms: u64) -> Child {
    assert_ok!(
        Command::new(HB)
            .args(["__guard", "--grace-ms", &grace_ms.to_string()])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    )
}

fn tell(guard: &mut Child, text: &str) {
    let stdin = guard.stdin.as_mut();
    assert!(stdin.is_some(), "the guard has no stdin");
    if let Some(stdin) = stdin {
        assert_ok!(stdin.write_all(text.as_bytes()));
        assert_ok!(stdin.flush());
    }
}

fn sleeper(script: &str) -> Child {
    assert_ok!(
        Command::new("/usr/bin/perl")
            .args(["-e", script])
            .stdout(Stdio::piped())
            .spawn()
    )
}

/// A child that prints `up` once it is running, so a test knows it has started.
fn started(script: &str) -> Child {
    let mut child = sleeper(&format!("$|=1; print \"up\\n\"; {script}"));
    let stdout = child.stdout.take();
    assert!(stdout.is_some());
    if let Some(stdout) = stdout {
        let mut line = String::new();
        assert_ok!(BufReader::new(stdout).read_line(&mut line));
        assert_eq!(line.trim(), "up");
    }
    child
}

fn pid_of(child: &Child) -> i32 {
    i32::try_from(child.id()).unwrap_or(i32::MAX)
}

/// Waits for the guard to see the registration, which is read before the end of input.
fn let_it_read() {
    thread::sleep(Duration::from_millis(300));
}

#[test]
fn when_hb_goes_away_a_registered_process_is_terminated() {
    let mut victim = started("sleep 1 for 1..60;");
    let mut guard = guard(500);
    tell(&mut guard, &format!("watch process {}\n", pid_of(&victim)));
    let_it_read();
    drop(guard.stdin.take());
    let status = assert_ok!(victim.wait());
    assert_eq!(status.signal(), Some(Signal::SIGTERM as i32), "{status:?}");
    assert!(assert_ok!(guard.wait()).success());
}

#[test]
fn a_release_leaves_the_registered_process_running_and_the_guard_gone() {
    let mut victim = started("sleep 1 for 1..60;");
    let mut guard = guard(500);
    tell(
        &mut guard,
        &format!("watch process {}\nrelease\n", pid_of(&victim)),
    );
    let status = assert_ok!(guard.wait());
    assert!(status.success(), "{status:?}");
    thread::sleep(Duration::from_millis(600));
    assert!(
        assert_ok!(victim.try_wait()).is_none(),
        "the process was ended although hb released the guard"
    );
    let _ = victim.kill();
    let _ = victim.wait();
}

#[test]
fn a_process_that_ignores_term_is_killed_when_the_grace_runs_out_and_not_before() {
    let mut victim = started("$SIG{TERM}='IGNORE'; sleep 1 for 1..60;");
    let mut guard = guard(1200);
    tell(&mut guard, &format!("watch process {}\n", pid_of(&victim)));
    let_it_read();
    let closed = Instant::now();
    drop(guard.stdin.take());
    thread::sleep(Duration::from_millis(600));
    assert!(
        assert_ok!(victim.try_wait()).is_none(),
        "killed before the grace period was over"
    );
    let status = assert_ok!(victim.wait());
    assert_eq!(status.signal(), Some(Signal::SIGKILL as i32), "{status:?}");
    assert!(closed.elapsed() >= Duration::from_millis(1200));
    assert!(closed.elapsed() < Duration::from_secs(4));
    assert!(assert_ok!(guard.wait()).success());
}

#[test]
fn a_process_that_ended_by_itself_is_forgotten_so_the_guard_does_not_wait_for_it() {
    // If the guard kept the number of a process that had ended, it would wait out the whole grace
    // period for it. (It would also signal whatever the number had been given to since.)
    let mut victim = started("select(undef,undef,undef,0.3);");
    let mut guard = guard(5000);
    tell(&mut guard, &format!("watch process {}\n", pid_of(&victim)));
    assert_ok!(victim.wait());
    let_it_read();
    let closed = Instant::now();
    drop(guard.stdin.take());
    let status = assert_ok!(guard.wait());
    assert!(status.success());
    assert!(
        closed.elapsed() < Duration::from_secs(2),
        "the guard waited {:?} for a process that was gone",
        closed.elapsed()
    );
}

#[test]
fn a_process_that_was_gone_before_it_was_registered_is_not_an_error() {
    let mut victim = started("");
    let gone = pid_of(&victim);
    assert_ok!(victim.wait());
    let mut guard = guard(500);
    tell(&mut guard, &format!("watch process {gone}\n"));
    let_it_read();
    drop(guard.stdin.take());
    assert!(assert_ok!(guard.wait()).success());
}

#[test]
fn a_group_is_ended_with_everything_in_it() {
    let mut leader = assert_ok!(
        Command::new("/bin/sh")
            .args(["-c", "sleep 60 & echo $!; wait"])
            .process_group(0)
            .stdout(Stdio::piped())
            .spawn()
    );
    let stdout = leader.stdout.take();
    assert!(stdout.is_some());
    let mut grandchild = String::new();
    if let Some(stdout) = stdout {
        assert_ok!(BufReader::new(stdout).read_line(&mut grandchild));
    }
    let grandchild: i32 = assert_ok!(grandchild.trim().parse());
    assert!(alive(grandchild));
    let mut guard = guard(500);
    tell(&mut guard, &format!("watch group {}\n", pid_of(&leader)));
    let_it_read();
    drop(guard.stdin.take());
    assert_ok!(leader.wait());
    assert!(
        within(Duration::from_secs(3), || !alive(grandchild)),
        "the group's other member was left running"
    );
    assert!(assert_ok!(guard.wait()).success());
}

#[test]
fn lines_the_guard_does_not_accept_are_skipped_and_the_next_line_still_counts() {
    let mut victim = started("sleep 1 for 1..60;");
    let mut guard = guard(500);
    tell(
        &mut guard,
        &format!(
            "garbage\nwatch process 1\nwatch group 0\nwatch group -1\nwatch process {}\n",
            pid_of(&victim)
        ),
    );
    let_it_read();
    drop(guard.stdin.take());
    assert_ok!(victim.wait());
    assert!(assert_ok!(guard.wait()).success());
    assert!(alive(1), "init is still there");
}

#[test]
fn the_guard_leads_a_group_of_its_own_so_a_terminal_signal_cannot_reach_it() {
    let mut guard = guard(500);
    let pid = Pid::from_raw(pid_of(&guard));
    // It has to start up and call setsid first.
    assert!(
        within(Duration::from_secs(5), || nix::unistd::getpgid(Some(pid))
            == Ok(pid)),
        "the guard never became the leader of its own group"
    );
    assert_ne!(assert_ok!(nix::unistd::getpgid(None)), pid);
    tell(&mut guard, "release\n");
    assert_ok!(guard.wait());
}

// ====================================================================================
// The Rust API hb itself uses
// ====================================================================================

#[test]
fn releasing_the_guardian_leaves_what_it_watched_alone_and_ends_the_guard() {
    let mut victim = started("sleep 1 for 1..60;");
    let mut guardian = assert_ok!(Guardian::start_with(
        std::path::Path::new(HB),
        Duration::from_millis(500)
    ));
    let guard_pid = i32::try_from(guardian.pid()).unwrap_or(i32::MAX);
    assert_ok!(guardian.watch(Target::Child(Pid::from_raw(pid_of(&victim)))));
    let started = Instant::now();
    guardian.release();
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "release took {:?}",
        started.elapsed()
    );
    assert!(
        within(Duration::from_secs(3), || !alive(guard_pid)),
        "the guard outlived its release"
    );
    thread::sleep(Duration::from_millis(700));
    assert!(
        assert_ok!(victim.try_wait()).is_none(),
        "release did not keep the guard from ending the process"
    );
    let _ = victim.kill();
    let _ = victim.wait();
}

#[test]
fn dropping_the_guardian_without_a_release_ends_what_it_watched() {
    let mut victim = started("sleep 1 for 1..60;");
    let mut guardian = assert_ok!(Guardian::start_with(
        std::path::Path::new(HB),
        Duration::from_millis(500)
    ));
    assert_ok!(guardian.watch(Target::Child(Pid::from_raw(pid_of(&victim)))));
    drop(guardian);
    let status = assert_ok!(victim.wait());
    assert_eq!(status.signal(), Some(Signal::SIGTERM as i32), "{status:?}");
}

// ====================================================================================
// A real run killed with SIGKILL
// ====================================================================================

/// `(pid, ppid, command)` for every process.
fn processes() -> Vec<(i32, i32, String)> {
    let out = assert_ok!(
        Command::new("/bin/ps")
            .args(["-axo", "pid=,ppid=,command="])
            .output()
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| {
            let mut words = line.split_whitespace();
            let pid = words.next()?.parse().ok()?;
            let ppid = words.next()?.parse().ok()?;
            Some((pid, ppid, words.collect::<Vec<_>>().join(" ")))
        })
        .collect()
}

fn children_of(parent: i32, containing: &str) -> Vec<i32> {
    processes()
        .into_iter()
        .filter(|(_, ppid, command)| *ppid == parent && command.contains(containing))
        .map(|(pid, _, _)| pid)
        .collect()
}

/// Starts `hb run --log-denials -- perl <sleeper>` with no terminal, and returns it with the
/// pids of the agent and of the `log stream` helper.
fn a_running_hb(w: &World) -> (Child, i32, i32) {
    let script = w.project.join("sleeper.pl");
    common::write(
        &script,
        "$|=1; print \"child=$$\\n\"; sleep 1 for 1..120;\n",
    );
    let mut hb = w.drive(
        DRIVE,
        &[
            "run",
            "--log-denials",
            "--",
            "/usr/bin/perl",
            &script.to_string_lossy(),
        ],
    );
    let mut hb = assert_ok!(
        hb.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    );
    let stdout = hb.stdout.take();
    assert!(stdout.is_some());
    let mut line = String::new();
    if let Some(stdout) = stdout {
        assert_ok!(BufReader::new(stdout).read_line(&mut line));
    }
    let agent: i32 = assert_ok!(line.trim().trim_start_matches("child=").parse());
    let me = pid_of(&hb);
    let log = children_of(me, "log stream");
    assert_eq!(log.len(), 1, "expected one log stream under hb: {log:?}");
    (hb, agent, log[0])
}

#[test]
fn a_run_killed_with_sigkill_leaves_neither_the_agent_nor_the_log_stream_behind() {
    sandboxed!();
    let w = World::new(PROJECT);
    let (mut hb, agent, log) = a_running_hb(&w);
    assert!(alive(agent) && alive(log));
    assert_ok!(hb.kill());
    assert_ok!(hb.wait());
    assert!(
        within(Duration::from_secs(6), || !alive(agent) && !alive(log)),
        "after SIGKILL of hb: agent alive = {}, log stream alive = {}",
        alive(agent),
        alive(log)
    );
}

#[test]
fn a_run_that_finishes_normally_ends_its_guard_and_nothing_else() {
    sandboxed!();
    let w = World::new(PROJECT);
    let script = w.project.join("short.pl");
    common::write(
        &script,
        "$|=1; print \"child=$$\\n\"; sleep 1; print \"done\\n\";\n",
    );
    let mut command = w.drive(
        DRIVE,
        &["run", "--", "/usr/bin/perl", &script.to_string_lossy()],
    );
    let hb = assert_ok!(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    );
    let me = pid_of(&hb);
    let guards = {
        let mut found = Vec::new();
        within(Duration::from_secs(5), || {
            found = children_of(me, "__guard");
            !found.is_empty()
        });
        found
    };
    assert_eq!(guards.len(), 1, "expected one guard under hb: {guards:?}");
    let out = assert_ok!(hb.wait_with_output());
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("done"));
    assert!(
        within(Duration::from_secs(3), || !alive(guards[0])),
        "the guard outlived a run that finished"
    );
}

#[test]
fn on_a_terminal_a_sigkilled_run_leaves_no_agent_and_no_log_stream() {
    sandboxed!();
    if !std::path::Path::new("/usr/bin/expect").exists() {
        eprintln!("SKIP: no expect to provide a terminal");
        return;
    }
    let w = World::new(PROJECT);
    let script = w.project.join("sleeper.pl");
    common::write(
        &script,
        "$|=1; print \"child=$$\\n\"; sleep 1 for 1..120;\n",
    );
    w.approve();
    let exp = w.base.join("kill.exp");
    let body = format!(
        "set env(HB_TD_HOME) {{{home}}}\nset env(HB_TD_CWD) {{{cwd}}}\nset env(HB_TD_PATH) {{{path}}}\nset env(HB_TD_TMP) {{{tmp}}}\n\
         set timeout 20\n{guard}\
         spawn -noecho {drive} run --log-denials -- /usr/bin/perl {script}\n\
         expect -re {{child=([0-9]+)}}\nputs \"AGENT=$expect_out(1,string)\"\n\
         set hb [exp_pid]\n\
         puts \"LOG=[exec /bin/sh -c \"/bin/ps -axo pid=,ppid=,command= | /usr/bin/awk '\\$2 == $hb && /log stream/ {{print \\$1}}'\"]\"\n\
         exec /bin/kill -9 $hb\nsleep 1\n",
        home = w.home_dir().display(),
        cwd = w.project.display(),
        path = w.base.join("bin").display(),
        tmp = w.base.join("tmp").display(),
        guard = EXPECT_GUARD,
        drive = DRIVE,
        script = script.display(),
    );
    common::write(&exp, &body);
    let out = assert_ok!(Command::new("/usr/bin/expect").arg(&exp).output());
    let text = String::from_utf8_lossy(&out.stdout).replace('\r', "");
    assert_no_expect_timeout(&text);
    let number = |key: &str| -> i32 {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(-1)
    };
    let (agent, log) = (number("AGENT="), number("LOG="));
    assert!(agent > 1 && log > 1, "{text}");
    assert!(
        within(Duration::from_secs(6), || !alive(agent) && !alive(log)),
        "after SIGKILL of hb on a terminal: agent alive = {}, log stream alive = {}",
        alive(agent),
        alive(log)
    );
}

// ====================================================================================
// The hb ctl socket
// ====================================================================================

#[test]
fn a_killed_hb_has_its_ctl_socket_removed_by_the_guard_and_a_released_one_is_left_alone() {
    use std::os::unix::net::UnixListener;
    let dir = assert_ok!(tempfile::Builder::new().prefix("hb-g").tempdir_in("/tmp"));
    let path = dir.path().join("ctl.sock");

    // hb dies without releasing: the guard unlinks the socket.
    let _listener = assert_ok!(UnixListener::bind(&path));
    let mut guardian = assert_ok!(Guardian::start_with(
        std::path::Path::new(HB),
        Duration::from_millis(200)
    ));
    assert_ok!(guardian.socket(&path));
    let guard_pid = i32::try_from(guardian.pid()).unwrap_or(i32::MAX);
    drop(guardian);
    assert!(
        within(Duration::from_secs(3), || !path.exists()),
        "the guard did not remove the socket"
    );
    // A guard that has exited but is not yet reaped by this test still answers `kill(pid, 0)`.
    let gone_or_zombie = |pid: i32| {
        let out = assert_ok!(
            Command::new("/bin/ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
        );
        String::from_utf8_lossy(&out.stdout).trim().is_empty()
            || String::from_utf8_lossy(&out.stdout).trim().starts_with('Z')
    };
    assert!(
        within(Duration::from_secs(3), || gone_or_zombie(guard_pid)),
        "the guard did not exit"
    );

    // hb finishes normally: the guard must not touch it (the broker removes its own).
    let _again = assert_ok!(UnixListener::bind(&path));
    let mut guardian = assert_ok!(Guardian::start_with(
        std::path::Path::new(HB),
        Duration::from_millis(200)
    ));
    assert_ok!(guardian.socket(&path));
    guardian.release();
    thread::sleep(Duration::from_millis(300));
    assert!(path.exists(), "release must leave the socket to the broker");
}
