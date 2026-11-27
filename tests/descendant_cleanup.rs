// ABOUTME: Black-box proof that the guardian ends work that outlives its group leader or leaves its session (hb-caj).
// ABOUTME: Each test arms a real `hb __guard` on a gated shell, lets it detach work, drops the guardian, and looks for survivors.
//! Leader-exit and detached-descendant cleanup, through the real guardian process.

#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use claims::{assert_ok, assert_some};
use hamster_ball::session::signals::Target;
use hamster_ball::session::{Guardian, WatchOutcome};
use nix::sys::signal::kill;
use nix::unistd::Pid;
use pretty_assertions::assert_eq;

const HB: &str = env!("CARGO_BIN_EXE_hb");

fn alive(pid: i32) -> bool {
    !matches!(
        kill(Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH)
    )
}

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

/// A shell in its own group, parked at a gate until the test has armed the guardian on it, as hb's
/// launch gate parks the agent. After release it runs `script`, which prints the pids it started.
struct Gated {
    leader: Child,
    go: ChildStdin,
    out: BufReader<ChildStdout>,
}

impl Gated {
    fn start(script: &str) -> Self {
        let mut leader = assert_ok!(
            Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("read go; {script}"))
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .process_group(0)
                .spawn()
        );
        let go = assert_some!(leader.stdin.take());
        let out = BufReader::new(assert_some!(leader.stdout.take()));
        Self { leader, go, out }
    }

    fn pid(&self) -> i32 {
        i32::try_from(self.leader.id()).unwrap_or(i32::MAX)
    }

    /// Opens the gate and reads one line of pids.
    fn release(&mut self) -> Vec<i32> {
        assert_ok!(self.go.write_all(b"go\n"));
        let mut line = String::new();
        assert_ok!(self.out.read_line(&mut line));
        line.split_whitespace()
            .map(|word| assert_ok!(word.parse()))
            .collect()
    }
}

fn guardian() -> Guardian {
    assert_ok!(Guardian::start_with(
        std::path::Path::new(HB),
        Duration::from_millis(500)
    ))
}

fn arm(guardian: &mut Guardian, gated: &Gated) {
    assert_eq!(
        assert_ok!(guardian.watch(Target::Group(Pid::from_raw(gated.pid())))),
        WatchOutcome::Armed
    );
}

/// The group member is made by a helper that exits at once, so by the time the tracker looks, the
/// member's parent is gone and it is reparented to launchd. Only the group scan can still find it:
/// nothing in the tracker lists its parent's children.
#[test]
fn work_in_the_group_of_a_leader_that_has_exited_is_ended_when_hb_dies() {
    let mut guardian = guardian();
    let mut gated =
        Gated::start("(sleep 60 </dev/null >/dev/null 2>&1 & echo $!) ; sleep 1; exit 0");
    arm(&mut guardian, &gated);
    let pids = gated.release();
    let _ = gated.leader.wait();
    let background = pids[0];
    assert!(
        alive(background),
        "the control: the work outlives its leader"
    );
    drop(guardian);
    assert!(
        within(Duration::from_secs(6), || !alive(background)),
        "the group member survived the guardian"
    );
}

#[test]
fn work_that_left_its_session_is_ended_when_hb_dies() {
    let mut guardian = guardian();
    // The leader lingers, so the fork is seen while it still exists; see the measured rates for a
    // leader that forks and exits at once.
    let mut gated = Gated::start(
        "/usr/bin/perl -e 'use POSIX; if (fork == 0) { setsid; print \"$$\\n\"; close STDOUT; sleep 60; exit } sleep 1; exit 0'",
    );
    arm(&mut guardian, &gated);
    let pids = gated.release();
    let detached = pids[0];
    assert!(alive(detached));
    drop(guardian);
    assert!(
        within(Duration::from_secs(6), || !alive(detached)),
        "the detached process survived the guardian"
    );
    let _ = gated.leader.wait();
}

#[test]
fn a_released_guardian_leaves_detached_work_alone() {
    let mut guardian = guardian();
    let mut gated = Gated::start("sleep 60 </dev/null >/dev/null 2>&1 & echo $!; exit 0");
    arm(&mut guardian, &gated);
    let pids = gated.release();
    let _ = gated.leader.wait();
    guardian.release();
    thread::sleep(Duration::from_millis(800));
    assert!(alive(pids[0]), "a normal release must not end anything");
    let _ = kill(Pid::from_raw(pids[0]), nix::sys::signal::Signal::SIGKILL);
}

#[test]
fn an_unrelated_process_is_never_signalled() {
    let mut guardian = guardian();
    let mut bystander = assert_ok!(Command::new("/bin/sleep").arg("60").spawn());
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    drop(guardian);
    thread::sleep(Duration::from_millis(1200));
    assert_eq!(
        assert_ok!(bystander.try_wait()),
        None,
        "the bystander was signalled"
    );
    let _ = bystander.kill();
    let _ = bystander.wait();
}

// ====================================================================================
// The teardown sweeps
// ====================================================================================

/// A long-lived program that is not Apple's, so macOS shows its environment (Apple's own tools are
/// hidden), and that takes any arguments, so a token can be placed in them. Built once by `rustc`
/// from a one-line source: the tests need nothing installed and never skip.
fn parked_program() -> &'static std::path::Path {
    static PROGRAM: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
    PROGRAM.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("hb-caj-fixture-{}", std::process::id()));
        assert_ok!(std::fs::create_dir_all(&dir));
        let source = dir.join("parked.rs");
        assert_ok!(std::fs::write(
            &source,
            "fn main() { std::thread::sleep(std::time::Duration::from_secs(300)); }\n"
        ));
        let program = dir.join("parked");
        let built = assert_ok!(
            Command::new(option_env!("RUSTC").unwrap_or("rustc"))
                .arg("-o")
                .arg(&program)
                .arg(&source)
                .output()
        );
        assert!(
            built.status.success(),
            "the fixture did not build: {}",
            String::from_utf8_lossy(&built.stderr)
        );
        program
    })
}

/// A parked process with exactly this environment and these arguments.
fn parked(env: &[(&str, &str)], args: &[&str]) -> Child {
    assert_ok!(
        Command::new(parked_program())
            .args(args)
            .env_clear()
            .envs(env.iter().copied())
            .spawn()
    )
}

/// Starts a process the tracker never sees: it is not under the gated root. It carries the token in
/// its environment, as an escaped descendant of the agent would.
fn stranger_with_token(token: &str) -> Child {
    parked(&[("HB_LAUNCH_TOKEN", token)], &[])
}

fn token() -> String {
    let mut bytes = [0u8; 16];
    assert_ok!(std::io::Read::read_exact(
        &mut assert_ok!(std::fs::File::open("/dev/urandom")),
        &mut bytes
    ));
    bytes.iter().fold(String::from("hb1-"), |mut hex, b| {
        hex.push_str(&format!("{b:02x}"));
        hex
    })
}

fn pid_of(child: &Child) -> i32 {
    i32::try_from(child.id()).unwrap_or(i32::MAX)
}

#[test]
fn a_process_the_tracker_missed_is_found_by_its_token_and_ended() {
    let mut guardian = guardian();
    let value = token();
    assert_ok!(guardian.token(&value));
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    // Started after the root, so a candidate that is not older than it.
    let mut stranger = stranger_with_token(&value);
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    assert!(alive(pid_of(&stranger)));
    drop(guardian);
    // The test is its parent, so an ended process stays a zombie until it is waited for.
    assert!(
        within(Duration::from_secs(6), || assert_ok!(stranger.try_wait())
            .is_some()),
        "the process carrying the token survived"
    );
}

#[test]
fn a_process_that_only_mentions_the_token_in_its_arguments_is_left_alone() {
    let mut guardian = guardian();
    let value = token();
    assert_ok!(guardian.token(&value));
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    let mut decoy = parked(&[], &[&format!("HB_LAUNCH_TOKEN={value}")]);
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    drop(guardian);
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        assert_ok!(decoy.try_wait()),
        None,
        "an argument was taken for the environment"
    );
    let _ = decoy.kill();
    let _ = decoy.wait();
}

/// The reviewer's decoy: the token appears in the `ps` text as a separate word because an unrelated
/// variable's value contains a space, but no environment entry is the token.
#[test]
fn a_value_that_merely_contains_the_token_text_is_not_taken_for_an_entry() {
    let mut guardian = guardian();
    let value = token();
    assert_ok!(guardian.token(&value));
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    let mut decoy = parked(&[("NOTE", &format!("see HB_LAUNCH_TOKEN={value}"))], &[]);
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    drop(guardian);
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        assert_ok!(decoy.try_wait()),
        None,
        "a value containing the token text was taken for an environment entry"
    );
    let _ = decoy.kill();
    let _ = decoy.wait();
}

#[test]
fn a_process_that_started_before_the_run_is_never_taken_for_it() {
    let value = token();
    // It already holds the token (forged or leaked) when the run starts.
    let mut older = stranger_with_token(&value);
    thread::sleep(Duration::from_millis(50));
    let mut guardian = guardian();
    assert_ok!(guardian.token(&value));
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    drop(guardian);
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        assert_ok!(older.try_wait()),
        None,
        "an older process was signalled"
    );
    let _ = older.kill();
    let _ = older.wait();
}

#[test]
fn a_process_that_kept_its_working_directory_in_the_session_directory_is_ended() {
    let dir = assert_ok!(tempfile::tempdir());
    let real = assert_ok!(dir.path().canonicalize());
    let mut guardian = guardian();
    assert_ok!(guardian.session_dir(&real));
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    let mut holder = assert_ok!(
        Command::new("/bin/sleep")
            .arg("60")
            .current_dir(&real)
            .process_group(0)
            .spawn()
    );
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    assert!(alive(pid_of(&holder)));
    drop(guardian);
    assert!(
        within(Duration::from_secs(6), || assert_ok!(holder.try_wait())
            .is_some()),
        "the process using the session directory survived"
    );
}

/// Nothing tracked is left once the roots exit, but a process still using the session directory is
/// a leftover. The guard must look once more after tracking empties, not conclude from emptiness.
///
/// The leftover appears only after the guard has begun tearing down: a second guardian command (a
/// token) keeps the first sweep from seeing it, and it is started once the first sweep has run.
#[test]
fn a_leftover_is_still_looked_for_after_everything_tracked_has_exited() {
    let dir = assert_ok!(tempfile::tempdir());
    let real = assert_ok!(dir.path().canonicalize());
    let mut guardian = guardian();
    assert_ok!(guardian.session_dir(&real));
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    // The guard is told hb is gone: it runs its first sweep, finds nothing, and tracking is empty.
    let handle = guardian.handle();
    drop(guardian);
    thread::sleep(Duration::from_millis(150));
    // A leftover that appears after that first sweep, while the guard is still deciding to stop.
    let mut late = assert_ok!(
        Command::new("/bin/sleep")
            .arg("60")
            .current_dir(&real)
            .process_group(0)
            .spawn()
    );
    drop(handle);
    assert!(
        within(Duration::from_secs(6), || assert_ok!(late.try_wait())
            .is_some()),
        "a leftover that appeared after the first sweep was not found"
    );
}

#[test]
fn a_malformed_token_is_refused_and_never_widens_the_search() {
    let mut guardian = guardian();
    for bad in ["x", "hb1-zz", "hb1-00112233445566778899aabbccddeeff0"] {
        assert!(guardian.token(bad).is_err(), "{bad}");
    }
}

// ====================================================================================
// Rates: how often the product tracker loses a detach race
// ====================================================================================

/// Runs `trials` gated roots that each detach a descendant by `script`, and counts how many of those
/// descendants the guardian did not end. The detached process prints its pid and sleeps.
fn escapes(script: &str, trials: usize) -> usize {
    let mut escaped = 0;
    for _ in 0..trials {
        let mut guardian = guardian();
        let mut gated = Gated::start(script);
        arm(&mut guardian, &gated);
        let pids = gated.release();
        let _ = gated.leader.wait();
        // Zero grace is not needed: the guardian's own 500 ms grace covers a polite stop.
        drop(guardian);
        let survivor = pids.first().copied();
        if let Some(pid) = survivor {
            if !within(Duration::from_secs(4), || !alive(pid)) {
                escaped += 1;
                let _ = kill(Pid::from_raw(pid), nix::sys::signal::Signal::SIGKILL);
            }
        }
    }
    escaped
}

/// A perl daemon is the survivor: Apple's `sleep` would work too, but perl lets one script fork,
/// call `setsid`, print its pid and close stdout so the gated shell can read it.
const DAEMON_LINGER: &str = "/usr/bin/perl -e 'use POSIX; if (fork == 0) { setsid; print \"$$\\n\"; close STDOUT; sleep 60; exit } sleep 1; exit 0'";
const DAEMON_DOUBLE_FORK: &str = "/usr/bin/perl -e 'use POSIX; if (fork == 0) { setsid; if (fork == 0) { print \"$$\\n\"; close STDOUT; sleep 60; exit } exit 0 } sleep 1; exit 0'";
const DAEMON_QUICK_EXIT: &str = "/usr/bin/perl -e 'use POSIX; if (fork == 0) { setsid; print \"$$\\n\"; close STDOUT; sleep 60; exit } exit 0'";

/// Every pattern is run and its escape count printed, so a run documents the rates. Only the
/// patterns the design promises are asserted, and only on a quiet machine: the double fork and the
/// instant exit can lose the race by scheduling alone, which is the documented residual.
#[test]
fn detach_patterns_are_ended_and_the_escape_rates_are_reported() {
    let trials: usize = std::env::var("HB_CAJ_TRIALS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    let linger = escapes(DAEMON_LINGER, trials);
    let double = escapes(DAEMON_DOUBLE_FORK, trials);
    let quick = escapes(DAEMON_QUICK_EXIT, trials);
    println!("RATES trials={trials} linger={linger} double_fork={double} quick_exit={quick}");
    // The tracker alone (no sweep is registered here). The lingering leader is deterministic, so none
    // may escape. The other two can lose the race by scheduling, so a small share is allowed: at most
    // 2% of the trials, rounded up. That bound is a choice, not a derived number; the measured rate
    // is 1 in 300 quiet and 0 in 300 under load (history/hb-caj-analysis-3.md).
    let allowed = trials / 50 + 1;
    assert_eq!(
        linger, 0,
        "a descendant that left its session while its leader lingered escaped"
    );
    assert!(
        double <= allowed,
        "double fork: {double} of {trials} escaped, allowed {allowed}"
    );
    assert!(
        quick <= allowed,
        "quick exit: {quick} of {trials} escaped, allowed {allowed}"
    );
}
