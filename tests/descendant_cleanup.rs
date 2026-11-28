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

/// A guardian with the production grace period. The sweeps get half of it, so a shorter one would
/// test the sweeps' time budget (a machine at a load average of 100 needs more than 250 ms for `ps`
/// and `lsof`) instead of what they find.
fn guardian() -> Guardian {
    assert_ok!(Guardian::start_with(
        std::path::Path::new(HB),
        hamster_ball::session::guardian::DEFAULT_GRACE
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
    // Keep the leader parked. Discovery itself is tested with a controlled fork event in tracker.rs;
    // this black-box case acknowledges ownership explicitly before killing hb.
    let mut gated = Gated::start(
        "exec /usr/bin/perl -e 'use POSIX; $|=1; if (fork == 0) { setsid; print \"$$\\n\"; close STDOUT; sleep 60; exit } <STDIN>; exit 0'",
    );
    arm(&mut guardian, &gated);
    let pids = gated.release();
    let detached = pids[0];
    assert!(alive(detached));
    assert_eq!(
        assert_ok!(guardian.watch(Target::Child(Pid::from_raw(detached)))),
        WatchOutcome::Armed
    );
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
    let dir = assert_ok!(tempfile::tempdir());
    let real = assert_ok!(dir.path().canonicalize());
    let value = token();
    assert_ok!(guardian.token(&value));
    assert_ok!(guardian.session_dir(&real));
    let mut token_holder = stranger_with_token(&value);
    let mut directory_holder = assert_ok!(
        Command::new("/bin/sleep")
            .arg("60")
            .current_dir(&real)
            .spawn()
    );
    let mut gated = Gated::start("sleep 60 </dev/null >/dev/null 2>&1 & echo $!; exit 0");
    arm(&mut guardian, &gated);
    let pids = gated.release();
    let _ = gated.leader.wait();
    guardian.release();
    thread::sleep(Duration::from_millis(800));
    let token_alive = assert_ok!(token_holder.try_wait()).is_none();
    let directory_alive = assert_ok!(directory_holder.try_wait()).is_none();
    let _ = token_holder.kill();
    let _ = token_holder.wait();
    let _ = directory_holder.kill();
    let _ = directory_holder.wait();
    assert!(
        token_alive && directory_alive,
        "release ran a recovery sweep"
    );
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
    let ended = within(Duration::from_secs(6), || {
        assert_ok!(stranger.try_wait()).is_some()
    });
    // A failed cleanup check must not leave its 300-second fixture running.
    if !ended {
        let _ = stranger.kill();
        let _ = stranger.wait();
    }
    assert!(ended, "the process carrying the token survived");
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

/// When one complete look after tracking empties finds nothing, the guard is done: it does not sit out
/// the rest of a long grace period. The guard is the test's own child, so its exit is seen by reaping it.
#[test]
fn a_guard_with_nothing_left_after_a_complete_look_does_not_wait_out_the_grace_period() {
    let dir = assert_ok!(tempfile::tempdir());
    let real = assert_ok!(dir.path().canonicalize());
    let mut guardian = assert_ok!(Guardian::start_with(
        std::path::Path::new(HB),
        Duration::from_secs(6)
    ));
    assert_ok!(guardian.session_dir(&real));
    let mut gated = Gated::start("exit 0");
    arm(&mut guardian, &gated);
    let _ = gated.go.write_all(b"go\n");
    let _ = gated.leader.wait();
    let guard = nix::unistd::Pid::from_raw(i32::try_from(guardian.pid()).unwrap_or(i32::MAX));
    let started = Instant::now();
    drop(guardian);
    let ended = within(Duration::from_secs(4), || {
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
        matches!(
            waitpid(guard, Some(WaitPidFlag::WNOHANG)),
            Ok(status) if status != WaitStatus::StillAlive
        )
    });
    assert!(
        ended,
        "the guard was still running {:?} after hb went, with a grace of 6 s",
        started.elapsed()
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
        // No pid printed or no live identity is a broken trial, not a clean measurement.
        let pid = claims::assert_some!(pids.first().copied());
        let identity = assert_ok!(hamster_ball::session::identity::Identity::of(pid));
        let _ = gated.leader.wait();
        // Use the production grace; escapes are observations, not assertions about scheduling.
        drop(guardian);
        if !within(Duration::from_secs(4), || !alive(pid)) {
            escaped += 1;
            if assert_ok!(identity.is_current()) {
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

/// Scheduling-dependent tracker-only measurements, not a cleanup-success gate.
/// Correctness assertions live in the synchronized ownership and recovery tests.
#[test]
fn detach_escape_rates_are_reported_without_a_probability_gate() {
    let trials: usize = std::env::var("HB_CAJ_TRIALS")
        .map(|value| assert_ok!(value.parse()))
        .unwrap_or(15);
    assert!(trials >= 1, "HB_CAJ_TRIALS must be at least 1");
    let linger = escapes(DAEMON_LINGER, trials);
    let double = escapes(DAEMON_DOUBLE_FORK, trials);
    let quick = escapes(DAEMON_QUICK_EXIT, trials);
    println!("RATES trials={trials} linger={linger} double_fork={double} quick_exit={quick}");
}
