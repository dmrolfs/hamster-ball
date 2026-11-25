// ABOUTME: Opt-in (HB_LAUNCHD=1) end-to-end test of `hb ctl launchd` against the real launchd with a throwaway job.
// ABOUTME: Shows the listed job restarts, its environment never reaches the agent, and the agent cannot run launchctl itself.
//! hb-ghd.8.1 (launchd). Run with `HB_LAUNCHD=1 cargo test --test launchd_e2e -- --nocapture`.
//!
//! It loads one job named `com.hbtest.m8.<pid>` into the user's GUI domain, and unloads it at the
//! end (also when an assertion fails). It touches no other job.

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use claims::assert_ok;
use common::{World, sandbox_available, write};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");

struct Job {
    domain_target: String,
}

impl Drop for Job {
    fn drop(&mut self) {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &self.domain_target])
            .output();
    }
}

fn uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

fn runs(file: &std::path::Path) -> usize {
    fs::read_to_string(file).map_or(0, |t| t.lines().count())
}

fn within(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn a_listed_launchd_job_can_be_inspected_and_restarted_and_its_environment_stays_hidden() {
    if std::env::var_os("HB_LAUNCHD").is_none() {
        eprintln!("SKIP: set HB_LAUNCHD=1 to run the launchd test");
        return;
    }
    if !sandbox_available() {
        return;
    }
    let label = format!("com.hbtest.m8.{}", std::process::id());
    let w = World::under_symlinked_tmp(
        &format!("[fs]\nwrite = [\".\"]\n[ctl]\nlaunchd = [\"{label}\"]\n"),
        "[fs]\nwrite = [\".\"]\n",
    );
    let runs_file = w.base.join("runs");
    let plist = w.base.join(format!("{label}.plist"));
    write(
        &plist,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>echo started &gt;&gt; '{}'; sleep 300</string></array>\n<key>EnvironmentVariables</key><dict><key>M8_SECRET</key><string>m8-secret-value</string></dict>\n<key>RunAtLoad</key><true/>\n</dict></plist>\n",
            runs_file.display()
        ),
    );
    let target = format!("gui/{}/{label}", uid());
    let _job = Job {
        domain_target: target.clone(),
    };
    let loaded = assert_ok!(
        Command::new("/bin/launchctl")
            .args(["bootstrap", &format!("gui/{}", uid())])
            .arg(&plist)
            .output()
    );
    assert!(
        loaded.status.success(),
        "could not load the throwaway job: {}",
        String::from_utf8_lossy(&loaded.stderr)
    );
    assert!(
        within(Duration::from_secs(10), || runs(&runs_file) == 1),
        "the job did not start"
    );

    let mut cmd = w.drive(
        DRIVE,
        &[
            "run",
            "--",
            "/bin/sh",
            "-c",
            &format!(
                "hb ctl launchd status {label}; echo \"status rc=$?\"; \
                 hb ctl launchd restart {label}; echo \"restart rc=$?\"; \
                 hb ctl launchd status com.hbtest.not.listed 2>&1; echo \"unlisted rc=$?\"; \
                 /bin/launchctl print {target} >/dev/null 2>&1 && echo DIRECT-LAUNCHCTL-WORKED || echo direct-launchctl-denied"
            ),
        ],
    );
    let out = assert_ok!(cmd.output());
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        stdout.contains("state: running") && stdout.contains("status rc=0"),
        "{stdout}{stderr}"
    );
    assert!(
        !stdout.contains("m8-secret-value")
            && !stdout.contains("M8_SECRET")
            && !stderr.contains("m8-secret-value"),
        "the job environment leaked: {stdout}{stderr}"
    );
    assert!(stdout.contains("restart rc=0"), "{stdout}{stderr}");
    assert!(
        stdout.contains("not listed in [ctl] launchd") && stdout.contains("unlisted rc=1"),
        "{stdout}{stderr}"
    );
    assert!(
        stdout.contains("direct-launchctl-denied") && !stdout.contains("DIRECT-LAUNCHCTL-WORKED"),
        "{stdout}{stderr}"
    );
    assert!(
        within(Duration::from_secs(10), || runs(&runs_file) >= 2),
        "restart must run the job again (kickstart -k): {} runs",
        runs(&runs_file)
    );
}
