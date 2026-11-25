// ABOUTME: `hb ctl` end to end with a fake podman: a real `hb run` under sandbox-exec, the real broker, the real client and wrapper.
// ABOUTME: Proves what the profile and run wiring do: one socket reachable, `hb` on PATH, no direct podman, pins and cleanup.
//! hb-ghd.8.1 and 8.3 through the real process (podman is faked; the opt-in suite uses the real one).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use claims::assert_ok;
use common::{World, sandbox_available, write};
use serde_json::json;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const ID: &str = "3333333333333333333333333333333333333333333333333333333333333333";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

const BASE: &str = "[fs]\nwrite = [\".\"]\n";

/// A podman that answers from files and logs every call. `Mounts` shares only the project.
fn fake_podman(w: &World) {
    let dir = w.base.join("fakepodman");
    let machine = dir.join("machine");
    assert_ok!(fs::create_dir_all(&machine));
    let source = format!(
        "{}/data",
        fs::canonicalize(&w.project)
            .map_or_else(|_| String::new(), |p| p.to_string_lossy().into_owned())
    );
    assert_ok!(fs::create_dir_all(&source));
    let record = json!([{
        "Id": ID, "Name": "db", "Config": {"Labels": {"proj": "x"}},
        "HostConfig": {"Privileged": false, "NetworkMode": "bridge", "PidMode": "private", "IpcMode": "shareable",
            "UsernsMode": "", "UTSMode": "private", "CgroupMode": "private", "CapAdd": [], "SecurityOpt": [],
            "Devices": [], "Binds": [format!("{source}:/d:rprivate,rbind")], "Tmpfs": {}},
        "Mounts": [{"Type": "bind", "Source": source, "Destination": "/d", "Propagation": "rprivate"}]
    }]);
    write(&dir.join("inspect"), &record.to_string());
    write(&dir.join("ps"), r#"[{"Names":["db"],"State":"running"}]"#);
    write(
        &machine.join("m.json"),
        &json!({"Mounts": [{"Source": fs::canonicalize(&w.project).map_or_else(|_| String::new(), |p| p.to_string_lossy().into_owned()), "Target": "/p", "ReadOnly": false}]}).to_string(),
    );
    write(
        &dir.join("machine.json"),
        &json!([{"Name": "m", "SSHConfig": {"Port": 4242}, "ConfigDir": {"Path": machine.to_string_lossy()}}]).to_string(),
    );
    write(&dir.join("machine-list.json"), r#"[{"Name":"m"}]"#);
    write(
        &dir.join("connections.json"),
        r#"[{"Name":"m","URI":"ssh://core@127.0.0.1:4242/run/user/1/podman/podman.sock","Default":true}]"#,
    );
    let script = w.base.join("bin/podman");
    write(
        &script,
        &format!(
            "#!/bin/sh\necho \"$@\" >> '{log}'\ncase \"$1\" in\n ps) cat '{d}/ps';;\n inspect) cat '{d}/inspect';;\n machine) case \"$2\" in list) cat '{d}/machine-list.json';; *) cat '{d}/machine.json';; esac;;\n system) cat '{d}/connections.json';;\n restart|start|stop|logs) shift; for last; do :; done; echo \"did $last\";;\n *) exit 1;;\nesac\n",
            log = dir.join("calls").display(),
            d = dir.display()
        ),
    );
    assert_ok!(fs::set_permissions(
        &script,
        fs::Permissions::from_mode(0o755)
    ));
}

fn calls(w: &World) -> String {
    fs::read_to_string(w.base.join("fakepodman/calls")).unwrap_or_default()
}

fn run(w: &World, script: &str) -> (String, String, bool) {
    let out = assert_ok!(
        w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", script])
            .output()
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.success(),
    )
}

/// Worlds sit under `/tmp` because the session directory path must fit a unix socket (103 bytes);
/// the default temp directory is deeper than a real user temp directory is.
fn world(ctl: &str) -> World {
    let w = World::under_symlinked_tmp(BASE, &format!("[fs]\nwrite = [\".\"]\n{ctl}"));
    fake_podman(&w);
    w
}

#[test]
fn inside_the_ball_hb_ctl_restarts_a_listed_container_through_the_broker() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    let (out, err, ok) = run(&w, "hb ctl ps; hb ctl restart db; echo \"rc=$?\"");
    assert!(ok, "{out}{err}");
    assert!(out.contains("db\trunning"), "{out}{err}");
    assert!(out.contains(&format!("did {ID}")), "{out}{err}");
    assert!(out.contains("rc=0"), "{out}{err}");
    let log = calls(&w);
    assert!(log.contains(&format!("restart -t 10 -- {ID}")), "{log}");
}

#[test]
fn the_agent_cannot_run_podman_itself_and_only_listed_names_work() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    let (out, err, _) = run(
        &w,
        "podman ps >/dev/null 2>&1 && echo DIRECT-PODMAN-WORKED || echo direct-podman-denied; \
         hb ctl restart other; echo \"other rc=$?\"; hb ctl exec db 2>&1 | head -1; hb ctl restart -- --all; echo \"flag rc=$?\"",
    );
    assert!(
        out.contains("direct-podman-denied") && !out.contains("DIRECT-PODMAN-WORKED"),
        "{out}{err}"
    );
    assert!(
        out.contains("other rc=1") || out.contains("other rc=2"),
        "{out}{err}"
    );
    assert!(out.contains("unrecognized subcommand"), "{out}{err}");
    assert!(
        !calls(&w).contains("other") || !calls(&w).contains("restart -t 10 -- other"),
        "{}",
        calls(&w)
    );
}

#[test]
fn the_socket_is_the_only_one_reachable_and_is_gone_after_the_run() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    let (out, err, ok) = run(
        &w,
        "echo \"sock=$HB_CTL_SOCKET\"; ls -l \"$HB_CTL_SOCKET\" | cut -c1-10; ls \"$TMPDIR\"",
    );
    assert!(ok, "{out}{err}");
    let sock = out
        .lines()
        .find_map(|l| l.strip_prefix("sock="))
        .unwrap_or_default()
        .to_owned();
    assert!(sock.ends_with("/ctl.sock"), "{out}");
    assert!(out.contains("srw-------"), "mode 0600 socket: {out}");
    assert!(
        !Path::new(&sock).exists(),
        "the socket must be removed when the run ends: {sock}"
    );
}

#[test]
fn a_run_with_no_ctl_config_has_no_broker_no_wrapper_and_no_variable() {
    sandboxed!();
    let w = World::with_base(BASE, BASE);
    let (out, err, ok) = run(
        &w,
        "echo \"var=${HB_CTL_SOCKET:-unset}\"; command -v hb || echo no-hb; hb ctl ps 2>&1 | head -1",
    );
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("var=unset") && out.contains("no-hb"),
        "{out}{err}"
    );
}

#[test]
fn a_launchd_only_run_needs_no_podman_and_refuses_unlisted_jobs() {
    sandboxed!();
    let w = World::under_symlinked_tmp(BASE, BASE);
    w.append_to_base("\n[ctl]\nlaunchd = [\"com.example.nothing\"]\n");
    let (out, err, ok) = run(
        &w,
        "hb ctl launchd status com.example.other 2>&1; echo \"unlisted rc=$?\"; hb ctl launchd status com.example.nothing 2>&1; echo \"listed rc=$?\"; hb ctl ps 2>&1; echo \"ps rc=$?\"",
    );
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("unlisted rc=1") && out.contains("not listed in [ctl] launchd"),
        "{out}{err}"
    );
    assert!(
        out.contains("ps rc=1") && out.contains("lists no containers"),
        "{out}{err}"
    );
    assert!(!calls(&w).contains("restart"), "no container command ran");
}

#[test]
fn mount_sources_are_pinned_in_the_running_profile_but_the_agent_can_still_edit_inside_them() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    write(&w.project.join("data/keep"), "k");
    let (out, err, ok) = run(
        &w,
        "mv data data2 2>/dev/null && echo SOURCE-RENAMED || echo source-pinned; echo x > data/new && echo edit-inside-ok; mv data/keep data/kept && echo rename-inside-ok",
    );
    assert!(ok, "{out}{err}");
    assert!(
        out.contains("source-pinned") && !out.contains("SOURCE-RENAMED"),
        "{out}{err}"
    );
    assert!(
        out.contains("edit-inside-ok") && out.contains("rename-inside-ok"),
        "{out}{err}"
    );
}

// ====================================================================================
// A run killed with SIGKILL
// ====================================================================================

use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::process::Stdio;
use std::thread;
use std::time::{Duration, Instant};

fn within(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(25));
    }
    false
}

#[test]
fn a_run_killed_with_sigkill_leaves_no_socket_and_the_agent_is_ended() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    let script = w.project.join("sleeper.sh");
    write(
        &script,
        "echo \"sock=$HB_CTL_SOCKET\"; echo \"pid=$$\"; while :; do sleep 1; done\n",
    );
    let mut hb = w.drive(DRIVE, &["run", "--", "/bin/sh", &script.to_string_lossy()]);
    let mut hb = assert_ok!(
        hb.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    );
    let mut reader = BufReader::new(assert_ok!(hb.stdout.take().ok_or("stdout")));
    let (mut sock, mut agent) = (String::new(), 0i32);
    for _ in 0..2 {
        let mut line = String::new();
        assert_ok!(reader.read_line(&mut line));
        if let Some(s) = line.trim().strip_prefix("sock=") {
            sock = s.to_owned();
        }
        if let Some(p) = line.trim().strip_prefix("pid=") {
            agent = p.parse().unwrap_or(0);
        }
    }
    assert!(
        Path::new(&sock).exists(),
        "the socket exists while the run is going: {sock}"
    );
    assert!(agent > 1);
    // A connection that is open when hb dies must not keep the socket alive.
    let _open = assert_ok!(UnixStream::connect(&sock));
    assert_ok!(hb.kill());
    assert_ok!(hb.wait());
    assert!(
        within(Duration::from_secs(8), || !Path::new(&sock).exists()),
        "the guard must remove the socket of a killed hb: {sock}"
    );
    assert!(
        within(Duration::from_secs(8), || {
            !matches!(
                nix::sys::signal::kill(nix::unistd::Pid::from_raw(agent), None),
                Ok(())
            )
        }),
        "the agent must be ended too"
    );
}

/// The pid of every process whose command line contains `needle` (this test's own marker).
fn pids_running(needle: &str) -> Vec<i32> {
    let out = assert_ok!(
        std::process::Command::new("/bin/ps")
            .args(["-axo", "pid=,command="])
            .output()
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains(needle) && !l.contains("ps -axo"))
        .filter_map(|l| l.split_whitespace().next()?.parse().ok())
        .collect()
}

#[test]
fn a_podman_command_running_when_hb_is_killed_does_not_outlive_it() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    // inspect answers at once; restart hangs, marked so the test can find it.
    let marker = format!("hb-hang-marker-{}", std::process::id());
    let podman = w.base.join("bin/podman");
    let original = assert_ok!(fs::read_to_string(&podman));
    let hung = original.replace(
        "restart|start|stop|logs) shift;",
        // A script that holds the marker in its own command line and sleeps in a child.
        &format!(
            "restart) exec /bin/sh -c 'sleep 300 & wait' {marker};;\n start|stop|logs) shift;"
        ),
    );
    assert_ne!(original, hung);
    write(&podman, &hung);
    assert_ok!(fs::set_permissions(
        &podman,
        fs::Permissions::from_mode(0o755)
    ));

    let script = w.project.join("ask.sh");
    write(
        &script,
        "echo \"sock=$HB_CTL_SOCKET\"; hb ctl restart db >/dev/null 2>&1 & sleep 1; echo ready; while :; do sleep 1; done\n",
    );
    let mut hb = w.drive(DRIVE, &["run", "--", "/bin/sh", &script.to_string_lossy()]);
    let mut hb = assert_ok!(
        hb.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    );
    let mut reader = BufReader::new(assert_ok!(hb.stdout.take().ok_or("stdout")));
    let mut line = String::new();
    for _ in 0..2 {
        line.clear();
        assert_ok!(reader.read_line(&mut line));
    }
    let started = within(Duration::from_secs(10), || {
        !pids_running(&marker).is_empty()
    });
    assert!(
        started,
        "the restart command must be running before the kill; podman calls: {}",
        calls(&w)
    );
    let running = pids_running(&marker);
    assert_ok!(hb.kill());
    assert_ok!(hb.wait());
    assert!(
        within(Duration::from_secs(10), || pids_running(&marker).is_empty()),
        "broker subprocesses {running:?} outlived a killed hb"
    );
}

#[test]
fn a_podman_command_still_running_when_the_agent_exits_is_stopped_with_the_run() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    let marker = format!("hb-hang-normal-{}", std::process::id());
    let podman = w.base.join("bin/podman");
    let original = assert_ok!(fs::read_to_string(&podman));
    write(
        &podman,
        &original.replace(
            "restart|start|stop|logs) shift;",
            &format!(
                "restart) exec /bin/sh -c 'sleep 300 & wait' {marker};;\n start|stop|logs) shift;"
            ),
        ),
    );
    assert_ok!(fs::set_permissions(
        &podman,
        fs::Permissions::from_mode(0o755)
    ));
    // The agent asks for a restart in the background and exits at once, leaving it running.
    let started = Instant::now();
    let (out, err, ok) = run(
        &w,
        "(hb ctl restart db >/dev/null 2>&1 &) ; sleep 1; echo agent-done",
    );
    assert!(ok, "{out}{err}");
    assert!(out.contains("agent-done"));
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the run must not wait for the 60 s restart budget: {:?}",
        started.elapsed()
    );
    assert!(
        within(Duration::from_secs(10), || pids_running(&marker).is_empty()),
        "{:?} still running after the run ended",
        pids_running(&marker)
    );
}

#[test]
fn the_podman_machine_key_and_container_directories_are_unreadable_inside_the_ball() {
    sandboxed!();
    let w = world("[ctl]\nlabel = \"proj=x\"\n");
    // The real floor names these under the world's home: make each one exist, grant the whole home
    // for reading, and show that only the floor stops the read (a sibling file is readable).
    let home = w.home_dir();
    for (dir, file) in [
        (".local/share/containers/podman/machine", "machine"),
        (".config/containers", "containers.conf"),
        (".local/share/containers", "storage.conf"),
    ] {
        write(&home.join(dir).join(file), "secret\n");
    }
    write(&home.join("sibling.txt"), "plain\n");
    // Grants that cover the three directories (the whole home is too broad to grant, so name them).
    w.set_base("[fs]\nwrite = [\".\"]\nread = [\"~/.local/share\", \"~/.config/containers\", \"~/sibling.txt\"]\n[ctl]\nlabel = \"proj=x\"\n");
    let (out, err, ok) = run(
        &w,
        "for f in .local/share/containers/podman/machine/machine .config/containers/containers.conf .local/share/containers/storage.conf; do \
           cat \"$HOME/$f\" >/dev/null 2>&1 && echo \"READABLE:$f\" || echo \"denied:$f\"; done; \
         cat \"$HOME/sibling.txt\" && echo sibling-readable",
    );
    assert!(ok, "{out}{err}");
    assert!(
        !out.contains("READABLE:"),
        "the floor must deny these: {out}{err}"
    );
    assert_eq!(out.matches("denied:").count(), 3, "{out}{err}");
    assert!(
        out.contains("sibling-readable"),
        "control: the home itself is readable: {out}{err}"
    );
}
