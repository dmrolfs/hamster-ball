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
use pretty_assertions::assert_eq;
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

/// Sends raw bytes, bypassing clap and Request serialization, from inside the sandbox.
fn raw_request(w: &World, payload: &[u8]) -> hamster_ball::ctl::op::Response {
    let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
    let script = format!(
        r#"/usr/bin/perl -MIO::Socket::UNIX -e '
            alarm 15;
            my $s = IO::Socket::UNIX->new(Peer => $ENV{{HB_CTL_SOCKET}}, Type => SOCK_STREAM)
                or die "connect: $!";
            print $s pack("H*", "{hex}") or die "write: $!";
            shutdown($s, 1) or die "shutdown: $!";
            my $reply = <$s>; defined($reply) or die "missing reply";
            print $reply;
        '"#
    );
    let (out, err, ok) = run(w, &script);
    assert!(ok, "raw client failed, not a refusal: {out}{err}");
    assert_ok!(serde_json::from_str(&out))
}

#[test]
fn raw_broker_requests_are_validated_before_any_host_mutation() {
    sandboxed!();
    let w = world("[ctl]\ncontainers = [\"db\"]\n");
    let valid = b"{\"target\":\"container\",\"op\":\"restart\",\"name\":\"db\"}\n";
    let control = raw_request(&w, valid);
    assert!(control.ok && control.out.contains(ID), "{control:?}");
    let mutations = || {
        calls(&w)
            .lines()
            .filter(|l| l.starts_with("restart "))
            .count()
    };
    assert_eq!(mutations(), 1, "raw control must reach the actual runner");
    let bad = [
        (
            b"{\"target\":\"container\",\"op\":\"restart\",\"name\":\"db\",\"argv\":[\"sh\"]}\n"
                .to_vec(),
            "not understood",
        ),
        (
            b"{\"target\":\"container\",\"op\":\"exec\",\"name\":\"db\"}\n".to_vec(),
            "not understood",
        ),
        (
            b"{\"target\":\"container\",\"op\":\"restart\",\"name\":\"--all\"}\n".to_vec(),
            "invalid container name",
        ),
        (
            b"{\"target\":\"container\",\"op\":\"restart\",\"name\":\"other\"}\n".to_vec(),
            "but other was requested",
        ),
        (b"\xff\n".to_vec(), "not text"),
        ([vec![b' '; 4096], valid.to_vec()].concat(), "too long"),
    ];
    for (payload, expected) in bad {
        let reply = raw_request(&w, &payload);
        assert!(
            !reply.ok && reply.err.contains(expected),
            "expected {expected}, got: {reply:?}"
        );
        assert_eq!(mutations(), 1, "host mutation escaped validation");
    }
    assert!(
        raw_request(&w, valid).ok,
        "rejections must not break the broker"
    );
    assert_eq!(mutations(), 2);
}

#[test]
fn raw_broker_admission_and_incomplete_requests_are_bounded() {
    sandboxed!();
    let w = world("[ctl]\ncontainers = [\"db\"]\n");
    let script = r#"/usr/bin/perl -MIO::Socket::UNIX -e '
        alarm 20;
        my @s;
        for (1..5) {
            push @s, IO::Socket::UNIX->new(Peer => $ENV{HB_CTL_SOCKET}, Type => SOCK_STREAM)
                or die "connect: $!";
        }
        print {$s[0]} qq({"target":) or die "partial write: $!";
        my $busy = readline($s[4]); defined($busy) or die "missing busy reply";
        print $busy;
        for my $s (@s[0..3]) {
            my $reply = <$s>; defined($reply) or die "missing timeout reply";
            print $reply;
        }
        close $_ for @s;
    ' && hb ctl ps"#;
    let (out, err, ok) = run(&w, script);
    assert!(ok, "client failed, not a bounded refusal: {out}{err}");
    let replies: Vec<hamster_ball::ctl::op::Response> = out
        .lines()
        .filter(|line| line.starts_with('{'))
        .map(|line| assert_ok!(serde_json::from_str(line)))
        .collect();
    assert_eq!(replies.len(), 5, "{out}{err}");
    assert!(
        !replies[0].ok && replies[0].err.contains("busy"),
        "{out}{err}"
    );
    for reply in &replies[1..] {
        assert!(!reply.ok && reply.err.contains("too slow"), "{reply:?}");
    }
    assert!(
        out.contains("db\trunning"),
        "valid request after saturation: {out}{err}"
    );
}

/// Covers launcher FD 3 reaching testdrive's host-side tool, not broker-internal descriptors.
#[test]
fn inherited_secret_descriptor_does_not_reach_the_host_broker_command() {
    sandboxed!();
    let w = world("[ctl]\ncontainers = [\"db\"]\n");
    let canary = w.base.join("fd-canary");
    write(&canary, "BROKER-FD-SECRET");
    let tool = w.base.join("bin/podman");
    let original = assert_ok!(fs::read_to_string(&tool));
    let probe =
        "/usr/bin/perl -e 'print qq(FD-PROBE:); print <F> if open(F, \"<&=3\"); print qq(\\n)'";
    write(
        &tool,
        &original.replace(
            "#!/bin/sh\n",
            &format!("#!/bin/sh\nif [ \"$1\" = logs ]; then {probe}; exit; fi\n"),
        ),
    );
    let control = assert_ok!(
        std::process::Command::new("/bin/sh")
            .args([
                "-c",
                &format!(
                    "exec 3<{}; exec {} logs",
                    common::quote(&canary),
                    common::quote(&tool)
                )
            ])
            .output()
    );
    assert!(control.status.success(), "{control:?}");
    assert_eq!(control.stdout, b"FD-PROBE:BROKER-FD-SECRET\n");
    w.approve();
    let mut command = std::process::Command::new("/bin/sh");
    command.args([
        "-c",
        &format!(
            "exec 3<{}; exec '{}' run -- /bin/sh -c 'hb ctl logs db'",
            common::quote(&canary),
            DRIVE
        ),
    ]);
    w.drive_env_unapproved(&mut command);
    let denied = assert_ok!(command.output());
    assert!(denied.status.success(), "{denied:?}");
    assert_eq!(
        denied.stdout, b"FD-PROBE:\n",
        "descriptor reached host-side command"
    );
}

#[test]
fn the_hidden_child_helper_cannot_replace_the_outer_sandbox() {
    sandboxed!();
    let w = world("[ctl]\ncontainers = [\"db\"]\n");
    let canary = w.base.join("outside-canary");
    write(&canary, "HELPER-ESCAPE-CANARY");
    let outside = assert_ok!(
        std::process::Command::new(DRIVE)
            .args([
                "__child",
                "--",
                "-p",
                "(version 1)(allow default)",
                "/bin/cat"
            ])
            .arg(&canary)
            .output()
    );
    assert!(outside.status.success(), "{outside:?}");
    assert_eq!(outside.stdout, b"HELPER-ESCAPE-CANARY");
    let (out, err, ok) = run(
        &w,
        &format!(
            "command -v hb >/dev/null || exit 90; hb __child -- -p '(version 1)(allow default)' /bin/cat '{}'; rc=$?; test $rc -eq 71 && echo nested-refused",
            canary.display()
        ),
    );
    assert!(ok && out.contains("nested-refused"), "{out}{err}");
    assert!(!out.contains("HELPER-ESCAPE-CANARY"), "{out}{err}");
    assert!(!err.contains("HELPER-ESCAPE-CANARY"), "{out}{err}");
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
    // Prove the covering grant works outside the floor and the denied fixtures exist.
    let home = w.home_dir();
    for (dir, file) in [
        (".local/share/containers/podman/machine", "machine"),
        (".config/containers", "containers.conf"),
        (".local/share/containers", "storage.conf"),
    ] {
        write(&home.join(dir).join(file), "secret\n");
        assert_eq!(
            assert_ok!(fs::read_to_string(home.join(dir).join(file))),
            "secret\n"
        );
    }
    write(
        &home.join(".local/share/plain.txt"),
        "covering-grant-control\n",
    );
    write(&home.join("sibling.txt"), "plain\n");
    // Grants that cover the three directories (the whole home is too broad to grant, so name them).
    w.set_base("[fs]\nwrite = [\".\"]\nread = [\"~/.local/share\", \"~/.config/containers\", \"~/sibling.txt\"]\n[ctl]\nlabel = \"proj=x\"\n");
    let (out, err, ok) = run(
        &w,
        "for f in .local/share/containers/podman/machine/machine .config/containers/containers.conf .local/share/containers/storage.conf; do \
           cat \"$HOME/$f\" >/dev/null 2>&1 && echo \"READABLE:$f\" || echo \"denied:$f\"; done; \
         cat \"$HOME/.local/share/plain.txt\"; cat \"$HOME/sibling.txt\" && echo sibling-readable",
    );
    assert!(ok, "{out}{err}");
    assert!(
        !out.contains("READABLE:"),
        "the floor must deny these: {out}{err}"
    );
    assert_eq!(out.matches("denied:").count(), 3, "{out}{err}");
    assert!(
        out.contains("sibling-readable") && out.contains("covering-grant-control"),
        "control: both explicit and covering grants work: {out}{err}"
    );
}
