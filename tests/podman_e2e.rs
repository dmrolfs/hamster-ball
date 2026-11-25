// ABOUTME: Opt-in (HB_PODMAN=1) end-to-end suite for `hb ctl` against real podman: throwaway containers, a real `hb run`, real pins.
// ABOUTME: The swap tests also need a podman machine that shares only HB_PODMAN_DIR; without one they are skipped and say so.
//! hb-ghd.8.4. Run with `HB_PODMAN=1 cargo test --test podman_e2e -- --nocapture`.
//!
//! What it needs:
//! - `HB_PODMAN=1`, a running podman machine, and the `alpine` image already pulled (it never pulls).
//! - For the isolated tests: `HB_PODMAN_DIR=<dir>` where `<dir>` is the only directory the running
//!   machine shares (`podman machine init --volume <dir>:<dir> --now`). Without it they are skipped.
//!
//! Every container, volume and network it makes is named `hb-m8-<pid>-...` and removed at the end,
//! also when a test fails. It never touches any other container.

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;

use claims::assert_ok;
use common::{World, sandbox_available, write};

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const IMAGE: &str = "docker.io/library/alpine:latest";

fn podman_binary() -> Option<PathBuf> {
    ["/opt/homebrew/bin/podman", "/usr/local/bin/podman"]
        .into_iter()
        .map(PathBuf::from)
        .find(|p| p.exists())
}

/// Whether the suite should run at all, and why not when it should not.
fn enabled() -> Option<PathBuf> {
    if std::env::var_os("HB_PODMAN").is_none() {
        eprintln!("SKIP: set HB_PODMAN=1 to run the real-podman suite");
        return None;
    }
    if !sandbox_available() {
        return None;
    }
    let podman = podman_binary();
    assert!(
        podman.is_some(),
        "HB_PODMAN is set but podman was not found"
    );
    podman
}

fn pm(binary: &PathBuf, args: &[&str]) -> (bool, String) {
    let out = assert_ok!(Command::new(binary).args(args).output());
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

/// Removes what a test made, in `Drop`, so a failed assertion still cleans up.
struct Cleanup {
    podman: PathBuf,
    containers: Vec<String>,
    volumes: Vec<String>,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        for c in &self.containers {
            let _ = Command::new(&self.podman)
                .args(["rm", "-f", "-t", "1", "--", c])
                .output();
        }
        for v in &self.volumes {
            let _ = Command::new(&self.podman)
                .args(["volume", "rm", "-f", "--", v])
                .output();
        }
    }
}

struct Rig {
    world: World,
    podman: PathBuf,
    label: String,
    cleanup: Cleanup,
}

fn name(suffix: &str) -> String {
    format!("hb-m8-{}-{suffix}", std::process::id())
}

fn rig(podman: PathBuf, parent: Option<&PathBuf>) -> Rig {
    let label = format!("hb.m8={}", std::process::id());
    let config = format!(
        "[fs]\nwrite = [\".\"]\n[ctl]\nlabel = \"{label}\"\ncontainers = [\"{}\"]\n",
        name("named")
    );
    // On a project-only machine the world must sit inside the one shared directory.
    let shared = parent
        .cloned()
        .or_else(|| std::env::var_os("HB_PODMAN_DIR").map(PathBuf::from));
    let world = match shared {
        Some(dir) => World::under(&dir, "[fs]\nwrite = [\".\"]\n", &config),
        None => World::under_symlinked_tmp("[fs]\nwrite = [\".\"]\n", &config),
    };
    // `podman` for the host side of the broker: found on the run's PATH.
    let wrapper = world.base.join("bin/podman");
    write(
        &wrapper,
        &format!("#!/bin/sh\nexec '{}' \"$@\"\n", podman.display()),
    );
    assert_ok!(fs::set_permissions(
        &wrapper,
        fs::Permissions::from_mode(0o755)
    ));
    Rig {
        world,
        label,
        cleanup: Cleanup {
            podman: podman.clone(),
            containers: Vec::new(),
            volumes: Vec::new(),
        },
        podman,
    }
}

/// Empties the shared project directory when the test ends, pass or fail.
struct Emptied(PathBuf);

impl Drop for Emptied {
    fn drop(&mut self) {
        if let Ok(entries) = fs::read_dir(&self.0) {
            for entry in entries.flatten() {
                let _ = fs::remove_dir_all(entry.path()).or_else(|_| fs::remove_file(entry.path()));
            }
        }
    }
}

/// A rig whose project is exactly `project`.
fn rig_at(podman: PathBuf, project: &std::path::Path) -> Rig {
    let label = format!("hb.m8={}", std::process::id());
    let config = format!("[fs]\nwrite = [\".\"]\n[ctl]\nlabel = \"{label}\"\n");
    let world = World::with_project_dir(project, "[fs]\nwrite = [\".\"]\n", &config);
    let wrapper = world.base.join("bin/podman");
    write(
        &wrapper,
        &format!("#!/bin/sh\nexec '{}' \"$@\"\n", podman.display()),
    );
    assert_ok!(fs::set_permissions(
        &wrapper,
        fs::Permissions::from_mode(0o755)
    ));
    Rig {
        world,
        label,
        cleanup: Cleanup {
            podman: podman.clone(),
            containers: Vec::new(),
            volumes: Vec::new(),
        },
        podman,
    }
}

impl Rig {
    fn project(&self) -> String {
        fs::canonicalize(&self.world.project)
            .map_or_else(|_| String::new(), |p| p.to_string_lossy().into_owned())
    }

    /// A throwaway container with `data/` of the project mounted, labelled for this run.
    fn container(&mut self, suffix: &str, labelled: bool) -> String {
        self.container_named(&name(suffix), labelled)
    }

    /// Like [`Rig::container`] with the exact name (the `[ctl] containers` entry is `hb-m8-<pid>-named`).
    fn container_named(&mut self, n: &str, labelled: bool) -> String {
        let n = n.to_owned();
        let source = format!("{}/data", self.project());
        assert_ok!(fs::create_dir_all(&source));
        let mount = format!("{source}:/data");
        let label = self.label.clone();
        let mut args = vec!["run", "-d", "--name", &n];
        if labelled {
            args.extend(["--label", &label]);
        }
        args.extend(["-v", &mount, IMAGE, "sleep", "600"]);
        let (ok, text) = pm(&self.podman, &args);
        assert!(ok, "could not create {n}: {text}");
        self.cleanup.containers.push(n.clone());
        n
    }

    fn state(&self, container: &str) -> String {
        pm(
            &self.podman,
            &["inspect", "--format", "{{.State.Status}}", "--", container],
        )
        .1
        .trim()
        .to_owned()
    }

    /// Runs `script` inside the ball with the real home visible to the host-side podman.
    fn run(&self, script: &str) -> (String, String) {
        let mut cmd = self
            .world
            .drive(DRIVE, &["run", "--", "/bin/sh", "-c", script]);
        // The harness clears the environment; podman needs the user's own to find its machine.
        for name in ["HOME", "CONTAINER_CONNECTION", "CONTAINER_HOST"] {
            if let Some(value) = std::env::var_os(name) {
                cmd.env(name, value);
            }
        }
        let out = assert_ok!(cmd.output());
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }
}

#[test]
fn ps_logs_stats_and_stop_work_on_labelled_and_named_containers_and_nothing_else_is_reachable() {
    let Some(binary) = enabled() else { return };
    let mut r = rig(binary, None);
    let labelled = r.container("a", true);
    let second = r.container("b", true);
    let named = r.container_named(&name("named"), false);
    let unlabelled = r.container("other", false);
    let (out, err) = r.run(&format!(
        "hb ctl ps; echo ---; hb ctl logs {labelled} --tail 5; echo \"logs rc=$?\"; hb ctl stats {labelled}; echo \"stats rc=$?\"; \
         hb ctl stop {unlabelled} 2>&1; echo \"unlabelled rc=$?\"; hb ctl stop {labelled}; echo \"stop rc=$?\"; \
         hb ctl stop {named}; echo \"named rc=$?\"; \
         /opt/homebrew/bin/podman ps >/dev/null 2>&1 && echo DIRECT-WORKED || echo direct-denied"
    ));
    assert!(
        out.contains(&format!("{labelled}\t"))
            && out.contains(&format!("{second}\t"))
            && out.contains(&format!("{named}\t")),
        "ps lists both labelled containers and the one listed by name: {out}{err}"
    );
    assert!(
        !out.contains(&format!("{unlabelled}\t")),
        "ps must not list a container outside the scope: {out}{err}"
    );
    assert!(
        out.contains("logs rc=0")
            && out.contains("stats rc=0")
            && out.contains("stop rc=0")
            && out.contains("named rc=0"),
        "{out}{err}"
    );
    assert!(
        out.contains("unlabelled rc=1") && out.contains("not in the approved scope"),
        "{out}{err}"
    );
    assert!(
        out.contains("direct-denied") && !out.contains("DIRECT-WORKED"),
        "{out}{err}"
    );
    assert_eq!(
        r.state(&named),
        "exited",
        "a container listed by name was stopped"
    );
    assert_eq!(
        r.state(&second),
        "running",
        "the other labelled container was not touched"
    );
    assert_eq!(r.state(&labelled), "exited", "stop took effect");
    assert_eq!(
        r.state(&unlabelled),
        "running",
        "a container outside the scope was not touched"
    );
}

#[test]
fn hostile_names_and_unsupported_commands_never_reach_podman() {
    let Some(binary) = enabled() else { return };
    let mut r = rig(binary, None);
    let labelled = r.container("a", true);
    let (out, err) = r.run(
        "for n in --help 'a;id' '../x' ''; do hb ctl restart \"$n\" 2>&1 | head -1; done; \
         hb ctl run alpine 2>&1 | head -1; hb ctl exec x 2>&1 | head -1; hb ctl cp a b 2>&1 | head -1; hb ctl rm x 2>&1 | head -1",
    );
    assert!(
        out.matches("unrecognized subcommand").count() >= 4 || out.contains("invalid"),
        "{out}{err}"
    );
    assert!(!out.contains("did"), "{out}");
    assert_eq!(r.state(&labelled), "running", "nothing was done to it");
}

#[test]
fn on_a_vm_that_shares_more_than_the_project_restart_is_refused_and_the_container_is_untouched() {
    let Some(binary) = enabled() else { return };
    if std::env::var_os("HB_PODMAN_DIR").is_some() {
        eprintln!("SKIP: HB_PODMAN_DIR is set, so the machine is meant to be isolated");
        return;
    }
    let mut r = rig(binary, None);
    let labelled = r.container("a", true);
    let before = pm(
        &r.podman,
        &[
            "inspect",
            "--format",
            "{{.State.StartedAt}}",
            "--",
            &labelled,
        ],
    )
    .1;
    let (out, err) = r.run(&format!("hb ctl restart {labelled} 2>&1; echo \"rc=$?\"; hb ctl logs {labelled} >/dev/null && echo logs-still-work"));
    assert!(
        out.contains("podman machine init --volume"),
        "the refusal names the fix: {out}{err}"
    );
    assert!(out.contains("logs-still-work"), "{out}{err}");
    let after = pm(
        &r.podman,
        &[
            "inspect",
            "--format",
            "{{.State.StartedAt}}",
            "--",
            &labelled,
        ],
    )
    .1;
    assert_eq!(before, after, "the container was not restarted");
    assert!(
        err.contains("start and restart are unavailable"),
        "startup warning: {err}"
    );
}

fn isolated_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(std::env::var_os("HB_PODMAN_DIR")?);
    assert!(dir.is_dir(), "HB_PODMAN_DIR is not a directory");
    Some(dir)
}

#[test]
fn on_a_project_only_vm_restart_works_and_a_swapped_source_does_not_expose_a_canary() {
    let Some(binary) = enabled() else { return };
    let Some(dir) = isolated_dir() else {
        eprintln!(
            "SKIP: HB_PODMAN_DIR is not set; this test needs a machine that shares only that directory"
        );
        return;
    };
    let dir = fs::canonicalize(dir).unwrap_or_default();
    // The machine shares exactly `dir`, so the project IS `dir`: start from an empty one.
    for entry in assert_ok!(fs::read_dir(&dir)).flatten() {
        let _ = fs::remove_dir_all(entry.path()).or_else(|_| fs::remove_file(entry.path()));
    }
    let mut r = rig_at(binary, &dir);
    let _clean = Emptied(dir.clone());
    let labelled = r.container("a", true);
    // The agent inside the ball cannot swap the mounted directory (pin), and restart works.
    let (out, err) = r.run(&format!(
        "mv data data-old 2>/dev/null && echo SWAPPED || echo swap-blocked; hb ctl restart {labelled}; echo \"restart rc=$?\""
    ));
    assert!(
        out.contains("swap-blocked") && !out.contains("SWAPPED"),
        "{out}{err}"
    );
    assert!(out.contains("restart rc=0"), "{out}{err}");
    assert_eq!(r.state(&labelled), "running");

    // The owner (outside the ball) swaps the source to a path the VM does not share, then asks again:
    // the restart fails and no canary from outside is exposed.
    let outside = assert_ok!(
        tempfile::Builder::new()
            .prefix("hb-m8-out")
            .tempdir_in("/tmp")
    );
    write(&outside.path().join("canary"), "OUTSIDE\n");
    let data = r.world.project.join("data");
    assert_ok!(fs::rename(&data, r.world.project.join("data-real")));
    assert_ok!(std::os::unix::fs::symlink(outside.path(), &data));
    // (preflight now refuses the symlink source before podman is asked)
    let (out, err) = r.run(&format!("hb ctl restart {labelled} 2>&1; echo \"rc=$?\""));
    assert!(
        out.contains("rc=1") || out.contains("symlink") || out.contains("refused"),
        "{out}{err}"
    );
    let (_, copied) = pm(&r.podman, &["exec", "--", &labelled, "cat", "/data/canary"]);
    assert!(
        !copied.contains("OUTSIDE"),
        "the canary must not be readable in the container: {copied}"
    );
}

#[test]
fn the_vm_ssh_port_is_open_outside_the_ball_and_unreachable_inside_it() {
    let Some(binary) = enabled() else { return };
    let (ok, text) = pm(&binary, &["machine", "inspect"]);
    assert!(ok, "podman machine inspect failed: {text}");
    let port = text
        .split("\"Port\":")
        .nth(1)
        .and_then(|rest| {
            rest.trim_start()
                .split(|c: char| !c.is_ascii_digit())
                .next()
        })
        .and_then(|digits| digits.parse::<u16>().ok());
    let Some(port) = port else {
        eprintln!("SKIP: could not read the machine's SSH port");
        return;
    };
    let reach = format!("/usr/bin/nc -z -w 2 127.0.0.1 {port}");
    let outside = assert_ok!(Command::new("/bin/sh").args(["-c", &reach]).status());
    assert!(
        outside.success(),
        "control: the SSH port {port} must be open outside the ball"
    );
    let r = rig(binary, None);
    let (out, err) = r.run(&format!("{reach} && echo SSH-REACHED || echo ssh-blocked"));
    assert!(
        out.contains("ssh-blocked") && !out.contains("SSH-REACHED"),
        "{out}{err}"
    );
}
