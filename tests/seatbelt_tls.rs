// ABOUTME: Real-sandbox tests of the system-trust grant and of the keychain floor, using throwaway keychains only.
// ABOUTME: Pins the measured minimum of design 4.5 (D62) and shows the floor, not securityd, keeps a keychain secret out.
//! Black-box tests of `tls.system_trust` and the `~/Library/Keychains` floor.
//!
//! The keychain tests never touch a real keychain: they create keychains inside the test's own
//! temporary home, and every `security` call that sets one up or tears it down runs under a write
//! guard that denies writes to the real home and `user-preference-write`, so the user's keychain
//! search list cannot change. The test compares the search list before and after.

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use claims::assert_ok;
use common::{World, quote, run, sandbox_available, stderr, succeeds};
use hamster_ball::seatbelt::RenderInputs;
use pretty_assertions::assert_eq;

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

const SECURITY: &str = "/usr/bin/security";
const SYSTEM_KEYCHAIN: &str = "/Library/Keychains/System.keychain";
const SECRET: &str = "SECRETVALUE";

fn trusting(on: bool) -> String {
    format!("[fs]\nwrite = [\".\"]\n[tls]\nsystem_trust = {on}\n")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

// ====================================================================================
// The grant is the measured minimum
// ====================================================================================

#[test]
fn system_trust_opens_the_system_keychain_file_and_not_its_neighbours() {
    sandboxed!();
    let on = World::new(&trusting(true));
    let off = World::new(&trusting(false));
    let (p_on, p_off) = (
        on.render(&RenderInputs::new()),
        off.render(&RenderInputs::new()),
    );
    let read = format!("/bin/cat {SYSTEM_KEYCHAIN} > /dev/null");
    assert!(
        succeeds(&run(&p_on, &on.home_dir(), &on.project, &read)),
        "the file Security.framework opens must be readable with system_trust"
    );
    assert!(
        !succeeds(&run(&p_off, &off.home_dir(), &off.project, &read)),
        "control: without system_trust the same read is refused"
    );
    // Paired: a world-readable sibling that no tested client opens stays closed.
    let sibling = "/Library/Keychains/apsd.keychain";
    if Path::new(sibling).exists() {
        let out = run(
            &p_on,
            &on.home_dir(),
            &on.project,
            &format!("/bin/cat {sibling} > /dev/null"),
        );
        assert!(!succeeds(&out), "{sibling} must not be granted");
    }
}

#[test]
fn system_trust_lets_security_list_system_certificates_through_securityserver() {
    sandboxed!();
    let on = World::new(&trusting(true));
    let off = World::new(&trusting(false));
    let script = format!("{SECURITY} find-certificate -a {SYSTEM_KEYCHAIN} | /usr/bin/wc -l");
    let lines = |w: &World| {
        let out = run(
            &w.render(&RenderInputs::new()),
            &w.home_dir(),
            &w.project,
            &script,
        );
        stdout(&out).trim().parse::<usize>().unwrap_or(0)
    };
    assert!(
        lines(&on) > 0,
        "SecurityServer plus the keychain read must be enough"
    );
    assert_eq!(lines(&off), 0, "control: no grant, no certificates");
}

#[test]
fn system_trust_is_what_lets_the_agent_see_the_hosts_proxy_settings() {
    sandboxed!();
    // Read only: `scutil --proxy` prints the system proxy and PAC settings and changes nothing.
    // Nothing here sets a proxy, so the test does not show a PAC being followed (design 4.5).
    let settings = |on: bool| {
        let w = World::new(&trusting(on));
        let out = run(
            &w.render(&RenderInputs::new()),
            &w.home_dir(),
            &w.project,
            "/usr/sbin/scutil --proxy",
        );
        stdout(&out)
    };
    let (on, off) = (settings(true), settings(false));
    assert!(
        on.contains("ExceptionsList") || on.contains("Proxy") || on.contains("PAC"),
        "with configd granted scutil should print the host's settings: {on:?}"
    );
    assert_eq!(
        off.trim(),
        "<dictionary> {\n}",
        "control: without configd the settings are empty, not an error"
    );
}

#[test]
fn system_trust_does_not_reach_services_no_tested_client_needed() {
    sandboxed!();
    let w = World::new(&trusting(true));
    let p = w.render(&RenderInputs::new());
    for denied in ["com.apple.securityd", "com.apple.securityd.xpc"] {
        assert!(
            !p.text.contains(denied),
            "{denied} must not be in the profile"
        );
    }
    assert!(!p.text.contains("/private/var/db/mds"));
    assert!(!p.text.contains("kCFPreferencesAnyApplication"));
}

// ====================================================================================
// The floor, not securityd, keeps the keychain file out
// ====================================================================================

/// Runs `security` setup and teardown under a guard that cannot write the real home.
struct Guard {
    profile: String,
    search_list_before: String,
}

impl Guard {
    fn new() -> Self {
        let real_home = std::env::var("HOME").unwrap_or_else(|_| "/Users".to_owned());
        let profile = format!(
            "(version 1)(allow default)(deny file-write* (subpath {real_home:?}))(deny user-preference-write)"
        );
        Self {
            profile,
            search_list_before: Self::search_list(),
        }
    }

    fn search_list() -> String {
        let out = assert_ok!(
            Command::new(SECURITY)
                .args(["list-keychains", "-d", "user"])
                .output()
        );
        stdout(&out)
    }

    fn security(&self, args: &[&str]) -> Output {
        assert_ok!(
            Command::new("/usr/bin/sandbox-exec")
                .args(["-p", &self.profile, SECURITY])
                .args(args)
                .output()
        )
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        // Runs while unwinding too: a failed assertion must not hide a changed search list.
        if !std::thread::panicking() {
            assert_eq!(
                Self::search_list(),
                self.search_list_before,
                "the user's keychain search list changed"
            );
        }
    }
}

/// A throwaway unlocked keychain holding [`SECRET`] under the service `hbtest`.
struct Keychain {
    path: PathBuf,
}

impl Keychain {
    fn create(guard: &Guard, path: PathBuf) -> Self {
        let text = path.to_string_lossy().into_owned();
        assert_ok!(fs::create_dir_all(assert_ok!(
            path.parent().ok_or("no parent")
        )));
        for args in [
            vec!["create-keychain", "-p", "x", text.as_str()],
            vec![
                "add-generic-password",
                "-a",
                "a",
                "-s",
                "hbtest",
                "-w",
                SECRET,
                "-A",
                text.as_str(),
            ],
            vec!["unlock-keychain", "-p", "x", text.as_str()],
        ] {
            let out = guard.security(&args);
            assert!(succeeds(&out), "{args:?}: {}", stderr(&out));
        }
        Self { path }
    }

    fn lookup(&self) -> String {
        format!(
            "{SECURITY} find-generic-password -s hbtest -w {}",
            quote(&self.path)
        )
    }

    fn delete(&self, guard: &Guard) {
        let _ = guard.security(&["delete-keychain", &self.path.to_string_lossy()]);
    }
}

#[test]
fn the_floor_keeps_a_keychain_secret_out_even_though_securityserver_is_reachable() {
    sandboxed!();
    let w = World::new(&trusting(true));
    let guard = Guard::new();
    // The same keychain content, once where the floor protects it and once in the project.
    let floored = Keychain::create(
        &guard,
        w.home_dir().join("Library/Keychains/throwaway.keychain-db"),
    );
    let open = Keychain::create(&guard, w.project.join("throwaway.keychain-db"));
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();

    // Control: the secret is reachable through the sandbox's own SecurityServer grant.
    let allowed = run(&p, &home, &w.project, &open.lookup());
    assert_eq!(stdout(&allowed).trim(), SECRET, "{}", stderr(&allowed));

    // The floor denies the client the file; securityd never gets the chance to answer.
    let blocked = run(&p, &home, &w.project, &floored.lookup());
    assert!(
        !stdout(&blocked).contains(SECRET),
        "the floor leaked a keychain secret"
    );
    assert!(!succeeds(&blocked));
    // Metadata is hidden too (design D51): the file cannot even be statted.
    let stat = run(
        &p,
        &home,
        &w.project,
        &format!("/usr/bin/stat {}", quote(&floored.path)),
    );
    assert!(!succeeds(&stat));
    // And writing a new item through securityd is refused.
    let add = run(
        &p,
        &home,
        &w.project,
        &format!(
            "{SECURITY} add-generic-password -a a -s other -w v {}",
            quote(&floored.path)
        ),
    );
    assert!(!succeeds(&add));

    floored.delete(&guard);
    open.delete(&guard);
}
