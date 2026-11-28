// ABOUTME: The probe matrix of design section 16: real programs under the real sandbox-exec, started through session::run.
// ABOUTME: Each probe pairs a denied case with an allowed one; see the table in section 16 for which test covers which claim.
//! Integration probes that the design's claims about Seatbelt still hold (hb-ghd.2.5).
//!
//! Seatbelt is undocumented and changes between macOS releases. These tests run ordinary tools
//! through `session::run` (the real policy, renderer, empty environment, session directory and
//! child helper) and check what they can and cannot do. Under deny-default a denial alone proves
//! little, so every probe has an allowed twin in the same world, or an unsandboxed control.
//!
//! After a macOS upgrade, or any change to the profile:
//! `HB_REQUIRE_SANDBOX=1 cargo test --all-features`

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::symlink;
use std::process::Command;

use claims::{assert_err, assert_ok};
use common::{World, hb_succeeds, hb_text, quote, sandbox_available, sh_in_hb, toml_string, write};
use pretty_assertions::assert_eq;

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

/// Whether `script` ran and exited 0 inside the world.
fn works(world: &World, script: &str) -> bool {
    hb_succeeds(&sh_in_hb(world, script))
}

/// The same command outside any sandbox (the control that the tool itself works).
fn outside(program: &str, args: &[&str]) -> std::process::Output {
    assert_ok!(Command::new(program).args(args).output())
}

// ====================================================================================
// Reads: credentials and personal directories
// ====================================================================================

#[test]
fn credential_and_personal_directories_cannot_be_read_by_any_tool_while_the_project_can() {
    sandboxed!();
    let w = World::new(PROJECT);
    let home = w.home_dir();
    let proj = &w.project;
    // Targets: a file in each place, plus a symlink in each (so `readlink` has something to say).
    for dir in [".ssh", ".aws", "Documents"] {
        write(&home.join(dir).join("probe.txt"), "secret");
        assert_ok!(symlink("/usr/bin", home.join(dir).join("probe-link")));
    }
    write(&proj.join("probe.txt"), "fine");
    assert_ok!(symlink("/usr/bin", proj.join("probe-link")));

    let file_tools = [
        "/bin/cat",
        "/usr/bin/stat",
        "/bin/ls -ld",
        "/usr/bin/xattr -l",
        "/bin/test -e",
    ];
    // The twin first: every tool works on the project's own file, and `readlink` on its link.
    for tool in file_tools {
        let script = format!("{tool} {}", quote(&proj.join("probe.txt")));
        assert!(works(&w, &script), "control: {script}");
    }
    let readlink_ok = format!("/usr/bin/readlink {}", quote(&proj.join("probe-link")));
    assert!(works(&w, &readlink_ok), "control: {readlink_ok}");

    // Floor paths: every tool is refused, metadata included (design D51: the floor names the
    // metadata operations in its deny, because the baseline allows metadata everywhere).
    for dir in [".ssh", ".aws"] {
        for tool in file_tools {
            let script = format!("{tool} {}", quote(&home.join(dir).join("probe.txt")));
            assert!(!works(&w, &script), "{script} reached ~/{dir}");
        }
        let script = format!(
            "/usr/bin/readlink {}",
            quote(&home.join(dir).join("probe-link"))
        );
        assert!(!works(&w, &script), "{script} reached ~/{dir}");
        let listing = format!("/bin/ls {}", quote(&home.join(dir)));
        assert!(!works(&w, &listing), "{listing} listed ~/{dir}");
    }
    // A directory that is merely not granted: the contents are refused. Metadata is not: the
    // baseline allows `file-read-metadata` everywhere, so `stat`, `ls -ld`, `test -e` and
    // `readlink` still answer (design D51). Pinned here so a change shows up.
    let documents = home.join("Documents");
    for tool in ["/bin/cat", "/usr/bin/xattr -l"] {
        let script = format!("{tool} {}", quote(&documents.join("probe.txt")));
        assert!(!works(&w, &script), "{script} read ~/Documents");
    }
    assert!(!works(&w, &format!("/bin/ls {}", quote(&documents))));
    for tool in ["/usr/bin/stat", "/bin/ls -ld", "/bin/test -e"] {
        let script = format!("{tool} {}", quote(&documents.join("probe.txt")));
        assert!(works(&w, &script), "metadata of ~/Documents: {script}");
    }
    let link = format!("/usr/bin/readlink {}", quote(&documents.join("probe-link")));
    assert!(works(&w, &link), "metadata of ~/Documents: {link}");
}

// ====================================================================================
// Writes: places that plant code a later shell runs
// ====================================================================================

#[test]
fn the_floor_keeps_the_path_directories_and_shell_startup_unwritable_beside_writable_siblings() {
    sandboxed!();
    // Grants that cover the protected places, so only the floor can be what refuses them.
    let w = World::new("[fs]\nwrite = [\".\", \"~/.local\", \"~/.cargo\"]\n");
    let home = w.home_dir();
    for dir in [
        ".local/bin",
        ".local/share",
        ".cargo/bin",
        ".cargo/registry",
    ] {
        assert_ok!(fs::create_dir_all(home.join(dir)));
    }
    write(&home.join(".zshrc"), "# user\n");

    // Allowed twins: the project, and a sibling inside each granted directory.
    for target in [
        w.project.join("ok"),
        home.join(".local/share/ok"),
        home.join(".cargo/registry/ok"),
    ] {
        let script = format!("echo x > {}", quote(&target));
        assert!(works(&w, &script), "control: {script}");
    }
    for target in [
        home.join(".local/bin/planted"),
        home.join(".cargo/bin/planted"),
    ] {
        let script = format!("echo x > {}", quote(&target));
        assert!(!works(&w, &script), "{script} planted code on PATH");
        assert!(!target.exists());
    }
    let append = format!("echo 'evil' >> {}", quote(&home.join(".zshrc")));
    assert!(!works(&w, &append));
    assert_eq!(
        assert_ok!(fs::read_to_string(home.join(".zshrc"))),
        "# user\n"
    );
}

// ====================================================================================
// Paths: symlinked /tmp and unusual names
// ====================================================================================

#[test]
fn a_tree_under_the_symlinked_tmp_works_whether_a_grant_is_spelled_through_the_link_or_not() {
    sandboxed!();
    let w = World::under_symlinked_tmp("", PROJECT);
    let data = w.home_dir().join("data");
    let other = w.home_dir().join("other");
    assert_ok!(fs::create_dir_all(&data));
    assert_ok!(fs::create_dir_all(&other));
    let spelled = w.spelled(&data);
    assert!(
        spelled.starts_with("/tmp"),
        "the world must sit under /tmp: {}",
        spelled.display()
    );
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string(&spelled.to_string_lossy())
    ));

    // Control: the working directory is usable (`uv_cwd` failed here before canonicalization).
    let cwd = "/usr/bin/perl -MCwd -e 'print getcwd(), qq(\\n)' && /bin/pwd -P";
    let out = sh_in_hb(&w, cwd);
    assert!(hb_succeeds(&out), "{}", hb_text(&out));
    assert!(hb_text(&out).contains("/private/tmp/"), "{}", hb_text(&out));
    // The grant spelled through `/tmp` reaches the real directory, by either spelling.
    for dir in [&spelled, &data] {
        let script = format!("echo x > {}", quote(&dir.join("f")));
        assert!(works(&w, &script), "{script}");
    }
    assert!(data.join("f").exists());
    // And only that directory: a neighbour spelled through the link is not granted.
    let neighbour = format!("echo x > {}", quote(&w.spelled(&other).join("f")));
    assert!(!works(&w, &neighbour), "{neighbour}");
    assert!(!other.join("f").exists());
}

#[test]
fn a_file_name_with_a_newline_works_in_the_project_and_a_config_path_with_one_is_refused() {
    sandboxed!();
    let w = World::new(PROJECT);
    // A name with a newline inside a granted directory is an ordinary file.
    assert!(works(
        &w,
        "echo x > \"$(printf 'a\\nb')\" && /bin/test -e \"$(printf 'a\\nb')\""
    ));
    assert!(w.project.join("a\nb").exists());
    // A name with a newline is not usable in a grant: the config is refused, naming the key, so
    // no newline can reach the profile text.
    let bad = w.home_dir().join("data").join("line\nbreak");
    assert_ok!(fs::create_dir_all(&bad));
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string(&bad.to_string_lossy())
    ));
    let error = assert_err!(w.try_loaded()).to_string();
    assert!(
        error.contains("fs.write") || error.contains("hamster-ball.toml"),
        "the error should say which entry: {error}"
    );
}

#[test]
fn a_case_variant_of_a_floor_path_is_denied_and_one_of_an_allowed_path_is_not() {
    sandboxed!();
    // The file system is case-insensitive: `GH` is the directory `gh`.
    let w = World::new("[fs]\nwrite = [\".\", \"~/.config\"]\n");
    let home = w.home_dir();
    write(&home.join(".config/gh/hosts.yml"), "token: secret\n");
    write(&home.join(".config/ok/file"), "fine");
    for allowed in [".config/ok/file", ".config/OK/file", ".CONFIG/ok/file"] {
        let script = format!("/bin/cat {}", quote(&home.join(allowed)));
        assert!(works(&w, &script), "control: {script}");
    }
    for denied in [
        ".config/gh/hosts.yml",
        ".config/GH/hosts.yml",
        ".CONFIG/Gh/HOSTS.yml",
    ] {
        let script = format!("/bin/cat {}", quote(&home.join(denied)));
        assert!(!works(&w, &script), "{script} read the floor path");
    }
}

#[test]
fn an_nfd_spelling_of_a_name_is_the_same_directory_for_a_grant_and_for_a_deny() {
    sandboxed!();
    let nfc = "caf\u{e9}";
    let nfd = "cafe\u{301}";
    let w = World::new(PROJECT);
    let home = w.home_dir();
    let granted = home.join("data").join(nfc);
    let secret = home.join("data").join("vault").join(nfc);
    assert_ok!(fs::create_dir_all(&granted));
    write(&secret.join("s"), "secret");
    write(&home.join("data/vault/plain"), "fine");
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", {}, {}]\ndeny_read = [{}]\n",
        toml_string(&granted.to_string_lossy()),
        toml_string(&home.join("data/vault").to_string_lossy()),
        toml_string(&secret.to_string_lossy()),
    ));
    // A grant written in one form is usable in the other; a neighbour is still refused.
    for name in [nfc, nfd] {
        let script = format!("echo x > {}/f", quote(&home.join("data").join(name)));
        assert!(works(&w, &script), "control: {script}");
    }
    assert!(!works(
        &w,
        &format!("echo x > {}/f", quote(&home.join("other")))
    ));
    // A deny written in one form refuses both; its sibling stays readable.
    for name in [nfc, nfd] {
        let script = format!("/bin/cat {}/s", quote(&home.join("data/vault").join(name)));
        assert!(!works(&w, &script), "{script} read the denied directory");
    }
    assert!(works(
        &w,
        &format!("/bin/cat {}", quote(&home.join("data/vault/plain")))
    ));
}

// ====================================================================================
// Network: resolver
// ====================================================================================

#[test]
fn name_resolution_through_the_system_resolver_fails_while_the_hosts_file_still_answers() {
    sandboxed!();
    let resolve =
        |name: &str| format!("/usr/bin/perl -e 'exit(gethostbyname(\"{name}\") ? 0 : 1)'");
    // Control outside: the resolver works on this machine, or the test says nothing.
    if !assert_ok!(
        Command::new("/bin/sh")
            .args(["-c", &resolve("example.com")])
            .status()
    )
    .success()
    {
        eprintln!("SKIP: no DNS on this machine");
        return;
    }
    let w = World::new(PROJECT);
    assert!(works(&w, &resolve("localhost")), "/etc/hosts must answer");
    assert!(!works(&w, &resolve("example.com")), "DNS must not");
}

// ====================================================================================
// Programs that reach outside the ball
// ====================================================================================

#[test]
fn sudo_cannot_start_while_an_ordinary_program_can() {
    sandboxed!();
    // Control: `sudo -V` needs no password and works outside.
    assert!(outside("/usr/bin/sudo", &["-V"]).status.success());
    let w = World::new(PROJECT);
    assert!(works(&w, "/usr/bin/true"));
    assert!(!works(&w, "/usr/bin/sudo -V"));
}

#[test]
fn the_pasteboard_cannot_be_read_or_written_by_the_command_line_tools() {
    sandboxed!();
    // Control: `pbpaste` works outside. The test never writes the user's clipboard.
    if !outside("/usr/bin/pbpaste", &[]).status.success() {
        eprintln!("SKIP: no pasteboard in this session");
        return;
    }
    let w = World::new(PROJECT);
    assert!(works(&w, "/usr/bin/true"));
    assert!(!works(&w, "/usr/bin/pbpaste"));
    assert!(!works(&w, "echo hb-probe | /usr/bin/pbcopy"));
}

#[test]
fn launchservices_shows_no_applications_and_open_cannot_start_one() {
    sandboxed!();
    // Control: LaunchServices answers outside. `lsappinfo` only asks; nothing is started.
    let find = "/usr/bin/lsappinfo find bundleid=com.apple.finder";
    let seen = outside("/bin/sh", &["-c", find]);
    if String::from_utf8_lossy(&seen.stdout).trim().is_empty() {
        eprintln!("SKIP: LaunchServices has no Finder (no login session)");
        return;
    }
    let w = World::new(PROJECT);
    assert!(works(&w, "/usr/bin/osascript -e '1 + 1'"), "plain script");
    let out = sh_in_hb(&w, find);
    assert_eq!(hb_text(&out).trim(), "", "LaunchServices answered: {out:?}");
    // `open -a` goes through the same service. Skip the launch check when the user already has
    // the application open, so the test never decides what was started.
    if outside("/usr/bin/pgrep", &["-x", "Calculator"])
        .status
        .success()
    {
        eprintln!("SKIP: Calculator is already running");
        return;
    }
    let open = sh_in_hb(&w, "/usr/bin/open -g -j -a Calculator");
    let started = outside("/usr/bin/pgrep", &["-x", "Calculator"])
        .status
        .success();
    if started {
        // Clean up before failing: a regression must not leave an application behind.
        let _ = outside("/usr/bin/pkill", &["-x", "Calculator"]);
    }
    assert!(!hb_succeeds(&open), "{}", hb_text(&open));
    assert!(!started, "open -a started Calculator inside the ball");
}

/// A script that sends `core/getd` (no parameters, so the target changes nothing) to a pid.
const AE_SEND: &str = r#"
import ctypes, ctypes.util, sys
AS = ctypes.CDLL(ctypes.util.find_library("ApplicationServices"))
class AEDesc(ctypes.Structure):
    _fields_ = [("descriptorType", ctypes.c_uint32), ("dataHandle", ctypes.c_void_p)]
def four(s): return int.from_bytes(s.encode(), "big")
target, event, reply = AEDesc(), AEDesc(), AEDesc()
pid = ctypes.c_int32(int(sys.argv[1]))
AS.AECreateDesc(four("kpid"), ctypes.byref(pid), 4, ctypes.byref(target))
AS.AECreateAppleEvent(four("core"), four("getd"), ctypes.byref(target), ctypes.c_int16(-1), ctypes.c_int32(0), ctypes.byref(event))
AS.AESendMessage.argtypes = [ctypes.POINTER(AEDesc), ctypes.POINTER(AEDesc), ctypes.c_int32, ctypes.c_long]
print("SENT", AS.AESendMessage(ctypes.byref(event), ctypes.byref(reply), ctypes.c_int32(3), ctypes.c_long(300)))
"#;

#[test]
fn an_apple_event_cannot_be_delivered_to_a_running_application() {
    sandboxed!();
    let finder = outside("/usr/bin/pgrep", &["-x", "Finder"]);
    let pid = String::from_utf8_lossy(&finder.stdout)
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    if pid.is_empty() {
        eprintln!("SKIP: no Finder running (no login session)");
        return;
    }
    let w = World::new(PROJECT);
    write(&w.project.join("ae_send.py"), AE_SEND);
    let script = w.project.join("ae_send.py");
    // Control: the same script outside the sandbox delivers the event.
    let control = outside("/usr/bin/python3", &[&script.to_string_lossy(), &pid]);
    if !String::from_utf8_lossy(&control.stdout).contains("SENT 0") {
        eprintln!(
            "SKIP: could not send an Apple Event outside the sandbox: {}",
            String::from_utf8_lossy(&control.stderr)
        );
        return;
    }
    let inside = sh_in_hb(&w, &format!("/usr/bin/python3 ae_send.py {pid}"));
    let said = hb_text(&inside);
    assert!(said.contains("SENT "), "the script did not run: {said}");
    assert!(
        !said.contains("SENT 0"),
        "an Apple Event reached a running application: {said}"
    );
    // The scripting front end agrees: Finder is invisible and its terminology is unavailable.
    let finder_says = sh_in_hb(
        &w,
        "/usr/bin/osascript -e 'tell application \"Finder\" to get name of home'",
    );
    assert!(!hb_succeeds(&finder_says), "{}", hb_text(&finder_says));
}

// ====================================================================================
// launchd (design 4.6)
// ====================================================================================

const BASE_ON: &str = "[system]\nlaunchctl = true\n";

fn uid() -> String {
    let out = outside("/usr/bin/id", &["-u"]);
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

/// Whether `csrutil` says System Integrity Protection is disabled. False if it cannot tell.
fn sip_disabled() -> bool {
    Command::new("/usr/bin/csrutil")
        .arg("status")
        .output()
        .is_ok_and(|out| {
            String::from_utf8_lossy(&out.stdout)
                .to_lowercase()
                .contains("disabled")
        })
}

#[test]
fn launchctl_cannot_run_unless_the_users_own_config_turns_it_on() {
    sandboxed!();
    // Control: `launchctl version` changes nothing and works outside.
    assert!(outside("/bin/launchctl", &["version"]).status.success());
    let off = World::new(PROJECT);
    assert!(works(&off, "/usr/bin/true"));
    assert!(!works(&off, "/bin/launchctl version"), "off by default");
    let on = World::with_base(BASE_ON, PROJECT);
    assert!(
        works(&on, "/bin/launchctl version"),
        "turned on in the base"
    );
    // A project may refuse what the user allowed.
    let refused = World::with_base(
        BASE_ON,
        "[fs]\nwrite = [\".\"]\n[system]\nlaunchctl = false\n",
    );
    assert!(!works(&refused, "/bin/launchctl version"));
    // A copy in the project does not get around the denial: macOS kills a platform binary that
    // is not on the system volume. (Checked on arm64; see design 4.6 for what is not.) With SIP
    // disabled, as on the hosted CI runner (measured), macOS does not kill it, so there is nothing
    // to check there. Where SIP is unknown the check runs.
    if sip_disabled() {
        eprintln!("SKIP: SIP is disabled, so a copied platform binary is not killed");
        return;
    }
    let copy = sh_in_hb(&off, "/bin/cp /bin/launchctl ./lc && ./lc version");
    assert!(!hb_succeeds(&copy), "{}", hb_text(&copy));
}

#[test]
fn a_project_file_cannot_turn_launchctl_on() {
    sandboxed!();
    let w = World::with_base(
        BASE_ON,
        "[fs]\nwrite = [\".\"]\n[system]\nlaunchctl = true\n",
    );
    let error = assert_err!(w.try_loaded()).to_string();
    assert!(error.contains("system.launchctl = true"), "{error}");
}

#[test]
fn a_job_cannot_be_created_from_inside_even_when_launchctl_is_on() {
    sandboxed!();
    let w = World::with_base(BASE_ON, PROJECT);
    let uid = uid();
    let label = format!("hb.probe.create.{}", std::process::id());
    let plist = w.project.join("job.plist");
    write(
        &plist,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>/usr/bin/true</string></array>\n</dict></plist>\n"
        ),
    );
    // Whatever happens, leave no job behind in the user's launchd.
    let _cleanup = Unload(format!("gui/{uid}/{label}"));
    let boot = sh_in_hb(
        &w,
        &format!("/bin/launchctl bootstrap gui/{uid} {}", quote(&plist)),
    );
    assert!(
        !hb_succeeds(&boot),
        "launchd accepted a job from inside the ball"
    );
    let listed = outside("/bin/launchctl", &["print", &format!("gui/{uid}/{label}")]);
    assert!(!listed.status.success(), "the job exists");
    // Control: the same plist loads from outside.
    let control = outside(
        "/bin/launchctl",
        &["bootstrap", &format!("gui/{uid}"), &plist.to_string_lossy()],
    );
    assert!(
        control.status.success(),
        "{}",
        String::from_utf8_lossy(&control.stderr)
    );
}

/// Unloads a launchd service when dropped, whether or not the test got that far.
struct Unload(String);

impl Drop for Unload {
    fn drop(&mut self) {
        let _ = Command::new("/bin/launchctl")
            .args(["bootout", &self.0])
            .output();
    }
}

/// What `system.launchctl = true` lets the agent do to jobs that already exist (design 4.6).
///
/// `disable` and `unload` of a job that is not running also work (measured by hand, see 4.6); they
/// are not run here because launchd keeps a record of every enable and disable.
///
/// Opt-in because it loads a throwaway job into your launchd (removed afterwards). Run it with
/// `cargo test --features test-support --test probe_matrix -- --ignored launchctl`.
#[test]
#[ignore = "loads a throwaway job into the user's launchd"]
fn with_launchctl_on_the_agent_can_start_a_job_that_is_not_running_but_not_restart_or_unload_a_running_one()
 {
    sandboxed!();
    let w = World::with_base(BASE_ON, PROJECT);
    let uid = uid();
    let label = format!("hb.probe.gap.{}", std::process::id());
    let service = format!("gui/{uid}/{label}");
    let marker = w.base.join("ran");
    let plist = w.base.join("gap.plist");
    write(
        &plist,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{label}</string>\n<key>ProgramArguments</key><array><string>/bin/sh</string><string>-c</string><string>touch {m}; sleep 30</string></array>\n</dict></plist>\n",
            m = marker.display()
        ),
    );
    let _cleanup = Unload(service.clone());
    let load = outside(
        "/bin/launchctl",
        &["bootstrap", &format!("gui/{uid}"), &plist.to_string_lossy()],
    );
    assert!(
        load.status.success(),
        "{}",
        String::from_utf8_lossy(&load.stderr)
    );
    // Start a job that is not running: it runs outside the ball.
    assert!(works(&w, &format!("/bin/launchctl kickstart {service}")));
    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(marker.exists(), "the job did not run");
    // A running job is out of reach: no restart, no unload.
    assert!(!works(
        &w,
        &format!("/bin/launchctl kickstart -k {service}")
    ));
    assert!(!works(&w, &format!("/bin/launchctl bootout {service}")));
    // Control: the same bootout works outside.
    assert!(
        outside("/bin/launchctl", &["bootout", &service])
            .status
            .success()
    );
}
