// ABOUTME: TLS handshakes from real clients under the generated profile, against a local server whose CA is throwaway.
// ABOUTME: Node's four settings run through hb itself; curl, git, Python and uv show the minimal grants do not break them.
//! Black-box tests of `tls.system_trust` and `tls.extra_ca_files` (design 4.5, hb-ghd.2.2).
//!
//! Nothing here touches the network or the user's keychain: the server is `openssl s_server` on
//! loopback and the CA is made for the test. What a throwaway CA cannot show (system trust
//! verifying a root that is in the keychain) is in `tests/tls_inspection.rs`.

#![cfg(target_os = "macos")]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use claims::assert_ok;
use common::tls::{TlsFixture, openssl_available};
use common::{World, run, sandbox_available, without_lines};
use hamster_ball::seatbelt::RenderInputs;
use tempfile::TempDir;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");

macro_rules! ready {
    () => {
        if !sandbox_available() || !openssl_available() {
            eprintln!("SKIP: no sandbox-exec or no system openssl");
            return;
        }
    };
}

/// The first `name` on `PATH`, resolved to its real file.
fn find(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .and_then(|candidate| fs::canonicalize(candidate).ok())
}

/// Every distinct Node the machine has: the one on `PATH`, Homebrew's, and each nvm install.
fn nodes() -> Vec<PathBuf> {
    let mut found: BTreeSet<PathBuf> = BTreeSet::new();
    found.extend(find("node"));
    if let Ok(real) = fs::canonicalize("/opt/homebrew/bin/node") {
        found.insert(real);
    }
    if let Some(home) = std::env::var_os("HOME") {
        let versions = Path::new(&home).join(".nvm/versions/node");
        if let Ok(entries) = fs::read_dir(versions) {
            for entry in entries.flatten() {
                if let Ok(real) = fs::canonicalize(entry.path().join("bin/node")) {
                    found.insert(real);
                }
            }
        }
    }
    found.into_iter().collect()
}

/// What a program needs read access to in order to start: its install tree.
fn install_tree(binary: &Path) -> PathBuf {
    if binary.starts_with("/opt/homebrew") {
        return PathBuf::from("/opt/homebrew");
    }
    binary
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| binary.to_path_buf(), Path::to_path_buf)
}

fn toml_path(path: &Path) -> String {
    common::toml_string(&path.to_string_lossy())
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

// ====================================================================================
// Node: the four combinations, through hb
// ====================================================================================

const CHECK_JS: &str = "const https = require('https');\n\
    const req = https.get({ host: 'localhost', port: Number(process.argv[2]), path: '/', timeout: 8000 },\n\
      (res) => { res.resume(); console.log('VERIFIED'); process.exit(0); });\n\
    req.on('error', (e) => { console.log('FAIL ' + (e.code || e.message)); process.exit(1); });\n";

/// One run of Node under hb with the given settings, as the verdict line it printed.
fn node_verdict(node: &Path, fixture: &TlsFixture, system_trust: bool, extra_ca: bool) -> String {
    let extra = if extra_ca {
        format!("extra_ca_files = [{}]\n", toml_path(&fixture.ca))
    } else {
        String::new()
    };
    let world = World::with_base(
        &format!("[tls]\nsystem_trust = {system_trust}\n"),
        &format!(
            "[fs]\nread = [{}]\nwrite = [\".\"]\n[net]\nloopback_ports = [{}]\n[tls]\n{extra}",
            toml_path(&install_tree(node)),
            fixture.port
        ),
    );
    common::write(&world.project.join("check.js"), CHECK_JS);
    let output = assert_ok!(
        world
            .drive(
                DRIVE,
                &[
                    "run",
                    "--",
                    &node.to_string_lossy(),
                    "check.js",
                    &fixture.port.to_string()
                ],
            )
            .output()
    );
    let all = text(&output);
    all.lines()
        .find(|line| line.starts_with("VERIFIED") || line.starts_with("FAIL"))
        .map_or_else(|| format!("NO VERDICT: {all}"), str::to_owned)
}

#[test]
fn node_verifies_a_private_ca_only_when_it_is_given_as_an_extra_ca_and_system_trust_does_not_get_in_the_way()
 {
    ready!();
    let found = nodes();
    if found.is_empty() {
        eprintln!("SKIP: no node on this machine");
        return;
    }
    let dir = assert_ok!(TempDir::new());
    let fixture = TlsFixture::start(dir.path());
    let mut table = Vec::new();
    for node in &found {
        for (system, extra, expected_ok) in [
            (false, false, false),
            (true, false, false),
            (false, true, true),
            (true, true, true),
        ] {
            let verdict = node_verdict(node, &fixture, system, extra);
            let ok = verdict == "VERIFIED";
            table.push(format!(
                "{} system_trust={system} extra_ca={extra}: {verdict}",
                node.display()
            ));
            assert_eq!(
                ok,
                expected_ok,
                "{} with system_trust={system} extra_ca={extra} gave {verdict}\n{}",
                node.display(),
                table.join("\n")
            );
        }
    }
}

#[test]
fn without_a_private_ca_node_fails_for_the_reason_the_server_is_not_trusted() {
    ready!();
    let Some(node) = nodes().into_iter().next() else {
        eprintln!("SKIP: no node on this machine");
        return;
    };
    let dir = assert_ok!(TempDir::new());
    let fixture = TlsFixture::start(dir.path());
    let verdict = node_verdict(&node, &fixture, true, false);
    assert!(
        verdict.contains("UNABLE_TO_VERIFY_LEAF_SIGNATURE")
            || verdict.contains("SELF_SIGNED")
            || verdict.contains("UNABLE_TO_GET_ISSUER_CERT"),
        "it failed, but not for trust: {verdict}"
    );
}

// ====================================================================================
// Other clients under the same grants
// ====================================================================================

/// A world whose profile lets a client reach the fixture and read what it needs.
fn client_world(fixture: &TlsFixture, system_trust: bool, reads: &[PathBuf]) -> World {
    let read_list: Vec<String> = reads.iter().map(|p| toml_path(p)).collect();
    World::with_base(
        &format!("[tls]\nsystem_trust = {system_trust}\n"),
        &format!(
            "[fs]\nread = [{}]\nwrite = [\".\"]\n[net]\nloopback_ports = [{}]\n[tls]\nextra_ca_files = [{}]\n",
            read_list.join(", "),
            fixture.port,
            toml_path(&fixture.ca)
        ),
    )
}

fn in_sandbox(world: &World, script: &str, drop_configd: bool) -> Output {
    let mut profile = world.render(&RenderInputs::new());
    if drop_configd {
        profile = without_lines(&profile, "configd");
    }
    run(&profile, &world.home_dir(), &world.project, script)
}

#[test]
fn curl_git_and_python_verify_the_server_with_the_ca_they_are_given_whether_or_not_system_trust_is_on()
 {
    ready!();
    let dir = assert_ok!(TempDir::new());
    let fixture = TlsFixture::start(dir.path());
    let python = find("python3");
    let reads: Vec<PathBuf> = python
        .iter()
        .map(|p| install_tree(p))
        .chain(
            [PathBuf::from("/opt/homebrew")]
                .into_iter()
                .filter(|_| python.is_some()),
        )
        .collect();
    let ca = fixture.ca.to_string_lossy().into_owned();
    for system_trust in [true, false] {
        let world = client_world(&fixture, system_trust, &reads);
        let curl = in_sandbox(
            &world,
            &format!(
                "/usr/bin/curl -sS --max-time 8 --cacert '{ca}' -o /dev/null {}",
                fixture.url()
            ),
            false,
        );
        assert!(
            curl.status.success(),
            "curl, system_trust={system_trust}: {}",
            text(&curl)
        );
        let git = in_sandbox(
            &world,
            &format!(
                "/usr/bin/git -c http.sslCAInfo='{ca}' ls-remote {}x.git",
                fixture.url()
            ),
            false,
        );
        let said = text(&git);
        assert!(
            !said.contains("SSL certificate problem")
                && !said.contains("unable to get local issuer"),
            "git, system_trust={system_trust} failed to verify: {said}"
        );
        if let Some(python) = &python {
            let check = format!(
                "'{}' -c \"import ssl,urllib.request; urllib.request.urlopen('{}', context=ssl.create_default_context(cafile='{ca}'), timeout=8).read(5); print('VERIFIED')\"",
                python.display(),
                fixture.url()
            );
            let out = in_sandbox(&world, &check, false);
            assert!(
                text(&out).contains("VERIFIED"),
                "python, system_trust={system_trust}: {}",
                text(&out)
            );
        }
    }
}

#[test]
fn uv_reaches_the_server_with_configd_granted_and_panics_without_it() {
    ready!();
    let (Some(uv), Some(python)) = (find("uv"), find("python3")) else {
        eprintln!("SKIP: no uv or no python3");
        return;
    };
    let dir = assert_ok!(TempDir::new());
    let fixture = TlsFixture::start(dir.path());
    let reads = vec![install_tree(&uv), PathBuf::from("/opt/homebrew")];
    let world = client_world(&fixture, true, &reads);
    let ca = fixture.ca.to_string_lossy().into_owned();
    let script = format!(
        "TMPDIR=\"$PWD\" SSL_CERT_FILE='{ca}' UV_CACHE_DIR=\"$PWD/uv-cache\" '{}' pip install --system --dry-run --break-system-packages --no-cache --python '{}' --index-url {}simple/ zzz-nonexistent",
        uv.display(),
        python.display(),
        fixture.url()
    );
    let with = text(&in_sandbox(&world, &script, false));
    assert!(
        !with.contains("panicked"),
        "uv panicked with configd granted: {with}"
    );
    assert!(
        !with.contains("invalid peer certificate") && !with.contains("UnknownIssuer"),
        "uv did not trust the CA it was given: {with}"
    );
    let without = text(&in_sandbox(&world, &script, true));
    assert!(
        without.contains("panicked") && without.contains("system-configuration"),
        "control: uv should panic in system-configuration without configd: {without}"
    );
}
