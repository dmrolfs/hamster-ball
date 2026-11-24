// ABOUTME: The conformance harness checked with fake agents: pass, each way to fail, skips, the time limit and isolation.
// ABOUTME: Runs under the real sandbox and proxy; a stub resolver sends the allowed test host to a local upstream.
//! Self-tests of [`hamster_ball::conformance`] (hb-ghd.3.4).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use claims::assert_ok;
use common::proxy::{Table, to_loopback};
use common::{World, sandbox_available};
use hamster_ball::config::StaticPresets;
use hamster_ball::conformance::{
    Agent, Context, Expect, Failure, Settings, Skip, Verdict, run_agent,
};
use hamster_ball::session::{ExitKind, ProxyTuning};
use pretty_assertions::assert_eq;

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// An HTTP upstream on loopback that answers every request with `HELLO`.
fn upstream() -> u16 {
    let listener = assert_ok!(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)));
    let port = assert_ok!(listener.local_addr()).port();
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nHELLO",
                );
            });
        }
    });
    port
}

/// A fake agent in a fixture world, with the preset that goes with it.
struct Fake {
    world: World,
    dir: PathBuf,
    port: u16,
    preset: String,
}

impl Fake {
    /// `body` is the script after the shebang; `$PORT` and `$SECRET` are replaced.
    fn new(body: &str) -> Self {
        Self::in_world(World::new("[fs]\nwrite = [\".\"]\n"), body)
    }

    fn in_world(world: World, body: &str) -> Self {
        let dir = world.base.join("agent-bin");
        assert_ok!(fs::create_dir_all(&dir));
        let port = upstream();
        let secret = dir.join("allowed.txt");
        assert_ok!(fs::write(&secret, "granted\n"));
        let script = dir.join("fake-agent");
        let text = body
            .replace("$PORT", &port.to_string())
            .replace("$SECRET", &secret.to_string_lossy());
        assert_ok!(fs::write(&script, format!("#!/bin/sh\n{text}\n")));
        assert_ok!(fs::set_permissions(
            &script,
            fs::Permissions::from_mode(0o755)
        ));
        let preset = format!(
            "[fs]\nread = [{}]\n[net]\nallow = [\"allowed.test:{port}\"]\n",
            common::toml_string(&dir.to_string_lossy())
        );
        Self {
            world,
            dir,
            port,
            preset,
        }
    }

    fn agent(&self, expect: Expect) -> Agent {
        let path: &'static str = Box::leak(
            self.dir
                .join("fake-agent")
                .to_string_lossy()
                .into_owned()
                .into_boxed_str(),
        );
        Agent {
            name: "fake",
            binary: path,
            args: &[],
            env: &[],
            expect,
        }
    }

    fn settings(&self) -> Settings {
        Settings {
            tuning: Some(ProxyTuning::new(|config| {
                config
                    .with_resolver(Table::of(&["allowed.test"]))
                    .with_dial_map(to_loopback())
            })),
            timeout: Duration::from_secs(30),
            ..Settings::default()
        }
    }

    fn check(&self, expect: Expect, settings: &Settings) -> Verdict {
        let presets = [("agent/fake", self.preset.as_str())];
        let builtins = StaticPresets(&presets);
        run_agent(
            &self.agent(expect),
            &Context {
                env: &self.world.env,
                builtins: &builtins,
                settings,
            },
        )
    }
}

const GOOD: &str = "/bin/cat $SECRET >/dev/null || exit 3\n\
    /usr/bin/curl -sS -m 10 http://allowed.test:$PORT/ >/dev/null || exit 4\n\
    echo OK";

fn failures(verdict: &Verdict) -> Vec<Failure> {
    assert!(verdict.is_failure(), "{verdict}");
    match verdict {
        Verdict::Failed { failures, .. } => failures.clone(),
        other => {
            assert_ok!(Err::<(), _>(format!("expected a failure, got {other}")));
            Vec::new()
        }
    }
}

#[test]
fn an_agent_that_reads_its_files_contacts_its_host_and_says_ok_passes() {
    sandboxed!();
    let fake = Fake::new(GOOD);
    let verdict = fake.check(Expect::Word("OK"), &fake.settings());
    let Verdict::Passed(report) = &verdict else {
        assert_ok!(Err::<(), _>(format!("{verdict}")));
        return;
    };
    assert_eq!(report.contacted, [format!("allowed.test:{}", fake.port)]);
    assert_eq!(report.exit, Some(ExitKind::Exited(0)));
    assert!(verdict.to_string().starts_with("PASS: fake"), "{verdict}");
}

#[test]
fn a_host_outside_the_preset_fails_naming_the_host_with_the_proxys_denial_as_a_hint() {
    sandboxed!();
    let fake = Fake::new(&format!(
        "{GOOD}\n/usr/bin/curl -sS -m 10 https://denied.example.org/ >/dev/null 2>&1; true"
    ));
    let verdict = fake.check(Expect::Word("OK"), &fake.settings());
    assert_eq!(
        failures(&verdict),
        [Failure::Refused(
            "denied.example.org:443".to_owned(),
            "not_allowed".to_owned()
        )]
    );
    let Verdict::Failed { report, .. } = &verdict else {
        assert_ok!(Err::<(), _>(format!("expected a failure: {verdict}")));
        return;
    };
    assert!(
        report
            .hints
            .iter()
            .any(|h| h.starts_with("proxy refused denied.example.org:443")),
        "{:?}",
        report.hints
    );
    let shown = verdict.to_string();
    assert!(
        shown.contains(&format!("contacted: allowed.test:{}", fake.port)),
        "{shown}"
    );
    assert!(
        shown.contains("outside the preset") && shown.contains("hint: proxy refused"),
        "{shown}"
    );
}

#[test]
fn wrong_output_a_bad_exit_and_a_missing_file_each_fail_for_their_own_reason() {
    sandboxed!();
    let settings = |f: &Fake| f.settings();
    let quiet = Fake::new("/bin/cat $SECRET >/dev/null; echo done");
    assert_eq!(
        failures(&quiet.check(Expect::Word("OK"), &settings(&quiet))),
        [Failure::MissingWord("OK")]
    );
    let broken = Fake::new("echo OK; exit 2");
    assert_eq!(
        failures(&broken.check(Expect::Word("OK"), &settings(&broken))),
        [Failure::Exit(ExitKind::Exited(2))]
    );
    // A file the preset does not grant cannot be read: the fake exits 3.
    let blind = Fake::new(
        "/bin/cat /private/etc/hosts.nonexistent-grant >/dev/null 2>&1 || exit 3\necho OK",
    );
    // It exited before it could say OK, so both are reported.
    assert_eq!(
        failures(&blind.check(Expect::Word("OK"), &settings(&blind))),
        [
            Failure::Exit(ExitKind::Exited(3)),
            Failure::MissingWord("OK")
        ]
    );
}

#[test]
fn an_agent_that_runs_past_the_time_limit_is_stopped_and_reported() {
    sandboxed!();
    let fake = Fake::new("sleep 60; echo OK");
    let settings = Settings {
        timeout: Duration::from_secs(2),
        ..fake.settings()
    };
    let started = Instant::now();
    let verdict = fake.check(Expect::Word("OK"), &settings);
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    let found = failures(&verdict);
    assert_eq!(
        found,
        [
            Failure::TimedOut(Duration::from_secs(2)),
            Failure::MissingWord("OK")
        ]
    );
}

#[test]
fn a_connection_agent_passes_only_with_a_served_connection_to_its_host_prefix() {
    sandboxed!();
    let fake = Fake::new(GOOD);
    assert!(matches!(
        fake.check(Expect::AllowedConnectionTo("allowed."), &fake.settings()),
        Verdict::Passed(_)
    ));
    assert_eq!(
        failures(&fake.check(
            Expect::AllowedConnectionTo("bedrock-runtime."),
            &fake.settings()
        )),
        [Failure::NoConnectionTo("bedrock-runtime.")]
    );
}

#[test]
fn an_agents_own_variables_reach_the_sandboxed_run_beside_the_users_project_env() {
    sandboxed!();
    let fake = Fake::new("echo \"key=$FAKE_KEY other=$OTHER\"");
    let agent = Agent {
        env: &[("FAKE_KEY", "bogus")],
        ..fake.agent(Expect::Word("key"))
    };
    let mut settings = fake.settings();
    settings.project_extra = "[env]\nset = { OTHER = \"user\" }\n".to_owned();
    let presets = [("agent/fake", fake.preset.as_str())];
    let builtins = StaticPresets(&presets);
    let verdict = run_agent(
        &Agent {
            expect: Expect::Word("bogus"),
            ..agent
        },
        &Context {
            env: &fake.world.env,
            builtins: &builtins,
            settings: &settings,
        },
    );
    let Verdict::Passed(report) = &verdict else {
        assert_ok!(Err::<(), _>(format!("{verdict}")));
        return;
    };
    assert!(
        report.output.iter().any(|l| l == "key=bogus other=user"),
        "{:?}",
        report.output
    );
}

#[test]
fn a_baseline_agent_must_exit_as_it_does_without_the_sandbox() {
    sandboxed!();
    // HB_SESSION exists only inside hb, so this agent behaves differently under the sandbox.
    let differs = Fake::new("[ -n \"$HB_SESSION\" ] && exit 0\nexit 5");
    assert_eq!(
        failures(&differs.check(Expect::SameExitAsBaseline, &differs.settings())),
        [Failure::ExitDiffers {
            baseline: Some(5),
            sandboxed: 0
        }]
    );
    let same = Fake::new("exit 7");
    assert!(matches!(
        same.check(Expect::SameExitAsBaseline, &same.settings()),
        Verdict::Passed(_)
    ));
}

#[test]
fn skips_say_why_and_are_not_failures() {
    sandboxed!();
    let fake = Fake::new(GOOD);
    let off = Settings {
        enabled: false,
        ..fake.settings()
    };
    assert_eq!(
        fake.check(Expect::Word("OK"), &off),
        Verdict::Skipped(Skip::Disabled)
    );
    let missing = Agent {
        binary: "/no/such/agent",
        ..fake.agent(Expect::Word("OK"))
    };
    let presets = [("agent/fake", fake.preset.as_str())];
    let builtins = StaticPresets(&presets);
    let ctx = |settings: &'static Settings| Context {
        env: &fake.world.env,
        builtins: &builtins,
        settings,
    };
    let on: &'static Settings = Box::leak(Box::new(fake.settings()));
    let verdict = run_agent(&missing, &ctx(on));
    assert_eq!(
        verdict,
        Verdict::Skipped(Skip::NotInstalled("/no/such/agent".to_owned()))
    );
    assert!(!verdict.is_failure());
    assert!(verdict.to_string().contains("not installed"));
    let none = StaticPresets(&[]);
    let verdict = run_agent(
        &fake.agent(Expect::Word("OK")),
        &Context {
            env: &fake.world.env,
            builtins: &none,
            settings: on,
        },
    );
    assert_eq!(verdict, Verdict::Skipped(Skip::NoPreset("fake".to_owned())));
    assert!(
        verdict
            .to_string()
            .contains("no built-in preset agent/fake")
    );
}

#[test]
fn what_the_preset_leaves_to_the_user_comes_from_the_project_file_and_nothing_else_is_read() {
    sandboxed!();
    // The user's own base config allows the denied host; the harness must not read it.
    let world = World::with_base(
        "[net]\nallow = [\"denied.example.org\"]\n",
        "[fs]\nwrite = [\".\"]\n",
    );
    let extra = world.base.join("extra").join("extra.txt");
    assert_ok!(fs::create_dir_all(world.base.join("extra")));
    assert_ok!(fs::write(&extra, "x"));
    let body = format!(
        "/bin/cat {extra} >/dev/null 2>&1 && echo EXTRA-READ\n/usr/bin/curl -sS -m 10 https://denied.example.org/ >/dev/null 2>&1; echo OK",
        extra = extra.display()
    );
    let fake = Fake::in_world(world, &body);
    // Without the extra grant the file is unreadable; the denied host is refused even though the
    // user's base config would allow it.
    let verdict = fake.check(Expect::Word("OK"), &fake.settings());
    let Verdict::Failed { failures, report } = &verdict else {
        assert_ok!(Err::<(), _>(format!("{verdict}")));
        return;
    };
    assert!(
        failures
            .iter()
            .any(|f| matches!(f, Failure::Refused(t, _) if t == "denied.example.org:443")),
        "{verdict}"
    );
    assert!(
        !report.output.iter().any(|l| l.contains("EXTRA-READ")),
        "{report:?}"
    );
    // With the extra, the file is readable.
    let extra_path = fake.world.base.join("extra").join("extra.txt");
    let with_extra = Settings {
        project_extra: format!(
            "[fs]\nread = [{}]\n",
            common::toml_string(&extra_path.to_string_lossy())
        ),
        ..fake.settings()
    };
    let verdict = fake.check(Expect::Word("OK"), &with_extra);
    let Verdict::Failed { report, .. } = &verdict else {
        assert_ok!(Err::<(), _>(format!("expected a failure: {verdict}")));
        return;
    };
    assert!(
        report.output.iter().any(|l| l.contains("EXTRA-READ")),
        "{report:?}"
    );
}
