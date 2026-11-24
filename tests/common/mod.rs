// ABOUTME: Shared fixture for the Seatbelt integration tests: a throwaway home and project, load(), render() and sandbox-exec.
// ABOUTME: Runs the real renderer under the real sandbox; each test pairs a denied case with an allowed one.
//! Test harness: a fixture world, the real [`render`], and `sandbox-exec`.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use claims::assert_ok;
use hamster_ball::approval::{ApprovalStore, Fingerprint};
use hamster_ball::config::{EmbeddedPresets, LoadRequest, Loaded, StaticPresets, discover, load};
use hamster_ball::policy::{CanonicalPath, HomeDir};
use hamster_ball::seatbelt::{Profile, RenderInputs, render, render_filtered};
use hamster_ball::session::{Outcome, RunSpec, run as session_run};
use hamster_ball::system::{Environment, FloorEnvironment, StateDir, UserConfigDir};
use tempfile::TempDir;

pub mod proxy;
pub mod tls;

/// A canonical, throwaway tree: `home/`, a project at `home/work/proj`, and a PATH.
pub struct World {
    _dir: TempDir,
    pub base: PathBuf,
    pub home: HomeDir,
    pub project: PathBuf,
    pub env: Environment,
}

pub const NO_PRESETS: StaticPresets<'static> = StaticPresets(&[]);

pub fn canonical(path: &Path) -> CanonicalPath {
    assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
        path
    ))))
}

pub fn write(path: &Path, text: &str) {
    if let Some(parent) = path.parent() {
        assert_ok!(fs::create_dir_all(parent));
    }
    assert_ok!(fs::write(path, text));
}

impl World {
    /// A world whose project config is `project_toml` and whose base config is `base_toml`.
    pub fn with_base(base_toml: &str, project_toml: &str) -> Self {
        Self::build(assert_ok!(TempDir::new()), base_toml, project_toml)
    }

    /// A world whose tree sits under `/tmp`, which is a symlink to `/private/tmp`, so a path
    /// spelled through `/tmp` differs from its resolved form (the case the spike hit).
    pub fn under_symlinked_tmp(base_toml: &str, project_toml: &str) -> Self {
        Self::build(assert_ok!(TempDir::new_in("/tmp")), base_toml, project_toml)
    }

    /// The same tree as [`World::base`], spelled through the symlink it was created under.
    pub fn spelled(&self, path: &Path) -> PathBuf {
        let real = Path::new("/private/tmp");
        path.strip_prefix(real)
            .map_or_else(|_| path.to_path_buf(), |rest| Path::new("/tmp").join(rest))
    }

    fn build(dir: TempDir, base_toml: &str, project_toml: &str) -> Self {
        let base = assert_ok!(fs::canonicalize(dir.path()));
        let home_path = base.join("home");
        let project = home_path.join("work/proj");
        assert_ok!(fs::create_dir_all(&project));
        let home = HomeDir::new(canonical(&home_path));
        let config_dir = home_path.join(".config/hamster-ball");
        write(&config_dir.join("base.toml"), base_toml);
        write(&project.join("hamster-ball.toml"), project_toml);
        let tools = base.join("bin");
        assert_ok!(fs::create_dir_all(&tools));
        let install = base.join("install");
        write(&install.join("hb"), "");
        let mut env = Environment::new(&project, home.clone());
        env.floor = FloorEnvironment::new()
            .with_path_var(tools.into_os_string())
            .with_user_temp_dir(base.join("tmp"))
            .with_hb_exe(install.join("hb"));
        assert_ok!(fs::create_dir_all(base.join("tmp")));
        Self {
            _dir: dir,
            base,
            home,
            project,
            env,
        }
    }

    /// A world with an empty base config.
    pub fn new(project_toml: &str) -> Self {
        Self::with_base("", project_toml)
    }

    /// Replaces the project config (for configs that name paths inside this world).
    pub fn set_project(&self, project_toml: &str) {
        write(&self.project.join("hamster-ball.toml"), project_toml);
    }

    pub fn home_dir(&self) -> PathBuf {
        PathBuf::from(self.home.path().as_str())
    }

    /// Loads the policy (the real discover + load + floor).
    pub fn loaded(&self) -> Loaded {
        assert_ok!(self.try_loaded())
    }

    /// Like [`World::loaded`], but hands back the error for a config that must be refused.
    pub fn try_loaded(&self) -> Result<Loaded, hamster_ball::config::LoadError> {
        let discovery = assert_ok!(discover(&self.project, &self.home));
        let user = UserConfigDir::locate(&self.home);
        load(
            &LoadRequest::new(&self.home, &discovery, &user, &self.env.floor)
                .with_builtins(&NO_PRESETS),
        )
    }

    /// A command that runs the test-only `hb-testdrive` binary in this world: same code as `hb`,
    /// but its home, project, tool `PATH` and temp directory come from variables, because the real
    /// `hb` takes its home from the passwd database (D28) and so cannot load a fixture project.
    pub fn drive(&self, testdrive: &str, args: &[&str]) -> Command {
        self.approve();
        self.drive_unapproved(testdrive, args)
    }

    /// Records the project's config as it is now as approved, as the owner's `y` at the prompt would.
    ///
    /// A config that does not load is left alone: the run then fails for that reason. The store is
    /// the world's own, under its temporary home.
    pub fn approve(&self) {
        let Ok(discovery) = discover(&self.project, &self.home) else {
            return;
        };
        let user = UserConfigDir::locate(&self.home);
        let Ok(loaded) = load(
            &LoadRequest::new(&self.home, &discovery, &user, &self.env.floor)
                .with_builtins(&EmbeddedPresets),
        ) else {
            return;
        };
        let store = ApprovalStore::new(&StateDir::locate(&self.home));
        assert_ok!(store.approve(discovery.root.path(), &Fingerprint::of(&loaded.closure)));
    }

    /// Like [`World::drive`], without approving the config first.
    pub fn drive_unapproved(&self, testdrive: &str, args: &[&str]) -> Command {
        // A process started from a background job or under `nohup` has INT, QUIT or HUP ignored,
        // and an ignored signal stays ignored through exec. perl resets them first, so what the
        // test sees does not depend on how cargo was started; perl then becomes the driver.
        let mut cmd = Command::new("/usr/bin/perl");
        cmd.args([
            "-e",
            "$SIG{$_}='DEFAULT' for qw(INT QUIT HUP TERM); exec @ARGV or die qq(exec: $!)",
            testdrive,
        ])
        .args(args)
        .env_clear()
        .current_dir(&self.project);
        self.drive_env_unapproved(&mut cmd);
        cmd
    }

    /// Sets the variables `hb-testdrive` reads on `cmd`, for a command that starts it indirectly.
    pub fn drive_env(&self, cmd: &mut Command) {
        self.approve();
        self.drive_env_unapproved(cmd);
    }

    /// Like [`World::drive_env`], without approving the config first.
    pub fn drive_env_unapproved(&self, cmd: &mut Command) {
        cmd.env("HB_TD_HOME", self.home_dir())
            .env("HB_TD_CWD", &self.project)
            .env("HB_TD_PATH", self.base.join("bin"))
            .env("HB_TD_TMP", self.base.join("tmp"));
    }

    pub fn render(&self, inputs: &RenderInputs) -> Profile {
        assert_ok!(render(&self.loaded().policy, inputs))
    }

    /// Renders without the floor's unlink pins (the control for the pin tests).
    pub fn render_without_pins(&self) -> Profile {
        assert_ok!(render_filtered(
            &self.loaded().policy,
            &RenderInputs::new(),
            &|rule| rule.effect != hamster_ball::policy::FloorEffect::PinUnlink
        ))
    }
}

/// `profile` without the lines containing `needle` (the control for a test of one rule family).
pub fn without_lines(profile: &Profile, needle: &str) -> Profile {
    let text: String = profile
        .text
        .lines()
        .filter(|line| !line.contains(needle))
        .map(|line| format!("{line}\n"))
        .collect();
    Profile {
        text,
        params: profile.params.clone(),
        warnings: profile.warnings.clone(),
    }
}

/// Runs `argv` in the world through [`session::run`](hamster_ball::session::run): the real
/// policy, the real renderer, the empty environment, the session directory and the child helper.
///
/// Call it only after [`sandbox_available`] said yes; the nesting preflight inside `run` would
/// otherwise turn a skip into an error.
pub fn run_in_hb(world: &World, argv: &[&str]) -> Outcome {
    let spec = RunSpec::new(argv.iter().copied());
    assert_ok!(session_run(&world.env, &world.loaded(), &spec))
}

/// `run_in_hb` of `/bin/sh -c script`.
pub fn sh_in_hb(world: &World, script: &str) -> Outcome {
    run_in_hb(world, &["/bin/sh", "-c", script])
}

/// Whether the child exited with code 0.
pub fn hb_succeeds(outcome: &Outcome) -> bool {
    outcome.exit == hamster_ball::session::ExitKind::Exited(0)
}

/// Captured stdout then stderr, lossily decoded.
pub fn hb_text(outcome: &Outcome) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&outcome.stdout),
        String::from_utf8_lossy(&outcome.stderr)
    )
}

/// Whether `sandbox-exec` works here: false when this process is already sandboxed.
pub fn sandbox_available() -> bool {
    let nested = hamster_ball::session::is_nested();
    if nested {
        // CI sets HB_REQUIRE_SANDBOX so an environment that cannot sandbox fails loudly instead
        // of turning every Seatbelt test into a silent pass.
        assert!(
            std::env::var_os("HB_REQUIRE_SANDBOX").is_none(),
            "HB_REQUIRE_SANDBOX is set but sandbox-exec is unavailable"
        );
        eprintln!("SKIP: sandbox-exec is unavailable (already sandboxed?)");
    }
    !nested
}

/// Runs `script` under `profile`, in `cwd`, with an empty environment except `HOME` and `PATH`.
pub fn run(profile: &Profile, home: &Path, cwd: &Path, script: &str) -> Output {
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(&profile.text);
    cmd.args(profile.define_args());
    cmd.args(["--", "/bin/sh", "-c", script]);
    cmd.env_clear()
        .env("HOME", home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("TERM", "dumb")
        .current_dir(cwd);
    assert_ok!(cmd.output())
}

pub fn succeeds(output: &Output) -> bool {
    output.status.success()
}

pub fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

pub fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// Whether this machine can reach a wildcard listener of its own at `address`.
///
/// A firewall or VPN can reset such connections even with no sandbox involved; a test about what
/// the sandbox allows must skip then, because it could not tell the two causes apart.
pub fn lan_loops_back(address: &str) -> bool {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, ToSocketAddrs};
    use std::time::Duration;
    let Ok(listener) = TcpListener::bind("0.0.0.0:0") else {
        return false;
    };
    let Ok(port) = listener.local_addr().map(|a| a.port()) else {
        return false;
    };
    let server = std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"hi");
        }
    });
    let reached = (address, port)
        .to_socket_addrs()
        .ok()
        .and_then(|mut addrs| addrs.next())
        .and_then(|addr| TcpStream::connect_timeout(&addr, Duration::from_secs(3)).ok())
        .and_then(|mut s| {
            let mut text = String::new();
            s.read_to_string(&mut text).ok().map(|_| text)
        })
        .is_some_and(|text| text == "hi");
    if !reached {
        // Unblock the accept so the thread can end.
        let _ = TcpStream::connect(("127.0.0.1", port));
    }
    let _ = server.join();
    reached
}

/// This machine's address on its local network, if it has one.
pub fn lan_address() -> Option<String> {
    ["en0", "en1"].iter().find_map(|interface| {
        let out = Command::new("/usr/sbin/ipconfig")
            .args(["getifaddr", interface])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        (out.status.success() && !text.is_empty()).then_some(text)
    })
}

/// A TOML string literal for `text`.
pub fn toml_string(text: &str) -> String {
    toml::Value::String(text.to_owned()).to_string()
}

/// Tcl for the top of an `expect` script: a timeout becomes a marker and exit status 3.
///
/// Without it a timed-out `expect` just carries on, so a test can wait out its whole timeout and
/// still pass on what it saw before.
pub const EXPECT_GUARD: &str =
    "expect_before -i any_spawn_id timeout {puts HB-EXPECT-TIMEOUT; exit 3}\n";

/// Fails the test if the `expect` script timed out (see [`EXPECT_GUARD`]).
pub fn assert_no_expect_timeout(output: &str) {
    assert!(
        !output.contains("HB-EXPECT-TIMEOUT"),
        "an expect step timed out:\n{output}"
    );
}
