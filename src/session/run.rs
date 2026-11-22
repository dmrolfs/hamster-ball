// ABOUTME: session::run: render the profile, build the environment and session dir, spawn sandbox-exec, wait, clean up.
// ABOUTME: The one library entry point that `hb run` and the probe-matrix harness share, so they cannot run differently.
//! Running a command under the profile (design 7.2, 7.4; hb-ghd.2.3a).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::Duration;

use nix::unistd::Pid;
use rustix::process::Pid as RustixPid;
use snafu::{ResultExt, Snafu, ensure};

use super::denials::{DenialSink, Denials, DenialsError, LogStream, generate_tag};
use super::dir::{SessionDir, SessionDirError, sweep_stale};
use super::env::{ChildEnv, EnvBuildError, EnvInputs, SESSION_MARKER};
use super::interactive::{Interactive, InteractiveError};
use super::preflight::{PreflightError, SANDBOX_EXEC, check_nesting};
use super::pty::{Pty, PtyError};
use super::signals::{Escalation, SignalError, Supervisor, Target, Watch};
use crate::config::Loaded;
use crate::policy::{CanonicalPath, PathError, ToolName};
use crate::seatbelt::{Profile, RenderError, RenderInputs, render};
use crate::system::{Environment, ToolsError, find_tools};

/// What the kernel accepts for `argv` plus `envp` on macOS (`kern.argmax`).
const ARG_MAX: usize = 1_048_576;
/// Left unused for the kernel's own bookkeeping and for the platform's variance.
const ARG_MARGIN: usize = 32 * 1024;
/// Bytes one pointer takes in the argument block.
const POINTER_BYTES: usize = 8;

/// How long hb waits after the first signal before it kills the child.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(5);

/// What `hb` does about INT, TERM and HUP while the child runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SignalMode {
    /// Nothing. The caller's signal handling is left alone; the child starts directly under
    /// `sandbox-exec` and inherits the caller's blocked signals. For the harness and tests.
    #[default]
    Off,
    /// Forward them to the child and escalate to SIGKILL after `grace` or on a second signal.
    ///
    /// The three signals must already be blocked in the calling thread (see
    /// [`block_supervised`](super::signals::block_supervised)). The child starts through `hb __child`, which clears the mask.
    Forward {
        /// How long the child may take to end after the first signal.
        grace: Duration,
    },
}

/// What to do with the child's standard streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StdioMode {
    /// Capture stdout and stderr; stdin is closed. For the probe harness and tests.
    Capture,
    /// The child shares `hb`'s terminal and streams. For `hb run`.
    Inherit,
}

/// Whether the child gets a pty of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PtyMode {
    /// The child gets the caller's streams as they are.
    Off,
    /// The child gets a pty of its own and leads its own session; `hb` relays the user's terminal
    /// to it. Needs `hb`'s stdin to be a terminal, inherited streams and [`SignalMode::Forward`]
    /// (window resizes and stops arrive as signals and are handled with the signal thread).
    On,
}

/// What to run.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RunSpec {
    /// The command and its arguments. The first word is looked up on the child's `PATH`.
    pub argv: Vec<OsString>,
    /// The standard streams.
    pub stdio: StdioMode,
    /// The pty.
    pub pty: PtyMode,
    /// What to do about INT, TERM and HUP.
    pub signals: SignalMode,
    /// Where denial lines go, or `None` to not log them.
    pub denials: Option<DenialSink>,
}

impl RunSpec {
    /// A run of `argv` with captured output and no pty.
    #[must_use]
    pub fn new(argv: impl IntoIterator<Item = impl Into<OsString>>) -> Self {
        Self {
            argv: argv.into_iter().map(Into::into).collect(),
            stdio: StdioMode::Capture,
            pty: PtyMode::Off,
            signals: SignalMode::Off,
            denials: None,
        }
    }

    /// Logs what the profile denies during this run, to `sink`.
    #[must_use]
    pub fn denials(mut self, sink: DenialSink) -> Self {
        self.denials = Some(sink);
        self
    }

    /// Sets what to do about signals.
    #[must_use]
    pub fn signals(mut self, signals: SignalMode) -> Self {
        self.signals = signals;
        self
    }

    /// Sets the standard stream mode.
    #[must_use]
    pub fn stdio(mut self, stdio: StdioMode) -> Self {
        self.stdio = stdio;
        self
    }
}

/// How the child ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitKind {
    /// It exited with this code.
    Exited(i32),
    /// A signal killed it.
    Signalled(i32),
}

impl ExitKind {
    /// What a shell would report: the code, or `128 + signal`.
    #[must_use]
    pub fn code(self) -> i32 {
        match self {
            Self::Exited(code) => code,
            Self::Signalled(signal) => 128 + signal,
        }
    }

    fn from_status(status: ExitStatus) -> Self {
        status
            .code()
            .map(Self::Exited)
            .or_else(|| status.signal().map(Self::Signalled))
            .unwrap_or(Self::Exited(1))
    }
}

/// The result of a run.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Outcome {
    /// How the child ended.
    pub exit: ExitKind,
    /// Captured stdout (empty when the child shared the terminal).
    pub stdout: Vec<u8>,
    /// Captured stderr (empty when the child shared the terminal).
    pub stderr: Vec<u8>,
    /// Things worth telling the user, in order.
    pub warnings: Vec<String>,
    /// What the profile denied, when [`RunSpec::denials`] was [`DenialSink::Collect`].
    pub denials: Denials,
}

/// Why a run could not start.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RunError {
    /// There was no command to run.
    #[snafu(display("there is no command to run"))]
    EmptyCommand,

    /// `hb` is inside another sandbox, or `sandbox-exec` does not work.
    #[snafu(transparent)]
    Preflight {
        /// The underlying error.
        source: PreflightError,
    },

    /// The `[env] tools` could not be looked up.
    #[snafu(transparent)]
    Tools {
        /// The underlying error.
        source: ToolsError,
    },

    /// The per-user temporary directory is not known.
    #[snafu(display(
        "the per-user temporary directory is unknown, so there is nowhere for the session directory"
    ))]
    NoTempDir,

    /// The per-user temporary directory could not be resolved.
    #[snafu(display("the per-user temporary directory {dir} could not be resolved"))]
    TempDir {
        /// The directory as reported.
        dir: String,
        /// The underlying error.
        source: io::Error,
    },

    /// The temporary directory is not a clean canonical path.
    #[snafu(display("the per-user temporary directory is not usable"))]
    TempDirPath {
        /// The underlying error.
        source: PathError,
    },

    /// The session directory could not be created.
    #[snafu(transparent)]
    Session {
        /// The underlying error.
        source: SessionDirError,
    },

    /// The profile could not be rendered.
    #[snafu(transparent)]
    Render {
        /// The underlying error.
        source: RenderError,
    },

    /// The child's environment could not be built.
    #[snafu(transparent)]
    Env {
        /// The underlying error.
        source: EnvBuildError,
    },

    /// The command is not on the child's `PATH`.
    #[snafu(display(
        "`{}` was not found on the PATH the program will have; add it to `[env] tools` or use its full path",
        name.to_string_lossy()
    ))]
    CommandNotFound {
        /// The first word of the command.
        name: OsString,
    },

    /// The command line and environment would not fit in what the kernel accepts.
    #[snafu(display(
        "the command line is {total} bytes (profile {profile}, parameters {params}, environment {env}, command {command}); the limit is {max}"
    ))]
    TooLarge {
        /// The whole size.
        total: usize,
        /// The limit.
        max: usize,
        /// The profile text.
        profile: usize,
        /// The `-D` parameters.
        params: usize,
        /// The environment.
        env: usize,
        /// The command and the fixed words.
        command: usize,
    },

    /// Signal supervision could not be set up.
    #[snafu(transparent)]
    Signals {
        /// The underlying error.
        source: SignalError,
    },

    /// The denial log could not be started.
    #[snafu(transparent)]
    Denials {
        /// The underlying error.
        source: DenialsError,
    },

    /// The path of the running `hb` is unknown, and the child helper needs it.
    #[snafu(display(
        "the path of the running hb is unknown, so the child helper cannot be started"
    ))]
    NoHbExe,

    /// A pty run was asked for without a terminal, without inherited streams or without signal forwarding.
    #[snafu(display(
        "a pty run needs hb's stdin to be a terminal, inherited streams and signal forwarding"
    ))]
    PtyUnavailable,

    /// The pty could not be set up.
    #[snafu(transparent)]
    Pty {
        /// The underlying error.
        source: PtyError,
    },

    /// The user's terminal could not be set up for the pty.
    #[snafu(transparent)]
    Interactive {
        /// The underlying error.
        source: InteractiveError,
    },

    /// `sandbox-exec` could not be started.
    #[snafu(display("{SANDBOX_EXEC} could not be started"))]
    Spawn {
        /// The underlying error.
        source: io::Error,
    },
}

/// Runs `spec` under the profile for `loaded`, and waits for it.
///
/// Checks that `sandbox-exec` works here, resolves `[env] tools`, sweeps stale session
/// directories, makes a new one, renders the profile, builds the child's environment from empty
/// and spawns. The session directory is removed when this returns, or unwinds.
///
/// Build `loaded` after the last interactive step: the profile is rendered here, and spawn follows
/// within milliseconds (design D52).
///
/// # Errors
/// [`RunError`] if the run could not start. A child that fails is an [`Outcome`], not an error.
pub fn run(env: &Environment, loaded: &Loaded, spec: &RunSpec) -> Result<Outcome, RunError> {
    ensure!(!spec.argv.is_empty(), EmptyCommandSnafu);
    check_nesting(env.vars.get(SESSION_MARKER).is_some())?;
    let pty = open_pty(spec)?;

    let names: Vec<ToolName> = loaded
        .policy
        .env
        .tools
        .iter()
        .map(|t| t.value.clone())
        .collect();
    let tools = find_tools(&names, env.floor.path_var.as_deref())?;
    let mut warnings: Vec<String> = tools
        .missing
        .iter()
        .map(|name| format!("tool `{name}` from [env] tools was not found on your PATH"))
        .collect();

    let temp = temp_parent(env)?;
    sweep_stale(temp.as_path());
    let session = SessionDir::create(&temp)?;

    let tool_dirs = tools.dirs();
    let tag = spec.denials.as_ref().map(|_| generate_tag());
    let mut inputs = RenderInputs::new()
        .with_session_dir(session.path().clone())
        .with_exec_dirs(tool_dirs.clone());
    if let Some(tag) = &tag {
        inputs = inputs.with_log_tag(tag.clone());
    }
    if let Some(pty) = &pty {
        inputs = inputs.with_tty(pty.slave_path().clone());
    }
    let profile = render(&loaded.policy, &inputs)?;
    warnings.extend(profile.warnings.iter().map(ToString::to_string));

    let stdin_is_tty = stdin_is_tty(spec.stdio, io::stdin().is_terminal());
    let child_env = ChildEnv::build(&EnvInputs {
        parent: &env.vars,
        home: &env.home,
        session_dir: session.path(),
        tool_dirs: &tool_dirs,
        stdin_is_tty,
        env: &loaded.policy.env,
    })?;
    ensure_command_exists(&spec.argv[0], &child_env)?;
    let helper = match (spec.signals, &pty) {
        (SignalMode::Off, None) => None,
        _ => Some(env.floor.hb_exe.as_deref().ok_or(RunError::NoHbExe)?),
    };
    let launcher = launcher_words(helper, pty.is_some());
    check_size(&profile, &child_env, &spec.argv, &launcher)?;
    let watch = match spec.signals {
        SignalMode::Off => None,
        SignalMode::Forward { .. } => Some(Watch::prepare(pty.is_some())?),
    };

    let mut command = command_for(&profile, &child_env, spec, &env.cwd, helper, pty.is_some());
    match &pty {
        Some(pty) => {
            // The helper's setsid makes the child leader of a new session and group, which it
            // cannot do if it already leads a group, so no process_group here.
            pty.copy_size_from(io::stdin());
            let (stdin, stdout, stderr) = pty.child_stdio().context(SpawnSnafu)?;
            command.stdin(stdin).stdout(stdout).stderr(stderr);
        }
        None => {
            // A child in its own group is a background group to a terminal and cannot read it,
            // so without a pty it gets one only when stdin is not a tty (hb-ghd.2.3 decision 1).
            if !stdin_is_tty {
                command.process_group(0);
            }
            if spec.stdio == StdioMode::Capture {
                command.stdout(Stdio::piped()).stderr(Stdio::piped());
            }
        }
    }
    // The log is listening before the child starts, so its first denials are not missed.
    let log = match (&tag, &spec.denials) {
        (Some(tag), Some(sink)) => Some(LogStream::start(tag, sink.clone())?),
        _ => None,
    };
    let child = command.spawn().context(SpawnSnafu)?;
    let running = match pty {
        Some(pty) => start_on_pty(child, pty, watch, spec.signals)?,
        None => start_supervisor(child, watch, spec.signals, stdin_is_tty)?,
    };
    let waited = running.wait_for_exit(spec.stdio);
    let denials = log.map(LogStream::finish).unwrap_or_default();
    let (exit, stdout, stderr) = waited?;
    drop(session);
    Ok(Outcome {
        exit,
        stdout,
        stderr,
        warnings,
        denials,
    })
}

/// Whether the child's stdin is a terminal: only when it shares `hb`'s streams and `hb`'s own
/// stdin is one. Captured runs close stdin.
fn stdin_is_tty(stdio: StdioMode, own_stdin_is_terminal: bool) -> bool {
    stdio == StdioMode::Inherit && own_stdin_is_terminal
}

/// A spawned child, with the signal thread that watches over it if there is one.
struct Running {
    child: Child,
    supervisor: Option<Supervisor>,
    terminal: Option<Interactive>,
}

/// Starts forwarding signals to `child`, if `watch` was prepared. If that fails the child is
/// killed and reaped first, so a failed start never leaves an unsupervised agent running.
fn start_supervisor(
    mut child: Child,
    watch: Option<Watch>,
    mode: SignalMode,
    stdin_is_tty: bool,
) -> Result<Running, RunError> {
    let (Some(watch), SignalMode::Forward { grace }) = (watch, mode) else {
        return Ok(Running {
            child,
            supervisor: None,
            terminal: None,
        });
    };
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX));
    // The child shares hb's group when stdin is a terminal, so a group signal would hit hb too.
    let target = if stdin_is_tty {
        Target::Child(pid)
    } else {
        Target::Group(pid)
    };
    match watch.start(target, Escalation::new(grace, stdin_is_tty), None) {
        Ok(supervisor) => Ok(Running {
            child,
            supervisor: Some(supervisor),
            terminal: None,
        }),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error.into())
        }
    }
}

/// Kills and reaps a child that was started but cannot be supervised, so a failed start never
/// leaves an agent running without its parent.
fn abort_child(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Starts the user's side of a pty run (raw mode, relay) and the signal thread with the resize
/// callback, after the child has been spawned.
fn start_on_pty(
    mut child: Child,
    pty: Pty,
    watch: Option<Watch>,
    mode: SignalMode,
) -> Result<Running, RunError> {
    let (Some(watch), SignalMode::Forward { grace }) = (watch, mode) else {
        abort_child(&mut child);
        return Err(RunError::PtyUnavailable);
    };
    // Dropping hb's own copy of the slave lets the master see the end of the child's output.
    let terminal = match Interactive::start(pty.release_slave()) {
        Ok(terminal) => terminal,
        Err(error) => {
            abort_child(&mut child);
            return Err(error.into());
        }
    };
    let pid = Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX));
    // The child leads its own session and group, and the terminal's keys reach it through the
    // pty, so every signal hb gets is an explicit one: all are forwarded to the group.
    match watch.start(
        Target::Group(pid),
        Escalation::new(grace, false),
        Some(terminal.resize_callback()),
    ) {
        Ok(supervisor) => Ok(Running {
            child,
            supervisor: Some(supervisor),
            terminal: Some(terminal),
        }),
        Err(error) => {
            abort_child(&mut child);
            terminal.finish();
            Err(error.into())
        }
    }
}

/// Allocates the pty a run asks for, after checking what it needs.
fn open_pty(spec: &RunSpec) -> Result<Option<Pty>, RunError> {
    if spec.pty != PtyMode::On {
        return Ok(None);
    }
    ensure!(
        spec.stdio == StdioMode::Inherit
            && io::stdin().is_terminal()
            && matches!(spec.signals, SignalMode::Forward { .. }),
        PtyUnavailableSnafu
    );
    Ok(Some(Pty::open()?))
}

impl Running {
    /// Waits for the child, then stops the signal thread, and returns how it ended.
    fn wait_for_exit(self, stdio: StdioMode) -> Result<(ExitKind, Vec<u8>, Vec<u8>), RunError> {
        let Self {
            child,
            supervisor,
            terminal,
        } = self;
        if let Some(terminal) = terminal {
            let pid = RustixPid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX));
            let exit = match pid {
                Some(pid) => terminal.wait(pid),
                None => Err(io::Error::other("the child has no valid pid")),
            };
            if let Some(supervisor) = supervisor {
                supervisor.finish();
            }
            terminal.finish();
            return exit
                .map(|exit| (exit, Vec::new(), Vec::new()))
                .context(SpawnSnafu);
        }
        let result = match stdio {
            StdioMode::Capture => child
                .wait_with_output()
                .map(|o| (ExitKind::from_status(o.status), o.stdout, o.stderr)),
            StdioMode::Inherit => {
                let mut child = child;
                child
                    .wait()
                    .map(|status| (ExitKind::from_status(status), Vec::new(), Vec::new()))
            }
        };
        if let Some(supervisor) = supervisor {
            supervisor.finish();
        }
        result.context(SpawnSnafu)
    }
}

/// The words that start the command: `sandbox-exec`, or the helper that execs it.
fn launcher_words(helper: Option<&Path>, controlling_tty: bool) -> Vec<OsString> {
    match helper {
        None => vec![OsString::from(SANDBOX_EXEC)],
        Some(hb) => {
            let mut words = vec![hb.as_os_str().to_owned(), "__child".into()];
            if controlling_tty {
                words.push("--controlling-tty".into());
            }
            words.push("--".into());
            words
        }
    }
}

/// The canonical per-user temporary directory, where session directories live.
fn temp_parent(env: &Environment) -> Result<CanonicalPath, RunError> {
    let dir = env
        .floor
        .user_temp_dir
        .as_deref()
        .ok_or(RunError::NoTempDir)?;
    let real = fs::canonicalize(dir).context(TempDirSnafu {
        dir: dir.to_string_lossy().into_owned(),
    })?;
    CanonicalPath::from_canonical(real).context(TempDirPathSnafu)
}

fn command_for(
    profile: &Profile,
    child_env: &ChildEnv,
    spec: &RunSpec,
    cwd: &Path,
    helper: Option<&Path>,
    controlling_tty: bool,
) -> Command {
    let mut words = launcher_words(helper, controlling_tty).into_iter();
    let mut command = Command::new(words.next().unwrap_or_default());
    command
        .args(words)
        .arg("-p")
        .arg(&profile.text)
        .args(profile.define_args())
        .arg("--")
        .args(&spec.argv)
        .env_clear()
        .envs(child_env.iter())
        .current_dir(cwd);
    if spec.stdio == StdioMode::Capture {
        command.stdin(Stdio::null());
    }
    command
}

/// Fails with a clear message when the command is not there, because `sandbox-exec` reports that
/// with exit 71, the code it also uses for "already sandboxed".
fn ensure_command_exists(word: &OsStr, child_env: &ChildEnv) -> Result<(), RunError> {
    let found = if word.as_bytes().contains(&b'/') {
        is_executable(Path::new(word))
    } else {
        let path = child_env.get("PATH").unwrap_or_default();
        path.as_bytes()
            .split(|b| *b == b':')
            .any(|dir| is_executable(&Path::new(OsStr::from_bytes(dir)).join(word)))
    };
    ensure!(found, CommandNotFoundSnafu { name: word });
    Ok(())
}

/// Whether `path` is a regular file (or a link to one) with an execute bit.
fn is_executable(path: &Path) -> bool {
    fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// Bytes `words` add to an `exec`: each string, its terminator and a pointer.
fn exec_bytes<'a>(words: impl IntoIterator<Item = &'a OsStr>) -> usize {
    words.into_iter().map(|w| w.len() + 1 + POINTER_BYTES).sum()
}

/// Checks the whole `sandbox-exec` command line and the environment against what `exec` accepts.
fn check_size(
    profile: &Profile,
    child_env: &ChildEnv,
    argv: &[OsString],
    launcher: &[OsString],
) -> Result<(), RunError> {
    let params = exec_bytes(profile.define_args().iter().map(OsStr::new));
    let profile_bytes = exec_bytes([OsStr::new(&profile.text)]);
    let command = exec_bytes(
        launcher
            .iter()
            .map(OsString::as_os_str)
            .chain([OsStr::new("-p"), OsStr::new("--")])
            .chain(argv.iter().map(OsString::as_os_str)),
    );
    let env = child_env.exec_bytes();
    let total = params + profile_bytes + command + env;
    let max = ARG_MAX - ARG_MARGIN;
    ensure!(
        total <= max,
        TooLargeSnafu {
            total,
            max,
            profile: profile_bytes,
            params,
            env,
            command
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HomeDir;
    use crate::system::ParentVars;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    fn status(raw: i32) -> ExitStatus {
        ExitStatus::from_raw(raw)
    }

    #[test]
    fn an_exit_is_its_code_and_a_signal_death_is_128_plus_the_signal() {
        assert_eq!(ExitKind::from_status(status(0)), ExitKind::Exited(0));
        assert_eq!(ExitKind::from_status(status(42 << 8)), ExitKind::Exited(42));
        assert_eq!(ExitKind::from_status(status(15)), ExitKind::Signalled(15));
        assert_eq!(ExitKind::Exited(42).code(), 42);
        assert_eq!(ExitKind::Signalled(15).code(), 143);
        assert_eq!(ExitKind::Signalled(9).code(), 137);
    }

    #[test]
    fn exec_bytes_counts_each_string_its_terminator_and_a_pointer() {
        assert_eq!(
            exec_bytes([OsStr::new("ab"), OsStr::new("")]),
            2 + 1 + 8 + 1 + 8
        );
        assert_eq!(exec_bytes([]), 0);
    }

    fn child_env_with_path(path_dirs: &[CanonicalPath]) -> ChildEnv {
        let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical("/Users/me")));
        let session = assert_ok!(CanonicalPath::from_canonical("/private/tmp/hb-1-2-3"));
        let policy_env = crate::config::MergedEnv::default();
        assert_ok!(ChildEnv::build(&EnvInputs {
            parent: &ParentVars::default(),
            home: &home,
            session_dir: &session,
            tool_dirs: path_dirs,
            stdin_is_tty: false,
            env: &policy_env,
        }))
    }

    #[test]
    fn a_bare_command_is_found_on_the_system_path_and_a_missing_one_is_a_clear_error() {
        let env = child_env_with_path(&[]);
        assert_ok!(ensure_command_exists(OsStr::new("ls"), &env));
        let err = assert_err!(ensure_command_exists(
            OsStr::new("no-such-command-xyz"),
            &env
        ));
        assert!(matches!(err, RunError::CommandNotFound { .. }));
        let text = err.to_string();
        assert!(
            text.contains("no-such-command-xyz") && text.contains("[env] tools"),
            "{text}"
        );
    }

    #[test]
    fn a_command_in_a_tool_directory_is_found_only_when_that_directory_is_on_the_path() {
        let dir = assert_ok!(TempDir::new());
        let real = assert_ok!(fs::canonicalize(dir.path()));
        let tool = real.join("mytool");
        assert_ok!(fs::write(&tool, "#!/bin/sh\n"));
        assert_ok!(fs::set_permissions(
            &tool,
            fs::Permissions::from_mode(0o755)
        ));
        let without = child_env_with_path(&[]);
        assert_err!(ensure_command_exists(OsStr::new("mytool"), &without));
        let with = child_env_with_path(&[assert_ok!(CanonicalPath::from_canonical(&real))]);
        assert_ok!(ensure_command_exists(OsStr::new("mytool"), &with));
    }

    #[test]
    fn a_command_with_a_slash_is_checked_as_a_path() {
        let env = child_env_with_path(&[]);
        assert_ok!(ensure_command_exists(OsStr::new("/usr/bin/true"), &env));
        assert_err!(ensure_command_exists(
            OsStr::new("/usr/bin/no-such-xyz"),
            &env
        ));
        assert_err!(ensure_command_exists(OsStr::new("/usr"), &env));
    }

    #[test]
    fn the_size_check_passes_a_normal_command_and_refuses_one_over_the_limit() {
        let env = child_env_with_path(&[]);
        let profile = Profile {
            text: "(version 1)".to_owned(),
            params: Vec::new(),
            warnings: Vec::new(),
        };
        assert_ok!(check_size(
            &profile,
            &env,
            &[OsString::from("ls")],
            &launcher()
        ));
        let big = OsString::from("x".repeat(ARG_MAX));
        let err = assert_err!(check_size(&profile, &env, &[big], &launcher()));
        let text = err.to_string();
        assert!(
            text.contains("the limit is") && text.contains("environment"),
            "{text}"
        );
        let just_fits = "x".repeat(ARG_MAX - ARG_MARGIN - 4096);
        assert_ok!(check_size(
            &profile,
            &env,
            &[OsString::from(just_fits)],
            &launcher()
        ));
    }

    fn pty_spec(stdio: StdioMode, signals: SignalMode) -> RunSpec {
        let mut spec = RunSpec::new(["true"]).stdio(stdio).signals(signals);
        spec.pty = PtyMode::On;
        spec
    }

    const FORWARD: SignalMode = SignalMode::Forward {
        grace: Duration::from_secs(1),
    };

    #[test]
    fn no_pty_is_opened_when_none_is_asked_for() {
        let spec = RunSpec::new(["true"]).stdio(StdioMode::Inherit);
        assert!(assert_ok!(open_pty(&spec)).is_none());
    }

    #[test]
    fn a_pty_run_needs_inherited_streams() {
        let spec = pty_spec(StdioMode::Capture, FORWARD);
        assert!(matches!(
            assert_err!(open_pty(&spec)),
            RunError::PtyUnavailable
        ));
    }

    #[test]
    fn a_pty_run_needs_signals_to_be_forwarded() {
        let spec = pty_spec(StdioMode::Inherit, SignalMode::Off);
        assert!(matches!(
            assert_err!(open_pty(&spec)),
            RunError::PtyUnavailable
        ));
    }

    #[test]
    fn stdin_is_a_tty_only_when_shared_and_hbs_own_is_one() {
        assert!(stdin_is_tty(StdioMode::Inherit, true));
        assert!(!stdin_is_tty(StdioMode::Inherit, false));
        assert!(!stdin_is_tty(StdioMode::Capture, true));
        assert!(!stdin_is_tty(StdioMode::Capture, false));
    }

    #[test]
    fn a_file_without_an_execute_bit_is_not_an_executable_command() {
        let dir = assert_ok!(TempDir::new());
        let file = dir.path().join("plain");
        assert_ok!(fs::write(&file, "x"));
        assert_ok!(fs::set_permissions(
            &file,
            fs::Permissions::from_mode(0o644)
        ));
        assert!(!is_executable(&file));
        assert_ok!(fs::set_permissions(
            &file,
            fs::Permissions::from_mode(0o700)
        ));
        assert!(is_executable(&file));
        assert_ok!(fs::set_permissions(
            &file,
            fs::Permissions::from_mode(0o001)
        ));
        assert!(is_executable(&file), "any execute bit counts");
    }

    fn launcher() -> Vec<OsString> {
        launcher_words(None, false)
    }

    fn empty_profile() -> Profile {
        Profile {
            text: String::new(),
            params: Vec::new(),
            warnings: Vec::new(),
        }
    }

    /// The size of everything but the user's command, for exact boundary tests.
    fn fixed_bytes(env: &ChildEnv) -> usize {
        exec_bytes([OsStr::new(SANDBOX_EXEC), OsStr::new("-p"), OsStr::new("--")])
            + exec_bytes([OsStr::new("")])
            + env.exec_bytes()
    }

    #[test]
    fn the_size_limit_is_exact_at_arg_max_minus_the_margin() {
        let env = child_env_with_path(&[]);
        let max = ARG_MAX - ARG_MARGIN;
        // One command word of `len` bytes adds `len + 1 + POINTER_BYTES`.
        let word_len = max - fixed_bytes(&env) - (1 + POINTER_BYTES);
        let at_limit = [OsString::from("x".repeat(word_len))];
        assert_ok!(check_size(&empty_profile(), &env, &at_limit, &launcher()));
        let over = [OsString::from("x".repeat(word_len + 1))];
        let err = assert_err!(check_size(&empty_profile(), &env, &over, &launcher()));
        assert!(
            matches!(err, RunError::TooLarge { total, max: m, .. } if total == max + 1 && m == max),
            "{err}"
        );
    }

    #[test]
    fn the_margin_and_limit_have_their_documented_values() {
        assert_eq!(ARG_MAX, 1_048_576);
        assert_eq!(ARG_MARGIN, 32_768);
    }
}
