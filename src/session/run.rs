// ABOUTME: session::run: render the profile, build the environment and session dir, spawn sandbox-exec, wait, clean up.
// ABOUTME: The one library entry point that `hb run` and the probe-matrix harness share, so they cannot run differently.
//! Running a command under the profile (design 7.2, 7.4; hb-ghd.2.3a).

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::time::Duration;

use nix::unistd::Pid;
use rustix::process::Pid as RustixPid;
use snafu::{ResultExt, Snafu, ensure};

use super::ca_bundle::{CaBundleError, write_bundle};
use super::denials::{DenialSink, Denials, DenialsError, LogStream, generate_tag};
use super::dir::{SessionDir, SessionDirError, sweep_stale};
use super::env::{ChildEnv, EnvBuildError, EnvInputs, SESSION_MARKER, TlsEnv};
use super::fence::settle;
use super::guardian::{Guardian, GuardianError};
use super::hooks::{HookRunError, run_pre_run};
use super::interactive::{Interactive, InteractiveError};
use super::launch_gate::{GateError, LaunchGate};
use super::offline::{OfflineError, OfflinePlan};
use super::ports::{closed_ports, closed_ports_warning};
use super::preflight::{PreflightError, SANDBOX_EXEC, check_nesting};
use super::proxy::{ProxyRun, ProxyTrail, ProxyTuning};
use super::pty::{Pty, PtyError};
use super::pump::Pump;
use super::reporter::Telemetry;
use super::sanitize::{ClipboardPolicy, ClipboardUse};
use super::signals::{Escalation, Setup, SignalError, StopSignal, Supervisor, Target, Watch};
use crate::config::Loaded;
use crate::guard::{SYSTEM_GIT, prepare as prepare_guard};
use crate::policy::HostRule;
use crate::policy::{CanonicalPath, PathError, ToolName};
use crate::proxy::ProxyError;
use crate::seatbelt::{Profile, RenderError, RenderInputs, render};
use crate::system::{Environment, ToolsError, find_tools};
use crate::text::Escaped;

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
    /// Where denial lines go, or `None` to not log them. The proxy's refusals go here too.
    pub denials: Option<DenialSink>,
    /// Where one line per proxy connection goes, or `None` to not log them.
    pub proxy_log: Option<DenialSink>,
    /// Whether a run that had proxy refusals ends with a warning that says so. The warning is
    /// not given when [`RunSpec::denials`] is set, because the lines are shown then.
    pub proxy_summary: bool,
    /// Adjusts the proxy before it starts. For tests.
    pub proxy_tuning: Option<ProxyTuning>,
    /// Makes this a `hb warm` run: see [`WarmSpec`].
    pub warm: Option<WarmSpec>,
    /// A way for another thread to stop the run as SIGTERM would, including during the pre-run
    /// hooks. Only used with [`SignalMode::Forward`].
    pub stop: Option<Arc<StopSignal>>,
    /// Where each proxy connection is reported as a typed event, for a supervisor.
    pub telemetry: Option<Telemetry>,
    /// Called with the agent's process id once it is running under the sandbox.
    pub on_start: Option<OnStart>,
}

/// A function called with the agent's process id; a newtype so [`RunSpec`] can stay `Debug`.
#[derive(Clone)]
pub struct OnStart(pub Arc<dyn Fn(u32) + Send + Sync>);

impl std::fmt::Debug for OnStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OnStart(..)")
    }
}

/// What makes a run a warm run (design 10, hb-ghd.7.3).
///
/// The files, environment and tools are the policy's, as in any run. The network is not: the
/// proxy allows exactly `allowlist`, and no launcher scripts are written, so the tools run online
/// with hb's cache named in their environment instead of offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmSpec {
    /// The only hosts the proxy allows.
    pub allowlist: Vec<HostRule>,
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
            proxy_log: None,
            proxy_summary: true,
            proxy_tuning: None,
            warm: None,
            stop: None,
            telemetry: None,
            on_start: None,
        }
    }

    /// Lets `stop` end the run as SIGTERM would.
    #[must_use]
    pub fn stop(mut self, stop: Arc<StopSignal>) -> Self {
        self.stop = Some(stop);
        self
    }

    /// Makes this a warm run.
    #[must_use]
    pub fn warm(mut self, warm: WarmSpec) -> Self {
        self.warm = Some(warm);
        self
    }

    /// Logs every proxy connection, to `sink`.
    #[must_use]
    pub fn proxy_log(mut self, sink: DenialSink) -> Self {
        self.proxy_log = Some(sink);
        self
    }

    /// Turns the end-of-run warning about refused proxy connections on or off.
    #[must_use]
    pub fn proxy_summary(mut self, on: bool) -> Self {
        self.proxy_summary = on;
        self
    }

    /// Adjusts the proxy's configuration before it starts. For tests.
    #[must_use]
    pub fn proxy_tuning(mut self, tuning: ProxyTuning) -> Self {
        self.proxy_tuning = Some(tuning);
        self
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
    /// What the profile denied and the proxy refused, when [`RunSpec::denials`] was
    /// [`DenialSink::Collect`].
    pub denials: Denials,
    /// Every proxy connection, when [`RunSpec::proxy_log`] was [`DenialSink::Collect`].
    pub proxy_log: Denials,
}

/// Why a run could not start.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum RunError {
    /// There was no command to run.
    #[snafu(display("there is no command to run"))]
    EmptyCommand,

    /// A stop (INT, TERM, HUP or the supervisor) arrived before the command was started.
    #[snafu(display("the run was stopped before the command started"))]
    Stopped,

    /// A pre-run hook failed.
    #[snafu(transparent)]
    Hook {
        /// The underlying error.
        source: HookRunError,
    },

    /// The offline MCP launchers or their cache could not be set up.
    #[snafu(transparent)]
    Offline {
        /// The underlying error.
        source: OfflineError,
    },

    /// The proxy could not start.
    #[snafu(transparent)]
    Proxy {
        /// The underlying error.
        source: ProxyError,
    },

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

    /// `hb ctl` could not be set up.
    #[snafu(transparent)]
    Ctl {
        /// The underlying error.
        source: super::ctl::CtlError,
    },

    /// The session directory is too deep for a unix socket.
    #[snafu(display("the path {path} is too long for the hb ctl socket"))]
    CtlSocketPath {
        /// The socket path.
        path: String,
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

    /// The process that cleans up after a killed hb could not be started or told what to watch.
    #[snafu(transparent)]
    Guardian {
        /// The underlying error.
        source: GuardianError,
    },

    /// The child could not obtain guardian-backed launch authorization.
    #[snafu(transparent)]
    LaunchGate {
        /// The gate error.
        source: GateError,
    },

    /// The CA bundle for `tls.extra_ca_files` could not be built.
    #[snafu(transparent)]
    CaBundle {
        /// The underlying error.
        source: CaBundleError,
    },

    /// The filter between the agent's output and the user's terminal could not be started.
    #[snafu(display("the output filter could not be started"))]
    OutputFilter {
        /// The underlying error.
        source: io::Error,
    },

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

    warnings.extend(skipped_allow_warnings(loaded));
    let offline = OfflinePlan::plan(&loaded.policy, &tools, &env.home);
    if let Some(plan) = &offline {
        warnings.extend(plan.warnings().iter().cloned());
    }

    let temp = temp_parent(env)?;
    sweep_stale(temp.as_path());
    let session = SessionDir::create(&temp)?;
    // Registered before the hooks so that a signal or a stop during them is seen: the hooks can
    // run for minutes and hold credentials. The thread ends just before the child starts, and
    // anything that arrives after is left for the thread that supervises the child.
    let watch = match spec.signals {
        SignalMode::Off => None,
        SignalMode::Forward { .. } => Some(Watch::prepare(pty.is_some())?),
    };
    if let (Some(watch), Some(stop)) = (&watch, &spec.stop) {
        stop.attach(watch.trigger());
    }
    let setup = watch.as_ref().map(Watch::guard_setup).transpose()?;
    // Host-side hooks run now, before the proxy and the profile: a failure ends the run here, and
    // the session directory (with whatever they wrote) goes with it.
    let stop_flag = setup.as_ref().map(Setup::flag);
    let hook_outputs = run_pre_run(
        &loaded.policy.hooks,
        session.path(),
        &env.home,
        stop_flag.as_deref(),
    )?;
    let (launchers, warm_cache) = match (&offline, &spec.warm) {
        (Some(plan), None) => (Some(plan.install(session.path())?), None),
        (Some(plan), Some(_)) => (None, Some(plan.install_cache()?)),
        (None, _) => (None, None),
    };
    // `hb ctl` (design 9.3). A warm run starts no agent, so it gets none. The guardian is started
    // first and told about the socket before it exists, so an `hb` killed at any point after
    // this leaves no socket behind.
    let ctl_scope = spec
        .warm
        .is_none()
        .then(|| super::ctl::scope_of(&loaded.policy))
        .flatten();
    let helper = match (spec.signals, &pty, &ctl_scope) {
        (SignalMode::Off, None, None) => None,
        _ => Some(env.floor.hb_exe.as_deref().ok_or(RunError::NoHbExe)?),
    };
    let mut guardian = helper.map(Guardian::start).transpose()?;
    let ctl = match ctl_scope {
        Some(scope) => {
            let hb = env.floor.hb_exe.as_deref().ok_or(RunError::NoHbExe)?;
            Some(start_ctl(
                env,
                loaded,
                &session,
                hb,
                scope,
                guardian.as_mut(),
                &mut warnings,
            )?)
        }
        None => None,
    };

    let loopback: Vec<_> = loaded
        .policy
        .net
        .loopback_ports
        .iter()
        .map(|p| p.value)
        .collect();
    warnings.extend(closed_ports_warning(&closed_ports(&loopback)));

    // The proxy lives as long as the child: started before the profile (which names its port)
    // and stopped after the child has gone.
    let trail = Arc::new(
        ProxyTrail::new(spec.denials.as_ref(), spec.proxy_log.as_ref())
            .with_telemetry(spec.telemetry.clone()),
    );
    let allowlist = spec.warm.as_ref().map_or_else(
        || loaded.policy.run_allowlist(),
        |warm| warm.allowlist.clone(),
    );
    let proxy = ProxyRun::start(&loaded.policy, allowlist, trail, spec.proxy_tuning.as_ref())?;
    let proxy_url = proxy.url();

    let tool_dirs = tools.dirs();
    let tag = spec.denials.as_ref().map(|_| generate_tag());
    let mut inputs = RenderInputs::new()
        .with_session_dir(session.path().clone())
        .with_exec_dirs(tool_dirs.clone());
    let cache_root = launchers
        .as_ref()
        .map(|installed| installed.cache_root())
        .or(warm_cache.as_ref());
    if let Some(root) = cache_root {
        inputs = inputs.with_cache_dir(root.clone());
    }
    let roots: Vec<CanonicalPath> = loaded
        .policy
        .fs
        .write
        .iter()
        .map(|grant| grant.value.clone())
        .collect();
    let guard = prepare_guard(&roots, Path::new(SYSTEM_GIT));
    warnings.extend(guard.notes.iter().map(ToString::to_string));
    inputs = inputs
        .with_guard(guard.inputs)
        .with_guard_allow(guard.tracked);
    if let Some(endpoint) = proxy.endpoint() {
        inputs = inputs.with_proxy(endpoint);
    }
    if let Some(tag) = &tag {
        inputs = inputs.with_log_tag(tag.clone());
    }
    if let Some(pty) = &pty {
        inputs = inputs.with_tty(pty.slave_path().clone());
    }
    if let Some(ctl) = &ctl {
        inputs = inputs
            .with_ctl_socket(ctl.socket.clone())
            .with_mount_pins(ctl.pins.clone());
    }
    let profile = render(&loaded.policy, &inputs)?;
    warnings.extend(profile.warnings.iter().map(ToString::to_string));

    let ca_files: Vec<CanonicalPath> = loaded
        .policy
        .tls
        .extra_ca_files
        .iter()
        .map(|file| file.value.clone())
        .collect();
    let ca_bundle = write_bundle(session.path(), &ca_files)?;

    let mut child_vars = hook_outputs.vars().clone();
    if let Some(root) = &warm_cache {
        child_vars.extend(super::offline::cache_vars(root));
    }
    let stdin_is_tty = stdin_is_tty(spec.stdio, io::stdin().is_terminal());
    let child_env = ChildEnv::build(&EnvInputs {
        parent: &env.vars,
        home: &env.home,
        session_dir: session.path(),
        tool_dirs: &tool_dirs,
        shim_dir: launchers
            .as_ref()
            .map(|installed| installed.bin_dir())
            .or(ctl.as_ref().map(|c| &c.bin)),
        stdin_is_tty,
        env: &loaded.policy.env,
        tls: TlsEnv {
            system_trust: loaded.policy.tls.effective_system_trust(),
            ca_bundle: ca_bundle.as_ref(),
        },
        proxy: Some(&proxy_url),
        hook_vars: &child_vars,
        ctl_socket: ctl.as_ref().map(|c| &c.socket),
    })?;
    ensure_command_exists(&spec.argv[0], &child_env)?;
    let gate = helper.map(|_| LaunchGate::bind()).transpose()?;
    let launcher = launcher_words(helper, pty.is_some(), gate.as_ref().map(LaunchGate::path));
    check_size(&profile, &child_env, &spec.argv, &launcher)?;

    let mut command = command_for(&profile, &child_env, spec, &env.cwd, launcher);
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
            } else {
                // Without a pty the agent would write to the user's terminal past the output
                // filter, so a stream that is a terminal goes through a pipe and the filter.
                if io::stdout().is_terminal() {
                    command.stdout(Stdio::piped());
                }
                if io::stderr().is_terminal() {
                    command.stderr(Stdio::piped());
                }
            }
        }
    }
    // If hb is killed (SIGKILL cannot be handled) nothing in hb can end the agent or the log
    // stream, so a guard process does. It exists whenever hb supervises the run.
    if let (Some(guardian), Some(_), Some(terminal)) = (guardian.as_mut(), &pty, user_terminal()) {
        // So that if hb is killed while it holds the terminal raw, the guard can say what happened.
        guardian.terminal(&terminal)?;
    }
    // The log is listening before the child starts, so its first denials are not missed.
    let log = match (&tag, &spec.denials) {
        (Some(tag), Some(sink)) => Some(LogStream::start(tag, sink.clone())?),
        _ => None,
    };
    if let (Some(guardian), Some(log)) = (guardian.as_mut(), &log) {
        guardian.watch(Target::Child(pid_of(log.pid())))?;
    }
    // The last point a stop can end the run without a child to clean up after.
    if setup.is_some_and(Setup::finish) {
        return StoppedSnafu.fail();
    }
    let mut child = command.spawn().context(SpawnSnafu)?;
    let permit = match gate.as_ref().map(|gate| gate.ready(child.id())).transpose() {
        Ok(permit) => permit,
        Err(error) => {
            abort_child(&mut child);
            return Err(error.into());
        }
    };
    #[cfg(feature = "test-support")]
    test_gate_pause("ready", child.id());
    if let Some(guardian) = guardian.as_mut() {
        // With a pty or no terminal the child leads its own group; otherwise it shares hb's.
        let target = if pty.is_some() || !stdin_is_tty {
            Target::Group(pid_of(child.id()))
        } else {
            Target::Child(pid_of(child.id()))
        };
        if let Err(error) = guardian.protect(target) {
            abort_child(&mut child);
            return Err(error.into());
        }
    }
    #[cfg(feature = "test-support")]
    test_gate_pause("protected", child.id());
    let clipboard = if loaded.policy.terminal.effective_clipboard_write() {
        ClipboardPolicy::Allow
    } else {
        ClipboardPolicy::Deny
    };
    let pumps = if spec.stdio == StdioMode::Inherit && pty.is_none() {
        match start_pumps(&mut child, clipboard) {
            Ok(pumps) => pumps,
            Err(error) => {
                abort_child(&mut child);
                return Err(error);
            }
        }
    } else {
        Vec::new()
    };
    let mut running = match pty {
        Some(pty) => start_on_pty(child, pty, watch, spec.signals, clipboard)?,
        None => start_supervisor(child, watch, spec.signals, stdin_is_tty)?,
    };
    running.pumps = pumps;
    if let Some((gate, permit)) = gate.zip(permit)
        && let Err(error) = gate.authorize(permit)
    {
        abort_child(&mut running.child);
        return Err(error.into());
    }
    if let Some(on_start) = &spec.on_start {
        (on_start.0)(running.child.id());
    }
    let waited = running.wait_for_exit(spec.stdio);
    let denials = log.map(LogStream::finish).unwrap_or_default();
    if let Some(ctl) = ctl {
        ctl.broker.finish();
    }
    // A failed wait cannot authorize the guardian to stand down.
    // On error, dropping it retains its independent cleanup path.
    let waited = waited?;
    if let Some(guardian) = guardian {
        guardian.release();
    }
    let Waited {
        exit,
        stdout,
        stderr,
        clipboard,
    } = waited;
    drop(session);
    warnings.extend(clipboard_notices(clipboard));
    let seen = proxy.finish();
    if spec.proxy_summary && spec.denials.is_none() {
        warnings.extend(seen.summary());
    }
    let mut denials = denials;
    denials.lines.extend(seen.denials.lines);
    denials.dropped += seen.denials.dropped;
    Ok(Outcome {
        exit,
        stdout,
        stderr,
        warnings,
        denials,
        proxy_log: seen.log,
    })
}

/// What `hb ctl` adds to a run: the broker, and the two things the child needs from it.
struct CtlRun {
    broker: crate::ctl::broker::Broker,
    pins: Vec<CanonicalPath>,
    socket: CanonicalPath,
    bin: CanonicalPath,
}

/// Starts the broker and writes the `hb` wrapper. The socket is registered with the guardian
/// before it is bound. Startup notes (a container that failed its checks) go into `warnings`.
fn start_ctl(
    env: &Environment,
    loaded: &Loaded,
    session: &SessionDir,
    hb: &Path,
    scope: crate::ctl::scope::Scope,
    mut guard: Option<&mut Guardian>,
    warnings: &mut Vec<String>,
) -> Result<CtlRun, RunError> {
    let socket_path = session.path().as_path().join(super::ctl::SOCKET_NAME);
    ensure!(
        super::ctl::socket_fits(session.path()),
        CtlSocketPathSnafu {
            path: socket_path.display().to_string()
        }
    );
    let handle = guard.as_ref().map(|g| g.handle());
    if let Some(guard) = guard.as_mut() {
        guard.socket(&socket_path)?;
    }
    let bin = session.path().as_path().join("bin");
    super::ctl::install_wrapper(&bin, hb)?;
    let started = super::ctl::start(env, loaded.root.path(), session.path(), scope, handle)?;
    warnings.extend(started.service.warnings);
    let bin =
        CanonicalPath::from_canonical(&bin).map_err(|source| RunError::TempDirPath { source })?;
    Ok(CtlRun {
        broker: started.service.broker,
        pins: started.service.pins,
        socket: started.socket,
        bin,
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
    /// The filters between the agent's streams and the user's terminal, when there is no pty.
    pumps: Vec<Pump>,
}

/// How a run ended, with what was captured and what the filters saw.
struct Waited {
    exit: ExitKind,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// What the agent did with the user's clipboard.
    clipboard: ClipboardUse,
}

/// Starts a [`Pump`] for each of the child's streams that was given a pipe in place of the
/// user's terminal.
fn start_pumps(child: &mut Child, clipboard: ClipboardPolicy) -> Result<Vec<Pump>, RunError> {
    let mut pumps = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let sink = io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .context(OutputFilterSnafu)?;
        pumps.push(
            Pump::start_with(OwnedFd::from(stdout), sink, clipboard).context(OutputFilterSnafu)?,
        );
    }
    if let Some(stderr) = child.stderr.take() {
        let sink = io::stderr()
            .as_fd()
            .try_clone_to_owned()
            .context(OutputFilterSnafu)?;
        pumps.push(
            Pump::start_with(OwnedFd::from(stderr), sink, clipboard).context(OutputFilterSnafu)?,
        );
    }
    Ok(pumps)
}

/// The path of the user's terminal (hb's stdin), if it has one.
fn user_terminal() -> Option<std::path::PathBuf> {
    let name = rustix::termios::ttyname(io::stdin(), Vec::new()).ok()?;
    Some(std::path::PathBuf::from(
        name.to_string_lossy().into_owned(),
    ))
}

/// The terminal the agent's output went to, as a descriptor `hb` can also read from: its stdout, or
/// failing that its stderr, whichever is a terminal.
fn output_terminal() -> Option<OwnedFd> {
    let stdout = io::stdout();
    let stderr = io::stderr();
    let fd = if stdout.is_terminal() {
        stdout.as_fd().try_clone_to_owned()
    } else if stderr.is_terminal() {
        stderr.as_fd().try_clone_to_owned()
    } else {
        return None;
    };
    fd.ok()
}

/// The lines that tell the user what the agent did with their clipboard: nothing, if nothing.
fn clipboard_notices(used: ClipboardUse) -> Vec<String> {
    let times = |n: usize| {
        if n == 1 {
            "1 time".to_owned()
        } else {
            format!("{n} times")
        }
    };
    let mut lines = Vec::new();
    if used.allowed > 0 {
        lines.push(format!(
            "the agent set your clipboard {}",
            times(used.allowed)
        ));
    }
    if used.blocked > 0 {
        lines.push(format!(
            "the agent tried to set your clipboard {}; terminal.clipboard_write = false stopped it",
            times(used.blocked)
        ));
    }
    lines
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
            pumps: Vec::new(),
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
            pumps: Vec::new(),
        }),
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(error.into())
        }
    }
}

/// A process number from the standard library's `u32` id.
fn pid_of(id: u32) -> Pid {
    Pid::from_raw(i32::try_from(id).unwrap_or(i32::MAX))
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
    clipboard: ClipboardPolicy,
) -> Result<Running, RunError> {
    let (Some(watch), SignalMode::Forward { grace }) = (watch, mode) else {
        abort_child(&mut child);
        return Err(RunError::PtyUnavailable);
    };
    // Dropping hb's own copy of the slave lets the master see the end of the child's output.
    let terminal = match Interactive::start(pty.release_slave(), clipboard) {
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
            pumps: Vec::new(),
        }),
        Err(error) => {
            abort_child(&mut child);
            terminal.finish();
            Err(error.into())
        }
    }
}

/// One warning for each `fs.read`/`fs.write` entry that was left out, so a rule that has no effect
/// is not discovered from the agent's own error.
fn skipped_allow_warnings(loaded: &Loaded) -> impl Iterator<Item = String> + '_ {
    loaded
        .closure
        .files()
        .iter()
        .flat_map(|file| file.diagnostics.skipped.iter())
        .map(|skipped| {
            format!(
                "{}: `{}` was not granted: {}",
                skipped.origin,
                Escaped(&skipped.value.spelling),
                skipped.value.reason.to_string().to_lowercase()
            )
        })
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
    fn wait_for_exit(self, stdio: StdioMode) -> Result<Waited, RunError> {
        let Self {
            child,
            supervisor,
            terminal,
            pumps,
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
            let clipboard = terminal.finish();
            return exit
                .map(|exit| Waited {
                    exit,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    clipboard,
                })
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
        // The agent has ended: let the filters write what is left before anything else is printed.
        let filtered = !pumps.is_empty();
        let clipboard = pumps
            .into_iter()
            .map(Pump::finish)
            .fold(ClipboardUse::default(), |sum, used| sum + used);
        if filtered && let Some(terminal) = output_terminal() {
            settle(&terminal);
        }
        result
            .map(|(exit, stdout, stderr)| Waited {
                exit,
                stdout,
                stderr,
                clipboard,
            })
            .context(SpawnSnafu)
    }
}

/// Pauses a real launch at a named boundary for parent-death and ordering tests.
#[cfg(feature = "test-support")]
fn test_gate_pause(stage: &str, pid: u32) {
    if std::env::var("HB_TEST_GATE_STAGE").unwrap_or_else(|_| "ready".into()) != stage {
        return;
    }
    if let Some(path) = std::env::var_os("HB_TEST_GATE_READY") {
        let path = std::path::PathBuf::from(path);
        let pending = path.with_extension("pending");
        if fs::write(&pending, pid.to_string())
            .and_then(|()| fs::rename(&pending, &path))
            .is_err()
        {
            return;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while !path.with_extension("continue").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// The words that start the command: `sandbox-exec`, or the helper that execs it.
fn launcher_words(
    helper: Option<&Path>,
    controlling_tty: bool,
    gate: Option<&Path>,
) -> Vec<OsString> {
    match helper {
        None => vec![OsString::from(SANDBOX_EXEC)],
        Some(hb) => {
            let mut words = vec![hb.as_os_str().to_owned(), "__child".into()];
            if controlling_tty {
                words.push("--controlling-tty".into());
            }
            if let Some(gate) = gate {
                words.extend([
                    "--launch-gate".into(),
                    gate.as_os_str().to_owned(),
                    "--gate-parent".into(),
                    std::process::id().to_string().into(),
                ]);
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
    launcher: Vec<OsString>,
) -> Command {
    let mut words = launcher.into_iter();
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
            shim_dir: None,
            stdin_is_tty: false,
            env: &policy_env,
            tls: TlsEnv::default(),
            proxy: None,
            hook_vars: &std::collections::BTreeMap::new(),
            ctl_socket: None,
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
    fn the_clipboard_notice_counts_in_the_singular_and_the_plural_and_is_silent_for_none() {
        let used = |allowed, blocked| ClipboardUse { allowed, blocked };
        assert!(clipboard_notices(used(0, 0)).is_empty());
        assert_eq!(
            clipboard_notices(used(1, 0)),
            ["the agent set your clipboard 1 time"]
        );
        assert_eq!(
            clipboard_notices(used(2, 0)),
            ["the agent set your clipboard 2 times"]
        );
        assert_eq!(
            clipboard_notices(used(40, 0)),
            ["the agent set your clipboard 40 times"]
        );
    }

    #[test]
    fn writes_that_were_blocked_are_reported_as_attempts_and_name_the_setting() {
        let used = |allowed, blocked| ClipboardUse { allowed, blocked };
        assert_eq!(
            clipboard_notices(used(0, 1)),
            [
                "the agent tried to set your clipboard 1 time; terminal.clipboard_write = false stopped it"
            ]
        );
        assert_eq!(
            clipboard_notices(used(0, 3)),
            [
                "the agent tried to set your clipboard 3 times; terminal.clipboard_write = false stopped it"
            ]
        );
        // Both can happen only if the policy changed mid-run, which it cannot; both are reported anyway.
        assert_eq!(clipboard_notices(used(1, 1)).len(), 2);
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
        launcher_words(None, false, None)
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
