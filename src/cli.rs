// ABOUTME: The `hb` command line: clap parsing and dispatch, with injected environment and output streams.
// ABOUTME: Lives in the library so tests call `run` directly; `src/bin/hb.rs` only forwards the process arguments.
//! The command line.
//!
//! [`run`] parses `args`, reads the process environment only when a command needs it, writes to
//! the given streams and returns the exit code:
//!
//! | code | meaning |
//! |---|---|
//! | 0 | success (`explain` with warnings is still 0) |
//! | 1 | config, load, floor or run-start error, printed with its cause chain (`hb ctl`: a refused or failed request) |
//! | 2 | usage error (clap's default); `hb ctl` outside a run with a `[ctl]` section |
//! | n | `hb run`: the command's own exit code, or `128 + signal` |
//! | 78 | the project's config is not approved; nothing was run |

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use nix::sys::signal::{Signal, raise};
use snafu::Report;

use crate::approval::{
    ApprovalStore, ApproveError, Candidate, NoTerminal, StdTerminal, Terminal, Verdict, require,
};
use crate::config::{Discovery, Loaded, discover, load_project};
use crate::explain::{ExplainRequest, Format, explain};
use crate::seatbelt::{ProxyEndpoint, RenderInputs, render};
use crate::session::signals::{block_supervised, unblock_supervised};
use crate::session::{
    self, DEFAULT_GRACE, DenialSink, Denials, ExitKind, PtyMode, RunError, RunSpec, SESSION_MARKER,
    SignalMode, StdioMode, check_nesting, exec_gated, exec_sandbox_exec, run_guard,
};
use crate::system::{Environment, StateDir, UserConfigDir};
use crate::text::Escaped;

/// Run AI coding agents inside a hamster ball.
#[derive(Debug, Parser)]
#[command(
    name = "hb",
    version,
    about,
    override_usage = "hb <COMMAND>\n       hb run [OPTIONS] [--] <COMMAND>...",
    after_help = "To run a program in the hamster ball: hb run -- <program> [args]\nFor example: hb run -- ~/.local/bin/claude"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create ~/.config/hamster-ball/base.toml (never overwrites).
    Init,
    /// Show every effective rule for this project and where it came from.
    Explain(ExplainArgs),
    /// Review and approve this project's config, or take the approval back.
    ///
    /// The agent can write the project directory, so `hb run` runs a project config only when its
    /// exact bytes were approved here. Needs a terminal; there is no way to approve without one.
    Approve(ApproveArgs),
    /// Report what hb cannot see: secrets the guard misses, git it does not protect, system proxies, and MCP servers that cannot start offline.
    ///
    /// Secrets: look-alike files, tracked files, launchd variables (names only, never contents).
    /// Git: repositories below a write grant, hook managers and `core.hooksPath`, which the floor
    /// does not cover. Proxy: the system proxy and PAC settings, which hb does not follow.
    /// MCP: `uvx` and `npx` servers never warmed, with a moving version tag or an unpinned git
    /// source, or whose launcher `[env] tools` lacks (the one flagged argument, never the others).
    Doctor,
    /// Print the Seatbelt profile and parameters this project would run under.
    ///
    /// The proxy parameter is a placeholder: each run's proxy listens on a port chosen at start.
    Profile,
    /// Fill hb's offline cache for the MCP servers a project declares (the only command that reaches the registries).
    ///
    /// Starts each `[mcp.*]` server whose command is `uvx` or `npx` once, in the same ball a run
    /// uses, with only the package registries (and the server's `warm_net`) reachable, and waits
    /// for it to answer an MCP `initialize`. `hb run` then starts those servers from the cache with
    /// no registry. Run it outside any hamster ball.
    Warm(WarmArgs),
    /// Run a command inside the hamster ball and exit with its status.
    ///
    /// The command starts with an empty environment: only HOME, PATH, TMPDIR, TERM and the names
    /// in `[env] pass` and `[env] set` reach it. A program found through `[env] tools` is on its PATH.
    Run(RunArgs),
    /// Inside the ball: see and restart the containers and launchd jobs the config lists.
    ///
    /// Talks to the run's broker over the one socket the sandbox allows (`HB_CTL_SOCKET`). There is
    /// no `run`, `exec`, `build`, `rm` or `cp`: only the operations below, on listed targets.
    Ctl(CtlArgs),
    /// Internal: clear the signal mask and exec sandbox-exec. Started by `hb run`, never by hand.
    #[command(name = "__child", hide = true)]
    Child(ChildArgs),
    /// Internal: exec a broker command after the cleanup guard has armed. Started by `hb run`.
    #[command(name = "__exec", hide = true)]
    Exec(ExecArgs),
    /// Internal: end the agent and the log stream if hb is killed. Started by `hb run`, never by hand.
    #[command(name = "__guard", hide = true)]
    Guard(GuardArgs),
}

#[derive(Debug, Args)]
struct CtlArgs {
    #[command(subcommand)]
    op: CtlOp,
}

#[derive(Debug, Subcommand)]
enum CtlOp {
    /// List the containers in scope with their state, or the one named.
    Ps {
        /// A container name.
        name: Option<String>,
    },
    /// The last lines of a container's log.
    Logs {
        /// The container.
        name: String,
        /// How many lines (at most 2000).
        #[arg(long, value_name = "N")]
        tail: Option<u64>,
    },
    /// One CPU and memory sample.
    Stats {
        /// The container.
        name: String,
    },
    /// Start a stopped container.
    Start {
        /// The container.
        name: String,
    },
    /// Stop a container.
    Stop {
        /// The container.
        name: String,
    },
    /// Restart a container.
    Restart {
        /// The container.
        name: String,
    },
    /// A launchd job listed in `[ctl] launchd`.
    Launchd {
        #[command(subcommand)]
        op: CtlLaunchd,
    },
}

#[derive(Debug, Subcommand)]
enum CtlLaunchd {
    /// State, pid, run count and last exit code (never the job's environment).
    Status {
        /// The job label.
        label: String,
    },
    /// Start a loaded job that is not running.
    Kickstart {
        /// The job label.
        label: String,
    },
    /// Kill the job's process and start it again.
    Restart {
        /// The job label.
        label: String,
    },
}

impl From<CtlOp> for crate::ctl::client::Command {
    fn from(op: CtlOp) -> Self {
        use crate::ctl::client::Command as C;
        use crate::ctl::op::{ContainerOp, LaunchdOp};
        let named = |op, name| C::Container {
            op,
            name: Some(name),
            tail: None,
        };
        match op {
            CtlOp::Ps { name } => C::Container {
                op: ContainerOp::Ps,
                name,
                tail: None,
            },
            CtlOp::Logs { name, tail } => C::Container {
                op: ContainerOp::Logs,
                name: Some(name),
                tail,
            },
            CtlOp::Stats { name } => named(ContainerOp::Stats, name),
            CtlOp::Start { name } => named(ContainerOp::Start, name),
            CtlOp::Stop { name } => named(ContainerOp::Stop, name),
            CtlOp::Restart { name } => named(ContainerOp::Restart, name),
            CtlOp::Launchd { op } => match op {
                CtlLaunchd::Status { label } => C::Launchd {
                    op: LaunchdOp::Status,
                    label,
                },
                CtlLaunchd::Kickstart { label } => C::Launchd {
                    op: LaunchdOp::Kickstart,
                    label,
                },
                CtlLaunchd::Restart { label } => C::Launchd {
                    op: LaunchdOp::Restart,
                    label,
                },
            },
        }
    }
}

#[derive(Debug, Args)]
struct ApproveArgs {
    /// Remove this project's approval. Needs no terminal.
    #[arg(long)]
    revoke: bool,
}

#[derive(Debug, Args)]
struct WarmArgs {
    /// Show what the sandbox denied while each server started.
    #[arg(long)]
    log_denials: bool,

    /// Show every connection the proxy handled: host, port, whether it was allowed, and bytes.
    #[arg(long)]
    log_proxy: bool,

    /// Seconds each server gets to answer before it is stopped.
    #[arg(long, value_name = "SECS", default_value_t = 300)]
    timeout: u64,

    /// The servers to warm; none means every one that starts `uvx` or `npx`.
    #[arg(value_name = "NAME")]
    names: Vec<String>,
}

#[derive(Debug, Args)]
struct GuardArgs {
    /// Milliseconds between SIGTERM and SIGKILL when the guard has to end the processes.
    #[arg(long, default_value_t = 2000)]
    grace_ms: u64,
}

#[derive(Debug, Args)]
struct ExecArgs {
    /// The absolute program, then its arguments.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

#[derive(Debug, Args)]
struct ChildArgs {
    /// Become a session leader and take stdin (the pty slave) as the controlling terminal first.
    #[arg(long)]
    controlling_tty: bool,
    /// Stdin is a launch-gate socket: receive the real stdin and exec only after release.
    #[arg(long)]
    gate: bool,
    /// The arguments for `sandbox-exec`.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    argv: Vec<OsString>,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Show what the sandbox denied during this run.
    ///
    /// Redirected stderr gets each denial as it happens; on a terminal they are printed after the
    /// command ends, so they cannot corrupt an interactive screen. The system log is not complete:
    /// treat the lines as hints, and put this flag before the command.
    #[arg(long)]
    log_denials: bool,

    /// Show every connection the proxy handled: host, port, whether it was allowed, and bytes.
    ///
    /// Shown like the denials: live when stderr is redirected, after the command ends on a
    /// terminal. Put this flag before the command.
    #[arg(long)]
    log_proxy: bool,

    /// Do not end the run with a warning that the proxy refused connections.
    ///
    /// The warning is also left out when `--log-denials` already shows them.
    #[arg(long)]
    no_proxy_summary: bool,

    /// The command and its arguments (a `--` before it is optional).
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "COMMAND"
    )]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Output format.
    #[arg(long, value_enum, default_value_t = FormatArg::Text)]
    format: FormatArg,

    /// Show MCP server and hook arguments instead of only counting them.
    ///
    /// Environment values set with `env.set` are never shown.
    #[arg(long)]
    show_args: bool,

    /// Explain why this path can or cannot be reached (relative paths are relative to the project root).
    ///
    /// The answer covers the merged config and the floor only, not the system allows or the
    /// secrets guard.
    #[arg(long, value_name = "PATH")]
    path: Option<String>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FormatArg {
    Text,
    Json,
}

impl From<FormatArg> for Format {
    fn from(arg: FormatArg) -> Self {
        match arg {
            FormatArg::Text => Self::Text,
            FormatArg::Json => Self::Json,
        }
    }
}

/// Runs `hb` with `args` (without the program name's special meaning: the first item is `hb`).
///
/// `env` is the environment to use; `None` reads the current process, and only if a command
/// needs it. Output goes to `out`, errors and usage problems to `err`.
///
/// This is the in-process entry point: it never touches the signal mask, so tests and embedders
/// can call it freely. A child that died of a signal gives `128 + signal`. The `hb` binary uses
/// [`main`], which takes over INT, TERM and HUP and re-raises (design D60).
pub fn run<I, T>(
    args: I,
    env: Option<&Environment>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    execute(args, env, out, err, None).code
}

/// How a command ended: the exit code, and a signal `hb` must now raise on itself.
#[derive(Debug, Clone, Copy)]
pub struct CliExit {
    /// What to exit with when there is no signal to raise.
    pub code: ExitCode,
    /// Set when the child died of INT, TERM, HUP or KILL: after cleanup `hb` dies of the same
    /// signal, so a calling shell or script sees a signalled child (design D60).
    pub reraise: Option<Signal>,
}

/// The process-level entry point of the `hb` binary.
///
/// For `hb run` it blocks INT, TERM and HUP first (this must be the main thread, before any
/// other thread exists), forwards them to the child and, if the child died of one, raises it on
/// this process after everything has been cleaned up.
pub fn main<I, T>(
    args: I,
    env: Option<&Environment>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    main_with_options(args, env, out, err, Supervision::default())
}

/// Whether `hb run` gives the child a pty of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PtyChoice {
    /// A pty exactly when `hb`'s stdin is a terminal.
    #[default]
    Auto,
    /// Never: the child shares `hb`'s terminal and process group. For tests of that library path.
    Off,
}

/// How [`main_with_options`] supervises a run.
#[derive(Debug, Clone, Copy)]
pub struct Supervision {
    /// How long a child gets after the first signal before it is killed.
    pub grace: Duration,
    /// Whether the child gets a pty.
    pub pty: PtyChoice,
}

impl Default for Supervision {
    fn default() -> Self {
        Self {
            grace: DEFAULT_GRACE,
            pty: PtyChoice::Auto,
        }
    }
}

/// [`main`] with the supervision settings spelled out.
pub fn main_with_options<I, T>(
    args: I,
    env: Option<&Environment>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    supervision: Supervision,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let exit = execute(args, env, out, err, Some(supervision));
    if let Some(signal) = exit.reraise {
        // The default action now runs. KILL cannot be blocked, and for the others the mask is
        // lifted first. If the process is still here, fall back to the shell convention.
        let _ = unblock_supervised();
        let _ = raise(signal);
    }
    exit.code
}

/// The signal to raise on `hb` for a child that ended this way, if any (D60).
fn reraise_for(exit: ExitKind) -> Option<Signal> {
    match exit {
        ExitKind::Signalled(n) => match Signal::try_from(n).ok()? {
            signal @ (Signal::SIGHUP | Signal::SIGINT | Signal::SIGKILL | Signal::SIGTERM) => {
                Some(signal)
            }
            _ => None,
        },
        ExitKind::Exited(_) => None,
    }
}

fn execute<I, T>(
    args: I,
    env: Option<&Environment>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    supervise: Option<Supervision>,
) -> CliExit
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let mut reraise = None;
    let code = dispatch(args, env, out, err, supervise, &mut reraise);
    CliExit { code, reraise }
}

fn dispatch<I, T>(
    args: I,
    env: Option<&Environment>,
    out: &mut dyn Write,
    err: &mut dyn Write,
    supervise: Option<Supervision>,
    reraise: &mut Option<Signal>,
) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let code = if error.use_stderr() { 2 } else { 0 };
            let stream: &mut dyn Write = if code == 0 { out } else { err };
            // Nothing to do if the stream itself is broken.
            let _ = write!(stream, "{error}");
            return ExitCode::from(code);
        }
    };
    let Some(command) = cli.command else {
        let _ = writeln!(
            out,
            "{} {}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );
        return ExitCode::SUCCESS;
    };

    // The helper replaces this process, so it needs neither the environment nor the project.
    if let Command::Child(child) = &command {
        return fail(
            err,
            crate::Error::from(exec_sandbox_exec(
                &child.argv,
                child.controlling_tty,
                child.gate,
            )),
        );
    }

    if let Command::Exec(exec) = &command {
        let (program, args) = exec.argv.split_first().unwrap_or((&exec.argv[0], &[]));
        return fail(err, crate::Error::from(exec_gated(program, args)));
    }

    // The client needs only the socket variable: no home, project or config is read inside the ball.
    if let Command::Ctl(ctl) = command {
        return ctl_command(ctl.op, out, err);
    }

    // The guard needs nothing from the environment either; it reads its orders from stdin.
    if let Command::Guard(guard) = &command {
        return match run_guard(Duration::from_millis(guard.grace_ms)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => fail(err, crate::Error::from(error)),
        };
    }

    let owned;
    let env = match env {
        Some(env) => env,
        None => match Environment::from_process() {
            Ok(process) => {
                owned = process;
                &owned
            }
            Err(error) => return fail(err, crate::Error::from(error)),
        },
    };

    match command {
        Command::Init => match UserConfigDir::locate(&env.home).init_base(&env.home) {
            Ok(path) => {
                let _ = writeln!(out, "created {}", path.display());
                ExitCode::SUCCESS
            }
            Err(error) => fail(err, crate::Error::from(error)),
        },
        Command::Profile => match profile(env) {
            Ok(text) => {
                let _ = write!(out, "{text}");
                ExitCode::SUCCESS
            }
            Err(error) => fail(err, error),
        },
        Command::Doctor => doctor_command(env, out, err),
        Command::Approve(args) => {
            approve_command(env, &args, terminal_for(supervise).as_mut(), out, err)
        }
        Command::Run(args) => run_command(env, args, err, supervise, reraise),
        Command::Warm(args) => warm_command(env, &args, out, err, supervise, reraise),
        Command::Child(_) | Command::Exec(_) | Command::Guard(_) | Command::Ctl(_) => {
            ExitCode::FAILURE
        }
        Command::Explain(args) => {
            let mut request = ExplainRequest::new(env)
                .format(args.format.into())
                .show_args(args.show_args);
            if let Some(path) = args.path.as_deref() {
                request = request.path(path);
            }
            match explain(&request) {
                Ok(text) => {
                    let _ = write!(out, "{text}");
                    ExitCode::SUCCESS
                }
                Err(error) => fail(err, crate::Error::from(error)),
            }
        }
    }
}

/// Runs a command under the project's profile and returns its status as the exit code.
///
/// The nesting check comes first, so a nested `hb` says so even where the project cannot be
/// loaded. [`session::run`] checks again; that costs about 60 ms and keeps the library entry
/// point safe to call on its own.
fn run_command(
    env: &Environment,
    args: RunArgs,
    err: &mut dyn Write,
    supervise: Option<Supervision>,
    reraise: &mut Option<Signal>,
) -> ExitCode {
    let at_terminal = std::io::stderr().is_terminal();
    let logging = RunLogging {
        denials: args.log_denials.then(|| denial_sink(at_terminal)),
        proxy_log: args.log_proxy.then(|| proxy_log_sink(at_terminal)),
        proxy_summary: !args.no_proxy_summary,
    };
    run_command_with(env, args.command, logging, err, supervise, reraise)
}

/// What `hb run` was asked to show about the run.
struct RunLogging {
    denials: Option<DenialSink>,
    proxy_log: Option<DenialSink>,
    proxy_summary: bool,
}

/// Where denial lines go: collected for printing after the run when stderr is a terminal, or
/// written live to stderr when it has been redirected.
fn denial_sink(stderr_is_terminal: bool) -> DenialSink {
    if stderr_is_terminal {
        DenialSink::Collect
    } else {
        DenialSink::Stream(std::sync::Arc::new(|line| {
            let _ = writeln!(std::io::stderr(), "hb: denied: {line}");
        }))
    }
}

/// Where the proxy's connection log goes: the same rule as [`denial_sink`].
fn proxy_log_sink(stderr_is_terminal: bool) -> DenialSink {
    if stderr_is_terminal {
        DenialSink::Collect
    } else {
        DenialSink::Stream(std::sync::Arc::new(|line| {
            let _ = writeln!(std::io::stderr(), "hb: proxy: {line}");
        }))
    }
}

/// The lines printed after the run for the collected proxy log.
fn proxy_log_lines(log: &Denials) -> Vec<String> {
    let mut out: Vec<String> = log
        .lines
        .iter()
        .map(|l| format!("hb: proxy: {l}"))
        .collect();
    if log.dropped > 0 {
        out.push(format!(
            "hb: ... and {} more connections not shown",
            log.dropped
        ));
    }
    out
}

/// The lines printed after the run for collected denials.
fn denial_summary(denials: &Denials) -> Vec<String> {
    if denials.lines.is_empty() && denials.dropped == 0 {
        return Vec::new();
    }
    let mut out = vec![format!(
        "hb: the sandbox and proxy denied {} operation(s) (the system log is not complete, so there may be more):",
        denials.lines.len() + denials.dropped
    )];
    out.extend(denials.lines.iter().map(|l| format!("hb: denied: {l}")));
    if denials.dropped > 0 {
        out.push(format!("hb: ... and {} more not shown", denials.dropped));
    }
    out
}

fn run_command_with(
    env: &Environment,
    command: Vec<OsString>,
    logging: RunLogging,
    err: &mut dyn Write,
    supervise: Option<Supervision>,
    reraise: &mut Option<Signal>,
) -> ExitCode {
    let inside_hb = env.vars.get(SESSION_MARKER).is_some();
    if let Err(error) = check_nesting(inside_hb) {
        return fail(err, crate::Error::from(RunError::from(error)));
    }
    let (discovery, loaded) = match load_project(env) {
        Ok(project) => project,
        Err(error) => return fail(err, crate::Error::from(error)),
    };
    // The question comes before signals are taken over, so Ctrl-C at the prompt ends `hb`.
    let mut terminal = terminal_for(supervise);
    if let Err(code) = ensure_approved(env, &discovery, &loaded, terminal.as_mut(), err) {
        return code;
    }
    if supervise.is_some() {
        if let Err(error) = block_supervised() {
            return fail(err, crate::Error::from(RunError::from(error)));
        }
    }
    // Said before the command starts: the agent's own error for it is only "Operation not permitted".
    if let Some(warning) = loaded.policy.project_grant_warning(discovery.root.path()) {
        let _ = writeln!(err, "warning: {warning}");
    }
    if let Some(warning) = crate::session::gitconfig::warning(&loaded.policy, &env.home) {
        let _ = writeln!(err, "warning: {warning}");
    }
    let warm_store = crate::warm::stamp::WarmStore::new(&StateDir::locate(&env.home));
    for warning in crate::warm::cold_warnings(&loaded.policy, &warm_store, discovery.root.path()) {
        let _ = writeln!(err, "warning: {warning}");
    }
    let signals = supervise.map_or(SignalMode::Off, |s| SignalMode::Forward { grace: s.grace });
    let mut spec = RunSpec::new(command)
        .stdio(StdioMode::Inherit)
        .signals(signals);
    // A pty exactly when hb is supervising and stdin is a terminal; the in-process entry point
    // (`run`) never allocates one, so a developer running `cargo test` in a terminal is unaffected.
    if supervise.is_some_and(|s| s.pty == PtyChoice::Auto) && std::io::stdin().is_terminal() {
        spec.pty = PtyMode::On;
    }
    spec.denials = logging.denials;
    spec.proxy_log = logging.proxy_log;
    spec.proxy_summary = logging.proxy_summary;
    match session::run(env, &loaded, &spec) {
        Ok(outcome) => {
            for warning in &outcome.warnings {
                let _ = writeln!(err, "warning: {warning}");
            }
            for line in denial_summary(&outcome.denials)
                .into_iter()
                .chain(proxy_log_lines(&outcome.proxy_log))
            {
                let _ = writeln!(err, "{line}");
            }
            if supervise.is_some() {
                *reraise = reraise_for(outcome.exit);
            }
            exit_code(outcome.exit)
        }
        Err(error) => fail(err, crate::Error::from(error)),
    }
}

/// `hb ctl ...`: one request to the broker of the run this process is inside.
fn ctl_command(op: CtlOp, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    use crate::ctl::client::{SOCKET_VAR, send, show};
    let socket = std::env::var_os(SOCKET_VAR).map(std::path::PathBuf::from);
    match send(socket.as_deref(), op.into()) {
        Ok(response) => ExitCode::from(show(&response, out, err)),
        Err(error) => {
            let _ = writeln!(err, "hb ctl: {}", snafu::Report::from_error(error));
            ExitCode::from(2)
        }
    }
}

/// `hb warm`: fill the offline cache for the declared `uvx` and `npx` servers.
fn warm_command(
    env: &Environment,
    args: &WarmArgs,
    out: &mut dyn Write,
    err: &mut dyn Write,
    supervise: Option<Supervision>,
    reraise: &mut Option<Signal>,
) -> ExitCode {
    use crate::warm::{self, Logging, Warmed};
    if env.vars.get(SESSION_MARKER).is_some() {
        let _ = writeln!(
            err,
            "error: hb warm reaches the package registries and must run outside the ball"
        );
        return ExitCode::FAILURE;
    }
    let (discovery, loaded) = match load_project(env) {
        Ok(project) => project,
        Err(error) => return fail(err, crate::Error::from(error)),
    };
    let mut terminal = terminal_for(supervise);
    if let Err(code) = ensure_approved(env, &discovery, &loaded, terminal.as_mut(), err) {
        return code;
    }
    let selection = match warm::select(&loaded.policy, &args.names) {
        Ok(selection) => selection,
        Err(error) => return fail(err, crate::Error::from(error)),
    };
    for name in &selection.nothing_to_warm {
        let _ = writeln!(out, "nothing to warm: {name} does not start uvx or npx");
    }
    if selection.warm.is_empty() {
        if selection.nothing_to_warm.is_empty() {
            let _ = writeln!(out, "nothing to warm: no [mcp.*] server starts uvx or npx");
        }
        return ExitCode::SUCCESS;
    }
    if supervise.is_some() {
        if let Err(error) = block_supervised() {
            return fail(err, crate::Error::from(RunError::from(error)));
        }
    }
    let signals = supervise.map_or(SignalMode::Off, |s| SignalMode::Forward { grace: s.grace });
    let at_terminal = std::io::stderr().is_terminal();
    let limit = Duration::from_secs(args.timeout);
    let tools = match crate::system::find_tools(
        &loaded
            .policy
            .env
            .tools
            .iter()
            .map(|t| t.value.clone())
            .collect::<Vec<_>>(),
        env.floor.path_var.as_deref(),
    ) {
        Ok(tools) => tools,
        Err(error) => return fail(err, crate::Error::from(RunError::from(error))),
    };
    // One workspace for the whole selection: nothing is published until every server answered,
    // so a failure or an interrupt leaves the previous generation current.
    let build = match warm::begin(env, &selection.warm, &tools, discovery.root.path()) {
        Ok(build) => build,
        Err(error) => return fail(err, crate::Error::from(error)),
    };
    let mut failed = false;
    for server in &selection.warm {
        let logging = Logging {
            denials: args.log_denials.then(|| denial_sink(at_terminal)),
            proxy_log: args.log_proxy.then(|| proxy_log_sink(at_terminal)),
        };
        let (result, outcome) = match warm::warm_server(
            env,
            &loaded,
            server,
            build.workspace(),
            limit,
            signals,
            logging,
        ) {
            Ok(done) => done,
            Err(error) => return fail(err, crate::Error::from(error)),
        };
        for warning in &outcome.warnings {
            let _ = writeln!(err, "warning: {warning}");
        }
        for line in denial_summary(&outcome.denials)
            .into_iter()
            .chain(proxy_log_lines(&outcome.proxy_log))
        {
            let _ = writeln!(err, "{line}");
        }
        match result {
            Warmed::Answered { took } => {
                let _ = writeln!(out, "warmed {} ({} s)", server.name, took.as_secs());
            }
            Warmed::Failed { why } => {
                failed = true;
                let _ = writeln!(out, "FAILED {}", server.name);
                for line in why.lines() {
                    let _ = writeln!(err, "  | {line}");
                }
            }
        }
        if supervise.is_some() {
            if let Some(signal) = reraise_for(outcome.exit) {
                *reraise = Some(signal);
                return exit_code(outcome.exit);
            }
        }
    }
    if failed {
        let _ = writeln!(
            out,
            "not published: a server did not answer; the previous cache is unchanged"
        );
        return ExitCode::FAILURE;
    }
    match warm::publish(env, build, discovery.root.path(), &selection.warm, &tools) {
        Ok(made) => {
            let _ = writeln!(out, "published cache generation {}", made.id);
            ExitCode::SUCCESS
        }
        Err(error) => fail(err, crate::Error::from(error)),
    }
}

/// The exit code for a config that is not approved (`EX_CONFIG`). A command that `hb run` runs
/// can also exit with 78; the message on stderr tells the two apart.
const NOT_APPROVED: u8 = 78;

/// The terminal to ask at: the process's own for the `hb` binary, none for the in-process entry
/// point, which tests call and which must never wait for a person.
fn terminal_for(supervise: Option<Supervision>) -> Box<dyn Terminal> {
    if supervise.is_some() {
        Box::new(StdTerminal)
    } else {
        Box::new(NoTerminal)
    }
}

fn approval_store(env: &Environment) -> ApprovalStore {
    ApprovalStore::new(&StateDir::locate(&env.home))
}

/// Lets the run go ahead only if the project's config is approved, asking when it can.
///
/// `Err` carries the exit code to stop with; the reason has been printed to `err`.
fn ensure_approved(
    env: &Environment,
    discovery: &Discovery,
    loaded: &Loaded,
    terminal: &mut dyn Terminal,
    err: &mut dyn Write,
) -> Result<(), ExitCode> {
    let candidate = Candidate::new(env, discovery, loaded);
    let verdict = require(&candidate, &approval_store(env), terminal, err)
        .map_err(|error| fail(err, crate::Error::from(error)))?;
    if verdict.allows_run() {
        return Ok(());
    }
    let _ = match verdict {
        Verdict::NoTerminal(why) => writeln!(
            err,
            "hb: {why}. Run `hb approve` in a terminal to review and approve it. Nothing was run."
        ),
        _ => writeln!(err, "hb: the config was not approved. Nothing was run."),
    };
    Err(ExitCode::from(NOT_APPROVED))
}

/// `hb doctor`: what the secrets guard cannot see (design section 3).
fn doctor_command(env: &Environment, out: &mut dyn Write, err: &mut dyn Write) -> ExitCode {
    use crate::guard::doctor::{Findings, launchd_environment, render, survey};
    use crate::guard::repos::survey_repos;
    let (discovery, loaded) = match load_project(env) {
        Ok(project) => project,
        Err(error) => return fail(err, crate::Error::from(error)),
    };
    let roots: Vec<crate::policy::CanonicalPath> = loaded
        .policy
        .fs
        .write
        .iter()
        .map(|grant| grant.value.clone())
        .collect();
    let prepared = crate::guard::prepare(&roots, std::path::Path::new(crate::guard::SYSTEM_GIT));
    let (suspects, survey_complete) = survey(&roots, 100_000);
    let findings = Findings {
        roots: roots.iter().map(|r| r.as_str().to_owned()).collect(),
        exemption: prepared.inputs.dependency_exemption,
        pins: prepared.inputs.pins.len(),
        tracked: prepared
            .tracked
            .iter()
            .map(|t| t.as_str().to_owned())
            .collect(),
        suspects,
        survey_complete,
        launchd: launchd_environment(),
        notes: prepared.notes.iter().map(ToString::to_string).collect(),
        repos: survey_repos(
            &roots,
            discovery.root.path(),
            100_000,
            &crate::guard::repos::GitContext {
                policy: &loaded.policy,
                home: &env.home,
                xdg_config_home: env.vars.get("XDG_CONFIG_HOME"),
            },
        ),
        proxies: crate::system::proxy_settings::system_proxies(),
        proxies_readable: loaded
            .policy
            .tls
            .system_trust
            .as_ref()
            .is_some_and(|trust| trust.value),
    };
    let _ = write!(out, "{}", render(&findings));
    let warm_store = crate::warm::stamp::WarmStore::new(&StateDir::locate(&env.home));
    let mcp = crate::warm::doctor::findings(&loaded.policy, &warm_store, discovery.root.path());
    let _ = write!(out, "{}", crate::warm::doctor::render(&loaded.policy, &mcp));
    ExitCode::SUCCESS
}

/// `hb approve`: ask about this project's config and store the answer, or take the approval back.
fn approve_command(
    env: &Environment,
    args: &ApproveArgs,
    terminal: &mut dyn Terminal,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> ExitCode {
    if env.vars.get(SESSION_MARKER).is_some() {
        return fail(err, crate::Error::from(ApproveError::InsideBall));
    }
    let store = approval_store(env);
    if args.revoke {
        let discovery = match discover(&env.cwd, &env.home) {
            Ok(discovery) => discovery,
            Err(error) => return fail(err, crate::Error::from(error)),
        };
        let root = Escaped(discovery.root.path().as_str());
        return match store.revoke(discovery.root.path()) {
            Ok(true) => {
                let _ = writeln!(out, "revoked the approval of {root}");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                let _ = writeln!(out, "{root} was not approved");
                ExitCode::SUCCESS
            }
            Err(error) => fail(err, crate::Error::from(error)),
        };
    }
    let (discovery, loaded) = match load_project(env) {
        Ok(project) => project,
        Err(error) => return fail(err, crate::Error::from(error)),
    };
    let candidate = Candidate::new(env, &discovery, &loaded);
    let root = Escaped(candidate.root().as_str()).to_string();
    match require(&candidate, &store, terminal, err) {
        Ok(Verdict::AlreadyApproved) => {
            let _ = writeln!(out, "{root} is already approved");
            ExitCode::SUCCESS
        }
        Ok(Verdict::Approved) => {
            let _ = writeln!(out, "approved {root}");
            ExitCode::SUCCESS
        }
        Ok(Verdict::NoTerminal(why)) => {
            let _ = writeln!(err, "hb: {why}. `hb approve` needs a terminal to ask you.");
            ExitCode::from(NOT_APPROVED)
        }
        Ok(_) => {
            let _ = writeln!(err, "hb: the config was not approved.");
            ExitCode::from(NOT_APPROVED)
        }
        Err(error) => fail(err, crate::Error::from(error)),
    }
}

/// The process exit code for how a child ended; a shell's `128 + signal` for a signal.
fn exit_code(exit: ExitKind) -> ExitCode {
    ExitCode::from(u8::try_from(exit.code()).unwrap_or(1))
}

/// The profile for the current project, with its `-D` parameters as leading comments.
fn profile(env: &Environment) -> Result<String, crate::Error> {
    let (_, loaded) = load_project(env)?;
    let roots: Vec<crate::policy::CanonicalPath> = loaded
        .policy
        .fs
        .write
        .iter()
        .map(|grant| grant.value.clone())
        .collect();
    let guard = crate::guard::prepare(&roots, std::path::Path::new(crate::guard::SYSTEM_GIT));
    let inputs = RenderInputs::new()
        .with_proxy(ProxyEndpoint::Placeholder)
        .with_guard(guard.inputs)
        .with_guard_allow(guard.tracked);
    let profile = render(&loaded.policy, &inputs)?;
    let mut text = String::from(
        "; hb profile. Run with: sandbox-exec -p <profile> <-D name=value>... -- <command>\n",
    );
    for (name, value) in &profile.params {
        text.push_str(&param_line(name, value));
    }
    for diagnostic in &loaded.floor_diagnostics {
        text.push_str(&format!("; warning: {diagnostic}\n"));
    }
    for warning in &profile.warnings {
        text.push_str(&format!("; warning: {warning}\n"));
    }
    for note in &guard.notes {
        text.push_str(&format!("; warning: {note}\n"));
    }
    text.push_str(&profile.text);
    Ok(text)
}

/// One `-D` comment line of `hb profile`.
///
/// The value is escaped so a terminal cannot be steered by it. If escaping changed it, the line
/// says so, because it is then not the exact text to pass to `sandbox-exec`.
fn param_line(name: &str, value: &str) -> String {
    let shown = Escaped(value).to_string();
    let note = if name == "PROXY" {
        "  (placeholder: each run's proxy listens on a port chosen at start)"
    } else if shown != value {
        "  (escaped for display; not copy-exact)"
    } else {
        ""
    };
    format!("; -D {name}={shown}{note}\n")
}

/// Prints `error` with its cause chain, and returns exit code 1.
fn fail(err: &mut dyn Write, error: crate::Error) -> ExitCode {
    let _ = writeln!(err, "{}", Report::from_error(error));
    ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::FloorEnvironment;
    use crate::testutil::{Tree, canonical};
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::fs;

    #[test]
    fn a_plain_parameter_line_is_copy_exact_with_no_note() {
        assert_eq!(
            param_line("R0", "/Users/me/p"),
            "; -D R0=/Users/me/p\n".to_owned()
        );
    }

    #[test]
    fn a_parameter_line_that_had_to_be_escaped_says_it_is_not_copy_exact() {
        for value in ["/a\u{202e}b", "/a\u{1b}[31mb", "/a\nb"] {
            let line = param_line("R0", value);
            assert!(
                line.ends_with("(escaped for display; not copy-exact)\n"),
                "{line}"
            );
            assert!(
                !line.contains('\u{202e}') && !line.contains('\u{1b}'),
                "{line:?}"
            );
            assert_eq!(line.matches('\n').count(), 1, "{line:?}");
        }
    }

    #[test]
    fn the_proxy_parameter_is_always_marked_a_placeholder() {
        assert_eq!(
            param_line("PROXY", "localhost:1"),
            "; -D PROXY=localhost:1  (placeholder: each run's proxy listens on a port chosen at start)\n"
        );
    }

    #[test]
    fn the_denial_summary_is_empty_for_no_denials_and_counts_and_lists_otherwise() {
        assert!(denial_summary(&Denials::default()).is_empty());
        let some = Denials {
            lines: vec!["cat(1) deny(1) file-read-data /a".to_owned()],
            dropped: 0,
        };
        let text = denial_summary(&some);
        assert_eq!(text.len(), 2, "{text:?}");
        assert!(
            text[0].contains("denied 1 operation(s)") && text[0].contains("not complete"),
            "{text:?}"
        );
        assert_eq!(text[1], "hb: denied: cat(1) deny(1) file-read-data /a");
    }

    #[test]
    fn the_denial_summary_counts_the_dropped_ones_and_says_so_only_when_there_are_some() {
        let over = Denials {
            lines: vec!["x".to_owned()],
            dropped: 4,
        };
        let text = denial_summary(&over);
        assert!(text[0].contains("denied 5 operation(s)"), "{text:?}");
        assert_eq!(
            text.last().map(String::as_str),
            Some("hb: ... and 4 more not shown")
        );
        let none_dropped = denial_summary(&Denials {
            lines: vec!["x".to_owned()],
            dropped: 0,
        });
        assert!(none_dropped.iter().all(|l| !l.contains("more not shown")));
        let only_dropped = denial_summary(&Denials {
            lines: Vec::new(),
            dropped: 2,
        });
        assert_eq!(only_dropped.len(), 2, "{only_dropped:?}");
    }

    #[test]
    fn the_proxy_log_lines_are_prefixed_and_say_how_many_more_there_were() {
        assert!(proxy_log_lines(&Denials::default()).is_empty());
        let log = Denials {
            lines: vec!["allowed a.example.com:443 up=1 down=2".to_owned()],
            dropped: 3,
        };
        assert_eq!(
            proxy_log_lines(&log),
            [
                "hb: proxy: allowed a.example.com:443 up=1 down=2",
                "hb: ... and 3 more connections not shown"
            ]
        );
    }

    #[test]
    fn the_proxy_log_goes_live_when_stderr_is_redirected_and_is_collected_on_a_terminal() {
        assert!(matches!(proxy_log_sink(true), DenialSink::Collect));
        assert!(matches!(proxy_log_sink(false), DenialSink::Stream(_)));
    }

    #[test]
    fn denials_go_live_to_stderr_when_it_is_redirected_and_are_collected_on_a_terminal() {
        assert!(matches!(denial_sink(true), DenialSink::Collect));
        assert!(matches!(denial_sink(false), DenialSink::Stream(_)));
    }

    #[test]
    fn a_child_killed_by_int_term_hup_or_kill_is_reraised_and_any_other_signal_is_not() {
        for (n, signal) in [
            (1, Signal::SIGHUP),
            (2, Signal::SIGINT),
            (9, Signal::SIGKILL),
            (15, Signal::SIGTERM),
        ] {
            assert_eq!(reraise_for(ExitKind::Signalled(n)), Some(signal));
        }
        for n in [3, 6, 11, 13, 14, 30] {
            assert_eq!(reraise_for(ExitKind::Signalled(n)), None, "signal {n}");
        }
        assert_eq!(reraise_for(ExitKind::Exited(130)), None);
        assert_eq!(reraise_for(ExitKind::Exited(0)), None);
    }

    #[test]
    fn the_child_helper_is_hidden_from_help_but_still_parses() {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _ = run(["hb", "--help"], None, &mut out, &mut err);
        let help = String::from_utf8_lossy(&out);
        assert!(!help.contains("__child"), "{help}");
        assert!(help.contains("run"), "{help}");
        assert_ok!(Cli::try_parse_from([
            "hb",
            "__child",
            "--",
            "-p",
            "(version 1)",
            "--",
            "ls"
        ]));
    }

    #[test]
    fn the_helper_needs_at_least_one_argument() {
        assert!(Cli::try_parse_from(["hb", "__child"]).is_err());
    }

    /// The exit code as a number; `ExitCode` has no accessor.
    fn code(code: ExitCode) -> u8 {
        if code == ExitCode::SUCCESS {
            0
        } else if code == ExitCode::FAILURE {
            1
        } else if code == ExitCode::from(2) {
            2
        } else {
            255
        }
    }

    struct Ran {
        code: u8,
        out: String,
        err: String,
    }

    fn run_with(args: &[&str], env: Option<&Environment>) -> Ran {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let exit = run(
            std::iter::once("hb").chain(args.iter().copied()),
            env,
            &mut out,
            &mut err,
        );
        Ran {
            code: code(exit),
            out: String::from_utf8_lossy(&out).into_owned(),
            err: String::from_utf8_lossy(&err).into_owned(),
        }
    }

    /// A home with a base config and a project, and an environment standing in for the process.
    fn world() -> (Tree, Environment) {
        let tree = Tree::new();
        let project = tree.inside_home("work/proj");
        let config_dir = tree.inside_home(".config/hamster-ball");
        assert_ok!(fs::write(config_dir.join("base.toml"), ""));
        assert_ok!(fs::write(
            project.join("hamster-ball.toml"),
            "[fs]\nwrite = [\".\"]\n"
        ));
        let mut env = Environment::new(canonical(&project).as_path(), tree.home().clone());
        env.floor = FloorEnvironment::new().with_path_var(tree.outside("bin").into_os_string());
        (tree, env)
    }

    #[test]
    fn bare_hb_prints_its_name_and_version() {
        let ran = run_with(&[], None);
        assert_eq!(ran.code, 0);
        assert!(ran.out.starts_with("hamster-ball "), "{}", ran.out);
        assert_eq!(ran.err, "");
    }

    #[test]
    fn an_unknown_command_is_a_usage_error_with_code_2_on_stderr() {
        let ran = run_with(&["frobnicate"], None);
        assert_eq!(ran.code, 2);
        assert_eq!(ran.out, "");
        assert!(ran.err.contains("Usage: hb"), "{}", ran.err);
    }

    #[test]
    fn help_goes_to_stdout_with_code_0_and_lists_the_commands() {
        let ran = run_with(&["--help"], None);
        assert_eq!(ran.code, 0);
        assert!(ran.out.contains("explain"), "{}", ran.out);
        assert!(ran.out.contains("init"), "{}", ran.out);
    }

    #[test]
    fn explain_help_describes_its_options() {
        let ran = run_with(&["explain", "--help"], None);
        assert_eq!(ran.code, 0);
        for option in ["--format", "--show-args", "--path"] {
            assert!(ran.out.contains(option), "{}", ran.out);
        }
    }

    #[test]
    fn a_bad_format_is_a_usage_error() {
        let (_tree, env) = world();
        let ran = run_with(&["explain", "--format", "yaml"], Some(&env));
        assert_eq!(ran.code, 2);
        assert!(ran.err.contains("--format"), "{}", ran.err);
    }

    #[test]
    fn explain_prints_text_and_exits_0_even_with_warnings() {
        let (tree, env) = world();
        let ran = run_with(&["explain"], Some(&env));
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert!(ran.out.starts_with("hb explain\n"));
        assert!(ran.out.contains("warnings"));
        assert_eq!(ran.err, "");
        drop(tree);
    }

    #[test]
    fn explain_json_is_valid_json_with_a_schema_version() {
        let (_tree, env) = world();
        let ran = run_with(&["explain", "--format", "json"], Some(&env));
        assert_eq!(ran.code, 0, "{}", ran.err);
        let value: serde_json::Value = assert_ok!(serde_json::from_str(&ran.out));
        assert_eq!(value["schema_version"], 1);
    }

    #[test]
    fn explain_path_answers_for_that_path() {
        let (_tree, env) = world();
        let ran = run_with(&["explain", "--path", "~/.ssh/id_rsa"], Some(&env));
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert!(ran.out.contains("denied_by_floor"), "{}", ran.out);
    }

    #[test]
    fn a_config_error_is_code_1_with_the_cause_chain_on_stderr() {
        let (tree, env) = world();
        let project = tree.home_path().join("work/proj/hamster-ball.toml");
        assert_ok!(fs::write(project, "[fs]\nbogus = 1\n"));
        let ran = run_with(&["explain"], Some(&env));
        assert_eq!(ran.code, 1);
        assert_eq!(ran.out, "");
        assert!(!ran.err.is_empty());
    }

    #[test]
    fn no_project_is_code_1() {
        let (tree, mut env) = world();
        env.cwd = tree.outside("nowhere");
        let ran = run_with(&["explain"], Some(&env));
        assert_eq!(ran.code, 1);
        assert!(ran.err.to_lowercase().contains("project"), "{}", ran.err);
    }

    #[test]
    fn profile_prints_a_valid_profile_with_its_parameters_as_comments_and_a_proxy_placeholder() {
        let (_tree, env) = world();
        let ran = run_with(&["profile"], Some(&env));
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert_eq!(ran.err, "");
        assert!(ran.out.starts_with("; hb profile"), "{}", ran.out);
        assert!(
            ran.out
                .contains("(version 1)\n(deny default)\n(import \"system.sb\")"),
            "{}",
            ran.out
        );
        assert!(
            ran.out
                .contains("; -D PROXY=localhost:1  (placeholder: each run's proxy listens on a port chosen at start)"),
            "{}",
            ran.out
        );
        assert!(
            ran.out
                .contains("(allow network-outbound (remote ip (param \"PROXY\")))")
        );
        // The project path is a parameter, never profile text.
        let (code, params): (Vec<&str>, Vec<&str>) =
            ran.out.lines().partition(|l| !l.starts_with("; -D "));
        assert!(
            params.iter().any(|l| l.contains("/work/proj")),
            "{params:?}"
        );
        assert!(!code.iter().any(|l| l.contains("/work/proj")), "{code:?}");
    }

    #[test]
    fn profile_reports_what_the_floor_builder_noticed_so_the_profile_does_not_look_complete() {
        let (_tree, mut env) = world();
        env.floor.path_var = Some(std::ffi::OsString::from("relative/bin:/usr/bin"));
        let ran = run_with(&["profile"], Some(&env));
        assert_eq!(ran.code, 0, "{}", ran.err);
        assert!(
            ran.out
                .lines()
                .any(|l| l.starts_with("; warning: PATH entry") && l.contains("relative/bin")),
            "{}",
            ran.out.lines().take(12).collect::<Vec<_>>().join("\n")
        );
    }

    #[test]
    fn profile_outside_a_project_is_code_1_and_prints_nothing_to_stdout() {
        let (tree, mut env) = world();
        env.cwd = tree.outside("nowhere");
        let ran = run_with(&["profile"], Some(&env));
        assert_eq!(ran.code, 1);
        assert_eq!(ran.out, "");
        assert!(ran.err.to_lowercase().contains("project"), "{}", ran.err);
    }

    #[test]
    fn profile_help_is_listed() {
        let ran = run_with(&["--help"], None);
        assert!(ran.out.contains("profile"), "{}", ran.out);
    }

    #[test]
    fn init_creates_the_base_config_and_never_overwrites() {
        let tree = Tree::new();
        let env = Environment::new(tree.home_path(), tree.home().clone());
        let first = run_with(&["init"], Some(&env));
        assert_eq!(first.code, 0, "{}", first.err);
        assert!(first.out.starts_with("created "));
        let second = run_with(&["init"], Some(&env));
        assert_eq!(second.code, 1);
        assert!(second.err.contains("already exists"), "{}", second.err);
    }
}
