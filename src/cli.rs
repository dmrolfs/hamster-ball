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
//! | 1 | config, load, floor or run-start error, printed with its cause chain |
//! | n | `hb run`: the command's own exit code, or `128 + signal` |
//! | 2 | usage error (clap's default) |
//! | 78 | reserved for an unapproved config (milestone 4) |

use std::ffi::OsString;
use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand, ValueEnum};
use nix::sys::signal::{Signal, raise};
use snafu::Report;

use crate::config::load_project;
use crate::explain::{ExplainRequest, Format, explain};
use crate::seatbelt::{ProxyEndpoint, RenderInputs, render};
use crate::session::signals::{block_supervised, unblock_supervised};
use crate::session::{
    self, DEFAULT_GRACE, DenialSink, Denials, ExitKind, PtyMode, RunError, RunSpec, SESSION_MARKER,
    SignalMode, StdioMode, check_nesting, exec_sandbox_exec, run_guard,
};
use crate::system::{Environment, UserConfigDir};
use crate::text::Escaped;

/// Run AI coding agents inside a hamster ball.
#[derive(Debug, Parser)]
#[command(name = "hb", version, about)]
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
    /// Print the Seatbelt profile and parameters this project would run under.
    ///
    /// The proxy parameter is a placeholder until the proxy exists.
    Profile,
    /// Run a command inside the hamster ball and exit with its status.
    ///
    /// The command starts with an empty environment: only HOME, PATH, TMPDIR, TERM and the names
    /// in `[env] pass` and `[env] set` reach it. A program found through `[env] tools` is on its PATH.
    Run(RunArgs),
    /// Internal: clear the signal mask and exec sandbox-exec. Started by `hb run`, never by hand.
    #[command(name = "__child", hide = true)]
    Child(ChildArgs),
    /// Internal: end the agent and the log stream if hb is killed. Started by `hb run`, never by hand.
    #[command(name = "__guard", hide = true)]
    Guard(GuardArgs),
}

#[derive(Debug, Args)]
struct GuardArgs {
    /// Milliseconds between SIGTERM and SIGKILL when the guard has to end the processes.
    #[arg(long, default_value_t = 2000)]
    grace_ms: u64,
}

#[derive(Debug, Args)]
struct ChildArgs {
    /// Become a session leader and take stdin (the pty slave) as the controlling terminal first.
    #[arg(long)]
    controlling_tty: bool,
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
            crate::Error::from(exec_sandbox_exec(&child.argv, child.controlling_tty)),
        );
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
        Command::Init => match UserConfigDir::locate(&env.home).init_base() {
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
        Command::Run(args) => run_command(env, args, err, supervise, reraise),
        Command::Child(_) | Command::Guard(_) => ExitCode::FAILURE,
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
    let sink = args.log_denials.then(|| denial_sink(at_terminal));
    run_command_with(env, args.command, sink, err, supervise, reraise)
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

/// The lines printed after the run for collected denials.
fn denial_summary(denials: &Denials) -> Vec<String> {
    if denials.lines.is_empty() && denials.dropped == 0 {
        return Vec::new();
    }
    let mut out = vec![format!(
        "hb: the sandbox denied {} operation(s) (the system log is not complete, so there may be more):",
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
    sink: Option<DenialSink>,
    err: &mut dyn Write,
    supervise: Option<Supervision>,
    reraise: &mut Option<Signal>,
) -> ExitCode {
    if supervise.is_some() {
        if let Err(error) = block_supervised() {
            return fail(err, crate::Error::from(RunError::from(error)));
        }
    }
    let inside_hb = env.vars.get(SESSION_MARKER).is_some();
    if let Err(error) = check_nesting(inside_hb) {
        return fail(err, crate::Error::from(RunError::from(error)));
    }
    let loaded = match load_project(env) {
        Ok((_, loaded)) => loaded,
        Err(error) => return fail(err, crate::Error::from(error)),
    };
    let signals = supervise.map_or(SignalMode::Off, |s| SignalMode::Forward { grace: s.grace });
    let mut spec = RunSpec::new(command)
        .stdio(StdioMode::Inherit)
        .signals(signals);
    // A pty exactly when hb is supervising and stdin is a terminal; the in-process entry point
    // (`run`) never allocates one, so a developer running `cargo test` in a terminal is unaffected.
    if supervise.is_some_and(|s| s.pty == PtyChoice::Auto) && std::io::stdin().is_terminal() {
        spec.pty = PtyMode::On;
    }
    spec.denials = sink;
    match session::run(env, &loaded, &spec) {
        Ok(outcome) => {
            for warning in &outcome.warnings {
                let _ = writeln!(err, "warning: {warning}");
            }
            for line in denial_summary(&outcome.denials) {
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

/// The process exit code for how a child ended; a shell's `128 + signal` for a signal.
fn exit_code(exit: ExitKind) -> ExitCode {
    ExitCode::from(u8::try_from(exit.code()).unwrap_or(1))
}

/// The profile for the current project, with its `-D` parameters as leading comments.
fn profile(env: &Environment) -> Result<String, crate::Error> {
    let (_, loaded) = load_project(env)?;
    let inputs = RenderInputs::new().with_proxy(ProxyEndpoint::Placeholder);
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
        "  (placeholder until the proxy exists)"
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
            "; -D PROXY=localhost:1  (placeholder until the proxy exists)\n"
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
                .contains("; -D PROXY=localhost:1  (placeholder until the proxy exists)"),
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
