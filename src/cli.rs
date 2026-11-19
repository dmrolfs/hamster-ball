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
//! | 1 | config, load or floor error, printed with its cause chain |
//! | 2 | usage error (clap's default) |
//! | 78 | reserved for an unapproved config (milestone 4) |

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand, ValueEnum};
use snafu::Report;

use crate::explain::{ExplainRequest, Format, explain};
use crate::system::{Environment, UserConfigDir};

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
