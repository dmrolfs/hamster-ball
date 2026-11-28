// ABOUTME: A test-only copy of `hb` that takes its Environment from variables, so tests run the real process behaviour.
// ABOUTME: Built only with the `test-support` feature; it is not part of a release build.
//! `hb-testdrive`: `hb` with a fixture environment.
//!
//! The real `hb` takes its home from the passwd database (D28), so it cannot load a project that
//! lives in a test's temporary home. This binary runs exactly the same `cli::main`, with an
//! [`Environment`] built from `HB_TD_*` variables. It also acts as the `__child`, `__guard` and `ctl`
//! helpers, which `hb` starts without them, so those cases need no variables.

use std::ffi::OsString;
use std::io::{BufRead, Write, stderr, stdout};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use hamster_ball::cli::{PtyChoice, Supervision};
use hamster_ball::policy::{CanonicalPath, HomeDir};
use hamster_ball::system::{Environment, FloorEnvironment, ParentVars};

fn var(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

fn canonical(path: &OsString) -> Option<CanonicalPath> {
    CanonicalPath::from_canonical(std::fs::canonicalize(path).ok()?).ok()
}

fn fixture() -> Option<Environment> {
    let home = HomeDir::new(canonical(&var("HB_TD_HOME")?)?);
    let mut env = Environment::new(PathBuf::from(var("HB_TD_CWD")?), home);
    env.floor = FloorEnvironment::new()
        .with_path_var(var("HB_TD_PATH")?)
        .with_user_temp_dir(PathBuf::from(var("HB_TD_TMP")?))
        // HB_TD_EXE lets a test put a wrapper in hb's place, to stand in for the guard process while
        // the gated helper stays the real one.
        .with_hb_exe(
            var("HB_TD_EXE")
                .map(PathBuf::from)
                .or_else(|| std::env::current_exe().ok())?,
        );
    env.vars = ParentVars::from_pairs(std::env::vars_os());
    Some(env)
}

/// A compiled guardian stand-in selected only by the test executable's special symlink name.
/// Configuration lives beside the symlink because the real launch clears the environment.
fn fake_guard(args: &[OsString]) -> Option<ExitCode> {
    let path = PathBuf::from(args.first()?);
    if path.file_name()? != "hb-fake-guard" || args.get(1)? != "__guard" {
        return None;
    }
    let result = (|| -> std::io::Result<()> {
        let _ = rustix::process::setsid();
        let reply = std::fs::read_to_string(path.with_extension("reply"))?;
        let mut output = stdout().lock();
        for line in std::io::stdin().lock().lines() {
            let line = line?;
            let mut parts = line.splitn(3, ' ');
            if parts.next() != Some("ack") {
                continue;
            }
            let (Some(id), Some(command)) = (parts.next(), parts.next()) else {
                continue;
            };
            let answer = if command.starts_with("watch ") {
                let mut log = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path.with_extension("watched"))?;
                writeln!(log, "{command}")?;
                reply.trim()
            } else {
                "ok"
            };
            writeln!(output, "{id} {answer}")?;
            output.flush()?;
        }
        Ok(())
    })();
    Some(if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn main() -> ExitCode {
    let start = hamster_ball::session::start_up();
    if let Some(problem) = start.problem {
        eprintln!("hb-testdrive: {}", snafu::Report::from_error(problem));
        return ExitCode::from(2);
    }
    let args: Vec<OsString> = std::env::args_os().collect();
    if let Some(status) = fake_guard(&args) {
        return status;
    }
    let grace = var("HB_TD_GRACE_MS")
        .and_then(|v| v.to_str().and_then(|t| t.parse::<u64>().ok()))
        .map_or(hamster_ball::session::DEFAULT_GRACE, Duration::from_millis);
    let helper = args
        .get(1)
        .is_some_and(|a| a == "__child" || a == "__exec" || a == "__guard" || a == "ctl");
    let env = if helper { None } else { fixture() };
    if env.is_none() && !helper {
        eprintln!("hb-testdrive: the HB_TD_* variables are missing or unusable");
        return ExitCode::from(2);
    }
    let pty = if var("HB_TD_PTY").is_some_and(|v| v == "off") {
        PtyChoice::Off
    } else {
        PtyChoice::Auto
    };
    hamster_ball::cli::main_supervised(
        args,
        env.as_ref(),
        &mut stdout(),
        &mut stderr(),
        Supervision { grace, pty },
        start.channel,
    )
}
