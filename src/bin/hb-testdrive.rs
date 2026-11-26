// ABOUTME: A test-only copy of `hb` that takes its Environment from variables, so tests run the real process behaviour.
// ABOUTME: Built only with the `test-support` feature; it is not part of a release build.
//! `hb-testdrive`: `hb` with a fixture environment.
//!
//! The real `hb` takes its home from the passwd database (D28), so it cannot load a project that
//! lives in a test's temporary home. This binary runs exactly the same `cli::main`, with an
//! [`Environment`] built from `HB_TD_*` variables. It also acts as the `__child`, `__guard` and `ctl`
//! helpers, which `hb` starts without them, so those cases need no variables.

use std::ffi::OsString;
use std::io::{stderr, stdout};
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
        .with_hb_exe(std::env::current_exe().ok()?);
    env.vars = ParentVars::from_pairs(std::env::vars_os());
    Some(env)
}

fn main() -> ExitCode {
    let start = hamster_ball::session::start_up();
    if let Some(problem) = start.problem {
        eprintln!("hb-testdrive: the supervisor channel is not usable: {problem}");
        return ExitCode::from(2);
    }
    let args: Vec<OsString> = std::env::args_os().collect();
    let grace = var("HB_TD_GRACE_MS")
        .and_then(|v| v.to_str().and_then(|t| t.parse::<u64>().ok()))
        .map_or(hamster_ball::session::DEFAULT_GRACE, Duration::from_millis);
    let helper = args
        .get(1)
        .is_some_and(|a| a == "__child" || a == "__guard" || a == "ctl");
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
