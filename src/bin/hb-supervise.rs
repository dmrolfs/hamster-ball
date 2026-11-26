// ABOUTME: The `hb-supervise` binary entry point: one terminal UI over several `hb run` sessions, and the hidden launch helper.
// ABOUTME: The UI itself lives in `hamster_ball::supervise`; this file only chooses between helper and supervisor.
//! `hb-supervise`: start and watch several sandboxed agent sessions from one terminal.

use std::ffi::OsString;
use std::process::ExitCode;

use clap::Parser;
use hamster_ball::supervise::launch::{LAUNCH_ARG, run_helper};
use hamster_ball::supervise::runtime::Paths;
use hamster_ball::supervise::ui::{Ended, run};
// Used by the library; named here so the lockfile and MSRV are checked for this binary too.
use {tui_term as _, vt100 as _};

/// Start and watch several sandboxed agent sessions from one terminal.
#[derive(Parser)]
#[command(name = "hb-supervise", version)]
struct Args {}

fn main() -> ExitCode {
    let argv: Vec<OsString> = std::env::args_os().collect();
    // The helper takes nothing from the environment and must run before anything else starts.
    if argv.get(1).is_some_and(|a| a == LAUNCH_ARG) {
        let error = run_helper(&argv[2..]);
        eprintln!("hb-supervise: could not launch: {error}");
        return ExitCode::from(2);
    }
    Args::parse();
    match supervise() {
        Ok(Ended::Clean) => ExitCode::SUCCESS,
        Ok(Ended::Unclean) => ExitCode::from(1),
        Err(error) => {
            eprintln!("hb-supervise: {error}");
            ExitCode::from(2)
        }
    }
}

/// Finds `hb` next to this program, and runs the UI in the directory it was started from.
fn supervise() -> std::io::Result<Ended> {
    let me = std::env::current_exe()?;
    let hb = me.with_file_name("hb");
    let cwd = std::env::current_dir()?;
    // Tests point this at a copy of hb that takes its fixture from variables. A release build
    // never reads the variable, so the environment cannot choose which `hb` approves a project.
    #[cfg(feature = "test-support")]
    let hb = std::env::var_os("HB_SUPERVISE_HB").map_or(hb, std::path::PathBuf::from);
    let paths = Paths {
        hb,
        me,
        env: Vec::new(),
    };
    run(paths, &cwd)
}
