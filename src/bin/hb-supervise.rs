// ABOUTME: The `hb-supervise` binary entry point: one terminal UI over several `hb run` sessions, and the hidden launch helper.
// ABOUTME: The UI itself lives in `hamster_ball::supervise`; this file only chooses between helper and supervisor.
//! `hb-supervise`: start and watch several sandboxed agent sessions from one terminal.

use std::ffi::OsString;
use std::process::ExitCode;

use clap::Parser;
use hamster_ball::supervise::launch::{LAUNCH_ARG, run_helper};
// Declared now so the lockfile and MSRV are verified; the view modules use them next.
use {crossterm as _, ratatui as _, tui_term as _, vt100 as _};

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
    ExitCode::SUCCESS
}
