// ABOUTME: The `hb-supervise` binary entry point: one terminal UI over several `hb run` sessions.
// ABOUTME: This is the skeleton; the UI lives in `hamster_ball::supervise` as later tasks add it.
//! `hb-supervise`: start and watch several sandboxed agent sessions from one terminal.

use clap::Parser;
// Declared now so the lockfile and MSRV are verified; the terminal and view modules use them next.
use {crossterm as _, ratatui as _, tui_term as _, vt100 as _};

/// Start and watch several sandboxed agent sessions from one terminal.
#[derive(Parser)]
#[command(name = "hb-supervise", version)]
struct Args {}

fn main() {
    Args::parse();
}
