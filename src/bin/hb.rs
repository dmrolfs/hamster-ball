// ABOUTME: The `hb` binary entry point: forwards the process arguments to `hamster_ball::cli::run`.
// ABOUTME: All behaviour lives in the library so it can be tested without spawning a process.
//! `hb`: run AI coding agents inside a hamster ball.

use std::io::{stderr, stdout};
use std::process::ExitCode;

fn main() -> ExitCode {
    // Before anything opens a file: nothing the launching shell left open may reach the agent.
    let _ = hamster_ball::session::close_inherited_fds();
    hamster_ball::cli::run(
        std::env::args_os(),
        None,
        &mut stdout().lock(),
        &mut stderr().lock(),
    )
}
