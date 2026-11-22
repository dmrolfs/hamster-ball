// ABOUTME: The `hb` binary entry point: forwards the process arguments to `hamster_ball::cli::run`.
// ABOUTME: All behaviour lives in the library so it can be tested without spawning a process.
//! `hb`: run AI coding agents inside a hamster ball.

use std::io::{stderr, stdout};
use std::process::ExitCode;

fn main() -> ExitCode {
    // stderr is passed unlocked on purpose: the thread that streams `--log-denials` writes to it
    // while this thread waits, and a held lock would deadlock the two.
    // Before anything opens a file: nothing the launching shell left open may reach the agent.
    let _ = hamster_ball::session::close_inherited_fds();
    hamster_ball::cli::main(
        std::env::args_os(),
        None,
        &mut stdout().lock(),
        &mut stderr(),
    )
}
