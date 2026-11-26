// ABOUTME: The `hb` binary entry point: forwards the process arguments to `hamster_ball::cli::main`.
// ABOUTME: All behaviour lives in the library so it can be tested without spawning a process.
//! `hb`: run AI coding agents inside a hamster ball.

use std::io::{stderr, stdout};
use std::process::ExitCode;

fn main() -> ExitCode {
    // Before anything opens a file: nothing the launching shell left open may reach the agent.
    // The one exception is the supervisor channel, which is claimed first (and made
    // close-on-exec) when `hb-supervise` passed one.
    let start = hamster_ball::session::start_up();
    if let Some(problem) = start.problem {
        eprintln!("hb: the supervisor channel is not usable: {problem}");
        return ExitCode::from(2);
    }
    // stderr is passed unlocked on purpose: the thread that streams `--log-denials` writes to it
    // while this thread waits, and a held lock would deadlock the two.
    hamster_ball::cli::main_supervised(
        std::env::args_os(),
        None,
        &mut stdout().lock(),
        &mut stderr(),
        hamster_ball::cli::Supervision::default(),
        start.channel,
    )
}
