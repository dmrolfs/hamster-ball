// ABOUTME: The `hb` binary entry point. Deliberately trivial until the config model exists; commands arrive in later tasks.
// ABOUTME: Prints the version and exits successfully so installation can be verified.
//! `hb`: run AI coding agents inside a hamster ball.

use std::process::ExitCode;

fn main() -> ExitCode {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    ExitCode::SUCCESS
}
