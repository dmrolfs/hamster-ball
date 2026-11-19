// ABOUTME: The `hb` binary entry point. Minimal until the full CLI exists: prints the version, or runs `hb init`.
// ABOUTME: `hb init` writes a first ~/.config/hamster-ball/base.toml and never overwrites one.
//! `hb`: run AI coding agents inside a hamster ball.

use std::process::ExitCode;

use hamster_ball::policy::HomeDir;
use hamster_ball::system::UserConfigDir;
use snafu::Report;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [command] if command == "init" => init(),
        _ => {
            eprintln!(
                "usage: hb [init]\n  init   create ~/.config/hamster-ball/base.toml (never overwrites)"
            );
            ExitCode::from(2)
        }
    }
}

/// Creates the user's base config from the template.
fn init() -> ExitCode {
    let result = HomeDir::from_environment()
        .map_err(hamster_ball::Error::from)
        .and_then(|home| {
            UserConfigDir::locate(&home)
                .init_base()
                .map_err(hamster_ball::Error::from)
        });
    match result {
        Ok(path) => {
            println!("created {}", path.display());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("{}", Report::from_error(error));
            ExitCode::FAILURE
        }
    }
}
