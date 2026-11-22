// ABOUTME: The hidden `hb __child` helper: clears the signal mask, then execs sandbox-exec with the arguments it was given.
// ABOUTME: Needed because Rust's Command passes hb's blocked signals to the child; it can exec only sandbox-exec, nothing else.
//! The re-exec helper behind `hb run` (design D53).
//!
//! `hb` blocks INT, TERM and HUP so it can receive them through kqueue, and `std` hands the
//! blocked set to every child it starts. The agent would then ignore Ctrl-C. `hb` therefore
//! starts itself as `hb __child -- <sandbox-exec arguments>`, and this process empties the mask
//! and replaces itself with `sandbox-exec`. It runs only `sandbox-exec`, by absolute path, so it
//! offers nothing that running `sandbox-exec` directly does not.

use std::ffi::OsString;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use snafu::Snafu;

use super::preflight::SANDBOX_EXEC;
use super::signals::{SignalError, clear_mask};

/// Why the helper could not hand over to `sandbox-exec`.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HelperError {
    /// The signal mask could not be cleared.
    #[snafu(display("the signal mask could not be cleared"))]
    Mask {
        /// The underlying error.
        source: SignalError,
    },

    /// `sandbox-exec` could not be started.
    #[snafu(display("{SANDBOX_EXEC} could not be started"))]
    Exec {
        /// The underlying error.
        source: io::Error,
    },
}

/// Clears the signal mask and replaces this process with `sandbox-exec args...`.
///
/// Returns only if that failed.
pub fn exec_sandbox_exec(args: &[OsString]) -> HelperError {
    if let Err(source) = clear_mask() {
        return HelperError::Mask { source };
    }
    HelperError::Exec {
        source: Command::new(SANDBOX_EXEC).args(args).exec(),
    }
}
