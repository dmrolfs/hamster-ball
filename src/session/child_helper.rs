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

use rustix::process::{ioctl_tiocsctty, setsid};
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

    /// The helper could not become the leader of a new session.
    #[snafu(display("the helper could not start a new session"))]
    NewSession {
        /// The underlying error.
        source: rustix::io::Errno,
    },

    /// The pty could not be made the controlling terminal.
    #[snafu(display("the pty could not be made the controlling terminal"))]
    ControllingTty {
        /// The underlying error.
        source: rustix::io::Errno,
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
/// With `controlling_tty` it first becomes the leader of a new session and takes its stdin, the
/// child's pty slave, as the controlling terminal, so the agent has job control and a `/dev/tty`
/// of its own. Returns only if something failed.
pub fn exec_sandbox_exec(args: &[OsString], controlling_tty: bool) -> HelperError {
    if let Err(source) = clear_mask() {
        return HelperError::Mask { source };
    }
    if controlling_tty {
        if let Err(source) = setsid() {
            return HelperError::NewSession { source };
        }
        if let Err(source) = ioctl_tiocsctty(std::io::stdin()) {
            return HelperError::ControllingTty { source };
        }
    }
    HelperError::Exec {
        source: Command::new(SANDBOX_EXEC).args(args).exec(),
    }
}
