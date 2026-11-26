// ABOUTME: Starting one `hb run --supervised` for a session: its own PTY as controlling terminal and the private channel on one descriptor, with no shell and no unsafe.
// ABOUTME: A short `hb-supervise __launch` helper does the part std cannot (setsid, TIOCSCTTY, keeping one descriptor open across exec) and then becomes hb.
//! Launching a session (epic hb-b6q).
//!
//! `hb` must get two things the standard library cannot hand a child by itself: the PTY slave
//! as its controlling terminal, and the channel socket on a descriptor that stays open across
//! `exec`. Both need calls between `fork` and `exec`, which `Command` allows only through
//! `unsafe`. So the supervisor starts *itself* as a helper:
//!
//! ```text
//! hb-supervise __launch -- <hb> run --supervised ...
//!   stdin  = the channel socket        stdout, stderr = the PTY slave
//! ```
//!
//! The helper, a single thread with nothing else running, duplicates the socket to a new
//! descriptor, clears close-on-exec on that duplicate only, moves the PTY slave onto stdin,
//! starts a session with the slave as its controlling terminal, and `exec`s `hb` with
//! `HB_SUPERVISOR_FD` naming the duplicate. `hb` then claims it ([`crate::session::start_up`])
//! and closes the original, so neither the agent nor anything `hb` starts can reach it.
//!
//! The helper runs `hb` at the path it was given and nothing else. It is reachable only as a
//! hidden argument of the supervisor, which the owner runs.

use std::ffi::OsString;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

use rustix::io::{FdFlags, dup, fcntl_setfd};
use rustix::process::{ioctl_tiocsctty, setsid};
use rustix::stdio::dup2_stdin;
use snafu::{ResultExt, Snafu};

use super::app::LaunchSpec;
use crate::session::supervised::SUPERVISOR_FD_VAR;
use crate::session::{Pty, PtyError, Winsize};

/// The hidden argument that makes `hb-supervise` act as the launch helper.
pub const LAUNCH_ARG: &str = "__launch";

/// Why a session could not be started.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum LaunchError {
    /// The session's terminal could not be allocated.
    #[snafu(display("a terminal for the session could not be allocated"))]
    Terminal {
        /// The underlying error.
        source: PtyError,
    },
    /// The terminal could not be given its size.
    #[snafu(display("the session's terminal could not be sized"))]
    Size {
        /// The OS error.
        source: rustix::io::Errno,
    },
    /// The channel could not be created.
    #[snafu(display("the session's channel could not be created"))]
    Channel {
        /// The OS error.
        source: io::Error,
    },
    /// A descriptor for the child could not be prepared.
    #[snafu(display("a descriptor for the session could not be prepared"))]
    Descriptor {
        /// The OS error.
        source: io::Error,
    },
    /// The helper could not be started.
    #[snafu(display("the launch helper could not be started"))]
    Spawn {
        /// The OS error.
        source: io::Error,
    },
}

/// What the supervisor keeps of a started session.
#[derive(Debug)]
pub struct Started {
    /// The `hb` process (through the helper, which becomes it).
    pub child: Child,
    /// The supervisor's end of the private channel.
    pub channel: UnixStream,
    /// The master of the session's terminal: output comes from it, input goes to it.
    pub terminal: std::fs::File,
}

/// Starts `hb run --supervised -- <command>` for `spec`.
///
/// `hb` is the path of the `hb` binary and `me` the path of this supervisor, which is started
/// again as the helper. The session's terminal is `rows` by `cols`.
///
/// # Errors
/// [`LaunchError`] if the terminal, channel or helper cannot be set up; nothing is left running.
pub fn start(
    hb: &std::path::Path,
    me: &std::path::Path,
    spec: &LaunchSpec,
    rows: u16,
    cols: u16,
) -> Result<Started, LaunchError> {
    start_with_env(hb, me, spec, rows, cols, &[])
}

/// [`start`] with `extra` variables set for the session, on top of this process's environment.
/// For a test binary that stands in for `hb` and takes its fixture from variables.
///
/// # Errors
/// As [`start`].
pub fn start_with_env(
    hb: &std::path::Path,
    me: &std::path::Path,
    spec: &LaunchSpec,
    rows: u16,
    cols: u16,
    extra: &[(&str, &std::ffi::OsStr)],
) -> Result<Started, LaunchError> {
    let pty = Pty::open().context(TerminalSnafu)?;
    pty.set_size(Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    })
    .context(SizeSnafu)?;
    let (ours, theirs) = UnixStream::pair().context(ChannelSnafu)?;
    let (_, slave_out, slave_err) = pty.child_stdio().context(DescriptorSnafu)?;
    let mut command = Command::new(me);
    command
        .arg(LAUNCH_ARG)
        .arg(hb)
        .arg("run")
        .arg("--supervised")
        .arg("--log-denials")
        .arg("--")
        .args(&spec.command)
        .current_dir(&spec.project)
        .envs(extra.iter().copied())
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(slave_out)
        .stderr(slave_err);
    let child = command.spawn().context(SpawnSnafu)?;
    // Dropping `command` closes the parent's copies of the child's ends; the pty's own slave is
    // released next, so the master sees the end of output when the session's last descriptor closes.
    drop(command);
    let channel = ours;
    let terminal = pty.release_slave();
    Ok(Started {
        child,
        channel,
        terminal,
    })
}

/// What the helper does, called from `main` when `__launch` is the first argument. Returns only
/// when something failed.
///
/// `argv` is everything after `__launch`: the `hb` path, then its arguments.
pub fn run_helper(argv: &[OsString]) -> io::Error {
    let Some((hb, rest)) = argv.split_first() else {
        return io::Error::new(io::ErrorKind::InvalidInput, "no program to launch");
    };
    match prepare_and_describe() {
        Ok(number) => {
            let error = Command::new(PathBuf::from(hb))
                .args(rest)
                .env(SUPERVISOR_FD_VAR, number.to_string())
                .exec();
            io::Error::new(error.kind(), format!("could not start hb: {error}"))
        }
        Err(error) => error,
    }
}

/// Makes stdin the controlling terminal and keeps a duplicate of the channel open across exec.
/// Returns the duplicate's number.
fn prepare_and_describe() -> io::Result<i32> {
    // The channel arrives on stdin and the terminal on stdout.
    let channel = dup(std::io::stdin())?;
    // Only this duplicate crosses exec; the original on stdin is replaced next.
    fcntl_setfd(&channel, FdFlags::empty())?;
    let number = channel.as_raw_fd();
    dup2_stdin(std::io::stdout())?;
    setsid()?;
    ioctl_tiocsctty(std::io::stdin())?;
    // Kept open for exec: forgetting the owner is the safe way to say "do not close this".
    std::mem::forget(channel);
    Ok(number)
}
