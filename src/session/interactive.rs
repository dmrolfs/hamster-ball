// ABOUTME: The user's side of a run on a pty: raw mode, the byte relay, window resizes and Ctrl-Z suspend and resume.
// ABOUTME: Built after the child has started and torn down after it ends, so the terminal is raw for as short a time as possible.
//! Running the child on a pty (design 7.3, hb-ghd.2.4).

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::Arc;

use rustix::process::{
    Pid as RustixPid, Signal as RustixSignal, WaitOptions, getpid, kill_process, waitpid,
};
use rustix::termios::tcsetwinsize;
use snafu::{ResultExt, Snafu};

use super::pty::terminal_size;
use super::relay::Relay;
use super::run::ExitKind;
use super::terminal::{RawMode, TerminalError};

/// Why the terminal side could not be set up.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum InteractiveError {
    /// The user's terminal descriptors could not be duplicated.
    #[snafu(display("the terminal's descriptors could not be duplicated"))]
    Duplicate {
        /// The underlying error.
        source: io::Error,
    },

    /// The user's terminal could not be put in raw mode.
    #[snafu(display("the terminal could not be put in raw mode"))]
    Raw {
        /// The underlying error.
        source: TerminalError,
    },

    /// The relay thread could not be started.
    #[snafu(display("the terminal relay could not be started"))]
    Relay {
        /// The underlying error.
        source: io::Error,
    },
}

/// The user's terminal while the child runs on the master's other side.
pub(super) struct Interactive {
    raw: RawMode,
    relay: Relay,
    master: Arc<File>,
    user: Arc<OwnedFd>,
}

impl Interactive {
    /// Puts the terminal in raw mode and starts relaying between it and `master`.
    pub(super) fn start(master: File) -> Result<Self, InteractiveError> {
        let stdin = io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .context(DuplicateSnafu)?;
        let stdout = io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .context(DuplicateSnafu)?;
        Self::start_on(stdin, stdout, master)
    }

    /// Like [`Interactive::start`] for a terminal given as descriptors (`input` and `output`
    /// both name it). Takes the descriptors so a test can use a pty of its own.
    fn start_on(input: OwnedFd, output: OwnedFd, master: File) -> Result<Self, InteractiveError> {
        let user = Arc::new(input.try_clone().context(DuplicateSnafu)?);
        let raw = RawMode::enter(input.try_clone().context(DuplicateSnafu)?).context(RawSnafu)?;
        let master = Arc::new(master);
        let relay = Relay::start(input, master.try_clone().context(DuplicateSnafu)?, output)
            .context(RelaySnafu)?;
        Ok(Self {
            raw,
            relay,
            master,
            user,
        })
    }

    /// Copies the user's current window size to the child's pty.
    pub(super) fn resize_callback(&self) -> Arc<dyn Fn() + Send + Sync> {
        let (master, user) = (Arc::clone(&self.master), Arc::clone(&self.user));
        Arc::new(move || copy_size(&user, &master))
    }

    /// Waits for the child to end. If it stops itself (a TUI handling Ctrl-Z), gives the terminal
    /// back, stops `hb` so the shell shows a suspended job, and on `fg` returns to raw mode,
    /// repaints and continues the child.
    pub(super) fn wait(&self, child: RustixPid) -> io::Result<ExitKind> {
        loop {
            match waitpid(Some(child), WaitOptions::UNTRACED) {
                Ok(Some((_, status))) if status.stopped() => {
                    // The relay must not hold a read on the terminal while it is flushed.
                    self.relay.pause();
                    self.raw.suspend();
                    let _ = kill_process(getpid(), RustixSignal::STOP);
                    self.raw.resume();
                    copy_size(&self.user, &self.master);
                    self.relay.resume();
                    let _ = kill_process(child, RustixSignal::CONT);
                }
                Ok(Some((_, status))) => return Ok(exit_kind(status)),
                Ok(None) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Drains the child's last output and gives the terminal back.
    pub(super) fn finish(self) {
        self.relay.finish();
        // `raw` drops here and restores the terminal, discarding input nobody read.
    }
}

fn copy_size(user: &OwnedFd, master: &File) {
    if let Some(size) = terminal_size(user) {
        let _ = tcsetwinsize(master, size);
    }
}

fn exit_kind(status: rustix::process::WaitStatus) -> ExitKind {
    match (status.exit_status(), status.terminating_signal()) {
        (Some(code), _) => ExitKind::Exited(code),
        (None, Some(signal)) => ExitKind::Signalled(signal),
        (None, None) => ExitKind::Exited(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::pty::Pty;
    use claims::assert_ok;
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use pretty_assertions::assert_eq;
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::time::{Duration, Instant};

    fn open_slave(pty: &Pty) -> File {
        assert_ok!(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(pty.slave_path().as_str())
        )
    }

    fn read_until(file: &mut File, want: &[u8], wait: Duration) -> Vec<u8> {
        let mut seen = Vec::new();
        let deadline = Instant::now() + wait;
        let mut buffer = [0u8; 256];
        while !seen.windows(want.len()).any(|w| w == want) && Instant::now() < deadline {
            let mut fds = [PollFd::new(file.as_fd(), PollFlags::POLLIN)];
            if assert_ok!(poll(&mut fds, PollTimeout::from(50u8))) > 0 {
                let n = assert_ok!(file.read(&mut buffer));
                seen.extend_from_slice(&buffer[..n]);
            }
        }
        seen
    }

    #[test]
    fn finishing_gives_the_users_terminal_back_and_ends_the_relay() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let user_slave = open_slave(&outer);
        let mut child = open_slave(&inner);
        let before = assert_ok!(rustix::termios::tcgetattr(&user_slave));
        let terminal = assert_ok!(Interactive::start_on(
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
        ));
        let during = assert_ok!(rustix::termios::tcgetattr(&user_slave));
        assert_ne!(
            during.local_modes, before.local_modes,
            "not raw while running"
        );
        // The screen: something must read what the relay writes, or restoring the terminal's mode
        // would wait for it, as it would for a real terminal that stopped reading.
        let mut screen = assert_ok!(outer.clone_master());
        let reader = std::thread::spawn(move || {
            read_until(&mut screen, b"never", Duration::from_millis(1500))
        });
        assert_ok!(child.write_all(b"last words"));
        terminal.finish();
        let after = assert_ok!(rustix::termios::tcgetattr(&user_slave));
        assert_eq!(
            after.local_modes, before.local_modes,
            "the terminal was not restored"
        );
        // The relay has ended: later output from the child goes nowhere.
        assert_ok!(child.write_all(b"too late"));
        let shown =
            String::from_utf8_lossy(&assert_ok!(reader.join().map_err(|_| "reader panicked")))
                .into_owned();
        assert!(shown.contains("last words"), "{shown:?}");
        assert!(
            !shown.contains("too late"),
            "the relay kept running: {shown:?}"
        );
        let mut leftover = assert_ok!(inner.clone_master());
        assert_eq!(
            read_until(&mut leftover, b"late", Duration::from_secs(3)),
            b"too late"
        );
    }
}
