// ABOUTME: RawMode: puts the user's terminal in raw mode for a run and restores it when dropped, flushing pending input.
// ABOUTME: Restoring uses TCSAFLUSH, so a terminal reply that arrives as the run ends cannot land in the shell afterwards.
//! The user's terminal while the agent runs (design 7.3, hb-ghd.2.4).
//!
//! Raw mode is entered as late as possible and left on every path that returns normally: normal
//! exit, a signal (signals are received through kqueue and return normally) and a panic that
//! unwinds. After SIGKILL of `hb` nothing can run, so the terminal stays raw: `reset` is the cure.

use std::os::fd::{AsFd, OwnedFd};

use rustix::termios::{OptionalActions, Termios, tcgetattr, tcsetattr};
use snafu::{ResultExt, Snafu};

/// Why the terminal could not be changed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum TerminalError {
    /// The terminal's settings could not be read or changed.
    #[snafu(display("the terminal's settings could not be changed"))]
    Settings {
        /// The underlying error.
        source: rustix::io::Errno,
    },
}

/// A terminal held in raw mode. Dropping it restores the settings it had.
#[derive(Debug)]
pub struct RawMode {
    terminal: OwnedFd,
    saved: Termios,
    raw: Termios,
}

impl RawMode {
    /// Saves the settings of `terminal` and puts it in raw mode.
    ///
    /// # Errors
    /// [`TerminalError`] if `terminal` is not a terminal or refuses the change.
    pub fn enter(terminal: OwnedFd) -> Result<Self, TerminalError> {
        let saved = tcgetattr(&terminal).context(SettingsSnafu)?;
        let mut raw = saved.clone();
        raw.make_raw();
        tcsetattr(&terminal, OptionalActions::Now, &raw).context(SettingsSnafu)?;
        Ok(Self {
            terminal,
            saved,
            raw,
        })
    }

    /// Gives the user's settings back, for example while `hb` is stopped by the shell.
    pub fn suspend(&self) {
        let _ = tcsetattr(&self.terminal, OptionalActions::Flush, &self.saved);
    }

    /// Returns to raw mode after [`RawMode::suspend`].
    pub fn resume(&self) {
        let _ = tcsetattr(&self.terminal, OptionalActions::Now, &self.raw);
    }

    /// The terminal.
    #[must_use]
    pub fn terminal(&self) -> impl AsFd + '_ {
        &self.terminal
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        self.suspend();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::pty::Pty;
    use claims::{assert_err, assert_ok};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use rustix::termios::{InputModes, LocalModes};
    use std::io::Write;
    use std::os::fd::OwnedFd;

    /// A pty slave standing in for the user's terminal, and the master that types into it.
    fn terminal() -> (OwnedFd, std::fs::File, Pty) {
        let pty = assert_ok!(Pty::open());
        let (stdin, _, _) = assert_ok!(pty.child_stdio());
        drop(stdin);
        let fd = OwnedFd::from(assert_ok!(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(pty.slave_path().as_str())
        ));
        let master = assert_ok!(pty.clone_master());
        (fd, master, pty)
    }

    fn local(fd: &OwnedFd) -> LocalModes {
        assert_ok!(tcgetattr(fd)).local_modes
    }

    #[test]
    fn raw_mode_turns_off_line_editing_echo_and_signal_keys_and_drop_gives_them_back() {
        let (fd, _master, _pty) = terminal();
        let before = assert_ok!(tcgetattr(&fd));
        assert!(
            before
                .local_modes
                .contains(LocalModes::ICANON | LocalModes::ECHO | LocalModes::ISIG)
        );
        let probe = assert_ok!(fd.try_clone());
        let raw = assert_ok!(RawMode::enter(fd));
        let during = local(&probe);
        assert!(
            !during.intersects(LocalModes::ICANON | LocalModes::ECHO | LocalModes::ISIG),
            "{during:?}"
        );
        drop(raw);
        let after = assert_ok!(tcgetattr(&probe));
        assert_eq!(after.local_modes, before.local_modes);
        assert_eq!(after.input_modes, before.input_modes);
        assert!(after.input_modes.contains(InputModes::ICRNL));
    }

    #[test]
    fn suspend_restores_the_users_settings_and_resume_goes_back_to_raw() {
        let (fd, _master, _pty) = terminal();
        let probe = assert_ok!(fd.try_clone());
        let raw = assert_ok!(RawMode::enter(fd));
        raw.suspend();
        assert!(local(&probe).contains(LocalModes::ICANON));
        raw.resume();
        assert!(!local(&probe).contains(LocalModes::ICANON));
        drop(raw);
        assert!(local(&probe).contains(LocalModes::ICANON));
    }

    #[test]
    fn restoring_discards_input_that_arrived_but_was_not_read() {
        let (fd, mut master, _pty) = terminal();
        let probe = assert_ok!(fd.try_clone());
        let raw = assert_ok!(RawMode::enter(fd));
        assert_ok!(master.write_all(b"LATEJUNK\n"));
        let readable = |fd: &OwnedFd| {
            let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
            assert_ok!(poll(&mut fds, PollTimeout::from(200u8))) > 0
        };
        assert!(
            readable(&probe),
            "the bytes never reached the terminal's input"
        );
        drop(raw);
        assert!(
            !readable(&probe),
            "late input survived the restore and would reach the shell"
        );
    }

    #[test]
    fn something_that_is_not_a_terminal_is_a_typed_error() {
        let file = OwnedFd::from(assert_ok!(std::fs::File::open("/dev/null")));
        let err = assert_err!(RawMode::enter(file));
        assert!(matches!(err, TerminalError::Settings { .. }));
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
