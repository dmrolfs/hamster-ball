// ABOUTME: Pty: a pseudo terminal pair for the child, with the master close-on-exec and the slave named for the profile.
// ABOUTME: Allocation, naming and sizing use only safe calls (rustix), so the crate stays under forbid(unsafe_code).
//! The agent's terminal (design 7.3, hb-ghd.2.4).
//!
//! The child runs on the slave side as the leader of its own session and `hb` keeps the master,
//! relaying bytes between it and the user's terminal. The slave's path goes into the profile as
//! the one `file-ioctl` grant. The master is close-on-exec so the child never inherits it.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::AsFd;
use std::process::Stdio;

use rustix::io::{FdFlags, fcntl_setfd};
use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
use rustix::termios::{tcgetwinsize, tcsetwinsize};
use snafu::{ResultExt, Snafu};

use crate::policy::{CanonicalPath, PathError};

/// A terminal window size, in characters and pixels.
pub type Winsize = rustix::termios::Winsize;

/// Why a pty could not be set up.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PtyError {
    /// The master side could not be allocated, unlocked or named.
    #[snafu(display("a pseudo terminal could not be allocated"))]
    Allocate {
        /// The underlying error.
        source: rustix::io::Errno,
    },

    /// The slave side could not be opened.
    #[snafu(display("the pseudo terminal's slave side could not be opened"))]
    OpenSlave {
        /// The underlying error.
        source: io::Error,
    },

    /// The slave's path is not a clean canonical path.
    #[snafu(display("the pseudo terminal's path is not usable"))]
    SlavePath {
        /// The underlying error.
        source: PathError,
    },
}

/// A pty: the master `hb` relays through, and the slave the child gets.
#[derive(Debug)]
pub struct Pty {
    master: File,
    slave: File,
    slave_path: CanonicalPath,
}

impl Pty {
    /// Allocates a pty. The master is close-on-exec.
    ///
    /// # Errors
    /// [`PtyError`] if the system has no pty to give or the slave cannot be opened.
    pub fn open() -> Result<Self, PtyError> {
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).context(AllocateSnafu)?;
        grantpt(&master).context(AllocateSnafu)?;
        unlockpt(&master).context(AllocateSnafu)?;
        fcntl_setfd(&master, FdFlags::CLOEXEC).context(AllocateSnafu)?;
        let name = ptsname(&master, Vec::new()).context(AllocateSnafu)?;
        let name = name.to_string_lossy().into_owned();
        let slave = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .context(OpenSlaveSnafu)?;
        let slave_path = CanonicalPath::from_canonical(&name).context(SlavePathSnafu)?;
        Ok(Self {
            master: File::from(master),
            slave,
            slave_path,
        })
    }

    /// The slave's device path, for the profile's `file-ioctl` grant.
    #[must_use]
    pub fn slave_path(&self) -> &CanonicalPath {
        &self.slave_path
    }

    /// The master side.
    #[must_use]
    pub fn master(&self) -> &File {
        &self.master
    }

    /// A second handle on the master, for the relay thread.
    ///
    /// # Errors
    /// [`io::Error`] if the descriptor cannot be duplicated.
    pub fn clone_master(&self) -> io::Result<File> {
        self.master.try_clone()
    }

    /// The slave as the child's stdin, stdout and stderr.
    ///
    /// # Errors
    /// [`io::Error`] if the descriptor cannot be duplicated.
    pub fn child_stdio(&self) -> io::Result<(Stdio, Stdio, Stdio)> {
        Ok((
            Stdio::from(self.slave.try_clone()?),
            Stdio::from(self.slave.try_clone()?),
            Stdio::from(self.slave.try_clone()?),
        ))
    }

    /// Closes `hb`'s own copy of the slave. Call it once the child has been started: the master
    /// then reports end of input when the child's last descriptor closes.
    #[must_use]
    pub fn release_slave(self) -> File {
        drop(self.slave);
        self.master
    }

    /// Sets the window size the child sees; the kernel tells the child's foreground group.
    ///
    /// # Errors
    /// [`rustix::io::Errno`] if the size cannot be set.
    pub fn set_size(&self, size: Winsize) -> Result<(), rustix::io::Errno> {
        tcsetwinsize(&self.master, size)
    }

    /// Copies the size of `terminal` to this pty, if `terminal` has one.
    pub fn copy_size_from(&self, terminal: impl AsFd) {
        if let Some(size) = terminal_size(terminal) {
            let _ = self.set_size(size);
        }
    }
}

/// The window size of `terminal`, if it is a terminal that reports one.
#[must_use]
pub fn terminal_size(terminal: impl AsFd) -> Option<Winsize> {
    tcgetwinsize(terminal).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::io::{Read, Write};

    fn pty() -> Pty {
        assert_ok!(Pty::open())
    }

    #[test]
    fn the_master_is_close_on_exec_so_the_child_never_inherits_it() {
        let pty = pty();
        let flags = assert_ok!(rustix::io::fcntl_getfd(pty.master()));
        assert!(flags.contains(FdFlags::CLOEXEC));
    }

    #[test]
    fn the_slave_path_is_a_terminal_device_that_exists() {
        let pty = pty();
        let path = pty.slave_path().as_str();
        assert!(path.starts_with("/dev/ttys"), "{path}");
        assert!(std::path::Path::new(path).exists());
    }

    #[test]
    fn two_ptys_have_different_slaves() {
        let (a, b) = (pty(), pty());
        assert!(a.slave_path() != b.slave_path());
    }

    #[test]
    fn bytes_written_to_the_master_arrive_on_the_slave_and_back() {
        let pty = pty();
        let mut master = assert_ok!(pty.clone_master());
        let (stdin, _, _) = assert_ok!(pty.child_stdio());
        // Read through a separate handle on the slave, as the child would.
        let mut slave = assert_ok!(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(pty.slave_path().as_str())
        );
        drop(stdin);
        assert_ok!(master.write_all(b"hi\n"));
        let mut buf = [0u8; 8];
        let n = assert_ok!(slave.read(&mut buf));
        assert_eq!(&buf[..n], b"hi\n");
        assert_ok!(slave.write_all(b"back\n"));
        // The line discipline echoes what was typed first, so read until the reply shows.
        let mut seen = Vec::new();
        while !seen.windows(4).any(|w| w == b"back") {
            let n = assert_ok!(master.read(&mut buf));
            seen.extend_from_slice(&buf[..n]);
        }
    }

    #[test]
    fn the_window_size_set_on_the_master_is_the_one_the_slave_reports() {
        let pty = pty();
        let size = Winsize {
            ws_row: 41,
            ws_col: 133,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_ok!(pty.set_size(size));
        let seen = assert_ok!(tcgetwinsize(&pty.slave));
        assert_eq!((seen.ws_row, seen.ws_col), (41, 133));
    }

    #[test]
    fn a_size_is_copied_from_another_terminal_and_a_non_terminal_changes_nothing() {
        let (source, target) = (pty(), pty());
        let size = Winsize {
            ws_row: 30,
            ws_col: 90,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_ok!(source.set_size(size));
        target.copy_size_from(&source.slave);
        let seen = assert_ok!(tcgetwinsize(&target.slave));
        assert_eq!((seen.ws_row, seen.ws_col), (30, 90));
        let file = assert_ok!(File::open("/dev/null"));
        assert!(terminal_size(&file).is_none());
        target.copy_size_from(&file);
        let still = assert_ok!(tcgetwinsize(&target.slave));
        assert_eq!((still.ws_row, still.ws_col), (30, 90));
    }

    #[test]
    fn releasing_the_slave_ends_the_masters_input_when_no_one_else_holds_it() {
        let pty = pty();
        let path = pty.slave_path().as_str().to_owned();
        let mut master = pty.release_slave();
        let mut buf = [0u8; 8];
        // With every slave descriptor closed the master read fails (EIO) or returns 0.
        let outcome = master.read(&mut buf);
        assert!(matches!(outcome, Ok(0) | Err(_)), "{outcome:?} for {path}");
    }
}
