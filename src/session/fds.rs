// ABOUTME: close_inherited_fds: the hb binary closes every descriptor above 2 at start so none reaches the agent.
// ABOUTME: A descriptor to a denied file is a way around Seatbelt, which checks the path only when a file is opened.
//! Descriptors inherited from the launching shell.
//!
//! `sandbox-exec` passes every open descriptor to the command, and Rust's `Command` closes only
//! the ones Rust opened. So `exec 3<~/.ssh/id_ed25519; hb run agent` would hand the agent a
//! readable key although the profile denies the path. The `hb` binary calls
//! [`close_inherited_fds`] first thing in `main`. Library callers must not: it closes every
//! descriptor of the calling process, including ones other code owns.

use std::fs::{self, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::errno::Errno;
use nix::unistd::close;
use snafu::{ResultExt, Snafu};

/// The directory that lists this process's open descriptors on macOS.
const FD_DIR: &str = "/dev/fd";

/// Why the sweep could not be completed. The run must not go on: a descriptor it could not close
/// might be one the sandbox profile denies by path, or the supervisor's channel.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SweepError {
    /// The directory that lists the open descriptors could not be read.
    #[snafu(display("the list of open descriptors could not be read"))]
    List {
        /// The OS error.
        source: io::Error,
    },
    /// A descriptor could not be closed.
    #[snafu(display("descriptor {fd} could not be closed"))]
    Close {
        /// The descriptor.
        fd: i32,
        /// The OS error.
        source: Errno,
    },
}

/// Closes every descriptor above 2 and returns the numbers it closed.
///
/// Call it once, before opening anything, in a program that is only `hb`. Descriptors 0, 1 and 2
/// stay: they are the child's standard streams.
///
/// # Errors
/// [`SweepError`] if the open descriptors cannot be listed, or one cannot be closed.
pub fn close_inherited_fds() -> Result<Vec<i32>, SweepError> {
    close_inherited_fds_except(None)
}

/// [`close_inherited_fds`], sparing `keep`: the supervisor channel claimed by [`claim_channel`].
///
/// # Errors
/// As [`close_inherited_fds`].
pub fn close_inherited_fds_except(keep: Option<RawFd>) -> Result<Vec<i32>, SweepError> {
    sweep(keep, list_open, close)
}

/// The names in the descriptor directory. An entry that cannot be read is an error, not a gap.
fn list_open() -> io::Result<Vec<String>> {
    fs::read_dir(FD_DIR)?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect()
}

/// The sweep, with the listing and the closing passed in so each failure can be tested.
fn sweep(
    keep: Option<RawFd>,
    list: impl FnOnce() -> io::Result<Vec<String>>,
    mut close_fd: impl FnMut(RawFd) -> Result<(), Errno>,
) -> Result<Vec<i32>, SweepError> {
    let names = list().context(ListSnafu)?;
    let mut closed = Vec::new();
    for fd in inherited_from(names.iter().map(String::as_str)) {
        if Some(fd) == keep {
            continue;
        }
        match close_fd(fd) {
            Ok(()) => closed.push(fd),
            // The directory iterator's own descriptor is in the list and is already closed by
            // now; that is the one close that is expected to find nothing.
            Err(Errno::EBADF) => {}
            Err(source) => return Err(source).context(CloseSnafu { fd }),
        }
    }
    Ok(closed)
}

/// Takes the supervisor channel the launcher left open as descriptor `number`.
///
/// The descriptor is reopened through `/dev/fd`, which gives a new descriptor that is
/// close-on-exec from the start, so nothing `hb` runs inherits it. The original is not
/// close-on-exec; the sweep ([`close_inherited_fds_except`]) closes it. This takes no `unsafe`:
/// `from_raw_fd` would.
///
/// # Errors
/// An [`io::Error`] if `number` is not an open descriptor, is not a unix socket, or is 0, 1 or 2.
pub fn claim_channel(number: RawFd) -> io::Result<UnixStream> {
    if number <= 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the channel descriptor must be above 2",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("{FD_DIR}/{number}"))?;
    let stream = UnixStream::from(OwnedFd::from(file));
    // Fails unless this is a socket.
    stream.local_addr()?;
    Ok(stream)
}

/// What [`start_up`] found: the channel, if a supervisor passed one.
#[derive(Debug)]
pub struct StartUp {
    /// The claimed channel.
    pub channel: Option<UnixStream>,
    /// Why the run must not start: the variable was present but unusable, or the sweep failed.
    pub problem: Option<StartUpError>,
}

/// Why `hb` must not start.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum StartUpError {
    /// The supervisor descriptor variable does not name a usable channel.
    #[snafu(display("the supervisor channel is not usable"))]
    Channel {
        /// The OS error.
        source: io::Error,
    },
    /// The inherited descriptors could not all be closed.
    #[snafu(display("the inherited descriptors could not be closed"))]
    Sweep {
        /// What failed.
        source: SweepError,
    },
}

/// What the `hb` binaries do first: claim the supervisor channel named by
/// [`SUPERVISOR_FD_VAR`](super::supervised::SUPERVISOR_FD_VAR), if any, then close every other
/// inherited descriptor.
///
/// The claim comes first because the sweep closes the original. A variable that does not name a
/// usable channel is reported in [`StartUp::problem`], never ignored: a supervisor that thinks it
/// has a channel must not get an unreported session.
pub fn start_up() -> StartUp {
    let named = std::env::var_os(super::supervised::SUPERVISOR_FD_VAR);
    start_up_with(named.as_deref(), close_inherited_fds_except)
}

/// [`start_up`] with the variable's value and the sweep passed in.
fn start_up_with(
    named: Option<&std::ffi::OsStr>,
    run_sweep: impl FnOnce(Option<RawFd>) -> Result<Vec<i32>, SweepError>,
) -> StartUp {
    let number = named.map(|value| {
        value
            .to_str()
            .and_then(|text| text.parse::<RawFd>().ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the supervisor descriptor is not a number",
                )
            })
    });
    let claimed = number.map(|number| {
        let number = number?;
        let channel = claim_channel(number)?;
        Ok::<_, io::Error>((number, channel))
    });
    let keep = claimed
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .map(|(_, channel)| raw(channel));
    let swept = run_sweep(keep);
    // The original is not close-on-exec. A finished sweep has closed it; one that failed half
    // way may not have, and nothing may be left open for the agent to inherit.
    if swept.is_err()
        && let Some(Ok((number, _))) = &claimed
        && *number > 2
    {
        let _ = close(*number);
    }
    if let Err(source) = swept {
        return StartUp {
            channel: None,
            problem: Some(StartUpError::Sweep { source }),
        };
    }
    match claimed {
        None => StartUp {
            channel: None,
            problem: None,
        },
        Some(Ok((_, channel))) => StartUp {
            channel: Some(channel),
            problem: None,
        },
        Some(Err(source)) => StartUp {
            channel: None,
            problem: Some(StartUpError::Channel { source }),
        },
    }
}

/// The descriptor of `stream`, to spare in the sweep.
#[must_use]
pub fn raw(stream: &UnixStream) -> RawFd {
    stream.as_raw_fd()
}

/// The descriptor numbers above 2 among `names`, sorted and without repeats.
fn inherited_from<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<i32> {
    let mut fds: Vec<i32> = names
        .into_iter()
        .filter_map(|n| n.parse::<i32>().ok())
        .filter(|fd| *fd > 2)
        .collect();
    fds.sort_unstable();
    fds.dedup();
    fds
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn only_numbers_above_two_are_inherited_and_the_list_is_sorted_and_distinct() {
        let names = [
            "0",
            "1",
            "2",
            "3",
            "10",
            "4",
            "4",
            "-1",
            "x",
            "",
            "3.5",
            "2147483647",
        ];
        assert_eq!(inherited_from(names), vec![3, 4, 10, 2_147_483_647]);
    }

    #[test]
    fn nothing_above_two_means_nothing_to_close() {
        assert_eq!(inherited_from(["0", "1", "2"]), Vec::<i32>::new());
        assert_eq!(inherited_from([]), Vec::<i32>::new());
    }

    #[test]
    fn a_number_too_large_for_a_descriptor_is_ignored() {
        assert_eq!(
            inherited_from(["2147483648", "99999999999"]),
            Vec::<i32>::new()
        );
    }

    #[test]
    fn a_claimed_channel_is_a_new_close_on_exec_descriptor_that_talks_to_the_peer() {
        use claims::{assert_err, assert_ok};
        use std::io::{Read, Write};
        let (mut peer, ours) = assert_ok!(UnixStream::pair());
        let number = ours.as_raw_fd();
        let mut claimed = assert_ok!(claim_channel(number));
        assert_ne!(raw(&claimed), number);
        let flags = assert_ok!(rustix::io::fcntl_getfd(&claimed));
        assert!(
            flags.contains(rustix::io::FdFlags::CLOEXEC),
            "the claimed descriptor leaks"
        );
        assert_ok!(claimed.write_all(b"x"));
        let mut byte = [0u8; 1];
        assert_ok!(peer.read_exact(&mut byte));
        assert_eq!(&byte, b"x");
        // Not a socket, and not a descriptor, are both refused.
        let file = assert_ok!(fs::File::open("/dev/null"));
        assert_err!(claim_channel(file.as_raw_fd()));
        assert_err!(claim_channel(2));
        assert_err!(claim_channel(2_000_000));
    }

    #[test]
    fn the_sweep_spares_only_the_kept_descriptor() {
        assert_eq!(
            inherited_from(["3", "4", "5"])
                .into_iter()
                .filter(|fd| Some(*fd) != Some(4))
                .collect::<Vec<_>>(),
            vec![3, 5]
        );
    }
    // ========================================================================
    // The sweep fails closed (hb-q9o security review)
    // ========================================================================

    /// A socket whose descriptor nothing owns, as the launcher leaves the original: the peer, and
    /// the descriptor's number as the variable would give it.
    fn original_channel() -> (UnixStream, String) {
        use claims::assert_ok;
        use std::os::fd::IntoRawFd;
        let (peer, ours) = assert_ok!(UnixStream::pair());
        (peer, ours.into_raw_fd().to_string())
    }

    fn names(list: &[&str]) -> io::Result<Vec<String>> {
        Ok(list.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn a_descriptor_list_that_cannot_be_read_is_an_error_not_an_empty_list() {
        use claims::assert_err;
        let failed = sweep(
            None,
            || Err(io::Error::from(io::ErrorKind::PermissionDenied)),
            |_| Ok(()),
        );
        let error = assert_err!(failed);
        assert!(matches!(error, SweepError::List { .. }), "{error:?}");
    }

    #[test]
    fn a_descriptor_that_cannot_be_closed_stops_the_sweep_and_is_named() {
        use claims::assert_err;
        let mut tried = Vec::new();
        let failed = sweep(
            None,
            || names(&["0", "3", "4", "5"]),
            |fd| {
                tried.push(fd);
                if fd == 4 { Err(Errno::EIO) } else { Ok(()) }
            },
        );
        let error = assert_err!(failed);
        assert!(
            matches!(error, SweepError::Close { fd: 4, .. }),
            "{error:?}"
        );
        assert_eq!(tried, vec![3, 4], "it must not go on past the failure");
    }

    #[test]
    fn a_descriptor_already_closed_by_the_listing_itself_is_not_a_failure() {
        use claims::assert_ok;
        let closed = assert_ok!(sweep(
            Some(5),
            || names(&["3", "4", "5", "6"]),
            |fd| if fd == 4 { Err(Errno::EBADF) } else { Ok(()) },
        ));
        assert_eq!(closed, vec![3, 6], "5 is kept, 4 was already gone");
    }

    #[test]
    fn a_failed_sweep_means_no_channel_and_a_reported_problem_so_hb_does_not_start() {
        use claims::assert_some;
        let (_peer, number) = original_channel();
        let started = start_up_with(Some(std::ffi::OsStr::new(&number)), |_| {
            Err(SweepError::List {
                source: io::Error::from(io::ErrorKind::PermissionDenied),
            })
        });
        assert!(started.channel.is_none());
        let problem = assert_some!(started.problem);
        assert!(matches!(problem, StartUpError::Sweep { .. }), "{problem:?}");
    }

    #[test]
    fn a_good_sweep_keeps_the_claimed_channel_and_a_bad_variable_is_still_reported() {
        use claims::assert_some;
        let (_peer, number) = original_channel();
        let ok = start_up_with(Some(std::ffi::OsStr::new(&number)), |_| Ok(Vec::new()));
        assert!(ok.channel.is_some() && ok.problem.is_none());
        let bad = start_up_with(Some(std::ffi::OsStr::new("x")), |_| Ok(Vec::new()));
        let problem = assert_some!(bad.problem);
        assert!(
            matches!(problem, StartUpError::Channel { .. }),
            "{problem:?}"
        );
        let none = start_up_with(None, |_| Ok(Vec::new()));
        assert!(none.channel.is_none() && none.problem.is_none());
    }
}
