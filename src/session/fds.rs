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

use nix::unistd::close;

/// The directory that lists this process's open descriptors on macOS.
const FD_DIR: &str = "/dev/fd";

/// Closes every descriptor above 2 and returns the numbers it closed.
///
/// Call it once, before opening anything, in a program that is only `hb`. Descriptors 0, 1 and 2
/// stay: they are the child's standard streams.
pub fn close_inherited_fds() -> Vec<i32> {
    close_inherited_fds_except(None)
}

/// [`close_inherited_fds`], sparing `keep`: the supervisor channel claimed by [`claim_channel`].
pub fn close_inherited_fds_except(keep: Option<RawFd>) -> Vec<i32> {
    let names: Vec<String> = fs::read_dir(FD_DIR)
        .map(|dir| {
            dir.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    // The directory iterator's own descriptor is in the list and is already closed by now, so a
    // failed close of it is expected and ignored.
    inherited_from(names.iter().map(String::as_str))
        .into_iter()
        .filter(|fd| Some(*fd) != keep)
        .filter(|fd| close(*fd).is_ok())
        .collect()
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
}
