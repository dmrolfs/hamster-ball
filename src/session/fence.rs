// ABOUTME: The exit fence: switch off input modes, ask the terminal one question, and throw away input until it answers.
// ABOUTME: Keeps late terminal replies from being typed into the shell, for a pty run (relayed) and for one with no pty (settle).
//! Giving a terminal back clean (design 7.3, D67).

use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use rustix::process::{Pid, getpgrp};
use rustix::termios::tcgetpgrp;

use super::sanitize::MODE_RESET;
use super::terminal::RawMode;

/// How long to wait for the terminal to answer the fence query before giving up on it.
///
/// It is the time a reply may take to cross a slow link (ssh) and still be caught. A terminal
/// that never answers costs this much at the end of a run.
pub(super) const FENCE_WAIT: Duration = Duration::from_millis(750);

/// Primary device attributes: every terminal answers it, and answers in the order it was asked.
const FENCE_QUERY: &[u8] = b"\x1b[c";

/// How long writing the reset and the query may take before the terminal is given up on.
///
/// A terminal that takes no output at all (a supervisor that stopped reading its session's
/// terminal, hb-807 review A, HIGH 3) would otherwise hold `hb` here for ever, after the agent
/// has ended and the stop has been asked for.
const FENCE_WRITE: Duration = Duration::from_millis(750);

/// A terminal opened a second time, by its device path, so that it can be written without ever
/// blocking.
///
/// A second open is a separate open file description: making it non-blocking does not change the
/// descriptor `hb` was given, which other code (and the agent's own terminal) still treats as
/// blocking. The name is the one the kernel reports for `terminal`; a descriptor that has none (a
/// test's socket) is used as it is, so callers must still tolerate a blocking descriptor there.
pub(super) fn open_for_nonblocking_write(terminal: &OwnedFd) -> io::Result<File> {
    let name = rustix::termios::ttyname(terminal, Vec::new())?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(
            rustix::fs::OFlags::NONBLOCK.bits() as i32 | rustix::fs::OFlags::NOCTTY.bits() as i32,
        )
        .open(std::ffi::OsStr::from_bytes(name.to_bytes()))?;
    Ok(file)
}

/// Writes all of `bytes` to a non-blocking `screen`, waiting for room with `poll` and giving up at
/// `until`. Returns how many were written; fewer than `bytes.len()` means the terminal took no
/// more by the deadline. Never blocks: the descriptor must be non-blocking (see
/// [`open_for_nonblocking_write`]).
pub(super) fn write_until(screen: &mut File, bytes: &[u8], until: Instant) -> usize {
    let mut done = 0;
    while done < bytes.len() {
        match screen.write(&bytes[done..]) {
            Ok(0) => return done,
            Ok(n) => done += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                let left = until.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return done;
                }
                let millis = u16::try_from(left.as_millis()).unwrap_or(u16::MAX);
                let mut fds = [PollFd::new(screen.as_fd(), PollFlags::POLLOUT)];
                match poll(&mut fds, PollTimeout::from(millis)) {
                    Ok(n) if n > 0 => {}
                    Err(nix::errno::Errno::EINTR) => {}
                    _ => return done,
                }
            }
            Err(_) => return done,
        }
    }
    done
}

/// Makes the terminal safe to give back to the shell.
///
/// The agent may have left input modes on (mouse reports, focus events, bracketed paste) and
/// may have asked the terminal questions whose answers are still on their way. Both would
/// arrive as typing at the shell's prompt. The modes are switched off, and `hb` asks the
/// terminal one question of its own: a terminal answers in order, so when that answer arrives
/// every earlier one has, and everything read until then is thrown away.
pub(super) fn hand_back(output: &OwnedFd, user: &OwnedFd) {
    // A second, non-blocking open of the terminal: the relay's output has all been written (it is
    // finished before this runs), so nothing else holds a write here. If it cannot be opened the
    // terminal is not one we can safely write to, and there is nothing to fence.
    let Ok(mut screen) = open_for_nonblocking_write(output) else {
        return;
    };
    let until = Instant::now() + FENCE_WRITE;
    let wanted = MODE_RESET.len() + FENCE_QUERY.len();
    let sent =
        write_until(&mut screen, MODE_RESET, until) + write_until(&mut screen, FENCE_QUERY, until);
    // If the terminal takes nothing, there is nothing to fence: no answer can come either.
    if sent < wanted {
        return;
    }
    let Ok(input) = user.try_clone() else {
        return;
    };
    let mut input = File::from(input);
    let deadline = Instant::now() + FENCE_WAIT;
    let mut seen: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 256];
    while Instant::now() < deadline && !has_device_attributes_reply(&seen) {
        let left = deadline.saturating_duration_since(Instant::now());
        let millis = u16::try_from(left.as_millis()).unwrap_or(u16::MAX);
        let mut fds = [PollFd::new(input.as_fd(), PollFlags::POLLIN)];
        if poll(&mut fds, PollTimeout::from(millis)).is_ok_and(|n| n > 0) {
            match input.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    seen.extend_from_slice(&chunk[..n]);
                    keep_the_tail(&mut seen);
                }
            }
        }
    }
}

/// What the fence keeps of the input it has read: past this many bytes only the last
/// [`FENCE_TAIL`] are kept, since only the end can still turn into a reply.
const FENCE_KEEP: usize = 512;
const FENCE_TAIL: usize = 64;

fn keep_the_tail(seen: &mut Vec<u8>) {
    if seen.len() > FENCE_KEEP {
        let cut = seen.len() - FENCE_TAIL;
        seen.drain(..cut);
    }
}

/// Whether `bytes` holds a reply to a primary device attributes query: `ESC [ ? Ps ; ... c`.
fn has_device_attributes_reply(bytes: &[u8]) -> bool {
    bytes.windows(4).enumerate().any(|(start, window)| {
        if window[..3] != *b"\x1b[?" {
            return false;
        }
        let rest = &bytes[start + 3..];
        let params = rest
            .iter()
            .take_while(|b| b.is_ascii_digit() || **b == b';')
            .count();
        params > 0 && rest.get(params) == Some(&b'c')
    })
}

/// Whether `hb`'s own process group is the terminal's foreground group. Only then may `hb` change
/// the terminal's settings: from the background that would stop it.
fn owns_the_terminal(foreground: Option<Pid>, mine: Pid) -> bool {
    foreground == Some(mine)
}

/// Gives back a terminal `hb` was not relaying (the agent had no pty, so its output went through
/// a filter and straight to the terminal): input modes off, then the same fence as for a pty.
///
/// The terminal is put in raw mode for the fence so the answers are not echoed on the screen,
/// and restored afterwards. Does nothing if `hb` is not the terminal's foreground group.
pub(super) fn settle(terminal: &OwnedFd) {
    if owns_the_terminal(tcgetpgrp(terminal).ok(), getpgrp()) {
        settle_foreground(terminal);
    }
}

fn settle_foreground(terminal: &OwnedFd) {
    let Ok(copy) = terminal.try_clone() else {
        return;
    };
    // `hb` is not reading this terminal for anyone, so it is not yet raw.
    let Ok(raw) = RawMode::enter(copy) else {
        return;
    };
    hand_back(terminal, terminal);
    drop(raw);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::pty::Pty;
    use claims::{assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use rustix::termios::tcgetattr;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::thread;

    /// A pty whose slave is the terminal under test, and its master (the far end).
    fn terminal_pair() -> (OwnedFd, File, Pty) {
        let pty = assert_ok!(Pty::open());
        let slave = open_slave(&pty);
        let master = assert_ok!(pty.clone_master());
        (OwnedFd::from(slave), master, pty)
    }

    /// Fills a terminal's output queue through its own non-blocking handle.
    fn fill(screen: &mut File) {
        while screen.write(&[b'x'; 1024]).is_ok() {}
    }

    #[test]
    fn writing_to_a_terminal_that_takes_nothing_gives_up_at_the_deadline_and_never_blocks() {
        let (slave, _master, _pty) = terminal_pair();
        let mut screen = assert_ok!(open_for_nonblocking_write(&slave));
        fill(&mut screen);
        let started = Instant::now();
        let wrote = write_until(
            &mut screen,
            b"\x1b[c",
            Instant::now() + Duration::from_millis(300),
        );
        assert_eq!(wrote, 0);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_blocking_terminal_handle_is_not_made_non_blocking_by_the_second_open() {
        let (slave, _master, _pty) = terminal_pair();
        let before = rustix::fs::fcntl_getfl(&slave).unwrap_or(rustix::fs::OFlags::empty());
        let second = assert_ok!(open_for_nonblocking_write(&slave));
        let after = rustix::fs::fcntl_getfl(&slave).unwrap_or(rustix::fs::OFlags::empty());
        assert_eq!(
            before.contains(rustix::fs::OFlags::NONBLOCK),
            after.contains(rustix::fs::OFlags::NONBLOCK)
        );
        assert!(
            rustix::fs::fcntl_getfl(&second)
                .unwrap_or(rustix::fs::OFlags::empty())
                .contains(rustix::fs::OFlags::NONBLOCK)
        );
    }

    #[test]
    fn writing_to_a_terminal_that_reads_delivers_every_byte_in_order() {
        let (slave, mut master, _pty) = terminal_pair();
        let mut screen = assert_ok!(open_for_nonblocking_write(&slave));
        let bytes = b"\x1b[?1000l\x1b[c";
        assert_eq!(
            write_until(&mut screen, bytes, Instant::now() + Duration::from_secs(2)),
            bytes.len()
        );
        let mut got = [0_u8; 64];
        let n = assert_ok!(std::io::Read::read(&mut master, &mut got));
        assert!(got[..n].starts_with(b"\x1b[?1000l"), "{:?}", &got[..n]);
    }

    #[test]
    fn a_terminal_that_drains_part_way_through_still_gets_the_whole_write() {
        let (slave, master, _pty) = terminal_pair();
        let mut screen = assert_ok!(open_for_nonblocking_write(&slave));
        fill(&mut screen);
        let reader = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            let mut master = master;
            let mut seen = Vec::new();
            let mut buf = [0_u8; 4096];
            let end = Instant::now() + Duration::from_secs(3);
            while Instant::now() < end && !seen.ends_with(b"TAIL") {
                if let Ok(n) = std::io::Read::read(&mut master, &mut buf) {
                    seen.extend_from_slice(&buf[..n]);
                }
            }
            seen
        });
        let tail = b"TAIL";
        let wrote = write_until(&mut screen, tail, Instant::now() + Duration::from_secs(3));
        assert_eq!(wrote, tail.len());
        let seen = assert_ok!(reader.join());
        assert!(seen.ends_with(b"TAIL"), "the tail was lost");
    }

    fn open_slave(pty: &Pty) -> File {
        assert_ok!(
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(pty.slave_path().as_str())
        )
    }

    #[test]
    fn the_terminal_is_only_changed_while_hbs_group_is_in_front() {
        let mine = assert_some!(Pid::from_raw(100));
        let other = assert_some!(Pid::from_raw(7));
        assert!(owns_the_terminal(Some(mine), mine));
        assert!(!owns_the_terminal(Some(other), mine));
        assert!(!owns_the_terminal(None, mine), "no controlling terminal");
    }

    #[test]
    fn settling_swallows_a_late_reply_gives_the_terminal_back_as_it_was_and_echoes_nothing() {
        let pty = assert_ok!(Pty::open());
        let slave = open_slave(&pty);
        let terminal = OwnedFd::from(assert_ok!(slave.try_clone()));
        let before = assert_ok!(tcgetattr(&slave));
        // The screen: answers the fence query 300 ms late, with a stale reply ahead of the answer.
        let mut screen = assert_ok!(pty.clone_master());
        let watcher = std::thread::spawn(move || {
            let mut seen = Vec::new();
            let mut buffer = [0u8; 256];
            let started = Instant::now();
            let mut asked_at: Option<Instant> = None;
            let mut answered = false;
            while started.elapsed() < Duration::from_secs(3) {
                let mut fds = [PollFd::new(screen.as_fd(), PollFlags::POLLIN)];
                if assert_ok!(poll(&mut fds, PollTimeout::from(10u8))) > 0 {
                    let n = assert_ok!(screen.read(&mut buffer));
                    seen.extend_from_slice(&buffer[..n]);
                    if asked_at.is_none() && seen.windows(3).any(|w| w == b"\x1b[c") {
                        asked_at = Some(Instant::now());
                    }
                }
                if let Some(at) = asked_at {
                    if !answered && at.elapsed() >= Duration::from_millis(300) {
                        let _ = screen.write_all(b"STALE\n\x1b[?62;22c");
                        answered = true;
                    }
                    if answered && at.elapsed() >= Duration::from_millis(900) {
                        break;
                    }
                }
            }
            seen
        });
        let started = Instant::now();
        settle_foreground(&terminal);
        assert!(
            started.elapsed() < FENCE_WAIT,
            "the fence did not see the answer"
        );
        let seen = assert_ok!(watcher.join().map_err(|_| "watcher panicked"));
        let text = String::from_utf8_lossy(&seen).into_owned();
        for mode in [
            "\u{1b}[?1000l",
            "\u{1b}[?1006l",
            "\u{1b}[?1004l",
            "\u{1b}[?2004l",
        ] {
            assert!(text.contains(mode), "{mode:?} not sent: {text:?}");
        }
        assert!(!text.contains("STALE"), "the reply was echoed: {text:?}");
        let after = assert_ok!(tcgetattr(&slave));
        assert_eq!(
            after.local_modes - rustix::termios::LocalModes::PENDIN,
            before.local_modes - rustix::termios::LocalModes::PENDIN
        );
        let mut fds = [PollFd::new(slave.as_fd(), PollFlags::POLLIN)];
        assert_eq!(assert_ok!(poll(&mut fds, PollTimeout::from(100u8))), 0);
    }

    #[test]
    fn settling_a_stream_that_is_not_a_terminal_does_nothing_and_does_not_hang() {
        let null = OwnedFd::from(assert_ok!(File::open("/dev/null")));
        let started = Instant::now();
        settle(&null);
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn the_fence_keeps_only_the_tail_of_a_flood_and_all_of_a_small_read() {
        let mut small: Vec<u8> = (0..=255u8).cycle().take(FENCE_KEEP).collect();
        let before = small.clone();
        keep_the_tail(&mut small);
        assert_eq!(small, before);
        let mut flood: Vec<u8> = (0..=255u8).cycle().take(FENCE_KEEP + 1).collect();
        let tail = flood[FENCE_KEEP + 1 - FENCE_TAIL..].to_vec();
        keep_the_tail(&mut flood);
        assert_eq!(flood, tail);
    }

    #[test]
    fn a_primary_attributes_reply_is_recognised_wherever_it_sits_in_what_was_read() {
        assert!(has_device_attributes_reply(b"\x1b[?62;22c"));
        assert!(has_device_attributes_reply(b"LATEJUNK\x1b[?1;2c"));
        assert!(has_device_attributes_reply(b"\x1b[?6c trailing"));
        for no in [
            &b""[..],
            b"\x1b[?62;22",
            b"\x1b[62;22c",
            b"\x1b[>0;95;0c",
            b"c",
            b"\x1b[?c",
            b"\x1b[?6x2c",
        ] {
            assert!(!has_device_attributes_reply(no), "{no:?}");
        }
    }
}
