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

use super::fence::hand_back;
use super::pty::terminal_size;
use super::relay::Relay;
use super::run::ExitKind;
use super::sanitize::{ClipboardPolicy, ClipboardUse};
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
    output: OwnedFd,
}

impl Interactive {
    /// Puts the terminal in raw mode and starts relaying between it and `master`.
    pub(super) fn start(
        master: File,
        clipboard: ClipboardPolicy,
    ) -> Result<Self, InteractiveError> {
        let stdin = io::stdin()
            .as_fd()
            .try_clone_to_owned()
            .context(DuplicateSnafu)?;
        let stdout = io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .context(DuplicateSnafu)?;
        Self::start_on_with(stdin, stdout, master, clipboard)
    }

    /// Like [`Interactive::start`] for a terminal given as descriptors (`input` and `output`
    /// both name it). Takes the descriptors so a test can use a pty of its own.
    #[cfg(test)]
    fn start_on(input: OwnedFd, output: OwnedFd, master: File) -> Result<Self, InteractiveError> {
        Self::start_on_with(input, output, master, ClipboardPolicy::default())
    }

    fn start_on_with(
        input: OwnedFd,
        output: OwnedFd,
        master: File,
        clipboard: ClipboardPolicy,
    ) -> Result<Self, InteractiveError> {
        let user = Arc::new(input.try_clone().context(DuplicateSnafu)?);
        let raw = RawMode::enter(input.try_clone().context(DuplicateSnafu)?).context(RawSnafu)?;
        let master = Arc::new(master);
        let screen = output.try_clone().context(DuplicateSnafu)?;
        let relay = Relay::start_with(
            input,
            master.try_clone().context(DuplicateSnafu)?,
            output,
            clipboard,
        )
        .context(RelaySnafu)?;
        Ok(Self {
            raw,
            relay,
            master,
            user,
            output: screen,
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
                    hand_back(&self.output, &self.user);
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

    /// Drains the child's last output and gives the terminal back. Returns how many times the
    /// agent set the clipboard.
    pub(super) fn finish(self) -> ClipboardUse {
        let Self {
            raw,
            relay,
            user,
            output,
            ..
        } = self;
        let clipboard = relay.finish();
        hand_back(&output, &user);
        // The terminal's own settings go back, and input nobody read is discarded.
        drop(raw);
        clipboard
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
    use crate::session::fence::FENCE_WAIT;
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

    /// A user's terminal that answers the fence query late, and sends a stale reply before that.
    fn slow_terminal(
        screen: File,
        stale_after: Duration,
        answer_after: Duration,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        slow_terminal_with(
            screen,
            b"LATEJUNK\n".to_vec(),
            stale_after,
            answer_after,
            false,
        )
    }

    /// Like [`slow_terminal`], with the stale reply chosen, and the answer optionally sent in two
    /// halves with a pause between them.
    fn slow_terminal_with(
        screen: File,
        stale: Vec<u8>,
        stale_after: Duration,
        answer_after: Duration,
        split_answer: bool,
    ) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut screen = screen;
            let started = Instant::now();
            let mut seen = Vec::new();
            let (mut stale_sent, mut answered) = (false, false);
            let mut buffer = [0u8; 256];
            while started.elapsed() < Duration::from_secs(4) {
                let mut fds = [PollFd::new(screen.as_fd(), PollFlags::POLLIN)];
                if assert_ok!(poll(&mut fds, PollTimeout::from(10u8))) > 0 {
                    let n = assert_ok!(screen.read(&mut buffer));
                    seen.extend_from_slice(&buffer[..n]);
                }
                if !stale_sent && started.elapsed() >= stale_after {
                    let _ = screen.write_all(&stale);
                    stale_sent = true;
                }
                let asked = seen.windows(3).any(|w| w == b"\x1b[c");
                if asked && !answered && started.elapsed() >= answer_after {
                    if split_answer {
                        let _ = screen.write_all(b"\x1b[?62;");
                        std::thread::sleep(Duration::from_millis(80));
                        let _ = screen.write_all(b"22c");
                    } else {
                        let _ = screen.write_all(b"\x1b[?62;22c");
                    }
                    answered = true;
                }
                if answered && started.elapsed() >= answer_after + Duration::from_millis(700) {
                    break;
                }
            }
            seen
        })
    }

    #[test]
    fn finishing_waits_for_the_terminals_answer_so_a_late_reply_cannot_reach_the_shell() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let user_slave = open_slave(&outer);
        let terminal = assert_ok!(Interactive::start_on(
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
        ));
        // The terminal is slow: a stale reply comes at 250 ms and its answer to hb's query at 450 ms.
        let screen = slow_terminal(
            assert_ok!(outer.clone_master()),
            Duration::from_millis(250),
            Duration::from_millis(450),
        );
        terminal.finish();
        // Whatever the terminal sent is gone from the input the shell would read.
        std::thread::sleep(Duration::from_millis(700));
        let mut fds = [PollFd::new(user_slave.as_fd(), PollFlags::POLLIN)];
        assert_eq!(
            assert_ok!(poll(&mut fds, PollTimeout::from(50u8))),
            0,
            "input was left for the shell"
        );
        let seen = assert_ok!(screen.join().map_err(|_| "terminal thread panicked"));
        let text = String::from_utf8_lossy(&seen).into_owned();
        // The input modes an agent may have left on are switched off before the terminal is handed back.
        for mode in [
            "\u{1b}[?1000l",
            "\u{1b}[?1006l",
            "\u{1b}[?1004l",
            "\u{1b}[?2004l",
        ] {
            assert!(text.contains(mode), "{mode:?} not sent: {text:?}");
        }
    }

    #[test]
    fn a_flood_of_stale_input_and_an_answer_in_two_halves_are_still_recognised() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let user_slave = open_slave(&outer);
        let terminal = assert_ok!(Interactive::start_on(
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
        ));
        let mut flood = b"x".repeat(3000);
        flood.push(b'\n');
        let screen = slow_terminal_with(
            assert_ok!(outer.clone_master()),
            flood,
            Duration::from_millis(100),
            Duration::from_millis(300),
            true,
        );
        let started = Instant::now();
        terminal.finish();
        // The answer was found, so the fence did not run out its whole wait.
        assert!(
            started.elapsed() < FENCE_WAIT,
            "the fence did not recognise the answer: {:?}",
            started.elapsed()
        );
        let _ = screen.join();
        std::thread::sleep(Duration::from_millis(300));
        let mut fds = [PollFd::new(user_slave.as_fd(), PollFlags::POLLIN)];
        assert_eq!(assert_ok!(poll(&mut fds, PollTimeout::from(50u8))), 0);
    }

    #[test]
    fn finishing_says_how_many_times_the_agent_set_the_clipboard() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let user_slave = open_slave(&outer);
        let mut child = open_slave(&inner);
        let terminal = assert_ok!(Interactive::start_on(
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
        ));
        let screen = slow_terminal(
            assert_ok!(outer.clone_master()),
            Duration::from_secs(10),
            Duration::from_millis(50),
        );
        assert_ok!(child.write_all(b"\x1b]52;c;aGk=\x07\x1b]52;c;?\x07\x1b]52;c;aGk=\x07done"));
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(terminal.finish().allowed, 2);
        let _ = screen.join();
    }

    #[test]
    fn a_terminal_that_never_answers_does_not_hold_up_the_end_of_the_run() {
        let outer = assert_ok!(Pty::open());
        let inner = assert_ok!(Pty::open());
        let user_slave = open_slave(&outer);
        let terminal = assert_ok!(Interactive::start_on(
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(user_slave.try_clone()).into(),
            assert_ok!(inner.clone_master()),
        ));
        // Something has to read the screen, or restoring the terminal's mode waits for it.
        let mut screen = assert_ok!(outer.clone_master());
        let reader =
            std::thread::spawn(move || read_until(&mut screen, b"never", Duration::from_secs(3)));
        let started = Instant::now();
        terminal.finish();
        let took = started.elapsed();
        let _ = reader.join();
        assert!(
            took >= FENCE_WAIT,
            "it did not wait for an answer: {took:?}"
        );
        assert!(took < FENCE_WAIT + Duration::from_secs(1), "{took:?}");
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
