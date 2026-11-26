// ABOUTME: TerminalGuard: owns the owner's real terminal modes (raw, alternate screen, paste, focus), and puts every one back on drop, on error and from a panic.
// ABOUTME: Restoration is idempotent and tries every step even when one fails; the panic hook restores first, then lets the earlier hook print.
//! The owner's terminal (epic hb-b6q).
//!
//! The guard is armed *before* the first mode is changed, so a failure half way through setup
//! still restores what was changed. [`TerminalGuard::suspend`] gives the terminal back for
//! `hb approve`, and [`TerminalGuard::resume`] takes it again.
//!
//! SIGKILL cannot be caught, so it cannot restore the terminal; the sessions still stop, through
//! the end of their channels.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use crossterm::cursor::{Hide, Show};
use crossterm::event::{
    DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
    EnableFocusChange,
};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

/// Set by the panic hook, so the loop can see that something panicked on another thread.
static FATAL: AtomicBool = AtomicBool::new(false);

/// Whether a panic has happened since the hook was installed.
#[must_use]
pub fn fatal() -> bool {
    FATAL.load(Ordering::SeqCst)
}

/// Puts the terminal back, trying every step whatever happens to the others. Returns the first
/// error. With `raw` false the raw mode is left alone (for tests, which have no terminal).
fn restore_modes<W: Write>(out: &mut W, raw: bool) -> io::Result<()> {
    macro_rules! step {
        ($first:ident, $command:expr) => {
            let result = crossterm::execute!(out, $command);
            if $first.is_none() {
                $first = result.err();
            }
        };
    }
    let mut first: Option<io::Error> = None;
    step!(first, DisableBracketedPaste);
    step!(first, DisableFocusChange);
    step!(first, DisableMouseCapture);
    step!(first, Show);
    step!(first, LeaveAlternateScreen);
    if raw {
        let result = disable_raw_mode();
        if first.is_none() {
            first = result.err();
        }
    }
    let flushed = out.flush();
    match first {
        Some(error) => Err(error),
        None => flushed,
    }
}

/// Takes the terminal's modes for the UI.
fn enter_modes<W: Write>(out: &mut W) -> io::Result<()> {
    enable_raw_mode()?;
    crossterm::execute!(
        out,
        EnterAlternateScreen,
        EnableBracketedPaste,
        EnableFocusChange,
        Hide
    )
}

/// Drops the terminal's unread input, as `tcflush` does. Input the owner typed before a hand-over
/// must not reach the next reader, so a failure is an error the caller must act on.
///
/// # Errors
/// The OS error if the terminal's queue cannot be flushed (for example, input is not a terminal).
pub fn flush_input() -> io::Result<()> {
    rustix::termios::tcflush(std::io::stdin(), rustix::termios::QueueSelector::IFlush)
        .map_err(io::Error::from)
}

/// Restores the terminal when dropped.
#[derive(Debug)]
pub struct TerminalGuard {
    active: bool,
}

impl TerminalGuard {
    /// Takes the terminal. If this fails part way, what was changed is put back.
    ///
    /// # Errors
    /// The OS error if a mode cannot be set.
    pub fn enter() -> io::Result<Self> {
        // Armed first: a failure below restores through Drop.
        let mut guard = Self { active: true };
        if let Err(error) = enter_modes(&mut io::stdout()) {
            let _ = guard.suspend();
            return Err(error);
        }
        Ok(guard)
    }

    /// Whether the UI holds the terminal now.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Gives the terminal back, for a program that needs the real one. Does nothing if it is
    /// already given back.
    ///
    /// # Errors
    /// The first error of the restoring steps; all of them were tried. The guard counts the
    /// terminal as given back either way, since nothing more can be done with it.
    pub fn suspend(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        // Every step is tried; the guard stays active if any failed, so Drop tries again rather
        // than leaving the owner's terminal in raw mode for want of one transient error.
        let restored = restore_modes(&mut io::stdout(), true);
        if restored.is_ok() {
            self.active = false;
        }
        restored
    }

    /// Takes the terminal again after [`TerminalGuard::suspend`].
    ///
    /// # Errors
    /// The OS error if a mode cannot be set; the terminal is then given back again.
    pub fn resume(&mut self) -> io::Result<()> {
        if self.active {
            return Ok(());
        }
        self.active = true;
        if let Err(error) = enter_modes(&mut io::stdout()) {
            let _ = self.suspend();
            return Err(error);
        }
        Ok(())
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.suspend();
    }
}

/// Installs a panic hook that restores the terminal first, so the message that follows is
/// readable, and then runs the hook that was there. Call once, after any other hook is set.
///
/// The hook joins no threads and takes none of this program's locks. Restoring does take the
/// terminal library's own lock for raw mode, so a thread that panics while another holds it is
/// the one case this cannot promise to be quick.
pub fn install_panic_hook() {
    let earlier = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        FATAL.store(true, Ordering::SeqCst);
        let _ = restore_modes(&mut io::stdout(), true);
        earlier(info);
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_err;
    use pretty_assertions::assert_eq;

    /// Fails every write, and counts them.
    struct Failing(usize);

    impl Write for Failing {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            self.0 += 1;
            Err(io::Error::other("closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn every_restoring_step_is_tried_even_when_each_one_fails() {
        let mut out = Failing(0);
        assert_err!(restore_modes(&mut out, false));
        // Paste, focus, mouse, cursor and alternate screen: five steps, five attempts.
        assert_eq!(out.0, 5);
    }

    #[test]
    fn restoring_to_a_working_writer_writes_all_five_resets() {
        let mut out = Vec::new();
        assert!(restore_modes(&mut out, false).is_ok());
        let text = String::from_utf8_lossy(&out).into_owned();
        for reset in ["\x1b[?2004l", "\x1b[?1004l", "\x1b[?25h", "\x1b[?1049l"] {
            assert!(text.contains(reset), "{reset:?} missing from {text:?}");
        }
        assert!(text.contains("\x1b[?1000l"), "mouse capture off: {text:?}");
    }

    #[test]
    fn a_restore_that_fails_leaves_the_guard_active_so_drop_tries_again() {
        // Under a test harness stdout is not a terminal, so raw mode cannot be turned off and
        // restoring reports an error: exactly the case that must stay pending.
        let mut guard = TerminalGuard { active: true };
        let result = guard.suspend();
        if result.is_err() {
            assert!(guard.is_active(), "a failed restore must stay pending");
        } else {
            assert!(!guard.is_active());
        }
        // Do not let Drop write reset bytes into the test output.
        guard.active = false;
    }

    #[test]
    fn a_guard_that_is_not_active_suspends_without_touching_the_terminal() {
        let mut guard = TerminalGuard { active: false };
        assert!(guard.suspend().is_ok());
        assert!(!guard.is_active());
    }
}
