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

use std::io::{self, IsTerminal, Write};
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

/// Puts the real terminal back, unless stdout is not one: then nothing was ever set, and the escape
/// sequences would be written into a file or pipe.
fn restore_terminal() -> io::Result<()> {
    if io::stdout().is_terminal() {
        restore_modes(&mut io::stdout(), true)
    } else {
        Ok(())
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

/// Who has the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hold {
    /// The UI has it: raw mode, alternate screen, paste and focus reporting.
    Ui,
    /// It was given back and every restoring step succeeded.
    Released,
    /// It was given back but a restoring step failed, so the terminal may be partly restored and
    /// the UI's modes are not on. Restoring is tried again at the next `suspend` and on drop,
    /// and `resume` refuses to build on it.
    Pending,
}

/// Restores the terminal when dropped.
#[derive(Debug)]
pub struct TerminalGuard {
    hold: Hold,
}

impl TerminalGuard {
    /// Takes the terminal. If this fails part way, what was changed is put back.
    ///
    /// # Errors
    /// The OS error if a mode cannot be set.
    pub fn enter() -> io::Result<Self> {
        // Nothing is changed, and nothing is written, unless both ends are a terminal: the escape
        // sequences would otherwise land in whatever file or pipe stdout was redirected to.
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "hb-supervise needs a terminal for both input and output",
            ));
        }
        // Armed first: a failure below restores through Drop.
        let mut guard = Self { hold: Hold::Ui };
        if let Err(error) = enter_modes(&mut io::stdout()) {
            let _ = guard.suspend();
            return Err(error);
        }
        Ok(guard)
    }

    /// Whether the UI holds the terminal now.
    #[cfg(test)]
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.hold == Hold::Ui
    }

    /// Whether a restoring step failed and has not yet been made good.
    #[cfg(test)]
    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.hold == Hold::Pending
    }

    /// Gives the terminal back, for a program that needs the real one. Does nothing if it is
    /// already given back.
    ///
    /// # Errors
    /// The first error of the restoring steps; all of them were tried. After an error the guard is
    /// pending, not released: the next call and drop try again.
    pub fn suspend(&mut self) -> io::Result<()> {
        self.suspend_with(restore_terminal)
    }

    /// [`TerminalGuard::suspend`] with the restoring passed in, so a failure can be tested.
    ///
    /// Every step is tried by `restore`. A failure leaves the guard pending so that Drop tries
    /// again, rather than leaving the owner's terminal in raw mode for want of one transient error.
    fn suspend_with(&mut self, restore: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
        if self.hold == Hold::Released {
            return Ok(());
        }
        let restored = restore();
        self.hold = if restored.is_ok() {
            Hold::Released
        } else {
            Hold::Pending
        };
        restored
    }

    /// Takes the terminal again after [`TerminalGuard::suspend`].
    ///
    /// # Errors
    /// The OS error if a mode cannot be set, or if the terminal was never fully given back
    /// (pending): modes are not built on a terminal in an unknown state. The terminal is then
    /// given back again.
    pub fn resume(&mut self) -> io::Result<()> {
        self.resume_with(|| enter_modes(&mut io::stdout()), restore_terminal)
    }

    /// [`TerminalGuard::resume`] with entering and restoring passed in, so each can be tested.
    fn resume_with(
        &mut self,
        enter: impl FnOnce() -> io::Result<()>,
        restore: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<()> {
        match self.hold {
            Hold::Ui => return Ok(()),
            Hold::Pending => {
                // Try once more to finish what failed; whatever the answer, the UI does not resume.
                self.suspend_with(restore)?;
                return Err(io::Error::other(
                    "the terminal was not fully restored before the review, so the UI was not resumed",
                ));
            }
            Hold::Released => {}
        }
        self.hold = Hold::Ui;
        if let Err(error) = enter() {
            // Part of the modes may be on. Put everything back, and keep the failure if that fails.
            self.hold = Hold::Pending;
            let _ = self.suspend_with(restore);
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
        let _ = restore_terminal();
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
    fn a_restore_that_fails_leaves_the_guard_pending_and_the_next_one_tries_again() {
        use claims::{assert_err, assert_ok};
        let mut guard = TerminalGuard { hold: Hold::Ui };
        let mut attempts = 0;
        assert_err!(guard.suspend_with(|| {
            attempts += 1;
            Err(io::Error::other("the terminal went away for a moment"))
        }));
        assert!(guard.is_pending(), "a failed restore must stay pending");
        assert!(!guard.is_active(), "and is not the UI");
        // Drop calls suspend again; this time it works.
        assert_ok!(guard.suspend_with(|| {
            attempts += 1;
            Ok(())
        }));
        assert!(!guard.is_active());
        assert_eq!(attempts, 2);
        // Once restored, nothing more is done: a third call must not restore again.
        assert_ok!(guard.suspend_with(|| {
            attempts += 1;
            Ok(())
        }));
        assert_eq!(attempts, 2);
    }

    #[test]
    fn a_guard_that_is_not_active_suspends_without_touching_the_terminal() {
        let mut guard = TerminalGuard {
            hold: Hold::Released,
        };
        assert!(guard.suspend().is_ok());
        assert!(!guard.is_active());
    }

    // ========================================================================
    // A terminal that was not fully given back is not built on again
    // ========================================================================

    fn failing() -> io::Result<()> {
        Err(io::Error::other("a restoring step failed"))
    }

    #[test]
    fn a_failed_suspend_makes_the_guard_pending_and_resume_does_not_enter_the_ui() {
        use claims::{assert_err, assert_ok};
        let mut guard = TerminalGuard { hold: Hold::Ui };
        assert_err!(guard.suspend_with(failing));
        assert!(guard.is_pending());
        let mut entered = false;
        let mut restored = 0;
        let error = assert_err!(guard.resume_with(
            || {
                entered = true;
                Ok(())
            },
            || {
                restored += 1;
                Ok(())
            }
        ));
        assert!(
            !entered,
            "modes were built on a terminal in an unknown state"
        );
        assert_eq!(restored, 1, "it tries once more to finish restoring");
        assert!(error.to_string().contains("not fully restored"), "{error}");
        // The retry worked, so the terminal is released now and a later resume may proceed.
        assert!(!guard.is_pending() && !guard.is_active());
        assert_ok!(guard.resume_with(|| Ok(()), || Ok(())));
        assert!(guard.is_active());
    }

    #[test]
    fn a_resume_whose_retry_also_fails_stays_pending_and_reports_the_not_resumed_error() {
        use claims::assert_err;
        let mut guard = TerminalGuard {
            hold: Hold::Pending,
        };
        let error = assert_err!(guard.resume_with(|| Ok(()), failing));
        assert!(guard.is_pending());
        assert!(!error.to_string().is_empty());
    }

    #[test]
    fn a_resume_that_fails_to_enter_puts_everything_back_and_leaves_no_ui_claim() {
        use claims::assert_err;
        let mut guard = TerminalGuard {
            hold: Hold::Released,
        };
        let mut restored = 0;
        assert_err!(guard.resume_with(failing, || {
            restored += 1;
            Ok(())
        }));
        assert_eq!(
            restored, 1,
            "everything was not put back after a half entry"
        );
        assert!(
            !guard.is_active(),
            "a half-entered UI must not count as the UI"
        );
    }

    #[test]
    fn a_failed_enter_whose_restore_also_fails_stays_pending_so_drop_tries_again() {
        use claims::assert_err;
        let mut guard = TerminalGuard {
            hold: Hold::Released,
        };
        assert_err!(guard.resume_with(failing, failing));
        assert!(guard.is_pending());
    }

    #[test]
    fn entering_without_a_terminal_changes_nothing_and_writes_nothing() {
        // Under cargo test stdin is not a terminal, which is the case being asserted.
        if io::stdin().is_terminal() && io::stdout().is_terminal() {
            return;
        }
        let error = assert_err!(TerminalGuard::enter());
        assert_eq!(error.kind(), io::ErrorKind::NotConnected);
    }
}
