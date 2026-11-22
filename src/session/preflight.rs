// ABOUTME: The nesting preflight: sandbox-exec cannot run inside another sandbox, so hb checks first and says so plainly.
// ABOUTME: classify() is pure and decides from the exit code and the exact message, because "command not found" also exits 71.
//! Detecting that `hb` is already inside a sandbox (design 7.4, D56).
//!
//! `sandbox-exec` fails inside any other macOS sandbox with
//! `sandbox-exec: sandbox_apply: Operation not permitted` and exit 71, whether the outer profile
//! is deny-default or `(allow default)`. The probe applies a harmless profile to `/usr/bin/true`
//! (about 60 ms). Exit 71 alone is not enough: `sandbox-exec` also uses 71 when the command to
//! run does not exist.

use std::io;
use std::process::Command;

use snafu::{ResultExt, Snafu};

use crate::text::EscapedBounded;

/// The only `sandbox-exec` hb runs, by absolute path so `PATH` cannot substitute another.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";
/// The message `sandbox-exec` prints when it is already sandboxed.
const NESTED_MESSAGE: &str = "sandbox_apply: Operation not permitted";
/// The exit code `sandbox-exec` uses for that failure.
const NESTED_EXIT: i32 = 71;
/// How much of an unexpected error message is echoed.
const PREVIEW_CHARS: usize = 200;

/// What the probe saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// `sandbox-exec` works here.
    Clear,
    /// `hb` is already inside a sandbox.
    Nested,
    /// The probe failed for some other reason.
    Failed {
        /// The exit code, if the probe exited.
        code: Option<i32>,
        /// What it printed, bounded and escaped.
        message: String,
    },
}

/// Why `hb` cannot go on.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PreflightError {
    /// `hb` is inside another sandbox.
    #[snafu(display(
        "hb cannot run inside another sandbox, because sandbox-exec cannot nest{}. Run hb from a shell that is not sandboxed",
        if *inside_hb { " (this shell is already inside an hb session)" } else { "" }
    ))]
    Nested {
        /// Whether the `HB_SESSION` marker says the outer sandbox is `hb` itself.
        inside_hb: bool,
    },

    /// `sandbox-exec` could not be started.
    #[snafu(display("{SANDBOX_EXEC} could not be started"))]
    Spawn {
        /// The underlying error.
        source: io::Error,
    },

    /// `sandbox-exec` failed for a reason other than nesting.
    #[snafu(display("{SANDBOX_EXEC} failed its self-check{}: {message}", exit_text(*code)))]
    Broken {
        /// The exit code, if there was one.
        code: Option<i32>,
        /// What it printed.
        message: String,
    },
}

fn exit_text(code: Option<i32>) -> String {
    code.map_or_else(String::new, |c| format!(" (exit {c})"))
}

/// Decides what a probe run means, from its exit code and stderr.
#[must_use]
pub fn classify(code: Option<i32>, stderr: &str) -> ProbeOutcome {
    if code == Some(0) {
        return ProbeOutcome::Clear;
    }
    if code == Some(NESTED_EXIT) && stderr.contains(NESTED_MESSAGE) {
        return ProbeOutcome::Nested;
    }
    ProbeOutcome::Failed {
        code,
        message: EscapedBounded::new(stderr.trim(), PREVIEW_CHARS).to_string(),
    }
}

/// Runs the probe.
///
/// # Errors
/// [`PreflightError::Spawn`] if `sandbox-exec` cannot be started.
pub fn probe() -> Result<ProbeOutcome, PreflightError> {
    let output = Command::new(SANDBOX_EXEC)
        .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
        .env_clear()
        .output()
        .context(SpawnSnafu)?;
    Ok(classify(
        output.status.code(),
        &String::from_utf8_lossy(&output.stderr),
    ))
}

/// Checks that `sandbox-exec` can be used from here.
///
/// `inside_hb` only changes the wording of the message.
///
/// # Errors
/// [`PreflightError::Nested`] if already sandboxed, [`PreflightError::Broken`] if the probe
/// failed some other way, [`PreflightError::Spawn`] if it could not start.
pub fn check_nesting(inside_hb: bool) -> Result<(), PreflightError> {
    verdict(probe()?, inside_hb)
}

/// What a probe outcome means for whether `hb` can go on.
fn verdict(outcome: ProbeOutcome, inside_hb: bool) -> Result<(), PreflightError> {
    match outcome {
        ProbeOutcome::Clear => Ok(()),
        ProbeOutcome::Nested => NestedSnafu { inside_hb }.fail(),
        ProbeOutcome::Failed { code, message } => BrokenSnafu { code, message }.fail(),
    }
}

/// Whether `hb` is inside another sandbox, for tests that must skip rather than fail there.
#[must_use]
pub fn is_nested() -> bool {
    matches!(probe(), Ok(ProbeOutcome::Nested))
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    const REAL_NESTED: &str = "sandbox-exec: sandbox_apply: Operation not permitted\n";

    #[test]
    fn success_is_clear() {
        assert_eq!(classify(Some(0), ""), ProbeOutcome::Clear);
        assert_eq!(classify(Some(0), "noise on stderr"), ProbeOutcome::Clear);
    }

    #[test]
    fn exit_71_with_the_exact_message_is_nested() {
        assert_eq!(classify(Some(71), REAL_NESTED), ProbeOutcome::Nested);
    }

    #[test]
    fn exit_71_for_a_missing_command_is_not_nested() {
        let stderr = "sandbox-exec: execvp() of 'nosuchcmd' failed: No such file or directory\n";
        assert!(matches!(
            classify(Some(71), stderr),
            ProbeOutcome::Failed { code: Some(71), .. }
        ));
    }

    #[test]
    fn the_message_with_another_exit_code_or_no_exit_is_not_nested() {
        assert!(matches!(
            classify(Some(1), REAL_NESTED),
            ProbeOutcome::Failed { .. }
        ));
        assert!(matches!(
            classify(None, REAL_NESTED),
            ProbeOutcome::Failed { code: None, .. }
        ));
    }

    #[test]
    fn a_failure_message_is_escaped_and_bounded() {
        let long = format!("\u{1b}[2J{}", "x".repeat(1000));
        let ProbeOutcome::Failed { message, .. } = classify(Some(2), &long) else {
            return;
        };
        assert!(!message.contains('\u{1b}'));
        assert!(message.len() < 400, "{}", message.len());
    }

    #[test]
    fn the_nested_error_says_what_to_do_and_names_hb_only_when_the_marker_says_so() {
        let plain = assert_err!(NestedSnafu { inside_hb: false }.fail::<()>()).to_string();
        assert!(plain.contains("not sandboxed"), "{plain}");
        assert!(!plain.contains("inside an hb session"), "{plain}");
        let inside = assert_err!(NestedSnafu { inside_hb: true }.fail::<()>()).to_string();
        assert!(inside.contains("inside an hb session"), "{inside}");
    }

    #[test]
    fn the_verdict_lets_only_a_clear_probe_through() {
        assert_ok!(verdict(ProbeOutcome::Clear, false));
        assert!(matches!(
            assert_err!(verdict(ProbeOutcome::Nested, true)),
            PreflightError::Nested { inside_hb: true }
        ));
        assert!(matches!(
            assert_err!(verdict(ProbeOutcome::Nested, false)),
            PreflightError::Nested { inside_hb: false }
        ));
        let failed = ProbeOutcome::Failed {
            code: Some(65),
            message: "x".to_owned(),
        };
        assert!(matches!(
            assert_err!(verdict(failed, false)),
            PreflightError::Broken { code: Some(65), .. }
        ));
    }

    /// Re-runs this test binary inside a real sandbox, where the library must say it is nested.
    #[test]
    #[cfg(target_os = "macos")]
    fn inside_a_real_sandbox_is_nested_and_check_nesting_refuses() {
        const CHILD_FLAG: &str = "HB_PREFLIGHT_TEST_CHILD";
        if std::env::var_os(CHILD_FLAG).is_some() {
            assert!(is_nested());
            assert!(matches!(
                assert_err!(check_nesting(false)),
                PreflightError::Nested { .. }
            ));
            return;
        }
        if is_nested() {
            // Already sandboxed (an agent ran `cargo test` inside hb): the outer layer cannot be made.
            return;
        }
        let exe = assert_ok!(std::env::current_exe());
        let output = assert_ok!(
            Command::new(SANDBOX_EXEC)
                .args(["-p", "(version 1)(allow default)"])
                .arg(exe)
                .args(["--exact", "session::preflight::tests::inside_a_real_sandbox_is_nested_and_check_nesting_refuses"])
                .env_clear()
                .env(CHILD_FLAG, "1")
                .output()
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn a_broken_probe_error_carries_the_exit_code_in_its_text() {
        let text = assert_err!(
            BrokenSnafu {
                code: Some(65),
                message: "bad".to_owned()
            }
            .fail::<()>()
        )
        .to_string();
        assert!(text.contains("exit 65") && text.contains("bad"), "{text}");
    }

    /// Runs the real probe from inside a real `sandbox-exec`: the case the design describes.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_real_probe_run_inside_a_sandbox_is_classified_nested() {
        let output = assert_ok!(
            Command::new(SANDBOX_EXEC)
                .args(["-p", "(version 1)(allow default)", SANDBOX_EXEC])
                .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
                .env_clear()
                .output()
        );
        assert_eq!(
            classify(
                output.status.code(),
                &String::from_utf8_lossy(&output.stderr)
            ),
            ProbeOutcome::Nested
        );
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn the_real_probe_outside_any_sandbox_is_clear_and_inside_one_is_nested() {
        // Agents run `cargo test` inside hb, so either answer is right for this process.
        let outcome = assert_ok!(probe());
        assert!(matches!(
            outcome,
            ProbeOutcome::Clear | ProbeOutcome::Nested
        ));
        assert_eq!(is_nested(), outcome == ProbeOutcome::Nested);
    }
}
