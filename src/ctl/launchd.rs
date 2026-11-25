// ABOUTME: Projects `launchctl print` output down to state, pid, runs and last exit code, and nothing else.
// ABOUTME: Structural: only a field at the job block's own indent counts, so a job environment entry named `pid` or `state` cannot leak or spoof.
//! launchd status (hb-ghd.8.1).
//!
//! `launchctl print gui/<uid>/<label>` lists the job's environment variables, which can hold
//! secrets. Nothing from that text reaches the agent except the four fields below, taken from the
//! one place they live: directly inside the job's top-level block, one tab in. Anything else, or
//! a shape this function does not recognise, is an error that carries no part of the text.

use snafu::Snafu;

/// What the agent is told about a job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// `running`, `not running` or another short state word launchd uses.
    pub state: String,
    /// The process, when there is one.
    pub pid: Option<u32>,
    /// How many times it has run.
    pub runs: Option<u32>,
    /// `(never exited)` or the code.
    pub last_exit: Option<String>,
}

/// Why the text was not projected. No variant holds any of the text.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatusError {
    /// Not a single job block of the expected shape.
    #[snafu(display("launchctl print output was not in a recognised form"))]
    Unrecognised,
    /// A field was present but not in a form that can be shown safely.
    #[snafu(display("launchctl print field {field} was not in a recognised form"))]
    Field {
        /// Which field (a fixed name).
        field: &'static str,
    },
}

/// The widest run of characters a state or exit-code value may have.
const MAX_VALUE: usize = 32;

fn word(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_VALUE
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'(' | b')' | b'-' | b'_'))
}

/// Reads the four fields from the one top-level block of `launchctl print` output.
///
/// # Errors
/// [`StatusError`] if the text is not one `<target> = {` ... `}` block, if a field is repeated, or
/// if a field value is not a short plain word or number.
pub fn project(text: &str) -> Result<Status, StatusError> {
    let mut lines = text.lines();
    let head = lines.next().ok_or(StatusError::Unrecognised)?;
    if !head.ends_with(" = {") || head.starts_with(char::is_whitespace) {
        return Err(StatusError::Unrecognised);
    }
    let mut state = None;
    let mut pid = None;
    let mut runs = None;
    let mut last_exit = None;
    let mut closed = false;
    for line in lines {
        if closed {
            if line.trim().is_empty() {
                continue;
            }
            return Err(StatusError::Unrecognised);
        }
        if line == "}" {
            closed = true;
            continue;
        }
        // Only a field exactly one tab deep belongs to the job; deeper lines are nested blocks.
        let Some(field) = line
            .strip_prefix('\t')
            .filter(|f| !f.starts_with(['\t', ' ']))
        else {
            continue;
        };
        let Some((key, value)) = field.split_once(" = ") else {
            continue;
        };
        match key {
            "state" => set(&mut state, "state", value, |v| {
                word(v).then(|| v.to_owned())
            })?,
            "pid" => set(&mut pid, "pid", value, |v| v.parse::<u32>().ok())?,
            "runs" => set(&mut runs, "runs", value, |v| v.parse::<u32>().ok())?,
            "last exit code" => {
                set(&mut last_exit, "last exit code", value, |v| {
                    word(v).then(|| v.to_owned())
                })?;
            }
            _ => {}
        }
    }
    if !closed {
        return Err(StatusError::Unrecognised);
    }
    Ok(Status {
        state: state.ok_or(StatusError::Field { field: "state" })?,
        pid,
        runs,
        last_exit,
    })
}

fn set<T>(
    slot: &mut Option<T>,
    field: &'static str,
    value: &str,
    parse: impl Fn(&str) -> Option<T>,
) -> Result<(), StatusError> {
    if slot.is_some() {
        return Err(StatusError::Field { field });
    }
    *slot = Some(parse(value).ok_or(StatusError::Field { field })?);
    Ok(())
}

impl Status {
    /// The lines shown to the agent.
    #[must_use]
    pub fn render(&self) -> String {
        let mut out = format!("state: {}\n", self.state);
        if let Some(pid) = self.pid {
            out.push_str(&format!("pid: {pid}\n"));
        }
        if let Some(runs) = self.runs {
            out.push_str(&format!("runs: {runs}\n"));
        }
        if let Some(code) = &self.last_exit {
            out.push_str(&format!("last exit code: {code}\n"));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    const RUNNING: &str = include_str!("../../tests/golden/launchctl/print_running.txt");
    const STOPPED: &str = include_str!("../../tests/golden/launchctl/print_stopped.txt");

    #[test]
    fn test_a_real_running_job_is_projected_to_its_own_fields_not_the_lookalikes_in_its_environment()
     {
        // Captured from macOS: the job's environment holds `pid`, `runs`, `state` and a secret.
        assert!(RUNNING.contains("pid => 99999") && RUNNING.contains("SECRET_TOKEN => shh-secret"));
        let status = assert_ok!(project(RUNNING));
        assert_eq!(
            status,
            Status {
                state: "running".into(),
                pid: Some(66031),
                runs: Some(1),
                last_exit: Some("(never exited)".into()),
            }
        );
        let shown = status.render();
        for leaked in [
            "99999",
            "shh-secret",
            "SECRET",
            "FAKE-STATE",
            "SSH_AUTH_SOCK",
            "/bin/sh",
            "plist",
        ] {
            assert!(!shown.contains(leaked), "{leaked} in {shown}");
        }
    }

    #[test]
    fn test_a_real_stopped_job_has_no_pid_and_still_shows_its_state() {
        let status = assert_ok!(project(STOPPED));
        assert_eq!(status.state, "not running");
        assert_eq!(status.pid, None);
        assert_eq!(status.runs, Some(1));
        assert_eq!(status.render(), "state: not running\nruns: 1\n");
    }

    #[test]
    fn test_a_repeated_top_level_field_or_a_hostile_value_is_an_error_with_no_text_in_it() {
        let doubled = RUNNING.replace("\tpid = 66031\n", "\tpid = 66031\n\tpid = 2\n");
        assert_eq!(
            assert_err!(project(&doubled)),
            StatusError::Field { field: "pid" }
        );
        let hostile = RUNNING.replace("state = running", "state = running; echo SECRET-LEAK");
        let err = assert_err!(project(&hostile));
        assert_eq!(err, StatusError::Field { field: "state" });
        assert!(!err.to_string().contains("SECRET-LEAK"));
        let escape = RUNNING.replace("state = running", "state = \u{1b}[2Jrunning");
        assert_err!(project(&escape));
    }

    #[test]
    fn test_unrecognised_shapes_are_refused_without_echoing_anything() {
        for bad in [
            "",
            "state = running",
            "x = {\n\tstate = running\n",
            "x = {\n\tpid = 1\n}\n",
            "x = {\n\tstate = running\n}\nextra\n",
            "  x = {\n}\n",
        ] {
            let err = assert_err!(project(bad), "{bad:?}");
            assert!(!err.to_string().contains("running"));
        }
        // a nested block with the field names but no real field is not a match
        let only_nested = "x = {\n\tenvironment = {\n\t\tstate = running\n\t}\n}\n";
        assert_eq!(
            assert_err!(project(only_nested)),
            StatusError::Field { field: "state" }
        );
    }
}
