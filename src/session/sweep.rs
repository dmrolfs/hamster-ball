// ABOUTME: The teardown sweep: finds leftover processes by launch token or by the session directory (hb-caj).
// ABOUTME: Candidates only; each is re-checked by identity before any signal, and a sweep never proves cleanup finished.
//! Recovery sweeps for processes the tracker missed.
//!
//! macOS hides the environment of Apple's own binaries, and a process can leave the session
//! directory, so a sweep can find some leftovers and prove nothing. [`Sweep`] results are
//! candidates, never evidence that cleanup is complete.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use snafu::{ResultExt, Snafu};

/// The only `ps` the sweep runs: the system's, by absolute path.
const PS: &str = "/bin/ps";
/// The only `lsof` the sweep runs.
const LSOF: &str = "/usr/sbin/lsof";
/// The most `ps` output the sweep reads. A longer listing is an error, not a truncated answer.
const MAX_OUTPUT: u64 = 8 * 1024 * 1024;
/// How long one `ps` may run.
/// Longest any one command runs, whatever budget the caller gives the whole sweep.
const DEADLINE: Duration = Duration::from_secs(5);

/// The name of the variable that carries a run's token into the agent's environment.
pub(super) const TOKEN_VAR: &str = super::env::LAUNCH_TOKEN_VAR;

/// A random value that marks one run's processes. Anyone of the same user can read it from a
/// process listing, so it is a way to find leftovers, never proof that a process is trustworthy.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct LaunchToken(String);

impl LaunchToken {
    /// 16 random bytes from the system, as hex.
    pub(super) fn generate() -> io::Result<Self> {
        let mut bytes = [0u8; 16];
        File::open("/dev/urandom")?.read_exact(&mut bytes)?;
        Ok(Self(bytes.iter().fold(
            String::from("hb1-"),
            |mut hex, b| {
                hex.push_str(&format!("{b:02x}"));
                hex
            },
        )))
    }

    /// Reads a token back from its value, as the guard receives it. Only the exact shape this
    /// module generates is accepted, so a hostile line cannot widen what the sweep matches.
    pub(super) fn parse(value: &str) -> Option<Self> {
        let hex = value.strip_prefix("hb1-")?;
        (hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| Self(value.to_owned()))
    }

    /// The `NAME=value` entry a process holds in its environment.
    pub(super) fn entry(&self) -> String {
        format!("{TOKEN_VAR}={}", self.0)
    }

    /// The value alone, for the child's environment.
    pub(super) fn value(&self) -> &str {
        &self.0
    }
}

/// Never printed: a token in a log would let it reach an argument list.
impl std::fmt::Debug for LaunchToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LaunchToken(..)")
    }
}

/// Why a listing could not be taken. A failed listing is never an empty one.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub(super) enum SweepError {
    /// The program could not be started.
    #[snafu(display("{program} could not be started"))]
    Start {
        /// Which program.
        program: &'static str,
        /// The underlying error.
        source: io::Error,
    },

    /// The program's output could not be read.
    #[snafu(display("the output of {program} could not be read"))]
    Read {
        /// Which program.
        program: &'static str,
        /// The underlying error.
        source: io::Error,
    },

    /// The program ran past its deadline and was ended.
    #[snafu(display("{program} did not finish in time"))]
    Deadline {
        /// Which program.
        program: &'static str,
    },

    /// The program printed more than the cap, so the listing would be incomplete.
    #[snafu(display("{program} printed more than the sweep will read"))]
    TooLarge {
        /// Which program.
        program: &'static str,
    },

    /// The program failed, or reported trouble that leaves its answer incomplete.
    #[snafu(display("{program} did not give a complete answer"))]
    Incomplete {
        /// Which program.
        program: &'static str,
    },

    /// The program printed something that is not what it should print.
    #[snafu(display("{program} printed output that is not valid"))]
    Malformed {
        /// Which program.
        program: &'static str,
    },

    /// A directory the sweep was asked about could not be checked.
    #[snafu(display("the directory to look in could not be checked"))]
    Directory {
        /// The underlying error.
        source: io::Error,
    },
}

/// What a bounded run produced.
struct Ran {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

/// Longest stderr kept: enough to know whether the program complained, never a flood.
const MAX_STDERR: u64 = 64 * 1024;
/// How long after a kill the sweep waits for the program and its pipes before abandoning them.
const REAP: Duration = Duration::from_millis(500);

/// Runs `program` with `args`, never longer than the deadline and never reading more than the cap.
/// Every wait is bounded, including the wait after a kill: a program stuck in the kernel is
/// abandoned (it is the guard's own child, and the guard is about to exit) rather than waited on.
fn run_bounded(program: &'static str, args: &[&str], by: Instant) -> Result<Ran, SweepError> {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().context(StartSnafu { program })?;
    let (Some(out), Some(err)) = (child.stdout.take(), child.stderr.take()) else {
        return IncompleteSnafu { program }.fail();
    };
    // The readers run on their own threads so a stalled child cannot hold the deadline hostage.
    let stdout = thread::spawn(move || read_capped(out, MAX_OUTPUT));
    let stderr = thread::spawn(move || read_capped(err, MAX_STDERR));
    let end = by.min(Instant::now() + DEADLINE);
    let status = loop {
        if let Some(status) = child.try_wait().context(ReadSnafu { program })? {
            break status;
        }
        if Instant::now() >= end {
            let _ = child.kill();
            reap(&mut child);
            return DeadlineSnafu { program }.fail();
        }
        thread::sleep(Duration::from_millis(5));
    };
    let stdout = finish(stdout).context(ReadSnafu { program })?;
    let stderr = finish(stderr).context(ReadSnafu { program })?;
    if u64::try_from(stdout.len()).unwrap_or(u64::MAX) > MAX_OUTPUT {
        return TooLargeSnafu { program }.fail();
    }
    Ok(Ran {
        code: status.code(),
        stdout: String::from_utf8(stdout).map_err(|_| SweepError::Malformed { program })?,
        // Only whether it complained matters, so lossy text is fine.
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

/// Reads up to `cap` bytes, plus one so an over-long stream can be told from one of exactly `cap`.
fn read_capped(source: impl Read, cap: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source.take(cap + 1).read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Joins a reader thread, giving up after [`REAP`] rather than waiting on a pipe something else holds.
fn finish(reader: thread::JoinHandle<io::Result<Vec<u8>>>) -> io::Result<Vec<u8>> {
    let end = Instant::now() + REAP;
    while !reader.is_finished() {
        if Instant::now() >= end {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the reader did not finish",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
    reader
        .join()
        .unwrap_or_else(|_| Err(io::Error::other("the reader panicked")))
}

/// Waits briefly for a killed child; a child stuck in the kernel is left behind.
fn reap(child: &mut std::process::Child) {
    let end = Instant::now() + REAP;
    while Instant::now() < end {
        if matches!(child.try_wait(), Ok(Some(_))) {
            return;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

/// One listing from `ps`, with the environment too when `with_env` is set.
///
/// # Errors
/// [`SweepError`] for every way the listing can be incomplete.
pub(super) fn listing(with_env: bool, by: Instant) -> Result<String, SweepError> {
    let flags = if with_env { "-Eaxww" } else { "-axww" };
    let ran = run_bounded(PS, &[flags, "-o", "pid=,command="], by)?;
    if ran.code == Some(0) {
        Ok(ran.stdout)
    } else {
        IncompleteSnafu { program: PS }.fail()
    }
}

/// The processes with a working directory or an open file under `dir`.
///
/// `lsof` exits 1 when nothing matches. A complaint on stderr with no output is an incomplete answer,
/// not "nothing there". Pids it did print are kept even beside a complaint, since a partial list is
/// still a list of candidates. A line that is not a number is an error, not skipped.
///
/// Measured limit (macOS 15.7.7): an unreadable subdirectory makes `lsof` exit 1 with no output and
/// no complaint, so a leftover that holds only a file inside one is not found and cannot be told
/// apart from "nothing there". The per-run directory is created by `hb` and private to the user, so
/// this needs the agent to make a subdirectory unreadable itself; it is a documented residual.
///
/// # Errors
/// [`SweepError`] for every way the answer can be incomplete.
pub(super) fn holders_of(dir: &std::path::Path, by: Instant) -> Result<Vec<i32>, SweepError> {
    // `lsof` answers a missing directory exactly like an empty one, so a directory that has
    // vanished would read as "nothing left". Say so instead.
    std::fs::metadata(dir).context(DirectorySnafu)?;
    let dir = dir.to_string_lossy();
    let ran = run_bounded(LSOF, &["-t", "+D", &dir], by)?;
    if !matches!(ran.code, Some(0 | 1)) {
        return IncompleteSnafu { program: LSOF }.fail();
    }
    let pids = ran
        .stdout
        .lines()
        .map(|line| line.trim().parse::<i32>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SweepError::Malformed { program: LSOF })?;
    if pids.is_empty() && !ran.stderr.trim().is_empty() {
        return IncompleteSnafu { program: LSOF }.fail();
    }
    Ok(pids)
}

/// Nominates the processes whose environment may hold `token`, from two `ps` listings.
///
/// These are candidates, not owners: the text cannot tell an environment entry from an argument that
/// shrank between the two reads, or from a value containing a space. Confirm each with
/// [`holds_entry`] before acting on it.
///
/// `ps -E` prints the arguments followed by the environment on one line; plain `ps` prints the
/// arguments alone. When the `-E` line starts with the plain line, the rest is the environment, so
/// a token that appears only in the arguments does not match. A line that does not start with its
/// plain line (a process that changed its own arguments between the two reads) is reported in
/// `unreadable`, never guessed at.
///
/// `token` is the full `NAME=value` entry, matched as a whole word.
#[must_use]
pub(super) fn owned_by_token(with_env: &str, plain: &str, token: &str) -> Matches {
    let plain = lines_by_pid(plain);
    let mut found = Matches::default();
    for (pid, line) in lines_by_pid(with_env) {
        let Some(args) = plain.get(&pid) else {
            continue;
        };
        let Some(environment) = line.strip_prefix(args.as_str()) else {
            found.unreadable.push(pid);
            continue;
        };
        if contains_word(environment, token) {
            found.pids.push(pid);
        }
    }
    found
}

/// Whether `pid` really holds `entry` (`NAME=value`) as one whole entry of its environment.
///
/// `ps` text cannot say: it joins arguments and environment, so a token in an argument, or one
/// inside a value that contains a space, reads the same as a real entry. The kernel's own block is
/// NUL-separated, and this reads it that way. A process whose environment cannot be read (another
/// user's, or one macOS hides, such as Apple's own tools) is `false`, never a guess.
#[must_use]
pub(super) fn holds_entry(pid: i32, entry: &str) -> bool {
    let Ok(raw) = u32::try_from(pid) else {
        return false;
    };
    let pid = sysinfo::Pid::from_u32(raw);
    let mut system = sysinfo::System::new();
    let kind = sysinfo::ProcessRefreshKind::new().with_environ(sysinfo::UpdateKind::Always);
    system.refresh_process_specifics(pid, kind);
    system
        .process(pid)
        .is_some_and(|process| process.environ().iter().any(|e| e == entry))
}

/// The processes a token sweep found, and those it could not read.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Matches {
    /// Processes whose environment holds the token.
    pub pids: Vec<i32>,
    /// Processes whose two lines disagreed, so nothing can be said about them.
    pub unreadable: Vec<i32>,
}

/// `pid command...` lines as a map; lines that do not start with a number are ignored.
fn lines_by_pid(text: &str) -> BTreeMap<i32, String> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid, rest) = line.split_once(char::is_whitespace)?;
            Some((pid.parse().ok()?, rest.to_owned()))
        })
        .collect()
}

/// Whether `word` appears in `text` bounded by a space or the ends of the text.
fn contains_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back();
        let after = text[at + word.len()..].chars().next();
        before.is_none_or(|c| c == ' ') && after.is_none_or(|c| c == ' ')
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::{assert_eq, assert_ne};
    use std::{thread, time::Duration};

    /// A budget that is never the limit in these tests.
    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    /// A budget that has already run out ends the command at once with a deadline error, rather than
    /// letting it run to its own 5 s limit.
    #[test]
    fn a_sweep_command_stops_at_the_budget_it_is_given() {
        let started = Instant::now();
        let err = claims::assert_err!(listing(true, Instant::now()));
        assert!(matches!(err, SweepError::Deadline { .. }), "{err:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn a_real_listing_has_this_test_process_in_it() {
        let me = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        let plain = assert_ok!(listing(false, soon()));
        let with_env = assert_ok!(listing(true, soon()));
        assert!(lines_by_pid(&plain).contains_key(&me));
        assert!(lines_by_pid(&with_env).contains_key(&me));
    }

    #[test]
    fn a_token_is_random_hex_and_never_printed() {
        let first = assert_ok!(LaunchToken::generate());
        let second = assert_ok!(LaunchToken::generate());
        assert_ne!(first, second);
        assert!(first.value().starts_with("hb1-") && first.value().len() == 4 + 32);
        assert!(first.value()[4..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(first.entry(), format!("HB_LAUNCH_TOKEN={}", first.value()));
        assert!(!format!("{first:?}").contains(first.value()));
    }

    #[test]
    fn holders_of_a_directory_are_found_and_an_empty_one_has_none() {
        use std::os::unix::process::CommandExt;
        let dir = assert_ok!(tempfile::tempdir());
        let real = assert_ok!(dir.path().canonicalize());
        assert_eq!(assert_ok!(holders_of(&real, soon())), Vec::<i32>::new());
        let mut holder = assert_ok!(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .current_dir(&real)
                .process_group(0)
                .spawn()
        );
        let pid = i32::try_from(holder.id()).unwrap_or(i32::MAX);
        assert!(assert_ok!(holders_of(&real, soon())).contains(&pid));
        let _ = holder.kill();
        let _ = holder.wait();
        assert_eq!(assert_ok!(holders_of(&real, soon())), Vec::<i32>::new());
    }

    /// Names the program that failed, where it used to say `ps` for everything.
    #[test]
    fn an_lsof_failure_names_lsof_and_a_ps_failure_names_ps() {
        let lsof = SweepError::Incomplete { program: LSOF };
        let ps = SweepError::Incomplete { program: PS };
        assert!(lsof.to_string().contains("lsof"), "{lsof}");
        assert!(!lsof.to_string().contains("/bin/ps"), "{lsof}");
        assert!(ps.to_string().contains("/bin/ps"), "{ps}");
    }

    #[test]
    fn a_missing_directory_is_an_error_not_an_empty_answer() {
        let result = holders_of(std::path::Path::new("/no/such/dir/anywhere"), soon());
        assert!(result.is_err(), "{result:?}");
    }

    #[test]
    fn only_the_exact_token_shape_is_accepted_back() {
        let token = assert_ok!(LaunchToken::generate());
        assert_eq!(LaunchToken::parse(token.value()), Some(token));
        for bad in [
            "",
            "hb1-",
            "hb1-zz",
            "hb2-00112233445566778899aabbccddeeff",
            "hb1-00112233445566778899aabbccddeef",
            "hb1-00112233445566778899aabbccddeeff0",
            "hb1-00112233445566778899aabbccddeeg0",
            "hb1-00112233445566778899aabbccddeeff HOME=/",
        ] {
            assert_eq!(LaunchToken::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn sweep_errors_follow_the_display_convention() {
        crate::error::conventions::assert_display_excludes_sources(&SweepError::Read {
            program: PS,
            source: io::Error::other("cause"),
        });
    }

    const TOKEN: &str = "HB_LAUNCH_TOKEN=hb1-abc123";

    fn found(with_env: &str, plain: &str) -> Matches {
        owned_by_token(with_env, plain, TOKEN)
    }

    #[test]
    fn a_token_in_the_environment_matches() {
        let matches = found(
            "10 /bin/tool arg HOME=/h HB_LAUNCH_TOKEN=hb1-abc123 PATH=/bin",
            "10 /bin/tool arg",
        );
        assert_eq!(matches.pids, vec![10]);
    }

    #[test]
    fn a_token_only_in_the_arguments_does_not_match() {
        let matches = found(
            "11 /bin/tool HB_LAUNCH_TOKEN=hb1-abc123 HOME=/h",
            "11 /bin/tool HB_LAUNCH_TOKEN=hb1-abc123",
        );
        assert_eq!(matches, Matches::default());
    }

    #[test]
    fn a_token_in_both_places_matches_through_the_environment() {
        let matches = found(
            "12 /bin/tool HB_LAUNCH_TOKEN=hb1-abc123 HB_LAUNCH_TOKEN=hb1-abc123",
            "12 /bin/tool HB_LAUNCH_TOKEN=hb1-abc123",
        );
        assert_eq!(matches.pids, vec![12]);
    }

    #[test]
    fn a_token_inside_another_variable_or_a_longer_value_does_not_match() {
        for environment in [
            "FOO=HB_LAUNCH_TOKEN=hb1-abc123",
            "HB_LAUNCH_TOKEN=hb1-abc123zz",
            "XHB_LAUNCH_TOKEN=hb1-abc123",
        ] {
            let matches = found(&format!("13 /bin/tool {environment}"), "13 /bin/tool");
            assert_eq!(matches, Matches::default(), "{environment}");
        }
    }

    #[test]
    fn a_process_whose_lines_disagree_is_unreadable_not_guessed() {
        let matches = found("14 /bin/other HB_LAUNCH_TOKEN=hb1-abc123", "14 /bin/tool");
        assert_eq!(matches.pids, Vec::<i32>::new());
        assert_eq!(matches.unreadable, vec![14]);
    }

    #[test]
    fn a_process_that_appears_in_only_one_listing_is_ignored() {
        let matches = found("15 /bin/tool HB_LAUNCH_TOKEN=hb1-abc123", "16 /bin/tool");
        assert_eq!(matches, Matches::default());
    }

    /// The reviewer's counterexamples. The text cannot tell these from a real environment entry, so
    /// the listing only nominates them; `holds_entry` is what decides.
    #[test]
    fn text_alone_nominates_an_argument_that_shrank_and_a_value_with_a_space() {
        assert_eq!(
            found("10 tool HB_LAUNCH_TOKEN=hb1-abc123", "10 tool").pids,
            vec![10]
        );
        assert_eq!(
            found("11 tool OTHER=x HB_LAUNCH_TOKEN=hb1-abc123", "11 tool").pids,
            vec![11]
        );
    }

    fn homebrew_python() -> Option<&'static str> {
        const PYTHON: &str = "/opt/homebrew/bin/python3";
        std::path::Path::new(PYTHON).exists().then_some(PYTHON)
    }

    fn python_with(args: &[&str], env: &[(&str, &str)]) -> std::process::Child {
        let python = homebrew_python().unwrap_or("/usr/bin/python3");
        assert_ok!(
            std::process::Command::new(python)
                .args(["-c", "import time; time.sleep(30)"])
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .envs(env.iter().copied())
                .spawn()
        )
    }

    fn settle() {
        thread::sleep(Duration::from_millis(400));
    }

    #[test]
    fn an_entry_is_held_only_as_a_whole_entry_of_the_environment() {
        let entry = "HB_LAUNCH_TOKEN=hb1-abc123";
        let mut holder = python_with(&[], &[("HB_LAUNCH_TOKEN", "hb1-abc123")]);
        let mut in_argument = python_with(&[entry], &[]);
        let mut in_other_variable = python_with(&[], &[("FOO", entry)]);
        // The decoy that fooled the text: a value containing a space and then the entry.
        let mut spaced_value = python_with(&[], &[("FOO", "x HB_LAUNCH_TOKEN=hb1-abc123")]);
        let mut longer_value = python_with(&[], &[("HB_LAUNCH_TOKEN", "hb1-abc123zz")]);
        settle();
        let pid = |c: &std::process::Child| i32::try_from(c.id()).unwrap_or(i32::MAX);
        assert!(holds_entry(pid(&holder), entry));
        assert!(!holds_entry(pid(&in_argument), entry));
        assert!(!holds_entry(pid(&in_other_variable), entry));
        assert!(!holds_entry(pid(&spaced_value), entry));
        assert!(!holds_entry(pid(&longer_value), entry));
        assert!(!holds_entry(999_990, entry));
        assert!(!holds_entry(-1, entry));
        for child in [
            &mut holder,
            &mut in_argument,
            &mut in_other_variable,
            &mut spaced_value,
            &mut longer_value,
        ] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn a_process_whose_environment_macos_hides_is_not_confirmed() {
        let entry = "HB_LAUNCH_TOKEN=hb1-abc123";
        let mut apple = assert_ok!(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .env_clear()
                .env("HB_LAUNCH_TOKEN", "hb1-abc123")
                .spawn()
        );
        settle();
        assert!(!holds_entry(
            i32::try_from(apple.id()).unwrap_or(i32::MAX),
            entry
        ));
        let _ = apple.kill();
        let _ = apple.wait();
    }

    #[test]
    fn a_process_with_no_arguments_text_still_matches_by_its_environment() {
        let matches = found("17 HB_LAUNCH_TOKEN=hb1-abc123", "17 ");
        assert_eq!(matches.pids, vec![17]);
    }
}
