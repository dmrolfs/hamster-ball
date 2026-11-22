// ABOUTME: --log-denials: a per-run tag in the profile, a `log stream` filtered by it, and the lines it yields.
// ABOUTME: The parsing and collecting are pure and tested on real log lines; the process part is tested against the real log.
//! Showing what the profile denied (design 13, hb-ghd.2.3b).
//!
//! The profile's `(deny default (with message "hb-<tag>"))` makes the kernel log every denial of
//! this run with the tag on a second line, so `log stream` can be told to show only those.
//! The log is not complete (about 36 of 40 for Python and 38 of 40 for Node were seen), so these
//! lines are hints for a person to read, never input to a rule generator.

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{self, BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use snafu::{ResultExt, Snafu};

use crate::seatbelt::LogTag;

/// `log` by absolute path: the shell has a builtin of the same name.
pub const LOG: &str = "/usr/bin/log";
/// The first line `log stream` prints, which shows it is listening.
const READY_PREFIX: &str = "Filtering the log data";
/// How long to wait for that line before going on without it.
const READY_TIMEOUT: Duration = Duration::from_secs(3);
/// After the child ends, how long the stream must be silent before it is stopped.
const QUIET: Duration = Duration::from_millis(300);
/// The most time spent waiting for that silence.
const MAX_TAIL: Duration = Duration::from_secs(2);
/// The most lines kept when collecting; the rest are counted.
pub const MAX_COLLECTED: usize = 1000;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A fresh tag for this run: 16 lowercase hexadecimal digits.
#[must_use]
pub fn generate_tag() -> LogTag {
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    hasher.write_u32(std::process::id());
    LogTag::from_bits(hasher.finish())
}

/// The `log stream` predicate that selects this run's denials.
///
/// The tag is hexadecimal and made by `hb`, so it cannot break out of the quoted string.
#[must_use]
pub fn predicate(tag: &LogTag) -> String {
    format!(
        "sender == \"Sandbox\" AND eventMessage CONTAINS \"hb-{}\"",
        tag.as_str()
    )
}

/// What one line of `log stream --style compact` is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Line {
    /// The first line: the stream is listening.
    Ready,
    /// A denial, as `cat(26029) deny(1) file-read-data /path`.
    Denial(String),
    /// The message line that follows a denial: empty for the default rule, or a label such as `floor`.
    Label(String),
    /// Anything else (the column header, blank lines).
    Other,
}

/// Classifies one output line of the stream for `tag`.
#[must_use]
pub fn parse_line(line: &str, tag: &LogTag) -> Line {
    let line = line.trim_end();
    if line.starts_with(READY_PREFIX) {
        return Line::Ready;
    }
    if let Some((_, rest)) = line.split_once("Sandbox: ") {
        return Line::Denial(rest.trim().to_owned());
    }
    let marker = format!("hb-{}", tag.as_str());
    if let Some(rest) = line.strip_prefix(&marker) {
        return Line::Label(rest.trim().to_owned());
    }
    Line::Other
}

/// Joins each denial with the label line that follows it, which names the kind of rule.
#[derive(Debug, Default)]
struct Pairer {
    pending: Option<String>,
}

impl Pairer {
    /// Takes a line; returns the denials that are now complete.
    fn push(&mut self, line: Line) -> Option<String> {
        match line {
            Line::Denial(text) => self.pending.replace(text),
            Line::Label(label) => {
                let text = self.pending.take()?;
                Some(if label.is_empty() {
                    text
                } else {
                    format!("{text} [{label}]")
                })
            }
            Line::Ready | Line::Other => None,
        }
    }

    /// The denial still waiting for a label, at the end of the stream.
    fn finish(&mut self) -> Option<String> {
        self.pending.take()
    }
}

/// Collects denials up to a limit and counts the rest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Collector {
    lines: Vec<String>,
    dropped: usize,
}

impl Collector {
    /// Adds a denial.
    pub fn add(&mut self, text: String) {
        if self.lines.len() >= MAX_COLLECTED {
            self.dropped += 1;
        } else {
            self.lines.push(text);
        }
    }

    /// The denials collected, and how many more there were.
    #[must_use]
    pub fn into_parts(self) -> (Vec<String>, usize) {
        (self.lines, self.dropped)
    }
}

/// Where denial lines go.
#[derive(Clone)]
#[non_exhaustive]
pub enum DenialSink {
    /// Keep them (up to [`MAX_COLLECTED`]) and return them in the outcome.
    Collect,
    /// Hand each to this function as it is complete. Nothing is kept.
    Stream(Arc<dyn Fn(&str) + Send + Sync>),
}

impl std::fmt::Debug for DenialSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Collect => f.write_str("Collect"),
            Self::Stream(_) => f.write_str("Stream(..)"),
        }
    }
}

/// What a finished stream saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Denials {
    /// The denials kept, in the order they were logged.
    pub lines: Vec<String>,
    /// How many more there were past the limit.
    pub dropped: usize,
}

/// Why the denial stream could not be started.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum DenialsError {
    /// `log stream` could not be started.
    #[snafu(display("{LOG} could not be started"))]
    Spawn {
        /// The underlying error.
        source: io::Error,
    },
}

/// A running `log stream` for one run.
pub struct LogStream {
    process: Child,
    reader: JoinHandle<()>,
    last_line: Arc<Mutex<Instant>>,
    kept: Arc<Mutex<Collector>>,
}

impl LogStream {
    /// Starts the stream and waits until it is listening (or three seconds pass), so a
    /// denial in the first moments of the child is not missed.
    ///
    /// # Errors
    /// [`DenialsError::Spawn`] if `log` cannot be started.
    pub fn start(tag: &LogTag, sink: DenialSink) -> Result<Self, DenialsError> {
        let mut process = Command::new(LOG)
            .args(["stream", "--style", "compact", "--predicate"])
            .arg(predicate(tag))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context(SpawnSnafu)?;
        let stdout = process.stdout.take();
        let last_line = Arc::new(Mutex::new(Instant::now()));
        let kept = Arc::new(Mutex::new(Collector::default()));
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let reader = {
            let (tag, last_line, kept) = (tag.clone(), Arc::clone(&last_line), Arc::clone(&kept));
            thread::spawn(move || read_stream(stdout, &tag, &sink, &last_line, &kept, &ready_tx))
        };
        let _ = ready_rx.recv_timeout(READY_TIMEOUT);
        Ok(Self {
            process,
            reader,
            last_line,
            kept,
        })
    }

    /// Waits for the stream to go quiet (the log lags the event a little), stops it, and returns
    /// what it kept.
    #[must_use]
    pub fn finish(mut self) -> Denials {
        wait_until_quiet(&self.last_line, QUIET, MAX_TAIL);
        let _ = self.process.kill();
        let _ = self.process.wait();
        let _ = self.reader.join();
        let collector = self.kept.lock().map(|k| k.clone()).unwrap_or_default();
        let (lines, dropped) = collector.into_parts();
        Denials { lines, dropped }
    }
}

/// Waits until no line has arrived for `quiet`, or `max` has passed, whichever is first.
fn wait_until_quiet(last_line: &Mutex<Instant>, quiet: Duration, max: Duration) {
    let started = Instant::now();
    while started.elapsed() < max {
        let quiet_for = last_line.lock().map_or(quiet, |last| last.elapsed());
        if quiet_for >= quiet {
            return;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

/// The reader thread: parse each line, pair it, and give the complete denials to the sink.
fn read_stream<R: io::Read>(
    stdout: Option<R>,
    tag: &LogTag,
    sink: &DenialSink,
    last_line: &Mutex<Instant>,
    kept: &Mutex<Collector>,
    ready: &std::sync::mpsc::Sender<()>,
) {
    let Some(stdout) = stdout else {
        return;
    };
    let mut pairer = Pairer::default();
    let emit = |text: String| match sink {
        DenialSink::Collect => {
            if let Ok(mut kept) = kept.lock() {
                kept.add(text);
            }
        }
        DenialSink::Stream(write) => write(&text),
    };
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if let Ok(mut last) = last_line.lock() {
            *last = Instant::now();
        }
        let parsed = parse_line(&line, tag);
        if parsed == Line::Ready {
            let _ = ready.send(());
        }
        if let Some(text) = pairer.push(parsed) {
            emit(text);
        }
    }
    if let Some(text) = pairer.finish() {
        emit(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn tag() -> LogTag {
        LogTag::from_bits(0x588b_cf18_6bc2_0001)
    }

    // Lines copied from a real `log stream --style compact` run (macOS 15.7).
    const HEADER: &str = "Filtering the log data using \"sender == \"Sandbox\" AND composedMessage CONTAINS \"hb-588bcf186bc2\"\"";
    const COLUMNS: &str = "Timestamp               Ty Process[PID:TID]";
    const DENIAL: &str = "2026-11-21 17:14:49.546 E  kernel[0:18cc530] (Sandbox) Sandbox: cat(26029) deny(1) file-read-data /private/tmp/hbl/denied.txt";

    #[test]
    fn the_header_is_ready_and_the_column_line_is_not_a_denial() {
        assert_eq!(parse_line(HEADER, &tag()), Line::Ready);
        assert_eq!(parse_line(COLUMNS, &tag()), Line::Other);
        assert_eq!(parse_line("", &tag()), Line::Other);
    }

    #[test]
    fn a_denial_line_keeps_only_what_follows_the_sandbox_prefix() {
        assert_eq!(
            parse_line(DENIAL, &tag()),
            Line::Denial(
                "cat(26029) deny(1) file-read-data /private/tmp/hbl/denied.txt".to_owned()
            )
        );
    }

    #[test]
    fn the_message_line_is_a_label_only_for_this_runs_tag() {
        let tag = tag();
        assert_eq!(
            parse_line(&format!("hb-{}", tag.as_str()), &tag),
            Line::Label(String::new())
        );
        assert_eq!(
            parse_line(&format!("hb-{} floor", tag.as_str()), &tag),
            Line::Label("floor".to_owned())
        );
        assert_eq!(parse_line("hb-ffffffffffffffff floor", &tag), Line::Other);
    }

    #[test]
    fn the_predicate_names_the_sandbox_and_this_runs_tag_only() {
        assert_eq!(
            predicate(&tag()),
            "sender == \"Sandbox\" AND eventMessage CONTAINS \"hb-588bcf186bc20001\""
        );
    }

    #[test]
    fn generated_tags_are_sixteen_hex_digits_and_differ() {
        let (a, b) = (generate_tag(), generate_tag());
        assert!(a != b);
        for tag in [a, b] {
            assert_eq!(tag.as_str().len(), 16);
            assert!(
                tag.as_str()
                    .bytes()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            );
        }
    }

    fn feed(lines: &[Line]) -> Vec<String> {
        let mut pairer = Pairer::default();
        let mut out: Vec<String> = lines
            .iter()
            .filter_map(|l| pairer.push(l.clone()))
            .collect();
        out.extend(pairer.finish());
        out
    }

    fn denial(t: &str) -> Line {
        Line::Denial(t.to_owned())
    }

    fn label(t: &str) -> Line {
        Line::Label(t.to_owned())
    }

    #[test]
    fn a_label_is_attached_to_the_denial_before_it_and_an_empty_one_adds_nothing() {
        assert_eq!(
            feed(&[denial("a"), label("floor"), denial("b"), label("")]),
            vec!["a [floor]", "b"]
        );
    }

    #[test]
    fn a_denial_without_a_label_line_is_still_reported_when_the_next_one_or_the_end_comes() {
        assert_eq!(feed(&[denial("a"), denial("b")]), vec!["a", "b"]);
        assert_eq!(feed(&[denial("a")]), vec!["a"]);
    }

    #[test]
    fn a_label_with_no_denial_and_other_lines_are_dropped() {
        assert_eq!(
            feed(&[label("floor"), Line::Other, Line::Ready]),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_collector_keeps_the_first_thousand_and_counts_the_rest() {
        let mut collector = Collector::default();
        for i in 0..MAX_COLLECTED + 7 {
            collector.add(format!("d{i}"));
        }
        let (lines, dropped) = collector.into_parts();
        assert_eq!(lines.len(), MAX_COLLECTED);
        assert_eq!(lines[0], "d0");
        assert_eq!(dropped, 7);
    }

    #[test]
    fn waiting_for_quiet_returns_at_once_when_nothing_arrived_recently() {
        let last = Mutex::new(Instant::now() - Duration::from_secs(10));
        let started = Instant::now();
        wait_until_quiet(&last, Duration::from_millis(200), Duration::from_secs(5));
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn waiting_for_quiet_waits_out_the_quiet_period_after_the_last_line() {
        let last = Mutex::new(Instant::now());
        let started = Instant::now();
        wait_until_quiet(&last, Duration::from_millis(200), Duration::from_secs(5));
        let took = started.elapsed();
        assert!(took >= Duration::from_millis(190), "{took:?}");
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    #[test]
    fn waiting_for_quiet_gives_up_at_the_maximum_while_lines_keep_coming() {
        let last = Arc::new(Mutex::new(Instant::now()));
        let keep_going = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let feeder = {
            let (last, keep_going) = (Arc::clone(&last), Arc::clone(&keep_going));
            thread::spawn(move || {
                while keep_going.load(Ordering::Relaxed) {
                    if let Ok(mut at) = last.lock() {
                        *at = Instant::now();
                    }
                    thread::sleep(Duration::from_millis(5));
                }
            })
        };
        let started = Instant::now();
        wait_until_quiet(
            &last,
            Duration::from_millis(200),
            Duration::from_millis(500),
        );
        let took = started.elapsed();
        keep_going.store(false, Ordering::Relaxed);
        let _ = feeder.join();
        assert!(took >= Duration::from_millis(450), "{took:?}");
        assert!(took < Duration::from_secs(2), "{took:?}");
    }

    fn read_all(text: &str) -> (Vec<String>, bool) {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let kept = Mutex::new(Collector::default());
        let last = Mutex::new(Instant::now());
        read_stream(
            Some(io::Cursor::new(text.to_owned())),
            &tag(),
            &DenialSink::Collect,
            &last,
            &kept,
            &ready_tx,
        );
        let lines = kept
            .lock()
            .map(|k| k.clone().into_parts().0)
            .unwrap_or_default();
        (lines, ready_rx.try_recv().is_ok())
    }

    #[test]
    fn the_reader_signals_ready_only_on_the_header_line() {
        let (_, ready) = read_all(&format!("{COLUMNS}\n{DENIAL}\n"));
        assert!(!ready, "ready without a header");
        let (_, ready) = read_all(&format!("{HEADER}\n{COLUMNS}\n"));
        assert!(ready);
    }

    #[test]
    fn the_reader_collects_a_denial_with_its_label_and_the_last_one_without_a_label_line() {
        let tag = tag();
        let text = format!(
            "{HEADER}\n{COLUMNS}\n{DENIAL}\nhb-{} floor\n{DENIAL}\n",
            tag.as_str()
        );
        let (lines, _) = read_all(&text);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].ends_with("denied.txt [floor]"), "{lines:?}");
        assert!(lines[1].ends_with("denied.txt"), "{lines:?}");
    }

    #[test]
    fn a_stream_sink_prints_in_debug_without_the_function() {
        let sink = DenialSink::Stream(Arc::new(|_| {}));
        assert_eq!(format!("{sink:?}"), "Stream(..)");
        assert_eq!(format!("{:?}", DenialSink::Collect), "Collect");
    }
}
