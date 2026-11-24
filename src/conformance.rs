// ABOUTME: The opt-in agent conformance harness: runs a real agent CLI under its preset and checks it worked and stayed on its hosts.
// ABOUTME: Pure checks over a run's outcome and proxy events; the environment, the preset and the agent come in as values.
//! Does a preset work with the real agent? (design 13.1, hb-ghd.3.4)
//!
//! Presets are written by hand (denial logs are incomplete, so nothing is generated from them),
//! so each one is proved against the installed agent. [`run_agent`] sets up a throwaway project
//! that extends only `agent/<name>`, runs the agent's one non-interactive question under the real
//! profile and proxy, and returns a [`Verdict`]:
//!
//! - the agent must answer the way its [`Expect`] says (the word `OK`, a served Bedrock
//!   connection, or the same exit status as an unsandboxed run);
//! - every host the agent asked for must be in the allow set in force, that is the preset plus
//!   whatever the person running the check gave in `HB_CONFORMANCE_PROJECT`; a refused connection is
//!   a failure that names the host;
//! - on a failure the verdict carries what the agent printed and every denial, as hints (the
//!   system log is incomplete, so they are hints and never a rule generator's input).
//!
//! The user's own `~/.config/hamster-ball` is not read: the run uses a private user config
//! directory holding `HB_CONFORMANCE_BASE` (default: system trust on), so a result depends on the
//! preset and the files the runner names, not on this machine's configuration. The home
//! directory is the real one, because the agent's login lives there.
//!
//! Everything is opt-in: nothing runs unless `HB_CONFORMANCE=1`, an agent that is not installed is
//! skipped, and so is one without a preset.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snafu::{ResultExt, Snafu};

use crate::config::{BuiltinPresets, LoadRequest, discover, load};
use crate::policy::{CanonicalPath, PresetName};
use crate::proxy::{AuditEvent, AuditSink, Decision};
use crate::session::{
    DenialSink, ExitKind, ProxyTuning, RunError, RunSpec, SessionDir, run as session_run,
};
use crate::system::{Environment, UserConfigDir};

/// Set to `1` to run the conformance checks.
pub const ENABLE_VAR: &str = "HB_CONFORMANCE";
/// A file whose text becomes the private user base config (default: [`DEFAULT_BASE`]).
pub const BASE_VAR: &str = "HB_CONFORMANCE_BASE";
/// A file whose text is appended to the throwaway project's config, for what the preset leaves to
/// the user (a provider host, a loopback port). It must not contain `extends`.
pub const PROJECT_VAR: &str = "HB_CONFORMANCE_PROJECT";
/// How many seconds one agent may take (default 180).
pub const TIMEOUT_VAR: &str = "HB_CONFORMANCE_TIMEOUT";
/// `HB_CONFORMANCE_ARGS_<NAME>` replaces an agent's arguments (`NAME` upper case, `-` as `_`).
pub const ARGS_VAR_PREFIX: &str = "HB_CONFORMANCE_ARGS_";

/// The base config used when none is given: the system trust store on, as on a TLS-inspected network.
pub const DEFAULT_BASE: &str = "[tls]\nsystem_trust = true\n";
/// The default time limit for one agent.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(180);
/// The one question every agent is asked.
pub const QUESTION: &str = "Reply with the single word OK";

/// The private preset that makes the throwaway project writable.
const PROJECT_PRESET: &str = "conformance-project";
/// How many lines of the agent's output a report keeps.
const TAIL_LINES: usize = 25;
/// What the wrapper exits with when the time limit stopped the agent (the code GNU `timeout` uses).
const TIMED_OUT: i32 = 124;

/// Runs the rest of its arguments as a command of its own process group and stops that whole group
/// when the time limit (the first argument, in seconds) runs out: an agent's children would
/// otherwise keep the output pipes open. The exit status is the command's (`128 + n` for a
/// signal), or [`TIMED_OUT`].
const WRAPPER: &str = "my ($limit, @cmd) = @ARGV;\
 my $pid = fork(); die qq(fork: $!) unless defined $pid;\
 if (!$pid) { setpgrp(0, 0); exec @cmd or die qq(exec: $!); }\
 $SIG{ALRM} = sub { kill 'TERM', -$pid; select(undef, undef, undef, 1.0); kill 'KILL', -$pid; exit 124; };\
 alarm $limit; waitpid($pid, 0); my $s = $?; exit(($s & 127) ? 128 + ($s & 127) : ($s >> 8));";

/// What counts as the agent having worked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Exit 0 and this word in what it printed.
    Word(&'static str),
    /// A connection served to a host starting with this prefix, and the word `OK` if the agent
    /// exits 0. A failed exit is not judged: the account may deny the model after the request has
    /// reached the provider through the sandbox, and that is not the preset's fault.
    AllowedConnectionTo(&'static str),
    /// Exit with the same status as the same command run without the sandbox.
    SameExitAsBaseline,
}

/// One agent CLI and how to check it.
#[derive(Debug, Clone, Copy)]
pub struct Agent {
    /// The preset is `agent/<name>`.
    pub name: &'static str,
    /// The program: a name looked up on `PATH`, or an absolute path.
    pub binary: &'static str,
    /// Its arguments for one non-interactive question.
    pub args: &'static [&'static str],
    /// What counts as success.
    pub expect: Expect,
}

/// The agents of design 13 and how each is checked.
pub const AGENTS: [Agent; 4] = [
    Agent {
        name: "claude",
        binary: "claude",
        args: &["-p", QUESTION, "--max-turns", "1"],
        expect: Expect::AllowedConnectionTo("bedrock-runtime."),
    },
    Agent {
        name: "kiro",
        binary: "kiro-cli",
        args: &["chat", "--no-interactive", QUESTION],
        expect: Expect::Word("OK"),
    },
    Agent {
        name: "opencode",
        binary: "opencode",
        args: &["run", QUESTION],
        expect: Expect::SameExitAsBaseline,
    },
    Agent {
        name: "pi",
        binary: "pi",
        args: &[
            "--provider",
            "here",
            "--model",
            "claude-haiku-4-5",
            "-p",
            QUESTION,
        ],
        expect: Expect::Word("OK"),
    },
];

/// What the person running the check asked for.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Whether to run at all.
    pub enabled: bool,
    /// The text of the private user base config.
    pub base_config: String,
    /// Text appended to the project config.
    pub project_extra: String,
    /// The time limit for one agent.
    pub timeout: Duration,
    /// Argument overrides by agent name.
    pub args: Vec<(String, Vec<String>)>,
    /// Adjusts the proxy (for the harness's own tests).
    pub tuning: Option<ProxyTuning>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            enabled: true,
            base_config: DEFAULT_BASE.to_owned(),
            project_extra: String::new(),
            timeout: DEFAULT_TIMEOUT,
            args: Vec::new(),
            tuning: None,
        }
    }
}

/// Why the settings could not be read.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum SettingsError {
    /// A file named by a variable could not be read.
    #[snafu(display("{var} names {}, which cannot be read", path.display()))]
    Unreadable {
        /// The variable.
        var: &'static str,
        /// The file.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// The time limit is not a whole number of seconds from 1.
    #[snafu(display("{TIMEOUT_VAR} must be a whole number of seconds, not {value:?}"))]
    BadTimeout {
        /// What it said.
        value: String,
    },
}

impl Settings {
    /// Reads the settings from variables; `get` answers for a name.
    ///
    /// # Errors
    /// See [`SettingsError`].
    pub fn from_vars(get: impl Fn(&str) -> Option<OsString>) -> Result<Self, SettingsError> {
        let mut settings = Self {
            enabled: get(ENABLE_VAR).is_some_and(|v| v == "1"),
            ..Self::default()
        };
        let read = |var: &'static str| -> Result<Option<String>, SettingsError> {
            get(var)
                .map(|path| {
                    let path = PathBuf::from(path);
                    fs::read_to_string(&path).context(UnreadableSnafu { var, path })
                })
                .transpose()
        };
        if let Some(text) = read(BASE_VAR)? {
            settings.base_config = text;
        }
        if let Some(text) = read(PROJECT_VAR)? {
            settings.project_extra = text;
        }
        if let Some(value) = get(TIMEOUT_VAR) {
            let value = value.to_string_lossy().into_owned();
            let seconds: u64 = value
                .parse()
                .ok()
                .filter(|s| *s > 0)
                .ok_or(SettingsError::BadTimeout { value })?;
            settings.timeout = Duration::from_secs(seconds);
        }
        for agent in AGENTS {
            let var = format!(
                "{ARGS_VAR_PREFIX}{}",
                agent.name.to_ascii_uppercase().replace('-', "_")
            );
            if let Some(words) = get(&var) {
                let words = words
                    .to_string_lossy()
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect();
                settings.args.push((agent.name.to_owned(), words));
            }
        }
        Ok(settings)
    }

    /// Reads the settings from this process's environment.
    ///
    /// # Errors
    /// See [`SettingsError`].
    pub fn from_process() -> Result<Self, SettingsError> {
        Self::from_vars(|name| std::env::var_os(name))
    }
}

/// What a check needs from its surroundings.
#[derive(Clone, Copy)]
pub struct Context<'a> {
    /// The real home, `PATH` and the parent's variables; its working directory is replaced.
    pub env: &'a Environment,
    /// Where `agent/<name>` presets come from.
    pub builtins: &'a dyn BuiltinPresets,
    /// What was asked for.
    pub settings: &'a Settings,
}

/// Why an agent was not checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    /// `HB_CONFORMANCE` is not `1`.
    Disabled,
    /// The program is not on `PATH`.
    NotInstalled(String),
    /// There is no built-in preset `agent/<name>` yet.
    NoPreset(String),
}

/// One way a check failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The throwaway project could not be set up or loaded.
    Setup(String),
    /// The agent ran past the time limit.
    TimedOut(Duration),
    /// The agent did not exit 0.
    Exit(ExitKind),
    /// The word was not in what the agent printed.
    MissingWord(&'static str),
    /// No connection to such a host was served.
    NoConnectionTo(&'static str),
    /// A connection to a host outside the allow set (the target and the proxy's code).
    Refused(String, String),
    /// The sandboxed exit differs from the unsandboxed one.
    ExitDiffers {
        /// Without the sandbox.
        baseline: Option<i32>,
        /// Under it.
        sandboxed: i32,
    },
    /// The unsandboxed run could not be made.
    Baseline(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Setup(why) => write!(f, "setup failed: {why}"),
            Self::TimedOut(limit) => write!(f, "the agent did not finish in {}s", limit.as_secs()),
            Self::Exit(exit) => write!(f, "the agent did not exit 0 ({exit:?})"),
            Self::MissingWord(word) => write!(f, "the agent never printed {word}"),
            Self::NoConnectionTo(prefix) => {
                write!(f, "no connection to {prefix}* was served")
            }
            Self::Refused(target, code) => write!(
                f,
                "the agent asked for {target}, which is outside the preset ({code})"
            ),
            Self::ExitDiffers {
                baseline,
                sandboxed,
            } => write!(
                f,
                "the sandboxed exit {sandboxed} differs from the unsandboxed one ({baseline:?})"
            ),
            Self::Baseline(why) => write!(f, "the unsandboxed run failed: {why}"),
        }
    }
}

/// What a check saw, for reading after a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The agent's name.
    pub agent: &'static str,
    /// How it ended.
    pub exit: Option<ExitKind>,
    /// The connections that were served, each once.
    pub contacted: Vec<String>,
    /// The last lines of what it printed.
    pub output: Vec<String>,
    /// Every denial: the sandbox's (a hint, the log is incomplete) and the proxy's.
    pub hints: Vec<String>,
}

/// The result of checking one agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not checked.
    Skipped(Skip),
    /// It worked and stayed on its hosts.
    Passed(Report),
    /// It did not.
    Failed {
        /// What was wrong.
        failures: Vec<Failure>,
        /// What was seen.
        report: Report,
    },
}

impl Verdict {
    /// Whether this is a failure (a skip is not).
    #[must_use]
    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skipped(Skip::Disabled) => write!(f, "SKIP: {ENABLE_VAR} is not 1"),
            Self::Skipped(Skip::NotInstalled(name)) => write!(f, "SKIP: {name} is not installed"),
            Self::Skipped(Skip::NoPreset(name)) => {
                write!(f, "SKIP: there is no built-in preset agent/{name} yet")
            }
            Self::Passed(report) => write!(
                f,
                "PASS: {} (contacted: {})",
                report.agent,
                report.contacted.join(", ")
            ),
            Self::Failed { failures, report } => {
                writeln!(f, "FAIL: {}", report.agent)?;
                for failure in failures {
                    writeln!(f, "  - {failure}")?;
                }
                if !report.contacted.is_empty() {
                    writeln!(f, "  contacted: {}", report.contacted.join(", "))?;
                }
                for line in &report.output {
                    writeln!(f, "  | {line}")?;
                }
                for hint in &report.hints {
                    writeln!(f, "  hint: {hint}")?;
                }
                Ok(())
            }
        }
    }
}

/// Collects the proxy's events.
#[derive(Default)]
struct Recorder(Mutex<Vec<AuditEvent>>);

impl Recorder {
    fn events(&self) -> Vec<AuditEvent> {
        self.0.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl AuditSink for Recorder {
    fn record(&self, event: &AuditEvent) {
        if let Ok(mut events) = self.0.lock() {
            events.push(event.clone());
        }
    }
}

/// Checks one agent.
#[must_use]
pub fn run_agent(agent: &Agent, ctx: &Context<'_>) -> Verdict {
    if !ctx.settings.enabled {
        return Verdict::Skipped(Skip::Disabled);
    }
    let Some(binary) = find_binary(agent.binary, ctx.env.vars.get("PATH")) else {
        return Verdict::Skipped(Skip::NotInstalled(agent.binary.to_owned()));
    };
    let preset = format!("agent/{}", agent.name);
    let has_preset = PresetName::parse(&preset)
        .ok()
        .and_then(|name| ctx.builtins.get(&name).map(|_| ()))
        .is_some();
    if !has_preset {
        return Verdict::Skipped(Skip::NoPreset(agent.name.to_owned()));
    }
    let args = args_for(agent, ctx.settings);
    let mut report = Report {
        agent: agent.name,
        exit: None,
        contacted: Vec::new(),
        output: Vec::new(),
        hints: Vec::new(),
    };
    let failures = match attempt(agent, ctx, &binary, &args, &preset, &mut report) {
        Ok(failures) => failures,
        Err(why) => vec![Failure::Setup(why)],
    };
    if failures.is_empty() {
        Verdict::Passed(report)
    } else {
        Verdict::Failed { failures, report }
    }
}

fn args_for(agent: &Agent, settings: &Settings) -> Vec<String> {
    settings
        .args
        .iter()
        .find(|(name, _)| name == agent.name)
        .map_or_else(
            || agent.args.iter().map(|a| (*a).to_owned()).collect(),
            |(_, words)| words.clone(),
        )
}

/// The throwaway project and private user config for one check. Removed when dropped.
struct Rig {
    _dir: SessionDir,
    project: PathBuf,
    user_config: PathBuf,
}

impl Rig {
    fn create(preset: &str, settings: &Settings) -> Result<Self, String> {
        let parent = CanonicalPath::from_canonical(
            &fs::canonicalize(std::env::temp_dir()).map_err(|e| format!("temp dir: {e}"))?,
        )
        .map_err(|e| format!("temp dir: {e}"))?;
        let dir = SessionDir::create(&parent).map_err(|e| format!("work dir: {e}"))?;
        let project = dir.path().as_path().join("project");
        let user_config = dir.path().as_path().join("user");
        for sub in [&project, &user_config] {
            fs::create_dir(sub).map_err(|e| format!("{}: {e}", sub.display()))?;
            fs::set_permissions(sub, fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("{}: {e}", sub.display()))?;
        }
        write_private(&user_config.join("base.toml"), &settings.base_config)?;
        // The project is writable, as in any project of the user's; a preset of its own keeps that
        // out of `project_extra`, which may have an `[fs]` table of its own.
        let presets = user_config.join("presets");
        fs::create_dir(&presets).map_err(|e| format!("{}: {e}", presets.display()))?;
        write_private(
            &presets.join(format!("{PROJECT_PRESET}.toml")),
            "[fs]\nwrite = [\".\"]\n",
        )?;
        write_private(
            &project.join("hamster-ball.toml"),
            &format!(
                "extends = [\"{preset}\", \"{PROJECT_PRESET}\"]\n{}",
                settings.project_extra
            ),
        )?;
        Ok(Self {
            _dir: dir,
            project,
            user_config,
        })
    }
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))
}

/// Runs the agent and judges the run. `Err` is a setup problem.
fn attempt(
    agent: &Agent,
    ctx: &Context<'_>,
    binary: &Path,
    args: &[String],
    preset: &str,
    report: &mut Report,
) -> Result<Vec<Failure>, String> {
    let rig = Rig::create(preset, ctx.settings)?;
    let mut env = ctx.env.clone();
    env.cwd = fs::canonicalize(&rig.project).map_err(|e| format!("project: {e}"))?;
    let discovery = discover(&env.cwd, &env.home).map_err(|e| e.to_string())?;
    let user = UserConfigDir::at(&rig.user_config);
    let loaded = load(
        &LoadRequest::new(&env.home, &discovery, &user, &env.floor).with_builtins(ctx.builtins),
    )
    .map_err(|e| snafu::Report::from_error(e).to_string())?;

    let recorder = Arc::new(Recorder::default());
    let sink = Arc::clone(&recorder);
    let user_tuning = ctx.settings.tuning.clone();
    let tuning = ProxyTuning::new(move |config| {
        let config = user_tuning
            .as_ref()
            .map_or(config.clone(), |tune| tune.apply(config));
        config.with_extra_audit(Arc::clone(&sink) as Arc<dyn AuditSink>)
    });
    let mut words: Vec<OsString> = vec![
        "/usr/bin/perl".into(),
        "-e".into(),
        WRAPPER.into(),
        ctx.settings.timeout.as_secs().to_string().into(),
        binary.as_os_str().to_owned(),
    ];
    words.extend(args.iter().map(OsString::from));
    let spec = RunSpec::new(words)
        .denials(DenialSink::Collect)
        .proxy_summary(false)
        .proxy_tuning(tuning);
    let outcome = session_run(&env, &loaded, &spec)
        .map_err(|e: RunError| snafu::Report::from_error(e).to_string())?;

    let events = recorder.events();
    report.exit = Some(outcome.exit);
    report.contacted = contacted(&events);
    report.output = tail(&outcome.stdout, &outcome.stderr);
    report.hints = outcome.denials.lines.clone();

    let baseline = match agent.expect {
        Expect::SameExitAsBaseline => Some(baseline_exit(binary, args, ctx.settings.timeout)),
        _ => None,
    };
    Ok(judge(
        agent,
        ctx.settings.timeout,
        outcome.exit,
        &outcome.stdout,
        &events,
        baseline,
    ))
}

/// The served connections, as `host:port`, each once.
fn contacted(events: &[AuditEvent]) -> Vec<String> {
    events
        .iter()
        .filter(|e| e.decision == Decision::Allowed)
        .map(AuditEvent::target)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The failures in a run, judged against the agent's [`Expect`].
fn judge(
    agent: &Agent,
    limit: Duration,
    exit: ExitKind,
    stdout: &[u8],
    events: &[AuditEvent],
    baseline: Option<Result<Option<i32>, String>>,
) -> Vec<Failure> {
    let mut failures = Vec::new();
    if exit == ExitKind::Exited(TIMED_OUT) {
        failures.push(Failure::TimedOut(limit));
    }
    let refused: BTreeSet<(String, String)> = events
        .iter()
        .filter_map(|e| match &e.decision {
            Decision::Refused { code, .. } if *code != "proxy_auth_required" => {
                Some((e.target(), (*code).to_owned()))
            }
            _ => None,
        })
        .collect();
    failures.extend(refused.into_iter().map(|(t, c)| Failure::Refused(t, c)));
    let timed_out = failures.iter().any(|f| matches!(f, Failure::TimedOut(_)));
    match agent.expect {
        Expect::Word(word) => {
            if !timed_out && exit != ExitKind::Exited(0) {
                failures.push(Failure::Exit(exit));
            }
            if !has_word(&strip_ansi(&String::from_utf8_lossy(stdout)), word) {
                failures.push(Failure::MissingWord(word));
            }
        }
        Expect::AllowedConnectionTo(prefix) => {
            if exit == ExitKind::Exited(0)
                && !has_word(&strip_ansi(&String::from_utf8_lossy(stdout)), "OK")
            {
                failures.push(Failure::MissingWord("OK"));
            }
            let served = events.iter().any(|e| {
                e.decision == Decision::Allowed
                    && e.host
                        .as_ref()
                        .is_some_and(|h| h.as_str().starts_with(prefix))
            });
            if !served {
                failures.push(Failure::NoConnectionTo(prefix));
            }
        }
        Expect::SameExitAsBaseline => match baseline {
            Some(Ok(baseline)) if !timed_out => {
                let sandboxed = exit.code();
                if baseline != Some(sandboxed) {
                    failures.push(Failure::ExitDiffers {
                        baseline,
                        sandboxed,
                    });
                }
            }
            Some(Err(why)) => failures.push(Failure::Baseline(why)),
            _ => {}
        },
    }
    failures
}

/// The exit code of the same command run without the sandbox, with the same time limit.
fn baseline_exit(binary: &Path, args: &[String], limit: Duration) -> Result<Option<i32>, String> {
    let status = Command::new("/usr/bin/perl")
        .args(["-e", WRAPPER])
        .arg(limit.as_secs().to_string())
        .arg(binary)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0)
        .status()
        .map_err(|e| e.to_string())?;
    Ok(status.code())
}

/// The program `name` resolves to: itself when it has a `/` and exists, else the first match on `path`.
fn find_binary(name: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    if name.contains('/') {
        return Path::new(name).is_file().then(|| PathBuf::from(name));
    }
    std::env::split_paths(path?)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
}

/// Whether `word` is a whole word of `text`.
fn has_word(text: &str, word: &str) -> bool {
    text.split(|c: char| !c.is_alphanumeric())
        .any(|token| token == word)
}

/// `text` without terminal escape sequences (colours, cursor movement).
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for next in chars.by_ref() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(next) = chars.next() {
                    if next == '\u{7}' {
                        break;
                    }
                    if next == '\u{1b}' {
                        chars.next();
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// The last lines of stdout then stderr, without escapes.
fn tail(stdout: &[u8], stderr: &[u8]) -> Vec<String> {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(stdout),
        String::from_utf8_lossy(stderr)
    );
    let lines: Vec<String> = strip_ansi(&text)
        .lines()
        .map(|l| l.trim_end().to_owned())
        .filter(|l| !l.is_empty())
        .collect();
    let skip = lines.len().saturating_sub(TAIL_LINES);
    lines.into_iter().skip(skip).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{HostName, Port};
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn event(host: &str, decision: Decision) -> AuditEvent {
        AuditEvent {
            host: Some(assert_ok!(HostName::parse(host))),
            port: Some(assert_ok!(Port::try_from(443))),
            decision,
            bytes_up: 1,
            bytes_down: 1,
        }
    }

    fn refused(host: &str, code: &'static str) -> AuditEvent {
        event(
            host,
            Decision::Refused {
                code,
                reason: String::new(),
            },
        )
    }

    const WORD: Agent = Agent {
        name: "fake",
        binary: "fake",
        args: &[],
        expect: Expect::Word("OK"),
    };

    #[test]
    fn a_word_is_found_only_as_a_whole_word_whatever_surrounds_it() {
        for text in [
            "OK",
            "OK\n",
            "  OK.",
            "Sure: OK!",
            "\u{1b}[1mOK\u{1b}[0m",
            "[OK]",
        ] {
            assert!(has_word(&strip_ansi(text), "OK"), "{text:?}");
        }
        for text in ["", "okay", "BOOK", "OKAY", "O K"] {
            assert!(!has_word(&strip_ansi(text), "OK"), "{text:?}");
        }
    }

    #[test]
    fn escape_sequences_are_removed_from_colours_cursor_moves_and_titles() {
        assert_eq!(strip_ansi("\u{1b}[31mred\u{1b}[0m plain"), "red plain");
        assert_eq!(strip_ansi("a\u{1b}[2K\u{1b}[1Gb"), "ab");
        assert_eq!(strip_ansi("\u{1b}]0;title\u{7}text"), "text");
        assert_eq!(strip_ansi("\u{1b}]0;title\u{1b}\\text"), "text");
        assert_eq!(strip_ansi("no escapes"), "no escapes");
    }

    #[test]
    fn the_tail_keeps_the_last_lines_of_both_streams_and_drops_blanks() {
        let out: String = (0..40).map(|i| format!("line {i}\n\n")).collect();
        let lines = tail(out.as_bytes(), b"error: boom\n");
        assert_eq!(lines.len(), TAIL_LINES);
        assert_eq!(lines.last().map(String::as_str), Some("error: boom"));
        assert_eq!(lines.first().map(String::as_str), Some("line 16"));
    }

    #[test]
    fn a_word_agent_passes_on_exit_zero_with_the_word_and_no_refusal() {
        let events = [event("app.kiro.dev", Decision::Allowed)];
        let failures = judge(
            &WORD,
            DEFAULT_TIMEOUT,
            ExitKind::Exited(0),
            b"OK\n",
            &events,
            None,
        );
        assert_eq!(failures, []);
    }

    #[test]
    fn each_way_to_fail_is_reported_on_its_own() {
        let none: [AuditEvent; 0] = [];
        assert_eq!(
            judge(
                &WORD,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(0),
                b"nope",
                &none,
                None
            ),
            [Failure::MissingWord("OK")]
        );
        assert_eq!(
            judge(
                &WORD,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(3),
                b"OK",
                &none,
                None
            ),
            [Failure::Exit(ExitKind::Exited(3))]
        );
        assert_eq!(
            judge(
                &WORD,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(TIMED_OUT),
                b"",
                &none,
                None
            ),
            [
                Failure::TimedOut(DEFAULT_TIMEOUT),
                Failure::MissingWord("OK")
            ]
        );
        let outside = [
            refused("evil.example.com", "not_allowed"),
            refused("evil.example.com", "not_allowed"),
            refused("github.com", "proxy_auth_required"),
        ];
        assert_eq!(
            judge(
                &WORD,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(0),
                b"OK",
                &outside,
                None
            ),
            [Failure::Refused(
                "evil.example.com:443".to_owned(),
                "not_allowed".to_owned()
            )]
        );
    }

    #[test]
    fn a_connection_agent_needs_a_served_connection_to_the_prefix() {
        let agent = Agent {
            expect: Expect::AllowedConnectionTo("bedrock-runtime."),
            ..WORD
        };
        let served = [event(
            "bedrock-runtime.us-east-1.amazonaws.com",
            Decision::Allowed,
        )];
        assert_eq!(
            judge(
                &agent,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(1),
                b"",
                &served,
                None
            ),
            []
        );
        let other = [event("sts.us-east-1.amazonaws.com", Decision::Allowed)];
        assert_eq!(
            judge(
                &agent,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(1),
                b"",
                &other,
                None
            ),
            [Failure::NoConnectionTo("bedrock-runtime.")]
        );
    }

    #[test]
    fn a_connection_agent_that_exits_cleanly_must_also_say_the_word_but_a_failed_exit_is_not_judged()
     {
        let agent = Agent {
            expect: Expect::AllowedConnectionTo("bedrock-runtime."),
            ..WORD
        };
        let served = [event(
            "bedrock-runtime.us-east-1.amazonaws.com",
            Decision::Allowed,
        )];
        let judged = |exit, out: &[u8]| judge(&agent, DEFAULT_TIMEOUT, exit, out, &served, None);
        assert_eq!(judged(ExitKind::Exited(0), b"OK\n"), []);
        assert_eq!(
            judged(ExitKind::Exited(0), b"I cannot say"),
            [Failure::MissingWord("OK")]
        );
        // The account may deny the model: the request still reached Bedrock through the sandbox.
        assert_eq!(judged(ExitKind::Exited(1), b"access denied"), []);
        assert_eq!(judged(ExitKind::Signalled(9), b""), []);
    }

    #[test]
    fn the_time_limit_is_reported_once_whatever_the_criterion_and_hides_the_exit_it_caused() {
        let none: [AuditEvent; 0] = [];
        let connection = Agent {
            expect: Expect::AllowedConnectionTo("bedrock-runtime."),
            ..WORD
        };
        assert_eq!(
            judge(
                &connection,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(TIMED_OUT),
                b"",
                &none,
                None
            ),
            [
                Failure::TimedOut(DEFAULT_TIMEOUT),
                Failure::NoConnectionTo("bedrock-runtime.")
            ]
        );
        let served = [event(
            "bedrock-runtime.us-east-1.amazonaws.com",
            Decision::Allowed,
        )];
        assert_eq!(
            judge(
                &connection,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(3),
                b"",
                &served,
                None
            ),
            []
        );
        let baseline = Agent {
            expect: Expect::SameExitAsBaseline,
            ..WORD
        };
        assert_eq!(
            judge(
                &baseline,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(TIMED_OUT),
                b"",
                &none,
                Some(Ok(Some(0)))
            ),
            [Failure::TimedOut(DEFAULT_TIMEOUT)]
        );
    }

    #[test]
    fn settings_from_the_process_follow_the_real_environment() {
        let settings = assert_ok!(Settings::from_process());
        assert_eq!(
            settings.enabled,
            std::env::var_os(ENABLE_VAR).is_some_and(|v| v == "1")
        );
    }

    #[test]
    fn only_a_failed_verdict_is_a_failure() {
        let report = Report {
            agent: "fake",
            exit: None,
            contacted: vec!["a.example.com:443".to_owned()],
            output: Vec::new(),
            hints: Vec::new(),
        };
        assert!(!Verdict::Passed(report.clone()).is_failure());
        assert!(!Verdict::Skipped(Skip::Disabled).is_failure());
        let failed = Verdict::Failed {
            failures: vec![Failure::MissingWord("OK")],
            report,
        };
        assert!(failed.is_failure());
        let shown = failed.to_string();
        assert!(shown.contains("contacted: a.example.com:443"), "{shown}");
        let quiet = Verdict::Failed {
            failures: vec![Failure::MissingWord("OK")],
            report: Report {
                agent: "fake",
                exit: None,
                contacted: Vec::new(),
                output: Vec::new(),
                hints: Vec::new(),
            },
        };
        assert!(!quiet.to_string().contains("contacted:"));
    }

    #[test]
    fn a_baseline_agent_must_exit_as_the_unsandboxed_run_did() {
        let agent = Agent {
            expect: Expect::SameExitAsBaseline,
            ..WORD
        };
        let none: [AuditEvent; 0] = [];
        assert_eq!(
            judge(
                &agent,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(1),
                b"",
                &none,
                Some(Ok(Some(1)))
            ),
            []
        );
        assert_eq!(
            judge(
                &agent,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(1),
                b"",
                &none,
                Some(Ok(Some(0)))
            ),
            [Failure::ExitDiffers {
                baseline: Some(0),
                sandboxed: 1
            }]
        );
        assert_eq!(
            judge(
                &agent,
                DEFAULT_TIMEOUT,
                ExitKind::Exited(0),
                b"",
                &none,
                Some(Err("x".into()))
            ),
            [Failure::Baseline("x".to_owned())]
        );
    }

    #[test]
    fn settings_come_from_the_variables_and_default_to_off() {
        let off = assert_ok!(Settings::from_vars(|_| None));
        assert!(!off.enabled);
        assert_eq!(off.base_config, DEFAULT_BASE);
        assert_eq!(off.timeout, DEFAULT_TIMEOUT);
        let on = assert_ok!(Settings::from_vars(|name| match name {
            ENABLE_VAR => Some("1".into()),
            TIMEOUT_VAR => Some("30".into()),
            "HB_CONFORMANCE_ARGS_KIRO" => Some("chat  hello  world".into()),
            _ => None,
        }));
        assert!(on.enabled);
        assert_eq!(on.timeout, Duration::from_secs(30));
        assert_eq!(args_for(&AGENTS[1], &on), ["chat", "hello", "world"]);
        assert_eq!(
            args_for(&AGENTS[3], &on).first().map(String::as_str),
            Some("--provider")
        );
        // Only the exact value 1 turns it on.
        let yes = assert_ok!(Settings::from_vars(
            |n| (n == ENABLE_VAR).then(|| "yes".into())
        ));
        assert!(!yes.enabled);
    }

    #[test]
    fn bad_settings_are_errors_that_name_the_variable() {
        for bad in ["0", "-3", "ten", ""] {
            let error = assert_err!(Settings::from_vars(
                |n| (n == TIMEOUT_VAR).then(|| bad.into())
            ));
            assert!(error.to_string().contains(TIMEOUT_VAR), "{error}");
        }
        let error = assert_err!(Settings::from_vars(|n| {
            (n == BASE_VAR).then(|| "/definitely/not/a/file".into())
        }));
        assert!(error.to_string().contains(BASE_VAR), "{error}");
    }

    #[test]
    fn a_binary_is_a_path_that_exists_or_the_first_match_on_path() {
        assert_eq!(find_binary("/bin/sh", None), Some(PathBuf::from("/bin/sh")));
        assert_eq!(find_binary("/no/such/binary", None), None);
        assert_eq!(
            find_binary("sh", Some(OsStr::new("/nonexistent:/bin"))),
            Some(PathBuf::from("/bin/sh"))
        );
        assert_eq!(find_binary("sh", None), None);
        assert_eq!(
            find_binary("no-such-agent", Some(OsStr::new("/bin:/usr/bin"))),
            None
        );
    }

    #[test]
    fn the_four_agents_have_the_documented_criteria() {
        let by_name = |name: &str| AGENTS.iter().find(|a| a.name == name).map(|a| a.expect);
        assert_eq!(by_name("kiro"), Some(Expect::Word("OK")));
        assert_eq!(by_name("pi"), Some(Expect::Word("OK")));
        assert_eq!(
            by_name("claude"),
            Some(Expect::AllowedConnectionTo("bedrock-runtime."))
        );
        assert_eq!(by_name("opencode"), Some(Expect::SameExitAsBaseline));
        let names: Vec<&str> = AGENTS.iter().map(|a| a.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
    }
}
