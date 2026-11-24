// ABOUTME: Runs the user's pre-run hooks on the host: argv only, scrubbed environment, bounded time, output kept in the session directory.
// ABOUTME: Never logs a hook's output, never echoes a credential in an error, and gives the agent only 0600 files by path.
//! Pre-run hooks (design sections 4.2 and 11).
//!
//! A hook is code the user's own config asked `hb` to run outside the sandbox. It gets no shell,
//! an environment of four variables, no standard input, a directory of its own inside the session
//! directory, and a time limit. What it prints is read by `hb` only when the hook has a `format`,
//! and is never shown.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;
use snafu::{ResultExt, Snafu, ensure};

use crate::origin::Sourced;
use crate::policy::{
    AwsProfile, CanonicalPath, EnvName, EnvNameError, HomeDir, Hook, HookFormat, HookName,
    PathError,
};
use crate::sys::{BoundedError, run_bounded};

/// Most a hook's standard output may be.
const MAX_OUTPUT_BYTES: u64 = 1_048_576;
/// The `PATH` a hook has: the system's, nothing from the user's shell.
const HOOK_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Longest accepted value of an AWS key or token.
const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Why a hook did not run to completion, or left something unusable. No variant carries what a
/// hook printed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HookRunError {
    /// A directory for hook output could not be made.
    #[snafu(display("cannot create the hook directory {}", path.display()))]
    Directory {
        /// The directory.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// The program could not be started.
    #[snafu(display("hook `{name}` could not be started"))]
    Start {
        /// The hook.
        name: HookName,
        /// The OS error.
        source: io::Error,
    },

    /// The program ended with a failure status.
    #[snafu(display("hook `{name}` failed ({how})"))]
    Failed {
        /// The hook.
        name: HookName,
        /// `exit status N` or `killed by signal N`.
        how: String,
    },

    /// The program ran past its time.
    #[snafu(display("hook `{name}` took more than {seconds} s and was stopped"))]
    TimedOut {
        /// The hook.
        name: HookName,
        /// Its limit.
        seconds: u64,
    },

    /// The hook's output did not have the shape its `format` promises.
    #[snafu(display("hook `{name}` printed output that is not usable as {format}"))]
    BadOutput {
        /// The hook.
        name: HookName,
        /// The format it asked for.
        format: HookFormat,
        /// What was wrong, without any value.
        source: CredentialsError,
    },

    /// A file the hook promised in `outputs` is not there or is not a plain file.
    #[snafu(display(
        "hook `{name}` was to write `{file}` for {variable}, and did not leave a regular file"
    ))]
    MissingOutput {
        /// The hook.
        name: HookName,
        /// The file name.
        file: String,
        /// The variable that was to point at it.
        variable: EnvName,
    },

    /// Two hooks set the same variable.
    #[snafu(display("hooks `{first}` and `{second}` both set {variable}"))]
    VariableTwice {
        /// The variable.
        variable: EnvName,
        /// The hook that set it first.
        first: HookName,
        /// The hook that set it again.
        second: HookName,
    },

    /// A file could not be written or its mode set.
    #[snafu(display("cannot write {}", path.display()))]
    Write {
        /// The file.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },

    /// A variable `hb` itself sets has an invalid name (a bug in `hb`).
    #[snafu(transparent)]
    Variable {
        /// The underlying error.
        source: EnvNameError,
    },

    /// A file the hook left has no canonical path.
    #[snafu(display("the file {} is not a usable path", path.display()))]
    Path {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: PathError,
    },
}

/// Why a credential tool's output is not usable. Never holds a value.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum CredentialsError {
    /// Not JSON of the expected shape.
    #[snafu(display("it is not the JSON an AWS credential_process prints"))]
    NotJson,

    /// A `Version` other than 1.
    #[snafu(display("its Version is not 1"))]
    WrongVersion,

    /// A required field is missing or empty.
    #[snafu(display("{field} is missing"))]
    Missing {
        /// The field.
        field: &'static str,
    },

    /// A value with characters a key or token does not have, or too long.
    #[snafu(display("{field} has characters or a length no AWS credential has"))]
    BadValue {
        /// The field.
        field: &'static str,
    },
}

/// What a `credential_process` prints.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ProcessOutput {
    version: Option<i64>,
    access_key_id: Option<String>,
    secret_access_key: Option<String>,
    session_token: Option<String>,
}

fn credential(field: &'static str, value: Option<String>) -> Result<String, CredentialsError> {
    let value = value.filter(|v| !v.is_empty());
    let value = value.ok_or(CredentialsError::Missing { field })?;
    ensure!(
        value.len() <= MAX_CREDENTIAL_BYTES
            && value.chars().all(|c| c.is_ascii_alphanumeric()
                || matches!(c, '/' | '+' | '=' | '_' | '.' | ':' | '-')),
        BadValueSnafu { field }
    );
    Ok(value)
}

/// The `config` and `credentials` text for `profile` from a `credential_process` output.
///
/// # Errors
/// [`CredentialsError`], which names a field and never shows a value.
pub(crate) fn aws_files(
    output: &[u8],
    profile: &AwsProfile,
) -> Result<(String, String), CredentialsError> {
    let parsed: ProcessOutput =
        serde_json::from_slice(output).map_err(|_| CredentialsError::NotJson)?;
    ensure!(parsed.version == Some(1), WrongVersionSnafu);
    let key = credential("AccessKeyId", parsed.access_key_id)?;
    let secret = credential("SecretAccessKey", parsed.secret_access_key)?;
    let token = parsed
        .session_token
        .map(|t| credential("SessionToken", Some(t)))
        .transpose()?;
    let name = profile.as_str();
    let header = if name == "default" {
        "[default]".to_owned()
    } else {
        format!("[profile {name}]")
    };
    let config = format!("{header}\n");
    let mut credentials =
        format!("[{name}]\naws_access_key_id = {key}\naws_secret_access_key = {secret}\n");
    if let Some(token) = token {
        credentials.push_str(&format!("aws_session_token = {token}\n"));
    }
    Ok((config, credentials))
}

/// The files the agent is pointed at, by variable.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookOutputs {
    vars: BTreeMap<EnvName, CanonicalPath>,
}

impl HookOutputs {
    /// The variables to set in the agent's environment, each a file in the session directory.
    #[must_use]
    pub fn vars(&self) -> &BTreeMap<EnvName, CanonicalPath> {
        &self.vars
    }

    /// Whether no hook set anything.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }
}

/// Runs every hook in name order, each in its own directory under `<session>/hooks/`.
///
/// # Errors
/// [`HookRunError`]; the first hook to fail stops the rest.
pub fn run_pre_run(
    hooks: &BTreeMap<HookName, Sourced<Hook>>,
    session: &CanonicalPath,
    home: &HomeDir,
) -> Result<HookOutputs, HookRunError> {
    let mut outputs = HookOutputs::default();
    if hooks.is_empty() {
        return Ok(outputs);
    }
    let root = session.as_path().join("hooks");
    private_dir(&root)?;
    let mut owners: BTreeMap<EnvName, HookName> = BTreeMap::new();
    for (name, hook) in hooks {
        let dir = root.join(name.as_str());
        private_dir(&dir)?;
        let produced = run_one(name, &hook.value, &dir, home)?;
        for (variable, path) in produced {
            if let Some(first) = owners.insert(variable.clone(), name.clone()) {
                return VariableTwiceSnafu {
                    variable,
                    first,
                    second: name.clone(),
                }
                .fail();
            }
            outputs.vars.insert(variable, path);
        }
    }
    Ok(outputs)
}

fn private_dir(path: &Path) -> Result<(), HookRunError> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(source) => Err(HookRunError::Directory {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// `~/rest` as `<home>/rest`; anything else as it is.
fn expand_home(word: &str, home: &HomeDir) -> String {
    word.strip_prefix("~/").map_or_else(
        || word.to_owned(),
        |rest| format!("{}/{rest}", home.path().as_str()),
    )
}

fn run_one(
    name: &HookName,
    hook: &Hook,
    dir: &Path,
    home: &HomeDir,
) -> Result<Vec<(EnvName, CanonicalPath)>, HookRunError> {
    let words = hook.command.words();
    let mut command = Command::new(expand_home(words[0].as_str(), home));
    command
        .args(words.iter().skip(1).map(|w| w.as_str()))
        .current_dir(dir)
        .env_clear()
        .env("HOME", home.path().as_str())
        .env("PATH", HOOK_PATH)
        .env("TMPDIR", dir)
        .env("HB_HOOK_DIR", dir);
    let finished = match run_bounded(&mut command, hook.timeout.get(), MAX_OUTPUT_BYTES) {
        Ok(finished) => finished,
        Err(BoundedError::Spawn(source)) => {
            return Err(HookRunError::Start {
                name: name.clone(),
                source,
            });
        }
        Err(BoundedError::TimedOut) => {
            return TimedOutSnafu {
                name: name.clone(),
                seconds: hook.timeout.get().as_secs(),
            }
            .fail();
        }
    };
    ensure!(
        finished.status.success(),
        FailedSnafu {
            name: name.clone(),
            how: how_it_ended(finished.status)
        }
    );
    let mut produced = Vec::new();
    if let (Some(format), Some(profile)) = (hook.format, &hook.profile) {
        match format {
            HookFormat::AwsCredentialProcess => {
                let (config, credentials) =
                    aws_files(&finished.stdout, profile).with_context(|_| BadOutputSnafu {
                        name: name.clone(),
                        format,
                    })?;
                for (variable, file, text) in [
                    ("AWS_CONFIG_FILE", "config", config),
                    ("AWS_SHARED_CREDENTIALS_FILE", "credentials", credentials),
                ] {
                    let path = dir.join(file);
                    write_private(&path, text.as_bytes())?;
                    produced.push((EnvName::parse(variable)?, canonical(&path)?));
                }
            }
        }
    }
    for (variable, file) in &hook.outputs {
        let path = dir.join(file.as_str());
        let regular = fs::symlink_metadata(&path).is_ok_and(|m| m.is_file());
        ensure!(
            regular,
            MissingOutputSnafu {
                name: name.clone(),
                file: file.as_str().to_owned(),
                variable: variable.clone()
            }
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .with_context(|_| WriteSnafu { path: path.clone() })?;
        produced.push((variable.clone(), canonical(&path)?));
    }
    Ok(produced)
}

fn canonical(path: &Path) -> Result<CanonicalPath, HookRunError> {
    let resolved = fs::canonicalize(path).with_context(|_| WriteSnafu {
        path: path.to_path_buf(),
    })?;
    CanonicalPath::from_canonical(resolved).with_context(|_| PathSnafu {
        path: path.to_path_buf(),
    })
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), HookRunError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|_| WriteSnafu {
            path: path.to_path_buf(),
        })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|_| WriteSnafu {
            path: path.to_path_buf(),
        })
}

fn how_it_ended(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("exit status {code}"),
        (None, Some(signal)) => format!("killed by signal {signal}"),
        (None, None) => "no status".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::{FileId, Source};
    use crate::policy::{Argv, HookTimeout, OutputFile};
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;
    use tempfile::TempDir;

    struct Fixture {
        dir: TempDir,
        session: CanonicalPath,
        home: HomeDir,
    }

    fn fixture() -> Fixture {
        let dir = assert_ok!(tempfile::tempdir());
        let base = assert_ok!(fs::canonicalize(dir.path()));
        let session = base.join("session");
        assert_ok!(fs::create_dir(&session));
        assert_ok!(fs::create_dir(base.join("home")));
        Fixture {
            session: assert_ok!(CanonicalPath::from_canonical(session)),
            home: HomeDir::new(assert_ok!(CanonicalPath::from_canonical(base.join("home")))),
            dir,
        }
    }

    fn script(f: &Fixture, name: &str, body: &str) -> String {
        let path = f.dir.path().join(name);
        assert_ok!(fs::write(&path, format!("#!/bin/sh\n{body}\n")));
        assert_ok!(fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o755)
        ));
        assert_ok!(fs::canonicalize(&path))
            .to_string_lossy()
            .into_owned()
    }

    fn name(text: &str) -> HookName {
        assert_ok!(HookName::parse(text))
    }

    fn hook(program: &str, args: &[&str]) -> Hook {
        let mut words = vec![program.to_owned()];
        words.extend(args.iter().map(|a| (*a).to_owned()));
        assert_ok!(Hook::new(
            assert_ok!(Argv::parse(&words)),
            HookTimeout::default(),
            None,
            None,
            BTreeMap::new()
        ))
    }

    fn with_outputs(mut hook: Hook, outputs: &[(&str, &str)]) -> Hook {
        hook.outputs = outputs
            .iter()
            .map(|(v, f)| {
                (
                    assert_ok!(EnvName::parse(v)),
                    assert_ok!(OutputFile::parse(f)),
                )
            })
            .collect();
        hook
    }

    fn sourced(hook: Hook) -> Sourced<Hook> {
        Sourced::new(hook, Source::value(FileId::new(0)))
    }

    fn hooks(entries: Vec<(&str, Hook)>) -> BTreeMap<HookName, Sourced<Hook>> {
        entries
            .into_iter()
            .map(|(n, h)| (name(n), sourced(h)))
            .collect()
    }

    fn run(f: &Fixture, entries: Vec<(&str, Hook)>) -> Result<HookOutputs, HookRunError> {
        run_pre_run(&hooks(entries), &f.session, &f.home)
    }

    fn mode(path: &Path) -> u32 {
        assert_ok!(fs::metadata(path)).mode() & 0o7777
    }

    const GOOD_JSON: &str = r#"{"Version":1,"AccessKeyId":"AKIAEXAMPLE","SecretAccessKey":"sEcr3t/value+x=","SessionToken":"tok/en+==","Expiration":"2030-01-01T00:00:00Z"}"#;

    #[test]
    fn no_hooks_make_no_directory() {
        let f = fixture();
        assert!(assert_ok!(run(&f, vec![])).is_empty());
        assert!(!f.session.as_path().join("hooks").exists());
    }

    #[test]
    fn a_hook_runs_without_a_shell_in_its_own_private_directory() {
        let f = fixture();
        let tool = script(&f, "tool", "pwd > seen-cwd; echo \"$1\" > seen-arg");
        let hook = with_outputs(hook(&tool, &["a b; touch pwned"]), &[("SEEN", "seen-arg")]);
        let out = assert_ok!(run(&f, vec![("tool", hook)]));
        let dir = f.session.as_path().join("hooks/tool");
        assert_eq!(mode(&f.session.as_path().join("hooks")), 0o700);
        assert_eq!(mode(&dir), 0o700);
        // The argument arrived as one word; nothing interpreted it.
        assert_eq!(
            assert_ok!(fs::read_to_string(dir.join("seen-arg"))),
            "a b; touch pwned\n"
        );
        assert!(!dir.join("pwned").exists());
        let cwd = assert_ok!(fs::read_to_string(dir.join("seen-cwd")));
        assert_eq!(
            cwd.trim(),
            assert_ok!(fs::canonicalize(&dir)).to_string_lossy()
        );
        assert_eq!(out.vars().len(), 1);
        assert!(!out.is_empty());
    }

    #[test]
    fn a_session_directory_that_cannot_be_written_is_a_directory_error_not_a_silent_skip() {
        let f = fixture();
        let tool = script(&f, "tool", "true");
        assert_ok!(fs::set_permissions(
            f.session.as_path(),
            fs::Permissions::from_mode(0o500)
        ));
        let result = run(&f, vec![("t", hook(&tool, &[]))]);
        assert_ok!(fs::set_permissions(
            f.session.as_path(),
            fs::Permissions::from_mode(0o700)
        ));
        assert!(matches!(
            assert_err!(result),
            HookRunError::Directory { .. }
        ));
    }

    #[test]
    fn the_hook_environment_is_four_variables_and_nothing_from_the_parent() {
        let f = fixture();
        let tool = script(&f, "tool", "env | sort > env.txt");
        assert_ok!(run(&f, vec![("tool", hook(&tool, &[]))]));
        let text = assert_ok!(fs::read_to_string(
            f.session.as_path().join("hooks/tool/env.txt")
        ));
        let names: Vec<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
        for expected in ["HOME", "PATH", "TMPDIR", "HB_HOOK_DIR"] {
            assert!(
                names.contains(&expected),
                "{expected} missing from {names:?}"
            );
        }
        // The test process has many more (CARGO_*, RUST_*, USER, SHELL...); none reaches the hook.
        for leaked in [
            "CARGO_MANIFEST_DIR",
            "USER",
            "SHELL",
            "LOGNAME",
            "SSH_AUTH_SOCK",
        ] {
            assert!(!names.contains(&leaked), "{leaked} leaked: {names:?}");
        }
        assert!(
            text.contains(&format!("HOME={}", f.home.path().as_str())),
            "{text}"
        );
        assert!(
            text.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin"),
            "{text}"
        );
    }

    #[test]
    fn a_program_under_home_is_found_through_the_tilde() {
        let f = fixture();
        let path = f.home.path().as_path().join("tool");
        assert_ok!(fs::write(&path, "#!/bin/sh\necho ran > ran\n"));
        assert_ok!(fs::set_permissions(
            &path,
            fs::Permissions::from_mode(0o755)
        ));
        assert_ok!(run(&f, vec![("t", hook("~/tool", &[]))]));
        assert!(f.session.as_path().join("hooks/t/ran").exists());
    }

    #[test]
    fn standard_input_is_closed_and_a_failing_hook_stops_the_run_naming_the_status() {
        let f = fixture();
        let reads = script(&f, "reads", "cat > /dev/null; echo ok > ok");
        assert_ok!(run(&f, vec![("reads", hook(&reads, &[]))]));
        assert!(f.session.as_path().join("hooks/reads/ok").exists());
        let fails = script(
            &f,
            "fails",
            "echo SENTINEL-OUTPUT; echo SENTINEL-ERR >&2; exit 7",
        );
        let error = assert_err!(run(&f, vec![("fails", hook(&fails, &[]))]));
        let shown = snafu::Report::from_error(error).to_string();
        assert!(
            shown.contains("hook `fails` failed (exit status 7)"),
            "{shown}"
        );
        assert!(
            !shown.contains("SENTINEL"),
            "output leaked into the error: {shown}"
        );
    }

    #[test]
    fn a_hook_that_runs_too_long_is_stopped_with_what_it_started() {
        let f = fixture();
        let slow = script(&f, "slow", "sleep 30 & wait");
        let mut h = hook(&slow, &[]);
        h.timeout = assert_ok!(HookTimeout::from_secs(1));
        let started = std::time::Instant::now();
        let error = assert_err!(run(&f, vec![("slow", h)]));
        assert!(
            matches!(error, HookRunError::TimedOut { seconds: 1, .. }),
            "{error:?}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn a_missing_program_says_which_hook() {
        let f = fixture();
        let error = assert_err!(run(&f, vec![("ghost", hook("/nonexistent/tool", &[]))]));
        assert!(matches!(error, HookRunError::Start { .. }), "{error:?}");
        assert!(error.to_string().contains("hook `ghost`"), "{error}");
    }

    #[test]
    fn hooks_run_in_name_order_and_the_first_failure_stops_the_rest() {
        let f = fixture();
        let log = f.dir.path().join("order");
        let log = log.to_string_lossy().into_owned();
        let one = script(&f, "one", &format!("echo one >> {log}"));
        let two = script(&f, "two", &format!("echo two >> {log}; exit 1"));
        let three = script(&f, "three", &format!("echo three >> {log}"));
        let error = assert_err!(run(
            &f,
            vec![
                ("30-c", hook(&three, &[])),
                ("10-a", hook(&one, &[])),
                ("20-b", hook(&two, &[]))
            ]
        ));
        assert!(matches!(error, HookRunError::Failed { .. }));
        assert_eq!(assert_ok!(fs::read_to_string(&log)), "one\ntwo\n");
    }

    #[test]
    fn an_output_file_becomes_a_variable_with_mode_0600_whatever_the_hook_made() {
        let f = fixture();
        let tool = script(&f, "tool", "echo data > out.txt; chmod 666 out.txt");
        let out = assert_ok!(run(
            &f,
            vec![(
                "t",
                with_outputs(hook(&tool, &[]), &[("MY_FILE", "out.txt")])
            )]
        ));
        let var = assert_ok!(EnvName::parse("MY_FILE"));
        let path = assert_ok!(out.vars().get(&var).ok_or("missing"));
        assert!(
            path.as_str().ends_with("/hooks/t/out.txt"),
            "{}",
            path.as_str()
        );
        assert_eq!(mode(path.as_path()), 0o600);
    }

    #[test]
    fn an_output_that_is_missing_a_directory_or_a_symlink_is_refused() {
        let f = fixture();
        let none = script(&f, "none", "true");
        let missing = assert_err!(run(
            &f,
            vec![("a", with_outputs(hook(&none, &[]), &[("V", "nope")]))]
        ));
        assert!(
            matches!(missing, HookRunError::MissingOutput { .. }),
            "{missing:?}"
        );
        let dir = script(&f, "dir", "mkdir out");
        assert_err!(run(
            &f,
            vec![("b", with_outputs(hook(&dir, &[]), &[("V", "out")]))]
        ));
        let link = script(&f, "link", "ln -s /etc/hosts out");
        assert_err!(run(
            &f,
            vec![("c", with_outputs(hook(&link, &[]), &[("V", "out")]))]
        ));
    }

    #[test]
    fn two_hooks_cannot_set_the_same_variable() {
        let f = fixture();
        let tool = script(&f, "tool", "echo x > f");
        let error = assert_err!(run(
            &f,
            vec![
                ("a", with_outputs(hook(&tool, &[]), &[("V", "f")])),
                ("b", with_outputs(hook(&tool, &[]), &[("V", "f")]))
            ]
        ));
        assert!(
            matches!(error, HookRunError::VariableTwice { .. }),
            "{error:?}"
        );
    }

    fn aws_hook(f: &Fixture, output: &str, profile: &str) -> Hook {
        let tool = script(f, "cred", &format!("cat <<'EOF'\n{output}\nEOF"));
        let mut h = hook(&tool, &[]);
        h.format = Some(HookFormat::AwsCredentialProcess);
        h.profile = Some(assert_ok!(AwsProfile::parse(profile)));
        h
    }

    #[test]
    fn the_aws_format_writes_a_config_and_credentials_pair_and_names_them_for_the_agent() {
        let f = fixture();
        let out = assert_ok!(run(
            &f,
            vec![("bedrock", aws_hook(&f, GOOD_JSON, "my-profile"))]
        ));
        let dir = f.session.as_path().join("hooks/bedrock");
        assert_eq!(mode(&dir.join("config")), 0o600);
        assert_eq!(mode(&dir.join("credentials")), 0o600);
        assert_eq!(
            assert_ok!(fs::read_to_string(dir.join("config"))),
            "[profile my-profile]\n"
        );
        assert_eq!(
            assert_ok!(fs::read_to_string(dir.join("credentials"))),
            "[my-profile]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = sEcr3t/value+x=\naws_session_token = tok/en+==\n"
        );
        let names: Vec<&str> = out.vars().keys().map(EnvName::as_str).collect();
        assert_eq!(names, ["AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE"]);
        for path in out.vars().values() {
            assert!(path.as_str().starts_with(f.session.as_str()));
        }
    }

    #[test]
    fn the_default_profile_is_written_as_default_and_a_token_is_optional() {
        let (config, credentials) = assert_ok!(aws_files(
            br#"{"Version":1,"AccessKeyId":"A","SecretAccessKey":"B"}"#,
            &assert_ok!(AwsProfile::parse("default"))
        ));
        assert_eq!(config, "[default]\n");
        assert_eq!(
            credentials,
            "[default]\naws_access_key_id = A\naws_secret_access_key = B\n"
        );
    }

    #[test]
    fn credential_output_that_is_wrong_is_refused_without_showing_any_value() {
        let profile = assert_ok!(AwsProfile::parse("p"));
        let cases: &[(&str, &str)] = &[
            ("not json SECRETVALUE", "not the JSON"),
            (
                r#"{"Version":2,"AccessKeyId":"A","SecretAccessKey":"SECRETVALUE"}"#,
                "Version",
            ),
            (
                r#"{"Version":1,"SecretAccessKey":"SECRETVALUE"}"#,
                "AccessKeyId is missing",
            ),
            (
                r#"{"Version":1,"AccessKeyId":"A","SecretAccessKey":""}"#,
                "SecretAccessKey is missing",
            ),
            (
                r#"{"Version":1,"AccessKeyId":"A\nb","SecretAccessKey":"SECRETVALUE"}"#,
                "AccessKeyId has characters",
            ),
            (
                r#"{"Version":1,"AccessKeyId":"A","SecretAccessKey":"SECRETVALUE","SessionToken":"x y"}"#,
                "SessionToken has characters",
            ),
        ];
        for (output, want) in cases {
            let error = assert_err!(aws_files(output.as_bytes(), &profile), "{output}");
            let shown = error.to_string();
            assert!(shown.contains(want), "{shown} lacks {want}");
            assert!(!shown.contains("SECRETVALUE"), "{shown}");
        }
        let too_long = format!(
            r#"{{"Version":1,"AccessKeyId":"{}","SecretAccessKey":"B"}}"#,
            "A".repeat(MAX_CREDENTIAL_BYTES + 1)
        );
        assert_err!(aws_files(too_long.as_bytes(), &profile));
    }

    #[test]
    fn a_credential_hook_with_unusable_output_fails_the_run_and_leaves_no_files() {
        let f = fixture();
        let error = assert_err!(run(
            &f,
            vec![("b", aws_hook(&f, "garbage SECRETVALUE", "p"))]
        ));
        let shown = snafu::Report::from_error(error).to_string();
        assert!(
            shown.contains("not usable as aws_credential_process"),
            "{shown}"
        );
        assert!(!shown.contains("SECRETVALUE"), "{shown}");
        assert!(!f.session.as_path().join("hooks/b/credentials").exists());
    }
}
