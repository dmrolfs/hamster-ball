// ABOUTME: Validated types of a host-side hook: its name, timeout, output format, AWS profile and output file names.
// ABOUTME: Pure; running a hook is `session::hooks`. Hooks run outside the sandbox, so every value here is checked tightly.
//! Hooks (design sections 4.2 and 11).
//!
//! A hook is a program the user's own config asks `hb` to run on the host before the agent starts.
//! It is code execution outside the sandbox, which is why only the user's files and the built-in
//! presets may define one (D36), and why its program must be named by an absolute path.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use snafu::{Snafu, ensure};
use strum::{Display, EnumString, IntoStaticStr};

use super::argv::Argv;
use super::env::EnvName;
use crate::text::EscapedBounded;

/// Longest accepted name, profile or output file name, in bytes.
pub const MAX_HOOK_WORD_BYTES: usize = 64;
/// Timeout used when a hook names none.
pub const DEFAULT_TIMEOUT_SECS: u64 = 30;
/// Longest timeout a hook may ask for.
pub const MAX_TIMEOUT_SECS: u64 = 300;
/// How much of a rejected value an error echoes.
const PREVIEW_CHARS: usize = 64;

/// Why a hook field is not acceptable.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum HookError {
    /// A name, profile or file name is empty.
    #[snafu(display("{what} is empty"))]
    Empty {
        /// Which field.
        what: &'static str,
    },

    /// A name, profile or file name is too long.
    #[snafu(display("{what} is {len} bytes long; the limit is {max}"))]
    TooLong {
        /// Which field.
        what: &'static str,
        /// Its length.
        len: usize,
        /// The limit.
        max: usize,
    },

    /// A character outside the allowed set.
    #[snafu(display(
        "{what} may contain only {allowed}: {}",
        EscapedBounded::new(text, PREVIEW_CHARS)
    ))]
    BadCharacter {
        /// Which field.
        what: &'static str,
        /// What is allowed.
        allowed: &'static str,
        /// The rejected value.
        text: String,
    },

    /// A name that starts with a character it may not start with.
    #[snafu(display(
        "{what} must not start with `{first}`: {}",
        EscapedBounded::new(text, PREVIEW_CHARS)
    ))]
    BadStart {
        /// Which field.
        what: &'static str,
        /// The offending first character.
        first: char,
        /// The rejected value.
        text: String,
    },

    /// A timeout outside 1 to 300 seconds.
    #[snafu(display("timeout_secs must be from 1 to {MAX_TIMEOUT_SECS}, not {seconds}"))]
    TimeoutOutOfRange {
        /// The value asked for.
        seconds: i64,
    },

    /// An unknown `format`.
    #[snafu(display(
        "unknown hook format `{}`; the only one is `aws_credential_process`",
        EscapedBounded::new(text, PREVIEW_CHARS)
    ))]
    UnknownFormat {
        /// The rejected value.
        text: String,
    },

    /// The program is not named by an absolute path.
    #[snafu(display(
        "a hook's program must be an absolute path or start with `~/`, because `hb` does not search PATH for code it runs outside the sandbox: {}",
        EscapedBounded::new(text, PREVIEW_CHARS)
    ))]
    ProgramNotAbsolute {
        /// The rejected program.
        text: String,
    },

    /// `format` and `profile` must come together.
    #[snafu(display(
        "a hook with format `{format}` needs `profile`, and `profile` is only for that format"
    ))]
    FormatProfileMismatch {
        /// The format involved.
        format: HookFormat,
    },
}

fn check_word(
    what: &'static str,
    allowed: &'static str,
    text: &str,
    ok: impl Fn(char) -> bool,
) -> Result<(), HookError> {
    ensure!(!text.is_empty(), EmptySnafu { what });
    ensure!(
        text.len() <= MAX_HOOK_WORD_BYTES,
        TooLongSnafu {
            what,
            len: text.len(),
            max: MAX_HOOK_WORD_BYTES
        }
    );
    ensure!(
        text.chars().all(ok),
        BadCharacterSnafu {
            what,
            allowed,
            text
        }
    );
    Ok(())
}

/// The name of a `[hooks.pre_run.<name>]` hook: `[a-z0-9][a-z0-9_-]{0,63}`.
///
/// Hooks run in name order, so a name that starts with a number orders them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct HookName(String);

impl HookName {
    /// Parses a hook name.
    ///
    /// # Errors
    /// See [`HookError`].
    pub fn parse(text: &str) -> Result<Self, HookError> {
        check_word(
            "hook name",
            "lower-case letters, digits, `_` and `-`",
            text,
            |c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-'),
        )?;
        if let Some(first) = text.chars().next() {
            ensure!(
                first.is_ascii_lowercase() || first.is_ascii_digit(),
                BadStartSnafu {
                    what: "hook name",
                    first,
                    text
                }
            );
        }
        Ok(Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HookName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An AWS profile name: `[A-Za-z0-9_.-]{1,64}`.
///
/// It is written into a config file as `[profile <name>]`, so no space, bracket or newline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct AwsProfile(String);

impl AwsProfile {
    /// Parses a profile name.
    ///
    /// # Errors
    /// See [`HookError`].
    pub fn parse(text: &str) -> Result<Self, HookError> {
        check_word("profile", "letters, digits, `_`, `.` and `-`", text, |c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-')
        })?;
        Ok(Self(text.to_owned()))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The name of a file a hook writes in its output directory: one path component, no leading dot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OutputFile(String);

impl OutputFile {
    /// Parses a file name.
    ///
    /// # Errors
    /// See [`HookError`].
    pub fn parse(text: &str) -> Result<Self, HookError> {
        check_word(
            "output file name",
            "letters, digits, `_`, `.` and `-`",
            text,
            |c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'),
        )?;
        if let Some(first) = text.chars().next() {
            ensure!(
                first != '.',
                BadStartSnafu {
                    what: "output file name",
                    first,
                    text
                }
            );
        }
        Ok(Self(text.to_owned()))
    }

    /// The file name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How long a hook may run: 1 to 300 seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HookTimeout(Duration);

impl HookTimeout {
    /// A timeout from a number of seconds in the config.
    ///
    /// # Errors
    /// [`HookError::TimeoutOutOfRange`].
    pub fn from_secs(seconds: i64) -> Result<Self, HookError> {
        let in_range = u64::try_from(seconds)
            .ok()
            .filter(|s| (1..=MAX_TIMEOUT_SECS).contains(s));
        match in_range {
            Some(s) => Ok(Self(Duration::from_secs(s))),
            None => TimeoutOutOfRangeSnafu { seconds }.fail(),
        }
    }

    /// The time allowed.
    #[must_use]
    pub fn get(self) -> Duration {
        self.0
    }
}

impl Default for HookTimeout {
    fn default() -> Self {
        Self(Duration::from_secs(DEFAULT_TIMEOUT_SECS))
    }
}

/// What `hb` does with a hook's standard output.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Display, EnumString, IntoStaticStr,
)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum HookFormat {
    /// The output is the JSON an AWS `credential_process` prints; `hb` writes an AWS `config` and
    /// `credentials` pair for the hook's profile and points the agent's `AWS_*` variables at it.
    AwsCredentialProcess,
}

impl HookFormat {
    /// Parses a format name.
    ///
    /// # Errors
    /// [`HookError::UnknownFormat`].
    pub fn parse(text: &str) -> Result<Self, HookError> {
        text.parse().map_err(|_| HookError::UnknownFormat {
            text: text.to_owned(),
        })
    }
}

/// One `[hooks.pre_run.<name>]` hook.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Hook {
    /// The program and its arguments; run without a shell.
    pub command: Argv,
    /// How long it may run.
    pub timeout: HookTimeout,
    /// What to do with its standard output, if anything.
    pub format: Option<HookFormat>,
    /// The AWS profile the agent selects, for the `aws_credential_process` format.
    pub profile: Option<AwsProfile>,
    /// Environment variables for the agent, each naming a file the hook wrote.
    pub outputs: BTreeMap<EnvName, OutputFile>,
}

impl Hook {
    /// Checks the fields against each other.
    ///
    /// # Errors
    /// [`HookError::ProgramNotAbsolute`] or [`HookError::FormatProfileMismatch`].
    pub fn new(
        command: Argv,
        timeout: HookTimeout,
        format: Option<HookFormat>,
        profile: Option<AwsProfile>,
        outputs: BTreeMap<EnvName, OutputFile>,
    ) -> Result<Self, HookError> {
        let program = command.program().as_str();
        ensure!(
            program.starts_with('/') || program.starts_with("~/"),
            ProgramNotAbsoluteSnafu { text: program }
        );
        match (format, &profile) {
            (Some(HookFormat::AwsCredentialProcess), None) => {
                return FormatProfileMismatchSnafu {
                    format: HookFormat::AwsCredentialProcess,
                }
                .fail();
            }
            (None, Some(_)) => {
                return FormatProfileMismatchSnafu {
                    format: HookFormat::AwsCredentialProcess,
                }
                .fail();
            }
            _ => {}
        }
        Ok(Self {
            command,
            timeout,
            format,
            profile,
            outputs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn argv(words: &[&str]) -> Argv {
        let owned: Vec<String> = words.iter().map(|w| (*w).to_owned()).collect();
        assert_ok!(Argv::parse(&owned))
    }

    #[test]
    fn a_hook_name_is_lower_case_words_that_may_start_with_a_number() {
        for good in ["bedrock", "10-bedrock", "a_b-c", "0"] {
            assert_ok!(HookName::parse(good), "{good}");
        }
        for bad in [
            "",
            "Bedrock",
            "a b",
            "a/b",
            "a.b",
            "-a",
            "_a",
            "é",
            &"a".repeat(65),
        ] {
            assert_err!(HookName::parse(bad), "{bad}");
        }
    }

    #[test]
    fn a_profile_cannot_carry_what_would_break_an_ini_file() {
        for good in ["default", "ai-coding-bedrock-us-east-1", "a.b_c"] {
            assert_ok!(AwsProfile::parse(good), "{good}");
        }
        for bad in ["", "a b", "a]", "a\nb", "[x", "a=b", "é", &"a".repeat(65)] {
            assert_err!(AwsProfile::parse(bad), "{bad:?}");
        }
    }

    #[test]
    fn an_output_file_is_one_visible_component() {
        assert_ok!(OutputFile::parse("credentials"));
        assert_ok!(OutputFile::parse("token.json"));
        for bad in [
            "",
            ".hidden",
            "..",
            ".",
            "a/b",
            "../x",
            "a b",
            &"a".repeat(65),
        ] {
            assert_err!(OutputFile::parse(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_timeout_is_one_to_three_hundred_seconds_and_defaults_to_thirty() {
        assert_eq!(HookTimeout::default().get(), Duration::from_secs(30));
        assert_eq!(
            assert_ok!(HookTimeout::from_secs(1)).get(),
            Duration::from_secs(1)
        );
        assert_eq!(
            assert_ok!(HookTimeout::from_secs(300)).get(),
            Duration::from_secs(300)
        );
        for bad in [0, -1, 301, i64::MAX, i64::MIN] {
            assert!(matches!(
                assert_err!(HookTimeout::from_secs(bad)),
                HookError::TimeoutOutOfRange { .. }
            ));
        }
    }

    #[test]
    fn the_format_is_spelled_in_snake_case_and_nothing_else_is_accepted() {
        assert_eq!(
            assert_ok!(HookFormat::parse("aws_credential_process")),
            HookFormat::AwsCredentialProcess
        );
        assert_eq!(
            HookFormat::AwsCredentialProcess.to_string(),
            "aws_credential_process"
        );
        for bad in [
            "",
            "json",
            "AWS_CREDENTIAL_PROCESS",
            "aws-credential-process",
        ] {
            assert!(matches!(
                assert_err!(HookFormat::parse(bad)),
                HookError::UnknownFormat { .. }
            ));
        }
    }

    fn hook(
        command: &[&str],
        format: Option<HookFormat>,
        profile: Option<&str>,
    ) -> Result<Hook, HookError> {
        Hook::new(
            argv(command),
            HookTimeout::default(),
            format,
            profile.map(|p| assert_ok!(AwsProfile::parse(p))),
            BTreeMap::new(),
        )
    }

    #[test]
    fn the_program_must_be_absolute_or_under_home() {
        assert_ok!(hook(&["/usr/bin/true"], None, None));
        assert_ok!(hook(&["~/bin/tool", "arg"], None, None));
        for bad in ["true", "./tool", "bin/tool", "~", "~user/x"] {
            assert!(
                matches!(
                    assert_err!(hook(&[bad], None, None), "{bad}"),
                    HookError::ProgramNotAbsolute { .. }
                ),
                "{bad}"
            );
        }
        // Arguments are free text.
        assert_ok!(hook(&["/usr/bin/env", "relative", "-x"], None, None));
    }

    #[test]
    fn the_aws_format_and_a_profile_come_together() {
        assert_ok!(hook(
            &["/x"],
            Some(HookFormat::AwsCredentialProcess),
            Some("p")
        ));
        assert!(matches!(
            assert_err!(hook(&["/x"], Some(HookFormat::AwsCredentialProcess), None)),
            HookError::FormatProfileMismatch { .. }
        ));
        assert!(matches!(
            assert_err!(hook(&["/x"], None, Some("p"))),
            HookError::FormatProfileMismatch { .. }
        ));
    }

    #[test]
    fn errors_name_the_field_and_escape_what_they_echo() {
        let shown = assert_err!(HookName::parse("a\u{1b}[2Jb")).to_string();
        assert!(
            shown.contains("hook name") && !shown.contains('\u{1b}'),
            "{shown:?}"
        );
    }
}
