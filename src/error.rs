// ABOUTME: Crate-level Error that transparently wraps every module error, plus the tests that pin the error conventions.
// ABOUTME: Convention: a variant's Display says what happened at its own level and never interpolates its source.
//! The crate-level [`Error`] and the conventions every error in this crate follows.

use snafu::Snafu;

use crate::approval::{ApproveError, GateError, StoreError};
use crate::config::{
    ConfigTextError, DiscoverError, EntryError, ExtendsError, LoadError, MergeErrors, ProjectError,
    ResolveErrors,
};
use crate::explain::ExplainError;
use crate::policy::{
    ArgWordError, ArgvError, ContainerLabelError, ContainerNameError, EnvNameError, EnvValueError,
    ExtendTargetError, GlobTailError, HostNameError, HostPatternError, HostRuleError, McpNameError,
    PathError, PathPatternError, PortError, PresetNameError, RefTextError, RootError,
};
use crate::seatbelt::RenderError;
use crate::session::{GuardError, HelperError, RunError};
use crate::system::{EnvironmentError, FloorError, HomeError, UserConfigError};

/// Any error produced by this crate.
///
/// Each variant is transparent: `Display` and `source()` come from the wrapped error, so
/// reporters that walk the source chain do not print a message twice.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    /// `hb warm` was asked for a server that does not exist.
    #[snafu(transparent)]
    UnknownServer {
        /// The underlying error.
        source: crate::warm::UnknownServer,
    },

    /// `hb warm` could not start a server's probe.
    #[snafu(transparent)]
    Warm {
        /// The underlying error.
        source: crate::warm::StartError,
    },

    /// Asking for approval of a project's config failed.
    #[snafu(transparent)]
    Gate {
        /// The underlying error.
        source: GateError,
    },

    /// The approval store could not be changed.
    #[snafu(transparent)]
    Store {
        /// The underlying error.
        source: StoreError,
    },

    /// `hb approve` was started where it must not be.
    #[snafu(transparent)]
    Approve {
        /// The underlying error.
        source: ApproveError,
    },

    /// A path was not in canonical form.
    #[snafu(transparent)]
    Path {
        /// The underlying error.
        source: PathError,
    },

    /// A project root was too broad.
    #[snafu(transparent)]
    Root {
        /// The underlying error.
        source: RootError,
    },

    /// A port number was out of range.
    #[snafu(transparent)]
    Port {
        /// The underlying error.
        source: PortError,
    },

    /// An environment variable name was invalid.
    #[snafu(transparent)]
    EnvName {
        /// The underlying error.
        source: EnvNameError,
    },

    /// An environment variable value was invalid.
    #[snafu(transparent)]
    EnvValue {
        /// The underlying error.
        source: EnvValueError,
    },

    /// A container name was invalid.
    #[snafu(transparent)]
    ContainerName {
        /// The underlying error.
        source: ContainerNameError,
    },

    /// A hostname was invalid.
    #[snafu(transparent)]
    HostName {
        /// The underlying error.
        source: HostNameError,
    },

    /// A network allowlist pattern was invalid.
    #[snafu(transparent)]
    HostPattern {
        /// The underlying error.
        source: HostPatternError,
    },

    /// A network allowlist rule was invalid.
    #[snafu(transparent)]
    HostRule {
        /// The underlying error.
        source: HostRuleError,
    },

    /// A deny glob pattern was invalid.
    #[snafu(transparent)]
    PathPattern {
        /// The underlying error.
        source: PathPatternError,
    },

    /// A glob tail was invalid.
    #[snafu(transparent)]
    GlobTail {
        /// The underlying error.
        source: GlobTailError,
    },

    /// A container label selector was invalid.
    #[snafu(transparent)]
    ContainerLabel {
        /// The underlying error.
        source: ContainerLabelError,
    },

    /// A command-line word was invalid.
    #[snafu(transparent)]
    ArgWord {
        /// The underlying error.
        source: ArgWordError,
    },

    /// An argument vector was invalid.
    #[snafu(transparent)]
    Argv {
        /// The underlying error.
        source: ArgvError,
    },

    /// An MCP server name was invalid.
    #[snafu(transparent)]
    McpName {
        /// The underlying error.
        source: McpNameError,
    },

    /// An `extends` or `guard.exceptions` value was invalid.
    #[snafu(transparent)]
    RefText {
        /// The underlying error.
        source: RefTextError,
    },

    /// The home directory could not be established.
    #[snafu(transparent)]
    Home {
        /// The underlying error.
        source: HomeError,
    },

    /// A config file could not be read.
    #[snafu(transparent)]
    ConfigText {
        /// The underlying error.
        source: ConfigTextError,
    },

    /// No usable project root was found.
    #[snafu(transparent)]
    Discover {
        /// The underlying error.
        source: DiscoverError,
    },

    /// One config entry was invalid.
    #[snafu(transparent)]
    Entry {
        /// The underlying error.
        source: EntryError,
    },

    /// A config file had invalid entries.
    #[snafu(transparent)]
    Resolve {
        /// The underlying error.
        source: ResolveErrors,
    },

    /// A preset name was invalid.
    #[snafu(transparent)]
    PresetName {
        /// The underlying error.
        source: PresetNameError,
    },

    /// An `extends` entry could not be classified.
    #[snafu(transparent)]
    ExtendTarget {
        /// The underlying error.
        source: ExtendTargetError,
    },

    /// An `extends` entry could not be resolved to something to load.
    #[snafu(transparent)]
    Extends {
        /// The underlying error.
        source: ExtendsError,
    },

    /// The config files could not be merged.
    #[snafu(transparent)]
    Merge {
        /// The underlying error.
        source: MergeErrors,
    },

    /// The project could not be found or loaded.
    #[snafu(transparent)]
    Project {
        /// The underlying error.
        source: ProjectError,
    },

    /// The config closure could not be loaded.
    #[snafu(transparent)]
    Load {
        /// The underlying error.
        source: LoadError,
    },

    /// A profile could not be rendered.
    #[snafu(transparent)]
    Render {
        /// The underlying error.
        source: RenderError,
    },

    /// A run could not start.
    #[snafu(transparent)]
    Run {
        /// The underlying error.
        source: RunError,
    },

    /// The child helper could not hand over to `sandbox-exec`.
    #[snafu(transparent)]
    Helper {
        /// The underlying error.
        source: HelperError,
    },

    /// The cleanup guard process failed.
    #[snafu(transparent)]
    Guard {
        /// The underlying error.
        source: GuardError,
    },

    /// `hb explain` failed.
    #[snafu(transparent)]
    Explain {
        /// The underlying error.
        source: ExplainError,
    },

    /// The process environment could not be read.
    #[snafu(transparent)]
    Environment {
        /// The underlying error.
        source: EnvironmentError,
    },

    /// The floor could not be built.
    #[snafu(transparent)]
    Floor {
        /// The underlying error.
        source: FloorError,
    },

    /// The user's config directory could not be located or initialized.
    #[snafu(transparent)]
    UserConfig {
        /// The underlying error.
        source: UserConfigError,
    },
}

/// Test helpers that enforce the crate's error conventions.
#[cfg(test)]
pub(crate) mod conventions {
    use std::error::Error as StdError;

    /// Asserts that `err`'s own `Display` does not repeat the text of any error in its source chain.
    ///
    /// A chain printer such as `snafu::Report` shows each source on its own line, so a parent
    /// that already interpolated `{source}` would print the cause twice.
    pub(crate) fn assert_display_excludes_sources(err: &dyn StdError) {
        let own = err.to_string();
        let mut next = err.source();
        while let Some(source) = next {
            let text = source.to_string();
            assert!(
                text.is_empty() || !own.contains(&text),
                "Display {own:?} repeats its source {text:?}; remove `{{source}}` from the display attribute"
            );
            next = source.source();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::conventions::assert_display_excludes_sources;
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use snafu::{Report, ResultExt};
    use std::error::Error as StdError;

    use crate::policy::{Argv, CanonicalPath, EnvName, Port};

    /// A local error that follows the convention: context only, no `{source}`.
    #[derive(Debug, Snafu)]
    enum Good {
        #[snafu(display("could not read the config file"))]
        Read { source: std::io::Error },
    }

    /// A local error that breaks the convention, to prove the helper notices.
    #[derive(Debug, Snafu)]
    enum Bad {
        #[snafu(display("could not fetch the config file: {source}"))]
        Fetch { source: std::io::Error },
    }

    fn io_failure() -> Result<(), std::io::Error> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no such file",
        ))
    }

    // ====================================================================================
    // The convention itself
    // ====================================================================================

    #[test]
    fn display_never_contains_source_text_for_a_conforming_error() {
        let err = assert_err!(io_failure().context(ReadSnafu));
        assert_display_excludes_sources(&err);
    }

    #[test]
    #[should_panic(expected = "repeats its source")]
    fn the_convention_helper_catches_an_error_that_interpolates_its_source() {
        let err = assert_err!(io_failure().map_err(|source| Bad::Fetch { source }));
        assert_display_excludes_sources(&err);
    }

    #[test]
    fn source_chain_walks_to_the_io_error() {
        let err = assert_err!(io_failure().context(ReadSnafu));
        let source = err.source();
        assert!(source.is_some_and(|s| s.to_string() == "no such file"));
    }

    #[test]
    fn report_prints_each_cause_once() {
        let err = assert_err!(io_failure().context(ReadSnafu));
        let report = Report::from_error(err).to_string();
        assert_eq!(report.matches("no such file").count(), 1, "{report}");
    }

    // ====================================================================================
    // The crate Error
    // ====================================================================================

    #[test]
    fn crate_error_transparent_preserves_inner_display() {
        let inner = assert_err!(Port::try_from(0));
        let expected = inner.to_string();
        let outer = Error::from(inner);
        assert_eq!(outer.to_string(), expected);
    }

    #[test]
    fn every_module_error_converts_into_the_crate_error() {
        let path: Error = assert_err!(CanonicalPath::from_canonical("relative")).into();
        let env: Error = assert_err!(EnvName::parse("1x")).into();
        assert!(matches!(path, Error::Path { .. }));
        assert!(matches!(env, Error::EnvName { .. }));
    }

    #[test]
    fn every_public_error_type_converts_into_the_crate_error_and_keeps_its_text() {
        use crate::policy::{ArgWord, ContainerLabel, ExtendRef, GlobTail, HomeDir, McpName};

        let errors: Vec<Error> = vec![
            assert_err!(ContainerLabel::parse("")).into(),
            assert_err!(ArgWord::parse("a\0b")).into(),
            assert_err!(Argv::parse(&[])).into(),
            assert_err!(ExtendRef::parse("")).into(),
            assert_err!(McpName::parse("")).into(),
            assert_err!(GlobTail::parse(&[".."])).into(),
            HomeError::RunningAsRoot.into(),
            assert_err!(crate::config::ConfigText::read_with(
                "/nonexistent/hb.toml",
                crate::origin::Layer::Project,
                crate::config::SymlinkPolicy::Refuse
            ))
            .into(),
            assert_err!(crate::config::discover(
                std::path::Path::new("/nonexistent/dir"),
                &HomeDir::new(assert_ok!(CanonicalPath::from_canonical("/Users/x")))
            ))
            .into(),
            EntryError::TooManyEntries { count: 5, max: 4 }.into(),
            ResolveErrors {
                errors: Vec::new(),
                truncated: false,
            }
            .into(),
            assert_err!(crate::policy::PresetName::parse("")).into(),
            assert_err!(assert_ok!(crate::policy::ExtendRef::parse("~x")).target()).into(),
            ExtendsError::BuiltinExtendsFile {
                entry: assert_ok!(crate::policy::ExtendRef::parse("./x.toml")),
            }
            .into(),
            MergeErrors {
                errors: Vec::new(),
                truncated: false,
            }
            .into(),
            LoadError::TooManyFiles.into(),
            FloorError::GitUnsupported {
                path: "/x/.git".to_owned(),
            }
            .into(),
            UserConfigError::BaseExists {
                path: std::path::PathBuf::from("/x"),
            }
            .into(),
        ];
        assert_eq!(errors.len(), 18);
        for error in &errors {
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
        assert!(matches!(errors[0], Error::ContainerLabel { .. }));
        assert!(matches!(errors[4], Error::McpName { .. }));
        assert!(matches!(errors[6], Error::Home { .. }));
        assert!(matches!(errors[9], Error::Entry { .. }));
        assert!(matches!(errors[10], Error::Resolve { .. }));
        assert!(matches!(errors[11], Error::PresetName { .. }));
        assert!(matches!(errors[12], Error::ExtendTarget { .. }));
        assert!(matches!(errors[13], Error::Extends { .. }));
        assert!(matches!(errors[14], Error::Merge { .. }));
        assert!(matches!(errors[15], Error::Load { .. }));
        assert!(matches!(errors[16], Error::Floor { .. }));
        assert!(matches!(errors[17], Error::UserConfig { .. }));
    }

    #[test]
    fn module_errors_follow_the_display_convention() {
        assert_display_excludes_sources(&assert_err!(CanonicalPath::from_canonical("relative")));
        assert_display_excludes_sources(&assert_err!(Port::try_from(-1)));
        assert_display_excludes_sources(&assert_err!(EnvName::parse("")));
        assert_ok!(Port::try_from(1));
    }
}
