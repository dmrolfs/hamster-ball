// ABOUTME: Crate-level Error that transparently wraps every module error, plus the tests that pin the error conventions.
// ABOUTME: Convention: a variant's Display says what happened at its own level and never interpolates its source.
//! The crate-level [`Error`] and the conventions every error in this crate follows.

use snafu::Snafu;

use crate::policy::{
    ContainerNameError, EnvNameError, EnvValueError, PathError, PortError, RootError,
};

/// Any error produced by this crate.
///
/// Each variant is transparent: `Display` and `source()` come from the wrapped error, so
/// reporters that walk the source chain do not print a message twice.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
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

    use crate::policy::{CanonicalPath, EnvName, Port};

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
    fn module_errors_follow_the_display_convention() {
        assert_display_excludes_sources(&assert_err!(CanonicalPath::from_canonical("relative")));
        assert_display_excludes_sources(&assert_err!(Port::try_from(-1)));
        assert_display_excludes_sources(&assert_err!(EnvName::parse("")));
        assert_ok!(Port::try_from(1));
    }
}
