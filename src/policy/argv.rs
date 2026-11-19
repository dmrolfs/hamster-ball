// ABOUTME: ArgWord and Argv: validated command-line words for hooks and MCP servers, safe to exec without a shell.
// ABOUTME: A word has no NUL (C strings would silently truncate it) and a bounded length; a program name is non-empty.
//! Command-line words and argument vectors.

use snafu::{Snafu, ensure};

/// Longest accepted word, in bytes.
pub const MAX_ARG_BYTES: usize = 4096;
/// Most words accepted in one argument vector.
pub const MAX_ARGV_WORDS: usize = 64;

/// Why a string is not an acceptable command-line word.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ArgWordError {
    /// The word contains NUL, which would truncate it when passed to `exec`.
    #[snafu(display("command-line word contains a NUL character"))]
    ContainsNul,

    /// The word is longer than [`MAX_ARG_BYTES`].
    #[snafu(display("command-line word is {len} bytes long; the limit is {max}"))]
    TooLong {
        /// Length in bytes.
        len: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// A program name is empty.
    #[snafu(display("program name is empty"))]
    EmptyProgram,
}

/// Why a list of strings is not an acceptable argument vector.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ArgvError {
    /// There are no words, so there is no program to run.
    #[snafu(display("command is empty; the first word must be the program to run"))]
    Empty,

    /// There are more than [`MAX_ARGV_WORDS`] words.
    #[snafu(display("command has {count} words; the limit is {max}"))]
    TooManyWords {
        /// How many words there were.
        count: usize,
        /// The limit that was exceeded.
        max: usize,
    },

    /// One word is invalid.
    #[snafu(display("word {index} of the command is invalid"))]
    Word {
        /// Zero-based position of the word.
        index: usize,
        /// The underlying error.
        source: ArgWordError,
    },
}

/// One command-line word: any text without NUL, at most [`MAX_ARG_BYTES`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArgWord(String);

impl ArgWord {
    /// Parses an argument (which may be empty).
    ///
    /// # Errors
    /// [`ArgWordError::ContainsNul`] or [`ArgWordError::TooLong`].
    pub fn parse(word: &str) -> Result<Self, ArgWordError> {
        ensure!(!word.contains('\0'), ContainsNulSnafu);
        ensure!(
            word.len() <= MAX_ARG_BYTES,
            TooLongSnafu {
                len: word.len(),
                max: MAX_ARG_BYTES
            }
        );
        Ok(Self(word.to_owned()))
    }

    /// Parses a program name, which must also be non-empty.
    ///
    /// # Errors
    /// [`ArgWordError::EmptyProgram`], or any error from [`ArgWord::parse`].
    pub fn parse_program(word: &str) -> Result<Self, ArgWordError> {
        ensure!(!word.is_empty(), EmptyProgramSnafu);
        Self::parse(word)
    }

    /// The word as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A non-empty argument vector whose first word is a non-empty program name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Argv(Vec<ArgWord>);

impl Argv {
    /// Parses an argument vector.
    ///
    /// # Errors
    /// See [`ArgvError`].
    pub fn parse(words: &[String]) -> Result<Self, ArgvError> {
        ensure!(!words.is_empty(), EmptySnafu);
        ensure!(
            words.len() <= MAX_ARGV_WORDS,
            TooManyWordsSnafu {
                count: words.len(),
                max: MAX_ARGV_WORDS
            }
        );
        let mut parsed = Vec::with_capacity(words.len());
        for (index, word) in words.iter().enumerate() {
            let result = if index == 0 {
                ArgWord::parse_program(word)
            } else {
                ArgWord::parse(word)
            };
            parsed.push(snafu::ResultExt::context(result, WordSnafu { index })?);
        }
        Ok(Self(parsed))
    }

    /// The program to run.
    #[must_use]
    pub fn program(&self) -> &ArgWord {
        &self.0[0]
    }

    /// Every word, program first.
    #[must_use]
    pub fn words(&self) -> &[ArgWord] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn a_word_may_be_empty_or_contain_spaces_and_newlines() {
        assert_ok!(ArgWord::parse(""));
        assert_ok!(ArgWord::parse("a b\nc"));
    }

    #[test]
    fn a_word_rejects_nul() {
        let err = assert_err!(ArgWord::parse("a\0b"));
        assert!(matches!(err, ArgWordError::ContainsNul), "{err:?}");
    }

    #[test]
    fn a_word_accepts_the_limit_and_rejects_one_over() {
        assert_ok!(ArgWord::parse(&"a".repeat(MAX_ARG_BYTES)));
        let err = assert_err!(ArgWord::parse(&"a".repeat(MAX_ARG_BYTES + 1)));
        assert!(
            matches!(err, ArgWordError::TooLong { len, max } if len == MAX_ARG_BYTES + 1 && max == MAX_ARG_BYTES),
            "{err:?}"
        );
    }

    #[test]
    fn a_program_name_must_not_be_empty() {
        assert_ok!(ArgWord::parse_program("uvx"));
        let err = assert_err!(ArgWord::parse_program(""));
        assert!(matches!(err, ArgWordError::EmptyProgram), "{err:?}");
    }

    #[test]
    fn argv_keeps_the_program_first_and_every_word_in_order() {
        let argv = assert_ok!(Argv::parse(&words(&["echo", "", "hi there"])));
        assert_eq!(argv.program().as_str(), "echo");
        let all: Vec<&str> = argv.words().iter().map(ArgWord::as_str).collect();
        assert_eq!(all, vec!["echo", "", "hi there"]);
    }

    #[test]
    fn argv_rejects_an_empty_vector() {
        let err = assert_err!(Argv::parse(&[]));
        assert!(matches!(err, ArgvError::Empty), "{err:?}");
    }

    #[test]
    fn argv_rejects_an_empty_program_name() {
        let err = assert_err!(Argv::parse(&words(&["", "x"])));
        assert!(
            matches!(
                err,
                ArgvError::Word {
                    index: 0,
                    source: ArgWordError::EmptyProgram
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn argv_reports_which_word_has_a_nul() {
        let err = assert_err!(Argv::parse(&words(&["ok", "fine", "b\0ad"])));
        assert!(
            matches!(
                err,
                ArgvError::Word {
                    index: 2,
                    source: ArgWordError::ContainsNul
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn argv_accepts_the_word_limit_and_rejects_one_over() {
        let at_limit = vec!["x".to_owned(); MAX_ARGV_WORDS];
        assert_ok!(Argv::parse(&at_limit));
        let over = vec!["x".to_owned(); MAX_ARGV_WORDS + 1];
        let err = assert_err!(Argv::parse(&over));
        assert!(
            matches!(err, ArgvError::TooManyWords { count, max } if count == MAX_ARGV_WORDS + 1 && max == MAX_ARGV_WORDS),
            "{err:?}"
        );
    }

    #[test]
    fn argv_error_display_names_the_word_not_its_text() {
        let err = assert_err!(Argv::parse(&words(&["ok", "secret\0value"])));
        let shown = err.to_string();
        assert!(shown.contains("word 1"), "{shown:?}");
        assert!(!shown.contains("secret"), "{shown:?}");
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
