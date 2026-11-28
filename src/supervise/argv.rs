// ABOUTME: Reversible command-field quoting without shell execution or expansion.
// ABOUTME: Spaces separate words; quotes and backslashes preserve literal argument boundaries.

use snafu::Snafu;

#[derive(Debug, Clone, PartialEq, Eq, Snafu)]
/// Why the command field cannot be split into literal arguments.
pub enum SplitError {
    /// An opening quote has no closing quote.
    #[snafu(display("close the {quote} quote in the command"))]
    UnclosedQuote {
        /// The unmatched quote character.
        quote: char,
    },
    /// A backslash has no following character.
    #[snafu(display("the command ends with a backslash"))]
    TrailingBackslash,
}

pub(super) fn split(text: &str) -> Result<Vec<String>, SplitError> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut quote = None;
    let mut started = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some(q), c) if c == q => quote = None,
            (None, '\'' | '"') => {
                quote = Some(c);
                started = true;
            }
            (None | Some('"'), '\\') => {
                let next = chars.next().ok_or(SplitError::TrailingBackslash)?;
                if quote == Some('"') && !matches!(next, '"' | '\\') {
                    word.push('\\');
                }
                word.push(next);
                started = true;
            }
            (None, c) if c.is_whitespace() => {
                if started {
                    words.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            _ => {
                word.push(c);
                started = true;
            }
        }
    }
    if let Some(quote) = quote {
        return Err(SplitError::UnclosedQuote { quote });
    }
    if started {
        words.push(word);
    }
    Ok(words)
}

pub(super) fn join(words: &[String]) -> String {
    words
        .iter()
        .map(|word| {
            if !word.is_empty()
                && !word
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '\\'))
            {
                word.clone()
            } else {
                format!("'{}'", word.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    #[test]
    fn quoting_is_literal_and_empty_arguments_survive() {
        assert_eq!(
            assert_ok!(split(r#"agent "two words" '' 'a'\''b' c\ d $HOME ~ * ; |"#)),
            [
                "agent",
                "two words",
                "",
                "a'b",
                "c d",
                "$HOME",
                "~",
                "*",
                ";",
                "|"
            ]
        );
        assert_eq!(
            split("'bad"),
            Err(SplitError::UnclosedQuote { quote: '\'' })
        );
        assert_eq!(split("bad\\"), Err(SplitError::TrailingBackslash));
    }

    proptest! {
        #[test]
        fn recalled_arguments_roundtrip(words in prop::collection::vec(".*", 0..20)) {
            prop_assert_eq!(split(&join(&words)), Ok(words));
        }
    }
}
