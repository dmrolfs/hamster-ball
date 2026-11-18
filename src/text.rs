// ABOUTME: Escaping for user-controlled text that appears in error messages and displays.
// ABOUTME: A hostile config key or path must not be able to reach the terminal as raw escape sequences.
//! Text helpers shared by every `Display` implementation that prints user-controlled input.

use std::fmt;

/// Wraps text so that control characters are printed as escapes instead of raw bytes.
///
/// A path or key containing `ESC [ 2 J` or a newline would otherwise be able to clear the
/// screen or forge extra lines in an error message.
///
/// # Examples
/// ```
/// use hamster_ball::text::Escaped;
/// assert_eq!(Escaped("a\nb").to_string(), "a\\nb");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct Escaped<'a>(pub &'a str);

impl fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for c in self.0.chars() {
            if c.is_control() {
                write!(f, "{}", c.escape_default())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn escaped_leaves_plain_text_alone() {
        assert_eq!(Escaped("fs.write/src ok").to_string(), "fs.write/src ok");
    }

    #[test]
    fn escaped_replaces_newline_and_tab() {
        assert_eq!(Escaped("a\nb\tc").to_string(), "a\\nb\\tc");
    }

    #[test]
    fn escaped_replaces_ansi_escape_sequences() {
        assert_eq!(Escaped("\u{1b}[2J").to_string(), "\\u{1b}[2J");
    }

    #[test]
    fn escaped_replaces_nul_and_delete() {
        assert_eq!(Escaped("a\0b\u{7f}").to_string(), "a\\u{0}b\\u{7f}");
    }

    #[test]
    fn escaped_keeps_unicode_text_and_quotes() {
        assert_eq!(Escaped("caf\u{e9} \"x\"").to_string(), "caf\u{e9} \"x\"");
    }
}
