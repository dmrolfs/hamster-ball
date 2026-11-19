// ABOUTME: Escaping for user-controlled text that appears in error messages and displays.
// ABOUTME: A hostile config key or path must not be able to reach the terminal as raw escape sequences.
//! Text helpers shared by every `Display` implementation that prints user-controlled input.

use std::fmt;

/// Reports whether `c` must be escaped to keep text safe to print to a terminal.
///
/// Beyond `char::is_control` (the Cc category), this also catches characters that are not
/// "control" by that definition but can still reorder or hide text: bidirectional overrides
/// and isolates, zero-width characters, the line and paragraph separators, and the BOM. A
/// hostile host name or path containing `U+202E` (right-to-left override), for example, could
/// otherwise make an error message display in a misleading order.
pub(crate) fn needs_escaping(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{200b}'..='\u{200f}' // zero-width space/joiners, LRM/RLM
            | '\u{2028}' | '\u{2029}' // line/paragraph separator
            | '\u{202a}'..='\u{202e}' // bidi embedding/override
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{feff}' // BOM / zero-width no-break space
        )
}

/// Wraps text so that control and text-reordering characters are printed as escapes instead of
/// raw bytes.
///
/// A path or key containing `ESC [ 2 J`, a newline, or a right-to-left override would otherwise
/// be able to clear the screen, forge extra lines, or visually reorder an error message.
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
            if needs_escaping(c) {
                write!(f, "{}", c.escape_default())?;
            } else {
                write!(f, "{c}")?;
            }
        }
        Ok(())
    }
}

/// Like [`Escaped`], but also truncates long text so a single untrusted value cannot flood an
/// error message. Truncation happens on a `char` boundary; a truncated value ends with `...`.
#[derive(Debug, Clone, Copy)]
pub struct EscapedBounded<'a> {
    text: &'a str,
    max_chars: usize,
}

impl<'a> EscapedBounded<'a> {
    /// Wraps `text`, keeping at most `max_chars` characters.
    #[must_use]
    pub fn new(text: &'a str, max_chars: usize) -> Self {
        Self { text, max_chars }
    }
}

impl fmt::Display for EscapedBounded<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut chars = self.text.chars();
        let truncated = chars.by_ref().take(self.max_chars).collect::<String>();
        write!(f, "{}", Escaped(&truncated))?;
        if chars.next().is_some() {
            f.write_str("...")?;
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

    #[test]
    fn escaped_replaces_bidi_override_and_isolate_characters() {
        for bad in [
            '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}', '\u{2066}', '\u{2069}',
        ] {
            let shown = Escaped(&bad.to_string()).to_string();
            assert!(!shown.contains(bad), "{bad:04x?} was not escaped");
        }
    }

    #[test]
    fn escaped_replaces_zero_width_characters_and_separators() {
        for bad in [
            '\u{200b}', '\u{200e}', '\u{200f}', '\u{2028}', '\u{2029}', '\u{feff}',
        ] {
            let shown = Escaped(&bad.to_string()).to_string();
            assert!(!shown.contains(bad), "{bad:04x?} was not escaped");
        }
    }

    #[test]
    fn escaped_bounded_passes_short_text_through_unchanged() {
        assert_eq!(EscapedBounded::new("short", 64).to_string(), "short");
    }

    #[test]
    fn escaped_bounded_truncates_long_text_with_an_ellipsis() {
        let long = "a".repeat(100);
        let shown = EscapedBounded::new(&long, 10).to_string();
        assert_eq!(shown, format!("{}...", "a".repeat(10)));
    }

    #[test]
    fn escaped_bounded_escapes_before_truncating() {
        let shown = EscapedBounded::new("a\u{1b}[2Jb", 3).to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }

    #[test]
    fn escaped_bounded_truncates_on_a_char_boundary() {
        let text = "caf\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}";
        let shown = EscapedBounded::new(text, 4).to_string();
        assert_eq!(shown, "caf\u{e9}...");
    }
}
