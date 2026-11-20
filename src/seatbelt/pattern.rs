// ABOUTME: Builds the whole regexes for glob tails and children-only extents, quoting every literal character.
// ABOUTME: A regex is passed to the profile as a -D parameter, so its text never needs to be a safe SBPL string.
//! Regex construction.
//!
//! A deny with a glob tail (`secrets/*.yaml`, `.git/modules/**/hooks`) or a children-only extent
//! cannot be a `subpath`. It becomes `(regex (param "G0"))` where `G0` is built here. The base
//! path and every literal part of the glob are quoted, so a directory named `a(b|c)+` matches
//! only itself. Seatbelt compares names case-insensitively on APFS, which the regex inherits.

use crate::policy::{GlobSegment, GlobTail};

/// Characters with a meaning in a regular expression.
const SPECIAL: &[char] = &[
    '\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}',
];

/// Escapes `text` so it matches only itself.
pub(crate) fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 4);
    for c in text.chars() {
        if SPECIAL.contains(&c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// `^<base>`, where a base of `/` is not followed by a second slash.
fn anchored_base(base: &str) -> String {
    format!("^{}", quote(base.trim_end_matches('/')))
}

/// Matches the direct children of `base` and nothing else.
pub(crate) fn children_regex(base: &str) -> String {
    format!("{}/[^/]+$", anchored_base(base))
}

/// Matches whatever the glob `tail` matches below `base`, and everything beneath a match.
pub(crate) fn tail_regex(base: &str, tail: &GlobTail) -> String {
    let mut out = anchored_base(base);
    for segment in tail.segments() {
        match segment {
            GlobSegment::AnyDepth => out.push_str("(/[^/]+)*"),
            GlobSegment::Segment(text) => {
                out.push('/');
                for c in text.chars() {
                    match c {
                        '*' => out.push_str("[^/]*"),
                        '?' => out.push_str("[^/]"),
                        c if SPECIAL.contains(&c) => {
                            out.push('\\');
                            out.push(c);
                        }
                        c => out.push(c),
                    }
                }
            }
        }
    }
    out.push_str("(/.*)?$");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    fn tail(segments: &[&str]) -> GlobTail {
        assert_ok!(GlobTail::parse(segments))
    }

    #[test]
    fn quote_escapes_every_regex_metacharacter_and_nothing_else() {
        assert_eq!(quote("plain/path-1_x"), "plain/path-1_x");
        assert_eq!(quote("a.b"), "a\\.b");
        assert_eq!(quote("a|b"), "a\\|b");
        assert_eq!(quote("p+l*us"), "p\\+l\\*us");
        assert_eq!(quote("[br]acket"), "\\[br\\]acket");
        assert_eq!(quote("(x){2}"), "\\(x\\)\\{2\\}");
        assert_eq!(quote("^$\\?"), "\\^\\$\\\\\\?");
        assert_eq!(quote("caf\u{e9} \u{1f600}"), "caf\u{e9} \u{1f600}");
    }

    #[test]
    fn children_regex_matches_one_level_below_the_base() {
        assert_eq!(children_regex("/Users/me/bin"), "^/Users/me/bin/[^/]+$");
        assert_eq!(children_regex("/a.b"), "^/a\\.b/[^/]+$");
    }

    #[test]
    fn children_of_the_filesystem_root_do_not_get_a_double_slash() {
        assert_eq!(children_regex("/"), "^/[^/]+$");
    }

    #[test]
    fn a_tail_becomes_segments_with_wildcards_translated_and_the_rest_quoted() {
        assert_eq!(
            tail_regex("/p", &tail(&["secrets", "*.yaml"])),
            "^/p/secrets/[^/]*\\.yaml(/.*)?$"
        );
        assert_eq!(
            tail_regex("/p/.git", &tail(&["modules", "**", "hooks"])),
            "^/p/\\.git/modules(/[^/]+)*/hooks(/.*)?$"
        );
        assert_eq!(tail_regex("/p", &tail(&["a?c"])), "^/p/a[^/]c(/.*)?$");
    }

    #[test]
    fn a_tail_under_the_root_has_a_single_slash_before_its_first_segment() {
        assert_eq!(
            tail_regex("/", &tail(&["*_history"])),
            "^/[^/]*_history(/.*)?$"
        );
    }

    #[test]
    fn a_hostile_base_is_quoted_in_both_forms() {
        let base = "/x/a(b|c)+[d]";
        assert!(children_regex(base).starts_with("^/x/a\\(b\\|c\\)\\+\\[d\\]/"));
        assert!(tail_regex(base, &tail(&["z"])).starts_with("^/x/a\\(b\\|c\\)\\+\\[d\\]/z"));
    }
}
