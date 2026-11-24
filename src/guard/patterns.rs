// ABOUTME: The secrets guard's name patterns, as a name test for the host side and as Seatbelt regexes per guard root.
// ABOUTME: Both come from one table and a test checks they agree; letters are folded so a case-sensitive volume is covered too.
//! The name patterns of the guard (design section 8).
//!
//! A file is guarded when its name is `.env` or `.env.*`, `*secret*.{yaml,yml,json,toml}`,
//! `*.pem`, `*.key` or `*.p12`. The same rule is written twice: [`is_guarded`] for code that
//! walks the project, and regexes for the profile. Names are compared without regard to case,
//! because Seatbelt does so on APFS and a creator of `.ENV` must not get past the deny.

use crate::seatbelt::quote;

/// Extensions of `*secret*.<ext>` files.
const SECRET_EXTENSIONS: &[&str] = &["yaml", "yml", "json", "toml"];
/// Extensions of key and certificate files.
const KEY_EXTENSIONS: &[&str] = &["pem", "key", "p12"];
/// Suffixes of templates, which stay editable.
pub const TEMPLATE_SUFFIXES: &[&str] = &["example", "sample", "template"];
/// Directory names whose key and secret-named files are re-allowed (with pins on secret directories).
pub const DEPENDENCY_DIRS: &[&str] = &["node_modules", "site-packages"];

/// The patterns in words, for `hb explain` and the doctor.
pub const GUARDED_PATTERNS: &[&str] = &[
    ".env",
    ".env.*",
    "*secret*.yaml",
    "*secret*.yml",
    "*secret*.json",
    "*secret*.toml",
    "*.pem",
    "*.key",
    "*.p12",
];

/// Whether `name` (one path component) is a guarded name.
#[must_use]
pub fn is_guarded(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == ".env" || lower.starts_with(".env.") {
        return true;
    }
    let Some((stem, extension)) = lower.rsplit_once('.') else {
        return false;
    };
    KEY_EXTENSIONS.contains(&extension)
        || (SECRET_EXTENSIONS.contains(&extension) && stem.contains("secret"))
}

/// Whether `name` ends with a template suffix.
#[must_use]
pub fn is_template(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower
        .rsplit_once('.')
        .is_some_and(|(_, extension)| TEMPLATE_SUFFIXES.contains(&extension))
}

/// Whether `name` is a key or secret-named file that a dependency directory may hold.
///
/// Every guarded name except the `.env` family.
#[must_use]
pub fn is_dependency_exempt(name: &str) -> bool {
    is_guarded(name) && !is_env_family(name)
}

fn is_env_family(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == ".env" || lower.starts_with(".env.")
}

/// `text` with each ASCII letter as a two-letter class and everything else quoted.
fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 4);
    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            out.push('[');
            out.push(c.to_ascii_lowercase());
            out.push(c.to_ascii_uppercase());
            out.push(']');
        } else {
            out.push_str(&quote(&c.to_string()));
        }
    }
    out
}

fn alternation(words: &[&str]) -> String {
    let folded: Vec<String> = words.iter().map(|w| fold(w)).collect();
    format!("({})", folded.join("|"))
}

/// The regex text for the guarded names, without anchors.
fn names(include_env: bool) -> String {
    let mut alternatives = Vec::new();
    if include_env {
        alternatives.push(format!("{}(\\.[^/]*)?", fold(".env")));
    }
    alternatives.push(format!(
        "[^/]*{}[^/]*\\.{}",
        fold("secret"),
        alternation(SECRET_EXTENSIONS)
    ));
    alternatives.push(format!("[^/]*\\.{}", alternation(KEY_EXTENSIONS)));
    format!("({})", alternatives.join("|"))
}

/// Everything below `root` whose name is guarded.
#[must_use]
pub fn deny_regex(root: &str) -> String {
    format!(
        "^{}(/.*)?/{}$",
        quote(root.trim_end_matches('/')),
        names(true)
    )
}

/// Everything below `root` that ends with a template suffix.
#[must_use]
pub fn template_regex(root: &str) -> String {
    format!(
        "^{}(/.*)?\\.{}$",
        quote(root.trim_end_matches('/')),
        alternation(TEMPLATE_SUFFIXES)
    )
}

/// Key and secret-named files below a dependency directory below `root`.
#[must_use]
pub fn dependency_regex(root: &str) -> String {
    format!(
        "^{}(/.*)?/{}/(.*/)?{}$",
        quote(root.trim_end_matches('/')),
        alternation(DEPENDENCY_DIRS),
        names(false)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;
    use regex::Regex;

    const ROOT: &str = "/Users/me/proj.x";

    fn matches(pattern: &str, path: &str) -> bool {
        Regex::new(pattern).is_ok_and(|re| re.is_match(path))
    }

    /// Names with the answer each of the three predicates must give: guarded, template, exempt.
    const NAMES: &[(&str, bool, bool, bool)] = &[
        (".env", true, false, false),
        (".env.local", true, false, false),
        (".env.production", true, false, false),
        (".env.example", true, true, false),
        (".ENV", true, false, false),
        (".Env.Local", true, false, false),
        (".environment", false, false, false),
        ("env", false, false, false),
        (".envrc", false, false, false),
        ("a.env", false, false, false),
        ("prod.secrets.yaml", true, false, true),
        ("secret.json", true, false, true),
        ("db_secret_v2.toml", true, false, true),
        ("SECRETS.YML", true, false, true),
        ("secret.json.example", false, true, false),
        ("secrets.txt", false, false, false),
        ("secret.yaml.bak", false, false, false),
        ("secrets", false, false, false),
        ("config.yaml", false, false, false),
        ("server.pem", true, false, true),
        ("server.key", true, false, true),
        ("store.p12", true, false, true),
        ("SERVER.PEM", true, false, true),
        (".pem", true, false, true),
        ("server.pem.example", false, true, false),
        ("key", false, false, false),
        ("keyring.txt", false, false, false),
        ("monkey", false, false, false),
        ("id_rsa", false, false, false),
        ("cacert.pem", true, false, true),
        ("notes.md.sample", false, true, false),
        ("x.template", false, true, false),
        ("x.templates", false, false, false),
    ];

    #[test]
    fn the_name_predicates_give_the_expected_answers() {
        for (name, guarded, template, exempt) in NAMES {
            assert_eq!(is_guarded(name), *guarded, "guarded: {name}");
            assert_eq!(is_template(name), *template, "template: {name}");
            assert_eq!(is_dependency_exempt(name), *exempt, "exempt: {name}");
        }
    }

    #[test]
    fn the_deny_regex_agrees_with_the_name_predicate_at_any_depth() {
        let deny = deny_regex(ROOT);
        for (name, guarded, _, _) in NAMES {
            for dir in ["", "/a", "/a/b.c/d"] {
                let path = format!("{ROOT}{dir}/{name}");
                assert_eq!(matches(&deny, &path), *guarded, "{path}");
            }
        }
    }

    #[test]
    fn the_deny_regex_covers_only_the_root_and_names_the_last_component() {
        let deny = deny_regex(ROOT);
        assert!(!matches(&deny, "/Users/me/other/.env"));
        assert!(!matches(&deny, "/Users/me/proj.x2/.env"));
        assert!(!matches(&deny, "/Users/me/projXx/.env"));
        assert!(!matches(&deny, &format!("{ROOT}/.env/readme")));
        assert!(!matches(&deny, &format!("{ROOT}/dir.key/readme")));
        assert!(matches(&deny, &format!("{ROOT}/dir/.env")));
    }

    #[test]
    fn the_template_regex_agrees_with_the_name_predicate_and_stays_inside_the_root() {
        let template = template_regex(ROOT);
        for (name, _, is_template, _) in NAMES {
            let path = format!("{ROOT}/sub/{name}");
            assert_eq!(matches(&template, &path), *is_template, "{path}");
        }
        assert!(!matches(&template, "/etc/passwd.example"));
        assert!(!matches(&template, "/Users/me/other/.env.example"));
    }

    #[test]
    fn the_dependency_regex_needs_a_dependency_directory_and_never_exempts_env_files() {
        let dependency = dependency_regex(ROOT);
        for (name, _, _, exempt) in NAMES {
            for dir in [
                "node_modules",
                "a/node_modules/b/c",
                ".venv/lib/python3.14/site-packages/pkg",
            ] {
                let path = format!("{ROOT}/{dir}/{name}");
                assert_eq!(matches(&dependency, &path), *exempt, "{path}");
            }
            let outside = format!("{ROOT}/vendor/{name}");
            assert!(!matches(&dependency, &outside), "{outside}");
        }
        assert!(!matches(
            &dependency,
            &format!("{ROOT}/node_modules_evil/x.pem")
        ));
        assert!(!matches(
            &dependency,
            &format!("{ROOT}/xnode_modules/x.pem")
        ));
        assert!(!matches(&dependency, &format!("{ROOT}/node_modules")));
        assert!(!matches(&dependency, "/Users/me/other/node_modules/x.pem"));
    }

    #[test]
    fn the_root_is_quoted_so_a_hostile_directory_name_matches_only_itself() {
        let deny = deny_regex("/p/a(b|c)+[d]");
        assert!(matches(&deny, "/p/a(b|c)+[d]/.env"));
        assert!(!matches(&deny, "/p/ab+d/.env"));
    }

    #[test]
    fn the_regexes_are_the_same_for_a_root_with_a_trailing_slash() {
        assert_eq!(deny_regex("/p/"), deny_regex("/p"));
        assert_eq!(template_regex("/p/"), template_regex("/p"));
        assert_eq!(dependency_regex("/p/"), dependency_regex("/p"));
    }

    #[test]
    fn the_pattern_words_cover_every_guarded_form() {
        assert_eq!(GUARDED_PATTERNS.len(), 9);
        assert!(GUARDED_PATTERNS.contains(&".env.*"));
    }
}
