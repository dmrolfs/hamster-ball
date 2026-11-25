// ABOUTME: What `hb doctor` says about MCP servers that cannot start from hb's offline cache, and the fix for each.
// ABOUTME: Never warmed or changed, a moving version tag, a git source without a full revision, a launcher `[env] tools` lacks.
//! The doctor's MCP section (design 10, hb-ghd.7.4).
//!
//! Only servers that start a bare `uvx` or `npx` are looked at (the ones `hb warm` can warm). The
//! text names a server and the one argument that is the problem, never the others: an argument can
//! carry a token, so `hb explain` hides them too. A URL is shown without its `user:password@`.

use std::fmt::Write as _;

use super::stamp::{Standing, WarmStore};
use crate::config::Policy;
use crate::policy::CanonicalPath;
use crate::text::EscapedBounded;

/// The longest flagged argument shown.
const MAX_SHOWN: usize = 160;
/// A full git revision.
const FULL_REVISION: usize = 40;

/// What is wrong with one argument.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgProblem {
    /// A package spec that ends in a tag that moves (`pkg@latest`).
    Moving(String),
    /// A `git+` source that does not end in a full revision, shown without credentials.
    UnpinnedGit(String),
}

/// One thing wrong with one server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Finding {
    /// Never warmed.
    NotWarmed,
    /// Warmed, but with another command or arguments.
    Changed,
    /// An argument that cannot give a stable offline start.
    Arg(ArgProblem),
    /// The server starts this launcher and `[env] tools` does not list it.
    LauncherNotListed(String),
}

/// A finding and its server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The `[mcp.<name>]` name.
    pub server: String,
    /// What is wrong.
    pub finding: Finding,
}

fn is_full_revision(text: &str) -> bool {
    text.len() == FULL_REVISION && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Whether `tag` (what follows the last `@` of a package spec) names a release channel and not a
/// version or a range: it starts with a letter, and `v1` is a version.
fn is_dist_tag(tag: &str) -> bool {
    let mut chars = tag.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    let version_like = first == 'v' && chars.clone().next().is_some_and(|c| c.is_ascii_digit());
    first.is_ascii_alphabetic()
        && !version_like
        && tag
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// `url` without `user[:password]@`.
fn without_credentials(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_owned();
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    match authority.rfind('@') {
        Some(at) => format!("{scheme}{}{}", &authority[at + 1..], &rest[authority_end..]),
        None => url.to_owned(),
    }
}

/// Whether a `git+` URL ends in a full revision: `@<40 hex>` (uv) or `#<40 hex>` (npm), where a
/// `#key=value` fragment after a pinned `@` revision is allowed.
fn git_is_pinned(url: &str) -> bool {
    let (main, fragment) = url.split_once('#').map_or((url, ""), |(m, f)| (m, f));
    if is_full_revision(fragment) {
        return true;
    }
    let last = main.rsplit('/').next().unwrap_or_default();
    last.rsplit_once('@')
        .is_some_and(|(_, revision)| is_full_revision(revision))
}

/// The problems of one argument.
#[must_use]
pub fn arg_problems(arg: &str) -> Vec<ArgProblem> {
    let value = if arg.starts_with("--") {
        arg.split_once('=').map_or(arg, |(_, value)| value)
    } else {
        arg
    };
    if let Some(at) = value.find("git+") {
        let url = value[at..].split_whitespace().next().unwrap_or_default();
        return if git_is_pinned(url) {
            Vec::new()
        } else {
            vec![ArgProblem::UnpinnedGit(without_credentials(url))]
        };
    }
    if value.contains("://") || value.contains(char::is_whitespace) {
        return Vec::new();
    }
    match value.rfind('@') {
        Some(at) if at > 0 && is_dist_tag(&value[at + 1..]) => {
            vec![ArgProblem::Moving(value.to_owned())]
        }
        _ => Vec::new(),
    }
}

/// Every finding for the servers `hb warm` can warm, by server name and then standing, argument
/// problems and launcher.
#[must_use]
pub fn findings(policy: &Policy, store: &WarmStore, root: &CanonicalPath) -> Vec<Entry> {
    let mut entries = Vec::new();
    for server in super::servers(policy) {
        let mut push = |finding| {
            entries.push(Entry {
                server: server.name.clone(),
                finding,
            });
        };
        match super::standing(store, root, &server) {
            Standing::Warmed => {}
            Standing::Changed => push(Finding::Changed),
            Standing::Never => push(Finding::NotWarmed),
        }
        for arg in &server.args {
            for problem in arg_problems(arg) {
                push(Finding::Arg(problem));
            }
        }
        let listed = policy
            .env
            .tools
            .iter()
            .any(|tool| tool.value.as_str() == server.command);
        if !listed {
            push(Finding::LauncherNotListed(server.command.clone()));
        }
    }
    entries
}

/// The section `hb doctor` prints after the secrets checks.
#[must_use]
pub fn render(policy: &Policy, entries: &[Entry]) -> String {
    let count = super::servers(policy).len();
    let mut out =
        String::from("\nmcp servers (uvx and npx servers start from hb's offline cache)\n");
    if count == 0 {
        out.push_str("  none starts uvx or npx\n");
        return out;
    }
    let plural = if count == 1 { "" } else { "s" };
    let _ = writeln!(
        out,
        "  {count} server{plural} start{} uvx or npx",
        if count == 1 { "s" } else { "" }
    );
    if entries.is_empty() {
        out.push_str("  no problems found\n");
    }
    for entry in entries {
        let _ = writeln!(out, "  {}: {}", entry.server, describe(&entry.finding));
    }
    out.push_str(
        "  note: a package with no version is whatever the last `hb warm` cached; the agent's own config must use the same command and arguments\n",
    );
    out
}

fn shown(text: &str) -> String {
    EscapedBounded::new(text, MAX_SHOWN).to_string()
}

fn describe(finding: &Finding) -> String {
    match finding {
        Finding::NotWarmed => "has not been warmed; run `hb warm`".to_owned(),
        Finding::Changed => {
            "was warmed with other arguments, so the cache may not hold this start; run `hb warm`"
                .to_owned()
        }
        Finding::Arg(ArgProblem::Moving(arg)) => format!(
            "`{}` moves: the version it resolves to changes whenever `hb warm` runs again; pin a version (for example `pkg@1.2.3`), then run `hb warm`",
            shown(arg)
        ),
        Finding::Arg(ArgProblem::UnpinnedGit(url)) => format!(
            "git source `{}` has no full revision, so uv cannot start it offline even from a warm cache; find one with `git ls-remote <url> HEAD`, use `<url>@<40 hex>` here and in the agent's own config, then run `hb warm`",
            shown(url)
        ),
        Finding::LauncherNotListed(tool) => format!(
            "starts `{tool}`, which is not in [env] tools, so hb cannot start it from its offline cache; add \"{tool}\" to [env] tools"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::SystemTime;

    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;
    use crate::config::{ResolvedMcpServer, merge};
    use crate::origin::{FileId, Source, Sourced};
    use crate::policy::{ArgWord, CanonicalPath, Floor, HomeDir, McpName, ToolName};
    use crate::system::StateDir;
    use crate::warm::stamp::{WarmStore, digest};

    const SHA: &str = "23c06ff715409b2e9dc9be7ca26b7b2fbf356b7c";

    fn problems(arg: &str) -> Vec<ArgProblem> {
        arg_problems(arg)
    }

    #[test]
    fn a_dist_tag_is_a_moving_version_whatever_its_name() {
        for arg in [
            "mcp-ripgrep@latest",
            "@browsermcp/mcp@latest",
            "@scope/pkg@next",
            "ruff@beta",
            "--from=pkg@canary",
        ] {
            let found = problems(arg);
            assert!(
                matches!(found.as_slice(), [ArgProblem::Moving(_)]),
                "{arg}: {found:?}"
            );
        }
        assert_eq!(
            problems("@scope/pkg@next"),
            [ArgProblem::Moving("@scope/pkg@next".to_owned())]
        );
        assert_eq!(
            problems("--from=pkg@latest"),
            [ArgProblem::Moving("pkg@latest".to_owned())]
        );
    }

    #[test]
    fn a_tag_may_start_with_v_or_hold_digits_dashes_and_underscores() {
        for arg in [
            "pkg@verbose",
            "pkg@a1",
            "pkg@release-candidate",
            "pkg@my_tag",
            "pkg@vnext",
        ] {
            assert!(
                matches!(problems(arg).as_slice(), [ArgProblem::Moving(_)]),
                "{arg}: {:?}",
                problems(arg)
            );
        }
        for arg in [
            "pkg@v1",
            "pkg@v10.2",
            "pkg@1a",
            "pkg@-x",
            "pkg@a.b",
            "pkg@a/b",
        ] {
            assert_eq!(problems(arg), [], "{arg}");
        }
    }

    #[test]
    fn an_address_or_a_sentence_is_not_a_package_spec_even_with_a_tag_shaped_ending() {
        assert_eq!(problems("https://example.com/x@latest"), [], "an address");
        assert_eq!(problems("say hi@latest"), [], "a sentence");
        assert_eq!(
            problems("@next"),
            [],
            "a scope marker alone is not a package"
        );
    }

    #[test]
    fn a_version_a_range_a_bare_name_a_scope_and_an_address_are_not_moving() {
        for arg in [
            "pkg@1.2.3",
            "pkg@^1.2",
            "pkg@~2",
            "pkg@>=1",
            "pkg@v3",
            "pkg",
            "-y",
            "@modelcontextprotocol/server-sequential-thinking",
            "me@example.com",
            "--user=me@example.com",
            "pkg@",
            "",
        ] {
            assert_eq!(problems(arg), [], "{arg}");
        }
    }

    #[test]
    fn a_git_source_is_pinned_only_by_a_full_revision_in_either_form() {
        for arg in [
            format!("git+https://github.com/oraios/serena@{SHA}"),
            format!(
                "git+https://github.com/oraios/serena@{}",
                SHA.to_uppercase()
            ),
            format!("git+https://github.com/oraios/serena@{SHA}#subdirectory=x"),
            format!("git+https://github.com/npm/node-semver#{SHA}"),
            format!("--from=git+https://github.com/oraios/serena@{SHA}"),
        ] {
            assert_eq!(problems(&arg), [], "{arg}");
        }
        for arg in [
            "git+https://github.com/oraios/serena".to_owned(),
            "git+https://github.com/oraios/serena@main".to_owned(),
            "git+https://github.com/oraios/serena@v1.2.0".to_owned(),
            "git+https://github.com/oraios/serena@23c06ff".to_owned(),
            format!("git+https://github.com/oraios/serena@{}", &SHA[..39]),
            "git+https://github.com/npm/node-semver#main".to_owned(),
            "git+ssh://git@github.com/oraios/serena".to_owned(),
        ] {
            let found = problems(&arg);
            assert!(
                matches!(found.as_slice(), [ArgProblem::UnpinnedGit(_)]),
                "{arg}: {found:?}"
            );
        }
    }

    #[test]
    fn a_flagged_git_url_is_shown_without_credentials_and_a_moving_tag_is_not_confused_with_it() {
        assert_eq!(
            problems("git+https://deploy:s3cret-token@git.corp.example/team/x"),
            [ArgProblem::UnpinnedGit(
                "git+https://git.corp.example/team/x".to_owned()
            )]
        );
        assert_eq!(
            problems("git+https://github.com/o/r@latest"),
            [ArgProblem::UnpinnedGit(
                "git+https://github.com/o/r@latest".to_owned()
            )],
            "a git ref called latest is a git problem only"
        );
    }

    fn policy(servers: &[(&str, &str, &[&str])], tools: &[&str]) -> Policy {
        let source = Source::value(FileId::new(0));
        let mut policy = assert_ok!(merge(&[], Floor::empty()));
        for (name, command, args) in servers {
            policy.mcp.insert(
                assert_ok!(McpName::parse(name)),
                Sourced::new(
                    ResolvedMcpServer {
                        command: Some(assert_ok!(ArgWord::parse_program(command))),
                        args: args.iter().map(|a| assert_ok!(ArgWord::parse(a))).collect(),
                        ..ResolvedMcpServer::default()
                    },
                    source,
                ),
            );
        }
        policy.env.tools = tools
            .iter()
            .map(|t| Sourced::new(assert_ok!(ToolName::parse(t)), source))
            .collect();
        policy
    }

    struct Fixture {
        _tmp: TempDir,
        store: WarmStore,
        root: CanonicalPath,
    }

    fn fixture() -> Fixture {
        let tmp = assert_ok!(TempDir::new());
        let base = assert_ok!(fs::canonicalize(tmp.path()));
        let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(&base)));
        Fixture {
            store: WarmStore::new(&StateDir::locate(&home)),
            root: assert_ok!(CanonicalPath::from_canonical(&base)),
            _tmp: tmp,
        }
    }

    fn kinds(entries: &[Entry]) -> Vec<(&str, &str)> {
        entries
            .iter()
            .map(|e| {
                (
                    e.server.as_str(),
                    match &e.finding {
                        Finding::NotWarmed => "not warmed",
                        Finding::Changed => "changed",
                        Finding::Arg(ArgProblem::Moving(_)) => "moving",
                        Finding::Arg(ArgProblem::UnpinnedGit(_)) => "git",
                        Finding::LauncherNotListed(_) => "launcher",
                    },
                )
            })
            .collect()
    }

    #[test]
    fn each_kind_of_problem_is_found_per_server_in_name_order() {
        let f = fixture();
        let p = policy(
            &[
                ("time", "uvx", &["mcp-server-time"]),
                ("ripgrep", "npx", &["-y", "mcp-ripgrep@latest"]),
                (
                    "serena",
                    "uvx",
                    &["--from", "git+https://github.com/oraios/serena", "serena"],
                ),
                ("memory", "npx", &["-y", "mcp-knowledge-graph"]),
                ("local", "/opt/homebrew/bin/lean-ctx", &["x@latest"]),
            ],
            &["uvx"],
        );
        assert_ok!(f.store.record(
            &f.root,
            "ripgrep",
            &digest("npx", &["-y", "mcp-ripgrep@latest"]),
            SystemTime::now()
        ));
        assert_ok!(f.store.record(
            &f.root,
            "serena",
            &digest("uvx", &["--from", "old", "serena"]),
            SystemTime::now()
        ));
        assert_ok!(f.store.record(
            &f.root,
            "time",
            &digest("uvx", &["mcp-server-time"]),
            SystemTime::now()
        ));
        let found = findings(&p, &f.store, &f.root);
        assert_eq!(
            kinds(&found),
            [
                ("memory", "not warmed"),
                ("memory", "launcher"),
                ("ripgrep", "moving"),
                ("ripgrep", "launcher"),
                ("serena", "changed"),
                ("serena", "git"),
            ]
        );
    }

    #[test]
    fn a_clean_project_has_no_findings_and_says_so() {
        let f = fixture();
        let p = policy(&[("time", "uvx", &["mcp-server-time@1.2.3"])], &["uvx"]);
        assert_ok!(f.store.record(
            &f.root,
            "time",
            &digest("uvx", &["mcp-server-time@1.2.3"]),
            SystemTime::now()
        ));
        let found = findings(&p, &f.store, &f.root);
        assert_eq!(found, []);
        let text = render(&p, &found);
        assert!(text.contains("no problems found"), "{text}");
        assert!(text.contains("1 server"), "{text}");
    }

    #[test]
    fn with_no_server_that_starts_uvx_or_npx_the_section_says_so() {
        let text = render(&policy(&[("local", "/bin/true", &[])], &[]), &[]);
        assert!(text.contains("none starts uvx or npx"), "{text}");
    }

    #[test]
    fn the_text_gives_the_fix_for_each_finding_and_shows_only_the_flagged_argument() {
        let f = fixture();
        let p = policy(
            &[
                (
                    "serena",
                    "uvx",
                    &[
                        "--api-key=hunter2-secret",
                        "--from",
                        "git+https://deploy:tok-123@github.com/oraios/serena",
                        "serena",
                    ],
                ),
                ("ripgrep", "npx", &["-y", "mcp-ripgrep@latest"]),
            ],
            &[],
        );
        let found = findings(&p, &f.store, &f.root);
        let text = render(&p, &found);
        assert!(text.contains("serena: has not been warmed"), "{text}");
        assert!(text.contains("hb warm"), "{text}");
        assert!(text.contains("`mcp-ripgrep@latest` moves"), "{text}");
        assert!(
            text.contains("git+https://github.com/oraios/serena"),
            "{text}"
        );
        assert!(text.contains("git ls-remote"), "{text}");
        assert!(text.contains("agent's own config"), "{text}");
        assert!(text.contains("add \"npx\" to [env] tools"), "{text}");
        for secret in ["hunter2-secret", "tok-123", "deploy"] {
            assert!(!text.contains(secret), "{secret} leaked: {text}");
        }
    }

    #[test]
    fn a_long_or_hostile_argument_is_bounded_and_escaped() {
        let f = fixture();
        let long = format!("pkg-{}@latest", "x".repeat(400));
        let p = policy(&[("s", "npx", &[&long])], &["npx"]);
        let text = render(&p, &findings(&p, &f.store, &f.root));
        assert!(!text.contains(&"x".repeat(300)), "{text}");
        assert!(text.contains("..."), "{text}");
        let hostile = "evil\u{1b}[2J@latest";
        let p = policy(&[("s", "npx", &[hostile])], &["npx"]);
        let text = render(&p, &findings(&p, &f.store, &f.root));
        assert!(!text.contains('\u{1b}'), "{text:?}");
    }

    #[test]
    fn the_server_count_line_agrees_in_number() {
        let one = render(&policy(&[("a", "uvx", &[])], &["uvx"]), &[]);
        assert!(one.contains("1 server starts uvx or npx"), "{one}");
        let two = render(
            &policy(&[("a", "uvx", &[]), ("b", "npx", &[])], &["uvx", "npx"]),
            &[],
        );
        assert!(two.contains("2 servers start uvx or npx"), "{two}");
    }
}
