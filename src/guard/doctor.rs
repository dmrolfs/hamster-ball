// ABOUTME: What `hb doctor` reports about secrets: files that look secret but no pattern guards, tracked secrets, launchd variables.
// ABOUTME: Reads file names and variable names only; no file or variable value is ever read into a report.
//! The doctor's secrets checks (design sections 3 and 8).

use std::fmt::Write as _;
use std::path::Path;

use super::patterns::{is_guarded, is_template};
use super::repos::{RepoFindings, WriteAssessment};
use super::scan::walk_files;
use crate::diagnostic::{Check, CheckGap, DiagnosticCode, Gaps};
use crate::policy::CanonicalPath;
use crate::system::proxy_settings::{ProxyKind, ProxySetting};
use crate::text::Escaped;

/// Most entries of one list shown.
const SHOWN: usize = 50;

/// Exact names that hold credentials.
const CREDENTIAL_FILES: &[&str] = &[
    ".netrc",
    "_netrc",
    ".npmrc",
    ".pgpass",
    ".pypirc",
    ".htpasswd",
    ".git-credentials",
    ".dockercfg",
    "kubeconfig",
    "credentials",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
];
/// Extensions that are keystores or state that holds secrets.
const SECRET_EXTENSIONS: &[&str] = &["pfx", "jks", "keystore", "kdbx", "tfvars", "tfstate", "gpg"];
/// Words in a name that suggest a credential, when the file is data and not code.
const SECRET_WORDS: &[&str] = &[
    "secret",
    "token",
    "credential",
    "password",
    "passwd",
    "api_key",
    "api-key",
    "apikey",
    "private_key",
    "private-key",
    "privatekey",
    "access_key",
];
/// Extensions of data files, where a secret-looking name is more likely a secret than code.
const DATA_EXTENSIONS: &[&str] = &[
    "json",
    "yaml",
    "yml",
    "toml",
    "txt",
    "env",
    "ini",
    "conf",
    "cfg",
    "properties",
    "xml",
    "csv",
    "",
];

/// Why a file name looks like a secret that no guard pattern covers, or `None`.
#[must_use]
pub fn suspicion(name: &str) -> Option<String> {
    if is_guarded(name) || is_template(name) {
        return None;
    }
    let lower = name.to_ascii_lowercase();
    if CREDENTIAL_FILES.contains(&lower.as_str()) {
        return Some(format!("`{lower}` holds credentials"));
    }
    let extension = lower.rsplit_once('.').map_or("", |(_, e)| e);
    if SECRET_EXTENSIONS.contains(&extension) {
        return Some(format!("a `.{extension}` file"));
    }
    if DATA_EXTENSIONS.contains(&extension) {
        let word = SECRET_WORDS.iter().find(|w| lower.contains(**w))?;
        return Some(format!("the name contains \"{word}\""));
    }
    None
}

/// A file that looks like a secret and that nothing guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspect {
    /// Its path.
    pub path: String,
    /// Why it looks like one.
    pub reason: String,
}

/// The files below `roots` whose names look secret and are not guarded, sorted by path.
///
/// `complete` is false when the walk stopped at `max_entries` or could not read part of the tree.
#[must_use]
pub fn survey(roots: &[CanonicalPath], max_entries: usize) -> (Vec<Suspect>, bool) {
    let mut found = Vec::new();
    let gaps = walk_files(roots, max_entries, |_, dir: &Path, name| {
        if let Some(reason) = suspicion(name) {
            found.push(Suspect {
                path: dir.join(name).to_string_lossy().into_owned(),
                reason,
            });
        }
        true
    });
    found.sort_by(|a, b| a.path.cmp(&b.path));
    (found, gaps.is_empty())
}

/// The names in the launchd environment that look like secrets, from `launchctl print gui/<uid>`.
///
/// Only names are kept; the values on the same lines are dropped here and never returned.
#[must_use]
pub fn launchd_secret_names(print: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut inside = false;
    for line in print.lines() {
        let trimmed = line.trim();
        if !inside {
            inside = trimmed == "environment = {";
            continue;
        }
        if trimmed == "}" {
            break;
        }
        let Some((name, _value)) = trimmed.split_once("=>") else {
            continue;
        };
        let name = name.trim();
        let lower = name.to_ascii_lowercase();
        if SECRET_WORDS.iter().any(|w| lower.contains(*w)) && !names.iter().any(|n| n == name) {
            names.push(name.to_owned());
        }
    }
    names.sort();
    names
}

/// The secret-looking names in this user's launchd environment, or none if it cannot be read.
#[must_use]
pub fn launchd_environment() -> Vec<String> {
    launchd_environment_from(Path::new("/bin/launchctl"), nix::unistd::getuid().as_raw())
}

fn launchd_environment_from(launchctl: &Path, uid: u32) -> Vec<String> {
    std::process::Command::new(launchctl)
        .args(["print", &format!("gui/{uid}")])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| launchd_secret_names(&String::from_utf8_lossy(&output.stdout)))
        .unwrap_or_default()
}

/// What the doctor found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Findings {
    /// The directories the guard covers.
    pub roots: Vec<String>,
    /// Whether the dependency exemption is on for this project.
    pub exemption: bool,
    /// How many directories are pinned.
    pub pins: usize,
    /// Tracked files the guard would deny: readable, because git has them.
    pub tracked: Vec<String>,
    /// Secret-looking files no pattern guards.
    pub suspects: Vec<Suspect>,
    /// Whether the survey of suspects covered everything.
    pub survey_complete: bool,
    /// Names in the launchd environment that look like secrets.
    pub launchd: Vec<String>,
    /// What the guard could not do in full, as sentences.
    pub notes: Vec<String>,
    /// Git outside the floor's reach: nested repositories and hook managers, and how complete that is.
    pub repos: Check<RepoFindings>,
    /// The proxies the system has switched on, and whether `tls.system_trust` lets the agent read them.
    pub proxies: Check<Vec<ProxySetting>>,
    /// Whether the agent can read the system proxy settings (`tls.system_trust` is on).
    pub proxies_readable: bool,
}

impl Default for Findings {
    /// Nothing found; the git check is unavailable, not clean, because nothing was inspected.
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            exemption: false,
            pins: 0,
            tracked: Vec::new(),
            suspects: Vec::new(),
            survey_complete: false,
            launchd: Vec::new(),
            notes: Vec::new(),
            repos: Check::Unavailable {
                gap: CheckGap {
                    code: DiagnosticCode::InspectionUnavailable,
                    subject: None,
                },
            },
            proxies: Check::Unavailable {
                gap: CheckGap {
                    code: DiagnosticCode::InspectionUnavailable,
                    subject: None,
                },
            },
            proxies_readable: false,
        }
    }
}

fn list(out: &mut String, title: &str, lines: &[String]) {
    let _ = writeln!(out, "\n{title}");
    if lines.is_empty() {
        let _ = writeln!(out, "  (none)");
    }
    for line in lines.iter().take(SHOWN) {
        let _ = writeln!(out, "  {line}");
    }
    if lines.len() > SHOWN {
        let _ = writeln!(out, "  ... and {} more", lines.len() - SHOWN);
    }
}

/// The report as text. Every name is escaped, because a file name is the project's to choose.
#[must_use]
pub fn render(findings: &Findings) -> String {
    let mut out = String::from("hb doctor\n");
    let roots: Vec<String> = findings
        .roots
        .iter()
        .map(|r| Escaped(r).to_string())
        .collect();
    let _ = writeln!(out, "\nsecrets guard covers");
    for root in &roots {
        let _ = writeln!(out, "  {root}");
    }
    let state = if findings.exemption {
        format!(
            "on: key and certificate files below node_modules and site-packages are usable; {} directories holding secrets are pinned against rename",
            findings.pins
        )
    } else {
        "off: those files stay denied".to_owned()
    };
    let _ = writeln!(out, "dependency exemption: {state}");
    if findings.exemption {
        let _ = writeln!(
            out,
            "  limit: a directory that gets its first key or certificate after `hb` starts is not pinned; \
             start `hb` again after creating one"
        );
    }
    for note in &findings.notes {
        let _ = writeln!(out, "  note: {}", Escaped(note));
    }
    list(
        &mut out,
        "tracked files the guard would deny (git has them, so the agent can read them with `git show`)",
        &findings
            .tracked
            .iter()
            .map(|t| Escaped(t).to_string())
            .collect::<Vec<_>>(),
    );
    let mut suspects: Vec<String> = findings
        .suspects
        .iter()
        .map(|s| format!("{}  ({})", Escaped(&s.path), Escaped(&s.reason)))
        .collect();
    if !findings.survey_complete {
        suspects.push("the survey stopped early: the project is large".to_owned());
    }
    list(
        &mut out,
        "files that look like secrets but no pattern guards (names only; add `fs.deny_read` for them)",
        &suspects,
    );
    list(
        &mut out,
        "secret-looking names in the launchd environment (values not shown; the agent can read it when system.launchctl is on)",
        &findings
            .launchd
            .iter()
            .map(|n| Escaped(n).to_string())
            .collect::<Vec<_>>(),
    );
    render_git(&mut out, &findings.repos);
    render_proxies(&mut out, &findings.proxies, findings.proxies_readable);
    out
}

/// The git section: repositories and hook managers that the floor does not cover.
///
/// The state and the gaps are printed outside the capped list, so a long list cannot hide them.
fn render_git(out: &mut String, check: &Check<RepoFindings>) {
    const TITLE: &str = "git the floor does not protect (git runs hooks outside the ball; the agent can write the ones named here unless a deny covers them: review what is executable there and narrow `fs.write` or add a reviewed `fs.deny_write`)";
    match check {
        Check::Complete { value } => list(out, TITLE, &git_lines(value)),
        Check::Partial { value, gaps } => {
            let lines = git_lines(value);
            if lines.is_empty() {
                let _ = writeln!(out, "\n{TITLE}");
                let _ = writeln!(out, "  no findings in the paths that were inspected");
            } else {
                list(out, TITLE, &lines);
            }
            render_gaps(out, "git", "partial", gaps);
        }
        Check::Unavailable { gap } => {
            let _ = writeln!(out, "\n{TITLE}");
            let mut gaps = Gaps::new();
            gaps.push(gap.clone());
            render_gaps(out, "git", "unavailable", &gaps);
        }
    }
}

fn render_gaps(out: &mut String, check: &str, state: &str, gaps: &Gaps) {
    let _ = writeln!(
        out,
        "  {check} inspection: {state}; this is not a clean result"
    );
    for gap in gaps.shown() {
        match &gap.subject {
            Some(subject) => {
                let _ = writeln!(out, "    {}: {subject}", gap.code);
            }
            None => {
                let _ = writeln!(out, "    {}", gap.code);
            }
        }
    }
    if gaps.omitted() > 0 {
        let _ = writeln!(out, "    ... and {} more", gaps.omitted());
    }
}

fn git_lines(repos: &RepoFindings) -> Vec<String> {
    let mut lines: Vec<String> = repos
        .nested
        .iter()
        .map(|p| format!("repository below a write grant: {}", Escaped(p)))
        .collect();
    lines.extend(
        repos
            .managers
            .iter()
            .map(|(path, manager)| format!("{manager}: {}", Escaped(path))),
    );
    for hook in &repos.hooks {
        let source = match (&hook.configured, &hook.origin) {
            (Some(value), Some(origin)) => {
                format!("core.hooksPath = {} ({})", Escaped(value), Escaped(origin))
            }
            _ => "core.hooksPath is not set (default hooks directory)".to_owned(),
        };
        let write = match hook.write {
            WriteAssessment::Permitted => "policy permits the agent to write there",
            WriteAssessment::Denied => "policy denies the agent writing there",
            WriteAssessment::NotGranted => "no write grant covers it",
            WriteAssessment::Unknown => "write access could not be established; review by hand",
        };
        lines.push(format!(
            "hooks of {}: {source}; directory {}: {write}",
            Escaped(&hook.repository),
            Escaped(&hook.hooks_dir)
        ));
    }
    lines
}

/// The system proxy section: three different outcomes read three different ways.
///
/// Every line is a constant, a kind label, a validated target or a gap code, so nothing the system
/// printed reaches the terminal as text.
fn render_proxies(out: &mut String, check: &Check<Vec<ProxySetting>>, readable: bool) {
    const TITLE: &str = "system proxy settings (`hb` connects directly and does not follow them, so connections may fail)";
    let _ = writeln!(out, "\n{TITLE}");
    match check {
        Check::Complete { value } if value.is_empty() => {
            let _ = writeln!(out, "  no proxy is switched on");
        }
        Check::Complete { value } => proxy_lines(out, value),
        Check::Partial { value, gaps } => {
            if value.is_empty() {
                let _ = writeln!(
                    out,
                    "  no proxy is switched on in the settings that were read"
                );
            } else {
                proxy_lines(out, value);
            }
            render_gaps(out, "proxy", "partial", gaps);
        }
        Check::Unavailable { gap } => {
            let mut gaps = Gaps::new();
            gaps.push(gap.clone());
            render_gaps(out, "proxy", "unavailable", &gaps);
            let _ = writeln!(
                out,
                "  hb could not read the system proxy settings, so it cannot say whether a proxy is switched on"
            );
        }
    }
    let _ = if readable {
        writeln!(
            out,
            "  the agent can read these settings (`tls.system_trust` is on)"
        )
    } else {
        writeln!(
            out,
            "  the agent cannot read these settings (`tls.system_trust` is off)"
        )
    };
}

fn proxy_lines(out: &mut String, proxies: &[ProxySetting]) {
    for proxy in proxies.iter().take(SHOWN) {
        let label = proxy.kind.label();
        let _ = match (&proxy.target, proxy.kind) {
            (Some(target), _) => writeln!(out, "  {label}: {target}"),
            (None, ProxyKind::AutoConfig) => writeln!(out, "  {label} (address not shown)"),
            (None, ProxyKind::AutoDiscovery) => writeln!(out, "  {label}"),
            (None, _) => writeln!(
                out,
                "  {label} (address not shown: it did not pass validation)"
            ),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diagnostic::SafePath;
    use crate::guard::repos::HookObservation;
    use crate::system::proxy_settings::parse as proxy_parse;
    use claims::{assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    #[test]
    fn credential_files_keystores_and_secret_named_data_look_suspicious() {
        for name in [
            ".netrc",
            ".NPMRC",
            "id_rsa",
            "id_ed25519",
            "credentials",
            "terraform.tfvars",
            "terraform.tfstate",
            "cert.pfx",
            "app.jks",
            "vault.kdbx",
            "secrets.txt",
            "api_token.json",
            "aws-credentials.ini",
            "db_password",
            "service-credential.yaml",
            "apikey.conf",
        ] {
            assert_some!(suspicion(name), "{name}");
        }
    }

    #[test]
    fn code_templates_public_keys_and_the_guarded_names_do_not() {
        for name in [
            "token.rs",
            "password_reset.py",
            "secrets.go",
            "README.md",
            "id_rsa.pub",
            ".env",
            "prod.secrets.yaml",
            "server.pem",
            "secrets.txt.example",
            "credentials.json.sample",
            "main.rs",
            "Cargo.toml",
            "tokenizer.json.template",
        ] {
            assert_none!(suspicion(name), "{name}");
        }
    }

    #[test]
    fn the_reason_names_what_matched() {
        assert_eq!(
            suspicion(".netrc").as_deref(),
            Some("`.netrc` holds credentials")
        );
        assert_eq!(
            suspicion("my-token.json").as_deref(),
            Some("the name contains \"token\"")
        );
        assert_eq!(suspicion("a.tfvars").as_deref(), Some("a `.tfvars` file"));
    }

    #[test]
    fn the_survey_lists_unguarded_look_alikes_and_skips_dependency_directories() {
        let dir = assert_ok!(tempfile::tempdir());
        let root = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
            std::fs::canonicalize(dir.path())
        )));
        for file in [
            "config/credentials.json",
            "deploy/terraform.tfvars",
            ".env",
            "src/token.rs",
            "node_modules/pkg/credentials.json",
        ] {
            let path = root.as_path().join(file);
            if let Some(parent) = path.parent() {
                assert_ok!(std::fs::create_dir_all(parent));
            }
            assert_ok!(std::fs::write(path, "x"));
        }
        let (found, complete) = survey(std::slice::from_ref(&root), 1000);
        assert!(complete);
        let names: Vec<&str> = found
            .iter()
            .map(|s| s.path.strip_prefix(root.as_str()).unwrap_or(&s.path))
            .collect();
        assert_eq!(
            names,
            ["/config/credentials.json", "/deploy/terraform.tfvars"]
        );
        assert!(!survey(&[root], 2).1);
    }

    #[test]
    fn a_survey_that_could_not_read_a_directory_is_incomplete() {
        use std::os::unix::fs::PermissionsExt;
        let dir = assert_ok!(tempfile::tempdir());
        let root = assert_ok!(CanonicalPath::from_canonical(assert_ok!(
            std::fs::canonicalize(dir.path())
        )));
        let sealed = root.as_path().join("sealed");
        assert_ok!(std::fs::create_dir_all(&sealed));
        assert_ok!(std::fs::write(sealed.join("credentials.json"), "x"));
        assert_ok!(std::fs::set_permissions(
            &sealed,
            std::fs::Permissions::from_mode(0o000)
        ));
        let (found, complete) = survey(std::slice::from_ref(&root), 1000);
        let _ = std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755));
        assert!(found.is_empty());
        assert!(!complete, "an unreadable directory read as a clean survey");
    }

    const LAUNCHD: &str = "\
gui/501 = {
\tservices = {
\t\tEARLIER_TOKEN => not-in-the-environment
\t}
\ttype = login
\tenvironment = {
\t\tGITHUB_TOKEN => ghp_REDACTED_VALUE
\t\tPATH => /usr/bin:/bin
\t\tOPENAI_API_KEY => sk-REDACTED
\t\tDB_PASSWORD => hunter2
\t\tGITHUB_TOKEN => again
\t\tHOME => /Users/me
\t}
\tother = {
\t\tSECRET_THING => no
\t}
}
";

    #[test]
    fn only_secret_looking_names_come_out_of_the_launchd_environment_and_never_a_value() {
        let names = launchd_secret_names(LAUNCHD);
        assert_eq!(names, ["DB_PASSWORD", "GITHUB_TOKEN", "OPENAI_API_KEY"]);
        let shown = names.join(" ");
        for value in ["ghp_REDACTED_VALUE", "sk-REDACTED", "hunter2"] {
            assert!(!shown.contains(value));
        }
    }

    #[test]
    fn the_launchd_environment_comes_from_launchctl_print_and_a_failure_gives_none() {
        let dir = assert_ok!(tempfile::tempdir());
        let script = |name: &str, body: &str| {
            let path = dir.path().join(name);
            assert_ok!(std::fs::write(&path, body));
            assert_ok!(std::fs::set_permissions(
                &path,
                std::os::unix::fs::PermissionsExt::from_mode(0o755)
            ));
            path
        };
        let good = script("good", &format!("#!/bin/sh\ncat <<'EOF'\n{LAUNCHD}EOF\n"));
        assert_eq!(
            launchd_environment_from(&good, 501),
            ["DB_PASSWORD", "GITHUB_TOKEN", "OPENAI_API_KEY"]
        );
        let args = script(
            "args",
            "#!/bin/sh\n[ \"$1 $2\" = \"print gui/777\" ] && echo '\tenvironment = {' && echo '\t\tA_TOKEN => x' && echo '\t}'\n",
        );
        assert_eq!(launchd_environment_from(&args, 777), ["A_TOKEN"]);
        let failing = script(
            "failing",
            "#!/bin/sh\necho '\tenvironment = {'; echo '\t\tA_TOKEN => x'; echo '\t}'; exit 1\n",
        );
        assert_eq!(
            launchd_environment_from(&failing, 501),
            Vec::<String>::new()
        );
        assert_eq!(
            launchd_environment_from(&dir.path().join("missing"), 501),
            Vec::<String>::new()
        );
    }

    #[test]
    fn the_real_launchd_environment_is_read_from_launchctl_for_this_user() {
        let uid = nix::unistd::getuid().as_raw();
        assert_eq!(
            launchd_environment(),
            launchd_environment_from(Path::new("/bin/launchctl"), uid)
        );
    }

    #[test]
    fn a_list_of_exactly_the_limit_has_no_more_line() {
        let exact = Findings {
            tracked: (0..50).map(|i| format!("/p/{i}.key")).collect(),
            survey_complete: true,
            ..Findings::default()
        };
        assert!(!render(&exact).contains("more"));
    }

    #[test]
    fn a_launchd_print_without_an_environment_block_has_no_names() {
        assert_eq!(
            launchd_secret_names("gui/501 = {\n}\n"),
            Vec::<String>::new()
        );
        assert_eq!(launchd_secret_names(""), Vec::<String>::new());
    }

    #[test]
    fn the_report_says_what_it_found_and_escapes_names() {
        let findings = Findings {
            roots: vec!["/p".to_owned()],
            exemption: true,
            pins: 3,
            tracked: vec!["/p/.env".to_owned()],
            suspects: vec![Suspect {
                path: "/p/\u{1b}[2Jcredentials.json".to_owned(),
                reason: "the name contains \"credential\"".to_owned(),
            }],
            survey_complete: true,
            launchd: vec!["GITHUB_TOKEN".to_owned()],
            notes: vec!["git could not list the tracked files".to_owned()],
            repos: Check::from_parts(
                RepoFindings {
                    nested: vec!["/p/vendor/\u{1b}[2Jlib".to_owned()],
                    managers: vec![("/p/.husky".to_owned(), "husky")],
                    hooks: vec![HookObservation {
                        repository: "/p".to_owned(),
                        hooks_dir: "/p/.husky/_".to_owned(),
                        configured: Some(".husky/_".to_owned()),
                        origin: Some("local file:.git/config".to_owned()),
                        write: WriteAssessment::Permitted,
                    }],
                },
                {
                    let mut gaps = Gaps::new();
                    gaps.push(CheckGap {
                        code: DiagnosticCode::DirectoryUnreadable,
                        subject: Some(SafePath::new("/p/\u{1b}[2Jlocked")),
                    });
                    gaps
                },
            ),
            proxies: proxy_parse(&scutil(
                "ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://u:pw@pac.example/wpad.dat?token=SECRET\n  HTTPSEnable : 1\n  HTTPSProxy : proxy.example\n  HTTPSPort : 8080",
            )),
            proxies_readable: true,
        };
        let text = render(&findings);
        assert!(
            text.contains("repository below a write grant: /p/vendor/"),
            "{text}"
        );
        assert!(text.contains("husky: /p/.husky"), "{text}");
        assert!(
            text.contains("core.hooksPath = .husky/_ (local file:.git/config)"),
            "{text}"
        );
        assert!(
            text.contains("policy permits the agent to write there"),
            "{text}"
        );
        assert!(text.contains("git inspection: partial"), "{text}");
        assert!(text.contains("directory_unreadable: /p/"), "{text}");
        assert!(text.contains("PAC file (address not shown)"), "{text}");
        assert!(
            !text.contains("pac.example") && !text.contains("SECRET"),
            "{text}"
        );
        assert!(text.contains("HTTPS: proxy.example:8080"), "{text}");
        assert!(text.contains("the agent can read these settings"), "{text}");
        assert!(text.contains("on: key and certificate files"), "{text}");
        assert!(
            text.contains("3 directories holding secrets are pinned"),
            "{text}"
        );
        assert!(
            text.contains("limit: a directory that gets its first key"),
            "{text}"
        );
        assert!(text.contains("note: git could not list"), "{text}");
        assert!(text.contains("/p/.env"), "{text}");
        assert!(text.contains("GITHUB_TOKEN"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text:?}");
    }

    #[test]
    fn an_empty_report_says_none_and_a_long_list_is_cut() {
        let text = render(&Findings {
            roots: vec!["/p".to_owned()],
            survey_complete: true,
            ..clean()
        });
        // Four lists say (none); the proxy section says what it read instead.
        assert_eq!(text.matches("(none)").count(), 4);
        assert!(text.contains("no proxy is switched on"), "{text}");
        assert!(text.contains("off: those files stay denied"));
        let many = Findings {
            tracked: (0..60).map(|i| format!("/p/{i}.key")).collect(),
            survey_complete: true,
            ..Findings::default()
        };
        assert!(render(&many).contains("... and 10 more"));
    }

    /// `scutil --proxy` output with `entries` as the top-level lines after the quiet defaults.
    fn scutil(entries: &str) -> String {
        format!("<dictionary> {{\n  {entries}\n}}\n")
    }

    /// Nothing found and both checks ran to the end: only this may print as clean.
    fn clean() -> Findings {
        Findings {
            repos: Check::from_parts(RepoFindings::default(), Gaps::new()),
            proxies: proxy_parse(&scutil("HTTPEnable : 0")),
            ..Findings::default()
        }
    }

    fn proxy_section(findings: &Findings) -> String {
        let text = render(findings);
        let from = text.find("system proxy settings").unwrap_or(0);
        text[from..].to_owned()
    }

    #[test]
    fn a_missing_scutil_a_partial_read_and_no_proxy_are_three_different_things() {
        let none = proxy_section(&clean());
        assert!(none.contains("no proxy is switched on"), "{none}");
        assert!(!none.contains("proxy inspection"), "{none}");
        assert!(!none.contains("could not read"), "{none}");

        let failed = proxy_section(&Findings::default());
        assert!(failed.contains("proxy inspection: unavailable"), "{failed}");
        assert!(
            failed.contains("could not read the system proxy settings"),
            "{failed}"
        );
        assert!(!failed.contains("no proxy is switched on"), "{failed}");

        let partial = proxy_section(&Findings {
            proxies: proxy_parse(&scutil(
                "HTTPEnable : 0\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      HTTPEnable : 1\n    }\n  }",
            )),
            ..clean()
        });
        assert!(partial.contains("proxy inspection: partial"), "{partial}");
        assert!(
            partial.contains("config_scope_omitted: __SCOPED__"),
            "{partial}"
        );
        assert!(
            partial.contains("no proxy is switched on in the settings that were read"),
            "{partial}"
        );
        assert!(!partial.contains("could not read"), "{partial}");
        assert!(!partial.contains("(none)"), "{partial}");
    }

    #[test]
    fn an_enabled_proxy_whose_address_failed_validation_is_listed_without_the_address() {
        let section = proxy_section(&Findings {
            proxies: proxy_parse(&scutil(
                "HTTPSEnable : 1\n  HTTPSProxy : user:p@ss@proxy.example/x?SECRET\n  HTTPSPort : 8080",
            )),
            ..clean()
        });
        assert!(
            section.contains("HTTPS (address not shown: it did not pass validation)"),
            "{section}"
        );
        assert!(section.contains("value_rejected: HTTPSProxy"), "{section}");
        assert!(
            !section.contains("SECRET") && !section.contains("p@ss"),
            "{section}"
        );
    }

    #[test]
    fn a_git_check_that_never_ran_is_unavailable_not_none() {
        let text = render(&Findings::default());
        let git = &text[text.find("git the floor does not protect").unwrap_or(0)..];
        let git = git.split("\n\n").next().unwrap_or(git);
        assert!(git.contains("git inspection: unavailable"), "{text}");
        assert!(git.contains("not a clean result"), "{text}");
        assert!(!git.contains("(none)"), "{text}");
    }

    #[test]
    fn a_partial_git_check_with_no_findings_says_what_it_did_not_cover() {
        let mut gaps = Gaps::new();
        gaps.push(CheckGap {
            code: DiagnosticCode::DirectoryUnreadable,
            subject: Some(SafePath::new("/p/locked")),
        });
        let text = render(&Findings {
            repos: Check::from_parts(RepoFindings::default(), gaps),
            ..Findings::default()
        });
        assert!(
            text.contains("no findings in the paths that were inspected"),
            "{text}"
        );
        assert!(text.contains("directory_unreadable: /p/locked"), "{text}");
    }

    #[test]
    fn the_gaps_stay_visible_when_the_findings_list_is_cut() {
        let mut gaps = Gaps::new();
        for _ in 0..40 {
            gaps.push(CheckGap {
                code: DiagnosticCode::DirectoryUnreadable,
                subject: Some(SafePath::new("/p/locked")),
            });
        }
        let repos = RepoFindings {
            nested: (0..60).map(|i| format!("/p/r{i}")).collect(),
            ..RepoFindings::default()
        };
        let text = render(&Findings {
            repos: Check::from_parts(repos, gaps),
            ..Findings::default()
        });
        assert!(text.contains("... and 10 more"), "{text}");
        assert!(text.contains("git inspection: partial"), "{text}");
        assert!(text.contains("... and 8 more"), "{text}");
    }

    #[test]
    fn a_survey_that_stopped_early_says_so() {
        let text = render(&Findings {
            survey_complete: false,
            ..Findings::default()
        });
        assert!(text.contains("the survey stopped early"), "{text}");
    }

    #[test]
    fn a_clean_report_says_none_for_git_and_proxies_and_says_when_the_agent_cannot_read_them() {
        let text = render(&clean());
        assert!(text.contains("git the floor does not protect"), "{text}");
        assert!(text.contains("system proxy settings"), "{text}");
        assert!(
            text.contains("the agent cannot read these settings"),
            "{text}"
        );
        assert_eq!(text.matches("(none)").count(), 3, "{text}");
        assert!(text.contains("no proxy is switched on"), "{text}");
    }
}
