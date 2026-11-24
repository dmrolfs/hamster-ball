// ABOUTME: The approval decision at `hb run` and `hb approve`: check the store, show the summary, ask at a terminal.
// ABOUTME: Nothing approves without a typed yes from a person at a terminal; there is no flag or variable that skips it.
//! Asking the owner (design section 5).

use std::io::{self, BufRead, IsTerminal, Write};

use super::digest::Fingerprint;
use super::store::{ApprovalStore, Standing, StoreError, Why};
use super::summary::GrantSummary;
use crate::config::{Discovery, Loaded};
use crate::policy::CanonicalPath;
use crate::system::Environment;
use crate::text::Escaped;

/// How many hex digits of a file's digest the prompt shows.
const SHOWN_DIGEST_DIGITS: usize = 12;

/// A person at a terminal, or not.
pub trait Terminal {
    /// Whether a person can be asked: input and the place the question appears are both terminals.
    fn is_interactive(&self) -> bool;

    /// Shows `question` and reads one line of answer. The end of the input is an empty answer.
    ///
    /// # Errors
    /// The terminal could not be written or read.
    fn ask(&mut self, question: &str) -> io::Result<String>;
}

/// The process's own terminal: questions go to stderr and answers come from stdin.
#[derive(Debug, Default)]
pub struct StdTerminal;

impl Terminal for StdTerminal {
    fn is_interactive(&self) -> bool {
        io::stdin().is_terminal() && io::stderr().is_terminal()
    }

    fn ask(&mut self, question: &str) -> io::Result<String> {
        let mut err = io::stderr().lock();
        write!(err, "{question}")?;
        err.flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        Ok(line)
    }
}

/// No terminal at all: nobody is ever asked. For callers that must not prompt, such as in-process tests.
#[derive(Debug, Default)]
pub struct NoTerminal;

impl Terminal for NoTerminal {
    fn is_interactive(&self) -> bool {
        false
    }

    fn ask(&mut self, _question: &str) -> io::Result<String> {
        Ok(String::new())
    }
}

/// What is to be approved: one project's config as it is now.
#[derive(Debug)]
pub struct Candidate {
    root: CanonicalPath,
    fingerprint: Fingerprint,
    summary: GrantSummary,
}

impl Candidate {
    /// The project `discovery` found, loaded as `loaded`.
    #[must_use]
    pub fn new(env: &Environment, discovery: &Discovery, loaded: &Loaded) -> Self {
        Self {
            root: discovery.root.path().clone(),
            fingerprint: Fingerprint::of(&loaded.closure),
            summary: GrantSummary::for_project(env, discovery, loaded),
        }
    }

    /// The canonical project root.
    #[must_use]
    pub fn root(&self) -> &CanonicalPath {
        &self.root
    }

    /// What the approval would cover.
    #[must_use]
    pub fn fingerprint(&self) -> &Fingerprint {
        &self.fingerprint
    }
}

/// How the question ended.
#[derive(Debug)]
#[non_exhaustive]
pub enum Verdict {
    /// The config was already approved; nothing was asked.
    AlreadyApproved,
    /// The owner said yes and it is stored.
    Approved,
    /// The owner did not say yes.
    Declined,
    /// Nobody could be asked, and the config is not approved.
    NoTerminal(Why),
}

impl Verdict {
    /// Whether the project may run.
    #[must_use]
    pub fn allows_run(&self) -> bool {
        matches!(self, Self::AlreadyApproved | Self::Approved)
    }
}

/// Checks the store and, when the config is not approved, asks the owner.
///
/// Everything shown goes to `out`. A store that cannot be written after a yes is an error: the
/// run must not go ahead as if it had been approved.
///
/// # Errors
/// [`GateError`] when the question cannot be put or the approval cannot be stored.
pub fn require(
    candidate: &Candidate,
    store: &ApprovalStore,
    terminal: &mut dyn Terminal,
    out: &mut dyn Write,
) -> Result<Verdict, GateError> {
    let why = match store.standing(&candidate.root, &candidate.fingerprint) {
        Standing::Approved => return Ok(Verdict::AlreadyApproved),
        Standing::Unapproved(why) => why,
    };
    if !terminal.is_interactive() {
        return Ok(Verdict::NoTerminal(why));
    }
    show(candidate, &why, out).map_err(|source| GateError::Show { source })?;
    let answer = terminal
        .ask("Approve this config? [y/N] ")
        .map_err(|source| GateError::Ask { source })?;
    if !is_yes(&answer) {
        return Ok(Verdict::Declined);
    }
    store
        .approve(&candidate.root, &candidate.fingerprint)
        .map_err(|source| GateError::Store { source })?;
    Ok(Verdict::Approved)
}

fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn show(candidate: &Candidate, why: &Why, out: &mut dyn Write) -> io::Result<()> {
    writeln!(out, "hb: {why}.")?;
    writeln!(out, "Project: {}", Escaped(candidate.root.as_str()))?;
    writeln!(
        out,
        "The agent can write the project, so approval is by content. Files covered:"
    )?;
    for file in candidate.fingerprint.files() {
        let digest = file.sha256.to_string();
        writeln!(
            out,
            "  {}  sha256:{}",
            Escaped(&file.path),
            &digest[..SHOWN_DIGEST_DIGITS]
        )?;
    }
    writeln!(out)?;
    write!(out, "{}", candidate.summary)?;
    writeln!(out)
}

/// Why `hb approve` refused to start.
#[derive(Debug, snafu::Snafu)]
#[non_exhaustive]
pub enum ApproveError {
    /// It was run from inside a hamster ball.
    #[snafu(display(
        "hb approve cannot run inside a hamster ball; approve from a terminal outside it"
    ))]
    InsideBall,
}

/// Why asking or recording failed.
#[derive(Debug, snafu::Snafu)]
#[non_exhaustive]
pub enum GateError {
    /// The summary could not be written.
    #[snafu(display("cannot show what is to be approved"))]
    Show {
        /// The OS error.
        source: io::Error,
    },

    /// The answer could not be read.
    #[snafu(display("cannot ask for approval"))]
    Ask {
        /// The OS error.
        source: io::Error,
    },

    /// The approval could not be stored.
    #[snafu(display("the approval could not be stored"))]
    Store {
        /// The store's error.
        source: StoreError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HomeDir;
    use crate::system::StateDir;
    use claims::{assert_matches, assert_ok};
    use pretty_assertions::assert_eq;
    use std::collections::VecDeque;
    use std::fs;
    use tempfile::TempDir;

    struct Scripted {
        interactive: bool,
        answers: VecDeque<String>,
        asked: Vec<String>,
    }

    impl Scripted {
        fn saying(answers: &[&str]) -> Self {
            Self {
                interactive: true,
                answers: answers.iter().map(|a| (*a).to_owned()).collect(),
                asked: Vec::new(),
            }
        }

        fn nobody() -> Self {
            Self {
                interactive: false,
                answers: VecDeque::new(),
                asked: Vec::new(),
            }
        }
    }

    impl Terminal for Scripted {
        fn is_interactive(&self) -> bool {
            self.interactive
        }

        fn ask(&mut self, question: &str) -> io::Result<String> {
            self.asked.push(question.to_owned());
            Ok(self.answers.pop_front().unwrap_or_default())
        }
    }

    struct Fixture {
        _dir: TempDir,
        store: ApprovalStore,
        candidate: Candidate,
    }

    fn fixture(files: &[(&str, &str)]) -> Fixture {
        let dir = assert_ok!(tempfile::tempdir());
        let root = assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
            dir.path()
        ))));
        let home = HomeDir::new(root.clone());
        Fixture {
            store: ApprovalStore::new(&StateDir::locate(&home)),
            candidate: Candidate {
                fingerprint: Fingerprint::from_files(
                    files.iter().map(|(p, b)| ((*p).to_owned(), b.as_bytes())),
                ),
                summary: GrantSummary::default(),
                root,
            },
            _dir: dir,
        }
    }

    fn run(f: &Fixture, terminal: &mut Scripted) -> (Verdict, String) {
        let mut out = Vec::new();
        let verdict = assert_ok!(require(&f.candidate, &f.store, terminal, &mut out));
        (verdict, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn no_terminal_is_never_interactive_and_answers_nothing() {
        let mut none = NoTerminal;
        assert!(!none.is_interactive());
        assert_eq!(assert_ok!(none.ask("Approve? ")), "");
    }

    #[test]
    fn an_unapproved_config_without_a_terminal_is_not_asked_about_and_does_not_run() {
        let f = fixture(&[("/p/hamster-ball.toml", "x")]);
        let mut terminal = Scripted::nobody();
        let (verdict, shown) = run(&f, &mut terminal);
        assert_matches!(verdict, Verdict::NoTerminal(Why::NeverApproved));
        assert!(!verdict.allows_run());
        assert!(terminal.asked.is_empty());
        assert_eq!(shown, "");
        assert_matches!(
            f.store
                .standing(f.candidate.root(), f.candidate.fingerprint()),
            Standing::Unapproved(_)
        );
    }

    #[test]
    fn a_yes_at_a_terminal_approves_and_the_next_run_is_not_asked() {
        let f = fixture(&[("/p/hamster-ball.toml", "x")]);
        let mut terminal = Scripted::saying(&["y\n"]);
        let (verdict, shown) = run(&f, &mut terminal);
        assert_matches!(verdict, Verdict::Approved);
        assert!(verdict.allows_run());
        assert!(shown.contains("has not been approved"), "{shown}");
        assert!(shown.contains("/p/hamster-ball.toml  sha256:"), "{shown}");
        assert!(
            shown.contains("adds nothing beyond your base config"),
            "{shown}"
        );

        let mut again = Scripted::saying(&[]);
        let (verdict, shown) = run(&f, &mut again);
        assert_matches!(verdict, Verdict::AlreadyApproved);
        assert!(again.asked.is_empty());
        assert_eq!(shown, "");
    }

    #[test]
    fn anything_but_yes_declines_and_stores_nothing() {
        for answer in ["", "\n", "n\n", "no\n", "yess\n", "maybe\n", "y y\n"] {
            let f = fixture(&[("/p/hamster-ball.toml", "x")]);
            let (verdict, _) = run(&f, &mut Scripted::saying(&[answer]));
            assert_matches!(verdict, Verdict::Declined);
            assert_matches!(
                f.store
                    .standing(f.candidate.root(), f.candidate.fingerprint()),
                Standing::Unapproved(Why::NeverApproved)
            );
        }
    }

    #[test]
    fn yes_in_either_case_with_spaces_counts() {
        for answer in ["y\n", "Y\n", "yes\n", "YES\n", "  yes  \n", "y"] {
            let f = fixture(&[("/p/hamster-ball.toml", "x")]);
            let (verdict, _) = run(&f, &mut Scripted::saying(&[answer]));
            assert_matches!(verdict, Verdict::Approved, "{answer:?}");
        }
    }

    #[test]
    fn the_end_of_the_input_is_a_no() {
        let f = fixture(&[("/p/hamster-ball.toml", "x")]);
        let mut terminal = Scripted {
            interactive: true,
            answers: VecDeque::from([String::new()]),
            asked: Vec::new(),
        };
        let (verdict, _) = run(&f, &mut terminal);
        assert_matches!(verdict, Verdict::Declined);
    }

    #[test]
    fn a_change_after_approval_asks_again_and_names_the_file() {
        let f = fixture(&[("/p/hamster-ball.toml", "x")]);
        assert_matches!(run(&f, &mut Scripted::saying(&["y"])).0, Verdict::Approved);
        let changed = Fixture {
            candidate: Candidate {
                fingerprint: Fingerprint::from_files([(
                    "/p/hamster-ball.toml".to_owned(),
                    "y".as_bytes(),
                )]),
                summary: GrantSummary::default(),
                root: f.candidate.root.clone(),
            },
            ..f
        };
        let (verdict, shown) = run(&changed, &mut Scripted::saying(&["n"]));
        assert_matches!(verdict, Verdict::Declined);
        assert!(
            shown.contains("changed since it was approved (changed: /p/hamster-ball.toml)"),
            "{shown}"
        );
    }

    #[test]
    fn a_path_with_control_characters_cannot_move_the_cursor() {
        let f = fixture(&[("/p/\u{1b}[2Jevil.toml", "x")]);
        let (_, shown) = run(&f, &mut Scripted::saying(&["n"]));
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }

    #[test]
    fn a_yes_that_cannot_be_stored_is_an_error_and_not_an_approval() {
        let f = fixture(&[("/p/hamster-ball.toml", "x")]);
        let state = f.store.clone();
        assert_ok!(state.approve(f.candidate.root(), &Fingerprint::from_files([])));
        assert_ok!(fs::set_permissions(
            f._dir.path().join(".local/state/hamster-ball/approvals"),
            std::os::unix::fs::PermissionsExt::from_mode(0o775)
        ));
        let mut out = Vec::new();
        let result = require(
            &f.candidate,
            &f.store,
            &mut Scripted::saying(&["y"]),
            &mut out,
        );
        assert_matches!(result, Err(GateError::Store { .. }));
        let shown = String::from_utf8_lossy(&out);
        assert!(
            shown.contains("cannot be used, so it counts as not approved"),
            "{shown}"
        );
    }
}
