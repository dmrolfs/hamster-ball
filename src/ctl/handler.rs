// ABOUTME: The one authority path: validated request -> scope -> reservation -> fresh preflight -> gates -> fixed command by ID.
// ABOUTME: Pure orchestration over the `Execute` and `Facts` traits, so every refusal and the exact order are tested without podman.
//! Request handling (hb-ghd.8.1, ordering from `history/hb-ghd.8_oracle-preflight-pins.md`).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use super::argv::{self, ContainerId};
use super::isolation::Broad;
use super::launchd;
use super::op::{ContainerOp, MAX_OUTPUT_BYTES, Request, Response, Validated, ValidatedRequest};
use super::preflight::{self, Facts, MountSource, Refusal, Selection, Vetted};
use super::runner::{Cancel, Capture, Execute, Finished, RunError};
use super::scope::Scope;
use crate::policy::{CanonicalPath, LaunchdLabel};

/// The largest `podman inspect` or `launchctl print` output that is parsed.
pub const MAX_METADATA_BYTES: usize = 1 << 20;

/// Where the host programs are. Absolute paths, found once at startup, never from the client.
#[derive(Debug, Clone)]
pub struct Programs {
    /// `podman`, if installed.
    pub podman: Option<PathBuf>,
    /// `/bin/launchctl`.
    pub launchctl: PathBuf,
}

/// What `start` and `restart` additionally need: facts fixed when `hb run` began.
#[derive(Debug, Clone)]
pub struct Startup {
    /// Every bind source that was pinned in the profile this run uses.
    pub pinned: BTreeSet<MountSource>,
    /// Containers that failed preflight at startup: never start or restart them in this run.
    pub ineligible: BTreeSet<ContainerId>,
    /// Whether the podman VM shares only the project (see [`super::isolation`]).
    pub isolation: Result<(), Broad>,
}

/// The reservation set: at most one mutating operation per target.
#[derive(Debug, Default)]
pub struct Busy(Mutex<BTreeSet<String>>);

/// Released on drop.
struct Reservation<'a> {
    busy: &'a Busy,
    key: String,
}

impl Busy {
    fn take(&self, key: String) -> Option<Reservation<'_>> {
        let mut set = self.0.lock().ok()?;
        set.insert(key.clone())
            .then(|| Reservation { busy: self, key })
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        if let Ok(mut set) = self.busy.0.lock() {
            set.remove(&self.key);
        }
    }
}

/// Everything a request needs, owned by the broker for the whole run.
pub struct Handler<'a> {
    /// What may be touched.
    pub scope: &'a Scope,
    /// Host programs.
    pub programs: &'a Programs,
    /// Runs them.
    pub exec: &'a dyn Execute,
    /// Filesystem and volume facts for preflight.
    pub facts: &'a dyn Facts,
    /// The project root.
    pub project: &'a CanonicalPath,
    /// The broker's own effective uid.
    pub euid: u32,
    /// Startup state for the start gate.
    pub startup: &'a Startup,
    /// Mutation reservations.
    pub busy: &'a Busy,
    /// Set when the run is ending.
    pub cancel: &'a Cancel,
}

fn refused(message: impl Into<String>) -> Response {
    Response {
        ok: false,
        out: String::new(),
        err: message.into(),
        truncated: false,
    }
}

fn ran(done: &Finished) -> Response {
    Response {
        ok: done.success,
        out: String::from_utf8_lossy(&done.bytes).into_owned(),
        err: if done.success {
            String::new()
        } else {
            format!(
                "the command failed (exit {})",
                done.code
                    .map_or_else(|| "signal".to_owned(), |c| c.to_string())
            )
        },
        truncated: done.truncated,
    }
}

fn failed(error: &RunError) -> Response {
    // A timeout or cancel can leave an accepted operation half done; say so rather than "failed".
    let note = match error {
        RunError::TimedOut { .. } | RunError::Cancelled => {
            " (the outcome is unknown; check with `hb ctl ps` or `status` before trying again)"
        }
        _ => "",
    };
    refused(format!("{error}{note}"))
}

impl Handler<'_> {
    /// Handles one decoded line. Never panics, never returns more than the response envelope.
    #[must_use]
    pub fn handle(&self, line: &str) -> Response {
        let request: Request = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(_) => return refused("the request was not understood"),
        };
        let validated = match request.validate() {
            Ok(v) => v,
            Err(e) => return refused(e.to_string()),
        };
        match validated.command() {
            Validated::Container { .. } => self.container(&validated),
            Validated::Launchd { .. } => self.launchd(&validated),
        }
    }

    fn run(
        &self,
        program: &Path,
        args: &[OsString],
        capture: Capture,
        timeout: std::time::Duration,
    ) -> Result<Finished, RunError> {
        self.exec.run(program, args, capture, timeout, self.cancel)
    }

    // ---------------------------------------------------------------- launchd

    fn launchd(&self, request: &ValidatedRequest) -> Response {
        let Validated::Launchd { op, label } = request.command() else {
            return refused("internal: wrong request kind");
        };
        if !self.scope.admits_launchd(label) {
            return refused(format!("{label} is not listed in [ctl] launchd"));
        }
        let _guard;
        if request.mutates() {
            match self.busy.take(format!("launchd:{label}")) {
                Some(r) => _guard = r,
                None => return refused(format!("another operation on {label} is running")),
            }
        }
        let timeout = request.timeout();
        let program = self.programs.launchctl.as_path();
        match op {
            super::op::LaunchdOp::Status => self.launchd_status(program, label, timeout),
            super::op::LaunchdOp::Kickstart => self.launchd_kick(program, label, false, timeout),
            super::op::LaunchdOp::Restart => self.launchd_kick(program, label, true, timeout),
        }
    }

    fn launchd_status(
        &self,
        program: &Path,
        label: &LaunchdLabel,
        timeout: std::time::Duration,
    ) -> Response {
        let args = argv::launchd_print(self.euid, label);
        match self.run(program, &args, Capture::Whole(MAX_METADATA_BYTES), timeout) {
            Err(e) => failed(&e),
            Ok(done) if !done.success => refused(format!(
                "launchd has no loaded job {label} (not bootstrapped?)"
            )),
            Ok(done) => match launchd::project(&String::from_utf8_lossy(&done.bytes)) {
                Ok(status) => Response {
                    ok: true,
                    out: status.render(),
                    err: String::new(),
                    truncated: false,
                },
                Err(e) => refused(e.to_string()),
            },
        }
    }

    fn launchd_kick(
        &self,
        program: &Path,
        label: &LaunchdLabel,
        kill: bool,
        timeout: std::time::Duration,
    ) -> Response {
        let args = argv::launchd_kickstart(self.euid, label, kill);
        match self.run(program, &args, Capture::Tail(2000), timeout) {
            Err(e) => failed(&e),
            // launchctl's own text is not returned: it can name paths and environment.
            Ok(done) if done.success => Response {
                ok: true,
                out: format!(
                    "asked launchd to {} {label}\n",
                    if kill { "restart" } else { "start" }
                ),
                err: String::new(),
                truncated: false,
            },
            Ok(done) => refused(format!(
                "launchd refused (exit {}); is {label} loaded?",
                done.code
                    .map_or_else(|| "signal".to_owned(), |c| c.to_string())
            )),
        }
    }

    // -------------------------------------------------------------- containers

    fn container(&self, request: &ValidatedRequest) -> Response {
        let Validated::Container { op, name, tail } = request.command() else {
            return refused("internal: wrong request kind");
        };
        if !self.scope.has_containers() {
            return refused("[ctl] lists no containers");
        }
        let Some(podman) = self.programs.podman.as_deref() else {
            return refused("podman was not found on this machine");
        };
        let timeout = request.timeout();
        let Some(name) = name else {
            return self.ps(podman, timeout);
        };
        let _guard;
        if op.mutates() {
            match self.busy.take(format!("container:{name}")) {
                Some(r) => _guard = r,
                None => return refused(format!("another operation on {name} is running")),
            }
        }
        let vetted = match self.vet(podman, name.as_str(), timeout) {
            Ok(v) => v,
            Err(response) => return response,
        };
        if op.needs_pin_gate() {
            if let Err(message) = self.gate(&vetted) {
                return refused(message);
            }
        }
        if *op == ContainerOp::Ps {
            return ran(&Finished {
                success: true,
                code: Some(0),
                bytes: format!("{}\n", vetted.name).into_bytes(),
                truncated: false,
            });
        }
        let Some(args) = argv::container_operation(*op, &vetted.id, *tail) else {
            return refused("internal: no command for this operation");
        };
        match self.run(podman, &args, Capture::Tail(MAX_OUTPUT_BYTES), timeout) {
            Ok(done) => ran(&done),
            Err(e) => failed(&e),
        }
    }

    /// Fresh inspect of the exact name, then every preflight rule.
    fn vet(
        &self,
        podman: &Path,
        name: &str,
        timeout: std::time::Duration,
    ) -> Result<Vetted, Response> {
        let parsed =
            crate::policy::ContainerName::parse(name).map_err(|e| refused(e.to_string()))?;
        let done = self
            .run(
                podman,
                &argv::inspect(&parsed),
                Capture::Whole(MAX_METADATA_BYTES),
                timeout,
            )
            .map_err(|e| failed(&e))?;
        if !done.success {
            return Err(refused(format!("{name} was not found")));
        }
        let names: BTreeSet<String> = self
            .scope
            .containers()
            .map(|c| c.as_str().to_owned())
            .collect();
        let label = self.scope.label().map(|l| (l.key(), l.value()));
        preflight::preflight(
            &String::from_utf8_lossy(&done.bytes),
            name,
            Selection {
                names: &names,
                label,
            },
            self.project,
            self.facts,
        )
        .map_err(|r: Refusal| refused(r.to_string()))
    }

    /// The start gate: runtime isolation, startup eligibility, and every source pinned.
    fn gate(&self, vetted: &Vetted) -> Result<(), String> {
        self.startup
            .isolation
            .as_ref()
            .map_err(ToString::to_string)?;
        if self.startup.ineligible.contains(&vetted.id) {
            return Err(format!(
                "{} did not pass the checks when hb started, so it cannot be started or restarted in this run",
                vetted.name
            ));
        }
        if let Some(source) = vetted
            .sources
            .iter()
            .find(|s| !self.startup.pinned.contains(*s))
        {
            return Err(format!(
                "{} has a mount ({}) that was not pinned when hb started; restart `hb run` to pin it",
                vetted.name,
                crate::text::Escaped(source.path.as_str())
            ));
        }
        Ok(())
    }

    /// Names and states of the in-scope containers, one line each, from podman's own listing.
    fn ps(&self, podman: &Path, timeout: std::time::Duration) -> Response {
        let mut lines = BTreeSet::new();
        let mut lists = Vec::new();
        if let Some(label) = self.scope.label() {
            lists.push(argv::list_by_label(label));
        }
        lists.extend(self.scope.containers().map(argv::list_by_name));
        for args in lists {
            match self.run(podman, &args, Capture::Whole(MAX_METADATA_BYTES), timeout) {
                Err(e) => return failed(&e),
                Ok(done) if !done.success => return refused("podman could not list containers"),
                Ok(done) => match listing(&done.bytes) {
                    Ok(found) => lines.extend(found),
                    Err(m) => return refused(m),
                },
            }
        }
        let out: String = lines.into_iter().map(|l| format!("{l}\n")).collect();
        Response {
            ok: true,
            out,
            err: String::new(),
            truncated: false,
        }
    }
}

/// `(name, state)` for each entry of `podman ps --format json`, and nothing else from it.
///
/// An entry whose name or state is not plain is dropped, not shown.
///
/// # Errors
/// A fixed message when the text is not a listing.
pub fn rows(bytes: &[u8]) -> Result<Vec<(String, String)>, &'static str> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Row {
        names: Vec<String>,
        state: String,
    }
    let rows: Vec<Row> =
        serde_json::from_slice(bytes).map_err(|_| "podman's listing was not understood")?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let name = r.names.into_iter().next()?;
            (crate::policy::ContainerName::parse(&name).is_ok()
                && r.state.bytes().all(|b| b.is_ascii_alphabetic()))
            .then_some((name, r.state))
        })
        .collect())
}

fn listing(bytes: &[u8]) -> Result<Vec<String>, &'static str> {
    Ok(rows(bytes)?
        .into_iter()
        .map(|(name, state)| format!("{name}\t{state}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::isolation::Broad;
    use crate::ctl::preflight::{SourceKind, SourceProblem, VolumeFacts};
    use crate::policy::{ContainerLabel, ContainerName};
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::collections::VecDeque;
    use std::time::Duration;

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Records every command and answers from a script, in order.
    #[derive(Default)]
    struct Script {
        calls: Mutex<Vec<String>>,
        answers: Mutex<VecDeque<Result<Finished, RunError>>>,
    }

    impl Script {
        fn answer(&self, a: Result<Finished, RunError>) {
            self.answers
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .push_back(a);
        }
        fn ok(&self, text: &str) {
            self.answer(Ok(Finished {
                success: true,
                code: Some(0),
                bytes: text.as_bytes().to_vec(),
                truncated: false,
            }));
        }
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap_or_else(|_| unreachable!()).clone()
        }
    }

    impl Execute for Script {
        fn run(
            &self,
            program: &Path,
            argv: &[OsString],
            _c: Capture,
            _t: Duration,
            _x: &Cancel,
        ) -> Result<Finished, RunError> {
            let line = std::iter::once(program.to_string_lossy().into_owned())
                .chain(argv.iter().map(|a| a.to_string_lossy().into_owned()))
                .collect::<Vec<_>>()
                .join(" ");
            self.calls
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .push(line);
            self.answers
                .lock()
                .unwrap_or_else(|_| unreachable!())
                .pop_front()
                .unwrap_or_else(|| {
                    Ok(Finished {
                        success: false,
                        code: Some(1),
                        bytes: vec![],
                        truncated: false,
                    })
                })
        }
    }

    struct Fs;
    impl Facts for Fs {
        fn bind_source(
            &self,
            path: &str,
            project: &CanonicalPath,
        ) -> Result<MountSource, SourceProblem> {
            let p = CanonicalPath::from_canonical(path).map_err(|_| SourceProblem::Malformed)?;
            if !project.is_same_or_ancestor_of(&p) {
                return Err(SourceProblem::OutsideProject);
            }
            Ok(MountSource {
                path: p,
                kind: SourceKind::Directory,
            })
        }
        fn volume(&self, name: &str) -> Result<VolumeFacts, String> {
            Ok(VolumeFacts {
                name: name.into(),
                driver: "local".into(),
                has_options: false,
            })
        }
    }

    fn record(name: &str, source: &str) -> String {
        json!([{
            "Id": ID, "Name": name, "Config": {"Labels": {"com.docker.compose.project": "icehouse"}},
            "HostConfig": {"Privileged": false, "NetworkMode": "bridge", "PidMode": "private", "IpcMode": "shareable",
                "UsernsMode": "", "UTSMode": "private", "CgroupMode": "private", "CapAdd": [], "SecurityOpt": [],
                "Devices": [], "Binds": [format!("{source}:/d:rprivate,rbind")], "Tmpfs": {}},
            "Mounts": [{"Type": "bind", "Source": source, "Destination": "/d", "Propagation": "rprivate"}]
        }]).to_string()
    }

    struct World {
        scope: Scope,
        programs: Programs,
        script: Script,
        project: CanonicalPath,
        startup: Startup,
        busy: Busy,
        cancel: Cancel,
    }

    fn scope() -> Scope {
        let policy_label = assert_ok!(ContainerLabel::parse("com.docker.compose.project=icehouse"));
        let mut s = Scope::default();
        s.set_for_test(
            Some(policy_label),
            vec![assert_ok!(ContainerName::parse("lgw-pg"))],
            vec![assert_ok!(LaunchdLabel::parse("com.example.db"))],
        );
        s
    }

    fn world() -> World {
        let project = assert_ok!(CanonicalPath::from_canonical("/Users/me/proj"));
        let pinned = [MountSource {
            path: assert_ok!(CanonicalPath::from_canonical("/Users/me/proj/data")),
            kind: SourceKind::Directory,
        }]
        .into();
        World {
            scope: scope(),
            programs: Programs {
                podman: Some("/opt/homebrew/bin/podman".into()),
                launchctl: "/bin/launchctl".into(),
            },
            script: Script::default(),
            project,
            startup: Startup {
                pinned,
                ineligible: BTreeSet::new(),
                isolation: Ok(()),
            },
            busy: Busy::default(),
            cancel: Cancel::default(),
        }
    }

    fn handle(w: &World, line: &str) -> Response {
        Handler {
            scope: &w.scope,
            programs: &w.programs,
            exec: &w.script,
            facts: &Fs,
            project: &w.project,
            euid: 501,
            startup: &w.startup,
            busy: &w.busy,
            cancel: &w.cancel,
        }
        .handle(line)
    }

    const RESTART: &str = r#"{"target":"container","op":"restart","name":"db"}"#;

    #[test]
    fn test_restart_inspects_by_name_then_acts_on_the_full_id_after_a_double_dash() {
        let w = world();
        w.script.ok(&record("db", "/Users/me/proj/data"));
        w.script.ok("db\n");
        let r = handle(&w, RESTART);
        assert!(r.ok, "{r:?}");
        assert_eq!(
            w.script.calls(),
            [
                "/opt/homebrew/bin/podman inspect --type container -- db".to_owned(),
                format!("/opt/homebrew/bin/podman restart -t 10 -- {ID}"),
            ]
        );
    }

    #[test]
    fn test_a_refused_preflight_runs_no_second_command() {
        let w = world();
        w.script.ok(&record("db", "/Users/me/.ssh"));
        let r = handle(&w, RESTART);
        assert!(!r.ok);
        assert!(
            r.err.contains("/Users/me/.ssh") && r.err.contains("outside the project"),
            "{}",
            r.err
        );
        assert_eq!(w.script.calls().len(), 1);
    }

    #[test]
    fn test_the_pin_gate_refuses_start_and_restart_for_an_unpinned_source_but_not_logs_or_stop() {
        let mut w = world();
        w.startup.pinned.clear();
        for op in ["start", "restart"] {
            w.script.ok(&record("db", "/Users/me/proj/data"));
            let r = handle(
                &w,
                &format!(r#"{{"target":"container","op":"{op}","name":"db"}}"#),
            );
            assert!(
                !r.ok && r.err.contains("not pinned when hb started"),
                "{op}: {}",
                r.err
            );
        }
        assert_eq!(w.script.calls().len(), 2, "no podman start/restart was run");
        for op in ["logs", "stop", "stats"] {
            w.script.ok(&record("db", "/Users/me/proj/data"));
            w.script.ok("fine");
            let r = handle(
                &w,
                &format!(r#"{{"target":"container","op":"{op}","name":"db"}}"#),
            );
            assert!(r.ok, "{op}: {r:?}");
        }
    }

    #[test]
    fn test_a_shared_vm_or_a_startup_failure_refuses_start_but_not_stop() {
        let mut w = world();
        w.startup.isolation = Err(Broad::Share {
            share: "/Users".into(),
            project: "/Users/me/proj".into(),
        });
        w.script.ok(&record("db", "/Users/me/proj/data"));
        let r = handle(&w, RESTART);
        assert!(
            !r.ok
                && r.err
                    .contains("podman machine init --volume /Users/me/proj:/Users/me/proj"),
            "{}",
            r.err
        );
        w.script.ok(&record("db", "/Users/me/proj/data"));
        w.script.ok("stopped");
        assert!(handle(&w, r#"{"target":"container","op":"stop","name":"db"}"#).ok);

        let mut w = world();
        w.startup
            .ineligible
            .insert(assert_ok!(ContainerId::parse(ID).ok_or("id")));
        w.script.ok(&record("db", "/Users/me/proj/data"));
        let r = handle(&w, RESTART);
        assert!(
            !r.ok && r.err.contains("did not pass the checks when hb started"),
            "{}",
            r.err
        );
    }

    #[test]
    fn test_a_second_mutation_of_the_same_container_is_refused_while_the_first_holds_the_reservation()
     {
        let w = world();
        let _held = assert_ok!(w.busy.take("container:db".into()).ok_or("busy"));
        let r = handle(&w, RESTART);
        assert!(!r.ok && r.err.contains("another operation on db is running"));
        assert!(w.script.calls().is_empty(), "nothing ran");
        // a read of the same container, and a mutation of another, are not blocked by it
        w.script.ok(&record("db", "/Users/me/proj/data"));
        w.script.ok("log line");
        let read = handle(&w, r#"{"target":"container","op":"logs","name":"db"}"#);
        assert!(read.ok && read.out == "log line", "{read:?}");
        w.script.ok(&record("lgw-pg", "/Users/me/proj/data"));
        w.script.ok("done");
        let other = handle(
            &w,
            r#"{"target":"container","op":"restart","name":"lgw-pg"}"#,
        );
        assert!(other.ok, "{other:?}");
    }

    #[test]
    fn test_the_reservation_is_released_after_the_request_even_when_it_fails() {
        let w = world();
        w.script.ok(&record("db", "/Users/me/.ssh"));
        assert!(!handle(&w, RESTART).ok);
        w.script.ok(&record("db", "/Users/me/proj/data"));
        w.script.ok("ok");
        assert!(
            handle(&w, RESTART).ok,
            "the first refusal must not leave the target reserved"
        );
    }

    #[test]
    fn test_bad_json_unknown_ops_and_out_of_scope_names_never_reach_podman() {
        let w = world();
        for line in [
            "",
            "garbage",
            r#"{"target":"container","op":"exec","name":"db"}"#,
            r#"{"target":"container","op":"restart","name":"--all"}"#,
        ] {
            assert!(!handle(&w, line).ok, "{line}");
        }
        assert!(w.script.calls().is_empty());
        w.script.ok(&record("other", "/Users/me/proj/data")
            .replace(r#""com.docker.compose.project":"icehouse""#, r#""x":"y""#));
        let r = handle(
            &w,
            r#"{"target":"container","op":"restart","name":"other"}"#,
        );
        assert!(
            !r.ok && r.err.contains("not in the approved scope"),
            "{}",
            r.err
        );
    }

    #[test]
    fn test_ps_lists_only_name_and_state_for_the_configured_selectors() {
        let w = world();
        w.script
            .ok(r#"[{"Names":["api"],"State":"running","Image":"secret/image"}]"#);
        w.script
            .ok(r#"[{"Names":["lgw-pg"],"State":"exited","Command":["x"]}]"#);
        let r = handle(&w, r#"{"target":"container","op":"ps"}"#);
        assert!(r.ok);
        assert_eq!(r.out, "api\trunning\nlgw-pg\texited\n");
        assert_eq!(
            w.script.calls(),
            [
                "/opt/homebrew/bin/podman ps -a --format json --filter label=com.docker.compose.project=icehouse".to_owned(),
                "/opt/homebrew/bin/podman ps -a --format json --filter name=^lgw-pg$".to_owned(),
            ]
        );
    }

    #[test]
    fn test_launchd_requires_a_listed_label_and_status_shows_only_the_projection() {
        let w = world();
        let r = handle(
            &w,
            r#"{"target":"launchd","op":"restart","label":"com.example.other"}"#,
        );
        assert!(!r.ok && r.err.contains("not listed in [ctl] launchd"));
        assert!(w.script.calls().is_empty());

        w.script.ok(include_str!(
            "../../tests/golden/launchctl/print_running.txt"
        ));
        let r = handle(
            &w,
            r#"{"target":"launchd","op":"status","label":"com.example.db"}"#,
        );
        assert!(r.ok, "{r:?}");
        assert!(
            r.out.contains("state: running")
                && !r.out.contains("SECRET")
                && !r.out.contains("shh-secret")
        );
        assert_eq!(
            w.script.calls(),
            ["/bin/launchctl print gui/501/com.example.db"]
        );
    }

    #[test]
    fn test_launchd_restart_is_kickstart_dash_k_and_does_not_echo_launchctls_text() {
        let w = world();
        w.script.ok("path = /secret/plist\n");
        let r = handle(
            &w,
            r#"{"target":"launchd","op":"restart","label":"com.example.db"}"#,
        );
        assert!(r.ok && !r.out.contains("/secret"), "{r:?}");
        assert_eq!(
            w.script.calls(),
            ["/bin/launchctl kickstart -k gui/501/com.example.db"]
        );
        w.script.answer(Ok(Finished {
            success: false,
            code: Some(113),
            bytes: b"Could not find service /secret".to_vec(),
            truncated: false,
        }));
        let r = handle(
            &w,
            r#"{"target":"launchd","op":"kickstart","label":"com.example.db"}"#,
        );
        assert!(!r.ok && !r.err.contains("/secret"), "{r:?}");
    }

    #[test]
    fn test_a_timeout_says_the_outcome_is_unknown_and_a_launchd_only_run_needs_no_podman() {
        let w = world();
        w.script.ok(&record("db", "/Users/me/proj/data"));
        w.script.answer(Err(RunError::TimedOut {
            limit: Duration::from_secs(60),
        }));
        let r = handle(&w, RESTART);
        assert!(!r.ok && r.err.contains("outcome is unknown"), "{}", r.err);

        let mut w = world();
        w.programs.podman = None;
        let r = handle(&w, RESTART);
        assert!(!r.ok && r.err.contains("podman was not found"));
        w.script.ok("state = ...");
        assert!(
            handle(
                &w,
                r#"{"target":"launchd","op":"kickstart","label":"com.example.db"}"#
            )
            .ok
        );
    }
}
