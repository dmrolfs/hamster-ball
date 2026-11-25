// ABOUTME: Starts `hb ctl` for a run: finds the programs, vets every in-scope container once, and opens the broker socket.
// ABOUTME: The startup result (pinned sources, ineligible IDs, VM isolation) is fixed here and never widened later.
//! The run's `hb ctl` service (hb-ghd.8.1 to 8.3).

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::argv;
use super::broker::{Broker, BrokerError, Serve};
use super::facts::{examine, parse_volume};
use super::handler::{Busy, Handler, MAX_METADATA_BYTES, Programs, Startup, rows};
use super::isolation::{self, Broad};
use super::op::Response;
use super::preflight::{self, Facts, MountSource, Selection, SourceProblem, VolumeFacts};
use super::runner::{Cancel, Capture, Execute};
use super::scope::Scope;
use crate::policy::{CanonicalPath, ContainerName};

/// How long each startup command may take.
const STARTUP_STEP: Duration = Duration::from_secs(30);

/// Real filesystem and volume facts; volumes are looked up through the same runner as everything else.
struct PodmanFacts {
    podman: PathBuf,
    exec: Arc<dyn Execute>,
    cancel: Cancel,
}

impl Facts for PodmanFacts {
    fn bind_source(
        &self,
        path: &str,
        project: &CanonicalPath,
    ) -> Result<MountSource, SourceProblem> {
        examine(path, project)
    }

    fn volume(&self, name: &str) -> Result<VolumeFacts, String> {
        let done = self
            .exec
            .run(
                &self.podman,
                &argv::volume_inspect(name),
                Capture::Whole(MAX_METADATA_BYTES),
                STARTUP_STEP,
                &self.cancel,
            )
            .map_err(|e| e.to_string())?;
        if !done.success {
            return Err("podman could not inspect it".to_owned());
        }
        parse_volume(&String::from_utf8_lossy(&done.bytes))
    }
}

/// Everything the broker's connections share.
struct Shared {
    scope: Scope,
    programs: Programs,
    exec: Arc<dyn Execute>,
    facts: PodmanFacts,
    project: CanonicalPath,
    euid: u32,
    startup: Startup,
    busy: Busy,
    cancel: Cancel,
}

impl Serve for Shared {
    fn serve(&self, line: &str) -> Response {
        Handler {
            scope: &self.scope,
            programs: &self.programs,
            exec: self.exec.as_ref(),
            facts: &self.facts,
            project: &self.project,
            euid: self.euid,
            startup: &self.startup,
            busy: &self.busy,
            cancel: &self.cancel,
        }
        .handle(line)
    }
}

/// What a run needs to start the service.
pub struct Inputs {
    /// The approved selectors.
    pub scope: Scope,
    /// The resolved project root.
    pub project: CanonicalPath,
    /// Where the host programs are.
    pub programs: Programs,
    /// Runs them.
    pub exec: Arc<dyn Execute>,
    /// Where to put the socket (inside the session directory).
    pub socket: PathBuf,
    /// The broker's own effective uid.
    pub euid: u32,
    /// `CONTAINER_CONNECTION` as `hb` saw it, which selects the podman connection.
    pub connection: Option<String>,
    /// `CONTAINER_HOST` as `hb` saw it, which overrides the connection.
    pub container_host: Option<String>,
}

/// A running service and what the profile and the user need from startup.
#[derive(Debug)]
pub struct Service {
    /// The broker; stop it when the child has ended.
    pub broker: Broker,
    /// Sources to pin in the profile this run uses. Empty when `start` and `restart` are unavailable.
    pub pins: Vec<CanonicalPath>,
    /// Plain-text notes for the user, one per refused container or unavailable feature.
    pub warnings: Vec<String>,
}

/// Why the service did not start.
pub type StartError = BrokerError;

/// Vets every in-scope container once, then opens the socket.
///
/// Containers that fail are warnings, not errors: the run goes on without `start` and `restart`
/// for them. The cancel flag is shared with the broker, so ending the run stops everything.
///
/// # Errors
/// [`StartError`] if the socket cannot be made.
pub fn start(inputs: Inputs) -> Result<Service, StartError> {
    let cancel = Cancel::default();
    let mut warnings = Vec::new();
    let facts = PodmanFacts {
        podman: inputs.programs.podman.clone().unwrap_or_default(),
        exec: inputs.exec.clone(),
        cancel: cancel.clone(),
    };
    let mut startup = Startup {
        pinned: BTreeSet::new(),
        ineligible: BTreeSet::new(),
        isolation: Ok(()),
    };
    if inputs.scope.has_containers() {
        match inputs.programs.podman.as_deref() {
            None => warnings.push("[ctl] lists containers but podman was not found".to_owned()),
            Some(podman) => {
                startup.isolation = machine_isolation(
                    podman,
                    inputs.exec.as_ref(),
                    &cancel,
                    &inputs.project,
                    inputs.connection.as_deref(),
                    inputs.container_host.as_deref(),
                );
                if let Err(broad) = &startup.isolation {
                    warnings.push(format!("hb ctl start and restart are unavailable: {broad}"));
                }
                vet_all(
                    podman,
                    &inputs,
                    &facts,
                    &cancel,
                    &mut startup,
                    &mut warnings,
                );
            }
        }
    }
    let pins = if startup.isolation.is_ok() {
        startup.pinned.iter().map(|s| s.path.clone()).collect()
    } else {
        Vec::new()
    };
    let shared = Arc::new(Shared {
        scope: inputs.scope,
        programs: inputs.programs,
        exec: inputs.exec,
        facts,
        project: inputs.project,
        euid: inputs.euid,
        startup,
        busy: Busy::default(),
        cancel: cancel.clone(),
    });
    let broker = Broker::start(&inputs.socket, shared, cancel)?;
    Ok(Service {
        broker,
        pins,
        warnings,
    })
}

/// Reads the config of the machine the active connection reaches and checks it shares only the project.
///
/// `podman machine inspect` with no name describes the default machine, which is not always the
/// one commands reach, so the machine is found by the active connection's port.
fn machine_isolation(
    podman: &Path,
    exec: &dyn Execute,
    cancel: &Cancel,
    project: &CanonicalPath,
    connection: Option<&str>,
    container_host: Option<&str>,
) -> Result<(), Broad> {
    let unknown = |detail: String| Broad::Unknown { detail };
    let run = |args: &[&str]| -> Result<String, Broad> {
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let done = exec
            .run(
                podman,
                &args,
                Capture::Whole(MAX_METADATA_BYTES),
                STARTUP_STEP,
                cancel,
            )
            .map_err(|e| unknown(e.to_string()))?;
        if done.success {
            Ok(String::from_utf8_lossy(&done.bytes).into_owned())
        } else {
            Err(unknown(format!(
                "podman {} failed (is a podman machine running?)",
                args.first()
                    .map_or_else(String::new, |a| a.to_string_lossy().into_owned())
            )))
        }
    };
    let connections = run(&["system", "connection", "list", "--format", "json"])?;
    let names = isolation::machine_names(&run(&["machine", "list", "--format", "json"])?)?;
    let mut described = Vec::new();
    for name in &names {
        described.push(run(&["machine", "inspect", name])?);
    }
    let refs: Vec<&str> = described.iter().map(String::as_str).collect();
    let (_, file) = isolation::active_machine(&connections, connection, container_host, &refs)?;
    let text =
        std::fs::read_to_string(&file).map_err(|e| unknown(format!("{}: {e}", file.display())))?;
    isolation::check(&text, project, |share| {
        std::fs::canonicalize(share)
            .ok()
            .and_then(|p| CanonicalPath::from_canonical(p).ok())
    })
}

fn vet_all(
    podman: &Path,
    inputs: &Inputs,
    facts: &PodmanFacts,
    cancel: &Cancel,
    startup: &mut Startup,
    warnings: &mut Vec<String>,
) {
    let names = candidates(podman, inputs, cancel, warnings);
    let wanted: BTreeSet<String> = inputs
        .scope
        .containers()
        .map(|c| c.as_str().to_owned())
        .collect();
    let label = inputs.scope.label().map(|l| (l.key(), l.value()));
    for name in names {
        let Ok(parsed) = ContainerName::parse(&name) else {
            continue;
        };
        let inspect = inputs.exec.run(
            podman,
            &argv::inspect(&parsed),
            Capture::Whole(MAX_METADATA_BYTES),
            STARTUP_STEP,
            cancel,
        );
        let Ok(done) = inspect else {
            warnings.push(format!(
                "{name}: could not be inspected, so it is not available to hb ctl"
            ));
            continue;
        };
        let text = String::from_utf8_lossy(&done.bytes);
        let selection = Selection {
            names: &wanted,
            label,
        };
        match preflight::preflight(&text, &name, selection, &inputs.project, facts) {
            Ok(vetted) => startup.pinned.extend(vetted.sources),
            Err(refusal) => {
                warnings.push(format!(
                    "{name}: {refusal}; hb ctl will not start or restart it in this run"
                ));
                startup.ineligible.extend(preflight::container_id(&text));
            }
        }
    }
}

/// The names of the in-scope containers that exist, from the configured selectors only.
fn candidates(
    podman: &Path,
    inputs: &Inputs,
    cancel: &Cancel,
    warnings: &mut Vec<String>,
) -> BTreeSet<String> {
    let mut lists: Vec<Vec<OsString>> = inputs
        .scope
        .label()
        .map(argv::list_by_label)
        .into_iter()
        .collect();
    lists.extend(inputs.scope.containers().map(argv::list_by_name));
    let mut names = BTreeSet::new();
    for args in lists {
        match inputs.exec.run(
            podman,
            &args,
            Capture::Whole(MAX_METADATA_BYTES),
            STARTUP_STEP,
            cancel,
        ) {
            Ok(done) if done.success => match rows(&done.bytes) {
                Ok(found) => names.extend(found.into_iter().map(|(name, _)| name)),
                Err(m) => warnings.push(format!(
                    "hb ctl could not read podman's container list: {m}"
                )),
            },
            Ok(_) | Err(_) => warnings.push(
                "hb ctl could not list containers (is the podman machine running?)".to_owned(),
            ),
        }
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctl::client::{Command, send};
    use crate::ctl::op::ContainerOp;
    use crate::ctl::runner::Host;
    use crate::policy::{ContainerLabel, LaunchdLabel};
    use crate::testutil::{Tree, canonical};
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use serde_json::json;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    const ID_OK: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ID_BAD: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    fn record(id: &str, name: &str, source: &str, privileged: bool) -> serde_json::Value {
        json!({
            "Id": id, "Name": name, "Config": {"Labels": {"proj": "x"}},
            "HostConfig": {"Privileged": privileged, "NetworkMode": "bridge", "PidMode": "private", "IpcMode": "shareable",
                "UsernsMode": "", "UTSMode": "private", "CgroupMode": "private", "CapAdd": [], "SecurityOpt": [],
                "Devices": [], "Binds": [format!("{source}:/d:rprivate,rbind")], "Tmpfs": {}},
            "Mounts": [{"Type": "bind", "Source": source, "Destination": "/d", "Propagation": "rprivate"}]
        })
    }

    /// A shell script standing in for podman: answers `ps`, `inspect`, `machine inspect`, and logs every call.
    fn fake_podman(dir: &Path, machine_dir: &Path, good_src: &str, bad_src: &str) -> PathBuf {
        let answers = dir.join("answers");
        assert_ok!(fs::create_dir_all(&answers));
        let w = |name: &str, text: String| assert_ok!(fs::write(answers.join(name), text));
        w("ps", json!([{"Names": ["good"], "State": "running"}, {"Names": ["bad"], "State": "running"}]).to_string());
        w(
            "inspect-good",
            json!([record(ID_OK, "good", good_src, false)]).to_string(),
        );
        w(
            "inspect-bad",
            json!([record(ID_BAD, "bad", bad_src, true)]).to_string(),
        );
        w(
            "machine",
            json!([{"Name": "m", "SSHConfig": {"Port": 4242}, "ConfigDir": {"Path": machine_dir.to_string_lossy()}}])
                .to_string(),
        );
        w("machine-list", json!([{"Name": "m"}]).to_string());
        w(
            "connections",
            json!([{"Name": "m", "URI": "ssh://core@127.0.0.1:4242/run/user/1/podman/podman.sock", "Default": true}])
                .to_string(),
        );
        let script = dir.join("podman");
        assert_ok!(fs::write(
            &script,
            format!(
                "#!/bin/sh\necho \"$@\" >> '{log}'\ncase \"$1\" in\n ps) cat '{a}/ps';;\n inspect) cat \"{a}/inspect-$5\";;\n machine) case \"$2\" in list) cat '{a}/machine-list';; *) cat '{a}/machine';; esac;;\n system) cat '{a}/connections';;\n restart|start|stop|logs) shift; for last; do :; done; echo \"did $last\";;\n *) exit 1;;\nesac\n",
                log = dir.join("calls").display(),
                a = answers.display()
            )
        ));
        assert_ok!(fs::set_permissions(
            &script,
            fs::Permissions::from_mode(0o755)
        ));
        script
    }

    struct Rig {
        _tree: Tree,
        project: CanonicalPath,
        dir: PathBuf,
        socket: PathBuf,
        service: Service,
    }

    fn rig(share: impl Fn(&Path) -> String) -> Rig {
        let tree = Tree::new();
        let root = tree.inside_home("proj");
        assert_ok!(fs::create_dir_all(root.join("data")));
        let project = canonical(&root);
        let dir = tree.base().join("fake");
        let machine_dir = dir.join("machine");
        assert_ok!(fs::create_dir_all(&machine_dir));
        assert_ok!(fs::write(
            machine_dir.join("m.json"),
            json!({"Mounts": [{"Source": share(&root), "Target": "/x", "ReadOnly": false}]})
                .to_string()
        ));
        let podman = fake_podman(
            &dir,
            &machine_dir,
            &format!("{}/data", project.as_str()),
            "/Users/someone/.ssh",
        );
        let mut scope = Scope::default();
        scope.set_for_test(
            Some(assert_ok!(ContainerLabel::parse("proj=x"))),
            vec![],
            vec![assert_ok!(LaunchdLabel::parse("com.example.db"))],
        );
        let socket = PathBuf::from(format!(
            "/tmp/hb-svc-{}-{}.sock",
            std::process::id(),
            tree.base()
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned())
        ));
        let service = assert_ok!(start(Inputs {
            scope,
            project: project.clone(),
            programs: Programs {
                podman: Some(podman),
                launchctl: PathBuf::from("/bin/launchctl")
            },
            exec: Arc::new(Host::new("/usr/bin:/bin", |_| None)),
            socket: socket.clone(),
            euid: 501,
            connection: None,
            container_host: None,
        }));
        Rig {
            _tree: tree,
            project,
            dir,
            socket,
            service,
        }
    }

    fn ask(rig: &Rig, op: ContainerOp, name: &str) -> crate::ctl::op::Response {
        assert_ok!(send(
            Some(&rig.socket),
            Command::Container {
                op,
                name: Some(name.into()),
                tail: None
            }
        ))
    }

    #[test]
    fn test_startup_pins_the_good_containers_sources_and_warns_about_the_bad_one() {
        let r = rig(|root| root.to_string_lossy().into_owned());
        assert_eq!(
            r.service.pins,
            [assert_ok!(CanonicalPath::from_canonical(format!(
                "{}/data",
                r.project.as_str()
            )))]
        );
        assert_eq!(r.service.warnings.len(), 1, "{:?}", r.service.warnings);
        assert!(
            r.service.warnings[0].starts_with("bad: ")
                && r.service.warnings[0].contains("privileged"),
            "{:?}",
            r.service.warnings
        );
    }

    #[test]
    fn test_over_the_socket_restart_works_for_the_vetted_container_and_not_for_the_refused_one() {
        let r = rig(|root| root.to_string_lossy().into_owned());
        let ok = ask(&r, ContainerOp::Restart, "good");
        assert!(ok.ok, "{ok:?}");
        assert!(ok.out.contains(&format!("did {ID_OK}")), "{}", ok.out);
        let no = ask(&r, ContainerOp::Restart, "bad");
        assert!(!no.ok, "{no:?}");
        let calls = assert_ok!(fs::read_to_string(r.dir.join("calls")));
        assert!(
            calls.contains(&format!("restart -t 10 -- {ID_OK}")),
            "{calls}"
        );
        assert!(
            !calls.contains(ID_BAD),
            "nothing may be run against the refused container: {calls}"
        );
        let stop_bad = ask(&r, ContainerOp::Stop, "bad");
        assert!(!stop_bad.ok, "preflight applies to every named operation");
    }

    #[test]
    fn test_a_vm_that_shares_more_than_the_project_disables_start_and_restart_and_pins_nothing() {
        let r = rig(|root| {
            root.parent()
                .map_or_else(|| "/".into(), |p| p.to_string_lossy().into_owned())
        });
        assert!(r.service.pins.is_empty());
        assert!(
            r.service
                .warnings
                .iter()
                .any(|w| w.contains("start and restart are unavailable")
                    && w.contains("podman machine init --volume")),
            "{:?}",
            r.service.warnings
        );
        let no = ask(&r, ContainerOp::Restart, "good");
        assert!(
            !no.ok && no.err.contains("podman machine init --volume"),
            "{no:?}"
        );
        let logs = ask(&r, ContainerOp::Logs, "good");
        assert!(logs.ok, "reads still work: {logs:?}");
    }

    #[test]
    fn test_the_socket_is_removed_when_the_broker_finishes() {
        let r = rig(|root| root.to_string_lossy().into_owned());
        assert!(r.socket.exists());
        let socket = r.socket.clone();
        r.service.broker.finish();
        assert!(!socket.exists());
    }
}
