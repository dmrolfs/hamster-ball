// ABOUTME: Decides whether an inspected container may be driven by `hb ctl`: positive allow-lists for settings and mounts.
// ABOUTME: Pure over a typed inspect record plus injected filesystem and volume facts; refusals name the reason and the offending path.
//! Container preflight (design 9.3, hb-ghd.8.2).
//!
//! The rules come from the oracle review in `history/hb-ghd.8_oracle-preflight-pins.md`:
//! a small allow-list, never "anything but host". Anything not understood is refused.

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use snafu::{Snafu, ensure};

use super::argv::ContainerId;
use crate::policy::CanonicalPath;
use crate::text::Escaped;

/// What a bind source is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SourceKind {
    /// A regular file, pinned as a file.
    File,
    /// A directory, pinned as a directory.
    Directory,
}

/// One accepted bind source, to be pinned.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MountSource {
    /// The exact resolved path, equal to the spelling podman stores.
    pub path: CanonicalPath,
    /// File or directory.
    pub kind: SourceKind,
}

/// What a passing preflight leaves behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vetted {
    /// The immutable ID every command must use.
    pub id: ContainerId,
    /// The exact name that was inspected.
    pub name: String,
    /// Every bind source, for pinning and for the start gate.
    pub sources: Vec<MountSource>,
}

/// Why a container is refused. Every message says what and, where there is one, which path.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The inspect text was not exactly one understood record.
    #[snafu(display("podman inspect output was not understood: {detail}"))]
    Unreadable {
        /// The parse failure (from serde, no inspect content).
        detail: String,
    },
    /// The inspected name is not the requested one (an ID prefix can resolve to another container).
    #[snafu(display(
        "inspected container is {} but {} was requested",
        Escaped(found),
        Escaped(wanted)
    ))]
    WrongName {
        /// The exact name asked for.
        wanted: String,
        /// The name podman returned.
        found: String,
    },
    /// The ID was not 64 lowercase hex characters.
    #[snafu(display("container ID is not a full podman ID"))]
    BadId,
    /// Not in the approved selectors.
    #[snafu(display(
        "{} is not in the approved scope ([ctl] label or containers)",
        Escaped(name)
    ))]
    OutOfScope {
        /// The container.
        name: String,
    },
    /// A setting that is refused.
    #[snafu(display("{setting} is {} (refused: {why})", Escaped(value)))]
    Setting {
        /// Which setting.
        setting: &'static str,
        /// Its value.
        value: String,
        /// Why.
        why: &'static str,
    },
    /// A mount that is refused.
    #[snafu(display("mount {} is refused: {why}", Escaped(what)))]
    Mount {
        /// The source or name.
        what: String,
        /// Why.
        why: String,
    },
    /// A bind source that is not a real file or directory inside the project.
    #[snafu(display("bind source {} is refused: {problem}", Escaped(path)))]
    Source {
        /// The path as podman stores it.
        path: String,
        /// The problem.
        problem: SourceProblem,
    },
    /// A volume that could expose a host path or is not understood.
    #[snafu(display("volume {} is refused: {why}", Escaped(name)))]
    Volume {
        /// The volume.
        name: String,
        /// Why.
        why: String,
    },
}

/// Why a bind source cannot be accepted.
#[derive(Debug, Snafu, PartialEq, Eq, Clone)]
#[non_exhaustive]
pub enum SourceProblem {
    /// Not an absolute, normalized, printable path.
    #[snafu(display("not an absolute normalized path"))]
    Malformed,
    /// A component does not exist.
    #[snafu(display("does not exist"))]
    Missing,
    /// A component is a symlink (podman re-resolves it at start).
    #[snafu(display("a component is a symlink: {}", Escaped(at)))]
    Symlink {
        /// The first symlink component.
        at: String,
    },
    /// Not a regular file or a directory (socket, device, fifo).
    #[snafu(display("not a regular file or directory"))]
    SpecialFile,
    /// Outside the project root.
    #[snafu(display("outside the project root"))]
    OutsideProject,
    /// The OS resolves it to a different spelling (case, Unicode or a firmlink alias).
    #[snafu(display("the real path is {}", Escaped(real)))]
    Respelled {
        /// The resolved spelling.
        real: String,
    },
    /// A regular file with more than one hard link: a pin protects names, not aliases.
    #[snafu(display("a file with more than one hard link"))]
    HardLinked,
    /// The filesystem could not be examined.
    #[snafu(display("could not be examined: {detail}"))]
    Examine {
        /// The OS error text.
        detail: String,
    },
}

/// What the volume driver reports for one volume.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeFacts {
    /// The volume name returned by `podman volume inspect`.
    pub name: String,
    /// Its driver.
    pub driver: String,
    /// Whether it has any option at all (a `device` option makes a host directory a volume).
    pub has_options: bool,
}

/// What preflight needs from outside the record: the filesystem and the volume store.
pub trait Facts {
    /// Examine one bind source against the project root.
    ///
    /// # Errors
    /// [`SourceProblem`] if it must be refused.
    fn bind_source(
        &self,
        path: &str,
        project: &CanonicalPath,
    ) -> Result<MountSource, SourceProblem>;

    /// Inspect one volume by its exact name.
    ///
    /// # Errors
    /// A short reason when the volume cannot be inspected.
    fn volume(&self, name: &str) -> Result<VolumeFacts, String>;
}

// ---------------------------------------------------------------------------------------
// The record
// ---------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Record {
    id: String,
    name: String,
    config: ConfigPart,
    host_config: HostConfig,
    #[serde(default)]
    mounts: Vec<MountDecl>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConfigPart {
    #[serde(default)]
    labels: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HostConfig {
    privileged: bool,
    network_mode: String,
    pid_mode: String,
    ipc_mode: String,
    userns_mode: String,
    #[serde(rename = "UTSMode")]
    uts_mode: String,
    cgroup_mode: String,
    #[serde(default)]
    cap_add: Option<Vec<String>>,
    #[serde(default)]
    security_opt: Option<Vec<String>>,
    #[serde(default)]
    devices: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    device_cgroup_rules: Option<Vec<String>>,
    #[serde(default)]
    volumes_from: Option<Vec<String>>,
    #[serde(default)]
    binds: Option<Vec<String>>,
    #[serde(default)]
    tmpfs: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MountDecl {
    #[serde(rename = "Type")]
    kind: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    source: String,
    destination: String,
    #[serde(default)]
    propagation: String,
}

/// The configured label key and value to match, from [`super::scope::Scope`].
#[derive(Debug, Clone, Copy)]
pub struct Selection<'a> {
    /// Names listed in `[ctl] containers`, exact.
    pub names: &'a BTreeSet<String>,
    /// `[ctl] label` as key and value.
    pub label: Option<(&'a str, &'a str)>,
}

/// Run every check. `wanted` is the exact name that was asked for.
///
/// # Errors
/// The first [`Refusal`]. Checks run in a fixed order, so a message is stable.
pub fn preflight(
    inspect_json: &str,
    wanted: &str,
    selection: Selection<'_>,
    project: &CanonicalPath,
    facts: &dyn Facts,
) -> Result<Vetted, Refusal> {
    let record = parse(inspect_json)?;
    let id = ContainerId::parse(&record.id).ok_or(Refusal::BadId)?;
    ensure!(
        record.name == wanted,
        WrongNameSnafu {
            wanted,
            found: record.name.clone()
        }
    );
    ensure!(
        in_scope(&record, &selection),
        OutOfScopeSnafu {
            name: record.name.clone()
        }
    );
    check_settings(&record.host_config)?;
    let sources = check_mounts(&record, project, facts)?;
    Ok(Vetted {
        id,
        name: record.name,
        sources,
    })
}

/// The full ID in an inspect record, whether or not the rest of it is acceptable.
#[must_use]
pub fn container_id(inspect_json: &str) -> Option<ContainerId> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct IdOnly {
        id: String,
    }
    let mut records: Vec<IdOnly> = serde_json::from_str(inspect_json).ok()?;
    (records.len() == 1)
        .then(|| ContainerId::parse(&records.remove(0).id))
        .flatten()
}

fn parse(json: &str) -> Result<Record, Refusal> {
    let mut records: Vec<Record> = serde_json::from_str(json).map_err(|e| Refusal::Unreadable {
        detail: e.to_string(),
    })?;
    ensure!(
        records.len() == 1,
        UnreadableSnafu {
            detail: format!("expected one record, found {}", records.len())
        }
    );
    Ok(records.remove(0))
}

fn in_scope(record: &Record, selection: &Selection<'_>) -> bool {
    let by_name = selection.names.contains(&record.name);
    let by_label = selection.label.is_some_and(|(key, value)| {
        record
            .config
            .labels
            .as_ref()
            .and_then(|l| l.get(key))
            .is_some_and(|v| v == value)
    });
    by_name || by_label
}

fn refuse(setting: &'static str, value: &str, why: &'static str) -> Refusal {
    Refusal::Setting {
        setting,
        value: value.to_owned(),
        why,
    }
}

fn check_settings(h: &HostConfig) -> Result<(), Refusal> {
    ensure!(
        !h.privileged,
        SettingSnafu {
            setting: "privileged",
            value: "true",
            why: "gives the container the host's devices and capabilities"
        }
    );
    if let Some(cap) = h.cap_add.iter().flatten().next() {
        return Err(refuse(
            "CapAdd",
            cap,
            "added capabilities can reach the kernel or devices",
        ));
    }
    if let Some(dev) = h.devices.iter().flatten().next() {
        return Err(refuse(
            "Devices",
            &dev.to_string(),
            "host devices are not allowed",
        ));
    }
    if let Some(rule) = h.device_cgroup_rules.iter().flatten().next() {
        return Err(refuse(
            "DeviceCgroupRules",
            rule,
            "device rules are not allowed",
        ));
    }
    if let Some(from) = h.volumes_from.iter().flatten().next() {
        return Err(refuse(
            "VolumesFrom",
            from,
            "inherits another container's mounts",
        ));
    }
    for opt in h.security_opt.iter().flatten() {
        if !matches!(
            opt.as_str(),
            "no-new-privileges" | "no-new-privileges=true" | "no-new-privileges:true"
        ) {
            return Err(refuse(
                "SecurityOpt",
                opt,
                "only no-new-privileges is allowed",
            ));
        }
    }
    let modes: [(&'static str, &str, &[&str]); 6] = [
        ("PidMode", &h.pid_mode, &["", "private"]),
        ("UTSMode", &h.uts_mode, &["", "private"]),
        ("CgroupMode", &h.cgroup_mode, &["", "private"]),
        ("UsernsMode", &h.userns_mode, &["", "private"]),
        (
            "IpcMode",
            &h.ipc_mode,
            &["", "private", "shareable", "none"],
        ),
        (
            "NetworkMode",
            &h.network_mode,
            &["bridge", "none", "pasta", "slirp4netns"],
        ),
    ];
    for (setting, value, allowed) in modes {
        if !allowed.contains(&value) {
            return Err(refuse(
                setting,
                value,
                "a host or joined namespace, or a mode that is not understood",
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Mounts
// ---------------------------------------------------------------------------------------

/// tmpfs options that cannot name a host path.
const TMPFS_OPTIONS: [&str; 17] = [
    "size",
    "mode",
    "uid",
    "gid",
    "nr_inodes",
    "ro",
    "rw",
    "nosuid",
    "nodev",
    "noexec",
    "exec",
    "rprivate",
    "private",
    "tmpcopyup",
    "notmpcopyup",
    "noatime",
    "relatime",
];

fn mount_refusal(what: &str, why: impl Into<String>) -> Refusal {
    Refusal::Mount {
        what: what.to_owned(),
        why: why.into(),
    }
}

fn check_mounts(
    record: &Record,
    project: &CanonicalPath,
    facts: &dyn Facts,
) -> Result<Vec<MountSource>, Refusal> {
    let mut sources = Vec::new();
    let mut declared: BTreeSet<(String, String)> = BTreeSet::new();
    for m in &record.mounts {
        match m.kind.as_str() {
            "bind" => {
                ensure!(
                    matches!(m.propagation.as_str(), "" | "rprivate" | "private"),
                    MountSnafu {
                        what: m.source.clone(),
                        why: format!("propagation {} can expose later mounts", m.propagation)
                    }
                );
                let source =
                    facts
                        .bind_source(&m.source, project)
                        .map_err(|problem| Refusal::Source {
                            path: m.source.clone(),
                            problem,
                        })?;
                declared.insert((m.source.clone(), m.destination.clone()));
                sources.push(source);
            }
            "volume" => {
                let name = m.name.clone().unwrap_or_default();
                check_volume(&name, facts)?;
                declared.insert((name, m.destination.clone()));
            }
            "tmpfs" => check_tmpfs_options(&m.destination, None)?,
            other => {
                return Err(mount_refusal(
                    &m.source,
                    format!("mount type {other} is not supported"),
                ));
            }
        }
    }
    for (dest, options) in record.host_config.tmpfs.iter().flatten() {
        check_tmpfs_options(dest, Some(options))?;
    }
    reconcile_binds(
        record.host_config.binds.as_deref().unwrap_or_default(),
        &declared,
    )?;
    sources.sort();
    sources.dedup();
    Ok(sources)
}

fn check_tmpfs_options(dest: &str, options: Option<&str>) -> Result<(), Refusal> {
    for option in options
        .into_iter()
        .flat_map(|o| o.split(','))
        .filter(|o| !o.is_empty())
    {
        let key = option.split('=').next().unwrap_or_default();
        ensure!(
            TMPFS_OPTIONS.contains(&key),
            MountSnafu {
                what: dest,
                why: format!("tmpfs option {key} is not allowed")
            }
        );
    }
    Ok(())
}

fn check_volume(name: &str, facts: &dyn Facts) -> Result<(), Refusal> {
    let refuse = |why: String| Refusal::Volume {
        name: name.to_owned(),
        why,
    };
    ensure!(
        !name.is_empty(),
        VolumeSnafu {
            name,
            why: "a volume mount has no name"
        }
    );
    let v = facts.volume(name).map_err(refuse)?;
    ensure!(
        v.name == name,
        VolumeSnafu {
            name,
            why: "podman returned a different volume"
        }
    );
    ensure!(
        v.driver == "local",
        VolumeSnafu {
            name,
            why: format!("driver {} is not local", v.driver)
        }
    );
    ensure!(
        !v.has_options,
        VolumeSnafu {
            name,
            why: "has options (a device option can make a host directory a volume)"
        }
    );
    Ok(())
}

/// `HostConfig.Binds` and `Mounts` describe the same mounts; any difference is refused.
fn reconcile_binds(binds: &[String], declared: &BTreeSet<(String, String)>) -> Result<(), Refusal> {
    let mut from_binds = BTreeSet::new();
    for bind in binds {
        let parts: Vec<&str> = bind.split(':').collect();
        ensure!(
            (2..=3).contains(&parts.len()) && !parts[0].is_empty() && parts[1].starts_with('/'),
            MountSnafu {
                what: bind.as_str(),
                why: "the bind description is ambiguous"
            }
        );
        from_binds.insert((parts[0].to_owned(), parts[1].to_owned()));
    }
    if let Some(extra) = from_binds.symmetric_difference(declared).next() {
        return Err(mount_refusal(
            &extra.0,
            "Binds and Mounts disagree about this mount",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use serde_json::{Value, json};

    const ID: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn project() -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical("/Users/me/proj"))
    }

    /// Facts that accept paths under the project, with a table of volumes.
    struct Fake {
        volumes: BTreeMap<String, VolumeFacts>,
        problems: BTreeMap<String, SourceProblem>,
    }

    impl Fake {
        fn new() -> Self {
            Self {
                volumes: BTreeMap::new(),
                problems: BTreeMap::new(),
            }
        }
    }

    impl Facts for Fake {
        fn bind_source(
            &self,
            path: &str,
            project: &CanonicalPath,
        ) -> Result<MountSource, SourceProblem> {
            if let Some(p) = self.problems.get(path) {
                return Err(p.clone());
            }
            let p = CanonicalPath::from_canonical(path).map_err(|_| SourceProblem::Malformed)?;
            if !project.is_same_or_ancestor_of(&p) {
                return Err(SourceProblem::OutsideProject);
            }
            let kind = if path.ends_with(".yaml") {
                SourceKind::File
            } else {
                SourceKind::Directory
            };
            Ok(MountSource { path: p, kind })
        }

        fn volume(&self, name: &str) -> Result<VolumeFacts, String> {
            self.volumes
                .get(name)
                .cloned()
                .ok_or_else(|| "no such volume".to_owned())
        }
    }

    fn record() -> Value {
        json!({
            "Id": ID, "Name": "db",
            "Config": {"Labels": {"com.docker.compose.project": "icehouse"}},
            "HostConfig": {
                "Privileged": false, "NetworkMode": "bridge", "PidMode": "private", "IpcMode": "shareable",
                "UsernsMode": "", "UTSMode": "private", "CgroupMode": "private", "CapAdd": [],
                "SecurityOpt": [], "Devices": [], "DeviceCgroupRules": null, "VolumesFrom": null,
                "Binds": ["/Users/me/proj/data:/data:rprivate,rbind"], "Tmpfs": {}
            },
            "Mounts": [{"Type": "bind", "Source": "/Users/me/proj/data", "Destination": "/data", "Propagation": "rprivate"}]
        })
    }

    fn selection<'a>(names: &'a BTreeSet<String>) -> Selection<'a> {
        Selection {
            names,
            label: Some(("com.docker.compose.project", "icehouse")),
        }
    }

    fn run(rec: &Value, facts: &Fake) -> Result<Vetted, Refusal> {
        let names = BTreeSet::new();
        preflight(
            &json!([rec]).to_string(),
            "db",
            selection(&names),
            &project(),
            facts,
        )
    }

    fn edit(f: impl FnOnce(&mut Value)) -> Value {
        let mut r = record();
        f(&mut r);
        r
    }

    #[test]
    fn test_a_plain_project_container_passes_and_yields_its_sources() {
        let v = assert_ok!(run(&record(), &Fake::new()));
        assert_eq!(v.id.as_str(), ID);
        assert_eq!(v.sources.len(), 1);
        assert_eq!(v.sources[0].path.as_str(), "/Users/me/proj/data");
    }

    #[test]
    fn test_host_and_joined_namespaces_privilege_and_extras_are_refused() {
        for (path, value) in [
            ("/HostConfig/Privileged", json!(true)),
            ("/HostConfig/NetworkMode", json!("host")),
            ("/HostConfig/NetworkMode", json!("container:abc")),
            ("/HostConfig/PidMode", json!("host")),
            ("/HostConfig/IpcMode", json!("host")),
            ("/HostConfig/UsernsMode", json!("host")),
            ("/HostConfig/UTSMode", json!("host")),
            ("/HostConfig/CgroupMode", json!("host")),
            ("/HostConfig/CapAdd", json!(["CAP_NET_ADMIN"])),
            ("/HostConfig/Devices", json!([{"PathOnHost": "/dev/fuse"}])),
            ("/HostConfig/DeviceCgroupRules", json!(["c 1:3 mr"])),
            ("/HostConfig/VolumesFrom", json!(["other"])),
            ("/HostConfig/SecurityOpt", json!(["seccomp=unconfined"])),
            ("/HostConfig/SecurityOpt", json!(["label=disable"])),
            ("/HostConfig/SecurityOpt", json!(["unmask=all"])),
        ] {
            let rec =
                edit(|r| *r.pointer_mut(path).unwrap_or_else(|| unreachable!()) = value.clone());
            assert!(
                matches!(
                    assert_err!(run(&rec, &Fake::new()), "{path}={value}"),
                    Refusal::Setting { .. }
                ),
                "{path}={value}"
            );
        }
    }

    #[test]
    fn test_understood_defaults_are_accepted() {
        for (path, value) in [
            ("/HostConfig/IpcMode", json!("private")),
            ("/HostConfig/IpcMode", json!("none")),
            ("/HostConfig/NetworkMode", json!("none")),
            ("/HostConfig/NetworkMode", json!("pasta")),
            ("/HostConfig/SecurityOpt", json!(["no-new-privileges"])),
            ("/HostConfig/UsernsMode", json!("private")),
        ] {
            let rec =
                edit(|r| *r.pointer_mut(path).unwrap_or_else(|| unreachable!()) = value.clone());
            assert_ok!(run(&rec, &Fake::new()), "{path}={value}");
        }
    }

    #[test]
    fn test_name_must_equal_the_request_and_scope_must_match() {
        let names = BTreeSet::new();
        let rec = json!([record()]).to_string();
        assert!(matches!(
            assert_err!(preflight(
                &rec,
                "other",
                selection(&names),
                &project(),
                &Fake::new()
            )),
            Refusal::WrongName { .. }
        ));
        let other_label = Selection {
            names: &names,
            label: Some(("com.docker.compose.project", "x")),
        };
        assert!(matches!(
            assert_err!(preflight(&rec, "db", other_label, &project(), &Fake::new())),
            Refusal::OutOfScope { .. }
        ));
        let by_name: BTreeSet<String> = ["db".to_owned()].into();
        assert_ok!(preflight(
            &rec,
            "db",
            Selection {
                names: &by_name,
                label: None
            },
            &project(),
            &Fake::new()
        ));
    }

    #[test]
    fn test_unreadable_or_multiple_records_and_bad_ids_are_refused() {
        let names = BTreeSet::new();
        let sel = || selection(&names);
        for bad in [
            "",
            "{}",
            "[]",
            "not json",
            &json!([record(), record()]).to_string(),
        ] {
            assert!(
                matches!(
                    assert_err!(preflight(bad, "db", sel(), &project(), &Fake::new())),
                    Refusal::Unreadable { .. }
                ),
                "{bad}"
            );
        }
        let rec = edit(|r| r["Id"] = json!("abc"));
        assert!(matches!(
            assert_err!(run(&rec, &Fake::new())),
            Refusal::BadId
        ));
        let missing = edit(|r| {
            r["HostConfig"]
                .as_object_mut()
                .map(|h| h.remove("Privileged"));
        });
        assert!(matches!(
            assert_err!(run(&missing, &Fake::new())),
            Refusal::Unreadable { .. }
        ));
    }

    #[test]
    fn test_bind_sources_outside_the_project_or_with_problems_name_the_path() {
        let outside = edit(|r| {
            r["Mounts"][0]["Source"] = json!("/Users/me/.ssh");
            r["HostConfig"]["Binds"] = json!(["/Users/me/.ssh:/data"]);
        });
        let err = assert_err!(run(&outside, &Fake::new()));
        assert!(
            matches!(&err, Refusal::Source { path, problem: SourceProblem::OutsideProject } if path == "/Users/me/.ssh")
        );
        assert!(err.to_string().contains("/Users/me/.ssh"));
        for problem in [
            SourceProblem::Symlink {
                at: "/Users/me/proj/l".into(),
            },
            SourceProblem::Missing,
            SourceProblem::SpecialFile,
            SourceProblem::HardLinked,
            SourceProblem::Respelled {
                real: "/Users/me/proj/Data".into(),
            },
        ] {
            let mut fake = Fake::new();
            fake.problems
                .insert("/Users/me/proj/data".into(), problem.clone());
            assert_eq!(
                assert_err!(run(&record(), &fake)),
                Refusal::Source {
                    path: "/Users/me/proj/data".into(),
                    problem
                }
            );
        }
    }

    #[test]
    fn test_propagation_other_than_private_is_refused() {
        for p in ["shared", "rshared", "slave", "rslave"] {
            let rec = edit(|r| r["Mounts"][0]["Propagation"] = json!(p));
            assert!(matches!(
                assert_err!(run(&rec, &Fake::new()), "{p}"),
                Refusal::Mount { .. }
            ));
        }
    }

    fn with_volume() -> Value {
        edit(|r| {
            r["Mounts"] = json!([{"Type": "volume", "Name": "pgdata", "Source": "/var/home/core/x", "Destination": "/v"}]);
            r["HostConfig"]["Binds"] = json!(["pgdata:/v:rprivate,nosuid,nodev,rbind"]);
        })
    }

    #[test]
    fn test_only_plain_local_volumes_are_accepted() {
        let good = VolumeFacts {
            name: "pgdata".into(),
            driver: "local".into(),
            has_options: false,
        };
        let mut fake = Fake::new();
        fake.volumes.insert("pgdata".into(), good.clone());
        assert!(assert_ok!(run(&with_volume(), &fake)).sources.is_empty());
        for bad in [
            VolumeFacts {
                has_options: true,
                ..good.clone()
            },
            VolumeFacts {
                driver: "nfs".into(),
                ..good.clone()
            },
            VolumeFacts {
                name: "other".into(),
                ..good
            },
        ] {
            let mut fake = Fake::new();
            fake.volumes.insert("pgdata".into(), bad);
            assert!(matches!(
                assert_err!(run(&with_volume(), &fake)),
                Refusal::Volume { .. }
            ));
        }
        assert!(matches!(
            assert_err!(run(&with_volume(), &Fake::new())),
            Refusal::Volume { .. }
        ));
    }

    #[test]
    fn test_tmpfs_is_allowed_with_plain_options_and_unknown_types_are_refused() {
        let ok = edit(|r| {
            r["HostConfig"]["Tmpfs"] = json!({"/t": "size=1m,rprivate,nosuid,nodev,tmpcopyup"});
        });
        assert_ok!(run(&ok, &Fake::new()));
        let bad_opt = edit(|r| r["HostConfig"]["Tmpfs"] = json!({"/t": "bind=/Users/me"}));
        assert!(matches!(
            assert_err!(run(&bad_opt, &Fake::new())),
            Refusal::Mount { .. }
        ));
        for kind in ["devpts", "image", "artifact", "overlay", "weird"] {
            let rec = edit(|r| r["Mounts"][0]["Type"] = json!(kind));
            assert!(matches!(
                assert_err!(run(&rec, &Fake::new()), "{kind}"),
                Refusal::Mount { .. }
            ));
        }
    }

    #[test]
    fn test_binds_and_mounts_must_describe_the_same_mounts() {
        let hidden = edit(|r| {
            r["HostConfig"]["Binds"] = json!(["/Users/me/proj/data:/data", "/Users/me/.ssh:/ssh"])
        });
        assert!(matches!(
            assert_err!(run(&hidden, &Fake::new())),
            Refusal::Mount { .. }
        ));
        let missing = edit(|r| r["HostConfig"]["Binds"] = json!([]));
        assert!(matches!(
            assert_err!(run(&missing, &Fake::new())),
            Refusal::Mount { .. }
        ));
        let ambiguous = edit(|r| r["HostConfig"]["Binds"] = json!(["/Users/me/a:b:/data:ro:x"]));
        assert!(matches!(
            assert_err!(run(&ambiguous, &Fake::new())),
            Refusal::Mount { .. }
        ));
    }
}
