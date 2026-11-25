// ABOUTME: Checks that the podman VM shares nothing but the project, the only thing that stops a container swapping its own mount source.
// ABOUTME: Pure over two JSON texts (`podman machine inspect` and the machine's own config file); fails closed when either is unreadable.
//! Runtime isolation (design 9.3, hb-ghd.8; measured in `history/hb-ghd.8_plan.md`).
//!
//! Pins constrain processes under Seatbelt. A container process is not under Seatbelt, so one that
//! can write a project file it executes can swap a bind source for a symlink and let `podman start`
//! follow it. Measured: the swap fails when the target is not shared with the VM and works when it
//! is. So `start` and `restart` need every VM share to be inside the project.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use snafu::Snafu;

use crate::policy::CanonicalPath;
use crate::text::Escaped;

/// Why `start` and `restart` are not available.
#[derive(Debug, Clone, Snafu, PartialEq, Eq)]
#[non_exhaustive]
pub enum Broad {
    /// The machine's share list could not be read, so nothing can be said about it.
    #[snafu(display("the podman machine's shared directories could not be read: {detail}"))]
    Unknown {
        /// What failed.
        detail: String,
    },
    /// A share reaches outside the project.
    #[snafu(display(
        "the podman VM shares {share} with containers, which is not inside the project {project}; a \
         container could swap its own mount source for a link into that share. Recreate the machine \
         with only the project shared: podman machine init --volume {project}:{project} --now",
        share = Escaped(share),
        project = Escaped(project)
    ))]
    Share {
        /// The share's source directory.
        share: String,
        /// The project root.
        project: String,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MachineInspect {
    name: String,
    config_dir: ConfigDir,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConfigDir {
    path: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct MachineConfig {
    #[serde(default)]
    mounts: Option<Vec<Share>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Share {
    source: String,
}

/// One entry of `podman system connection list --format json`.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Connection {
    name: String,
    #[serde(rename = "URI")]
    uri: String,
    #[serde(default)]
    default: bool,
}

/// `podman machine inspect <name>`: what is needed to tell which connection reaches it.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Described {
    name: String,
    #[serde(rename = "SSHConfig")]
    ssh: Ssh,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Ssh {
    port: u32,
}

/// The `host:port` of a connection URI such as `ssh://core@127.0.0.1:61435/run/...`.
fn endpoint(uri: &str) -> Option<&str> {
    let rest = uri.split_once("://")?.1;
    let authority = rest.split('/').next()?;
    authority.rsplit('@').next()
}

fn port_of(uri: &str) -> Option<u32> {
    endpoint(uri)?.rsplit_once(':')?.1.parse().ok()
}

/// The connection podman will use: `CONTAINER_HOST` if set, else the one named by
/// `CONTAINER_CONNECTION`, else the one marked default.
///
/// # Errors
/// [`Broad::Unknown`] if the list is unreadable, or the named connection is not in it.
fn active_uri(
    connections_json: &str,
    connection: Option<&str>,
    container_host: Option<&str>,
) -> Result<String, Broad> {
    if let Some(host) = container_host.filter(|h| !h.is_empty()) {
        return Ok(host.to_owned());
    }
    let list: Vec<Connection> =
        serde_json::from_str(connections_json).map_err(|e| Broad::Unknown {
            detail: e.to_string(),
        })?;
    let chosen = match connection.filter(|c| !c.is_empty()) {
        Some(name) => list.into_iter().find(|c| c.name == name),
        None => list.into_iter().find(|c| c.default),
    };
    chosen.map(|c| c.uri).ok_or_else(|| Broad::Unknown {
        detail: "no podman connection is selected".to_owned(),
    })
}

/// Which machine the active connection reaches, matched by SSH port.
///
/// `podman machine inspect` with no name describes the default machine, not the one commands
/// reach, so the shares must be read for the machine found here.
///
/// # Errors
/// [`Broad::Unknown`] when the connection is not a local machine, or two machines claim one port.
pub fn active_machine(
    connections_json: &str,
    connection: Option<&str>,
    container_host: Option<&str>,
    machines_json: &[&str],
) -> Result<(String, PathBuf), Broad> {
    let uri = active_uri(connections_json, connection, container_host)?;
    let port = port_of(&uri).ok_or_else(|| Broad::Unknown {
        detail: "the active podman connection has no port".to_owned(),
    })?;
    let mut found = Vec::new();
    for text in machines_json {
        let described: Vec<Described> = serde_json::from_str(text).map_err(|e| Broad::Unknown {
            detail: e.to_string(),
        })?;
        for machine in described {
            if machine.ssh.port == port {
                found.push((machine.name.clone(), config_file(text)?));
            }
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(Broad::Unknown {
            detail: "the active podman connection is not a local podman machine".to_owned(),
        }),
        _ => Err(Broad::Unknown {
            detail: "more than one podman machine claims the active connection's port".to_owned(),
        }),
    }
}

/// Names from `podman machine list --format json`, each safe to pass as one argument.
///
/// # Errors
/// [`Broad::Unknown`] if the text is not a list.
pub fn machine_names(list_json: &str) -> Result<Vec<String>, Broad> {
    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Row {
        name: String,
    }
    let rows: Vec<Row> = serde_json::from_str(list_json).map_err(|e| Broad::Unknown {
        detail: e.to_string(),
    })?;
    Ok(rows
        .into_iter()
        .map(|r| r.name)
        .filter(|n| !n.is_empty() && !n.starts_with(['-', '.']) && !n.contains('/'))
        .collect())
}

/// Where the machine's own config file is, from `podman machine inspect` output.
///
/// # Errors
/// [`Broad::Unknown`] if the text is not one understood record.
pub fn config_file(inspect_json: &str) -> Result<PathBuf, Broad> {
    let mut machines: Vec<MachineInspect> =
        serde_json::from_str(inspect_json).map_err(|e| Broad::Unknown {
            detail: e.to_string(),
        })?;
    if machines.len() != 1 {
        return Err(Broad::Unknown {
            detail: format!("expected one machine, found {}", machines.len()),
        });
    }
    let m = machines.remove(0);
    if m.name.is_empty() || m.name.contains('/') || m.name.starts_with('.') {
        return Err(Broad::Unknown {
            detail: "the machine name is not a plain name".to_owned(),
        });
    }
    Ok(Path::new(&m.config_dir.path).join(format!("{}.json", m.name)))
}

/// Requires every share to be the project or inside it. `real` resolves a share to its real path
/// (so a share reached through a link is judged by where it ends up).
///
/// # Errors
/// [`Broad`] naming the first share outside the project, or that the list is unreadable or empty.
pub fn check(
    machine_json: &str,
    project: &CanonicalPath,
    real: impl Fn(&str) -> Option<CanonicalPath>,
) -> Result<(), Broad> {
    let config: MachineConfig = serde_json::from_str(machine_json).map_err(|e| Broad::Unknown {
        detail: e.to_string(),
    })?;
    let shares = config.mounts.ok_or_else(|| Broad::Unknown {
        detail: "the machine file has no Mounts list".to_owned(),
    })?;
    for share in shares {
        let inside = real(&share.source).is_some_and(|p| project.is_same_or_ancestor_of(&p));
        if !inside {
            return Err(Broad::Share {
                share: share.source,
                project: project.as_str().to_owned(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn project() -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical("/Users/me/proj"))
    }

    fn identity(p: &str) -> Option<CanonicalPath> {
        CanonicalPath::from_canonical(p).ok()
    }

    fn machine(sources: &[&str]) -> String {
        let mounts: Vec<String> = sources
            .iter()
            .map(|s| format!(r#"{{"Source":"{s}","Target":"{s}","ReadOnly":false}}"#))
            .collect();
        format!(r#"{{"Mounts":[{}]}}"#, mounts.join(","))
    }

    #[test]
    fn test_only_the_project_or_things_inside_it_may_be_shared() {
        assert_ok!(check(&machine(&["/Users/me/proj"]), &project(), identity));
        assert_ok!(check(
            &machine(&["/Users/me/proj/a", "/Users/me/proj/b"]),
            &project(),
            identity
        ));
    }

    #[test]
    fn test_the_default_shares_and_a_shared_parent_of_the_project_are_refused_with_the_fix() {
        for sources in [
            vec!["/Users", "/private", "/var/folders"],
            vec!["/Users/me"],
            vec!["/Users/me/proj", "/tmp"],
            vec!["/Users/me/proj2"],
        ] {
            let err = assert_err!(
                check(&machine(&sources), &project(), identity),
                "{sources:?}"
            );
            assert!(matches!(err, Broad::Share { .. }));
            assert!(
                err.to_string()
                    .contains("podman machine init --volume /Users/me/proj:/Users/me/proj"),
                "{err}"
            );
        }
    }

    #[test]
    fn test_an_unreadable_missing_or_empty_list_fails_closed() {
        for bad in ["", "{}", "[]", r#"{"Mounts":null}"#, "nonsense"] {
            assert!(
                matches!(
                    assert_err!(check(bad, &project(), identity), "{bad}"),
                    Broad::Unknown { .. }
                ),
                "{bad}"
            );
        }
        // an empty list shares nothing, which is isolated
        assert_ok!(check(r#"{"Mounts":[]}"#, &project(), identity));
        // a share that cannot be resolved is not trusted
        assert!(matches!(
            assert_err!(check(&machine(&["/Users/me/proj/x"]), &project(), |_| None)),
            Broad::Share { .. }
        ));
    }

    #[test]
    fn test_the_machine_file_comes_from_podman_machine_inspect() {
        let inspect = r#"[{"Name":"podman-machine-default","ConfigDir":{"Path":"/Users/me/.config/containers/podman/machine/applehv"}}]"#;
        assert_eq!(
            assert_ok!(config_file(inspect)),
            PathBuf::from(
                "/Users/me/.config/containers/podman/machine/applehv/podman-machine-default.json"
            )
        );
        for bad in [
            "",
            "[]",
            "[{},{}]",
            r#"[{"Name":"../x","ConfigDir":{"Path":"/a"}}]"#,
            r#"[{"Name":"","ConfigDir":{"Path":"/a"}}]"#,
        ] {
            assert!(matches!(
                assert_err!(config_file(bad), "{bad}"),
                Broad::Unknown { .. }
            ));
        }
    }

    fn conns() -> &'static str {
        r#"[{"Name":"hbiso","URI":"ssh://core@127.0.0.1:61435/run/user/502/podman/podman.sock","Default":false},
            {"Name":"hbiso-root","URI":"ssh://root@127.0.0.1:61435/run/podman/podman.sock","Default":false},
            {"Name":"podman-machine-default","URI":"ssh://core@127.0.0.1:53131/run/user/502/podman/podman.sock","Default":true}]"#
    }

    fn machine_json(name: &str, port: u32) -> String {
        format!(
            r#"[{{"Name":"{name}","SSHConfig":{{"Port":{port}}},"ConfigDir":{{"Path":"/c"}}}}]"#
        )
    }

    #[test]
    fn test_the_machine_read_is_the_one_the_active_connection_reaches_not_the_default() {
        let (iso, def) = (
            machine_json("hbiso", 61435),
            machine_json("podman-machine-default", 53131),
        );
        let both = [iso.as_str(), def.as_str()];
        // by name, by default flag, and by CONTAINER_HOST
        assert_eq!(
            assert_ok!(active_machine(conns(), Some("hbiso"), None, &both)).0,
            "hbiso"
        );
        assert_eq!(
            assert_ok!(active_machine(conns(), Some("hbiso-root"), None, &both)).0,
            "hbiso"
        );
        assert_eq!(
            assert_ok!(active_machine(conns(), None, None, &both)).0,
            "podman-machine-default"
        );
        assert_eq!(
            assert_ok!(active_machine(
                conns(),
                None,
                Some("ssh://core@127.0.0.1:61435/x"),
                &both
            ))
            .0,
            "hbiso"
        );
        assert_eq!(
            assert_ok!(active_machine(conns(), Some("hbiso"), None, &both)).1,
            PathBuf::from("/c/hbiso.json")
        );
    }

    #[test]
    fn test_a_connection_that_is_not_a_local_machine_or_is_ambiguous_fails_closed() {
        let (iso, def) = (
            machine_json("hbiso", 61435),
            machine_json("podman-machine-default", 53131),
        );
        let both = [iso.as_str(), def.as_str()];
        for (connection, host) in [
            (Some("nope"), None),
            (None, Some("ssh://u@build.example.com:22/x")),
            (None, Some("unix:///run/podman.sock")),
            (None, Some("tcp://127.0.0.1:2375")),
        ] {
            assert!(matches!(
                assert_err!(
                    active_machine(conns(), connection, host, &both),
                    "{connection:?} {host:?}"
                ),
                Broad::Unknown { .. }
            ));
        }
        let twin = machine_json("other", 61435);
        let dup = [iso.as_str(), twin.as_str()];
        assert!(matches!(
            assert_err!(active_machine(conns(), Some("hbiso"), None, &dup)),
            Broad::Unknown { .. }
        ));
        for bad in ["", "{}", "garbage"] {
            assert_err!(active_machine(bad, None, None, &both));
        }
        assert_err!(active_machine(conns(), None, None, &["not json"]));
        assert_err!(active_machine(conns(), None, None, &[]));
    }

    #[test]
    fn test_machine_names_from_the_list_are_plain_arguments() {
        let list = r#"[{"Name":"a"},{"Name":"-x"},{"Name":"../y"},{"Name":""},{"Name":"podman-machine-default"}]"#;
        assert_eq!(
            assert_ok!(machine_names(list)),
            ["a", "podman-machine-default"]
        );
        assert_err!(machine_names("nope"));
    }
}
