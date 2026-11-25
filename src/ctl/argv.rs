// ABOUTME: Fixed argument vectors for podman and launchctl, built only from validated request types.
// ABOUTME: Names follow `--` and the full inspected container ID is used for acting; no client text is a flag.
//! Fixed command lines.

use std::ffi::OsString;

use super::op::ContainerOp;
use crate::policy::{ContainerLabel, ContainerName, LaunchdLabel};

/// Words after the executable name.
pub type Argv = Vec<OsString>;

fn words<const N: usize>(items: [&str; N]) -> Argv {
    items.into_iter().map(OsString::from).collect()
}

/// A full container ID read from `podman inspect`, never from the client.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ContainerId(String);

impl ContainerId {
    /// Parse the 64-character hexadecimal ID podman reports.
    #[must_use]
    pub fn parse(id: &str) -> Option<Self> {
        (id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
        .then(|| Self(id.to_owned()))
    }

    /// The ID as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Metadata inspection for one requested name; the broker compares the returned exact Name.
#[must_use]
pub fn inspect(name: &ContainerName) -> Argv {
    words(["inspect", "--type", "container", "--"])
        .into_iter()
        .chain([OsString::from(name.as_str())])
        .collect()
}

/// Inspect one local volume by the exact name found in a mount description.
#[must_use]
pub fn volume_inspect(name: &str) -> Argv {
    words(["volume", "inspect", "--format", "json", "--"])
        .into_iter()
        .chain([OsString::from(name)])
        .collect()
}

/// List candidates by the one configured selector (never an agent-selected filter).
#[must_use]
pub fn list_by_label(label: &ContainerLabel) -> Argv {
    words(["ps", "-a", "--format", "json", "--filter"])
        .into_iter()
        .chain([OsString::from(format!("label={label}"))])
        .collect()
}

/// List one explicit configured name, anchored so podman does not treat it as a substring.
#[must_use]
pub fn list_by_name(name: &ContainerName) -> Argv {
    words(["ps", "-a", "--format", "json", "--filter"])
        .into_iter()
        .chain([OsString::from(format!("name=^{}$", name.as_str()))])
        .collect()
}

/// Act on a container already vetted by exact ID. `Ps` has no per-container command.
#[must_use]
pub fn container_operation(op: ContainerOp, id: &ContainerId, tail: u16) -> Option<Argv> {
    let target = OsString::from(id.as_str());
    let mut argv = match op {
        ContainerOp::Ps => return None,
        ContainerOp::Logs => words(["logs", "--tail"])
            .into_iter()
            .chain([OsString::from(tail.to_string()), OsString::from("--")])
            .collect(),
        ContainerOp::Stats => words([
            "stats",
            "--no-stream",
            "--format",
            "{{.CPUPerc}} {{.MemUsage}}",
            "--",
        ]),
        ContainerOp::Start => words(["start", "--"]),
        ContainerOp::Stop => words(["stop", "-t", "10", "--"]),
        ContainerOp::Restart => words(["restart", "-t", "10", "--"]),
    };
    argv.push(target);
    Some(argv)
}

/// `gui/<euid>/<label>`: the user domain is never taken from the client.
#[must_use]
pub fn launchd_target(euid: u32, label: &LaunchdLabel) -> OsString {
    format!("gui/{euid}/{label}").into()
}

/// Print one job (stdout is projected by the broker and never returned raw).
#[must_use]
pub fn launchd_print(euid: u32, label: &LaunchdLabel) -> Argv {
    vec!["print".into(), launchd_target(euid, label)]
}

/// Start a loaded job, optionally killing a running instance first.
#[must_use]
pub fn launchd_kickstart(euid: u32, label: &LaunchdLabel, kill_running: bool) -> Argv {
    let mut argv = vec![OsString::from("kickstart")];
    if kill_running {
        argv.push("-k".into());
    }
    argv.push(launchd_target(euid, label));
    argv
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    fn text(argv: Argv) -> Vec<String> {
        argv.into_iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect()
    }

    fn id() -> ContainerId {
        assert_ok!(ContainerId::parse(&"a".repeat(64)).ok_or("id"))
    }

    #[test]
    fn test_container_argv_is_fixed_and_acts_after_double_dash_on_the_id() {
        let id = id();
        for (op, expected) in [
            (ContainerOp::Logs, vec!["logs", "--tail", "7", "--"]),
            (
                ContainerOp::Stats,
                vec![
                    "stats",
                    "--no-stream",
                    "--format",
                    "{{.CPUPerc}} {{.MemUsage}}",
                    "--",
                ],
            ),
            (ContainerOp::Start, vec!["start", "--"]),
            (ContainerOp::Stop, vec!["stop", "-t", "10", "--"]),
            (ContainerOp::Restart, vec!["restart", "-t", "10", "--"]),
        ] {
            let mut want: Vec<String> = expected.into_iter().map(str::to_owned).collect();
            want.push(id.as_str().to_owned());
            assert_eq!(
                text(assert_ok!(container_operation(op, &id, 7).ok_or("argv"))),
                want
            );
        }
        assert!(container_operation(ContainerOp::Ps, &id, 1).is_none());
    }

    #[test]
    fn test_metadata_argv_cannot_turn_a_name_into_an_option() {
        let name = assert_ok!(ContainerName::parse("db-1"));
        assert_eq!(
            text(inspect(&name)),
            ["inspect", "--type", "container", "--", "db-1"]
        );
        assert_eq!(
            text(list_by_name(&name)).last().map(String::as_str),
            Some("name=^db-1$")
        );
        assert_eq!(
            text(volume_inspect("v1")),
            ["volume", "inspect", "--format", "json", "--", "v1"]
        );
        let label = assert_ok!(ContainerLabel::parse("com.docker.compose.project=icehouse"));
        assert_eq!(
            text(list_by_label(&label)).last().map(String::as_str),
            Some("label=com.docker.compose.project=icehouse")
        );
    }

    #[test]
    fn test_container_id_must_be_podmans_full_lowercase_hex() {
        assert!(ContainerId::parse(&"0123456789abcdef".repeat(4)).is_some());
        for bad in [
            "",
            "abc",
            &"A".repeat(64),
            &"g".repeat(64),
            &"a".repeat(65),
            &"-".repeat(64),
        ] {
            assert!(ContainerId::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn test_launchd_argv_names_one_gui_target_and_only_kickstart_or_print() {
        let label = assert_ok!(LaunchdLabel::parse("com.example.db"));
        assert_eq!(
            text(launchd_print(501, &label)),
            ["print", "gui/501/com.example.db"]
        );
        assert_eq!(
            text(launchd_kickstart(501, &label, false)),
            ["kickstart", "gui/501/com.example.db"]
        );
        assert_eq!(
            text(launchd_kickstart(501, &label, true)),
            ["kickstart", "-k", "gui/501/com.example.db"]
        );
    }
}
