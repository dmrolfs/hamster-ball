// ABOUTME: The immutable selectors that decide which containers and launchd jobs a run may touch.
// ABOUTME: Built from the merged policy once at startup; the client has no way to widen it.
//! Approved targets.

use std::collections::BTreeSet;

use crate::config::Policy;
use crate::policy::{ContainerLabel, ContainerName, LaunchdLabel};

/// What the user-owned and approved config lets `hb ctl` touch.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scope {
    label: Option<ContainerLabel>,
    containers: BTreeSet<ContainerName>,
    launchd: BTreeSet<LaunchdLabel>,
}

/// A container as podman reported it, reduced to what scope needs.
#[derive(Debug, Clone, Copy)]
pub struct Candidate<'a> {
    /// Exact `Name` from `podman inspect` (no leading slash).
    pub name: &'a str,
    /// The value of the configured label key, if present.
    pub label_value: Option<&'a str>,
}

impl Scope {
    /// Copy the three selector lists from the merged policy.
    #[must_use]
    pub fn from_policy(policy: &Policy) -> Self {
        Self {
            label: policy.ctl.label.as_ref().map(|l| l.value.clone()),
            containers: policy
                .ctl
                .containers
                .iter()
                .map(|c| c.value.clone())
                .collect(),
            launchd: policy.ctl.launchd.iter().map(|l| l.value.clone()).collect(),
        }
    }

    /// A scope built by hand, for tests of code that takes one.
    #[cfg(test)]
    pub(crate) fn set_for_test(
        &mut self,
        label: Option<ContainerLabel>,
        containers: Vec<ContainerName>,
        launchd: Vec<LaunchdLabel>,
    ) {
        self.label = label;
        self.containers = containers.into_iter().collect();
        self.launchd = launchd.into_iter().collect();
    }

    /// Whether `hb ctl` has any target at all, so a broker is needed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.label.is_none() && self.containers.is_empty() && self.launchd.is_empty()
    }

    /// Whether any container selector exists (a launchd-only run needs no podman).
    #[must_use]
    pub fn has_containers(&self) -> bool {
        self.label.is_some() || !self.containers.is_empty()
    }

    /// The configured label selector.
    #[must_use]
    pub fn label(&self) -> Option<&ContainerLabel> {
        self.label.as_ref()
    }

    /// The explicitly named containers.
    pub fn containers(&self) -> impl Iterator<Item = &ContainerName> {
        self.containers.iter()
    }

    /// Whether the inspected container is in scope: exact listed name, or the exact label value.
    #[must_use]
    pub fn admits(&self, c: Candidate<'_>) -> bool {
        let by_name = ContainerName::parse(c.name).is_ok_and(|n| self.containers.contains(&n));
        let by_label = self
            .label
            .as_ref()
            .is_some_and(|l| c.label_value == Some(l.value()));
        by_name || by_label
    }

    /// Whether this exact job label is owner-listed (the only authority for any launchd operation).
    #[must_use]
    pub fn admits_launchd(&self, label: &LaunchdLabel) -> bool {
        self.launchd.contains(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;

    fn scope() -> Scope {
        Scope {
            label: Some(assert_ok!(ContainerLabel::parse(
                "com.docker.compose.project=myapp"
            ))),
            containers: [assert_ok!(ContainerName::parse("app-db"))].into(),
            launchd: [assert_ok!(LaunchdLabel::parse("com.example.db"))].into(),
        }
    }

    #[test]
    fn test_scope_admits_exact_name_or_exact_label_value_only() {
        let s = scope();
        assert!(s.admits(Candidate {
            name: "app-db",
            label_value: None
        }));
        assert!(s.admits(Candidate {
            name: "api",
            label_value: Some("myapp")
        }));
        assert!(!s.admits(Candidate {
            name: "app-db2",
            label_value: None
        }));
        assert!(!s.admits(Candidate {
            name: "api",
            label_value: Some("myapp2")
        }));
        assert!(!s.admits(Candidate {
            name: "api",
            label_value: None
        }));
        assert!(!s.admits(Candidate {
            name: "--help",
            label_value: Some("other")
        }));
    }

    #[test]
    fn test_container_labels_never_authorize_a_launchd_job() {
        let s = scope();
        assert!(s.admits_launchd(&assert_ok!(LaunchdLabel::parse("com.example.db"))));
        assert!(!s.admits_launchd(&assert_ok!(LaunchdLabel::parse("myapp"))));
        assert!(!s.admits_launchd(&assert_ok!(LaunchdLabel::parse("com.example.db2"))));
    }

    #[test]
    fn test_an_empty_scope_needs_no_broker_and_launchd_alone_needs_no_podman() {
        assert!(Scope::default().is_empty());
        let only_launchd = Scope {
            launchd: scope().launchd,
            ..Scope::default()
        };
        assert!(!only_launchd.is_empty());
        assert!(!only_launchd.has_containers());
        assert!(scope().has_containers());
    }
}
