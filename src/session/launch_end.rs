// ABOUTME: Guardian-local launch tickets outlive a root process and keep teardown scoped to that launch.
// ABOUTME: End requests change state or read status; process work runs between command batches.
//! Per-launch cleanup records, separate from PID watch admission.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::identity::Identity;

pub(super) const CAPACITY: usize = 14;
pub(crate) const CLEANUP_BUDGET: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum EndPhase {
    Pinned,
    Reaped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, strum::Display, strum::EnumString)]
#[strum(serialize_all = "snake_case")]
pub(crate) enum EndStatus {
    Pending,
    ReapReady,
    Complete,
    Incomplete,
}

pub(super) struct Record {
    pub root: Identity,
    pub phase: EndPhase,
    pub deadline: Option<Instant>,
    pub ready: bool,
    pub failed: bool,
    pub cursor: Option<i32>,
    pub revision: isize,
    pub internal: bool,
}

#[derive(Default)]
pub(super) struct Launches {
    next: u64,
    pub records: HashMap<u64, Record>,
    pub failed: bool,
}

impl Launches {
    pub fn insert(&mut self, root: Identity) -> Option<u64> {
        if let Some((&ticket, _)) = self.records.iter().find(|(_, r)| r.root == root) {
            return Some(ticket);
        }
        if self.records.len() >= CAPACITY {
            return None;
        }
        self.next = self.next.checked_add(1)?;
        self.records.insert(
            self.next,
            Record {
                root,
                phase: EndPhase::Pinned,
                deadline: None,
                ready: false,
                failed: false,
                cursor: None,
                revision: 0,
                internal: false,
            },
        );
        Some(self.next)
    }

    pub fn request(&mut self, ticket: u64, phase: EndPhase, now: Instant) -> Option<EndStatus> {
        let record = self.records.get_mut(&ticket)?;
        if phase == EndPhase::Reaped && !record.ready {
            return None;
        }
        if phase == EndPhase::Pinned && record.phase == EndPhase::Reaped {
            return None;
        }
        if record.phase != phase {
            record.cursor = None;
        }
        record.phase = phase;
        record.deadline.get_or_insert(now + CLEANUP_BUDGET);
        if now >= record.deadline? {
            record.failed = true;
            self.failed = true;
            return Some(EndStatus::Incomplete);
        }
        Some(if record.ready && phase == EndPhase::Pinned {
            EndStatus::ReapReady
        } else {
            EndStatus::Pending
        })
    }

    pub fn active(&self) -> bool {
        self.records.values().any(|r| r.deadline.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;

    fn identity() -> Identity {
        assert_ok!(Identity::of(std::process::id() as i32))
    }

    #[test]
    fn duplicate_launch_keeps_ticket_and_reaped_requires_handover() {
        let mut launches = Launches::default();
        let root = identity();
        let ticket = assert_some!(launches.insert(root));
        assert_eq!(launches.insert(root), Some(ticket));
        assert_none!(launches.request(ticket, EndPhase::Reaped, Instant::now()));
        assert_none!(launches.request(ticket + 1, EndPhase::Pinned, Instant::now()));
        assert_eq!(
            launches.request(ticket, EndPhase::Pinned, Instant::now()),
            Some(EndStatus::Pending)
        );
        assert_some!(launches.records.get_mut(&ticket)).ready = true;
        assert_eq!(
            launches.request(ticket, EndPhase::Pinned, Instant::now()),
            Some(EndStatus::ReapReady)
        );
        assert_eq!(
            launches.request(ticket, EndPhase::Reaped, Instant::now()),
            Some(EndStatus::Pending)
        );
        assert_none!(launches.request(ticket, EndPhase::Pinned, Instant::now()));
    }

    #[test]
    fn polling_cannot_extend_deadline_or_erase_failure() {
        let mut launches = Launches::default();
        let ticket = assert_some!(launches.insert(identity()));
        let start = Instant::now();
        assert_eq!(
            launches.request(ticket, EndPhase::Pinned, start),
            Some(EndStatus::Pending)
        );
        assert_eq!(
            launches.request(ticket, EndPhase::Pinned, start + CLEANUP_BUDGET),
            Some(EndStatus::Incomplete)
        );
        assert!(launches.failed);
        assert!(launches.records[&ticket].failed);
        assert_eq!(
            launches.records[&ticket].deadline,
            Some(start + CLEANUP_BUDGET)
        );
    }

    #[test]
    fn retired_ticket_is_never_reissued_and_overflow_refuses_admission() {
        let mut launches = Launches::default();
        let first = assert_some!(launches.insert(identity()));
        launches.records.remove(&first);
        let next = assert_some!(launches.insert(identity()));
        assert!(next > first);
        assert_none!(launches.request(first, EndPhase::Pinned, Instant::now()));
        launches.records.clear();
        launches.next = u64::MAX;
        assert_none!(launches.insert(identity()));
    }
}
