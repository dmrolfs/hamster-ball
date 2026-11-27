// ABOUTME: A process identity (pid, start time, uid) read from the kernel, and typed lists of a process's children and group.
// ABOUTME: A pid alone can be reused; the start time tells a recycled number from the process hb recorded (design hb-caj).
//! Who a process is, as the kernel states it right now.
//!
//! A process number can be handed to an unrelated program once the first has gone. An
//! [`Identity`] adds the start time and owner, so the guardian can tell whether a number still
//! names the process it recorded. Reading the identity and then signalling are two steps, so the
//! window between them is not closed: it is unlikely, not bounded in time.

use std::io;

use snafu::{ResultExt, Snafu};

/// Why a process could not be read.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum IdentityError {
    /// There is no such process (it exited, or it is a zombie the kernel no longer describes).
    #[snafu(display("process {pid} does not exist"))]
    Gone {
        /// The process number asked about.
        pid: i32,
    },

    /// The kernel refused or failed the query for another reason, such as a process of another user.
    #[snafu(display("the kernel could not describe process {pid}"))]
    Query {
        /// The process number asked about.
        pid: i32,
        /// The underlying error.
        source: io::Error,
    },
}

/// A process with the links the kernel reported in the same read.
///
/// The parent and group change over a process's life (a daemon is reparented, `setsid` leaves its
/// group), so they are not part of the [`Identity`]. Read together with it, they let a caller check
/// that a number found in a list still stands in the relation it was listed for: a recycled number
/// is a different process and almost never has the same parent or group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    /// Who the process is.
    pub identity: Identity,
    /// Its parent at the time of the read.
    pub ppid: i32,
    /// Its process group at the time of the read.
    pub pgid: i32,
}

impl Observed {
    /// Reads `pid` now.
    ///
    /// # Errors
    /// [`IdentityError::Gone`] when there is no such process; [`IdentityError::Query`] otherwise.
    pub fn of(pid: i32) -> Result<Self, IdentityError> {
        let info =
            darwin_libproc::task_all_info(pid).map_err(|source| match source.raw_os_error() {
                Some(code) if code == nix::libc::ESRCH => IdentityError::Gone { pid },
                _ => IdentityError::Query { pid, source },
            })?;
        Ok(Self {
            identity: Identity {
                pid,
                start_sec: info.pbsd.pbi_start_tvsec,
                start_usec: info.pbsd.pbi_start_tvusec,
                uid: info.pbsd.pbi_uid,
            },
            ppid: i32::try_from(info.pbsd.pbi_ppid).unwrap_or(i32::MAX),
            pgid: i32::try_from(info.pbsd.pbi_pgid).unwrap_or(i32::MAX),
        })
    }
}

/// A process as the kernel described it: number, start time and owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Identity {
    pid: i32,
    start_sec: u64,
    start_usec: u64,
    uid: u32,
}

impl Identity {
    /// Reads the identity of `pid` now.
    ///
    /// # Errors
    /// [`IdentityError::Gone`] when there is no such process; [`IdentityError::Query`] otherwise.
    pub fn of(pid: i32) -> Result<Self, IdentityError> {
        Observed::of(pid).map(|observed| observed.identity)
    }

    /// The process number.
    #[must_use]
    pub fn pid(&self) -> i32 {
        self.pid
    }

    /// The owning user.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// When the process started, as whole seconds and microseconds since the epoch.
    #[must_use]
    pub fn started(&self) -> (u64, u64) {
        (self.start_sec, self.start_usec)
    }

    /// This identity under a different process number, for tests that need an unreadable member.
    #[cfg(test)]
    pub(super) fn with_pid(&self, pid: i32) -> Self {
        Self { pid, ..*self }
    }

    /// This identity with a different start time, for tests that stand in for a reused number.
    #[cfg(test)]
    pub(super) fn with_start(&self, start_usec: u64) -> Self {
        Self {
            start_usec,
            ..*self
        }
    }

    /// Whether this process started no earlier than `other`. A child cannot predate its parent, so
    /// a listed process that fails this was not started by it.
    #[must_use]
    pub fn started_no_earlier_than(&self, other: &Self) -> bool {
        self.started() >= other.started()
    }

    /// Whether this number still names the process that was recorded. A process that is gone is
    /// `false`, not an error: nothing is left to signal.
    ///
    /// # Errors
    /// [`IdentityError::Query`] when the kernel could not answer.
    pub fn is_current(&self) -> Result<bool, IdentityError> {
        match Self::of(self.pid) {
            Ok(now) => Ok(now == *self),
            Err(IdentityError::Gone { .. }) => Ok(false),
            Err(other) => Err(other),
        }
    }
}

/// Why a list of processes could not be read.
#[derive(Debug, Snafu)]
#[snafu(display("the kernel could not list processes"))]
pub struct ListError {
    /// The underlying error.
    source: io::Error,
}

/// Runs a listing so that an empty answer is told apart from a failure.
///
/// The library reports an empty list as the thread's last `errno`, which may be left over from
/// earlier work. Clearing it first makes an empty answer read as code 0 and a failure keep its own
/// code. A process that has just exited answers ESRCH. Neither has anything to list.
fn listed(list: impl FnOnce() -> io::Result<Vec<i32>>) -> io::Result<Vec<i32>> {
    nix::errno::Errno::clear();
    match list() {
        Err(error) if matches!(error.raw_os_error(), Some(0 | nix::libc::ESRCH)) => Ok(Vec::new()),
        other => other,
    }
}

/// The direct children of `pid`.
///
/// # Errors
/// [`ListError`] when the kernel could not list them. A process with no children is an empty list.
pub fn children_of(pid: i32) -> Result<Vec<i32>, ListError> {
    listed(|| darwin_libproc::ppid_only_pids(pid)).context(ListSnafu)
}

/// The members of process group `pgid`.
///
/// # Errors
/// [`ListError`] when the kernel could not list them. A group with no members is an empty list.
pub fn group_members(pgid: i32) -> Result<Vec<i32>, ListError> {
    listed(|| darwin_libproc::pgrp_only_pids(pgid)).context(ListSnafu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    fn sleeper() -> Child {
        assert_ok!(Command::new("/bin/sleep").arg("30").spawn())
    }

    fn pid_of(child: &Child) -> i32 {
        i32::try_from(child.id()).unwrap_or(i32::MAX)
    }

    fn reap(mut child: Child) {
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn a_running_process_has_a_stable_identity_that_is_current() {
        let child = sleeper();
        let first = assert_ok!(Identity::of(pid_of(&child)));
        let second = assert_ok!(Identity::of(pid_of(&child)));
        assert_eq!(first, second);
        assert_eq!(first.pid(), pid_of(&child));
        assert!(assert_ok!(first.is_current()));
        reap(child);
    }

    #[test]
    fn an_observation_reports_the_parent_and_group_read_with_the_identity() {
        let leader = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
        );
        let pid = pid_of(&leader);
        let seen = assert_ok!(Observed::of(pid));
        assert_eq!(seen.identity, assert_ok!(Identity::of(pid)));
        assert_eq!(seen.pgid, pid, "a group leader's group is its own number");
        assert_eq!(
            seen.ppid,
            i32::try_from(std::process::id()).unwrap_or(i32::MAX)
        );
        reap(leader);
    }

    #[test]
    fn an_identity_belongs_to_the_current_user() {
        let me = assert_ok!(Identity::of(
            i32::try_from(std::process::id()).unwrap_or(i32::MAX)
        ));
        assert_eq!(me.uid(), nix::unistd::getuid().as_raw());
        assert!(me.started().0 > 0);
    }

    #[test]
    fn a_process_that_has_gone_is_not_current_and_is_reported_as_gone() {
        let child = sleeper();
        let pid = pid_of(&child);
        let recorded = assert_ok!(Identity::of(pid));
        reap(child);
        assert!(!assert_ok!(recorded.is_current()));
        assert!(matches!(
            assert_err!(Identity::of(pid)),
            IdentityError::Gone { pid: p } if p == pid
        ));
    }

    #[test]
    fn the_same_number_with_a_different_start_time_is_not_the_recorded_process() {
        let child = sleeper();
        let real = assert_ok!(Identity::of(pid_of(&child)));
        let stale = Identity {
            start_usec: real.start_usec ^ 1,
            ..real
        };
        assert!(!assert_ok!(stale.is_current()));
        let other_owner = Identity {
            uid: real.uid + 1,
            ..real
        };
        assert!(!assert_ok!(other_owner.is_current()));
        reap(child);
    }

    #[test]
    fn children_and_group_members_are_listed_and_an_empty_answer_is_an_empty_list() {
        let leader = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
        );
        let pgid = pid_of(&leader);
        let member = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(pgid)
                .spawn()
        );
        let members = assert_ok!(group_members(pgid));
        assert!(
            members.contains(&pgid) && members.contains(&pid_of(&member)),
            "{members:?}"
        );
        let mine = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        assert!(assert_ok!(children_of(mine)).contains(&pid_of(&member)));
        assert_eq!(assert_ok!(children_of(1_000_000)), Vec::<i32>::new());
        assert_eq!(assert_ok!(group_members(1_000_000)), Vec::<i32>::new());
        assert_eq!(assert_ok!(group_members(999_990)), Vec::<i32>::new());
        reap(member);
        reap(leader);
    }

    #[test]
    fn an_empty_listing_is_empty_even_when_errno_was_left_set_by_earlier_work() {
        // A failed call elsewhere in the process leaves errno set; the listing must not mistake it.
        let _ = std::fs::File::open("/dev/null/not-a-file");
        nix::errno::Errno::EBADF.set();
        assert_eq!(assert_ok!(children_of(1_000_000)), Vec::<i32>::new());
        nix::errno::Errno::EBADF.set();
        assert_eq!(assert_ok!(group_members(999_990)), Vec::<i32>::new());
    }

    #[test]
    fn the_group_outlives_its_leader_while_a_member_remains() {
        let leader = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
        );
        let pgid = pid_of(&leader);
        let member = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(pgid)
                .spawn()
        );
        reap(leader);
        assert_eq!(assert_ok!(group_members(pgid)), vec![pid_of(&member)]);
        reap(member);
        assert_eq!(assert_ok!(group_members(pgid)), Vec::<i32>::new());
    }

    #[test]
    fn identity_errors_follow_the_display_convention() {
        crate::error::conventions::assert_display_excludes_sources(&IdentityError::Query {
            pid: 5,
            source: io::Error::other("cause"),
        });
        crate::error::conventions::assert_display_excludes_sources(&ListError {
            source: io::Error::other("cause"),
        });
    }
}
