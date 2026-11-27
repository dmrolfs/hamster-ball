// ABOUTME: Identity-qualified descendant watches that survive a root's exit and a descendant's setsid.
// ABOUTME: Fork events trigger discovery, not automatic kernel tracking; fast reparenting can escape this registry (hb-caj).
//! The guardian's process registry. macOS does not support NOTE_TRACK, so children must be
//! discovered while their parent still exists. This is cleanup, not full-tree containment.

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::event::{EvFlags, EventFilter, FilterFlag, KEvent, Kqueue};
use nix::sys::signal::{Signal, kill};
use nix::sys::time::TimeSpec;
use nix::unistd::Pid;
use snafu::{ResultExt, Snafu};

use super::identity::{Identity, IdentityError, ListError, Observed, children_of, group_members};

const MAX_IDENTITIES: usize = 1024;

/// A failure is visible to the guardian; it must not silently evict an owned identity.
#[derive(Debug, Snafu)]
pub(super) enum TrackerError {
    #[snafu(display("the descendant registry is full"))]
    Capacity,
    #[snafu(display("a process identity could not be checked"))]
    Identity { source: IdentityError },
    #[snafu(display("descendants could not be listed"))]
    List { source: ListError },
    #[snafu(display("the kernel could not watch a descendant"))]
    Watch { source: Errno },
    #[snafu(display("the kernel could not signal process {pid}"))]
    Signal { pid: i32, source: Errno },
    #[snafu(display("the process changed while its watch was being armed"))]
    Changed,
    #[snafu(display("the discovery deadline has elapsed"))]
    Deadline,
}

/// The relation a process was listed under, which it must still be in when it is read: a number that
/// was listed and then recycled is a different process, and almost never in the same place.
#[derive(Debug, Clone, Copy)]
enum Listed {
    /// Listed as a child of this process number.
    ChildOf(i32),
    /// Listed as a member of this process group.
    InGroup(i32),
}

impl Listed {
    fn still_holds(self, seen: &Observed) -> bool {
        match self {
            Self::ChildOf(parent) => seen.ppid == parent,
            Self::InGroup(group) => seen.pgid == group,
        }
    }
}

/// The children of `parent`, or none if the number no longer names the recorded process. A number
/// reused between the adoption and the listing would otherwise list a stranger's children, and every
/// later check (parent number, user, age) can pass for them.
fn children_while_current(parent: Identity) -> Result<Vec<i32>, TrackerError> {
    let children = children_of(parent.pid()).context(ListSnafu)?;
    if parent.is_current().context(IdentitySnafu)? {
        Ok(children)
    } else {
        Ok(Vec::new())
    }
}

/// Whether a listed process may be adopted under `root`: it still stands in the relation it was
/// listed for, it is the root's user, and it started no earlier than the root.
fn may_adopt(listed: Listed, seen: &Observed, root: &Identity) -> bool {
    listed.still_holds(seen)
        && seen.identity.uid() == root.uid()
        && seen.identity.started_no_earlier_than(root)
}

#[derive(Debug, Clone, Copy)]
struct Member {
    identity: Identity,
    cookie: isize,
    root: Identity,
    /// Set on a root that leads its own group; new members require its live or zombie identity.
    scan_group: bool,
}

/// Each registration has a new cookie; an event from a retired registration cannot remove its
/// replacement. Root admission (16 slots) belongs to the guardian, not this descendant cap.
#[derive(Default)]
pub(super) struct Tracker {
    members: HashMap<i32, Member>,
    next_cookie: isize,
    /// The earliest root ever armed. It is kept after the root exits, because a sweep matters most
    /// once the roots are gone, and a candidate older than every root cannot be this run's.
    earliest_root: Option<Identity>,
    discovery_deadline: Option<Instant>,
}

impl Tracker {
    pub(super) fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    pub(super) fn discovery_until(&mut self, by: Option<Instant>) {
        self.discovery_deadline = by;
    }

    fn check_discovery_deadline(&self) -> Result<(), TrackerError> {
        if self
            .discovery_deadline
            .is_some_and(|by| Instant::now() >= by)
        {
            DeadlineSnafu.fail()
        } else {
            Ok(())
        }
    }

    /// Whether admission still refers to a watched identity, not just the same process number.
    pub(super) fn contains(&self, identity: Identity) -> bool {
        self.members
            .get(&identity.pid())
            .is_some_and(|member| member.identity == identity)
    }

    /// Called while the root is still at its launch gate. The caller may acknowledge Armed only
    /// after this succeeds. Shared terminal groups must pass `group = false`.
    pub(super) fn arm(
        &mut self,
        queue: &Kqueue,
        pid: i32,
        group: bool,
    ) -> Result<Identity, TrackerError> {
        let root = Identity::of(pid).context(IdentitySnafu)?;
        self.adopt(queue, root, root)?;
        if self
            .earliest_root
            .is_none_or(|earliest| root.started() < earliest.started())
        {
            self.earliest_root = Some(root);
        }
        if let Some(member) = self.members.get_mut(&root.pid()) {
            member.scan_group = group;
        }
        self.discover(queue, root, root, group)?;
        Ok(root)
    }

    fn adopt(
        &mut self,
        queue: &Kqueue,
        identity: Identity,
        root: Identity,
    ) -> Result<bool, TrackerError> {
        self.check_discovery_deadline()?;
        if self
            .members
            .get(&identity.pid())
            .is_some_and(|m| m.identity == identity)
        {
            return Ok(false);
        }
        if self.members.len() >= MAX_IDENTITIES {
            return CapacitySnafu.fail();
        }
        self.next_cookie = self
            .next_cookie
            .checked_add(1)
            .ok_or(TrackerError::Capacity)?;
        let cookie = self.next_cookie;
        let event = KEvent::new(
            identity.pid() as usize,
            EventFilter::EVFILT_PROC,
            EvFlags::EV_ADD | EvFlags::EV_CLEAR,
            FilterFlag::NOTE_FORK | FilterFlag::NOTE_EXIT,
            0,
            cookie,
        );
        queue
            .kevent(&[event], &mut [], Some(zero()))
            .context(WatchSnafu)?;
        if !identity.is_current().context(IdentitySnafu)? {
            let delete = KEvent::new(
                identity.pid() as usize,
                EventFilter::EVFILT_PROC,
                EvFlags::EV_DELETE,
                FilterFlag::empty(),
                0,
                cookie,
            );
            let _ = queue.kevent(&[delete], &mut [], Some(zero()));
            return ChangedSnafu.fail();
        }
        self.members.insert(
            identity.pid(),
            Member {
                identity,
                cookie,
                root,
                scan_group: false,
            },
        );
        Ok(true)
    }

    fn discover(
        &mut self,
        queue: &Kqueue,
        parent: Identity,
        root: Identity,
        group: bool,
    ) -> Result<(), TrackerError> {
        self.check_discovery_deadline()?;
        // An old parent's number is not authority to enumerate a new parent's children.
        if !parent.is_current().context(IdentitySnafu)? {
            return Ok(());
        }
        let mut candidates: VecDeque<(i32, Listed, Identity)> = children_of(parent.pid())
            .context(ListSnafu)?
            .into_iter()
            .map(|pid| (pid, Listed::ChildOf(parent.pid()), parent))
            .collect();
        if group {
            candidates.extend(
                group_members(parent.pid())
                    .context(ListSnafu)?
                    .into_iter()
                    .map(|pid| (pid, Listed::InGroup(parent.pid()), parent)),
            );
        }
        if !parent.is_current().context(IdentitySnafu)? {
            return Ok(());
        }
        while let Some((pid, listed, witness)) = candidates.pop_front() {
            self.check_discovery_deadline()?;
            if pid <= 1 || self.members.contains_key(&pid) {
                continue;
            }
            let seen = match Observed::of(pid) {
                Ok(seen) => seen,
                Err(IdentityError::Gone { .. }) => continue,
                Err(source) => return Err(TrackerError::Identity { source }),
            };
            if !may_adopt(listed, &seen, &root) || !witness.is_current().context(IdentitySnafu)? {
                continue;
            }
            match self.adopt(queue, seen.identity, root) {
                Ok(true) => candidates.extend(
                    children_while_current(seen.identity)?
                        .into_iter()
                        .map(|child| (child, Listed::ChildOf(pid), seen.identity)),
                ),
                Ok(false)
                | Err(TrackerError::Changed)
                | Err(TrackerError::Watch {
                    source: Errno::ESRCH,
                }) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    /// Adopts group members only while the original leader still pins the group number.
    /// A zombie leader also pins it until reaped. Once the leader is gone, previously tracked
    /// members remain owned, but the bare group number is no longer ownership evidence.
    fn scan_group(
        &mut self,
        queue: &Kqueue,
        leader: Identity,
        root: Identity,
    ) -> Result<(), TrackerError> {
        self.check_discovery_deadline()?;
        if !leader.is_current().context(IdentitySnafu)? {
            return Ok(());
        }
        for pid in group_members(leader.pid()).context(ListSnafu)? {
            self.check_discovery_deadline()?;
            if pid <= 1 || self.members.contains_key(&pid) {
                continue;
            }
            let seen = match Observed::of(pid) {
                Ok(seen) => seen,
                Err(IdentityError::Gone { .. }) => continue,
                Err(source) => return Err(TrackerError::Identity { source }),
            };
            let member = seen.identity;
            if !may_adopt(Listed::InGroup(leader.pid()), &seen, &root)
                || !leader.is_current().context(IdentitySnafu)?
            {
                continue;
            }
            match self.adopt(queue, member, root) {
                Ok(true) => self.discover(queue, member, root, false)?,
                Ok(false)
                | Err(TrackerError::Changed)
                | Err(TrackerError::Watch {
                    source: Errno::ESRCH,
                }) => {}
                Err(other) => return Err(other),
            }
        }
        Ok(())
    }

    /// Adopts a process a sweep found, so it is signalled with the rest and only after its identity
    /// is checked again. The sweep only suggests: the process must be the guard's own user, must have
    /// started no earlier than the earliest root (an older process cannot hold this run's token), and
    /// must not be the guard itself.
    ///
    /// The caller captures `candidate` before confirming ownership evidence. Retain that identity
    /// through registration: a later occupant of the number must never inherit the evidence.
    ///
    /// Returns whether the process was adopted. A process that is gone, foreign or too old is not an
    /// error.
    pub(super) fn adopt_candidate(
        &mut self,
        queue: &Kqueue,
        candidate: Identity,
        own_pid: i32,
    ) -> Result<bool, TrackerError> {
        self.check_discovery_deadline()?;
        let pid = candidate.pid();
        if pid <= 1 || pid == own_pid || self.contains(candidate) {
            return Ok(false);
        }
        let Some(earliest) = self.earliest_root else {
            return Ok(false);
        };
        if candidate.uid() != earliest.uid()
            || !candidate.started_no_earlier_than(&earliest)
            || !candidate.is_current().context(IdentitySnafu)?
        {
            return Ok(false);
        }
        match self.adopt(queue, candidate, earliest) {
            Ok(adopted) => Ok(adopted),
            Err(TrackerError::Changed)
            | Err(TrackerError::Watch {
                source: Errno::ESRCH,
            }) => Ok(false),
            Err(other) => Err(other),
        }
    }

    /// Handles combined FORK+EXIT before retiring the parent. Detached members remain owned.
    ///
    /// Returns whether a current registration exited, so the caller frees its root slot only for a
    /// real exit and never for a stale event from a number that has since been reused.
    pub(super) fn event(&mut self, queue: &Kqueue, event: &KEvent) -> Result<bool, TrackerError> {
        let pid = i32::try_from(event.ident()).unwrap_or(0);
        let Some(member) = self.members.get(&pid).copied() else {
            return Ok(false);
        };
        if member.cookie != event.udata() {
            return Ok(false);
        }
        let mut discovery = Ok(());
        if event.fflags().contains(FilterFlag::NOTE_FORK) {
            discovery = self.discover(queue, member.identity, member.root, false);
        }
        if member.scan_group && discovery.is_ok() {
            // Group discovery requires the leader to remain identifiable; known members survive it.
            discovery = self.scan_group(queue, member.identity, member.root);
        }
        // The exit is retired whatever discovery did: a failed discovery (a full registry, a kernel
        // refusal) must not leave a dead root holding its slot, where a reused number would then be
        // taken for it.
        let exited = event.fflags().contains(FilterFlag::NOTE_EXIT);
        if exited {
            self.members.remove(&pid);
            // shortcut: the discovery error is dropped when the process also exited, because the caller
            // must learn of the exit; the sweep and the documented residual cover what was missed.
            return Ok(true);
        }
        discovery.map(|()| false)
    }

    /// Never signals a group number. An identity is checked again immediately before each kill.
    /// The check and kill are not atomic; the owner-approved residual race remains.
    ///
    /// Every member is attempted, whatever happens to the others: one process that cannot be read
    /// or signalled must not leave the rest running. Members that are gone are forgotten. The first
    /// failure is returned after the pass, so the caller can say cleanup was incomplete.
    pub(super) fn signal(&mut self, signal: Signal) -> Result<(), TrackerError> {
        self.signal_while(signal, || true)
    }

    /// Yield an ongoing TERM pass to KILL when the grace expires; KILL itself is never cut short.
    pub(super) fn term_until(&mut self, by: Instant) -> Result<(), TrackerError> {
        self.signal_while(Signal::SIGTERM, || Instant::now() < by)
    }

    fn signal_while(
        &mut self,
        signal: Signal,
        mut keep_going: impl FnMut() -> bool,
    ) -> Result<(), TrackerError> {
        let mut gone = Vec::new();
        let mut first_failure = None;
        for (pid, member) in &self.members {
            if !keep_going() {
                break;
            }
            match member.identity.is_current() {
                Ok(true) => {}
                Ok(false) => {
                    gone.push(*pid);
                    continue;
                }
                Err(source) => {
                    first_failure.get_or_insert(TrackerError::Identity { source });
                    continue;
                }
            }
            match kill(Pid::from_raw(*pid), signal) {
                Ok(()) => {}
                Err(Errno::ESRCH) => gone.push(*pid),
                Err(source) => {
                    first_failure.get_or_insert(TrackerError::Signal { pid: *pid, source });
                }
            }
        }
        for pid in gone {
            self.members.remove(&pid);
        }
        first_failure.map_or(Ok(()), Err)
    }
}

fn zero() -> nix::libc::timespec {
    *TimeSpec::from_duration(Duration::ZERO).as_ref()
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::process::Command;

    #[test]
    fn expired_term_signals_nobody_and_does_not_disable_kill() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut child = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        assert_ok!(tracker.arm(&queue, i32::try_from(child.id()).unwrap_or(i32::MAX), false));
        assert_ok!(tracker.term_until(Instant::now()));
        std::thread::sleep(Duration::from_millis(50));
        let before_kill = assert_ok!(child.try_wait());
        assert_ok!(tracker.signal(Signal::SIGKILL));
        let _ = child.wait();
        assert_eq!(before_kill, None);
    }

    #[test]
    fn a_term_pass_yields_between_members_but_kill_still_reaches_every_member() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut children: Vec<_> = (0..3)
            .map(|_| assert_ok!(Command::new("/bin/sleep").arg("30").spawn()))
            .collect();
        for child in &children {
            assert_ok!(tracker.arm(&queue, i32::try_from(child.id()).unwrap_or(i32::MAX), false));
        }
        let mut checks = 0;
        assert_ok!(tracker.signal_while(Signal::SIGTERM, || {
            checks += 1;
            checks == 1
        }));
        assert_eq!(checks, 2);
        assert_ok!(tracker.signal(Signal::SIGKILL));
        for child in &mut children {
            assert!(!assert_ok!(child.wait()).success());
        }
    }

    #[test]
    fn a_stale_exit_event_cannot_remove_a_new_registration() {
        let queue = assert_ok!(Kqueue::new());
        let mut child = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let mut tracker = Tracker::default();
        let pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
        assert_ok!(tracker.arm(&queue, pid, false));
        let cookie = tracker.members[&pid].cookie;
        let stale = KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            EvFlags::empty(),
            FilterFlag::NOTE_EXIT,
            0,
            cookie + 1,
        );
        assert!(!assert_ok!(tracker.event(&queue, &stale)));
        assert_eq!(tracker.members.len(), 1);
        let current = KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            EvFlags::empty(),
            FilterFlag::NOTE_EXIT,
            0,
            cookie,
        );
        assert!(assert_ok!(tracker.event(&queue, &current)));
        assert!(tracker.is_empty());
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn expired_discovery_does_not_admit_work_or_prevent_signalling() {
        let queue = assert_ok!(Kqueue::new());
        let mut child = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let pid = i32::try_from(child.id()).unwrap_or(i32::MAX);
        let mut tracker = Tracker::default();
        let root = assert_ok!(tracker.arm(&queue, pid, false));
        tracker.discovery_until(Some(Instant::now()));
        assert!(matches!(
            tracker.discover(&queue, root, root, false),
            Err(TrackerError::Deadline)
        ));
        assert!(matches!(
            tracker.scan_group(&queue, root, root),
            Err(TrackerError::Deadline)
        ));
        assert_ok!(tracker.signal(Signal::SIGKILL));
        assert!(!assert_ok!(child.wait()).success());
    }

    /// A recorded process is replaced by a different one under the same number, which is what a reused
    /// pid looks like. The record is edited to a start time the live process does not have, so the
    /// number now names "someone else": the signal must be dropped, not delivered.
    #[test]
    fn a_number_that_now_names_a_different_process_is_not_signalled() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut stranger = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let pid = i32::try_from(stranger.id()).unwrap_or(i32::MAX);
        assert_ok!(tracker.arm(&queue, pid, false));
        let recorded = tracker.members[&pid].identity;
        let wrong = recorded.with_start(recorded.started().1 ^ 1);
        if let Some(member) = tracker.members.get_mut(&pid) {
            member.identity = wrong;
        }
        assert_ok!(tracker.signal(Signal::SIGKILL));
        assert_eq!(
            assert_ok!(stranger.try_wait()),
            None,
            "a different process was signalled"
        );
        assert!(tracker.is_empty(), "the stale record was kept");
        let _ = stranger.kill();
        let _ = stranger.wait();
    }

    /// A member that cannot be signalled (another user's process, here `launchd`, which is pid 1 and
    /// belongs to root) must not stop the members after it from being signalled.
    #[test]
    fn a_member_that_cannot_be_signalled_does_not_stop_the_others() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut victims: Vec<_> = (0..6)
            .map(|_| assert_ok!(Command::new("/bin/sleep").arg("30").spawn()))
            .collect();
        for victim in &victims {
            let pid = i32::try_from(victim.id()).unwrap_or(i32::MAX);
            assert_ok!(tracker.arm(&queue, pid, false));
        }
        // launchd (pid 1, root's): this user cannot read its identity, so the check fails. A record
        // is built by hand, since a real member could never have been adopted.
        let own = assert_ok!(Identity::of(
            i32::try_from(std::process::id()).unwrap_or(i32::MAX)
        ));
        let unreadable = own.with_pid(1);
        tracker.members.insert(
            1,
            Member {
                identity: unreadable,
                cookie: -1,
                root: unreadable,
                scan_group: false,
            },
        );
        let result = tracker.signal(Signal::SIGKILL);
        assert!(
            matches!(result, Err(TrackerError::Identity { .. })),
            "{result:?}"
        );
        for victim in &mut victims {
            assert!(
                assert_ok!(victim.wait()).code().is_none(),
                "a member after the failing one was not signalled"
            );
        }
        // Killed members are forgotten by their exit events, not by the pass that signalled them; the
        // unreadable one is kept so the caller can still report that cleanup was incomplete.
        assert!(
            tracker.members.contains_key(&1),
            "the unreadable member was dropped"
        );
    }

    /// The recycled-number case, with forged evidence a real listing never produces: a process listed
    /// under one group or parent that now reads as being somewhere else is refused, even though it is
    /// the same user and newer than the root, which is all the age rule checks.
    #[test]
    fn a_listed_process_that_moved_is_refused_even_when_user_and_age_pass() {
        // The root starts first, so the bystander is newer than it: the age rule alone would pass.
        let mut older_root = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        std::thread::sleep(Duration::from_millis(30));
        let mut bystander = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let root = assert_ok!(Identity::of(
            i32::try_from(older_root.id()).unwrap_or(i32::MAX)
        ));
        let seen = assert_ok!(Observed::of(
            i32::try_from(bystander.id()).unwrap_or(i32::MAX)
        ));
        // Control: listed where it really is, same user, newer than the root.
        let me = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        assert!(may_adopt(Listed::ChildOf(me), &seen, &root));
        assert!(may_adopt(Listed::InGroup(seen.pgid), &seen, &root));
        // The process is not under that parent or in that group any more.
        assert!(!may_adopt(Listed::ChildOf(me + 1), &seen, &root));
        assert!(!may_adopt(Listed::InGroup(seen.pgid + 1), &seen, &root));
        let _ = bystander.kill();
        let _ = bystander.wait();
        let _ = older_root.kill();
        let _ = older_root.wait();
    }

    /// A listed child must still have the listing parent. The same number under another parent is the
    /// recycled-number case.
    #[test]
    fn a_listed_child_that_no_longer_has_that_parent_is_not_adopted() {
        let mut child = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let seen = assert_ok!(Observed::of(i32::try_from(child.id()).unwrap_or(i32::MAX)));
        let me = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
        assert!(Listed::ChildOf(me).still_holds(&seen));
        assert!(!Listed::ChildOf(me + 1).still_holds(&seen));
        assert!(Listed::InGroup(seen.pgid).still_holds(&seen));
        assert!(!Listed::InGroup(seen.pgid + 1).still_holds(&seen));
        let _ = child.kill();
        let _ = child.wait();
    }

    /// The recorded parent's number now names a different process that has a child: nothing is listed.
    #[test]
    fn a_child_listed_after_its_parent_was_replaced_is_not_adopted() {
        let mut parent = assert_ok!(
            Command::new("/bin/sh")
                .args(["-c", "sleep 30 & wait"])
                .spawn()
        );
        let pid = i32::try_from(parent.id()).unwrap_or(i32::MAX);
        let mut seen = Vec::new();
        for _ in 0..100 {
            seen = assert_ok!(children_of(pid));
            if !seen.is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!seen.is_empty(), "the parent never had a child");
        let recorded = assert_ok!(Identity::of(pid));
        assert_eq!(assert_ok!(children_while_current(recorded)), seen);
        assert!(assert_ok!(children_while_current(recorded.with_start(1))).is_empty());
        for child in seen {
            let _ = kill(Pid::from_raw(child), Signal::SIGKILL);
        }
        let _ = parent.kill();
        let _ = parent.wait();
    }

    fn identity_of(child: &std::process::Child) -> Identity {
        assert_ok!(Identity::of(i32::try_from(child.id()).unwrap_or(i32::MAX)))
    }

    /// Evidence belongs to the observed identity, not the next occupant of its number.
    /// A genuinely new candidate remains admissible when its own identity was confirmed.
    #[test]
    fn a_sweep_identity_cannot_be_replaced_before_adoption() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut root = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let root_pid = i32::try_from(root.id()).unwrap_or(i32::MAX);
        assert_ok!(tracker.arm(&queue, root_pid, false));
        let root_identity = assert_ok!(Identity::of(root_pid));
        std::thread::sleep(Duration::from_millis(30));
        let mut later = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let later_pid = i32::try_from(later.id()).unwrap_or(i32::MAX);
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            root_identity.with_pid(later_pid),
            0
        )));
        assert!(assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&later),
            0
        )));
        let _ = root.kill();
        let _ = root.wait();
        let _ = later.kill();
        let _ = later.wait();
    }

    #[test]
    fn a_candidate_is_adopted_only_when_it_is_the_users_and_not_older_than_the_roots() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut older = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        std::thread::sleep(Duration::from_millis(30));
        let mut root = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let mut newer = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let pid = |c: &std::process::Child| i32::try_from(c.id()).unwrap_or(i32::MAX);
        // With no roots there is nothing to compare against.
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&newer),
            0
        )));
        assert_ok!(tracker.arm(&queue, pid(&root), false));
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&older),
            0
        )));
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&root).with_pid(1),
            0
        )));
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&newer),
            pid(&newer)
        )));
        assert!(assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&newer),
            0
        )));
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&newer),
            0
        )));
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&root).with_pid(999_990),
            0
        )));
        // The root's exit does not forget it: a sweep after the roots are gone still has a reference.
        let _ = root.kill();
        let _ = root.wait();
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            identity_of(&older),
            0
        )));
        for child in [&mut older, &mut root, &mut newer] {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    #[test]
    fn verified_signalling_removes_a_gone_process_without_hitting_an_unrelated_one() {
        let queue = assert_ok!(Kqueue::new());
        let mut child = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let mut unrelated = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let mut tracker = Tracker::default();
        assert_ok!(tracker.arm(&queue, i32::try_from(child.id()).unwrap_or(i32::MAX), false));
        let _ = child.kill();
        let _ = child.wait();
        assert_ok!(tracker.signal(Signal::SIGKILL));
        assert!(tracker.is_empty());
        assert_eq!(assert_ok!(unrelated.try_wait()), None);
        let _ = unrelated.kill();
        let _ = unrelated.wait();
    }
}

#[cfg(test)]
mod descendants {
    use super::*;
    use claims::{assert_ok, assert_some};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::time::{Duration, Instant};

    /// A shell held at a gate until the test has armed the tracker on it, as hb's launch gate does.
    struct Gated {
        leader: Child,
        go: ChildStdin,
        out: BufReader<ChildStdout>,
    }

    impl Gated {
        fn start(script: &str) -> Self {
            let mut leader = assert_ok!(
                Command::new("/bin/sh")
                    .arg("-c")
                    .arg(format!("read go; {script}"))
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .process_group(0)
                    .spawn()
            );
            let go = assert_some!(leader.stdin.take());
            let out = BufReader::new(assert_some!(leader.stdout.take()));
            Self { leader, go, out }
        }

        fn pid(&self) -> i32 {
            i32::try_from(self.leader.id()).unwrap_or(i32::MAX)
        }

        /// Opens the gate and returns the pid the script printed.
        fn release(&mut self) -> i32 {
            assert_ok!(self.go.write_all(b"go\n"));
            let mut line = String::new();
            assert_ok!(self.out.read_line(&mut line));
            assert_ok!(line.trim().parse())
        }
    }

    fn drain(tracker: &mut Tracker, queue: &Kqueue, wait: Duration) {
        let end = Instant::now() + wait;
        let blank = KEvent::new(
            0,
            EventFilter::EVFILT_PROC,
            EvFlags::empty(),
            FilterFlag::empty(),
            0,
            0,
        );
        let mut events = [blank; 8];
        while Instant::now() < end {
            let t = TimeSpec::from_duration(Duration::from_millis(20));
            let n = queue
                .kevent(&[], &mut events, Some(*t.as_ref()))
                .unwrap_or(0);
            for e in &events[..n] {
                assert_ok!(tracker.event(queue, e));
            }
        }
    }

    fn alive(pid: i32) -> bool {
        !matches!(kill(Pid::from_raw(pid), None), Err(Errno::ESRCH))
    }

    fn assert_dies(pid: i32) {
        let end = Instant::now() + Duration::from_secs(2);
        while alive(pid) && Instant::now() < end {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(!alive(pid), "process {pid} survived");
    }

    /// An exit and a fork arrive together while the registry is full, so discovery fails. The exit must
    /// still be retired, or the dead root keeps its slot and a reused number is taken for it.
    #[test]
    fn an_exit_is_retired_even_when_discovery_fails() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated = Gated::start("sleep 30 & wait");
        let root_pid = gated.pid();
        assert_ok!(tracker.arm(&queue, root_pid, false));
        let root = tracker.members[&root_pid].identity;
        let cookie = tracker.members[&root_pid].cookie;
        let _ = gated.go.write_all(b"go\n");
        std::thread::sleep(Duration::from_millis(400));
        let children = assert_ok!(children_of(root_pid));
        // Fill every other slot, so adopting the root's child is refused for capacity.
        let mut fake = 900_000;
        while tracker.members.len() < MAX_IDENTITIES {
            fake += 1;
            tracker.members.insert(
                fake,
                Member {
                    identity: root.with_pid(fake),
                    cookie: 0,
                    root,
                    scan_group: false,
                },
            );
        }
        let both = KEvent::new(
            root_pid as usize,
            EventFilter::EVFILT_PROC,
            EvFlags::empty(),
            FilterFlag::NOTE_FORK | FilterFlag::NOTE_EXIT,
            0,
            cookie,
        );
        assert!(assert_ok!(tracker.event(&queue, &both)));
        assert!(!tracker.members.contains_key(&root_pid));
        for child in children {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        let _ = gated.leader.wait();
    }

    #[test]
    fn a_member_still_dies_after_its_group_leader_has_exited() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated =
            Gated::start("sleep 30 </dev/null >/dev/null 2>&1 & echo $!; read exit_now; exit 0");
        assert_ok!(tracker.arm(&queue, gated.pid(), true));
        let child = gated.release();
        drain(&mut tracker, &queue, Duration::from_millis(300));
        assert!(
            tracker.members.contains_key(&child),
            "{:?}",
            tracker.members.keys()
        );
        let _ = gated.go.write_all(b"exit\n");
        let _ = gated.leader.wait();
        drain(&mut tracker, &queue, Duration::from_millis(50));
        assert_ok!(tracker.signal(Signal::SIGKILL));
        assert_dies(child);
    }

    /// The leader lingers (`sleep 1`) so the fork event is handled while it still exists. A leader that
    /// forks and exits at once can win the race against discovery; that is a measured rate, not a gate.
    #[test]
    fn a_descendant_that_left_its_session_is_still_owned_and_killed() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated = Gated::start(
            "/usr/bin/perl -e 'use POSIX; if (fork == 0) { setsid; print \"$$\\n\"; close STDOUT; sleep 30; exit } sleep 1; exit 0'",
        );
        assert_ok!(tracker.arm(&queue, gated.pid(), true));
        let child = gated.release();
        drain(&mut tracker, &queue, Duration::from_millis(300));
        assert!(
            tracker.members.contains_key(&child),
            "{:?}",
            tracker.members.keys()
        );
        assert_ok!(tracker.signal(Signal::SIGKILL));
        let _ = gated.leader.wait();
        assert_dies(child);
    }

    /// The member is started by the test, so it is in the root's group but is nobody's descendant
    /// of the root: parentage cannot find it, only the group scan can.
    #[test]
    fn an_owned_group_member_is_retained_when_the_root_exits() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated = Gated::start("exit 0");
        assert_ok!(tracker.arm(&queue, gated.pid(), true));
        let mut member = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(gated.pid())
                .spawn()
        );
        let member_pid = i32::try_from(member.id()).unwrap_or(i32::MAX);
        let root = tracker.members[&gated.pid()].identity;
        assert_ok!(tracker.scan_group(&queue, root, root));
        let _ = gated.go.write_all(b"go\n");
        drain(&mut tracker, &queue, Duration::from_millis(300));
        assert!(
            tracker.members.contains_key(&member_pid),
            "{:?}",
            tracker.members.keys()
        );
        let _ = gated.leader.wait();
        let _ = member.kill();
        let _ = member.wait();
    }

    #[test]
    fn a_gone_leader_is_not_authority_to_adopt_an_unknown_group_member() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated = Gated::start("exit 0");
        let root = assert_ok!(tracker.arm(&queue, gated.pid(), true));
        let mut stranger = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(gated.pid())
                .spawn()
        );
        let stranger_pid = i32::try_from(stranger.id()).unwrap_or(i32::MAX);
        let _ = gated.go.write_all(b"go\n");
        let _ = gated.leader.wait();
        assert_ok!(tracker.scan_group(&queue, root, root));
        let adopted = tracker.members.contains_key(&stranger_pid);
        let _ = stranger.kill();
        let _ = stranger.wait();
        assert!(
            !adopted,
            "a leaderless numeric group was treated as ownership"
        );
    }

    /// The reviewer's counterexample for the group scan. The root's group number is "reused": the root
    /// is gone, and an unrelated process now leads a group with another number entirely. Scanning the
    /// recorded root must find nothing of that process, because it is not in the root's group.
    #[test]
    fn a_process_that_is_not_in_the_roots_group_is_never_adopted_by_the_group_scan() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated = Gated::start("exit 0");
        assert_ok!(tracker.arm(&queue, gated.pid(), true));
        let root = tracker.members[&gated.pid()].identity;
        // Newer than the root, same user, a group leader of its own: every check the age rule makes
        // passes, and only the group membership says it is someone else.
        let mut other = assert_ok!(
            Command::new("/bin/sleep")
                .arg("30")
                .process_group(0)
                .spawn()
        );
        let other_pid = i32::try_from(other.id()).unwrap_or(i32::MAX);
        let seen = assert_ok!(Observed::of(other_pid));
        assert!(!Listed::InGroup(root.pid()).still_holds(&seen));
        assert_ok!(tracker.scan_group(&queue, root, root));
        assert!(
            !tracker.members.contains_key(&other_pid),
            "a process outside the group was adopted"
        );
        let _ = gated.go.write_all(b"go\n");
        let _ = gated.leader.wait();
        let _ = other.kill();
        let _ = other.wait();
    }

    /// The reissued-number case from the review: the recorded root's number now belongs to another
    /// process that leads a group with a member of its own. Every other check passes for that member
    /// (same group number, same user, newer than the root), so only the leader check refuses it.
    #[test]
    fn a_group_listed_under_a_reissued_leader_number_is_not_scanned() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated = Gated::start("exit 0");
        assert_ok!(tracker.arm(&queue, gated.pid(), true));
        let root = tracker.members[&gated.pid()].identity;
        let mut stranger = assert_ok!(
            Command::new("/bin/sh")
                .args(["-c", "sleep 30 & wait"])
                .process_group(0)
                .spawn()
        );
        let stranger_pid = i32::try_from(stranger.id()).unwrap_or(i32::MAX);
        let mut member = 0;
        for _ in 0..100 {
            if let Some(pid) = group_members(stranger_pid)
                .unwrap_or_default()
                .into_iter()
                .find(|pid| *pid != stranger_pid)
            {
                member = pid;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_ne!(member, 0, "the stranger's member never appeared");
        // The recorded leader claims the stranger's number with another start time.
        let recorded = assert_ok!(Identity::of(stranger_pid)).with_start(1);
        assert_ok!(tracker.scan_group(&queue, recorded, root));
        assert!(
            !tracker.members.contains_key(&member),
            "a member of a group under a reissued number was adopted"
        );
        let _ = gated.go.write_all(b"go\n");
        let _ = gated.leader.wait();
        let _ = stranger.kill();
        let _ = stranger.wait();
        let _ = nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(member),
            nix::sys::signal::Signal::SIGKILL,
        );
    }

    #[test]
    fn a_process_that_was_never_a_descendant_is_left_alone() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut bystander = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
        let mut gated = Gated::start("exit 0");
        assert_ok!(tracker.arm(&queue, gated.pid(), true));
        let _ = gated.go.write_all(b"go\n");
        drain(&mut tracker, &queue, Duration::from_millis(200));
        assert_ok!(tracker.signal(Signal::SIGKILL));
        assert!(alive(i32::try_from(bystander.id()).unwrap_or(0)));
        let _ = gated.leader.wait();
        let _ = bystander.kill();
        let _ = bystander.wait();
    }
}
