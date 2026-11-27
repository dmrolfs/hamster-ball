// ABOUTME: Identity-qualified descendant watches that survive a root's exit and a descendant's setsid.
// ABOUTME: Fork events trigger discovery, not automatic kernel tracking; fast reparenting can escape this registry (hb-caj).
//! The guardian's process registry. macOS does not support NOTE_TRACK, so children must be
//! discovered while their parent still exists. This is cleanup, not full-tree containment.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

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
    /// Set on a root that leads its own process group: the group is scanned even after the root exits.
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
}

impl Tracker {
    pub(super) fn is_empty(&self) -> bool {
        self.members.is_empty()
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
        // An old parent's number is not authority to enumerate a new parent's children.
        if !parent.is_current().context(IdentitySnafu)? {
            return Ok(());
        }
        let mut candidates: VecDeque<(i32, Listed)> = children_of(parent.pid())
            .context(ListSnafu)?
            .into_iter()
            .map(|pid| (pid, Listed::ChildOf(parent.pid())))
            .collect();
        if group {
            candidates.extend(
                group_members(parent.pid())
                    .context(ListSnafu)?
                    .into_iter()
                    .map(|pid| (pid, Listed::InGroup(parent.pid()))),
            );
        }
        if !parent.is_current().context(IdentitySnafu)? {
            return Ok(());
        }
        while let Some((pid, listed)) = candidates.pop_front() {
            if pid <= 1 || self.members.contains_key(&pid) {
                continue;
            }
            let seen = match Observed::of(pid) {
                Ok(seen) => seen,
                Err(IdentityError::Gone { .. }) => continue,
                Err(source) => return Err(TrackerError::Identity { source }),
            };
            if !may_adopt(listed, &seen, &root) {
                continue;
            }
            match self.adopt(queue, seen.identity, root) {
                Ok(true) => candidates.extend(
                    children_of(pid)
                        .context(ListSnafu)?
                        .into_iter()
                        .map(|child| (child, Listed::ChildOf(pid))),
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

    /// Adopts live members of the root's own process group. The group number cannot be reissued
    /// while a member exists; a member is only adopted when it is the root's user and started no
    /// earlier than the root, so a number reused after the group emptied adopts nothing.
    fn scan_group(
        &mut self,
        queue: &Kqueue,
        leader: Identity,
        root: Identity,
    ) -> Result<(), TrackerError> {
        // The leader is usually gone by now. If a different process holds its number, that number was
        // reissued and the group listed under it is not ours. (A dead root is not kept as a zombie:
        // launchd reaps an orphan first, measured 0 of 300, so this check cannot be a hold on the
        // number. It narrows the window; the remaining case needs a pid wrap, at least 38 s.)
        match Identity::of(leader.pid()) {
            Ok(now) if now != leader => return Ok(()),
            Ok(_) | Err(IdentityError::Gone { .. }) => {}
            Err(source) => return Err(TrackerError::Identity { source }),
        }
        for pid in group_members(leader.pid()).context(ListSnafu)? {
            if pid <= 1 || self.members.contains_key(&pid) {
                continue;
            }
            let seen = match Observed::of(pid) {
                Ok(seen) => seen,
                Err(IdentityError::Gone { .. }) => continue,
                Err(source) => return Err(TrackerError::Identity { source }),
            };
            let member = seen.identity;
            if !may_adopt(Listed::InGroup(leader.pid()), &seen, &root) {
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
    /// Returns whether the process was adopted. A process that is gone, foreign or too old is not an
    /// error.
    pub(super) fn adopt_candidate(
        &mut self,
        queue: &Kqueue,
        pid: i32,
        own_pid: i32,
    ) -> Result<bool, TrackerError> {
        if pid <= 1 || pid == own_pid || self.members.contains_key(&pid) {
            return Ok(false);
        }
        let Some(earliest) = self.earliest_root else {
            return Ok(false);
        };
        let candidate = match Identity::of(pid) {
            Ok(candidate) => candidate,
            Err(IdentityError::Gone { .. }) => return Ok(false),
            Err(source) => return Err(TrackerError::Identity { source }),
        };
        if candidate.uid() != earliest.uid() || !candidate.started_no_earlier_than(&earliest) {
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
        if event.fflags().contains(FilterFlag::NOTE_FORK) {
            self.discover(queue, member.identity, member.root, false)?;
        }
        if member.scan_group {
            // The root leads its own group, which outlives it while any member lives, so members
            // forked before the root exited are found even though their parent is already gone.
            self.scan_group(queue, member.identity, member.root)?;
        }
        let exited = event.fflags().contains(FilterFlag::NOTE_EXIT);
        if exited {
            self.members.remove(&pid);
        }
        Ok(exited)
    }

    /// Never signals a group number. An identity is checked again immediately before each kill.
    /// The check and kill are not atomic; the owner-approved residual race remains.
    ///
    /// Every member is attempted, whatever happens to the others: one process that cannot be read
    /// or signalled must not leave the rest running. Members that are gone are forgotten. The first
    /// failure is returned after the pass, so the caller can say cleanup was incomplete.
    pub(super) fn signal(&mut self, signal: Signal) -> Result<(), TrackerError> {
        let mut gone = Vec::new();
        let mut first_failure = None;
        for (pid, member) in &self.members {
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
        assert!(!assert_ok!(tracker.adopt_candidate(&queue, pid(&newer), 0)));
        assert_ok!(tracker.arm(&queue, pid(&root), false));
        assert!(!assert_ok!(tracker.adopt_candidate(&queue, pid(&older), 0)));
        assert!(!assert_ok!(tracker.adopt_candidate(&queue, 1, 0)));
        assert!(!assert_ok!(tracker.adopt_candidate(
            &queue,
            pid(&newer),
            pid(&newer)
        )));
        assert!(assert_ok!(tracker.adopt_candidate(&queue, pid(&newer), 0)));
        assert!(!assert_ok!(tracker.adopt_candidate(&queue, pid(&newer), 0)));
        assert!(!assert_ok!(tracker.adopt_candidate(&queue, 999_990, 0)));
        // The root's exit does not forget it: a sweep after the roots are gone still has a reference.
        let _ = root.kill();
        let _ = root.wait();
        assert!(!assert_ok!(tracker.adopt_candidate(&queue, pid(&older), 0)));
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

    #[test]
    fn a_member_still_dies_after_its_group_leader_has_exited() {
        let queue = assert_ok!(Kqueue::new());
        let mut tracker = Tracker::default();
        let mut gated = Gated::start("sleep 30 </dev/null >/dev/null 2>&1 & echo $!; exit 0");
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
    fn a_member_of_the_roots_own_group_is_found_by_the_group_scan_when_the_root_exits() {
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
