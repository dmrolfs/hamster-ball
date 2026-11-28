// ABOUTME: Process-lifetime ownership for children that outlast a bounded cleanup attempt.
// ABOUTME: Capacity and the reaper worker are acquired before spawn; failed calls cannot drop a live-parent child.
//! Private child custody shared by synchronous library calls.

use std::io;
use std::process::Child;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use snafu::{ResultExt, Snafu};

const CAPACITY: usize = 64;
const POLL: Duration = Duration::from_millis(10);

/// Why cleanup ownership could not be reserved before a spawn.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum CustodyError {
    /// All permitted child slots are occupied.
    #[snafu(display("child cleanup capacity is exhausted"))]
    Full,
    /// A previous cleanup failure closed this group to new children.
    #[snafu(display("this session has an unresolved cleanup failure"))]
    Failed,
    /// The operating system refused the cleanup worker.
    #[snafu(display("the child cleanup worker could not start"))]
    Start {
        /// The thread creation error.
        source: io::Error,
    },
    /// The process-lifetime cleanup worker is no longer running.
    #[snafu(display("the child cleanup worker stopped"))]
    Stopped,
}

#[derive(Debug)]
struct GroupState {
    failed: AtomicBool,
    limit: usize,
}

/// Clones share admission and sticky failure, including after the caller returns.
#[derive(Clone, Debug)]
pub(crate) struct Group(Arc<GroupState>);

impl Group {
    pub(crate) fn new(limit: usize) -> Self {
        Self(Arc::new(GroupState {
            failed: AtomicBool::new(false),
            limit,
        }))
    }

    #[cfg(test)]
    pub(crate) fn failed(&self) -> bool {
        self.0.failed.load(Ordering::Acquire)
    }

    pub(crate) fn reserve(&self) -> Result<Permit, CustodyError> {
        let service = global();
        let mut state = lock(&service.state);
        match &state.worker {
            Some(worker) if worker.is_finished() => return Err(CustodyError::Stopped),
            Some(_) => {}
            None => {
                state.worker = Some(
                    thread::Builder::new()
                        .name("hb-child-custody".into())
                        .spawn(move || service.run())
                        .context(StartSnafu)?,
                );
            }
        }
        let index = state.slots.reserve(&self.0)?;
        Ok(Permit {
            index,
            service,
            transferred: false,
        })
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct Slot<T> {
    group: Option<Arc<GroupState>>,
    pending: Option<T>,
}

struct Slots<T> {
    entries: Vec<Slot<T>>,
}

impl<T> Slots<T> {
    fn new(capacity: usize) -> Self {
        Self {
            entries: (0..capacity)
                .map(|_| Slot {
                    group: None,
                    pending: None,
                })
                .collect(),
        }
    }

    fn reserve(&mut self, group: &Arc<GroupState>) -> Result<usize, CustodyError> {
        if group.failed.load(Ordering::Acquire) {
            return Err(CustodyError::Failed);
        }
        let occupied = self
            .entries
            .iter()
            .filter(|slot| slot.group.as_ref().is_some_and(|g| Arc::ptr_eq(g, group)))
            .count();
        if occupied >= group.limit {
            return Err(CustodyError::Full);
        }
        let index = self
            .entries
            .iter()
            .position(|slot| slot.group.is_none())
            .ok_or(CustodyError::Full)?;
        self.entries[index].group = Some(Arc::clone(group));
        Ok(index)
    }

    fn hand_over(&mut self, index: usize, pending: T) {
        let slot = &mut self.entries[index];
        if let Some(group) = &slot.group {
            group.failed.store(true, Ordering::Release);
        }
        slot.pending = Some(pending);
    }

    fn release(&mut self, index: usize) {
        self.entries[index].group = None;
        self.entries[index].pending = None;
    }
}

struct State {
    slots: Slots<Pending>,
    worker: Option<JoinHandle<()>>,
}

struct Service {
    state: Mutex<State>,
    wake: Condvar,
}

fn global() -> &'static Service {
    static SERVICE: OnceLock<Service> = OnceLock::new();
    SERVICE.get_or_init(|| Service {
        state: Mutex::new(State {
            slots: Slots::new(CAPACITY),
            worker: None,
        }),
        wake: Condvar::new(),
    })
}

impl Service {
    fn run(&'static self) {
        loop {
            for index in 0..CAPACITY {
                // Keep the reservation while OS calls run outside the admission lock.
                let pending = lock(&self.state).slots.entries[index].pending.take();
                if let Some(mut pending) = pending {
                    // Keep the entry owned even if an unexpected polling panic unwinds.
                    let done =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pending.poll()))
                            .unwrap_or(false);
                    let mut state = lock(&self.state);
                    if done {
                        state.slots.release(index);
                    } else {
                        state.slots.entries[index].pending = Some(pending);
                    }
                }
            }
            let mut state = lock(&self.state);
            while !state
                .slots
                .entries
                .iter()
                .any(|slot| slot.pending.is_some())
            {
                state = self
                    .wake
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
            let _ = self.wake.wait_timeout(state, POLL);
        }
    }
}

/// A reserved slot, acquired before the executable is spawned.
pub(crate) struct Permit {
    index: usize,
    service: &'static Service,
    transferred: bool,
}

impl Permit {
    pub(crate) fn install(self, child: Child) -> Lease {
        Lease {
            permit: self,
            child: Some(child),
            readers: Vec::with_capacity(2),
            kill_on_transfer: true,
        }
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        lock(&self.service.state).slots.release(self.index);
    }
}

/// Exclusive child access while a caller is executing the command.
pub(crate) struct Lease {
    permit: Permit,
    child: Option<Child>,
    readers: Vec<JoinHandle<()>>,
    kill_on_transfer: bool,
}

impl Lease {
    pub(crate) fn wait_with_output_before_reap(
        &mut self,
        before_reap: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<std::process::Output> {
        use std::io::Read;
        let mut buffers = Vec::new();
        let streams: [Option<Box<dyn Read + Send>>; 2] = [
            self.stdout.take().map(|stream| Box::new(stream) as _),
            self.stderr.take().map(|stream| Box::new(stream) as _),
        ];
        for stream in streams {
            let buffer = Arc::new(Mutex::new(Vec::new()));
            if let Some(mut stream) = stream {
                let target = buffer.clone();
                self.adopt_reader(thread::Builder::new().spawn(move || {
                    let mut bytes = [0; 4096];
                    loop {
                        match stream.read(&mut bytes) {
                            Ok(0) | Err(_) => break,
                            Ok(n) => lock(&target).extend_from_slice(&bytes[..n]),
                        }
                    }
                })?);
            }
            buffers.push(buffer);
        }
        before_reap()?;
        let status = self.wait()?;
        self.join_readers(std::time::Instant::now() + super::launch_end::CLEANUP_BUDGET);
        if !self.readers.is_empty() {
            return Err(io::Error::other("agent output cleanup incomplete"));
        }
        Ok(std::process::Output {
            status,
            stdout: std::mem::take(&mut *lock(&buffers[0])),
            stderr: std::mem::take(&mut *lock(&buffers[1])),
        })
    }

    pub(crate) fn allow_cleanup_after_drop(&mut self) {
        self.kill_on_transfer = false;
    }

    pub(crate) fn adopt_reader(&mut self, reader: JoinHandle<()>) {
        self.readers.push(reader);
    }

    pub(crate) fn join_readers(&mut self, by: std::time::Instant) {
        while !self.readers.is_empty() {
            let mut index = 0;
            while index < self.readers.len() {
                if self.readers[index].is_finished() {
                    let _ = self.readers.swap_remove(index).join();
                } else {
                    index += 1;
                }
            }
            if self.readers.is_empty() || std::time::Instant::now() >= by {
                break;
            }
            thread::sleep(POLL);
        }
    }

    pub(crate) fn settle(mut self) -> bool {
        self.transfer()
    }

    fn transfer(&mut self) -> bool {
        let Some(mut child) = self.child.take() else {
            return false;
        };
        if matches!(child.try_wait(), Ok(Some(_))) && self.readers.is_empty() {
            return false;
        }
        let pending = Pending {
            child,
            readers: std::mem::take(&mut self.readers),
            kill: self.kill_on_transfer,
        };
        self.permit.transferred = true;
        lock(&self.permit.service.state)
            .slots
            .hand_over(self.permit.index, pending);
        self.permit.service.wake.notify_one();
        true
    }
}

impl std::fmt::Debug for Lease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease")
            .field("child", &self.child)
            .finish_non_exhaustive()
    }
}

impl std::ops::Deref for Lease {
    type Target = Child;

    fn deref(&self) -> &Child {
        match &self.child {
            Some(child) => child,
            None => unreachable!("a live lease always owns its child"),
        }
    }
}

impl std::ops::DerefMut for Lease {
    fn deref_mut(&mut self) -> &mut Child {
        match &mut self.child {
            Some(child) => child,
            None => unreachable!("a live lease always owns its child"),
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        self.transfer();
    }
}

struct Pending {
    child: Child,
    readers: Vec<JoinHandle<()>>,
    kill: bool,
}

impl Pending {
    fn poll(&mut self) -> bool {
        let mut index = 0;
        while index < self.readers.len() {
            if self.readers[index].is_finished() {
                let _ = self.readers.swap_remove(index).join();
            } else {
                index += 1;
            }
        }
        let reaped = match self.child.try_wait() {
            Ok(Some(_)) => true,
            // Another component reaped our child: its number is no longer signal authority.
            Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => true,
            Ok(None) => {
                if self.kill {
                    let _ = self.child.kill();
                }
                false
            }
            Err(_) => false,
        };
        reaped && self.readers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    #[test]
    fn a_child_transferred_after_return_is_reaped_without_the_caller_driving_it() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        use std::time::Instant;

        let group = Group::new(1);
        let permit = assert_ok!(group.reserve());
        let mut lease = permit.install(assert_ok!(
            Command::new("/bin/sh")
                .args(["-c", "echo ready; read done"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
        ));
        let output = claims::assert_some!(lease.stdout.take());
        let mut ready = String::new();
        assert_ok!(BufReader::new(output).read_line(&mut ready));
        assert_eq!(ready, "ready\n");
        let pid = lease.id();
        drop(lease);
        assert!(group.failed());
        let by = Instant::now() + Duration::from_secs(5);
        loop {
            let retained = lock(&global().state).slots.entries.iter().any(|slot| {
                slot.group
                    .as_ref()
                    .is_some_and(|g| Arc::ptr_eq(g, &group.0))
            });
            if !retained {
                break;
            }
            assert!(Instant::now() < by, "custody did not resolve {pid}");
            thread::sleep(POLL);
        }
        let pid = claims::assert_some!(rustix::process::Pid::from_raw(pid as i32));
        let result = rustix::process::waitid(
            rustix::process::WaitId::Pid(pid),
            rustix::process::WaitIdOptions::EXITED | rustix::process::WaitIdOptions::NOHANG,
        );
        assert_eq!(assert_err!(result), rustix::io::Errno::CHILD);
    }

    #[test]
    fn reservations_bound_running_and_transferred_children() {
        let group = Group::new(2);
        let mut slots = Slots::new(3);
        let a = assert_ok!(slots.reserve(&group.0));
        let _b = assert_ok!(slots.reserve(&group.0));
        assert!(matches!(
            assert_err!(slots.reserve(&group.0)),
            CustodyError::Full
        ));
        slots.hand_over(a, 7);
        assert!(matches!(
            assert_err!(slots.reserve(&group.0)),
            CustodyError::Failed
        ));
        assert_eq!(
            slots.entries.iter().filter(|s| s.group.is_some()).count(),
            2
        );
        slots.release(a);
        assert!(group.failed());
    }

    #[test]
    fn global_capacity_survives_dropping_a_failed_callers_group() {
        let mut slots = Slots::new(1);
        let group = Group::new(1);
        let index = assert_ok!(slots.reserve(&group.0));
        slots.hand_over(index, 7);
        drop(group);
        let next = Group::new(1);
        assert!(matches!(
            assert_err!(slots.reserve(&next.0)),
            CustodyError::Full
        ));
        slots.release(index);
        assert_ok!(slots.reserve(&next.0));
    }
}
