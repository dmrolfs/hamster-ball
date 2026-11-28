// ABOUTME: The launch gate: the helper reports Prepared, waits for Release over an owned socket, then execs.
// ABOUTME: The real stdin travels as an SCM_RIGHTS descriptor, so no user byte is read and no path is trusted.
//! Gated launch (hb-9lu).
//!
//! The parent starts `hb __child --gate` with fd 0 set to one end of a socketpair and sends the
//! target's real stdin across it. The helper establishes its final session and group, says
//! `prepared <pid>`, and waits up to [`GATE_DEADLINE`] for `release`. Only then does it put the
//! received descriptor on fd 0 and exec `sandbox-exec`. If the parent dies, the socket closes and
//! the helper exits without running anything. A watch armed before `release` therefore covers
//! the target from its first instruction.

use std::io::{self, IoSlice, IoSliceMut, Read, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use rustix::net::{
    RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, recvmsg, sendmsg,
};
use snafu::{ResultExt, Snafu};

/// Longest wait on either side of the gate.
pub const GATE_DEADLINE: Duration = Duration::from_secs(5);
const PREPARED: &str = "prepared";
const RELEASE: &[u8] = b"release\n";
const MAX_LINE: usize = 64;
const POLL: Duration = Duration::from_millis(2);

/// Why the gate did not open.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum GateError {
    /// The socket could not be used.
    #[snafu(display("the launch gate failed"))]
    Io {
        /// The OS error.
        source: io::Error,
    },
    /// The other side closed or sent something unexpected.
    #[snafu(display("the launch gate saw an unexpected message"))]
    Protocol,
    /// The other side did not answer in time.
    #[snafu(display("the launch gate timed out"))]
    Deadline,
    /// The helper did not receive the target's stdin.
    #[snafu(display("the launch gate did not receive the child's stdin"))]
    NoStdin,
}

/// The parent's end of the gate.
#[derive(Debug)]
pub struct ParentGate {
    socket: UnixStream,
}

impl ParentGate {
    /// Wraps the parent's end.
    #[must_use]
    pub fn new(socket: UnixStream) -> Self {
        Self { socket }
    }

    /// Sends the target's stdin and waits for the helper's process number.
    ///
    /// # Errors
    /// [`GateError`]: the helper died, misbehaved or did not answer in time.
    pub fn prepare(&mut self, stdin: impl AsFd) -> Result<i32, GateError> {
        let fds = [stdin.as_fd()];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !control.push(SendAncillaryMessage::ScmRights(&fds)) {
            return Err(GateError::Protocol);
        }
        sendmsg(
            &self.socket,
            &[IoSlice::new(b"stdin\n")],
            &mut control,
            SendFlags::empty(),
        )
        .map_err(io::Error::from)
        .context(IoSnafu)?;
        let line = read_line(&mut self.socket, Instant::now() + GATE_DEADLINE)?;
        let pid = line
            .strip_prefix(PREPARED)
            .and_then(|rest| rest.strip_prefix(' '))
            .and_then(|pid| pid.parse::<i32>().ok())
            .filter(|pid| *pid > 1)
            .ok_or(GateError::Protocol)?;
        Ok(pid)
    }

    /// Lets the helper exec the target.
    ///
    /// # Errors
    /// [`GateError::Io`] if the helper is gone.
    pub fn release(mut self) -> Result<(), GateError> {
        self.socket.set_nonblocking(false).context(IoSnafu)?;
        self.socket.write_all(RELEASE).context(IoSnafu)
    }
}

/// Spawns a parked helper, drops the parent's duplicate socket end, and validates Prepared.
/// The owner supplies its child-custody installation and arming operations before any release.
pub(crate) fn prepare_launch<C, A, E>(
    command: &mut Command,
    stdin: impl AsFd,
    install: impl FnOnce(Child) -> C,
    mut child_ref: impl FnMut(&mut C) -> &mut Child,
    arm: impl FnOnce(i32) -> Result<A, E>,
    io_error: impl Fn(io::Error) -> E,
    gate_error: impl Fn(GateError) -> E,
) -> Result<(C, ParentGate, A), E> {
    let (ours, theirs) = UnixStream::pair().map_err(&io_error)?;
    command.stdin(Stdio::from(OwnedFd::from(theirs)));
    let spawned = command.spawn();
    command.stdin(Stdio::null());
    let mut child = install(spawned.map_err(io_error)?);
    let mut gate = ParentGate::new(ours);
    let prepared = gate.prepare(stdin).map_err(&gate_error).and_then(|pid| {
        if u32::try_from(pid).ok() != Some(child_ref(&mut child).id()) {
            return Err(gate_error(GateError::Protocol));
        }
        arm(pid)
    });
    match prepared {
        Ok(armed) => Ok((child, gate, armed)),
        Err(error) => {
            let child = child_ref(&mut child);
            let _ = child.kill();
            let by = Instant::now() + super::launch_end::CLEANUP_BUDGET;
            while Instant::now() < by {
                match child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => std::thread::sleep(POLL),
                }
            }
            // An unresolved child remains in its pre-reserved custody slot.
            Err(error)
        }
    }
}

/// The helper's end of the gate: fd 0 at start.
#[derive(Debug)]
pub struct HelperGate {
    socket: UnixStream,
}

impl HelperGate {
    /// Takes ownership of the gate socket, which is the helper's current stdin.
    ///
    /// # Errors
    /// [`GateError::Io`] if fd 0 cannot be duplicated.
    pub fn from_stdin() -> Result<Self, GateError> {
        let owned: OwnedFd = io::stdin().as_fd().try_clone_to_owned().context(IoSnafu)?;
        Ok(Self {
            socket: UnixStream::from(owned),
        })
    }

    /// Receives the target's stdin.
    ///
    /// # Errors
    /// [`GateError`] when no descriptor arrived in time.
    pub fn receive_stdin(&self) -> Result<OwnedFd, GateError> {
        self.socket.set_nonblocking(false).context(IoSnafu)?;
        self.socket
            .set_read_timeout(Some(GATE_DEADLINE))
            .context(IoSnafu)?;
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let mut bytes = [0u8; 8];
        let received = recvmsg(
            &self.socket,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut control,
            RecvFlags::empty(),
        )
        // The read timeout reports as EAGAIN; say it was the deadline, not a failed socket.
        .map_err(|errno| match errno {
            rustix::io::Errno::AGAIN => GateError::Deadline,
            other => GateError::Io {
                source: io::Error::from(other),
            },
        })?;
        if &bytes[..received.bytes] != b"stdin\n" {
            return Err(GateError::Protocol);
        }
        let mut fds = Vec::new();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(rights) = message {
                fds.extend(rights);
            }
        }
        match <[OwnedFd; 1]>::try_from(fds) {
            // macOS has no MSG_CMSG_CLOEXEC; close-on-exec is set at once. dup2 onto fd 0 clears it.
            Ok([fd]) => {
                rustix::io::fcntl_setfd(&fd, rustix::io::FdFlags::CLOEXEC)
                    .map_err(io::Error::from)
                    .context(IoSnafu)?;
                Ok(fd)
            }
            Err(_) => Err(GateError::NoStdin),
        }
    }

    /// Says the helper is ready, then waits for `release`.
    ///
    /// # Errors
    /// [`GateError`]: the parent closed the socket, sent something else or waited too long.
    pub fn wait_for_release(mut self, pid: u32) -> Result<(), GateError> {
        self.socket.set_nonblocking(false).context(IoSnafu)?;
        self.socket
            .write_all(format!("{PREPARED} {pid}\n").as_bytes())
            .context(IoSnafu)?;
        let line = read_line(&mut self.socket, Instant::now() + GATE_DEADLINE)?;
        if line.as_bytes() == &RELEASE[..RELEASE.len() - 1] {
            Ok(())
        } else {
            Err(GateError::Protocol)
        }
    }
}

/// Reads one line before `deadline` without ever blocking: the socket is nonblocking and polled,
/// so a peer that is closed, silent or refuses a timeout cannot hold the helper past the deadline.
fn read_line(socket: &mut UnixStream, deadline: Instant) -> Result<String, GateError> {
    socket.set_nonblocking(true).context(IoSnafu)?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if Instant::now() >= deadline {
            return Err(GateError::Deadline);
        }
        match socket.read(&mut byte) {
            Ok(0) => return Err(GateError::Protocol),
            Ok(_) if byte[0] == b'\n' => {
                return String::from_utf8(line).map_err(|_| GateError::Protocol);
            }
            Ok(_) if line.len() < MAX_LINE => line.push(byte[0]),
            Ok(_) => return Err(GateError::Protocol),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::sleep(POLL),
            Err(source) => return Err(GateError::Io { source }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::thread;

    #[test]
    fn the_parent_sends_stdin_and_the_helper_reports_prepared() {
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        let helper = thread::spawn(move || {
            let gate = HelperGate { socket: theirs };
            let fd = gate.receive_stdin()?;
            drop(fd);
            gate.wait_for_release(4242)
        });
        let mut parent = ParentGate::new(ours);
        let null = assert_ok!(std::fs::File::open("/dev/null"));
        assert_eq!(assert_ok!(parent.prepare(&null)), 4242);
        assert_ok!(parent.release());
        assert_ok!(assert_ok!(helper.join().map_err(|_| "helper panicked")));
    }

    fn gate_pair() -> (UnixStream, HelperGate) {
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        (ours, HelperGate { socket: theirs })
    }

    /// Sends `bytes` with `fds` attached, as a misbehaving parent might.
    fn send_raw(socket: &UnixStream, bytes: &[u8], fds: &[std::os::fd::BorrowedFd<'_>]) {
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(2))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !fds.is_empty() {
            assert!(control.push(SendAncillaryMessage::ScmRights(fds)));
        }
        assert_ok!(sendmsg(
            socket,
            &[IoSlice::new(bytes)],
            &mut control,
            SendFlags::empty()
        ));
    }

    #[test]
    fn test_receive_stdin_takes_exactly_one_descriptor_and_marks_it_close_on_exec() {
        let (ours, gate) = gate_pair();
        let null = assert_ok!(std::fs::File::open("/dev/null"));
        send_raw(&ours, b"stdin\n", &[null.as_fd()]);
        let fd = assert_ok!(gate.receive_stdin());
        let flags = assert_ok!(rustix::io::fcntl_getfd(&fd));
        assert!(flags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[test]
    fn test_receive_stdin_refuses_no_descriptor_two_descriptors_and_other_bytes() {
        let null = assert_ok!(std::fs::File::open("/dev/null"));
        let (ours, gate) = gate_pair();
        send_raw(&ours, b"stdin\n", &[]);
        assert!(matches!(gate.receive_stdin(), Err(GateError::NoStdin)));
        let (ours, gate) = gate_pair();
        send_raw(&ours, b"stdin\n", &[null.as_fd(), null.as_fd()]);
        assert!(matches!(gate.receive_stdin(), Err(GateError::NoStdin)));
        let (ours, gate) = gate_pair();
        send_raw(&ours, b"other\n", &[null.as_fd()]);
        assert!(matches!(gate.receive_stdin(), Err(GateError::Protocol)));
    }

    #[test]
    fn test_prepare_accepts_only_a_well_formed_prepared_line() {
        let null = assert_ok!(std::fs::File::open("/dev/null"));
        for reply in [
            "prepared\n",
            "prepared x\n",
            "prepared  12\n",
            "prepared 1\n",
            "ready 123\n",
            "prepared 12 extra\n",
        ] {
            let (ours, mut theirs) = assert_ok!(UnixStream::pair());
            assert_ok!(theirs.write_all(reply.as_bytes()));
            let mut parent = ParentGate::new(ours);
            assert!(
                matches!(parent.prepare(&null), Err(GateError::Protocol)),
                "{reply:?}"
            );
        }
        // Sending stdin to a closed peer fails immediately, not at the response deadline.
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        drop(theirs);
        let mut parent = ParentGate::new(ours);
        let started = Instant::now();
        assert!(matches!(parent.prepare(&null), Err(GateError::Io { .. })));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn test_wait_for_release_accepts_only_the_exact_release_line() {
        for reply in [&b"releasex\n"[..], b"RELEASE\n", b"\xff\xfe\n", &[b'a'; 65]] {
            let (mut ours, gate) = gate_pair();
            assert_ok!(ours.write_all(reply));
            assert_ok!(ours.write_all(b"\n"));
            assert!(
                matches!(gate.wait_for_release(7), Err(GateError::Protocol)),
                "{reply:?}"
            );
        }
        let (mut ours, gate) = gate_pair();
        assert_ok!(ours.write_all(b"release\n"));
        assert_ok!(gate.wait_for_release(7));
    }

    #[test]
    fn test_read_line_gives_up_at_its_deadline_and_not_before() {
        let (mut ours, _theirs) = assert_ok!(UnixStream::pair());
        let started = Instant::now();
        let result = read_line(&mut ours, Instant::now() + Duration::from_millis(60));
        assert!(matches!(result, Err(GateError::Deadline)));
        assert!(started.elapsed() >= Duration::from_millis(60));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn test_release_after_the_helper_closed_its_end_is_an_error() {
        let (ours, theirs) = assert_ok!(UnixStream::pair());
        drop(theirs);
        assert!(matches!(
            ParentGate::new(ours).release(),
            Err(GateError::Io { .. })
        ));
    }
}
