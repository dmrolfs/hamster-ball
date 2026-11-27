// ABOUTME: Keeps the trusted child helper from executing agent code before guardian registration.
// ABOUTME: A private one-shot Unix socket authenticates both process peers; EOF or timeout denies launch.
//! The pre-execution guardian barrier.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use nix::sys::socket::{getsockopt, sockopt::LocalPeerPid};
use snafu::{ResultExt, Snafu};

use super::dir::{SessionDir, SessionDirError};
use crate::policy::{CanonicalPath, PathError};

const LIMIT: Duration = Duration::from_secs(10);

/// Why a launch could not be authorized.
#[derive(Debug, Snafu)]
pub enum GateError {
    /// The short socket root is not a canonical path.
    #[snafu(display("the launch gate root is not canonical"))]
    Root {
        /// Canonical path validation failure.
        source: PathError,
    },
    /// The private gate directory could not be created.
    #[snafu(display("could not create the launch gate directory"))]
    Directory {
        /// Directory creation failure.
        source: SessionDirError,
    },
    /// Socket setup or communication failed.
    #[snafu(display("the launch gate failed"))]
    Io {
        /// Socket or filesystem failure.
        source: io::Error,
    },
    /// The kernel could not identify a socket peer.
    #[snafu(display("could not identify the launch gate peer"))]
    Peer {
        /// Kernel credential query failure.
        source: nix::errno::Errno,
    },
    /// The socket peer was not the expected parent or child.
    #[snafu(display("unexpected launch gate peer: expected {expected}, got {actual}"))]
    Identity {
        /// Expected process ID.
        expected: u32,
        /// Process ID supplied by the kernel.
        actual: i32,
    },
    /// No complete handshake arrived in time.
    #[snafu(display("the launch gate timed out"))]
    Timeout,
    /// The parent did not permit execution.
    #[snafu(display("the launch gate did not authorize execution"))]
    Denied,
}

/// Bound before spawn; only the expected helper can receive permission.
pub(super) struct LaunchGate {
    _dir: SessionDir,
    path: PathBuf,
    listener: UnixListener,
}

impl LaunchGate {
    pub(super) fn bind() -> Result<Self, GateError> {
        // Darwin's sockaddr_un cannot hold long per-user or project temporary paths.
        let parent = CanonicalPath::from_canonical("/private/tmp").context(RootSnafu)?;
        let _ = super::dir::sweep_stale(parent.as_path());
        let dir = SessionDir::create(&parent).context(DirectorySnafu)?;
        let path = dir.path().as_path().join("gate");
        let listener = UnixListener::bind(&path).context(IoSnafu)?;
        listener.set_nonblocking(true).context(IoSnafu)?;
        Ok(Self {
            _dir: dir,
            path,
            listener,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn ready(&self, child: u32) -> Result<UnixStream, GateError> {
        let deadline = Instant::now() + LIMIT;
        loop {
            if Instant::now() >= deadline {
                return TimeoutSnafu.fail();
            }
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    if peer(&stream)? != i32::try_from(child).unwrap_or(-1) {
                        continue;
                    }
                    stream
                        .set_read_timeout(Some(
                            deadline
                                .saturating_duration_since(Instant::now())
                                .max(Duration::from_millis(1)),
                        ))
                        .context(IoSnafu)?;
                    stream.set_write_timeout(Some(LIMIT)).context(IoSnafu)?;
                    let mut ready = [0];
                    stream.read_exact(&mut ready).context(IoSnafu)?;
                    if ready != [1] {
                        return DeniedSnafu.fail();
                    }
                    return Ok(stream);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(source) => return Err(GateError::Io { source }),
            }
        }
    }

    pub(super) fn authorize(self, mut stream: UnixStream) -> Result<(), GateError> {
        // The endpoint must be gone before untrusted code can run, even with broad file grants.
        fs::remove_file(&self.path).context(IoSnafu)?;
        drop(self.listener);
        stream.write_all(&[1]).context(IoSnafu)
    }
}

fn peer(stream: &UnixStream) -> Result<i32, GateError> {
    getsockopt(stream, LocalPeerPid).context(PeerSnafu)
}

/// Wait for the parent to confirm guardian protection, preserving all three stdio descriptors.
///
/// # Errors
/// Parent loss, a wrong peer, a timeout, or an invalid permit prevents agent execution.
pub fn await_permission(path: &Path, parent: u32) -> Result<(), GateError> {
    let mut stream = UnixStream::connect(path).context(IoSnafu)?;
    let actual = peer(&stream)?;
    if i32::try_from(parent).ok() != Some(actual) || parent < 2 {
        return IdentitySnafu {
            expected: parent,
            actual,
        }
        .fail();
    }
    stream.set_read_timeout(Some(LIMIT)).context(IoSnafu)?;
    stream.set_write_timeout(Some(LIMIT)).context(IoSnafu)?;
    stream.write_all(&[1]).context(IoSnafu)?;
    let mut permit = [0];
    stream.read_exact(&mut permit).context(IoSnafu)?;
    if permit != [1] {
        return DeniedSnafu.fail();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use std::os::unix::fs::PermissionsExt;
    use std::process::{Command, Stdio};

    #[test]
    fn a_rogue_child_cannot_take_the_real_helpers_permission() {
        let gate = assert_ok!(LaunchGate::bind());
        assert_eq!(
            assert_ok!(fs::metadata(gate.path.parent().unwrap_or(Path::new("/"))))
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(gate.path.as_os_str().len() < 104);
        let connected = gate.path.with_file_name("rogue-ready");
        let mut rogue = assert_ok!(Command::new("/usr/bin/perl")
            .args(["-MIO::Socket::UNIX", "-e",
                "my $s=IO::Socket::UNIX->new(Type=>SOCK_STREAM,Peer=>$ARGV[0]) or die $!; print $s chr(1); $s->flush(); open(my $f,'>',$ARGV[1]) or die $!; close $f; my $b; my $n=sysread($s,$b,1); exit(defined($n) && $n==1 && ord($b)==1 ? 9 : 0)"])
            .arg(gate.path()).arg(&connected).stdin(Stdio::null()).stdout(Stdio::null()).spawn());
        let deadline = Instant::now() + LIMIT;
        while !connected.exists() {
            assert!(Instant::now() < deadline, "rogue never connected");
            std::thread::sleep(Duration::from_millis(5));
        }
        let path = gate.path.clone();
        let helper = std::thread::spawn(move || await_permission(&path, std::process::id()));
        let stream = assert_ok!(gate.ready(std::process::id()));
        assert_ok!(gate.authorize(stream));
        assert_ok!(assert_ok!(helper.join()));
        assert!(
            assert_ok!(rogue.wait()).success(),
            "rogue received a permit"
        );
    }

    #[test]
    fn a_removed_gate_cannot_authorize_a_late_helper() {
        let gate = assert_ok!(LaunchGate::bind());
        let path = gate.path.clone();
        drop(gate);
        assert!(await_permission(&path, std::process::id()).is_err());
    }
}
