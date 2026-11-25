// ABOUTME: Run-side wiring for `hb ctl`: the `hb` wrapper script, the socket path, and starting the service for a run.
// ABOUTME: Kept apart from `run` so that function only gains a few lines; all decisions are in `crate::ctl`.
//! `hb ctl` in a run (hb-ghd.8.1).

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use snafu::{ResultExt, Snafu};

use crate::config::Policy;
use crate::ctl::broker::MAX_SOCKET_PATH_BYTES;
use crate::ctl::client::SOCKET_VAR;
use crate::ctl::handler::Programs;
use crate::ctl::runner::Host;
use crate::ctl::scope::Scope;
use crate::ctl::service::{self, Inputs, Service, StartError};
use crate::policy::CanonicalPath;
use crate::session::GuardHandle;
use crate::system::Environment;

/// A variable of `hb`'s own environment as text, if set and valid UTF-8.
fn text_var(env: &Environment, name: &str) -> Option<String> {
    env.vars.get(name)?.to_str().map(ToOwned::to_owned)
}

/// What follows the user's `PATH` for host commands.
const HOST_SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// The one socket name, which the guardian also knows.
pub const SOCKET_NAME: &str = crate::session::guardian::CTL_SOCKET_NAME;

/// Why `hb ctl` could not be set up for this run.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum CtlError {
    /// The `hb` wrapper could not be written.
    #[snafu(display("could not write the hb wrapper {}", path.display()))]
    Wrapper {
        /// Where.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },
    /// The broker could not start.
    #[snafu(display("hb ctl could not start"))]
    Start {
        /// The cause.
        source: StartError,
    },
}

/// A running `hb ctl` for one run.
#[derive(Debug)]
pub struct RunCtl {
    /// The broker and what startup found.
    pub service: Service,
    /// The socket, for `HB_CTL_SOCKET` and the profile.
    pub socket: CanonicalPath,
}

/// `text` as one shell word in single quotes.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The wrapper that makes `hb` callable by name inside the ball: it runs the real `hb`, so no
/// copy, link or read grant for the install directory is needed.
#[must_use]
pub fn wrapper_script(real_hb: &Path) -> String {
    format!(
        "#!/bin/sh\n# Written by hb for this run: `hb ctl` talks to the broker of the run it is inside.\nexec {} \"$@\"\n",
        quoted(&real_hb.to_string_lossy())
    )
}

/// Writes `<bin>/hb`, creating `bin` private if it is not there yet.
///
/// # Errors
/// [`CtlError::Wrapper`].
pub fn install_wrapper(bin: &Path, real_hb: &Path) -> Result<(), CtlError> {
    let path = bin.join("hb");
    let result = DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(bin)
        .and_then(|()| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&path)?;
            file.write_all(wrapper_script(real_hb).as_bytes())
        });
    result.context(WrapperSnafu { path })
}

/// The approved selectors for this policy, or `None` when `hb ctl` has nothing to do.
#[must_use]
pub fn scope_of(policy: &Policy) -> Option<Scope> {
    let scope = Scope::from_policy(policy);
    (!scope.is_empty()).then_some(scope)
}

/// Where `podman` is: the first executable on the invoking shell's `PATH`, as an absolute path.
fn find_podman(path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    std::env::split_paths(path_var?)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join("podman"))
        .find(|candidate| {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(candidate)
                .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        })
}

/// Starts `hb ctl` for a run whose session directory is `session`.
///
/// # Errors
/// [`CtlError`] if the socket cannot be made. A container that fails its checks is a warning.
pub fn start(
    env: &Environment,
    project: &CanonicalPath,
    session: &CanonicalPath,
    scope: Scope,
    guard: Option<GuardHandle>,
) -> Result<RunCtl, CtlError> {
    let socket = session.as_path().join(SOCKET_NAME);
    let programs = Programs {
        podman: find_podman(env.floor.path_var.as_deref()),
        launchctl: PathBuf::from("/bin/launchctl"),
    };
    // The user's PATH first (where `podman` and its helpers live), then the system directories a
    // helper script may need. Never the agent's PATH: it is not consulted here.
    let user = env
        .floor
        .path_var
        .as_deref()
        .map(|p| p.to_string_lossy().into_owned())
        .filter(|p| !p.is_empty());
    let path = match user {
        Some(user) => format!("{user}:{HOST_SYSTEM_PATH}"),
        None => HOST_SYSTEM_PATH.to_owned(),
    };
    let mut host = Host::new(&path, |name| env.vars.get(name).map(ToOwned::to_owned));
    if let Some(guard) = guard {
        host = host.with_guard(guard);
    }
    let service = service::start(Inputs {
        scope,
        project: project.clone(),
        programs,
        exec: Arc::new(host),
        socket: socket.clone(),
        euid: nix::unistd::geteuid().as_raw(),
        connection: text_var(env, "CONTAINER_CONNECTION"),
        container_host: text_var(env, "CONTAINER_HOST"),
    })
    .context(StartSnafu)?;
    let canonical = CanonicalPath::from_canonical(&socket).map_err(|e| CtlError::Wrapper {
        path: socket.clone(),
        source: io::Error::other(e.to_string()),
    })?;
    Ok(RunCtl {
        service,
        socket: canonical,
    })
}

/// The longest session directory path that still leaves room for the socket name.
#[must_use]
pub fn socket_fits(session: &CanonicalPath) -> bool {
    session.as_str().len() + 1 + SOCKET_NAME.len() <= MAX_SOCKET_PATH_BYTES
}

/// The name of the variable the client reads.
pub const ENV_VAR: &str = SOCKET_VAR;

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn test_the_wrapper_execs_the_real_hb_quoted_and_is_private() {
        let dir = assert_ok!(tempfile::tempdir());
        let bin = dir.path().join("bin");
        assert_ok!(install_wrapper(&bin, Path::new("/opt/it's here/hb")));
        let text = assert_ok!(fs::read_to_string(bin.join("hb")));
        assert_eq!(
            text.lines().last(),
            Some("exec '/opt/it'\\''s here/hb' \"$@\"")
        );
        assert_eq!(
            assert_ok!(fs::metadata(bin.join("hb")))
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        // a second call keeps the directory and refuses to overwrite a script that is there
        assert!(install_wrapper(&bin, Path::new("/x/hb")).is_err());
    }

    #[test]
    fn test_the_wrapper_runs_the_named_program_with_every_argument_intact() {
        let dir = assert_ok!(tempfile::tempdir());
        let bin = dir.path().join("bin");
        assert_ok!(install_wrapper(&bin, Path::new("/bin/echo")));
        let out = assert_ok!(
            std::process::Command::new(bin.join("hb"))
                .args(["a b", "$HOME", ";id"])
                .output()
        );
        assert_eq!(String::from_utf8_lossy(&out.stdout), "a b $HOME ;id\n");
    }

    #[test]
    fn test_podman_is_the_first_absolute_executable_on_the_given_path() {
        let a = assert_ok!(tempfile::tempdir());
        let b = assert_ok!(tempfile::tempdir());
        assert_ok!(fs::write(b.path().join("podman"), "#!/bin/sh\n"));
        assert_eq!(
            find_podman(Some(
                &std::env::join_paths([a.path(), b.path()]).unwrap_or_default()
            )),
            None,
            "not executable yet"
        );
        assert_ok!(fs::set_permissions(
            b.path().join("podman"),
            fs::Permissions::from_mode(0o755)
        ));
        let path = assert_ok!(std::env::join_paths([
            Path::new("relative"),
            a.path(),
            b.path()
        ]));
        assert_eq!(find_podman(Some(&path)), Some(b.path().join("podman")));
        assert_eq!(find_podman(None), None);
    }

    #[test]
    fn test_the_socket_name_is_the_one_the_guardian_will_remove() {
        assert_eq!(SOCKET_NAME, "ctl.sock");
        let long = assert_ok!(CanonicalPath::from_canonical(format!(
            "/{}",
            "a".repeat(100)
        )));
        assert!(!socket_fits(&long));
        let ok = assert_ok!(CanonicalPath::from_canonical(
            "/var/folders/zw/x/T/hb-1-2-3"
        ));
        assert!(socket_fits(&ok));
    }
}
