// ABOUTME: RenderInputs: everything render() needs besides the Policy, with typed slots owned by later tasks.
// ABOUTME: A slot that is not filled yet (proxy before M3, guard allows before M5) simply emits nothing.
//! Inputs to [`render`](super::render) beyond the merged policy.
//!
//! The policy says what the user allowed; these say what this particular run adds: where the
//! proxy listens (M3), the session directory and pty (M2.3, M2.4), a tag for denial logs
//! (M2.3b), files the secrets guard re-allows (M5) and the `hb ctl` socket (M8). Each slot is
//! optional and emits nothing when empty, so `hb profile` can print a profile before any of
//! those milestones exist.

use super::emit::LogTag;
use crate::guard::GuardInputs;
use crate::policy::{CanonicalPath, Port};

/// Where the proxy listens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyEndpoint {
    /// Not known yet (`hb profile` before M3): `localhost:1`, marked as a placeholder by the caller.
    /// Port 0 is not accepted by `sandbox-exec` on this macOS.
    Placeholder,
    /// The proxy's loopback port.
    Port(Port),
}

impl ProxyEndpoint {
    /// The `-D PROXY=` value.
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::Placeholder => "localhost:1".to_owned(),
            Self::Port(port) => format!("localhost:{}", port.get()),
        }
    }
}

/// What a run adds to the policy.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct RenderInputs {
    /// The proxy, or `None` for no network at all.
    pub proxy: Option<ProxyEndpoint>,
    /// The per-session directory (read and write).
    pub session_dir: Option<CanonicalPath>,
    /// hb's own cache for the offline MCP launchers (read and write); `None` when the run has none.
    pub cache_dir: Option<CanonicalPath>,
    /// The pty slave the child owns (`file-ioctl` on this one node).
    pub tty: Option<CanonicalPath>,
    /// Tags every denial so `--log-denials` can find it.
    pub log_tag: Option<LogTag>,
    /// Files re-allowed after the guard denies and before the floor (milestone 5).
    pub guard_allow: Vec<CanonicalPath>,
    /// The secrets guard's pins and dependency exemption (milestone 5).
    pub guard: GuardInputs,
    /// The `hb ctl` broker socket (milestone 8).
    pub ctl_socket: Option<CanonicalPath>,
    /// Bind-mount sources of the containers `hb ctl` may restart, from preflight (milestone 8).
    ///
    /// Each gets an unlink and a link deny, and so does every ancestor a write grant reaches.
    pub mount_pins: Vec<CanonicalPath>,
    /// Directories of `[env] tools`, readable so scripts on `PATH` run.
    pub exec_dirs: Vec<CanonicalPath>,
}

impl RenderInputs {
    /// Inputs with every slot empty.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the proxy.
    #[must_use]
    pub fn with_proxy(mut self, proxy: ProxyEndpoint) -> Self {
        self.proxy = Some(proxy);
        self
    }

    /// Sets the session directory.
    #[must_use]
    pub fn with_session_dir(mut self, dir: CanonicalPath) -> Self {
        self.session_dir = Some(dir);
        self
    }

    /// Sets hb's cache directory.
    #[must_use]
    pub fn with_cache_dir(mut self, dir: CanonicalPath) -> Self {
        self.cache_dir = Some(dir);
        self
    }

    /// Sets the pty slave.
    #[must_use]
    pub fn with_tty(mut self, tty: CanonicalPath) -> Self {
        self.tty = Some(tty);
        self
    }

    /// Sets the denial tag.
    #[must_use]
    pub fn with_log_tag(mut self, tag: LogTag) -> Self {
        self.log_tag = Some(tag);
        self
    }

    /// Sets the guard's pins and dependency exemption.
    #[must_use]
    pub fn with_guard(mut self, guard: GuardInputs) -> Self {
        self.guard = guard;
        self
    }

    /// Sets the files the guard re-allows.
    #[must_use]
    pub fn with_guard_allow(mut self, files: Vec<CanonicalPath>) -> Self {
        self.guard_allow = files;
        self
    }

    /// Sets the `hb ctl` socket.
    #[must_use]
    pub fn with_ctl_socket(mut self, socket: CanonicalPath) -> Self {
        self.ctl_socket = Some(socket);
        self
    }

    /// Sets the mount sources to pin.
    #[must_use]
    pub fn with_mount_pins(mut self, sources: Vec<CanonicalPath>) -> Self {
        self.mount_pins = sources;
        self
    }

    /// Sets the tool directories.
    #[must_use]
    pub fn with_exec_dirs(mut self, dirs: Vec<CanonicalPath>) -> Self {
        self.exec_dirs = dirs;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    #[test]
    fn the_proxy_endpoint_text_is_a_loopback_address_and_the_placeholder_is_port_one() {
        assert_eq!(ProxyEndpoint::Placeholder.text(), "localhost:1");
        assert_eq!(
            ProxyEndpoint::Port(assert_ok!(Port::try_from(41234))).text(),
            "localhost:41234"
        );
    }

    #[test]
    fn new_inputs_fill_no_slot() {
        let inputs = RenderInputs::new();
        assert!(inputs.proxy.is_none() && inputs.session_dir.is_none() && inputs.tty.is_none());
        assert!(inputs.log_tag.is_none() && inputs.ctl_socket.is_none());
        assert!(inputs.guard_allow.is_empty() && inputs.exec_dirs.is_empty());
    }

    #[test]
    fn builders_fill_their_slot() {
        let dir = assert_ok!(CanonicalPath::from_canonical("/private/tmp/s"));
        let inputs = RenderInputs::new()
            .with_proxy(ProxyEndpoint::Placeholder)
            .with_session_dir(dir.clone())
            .with_tty(dir.clone())
            .with_ctl_socket(dir.clone())
            .with_guard_allow(vec![dir.clone()])
            .with_exec_dirs(vec![dir.clone()])
            .with_log_tag(assert_ok!(LogTag::new("0123abcd")));
        assert_eq!(inputs.session_dir, Some(dir.clone()));
        assert_eq!(inputs.guard_allow, vec![dir]);
        assert!(inputs.proxy.is_some() && inputs.log_tag.is_some());
    }
}
