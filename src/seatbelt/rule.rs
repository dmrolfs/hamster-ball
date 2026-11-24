// ABOUTME: The typed Seatbelt rule list: sections, operations and filters, with parameters carried as typed values.
// ABOUTME: Unsafe operations (hid-control, appleevent-send) and free-form filter text are not representable.
//! Typed rules.
//!
//! A profile is built as a `Vec<Rule>`, checked ([`super::check`]) and only then written as text
//! ([`super::emit`]). The types are the first line of defense: there is no [`Op`] for
//! `hid-control` (the operation that gates `TIOCSTI` keystroke injection) or `appleevent-send`,
//! and a [`Filter`] carries either a [`ParamValue`] (which reaches the profile as a `(param ...)`
//! reference, never as text) or a `&'static str` written in this crate.

use strum::{Display, IntoStaticStr};

/// Where a rule belongs in the profile. The derived order is the emission order (design 7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Section {
    /// Process, signal and IPC basics.
    Process,
    /// Metadata for every path, and ancestor directory reads.
    Metadata,
    /// System directories and device nodes.
    SystemRead,
    /// Allows from the merged policy.
    Grants,
    /// TLS trust services and keychain reads.
    Tls,
    /// Network.
    Network,
    /// Secrets-guard denies (milestone 5).
    Guard,
    /// Template re-allow, after the guard denies.
    TemplateAllow,
    /// Denies of host services the policy has not turned on (`launchctl`). After every allow.
    HostServices,
    /// `fs.deny_read` and `fs.deny_write` from config.
    PolicyDeny,
    /// The floor.
    Floor,
    /// Unlink pins on ancestors of protected paths.
    Pins,
}

/// Whether a rule allows or denies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub enum Action {
    /// `(allow ...)`.
    Allow,
    /// `(deny ...)`.
    Deny,
}

/// A Seatbelt operation this crate may emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display, IntoStaticStr)]
pub enum Op {
    /// `process-exec`.
    #[strum(serialize = "process-exec")]
    ProcessExec,
    /// `process-fork`.
    #[strum(serialize = "process-fork")]
    ProcessFork,
    /// `signal`.
    #[strum(serialize = "signal")]
    Signal,
    /// `ipc-posix-shm`.
    #[strum(serialize = "ipc-posix-shm")]
    IpcPosixShm,
    /// `ipc-posix-sem`.
    #[strum(serialize = "ipc-posix-sem")]
    IpcPosixSem,
    /// `file-read-data`.
    #[strum(serialize = "file-read-data")]
    FileReadData,
    /// `file-read-metadata`.
    #[strum(serialize = "file-read-metadata")]
    FileReadMetadata,
    /// `file-read-xattr`.
    #[strum(serialize = "file-read-xattr")]
    FileReadXattr,
    /// `file-test-existence`.
    #[strum(serialize = "file-test-existence")]
    FileTestExistence,
    /// `file-map-executable`: mapping a file as code, a child of `file-read-data`.
    #[strum(serialize = "file-map-executable")]
    FileMapExecutable,
    /// `file-read*`: every read operation. Allows only; a deny must name each operation.
    #[strum(serialize = "file-read*")]
    FileReadAll,
    /// `file-write*`: every write operation.
    #[strum(serialize = "file-write*")]
    FileWriteAll,
    /// `file-write-unlink`.
    #[strum(serialize = "file-write-unlink")]
    FileWriteUnlink,
    /// `file-ioctl`.
    #[strum(serialize = "file-ioctl")]
    FileIoctl,
    /// `mach-lookup`.
    #[strum(serialize = "mach-lookup")]
    MachLookup,
    /// `user-preference-read`.
    #[strum(serialize = "user-preference-read")]
    UserPreferenceRead,
    /// `network-outbound`.
    #[strum(serialize = "network-outbound")]
    NetworkOutbound,
    /// `network-bind`.
    #[strum(serialize = "network-bind")]
    NetworkBind,
    /// `network-inbound`.
    #[strum(serialize = "network-inbound")]
    NetworkInbound,
}

impl Op {
    /// The read operations a deny must list explicitly, in the order they are written.
    ///
    /// Seatbelt resolves the most specific operation first, so a wildcard `(deny file-read* X)`
    /// does not override an earlier `(allow file-read-metadata)` (design 7.1, D51).
    /// `file-map-executable` is a child of `file-read-data`; naming it closes mapping a denied
    /// file as code through a descriptor opened before the sandbox (design 7.1, D62).
    pub const READ_SET: [Op; 5] = [
        Op::FileReadData,
        Op::FileReadMetadata,
        Op::FileReadXattr,
        Op::FileTestExistence,
        Op::FileMapExecutable,
    ];

    /// Whether this is one of the specific read operations in [`Op::READ_SET`].
    #[must_use]
    pub fn is_specific_read(self) -> bool {
        Self::READ_SET.contains(&self)
    }

    /// Whether the operation reads file data or metadata, specifically or by wildcard.
    #[must_use]
    pub fn is_read_class(self) -> bool {
        self.is_specific_read() || self == Op::FileReadAll
    }

    /// Whether an unfiltered rule on this operation would be dangerous.
    #[must_use]
    pub fn needs_filter(self) -> bool {
        matches!(
            self,
            Op::MachLookup
                | Op::FileIoctl
                | Op::NetworkOutbound
                | Op::NetworkBind
                | Op::NetworkInbound
        )
    }
}

/// The kind of a `-D` parameter, which fixes its name prefix and what its value may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ParamKind {
    /// A directory whose ancestors may be listed (`A<n>`).
    Ancestor,
    /// A read grant (`R<n>`).
    Read,
    /// A read-write grant (`W<n>`).
    Write,
    /// A floor or policy deny path (`F<n>`).
    Deny,
    /// A whole regex built by this crate (`G<n>`).
    Regex,
    /// A loopback port the agent may connect to (`L<n>`).
    Loopback,
    /// A loopback port a server may listen on (`B<n>`).
    Bind,
    /// The pty slave (`T<n>`).
    Tty,
    /// The session directory (`S<n>`).
    Session,
    /// hb's own cache directory, read and write (`C<n>`).
    Cache,
    /// A unix socket (`K<n>`).
    Socket,
    /// The proxy endpoint (`PROXY`).
    Proxy,
}

impl ParamKind {
    /// The name prefix; the proxy has the fixed name `PROXY`.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::Ancestor => "A",
            Self::Read => "R",
            Self::Write => "W",
            Self::Deny => "F",
            Self::Regex => "G",
            Self::Loopback => "L",
            Self::Bind => "B",
            Self::Tty => "T",
            Self::Session => "S",
            Self::Cache => "C",
            Self::Socket => "K",
            Self::Proxy => "PROXY",
        }
    }

    /// Whether the value is a `host:port` endpoint rather than a path or regex.
    #[must_use]
    pub fn is_endpoint(self) -> bool {
        matches!(self, Self::Loopback | Self::Bind | Self::Proxy)
    }
}

/// A value that reaches the profile as a `-D` parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ParamValue {
    /// What the value is for.
    pub kind: ParamKind,
    /// The value: an absolute path, a regex starting `^/`, or `localhost:<port>`.
    pub text: String,
}

impl ParamValue {
    /// A parameter of `kind` with `text`.
    #[must_use]
    pub fn new(kind: ParamKind, text: impl Into<String>) -> Self {
        Self {
            kind,
            text: text.into(),
        }
    }
}

/// What a rule applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Filter {
    /// `(subpath (param ..))`.
    Subpath(ParamValue),
    /// `(literal (param ..))`.
    Literal(ParamValue),
    /// `(regex (param ..))`: the whole regex is the parameter.
    Regex(ParamValue),
    /// `(path-ancestors (param ..))`.
    PathAncestors(ParamValue),
    /// `(remote ip (param ..))`.
    RemoteIp(ParamValue),
    /// `(local ip (param ..))`.
    LocalIp(ParamValue),
    /// `(remote unix-socket (subpath (param ..)))`: a deny covers a whole directory of sockets.
    RemoteUnixSocket(ParamValue),
    /// `(remote unix-socket (path-literal (param ..)))`: an allow names exactly one socket.
    RemoteUnixSocketLiteral(ParamValue),
    /// `(global-name "..")`.
    GlobalName(&'static str),
    /// `(preference-domain "..")`.
    PreferenceDomain(&'static str),
    /// `(subpath "..")` with text written in this crate.
    StaticSubpath(&'static str),
    /// `(literal "..")` with text written in this crate.
    StaticLiteral(&'static str),
    /// `(regex #"..")` with text written in this crate.
    StaticRegex(&'static str),
    /// `(target same-sandbox)`.
    TargetSameSandbox,
}

impl Filter {
    /// The parameter this filter carries, if any.
    #[must_use]
    pub fn param(&self) -> Option<&ParamValue> {
        match self {
            Self::Subpath(p)
            | Self::Literal(p)
            | Self::Regex(p)
            | Self::PathAncestors(p)
            | Self::RemoteIp(p)
            | Self::LocalIp(p)
            | Self::RemoteUnixSocket(p)
            | Self::RemoteUnixSocketLiteral(p) => Some(p),
            _ => None,
        }
    }

    /// The text written in this crate, if any.
    #[must_use]
    pub fn static_text(&self) -> Option<&'static str> {
        match self {
            Self::GlobalName(t)
            | Self::PreferenceDomain(t)
            | Self::StaticSubpath(t)
            | Self::StaticLiteral(t)
            | Self::StaticRegex(t) => Some(t),
            _ => None,
        }
    }
}

/// One rule of the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Where it goes.
    pub section: Section,
    /// Allow or deny.
    pub action: Action,
    /// The operations, written space-separated.
    pub ops: Vec<Op>,
    /// The filters; any one matching is enough. Empty means "everything".
    pub filters: Vec<Filter>,
    /// A short label appended to the denial message, so `--log-denials` can say which part denied.
    pub label: Option<&'static str>,
}

impl Rule {
    /// An allow rule.
    #[must_use]
    pub fn allow(section: Section, ops: &[Op], filters: Vec<Filter>) -> Self {
        Self {
            section,
            action: Action::Allow,
            ops: ops.to_vec(),
            filters,
            label: None,
        }
    }

    /// A deny rule.
    #[must_use]
    pub fn deny(section: Section, ops: &[Op], filters: Vec<Filter>) -> Self {
        Self {
            section,
            action: Action::Deny,
            ops: ops.to_vec(),
            filters,
            label: None,
        }
    }

    /// The same rule with a denial label.
    #[must_use]
    pub fn labelled(mut self, label: &'static str) -> Self {
        self.label = Some(label);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn sections_are_ordered_as_the_design_emits_them() {
        let order = [
            Section::Process,
            Section::Metadata,
            Section::SystemRead,
            Section::Grants,
            Section::Tls,
            Section::Network,
            Section::Guard,
            Section::TemplateAllow,
            Section::HostServices,
            Section::PolicyDeny,
            Section::Floor,
            Section::Pins,
        ];
        let mut sorted = order;
        sorted.sort();
        assert_eq!(sorted, order);
    }

    #[test]
    fn operations_print_as_seatbelt_names() {
        assert_eq!(Op::FileReadAll.to_string(), "file-read*");
        assert_eq!(Op::FileWriteAll.to_string(), "file-write*");
        assert_eq!(Op::FileWriteUnlink.to_string(), "file-write-unlink");
        assert_eq!(Op::IpcPosixSem.to_string(), "ipc-posix-sem");
        assert_eq!(Op::UserPreferenceRead.to_string(), "user-preference-read");
    }

    #[test]
    fn the_read_set_is_the_five_specific_operations_and_not_the_wildcard() {
        let names: Vec<String> = Op::READ_SET.iter().map(ToString::to_string).collect();
        assert_eq!(
            names,
            [
                "file-read-data",
                "file-read-metadata",
                "file-read-xattr",
                "file-test-existence",
                "file-map-executable"
            ]
        );
        assert!(!Op::READ_SET.contains(&Op::FileReadAll));
        assert!(Op::FileReadAll.is_read_class());
        assert!(!Op::FileReadAll.is_specific_read());
        assert!(!Op::FileWriteAll.is_read_class());
        assert!(Op::FileMapExecutable.is_specific_read());
    }

    #[test]
    fn operations_that_must_be_filtered_are_the_dangerous_ones() {
        for op in [
            Op::MachLookup,
            Op::FileIoctl,
            Op::NetworkOutbound,
            Op::NetworkBind,
            Op::NetworkInbound,
        ] {
            assert!(op.needs_filter(), "{op}");
        }
        for op in [
            Op::ProcessExec,
            Op::FileReadAll,
            Op::Signal,
            Op::FileWriteAll,
        ] {
            assert!(!op.needs_filter(), "{op}");
        }
    }

    #[test]
    fn param_prefixes_are_distinct() {
        let kinds = [
            ParamKind::Ancestor,
            ParamKind::Read,
            ParamKind::Write,
            ParamKind::Deny,
            ParamKind::Regex,
            ParamKind::Loopback,
            ParamKind::Bind,
            ParamKind::Tty,
            ParamKind::Session,
            ParamKind::Cache,
            ParamKind::Socket,
            ParamKind::Proxy,
        ];
        let mut prefixes: Vec<&str> = kinds.iter().map(|k| k.prefix()).collect();
        prefixes.sort_unstable();
        prefixes.dedup();
        assert_eq!(prefixes.len(), kinds.len());
        assert!(ParamKind::Proxy.is_endpoint() && ParamKind::Bind.is_endpoint());
        assert!(!ParamKind::Read.is_endpoint());
    }

    #[test]
    fn a_filter_exposes_its_param_or_its_static_text_but_not_both() {
        let p = ParamValue::new(ParamKind::Read, "/a");
        let with_param = Filter::Subpath(p.clone());
        assert_eq!(with_param.param(), Some(&p));
        assert_eq!(with_param.static_text(), None);
        let with_text = Filter::GlobalName("com.apple.trustd");
        assert_eq!(with_text.param(), None);
        assert_eq!(with_text.static_text(), Some("com.apple.trustd"));
        assert_eq!(Filter::TargetSameSandbox.param(), None);
    }
}
