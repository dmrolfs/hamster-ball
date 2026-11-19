// ABOUTME: Pure policy value types: paths, home and project root, hosts, ports, environment names, container selectors, commands.
// ABOUTME: Nothing here performs I/O; resolving a spelling or reading the passwd database lives in `system`.
//! Validated value types that later modules combine into a sandbox policy.
//!
//! No constructor here performs I/O. Expanding a config spelling against the real filesystem
//! ([`crate::system::PathResolver`]) and reading the home directory from the passwd database
//! ([`HomeDir::from_environment`]) live in [`crate::system`].

pub mod argv;
pub mod ctl;
pub mod env;
pub mod home;
pub mod host;
pub mod names;
pub mod path;
pub mod pattern;
pub mod port;

pub use argv::{ArgWord, ArgWordError, Argv, ArgvError};
pub use ctl::{ContainerLabel, ContainerLabelError, ContainerName, ContainerNameError};
pub use env::{EnvName, EnvNameError, EnvValue, EnvValueError};
pub use home::{HomeDir, ProjectRoot, RootError, broadness};
pub use host::{
    HostName, HostNameError, HostPattern, HostPatternError, protected_suffix_list_version,
};
pub use names::{ExtendRef, GuardException, McpName, McpNameError, RefTextError};
pub use path::{BroadRoot, CanonicalPath, PathError};
pub use pattern::{GlobSegment, GlobTail, GlobTailError, PathPattern, PathPatternError};
pub use port::{Port, PortError};
