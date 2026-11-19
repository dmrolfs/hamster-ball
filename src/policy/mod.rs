// ABOUTME: Pure policy value types: paths, home and project root, ports, environment names, container names.
// ABOUTME: Constructing any of these performs no I/O; each constructor validates form and rejects unsafe values.
//! Validated value types that later modules combine into a sandbox policy.

pub mod ctl;
pub mod env;
pub mod home;
pub mod host;
pub mod path;
pub mod port;
pub mod resolve;

pub use ctl::{ContainerName, ContainerNameError};
pub use env::{EnvName, EnvNameError, EnvValue, EnvValueError};
pub use home::{BroadRoot, HomeDir, ProjectRoot, RootError, broadness};
pub use host::{
    HostName, HostNameError, HostPattern, HostPatternError, protected_suffix_list_version,
};
pub use path::{CanonicalPath, PathError};
pub use port::{Port, PortError};
pub use resolve::{
    AllowOutcome, DenyResolution, GlobSegment, GlobTail, GlobTailError, PathPattern,
    PathPatternError, PathResolver, SkipReason, SkippedPath,
};
