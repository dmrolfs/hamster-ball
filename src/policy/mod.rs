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
pub mod extends;
pub mod floor;
pub mod home;
pub mod host;
pub mod names;
pub mod path;
pub mod pattern;
pub mod port;

pub use argv::{ArgWord, ArgWordError, Argv, ArgvError};
pub use ctl::{ContainerLabel, ContainerLabelError, ContainerName, ContainerNameError};
pub use env::{
    EnvName, EnvNameError, EnvValue, EnvValueError, MAX_TOOL_NAME_BYTES, ToolName, ToolNameError,
};
pub use extends::{
    ExtendTarget, ExtendTargetError, MAX_PRESET_NAME_BYTES, PresetName, PresetNameError,
};
pub use floor::{
    Floor, FloorEffect, FloorGroup, FloorHit, FloorRule, FloorRuleId, FloorTooLarge, FsAccess,
    GitdirError, GitdirPointer, MAX_FLOOR_RULES, MAX_GITDIR_POINTER_BYTES, MAX_PATH_ENTRIES,
    MAX_PATH_VAR_BYTES, PathEntries, PathEntryProblem, PathVarError, SkippedPathEntry,
    parse_commondir, parse_gitdir_pointer, parse_path_var,
};
pub use home::{HomeDir, ProjectRoot, RootError, broadness};
pub use host::{
    HostName, HostNameError, HostPattern, HostPatternError, protected_suffix_list_version,
};
pub use names::{ExtendRef, GuardException, McpName, McpNameError, RefTextError};
pub use path::{BroadRoot, CanonicalPath, PathError};
pub use pattern::{
    Coverage, Extent, GlobSegment, GlobTail, GlobTailError, PathPattern, PathPatternError,
};
pub use port::{BindPort, Port, PortError};
