// ABOUTME: Config intake and layering: read each file once, validate it, load the extends closure, merge it into a Policy.
// ABOUTME: `raw` stays private: the public views are ResolvedConfig (one file), Closure (all files, exact bytes) and Policy (merged).
//! Turns a project's `hamster-ball.toml` and everything it builds on into one validated policy.
//!
//! The entry point is [`load`]. It reads the user's base file and the project file, follows
//! every `extends` entry ([`load_closure`]), and merges the result ([`merge`]):
//!
//! 1. **Read** each file exactly once ([`ConfigText`]), with the symlink policy its role
//!    (`FileRole`) implies, and keep the bytes. M4 hashes those same bytes.
//! 2. **Admit** it: still the file the path names, not already loaded (identified by device
//!    and inode), within the file and depth caps, owned by you and not world-writable.
//! 3. **Classify** where it physically is ([`FileLocation`]); only the user's own files and
//!    built-ins may define `hooks` or `guard.exceptions`, and a file that may not is refused
//!    before any of its paths are touched.
//! 4. **Resolve** its entries into validated values ([`resolve_file`]).
//! 5. **Merge** into a [`Policy`]: lists union, keyed values must agree, scalars never
//!    loosen, and every deny from every file is kept. [`Policy::decide`] is the advisory
//!    deny-wins query; Seatbelt rule order is the enforcement.
//!
//! The pure pieces ([`classify`], [`merge`], [`Policy::decide`]) do no I/O; the loader does.

mod builtin;
mod closure;
mod decision;
mod discover;
mod extends;
mod location;
mod merge;
mod raw;
mod resolve;
mod text;

pub use crate::policy::FsAccess;
pub use builtin::{BuiltinPresets, EmbeddedPresets, StaticPresets};
pub use closure::{
    Closure, ClosureFile, FileSource, LoadError, LoadRequest, Loaded, MAX_CLOSURE_FILES,
    MAX_EXTENDS_DEPTH, MAX_EXTENDS_PER_FILE, load, load_closure,
};
pub use decision::FsDecision;
pub use discover::{DiscoverError, Discovery, Subject, Untrusted, discover};
pub use extends::ExtendsError;
pub use location::{FileLocation, classify};
pub use merge::{
    MAX_MERGE_ERRORS, MergeError, MergeErrors, MergedCtl, MergedEnv, MergedFs, MergedNet,
    MergedTls, Policy, merge,
};
pub use resolve::{
    Diagnostics, EntryError, Indexed, ResolveContext, ResolveErrors, Resolved, ResolvedConfig,
    ResolvedCtl, ResolvedEnv, ResolvedFs, ResolvedGuard, ResolvedMcpServer, ResolvedNet,
    ResolvedTls, resolve_file,
};
#[cfg(test)]
pub(crate) use text::SymlinkPolicy;
pub use text::{ConfigText, ConfigTextError, FileIdentity, MAX_CONFIG_BYTES};
