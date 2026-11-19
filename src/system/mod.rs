// ABOUTME: The parts of the crate that consult the operating system: filesystem resolution and the passwd database.
// ABOUTME: Everything here is I/O; the pure value types these build live in `policy`.
//! Operating-system access.
//!
//! [`PathResolver`] expands a config spelling against the real filesystem, and
//! [`HomeDir::from_environment`](crate::policy::HomeDir::from_environment) reads the passwd database and `$HOME`. The value types they
//! produce ([`crate::policy::CanonicalPath`], [`crate::policy::HomeDir`], ...) are pure and live
//! in [`crate::policy`]. Config-file reading ([`crate::config::ConfigText`]) and project
//! discovery ([`crate::config::discover`]) are the other I/O, and live with the config model.

pub mod home;
pub mod resolver;
pub mod userdir;

pub use home::HomeError;
pub use resolver::{AllowOutcome, DenyResolution, PathResolver, SkipReason, SkippedPath};
pub use userdir::{BASE_TEMPLATE, UserConfigDir, UserConfigError};
