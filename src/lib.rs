// ABOUTME: Library root for hamster-ball: validated policy types, config intake and the origin tracking they share.
// ABOUTME: Value types are pure; filesystem and passwd access is confined to a few named items (see ref/Hamster-Ball-Design.md section 14).
//! `hamster_ball` validates untrusted configuration into values that cannot describe an unsafe
//! sandbox rule by accident.
//!
//! The value types in [`policy`] are pure: constructing one never performs I/O. The code that
//! does touch the system is small and named: [`system::PathResolver`],
//! [`policy::HomeDir::from_environment`] (in [`system`]), and in [`config`] the loader
//! ([`config::load`]) and [`config::discover`].
//!
//! # Error conventions
//!
//! Every module has its own [`snafu`] error enum. The crate-level [`Error`] wraps every public
//! one with `#[snafu(transparent)]`. A variant's `Display` states only what happened at that level and
//! never interpolates its `source`; callers print the chain with [`snafu::Report`]. Any
//! user-controlled text in a message is escaped (see [`text::Escaped`]).

pub mod cli;
pub mod config;
pub mod error;
pub mod explain;
pub mod origin;
pub mod policy;
pub mod seatbelt;
pub(crate) mod sys;
pub mod system;
pub mod text;

#[cfg(test)]
#[path = "../build/psl_gen.rs"]
mod psl_gen;

#[cfg(test)]
pub(crate) mod testutil;

pub use error::Error;
