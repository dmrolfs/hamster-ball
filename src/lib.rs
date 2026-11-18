// ABOUTME: Library root for hamster-ball: validated policy types and the origin tracking used by every later module.
// ABOUTME: Pure types live here; filesystem access arrives in later modules (see ref/Hamster-Ball-Design.md section 14).
//! `hamster_ball` validates untrusted configuration into values that cannot describe an unsafe
//! sandbox rule by accident.
//!
//! The crate is organised so that anything that touches the filesystem is isolated, and the
//! value types in [`policy`] are pure: constructing one never performs I/O.
//!
//! # Error conventions
//!
//! Every module has its own [`snafu`] error enum. The crate-level [`Error`] wraps them with
//! `#[snafu(transparent)]`. A variant's `Display` states only what happened at that level and
//! never interpolates its `source`; callers print the chain with [`snafu::Report`]. Any
//! user-controlled text in a message is escaped (see [`text::Escaped`]).

#![forbid(unsafe_code)]

pub mod error;
pub mod origin;
pub mod policy;
pub mod text;

#[cfg(test)]
#[path = "../build/psl_gen.rs"]
mod psl_gen;

pub use error::Error;
