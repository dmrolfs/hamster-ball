// ABOUTME: The secrets guard: name patterns, the host-side scan that pins secret directories, git-tracked files, doctor.
// ABOUTME: The profile rules come from `seatbelt`; this module decides what they cover and supplies their inputs.
//! The secrets guard (design section 8).

pub mod doctor;
pub mod patterns;
pub mod prepare;
pub mod repos;
pub mod scan;
pub mod tracked;

pub use prepare::{GuardNote, Prepared, prepare};
pub use tracked::SYSTEM_GIT;

use crate::policy::CanonicalPath;

/// What the host-side preparation adds to the profile (see [`scan`] and [`tracked`]).
///
/// The default, all empty and no exemption, is the strict guard: nothing is re-allowed below a
/// dependency directory.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GuardInputs {
    /// Directories pinned against rename and delete because they hold, or sit above, a guarded file.
    pub pins: Vec<CanonicalPath>,
    /// Whether key and secret-named files below `node_modules` and `site-packages` are re-allowed.
    /// Only sound together with `pins` from a complete scan.
    pub dependency_exemption: bool,
}
