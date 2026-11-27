// ABOUTME: Renders a Report as pretty JSON; the terminal-safe formatter lives in crate::safe_json.
// ABOUTME: Field order is the declaration order of the structs in report.rs, so the output is stable.
//! The JSON renderer.

use super::report::Report;

/// Renders `report` as pretty JSON ending in a newline.
///
/// # Errors
/// [`serde_json::Error`] if serialization fails, which a [`Report`] cannot cause.
pub fn render_json(report: &Report) -> Result<String, serde_json::Error> {
    crate::safe_json::to_safe_json(report)
}
