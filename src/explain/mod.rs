// ABOUTME: `hb explain`: every effective rule with its origin, as grouped text or stable JSON.
// ABOUTME: `explain()` is the only I/O entry; the report model and both renderers are pure.
//! `hb explain`.
//!
//! - [`build_report`] turns a loaded policy into a [`Report`] (pure; secrets are redacted here).
//! - [`render_text`] and [`render_json`] lay it out (pure; untrusted text is escaped here).
//! - [`explain`] does the work from a process [`Environment`]: discover the project, load the
//!   closure and floor, build the report, render it.
//!
//! `explain` works on a project whose config has not been approved: it is the tool you use to
//! decide whether to approve it.

mod json;
mod report;
mod text;

use std::path::Path;

use snafu::{ResultExt, Snafu};

pub use json::render_json;
pub use report::{
    AccessRow, CtlReport, DenyRow, EnvReport, EnvSetRow, FileRow, FsReport, HookRow, McpRow,
    NetReport, OriginRow, PathQuery, ProjectRow, Report, ReportOptions, Row, SCHEMA_VERSION,
    TlsReport, WarningRow, build_report,
};
pub use text::render_text;

use crate::config::{ProjectError, load_project};
use crate::policy::PathError;
use crate::system::{Environment, PathResolver};

/// How to print the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// Grouped, human-readable text.
    #[default]
    Text,
    /// Stable JSON with a `schema_version`.
    Json,
}

/// What `hb explain` was asked.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ExplainRequest<'a> {
    /// The process environment.
    pub env: &'a Environment,
    /// Text or JSON.
    pub format: Format,
    /// Show `mcp` and hook arguments instead of counting them.
    pub show_args: bool,
    /// A path to explain; relative paths are relative to the project root.
    pub path: Option<&'a str>,
}

impl<'a> ExplainRequest<'a> {
    /// A text report for `env`, with arguments hidden and no path query.
    #[must_use]
    pub fn new(env: &'a Environment) -> Self {
        Self {
            env,
            format: Format::Text,
            show_args: false,
            path: None,
        }
    }

    /// Sets the output format.
    #[must_use]
    pub fn format(mut self, format: Format) -> Self {
        self.format = format;
        self
    }

    /// Shows `mcp` and hook arguments.
    #[must_use]
    pub fn show_args(mut self, show: bool) -> Self {
        self.show_args = show;
        self
    }

    /// Explains why `path` can or cannot be reached.
    #[must_use]
    pub fn path(mut self, path: &'a str) -> Self {
        self.path = Some(path);
        self
    }
}

/// Why `hb explain` could not produce a report.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ExplainError {
    /// The project could not be found or loaded.
    #[snafu(display("the project could not be loaded"))]
    Project {
        /// The underlying error.
        source: ProjectError,
    },

    /// The path given to `--path` could not be resolved.
    #[snafu(display("the path to explain could not be resolved"))]
    Query {
        /// The underlying error.
        source: PathError,
    },

    /// JSON could not be produced.
    #[snafu(display("the report could not be written as JSON"))]
    Render {
        /// The underlying error.
        source: serde_json::Error,
    },
}

/// Discovers the project, loads it, and renders the report.
///
/// # Errors
/// See [`ExplainError`].
pub fn explain(request: &ExplainRequest<'_>) -> Result<String, ExplainError> {
    let env = request.env;
    let (discovery, loaded) = load_project(env).context(ProjectSnafu)?;

    let resolved = request
        .path
        .map(|spelling| {
            PathResolver::new(&env.home, &discovery.root)
                .deny(spelling)
                .map(|resolution| (spelling, resolution))
                .context(QuerySnafu)
        })
        .transpose()?;

    let mut options = ReportOptions::new(
        &env.home,
        discovery.root.path(),
        Path::new(&discovery.config),
    );
    options.show_args = request.show_args;
    options.xdg_state_home_set = env.xdg_state_home.is_some();
    options.path_var = env.floor.path_var.as_deref();
    options.query = resolved
        .as_ref()
        .map(|(spelling, r)| (*spelling, &r.target, r.alias.as_ref()));

    let report = build_report(&loaded, &options);
    match request.format {
        Format::Text => Ok(render_text(&report)),
        Format::Json => render_json(&report).context(RenderSnafu),
    }
}
