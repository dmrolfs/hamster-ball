// ABOUTME: The grant summary: what a project's config adds beyond the user's base config, for the approval prompt.
// ABOUTME: A value the base also gives is not an addition; every value is escaped; env.set values are shown, unlike in `hb explain`.
//! What the owner is asked to approve.

use std::fmt;

use std::path::Path;

use crate::config::{Closure, Discovery, Loaded};
use crate::explain::{OriginRow, Report, ReportOptions, Row, build_report};
use crate::system::Environment;
use crate::text::{Escaped, EscapedBounded};

/// The most characters of one value shown.
const MAX_VALUE_CHARS: usize = 300;

/// One thing the project adds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addition {
    /// The setting, such as `fs.write`.
    pub setting: &'static str,
    /// The value.
    pub value: String,
    /// The files and presets that declare it.
    pub from: String,
}

/// Everything a project's config adds beyond the base.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantSummary {
    additions: Vec<Addition>,
}

impl GrantSummary {
    /// The additions of the project `discovery` found, loaded as `loaded`.
    ///
    /// Program arguments are shown, because an MCP server's arguments decide what it runs.
    #[must_use]
    pub fn for_project(env: &Environment, discovery: &Discovery, loaded: &Loaded) -> Self {
        let mut options = ReportOptions::new(
            &env.home,
            discovery.root.path(),
            Path::new(&discovery.config),
        );
        options.show_args = true;
        options.path_var = env.floor.path_var.as_deref();
        Self::of(loaded, &build_report(loaded, &options))
    }

    /// The additions in `loaded`: every value no file of the user's base chain also gives.
    ///
    /// `report` must be built from `loaded` with `show_args` on, so program arguments are shown.
    #[must_use]
    pub fn of(loaded: &Loaded, report: &Report) -> Self {
        let mut out = Collector {
            closure: &loaded.closure,
            additions: Vec::new(),
        };
        out.rows("fs.read", &report.fs.read);
        out.rows("fs.write", &report.fs.write);
        for deny in report.deny.iter().filter(|d| d.source == "config") {
            let value = match &deny.tail {
                Some(tail) => format!("{} {}/{tail}", deny.effect, deny.path),
                None => format!("{} {}", deny.effect, deny.path),
            };
            out.add("deny", value, &deny.origins);
        }
        out.rows("net.allow", &report.net.hosts);
        out.rows("net.internal_hosts", &report.net.internal_hosts);
        out.rows("net.loopback_ports", &report.net.loopback_ports);
        out.rows("env.pass", &report.env.pass);
        for tool in &report.env.tools {
            out.add("env.tools", tool.name.clone(), &tool.origins);
        }
        out.env_set(loaded);
        out.row("tls.system_trust", &report.tls.system_trust);
        out.rows("tls.extra_ca_files", &report.tls.extra_ca_files);
        out.row("terminal.clipboard_write", &report.terminal.clipboard_write);
        out.row("system.launchctl", &report.system.launchctl);
        if let Some(label) = &report.ctl.label {
            out.row("ctl.label", label);
        }
        out.rows("ctl.containers", &report.ctl.containers);
        out.rows("ctl.launchd", &report.ctl.launchd);
        for mcp in &report.mcp {
            let mut value = format!("{} = {}", mcp.name, mcp.command.as_deref().unwrap_or("?"));
            for arg in mcp.args.iter().flatten() {
                value.push(' ');
                value.push_str(arg);
            }
            if !mcp.net.is_empty() {
                value.push_str(&format!("; net: {}", mcp.net.join(", ")));
            }
            if !mcp.warm_net.is_empty() {
                value.push_str(&format!("; warm_net: {}", mcp.warm_net.join(", ")));
            }
            if !mcp.bind_ports.is_empty() {
                let ports: Vec<String> = mcp.bind_ports.iter().map(u16::to_string).collect();
                value.push_str(&format!("; listens on: {}", ports.join(", ")));
            }
            out.add("mcp", value, &mcp.origins);
        }
        for hook in &report.hooks {
            let mut value = format!("{}: {}", hook.name, hook.program);
            for arg in hook.args.iter().flatten() {
                value.push(' ');
                value.push_str(arg);
            }
            out.add("hooks", value, &hook.origins);
        }
        out.rows("guard_exceptions", &report.guard_exceptions);
        Self {
            additions: out.additions,
        }
    }

    /// The additions, in report order.
    #[must_use]
    pub fn additions(&self) -> &[Addition] {
        &self.additions
    }

    /// Whether the project adds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.additions.is_empty()
    }
}

impl fmt::Display for GrantSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.additions.is_empty() {
            return writeln!(f, "This project adds nothing beyond your base config.");
        }
        writeln!(f, "This project adds, beyond your base config:")?;
        let width = self
            .additions
            .iter()
            .map(|a| a.setting.len())
            .max()
            .unwrap_or(0);
        for addition in &self.additions {
            writeln!(
                f,
                "  {:width$}  {}  (from {})",
                addition.setting,
                EscapedBounded::new(&addition.value, MAX_VALUE_CHARS),
                Escaped(&addition.from),
            )?;
        }
        Ok(())
    }
}

struct Collector<'a> {
    closure: &'a Closure,
    additions: Vec<Addition>,
}

impl Collector<'_> {
    /// Adds a line unless the base chain also declares the value, or nothing declares it.
    fn add(&mut self, setting: &'static str, value: String, origins: &[OriginRow]) {
        if origins.is_empty() || origins.iter().any(|o| self.in_base(o)) {
            return;
        }
        self.additions.push(Addition {
            setting,
            value,
            from: from_label(origins),
        });
    }

    fn in_base(&self, origin: &OriginRow) -> bool {
        origin
            .file_index
            .and_then(|index| self.closure.files().get(index))
            .is_none_or(|file| file.from_base)
    }

    fn rows<T: ToString>(&mut self, setting: &'static str, rows: &[Row<T>]) {
        for row in rows {
            self.row(setting, row);
        }
    }

    fn row<T: ToString>(&mut self, setting: &'static str, row: &Row<T>) {
        self.add(setting, row.value.to_string(), &row.origins);
    }

    /// `env.set` shows its values here: this is the config being reviewed, not a report to share.
    fn env_set(&mut self, loaded: &Loaded) {
        for (name, value) in &loaded.policy.env.set {
            let from: Vec<OriginRow> = value
                .sources
                .iter()
                .map(|source| {
                    let id = source.file();
                    OriginRow {
                        layer: String::new(),
                        file_index: Some(id.index()),
                        name: file_name(self.closure, id.index()),
                        file: None,
                        key: None,
                        floor_rule: None,
                    }
                })
                .collect();
            self.add(
                "env.set",
                format!("{}={}", name.as_str(), value.value.as_str()),
                &from,
            );
        }
    }
}

fn file_name(closure: &Closure, index: usize) -> Option<String> {
    use crate::config::FileSource;
    match &closure.files().get(index)?.source {
        FileSource::Builtin { name } => Some(name.to_string()),
        FileSource::Disk {
            preset: Some(name), ..
        } => Some(name.to_string()),
        FileSource::Disk { canonical, .. } => canonical
            .as_path()
            .file_name()
            .map(|n| n.to_string_lossy().into_owned()),
    }
}

/// The distinct names of the files that declare a value, in order.
fn from_label(origins: &[OriginRow]) -> String {
    let mut names: Vec<String> = Vec::new();
    for origin in origins {
        let name = origin.name.clone().or_else(|| {
            origin.file.as_deref().map(|path| {
                path.rsplit('/')
                    .next()
                    .map_or_else(|| path.to_owned(), str::to_owned)
            })
        });
        if let Some(name) = name
            && !names.contains(&name)
        {
            names.push(name);
        }
    }
    names.join(", ")
}
