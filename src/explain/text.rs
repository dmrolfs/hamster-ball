// ABOUTME: Renders a Report as grouped, human-readable text: home shown as `~`, every untrusted string escaped.
// ABOUTME: Pure; layout only. Redaction already happened in the report, so nothing secret is here to leak.
//! The text renderer.
//!
//! Every value that came from a config file, a path or the environment goes through
//! [`Escaped`], so a hostile value cannot forge a line (`\n`), move the cursor (`ESC [`) or
//! reorder text (bidi controls). Home is shown as `~` for reading; the JSON renderer keeps
//! absolute paths.

use std::fmt::Write as _;

use super::report::{
    AccessRow, DenyRow, FileRow, HookRow, McpRow, OriginRow, PathQuery, Report, Row, WarningRow,
};
use crate::text::Escaped;

/// Renders `report` as text ending in a newline.
#[must_use]
pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    let t = Tilde(&report.project.home);
    // Writing to a `String` cannot fail.
    let _ = render(&mut out, report, &t);
    out
}

/// Escapes `text` and, if it could be read as the start of an origin annotation, quotes it.
///
/// Rows are `value  <- origin`; a value such as `x  <- floor:ssh` is escaped but would still
/// look like a row with an origin. Quoting it removes the doubt.
fn cell(text: &str) -> String {
    let shown = Escaped(text).to_string();
    if shown.contains("  ") || shown.contains("<-") {
        format!("\"{}\"", shown.replace('"', "\\\""))
    } else {
        shown
    }
}

/// Replaces the home prefix with `~` for display.
struct Tilde<'a>(&'a str);

impl Tilde<'_> {
    fn show(&self, path: &str) -> String {
        let shown = match path.strip_prefix(self.0) {
            Some("") => "~".to_owned(),
            Some(rest) if rest.starts_with('/') => format!("~{rest}"),
            _ => path.to_owned(),
        };
        cell(&shown)
    }
}

fn render(out: &mut String, report: &Report, t: &Tilde<'_>) -> std::fmt::Result {
    writeln!(out, "hb explain")?;
    writeln!(out, "project  {}", t.show(&report.project.root))?;
    writeln!(out, "config   {}", t.show(&report.project.config))?;

    section(
        out,
        "files (a later file takes precedence)",
        report.files.is_empty(),
    )?;
    for file in &report.files {
        writeln!(out, "  [{}] {}", file.index, file_line(file, t))?;
    }

    section(out, "fs.read", report.fs.read.is_empty())?;
    rows(out, &report.fs.read, t, |v| t.show(v))?;
    section(out, "fs.write", report.fs.write.is_empty())?;
    rows(out, &report.fs.write, t, |v| t.show(v))?;

    let config_denies = report.deny.iter().filter(|d| d.source == "config").count();
    let floor_denies = report.deny.len() - config_denies;
    writeln!(
        out,
        "\ndeny ({floor_denies} from the floor, which no config can change; {config_denies} from config)"
    )?;
    let name_width = report
        .deny
        .iter()
        .filter_map(|d| d.rule.as_deref())
        .map(|r| short_name(r).chars().count())
        .max()
        .unwrap_or(0);
    let effect_width = report
        .deny
        .iter()
        .map(|d| d.effect.len())
        .max()
        .unwrap_or(0);
    for deny in &report.deny {
        writeln!(out, "  {}", deny_line(deny, t, name_width, effect_width))?;
    }

    section(out, "net.allow", report.net.hosts.is_empty())?;
    rows(out, &report.net.hosts, t, |v| cell(v))?;
    section(
        out,
        "net.loopback_ports",
        report.net.loopback_ports.is_empty(),
    )?;
    rows(out, &report.net.loopback_ports, t, ToString::to_string)?;

    section(out, "env.pass", report.env.pass.is_empty())?;
    rows(out, &report.env.pass, t, |v| cell(v))?;
    section(out, "env.tools", report.env.tools.is_empty())?;
    for tool in &report.env.tools {
        let place = tool.dir.as_deref().map_or_else(
            || "(not found on PATH)".to_owned(),
            |dir| Escaped(dir).to_string(),
        );
        writeln!(
            out,
            "  {}  {place}  {}",
            Escaped(&tool.name),
            origins(&tool.origins, t)
        )?;
    }
    section(
        out,
        "env.set (values are never shown)",
        report.env.set.is_empty(),
    )?;
    for set in &report.env.set {
        writeln!(
            out,
            "  {}  (value hidden)  {}",
            Escaped(&set.name),
            origins(&set.origins, t)
        )?;
    }

    writeln!(out, "\ntls")?;
    writeln!(
        out,
        "  system_trust = {}  {}",
        report.tls.system_trust.value,
        origins(&report.tls.system_trust.origins, t)
    )?;
    if !report.tls.extra_ca_files.is_empty() {
        writeln!(out, "  extra_ca_files (read grants)")?;
        rows(out, &report.tls.extra_ca_files, t, |v| t.show(v))?;
    }

    section(
        out,
        "ctl",
        report.ctl.label.is_none() && report.ctl.containers.is_empty(),
    )?;
    if let Some(label) = &report.ctl.label {
        writeln!(
            out,
            "  label = {}  {}",
            Escaped(&label.value),
            origins(&label.origins, t)
        )?;
    }
    for container in &report.ctl.containers {
        writeln!(
            out,
            "  container {}  {}",
            Escaped(&container.value),
            origins(&container.origins, t)
        )?;
    }

    section(out, "mcp", report.mcp.is_empty())?;
    for server in &report.mcp {
        writeln!(out, "  {}", mcp_line(server, t))?;
    }

    section(
        out,
        "hooks (run on the host, in order)",
        report.hooks.is_empty(),
    )?;
    for hook in &report.hooks {
        writeln!(out, "  {}", hook_line(hook, t))?;
    }

    section(out, "guard.exceptions", report.guard_exceptions.is_empty())?;
    rows(out, &report.guard_exceptions, t, |v| cell(v))?;

    if let Some(query) = &report.query {
        query_section(out, query, t)?;
    }

    section(out, "warnings", report.warnings.is_empty())?;
    for warning in &report.warnings {
        writeln!(out, "  {}", warning_line(warning, t))?;
    }
    Ok(())
}

/// A blank line, the group's title, and `(none)` when empty.
fn section(out: &mut String, title: &str, empty: bool) -> std::fmt::Result {
    writeln!(out, "\n{title}")?;
    if empty {
        writeln!(out, "  (none)")?;
    }
    Ok(())
}

fn rows<T>(
    out: &mut String,
    items: &[Row<T>],
    t: &Tilde<'_>,
    show: impl Fn(&T) -> String,
) -> std::fmt::Result {
    for item in items {
        writeln!(
            out,
            "  {}  {}",
            show(&item.value),
            origins(&item.origins, t)
        )?;
    }
    Ok(())
}

fn file_line(file: &FileRow, t: &Tilde<'_>) -> String {
    let what = match (&file.name, &file.file) {
        (Some(name), None) => format!("{} (built into hb)", Escaped(name)),
        (Some(name), Some(path)) => format!("{} ({})", Escaped(name), t.show(path)),
        (None, Some(path)) => t.show(path),
        (None, None) => String::new(),
    };
    format!("{:<9} {what}  [{}]", file.layer, Escaped(&file.location))
}

fn deny_line(deny: &DenyRow, t: &Tilde<'_>, name_width: usize, effect_width: usize) -> String {
    let mut path = t.show(&deny.path);
    if let Some(tail) = &deny.tail {
        let _ = write!(path, "/{}", Escaped(tail));
    }
    if let Some(alias) = &deny.alias {
        let _ = write!(path, " (also {})", t.show(alias));
    }
    let extent = if deny.extent == "subtree" {
        String::new()
    } else {
        format!(" [{} only]", deny.extent)
    };
    match &deny.rule {
        Some(rule) => format!(
            "floor  {:<name_width$}  {:<effect_width$}  {path}{extent}  ({})",
            Escaped(short_name(rule)).to_string(),
            deny.effect,
            Escaped(deny.reason.as_deref().unwrap_or(""))
        ),
        None => format!(
            "config {:<name_width$}  {:<effect_width$}  {path}{extent}  {}",
            "",
            deny.effect,
            origins(&deny.origins, t)
        ),
    }
}

/// A floor rule's name without the path a derived rule carries (`pin:/a/b` is `pin`).
fn short_name(rule: &str) -> &str {
    rule.split(':').next().unwrap_or(rule)
}

fn mcp_line(server: &McpRow, t: &Tilde<'_>) -> String {
    let command = server.command.as_deref().unwrap_or("");
    let args = server.args.as_ref().map_or_else(
        || format!("{} args hidden", server.arg_count),
        |args| {
            args.iter()
                .map(|a| Escaped(a).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        },
    );
    let net = if server.net.is_empty() {
        String::new()
    } else {
        format!(
            "  hosts: {}",
            server
                .net
                .iter()
                .map(|h| Escaped(h).to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let bind = if server.bind_ports.is_empty() {
        String::new()
    } else {
        let ports: Vec<String> = server.bind_ports.iter().map(ToString::to_string).collect();
        format!(
            "  may listen on {} (profile-wide, not loopback-only)",
            ports.join(", ")
        )
    };
    format!(
        "{}: {} {args}{net}{bind}  {}",
        Escaped(&server.name),
        Escaped(command),
        origins(&server.origins, t)
    )
}

fn hook_line(hook: &HookRow, t: &Tilde<'_>) -> String {
    let args = hook.args.as_ref().map_or_else(
        || format!("{} args hidden", hook.arg_count),
        |args| {
            args.iter()
                .map(|a| Escaped(a).to_string())
                .collect::<Vec<_>>()
                .join(" ")
        },
    );
    format!(
        "{} {args}  {}",
        Escaped(&hook.program),
        origins(&hook.origins, t)
    )
}

fn warning_line(warning: &WarningRow, t: &Tilde<'_>) -> String {
    let at = if warning.origins.is_empty() {
        String::new()
    } else {
        format!("  {}", origins(&warning.origins, t))
    };
    format!("{}: {}{at}", warning.kind, cell(&warning.message))
}

fn query_section(out: &mut String, query: &PathQuery, t: &Tilde<'_>) -> std::fmt::Result {
    writeln!(out, "\npath {}", Escaped(&query.spelling))?;
    writeln!(out, "  resolved  {}", t.show(&query.path))?;
    for (name, access) in [
        ("read", &query.read),
        ("write", &query.write),
        ("connect", &query.connect),
    ] {
        writeln!(out, "  {name:<8}  {}", access_line(access, t))?;
    }
    writeln!(out, "  note      {}", Escaped(&query.note))
}

fn access_line(access: &AccessRow, t: &Tilde<'_>) -> String {
    let folded = if access.folded {
        " (case or Unicode variant)"
    } else {
        ""
    };
    let rule = access.rule.as_ref().map_or_else(String::new, |rule| {
        format!(" by floor rule {}", Escaped(rule))
    });
    let effect = access
        .effect
        .as_ref()
        .map_or_else(String::new, |effect| match effect.as_str() {
            "pin_unlink" => " [pin: the path itself cannot be renamed or deleted]".to_owned(),
            other => format!(" [{other}]"),
        });
    format!(
        "{}{rule}{effect}{folded}  {}",
        access.decision,
        origins(&access.origins, t)
    )
}

/// `<- [0] fs.read[1]; [2] fs.read[0]`, or `<- floor:ssh`.
fn origins(origins: &[OriginRow], t: &Tilde<'_>) -> String {
    if origins.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = origins
        .iter()
        .map(|origin| match (&origin.floor_rule, origin.file_index) {
            (Some(rule), _) => format!("floor:{}", Escaped(rule)),
            (None, Some(index)) => {
                format!("[{index}] {}", Escaped(origin.key.as_deref().unwrap_or("")))
            }
            (None, None) => match (&origin.file, &origin.key) {
                (Some(file), Some(key)) => format!("{} {}", t.show(file), Escaped(key)),
                (Some(file), None) => t.show(file),
                _ => origin.layer.clone(),
            },
        })
        .collect();
    format!("<- {}", parts.join("; "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn origin(file_index: Option<usize>, file: Option<&str>, key: Option<&str>) -> OriginRow {
        OriginRow {
            layer: "project".to_owned(),
            file_index,
            name: None,
            file: file.map(str::to_owned),
            key: key.map(str::to_owned),
            floor_rule: None,
        }
    }

    #[test]
    fn a_plain_cell_is_left_alone_and_an_ambiguous_one_is_quoted_with_inner_quotes_escaped() {
        assert_eq!(cell("plain value"), "plain value");
        assert_eq!(cell("two  spaces"), "\"two  spaces\"");
        assert_eq!(cell("looks<-like origin"), "\"looks<-like origin\"");
        assert_eq!(cell("a  \"q\""), "\"a  \\\"q\\\"\"");
        assert_eq!(cell("new\nline  x"), "\"new\\nline  x\"");
    }

    #[test]
    fn home_is_shown_as_tilde_only_at_a_path_boundary() {
        let t = Tilde("/Users/me");
        assert_eq!(t.show("/Users/me"), "~");
        assert_eq!(t.show("/Users/me/x/y"), "~/x/y");
        assert_eq!(t.show("/Users/me2/x"), "/Users/me2/x");
        assert_eq!(t.show("/elsewhere"), "/elsewhere");
    }

    #[test]
    fn origins_name_the_file_index_the_floor_rule_or_the_path() {
        let t = Tilde("/Users/me");
        assert_eq!(origins(&[], &t), "");
        assert_eq!(
            origins(&[origin(Some(2), None, Some("fs.read[1]"))], &t),
            "<- [2] fs.read[1]"
        );
        let floor = OriginRow {
            floor_rule: Some("ssh".to_owned()),
            ..origin(None, None, None)
        };
        assert_eq!(origins(&[floor], &t), "<- floor:ssh");
        assert_eq!(
            origins(
                &[origin(None, Some("/Users/me/x.toml"), Some("net.allow[0]"))],
                &t
            ),
            "<- ~/x.toml net.allow[0]"
        );
        assert_eq!(
            origins(&[origin(None, Some("/Users/me/x.toml"), None)], &t),
            "<- ~/x.toml"
        );
        assert_eq!(origins(&[origin(None, None, None)], &t), "<- project");
        assert_eq!(
            origins(
                &[
                    origin(Some(0), None, Some("a")),
                    origin(Some(1), None, Some("b"))
                ],
                &t
            ),
            "<- [0] a; [1] b"
        );
    }
}
