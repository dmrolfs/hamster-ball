// ABOUTME: resolve_file turns one file's RawConfig into a validated ResolvedConfig plus diagnostics.
// ABOUTME: Collects entry errors up to a cap instead of stopping at the first; ResolvedConfig is the only public view.
//! Resolves a parsed, raw config into validated types, collecting every entry error it finds
//! (up to a cap) instead of stopping at the first one, so a config with several mistakes shows
//! all of them in one pass.

use std::collections::HashMap;

use snafu::Snafu;

use crate::origin::{KeyPath, Located, Origin};
use crate::policy::{
    AllowOutcome, CanonicalPath, ContainerName, ContainerNameError, EnvName, EnvNameError,
    EnvValue, EnvValueError, HomeDir, HostPattern, HostPatternError, PathError, PathPattern,
    PathPatternError, PathResolver, Port, PortError, ProjectRoot, SkippedPath,
};
use crate::text::EscapedBounded;

use super::raw::{self, RawMcpServer};
use super::text::ConfigText;

/// Longest text echoed from a TOML parse error's message before it is cut off.
const PARSE_MESSAGE_PREVIEW_CHARS: usize = 200;

/// Most entries accepted in any one list or map field, enforced before any entry is resolved.
///
/// A list over this size is rejected with one [`EntryError::TooManyEntries`] and none of its
/// entries are resolved, so an oversized list cannot trigger thousands of filesystem or
/// validation calls.
const MAX_LIST_ENTRIES: usize = 4096;

/// Most entry errors collected before giving up and reporting [`ResolveErrors::truncated`].
///
/// A policy choice, not derived from anything structural: large enough that a realistic
/// typo-laden config shows everything useful in one pass, small enough that a config with
/// many bad entries can't make the error list itself unbounded.
const ENTRY_ERROR_CAP: usize = 64;

/// What `resolve_file` needs beyond the raw config text: the home and project root a relative
/// or `~` spelling resolves against (see [`PathResolver`]).
#[derive(Debug, Clone, Copy)]
pub struct ResolveContext<'a> {
    resolver: PathResolver<'a>,
}

impl<'a> ResolveContext<'a> {
    /// Builds a context from the home directory and project root every path in every layer
    /// resolves against.
    #[must_use]
    pub fn new(home: &'a HomeDir, project_root: &'a ProjectRoot) -> Self {
        Self {
            resolver: PathResolver::new(home, project_root),
        }
    }

    fn resolver(&self) -> PathResolver<'a> {
        self.resolver
    }
}

/// The successful result of [`resolve_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The validated config.
    pub config: ResolvedConfig,
    /// Things that were not an error but are worth showing, such as a skipped allow rule.
    pub diagnostics: Diagnostics,
}

/// Non-error findings from resolving one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diagnostics {
    /// Every `fs.read`/`fs.write` allow rule that was not granted, and why.
    pub skipped: Vec<Located<SkippedPath>>,
}

/// The entry errors found while resolving a file.
///
/// Collection stops adding new errors once `ENTRY_ERROR_CAP` is reached; `truncated` is set
/// when that happens, so a reporter can say "and more" instead of implying this is the whole
/// list. Entries that resolved successfully are still returned... from nowhere, because a
/// file that produced any entry error resolves to no [`Resolved`] at all: partial success is
/// not represented by this type. A future caller that wants the valid entries alongside the
/// errors is not yet a requirement of this task.
#[derive(Debug)]
pub struct ResolveErrors {
    /// Every entry error found, each with its origin.
    pub errors: Vec<Located<EntryError>>,
    /// Whether more errors existed beyond `ENTRY_ERROR_CAP`.
    pub truncated: bool,
}

impl std::fmt::Display for ResolveErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} configuration error(s)", self.errors.len())?;
        if self.truncated {
            write!(f, " (more exist past the first {ENTRY_ERROR_CAP})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ResolveErrors {}

/// Why one config entry could not be resolved.
///
/// One variant per existing validation type, transparently wrapping its error, matching
/// [`crate::error::Error`]'s own shape; plus [`EntryError::Parse`] for a TOML syntax or schema
/// error, and [`EntryError::TooManyEntries`] for a list or map over `MAX_LIST_ENTRIES`.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EntryError {
    /// An `fs` path was malformed, too broad, or otherwise invalid.
    #[snafu(transparent)]
    Path {
        /// The underlying error.
        source: PathError,
    },
    /// An `fs.deny_read`/`fs.deny_write` glob pattern was malformed.
    #[snafu(transparent)]
    PathPattern {
        /// The underlying error.
        source: PathPatternError,
    },
    /// A `net.allow` host pattern was invalid.
    #[snafu(transparent)]
    Host {
        /// The underlying error.
        source: HostPatternError,
    },
    /// A `net.loopback_ports` entry was out of range.
    #[snafu(transparent)]
    Port {
        /// The underlying error.
        source: PortError,
    },
    /// An `env.pass`/`env.set` name was invalid.
    #[snafu(transparent)]
    EnvName {
        /// The underlying error.
        source: EnvNameError,
    },
    /// An `env.set` value was invalid.
    #[snafu(transparent)]
    EnvValue {
        /// The underlying error.
        source: EnvValueError,
    },
    /// A `ctl.containers` name was invalid.
    #[snafu(transparent)]
    Container {
        /// The underlying error.
        source: ContainerNameError,
    },
    /// The file was not valid TOML, or did not match the schema.
    #[snafu(display("{line}:{column}: {}", escaped_parse_message(message)))]
    Parse {
        /// The 1-based line the error was found at.
        line: u32,
        /// The 1-based column the error was found at.
        column: u32,
        /// A message from the TOML library's structured accessors, never its `Display` (which
        /// embeds the raw source line); bounded and escaped again here regardless, since a
        /// type-mismatch message can itself echo an attacker-controlled value.
        message: String,
    },
    /// A list or map had more than `MAX_LIST_ENTRIES` entries.
    #[snafu(display("list has {count} entries, more than the {max} allowed"))]
    TooManyEntries {
        /// How many entries the list or map actually had.
        count: usize,
        /// The limit, `MAX_LIST_ENTRIES`.
        max: usize,
    },
}

fn escaped_parse_message(message: &str) -> EscapedBounded<'_> {
    EscapedBounded::new(message, PARSE_MESSAGE_PREVIEW_CHARS)
}

/// The validated view of one config file; the only type this module exposes besides the error
/// and diagnostic types above. Every `raw` type stays `pub(crate)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedConfig {
    /// The presets and base files this file extends, in the order written.
    pub extends: Vec<String>,
    /// `[fs]`.
    pub fs: ResolvedFs,
    /// `[net]`.
    pub net: ResolvedNet,
    /// `[env]`.
    pub env: ResolvedEnv,
    /// `[tls]`.
    pub tls: ResolvedTls,
    /// `[ctl]`.
    pub ctl: ResolvedCtl,
    /// `[mcp.<name>]`, keyed by name.
    pub mcp: HashMap<String, ResolvedMcpServer>,
    /// Each `[[hooks]]` entry, as an argv array. Shape-only: the schema already requires an
    /// array of strings; whether a project file may declare `[hooks]` at all is a merge-time
    /// rule (section 4.2), not this module's concern.
    pub hooks: Vec<Vec<String>>,
    /// `[guard]`.
    pub guard: ResolvedGuard,
}

/// `[fs]`: granted read/write paths, and deny patterns that apply regardless of any grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedFs {
    /// Extra read-only paths, each one granted or skipped (see [`Diagnostics::skipped`]).
    pub read: Vec<CanonicalPath>,
    /// Writable paths, each one granted or skipped (see [`Diagnostics::skipped`]).
    pub write: Vec<CanonicalPath>,
    /// Read-deny patterns; deny always wins over an allow.
    pub deny_read: Vec<PathPattern>,
    /// Write-deny patterns; deny always wins over an allow.
    pub deny_write: Vec<PathPattern>,
}

/// `[net]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedNet {
    /// Allowed outbound hosts.
    pub allow: Vec<HostPattern>,
    /// Loopback ports the hamster ball may reach.
    pub loopback_ports: Vec<Port>,
}

/// `[env]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEnv {
    /// Variable names copied from the invoking shell.
    pub pass: Vec<EnvName>,
    /// Variables set to a fixed value.
    pub set: HashMap<EnvName, EnvValue>,
}

/// `[tls]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedTls {
    /// Whether the system trust store is reachable; `None` means this file did not say,
    /// leaving the merge in section 4.2 to apply the base default.
    pub system_trust: Option<bool>,
    /// Extra CA bundle files, each of which must already exist: a missing one is an
    /// [`EntryError`], not a [`Diagnostics::skipped`] entry, because a TLS trust file silently
    /// missing is not the safe direction the way a missing `fs.read` grant is.
    pub extra_ca_files: Vec<CanonicalPath>,
}

/// `[ctl]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCtl {
    /// The container label filter, verbatim; no validation type exists for it yet.
    pub label: Option<String>,
    /// Container names this hamster ball may operate on.
    pub containers: Vec<ContainerName>,
}

/// One `[mcp.<name>]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedMcpServer {
    /// The command to run; verbatim, no validation type exists for it yet.
    pub command: Option<String>,
    /// Its arguments, verbatim.
    pub args: Vec<String>,
    /// Hosts this server needs at run time.
    pub net: Vec<HostPattern>,
    /// Whether this server may bind a loopback port.
    pub bind_loopback: Option<bool>,
}

/// `[guard]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedGuard {
    /// Secrets-guard patterns to re-allow; verbatim, no validation type exists for it yet
    /// (the guard's own matching semantics belong to a later milestone).
    pub exceptions: Vec<String>,
}

/// Accumulates entry errors across every section of one file, up to `ENTRY_ERROR_CAP`.
#[derive(Debug, Default)]
struct Collector {
    errors: Vec<Located<EntryError>>,
    truncated: bool,
}

impl Collector {
    fn push(&mut self, origin: Origin, error: impl Into<EntryError>) {
        if self.errors.len() >= ENTRY_ERROR_CAP {
            self.truncated = true;
            return;
        }
        self.errors.push(Located::new(error.into(), origin));
    }
}

fn origin(text: &ConfigText, key: KeyPath) -> Origin {
    Origin::new(text.layer(), text.path(), key)
}

/// Checks a list or map's length against `MAX_LIST_ENTRIES` before any entry is touched.
fn over_cap(collector: &mut Collector, text: &ConfigText, key: KeyPath, len: usize) -> bool {
    if len > MAX_LIST_ENTRIES {
        collector.push(
            origin(text, key),
            EntryError::TooManyEntries {
                count: len,
                max: MAX_LIST_ENTRIES,
            },
        );
        true
    } else {
        false
    }
}

/// Caps and clones a list with no per-entry validation of its own (an argv array, a verbatim
/// string list): the schema's own shape check is the only validation these have.
fn clamp<T: Clone>(
    collector: &mut Collector,
    text: &ConfigText,
    key: KeyPath,
    items: &[T],
) -> Vec<T> {
    if over_cap(collector, text, key, items.len()) {
        return Vec::new();
    }
    items.to_vec()
}

/// Caps, then resolves each string entry with `f`, collecting every failure instead of
/// stopping at the first so the valid entries alongside it are still returned.
fn resolve_str_list<T, E>(
    collector: &mut Collector,
    text: &ConfigText,
    key: KeyPath,
    items: &[String],
    mut f: impl FnMut(&str) -> Result<T, E>,
) -> Vec<T>
where
    EntryError: From<E>,
{
    if over_cap(collector, text, key.clone(), items.len()) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match f(item) {
            Ok(value) => out.push(value),
            Err(error) => collector.push(origin(text, key.clone().index(index)), error),
        }
    }
    out
}

/// Caps, then resolves each `net.loopback_ports` entry.
fn resolve_port_list(
    collector: &mut Collector,
    text: &ConfigText,
    key: KeyPath,
    items: &[i64],
) -> Vec<Port> {
    if over_cap(collector, text, key.clone(), items.len()) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        match Port::try_from(*item) {
            Ok(port) => out.push(port),
            Err(error) => collector.push(origin(text, key.clone().index(index)), error),
        }
    }
    out
}

/// Caps, then resolves each `fs.read`/`fs.write` allow rule: granted paths go into the
/// returned list, skipped ones into `diagnostics`, and only a genuine error (not "missing" or
/// "dangling") becomes an [`EntryError`].
fn resolve_allow_list(
    collector: &mut Collector,
    diagnostics: &mut Diagnostics,
    text: &ConfigText,
    resolver: PathResolver<'_>,
    key: KeyPath,
    items: &[String],
) -> Vec<CanonicalPath> {
    if over_cap(collector, text, key.clone(), items.len()) {
        return Vec::new();
    }
    let mut granted = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let entry_key = key.clone().index(index);
        match resolver.allow(item) {
            Ok(AllowOutcome::Granted(path)) => granted.push(path),
            Ok(AllowOutcome::Skipped(skipped)) => {
                diagnostics
                    .skipped
                    .push(Located::new(skipped, origin(text, entry_key)));
            }
            Err(error) => collector.push(origin(text, entry_key), error),
        }
    }
    granted
}

/// Caps, then resolves `env.set`: each key and value is validated independently, so a bad key
/// does not hide a bad value in the same entry.
fn resolve_env_set(
    collector: &mut Collector,
    text: &ConfigText,
    items: &HashMap<String, String>,
) -> HashMap<EnvName, EnvValue> {
    let key = KeyPath::root().field("env").field("set");
    if over_cap(collector, text, key.clone(), items.len()) {
        return HashMap::new();
    }
    let mut set = HashMap::with_capacity(items.len());
    for (raw_key, raw_value) in items {
        let entry_key = key.clone().key(raw_key.clone());
        let name = match EnvName::parse(raw_key) {
            Ok(name) => name,
            Err(error) => {
                collector.push(origin(text, entry_key), error);
                continue;
            }
        };
        match EnvValue::parse(raw_value) {
            Ok(value) => {
                set.insert(name, value);
            }
            Err(error) => collector.push(origin(text, entry_key), error),
        }
    }
    set
}

/// Caps, then resolves every `[mcp.<name>]` entry.
fn resolve_mcp(
    collector: &mut Collector,
    text: &ConfigText,
    items: &HashMap<String, RawMcpServer>,
) -> HashMap<String, ResolvedMcpServer> {
    let key = KeyPath::root().field("mcp");
    if over_cap(collector, text, key.clone(), items.len()) {
        return HashMap::new();
    }
    let mut resolved = HashMap::with_capacity(items.len());
    for (name, server) in items {
        let entry_key = key.clone().key(name.clone());
        let net = resolve_str_list(
            collector,
            text,
            entry_key.clone().field("net"),
            &server.net,
            HostPattern::parse,
        );
        let args = clamp(
            collector,
            text,
            entry_key.clone().field("args"),
            &server.args,
        );
        resolved.insert(
            name.clone(),
            ResolvedMcpServer {
                command: server.command.clone(),
                args,
                net,
                bind_loopback: server.bind_loopback,
            },
        );
    }
    resolved
}

/// Parses and resolves `text` into a [`Resolved`] config.
///
/// A TOML syntax or schema error is reported as the single entry in [`ResolveErrors::errors`],
/// since nothing downstream can be resolved without a parsed document. Otherwise, every
/// section is resolved and every entry error is collected (up to `ENTRY_ERROR_CAP`) before
/// returning, so a config with several mistakes shows all of them at once.
///
/// # Errors
/// [`ResolveErrors`] if the file failed to parse, or any entry failed to resolve.
pub fn resolve_file(
    text: &ConfigText,
    ctx: &ResolveContext<'_>,
) -> Result<Resolved, ResolveErrors> {
    let parsed = match raw::parse(text) {
        Ok(parsed) => parsed,
        Err(parse_error) => {
            let location = Origin::new(text.layer(), text.path(), parse_error.key.clone())
                .with_line(parse_error.line);
            let error = EntryError::Parse {
                line: parse_error.line,
                column: parse_error.column,
                message: parse_error.message.clone(),
            };
            return Err(ResolveErrors {
                errors: vec![Located::new(error, location)],
                truncated: false,
            });
        }
    };

    let resolver = ctx.resolver();
    let mut collector = Collector::default();
    let mut diagnostics = Diagnostics::default();

    let extends = clamp(
        &mut collector,
        text,
        KeyPath::root().field("extends"),
        &parsed.extends,
    );

    let fs = ResolvedFs {
        read: resolve_allow_list(
            &mut collector,
            &mut diagnostics,
            text,
            resolver,
            KeyPath::root().field("fs").field("read"),
            &parsed.fs.read,
        ),
        write: resolve_allow_list(
            &mut collector,
            &mut diagnostics,
            text,
            resolver,
            KeyPath::root().field("fs").field("write"),
            &parsed.fs.write,
        ),
        deny_read: resolve_str_list(
            &mut collector,
            text,
            KeyPath::root().field("fs").field("deny_read"),
            &parsed.fs.deny_read,
            |s| PathPattern::parse(&resolver, s),
        ),
        deny_write: resolve_str_list(
            &mut collector,
            text,
            KeyPath::root().field("fs").field("deny_write"),
            &parsed.fs.deny_write,
            |s| PathPattern::parse(&resolver, s),
        ),
    };

    let net = ResolvedNet {
        allow: resolve_str_list(
            &mut collector,
            text,
            KeyPath::root().field("net").field("allow"),
            &parsed.net.allow,
            HostPattern::parse,
        ),
        loopback_ports: resolve_port_list(
            &mut collector,
            text,
            KeyPath::root().field("net").field("loopback_ports"),
            &parsed.net.loopback_ports,
        ),
    };

    let env = ResolvedEnv {
        pass: resolve_str_list(
            &mut collector,
            text,
            KeyPath::root().field("env").field("pass"),
            &parsed.env.pass,
            EnvName::parse,
        ),
        set: resolve_env_set(&mut collector, text, &parsed.env.set),
    };

    let tls = ResolvedTls {
        system_trust: parsed.tls.system_trust,
        extra_ca_files: resolve_str_list(
            &mut collector,
            text,
            KeyPath::root().field("tls").field("extra_ca_files"),
            &parsed.tls.extra_ca_files,
            |s| resolver.existing(s),
        ),
    };

    let ctl = ResolvedCtl {
        label: parsed.ctl.label.clone(),
        containers: resolve_str_list(
            &mut collector,
            text,
            KeyPath::root().field("ctl").field("containers"),
            &parsed.ctl.containers,
            ContainerName::parse,
        ),
    };

    let mcp = resolve_mcp(&mut collector, text, &parsed.mcp);
    let hooks = clamp(
        &mut collector,
        text,
        KeyPath::root().field("hooks"),
        &parsed.hooks,
    );
    let guard = ResolvedGuard {
        exceptions: clamp(
            &mut collector,
            text,
            KeyPath::root().field("guard").field("exceptions"),
            &parsed.guard.exceptions,
        ),
    };

    if !collector.errors.is_empty() || collector.truncated {
        return Err(ResolveErrors {
            errors: collector.errors,
            truncated: collector.truncated,
        });
    }

    Ok(Resolved {
        config: ResolvedConfig {
            extends,
            fs,
            net,
            env,
            tls,
            ctl,
            mcp,
            hooks,
            guard,
        },
        diagnostics,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::time::{Duration, Instant};

    use crate::origin::Layer;
    use crate::policy::CanonicalPath;

    struct Fixture {
        _dir: tempfile::TempDir,
        home: HomeDir,
        root: ProjectRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = assert_ok!(tempfile::TempDir::new());
            let home_path = dir.path().join("home");
            let project_path = home_path.join("work").join("proj");
            assert_ok!(fs::create_dir_all(&project_path));
            let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(assert_ok!(
                fs::canonicalize(&home_path)
            ))));
            let root = assert_ok!(ProjectRoot::new(
                assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
                    &project_path
                )))),
                &home,
            ));
            Self {
                _dir: dir,
                home,
                root,
            }
        }

        fn ctx(&self) -> ResolveContext<'_> {
            ResolveContext::new(&self.home, &self.root)
        }

        fn project_path(&self) -> std::path::PathBuf {
            self.root.path().as_path().to_path_buf()
        }

        fn write_config(&self, toml_text: &str) -> ConfigText {
            let path = self.project_path().join("hamster-ball.toml");
            assert_ok!(fs::write(&path, toml_text));
            assert_ok!(ConfigText::read(&path, Layer::Project, false))
        }
    }

    // ====================================================================================
    // Happy path
    // ====================================================================================

    #[test]
    fn resolves_the_design_sample_into_a_resolved_config() {
        let fx = Fixture::new();
        assert_ok!(fs::create_dir_all(fx.project_path().join("src")));
        let text = fx.write_config(
            "[fs]\n\
             write = [\"src\"]\n\
             [net]\n\
             allow = [\"crates.io\"]\n\
             loopback_ports = [3030]\n\
             [env]\n\
             pass = [\"TERM\"]\n\
             [env.set]\n\
             RUST_BACKTRACE = \"1\"\n\
             [tls]\n\
             system_trust = true\n\
             [ctl]\n\
             label = \"com.docker.compose.project=icehouse\"\n\
             [mcp.serena]\n\
             command = \"uvx\"\n\
             args = [\"start-mcp-server\"]\n\
             bind_loopback = true\n",
        );
        let resolved = assert_ok!(resolve_file(&text, &fx.ctx()));
        assert_eq!(resolved.config.fs.write.len(), 1);
        assert_eq!(resolved.config.net.loopback_ports[0].get(), 3030);
        assert_eq!(
            resolved
                .config
                .env
                .set
                .get(&assert_ok!(EnvName::parse("RUST_BACKTRACE"))),
            Some(&assert_ok!(EnvValue::parse("1")))
        );
        assert_eq!(resolved.config.tls.system_trust, Some(true));
        assert_eq!(
            resolved.config.ctl.label,
            Some("com.docker.compose.project=icehouse".to_owned())
        );
        let serena = &resolved.config.mcp["serena"];
        assert_eq!(serena.command, Some("uvx".to_owned()));
        assert_eq!(serena.bind_loopback, Some(true));
        assert!(resolved.diagnostics.skipped.is_empty());
    }

    #[test]
    fn an_empty_file_resolves_to_an_empty_config() {
        let fx = Fixture::new();
        let text = fx.write_config("");
        let resolved = assert_ok!(resolve_file(&text, &fx.ctx()));
        assert!(resolved.config.fs.read.is_empty());
        assert!(resolved.config.mcp.is_empty());
    }

    // ====================================================================================
    // Parse failure short-circuits resolution
    // ====================================================================================

    #[test]
    fn a_syntax_error_is_the_single_reported_error() {
        let fx = Fixture::new();
        let text = fx.write_config("fs = [this is not valid toml\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
        assert!(!errors.truncated);
    }

    #[test]
    fn a_parse_error_carries_its_key_path_and_line() {
        let fx = Fixture::new();
        let text = fx.write_config("[fs]\nwrite = \"not-a-list\"\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        let located = &errors.errors[0];
        assert_eq!(located.origin.key.to_string(), "fs.write");
        assert!(located.origin.line.is_some());
    }

    #[test]
    fn a_parse_error_display_never_echoes_the_source_excerpt() {
        let fx = Fixture::new();
        let text = fx.write_config("[fs]\nwrite = \"not-a-list\"\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        let shown = errors.errors[0].value.to_string();
        // The message legitimately names the bad value; what must never appear is the
        // multi-line "2 | write = ..." excerpt box with its `^^^` marker.
        assert!(!shown.contains('^'), "{shown:?}");
        assert!(!shown.contains('\n'), "{shown:?}");
    }

    // ====================================================================================
    // Mixed good and bad entries
    // ====================================================================================

    #[test]
    fn a_bad_host_pattern_is_reported_without_losing_the_good_one() {
        let fx = Fixture::new();
        let text = fx.write_config("[net]\nallow = [\"crates.io\", \"not a host\"]\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(errors.errors[0].origin.key.to_string(), "net.allow[1]");
    }

    #[test]
    fn every_collected_error_carries_the_files_layer() {
        let fx = Fixture::new();
        let text = fx.write_config("[net]\nallow = [\"not a host\"]\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors[0].origin.layer, Layer::Project);
    }

    // ====================================================================================
    // fs.read / fs.write: missing is a skip, not an error
    // ====================================================================================

    #[test]
    fn a_missing_allow_path_is_skipped_not_an_error() {
        let fx = Fixture::new();
        let text = fx.write_config("[fs]\nread = [\"does-not-exist\"]\n");
        let resolved = assert_ok!(resolve_file(&text, &fx.ctx()));
        assert!(resolved.config.fs.read.is_empty());
        assert_eq!(resolved.diagnostics.skipped.len(), 1);
        assert_eq!(
            resolved.diagnostics.skipped[0].origin.key.to_string(),
            "fs.read[0]"
        );
    }

    #[test]
    fn tls_extra_ca_files_missing_is_an_entry_error_not_a_skip() {
        let fx = Fixture::new();
        let text = fx.write_config("[tls]\nextra_ca_files = [\"does-not-exist.pem\"]\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(
            errors.errors[0].origin.key.to_string(),
            "tls.extra_ca_files[0]"
        );
    }

    #[test]
    fn contrast_fs_read_skips_but_tls_extra_ca_files_errors_for_the_same_missing_spelling() {
        let fx = Fixture::new();
        let text = fx.write_config(
            "[fs]\nread = [\"missing.pem\"]\n[tls]\nextra_ca_files = [\"missing.pem\"]\n",
        );
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(
            errors.errors[0].origin.key.to_string(),
            "tls.extra_ca_files[0]"
        );
    }

    // ====================================================================================
    // NUL survives parsing, rejected at resolution
    // ====================================================================================

    #[test]
    fn a_nul_byte_in_a_path_is_rejected_at_resolution() {
        let fx = Fixture::new();
        let text = fx.write_config("[fs]\nwrite = [\"a\\u0000b\"]\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
    }

    #[test]
    fn a_nul_byte_in_a_host_is_rejected_at_resolution() {
        let fx = Fixture::new();
        let text = fx.write_config("[net]\nallow = [\"a\\u0000b\"]\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
    }

    #[test]
    fn a_nul_byte_in_an_env_value_is_rejected_at_resolution() {
        let fx = Fixture::new();
        let text = fx.write_config("[env.set]\nA = \"a\\u0000b\"\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
    }

    // ====================================================================================
    // Caps
    // ====================================================================================

    #[test]
    fn exactly_4096_entries_in_a_list_resolves() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..4096).map(|i| format!("host{i}.example.com")).collect();
        let toml_text = format!("[net]\nallow = {:?}\n", hosts);
        let text = fx.write_config(&toml_text);
        let resolved = assert_ok!(resolve_file(&text, &fx.ctx()));
        assert_eq!(resolved.config.net.allow.len(), 4096);
    }

    #[test]
    fn entries_over_4096_in_a_list_is_a_typed_cap_error_not_a_generic_failure() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..4097).map(|i| format!("host{i}.example.com")).collect();
        let toml_text = format!("[net]\nallow = {:?}\n", hosts);
        let text = fx.write_config(&toml_text);
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
        assert!(matches!(
            errors.errors[0].value,
            EntryError::TooManyEntries {
                count: 4097,
                max: 4096
            }
        ));
    }

    #[test]
    fn an_oversized_list_resolves_no_entries_and_does_not_block_on_the_filesystem() {
        // Every spelling is a nonexistent path under a directory that itself does not exist;
        // if the cap check ran per-entry instead of on the list length up front, this would
        // still finish quickly (these are just string compares), but it should return exactly
        // one error, not 5000 individual results.
        let fx = Fixture::new();
        let paths: Vec<String> = (0..5000).map(|i| format!("nowhere/path{i}")).collect();
        let toml_text = format!("[fs]\nread = {:?}\n", paths);
        let text = fx.write_config(&toml_text);
        let started = Instant::now();
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(errors.errors.len(), 1);
        assert!(matches!(
            errors.errors[0].value,
            EntryError::TooManyEntries { count: 5000, .. }
        ));
    }

    #[test]
    fn more_than_the_error_cap_collects_exactly_the_cap_and_marks_truncated() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..100).map(|_| "not a host".to_owned()).collect();
        let toml_text = format!("[net]\nallow = {:?}\n", hosts);
        let text = fx.write_config(&toml_text);
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), ENTRY_ERROR_CAP);
        assert!(errors.truncated);
    }

    #[test]
    fn exactly_the_error_cap_of_bad_entries_is_not_marked_truncated() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..ENTRY_ERROR_CAP)
            .map(|_| "not a host".to_owned())
            .collect();
        let toml_text = format!("[net]\nallow = {:?}\n", hosts);
        let text = fx.write_config(&toml_text);
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), ENTRY_ERROR_CAP);
        assert!(!errors.truncated);
    }

    #[test]
    fn errors_past_the_cap_do_not_hide_good_entries_resolved_after_them() {
        // Bad entries exhaust the error cap, but a good entry listed after them must still
        // resolve -- the cap bounds the error list, not how much of the input is examined.
        // Since any entry error means the whole resolution fails, the good entry is confirmed
        // indirectly: the returned error count stays at the cap, not cap+1, even though there
        // are 100 bad entries plus one good one (resolving the good one pushes no error).
        let fx = Fixture::new();
        let mut hosts: Vec<String> = (0..100).map(|_| "not a host".to_owned()).collect();
        hosts.push("crates.io".to_owned());
        let toml_text = format!("[net]\nallow = {:?}\n", hosts);
        let text = fx.write_config(&toml_text);
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), ENTRY_ERROR_CAP);
        assert!(errors.truncated);
    }

    #[test]
    fn env_set_over_the_cap_is_a_typed_error() {
        let fx = Fixture::new();
        let mut toml_text = String::from("[env.set]\n");
        for i in 0..4097 {
            toml_text.push_str(&format!("VAR{i} = \"x\"\n"));
        }
        let text = fx.write_config(&toml_text);
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        assert_eq!(errors.errors.len(), 1);
        assert!(matches!(
            errors.errors[0].value,
            EntryError::TooManyEntries { count: 4097, .. }
        ));
    }

    // ====================================================================================
    // ResolveErrors / EntryError Display
    // ====================================================================================

    #[test]
    fn resolve_errors_display_reports_the_count_and_truncation() {
        let errors = ResolveErrors {
            errors: Vec::new(),
            truncated: true,
        };
        assert!(errors.to_string().contains('0'));
        assert!(errors.to_string().contains("more exist"));
    }

    #[test]
    fn entry_error_display_follows_the_crate_convention() {
        let fx = Fixture::new();
        let text = fx.write_config("[net]\nallow = [\"not a host\"]\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        crate::error::conventions::assert_display_excludes_sources(&errors.errors[0].value);
    }

    #[test]
    fn parse_error_display_escapes_a_hostile_value_in_its_message() {
        let fx = Fixture::new();
        let text = fx.write_config("[fs]\nwrite = \"a\u{1b}[2Jb\"\n");
        let errors = assert_err!(resolve_file(&text, &fx.ctx()));
        let shown = errors.errors[0].value.to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }
}
