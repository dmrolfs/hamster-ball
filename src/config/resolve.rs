// ABOUTME: resolve_file turns one file's RawConfig into a validated ResolvedConfig plus diagnostics.
// ABOUTME: Collects entry errors up to a cap instead of stopping at the first; ResolvedConfig is the only public view.
//! Resolves a parsed, raw config into validated types, collecting every entry error it finds
//! (up to a cap) instead of stopping at the first one, so a config with several mistakes shows
//! all of them in one pass.
//!
//! A file with any entry error resolves to no [`ResolvedConfig`] at all: the result is either
//! a complete, valid config or the list of what is wrong, never a partly valid one.

use std::collections::BTreeMap;

use snafu::Snafu;

use crate::origin::{KeyPath, Located, Origin};
use crate::policy::{
    ArgWord, ArgWordError, Argv, ArgvError, CanonicalPath, ContainerLabel, ContainerLabelError,
    ContainerName, ContainerNameError, EnvName, EnvNameError, EnvValue, EnvValueError, ExtendRef,
    GuardException, HomeDir, HostPattern, HostPatternError, McpName, McpNameError, PathError,
    PathPattern, PathPatternError, Port, PortError, ProjectRoot, RefTextError,
};
use crate::system::{AllowOutcome, PathResolver, SkippedPath};
use crate::text::EscapedBounded;

use super::raw::{self, ParseError, RawConfig, RawMcpServer};
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
}

/// The successful result of [`resolve_file`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Resolved {
    /// The validated config.
    pub config: ResolvedConfig,
    /// Things that were not an error but are worth showing, such as a skipped allow rule.
    pub diagnostics: Diagnostics,
}

/// Non-error findings from resolving one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Diagnostics {
    /// Every `fs.read`/`fs.write` allow rule that was not granted, and why.
    pub skipped: Vec<Located<SkippedPath>>,
}

/// The entry errors found while resolving a file.
///
/// Collection stops adding new errors once `ENTRY_ERROR_CAP` is reached; `truncated` is set
/// when that happens, so a reporter can say "and more" instead of implying this is the whole
/// list. Errors appear in schema order (`extends`, `fs`, `net`, `env`, `tls`, `ctl`, `mcp`,
/// `hooks`, `guard`) and, within a section, in file order or sorted key order, so the same
/// file always produces the same list.
#[derive(Debug)]
#[non_exhaustive]
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
    /// The `ctl.label` selector was invalid.
    #[snafu(transparent)]
    Label {
        /// The underlying error.
        source: ContainerLabelError,
    },
    /// An `mcp.<name>.command` or `args` word was invalid.
    #[snafu(transparent)]
    ArgWord {
        /// The underlying error.
        source: ArgWordError,
    },
    /// A `hooks` command was invalid.
    #[snafu(transparent)]
    Argv {
        /// The underlying error.
        source: ArgvError,
    },
    /// An `[mcp.<name>]` server name was invalid.
    #[snafu(transparent)]
    McpName {
        /// The underlying error.
        source: McpNameError,
    },
    /// An `extends` or `guard.exceptions` entry was invalid.
    #[snafu(transparent)]
    RefText {
        /// The underlying error.
        source: RefTextError,
    },
    /// The file was not valid TOML, or did not match the schema.
    #[snafu(display("{line}:{column}: {}", escaped_parse_message(message)))]
    Parse {
        /// The 1-based line the error was found at.
        line: u32,
        /// The 1-based column, in characters, the error was found at.
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
///
/// `#[non_exhaustive]`: later milestones add fields. Only this crate builds one.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedConfig {
    /// The presets and base files this file extends, in the order written.
    pub extends: Vec<ExtendRef>,
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
    /// `[mcp.<name>]`, keyed by name, in sorted order.
    pub mcp: BTreeMap<McpName, ResolvedMcpServer>,
    /// Each `hooks` entry, as an argv array. Shape-only: whether a project file may declare
    /// `hooks` at all is a merge-time rule (section 4.2), not this module's concern.
    pub hooks: Vec<Argv>,
    /// `[guard]`.
    pub guard: ResolvedGuard,
}

/// `[fs]`: granted read/write paths, and deny patterns that apply regardless of any grant.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct ResolvedNet {
    /// Allowed outbound hosts.
    pub allow: Vec<HostPattern>,
    /// Loopback ports the hamster ball may reach.
    pub loopback_ports: Vec<Port>,
}

/// `[env]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedEnv {
    /// Variable names copied from the invoking shell.
    pub pass: Vec<EnvName>,
    /// Variables set to a fixed value, in sorted name order.
    pub set: BTreeMap<EnvName, EnvValue>,
}

/// `[tls]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct ResolvedCtl {
    /// The container label selector that scopes `hb ctl`.
    pub label: Option<ContainerLabel>,
    /// Container names this hamster ball may operate on.
    pub containers: Vec<ContainerName>,
}

/// One `[mcp.<name>]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedMcpServer {
    /// The program to run.
    pub command: Option<ArgWord>,
    /// Its arguments.
    pub args: Vec<ArgWord>,
    /// Hosts this server needs at run time.
    pub net: Vec<HostPattern>,
    /// Whether this server may bind a loopback port.
    pub bind_loopback: Option<bool>,
}

/// `[guard]`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvedGuard {
    /// Secrets-guard patterns to re-allow; only their form is checked here, what they match is
    /// defined with the guard itself.
    pub exceptions: Vec<GuardException>,
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
    let parsed = raw::parse(text).map_err(|error| parse_failure(text, &error))?;
    Resolution::new(text, ctx).run(&parsed)
}

/// The single-entry [`ResolveErrors`] for a file that did not parse.
fn parse_failure(text: &ConfigText, error: &ParseError) -> ResolveErrors {
    let origin = Origin::new(text.layer(), text.path(), error.key.clone()).with_line(error.line);
    let entry = EntryError::Parse {
        line: error.line,
        column: error.column,
        message: error.message.clone(),
    };
    ResolveErrors {
        errors: vec![Located::new(entry, origin)],
        truncated: false,
    }
}

/// One resolution pass over one file: the state every section shares.
struct Resolution<'a> {
    text: &'a ConfigText,
    resolver: PathResolver<'a>,
    errors: Vec<Located<EntryError>>,
    truncated: bool,
    skipped: Vec<Located<SkippedPath>>,
}

impl<'a> Resolution<'a> {
    fn new(text: &'a ConfigText, ctx: &ResolveContext<'a>) -> Self {
        Self {
            text,
            resolver: ctx.resolver,
            errors: Vec::new(),
            truncated: false,
            skipped: Vec::new(),
        }
    }

    /// Resolves every section, in schema order, then reports errors or the finished config.
    fn run(mut self, parsed: &RawConfig) -> Result<Resolved, ResolveErrors> {
        // Struct-literal fields evaluate in source order, which fixes the error order.
        let config = ResolvedConfig {
            extends: self.list(
                KeyPath::root().field("extends"),
                &parsed.extends,
                ExtendRef::parse,
            ),
            fs: self.fs(&parsed.fs),
            net: ResolvedNet {
                allow: self.list(net_key("allow"), &parsed.net.allow, HostPattern::parse),
                loopback_ports: self.ports(net_key("loopback_ports"), &parsed.net.loopback_ports),
            },
            env: ResolvedEnv {
                pass: self.list(env_key("pass"), &parsed.env.pass, EnvName::parse),
                set: self.env_set(&parsed.env.set),
            },
            tls: ResolvedTls {
                system_trust: parsed.tls.system_trust,
                extra_ca_files: self.extra_ca_files(&parsed.tls.extra_ca_files),
            },
            ctl: ResolvedCtl {
                label: self.label(parsed.ctl.label.as_deref()),
                containers: self.list(
                    KeyPath::root().field("ctl").field("containers"),
                    &parsed.ctl.containers,
                    ContainerName::parse,
                ),
            },
            mcp: self.mcp(&parsed.mcp),
            hooks: self.hooks(&parsed.hooks),
            guard: ResolvedGuard {
                exceptions: self.list(
                    KeyPath::root().field("guard").field("exceptions"),
                    &parsed.guard.exceptions,
                    GuardException::parse,
                ),
            },
        };
        if self.errors.is_empty() {
            Ok(Resolved {
                config,
                diagnostics: Diagnostics {
                    skipped: self.skipped,
                },
            })
        } else {
            Err(ResolveErrors {
                errors: self.errors,
                truncated: self.truncated,
            })
        }
    }

    fn origin(&self, key: KeyPath) -> Origin {
        Origin::new(self.text.layer(), self.text.path(), key)
    }

    /// Records an entry error, or marks the list truncated once the cap is reached.
    fn push(&mut self, key: KeyPath, error: impl Into<EntryError>) {
        if self.errors.len() >= ENTRY_ERROR_CAP {
            self.truncated = true;
            return;
        }
        let origin = self.origin(key);
        self.errors.push(Located::new(error.into(), origin));
    }

    /// Records [`EntryError::TooManyEntries`] and returns `true` if `len` is over the cap.
    ///
    /// Called before any entry of the list is touched.
    fn over_cap(&mut self, key: &KeyPath, len: usize) -> bool {
        if len <= MAX_LIST_ENTRIES {
            return false;
        }
        let error = EntryError::TooManyEntries {
            count: len,
            max: MAX_LIST_ENTRIES,
        };
        self.push(key.clone(), error);
        true
    }

    /// Caps, then resolves each entry with `f`, collecting every failure so the valid
    /// entries beside it are still examined.
    fn list<T, E, S: AsRef<str>>(
        &mut self,
        key: KeyPath,
        items: &[S],
        mut f: impl FnMut(&str) -> Result<T, E>,
    ) -> Vec<T>
    where
        EntryError: From<E>,
    {
        if self.over_cap(&key, items.len()) {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            match f(item.as_ref()) {
                Ok(value) => out.push(value),
                Err(error) => self.push(key.clone().index(index), error),
            }
        }
        out
    }

    fn ports(&mut self, key: KeyPath, items: &[i64]) -> Vec<Port> {
        if self.over_cap(&key, items.len()) {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            match Port::try_from(*item) {
                Ok(port) => out.push(port),
                Err(error) => self.push(key.clone().index(index), error),
            }
        }
        out
    }

    fn fs(&mut self, raw: &raw::RawFs) -> ResolvedFs {
        let resolver = self.resolver;
        let parse_pattern = |spelling: &str| PathPattern::parse(&resolver, spelling);
        ResolvedFs {
            read: self.allow_list(fs_key("read"), &raw.read),
            write: self.allow_list(fs_key("write"), &raw.write),
            deny_read: self.list(fs_key("deny_read"), &raw.deny_read, parse_pattern),
            deny_write: self.list(fs_key("deny_write"), &raw.deny_write, parse_pattern),
        }
    }

    /// Resolves `fs.read`/`fs.write` allow rules: granted paths are returned, skipped ones go
    /// to the diagnostics, and only a genuine error (not "missing" or "dangling") is an error.
    fn allow_list(&mut self, key: KeyPath, items: &[String]) -> Vec<CanonicalPath> {
        if self.over_cap(&key, items.len()) {
            return Vec::new();
        }
        let mut granted = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let entry_key = key.clone().index(index);
            match self.resolver.allow(item) {
                Ok(AllowOutcome::Granted(path)) => granted.push(path),
                Ok(AllowOutcome::Skipped(skipped)) => {
                    let origin = self.origin(entry_key);
                    self.skipped.push(Located::new(skipped, origin));
                }
                Err(error) => self.push(entry_key, error),
            }
        }
        granted
    }

    /// `tls.extra_ca_files` must exist: a missing file is an error here, not a skip.
    fn extra_ca_files(&mut self, items: &[String]) -> Vec<CanonicalPath> {
        let resolver = self.resolver;
        self.list(
            KeyPath::root().field("tls").field("extra_ca_files"),
            items,
            |spelling| resolver.existing(spelling),
        )
    }

    /// Validates each `env.set` key and value independently, so one bad entry reports both
    /// of its problems instead of hiding the second behind the first.
    fn env_set(&mut self, items: &BTreeMap<String, String>) -> BTreeMap<EnvName, EnvValue> {
        let key = env_key("set");
        if self.over_cap(&key, items.len()) {
            return BTreeMap::new();
        }
        let mut set = BTreeMap::new();
        for (raw_name, raw_value) in items {
            let entry_key = key.clone().key(raw_name.clone());
            let name = EnvName::parse(raw_name);
            let value = EnvValue::parse(raw_value);
            match (name, value) {
                (Ok(name), Ok(value)) => {
                    set.insert(name, value);
                }
                (name, value) => {
                    if let Err(error) = name {
                        self.push(entry_key.clone(), error);
                    }
                    if let Err(error) = value {
                        self.push(entry_key, error);
                    }
                }
            }
        }
        set
    }

    fn label(&mut self, raw: Option<&str>) -> Option<ContainerLabel> {
        let key = KeyPath::root().field("ctl").field("label");
        match ContainerLabel::parse(raw?) {
            Ok(label) => Some(label),
            Err(error) => {
                self.push(key, error);
                None
            }
        }
    }

    fn mcp(
        &mut self,
        items: &BTreeMap<String, RawMcpServer>,
    ) -> BTreeMap<McpName, ResolvedMcpServer> {
        let key = KeyPath::root().field("mcp");
        if self.over_cap(&key, items.len()) {
            return BTreeMap::new();
        }
        let mut resolved = BTreeMap::new();
        for (name, server) in items {
            let entry_key = key.clone().key(name.clone());
            // A bad name is reported, and the server's own fields are still checked so one
            // pass shows every problem; the server is simply not returned.
            let valid_name = match McpName::parse(name) {
                Ok(valid) => Some(valid),
                Err(error) => {
                    self.push(entry_key.clone(), error);
                    None
                }
            };
            let command = self.mcp_command(&entry_key, server.command.as_deref());
            let args = self.list(
                entry_key.clone().field("args"),
                &server.args,
                ArgWord::parse,
            );
            let net = self.list(entry_key.field("net"), &server.net, HostPattern::parse);
            if let Some(valid_name) = valid_name {
                resolved.insert(
                    valid_name,
                    ResolvedMcpServer {
                        command,
                        args,
                        net,
                        bind_loopback: server.bind_loopback,
                    },
                );
            }
        }
        resolved
    }

    fn mcp_command(&mut self, server_key: &KeyPath, raw: Option<&str>) -> Option<ArgWord> {
        match ArgWord::parse_program(raw?) {
            Ok(command) => Some(command),
            Err(error) => {
                self.push(server_key.clone().field("command"), error);
                None
            }
        }
    }

    fn hooks(&mut self, items: &[Vec<String>]) -> Vec<Argv> {
        let key = KeyPath::root().field("hooks");
        if self.over_cap(&key, items.len()) {
            return Vec::new();
        }
        let mut hooks = Vec::with_capacity(items.len());
        for (index, words) in items.iter().enumerate() {
            match Argv::parse(words) {
                Ok(argv) => hooks.push(argv),
                Err(error) => self.push(key.clone().index(index), error),
            }
        }
        hooks
    }
}

fn fs_key(field: &str) -> KeyPath {
    KeyPath::root().field("fs").field(field)
}

fn net_key(field: &str) -> KeyPath {
    KeyPath::root().field("net").field(field)
}

fn env_key(field: &str) -> KeyPath {
    KeyPath::root().field("env").field(field)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::Layer;
    use crate::testutil::Tree;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::time::{Duration, Instant};

    use super::super::text::SymlinkPolicy;

    struct Fixture {
        tree: Tree,
        root: ProjectRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let tree = Tree::new();
            let root = tree.project_root("work/proj");
            Self { tree, root }
        }

        fn ctx(&self) -> ResolveContext<'_> {
            ResolveContext::new(self.tree.home(), &self.root)
        }

        fn project_path(&self) -> std::path::PathBuf {
            self.root.path().as_path().to_path_buf()
        }

        fn write_config(&self, toml_text: &str) -> ConfigText {
            let path = self.project_path().join("hamster-ball.toml");
            assert_ok!(fs::write(&path, toml_text));
            assert_ok!(ConfigText::read(
                &path,
                Layer::Project,
                SymlinkPolicy::Refuse
            ))
        }

        /// Resolves `toml_text`, which must produce errors, and returns them.
        fn errors(&self, toml_text: &str) -> ResolveErrors {
            assert_err!(resolve_file(&self.write_config(toml_text), &self.ctx()))
        }

        /// Resolves `toml_text`, which must be valid.
        fn resolved(&self, toml_text: &str) -> Resolved {
            assert_ok!(resolve_file(&self.write_config(toml_text), &self.ctx()))
        }
    }

    fn key_of(errors: &ResolveErrors, index: usize) -> String {
        assert_some!(errors.errors.get(index))
            .origin
            .key
            .to_string()
    }

    // ====================================================================================
    // Happy path
    // ====================================================================================

    #[test]
    fn resolves_the_design_sample_into_a_resolved_config() {
        let fx = Fixture::new();
        assert_ok!(fs::create_dir_all(fx.project_path().join("src")));
        let resolved = fx.resolved(
            "extends = [\"rust\", \"agent/kiro\"]\n\
             hooks = [[\"echo\", \"hi there\"], [\"true\"]]\n\
             [fs]\n\
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
             containers = [\"pg-1\"]\n\
             [guard]\n\
             exceptions = [\".env.example\"]\n\
             [mcp.serena]\n\
             command = \"uvx\"\n\
             args = [\"--from\", \"git+https://x\", \"serena\"]\n\
             net = [\"pypi.org\"]\n\
             bind_loopback = true\n",
        );
        let config = &resolved.config;
        let extends: Vec<&str> = config.extends.iter().map(ExtendRef::as_str).collect();
        assert_eq!(extends, vec!["rust", "agent/kiro"]);
        assert_eq!(config.fs.write.len(), 1);
        assert_eq!(config.net.loopback_ports[0].get(), 3030);
        assert_eq!(config.net.allow.len(), 1);
        assert_eq!(config.env.pass[0].as_str(), "TERM");
        let name = assert_ok!(EnvName::parse("RUST_BACKTRACE"));
        assert_eq!(assert_some!(config.env.set.get(&name)).as_str(), "1");
        assert_eq!(config.tls.system_trust, Some(true));
        let label = assert_some!(config.ctl.label.as_ref());
        assert_eq!(label.to_string(), "com.docker.compose.project=icehouse");
        assert_eq!(config.ctl.containers[0].as_str(), "pg-1");
        assert_eq!(config.guard.exceptions[0].as_str(), ".env.example");
        let serena = assert_some!(config.mcp.get("serena"));
        assert_eq!(assert_some!(serena.command.as_ref()).as_str(), "uvx");
        let args: Vec<&str> = serena.args.iter().map(ArgWord::as_str).collect();
        assert_eq!(args, vec!["--from", "git+https://x", "serena"]);
        assert_eq!(serena.net.len(), 1);
        assert_eq!(serena.bind_loopback, Some(true));
        assert_eq!(config.hooks.len(), 2);
        assert_eq!(config.hooks[0].program().as_str(), "echo");
        assert_eq!(config.hooks[0].words()[1].as_str(), "hi there");
        assert!(resolved.diagnostics.skipped.is_empty());
    }

    #[test]
    fn an_empty_file_resolves_to_an_empty_config() {
        let fx = Fixture::new();
        let resolved = fx.resolved("");
        assert!(resolved.config.fs.read.is_empty());
        assert!(resolved.config.mcp.is_empty());
        assert_eq!(resolved.config.tls.system_trust, None);
        assert_eq!(resolved.config.ctl.label, None);
    }

    #[test]
    fn an_unset_system_trust_stays_unset_rather_than_defaulting() {
        let fx = Fixture::new();
        assert_eq!(fx.resolved("[tls]\n").config.tls.system_trust, None);
        let off = fx.resolved("[tls]\nsystem_trust = false\n");
        assert_eq!(off.config.tls.system_trust, Some(false));
    }

    #[test]
    fn extends_and_guard_exceptions_keep_their_order() {
        let fx = Fixture::new();
        let resolved =
            fx.resolved("extends = [\"z\", \"a\", \"m\"]\n[guard]\nexceptions = [\"y\", \"b\"]\n");
        let extends: Vec<&str> = resolved
            .config
            .extends
            .iter()
            .map(ExtendRef::as_str)
            .collect();
        assert_eq!(extends, vec!["z", "a", "m"]);
        let exceptions: Vec<&str> = resolved
            .config
            .guard
            .exceptions
            .iter()
            .map(GuardException::as_str)
            .collect();
        assert_eq!(exceptions, vec!["y", "b"]);
    }

    #[test]
    fn mcp_servers_are_returned_in_sorted_name_order() {
        let fx = Fixture::new();
        let resolved = fx.resolved("[mcp.zeta]\n[mcp.alpha]\n[mcp.mid]\n");
        let names: Vec<&str> = resolved.config.mcp.keys().map(McpName::as_str).collect();
        assert_eq!(names, vec!["alpha", "mid", "zeta"]);
    }

    // ====================================================================================
    // Parse failure short-circuits resolution
    // ====================================================================================

    #[test]
    fn a_syntax_error_is_the_single_reported_error() {
        let fx = Fixture::new();
        let errors = fx.errors("fs = [this is not valid toml\n");
        assert_eq!(errors.errors.len(), 1);
        assert!(!errors.truncated);
        assert!(matches!(errors.errors[0].value, EntryError::Parse { .. }));
    }

    #[test]
    fn a_parse_error_carries_its_key_path_line_and_column() {
        let fx = Fixture::new();
        let errors = fx.errors("[fs]\nwrite = \"not-a-list\"\n");
        let located = &errors.errors[0];
        assert_eq!(located.origin.key.to_string(), "fs.write");
        assert_eq!(located.origin.line, Some(2));
        assert!(matches!(
            located.value,
            EntryError::Parse {
                line: 2,
                column: 9,
                ..
            }
        ));
        assert_eq!(
            located.origin.file,
            fx.project_path().join("hamster-ball.toml")
        );
        assert_eq!(located.origin.layer, Layer::Project);
    }

    #[test]
    fn a_parse_error_display_never_echoes_the_source_excerpt() {
        let fx = Fixture::new();
        let errors = fx.errors("[fs]\nwrite = \"not-a-list\"\n");
        let shown = errors.errors[0].value.to_string();
        // The message legitimately names the bad value; what must never appear is the
        // multi-line "2 | write = ..." excerpt box with its `^^^` marker.
        assert!(!shown.contains('^'), "{shown:?}");
        assert!(!shown.contains('\n'), "{shown:?}");
        assert!(shown.starts_with("2:9: "), "{shown:?}");
    }

    #[test]
    fn parse_error_display_escapes_a_hostile_value_in_its_message() {
        let fx = Fixture::new();
        let errors = fx.errors("[fs]\nwrite = \"a\u{1b}[2Jb\"\n");
        let shown = errors.errors[0].value.to_string();
        assert!(!shown.contains('\u{1b}'), "{shown:?}");
    }

    // ====================================================================================
    // Mixed good and bad entries
    // ====================================================================================

    #[test]
    fn a_bad_host_pattern_is_reported_with_its_index_among_good_ones() {
        let fx = Fixture::new();
        let errors = fx.errors("[net]\nallow = [\"crates.io\", \"not a host\", \"pypi.org\"]\n");
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "net.allow[1]");
        assert!(matches!(errors.errors[0].value, EntryError::Host { .. }));
    }

    #[test]
    fn every_collected_error_carries_the_files_layer_and_path() {
        let fx = Fixture::new();
        let errors = fx.errors("[net]\nallow = [\"not a host\"]\n");
        let origin = &errors.errors[0].origin;
        assert_eq!(origin.layer, Layer::Project);
        assert_eq!(origin.file, fx.project_path().join("hamster-ball.toml"));
    }

    #[test]
    fn errors_in_several_sections_are_all_reported_in_schema_order() {
        let fx = Fixture::new();
        let errors = fx.errors(
            "extends = [\"\"]\n\
             [guard]\nexceptions = [\"\"]\n\
             [net]\nloopback_ports = [0]\nallow = [\"bad host\"]\n\
             [env]\npass = [\"1x\"]\n",
        );
        let keys: Vec<String> = (0..errors.errors.len())
            .map(|i| key_of(&errors, i))
            .collect();
        assert_eq!(
            keys,
            vec![
                "extends[0]",
                "net.allow[0]",
                "net.loopback_ports[0]",
                "env.pass[0]",
                "guard.exceptions[0]"
            ]
        );
    }

    #[test]
    fn env_set_reports_a_bad_name_and_a_bad_value_of_the_same_entry() {
        let fx = Fixture::new();
        let errors = fx.errors("[env.set]\n\"1BAD\" = \"a\\u0000b\"\n");
        assert_eq!(errors.errors.len(), 2);
        assert!(matches!(errors.errors[0].value, EntryError::EnvName { .. }));
        assert!(matches!(
            errors.errors[1].value,
            EntryError::EnvValue { .. }
        ));
        assert_eq!(key_of(&errors, 0), "env.set.1BAD");
    }

    #[test]
    fn env_set_errors_come_out_in_sorted_key_order_whatever_the_file_order() {
        let fx = Fixture::new();
        let errors = fx.errors("[env.set]\n\"9z\" = \"x\"\n\"9a\" = \"x\"\n\"9m\" = \"x\"\n");
        let keys: Vec<String> = (0..errors.errors.len())
            .map(|i| key_of(&errors, i))
            .collect();
        assert_eq!(keys, vec!["env.set.9a", "env.set.9m", "env.set.9z"]);
    }

    // ====================================================================================
    // Validated passthrough values (ctl.label, hooks, mcp, extends, guard)
    // ====================================================================================

    #[test]
    fn an_empty_ctl_label_is_an_error() {
        let fx = Fixture::new();
        let errors = fx.errors("[ctl]\nlabel = \"\"\n");
        assert_eq!(key_of(&errors, 0), "ctl.label");
        assert!(matches!(errors.errors[0].value, EntryError::Label { .. }));
    }

    #[test]
    fn a_bare_key_or_nul_ctl_label_is_an_error() {
        let fx = Fixture::new();
        for bad in ["com.docker.compose.project", "a=b\\u0000c"] {
            let errors = fx.errors(&format!("[ctl]\nlabel = \"{bad}\"\n"));
            assert!(
                matches!(errors.errors[0].value, EntryError::Label { .. }),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_empty_hook_command_is_an_error_with_its_index() {
        let fx = Fixture::new();
        let errors = fx.errors("hooks = [[\"ok\"], []]\n");
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "hooks[1]");
        assert!(matches!(
            errors.errors[0].value,
            EntryError::Argv {
                source: ArgvError::Empty
            }
        ));
    }

    #[test]
    fn a_nul_in_a_hook_word_is_an_error() {
        let fx = Fixture::new();
        let errors = fx.errors("hooks = [[\"echo\", \"a\\u0000b\"]]\n");
        assert_eq!(key_of(&errors, 0), "hooks[0]");
        assert!(matches!(
            errors.errors[0].value,
            EntryError::Argv {
                source: ArgvError::Word { index: 1, .. }
            }
        ));
    }

    #[test]
    fn mcp_command_and_args_are_validated() {
        let fx = Fixture::new();
        let errors = fx.errors("[mcp.a]\ncommand = \"\"\nargs = [\"ok\", \"b\\u0000d\"]\n");
        assert_eq!(errors.errors.len(), 2);
        assert_eq!(key_of(&errors, 0), "mcp.a.command");
        assert!(matches!(
            errors.errors[0].value,
            EntryError::ArgWord {
                source: ArgWordError::EmptyProgram
            }
        ));
        assert_eq!(key_of(&errors, 1), "mcp.a.args[1]");
        assert!(matches!(
            errors.errors[1].value,
            EntryError::ArgWord {
                source: ArgWordError::ContainsNul
            }
        ));
    }

    #[test]
    fn an_invalid_mcp_server_name_is_an_error_and_its_contents_are_still_checked() {
        let fx = Fixture::new();
        let errors =
            fx.errors("[mcp.\"../evil\"]\ncommand = \"\"\n[mcp.good]\ncommand = \"uvx\"\n");
        assert_eq!(errors.errors.len(), 2);
        assert_eq!(key_of(&errors, 0), "mcp.\"../evil\"");
        assert!(matches!(errors.errors[0].value, EntryError::McpName { .. }));
        // The bad server's own fields are still reported, so one pass shows every problem.
        assert_eq!(key_of(&errors, 1), "mcp.\"../evil\".command");
    }

    #[test]
    fn mcp_servers_are_keyed_by_validated_names() {
        let fx = Fixture::new();
        let resolved = fx.resolved("[mcp.sequential-thinking]\ncommand = \"npx\"\n");
        let name = assert_ok!(McpName::parse("sequential-thinking"));
        assert!(resolved.config.mcp.contains_key(&name));
    }

    #[test]
    fn mcp_net_hosts_are_validated_with_their_key_path() {
        let fx = Fixture::new();
        let errors = fx.errors("[mcp.a]\nnet = [\"fine.example.com\", \"bad host\"]\n");
        assert_eq!(key_of(&errors, 0), "mcp.a.net[1]");
    }

    #[test]
    fn empty_or_control_extends_and_guard_exceptions_are_errors() {
        let fx = Fixture::new();
        let errors =
            fx.errors("extends = [\"\", \"a\\nb\"]\n[guard]\nexceptions = [\"x\\u0000\"]\n");
        let keys: Vec<String> = (0..errors.errors.len())
            .map(|i| key_of(&errors, i))
            .collect();
        assert_eq!(
            keys,
            vec!["extends[0]", "extends[1]", "guard.exceptions[0]"]
        );
        assert!(
            errors
                .errors
                .iter()
                .all(|e| matches!(e.value, EntryError::RefText { .. }))
        );
    }

    // ====================================================================================
    // fs.read / fs.write: missing is a skip, not an error
    // ====================================================================================

    #[test]
    fn a_missing_allow_path_is_skipped_with_its_spelling_and_origin() {
        let fx = Fixture::new();
        let resolved =
            fx.resolved("[fs]\nread = [\"does-not-exist\"]\nwrite = [\"also-missing\"]\n");
        assert!(resolved.config.fs.read.is_empty());
        assert_eq!(resolved.diagnostics.skipped.len(), 2);
        let first = &resolved.diagnostics.skipped[0];
        assert_eq!(first.origin.key.to_string(), "fs.read[0]");
        assert_eq!(first.value.spelling, "does-not-exist");
        assert_eq!(
            resolved.diagnostics.skipped[1].origin.key.to_string(),
            "fs.write[0]"
        );
    }

    #[test]
    fn skipped_rules_do_not_stop_later_entries_from_resolving() {
        let fx = Fixture::new();
        assert_ok!(fs::create_dir_all(fx.project_path().join("src")));
        let resolved = fx.resolved("[fs]\nwrite = [\"missing\", \"src\", \"missing2\"]\n");
        assert_eq!(resolved.config.fs.write.len(), 1);
        assert_eq!(resolved.diagnostics.skipped.len(), 2);
        assert_eq!(
            resolved.diagnostics.skipped[1].origin.key.to_string(),
            "fs.write[2]"
        );
    }

    #[test]
    fn tls_extra_ca_files_missing_is_an_entry_error_not_a_skip() {
        let fx = Fixture::new();
        let errors = fx.errors("[tls]\nextra_ca_files = [\"does-not-exist.pem\"]\n");
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "tls.extra_ca_files[0]");
    }

    #[test]
    fn contrast_fs_read_skips_but_tls_extra_ca_files_errors_for_the_same_missing_spelling() {
        let fx = Fixture::new();
        let errors = fx
            .errors("[fs]\nread = [\"missing.pem\"]\n[tls]\nextra_ca_files = [\"missing.pem\"]\n");
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "tls.extra_ca_files[0]");
    }

    #[test]
    fn an_existing_extra_ca_file_resolves() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("ca.pem"), b"x"));
        let resolved = fx.resolved("[tls]\nextra_ca_files = [\"ca.pem\"]\n");
        assert_eq!(resolved.config.tls.extra_ca_files.len(), 1);
    }

    #[test]
    fn deny_patterns_resolve_and_a_slash_star_pattern_has_the_filesystem_root_as_base() {
        let fx = Fixture::new();
        let resolved =
            fx.resolved("[fs]\ndeny_read = [\"config/*.secrets.yaml\"]\ndeny_write = [\"/*\"]\n");
        assert_eq!(
            resolved.config.fs.deny_read[0].base.as_path(),
            fx.project_path().join("config")
        );
        assert_eq!(resolved.config.fs.deny_write[0].base.as_str(), "/");
    }

    // ====================================================================================
    // NUL survives parsing, rejected at resolution
    // ====================================================================================

    #[test]
    fn a_nul_byte_in_a_path_is_rejected_at_resolution() {
        let fx = Fixture::new();
        let errors = fx.errors("[fs]\nwrite = [\"a\\u0000b\"]\n");
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "fs.write[0]");
        assert!(matches!(
            errors.errors[0].value,
            EntryError::Path {
                source: PathError::SpellingControlCharacter { .. }
            }
        ));
    }

    #[test]
    fn a_nul_byte_in_a_host_is_rejected_at_resolution() {
        let fx = Fixture::new();
        let errors = fx.errors("[net]\nallow = [\"a\\u0000b\"]\n");
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "net.allow[0]");
        assert!(matches!(errors.errors[0].value, EntryError::Host { .. }));
    }

    #[test]
    fn a_nul_byte_in_an_env_value_is_rejected_at_resolution() {
        let fx = Fixture::new();
        let errors = fx.errors("[env.set]\nA = \"a\\u0000b\"\n");
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "env.set.A");
        assert!(matches!(
            errors.errors[0].value,
            EntryError::EnvValue {
                source: EnvValueError::ContainsNul
            }
        ));
    }

    // ====================================================================================
    // Caps
    // ====================================================================================

    #[test]
    fn exactly_4096_entries_in_a_list_resolves() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..4096).map(|i| format!("host{i}.example.com")).collect();
        let resolved = fx.resolved(&format!("[net]\nallow = {hosts:?}\n"));
        assert_eq!(resolved.config.net.allow.len(), 4096);
    }

    #[test]
    fn entries_over_4096_in_a_list_is_a_typed_cap_error_naming_the_count_and_limit() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..4097).map(|i| format!("host{i}.example.com")).collect();
        let errors = fx.errors(&format!("[net]\nallow = {hosts:?}\n"));
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "net.allow");
        assert!(matches!(
            errors.errors[0].value,
            EntryError::TooManyEntries {
                count: 4097,
                max: 4096
            }
        ));
    }

    #[test]
    fn the_list_cap_is_checked_before_any_entry_is_resolved() {
        // Every entry would be an error on its own. If entries were resolved first, the
        // result would be 64 errors and `truncated`; checking the cap first gives exactly one.
        let fx = Fixture::new();
        let bad: Vec<String> = (0..5000).map(|_| "bad host".to_owned()).collect();
        let errors = fx.errors(&format!("[net]\nallow = {bad:?}\n"));
        assert_eq!(errors.errors.len(), 1);
        assert!(!errors.truncated);
        assert!(matches!(
            errors.errors[0].value,
            EntryError::TooManyEntries { count: 5000, .. }
        ));
    }

    #[test]
    fn an_oversized_fs_list_makes_no_filesystem_calls_it_would_have_been_slow_to_make() {
        let fx = Fixture::new();
        let paths: Vec<String> = (0..5000).map(|i| format!("nowhere/path{i}")).collect();
        let started = Instant::now();
        let errors = fx.errors(&format!("[fs]\nread = {paths:?}\n"));
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "took {:?}",
            started.elapsed()
        );
        assert_eq!(errors.errors.len(), 1);
    }

    #[test]
    fn every_list_and_map_field_enforces_the_cap() {
        let fx = Fixture::new();
        let many = |value: &str| -> String { format!("{:?}", vec![value; 4097]) };
        let cases = [
            (format!("extends = {}\n", many("a")), "extends"),
            (format!("[fs]\nwrite = {}\n", many("x")), "fs.write"),
            (format!("[fs]\ndeny_read = {}\n", many("x")), "fs.deny_read"),
            (
                format!("[net]\nloopback_ports = {:?}\n", vec![80; 4097]),
                "net.loopback_ports",
            ),
            (format!("[env]\npass = {}\n", many("A")), "env.pass"),
            (
                format!("[tls]\nextra_ca_files = {}\n", many("x")),
                "tls.extra_ca_files",
            ),
            (
                format!("[ctl]\ncontainers = {}\n", many("a")),
                "ctl.containers",
            ),
            (format!("hooks = {:?}\n", vec![vec!["x"]; 4097]), "hooks"),
            (
                format!("[guard]\nexceptions = {}\n", many("a")),
                "guard.exceptions",
            ),
            (format!("[mcp.a]\nargs = {}\n", many("a")), "mcp.a.args"),
            (
                format!("[mcp.a]\nnet = {}\n", many("a.example.com")),
                "mcp.a.net",
            ),
        ];
        for (toml_text, key) in cases {
            let errors = fx.errors(&toml_text);
            assert_eq!(errors.errors.len(), 1, "{key}");
            assert_eq!(key_of(&errors, 0), key);
            assert!(
                matches!(errors.errors[0].value, EntryError::TooManyEntries { .. }),
                "{key}"
            );
        }
    }

    #[test]
    fn env_set_over_the_cap_is_a_typed_error() {
        let fx = Fixture::new();
        let mut toml_text = String::from("[env.set]\n");
        for i in 0..4097 {
            toml_text.push_str(&format!("VAR{i} = \"x\"\n"));
        }
        let errors = fx.errors(&toml_text);
        assert_eq!(errors.errors.len(), 1);
        assert_eq!(key_of(&errors, 0), "env.set");
        assert!(matches!(
            errors.errors[0].value,
            EntryError::TooManyEntries { count: 4097, .. }
        ));
    }

    #[test]
    fn mcp_over_the_cap_is_a_typed_error() {
        let fx = Fixture::new();
        let mut toml_text = String::new();
        for i in 0..4097 {
            toml_text.push_str(&format!("[mcp.s{i}]\n"));
        }
        let errors = fx.errors(&toml_text);
        assert_eq!(key_of(&errors, 0), "mcp");
        assert_eq!(errors.errors.len(), 1);
    }

    #[test]
    fn more_than_the_error_cap_collects_exactly_the_cap_and_marks_truncated() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..100).map(|_| "not a host".to_owned()).collect();
        let errors = fx.errors(&format!("[net]\nallow = {hosts:?}\n"));
        assert_eq!(errors.errors.len(), ENTRY_ERROR_CAP);
        assert!(errors.truncated);
        assert_eq!(key_of(&errors, ENTRY_ERROR_CAP - 1), "net.allow[63]");
    }

    #[test]
    fn exactly_the_error_cap_of_bad_entries_is_not_marked_truncated() {
        let fx = Fixture::new();
        let hosts: Vec<String> = (0..ENTRY_ERROR_CAP)
            .map(|_| "not a host".to_owned())
            .collect();
        let errors = fx.errors(&format!("[net]\nallow = {hosts:?}\n"));
        assert_eq!(errors.errors.len(), ENTRY_ERROR_CAP);
        assert!(!errors.truncated);
    }

    // ====================================================================================
    // ResolveErrors / EntryError Display
    // ====================================================================================

    #[test]
    fn resolve_errors_display_reports_the_count_and_truncation() {
        let plain = ResolveErrors {
            errors: Vec::new(),
            truncated: false,
        };
        assert_eq!(plain.to_string(), "0 configuration error(s)");
        let truncated = ResolveErrors {
            errors: Vec::new(),
            truncated: true,
        };
        assert_eq!(
            truncated.to_string(),
            "0 configuration error(s) (more exist past the first 64)"
        );
    }

    #[test]
    fn entry_errors_follow_the_display_convention() {
        let fx = Fixture::new();
        let errors = fx.errors(
            "extends = [\"\"]\n[net]\nallow = [\"not a host\"]\nloopback_ports = [0]\n\
             [ctl]\nlabel = \"x\"\n[mcp.a]\ncommand = \"\"\n",
        );
        assert!(errors.errors.len() >= 4);
        for located in &errors.errors {
            crate::error::conventions::assert_display_excludes_sources(&located.value);
        }
    }

    // ====================================================================================
    // Property: arbitrary input never panics
    // ====================================================================================

    /// A TOML string literal for `text`, with every character escaped correctly.
    fn toml_string(text: &str) -> String {
        toml::Value::String(text.to_owned()).to_string()
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(48))]

        #[test]
        fn resolve_file_never_panics_on_arbitrary_text(text in "\\PC{0,300}") {
            let fx = Fixture::new();
            let _ = resolve_file(&fx.write_config(&text), &fx.ctx());
        }

        #[test]
        fn resolve_file_never_panics_on_arbitrary_values_in_every_field(
            host in "\\PC{0,30}",
            path in "\\PC{0,30}",
            label in "\\PC{0,30}",
            word in "\\PC{0,30}",
            name in "\\PC{0,12}",
        ) {
            let (host, path, label, word, name) = (
                toml_string(&host), toml_string(&path), toml_string(&label),
                toml_string(&word), toml_string(&name),
            );
            let doc = format!(
                "extends = [{path}]\nhooks = [[{word}, {word}]]\n\
                 [fs]\nread = [{path}]\nwrite = [{path}]\ndeny_read = [{path}]\ndeny_write = [{path}]\n\
                 [net]\nallow = [{host}]\n[env]\npass = [{name}]\n[env.set]\n{name} = {word}\n\
                 [tls]\nextra_ca_files = [{path}]\n[ctl]\nlabel = {label}\ncontainers = [{name}]\n\
                 [guard]\nexceptions = [{word}]\n\
                 [mcp.{name}]\ncommand = {word}\nargs = [{word}]\nnet = [{host}]\n"
            );
            let fx = Fixture::new();
            let _ = resolve_file(&fx.write_config(&doc), &fx.ctx());
        }
    }
}
