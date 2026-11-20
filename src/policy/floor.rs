// ABOUTME: The floor: compiled-in rules no config layer can override, plus the pure parsers (PATH, gitdir pointer) its builder uses.
// ABOUTME: Pure and I/O-free; resolving the table against the real filesystem lives in `system::floor`.
//! The floor (design section 6).
//!
//! A [`Floor`] is a list of [`FloorRule`]s. It is built once, by [`crate::system::build_floor`],
//! and a [`crate::config::Policy`] cannot exist without one: [`Floor`] has no public constructor
//! and no `Default`. A rule can only be added to it, never removed or narrowed by a config file,
//! because config files never see it.
//!
//! Each rule has an [`FloorEffect`] (what it forbids) and an [`Extent`] (how much of the tree it
//! covers). The Seatbelt renderer (hb-ghd.2.1) emits every rule after every allow, so a floor
//! rule wins. [`Floor::denying`] is the advisory Rust query for the same question.

use std::borrow::Cow;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use snafu::{OptionExt, Snafu, ensure};
use strum::{Display, IntoStaticStr};

use super::path::{CanonicalPath, MAX_PATH_BYTES};
use super::pattern::{Coverage, Extent, PathPattern};
use crate::text::{Escaped, EscapedBounded};

/// What the caller wants to do with a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsAccess {
    /// Read the path.
    Read,
    /// Write, create, delete or rename the path.
    Write,
    /// Connect to the path as a unix-domain socket.
    Connect,
}

/// What a floor rule forbids.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum FloorEffect {
    /// Reading, writing, creating, deleting and renaming.
    DenyReadWrite,
    /// Writing, creating, deleting and renaming; reads stay up to the grants.
    DenyWrite,
    /// Connecting to a unix-domain socket. A file deny does not stop `connect()`.
    DenyConnect,
    /// Unlinking or renaming the node itself, nothing else.
    ///
    /// Protects an ancestor of a denied path: without it the ancestor can be renamed and the
    /// denied path recreated elsewhere (design section 6, `.git` and approval files).
    PinUnlink,
}

impl FloorEffect {
    /// Whether this effect forbids `access`.
    #[must_use]
    pub fn forbids(self, access: FsAccess) -> bool {
        matches!(
            (self, access),
            (Self::DenyReadWrite, FsAccess::Read | FsAccess::Write)
                | (Self::DenyWrite | Self::PinUnlink, FsAccess::Write)
                | (Self::DenyConnect, FsAccess::Connect)
        )
    }

    /// Whether the effect protects the covered path from being written, renamed or deleted.
    #[must_use]
    pub fn protects_writes(self) -> bool {
        matches!(self, Self::DenyReadWrite | Self::DenyWrite)
    }
}

/// Most rules a floor may hold. Profile compile time grows roughly with the square of the rule count.
pub const MAX_FLOOR_RULES: usize = 4096;

/// A floor would have more than [`MAX_FLOOR_RULES`] rules.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[snafu(display("the floor would have {count} rules; the limit is {max}"))]
pub struct FloorTooLarge {
    /// How many rules were requested.
    pub count: usize,
    /// The limit.
    pub max: usize,
}

/// The position of a rule in its [`Floor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FloorRuleId(u16);

impl FloorRuleId {
    /// The index into [`Floor::rules`].
    #[must_use]
    pub fn index(self) -> usize {
        usize::from(self.0)
    }
}

/// Where a floor rule came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum FloorGroup {
    /// The compiled table (and rules derived from the environment the same way).
    Table,
    /// The project's own config, approval files and git directories.
    Project,
    /// `PATH` entries, the programs they link to, and `hb` itself.
    Path,
    /// An unlink pin on an ancestor of a protected path.
    Pin,
}

/// One floor rule.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct FloorRule {
    /// A stable name: the table's name, or `kind:<canonical path>` for a derived rule.
    pub name: Cow<'static, str>,
    /// Where the rule came from.
    pub group: FloorGroup,
    /// What the rule forbids.
    pub effect: FloorEffect,
    /// How much of the tree below the pattern's base it covers.
    pub extent: Extent,
    /// The resolved path (with the symlink alias, if any) and optional glob tail.
    pub pattern: PathPattern,
    /// A short reason, for `explain`.
    pub reason: &'static str,
}

impl FloorRule {
    /// A rule. A glob tail only makes sense for [`Extent::Subtree`], so a rule with a tail is
    /// always a subtree rule, whatever extent was asked for.
    #[must_use]
    pub(crate) fn new(
        name: impl Into<Cow<'static, str>>,
        effect: FloorEffect,
        extent: Extent,
        pattern: PathPattern,
        reason: &'static str,
    ) -> Self {
        let extent = if pattern.tail.is_some() {
            Extent::Subtree
        } else {
            extent
        };
        Self {
            name: name.into(),
            group: FloorGroup::Table,
            effect,
            extent,
            pattern,
            reason,
        }
    }

    /// The same rule, labelled as coming from `group`.
    #[must_use]
    pub(crate) fn in_group(mut self, group: FloorGroup) -> Self {
        self.group = group;
        self
    }

    /// Whether the rule covers `path` (ignoring the effect).
    #[must_use]
    pub fn covers(&self, path: &CanonicalPath) -> Coverage {
        self.pattern.covers_within(path, self.extent)
    }
}

/// A floor rule that forbids an access, and how it matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorHit<'a> {
    /// The rule's position.
    pub id: FloorRuleId,
    /// The rule.
    pub rule: &'a FloorRule,
    /// Whether the rule matched only under case-insensitive or Unicode-conservative comparison.
    pub folded: bool,
}

/// The compiled rules no config can override.
///
/// Cannot be built outside this crate, and does not implement `Default`: a policy without a floor
/// is not representable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Floor {
    rules: Vec<FloorRule>,
}

impl Floor {
    /// A floor of `rules`, in order.
    ///
    /// # Errors
    /// [`FloorTooLarge`] if there are more than [`MAX_FLOOR_RULES`] rules. A floor is never
    /// silently shortened: a missing rule is an unprotected path.
    pub(crate) fn new(rules: Vec<FloorRule>) -> Result<Self, FloorTooLarge> {
        if rules.len() > MAX_FLOOR_RULES {
            return FloorTooLargeSnafu {
                count: rules.len(),
                max: MAX_FLOOR_RULES,
            }
            .fail();
        }
        Ok(Self { rules })
    }

    /// A floor with no rules, for tests of code that only needs some floor.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn empty() -> Self {
        Self { rules: Vec::new() }
    }

    /// Every rule, in a stable order: the compiled table first.
    #[must_use]
    pub fn rules(&self) -> &[FloorRule] {
        &self.rules
    }

    /// The rule with `id`, if it belongs to this floor.
    #[must_use]
    pub fn rule(&self, id: FloorRuleId) -> Option<&FloorRule> {
        self.rules.get(id.index())
    }

    /// Every rule with its id.
    pub fn iter(&self) -> impl Iterator<Item = (FloorRuleId, &FloorRule)> {
        self.rules
            .iter()
            .enumerate()
            .map(|(index, rule)| (FloorRuleId(u16::try_from(index).unwrap_or(u16::MAX)), rule))
    }

    /// The rule that forbids `access` to `path`, if any.
    ///
    /// A rule that matches exactly is reported in preference to one that matches only after
    /// folding; otherwise the first in floor order. Errs toward "denied".
    #[must_use]
    pub fn denying(&self, path: &CanonicalPath, access: FsAccess) -> Option<FloorHit<'_>> {
        let mut folded = None;
        for (id, rule) in self.iter().filter(|(_, rule)| rule.effect.forbids(access)) {
            match rule.covers(path) {
                Coverage::No => {}
                Coverage::Yes => {
                    return Some(FloorHit {
                        id,
                        rule,
                        folded: false,
                    });
                }
                Coverage::YesFolded => {
                    folded.get_or_insert(FloorHit {
                        id,
                        rule,
                        folded: true,
                    });
                }
            }
        }
        folded
    }
}

// ======================================================================================
// The compiled table
// ======================================================================================

/// One row of the compiled table. Every row has [`Extent::Subtree`]; the base is `~/...` or absolute.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TableRule {
    pub name: &'static str,
    pub effect: FloorEffect,
    pub base: &'static str,
    /// Glob segments below `base`, or empty for a plain path.
    pub tail: &'static [&'static str],
    pub reason: &'static str,
}

const fn rw(name: &'static str, base: &'static str, reason: &'static str) -> TableRule {
    TableRule {
        name,
        effect: FloorEffect::DenyReadWrite,
        base,
        tail: &[],
        reason,
    }
}

const fn rw_glob(
    name: &'static str,
    base: &'static str,
    tail: &'static [&'static str],
    reason: &'static str,
) -> TableRule {
    TableRule {
        name,
        effect: FloorEffect::DenyReadWrite,
        base,
        tail,
        reason,
    }
}

const fn wr(name: &'static str, base: &'static str, reason: &'static str) -> TableRule {
    TableRule {
        name,
        effect: FloorEffect::DenyWrite,
        base,
        tail: &[],
        reason,
    }
}

const fn conn(name: &'static str, base: &'static str, reason: &'static str) -> TableRule {
    TableRule {
        name,
        effect: FloorEffect::DenyConnect,
        base,
        tail: &[],
        reason,
    }
}

const CREDENTIALS: &str = "credentials";
const BROWSER: &str = "browser profile, cookies and sessions";
const CONTAINER: &str = "container runtime access is host access";
const HB_STATE: &str = "hamster-ball's own configuration and approvals";
const STARTUP: &str = "runs outside the sandbox at the next shell start";
const TOOL_CONFIG: &str = "tool configuration that runs code or redirects package sources";
/// The reason on every rule that protects a directory of programs.
pub(crate) const PATH_DIR: &str = "a directory of programs you run outside the sandbox";
const HISTORY: &str = "shell and tool history can contain secrets";

/// Where the user's temporary directory's podman socket directory lives, relative to that directory.
pub(crate) const USER_TEMP_PODMAN: &str = "podman";

/// The table, in a stable order. Rule ids are positions in the built floor, so an addition goes
/// at the end of its group and a test pins the set of names.
pub(crate) const TABLE: &[TableRule] = &[
    // Credentials (design section 6).
    rw("ssh", "~/.ssh", CREDENTIALS),
    rw("aws", "~/.aws", CREDENTIALS),
    rw("gnupg", "~/.gnupg", CREDENTIALS),
    rw("netrc", "~/.netrc", CREDENTIALS),
    rw("gh", "~/.config/gh", CREDENTIALS),
    rw("docker-config", "~/.docker", CREDENTIALS),
    rw("kube", "~/.kube", CREDENTIALS),
    rw("keychains", "~/Library/Keychains", CREDENTIALS),
    // More credential stores.
    rw("git-credentials", "~/.git-credentials", CREDENTIALS),
    rw_glob(
        "cargo-credentials",
        "~/.cargo",
        &["credentials*"],
        CREDENTIALS,
    ),
    rw("op", "~/.config/op", CREDENTIALS),
    rw("rclone", "~/.config/rclone", CREDENTIALS),
    rw("gcloud", "~/.config/gcloud", CREDENTIALS),
    rw("azure", "~/.azure", CREDENTIALS),
    rw("oci", "~/.oci", CREDENTIALS),
    rw("doctl", "~/.config/doctl", CREDENTIALS),
    rw("hub", "~/.config/hub", CREDENTIALS),
    rw("glab", "~/.config/glab-cli", CREDENTIALS),
    rw("vault-token", "~/.vault-token", CREDENTIALS),
    rw("pgpass", "~/.pgpass", CREDENTIALS),
    rw("gem-credentials", "~/.gem/credentials", CREDENTIALS),
    rw(
        "terraform-credentials",
        "~/.terraform.d/credentials.tfrc.json",
        CREDENTIALS,
    ),
    rw("pypirc", "~/.pypirc", CREDENTIALS),
    rw("npmrc", "~/.npmrc", CREDENTIALS),
    rw(
        "1password-data",
        "~/Library/Application Support/1Password",
        CREDENTIALS,
    ),
    rw(
        "1password-group",
        "~/Library/Group Containers/2BUA8C4S2C.com.1password",
        CREDENTIALS,
    ),
    // History.
    rw_glob("history", "~", &[".*_history"], HISTORY),
    rw("zsh-sessions", "~/.zsh_sessions", HISTORY),
    rw("atuin-data", "~/.local/share/atuin", HISTORY),
    rw("atuin-config", "~/.config/atuin", HISTORY),
    // Browsers: whole vendor directories, not profile subdirectories.
    rw(
        "browser-chrome",
        "~/Library/Application Support/Google",
        BROWSER,
    ),
    rw(
        "browser-chromium",
        "~/Library/Application Support/Chromium",
        BROWSER,
    ),
    rw(
        "browser-edge",
        "~/Library/Application Support/Microsoft Edge",
        BROWSER,
    ),
    rw(
        "browser-edge-beta",
        "~/Library/Application Support/Microsoft Edge Beta",
        BROWSER,
    ),
    rw(
        "browser-edge-dev",
        "~/Library/Application Support/Microsoft Edge Dev",
        BROWSER,
    ),
    rw(
        "browser-edge-canary",
        "~/Library/Application Support/Microsoft Edge Canary",
        BROWSER,
    ),
    rw(
        "browser-vivaldi",
        "~/Library/Application Support/Vivaldi",
        BROWSER,
    ),
    rw(
        "browser-vivaldi-snapshot",
        "~/Library/Application Support/Vivaldi Snapshot",
        BROWSER,
    ),
    rw(
        "browser-opera",
        "~/Library/Application Support/com.operasoftware.Opera",
        BROWSER,
    ),
    rw(
        "browser-brave",
        "~/Library/Application Support/BraveSoftware",
        BROWSER,
    ),
    rw("browser-arc", "~/Library/Application Support/Arc", BROWSER),
    rw(
        "browser-comet",
        "~/Library/Application Support/Comet",
        BROWSER,
    ),
    rw(
        "browser-firefox",
        "~/Library/Application Support/Firefox",
        BROWSER,
    ),
    rw(
        "browser-mozilla",
        "~/Library/Application Support/Mozilla",
        BROWSER,
    ),
    rw("browser-zen", "~/Library/Application Support/zen", BROWSER),
    rw(
        "browser-tor",
        "~/Library/Application Support/TorBrowser-Data",
        BROWSER,
    ),
    rw("browser-safari", "~/Library/Safari", BROWSER),
    rw("browser-cookies", "~/Library/Cookies", BROWSER),
    rw("browser-webkit", "~/Library/WebKit", BROWSER),
    rw("browser-http-storages", "~/Library/HTTPStorages", BROWSER),
    rw(
        "browser-safari-container",
        "~/Library/Containers/com.apple.Safari",
        BROWSER,
    ),
    rw(
        "browser-safari-broker",
        "~/Library/Group Containers/group.com.apple.Safari.SandboxBroker",
        BROWSER,
    ),
    rw("browser-cache-google", "~/Library/Caches/Google", BROWSER),
    rw("browser-cache-firefox", "~/Library/Caches/Firefox", BROWSER),
    rw("browser-cache-mozilla", "~/Library/Caches/Mozilla", BROWSER),
    rw(
        "browser-cache-safari",
        "~/Library/Caches/com.apple.Safari",
        BROWSER,
    ),
    rw("browser-cache-arc", "~/Library/Caches/Arc", BROWSER),
    rw(
        "browser-cache-arc-bundle",
        "~/Library/Caches/company.thebrowser.Browser",
        BROWSER,
    ),
    // Container runtimes (design sections 6 and 9).
    rw("containers-data", "~/.local/share/containers", CONTAINER),
    rw("containers-config", "~/.config/containers", CONTAINER),
    rw("docker-socket", "/var/run/docker.sock", CONTAINER),
    rw("podman-run", "/var/run/podman", CONTAINER),
    conn("connect-docker-socket", "/var/run/docker.sock", CONTAINER),
    conn("connect-podman-run", "/var/run/podman", CONTAINER),
    conn("connect-docker-run", "~/.docker/run", CONTAINER),
    conn("connect-colima", "~/.colima", CONTAINER),
    conn("connect-lima", "~/.lima", CONTAINER),
    conn("connect-rancher", "~/.rd", CONTAINER),
    conn("connect-orbstack", "~/.orbstack", CONTAINER),
    conn(
        "connect-docker-desktop",
        "~/Library/Containers/com.docker.docker",
        CONTAINER,
    ),
    conn(
        "connect-podman-data",
        "~/.local/share/containers",
        CONTAINER,
    ),
    // hamster-ball itself.
    rw("hb-config", "~/.config/hamster-ball", HB_STATE),
    rw("hb-state", "~/.local/state/hamster-ball", HB_STATE),
    // Shell startup and login files.
    wr("zshrc", "~/.zshrc", STARTUP),
    wr("zshenv", "~/.zshenv", STARTUP),
    wr("zprofile", "~/.zprofile", STARTUP),
    wr("zlogin", "~/.zlogin", STARTUP),
    wr("zlogout", "~/.zlogout", STARTUP),
    wr("bashrc", "~/.bashrc", STARTUP),
    wr("bash-profile", "~/.bash_profile", STARTUP),
    wr("bash-login", "~/.bash_login", STARTUP),
    wr("bash-logout", "~/.bash_logout", STARTUP),
    wr("profile", "~/.profile", STARTUP),
    wr("fish", "~/.config/fish", STARTUP),
    wr("cargo-env", "~/.cargo/env", STARTUP),
    wr("launch-agents", "~/Library/LaunchAgents", STARTUP),
    // Tool configuration that runs code.
    wr("gitconfig", "~/.gitconfig", TOOL_CONFIG),
    wr("git-config-dir", "~/.config/git", TOOL_CONFIG),
    wr("cargo-config-toml", "~/.cargo/config.toml", TOOL_CONFIG),
    wr("cargo-config", "~/.cargo/config", TOOL_CONFIG),
    wr("terraformrc", "~/.terraformrc", TOOL_CONFIG),
    wr("yarnrc", "~/.yarnrc", TOOL_CONFIG),
    wr("yarnrc-yml", "~/.yarnrc.yml", TOOL_CONFIG),
    wr("maven-settings", "~/.m2/settings.xml", TOOL_CONFIG),
    wr("pip-config", "~/.config/pip", TOOL_CONFIG),
    wr("uv-config", "~/.config/uv", TOOL_CONFIG),
    // Directories of programs.
    wr("bin-local", "~/.local/bin", PATH_DIR),
    wr("bin-cargo", "~/.cargo/bin", PATH_DIR),
    wr("bin-go", "~/go/bin", PATH_DIR),
    wr("bin-bun", "~/.bun/bin", PATH_DIR),
    wr("bin-homebrew", "/opt/homebrew/bin", PATH_DIR),
    wr("sbin-homebrew", "/opt/homebrew/sbin", PATH_DIR),
    wr("bin-usr-local", "/usr/local/bin", PATH_DIR),
];

// ======================================================================================
// Pins
// ======================================================================================

/// The directories to unlink-pin so `pattern` (at `extent`) cannot be moved aside.
///
/// Denying a path does not stop renaming one of its ancestors: `mv secrets secrets-old` moves a
/// denied file somewhere no rule covers. So every ancestor of the protected path that a writable
/// root reaches needs a pin. A glob rule, and a children-only rule, leave their own base
/// unprotected, so the base is pinned too; a plain subtree or node rule already protects its own
/// node. The symlink alias gets the same treatment. `/` is never pinned.
///
/// The floor builder and the renderer's user denies both use this, so they cannot diverge.
pub(crate) fn pin_ancestors(
    pattern: &PathPattern,
    extent: Extent,
    writable: &[&CanonicalPath],
) -> Vec<CanonicalPath> {
    let skip = usize::from(pattern.tail.is_none() && extent != Extent::Children);
    let bases = std::iter::once(&pattern.base).chain(pattern.alias.as_ref());
    let mut pins = Vec::new();
    for base in bases {
        for ancestor in base.as_path().ancestors().skip(skip) {
            if ancestor == std::path::Path::new("/") {
                continue;
            }
            let Ok(path) = CanonicalPath::from_canonical(ancestor) else {
                continue;
            };
            if writable
                .iter()
                .any(|root| root.is_same_or_ancestor_of(&path))
            {
                pins.push(path);
            }
        }
    }
    pins
}

// ======================================================================================
// PATH
// ======================================================================================

/// Most `PATH` entries accepted.
pub const MAX_PATH_ENTRIES: usize = 256;
/// Largest `PATH` value accepted, in bytes.
pub const MAX_PATH_VAR_BYTES: usize = 32 * 1024;
/// Characters of an entry kept in a diagnostic.
const PREVIEW_CHARS: usize = 64;

/// Why a `PATH` entry was not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum PathEntryProblem {
    /// An empty entry, which the shell reads as the current directory.
    Empty,
    /// Not an absolute path (`.`, `bin`, `~/bin`): it means a different directory in every shell.
    Relative,
    /// Not valid UTF-8.
    NotUtf8,
    /// Contains a control character.
    ControlCharacter,
    /// Longer than the path limit.
    TooLong,
}

/// A `PATH` entry that was not used, with a printable preview.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkippedPathEntry {
    /// Zero-based position in `PATH`.
    pub position: usize,
    /// Why.
    pub problem: PathEntryProblem,
    /// The entry, escaped and shortened for display.
    pub preview: String,
}

/// The usable and unusable entries of a `PATH` value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct PathEntries {
    /// Absolute entries in order, without exact duplicates.
    pub accepted: Vec<String>,
    /// Entries that were not used, in order.
    pub skipped: Vec<SkippedPathEntry>,
}

/// Why a `PATH` value was refused outright.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[non_exhaustive]
pub enum PathVarError {
    /// More bytes than [`MAX_PATH_VAR_BYTES`].
    #[snafu(display("PATH is {len} bytes long; the limit is {max}"))]
    TooLarge {
        /// Length in bytes.
        len: usize,
        /// The limit.
        max: usize,
    },
    /// More distinct usable entries (or more unusable ones) than [`MAX_PATH_ENTRIES`].
    #[snafu(display("PATH has {count} entries; the limit is {max}"))]
    TooManyEntries {
        /// Number of entries.
        count: usize,
        /// The limit.
        max: usize,
    },
}

/// Splits a `PATH` value into the entries the floor can protect and the ones it cannot.
///
/// Only absolute entries are used. The rest (empty, `.`, `bin`, an unexpanded `~/bin`) mean
/// different directories in different shells and are reported, not guessed at.
///
/// # Errors
/// [`PathVarError`] if the value is too large or has too many distinct entries.
pub fn parse_path_var(raw: &OsStr) -> Result<PathEntries, PathVarError> {
    let bytes = raw.as_bytes();
    if bytes.len() > MAX_PATH_VAR_BYTES {
        return TooLargeSnafu {
            len: bytes.len(),
            max: MAX_PATH_VAR_BYTES,
        }
        .fail();
    }
    let mut entries = PathEntries::default();
    for (position, part) in bytes.split(|b| *b == b':').enumerate() {
        match classify_entry(part) {
            Ok(entry) => {
                if !entries.accepted.iter().any(|seen| seen == entry) {
                    entries.accepted.push(entry.to_owned());
                }
            }
            Err(problem) => entries.skipped.push(SkippedPathEntry {
                position,
                problem,
                preview: EscapedBounded::new(&String::from_utf8_lossy(part), PREVIEW_CHARS)
                    .to_string(),
            }),
        }
        // Counted as they come, so a huge value cannot build a huge list first.
        let count = entries.accepted.len().max(entries.skipped.len());
        if count > MAX_PATH_ENTRIES {
            return TooManyEntriesSnafu {
                count,
                max: MAX_PATH_ENTRIES,
            }
            .fail();
        }
    }
    Ok(entries)
}

fn classify_entry(part: &[u8]) -> Result<&str, PathEntryProblem> {
    if part.is_empty() {
        return Err(PathEntryProblem::Empty);
    }
    let text = std::str::from_utf8(part).map_err(|_| PathEntryProblem::NotUtf8)?;
    if text.chars().any(char::is_control) {
        return Err(PathEntryProblem::ControlCharacter);
    }
    if text.len() > MAX_PATH_BYTES {
        return Err(PathEntryProblem::TooLong);
    }
    if !text.starts_with('/') {
        return Err(PathEntryProblem::Relative);
    }
    Ok(text)
}

// ======================================================================================
// gitdir pointer
// ======================================================================================

/// Most bytes of a `.git` pointer file that are read.
pub const MAX_GITDIR_POINTER_BYTES: usize = 1024;

const GITDIR_PREFIX: &str = "gitdir: ";

/// Why a `.git` pointer file was not accepted.
#[derive(Debug, Snafu, PartialEq, Eq)]
#[non_exhaustive]
pub enum GitdirError {
    /// Longer than [`MAX_GITDIR_POINTER_BYTES`].
    #[snafu(display("a .git file is longer than {max} bytes"))]
    PointerTooLong {
        /// The limit.
        max: usize,
    },
    /// Not valid UTF-8.
    #[snafu(display("a .git file is not valid UTF-8"))]
    PointerNotUtf8,
    /// Does not start with `gitdir: `.
    #[snafu(display("a .git file does not start with `gitdir: `"))]
    PointerMissingPrefix,
    /// Names no path.
    #[snafu(display("a .git file names no path"))]
    PointerEmpty,
    /// Contains a control character, or more than one line.
    #[snafu(display(
        "a .git file contains a control character or more than one line: {}",
        Escaped(preview)
    ))]
    PointerControlCharacter {
        /// The offending text, escaped when displayed.
        preview: String,
    },
}

/// The path a `.git` file points at, as written: absolute, or relative to the directory holding the file.
///
/// The text is untrusted (the project, and so the agent, can write it). It is only ever joined
/// to a directory and resolved; it is never expanded as a `~` or glob spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitdirPointer(String);

impl GitdirPointer {
    /// The path text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Parses the content of a `.git` file (`gitdir: <path>`), as git does: one line, with only the
/// line ending removed. Whitespace in the path is kept, because git keeps it: a directory named
/// `x ` is not the directory `x`.
///
/// # Errors
/// [`GitdirError`] if the content is too long, not text, not a pointer, or has control characters.
pub fn parse_gitdir_pointer(bytes: &[u8]) -> Result<GitdirPointer, GitdirError> {
    let path = single_line(bytes)?
        .strip_prefix(GITDIR_PREFIX)
        .context(PointerMissingPrefixSnafu)?;
    ensure!(!path.is_empty(), PointerEmptySnafu);
    Ok(GitdirPointer(path.to_owned()))
}

/// Parses the content of a `commondir` file: one path, relative to the git directory or absolute.
///
/// # Errors
/// [`GitdirError`] if the content is too long, not text, empty, or has control characters.
pub fn parse_commondir(bytes: &[u8]) -> Result<GitdirPointer, GitdirError> {
    let path = single_line(bytes)?;
    ensure!(!path.is_empty(), PointerEmptySnafu);
    Ok(GitdirPointer(path.to_owned()))
}

/// The one line of `bytes`, without its line ending.
fn single_line(bytes: &[u8]) -> Result<&str, GitdirError> {
    if bytes.len() > MAX_GITDIR_POINTER_BYTES {
        return PointerTooLongSnafu {
            max: MAX_GITDIR_POINTER_BYTES,
        }
        .fail();
    }
    let text = std::str::from_utf8(bytes)
        .ok()
        .context(PointerNotUtf8Snafu)?
        .trim_end_matches(['\n', '\r']);
    if text.chars().any(char::is_control) {
        return PointerControlCharacterSnafu {
            preview: EscapedBounded::new(text, PREVIEW_CHARS).to_string(),
        }
        .fail();
    }
    Ok(text)
}

/// The rule tails protected below a git directory (`GIT_DIR` or its common directory).
///
/// `commondir` is on the list because git takes `hooks` and `config` from the directory that
/// file names: writing it redirects both (verified with git 2.50). `worktrees/*/commondir` is
/// not, so `git worktree add` keeps working; a worktree only matters once something points a
/// `.git` file at it, and nested repositories are out of scope (D46).
///
/// `modules/**/hooks` does not match `hooks`, so each pair is listed; `**/hooks` is not used
/// because it also matches a branch named `hooks` under `refs/`.
pub(crate) const GIT_DIR_TAILS: &[(&str, &[&str])] = &[
    ("hooks", &["hooks"]),
    ("config", &["config"]),
    ("config-worktree", &["config.worktree"]),
    ("commondir", &["commondir"]),
    ("modules-hooks", &["modules", "**", "hooks"]),
    ("modules-config", &["modules", "**", "config"]),
    (
        "modules-config-worktree",
        &["modules", "**", "config.worktree"],
    ),
    ("modules-commondir", &["modules", "**", "commondir"]),
    ("worktrees-config", &["worktrees", "*", "config.worktree"]),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::GlobTail;
    use claims::{assert_err, assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::collections::HashSet;

    fn cp(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    const EXPECTED_TABLE_NAMES: &[&str] = &[
        "ssh",
        "aws",
        "gnupg",
        "netrc",
        "gh",
        "docker-config",
        "kube",
        "keychains",
        "git-credentials",
        "cargo-credentials",
        "op",
        "rclone",
        "gcloud",
        "azure",
        "oci",
        "doctl",
        "hub",
        "glab",
        "vault-token",
        "pgpass",
        "gem-credentials",
        "terraform-credentials",
        "pypirc",
        "npmrc",
        "1password-data",
        "1password-group",
        "history",
        "zsh-sessions",
        "atuin-data",
        "atuin-config",
        "browser-chrome",
        "browser-chromium",
        "browser-edge",
        "browser-edge-beta",
        "browser-edge-dev",
        "browser-edge-canary",
        "browser-vivaldi",
        "browser-vivaldi-snapshot",
        "browser-opera",
        "browser-brave",
        "browser-arc",
        "browser-comet",
        "browser-firefox",
        "browser-mozilla",
        "browser-zen",
        "browser-tor",
        "browser-safari",
        "browser-cookies",
        "browser-webkit",
        "browser-http-storages",
        "browser-safari-container",
        "browser-safari-broker",
        "browser-cache-google",
        "browser-cache-firefox",
        "browser-cache-mozilla",
        "browser-cache-safari",
        "browser-cache-arc",
        "browser-cache-arc-bundle",
        "containers-data",
        "containers-config",
        "docker-socket",
        "podman-run",
        "connect-docker-socket",
        "connect-podman-run",
        "connect-docker-run",
        "connect-colima",
        "connect-lima",
        "connect-rancher",
        "connect-orbstack",
        "connect-docker-desktop",
        "connect-podman-data",
        "hb-config",
        "hb-state",
        "zshrc",
        "zshenv",
        "zprofile",
        "zlogin",
        "zlogout",
        "bashrc",
        "bash-profile",
        "bash-login",
        "bash-logout",
        "profile",
        "fish",
        "cargo-env",
        "launch-agents",
        "gitconfig",
        "git-config-dir",
        "cargo-config-toml",
        "cargo-config",
        "terraformrc",
        "yarnrc",
        "yarnrc-yml",
        "maven-settings",
        "pip-config",
        "uv-config",
        "bin-local",
        "bin-cargo",
        "bin-go",
        "bin-bun",
        "bin-homebrew",
        "sbin-homebrew",
        "bin-usr-local",
    ];

    fn rule(name: &'static str, effect: FloorEffect, extent: Extent, base: &str) -> FloorRule {
        FloorRule::new(
            name,
            effect,
            extent,
            PathPattern {
                base: cp(base),
                alias: None,
                tail: None,
            },
            "test",
        )
    }

    fn floor_of(rules: Vec<FloorRule>) -> Floor {
        assert_ok!(Floor::new(rules))
    }

    fn os(s: &str) -> &OsStr {
        OsStr::new(s)
    }

    // ----- effects -----

    #[test]
    fn effects_forbid_the_accesses_they_name() {
        use FloorEffect::*;
        use FsAccess::*;
        let table = [
            (DenyReadWrite, Read, true),
            (DenyReadWrite, Write, true),
            (DenyReadWrite, Connect, false),
            (DenyWrite, Read, false),
            (DenyWrite, Write, true),
            (DenyWrite, Connect, false),
            (PinUnlink, Read, false),
            (PinUnlink, Write, true),
            (PinUnlink, Connect, false),
            (DenyConnect, Read, false),
            (DenyConnect, Write, false),
            (DenyConnect, Connect, true),
        ];
        for (effect, access, expected) in table {
            assert_eq!(effect.forbids(access), expected, "{effect:?} {access:?}");
        }
    }

    #[test]
    fn only_deny_effects_protect_writes() {
        assert!(FloorEffect::DenyReadWrite.protects_writes());
        assert!(FloorEffect::DenyWrite.protects_writes());
        assert!(!FloorEffect::PinUnlink.protects_writes());
        assert!(!FloorEffect::DenyConnect.protects_writes());
    }

    // ----- Floor::denying -----

    #[test]
    fn denying_reports_the_first_exact_match_for_the_access() {
        let floor = floor_of(vec![
            rule("a", FloorEffect::DenyWrite, Extent::Subtree, "/Users/me/x"),
            rule(
                "b",
                FloorEffect::DenyReadWrite,
                Extent::Subtree,
                "/Users/me/x",
            ),
        ]);
        let hit = assert_some!(floor.denying(&cp("/Users/me/x/f"), FsAccess::Write));
        assert_eq!(hit.rule.name, "a");
        assert_eq!(hit.id.index(), 0);
        assert!(!hit.folded);
        let hit = assert_some!(floor.denying(&cp("/Users/me/x/f"), FsAccess::Read));
        assert_eq!(hit.rule.name, "b");
    }

    #[test]
    fn denying_prefers_an_exact_match_over_a_folded_one() {
        let floor = floor_of(vec![
            rule(
                "upper",
                FloorEffect::DenyWrite,
                Extent::Subtree,
                "/Users/me/X",
            ),
            rule(
                "lower",
                FloorEffect::DenyWrite,
                Extent::Subtree,
                "/Users/me/x",
            ),
        ]);
        let hit = assert_some!(floor.denying(&cp("/Users/me/x"), FsAccess::Write));
        assert_eq!(hit.rule.name, "lower");
        assert!(!hit.folded);
        let only_folded = floor_of(vec![rule(
            "upper",
            FloorEffect::DenyWrite,
            Extent::Subtree,
            "/Users/me/X",
        )]);
        let hit = assert_some!(only_folded.denying(&cp("/Users/me/x"), FsAccess::Write));
        assert!(hit.folded);
    }

    #[test]
    fn a_pin_denies_writing_the_node_and_nothing_beneath() {
        let floor = floor_of(vec![rule(
            "pin",
            FloorEffect::PinUnlink,
            Extent::Node,
            "/Users/me/p/.git",
        )]);
        assert_some!(floor.denying(&cp("/Users/me/p/.git"), FsAccess::Write));
        assert_none!(floor.denying(&cp("/Users/me/p/.git/objects"), FsAccess::Write));
        assert_none!(floor.denying(&cp("/Users/me/p/.git"), FsAccess::Read));
    }

    #[test]
    fn a_connect_rule_forbids_only_connecting() {
        let floor = floor_of(vec![rule(
            "sock",
            FloorEffect::DenyConnect,
            Extent::Subtree,
            "/var/run/docker.sock",
        )]);
        assert_some!(floor.denying(&cp("/var/run/docker.sock"), FsAccess::Connect));
        assert_none!(floor.denying(&cp("/var/run/docker.sock"), FsAccess::Write));
        assert_none!(floor.denying(&cp("/var/run/docker.sock"), FsAccess::Read));
    }

    #[test]
    fn iter_ids_match_positions_and_rule_looks_them_up() {
        let floor = floor_of(vec![
            rule("a", FloorEffect::DenyWrite, Extent::Subtree, "/Users/me/a"),
            rule("b", FloorEffect::DenyWrite, Extent::Subtree, "/Users/me/b"),
        ]);
        for (id, rule) in floor.iter() {
            assert_eq!(assert_some!(floor.rule(id)), rule);
        }
        assert_eq!(floor.rules().len(), 2);
    }

    #[test]
    fn a_floor_over_the_limit_is_refused_not_shortened() {
        let r = rule("x", FloorEffect::DenyWrite, Extent::Subtree, "/Users/me/x");
        assert_ok!(Floor::new(vec![r.clone(); MAX_FLOOR_RULES]));
        let err = assert_err!(Floor::new(vec![r; MAX_FLOOR_RULES + 1]));
        assert_eq!(err.count, MAX_FLOOR_RULES + 1);
    }

    // ----- the table -----

    #[test]
    fn the_table_is_exactly_the_reviewed_set_of_names_in_order() {
        // A change to the floor must change this list, in the same commit that explains why.
        let names: Vec<&str> = TABLE.iter().map(|rule| rule.name).collect();
        assert_eq!(names, EXPECTED_TABLE_NAMES);
    }

    #[test]
    fn a_glob_tail_forces_the_subtree_extent() {
        let pattern = PathPattern {
            base: cp("/Users/me/x"),
            alias: None,
            tail: Some(assert_ok!(GlobTail::parse(&["*"]))),
        };
        let rule = FloorRule::new("g", FloorEffect::DenyWrite, Extent::Node, pattern, "test");
        assert_eq!(rule.extent, Extent::Subtree);
    }

    #[test]
    fn table_names_are_unique() {
        let names: HashSet<_> = TABLE.iter().map(|rule| rule.name).collect();
        assert_eq!(names.len(), TABLE.len());
    }

    #[test]
    fn table_bases_are_home_relative_or_absolute_and_never_firmlink_spelled() {
        for rule in TABLE {
            assert!(
                rule.base == "~" || rule.base.starts_with("~/") || rule.base.starts_with('/'),
                "{}",
                rule.name
            );
            assert!(
                !rule.base.starts_with("/System/Volumes/Data"),
                "{} uses the firmlink spelling",
                rule.name
            );
            assert!(
                !rule.base.contains(['*', '?']),
                "{} has a glob in its base",
                rule.name
            );
            assert!(
                !rule.base.ends_with('/') || rule.base == "/",
                "{}",
                rule.name
            );
        }
    }

    #[test]
    fn table_tails_parse_as_glob_tails() {
        for rule in TABLE.iter().filter(|rule| !rule.tail.is_empty()) {
            assert_ok!(GlobTail::parse(rule.tail));
        }
    }

    #[test]
    fn only_read_write_rules_carry_glob_tails() {
        for rule in TABLE.iter().filter(|rule| !rule.tail.is_empty()) {
            assert_eq!(rule.effect, FloorEffect::DenyReadWrite, "{}", rule.name);
        }
    }

    #[test]
    fn table_contains_every_design_section_6_entry() {
        let names: HashSet<_> = TABLE.iter().map(|rule| rule.name).collect();
        for expected in [
            "ssh",
            "aws",
            "gnupg",
            "netrc",
            "gh",
            "docker-config",
            "kube",
            "keychains",
            "containers-data",
            "containers-config",
            "docker-socket",
            "hb-config",
            "hb-state",
            "zshrc",
            "zshenv",
            "zprofile",
            "bashrc",
            "profile",
            "launch-agents",
            "bin-local",
            "bin-cargo",
            "bin-go",
            "bin-bun",
        ] {
            assert!(names.contains(expected), "missing {expected}");
        }
    }

    #[test]
    fn socket_rules_carry_the_connect_effect() {
        let connects: Vec<_> = TABLE
            .iter()
            .filter(|rule| rule.effect == FloorEffect::DenyConnect)
            .map(|rule| rule.base)
            .collect();
        for expected in [
            "/var/run/docker.sock",
            "/var/run/podman",
            "~/.docker/run",
            "~/.colima",
        ] {
            assert!(
                connects.contains(&expected),
                "missing connect rule {expected}"
            );
        }
    }

    #[test]
    fn credentials_are_read_write_denied_and_startup_files_are_write_denied() {
        let effect = |name: &str| {
            TABLE
                .iter()
                .find(|rule| rule.name == name)
                .map(|rule| rule.effect)
        };
        assert_eq!(effect("ssh"), Some(FloorEffect::DenyReadWrite));
        assert_eq!(effect("npmrc"), Some(FloorEffect::DenyReadWrite));
        assert_eq!(effect("zshrc"), Some(FloorEffect::DenyWrite));
        assert_eq!(effect("gitconfig"), Some(FloorEffect::DenyWrite));
    }

    // ----- pin_ancestors -----

    fn pattern_at(base: &str) -> PathPattern {
        PathPattern {
            base: cp(base),
            alias: None,
            tail: None,
        }
    }

    fn pin_texts(pattern: &PathPattern, extent: Extent, roots: &[&str]) -> Vec<String> {
        let roots: Vec<CanonicalPath> = roots.iter().map(|r| cp(r)).collect();
        let refs: Vec<&CanonicalPath> = roots.iter().collect();
        pin_ancestors(pattern, extent, &refs)
            .iter()
            .map(|p| p.as_str().to_owned())
            .collect()
    }

    #[test]
    fn a_subtree_rule_pins_its_ancestors_inside_a_writable_root_but_not_itself_or_the_root_above() {
        let pins = pin_texts(
            &pattern_at("/Users/me/p/a/b"),
            Extent::Subtree,
            &["/Users/me/p"],
        );
        assert_eq!(pins, ["/Users/me/p/a", "/Users/me/p"]);
    }

    #[test]
    fn nothing_is_pinned_when_no_writable_root_reaches_the_path() {
        assert!(
            pin_texts(
                &pattern_at("/Users/me/p/a"),
                Extent::Subtree,
                &["/Users/me/other"]
            )
            .is_empty()
        );
        assert!(pin_texts(&pattern_at("/Users/me/p/a"), Extent::Subtree, &[]).is_empty());
    }

    #[test]
    fn a_glob_or_children_rule_also_pins_its_own_base() {
        let glob = PathPattern {
            tail: Some(assert_ok!(GlobTail::parse(&["*.yaml"]))),
            ..pattern_at("/Users/me/p/secrets")
        };
        assert_eq!(
            pin_texts(&glob, Extent::Subtree, &["/Users/me/p"]),
            ["/Users/me/p/secrets", "/Users/me/p"]
        );
        assert_eq!(
            pin_texts(
                &pattern_at("/Users/me/p/bin"),
                Extent::Children,
                &["/Users/me/p"]
            ),
            ["/Users/me/p/bin", "/Users/me/p"]
        );
    }

    #[test]
    fn a_symlink_alias_is_pinned_like_the_base_and_the_filesystem_root_never() {
        let aliased = PathPattern {
            alias: Some(cp("/Users/me/p/link")),
            ..pattern_at("/Users/me/p/real/target")
        };
        let pins = pin_texts(&aliased, Extent::Subtree, &["/Users/me/p"]);
        assert!(pins.contains(&"/Users/me/p/real".to_owned()), "{pins:?}");
        assert!(pins.contains(&"/Users/me/p".to_owned()));
        assert!(!pin_texts(&pattern_at("/a"), Extent::Subtree, &["/"]).contains(&"/".to_owned()));
    }

    // ----- PATH -----

    #[test]
    fn path_keeps_absolute_entries_in_order_without_duplicates() {
        let parsed = assert_ok!(parse_path_var(os("/usr/bin:/opt/x/bin:/usr/bin")));
        assert_eq!(parsed.accepted, ["/usr/bin", "/opt/x/bin"]);
        assert!(parsed.skipped.is_empty());
    }

    #[test]
    fn path_reports_empty_dot_relative_and_tilde_entries() {
        let parsed = assert_ok!(parse_path_var(os("/usr/bin::.:bin:~/.cargo/bin:/ok")));
        assert_eq!(parsed.accepted, ["/usr/bin", "/ok"]);
        let problems: Vec<_> = parsed
            .skipped
            .iter()
            .map(|s| (s.position, s.problem))
            .collect();
        assert_eq!(
            problems,
            [
                (1, PathEntryProblem::Empty),
                (2, PathEntryProblem::Relative),
                (3, PathEntryProblem::Relative),
                (4, PathEntryProblem::Relative),
            ]
        );
    }

    #[test]
    fn path_rejects_control_characters_and_non_utf8() {
        let parsed = assert_ok!(parse_path_var(os("/a\nb:/ok")));
        assert_eq!(parsed.accepted, ["/ok"]);
        assert_eq!(
            parsed.skipped[0].problem,
            PathEntryProblem::ControlCharacter
        );
        assert!(!parsed.skipped[0].preview.contains('\n'));

        let raw = OsStr::from_bytes(b"/a\xff:/ok");
        let parsed = assert_ok!(parse_path_var(raw));
        assert_eq!(parsed.skipped[0].problem, PathEntryProblem::NotUtf8);
    }

    #[test]
    fn path_rejects_an_overlong_entry_but_keeps_the_rest() {
        let long = format!("/{}", "a".repeat(MAX_PATH_BYTES));
        let parsed = assert_ok!(parse_path_var(os(&format!("{long}:/ok"))));
        assert_eq!(parsed.accepted, ["/ok"]);
        assert_eq!(parsed.skipped[0].problem, PathEntryProblem::TooLong);
    }

    #[test]
    fn path_skipped_preview_is_bounded_and_escaped() {
        let hostile = format!("x\u{202e}{}", "y".repeat(500));
        let parsed = assert_ok!(parse_path_var(os(&hostile)));
        let preview = &parsed.skipped[0].preview;
        assert!(preview.len() < 200, "{}", preview.len());
        assert!(!preview.contains('\u{202e}'));
    }

    #[test]
    fn path_counts_unique_usable_entries_not_repeats_or_skipped_ones() {
        let repeated = vec!["/a"; MAX_PATH_ENTRIES * 3].join(":");
        let parsed = assert_ok!(parse_path_var(os(&repeated)));
        assert_eq!(parsed.accepted, ["/a"]);
        let many_skipped = vec!["rel"; 50].join(":");
        assert_ok!(parse_path_var(os(&many_skipped)));
    }

    #[test]
    fn path_refuses_too_many_unique_entries_and_too_many_bytes() {
        let unique = |n: usize| {
            (0..n)
                .map(|i| format!("/d{i}"))
                .collect::<Vec<_>>()
                .join(":")
        };
        let many = unique(MAX_PATH_ENTRIES + 1);
        assert!(matches!(
            assert_err!(parse_path_var(os(&many))),
            PathVarError::TooManyEntries { .. }
        ));
        let big = "a".repeat(MAX_PATH_VAR_BYTES + 1);
        assert!(matches!(
            assert_err!(parse_path_var(os(&big))),
            PathVarError::TooLarge { .. }
        ));
        assert_ok!(parse_path_var(os(&unique(MAX_PATH_ENTRIES))));
        let skipped = vec!["rel"; MAX_PATH_ENTRIES + 1]
            .iter()
            .enumerate()
            .map(|(i, r)| format!("{r}{i}"))
            .collect::<Vec<_>>()
            .join(":");
        assert!(matches!(
            assert_err!(parse_path_var(os(&skipped))),
            PathVarError::TooManyEntries { .. }
        ));
    }

    #[test]
    fn path_size_and_entry_length_limits_are_inclusive() {
        let exactly = format!("/{}", "a".repeat(MAX_PATH_VAR_BYTES - 1));
        assert_eq!(exactly.len(), MAX_PATH_VAR_BYTES);
        let parsed = assert_ok!(parse_path_var(os(&exactly)));
        assert_eq!(parsed.skipped[0].problem, PathEntryProblem::TooLong);
        let over = format!("{exactly}a");
        assert!(matches!(
            assert_err!(parse_path_var(os(&over))),
            PathVarError::TooLarge { .. }
        ));
        let longest = format!("/{}", "b".repeat(MAX_PATH_BYTES - 1));
        assert_eq!(assert_ok!(parse_path_var(os(&longest))).accepted, [longest]);
    }

    #[test]
    fn an_empty_path_variable_is_one_empty_entry() {
        let parsed = assert_ok!(parse_path_var(os("")));
        assert!(parsed.accepted.is_empty());
        assert_eq!(parsed.skipped.len(), 1);
    }

    // ----- gitdir pointer -----

    #[test]
    fn a_pointer_yields_its_path_without_the_line_ending_and_nothing_else_trimmed() {
        let p = assert_ok!(parse_gitdir_pointer(b"gitdir: ../.git/modules/x\n"));
        assert_eq!(p.as_str(), "../.git/modules/x");
        let p = assert_ok!(parse_gitdir_pointer(b"gitdir: /abs/path"));
        assert_eq!(p.as_str(), "/abs/path");
        let p = assert_ok!(parse_gitdir_pointer(b"gitdir: ~/x\r\n"));
        assert_eq!(p.as_str(), "~/x");
        // Git keeps whitespace in the path, so a directory named `x ` is a different
        // directory from `x`; trimming it would protect the wrong one.
        let p = assert_ok!(parse_gitdir_pointer(b"gitdir: ../real.git \n"));
        assert_eq!(p.as_str(), "../real.git ");
        let p = assert_ok!(parse_gitdir_pointer(
            "gitdir: ../real.git\u{3000}".as_bytes()
        ));
        assert_eq!(p.as_str(), "../real.git\u{3000}");
        let p = assert_ok!(parse_gitdir_pointer(b"gitdir:  two-leading"));
        assert_eq!(p.as_str(), " two-leading");
    }

    #[test]
    fn a_pointer_of_exactly_the_size_limit_is_accepted() {
        let path = "a".repeat(MAX_GITDIR_POINTER_BYTES - GITDIR_PREFIX.len());
        let text = format!("{GITDIR_PREFIX}{path}");
        assert_eq!(text.len(), MAX_GITDIR_POINTER_BYTES);
        assert_eq!(
            assert_ok!(parse_gitdir_pointer(text.as_bytes())).as_str(),
            path
        );
    }

    #[test]
    fn a_pointer_is_rejected_when_malformed() {
        assert_eq!(
            assert_err!(parse_gitdir_pointer(b"not a pointer")),
            GitdirError::PointerMissingPrefix
        );
        assert_eq!(
            assert_err!(parse_gitdir_pointer(b"gitdir: \n")),
            GitdirError::PointerEmpty
        );
        assert_eq!(
            assert_err!(parse_gitdir_pointer(b"gitdir: \xff")),
            GitdirError::PointerNotUtf8
        );
        assert!(matches!(
            assert_err!(parse_gitdir_pointer(b"gitdir: a\0b")),
            GitdirError::PointerControlCharacter { .. }
        ));
        assert!(matches!(
            assert_err!(parse_gitdir_pointer(b"gitdir: a\nextra")),
            GitdirError::PointerControlCharacter { .. }
        ));
        let long = format!("gitdir: {}", "a".repeat(MAX_GITDIR_POINTER_BYTES));
        assert!(matches!(
            assert_err!(parse_gitdir_pointer(long.as_bytes())),
            GitdirError::PointerTooLong { .. }
        ));
    }

    #[test]
    fn a_pointer_error_message_does_not_carry_raw_control_characters() {
        let message = assert_err!(parse_gitdir_pointer(b"gitdir: \x1b[2Jx\ny")).to_string();
        assert!(!message.contains('\x1b'));
        assert!(!message.contains('\n'));
    }

    #[test]
    fn a_commondir_is_one_path() {
        let p = assert_ok!(parse_commondir(b"../..\n"));
        assert_eq!(p.as_str(), "../..");
        let p = assert_ok!(parse_commondir(b"../../evil  \n"));
        assert_eq!(p.as_str(), "../../evil  ");
        assert_eq!(
            assert_err!(parse_commondir(b"\n")),
            GitdirError::PointerEmpty
        );
        assert!(matches!(
            assert_err!(parse_commondir(b"a\0b")),
            GitdirError::PointerControlCharacter { .. }
        ));
    }

    // ----- git tails -----

    #[test]
    fn git_dir_tails_parse_and_cover_the_intended_paths() {
        for (_, tail) in GIT_DIR_TAILS {
            assert_ok!(GlobTail::parse(tail));
        }
        let base = "/Users/me/p/.git";
        let covers = |tail: &[&str], path: &str| {
            PathPattern {
                base: cp(base),
                alias: None,
                tail: Some(assert_ok!(GlobTail::parse(tail))),
            }
            .covers(&cp(path))
                != Coverage::No
        };
        assert!(covers(&["hooks"], "/Users/me/p/.git/hooks/pre-commit"));
        assert!(covers(&["commondir"], "/Users/me/p/.git/commondir"));
        assert!(covers(
            &["modules", "**", "commondir"],
            "/Users/me/p/.git/modules/a/commondir"
        ));
        assert!(covers(
            &["modules", "**", "hooks"],
            "/Users/me/p/.git/modules/a/b/hooks/x"
        ));
        assert!(!covers(
            &["modules", "**", "hooks"],
            "/Users/me/p/.git/hooks"
        ));
        assert!(!covers(&["hooks"], "/Users/me/p/.git/refs/heads/hooks"));
        assert!(covers(
            &["worktrees", "*", "config.worktree"],
            "/Users/me/p/.git/worktrees/w1/config.worktree"
        ));
    }
}
