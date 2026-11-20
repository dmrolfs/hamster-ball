// ABOUTME: Builds the floor for one project: resolves the compiled table, derives project, PATH and pin rules from the real filesystem.
// ABOUTME: Fails closed: a table or project rule that cannot be resolved is an error, never a lexical guess.
//! Building the [`Floor`] (design section 6).
//!
//! The compiled table ([`crate::policy::floor`]) is resolved against the real filesystem so every
//! rule names a canonical path. On top of the table, [`build_floor`] derives:
//!
//! - **project rules**: the project config and every approval file, the `.git` directory's
//!   hooks and config (however `.git` is laid out: directory, `gitdir:` file, symlink, missing),
//!   and the same for any enclosing repository;
//! - **`PATH` rules**: every absolute `PATH` entry, the programs those entries point at when
//!   they sit under a write grant, and `hb` itself;
//! - **pins**: an unlink pin on each ancestor of a protected path that a write grant reaches,
//!   because a denied path can otherwise be moved aside by renaming an ancestor.
//!
//! A path a rule needs that cannot be resolved is an error ([`FloorError`]): a dangling link at
//! a protected location is exactly where something could be planted. `PATH` entries are the
//! exception, because a broken `PATH` must not stop `hb`; they are skipped with a diagnostic.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use snafu::{ResultExt, Snafu};
use strum::IntoStaticStr;

use super::resolver::{DenyResolution, PathResolver};
use crate::policy::floor::{
    GIT_DIR_TAILS, PATH_DIR as REASON_PATH, TABLE, TableRule, USER_TEMP_PODMAN, pin_ancestors,
};
use crate::policy::{
    CanonicalPath, Extent, Floor, FloorEffect, FloorGroup, FloorRule, FloorTooLarge, GitdirError,
    GlobTail, GlobTailError, HomeDir, MAX_GITDIR_POINTER_BYTES, PathError, PathPattern,
    PathVarError, ProjectRoot, SkippedPathEntry, parse_commondir, parse_gitdir_pointer,
    parse_path_var,
};
use crate::text::Escaped;

/// The `PATH` used when none is given.
const DEFAULT_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Most enclosing directories searched for a repository.
const MAX_ENCLOSING_LEVELS: usize = 32;
/// Most files in a `hooks` directory that are checked for hard links.
const MAX_HOOK_FILES_CHECKED: usize = 256;
/// Most symlink targets protected, so a huge `/opt/homebrew/bin` cannot grow the profile without bound.
pub const MAX_PATH_TARGETS: usize = 256;
/// Most directory entries examined per `PATH` directory.
const MAX_ENTRIES_PER_PATH_DIR: usize = 8192;
/// Most directory entries examined across all `PATH` directories.
const MAX_ENTRIES_TOTAL: usize = 50_000;

const REASON_PROJECT: &str =
    "the project's config, which the agent must not change to widen itself";
const REASON_GIT: &str = "git runs hooks and config outside the sandbox";
const REASON_TARGET: &str = "the program a PATH entry points to, which you run outside the sandbox";
const REASON_EXE: &str = "hb itself";
const REASON_PIN: &str = "keeps a protected path from being moved aside by renaming an ancestor";
const REASON_TEMP: &str = "container runtime access is host access";

/// What `hb` reads from the process once, so the floor never consults the environment itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FloorEnvironment {
    /// The `PATH` variable, if set.
    pub path_var: Option<OsString>,
    /// The per-user temporary directory (`confstr(_CS_DARWIN_USER_TEMP_DIR)`), if known.
    pub user_temp_dir: Option<PathBuf>,
    /// The running `hb` executable, if known.
    pub hb_exe: Option<PathBuf>,
}

impl FloorEnvironment {
    /// An environment with nothing set: the default `PATH`, and no temp directory or `hb` path.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets `PATH`.
    #[must_use]
    pub fn with_path_var(mut self, path_var: impl Into<OsString>) -> Self {
        self.path_var = Some(path_var.into());
        self
    }

    /// Sets the per-user temporary directory.
    #[must_use]
    pub fn with_user_temp_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.user_temp_dir = Some(dir.into());
        self
    }

    /// Sets the running executable.
    #[must_use]
    pub fn with_hb_exe(mut self, exe: impl Into<PathBuf>) -> Self {
        self.hb_exe = Some(exe.into());
        self
    }
}

/// Everything [`build_floor`] needs.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FloorInputs<'a> {
    /// The home directory.
    pub home: &'a HomeDir,
    /// The project root.
    pub root: &'a ProjectRoot,
    /// What was read from the process.
    pub env: &'a FloorEnvironment,
    /// Canonical paths of the config files the sandbox could write (they need approval).
    pub approval_files: &'a [CanonicalPath],
    /// Every directory the agent can write: the closure's `fs.write` grants, and (once the
    /// renderer adds them) the system write allows such as the temp directories. Pins and
    /// program-link protection only reach what is listed here.
    pub write_grants: &'a [CanonicalPath],
}

impl<'a> FloorInputs<'a> {
    /// Inputs for `root`.
    #[must_use]
    pub fn new(
        home: &'a HomeDir,
        root: &'a ProjectRoot,
        env: &'a FloorEnvironment,
        approval_files: &'a [CanonicalPath],
        write_grants: &'a [CanonicalPath],
    ) -> Self {
        Self {
            home,
            root,
            env,
            approval_files,
            write_grants,
        }
    }
}

/// Something about the floor the user should know, which is not an error.
#[derive(Debug, Clone, PartialEq, Eq, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum FloorDiagnostic {
    /// A `PATH` entry that is not an absolute path was not used.
    PathEntrySkipped(SkippedPathEntry),
    /// A `PATH` entry could not be resolved and was not used.
    PathEntryUnresolvable {
        /// The entry as it appears in `PATH`.
        entry: String,
        /// Why it could not be resolved.
        reason: String,
    },
    /// A `PATH` entry inside the project is not write-denied, because that would stop package
    /// managers installing into the project.
    PathEntryInsideProject {
        /// The entry.
        path: CanonicalPath,
    },
    /// A `PATH` entry equals or contains the project, your home or a write grant, so only its
    /// direct children are write-denied.
    PathEntryContainsProtected {
        /// The entry.
        path: CanonicalPath,
    },
    /// More programs than the limit are linked from `PATH` directories into a write grant; only
    /// the first by path are protected.
    PathTargetsTruncated {
        /// The limit.
        limit: usize,
    },
    /// `PATH` directories hold more entries than were examined.
    PathScanTruncated,
    /// `hb` itself is inside the project.
    HbExeInsideProject {
        /// Its path.
        path: CanonicalPath,
    },
    /// `hb`'s own path could not be protected.
    HbExeUnusable {
        /// Why.
        reason: String,
    },
    /// The per-user temporary directory is unknown, so its podman socket directory is not covered.
    UserTempDirUnknown,
    /// A protected file has other hard links, which a path rule cannot see.
    HardLinkedFloorFile {
        /// The file.
        path: PathBuf,
        /// Its link count.
        links: u64,
    },
    /// A repository above the project could not be protected.
    EnclosingRepoSkipped {
        /// The directory holding its `.git`.
        dir: String,
        /// Why.
        reason: String,
    },
}

impl fmt::Display for FloorDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathEntrySkipped(entry) => write!(
                f,
                "PATH entry {} (`{}`) was not protected: {}",
                entry.position,
                Escaped(&entry.preview),
                entry.problem
            ),
            Self::PathEntryUnresolvable { entry, reason } => write!(
                f,
                "PATH entry `{}` could not be resolved ({}) and was not protected",
                Escaped(entry),
                Escaped(reason)
            ),
            Self::PathEntryInsideProject { path } => write!(
                f,
                "PATH entry `{}` is inside the project and is not write-protected",
                Escaped(path.as_str())
            ),
            Self::PathEntryContainsProtected { path } => write!(
                f,
                "PATH entry `{}` contains the project, your home or a write grant; only its direct children are write-protected",
                Escaped(path.as_str())
            ),
            Self::PathTargetsTruncated { limit } => write!(
                f,
                "more than {limit} programs on PATH link into a write grant; the rest are not protected"
            ),
            Self::PathScanTruncated => {
                f.write_str("PATH directories are large; not every entry was examined")
            }
            Self::HbExeInsideProject { path } => write!(
                f,
                "hb is inside the project (`{}`); it is write-protected there too",
                Escaped(path.as_str())
            ),
            Self::HbExeUnusable { reason } => {
                write!(f, "hb's own path was not protected: {}", Escaped(reason))
            }
            Self::UserTempDirUnknown => f.write_str(
                "the per-user temporary directory is unknown; its podman socket directory is not covered",
            ),
            Self::HardLinkedFloorFile { path, links } => write!(
                f,
                "`{}` has {links} hard links; a path rule cannot protect the other names",
                Escaped(&path.to_string_lossy())
            ),
            Self::EnclosingRepoSkipped { dir, reason } => write!(
                f,
                "the repository at `{}` was not protected: {}",
                Escaped(dir),
                Escaped(reason)
            ),
        }
    }
}

impl FloorDiagnostic {
    /// A stable machine-readable name for the kind of diagnostic.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        self.into()
    }
}

/// The floor and what building it noticed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct BuiltFloor {
    /// The rules.
    pub floor: Floor,
    /// Things worth reporting, in the order they were found.
    pub diagnostics: Vec<FloorDiagnostic>,
}

/// Why the floor could not be built.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum FloorError {
    /// A compiled or derived rule's path cannot be resolved.
    #[snafu(display(
        "floor rule `{rule}` cannot be resolved at `{}`; fix or remove what is there (a dangling or looping symlink, or a file where a directory should be)",
        Escaped(spelling)
    ))]
    Resolve {
        /// The rule's name.
        rule: String,
        /// The path as spelled.
        spelling: String,
        /// Why.
        source: PathError,
    },

    /// A compiled rule's glob is malformed (a bug in this build).
    #[snafu(display("floor rule `{rule}` has a malformed glob"))]
    Table {
        /// The rule's name.
        rule: String,
        /// Why.
        source: GlobTailError,
    },

    /// `PATH` is too large to protect.
    #[snafu(display("PATH cannot be protected; shorten it"))]
    PathVar {
        /// Why.
        source: PathVarError,
    },

    /// A file or directory under the project's `.git` could not be inspected.
    #[snafu(display("cannot inspect `{}` to protect git's hooks and config", Escaped(path)))]
    GitIo {
        /// The path.
        path: String,
        /// Why.
        source: io::Error,
    },

    /// A `.git` entry is not a directory, file or symlink.
    #[snafu(display(
        "`{}` is not a directory or file; git's hooks and config cannot be protected",
        Escaped(path)
    ))]
    GitUnsupported {
        /// The path.
        path: String,
    },

    /// A `.git` file does not hold a valid pointer.
    #[snafu(display("`{}` is not a valid git pointer", Escaped(path)))]
    GitPointer {
        /// The path.
        path: String,
        /// Why.
        source: GitdirError,
    },

    /// The place a `.git` file points to cannot be resolved.
    #[snafu(display("the git directory `{}` points to cannot be resolved", Escaped(path)))]
    GitResolve {
        /// The `.git` entry.
        path: String,
        /// Why.
        source: PathError,
    },

    /// The floor would be too large.
    #[snafu(display("the floor is too large"))]
    TooLarge {
        /// Why.
        source: FloorTooLarge,
    },
}

/// Builds the floor for `inputs`.
///
/// # Errors
/// [`FloorError`] if a compiled rule or a project rule cannot be resolved, or `PATH` is too
/// large. A `PATH` entry that cannot be used is a diagnostic, not an error.
pub fn build_floor(inputs: &FloorInputs<'_>) -> Result<BuiltFloor, FloorError> {
    build_floor_with(inputs, ScanLimits::default())
}

/// How much of the `PATH` directories to examine.
#[derive(Debug, Clone, Copy)]
struct ScanLimits {
    /// Entries examined in one directory.
    per_dir: usize,
    /// Entries examined across all directories.
    total: usize,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            per_dir: MAX_ENTRIES_PER_PATH_DIR,
            total: MAX_ENTRIES_TOTAL,
        }
    }
}

fn build_floor_with(
    inputs: &FloorInputs<'_>,
    limits: ScanLimits,
) -> Result<BuiltFloor, FloorError> {
    let mut builder = Builder::new(inputs, limits);
    builder.table()?;
    builder.user_temp_dir()?;
    builder.project()?;
    builder.path_entries()?;
    builder.hb_exe();
    builder.path_targets();
    builder.pins();
    builder.finish()
}

/// Accumulates rules and diagnostics.
struct Builder<'a> {
    inputs: &'a FloorInputs<'a>,
    resolver: PathResolver<'a>,
    /// Write grants plus the project root: where an agent can rename things.
    writable: Vec<&'a CanonicalPath>,
    limits: ScanLimits,
    rules: Vec<FloorRule>,
    seen: HashSet<RuleKey>,
    diagnostics: Vec<FloorDiagnostic>,
}

/// What makes two rules the same rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuleKey {
    effect: FloorEffect,
    extent: Extent,
    pattern: PathPattern,
}

impl<'a> Builder<'a> {
    fn new(inputs: &'a FloorInputs<'a>, limits: ScanLimits) -> Self {
        let writable = inputs
            .write_grants
            .iter()
            .chain(std::iter::once(inputs.root.path()))
            .collect();
        Self {
            inputs,
            resolver: PathResolver::new(inputs.home, inputs.root),
            writable,
            limits,
            rules: Vec::new(),
            seen: HashSet::new(),
            diagnostics: Vec::new(),
        }
    }

    /// Adds `rule` unless an identical one is already present.
    fn push(&mut self, rule: FloorRule) {
        let key = RuleKey {
            effect: rule.effect,
            extent: rule.extent,
            pattern: rule.pattern.clone(),
        };
        if self.seen.insert(key) {
            self.rules.push(rule);
        }
    }

    fn resolve(&self, rule: &str, spelling: &str) -> Result<DenyResolution, FloorError> {
        self.resolver.deny(spelling).context(ResolveSnafu {
            rule: rule.to_owned(),
            spelling: spelling.to_owned(),
        })
    }

    fn literal(resolution: DenyResolution) -> PathPattern {
        PathPattern {
            base: resolution.target,
            alias: resolution.alias,
            tail: None,
        }
    }

    // ---- the table ----

    fn table(&mut self) -> Result<(), FloorError> {
        for row in TABLE {
            let rule = self.table_rule(row)?;
            self.push(rule);
        }
        Ok(())
    }

    fn table_rule(&self, row: &TableRule) -> Result<FloorRule, FloorError> {
        let DenyResolution { target, alias } = self.resolve(row.name, row.base)?;
        let tail = if row.tail.is_empty() {
            None
        } else {
            Some(GlobTail::parse(row.tail).context(TableSnafu { rule: row.name })?)
        };
        Ok(FloorRule::new(
            row.name,
            row.effect,
            Extent::Subtree,
            PathPattern {
                base: target,
                alias,
                tail,
            },
            row.reason,
        ))
    }

    fn user_temp_dir(&mut self) -> Result<(), FloorError> {
        let Some(dir) = &self.inputs.env.user_temp_dir else {
            self.diagnostics.push(FloorDiagnostic::UserTempDirUnknown);
            return Ok(());
        };
        let Some(dir) = dir.to_str() else {
            self.diagnostics.push(FloorDiagnostic::UserTempDirUnknown);
            return Ok(());
        };
        let spelling = join(dir, USER_TEMP_PODMAN);
        let resolution = self.resolve("connect-podman-temp", &spelling)?;
        self.push(FloorRule::new(
            "connect-podman-temp",
            FloorEffect::DenyConnect,
            Extent::Subtree,
            Self::literal(resolution),
            REASON_TEMP,
        ));
        Ok(())
    }

    // ---- the project ----

    fn project(&mut self) -> Result<(), FloorError> {
        let root = self.inputs.root.path().as_str().to_owned();
        let config = join(&root, "hamster-ball.toml");
        self.protect_file("project-config", &config, REASON_PROJECT)?;
        for file in self.inputs.approval_files {
            self.protect_file("approval-file", file.as_str(), REASON_PROJECT)?;
        }

        self.git_for(&root).map(|rules| self.extend(rules))?;

        for ancestor in Path::new(&root)
            .ancestors()
            .skip(1)
            .take(MAX_ENCLOSING_LEVELS)
        {
            let Some(dir) = ancestor.to_str() else {
                continue;
            };
            match self.git_for(dir) {
                Ok(rules) => self.extend(rules),
                Err(error) => self
                    .diagnostics
                    .push(FloorDiagnostic::EnclosingRepoSkipped {
                        dir: dir.to_owned(),
                        reason: snafu::Report::from_error(error).to_string(),
                    }),
            }
        }
        Ok(())
    }

    fn extend(&mut self, rules: Vec<FloorRule>) {
        for rule in rules {
            self.push(rule);
        }
    }

    /// Write-protects one file and notes it if it has other hard links.
    fn protect_file(
        &mut self,
        name: &'static str,
        spelling: &str,
        reason: &'static str,
    ) -> Result<(), FloorError> {
        let resolution = self.resolve(name, spelling)?;
        self.push(
            FloorRule::new(
                name,
                FloorEffect::DenyWrite,
                Extent::Subtree,
                Self::literal(resolution),
                reason,
            )
            .in_group(FloorGroup::Project),
        );
        self.note_hard_links(Path::new(spelling));
        Ok(())
    }

    fn note_hard_links(&mut self, path: &Path) {
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.is_file() && meta.nlink() > 1 {
                self.diagnostics.push(FloorDiagnostic::HardLinkedFloorFile {
                    path: path.to_path_buf(),
                    links: meta.nlink(),
                });
            }
        }
    }

    /// The rules for the `.git` entry directly inside `dir`, or none if there is no repository.
    ///
    /// Collected before being added so a failure partway adds nothing.
    fn git_for(&mut self, dir: &str) -> Result<Vec<FloorRule>, FloorError> {
        let is_project_root = dir == self.inputs.root.path().as_str();
        let git = join(dir, ".git");
        let meta = match fs::symlink_metadata(&git) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                if !is_project_root {
                    return Ok(Vec::new());
                }
                // Nothing there now. Deny creating it: a `.git` file the agent writes could
                // point git at a directory of its own, hooks included.
                let resolution = self.resolve("git-missing", &git)?;
                return Ok(vec![
                    FloorRule::new(
                        "git-missing",
                        FloorEffect::DenyWrite,
                        Extent::Node,
                        Self::literal(resolution),
                        REASON_GIT,
                    )
                    .in_group(FloorGroup::Project),
                ]);
            }
            Err(source) => return Err(source).context(GitIoSnafu { path: git }),
        };

        let mut rules = Vec::new();
        let (entry, meta) = if meta.is_symlink() {
            // Protect the link's own name, then treat what it points at as the entry.
            let resolution = self.resolve("git-link", &git)?;
            let target = resolution.target.as_str().to_owned();
            rules.push(
                FloorRule::new(
                    "git-link",
                    FloorEffect::DenyWrite,
                    Extent::Node,
                    Self::literal(resolution),
                    REASON_GIT,
                )
                .in_group(FloorGroup::Project),
            );
            let meta = fs::metadata(&target).context(GitIoSnafu { path: git.clone() })?;
            (target, meta)
        } else {
            (git.clone(), meta)
        };

        if meta.is_dir() {
            rules.extend(self.git_dir_rules(&entry)?);
        } else if meta.is_file() {
            let resolution = self.resolve("git-file", &entry)?;
            rules.push(
                FloorRule::new(
                    "git-file",
                    FloorEffect::DenyWrite,
                    Extent::Node,
                    Self::literal(resolution),
                    REASON_GIT,
                )
                .in_group(FloorGroup::Project),
            );
            self.note_hard_links(Path::new(&entry));
            rules.extend(self.git_pointer_rules(&git, &entry, dir)?);
        } else {
            return GitUnsupportedSnafu { path: git }.fail();
        }
        Ok(rules)
    }

    /// Follows a `.git` file's pointer, and the git directory's `commondir`, and protects both.
    fn git_pointer_rules(
        &mut self,
        git: &str,
        file: &str,
        dir: &str,
    ) -> Result<Vec<FloorRule>, FloorError> {
        let bytes = read_bounded(Path::new(file)).context(GitIoSnafu { path: git })?;
        let pointer = parse_gitdir_pointer(&bytes).context(GitPointerSnafu { path: git })?;
        let gitdir = self.resolve_pointer(git, dir, pointer.as_str())?;

        let mut rules = self.git_dir_rules(gitdir.as_str())?;
        let commondir_file = join(gitdir.as_str(), "commondir");
        match read_bounded(Path::new(&commondir_file)) {
            Ok(bytes) => {
                let common = parse_commondir(&bytes).context(GitPointerSnafu {
                    path: commondir_file.clone(),
                })?;
                let common =
                    self.resolve_pointer(&commondir_file, gitdir.as_str(), common.as_str())?;
                if common != gitdir {
                    rules.extend(self.git_dir_rules(common.as_str())?);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(source).context(GitIoSnafu {
                    path: commondir_file,
                });
            }
        }
        Ok(rules)
    }

    /// Resolves untrusted pointer text, which is absolute or relative to `base_dir`.
    ///
    /// The text is joined to a directory and resolved as a literal path; it is never read as a
    /// `~` or glob spelling.
    fn resolve_pointer(
        &self,
        from: &str,
        base_dir: &str,
        pointer: &str,
    ) -> Result<CanonicalPath, FloorError> {
        let joined = if pointer.starts_with('/') {
            pointer.to_owned()
        } else {
            join(base_dir, pointer)
        };
        let resolution = self
            .resolver
            .deny(&joined)
            .context(GitResolveSnafu { path: from })?;
        Ok(resolution.target)
    }

    /// The rules for a git directory's hooks, config and submodule equivalents.
    fn git_dir_rules(&mut self, gitdir: &str) -> Result<Vec<FloorRule>, FloorError> {
        let mut rules = Vec::with_capacity(GIT_DIR_TAILS.len());
        for (name, segments) in GIT_DIR_TAILS {
            let (first, rest) = segments.split_first().unwrap_or((&"", &[]));
            let resolution = self.resolve(name, &join(gitdir, first))?;
            let tail = if rest.is_empty() {
                None
            } else {
                Some(GlobTail::parse(rest).context(TableSnafu { rule: *name })?)
            };
            rules.push(
                FloorRule::new(
                    format!("git-{name}:{gitdir}"),
                    FloorEffect::DenyWrite,
                    Extent::Subtree,
                    PathPattern {
                        base: resolution.target,
                        alias: resolution.alias,
                        tail,
                    },
                    REASON_GIT,
                )
                .in_group(FloorGroup::Project),
            );
        }
        self.note_hard_links(&Path::new(gitdir).join("config"));
        self.note_hook_links(&Path::new(gitdir).join("hooks"));
        Ok(rules)
    }

    fn note_hook_links(&mut self, hooks: &Path) {
        let Ok(entries) = fs::read_dir(hooks) else {
            return;
        };
        let mut names: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .take(MAX_HOOK_FILES_CHECKED)
            .collect();
        names.sort();
        for path in names {
            self.note_hard_links(&path);
        }
    }

    // ---- PATH ----

    fn path_entries(&mut self) -> Result<(), FloorError> {
        let raw = self
            .inputs
            .env
            .path_var
            .clone()
            .unwrap_or_else(|| OsString::from(DEFAULT_PATH));
        let entries = parse_path_var(&raw).context(PathVarSnafu)?;
        self.diagnostics.extend(
            entries
                .skipped
                .into_iter()
                .map(FloorDiagnostic::PathEntrySkipped),
        );

        // Keyed by canonical path so the output order does not depend on PATH order.
        let mut derived: BTreeMap<String, FloorRule> = BTreeMap::new();
        for entry in &entries.accepted {
            let resolution = match self.resolver.deny(entry) {
                Ok(resolution) => resolution,
                Err(error) => {
                    self.diagnostics
                        .push(FloorDiagnostic::PathEntryUnresolvable {
                            entry: entry.clone(),
                            reason: error.to_string(),
                        });
                    continue;
                }
            };
            let target = resolution.target.clone();
            let extent = if &target == self.inputs.root.path() {
                // Children-only would write-deny the project's own top-level files.
                self.diagnostics
                    .push(FloorDiagnostic::PathEntryInsideProject { path: target });
                continue;
            } else if self.contains_protected(&target) {
                self.diagnostics
                    .push(FloorDiagnostic::PathEntryContainsProtected {
                        path: target.clone(),
                    });
                Extent::Children
            } else if self.inputs.root.path().is_same_or_ancestor_of(&target) {
                self.diagnostics
                    .push(FloorDiagnostic::PathEntryInsideProject { path: target });
                continue;
            } else {
                Extent::Subtree
            };
            derived.insert(
                target.as_str().to_owned(),
                FloorRule::new(
                    format!("path:{}", target.as_str()),
                    FloorEffect::DenyWrite,
                    extent,
                    Self::literal(resolution),
                    REASON_PATH,
                )
                .in_group(FloorGroup::Path),
            );
        }
        self.extend(derived.into_values().collect());
        Ok(())
    }

    /// Whether `entry` equals or contains the project, the home directory or a write grant.
    fn contains_protected(&self, entry: &CanonicalPath) -> bool {
        entry.is_same_or_ancestor_of(self.inputs.root.path())
            || entry.is_same_or_ancestor_of(self.inputs.home.path())
            || self
                .inputs
                .write_grants
                .iter()
                .any(|grant| entry.is_same_or_ancestor_of(grant))
    }

    fn hb_exe(&mut self) {
        let Some(exe) = &self.inputs.env.hb_exe else {
            self.diagnostics.push(FloorDiagnostic::HbExeUnusable {
                reason: "its path is unknown".to_owned(),
            });
            return;
        };
        let Some(spelling) = exe.to_str() else {
            self.diagnostics.push(FloorDiagnostic::HbExeUnusable {
                reason: "its path is not valid UTF-8".to_owned(),
            });
            return;
        };
        if !spelling.starts_with('/') {
            // A relative spelling would resolve against the project, not against where hb is.
            self.diagnostics.push(FloorDiagnostic::HbExeUnusable {
                reason: "its path is not absolute".to_owned(),
            });
            return;
        }
        match self.resolver.deny(spelling) {
            Ok(resolution) => {
                if self
                    .inputs
                    .root
                    .path()
                    .is_same_or_ancestor_of(&resolution.target)
                {
                    self.diagnostics.push(FloorDiagnostic::HbExeInsideProject {
                        path: resolution.target.clone(),
                    });
                }
                self.push(
                    FloorRule::new(
                        "hb-exe",
                        FloorEffect::DenyWrite,
                        Extent::Subtree,
                        Self::literal(resolution),
                        REASON_EXE,
                    )
                    .in_group(FloorGroup::Path),
                );
            }
            Err(error) => self.diagnostics.push(FloorDiagnostic::HbExeUnusable {
                reason: error.to_string(),
            }),
        }
    }

    /// Protects programs that a `PATH` directory links to, when they sit where an agent can write.
    ///
    /// A directory entry that is a symlink into a write grant (`~/.local/bin/pi` pointing into
    /// `~/.pi/agent`) would otherwise let the agent replace a program you later run outside the
    /// sandbox.
    fn path_targets(&mut self) {
        let mut dirs: Vec<PathBuf> = self
            .rules
            .iter()
            .filter(|rule| rule.reason == REASON_PATH && rule.extent == Extent::Subtree)
            .map(|rule| rule.pattern.base.as_path().to_path_buf())
            .collect();
        dirs.sort();
        dirs.dedup();

        let (targets, truncated) = self.link_targets(&dirs);
        if truncated {
            self.note_scan_truncated();
        }

        if targets.len() > MAX_PATH_TARGETS {
            self.diagnostics
                .push(FloorDiagnostic::PathTargetsTruncated {
                    limit: MAX_PATH_TARGETS,
                });
        }
        for (path, extent) in targets.into_iter().take(MAX_PATH_TARGETS) {
            let Ok(base) = CanonicalPath::from_canonical(&path) else {
                continue;
            };
            let kind = if extent == Extent::Node {
                "path-link"
            } else {
                "path-target"
            };
            self.push(
                FloorRule::new(
                    format!("{kind}:{path}"),
                    FloorEffect::DenyWrite,
                    extent,
                    PathPattern {
                        base,
                        alias: None,
                        tail: None,
                    },
                    REASON_TARGET,
                )
                .in_group(FloorGroup::Path),
            );
        }
    }

    /// The links and link targets under `dirs` that an agent could replace, and whether the
    /// scan stopped early because a directory or the whole walk was too large.
    ///
    /// A link is protected as itself (node) and the end of its chain as a subtree.
    fn link_targets(&self, dirs: &[PathBuf]) -> (BTreeMap<String, Extent>, bool) {
        let mut targets: BTreeMap<String, Extent> = BTreeMap::new();
        let mut truncated = false;
        let mut scanned = 0usize;
        'dirs: for dir in dirs {
            let Ok(entries) = fs::read_dir(dir) else {
                continue;
            };
            // Read generously, sort, then cut, so which entries are kept does not depend on
            // the order the filesystem lists them in.
            let ceiling = self.limits.per_dir.saturating_mul(8);
            let mut names: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .take(ceiling.saturating_add(1))
                .collect();
            names.sort();
            if names.len() > self.limits.per_dir {
                truncated = true;
                names.truncate(self.limits.per_dir);
            }
            for name in names {
                scanned += 1;
                if scanned > self.limits.total {
                    truncated = true;
                    break 'dirs;
                }
                if !fs::symlink_metadata(&name).is_ok_and(|meta| meta.is_symlink()) {
                    continue;
                }
                // A chain that loops, or cannot be read, has no program at its end.
                let Some(walk) = walk_links(&name) else {
                    continue;
                };
                // Every link on the way can be re-pointed by whoever can write it, and the
                // end of the chain (which may not exist yet) can be written to.
                for link in &walk.links {
                    self.note_target(&mut targets, link, Extent::Node);
                }
                self.note_target(&mut targets, &walk.end, Extent::Subtree);
            }
        }
        (targets, truncated)
    }

    /// Records `path` for protection if an agent can write it and no rule already covers it.
    fn note_target(&self, targets: &mut BTreeMap<String, Extent>, path: &Path, extent: Extent) {
        let Ok(path) = CanonicalPath::from_canonical(path) else {
            return;
        };
        if self
            .writable
            .iter()
            .any(|grant| grant.is_same_or_ancestor_of(&path))
            && !self.already_write_protected(&path)
        {
            let entry = targets.entry(path.as_str().to_owned()).or_insert(extent);
            if extent == Extent::Subtree {
                *entry = Extent::Subtree;
            }
        }
    }

    fn note_scan_truncated(&mut self) {
        if !self
            .diagnostics
            .contains(&FloorDiagnostic::PathScanTruncated)
        {
            self.diagnostics.push(FloorDiagnostic::PathScanTruncated);
        }
    }

    fn already_write_protected(&self, path: &CanonicalPath) -> bool {
        self.rules.iter().any(|rule| {
            rule.effect.protects_writes() && rule.covers(path) == crate::policy::Coverage::Yes
        })
    }

    // ---- pins ----

    /// Pins every ancestor of a protected path that a write grant reaches.
    ///
    /// Renaming such an ancestor moves the protected path somewhere no rule covers, and the old
    /// location can then be rebuilt by the agent (design section 6, `.git` and approval files).
    fn pins(&mut self) {
        let mut pins: BTreeSet<String> = BTreeSet::new();
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.effect.protects_writes())
        {
            for pin in pin_ancestors(&rule.pattern, rule.extent, &self.writable) {
                pins.insert(pin.as_str().to_owned());
            }
        }
        for text in pins {
            if let Ok(path) = CanonicalPath::from_canonical(&text) {
                self.push(
                    FloorRule::new(
                        format!("pin:{text}"),
                        FloorEffect::PinUnlink,
                        Extent::Node,
                        PathPattern {
                            base: path,
                            alias: None,
                            tail: None,
                        },
                        REASON_PIN,
                    )
                    .in_group(FloorGroup::Pin),
                );
            }
        }
    }

    fn finish(self) -> Result<BuiltFloor, FloorError> {
        let floor = Floor::new(self.rules).context(TooLargeSnafu)?;
        Ok(BuiltFloor {
            floor,
            diagnostics: self.diagnostics,
        })
    }
}

/// Most symlinks followed while walking one path, as the kernel's own limit.
const MAX_LINK_HOPS: usize = 32;

/// Every symlink met while resolving a path, and where it ends.
#[derive(Debug)]
struct LinkWalk {
    /// The location of each symlink, in the order met, with its parents already resolved.
    links: Vec<PathBuf>,
    /// The resolved path, which may not exist: a dangling chain ends at the place a program
    /// would be created.
    end: PathBuf,
}

/// Resolves `path` one component at a time, noting every symlink on the way.
///
/// Unlike `fs::canonicalize` this does not stop at a missing target, and it reports the
/// intermediate links (`~/.tool/current -> versions/1.2`), which decide what the end is.
/// A component that is missing or that `hb` may not look at ends the walk and the rest is
/// appended as written: the agent may be able to reach what `hb` cannot see, so the protection
/// stays. `None` for a relative path, a loop, or another I/O error.
fn walk_links(path: &Path) -> Option<LinkWalk> {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::path::Component;

    fn parts(path: &Path) -> impl Iterator<Item = OsString> + '_ {
        path.components().filter_map(|component| match component {
            Component::Normal(name) => Some(name.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
    }

    if !path.is_absolute() {
        return None;
    }
    let mut pending: VecDeque<OsString> = parts(path).collect();
    let mut resolved = PathBuf::from("/");
    let mut links = Vec::new();
    while let Some(part) = pending.pop_front() {
        if part == ".." {
            resolved.pop();
            continue;
        }
        let next = resolved.join(&part);
        match fs::symlink_metadata(&next) {
            Ok(meta) if meta.is_symlink() => {
                if links.len() >= MAX_LINK_HOPS {
                    return None;
                }
                let target = fs::read_link(&next).ok()?;
                links.push(next);
                if target.is_absolute() {
                    resolved = PathBuf::from("/");
                }
                for name in parts(&target).collect::<Vec<_>>().into_iter().rev() {
                    pending.push_front(name);
                }
            }
            Ok(_) => resolved = next,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::NotADirectory
                        | io::ErrorKind::PermissionDenied
                ) =>
            {
                resolved = next;
                for rest in pending.drain(..) {
                    if rest == ".." {
                        resolved.pop();
                    } else {
                        resolved.push(rest);
                    }
                }
            }
            Err(_) => return None,
        }
    }
    Some(LinkWalk {
        links,
        end: resolved,
    })
}

fn join(dir: &str, name: &str) -> String {
    format!("{}/{name}", dir.trim_end_matches('/'))
}

/// Reads at most one byte more than a pointer file may hold, so an oversized file is detectable.
///
/// Only a regular file is opened: a FIFO the agent planted would otherwise block `hb` at `open`,
/// and a symlink would be followed to somewhere the floor never looked.
fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(u64::try_from(MAX_GITDIR_POINTER_BYTES).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Coverage, FsAccess, PathEntryProblem, SkippedPathEntry};
    use crate::testutil::{Tree, canonical};
    use claims::{assert_err, assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::symlink;

    /// A home directory, a project inside it, and a `PATH` that touches nothing real.
    struct Fix {
        tree: Tree,
        root: ProjectRoot,
        env: FloorEnvironment,
    }

    impl Fix {
        fn new() -> Self {
            let tree = Tree::new();
            let root = tree.project_root("work/proj");
            let bin = tree.outside("bin");
            let env = FloorEnvironment::new()
                .with_path_var(bin.into_os_string())
                .with_user_temp_dir(tree.outside("tmp"));
            Self { tree, root, env }
        }

        fn home(&self) -> PathBuf {
            self.tree.home_path().to_path_buf()
        }

        fn proj(&self) -> PathBuf {
            PathBuf::from(self.root.path().as_str())
        }

        fn build_with(
            &self,
            grants: &[CanonicalPath],
            approval: &[CanonicalPath],
        ) -> Result<BuiltFloor, FloorError> {
            build_floor(&FloorInputs::new(
                self.tree.home(),
                &self.root,
                &self.env,
                approval,
                grants,
            ))
        }

        fn build(&self) -> BuiltFloor {
            assert_ok!(self.build_with(&[], &[]))
        }

        fn grant(&self) -> Vec<CanonicalPath> {
            vec![self.root.path().clone()]
        }
    }

    fn named<'a>(floor: &'a Floor, name: &str) -> &'a FloorRule {
        assert_some!(
            floor.rules().iter().find(|rule| rule.name == name),
            "no rule named {name}"
        )
    }

    fn names(floor: &Floor) -> Vec<String> {
        floor.rules().iter().map(|r| r.name.to_string()).collect()
    }

    fn with_prefix<'a>(floor: &'a Floor, prefix: &str) -> Vec<&'a FloorRule> {
        floor
            .rules()
            .iter()
            .filter(|rule| rule.name.starts_with(prefix))
            .collect()
    }

    fn cp(p: &Path) -> CanonicalPath {
        canonical(p)
    }

    fn has_diag(built: &BuiltFloor, kind: &str) -> bool {
        built.diagnostics.iter().any(|d| d.kind() == kind)
    }

    // ====================================================================================
    // The compiled table
    // ====================================================================================

    #[test]
    fn the_table_comes_first_in_table_order() {
        let fix = Fix::new();
        let built = fix.build();
        let expected: Vec<&str> = TABLE.iter().map(|row| row.name).collect();
        let actual = names(&built.floor);
        assert_eq!(
            actual
                .iter()
                .map(String::as_str)
                .take(expected.len())
                .collect::<Vec<_>>(),
            expected
        );
    }

    #[test]
    fn home_rules_resolve_under_the_injected_home_even_when_the_paths_are_absent() {
        let fix = Fix::new();
        let built = fix.build();
        let ssh = named(&built.floor, "ssh");
        assert_eq!(
            ssh.pattern.base.as_str(),
            format!("{}/.ssh", fix.home().display())
        );
        assert_eq!(ssh.effect, FloorEffect::DenyReadWrite);
        let keychains = named(&built.floor, "keychains");
        assert_eq!(
            keychains.pattern.base.as_str(),
            format!("{}/Library/Keychains", fix.home().display())
        );
    }

    #[test]
    fn no_rule_uses_the_firmlink_spelling() {
        let fix = Fix::new();
        let built = fix.build();
        for rule in built.floor.rules() {
            assert!(
                !rule
                    .pattern
                    .base
                    .as_str()
                    .starts_with("/System/Volumes/Data"),
                "{}",
                rule.name
            );
        }
    }

    #[test]
    fn a_symlinked_floor_path_is_covered_by_both_the_link_and_its_target() {
        let fix = Fix::new();
        let dotfiles = fix.tree.inside_home("dotfiles");
        assert_ok!(fs::write(dotfiles.join("zshrc"), "x"));
        assert_ok!(symlink(dotfiles.join("zshrc"), fix.home().join(".zshrc")));
        let built = fix.build();
        let rule = named(&built.floor, "zshrc");
        assert_eq!(rule.pattern.base, cp(&dotfiles.join("zshrc")));
        assert_eq!(rule.pattern.alias, Some(cp(&fix.home()).join_str(".zshrc")));
        for path in [dotfiles.join("zshrc"), fix.home().join(".zshrc")] {
            assert_some!(built.floor.denying(&cp_missing(&path), FsAccess::Write));
        }
    }

    #[test]
    fn a_dangling_symlink_at_a_table_path_fails_closed_naming_the_rule() {
        let fix = Fix::new();
        assert_ok!(symlink("/nonexistent/x", fix.home().join(".zshrc")));
        let err = assert_err!(fix.build_with(&[], &[]));
        assert!(
            matches!(&err, FloorError::Resolve { rule, .. } if rule == "zshrc"),
            "{err:?}"
        );
    }

    #[test]
    fn a_file_where_a_table_directory_should_be_fails_closed() {
        let fix = Fix::new();
        // `~/.config` is a file, so `~/.config/gh` has a non-directory ancestor.
        assert_ok!(fs::write(fix.home().join(".config"), "x"));
        let err = assert_err!(fix.build_with(&[], &[]));
        assert!(matches!(err, FloorError::Resolve { .. }), "{err:?}");
    }

    #[test]
    fn a_symlink_loop_at_a_table_path_fails_closed() {
        let fix = Fix::new();
        assert_ok!(symlink(
            fix.home().join(".zshenv"),
            fix.home().join(".zshenv")
        ));
        let err = assert_err!(fix.build_with(&[], &[]));
        assert!(matches!(err, FloorError::Resolve { .. }), "{err:?}");
    }

    #[test]
    fn the_resolve_error_message_names_the_rule_and_does_not_repeat_its_source() {
        let fix = Fix::new();
        assert_ok!(symlink("/nonexistent/x", fix.home().join(".zshrc")));
        let err = assert_err!(fix.build_with(&[], &[]));
        assert!(err.to_string().contains("`zshrc`"));
        crate::error::conventions::assert_display_excludes_sources(&err);
    }

    #[test]
    fn the_history_rule_denies_dot_history_files_in_home_but_not_home_itself() {
        let fix = Fix::new();
        let built = fix.build();
        let home = fix.home();
        assert_some!(
            built
                .floor
                .denying(&cp_missing(&home.join(".zsh_history")), FsAccess::Read)
        );
        assert_none!(built.floor.denying(&cp(&home), FsAccess::Read));
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&home.join("notes_history")), FsAccess::Read)
        );
    }

    fn cp_missing(p: &Path) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    trait JoinStr {
        fn join_str(&self, name: &str) -> CanonicalPath;
    }

    impl JoinStr for CanonicalPath {
        fn join_str(&self, name: &str) -> CanonicalPath {
            cp_missing(&self.as_path().join(name))
        }
    }

    // ====================================================================================
    // Sockets and the user temp directory
    // ====================================================================================

    #[test]
    fn the_user_temp_podman_directory_gets_a_connect_rule() {
        let fix = Fix::new();
        let built = fix.build();
        let rule = named(&built.floor, "connect-podman-temp");
        assert_eq!(rule.effect, FloorEffect::DenyConnect);
        assert!(rule.pattern.base.as_str().ends_with("/tmp/podman"));
    }

    #[test]
    fn an_unknown_user_temp_dir_is_reported() {
        let mut fix = Fix::new();
        fix.env.user_temp_dir = None;
        let built = fix.build();
        assert!(has_diag(&built, "user_temp_dir_unknown"));
        assert!(with_prefix(&built.floor, "connect-podman-temp").is_empty());
    }

    // ====================================================================================
    // The project
    // ====================================================================================

    #[test]
    fn the_project_config_and_approval_files_are_write_denied() {
        let fix = Fix::new();
        let extra = fix.tree.outside("elsewhere");
        let preset = extra.join("preset.toml");
        assert_ok!(fs::write(&preset, ""));
        let built = assert_ok!(fix.build_with(&fix.grant(), &[cp(&preset)]));
        let config = named(&built.floor, "project-config");
        assert_eq!(config.effect, FloorEffect::DenyWrite);
        assert_eq!(
            config.pattern.base.as_str(),
            format!("{}/hamster-ball.toml", fix.proj().display())
        );
        let approval = named(&built.floor, "approval-file");
        assert_eq!(approval.pattern.base, cp(&preset));
    }

    #[test]
    fn a_git_directory_gets_hook_config_and_submodule_rules() {
        let fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let built = fix.build();
        let git = fix.proj().join(".git");
        for (path, expected) in [
            (git.join("hooks/pre-commit"), true),
            (git.join("config"), true),
            (git.join("config.worktree"), true),
            (git.join("commondir"), true),
            (git.join("modules/a/commondir"), true),
            (git.join("worktrees/w/commondir"), false),
            (git.join("modules/a/hooks/post-merge"), true),
            (git.join("modules/a/b/config"), true),
            (git.join("worktrees/w/config.worktree"), true),
            (git.join("objects/ab/cd"), false),
            (git.join("refs/heads/hooks"), false),
            (git.join("HEAD"), false),
            (git.join("index"), false),
        ] {
            assert_eq!(
                built
                    .floor
                    .denying(&cp_missing(&path), FsAccess::Write)
                    .is_some(),
                expected,
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn a_missing_git_is_denied_so_a_pointer_cannot_be_planted() {
        let fix = Fix::new();
        let built = fix.build();
        let rule = named(&built.floor, "git-missing");
        assert_eq!(rule.extent, Extent::Node);
        let git = cp_missing(&fix.proj().join(".git"));
        assert_some!(built.floor.denying(&git, FsAccess::Write));
        // Only the node: a sibling is unaffected.
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&fix.proj().join("src")), FsAccess::Write)
        );
    }

    #[test]
    fn a_git_file_pointer_protects_the_directory_it_names() {
        let fix = Fix::new();
        let modules = fix
            .proj()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let main = modules.join("main/.git/modules/sub");
        assert_ok!(fs::create_dir_all(&main));
        assert_ok!(fs::write(
            fix.proj().join(".git"),
            "gitdir: ../main/.git/modules/sub\n"
        ));
        let built = fix.build();
        let hooks = cp_missing(&main.join("hooks/pre-commit"));
        let hit = assert_some!(built.floor.denying(&hooks, FsAccess::Write));
        assert!(hit.rule.name.starts_with("git-hooks:"));
        // The pointer file itself is protected too.
        assert_some!(
            built
                .floor
                .denying(&cp_missing(&fix.proj().join(".git")), FsAccess::Write)
        );
    }

    #[test]
    fn a_worktree_protects_its_gitdir_and_its_common_directory() {
        let fix = Fix::new();
        let parent = fix
            .proj()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let common = parent.join("main/.git");
        let gitdir = common.join("worktrees/wt");
        assert_ok!(fs::create_dir_all(&gitdir));
        assert_ok!(fs::write(gitdir.join("commondir"), "../..\n"));
        assert_ok!(fs::write(
            fix.proj().join(".git"),
            format!("gitdir: {}\n", gitdir.display())
        ));
        let built = fix.build();
        for path in [
            gitdir.join("config.worktree"),
            common.join("hooks/pre-commit"),
            common.join("config"),
            common.join("worktrees/other/config.worktree"),
        ] {
            assert_some!(
                built.floor.denying(&cp_missing(&path), FsAccess::Write),
                "{}",
                path.display()
            );
        }
    }

    #[test]
    fn a_git_symlink_protects_the_link_and_what_it_points_to() {
        let fix = Fix::new();
        let real = fix.tree.outside("realgit");
        assert_ok!(fs::create_dir_all(real.join("hooks")));
        assert_ok!(symlink(&real, fix.proj().join(".git")));
        let built = fix.build();
        assert_some!(
            built
                .floor
                .denying(&cp_missing(&fix.proj().join(".git")), FsAccess::Write)
        );
        assert_some!(
            built
                .floor
                .denying(&cp(&real).join_str("hooks/x"), FsAccess::Write)
        );
    }

    #[test]
    fn pointer_text_is_a_literal_path_never_a_tilde_or_glob_spelling() {
        let fix = Fix::new();
        assert_ok!(fs::write(fix.proj().join(".git"), "gitdir: ~/x*y\n"));
        let built = fix.build();
        // Joined to the directory holding `.git`, not expanded to home, and `*` is a name.
        let literal = fix.proj().join("~/x*y/hooks/h");
        assert_some!(built.floor.denying(&cp_missing(&literal), FsAccess::Write));
        let other = fix.proj().join("~/xzy/hooks/h");
        assert_none!(built.floor.denying(&cp_missing(&other), FsAccess::Write));
        let home_target = fix.home().join("x*y/hooks/h");
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&home_target), FsAccess::Write)
        );
    }

    #[test]
    fn a_pointer_at_the_filesystem_root_protects_only_root_level_hooks_and_config() {
        let fix = Fix::new();
        assert_ok!(fs::write(fix.proj().join(".git"), "gitdir: /\n"));
        let built = fix.build();
        assert_some!(
            built
                .floor
                .denying(&cp_missing(Path::new("/hooks/x")), FsAccess::Write)
        );
        assert_none!(
            built
                .floor
                .denying(&cp_missing(Path::new("/etc/hosts")), FsAccess::Write)
        );
        assert_none!(
            built
                .floor
                .denying(&cp_missing(Path::new("/")), FsAccess::Write)
        );
    }

    #[test]
    fn a_malformed_pointer_in_the_project_is_an_error() {
        let fix = Fix::new();
        for content in [
            b"nonsense".to_vec(),
            b"gitdir: a\0b".to_vec(),
            format!("gitdir: {}", "a".repeat(2000)).into_bytes(),
            b"gitdir: \xff".to_vec(),
        ] {
            assert_ok!(fs::write(fix.proj().join(".git"), &content));
            let err = assert_err!(fix.build_with(&[], &[]));
            assert!(matches!(err, FloorError::GitPointer { .. }), "{err:?}");
            crate::error::conventions::assert_display_excludes_sources(&err);
        }
    }

    #[test]
    fn a_pointer_through_a_missing_directory_still_protects_the_named_path() {
        let fix = Fix::new();
        assert_ok!(fs::write(fix.proj().join(".git"), "gitdir: ../gone/.git\n"));
        let built = fix.build();
        let target = fix
            .proj()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default()
            .join("gone/.git/hooks/x");
        assert_some!(built.floor.denying(&cp_missing(&target), FsAccess::Write));
    }

    #[test]
    fn a_pointer_through_a_file_is_an_error() {
        let fix = Fix::new();
        let blocker = fix.tree.outside("blocker");
        assert_ok!(fs::write(blocker.join("file"), "x"));
        assert_ok!(fs::write(
            fix.proj().join(".git"),
            format!("gitdir: {}/file/.git\n", blocker.display())
        ));
        let err = assert_err!(fix.build_with(&[], &[]));
        assert!(matches!(err, FloorError::GitResolve { .. }), "{err:?}");
    }

    #[test]
    fn an_enclosing_repository_is_protected_when_the_root_is_a_subdirectory() {
        let fix = Fix::new();
        let enclosing = fix.home().join("work");
        assert_ok!(fs::create_dir_all(enclosing.join(".git/hooks")));
        let built = fix.build();
        assert_some!(built.floor.denying(
            &cp_missing(&enclosing.join(".git/hooks/pre-push")),
            FsAccess::Write
        ));
        assert_some!(
            built
                .floor
                .denying(&cp_missing(&enclosing.join(".git/config")), FsAccess::Write)
        );
    }

    #[test]
    fn a_malformed_enclosing_pointer_is_reported_not_fatal() {
        let fix = Fix::new();
        assert_ok!(fs::write(fix.home().join("work/.git"), "garbage"));
        let built = fix.build();
        assert!(has_diag(&built, "enclosing_repo_skipped"));
    }

    #[test]
    fn a_missing_enclosing_git_adds_no_rule() {
        let fix = Fix::new();
        let built = fix.build();
        assert_eq!(with_prefix(&built.floor, "git-missing").len(), 1);
    }

    #[test]
    fn a_hard_linked_project_config_is_reported() {
        let fix = Fix::new();
        let config = fix.proj().join("hamster-ball.toml");
        assert_ok!(fs::write(&config, ""));
        assert_ok!(fs::hard_link(&config, fix.proj().join("alias.toml")));
        let built = fix.build();
        assert!(has_diag(&built, "hard_linked_floor_file"));
    }

    #[test]
    fn a_single_link_config_is_not_reported() {
        let fix = Fix::new();
        assert_ok!(fs::write(fix.proj().join("hamster-ball.toml"), ""));
        assert!(!has_diag(&fix.build(), "hard_linked_floor_file"));
    }

    #[test]
    fn a_hard_linked_hook_is_reported() {
        let fix = Fix::new();
        let hooks = fix.proj().join(".git/hooks");
        assert_ok!(fs::create_dir_all(&hooks));
        assert_ok!(fs::write(hooks.join("pre-commit"), ""));
        assert_ok!(fs::hard_link(
            hooks.join("pre-commit"),
            fix.proj().join("src.sh")
        ));
        assert!(has_diag(&fix.build(), "hard_linked_floor_file"));
    }

    // ====================================================================================
    // Pins
    // ====================================================================================

    fn pins(floor: &Floor) -> Vec<String> {
        floor
            .rules()
            .iter()
            .filter(|rule| rule.effect == FloorEffect::PinUnlink)
            .map(|rule| rule.pattern.base.as_str().to_owned())
            .collect()
    }

    #[test]
    fn the_project_root_and_git_directory_are_pinned_when_the_root_is_writable() {
        let fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        let pins = pins(&built.floor);
        assert!(pins.contains(&fix.proj().display().to_string()), "{pins:?}");
        assert!(
            pins.contains(&fix.proj().join(".git").display().to_string()),
            "{pins:?}"
        );
    }

    #[test]
    fn ancestors_of_protected_paths_are_pinned_only_where_a_write_grant_reaches() {
        let fix = Fix::new();
        let local = fix.tree.inside_home(".local");
        let grants = [cp(&local)];
        // `~/.local/share` is an ancestor of `~/.local/share/containers`, inside the grant.
        assert_ok!(fs::create_dir_all(local.join("share")));
        let built = assert_ok!(fix.build_with(&grants, &[]));
        let pins = pins(&built.floor);
        assert!(
            pins.contains(&local.join("share").display().to_string()),
            "{pins:?}"
        );
        // `~/.config` is not under any grant.
        assert!(!pins.contains(&fix.home().join(".config").display().to_string()));
        // The grant itself is an ancestor and is pinned, `/` and `~` are not.
        assert!(pins.contains(&local.display().to_string()));
        assert!(!pins.contains(&fix.home().display().to_string()));
        assert!(!pins.contains(&"/".to_owned()));
    }

    #[test]
    fn a_glob_rules_base_is_pinned_because_the_base_itself_is_not_denied() {
        let fix = Fix::new();
        let cargo = fix.tree.inside_home(".cargo");
        let built = assert_ok!(fix.build_with(&[cp(&cargo)], &[]));
        assert!(pins(&built.floor).contains(&cargo.display().to_string()));
    }

    #[test]
    fn a_pin_denies_renaming_the_node_but_not_writing_inside_it() {
        let fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        let root = cp(&fix.proj());
        let hit = assert_some!(built.floor.denying(&root, FsAccess::Write));
        assert_eq!(hit.rule.effect, FloorEffect::PinUnlink);
        assert_none!(built.floor.denying(
            &cp_missing(&fix.proj().join("src/main.rs")),
            FsAccess::Write
        ));
    }

    #[test]
    fn pins_are_unique_and_sorted() {
        let fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        let pins = pins(&built.floor);
        let mut sorted = pins.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(pins, sorted);
    }

    #[test]
    fn an_approval_file_in_a_nested_project_directory_pins_every_ancestor_up_to_the_root() {
        let fix = Fix::new();
        let presets = fix.proj().join("presets");
        assert_ok!(fs::create_dir_all(&presets));
        assert_ok!(fs::write(presets.join("x.toml"), ""));
        let built = assert_ok!(fix.build_with(&fix.grant(), &[cp(&presets.join("x.toml"))]));
        let pins = pins(&built.floor);
        assert!(pins.contains(&presets.display().to_string()), "{pins:?}");
        assert!(pins.contains(&fix.proj().display().to_string()));
    }

    // ====================================================================================
    // PATH
    // ====================================================================================

    #[test]
    fn a_path_entry_is_write_denied_missing_ones_included() {
        let mut fix = Fix::new();
        let present = fix.tree.outside("tools/bin");
        let missing = fix.tree.base().join("outside/tools/later");
        fix.env.path_var = Some(OsString::from(format!(
            "{}:{}",
            present.display(),
            missing.display()
        )));
        let built = fix.build();
        for dir in [&present, &missing] {
            let hit = assert_some!(
                built
                    .floor
                    .denying(&cp_missing(&dir.join("tool")), FsAccess::Write),
                "{}",
                dir.display()
            );
            assert_eq!(hit.rule.effect, FloorEffect::DenyWrite);
        }
    }

    #[test]
    fn a_symlinked_path_entry_covers_the_link_and_its_target() {
        let mut fix = Fix::new();
        let real = fix.tree.outside("store/bin");
        let link = fix.tree.base().join("outside/link-bin");
        assert_ok!(symlink(&real, &link));
        fix.env.path_var = Some(link.clone().into_os_string());
        let built = fix.build();
        let rule = named(&built.floor, &format!("path:{}", cp(&real).as_str()));
        assert_eq!(rule.pattern.base, cp(&real));
        assert_eq!(rule.pattern.alias, Some(cp_missing(&link)));
    }

    #[test]
    fn relative_empty_and_dot_entries_are_skipped_with_diagnostics() {
        let mut fix = Fix::new();
        let good = fix.tree.outside("good");
        fix.env.path_var = Some(OsString::from(format!(
            ".::bin:~/.cargo/bin:{}",
            good.display()
        )));
        let built = fix.build();
        let skipped = built
            .diagnostics
            .iter()
            .filter(|d| d.kind() == "path_entry_skipped")
            .count();
        assert_eq!(skipped, 4);
        assert!(
            with_prefix(&built.floor, "path:")
                .iter()
                .any(|r| r.pattern.base == cp(&good))
        );
        // Nothing was resolved against the project or the process's working directory.
        assert!(
            with_prefix(&built.floor, "path:").iter().all(|r| r
                .pattern
                .base
                .as_str()
                .starts_with('/'))
        );
    }

    #[test]
    fn duplicate_entries_through_different_spellings_yield_one_rule() {
        let mut fix = Fix::new();
        let real = fix.tree.outside("dup/bin");
        let link = fix.tree.base().join("outside/dup-link");
        assert_ok!(symlink(&real, &link));
        fix.env.path_var = Some(OsString::from(format!(
            "{}:{}:{}",
            real.display(),
            link.display(),
            real.display()
        )));
        let built = fix.build();
        let count = with_prefix(&built.floor, "path:")
            .iter()
            .filter(|r| r.pattern.base == cp(&real))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn path_rules_are_sorted_by_path_not_by_path_order() {
        let mut fix = Fix::new();
        let a = fix.tree.outside("zz/bin");
        let b = fix.tree.outside("aa/bin");
        fix.env.path_var = Some(OsString::from(format!("{}:{}", a.display(), b.display())));
        let forward = names(&fix.build().floor);
        fix.env.path_var = Some(OsString::from(format!("{}:{}", b.display(), a.display())));
        assert_eq!(names(&fix.build().floor), forward);
    }

    #[test]
    fn a_dangling_path_entry_is_skipped_with_a_diagnostic_not_an_error() {
        let mut fix = Fix::new();
        let link = fix.tree.base().join("outside/broken");
        assert_ok!(symlink("/nonexistent/dir", &link));
        fix.env.path_var = Some(link.into_os_string());
        let built = fix.build();
        assert!(has_diag(&built, "path_entry_unresolvable"));
    }

    #[test]
    fn a_path_entry_inside_the_project_is_not_denied_and_is_reported() {
        let mut fix = Fix::new();
        let venv = fix.proj().join(".venv/bin");
        assert_ok!(fs::create_dir_all(&venv));
        fix.env.path_var = Some(venv.clone().into_os_string());
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        assert!(has_diag(&built, "path_entry_inside_project"));
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&venv.join("python")), FsAccess::Write)
        );
    }

    #[test]
    fn a_path_entry_containing_the_project_denies_only_its_direct_children() {
        let mut fix = Fix::new();
        let work = fix.home().join("work");
        fix.env.path_var = Some(work.clone().into_os_string());
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        assert!(has_diag(&built, "path_entry_contains_protected"));
        // A new program directly in the entry is denied.
        assert_some!(
            built
                .floor
                .denying(&cp_missing(&work.join("newbin")), FsAccess::Write)
        );
        // The project beneath it stays writable.
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&fix.proj().join("src/x.rs")), FsAccess::Write)
        );
        let rule = named(&built.floor, &format!("path:{}", cp(&work).as_str()));
        assert_eq!(rule.extent, Extent::Children);
    }

    #[test]
    fn a_path_entry_equal_to_home_is_children_only_too() {
        let mut fix = Fix::new();
        fix.env.path_var = Some(fix.home().into_os_string());
        let built = fix.build();
        assert!(has_diag(&built, "path_entry_contains_protected"));
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&fix.proj().join("a")), FsAccess::Write)
        );
    }

    #[test]
    fn an_unset_path_falls_back_to_the_system_default() {
        let mut fix = Fix::new();
        fix.env.path_var = None;
        let built = fix.build();
        let bins = with_prefix(&built.floor, "path:");
        assert!(
            bins.iter()
                .any(|r| r.pattern.base.as_str().ends_with("/usr/bin")),
            "{:?}",
            names(&built.floor)
        );
    }

    #[test]
    fn the_fixed_program_directories_are_present_whatever_path_says() {
        let fix = Fix::new();
        let built = fix.build();
        for name in [
            "bin-local",
            "bin-cargo",
            "bin-go",
            "bin-bun",
            "bin-homebrew",
            "bin-usr-local",
        ] {
            assert_eq!(named(&built.floor, name).effect, FloorEffect::DenyWrite);
        }
    }

    #[test]
    fn an_oversized_path_is_refused() {
        let mut fix = Fix::new();
        fix.env.path_var = Some(OsString::from(
            (0..300)
                .map(|i| format!("/d{i}"))
                .collect::<Vec<_>>()
                .join(":"),
        ));
        let err = assert_err!(fix.build_with(&[], &[]));
        assert!(matches!(err, FloorError::PathVar { .. }), "{err:?}");
        crate::error::conventions::assert_display_excludes_sources(&err);
    }

    // ====================================================================================
    // hb itself
    // ====================================================================================

    #[test]
    fn hb_itself_is_write_denied() {
        let mut fix = Fix::new();
        let exe = fix.tree.outside("install").join("hb");
        assert_ok!(fs::write(&exe, ""));
        fix.env.hb_exe = Some(exe.clone());
        let built = fix.build();
        let rule = named(&built.floor, "hb-exe");
        assert_eq!(rule.pattern.base, cp(&exe));
        assert!(!has_diag(&built, "hb_exe_inside_project"));
    }

    #[test]
    fn hb_inside_the_project_is_denied_and_reported() {
        let mut fix = Fix::new();
        let exe = fix.proj().join("target/debug/hb");
        assert_ok!(fs::create_dir_all(assert_some!(exe.parent())));
        assert_ok!(fs::write(&exe, ""));
        fix.env.hb_exe = Some(exe);
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        assert!(has_diag(&built, "hb_exe_inside_project"));
        assert_eq!(named(&built.floor, "hb-exe").effect, FloorEffect::DenyWrite);
    }

    #[test]
    fn an_unusable_hb_path_is_reported_not_fatal() {
        let mut fix = Fix::new();
        fix.env.hb_exe = Some(PathBuf::from("relative/hb"));
        assert!(has_diag(&fix.build(), "hb_exe_unusable"));
    }

    // ====================================================================================
    // Programs a PATH directory links to
    // ====================================================================================

    /// A `PATH` directory whose entries link into `agent`, which is granted write.
    fn linked_bin(fix: &mut Fix, count: usize) -> (PathBuf, PathBuf) {
        let bin = fix.tree.outside("linkbin/bin");
        let agent = fix.tree.inside_home(".pi/agent");
        assert_ok!(fs::create_dir_all(agent.join("bin")));
        for i in 0..count {
            let target = agent.join(format!("bin/tool{i:04}"));
            assert_ok!(fs::write(&target, ""));
            assert_ok!(symlink(&target, bin.join(format!("tool{i:04}"))));
        }
        fix.env.path_var = Some(bin.clone().into_os_string());
        (bin, agent)
    }

    #[test]
    fn a_program_linked_into_a_write_grant_is_write_denied() {
        let mut fix = Fix::new();
        let (_, agent) = linked_bin(&mut fix, 2);
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        let hit = assert_some!(
            built
                .floor
                .denying(&cp(&agent.join("bin/tool0000")), FsAccess::Write)
        );
        assert!(
            hit.rule.name.starts_with("path-target:"),
            "{}",
            hit.rule.name
        );
        // Other files in the grant stay writable.
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&agent.join("settings.json")), FsAccess::Write)
        );
    }

    #[test]
    fn a_program_linked_outside_any_write_grant_adds_no_target_rule() {
        let mut fix = Fix::new();
        let _ = linked_bin(&mut fix, 2);
        let built = fix.build();
        assert!(with_prefix(&built.floor, "path-target:").is_empty());
    }

    #[test]
    fn programs_linked_into_a_grant_are_capped_with_a_diagnostic_in_path_order() {
        let mut fix = Fix::new();
        let (_, agent) = linked_bin(&mut fix, MAX_PATH_TARGETS + 4);
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        assert_eq!(
            with_prefix(&built.floor, "path-target:").len(),
            MAX_PATH_TARGETS
        );
        assert!(has_diag(&built, "path_targets_truncated"));
        // The first by path are kept.
        assert_some!(
            built
                .floor
                .denying(&cp(&agent.join("bin/tool0000")), FsAccess::Write)
        );
        assert_none!(built.floor.denying(
            &cp(&agent.join(format!("bin/tool{:04}", MAX_PATH_TARGETS + 3))),
            FsAccess::Write
        ));
    }

    #[test]
    fn a_target_already_covered_by_a_write_deny_is_not_repeated() {
        let mut fix = Fix::new();
        let (_, agent) = linked_bin(&mut fix, 1);
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        let first = names(&built.floor);
        // Protecting the agent's bin directory directly covers the target.
        fix.env.path_var = Some(OsString::from(format!(
            "{}:{}",
            fix.env
                .path_var
                .clone()
                .unwrap_or_default()
                .to_string_lossy(),
            agent.join("bin").display()
        )));
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        assert!(
            with_prefix(&built.floor, "path-target:").is_empty(),
            "{first:?}"
        );
    }

    // ====================================================================================
    // Whole-floor properties
    // ====================================================================================

    #[test]
    fn every_derived_rule_is_labelled_with_the_group_it_came_from() {
        let mut fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let exe = fix.tree.outside("install").join("hb");
        assert_ok!(fs::write(&exe, ""));
        fix.env.hb_exe = Some(exe);
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        let table: HashSet<&str> = TABLE.iter().map(|row| row.name).collect();
        for rule in built.floor.rules() {
            let name: &str = &rule.name;
            let expected = if table.contains(name) || name == "connect-podman-temp" {
                FloorGroup::Table
            } else if name.starts_with("pin:") {
                FloorGroup::Pin
            } else if name.starts_with("path:")
                || name.starts_with("path-target:")
                || name.starts_with("path-link:")
                || name == "hb-exe"
            {
                FloorGroup::Path
            } else {
                FloorGroup::Project
            };
            assert_eq!(rule.group, expected, "{name}");
        }
    }

    // ----- review findings -----

    #[test]
    fn a_pointer_with_trailing_space_protects_the_directory_git_will_use_not_its_trimmed_twin() {
        let fix = Fix::new();
        let parent = fix
            .proj()
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        assert_ok!(fs::create_dir_all(parent.join("sp ")));
        assert_ok!(fs::write(fix.proj().join(".git"), "gitdir: ../sp \n"));
        let built = fix.build();
        assert_some!(
            built
                .floor
                .denying(&cp_missing(&parent.join("sp /hooks/x")), FsAccess::Write)
        );
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&parent.join("sp/hooks/x")), FsAccess::Write)
        );
    }

    #[test]
    fn a_fifo_named_commondir_is_an_error_not_a_hang() {
        let fix = Fix::new();
        let gitdir = fix.tree.outside("gd");
        crate::testutil::mkfifo(&gitdir.join("commondir"));
        assert_ok!(fs::write(
            fix.proj().join(".git"),
            format!("gitdir: {}\n", gitdir.display())
        ));
        // An owned fixture on a detached thread: if the build blocks on the FIFO the thread is
        // abandoned and the timeout fails the test instead of hanging the suite.
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(fix.build_with(&[], &[]).is_err());
        });
        assert_eq!(
            receiver.recv_timeout(std::time::Duration::from_secs(10)),
            Ok(true),
            "must fail promptly, not block on the FIFO"
        );
    }

    #[test]
    fn a_symlink_named_commondir_is_refused_not_followed() {
        let fix = Fix::new();
        let gitdir = fix.tree.outside("gd2");
        assert_ok!(symlink("/etc", gitdir.join("commondir")));
        assert_ok!(fs::write(
            fix.proj().join(".git"),
            format!("gitdir: {}\n", gitdir.display())
        ));
        assert!(matches!(
            assert_err!(fix.build_with(&[], &[])),
            FloorError::GitIo { .. } | FloorError::GitUnsupported { .. }
        ));
    }

    #[test]
    fn a_dangling_link_in_a_program_directory_still_protects_where_it_will_point() {
        let mut fix = Fix::new();
        let bin = fix.tree.outside("dl/bin");
        let agent = fix.tree.inside_home(".agent");
        assert_ok!(symlink(agent.join("build/tool"), bin.join("tool")));
        fix.env.path_var = Some(bin.into_os_string());
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        assert_some!(
            built
                .floor
                .denying(&cp_missing(&agent.join("build/tool")), FsAccess::Write)
        );
    }

    #[test]
    fn every_hop_of_a_link_chain_under_a_write_grant_is_protected() {
        let mut fix = Fix::new();
        let bin = fix.tree.outside("chain/bin");
        let agent = fix.tree.inside_home(".tool");
        assert_ok!(fs::create_dir_all(agent.join("versions/1.2/bin")));
        assert_ok!(fs::write(agent.join("versions/1.2/bin/tool"), ""));
        assert_ok!(symlink("versions/1.2", agent.join("current")));
        assert_ok!(symlink(agent.join("current/bin/tool"), bin.join("tool")));
        fix.env.path_var = Some(bin.into_os_string());
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        // The final program.
        assert_some!(
            built
                .floor
                .denying(&cp(&agent.join("versions/1.2/bin/tool")), FsAccess::Write)
        );
        // The directory link that decides which version that is.
        let hit = assert_some!(
            built
                .floor
                .denying(&cp(&agent).join_str("current"), FsAccess::Write)
        );
        assert!(hit.rule.name.starts_with("path-link:"), "{}", hit.rule.name);
        // Only the link itself: the version it points at stays otherwise writable.
        assert_none!(built.floor.denying(
            &cp(&agent.join("versions/1.2")).join_str("notes.txt"),
            FsAccess::Write
        ));
    }

    #[test]
    fn a_link_loop_in_a_program_directory_does_not_stop_the_build() {
        let mut fix = Fix::new();
        let bin = fix.tree.outside("loop/bin");
        assert_ok!(symlink(bin.join("b"), bin.join("a")));
        assert_ok!(symlink(bin.join("a"), bin.join("b")));
        fix.env.path_var = Some(bin.into_os_string());
        let built = fix.build();
        assert!(with_prefix(&built.floor, "path-target:").is_empty());
    }

    #[test]
    fn a_path_entry_equal_to_the_project_root_is_inside_the_project_not_children_only() {
        let mut fix = Fix::new();
        fix.env.path_var = Some(fix.proj().into_os_string());
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        assert!(has_diag(&built, "path_entry_inside_project"));
        assert_none!(
            built
                .floor
                .denying(&cp_missing(&fix.proj().join("README.md")), FsAccess::Write)
        );
        assert!(
            with_prefix(&built.floor, "path:")
                .iter()
                .all(|rule| rule.pattern.base != *fix.root.path())
        );
    }

    #[test]
    fn an_unknown_hb_path_is_reported() {
        let mut fix = Fix::new();
        fix.env.hb_exe = None;
        assert!(has_diag(&fix.build(), "hb_exe_unusable"));
    }

    #[test]
    fn the_base_of_a_children_only_rule_is_pinned_when_a_write_grant_reaches_it() {
        let mut fix = Fix::new();
        let outer = fix.tree.inside_home("outer");
        let inner = fix.tree.inside_home("outer/mid/inner");
        // `mid` contains the inner grant but not the project, and sits under the outer grant.
        let mid = outer.join("mid");
        fix.env.path_var = Some(mid.clone().into_os_string());
        let built = assert_ok!(fix.build_with(&[cp(&outer), cp(&inner)], &[]));
        let rule = named(&built.floor, &format!("path:{}", cp(&mid).as_str()));
        assert_eq!(rule.extent, Extent::Children);
        assert!(
            pins(&built.floor).contains(&mid.display().to_string()),
            "{:?}",
            pins(&built.floor)
        );
    }

    // ----- mutation-driven: limits, boundaries, classification -----

    /// A program directory `name` holding `count` links (`tool0`, `tool1`, ...) into `agent`.
    fn bin_with_links(fix: &Fix, agent: &Path, name: &str, count: usize) -> PathBuf {
        let bin = fix.tree.outside(name);
        for i in 0..count {
            let target = agent.join(format!("{name}-tool{i}"));
            assert_ok!(fs::write(&target, ""));
            assert_ok!(symlink(&target, bin.join(format!("tool{i}"))));
        }
        bin
    }

    fn count_diag(built: &BuiltFloor, kind: &str) -> usize {
        built
            .diagnostics
            .iter()
            .filter(|d| d.kind() == kind)
            .count()
    }

    /// Runs the link scan over exactly `dirs`, with `limits`, for `fix`.
    fn scan(
        fix: &Fix,
        grants: &[CanonicalPath],
        dirs: &[&Path],
        limits: ScanLimits,
    ) -> (Vec<String>, bool) {
        let inputs = FloorInputs::new(fix.tree.home(), &fix.root, &fix.env, &[], grants);
        let builder = Builder::new(&inputs, limits);
        let dirs: Vec<PathBuf> = dirs.iter().map(|d| d.to_path_buf()).collect();
        let (targets, truncated) = builder.link_targets(&dirs);
        let names = targets
            .keys()
            .map(|path| {
                Path::new(path)
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default()
            })
            .collect();
        (names, truncated)
    }

    #[test]
    fn a_directory_over_the_per_directory_limit_is_cut_in_name_order() {
        let fix = Fix::new();
        let agent = fix.tree.inside_home(".agent");
        let bin = bin_with_links(&fix, &agent, "b1", 4);
        let (names, truncated) = scan(
            &fix,
            &[cp(&agent)],
            &[&bin],
            ScanLimits {
                per_dir: 3,
                total: 100,
            },
        );
        assert!(truncated);
        assert_eq!(names, ["b1-tool0", "b1-tool1", "b1-tool2"]);
    }

    #[test]
    fn a_directory_exactly_at_the_per_directory_limit_is_complete() {
        let fix = Fix::new();
        let agent = fix.tree.inside_home(".agent");
        let bin = bin_with_links(&fix, &agent, "b1", 3);
        let (names, truncated) = scan(
            &fix,
            &[cp(&agent)],
            &[&bin],
            ScanLimits {
                per_dir: 3,
                total: 100,
            },
        );
        assert!(!truncated);
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn the_total_scan_limit_stops_the_walk_only_when_exceeded() {
        let fix = Fix::new();
        let agent = fix.tree.inside_home(".agent");
        let a = bin_with_links(&fix, &agent, "a", 2);
        let b = bin_with_links(&fix, &agent, "b", 2);
        let (names, truncated) = scan(
            &fix,
            &[cp(&agent)],
            &[&a, &b],
            ScanLimits {
                per_dir: 100,
                total: 3,
            },
        );
        assert!(truncated);
        assert_eq!(names, ["a-tool0", "a-tool1", "b-tool0"]);
        let (names, truncated) = scan(
            &fix,
            &[cp(&agent)],
            &[&a, &b],
            ScanLimits {
                per_dir: 100,
                total: 4,
            },
        );
        assert!(!truncated);
        assert_eq!(names.len(), 4);
    }

    #[test]
    fn a_scan_truncation_is_reported_once_however_often_it_is_noted() {
        let fix = Fix::new();
        let inputs = FloorInputs::new(fix.tree.home(), &fix.root, &fix.env, &[], &[]);
        let mut builder = Builder::new(&inputs, ScanLimits::default());
        builder.note_scan_truncated();
        builder.note_scan_truncated();
        assert_eq!(builder.diagnostics, [FloorDiagnostic::PathScanTruncated]);
    }

    #[test]
    fn exactly_the_target_limit_is_kept_in_full_and_not_reported() {
        let mut fix = Fix::new();
        let (_, agent) = linked_bin(&mut fix, MAX_PATH_TARGETS);
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        assert_eq!(
            with_prefix(&built.floor, "path-target:").len(),
            MAX_PATH_TARGETS
        );
        assert_eq!(count_diag(&built, "path_targets_truncated"), 0);
    }

    #[test]
    fn only_program_directories_are_scanned_for_links_not_every_directory_the_floor_protects() {
        let fix = Fix::new();
        let agent = fix.tree.inside_home(".agent");
        assert_ok!(fs::write(agent.join("tool"), ""));
        // `~/.config/git` is write-denied but is not a directory of programs.
        let git_config = fix.tree.inside_home(".config/git");
        assert_ok!(symlink(agent.join("tool"), git_config.join("link")));
        let built = assert_ok!(fix.build_with(&[cp(&agent)], &[]));
        assert!(with_prefix(&built.floor, "path-target:").is_empty());
    }

    #[test]
    fn a_children_only_path_entry_is_not_scanned_for_links() {
        let mut fix = Fix::new();
        let agent = fix.tree.inside_home(".agent");
        assert_ok!(fs::write(agent.join("tool"), ""));
        let work = fix.home().join("work");
        assert_ok!(symlink(agent.join("tool"), work.join("danger")));
        fix.env.path_var = Some(work.into_os_string());
        let grants = [fix.root.path().clone(), cp(&agent)];
        let built = assert_ok!(fix.build_with(&grants, &[]));
        assert!(with_prefix(&built.floor, "path-target:").is_empty());
    }

    /// A project outside the home directory, so each "contains" condition can be tested alone.
    fn outside_fix() -> Fix {
        let tree = Tree::new();
        let project = tree.outside("project");
        let root = assert_ok!(ProjectRoot::new(canonical(&project), tree.home()));
        let env = FloorEnvironment::new().with_user_temp_dir(tree.outside("tmp"));
        Fix { tree, root, env }
    }

    #[test]
    fn a_path_entry_that_is_the_home_directory_alone_is_children_only() {
        let mut fix = outside_fix();
        fix.env.path_var = Some(fix.home().into_os_string());
        let built = fix.build();
        assert!(has_diag(&built, "path_entry_contains_protected"));
        assert_eq!(
            named(&built.floor, &format!("path:{}", cp(&fix.home()).as_str())).extent,
            Extent::Children
        );
    }

    #[test]
    fn a_path_entry_that_contains_only_the_project_is_children_only() {
        let mut fix = outside_fix();
        let outside = fix.tree.base().join("outside");
        fix.env.path_var = Some(outside.into_os_string());
        let built = fix.build();
        assert!(has_diag(&built, "path_entry_contains_protected"));
    }

    #[test]
    fn a_path_entry_that_contains_only_a_write_grant_is_children_only() {
        let mut fix = outside_fix();
        let parent = fix.tree.outside("elsewhere");
        let grant = fix.tree.outside("elsewhere/g");
        fix.env.path_var = Some(parent.into_os_string());
        let built = assert_ok!(fix.build_with(&[cp(&grant)], &[]));
        assert!(has_diag(&built, "path_entry_contains_protected"));
    }

    #[test]
    fn an_unreadable_git_entry_is_an_error_not_a_missing_one() {
        let fix = Fix::new();
        let _guard = crate::testutil::ModeGuard::set(&fix.proj(), 0o600);
        let err = assert_err!(fix.build_with(&[], &[]));
        assert!(matches!(err, FloorError::GitIo { .. }), "{err:?}");
        crate::error::conventions::assert_display_excludes_sources(&err);
    }

    // ----- walk_links -----

    #[test]
    fn walk_links_resolves_dotdot_inside_a_link_target() {
        let tree = Tree::new();
        let base = tree.outside("w1");
        assert_ok!(fs::create_dir_all(base.join("a")));
        assert_ok!(fs::create_dir_all(base.join("b")));
        assert_ok!(fs::write(base.join("b/f"), ""));
        assert_ok!(symlink("../b/f", base.join("a/l")));
        let walk = assert_some!(walk_links(&base.join("a/l")));
        assert_eq!(walk.end, base.join("b/f"));
        assert_eq!(walk.links, [base.join("a/l")]);
    }

    #[test]
    fn walk_links_applies_dotdot_after_a_missing_component() {
        let tree = Tree::new();
        let base = tree.outside("w2");
        assert_ok!(symlink("missing/../f2", base.join("l")));
        let walk = assert_some!(walk_links(&base.join("l")));
        assert_eq!(walk.end, base.join("f2"));
    }

    #[test]
    fn walk_links_records_every_hop_and_ends_at_a_missing_target() {
        let tree = Tree::new();
        let base = tree.outside("w3");
        assert_ok!(symlink("two", base.join("one")));
        assert_ok!(symlink(base.join("gone"), base.join("two")));
        let walk = assert_some!(walk_links(&base.join("one")));
        assert_eq!(walk.links, [base.join("one"), base.join("two")]);
        assert_eq!(walk.end, base.join("gone"));
    }

    #[test]
    fn walk_links_gives_up_on_a_loop_a_relative_path_and_a_name_too_long_to_look_up() {
        let tree = Tree::new();
        let base = tree.outside("w4");
        assert_ok!(symlink(base.join("b"), base.join("a")));
        assert_ok!(symlink(base.join("a"), base.join("b")));
        assert_none!(walk_links(&base.join("a")));
        assert_none!(walk_links(Path::new("relative/path")));
        assert_none!(walk_links(&base.join("x".repeat(300))));
    }

    #[test]
    fn walk_links_keeps_going_below_a_directory_it_may_not_look_into() {
        let tree = Tree::new();
        let base = tree.outside("w5");
        let locked = base.join("locked");
        assert_ok!(fs::create_dir_all(&locked));
        let _guard = crate::testutil::ModeGuard::set(&locked, 0o000);
        let walk = assert_some!(walk_links(&locked.join("inner")));
        assert_eq!(walk.end, locked.join("inner"));
    }

    // ----- diagnostics read well -----

    #[test]
    fn every_diagnostic_displays_what_happened_with_untrusted_text_escaped() {
        let path = cp(Path::new("/"));
        let all = [
            FloorDiagnostic::PathEntrySkipped(SkippedPathEntry {
                position: 3,
                problem: PathEntryProblem::Relative,
                preview: "bin\u{1b}".to_owned(),
            }),
            FloorDiagnostic::PathEntryUnresolvable {
                entry: "/e\nx".to_owned(),
                reason: "gone".to_owned(),
            },
            FloorDiagnostic::PathEntryInsideProject { path: path.clone() },
            FloorDiagnostic::PathEntryContainsProtected { path: path.clone() },
            FloorDiagnostic::PathTargetsTruncated { limit: 7 },
            FloorDiagnostic::PathScanTruncated,
            FloorDiagnostic::HbExeInsideProject { path },
            FloorDiagnostic::HbExeUnusable {
                reason: "because".to_owned(),
            },
            FloorDiagnostic::UserTempDirUnknown,
            FloorDiagnostic::HardLinkedFloorFile {
                path: PathBuf::from("/x/f"),
                links: 4,
            },
            FloorDiagnostic::EnclosingRepoSkipped {
                dir: "/d".to_owned(),
                reason: "bad".to_owned(),
            },
        ];
        let expected = [
            "PATH entry 3",
            "could not be resolved",
            "inside the project",
            "direct children",
            "more than 7",
            "not every entry",
            "hb is inside the project",
            "because",
            "temporary directory",
            "4 hard links",
            "was not protected: bad",
        ];
        for (diagnostic, needle) in all.iter().zip(expected) {
            let shown = diagnostic.to_string();
            assert!(shown.contains(needle), "{shown} lacks {needle}");
            assert!(!shown.contains(['\u{1b}', '\n']), "{shown:?}");
            assert!(!diagnostic.kind().is_empty());
        }
    }

    #[test]
    fn building_twice_gives_the_same_floor() {
        let fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let a = assert_ok!(fix.build_with(&fix.grant(), &[]));
        let b = assert_ok!(fix.build_with(&fix.grant(), &[]));
        assert_eq!(a, b);
    }

    #[test]
    fn every_rule_name_is_unique() {
        let fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        let mut names = names(&built.floor);
        let total = names.len();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), total);
    }

    #[test]
    fn every_floor_rule_is_canonical_and_never_covers_the_home_directory_or_the_project_root_by_a_subtree()
     {
        let fix = Fix::new();
        assert_ok!(fs::create_dir_all(fix.proj().join(".git/hooks")));
        let built = assert_ok!(fix.build_with(&fix.grant(), &[]));
        for protected in [cp(&fix.home()), cp(&fix.proj())] {
            for rule in built.floor.rules() {
                if rule.effect != FloorEffect::PinUnlink && rule.extent == Extent::Subtree {
                    assert_ne!(
                        rule.covers(&protected),
                        Coverage::Yes,
                        "{} would deny {}",
                        rule.name,
                        protected.as_str()
                    );
                }
            }
        }
    }
}
