// ABOUTME: Cache generations: a sealed, closed tree built by `hb warm`, and an independent writable copy for each run.
// ABOUTME: A run never gets the published tree, so one hostile run cannot change what a later run executes (hb-dai).
//! Isolated cache generations (design 10, hb-dai).
//!
//! `hb warm` builds a generation in a workspace, seals it into a separate tree (a rename would
//! keep a warm descendant's open writable descriptors), and publishes it. Each run then copies the
//! generation into its own session directory. Nothing here follows a symlink out of a tree, and
//! nothing falls back to the old shared cache.

use std::collections::{BTreeMap, HashMap};
use std::fs::{self, DirBuilder, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::io::Errno;
use rustix::process::geteuid;
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu, ensure};
use strum::{AsRefStr, Display};

use crate::approval::Digest;
use crate::policy::CanonicalPath;
use crate::system::ToolLookup;
use crate::warm::stamp::digest as invocation_digest;
use crate::warm::{Server, servers};

/// Which bounded resource a copy or seal ran out of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum Resource {
    /// Total logical bytes of regular files.
    Bytes,
    /// Number of directory entries.
    Entries,
    /// Directory nesting depth.
    Depth,
    /// Length of one path.
    PathLength,
}

/// Why a tree entry cannot be part of a generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum Rejection {
    /// A socket, FIFO or device.
    SpecialFile,
    /// A symlink whose target leaves the tree.
    EscapingLink,
    /// A symlink that points nowhere.
    DanglingLink,
    /// A chain of symlinks that never ends.
    LinkCycle,
    /// A file with a link count above one that the tree does not account for.
    ForeignHardLink,
    /// A setuid or setgid bit.
    SpecialMode,
    /// A file or directory writable by group or others.
    OpenPermissions,
    /// An owner other than the current user.
    ForeignOwner,
    /// A path that is not valid UTF-8 or has a `..` component.
    BadName,
    /// A different filesystem mounted inside the tree.
    MountCrossing,
}

/// What is wrong with a record file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum RecordFault {
    /// Larger than the bound, or not a regular file.
    TooLarge,
    /// Not valid JSON of the expected shape.
    Malformed,
    /// A format number this hb does not know.
    UnsupportedFormat,
    /// An id that is not a plain name.
    BadId,
    /// The manifest's hash differs from the one the current record names.
    HashMismatch,
}

/// The step of publication that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum Phase {
    /// Writing the manifest or inventory.
    Metadata,
    /// Flushing data to disk.
    Sync,
    /// Renaming the sealed tree into place.
    Rename,
    /// Replacing the project's current record.
    Current,
}

/// Which input a published generation no longer matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum Mismatch {
    /// A tool (uv, npm, node) changed.
    Tool,
    /// A declared server was not warmed, or was warmed with other arguments.
    Server,
    /// Built for another OS or architecture.
    Platform,
    /// The bytes on disk are not the bytes that were published.
    Contents,
}

/// What a cache operation can refuse or fail at.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum CacheError {
    /// A tree entry is not allowed in a generation.
    #[snafu(display("{} cannot be part of a cache generation: {reason}", path.display()))]
    InvalidEntry {
        /// The entry, relative to the tree root.
        path: PathBuf,
        /// Why it was refused.
        reason: Rejection,
    },

    /// A bound on a tree was exceeded.
    #[snafu(display("the cache tree has {required} {resource}, over the limit of {limit}"))]
    BudgetExceeded {
        /// The bounded resource.
        resource: Resource,
        /// How much the tree needs.
        required: u64,
        /// The most that is allowed.
        limit: u64,
    },

    /// The volume has less free space than the copy needs plus the floor.
    #[snafu(display(
        "{} has {available} bytes free; the cache copy needs {required} and the floor is {floor}",
        path.display()
    ))]
    NoSpace {
        /// A directory on the destination volume.
        path: PathBuf,
        /// Bytes free now.
        available: u64,
        /// Bytes the copy needs.
        required: u64,
        /// Bytes that must stay free.
        floor: u64,
    },

    /// Reading, copying or creating one entry failed.
    #[snafu(display("could not copy {} to {}", from.display(), to.display()))]
    Copy {
        /// The source entry.
        from: PathBuf,
        /// The destination entry.
        to: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// Reading the tree failed.
    #[snafu(display("could not read {}", path.display()))]
    Read {
        /// The entry.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// No generation was ever published for this project.
    #[snafu(display(
        "no cache generation exists for this project; run `hb warm` outside the ball"
    ))]
    MissingGeneration,

    /// Only the old shared cache exists, and hb never uses it.
    #[snafu(display(
        "only the old shared cache at {} exists; hb does not use it. Run `hb warm` outside the ball (the old cache is left untouched)",
        path.display()
    ))]
    LegacyCache {
        /// The old cache root.
        path: PathBuf,
    },

    /// A published generation no longer matches what this run needs.
    #[snafu(display(
        "the cache generation {id} is stale ({what}); run `hb warm` outside the ball"
    ))]
    StaleManifest {
        /// The generation.
        id: String,
        /// What differs.
        what: Mismatch,
    },

    /// A record or manifest could not be read as the supported format.
    #[snafu(display(
        "{} is not a usable cache record ({reason}); run `hb warm` outside the ball to publish a new one",
        path.display()
    ))]
    BadRecord {
        /// The file.
        path: PathBuf,
        /// What was wrong with it.
        reason: RecordFault,
    },

    /// There is no per-user temporary directory to build in.
    #[snafu(display("there is no per-user temporary directory to build the cache in"))]
    NoTempDir,

    /// Another `hb warm` holds the project's lock.
    #[snafu(display("another hb warm is already running for this project"))]
    WarmBusy,

    /// Publishing a sealed generation failed.
    #[snafu(display("could not publish the cache generation ({phase})"))]
    Publish {
        /// The step.
        phase: Phase,
        /// The underlying error.
        source: io::Error,
    },

    /// Removing a partial tree failed; the bytes are still on disk.
    #[snafu(display("could not remove {}", path.display()))]
    Cleanup {
        /// The leftover path.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

/// Bounds on a tree that is sealed or copied.
///
/// A byte and entry cap bound what is materialised. They do not bound what a run writes later.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLimits {
    /// Most logical bytes of regular files (sparse files count their full length).
    pub max_bytes: u64,
    /// Most directory entries of any kind.
    pub max_entries: u64,
    /// Deepest nesting.
    pub max_depth: u32,
    /// Longest single path in bytes.
    pub max_path_len: u32,
    /// Free bytes that must remain on the destination volume after the copy.
    pub min_free_bytes: u64,
}

impl Default for CacheLimits {
    fn default() -> Self {
        const GIB: u64 = 1 << 30;
        Self {
            max_bytes: 2 * GIB,
            max_entries: 100_000,
            max_depth: 64,
            max_path_len: 1024,
            min_free_bytes: 2 * GIB,
        }
    }
}

/// What one tree copy did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CopyStats {
    /// Logical bytes of regular files.
    pub bytes: u64,
    /// Entries of any kind, directories included.
    pub entries: u64,
    /// Regular files made by an APFS clone.
    pub cloned: u64,
    /// Regular files made by a byte copy.
    pub copied: u64,
}

/// How a tree is copied.
#[derive(Debug, Clone, Copy)]
pub struct CopyPlan<'a> {
    /// The bounds the tree must stay inside.
    pub limits: CacheLimits,
    /// An absolute symlink under this old root is rewritten as a relative link inside the copy.
    /// `None` means every link must already be relative.
    pub rewrite_from: Option<&'a Path>,
}

/// Copies the tree at `src` to the new directory `dst`, one entry at a time, never following a
/// symlink. Every regular file becomes a new inode, so no hard link survives.
///
/// # Errors
/// [`CacheError`] naming the first entry that is not allowed, or the bound that was exceeded.
pub fn copy_tree(src: &Path, dst: &Path, plan: CopyPlan<'_>) -> Result<CopyStats, CacheError> {
    let root_meta = fs::symlink_metadata(src).context(ReadSnafu { path: src })?;
    let mut walk = Walk {
        plan,
        src_root: src,
        dst_root: dst,
        dev: root_meta.dev(),
        uid: geteuid().as_raw(),
        stats: CopyStats::default(),
        names_per_inode: HashMap::new(),
        links: Vec::new(),
    };
    private_dir(dst).context(CopySnafu { from: src, to: dst })?;
    walk.dir(src, dst, 0)?;
    walk.check_hard_links()?;
    walk.check_links()?;
    Ok(walk.stats)
}

struct Walk<'a> {
    plan: CopyPlan<'a>,
    src_root: &'a Path,
    dst_root: &'a Path,
    dev: u64,
    uid: u32,
    stats: CopyStats,
    /// (device, inode) -> (names seen in the tree, link count the filesystem reports).
    names_per_inode: HashMap<(u64, u64), (u64, u64)>,
    /// Links written, to check once the whole tree exists.
    links: Vec<PathBuf>,
}

impl Walk<'_> {
    fn rel(&self, path: &Path) -> PathBuf {
        path.strip_prefix(self.src_root)
            .unwrap_or(path)
            .to_path_buf()
    }

    fn reject<T>(&self, path: &Path, reason: Rejection) -> Result<T, CacheError> {
        InvalidEntrySnafu {
            path: self.rel(path),
            reason,
        }
        .fail()
    }

    fn count(
        &mut self,
        resource: Resource,
        now: u64,
        add: u64,
        limit: u64,
    ) -> Result<u64, CacheError> {
        let total = now.saturating_add(add);
        ensure!(
            total <= limit,
            BudgetExceededSnafu {
                resource,
                required: total,
                limit
            }
        );
        Ok(total)
    }

    fn dir(&mut self, src: &Path, dst: &Path, depth: u32) -> Result<(), CacheError> {
        let limits = self.plan.limits;
        ensure!(
            depth <= limits.max_depth,
            BudgetExceededSnafu {
                resource: Resource::Depth,
                required: u64::from(depth),
                limit: u64::from(limits.max_depth)
            }
        );
        let mut names: Vec<_> = fs::read_dir(src)
            .context(ReadSnafu { path: src })?
            .map(|e| e.map(|e| e.file_name()).context(ReadSnafu { path: src }))
            .collect::<Result<_, _>>()?;
        names.sort();
        for name in names {
            self.stats.entries =
                self.count(Resource::Entries, self.stats.entries, 1, limits.max_entries)?;
            let (from, to) = (src.join(&name), dst.join(&name));
            ensure!(
                name.to_str().is_some()
                    && from.as_os_str().len() as u64 <= u64::from(limits.max_path_len),
                InvalidEntrySnafu {
                    path: self.rel(&from),
                    reason: Rejection::BadName
                }
            );
            self.entry(&from, &to, depth)?;
        }
        Ok(())
    }

    fn entry(&mut self, from: &Path, to: &Path, depth: u32) -> Result<(), CacheError> {
        let meta = fs::symlink_metadata(from).context(ReadSnafu { path: from })?;
        if meta.dev() != self.dev {
            return self.reject(from, Rejection::MountCrossing);
        }
        if meta.uid() != self.uid {
            return self.reject(from, Rejection::ForeignOwner);
        }
        let kind = meta.file_type();
        if kind.is_symlink() {
            return self.link(from, to);
        }
        if meta.mode() & 0o6000 != 0 {
            return self.reject(from, Rejection::SpecialMode);
        }
        if meta.mode() & 0o022 != 0 {
            return self.reject(from, Rejection::OpenPermissions);
        }
        if kind.is_dir() {
            private_dir(to).context(CopySnafu { from, to })?;
            return self.dir(from, to, depth + 1);
        }
        if kind.is_file() {
            return self.file(from, to, &meta);
        }
        self.reject(from, Rejection::SpecialFile)
    }

    fn link(&mut self, from: &Path, to: &Path) -> Result<(), CacheError> {
        let target = fs::read_link(from).context(ReadSnafu { path: from })?;
        let new = match (target.is_absolute(), self.plan.rewrite_from) {
            (false, _) => target,
            (true, Some(old)) => match target.strip_prefix(old) {
                Ok(inside) => relative_between(
                    to.parent().unwrap_or(self.dst_root),
                    &self.dst_root.join(inside),
                ),
                Err(_) => return self.reject(from, Rejection::EscapingLink),
            },
            (true, None) => return self.reject(from, Rejection::EscapingLink),
        };
        std::os::unix::fs::symlink(&new, to).context(CopySnafu { from, to })?;
        self.links.push(to.to_path_buf());
        Ok(())
    }

    fn file(&mut self, from: &Path, to: &Path, meta: &fs::Metadata) -> Result<(), CacheError> {
        self.stats.bytes = self.count(
            Resource::Bytes,
            self.stats.bytes,
            meta.len(),
            self.plan.limits.max_bytes,
        )?;
        let seen = self
            .names_per_inode
            .entry((meta.dev(), meta.ino()))
            .or_insert((0, meta.nlink()));
        seen.0 += 1;
        let executable = meta.mode() & 0o100 != 0;
        match clone_or_copy(from, to).context(CopySnafu { from, to })? {
            Made::Cloned => self.stats.cloned += 1,
            Made::Copied => self.stats.copied += 1,
        }
        let mode = if executable { 0o700 } else { 0o600 };
        fs::set_permissions(to, fs::Permissions::from_mode(mode)).context(CopySnafu { from, to })
    }

    fn check_hard_links(&self) -> Result<(), CacheError> {
        for (names, count) in self.names_per_inode.values() {
            if names != count {
                return InvalidEntrySnafu {
                    path: PathBuf::from("."),
                    reason: Rejection::ForeignHardLink,
                }
                .fail();
            }
        }
        Ok(())
    }

    fn check_links(&self) -> Result<(), CacheError> {
        let root = fs::canonicalize(self.dst_root).context(ReadSnafu {
            path: self.dst_root,
        })?;
        for link in &self.links {
            let reason = match fs::canonicalize(link) {
                Ok(real) if real.starts_with(&root) => continue,
                Ok(_) => Rejection::EscapingLink,
                Err(e) if e.raw_os_error() == Some(Errno::LOOP.raw_os_error()) => {
                    Rejection::LinkCycle
                }
                Err(_) => Rejection::DanglingLink,
            };
            let path = link
                .strip_prefix(self.dst_root)
                .unwrap_or(link)
                .to_path_buf();
            return InvalidEntrySnafu { path, reason }.fail();
        }
        Ok(())
    }
}

enum Made {
    Cloned,
    Copied,
}

/// Makes `to` a new file with the bytes of `from`: an APFS clone where the volume supports it,
/// a byte copy where it says so. Any other error is the caller's, never retried another way.
fn clone_or_copy(from: &Path, to: &Path) -> io::Result<Made> {
    let source = OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(from)?;
    match rustix::fs::fclonefileat(
        &source,
        rustix::fs::CWD,
        to,
        rustix::fs::CloneFlags::empty(),
    ) {
        Ok(()) => Ok(Made::Cloned),
        Err(Errno::NOTSUP | Errno::XDEV) => {
            let mut dest = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(to)?;
            io::copy(&mut &source, &mut dest)?;
            Ok(Made::Copied)
        }
        Err(e) => Err(e.into()),
    }
}

fn libc_o_nofollow() -> i32 {
    rustix::fs::OFlags::NOFOLLOW.bits() as i32
}

/// The relative path from directory `base` to `target`, both absolute.
fn relative_between(base: &Path, target: &Path) -> PathBuf {
    let (b, t): (Vec<_>, Vec<_>) = (base.components().collect(), target.components().collect());
    let common = b.iter().zip(&t).take_while(|(x, y)| x == y).count();
    let mut out = PathBuf::new();
    for _ in common..b.len() {
        out.push("..");
    }
    for part in &t[common..] {
        out.push(part);
    }
    out
}

/// Creates `path` private to the owner; it must not exist yet.
fn private_dir(path: &Path) -> io::Result<()> {
    DirBuilder::new().mode(0o700).create(path)
}

/// A run's own writable copy of a generation, inside its session directory.
#[derive(Debug)]
pub struct SessionCache {
    root: PathBuf,
    stats: CopyStats,
}

impl SessionCache {
    /// The directory the run's `uv` and `npm` write to.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// What the copy did.
    #[must_use]
    pub fn stats(&self) -> CopyStats {
        self.stats
    }
}

/// Copies the sealed tree `generation` to `<session>/cache`, all or nothing.
///
/// The copy is built in `<session>/cache.partial` and renamed once complete, so a run never starts
/// on half a cache. If anything fails, the partial tree is removed; if that removal fails too, the
/// error says so, because those bytes are still on disk.
///
/// # Errors
/// [`CacheError`]: a bound exceeded, too little free space, a refused entry, an I/O failure, or a
/// cleanup that could not finish.
pub fn materialize(
    generation: &Path,
    session: &Path,
    limits: CacheLimits,
) -> Result<SessionCache, CacheError> {
    let partial = session.join("cache.partial");
    let root = session.join("cache");
    let attempt = (|| {
        check_free_space(generation, session, limits)?;
        let stats = copy_tree(
            generation,
            &partial,
            CopyPlan {
                limits,
                rewrite_from: None,
            },
        )?;
        fs::rename(&partial, &root).context(CopySnafu {
            from: &partial,
            to: &root,
        })?;
        Ok(SessionCache {
            root: root.clone(),
            stats,
        })
    })();
    if attempt.is_err() {
        remove_tree(&partial)?;
    }
    attempt
}

/// Fails with [`CacheError::NoSpace`] unless the volume of `session` can hold the tree at
/// `generation` and still keep `limits.min_free_bytes` free.
fn check_free_space(
    generation: &Path,
    session: &Path,
    limits: CacheLimits,
) -> Result<(), CacheError> {
    let required = tree_bytes(generation, limits)?;
    let stat = rustix::fs::statvfs(session)
        .map_err(io::Error::from)
        .context(ReadSnafu { path: session })?;
    let available = stat.f_bavail.saturating_mul(stat.f_frsize);
    ensure!(
        available >= required.saturating_add(limits.min_free_bytes),
        NoSpaceSnafu {
            path: session,
            available,
            required,
            floor: limits.min_free_bytes
        }
    );
    Ok(())
}

/// Logical bytes of the regular files under `root`, within `limits`.
fn tree_bytes(root: &Path, limits: CacheLimits) -> Result<u64, CacheError> {
    let mut total = 0_u64;
    let mut entries = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).context(ReadSnafu { path: &dir })? {
            let entry = entry.context(ReadSnafu { path: &dir })?;
            entries += 1;
            ensure!(
                entries <= limits.max_entries,
                BudgetExceededSnafu {
                    resource: Resource::Entries,
                    required: entries,
                    limit: limits.max_entries
                }
            );
            let meta =
                fs::symlink_metadata(entry.path()).context(ReadSnafu { path: entry.path() })?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() {
                total = total.saturating_add(meta.len());
                ensure!(
                    total <= limits.max_bytes,
                    BudgetExceededSnafu {
                        resource: Resource::Bytes,
                        required: total,
                        limit: limits.max_bytes
                    }
                );
            }
        }
    }
    Ok(total)
}

/// Removes `path` and everything under it without following links; a missing path is fine.
///
/// # Errors
/// [`CacheError::Cleanup`] if something is left behind.
pub fn remove_tree(path: &Path) -> Result<(), CacheError> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(CacheError::Cleanup {
                path: path.to_path_buf(),
                source,
            });
        }
        Ok(_) => {}
    }
    // A run may have made directories unreadable; make ours writable again before removing.
    reopen(path);
    fs::remove_dir_all(path).context(CleanupSnafu { path })
}

/// Makes every directory under `dir` (and `dir`) owner-accessible so `remove_dir_all` can enter it.
fn reopen(dir: &Path) {
    let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.file_type().is_ok_and(|t| t.is_dir()) {
            reopen(&entry.path());
        }
    }
}

/// The manifest format this hb writes and reads.
pub const MANIFEST_FORMAT: u32 = 1;
/// The largest manifest or current record that is read.
const MAX_RECORD_BYTES: u64 = 1 << 20;
/// Name of the legacy shared cache's subdirectories, which are never read.
const LEGACY_DIRS: [&str; 3] = ["uv", "uv-tools", "npm"];

/// What a generation was built from. A run recomputes these and compares; a difference is stale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedInputs {
    /// Hash of the canonical project root; names the project's `current` record.
    pub project_key: String,
    /// Digest of the resolved uv, npm and node (canonical path, size and modification time).
    pub tool_digest: String,
    /// Each warmed server's name and the digest of its command and arguments. A generation
    /// serves a run when it holds every server the run declares; extra servers are fine.
    pub servers: BTreeMap<String, String>,
    /// `<os>-<arch>`.
    pub platform: String,
}

/// What `hb warm` publishes next to a generation. It is metadata, not a signature and not proof
/// that the packages are benign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheManifest {
    /// [`MANIFEST_FORMAT`].
    pub format: u32,
    /// The generation's id.
    pub id: String,
    /// What it was built from.
    pub inputs: ExpectedInputs,
    /// Logical bytes of regular files.
    pub logical_bytes: u64,
    /// Entries of any kind.
    pub entries: u64,
    /// Seconds since the epoch, for display only.
    pub created_at: u64,
    /// The hb version that built it, for display only.
    pub hb_version: String,
}

/// The per-project pointer to the one complete generation. Written whole and renamed into place.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CurrentRecord {
    format: u32,
    id: String,
    manifest_sha256: String,
}

/// A published generation, found and checked but not yet copied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheGeneration {
    /// Its id.
    pub id: String,
    /// The sealed tree.
    pub root: PathBuf,
    /// Its manifest.
    pub manifest: CacheManifest,
}

/// Where generations live: `<cache root>/generations`, `projects`, `staging`.
#[derive(Debug, Clone)]
pub struct CacheStore {
    root: PathBuf,
}

impl CacheStore {
    /// The store under `root` (normally `~/.cache/hamster-ball`). Performs no I/O.
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn generation_dir(&self, id: &str) -> PathBuf {
        self.root.join("generations").join(id)
    }

    fn current_path(&self, project_key: &str) -> PathBuf {
        self.root.join("projects").join(project_key).join("current")
    }

    /// Finds the generation the project's `current` record names and checks it against
    /// `expected`. It never looks at the old shared cache except to say it exists.
    ///
    /// # Errors
    /// [`CacheError::LegacyCache`] when only the old cache exists, [`CacheError::MissingGeneration`]
    /// when nothing does, [`CacheError::StaleManifest`] when an input differs, and
    /// [`CacheError::BadRecord`] when a record is unreadable.
    pub fn select(&self, expected: &ExpectedInputs) -> Result<CacheGeneration, CacheError> {
        let current_path = self.current_path(&expected.project_key);
        let Some(bytes) = read_record(&current_path)? else {
            return Err(self.absent());
        };
        let record: CurrentRecord = parse(&current_path, &bytes)?;
        check_id(&current_path, &record.id)?;
        ensure!(
            record.format == MANIFEST_FORMAT,
            BadRecordSnafu {
                path: &current_path,
                reason: RecordFault::UnsupportedFormat
            }
        );
        let manifest_path = self.generation_dir(&record.id).join("manifest.json");
        let manifest_bytes = read_record(&manifest_path)?.context(MissingGenerationSnafu)?;
        ensure!(
            Digest::of(&manifest_bytes).to_string() == record.manifest_sha256,
            BadRecordSnafu {
                path: &manifest_path,
                reason: RecordFault::HashMismatch
            }
        );
        let manifest: CacheManifest = parse(&manifest_path, &manifest_bytes)?;
        ensure!(
            manifest.format == MANIFEST_FORMAT && manifest.id == record.id,
            BadRecordSnafu {
                path: &manifest_path,
                reason: RecordFault::UnsupportedFormat
            }
        );
        manifest.inputs.check(&record.id, expected)?;
        Ok(CacheGeneration {
            root: self.generation_dir(&record.id).join("data"),
            id: record.id,
            manifest,
        })
    }

    /// The error for "no current record": legacy if the old cache directories exist.
    fn absent(&self) -> CacheError {
        match LEGACY_DIRS
            .iter()
            .map(|d| self.root.join(d))
            .find(|p| p.is_dir())
        {
            Some(_) => CacheError::LegacyCache {
                path: self.root.clone(),
            },
            None => CacheError::MissingGeneration,
        }
    }
}

impl ExpectedInputs {
    /// Checks that this (published) set can serve `expected`, naming the first input that differs.
    fn check(&self, id: &str, expected: &Self) -> Result<(), CacheError> {
        let served = expected
            .servers
            .iter()
            .all(|(name, digest)| self.servers.get(name) == Some(digest));
        let what = [
            (self.platform != expected.platform, Mismatch::Platform),
            (self.tool_digest != expected.tool_digest, Mismatch::Tool),
            (!served, Mismatch::Server),
        ]
        .into_iter()
        .find_map(|(differs, what)| differs.then_some(what));
        match what {
            Some(what) => StaleManifestSnafu { id, what }.fail(),
            None => Ok(()),
        }
    }
}

/// What the current config and tools say a generation must hold.
///
/// `root` is the project's canonical root. The tool digest covers each found `uv`, `uvx`, `npm`
/// and `npx`, `node` and so on by canonical path, size and modification time: a replaced
/// binary changes it, and no tool is run to find out.
///
/// # Errors
/// [`CacheError::Read`] if a found tool cannot be examined.
pub fn expected_inputs(
    root: &CanonicalPath,
    policy: &crate::config::Policy,
    tools: &ToolLookup,
) -> Result<ExpectedInputs, CacheError> {
    let selected: Vec<Server> = servers(policy);
    expected_inputs_for(root, &selected, tools)
}

/// [`expected_inputs`] for an explicit server list (what `hb warm NAME...` publishes).
///
/// # Errors
/// [`CacheError::Read`] if a found tool cannot be examined.
pub fn expected_inputs_for(
    root: &CanonicalPath,
    selected: &[Server],
    tools: &ToolLookup,
) -> Result<ExpectedInputs, CacheError> {
    let servers = selected
        .iter()
        .map(|s| {
            let args: Vec<&str> = s.args.iter().map(String::as_str).collect();
            (s.name.clone(), invocation_digest(&s.command, &args))
        })
        .collect();
    let mut tool_bytes = Vec::new();
    let mut found: Vec<_> = tools.found.iter().collect();
    found.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
    for tool in found {
        let path = tool.dir.as_path().join(tool.name.as_str());
        let meta = fs::metadata(&path).context(ReadSnafu { path: &path })?;
        let stamp = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok());
        for word in [
            path.to_string_lossy().into_owned(),
            meta.len().to_string(),
            stamp.map_or_else(String::new, |d| d.as_nanos().to_string()),
        ] {
            tool_bytes.extend_from_slice(&(word.len() as u64).to_be_bytes());
            tool_bytes.extend_from_slice(word.as_bytes());
        }
    }
    Ok(ExpectedInputs {
        project_key: Digest::of(root.as_str().as_bytes()).to_string(),
        tool_digest: Digest::of(&tool_bytes).to_string(),
        servers,
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    })
}

/// Copies the user's own uv-managed interpreter into `workspace/python`, so the warm ball builds
/// against a Python inside the generation and no link names `~/.local/share/uv/python`.
///
/// The interpreter is copied by this process on the host, before the warm ball starts, from a tree
/// uv itself installed. It is refused like any other tree if it holds a link that leaves it.
/// `None` means the user has no managed interpreter; a warm without one is refused by uv itself
/// (downloads are off), with uv's own message.
///
/// # Errors
/// [`CacheError`] if the interpreter tree is refused or cannot be copied.
pub fn seed_python(
    uv_python_dir: &Path,
    workspace: &Path,
    limits: CacheLimits,
) -> Result<Option<PathBuf>, CacheError> {
    let Some(newest) = newest_interpreter(uv_python_dir)? else {
        return Ok(None);
    };
    let python = workspace.join("python");
    DirBuilder::new()
        .mode(0o700)
        .create(&python)
        .context(ReadSnafu { path: &python })?;
    let name = newest.file_name().unwrap_or_default();
    let dest = python.join(name);
    copy_tree(
        &newest,
        &dest,
        CopyPlan {
            limits,
            rewrite_from: None,
        },
    )?;
    Ok(Some(dest))
}

/// The highest-named `cpython-*` directory under `dir`, a plain directory (never a link).
fn newest_interpreter(dir: &Path) -> Result<Option<PathBuf>, CacheError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CacheError::Read {
                path: dir.to_path_buf(),
                source,
            });
        }
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("cpython-"))
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .map(|e| e.path())
        .collect();
    found.sort();
    Ok(found.pop())
}

/// A unique name for a build or generation: process id, nanoseconds and a counter.
fn fresh_id() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("g{}-{nanos}-{n}", std::process::id())
}

/// `hb-<pid>-<nanos>-<counter>`: the name shape the session sweep recognises and, once the
/// process is gone, removes.
fn fresh_build_name() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("hb-{}-{nanos}-{n}", std::process::id())
}

impl CacheStore {
    /// Creates the store's directories, private to the owner. Existing ones are left alone.
    ///
    /// # Errors
    /// [`CacheError::Copy`]-free: a [`CacheError::Read`] if a directory cannot be made.
    pub fn ensure_dirs(&self) -> Result<(), CacheError> {
        for sub in ["", "generations", "projects", "staging"] {
            let dir = self.root.join(sub);
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir)
                .context(ReadSnafu { path: dir })?;
        }
        Ok(())
    }

    /// A fresh, empty workspace under `parent` (the per-user temporary directory) for `hb warm`
    /// to build in. It is never selectable, and it is named like a session directory, so the
    /// stale-directory sweep removes one that an interrupted warm left behind.
    ///
    /// The workspace is outside the store on purpose: no ball is ever given a path inside it.
    ///
    /// # Errors
    /// [`CacheError`] if the directory cannot be made.
    pub fn begin_build(&self, parent: &Path) -> Result<PathBuf, CacheError> {
        let dir = parent.join(fresh_build_name());
        private_dir(&dir).context(ReadSnafu { path: &dir })?;
        Ok(dir)
    }

    /// Seals the finished `workspace` and publishes it as the project's current generation.
    ///
    /// The sealed tree is a separate copy, so a warm process that still holds an open file in the
    /// workspace cannot write into what is published. The `current` record is replaced last and
    /// whole, so a reader sees the old generation or the new one, never a half-written one.
    /// The caller owns `workspace` and removes it (see [`remove_tree`]) after this returns, so a
    /// cleanup failure is never mistaken for a failed publish. On failure the staging copy is
    /// removed and the project's `current` record is untouched.
    ///
    /// # Errors
    /// [`CacheError`] for a refused entry, a bound, or a failed write, sync or rename.
    pub fn seal_and_publish(
        &self,
        workspace: &Path,
        inputs: &ExpectedInputs,
        old_root: Option<&Path>,
        limits: CacheLimits,
    ) -> Result<CacheGeneration, CacheError> {
        let id = fresh_id();
        let staging = self.root.join("staging").join(&id);
        let result =
            self.seal_and_publish_inner(workspace, &staging, &id, inputs, old_root, limits);
        if result.is_err() {
            remove_tree(&staging)?;
            let _ = std::fs::remove_dir_all(self.generation_dir(&id));
        }
        result
    }

    fn seal_and_publish_inner(
        &self,
        workspace: &Path,
        staging: &Path,
        id: &str,
        inputs: &ExpectedInputs,
        old_root: Option<&Path>,
        limits: CacheLimits,
    ) -> Result<CacheGeneration, CacheError> {
        self.ensure_dirs()?;
        private_dir(staging).context(ReadSnafu { path: staging })?;
        let data = staging.join("data");
        let stats = copy_tree(
            workspace,
            &data,
            CopyPlan {
                limits,
                rewrite_from: old_root,
            },
        )?;
        let manifest = CacheManifest {
            format: MANIFEST_FORMAT,
            id: id.to_owned(),
            inputs: inputs.clone(),
            logical_bytes: stats.bytes,
            entries: stats.entries,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
            hb_version: env!("CARGO_PKG_VERSION").to_owned(),
        };
        let manifest_bytes = serde_json::to_vec(&manifest).map_err(|e| CacheError::Publish {
            phase: Phase::Metadata,
            source: io::Error::other(e),
        })?;
        write_new(
            &staging.join("manifest.json"),
            &manifest_bytes,
            Phase::Metadata,
        )?;
        sync_tree(staging)?;
        let published = self.generation_dir(id);
        fs::rename(staging, &published).context(PublishSnafu {
            phase: Phase::Rename,
        })?;
        sync_dir(&self.root.join("generations"), Phase::Rename)?;
        let record = CurrentRecord {
            format: MANIFEST_FORMAT,
            id: id.to_owned(),
            manifest_sha256: Digest::of(&manifest_bytes).to_string(),
        };
        self.replace_current(&inputs.project_key, &record)?;
        Ok(CacheGeneration {
            id: id.to_owned(),
            root: published.join("data"),
            manifest,
        })
    }

    fn replace_current(&self, project_key: &str, record: &CurrentRecord) -> Result<(), CacheError> {
        let path = self.current_path(project_key);
        let dir = path.parent().unwrap_or(&self.root);
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .context(PublishSnafu {
                phase: Phase::Current,
            })?;
        let bytes = serde_json::to_vec(record).map_err(|e| CacheError::Publish {
            phase: Phase::Current,
            source: io::Error::other(e),
        })?;
        let tmp = dir.join(format!("current.{}", fresh_id()));
        write_new(&tmp, &bytes, Phase::Current)?;
        fs::rename(&tmp, &path).context(PublishSnafu {
            phase: Phase::Current,
        })?;
        sync_dir(dir, Phase::Current)
    }
}

/// An exclusive hold on one project's warm. Released when dropped, including when `hb` is killed,
/// because the kernel drops an advisory lock with its file descriptor.
#[derive(Debug)]
pub struct WarmLock {
    _file: fs::File,
}

impl CacheStore {
    /// Takes the project's warm lock without waiting.
    ///
    /// # Errors
    /// [`CacheError::WarmBusy`] if another `hb warm` for the project holds it.
    pub fn lock_warm(&self, project_key: &str) -> Result<WarmLock, CacheError> {
        self.ensure_dirs()?;
        let dir = self.root.join("projects").join(project_key);
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)
            .context(ReadSnafu { path: &dir })?;
        let path = dir.join("warm.lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .custom_flags(libc_o_nofollow())
            .open(&path)
            .context(ReadSnafu { path: &path })?;
        match rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(WarmLock { _file: file }),
            Err(Errno::WOULDBLOCK) => Err(CacheError::WarmBusy),
            Err(e) => Err(CacheError::Read {
                path,
                source: e.into(),
            }),
        }
    }
}

/// Writes `bytes` to a new private file and flushes it.
fn write_new(path: &Path, bytes: &[u8], phase: Phase) -> Result<(), CacheError> {
    use std::io::Write;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .context(PublishSnafu { phase })?;
    file.write_all(bytes).context(PublishSnafu { phase })?;
    file.sync_all().context(PublishSnafu { phase })
}

fn sync_dir(dir: &Path, phase: Phase) -> Result<(), CacheError> {
    fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .context(PublishSnafu { phase })
}

/// Flushes every file and directory under `root`, bottom up.
fn sync_tree(root: &Path) -> Result<(), CacheError> {
    for entry in fs::read_dir(root).context(PublishSnafu { phase: Phase::Sync })? {
        let entry = entry.context(PublishSnafu { phase: Phase::Sync })?;
        let kind = entry
            .file_type()
            .context(PublishSnafu { phase: Phase::Sync })?;
        if kind.is_dir() {
            sync_tree(&entry.path())?;
        } else if kind.is_file() {
            fs::File::open(entry.path())
                .and_then(|f| f.sync_all())
                .context(PublishSnafu { phase: Phase::Sync })?;
        }
    }
    sync_dir(root, Phase::Sync)
}

/// Reads a small regular file with no symlink following; `None` if it does not exist.
fn read_record(path: &Path) -> Result<Option<Vec<u8>>, CacheError> {
    use std::io::Read;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc_o_nofollow())
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(CacheError::Read {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    let meta = file.metadata().context(ReadSnafu { path })?;
    ensure!(
        meta.is_file() && meta.len() <= MAX_RECORD_BYTES,
        BadRecordSnafu {
            path,
            reason: RecordFault::TooLarge
        }
    );
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES)
        .read_to_end(&mut bytes)
        .context(ReadSnafu { path })?;
    Ok(Some(bytes))
}

fn parse<T: serde::de::DeserializeOwned>(path: &Path, bytes: &[u8]) -> Result<T, CacheError> {
    serde_json::from_slice(bytes).map_err(|_| CacheError::BadRecord {
        path: path.to_path_buf(),
        reason: RecordFault::Malformed,
    })
}

/// An id is one plain path component: no separator, no dot-dot, not empty, not long.
fn check_id(path: &Path, id: &str) -> Result<(), CacheError> {
    let plain = !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    ensure!(
        plain,
        BadRecordSnafu {
            path,
            reason: RecordFault::BadId
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use tempfile::TempDir;

    use super::*;

    fn world() -> (TempDir, PathBuf, PathBuf) {
        let dir = assert_ok!(TempDir::new());
        let base = assert_ok!(fs::canonicalize(dir.path()));
        let src = base.join("src");
        assert_ok!(fs::create_dir(&src));
        assert_ok!(fs::set_permissions(&src, fs::Permissions::from_mode(0o700)));
        let dst = base.join("dst");
        (dir, src, dst)
    }

    fn put(path: &Path, text: &str) {
        if let Some(parent) = path.parent() {
            assert_ok!(fs::create_dir_all(parent));
        }
        assert_ok!(fs::write(path, text));
        assert_ok!(fs::set_permissions(path, fs::Permissions::from_mode(0o600)));
    }

    fn plan(rewrite: Option<&Path>) -> CopyPlan<'_> {
        CopyPlan {
            limits: CacheLimits::default(),
            rewrite_from: rewrite,
        }
    }

    fn reason(error: &CacheError) -> Rejection {
        assert!(
            matches!(error, CacheError::InvalidEntry { .. }),
            "not a rejection: {error}"
        );
        match error {
            CacheError::InvalidEntry { reason, .. } => *reason,
            _ => Rejection::BadName,
        }
    }

    #[test]
    fn test_copy_tree_makes_independent_files_a_write_does_not_reach_the_source() {
        let (_d, src, dst) = world();
        put(&src.join("a/f"), "original");
        let stats = assert_ok!(copy_tree(&src, &dst, plan(None)));
        assert_eq!(stats.bytes, 8);
        assert_eq!(stats.cloned + stats.copied, 1);
        assert_ne!(
            assert_ok!(fs::metadata(src.join("a/f"))).ino(),
            assert_ok!(fs::metadata(dst.join("a/f"))).ino()
        );
        assert_ok!(fs::write(dst.join("a/f"), "poisoned"));
        assert_eq!(assert_ok!(fs::read_to_string(src.join("a/f"))), "original");
    }

    #[test]
    fn test_copy_tree_breaks_an_internal_hard_link_into_two_inodes() {
        let (_d, src, dst) = world();
        put(&src.join("x"), "same");
        assert_ok!(fs::hard_link(src.join("x"), src.join("y")));
        assert_ok!(copy_tree(&src, &dst, plan(None)));
        let (x, y) = (
            assert_ok!(fs::metadata(dst.join("x"))),
            assert_ok!(fs::metadata(dst.join("y"))),
        );
        assert_ne!(x.ino(), y.ino());
        assert_eq!((x.nlink(), y.nlink()), (1, 1));
    }

    #[test]
    fn test_copy_tree_refuses_a_hard_link_that_an_outside_name_shares() {
        let (d, src, dst) = world();
        put(&src.join("x"), "shared");
        assert_ok!(fs::hard_link(src.join("x"), d.path().join("outside")));
        assert_eq!(
            reason(&assert_err!(copy_tree(&src, &dst, plan(None)))),
            Rejection::ForeignHardLink
        );
    }

    #[test]
    fn test_copy_tree_rewrites_an_absolute_self_link_to_a_relative_one_inside_the_copy() {
        let (_d, src, dst) = world();
        put(&src.join("real/f"), "x");
        assert_ok!(fs::create_dir_all(src.join("links")));
        assert_ok!(symlink(src.join("real"), src.join("links/to_real")));
        assert_ok!(copy_tree(&src, &dst, plan(Some(&src))));
        let target = assert_ok!(fs::read_link(dst.join("links/to_real")));
        assert!(target.is_relative(), "{}", target.display());
        assert_eq!(
            assert_ok!(fs::read_to_string(dst.join("links/to_real/f"))),
            "x"
        );
        assert!(
            assert_ok!(fs::canonicalize(dst.join("links/to_real")))
                .starts_with(assert_ok!(fs::canonicalize(&dst)))
        );
    }

    #[test]
    fn test_copy_tree_refuses_an_absolute_link_when_no_rewrite_root_is_given_and_one_that_leaves_it()
     {
        let (d, src, dst) = world();
        put(&src.join("f"), "x");
        assert_ok!(symlink(d.path().join("elsewhere"), src.join("abs")));
        assert_eq!(
            reason(&assert_err!(copy_tree(&src, &dst, plan(None)))),
            Rejection::EscapingLink
        );
        let dst2 = d.path().join("dst2");
        assert_eq!(
            reason(&assert_err!(copy_tree(&src, &dst2, plan(Some(&src))))),
            Rejection::EscapingLink
        );
    }

    #[test]
    fn test_copy_tree_refuses_dangling_escaping_relative_and_cyclic_links() {
        for (name, target, expect) in [
            ("dangling", "nowhere", Rejection::DanglingLink),
            ("escape", "../outside", Rejection::EscapingLink),
            ("loop", "loop", Rejection::LinkCycle),
        ] {
            let (d, src, dst) = world();
            put(&d.path().join("outside"), "x");
            assert_ok!(symlink(target, src.join(name)));
            assert_eq!(
                reason(&assert_err!(copy_tree(&src, &dst, plan(None)))),
                expect,
                "{name}"
            );
        }
    }

    #[test]
    fn test_copy_tree_refuses_unsafe_modes_and_special_files() {
        let (_d, src, dst) = world();
        put(&src.join("w"), "x");
        assert_ok!(fs::set_permissions(
            src.join("w"),
            fs::Permissions::from_mode(0o666)
        ));
        assert_eq!(
            reason(&assert_err!(copy_tree(&src, &dst, plan(None)))),
            Rejection::OpenPermissions
        );
        let (_d, src, dst) = world();
        put(&src.join("s"), "x");
        assert_ok!(fs::set_permissions(
            src.join("s"),
            fs::Permissions::from_mode(0o4700)
        ));
        assert_eq!(
            reason(&assert_err!(copy_tree(&src, &dst, plan(None)))),
            Rejection::SpecialMode
        );
        let (_d, src, dst) = world();
        let sock = assert_ok!(std::os::unix::net::UnixListener::bind(src.join("sock")));
        assert_eq!(
            reason(&assert_err!(copy_tree(&src, &dst, plan(None)))),
            Rejection::SpecialFile
        );
        drop(sock);
    }

    #[test]
    fn test_copy_tree_bounds_bytes_entries_and_depth_at_the_exact_edge() {
        let (_d, src, dst) = world();
        put(&src.join("a/b/f"), "12345");
        let edge = |bytes, entries, depth| CopyPlan {
            limits: CacheLimits {
                max_bytes: bytes,
                max_entries: entries,
                max_depth: depth,
                ..CacheLimits::default()
            },
            rewrite_from: None,
        };
        assert_ok!(copy_tree(&src, &dst, edge(5, 3, 2)));
        for (i, (bytes, entries, depth, resource)) in [
            (4, 3, 2, Resource::Bytes),
            (5, 2, 2, Resource::Entries),
            (5, 3, 1, Resource::Depth),
        ]
        .into_iter()
        .enumerate()
        {
            let out = src
                .parent()
                .map(|p| p.join(format!("d{i}")))
                .unwrap_or_default();
            let got = assert_err!(copy_tree(&src, &out, edge(bytes, entries, depth)));
            assert!(
                matches!(got, CacheError::BudgetExceeded { resource: r, .. } if r == resource),
                "{got}"
            );
        }
    }

    #[test]
    fn test_copy_tree_refuses_to_write_into_an_existing_destination() {
        let (_d, src, dst) = world();
        put(&src.join("f"), "x");
        assert_ok!(fs::create_dir(&dst));
        assert!(matches!(
            assert_err!(copy_tree(&src, &dst, plan(None))),
            CacheError::Copy { .. }
        ));
    }

    #[test]
    fn test_relative_between_walks_up_then_down() {
        assert_eq!(
            relative_between(Path::new("/r/a/b"), Path::new("/r/c/d")),
            PathBuf::from("../../c/d")
        );
        assert_eq!(
            relative_between(Path::new("/r"), Path::new("/r/x/y")),
            PathBuf::from("x/y")
        );
    }

    fn session() -> (TempDir, PathBuf, PathBuf) {
        let (d, src, _) = world();
        let sess = d.path().join("sess");
        assert_ok!(fs::create_dir(&sess));
        let sess = assert_ok!(fs::canonicalize(sess));
        (d, src, sess)
    }

    #[test]
    fn test_materialize_gives_a_private_copy_and_leaves_no_partial_directory() {
        let (_d, gen_dir, sess) = session();
        put(&gen_dir.join("uv/f"), "trusted");
        let cache = assert_ok!(materialize(
            &gen_dir,
            &sess,
            CacheLimits {
                min_free_bytes: 0,
                ..CacheLimits::default()
            }
        ));
        assert_eq!(cache.root(), sess.join("cache"));
        assert!(!sess.join("cache.partial").exists());
        assert_ok!(fs::write(cache.root().join("uv/f"), "poisoned"));
        assert_eq!(
            assert_ok!(fs::read_to_string(gen_dir.join("uv/f"))),
            "trusted"
        );
    }

    #[test]
    fn test_two_materialized_copies_do_not_share_writes() {
        let (_d, gen_dir, sess) = session();
        put(&gen_dir.join("f"), "base");
        let limits = CacheLimits {
            min_free_bytes: 0,
            ..CacheLimits::default()
        };
        let a = assert_ok!(materialize(&gen_dir, &sess, limits));
        let sess_b = sess.parent().map(|p| p.join("sess_b")).unwrap_or_default();
        assert_ok!(fs::create_dir(&sess_b));
        let b = assert_ok!(materialize(&gen_dir, &sess_b, limits));
        assert_ok!(fs::write(a.root().join("f"), "a-only"));
        assert_eq!(assert_ok!(fs::read_to_string(b.root().join("f"))), "base");
    }

    #[test]
    fn test_materialize_over_budget_fails_before_copying_and_cleans_up() {
        let (_d, gen_dir, sess) = session();
        put(&gen_dir.join("f"), "123456");
        let limits = CacheLimits {
            max_bytes: 5,
            min_free_bytes: 0,
            ..CacheLimits::default()
        };
        assert!(matches!(
            assert_err!(materialize(&gen_dir, &sess, limits)),
            CacheError::BudgetExceeded { .. }
        ));
        assert!(!sess.join("cache").exists() && !sess.join("cache.partial").exists());
    }

    #[test]
    fn test_materialize_with_too_little_free_space_names_the_floor_and_copies_nothing() {
        let (_d, gen_dir, sess) = session();
        put(&gen_dir.join("f"), "x");
        let limits = CacheLimits {
            min_free_bytes: u64::MAX / 2,
            ..CacheLimits::default()
        };
        assert!(matches!(
            assert_err!(materialize(&gen_dir, &sess, limits)),
            CacheError::NoSpace { .. }
        ));
        assert!(!sess.join("cache.partial").exists());
    }

    #[test]
    fn test_materialize_removes_a_partial_copy_when_an_entry_is_refused_midway() {
        let (_d, gen_dir, sess) = session();
        put(&gen_dir.join("a"), "fine");
        assert_ok!(symlink("/etc/passwd", gen_dir.join("z-escape")));
        let limits = CacheLimits {
            min_free_bytes: 0,
            ..CacheLimits::default()
        };
        assert!(matches!(
            assert_err!(materialize(&gen_dir, &sess, limits)),
            CacheError::InvalidEntry { .. }
        ));
        assert!(!sess.join("cache").exists() && !sess.join("cache.partial").exists());
    }

    #[test]
    fn test_remove_tree_deletes_an_unreadable_directory_and_does_not_follow_a_link() {
        let (d, _src, sess) = session();
        let outside = d.path().join("keep");
        put(&outside.join("f"), "keep");
        let tree = sess.join("t");
        put(&tree.join("locked/f"), "x");
        assert_ok!(symlink(&outside, tree.join("link")));
        assert_ok!(fs::set_permissions(
            tree.join("locked"),
            fs::Permissions::from_mode(0o000)
        ));
        assert_ok!(remove_tree(&tree));
        assert!(!tree.exists());
        assert_eq!(assert_ok!(fs::read_to_string(outside.join("f"))), "keep");
        assert_ok!(remove_tree(&tree));
    }

    // ---- store: select ----

    fn inputs() -> ExpectedInputs {
        ExpectedInputs {
            project_key: "pk".into(),
            tool_digest: "t1".into(),
            servers: BTreeMap::from([
                ("time".into(), "d1".into()),
                ("ripgrep".into(), "d2".into()),
            ]),
            platform: "macos-aarch64".into(),
        }
    }

    /// Writes a generation `id` and a current record for it, by hand, as `publish` will.
    fn publish_by_hand(store_root: &Path, id: &str, inputs: &ExpectedInputs) {
        let dir = store_root.join("generations").join(id);
        put(&dir.join("data/uv/f"), "x");
        let manifest = CacheManifest {
            format: MANIFEST_FORMAT,
            id: id.into(),
            inputs: inputs.clone(),
            logical_bytes: 1,
            entries: 3,
            created_at: 0,
            hb_version: "t".into(),
        };
        let bytes = assert_ok!(serde_json::to_vec(&manifest));
        assert_ok!(fs::write(dir.join("manifest.json"), &bytes));
        let record = CurrentRecord {
            format: MANIFEST_FORMAT,
            id: id.into(),
            manifest_sha256: Digest::of(&bytes).to_string(),
        };
        let cur = store_root
            .join("projects")
            .join(&inputs.project_key)
            .join("current");
        put(&cur, &assert_ok!(serde_json::to_string(&record)));
    }

    fn store() -> (TempDir, PathBuf, CacheStore) {
        let dir = assert_ok!(TempDir::new());
        let root = assert_ok!(fs::canonicalize(dir.path()));
        let store = CacheStore::new(root.clone());
        (dir, root, store)
    }

    #[test]
    fn test_select_finds_the_generation_the_current_record_names() {
        let (_d, root, store) = store();
        publish_by_hand(&root, "g1", &inputs());
        let found = assert_ok!(store.select(&inputs()));
        assert_eq!(found.id, "g1");
        assert_eq!(found.root, root.join("generations/g1/data"));
    }

    #[test]
    fn test_select_with_nothing_published_says_missing_and_with_only_the_old_cache_says_legacy_and_keeps_it()
     {
        let (_d, root, store) = store();
        assert!(matches!(
            assert_err!(store.select(&inputs())),
            CacheError::MissingGeneration
        ));
        put(&root.join("uv/old"), "legacy bytes");
        assert!(matches!(
            assert_err!(store.select(&inputs())),
            CacheError::LegacyCache { .. }
        ));
        assert_eq!(
            assert_ok!(fs::read_to_string(root.join("uv/old"))),
            "legacy bytes"
        );
    }

    #[test]
    fn test_select_names_each_input_that_changed() {
        let (_d, root, store) = store();
        publish_by_hand(&root, "g1", &inputs());
        for (what, edit) in [
            (
                Mismatch::Tool,
                (|i: &mut ExpectedInputs| i.tool_digest = "x".into()) as fn(&mut ExpectedInputs),
            ),
            (Mismatch::Server, |i| {
                i.servers.insert("time".into(), "changed-args".into());
            }),
            (Mismatch::Server, |i| {
                i.servers.insert("never-warmed".into(), "d9".into());
            }),
            (Mismatch::Platform, |i| i.platform = "linux-x86_64".into()),
        ] {
            let mut changed = inputs();
            edit(&mut changed);
            let got = assert_err!(store.select(&changed));
            assert!(
                matches!(&got, CacheError::StaleManifest { what: w, .. } if *w == what),
                "{got}"
            );
        }
    }

    #[test]
    fn test_a_generation_with_extra_servers_serves_a_run_that_needs_fewer() {
        let (_d, root, store) = store();
        publish_by_hand(&root, "g1", &inputs());
        let mut fewer = inputs();
        fewer.servers.remove("ripgrep");
        assert_ok!(store.select(&fewer));
    }

    #[test]
    fn test_select_refuses_a_tampered_manifest_a_bad_id_and_an_oversized_record() {
        let (_d, root, store) = store();
        publish_by_hand(&root, "g1", &inputs());
        let manifest = root.join("generations/g1/manifest.json");
        let good = assert_ok!(fs::read(&manifest));
        assert_ok!(fs::write(&manifest, [good.clone(), b" ".to_vec()].concat()));
        let got = assert_err!(store.select(&inputs()));
        assert!(
            matches!(
                got,
                CacheError::BadRecord {
                    reason: RecordFault::HashMismatch,
                    ..
                }
            ),
            "{got}"
        );
        assert_ok!(fs::write(&manifest, &good));
        let current = root.join("projects/pk/current");
        put(
            &current,
            r#"{"format":1,"id":"../escape","manifest_sha256":"00"}"#,
        );
        let got = assert_err!(store.select(&inputs()));
        assert!(
            matches!(
                got,
                CacheError::BadRecord {
                    reason: RecordFault::BadId,
                    ..
                }
            ),
            "{got}"
        );
        put(
            &current,
            &"x".repeat(usize::try_from(MAX_RECORD_BYTES).unwrap_or(0) + 1),
        );
        let got = assert_err!(store.select(&inputs()));
        assert!(
            matches!(
                got,
                CacheError::BadRecord {
                    reason: RecordFault::TooLarge,
                    ..
                }
            ),
            "{got}"
        );
    }

    #[test]
    fn test_select_does_not_follow_a_symlinked_current_record() {
        let (d, root, store) = store();
        publish_by_hand(&root, "g1", &inputs());
        let real = root.join("projects/pk/current");
        let elsewhere = d.path().join("elsewhere");
        assert_ok!(fs::rename(&real, &elsewhere));
        assert_ok!(symlink(&elsewhere, &real));
        assert_err!(store.select(&inputs()));
    }

    // ---- store: seal and publish ----

    /// A directory standing in for the per-user temporary directory, removed when the process ends.
    fn temp_parent() -> PathBuf {
        let dir = assert_ok!(TempDir::new());
        let path = assert_ok!(fs::canonicalize(dir.path()));
        std::mem::forget(dir);
        path
    }

    fn loose() -> CacheLimits {
        CacheLimits {
            min_free_bytes: 0,
            ..CacheLimits::default()
        }
    }

    fn workspace(store: &CacheStore, files: &[(&str, &str)]) -> PathBuf {
        let ws = assert_ok!(store.begin_build(&temp_parent()));
        for (name, text) in files {
            put(&ws.join(name), text);
        }
        ws
    }

    #[test]
    fn test_seal_and_publish_makes_a_selectable_generation_that_is_a_separate_copy() {
        let (_d, _root, store) = store();
        let ws = workspace(&store, &[("uv/f", "built")]);
        let made = assert_ok!(store.seal_and_publish(&ws, &inputs(), None, loose()));
        let found = assert_ok!(store.select(&inputs()));
        assert_eq!(found, made);
        assert_eq!(
            assert_ok!(fs::read_to_string(found.root.join("uv/f"))),
            "built"
        );
        // A warm process that still has the workspace open cannot reach the published bytes.
        assert_ok!(fs::write(ws.join("uv/f"), "late write"));
        assert_eq!(
            assert_ok!(fs::read_to_string(found.root.join("uv/f"))),
            "built"
        );
        assert_eq!(found.manifest.logical_bytes, 5);
    }

    #[test]
    fn test_a_failed_seal_leaves_the_previous_generation_current_and_no_staging_behind() {
        let (_d, root, store) = store();
        let first = workspace(&store, &[("f", "one")]);
        let old = assert_ok!(store.seal_and_publish(&first, &inputs(), None, loose()));
        let bad = workspace(&store, &[("f", "two")]);
        assert_ok!(symlink("/etc/passwd", bad.join("escape")));
        assert!(matches!(
            assert_err!(store.seal_and_publish(&bad, &inputs(), None, loose())),
            CacheError::InvalidEntry { .. }
        ));
        assert_eq!(assert_ok!(store.select(&inputs())), old);
        assert_eq!(assert_ok!(fs::read_dir(root.join("staging"))).count(), 0);
        assert_eq!(
            assert_ok!(fs::read_dir(root.join("generations"))).count(),
            1
        );
    }

    #[test]
    fn test_a_second_publish_replaces_current_and_keeps_the_first_generation_on_disk() {
        let (_d, root, store) = store();
        let a = workspace(&store, &[("f", "one")]);
        let first = assert_ok!(store.seal_and_publish(&a, &inputs(), None, loose()));
        let b = workspace(&store, &[("f", "two")]);
        let second = assert_ok!(store.seal_and_publish(&b, &inputs(), None, loose()));
        assert_ne!(first.id, second.id);
        assert_eq!(assert_ok!(store.select(&inputs())).id, second.id);
        assert_eq!(assert_ok!(fs::read_to_string(first.root.join("f"))), "one");
        assert_eq!(
            assert_ok!(fs::read_dir(root.join("generations"))).count(),
            2
        );
    }

    #[test]
    fn test_an_unpublished_build_or_stray_generation_is_never_selected() {
        let (_d, root, store) = store();
        let _ws = workspace(&store, &[("f", "x")]);
        assert!(matches!(
            assert_err!(store.select(&inputs())),
            CacheError::MissingGeneration
        ));
        put(&root.join("generations/orphan/data/f"), "x");
        assert!(matches!(
            assert_err!(store.select(&inputs())),
            CacheError::MissingGeneration
        ));
    }

    #[test]
    fn test_published_trees_have_one_inode_per_file_and_private_modes() {
        let (_d, _root, store) = store();
        let ws = workspace(&store, &[("a", "same")]);
        assert_ok!(fs::hard_link(ws.join("a"), ws.join("b")));
        let made = assert_ok!(store.seal_and_publish(&ws, &inputs(), None, loose()));
        let (a, b) = (
            assert_ok!(fs::metadata(made.root.join("a"))),
            assert_ok!(fs::metadata(made.root.join("b"))),
        );
        assert_ne!(a.ino(), b.ino());
        assert_eq!(a.mode() & 0o777, 0o600);
        assert_eq!(assert_ok!(fs::metadata(&made.root)).mode() & 0o777, 0o700);
    }

    #[test]
    fn test_a_second_warm_for_the_same_project_is_busy_until_the_first_drops_and_other_projects_are_free()
     {
        let (_d, _root, store) = store();
        let first = assert_ok!(store.lock_warm("pk"));
        assert!(matches!(
            assert_err!(store.lock_warm("pk")),
            CacheError::WarmBusy
        ));
        assert_ok!(store.lock_warm("other"));
        drop(first);
        assert_ok!(store.lock_warm("pk"));
    }

    // ---- expected inputs ----

    fn tools_in(dir: &Path, name: &str, body: &str) -> ToolLookup {
        put(&dir.join(name), body);
        ToolLookup {
            found: vec![crate::system::FoundTool {
                name: assert_ok!(crate::policy::ToolName::parse(name)),
                dir: assert_ok!(CanonicalPath::from_canonical(dir)),
            }],
            missing: Vec::new(),
        }
    }

    fn server(name: &str, args: &[&str]) -> Server {
        Server {
            name: name.into(),
            command: "uvx".into(),
            args: args.iter().map(|a| (*a).to_owned()).collect(),
            allowlist: Vec::new(),
        }
    }

    #[test]
    fn test_expected_inputs_change_with_a_tool_a_server_argument_and_the_project_but_not_with_time()
    {
        let (d, root, _store) = store();
        let bin = d.path().join("bin");
        let proj = assert_ok!(CanonicalPath::from_canonical(&root));
        let tools = tools_in(
            &assert_ok!(fs::canonicalize({
                assert_ok!(fs::create_dir_all(&bin));
                &bin
            })),
            "uvx",
            "v1",
        );
        let a = assert_ok!(expected_inputs_for(
            &proj,
            &[server("time", &["x"])],
            &tools
        ));
        let again = assert_ok!(expected_inputs_for(
            &proj,
            &[server("time", &["x"])],
            &tools
        ));
        assert_eq!(a, again);
        let other_args = assert_ok!(expected_inputs_for(
            &proj,
            &[server("time", &["y"])],
            &tools
        ));
        assert_ne!(a.servers, other_args.servers);
        assert_eq!(a.tool_digest, other_args.tool_digest);
        let replaced = tools_in(
            &assert_ok!(fs::canonicalize(&bin)),
            "uvx",
            "a longer replacement",
        );
        let c = assert_ok!(expected_inputs_for(
            &proj,
            &[server("time", &["x"])],
            &replaced
        ));
        assert_ne!(a.tool_digest, c.tool_digest);
        let elsewhere = assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
            &bin
        ))));
        let moved = assert_ok!(expected_inputs_for(
            &elsewhere,
            &[server("time", &["x"])],
            &tools
        ));
        assert_ne!(a.project_key, moved.project_key);
    }

    #[test]
    fn test_seed_python_copies_the_newest_interpreter_into_the_workspace_and_none_is_fine() {
        let (d, root, store) = store();
        let uv_python = d.path().join("uvpy");
        assert_eq!(assert_ok!(seed_python(&uv_python, &root, loose())), None);
        put(&uv_python.join("cpython-3.11.1-x/bin/python3.11"), "old");
        put(&uv_python.join("cpython-3.12.9-x/bin/python3.12"), "new");
        let ws = assert_ok!(store.begin_build(&temp_parent()));
        let seeded = assert_some!(assert_ok!(seed_python(&uv_python, &ws, loose())));
        assert_eq!(seeded, ws.join("python/cpython-3.12.9-x"));
        assert_eq!(
            assert_ok!(fs::read_to_string(seeded.join("bin/python3.12"))),
            "new"
        );
        assert_ok!(fs::write(seeded.join("bin/python3.12"), "tampered"));
        assert_eq!(
            assert_ok!(fs::read_to_string(
                uv_python.join("cpython-3.12.9-x/bin/python3.12")
            )),
            "new"
        );
    }

    #[test]
    fn test_seed_python_refuses_an_interpreter_whose_link_leaves_its_tree() {
        let (d, _root, store) = store();
        let uv_python = d.path().join("uvpy");
        put(&uv_python.join("cpython-3.12.9-x/bin/real"), "x");
        assert_ok!(symlink(
            "/usr/bin/python3",
            uv_python.join("cpython-3.12.9-x/bin/python")
        ));
        let ws = assert_ok!(store.begin_build(&temp_parent()));
        let got = assert_err!(seed_python(&uv_python, &ws, loose()));
        assert!(
            matches!(
                got,
                CacheError::InvalidEntry {
                    reason: Rejection::EscapingLink,
                    ..
                }
            ),
            "{got}"
        );
    }
}
