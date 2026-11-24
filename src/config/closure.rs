// ABOUTME: Loads the closure of config files (base, project, and everything they extend) with every safety check.
// ABOUTME: Returns each file's exact bytes and location, in a deterministic order, for merging and for M4's approval hash.
//! The config closure.
//!
//! Starting from the user's base file and the project file, follows every `extends` entry
//! depth-first, reading each file exactly once. Dependencies come before the files that extend
//! them (post-order), the base chain comes before the project chain, so the project is last and
//! highest precedence. The order, and therefore every error list built from it, is
//! deterministic.
//!
//! Each file is, in this order: read through a role-derived symlink policy, checked to still be
//! the file the path names, identified by device and inode (so a hard link, a symlinked
//! directory or a case variant is the same file, and a cycle through an alias is still a cycle),
//! checked for owner and world-writability, classified by physical location, probed for
//! user-only sections, and only then resolved. A hostile file is therefore refused before any
//! of its paths are touched.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use nix::unistd::getuid;
use snafu::Snafu;

use super::builtin::{BuiltinPresets, EmbeddedPresets};
use super::discover::{Discovery, Subject, Untrusted, untrusted};
use super::extends::{Containing, Extends, ExtendsError, Node};
use super::location::{FileLocation, classify};
use super::merge::{MergeErrors, Policy, merge};
use super::raw::user_only_sections;
use super::resolve::{Diagnostics, ResolveContext, ResolveErrors, ResolvedConfig, resolve_file};
use super::text::{ConfigText, ConfigTextError, FileRole};
use crate::origin::{FileId, KeyPath, Layer, Origin, Source};
use crate::policy::{CanonicalPath, HomeDir, PresetName};
use crate::sys::path_preview;
use crate::system::{
    FloorDiagnostic, FloorEnvironment, FloorError, FloorInputs, UserConfigDir, UserConfigError,
    build_floor,
};
use crate::text::Escaped;

/// Most files a closure may hold, base and project included.
///
/// A realistic closure is 6 to 8 files. Each file costs filesystem work to resolve before the
/// user has approved anything, so the cap bounds that work for a hostile in-project file set.
pub const MAX_CLOSURE_FILES: usize = 16;
/// Most files that may be in progress at once: how deep `extends` may nest.
pub const MAX_EXTENDS_DEPTH: usize = 8;
/// Most `extends` entries one file may list.
pub const MAX_EXTENDS_PER_FILE: usize = 32;

/// What `load_closure` needs to know about the world.
pub struct LoadRequest<'a> {
    home: &'a HomeDir,
    project: &'a Discovery,
    user_config: &'a UserConfigDir,
    floor_env: &'a FloorEnvironment,
    builtins: &'a dyn BuiltinPresets,
    pub(crate) uid: u32,
}

impl<'a> LoadRequest<'a> {
    /// A request for `project`, with the presets compiled into this build of `hb`.
    ///
    /// `floor_env` is required, so a caller cannot forget to say what `PATH` and `hb` are.
    #[must_use]
    pub fn new(
        home: &'a HomeDir,
        project: &'a Discovery,
        user_config: &'a UserConfigDir,
        floor_env: &'a FloorEnvironment,
    ) -> Self {
        static EMBEDDED: EmbeddedPresets = EmbeddedPresets;
        Self {
            home,
            project,
            user_config,
            floor_env,
            builtins: &EMBEDDED,
            uid: getuid().as_raw(),
        }
    }

    /// Use `builtins` instead of the presets compiled into `hb`.
    #[must_use]
    pub fn with_builtins(mut self, builtins: &'a dyn BuiltinPresets) -> Self {
        self.builtins = builtins;
        self
    }

    /// Trust files owned by `uid` instead of the running user. For tests.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn trusting_uid(mut self, uid: u32) -> Self {
        self.uid = uid;
        self
    }
}

/// Why the config closure could not be loaded.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum LoadError {
    /// The user's base config does not exist.
    #[snafu(display(
        "your base config {} does not exist; run `hb init` to create one (it may be empty)",
        path_preview(path)
    ))]
    BaseMissing {
        /// Where the base config is expected.
        path: PathBuf,
    },

    /// The user's config directory could not be resolved.
    #[snafu(display("your config directory could not be resolved"))]
    UserConfig {
        /// The underlying error.
        source: UserConfigError,
    },

    /// A config file could not be read.
    #[snafu(display(
        "could not load config file {} (reached via {})",
        path_preview(path),
        Escaped(via)
    ))]
    Read {
        /// The file, as referenced.
        path: PathBuf,
        /// How it was reached, from the root.
        via: String,
        /// The underlying error.
        #[snafu(source(from(ConfigTextError, Box::new)))]
        source: Box<ConfigTextError>,
    },

    /// An `extends` entry could not be turned into something to load.
    #[snafu(display(
        "`extends` entry `{}` in {} could not be resolved",
        Escaped(entry),
        path_preview(path)
    ))]
    Extends {
        /// The file that contains the entry.
        path: PathBuf,
        /// The entry as written.
        entry: String,
        /// The underlying error.
        #[snafu(source(from(ExtendsError, Box::new)))]
        source: Box<ExtendsError>,
    },

    /// A file has invalid entries.
    #[snafu(display("{} has invalid entries", path_preview(path)))]
    Resolve {
        /// The file.
        path: PathBuf,
        /// The underlying errors.
        #[snafu(source(from(ResolveErrors, Box::new)))]
        source: Box<ResolveErrors>,
    },

    /// A file that is not the user's own defines a section only the user may define.
    #[snafu(display(
        "`{section}` is only allowed in your own files (~/.config/hamster-ball) and built-in \
         presets, but {} ({location}) defines it; reached via {}. Move it to your base config or a \
         preset in ~/.config/hamster-ball/presets.",
        path_preview(path),
        Escaped(via)
    ))]
    UserOnlySection {
        /// The file that defines the section.
        path: PathBuf,
        /// The section: `hooks`, `guard.exceptions`, `system.launchctl = true` or `net.internal_hosts`.
        section: &'static str,
        /// Where the file is.
        location: FileLocation,
        /// How the file was reached.
        via: String,
    },

    /// A file extends something that is already being loaded.
    #[snafu(display("`extends` forms a cycle: {}", Escaped(&chain.join(" -> "))))]
    ExtendsCycle {
        /// The files in the cycle, first to last, ending where it began.
        chain: Vec<String>,
    },

    /// `extends` nests deeper than the limit.
    #[snafu(display(
        "`extends` nests deeper than {MAX_EXTENDS_DEPTH} files: {}",
        Escaped(via)
    ))]
    TooDeep {
        /// How the file that went too deep was reached.
        via: String,
    },

    /// The closure has more files than the limit.
    #[snafu(display("the config closure has more than {MAX_CLOSURE_FILES} files"))]
    TooManyFiles,

    /// One file lists more `extends` entries than the limit.
    #[snafu(display(
        "{} lists {count} `extends` entries; the limit is {max}",
        path_preview(path)
    ))]
    TooManyExtends {
        /// The file.
        path: PathBuf,
        /// How many entries it lists.
        count: usize,
        /// The limit.
        max: usize,
    },

    /// The floor could not be built for this project.
    #[snafu(display("the floor could not be built"))]
    Floor {
        /// The underlying error.
        #[snafu(source(from(FloorError, Box::new)))]
        source: Box<FloorError>,
    },

    /// The files load but do not merge: a keyed value or scalar conflicts, or a user-only
    /// section is in the wrong file.
    #[snafu(display("the config files do not merge"))]
    Merge {
        /// The underlying errors.
        #[snafu(source(from(MergeErrors, Box::new)))]
        source: Box<MergeErrors>,
    },

    /// A config file belongs to someone else, or anyone can write it.
    #[snafu(display(
        "the {subject} {} is {problem}; hb only reads config that belongs to you and that other \
         users cannot write. Fix it with `chown` or `chmod o-w`.",
        path_preview(path)
    ))]
    Untrusted {
        /// The file.
        path: PathBuf,
        /// What kind of thing it is.
        subject: Subject,
        /// What is wrong with it.
        problem: Untrusted,
    },
}

/// Where a closure file's text came from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileSource {
    /// A preset compiled into `hb`.
    Builtin {
        /// Its name.
        name: PresetName,
    },
    /// A file on disk.
    Disk {
        /// The path it was reached by.
        path: PathBuf,
        /// Where it really is.
        canonical: CanonicalPath,
        /// The preset name it was reached by, for a user preset named in `extends`.
        preset: Option<PresetName>,
    },
}

/// One file of the closure, with everything later stages need.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ClosureFile {
    /// Its position in [`Closure::files`].
    pub id: FileId,
    /// Where it came from.
    pub source: FileSource,
    /// Its layer.
    pub layer: Layer,
    /// Where it physically is.
    pub location: FileLocation,
    /// Whether the user's base file (directly or through its `extends`) provides it.
    pub from_base: bool,
    /// The exact bytes that were parsed, and that approval hashes.
    pub text: ConfigText,
    /// The validated config.
    pub resolved: ResolvedConfig,
    /// Allow rules that were skipped.
    pub diagnostics: Diagnostics,
}

/// Every config file that applies, in deterministic order.
#[derive(Debug, Clone)]
pub struct Closure {
    files: Vec<ClosureFile>,
}

impl Closure {
    /// The files, dependencies before dependents, base chain before project chain.
    #[must_use]
    pub fn files(&self) -> &[ClosureFile] {
        &self.files
    }

    /// The files the hamster ball could write, which need approval and a hash.
    pub fn approval_files(&self) -> impl Iterator<Item = &ClosureFile> {
        self.files
            .iter()
            .filter(|file| file.location.needs_approval())
    }

    /// Rebuilds a full [`Origin`] from a compact [`Source`].
    ///
    /// The file in the origin is the canonical path, not the spelling it was reached by.
    ///
    /// # Panics
    /// Never for a `Source` produced from this closure; an id from another closure may index
    /// out of range.
    #[must_use]
    pub fn origin(&self, source: Source, key: KeyPath) -> Origin {
        self.files[source.file().index()].origin(key)
    }
}

impl ClosureFile {
    /// An [`Origin`] for `key` in this file: the canonical path, not the spelling it was reached by.
    #[must_use]
    pub fn origin(&self, key: KeyPath) -> Origin {
        let path = match &self.source {
            FileSource::Disk { canonical, .. } => canonical.as_path().to_path_buf(),
            FileSource::Builtin { .. } => self.text.path().to_path_buf(),
        };
        Origin::new(self.layer, path, key)
    }
}

/// The closure and the policy merged from it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Loaded {
    /// Every config file that applies, with its exact bytes.
    pub closure: Closure,
    /// The merged policy, including the floor.
    pub policy: Policy,
    /// Things the floor builder noticed that are not errors.
    pub floor_diagnostics: Vec<FloorDiagnostic>,
}

/// Loads the config closure for `request`, builds the floor, and merges them into one policy.
///
/// # Errors
/// See [`LoadError`].
pub fn load(request: &LoadRequest<'_>) -> Result<Loaded, LoadError> {
    let closure = load_closure(request)?;
    let approval_files: Vec<CanonicalPath> = closure
        .approval_files()
        .filter_map(|file| match &file.source {
            FileSource::Disk { canonical, .. } => Some(canonical.clone()),
            FileSource::Builtin { .. } => None,
        })
        .collect();
    let write_grants: Vec<CanonicalPath> = closure
        .files()
        .iter()
        .flat_map(|file| {
            file.resolved
                .fs
                .write
                .iter()
                .map(|grant| grant.value.clone())
        })
        .collect();
    let built = build_floor(&FloorInputs::new(
        request.home,
        &request.project.root,
        request.floor_env,
        &approval_files,
        &write_grants,
    ))
    .map_err(|source| LoadError::Floor {
        source: Box::new(source),
    })?;
    let policy = merge(closure.files(), built.floor).map_err(|source| LoadError::Merge {
        source: Box::new(source),
    })?;
    Ok(Loaded {
        closure,
        policy,
        floor_diagnostics: built.diagnostics,
    })
}

/// Loads the config closure for `request`, without merging it.
///
/// # Errors
/// See [`LoadError`].
pub fn load_closure(request: &LoadRequest<'_>) -> Result<Closure, LoadError> {
    let base = request.user_config.base_file();
    if let Err(error) = fs::symlink_metadata(&base) {
        if error.kind() == io::ErrorKind::NotFound {
            return Err(LoadError::BaseMissing { path: base });
        }
    }
    let user_canonical = request
        .user_config
        .canonical()
        .map_err(|source| LoadError::UserConfig { source })?;
    let mut loader = Loader::new(request, user_canonical);
    loader.visit(
        Node::Disk {
            path: base,
            role: FileRole::UserBase,
        },
        true,
    )?;
    loader.visit(
        Node::Disk {
            path: request.project.config.clone(),
            role: FileRole::Project,
        },
        false,
    )?;
    Ok(Closure {
        files: loader.files,
    })
}

/// What identifies a file for deduplication and cycle detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Key {
    Disk { dev: u64, ino: u64 },
    Builtin(PresetName),
}

/// A file currently being loaded.
struct Frame {
    key: Key,
    label: String,
}

struct Loader<'a> {
    request: &'a LoadRequest<'a>,
    user_canonical: Option<CanonicalPath>,
    extends: Extends<'a>,
    context: ResolveContext<'a>,
    files: Vec<ClosureFile>,
    loaded: HashMap<Key, usize>,
    stack: Vec<Frame>,
    seen: usize,
}

impl<'a> Loader<'a> {
    fn new(request: &'a LoadRequest<'a>, user_canonical: Option<CanonicalPath>) -> Self {
        Self {
            request,
            user_canonical,
            extends: Extends::new(request.home, request.user_config, request.builtins),
            context: ResolveContext::new(request.home, &request.project.root),
            files: Vec::new(),
            loaded: HashMap::new(),
            stack: Vec::new(),
            seen: 0,
        }
    }

    /// How the file now being loaded was reached, for error messages.
    fn via(&self, last: &str) -> String {
        let mut labels: Vec<&str> = self
            .stack
            .iter()
            .map(|frame| frame.label.as_str())
            .collect();
        labels.push(last);
        labels.join(" -> ")
    }

    fn visit(&mut self, node: Node, from_base: bool) -> Result<usize, LoadError> {
        match node {
            Node::Builtin(name) => self.visit_builtin(name, from_base),
            Node::Disk { path, role } => self.visit_disk(path, role, from_base),
        }
    }

    fn visit_disk(
        &mut self,
        path: PathBuf,
        role: FileRole,
        from_base: bool,
    ) -> Result<usize, LoadError> {
        let label = path.to_string_lossy().into_owned();
        let read_error = |loader: &Self, source| LoadError::Read {
            path: path.clone(),
            via: loader.via(&label),
            source: Box::new(source),
        };
        let text = ConfigText::read(&path, role).map_err(|source| read_error(self, source))?;
        let canonical = text.verify().map_err(|source| read_error(self, source))?;
        let identity = text
            .identity()
            .ok_or_else(|| read_error(self, ConfigTextError::NotOnDisk { path: path.clone() }))?;
        let key = Key::Disk {
            dev: identity.dev,
            ino: identity.ino,
        };
        let label = canonical.as_path().to_string_lossy().into_owned();
        if let Some(existing) = self.revisit(&key, &label, text.layer(), from_base)? {
            return Ok(existing);
        }
        self.admit()?;

        if let Some(problem) = untrusted(identity.uid, identity.mode, self.request.uid) {
            return Err(LoadError::Untrusted {
                path: canonical.as_path().to_path_buf(),
                subject: Subject::ConfigFile,
                problem,
            });
        }
        let location = classify(
            &canonical,
            identity.nlink,
            &self.request.project.root,
            self.user_canonical.as_ref(),
        );
        self.check_user_only(&text, canonical.as_path(), location, &label)?;
        let preset = (role == FileRole::UserPresetByName)
            .then(|| self.request.user_config.preset_name_of(&path))
            .flatten();
        let source = FileSource::Disk {
            path: path.clone(),
            canonical: canonical.clone(),
            preset,
        };
        let dir = canonical.as_path().parent().map(Path::to_path_buf);
        let containing = dir.as_deref().map_or(Containing::Builtin, Containing::Disk);
        self.finish(Pending {
            key,
            label,
            source,
            location,
            from_base,
            text,
            file: canonical.as_path().to_path_buf(),
            containing,
        })
    }

    fn visit_builtin(&mut self, name: PresetName, from_base: bool) -> Result<usize, LoadError> {
        let label = format!("builtin:{name}");
        let key = Key::Builtin(name.clone());
        if let Some(existing) = self.revisit(&key, &label, Layer::Preset, from_base)? {
            return Ok(existing);
        }
        self.admit()?;
        // The extends resolver only returns a built-in node for a name the registry has.
        let body = self.request.builtins.get(&name).unwrap_or_default();
        let text = ConfigText::builtin(name.as_str(), body);
        let file = text.path().to_path_buf();
        self.finish(Pending {
            key,
            label,
            source: FileSource::Builtin { name },
            location: FileLocation::Builtin,
            from_base,
            text,
            file,
            containing: Containing::Builtin,
        })
    }

    /// If `key` is already loaded, merges the new reference into it; if it is being loaded,
    /// reports the cycle.
    fn revisit(
        &mut self,
        key: &Key,
        label: &str,
        layer: Layer,
        from_base: bool,
    ) -> Result<Option<usize>, LoadError> {
        if let Some(start) = self.stack.iter().position(|frame| &frame.key == key) {
            let mut chain: Vec<String> = self.stack[start..]
                .iter()
                .map(|frame| frame.label.clone())
                .collect();
            chain.push(label.to_owned());
            return Err(LoadError::ExtendsCycle { chain });
        }
        if let Some(&index) = self.loaded.get(key) {
            let file = &mut self.files[index];
            file.from_base |= from_base;
            file.layer = file.layer.max(layer);
            return Ok(Some(index));
        }
        Ok(None)
    }

    /// Counts a new file against the caps.
    fn admit(&mut self) -> Result<(), LoadError> {
        if self.stack.len() >= MAX_EXTENDS_DEPTH {
            let via = self.via("...");
            return Err(LoadError::TooDeep { via });
        }
        self.seen += 1;
        if self.seen > MAX_CLOSURE_FILES {
            return Err(LoadError::TooManyFiles);
        }
        Ok(())
    }

    /// Refuses a file that defines a user-only section without being allowed to.
    fn check_user_only(
        &self,
        text: &ConfigText,
        path: &Path,
        location: FileLocation,
        label: &str,
    ) -> Result<(), LoadError> {
        let found = user_only_sections(text.as_str());
        if !found.any()
            || (location.may_define_user_only_sections() && text.layer() != Layer::Project)
        {
            return Ok(());
        }
        let section = if found.hooks {
            "hooks"
        } else if found.guard_exceptions {
            "guard.exceptions"
        } else if found.launchctl_on {
            "system.launchctl = true"
        } else {
            "net.internal_hosts"
        };
        Err(LoadError::UserOnlySection {
            path: path.to_path_buf(),
            section,
            location,
            via: self.via(label),
        })
    }

    /// Resolves the file, loads what it extends, and records it.
    fn finish(&mut self, pending: Pending<'_>) -> Result<usize, LoadError> {
        let Pending {
            key,
            label,
            source,
            location,
            from_base,
            text,
            file,
            containing,
        } = pending;
        let resolved = resolve_file(&text, &self.context).map_err(|source| LoadError::Resolve {
            path: file.clone(),
            source: Box::new(source),
        })?;
        let entries = &resolved.config.extends;
        if entries.len() > MAX_EXTENDS_PER_FILE {
            return Err(LoadError::TooManyExtends {
                path: file,
                count: entries.len(),
                max: MAX_EXTENDS_PER_FILE,
            });
        }
        self.stack.push(Frame {
            key: key.clone(),
            label,
        });
        let children = self.load_children(&resolved.config.extends, containing, &file, from_base);
        self.stack.pop();
        children?;

        let index = self.files.len();
        self.files.push(ClosureFile {
            id: FileId::new(u16::try_from(index).unwrap_or(u16::MAX)),
            source,
            layer: text.layer(),
            location,
            from_base,
            text,
            resolved: resolved.config,
            diagnostics: resolved.diagnostics,
        });
        self.loaded.insert(key, index);
        Ok(index)
    }

    fn load_children(
        &mut self,
        entries: &[crate::policy::ExtendRef],
        containing: Containing<'_>,
        file: &Path,
        from_base: bool,
    ) -> Result<(), LoadError> {
        for entry in entries {
            let node =
                self.extends
                    .node(entry, containing)
                    .map_err(|source| LoadError::Extends {
                        path: file.to_path_buf(),
                        entry: entry.to_string(),
                        source: Box::new(source),
                    })?;
            self.visit(node, from_base)?;
        }
        Ok(())
    }
}

/// A file that has been read and admitted, before it is resolved.
struct Pending<'a> {
    key: Key,
    label: String,
    source: FileSource,
    location: FileLocation,
    from_base: bool,
    text: ConfigText,
    file: PathBuf,
    containing: Containing<'a>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Discovery, StaticPresets};
    use crate::origin::Layer;
    use crate::system::UserConfigDir;
    use crate::testutil::{ModeGuard, Tree, mkfifo};
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    /// A throwaway home, user config directory and project, all under one temp tree.
    struct World {
        tree: Tree,
        user: UserConfigDir,
        discovery: Discovery,
        floor_env: FloorEnvironment,
    }

    const BUILTINS: StaticPresets<'static> = StaticPresets(&[
        ("rust", "[net]\nallow = [\"crates.io\"]\n"),
        ("git", "[net]\nallow = [\"github.com\"]\n"),
        ("hooked", "hooks = [[\"echo\", \"built-in\"]]\n"),
        ("loops", "extends = [\"loops\"]\n"),
    ]);

    impl World {
        fn new() -> Self {
            let tree = Tree::new();
            let root = tree.project_root("work/proj");
            let config = root.path().as_path().join("hamster-ball.toml");
            let user = UserConfigDir::locate(tree.home());
            Self {
                tree,
                user,
                discovery: Discovery { root, config },
                floor_env: FloorEnvironment::new(),
            }
        }

        fn project_dir(&self) -> PathBuf {
            self.discovery.root.path().as_path().to_path_buf()
        }

        fn write(&self, path: &Path, text: &str) -> PathBuf {
            assert_ok!(fs::create_dir_all(assert_ok!(
                path.parent().ok_or("no parent")
            )));
            assert_ok!(fs::write(path, text));
            path.to_path_buf()
        }

        fn base(&self, text: &str) -> PathBuf {
            self.write(&self.user.base_file(), text)
        }

        fn project(&self, text: &str) -> PathBuf {
            self.write(&self.discovery.config, text)
        }

        fn user_preset(&self, name: &str, text: &str) -> PathBuf {
            let name = assert_ok!(crate::policy::PresetName::parse(name));
            self.write(&self.user.preset_file(&name), text)
        }

        fn request(&self) -> LoadRequest<'_> {
            // Re-locate so a base file created after `World::new` is picked up.
            LoadRequest::new(
                self.tree.home(),
                &self.discovery,
                &self.user,
                &self.floor_env,
            )
            .with_builtins(&BUILTINS)
        }

        fn load(&self) -> Result<Closure, LoadError> {
            load_closure(&self.request())
        }

        fn closure(&self) -> Closure {
            assert_ok!(self.load())
        }
    }

    fn paths(closure: &Closure) -> Vec<String> {
        closure
            .files()
            .iter()
            .map(|f| match &f.source {
                FileSource::Builtin { name } => format!("builtin:{name}"),
                FileSource::Disk { canonical, .. } => canonical
                    .as_path()
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            })
            .collect()
    }

    // ====================================================================================
    // Base and project
    // ====================================================================================

    #[test]
    fn the_base_always_applies_even_when_the_project_has_no_extends() {
        let w = World::new();
        w.base("[net]\nallow = [\"base.example.com\"]\n");
        w.project("[net]\nallow = [\"proj.example.com\"]\n");
        let closure = w.closure();
        assert_eq!(paths(&closure), vec!["base.toml", "hamster-ball.toml"]);
        let layers: Vec<Layer> = closure.files().iter().map(|f| f.layer).collect();
        assert_eq!(layers, vec![Layer::UserBase, Layer::Project]);
        let from_base: Vec<bool> = closure.files().iter().map(|f| f.from_base).collect();
        assert_eq!(from_base, vec![true, false]);
    }

    #[test]
    fn a_missing_base_is_an_error_that_says_how_to_create_one() {
        let w = World::new();
        w.project("");
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::BaseMissing { .. }), "{err:?}");
        let shown = err.to_string();
        assert!(shown.contains("hb init"), "{shown:?}");
        assert!(shown.contains("base.toml"), "{shown:?}");
    }

    #[test]
    fn an_empty_base_is_valid() {
        let w = World::new();
        w.base("");
        w.project("");
        assert_eq!(w.closure().files().len(), 2);
    }

    #[test]
    fn the_project_file_is_read_in_the_project_layer_and_located_in_the_project() {
        let w = World::new();
        w.base("");
        w.project("");
        let closure = w.closure();
        let project = &closure.files()[1];
        assert_eq!(project.layer, Layer::Project);
        assert_eq!(project.location, FileLocation::InProject);
        let base = &closure.files()[0];
        assert_eq!(base.location, FileLocation::UserConfig);
    }

    // ====================================================================================
    // extends: names, built-ins, paths
    // ====================================================================================

    #[test]
    fn a_builtin_preset_loads_before_the_file_that_extends_it() {
        let w = World::new();
        w.base("");
        w.project("extends = [\"rust\"]\n");
        let closure = w.closure();
        assert_eq!(
            paths(&closure),
            vec!["base.toml", "builtin:rust", "hamster-ball.toml"]
        );
        let rust = &closure.files()[1];
        assert_eq!(rust.layer, Layer::Preset);
        assert_eq!(rust.location, FileLocation::Builtin);
        assert!(!rust.from_base);
    }

    #[test]
    fn a_user_preset_by_name_is_found_in_the_presets_directory() {
        let w = World::new();
        w.base("");
        w.user_preset("mine", "[net]\nallow = [\"mine.example.com\"]\n");
        w.project("extends = [\"mine\"]\n");
        let closure = w.closure();
        assert_eq!(
            paths(&closure),
            vec!["base.toml", "mine.toml", "hamster-ball.toml"]
        );
        assert_eq!(closure.files()[1].location, FileLocation::UserConfig);
    }

    #[test]
    fn presets_may_extend_presets_and_dependencies_come_first() {
        let w = World::new();
        w.base("");
        w.user_preset("outer", "extends = [\"inner\"]\n");
        w.user_preset("inner", "extends = [\"rust\"]\n");
        w.project("extends = [\"outer\"]\n");
        let closure = w.closure();
        assert_eq!(
            paths(&closure),
            vec![
                "base.toml",
                "builtin:rust",
                "inner.toml",
                "outer.toml",
                "hamster-ball.toml"
            ]
        );
    }

    #[test]
    fn a_base_that_extends_a_preset_marks_the_whole_base_chain_from_base() {
        let w = World::new();
        w.user_preset("shared", "");
        w.base("extends = [\"shared\", \"git\"]\n");
        w.project("extends = [\"rust\"]\n");
        let closure = w.closure();
        let flags: Vec<(String, bool)> = paths(&closure)
            .into_iter()
            .zip(closure.files().iter().map(|f| f.from_base))
            .collect();
        assert_eq!(
            flags,
            vec![
                ("shared.toml".to_owned(), true),
                ("builtin:git".to_owned(), true),
                ("base.toml".to_owned(), true),
                ("builtin:rust".to_owned(), false),
                ("hamster-ball.toml".to_owned(), false),
            ]
        );
    }

    #[test]
    fn extends_entries_load_in_the_order_written() {
        let w = World::new();
        w.base("");
        w.project("extends = [\"git\", \"rust\"]\n");
        assert_eq!(
            paths(&w.closure()),
            vec![
                "base.toml",
                "builtin:git",
                "builtin:rust",
                "hamster-ball.toml"
            ]
        );
    }

    #[test]
    fn a_relative_path_resolves_against_the_extending_files_directory() {
        let w = World::new();
        w.base("");
        w.write(
            &w.project_dir().join("presets/a.toml"),
            "extends = [\"./b.toml\"]\n",
        );
        w.write(&w.project_dir().join("presets/b.toml"), "");
        w.write(&w.project_dir().join("shared.toml"), "");
        w.project("extends = [\"./presets/a.toml\"]\n");
        // `b.toml` is found next to `a.toml`, not next to the project file.
        let closure = w.closure();
        assert_eq!(
            paths(&closure),
            vec!["base.toml", "b.toml", "a.toml", "hamster-ball.toml"]
        );
        assert!(
            closure.files()[1..3]
                .iter()
                .all(|f| f.location == FileLocation::InProject)
        );
    }

    #[test]
    fn dot_dot_and_absolute_and_tilde_paths_load_and_are_located_by_where_they_are() {
        let w = World::new();
        w.base("");
        let outside = w.tree.outside("shared");
        w.write(&outside.join("abs.toml"), "");
        w.write(&w.tree.home_path().join("tilde.toml"), "");
        w.write(&w.tree.home_path().join("work/up.toml"), "");
        w.project(&format!(
            "extends = [\"{}\", \"~/tilde.toml\", \"../up.toml\"]\n",
            outside.join("abs.toml").display()
        ));
        let closure = w.closure();
        assert_eq!(
            paths(&closure),
            vec![
                "base.toml",
                "abs.toml",
                "tilde.toml",
                "up.toml",
                "hamster-ball.toml"
            ]
        );
        let locations: Vec<FileLocation> = closure.files().iter().map(|f| f.location).collect();
        assert_eq!(
            locations,
            vec![
                FileLocation::UserConfig,
                FileLocation::Other,
                FileLocation::Other,
                FileLocation::Other,
                FileLocation::InProject,
            ]
        );
    }

    #[test]
    fn an_absolute_path_to_a_user_preset_behaves_exactly_like_the_name() {
        let w = World::new();
        w.base("");
        let file = w.user_preset("mine", "hooks = [[\"echo\"]]\n");
        w.project(&format!("extends = [\"{}\"]\n", file.display()));
        // Location is physical, so the alias is as trusted as the name: hooks are allowed.
        let closure = w.closure();
        assert_eq!(closure.files()[1].location, FileLocation::UserConfig);
    }

    #[test]
    fn a_missing_preset_is_an_error_never_a_skip() {
        let w = World::new();
        w.base("");
        w.project("extends = [\"nope\"]\n");
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::Extends { .. }), "{err:?}");
        assert!(err.to_string().contains("nope"), "{err}");

        w.project("extends = [\"./missing.toml\"]\n");
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::Read { .. }), "{err:?}");
    }

    #[test]
    fn a_builtin_that_extends_itself_is_a_cycle() {
        let w = World::new();
        w.base("");
        w.project("extends = [\"loops\"]\n");
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::ExtendsCycle { .. }), "{err:?}");
    }

    // ====================================================================================
    // Dedupe and cycles
    // ====================================================================================

    #[test]
    fn a_diamond_loads_the_shared_file_once() {
        let w = World::new();
        w.base("");
        w.user_preset("left", "extends = [\"shared\"]\n");
        w.user_preset("right", "extends = [\"shared\"]\n");
        w.user_preset("shared", "[net]\nallow = [\"s.example.com\"]\n");
        w.project("extends = [\"left\", \"right\"]\n");
        assert_eq!(
            paths(&w.closure()),
            vec![
                "base.toml",
                "shared.toml",
                "left.toml",
                "right.toml",
                "hamster-ball.toml"
            ]
        );
    }

    #[test]
    fn a_hard_link_to_an_already_loaded_file_is_the_same_file() {
        let w = World::new();
        w.base("");
        let first = w.write(&w.project_dir().join("one.toml"), "");
        let alias = w.project_dir().join("two.toml");
        assert_ok!(fs::hard_link(&first, &alias));
        w.project("extends = [\"./one.toml\", \"./two.toml\"]\n");
        assert_eq!(
            paths(&w.closure()),
            vec!["base.toml", "one.toml", "hamster-ball.toml"]
        );
    }

    #[test]
    fn an_alias_through_a_symlinked_directory_is_the_same_file() {
        let w = World::new();
        w.base("");
        w.write(&w.project_dir().join("real/x.toml"), "");
        assert_ok!(symlink(
            w.project_dir().join("real"),
            w.project_dir().join("alias")
        ));
        w.project("extends = [\"./real/x.toml\", \"./alias/x.toml\"]\n");
        assert_eq!(
            paths(&w.closure()),
            vec!["base.toml", "x.toml", "hamster-ball.toml"]
        );
    }

    #[test]
    fn a_two_file_cycle_names_the_chain() {
        let w = World::new();
        w.base("");
        w.write(
            &w.project_dir().join("a.toml"),
            "extends = [\"./b.toml\"]\n",
        );
        w.write(
            &w.project_dir().join("b.toml"),
            "extends = [\"./a.toml\"]\n",
        );
        w.project("extends = [\"./a.toml\"]\n");
        let err = assert_err!(w.load());
        let LoadError::ExtendsCycle { chain } = &err else {
            assert_ok!(Err::<(), _>(format!("expected a cycle, got {err:?}")));
            return;
        };
        assert_eq!(chain.len(), 3, "{chain:?}");
        assert_eq!(chain.first(), chain.last());
        let shown = err.to_string();
        assert!(
            shown.contains("a.toml") && shown.contains("b.toml") && shown.contains("->"),
            "{shown}"
        );
    }

    #[test]
    fn a_file_that_extends_itself_is_a_cycle() {
        let w = World::new();
        w.base("");
        w.write(
            &w.project_dir().join("me.toml"),
            "extends = [\"./me.toml\"]\n",
        );
        w.project("extends = [\"./me.toml\"]\n");
        assert!(matches!(
            assert_err!(w.load()),
            LoadError::ExtendsCycle { .. }
        ));
    }

    #[test]
    fn a_cycle_through_a_hard_link_alias_is_still_found() {
        let w = World::new();
        w.base("");
        let a = w.write(
            &w.project_dir().join("a.toml"),
            "extends = [\"./a-alias.toml\"]\n",
        );
        assert_ok!(fs::hard_link(&a, w.project_dir().join("a-alias.toml")));
        w.project("extends = [\"./a.toml\"]\n");
        assert!(matches!(
            assert_err!(w.load()),
            LoadError::ExtendsCycle { .. }
        ));
    }

    #[test]
    fn the_project_file_reached_through_the_base_keeps_its_project_layer() {
        let w = World::new();
        w.project("");
        w.base(&format!(
            "extends = [\"{}\"]\n",
            w.discovery.config.display()
        ));
        let closure = w.closure();
        let project = closure
            .files()
            .iter()
            .find(|f| f.location == FileLocation::InProject)
            .map(|f| f.layer);
        assert_eq!(project, Some(Layer::Project));
        assert_eq!(closure.files().len(), 2);
    }

    // ====================================================================================
    // Caps
    // ====================================================================================

    fn chain_of(w: &World, length: usize) {
        for i in 0..length {
            let next = if i + 1 < length {
                format!("extends = [\"./p{}.toml\"]\n", i + 1)
            } else {
                String::new()
            };
            w.write(&w.project_dir().join(format!("p{i}.toml")), &next);
        }
        w.project("extends = [\"./p0.toml\"]\n");
    }

    #[test]
    fn a_chain_at_the_depth_limit_loads_and_one_deeper_is_refused() {
        let w = World::new();
        w.base("");
        // Depth counts the files on the stack, project file included.
        chain_of(&w, MAX_EXTENDS_DEPTH - 1);
        assert_ok!(w.load());
        chain_of(&w, MAX_EXTENDS_DEPTH);
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::TooDeep { .. }), "{err:?}");
        assert!(
            err.to_string().contains(&MAX_EXTENDS_DEPTH.to_string()),
            "{err}"
        );
    }

    #[test]
    fn a_file_shared_by_the_base_chain_and_the_project_chain_stays_from_base() {
        let w = World::new();
        w.user_preset("shared", "");
        w.base("extends = [\"shared\"]\n");
        w.project("extends = [\"shared\"]\n");
        let closure = w.closure();
        let shared = assert_some!(closure
            .files()
            .iter()
            .find(|f| matches!(&f.source, FileSource::Disk { canonical, .. } if canonical.as_path().ends_with("shared.toml"))));
        assert!(
            shared.from_base,
            "the base chain provides it, so it is not a project addition"
        );
        assert_eq!(closure.files().len(), 3);
    }

    #[test]
    fn exactly_the_maximum_number_of_files_loads_and_one_more_does_not() {
        let w = World::new();
        w.base("");
        // base + project + (MAX - 2) presets is exactly MAX files.
        let at_limit = MAX_CLOSURE_FILES - 2;
        let entries: Vec<String> = (0..at_limit)
            .map(|i| {
                w.write(&w.project_dir().join(format!("f{i}.toml")), "");
                format!("\"./f{i}.toml\"")
            })
            .collect();
        // Spread over two files to stay under the per-file entry limit of 32 and the depth cap.
        w.project(&format!("extends = [{}]\n", entries.join(", ")));
        assert_eq!(w.closure().files().len(), MAX_CLOSURE_FILES);

        w.write(&w.project_dir().join("one-more.toml"), "");
        let mut more = entries;
        more.push("\"./one-more.toml\"".to_owned());
        w.project(&format!("extends = [{}]\n", more.join(", ")));
        assert!(matches!(assert_err!(w.load()), LoadError::TooManyFiles));
    }

    #[test]
    fn exactly_the_maximum_number_of_extends_entries_in_one_file_is_accepted() {
        let w = World::new();
        w.base("");
        let entries: Vec<String> = (0..MAX_EXTENDS_PER_FILE)
            .map(|_| "\"rust\"".to_owned())
            .collect();
        w.project(&format!("extends = [{}]\n", entries.join(", ")));
        // The same preset listed 32 times loads once.
        assert_eq!(w.closure().files().len(), 3);
    }

    #[test]
    fn the_file_count_is_capped() {
        let w = World::new();
        w.base("");
        let entries: Vec<String> = (0..MAX_CLOSURE_FILES + 1)
            .map(|i| {
                w.write(&w.project_dir().join(format!("f{i}.toml")), "");
                format!("\"./f{i}.toml\"")
            })
            .collect();
        // Stay under the per-file extends cap by nesting two groups.
        let (first, second) = entries.split_at(entries.len() / 2);
        w.write(
            &w.project_dir().join("g1.toml"),
            &format!("extends = [{}]\n", first.join(", ")),
        );
        w.write(
            &w.project_dir().join("g2.toml"),
            &format!("extends = [{}]\n", second.join(", ")),
        );
        w.project("extends = [\"./g1.toml\", \"./g2.toml\"]\n");
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::TooManyFiles), "{err:?}");
    }

    #[test]
    fn too_many_extends_entries_in_one_file_is_refused() {
        let w = World::new();
        w.base("");
        let entries: Vec<String> = (0..=MAX_EXTENDS_PER_FILE)
            .map(|_| "\"rust\"".to_owned())
            .collect();
        w.project(&format!("extends = [{}]\n", entries.join(", ")));
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::TooManyExtends { .. }), "{err:?}");
    }

    // ====================================================================================
    // Read failures
    // ====================================================================================

    #[test]
    fn an_unreadable_preset_is_an_error() {
        let w = World::new();
        w.base("");
        let file = w.user_preset("secret", "");
        let _guard = ModeGuard::set(&file, 0o000);
        w.project("extends = [\"secret\"]\n");
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::Read { .. }), "{err:?}");
    }

    #[test]
    fn a_fifo_named_as_a_preset_is_an_error_without_blocking() {
        let w = World::new();
        w.base("");
        mkfifo(&w.project_dir().join("pipe.toml"));
        w.project("extends = [\"./pipe.toml\"]\n");
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::Read { .. }), "{err:?}");
    }

    #[test]
    fn a_symlink_leaf_named_by_path_is_refused_but_one_in_the_user_presets_is_followed() {
        let w = World::new();
        w.base("");
        let real = w.write(&w.tree.outside("dotfiles").join("real.toml"), "");
        assert_ok!(symlink(&real, w.project_dir().join("link.toml")));
        w.project("extends = [\"./link.toml\"]\n");
        assert!(matches!(assert_err!(w.load()), LoadError::Read { .. }));

        let name = assert_ok!(crate::policy::PresetName::parse("dotfile"));
        let preset = w.user.preset_file(&name);
        assert_ok!(fs::create_dir_all(assert_ok!(
            preset.parent().ok_or("no parent")
        )));
        assert_ok!(symlink(&real, &preset));
        w.project("extends = [\"dotfile\"]\n");
        let closure = w.closure();
        // The symlink target lives outside the config directory, so it is classified `Other`.
        assert_eq!(closure.files()[1].location, FileLocation::Other);
    }

    #[test]
    fn a_resolve_error_names_the_file_it_is_in() {
        let w = World::new();
        w.base("");
        w.user_preset("broken", "[net]\nallow = [\"not a host\"]\n");
        w.project("extends = [\"broken\"]\n");
        let err = assert_err!(w.load());
        let LoadError::Resolve { path: file, source } = &err else {
            assert_ok!(Err::<(), _>(format!("expected Resolve, got {err:?}")));
            return;
        };
        assert!(file.ends_with("broken.toml"), "{file:?}");
        assert_eq!(source.errors.len(), 1);
    }

    #[test]
    fn a_collision_between_a_builtin_and_a_user_preset_is_an_error() {
        let w = World::new();
        w.base("");
        w.user_preset("rust", "");
        w.project("extends = [\"rust\"]\n");
        assert!(matches!(assert_err!(w.load()), LoadError::Extends { .. }));
    }

    // ====================================================================================
    // Trust: owner and world-writable on every file
    // ====================================================================================

    #[test]
    fn a_world_writable_base_is_refused() {
        let w = World::new();
        let base = w.base("");
        w.project("");
        let _guard = ModeGuard::set(&base, 0o666);
        let err = assert_err!(w.load());
        assert!(matches!(err, LoadError::Untrusted { .. }), "{err:?}");
        assert!(err.to_string().contains("base.toml"), "{err}");
    }

    #[test]
    fn a_world_writable_preset_is_refused() {
        let w = World::new();
        w.base("");
        let preset = w.user_preset("loose", "");
        let _guard = ModeGuard::set(&preset, 0o666);
        w.project("extends = [\"loose\"]\n");
        assert!(matches!(assert_err!(w.load()), LoadError::Untrusted { .. }));
    }

    #[test]
    fn a_file_owned_by_another_user_is_refused() {
        let w = World::new();
        w.base("");
        w.project("");
        let request = w.request().trusting_uid(w.request().uid + 1);
        let err = assert_err!(load_closure(&request));
        assert!(matches!(err, LoadError::Untrusted { .. }), "{err:?}");
    }

    #[test]
    fn a_group_writable_file_is_accepted() {
        let w = World::new();
        let base = w.base("");
        w.project("");
        let _guard = ModeGuard::set(&base, 0o664);
        assert_ok!(w.load());
    }

    // ====================================================================================
    // User-only sections: hooks and guard.exceptions
    // ====================================================================================

    fn user_only_error(err: &LoadError) -> (&Path, &'static str, FileLocation) {
        match err {
            LoadError::UserOnlySection {
                path,
                section,
                location,
                ..
            } => (path, section, *location),
            other => {
                assert_ok!(Err::<(), _>(format!(
                    "expected UserOnlySection, got {other:?}"
                )));
                unreachable!()
            }
        }
    }

    #[test]
    fn hooks_in_the_project_file_are_an_error_naming_that_file() {
        let w = World::new();
        w.base("");
        let project = w.project("hooks = [[\"curl\", \"evil\"]]\n");
        let err = assert_err!(w.load());
        let (path, section, location) = user_only_error(&err);
        assert_eq!(path, assert_ok!(fs::canonicalize(&project)));
        assert_eq!(section, "hooks");
        assert_eq!(location, FileLocation::InProject);
        let shown = err.to_string();
        assert!(
            shown.contains("hamster-ball.toml") && shown.contains("hooks"),
            "{shown}"
        );
        assert!(
            !shown.contains("evil"),
            "the hook's argv is untrusted and must not be echoed"
        );
    }

    #[test]
    fn launchctl_true_in_the_project_file_is_an_error_but_false_is_not() {
        let w = World::new();
        w.base("");
        let project = w.project("[system]\nlaunchctl = true\n");
        let err = assert_err!(w.load());
        let (path, section, location) = user_only_error(&err);
        assert_eq!(path, assert_ok!(fs::canonicalize(&project)));
        assert_eq!(section, "system.launchctl = true");
        assert_eq!(location, FileLocation::InProject);
        assert!(err.to_string().contains("system.launchctl = true"));
        // A project may refuse what the user allowed; saying `false` is harmless anywhere.
        w.project("[system]\nlaunchctl = false\n");
        assert_ok!(w.load());
    }

    #[test]
    fn internal_hosts_in_a_project_file_are_an_error_even_when_empty_but_fine_in_the_base() {
        let w = World::new();
        w.base("[net]\ninternal_hosts = [\"github.com\"]\n");
        w.project("");
        assert_ok!(w.load());
        let project = w.project("[net]\ninternal_hosts = []\n");
        let err = assert_err!(w.load());
        let (path, section, location) = user_only_error(&err);
        assert_eq!(path, assert_ok!(fs::canonicalize(&project)));
        assert_eq!(section, "net.internal_hosts");
        assert_eq!(location, FileLocation::InProject);
    }

    #[test]
    fn launchctl_true_in_the_users_base_is_accepted() {
        let w = World::new();
        w.base("[system]\nlaunchctl = true\n");
        w.project("");
        assert_ok!(w.load());
    }

    #[test]
    fn launchctl_true_in_an_in_project_preset_is_an_error_naming_the_preset() {
        let w = World::new();
        w.base("");
        w.write(
            &w.project_dir().join("p.toml"),
            "[system]\nlaunchctl = true\n",
        );
        w.project("extends = [\"./p.toml\"]\n");
        let err = assert_err!(w.load());
        let (path, section, _) = user_only_error(&err);
        assert!(path.ends_with("p.toml"), "{path:?}");
        assert_eq!(section, "system.launchctl = true");
    }

    #[test]
    fn an_empty_hooks_key_in_the_project_is_still_an_error() {
        let w = World::new();
        w.base("");
        w.project("hooks = []\n");
        assert!(matches!(
            assert_err!(w.load()),
            LoadError::UserOnlySection { .. }
        ));
    }

    #[test]
    fn hooks_in_an_in_project_preset_are_an_error_naming_the_preset() {
        let w = World::new();
        w.base("");
        w.write(&w.project_dir().join("p.toml"), "hooks = [[\"x\"]]\n");
        w.project("extends = [\"./p.toml\"]\n");
        let err = assert_err!(w.load());
        let (path, _, location) = user_only_error(&err);
        assert!(path.ends_with("p.toml"), "{path:?}");
        assert_eq!(location, FileLocation::InProject);
    }

    #[test]
    fn hooks_in_a_file_outside_both_the_project_and_the_config_dir_are_an_error() {
        let w = World::new();
        w.base("");
        let elsewhere = w.write(
            &w.tree.outside("shared").join("h.toml"),
            "hooks = [[\"x\"]]\n",
        );
        w.project(&format!("extends = [\"{}\"]\n", elsewhere.display()));
        let err = assert_err!(w.load());
        let (_, _, location) = user_only_error(&err);
        assert_eq!(location, FileLocation::Other);
    }

    #[test]
    fn hooks_in_the_base_a_user_preset_and_a_builtin_are_accepted() {
        let w = World::new();
        w.base("hooks = [[\"echo\", \"base\"]]\n");
        w.user_preset("mine", "hooks = [[\"echo\", \"preset\"]]\n");
        w.project("extends = [\"mine\", \"hooked\"]\n");
        assert_eq!(w.closure().files().len(), 4);
    }

    #[test]
    fn a_user_preset_that_extends_an_in_project_file_with_hooks_names_the_in_project_file() {
        let w = World::new();
        w.base("");
        let inner = w.write(&w.project_dir().join("inner.toml"), "hooks = [[\"x\"]]\n");
        w.user_preset("trusted", &format!("extends = [\"{}\"]\n", inner.display()));
        w.project("extends = [\"trusted\"]\n");
        let err = assert_err!(w.load());
        let (path, _, location) = user_only_error(&err);
        assert!(path.ends_with("inner.toml"), "{path:?}");
        assert_eq!(location, FileLocation::InProject);
        // The reference chain shows how the file was reached.
        assert!(err.to_string().contains("trusted"), "{err}");
    }

    #[test]
    fn a_base_that_extends_a_project_file_with_hooks_is_refused() {
        let w = World::new();
        w.project("hooks = [[\"x\"]]\n");
        w.base(&format!(
            "extends = [\"{}\"]\n",
            w.discovery.config.display()
        ));
        assert!(matches!(
            assert_err!(w.load()),
            LoadError::UserOnlySection { .. }
        ));
    }

    #[test]
    fn a_user_preset_that_is_also_hard_linked_elsewhere_cannot_carry_hooks() {
        let w = World::new();
        w.base("");
        let preset = w.user_preset("linked", "hooks = [[\"x\"]]\n");
        assert_ok!(fs::hard_link(
            &preset,
            w.project_dir().join("writable-alias.toml")
        ));
        w.project("extends = [\"linked\"]\n");
        let err = assert_err!(w.load());
        let (_, _, location) = user_only_error(&err);
        assert_eq!(location, FileLocation::Other);
    }

    #[test]
    fn a_user_preset_symlinked_to_a_dotfiles_directory_loses_hook_rights_and_is_hashed() {
        let w = World::new();
        w.base("");
        let target = w.write(
            &w.tree.outside("dotfiles").join("p.toml"),
            "hooks = [[\"x\"]]\n",
        );
        let name = assert_ok!(crate::policy::PresetName::parse("dot"));
        let path = w.user.preset_file(&name);
        assert_ok!(fs::create_dir_all(assert_ok!(
            path.parent().ok_or("no parent")
        )));
        assert_ok!(symlink(&target, &path));
        w.project("extends = [\"dot\"]\n");
        let err = assert_err!(w.load());
        let (_, _, location) = user_only_error(&err);
        assert_eq!(location, FileLocation::Other);
        assert!(location.needs_approval());
    }

    #[test]
    fn guard_exceptions_follow_the_same_rule_as_hooks() {
        let w = World::new();
        w.base("[guard]\nexceptions = [\"~/p/.env.example\"]\n");
        w.project("[guard]\nexceptions = [\"~/p/.env\"]\n");
        let err = assert_err!(w.load());
        let (path, section, _) = user_only_error(&err);
        assert!(path.ends_with("hamster-ball.toml"), "{path:?}");
        assert_eq!(section, "guard.exceptions");
    }

    #[test]
    fn user_only_sections_are_reported_before_other_resolve_errors_in_the_same_file() {
        let w = World::new();
        w.base("");
        w.project("hooks = [[\"x\"]]\n[net]\nallow = [\"bad host\"]\n");
        assert!(matches!(
            assert_err!(w.load()),
            LoadError::UserOnlySection { .. }
        ));
    }

    #[test]
    fn a_project_inside_the_user_config_dir_cannot_launder_hooks() {
        // InProject wins over UserConfig: a project placed under ~/.config/hamster-ball is
        // still a project.
        let tree = Tree::new();
        let user = UserConfigDir::locate(tree.home());
        assert_ok!(fs::create_dir_all(user.dir()));
        let project_dir = tree.inside_home(".config/hamster-ball/projects/app");
        let root = assert_ok!(crate::policy::ProjectRoot::new(
            crate::testutil::canonical(&project_dir),
            tree.home()
        ));
        let config = project_dir.join("hamster-ball.toml");
        assert_ok!(fs::write(&config, "hooks = [[\"x\"]]\n"));
        assert_ok!(fs::write(user.base_file(), ""));
        let discovery = Discovery { root, config };
        let floor_env = FloorEnvironment::new();
        let request =
            LoadRequest::new(tree.home(), &discovery, &user, &floor_env).with_builtins(&BUILTINS);
        assert!(matches!(
            assert_err!(load_closure(&request)),
            LoadError::UserOnlySection { .. }
        ));
    }

    // ====================================================================================
    // What M4 receives
    // ====================================================================================

    #[test]
    fn approval_files_are_exactly_the_in_project_and_other_files_in_closure_order() {
        let w = World::new();
        w.base("");
        w.user_preset("mine", "");
        w.write(&w.project_dir().join("local.toml"), "");
        let elsewhere = w.write(&w.tree.outside("shared").join("o.toml"), "");
        w.project(&format!(
            "extends = [\"rust\", \"mine\", \"./local.toml\", \"{}\"]\n",
            elsewhere.display()
        ));
        let closure = w.closure();
        let names: Vec<String> = closure
            .approval_files()
            .map(|f| match &f.source {
                FileSource::Disk { canonical, .. } => assert_some!(canonical.as_path().file_name())
                    .to_string_lossy()
                    .into_owned(),
                FileSource::Builtin { name } => name.to_string(),
            })
            .collect();
        assert_eq!(names, vec!["local.toml", "o.toml", "hamster-ball.toml"]);
    }

    #[test]
    fn closure_files_carry_the_exact_bytes_that_were_parsed() {
        let w = World::new();
        w.base("# base\n");
        let text = "# project\n[net]\nallow = [\"a.example.com\"]\n";
        w.project(text);
        let closure = w.closure();
        assert_eq!(closure.files()[1].text.bytes(), text.as_bytes());
        assert_eq!(closure.files()[1].resolved.net.allow.len(), 1);
    }

    #[test]
    fn origin_rebuilds_a_full_origin_from_a_compact_source() {
        let w = World::new();
        w.base("");
        w.project("");
        let closure = w.closure();
        let file = closure.files()[1].id;
        let origin = closure.origin(
            crate::origin::Source::entry(file, 2),
            crate::origin::KeyPath::root()
                .field("net")
                .field("allow")
                .index(2),
        );
        assert_eq!(origin.layer, Layer::Project);
        assert!(
            origin.file.ends_with("hamster-ball.toml"),
            "{:?}",
            origin.file
        );
        assert_eq!(origin.key.to_string(), "net.allow[2]");
    }

    #[test]
    fn origins_use_the_canonical_path_not_the_spelling_it_was_reached_by() {
        let w = World::new();
        w.base("");
        w.write(&w.project_dir().join("real/x.toml"), "");
        assert_ok!(symlink(
            w.project_dir().join("real"),
            w.project_dir().join("alias")
        ));
        w.project("extends = [\"./alias/x.toml\"]\n");
        let closure = w.closure();
        let x = &closure.files()[1];
        let origin = closure.origin(
            crate::origin::Source::value(x.id),
            crate::origin::KeyPath::root(),
        );
        assert!(
            origin.file.to_string_lossy().contains("/real/"),
            "{:?}",
            origin.file
        );
    }

    // ====================================================================================
    // load: closure plus merged policy, end to end
    // ====================================================================================

    #[test]
    fn load_returns_the_closure_and_the_merged_policy() {
        let w = World::new();
        w.base("[net]\nallow = [\"base.example.com\"]\n");
        w.project("extends = [\"rust\"]\n[net]\nallow = [\"proj.example.com\"]\n");
        let loaded = assert_ok!(load(&w.request()));
        assert_eq!(loaded.closure.files().len(), 3);
        let hosts: Vec<String> = loaded
            .policy
            .net
            .allow
            .iter()
            .map(|h| h.value.to_string())
            .collect();
        assert_eq!(
            hosts,
            vec!["base.example.com", "crates.io", "proj.example.com"]
        );
    }

    #[test]
    fn a_project_allow_on_a_base_denied_path_is_still_denied_end_to_end() {
        use crate::config::{FsAccess, FsDecision};
        let w = World::new();
        let secret = w.tree.inside_home("secrets");
        w.base(&format!("[fs]\ndeny_read = [\"{}\"]\n", secret.display()));
        w.project(&format!("[fs]\nwrite = [\"{}\"]\n", secret.display()));
        let loaded = assert_ok!(load(&w.request()));
        let target = crate::testutil::canonical(&secret);
        for access in [FsAccess::Read, FsAccess::Write] {
            assert!(
                matches!(
                    loaded.policy.decide(&target, access),
                    FsDecision::Denied { .. }
                ),
                "{access:?}"
            );
        }
    }

    #[test]
    fn a_conflict_between_real_files_is_a_merge_error_naming_both_files() {
        let w = World::new();
        w.base("[env.set]\nMODE = \"a\"\n");
        w.project("[env.set]\nMODE = \"b\"\n");
        let err = assert_err!(load(&w.request()));
        assert!(matches!(err, LoadError::Merge { .. }), "{err:?}");
        let LoadError::Merge { source } = &err else {
            return;
        };
        let shown = source.errors[0].to_string();
        assert!(
            shown.contains("base.toml") && shown.contains("hamster-ball.toml"),
            "{shown}"
        );
    }

    #[test]
    fn sources_in_the_policy_resolve_back_to_real_origins_through_the_closure() {
        let w = World::new();
        w.base("[net]\nallow = [\"both.example.com\"]\n");
        w.project("[net]\nallow = [\"other.example.com\", \"both.example.com\"]\n");
        let loaded = assert_ok!(load(&w.request()));
        let both = assert_some!(
            loaded
                .policy
                .net
                .allow
                .iter()
                .find(|h| h.value.to_string() == "both.example.com")
        );
        let origins: Vec<String> = both
            .sources
            .iter()
            .map(|source| {
                let index = match source {
                    crate::origin::Source::File { index, .. } => *index,
                };
                let key = crate::origin::KeyPath::root()
                    .field("net")
                    .field("allow")
                    .index(index.unwrap_or(0) as usize);
                let origin = loaded.closure.origin(*source, key);
                format!(
                    "{}:{}",
                    origin
                        .file
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    origin.key
                )
            })
            .collect();
        assert_eq!(
            origins,
            vec!["base.toml:net.allow[0]", "hamster-ball.toml:net.allow[1]"]
        );
    }

    // ====================================================================================
    // Determinism and error text
    // ====================================================================================

    #[test]
    fn loading_twice_gives_the_same_order_and_bytes() {
        let w = World::new();
        w.base("");
        w.user_preset("a", "");
        w.user_preset("b", "extends = [\"a\"]\n");
        w.project("extends = [\"b\", \"rust\"]\n");
        let first = paths(&w.closure());
        let second = paths(&w.closure());
        assert_eq!(first, second);
    }

    #[test]
    fn errors_follow_the_display_convention_and_escape_hostile_names() {
        let w = World::new();
        w.base("");
        w.project("extends = [\"nope\\u202eevil\"]\n");
        let err = assert_err!(w.load());
        assert!(!err.to_string().contains('\u{202e}'), "{err}");
        crate::error::conventions::assert_display_excludes_sources(&err);

        w.project("hooks = [[\"x\"]]\n");
        let err = assert_err!(w.load());
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
