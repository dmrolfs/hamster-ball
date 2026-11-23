// ABOUTME: UserConfigDir: the user's ~/.config/hamster-ball directory, where base.toml and presets/ live.
// ABOUTME: Also writes a first base.toml template. XDG_CONFIG_HOME is deliberately ignored.
//! The user's own config directory.
//!
//! The directory is always `<home>/.config/hamster-ball`, derived from the passwd-authoritative
//! home. `XDG_CONFIG_HOME` is not consulted: honouring it would let a launcher relocate the
//! directory the floor protects and the hook trust rule keys on, the same class of problem
//! decision D28 closes for `$HOME`.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use snafu::{ResultExt, Snafu};

use crate::policy::{CanonicalPath, HomeDir, PathError, PresetName};
use crate::sys::path_preview;

/// The file name of the user's base config.
const BASE_FILE_NAME: &str = "base.toml";
/// The directory, under the config directory, that holds the user's presets.
const PRESETS_DIR_NAME: &str = "presets";

/// The content `hb init` writes: a small, commented base that parses and resolves.
pub const BASE_TEMPLATE: &str = "\
# hamster-ball base config.
#
# Always applied, for every project. Only you can change this file: a project can add to
# what is allowed here but can never remove or weaken anything this file or the floor forbids.
# Add the hosts, paths and environment variables you want every hamster ball to have.

[tls]
# Trust the system certificate store (needed behind a TLS-inspecting proxy such as Zscaler).
system_trust = true

[terminal]
# An agent can set your clipboard through your terminal (OSC 52); hb says so when it does.
# Uncomment to refuse: the write is removed and hb says it tried.
# clipboard_write = false

[system]
# The agent cannot run launchctl. Turning it on lets the agent start, unload and disable your
# launchd jobs that are not running, and read your launchd service list. Only this file and
# your presets can say true; any file can say false.
# launchctl = true

[net]
# Hosts allowed to resolve to private, tunnel or other internal addresses, for example a corporate
# network where github.com or an internal registry answers with a 100.64.x.x address. Only this
# file and your presets can list them; hb says which entry to add when it refuses one.
# internal_hosts = [\"github.com\", \"*.in.example.com\"]

[env]
# Variables copied from your shell into every hamster ball. HOME, PATH, TMPDIR, TERM and the proxy
# and TLS variables are set by hb itself and cannot be listed here.
pass = [\"LANG\", \"COLORTERM\"]
";

/// Where `hb` keeps approvals: `<home>/.local/state/hamster-ball`.
///
/// `XDG_STATE_HOME` is deliberately not consulted. A project's `.envrc` (after `direnv allow`)
/// can set it, which would move the approval store into a directory the agent can write. This is
/// the same relocation hazard as `$HOME` (decision D28) and `XDG_CONFIG_HOME` (D39).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateDir {
    dir: PathBuf,
}

impl StateDir {
    /// Locates `<home>/.local/state/hamster-ball`. Performs no I/O; the directory need not exist.
    #[must_use]
    pub fn locate(home: &HomeDir) -> Self {
        Self {
            dir: home
                .path()
                .as_path()
                .join(".local")
                .join("state")
                .join("hamster-ball"),
        }
    }

    /// The directory, spelled from the home directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// Why the user's config directory could not be located or initialized.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum UserConfigError {
    /// The directory exists but could not be resolved.
    #[snafu(display("{} could not be resolved", path_preview(path)))]
    Unreadable {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },

    /// The directory's canonical path is not usable.
    #[snafu(display("{} has an unusable canonical path", path_preview(path)))]
    Canonical {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: PathError,
    },

    /// A base config already exists, and is never overwritten.
    #[snafu(display(
        "{} already exists; hb init never overwrites it. Edit it directly.",
        path_preview(path)
    ))]
    BaseExists {
        /// The existing base config.
        path: PathBuf,
    },

    /// The config directory or base file could not be created.
    #[snafu(display("{} could not be created", path_preview(path)))]
    Create {
        /// What could not be created.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
}

/// The user's `~/.config/hamster-ball` directory.
///
/// Holds only where the directory is; whether it exists, and where it really is (a dotfile
/// manager may symlink it), is asked fresh by [`UserConfigDir::canonical`], so a directory
/// created after this value (by `hb init`, say) is seen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserConfigDir {
    dir: PathBuf,
}

impl UserConfigDir {
    /// Locates `<home>/.config/hamster-ball`. Performs no I/O; the directory need not exist.
    #[must_use]
    pub fn locate(home: &HomeDir) -> Self {
        Self {
            dir: home.path().as_path().join(".config").join("hamster-ball"),
        }
    }

    /// A user config directory kept somewhere else, for tools that must not read the real one
    /// (the conformance harness). `hb` itself never calls this: its user directory is always
    /// [`UserConfigDir::locate`], so no variable or flag can move it (D39).
    #[must_use]
    pub fn at(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The directory, spelled from the home directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The directory's canonical path, or `None` if it does not exist.
    ///
    /// Resolved now, so a symlinked `~/.config` or `~/.config/hamster-ball` (a dotfile manager)
    /// anchors at its target, and a directory created after `locate` is seen.
    ///
    /// # Errors
    /// See [`UserConfigError`].
    pub fn canonical(&self) -> Result<Option<CanonicalPath>, UserConfigError> {
        match fs::canonicalize(&self.dir) {
            Ok(path) => CanonicalPath::from_canonical(&path)
                .map(Some)
                .context(CanonicalSnafu {
                    path: self.dir.clone(),
                }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).context(UnreadableSnafu {
                path: self.dir.clone(),
            }),
        }
    }

    /// Where the base config is, or would be.
    #[must_use]
    pub fn base_file(&self) -> PathBuf {
        self.dir.join(BASE_FILE_NAME)
    }

    /// Where the user's preset `name` is, or would be.
    #[must_use]
    pub fn preset_file(&self, name: &PresetName) -> PathBuf {
        self.dir.join(PRESETS_DIR_NAME).join(format!("{name}.toml"))
    }

    /// The preset name a file under `presets/` answers to: its path below that directory, without `.toml`.
    ///
    /// `None` if `path` is not under the presets directory or the name is not a valid preset name.
    #[must_use]
    pub fn preset_name_of(&self, path: &Path) -> Option<PresetName> {
        let relative = path
            .strip_prefix(self.dir.join(PRESETS_DIR_NAME))
            .ok()?
            .with_extension("");
        PresetName::parse(relative.to_str()?).ok()
    }

    /// Writes [`BASE_TEMPLATE`] as the base config, creating the directory (mode 0700) and the
    /// file (mode 0600), and returns the file's path.
    ///
    /// Never overwrites: an existing base config is an error, so running this twice cannot
    /// destroy the user's edits.
    ///
    /// # Errors
    /// [`UserConfigError::BaseExists`] if the file exists, or [`UserConfigError::Create`].
    pub fn init_base(&self) -> Result<PathBuf, UserConfigError> {
        let base = self.base_file();
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .context(CreateSnafu {
                path: self.dir.clone(),
            })?;
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&base)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return BaseExistsSnafu { path: base }.fail();
            }
            Err(error) => return Err(error).context(CreateSnafu { path: base }),
        };
        file.write_all(BASE_TEMPLATE.as_bytes())
            .context(CreateSnafu { path: base.clone() })?;
        Ok(base)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::Tree;
    use claims::{assert_err, assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::{MetadataExt, symlink};

    #[test]
    fn locate_is_dot_config_hamster_ball_under_the_passwd_home() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        assert_eq!(dir.dir(), tree.home_path().join(".config/hamster-ball"));
        assert_eq!(
            dir.base_file(),
            tree.home_path().join(".config/hamster-ball/base.toml")
        );
    }

    #[test]
    fn a_preset_file_maps_back_to_its_name() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        let name = assert_ok!(PresetName::parse("team/rust"));
        assert_eq!(dir.preset_name_of(&dir.preset_file(&name)), Some(name));
        assert_none!(dir.preset_name_of(&dir.dir().join("base.toml")));
        assert_none!(dir.preset_name_of(Path::new("/elsewhere/presets/x.toml")));
    }

    #[test]
    fn the_state_dir_is_under_the_passwd_home_and_ignores_xdg_state_home() {
        let tree = Tree::new();
        let dir = StateDir::locate(tree.home());
        assert_eq!(
            dir.dir(),
            tree.home_path().join(".local/state/hamster-ball")
        );
        // `locate` takes no environment, so a variable cannot move it. The floor protects it.
        assert!(
            crate::policy::floor::TABLE
                .iter()
                .any(|rule| rule.base == "~/.local/state/hamster-ball")
        );
    }

    #[test]
    fn a_directory_that_does_not_exist_yet_has_no_canonical_path() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        assert_none!(assert_ok!(dir.canonical()));
    }

    #[test]
    fn an_existing_directory_records_its_canonical_path() {
        let tree = Tree::new();
        let real = tree.inside_home(".config/hamster-ball");
        let dir = UserConfigDir::locate(tree.home());
        assert_eq!(assert_some!(assert_ok!(dir.canonical())).as_path(), real);
    }

    #[test]
    fn a_symlinked_config_directory_is_anchored_at_its_target() {
        let tree = Tree::new();
        let dotfiles = tree.outside("dotfiles/hamster-ball");
        let config = tree.inside_home(".config");
        assert_ok!(symlink(&dotfiles, config.join("hamster-ball")));
        let dir = UserConfigDir::locate(tree.home());
        assert_eq!(
            assert_some!(assert_ok!(dir.canonical())).as_path(),
            dotfiles
        );
    }

    #[test]
    fn a_directory_created_after_locate_is_seen_by_canonical() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        assert_none!(assert_ok!(dir.canonical()));
        assert_ok!(dir.init_base());
        assert_some!(assert_ok!(dir.canonical()));
    }

    #[test]
    fn an_unreadable_parent_is_an_error_not_an_absent_directory() {
        use crate::testutil::ModeGuard;
        let tree = Tree::new();
        let config = tree.inside_home(".config");
        let _guard = ModeGuard::set(&config, 0o000);
        let dir = UserConfigDir::locate(tree.home());
        let err = assert_err!(dir.canonical());
        assert!(matches!(err, UserConfigError::Unreadable { .. }), "{err:?}");
    }

    #[test]
    fn init_base_reports_a_permission_error_as_such_not_as_an_existing_base() {
        use crate::testutil::ModeGuard;
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        let created = tree.inside_home(".config/hamster-ball");
        let _guard = ModeGuard::set(&created, 0o500);
        let err = assert_err!(dir.init_base());
        assert!(matches!(err, UserConfigError::Create { .. }), "{err:?}");
        assert!(!dir.base_file().exists());
    }

    #[test]
    fn preset_files_live_under_presets_with_a_toml_extension() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        let name = assert_ok!(PresetName::parse("agent/mine"));
        assert_eq!(
            dir.preset_file(&name),
            tree.home_path()
                .join(".config/hamster-ball/presets/agent/mine.toml")
        );
    }

    #[test]
    fn a_directory_given_explicitly_is_used_for_the_base_and_the_presets() {
        let dir = UserConfigDir::at("/tmp/elsewhere/hb");
        assert_eq!(dir.dir(), Path::new("/tmp/elsewhere/hb"));
        assert_eq!(dir.base_file(), Path::new("/tmp/elsewhere/hb/base.toml"));
        assert_eq!(
            dir.preset_file(&assert_ok!(PresetName::parse("mine"))),
            Path::new("/tmp/elsewhere/hb/presets/mine.toml")
        );
    }

    #[test]
    fn init_base_creates_a_private_directory_and_file_with_the_template() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        let base = assert_ok!(dir.init_base());
        assert_eq!(base, dir.base_file());
        assert_eq!(assert_ok!(fs::read_to_string(&base)), BASE_TEMPLATE);
        assert_eq!(assert_ok!(fs::metadata(&base)).mode() & 0o777, 0o600);
        assert_eq!(assert_ok!(fs::metadata(dir.dir())).mode() & 0o777, 0o700);
    }

    #[test]
    fn init_base_never_overwrites_an_existing_base() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        assert_ok!(dir.init_base());
        assert_ok!(fs::write(dir.base_file(), b"# my edits\n"));
        let err = assert_err!(dir.init_base());
        assert!(matches!(err, UserConfigError::BaseExists { .. }), "{err:?}");
        assert_eq!(
            assert_ok!(fs::read_to_string(dir.base_file())),
            "# my edits\n"
        );
    }

    #[test]
    fn init_base_refuses_even_when_the_existing_base_is_empty() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        assert_ok!(fs::create_dir_all(dir.dir()));
        assert_ok!(fs::write(dir.base_file(), b""));
        assert!(matches!(
            assert_err!(dir.init_base()),
            UserConfigError::BaseExists { .. }
        ));
    }

    #[test]
    fn the_template_is_valid_config_that_resolves() {
        use crate::config::{ConfigText, ResolveContext, resolve_file};
        use crate::origin::Layer;
        let tree = Tree::new();
        let root = tree.project_root("work/proj");
        let dir = UserConfigDir::locate(tree.home());
        let base = assert_ok!(dir.init_base());
        let text = assert_ok!(ConfigText::read_with(
            &base,
            Layer::UserBase,
            crate::config::SymlinkPolicy::Refuse
        ));
        let resolved = assert_ok!(resolve_file(
            &text,
            &ResolveContext::new(tree.home(), &root)
        ));
        assert_eq!(resolved.config.tls.system_trust, Some(true));
        assert_eq!(resolved.config.env.pass.len(), 2);
        assert!(BASE_TEMPLATE.contains("# launchctl = true"));
        assert!(BASE_TEMPLATE.contains("# internal_hosts ="));
        assert!(resolved.config.net.internal_hosts.is_empty());
        assert_eq!(
            resolved.config.system.launchctl, None,
            "the template must not turn launchctl on"
        );
    }

    #[test]
    fn errors_follow_the_display_convention_and_say_what_to_do() {
        let tree = Tree::new();
        let dir = UserConfigDir::locate(tree.home());
        assert_ok!(dir.init_base());
        let err = assert_err!(dir.init_base());
        assert!(err.to_string().contains("never overwrites"), "{err}");
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
