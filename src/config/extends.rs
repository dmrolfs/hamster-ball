// ABOUTME: Turns one `extends` entry into the node to load: a built-in preset or a file with a role.
// ABOUTME: Pure apart from one existence check on the user's presets directory; reading is config::closure.
//! Resolving an `extends` entry to something loadable.
//!
//! Rules (each is tested):
//! - An entry starting `/`, `~/`, `./` or `../` is a **path**; anything else is a preset
//!   **name** (see [`ExtendRef::target`]).
//! - A relative path resolves against the directory of the file that contains the `extends`,
//!   so a preset's own relative references keep working wherever it lives. (Decision D22 scopes
//!   "relative to the project root" to filesystem grants only.)
//! - A name is looked up among the built-ins and the user's presets directory. A name found in
//!   both is an error naming both, so a new built-in cannot silently change what a name means.
//! - A built-in may extend only other built-ins, so no user or project file can be pulled into
//!   text that ships inside `hb`.
//! - A missing target is always an error, never a skip: a skipped preset could silently drop
//!   its denies.

use std::fs;
use std::path::{Path, PathBuf};

use snafu::{ResultExt, Snafu};

use super::builtin::BuiltinPresets;
use super::text::FileRole;
use crate::policy::{ExtendRef, ExtendTarget, ExtendTargetError, HomeDir, PresetName};
use crate::sys::path_preview;
use crate::system::UserConfigDir;

/// Why an `extends` entry could not be turned into something to load.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ExtendsError {
    /// The entry is neither a path nor a valid preset name.
    #[snafu(display("`extends` entry is not valid"))]
    InvalidTarget {
        /// Why.
        source: ExtendTargetError,
    },

    /// No built-in preset and no user preset has this name.
    #[snafu(display("no preset named `{name}`; looked in {}", searched.join(" and ")))]
    UnknownPreset {
        /// The name.
        name: PresetName,
        /// Where it was looked for, for the message.
        searched: Vec<String>,
    },

    /// The name is both a built-in preset and a file in the user's presets directory.
    #[snafu(display(
        "preset `{name}` is both a built-in preset and a file at {}; rename your file, or extend it by path",
        path_preview(user_file)
    ))]
    NameCollision {
        /// The name.
        name: PresetName,
        /// The user's file with the same name.
        user_file: PathBuf,
    },

    /// A built-in preset names a file, which a built-in may not do.
    #[snafu(display("built-in preset extends a file, which built-ins may not do: {entry}"))]
    BuiltinExtendsFile {
        /// The offending entry.
        entry: ExtendRef,
    },
}

/// What an `extends` entry resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    /// A preset compiled into `hb`.
    Builtin(PresetName),
    /// A file to read, in the given role.
    Disk {
        /// The path to open (not yet canonical).
        path: PathBuf,
        /// How it was reached.
        role: FileRole,
    },
}

/// The file an `extends` entry appears in.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Containing<'a> {
    /// Text built into `hb`.
    Builtin,
    /// A file on disk whose directory is `dir` (its canonical directory).
    Disk(&'a Path),
}

/// Resolves `extends` entries.
pub(crate) struct Extends<'a> {
    home: &'a HomeDir,
    user_config: &'a UserConfigDir,
    builtins: &'a dyn BuiltinPresets,
}

impl<'a> Extends<'a> {
    pub(crate) fn new(
        home: &'a HomeDir,
        user_config: &'a UserConfigDir,
        builtins: &'a dyn BuiltinPresets,
    ) -> Self {
        Self {
            home,
            user_config,
            builtins,
        }
    }

    /// Resolves `entry`, found in `containing`.
    pub(crate) fn node(
        &self,
        entry: &ExtendRef,
        containing: Containing<'_>,
    ) -> Result<Node, ExtendsError> {
        match entry.target().context(InvalidTargetSnafu)? {
            ExtendTarget::Name(name) => self.named(name, containing),
            ExtendTarget::Path(spelling) => self.path(entry, &spelling, containing),
        }
    }

    fn named(&self, name: PresetName, containing: Containing<'_>) -> Result<Node, ExtendsError> {
        let built_in = self.builtins.get(&name).is_some();
        if matches!(containing, Containing::Builtin) {
            return if built_in {
                Ok(Node::Builtin(name))
            } else {
                UnknownPresetSnafu {
                    name,
                    searched: vec!["the built-in presets".to_owned()],
                }
                .fail()
            };
        }
        let user_file = self.user_config.preset_file(&name);
        // `symlink_metadata`: a dangling link is a user file that fails to load with a clear
        // error, not a name that quietly resolves to something else.
        let user_present = fs::symlink_metadata(&user_file).is_ok();
        match (built_in, user_present) {
            (true, true) => NameCollisionSnafu { name, user_file }.fail(),
            (true, false) => Ok(Node::Builtin(name)),
            (false, true) => Ok(Node::Disk {
                path: user_file,
                role: FileRole::UserPresetByName,
            }),
            (false, false) => UnknownPresetSnafu {
                searched: vec![
                    "the built-in presets".to_owned(),
                    path_preview(&user_file).to_string(),
                ],
                name,
            }
            .fail(),
        }
    }

    fn path(
        &self,
        entry: &ExtendRef,
        spelling: &str,
        containing: Containing<'_>,
    ) -> Result<Node, ExtendsError> {
        let Containing::Disk(dir) = containing else {
            return BuiltinExtendsFileSnafu {
                entry: entry.clone(),
            }
            .fail();
        };
        let path = if let Some(rest) = spelling.strip_prefix("~/") {
            self.home.path().as_path().join(rest)
        } else if spelling.starts_with('/') {
            PathBuf::from(spelling)
        } else {
            dir.join(spelling)
        };
        Ok(Node::Disk {
            path,
            role: FileRole::ReferencedByPath,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::StaticPresets;
    use crate::policy::ExtendRef;
    use crate::system::UserConfigDir;
    use crate::testutil::Tree;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::fs;

    struct World {
        tree: Tree,
        user: UserConfigDir,
    }

    impl World {
        fn new() -> Self {
            let tree = Tree::new();
            let user = UserConfigDir::locate(tree.home());
            Self { tree, user }
        }

        fn user_preset(&self, name: &str, text: &str) -> std::path::PathBuf {
            let name = assert_ok!(PresetName::parse(name));
            let path = self.user.preset_file(&name);
            assert_ok!(fs::create_dir_all(assert_ok!(
                path.parent().ok_or("no parent")
            )));
            assert_ok!(fs::write(&path, text));
            path
        }
    }

    fn entry(text: &str) -> ExtendRef {
        assert_ok!(ExtendRef::parse(text))
    }

    const BUILTINS: StaticPresets<'static> =
        StaticPresets(&[("rust", "# built-in rust\n"), ("git", "")]);

    fn resolver<'a>(w: &'a World) -> Extends<'a> {
        Extends::new(w.tree.home(), &w.user, &BUILTINS)
    }

    #[test]
    fn a_name_that_is_only_built_in_resolves_to_the_builtin() {
        let w = World::new();
        let node = assert_ok!(resolver(&w).node(&entry("rust"), Containing::Disk(w.tree.base())));
        assert_eq!(node, Node::Builtin(assert_ok!(PresetName::parse("rust"))));
    }

    #[test]
    fn a_name_that_is_only_a_user_preset_resolves_to_the_user_file_with_the_by_name_role() {
        let w = World::new();
        let file = w.user_preset("mine", "x = 1\n");
        let node = assert_ok!(resolver(&w).node(&entry("mine"), Containing::Disk(w.tree.base())));
        assert_eq!(
            node,
            Node::Disk {
                path: file,
                role: FileRole::UserPresetByName
            }
        );
    }

    #[test]
    fn a_nested_user_preset_name_maps_to_a_nested_file() {
        let w = World::new();
        let file = w.user_preset("agent/mine", "");
        let node =
            assert_ok!(resolver(&w).node(&entry("agent/mine"), Containing::Disk(w.tree.base())));
        assert_eq!(
            node,
            Node::Disk {
                path: file,
                role: FileRole::UserPresetByName
            }
        );
    }

    #[test]
    fn a_name_that_is_both_built_in_and_a_user_preset_is_an_error_naming_both() {
        let w = World::new();
        let file = w.user_preset("rust", "");
        let err = assert_err!(resolver(&w).node(&entry("rust"), Containing::Disk(w.tree.base())));
        assert!(
            matches!(&err, ExtendsError::NameCollision { user_file, .. } if *user_file == file),
            "{err:?}"
        );
        let shown = err.to_string();
        assert!(
            shown.contains("built-in") && shown.contains("rust.toml"),
            "{shown:?}"
        );
    }

    #[test]
    fn an_unknown_name_lists_where_it_was_looked_for() {
        let w = World::new();
        let err = assert_err!(resolver(&w).node(&entry("nope"), Containing::Disk(w.tree.base())));
        let ExtendsError::UnknownPreset { searched, .. } = &err else {
            assert_ok!(Err::<(), _>(format!("expected UnknownPreset, got {err:?}")));
            return;
        };
        assert_eq!(searched.len(), 2);
        assert!(err.to_string().contains("nope.toml"), "{err}");
    }

    #[test]
    fn a_broken_user_preset_symlink_still_counts_as_present_rather_than_as_unknown() {
        // `symlink_metadata`, not `metadata`: a dangling link is a user file that fails to load
        // with a clear error, not a name that silently resolves to something else.
        let w = World::new();
        let name = assert_ok!(PresetName::parse("dangling"));
        let path = w.user.preset_file(&name);
        assert_ok!(fs::create_dir_all(assert_ok!(
            path.parent().ok_or("no parent")
        )));
        assert_ok!(std::os::unix::fs::symlink("/nonexistent/target", &path));
        let node =
            assert_ok!(resolver(&w).node(&entry("dangling"), Containing::Disk(w.tree.base())));
        assert!(matches!(node, Node::Disk { .. }), "{node:?}");
    }

    #[test]
    fn an_absolute_path_is_a_referenced_by_path_file() {
        let w = World::new();
        let node =
            assert_ok!(resolver(&w).node(&entry("/opt/x/y.toml"), Containing::Disk(w.tree.base())));
        assert_eq!(
            node,
            Node::Disk {
                path: "/opt/x/y.toml".into(),
                role: FileRole::ReferencedByPath
            }
        );
    }

    #[test]
    fn tilde_slash_expands_against_the_passwd_home() {
        let w = World::new();
        let node =
            assert_ok!(resolver(&w).node(&entry("~/p/x.toml"), Containing::Disk(w.tree.base())));
        assert_eq!(
            node,
            Node::Disk {
                path: w.tree.home_path().join("p/x.toml"),
                role: FileRole::ReferencedByPath
            }
        );
    }

    #[test]
    fn relative_paths_resolve_against_the_directory_of_the_containing_file() {
        let w = World::new();
        let dir = w.tree.outside("proj/sub");
        let node = assert_ok!(resolver(&w).node(&entry("./x.toml"), Containing::Disk(&dir)));
        assert_eq!(
            node,
            Node::Disk {
                path: dir.join("./x.toml"),
                role: FileRole::ReferencedByPath
            }
        );
        let node = assert_ok!(resolver(&w).node(&entry("../y.toml"), Containing::Disk(&dir)));
        assert_eq!(
            node,
            Node::Disk {
                path: dir.join("../y.toml"),
                role: FileRole::ReferencedByPath
            }
        );
    }

    #[test]
    fn a_builtin_may_extend_only_other_builtins() {
        let w = World::new();
        w.user_preset("mine", "");
        assert_ok!(resolver(&w).node(&entry("git"), Containing::Builtin));
        for bad in ["/opt/x.toml", "~/x.toml", "./x.toml", "../x.toml"] {
            let err = assert_err!(resolver(&w).node(&entry(bad), Containing::Builtin), "{bad}");
            assert!(
                matches!(err, ExtendsError::BuiltinExtendsFile { .. }),
                "{bad}: {err:?}"
            );
        }
        // A user preset name is not visible from a built-in.
        let err = assert_err!(resolver(&w).node(&entry("mine"), Containing::Builtin));
        assert!(matches!(err, ExtendsError::UnknownPreset { .. }), "{err:?}");
    }

    #[test]
    fn an_invalid_entry_is_reported_with_the_classifier_error() {
        let w = World::new();
        let err =
            assert_err!(resolver(&w).node(&entry("Foo.toml"), Containing::Disk(w.tree.base())));
        assert!(matches!(err, ExtendsError::InvalidTarget { .. }), "{err:?}");
        let err =
            assert_err!(resolver(&w).node(&entry("~root/x"), Containing::Disk(w.tree.base())));
        assert!(matches!(err, ExtendsError::InvalidTarget { .. }), "{err:?}");
    }

    #[test]
    fn errors_follow_the_display_convention() {
        let w = World::new();
        w.user_preset("rust", "");
        for text in ["rust", "nope", "Foo.toml"] {
            let err = assert_err!(resolver(&w).node(&entry(text), Containing::Disk(w.tree.base())));
            crate::error::conventions::assert_display_excludes_sources(&err);
        }
    }
}
