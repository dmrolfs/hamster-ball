// ABOUTME: FileLocation: where a loaded config file physically is, which decides who could have written it.
// ABOUTME: Pure classification of a canonical path; trust is a property of location, not of how the file was reached.
//! Classifying a config file by where it physically lives.
//!
//! Whether a file may carry hooks, and whether it needs approval, depends on who could have
//! written it, which is a fact about its location, not about the `extends` edge that reached
//! it. Classifying the canonical path (and the link count) means an alias of a trusted file
//! behaves exactly like the file, and DFS order cannot change a security result.

use strum::Display;

use crate::policy::{CanonicalPath, ProjectRoot};

/// Where a config file physically is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Display)]
#[non_exhaustive]
pub enum FileLocation {
    /// Text compiled into `hb`.
    #[strum(to_string = "built into hb")]
    Builtin,
    /// A file under the user's own `~/.config/hamster-ball`, with no other link to its bytes.
    #[strum(to_string = "in ~/.config/hamster-ball")]
    UserConfig,
    /// A file under the project root, which the agent can write.
    #[strum(to_string = "inside the project")]
    InProject,
    /// Anything else: a path outside both, or a user file that is also reachable by another
    /// link. Treated as writable by the ball, and never trusted with user-only sections.
    #[strum(to_string = "outside both the project and ~/.config/hamster-ball")]
    Other,
}

impl FileLocation {
    /// Whether the hamster ball could write this file, so it must be approved and hashed.
    #[must_use]
    pub fn needs_approval(self) -> bool {
        matches!(self, Self::InProject | Self::Other)
    }

    /// Whether this file may define user-only sections (`hooks`, `guard.exceptions`).
    ///
    /// Only the user's own files and built-ins may: those are exactly the files the floor makes
    /// unwritable from inside the ball and that a project cannot supply.
    #[must_use]
    pub fn may_define_user_only_sections(self) -> bool {
        matches!(self, Self::Builtin | Self::UserConfig)
    }
}

/// Classifies a file on disk from its canonical path and link count.
///
/// `InProject` wins over `UserConfig`, so a project placed inside the user's config directory
/// cannot launder its own files into the trusted set. A file with `nlink > 1` is never
/// `UserConfig`: another path names the same bytes, and that path might be one the ball can
/// write.
#[must_use]
pub fn classify(
    canonical: &CanonicalPath,
    nlink: u64,
    project: &ProjectRoot,
    user_config: Option<&CanonicalPath>,
) -> FileLocation {
    if project.path().is_same_or_ancestor_of(canonical) {
        FileLocation::InProject
    } else if nlink == 1 && user_config.is_some_and(|dir| dir.is_same_or_ancestor_of(canonical)) {
        FileLocation::UserConfig
    } else {
        FileLocation::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    fn path(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    fn root(p: &str) -> ProjectRoot {
        let home = crate::policy::HomeDir::new(path("/Users/me"));
        assert_ok!(ProjectRoot::new(path(p), &home))
    }

    const USER_DIR: &str = "/Users/me/.config/hamster-ball";

    fn classify_in(file: &str, nlink: u64, project: &str) -> FileLocation {
        classify(&path(file), nlink, &root(project), Some(&path(USER_DIR)))
    }

    #[test]
    fn a_file_under_the_project_root_is_in_project() {
        assert_eq!(
            classify_in(
                "/Users/me/work/app/hamster-ball.toml",
                1,
                "/Users/me/work/app"
            ),
            FileLocation::InProject
        );
        assert_eq!(
            classify_in("/Users/me/work/app/presets/x.toml", 1, "/Users/me/work/app"),
            FileLocation::InProject
        );
    }

    #[test]
    fn a_file_under_the_user_config_dir_is_user_config() {
        assert_eq!(
            classify_in(&format!("{USER_DIR}/base.toml"), 1, "/Users/me/work/app"),
            FileLocation::UserConfig
        );
        assert_eq!(
            classify_in(
                &format!("{USER_DIR}/presets/agent/kiro.toml"),
                1,
                "/Users/me/work/app"
            ),
            FileLocation::UserConfig
        );
    }

    #[test]
    fn a_file_elsewhere_is_other() {
        for file in [
            "/tmp/x.toml",
            "/Users/me/dotfiles/x.toml",
            "/opt/shared/x.toml",
        ] {
            assert_eq!(
                classify_in(file, 1, "/Users/me/work/app"),
                FileLocation::Other,
                "{file}"
            );
        }
    }

    #[test]
    fn a_user_file_with_another_hard_link_is_never_user_config() {
        assert_eq!(
            classify_in(&format!("{USER_DIR}/base.toml"), 2, "/Users/me/work/app"),
            FileLocation::Other
        );
    }

    #[test]
    fn in_project_wins_when_the_project_sits_inside_the_user_config_dir() {
        let project = format!("{USER_DIR}/projects/app");
        assert_eq!(
            classify_in(&format!("{project}/hamster-ball.toml"), 1, &project),
            FileLocation::InProject
        );
    }

    #[test]
    fn location_is_decided_by_path_components_not_string_prefixes() {
        assert_eq!(
            classify_in("/Users/me/work/app2/x.toml", 1, "/Users/me/work/app"),
            FileLocation::Other
        );
        assert_eq!(
            classify_in(
                "/Users/me/.config/hamster-ball2/x.toml",
                1,
                "/Users/me/work/app"
            ),
            FileLocation::Other
        );
    }

    #[test]
    fn with_no_user_config_dir_nothing_is_user_config() {
        let location = classify(
            &path(&format!("{USER_DIR}/base.toml")),
            1,
            &root("/Users/me/work/app"),
            None,
        );
        assert_eq!(location, FileLocation::Other);
    }

    #[test]
    fn locations_display_as_phrases_for_error_messages() {
        assert_eq!(FileLocation::InProject.to_string(), "inside the project");
        assert_eq!(
            FileLocation::UserConfig.to_string(),
            "in ~/.config/hamster-ball"
        );
        assert_eq!(FileLocation::Builtin.to_string(), "built into hb");
        assert_eq!(
            FileLocation::Other.to_string(),
            "outside both the project and ~/.config/hamster-ball"
        );
    }

    #[test]
    fn only_in_project_and_other_need_approval() {
        assert!(FileLocation::InProject.needs_approval());
        assert!(FileLocation::Other.needs_approval());
        assert!(!FileLocation::UserConfig.needs_approval());
        assert!(!FileLocation::Builtin.needs_approval());
    }

    #[test]
    fn only_builtin_and_user_config_may_define_user_only_sections() {
        assert!(FileLocation::Builtin.may_define_user_only_sections());
        assert!(FileLocation::UserConfig.may_define_user_only_sections());
        assert!(!FileLocation::InProject.may_define_user_only_sections());
        assert!(!FileLocation::Other.may_define_user_only_sections());
    }
}
