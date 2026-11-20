// ABOUTME: load_project: discover the project from the environment's cwd, then load its closure, floor and policy.
// ABOUTME: The one entry point `hb explain`, `hb profile` and `hb run` share, so they cannot load differently.
//! Loading the project the process is standing in.

use snafu::{ResultExt, Snafu};

use super::{DiscoverError, Discovery, LoadError, LoadRequest, Loaded, discover, load};
use crate::system::{Environment, UserConfigDir};

/// Why the project could not be loaded.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ProjectError {
    /// No usable project was found from the current directory.
    #[snafu(display("no usable project here"))]
    Discover {
        /// The underlying error.
        source: DiscoverError,
    },

    /// The config could not be loaded.
    #[snafu(display("the config could not be loaded"))]
    Load {
        /// The underlying error.
        source: LoadError,
    },
}

/// Discovers the project from `env.cwd` and loads it with the presets compiled into this build.
///
/// # Errors
/// [`ProjectError`] if there is no project, or its config cannot be loaded.
pub fn load_project(env: &Environment) -> Result<(Discovery, Loaded), ProjectError> {
    let discovery = discover(&env.cwd, &env.home).context(DiscoverSnafu)?;
    let user_config = UserConfigDir::locate(&env.home);
    let loaded = load(&LoadRequest::new(
        &env.home,
        &discovery,
        &user_config,
        &env.floor,
    ))
    .context(LoadSnafu)?;
    Ok((discovery, loaded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Tree, canonical};
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::fs;

    fn world() -> (Tree, Environment) {
        let tree = Tree::new();
        let project = tree.inside_home("work/proj");
        let config_dir = tree.inside_home(".config/hamster-ball");
        assert_ok!(fs::write(config_dir.join("base.toml"), ""));
        assert_ok!(fs::write(
            project.join("hamster-ball.toml"),
            "[fs]\nwrite = [\".\"]\n"
        ));
        let env = Environment::new(canonical(&project).as_path(), tree.home().clone());
        (tree, env)
    }

    #[test]
    fn a_project_loads_with_its_discovery_and_policy() {
        let (_tree, env) = world();
        let (discovery, loaded) = assert_ok!(load_project(&env));
        assert_eq!(discovery.root.path().as_path(), env.cwd.as_path());
        assert_eq!(loaded.policy.fs.write.len(), 1);
    }

    #[test]
    fn no_project_is_a_discover_error_and_a_bad_config_is_a_load_error() {
        let (tree, env) = world();
        let mut elsewhere = env.clone();
        elsewhere.cwd = tree.outside("nowhere");
        assert!(matches!(
            assert_err!(load_project(&elsewhere)),
            ProjectError::Discover { .. }
        ));
        let config = env.cwd.join("hamster-ball.toml");
        assert_ok!(fs::write(config, "[fs]\nbogus = 1\n"));
        let err = assert_err!(load_project(&env));
        assert!(matches!(err, ProjectError::Load { .. }), "{err:?}");
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
