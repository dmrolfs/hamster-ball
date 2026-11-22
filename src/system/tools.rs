// ABOUTME: Finds the directories of `[env] tools` programs on the invoking shell's PATH (design 7.2, D59).
// ABOUTME: Reads the filesystem, so it lives here and not in the pure config resolve.
//! `[env] tools`: which directory each named program lives in.

use std::ffi::OsStr;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use snafu::{ResultExt, Snafu};

use crate::policy::{CanonicalPath, PathVarError, ToolName, parse_path_var};

/// Why the tools could not be looked up at all.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum ToolsError {
    /// The invoking shell's `PATH` is too large to use.
    #[snafu(display("the PATH of your shell cannot be used to find tools"))]
    PathVar {
        /// The underlying error.
        source: PathVarError,
    },
}

/// A tool found on `PATH`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundTool {
    /// The program name from `[env] tools`.
    pub name: ToolName,
    /// The canonical directory that holds it.
    pub dir: CanonicalPath,
}

/// The outcome of looking up every tool.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolLookup {
    /// Tools that were found, in the order they were asked for.
    pub found: Vec<FoundTool>,
    /// Tools that were not on `PATH`: a warning, like a skipped allow rule.
    pub missing: Vec<ToolName>,
}

impl ToolLookup {
    /// The distinct directories of the found tools, in first-found order.
    #[must_use]
    pub fn dirs(&self) -> Vec<CanonicalPath> {
        let mut dirs: Vec<CanonicalPath> = Vec::new();
        for tool in &self.found {
            if !dirs.contains(&tool.dir) {
                dirs.push(tool.dir.clone());
            }
        }
        dirs
    }
}

/// Looks each of `names` up in `path_var`, the invoking shell's `PATH`.
///
/// A tool is the first regular file with an execute bit, named exactly so, in an absolute
/// `PATH` entry; a symlink to one counts. The directory is canonicalized, because Seatbelt
/// matches resolved paths.
///
/// # Errors
/// [`ToolsError::PathVar`] if `path_var` is too large to parse.
pub fn find_tools(names: &[ToolName], path_var: Option<&OsStr>) -> Result<ToolLookup, ToolsError> {
    let dirs = match path_var {
        Some(raw) => parse_path_var(raw).context(PathVarSnafu)?.accepted,
        None => Vec::new(),
    };
    let mut lookup = ToolLookup::default();
    for name in names {
        match dirs.iter().find_map(|dir| locate(Path::new(dir), name)) {
            Some(dir) => lookup.found.push(FoundTool {
                name: name.clone(),
                dir,
            }),
            None => lookup.missing.push(name.clone()),
        }
    }
    Ok(lookup)
}

/// The canonical directory `dir` if it holds an executable file called `name`.
fn locate(dir: &Path, name: &ToolName) -> Option<CanonicalPath> {
    let candidate: PathBuf = dir.join(name.as_str());
    let meta = fs::metadata(&candidate).ok()?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return None;
    }
    let canonical = fs::canonicalize(dir).ok()?;
    CanonicalPath::from_canonical(canonical).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;
    use std::ffi::OsString;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn tool(name: &str) -> ToolName {
        assert_ok!(ToolName::parse(name))
    }

    /// A canonical temp root, so expected paths match what `find_tools` returns.
    fn root() -> (TempDir, PathBuf) {
        let dir = assert_ok!(TempDir::new());
        let real = assert_ok!(fs::canonicalize(dir.path()));
        (dir, real)
    }

    fn make(dir: &Path, name: &str, mode: u32) {
        assert_ok!(fs::create_dir_all(dir));
        let file = dir.join(name);
        assert_ok!(fs::write(&file, "#!/bin/sh\n"));
        assert_ok!(fs::set_permissions(&file, fs::Permissions::from_mode(mode)));
    }

    fn path_of(dirs: &[&Path]) -> OsString {
        let parts: Vec<&str> = dirs.iter().filter_map(|d| d.to_str()).collect();
        OsString::from(parts.join(":"))
    }

    fn lookup(names: &[&str], path: &OsString) -> ToolLookup {
        let names: Vec<ToolName> = names.iter().map(|n| tool(n)).collect();
        assert_ok!(find_tools(&names, Some(path.as_os_str())))
    }

    #[test]
    fn a_tool_is_found_in_the_first_path_directory_that_has_it() {
        let (_guard, root) = root();
        let (a, b) = (root.join("a"), root.join("b"));
        make(&a, "node", 0o755);
        make(&b, "node", 0o755);
        make(&b, "npx", 0o755);
        let found = lookup(&["node", "npx"], &path_of(&[&a, &b]));
        assert_eq!(found.found[0].dir.as_path(), a.as_path());
        assert_eq!(found.found[1].dir.as_path(), b.as_path());
        assert!(found.missing.is_empty());
    }

    #[test]
    fn a_file_without_an_execute_bit_or_a_directory_of_that_name_is_not_a_tool() {
        let (_guard, root) = root();
        let (a, b) = (root.join("a"), root.join("b"));
        make(&a, "node", 0o644);
        assert_ok!(fs::create_dir_all(a.join("npx")));
        make(&b, "node", 0o755);
        let found = lookup(&["node", "npx"], &path_of(&[&a, &b]));
        assert_eq!(found.found.len(), 1);
        assert_eq!(found.found[0].dir.as_path(), b.as_path());
        assert_eq!(found.missing, vec![tool("npx")]);
    }

    #[test]
    fn a_symlink_to_an_executable_counts_and_a_dangling_one_does_not() {
        let (_guard, root) = root();
        let (real, bin) = (root.join("real"), root.join("bin"));
        make(&real, "node", 0o755);
        assert_ok!(fs::create_dir_all(&bin));
        assert_ok!(symlink(real.join("node"), bin.join("node")));
        assert_ok!(symlink(root.join("gone"), bin.join("ghost")));
        let found = lookup(&["node", "ghost"], &path_of(&[&bin]));
        assert_eq!(found.found[0].dir.as_path(), bin.as_path());
        assert_eq!(found.missing, vec![tool("ghost")]);
    }

    #[test]
    fn a_symlinked_path_directory_is_reported_as_its_real_directory() {
        let (_guard, root) = root();
        let real = root.join("real");
        make(&real, "node", 0o755);
        let link = root.join("link");
        assert_ok!(symlink(&real, &link));
        let found = lookup(&["node"], &path_of(&[&link]));
        assert_eq!(found.found[0].dir.as_path(), real.as_path());
    }

    #[test]
    fn relative_and_empty_path_entries_are_never_searched() {
        let (_guard, root) = root();
        make(&root.join("rel"), "node", 0o755);
        let path = OsString::from(format!(":.:rel:{}/nowhere", root.display()));
        let found = lookup(&["node"], &path);
        assert!(found.found.is_empty());
    }

    #[test]
    fn dirs_are_distinct_and_in_the_order_the_tools_were_asked_for() {
        let (_guard, root) = root();
        let (a, b) = (root.join("a"), root.join("b"));
        make(&a, "node", 0o755);
        make(&a, "npx", 0o755);
        make(&b, "uvx", 0o755);
        let found = lookup(&["uvx", "node", "npx"], &path_of(&[&a, &b]));
        let texts: Vec<String> = found.dirs().iter().map(|d| d.as_str().to_owned()).collect();
        assert_eq!(
            texts,
            vec![b.display().to_string(), a.display().to_string()]
        );
    }

    #[test]
    fn no_path_means_every_tool_is_missing() {
        let names = vec![tool("node")];
        let found = assert_ok!(find_tools(&names, None));
        assert_eq!(found.missing, names);
        assert!(found.found.is_empty());
    }

    #[test]
    fn an_oversized_path_is_an_error_that_does_not_echo_it() {
        let huge = OsString::from("/a:".repeat(crate::policy::MAX_PATH_VAR_BYTES));
        let err = assert_err!(find_tools(&[tool("node")], Some(huge.as_os_str())));
        crate::error::conventions::assert_display_excludes_sources(&err);
    }
}
