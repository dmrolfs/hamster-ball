// ABOUTME: PathResolver turns a config spelling into filesystem-checked CanonicalPath values; the crate's only I/O.
// ABOUTME: Also PathPattern/GlobTail for fs.deny_read/fs.deny_write globs, whose base is resolved the same way.
//! Resolves config path spellings against the real filesystem.
//!
//! Every other type in [`super`] is a pure form check with no I/O. This module is the
//! exception: it is where `~` and relative spellings are expanded, and where the result is
//! checked against what actually exists, because Seatbelt will later compare against the
//! filesystem's own resolved form, not the text a user wrote (a rule on `/tmp/...` silently
//! does nothing on macOS, because `/tmp` is a symlink to `/private/tmp`).

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};

use snafu::{Snafu, ensure};
use strum::{Display, IntoStaticStr};

use super::home::{HomeDir, ProjectRoot, broadness};
use super::path::{CanonicalPath, DotDotInTailSnafu, PathError};

/// Why an allow rule's path was skipped instead of granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Display, IntoStaticStr)]
pub enum SkipReason {
    /// Nothing exists at the path.
    Missing,
    /// The path, or an ancestor of it, is a symlink whose target does not exist.
    Dangling,
}

/// An allow rule's path, when it was not granted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedPath {
    /// The spelling as written in the config.
    pub spelling: String,
    /// The spelling after `~` and relative expansion, before any filesystem check.
    pub expanded: PathBuf,
    /// Why it was skipped.
    pub reason: SkipReason,
}

/// The result of resolving an `fs.read` or `fs.write` allow rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AllowOutcome {
    /// The path exists, is not too broad, and is granted.
    Granted(CanonicalPath),
    /// The path was not granted; see [`SkippedPath::reason`].
    Skipped(SkippedPath),
}

/// The result of resolving an `fs.deny_read` or `fs.deny_write` rule.
///
/// `target` is kept even if it does not exist yet, so a deny rule still covers a path an
/// agent creates later. `alias` is set only when the rule's final component (after
/// expansion) is itself an existing symlink: `target` is what it points to, `alias` is the
/// symlink's own location, so both the link and what it resolves to are covered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyResolution {
    /// What the rule covers: the deepest resolved ancestor plus any tail that does not yet exist.
    pub target: CanonicalPath,
    /// The symlink's own path, when `target` was reached by following one.
    pub alias: Option<CanonicalPath>,
}

/// Resolves config path spellings against the real filesystem.
///
/// Holds the two values every spelling needs to be interpreted: the home directory (for `~`)
/// and the project root (relative spellings resolve against it, in every config layer).
#[derive(Debug, Clone, Copy)]
pub struct PathResolver<'a> {
    home: &'a HomeDir,
    project_root: &'a ProjectRoot,
}

/// What the shared walk found, before `allow`/`deny` interpret it.
enum Resolution {
    /// The spelling's final component, after expansion, is an existing symlink.
    LeafSymlink { target: PathBuf, alias: PathBuf },
    /// The deepest ancestor that exists, plus the components (if any) that do not.
    Resolved {
        ancestor: PathBuf,
        tail: Vec<String>,
    },
    /// A symlink with no live target, found at the leaf or partway up the walk.
    Dangling,
}

impl<'a> PathResolver<'a> {
    /// Resolves spellings against `home` and `project_root`.
    #[must_use]
    pub fn new(home: &'a HomeDir, project_root: &'a ProjectRoot) -> Self {
        Self { home, project_root }
    }

    /// Resolves an `fs.read` or `fs.write` allow rule.
    ///
    /// A missing or dangling path is skipped, not an error: the safe direction for an allow
    /// rule is to grant nothing. A permission error is an error, because silently granting
    /// less than the config asked for is not obviously safe, and should be visible.
    ///
    /// # Errors
    /// [`PathError::TooBroad`] if the resolved path is `/`, `$HOME`, an ancestor of `$HOME`,
    /// or shallower than two components. Otherwise see [`PathError`] for malformed input or
    /// an I/O error other than "missing" or "dangling".
    pub fn allow(&self, spelling: &str) -> Result<AllowOutcome, PathError> {
        let expanded = self.expand(spelling)?;
        let is_relative = !spelling.starts_with('/') && !spelling.starts_with('~');
        match resolve(&expanded, Mode::Allow)? {
            Resolution::LeafSymlink { target, .. } => Ok(AllowOutcome::Granted(self.grant(
                spelling,
                target,
                is_relative,
            )?)),
            Resolution::Resolved { ancestor, tail } if tail.is_empty() => Ok(
                AllowOutcome::Granted(self.grant(spelling, ancestor, is_relative)?),
            ),
            Resolution::Resolved {
                ancestor: _,
                tail: _,
            } => Ok(AllowOutcome::Skipped(SkippedPath {
                spelling: spelling.to_owned(),
                expanded,
                reason: SkipReason::Missing,
            })),
            Resolution::Dangling => Ok(AllowOutcome::Skipped(SkippedPath {
                spelling: spelling.to_owned(),
                expanded,
                reason: SkipReason::Dangling,
            })),
        }
    }

    /// Checks the breadth and project-containment of a granted path and wraps it.
    ///
    /// A relative spelling means "inside this project" (decision D22), so once the walk
    /// resolves it -- following any symlink on the way -- the result must still be inside
    /// the project root. An absolute or `~`-based spelling carries no such restriction: a
    /// preset legitimately reads something like `~/.cargo/registry`.
    fn grant(
        &self,
        spelling: &str,
        path: PathBuf,
        is_relative: bool,
    ) -> Result<CanonicalPath, PathError> {
        let canonical = CanonicalPath::from_canonical(path)?;
        if is_relative && !self.project_root.path().is_same_or_ancestor_of(&canonical) {
            return Err(PathError::RelativeEscapesProject {
                spelling: spelling.to_owned(),
                resolved: canonical,
                project_root: self.project_root.path().clone(),
            });
        }
        match broadness(&canonical, self.home) {
            Some(reason) => Err(PathError::TooBroad {
                path: canonical,
                reason,
            }),
            None => Ok(canonical),
        }
    }

    /// Resolves an `fs.deny_read` or `fs.deny_write` rule.
    ///
    /// A missing path is kept: the deepest resolvable ancestor, plus the tail that does not
    /// exist yet, so the rule still applies once something is created there. A dangling
    /// symlink is an error, not something to fall through past, because the rule's whole
    /// point is to keep covering something regardless of what an agent does to the path.
    ///
    /// # Errors
    /// See [`PathError`]. There is no breadth check for a deny rule.
    pub fn deny(&self, spelling: &str) -> Result<DenyResolution, PathError> {
        let expanded = self.expand(spelling)?;
        match resolve(&expanded, Mode::Deny)? {
            Resolution::LeafSymlink { target, alias } => Ok(DenyResolution {
                target: CanonicalPath::from_canonical(target)?,
                alias: Some(CanonicalPath::from_canonical(alias)?),
            }),
            Resolution::Resolved { ancestor, tail } => {
                let mut full = ancestor;
                for component in tail {
                    full.push(component);
                }
                Ok(DenyResolution {
                    target: CanonicalPath::from_canonical(full)?,
                    alias: None,
                })
            }
            Resolution::Dangling => Err(PathError::Dangling {
                spelling: spelling.to_owned(),
            }),
        }
    }

    /// Resolves a path that must already exist, such as `tls.extra_ca_files`.
    ///
    /// Unlike `allow`, a missing path is always an error, so there is no need to walk past it
    /// looking for the deepest ancestor: the first failure is the answer.
    ///
    /// # Errors
    /// [`PathError::Missing`], [`PathError::Dangling`], or another [`PathError`] variant for
    /// a permission error, a symlink loop, or a non-directory ancestor.
    pub fn existing(&self, spelling: &str) -> Result<CanonicalPath, PathError> {
        let expanded = self.expand(spelling)?;
        match fs::symlink_metadata(&expanded) {
            Ok(meta) if meta.is_symlink() => match fs::canonicalize(&expanded) {
                Ok(target) => CanonicalPath::from_canonical(target),
                Err(_) => Err(PathError::Dangling {
                    spelling: spelling.to_owned(),
                }),
            },
            _ => match fs::canonicalize(&expanded) {
                Ok(target) => CanonicalPath::from_canonical(target),
                Err(error) if error.kind() == ErrorKind::NotFound => Err(PathError::Missing {
                    spelling: spelling.to_owned(),
                }),
                Err(error) => Err(classify_other(error, spelling)),
            },
        }
    }

    /// Expands `~`, `~/...` and a relative spelling, and rejects malformed input before any
    /// filesystem call. `.` segments are dropped; `..` is left untouched here (the walk
    /// decides whether it resolves through an existing prefix or ends up in a missing tail).
    ///
    /// This is the only place `~` is substituted; nothing downstream re-detects or re-expands
    /// it, so there is no risk of expanding twice.
    fn expand(&self, spelling: &str) -> Result<PathBuf, PathError> {
        ensure!(!spelling.is_empty(), super::path::EmptySpellingSnafu);
        ensure!(
            spelling.len() <= super::path::MAX_PATH_BYTES,
            super::path::SpellingTooLongSnafu {
                len: spelling.len()
            }
        );
        ensure!(
            !spelling.chars().any(char::is_control),
            super::path::SpellingControlCharacterSnafu { spelling }
        );

        let full = if spelling == "~" {
            self.home.path().as_str().to_owned()
        } else if let Some(rest) = spelling.strip_prefix("~/") {
            format!("{}/{rest}", self.home.path().as_str())
        } else if spelling.starts_with('~') {
            return super::path::TildeUserSnafu { spelling }.fail();
        } else if spelling.starts_with('/') {
            spelling.to_owned()
        } else {
            format!("{}/{spelling}", self.project_root.path().as_str())
        };

        let cleaned = full
            .split('/')
            .filter(|segment| *segment != ".")
            .collect::<Vec<_>>()
            .join("/");
        Ok(PathBuf::from(cleaned))
    }
}

/// Which rule flavor is being resolved; only `PermissionDenied` behaves differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Allow,
    Deny,
}

/// The shared walk: canonicalize `full`, or find the deepest ancestor that does, popping
/// unresolved components into a tail. `symlink_metadata` on the remaining candidate is the
/// only way to tell a plain `NotFound` from a dangling symlink, because the OS reports both
/// of those as `NotFound` from `canonicalize`.
fn resolve(full: &Path, mode: Mode) -> Result<Resolution, PathError> {
    let spelling = full.to_string_lossy().into_owned();

    match fs::symlink_metadata(full) {
        Ok(meta) if meta.is_symlink() => {
            return match fs::canonicalize(full) {
                Ok(target) => {
                    let name = full.file_name().unwrap_or_default();
                    let parent = fs::canonicalize(full.parent().unwrap_or(Path::new("/")))
                        .map_err(|error| classify_other(error, &spelling))?;
                    Ok(Resolution::LeafSymlink {
                        target,
                        alias: parent.join(name),
                    })
                }
                Err(error) if is_symlink_loop(&error) => Err(PathError::SymlinkLoop { spelling }),
                Err(_) => Ok(Resolution::Dangling),
            };
        }
        Ok(_) => {} // exists, not a symlink: the walk below resolves it in one step.
        Err(error) if error.kind() == ErrorKind::NotFound => {} // fall through to the walk.
        Err(error) if error.kind() == ErrorKind::PermissionDenied && mode == Mode::Allow => {
            return Err(PathError::PathUnreadable {
                spelling,
                source: error,
            });
        }
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {} // deny: fall through, fail closed.
        Err(error) => return Err(classify_other(error, &spelling)),
    }

    let mut current = full.to_path_buf();
    let mut tail: Vec<String> = Vec::new();
    loop {
        match fs::canonicalize(&current) {
            Ok(ancestor) => {
                tail.reverse();
                return Ok(Resolution::Resolved { ancestor, tail });
            }
            Err(error) => {
                let ambiguous_with_dangling = match error.kind() {
                    ErrorKind::NotFound => true,
                    ErrorKind::PermissionDenied if mode == Mode::Deny => true,
                    ErrorKind::PermissionDenied => {
                        return Err(PathError::PathUnreadable {
                            spelling,
                            source: error,
                        });
                    }
                    _ => false,
                };
                if !ambiguous_with_dangling {
                    return Err(classify_other(error, &spelling));
                }
                // `canonicalize` reports both "missing" and "a dangling symlink here" as
                // `NotFound` (and, for deny, `PermissionDenied` is treated the same way); only
                // `symlink_metadata` on this exact candidate can tell them apart.
                if matches!(fs::symlink_metadata(&current), Ok(meta) if meta.is_symlink()) {
                    return Ok(Resolution::Dangling);
                }
                // `Path::file_name()` returns `None` for a path ending in `..`, so a trailing
                // `..` must be detected through `Component`, not `file_name`, or it would be
                // silently popped as an empty name instead of rejected.
                match current.components().next_back() {
                    Some(std::path::Component::ParentDir) => {
                        return DotDotInTailSnafu {
                            spelling: spelling.clone(),
                        }
                        .fail();
                    }
                    Some(std::path::Component::Normal(name)) => {
                        tail.push(name.to_str().unwrap_or_default().to_owned());
                    }
                    _ => return Err(classify_other(error, &spelling)),
                }
                current = match current.parent() {
                    Some(parent) => parent.to_path_buf(),
                    None => return Err(classify_other(error, &spelling)),
                };
            }
        }
    }
}

/// Maps an I/O error that isn't "missing" or "permission denied" to a typed [`PathError`].
fn classify_other(error: io::Error, spelling: &str) -> PathError {
    if is_symlink_loop(&error) {
        return PathError::SymlinkLoop {
            spelling: spelling.to_owned(),
        };
    }
    match error.kind() {
        ErrorKind::NotADirectory => PathError::NotADirectoryAncestor {
            spelling: spelling.to_owned(),
        },
        _ => PathError::Io {
            spelling: spelling.to_owned(),
            source: error,
        },
    }
}

/// `ELOOP`'s errno value. `std::io::ErrorKind::FilesystemLoop` is still unstable (library
/// feature `io_error_more`), so this crate detects a symlink loop by raw errno instead. This
/// crate targets macOS only (62); the Linux value (40) is kept only so the crate still builds
/// elsewhere for linting, not because this error path is expected to run there.
#[cfg(target_os = "macos")]
const ELOOP: i32 = 62;
#[cfg(not(target_os = "macos"))]
const ELOOP: i32 = 40;

fn is_symlink_loop(error: &io::Error) -> bool {
    error.raw_os_error() == Some(ELOOP)
}

/// Why a glob tail component is not acceptable.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum GlobTailError {
    /// A component is `..`.
    #[snafu(display("glob pattern must not contain `..`"))]
    DotDot,
    /// A component is empty (consecutive or leading/trailing slash in the tail).
    #[snafu(display("glob pattern has an empty segment"))]
    EmptySegment,
    /// A component contains `[` or `{`, which this grammar does not support.
    #[snafu(display("glob pattern may only use `*`, `?` and `**`, not `[` or `{{`"))]
    UnsupportedMetacharacter,
    /// `**` is combined with other characters in the same segment.
    #[snafu(display("`**` must be its own path segment, not combined with other text"))]
    DoubleStarMixedWithText,
}

/// One segment of a glob tail: `**` (any number of path segments), or a segment that may mix
/// literal characters with `*` and `?` (an ordinary shell-style glob within one segment).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GlobSegment {
    /// Matches any number of path segments, including zero.
    AnyDepth,
    /// A pattern to match within exactly one path segment.
    Segment(String),
}

/// The non-literal tail of an `fs.deny_read`/`fs.deny_write` glob pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobTail(Vec<GlobSegment>);

impl GlobTail {
    /// Parses the glob segments after a `PathPattern`'s literal base.
    ///
    /// # Errors
    /// See [`GlobTailError`].
    pub fn parse(segments: &[&str]) -> Result<Self, GlobTailError> {
        let mut parsed = Vec::with_capacity(segments.len());
        for segment in segments {
            ensure!(!segment.is_empty(), EmptySegmentSnafu);
            if *segment == "**" {
                parsed.push(GlobSegment::AnyDepth);
                continue;
            }
            ensure!(*segment != "..", DotDotSnafu);
            ensure!(!segment.contains(['[', '{']), UnsupportedMetacharacterSnafu);
            ensure!(!segment.contains("**"), DoubleStarMixedWithTextSnafu);
            parsed.push(GlobSegment::Segment((*segment).to_owned()));
        }
        Ok(Self(parsed))
    }

    /// The parsed segments, in order.
    #[must_use]
    pub fn segments(&self) -> &[GlobSegment] {
        &self.0
    }
}

/// An `fs.deny_read`/`fs.deny_write` entry: a resolved literal base, and an optional glob tail.
///
/// `config/*.secrets.yaml` has base `config` and a tail of one segment, `*.secrets.yaml`. A
/// plain literal entry such as `~/.ssh` has no glob metacharacter anywhere, so `tail` is
/// `None` and `base` is the whole thing. The base is resolved with deny semantics (a glob
/// target does not exist yet as a literal path, so a missing base is not an error).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    /// The longest glob-free prefix, resolved as a deny rule.
    pub base: CanonicalPath,
    /// The glob segments after the base, or `None` for a plain literal entry.
    pub tail: Option<GlobTail>,
}

/// Why a glob pattern spelling could not be parsed.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum PathPatternError {
    /// The base, or the whole spelling for a literal entry, could not be resolved.
    #[snafu(transparent)]
    Base {
        /// The underlying error.
        source: PathError,
    },
    /// The glob tail was malformed.
    #[snafu(transparent)]
    Tail {
        /// The underlying error.
        source: GlobTailError,
    },
}

impl PathPattern {
    /// Parses an `fs.deny_read`/`fs.deny_write` entry, which may contain `*`, `?` or `**`.
    ///
    /// # Errors
    /// See [`PathPatternError`].
    pub fn parse(resolver: &PathResolver<'_>, spelling: &str) -> Result<Self, PathPatternError> {
        let components: Vec<&str> = spelling.split('/').collect();
        let glob_at = components
            .iter()
            .position(|segment| segment.contains('*') || segment.contains('?'));
        match glob_at {
            None => Ok(Self {
                base: resolver.deny(spelling)?.target,
                tail: None,
            }),
            Some(0) => {
                let tail = GlobTail::parse(&components)?;
                Ok(Self {
                    base: resolver.deny(".")?.target,
                    tail: Some(tail),
                })
            }
            Some(index) => {
                let base_spelling = components[..index].join("/");
                let tail = GlobTail::parse(&components[index..])?;
                Ok(Self {
                    base: resolver.deny(&base_spelling)?.target,
                    tail: Some(tail),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_err, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    struct Fixture {
        _dir: TempDir,
        home: HomeDir,
        root: ProjectRoot,
    }

    impl Fixture {
        /// A fresh temp directory with `home` and `project` subdirectories, so tests never
        /// touch the real filesystem outside a throwaway tree.
        fn new() -> Self {
            let dir = assert_ok!(TempDir::new());
            let home_path = dir.path().join("home");
            let project_path = dir.path().join("project");
            assert_ok!(fs::create_dir_all(&home_path));
            assert_ok!(fs::create_dir_all(&project_path));
            let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(assert_ok!(
                fs::canonicalize(&home_path)
            ))));
            let root = assert_ok!(ProjectRoot::new(
                assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
                    &project_path
                )))),
                &home,
            ));
            Self {
                _dir: dir,
                home,
                root,
            }
        }

        fn resolver(&self) -> PathResolver<'_> {
            PathResolver::new(&self.home, &self.root)
        }

        fn home_path(&self) -> PathBuf {
            PathBuf::from(self.home.path().as_str())
        }

        fn project_path(&self) -> PathBuf {
            PathBuf::from(self.root.path().as_str())
        }
    }

    // ====================================================================================
    // Expansion
    // ====================================================================================

    #[test]
    fn allow_expands_tilde_to_home() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.home_path().join("f.txt"), b"x"));
        let granted = assert_ok!(fx.resolver().allow("~/f.txt"));
        assert_eq!(
            granted,
            AllowOutcome::Granted(assert_ok!(CanonicalPath::from_canonical(
                fx.home_path().join("f.txt")
            )))
        );
    }

    #[test]
    fn allow_rejects_tilde_user() {
        let fx = Fixture::new();
        let err = assert_err!(fx.resolver().allow("~rolfs/f.txt"));
        assert!(matches!(err, PathError::TildeUser { .. }));
    }

    #[test]
    fn allow_does_not_expand_dollar_vars() {
        let fx = Fixture::new();
        // "$HOME/f.txt" is a literal, nonexistent filename under the project root; no special
        // handling of `$` should occur, so this just behaves like any other missing path.
        let outcome = assert_ok!(fx.resolver().allow("$HOME/f.txt"));
        assert!(matches!(
            outcome,
            AllowOutcome::Skipped(SkippedPath {
                reason: SkipReason::Missing,
                ..
            })
        ));
    }

    #[test]
    fn allow_relative_resolves_against_project_root_not_cwd() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("f.txt"), b"x"));
        let granted = assert_ok!(fx.resolver().allow("f.txt"));
        assert_eq!(
            granted,
            AllowOutcome::Granted(assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("f.txt")
            )))
        );
    }

    #[test]
    fn dot_segments_are_dropped_lexically() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("f.txt"), b"x"));
        let granted = assert_ok!(fx.resolver().allow("./f.txt"));
        assert_eq!(
            granted,
            AllowOutcome::Granted(assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("f.txt")
            )))
        );
    }

    // ====================================================================================
    // allow: missing, dangling, granted
    // ====================================================================================

    #[test]
    fn allow_missing_is_skipped_with_spelling_and_reason() {
        let fx = Fixture::new();
        let outcome = assert_ok!(fx.resolver().allow("nope.txt"));
        let AllowOutcome::Skipped(skipped) = outcome else {
            unreachable!("expected Skipped")
        };
        assert_eq!(skipped.spelling, "nope.txt");
        assert_eq!(skipped.reason, SkipReason::Missing);
    }

    #[test]
    fn allow_dangling_symlink_is_skipped_dangling() {
        let fx = Fixture::new();
        assert_ok!(symlink(
            fx.project_path().join("ghost"),
            fx.project_path().join("link"),
        ));
        let outcome = assert_ok!(fx.resolver().allow("link"));
        assert!(matches!(
            outcome,
            AllowOutcome::Skipped(SkippedPath {
                reason: SkipReason::Dangling,
                ..
            })
        ));
    }

    #[test]
    fn allow_dangling_symlink_mid_walk_is_skipped_dangling() {
        let fx = Fixture::new();
        assert_ok!(symlink(
            fx.project_path().join("ghost"),
            fx.project_path().join("linkdir"),
        ));
        let outcome = assert_ok!(fx.resolver().allow("linkdir/sub/file.txt"));
        assert!(matches!(
            outcome,
            AllowOutcome::Skipped(SkippedPath {
                reason: SkipReason::Dangling,
                ..
            })
        ));
    }

    #[test]
    fn allow_grants_a_real_file_and_a_symlinked_one() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("real.txt"), b"x"));
        assert_ok!(symlink(
            fx.project_path().join("real.txt"),
            fx.project_path().join("alias.txt"),
        ));
        assert!(matches!(
            assert_ok!(fx.resolver().allow("alias.txt")),
            AllowOutcome::Granted(_)
        ));
    }

    #[test]
    fn allow_symlink_loop_is_error() {
        let fx = Fixture::new();
        let loop_path = fx.project_path().join("loop");
        assert_ok!(symlink(&loop_path, &loop_path));
        let err = assert_err!(fx.resolver().allow("loop"));
        assert!(matches!(err, PathError::SymlinkLoop { .. }), "{err:?}");
    }

    #[test]
    fn allow_permission_denied_is_error_not_skip() {
        let fx = Fixture::new();
        let blocked = fx.project_path().join("blocked");
        assert_ok!(fs::create_dir(&blocked));
        assert_ok!(fs::write(blocked.join("inner.txt"), b"x"));
        assert_ok!(fs::set_permissions(
            &blocked,
            fs::Permissions::from_mode(0o000)
        ));
        let result = fx.resolver().allow("blocked/inner.txt");
        assert_ok!(fs::set_permissions(
            &blocked,
            fs::Permissions::from_mode(0o755)
        ));
        assert!(matches!(
            assert_err!(result),
            PathError::PathUnreadable { .. }
        ));
    }

    #[test]
    fn allow_rejects_broad_root_home_and_ancestors() {
        let fx = Fixture::new();
        // Granting the project root itself is the ordinary case (every project's base config
        // grants write = ["."]), so it is NOT too broad; the breadth check is about $HOME and
        // the filesystem root, not project containment.
        assert!(matches!(
            fx.resolver().allow("."),
            Ok(AllowOutcome::Granted(_))
        ));
        let err = assert_err!(fx.resolver().allow("~"));
        assert!(matches!(err, PathError::TooBroad { .. }), "home: {err:?}");
        let err = assert_err!(fx.resolver().allow("~/.."));
        assert!(
            matches!(err, PathError::TooBroad { .. }),
            "home ancestor: {err:?}"
        );
    }

    #[test]
    fn allow_not_a_directory_ancestor_is_error() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("file.txt"), b"x"));
        let err = assert_err!(fx.resolver().allow("file.txt/more"));
        assert!(
            matches!(err, PathError::NotADirectoryAncestor { .. }),
            "{err:?}"
        );
    }

    // ====================================================================================
    // allow: a relative grant must stay inside the project (D22's own meaning of "relative")
    // ====================================================================================

    /// A project nested a few levels under home, the realistic layout: a sibling-of-home
    /// fixture would let the pre-existing $HOME-ancestor check accidentally catch an escape
    /// by coincidence, masking whether containment is actually enforced.
    struct NestedFixture {
        _dir: TempDir,
        home: HomeDir,
        root: ProjectRoot,
    }

    impl NestedFixture {
        fn new() -> Self {
            let dir = assert_ok!(TempDir::new());
            let home_path = dir.path().join("home");
            let project_path = home_path.join("work").join("myproject");
            assert_ok!(fs::create_dir_all(&project_path));
            let home = HomeDir::new(assert_ok!(CanonicalPath::from_canonical(assert_ok!(
                fs::canonicalize(&home_path)
            ))));
            let root = assert_ok!(ProjectRoot::new(
                assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
                    &project_path
                )))),
                &home,
            ));
            Self {
                _dir: dir,
                home,
                root,
            }
        }

        fn resolver(&self) -> PathResolver<'_> {
            PathResolver::new(&self.home, &self.root)
        }

        fn project_path(&self) -> PathBuf {
            PathBuf::from(self.root.path().as_str())
        }
    }

    #[test]
    fn allow_rejects_a_relative_grant_that_escapes_the_project_root() {
        let fx = NestedFixture::new();
        // "work" is the project's own parent; this is a real directory, not merely a missing
        // tail, so the escape is not incidentally caught by anything else.
        let err = assert_err!(fx.resolver().allow(".."));
        assert!(
            matches!(err, PathError::RelativeEscapesProject { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn allow_rejects_a_multi_component_relative_escape() {
        let fx = NestedFixture::new();
        let project_path = fx.project_path();
        let parent = assert_some!(project_path.parent());
        assert_ok!(fs::create_dir_all(parent.join("sibling-project")));
        let err = assert_err!(fx.resolver().allow("../sibling-project"));
        assert!(
            matches!(err, PathError::RelativeEscapesProject { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn allow_accepts_a_relative_grant_that_stays_inside_the_project() {
        let fx = NestedFixture::new();
        assert_ok!(fs::create_dir(fx.project_path().join("fixtures")));
        assert!(matches!(
            assert_ok!(fx.resolver().allow("fixtures")),
            AllowOutcome::Granted(_)
        ));
        assert!(matches!(
            assert_ok!(fx.resolver().allow(".")),
            AllowOutcome::Granted(_)
        ));
    }

    #[test]
    fn allow_does_not_apply_project_containment_to_absolute_or_tilde_paths() {
        let fx = NestedFixture::new();
        // An absolute or ~-based grant is explicitly allowed to point outside the project;
        // only a *relative* spelling carries the "stays inside the project" meaning.
        assert!(matches!(
            assert_ok!(fx.resolver().allow("~/work")),
            AllowOutcome::Granted(_)
        ));
    }

    // ====================================================================================
    // deny: missing tail, dangling, alias, permission fall-through
    // ====================================================================================

    #[test]
    fn deny_missing_leaf_keeps_canonical_parent_plus_name() {
        let fx = Fixture::new();
        let resolution = assert_ok!(fx.resolver().deny("nope.txt"));
        assert_eq!(
            resolution.target,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("nope.txt")
            ))
        );
        assert_eq!(resolution.alias, None);
    }

    #[test]
    fn deny_missing_multi_component_tail() {
        let fx = Fixture::new();
        let resolution = assert_ok!(fx.resolver().deny("a/b/c.txt"));
        assert_eq!(
            resolution.target,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("a/b/c.txt")
            ))
        );
    }

    #[test]
    fn deny_missing_tail_under_an_existing_symlinked_parent() {
        let fx = Fixture::new();
        let real_dir = fx.project_path().join("real_dir");
        assert_ok!(fs::create_dir(&real_dir));
        assert_ok!(symlink(&real_dir, fx.project_path().join("link_dir")));
        let resolution = assert_ok!(fx.resolver().deny("link_dir/missing.txt"));
        assert_eq!(
            resolution.target,
            assert_ok!(CanonicalPath::from_canonical(real_dir.join("missing.txt")))
        );
    }

    #[test]
    fn deny_missing_tail_rejects_dotdot() {
        let fx = Fixture::new();
        let err = assert_err!(fx.resolver().deny("a/../b/missing/../c.txt"));
        assert!(matches!(err, PathError::DotDotInTail { .. }), "{err:?}");
    }

    #[test]
    fn deny_existing_prefix_dotdot_resolves_through_the_kernel() {
        let fx = Fixture::new();
        assert_ok!(fs::create_dir(fx.project_path().join("a")));
        assert_ok!(fs::write(fx.project_path().join("c.txt"), b"x"));
        let resolution = assert_ok!(fx.resolver().deny("a/../c.txt"));
        assert_eq!(
            resolution.target,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("c.txt")
            ))
        );
    }

    #[test]
    fn deny_permission_denied_keeps_the_deepest_resolvable_ancestor() {
        let fx = Fixture::new();
        let blocked = fx.project_path().join("blocked");
        assert_ok!(fs::create_dir(&blocked));
        assert_ok!(fs::write(blocked.join("inner.txt"), b"x"));
        assert_ok!(fs::set_permissions(
            &blocked,
            fs::Permissions::from_mode(0o000)
        ));
        let result = fx.resolver().deny("blocked/inner.txt");
        assert_ok!(fs::set_permissions(
            &blocked,
            fs::Permissions::from_mode(0o755)
        ));
        let resolution = assert_ok!(result);
        assert_eq!(
            resolution.target,
            assert_ok!(CanonicalPath::from_canonical(blocked.join("inner.txt")))
        );
    }

    #[test]
    fn deny_permission_denied_on_the_target_itself_resolves_transparently() {
        let fx = Fixture::new();
        let restricted = fx.project_path().join("restricted_itself");
        assert_ok!(fs::create_dir(&restricted));
        assert_ok!(fs::set_permissions(
            &restricted,
            fs::Permissions::from_mode(0o000)
        ));
        let result = fx.resolver().deny("restricted_itself");
        assert_ok!(fs::set_permissions(
            &restricted,
            fs::Permissions::from_mode(0o755)
        ));
        let resolution = assert_ok!(result);
        assert_eq!(
            resolution.target,
            assert_ok!(CanonicalPath::from_canonical(&restricted))
        );
    }

    #[test]
    fn deny_dangling_symlink_is_error() {
        let fx = Fixture::new();
        assert_ok!(symlink(
            fx.project_path().join("ghost"),
            fx.project_path().join("link"),
        ));
        let err = assert_err!(fx.resolver().deny("link"));
        assert!(matches!(err, PathError::Dangling { .. }));
    }

    #[test]
    fn deny_dangling_symlink_mid_walk_is_error() {
        let fx = Fixture::new();
        assert_ok!(symlink(
            fx.project_path().join("ghost"),
            fx.project_path().join("linkdir"),
        ));
        let err = assert_err!(fx.resolver().deny("linkdir/sub/file.txt"));
        assert!(matches!(err, PathError::Dangling { .. }));
    }

    #[test]
    fn deny_existing_symlink_returns_target_and_alias() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("real.txt"), b"x"));
        assert_ok!(symlink(
            fx.project_path().join("real.txt"),
            fx.project_path().join("alias.txt"),
        ));
        let resolution = assert_ok!(fx.resolver().deny("alias.txt"));
        assert_eq!(
            resolution.target,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("real.txt")
            ))
        );
        assert_eq!(
            resolution.alias,
            Some(assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("alias.txt")
            )))
        );
    }

    #[test]
    fn deny_under_a_file_is_not_a_directory_error() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("file.txt"), b"x"));
        let err = assert_err!(fx.resolver().deny("file.txt/more"));
        assert!(matches!(err, PathError::NotADirectoryAncestor { .. }));
    }

    #[test]
    fn deny_symlink_loop_is_error() {
        let fx = Fixture::new();
        let loop_path = fx.project_path().join("loop");
        assert_ok!(symlink(&loop_path, &loop_path));
        let err = assert_err!(fx.resolver().deny("loop"));
        assert!(matches!(err, PathError::SymlinkLoop { .. }));
    }

    #[test]
    fn deny_rejects_nul_control_and_overlong_spellings() {
        let fx = Fixture::new();
        assert!(matches!(
            assert_err!(fx.resolver().deny("")),
            PathError::EmptySpelling
        ));
        assert!(matches!(
            assert_err!(fx.resolver().deny("a\0b")),
            PathError::SpellingControlCharacter { .. }
        ));
        assert!(matches!(
            assert_err!(
                fx.resolver()
                    .deny(&"a".repeat(super::super::path::MAX_PATH_BYTES + 1))
            ),
            PathError::SpellingTooLong { .. }
        ));
    }

    #[test]
    fn deny_has_no_breadth_check() {
        let fx = Fixture::new();
        // Unlike allow, denying "~" or "/" is legitimate: the whole point of a deny rule is
        // to cover something broad.
        assert_ok!(fx.resolver().deny("~"));
    }

    // ====================================================================================
    // existing
    // ====================================================================================

    #[test]
    fn existing_errors_on_missing() {
        let fx = Fixture::new();
        assert!(matches!(
            assert_err!(fx.resolver().existing("nope.txt")),
            PathError::Missing { .. }
        ));
    }

    #[test]
    fn existing_succeeds_on_a_real_file_dir_and_followed_symlink() {
        let fx = Fixture::new();
        assert_ok!(fs::write(fx.project_path().join("f.txt"), b"x"));
        assert_ok!(fs::create_dir(fx.project_path().join("d")));
        assert_ok!(symlink(
            fx.project_path().join("f.txt"),
            fx.project_path().join("alias.txt"),
        ));
        assert_ok!(fx.resolver().existing("f.txt"));
        assert_ok!(fx.resolver().existing("d"));
        let resolved = assert_ok!(fx.resolver().existing("alias.txt"));
        assert_eq!(
            resolved,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("f.txt")
            ))
        );
    }

    #[test]
    fn existing_errors_on_a_dangling_symlink() {
        let fx = Fixture::new();
        assert_ok!(symlink(
            fx.project_path().join("ghost"),
            fx.project_path().join("link"),
        ));
        assert!(matches!(
            assert_err!(fx.resolver().existing("link")),
            PathError::Dangling { .. }
        ));
    }

    // ====================================================================================
    // PathPattern / GlobTail
    // ====================================================================================

    #[test]
    fn pattern_literal_entry_has_no_tail() {
        let fx = Fixture::new();
        assert_ok!(fs::create_dir(fx.project_path().join("config")));
        let pattern = assert_ok!(PathPattern::parse(&fx.resolver(), "config/app.yaml"));
        assert_eq!(
            pattern.base,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("config/app.yaml")
            ))
        );
        assert_eq!(pattern.tail, None);
    }

    #[test]
    fn pattern_splits_base_and_glob_tail() {
        let fx = Fixture::new();
        assert_ok!(fs::create_dir(fx.project_path().join("config")));
        let pattern = assert_ok!(PathPattern::parse(&fx.resolver(), "config/*.secrets.yaml"));
        assert_eq!(
            pattern.base,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("config")
            ))
        );
        assert_eq!(
            pattern.tail,
            Some(assert_ok!(GlobTail::parse(&["*.secrets.yaml"])))
        );
    }

    #[test]
    fn pattern_missing_base_uses_deny_semantics() {
        let fx = Fixture::new();
        // "config" does not exist; the base must still resolve (deny-style), not error.
        let pattern = assert_ok!(PathPattern::parse(&fx.resolver(), "config/*.secrets.yaml"));
        assert_eq!(
            pattern.base,
            assert_ok!(CanonicalPath::from_canonical(
                fx.project_path().join("config")
            ))
        );
    }

    #[test]
    fn pattern_with_a_glob_at_the_project_root_has_the_root_as_base() {
        let fx = Fixture::new();
        let pattern = assert_ok!(PathPattern::parse(&fx.resolver(), "*.env"));
        assert_eq!(
            pattern.base,
            assert_ok!(CanonicalPath::from_canonical(fx.project_path()))
        );
        assert_eq!(pattern.tail, Some(assert_ok!(GlobTail::parse(&["*.env"]))));
    }

    #[test]
    fn pattern_rejects_dotdot_absolute_brackets_and_braces_in_the_tail() {
        assert!(matches!(
            assert_err!(GlobTail::parse(&[".."])),
            GlobTailError::DotDot
        ));
        assert!(matches!(
            assert_err!(GlobTail::parse(&["[abc]"])),
            GlobTailError::UnsupportedMetacharacter
        ));
        assert!(matches!(
            assert_err!(GlobTail::parse(&["{a,b}"])),
            GlobTailError::UnsupportedMetacharacter
        ));
    }

    #[test]
    fn pattern_rejects_double_star_mixed_with_other_text() {
        assert!(matches!(
            assert_err!(GlobTail::parse(&["**x"])),
            GlobTailError::DoubleStarMixedWithText
        ));
    }

    #[test]
    fn pattern_rejects_an_empty_segment() {
        assert!(matches!(
            assert_err!(GlobTail::parse(&[""])),
            GlobTailError::EmptySegment
        ));
    }

    #[test]
    fn pattern_double_star_is_its_own_segment() {
        let tail = assert_ok!(GlobTail::parse(&["logs", "**", "*.log"]));
        assert_eq!(
            tail.segments(),
            &[
                GlobSegment::Segment("logs".to_owned()),
                GlobSegment::AnyDepth,
                GlobSegment::Segment("*.log".to_owned())
            ]
        );
    }

    #[test]
    fn pattern_allows_star_and_question_mark_mixed_with_literal_text_in_one_segment() {
        let tail = assert_ok!(GlobTail::parse(&["*.secrets.yaml", "a?b.env"]));
        assert_eq!(
            tail.segments(),
            &[
                GlobSegment::Segment("*.secrets.yaml".to_owned()),
                GlobSegment::Segment("a?b.env".to_owned())
            ]
        );
    }

    // ====================================================================================
    // Seatbelt regressions (macOS only): guard the measured real-world behavior directly
    // ====================================================================================

    #[cfg(target_os = "macos")]
    mod seatbelt {
        use claims::assert_ok;
        use std::process::Command;
        use tempfile::TempDir;

        fn run_sandboxed(
            profile: &str,
            params: &[(&str, &str)],
            command: &[&str],
        ) -> std::process::Output {
            let mut args: Vec<String> = vec!["-p".to_owned(), profile.to_owned()];
            for (name, value) in params {
                args.push("-D".to_owned());
                args.push(format!("{name}={value}"));
            }
            args.push("--".to_owned());
            for part in command {
                args.push((*part).to_owned());
            }
            let output = Command::new("/usr/bin/sandbox-exec").args(&args).output();
            assert_ok!(output)
        }

        #[test]
        fn seatbelt_denies_case_variant_of_missing_name() {
            let dir = assert_ok!(TempDir::new());
            let canonical_dir = assert_ok!(std::fs::canonicalize(dir.path()));
            let profile =
                r#"(version 1)(allow default)(deny file-write* (literal (param "TARGET")))"#;
            let target = canonical_dir.join("ID_RSA").to_string_lossy().into_owned();
            let output = run_sandboxed(
                profile,
                &[("TARGET", &target)],
                &[
                    "/bin/sh",
                    "-c",
                    &format!("echo x > {}", canonical_dir.join("id_rsa").display()),
                ],
            );
            assert!(
                !output.status.success(),
                "lowercase create should have been blocked by an uppercase deny"
            );
        }

        #[test]
        fn seatbelt_denies_nfd_variant_of_nfc_rule() {
            let dir = assert_ok!(TempDir::new());
            let canonical_dir = assert_ok!(std::fs::canonicalize(dir.path()));
            let nfc = "caf\u{e9}"; // precomposed e-acute
            let nfd = "cafe\u{301}"; // combining acute accent
            let profile =
                r#"(version 1)(allow default)(deny file-write* (literal (param "TARGET")))"#;
            let target = canonical_dir.join(nfc).to_string_lossy().into_owned();
            let output = run_sandboxed(
                profile,
                &[("TARGET", &target)],
                &[
                    "/bin/sh",
                    "-c",
                    &format!("echo x > {}", canonical_dir.join(nfd).display()),
                ],
            );
            assert!(
                !output.status.success(),
                "NFD create should have been blocked by an NFC deny"
            );
        }

        #[test]
        fn seatbelt_accepts_a_parameter_value_with_newline_quote_and_parenthesis() {
            let profile =
                r#"(version 1)(allow default)(deny file-write* (literal (param "TARGET")))"#;
            let hostile_value = "/tmp/a\nb\"c)d";
            let output = run_sandboxed(profile, &[("TARGET", hostile_value)], &["/usr/bin/true"]);
            assert!(output.status.success(), "{output:?}");
        }

        #[test]
        fn seatbelt_regression_an_uncanonicalized_tmp_spelling_does_not_block_private_tmp() {
            // The exact footgun this task exists to prevent: a deny written against the
            // symlink spelling `/tmp/...` does not block the canonical `/private/tmp/...`
            // path the kernel actually uses.
            let profile =
                r#"(version 1)(allow default)(deny file-write* (literal (param "TARGET")))"#;
            let marker = format!("hb-regression-{}", std::process::id());
            let uncanonical_target = format!("/tmp/{marker}");
            let real_path = format!("/private/tmp/{marker}");
            let output = run_sandboxed(
                profile,
                &[("TARGET", &uncanonical_target)],
                &["/bin/sh", "-c", &format!("echo x > {real_path}")],
            );
            let _ = std::fs::remove_file(&real_path);
            assert!(
                output.status.success(),
                "a deny on the /tmp spelling should NOT block /private/tmp (documents the footgun)"
            );
        }
    }
}
