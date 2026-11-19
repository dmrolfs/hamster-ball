// ABOUTME: BuiltinPresets: the registry of presets compiled into hb, looked up by validated name.
// ABOUTME: Mechanism only for now; the real preset contents are measured data owned by later milestones.
//! Presets compiled into `hb`.
//!
//! A built-in preset is ordinary config text, parsed and resolved like any other file, but it
//! has no path on disk, so it is never approved, hashed or symlink-checked, and it may define
//! user-only sections. Which presets exist is data owned by the agent-preset milestones
//! (`hb-ghd.3.x`, `hb-ghd.6.x`); this module is the mechanism that serves them.

use crate::policy::PresetName;

/// A source of built-in preset text.
pub trait BuiltinPresets {
    /// The text of the built-in preset `name`, if there is one.
    fn get(&self, name: &PresetName) -> Option<&str>;
}

/// The presets compiled into this build of `hb`.
///
/// Add a preset by adding a file under `presets/` and one line to the table below; the
/// completeness test fails if a file is not registered.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmbeddedPresets;

/// `(name, text)` pairs. Keep sorted by name.
const EMBEDDED: &[(&str, &str)] = &[];

/// The text registered under `name` in `table`.
fn lookup<'a>(table: &[(&'a str, &'a str)], name: &PresetName) -> Option<&'a str> {
    table
        .iter()
        .find(|(candidate, _)| *candidate == name.as_str())
        .map(|(_, text)| *text)
}

impl BuiltinPresets for EmbeddedPresets {
    fn get(&self, name: &PresetName) -> Option<&str> {
        lookup(EMBEDDED, name)
    }
}

/// A fixed table of presets, for tests and for callers that bring their own.
#[derive(Debug, Clone, Copy)]
pub struct StaticPresets<'a>(pub &'a [(&'a str, &'a str)]);

impl BuiltinPresets for StaticPresets<'_> {
    fn get(&self, name: &PresetName) -> Option<&str> {
        lookup(self.0, name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_none, assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use std::fs;
    use std::path::Path;

    fn name(text: &str) -> PresetName {
        assert_ok!(PresetName::parse(text))
    }

    #[test]
    fn a_static_table_serves_its_entries_by_exact_name() {
        let table = StaticPresets(&[("rust", "# rust\n"), ("agent/kiro", "# kiro\n")]);
        assert_eq!(assert_some!(table.get(&name("rust"))), "# rust\n");
        assert_eq!(assert_some!(table.get(&name("agent/kiro"))), "# kiro\n");
        assert_none!(table.get(&name("agent")));
        assert_none!(table.get(&name("ruste")));
    }

    #[test]
    fn the_embedded_registry_serves_exactly_its_table() {
        for (registered, text) in EMBEDDED {
            assert_eq!(assert_some!(EmbeddedPresets.get(&name(registered))), *text);
        }
        assert_none!(EmbeddedPresets.get(&name("definitely-not-a-preset")));
    }

    #[test]
    fn the_embedded_table_is_sorted_and_has_valid_unique_names() {
        let names: Vec<&str> = EMBEDDED.iter().map(|(name, _)| *name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            names, sorted,
            "EMBEDDED must be sorted and free of duplicates"
        );
        for entry in names {
            assert_ok!(PresetName::parse(entry), "{entry}");
        }
    }

    #[test]
    fn every_embedded_preset_text_is_valid_config() {
        use crate::config::{ConfigText, ResolveContext, resolve_file};
        use crate::testutil::Tree;
        let tree = Tree::new();
        let root = tree.project_root("work/proj");
        for (preset, text) in EMBEDDED {
            let parsed = ConfigText::builtin(preset, text);
            assert_ok!(
                resolve_file(&parsed, &ResolveContext::new(tree.home(), &root)),
                "{preset}"
            );
        }
    }

    /// Every `presets/**/*.toml` file in the repository is registered, so adding a file
    /// without adding it to the table cannot silently ship a preset that does not exist.
    #[test]
    fn every_file_under_presets_is_registered() {
        fn collect(dir: &Path, base: &Path, found: &mut Vec<String>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect(&path, base, found);
                } else if path.extension().is_some_and(|ext| ext == "toml") {
                    if let Ok(relative) = path.strip_prefix(base) {
                        found.push(relative.with_extension("").to_string_lossy().into_owned());
                    }
                }
            }
        }
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("presets");
        let mut on_disk = Vec::new();
        collect(&base, &base, &mut on_disk);
        on_disk.sort_unstable();
        let registered: Vec<String> = EMBEDDED
            .iter()
            .map(|(name, _)| (*name).to_owned())
            .collect();
        assert_eq!(on_disk, registered);
    }
}
