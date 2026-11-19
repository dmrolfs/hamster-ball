// ABOUTME: Policy::decide: an advisory, over-approximating answer to "is this path denied, allowed or not granted?".
// ABOUTME: Seatbelt rule order is the enforcement; this exists for tests, `hb explain` and the deny-wins guarantee.
//! The advisory filesystem decision.
//!
//! A deny from any layer beats an allow from any layer: [`Policy::decide`] looks at every deny
//! first, and only if none covers the path does it look at grants. The query errs toward
//! "denied" (see [`PathPattern::covers`]) and toward "not granted" (grants are matched
//! exactly), so a mistake here can only be conservative. The enforcement is the order of rules
//! in the generated Seatbelt profile (hb-ghd.2.1), where denies come last and win.

use super::merge::Policy;
use crate::origin::Sourced;
use crate::policy::{CanonicalPath, Coverage, PathPattern};

/// What the caller wants to do with a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsAccess {
    /// Read the path.
    Read,
    /// Write, create, delete or rename the path.
    Write,
}

/// The advisory answer for one path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FsDecision<'a> {
    /// A deny rule covers the path; no allow can change that.
    Denied {
        /// The rule, with every place it was declared.
        by: &'a Sourced<PathPattern>,
        /// Whether the rule matched only under case-insensitive or Unicode-conservative
        /// comparison.
        folded: bool,
    },
    /// No deny covers the path, and a grant does.
    Allowed {
        /// The grant, with every place it was declared.
        by: &'a Sourced<CanonicalPath>,
    },
    /// Neither a deny nor a grant covers the path.
    NotGranted,
}

impl Policy {
    /// Decides whether `access` to `path` is denied, allowed or not granted.
    ///
    /// A read-deny also denies writing (decision D5); a write-deny denies only writing. A
    /// write grant also allows reading; a read grant does not allow writing. When several
    /// rules deny, one that matches exactly is reported in preference to one that matches only
    /// after folding, and otherwise the first in sorted order.
    #[must_use]
    pub fn decide(&self, path: &CanonicalPath, access: FsAccess) -> FsDecision<'_> {
        let denies: &[&[Sourced<PathPattern>]] = match access {
            FsAccess::Read => &[&self.fs.deny_read],
            FsAccess::Write => &[&self.fs.deny_read, &self.fs.deny_write],
        };
        let mut folded_match = None;
        for rule in denies.iter().flat_map(|rules| rules.iter()) {
            match rule.value.covers(path) {
                Coverage::No => {}
                Coverage::Yes => {
                    return FsDecision::Denied {
                        by: rule,
                        folded: false,
                    };
                }
                Coverage::YesFolded => {
                    folded_match.get_or_insert(rule);
                }
            }
        }
        if let Some(by) = folded_match {
            return FsDecision::Denied { by, folded: true };
        }

        let grants: &[&[Sourced<CanonicalPath>]] = match access {
            FsAccess::Read => &[&self.fs.read, &self.fs.write],
            FsAccess::Write => &[&self.fs.write],
        };
        grants
            .iter()
            .flat_map(|grants| grants.iter())
            .find(|grant| grant.value.is_same_or_ancestor_of(path))
            .map_or(FsDecision::NotGranted, |by| FsDecision::Allowed { by })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ClosureFile, ConfigText, Diagnostics, FileLocation, FileSource, Indexed, ResolvedConfig,
        merge,
    };
    use crate::origin::{FileId, Layer, Source};
    use crate::policy::{CanonicalPath, GlobTail, PathPattern, PresetName};
    use claims::{assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;

    fn cpath(p: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(p))
    }

    fn deny(base: &str) -> PathPattern {
        PathPattern {
            base: cpath(base),
            alias: None,
            tail: None,
        }
    }

    fn deny_glob(base: &str, tail: &[&str]) -> PathPattern {
        PathPattern {
            base: cpath(base),
            alias: None,
            tail: Some(assert_ok!(GlobTail::parse(tail))),
        }
    }

    fn grant(p: &str, index: u32) -> Indexed<CanonicalPath> {
        Indexed {
            value: cpath(p),
            index,
        }
    }

    fn file(
        name: &str,
        layer: Layer,
        location: FileLocation,
        config: ResolvedConfig,
    ) -> ClosureFile {
        ClosureFile {
            id: FileId::new(0),
            source: FileSource::Builtin {
                name: assert_ok!(PresetName::parse(name)),
            },
            layer,
            location,
            from_base: false,
            text: ConfigText::builtin(name, ""),
            resolved: config,
            diagnostics: Diagnostics::default(),
        }
    }

    fn numbered(mut files: Vec<ClosureFile>) -> Vec<ClosureFile> {
        for (i, f) in files.iter_mut().enumerate() {
            f.id = FileId::new(u16::try_from(i).unwrap_or(0));
        }
        files
    }

    fn policy(base: ResolvedConfig, project: ResolvedConfig) -> Policy {
        let files = numbered(vec![
            file("base", Layer::UserBase, FileLocation::UserConfig, base),
            file("project", Layer::Project, FileLocation::InProject, project),
        ]);
        assert_ok!(merge(&files))
    }

    fn config(
        read: &[&str],
        write: &[&str],
        deny_read: Vec<PathPattern>,
        deny_write: Vec<PathPattern>,
    ) -> ResolvedConfig {
        let mut c = ResolvedConfig::default();
        c.fs.read = read
            .iter()
            .enumerate()
            .map(|(i, p)| grant(p, i as u32))
            .collect();
        c.fs.write = write
            .iter()
            .enumerate()
            .map(|(i, p)| grant(p, i as u32))
            .collect();
        c.fs.deny_read = deny_read;
        c.fs.deny_write = deny_write;
        c
    }

    fn is_denied(d: &FsDecision<'_>) -> bool {
        matches!(d, FsDecision::Denied { .. })
    }

    // ====================================================================================
    // The headline guarantee: a deny from any layer beats an allow from any layer
    // ====================================================================================

    #[test]
    fn a_project_allow_on_a_base_denied_path_is_still_denied() {
        let base = config(&[], &[], vec![deny("/Users/me/.ssh")], vec![]);
        let project = config(&["/Users/me/.ssh"], &["/Users/me/.ssh"], vec![], vec![]);
        let policy = policy(base, project);
        for access in [FsAccess::Read, FsAccess::Write] {
            let decision = policy.decide(&cpath("/Users/me/.ssh"), access);
            let FsDecision::Denied { by, folded } = decision else {
                assert_ok!(Err::<(), _>(format!("expected Denied, got {decision:?}")));
                return;
            };
            assert!(!folded);
            // The deny is attributed to the base (file 0), not to the project's allow.
            assert_eq!(by.sources, vec![Source::entry(FileId::new(0), 0)]);
        }
    }

    #[test]
    fn a_base_allow_on_a_project_denied_path_is_denied_too() {
        let base = config(&["/p/vendor"], &[], vec![], vec![]);
        let project = config(&[], &[], vec![deny("/p/vendor")], vec![]);
        assert!(is_denied(
            &policy(base, project).decide(&cpath("/p/vendor/x"), FsAccess::Read)
        ));
    }

    #[test]
    fn an_allow_under_a_denied_directory_is_denied() {
        let base = config(&[], &[], vec![deny("/Users/me/.ssh")], vec![]);
        let project = config(&["/Users/me/.ssh/sub"], &[], vec![], vec![]);
        assert!(is_denied(
            &policy(base, project).decide(&cpath("/Users/me/.ssh/sub"), FsAccess::Read)
        ));
    }

    #[test]
    fn an_allow_that_falls_under_a_deny_glob_is_denied() {
        let base = config(
            &[],
            &[],
            vec![deny_glob("/p/config", &["*.secrets.yaml"])],
            vec![],
        );
        let project = config(&[], &["/p/config"], vec![], vec![]);
        let policy = policy(base, project);
        assert!(is_denied(
            &policy.decide(&cpath("/p/config/prod.secrets.yaml"), FsAccess::Write)
        ));
        // A neighbouring file in the same allowed directory is not denied.
        assert!(matches!(
            policy.decide(&cpath("/p/config/app.yaml"), FsAccess::Write),
            FsDecision::Allowed { .. }
        ));
    }

    #[test]
    fn an_allow_that_is_an_ancestor_of_a_deny_still_allows_the_rest_of_its_tree() {
        let base = config(&[], &[], vec![deny("/p/.git/hooks")], vec![]);
        let project = config(&[], &["/p"], vec![], vec![]);
        let policy = policy(base, project);
        assert!(matches!(
            policy.decide(&cpath("/p/src/main.rs"), FsAccess::Write),
            FsDecision::Allowed { .. }
        ));
        assert!(is_denied(
            &policy.decide(&cpath("/p/.git/hooks/pre-commit"), FsAccess::Write)
        ));
    }

    // ====================================================================================
    // Allow, not granted, and access kinds
    // ====================================================================================

    #[test]
    fn a_path_outside_every_grant_is_not_granted() {
        let policy = policy(
            config(&["/p/a"], &[], vec![], vec![]),
            ResolvedConfig::default(),
        );
        assert!(matches!(
            policy.decide(&cpath("/p/b"), FsAccess::Read),
            FsDecision::NotGranted
        ));
        assert!(matches!(
            policy.decide(&cpath("/p"), FsAccess::Read),
            FsDecision::NotGranted
        ));
    }

    #[test]
    fn grants_apply_by_path_component_not_string_prefix() {
        let policy = policy(
            config(&["/p"], &[], vec![], vec![]),
            ResolvedConfig::default(),
        );
        assert!(matches!(
            policy.decide(&cpath("/p/x"), FsAccess::Read),
            FsDecision::Allowed { .. }
        ));
        assert!(matches!(
            policy.decide(&cpath("/p2/x"), FsAccess::Read),
            FsDecision::NotGranted
        ));
    }

    #[test]
    fn a_write_grant_allows_reading_but_a_read_grant_does_not_allow_writing() {
        let policy = policy(
            config(&["/r"], &["/w"], vec![], vec![]),
            ResolvedConfig::default(),
        );
        assert!(matches!(
            policy.decide(&cpath("/w/x"), FsAccess::Read),
            FsDecision::Allowed { .. }
        ));
        assert!(matches!(
            policy.decide(&cpath("/w/x"), FsAccess::Write),
            FsDecision::Allowed { .. }
        ));
        assert!(matches!(
            policy.decide(&cpath("/r/x"), FsAccess::Read),
            FsDecision::Allowed { .. }
        ));
        assert!(matches!(
            policy.decide(&cpath("/r/x"), FsAccess::Write),
            FsDecision::NotGranted
        ));
    }

    #[test]
    fn a_read_deny_also_denies_writing_but_a_write_deny_does_not_deny_reading() {
        let policy = policy(
            config(
                &["/p"],
                &["/p"],
                vec![deny("/p/secret")],
                vec![deny("/p/frozen")],
            ),
            ResolvedConfig::default(),
        );
        assert!(is_denied(
            &policy.decide(&cpath("/p/secret/k"), FsAccess::Read)
        ));
        assert!(is_denied(
            &policy.decide(&cpath("/p/secret/k"), FsAccess::Write)
        ));
        assert!(is_denied(
            &policy.decide(&cpath("/p/frozen/f"), FsAccess::Write)
        ));
        assert!(matches!(
            policy.decide(&cpath("/p/frozen/f"), FsAccess::Read),
            FsDecision::Allowed { .. }
        ));
    }

    #[test]
    fn an_empty_policy_grants_nothing() {
        assert!(matches!(
            Policy::default().decide(&cpath("/anything"), FsAccess::Read),
            FsDecision::NotGranted
        ));
    }

    // ====================================================================================
    // Over-approximation: spelling variants
    // ====================================================================================

    #[test]
    fn a_case_variant_of_a_denied_path_is_denied_and_marked_folded() {
        let policy = policy(
            config(&[], &["/p"], vec![deny("/p/.ssh")], vec![]),
            ResolvedConfig::default(),
        );
        let FsDecision::Denied { folded, .. } =
            policy.decide(&cpath("/p/.SSH/id"), FsAccess::Write)
        else {
            assert_ok!(Err::<(), _>("expected a folded deny".to_owned()));
            return;
        };
        assert!(folded);
    }

    #[test]
    fn an_exact_match_is_preferred_over_a_folded_one() {
        let policy = policy(
            config(&[], &[], vec![deny("/P/X"), deny("/p/x")], vec![]),
            ResolvedConfig::default(),
        );
        let FsDecision::Denied { by, folded } = policy.decide(&cpath("/p/x/y"), FsAccess::Read)
        else {
            assert_ok!(Err::<(), _>("expected Denied".to_owned()));
            return;
        };
        assert!(!folded);
        assert_eq!(by.value, deny("/p/x"));
    }

    #[test]
    fn grants_are_matched_exactly_so_a_case_variant_is_not_granted() {
        // Under-allowing is the safe direction.
        let policy = policy(
            config(&["/p/Data"], &[], vec![], vec![]),
            ResolvedConfig::default(),
        );
        assert!(matches!(
            policy.decide(&cpath("/p/data/x"), FsAccess::Read),
            FsDecision::NotGranted
        ));
    }

    #[test]
    fn a_denied_decision_reports_the_denying_rule_and_its_sources() {
        let base = config(&[], &[], vec![deny("/a"), deny("/b")], vec![]);
        let policy = policy(base, ResolvedConfig::default());
        let FsDecision::Denied { by, .. } = policy.decide(&cpath("/b/x"), FsAccess::Read) else {
            assert_ok!(Err::<(), _>("expected Denied".to_owned()));
            return;
        };
        let by = assert_some!(Some(by));
        assert_eq!(by.value, deny("/b"));
        assert_eq!(by.sources, vec![Source::entry(FileId::new(0), 1)]);
    }

    // ====================================================================================
    // Properties
    // ====================================================================================

    const PATHS: &[&str] = &["/p", "/p/a", "/p/a/b", "/p/c", "/q", "/q/x", "/P/A"];
    const HOSTS: &[&str] = &["a.example.com", "b.example.com", "crates.io"];

    fn path_index() -> impl Strategy<Value = usize> {
        0..PATHS.len()
    }

    /// A random config over a small pool, so merges collide often enough to be interesting.
    fn arb_config() -> impl Strategy<Value = ResolvedConfig> {
        (
            proptest::collection::vec(path_index(), 0..4),
            proptest::collection::vec(path_index(), 0..4),
            proptest::collection::vec(path_index(), 0..3),
            proptest::collection::vec(path_index(), 0..3),
            proptest::collection::vec(0..HOSTS.len(), 0..3),
            proptest::option::of(any::<bool>()),
        )
            .prop_map(|(read, write, deny_read, deny_write, hosts, trust)| {
                let mut c = ResolvedConfig::default();
                c.fs.read = read
                    .iter()
                    .enumerate()
                    .map(|(i, &p)| grant(PATHS[p], i as u32))
                    .collect();
                c.fs.write = write
                    .iter()
                    .enumerate()
                    .map(|(i, &p)| grant(PATHS[p], i as u32))
                    .collect();
                c.fs.deny_read = deny_read.iter().map(|&p| deny(PATHS[p])).collect();
                c.fs.deny_write = deny_write.iter().map(|&p| deny(PATHS[p])).collect();
                c.net.allow = hosts
                    .iter()
                    .map(|&h| assert_ok!(crate::policy::HostPattern::parse(HOSTS[h])))
                    .collect();
                c.tls.system_trust = trust;
                c
            })
    }

    fn as_files(configs: &[ResolvedConfig], names: &[&str]) -> Vec<ClosureFile> {
        numbered(
            configs
                .iter()
                .zip(names)
                .map(|(c, n)| file(n, Layer::Preset, FileLocation::UserConfig, c.clone()))
                .collect(),
        )
    }

    const NAMES: &[&str] = &["f0", "f1", "f2", "f3", "f4", "f5"];

    /// A policy's content with sources replaced by stable (file name, index) pairs, so two
    /// merges of the same files in different orders can be compared.
    fn normal_form(policy: &Policy, files: &[ClosureFile]) -> String {
        let name_of = |id: FileId| files[id.index()].text.path().to_string_lossy().into_owned();
        let sources = |sources: &[Source]| {
            let mut out: Vec<String> = sources
                .iter()
                .map(|s| match s {
                    Source::File { file, index } => format!("{}#{index:?}", name_of(*file)),
                })
                .collect();
            out.sort();
            out
        };
        let list = |items: Vec<(String, Vec<String>)>| format!("{items:?}");
        let fs = |v: &[crate::origin::Sourced<CanonicalPath>]| {
            list(
                v.iter()
                    .map(|s| (s.value.to_string(), sources(&s.sources)))
                    .collect(),
            )
        };
        let pats = |v: &[crate::origin::Sourced<PathPattern>]| {
            list(
                v.iter()
                    .map(|s| (format!("{:?}", s.value), sources(&s.sources)))
                    .collect(),
            )
        };
        format!(
            "{}|{}|{}|{}|{}|{:?}",
            fs(&policy.fs.read),
            fs(&policy.fs.write),
            pats(&policy.fs.deny_read),
            pats(&policy.fs.deny_write),
            list(
                policy
                    .net
                    .allow
                    .iter()
                    .map(|s| (s.value.to_string(), sources(&s.sources)))
                    .collect()
            ),
            policy
                .tls
                .system_trust
                .as_ref()
                .map(|t| (t.value, sources(&t.sources))),
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn merging_in_any_order_gives_the_same_policy(
            configs in proptest::collection::vec(arb_config(), 1..5),
            seed in any::<u64>(),
        ) {
            let names = &NAMES[..configs.len()];
            let forward = as_files(&configs, names);
            let mut order: Vec<usize> = (0..configs.len()).collect();
            // A deterministic shuffle from the seed.
            let mut state = seed | 1;
            for i in (1..order.len()).rev() {
                state ^= state << 13; state ^= state >> 7; state ^= state << 17;
                order.swap(i, (state % (i as u64 + 1)) as usize);
            }
            let shuffled_configs: Vec<ResolvedConfig> = order.iter().map(|&i| configs[i].clone()).collect();
            let shuffled_names: Vec<&str> = order.iter().map(|&i| names[i]).collect();
            let shuffled = as_files(&shuffled_configs, &shuffled_names);
            let a = assert_ok!(merge(&forward));
            let b = assert_ok!(merge(&shuffled));
            prop_assert_eq!(normal_form(&a, &forward), normal_form(&b, &shuffled));
        }

        #[test]
        fn adding_a_file_never_removes_a_deny(
            configs in proptest::collection::vec(arb_config(), 1..4),
            extra in arb_config(),
        ) {
            let names = &NAMES[..configs.len()];
            let before = assert_ok!(merge(&as_files(&configs, names)));
            let mut more = configs.clone();
            more.push(extra);
            let after = assert_ok!(merge(&as_files(&more, &NAMES[..more.len()])));
            for deny in &before.fs.deny_read {
                prop_assert!(after.fs.deny_read.iter().any(|d| d.value == deny.value));
            }
            for deny in &before.fs.deny_write {
                prop_assert!(after.fs.deny_write.iter().any(|d| d.value == deny.value));
            }
        }

        #[test]
        fn adding_a_file_never_turns_a_denied_path_into_an_allowed_one(
            configs in proptest::collection::vec(arb_config(), 1..4),
            extra in arb_config(),
            probe in path_index(),
            write in any::<bool>(),
        ) {
            let access = if write { FsAccess::Write } else { FsAccess::Read };
            let before = assert_ok!(merge(&as_files(&configs, &NAMES[..configs.len()])));
            let mut more = configs.clone();
            more.push(extra);
            let after = assert_ok!(merge(&as_files(&more, &NAMES[..more.len()])));
            let target = cpath(PATHS[probe]);
            if is_denied(&before.decide(&target, access)) {
                prop_assert!(is_denied(&after.decide(&target, access)));
            }
        }

        #[test]
        fn a_deny_beats_every_allow_whatever_the_layers(
            deny_at in path_index(),
            allow_at in proptest::collection::vec(path_index(), 0..4),
            deny_in_base in any::<bool>(),
        ) {
            let denying = config(&[], &[], vec![deny(PATHS[deny_at])], vec![]);
            let allowing = {
                let mut c = ResolvedConfig::default();
                c.fs.write = allow_at.iter().enumerate().map(|(i, &p)| grant(PATHS[p], i as u32)).collect();
                c.fs.read = c.fs.write.clone();
                c
            };
            let (base, project) = if deny_in_base { (denying, allowing) } else { (allowing, denying) };
            let policy = policy(base, project);
            let target = cpath(PATHS[deny_at]);
            prop_assert!(is_denied(&policy.decide(&target, FsAccess::Read)));
            prop_assert!(is_denied(&policy.decide(&target, FsAccess::Write)));
        }

        #[test]
        fn merging_the_same_file_twice_changes_no_value(config in arb_config()) {
            let once = assert_ok!(merge(&as_files(std::slice::from_ref(&config), &["f0"])));
            let twice = assert_ok!(merge(&as_files(&[config.clone(), config], &["f0", "f1"])));
            prop_assert_eq!(
                once.fs.deny_read.iter().map(|d| d.value.clone()).collect::<Vec<_>>(),
                twice.fs.deny_read.iter().map(|d| d.value.clone()).collect::<Vec<_>>()
            );
            prop_assert_eq!(
                once.net.allow.iter().map(|d| d.value.clone()).collect::<Vec<_>>(),
                twice.net.allow.iter().map(|d| d.value.clone()).collect::<Vec<_>>()
            );
            prop_assert_eq!(once.tls.system_trust.map(|t| t.value), twice.tls.system_trust.map(|t| t.value));
        }

        #[test]
        fn every_input_list_value_appears_in_the_output(configs in proptest::collection::vec(arb_config(), 1..4)) {
            let policy = assert_ok!(merge(&as_files(&configs, &NAMES[..configs.len()])));
            for config in &configs {
                for host in &config.net.allow {
                    prop_assert!(policy.net.allow.iter().any(|h| &h.value == host));
                }
                for grant in &config.fs.write {
                    prop_assert!(policy.fs.write.iter().any(|g| g.value == grant.value));
                }
            }
        }

        #[test]
        fn the_merged_system_trust_is_never_looser_than_any_input(configs in proptest::collection::vec(arb_config(), 1..5)) {
            let policy = assert_ok!(merge(&as_files(&configs, &NAMES[..configs.len()])));
            let any_false = configs.iter().any(|c| c.tls.system_trust == Some(false));
            let any_true = configs.iter().any(|c| c.tls.system_trust == Some(true));
            let result = policy.tls.system_trust.map(|t| t.value);
            if any_false {
                prop_assert_eq!(result, Some(false));
            } else if any_true {
                prop_assert_eq!(result, Some(true));
            } else {
                prop_assert_eq!(result, None);
            }
        }

        #[test]
        fn hooks_from_an_ineligible_file_never_reach_the_policy(
            hooked_in_project in any::<bool>(),
            location_index in 0usize..2,
        ) {
            let location = [FileLocation::InProject, FileLocation::Other][location_index];
            let mut c = ResolvedConfig::default();
            let words = vec!["echo".to_owned()];
            c.hooks = vec![assert_ok!(crate::policy::Argv::parse(&words))];
            let layer = if hooked_in_project { Layer::Project } else { Layer::Preset };
            let files = numbered(vec![file("evil", layer, location, c)]);
            // Either the merge refuses, or the hook is absent; it is never merged in.
            match merge(&files) {
                Err(_) => {}
                Ok(policy) => prop_assert!(policy.hooks.is_empty()),
            }
        }
    }
}
