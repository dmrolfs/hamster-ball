// ABOUTME: `hb doctor` end to end: look-alike secret files, tracked secrets and the guard's state, names only.
// ABOUTME: In-process through cli::run with a fixture Environment; the launchd section reads the real launchd and is only checked for shape.
//! Black-box tests of `hb doctor`.

#![cfg(target_os = "macos")]

mod common;

use std::path::Path;
use std::process::{Command, ExitCode, Stdio};

use claims::assert_ok;
use common::{World, write};
use hamster_ball::cli::run;
use pretty_assertions::assert_eq;

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

fn doctor(w: &World) -> (ExitCode, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = run(["hb", "doctor"], Some(&w.env), &mut out, &mut err);
    (
        code,
        String::from_utf8_lossy(&out).into_owned(),
        String::from_utf8_lossy(&err).into_owned(),
    )
}

fn section<'a>(text: &'a str, title: &str) -> &'a str {
    let start = text.find(title).unwrap_or(0);
    let rest = &text[start..];
    let end = rest[title.len()..]
        .find("\n\n")
        .map_or(rest.len(), |i| i + title.len());
    &rest[..end]
}

#[test]
fn doctor_lists_look_alike_files_by_name_and_never_their_contents() {
    let w = World::new(PROJECT);
    write(
        &w.project.join("config/credentials.json"),
        "CONTENTS-MUST-NOT-APPEAR",
    );
    write(
        &w.project.join("deploy/terraform.tfvars"),
        "CONTENTS-MUST-NOT-APPEAR",
    );
    write(&w.project.join(".env"), "CONTENTS-MUST-NOT-APPEAR");
    write(&w.project.join("src/token.rs"), "fn main() {}");
    let (code, out, err) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    let suspects = section(&out, "files that look like secrets");
    assert!(suspects.contains("config/credentials.json"), "{out}");
    assert!(suspects.contains("deploy/terraform.tfvars"), "{out}");
    assert!(
        !suspects.contains(".env"),
        "a guarded file is not a look-alike: {out}"
    );
    assert!(!suspects.contains("token.rs"), "{out}");
    assert!(!out.contains("CONTENTS-MUST-NOT-APPEAR"));
}

#[test]
fn doctor_says_how_the_guard_stands() {
    let w = World::new(PROJECT);
    write(&w.project.join("certs/server.key"), "PRIVATE");
    let (_, out, _) = doctor(&w);
    assert!(out.contains("secrets guard covers"), "{out}");
    assert!(out.contains(&w.project.display().to_string()), "{out}");
    assert!(out.contains("dependency exemption: on"), "{out}");
    assert!(
        out.contains("directories holding secrets are pinned"),
        "{out}"
    );
    assert!(
        out.contains("limit: a directory that gets its first key"),
        "{out}"
    );
}

#[test]
fn doctor_lists_tracked_files_the_guard_would_deny() {
    if !Path::new("/usr/bin/git").exists() {
        return;
    }
    let w = World::new(PROJECT);
    write(&w.project.join(".env"), "T=1");
    write(&w.project.join(".env.local"), "T=2");
    for args in [vec!["init", "-q"], vec!["add", "-f", ".env"]] {
        assert_ok!(
            Command::new("/usr/bin/git")
                .arg("-C")
                .arg(&w.project)
                .args(args)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
        );
    }
    let (_, out, _) = doctor(&w);
    let tracked = section(&out, "tracked files the guard would deny");
    assert!(tracked.contains("/.env"), "{out}");
    assert!(!tracked.contains(".env.local"), "{out}");
}

#[test]
fn doctor_has_a_launchd_section_and_a_clean_project_says_none() {
    let w = World::new(PROJECT);
    let (code, out, _) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(
        out.contains("secret-looking names in the launchd environment"),
        "{out}"
    );
    let suspects = section(&out, "files that look like secrets");
    assert!(suspects.contains("(none)"), "{out}");
}

/// A directory git accepts as a repository, with `config` as its `.git/config`.
fn repository(dir: &Path, config: &str) {
    for sub in [".git/refs", ".git/objects", ".git/hooks"] {
        assert_ok!(std::fs::create_dir_all(dir.join(sub)));
    }
    write(&dir.join(".git/HEAD"), "ref: refs/heads/main\n");
    write(&dir.join(".git/config"), config);
}

#[test]
fn doctor_names_a_nested_repository_a_hook_manager_and_a_hooks_path_but_not_the_projects_own_git() {
    let w = World::new(PROJECT);
    repository(&w.project, "[core]\n\thooksPath = .husky/_\n");
    repository(&w.project.join("vendor/lib"), "");
    assert_ok!(std::fs::create_dir_all(w.project.join(".husky")));
    write(&w.project.join("lefthook.yml"), "");
    let (code, out, err) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS, "{err}");
    let git = section(&out, "git the floor does not protect");
    assert!(git.contains("repository below a write grant:"), "{out}");
    assert!(git.contains("vendor/lib"), "{out}");
    assert!(
        !git.contains(&format!("{}\n", w.project.display())),
        "{out}"
    );
    assert!(git.contains("husky:") && git.contains(".husky"), "{out}");
    assert!(
        git.contains("lefthook:") && git.contains("lefthook.yml"),
        "{out}"
    );
    assert!(
        git.contains("core.hooksPath = .husky/_ (local file:"),
        "{out}"
    );
    assert!(
        git.contains("policy permits the agent to write there"),
        "{out}"
    );
    // The system git configuration is left out on purpose, and the report says it is not clean.
    assert!(git.contains("config_scope_omitted"), "{out}");
    assert!(git.contains("git inspection: partial"), "{out}");
}

#[test]
fn doctor_reports_the_last_hooks_path_and_one_from_an_include_inside_dot_git() {
    let w = World::new(PROJECT);
    repository(&w.project, "");
    write(
        &w.project.join(".git/extra.cfg"),
        "[core]\n\thooksPath = from/include\n",
    );
    write(
        &w.project.join(".git/config"),
        &format!(
            "[core]\n\thooksPath = first\n[include]\n\tpath = {}\n",
            w.project.join(".git/extra.cfg").display()
        ),
    );
    let (_, out, _) = doctor(&w);
    let git = section(&out, "git the floor does not protect");
    assert!(git.contains("core.hooksPath = from/include"), "{out}");
    assert!(!git.contains("core.hooksPath = first"), "{out}");
}

#[test]
fn doctor_does_not_read_an_include_outside_dot_git_and_says_so() {
    let w = World::new(PROJECT);
    repository(&w.project, "");
    write(
        &w.project.join("outside.cfg"),
        "[core]\n\thooksPath = LEAKED-CONTENT\n",
    );
    write(
        &w.project.join(".git/config"),
        &format!(
            "[include]\n\tpath = {}\n",
            w.project.join("outside.cfg").display()
        ),
    );
    let (code, out, _) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(!out.contains("LEAKED-CONTENT"), "{out}");
    let git = section(&out, "git the floor does not protect");
    assert!(git.contains("git_config_unavailable"), "{out}");
    assert!(git.contains("not a clean result"), "{out}");
}

#[test]
fn doctor_survives_a_fifo_config_and_never_runs_hook_or_fsmonitor_canaries() {
    let w = World::new(PROJECT);
    let hook_marker = w.project.join("hook-ran");
    let monitor_marker = w.project.join("monitor-ran");
    let monitor = w.project.join("monitor.sh");
    repository(&w.project, "");
    let hook = w.project.join(".git/hooks/post-checkout");
    for (path, marker) in [(&hook, &hook_marker), (&monitor, &monitor_marker)] {
        write(path, &format!("#!/bin/sh\ntouch '{}'\n", marker.display()));
        assert_ok!(std::fs::set_permissions(
            path,
            std::os::unix::fs::PermissionsExt::from_mode(0o755)
        ));
    }
    write(
        &w.project.join(".git/config"),
        &format!(
            "[core]\n\tfsmonitor = {}\n\thooksPath = {}\n",
            monitor.display(),
            w.project.join(".git/hooks").display()
        ),
    );
    // A nested repository whose config is a FIFO nobody writes to: the doctor must not wait on it.
    let nested = w.project.join("vendor/lib");
    repository(&nested, "");
    assert_ok!(std::fs::remove_file(nested.join(".git/config")));
    assert!(
        assert_ok!(
            Command::new("/usr/bin/mkfifo")
                .arg(nested.join(".git/config"))
                .status()
        )
        .success()
    );
    let started = std::time::Instant::now();
    let (code, out, _) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(30),
        "{:?}",
        started.elapsed()
    );
    let git = section(&out, "git the floor does not protect");
    // The control: the query saw the canary's directory, so the setting was observed, not masked.
    assert!(
        git.contains(&format!(
            "core.hooksPath = {}",
            w.project.join(".git/hooks").display()
        )),
        "{out}"
    );
    assert!(git.contains("git_config_unavailable"), "{out}");
    assert!(!hook_marker.exists() && !monitor_marker.exists());
}

#[test]
fn doctor_with_a_fifo_as_the_projects_own_git_config_finishes_and_says_it_could_not_look() {
    let w = World::new(PROJECT);
    repository(&w.project, "");
    let config = w.project.join(".git/config");
    assert_ok!(std::fs::remove_file(&config));
    assert!(assert_ok!(Command::new("/usr/bin/mkfifo").arg(&config).status()).success());
    let started = std::time::Instant::now();
    let (code, out, _) = doctor(&w);
    // The tracked-files listing is bounded by its own 5 s timeout; the git section is bounded by ours.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(code, ExitCode::SUCCESS);
    let git = section(&out, "git the floor does not protect");
    assert!(git.contains("git_config_unavailable"), "{out}");
    assert!(git.contains("not a clean result"), "{out}");
}

#[test]
fn doctor_says_what_the_policy_allows_for_each_hooks_directory() {
    let w = World::new("[fs]\nwrite = [\".\"]\ndeny_write = [\"vendor/denied/.git/hooks\"]\n");
    repository(&w.project, "[core]\n\thooksPath = .husky/_\n");
    repository(&w.project.join("vendor/open"), "");
    repository(&w.project.join("vendor/denied"), "");
    let (_, out, _) = doctor(&w);
    let git = section(&out, "git the floor does not protect");
    let line = |needle: &str| {
        git.lines()
            .find(|l| l.starts_with("  hooks of") && l.contains(needle))
            .unwrap_or_default()
            .to_owned()
    };
    // A configured directory that does not exist yet is still one the agent could create, and the
    // floor protects only the project's own `.git/hooks`, not a hooks path elsewhere in the project.
    assert!(line("/.husky/_").contains("policy permits"), "{out}");
    assert!(line("vendor/open").contains("policy permits"), "{out}");
    assert!(line("vendor/denied").contains("policy denies"), "{out}");
}

#[test]
fn doctor_reports_the_owners_global_hooks_path_even_with_no_repository() {
    let w = World::new(PROJECT);
    write(
        &w.home_dir().join(".gitconfig"),
        &format!(
            "[core]\n\thooksPath = {}\n",
            w.project.join(".global-hooks").display()
        ),
    );
    let (_, out, _) = doctor(&w);
    let git = section(&out, "git the floor does not protect");
    assert!(
        git.contains("every repository (global git config)"),
        "{out}"
    );
    assert!(git.contains("global file:"), "{out}");
    assert!(
        git.contains("policy permits the agent to write there"),
        "{out}"
    );
}

#[test]
fn doctor_expands_a_tilde_hooks_path_and_assesses_the_real_directory() {
    let w = World::new(PROJECT);
    repository(&w.project, "[core]\n\thooksPath = ~/hk\n");
    let (_, out, _) = doctor(&w);
    let git = section(&out, "git the floor does not protect");
    let line = git
        .lines()
        .find(|l| l.starts_with("  hooks of"))
        .unwrap_or_default();
    // The home directory is not under the project's write grant.
    assert!(
        line.contains(&format!("{}/hk", w.home_dir().display())),
        "{out}"
    );
    assert!(line.contains("no write grant covers it"), "{out}");
    assert!(!line.contains("/~/hk"), "{out}");
}

#[test]
fn doctor_treats_a_link_in_a_writable_directory_as_writable_whatever_it_points_at_today() {
    let w = World::new(PROJECT);
    repository(&w.project, "[core]\n\thooksPath = .husky/_\n");
    let elsewhere = w.home_dir().join("not-granted");
    assert_ok!(std::fs::create_dir_all(&elsewhere));
    assert_ok!(std::os::unix::fs::symlink(
        &elsewhere,
        w.project.join(".husky")
    ));
    let (_, out, _) = doctor(&w);
    let git = section(&out, "git the floor does not protect");
    let line = git
        .lines()
        .find(|l| l.starts_with("  hooks of"))
        .unwrap_or_default();
    assert!(
        line.contains("policy permits the agent to write there"),
        "{out}"
    );
}

#[test]
fn doctor_lists_a_skipped_dependency_directory_as_not_inspected() {
    let w = World::new(PROJECT);
    assert_ok!(std::fs::create_dir_all(
        w.project.join("node_modules/dep/.git")
    ));
    let (_, out, _) = doctor(&w);
    let git = section(&out, "git the floor does not protect");
    assert!(git.contains("directory_not_inspected"), "{out}");
    assert!(git.contains("git inspection: partial"), "{out}");
}

#[test]
fn doctor_stops_at_the_repository_query_cap_and_says_which_it_skipped() {
    let w = World::new(PROJECT);
    // The project's own repository plus 34 nested ones: more than the 32 queried.
    repository(&w.project, "");
    for i in 0..34 {
        repository(&w.project.join(format!("vendor/r{i:02}")), "");
    }
    let (code, out, _) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS);
    let git = section(&out, "git the floor does not protect");
    assert!(git.contains("inspection_limit_reached"), "{out}");
    assert!(git.contains("git inspection: partial"), "{out}");
    // The 33 repositories asked about (the project's and 32 more) are 32 queries: the first 32 are
    // answered, the last two are named as skipped, and the 50-line list says how many it cut.
    assert!(git.contains("vendor/r32"), "{out}");
    assert!(git.contains("vendor/r33"), "{out}");
    assert!(
        !git.contains("inspection_limit_reached: ")
            || git.matches("inspection_limit_reached").count() == 3,
        "{out}"
    );
    assert!(git.contains("... and "), "{out}");
}

#[test]
fn doctor_reports_an_unreadable_subdirectory_as_partial_not_clean() {
    let w = World::new(PROJECT);
    repository(&w.project, "");
    let locked = w.project.join("locked");
    assert_ok!(std::fs::create_dir_all(&locked));
    assert_ok!(std::fs::set_permissions(
        &locked,
        std::os::unix::fs::PermissionsExt::from_mode(0o000)
    ));
    let (code, out, _) = doctor(&w);
    assert_ok!(std::fs::set_permissions(
        &locked,
        std::os::unix::fs::PermissionsExt::from_mode(0o755)
    ));
    assert_eq!(code, ExitCode::SUCCESS);
    let git = section(&out, "git the floor does not protect");
    assert!(git.contains("git inspection: partial"), "{out}");
    assert!(git.contains("directory_unreadable"), "{out}");
    assert!(!git.contains("(none)"), "{out}");
}

#[test]
fn doctor_has_a_git_section_and_a_proxy_section_and_a_plain_project_has_no_git_findings() {
    let w = World::new(PROJECT);
    let (code, out, _) = doctor(&w);
    assert_eq!(code, ExitCode::SUCCESS);
    let git = section(&out, "git the floor does not protect");
    // Nothing found, but the system git configuration is never read, so this is not clean.
    assert!(
        git.contains("no findings in the paths that were inspected"),
        "{out}"
    );
    assert!(git.contains("config_scope_omitted"), "{out}");
    assert!(out.contains("system proxy settings"), "{out}");
}

#[test]
fn doctor_says_whether_the_agent_can_read_the_system_proxy_settings_by_system_trust() {
    let on = World::with_base("[tls]\nsystem_trust = true\n", PROJECT);
    let (_, out, _) = doctor(&on);
    assert!(out.contains("the agent can read these settings"), "{out}");
    assert!(!out.contains("the agent cannot read"), "{out}");
    let off = World::with_base("[tls]\nsystem_trust = false\n", PROJECT);
    let (_, out, _) = doctor(&off);
    assert!(
        out.contains("the agent cannot read these settings"),
        "{out}"
    );
}

#[test]
fn doctor_outside_a_project_is_an_error_that_prints_nothing_to_stdout() {
    let mut w = World::new(PROJECT);
    w.env.cwd = w.home_dir();
    let (code, out, err) = doctor(&w);
    assert_ne!(code, ExitCode::SUCCESS);
    assert_eq!(out, "");
    assert!(!err.is_empty());
}
