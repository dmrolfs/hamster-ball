// ABOUTME: The real render() under the real sandbox-exec: baseline, floor, pins, network, ports and hostile names.
// ABOUTME: Replaces the test-only profile builder of tests/floor_seatbelt.rs; each denial is paired with an allowed case.
//! Black-box tests of the Seatbelt backend.
//!
//! Each test builds a throwaway home and project, loads the real policy and floor, renders the
//! real profile and runs `/bin/sh` under `sandbox-exec`. Under deny-default "it was blocked"
//! proves little, so every denial has a paired allowed case in the same world.

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::process::Command;

use claims::assert_ok;
use common::{
    World, canonical, quote, run, sandbox_available, stderr, succeeds, toml_string, without_lines,
    write,
};
use hamster_ball::policy::{FloorEffect, Port};
use hamster_ball::seatbelt::{ProxyEndpoint, RenderInputs};
use pretty_assertions::assert_eq;

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

// ====================================================================================
// Baseline
// ====================================================================================

#[test]
fn the_baseline_runs_ordinary_tools_and_the_standard_stream_nodes() {
    sandboxed!();
    let w = World::new(PROJECT);
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    for script in [
        "/usr/bin/true",
        "echo hi",
        "/usr/bin/git --version",
        "echo hi > /dev/stdout; echo hi > /dev/stderr",
        "echo hi | /bin/cat /dev/fd/0",
        "/usr/bin/perl -e 'print 1'",
        "/usr/bin/env",
    ] {
        let out = run(&p, &home, &w.project, script);
        assert!(succeeds(&out), "{script}: {}", stderr(&out));
    }
}

#[test]
fn a_process_can_signal_its_own_children_but_not_other_processes() {
    sandboxed!();
    let w = World::new(PROJECT);
    let p = w.render(&RenderInputs::new());
    let own = run(
        &p,
        &w.home_dir(),
        &w.project,
        "sleep 30 & kill $! && echo killed",
    );
    assert!(succeeds(&own), "{}", stderr(&own));
    // An unrelated same-user process outside the sandbox.
    let mut outside = assert_ok!(Command::new("/bin/sleep").arg("30").spawn());
    let attempt = run(
        &p,
        &w.home_dir(),
        &w.project,
        &format!("kill {}", outside.id()),
    );
    assert!(
        !succeeds(&attempt),
        "must not be able to kill an outside process"
    );
    assert_ok!(outside.kill());
    let _ = outside.wait();
}

#[test]
fn setuid_programs_do_not_run() {
    sandboxed!();
    let w = World::new(PROJECT);
    let p = w.render(&RenderInputs::new());
    // Control: `ps` is setuid and works outside the sandbox, so it is the sandbox that stops it.
    assert!(
        assert_ok!(Command::new("/bin/ps").output())
            .status
            .success()
    );
    assert!(!succeeds(&run(&p, &w.home_dir(), &w.project, "/bin/ps")));
    assert!(succeeds(&run(&p, &w.home_dir(), &w.project, "/bin/ls")));
}

#[test]
fn the_profile_never_grants_keystroke_injection_and_never_uses_the_read_wildcard_in_a_deny() {
    let w = World::new(PROJECT);
    let text = w.render(&RenderInputs::new()).text;
    assert!(!text.contains("hid-control"));
    for line in text.lines().filter(|l| l.starts_with("(deny ")) {
        assert!(!line.contains("file-read*"), "{line}");
    }
}

// ====================================================================================
// The floor under deny-default
// ====================================================================================

#[test]
fn a_granted_ancestor_cannot_reach_credentials_beneath_it_and_stat_does_not_leak() {
    sandboxed!();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string("~/.config")
    ));
    let home = w.home_dir();
    write(&home.join(".config/gh/hosts.yml"), "token: secret\n");
    write(&home.join(".config/other/ok"), "fine");
    let p = w.render(&RenderInputs::new());
    let denied = |script: String| !succeeds(&run(&p, &home, &w.project, &script));
    assert!(denied(format!(
        "cat {}",
        quote(&home.join(".config/gh/hosts.yml"))
    )));
    assert!(denied(format!(
        "echo x > {}",
        quote(&home.join(".config/gh/new"))
    )));
    // `file-read*` would leave these working under the global metadata allow (design D51).
    for tool in [
        "/usr/bin/stat",
        "/bin/ls -ld",
        "/bin/test -e",
        "/usr/bin/xattr -l",
    ] {
        let script = format!("{tool} {}", quote(&home.join(".config/gh/hosts.yml")));
        assert!(denied(script.clone()), "{script} leaked");
    }
    // The paired allowed case: a sibling in the same grant is fully usable.
    let ok = run(
        &p,
        &home,
        &w.project,
        &format!("cat {}", quote(&home.join(".config/other/ok"))),
    );
    assert!(succeeds(&ok), "{}", stderr(&ok));
    // Listing the granted ancestor works; listing the denied directory does not.
    assert!(succeeds(&run(
        &p,
        &home,
        &w.project,
        &format!("/bin/ls {}", quote(&home.join(".config")))
    )));
    assert!(denied(format!(
        "/bin/ls {}",
        quote(&home.join(".config/gh"))
    )));
}

#[test]
fn control_the_shorter_read_wildcard_deny_form_does_leak_stat_under_this_baseline() {
    sandboxed!();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string("~/.config")
    ));
    let home = w.home_dir();
    write(&home.join(".config/gh/hosts.yml"), "token: secret\n");
    let mut p = w.render(&RenderInputs::new());
    let full = "file-read-data file-read-metadata file-read-xattr file-test-existence file-map-executable file-write*";
    assert!(p.text.contains(full), "{}", p.text);
    p.text = p.text.replace(full, "file-read* file-write*");
    let target = quote(&home.join(".config/gh/hosts.yml"));
    // Contents stay protected, but the metadata the global allow grants shows through.
    assert!(!succeeds(&run(
        &p,
        &home,
        &w.project,
        &format!("cat {target}")
    )));
    assert!(
        succeeds(&run(
            &p,
            &home,
            &w.project,
            &format!("/usr/bin/stat {target}")
        )),
        "the control must leak, or the stat test above proves nothing"
    );
}

#[test]
fn a_missing_floor_path_under_a_grant_cannot_be_created_in_any_case() {
    sandboxed!();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string("~/.config")
    ));
    let home = w.home_dir();
    write(&home.join(".config/other/ok"), "x");
    let p = w.render(&RenderInputs::new());
    for name in ["fish/config.fish", "FISH/config.fish"] {
        let script = format!(
            "mkdir -p \"$(dirname {t})\" && echo x > {t}",
            t = quote(&home.join(".config").join(name))
        );
        assert!(!succeeds(&run(&p, &home, &w.project, &script)), "{name}");
    }
    assert!(succeeds(&run(
        &p,
        &home,
        &w.project,
        &format!("echo y > {}", quote(&home.join(".config/other/new")))
    )));
}

#[test]
fn history_style_glob_denies_work_and_unrelated_names_stay_usable() {
    sandboxed!();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\"]\ndeny_read = [{}]\n",
        toml_string("secrets/*.yaml")
    ));
    let proj = w.project.clone();
    write(&proj.join("secrets/a.yaml"), "k: v");
    write(&proj.join("secrets/a.txt"), "fine");
    write(&proj.join("secrets/ayaml"), "decoy");
    write(&proj.join("secrets/a(b|c)+[d].yaml"), "k: v");
    write(&proj.join("secrets/a(b|c)+[d].txt"), "fine");
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    let blocked = |name: &str| {
        !succeeds(&run(
            &p,
            &home,
            &proj,
            &format!("cat {}", quote(&proj.join("secrets").join(name))),
        ))
    };
    assert!(blocked("a.yaml"));
    assert!(blocked("a(b|c)+[d].yaml"));
    // A regex that did not quote its literals would let these through, or block them.
    for fine in ["a.txt", "ayaml", "a(b|c)+[d].txt"] {
        assert!(!blocked(fine), "{fine} must stay readable");
    }
    // A read deny also denies writing (design D34).
    assert!(!succeeds(&run(
        &p,
        &home,
        &proj,
        &format!("echo x > {}", quote(&proj.join("secrets/a.yaml")))
    )));
}

#[test]
fn regex_metacharacters_in_a_denied_base_match_only_themselves_under_the_real_sandbox() {
    sandboxed!();
    // (denied name, a decoy a careless regex would also match)
    let names: [(&str, &str); 10] = [
        ("a.b", "aXb"),
        ("a|b", "a"),
        ("p+l", "ppl"),
        ("[br]acket", "racket"),
        ("(x){2}", "xx"),
        ("^start", "start"),
        ("end$", "end"),
        ("back\\slash", "backslash"),
        ("sp ace", "space"),
        ("caf\u{e9}", "cafe"),
    ];
    let denies: Vec<String> = names
        .iter()
        .map(|(n, _)| toml_string(&format!("hostile/{n}/*.k")))
        .collect();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\"]\ndeny_read = [{}]\n",
        denies.join(", ")
    ));
    let proj = w.project.clone();
    for (name, decoy) in names {
        write(&proj.join("hostile").join(name).join("s.k"), "secret");
        write(&proj.join("hostile").join(decoy).join("s.k"), "decoy");
    }
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    let read = |name: &str| {
        succeeds(&run(
            &p,
            &home,
            &proj,
            &format!(
                "cat {}",
                quote(&proj.join("hostile").join(name).join("s.k"))
            ),
        ))
    };
    for (name, decoy) in names {
        assert!(!read(name), "{name} must be denied");
        assert!(read(decoy), "{decoy} (decoy for {name}) must stay readable");
    }
}

#[test]
fn a_users_own_denies_cannot_be_dodged_by_renaming_their_parent_directory() {
    sandboxed!();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\"]\ndeny_read = [{}]\ndeny_write = [\"vend/secret.txt\"]\n",
        toml_string("secrets/*.yaml")
    ));
    let proj = w.project.clone();
    write(&proj.join("secrets/a.yaml"), "k: v");
    write(&proj.join("vend/secret.txt"), "frozen");
    write(&proj.join("plain/ok.txt"), "fine");
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    let sh = |p: &hamster_ball::seatbelt::Profile, script: &str| run(p, &home, &proj, script);
    // Reading and writing the denied files directly is blocked...
    assert!(!succeeds(&sh(&p, "cat secrets/a.yaml")));
    assert!(!succeeds(&sh(&p, "echo x >> vend/secret.txt")));
    // ...and so is moving their parent aside and reading or writing them at the new name.
    assert!(!succeeds(&sh(
        &p,
        "mv secrets secrets-old && cat secrets-old/a.yaml"
    )));
    assert!(!succeeds(&sh(
        &p,
        "mv vend vend2 && echo x >> vend2/secret.txt"
    )));
    assert!(proj.join("secrets/a.yaml").is_file() && proj.join("vend/secret.txt").is_file());
    // The paired allowed case: an unrelated directory renames freely.
    assert!(succeeds(&sh(&p, "mv plain plain2 && cat plain2/ok.txt")));
    // The control: without the pins the same renames succeed, so the pins are what stop them.
    let unpinned = without_lines(&p, "file-write-unlink");
    assert!(succeeds(&sh(
        &unpinned,
        "mv secrets secrets-old && cat secrets-old/a.yaml"
    )));
    assert!(succeeds(&sh(
        &unpinned,
        "mv vend vend2 && echo x >> vend2/secret.txt"
    )));
}

#[test]
fn the_template_reallow_reopens_a_guard_deny_which_a_wildcard_allow_could_not() {
    sandboxed!();
    let w = World::new(PROJECT);
    let proj = w.project.clone();
    write(&proj.join(".env"), "SECRET=1");
    write(&proj.join(".env.example"), "SECRET=");
    let allow = vec![canonical(&proj.join(".env.example"))];
    let with = w.render(&RenderInputs::new().with_guard_allow(allow));
    let without = w.render(&RenderInputs::new());
    // The secrets guard is milestone 5; inject a deny shaped as the design says (data and xattr
    // plus the write class, so names stay visible) into the Guard section, before the re-allow.
    let canonical_proj = canonical(&proj);
    let quoted = canonical_proj.as_str().replace('.', "\\.");
    let guard = format!(
        "; guard\n(deny file-read-data file-read-xattr file-write* (regex #\"^{quoted}/\\.env.*$\"))\n"
    );
    let with_guard = |p: &hamster_ball::seatbelt::Profile| {
        let mut p = p.clone();
        let at = p.text.find("; template_allow").unwrap_or(p.text.len());
        p.text.insert_str(at, &guard);
        p
    };
    let (with, without) = (with_guard(&with), with_guard(&without));
    let home = w.home_dir();
    let sh =
        |p: &hamster_ball::seatbelt::Profile, script: &str| succeeds(&run(p, &home, &proj, script));
    // The guard denies the secret in both profiles, and leaves its name visible.
    assert!(!sh(&with, "cat .env") && !sh(&without, "cat .env"));
    assert!(
        sh(&with, "/usr/bin/stat .env"),
        "names stay visible under the guard"
    );
    // The re-allowed template is readable and writable only where the re-allow is present.
    assert!(sh(&with, "cat .env.example && echo x >> .env.example"));
    assert!(
        !sh(&without, "cat .env.example"),
        "control: the guard alone denies the template"
    );
}

#[test]
fn a_path_entry_that_contains_the_project_protects_its_children_but_not_the_project() {
    sandboxed!();
    let mut w = World::new(PROJECT);
    let work = w
        .project
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string(&work.to_string_lossy())
    ));
    w.env.floor = w
        .env
        .floor
        .clone()
        .with_path_var(work.clone().into_os_string());
    write(&work.join("tool"), "#!/bin/sh\n");
    write(&work.join("sub/inner"), "x");
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    let sh = |script: String| succeeds(&run(&p, &home, &w.project, &script));
    // A new program directly in the PATH entry, and replacing one, are refused.
    assert!(!sh(format!("echo evil > {}", quote(&work.join("newbin")))));
    assert!(!sh(format!("echo evil > {}", quote(&work.join("tool")))));
    // The project below it, and files deeper than a direct child, stay writable.
    assert!(sh(format!(
        "echo ok > {}",
        quote(&w.project.join("src.txt"))
    )));
    assert!(sh(format!("echo ok > {}", quote(&work.join("sub/inner")))));
}

#[test]
fn a_symlinked_floor_file_is_protected_at_the_link_and_at_its_target() {
    sandboxed!();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\", {}, {}]\n",
        toml_string("~/.cargo"),
        toml_string("~/dotfiles")
    ));
    let home = w.home_dir();
    write(&home.join("dotfiles/cargo-config"), "[build]\n");
    write(&home.join(".cargo/registry/index"), "x");
    assert_ok!(symlink(
        "../dotfiles/cargo-config",
        home.join(".cargo/config.toml")
    ));
    let p = w.render(&RenderInputs::new());
    let sh = |script: String| succeeds(&run(&p, &home, &w.project, &script));
    let link = quote(&home.join(".cargo/config.toml"));
    let target = quote(&home.join("dotfiles/cargo-config"));
    assert!(!sh(format!("echo evil >> {link}")), "through the link");
    assert!(
        !sh(format!("echo evil >> {target}")),
        "the target is protected even though its directory is granted"
    );
    assert!(
        !sh(format!("rm {link} && echo evil > {link}")),
        "swapping the link for a file"
    );
    assert_eq!(
        assert_ok!(fs::read_to_string(home.join("dotfiles/cargo-config"))),
        "[build]\n"
    );
    assert!(assert_ok!(fs::symlink_metadata(home.join(".cargo/config.toml"))).is_symlink());
    // The paired allowed cases: siblings in both granted directories are writable.
    assert!(sh(format!(
        "echo ok > {}",
        quote(&home.join(".cargo/registry/new"))
    )));
    assert!(sh(format!(
        "echo ok > {}",
        quote(&home.join("dotfiles/other"))
    )));
}

#[test]
fn a_symlinked_floor_directory_is_protected_at_the_link_and_the_link_cannot_be_swapped() {
    sandboxed!();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string("~/Library")
    ));
    let home = w.home_dir();
    write(&home.join("dotfiles/LaunchAgents/keep"), "x");
    write(&home.join("Library/other/ok"), "x");
    assert_ok!(symlink(
        "../dotfiles/LaunchAgents",
        home.join("Library/LaunchAgents")
    ));
    let p = w.render(&RenderInputs::new());
    let swap = format!(
        "rm {l} && mkdir {l} && echo evil > {l}/x.plist",
        l = quote(&home.join("Library/LaunchAgents"))
    );
    assert!(!succeeds(&run(&p, &home, &w.project, &swap)));
    assert!(assert_ok!(fs::symlink_metadata(home.join("Library/LaunchAgents"))).is_symlink());
    assert!(succeeds(&run(
        &p,
        &home,
        &w.project,
        &format!("echo y > {}", quote(&home.join("Library/other/new")))
    )));
}

// ====================================================================================
// The project's own files: .git, closure files, the root
// ====================================================================================

#[test]
fn git_hooks_and_config_cannot_be_written_but_the_rest_of_the_project_can() {
    sandboxed!();
    let w = World::new(PROJECT);
    let proj = w.project.clone();
    write(&proj.join(".git/hooks/.keep"), "");
    write(&proj.join(".git/config"), "[core]\n");
    write(&proj.join("src/main.rs"), "");
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    assert!(succeeds(&run(
        &p,
        &home,
        &proj,
        &format!("echo x > {}", quote(&proj.join("src/main.rs")))
    )));
    for target in [
        ".git/hooks/pre-commit",
        ".git/config",
        "hamster-ball.toml",
        ".git/modules/m/hooks/post-merge",
        ".git/commondir",
    ] {
        let script = format!(
            "mkdir -p \"$(dirname {t})\" 2>/dev/null; echo x > {t}",
            t = quote(&proj.join(target))
        );
        assert!(!succeeds(&run(&p, &home, &proj, &script)), "{target}");
    }
    assert!(!proj.join(".git/hooks/pre-commit").exists());
    assert!(!proj.join(".git/commondir").exists());
}

#[test]
fn renaming_git_aside_and_planting_a_pointer_is_blocked_and_the_control_shows_the_pin_is_why() {
    sandboxed!();
    let w = World::new(PROJECT);
    let proj = w.project.clone();
    write(&proj.join(".git/hooks/.keep"), "");
    write(&proj.join(".git/config"), "");
    let attack = format!(
        "mv {git} {old} && mkdir -p {old}/hooks && echo 'gitdir: {old}' > {git}",
        git = quote(&proj.join(".git")),
        old = quote(&proj.join(".git-old")),
    );
    let home = w.home_dir();
    let with_pins = w.render(&RenderInputs::new());
    assert!(!succeeds(&run(&with_pins, &home, &proj, &attack)));
    assert!(proj.join(".git/hooks").is_dir() && !proj.join(".git-old").exists());
    // The control: the same attack with the pins left out succeeds, so the pin is what stopped it.
    let without = w.render_without_pins();
    assert!(succeeds(&run(&without, &home, &proj, &attack)));
}

#[test]
fn creating_a_git_pointer_where_git_is_missing_is_blocked_but_other_files_are_not() {
    sandboxed!();
    let w = World::new(PROJECT);
    let proj = w.project.clone();
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    assert!(!succeeds(&run(
        &p,
        &home,
        &proj,
        &format!("echo 'gitdir: /tmp/evil' > {}", quote(&proj.join(".git")))
    )));
    assert!(succeeds(&run(
        &p,
        &home,
        &proj,
        &format!("echo ok > {}", quote(&proj.join("notes.txt")))
    )));
}

#[test]
fn replacing_git_config_by_rename_is_blocked_but_the_lock_file_is_allowed() {
    sandboxed!();
    let w = World::new(PROJECT);
    let proj = w.project.clone();
    write(&proj.join(".git/config"), "[core]\n");
    let p = w.render(&RenderInputs::new());
    let script = format!(
        "echo evil > {l} && mv {l} {c}",
        l = quote(&proj.join(".git/config.lock")),
        c = quote(&proj.join(".git/config"))
    );
    assert!(!succeeds(&run(&p, &w.home_dir(), &proj, &script)));
    assert_eq!(
        assert_ok!(fs::read_to_string(proj.join(".git/config"))),
        "[core]\n"
    );
    assert_eq!(
        assert_ok!(fs::read_to_string(proj.join(".git/config.lock"))),
        "evil\n"
    );
}

#[test]
fn a_worktree_style_git_file_cannot_be_rewritten_and_its_hooks_stay_protected() {
    sandboxed!();
    let w = World::new(PROJECT);
    let main = w.base.join("main/.git");
    let gitdir = main.join("worktrees/wt");
    write(&gitdir.join("commondir"), "../..\n");
    write(&main.join("hooks/.keep"), "");
    write(&main.join("objects/.keep"), "");
    write(
        &w.project.join(".git"),
        &format!("gitdir: {}\n", gitdir.display()),
    );
    // The agent may write the main repository (objects, refs), as a worktree needs.
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string(&main.to_string_lossy())
    ));
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    let fails = |script: String| !succeeds(&run(&p, &home, &w.project, &script));
    assert!(fails(format!(
        "echo 'gitdir: /elsewhere' > {}",
        quote(&w.project.join(".git"))
    )));
    assert!(fails(format!(
        "echo x > {}",
        quote(&main.join("hooks/pre-commit"))
    )));
    assert!(fails(format!(
        "echo x > {}",
        quote(&gitdir.join("config.worktree"))
    )));
    assert!(fails(format!(
        "echo ../../evil > {}",
        quote(&main.join("commondir"))
    )));
    // The paired allowed case: the object store of the same repository is writable.
    assert!(succeeds(&run(
        &p,
        &home,
        &w.project,
        &format!("echo x > {}", quote(&main.join("objects/new")))
    )));
}

#[test]
fn an_in_project_closure_file_cannot_be_replaced_even_by_renaming_its_directory() {
    sandboxed!();
    let w = World::new("extends = [\"./presets/x.toml\"]\n[fs]\nwrite = [\".\"]\n");
    let proj = w.project.clone();
    write(&proj.join("presets/x.toml"), "");
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    let preset = proj.join("presets/x.toml");
    assert!(!succeeds(&run(
        &p,
        &home,
        &proj,
        &format!("echo evil > {}", quote(&preset))
    )));
    let swap = format!(
        "mv {d} {o} && ln -s {e} {d}",
        d = quote(&proj.join("presets")),
        o = quote(&proj.join("presets-old")),
        e = quote(&proj.join("elsewhere"))
    );
    assert!(!succeeds(&run(&p, &home, &proj, &swap)));
    assert!(preset.is_file());
    // Other directories in the project rename freely.
    write(&proj.join("docs/a.md"), "x");
    assert!(succeeds(&run(
        &p,
        &home,
        &proj,
        &format!(
            "mv {} {}",
            quote(&proj.join("docs")),
            quote(&proj.join("docs2"))
        )
    )));
}

#[test]
fn the_project_directory_cannot_be_renamed_when_an_ancestor_is_granted() {
    sandboxed!();
    let w = World::new(PROJECT);
    let parent = w
        .project
        .parent()
        .map(std::path::Path::to_path_buf)
        .unwrap_or_default();
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string(&parent.to_string_lossy())
    ));
    write(&parent.join("sibling/x"), "x");
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    let mv = |from: &std::path::Path, to: &str| {
        run(
            &p,
            &home,
            &parent,
            &format!("mv {} {}", quote(from), quote(&parent.join(to))),
        )
    };
    assert!(!succeeds(&mv(&w.project, "proj2")));
    assert!(w.project.is_dir());
    // A sibling in the same granted directory renames freely.
    assert!(succeeds(&mv(&parent.join("sibling"), "sibling2")));
}

#[test]
fn a_hard_link_made_inside_to_a_protected_file_is_blocked_but_an_ordinary_one_is_not() {
    sandboxed!();
    let w = World::new(PROJECT);
    let proj = w.project.clone();
    write(&proj.join("ordinary.txt"), "x");
    let p = w.render(&RenderInputs::new());
    let home = w.home_dir();
    assert!(!succeeds(&run(
        &p,
        &home,
        &proj,
        &format!(
            "ln {} {}",
            quote(&proj.join("hamster-ball.toml")),
            quote(&proj.join("alias.toml"))
        )
    )));
    assert!(succeeds(&run(
        &p,
        &home,
        &proj,
        &format!(
            "ln {} {}",
            quote(&proj.join("ordinary.txt")),
            quote(&proj.join("alias.txt"))
        )
    )));
}

#[test]
fn normal_git_work_still_succeeds_under_the_floor() {
    sandboxed!();
    let w = World::new(PROJECT);
    let proj = w.project.clone();
    let git = |args: &[&str]| {
        let out = assert_ok!(
            Command::new("/usr/bin/git")
                .current_dir(&proj)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(args)
                .output()
        );
        assert!(out.status.success(), "{args:?}: {out:?}");
    };
    git(&["init", "-q"]);
    write(&proj.join("a.txt"), "1");
    let p = w.render(&RenderInputs::new());
    let script = format!(
        "cd {proj} && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null && G='/usr/bin/git -c user.name=t -c user.email=t@example.com' && $G add -A && $G commit -q -m one && echo 2 > a.txt && $G commit -q -am two && $G branch feature && $G tag v1 && $G reset -q --hard HEAD~1",
        proj = quote(&proj)
    );
    let out = run(&p, &w.home_dir(), &proj, &script);
    assert!(succeeds(&out), "{}", stderr(&out));
}

// ====================================================================================
// Sockets, network and ports
// ====================================================================================

#[test]
fn a_broad_network_allow_added_earlier_still_cannot_reach_a_container_socket() {
    sandboxed!();
    let w = World::new(PROJECT);
    let socket_dir = w.base.join("tmp/podman");
    assert_ok!(fs::create_dir_all(&socket_dir));
    let socket = socket_dir.join("api.sock");
    let _listener = assert_ok!(UnixListener::bind(&socket));
    let connect = format!("/usr/bin/nc -U -w 1 {} < /dev/null", quote(&socket));
    let home = w.home_dir();
    // Simulate a future broad `network-outbound` allow in an earlier section.
    let broaden = |text: &str| {
        text.replacen(
            "(import \"system.sb\")\n",
            "(import \"system.sb\")\n(allow network*)\n",
            1,
        )
    };
    let mut with_rule = w.render(&RenderInputs::new());
    with_rule.text = broaden(&with_rule.text);
    assert!(
        !succeeds(&run(&with_rule, &home, &w.project, &connect)),
        "the connect rule must stop it"
    );
    // The control: without the DenyConnect rules the same broad allow lets the connect through.
    let loaded = w.loaded();
    let mut without = assert_ok!(hamster_ball::seatbelt::render_filtered(
        &loaded.policy,
        &RenderInputs::new(),
        &|r| r.effect != FloorEffect::DenyConnect
    ));
    without.text = broaden(&without.text);
    assert!(
        succeeds(&run(&without, &home, &w.project, &connect)),
        "control: the broad allow alone connects"
    );
}

#[test]
fn the_ctl_socket_is_reachable_and_no_other_unix_socket_is() {
    sandboxed!();
    let w = World::new(PROJECT);
    let dir = w.base.join("sockets");
    assert_ok!(fs::create_dir_all(&dir));
    let (ctl, other) = (dir.join("ctl.sock"), dir.join("other.sock"));
    let _a = assert_ok!(UnixListener::bind(&ctl));
    let _b = assert_ok!(UnixListener::bind(&other));
    let p = w.render(&RenderInputs::new().with_ctl_socket(canonical(&ctl)));
    let home = w.home_dir();
    let connect = |s: &std::path::Path| {
        succeeds(&run(
            &p,
            &home,
            &w.project,
            &format!("/usr/bin/nc -U -w 1 {} < /dev/null", quote(s)),
        ))
    };
    assert!(connect(&ctl), "the broker socket must be reachable");
    assert!(
        !connect(&other),
        "a sibling socket in the same directory must not be"
    );
}

#[test]
fn only_the_proxy_and_listed_loopback_ports_are_reachable() {
    sandboxed!();
    let proxy = assert_ok!(TcpListener::bind("127.0.0.1:0"));
    let listed = assert_ok!(TcpListener::bind("127.0.0.1:0"));
    let other = assert_ok!(TcpListener::bind("127.0.0.1:0"));
    let port = |l: &TcpListener| assert_ok!(l.local_addr()).port();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\"]\n[net]\nloopback_ports = [{}]\n",
        port(&listed)
    ));
    let inputs = RenderInputs::new().with_proxy(ProxyEndpoint::Port(assert_ok!(Port::try_from(
        i64::from(port(&proxy))
    ))));
    let p = w.render(&inputs);
    let home = w.home_dir();
    let reach = |p_: u16| {
        succeeds(&run(
            &p,
            &home,
            &w.project,
            &format!("/usr/bin/nc -z -w 2 127.0.0.1 {p_}"),
        ))
    };
    assert!(reach(port(&proxy)), "proxy port");
    assert!(reach(port(&listed)), "listed loopback port");
    assert!(
        !reach(port(&other)),
        "an unlisted loopback port must be refused"
    );
    // Direct non-loopback access and DNS fail.
    assert!(!succeeds(&run(
        &p,
        &home,
        &w.project,
        "/usr/bin/nc -z -w 2 1.1.1.1 443"
    )));
    assert!(!succeeds(&run(
        &p,
        &home,
        &w.project,
        "/usr/bin/nc -z -w 2 example.com 443"
    )));
}

#[test]
fn without_a_proxy_slot_no_network_is_reachable_at_all() {
    sandboxed!();
    let any = assert_ok!(TcpListener::bind("127.0.0.1:0"));
    let port = assert_ok!(any.local_addr()).port();
    let w = World::new(PROJECT);
    let p = w.render(&RenderInputs::new());
    assert!(!succeeds(&run(
        &p,
        &w.home_dir(),
        &w.project,
        &format!("/usr/bin/nc -z -w 2 127.0.0.1 {port}")
    )));
}

/// Starts a perl listener under `p` on `bind:port` and returns what an outside client at
/// `connect_to:port` reads, if it could connect.
fn serve_and_fetch(
    p: &hamster_ball::seatbelt::Profile,
    cwd: &std::path::Path,
    bind: &str,
    connect_to: &str,
    port: u16,
) -> Option<String> {
    let script = format!(
        "/usr/bin/perl -MIO::Socket::INET -e '$s=IO::Socket::INET->new(Listen=>1,LocalAddr=>\"{bind}\",LocalPort=>{port},ReuseAddr=>1) or exit 3; $s->timeout(5); $c=$s->accept or exit 4; print $c \"hi\"; exit 0'"
    );
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p")
        .arg(&p.text)
        .args(p.define_args())
        .args(["--", "/bin/sh", "-c", &script]);
    cmd.env_clear().current_dir(cwd);
    let mut server = assert_ok!(cmd.spawn());
    let mut reply = None;
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_millis(150));
        if let Ok(mut s) = TcpStream::connect((connect_to, port)) {
            let mut text = String::new();
            assert_ok!(s.read_to_string(&mut text));
            reply = Some(text);
            break;
        }
    }
    let _ = server.wait();
    reply
}

fn free_port() -> u16 {
    let l = assert_ok!(TcpListener::bind("127.0.0.1:0"));
    assert_ok!(l.local_addr()).port()
}

#[test]
fn an_mcp_server_may_listen_only_on_its_declared_ports_and_an_outside_client_can_reach_it() {
    sandboxed!();
    let (allowed, denied) = (free_port(), free_port());
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\"]\n[mcp.serena]\ncommand = \"uvx\"\nbind_ports = [{allowed}]\n"
    ));
    let p = w.render(&RenderInputs::new());
    // The declared port: the server listens and an outside client connects.
    assert_eq!(
        serve_and_fetch(&p, &w.project, "127.0.0.1", "127.0.0.1", allowed).as_deref(),
        Some("hi")
    );
    // Any other port is refused (perl exits 3 when it cannot bind).
    let other = run(
        &p,
        &w.home_dir(),
        &w.project,
        &format!(
            "/usr/bin/perl -MIO::Socket::INET -e 'IO::Socket::INET->new(Listen=>1,LocalAddr=>\"127.0.0.1\",LocalPort=>{denied}) or exit 3'"
        ),
    );
    assert_eq!(other.status.code(), Some(3), "{}", stderr(&other));
}

/// Characterization of design D58: a port rule does not confine the listener to loopback.
/// If macOS ever changes this, the test fails and the design text and `explain` note must follow.
#[test]
fn a_declared_bind_port_can_be_listened_on_all_interfaces_which_the_design_says_plainly() {
    sandboxed!();
    let Some(lan) = common::lan_address() else {
        eprintln!("SKIP: no LAN address on this machine");
        return;
    };
    if !common::lan_loops_back(&lan) {
        eprintln!(
            "SKIP: this machine cannot reach its own listener at {lan} even without a sandbox"
        );
        return;
    }
    let port = free_port();
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\"]\n[mcp.serena]\ncommand = \"uvx\"\nbind_ports = [{port}]\n"
    ));
    let p = w.render(&RenderInputs::new());
    assert_eq!(
        serve_and_fetch(&p, &w.project, "0.0.0.0", &lan, port).as_deref(),
        Some("hi"),
        "a 0.0.0.0 listener on a declared port is reachable at the LAN address (D58)"
    );
}

/// Characterization of the OS behaviour behind rejecting `bind_ports` below 1024 (D62): any user
/// may bind a privileged port on the wildcard address, and a Seatbelt `localhost:<port>` filter
/// matches every local address. If macOS closes this, the rejection can be relaxed.
#[test]
fn macos_lets_any_user_bind_a_privileged_port_on_every_interface_but_not_on_loopback() {
    let bind = |address: &str| {
        let script = format!(
            "use IO::Socket::INET; my $s = IO::Socket::INET->new(Listen=>1, LocalAddr=>'{address}', LocalPort=>1023); \
             exit 0 if $s; exit 4 if $!{{EADDRINUSE}}; exit 3"
        );
        Command::new("/usr/bin/perl")
            .args(["-e", &script])
            .status()
            .ok()
            .and_then(|s| s.code())
    };
    let wildcard = bind("0.0.0.0");
    if wildcard == Some(4) {
        eprintln!("SKIP: port 1023 is in use");
        return;
    }
    assert_eq!(wildcard, Some(0), "wildcard bind of a privileged port");
    assert_eq!(
        bind("127.0.0.1"),
        Some(3),
        "loopback bind of a privileged port"
    );
}

// ====================================================================================
// Mapping a floor file as code
// ====================================================================================

#[test]
fn a_floor_file_cannot_be_loaded_as_code_but_the_same_library_in_the_project_can() {
    sandboxed!();
    // A system perl extension: a real loadable Mach-O that needs no compiler.
    let bundle = std::path::PathBuf::from(
        "/System/Library/Perl/5.34/darwin-thread-multi-2level/auto/List/Util/Util.bundle",
    );
    if !bundle.exists() {
        eprintln!("SKIP: no perl bundle to load");
        return;
    }
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string("~/.config")
    ));
    let home = w.home_dir();
    let floored = home.join(".config/gh/Util.bundle");
    let open = w.project.join("Util.bundle");
    for target in [&floored, &open] {
        if let Some(parent) = target.parent() {
            assert_ok!(fs::create_dir_all(parent));
        }
        assert_ok!(fs::copy(&bundle, target));
    }
    let p = w.render(&RenderInputs::new());
    let load = |path: &std::path::Path| {
        run(
            &p,
            &home,
            &w.project,
            &format!(
                "/usr/bin/perl -MDynaLoader -e 'DynaLoader::dl_load_file($ARGV[0], 0) or exit 3' {}",
                quote(path)
            ),
        )
    };
    let allowed = load(&open);
    assert!(succeeds(&allowed), "{}", stderr(&allowed));
    assert!(
        !succeeds(&load(&floored)),
        "a floor file was loaded as code"
    );
}

// ====================================================================================
// Hostile names reach the profile only as parameters
// ====================================================================================

#[test]
fn a_directory_name_with_quotes_parentheses_and_a_backslash_is_granted_without_changing_the_profile()
 {
    sandboxed!();
    let w = World::new(PROJECT);
    let dir = w.home_dir().join("data").join("we\"ird (x) ;allow #\"q\\x");
    assert_ok!(fs::create_dir_all(&dir));
    let neighbour = w.home_dir().join("data").join("other");
    assert_ok!(fs::create_dir_all(&neighbour));
    w.set_project(&format!(
        "[fs]\nwrite = [\".\", {}]\n",
        toml_string(&dir.to_string_lossy())
    ));
    let p = w.render(&RenderInputs::new());
    assert!(
        !p.text.contains("we\"ird") && !p.text.contains("allow\nnext"),
        "{}",
        p.text
    );
    assert!(p.params.iter().any(|(_, v)| v == canonical(&dir).as_str()));
    let home = w.home_dir();
    assert!(succeeds(&run(
        &p,
        &home,
        &w.project,
        &format!("echo x > {}/f", quote(&dir))
    )));
    // A neighbour that merely shares a prefix is not granted.
    assert!(!succeeds(&run(
        &p,
        &home,
        &w.project,
        &format!("echo x > {}/f", quote(&neighbour))
    )));
}
