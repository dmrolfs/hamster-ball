// ABOUTME: The secrets guard under the real sandbox: guarded names are unreadable and unchangeable, templates and tracked files are not.
// ABOUTME: Ports the spike's bypass cases (rename, copy, link, symlink, parent rename, delete, overwrite, new file, git add -f, case).
//! Black-box tests of the secrets guard (design section 8).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use claims::{assert_err, assert_ok};
use common::{World, hb_succeeds, hb_text, sandbox_available, sh_in_hb, write};
use pretty_assertions::assert_eq;

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// A project with one file of each guarded kind, a template, and ordinary files.
fn world() -> World {
    let w = World::new(PROJECT);
    for (name, text) in [
        (".env", "TOKEN=1"),
        (".env.local", "TOKEN=2"),
        ("config/prod.secrets.yaml", "key: 3"),
        ("config/db_secret.json", "{}"),
        ("certs/server.pem", "PRIVATE"),
        ("certs/id.key", "PRIVATE"),
        ("certs/store.p12", "PRIVATE"),
        (".env.example", "TOKEN="),
        ("config/prod.secrets.yaml.sample", "key: "),
        ("src/main.rs", "fn main() {}"),
        ("notes.txt", "hello"),
    ] {
        write(&w.project.join(name), text);
    }
    w
}

fn works(w: &World, script: &str) {
    let outcome = sh_in_hb(w, script);
    assert!(
        hb_succeeds(&outcome),
        "`{script}` failed: {}",
        hb_text(&outcome)
    );
}

fn blocked(w: &World, script: &str) {
    let outcome = sh_in_hb(w, script);
    assert!(
        !hb_succeeds(&outcome),
        "`{script}` was allowed: {}",
        hb_text(&outcome)
    );
}

fn read_host(w: &World, name: &str) -> String {
    fs::read_to_string(w.project.join(name)).unwrap_or_default()
}

#[test]
fn each_guarded_name_is_unreadable_and_ordinary_files_are_not() {
    sandboxed!();
    let w = world();
    for name in [
        ".env",
        ".env.local",
        "config/prod.secrets.yaml",
        "config/db_secret.json",
        "certs/server.pem",
        "certs/id.key",
        "certs/store.p12",
    ] {
        blocked(&w, &format!("cat {name} > /dev/null"));
    }
    for name in ["src/main.rs", "notes.txt"] {
        works(&w, &format!("cat {name} > /dev/null"));
    }
}

#[test]
fn file_names_stay_visible_but_contents_do_not() {
    sandboxed!();
    let w = world();
    works(&w, "ls -a . certs config > /dev/null");
    works(
        &w,
        "test -e .env && stat .env > /dev/null && ls -l certs/id.key > /dev/null",
    );
    blocked(&w, "head -c 1 .env");
}

#[test]
fn rename_copy_link_symlink_delete_overwrite_and_create_are_all_refused() {
    sandboxed!();
    let w = world();
    for script in [
        "mv .env moved.txt",
        "mv certs/id.key key.txt",
        "cp .env copy.txt",
        "ln .env hard.txt",
        "ln -s .env soft.txt && cat soft.txt",
        "rm .env",
        "rm -f certs/id.key",
        "echo x > .env",
        "echo x >> certs/server.pem",
        "echo x > .env.production",
        "echo x > new.key",
        "touch .env",
        "truncate -s 0 .env",
    ] {
        blocked(&w, script);
    }
    assert_eq!(read_host(&w, ".env"), "TOKEN=1");
    assert_eq!(read_host(&w, "certs/id.key"), "PRIVATE");
    for gone in [
        "moved.txt",
        "key.txt",
        "copy.txt",
        "hard.txt",
        ".env.production",
        "new.key",
    ] {
        assert!(!w.project.join(gone).exists(), "{gone} was created");
    }
}

#[test]
fn a_directory_that_holds_a_secret_cannot_be_renamed_but_a_plain_one_can() {
    sandboxed!();
    let w = world();
    // Pinned by the scan: moving it aside would be the first step of a bypass.
    blocked(&w, "mv certs certs2");
    blocked(&w, "mv config cfg");
    blocked(&w, "rm -rf certs");
    works(
        &w,
        "mkdir plain && echo x > plain/a.txt && mv plain plain2 && cat plain2/a.txt",
    );
    assert!(w.project.join("certs/id.key").exists());
}

#[test]
fn a_secret_cannot_be_given_a_template_name_or_read_under_one() {
    sandboxed!();
    let w = world();
    for script in [
        "mv .env .env.example2 && cat .env.example2",
        "mv .env stolen.example",
        "cp .env stolen.example",
        "ln .env stolen.template",
        "ln -s .env stolen.sample && cat stolen.sample",
        "ln -s ../.env certs/k.example && cat certs/k.example",
    ] {
        blocked(&w, script);
    }
    assert_eq!(read_host(&w, ".env"), "TOKEN=1");
}

#[test]
fn a_case_variant_of_a_guarded_name_is_guarded() {
    sandboxed!();
    let w = world();
    blocked(&w, "cat .ENV > /dev/null");
    blocked(&w, "echo x > .Env.Local2");
    blocked(&w, "cat CERTS/SERVER.PEM > /dev/null");
    blocked(&w, "echo x > Prod.Secrets.YAML");
}

#[test]
fn templates_and_source_files_stay_readable_and_editable() {
    sandboxed!();
    let w = world();
    works(
        &w,
        "cat .env.example config/prod.secrets.yaml.sample > /dev/null",
    );
    works(&w, "echo 'TOKEN=changed' > .env.example");
    works(&w, "echo 'key: new' >> config/prod.secrets.yaml.sample");
    works(
        &w,
        "echo x > new-service.env.template && cat new-service.env.template",
    );
    works(&w, "echo 'fn main() { }' > src/main.rs && rm -f notes.txt");
    assert_eq!(read_host(&w, ".env.example"), "TOKEN=changed\n");
    assert!(!w.project.join("notes.txt").exists());
}

#[test]
fn templates_outside_the_guard_roots_are_not_opened_up() {
    sandboxed!();
    let w = world();
    let outside = tempfile::tempdir_in("/tmp").map(|d| d.keep());
    let outside = assert_ok!(outside);
    write(&outside.join("a.example"), "x");
    blocked(
        &w,
        &format!("cat {} > /dev/null", outside.join("a.example").display()),
    );
    assert_ok!(fs::remove_dir_all(&outside));
}

#[test]
fn git_tracked_files_are_left_readable_and_untracked_ones_are_not() {
    sandboxed!();
    let w = world();
    let git = |args: &[&str]| {
        let status = assert_ok!(
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
        assert!(status.success(), "git {args:?}");
    };
    if !Path::new("/usr/bin/git").exists() {
        return;
    }
    git(&["init", "-q"]);
    git(&["add", "-f", ".env", "certs/server.pem"]);
    works(&w, "cat .env certs/server.pem > /dev/null");
    works(&w, "echo 'TOKEN=edited' > .env");
    blocked(&w, "cat .env.local > /dev/null");
    blocked(&w, "cat certs/id.key > /dev/null");
}

#[test]
fn git_add_force_of_a_secret_is_refused() {
    sandboxed!();
    let w = world();
    if !Path::new("/usr/bin/git").exists() {
        return;
    }
    assert_ok!(
        Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&w.project)
            .args(["init", "-q"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .status()
    );
    blocked(&w, "git add -f .env.local");
    blocked(&w, "git add -f certs/id.key");
}

#[test]
fn an_exception_in_the_user_base_reopens_exactly_what_it_names() {
    sandboxed!();
    let w = world();
    let base = w.home_dir().join(".config/hamster-ball/base.toml");
    let mut text = fs::read_to_string(&base).unwrap_or_default();
    text.push_str(&format!(
        "\n[guard]\nexceptions = [\"{0}/.env.local\", \"{0}/config/*.secrets.yaml\"]\n",
        w.project.display()
    ));
    write(&base, &text);
    works(&w, "cat .env.local config/prod.secrets.yaml > /dev/null");
    works(&w, "echo x >> .env.local");
    blocked(&w, "cat .env > /dev/null");
    blocked(&w, "cat config/db_secret.json > /dev/null");
}

#[test]
fn an_exception_in_a_project_file_is_refused() {
    sandboxed!();
    let w = world();
    w.set_project(&format!(
        "{PROJECT}[guard]\nexceptions = [\"{}/.env\"]\n",
        w.project.display()
    ));
    let error = assert_err!(w.try_loaded());
    assert!(
        snafu::Report::from_error(error)
            .to_string()
            .contains("guard.exceptions"),
        "the error does not name the setting"
    );
}

#[test]
fn a_template_name_does_not_reopen_what_the_floor_protects() {
    sandboxed!();
    let w = world();
    assert_ok!(
        Command::new("/usr/bin/git")
            .arg("-C")
            .arg(&w.project)
            .args(["init", "-q"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .status()
    );
    // git's own sample hooks end in `.sample`, and the floor denies writes under `.git/hooks`.
    blocked(&w, "echo x > .git/hooks/pre-commit.sample");
    blocked(&w, "echo x > .git/hooks/post-merge.example");
}

#[test]
fn a_template_name_does_not_reopen_the_projects_own_denies() {
    sandboxed!();
    let w = World::new(&format!("{PROJECT}deny_write = [\"locked.example\"]\n"));
    write(&w.project.join("locked.example"), "x");
    blocked(&w, "echo y > locked.example");
}

#[test]
fn every_writable_grant_is_guarded_and_a_read_only_one_is_not() {
    sandboxed!();
    let other = assert_ok!(tempfile::tempdir_in("/tmp"));
    let other_path = assert_ok!(fs::canonicalize(other.path()));
    let read_only = assert_ok!(tempfile::tempdir_in("/tmp"));
    let read_only_path = assert_ok!(fs::canonicalize(read_only.path()));
    write(&other_path.join(".env"), "T=1");
    write(&read_only_path.join("ca.pem"), "PUBLIC");
    let w = World::new(&format!(
        "[fs]\nwrite = [\".\", \"{}\"]\nread = [\"{}\"]\n",
        other_path.display(),
        read_only_path.display()
    ));
    blocked(
        &w,
        &format!("cat {}/.env > /dev/null", other_path.display()),
    );
    works(
        &w,
        &format!("cat {}/ca.pem > /dev/null", read_only_path.display()),
    );
}

/// A project whose dependency directories hold files with guarded names, as real packages do.
fn world_with_dependencies() -> World {
    let w = world();
    for name in [
        "node_modules/pkg/fixture.pem",
        "node_modules/pkg/secretsmanager-2017.min.json",
        ".venv/lib/python3.14/site-packages/certifi/cacert.pem",
        "node_modules/pkg/.env",
    ] {
        write(&w.project.join(name), "PUBLIC");
    }
    w
}

#[test]
fn key_and_certificate_files_in_dependency_directories_are_usable() {
    sandboxed!();
    let w = world_with_dependencies();
    works(
        &w,
        "cat node_modules/pkg/fixture.pem node_modules/pkg/secretsmanager-2017.min.json > /dev/null",
    );
    works(
        &w,
        "cat .venv/lib/python3.14/site-packages/certifi/cacert.pem > /dev/null",
    );
    // What an install does: create, write, chmod, set times, replace and delete.
    works(
        &w,
        "d=.venv/lib/python3.14/site-packages/tornado/test; mkdir -p $d && echo x > $d/test.key \
         && chmod 600 $d/test.key && touch -t 202001010101 $d/test.key && cat $d/test.key \
         && rm $d/test.key && rm -rf .venv/lib/python3.14/site-packages/tornado",
    );
    works(
        &w,
        "echo x > node_modules/pkg/new.p12 && rm node_modules/pkg/new.p12 && rm node_modules/pkg/fixture.pem",
    );
}

#[test]
fn the_dependency_exemption_leaves_env_files_and_everything_outside_denied() {
    sandboxed!();
    let w = world_with_dependencies();
    blocked(&w, "cat node_modules/pkg/.env > /dev/null");
    blocked(&w, "echo x > node_modules/pkg/.env.local");
    blocked(&w, "cat certs/server.pem > /dev/null");
    blocked(&w, "echo x > vendor-key.pem");
    blocked(
        &w,
        "mkdir -p node_modules_evil && echo x > node_modules_evil/a.pem",
    );
}

#[test]
fn a_secret_directory_cannot_be_moved_into_a_dependency_directory_to_be_read() {
    sandboxed!();
    let w = world_with_dependencies();
    for script in [
        "mv certs node_modules/pkg/c && cat node_modules/pkg/c/id.key",
        "mv certs/id.key node_modules/pkg/k.key && cat node_modules/pkg/k.key",
        "cp -R certs node_modules/pkg/c",
        "cp certs/id.key node_modules/pkg/k.key",
        "ln certs/id.key node_modules/pkg/k.key",
        "ln -s ../../certs/id.key node_modules/pkg/k.key && cat node_modules/pkg/k.key",
        "ln -s ../../certs node_modules/pkg/c && cat node_modules/pkg/c/id.key",
        "tar -cf ../x.tar certs && tar -xf ../x.tar -C node_modules/pkg && cat node_modules/pkg/certs/id.key",
        "mv .env node_modules/pkg/e.key",
        "mv config node_modules/pkg/config && cat node_modules/pkg/config/db_secret.json",
    ] {
        blocked(&w, script);
    }
    assert_eq!(read_host(&w, "certs/id.key"), "PRIVATE");
    assert_eq!(read_host(&w, ".env"), "TOKEN=1");
    assert_eq!(read_host(&w, "config/db_secret.json"), "{}");
}

#[test]
fn a_project_with_a_secret_directory_beside_the_dependencies_still_installs_packages() {
    sandboxed!();
    let w = world_with_dependencies();
    works(
        &w,
        "mkdir -p node_modules/ssh2/test/fixtures && echo x > node_modules/ssh2/test/fixtures/https_key.pem",
    );
}
