// ABOUTME: hb-dai end to end: `hb warm` publishes one generation; each run gets its own copy and cannot change the published tree or another run.
// ABOUTME: Real sandbox and the real warm path with a fake `uvx` as the MCP server; the fake writes a tree with the shapes uv leaves (links, hard links).
//! Cache isolation (hb-dai).

#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Output, Stdio};

use claims::assert_ok;
use common::{World, quote, sandbox_available, write};
use pretty_assertions::assert_eq;

const DRIVE: &str = env!("CARGO_BIN_EXE_hb-testdrive");
const BASE: &str = "[fs]\nwrite = [\".\"]\n[env]\ntools = [\"uvx\"]\n";
const PROJECT: &str = "[mcp.time]\ncommand = \"uvx\"\nargs = [\"mcp-server-time\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// A fake `uvx`: as the warm probe's server it fills `$UV_CACHE_DIR` the way uv does (an archive,
/// an absolute link to it, a hard-linked pair), then answers `initialize`. As a run's launcher
/// target it just prints the cache it was given.
fn fake_uvx(w: &World) {
    let path = w.base.join("bin/uvx");
    write(
        &path,
        "#!/bin/sh\n\
         if [ -n \"$HB_FAKE_PRINT\" ]; then echo \"cache=$UV_CACHE_DIR\"; exit 0; fi\n\
         mkdir -p \"$UV_CACHE_DIR/archive-v0/aaa\" \"$UV_CACHE_DIR/wheels-v5\" \"$UV_CACHE_DIR/git-v0/db\" \"$UV_CACHE_DIR/git-v0/co\"\n\
         echo trusted > \"$UV_CACHE_DIR/archive-v0/aaa/mod.py\"\n\
         ln -s \"$UV_CACHE_DIR/archive-v0/aaa\" \"$UV_CACHE_DIR/wheels-v5/pkg\"\n\
         echo pack > \"$UV_CACHE_DIR/git-v0/db/pack\"\n\
         ln \"$UV_CACHE_DIR/git-v0/db/pack\" \"$UV_CACHE_DIR/git-v0/co/pack\"\n\
         read line\n\
         echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}'\n\
         sleep 20\n",
    );
    assert_ok!(fs::set_permissions(
        &path,
        fs::Permissions::from_mode(0o755)
    ));
}

fn world() -> World {
    let w = World::with_base(BASE, PROJECT);
    fake_uvx(&w);
    w
}

fn hb(w: &World, args: &[&str]) -> Output {
    assert_ok!(w.drive(DRIVE, args).stdin(Stdio::null()).output())
}

fn text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn store(w: &World) -> PathBuf {
    w.home_dir().join(".cache/hamster-ball")
}

/// The one published generation's `data` directory.
fn published(w: &World) -> PathBuf {
    let mut all: Vec<PathBuf> = assert_ok!(fs::read_dir(store(w).join("generations")))
        .flatten()
        .map(|e| e.path().join("data"))
        .collect();
    all.sort();
    assert_eq!(all.len(), 1, "one generation: {all:?}");
    all.remove(0)
}

fn warm(w: &World) {
    let out = hb(w, &["warm"]);
    assert_eq!(out.status.code(), Some(0), "{}", text(&out));
}

fn run(w: &World, script: &str) -> Output {
    assert_ok!(
        w.drive(DRIVE, &["run", "--", "/bin/sh", "-c", script])
            .output()
    )
}

/// Every file under `root` with its bytes, links by target, for before/after comparison.
fn tree(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in assert_ok!(fs::read_dir(&dir)).flatten() {
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            let meta = assert_ok!(fs::symlink_metadata(&path));
            if meta.file_type().is_symlink() {
                out.push((
                    rel,
                    format!("-> {}", assert_ok!(fs::read_link(&path)).display()),
                ));
            } else if meta.is_dir() {
                stack.push(path);
            } else {
                out.push((
                    rel,
                    String::from_utf8_lossy(&assert_ok!(fs::read(&path))).into_owned(),
                ));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn a_warmed_generation_has_closed_relative_links_and_no_shared_inodes() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    eprintln!(
        "DEBUG tree: {:?}\nSEEN: {}",
        tree(&data),
        fs::read_to_string(w.project.join("seen.txt")).unwrap_or_default()
    );
    let target = assert_ok!(fs::read_link(data.join("uv/wheels-v5/pkg")));
    assert!(
        target.is_relative(),
        "the absolute link was rewritten relative: {}",
        target.display()
    );
    assert_eq!(
        assert_ok!(fs::read_to_string(data.join("uv/wheels-v5/pkg/mod.py"))),
        "trusted\n"
    );
    assert!(
        assert_ok!(fs::canonicalize(data.join("uv/wheels-v5/pkg")))
            .starts_with(assert_ok!(fs::canonicalize(&data))),
        "the link resolves inside the generation"
    );
    let (a, b) = (
        assert_ok!(fs::metadata(data.join("uv/git-v0/db/pack"))),
        assert_ok!(fs::metadata(data.join("uv/git-v0/co/pack"))),
    );
    assert_ne!(a.ino(), b.ino(), "the hard-linked pair became two files");
    assert_eq!((a.nlink(), b.nlink()), (1, 1));
    assert_eq!(
        assert_ok!(fs::metadata(&data)).mode() & 0o777,
        0o700,
        "private"
    );
}

#[test]
fn a_runs_copy_is_independent_through_every_link_the_warm_left_in_it() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    let before = tree(&data);
    // Write through the relative link and through both former hard-link names, and add and remove
    // files; then compare the published tree.
    let out = run(
        &w,
        "c=\"$TMPDIR/cache/uv\"; echo POISON > \"$c/wheels-v5/pkg/mod.py\"; \
         echo POISON > \"$c/git-v0/co/pack\"; echo POISON > \"$c/git-v0/db/pack\"; \
         rm \"$c/archive-v0/aaa/mod.py\"; echo new > \"$c/added\"",
    );
    assert!(out.status.success(), "{}", text(&out));
    assert_eq!(tree(&data), before, "the published generation is unchanged");
    let again = run(
        &w,
        "c=\"$TMPDIR/cache/uv\"; cat \"$c/archive-v0/aaa/mod.py\" \"$c/git-v0/co/pack\"; ls \"$c\"",
    );
    let said = text(&again);
    assert!(
        said.starts_with("trusted\npack\n"),
        "a later run starts from the published bytes: {said}"
    );
    assert!(
        !said.contains("added"),
        "and has none of the earlier run's files: {said}"
    );
}

#[test]
fn two_runs_at_the_same_time_write_to_different_copies() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    let before = tree(&data);
    let slow = |tag: &str| {
        let mut cmd = w.drive(
            DRIVE,
            &[
                "run",
                "--",
                "/bin/sh",
                "-c",
                &format!(
                    "echo {tag} > \"$TMPDIR/cache/uv/who\"; sleep 2; cat \"$TMPDIR/cache/uv/who\""
                ),
            ],
        );
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        assert_ok!(cmd.spawn())
    };
    let (first, second) = (slow("one"), slow("two"));
    let (a, b) = (
        assert_ok!(first.wait_with_output()),
        assert_ok!(second.wait_with_output()),
    );
    assert_eq!(
        String::from_utf8_lossy(&a.stdout).trim(),
        "one",
        "{}",
        text(&a)
    );
    assert_eq!(
        String::from_utf8_lossy(&b.stdout).trim(),
        "two",
        "{}",
        text(&b)
    );
    assert_eq!(tree(&data), before);
}

#[test]
fn the_ball_cannot_reach_the_store_by_any_path_and_the_copy_is_the_only_cache_it_has() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    let before = tree(&data);
    let s = store(&w);
    let out = run(
        &w,
        &format!(
            "ls {s} 2>&1; cat {d}/uv/archive-v0/aaa/mod.py 2>&1; echo x > {d}/uv/new 2>&1; \
             ln {d}/uv/archive-v0/aaa/mod.py \"$TMPDIR/stolen\" 2>&1; rm -rf {d} 2>&1; \
             mkdir {s}/generations/evil 2>&1; echo x > {s}/projects/current 2>&1; true",
            s = quote(&s),
            d = quote(&data)
        ),
    );
    let said = text(&out);
    assert!(
        said.matches("Operation not permitted").count() >= 6,
        "every reach into the store is refused: {said}"
    );
    assert!(
        !said.contains("trusted"),
        "no byte of the generation was read: {said}"
    );
    assert_eq!(tree(&data), before);
    assert!(!s.join("generations/evil").exists());
}

#[test]
fn a_failed_warm_leaves_the_previous_generation_current_and_no_workspace_or_staging_behind() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    let before = tree(&data);
    write(
        &w.base.join("bin/uvx"),
        "#!/bin/sh\nmkdir -p \"$UV_CACHE_DIR/half\"; echo partial > \"$UV_CACHE_DIR/half/f\"\necho 'boom' >&2\nexit 3\n",
    );
    assert_ok!(fs::set_permissions(
        w.base.join("bin/uvx"),
        fs::Permissions::from_mode(0o755)
    ));
    let out = hb(&w, &["warm"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert_eq!(
        published(&w),
        data,
        "still exactly one generation, the old one"
    );
    assert_eq!(tree(&data), before);
    let staging = fs::read_dir(store(&w).join("staging")).map_or(0, Iterator::count);
    assert_eq!(staging, 0, "no staging copy is left behind");
    let temp = fs::read_dir(w.base.join("tmp")).map_or(0, Iterator::count);
    assert_eq!(temp, 0, "the workspace is removed");
}

#[test]
fn a_second_warm_publishes_a_new_generation_and_the_first_stays_on_disk_unchanged() {
    sandboxed!();
    let w = world();
    warm(&w);
    let first = published(&w);
    let before = tree(&first);
    warm(&w);
    let all = assert_ok!(fs::read_dir(store(&w).join("generations"))).count();
    assert_eq!(all, 2, "nothing is deleted automatically");
    assert_eq!(tree(&first), before);
}

#[test]
fn tampering_with_a_published_manifest_is_refused_before_the_agent_starts() {
    sandboxed!();
    let w = world();
    warm(&w);
    let manifest = published(&w)
        .parent()
        .map(|g| g.join("manifest.json"))
        .unwrap_or_default();
    let good = assert_ok!(fs::read(&manifest));
    assert_ok!(fs::write(&manifest, [good, b" ".to_vec()].concat()));
    let out = run(&w, "echo agent-started");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("agent-started"), "{}", text(&out));
    assert!(text(&out).contains("hb warm"), "{}", text(&out));
}

#[test]
fn a_payload_edited_after_publication_is_refused_even_though_the_manifest_still_matches() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    // As a same-user process outside any ball could: edit a published file in place. The manifest
    // and the current record are untouched, so only the content digest can notice.
    let victim = data.join("uv/archive-v0/aaa/mod.py");
    assert_ok!(fs::set_permissions(
        &victim,
        fs::Permissions::from_mode(0o600)
    ));
    assert_ok!(fs::write(&victim, "backdoor\n"));
    let out = run(&w, "echo agent-started");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("agent-started"), "{}", text(&out));
    assert!(
        text(&out).contains("stale") && text(&out).contains("contents"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_legacy_cache_next_to_a_new_generation_is_ignored_and_never_deleted() {
    sandboxed!();
    let w = world();
    write(&store(&w).join("uv/legacy"), "old mutable cache");
    warm(&w);
    let out = run(&w, "ls \"$TMPDIR/cache/uv\"");
    assert!(out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("legacy"), "{}", text(&out));
    assert_eq!(
        assert_ok!(fs::read_to_string(store(&w).join("uv/legacy"))),
        "old mutable cache"
    );
}

#[test]
fn a_warm_that_answers_but_builds_something_unsealable_publishes_nothing_and_cleans_up() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    let before = tree(&data);
    // The server answers, but leaves a link that points outside the tree: sealing must refuse it.
    write(
        &w.base.join("bin/uvx"),
        "#!/bin/sh\nmkdir -p \"$UV_CACHE_DIR/archive-v0\"; echo ok > \"$UV_CACHE_DIR/archive-v0/f\"\n\
         ln -s /etc/passwd \"$UV_CACHE_DIR/escape\"\nread line\n\
         echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}'\nsleep 20\n",
    );
    assert_ok!(fs::set_permissions(
        w.base.join("bin/uvx"),
        fs::Permissions::from_mode(0o755)
    ));
    let out = hb(&w, &["warm"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        text(&out).contains("cannot be part of a cache generation"),
        "{}",
        text(&out)
    );
    assert_eq!(
        published(&w),
        data,
        "the old generation is still the only one"
    );
    assert_eq!(tree(&data), before);
    let staging = fs::read_dir(store(&w).join("staging")).map_or(0, Iterator::count);
    assert_eq!(staging, 0, "the half-built staging copy was removed");
    assert_eq!(
        fs::read_dir(w.base.join("tmp")).map_or(0, Iterator::count),
        0
    );
}

/// F7 probe: a project that is granted write access to the per-user temp directory (the parent
/// of every session directory) can reach another run's private copy and a warm workspace.
fn grant_temp_world() -> World {
    let w = World::with_base(BASE, PROJECT);
    fake_uvx(&w);
    let temp = fs::canonicalize(w.base.join("tmp")).unwrap_or_else(|_| w.base.join("tmp"));
    w.set_base(&format!(
        "[fs]\nwrite = [\".\", \"{}\"]\n[env]\ntools = [\"uvx\"]\n",
        temp.display()
    ));
    w
}

#[test]
fn a_grant_that_covers_the_shared_temp_directory_is_refused_before_anything_starts() {
    sandboxed!();
    let w = grant_temp_world();
    warm_expect_refusal(&w);
    let out = run(&w, "echo agent-started");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("agent-started"), "{}", text(&out));
    assert!(
        text(&out).contains("where every run keeps its private directory"),
        "{}",
        text(&out)
    );
}

fn warm_expect_refusal(w: &World) {
    let out = hb(w, &["warm"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        text(&out).contains("where every run keeps its private directory"),
        "warm is refused too: {}",
        text(&out)
    );
}

#[test]
fn a_read_grant_over_the_shared_temp_directory_is_refused_too_because_it_exposes_credentials() {
    sandboxed!();
    let w = World::with_base(BASE, PROJECT);
    fake_uvx(&w);
    let temp = fs::canonicalize(w.base.join("tmp")).unwrap_or_else(|_| w.base.join("tmp"));
    w.set_base(&format!(
        "[fs]\nwrite = [\".\"]\nread = [\"{}\"]\n[env]\ntools = [\"uvx\"]\n",
        temp.display()
    ));
    let out = hb(&w, &["warm"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("overlaps"), "{}", text(&out));
}

#[test]
fn a_project_grant_inside_the_project_and_one_beside_the_temp_directory_still_work() {
    sandboxed!();
    let w = World::with_base(BASE, PROJECT);
    fake_uvx(&w);
    let sibling = w.base.join("tmp-not-the-temp-dir");
    assert_ok!(fs::create_dir_all(&sibling));
    let sibling = fs::canonicalize(&sibling).unwrap_or(sibling);
    w.set_base(&format!(
        "[fs]\nwrite = [\".\", \"{}\"]\n[env]\ntools = [\"uvx\"]\n",
        sibling.display()
    ));
    warm(&w);
    let out = run(&w, "echo ok");
    assert!(out.status.success(), "{}", text(&out));
}

/// `~/.cache` is a link to `~/redirect/current`, which is a link to a real directory; `redirect`
/// is in a write grant, so the agent can repoint `current`. Returns the world and the paths.
fn redirected_store(granted: bool) -> (World, PathBuf, PathBuf) {
    let w = World::with_base(BASE, PROJECT);
    fake_uvx(&w);
    let home = w.home_dir();
    let (redirect, real) = (home.join("redirect"), home.join("real-cache"));
    assert_ok!(fs::create_dir_all(&redirect));
    assert_ok!(fs::create_dir_all(&real));
    assert_ok!(std::os::unix::fs::symlink(&real, redirect.join("current")));
    assert_ok!(std::os::unix::fs::symlink(
        redirect.join("current"),
        home.join(".cache")
    ));
    let grant = if granted { ", \"~/redirect\"" } else { "" };
    w.set_base(&format!(
        "[fs]\nwrite = [\".\"{grant}]\n[env]\ntools = [\"uvx\"]\n"
    ));
    (w, redirect, real)
}

#[test]
fn a_store_reached_through_a_link_the_ball_can_rewrite_is_refused() {
    sandboxed!();
    let (w, _redirect, real) = redirected_store(true);
    let out = hb(&w, &["warm"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(
        text(&out).contains("lets a run rewrite it") && text(&out).contains("redirect/current"),
        "names the link: {}",
        text(&out)
    );
    assert!(
        !real.join("hamster-ball").exists(),
        "nothing was written through the writable link"
    );
}

#[test]
fn a_run_also_refuses_a_store_a_grant_can_redirect_even_when_a_generation_already_exists() {
    sandboxed!();
    // Warm while nothing can rewrite the link, then widen the grant: the run must notice.
    let (w, _redirect, _real) = redirected_store(false);
    warm(&w);
    let home = w.home_dir();
    w.set_base(&format!(
        "[fs]\nwrite = [\".\", \"{}\"]\n[env]\ntools = [\"uvx\"]\n",
        home.join("redirect").display()
    ));
    let out = run(&w, "echo agent-started");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("agent-started"), "{}", text(&out));
    assert!(
        text(&out).contains("lets a run rewrite it"),
        "{}",
        text(&out)
    );
}

#[test]
fn a_store_reached_through_a_link_nothing_can_write_works_and_stays_protected() {
    sandboxed!();
    let (w, _redirect, real) = redirected_store(false);
    warm(&w);
    assert!(real.join("hamster-ball/generations").exists());
    let out = run(
        &w,
        &format!("ls {} 2>&1; true", quote(&real.join("hamster-ball"))),
    );
    assert!(
        text(&out).contains("Operation not permitted"),
        "{}",
        text(&out)
    );
}

/// A grant INSIDE the shared temp directory (a peer's exact session directory, say) is as bad as
/// one over it: the ball is given the peer's whole subtree.
#[test]
fn a_grant_inside_the_shared_temp_directory_is_refused_too() {
    sandboxed!();
    let w = World::with_base(BASE, PROJECT);
    fake_uvx(&w);
    let temp = fs::canonicalize(w.base.join("tmp")).unwrap_or_else(|_| w.base.join("tmp"));
    let peer = temp.join("hb-1-2-3");
    assert_ok!(fs::create_dir_all(&peer));
    w.set_base(&format!(
        "[fs]\nwrite = [\".\", \"{}\"]\n[env]\ntools = [\"uvx\"]\n",
        peer.display()
    ));
    let out = hb(&w, &["warm"]);
    assert_ne!(out.status.code(), Some(0), "{}", text(&out));
    assert!(text(&out).contains("overlaps"), "{}", text(&out));
}

/// The store check applies to a run that never uses the cache (an absolute-path server only).
#[test]
fn a_run_with_no_cache_still_refuses_a_store_a_grant_can_redirect() {
    sandboxed!();
    let w = World::with_base(BASE, "[mcp.local]\ncommand = \"/usr/bin/true\"\n");
    fake_uvx(&w);
    let home = w.home_dir();
    let (redirect, real) = (home.join("redirect"), home.join("real-cache"));
    assert_ok!(fs::create_dir_all(&redirect));
    assert_ok!(fs::create_dir_all(&real));
    assert_ok!(std::os::unix::fs::symlink(&real, redirect.join("current")));
    assert_ok!(std::os::unix::fs::symlink(
        redirect.join("current"),
        home.join(".cache")
    ));
    w.set_base(&format!(
        "[fs]\nwrite = [\".\", \"{}\"]\n[env]\ntools = [\"uvx\"]\n",
        redirect.display()
    ));
    let out = run(&w, "echo agent-started");
    assert!(!out.status.success(), "{}", text(&out));
    assert!(!text(&out).contains("agent-started"), "{}", text(&out));
    assert!(
        text(&out).contains("lets a run rewrite it"),
        "{}",
        text(&out)
    );
}

/// The warm's own server replaces the tool while it runs (the project directory is writable and
/// is where this fake `uvx` lives). What was built came from the OLD tool, so it must not be
/// published under the NEW tool's identity, where a run with the new tool would accept it.
#[test]
fn a_tool_replaced_while_the_servers_ran_publishes_nothing() {
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    let before = tree(&data);
    // A tool directory the ball cannot write; the swap happens from outside, driven by the test:
    // the server blocks on a file the test creates after replacing the tool.
    write(
        &w.base.join("bin/uvx"),
        "#!/bin/sh\n\
         mkdir -p \"$UV_CACHE_DIR/archive-v0\"; echo old-tool-output > \"$UV_CACHE_DIR/archive-v0/f\"\n\
         touch ready.flag\n\
         while [ ! -f go.flag ]; do sleep 0.2; done\n\
         read line\n\
         echo '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"capabilities\":{}}}'\n\
         sleep 20\n",
    );
    assert_ok!(fs::set_permissions(
        w.base.join("bin/uvx"),
        fs::Permissions::from_mode(0o755)
    ));
    let mut cmd = w.drive(DRIVE, &["warm"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = assert_ok!(cmd.spawn());
    for _ in 0..100 {
        if w.project.join("ready.flag").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(w.project.join("ready.flag").exists(), "the server started");
    // Replace the tool, then let the server finish.
    let tool = w.base.join("bin/uvx");
    let current = assert_ok!(fs::read_to_string(&tool));
    write(&tool, &format!("{current}\n# a different tool\n"));
    assert_ok!(fs::set_permissions(
        &tool,
        fs::Permissions::from_mode(0o755)
    ));
    write(&w.project.join("go.flag"), "");
    let out = assert_ok!(child.wait_with_output());
    let said = text(&out);
    assert_ne!(out.status.code(), Some(0), "{said}");
    assert!(said.contains("changed while hb warm was running"), "{said}");
    assert_eq!(published(&w), data, "still exactly the first generation");
    assert_eq!(tree(&data), before);
}

/// `hb warm` is killed with SIGKILL while its server is still running (the longest window before
/// sealing): nothing may be published, nothing selectable may exist, and the next `hb warm`
/// must work (the lock dies with the process) and publish normally.
#[test]
fn a_warm_killed_with_sigkill_publishes_nothing_leaves_nothing_selectable_and_the_next_warm_works()
{
    sandboxed!();
    let w = world();
    warm(&w);
    let data = published(&w);
    let before = tree(&data);
    write(
        &w.base.join("bin/uvx"),
        "#!/bin/sh\nmkdir -p \"$UV_CACHE_DIR/archive-v0\"; echo partial > \"$UV_CACHE_DIR/archive-v0/f\"\n\
         touch ready.flag\nsleep 60\n",
    );
    assert_ok!(fs::set_permissions(
        w.base.join("bin/uvx"),
        fs::Permissions::from_mode(0o755)
    ));
    let mut cmd = w.drive(DRIVE, &["warm"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = assert_ok!(cmd.spawn());
    for _ in 0..100 {
        if w.project.join("ready.flag").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(w.project.join("ready.flag").exists(), "the server started");
    assert_ok!(child.kill());
    let _ = child.wait();
    std::thread::sleep(std::time::Duration::from_millis(500));
    assert_eq!(published(&w), data, "still exactly the first generation");
    assert_eq!(tree(&data), before);
    // Put the original tool back: the old generation was built with it, so it serves runs again.
    fake_uvx(&w);
    let out = run(&w, "echo still-runs");
    assert!(
        out.status.success() && text(&out).contains("still-runs"),
        "the old generation still serves runs: {}",
        text(&out)
    );
    // The lock died with the process; the next warm is not "already running".
    let again = hb(&w, &["warm"]);
    assert_eq!(again.status.code(), Some(0), "{}", text(&again));
    assert!(
        !text(&again).contains("already running"),
        "{}",
        text(&again)
    );
    let generations = assert_ok!(fs::read_dir(store(&w).join("generations"))).count();
    assert_eq!(
        generations, 2,
        "the first and the new one, nothing half-built"
    );
}
