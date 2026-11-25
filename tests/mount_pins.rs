// ABOUTME: Mount pins under the real sandbox-exec: the swap attempts that must fail and the normal work that must still succeed.
// ABOUTME: Every blocked case has an unpinned control in the same world, so "blocked" is the pin and not the baseline.
//! hb-ghd.8.3: pinning bind-mount sources so `podman restart` cannot be pointed somewhere else.

#![cfg(target_os = "macos")]

mod common;

use std::fs;

use claims::assert_ok;
use common::{World, canonical, quote, run, sandbox_available, succeeds, write};
use hamster_ball::seatbelt::RenderInputs;

const PROJECT: &str = "[fs]\nwrite = [\".\"]\n";

macro_rules! sandboxed {
    () => {
        if !sandbox_available() {
            return;
        }
    };
}

/// A project with a directory mount source (`var/data`) and a file mount source (`cfg/app.yaml`).
fn pinned_world() -> World {
    let w = World::new(PROJECT);
    write(&w.project.join("var/data/keep"), "k");
    write(&w.project.join("cfg/app.yaml"), "a");
    w
}

fn pins(w: &World) -> RenderInputs {
    RenderInputs::new().with_mount_pins(vec![
        canonical(&w.project.join("var/data")),
        canonical(&w.project.join("cfg/app.yaml")),
    ])
}

/// Runs `script` pinned (expected to fail) and unpinned in a fresh copy (expected to succeed).
fn blocked_by_the_pin(attempt: &str, script: impl Fn(&World) -> String) {
    let pinned = pinned_world();
    let p = pinned.render(&pins(&pinned));
    let out = run(&p, &pinned.home_dir(), &pinned.project, &script(&pinned));
    assert!(!succeeds(&out), "{attempt}: should be blocked by the pin");

    let control = pinned_world();
    let p = control.render(&RenderInputs::new());
    let out = run(&p, &control.home_dir(), &control.project, &script(&control));
    assert!(
        succeeds(&out),
        "{attempt}: control without the pin must succeed"
    );
}

fn allowed_with_the_pin(case: &str, script: impl Fn(&World) -> String) {
    let w = pinned_world();
    let p = w.render(&pins(&w));
    let out = run(&p, &w.home_dir(), &w.project, &script(&w));
    assert!(succeeds(&out), "{case}: normal work must still succeed");
}

fn path(w: &World, rel: &str) -> String {
    quote(&w.project.join(rel))
}

#[test]
fn the_swap_attempts_are_blocked() {
    sandboxed!();
    blocked_by_the_pin("rename the mounted directory", |w| {
        format!("mv {} {}", path(w, "var/data"), path(w, "var/data2"))
    });
    blocked_by_the_pin("remove the mounted directory", |w| {
        format!("rm -r {}", path(w, "var/data"))
    });
    blocked_by_the_pin("rename the directory above the mount", |w| {
        format!("mv {} {}", path(w, "var"), path(w, "var2"))
    });
    // `mv` would move a directory into an existing one, so call rename(2) itself onto an empty directory.
    blocked_by_the_pin("rename another directory over the mount", |w| {
        format!(
            "rm {keep} && mkdir {new} && /usr/bin/perl -e 'rename($ARGV[0], $ARGV[1]) or die $!' {new} {data}",
            keep = path(w, "var/data/keep"),
            new = path(w, "var/new"),
            data = path(w, "var/data")
        )
    });
    blocked_by_the_pin("rename the mounted file", |w| {
        format!("mv {} {}", path(w, "cfg/app.yaml"), path(w, "cfg/x"))
    });
    blocked_by_the_pin("remove the mounted file", |w| {
        format!("rm {}", path(w, "cfg/app.yaml"))
    });
}

#[test]
fn a_hard_link_made_from_a_mounted_file_is_blocked() {
    sandboxed!();
    blocked_by_the_pin("hard link from the mounted file", |w| {
        format!("ln {} {}", path(w, "cfg/app.yaml"), path(w, "cfg/alias"))
    });
}

#[test]
fn a_file_mount_cannot_be_saved_by_atomic_rename_but_an_unmounted_neighbour_can() {
    sandboxed!();
    blocked_by_the_pin("atomic save over the mounted file", |w| {
        format!(
            "echo n > {1} && mv {1} {0}",
            path(w, "cfg/app.yaml"),
            path(w, "cfg/tmp")
        )
    });
    allowed_with_the_pin("atomic save of an unmounted neighbour", |w| {
        format!(
            "echo a > {0} && echo n > {1} && mv {1} {0}",
            path(w, "cfg/other.yaml"),
            path(w, "cfg/other.tmp")
        )
    });
}

#[test]
fn normal_work_around_the_mounts_still_succeeds() {
    sandboxed!();
    allowed_with_the_pin("edit the mounted file in place", |w| {
        format!("echo b >> {}", path(w, "cfg/app.yaml"))
    });
    allowed_with_the_pin("rewrite the mounted file in place", |w| {
        format!("echo b > {}", path(w, "cfg/app.yaml"))
    });
    allowed_with_the_pin("write inside the mounted directory", |w| {
        format!("echo b > {}", path(w, "var/data/new"))
    });
    allowed_with_the_pin("atomic save of a file inside the mounted directory", |w| {
        format!(
            "echo n > {1} && mv {1} {0}",
            path(w, "var/data/keep"),
            path(w, "var/data/tmp")
        )
    });
    allowed_with_the_pin("delete a file inside the mounted directory", |w| {
        format!("rm {}", path(w, "var/data/keep"))
    });
    allowed_with_the_pin("create and delete entries next to the mounts", |w| {
        format!(
            "mkdir {0} && rmdir {0} && touch {1} && rm {1}",
            path(w, "var/scratch"),
            path(w, "scratch")
        )
    });
    allowed_with_the_pin("create a new directory and a symlink", |w| {
        format!(
            "mkdir {0} && ln -s /etc {1}",
            path(w, "newdir"),
            path(w, "newlink")
        )
    });
}

#[test]
fn nothing_is_pinned_when_no_mount_source_was_given() {
    sandboxed!();
    let w = pinned_world();
    let p = w.render(&RenderInputs::new());
    assert!(
        !p.text.contains("file-link"),
        "a run with no containers must render no link rule"
    );
    let out = run(
        &p,
        &w.home_dir(),
        &w.project,
        &format!("mv {} {}", path(&w, "var"), path(&w, "var2")),
    );
    assert!(succeeds(&out));
    assert_ok!(fs::metadata(w.project.join("var2")));
}

#[test]
fn ancestors_are_pinned_up_to_the_write_grant_that_reaches_them() {
    sandboxed!();
    // The floor already pins the project root (it protects the config file), so use a source in a
    // sibling directory of the project, under a grant that covers both.
    let make = || {
        let w = World::with_base("[fs]\nwrite = [\"~/work\"]\n", PROJECT);
        write(&w.home_dir().join("work/other/var/data/keep"), "k");
        w
    };
    let source = |w: &World| canonical(&w.home_dir().join("work/other/var/data"));
    let rename = |w: &World, rel: &str| {
        let dir = w.home_dir().join("work").join(rel);
        format!("mv {} {}2", quote(&dir), quote(&dir))
    };
    let pinned = make();
    let p = pinned.render(&RenderInputs::new().with_mount_pins(vec![source(&pinned)]));
    for rel in ["other", "other/var", "other/var/data"] {
        let out = run(
            &p,
            &pinned.home_dir(),
            &pinned.project,
            &rename(&pinned, rel),
        );
        assert!(!succeeds(&out), "{rel} must be pinned");
    }
    let control = make();
    let p = control.render(&RenderInputs::new());
    let out = run(
        &p,
        &control.home_dir(),
        &control.project,
        &rename(&control, "other"),
    );
    assert!(
        succeeds(&out),
        "control: without the pin the same rename succeeds"
    );
}
