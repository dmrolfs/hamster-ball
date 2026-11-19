// ABOUTME: Builds the floor against the real home, PATH and filesystem of the machine running the tests (ignored by default).
// ABOUTME: Run with `cargo test --test floor_real_machine -- --ignored --nocapture` to see what the floor does on your machine.
//! The floor on the real machine.
//!
//! Hermetic tests cannot see machine-specific problems: a dangling `/var/run/docker.sock` link,
//! a `PATH` full of symlinks, a read-only home. This test builds the floor for the current
//! directory's repository root and prints a summary.

use claims::assert_ok;
use hamster_ball::policy::{CanonicalPath, ProjectRoot};
use hamster_ball::system::{Environment, FloorInputs, build_floor};

#[test]
#[ignore = "reads the real home directory and PATH"]
fn the_floor_builds_on_this_machine_and_reports_what_it_noticed() {
    let env = assert_ok!(Environment::from_process());
    let root = assert_ok!(ProjectRoot::new(
        assert_ok!(CanonicalPath::from_canonical(assert_ok!(
            std::fs::canonicalize(&env.cwd)
        ))),
        &env.home
    ));
    let grants = [root.path().clone()];
    let built = assert_ok!(build_floor(&FloorInputs::new(
        &env.home,
        &root,
        &env.floor,
        &[],
        &grants,
    )));
    let by_group = |group: &str| {
        built
            .floor
            .rules()
            .iter()
            .filter(|rule| rule.group.to_string() == group)
            .count()
    };
    println!(
        "floor: {} rules (table {}, project {}, path {}, pin {})",
        built.floor.rules().len(),
        by_group("table"),
        by_group("project"),
        by_group("path"),
        by_group("pin"),
    );
    for diagnostic in &built.diagnostics {
        println!("  {}: {diagnostic}", diagnostic.kind());
    }
}
