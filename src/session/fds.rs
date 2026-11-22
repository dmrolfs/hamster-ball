// ABOUTME: close_inherited_fds: the hb binary closes every descriptor above 2 at start so none reaches the agent.
// ABOUTME: A descriptor to a denied file is a way around Seatbelt, which checks the path only when a file is opened.
//! Descriptors inherited from the launching shell.
//!
//! `sandbox-exec` passes every open descriptor to the command, and Rust's `Command` closes only
//! the ones Rust opened. So `exec 3<~/.ssh/id_ed25519; hb run agent` would hand the agent a
//! readable key although the profile denies the path. The `hb` binary calls
//! [`close_inherited_fds`] first thing in `main`. Library callers must not: it closes every
//! descriptor of the calling process, including ones other code owns.

use std::fs;

use nix::unistd::close;

/// The directory that lists this process's open descriptors on macOS.
const FD_DIR: &str = "/dev/fd";

/// Closes every descriptor above 2 and returns the numbers it closed.
///
/// Call it once, before opening anything, in a program that is only `hb`. Descriptors 0, 1 and 2
/// stay: they are the child's standard streams.
pub fn close_inherited_fds() -> Vec<i32> {
    let names: Vec<String> = fs::read_dir(FD_DIR)
        .map(|dir| {
            dir.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    // The directory iterator's own descriptor is in the list and is already closed by now, so a
    // failed close of it is expected and ignored.
    inherited_from(names.iter().map(String::as_str))
        .into_iter()
        .filter(|fd| close(*fd).is_ok())
        .collect()
}

/// The descriptor numbers above 2 among `names`, sorted and without repeats.
fn inherited_from<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<i32> {
    let mut fds: Vec<i32> = names
        .into_iter()
        .filter_map(|n| n.parse::<i32>().ok())
        .filter(|fd| *fd > 2)
        .collect();
    fds.sort_unstable();
    fds.dedup();
    fds
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn only_numbers_above_two_are_inherited_and_the_list_is_sorted_and_distinct() {
        let names = [
            "0",
            "1",
            "2",
            "3",
            "10",
            "4",
            "4",
            "-1",
            "x",
            "",
            "3.5",
            "2147483647",
        ];
        assert_eq!(inherited_from(names), vec![3, 4, 10, 2_147_483_647]);
    }

    #[test]
    fn nothing_above_two_means_nothing_to_close() {
        assert_eq!(inherited_from(["0", "1", "2"]), Vec::<i32>::new());
        assert_eq!(inherited_from([]), Vec::<i32>::new());
    }

    #[test]
    fn a_number_too_large_for_a_descriptor_is_ignored() {
        assert_eq!(
            inherited_from(["2147483648", "99999999999"]),
            Vec::<i32>::new()
        );
    }
}
