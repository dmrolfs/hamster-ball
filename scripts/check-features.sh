#!/usr/bin/env bash
# ABOUTME: Checks that ordinary hb builds exclude UI crates and the opt-in supervisor builds independently.
# ABOUTME: Uses the lockfile and an isolated temporary target; set RUSTUP_TOOLCHAIN=1.88 to check the MSRV.
set -euo pipefail
cd "$(dirname "$0")/.."

tree=$(cargo tree --locked --edges normal,build --prefix none --format '{p}')
if grep -E '^(ratatui|crossterm|tui-term|vt100) v' <<< "$tree"; then
    echo 'default build unexpectedly depends on supervisor UI crates' >&2
    exit 1
fi

target=$(mktemp -d "${TMPDIR:-/tmp}/hb-features.XXXXXX")
trap 'rm -rf "$target"' EXIT
export CARGO_TARGET_DIR="$target"
cargo build --locked --bins
[[ -x "$target/debug/hb" && ! -e "$target/debug/hb-supervise" ]]
cargo check --locked --all-targets
cargo check --locked --all-targets --features supervise
cargo build --locked --no-default-features --features supervise --bins
"$target/debug/hb-supervise" --help
