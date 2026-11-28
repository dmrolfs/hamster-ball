# Local vte patch

Source: crates.io `vte` 0.15.0, copied from the Cargo registry with upstream licenses and source retained.
Cargo registry marker files are omitted.

`src/lib.rs` caches the absolute position of the next ESC within each `advance` or `advance_until_terminated` call.
The cache is refreshed only after parsing has passed that position.
An invalid UTF-8 byte therefore does not trigger another search through the same remaining suffix.
`advance_ground` receives the same ESC offset it would previously have searched for.
It retains all original callback, consumed-byte, partial UTF-8, and early-termination behavior.
No input call is split or combined.

The existing partial decoder has known boundary-dependent behavior, including swallowing a space after a split C1 sequence.
This performance patch intentionally does not fix that separate compatibility issue.
A proposed application-level chunking optimization was rejected after reproducing that behavior.

`tests/vte-compat` compares callback traces and early-termination offsets against the unmodified crates.io release for identical external reads.
Run `cargo test --locked --manifest-path tests/vte-compat/Cargo.toml` from the repository root.
The existing supervisor hostile-input timing tests retain their original limits.

`vt100` and `tui-term` are also copied locally with only dependency-path metadata changes, so downstream consumers use this parser without relying on a root-only Cargo patch table.
No upstream fix or submission is claimed.
Replace these local copies when a released upstream fix passes the differential checks and supervisor tests.
