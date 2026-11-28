# Local dependency patch

Vendored from crates.io `darwin-libproc` 0.2.0.
Source, tests, examples, README and both upstream licenses are unchanged.
The normalized Cargo manifest changes only `memchr = "~2.3"` to `memchr = "2.3"`.
This allows a shared compatible 2.x version with the supervisor's vte dependency, which requires at least 2.7.4.
The sole call is `memchr::memchr` in `src/pid_cwd.rs`.

The root uses a direct path dependency so downstream consumers also get the fix without needing their own `[patch]` table.
Return to a registry dependency when upstream publishes a compatible requirement.
