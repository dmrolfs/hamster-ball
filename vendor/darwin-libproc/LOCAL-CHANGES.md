# Local dependency patch

Vendored from crates.io `darwin-libproc` 0.2.0.
Upstream licenses, examples and tests are retained.
The normalized Cargo manifest changes `memchr = "~2.3"` to `memchr = "2.3"`.
This allows a shared compatible 2.x version with the supervisor's vte dependency, which requires at least 2.7.4.
The existing call is `memchr::memchr` in `src/pid_cwd.rs`.
The root uses a direct path dependency so downstream consumers also get the fix without needing their own `[patch]` table.
Return to a registry dependency when upstream supplies both the compatible requirement and the inventory contract below.

## Complete self-descriptor inventory (hb-807)

`self_fds()` wraps `PROC_PIDLISTFDS` for the single-threaded startup sweep.
It uses initialized records, retries an exact-full buffer, validates byte counts and descriptor values, and fails instead of guessing an allocation ceiling.
The main crate remains free of unsafe code; the FFI stays in this existing vendor boundary.
A snapshot is not safe for closing descriptors while other threads can open or close them.

Run the vendor's tests explicitly:

```sh
cargo test --manifest-path vendor/darwin-libproc/Cargo.toml self_fds
```
