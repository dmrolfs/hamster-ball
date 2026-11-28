# Local vt100 dependency wiring

Source: crates.io `vt100` 0.16.2, with upstream source and license retained.
Only the normalized `Cargo.toml` dependency on `vte` gains `path = "../vte"`.
This ensures downstream path consumers use the parser performance correction.
See `../vte/LOCAL-CHANGES.md` for the patch and replacement criteria.
Cargo registry marker files are omitted; `Cargo.toml.orig` retains upstream metadata.
