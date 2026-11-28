# Local tui-term dependency wiring

Source: crates.io `tui-term` 0.3.4, with upstream source and license retained.
Only the normalized `Cargo.toml` dependency on `vt100` gains `path = "../vt100"`.
The application and terminal widget must use the same local `vt100` type and patched parser.
See `../vte/LOCAL-CHANGES.md` for the patch and replacement criteria.
Cargo registry marker files are omitted; `Cargo.toml.orig` retains upstream metadata.
Local `.gitattributes` treats recorded terminal streams as binary, preserving their intentional carriage returns and trailing spaces.
