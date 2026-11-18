// ABOUTME: Build script: parses the vendored Public Suffix List and the supplement file into OUT_DIR/psl_generated.rs.
// ABOUTME: No build-dependencies: the shared parser in build/psl_gen.rs is std-only and is also compiled into the lib for tests.
//! Generates the protected-suffix lookup tables at build time. See `build/psl_gen.rs` for the
//! parser, which is shared with the library's own unit tests via `#[path]`.

#[path = "build/psl_gen.rs"]
mod psl_gen;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

fn run() -> Result<(), String> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").map_err(|error| error.to_string())?;
    let out_dir = env::var("OUT_DIR").map_err(|error| error.to_string())?;

    let psl_path = PathBuf::from(&manifest_dir).join("data/public_suffix_list.dat");
    let extra_path = PathBuf::from(&manifest_dir).join("data/extra_protected_suffixes.txt");

    println!("cargo::rerun-if-changed={}", psl_path.display());
    println!("cargo::rerun-if-changed={}", extra_path.display());
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=build/psl_gen.rs");

    let psl_text = fs::read_to_string(&psl_path)
        .map_err(|error| format!("{}: {error}", psl_path.display()))?;
    let extra_text = fs::read_to_string(&extra_path)
        .map_err(|error| format!("{}: {error}", extra_path.display()))?;

    let (data, version) = psl_gen::parse_psl(&psl_text).map_err(|error| error.to_string())?;
    let extra = psl_gen::parse_supplement(&extra_text).map_err(|error| error.to_string())?;
    let set = psl_gen::build_protected_set(&data, &version, &extra);
    let rendered = psl_gen::render(&set);

    let out_path = PathBuf::from(out_dir).join("psl_generated.rs");
    fs::write(&out_path, rendered).map_err(|error| format!("{}: {error}", out_path.display()))
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("build.rs: {message}");
            ExitCode::FAILURE
        }
    }
}
