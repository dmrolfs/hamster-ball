// ABOUTME: Config intake: reading one file's bytes, parsing its raw TOML shape, and resolving entries into a ResolvedConfig.
// ABOUTME: `raw` stays pub(crate): the only public type from this module is ResolvedConfig and the types resolve_file returns.
//! Turns a project's `hamster-ball.toml` text into validated config.

mod discover;
mod raw;
mod resolve;
mod text;

pub use discover::{DiscoverError, Discovery, discover};
pub use resolve::{
    Diagnostics, EntryError, ResolveContext, ResolveErrors, Resolved, ResolvedConfig, resolve_file,
};
pub use text::{ConfigText, ConfigTextError, MAX_CONFIG_BYTES};
