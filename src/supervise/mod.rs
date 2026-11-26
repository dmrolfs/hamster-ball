// ABOUTME: The supervisor UI's library side: terminal emulation and input encoding now, app state and screens in later tasks.
// ABOUTME: Everything here is pure or owns only its own buffers; nothing writes to the owner's real terminal except the view in a later task.
//! The supervisor (epic hb-b6q): what `hb-supervise` is built from.

pub mod app;
pub mod input;
pub mod launch;
pub mod runtime;
pub mod session;
pub mod terminal;
