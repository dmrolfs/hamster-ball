// ABOUTME: `hb ctl`: the container and launchd broker (host side) and its client (inside the ball). Design section 9.3.
// ABOUTME: `op`, `argv`, `scope` and `preflight` are pure and unit tested without podman; effects live in the other modules.
//! `hb ctl` (design section 9.3, hb-ghd.8).
//!
//! An agent inside the ball cannot run `podman` or `launchctl`. A broker inside `hb run` listens on
//! one unix socket and runs a short list of fixed commands for the containers and launchd jobs a
//! user-owned config names. Every decision is made here, on the host side, from values that were
//! validated into types; nothing the client sends reaches a command line as text.

pub mod argv;
pub mod broker;
pub mod client;
pub mod facts;
pub mod handler;
pub mod isolation;
pub mod launchd;
pub mod op;
pub mod preflight;
pub mod runner;
pub mod scope;
pub mod service;
