// ABOUTME: Running a command under the profile: child environment, session directory, nesting check, spawn.
// ABOUTME: `run` is the library entry point that `hb run` and the probe-matrix harness both call.
//! A run: everything between "the policy is loaded" and "the child has exited".

pub mod ca_bundle;
pub mod child_helper;
pub mod ctl;
pub mod denials;
pub mod dir;
pub mod env;
pub mod fds;
mod fence;
pub mod gitconfig;
mod guard_channel;
pub mod guardian;
pub mod hooks;
mod interactive;
pub mod offline;
pub mod ports;
pub mod preflight;
pub mod proxy;
pub mod pty;
pub mod pump;
pub mod relay;
pub mod run;
pub mod sanitize;
pub mod signals;
pub mod terminal;

pub use ca_bundle::{CaBundleError, write_bundle};
pub use child_helper::{HelperError, exec_sandbox_exec};
pub use denials::{DenialSink, Denials, DenialsError, LogStream, generate_tag};
pub use dir::{SessionDir, SessionDirError, SweepReport, sweep_stale};
pub use env::{ChildEnv, EnvBuildError, EnvInputs, SESSION_MARKER, TlsEnv};
pub use fds::close_inherited_fds;
pub use guardian::{
    GuardError, GuardHandle, Guardian, GuardianError, WatchOutcome, WatchRefusal, run_guard,
};
pub use interactive::InteractiveError;
pub use preflight::{
    PreflightError, ProbeOutcome, SANDBOX_EXEC, check_nesting, classify, is_nested,
};
pub use proxy::{ProxyReport, ProxyRun, ProxyTrail, ProxyTuning};
pub use pty::{Pty, PtyError, Winsize};
pub use pump::Pump;
pub use relay::Relay;
pub use run::{
    DEFAULT_GRACE, ExitKind, Outcome, PtyMode, RunError, RunSpec, SignalMode, StdioMode, WarmSpec,
    run,
};
pub use signals::{Escalation, Step};
pub use terminal::{RawMode, TerminalError};
