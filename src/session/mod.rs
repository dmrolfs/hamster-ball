// ABOUTME: Running a command under the profile: child environment, session directory, nesting check, spawn.
// ABOUTME: `run` is the library entry point that `hb run` and the probe-matrix harness both call.
//! A run: everything between "the policy is loaded" and "the child has exited".

pub mod child_helper;
pub mod denials;
pub mod dir;
pub mod env;
pub mod fds;
pub mod preflight;
pub mod run;
pub mod signals;

pub use child_helper::{HelperError, exec_sandbox_exec};
pub use denials::{DenialSink, Denials, DenialsError, LogStream, generate_tag};
pub use dir::{SessionDir, SessionDirError, SweepReport, sweep_stale};
pub use env::{ChildEnv, EnvBuildError, EnvInputs, SESSION_MARKER};
pub use fds::close_inherited_fds;
pub use preflight::{
    PreflightError, ProbeOutcome, SANDBOX_EXEC, check_nesting, classify, is_nested,
};
pub use run::{
    DEFAULT_GRACE, ExitKind, Outcome, PtyMode, RunError, RunSpec, SignalMode, StdioMode, run,
};
pub use signals::{Escalation, Step};
