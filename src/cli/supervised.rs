// ABOUTME: `hb run --supervised`: the same run as `hb run`, reporting state and telemetry over the supervisor's private channel.
// ABOUTME: It never prompts, never changes policy, and stops its session when the supervisor goes away; enforcement is the ordinary run.
//! The supervised variant of `hb run` (epic hb-b6q).
//!
//! The differences from an ordinary run are small and all about reporting:
//!
//! - The outer terminal belongs to the supervisor's PTY, so a config that is not approved is not
//!   asked about. `ApprovalRequired` is reported and `hb` exits 78 without running anything.
//! - Denials and proxy connections go to the channel as typed events instead of stderr text.
//!   The `--log-denials` and `--log-proxy` flags still choose whether they are produced.
//! - A closed channel, a stalled one, or a `Stop` command stops the session as SIGTERM does,
//!   including during the pre-run hooks.
//!
//! Nothing here grants anything: the channel carries events out and one command in.

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::sync::Arc;

use nix::sys::signal::Signal;

use super::{
    Channel, NOT_APPROVED, RunArgs, Supervision, exit_code, fail, load_project, reraise_for,
    startup_warnings,
};
use crate::approval::{ApprovalStore, Candidate, NoTerminal, require};
use crate::config::{Discovery, Loaded};
use crate::session::reporter::{Lifecycle, Reporter};
use crate::session::signals::{StopSignal, block_supervised};
use crate::session::supervised::{Cleanup, Event};
use crate::session::{
    DenialSink, ExitKind, OnStart, OnStopping, PtyMode, RunError, RunSpec, SESSION_MARKER,
    SignalMode, StdioMode, check_nesting,
};
use crate::system::{Environment, StateDir};

/// How a supervised run ended, for the process exit and for the closing event.
struct Ended {
    code: ExitCode,
    event: Event,
}

impl Ended {
    /// Ended before the agent ran, for a reason `hb` prints.
    fn failed(code: ExitCode) -> Self {
        Self {
            code,
            event: Event::Exited {
                code: None,
                signal: None,
                cleanup: Cleanup::Complete {},
            },
        }
    }
}

/// `hb run --supervised`: see the module documentation.
pub(super) fn run(
    env: &Environment,
    args: RunArgs,
    channel: Channel,
    supervision: Supervision,
    err: &mut dyn Write,
    reraise: &mut Option<Signal>,
) -> ExitCode {
    // Before any thread: the reporter's threads must inherit the blocked set, or a signal could
    // kill `hb` before it has cleaned up.
    if let Err(error) = block_supervised() {
        return fail(err, crate::Error::from(RunError::from(error)));
    }
    let stop = StopSignal::new();
    let reporter = match Reporter::connect(channel, Arc::clone(&stop)) {
        Ok(reporter) => reporter,
        Err(error) => {
            let _ = writeln!(err, "{}", snafu::Report::from_error(error));
            return ExitCode::from(2);
        }
    };
    let ended = report_run(env, args, &reporter, &stop, supervision, err, reraise);
    reporter.lifecycle(Event::Stopping {});
    reporter.finish(ended.event);
    ended.code
}

fn report_run(
    env: &Environment,
    args: RunArgs,
    reporter: &Reporter,
    stop: &Arc<StopSignal>,
    supervision: Supervision,
    err: &mut dyn Write,
    reraise: &mut Option<Signal>,
) -> Ended {
    let events = reporter.lifecycle_handle();
    events.send(Event::Starting {});
    if let Err(error) = check_nesting(env.vars.get(SESSION_MARKER).is_some()) {
        return Ended::failed(fail(err, crate::Error::from(RunError::from(error))));
    }
    let (discovery, loaded) = match load_project(env) {
        Ok(project) => project,
        Err(error) => return Ended::failed(fail(err, crate::Error::from(error))),
    };
    if let Some(ended) = unapproved(env, &discovery, &loaded, &events, err) {
        return ended;
    }
    for warning in startup_warnings(env, &discovery, &loaded) {
        events.send(Event::warning(&warning));
    }
    let spec = spec_for(args, reporter, stop, supervision, &events);
    match crate::session::run(env, &loaded, &spec) {
        Ok(outcome) => {
            for warning in &outcome.warnings {
                events.send(Event::warning(warning));
            }
            *reraise = reraise_for(outcome.exit);
            Ended {
                code: exit_code(outcome.exit),
                event: exited_event(outcome.exit),
            }
        }
        Err(RunError::Cleanup { exit: Some(exit) }) => {
            let mut event = exited_event(exit);
            if let Event::Exited { cleanup, .. } = &mut event {
                *cleanup = Cleanup::Failed {
                    what: "broker or guardian cleanup failed".into(),
                };
            }
            Ended {
                code: ExitCode::FAILURE,
                event,
            }
        }
        Err(RunError::Stopped) => unconfirmed(ExitCode::from(143)),
        Err(error) => unconfirmed(fail(err, crate::Error::from(error))),
    }
}

/// Returning from session setup or waiting does not establish successful resource cleanup.
fn unconfirmed(code: ExitCode) -> Ended {
    Ended {
        code,
        event: Event::Exited {
            code: None,
            signal: None,
            cleanup: Cleanup::Failed {
                what: "session cleanup could not be confirmed after an error".to_owned(),
            },
        },
    }
}

/// Reports `ApprovalRequired` and gives the exit code, unless the config is approved.
///
/// Nothing is asked: the terminal is the supervisor's, and an approval has to be given by the
/// owner running `hb approve` on their own terminal.
fn unapproved(
    env: &Environment,
    discovery: &Discovery,
    loaded: &Loaded,
    events: &Lifecycle,
    err: &mut dyn Write,
) -> Option<Ended> {
    let candidate = Candidate::new(env, discovery, loaded);
    let store = ApprovalStore::new(&StateDir::locate(&env.home));
    match require(&candidate, &store, &mut NoTerminal, err) {
        Ok(verdict) if verdict.allows_run() => None,
        Ok(_) => {
            events.send(Event::approval_required(candidate.root().as_str()));
            let _ = writeln!(
                err,
                "hb: the config is not approved. Run `hb approve` in this project. Nothing was run."
            );
            Some(Ended::failed(ExitCode::from(NOT_APPROVED)))
        }
        Err(error) => Some(Ended::failed(fail(err, crate::Error::from(error)))),
    }
}

/// The run's settings: signals forwarded, telemetry to the channel, a stop from the channel.
fn spec_for(
    args: RunArgs,
    reporter: &Reporter,
    stop: &Arc<StopSignal>,
    supervision: Supervision,
    events: &Lifecycle,
) -> RunSpec {
    let telemetry = reporter.telemetry();
    let mut spec = RunSpec::new(args.command)
        .stdio(StdioMode::Inherit)
        .signals(SignalMode::Forward {
            grace: supervision.grace,
        })
        .stop(Arc::clone(stop));
    // The supervisor's PTY is this process's terminal, and the agent gets one of its own.
    if std::io::stdin().is_terminal() {
        spec.pty = PtyMode::On;
    }
    if args.log_denials {
        let sink = telemetry.clone();
        spec.denials = Some(DenialSink::Stream(Arc::new(move |line| sink.denial(line))));
    }
    spec.proxy_summary = false;
    spec.telemetry = Some(telemetry);
    let stopping = events.clone();
    spec.on_stopping = Some(OnStopping(Arc::new(move || {
        stopping.send(Event::Stopping {})
    })));
    let running = events.clone();
    spec.on_start = Some(OnStart(Arc::new(move |pid| {
        running.send(Event::Running { agent_pid: pid });
    })));
    spec
}

fn exited_event(exit: ExitKind) -> Event {
    let (code, signal) = match exit {
        ExitKind::Exited(code) => (Some(code), None),
        ExitKind::Signalled(signal) => (None, Some(signal)),
    };
    Event::Exited {
        code,
        signal,
        cleanup: Cleanup::Complete {},
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::assert_matches;

    #[test]
    fn session_errors_never_claim_cleanup_or_an_unobserved_agent_exit() {
        for code in [ExitCode::FAILURE, ExitCode::from(143)] {
            assert_matches!(
                unconfirmed(code).event,
                Event::Exited {
                    code: None,
                    signal: None,
                    cleanup: Cleanup::Failed { .. },
                }
            );
        }
    }

    #[test]
    fn failure_before_session_work_can_report_complete() {
        assert_matches!(
            Ended::failed(ExitCode::FAILURE).event,
            Event::Exited {
                code: None,
                signal: None,
                cleanup: Cleanup::Complete {},
            }
        );
    }
}
