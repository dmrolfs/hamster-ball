// ABOUTME: Starts the per-run egress proxy from the policy and turns its audit events into denial lines, a log and a summary.
// ABOUTME: The proxy lives exactly as long as the child: started before the profile is rendered, stopped after the child ends.
//! The proxy for one run (design 12, hb-ghd.3.3).
//!
//! `hb` starts the proxy for every run, even with an empty allowlist, so an agent that reaches
//! for a host it may not have gets a `403` that says why instead of a refused connection. The
//! profile lets the child reach only the proxy's port (and the policy's loopback ports); the
//! proxy variables in the child's environment point at it.
//!
//! The proxy's audit events become three things for the person running `hb`:
//! - refusals, as lines in the same stream as the sandbox's denials (`--log-denials`);
//! - every connection, as lines in a log of its own (`--log-proxy`);
//! - one warning at the end of the run when anything was refused, unless it is switched off or
//!   the details were already shown.
//!
//! A `407` is not a refusal here: curl and git send credentials only after one, and another
//! process that guessed wrong gets one too. It appears in the full log only.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use super::denials::{Collector, DenialSink, Denials};
use crate::config::Policy;
use crate::policy::{HostRule, Port};
use crate::proxy::{
    AuditEvent, AuditSink, Decision, ProxyConfig, ProxyError, ProxyHandle, ProxyUrl,
};
use crate::seatbelt::ProxyEndpoint;

/// The refusal code that is part of the credentials handshake, not a denial.
const CHALLENGE_CODE: &str = "proxy_auth_required";

/// Adjusts the proxy's configuration before it starts. For tests: a resolver and a dial map that
/// send a test host name to a local upstream while the real checks run.
#[derive(Clone)]
pub struct ProxyTuning(Arc<dyn Fn(ProxyConfig) -> ProxyConfig + Send + Sync>);

impl ProxyTuning {
    /// A tuning that applies `adjust` to the configuration `hb` built from the policy.
    pub fn new(adjust: impl Fn(ProxyConfig) -> ProxyConfig + Send + Sync + 'static) -> Self {
        Self(Arc::new(adjust))
    }
}

impl ProxyTuning {
    /// The configuration after this tuning.
    #[must_use]
    pub fn apply(&self, config: ProxyConfig) -> ProxyConfig {
        (self.0)(config)
    }
}

impl std::fmt::Debug for ProxyTuning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyTuning(..)")
    }
}

/// One place events go.
enum Channel {
    Collect(Mutex<Collector>),
    Stream(Arc<dyn Fn(&str) + Send + Sync>),
}

impl Channel {
    fn new(sink: &DenialSink) -> Self {
        match sink {
            DenialSink::Stream(write) => Self::Stream(Arc::clone(write)),
            _ => Self::Collect(Mutex::new(Collector::default())),
        }
    }

    fn push(&self, line: String) {
        match self {
            Self::Collect(kept) => {
                if let Ok(mut kept) = kept.lock() {
                    kept.add(line);
                }
            }
            Self::Stream(write) => write(&line),
        }
    }

    fn take(&self) -> Denials {
        match self {
            Self::Collect(kept) => {
                let collector = kept.lock().map(|k| k.clone()).unwrap_or_default();
                let (lines, dropped) = collector.into_parts();
                Denials { lines, dropped }
            }
            Self::Stream(_) => Denials::default(),
        }
    }
}

#[derive(Default)]
struct Tally {
    refusals: usize,
    hosts: BTreeSet<String>,
    unnamed: usize,
}

/// The audit sink of a run.
pub struct ProxyTrail {
    denials: Option<Channel>,
    log: Option<Channel>,
    tally: Mutex<Tally>,
}

impl ProxyTrail {
    /// A trail that sends refusals to `denials` and every connection to `log`, where given.
    #[must_use]
    pub fn new(denials: Option<&DenialSink>, log: Option<&DenialSink>) -> Self {
        Self {
            denials: denials.map(Channel::new),
            log: log.map(Channel::new),
            tally: Mutex::new(Tally::default()),
        }
    }

    /// What the run saw.
    #[must_use]
    pub fn report(&self) -> ProxyReport {
        let (refusals, hosts, unnamed) = self
            .tally
            .lock()
            .map(|t| (t.refusals, t.hosts.len(), t.unnamed))
            .unwrap_or_default();
        ProxyReport {
            denials: self.denials.as_ref().map(Channel::take).unwrap_or_default(),
            log: self.log.as_ref().map(Channel::take).unwrap_or_default(),
            refusals,
            hosts,
            unnamed,
        }
    }
}

impl AuditSink for ProxyTrail {
    fn record(&self, event: &AuditEvent) {
        let line = event.to_string();
        if let Some(log) = &self.log {
            log.push(line.clone());
        }
        let Decision::Refused { code, .. } = &event.decision else {
            return;
        };
        if *code == CHALLENGE_CODE {
            return;
        }
        if let Ok(mut tally) = self.tally.lock() {
            tally.refusals += 1;
            match &event.host {
                Some(host) => {
                    tally.hosts.insert(host.to_string());
                }
                None => tally.unnamed += 1,
            }
        }
        if let Some(denials) = &self.denials {
            denials.push(format!("proxy {line}"));
        }
    }
}

/// What the proxy did during a run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProxyReport {
    /// The refusals, when they were collected.
    pub denials: Denials,
    /// Every connection, when they were collected.
    pub log: Denials,
    /// How many connections were refused (not counting the credentials challenge).
    pub refusals: usize,
    /// How many different hosts they named.
    pub hosts: usize,
    /// How many refusals named no valid host.
    pub unnamed: usize,
}

impl ProxyReport {
    /// The end-of-run warning, or `None` when nothing was refused.
    #[must_use]
    pub fn summary(&self) -> Option<String> {
        if self.refusals == 0 {
            return None;
        }
        let connections = plural(self.refusals, "connection", "connections");
        let to = if self.hosts == 0 {
            String::new()
        } else {
            format!(
                " to {} {}",
                self.hosts,
                plural_word(self.hosts, "host", "hosts")
            )
        };
        Some(format!(
            "the proxy refused {} {connections}{to}; run with --log-denials to see them",
            self.refusals
        ))
    }
}

fn plural(count: usize, one: &str, many: &str) -> String {
    plural_word(count, one, many).to_owned()
}

fn plural_word<'a>(count: usize, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 { one } else { many }
}

/// A started proxy and what listens to it.
pub struct ProxyRun {
    handle: ProxyHandle,
    trail: Arc<ProxyTrail>,
}

impl ProxyRun {
    /// Starts the proxy for `policy`, allowing exactly `allowlist`.
    ///
    /// # Errors
    /// [`ProxyError`] if it cannot listen or start its thread.
    pub fn start(
        policy: &Policy,
        allowlist: Vec<HostRule>,
        trail: Arc<ProxyTrail>,
        tuning: Option<&ProxyTuning>,
    ) -> Result<Self, ProxyError> {
        let mut config = ProxyConfig::new(allowlist)
            .with_internal_hosts(
                policy
                    .net
                    .internal_hosts
                    .iter()
                    .map(|h| h.value.clone())
                    .collect(),
            )
            .with_audit(Arc::clone(&trail) as Arc<dyn AuditSink>);
        if let Some(tune) = tuning {
            config = tune.apply(config);
        }
        Ok(Self {
            handle: ProxyHandle::start(config)?,
            trail,
        })
    }

    /// The endpoint the profile allows the child to reach.
    #[must_use]
    pub fn endpoint(&self) -> Option<ProxyEndpoint> {
        Port::try_from(i64::from(self.handle.port()))
            .ok()
            .map(ProxyEndpoint::Port)
    }

    /// The URL for the child's proxy variables.
    #[must_use]
    pub fn url(&self) -> ProxyUrl {
        self.handle.url()
    }

    /// Stops the proxy (ending any connection still open) and reports what it did.
    #[must_use]
    pub fn finish(mut self) -> ProxyReport {
        self.handle.stop();
        self.trail.report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::HostName;
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    fn event(host: Option<&str>, decision: Decision) -> AuditEvent {
        AuditEvent {
            host: host.map(|h| assert_ok!(HostName::parse(h))),
            port: host.map(|_| assert_ok!(Port::try_from(443))),
            decision,
            bytes_up: 1,
            bytes_down: 2,
        }
    }

    fn refused(host: Option<&str>, code: &'static str) -> AuditEvent {
        event(
            host,
            Decision::Refused {
                code,
                reason: format!("because {code}"),
            },
        )
    }

    fn collect() -> DenialSink {
        DenialSink::Collect
    }

    #[test]
    fn refusals_become_proxy_lines_in_the_denial_stream_and_connections_go_to_the_log() {
        let trail = ProxyTrail::new(Some(&collect()), Some(&collect()));
        trail.record(&event(Some("ok.example.com"), Decision::Allowed));
        trail.record(&refused(Some("no.example.com"), "not_allowed"));
        let report = trail.report();
        assert_eq!(
            report.denials.lines,
            ["proxy refused no.example.com:443 not_allowed (because not_allowed)"]
        );
        assert_eq!(
            report.log.lines,
            [
                "allowed ok.example.com:443 up=1 down=2",
                "refused no.example.com:443 not_allowed (because not_allowed)"
            ]
        );
        assert_eq!((report.refusals, report.hosts, report.unnamed), (1, 1, 0));
    }

    #[test]
    fn a_credentials_challenge_is_in_the_log_but_is_not_a_refusal() {
        let trail = ProxyTrail::new(Some(&collect()), Some(&collect()));
        trail.record(&refused(Some("github.com"), "proxy_auth_required"));
        let report = trail.report();
        assert!(report.denials.lines.is_empty());
        assert_eq!(report.log.lines.len(), 1);
        assert_eq!(report.refusals, 0);
        assert_eq!(report.summary(), None);
    }

    #[test]
    fn without_sinks_nothing_is_kept_but_the_tally_still_counts() {
        let trail = ProxyTrail::new(None, None);
        trail.record(&refused(Some("a.example.com"), "not_allowed"));
        trail.record(&refused(Some("a.example.com"), "port_not_allowed"));
        trail.record(&refused(Some("b.example.com"), "not_allowed"));
        trail.record(&refused(None, "malformed"));
        let report = trail.report();
        assert!(report.denials.lines.is_empty() && report.log.lines.is_empty());
        assert_eq!((report.refusals, report.hosts, report.unnamed), (4, 2, 1));
    }

    #[test]
    fn a_stream_sink_receives_each_line_as_it_happens_and_keeps_nothing() {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let writer = Arc::clone(&seen);
        let sink = DenialSink::Stream(Arc::new(move |line| {
            if let Ok(mut seen) = writer.lock() {
                seen.push(line.to_owned());
            }
        }));
        let trail = ProxyTrail::new(Some(&sink), None);
        trail.record(&refused(Some("no.example.com"), "not_allowed"));
        assert_eq!(seen.lock().map(|s| s.len()).unwrap_or_default(), 1);
        assert!(trail.report().denials.lines.is_empty());
    }

    #[test]
    fn a_tuning_applies_its_change_and_prints_without_its_closure() {
        let tuning = ProxyTuning::new(|config| config.with_max_connections(7));
        let config = tuning.apply(ProxyConfig::new(Vec::new()));
        assert!(format!("{config:?}").contains("max_connections: 7"));
        assert_eq!(format!("{tuning:?}"), "ProxyTuning(..)");
    }

    #[test]
    fn the_summary_counts_connections_and_hosts_in_the_singular_and_plural() {
        let one = ProxyReport {
            refusals: 1,
            hosts: 1,
            ..ProxyReport::default()
        };
        assert_eq!(
            one.summary().as_deref(),
            Some("the proxy refused 1 connection to 1 host; run with --log-denials to see them")
        );
        let many = ProxyReport {
            refusals: 5,
            hosts: 2,
            ..ProxyReport::default()
        };
        assert_eq!(
            many.summary().as_deref(),
            Some("the proxy refused 5 connections to 2 hosts; run with --log-denials to see them")
        );
        let unnamed = ProxyReport {
            refusals: 2,
            hosts: 0,
            unnamed: 2,
            ..ProxyReport::default()
        };
        assert_eq!(
            unnamed.summary().as_deref(),
            Some("the proxy refused 2 connections; run with --log-denials to see them")
        );
        assert_eq!(ProxyReport::default().summary(), None);
    }
}
