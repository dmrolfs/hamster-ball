// ABOUTME: Reads the macOS system proxy settings (`scutil --proxy`) and says which of them hb does not follow.
// ABOUTME: Keeps only the kind and a validated host and port; a PAC address is never read, and a failed read is never an empty one.
//! The host's proxy configuration (design 4.5, 12.1, D74).
//!
//! `hb`'s proxy connects directly. A network that needs an upstream proxy or a PAC file will
//! fail every connection, and the agent can read these settings through `configd` while
//! `tls.system_trust` is on. `hb doctor` reports both.
//!
//! The result is a [`Check`]: a failed, cut-off or malformed read is [`Check::Unavailable`], a
//! read that left something out (a scoped section, a value that did not validate) is
//! [`Check::Partial`], and only a read that covered the whole top-level dictionary is
//! [`Check::Complete`], with an empty list meaning no proxy is switched on.
//!
//! Nothing here keeps text that `scutil` printed: a target holds a parsed host and port and no
//! string, a PAC file has no target at all, and no error carries the input. That is what keeps
//! `user:password@` and query secrets out of every `Display`, `Debug` and JSON output.

use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::path::Path;
use std::process::Command;
use std::str::FromStr as _;
use std::time::Duration;

use serde::{Serialize, Serializer};
use strum::{AsRefStr, Display};

use crate::diagnostic::{Check, CheckGap, DiagnosticCode, Gaps, SafePath};
use crate::policy::HostName;
use crate::sys::{BoundedError, run_bounded};

/// `scutil`, the program that prints the system proxy settings.
const SCUTIL: &str = "/usr/sbin/scutil";
/// The most output read.
const MAX_BYTES: u64 = 64 * 1024;
/// How long `scutil` may take.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Deepest nesting accepted; anything deeper is not a dictionary `scutil` printed.
const MAX_DEPTH: usize = 16;

/// What kind of proxy setting is switched on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Display, AsRefStr)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
#[non_exhaustive]
pub enum ProxyKind {
    /// An HTTP proxy.
    Http,
    /// An HTTPS proxy.
    Https,
    /// A SOCKS proxy.
    Socks,
    /// An FTP proxy.
    Ftp,
    /// A proxy auto-config (PAC) file. Its address is never read.
    AutoConfig,
    /// Automatic proxy discovery.
    AutoDiscovery,
}

impl ProxyKind {
    /// The words the text report uses.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Http => "HTTP",
            Self::Https => "HTTPS",
            Self::Socks => "SOCKS",
            Self::Ftp => "FTP",
            Self::AutoConfig => "PAC file",
            Self::AutoDiscovery => "automatic discovery",
        }
    }
}

/// The host of a proxy, validated: never text that could hold `user:password@`, a path or a query.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProxyHost {
    Name(HostName),
    Ip(IpAddr),
    Localhost,
}

impl ProxyHost {
    /// `None` for anything that is not a plain host name, an address or `localhost`.
    ///
    /// The validation error is dropped on the spot: it carries the input text.
    fn parse(text: &str) -> Option<Self> {
        let bare = text
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .unwrap_or(text);
        if let Ok(ip) = IpAddr::from_str(bare) {
            return Some(Self::Ip(ip));
        }
        if text == "localhost" {
            return Some(Self::Localhost);
        }
        HostName::parse(text).ok().map(Self::Name)
    }
}

/// The address a proxy is reached at: a validated host and, if one was given, a port.
///
/// The fields are private and no raw text is kept, so a derived `Debug` or `Serialize` cannot leak
/// what `scutil` printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyTarget {
    host: ProxyHost,
    port: Option<NonZeroU16>,
}

impl fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (&self.host, self.port) {
            (ProxyHost::Name(name), None) => write!(f, "{name}"),
            (ProxyHost::Name(name), Some(port)) => write!(f, "{name}:{port}"),
            (ProxyHost::Localhost, None) => f.write_str("localhost"),
            (ProxyHost::Localhost, Some(port)) => write!(f, "localhost:{port}"),
            (ProxyHost::Ip(ip @ IpAddr::V6(_)), None) => write!(f, "[{ip}]"),
            (ProxyHost::Ip(ip @ IpAddr::V6(_)), Some(port)) => write!(f, "[{ip}]:{port}"),
            (ProxyHost::Ip(ip), None) => write!(f, "{ip}"),
            (ProxyHost::Ip(ip), Some(port)) => write!(f, "{ip}:{port}"),
        }
    }
}

impl Serialize for ProxyTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// One proxy the system has switched on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProxySetting {
    /// What it is.
    pub kind: ProxyKind,
    /// Where it is, when the system names a host that passed validation. Always `None` for a PAC
    /// file and for automatic discovery.
    pub target: Option<ProxyTarget>,
}

/// One kind `scutil` prints: its switch, and for a host-and-port kind the keys of its address.
struct KindKeys {
    kind: ProxyKind,
    enable: &'static str,
    address: Option<(&'static str, &'static str)>,
}

const fn keys(
    kind: ProxyKind,
    enable: &'static str,
    address: Option<(&'static str, &'static str)>,
) -> KindKeys {
    KindKeys {
        kind,
        enable,
        address,
    }
}

const KINDS: &[KindKeys] = &[
    keys(
        ProxyKind::Http,
        "HTTPEnable",
        Some(("HTTPProxy", "HTTPPort")),
    ),
    keys(
        ProxyKind::Https,
        "HTTPSEnable",
        Some(("HTTPSProxy", "HTTPSPort")),
    ),
    keys(
        ProxyKind::Socks,
        "SOCKSEnable",
        Some(("SOCKSProxy", "SOCKSPort")),
    ),
    keys(ProxyKind::Ftp, "FTPEnable", Some(("FTPProxy", "FTPPort"))),
    keys(ProxyKind::AutoConfig, "ProxyAutoConfigEnable", None),
    keys(ProxyKind::AutoDiscovery, "ProxyAutoDiscoveryEnable", None),
];

/// Top-level containers `scutil` prints that hold no proxy setting.
const HARMLESS: &[&str] = &[
    "ExceptionsList",
    "SupplementalMatchDomains",
    "SupplementalMatchOrders",
];

/// What one top-level entry of the dictionary was.
struct Top<'a> {
    scalars: Vec<(&'a str, &'a str)>,
    containers: Vec<&'a str>,
}

/// Reads the top level of `scutil`'s dictionary, or `None` when its structure is not what it
/// prints (no dictionary, bad indent, unbalanced braces, text after the end, too deep).
///
/// Only entries at depth 1 are returned, so a per-interface `HTTPEnable : 1` inside a scoped
/// section can never be mistaken for the global switch.
fn structure(text: &str) -> Option<Top<'_>> {
    let mut lines = text.lines();
    if lines.next()? != "<dictionary> {" {
        return None;
    }
    let mut depth = 1_usize;
    let mut top = Top {
        scalars: Vec::new(),
        containers: Vec::new(),
    };
    for line in lines {
        if depth == 0 {
            // Text after the closing brace is not part of what was printed.
            return None;
        }
        let trimmed = line.trim_start_matches(' ');
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with('\t') || trimmed.is_empty() {
            return None;
        }
        if trimmed == "}" {
            if indent != 2 * (depth - 1) {
                return None;
            }
            depth -= 1;
            continue;
        }
        if indent != 2 * depth {
            return None;
        }
        // `scutil` prints an empty string as `Key : ` (verified), so an empty value is a value and
        // not a malformed line; `lines()` keeps the trailing space the separator needs.
        let (key, value) = trimmed.split_once(" : ")?;
        if key.is_empty() {
            return None;
        }
        if value == "<dictionary> {" || value == "<array> {" {
            if depth == 1 {
                top.containers.push(key);
            }
            depth += 1;
            if depth > MAX_DEPTH {
                return None;
            }
        } else if depth == 1 {
            if top.scalars.iter().any(|(known, _)| *known == key) {
                return None;
            }
            top.scalars.push((key, value));
        }
    }
    (depth == 0).then_some(top)
}

/// The key text safe to show: one of Apple's plain key names, or nothing.
fn plain_key(key: &str) -> Option<SafePath> {
    let ok = !key.is_empty()
        && key.len() <= 64
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
    ok.then(|| SafePath::new(key))
}

fn gap(code: DiagnosticCode, key: Option<&str>) -> CheckGap {
    CheckGap {
        code,
        subject: key.and_then(plain_key),
    }
}

fn unavailable(code: DiagnosticCode) -> Check<Vec<ProxySetting>> {
    Check::Unavailable {
        gap: gap(code, None),
    }
}

/// The proxies switched on in `scutil --proxy` output, and what the read left out.
///
/// Anything structurally wrong gives [`Check::Unavailable`]: a value read from output that may be
/// cut off or misread would pass for an answer.
#[must_use]
pub fn parse(text: &str) -> Check<Vec<ProxySetting>> {
    let Some(top) = structure(text) else {
        return unavailable(DiagnosticCode::InspectionUnavailable);
    };
    let mut gaps = Gaps::new();
    for container in &top.containers {
        if !HARMLESS.contains(container) {
            // A scoped section says which interface a proxy applies to, which configd decides.
            gaps.push(gap(DiagnosticCode::ConfigScopeOmitted, Some(container)));
        }
    }
    let scalar = |key: &str| top.scalars.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
    for (key, value) in &top.scalars {
        let known = KINDS.iter().any(|k| k.enable == *key);
        if !known && key.ends_with("Enable") && *value != "0" {
            gaps.push(gap(DiagnosticCode::ConfigScopeOmitted, Some(key)));
        }
    }
    let mut found = Vec::new();
    for KindKeys {
        kind,
        enable,
        address,
    } in KINDS
    {
        match scalar(enable) {
            None | Some("0") => {}
            Some("1") => {
                let target = address.and_then(|(host_key, port_key)| {
                    let target = target(scalar(host_key), scalar(port_key));
                    if target.is_none() {
                        gaps.push(gap(DiagnosticCode::ValueRejected, Some(host_key)));
                    }
                    target
                });
                found.push(ProxySetting {
                    kind: *kind,
                    target,
                });
            }
            Some(_) => gaps.push(gap(DiagnosticCode::ValueRejected, Some(enable))),
        }
    }
    Check::from_parts(found, gaps)
}

/// A host and port that both validate. A switch that is on without a host has no target, and that
/// is a rejected value too: the owner is told it was not shown.
fn target(host: Option<&str>, port: Option<&str>) -> Option<ProxyTarget> {
    let host = ProxyHost::parse(host?)?;
    let port = match port {
        None => None,
        Some(text) => Some(text.parse::<NonZeroU16>().ok()?),
    };
    Some(ProxyTarget { host, port })
}

/// The proxies the system has switched on, or why they could not be read.
#[must_use]
pub fn system_proxies() -> Check<Vec<ProxySetting>> {
    proxies_from(Path::new(SCUTIL), TIMEOUT)
}

fn proxies_from(scutil: &Path, timeout: Duration) -> Check<Vec<ProxySetting>> {
    let mut command = Command::new(scutil);
    command.arg("--proxy");
    let done = match run_bounded(&mut command, timeout, MAX_BYTES) {
        Ok(done) => done,
        Err(BoundedError::TimedOut | BoundedError::Cancelled) => {
            return unavailable(DiagnosticCode::InspectionLimitReached);
        }
        Err(BoundedError::Spawn(_)) => return unavailable(DiagnosticCode::InspectionUnavailable),
    };
    if done.truncated {
        return unavailable(DiagnosticCode::InspectionLimitReached);
    }
    if !done.status.success() {
        return unavailable(DiagnosticCode::InspectionUnavailable);
    }
    match String::from_utf8(done.stdout) {
        Ok(text) => parse(&text),
        Err(_) => unavailable(DiagnosticCode::InspectionUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use claims::{assert_ok, assert_some};
    use pretty_assertions::assert_eq;
    use proptest::prelude::*;
    use std::os::unix::fs::PermissionsExt;

    /// What `scutil --proxy` prints on a machine with nothing switched on, as seen on macOS.
    const QUIET: &str = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n    1 : 169.254/16\n  }\n  ExcludeSimpleHostnames : 0\n  FTPPassive : 1\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  ProxyAutoConfigEnable : 0\n  ProxyAutoDiscoveryEnable : 0\n  SOCKSEnable : 0\n}\n";

    fn with(replace: &str, with: &str) -> String {
        assert!(QUIET.contains(replace), "{replace} is not in the fixture");
        QUIET.replace(replace, with)
    }

    fn value(check: &Check<Vec<ProxySetting>>) -> &[ProxySetting] {
        match check {
            Check::Complete { value } | Check::Partial { value, .. } => value,
            Check::Unavailable { .. } => &[],
        }
    }

    fn codes(check: &Check<Vec<ProxySetting>>) -> Vec<(DiagnosticCode, Option<String>)> {
        let gaps: Vec<&CheckGap> = match check {
            Check::Complete { .. } => Vec::new(),
            Check::Partial { gaps, .. } => gaps.shown().iter().collect(),
            Check::Unavailable { gap } => vec![gap],
        };
        gaps.iter()
            .map(|g| (g.code, g.subject.as_ref().map(ToString::to_string)))
            .collect()
    }

    /// Every way a result can be turned into text: Debug, the JSON report form, and the target's
    /// Display.
    fn every_output(check: &Check<Vec<ProxySetting>>) -> String {
        let mut text = format!("{check:?}");
        text.push_str(&assert_ok!(serde_json::to_string(check)));
        for setting in value(check) {
            text.push_str(&format!("{setting:?}"));
            if let Some(target) = &setting.target {
                text.push_str(&target.to_string());
            }
        }
        text
    }

    #[test]
    fn the_json_shape_of_each_state_holds_no_raw_text() {
        let complete = parse(&with(
            "HTTPSEnable : 0",
            "HTTPSEnable : 1\n  HTTPSProxy : Proxy.Corp.Example\n  HTTPSPort : 8080",
        ));
        assert_eq!(
            assert_ok!(serde_json::to_value(&complete)),
            serde_json::json!({
                "state": "complete",
                "value": [{"kind": "https", "target": "proxy.corp.example:8080"}]
            })
        );
        let partial = parse(&with(
            "HTTPSEnable : 0",
            "HTTPSEnable : 1\n  HTTPSProxy : u:p@ss@h.example\n  HTTPSPort : 8080",
        ));
        assert_eq!(
            assert_ok!(serde_json::to_value(&partial)),
            serde_json::json!({
                "state": "partial",
                "value": [{"kind": "https", "target": null}],
                "gaps": {
                    "shown": [{"code": "value_rejected", "subject": "HTTPSProxy"}],
                    "omitted": 0
                }
            })
        );
        let unavailable = parse("");
        assert_eq!(
            assert_ok!(serde_json::to_value(&unavailable)),
            serde_json::json!({
                "state": "unavailable",
                "gap": {"code": "inspection_unavailable", "subject": null}
            })
        );
        // Debug of a target goes through derived Debug of private fields: the parsed host only.
        let debug = format!("{complete:?}");
        assert!(!debug.contains("Proxy.Corp"), "{debug}");
    }

    #[test]
    fn a_hostile_key_name_in_a_scoped_container_is_not_shown() {
        let text = with(
            "ExcludeSimpleHostnames : 0",
            "bad key@x : <dictionary> {\n    HTTPEnable : 1\n  }",
        );
        let found = parse(&text);
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::ConfigScopeOmitted, None)]
        );
        assert!(!every_output(&found).contains("bad key"));
    }

    #[test]
    fn an_unknown_switch_with_an_odd_value_is_a_gap() {
        let found = parse(&with("SOCKSEnable : 0", "FooEnable : yes"));
        assert_eq!(
            codes(&found),
            vec![(
                DiagnosticCode::ConfigScopeOmitted,
                Some("FooEnable".to_owned())
            )]
        );
    }

    // Criterion 3: a missing tool and no enabled proxies are different results.

    #[test]
    fn a_quiet_system_is_a_complete_empty_result() {
        assert_eq!(parse(QUIET), Check::Complete { value: Vec::new() });
    }

    #[test]
    fn a_missing_program_is_unavailable_and_not_equal_to_a_quiet_system() {
        let missing = proxies_from(Path::new("/nonexistent/scutil"), Duration::from_secs(5));
        assert_eq!(
            codes(&missing),
            vec![(DiagnosticCode::InspectionUnavailable, None)]
        );
        assert!(matches!(missing, Check::Unavailable { .. }));
        assert_ne!(missing, parse(QUIET));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_real_scutil_output_of_this_machine_is_read_completely() {
        // Guards the strict indent rule against the real format: a parser that rejects what
        // macOS prints would turn every doctor run into Unavailable.
        let found = system_proxies();
        assert!(
            !matches!(found, Check::Unavailable { .. }),
            "scutil output was not understood: {found:?}"
        );
    }

    // Switched-on proxies and what is kept of them.

    #[test]
    fn a_switched_on_proxy_is_named_with_its_validated_host_and_port() {
        let found = parse(&with(
            "HTTPSEnable : 0",
            "HTTPSEnable : 1\n  HTTPSProxy : proxy.corp.example\n  HTTPSPort : 8080",
        ));
        let setting = assert_some!(value(&found).first());
        assert_eq!(setting.kind, ProxyKind::Https);
        assert_eq!(
            assert_some!(setting.target.as_ref()).to_string(),
            "proxy.corp.example:8080"
        );
        assert!(matches!(found, Check::Complete { .. }));
    }

    #[test]
    fn addresses_that_are_not_names_are_accepted_as_hosts() {
        for (host, shown) in [
            ("10.0.0.1", "10.0.0.1:3128"),
            ("127.0.0.1", "127.0.0.1:3128"),
            ("::1", "[::1]:3128"),
            ("[::1]", "[::1]:3128"),
            ("localhost", "localhost:3128"),
        ] {
            let found = parse(&with(
                "HTTPEnable : 0",
                &format!("HTTPEnable : 1\n  HTTPProxy : {host}\n  HTTPPort : 3128"),
            ));
            let setting = assert_some!(value(&found).first(), "{host}");
            assert_eq!(assert_some!(setting.target.as_ref()).to_string(), shown);
        }
    }

    #[test]
    fn every_host_and_port_combination_shows_exactly_the_parsed_address() {
        for (host, port, shown) in [
            ("Proxy.Example", None, "proxy.example"),
            ("proxy.example", Some("8080"), "proxy.example:8080"),
            ("10.0.0.1", None, "10.0.0.1"),
            ("::1", None, "[::1]"),
            ("[::1]", Some("1"), "[::1]:1"),
            ("localhost", None, "localhost"),
            ("localhost", Some("65535"), "localhost:65535"),
        ] {
            let port_line = port.map_or_else(String::new, |p| format!("\n  HTTPPort : {p}"));
            let found = parse(&with(
                "HTTPEnable : 0",
                &format!("HTTPEnable : 1\n  HTTPProxy : {host}{port_line}"),
            ));
            let setting = assert_some!(value(&found).first(), "{host}");
            let target = assert_some!(setting.target.as_ref(), "{host}");
            assert_eq!(target.to_string(), shown, "{host}");
            assert_eq!(
                assert_ok!(serde_json::to_value(target)),
                serde_json::Value::String(shown.to_owned()),
                "{host}"
            );
        }
    }

    #[test]
    fn a_switch_that_is_on_without_an_address_is_listed_and_the_missing_value_is_a_gap() {
        let found = parse(&with("SOCKSEnable : 0", "SOCKSEnable : 1"));
        assert_eq!(
            value(&found),
            [ProxySetting {
                kind: ProxyKind::Socks,
                target: None
            }]
        );
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::ValueRejected, Some("SOCKSProxy".to_owned()))]
        );
    }

    #[test]
    fn a_missing_switch_means_off_as_on_a_real_machine_without_ftp() {
        assert!(!QUIET.contains("FTPEnable"));
        assert!(value(&parse(QUIET)).is_empty());
    }

    // Criterion 1: nothing secret in any output.

    #[test]
    fn a_pac_file_is_named_with_no_address_at_all() {
        let found = parse(&with(
            "ProxyAutoConfigEnable : 0",
            "ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://u:p@ss@w0rd@pac.example/wpad.dat?token=SECRET#frag",
        ));
        assert_eq!(
            value(&found),
            [ProxySetting {
                kind: ProxyKind::AutoConfig,
                target: None
            }]
        );
        let out = every_output(&found);
        for secret in [
            "p@ss",
            "w0rd",
            "SECRET",
            "token",
            "frag",
            "wpad",
            "pac.example",
        ] {
            assert!(!out.contains(secret), "{secret} leaked: {out}");
        }
    }

    #[test]
    fn a_pac_address_that_would_pass_host_validation_is_still_never_a_target() {
        for url in ["pac.example", "10.0.0.1", "localhost"] {
            let found = parse(&with(
                "ProxyAutoConfigEnable : 0",
                &format!("ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : {url}"),
            ));
            assert_eq!(
                found,
                Check::Complete {
                    value: vec![ProxySetting {
                        kind: ProxyKind::AutoConfig,
                        target: None
                    }]
                },
                "{url}"
            );
            assert!(!every_output(&found).contains(url), "{url}");
        }
    }

    #[test]
    fn a_host_with_userinfo_or_a_path_or_a_query_is_rejected_without_its_text() {
        for host in [
            "user:p@ss@proxy.example",
            "u@proxy.example",
            "proxy.example/path?x=SECRET",
            "proxy.example#SECRET",
            "http://proxy.example",
            "proxy.example:8080",
            "pro xy.example",
            "fe80::1%en0",
            "[fe80::1%en0]",
            "[proxy.example]",
        ] {
            let found = parse(&with(
                "HTTPSEnable : 0",
                &format!("HTTPSEnable : 1\n  HTTPSProxy : {host}\n  HTTPSPort : 8080"),
            ));
            let setting = assert_some!(value(&found).first(), "{host}");
            assert_eq!(setting.target, None, "{host}");
            assert_eq!(
                codes(&found),
                vec![(DiagnosticCode::ValueRejected, Some("HTTPSProxy".to_owned()))],
                "{host}"
            );
            let out = every_output(&found);
            assert!(
                !out.contains("SECRET") && !out.contains("p@ss"),
                "{host}: {out}"
            );
        }
    }

    #[test]
    fn a_bad_port_is_rejected_without_its_text() {
        for port in ["0", "65536", "-1", "8080?SECRET", "http", " 80"] {
            let found = parse(&with(
                "HTTPEnable : 0",
                &format!("HTTPEnable : 1\n  HTTPProxy : proxy.example\n  HTTPPort : {port}"),
            ));
            assert_eq!(assert_some!(value(&found).first()).target, None, "{port}");
            assert!(!every_output(&found).contains("SECRET"), "{port}");
        }
    }

    // Criterion 2: malformed, truncated and scoped settings are explicit.

    #[test]
    fn a_scoped_section_is_reported_as_not_inspected_and_never_read_as_the_global_switch() {
        // The old parser took the first HTTPEnable it saw, so this was a clean "no proxy".
        let text = "<dictionary> {\n  HTTPEnable : 0\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      HTTPEnable : 1\n      HTTPProxy : scoped.example\n    }\n  }\n}\n";
        let found = parse(text);
        assert!(value(&found).is_empty());
        assert_eq!(
            codes(&found),
            vec![(
                DiagnosticCode::ConfigScopeOmitted,
                Some("__SCOPED__".to_owned())
            )]
        );
        assert!(matches!(found, Check::Partial { .. }));
    }

    #[test]
    fn a_scoped_section_before_the_global_switch_does_not_hide_it() {
        let text = "<dictionary> {\n  __SCOPED__ : <dictionary> {\n    en0 : <dictionary> {\n      HTTPEnable : 0\n    }\n  }\n  HTTPEnable : 1\n  HTTPProxy : proxy.example\n  HTTPPort : 80\n}\n";
        let found = parse(text);
        assert_eq!(assert_some!(value(&found).first()).kind, ProxyKind::Http);
    }

    #[test]
    fn known_harmless_containers_add_no_gap_and_unknown_ones_do() {
        assert!(matches!(parse(QUIET), Check::Complete { .. }));
        let found = parse(&with(
            "ExcludeSimpleHostnames : 0",
            "Mystery : <array> {\n    0 : x\n  }",
        ));
        assert_eq!(
            codes(&found),
            vec![(
                DiagnosticCode::ConfigScopeOmitted,
                Some("Mystery".to_owned())
            )]
        );
    }

    #[test]
    fn an_unknown_enable_switch_that_is_on_is_a_gap_and_a_hostile_key_name_is_not_shown() {
        let found = parse(&with("SOCKSEnable : 0", "RTSPEnable : 1"));
        assert_eq!(
            codes(&found),
            vec![(
                DiagnosticCode::ConfigScopeOmitted,
                Some("RTSPEnable".to_owned())
            )]
        );
        let hostile = parse(&with("SOCKSEnable : 0", "Bad\u{1b}[2JEnable : 1"));
        assert_eq!(
            codes(&hostile),
            vec![(DiagnosticCode::ConfigScopeOmitted, None)]
        );
    }

    #[test]
    fn a_switch_that_is_neither_zero_nor_one_is_rejected_and_not_listed() {
        let found = parse(&with("HTTPEnable : 0", "HTTPEnable : yes"));
        assert!(value(&found).is_empty());
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::ValueRejected, Some("HTTPEnable".to_owned()))]
        );
    }

    #[test]
    fn structure_that_is_not_what_scutil_prints_is_unavailable_not_empty() {
        let cases: &[(&str, String)] = &[
            ("empty", String::new()),
            ("no dictionary", "HTTPEnable : 1\n".to_owned()),
            ("indented first line", " <dictionary> {\n}\n".to_owned()),
            ("unclosed", "<dictionary> {\n  HTTPEnable : 0\n".to_owned()),
            ("extra brace", format!("{QUIET}}}\n")),
            ("text after the end", format!("{QUIET}HTTPEnable : 1\n")),
            ("odd indent", with("HTTPEnable : 0", "   HTTPEnable : 0")),
            (
                "even but too deep",
                with("  HTTPEnable : 0", "    HTTPEnable : 1"),
            ),
            (
                "closing brace too shallow",
                with("    1 : 169.254/16\n  }", "    1 : 169.254/16\n}"),
            ),
            ("tab indent", with("  HTTPEnable : 0", "\tHTTPEnable : 0")),
            ("blank line", with("  HTTPEnable : 0", "")),
            ("no separator", with("HTTPEnable : 0", "HTTPEnable=0")),
            (
                "duplicate key",
                with("HTTPEnable : 0", "HTTPEnable : 0\n  HTTPEnable : 1"),
            ),
            (
                "closing brace at the wrong depth",
                with("    1 : 169.254/16\n  }", "    1 : 169.254/16\n    }"),
            ),
        ];
        for (name, text) in cases {
            let found = parse(text);
            assert!(
                matches!(found, Check::Unavailable { .. }),
                "{name}: {found:?}"
            );
            assert_eq!(
                codes(&found),
                vec![(DiagnosticCode::InspectionUnavailable, None)],
                "{name}"
            );
        }
    }

    #[test]
    fn an_empty_string_value_is_a_value_as_scutil_prints_it() {
        // Verified: `d.add Empty ""` then `d.show` prints `  Empty : ` with a trailing space.
        assert!(matches!(
            parse(&with("FTPPassive : 1", "FTPPassive : ")),
            Check::Complete { .. }
        ));
        assert!(matches!(
            parse(&with("0 : *.local", "0 : ")),
            Check::Complete { .. }
        ));
        // A switch that is on with an empty host is a rejected value, not a failed read.
        let found = parse(&with(
            "HTTPEnable : 0",
            "HTTPEnable : 1\n  HTTPProxy : \n  HTTPPort : 80",
        ));
        assert_eq!(assert_some!(value(&found).first()).target, None);
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::ValueRejected, Some("HTTPProxy".to_owned()))]
        );
        // A line with no separator at all is still malformed.
        assert!(matches!(
            parse(&with("HTTPEnable : 0", "HTTPEnable")),
            Check::Unavailable { .. }
        ));
    }

    #[test]
    fn nesting_deeper_than_the_limit_is_unavailable() {
        let mut text = String::from("<dictionary> {\n");
        for depth in 1..=MAX_DEPTH + 1 {
            text.push_str(&format!("{}k : <dictionary> {{\n", "  ".repeat(depth)));
        }
        assert!(matches!(parse(&text), Check::Unavailable { .. }));
    }

    // The run: every failure of the tool is Unavailable, never an empty list.

    fn fake(dir: &tempfile::TempDir, body: &str) -> std::path::PathBuf {
        let path = dir.path().join("scutil");
        assert_ok!(std::fs::write(&path, format!("#!/bin/sh\n{body}\n")));
        assert_ok!(std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o755)
        ));
        path
    }

    fn run_fake(body: &str, timeout: Duration) -> Check<Vec<ProxySetting>> {
        let dir = assert_ok!(tempfile::tempdir());
        proxies_from(&fake(&dir, body), timeout)
    }

    fn quiet_printf() -> String {
        format!("printf '%s' '{}'", QUIET.replace('\'', ""))
    }

    #[test]
    fn a_fake_scutil_that_prints_a_quiet_dictionary_is_complete() {
        let found = run_fake(&quiet_printf(), Duration::from_secs(5));
        assert_eq!(found, Check::Complete { value: Vec::new() });
    }

    #[test]
    fn a_nonzero_exit_is_unavailable_even_after_a_good_dictionary() {
        let body = format!("{}\nexit 1", quiet_printf());
        let found = run_fake(&body, Duration::from_secs(5));
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::InspectionUnavailable, None)]
        );
    }

    #[test]
    fn a_timeout_is_unavailable_with_the_limit_code_and_returns_promptly() {
        let started = std::time::Instant::now();
        let found = run_fake("sleep 20", Duration::from_millis(300));
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::InspectionLimitReached, None)]
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn output_past_the_limit_is_unavailable_with_the_limit_code() {
        let found = run_fake(
            "head -c 70000 /dev/zero | tr '\\0' 'a'",
            Duration::from_secs(5),
        );
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::InspectionLimitReached, None)]
        );
    }

    #[test]
    fn output_that_is_not_utf8_is_unavailable_not_decoded_lossily() {
        let found = run_fake("printf '\\377\\376'", Duration::from_secs(5));
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::InspectionUnavailable, None)]
        );
    }

    #[test]
    fn a_bad_byte_inside_an_otherwise_valid_dictionary_is_unavailable_not_decoded() {
        // Lossy decoding would turn the byte into U+FFFD inside an ignored value and read on.
        let found = run_fake(
            "printf '<dictionary> {\\n  FTPPassive : \\377\\n  HTTPEnable : 0\\n}\\n'",
            Duration::from_secs(5),
        );
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::InspectionUnavailable, None)]
        );
    }

    #[test]
    fn half_a_dictionary_with_a_clean_exit_is_unavailable() {
        let found = run_fake(
            "printf '<dictionary> {\\n  HTTPEnable : 0\\n'",
            Duration::from_secs(5),
        );
        assert_eq!(
            codes(&found),
            vec![(DiagnosticCode::InspectionUnavailable, None)]
        );
    }

    // Hostile input: whatever the fields hold, none of it comes out.

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Whatever surrounds it, a secret that rides in a host, a port or a PAC address is never
        /// shown. Each field gets the hostile text on its own, so a rejected value cannot be
        /// confused with an accepted one.
        #[test]
        fn no_hostile_text_in_a_url_host_or_port_ever_reaches_an_output(
            pieces in prop::collection::vec(
                prop::sample::select(vec![
                    "@", ":", "?", "#", "/", "%", "\u{202e}", "\u{2066}", "a", "Z", "0", ".",
                    "-", "[", "]", " ", "p@ss", "u:pw@",
                ]),
                0..24,
            ),
        ) {
            // Always contains a character no host or port accepts, so the whole value must be
            // rejected, and the marker is lower-cased because validation lower-cases hosts.
            let secret = "zzsecretzz";
            let value = format!("{}{}@{}", pieces.concat(), secret, pieces.concat());
            for (field, enabled) in [
                ("HTTPSProxy", "HTTPSEnable"),
                ("HTTPSPort", "HTTPSEnable"),
                ("ProxyAutoConfigURLString", "ProxyAutoConfigEnable"),
            ] {
                let other = if field == "HTTPSPort" { "HTTPSProxy : ok.example\n  " } else { "" };
                let text = format!(
                    "<dictionary> {{\n  {enabled} : 1\n  {other}{field} : {value}\n}}\n"
                );
                let found = parse(&text);
                let out = every_output(&found).to_lowercase();
                let leaked = out.contains(secret);
                prop_assert!(!leaked, "{} leaked into {}", field, out);
                // The kind is still listed, with no target to hold the text.
                let no_target = value_targets(&found).iter().all(Option::is_none);
                prop_assert!(no_target, "{} produced a target: {}", field, out);
            }
        }

        /// Control and bidirectional characters in a key or value never reach an output either.
        #[test]
        fn control_and_bidi_text_never_reaches_an_output(
            junk in prop::sample::select(vec![
                "\u{1b}[2J", "\u{202e}", "\u{2066}", "\u{0}", "\r", "\u{85}", "\t",
            ]),
        ) {
            for text in [
                format!("<dictionary> {{\n  HTTPEnable : 1\n  HTTPProxy : h{junk}.example\n}}\n"),
                format!("<dictionary> {{\n  K{junk}Enable : 1\n}}\n"),
                format!("<dictionary> {{\n  S{junk} : <dictionary> {{\n  }}\n}}\n"),
            ] {
                let out = every_output(&parse(&text));
                let has_control = out.chars().any(crate::text::needs_escaping);
                prop_assert!(!has_control, "{}", "a control character reached an output");
            }
        }

        #[test]
        fn arbitrary_text_never_panics_and_complete_needs_a_dictionary(
            text in "(?s).{0,400}",
        ) {
            let found = parse(&text);
            if matches!(found, Check::Complete { .. }) {
                let opens = text.starts_with("<dictionary> {\n");
                prop_assert!(opens, "{}", "complete without a dictionary");
            }
        }
    }

    #[test]
    fn the_property_generator_can_reach_a_complete_result() {
        // Guards against the property being vacuous: a dictionary the generator's shape can
        // produce does parse as Complete.
        assert!(matches!(parse(QUIET), Check::Complete { .. }));
    }

    fn value_targets(check: &Check<Vec<ProxySetting>>) -> Vec<Option<ProxyTarget>> {
        value(check).iter().map(|p| p.target.clone()).collect()
    }
}
