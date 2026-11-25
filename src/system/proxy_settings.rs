// ABOUTME: Reads the macOS system proxy settings (`scutil --proxy`) and says which of them hb does not follow.
// ABOUTME: Only the on/off flags and the host and port are kept; no credential or exception list is read into a report.
//! The host's proxy configuration (design 4.5, 12.1, D74).
//!
//! `hb`'s proxy connects directly. A network that needs an upstream proxy or a PAC file will
//! fail every connection, and the agent can read these settings through `configd` while
//! `tls.system_trust` is on. `hb doctor` reports both.

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::sys::run_bounded;

/// `scutil`, the program that prints the system proxy settings.
const SCUTIL: &str = "/usr/sbin/scutil";
/// The most output read.
const MAX_BYTES: u64 = 64 * 1024;
/// How long `scutil` may take.
const TIMEOUT: Duration = Duration::from_secs(5);

/// One proxy the system has switched on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxySetting {
    /// What it is: `HTTP`, `HTTPS`, `SOCKS`, `FTP`, `PAC file` or `automatic discovery`.
    pub kind: &'static str,
    /// The host and port (or the PAC address) the system names, if it names one.
    pub target: Option<String>,
}

/// The kinds `scutil` prints, with the key that switches each on and the keys of its address.
const KINDS: &[(&str, &str, &str, Option<&str>)] = &[
    ("HTTP", "HTTPEnable", "HTTPProxy", Some("HTTPPort")),
    ("HTTPS", "HTTPSEnable", "HTTPSProxy", Some("HTTPSPort")),
    ("SOCKS", "SOCKSEnable", "SOCKSProxy", Some("SOCKSPort")),
    ("FTP", "FTPEnable", "FTPProxy", Some("FTPPort")),
    (
        "PAC file",
        "ProxyAutoConfigEnable",
        "ProxyAutoConfigURLString",
        None,
    ),
    ("automatic discovery", "ProxyAutoDiscoveryEnable", "", None),
];

/// The proxies switched on in `scutil --proxy` output.
#[must_use]
pub fn enabled_proxies(text: &str) -> Vec<ProxySetting> {
    let value = |key: &str| -> Option<&str> {
        text.lines().find_map(|line| {
            let (name, value) = line.split_once(" : ")?;
            (name.trim() == key).then(|| value.trim())
        })
    };
    KINDS
        .iter()
        .filter(|(_, enable, _, _)| value(enable) == Some("1"))
        .map(|(kind, _, host_key, port_key)| {
            let host = value(host_key).filter(|h| !h.is_empty());
            let port = port_key.and_then(&value);
            let target = host.map(|h| match port {
                Some(p) => format!("{h}:{p}"),
                None => h.to_owned(),
            });
            ProxySetting {
                kind,
                target: target.map(|t| strip_userinfo(&t)),
            }
        })
        .collect()
}

/// A PAC URL can carry `user:password@`; keep only what follows it.
fn strip_userinfo(text: &str) -> String {
    match (text.find("://"), text.find('@')) {
        (Some(scheme), Some(at)) if at > scheme => {
            format!("{}{}", &text[..scheme + 3], &text[at + 1..])
        }
        (None, Some(at)) => text[at + 1..].to_owned(),
        _ => text.to_owned(),
    }
}

/// The proxies the system has switched on, or none if `scutil` cannot be run.
#[must_use]
pub fn system_proxies() -> Vec<ProxySetting> {
    proxies_from(Path::new(SCUTIL))
}

fn proxies_from(scutil: &Path) -> Vec<ProxySetting> {
    let mut command = Command::new(scutil);
    command.arg("--proxy");
    match run_bounded(&mut command, TIMEOUT, MAX_BYTES) {
        Ok(done) if done.status.success() => {
            enabled_proxies(&String::from_utf8_lossy(&done.stdout))
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    const QUIET: &str = "<dictionary> {\n  ExceptionsList : <array> {\n    0 : *.local\n  }\n  HTTPEnable : 0\n  HTTPSEnable : 0\n  ProxyAutoConfigEnable : 0\n  ProxyAutoDiscoveryEnable : 0\n  SOCKSEnable : 0\n}\n";

    #[test]
    fn a_quiet_system_has_no_proxy() {
        assert_eq!(enabled_proxies(QUIET), Vec::new());
        assert_eq!(enabled_proxies(""), Vec::new());
    }

    #[test]
    fn a_switched_on_proxy_is_named_with_its_host_and_port() {
        let text = QUIET.replace(
            "HTTPSEnable : 0",
            "HTTPSEnable : 1\n  HTTPSProxy : proxy.corp.example\n  HTTPSPort : 8080",
        );
        assert_eq!(
            enabled_proxies(&text),
            vec![ProxySetting {
                kind: "HTTPS",
                target: Some("proxy.corp.example:8080".to_owned())
            }]
        );
    }

    #[test]
    fn a_pac_file_and_discovery_are_named_and_a_pac_password_is_dropped() {
        let text = QUIET
            .replace(
                "ProxyAutoConfigEnable : 0",
                "ProxyAutoConfigEnable : 1\n  ProxyAutoConfigURLString : http://user:secret@pac.corp.example/wpad.dat",
            )
            .replace("ProxyAutoDiscoveryEnable : 0", "ProxyAutoDiscoveryEnable : 1");
        let found = enabled_proxies(&text);
        assert_eq!(
            found,
            vec![
                ProxySetting {
                    kind: "PAC file",
                    target: Some("http://pac.corp.example/wpad.dat".to_owned())
                },
                ProxySetting {
                    kind: "automatic discovery",
                    target: None
                },
            ]
        );
        assert!(!format!("{found:?}").contains("secret"));
    }

    #[test]
    fn a_switch_that_is_on_without_an_address_still_counts() {
        let text = QUIET.replace("SOCKSEnable : 0", "SOCKSEnable : 1");
        assert_eq!(
            enabled_proxies(&text),
            vec![ProxySetting {
                kind: "SOCKS",
                target: None
            }]
        );
    }

    #[test]
    fn a_missing_program_gives_no_proxies() {
        assert_eq!(proxies_from(Path::new("/nonexistent/scutil")), Vec::new());
    }

    #[test]
    fn the_real_system_is_read_without_error() {
        // The result depends on the machine; reading it must not fail or hang.
        let _ = system_proxies();
    }
}
