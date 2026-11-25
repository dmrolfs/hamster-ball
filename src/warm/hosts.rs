// ABOUTME: The hosts `hb warm` may reach while it starts one MCP server: the registries, its git source hosts and its own `warm_net`.
// ABOUTME: Pure. The run allowlist (`net.allow` and `[mcp] net`) is deliberately not part of it, and `warm_net` is not part of a run's.
//! The warm-time allowlist of one server (design 10, hb-ghd.7.3).

use std::collections::BTreeSet;

use crate::config::ResolvedMcpServer;
use crate::policy::{ArgWord, HostRule};

/// The package registries `uvx` and `npx` install from.
pub const REGISTRIES: [&str; 3] = ["pypi.org", "files.pythonhosted.org", "registry.npmjs.org"];

/// What a git source on `github.com` also needs, measured: the API and the raw file host.
const GITHUB_EXTRAS: [&str; 2] = ["api.github.com", "raw.githubusercontent.com"];

/// The scheme of a git source that `uv` fetches over HTTPS.
const GIT_HTTPS: &str = "git+https://";

/// The hosts `hb warm` allows while it starts `server`, in order, without duplicates.
///
/// The registries, the host of every `git+https://HOST/...` argument (`github.com` brings its API
/// and raw hosts), and the server's `warm_net`. An argument that does not name a valid host adds
/// nothing: the install then fails visibly at the proxy, not silently here.
#[must_use]
pub fn allowlist(server: &ResolvedMcpServer) -> Vec<HostRule> {
    let from_text = REGISTRIES
        .iter()
        .map(ToString::to_string)
        .chain(git_hosts(&server.args));
    from_text
        .filter_map(|entry| HostRule::parse(&entry).ok())
        .chain(server.warm_net.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// The `host` or `host:port` of each git source among `args`, plus what `github.com` needs.
fn git_hosts(args: &[ArgWord]) -> Vec<String> {
    let mut hosts = Vec::new();
    for arg in args {
        let mut rest = arg.as_str();
        while let Some(at) = rest.find(GIT_HTTPS) {
            rest = &rest[at + GIT_HTTPS.len()..];
            let authority = rest.split('/').next().unwrap_or_default();
            let host = authority.rsplit('@').next().unwrap_or_default();
            if host.is_empty() {
                continue;
            }
            hosts.push(host.to_owned());
            if host == "github.com" {
                hosts.extend(GITHUB_EXTRAS.iter().map(ToString::to_string));
            }
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use claims::assert_ok;
    use pretty_assertions::assert_eq;

    use super::*;

    fn server(args: &[&str], warm_net: &[&str], net: &[&str]) -> ResolvedMcpServer {
        ResolvedMcpServer {
            command: Some(assert_ok!(ArgWord::parse_program("uvx"))),
            args: args.iter().map(|a| assert_ok!(ArgWord::parse(a))).collect(),
            warm_net: warm_net
                .iter()
                .map(|h| assert_ok!(HostRule::parse(h)))
                .collect(),
            net: net.iter().map(|h| assert_ok!(HostRule::parse(h))).collect(),
            ..ResolvedMcpServer::default()
        }
    }

    fn shown(rules: &[HostRule]) -> Vec<String> {
        rules
            .iter()
            .map(|r| format!("{}:{}", r.pattern, r.port))
            .collect()
    }

    #[test]
    fn a_registry_server_gets_exactly_the_three_registries() {
        assert_eq!(
            shown(&allowlist(&server(&["mcp-server-time"], &[], &[]))),
            [
                "files.pythonhosted.org:443",
                "pypi.org:443",
                "registry.npmjs.org:443"
            ]
        );
    }

    #[test]
    fn a_github_source_adds_github_and_its_api_and_raw_hosts() {
        let hosts = shown(&allowlist(&server(
            &[
                "--from",
                "git+https://github.com/oraios/serena@abc",
                "serena",
            ],
            &[],
            &[],
        )));
        for wanted in [
            "github.com:443",
            "api.github.com:443",
            "raw.githubusercontent.com:443",
        ] {
            assert!(hosts.iter().any(|h| h == wanted), "{wanted}: {hosts:?}");
        }
    }

    #[test]
    fn another_git_host_adds_only_itself_with_its_port_and_without_userinfo() {
        let hosts = shown(&allowlist(&server(
            &[
                "--from=git+https://deploy:token@git.corp.example:8443/team/x",
                "x",
            ],
            &[],
            &[],
        )));
        assert!(
            hosts.iter().any(|h| h == "git.corp.example:8443"),
            "{hosts:?}"
        );
        assert!(
            !hosts
                .iter()
                .any(|h| h.contains("token") || h.contains("api.github")),
            "{hosts:?}"
        );
    }

    #[test]
    fn warm_net_is_added_and_net_is_not() {
        let hosts = shown(&allowlist(&server(
            &["pkg"],
            &["oraios-software.de"],
            &["mcp.example.com"],
        )));
        assert!(
            hosts.iter().any(|h| h == "oraios-software.de:443"),
            "{hosts:?}"
        );
        assert!(
            !hosts.iter().any(|h| h.contains("mcp.example.com")),
            "{hosts:?}"
        );
    }

    #[test]
    fn duplicates_collapse_and_an_unparsable_source_host_adds_nothing() {
        let hosts = shown(&allowlist(&server(
            &[
                "git+https://pypi.org/x",
                "git+https://bad host/x",
                "git+https:///nohost",
                "git+http://insecure.example/x",
            ],
            &["pypi.org"],
            &[],
        )));
        assert_eq!(
            hosts,
            [
                "files.pythonhosted.org:443",
                "pypi.org:443",
                "registry.npmjs.org:443"
            ]
        );
    }

    #[test]
    fn two_sources_in_one_argument_are_both_found() {
        let hosts = shown(&allowlist(&server(
            &["git+https://one.example/a git+https://two.example/b"],
            &[],
            &[],
        )));
        assert!(hosts.iter().any(|h| h == "one.example:443"), "{hosts:?}");
        assert!(hosts.iter().any(|h| h == "two.example:443"), "{hosts:?}");
    }
}
