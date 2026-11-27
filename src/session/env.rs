// ABOUTME: ChildEnv: the child's environment, built from empty so no token in the parent shell reaches the agent.
// ABOUTME: A pure function of the parent snapshot, the policy's [env] section and a few facts about this run.
//! The child's environment (design 7.2).
//!
//! Built from nothing. The old `sb` exported a few variables on top of the parent's environment,
//! so every token in the shell reached the agent. This builder never reads the process; it
//! takes a snapshot ([`ParentVars`]) and copies only the names the config lists.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;

use snafu::{Snafu, ensure};

use crate::config::MergedEnv;
use crate::policy::{CanonicalPath, EnvName, HomeDir};
use crate::proxy::ProxyUrl;
use crate::system::ParentVars;

/// The directories every program needs, always first on the child's `PATH`.
pub const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// Set in the child so a nested `hb` can say it is inside one (design 7.4). It proves nothing:
/// other sandboxes leave no marker, and the preflight is what decides.
pub const SESSION_MARKER: &str = "HB_SESSION";

/// The variable that carries a run's launch token, which the guard's teardown sweep looks for.
pub const LAUNCH_TOKEN_VAR: &str = "HB_LAUNCH_TOKEN";
/// `TERM` when stdin is not a terminal, or the parent has none.
pub const DUMB_TERM: &str = "dumb";

/// The variables that point a client at the proxy: the forms tools read, upper and lower case.
pub const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];
/// What bypasses the proxy: the loopback ports the policy lists are reached directly, because the
/// profile allows nothing else on loopback and the proxy refuses `localhost` (design 12).
pub const NO_PROXY_VALUE: &str = "localhost,127.0.0.1";

/// Why the environment could not be built.
#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum EnvBuildError {
    /// A config listed a name `hb` sets itself. `resolve` rejects these; this is the second check.
    #[snafu(display("environment variable {name} is set by hb and cannot be passed or set"))]
    Reserved {
        /// The name.
        name: EnvName,
    },

    /// A tool directory contains `:`, which would split it in two inside `PATH`.
    #[snafu(display("the tool directory {dir} contains a `:` and cannot go on PATH"))]
    ColonInToolDir {
        /// The directory.
        dir: String,
    },
}

/// What the child needs to know about TLS trust (design 4.5).
#[derive(Debug, Clone, Copy, Default)]
pub struct TlsEnv<'a> {
    /// `tls.system_trust`: Node is told to use the system certificate store.
    pub system_trust: bool,
    /// The per-session bundle of `tls.extra_ca_files`, if there are any: Node adds its certificates.
    pub ca_bundle: Option<&'a CanonicalPath>,
}

/// What the child's environment is built from.
#[derive(Debug, Clone, Copy)]
pub struct EnvInputs<'a> {
    /// The parent's variables, from which `pass` copies.
    pub parent: &'a ParentVars,
    /// The real home directory.
    pub home: &'a HomeDir,
    /// This run's private directory, which becomes `TMPDIR`.
    pub session_dir: &'a CanonicalPath,
    /// Directories of `[env] tools`, appended to `PATH` in this order.
    pub tool_dirs: &'a [CanonicalPath],
    /// The directory of the offline `uvx` and `npx` launchers, put first on `PATH`.
    pub shim_dir: Option<&'a CanonicalPath>,
    /// Whether stdin is a terminal, which decides `TERM`.
    pub stdin_is_tty: bool,
    /// The merged `[env]` section.
    pub env: &'a MergedEnv,
    /// TLS trust settings.
    pub tls: TlsEnv<'a>,
    /// The proxy the child must use. `None` only for a child that has no network at all.
    pub proxy: Option<&'a ProxyUrl>,
    /// The variables the pre-run hooks set, each naming a file in the session directory. They
    /// win over `[env] set`: a hook is the later and more specific word.
    pub hook_vars: &'a BTreeMap<EnvName, CanonicalPath>,
    /// The `hb ctl` broker socket, when this run has one. Set last, so nothing can override it.
    pub ctl_socket: Option<&'a CanonicalPath>,
    /// The value of `HB_LAUNCH_TOKEN`, when the run has a guard that sweeps for leftovers.
    /// `HB_` names are reserved, so configuration cannot set or pass it.
    pub launch_token: Option<&'a str>,
}

/// What `[env] set` values may contain to name this run's private directory.
pub const SESSION_DIR_PLACEHOLDER: &str = "{session_dir}";

/// The environment the child starts with, and nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct ChildEnv(BTreeMap<OsString, OsString>);

impl ChildEnv {
    /// Builds the child's environment.
    ///
    /// # Errors
    /// [`EnvBuildError::Reserved`] if the config names a variable `hb` sets, or
    /// [`EnvBuildError::ColonInToolDir`] if a tool directory cannot go on `PATH`.
    pub fn build(inputs: &EnvInputs<'_>) -> Result<Self, EnvBuildError> {
        let mut vars: BTreeMap<OsString, OsString> = BTreeMap::new();
        for pass in &inputs.env.pass {
            ensure!(
                !pass.value.is_reserved(),
                ReservedSnafu {
                    name: pass.value.clone()
                }
            );
            if let Some(value) = inputs.parent.get(pass.value.as_str()) {
                vars.insert(OsString::from(pass.value.as_str()), value.to_owned());
            }
        }
        for (name, value) in &inputs.env.set {
            ensure!(!name.is_reserved(), ReservedSnafu { name: name.clone() });
            vars.insert(
                OsString::from(name.as_str()),
                OsString::from(
                    value
                        .value
                        .as_str()
                        .replace(SESSION_DIR_PLACEHOLDER, inputs.session_dir.as_str()),
                ),
            );
        }
        for (name, path) in inputs.hook_vars {
            vars.insert(OsString::from(name.as_str()), OsString::from(path.as_str()));
        }
        vars.insert(SESSION_MARKER.into(), "1".into());
        if let Some(token) = inputs.launch_token {
            vars.insert(LAUNCH_TOKEN_VAR.into(), token.into());
        }
        if let Some(socket) = inputs.ctl_socket {
            vars.insert(
                crate::ctl::client::SOCKET_VAR.into(),
                socket.as_str().into(),
            );
        }
        vars.insert("HOME".into(), inputs.home.path().as_str().into());
        vars.insert("TMPDIR".into(), inputs.session_dir.as_str().into());
        vars.insert(
            "PATH".into(),
            path_value(inputs.shim_dir, inputs.tool_dirs)?,
        );
        vars.insert("TERM".into(), term_value(inputs));
        // Only Node's variables: `SSL_CERT_FILE` and its kin would replace the public roots in the
        // clients that read them (measured: Python, uv) and mean nothing to curl and git.
        if inputs.tls.system_trust {
            vars.insert("NODE_USE_SYSTEM_CA".into(), "1".into());
        }
        if let Some(bundle) = inputs.tls.ca_bundle {
            vars.insert("NODE_EXTRA_CA_CERTS".into(), bundle.as_str().into());
        }
        if let Some(url) = inputs.proxy {
            for name in PROXY_VARS {
                vars.insert(name.into(), url.expose().into());
            }
            vars.insert("NO_PROXY".into(), NO_PROXY_VALUE.into());
            vars.insert("no_proxy".into(), NO_PROXY_VALUE.into());
        }
        Ok(Self(vars))
    }

    /// The value of `name`, if the child will have it.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&OsStr> {
        self.0.get(OsStr::new(name)).map(OsString::as_os_str)
    }

    /// The variable names, sorted.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.0.keys().filter_map(|k| k.to_str())
    }

    /// Every variable, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.0.iter().map(|(k, v)| (k.as_os_str(), v.as_os_str()))
    }

    /// What this environment adds to the size of an `exec`: each `name=value` string with its
    /// terminator and a pointer.
    #[must_use]
    pub fn exec_bytes(&self) -> usize {
        self.0
            .iter()
            .map(|(k, v)| k.len() + 1 + v.len() + 1 + POINTER_BYTES)
            .sum()
    }
}

/// Bytes one pointer takes in the argument block.
const POINTER_BYTES: usize = 8;

// Values can be secrets, so `Debug` lists names only.
impl fmt::Debug for ChildEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set().entries(self.0.keys()).finish()
    }
}

fn path_value(
    shim_dir: Option<&CanonicalPath>,
    tool_dirs: &[CanonicalPath],
) -> Result<OsString, EnvBuildError> {
    let mut path = String::new();
    if let Some(dir) = shim_dir {
        ensure!(
            !dir.as_str().contains(':'),
            ColonInToolDirSnafu {
                dir: dir.as_str().to_owned()
            }
        );
        path.push_str(dir.as_str());
        path.push(':');
    }
    path.push_str(SYSTEM_PATH);
    for dir in tool_dirs {
        ensure!(
            !dir.as_str().contains(':'),
            ColonInToolDirSnafu {
                dir: dir.as_str().to_owned()
            }
        );
        path.push(':');
        path.push_str(dir.as_str());
    }
    Ok(path.into())
}

/// The parent's `TERM` when stdin is a terminal, else `dumb`.
fn term_value(inputs: &EnvInputs<'_>) -> OsString {
    let parent = inputs.parent.get("TERM").filter(|t| !t.is_empty());
    match parent {
        Some(term) if inputs.stdin_is_tty => term.to_owned(),
        _ => OsString::from(DUMB_TERM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::origin::{FileId, Source, Sourced};
    use crate::policy::EnvValue;
    use claims::{assert_err, assert_ok};
    use pretty_assertions::assert_eq;

    fn cp(path: &str) -> CanonicalPath {
        assert_ok!(CanonicalPath::from_canonical(path))
    }

    fn name(n: &str) -> EnvName {
        assert_ok!(EnvName::parse(n))
    }

    fn src() -> Source {
        Source::value(FileId::new(0))
    }

    fn parent(pairs: &[(&str, &str)]) -> ParentVars {
        ParentVars::from_pairs(
            pairs
                .iter()
                .map(|(k, v)| (OsString::from(k), OsString::from(v))),
        )
    }

    fn merged(pass: &[&str], set: &[(&str, &str)]) -> MergedEnv {
        let mut env = MergedEnv {
            pass: pass.iter().map(|n| Sourced::new(name(n), src())).collect(),
            ..MergedEnv::default()
        };
        for (k, v) in set {
            env.set
                .insert(name(k), Sourced::new(assert_ok!(EnvValue::parse(v)), src()));
        }
        env
    }

    struct Case {
        parent: ParentVars,
        home: HomeDir,
        session: CanonicalPath,
        tools: Vec<CanonicalPath>,
        shim: Option<CanonicalPath>,
        tty: bool,
        env: MergedEnv,
        trust: bool,
        bundle: Option<CanonicalPath>,
        proxy: Option<ProxyUrl>,
        hook_vars: BTreeMap<EnvName, CanonicalPath>,
        ctl_socket: Option<CanonicalPath>,
        token: Option<String>,
    }

    impl Case {
        fn new() -> Self {
            Self {
                parent: ParentVars::default(),
                home: HomeDir::new(cp("/Users/me")),
                session: cp("/private/var/folders/x/T/hb-1-2-3"),
                tools: Vec::new(),
                shim: None,
                tty: false,
                env: MergedEnv::default(),
                trust: false,
                bundle: None,
                proxy: None,
                hook_vars: BTreeMap::new(),
                ctl_socket: None,
                token: None,
            }
        }

        fn build(&self) -> Result<ChildEnv, EnvBuildError> {
            ChildEnv::build(&EnvInputs {
                parent: &self.parent,
                home: &self.home,
                session_dir: &self.session,
                tool_dirs: &self.tools,
                shim_dir: self.shim.as_ref(),
                stdin_is_tty: self.tty,
                env: &self.env,
                tls: TlsEnv {
                    system_trust: self.trust,
                    ca_bundle: self.bundle.as_ref(),
                },
                proxy: self.proxy.as_ref(),
                hook_vars: &self.hook_vars,
                ctl_socket: self.ctl_socket.as_ref(),
                launch_token: self.token.as_deref(),
            })
        }

        fn ok(&self) -> ChildEnv {
            assert_ok!(self.build())
        }
    }

    fn get<'a>(env: &'a ChildEnv, key: &str) -> Option<&'a OsStr> {
        env.get(key)
    }

    fn proxy_url() -> ProxyUrl {
        let token = assert_ok!(crate::proxy::Token::generate());
        ProxyUrl::new(51234, &token)
    }

    #[test]
    fn the_session_dir_placeholder_in_a_set_value_names_this_runs_directory() {
        let mut case = Case::new();
        case.env = merged(
            &[],
            &[
                ("CLAUDE_CODE_TMPDIR", "{session_dir}"),
                ("TWICE", "{session_dir}/a:{session_dir}/b"),
                ("OTHER", "{not_a_placeholder}"),
            ],
        );
        let env = assert_ok!(case.build());
        let session = "/private/var/folders/x/T/hb-1-2-3";
        assert_eq!(env.get("CLAUDE_CODE_TMPDIR"), Some(OsStr::new(session)));
        assert_eq!(
            env.get("TWICE"),
            Some(OsStr::new(&format!("{session}/a:{session}/b")))
        );
        assert_eq!(env.get("OTHER"), Some(OsStr::new("{not_a_placeholder}")));
    }

    #[test]
    fn a_variable_a_hook_set_wins_over_the_config_and_is_a_path_in_the_session() {
        let mut case = Case::new();
        case.env = merged(&[], &[("AWS_CONFIG_FILE", "/elsewhere/config")]);
        case.hook_vars.insert(
            name("AWS_CONFIG_FILE"),
            cp("/private/var/folders/x/T/hb-1-2-3/hooks/b/config"),
        );
        case.hook_vars.insert(
            name("OTHER_FILE"),
            cp("/private/var/folders/x/T/hb-1-2-3/hooks/b/other"),
        );
        let env = assert_ok!(case.build());
        assert_eq!(
            env.get("AWS_CONFIG_FILE"),
            Some(OsStr::new(
                "/private/var/folders/x/T/hb-1-2-3/hooks/b/config"
            ))
        );
        assert_eq!(
            env.get("OTHER_FILE"),
            Some(OsStr::new(
                "/private/var/folders/x/T/hb-1-2-3/hooks/b/other"
            ))
        );
    }

    #[test]
    fn a_proxy_sets_all_six_proxy_variables_to_its_url_and_no_proxy_to_loopback() {
        let mut case = Case::new();
        let url = proxy_url();
        case.proxy = Some(url.clone());
        let env = case.ok();
        for name in PROXY_VARS {
            assert_eq!(get(&env, name), Some(OsStr::new(url.expose())), "{name}");
        }
        for name in ["NO_PROXY", "no_proxy"] {
            assert_eq!(
                get(&env, name),
                Some(OsStr::new("localhost,127.0.0.1")),
                "{name}"
            );
        }
        assert!(
            url.expose().starts_with("http://hb:") && url.expose().ends_with("@127.0.0.1:51234")
        );
    }

    #[test]
    fn without_a_proxy_no_proxy_variable_is_set() {
        let env = Case::new().ok();
        for name in PROXY_VARS.iter().chain(["NO_PROXY", "no_proxy"].iter()) {
            assert_eq!(get(&env, name), None, "{name}");
        }
    }

    #[test]
    fn the_parent_cannot_pass_and_the_config_cannot_set_a_proxy_variable() {
        for name in PROXY_VARS.iter().chain(["NO_PROXY", "no_proxy"].iter()) {
            let mut case = Case::new();
            case.proxy = Some(proxy_url());
            case.parent = parent(&[(name, "http://evil.example.com:3128")]);
            case.env = merged(&[name], &[]);
            let error = assert_err!(case.build());
            assert!(
                matches!(error, EnvBuildError::Reserved { .. }),
                "{name}: {error}"
            );
            let mut case = Case::new();
            case.proxy = Some(proxy_url());
            case.env = merged(&[], &[(name, "http://evil.example.com:3128")]);
            assert!(
                matches!(assert_err!(case.build()), EnvBuildError::Reserved { .. }),
                "{name}"
            );
        }
    }

    #[test]
    fn nothing_from_the_parent_survives_unless_named() {
        let mut case = Case::new();
        case.parent = parent(&[
            ("GITHUB_TOKEN", "ghp_x"),
            ("AWS_SECRET_ACCESS_KEY", "k"),
            ("LANG", "en_US.UTF-8"),
            ("SSH_AUTH_SOCK", "/tmp/agent"),
        ]);
        let names: Vec<String> = case.ok().names().map(str::to_owned).collect();
        assert_eq!(names, vec!["HB_SESSION", "HOME", "PATH", "TERM", "TMPDIR"]);
    }

    #[test]
    fn the_fixed_variables_have_their_documented_values() {
        let env = Case::new().ok();
        assert_eq!(get(&env, "HOME"), Some(OsStr::new("/Users/me")));
        assert_eq!(
            get(&env, "TMPDIR"),
            Some(OsStr::new("/private/var/folders/x/T/hb-1-2-3"))
        );
        assert_eq!(get(&env, "PATH"), Some(OsStr::new(SYSTEM_PATH)));
        assert_eq!(get(&env, "TERM"), Some(OsStr::new("dumb")));
        assert_eq!(get(&env, "HB_SESSION"), Some(OsStr::new("1")));
    }

    #[test]
    fn pass_copies_only_names_that_are_set_in_the_parent() {
        let mut case = Case::new();
        case.parent = parent(&[("LANG", "en_US.UTF-8"), ("GITHUB_TOKEN", "ghp_x")]);
        case.env = merged(&["LANG", "COLORTERM"], &[]);
        let env = case.ok();
        assert_eq!(get(&env, "LANG"), Some(OsStr::new("en_US.UTF-8")));
        assert_eq!(get(&env, "COLORTERM"), None);
        assert_eq!(get(&env, "GITHUB_TOKEN"), None);
    }

    #[test]
    fn set_adds_a_literal_and_wins_over_pass() {
        let mut case = Case::new();
        case.parent = parent(&[("RUST_LOG", "from-parent")]);
        case.env = merged(
            &["RUST_LOG"],
            &[("RUST_LOG", "debug"), ("RUST_BACKTRACE", "1")],
        );
        let env = case.ok();
        assert_eq!(get(&env, "RUST_LOG"), Some(OsStr::new("debug")));
        assert_eq!(get(&env, "RUST_BACKTRACE"), Some(OsStr::new("1")));
    }

    #[test]
    fn term_is_the_parents_on_a_tty_and_dumb_otherwise() {
        let mut case = Case::new();
        case.parent = parent(&[("TERM", "xterm-256color")]);
        case.tty = true;
        assert_eq!(get(&case.ok(), "TERM"), Some(OsStr::new("xterm-256color")));
        case.tty = false;
        assert_eq!(get(&case.ok(), "TERM"), Some(OsStr::new("dumb")));
        case.tty = true;
        case.parent = ParentVars::default();
        assert_eq!(get(&case.ok(), "TERM"), Some(OsStr::new("dumb")));
    }

    #[test]
    fn the_launcher_directory_comes_before_the_system_path_and_only_when_there_is_one() {
        let mut case = Case::new();
        case.tools = vec![cp("/Users/me/.nvm/bin")];
        case.shim = Some(cp("/private/var/folders/x/T/hb-1-2-3/bin"));
        assert_eq!(
            get(&case.ok(), "PATH"),
            Some(OsStr::new(&format!(
                "/private/var/folders/x/T/hb-1-2-3/bin:{SYSTEM_PATH}:/Users/me/.nvm/bin"
            )))
        );
        case.shim = None;
        assert_eq!(
            get(&case.ok(), "PATH"),
            Some(OsStr::new(&format!("{SYSTEM_PATH}:/Users/me/.nvm/bin")))
        );
    }

    #[test]
    fn a_launcher_directory_with_a_colon_cannot_go_on_path() {
        let mut case = Case::new();
        case.shim = Some(cp("/private/tmp/a:b/bin"));
        assert!(matches!(
            case.build(),
            Err(EnvBuildError::ColonInToolDir { .. })
        ));
    }

    #[test]
    fn tool_directories_follow_the_system_path_in_order() {
        let mut case = Case::new();
        case.tools = vec![cp("/Users/me/.nvm/bin"), cp("/opt/homebrew/bin")];
        assert_eq!(
            get(&case.ok(), "PATH"),
            Some(OsStr::new(&format!(
                "{SYSTEM_PATH}:/Users/me/.nvm/bin:/opt/homebrew/bin"
            )))
        );
    }

    #[test]
    fn a_tool_directory_with_a_colon_is_refused() {
        let mut case = Case::new();
        case.tools = vec![cp("/Users/me/odd:dir")];
        assert!(matches!(
            assert_err!(case.build()),
            EnvBuildError::ColonInToolDir { .. }
        ));
    }

    #[test]
    fn node_is_told_to_use_the_system_store_only_when_system_trust_is_on() {
        let mut case = Case::new();
        assert_eq!(case.ok().get("NODE_USE_SYSTEM_CA"), None);
        case.trust = true;
        assert_eq!(case.ok().get("NODE_USE_SYSTEM_CA"), Some(OsStr::new("1")));
    }

    #[test]
    fn node_gets_the_session_bundle_as_its_extra_ca_file_only_when_there_is_one() {
        let mut case = Case::new();
        assert_eq!(case.ok().get("NODE_EXTRA_CA_CERTS"), None);
        case.bundle = Some(cp("/private/var/folders/x/T/hb-1-2-3/ca-bundle.pem"));
        assert_eq!(
            case.ok().get("NODE_EXTRA_CA_CERTS"),
            Some(OsStr::new(
                "/private/var/folders/x/T/hb-1-2-3/ca-bundle.pem"
            ))
        );
    }

    #[test]
    fn the_two_settings_are_independent_and_nothing_else_about_tls_is_set() {
        let mut case = Case::new();
        case.trust = true;
        case.bundle = Some(cp("/private/var/folders/x/T/hb-1-2-3/ca-bundle.pem"));
        let env = case.ok();
        for name in ["NODE_USE_SYSTEM_CA", "NODE_EXTRA_CA_CERTS"] {
            assert!(env.get(name).is_some(), "{name}");
        }
        for name in [
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "CURL_CA_BUNDLE",
            "GIT_SSL_CAINFO",
            "REQUESTS_CA_BUNDLE",
        ] {
            assert_eq!(
                env.get(name),
                None,
                "{name} replaces the public roots in some clients, so hb does not set it"
            );
        }
    }

    #[test]
    fn a_config_cannot_override_what_hb_sets_for_tls() {
        for name in ["NODE_USE_SYSTEM_CA", "NODE_EXTRA_CA_CERTS"] {
            let mut case = Case::new();
            case.trust = true;
            case.env = merged(&[], &[(name, "0")]);
            assert!(
                matches!(assert_err!(case.build()), EnvBuildError::Reserved { .. }),
                "{name}"
            );
        }
    }

    #[test]
    fn the_ctl_socket_variable_is_set_from_the_run_and_nothing_else_can_set_it() {
        let mut case = Case::new();
        assert!(case.ok().get("HB_CTL_SOCKET").is_none());
        case.ctl_socket = Some(cp("/private/var/folders/x/T/hb-1-2-3/ctl.sock"));
        assert_eq!(
            get(&case.ok(), "HB_CTL_SOCKET"),
            Some(OsStr::new("/private/var/folders/x/T/hb-1-2-3/ctl.sock"))
        );
        // The HB_ prefix is reserved, so neither `pass` nor `set` can put the name in.
        assert!(EnvName::parse_user("HB_CTL_SOCKET").is_err());
    }

    #[test]
    fn reserved_names_are_refused_again_whatever_resolve_did() {
        for reserved in [
            "HOME",
            "PATH",
            "TERM",
            "TMPDIR",
            "HTTPS_PROXY",
            "DYLD_X",
            "HB_Y",
        ] {
            let mut case = Case::new();
            case.env = merged(&[reserved], &[]);
            assert!(
                matches!(assert_err!(case.build()), EnvBuildError::Reserved { .. }),
                "pass {reserved}"
            );
            let mut case = Case::new();
            case.env = merged(&[], &[(reserved, "x")]);
            assert!(
                matches!(assert_err!(case.build()), EnvBuildError::Reserved { .. }),
                "set {reserved}"
            );
        }
    }

    #[test]
    fn building_twice_gives_the_same_environment_and_debug_hides_values() {
        let mut case = Case::new();
        case.parent = parent(&[("LANG", "secret-looking-value")]);
        case.env = merged(&["LANG"], &[("API_KEY", "hunter2")]);
        assert_eq!(case.ok(), case.ok());
        let shown = format!("{:?}", case.ok());
        assert!(
            shown.contains("API_KEY") && shown.contains("LANG"),
            "{shown}"
        );
        assert!(
            !shown.contains("hunter2") && !shown.contains("secret-looking"),
            "{shown}"
        );
    }

    #[test]
    fn the_byte_size_counts_names_values_separators_and_pointers() {
        let env = Case::new().ok();
        let expected: usize = env
            .iter()
            .map(|(k, v)| k.len() + 1 + v.len() + 1 + 8)
            .sum::<usize>();
        assert_eq!(env.exec_bytes(), expected);
        assert!(expected > 0);
    }
}
