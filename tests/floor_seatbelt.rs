// ABOUTME: Runs the built floor under real `sandbox-exec` to prove each rule blocks the attack it exists for.
// ABOUTME: Uses a test-only profile builder with the design's rule order (floor last); hb-ghd.2.1 replaces it with `render()`.
//! The floor, enforced by the real Seatbelt.
//!
//! These are the attacks the floor's design rests on: renaming `.git` and planting a `gitdir:`
//! pointer, swapping a symlinked rc file, replacing a protected file by rename, connecting to a
//! container socket the file rules do not cover, and `stat` on a denied path.

#![cfg(target_os = "macos")]

use std::fs;
use std::os::unix::fs::symlink;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use claims::{assert_ok, assert_some};
use hamster_ball::policy::{
    CanonicalPath, Extent, Floor, FloorEffect, FloorRule, GlobSegment, HomeDir, ProjectRoot,
};
use hamster_ball::system::{FloorEnvironment, FloorInputs, build_floor};
use pretty_assertions::assert_eq;
use tempfile::TempDir;

// ----- a throwaway home and project -----

struct World {
    _dir: TempDir,
    base: PathBuf,
    home: HomeDir,
    root: ProjectRoot,
}

impl World {
    fn new() -> Self {
        let dir = assert_ok!(TempDir::new());
        let base = assert_ok!(fs::canonicalize(dir.path()));
        let home_path = base.join("home");
        let project = home_path.join("work/proj");
        assert_ok!(fs::create_dir_all(&project));
        let home = HomeDir::new(canonical(&home_path));
        let root = assert_ok!(ProjectRoot::new(canonical(&project), &home));
        Self {
            _dir: dir,
            base,
            home,
            root,
        }
    }

    fn home_dir(&self) -> PathBuf {
        PathBuf::from(self.home.path().as_str())
    }

    fn proj(&self) -> PathBuf {
        PathBuf::from(self.root.path().as_str())
    }

    fn floor(&self, grants: &[&Path], approval: &[&Path], env: &FloorEnvironment) -> Floor {
        let grants: Vec<CanonicalPath> = grants.iter().map(|p| canonical(p)).collect();
        let approval: Vec<CanonicalPath> = approval.iter().map(|p| canonical(p)).collect();
        let built = assert_ok!(build_floor(&FloorInputs::new(
            &self.home, &self.root, env, &approval, &grants,
        )));
        built.floor
    }
}

fn canonical(path: &Path) -> CanonicalPath {
    assert_ok!(CanonicalPath::from_canonical(assert_ok!(fs::canonicalize(
        path
    ))))
}

fn write(path: &Path, text: &str) {
    if let Some(parent) = path.parent() {
        assert_ok!(fs::create_dir_all(parent));
    }
    assert_ok!(fs::write(path, text));
}

// ----- the test-only profile builder -----

struct Profile {
    text: String,
    params: Vec<(String, String)>,
}

impl Profile {
    fn param(&mut self, value: &str) -> String {
        let name = format!("P{}", self.params.len());
        self.params.push((name.clone(), value.to_owned()));
        name
    }
}

/// Everything writable under `grants`, with the floor emitted last.
fn profile(floor: &Floor, grants: &[&Path]) -> Profile {
    profile_with(floor, grants, true)
}

/// Like [`profile`], optionally leaving out the unlink pins (the control for the pin tests).
fn profile_with(floor: &Floor, grants: &[&Path], pins: bool) -> Profile {
    let mut p = Profile {
        text: String::from(
            "(version 1)(allow default)(deny file-write*)(allow file-write* (literal \"/dev/null\"))",
        ),
        params: Vec::new(),
    };
    for grant in grants {
        let n = p.param(&grant.to_string_lossy());
        p.text
            .push_str(&format!("(allow file-write* (subpath (param \"{n}\")))"));
    }
    for rule in floor.rules() {
        let matchers = matchers(&mut p, rule);
        let joined = matchers.join(" ");
        let line = match rule.effect {
            FloorEffect::DenyReadWrite => format!("(deny file-read* file-write* {joined})"),
            FloorEffect::DenyWrite => format!("(deny file-write* {joined})"),
            FloorEffect::DenyConnect => {
                format!("(deny network-outbound (remote unix-socket {joined}))")
            }
            FloorEffect::PinUnlink if pins => format!("(deny file-write-unlink {joined})"),
            _ => continue,
        };
        p.text.push_str(&line);
    }
    p
}

fn matchers(p: &mut Profile, rule: &FloorRule) -> Vec<String> {
    let mut out = Vec::new();
    let paths = std::iter::once(&rule.pattern.base).chain(rule.pattern.alias.as_ref());
    for (position, path) in paths.enumerate() {
        let n = p.param(path.as_str());
        let is_alias = position == 1;
        out.push(match (&rule.pattern.tail, rule.extent) {
            (Some(tail), _) => {
                let mut re = String::new();
                for segment in tail.segments() {
                    match segment {
                        GlobSegment::AnyDepth => re.push_str("(/[^/]+)*"),
                        GlobSegment::Segment(text) => {
                            re.push('/');
                            for c in text.chars() {
                                match c {
                                    '*' => re.push_str("[^/]*"),
                                    '?' => re.push_str("[^/]"),
                                    '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$'
                                    | '|' | '\\' => {
                                        re.push('\\');
                                        re.push(c);
                                    }
                                    c => re.push(c),
                                }
                            }
                        }
                    }
                }
                format!(
                    "(regex (string-append \"^\" (regex-quote (param \"{n}\")) \"{}(/.*)?$\"))",
                    re.replace('\\', "\\\\")
                )
            }
            (None, Extent::Subtree) if is_alias => format!("(literal (param \"{n}\"))"),
            (None, Extent::Subtree) => format!("(subpath (param \"{n}\"))"),
            (None, Extent::Node) => format!("(literal (param \"{n}\"))"),
            // Under `/` the base already ends in a slash, so the separator is not repeated.
            (None, Extent::Children) if path.as_str() == "/" => "(regex #\"^/[^/]+$\")".to_owned(),
            (None, Extent::Children) => {
                format!("(regex (string-append \"^\" (regex-quote (param \"{n}\")) \"/[^/]+$\"))")
            }
        });
    }
    out
}

fn sandboxed(profile: &Profile, script: &str) -> Output {
    let mut cmd = Command::new("/usr/bin/sandbox-exec");
    cmd.arg("-p").arg(&profile.text);
    for (name, value) in &profile.params {
        cmd.arg("-D").arg(format!("{name}={value}"));
    }
    cmd.args(["--", "/bin/sh", "-c", script]);
    assert_ok!(cmd.output())
}

fn succeeds(profile: &Profile, script: &str) -> bool {
    sandboxed(profile, script).status.success()
}

fn blocked(profile: &Profile, script: &str) -> bool {
    !succeeds(profile, script)
}

fn sh_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

fn env() -> FloorEnvironment {
    FloorEnvironment::new().with_path_var("/usr/bin:/bin")
}

// ====================================================================================
// .git
// ====================================================================================

#[test]
fn git_hooks_and_config_cannot_be_written_but_the_rest_of_the_project_can() {
    let w = World::new();
    let proj = w.proj();
    write(&proj.join(".git/hooks/.keep"), "");
    write(&proj.join(".git/config"), "[core]\n");
    write(&proj.join("src/main.rs"), "");
    write(&proj.join("hamster-ball.toml"), "");
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile(&floor, &[&proj]);

    assert!(succeeds(
        &p,
        &format!("echo x > {}", sh_quote(&proj.join("src/main.rs")))
    ));
    for target in [
        ".git/hooks/pre-commit",
        ".git/config",
        "hamster-ball.toml",
        ".git/modules/m/hooks/post-merge",
    ] {
        let script = format!(
            "mkdir -p \"$(dirname {t})\" 2>/dev/null; echo x > {t}",
            t = sh_quote(&proj.join(target))
        );
        assert!(blocked(&p, &script), "{target}");
    }
    assert!(!proj.join(".git/hooks/pre-commit").exists());
}

#[test]
fn renaming_git_aside_and_planting_a_pointer_is_blocked() {
    let w = World::new();
    let proj = w.proj();
    write(&proj.join(".git/hooks/.keep"), "");
    write(&proj.join(".git/config"), "");
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile(&floor, &[&proj]);
    let script = format!(
        "mv {git} {old} && mkdir -p {old}/hooks && echo 'echo pwned' > {old}/hooks/pre-commit && echo 'gitdir: {old}' > {git}",
        git = sh_quote(&proj.join(".git")),
        old = sh_quote(&proj.join(".git-old")),
    );
    assert!(blocked(&p, &script));
    assert!(
        proj.join(".git/hooks").is_dir(),
        ".git must still be the original directory"
    );
    assert!(!proj.join(".git-old").exists());
}

#[test]
fn without_the_pin_the_same_attack_succeeds() {
    // The control: proves the test above is sensitive to the pin and not to something else.
    let w = World::new();
    let proj = w.proj();
    write(&proj.join(".git/hooks/.keep"), "");
    write(&proj.join(".git/config"), "");
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile_with(&floor, &[&proj], false);
    let script = format!(
        "mv {} {}",
        sh_quote(&proj.join(".git")),
        sh_quote(&proj.join(".git-old"))
    );
    assert!(succeeds(&p, &script));
}

#[test]
fn creating_a_git_pointer_where_git_is_missing_is_blocked() {
    let w = World::new();
    let proj = w.proj();
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile(&floor, &[&proj]);
    let script = format!(
        "echo 'gitdir: /tmp/evil' > {}",
        sh_quote(&proj.join(".git"))
    );
    assert!(blocked(&p, &script));
    assert!(!proj.join(".git").exists());
}

#[test]
fn replacing_git_config_by_rename_is_blocked_but_the_lock_file_is_allowed() {
    let w = World::new();
    let proj = w.proj();
    write(&proj.join(".git/config"), "[core]\n");
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile(&floor, &[&proj]);
    let script = format!(
        "echo evil > {lock} && mv {lock} {config}",
        lock = sh_quote(&proj.join(".git/config.lock")),
        config = sh_quote(&proj.join(".git/config")),
    );
    assert!(blocked(&p, &script));
    assert_eq!(
        assert_ok!(fs::read_to_string(proj.join(".git/config"))),
        "[core]\n"
    );
}

#[test]
fn a_worktree_style_git_file_cannot_be_rewritten_and_its_hooks_stay_protected() {
    let w = World::new();
    let proj = w.proj();
    let main = w.base.join("main/.git/worktrees/wt");
    write(&main.join("commondir"), "../..\n");
    write(&w.base.join("main/.git/hooks/.keep"), "");
    write(&proj.join(".git"), &format!("gitdir: {}\n", main.display()));
    let main_git = w.base.join("main/.git");
    let floor = w.floor(&[&proj, &main_git], &[], &env());
    let p = profile(&floor, &[&proj, &main_git]);
    assert!(blocked(
        &p,
        &format!(
            "echo 'gitdir: /elsewhere' > {}",
            sh_quote(&proj.join(".git"))
        )
    ));
    assert!(blocked(
        &p,
        &format!(
            "echo x > {}",
            sh_quote(&w.base.join("main/.git/hooks/pre-commit"))
        )
    ));
    assert!(blocked(
        &p,
        &format!("echo x > {}", sh_quote(&main.join("config.worktree")))
    ));
}

#[test]
fn normal_git_work_still_succeeds_under_the_floor() {
    let w = World::new();
    let proj = w.proj();
    let git = |args: &[&str]| {
        let out = assert_ok!(
            Command::new("/usr/bin/git")
                .current_dir(&proj)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_SYSTEM", "/dev/null")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
                .args(args)
                .output()
        );
        assert!(out.status.success(), "{args:?}: {out:?}");
    };
    git(&["init", "-q"]);
    write(&proj.join("a.txt"), "1");
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile(&floor, &[&proj]);
    let script = format!(
        "cd {proj} && export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null && \
         /usr/bin/git -c user.name=t -c user.email=t@example.com add -A && \
         /usr/bin/git -c user.name=t -c user.email=t@example.com commit -q -m one && \
         echo 2 > a.txt && \
         /usr/bin/git -c user.name=t -c user.email=t@example.com commit -q -am two && \
         /usr/bin/git branch feature && /usr/bin/git tag v1 && /usr/bin/git reset -q --hard HEAD~1",
        proj = sh_quote(&proj)
    );
    let out = sandboxed(&p, &script);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn commondir_cannot_be_written_to_redirect_git_to_another_hooks_directory() {
    let w = World::new();
    let proj = w.proj();
    write(&proj.join(".git/hooks/.keep"), "");
    write(&proj.join(".git/config"), "");
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile(&floor, &[&proj]);
    for target in [".git/commondir", ".git/modules/m/commondir"] {
        let script = format!(
            "mkdir -p \"$(dirname {t})\" 2>/dev/null; echo ../../evil > {t}",
            t = sh_quote(&proj.join(target))
        );
        assert!(blocked(&p, &script), "{target}");
    }
    assert!(!proj.join(".git/commondir").exists());
}

// ====================================================================================
// Approval files
// ====================================================================================

#[test]
fn an_in_project_closure_file_cannot_be_replaced_even_by_renaming_its_directory() {
    let w = World::new();
    let proj = w.proj();
    write(&proj.join("hamster-ball.toml"), "");
    write(&proj.join("presets/x.toml"), "");
    let preset = proj.join("presets/x.toml");
    let floor = w.floor(&[&proj], &[&preset], &env());
    let p = profile(&floor, &[&proj]);
    assert!(blocked(&p, &format!("echo evil > {}", sh_quote(&preset))));
    let script = format!(
        "mv {presets} {old} && ln -s {evil} {presets}",
        presets = sh_quote(&proj.join("presets")),
        old = sh_quote(&proj.join("presets-old")),
        evil = sh_quote(&proj.join("elsewhere")),
    );
    assert!(blocked(&p, &script));
    assert!(proj.join("presets/x.toml").is_file());
}

#[test]
fn the_project_directory_itself_cannot_be_renamed() {
    let w = World::new();
    let proj = w.proj();
    write(&proj.join("hamster-ball.toml"), "");
    let parent = assert_some!(proj.parent()).to_path_buf();
    // An ancestor grant would otherwise let the project be moved and recreated.
    let floor = w.floor(&[&parent], &[], &env());
    let p = profile(&floor, &[&parent]);
    let script = format!("mv {} {}", sh_quote(&proj), sh_quote(&parent.join("proj2")));
    assert!(blocked(&p, &script));
    assert!(proj.is_dir());
}

#[test]
fn a_hard_link_made_inside_the_sandbox_to_a_protected_file_is_blocked() {
    let w = World::new();
    let proj = w.proj();
    write(&proj.join("hamster-ball.toml"), "");
    let floor = w.floor(&[&proj], &[], &env());
    let p = profile(&floor, &[&proj]);
    let script = format!(
        "ln {} {}",
        sh_quote(&proj.join("hamster-ball.toml")),
        sh_quote(&proj.join("alias.toml"))
    );
    assert!(blocked(&p, &script));
}

// ====================================================================================
// Symlinked floor paths
// ====================================================================================

#[test]
fn a_symlinked_rc_file_is_protected_at_the_link_and_at_its_target() {
    let w = World::new();
    let home = w.home_dir();
    write(&home.join("dotfiles/zshrc"), "original\n");
    assert_ok!(symlink(home.join("dotfiles/zshrc"), home.join(".zshrc")));
    // The agent was (wrongly) granted the whole home directory.
    let floor = w.floor(&[&home], &[], &env());
    let p = profile(&floor, &[&home]);
    assert!(blocked(
        &p,
        &format!("echo evil >> {}", sh_quote(&home.join("dotfiles/zshrc")))
    ));
    assert!(blocked(
        &p,
        &format!("echo evil >> {}", sh_quote(&home.join(".zshrc")))
    ));
    let swap = format!(
        "rm {rc} && echo evil > {rc}",
        rc = sh_quote(&home.join(".zshrc"))
    );
    assert!(blocked(&p, &swap));
    assert_eq!(
        assert_ok!(fs::read_to_string(home.join("dotfiles/zshrc"))),
        "original\n"
    );
    assert!(assert_ok!(fs::symlink_metadata(home.join(".zshrc"))).is_symlink());
}

#[test]
fn a_version_link_that_decides_which_program_a_path_entry_runs_cannot_be_re_pointed() {
    let w = World::new();
    let home = w.home_dir();
    let agent = home.join(".tool");
    write(&agent.join("versions/1.2/bin/tool"), "good");
    assert_ok!(symlink("versions/1.2", agent.join("current")));
    let bin = w.base.join("bin");
    assert_ok!(fs::create_dir_all(&bin));
    assert_ok!(symlink(agent.join("current/bin/tool"), bin.join("tool")));
    let env = FloorEnvironment::new().with_path_var(bin.as_os_str());
    let floor = w.floor(&[&agent], &[], &env);
    let p = profile(&floor, &[&agent]);
    let swap = format!(
        "mkdir -p {evil}/bin && echo bad > {evil}/bin/tool && rm {cur} && ln -s {evil} {cur}",
        evil = sh_quote(&agent.join("versions/evil")),
        cur = sh_quote(&agent.join("current")),
    );
    assert!(blocked(&p, &swap));
    assert_eq!(
        assert_ok!(fs::read_link(agent.join("current"))),
        PathBuf::from("versions/1.2")
    );
    // Ordinary work next to the link is untouched.
    assert!(succeeds(
        &p,
        &format!("echo n > {}", sh_quote(&agent.join("notes.txt")))
    ));
}

#[test]
fn a_missing_rc_file_cannot_be_created() {
    let w = World::new();
    let home = w.home_dir();
    let floor = w.floor(&[&home], &[], &env());
    let p = profile(&floor, &[&home]);
    for name in [".zlogin", ".ZLOGIN", ".bash_profile"] {
        assert!(
            blocked(&p, &format!("echo x > {}", sh_quote(&home.join(name)))),
            "{name}"
        );
    }
}

// ====================================================================================
// Credentials and metadata
// ====================================================================================

#[test]
fn a_granted_ancestor_cannot_reach_credentials_beneath_it_and_stat_does_not_leak() {
    let w = World::new();
    let home = w.home_dir();
    write(&home.join(".ssh/id_ed25519"), "secret");
    write(&home.join(".config/other/ok"), "fine");
    let floor = w.floor(&[&home], &[], &env());
    let p = profile(&floor, &[&home]);
    assert!(blocked(
        &p,
        &format!("cat {}", sh_quote(&home.join(".ssh/id_ed25519")))
    ));
    assert!(blocked(
        &p,
        &format!("echo x > {}", sh_quote(&home.join(".ssh/new")))
    ));
    // `file-read*` hides existence and size too, not only contents.
    assert!(blocked(
        &p,
        &format!("/usr/bin/stat {}", sh_quote(&home.join(".ssh/id_ed25519")))
    ));
    assert!(succeeds(
        &p,
        &format!("cat {}", sh_quote(&home.join(".config/other/ok")))
    ));
}

#[test]
fn history_files_in_home_are_unreadable_but_home_is_not() {
    let w = World::new();
    let home = w.home_dir();
    write(&home.join(".zsh_history"), "export TOKEN=x\n");
    write(&home.join("notes.txt"), "fine");
    let floor = w.floor(&[&home], &[], &env());
    let p = profile(&floor, &[&home]);
    assert!(blocked(
        &p,
        &format!("cat {}", sh_quote(&home.join(".zsh_history")))
    ));
    assert!(succeeds(
        &p,
        &format!("cat {}", sh_quote(&home.join("notes.txt")))
    ));
}

// ====================================================================================
// Sockets: a file deny does not stop connect()
// ====================================================================================

#[test]
fn a_file_deny_alone_does_not_stop_connecting_but_the_connect_rule_does() {
    let w = World::new();
    let temp = w.base.join("tmp");
    let socket_dir = temp.join("podman");
    assert_ok!(fs::create_dir_all(&socket_dir));
    let socket = socket_dir.join("api.sock");
    let _listener = assert_ok!(UnixListener::bind(&socket));
    let connect = format!("/usr/bin/nc -U -w 1 {} < /dev/null", sh_quote(&socket));

    let env = FloorEnvironment::new()
        .with_path_var("/usr/bin:/bin")
        .with_user_temp_dir(&temp);
    let floor = w.floor(&[], &[], &env);

    // The control: file rules only, as design section 6 first had it.
    let file_rules_only = Profile {
        text: "(version 1)(allow default)(deny file-read* file-write* (subpath (param \"S\")))"
            .to_owned(),
        params: vec![("S".to_owned(), socket_dir.to_string_lossy().into_owned())],
    };
    assert!(
        succeeds(&file_rules_only, &connect),
        "a file deny must not stop connect()"
    );

    let p = profile(&floor, &[]);
    assert!(blocked(&p, &connect), "the DenyConnect rule must");
}
