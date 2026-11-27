<!-- ABOUTME: Design for `hb`, a macOS command that runs AI coding agents in a Seatbelt hamster ball defined by layered TOML config. -->
<!-- ABOUTME: Covers threat model, config model, enforcement, agent presets, containers, build plan. Status: implemented (milestones 1 to 8). -->

# Hamster Ball Design

Project: **hamster-ball** (`github.com/dmrolfs/hamster-ball`, public). Binary: `hb`.
Status: **implemented**, milestones 1 to 8 (version 0.1). Sections written as plans before the code existed were updated to say what was built; a statement marked Measured
was run on a real machine, and a statement marked Unverified was not.
Platform: **macOS only** (tested on macOS 15.7, arm64).
Language: **Rust**, shipped as one binary named `hb`.

Every "Measured" statement below comes from a throwaway spike run on this machine.
The scripts and raw notes are in `history/spike/` and `history/Spike-Findings.md`
(not committed). Items marked **Unverified** have not been tested and must become tests.

## 1. Purpose and scope

Run an AI coding agent against a project with the least access that still lets it work,
using one command and one small config file per project.

Goals:

- One command for all agents (kiro-cli, pi, claude, opencode; codex and omp later).
- Per-project `hamster-ball.toml` that extends shared presets and a user-level base.
- A base policy that no project can loosen. Deny always wins.
- Filesystem and network isolation together, with a domain allowlist for network.
- Secrets stay out of the hamster ball by default.

Non-goals:

- Linux or Windows support.
- Defense against a deliberately hostile agent with a kernel exploit. A VM is the right tool for that.
- Letting agents build images or run containers (see section 9).
- Replacing another supervisor tool that keeps its own sandbox code.

## 2. Threat model

In scope (owner decision):

1. **Agent mistakes**: deleting or overwriting the wrong thing, installing into the wrong place.
2. **Prompt injection and malicious dependencies**: instructions or code in a file, web page,
   MCP result or package that make the agent read secrets and send them out, or plant code that
   your shell outside the hamster ball runs later.

Out of scope: a hostile agent that exploits macOS itself.

Attack paths the design must close, each backed by a measurement or a decision:

| Path | Control |
|---|---|
| Read credentials (`~/.ssh`, `~/.aws`, keychains, browser data) | Deny-default reads plus a compiled-in floor |
| Plant code your shell runs later (`~/.cargo/bin`, `~/.local/bin`, shell rc files, `.git/hooks`) | Write-deny floor |
| Send data out | Seatbelt allows one proxy port only; proxy enforces a domain allowlist |
| DNS exfiltration | No resolver access in the hamster ball; the proxy resolves names. Measured: direct DNS fails inside |
| Read secrets in the project (`.env`, `*.secrets.yaml`) | Secrets guard (section 8) |
| Tokens in the environment | Environment starts empty; only named variables pass |
| Start, unload or disable your launch agents (`launchctl`) | `system.launchctl` is off unless your own config turns it on (section 4.6); the profile denies exec of `/bin/launchctl` |
| Edit its own hamster ball config | `hamster-ball.toml` is write-denied inside the hamster ball; approval by hash (section 5) |
| Escape through podman | Floor denies podman paths; `hb ctl` is the only container channel (section 9) |

## 3. Usage

```sh
cd ~/work/myproj
hb run -- kiro-cli chat   # run any command in the hamster ball (`--` is optional)
hb run -- cargo test
hb explain                # effective policy, with the source file of every rule
hb approve                # review and approve this project's hamster-ball.toml (needs a terminal)
hb approve --revoke       # take the approval back (no terminal needed)
hb doctor                 # unprotected secret-looking files, tracked files the guard would deny, secret-looking launchd variables,
                          # git hooks the floor does not cover, system proxy settings, MCP servers that cannot start offline
hb warm                   # fill hb's offline cache for declared uvx and npx MCP servers (the only step that may reach registries)
hb profile                # print the generated Seatbelt profile
hb ctl ps|logs|stats|start|stop|restart [name]   # inside the hamster ball: see and restart the listed containers
hb ctl launchd status|kickstart|restart <label>  # inside: the launchd jobs listed in [ctl] launchd
```

Install: `cargo install --path .`. `hb` must live in a directory the hamster ball cannot write
(the floor write-denies every PATH directory).

A project contains only TOML. No Rust or scripts are added to projects.

`hb <command>` is not a shorthand for `hb run -- <command>` (D82): a typo of a subcommand would run a program of that name, and
each new subcommand would change what `hb <word>` means. An alias (`alias hbr='hb run --'`) gives the short form.

**The project is not granted by itself (D82).** `write = ["."]` gives the project, and it comes from a file: normally the base, so
`hb init` writes it, but a preset or the project file can say it. With no read or write grant over the project directory the agent
cannot read it, and `hb explain` (warning `project_not_granted`) and `hb run` (before the command starts) say what to add. A grant
inside the project does not count. An implicit grant was rejected: it could not be removed (a read-only review of a project would
be impossible, since nothing narrows a grant), and the approval summary, `explain`, the guard roots and the pins would each need to
know a rule that no file states.

## 4. Config model

### 4.1 Layers and files

From lowest to highest precedence:

1. **Floor**: compiled into `hb`. Cannot be changed by any file (section 6).
2. **User base**: `~/.config/hamster-ball/base.toml`. Always applied. Not opt-in, so a project cannot skip it.
3. **Presets**: named in `extends`. Built-in (`agent/kiro`, `agent/pi`, `agent/claude`, `agent/opencode`;
   the language presets `rust`, `node`, `python` and `git` are planned and not built), user presets in `~/.config/hamster-ball/presets/<name>.toml`,
   or a path to a TOML file. Presets may extend other presets.
4. **Project**: `hamster-ball.toml` in the project root.

`hb` finds the project root by walking up from the current directory to the first `hamster-ball.toml`.
The walk uses `symlink_metadata` on each candidate: not found keeps walking; a permission error, or a
symlink, directory or other non-regular file named `hamster-ball.toml`, is fatal, so a parent project's
config never applies silently.

- If no `hamster-ball.toml` exists up to `/`, `hb` stops with a `NoProjectConfig` error. It never falls back to
  the current directory (the old `sb` did, which made that directory writable with no approval).
- `hb` refuses a current directory or a discovered root that is "too broad": `/`, `$HOME`, an ancestor of `$HOME`,
  or any path with fewer than two components below `/` (`/Users`, `/private`, `/Volumes`). The same check applies
  to every `fs.read` and `fs.write` grant in every layer (a `write = ["~"]` would otherwise make your whole home
  writable). Comparison is by path component, so `/Users/me2` is not confused with `/Users/me`.
  (The old `sb` only checked `PWD == $HOME`; `sandbox.py` checks containment.)
- The discovered `hamster-ball.toml` and its directory must belong to the real uid and must not be
  world-writable, so a file planted in a shared directory such as `/tmp` (`/private/tmp` has only two
  components and passes the breadth rule) cannot become a project root. Group write is allowed:
  every macOS user shares the `staff` group and some keep project trees group-writable on purpose.
  The approval hash (section 5) controls what the file says; this check is about who could have put it there.
- The home directory comes from the passwd database, not `$HOME`, and is compared with a canonicalized `$HOME`.
  A mismatch is a `HomeError::Mismatch` error, because the floor is built from home and `HOME=/tmp/x hb ...` would
  otherwise relocate every floor path. An unset `$HOME` is fine. `hb` also refuses to run as root.
  Verified on this machine: a normal shell, a launchd job, `env -i`, a trailing-slash `HOME` and a poisoned
  `HOME` all give the expected result. Not tested: `sudo -E` (reasoned: root's passwd home is `/var/root`,
  hence the root refusal) and nix `--pure` shells.

### 4.2 Merge rules

- Lists (allow, deny, hosts, ports, env names) are **unioned**; equal values collapse into one entry that keeps
  every place it was declared. The result does not depend on the order files are merged in.
- Maps (`env.set`, `mcp`) merge by key; a duplicate key is an error unless the values are equal. The error names
  both files and never prints the values (an environment value can be a secret).
- `deny` rules from every layer apply, and **deny wins** over any allow. A read-deny (`fs.deny_read`) also denies
  write, delete and rename; a write-deny denies only those (D34).
- There is no syntax to remove or narrow an entry that a lower layer added. A project can only add.
- Scalars (few exist) never loosen: `tls.system_trust`, `terminal.clipboard_write` and `system.launchctl` take `false` if any file says `false` (D35, D67, D70), and
  `ctl.label` must be the same in every file that sets it, because a project label would otherwise replace the base's
  scope (D33). The earlier "otherwise the highest layer" fallback is removed.
- Sections that run code on the host or switch protections off (`hooks`, `guard.exceptions`, `net.internal_hosts` in any form, and `system.launchctl = true`; a `false` is accepted anywhere) are accepted **only**
  from files that physically are the user's own: the base, files under `~/.config/hamster-ball` (with no other hard
  link), and built-in presets (D36). The rule is by where the file really is (its canonical path), not by how it was
  reached, so a path alias of a user preset behaves exactly like the name, and a symlinked or hard-linked user file
  loses the right. A project file, any file inside the project, and any other file (including one the project
  names by absolute path) that defines them is an error naming that file. The error never prints the hook.
- Even a trusted file's hooks are chosen by the project when it extends that preset. The approval summary (hb-ghd.4) lists every
  hook that will run, with the files that define it (`hb approve` and `hb explain` show the origin of each).
- `hb explain` prints each effective rule with its origin file, so every grant can be audited.

### 4.2a Extends and the closure

- An `extends` entry is a **path** if it starts with `/`, `~/`, `./` or `../`; otherwise it is a preset **name**
  (`[a-z0-9][a-z0-9_-]*` segments joined by `/`, at most 64 bytes, no `.`, so `foo.toml` is an error that suggests
  `./foo.toml`). `~` alone and `~user/...` are errors.
- A relative path resolves against the directory of the file that contains the `extends` (D37). Decision D22 is
  about filesystem grants only.
- A name is looked up among the built-in presets and `~/.config/hamster-ball/presets/<name>.toml`. A name in both is
  an error naming both (D38). A built-in may extend only other built-ins. A missing preset is always an error,
  never a skip, because a skipped preset could silently drop its denies.
- The closure is loaded depth first, dependencies before the files that extend them, the base chain before the
  project chain, so the project is last. Files are identified by device and inode, so a hard link, a symlinked
  directory or a case variant is the same file, and a cycle through an alias is still a cycle. Limits: 16 files,
  nesting depth 8, 32 `extends` entries per file.
- Each file is read once. The same bytes are parsed and returned to M4 for hashing; M4 hashes the files whose
  location is inside the project or elsewhere (anything the ball could write), in closure order.
- Every closure file must belong to you and not be world-writable (D31), starting with the base.
- A missing `~/.config/hamster-ball/base.toml` is an error that says to run `hb init`, which writes a commented
  template with mode 0600 and never overwrites (D39). `XDG_CONFIG_HOME` is ignored (D39). The template lists `[system] launchctl = false`, commented out, so the one switch only your own files can turn on is easy to find (4.6).

### 4.3 Schema

```toml
# ~/work/myapp/hamster-ball.toml
extends = ["agent/kiro", "agent/pi"]                 # plus your own presets; "rust", "node", "python" and "git" are planned

[fs]
read       = ["~/work/shared-fixtures"]        # extra read-only paths
write      = ["."]                              # relative to the project root; "." is the project (see below)
deny_read  = ["config/*.secrets.yaml"]          # project-specific secrets (section 8)

[net]
allow          = ["crates.io", "static.crates.io", "registry.corp.example.com:8443"]   # exact or "*.suffix", optional :port (default 443)
internal_hosts = ["github.com", "*.in.example.com"]                                    # only your own files; may resolve to private addresses (12.1)
loopback_ports = [3030, 3031, 3032, 5432, 9001, 9002]                                  # services you started yourself

[env]
pass  = ["LANG", "COLORTERM"]                   # names copied from your shell (not HOME, PATH, TMPDIR, TERM, proxy or TLS names, HB_*, DYLD_*, LD_*)
set   = { RUST_BACKTRACE = "1" }                # a value may say {session_dir}: this run's private directory (also TMPDIR)
tools = ["node", "git"]                         # programs found on your PATH when hb starts; see 7.2

[tls]
system_trust = true                             # base default; see 4.5
extra_ca_files = []

[terminal]
clipboard_write = true                          # false: remove the agent's OSC 52 clipboard writes; see 7.3

[system]
launchctl = false                               # default off; only your own files may say true; see 4.6

[ctl]                                           # section 9
label      = "com.docker.compose.project=myapp"
containers = []
launchd    = []                                 # launchd job labels `hb ctl launchd` may start and restart; your own files only

[mcp.serena]                                    # section 10
command = "uvx"
args    = ["--from", "git+https://github.com/oraios/serena", "serena", "start-mcp-server"]
net     = []                                    # hosts needed at run time (host or host:port); they join net.allow. A remote server has no command: [mcp.context7] net = ["mcp.context7.com"]
warm_net = []                                   # hosts `hb warm` may reach for this server (registries are built in); never allowed at run time
bind_ports = []                                 # ports it may listen on, 1024-65535, at most 16 (profile-wide, at most 64 distinct in all; see 7.1 step 5)
```

### 4.4 Path handling

- `~` and relative paths are expanded, then **canonicalized with `realpath`** before use.
  Measured: Seatbelt matches resolved paths. `/tmp` is a symlink to `/private/tmp`, and a rule on
  `/tmp/...` made `uv_cwd` fail with `EPERM`.
- `~` and `~/...` only (no `~user`); no `$VARIABLE` expansion. **Relative filesystem paths resolve against the
  project root in every layer**, so `write = ["."]` in a preset or the base means the project. (`extends` paths are
  different: see 4.2a.)
- An allow rule whose path does not exist is skipped with a recorded reason (`Missing` or `Dangling`) shown by
  `hb explain` (the safe direction). A permission error on an allow rule is an error, not a skip.
- A deny rule whose path does not exist is still emitted: the deepest resolvable ancestor, canonicalized, plus the
  missing tail. `..` in the missing tail is an error. A dangling symlink or a non-directory ancestor is an error.
  A deny on an existing symlink emits both the target and the link name.
- **Case and Unicode spelling of a missing tail is not a hole.** Measured on this APFS volume: Seatbelt `literal`,
  `subpath` and `regex` rules match case-insensitively and NFC/NFD-insensitively (a deny on a missing `ID_RSA`
  blocks creating `id_rsa`; verified again on 2026-11-18). Do not emit case-folding regexes. Never use a Rust
  string comparison on an unresolved tail for a security decision; only compare fully canonical paths.
- `fs.deny_read` and `fs.deny_write` entries may be globs (`config/*.secrets.yaml`). They are represented as a
  `PathPattern`: the longest non-glob prefix is resolved with deny semantics, and the tail may use only `*`, `?` and
  `**` (no `[`, `{`, `..` or absolute segments).
- Config input is untrusted: each file is read once (symlinks refused except for user-level files, regular file
  only, no blocking), capped at 256 KiB and 4096 entries per list, validated as UTF-8, and the exact bytes are kept
  for approval hashing (section 5).
- Paths reach the profile through Seatbelt `-D` parameters (`(param "R3")`), never by string
  interpolation. This is the approach in `sandbox.py`; it avoids the old `sb`'s profile-injection bug
  (an unquoted heredoc put `$HOME` and `$PROJECT` into the profile text). Found in review, not tested here.

### 4.5 TLS

- `tls.system_trust` (base default `true`): allows the Mach lookups `com.apple.SecurityServer`,
  `com.apple.SystemConfiguration.configd` and `com.apple.TrustEvaluationAgent`, read access to the files
  `/Library/Keychains/System.keychain` and `System.keychain-db` (never the directory), and sets `NODE_USE_SYSTEM_CA=1`
  (D62, D68). `trustd` and `trustd.agent` come from `system.sb`.
- `tls.extra_ca_files`: read access to each file, and `NODE_EXTRA_CA_CERTS` set to a per-session bundle. `hb` reads the files
  outside the sandbox, copies only their PEM `CERTIFICATE` blocks (a key or notes in the same file are not copied), joins them in
  the order of the config, and writes `ca-bundle.pem` (mode 0600) in the session directory. A file with no certificate, a file over
  1 MiB or a bundle over 4 MiB stops the run before the agent starts, because Node would only print `Ignoring extra certs` and the
  run would look like "system trust only".
- Only Node's two variables are set. `SSL_CERT_FILE` and its kin are not: in Python and `uv` they replace the public roots (measured,
  below), and curl and git ignore them. A tool that needs a private CA can be given its own variable with `[env] set`.
- The proxy never decrypts traffic. It tunnels bytes.

Measured (Node 24 inside the hamster ball, through the proxy):

| Setting | Host re-signed by the corporate proxy | AWS host | private gateway |
|---|---|---|---|
| none | fail | OK | fail |
| `NODE_USE_SYSTEM_CA=1` | OK | OK | fail |
| `NODE_EXTRA_CA_CERTS` only | fail | OK | OK |
| both | OK | OK | OK |

Reproduced under `hb` with a throwaway CA and a local server (`tests/tls_handshake.rs`, Node 24.11.1 and 26.3.0): no setting and
system trust alone fail with `UNABLE_TO_VERIFY_LEAF_SIGNATURE` (a throwaway CA is not in the system store); the extra CA alone
verifies, and so do both together. The "both" row stands. The first analysis's contrary report is not reproduced a third time.

The measured minimum (D62; `history/hb-ghd.2.1_oracle-tls-ports-keychain.md`, then re-checked by hand for Node 24 and `uv`), macOS 15.7.7 only:

| Element | Needed by | Without it |
|---|---|---|
| `com.apple.SecurityServer` | Node with `NODE_USE_SYSTEM_CA=1` | Node 24 fails every handshake (`SecItemCopyMatching failed -50`) |
| read of `System.keychain` | the same | Node 24 fails (`-25300`) |
| `com.apple.SystemConfiguration.configd` | `uv` and `uvx` (Rust `system-configuration`) | `uv` panics, even with an explicit proxy env |
| `com.apple.trustd`, `trustd.agent` | curl, git, Node, Go, Rust | in `system.sb` already |
| `com.apple.TrustEvaluationAgent` | curl and git (SecureTransport), verifying a host signed by a root in the system store | `(60) unable to get local issuer certificate` (D68) |

Dropped, because no tested client regressed without them: `securityd`, `securityd.xpc` (also the route to the data-protection
keychain), the `/private/var/db/mds` read, the whole `/Library/Keychains` directory (it held `apsd.keychain`, 0644, which no client opens)
and `user-preference-read` for `kCFPreferencesAnyApplication`. Tested clients: curl, git, Node 24/26, Bun, Go, Rust (rustls),
Python, `uv`, claude, pi and opencode (the last three against a local TLS server only; kiro-cli ignores the CA env vars).
Not tested: native-tls, Deno, Electron CLIs, a system proxy or PAC being followed (see below) and
macOS versions other than 15.7. A client that needs a dropped item shows up as a denial under `--log-denials` (hb-ghd.2.3b); the fix
is one more entry in `TLS_SERVICES`. `configd` is kept although it exposes the network configuration store (interface names, SSID text,
DNS addresses, console user): `uv` needs it.

`NODE_USE_SYSTEM_CA=1` together with `NODE_EXTRA_CA_CERTS` failed to verify a local-CA server in the first M2 analysis. It could not
be reproduced: both settings worked on Node 24.11, 26.0 and 26.3 under the minimum, in a clean environment. The earlier run most likely did not load
the extra bundle (an unreadable path prints `Ignoring extra certs` and looks like "system only"). The four-combination handshake test
(hb-ghd.2.2) still decides. The user keychain domain is not visible inside the ball (the floor denies `~/Library/Keychains`), so a corporate root installed only there is missing. The floor, not `securityd`, is what keeps the user keychain out: see section 6 and `tests/seatbelt_tls.rs`.

**A real TLS-inspecting proxy (D68, `tests/tls_inspection.rs`, opt-in).** On a machine where the corporate proxy re-signs `kiro.dev`, `opencode.ai` and
`context7.com` (and not `example.com`), under the generated profile plus a network allow: Node with `NODE_USE_SYSTEM_CA=1`, Bun and
`uv --native-tls` verify the re-signed hosts; Node without system trust fails them with `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` and still
verifies `example.com`, which is the inspector-off case. curl failed on the re-signed hosts until `TrustEvaluationAgent` was granted
(denials logged: `TrustEvaluationAgent`, `kCFPreferencesAnyApplication`, `networkd.plist`; adding each alone: only the first fixed it).
`kCFPreferencesAnyApplication` and `networkd.plist` stay out. The test decides "re-signed" by whether Node's own roots verify the host, so
it names no vendor. claude, driven through `hb` against a local server, fails with `UNABLE_TO_VERIFY_LEAF_SIGNATURE` without an extra CA and
completes the handshake and sends `POST /v1/messages` with one. pi and opencode could not be driven without credentials and a provider
config; they run on Node and Bun, whose rows are measured. kiro-cli ignores the CA variables and needs a login before any TLS call: not exercised.

**Extra CAs reach Node-based clients only (D68).** `NODE_EXTRA_CA_CERTS` adds to Node's roots. The variables other clients read do not
behave alike under the profile, so `hb` sets none of them. Measured: Python's `SSL_CERT_FILE` and `uv`'s (also with `--native-tls`)
replace the roots, so a public host then fails; Node ignores it; the system curl (SecureTransport) ignores `SSL_CERT_FILE`,
`CURL_CA_BUNDLE` and `--cacert`; git's `GIT_SSL_CAINFO` did not break a public host. A tool outside Node that must trust a private CA is
configured by the user with its own variable through `[env] set`, pointing at a file the tool can read. Where the tool's variable replaces
the roots (Python, `uv`), that file must hold the public roots as well. A bundle of
the system roots plus the extra CAs for non-Node clients was considered and not built: it needs a second trust store.

**System proxy and PAC.** Not exercised: `networksetup` needs admin rights and rewrites live network settings, so no test changes them.
What is measured, read-only (`tests/seatbelt_tls.rs`): `scutil --proxy` inside the ball prints the host's proxy settings with
`configd` granted and an empty dictionary without it, so `configd` is what carries system proxy and PAC settings in, and without it
they disappear without an error. `uv` panics without `configd` (`tests/tls_handshake.rs`). The same visibility means the agent can read
the host's proxy configuration while `system_trust` is on. `hb doctor` lists the proxy settings the system has switched on and says whether the agent can read them (D90).

These settings add trusted roots only. They work with the proxy off, because hosts then present
public-CA certificates that Node already trusts. Nothing in `hb` is specific to one vendor.

### 4.6 Host services

What the agent may do with the machine around it is a small set of named levels. Each row says the default, who may change it, what
it does, what enforces it and which test pins it. Rows in the first group are switches; the second group is never available.
Everything else in the profile (paths, hosts, ports) is the grant model of 4.2 to 4.4.

| Service | Default | Who may change it | What it gives the agent | Enforced by | Test |
|---|---|---|---|---|---|
| Network | none | any file adds hosts and loopback ports; MCP `bind_ports` | the proxy port and the listed loopback ports | `network-outbound` and `network-bind` rules (7.1 step 5) | `seatbelt_render` network tests |
| System trust store (`tls.system_trust`) | on in the base | any file may turn it off | TLS verification against the system roots. Also lets `configd` answer, which shows the host's proxy and PAC settings | Mach lookups and the keychain read (4.5) | `seatbelt_tls`, `tls_handshake` |
| Clipboard writes (`terminal.clipboard_write`) | on | any file may turn it off | OSC 52 writes reach your clipboard | the output filter (7.3) | `pty` |
| Container control (`ctl`) | none | any file lists containers | `hb ctl` on a labelled or named container (9.3) | the broker, preflight, pins | `ctl_broker`, `mount_pins`, `podman_e2e` |
| **launchd jobs (`ctl.launchd`)** | **none** | **only your own files, in any form** | `hb ctl launchd status`, `kickstart` and `restart` for each listed job label (9.3) | the broker; `/bin/launchctl` stays denied | `ctl_broker`, `launchd_e2e` |
| **Internal addresses (`net.internal_hosts`)** | **none** | **only your own files, in any form** | the listed hosts may resolve to private, unique-local and tunnel addresses (12.1) | proxy address classes (12) | `proxy_hardening` |
| **`launchctl` (`system.launchctl`)** | **off** | **only your own files may say `true`; any file may say `false`** | run `/bin/launchctl`: see below | `(deny process-exec (literal "/bin/launchctl"))` | `probe_matrix` |

**`system.launchctl`.** Measured on macOS 15.7 with a throwaway job loaded from outside the ball: launchd refuses a sandboxed caller
anything that creates a job or touches a running process (`bootstrap`, `load`, `submit`, `setenv`, `start`, `stop`, `kill`,
`kickstart -k`, `bootout` of a running job). It allows `kickstart` of a job that is not running (the job runs outside the ball),
`bootout` and `unload` of a job that is not running, `disable` and `enable` (a disable persists across logins), and
`print` of the whole service list, the launchd user environment and the names of installed software. Nothing is logged as a denial,
and the requests go over the bootstrap port, so no `mach-lookup` rule can tell them apart. The profile therefore denies running the
program unless you turn it on. A copy of `launchctl` in the project does not help the agent: it is killed at exec (a plain copy, a
copy re-signed ad hoc, and thinned x86_64 and arm64e copies were tried), because macOS kills a platform-signed binary that is not on
the system volume. **Not tested:** an Intel Mac, other macOS versions, and a program that speaks launchd's private XPC protocol
itself (that is work against macOS, which section 2 puts out of scope). With it on, treat every LaunchAgent you have as something
the agent can start. `brew services` and a job that needs `bootstrap` do not work either way. The scoped form is `[ctl] launchd` with
`hb ctl launchd` (9.3, D87): it needs `system.launchctl` to stay off. `hb doctor` (hb-ghd.5) warns, by name only, when `launchctl print gui/<uid>` shows a secret-looking name in
the launchd environment, because the agent could read it if `launchctl` is on.

Never available, with no switch (measured, `probe_matrix`): LaunchServices (`open -a` starts nothing, `lsappinfo` lists no
applications), Apple Events (an event to a running application fails with `-600`, and still fails with every Mach lookup allowed),
setuid programs (`sudo`, `ps`, `top`, `crontab`), the pasteboard command-line tools (`pbcopy`, `pbpaste`), keystroke injection
(`hid-control` is not representable), `log show`, and signalling a process outside the ball. `pgrep`, `diskutil`, `dscl`,
`caffeinate`, `pmset -g`, `networksetup` and `defaults read` fail too; nothing asked for them, so there is no switch.

Machine information the agent can read, which no setting controls: `ioreg` and `system_profiler` (hardware serial number and platform
UUID), `ifconfig` (MAC addresses), `netstat -an` (every process's connections), `lsof`, `mount`, `hostname`, `id`, `sw_vers` and the
host's proxy settings through `configd`. None is a path in the threat model (credentials, planted code, exfiltration, tokens); they
tell the agent about the machine, and with the proxy as the only way out they cannot leave it.

## 5. Trust and approval

The agent can write the project directory, so a project config or a file it extends could be
changed by the agent, or by a `git pull` of someone else's change.

- The floor makes `hamster-ball.toml` (and any `extends` file inside the project) **read-only inside the hamster ball**.
- An **approval record** says "the user reviewed this closure of config files and allowed `hb` to run it".
  The record holds the canonical project root and a SHA-256 over the contents of every config file
  in the resolved closure that the hamster ball could write (project file and in-project `extends` files).
  User-level files are outside the hamster ball's reach and need no approval.
- On first run, or when any hash changes, `hb` prints what the project **adds beyond the base**
  (the grant summary) and asks for confirmation. The result is stored in
  `~/.local/state/hamster-ball/approvals/`, which the floor denies to the hamster ball for read and write.
  `XDG_STATE_HOME` is **ignored** (D47): a project `.envrc` (after `direnv allow`) could otherwise move the store into
  a directory the agent can write. `hb explain` says when the variable is set and ignored.
- Without a terminal, an unapproved config is a hard error (exit code 78). It is never auto-approved.
- This is an approval store like `direnv allow`. It is not an access log.

**How it works (hb-ghd.4, D77).**

- **Fingerprint.** SHA-256 over length-prefixed (canonical path, exact bytes) pairs of the approval files in closure order,
  with a version prefix. A changed byte, a renamed, added, removed or reordered file all change it; modification times are
  never read. Moving the project gives another record, because the record is keyed by the canonical root.
- **Record.** `approvals/<sha256 of the canonical root>.toml`: `format = 1`, `root`, `closure_sha256`, and each file's path and
  digest (the per-file digests only let the prompt say which file changed). The directory is mode 0700, the record 0600, written
  to a temporary name and renamed. A record or directory that is unreadable, a link, owned by someone else, writable by group or
  others, over 256 KiB, malformed, of another format or root, or has a bad digest counts as **not approved**, with the reason shown.
- **The question.** `hb run` and `hb approve` print why, the project root, each file with a short digest, and what the project
  **adds beyond your base**: every value no file of your base chain also gives, including what a preset the project names grants.
  An `env.set` value and an MCP server's arguments are shown (they decide what runs), bounded and with control characters escaped.
  `Approve this config? [y/N]` takes only `y` or `yes`, typed at a terminal (stdin and stderr both terminals).
- **No terminal, or a no.** `hb run` exits **78** without starting the command, and says so. A command that `hb run` runs can also
  exit with 78; the message tells them apart. `hb approve` without a terminal exits 78 too, and has no `--yes`.
- **Unaffected.** `hb explain` and `hb profile` run nothing and need no approval; `hb explain` adds a warning when the config is not
  approved. The library entry point (`cli::run`, used by tests) never prompts. `hb approve` refuses inside a hamster ball.
- **Revoke.** `hb approve --revoke` removes the project's record, needs no terminal (it only narrows), and says whether there was one.
- **Not covered.** Built-in presets are not hashed, so a newer `hb` that changes a preset changes what a project that names it
  grants without a new question. That is the trust you put in the binary you installed.

## 6. The floor

Compiled into `hb` (`policy::floor`), resolved against the real filesystem when a project is loaded
(`system::floor`). It cannot be overridden by the user base, presets or projects: a `Policy` holds the floor it
was built on, has no `Default`, and config files never see it. Every rule has an **effect** and an **extent**:

| Effect | Forbids | Seatbelt form (hb-ghd.2.1) |
|---|---|---|
| `deny_read_write` | read, write, create, delete, rename | `(deny file-read-data file-read-metadata file-read-xattr file-test-existence file-write* ...)`. The shorter `file-read*` form leaves `stat` working under the global metadata allow (7.1) |
| `deny_write` | write, create, delete, rename | `(deny file-write* ...)` |
| `deny_connect` | `connect()` to a unix socket | `(deny network-outbound (remote unix-socket (subpath ...)))` |
| `pin_unlink` | unlink or rename of the node itself | `(deny file-write-unlink (literal ...))` |

| Extent | Covers |
|---|---|
| subtree | the path and everything under it (`subpath`); a symlink's own name is added as `literal` |
| node | the path only |
| children | the path's direct children, not the path |

Rules are emitted after every allow (7.1 step 8), so a floor rule wins. Every rule names a canonical path (a test
asserts none starts with `/System/Volumes/Data`). A path that does not exist yet is still covered.

**Read and write denied** (credentials, history, browsers, containers, `hb` itself):

- `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`, `~/.config/gh`, `~/.docker`, `~/.kube`, `~/Library/Keychains`
  (measured with a throwaway keychain, D62: every client fails to read a secret while the floor is on, because the Security framework opens
  the file itself; `securityd` does **not** check the client's sandbox. A process that already held an open, unlocked keychain handle
  before the sandbox was applied keeps reading through it, and a descriptor inherited from before the sandbox is readable. `hb` spawns the agent inside
  the sandbox with no such handle, so neither case arises; any path that gives the agent an unsandboxed reader of the file would defeat the floor. The
  data-protection keychain was not exercised.)
- More credential stores: `~/.git-credentials`, `~/.cargo/credentials*`, `~/.npmrc`, `~/.pypirc`, `~/.pgpass`,
  `~/.vault-token`, `~/.gem/credentials`, `~/.terraform.d/credentials.tfrc.json`, `~/.config/{op,rclone,gcloud,doctl,hub,glab-cli}`,
  `~/.azure`, `~/.oci`, and the 1Password data and group-container directories
- History: `~/.*_history`, `~/.zsh_sessions`, atuin's data and config
- Browsers, whole vendor directories under `~/Library` (Application Support: Google, Chromium, Microsoft Edge (+ Beta, Dev,
  Canary), Vivaldi (+ Snapshot), Opera, BraveSoftware, Arc, Comet, Firefox, Mozilla, zen, TorBrowser-Data; plus Safari,
  Cookies, WebKit, HTTPStorages, the Safari container and sandbox broker; caches for Google, Firefox, Mozilla, Safari, Arc)
- Containers: `~/.local/share/containers`, `~/.config/containers`, `/var/run/docker.sock`, `/var/run/podman`
- `~/.config/hamster-ball` and `~/.local/state/hamster-ball` (base config and approvals)

**Connect denied** (D42; a file deny does not stop `connect()`): `/var/run/docker.sock`, `/var/run/podman`, `~/.docker/run`,
`~/.colima`, `~/.lima`, `~/.rd`, `~/.orbstack`, `~/Library/Containers/com.docker.docker`, `~/.local/share/containers`, and
`<per-user temp dir>/podman`, where a podman machine started from a nix shell or launcher puts its API socket. The temp
directory comes from `getconf DARWIN_USER_TEMP_DIR`, not `$TMPDIR`. A socket at an unknowable path is covered only by
the deny-default network (7.1 step 5): no `network-outbound` rule may allow a unix socket except the `hb ctl` socket.

**Write denied** (reads stay up to the grants):

- Shell startup: `~/.zshrc`, `~/.zshenv`, `~/.zprofile`, `~/.zlogin`, `~/.zlogout`, `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`,
  `~/.bash_logout`, `~/.profile`, `~/.config/fish`, `~/.cargo/env`, `~/Library/LaunchAgents`
- Tool configuration that runs code or redirects package sources (D43): `~/.gitconfig`, `~/.config/git`, `~/.cargo/config.toml`,
  `~/.cargo/config`, `~/.terraformrc`, `~/.yarnrc`, `~/.yarnrc.yml`, `~/.m2/settings.xml`, `~/.config/pip`, `~/.config/uv`
- Programs: `~/.local/bin`, `~/.cargo/bin`, `~/go/bin`, `~/.bun/bin`, `/opt/homebrew/bin`, `/opt/homebrew/sbin`, `/usr/local/bin`,
  every absolute directory on your `PATH`, and `hb` itself (D45)
- In the project: `hamster-ball.toml`, every approval file (the closure files the ball could write), and git's hooks and
  config (D41)

**Git** (D41). `.git` is classified by what is there, because an agent that can rename `.git` can plant a `gitdir:` pointer
and have git run its hooks outside the sandbox (measured: real `git commit` ran the planted hook):

| `.git` is | Rules |
|---|---|
| a directory | `hooks`, `config`, `config.worktree`, `commondir`, `modules/**/{hooks,config,config.worktree,commondir}` and `worktrees/*/config.worktree` below it. `commondir` is on the list because git takes hooks and config from the directory that file names (verified: a planted `commondir` made git 2.50 run a hook from an agent-controlled directory). `worktrees/*/commondir` is not, so `git worktree add` keeps working |
| a file (`gitdir:` pointer: worktree, submodule) | the file itself, and the same rules under the git directory it names and under that directory's `commondir` |
| a symlink | the link's own name, and the same rules under what it points to |
| missing | the `.git` name itself, so a pointer cannot be created |

The pointer is untrusted text (the agent can write it): at most 1 KiB, one line, no control characters, only the line ending
removed (git keeps trailing spaces, so a directory named `x ` is not `x`), joined to the directory holding `.git` and resolved
as a literal path (never as `~` or a glob). Only regular files are read, so a FIFO or symlink named `commondir` is an error. A malformed pointer in the project is an
error; the same walk applies to every enclosing repository above the project root, where a problem is a warning. Not
protected: standalone repositories nested below the root (protecting them would break `git init` and `git clone` in
subdirectories; D46), and hard links that existed before the ball started (reported when a protected file has `nlink > 1`).

**Pins** (D41). Denying a path does not stop renaming one of its ancestors. For every protected path, each ancestor that a
write grant (or the project root) reaches gets a `pin_unlink`, so `mv .git .git-old` and `mv presets presets-old` fail while
ordinary writes beside them work. A glob rule's base is pinned too, since the base itself is not denied.

**`PATH`** (D44, D45). Read from the process once. Only absolute entries are used; empty, `.`, relative and unexpanded `~`
entries are reported and skipped. Entries are resolved (a symlinked entry covers both names), de-duplicated and sorted by
path. A missing directory is kept. An entry that equals or contains the project, your home or a write grant is covered for
its direct children only, so the project stays writable. An entry inside the project (`.venv/bin`, `node_modules/.bin`)
is not write-denied, because that would stop `uv sync` and `npm install`; it is reported. A symlink in a program directory
that points into a write grant has its target write-denied (up to 256 targets), and so does every link on the way
(`~/.tool/current -> versions/1.2`), including when the end of the chain does not exist yet, because the agent could otherwise replace
a program you later run outside the sandbox (`~/.local/bin/pi` into `~/.pi/agent`; a preset can say
`deny_write = ["~/.pi/agent/bin"]` to make that intent explicit).

**Failure behavior** (D48). A table or project rule whose path cannot be resolved (a dangling or looping symlink, a file where a
directory should be) is an error naming the rule; there is no lexical fallback, because an unresolvable path is where something
could be planted. Only `PATH` entries and enclosing repositories degrade to warnings.

Notes:

- `~/.kube` is denied because it can hold credentials for real clusters. A project that needs
  `kubectl` to a local cluster should point `KUBECONFIG` at a project-scoped file.
  A project with a local cluster needs this; the exact mechanism is an open item (section 15).
- `~/.npmrc` is denied for read as well as write (D43). A private registry needs its auth in a project `.npmrc` that
  reads `${NPM_TOKEN}`, passed with `env.pass`.
- Denying `.git/config` blocks `git push -u` and `git remote add` inside the hamster ball. This is the
  default; revisit after use (section 15). `config.lock` can still be created, so git fails with "could not write config file".
- Git network operations work over HTTPS through the proxy only, with no credentials
  (keychain and credential helpers are not reachable). Pushing is done by you, outside the hamster ball.
- Out of scope, because they are project files you run and the agent legitimately edits: `Makefile`, `justfile`, `.husky/`,
  `.envrc`, `.vscode/tasks.json`, `.pre-commit-config.yaml`, `package.json` scripts, `conftest.py`.
- A floor rule can make a grant useless. `hb explain` reports a grant that the floor overrides in whole or in part
  (`grant_shadowed_by_floor`), so a mistaken grant does not lose silently.

## 7. Enforcement

### 7.1 Seatbelt profile

`hb` generates a profile and runs `sandbox-exec -p <profile> -D name=value ... -- <command>`. All config-derived
text (paths, regexes, ports) reaches the profile only as `(param "...")` values; the profile text itself contains no
config-derived string (D52). The generator is a pure function of `(Policy, RenderInputs)` that builds a typed rule list,
checks it (`check.rs`), then emits text (`emit.rs`).

**Rule precedence** (measured, D51). Seatbelt resolves the most specific *operation* first; rule order only decides
between rules at the same operation level. A later `(deny file-read* X)` does **not** override an earlier
`(allow file-read-metadata)`: `stat`, `ls -ld`, `test -e` and `readlink` still work on X. Floor and guard denies
therefore name the operations explicitly. Order still matters inside one level (a template re-allow placed after a deny
reopened the file; placed before, it did not). Generated order:

1. `(version 1)` (version 3 breaks exec), `(deny default (with message "hb-<token>"))`, `(import "system.sb")` (`system.hb`
   does not exist; the file is `system.sb`), `process-exec`, `process-fork`, `(allow signal (target same-sandbox))`,
   `ipc-posix-shm`, `ipc-posix-sem`. `sysctl-read` is already in `system.sb`. No `hid-control`, ever: it is the
   operation that gates `TIOCSTI` keystroke injection (D54).
2. Metadata for all paths: `(allow file-read-metadata)`. This is more than names: existence, size, mode, owner, times and a
   symlink's target text are visible for every path, including floor paths. Contents, directory listings and xattr
   values are not. Plus `(allow file-read-data (path-ancestors ...))` for each grant (Bun and Node list ancestors while
   resolving modules; a floor-denied ancestor is not listed).
3. Allow reads and writes from the merged config, with wildcard operations only. System read-only directories: `/usr`,
   `/bin`, `/sbin`, `/private/etc`, `/private/var/select` (`/bin/sh` is a select symlink), `/Library/Developer/CommandLineTools`
   (git, clang). Not `/Library` whole: it contains `/Library/Keychains`, which section 4.5 gates. Device nodes: `/dev/fd/N`,
   `/dev/stdin`, `/dev/stdout`, `/dev/stderr`. The `xcrun` tool-path cache `<user temp dir>/xcrun_db`, read only (D69).
4. TLS Mach services and keychain reads (section 4.5), as typed rules in the first renderer cut.
5. Network: outbound only to `(remote ip (param "PROXY"))`, plus each `loopback_ports` entry. Never `localhost:*`
   (a wildcard allowed other loopback ports). The port is a parameter, so the text does not depend on it.
   `network-bind` and `network-inbound` are allowed only for the ports a config lists in `mcp.<name>.bind_ports`, one
   `localhost:<port>` rule each (D58). A bind port must be 1024-65535 (macOS lets any user bind a port below 1024 on the wildcard
   address, measured; `localhost:80` matches that bind), at most 16 per server and 64 distinct in all (D62). The cap is exposure,
   not cost: each parameterised port adds compile time (about 0.1 s at 64 ports, 0.3 s at 256), Seatbelt refuses a profile somewhere
   above 3000, and no real server asked for more than two. Measured: both are needed (bind alone fails), a wrong port is denied, there is no
   range syntax, and port 0 needs the wildcard `localhost:*`, which is never emitted. Two limits to state plainly: the rule
   is profile-wide, because the agent spawns its MCP servers and every process shares one profile; and it does **not**
   confine the listener to loopback: a server that bound `0.0.0.0` on an allowed port was reachable from the machine's LAN
   address. `hb explain` and the approval summary list every bind port with that caveat.
6. Secrets guard denies (section 8): `file-read-data file-read-xattr` plus the write class, so file names stay visible.
7. Template re-allow (`*.example`, `*.sample`, `*.template`), naming the same operations the guard deny names (a wildcard `file-read*` allow cannot reopen a specific-operation deny; measured).
7a. Host services: unless `system.launchctl` is on, `(deny process-exec (literal "/bin/launchctl"))` (4.6). After every allow, because a
   later rule on the same operation wins.
8. Floor (all four effects, 6), pins (the secrets guard's, and the `hb ctl` mount pins of 9.3: `file-write-unlink` and `file-link`) and `deny_*` rules last, so nothing re-allows them. Read-class denies list the full
   read set: `file-read-data file-read-metadata file-read-xattr file-test-existence file-map-executable`, plus `file-write*`
   (`file-map-executable` is a child of `file-read-data`; naming it closes mapping a denied file as code through a descriptor
   opened before the sandbox, D62).

Invariants checked on the typed rule list before any text is written (`check.rs`): sections are non-decreasing; each section
allows or denies, not both (the host-services, guard, policy-deny, floor and pin sections only deny); an exec rule names only a literal written in the crate; no allow of `file-write-unlink` or any
specific write operation (it would override a `file-write*` deny regardless of order); a deny never uses `file-read*`, and a
floor or policy deny that names reads names all five and `file-write*` (the guard may name a subset so file names stay visible,
but must name the write class); a specific read allow appears only in the metadata section and the template re-allow;
every `network-outbound` allow is a `remote ip (param)` or a unix-socket path-literal; `mach-lookup`, `file-ioctl` and the
network operations are never allowed unfiltered or with another operation's filter; each filter carries the parameter kind that
belongs to it; every param is non-empty and absolute (endpoints are `localhost:<port>`, port 1-65535; a bind port 1024-65535); static text contains no
quote, backslash or control character. `hid-control` and `appleevent-send` are not representable at all. Whether "no specific
operation allow can match a floor path" holds is a consequence of these, since every deny names its operations explicitly and
comes after every allow. A render budget warns at 600 filters and errors at about 1500 (compile time follows the filter count and
is roughly quadratic: 0.06 s at 131, 1.5 s at 600, 36 s at 4096).

### 7.2 Environment

The child starts with an empty environment (`env -i` semantics). `hb` sets `HOME` (real), `TMPDIR` (the session directory),
`PATH`, `TERM`, `HB_SESSION=1` (so a nested `hb` can say it is inside one; other sandboxes leave no marker, so it never decides anything), proxy variables, TLS variables, and the names in `[env] pass` / values in `[env] set`. Measured gap in the
old `sb`: it inherited every token in the parent shell. Static AWS keys are never passed (section 11).

**`PATH`** (D59) is the fixed system directories `/usr/bin:/bin:/usr/sbin:/sbin`, then the directory of each program named in
`[env] tools`. `hb` resolves each name against the invoking shell's `PATH` when it starts, canonicalizes the directory, adds it
to the child's `PATH` and grants it read (a script on `PATH` needs the read; a binary does not). A name that is not found is a
warning, like a skipped allow. This is how `pi` and `npx` (`#!/usr/bin/env node`) find node under nvm, whose directory changes
with the version; an agent binary launched by absolute path needs nothing. A project that steers your `PATH` only changes which
program runs inside the sandbox. `hb explain` shows each resolved directory. Tools are kept sorted by name, so the profile does not
depend on file order. The command of `hb run` is looked up on that child `PATH` by `hb` itself, because `sandbox-exec` reports a
missing command with exit 71, the code it also uses for "already sandboxed".

**Reserved names** (D59): `[env] pass` and `[env] set` cannot name `HOME`, `PATH`, `TMPDIR`, `TERM`, the proxy and TLS variables,
`HB_*`, `DYLD_*` or `LD_*`. The error names the file. `set` wins over `pass`. `TERM` is the parent's when stdin is a tty, else
`dumb`.

**Descriptors** (D63). `sandbox-exec` passes every open descriptor to the command and Rust's `Command` closes only the ones Rust opened,
so `exec 3<~/.ssh/id_x; hb run agent` would hand the agent a readable key although the profile denies the path (Seatbelt checks a path when
a file is opened). The `hb` binary closes every descriptor above 2 first thing in `main`. Library callers (`session::run`) do not, and must not
close their host's descriptors; an embedder has to do it itself.

**Size** (D63). The command line and environment together must fit in `kern.argmax` (1 MiB, measured: argv and env share it). `session::run`
checks the whole `sandbox-exec` command line (profile text, `-D` parameters, the command) plus the environment against 1 MiB minus 32 KiB
before it spawns, and names the parts in the error.

**Exit status** (D60). `hb run` returns the child's exit code. If the child died of a signal, `hb` cleans up (session directory,
terminal) and then re-raises that signal on itself for INT, TERM, HUP and KILL, so a calling shell sees a signalled child and a
script aborts on Ctrl-C (measured: with `exit 130` a bash loop kept going; with a re-raise it stopped). Other signals (SEGV, ABRT)
return `128+n`, so `hb` does not leave core files.

**Signals** (D64, hb-ghd.2.3b). The `hb` binary blocks INT, TERM, HUP and WINCH in its main thread before any other thread exists, and
receives them through a kqueue (`EVFILT_SIGNAL`; `sigwait` never gets SIGWINCH on macOS, and kqueue was measured to work).
They are forwarded to the child's process group (own group, stdin not a tty) or to the child alone (shared group). The first
signal starts a 5 s clock; a second signal, or the clock running out, sends SIGKILL. When the child shares `hb`'s group and stdin is
a terminal, the terminal already sends INT and HUP to the child (measured: one Ctrl-C reaches both once, so forwarding gives the
child two), so `hb` is passive for them: no forward and no clock, or it would kill an agent that handles its own Ctrl-C. TERM is still
forwarded. With a pty (7.3) the child is its own session, none of this applies, and every signal is forwarded to its group. Rust's `Command` passes the parent's blocked set to the child, so `hb` starts itself as `hb __child -- <sandbox-exec
arguments>`, a hidden subcommand that empties the mask and execs `/usr/bin/sandbox-exec` (only that), and the child's blocked set is
empty (tested with perl `sigprocmask`). The re-raise lives in `cli::main`, never in the library: when the child died of INT, TERM,
HUP or KILL `hb` finishes cleanup, lifts the mask and raises the same signal on itself. A signal the caller sent to `hb` is still
pending then, so `hb` dies of that one (a TERM sent to `hb` whose child was then killed ends as TERM, not KILL). Tests run the
real process through `hb-testdrive`, a test-only binary (feature `test-support`) that is `hb` with an `Environment` from `HB_TD_*`
variables, because the real `hb` takes its home from the passwd database (D28).

**`--log-denials`** (D64). The profile's `(deny default (with message "hb-<tag>"))` tags this run's denials; `log stream` is started
first, with a predicate on that tag, and confirmed listening by its header line (about 200 ms). When stderr is redirected each denial
is written live as `hb: denied: ...`; on a terminal the denials are collected (1000 at most) and printed after the command ends, so
they cannot corrupt an interactive screen. After the child ends `hb` waits for 300 ms of quiet on the stream (2 s at most). Measured:
90 of 90 reads seen for `sh` and `perl`, 0.12 s at most behind the event, also under 24 CPU hogs; Python and Node were incomplete
before, so the lines are hints for a person, never input to rule generation.

### 7.3 Terminal

**What stops keystroke injection** (measured on macOS 15.7, a regression probe in `tests/pty.rs`). `TIOCSTI` pushes bytes into a
terminal's input queue. The probe tries it three ways: through descriptor 0, by re-opening the terminal's path, and through
`/dev/tty`.

| Run | fd 0 | path | `/dev/tty` |
|---|---|---|---|
| unsandboxed, on a pty | injected | injected | injected |
| `(allow default)` profile | injected | injected | injected |
| `(allow default)(deny hid-control)` | refused | refused | refused |
| `hb`'s profile (`file-ioctl` on the slave, no `hid-control`) | refused | open refused | open refused |
| `hb`'s profile plus a hand-added `(allow hid-control)` | injected | open refused | open refused |

The gate is the `hid-control` operation, which `system.sb` does not grant. The profile never gains it (a static check on the
rendered text, and the last row above shows the probe test fails if it did, through descriptor 0). So the pty is **hygiene and job control, not the
injection control**.

**The pty** (D65, hb-ghd.2.4). `hb run` allocates a fresh pty when it supervises the run and its stdin is a terminal. The child
starts through `hb __child --controlling-tty`, which calls `setsid` and takes the slave as its controlling terminal, so the child
leads its own session and group and is that terminal's foreground group. Its three standard streams are the slave. The profile
grants `file-ioctl` on that one slave path only. Re-opening the slave by path, opening `/dev/tty` and opening other terminals are all refused, so the child works through the descriptors it was given. The master is close-on-exec, and `hb` drops its own copy of the
slave once the child has started, so no descriptor above 2 reaches the child and the master sees the end of the child's output. If
the pty cannot be set up the run fails with `PtyUnavailable`. There is no fallback to the user's terminal. When stdin is not a
terminal there is no pty, and the child has its own process group as before (7.2).

**Relay.** `hb` puts the user's terminal in raw mode only after the child has started. One thread copies the user's keystrokes to
the master and the master's output to the screen byte for byte. When the child ends, the thread drains what it last wrote (150 ms
of quiet, 2 s at most). `hb` copies the user's window size to the pty at start and on every SIGWINCH. Every signal `hb` receives
is an explicit one, because the terminal's keys now reach the child through the pty, so all of INT, TERM and HUP are forwarded to
the child's group with the 5 s escalation (7.2).

**Ctrl-Z.** The child's terminal driver turns Ctrl-Z into SIGTSTP for the child, and an agent that handles it stops itself. `hb`
sees the stop, pauses the relay, gives the user's terminal back in its original mode, and stops itself with SIGSTOP, so the shell
shows a suspended job. On `fg` it returns to raw mode, copies the window size, resumes the relay, and sends SIGCONT to the child.
The relay is paused first because the terminal restore flushes the input queue. A relay that had already seen bytes there would
block in its next read, and the child could never finish its output (found with `fg` typed at once, fixed, with a regression
test). A child stopped by `hb`'s SIGSTOP is stopped too, which is the point.

**Restore.** The terminal's original settings are put back by `Drop`, with `TCSAFLUSH`, so keys typed after the child ended are
discarded and not read by the shell (measured: with a plain restore, late input reached the shell). That covers a normal exit, a
child that is killed, and SIGINT, SIGTERM or SIGHUP to `hb`, and `hb` has no `panic = "abort"` profile so an unwinding panic runs
it as well (no panic hook is installed).

**SIGKILL of `hb`** (D66). Nothing in `hb` can run when it is killed, so a second process does. `hb` starts `hb __guard` in a
session of its own, registers the agent's process (or group) and the `log stream` helper with it, and holds the only write end of a
pipe to it. A normal end sends `release` and the guard exits. If the pipe closes without one, the guard sends what is still
running SIGTERM and, after 2 s, SIGKILL. It watches each registered process with a kernel exit notification and records each
process's number with its start time. Before every signal it reads the process again, and a number whose start time differs is
not signalled, so a number the system has given to an unrelated program is left alone. The check and the signal are two steps,
so a gap remains that is unlikely and not bounded in time (hb-caj).

**Descendants** (hb-caj). macOS refuses `NOTE_TRACK`, so the kernel does not follow forks. The guard registers `NOTE_FORK` and
`NOTE_EXIT` on each owned process and, on a fork, lists the children and adopts them.
A group's original leader must still be identifiable (live or unreaped zombie) through observation before additional members are adopted.
Already-owned members remain tracked after the leader is gone; a bare leaderless group number authorizes no new adoption.
Parent identity is likewise retained through child observation.
Each adoption checks the listed relation, user and root age.
Recovery retains the identity captured before token confirmation or before the `lsof` directory scan and checks it again at registration.
The directory snapshot can miss a process born during that scan; this is an incomplete pass, not proof of absence.
Two recovery sweeps look for missed descendants: processes whose environment holds this run's `HB_LAUNCH_TOKEN`
(candidates from two `ps` listings, each confirmed by reading the process's environment as separate entries) and processes
using the per-run directory (`lsof`). A sweep finds candidates only and never shows that cleanup is complete. **Residual,
measured:** a process started in a chain of fork-then-exit generations can win the race against discovery; a process that
clears its environment is invisible to the token sweep; macOS hides the environment of Apple's own tools (`/bin/sh`, `perl`,
`sleep`), so such a survivor that has also left the directory and closed its files there is not found; processes of other users
are out of scope.
An unreadable subtree can hide directory holders without a diagnostic.
Known members receive KILL before the final sweep; deadlines are cooperative between operations, not guarantees against OS stalls.
No durable cleanup report is produced once hb dies.
Stopping a dedicated VM stops its guest processes; simply using one does not arrange that teardown.
Measured before the
guard: with no terminal, a killed `hb` left both the agent and the `log stream` running (with a pty the kernel hangs up the agent,
and `log stream` dies with the session). **The raw terminal cannot be repaired, so the guard says so.** Bash puts the terminal back itself. zsh (the macOS login shell)
adopts the settings of a job that was killed and applies them to every later command: measured, with a guard that restored the
settings first (0 of 8), and with `stty sane` from outside at 0 and 300 ms after the shell reaped the job (undone at the next
command both times). That holds for every raw-mode program, not only `hb`. So the guard is told the user's terminal when `hb` is
about to put it in raw mode, and if `hb` dies without a release it waits 300 ms and, if the signal keys are still off, writes
`[hb was killed while it held your terminal in raw mode. If the terminal misbehaves, type: reset]`. Under bash, which has
repaired it, nothing is printed.

**What the agent can ask the user's terminal** (D67). The agent's output reaches the user's real terminal, and some terminals
answer some queries with text the asker chose, typing the answer into the terminal's input: the title report (CVE-2003-0063
xterm, CVE-2022-45872 iTerm2, CVE-2024-56803 Ghostty), kitty's colour-control and DCS handlers and iTerm2's graphics replies
(2026). While `hb` runs, the answer goes back to the agent, which is harmless. It is dangerous when it arrives after `hb` has handed
the terminal back: the shell reads it as typed commands, and `hb`'s old behaviour left a window of a drain period (150 ms) in
which it was swallowed and a slow link (ssh) could miss it. This was reproduced with a terminal emulator in `tests/pty.rs`. Three
measures:

1. **A filter on the agent's output** (`session::sanitize`) removes what cannot be allowed, with an allowlist for the string
   sequences, where the bugs are. OSC passes for 0, 1, 2, 4, 7, 8, 9, 10 to 12, 99, 104, 110 to 112, 133, 777 and 52 as a *write* (a
   clipboard read is dropped; whether a write is allowed is the terminal's own policy). DCS passes for sixel and synchronized
   output only. APC, PM and SOS are dropped (APC carries the kitty graphics protocol, whose error replies echo what the sender
   wrote). `CSI 20 t` and `CSI 21 t` (title report) are dropped, as are `ENQ` and every C1 control in both its single-byte and
   UTF-8 spelling, because terminals differ on whether they honour them. Queries whose answers are fixed numbers (device
   attributes, cursor position, mode reports, colours) pass, because terminal programs need them. The parser is the DEC state
   machine, works on chunks of any size (tested: the result does not depend on how the input is split), validates UTF-8 strictly,
   and ends a string the agent cut off with its own terminator, so the terminal never decides what a cut-off string means. It
   filters only the agent's output; what the user types is not touched.
2. **A fence at the end.** Before `hb` gives the terminal back (at the end of a run and at Ctrl-Z), it switches off the input modes
   an agent may have left on (mouse, focus events, bracketed paste) and asks the terminal for its primary device attributes. A terminal
   answers in order, so when that answer arrives every earlier reply has, and everything read until then is discarded. A terminal
   that never answers costs 750 ms. The fence is defence in depth for a terminal bug in a query the filter lets through, and it
   also stops an ordinary late cursor-position report from showing up at the prompt.
3. **No unfiltered mode.** When stdin is not a terminal there is no pty, but if stdout or stderr is a terminal the agent is given a
   pipe for it and `hb` copies the pipe to the terminal through the same filter (`session::pump`). The agent then sees a stdout that
   is not a terminal, as it would in `agent | tee`, which is what a batch or print-mode run expects; every interactive agent needs a
   terminal on stdin as well, so none of them is affected. `hb` is not relaying the terminal here, so at the end it does what it does
   for a pty run on its own copy of the terminal: it puts the terminal in raw mode (so the answers are not echoed), switches off
   mouse, focus and paste reporting, asks for the device attributes, discards input until the answer, and restores the settings.
   It does this only if its own process group is the terminal's foreground group, because from the background it would be
   stopped. Measured before the change: with `hb run -- agent < /dev/null` a late title-report reply ran a command in the user's
   shell. The two streams are copied by separate threads, so their interleaving on screen can differ from a shared terminal's. A
   background process of the agent that keeps a pipe open cannot hold up the end of the run (the copy stops 150 ms after the last
   byte, 2 s at most).
4. **Clipboard writes are counted, and can be refused.** An agent can only reach the clipboard through `OSC 52` (`pbcopy`,
   `pbpaste` and `osascript` are denied the pasteboard, measured), so writes pass by default and reads are dropped. At the end of
   a run `hb` prints `warning: the agent set your clipboard N times` when there were any. `[terminal] clipboard_write = false`
   removes the writes instead, and the end of the run says `the agent tried to set your clipboard N times;
   terminal.clipboard_write = false stopped it`. Like `tls.system_trust`, `false` from any file wins, so a project can refuse but
   cannot turn back on what the user's base refused. `hb init` writes the setting commented out.

Measured on the four agents: they emit OSC 0, 4, 8, 10 to 12 and 112 and the other sequences above, all of which pass. Two capability
probes are dropped (pi's `OSC 7501;?` and opencode's `OSC 66`, a kitty text-sizing probe followed by a cursor-position query), and
both agents ran the same without them.

**Shared group (no pty).** A library caller that asks for no pty while its stdin is a terminal still gets the child in `hb`'s
group, so Ctrl-C reaches both and `hb` is passive for INT and HUP (7.2). The CLI does not take this path. `hb` does not block
QUIT (Ctrl-backslash) there.

### 7.4 Nesting

`sandbox-exec` fails when run inside another macOS sandbox (also documented by other sandbox tools): `sandbox-exec: sandbox_apply:
Operation not permitted`, exit 71, whether the outer profile is deny-default or `(allow default)`. `hb` always runs the
preflight `sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` (about 60 ms) before anything else; exit 71 with that text
means nested, and `hb` stops with a clear message. An environment marker is used only to say "inside hb" in that message,
because other sandboxes (Claude Code's, Codex's) leave none. Integration tests skip, not fail, when the preflight reports
nesting, since agents run `cargo test` inside `hb`.

## 8. Secrets guard

On by default; no setup. Denies read, write, delete, rename and hard-link for files matching:

`.env`, `.env.*`, `*secret*.{yaml,yml,json,toml}`, `*.pem`, `*.key`, `*.p12`

- **Where.** Below every `fs.write` grant (the project, and any other directory you made writable), at any depth. Not below
  read-only grants: toolchains carry CA bundles named `*.pem` that TLS needs. Names are compared without regard to case, and each
  letter is written as a two-letter class in the regex so a case-sensitive volume is covered too.
- **Templates stay editable**: `*.example`, `*.sample`, `*.template` below a guard root are re-allowed after the deny, naming
  the same operations the deny names. Anchored to the roots, so the re-allow opens nothing outside them. The floor and
  `deny_*` come after, so a template name cannot reopen them (`.git/hooks/pre-commit.sample` stays denied).
- **Git-tracked files are skipped**: the agent can already read them with `git show`. `hb` runs `git ls-files -z` on the host
  with the system `/usr/bin/git`, an empty environment and config, `core.fsmonitor=false`, hooks off and a 5 s limit, and
  re-allows each tracked file with a guarded name (at most 128; symbolic links are left out). No git, or a failure, means nothing
  is skipped, and the run says so. `hb doctor` lists tracked files the guard would deny. One of the projects read for this design tracks a `.env`; its contents
  were not inspected.
- **Exceptions live only in the user base.** `[guard] exceptions` is a list of patterns that must start with `/` or `~/` and use the
  grammar of `fs.deny_read` (a base directory plus a glob tail); a relative entry is refused, because the base applies to every
  project and a relative one would switch the guard off everywhere. A matched file is re-allowed for read and write. A project
  file with the section is refused (D36).
- File names stay visible (`ls`, `stat` work); contents do not.
- Projects add their own patterns with `fs.deny_read`.
- **Dependency directories (D78).** Packages ship files with these names: `certifi/cacert.pem` (also inside `pip`), `botocore/cacert.pem`,
  grpc's `roots.pem`, `tornado/test/test.key`, twisted's test certificates, aws-sdk's `secretsmanager-*.json`. Denied, they stop
  `pip install` of tornado or twisted, `rm -rf node_modules`, and every Python TLS client that reads certifi. So below a directory
  named `node_modules` or `site-packages` (a venv is `.venv/lib/pythonX/site-packages`), the key and secret-named names (not
  `.env*`) are re-allowed for read, write and delete.
- **The pins that make that sound.** A deny on the files inside a directory does not stop renaming the directory, so
  `mv certs node_modules/x/certs` would put a key where the exemption reads it, and `mv` of the key out under a harmless name
  would follow. Measured both (`history/hb-ghd.5_dependency-dir-spike.md`). So at start `hb` walks the guard roots on the host
  (skipping `.git`, `node_modules`, `site-packages`, `.venv`, `venv` and `target`; at most 100,000 entries) and pins against rename and
  delete every directory that holds a guarded file and every directory above it up to the root (at most 256). A walk over a
  limit switches the exemption off, which fails closed and is reported. Symbolic links, hard links, `cp` and `tar` into a dependency
  directory were measured blocked.
- **Residual, stated.** A directory that gets its first key or certificate after `hb` has started is not pinned; an agent that
  blindly moves directories into `node_modules` could read it. `.env*` files are never exempt, so the commonest secret is not affected.
  `hb doctor` and `hb explain` say the exemption is on.
- Limit: a secret with an unusual name is not caught. `hb doctor` lists unmatched secret-looking files by name (never their
  contents): `.netrc`, `.npmrc`, `id_rsa`, keystores, `*.tfvars`, `*.tfstate`, and data files whose name contains secret, token,
  credential, password or api key. It also names secret-looking variables in the launchd environment, which the agent can read when
  `system.launchctl` is on (4.6). Values are never printed.

Measured: all four pattern types blocked on read; blocked all of rename-then-read, copy, hard link,
symlink, parent-directory rename, delete, overwrite, new `.env.local`, and `git add -f`; blocked
renaming, hard-linking, copying and symlinking a secret under a template name; `.ENV` blocked
on the case-insensitive filesystem (Seatbelt evaluates the canonical path); templates and source
files stay readable and writable. `tests/secrets_guard.rs` repeats these under the real profile.

## 9. Containers

### 9.1 Why agents cannot run podman

Measured:

- The podman VM mounts `/Users`, `/private` and `/var/folders` read-write. A throwaway container
  listed `~/.ssh` through a bind mount. Access to podman therefore bypasses the hamster ball's filesystem isolation.
- A container reaches the internet and host loopback-only services directly (`host.containers.internal`).
  Any agent-launched container bypasses the proxy.
- `podman network create --internal` blocks both, but also breaks published ports and
  container-to-container DNS, so compose projects cannot use it.
- Podman follows symlinks the agent plants in the project. Swapping a bind-mount source for a
  symlink, then running `podman restart`, exposed a canary file outside the project.

The floor denies the podman machine key and config paths for read and write, and denies `connect()` to the known socket
locations (section 6). A file deny alone does not stop a unix-socket `connect()` (measured).

### 9.2 Tier 1: connect-only

You start services outside the hamster ball (`just up`, `podman-compose up`). The project lists the ports in
`net.loopback_ports`. `hb` warns at start if a listed port is not listening.

Example ports (a compose project and a cluster project read, not run; the names here are neutral):

- A compose project with a dozen services, 16 bind mounts all inside the project, and no privileged or host-network settings: its database, API, tracing and query ports (3030, 5432, 8080, 9001 and similar).
- A project with no compose file, a local Kubernetes cluster and a Postgres container: a gateway port, a database port, an observability UI and a load-metrics port.
  Cluster lifecycle recipes configure the podman VM and stay host-run.
  The cluster's API port was not found.
  A pi preset for a gateway on this machine needs that gateway's port in `net.loopback_ports`.

### 9.3 Tier 2: `hb ctl`

A broker inside `hb run` listens on one unix socket, `<session dir>/ctl.sock` (mode 0600), and the profile allows the hamster ball to
connect to that socket and no other. `hb ctl` is a program inside the ball: `hb` writes `<session>/bin/hb`, a two-line script that runs
the real `hb`, first on `PATH`, and sets `HB_CTL_SOCKET`. The client reads no config; the broker decides everything from the approved
config, on the host.

- Container operations: `ps`, `logs` (tail capped at 2000), `stats`, `start`, `stop`, `restart`. No `run`, `exec`, `build`, `rm`, `cp`,
  `compose`, `kube play`. The request is one JSON line of at most 4 KiB with a closed set of fields; unknown fields and operations are refused.
- launchd operations (D87): `hb ctl launchd status|kickstart|restart LABEL`, only for labels in `[ctl] launchd` (your own files only, like
  hooks). They run `launchctl print|kickstart|kickstart -k gui/<broker uid>/<label>`; `/bin/launchctl` stays denied to the agent. `status` shows
  state, pid, run count and last exit code and nothing else: `launchctl print` lists the job's environment variables, which can hold
  secrets, so the broker keeps four fields from the job's own block and never returns the text.
- Scope: containers matching the project's compose-project label or an explicit name list (`app-db` has no label, so it is listed by
  name). The inspected name must equal the requested one (podman resolves an ID prefix).
- Fixed argument vectors, a name after `--`, and every command that acts on a container uses its full inspected ID, never the name again.
  Names match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`.
- Limits: four connections at once, five seconds to send the request, 30 s (reads) or 60 s (changes) per request, 20 KB of output (the end
  of it, stdout and stderr together). A timeout reports that the outcome is unknown. One change per container or job at a time; a second is
  refused as busy, not queued.
- **Preflight** at `hb run` start and before every operation (D88), as an allow-list. Refused: privileged; any added capability, device or
  device rule; `VolumesFrom`; a security option other than `no-new-privileges`; a PID, UTS, cgroup or user namespace that is not private;
  an IPC namespace that is host or joined; a network that is not `bridge`, `none`, `pasta` or `slirp4netns`; a mount type other than bind,
  volume or tmpfs; a volume with a non-`local` driver or any option (a `device` option makes a host directory a volume, measured); a bind
  whose propagation is not private; a bind source that is not a real file or directory inside the project (no symlink in any component, the
  OS path equals the spelling podman stores, not a file with more than one hard link); `Binds` and `Mounts` that disagree. Each refusal
  names the reason and the path. At start a refused container is a warning, gets no pins and no `start` or `restart` in that run.
- **Pinning**: the profile denies `file-write-unlink` on each mount source and on every ancestor a write grant reaches, and `file-link` on the
  source. With the usual `write = ["."]` that is the source up to and including the project root; with a wider grant it reaches up to that grant,
  because the agent can rename any directory it can write. Contents stay writable. A single file that is a mount source cannot be
  replaced by an atomic rename (the container would keep the old file anyway): edit it in place, or mount its directory.
- **Start gate** (D89): `start` and `restart` also need every bind source of the container to be among those pinned when `hb run` began,
  and the container not to have failed preflight then. A container recreated with new mounts needs a new `hb run`. Other operations do not
  re-resolve mounts and have no such gate.
- **Runtime isolation** (D89): a process in a container is not under Seatbelt, so pins do not stop it. Measured: a container that runs
  project code (which the agent can edit) can rename its own mount source and put a symlink in its place, and the next `podman start` follows
  it to any directory the VM shares. The same swap fails when the target is not shared with the VM. So `start` and `restart` are available
  only when every directory the active podman machine shares is the project or inside it. `hb` reads the machine's own file (found by the
  active connection's port, not by `podman machine inspect` alone) and, if the shares are wider, warns and refuses both operations with the
  command `podman machine init --volume <project>:<project> --now`. `hb` never changes the machine. `ps`, `logs`, `stats` and `stop` work either way.
  Only one podman machine can run at a time, so this replaces the default machine while it runs, and a new machine has no images or containers.
  Measured on the owner's machine: a second machine (`podman machine init hb-<project> --volume <project>:<project> --now`) beside the default one
  leaves the default's images and containers alone; `podman system connection default` selects the machine `podman` and `hb` use. A project
  that is narrower than the share (a scratch project under the shared repository) is refused as well: every share must be the project or inside it.
- Cleanup: the broker stops, its commands are killed and the socket is removed when the agent exits. If `hb` is killed with SIGKILL, the guard
  process (D66) removes the socket and ends the broker's running commands; a command that has just started in the microseconds before
  it is registered is left to finish or time out.

**Not covered.** Containers started by the owner keep unrestricted network egress (podman on macOS cannot restrict it). The image and the
command a container runs are trusted: only mounts and host settings are checked, so project code that a container runs can do whatever the
container can. A pin protects a name, not a file that already has a second hard link (such a source is refused). Output of `logs` can hold
secrets and reaches the agent: the 20 KB cap limits volume, not content. The `launchd` jobs are the owner's: restarting one runs whatever it
is configured to run, outside the ball. Not checked on an Intel Mac, other macOS versions or other podman versions.

Measured (macOS 15.7, podman 5.7.1; hb-ghd.8.4):
`hb ctl restart` on the owner's own project-only machine restarted a container (its start time changed) with no warning at start; on the default
machine from a project narrower than the share, `restart` was refused with the exact command and `ps` worked. The hamster ball cannot run `podman` or `launchctl`, or reach the VM's SSH port. The swap attempts (rename or
remove the mounted directory, rename the directory above it, rename another directory over it, rename or
remove the mounted file) are blocked and a hard link from a mounted file is blocked; each has a control without the pin that succeeds
(`tests/mount_pins.rs`). Editing a mounted file in place, writing, renaming or deleting files inside a mounted directory, creating entries
next to the mounts and a new directory or symlink all work. Against a real project-only machine, the swap exploit does not expose a canary
and the same exploit on a machine that shares the canary's directory does (`tests/podman_e2e.rs`, opt-in).

### 9.4 Stays manual

`up`, `down`, `build`, `run`, `exec`, `rm`, `cp`, compose changes, local Kubernetes cluster and kubectl operations, anything
touching the podman machine (including creating the project-only machine of 9.3). The agent tells you what to run. A later, separate option is an approval
prompt in the same terminal showing the exact command and the diff against the approved compose file.
It has not been prototyped.

## 10. MCP servers and tool caches

Measured (hb-ghd.7.5, `tests/mcp_offline.rs`, opt-in with `HB_MCP=1`): each server below answered an MCP `initialize` inside the hamster ball, started
by hb's offline launchers from hb's own cache after `hb warm`, in 1 to 2 s, and the proxy logged no connection at all except serena's refused ones.

| Server | Hosts `hb warm` needed | Offline after `hb warm` |
|---|---|---|
| time, fetch (`uvx`) | `pypi.org`, `files.pythonhosted.org` | yes |
| reddit, ripgrep (`@latest`), browsermap (`@latest`), sequential-thinking (`npx`) | `registry.npmjs.org` | yes |
| serena (`uvx --from git+https://github.com/oraios/serena@<full sha>`) | the registries, `github.com`, `api.github.com`, `raw.githubusercontent.com` | yes, with a full-revision pin (an unpinned source cannot start offline, even warm), `bind_ports` over several ports (its dashboard listens on the first free one from 24282 and other instances hold the first ones), `~/.serena` writable. While running it asks for `pypi.org` and `oraios-software.de` (version and news checks): refused and harmless |
| a package never warmed | n/a | fails offline with uv's or npm's own text; `hb run` and `hb doctor` say `run hb warm` |
| obscura, lean-ctx (a program of their own) | none | not looked at: nothing to warm |

- Agent presets list only the agent's own hosts. MCP servers are declared in `[mcp.<name>]` and each
  contributes its own run-time hosts (normally none).
- **Offline launchers (hb-ghd.7.2, D83).** When a declared server has a `command`, `hb` writes `uvx` and `npx` scripts into
  `<session>/bin`, first on the child's `PATH`. Each is `exec <real tool> --offline "$@"` with the tool's cache variables
  (`UV_CACHE_DIR`, `UV_TOOL_DIR`, or `npm_config_cache`) set for that call only. The real tool comes from `[env] tools`; a declared server that
  starts a bare `uvx` or `npx` that `[env] tools` does not list is a warning (`hb explain` kind `offline_launcher_unavailable`). So no registry is
  reachable from these two commands and `@latest` cannot drift. `uv sync`, `npm install` and a call by absolute path are untouched. The script
  `exec`s, so stdin, stdout, signals and the process are the tool's own: a wrapper that kept the tool as a child lost stdin (a background job
  in a non-interactive `sh`) or left the tool running after a TERM (measured). Before the `exec` it prints a hint naming `hb warm` to stderr when
  `<cache>/warmed` is missing; a package missing from a warmed cache keeps uv's or npm's own failure text.
- **`hb warm` (hb-ghd.7.3, D84).** For each declared server whose `command` is a bare `uvx` or `npx` (the only ones that reach a registry), `hb warm` runs
  one ball session through the same code as `hb run` (same files, environment and tools; the cache granted, its three variables set in the child's
  environment, no launcher scripts, so no `--offline`) with the proxy allowlist replaced by `pypi.org`, `files.pythonhosted.org`,
  `registry.npmjs.org`, the host of each `git+https://HOST/...` argument (`github.com` also brings `api.github.com` and `raw.githubusercontent.com`) and
  the server's `warm_net`. `net.allow` and `[mcp] net` are not in it; `internal_hosts` is kept. The ball runs `/usr/bin/perl` with a probe script that starts the
  server in its own process group, sends an MCP `initialize`, waits for the result (default 300 s), prints the last 20 stderr lines on failure, and
  ends the group. A success writes a stamp under `~/.local/state/hamster-ball/warm/` (digest of command and arguments, time, hb version; the floor
  denies the directory to the ball) and the marker `<cache>/warmed`. `hb run` warns before starting about each such server with no stamp or a stale one;
  `hb explain` shows the status. It needs an approved config and refuses inside a ball. An unpinned `git+` source cannot start offline even from a
  warm cache (uv must resolve HEAD): pin `@<full sha>`.
- **`hb doctor` (hb-ghd.7.4, D85).** For each server `hb warm` can warm it names: never warmed or warmed with other arguments; an argument whose package
  spec ends in a tag that is not a version or a range (`pkg@latest`, `@scope/pkg@next`; a bare name is not flagged, it is whatever the last `hb warm`
  cached); a `git+` source whose URL does not end in a full revision (`@<40 hex>` for uv, measured; `#<40 hex>` for npm, not measured offline), which uv
  cannot start offline even from a warm cache; and a launcher `[env] tools` does not list. It prints the server and the one flagged argument, bounded and
  escaped, with `user:password@` removed from a URL, never the other arguments. The exit code stays 0.
- **hb's own cache** is `~/.cache/hamster-ball/{uv,uv-tools,npm}`, made 0700 on the host and granted read-write through the profile's cache
  parameter, not through `fs.write`, so it is not a secrets-guard root (uv unpacks `certifi/cacert.pem` into its cache). It is never the
  user's `~/.cache/uv` or `~/.npm`: uv writes to its cache even offline (a read-only cache fails), so a shared one would be agent-writable
  and a planted package would run in the user's own `npx` later. `hb explain` shows the launchers and the cache (group `offline`).
- `hb warm` is the only command that may reach registries. It runs outside agent sessions.
- `uv` and other Rust tools need `com.apple.SystemConfiguration.configd`, which is in the base (section 4.5).
- `beads-mcp` is broken on the host (its Python interpreter is gone); unrelated to `hb`.

## 11. Credentials

Principle: the hamster ball holds only credentials the agent itself needs to reach its model provider.

- **Agent logins** live in each agent's state directory, which its preset allows (kiro-cli's token is in
  `~/Library/Application Support/kiro-cli`, pi's in `~/.pi/agent/auth.json`). Domain allowlisting limits where
  they can be sent. Accepted by the owner.
- **Host-side hooks (hb-ghd.6.1, D79)** run before the hamster ball starts, outside it, in your own base or presets only (4.2):

  ```toml
  [hooks.pre_run.bedrock]                       # name: lower case, digits, _ and -; hooks run in name order
  command      = ["~/tools/credential-process", "--profile", "p"]   # argv only, no shell; the program is absolute or ~/
  timeout_secs = 30                             # 1 to 300, default 30; a hook past it is killed with what it started
  format       = "aws_credential_process"       # optional; needs profile
  profile      = "p"                            # the AWS profile the agent selects
  outputs      = { MY_FILE = "out.txt" }        # optional: variable for the agent -> a file the hook wrote
  ```

  The hook runs with `HOME`, a system `PATH`, and `TMPDIR` and `HB_HOOK_DIR` set to its own 0700 directory
  `<session>/hooks/<name>`; no other variable, no input, and its output is never shown (nor any error that holds it).
  A non-zero exit, a timeout or output that does not fit its `format` ends the run before the agent starts, and names the
  hook. Files named in `outputs` must be regular files; `hb` sets them to 0600 and gives the agent their paths (a hook's
  variable wins over `[env] set`; two hooks cannot set the same one). With `format = "aws_credential_process"` `hb` itself reads
  the tool's JSON (Version 1, `AccessKeyId`, `SecretAccessKey`, optional `SessionToken`; characters a key never has are
  refused) and writes `config` (`[profile p]`, or `[default]`) and `credentials` there, and sets `AWS_CONFIG_FILE` and
  `AWS_SHARED_CREDENTIALS_FILE`. No converter program runs outside the sandbox. The whole session directory, hook files
  included, is removed at the end of the run and after a signal. Signals are held while a hook runs, so the time limit is
  what bounds it. A project that extends a user preset runs that preset's hooks, so the approval summary lists them.
- **claude on Bedrock**: a hook runs your `credential-process` on the host and writes a 0600
  `credentials`/`config` pair into a per-session directory. `hb` sets `AWS_CONFIG_FILE` and
  `AWS_SHARED_CREDENTIALS_FILE` to it, and removes the directory on exit.
  Measured: claude completed a Bedrock request with no access to `~/.aws` and no way to run the credential
  tool. Static `AWS_ACCESS_KEY_ID` variables do not work because claude's settings force `AWS_PROFILE`,
  and the AWS SDK then ignores them. Credentials last about 11 hours (read from the tool's output).
- **claude telemetry**: claude's `otelHeadersHelper` fails in the hamster ball and no telemetry is sent.
  The owner confirmed it is not required. Documented gap.

## 12. Network proxy

Built into `hb` (Rust, tokio). One listener on `127.0.0.1`, random port chosen by the OS, per session.

- Handles `CONNECT` (HTTPS) and plain HTTP forwarding. Decisions are by hostname from the request.
  Built in hb-ghd.3.1 (`src/proxy`): `ProxyHandle::start` binds `127.0.0.1:0` in the calling thread, so the port is known on return, and
  serves on its own thread with a single-threaded tokio runtime; the rest of `hb` stays synchronous. Dropping the handle aborts every open
  connection and joins the thread. At most 512 connections are served at once (more get `503`); `RLIMIT_NOFILE` is raised best-effort
  because each tunnel holds two sockets. The request head is limited to 16 KiB and 64 headers and must arrive in 10 s; resolving and each
  connect attempt get 10 s; an established tunnel has no time limit, so a long streaming response is never cut off. Bytes are copied with
  `copy_bidirectional` (8 KiB buffers; a half-close is passed on), so memory does not grow with the stream: a 1 GiB tunnel test grows
  resident memory by under 64 MiB.
- **Plain HTTP** is one request per connection (D71): the absolute-URI request is rewritten to origin form with our own `Host`, the
  proxy and hop-by-hop headers (and those named in `Connection`) are dropped, `Connection: close` is added, and bytes are copied until
  either side ends. No body is ever framed, so there is no request-smuggling state to desynchronise; a pipelined second request is only
  body bytes to the same, already allowed, upstream. A request with both `Content-Length` and `Transfer-Encoding` is refused. `https://`
  in an absolute URI is refused (use `CONNECT`).
- **Refusals** are HTTP replies with a one-line reason and an `X-Hb-Refusal` code: `not_allowed` 403, `ip_literal` 403, `bad_target`,
  `malformed`, `not_a_proxy_request`, `unsupported_scheme` 400, `too_large` 431, `head_timeout` 408, `unresolved` and `unreachable` 502,
  `timed_out` 504, `busy` 503. Address literals (`127.0.0.1`, `[::1]`, `2130706433`) are always refused in v1 (D71); an allowlist entry
  is a host name.
- Allowlist entries: exact host or `*.suffix`. Default is deny. Denials return `403` with a reason and are logged.
  `*.example.com` matches `a.example.com` and `a.b.example.com` but not `example.com`, and is label-boundary safe.
  Hosts are strict LDH (a `_` in a label is rejected), punycode only, and the last label must start with a letter
  (so `2130706433` and `0x7f.1` are rejected). **Wildcards over protected suffixes are rejected at config time**:
  a wildcard whose suffix is on the public suffix list, or is an ancestor of any entry on it, is an error
  (`*.github.io`, `*.co.uk`, `*.cloudfront.net`, and also `*.amazonaws.com`, which is not itself listed but
  covers every `*.s3.amazonaws.com` tenant). List exact hosts instead. The list is vendored (MPL-2.0, unmodified)
  and compiled into a protected set by `build.rs`; no runtime network is used.
- **Rules and ports.** An allow entry is `host` or `host:port` and means one (pattern, port) rule; `host` is `host:443`. Rules from every
  file are unioned, so `x.com` and `x.com:8443` allow both ports. A listed host on another port is `port_not_allowed` and the reply says
  which entry to add; an unlisted host is `not_allowed` whatever the port (D72).
- **Addresses.** The proxy resolves names itself and connects to the address it chose (no second lookup). It classifies every address
  (`proxy::classify`; IPv4-mapped, NAT64 `64:ff9b::/96` and 6to4 addresses by the IPv4 address they carry):
  *never allowed*: loopback, `0.0.0.0/8` and `::`, link-local (including 169.254.169.254), multicast, `240/4`, `192.0.0.0/24`
  (includes the NAT64 probe address 192.0.0.170), documentation ranges, Teredo and any IPv6 outside `2000::/3` that is not one of the
  carrying forms; *internal*: RFC 1918, `fc00::/7`, `fec0::/10`, `100.64.0.0/10` and `198.18.0.0/15`, allowed only for hosts in
  `net.internal_hosts`; everything else is global. Forbidden addresses are dropped and the rest tried; if none is left the reply names the
  class and, for an internal address, the exact line to add (D73).
- **Auth.** The proxy URL carries a random per-session credential (`http://hb:<token>@127.0.0.1:<port>`; 128 bits from the OS, 32 hex
  digits) so other local processes cannot use the proxy. It is checked before the allowlist and before any lookup, in constant time, so a
  caller without it learns nothing about the allowlist; a missing or wrong credential, or two credential headers, is `407` with
  `Proxy-Authenticate: Basic realm="hb"` (curl and git only send credentials after that challenge). The agent holds the token in its
  environment, so it protects against other processes, not against the agent. Measured with the real proxy (`tests/proxy_agents.rs`, opt-in): claude 2.1.328,
  pi 1.6.0, opencode 1.2.0 and kiro-cli 3.5.0 all send Basic credentials from the URL on their first request; one opencode request
  (a `git`-style client) arrived without and was retried after the challenge.
- **Lifecycle (hb-ghd.3.3).** `session::run` starts the proxy for every run, even with an empty allowlist (D71), before the profile is rendered
  (the profile names its port) and stops it after the child has ended, so a refusal is an HTTP `403` with a reason and not a refused
  connection. The child's environment gets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lowercase forms, all the same credentialed URL,
  and `NO_PROXY=no_proxy=localhost,127.0.0.1`: the policy's `loopback_ports` are reached directly because the profile allows nothing else on
  loopback and the proxy refuses `localhost`. These names are reserved: no config can set or pass them. A new token and port per run.
- **Closed loopback ports.** At start `hb` connects to each `net.loopback_ports` entry from outside the ball (IPv4 and IPv6 loopback, 250 ms) and
  warns, without failing, which are not listening (`net.loopback_ports ports 3030, 5432 are not listening; start the service or remove the
  port`). The probe sends nothing, but a service may log the connection. `hb explain` shows each port with its origin.
- **What you see (D75).** `--log-denials` includes the proxy's refusals as `hb: denied: proxy refused host:port code (reason)`; `--log-proxy` shows
  every connection as `hb: proxy: allowed host:port up=N down=M` or `refused ...`. Both follow the denial rule: live when stderr is redirected,
  after the run on a terminal (capped at 1000 lines). A run that had refusals and no `--log-denials` ends with `warning: the proxy refused N
  connections to M hosts; run with --log-denials to see them`; `--no-proxy-summary` hides it. A `407` is part of the credentials handshake
  (curl and git) and counts as no refusal; it appears in `--log-proxy` only.
- Measured: kiro-cli, pi, claude and opencode all honor these variables. A direct connection, and DNS
  resolution, fail inside the hamster ball. A connection to another loopback port fails.
- Loopback connections to the hamster ball's own listeners are denied by default (measured). Only
  `net.loopback_ports` are reachable.
- **Audit.** One event per connection (`AuditEvent`: host and port when the request named a valid one, served or refused with the code and
  reason, bytes each way). No headers, no bodies, no token: nothing from the request but the validated host and port is recorded. A served
  connection is recorded when it ends, and also when the run ends first, with the bytes that had crossed (hb-ghd.3.5: an agent's
  keep-alive tunnels are usually still open then, and were lost before). Events go to an optional sink; hb-ghd.3.3 connects it to `--log-denials` (refusals), `--log-proxy` (everything) and a one-line end-of-run
  summary of refusals that `--no-proxy-summary` hides.

### 12.1 Corporate networks

Measured on a corporate network with a TLS-inspecting client tunnel (macOS 15.7; nothing about it is vendor-specific in `hb`): no system proxy or
PAC; direct egress through the tunnel (`utun4`); split DNS (three corporate domains go to an internal resolver, the rest to the
tunnel's); corporate internal names such as an Artifactory or Confluence host, and some public ones (`github.com`, `api.github.com`)
resolve into `100.64.0.0/10`, which the tunnel hands out. A name may also return one tunnel address and several public ones.

| Need | Support |
|---|---|
| TLS inspection (re-signed hosts) | yes: `tls.system_trust`, `tls.extra_ca_files` (4.5) |
| Split DNS, search domains | yes: the proxy resolves with the system resolver |
| Internal hosts that resolve to private, unique-local or tunnel addresses | yes, per host: `net.internal_hosts` (only your own files) |
| IPv6-only networks with NAT64 | yes: the embedded IPv4 address is classified |
| Explicit HTTP proxy or PAC required for egress | **no**: the proxy connects directly (D74) |
| NTLM or Kerberos proxy authentication | no |

`net.internal_hosts` lists host patterns (exact or `*.suffix`, like `net.allow`) whose names may resolve to internal addresses. It is a
per-host list because a global switch would let any allowed name that rebinds into the corporate private-app space reach it. Only
your own files may set it, in any form, even `[]`; a project file that does is an error naming the file. On the measured network you
would list `github.com`, `api.github.com` and `*.in.<company>.com` once in the base config. Loopback, link-local, multicast and the
reserved ranges stay refused for listed hosts.

Not supported, and what `hb` does about it (D74): an upstream proxy would resolve names itself, so `hb` could no longer pin the address or enforce the
rebinding checks; it is not built until there is a concrete network to test it against. A connection failure is reported as `unreachable` or
`timed_out` with the host and port. `hb doctor` lists the HTTP, HTTPS, SOCKS, FTP, PAC and auto-discovery settings the system has on (from `scutil --proxy`;
host and port only, a password in a PAC URL is dropped) and says that `hb` does not follow them (D74, D90).

## 13. Agent presets (initial contents)

All measured under the deny-default profile with proxy-only network. Home-relative paths shown.

| Agent | Read-only | Read-write | Hosts (own) | Notes |
|---|---|---|---|---|
| kiro-cli 3.5.0 | none (its binary needs no read grant) | `~/.kiro`, `~/Library/Application Support/kiro-cli` except `node`, `bun`, `tui.js`, `bunfig.toml` and `kas` (`deny_write`: a plain `kiro-cli` runs them outside the sandbox; kiro cannot self-update its agent server inside hb) | `app.kiro.dev`, `runtime.us-east-1.kiro.dev`, `management.us-east-1.kiro.dev`, `telemetry.us-east-1.kiro.dev`, `client-telemetry.us-east-1.amazonaws.com`, `cognito-identity.us-east-1.amazonaws.com` | Probes `~/.local/bin` for write access; denial is harmless. Needs system trust (the corporate proxy re-signs `kiro.dev`). Measured in hb-ghd.3.5: the 3.3.0 spike also listed `desktop-release.q.us-east-1.amazonaws.com` (update check) and a read of `~/.local/bin/kiro-cli`; 3.5.0 needs neither. Its MCP servers, `~/.gitconfig` and FSEvents are denied harmlessly. |
| pi 1.6.0 | none (`env.tools = ["node"]` makes the Node install readable) | `~/.pi/agent`, except `bin` and `install` (`deny_write`: they hold the launcher a plain `pi` runs outside the sandbox) | none: the provider is user config (`net.allow` for a remote gateway, `loopback_ports` for a local one such as `localhost:18089`, `tls.extra_ca_files` for a private CA) | Measured in hb-ghd.3.6 with provider `here` (a remote gateway behind a self-signed CA). Without the CA file pi fails with `DEPTH_ZERO_SELF_SIGNED_CERT`. Its update check (`install/update.lock`) and `~/.agents/skills` reads are denied harmlessly. A loopback gateway was reached directly with `loopback_ports` (a stub on 18089 saw pi's requests). |
| claude 2.1.328 | `~/.local/share/claude`, `~/.local/bin/claude` | `~/.claude`, `~/.claude.json`, `~/.cache/claude`, `~/.local/state/claude` | Bedrock: `bedrock-runtime`, `bedrock`, `sts` in `us-east-1` | Credentials via a host hook in the user base (section 11), not in the preset. `CLAUDE_CODE_TMPDIR={session_dir}` keeps claude out of the shared `/private/tmp`; `DISABLE_AUTOUPDATER=1` and the read-only install keep the updater idle (`api.anthropic.com` and `downloads.claude.ai` are not requested in a headless Bedrock run). Sandboxed runs wait about 20 s on the OTEL and `awsAuthRefresh` helpers. |
| opencode 1.2.0 (Homebrew) | `~/.config/opencode`, and from Homebrew `Cellar`, `opt`, `lib`, `etc/openssl@3` (not all of `/opt/homebrew`, which holds `var`; `~/.bun/install` is not needed) | `~/.local/share/opencode`, `~/.cache/opencode`, `~/.local/state/opencode`; `deny_write` on what a plain opencode runs: `~/.cache/opencode/{node_modules,package.json,bun.lock}` and `~/.local/share/opencode/bin` | `models.dev`, `opencode.ai` (re-signed by the corporate proxy; system trust) | The config directory can be read-only (opencode skips its dependency install). The `securityd` and preference denials do not stop TLS. MCP servers in the user's opencode config are not part of the preset: `npx`/`uvx` ones fail, remote ones are refused (M7). Run opencode once outside hb after an install or update (default plugin install needs npm). Loopback bind for its in-process server needs `bind_ports`. |
| codex, omp | | | | **Not installed here; no preset until tested.** |

Presets are hand-written. Measured: Seatbelt denial logs are incomplete (40 of 40 reported for `sh` and
Python, 32 of 40 for Node), so no allow rules are generated from logs. `hb run --log-denials` shows
denials as hints for you to read (7.2).

### 13.1 Preset format and conformance (hb-ghd.3.4)

A built-in preset is an ordinary config file (section 4) named `agent/<name>`, kept in `presets/agent/<name>.toml` and compiled in with
`include_str!` through one line in `EMBEDDED` (`src/config/builtin.rs`); a test fails for an unregistered file, an unsorted table or a
preset that is not valid config. It lists only what the agent needs for itself: its install tree (`fs.read`), its own state (`fs.write`,
no wider than needed), its own hosts (`net.allow`, `host:port` for a port other than 443), `env.tools`, and a header with the version
and date it was measured against. Provider hosts, MCP hosts, credentials and the user-only settings are not in one. `presets/README.md`
is the how-to.

The **conformance harness** (`hamster_ball::conformance`, behind `test-support`; `tests/conformance.rs` is the opt-in runner) proves a
preset against the real agent. For each agent it builds a throwaway project that extends only `agent/<name>`, runs the agent's one
question under the real profile and proxy, and returns a verdict:

| Agent | Command | Passes when |
|---|---|---|
| kiro-cli | `chat --no-interactive "Reply with the single word OK"` | exit 0 and `OK` in the output |
| pi | `--provider here --model claude-haiku-4-5 -p "..."` | exit 0 and `OK` in the output |
| claude | `-p "..." --max-turns 1` | a served connection to `bedrock-runtime.*`, and `OK` in the output if it exits 0 (a failed exit is not judged: the account may deny the model) |
| opencode | `run --format json -m opencode/big-pickle "..."` with a made-up `OPENCODE_API_KEY` (set by the harness) | exit 0 and `Invalid credential` in the output: a model request goes through the proxy and `opencode.ai` refuses the key (HTTP 401). No provider is needed, no free-tier request is spent, and it takes about 7 s |

Every connection the proxy refuses (other than the credentials challenge) fails the check and names the host: the agent asked for
something outside the allow set in force, which is the preset plus what the runner put in `HB_CONFORMANCE_PROJECT`. On a failure the
verdict carries the agent's last lines and every denial as hints. The home directory is the real one, since the agent's login is there;
the user's own `~/.config/hamster-ball` is not read, a private user config holds `HB_CONFORMANCE_BASE` (default: system trust on), so a
result depends on the preset (D76). Each agent runs in its own process group under a wrapper that ends the whole group at the time limit
(`HB_CONFORMANCE_TIMEOUT`, default 180 s), because an agent's children would otherwise hold the output open. Nothing runs without
`HB_CONFORMANCE=1`; an agent that is not installed, or has no preset yet, is skipped. The checks spend real model requests.

## 14. Architecture (Rust)

One crate with a library and a `hb` binary. Conventions: `snafu` errors, `strum` enums, newtypes for domain
values, `ABOUTME` headers, TDD, `claims` and `pretty_assertions` in tests.

| Module | Responsibility |
|---|---|
| `config` | Parse TOML (`serde`), resolve `extends`, merge, produce a `Policy` with provenance |
| `policy` | Pure validated value types: `CanonicalPath`, `HostPattern`, `Port`, `EnvName`, `ContainerLabel`, `Argv`, `McpName`, `PathPattern`. No I/O |
| `system` | The only OS access besides config reading: `PathResolver` (filesystem), `HomeDir::from_environment` (passwd and `$HOME`) |
| `floor` | Compiled-in rules |
| `approval` | Closure hash, store, grant summary, prompt |
| `seatbelt` | Policy to SBPL text plus `-D` parameter list. Pure function, golden-file tested |
| `proxy` | CONNECT and HTTP proxy, allowlist, address checks, logging |
| `ctl` | `hb ctl`: request protocol, fixed argv, scope, preflight (allow-list over `podman inspect`), runtime isolation check, bounded command runner, launchd status projection, handler, unix-socket broker, client, start-up service |
| `warm` | `hb warm`: probe ball, hosts, stamps, the MCP part of `hb doctor` |
| `explain` | `hb explain`: report, JSON and text, per-path query |
| `conformance` | The opt-in agent harness (`HB_CONFORMANCE=1`) |
| `guard` | Secret patterns, git-tracked detection, doctor scan |
| `session` | Per-session directory (0700), env construction, hooks, offline launchers, `hb ctl` wiring, guardian process, pty, spawn, cleanup |
| `cli` | `clap` commands |

Pure core, effects at the edges: `policy` is pure; `system` and the file loading and discovery in `config` hold the I/O (reading files, `realpath`, passwd); `seatbelt` is a pure function of the resolved policy.

## 15. Open items (decide or verify before or during implementation)

1. ~~**Terminal isolation** (7.3)~~ Done in hb-ghd.2.4 (D65): the pty is allocated and `TIOCSTI` is measured to be closed by the missing `hid-control`. Still open under it: whether an agent's TUI behaves on the pty is checked per agent in M3 (3.5, 3.6 and the claude and opencode presets).
2. ~~**Proxy credentials in the URL** (12)~~ Measured (hb-ghd.3.2): all four accept them and send them on the first request; see 12.
3. ~~**Narrow `/private/tmp`**~~ Done in hb-ghd.6.2 (D80): `CLAUDE_CODE_TMPDIR={session_dir}` moves `claude-<uid>` and `cc-socks` into the run's private directory; no `/private/tmp` grant.
4. **`.git/config` write-deny** (6): blocks `git push -u`. Keep as default and revisit after dogfooding.
5. **`~/.kube`**: how a project with a local cluster gets a project-scoped kubeconfig, and the cluster's API port.
6. ~~**Preflight for `hb ctl`**~~ Done in hb-ghd.8 (D88, D89): an allow-list, a no-symlink walk of every bind source, a volume check and runtime isolation; measured against real podman.
7. ~~**Claude updater**~~ Done in hb-ghd.6.2 (D80): `DISABLE_AUTOUPDATER=1` is the name the 2.1.328 updater reads; a headless Bedrock run made no update request with or without it, so the setting is unproven by traffic and the read-only install is what stops an update.
8. ~~**A project's database port**~~ A port mismatch between one project's justfile and its probes. Not a change for this repo; reported to that project.
9. Presets for codex and omp once installed.
10. **AppleEvents and LaunchServices** are measured and closed (16.1): no event reaches a running application and `open -a` starts nothing.
    **launchd** is measured (4.6): job creation is refused from inside, starting and disabling existing jobs is not, so `launchctl` is off unless
    the user's own config turns it on (D70).
    Reaching user keychain items through `securityd` is measured (section 6, D62): not possible without a pre-sandbox handle. Still
    open: the data-protection keychain and a system proxy or PAC actually being followed (`configd` gates the settings; see 4.5).
11. ~~**Nested standalone repositories** (D46)~~ Done (D90): `hb doctor` lists repositories below a write grant, hook managers and `core.hooksPath`. The floor still does not protect them.
12. ~~**Output with no pty** (7.3)~~ Done (D67): a stdout or stderr that is a terminal goes through a pipe and the same filter when there is no pty, and the exit fence runs after the run. The agent then sees output that is not a terminal.
13. ~~**System proxy or PAC** (4.5, 12.1, D74)~~ Done (D90): `hb doctor` lists the system's proxy settings and whether the agent can read them. Following an upstream proxy or PAC is still not built.
14. **Container egress** (9.3): a container the owner started has unrestricted network access, which the agent can use through `hb ctl` operations that run it. Measured, not mitigated in v1 (section 17).
15. **Secrets in `hb ctl logs`** (9.3): container logs reach the agent, capped at 20 KB, and may hold secrets. Not filtered.

## 16. Test plan

- **Unit**: config parsing and merge (union, deny-wins, no-loosening, hooks only from allowed layers),
  path canonicalization, host pattern matching, closure hashing, profile golden files.
- **Property**: merge is monotone (adding a layer never removes a deny); profile never contains an unescaped path.
- **Integration (macOS, real `sandbox-exec`)**: the spike probe matrix as automated tests, including secrets-guard
  deny cases (13: 4 direct reads and 9 bypass attempts), pin swap attempts (7 cases), symlink-mount attack, direct network and DNS blocked,
  other-loopback-port blocked, env empty.
- **Proxy**: allowlist, rebinding refusal, port restrictions, auth token, large streaming bodies.
- **Agent conformance (opt-in, needs installed agents and logins)**: one non-interactive prompt per preset;
  pass means a response through the proxy with no errors caused by the hamster ball. claude and opencode have different
  pass criteria (Bedrock request; reaches the model step).
- **`hb ctl`**: unit tests of the request table, argv, scope, preflight, isolation, status projection, handler order and runner; `tests/mount_pins.rs` and `tests/ctl_broker.rs` under the real `sandbox-exec` with a fake `podman`; opt-in `HB_PODMAN=1 tests/podman_e2e.rs` (real podman; `HB_PODMAN_DIR=<dir>` for a machine that shares only `<dir>`) and `HB_LAUNCHD=1 tests/launchd_e2e.rs` (a throwaway launchd job).

### 16.1 Probe matrix (hb-ghd.2.5)

Seatbelt is undocumented and changes between macOS releases, so each claim the design makes about what the ball blocks or allows
is a test that runs a real program under the real `sandbox-exec`. `tests/probe_matrix.rs` goes through `session::run`
(`tests/common`: `run_in_hb`, `sh_in_hb`); the older profile-level tests in `tests/seatbelt_render.rs` render with the real `render()` and
edit the profile text for their controls. Every probe has an allowed twin in the same world or an unsandboxed control, and a test that
cannot run (no login session, no DNS) prints `SKIP:` with the reason. `HB_REQUIRE_SANDBOX=1` turns "already sandboxed" from a skip into a failure.
**After a macOS upgrade, or any change to the profile: `HB_REQUIRE_SANDBOX=1 cargo test --all-features`.**

| Claim | Test (`tests/` file, function) |
|---|---|
| `~/.ssh`, `~/.aws`: no tool reads them, metadata included. `~/Documents`: contents refused, metadata visible (D51) | `probe_matrix` `credential_and_personal_directories_cannot_be_read_by_any_tool_while_the_project_can` |
| `stat`, `ls -ld`, `test -e`, `xattr -l` on a floor path under a granted ancestor; the shorter deny form would leak (control) | `seatbelt_render` `a_granted_ancestor_cannot_reach_credentials_beneath_it_and_stat_does_not_leak`, `control_the_shorter_read_wildcard_deny_form_does_leak_stat_under_this_baseline` |
| `~/.local/bin`, `~/.cargo/bin`, `~/.zshrc` unwritable beside writable siblings; project write works | `probe_matrix` `the_floor_keeps_the_path_directories_and_shell_startup_unwritable_beside_writable_siblings`; `seatbelt_render` `a_missing_floor_path_under_a_grant_cannot_be_created_in_any_case` |
| Symlinked `/tmp`: working directory and grants spelled through the link | `probe_matrix` `a_tree_under_the_symlinked_tmp_works_whether_a_grant_is_spelled_through_the_link_or_not` |
| Names: quotes and backslash; newline; case variant; NFD; regex metacharacters | `seatbelt_render` `a_directory_name_with_quotes_parentheses_and_a_backslash_is_granted_without_changing_the_profile`, `regex_metacharacters_in_a_denied_base_match_only_themselves_under_the_real_sandbox`; `probe_matrix` `a_file_name_with_a_newline_works_in_the_project_and_a_config_path_with_one_is_refused`, `a_case_variant_of_a_floor_path_is_denied_and_one_of_an_allowed_path_is_not`, `an_nfd_spelling_of_a_name_is_the_same_directory_for_a_grant_and_for_a_deny` |
| Network: direct and unlisted loopback port refused, proxy and listed port reachable, no proxy means none | `seatbelt_render` `only_the_proxy_and_listed_loopback_ports_are_reachable`, `without_a_proxy_slot_no_network_is_reachable_at_all` |
| DNS through the system resolver fails, `/etc/hosts` answers | `probe_matrix` `name_resolution_through_the_system_resolver_fails_while_the_hosts_file_still_answers` |
| Unix sockets: only the `hb ctl` socket | `seatbelt_render` `the_ctl_socket_is_reachable_and_no_other_unix_socket_is`, `a_broad_network_allow_added_earlier_still_cannot_reach_a_container_socket` |
| Later rule wins (template re-allow after guard deny); ancestor listing works, a sibling's contents do not | `seatbelt_render` `the_template_reallow_reopens_a_guard_deny_which_a_wildcard_allow_could_not`, `a_granted_ancestor_cannot_reach_credentials_beneath_it_and_stat_does_not_leak` |
| Empty environment; descriptors 0 to 2 only | `session_run` `the_child_environment_is_exactly_the_allowed_set_and_no_parent_token_reaches_it`, `after_the_close_the_child_has_only_the_three_standard_descriptors` |
| `ps`, `sudo` cannot start (setuid); own child can be signalled, an outside process cannot | `seatbelt_render` `setuid_programs_do_not_run`, `a_process_can_signal_its_own_children_but_not_other_processes`; `probe_matrix` `sudo_cannot_start_while_an_ordinary_program_can` |
| Pasteboard tools, LaunchServices (`open -a`, application lookup) and Apple Events refused | `probe_matrix` `the_pasteboard_cannot_be_read_or_written_by_the_command_line_tools`, `launchservices_shows_no_applications_and_open_cannot_start_one`, `an_apple_event_cannot_be_delivered_to_a_running_application` |
| `/dev/fd` and the standard stream nodes work | `seatbelt_render` `the_baseline_runs_ordinary_tools_and_the_standard_stream_nodes` |
| Session directory is 0700 and gone after exit, SIGINT, SIGTERM, SIGHUP | `session_run` `tmpdir_is_a_private_0700_directory_the_child_can_use_and_it_is_gone_afterwards`; `signals` `each_of_int_term_and_hup_sent_to_hb_reaches_the_child_and_the_session_dir_is_removed` |
| TLS trust and the keychain floor | `seatbelt_tls`, `tls_handshake`, opt-in `tls_inspection` |
| `launchctl` cannot run unless the user's own config turns it on; a project cannot turn it on; a copy is killed; a job cannot be created from inside; with it on, a job that is not running can be started and a running one cannot be touched (opt-in) | `probe_matrix` `launchctl_cannot_run_unless_the_users_own_config_turns_it_on`, `a_project_file_cannot_turn_launchctl_on`, `a_job_cannot_be_created_from_inside_even_when_launchctl_is_on`, `with_launchctl_on_the_agent_can_start_a_job_that_is_not_running_but_not_restart_or_unload_a_running_one` (`--ignored`) |
| The `xcrun` cache is readable, never writable | `seatbelt_render` `the_git_shim_reads_the_xcrun_cache_quietly_and_the_cache_stays_unwritable` |

The Apple Event probe uses Finder because it is the one application nearly always running in a login session. The test sends an event
with no parameters (`core/getd`), so the target changes nothing. Measured: outside the ball the event is delivered; inside it fails with
`-600` (no such process), and still fails with every `mach-lookup` and `process-info` allowed, so delivery depends on much more than one
missing rule. LaunchServices is probed with `lsappinfo`, which only asks: it lists no applications inside the ball. (An AppleScript
`path to application "X"` looks harmless but starts the application when run outside, so the matrix does not use it.)

## 17. Alternatives considered

| Option | Why not |
|---|---|
| Wrap `srt` (Anthropic Sandbox Runtime) | Node dependency; JSON with no inheritance or floor; we want approval, secrets guard and ctl. Its design (proxy-mediated network, per-session proxy) is adopted here. |
| Container or VM per agent | Stronger isolation, but agents, MCP servers and your toolchains live on the host, and podman on macOS cannot restrict container egress (measured). Revisit for hostile-agent use. |
| Keep `sb` and extend the shell script | Shell cannot parse layered TOML safely, or implement the proxy and broker. |
| Reuse `sandbox.py` | Python and tied to the supervisor's workdir layout. Its profile-generation ideas are reused. |

`sandbox-exec` is deprecated by Apple but is what Codex, Claude Code (`srt`) and Chrome use. The risk is
accepted. All Seatbelt use is isolated in the `seatbelt` module so a replacement backend is possible.

## 18. Build plan

The milestones, each ending with passing tests (all built):

1. Repo scaffold, `config` + `policy` + `floor` + `hb explain`. (No CI config was added; the gates are run by hand: see the README's Development section.)
2. `seatbelt` generation + `hb run` + environment + paths; integration probe matrix.
3. `proxy` and network policy; agent presets for kiro-cli and pi.
4. `approval`, `hb approve`, project-file write-protection.
5. `guard`, `hb doctor`.
6. claude and opencode presets, hooks, TLS settings.
7. `hb warm`, MCP server handling.
8. `hb ctl`, preflight and pinning.

Tracked in beads (stealth mode, prefix `hb`) as epic `hb-ghd`. Milestones 1, 2, 3, 6 and 8 became child epics (`hb-ghd.1`, `.2`, `.3`, `.6`, `.8`) with real child tasks; milestones 4, 5 and 7 are tasks (`hb-ghd.4`, `.5`, `.7`). The planned ninth "open-items closeout" milestone was dissolved: each unverified item (section 15) is a task inside the epic that owns it (pty: `hb-ghd.2.4`; proxy credentials: `hb-ghd.3.2`; `/private/tmp` narrowing and claude updater: `hb-ghd.6.2`; `hb ctl` preflight: `hb-ghd.8.2`).

## 19. Decision log

| # | Decision | Owner answer |
|---|---|---|
| D1 | Threat model: mistakes plus prompt injection and exfiltration | agreed |
| D2 | macOS only | agreed |
| D3 | Rust, one `hb` binary, no code in projects | agreed |
| D4 | Project config approved by hash | agreed |
| D5 | Projects add allows only; base deny always wins | agreed |
| D6 | Proxy built into `hb` | agreed |
| D7 | Agents' own logins visible in the hamster ball | accepted |
| D8 | Agent presets list only the agent's hosts; MCP servers declared separately and run offline | agreed |
| D9 | Host-side hooks only in user base and presets | agreed |
| D10 | TLS: `system_trust` plus `extra_ca_files`; no interception | agreed |
| D11 | No log-based learn mode; hand-written presets with conformance tests | agreed |
| D12 | Presets for the four installed agents; none for codex and omp yet | agreed |
| D13 | Paths canonicalized; env cleared; trust-store services in base | agreed |
| D14 | Directory-listing reads of ancestors in the base | agreed |
| D15 | Loopback only to listed ports | agreed |
| D16 | claude OTEL telemetry not required | confirmed |
| D17 | Containers: floor deny; tier 1 connect-only; tier 2 `hb ctl`; lifecycle stays manual | agreed |
| D18 | Secrets guard on by default; templates editable; tracked files skipped; exceptions user-level only | agreed |
| D19 | Project name `hamster-ball`; binary stays `hb`; GitHub `dmrolfs/hamster-ball`. It was private until the names of the owner's own projects were replaced with neutral examples (D91); it is now public | chosen by owner (name); public by owner decision |
| D20 | User config and state live under `~/.config/hamster-ball` and `~/.local/state/hamster-ball` (not `sandbox`, which the old `sb` and Linux setup already use as `~/.sandbox`) | change made while renaming; pending owner review |
| D21 | Binary is `hb` (not `sb`); the project config file is `hamster-ball.toml` (not `sandbox.toml`); "sandbox" becomes "hamster ball" in this repo's prose. Kept as-is: Apple's `sandbox-exec`, `sandbox.py`, Anthropic's "Sandbox Runtime", the legacy `sb` script, another supervisor tool's own sandbox | owner feedback; file name `hamster-ball.toml` is my choice, pending review |
| D22 | Relative filesystem grant paths resolve against the project root in every layer (scoped to grants by D37; `extends` paths resolve against the containing file) | agreed |
| D23 | `fs.read`/`fs.write` grants (and the project root) that are `/`, `$HOME`, an ancestor of `$HOME`, or shallower than two components are rejected in every layer | agreed |
| D24 | No `hamster-ball.toml` is a typed `NoProjectConfig` error; no fallback to the cwd | agreed |
| D25 | Config files read once, capped at 256 KiB and 4096 entries per list; exact bytes kept for hashing | agreed |
| D26 | Glob deny patterns are a `PathPattern` type (resolved base plus validated glob tail) | agreed |
| D27 | Wildcard hosts are rejected when the suffix is a public suffix or an ancestor of one; list vendored, set generated by `build.rs` | agreed (stricter than the first proposal, which missed `*.amazonaws.com`) |
| D28 | Home from the passwd database, `HomeError::Mismatch` on disagreement with `$HOME`; `hb` refuses to run as root | agreed; `sudo -E` and nix `--pure` untested |
| D29 | Error `Display` never interpolates `{source}`; `main` prints chains with `snafu::Report`. The `{source}` examples in the owner's `rust/GUIDELINES` and the `snafu-strum-refactoring` skill were an error to follow | owner decision |
| D30 | `hb-ghd.1.1` promoted to an epic with five children (11 days; M1 is now 17 days) | agreed |
| D31 | `discover` requires the config file and root directory to be owned by the real uid and not world-writable; group write is allowed | review finding H2 (hb-alt); ownership-only rule chosen over also requiring roots under `$HOME`, to keep projects outside home usable; confirmed by owner |
| D32 | `ctl.label` must be `key=value` with a non-empty value from a restricted alphabet (a bare key or empty selector would widen `hb ctl`'s scope); hooks and MCP commands are validated argument vectors (non-empty program, no NUL, bounded); `extends` and `guard.exceptions` are form-checked text until M1.2 and the guard define their meaning; `mcp.<name>` names match `[A-Za-z0-9][A-Za-z0-9_-]{0,63}` | review finding H1 and gap 6 (hb-alt); confirmed by owner |
| D33 | A differing `ctl.label` across files is an error (amends 4.2's "highest layer" scalar fallback) | owner, hb-ghd.1.2 |
| D34 | `fs.deny_read` also denies write-class access | owner, hb-ghd.1.2 |
| D35 | `tls.system_trust`: any `false` wins; unset in every file is unset (the compiled default is `false`; the base template sets `true`) | owner, hb-ghd.1.2 |
| D36 | Hooks and `guard.exceptions` are accepted only from files that physically are the user's own or built-in (amends the AC5 wording, which named only the project) | owner, hb-ghd.1.2 |
| D37 | Relative `extends` paths resolve against the containing file's directory; D22 is scoped to filesystem grants | owner, hb-ghd.1.2 |
| D38 | A preset name that is both built-in and a user file is an error naming both | owner, hb-ghd.1.2 |
| D39 | A missing base is an error; `hb init` creates one (0600, never overwrites); `XDG_CONFIG_HOME` is ignored | owner, hb-ghd.1.2 |
| D40 | A user preset symlinked outside the config directory is classified by where it really is: it loses hook rights and is approved and hashed like any other writable file | owner, hb-ghd.1.2 |
| D41 | The floor protects `.git` by classification (directory, `gitdir:` file, symlink, missing), parses the untrusted pointer safely, and adds unlink pins on every ancestor of a protected path that a write grant reaches; enclosing repositories get the same treatment | owner, hb-ghd.1.3; both bypasses measured (rename of `.git`, rename of a closure file's directory) |
| D42 | A `deny_connect` effect covers container sockets; section 6's "podman socket directory" becomes the named paths plus `<per-user temp dir>/podman` | owner, hb-ghd.1.3; measured: a file deny does not stop `connect()` |
| D43 | Floor additions: persistence and code-running tool config (write-deny), credential stores, history and browser vendor directories (read+write deny), `~/.npmrc` read+write deny | owner, hb-ghd.1.3 |
| D44 | `PATH` is read once; only absolute entries count; entries inside the project are not write-denied; entries containing the project, home or a write grant are covered for direct children only | owner, hb-ghd.1.3 |
| D45 | Program directories also include `/opt/homebrew/{bin,sbin}` and `/usr/local/bin`; `hb` itself is write-denied; symlink targets of program-directory entries under a write grant are write-denied (cap 256) | owner, hb-ghd.1.3 |
| D46 | Standalone repositories nested below the project root stay unprotected | owner, hb-ghd.1.3 |
| D47 | `XDG_STATE_HOME` is ignored; approvals live in `~/.local/state/hamster-ball` (amends section 5 and hb-ghd.4) | owner, hb-ghd.1.3 |
| D48 | Floor path-resolution errors fail closed with a `FloorError` naming the rule; only `PATH` entries and enclosing repositories degrade to warnings. A `Policy` has no `Default` and `Floor` has no public constructor | owner (recommendation), hb-ghd.1.3 |
| D49 | `hb explain` ships `--format json` (`schema_version: 1`, typed structs, bidi-escaping formatter), `--show-args`, `--path` and a `grant_shadowed_by_floor` warning; `env.set` values are never shown; `clap` and `serde_json` are dependencies | owner, hb-ghd.1.3 |
| D50 | The in-project closure files' read-only rule belongs to the floor (hb-ghd.1.3), not to the approval task; `FloorRule` provenance is the `FsDecision::DeniedByFloor` variant, not a `Source::Floor` | owner, hb-ghd.1.3 |
| D51 | Seatbelt resolves the most specific operation first, so floor and guard denies name their operations explicitly; section 7.1 baseline is `(version 1)` + `system.sb` (not `system.hb`) with the measured additions (`signal same-sandbox`, `ipc-posix-sem`, `/dev/fd` and std nodes, `/private/var/select`, CLT read) and no explicit `sysctl-read`; global `file-read-metadata` is kept and its real leak documented | owner, hb-ghd.2; measured |
| D52 | The profile text contains no config-derived string; the render is a pure function of `(Policy, RenderInputs)`; `Loaded` is built after the last interactive step instead of "re-resolving at the last moment"; `hb profile` prints a placeholder `PROXY` param (`localhost:1`; this macOS rejects port 0); a render budget replaces the 4096-rule cap | owner, hb-ghd.2 |
| D53 | Signals, pty and cleanup stay under `unsafe_code = forbid`: nix (`signal`, `term`, `process`, `event`) plus rustix, a hidden `hb __child` re-exec helper that clears the signal mask, kqueue `EVFILT_SIGNAL`, and `FD_CLOEXEC` on the pty master | owner, hb-ghd.2 |
| D54 | The pty is hygiene and job control; `TIOCSTI` is already blocked by the absence of `hid-control`, which the profile must never gain | owner, hb-ghd.2 |
| D55 | TLS rules are part of the first renderer cut; 2.2 covers env vars, the CA bundle and a four-combination handshake test | owner, hb-ghd.2 |
| D56 | Nesting is detected by an always-on preflight probe (exit 71 plus `sandbox_apply: Operation not permitted`) | owner, hb-ghd.2 |
| D57 | hb-ghd.2.3 is split: 2.3a (environment, session directory, nesting preflight, spawn, `session::run`) and 2.3b (signals, `hb __child` helper, `--log-denials`); epic estimate 16-18 days | owner, hb-ghd.2 |
| D58 | `mcp.<name>.bind_loopback` (boolean) is replaced by `bind_ports = [..]`: per-port `network-bind` + `network-inbound`, profile-wide, never a wildcard; Seatbelt cannot confine the listener to loopback (measured), so the ports are shown in `explain` and the approval summary; the serena preset disables its dashboard instead | owner, hb-ghd.2 |
| D59 | `[env] tools = [names]` resolved against the invoking `PATH` adds each directory to the child's `PATH` with a read grant; reserved variable names are rejected at load | owner, hb-ghd.2 |
| D60 | A signal-killed child makes `hb` clean up and re-raise INT, TERM, HUP or KILL on itself; other signals exit `128+n` | owner, hb-ghd.2; measured with a real Ctrl-C in a pty |
| D61 | The config's own `deny_read`/`deny_write` entries get unlink pins by the same computation as the floor (`pin_ancestors`); the template re-allow names the guard deny's operations; `render_filtered` exists only under `cfg(test)` or the `test-support` feature, so a release build cannot render a floor-less profile; the `hb ctl` socket allow is a `path-literal` | review of hb-ghd.2.1 |
| D62 | `system_trust` grants exactly the measured minimum: `SecurityServer` and `configd` lookups, and reads of the `System.keychain` and `System.keychain-db` files (no `trustd`, `securityd`, `securityd.xpc`, `mds`, preference domain or keychain directory); a `BindPort` is 1024-65535, at most 16 per server and 64 distinct in all (`MergeError::TooManyBindPorts`); `file-map-executable` joins the floor's read set; the floor stays the keychain control and `securityd` is documented as not a gate; `hb profile` marks a `-D` value it had to escape as not copy-exact | owner (high-confidence items), oracle `hb-ghd.2.1_oracle-tls-ports-keychain.md` |
| D63 | `session::run` builds the child environment from empty (sorted, deterministic; `HB_SESSION=1` marker), refuses reserved names again in the builder, and checks the whole exec size (1 MiB minus 32 KiB); `hb run` runs the nesting check first, looks the command up itself, and returns the child's code or `128+signal` (the D60 re-raise is 2.3b); the child has its own process group only when stdin is not a tty (with a pty, D65, it leads its own session); the `hb` binary closes every inherited descriptor above 2 at start; `RunSpec.pty` is a `#[non_exhaustive]` enum (`Off`, and `On` from D65) | owner, hb-ghd.2.3 |
| D64 | `RunSpec.signals` is `Off` (default) or `Forward { grace }`; the `hb` binary blocks INT/TERM/HUP, receives them via kqueue, forwards them (group, or child only while the child shares hb's group), escalates to SIGKILL on a second signal or after 5 s, and is passive for INT/HUP when the terminal already delivers them; the child starts through the hidden `hb __child`, which clears the signal mask; the D60 re-raise is in `cli::main`; `--log-denials` streams live when stderr is redirected and prints after exit on a terminal, with 300 ms of quiet after the child ends; tests use the test-only `hb-testdrive` binary | owner, hb-ghd.2.3b |
| D65 | When `hb run` supervises and stdin is a terminal it allocates a pty (`PtyMode::On`; typed error `PtyUnavailable` otherwise, no fallback); the child is a session leader with the slave as its controlling terminal (`hb __child --controlling-tty`); one relay thread copies bytes, drains at the end, and is paused while the terminal is handed back; Ctrl-Z in the child stops `hb` with SIGSTOP after restoring the terminal, and `fg` re-enters raw mode and sends SIGCONT; the restore uses `TCSAFLUSH`; SIGWINCH is received by the same kqueue and copied to the pty; `TIOCSTI` is closed by the absence of `hid-control`, measured by a probe on sacrificial ptys | owner, hb-ghd.2.4 |
| D66 | `hb run` starts a guard process (`hb __guard`, own session) that ends the agent's process or group and the `log stream` helper with SIGTERM then SIGKILL if `hb` dies without a `release`; it retains identities and rechecks before each signal, with an accepted non-atomic check-to-signal race; the raw terminal after SIGKILL is not repaired (zsh wins the race, measured) | owner, hb-ghd.2.4 follow-up |
| D67 | The agent's output goes through `session::sanitize` (strict UTF-8, no C1 controls or ENQ, OSC and DCS by allowlist, APC/PM/SOS dropped, title report dropped, clipboard read dropped); at the end of a run and at Ctrl-Z `hb` switches off input modes and discards input until the terminal answers a device-attributes query (750 ms at most); the expect-driven tests answer that query and fail on any silent timeout; with no pty a stdout or stderr that is a terminal goes through a pipe and the same filter; the end of a run says how many times the agent set the clipboard, and `[terminal] clipboard_write = false` (any file wins) removes the writes and says it did; after a no-pty run `hb` runs the same mode reset and device-attributes fence on the terminal; the guard prints a one-line hint when a killed `hb` left the terminal raw | owner, hb-ghd.2.4 follow-up |
| D68 | `session::env` sets `NODE_USE_SYSTEM_CA=1` with `system_trust` and `NODE_EXTRA_CA_CERTS` to a per-session `ca-bundle.pem` (only the PEM certificates of `tls.extra_ca_files`, 0600, size-capped; a file with no certificate stops the run); no other CA variable is set; `com.apple.TrustEvaluationAgent` joins the system-trust grants because curl and git fail against a TLS-inspected host without it | owner, hb-ghd.2.2 |
| D69 | The profile allows `file-read*` on `^/private/var/folders/[^/]+/[^/]+/T/xcrun_db$` and never a write: `/usr/bin/git` and the other developer-tool shims read that cache to find the real tool and print two error lines per call without it; the user's own unsandboxed `xcrun` trusts the same file, so a write grant would let the agent redirect `git` for the user's shells. If the cache has no entry for a tool the first call still fails to write it and prints once | owner, hb-ghd.2.2 |
| D70 | `[system] launchctl` (default off) decides whether `/bin/launchctl` may run: `false` from any file wins and `true` is accepted only from the user's own files (the D36 rule); the profile denies exec of the program otherwise (section 4.6). Chosen over leaving it open because launchd lets a sandboxed caller start, unload and disable jobs that are not running, which no profile rule can separate, and over a hard-coded deny so a user who runs services can opt in | owner, hb-ghd.2.5 |
| D71 | The proxy (`src/proxy`, hb-ghd.3.1) runs on tokio (`rt`, `net`, `io-util`, `time`, `sync`, `macros`) with `httparse`, on its own thread behind `ProxyHandle`; plain HTTP is one request per connection with `Connection: close`; address-literal targets are always refused; the proxy starts for every run, even with an empty allowlist, so the agent gets a `403` with a reason rather than a refused connection | owner, hb-ghd.3 |
| D72 | `net.allow` entries are `host` or `host:port`, one (pattern, port) rule each, default port 443; a listed host on another port is `port_not_allowed` and the reply names the entry to add | owner, hb-ghd.3.2 |
| D73 | `net.internal_hosts` (only the user's own files, any spelling) lists the hosts whose names may resolve to private, unique-local, tunnel (`100.64.0.0/10`, `198.18.0.0/15`) and site-local addresses; loopback, link-local, multicast and reserved ranges are never allowed; IPv4-mapped, NAT64 and 6to4 addresses are classified by the IPv4 address they carry. Per host, not a global switch, because corporate internal names resolve into the tunnel range | owner, hb-ghd.3 |
| D74 | No upstream-proxy, PAC or NTLM support in v1 (only a TLS-inspecting client tunnel is measured); documented in 12.1, with a `hb doctor` listing of the system's proxy settings (D90) | owner, hb-ghd.3 |
| D75 | The proxy's refusals go through the `--log-denials` stream and every connection through `--log-proxy`; a run with refusals ends with one warning (hidden by `--no-proxy-summary`, and skipped when `--log-denials` shows them); a `407` is not a refusal; closed `loopback_ports` are a start-up warning, never an error | owner, hb-ghd.3 |
| D76 | Presets are checked against the real agent by an opt-in harness (`hamster_ball::conformance`, `HB_CONFORMANCE=1`): a throwaway project extending only `agent/<name>`, the real home and a private user config, one question per agent with a per-agent criterion, and any refused connection fails the check; the run is time-limited through a process-group wrapper | owner, hb-ghd.3.4 |
| D77 | Approval (`src/approval`, hb-ghd.4): fingerprint = SHA-256 over length-prefixed (canonical path, bytes) of the approval files in closure order; one owner-only record per canonical root under `~/.local/state/hamster-ball/approvals`; an untrusted record counts as not approved; the grant summary is every value the base chain does not also give and shows `env.set` values and MCP arguments; only a typed `y`/`yes` at a terminal approves, otherwise `hb run` exits 78 (`hb approve` too, with no `--yes`); `hb approve --revoke` needs no terminal; `hb explain` warns when unapproved; the in-process `cli::run` never prompts | owner, hb-ghd.4 |
| D78 | Secrets guard (`src/guard`, hb-ghd.5): covers every writable grant; exceptions are absolute or `~/` path patterns (a relative one is refused); templates are re-allowed by name inside each root; tracked files come from a hardened host-side `git ls-files`; key and secret-named files (not `.env*`) below `node_modules` and `site-packages` are re-allowed together with unlink pins on every directory that holds a guarded file (a directory rename is otherwise a bypass, measured); an incomplete scan switches the exemption off; `hb doctor` reports look-alike names, tracked secrets and launchd variable names, never contents | owner, hb-ghd.5 |
| D79 | Hooks (`[hooks.pre_run.<name>]`, hb-ghd.6.1) replace the flat argv list: argv only, an absolute or `~/` program, a scrubbed environment, a 1 to 300 s timeout that kills the process group, per-hook 0700 directories under the session directory, file outputs by variable, and an `aws_credential_process` format parsed by `hb` itself so no converter runs on the host; keyed merge (two files defining one name differently conflict); run in name order; `[env] set` values may use `{session_dir}` | owner, hb-ghd.6 |
| D80 | claude preset (hb-ghd.6.2): no `/private/tmp` grant; `CLAUDE_CODE_TMPDIR={session_dir}` replaces the planned `claude-<uid>`/`cc-socks` narrowing (a uid-named path cannot be spelled by a preset and must exist beforehand); the credential command is a hook in the user's base, not in the preset; `DISABLE_AUTOUPDATER=1` with a read-only install; the harness passes claude on a served `bedrock-runtime` connection and requires `OK` only on exit 0, because the measuring account's Bedrock role explicitly denies `InvokeModel` | agreed |
| D81 | opencode preset (hb-ghd.6.3): narrow Homebrew reads instead of `/opt/homebrew` (it holds database data under `var`); config directory read-only; `deny_write` on the plugin cache and downloaded tools so the agent cannot plant code that a plain `opencode` runs; conformance by a made-up API key and `opencode.ai`'s 401, because a provider-less `run` depends on free-tier quota and retried for over 100 s (one run in 34 s); `Agent` has an `env` field that the harness sets in its own project preset; `Expect::Word` matches a phrase of consecutive whole words | agreed |
| D82 | The project directory is granted by a file, not implicitly: `hb init` writes `[fs] write = ["."]` into the base, and `hb explain` and `hb run` warn when no read or write grant covers the project (`Policy::project_grant_warning`). `hb <command>` without `run` is not built: the usage line and `--help` show `hb run -- <program>` instead | agreed |
| D83 | Offline MCP launchers (hb-ghd.7.2): `uvx` and `npx` scripts first on `PATH` that `exec` the real tool with `--offline` and hb's own cache, only when a declared `[mcp.*]` has a command; the hint naming `hb warm` is printed before the `exec` (a wrapper that keeps the tool as a child loses stdin or orphans the tool); the cache is hb's, outside the user's caches and the guard's roots | agreed |
| D84 | `hb warm` (hb-ghd.7.3): only `uvx`/`npx` servers are warmed or warned about; the probe is the system perl in the ball (no hb binary runs there); warm is the same ball as a run with only the network replaced (registries, git hosts, `warm_net`); stamps in the denied state directory, advisory; `hb run` and `hb explain` warn about a git config file the ball cannot read (git treats EPERM as fatal), and `hb init` grants the git files that exist | agreed |
| D85 | `hb doctor` MCP section (hb-ghd.7.4): flags any non-version `@tag` (not only `@latest`) and unpinned `git+` sources, shows only the flagged argument without URL credentials, includes the missing-launcher warning, and does not flag bare package names | agreed |
| D86 | MCP offline check (hb-ghd.7.5): an opt-in test at library level (`warm_server`, then `session::run` with the probe) against the real home, toolchain and hb's real cache, the network at warm time only; serena's revision is resolved with `git ls-remote` unless given; strict zero proxy lines for the six, no allowed connection for serena; `WarmStore::forget` removes the stamps it made | agreed |
| D87 | `hb ctl` (hb-ghd.8): one broker per run on `<session>/ctl.sock`; synchronous threads (no second runtime), at most four connections, one 4 KiB JSON line, closed operation set, per-target mutation exclusion; commands run by the full inspected container ID after `--`; `hb` reaches the agent through a wrapper script in the session `bin`; `[ctl] launchd` (user-only, like hooks) adds `hb ctl launchd status\|kickstart\|restart` with `launchctl kickstart [-k] gui/<uid>/<label>` and a status projected to four fields (the owner added launchd to M8) |
| D88 | Preflight is an allow-list (hb-ghd.8.2; oracle review in `history/hb-ghd.8_oracle-preflight-pins.md`): see 9.3 for the refusals; a refused container at start is a warning with no pins and no start or restart; the check runs before every named operation |
| D89 | Pins and isolation (hb-ghd.8.3): pins are the source plus every ancestor a write grant reaches (not only up to the project root), `file-link` on the source, derived from preflight at start; `start` and `restart` need every source pinned at start; a container process can swap its own mount source (measured), so they also need a podman machine that shares only the project (owner chose "isolate the runtime"); the active machine is found by connection port; the owner recreates the machine, `hb` never does |
| D90 | `hb doctor` reports two more things (hb-ghd.8 follow-up): **git the floor does not protect**: repositories (a `.git` directory or file) below a write grant other than the project's own and the ones above it, hook manager files (`.husky`, `.githooks`, `.git-hooks`, `lefthook*`, `.pre-commit-config.yaml`) and `core.hooksPath` from the project's `.git/config`; walked with the guard's limits (dependency and build directories skipped, symlinks not followed, 100,000 entries), names only. **System proxy settings** from `/usr/sbin/scutil --proxy` (5 s limit): the kinds that are on, host and port, a password in a PAC URL dropped, and whether `tls.system_trust` lets the agent read them. Findings only; the exit code stays 0 and the floor is unchanged (protecting nested repositories would break `git init` and `git clone`, D46) | owner, "address the gaps" |
| D91 | The repository is public, so the names of the owner's own projects and of a vendor were replaced with neutral ones: example project `myapp`, container `app-db`, a corporate TLS-inspecting tunnel. Section 9.2 keeps the shape of the port survey without the project names. The old names remain in git history; they are names, not credentials, and a history rewrite was not done. A scan of all tracked files and the full history found no keys, tokens, private addresses or personal paths | owner, "proceed with recommendations" |
