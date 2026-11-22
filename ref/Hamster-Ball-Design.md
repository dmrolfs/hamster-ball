<!-- ABOUTME: Design for `hb`, a macOS command that runs AI coding agents in a Seatbelt hamster ball defined by layered TOML config. -->
<!-- ABOUTME: Covers threat model, config model, enforcement, agent presets, containers, build plan. Status: DRAFT for owner approval. -->

# Hamster Ball Design

Project: **hamster-ball** (`github.com/dmrolfs/hamster-ball`, private). Binary: `hb`.
Status: **draft, awaiting approval** (Plan and Design gate; no code written).
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
- Replacing `omp-supervisor`, which keeps its own sandbox code.

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
| Edit its own hamster ball config | `hamster-ball.toml` is write-denied inside the hamster ball; approval by hash (section 5) |
| Escape through podman | Floor denies podman paths; `hb ctl` is the only container channel (section 9) |

## 3. Usage

```sh
cd ~/work/myproj
hb kiro-cli chat          # run any command in the hamster ball (default action is `run`)
hb run -- cargo test      # explicit form
hb explain                # effective policy, with the source file of every rule
hb approve                # review and approve this project's hamster-ball.toml
hb doctor                 # warn about unprotected secret-looking files, missing ports, stale caches
hb warm                   # populate MCP and tool caches (the only step that may reach registries)
hb profile                # print the generated Seatbelt profile
hb ctl ps|logs|stats|start|stop|restart [name]   # inside the hamster ball: manage project containers
```

Install: `cargo install --path .`. `hb` must live in a directory the hamster ball cannot write
(the floor write-denies every PATH directory).

A project contains only TOML. No Rust or scripts are added to projects.

## 4. Config model

### 4.1 Layers and files

From lowest to highest precedence:

1. **Floor**: compiled into `hb`. Cannot be changed by any file (section 6).
2. **User base**: `~/.config/hamster-ball/base.toml`. Always applied. Not opt-in, so a project cannot skip it.
3. **Presets**: named in `extends`. Built-in (`rust`, `node`, `python`, `git`, `agent/kiro`,
   `agent/pi`, `agent/claude`, `agent/opencode`), user presets in `~/.config/hamster-ball/presets/<name>.toml`,
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
  writable). Comparison is by path component, so `/Users/rolfs2` is not confused with `/Users/rolfs`.
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
- Scalars (few exist) never loosen: `tls.system_trust` takes `false` if any file says `false` (D35), and
  `ctl.label` must be the same in every file that sets it, because a project label would otherwise replace the base's
  scope (D33). The earlier "otherwise the highest layer" fallback is removed.
- Sections that run code on the host or switch protections off (`hooks`, `guard.exceptions`) are accepted **only**
  from files that physically are the user's own: the base, files under `~/.config/hamster-ball` (with no other hard
  link), and built-in presets (D36). The rule is by where the file really is (its canonical path), not by how it was
  reached, so a path alias of a user preset behaves exactly like the name, and a symlinked or hard-linked user file
  loses the right. A project file, any file inside the project, and any other file (including one the project
  names by absolute path) that defines them is an error naming that file. The error never prints the hook.
- Even a trusted file's hooks are chosen by the project when it extends that preset. The approval summary (M4) must
  list every hook that will run, labelled project-selected.
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
  template with mode 0600 and never overwrites (D39). `XDG_CONFIG_HOME` is ignored (D39).

### 4.3 Schema (draft)

```toml
# ~/work/icehouse/hamster-ball.toml
extends = ["rust", "git", "agent/kiro", "agent/pi"]

[fs]
read       = ["~/work/shared-fixtures"]        # extra read-only paths
write      = ["."]                              # relative to the project root ("." is implicit)
deny_read  = ["config/*.secrets.yaml"]          # project-specific secrets (section 8)

[net]
allow          = ["crates.io", "static.crates.io", "index.crates.io"]   # exact or "*.suffix"
loopback_ports = [3030, 3031, 3032, 5432, 9001, 9002]                   # services you started yourself

[env]
pass  = ["LANG", "COLORTERM"]                   # names copied from your shell (not HOME, PATH, TMPDIR, TERM, proxy or TLS names, HB_*, DYLD_*, LD_*)
set   = { RUST_BACKTRACE = "1" }
tools = ["node", "git"]                         # programs found on your PATH when hb starts; see 7.2

[tls]
system_trust = true                             # base default; see 4.5
extra_ca_files = []

[ctl]                                           # section 9
label      = "com.docker.compose.project=icehouse"
containers = []

[mcp.serena]                                    # section 10
command = "uvx"
args    = ["--from", "git+https://github.com/oraios/serena", "serena", "start-mcp-server"]
net     = []                                    # hosts needed at run time (none: cache is warm)
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

- `tls.system_trust` (base default `true`): allows the Mach lookups `com.apple.SecurityServer` and
  `com.apple.SystemConfiguration.configd`, read access to the files `/Library/Keychains/System.keychain` and
  `System.keychain-db` (never the directory), and sets `NODE_USE_SYSTEM_CA=1` (D62). `trustd` and `trustd.agent` come
  from `system.sb`.
- `tls.extra_ca_files`: read access to each file and `NODE_EXTRA_CA_CERTS` set to it
  (several files are concatenated into a per-session bundle).
- The proxy never decrypts traffic. It tunnels bytes.

Measured (Node 24 inside the hamster ball, through the proxy):

| Setting | Zscaler-signed host | AWS host | private gateway |
|---|---|---|---|
| none | fail | OK | fail |
| `NODE_USE_SYSTEM_CA=1` | OK | OK | fail |
| `NODE_EXTRA_CA_CERTS` only | fail | OK | OK |
| both | OK | OK | OK |

The measured minimum (D62; `history/hb-ghd.2.1_oracle-tls-ports-keychain.md`, then re-checked by hand for Node 24 and `uv`), macOS 15.7.7 only:

| Element | Needed by | Without it |
|---|---|---|
| `com.apple.SecurityServer` | Node with `NODE_USE_SYSTEM_CA=1` | Node 24 fails every handshake (`SecItemCopyMatching failed -50`) |
| read of `System.keychain` | the same | Node 24 fails (`-25300`) |
| `com.apple.SystemConfiguration.configd` | `uv` and `uvx` (Rust `system-configuration`) | `uv` panics, even with an explicit proxy env |
| `com.apple.trustd`, `trustd.agent` | curl, git, Node, Go, Rust | in `system.sb` already |

Dropped, because no tested client regressed without them: `securityd`, `securityd.xpc` (also the route to the data-protection
keychain), the `/private/var/db/mds` read, the whole `/Library/Keychains` directory (it held `apsd.keychain`, 0644, which no client opens)
and `user-preference-read` for `kCFPreferencesAnyApplication`. Tested clients: curl, git, Node 24/26, Bun, Go, Rust (rustls),
Python, `uv`, claude, pi and opencode (the last three against a local TLS server only; kiro-cli ignores the CA env vars).
Not tested: native-tls, Deno, Electron CLIs, a real TLS-inspecting proxy, a system proxy or PAC (`configd` may matter there) and
macOS versions other than 15.7. A client that needs a dropped item shows up as a denial under `--log-denials` (hb-ghd.2.3b); the fix
is one more entry in `TLS_SERVICES`. `configd` is kept although it exposes the network configuration store (interface names, SSID text,
DNS addresses, console user): `uv` needs it.

`NODE_USE_SYSTEM_CA=1` together with `NODE_EXTRA_CA_CERTS` failed to verify a local-CA server in the first M2 analysis. It could not
be reproduced: both settings worked on Node 24.11, 26.0 and 26.3 under the minimum, in a clean environment. The earlier run most likely did not load
the extra bundle (an unreadable path prints `Ignoring extra certs` and looks like "system only"). The four-combination handshake test
(hb-ghd.2.2) still decides. The user keychain domain is not visible inside the ball (the floor denies `~/Library/Keychains`), so a corporate root installed only there is missing. The floor, not `securityd`, is what keeps the user keychain out: see section 6 and `tests/seatbelt_tls.rs`.

These settings add trusted roots only. They work with Zscaler off, because hosts then present
public-CA certificates that Node already trusts. Nothing in `hb` is Zscaler-specific.

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
  llm_gateway needs this; the exact mechanism is an open item (section 15).
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
   `/dev/stdin`, `/dev/stdout`, `/dev/stderr`.
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
8. Floor (all four effects, 6), pins and `deny_*` rules last, so nothing re-allows them. Read-class denies list the full
   read set: `file-read-data file-read-metadata file-read-xattr file-test-existence file-map-executable`, plus `file-write*`
   (`file-map-executable` is a child of `file-read-data`; naming it closes mapping a denied file as code through a descriptor
   opened before the sandbox, D62).

Invariants checked on the typed rule list before any text is written (`check.rs`): sections are non-decreasing; each section
allows or denies, not both (the guard, policy-deny, floor and pin sections only deny); no allow of `file-write-unlink` or any
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

### 7.3 Terminal

Measured during the M2 analysis, and to be re-run as the regression probe of hb-ghd.2.4 (D54): `TIOCSTI` injects keystrokes into a controlling tty when run unsandboxed. Under any deny-default profile it
fails with EPERM, even with `file-ioctl` granted on the real tty. The gate is the `hid-control` operation, which
`system.sb` does not grant. Until 2.4 there is no pty: `hb run` gives the child its own process group only when stdin is not a tty (a child in its own group while stdin is a
terminal is a background group and could not read it, measured on a real pty); on a tty it shares `hb`'s group, so Ctrl-C reaches both. So the pty is **hygiene and job control, not the injection control**: `hb` allocates a fresh pty
whenever stdin is a tty, so `/dev/tty` and re-opens name the child's own slave, `^C` and job control work, and a child that
changes terminal modes cannot leave your shell raw. The profile grants `file-ioctl` on that one slave only, and must never
gain `hid-control` (an invariant, checked on the rendered text; the real `TIOCSTI` regression probe is hb-ghd.2.4). The terminal is restored on exit, panic, SIGINT, SIGTERM and SIGHUP. Restoring after a
SIGKILL of `hb` is impossible by construction; raw mode is therefore entered as late as possible and `reset` is the cure.
Escape sequences in the child's output still reach your terminal through the relay (UNVERIFIED).

### 7.4 Nesting

`sandbox-exec` fails when run inside another macOS sandbox (also documented in `omp-supervisor`): `sandbox-exec: sandbox_apply:
Operation not permitted`, exit 71, whether the outer profile is deny-default or `(allow default)`. `hb` always runs the
preflight `sandbox-exec -p '(version 1)(allow default)' /usr/bin/true` (about 60 ms) before anything else; exit 71 with that text
means nested, and `hb` stops with a clear message. An environment marker is used only to say "inside hb" in that message,
because other sandboxes (Claude Code's, Codex's) leave none. Integration tests skip, not fail, when the preflight reports
nesting, since agents run `cargo test` inside `hb`.

## 8. Secrets guard

On by default; no setup. Denies read, write, delete, rename and hard-link for files matching:

`.env`, `.env.*`, `*secret*.{yaml,yml,json,toml}`, `*.pem`, `*.key`, `*.p12`

- **Templates stay editable**: `*.example`, `*.sample`, `*.template` are re-allowed after the deny.
- **Git-tracked files are skipped**: the agent can already read them with `git show`.
  `hb doctor` warns when a tracked file looks like a secret. icehouse tracks a `.env`;
  its contents have not been inspected.
- **Exceptions live only in the user base** (`[guard.exceptions]` keyed by project path), never in a project file.
- File names stay visible (`ls`, `stat` work); contents do not.
- Projects add their own patterns with `fs.deny_read`.
- Limit: a secret with an unusual name is not caught. `hb doctor` lists unmatched secret-looking files.

Measured: all four pattern types blocked on read; blocked all of rename-then-read, copy, hard link,
symlink, parent-directory rename, delete, overwrite, new `.env.local`, and `git add -f`; blocked
renaming, hard-linking, copying and symlinking a secret under a template name; `.ENV` blocked
on the case-insensitive filesystem (Seatbelt evaluates the canonical path); templates and source
files stay readable and writable.

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

Known ports (read from the projects, not by running them):

- **icehouse** (12 services, 16 bind mounts all inside the project, no privileged or host-network settings):
  3030, 3031, 3032, 5432, 9001, 9002, 4317, 8080, 8474, 9047, 9902, 16686, 19120, 31010, 32010
- **llm_gateway** (no compose file; a k3d cluster plus a Postgres container): 18089 (gateway), 15433
  (ledger Postgres), 3000 and 13099 (Langfuse), 9090 and 15020 (load metrics), 19000 (RustFS test).
  Cluster lifecycle recipes configure the podman VM and stay host-run.
  The k3d Kubernetes API port was not found.
  pi's default provider points at `localhost:18089`, so the pi preset in this project needs that port.

### 9.3 Tier 2: `hb ctl`

A broker inside `hb` listens on one unix socket in the per-session directory. The profile allows the
hamster ball to connect to that socket and nothing else podman-related.

- Operations: `ps`, `logs`, `stats`, `start`, `stop`, `restart`. No `run`, `exec`, `build`, `rm`, `cp`, `compose`, `kube play`.
- Scope: containers matching the project's compose-project label or an explicit name list
  (`lgw-ledger-pg` has no label, so it is listed by name).
- Fixed argument vectors. Container names must match `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`.
- **Preflight** at `hb` start and before each operation: every mount source is a real file or
  directory inside the project (not a symlink), and the container is not privileged and uses no host
  namespace or device. **Unverified** (not prototyped).
- **Pinning**: the profile denies unlink, rename and link on each mount source and its ancestors up to the
  project root. Contents stay writable.

Measured on a prototype: the hamster ball cannot run `podman` or reach the VM's SSH port (`64334`),
while the same port is open outside the hamster ball. Allowed: `ps`, `logs`, `restart` on a labelled
container. Refused: a non-project container, `run`, `exec`, two argument-injection attempts.
Pinning blocked 7 of 7 swap attempts (rename, remove, ancestor rename, rename-over, project-root rename)
and allowed in-place edits, file creation in pinned directories, and atomic-rename saves of source files.

### 9.4 Stays manual

`up`, `down`, `build`, `run`, `exec`, compose changes, k3d and kubectl cluster operations, anything
touching the podman machine. The agent tells you what to run. A later, separate option is an approval
prompt in the same terminal showing the exact command and the diff against the approved compose file.
It has not been prototyped.

## 10. MCP servers and tool caches

Measured: each of your MCP servers started inside the hamster ball and answered an MCP `initialize`.

| Server | Hosts needed on first start | Offline from warm cache |
|---|---|---|
| time, fetch (uvx) | `pypi.org`, `files.pythonhosted.org` | yes, `uvx --offline` |
| serena (uvx from git) | `api.github.com`, `raw.githubusercontent.com`, `oraios-software.de`, `pypi.org` | its web dashboard binds a loopback port (24282, then upward until one is free; a denied bind makes it scan every port): run it with `--enable-web-dashboard false`, or list `bind_ports` |
| reddit, ripgrep, browsermap, sequential-thinking (npx) | `registry.npmjs.org` | yes, `npx --offline` |
| obscura, lean-ctx | none | n/a |

- Agent presets list only the agent's own hosts. MCP servers are declared in `[mcp.<name>]` and each
  contributes its own run-time hosts (normally none).
- `hb` rewrites `uvx` and `npx` invocations to their offline forms, so no registry is reachable at run time
  and `@latest` cannot drift.
- `hb warm` is the only command that may reach registries. It runs outside agent sessions.
- `uv` and other Rust tools need `com.apple.SystemConfiguration.configd`, which is in the base (section 4.5).
- `beads-mcp` is broken on the host (its Python interpreter is gone); unrelated to `hb`.

## 11. Credentials

Principle: the hamster ball holds only credentials the agent itself needs to reach its model provider.

- **Agent logins** live in each agent's state directory, which its preset allows (kiro-cli's token is in
  `~/Library/Application Support/kiro-cli`, pi's in `~/.pi/agent/auth.json`). Domain allowlisting limits where
  they can be sent. Accepted by the owner.
- **Host-side hooks** run before the hamster ball starts, outside it, with argv only (no shell). They are
  accepted only from the user base and presets (section 4.2).
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
- Allowlist entries: exact host or `*.suffix`. Default is deny. Denials return `403` with a reason and are logged.
  `*.example.com` matches `a.example.com` and `a.b.example.com` but not `example.com`, and is label-boundary safe.
  Hosts are strict LDH (a `_` in a label is rejected), punycode only, and the last label must start with a letter
  (so `2130706433` and `0x7f.1` are rejected). **Wildcards over protected suffixes are rejected at config time**:
  a wildcard whose suffix is on the public suffix list, or is an ancestor of any entry on it, is an error
  (`*.github.io`, `*.co.uk`, `*.cloudfront.net`, and also `*.amazonaws.com`, which is not itself listed but
  covers every `*.s3.amazonaws.com` tenant). List exact hosts instead. The list is vendored (MPL-2.0, unmodified)
  and compiled into a protected set by `build.rs`; no runtime network is used.
- The proxy resolves names and refuses to connect to loopback, link-local or private addresses for allowed
  names (prevents DNS rebinding into local services). Default port: 443 only.
- Auth: the proxy URL carries a random per-session credential
  (`http://hb:<token>@127.0.0.1:<port>`) so other local processes cannot use the proxy.
  **Unverified** that all four agents accept credentials in the proxy URL.
- Proxy variables: `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and lowercase forms.
- Measured: kiro-cli, pi, claude and opencode all honor these variables. A direct connection, and DNS
  resolution, fail inside the hamster ball. A connection to another loopback port fails.
- Loopback connections to the hamster ball's own listeners are denied by default (measured). Only
  `net.loopback_ports` are reachable.
- The proxy logs host, port, decision and byte counts. It never logs bodies.

## 13. Agent presets (initial contents)

All measured under the deny-default profile with proxy-only network. Home-relative paths shown.

| Agent | Read-only | Read-write | Hosts (own) | Notes |
|---|---|---|---|---|
| kiro-cli 3.3.0 | `~/.local/bin/kiro-cli` | `~/.kiro`, `~/Library/Application Support/kiro-cli` | `app.kiro.dev`, `runtime.us-east-1.kiro.dev`, `management.us-east-1.kiro.dev`, `telemetry.us-east-1.kiro.dev`, `client-telemetry.us-east-1.amazonaws.com`, `cognito-identity.us-east-1.amazonaws.com`, `desktop-release.q.us-east-1.amazonaws.com` | Probes `~/.local/bin` for write access; denial is harmless. Needs system trust (Zscaler re-signs `kiro.dev`). |
| pi 1.5.2 | `~/.pi/agent/bin`, `~/.pi/agent/install`, `~/.nvm/versions/node` | `~/.pi/agent` (whole directory; it creates lock files) | provider gateway (user-specific) | Needs `NODE_EXTRA_CA_CERTS` for the private gateway CA. Default provider is `localhost:18089`. |
| claude 2.1.296 | `~/.local/share/claude`, `~/.local/bin/claude`, `/private/tmp` | `~/.claude`, `~/.claude.json`, `~/.cache/claude`, `~/.local/state/claude` | Bedrock: `bedrock-runtime`, `bedrock`, `sts` in `us-east-1` | Credentials via host hook (section 11). Uses fixed `/tmp/claude-<uid>`; narrowing `/private/tmp` is open (section 15). Optional hosts seen: `api.anthropic.com`, `downloads.claude.ai` (updater); denied by default. |
| opencode 1.2.0 | `~/.config/opencode`, `~/.bun/install`, `/opt/homebrew` | `~/.local/share/opencode`, `~/.cache/opencode`, `~/.local/state/opencode` | `models.dev`, `opencode.ai` (Zscaler-signed) | Earlier notes said it needs `com.apple.securityd.xpc` and the `kCFPreferencesAnyApplication` read. The D62 run showed a TLS fetch to a local server works without both (a denial is logged, the call succeeds); an end-to-end run is still missing (no provider is configured on this machine). Loopback bind for its in-process server needs `bind_ports`. |
| codex, omp | | | | **Not installed here; no preset until tested.** |

Presets are hand-written. Measured: Seatbelt denial logs are incomplete (40 of 40 reported for `sh` and
Python, 32 of 40 for Node), so no allow rules are generated from logs. `hb run --log-denials` streams
denials as hints for you to read.

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
| `ctl` | Unix-socket broker and client, preflight, pinning inputs |
| `guard` | Secret patterns, git-tracked detection, doctor scan |
| `session` | Per-session directory (0700), env construction, hooks, pty, spawn, cleanup |
| `cli` | `clap` commands |

Pure core, effects at the edges: `policy` is pure; `system` and the file loading and discovery in `config` hold the I/O (reading files, `realpath`, passwd); `seatbelt` is a pure function of the resolved policy.

## 15. Open items (decide or verify before or during implementation)

1. **Terminal isolation** (7.3): allocate a pty for the child; verify keystroke injection is closed.
2. **Proxy credentials in the URL** (12): confirm kiro-cli, pi, claude and opencode accept them.
3. **Narrow `/private/tmp`**: claude needs `/tmp/claude-<uid>` and `/tmp/cc-socks`. Seatbelt has no private `/tmp`,
   so allow only named subpaths per agent, and give every other tool a per-session `TMPDIR`. Verify claude still works.
4. **`.git/config` write-deny** (6): blocks `git push -u`. Keep as default and revisit after dogfooding.
5. **`~/.kube`**: how llm_gateway gets a project-scoped kubeconfig for its local k3d cluster, and the API port.
6. **Preflight for `hb ctl`** (9.3): implement and test; not prototyped.
7. **Claude updater**: confirm `DISABLE_AUTOUPDATER=1` (or the current setting name) stops `downloads.claude.ai` traffic.
8. **llm_gateway ledger port**: `justfile` and the running container use 15433; two `psql` probes in
   `just/analytics.just` use 15432. Report to that project; not a change for this repo.
9. Presets for codex and omp once installed.
10. **Unverified under the final profile**: AppleEvents (`osascript` driving Terminal) and `launchctl submit` (hb-ghd.2.5).
    Reaching user keychain items through `securityd` is measured (section 6, D62): not possible without a pre-sandbox handle. Still
    open: the data-protection keychain, a real corporate TLS-inspecting proxy, and a system proxy or PAC that might need `configd`.
11. **Nested standalone repositories** (D46): `hb doctor` (M5) should flag them and any git-hook manager.

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
- **`hb ctl`**: policy table tests plus a test against real podman when available.

## 17. Alternatives considered

| Option | Why not |
|---|---|
| Wrap `srt` (Anthropic Sandbox Runtime) | Node dependency; JSON with no inheritance or floor; we want approval, secrets guard and ctl. Its design (proxy-mediated network, per-session proxy) is adopted here. |
| Container or VM per agent | Stronger isolation, but agents, MCP servers and your toolchains live on the host, and podman on macOS cannot restrict container egress (measured). Revisit for hostile-agent use. |
| Keep `sb` and extend the shell script | Shell cannot parse layered TOML safely, or implement the proxy and broker. |
| Reuse `sandbox.py` | Python and tied to the supervisor's workdir layout. Its profile-generation ideas are reused. |

`sandbox-exec` is deprecated by Apple but is what Codex, Claude Code (`srt`) and Chrome use. The risk is
accepted. All Seatbelt use is isolated in the `seatbelt` module so a replacement backend is possible.

## 18. Build plan (after approval)

Proposed milestones, each ending with passing tests:

1. Repo scaffold, CI config, `config` + `policy` + `floor` + `hb explain`.
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
| D19 | Project name `hamster-ball`; binary stays `hb`; GitHub `dmrolfs/hamster-ball`, private until the project-specific details are moved out | chosen by owner (name); private is my default |
| D20 | User config and state live under `~/.config/hamster-ball` and `~/.local/state/hamster-ball` (not `sandbox`, which the old `sb` and Linux setup already use as `~/.sandbox`) | change made while renaming; pending owner review |
| D21 | Binary is `hb` (not `sb`); the project config file is `hamster-ball.toml` (not `sandbox.toml`); "sandbox" becomes "hamster ball" in this repo's prose. Kept as-is: Apple's `sandbox-exec`, `sandbox.py`, Anthropic's "Sandbox Runtime", the legacy `sb` script, `omp-supervisor`'s own sandbox | owner feedback; file name `hamster-ball.toml` is my choice, pending review |
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
| D63 | `session::run` builds the child environment from empty (sorted, deterministic; `HB_SESSION=1` marker), refuses reserved names again in the builder, and checks the whole exec size (1 MiB minus 32 KiB); `hb run` runs the nesting check first, looks the command up itself, and returns the child's code or `128+signal` (the D60 re-raise is 2.3b); the child has its own process group only when stdin is not a tty (until the pty of 2.4); the `hb` binary closes every inherited descriptor above 2 at start; `RunSpec.pty` is a `#[non_exhaustive]` enum with only `Off` until 2.4 | owner, hb-ghd.2.3 |
