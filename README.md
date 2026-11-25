<!-- ABOUTME: Entry point for hamster-ball: what `hb` does, how to install and use it, the config reference and troubleshooting. -->
<!-- ABOUTME: Describes what is built today (milestones 1 to 8); the design and its decision log are in ref/Hamster-Ball-Design.md. -->

# hamster-ball

The agent runs freely inside a clear ball it can't leave, and you can watch.

`hb` runs an AI coding agent (kiro-cli, pi, claude, opencode, or any command) inside a macOS Seatbelt sandbox.
Each project describes its ball in a small `hamster-ball.toml`. A base config of your own applies to every project, and no
project can loosen it. The agent reaches the network only through a proxy that checks every host against an allowlist, and
it cannot read your credentials, your browser profiles or the secret files in the project.

- [What it protects, and what it does not](#what-it-protects-and-what-it-does-not)
- [Status](#status)
- [Getting started](#getting-started)
- [User guide](#user-guide)
- [Reference](#reference)
- [Troubleshooting](#troubleshooting)
- [Development](#development)

For a longer explanation of the ideas, the parts and worked examples, see the [guide](docs/README.md), also published as a book at https://dmrolfs.github.io/hamster-ball/ once GitHub Pages is switched on (see Development).

## What it protects, and what it does not

`hb` limits what an agent can do when it is wrong, confused or tricked by text it reads. Inside the ball:

| The agent can | The agent cannot |
|---|---|
| read and write the directories you grant (normally the project) | read `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, keychains, browser profiles, shell history, other credential stores |
| reach the hosts you list, over HTTPS or HTTP, through the proxy | open any other connection, resolve names itself, or reach another local port |
| read `.env.example` and other templates | read `.env`, `*.pem`, `*.key`, `*secret*.yaml` and the like, in any directory it may write |
| run the programs on a fixed, short `PATH` | change your shell startup files, `~/.gitconfig`, programs on your `PATH`, git hooks, or `hamster-ball.toml` itself |
| see only the environment variables you pass | run `podman` or `docker`, `launchctl`, `open`, `sudo`, or type into your terminal |
| use `hb ctl` to see and restart the containers and launchd jobs you list | start, run or exec any other container, or change any other job |

The floor (what is always denied) is compiled into `hb`. No config file can remove an item from it.

Not covered: a hostile agent with a kernel exploit (use a VM), other operating systems, and anything you grant yourself.
The proxy tunnels bytes and never decrypts them, so an allowed host can still receive anything the agent can read.
The full threat model is section 2 of [ref/Hamster-Ball-Design.md](ref/Hamster-Ball-Design.md).

## Status

Version 0.1, macOS only (built and measured on macOS 15.7, arm64). The design lists eight milestones and all eight are built.

| Built and tested | Not built |
|---|---|
| layered config, `hb explain`, `hb profile` | the language presets `rust`, `node`, `python`, `git` (write your own: see [Presets](#presets)) |
| `hb run`: Seatbelt profile, empty environment, pty, signals | an upstream HTTP proxy or PAC (the proxy connects directly) |
| HTTP proxy with a host allowlist, TLS trust settings, corporate-network settings | presets for codex and omp |
| approval of a project's config (`hb approve`) | `hb ctl` for anything but podman containers and launchd jobs |
| secrets guard, `hb doctor` | |
| host-side hooks, Bedrock credentials | |
| presets for kiro-cli, pi, claude and opencode | |
| MCP servers: `[mcp.*]` hosts and ports, offline `uvx`/`npx` launchers, `hb warm`, MCP checks in `hb doctor` | |
| `hb ctl`: container and launchd broker, preflight, mount pinning (see [Containers and launchd jobs](#containers-and-launchd-jobs)) | |

Opt-in tests prove the parts that need real tools: agent presets (`HB_CONFORMANCE`), MCP servers (`HB_MCP`), podman (`HB_PODMAN`) and launchd
(`HB_LAUNCHD`). See [Development](#development).

## Getting started

### Requirements

- macOS (15 tested) on Apple silicon. `hb` uses `/usr/bin/sandbox-exec`, which ships with macOS.
- Rust 1.85 or newer to build it.
- An agent you already use and can run outside the ball (log in to it there first).

### Install

```sh
git clone https://github.com/dmrolfs/hamster-ball && cd hamster-ball
cargo install --path .
hb --version
```

`hb` must live in a directory the agent cannot write. The floor write-denies every directory on your `PATH`, and
`hb` itself, so `~/.cargo/bin` is fine. `hb` refuses to run as root and refuses to start inside another sandbox
(macOS does not nest them).

### First run

1. **Create your base config.** It applies to every project and only you can edit it (the floor denies it to the agent).

   ```sh
   hb init        # writes ~/.config/hamster-ball/base.toml, never overwrites
   ```

   The file is commented. It also lets git read the `~/.gitconfig` and `~/.config/git` that exist on your machine (git fails every command if it cannot read its config), and it makes every project writable (`[fs] write = ["."]`: a project is not granted on its own, so a
   base without that line leaves the agent unable to read the project). On a network that inspects TLS (a corporate TLS-inspecting proxy or tunnel)
   leave `tls.system_trust = true`.

2. **Describe the project.** In the project's root directory:

   ```toml
   # hamster-ball.toml
   extends = ["agent/kiro"]     # kiro-cli's own state and hosts; see Presets for the others
   ```

   Add hosts, paths and variables here as the project needs them (see the config reference).

   `hb` finds the project by walking up from the current directory to the first `hamster-ball.toml`. It stops with an
   error if there is none; it never falls back to the current directory.

3. **Look at what you are granting.**

   ```sh
   hb explain                       # every effective rule and the file it came from
   hb explain --path ~/.ssh/id_rsa  # why one path can or cannot be reached
   ```

4. **Approve it.** The agent can write the project directory, so `hb` runs a project config only after you have
   reviewed its exact bytes.

   ```sh
   hb approve                       # shows what the project adds beyond your base; type y
   ```

5. **Run the agent.**

   ```sh
   hb run -- "$(command -v kiro-cli)" chat
   ```

   The command is looked up on a short `PATH` (`/usr/bin:/bin:/usr/sbin:/sbin` plus the programs named in `[env] tools`).
   An agent installed elsewhere needs its full path, as above, or an entry in `[env] tools`.

6. **Watch what it asks for.** If something fails, see what was refused:

   ```sh
   hb run --log-denials --log-proxy -- "$(command -v kiro-cli)" chat
   ```

   Denials print as `hb: denied: ...` and connections as `hb: proxy: allowed|refused host:port ...`. They are hints for a
   person: the macOS log is incomplete, so do not turn them into rules without testing.

Run `hb doctor` once per project to see secret-looking files the guard does not cover.

## User guide

### Commands

| Command | What it does |
|---|---|
| `hb init` | Creates `~/.config/hamster-ball/base.toml` from a commented template. Never overwrites. |
| `hb run [--log-denials] [--log-proxy] [--no-proxy-summary] [--] <command>...` | Runs the command in the ball and exits with its status (`128 + n` for a signal). Needs an approved config. |
| `hb explain [--format text\|json] [--show-args] [--path <path>]` | Prints every effective rule with the file it came from, what the floor overrides, skipped grants and warnings (including a project that no grant covers). Runs nothing, needs no approval. `--path` answers one question about one path (merged config and floor only). |
| `hb approve [--revoke]` | Shows what the project adds beyond your base and asks `Approve this config? [y/N]`. Needs a terminal. `--revoke` takes the approval back and needs none. |
| `hb warm [--timeout SECS] [--log-denials] [--log-proxy] [NAME...]` | Fills hb's offline cache: starts each declared `[mcp.*]` server whose command is `uvx` or `npx` once, in the same ball a run uses, with only the package registries (and the server's `warm_net`) reachable, and waits for it to answer an MCP `initialize`. The only command that reaches a registry. Needs an approved config; refuses inside a ball. |
| `hb doctor` | Lists secret-looking files the guard misses, tracked files it would deny, secret-looking launchd variable names, git hooks the floor does not cover (repositories below a write grant, hook managers, `core.hooksPath`), the proxy settings the system has on, and the `uvx`/`npx` MCP servers that cannot start offline (never warmed, a moving version tag, an unpinned git source, a launcher missing from `[env] tools`). Prints names and the one flagged argument, never contents. Always exits 0. |
| `hb profile` | Prints the Seatbelt profile and its parameters for this project. |
| `hb ctl ps\|logs\|stats\|start\|stop\|restart [NAME]`, `hb ctl launchd status\|kickstart\|restart LABEL` | Only inside the ball (anywhere else it exits 2 and says no `[ctl]` is set up): see and restart the containers and launchd jobs the config lists. See [Containers and launchd jobs](#containers-and-launchd-jobs). |

### How a run is built

1. `hb` finds the project, loads your base, the presets in `extends`, and the project file, and merges them under the floor.
2. It checks the project config is approved (exit 78 if not).
3. It scans for secret files, lists tracked ones, and runs your pre-run hooks on the host.
4. It starts a proxy on `127.0.0.1` with a random port and a per-run credential, and creates a private session directory
   (this run's `TMPDIR`).
5. With a declared `[mcp.*]` that has a `command`, it also writes offline `uvx` and `npx` launchers first on `PATH` (see `hb explain`), and warns before starting about each such server that `hb warm` has not warmed.
6. With a `[ctl]` section, it checks each listed container, starts the `hb ctl` broker on a private socket in the session directory, writes an `hb` wrapper first on `PATH`, sets `HB_CTL_SOCKET`, and pins the containers' mount sources in the profile (see [Containers and launchd jobs](#containers-and-launchd-jobs)). A container that fails the checks is named in a warning.
7. It starts the command under a generated deny-by-default Seatbelt profile, with an empty environment plus the variables
   it sets itself and the ones you list, on a pty of its own when stdin is a terminal.
8. When the command ends it stops the broker and the proxy, removes the session directory (hook files and the socket included) and exits with the command's status.

Paths are canonicalized with `realpath` before they reach the profile, because Seatbelt matches resolved paths. A grant whose
path does not exist is skipped, and `hb explain` and `hb run` say so: create the directory first.

### Config files and layers

From weakest to strongest:

| Layer | File | Who can change it |
|---|---|---|
| Floor | compiled into `hb` | nobody |
| Base | `~/.config/hamster-ball/base.toml` | you; always applied; a project cannot skip it |
| Presets | built in (`agent/...`), or yours in `~/.config/hamster-ball/presets/<name>.toml`, or a path | named by `extends`; presets may extend presets |
| Project | `hamster-ball.toml` in the project root | you and the agent's changes, which is why it needs approval |

Merge rules:

- Lists are unioned. A project can add and never remove. `deny` from any layer beats any allow.
- Maps (`env.set`) merge by key. The same key with two different values is an error that names both files.
- Switches never loosen: `tls.system_trust`, `terminal.clipboard_write` and `system.launchctl` are `false` if any file says so.
- Settings that run code on your machine or switch protections off are accepted only from files that are physically yours (the
  base, your presets): `hooks`, `guard.exceptions`, `net.internal_hosts`, `ctl.launchd`, and `system.launchctl = true`. A project file that has
  one is an error naming the file.
- Relative paths mean the project root in every layer, so `write = ["."]` in a preset means the project. `~` and `~/...` are
  the only home forms; there is no `$VAR` expansion. Patterns in `deny_read` and `deny_write` may use `*`, `?` and `**`.
- `hb` refuses a grant that is too broad: `/`, your home, an ancestor of it, or a path with fewer than two components.

### Config reference

```toml
extends = ["agent/pi", "my-team"]       # built-in presets, ~/.config/hamster-ball/presets/<name>.toml, or a path

[fs]
read       = ["~/work/shared-fixtures"]  # read-only
write      = ["."]                       # read and write; "." is the project
deny_read  = ["config/*.secrets.yaml"]   # also denies write, delete and rename
deny_write = ["~/.pi/agent/bin"]         # reads stay as granted

[net]
allow          = ["crates.io", "*.example.com", "git.example.com:8443"]   # host, *.suffix, optional :port (default 443)
internal_hosts = ["github.com"]          # your own files only: may resolve to private addresses
loopback_ports = [5432, 9001]            # services you started yourself; reached directly, not through the proxy; `hb run` warns if one is not listening

[env]
pass  = ["LANG", "COLORTERM"]            # copied from your shell
set   = { RUST_BACKTRACE = "1", MY_TMP = "{session_dir}/work" }   # {session_dir} is this run's private directory
tools = ["node", "git"]                  # programs found on your PATH when hb starts; their directories are added and readable

[tls]
system_trust   = true                    # verify against the system roots (TLS-inspecting networks); sets NODE_USE_SYSTEM_CA=1
extra_ca_files = ["~/ca/corp.pem"]       # private CAs for Node clients; hb sets NODE_EXTRA_CA_CERTS to a per-run bundle

[terminal]
clipboard_write = true                   # false removes the agent's OSC 52 clipboard writes

[system]
launchctl = false                        # true (your own files only) lets the agent run launchctl; see the warning in the design, 4.6

[ctl]
label      = "com.docker.compose.project=myapp"   # containers with this label, for `hb ctl`; must be the same in every file
containers = ["app-db"]                       # or by exact name
launchd    = ["com.example.postgres"]                # your own files only: jobs `hb ctl launchd` may start and restart

[guard]
exceptions = ["~/work/myproj/.env.local"]   # base and your presets only; absolute or ~/ patterns

[mcp.context7]                           # a remote MCP server: no command, only the host it needs at run time
net = ["mcp.context7.com"]               # host or host:port; joins net.allow
# warm_net = ["pypi.org"]                # hosts only `hb warm` may reach for this server, beside the registries
# bind_ports = [24282, 24283]            # loopback ports the server may listen on (profile-wide)

[hooks.pre_run.bedrock]                  # base and your presets only; see Credentials
command      = ["~/bin/credential-process", "--profile", "my-profile"]
format       = "aws_credential_process"
profile      = "my-profile"
timeout_secs = 30                        # 1 to 300
```

Limits: a config file is read as UTF-8, up to 256 KiB and 4096 entries per list, from a regular file you own that is not
world-writable. Wildcards over a public suffix or a whole cloud domain (`*.github.io`, `*.amazonaws.com`) are refused at load time:
list the exact hosts. A host entry is a name, never an IP address.

### Presets

Built into `hb` today: `agent/kiro`, `agent/pi`, `agent/claude`, `agent/opencode`. Each lists only the agent's own state and hosts.
No preset names a model provider or an MCP server.

| Preset | Measured with | Reads | Writes | Hosts | You still add |
|---|---|---|---|---|---|
| `agent/kiro` | kiro-cli 3.5.0 | none | `~/.kiro`, `~/Library/Application Support/kiro-cli` (not its `node`, `bun`, `tui.js`, `bunfig.toml`, `kas`) | `app.kiro.dev` and five more | nothing |
| `agent/pi` | pi 1.6.0 | via `env.tools = ["node"]` | `~/.pi/agent` (not `bin`, `install`) | none | your provider's host or gateway port, and its CA if private |
| `agent/claude` | claude 2.1.328 | `~/.local/share/claude`, `~/.local/bin/claude` | `~/.claude`, `~/.claude.json`, `~/.cache/claude`, `~/.local/state/claude` | `bedrock-runtime`, `bedrock`, `sts` in us-east-1 | a credential hook in your base (below) |
| `agent/opencode` | opencode 1.2.0 (Homebrew) | `~/.config/opencode`, Homebrew `Cellar`, `opt`, `lib`, `etc/openssl@3` | `~/.local/share/opencode`, `~/.cache/opencode`, `~/.local/state/opencode` (not its plugin cache or `bin`) | `models.dev`, `opencode.ai` | hosts for your MCP servers, if any |

Each preset file in [`presets/agent/`](presets/agent) starts with a header that says what was measured, what is denied and
harmless, and what is not proven. [`presets/README.md`](presets/README.md) explains how to write one and how to check it against the
real agent (`HB_CONFORMANCE=1 cargo test --features test-support --test conformance`).

Write your own the same way: a TOML file in `~/.config/hamster-ball/presets/<name>.toml`, used as `extends = ["<name>"]`. A team
preset with `[fs] write = ["."]` and the hosts your toolchain needs saves repeating them. Agents installed some other way (a
different Node, a non-Homebrew opencode) need their own `fs.read` grant for the install.

Preset grants for programs the agent could replace are write-denied on purpose: a plain `claude` or `pi` that you run outside
the ball must never run something the agent planted. Keep that in mind when you widen a write grant over an install directory.

### MCP servers

Agents start MCP servers with `uvx` and `npx`, which download packages at every start. In the ball no registry is open, so `hb` splits
that into two steps.

1. **Declare** each server in your base or project, and list the launchers in `[env] tools` so `hb` can find the real ones:

   ```toml
   [env]
   tools = ["uvx", "npx", "node"]

   [mcp.time]
   command = "uvx"
   args = ["mcp-server-time"]            # the same command and arguments the agent runs

   [mcp.serena]
   command = "uvx"
   args = ["--from", "git+https://github.com/oraios/serena@<full-sha>", "serena", "start-mcp-server"]
   bind_ports = [24282, 24283, 24284, 24285, 24286, 24287, 24288, 24289]   # its dashboard listens on the first free one
   ```

2. **Warm** once, outside the ball: `hb warm`. It starts each declared `uvx`/`npx` server in the ball with only the registries open and keeps what it
   downloaded in `~/.cache/hamster-ball` (hb's own cache, never your `~/.cache/uv` or `~/.npm`). Warm again after you change a server's arguments.

After that `hb run` puts `uvx` and `npx` launchers first on the child's `PATH`: each starts the real tool with `--offline` and hb's cache, so a server starts
from the cache with no network. Only those two names change: `uv sync`, `npm install` and a program called by absolute path behave as before. A remote
MCP server has no command; give it `[mcp.context7] net = ["mcp.context7.com"]`. A server's own files (serena's `~/.serena`) are ordinary `[fs]` grants.
`hb explain` shows the launchers, the cache and whether each server is warmed. Measured on the servers above (time, fetch, reddit, ripgrep, browsermap,
sequential-thinking and a pinned serena): each answers an MCP `initialize` in the ball in 1 to 2 seconds with no proxy connection (`mcp_offline`, see Development).
Serena needs a full-revision pin, several `bind_ports`, and `~/.serena` writable, and asks for `pypi.org` and `oraios-software.de` while running (refused, harmless).

### Containers and launchd jobs

The agent cannot run `podman` (the podman machine shares your home with every container, so a container can read `~/.ssh`) or
`launchctl`. `hb ctl` is the one way in. A broker inside `hb run` listens on a private socket in the run's directory and runs a short
list of fixed commands for what you list:

```toml
[ctl]
label      = "com.docker.compose.project=myapp"   # every container with this label
containers = ["app-db"]                       # and these, by name
launchd    = ["com.example.postgres"]                # launchd jobs; only your own files may list them
```

Inside the ball: `hb ctl ps`, `hb ctl logs NAME --tail 100`, `hb ctl stats NAME`, `hb ctl start|stop|restart NAME`, and
`hb ctl launchd status|kickstart|restart LABEL`. There is no `run`, `exec`, `build`, `rm` or `cp`. `launchd status` shows the state,
process number, run count and last exit code, never the job's environment. Output is capped at 20 KB.

What `hb` checks before it lets the agent touch a container: it must be in the list; it must not be privileged or use a host or
joined namespace, added capability, device, or `volumes_from`; every bind mount must be a real file or directory inside the project
(no symlink in the path); a volume must be a plain local one. A container that fails is named in a warning when `hb run` starts, and
`hb ctl` will not start or restart it in that run. The mounted directories (and the directories above them, as far as the agent can
write) cannot be renamed, deleted or linked by the agent, so it cannot swap a mount for a link and then ask for a restart. The files
inside stay writable. A single file that is itself a mount cannot be saved by "write a temp file and rename": edit it in place.

Which containers to list: the ones the agent should be able to look at and restart. Name them exactly as `podman ps -a` does (`app-db`),
or give the compose label every one of them carries (`hb ctl ps` shows what the label matched). The label must be the same wherever it is
set, so a project cannot widen the scope your base gave. A container name that does not exist is simply never found.

**`start` and `restart` need a podman machine that shares only the project.** A process inside a container is not confined by the
sandbox: one that runs project code (which the agent can edit) can swap its own mount for a link to any directory the machine
shares (measured). If the machine shares more (the default is `/Users`, `/private` and `/var/folders`), `hb` says so at start and
refuses `start` and `restart`; `ps`, `logs`, `stats` and `stop` still work. `hb` never changes the machine. To get one that shares only the project,
create a second machine beside your existing one (measured, this keeps the old machine's images and containers):

```sh
podman machine stop                                   # only one machine runs at a time
podman machine init hb-myproj --cpus 6 --memory 8192 \
  --volume /path/to/project:/path/to/project --now    # the same path on both sides; no other --volume
podman system connection default hb-myproj            # `podman` and `hb` use the machine this points at
```

The new machine starts empty (pull or build what the project needs), and it serves only that project. To go back:
`podman machine stop hb-myproj; podman machine start podman-machine-default; podman system connection default podman-machine-default`.
Every share must be the project root or inside it. A project that sits inside a wider share (for example a scratch project under the shared repo) is refused.
A machine's name is its first argument; without one, `init` fails while `podman-machine-default` exists. `podman machine rm` deletes a machine's images, containers and volumes.

Not covered: a container you start keeps unrestricted network access; its image and command are trusted; `logs` can show secrets.
Design: section 9.3 and D87 to D89 in [ref/Hamster-Ball-Design.md](ref/Hamster-Ball-Design.md).

### Network access

The agent has no direct network and no DNS. It gets `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` (and lowercase forms) pointing at
the per-run proxy, with a random credential so other local processes cannot use it. The proxy:

- allows a host only if an `allow` entry matches it and its port, and answers anything else with a `403` and an `X-Hb-Refusal` code;
- resolves names itself and connects to the address it checked, so a name that later points at `127.0.0.1` or `169.254.169.254` is refused;
- refuses private, tunnel and other internal addresses unless the host is in `net.internal_hosts`;
- never decrypts traffic, and logs no headers or bodies.

Refusal codes you will see: `not_allowed` (add the host), `port_not_allowed` (add `host:port`), `internal_address` (add the host to
`net.internal_hosts` in your base), `ip_literal` (use a name), `unresolved` and `unreachable` (the name or route is wrong), `timed_out`.

**Corporate networks.** Measured on a corporate client tunnel that inspects TLS; nothing in `hb` is specific to it.

| Need | How |
|---|---|
| TLS inspection re-signs hosts | `tls.system_trust = true` (base default). A private CA for Node clients: `tls.extra_ca_files` |
| Internal names, or public names such as `github.com`, that resolve to `100.64.0.0/10` or RFC 1918 addresses | list them in `net.internal_hosts` in your base |
| Split DNS | works: the proxy uses the system resolver |
| An upstream HTTP proxy, PAC, NTLM or Kerberos | not supported: the proxy connects directly |

`tls.extra_ca_files` and `NODE_USE_SYSTEM_CA` reach Node-based clients (pi, opencode's Node launcher, claude). kiro-cli ignores
both. Python and `uv` read their own variables: give them one with `[env] set` if you need it.

### Environment

The agent starts with an empty environment. `hb` sets `HOME`, `PATH`, `TMPDIR` (the private session directory), `TERM`,
`HB_SESSION=1`, the proxy variables and the TLS variables. Everything else you must ask for with `[env] pass` (copied) or
`[env] set` (fixed). `HOME`, `PATH`, `TMPDIR`, `TERM`, `HB_*`, `DYLD_*`, `LD_*` and the proxy and TLS names cannot be set or passed.
`set` wins over `pass`, and a hook's variable wins over `set`. `hb explain` never shows a `set` value. Static cloud keys are never
passed on purpose; use a hook (below).

### Secrets guard

Always on. Below every directory the agent may write (normally the project), at any depth, these names cannot be read, written,
renamed, deleted or hard-linked: `.env`, `.env.*`, `*secret*.yaml|yml|json|toml`, `*.pem`, `*.key`, `*.p12`. Names stay visible, so
`ls` works; contents do not.

- Templates (`*.example`, `*.sample`, `*.template`) stay editable.
- Files git tracks are skipped, since the agent can already read them with `git show`. `hb doctor` lists them.
- Key and certificate files below `node_modules` and `site-packages` (not `.env*`) are usable, so `pip install` and
  `rm -rf node_modules` work. `hb` pins the directories that hold them against rename. A directory that gets its first key after
  `hb` starts is not pinned.
- Add project patterns with `fs.deny_read`. To switch the guard off for a file, list its absolute or `~/` pattern in
  `[guard] exceptions` in your base. A project cannot.
- A secret with an unusual name is not caught. `hb doctor` lists look-alikes (`.netrc`, `id_rsa`, `*.tfvars`, `*.tfstate`, files with
  `token`, `password` or `api key` in the name) by name only.

### Approval

A project's `hamster-ball.toml`, and any file it extends from inside the project, can be changed by the agent or by a `git pull`.
So `hb run` runs them only when their exact bytes were approved, and the ball makes those files read-only for the agent.

- `hb approve` prints the project root, each file with a short digest and everything the project adds beyond your base,
  including what the presets it names grant. It accepts only a typed `y` or `yes`, at a terminal. There is no `--yes`.
- Any change to a byte, or a renamed, added or removed file, asks again. Moving the project asks again.
- Records live in `~/.local/state/hamster-ball/approvals/` (the floor hides the directory from the agent). `XDG_STATE_HOME` is ignored.
- Without a terminal an unapproved config exits **78** and runs nothing. `hb approve --revoke` works without one.
- Your base and user presets are not hashed: they are outside the ball's reach. Built-in presets are part of the `hb` you installed.

### Credentials and hooks

A hook runs a program of yours on the host, before the agent starts, and gives the agent a file instead of the credential tool.
Hooks are defined only in your base or user presets. A project that extends such a preset runs its hooks, and `hb approve` lists them.

```toml
# ~/.config/hamster-ball/base.toml
[hooks.pre_run.bedrock]
command = ["~/ai-coding/credential-process", "--profile", "my-profile"]
format  = "aws_credential_process"
profile = "my-profile"           # the profile the agent selects (claude's settings pick AWS_PROFILE)
```

- `command` is an argument list (no shell), and its program is an absolute path or starts with `~/`. It runs with a scrubbed
  environment and a time limit (`timeout_secs`, default 30, at most 300) that kills its process group. A failing hook stops the run
  before the agent starts. Signals wait while a hook runs, so the limit is what bounds it.
- With `format = "aws_credential_process"`, `hb` itself reads the tool's JSON (Version 1) and writes an AWS `config` and `credentials`
  pair, mode 0600, into the session directory, then sets `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`. No converter program
  runs on the host. The agent never sees `~/.aws` or your credential tool.
- Without a format, list `outputs = { VAR = "file" }`: `hb` makes each file mode 0600, sets `VAR` to its path, and removes it at the end.
- Credentials last as long as your tool says (about 11 hours for the one measured): start a new run after that.
- A hook's output files and the whole session directory are removed when the run ends, including after a signal.

**claude on Bedrock.** Add the hook above, put `extends = ["agent/claude"]` in the project, and run
`hb run -- ~/.local/bin/claude`. Expect about 20 s of extra start time: claude's `otelHeadersHelper` and `awsAuthRefresh` from
`~/.claude/settings.json` cannot run inside the ball, so no telemetry is sent, and claude waits for them before it goes on.
claude's temp files go to the run's private directory (`CLAUDE_CODE_TMPDIR`), so `/private/tmp` stays closed.

### Debugging a run

| Want | Use |
|---|---|
| The rules and where each came from | `hb explain` (`--format json` for scripts) |
| Why one path is or is not reachable | `hb explain --path <path>` |
| What the sandbox denied | `hb run --log-denials ...` |
| Every proxy connection with its byte counts | `hb run --log-proxy ...` |
| The generated profile | `hb profile` |
| Whether secrets are exposed | `hb doctor` |

Both log flags print live when stderr is redirected and after the run on a terminal, so an interactive screen is not corrupted
(1000 lines at most). A run that had proxy refusals and no `--log-denials` ends with a one-line warning, which `--no-proxy-summary` hides.

## Reference

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success (`hb explain` with warnings is still 0) |
| 1 | config, load, floor, hook or run-start error (including `hb` started inside another sandbox), printed with its cause chain |
| 2 | usage error |
| 78 | the project's config is not approved; nothing was run. The message tells this apart from a command that exited 78 itself |
| other | `hb run`: the command's own code, or `128 + signal` |

When the command dies of INT, TERM, HUP or KILL, `hb` cleans up and raises the same signal on itself, so a calling shell sees a
signalled child.

### Files and directories

| Path | What |
|---|---|
| `~/.config/hamster-ball/base.toml` | your base config |
| `~/.config/hamster-ball/presets/<name>.toml` | your presets |
| `~/.local/state/hamster-ball/approvals/` | approval records (0700; the agent cannot read or write it) |
| `<project>/hamster-ball.toml` | the project config; read-only inside the ball |
| a private directory under your temp dir | this run's `TMPDIR`, with the hook files and the TLS bundle; removed at exit |

`hb` takes your home from the password database, not `$HOME`, and refuses a mismatch. `XDG_CONFIG_HOME` and `XDG_STATE_HOME` are ignored.

### What the floor always denies

| Effect | Paths (home-relative unless absolute) |
|---|---|
| no read, no write | `.ssh`, `.aws`, `.gnupg`, `.netrc`, `.config/gh`, `.docker`, `.kube`, `Library/Keychains`, `.git-credentials`, `.cargo/credentials*`, `.npmrc`, `.pypirc`, `.pgpass`, `.vault-token`, cloud CLIs (`gcloud`, `azure`, `oci`, `doctl`, ...), 1Password, shell and atuin history, every major browser's profile, container data (`.local/share/containers`, `/var/run/docker.sock`, `/var/run/podman`), and `~/.config/hamster-ball` with `~/.local/state/hamster-ball` |
| no connect | the Docker, Podman, Colima, Lima, Rancher and OrbStack sockets |
| no write | shell startup files, `.gitconfig`, `.config/git`, `.cargo/config*`, `.terraformrc`, `.yarnrc*`, `.m2/settings.xml`, `.config/pip`, `.config/uv`, LaunchAgents, program directories (`~/.local/bin`, `~/.cargo/bin`, `~/go/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, every directory on your `PATH`), `hb` itself, and in the project `hamster-ball.toml` plus git's `hooks` and `config` |

Deny wins over every allow. The list is section 6 of the design. `hb explain` prints the 140-odd rules that apply to your
machine and reports a grant the floor overrides (`grant_shadowed_by_floor`).

### Host services

| Service | Default | Who can change it |
|---|---|---|
| network | none; the proxy and listed loopback ports | any file adds hosts and ports |
| system trust store | on in the generated base | any file may turn it off |
| clipboard writes | on | any file may turn it off |
| internal addresses (`net.internal_hosts`) | none | your own files only |
| `launchctl` | off | your own files may turn it on |

Never available, with no switch: LaunchServices (`open`), Apple Events, setuid programs (`sudo`, `ps`, `top`), the pasteboard tools
(`pbcopy`, `pbpaste`), keystroke injection, `log show`, and signalling a process outside the ball. The agent can still read machine
facts such as `ifconfig`, `hostname` and `sw_vers`; with the proxy as the only way out they cannot leave the machine.

## Troubleshooting

Start with `hb explain` (what is granted) and `hb run --log-denials --log-proxy` (what was refused).

| Symptom | Cause and fix |
|---|---|
| `hb: this project's config has not been approved` (exit 78) | Run `hb approve` in a terminal. Any edit to the project file, or a `git pull` that changes it, asks again. |
| `no hamster-ball.toml found in ... or any parent directory` | Create one in the project root. `hb` never uses the current directory by default. |
| `` `claude` was not found on the PATH the program will have `` | The ball's `PATH` is short. Use the full path (`hb run -- ~/.local/bin/claude`) or add the program to `[env] tools`. |
| `warning: the project directory is not granted`, or `Can't read the current directory (EPERM)` | No grant covers the project. Add `[fs] write = ["."]` to your base (a base made by an older `hb init` lacks it) or to the project file. A grant of a directory inside the project does not count. |
| `` `~/.cache/claude` was not granted: missing `` | An allow rule for a path that does not exist is skipped. Create the directory, or start the agent once outside the ball. |
| `hb: proxy: refused host:443 not_allowed` | The agent asked for a host you have not listed. Add it to `[net] allow` if you trust it. |
| `refused ... (internal_address)` | The name resolves to a private or tunnel address (common for `github.com` behind a corporate tunnel). Add the host to `net.internal_hosts` in your **base**; a project file cannot. |
| `port_not_allowed` | The host is listed on another port. Add `host:port`. |
| TLS errors such as `UNABLE_TO_VERIFY_LEAF_SIGNATURE` or `UNABLE_TO_GET_ISSUER_CERT_LOCALLY` | The network re-signs the host. Keep `tls.system_trust = true`, or give the CA with `tls.extra_ca_files`. kiro-cli and Python ignore Node's variables. |
| A connection shows `allowed ... down=0` and nothing comes back | `hb` connected and the far side sent nothing. Seen once on a corporate tunnel network for about an hour, including for a plain Rust program with no `hb`; the cause was not found. Check the same host with `curl` outside the ball. |
| `hb cannot run inside another sandbox, because sandbox-exec cannot nest` (exit 1) | macOS cannot nest sandboxes. Run `hb` from a shell that is not inside another agent's sandbox (including another `hb`). |
| A file is unreadable inside the ball: `.env`, `*.pem`, `*secret*.yaml` | The secrets guard, by design. Use a template (`.env.example`), pass the value with `[env] pass`, or list an exception in your base. |
| `git push -u`, `git remote add` or `git commit` hooks fail | `.git/config` and `.git/hooks` are write-denied so the agent cannot plant code that git runs outside the ball. Do these outside, and push from your own shell. `git` over HTTPS needs an `allow` entry and has no credentials inside. |
| `podman` or `docker` does nothing, or `launchctl`, `open`, `pbcopy` fail | By design. Use `hb ctl` for the containers and jobs you list ([Containers and launchd jobs](#containers-and-launchd-jobs)); `launchctl` is a base-only switch. |
| `hb ctl restart` says the podman VM shares a directory outside the project | By design (see above). Use a podman machine that shares only the project (see [Containers and launchd jobs](#containers-and-launchd-jobs)), or use `hb ctl stop` and start the container yourself. |
| `hb ctl` says a container is "not pinned when hb started" or "did not pass the checks" | Its mounts or settings are new or unsafe. Fix the container (or its compose file) and start a new `hb run`. |
| An environment variable is missing in the agent | The environment starts empty. Add the name to `[env] pass`, or set a value with `[env] set`. |
| `[env] pass` or `set` rejected | The name is reserved (`HOME`, `PATH`, `TMPDIR`, `TERM`, `HB_*`, `DYLD_*`, `LD_*`, proxy and TLS names). |
| `hooks` or `guard`, `net.internal_hosts` rejected in a project | Those sections are accepted only from your base and your presets. Move them there. |
| A hook fails or times out and nothing starts | The run stops before the agent. Run the hook command by hand to see its error; raise `timeout_secs` (at most 300). |
| claude is about 20 s slower inside the ball | Expected: its OTEL and `awsAuthRefresh` helpers cannot run and it waits for them. |
| claude fails with `AWS authentication failed ... check AWS permissions and model access` | The credentials reached Bedrock but your role cannot invoke the model. The same failure happens outside the ball. |
| `hb doctor` lists a repository below the project, a hook manager or `core.hooksPath` | The floor protects the project's own `.git/hooks` and `.git/config`, not other repositories or a hooks directory the agent can write. A hook there runs outside the ball when you run git. Add `fs.deny_write` for it, or run git in that directory yourself. |
| `hb doctor` lists system proxy settings, or every connection fails behind a corporate proxy | `hb`'s proxy connects directly and does not follow an upstream proxy or PAC. See [Network access](#network-access). |
| `hb doctor` says an MCP server `moves` or has a git source with no full revision | `pkg@latest` (any `@tag` that is not a version) resolves to something new whenever `hb warm` runs again: pin a version (`pkg@1.2.3`). A `git+` source needs `@<40 hex>` (uv) or `#<40 hex>` (npm; its offline start is not measured): find the value with `git ls-remote <url> HEAD`, and use the same argument in the agent's own config. Then run `hb warm`. A package with no version is not flagged: it is whatever the last `hb warm` cached. |
| `warning: mcp server X has not been warmed (or its command changed): run hb warm` | `hb run` starts `uvx` and `npx` servers from hb's own cache with `--offline`, and that cache is empty or was filled for other arguments. Run `hb warm` outside the ball. |
| An MCP server started with `npx` or `uvx` says the package is not available offline | The cache lacks it. Run `hb warm` (it warms exactly the command and arguments in `[mcp.<name>]`, so keep them equal to what the agent runs). A git source needs a pinned revision (`git+https://host/repo@<sha>`): an unpinned one cannot start offline even from a warm cache. |
| `warning: git inside the ball will fail with `unable to access`` | `~/.gitconfig` or `~/.config/git/config` exists and the ball cannot read it, and git treats that as fatal. Add the path to `[fs] read` in your base (`hb init` writes the ones that exist). |
| opencode asks for MCP hosts (`mcp.example.com`) or fails to start `npx` servers | MCP servers in your own opencode config are not part of the preset. Declare each remote one with `[mcp.<name>] net = ["mcp.example.com"]` in your base. A local one that runs `npx` or `uvx` needs the launcher in `[env] tools` and a warm cache: see [MCP servers](#mcp-servers). |
| `hb explain` warns that the approval store location is ignored | `XDG_STATE_HOME` is set; `hb` ignores it on purpose. |
| Grants differ from what you wrote | `hb explain` lists skipped grants (missing path) and floor overrides. |

Still stuck: `hb profile` prints the exact profile, and `hb explain --format json` gives every rule with its origin for a bug report.
Do not paste `[env] set` values or hook arguments into one; `hb explain` hides them unless you pass `--show-args`.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features                       # about 1800 tests; the sandbox ones skip when sandbox-exec is nested
HB_REQUIRE_SANDBOX=1 cargo test --all-features  # fail instead of skipping when the sandbox is not usable
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --lib
```

- The offline MCP servers are proved against the real tools by an opt-in test that uses your home, your `uvx`, `npx` and `node`, hb's real cache and the network:
  `HB_MCP=1 cargo test --features test-support --test mcp_offline -- --nocapture` (variables in [presets/README.md](presets/README.md)). The first run downloads
  about 500 MB into `~/.cache/hamster-ball`; later runs take under a minute.
- `hb ctl` is proved against real podman and launchd by opt-in tests: `HB_PODMAN=1 cargo test --test podman_e2e -- --nocapture` (needs a running podman machine and
  the `alpine` image; add `HB_PODMAN_DIR=<dir>` for a machine created with `--volume <dir>:<dir>` to run the isolated test) and
  `HB_LAUNCHD=1 cargo test --test launchd_e2e -- --nocapture` (loads and unloads one throwaway job).
- The code is a library (`hamster_ball`) and a thin binary (`hb`). `hb-testdrive` is a test-only copy of `hb` that takes its
  environment from variables (feature `test-support`).
- Linting is strict: no `unsafe`, no `unwrap` or `expect` outside tests. Errors use `snafu`. Every file starts with two `ABOUTME:` lines.
- Agent presets are proved against the real agent by an opt-in harness that spends real requests:
  `HB_CONFORMANCE=1 cargo test --features test-support --test conformance -- --nocapture <agent>`. See [presets/README.md](presets/README.md).
- [ref/Hamster-Ball-Design.md](ref/Hamster-Ball-Design.md) is the design: threat model, config schema, the floor, enforcement,
  proxy, presets, test plan and the numbered decision log (D1 to D91). Each "Measured" statement in it comes from a run on a real machine.
- The guide in `docs/` is an [mdBook](https://rust-lang.github.io/mdBook/). Build and read it locally with `cargo install mdbook` then `mdbook serve --open`. `.github/workflows/book.yml` builds it on every change under `docs/` and publishes it to GitHub Pages from `main`. One-time setup: in the repository, Settings, Pages, Source: GitHub Actions.
- Work is tracked with beads (`bd`), epic `hb-ghd`; working notes live in `history/` and are not committed.
