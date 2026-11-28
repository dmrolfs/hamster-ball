<!-- ABOUTME: How to write a built-in agent preset and how to prove it against the real agent. -->
<!-- ABOUTME: Presets are ordinary config files embedded in hb; the conformance harness is opt-in and spends real model requests. -->
# Built-in presets

A preset is an ordinary `hamster-ball.toml` fragment (design section 4) that a project pulls in with
`extends = ["agent/kiro"]`. Built-in presets are compiled into `hb`, so they need no file on the user's
machine, are never approved or hashed, and are the only files besides the user's own that may carry
user-only settings (4.2). They are written by hand from what the agent was measured to need; nothing is
generated from denial logs, because the system log is incomplete.

## Where they live

| What | Where |
|---|---|
| The file | `presets/agent/<name>.toml` (name in lower case, `-` allowed) |
| The registration | one line in `EMBEDDED` in `src/config/builtin.rs`: `("agent/<name>", include_str!("../../presets/agent/<name>.toml")),` (keep the table sorted) |
| The checks | `cargo test` fails if a file is not registered, if the table is unsorted, or if a preset is not valid config |

## What goes in one

Only what the agent needs for *itself*:

- `fs.read`: its install tree (the binary, its runtime, a Node install if it is a script).
- `fs.write`: its own state, cache and login directories, and no wider than it needs (`~/.pi/agent`, not `~`).
- `net.allow`: the hosts the agent contacts for its own service, one entry each (`host`, or `host:port` for a port other than 443).
  Never a wildcard over a shared suffix (`*.amazonaws.com` is refused at load time).
- `env.tools`: programs it needs found on `PATH` (a `#!/usr/bin/env node` script needs `node`).
- A header comment with the agent and version it was measured against, the date, and anything surprising
  (a probe that is denied harmlessly, a variable it ignores).

Not in a preset: a model provider's host or gateway (user config), MCP servers' hosts (`[mcp.*]`), credentials or
paths the floor protects, and `net.internal_hosts` or `system.launchctl` (settings that only a user should turn on).

## State, login and persistence

A preset gives the agent a write grant on its own home, and that home mixes two kinds of file: what the agent needs to write
(history, caches) and what a plain run of the same agent later executes outside the sandbox (hooks, plugins, settings that name
programs). A write to the second kind changes what a later, unconfined run does (hb-tx4 F10, F14). So every shipped preset
lists the second kind in `deny_write`, and a test (`tests/executable_state.rs`) fails if one is reopened.

| Agent (measured version) | Read-only inside hb | Writable: history | Writable: login and other state | Not measured |
|---|---|---|---|---|
| claude 2.1.328 | `settings.json`, `~/.claude.json`, `hooks`, `plugins`, `commands`, `agents`, `shell-snapshots` | `projects`, `sessions`, `history.jsonl` | Bedrock credentials come from your own `pre_run` hook, not from a file here | interactive use: onboarding, `/config`, OAuth refresh, the Bash tool's shell snapshot |
| pi 1.7.0 | `settings.json`, `models.json`, `models-store.json`, `trust.json`, `extensions`, `npm`, `git`, `agents`, `bin`, `install` | `sessions` | `auth.json` (so a refresh can work) | whether pi treats `auth.json` or its other files as code; a provider that needs a denied file |
| kiro-cli 3.6.2 | `run/chat-cli-*`, `shell-integration-backup`, `~/.kiro/settings`, `~/.kiro/agents`, `bun`, `bunfig.toml`, `kas`, `node`, `tui.js` | `~/.kiro/sessions` | `data.sqlite3` holds the login token and conversations in one file, so it stays writable and is not protected | a token refresh with the file write-denied |
| opencode 1.2.0 | `~/.config/opencode`, the plugin cache files, `~/.local/share/opencode/bin` | `~/.local/share/opencode`, `~/.local/state/opencode` | `auth.json` is in `~/.local/share/opencode`, so the agent can read it | the whole row: opencode was not installed when this was last checked |

What this does not do:

- It does not make files the agent can still write safe. `data.sqlite3` (kiro) is the one row the presets leave open on purpose; a
  test pins that set, so adding another needs an owner decision.
- It does not check what is already on disk. Hooks or plugins that were planted before you used these presets are still there.
  Reinstall the agent from its distributor outside `hb`, and review `settings.json`, `hooks` and `plugins`. `hb` never rewrites a
  host agent home and never copies a change from a run back into it.
- "History stays usable" means `hb` does not deny the history paths. It does not mean every agent resumes every session. Measured: a
  `claude -p` run wrote its transcript and a kiro chat wrote a session while the denies were on, and pi's `sessions` is outside every deny.
  Resuming a session was not exercised.
- A deny that breaks something you rely on cannot be undone from inside `hb`: a deny wins over any broader `[fs] write` grant.
  Do that one action outside `hb` (install a plugin, trust a folder, log in again).

## Measuring

```sh
hb run --log-denials --log-proxy -- <agent> <one non-interactive question>
```

`--log-denials` shows what the sandbox and the proxy refused; `--log-proxy` shows every connection with its bytes. The
sandbox's denial lines are hints for you to read, never rules to copy.

## Proving a preset against the real agent

```sh
HB_CONFORMANCE=1 cargo test --features test-support --test conformance -- --nocapture
```

Each installed agent that has a preset is asked one question under the real profile and proxy. It passes when it answers
as its criterion says and every host it asked for is allowed (a refused connection fails the check and names the host).
An agent that is not installed, or has no preset yet, is skipped. On a failure the output shows the agent's last lines and every denial.

| Agent | Criterion |
|---|---|
| kiro-cli | exits 0 and prints `OK` |
| pi | exits 0 and prints `OK` |
| claude | a connection to `bedrock-runtime.*` is served, and `OK` is printed if it exits 0 (a failed exit is not judged: the account may deny the model) |
| opencode | exits 0 and prints `Invalid credential`: the harness sets a made-up `OPENCODE_API_KEY`, so a model request goes through the proxy and `opencode.ai` answers 401 (no provider needed, no free-tier request spent) |

The run uses the real home directory (the agent's login is there) but not your `~/.config/hamster-ball`: a private user
config holds only what the variables give it, so a result depends on the preset.

| Variable | Meaning |
|---|---|
| `HB_CONFORMANCE=1` | turn the checks on |
| `HB_CONFORMANCE_PROJECT=<file>` | appended to the throwaway project's config: what the preset leaves to you (a provider host in `[net] allow`, a gateway port in `loopback_ports`). No `extends` |
| `HB_CONFORMANCE_BASE=<file>` | the private user base config (default: `[tls] system_trust = true`); put `net.internal_hosts` for your network and `tls.extra_ca_files` for a private gateway CA here |
| `HB_CONFORMANCE_TIMEOUT=<seconds>` | the limit for one agent (default 180) |
| `HB_CONFORMANCE_ARGS_<AGENT>="..."` | replaces the agent's arguments (`AGENT` in upper case, `-` as `_`) |

Example for pi against a remote gateway with a private CA (`provider.toml` is the project file, `base.toml` the base):

```sh
# provider.toml:   [net]
#                  allow = ["gateway.example.com"]
# base.toml:       [tls]
#                  system_trust = true
#                  extra_ca_files = ["~/.config/gateway/ca.pem"]
HB_CONFORMANCE=1 HB_CONFORMANCE_PROJECT=provider.toml HB_CONFORMANCE_BASE=base.toml \
  cargo test --features test-support --test conformance -- --nocapture pi
```

## Proving the MCP servers offline

```sh
HB_MCP=1 cargo test --features test-support --test mcp_offline -- --nocapture
```

Warms the servers a user has measured (time, fetch, reddit, ripgrep, browsermap, sequential-thinking, and serena at a pinned revision) with the code of `hb warm`,
then starts each in the ball through hb's offline launchers and checks it answers an MCP `initialize` with no proxy connection (serena: no allowed one). It also
checks that every server is reported cold before warming and that an uncached package fails with the tool's own words. It uses your home, your `uvx`/`npx`/`node`,
hb's real cache `~/.cache/hamster-ball` (the first run downloads about 500 MB) and the network, and removes the stamps it makes.

| Variable | Meaning |
|---|---|
| `HB_MCP=1` | turn the check on |
| `HB_MCP_SERVERS=time,fetch,serena` | only these (default: all that this machine can run) |
| `HB_MCP_BASE=<file>` | appended to the private base config: `net.internal_hosts` for a corporate network (github.com, api.github.com, raw.githubusercontent.com) |
| `HB_MCP_PROJECT=<file>` | appended to the throwaway project config |
| `HB_MCP_TIMEOUT=<seconds>` | the limit for one server (default 300) |
| `HB_MCP_SERENA_REV=<40 hex>` | serena's revision (default: HEAD, from `git ls-remote`) |

An agent that starts MCP servers from your own config (opencode reads `~/.config/opencode/opencode.json`) asks for their hosts too,
and the check fails on each one the preset does not allow. For a check on such a machine, list them in the project file, and put a
host that resolves to a private address (a corporate proxy's range) in `net.internal_hosts` of the base file:

```sh
# project.toml:  [net]
#                allow = ["mcp.example.com", "github.com"]
# base.toml:     [tls]
#                system_trust = true
#                [net]
#                internal_hosts = ["github.com"]
HB_CONFORMANCE=1 HB_CONFORMANCE_PROJECT=project.toml HB_CONFORMANCE_BASE=base.toml \
  cargo test --features test-support --test conformance -- --nocapture opencode
```

Some criteria need a variable the agent cannot get without a provider (opencode's made-up key). The harness sets those itself in
`Agent::env`; they reach only the sandboxed run.

## Proving `hb ctl` against real podman and launchd

Two opt-in suites run the broker, preflight and pins against the real tools. Neither needs an agent or a network beyond pulling `alpine`.

```sh
HB_PODMAN=1 cargo test --test podman_e2e -- --nocapture --test-threads=1
HB_LAUNCHD=1 cargo test --test launchd_e2e -- --nocapture
```

`podman_e2e` needs a running podman machine and the `docker.io/library/alpine` image. It starts two labelled containers and one named one, then checks
`ps`, `logs`, `stats` and `stop`, that an unlabelled container and `run`, `exec` and `cp` are refused, that the VM's SSH port is open outside the ball and
closed inside it, and that `restart` is refused when the machine shares more than the project. Every container it makes is named `hb-m8-<pid>-...` and is
removed at the end, also after a failure.

| Variable | Meaning |
|---|---|
| `HB_PODMAN=1` | turn the suite on |
| `HB_PODMAN_DIR=<dir>` | the directory the active podman machine shares and nothing else (made with `podman machine init --volume <dir>:<dir>`); runs the test where the agent swaps a mount source for a link and `restart` must not expose a canary. Without it that test skips |

`launchd_e2e` loads one throwaway job into your own launchd, checks `hb ctl launchd status` and `restart`, that the job's environment never appears and that `launchctl`
itself is denied, then removes the job.
