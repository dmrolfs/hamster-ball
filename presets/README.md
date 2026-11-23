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
| claude | exits 0 and a connection to `bedrock-runtime.*` is served |
| opencode | exits as the same command does without the sandbox |

The run uses the real home directory (the agent's login is there) but not your `~/.config/hamster-ball`: a private user
config holds only what the variables give it, so a result depends on the preset.

| Variable | Meaning |
|---|---|
| `HB_CONFORMANCE=1` | turn the checks on |
| `HB_CONFORMANCE_PROJECT=<file>` | appended to the throwaway project's config: what the preset leaves to you (a provider host in `[net] allow`, a gateway port in `loopback_ports`). No `extends` |
| `HB_CONFORMANCE_BASE=<file>` | the private user base config (default: `[tls] system_trust = true`); put `net.internal_hosts` for your network here |
| `HB_CONFORMANCE_TIMEOUT=<seconds>` | the limit for one agent (default 180) |
| `HB_CONFORMANCE_ARGS_<AGENT>="..."` | replaces the agent's arguments (`AGENT` in upper case, `-` as `_`) |
