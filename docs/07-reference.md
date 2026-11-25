<!-- ABOUTME: Guide part 7: reference tables (exit codes, files, environment, the floor, limits, host services) and troubleshooting. -->
<!-- ABOUTME: Look-up material; the explanations are in the earlier documents and the full design is in ref/Hamster-Ball-Design.md. -->

# 7. Reference

- [Exit codes](#exit-codes)
- [Files and directories](#files-and-directories)
- [Environment inside the ball](#environment-inside-the-ball)
- [Every config key](#every-config-key)
- [What the floor always denies](#what-the-floor-always-denies)
- [Host services](#host-services)
- [Limits](#limits)
- [Proxy refusal codes](#proxy-refusal-codes)
- [Corporate networks](#corporate-networks)
- [Troubleshooting](#troubleshooting)
- [Tests and development](#tests-and-development)

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. `hb explain` with warnings is still 0. `hb doctor` always exits 0. |
| 1 | A config, load, floor, hook or run-start error, printed with its cause chain. This includes `hb` started inside another sandbox. For `hb ctl`: the broker refused the request or it failed. |
| 2 | A usage error. For `hb ctl`: there is no broker (no `[ctl]` section, or not inside the ball). |
| 78 | The project's config is not approved. Nothing was run. The message tells this apart from a command that itself exited 78. |
| other | `hb run`: the command's own code, or `128 + signal`. |

When the command dies of INT, TERM, HUP or KILL, `hb` cleans up and raises the same signal on itself, so a calling shell sees a signalled child.

## Files and directories

| Path | What |
|---|---|
| `~/.config/hamster-ball/base.toml` | Your base config. |
| `~/.config/hamster-ball/presets/<name>.toml` | Your presets. |
| `~/.local/state/hamster-ball/approvals/` | Approval records (mode 0700). The agent cannot read or write it. |
| `~/.local/state/hamster-ball/warm/` | Stamps that `hb warm` leaves. The floor hides them from the agent. |
| `~/.cache/hamster-ball/{uv,uv-tools,npm}` | `hb`'s offline package cache, mode 0700. |
| `<project>/hamster-ball.toml` | The project config. Read-only inside the ball. |
| The session directory, under your temp directory | One run's private directory: `TMPDIR`, hook files, the TLS bundle, the `hb` wrapper, the offline launchers and the `hb ctl` socket. Mode 0700. Removed at exit. |

`hb` takes your home from the password database, not from `$HOME`, and refuses a mismatch.
`XDG_CONFIG_HOME` and `XDG_STATE_HOME` are ignored.

## Environment inside the ball

`hb` sets these. Everything else comes from `[env] pass` and `[env] set`.

| Variable | Value |
|---|---|
| `HOME` | Your real home directory. |
| `PATH` | `/usr/bin:/bin:/usr/sbin:/sbin`, then the directory of each `[env] tools` program. With MCP launchers or `hb ctl`, the run's `bin` directory comes first. |
| `TMPDIR` | The session directory. |
| `TERM` | Your `TERM` when stdin is a terminal, else `dumb`. |
| `HB_SESSION` | `1`. A nested `hb` uses it to say it is inside a ball. |
| `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and lowercase forms | The run's proxy, with a random per-run credential. |
| `NO_PROXY`, `no_proxy` | `localhost,127.0.0.1`. |
| `NODE_USE_SYSTEM_CA` | `1`, when `tls.system_trust` is true. |
| `NODE_EXTRA_CA_CERTS` | A bundle of `tls.extra_ca_files`, when any are set. |
| `HB_CTL_SOCKET` | The broker's socket, when `[ctl]` is set. |
| `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` | Set by a hook with `format = "aws_credential_process"`. |

`HOME`, `PATH`, `TMPDIR`, `TERM`, `HB_*`, `DYLD_*`, `LD_*` and the proxy and TLS names cannot be set or passed.

## Every config key

| Section | Key | Type | Who may set it |
|---|---|---|---|
| (top) | `extends` | list of names or paths | any file |
| `[fs]` | `read`, `write` | list of paths | any file |
| `[fs]` | `deny_read`, `deny_write` | list of paths or patterns | any file |
| `[net]` | `allow` | list of `host` or `host:port` | any file |
| `[net]` | `internal_hosts` | list of hosts | your own files only |
| `[net]` | `loopback_ports` | list of ports | any file |
| `[env]` | `pass` | list of names | any file |
| `[env]` | `set` | table of name to value | any file |
| `[env]` | `tools` | list of program names | any file |
| `[tls]` | `system_trust` | true or false | any file may say `false`; `true` is the base default |
| `[tls]` | `extra_ca_files` | list of paths | any file |
| `[terminal]` | `clipboard_write` | true or false | any file may say `false` |
| `[system]` | `launchctl` | true or false | `false` from any file; `true` from your own files only |
| `[ctl]` | `label` | `key=value` | any file; must be equal in every file that sets it |
| `[ctl]` | `containers` | list of container names | any file |
| `[ctl]` | `launchd` | list of launchd labels | your own files only |
| `[mcp.<name>]` | `command`, `args` | string, list | any file |
| `[mcp.<name>]` | `net`, `warm_net` | list of hosts | any file |
| `[mcp.<name>]` | `bind_ports` | list of ports | any file |
| `[hooks.pre_run.<name>]` | `command`, `format`, `profile`, `timeout_secs`, `outputs` | see [Configuration](04-configuration.md#hookspre_runname-host-side-hooks) | your own files only |
| `[guard]` | `exceptions` | list of absolute or `~/` patterns | your own files only |

A key that `hb` does not know is an error that names the file and the key.

## What the floor always denies

| Effect | Paths (relative to your home unless absolute) |
|---|---|
| No read, no write | `.ssh`, `.aws`, `.gnupg`, `.netrc`, `.config/gh`, `.docker`, `.kube`, `Library/Keychains`, `.git-credentials`, `.cargo/credentials*`, `.npmrc`, `.pypirc`, `.pgpass`, `.vault-token`, cloud CLIs (`gcloud`, `azure`, `oci`, `doctl` and others), 1Password, shell and atuin history, every major browser's profile, container data (`.local/share/containers`, `.config/containers`, `/var/run/docker.sock`, `/var/run/podman`), and `~/.config/hamster-ball` with `~/.local/state/hamster-ball` |
| No connect | The Docker, Podman, Colima, Lima, Rancher and OrbStack sockets. A file deny does not stop `connect()`, so these are separate rules. |
| No write | Shell startup files, `.gitconfig`, `.config/git`, `.cargo/config*`, `.terraformrc`, `.yarnrc*`, `.m2/settings.xml`, `.config/pip`, `.config/uv`, LaunchAgents, program directories (`~/.local/bin`, `~/.cargo/bin`, `~/go/bin`, `/opt/homebrew/bin`, `/usr/local/bin`, every directory on your `PATH`), `hb` itself, and in the project `hamster-ball.toml` plus git's `hooks` and `config` |

Deny wins over every allow.
`hb explain` prints the 130-odd rules that apply to your machine and reports a grant the floor overrides (`grant_shadowed_by_floor`).
The full list is section 6 of the [design](../ref/Hamster-Ball-Design.md).

## Host services

| Service | Default | Who can change it |
|---|---|---|
| Network | None. Only the proxy and the loopback ports you list. | Any file adds hosts and ports. |
| System trust store | On in the generated base. | Any file may turn it off. |
| Clipboard writes | On. | Any file may turn it off. |
| Internal addresses (`net.internal_hosts`) | None. | Your own files only. |
| `launchctl` | Off. | Your own files may turn it on. |

Never available, with no switch: LaunchServices (`open`), Apple Events, setuid programs (`sudo`, `ps`, `top`), the pasteboard tools (`pbcopy`, `pbpaste`), keystroke injection, `log show`, and signalling a process outside the ball.
The agent can still read machine facts such as `ifconfig`, `hostname` and `sw_vers`.
With the proxy as the only way out, they cannot leave the machine.

## Limits

| What | Limit |
|---|---|
| A config file | 256 KiB, UTF-8, a regular file you own that is not world-writable |
| Entries in a list | 4096 |
| A path | 1024 bytes |
| A hook's argument vector | 64 words; hook `timeout_secs` 1 to 300, default 30 |
| `bind_ports` | 16 per server, 64 distinct in all, ports 1024 to 65535 |
| MCP server and preset names | 64 bytes |
| Container name | `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` |
| `hb ctl` request | One JSON line, at most 4 KiB; 4 connections at once; 5 seconds to send it |
| `hb ctl` run time | 30 seconds for reads, 60 for changes; a timeout says the outcome is unknown |
| `hb ctl` output | The last 20 KB; `logs --tail` at most 2000 lines |
| `hb ctl` socket path | 103 bytes (a macOS limit) |
| Denial and proxy logs | 1000 lines |
| Secrets guard scan | 100,000 directory entries; at most 256 pinned directories |
| `hb doctor` git survey | 100,000 directory entries; `node_modules`, `site-packages`, `.venv`, `venv` and `target` skipped |
| `hb warm` | 300 seconds per server by default |

Wildcard hosts over a public suffix or a whole cloud domain (`*.github.io`, `*.amazonaws.com`) are refused when the config loads.

## Proxy refusal codes

Every refused request gets a `403` with an `X-Hb-Refusal` header.

| Code | Meaning | What to do |
|---|---|---|
| `not_allowed` | No `allow` entry matches the host. | Add the host if you trust it. |
| `port_not_allowed` | The host is listed, on another port. | Add `host:port`. |
| `internal_address` | The name resolves to a private, tunnel or other internal address. | Add the host to `net.internal_hosts` in your base config. |
| `ip_literal` | The request used an IP address. | Use a name. |
| `unresolved`, `unreachable`, `timed_out` | The name or the route is wrong. | Check the host with `curl` outside the ball. |

The proxy resolves names itself and connects to the address it checked.
It refuses private, tunnel and other internal addresses unless the host is in `net.internal_hosts`.
Loopback, link-local, multicast and reserved addresses stay refused even for listed hosts.
It never opens encrypted traffic.
It keeps no headers or bodies.

## Corporate networks

Measured on a Zscaler client tunnel. Nothing in `hb` is specific to it.

| Need | How |
|---|---|
| TLS inspection re-signs hosts | `tls.system_trust = true`, the base default. For a private CA for Node clients, use `tls.extra_ca_files`. |
| Internal names, or public names such as `github.com`, that resolve to `100.64.0.0/10` or private addresses | List them in `net.internal_hosts` in your base config. |
| Split DNS | Works. The proxy uses the system resolver. |
| An upstream HTTP proxy, a PAC file, NTLM or Kerberos | Not supported. The proxy connects directly. `hb doctor` lists the proxy settings your Mac has on. |

`tls.extra_ca_files` and `NODE_USE_SYSTEM_CA` reach Node clients (pi, claude, opencode's launcher).
kiro-cli ignores both.
Python and `uv` read their own variables. Set one with `[env] set` if you need it.

## Troubleshooting

Start with `hb explain` (what is granted) and `hb run --log-denials --log-proxy` (what was refused).

| Symptom | Cause and fix |
|---|---|
| `hb: this project's config has not been approved` (exit 78) | Run `hb approve` in a terminal. Any edit to the project file, or a `git pull` that changes it, asks again. |
| `no hamster-ball.toml found in ... or any parent directory` | Create one in the project root. `hb` never uses the current directory by default. |
| `` `claude` was not found on the PATH the program will have `` | The ball's `PATH` is short. Use the full path or add the program to `[env] tools`. |
| `warning: the project directory is not granted`, or `Can't read the current directory (EPERM)` | No grant covers the project. Add `[fs] write = ["."]` to your base or the project file. A grant of a directory inside the project does not count. |
| `` `~/.cache/claude` was not granted: missing `` | A grant for a path that does not exist is skipped. Create the directory, or start the agent once outside the ball. |
| `hb: proxy: refused host:443 not_allowed` | The agent asked for a host you have not listed. Add it to `[net] allow` if you trust it. |
| `internal_address` | The name resolves to a private or tunnel address (common for `github.com` behind Zscaler). Add it to `net.internal_hosts` in your base config. A project file cannot. |
| `port_not_allowed` | The host is listed on another port. Add `host:port`. |
| TLS errors such as `UNABLE_TO_VERIFY_LEAF_SIGNATURE` | The network re-signs the host. Keep `tls.system_trust = true`, or give the CA with `tls.extra_ca_files`. kiro-cli and Python ignore Node's variables. |
| A connection shows `allowed ... down=0` and nothing comes back | `hb` connected and the far side sent nothing. Seen once on a Zscaler network for about an hour, also for a plain Rust program with no `hb`. The cause was not found. Check the host with `curl` outside the ball. |
| `hb cannot run inside another sandbox` (exit 1) | macOS cannot nest sandboxes. Run `hb` from a shell that is not inside another agent's sandbox, including another `hb`. |
| A file is unreadable: `.env`, `*.pem`, `*secret*.yaml` | The secrets guard, by design. Use a template, pass the value with `[env] pass`, or list an exception in your base config. |
| `git push -u`, `git remote add` or git hooks fail | `.git/config` and `.git/hooks` are write-denied so the agent cannot plant code that git runs outside the ball. Do these outside, and push from your own shell. Git over HTTPS needs an `allow` entry and has no credentials inside. |
| `warning: git inside the ball will fail with `unable to access`` | `~/.gitconfig` or `~/.config/git/config` exists and the ball cannot read it. Add the path to `[fs] read` in your base config. `hb init` writes the ones that exist. |
| `podman`, `docker`, `launchctl`, `open` or `pbcopy` fail | By design. Use `hb ctl` for the containers and jobs you list. `launchctl` is a base-only switch. |
| `hb ctl` says it is not available | This run has no `[ctl]` section, or you are not inside the ball. |
| `hb ctl restart` says the podman VM shares a directory outside the project | By design. Use a podman machine that shares only the project (see [Use cases](06-use-cases.md#5-create-a-project-only-machine)), or use `hb ctl stop` and start the container yourself. |
| `hb ctl` says a container is "not pinned when hb started" or "did not pass the checks" | Its mounts or settings are new or unsafe. Fix the container or its compose file, and start a new `hb run`. |
| `hb ctl` says a container "is not in the approved scope" or "was not found" | It is not in `[ctl] containers` or the label, or it does not exist on the active podman machine. |
| `hb ctl is busy; try again` | Four requests were already running, or another change to the same container is in progress. |
| An environment variable is missing in the agent | The environment starts empty. Add the name to `[env] pass`, or set it with `[env] set`. |
| `[env] pass` or `set` rejected | The name is reserved (`HOME`, `PATH`, `TMPDIR`, `TERM`, `HB_*`, `DYLD_*`, `LD_*`, proxy and TLS names). |
| `hooks`, `guard`, `net.internal_hosts` or `ctl.launchd` rejected in a project | Those are accepted only from your base config and your presets. Move them there. |
| A hook fails or times out and nothing starts | The run stops before the agent. Run the hook command by hand to see its error. Raise `timeout_secs`, at most 300. |
| claude is about 20 seconds slower in the ball | Expected. Its OTEL and `awsAuthRefresh` helpers cannot run, and it waits for them. |
| claude fails with `AWS authentication failed ... check AWS permissions and model access` | The credentials reached Bedrock but your role cannot invoke the model. The same failure happens outside the ball. |
| `warning: mcp server X has not been warmed (or its command changed): run hb warm` | The offline cache is empty or was filled for other arguments. Run `hb warm` outside the ball. |
| An MCP server started with `npx` or `uvx` says the package is not available offline | The cache lacks it. Run `hb warm`, with the arguments in `[mcp.<name>]` equal to what the agent runs. A git source needs a pinned revision (`git+https://host/repo@<sha>`). |
| `hb doctor` says an MCP server `moves`, or has a git source with no full revision | `@latest` or any non-version tag resolves to something new each time `hb warm` runs. Pin a version (`pkg@1.2.3`). A `git+` source needs `@<40 hex>` for uv, or `#<40 hex>` for npm. Find the value with `git ls-remote <url> HEAD`. |
| `hb doctor` lists a repository below the project, a hook manager or `core.hooksPath` | The floor protects the project's own `.git/hooks` and `.git/config`, not other repositories or a hooks directory the agent can write. A hook there runs outside the ball when you run git. Add `fs.deny_write` for it, or run git in that directory yourself. |
| `hb doctor` lists system proxy settings, or every connection fails behind a corporate proxy | `hb`'s proxy connects directly and does not follow an upstream proxy or PAC. |
| opencode asks for MCP hosts or fails to start `npx` servers | MCP servers in your opencode config are not part of the preset. Declare each with `[mcp.<name>]`. A local one that runs `npx` or `uvx` needs the launcher in `[env] tools` and a warm cache. |
| `hb explain` warns that the approval store location is ignored | `XDG_STATE_HOME` is set. `hb` ignores it on purpose. |
| Grants differ from what you wrote | `hb explain` lists skipped grants (missing path) and floor overrides. |

Still stuck: `hb profile` prints the exact profile, and `hb explain --format json` gives every rule with its origin for a bug report.
Do not paste `[env] set` values or hook arguments into one. `hb explain` hides them unless you pass `--show-args`.

## Tests and development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features                       # about 1800 tests; sandbox tests skip when sandbox-exec is nested
HB_REQUIRE_SANDBOX=1 cargo test --all-features  # fail instead of skipping when the sandbox is not usable
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --lib
```

Opt-in suites use real tools:

| Variable | Suite | Needs |
|---|---|---|
| `HB_CONFORMANCE=1` | One question per agent preset against the real agent | The installed agent, logged in. Spends real requests. |
| `HB_MCP=1` | Real MCP servers start offline after `hb warm` | Your `uvx`, `npx`, `node` and the network. The first run downloads about 500 MB. |
| `HB_PODMAN=1` | `hb ctl` against real podman | A running podman machine and the `alpine` image. |
| `HB_PODMAN_DIR=<dir>` | The container swap test | A machine created with `--volume <dir>:<dir>` and no other share. |
| `HB_LAUNCHD=1` | `hb ctl launchd` against real launchd | Loads and unloads one throwaway job. |

Commands and details are in [presets/README.md](../presets/README.md).
The code is a library (`hamster_ball`) and a thin binary (`hb`).
Lints are strict: no `unsafe`, no `unwrap` or `expect` outside tests, errors use `snafu`, and every file starts with two `ABOUTME:` lines.

Back to the [index](README.md).
