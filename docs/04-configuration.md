<!-- ABOUTME: Guide part 4: the config files, how layers combine, every setting with an example, presets, hooks and MCP servers. -->
<!-- ABOUTME: Task-oriented explanation first; the closed list of every key and limit is in 07-reference.md. -->

# 4. Configuration

## The idea

You say what the agent may reach, in TOML.
You write it in up to three places, and `hb` merges them.

| Where | File | Purpose |
|---|---|---|
| Your base | `~/.config/hamster-ball/base.toml` | What every project gets, and the settings only you may make. |
| A preset | built in, or `~/.config/hamster-ball/presets/<name>.toml` | A reusable piece, such as what kiro-cli needs. |
| The project | `hamster-ball.toml` in the project root | What this project adds. |

Under all of them sits the floor, which is built into `hb` and cannot be changed.

## How layers combine

- Lists are unioned. A project adds entries and cannot remove one.
- A `deny` from any layer beats any allow from any layer.
- Maps, such as `env.set`, merge by key. The same key with two different values is an error that names both files.
- Switches never loosen. `tls.system_trust`, `terminal.clipboard_write` and `system.launchctl` are `false` if any file says `false`.
- Some settings run code on your machine or switch a protection off. Only files that are yours (your base config and your presets) may set them: `hooks`, `guard.exceptions`, `net.internal_hosts`, `ctl.launchd` and `system.launchctl = true`. A project file that has one is an error that names the file.
- Relative paths mean the project root, in every layer. `write = ["."]` in a preset means the project. `~` and `~/...` are the only home forms. There is no `$VAR` expansion. Patterns in `deny_read` and `deny_write` may use `*`, `?` and `**`.
- `hb` refuses a grant that is too broad: `/`, your home directory, a directory above it, or a path with fewer than two parts. `/` and `/Users` are refused. `~/work` and `/opt/data` are accepted. A relative path such as `.` is judged after it is resolved to the project's full path.
- A grant for a path that does not exist is skipped, and `hb explain` and `hb run` say so. Create the directory first.

## A complete example

```toml
# hamster-ball.toml in the project root
extends = ["agent/kiro", "my-team"]     # my-team is a preset you wrote yourself; see Presets below

[fs]
read       = ["~/work/shared-fixtures"]     # read only
write      = ["."]                          # read and write; "." is the project
deny_read  = ["config/*.secrets.yaml"]      # also blocks write, delete and rename
deny_write = ["~/.pi/agent/bin"]            # reads stay as granted

[net]
allow          = ["crates.io", "*.example.com", "git.example.com:8443"]
loopback_ports = [5432, 9001]               # services you started yourself

[env]
pass  = ["LANG", "COLORTERM"]               # copied from your shell
set   = { RUST_BACKTRACE = "1" }            # fixed values
tools = ["node", "git"]                     # programs found on your PATH

[terminal]
clipboard_write = true
```

## The sections

### `extends`

```toml
extends = ["agent/pi", "my-team"]
```

Names the presets to merge in.
A name is a built-in preset, a file at `~/.config/hamster-ball/presets/<name>.toml`, or a path to a TOML file.
Presets may extend presets.

### `[fs]`: files

| Key | Meaning |
|---|---|
| `read` | Directories or files the agent may read. |
| `write` | Directories or files the agent may read and write. `"."` is the project. |
| `deny_read` | Paths or patterns the agent may not read, write, delete or rename. |
| `deny_write` | Paths or patterns the agent may read but not change. |

The project is not granted on its own.
`write = ["."]` comes from a file, normally your base config, and `hb init` writes it.
With no grant over the project directory, the agent cannot read it, and `hb explain` and `hb run` say what to add.

### `[net]`: network

| Key | Meaning |
|---|---|
| `allow` | Hosts the proxy lets through. A host name, `*.suffix`, or either with `:port`. The default port is 443. |
| `internal_hosts` | Hosts whose names may resolve to private addresses. Your own files only. |
| `loopback_ports` | Ports on this machine that the agent may reach directly. For services you started yourself. |

A host entry is a name and never an IP address.
Wildcards over a public suffix or a whole cloud domain, such as `*.github.io` or `*.amazonaws.com`, are refused when the config loads.
List the exact hosts.

`internal_hosts` matters on a corporate network.
A corporate tunnel can make a public name, like `github.com`, resolve to a private address.
The proxy refuses private addresses by default.
List the host in `internal_hosts` in your base to allow it.

`hb run` warns at start if a port in `loopback_ports` has nothing listening.

### `[env]`: environment

The agent starts with an empty environment.
`hb` sets `HOME`, `PATH`, `TMPDIR`, `TERM`, `HB_SESSION=1`, the proxy variables and the TLS variables.
Everything else you ask for.

| Key | Meaning |
|---|---|
| `pass` | Names copied from your shell. |
| `set` | Names with fixed values. `{session_dir}` in a value is the session directory. |
| `tools` | Programs found on your `PATH` when `hb` starts. Their directories are added to the agent's `PATH` and made readable. |

`HOME`, `PATH`, `TMPDIR`, `TERM`, `HB_*`, `DYLD_*`, `LD_*` and the proxy and TLS names cannot be set or passed.
`set` wins over `pass`, and a hook's variable wins over `set`.
`hb explain` never prints a `set` value.
Static cloud keys are never passed on purpose. Use a hook; see [Hooks](#hookspre_runname-host-side-hooks) and [Getting started](03-getting-started.md#claude-on-bedrock).

### `[tls]`: certificates

| Key | Meaning |
|---|---|
| `system_trust` | Trust the macOS system certificates. Keep it `true` on a network that re-signs TLS. It sets `NODE_USE_SYSTEM_CA=1`. `hb init` writes `true`. |
| `extra_ca_files` | Private certificate authorities. `hb` makes a bundle and sets `NODE_EXTRA_CA_CERTS` to it. |

These variables reach Node programs: pi, claude and opencode's launcher.
kiro-cli ignores both.
Python and `uv` read their own variables, which you can set with `[env] set`.

### `[terminal]`

| Key | Meaning |
|---|---|
| `clipboard_write` | `false` removes the agent's attempts to set your clipboard through the terminal. The default is `true`. |

### `[system]`

| Key | Meaning |
|---|---|
| `launchctl` | `true` lets the agent run `launchctl`. Your own files only. The default is `false`. |

Turning `launchctl` on lets the agent start, unload and disable launchd jobs that are not running, and read your launchd service list. It cannot create jobs, and it cannot restart or unload a job that is running.
Prefer `[ctl] launchd`, which allows named jobs only.

### `[ctl]`: containers and launchd jobs

```toml
[ctl]
label      = "com.docker.compose.project=myapp"   # every container with this label
containers = ["app-db"]                       # and these, by exact name
launchd    = ["com.example.postgres"]                # your own files only
```

This tells `hb ctl` what the agent may look at and restart.
The label must be `key=value`, and it must be the same in every file that sets it, so a project cannot widen the scope your base gave.
Container names are those that `podman ps -a` shows.
The `launchd` list is for launchd job labels. Only your own files can set it.

To use `hb ctl restart`, you also need a podman machine that shares only the project.
See [Use cases](06-use-cases.md#let-the-agent-restart-a-container).

### `[mcp.<name>]`: MCP servers

```toml
[env]
tools = ["uvx", "npx", "node"]

[mcp.time]
command = "uvx"
args    = ["mcp-server-time"]                    # the same command and arguments the agent runs

[mcp.context7]                                   # a remote server: no command
net = ["mcp.context7.com"]                       # the host it needs at run time; joins net.allow
```

| Key | Meaning |
|---|---|
| `command` | The program the agent starts for this server. |
| `args` | Its arguments. |
| `net` | Hosts needed while running. They join `net.allow`. |
| `warm_net` | Hosts only `hb warm` may reach for this server, beside the package registries. Never allowed at run time. |
| `bind_ports` | Ports the server may listen on, from 1024 to 65535, at most 16 for one server. |

If the command is `uvx` or `npx`, run `hb warm` once, outside the ball, to download the packages.
After that, `hb run` puts launchers for `uvx` and `npx` first on the agent's `PATH`.
They start the real tool with `--offline` and `hb`'s own cache, so the server starts with no network.
Run `hb warm` again after you change a server's arguments.
`hb doctor` flags servers that are not warmed, that use a moving version such as `@latest`, or that use an unpinned git source.

Pin versions.
`pkg@1.2.3` is fine.
A `git+` source needs a full revision, such as `@<40 hex>`.

### `[hooks.pre_run.<name>]`: host-side hooks

```toml
# ~/.config/hamster-ball/base.toml
[hooks.pre_run.bedrock]
command      = ["~/ai-coding/credential-process", "--profile", "my-profile"]
format       = "aws_credential_process"
profile      = "my-profile"
timeout_secs = 30                         # 1 to 300
```

A hook runs a program of yours on your machine, outside the ball, before the agent starts.
Only your base config and your presets can define one.

| Key | Meaning |
|---|---|
| `command` | The program and its arguments, as a list. No shell. The program is an absolute path or starts with `~/`. |
| `format` | `aws_credential_process` makes `hb` turn the tool's JSON into AWS config files. Leave it out to use `outputs`. |
| `profile` | The AWS profile name that the agent selects. Used with `format = "aws_credential_process"`. |
| `timeout_secs` | 1 to 300. The default is 30. |
| `outputs` | A table of variable name to file name. `hb` makes each file mode 0600 and sets the variable to its path. |
`command` runs with a scrubbed environment and a time limit that kills its process group.
A hook that fails stops the run before the agent starts.

- With `format = "aws_credential_process"`, `hb` reads the tool's JSON output itself and writes an AWS `config` and `credentials` pair, mode 0600, into the session directory. It sets `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`. No converter program runs.
- Without a format, list `outputs = { VAR = "file" }`. `hb` makes each file mode 0600, sets `VAR` to its path and removes it at the end.

A project that extends one of your presets runs that preset's hooks.
`hb approve` lists them.

### `[guard]`

| Key | Meaning |
|---|---|
| `exceptions` | Absolute or `~/` patterns that switch the secrets guard off for matching files. Your base and presets only. |

## The secrets guard

The guard is always on.
Below every directory the agent may write, at any depth, these names cannot be read, written, renamed, deleted or hard-linked: `.env`, `.env.*`, `*secret*.yaml|yml|json|toml`, `*.pem`, `*.key` and `*.p12`.
Names stay visible, so `ls` works. Contents do not.

- Templates (`*.example`, `*.sample`, `*.template`) stay editable.
- Files that git tracks are skipped, because the agent can read them with `git show` anyway. `hb doctor` lists them.
- Key and certificate files below `node_modules` and `site-packages` (not `.env*`) are usable, so `pip install` and `rm -rf node_modules` work. `hb` pins the directories that hold them against rename. A directory that gets its first key after `hb` starts is not pinned.
- Add project patterns with `fs.deny_read`.
- To switch the guard off for one file, list its absolute or `~/` pattern in `[guard] exceptions` in your base config. A project cannot.
- A secret with an unusual name is not caught. `hb doctor` lists look-alikes such as `.netrc`, `id_rsa`, `*.tfvars`, `*.tfstate` and files with `token`, `password` or `api key` in the name. It lists names only.

## Presets

Built into `hb`: `agent/kiro`, `agent/pi`, `agent/claude`, `agent/opencode`.
Each lists only the agent's own state and hosts.
No preset names a model provider or an MCP server.

| Preset | Writes | Hosts | You still add |
|---|---|---|---|
| `agent/kiro` | `~/.kiro` and kiro-cli's own directory, but not its programs | `app.kiro.dev` and five more | Nothing |
| `agent/pi` | `~/.pi/agent`, but not `bin` and `install` | None | Your provider's host or gateway port, and its CA if private |
| `agent/claude` | `~/.claude`, `~/.claude.json` and caches; its install is read only | Bedrock, Bedrock runtime and STS in us-east-1 | A credential hook in your base |
| `agent/opencode` | `~/.local/share/opencode` and caches | `models.dev`, `opencode.ai` | Hosts for your MCP servers |

Preset grants for programs the agent could replace are write-denied on purpose.
A plain `claude` or `pi` that you run outside the ball must never run something the agent planted.
Keep that in mind if you widen a write grant over an install directory.

To write your own, create `~/.config/hamster-ball/presets/<name>.toml` and use `extends = ["<name>"]`.
A team preset with `[fs] write = ["."]` and the hosts your toolchain needs saves repeating them.
How to measure and check a preset is in [presets/README.md](https://github.com/dmrolfs/hamster-ball/blob/main/presets/README.md).

## Approval

A project's `hamster-ball.toml`, and any file it extends from inside the project, can be changed by the agent or by a `git pull`.
So `hb run` runs them only when their exact bytes were approved.

- `hb approve` shows the project root, each file with a short digest, and everything the project adds beyond your base config, including what its presets grant. It accepts a typed `y` or `yes`, at a terminal.
- Any change to a byte, or a renamed, added or removed file, asks again. Moving the project asks again.
- Approval records live in `~/.local/state/hamster-ball/approvals/`, which the floor hides from the agent.
- Without a terminal, an unapproved config exits with code 78 and runs nothing.
- Your base and your own presets are not hashed, because they are outside the ball's reach. Built-in presets are part of the `hb` you installed.

## Seeing the result

```sh
hb explain                     # every rule and the file it came from
hb explain --format json       # the same, for scripts
hb explain --path <path>       # why one path can or cannot be reached
hb profile                     # the exact Seatbelt profile
```

Next: [Commands](05-commands.md).
