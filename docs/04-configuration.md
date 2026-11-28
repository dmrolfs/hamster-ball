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
Static cloud keys are never passed on purpose. Use a hook; see [Hooks](#hookspre_runname-prepare-files-before-the-agent-starts) and [Getting started](03-getting-started.md#claude-on-bedrock).

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

### `[ctl]`: services the agent may check or restart

Use `[ctl]` when the agent needs a local service while it works, but must not get full control of your computer.

For example, a web app uses a Postgres database in a container.
When its tests fail because the database is down, the agent can run:

```sh
hb ctl ps
hb ctl logs app-db --tail 100
hb ctl restart app-db
```

It cannot run arbitrary `podman` commands, open a shell in the container, create containers or delete them.
`hb` checks each request against your config and runs only a fixed operation.

#### Containers

A **container** is a service, such as a database, running in its own isolated environment.
These settings select which containers the agent may manage:

```toml
# your-project/hamster-ball.toml
[ctl]
containers = ["app-db", "app-redis"]
```

This names two containers exactly, as shown by `podman ps -a`.
The agent can view their status and logs, and start, stop or restart them.

If your project uses Compose, it often labels all of its containers with the project name:

```toml
[ctl]
label = "com.docker.compose.project=shopfront"
```

This allows every container whose label is `com.docker.compose.project=shopfront`.
To see a container's labels, run `podman inspect app-db --format '{{json .Config.Labels}}'` outside the ball.
You can use `label` and `containers` together.

Viewing status and logs works with podman's normal machine.
Starting or restarting a container requires a podman machine that shares only this project, as explained in [Use cases](06-use-cases.md#let-the-agent-restart-a-container).
That requirement prevents code in a container from reaching other host files.

#### launchd jobs

On macOS, **launchd** starts background services, such as a database installed with Homebrew.
Each service has a label.
For Homebrew Postgres 16, the label is commonly `homebrew.mxcl.postgresql@16`.

```toml
# ~/.config/hamster-ball/base.toml
[ctl]
launchd = ["homebrew.mxcl.postgresql@16"]
```

The agent can then run:

```sh
hb ctl launchd status homebrew.mxcl.postgresql@16
hb ctl launchd restart homebrew.mxcl.postgresql@16
```

Find your exact label with `brew services list` or `launchctl list | grep postgresql` outside the ball.
Only your own base config or presets can list launchd jobs.
A project file cannot, because restarting a job runs code on your machine outside the ball.
`status` shows its state, process number, run count and last exit code, never its environment variables.

Rules:

- Container names must match exactly; a name prefix or container ID is not accepted.
- A label must be one `key=value` pair. If more than one config file sets it, every file must use the same value.
- `[ctl]` does not grant network access to a service. If the agent should connect to Postgres on port 5432, also set `[net] loopback_ports = [5432]`.

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

### `[hooks.pre_run.<name>]`: prepare files before the agent starts

A **hook** is a small program you choose.
`hb` runs it on your Mac, outside the ball, immediately before every agent session.
Its job is to prepare something the agent needs, then exit.
The agent does not run the hook, and the hook does not keep running during the session.

Hooks are not Git hooks.
A Git hook runs when you use Git; a hamster-ball hook runs when you start `hb run`.

Use a hook when the agent needs a narrow result, but must not access the source used to create it.
For example, the agent may need a temporary token, but not your password manager, cloud login cache or credential tool.

```text
your Mac, outside the ball
  hook program -> private file in this session
                         |
                         v
agent inside the ball reads only that file through an environment variable
```

When to use one:

| Use a hook to... | Prefer something else when... |
|---|---|
| Create a short-lived credential for one session. | The value is not secret: use `[env] set`. |
| Turn your local credentials into a narrower file. | The agent only needs an existing readable file: use `[fs] read`. |
| Prepare a generated config file. | The work belongs to the agent and is safe inside the ball. |
| Check that a required local setting exists before starting. | It should run repeatedly during the session. Hooks run only once at startup. |

#### How a hook passes results to the agent

Most hooks write files to `HB_HOOK_DIR`, a private directory created for that hook.
`outputs` maps an environment variable to one of those files:

```toml
outputs = { API_TOKEN_FILE = "token" }
```

If the hook writes `$HB_HOOK_DIR/token`, the agent receives `API_TOKEN_FILE=/private/.../token`.
The variable contains the file's path, not the file's contents.
The agent's program must know how to read that file.

A hook can also stop the session.
If it exits with an error or exceeds its time limit, the agent does not start.

#### Example 1: create a short-lived service token file

Suppose a company tool creates a staging-only deployment token that expires after one hour.
You want the agent to call a staging API, but not to see your company login or run that tool.

```sh
#!/bin/sh
# ~/bin/hb-staging-token
set -eu
umask 077
/opt/company/bin/mint-token \
  --service staging-api \
  --scope deploy:read \
  --ttl 1h > "$HB_HOOK_DIR/staging-token"
```

```toml
# ~/.config/hamster-ball/base.toml
[hooks.pre_run.staging]
command = ["~/bin/hb-staging-token"]
outputs = { STAGING_TOKEN_FILE = "staging-token" }
timeout_secs = 20

[net]
allow = ["staging-api.example.com"]
```

A program in the ball can use `$STAGING_TOKEN_FILE`.
The proxy still decides which hosts it can contact.

#### Example 2: give GitHub CLI a limited token file

Some tools read a token from a variable, not from a file path.
For those, prefer a project script that reads the file only for the command that needs it.

```sh
#!/bin/sh
# ~/bin/hb-github-token
set -eu
umask 077
/opt/homebrew/bin/gh auth token > "$HB_HOOK_DIR/github-token"
```

```toml
# ~/.config/hamster-ball/base.toml
[hooks.pre_run.github]
command = ["~/bin/hb-github-token"]
outputs = { GITHUB_TOKEN_FILE = "github-token" }
```

Inside the ball, a command can use it only when needed:

```sh
GH_TOKEN="$(cat "$GITHUB_TOKEN_FILE")" gh pr view 123
```

This example uses your current GitHub CLI login token, which may have broad access.
Use a fine-grained, short-lived token when your workflow supports one.
GitHub CLI also needs `api.github.com` in `[net] allow`.

#### Example 3: create a generated config file

A local tool needs a config containing the current Git commit and an environment name.
The tool does not need a secret; the hook simply prepares the file.

```sh
#!/bin/sh
# ~/bin/hb-tool-config
set -eu
umask 077
commit=$(/usr/bin/git -C "$HOME/work/shopfront" rev-parse HEAD)
cat > "$HB_HOOK_DIR/tool.toml" <<EOF
environment = "local"
commit = "$commit"
EOF
```

```toml
[hooks.pre_run.tool_config]
command = ["~/bin/hb-tool-config"]
outputs = { TOOL_CONFIG = "tool.toml" }
```

The hook runs Git outside the ball.
Review a project's Git configuration and hooks before using a hook like this in a repository the agent can edit.

#### Example 4: stop if a required local service is down

A project's tests need a local database.
This hook succeeds only if Postgres answers, so the agent does not start against a broken environment.

```toml
[hooks.pre_run.database_ready]
command = ["/opt/homebrew/bin/pg_isready", "-h", "127.0.0.1", "-p", "5432"]
timeout_secs = 5
```

This hook creates no files, so it has no `outputs`.
It only allows or blocks the start of the session.

#### Example 5: use AWS temporary credentials

`command` and `format` do different jobs:

- `command` says which program to run.
- `format` says what `hb` should do with what that program prints.

Without `format`, `hb` does not use printed output; use `outputs` for files the hook writes.
The only built-in `format` is `aws_credential_process`.
It expects AWS's standard temporary-credential JSON, such as the output of `aws configure export-credentials`:

```toml
# ~/.config/hamster-ball/base.toml
[hooks.pre_run.aws_dev]
command = ["/opt/homebrew/bin/aws", "configure", "export-credentials", "--profile", "dev-sso", "--format", "process"]
format  = "aws_credential_process"
profile = "dev-sso"
```

`hb` writes private AWS `config` and `credentials` files for profile `dev-sso`.
It sets `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE`.
The agent does not get `~/.aws`, your SSO cache or permission to run the AWS CLI.

#### Settings

| Key | What it means |
|---|---|
| `command` | Program and arguments to run, as a list. Use an absolute path or `~/`; `hb` does not search `PATH` or use a shell. |
| `outputs` | Variables for the agent. Each points to a file the hook wrote in `HB_HOOK_DIR`. |
| `format` | Optional built-in converter for the program's output. Today only `aws_credential_process`. |
| `profile` | AWS profile name; required with `aws_credential_process`, and not allowed otherwise. |
| `timeout_secs` | Maximum run time, from 1 to 300 seconds. The default is 30. |

#### Safety rules

- Only your base config and presets can define hooks. A project file cannot, because hooks run with your normal access.
- Hooks receive only `HOME`, a system `PATH`, `TMPDIR` and `HB_HOOK_DIR`; no input is provided.
- `hb` never displays what a hook prints, and failure messages do not include its output.
- `hb` makes output files private and deletes the whole session directory when the run ends.
- Keep hooks small. Do not have a hook run untrusted project code.
- `hb approve` lists hooks inherited from presets.

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

- `hb approve` shows the project root, each file with a short digest, and everything the project adds beyond your base config, including what its presets grant. It accepts only the typed words `approve` and the code shown with the question, at a terminal.
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
