<!-- ABOUTME: Guide part 3: install, the first config, the first run, and using hb with kiro-cli, pi, claude, opencode or any command. -->
<!-- ABOUTME: Step by step for a new user; each step says what to type and what you should see. -->

# 3. Getting started

## What you need

These steps assume you use a terminal and have built a Rust program before.

- A Mac with Apple silicon. `hb` was built and measured on macOS 15.7.
- Rust 1.85 or newer, to build `hb`. If you do not have it, install it with [rustup](https://rustup.rs).
- An agent you already use. Log in to it outside the ball first, because the ball has no browser and cannot open one.

`hb` uses `/usr/bin/sandbox-exec`, which ships with macOS.
`hb` refuses to run as root, and refuses to start inside another sandbox (macOS cannot nest sandboxes).

## Install

```sh
git clone https://github.com/dmrolfs/hamster-ball
cd hamster-ball
cargo install --path .
hb --version
```

Put `hb` in a directory that the agent cannot write.
The floor blocks writes to every directory on your `PATH` and to `hb` itself.
`~/.cargo/bin`, where `cargo install` puts it, is fine.

## First run in five steps

### 1. Create your base config

The base config applies to every project, and only you can edit it.

```sh
hb init
```

This writes `~/.config/hamster-ball/base.toml`. It never overwrites an existing file.
The file is commented. It contains a few settings you should know about:

| Setting | What it does |
|---|---|
| `[fs] write = ["."]` | Grants read and write on the project. A project is neither readable nor writable until a file grants it, and this line is that grant. |
| `[tls] system_trust = true` | Trusts the system certificate store. Keep it on if your network inspects TLS (Zscaler and similar). |
| `read` entries for `~/.gitconfig` and `~/.config/git` | Added only if those exist. Git fails every command if it cannot read its own config. |
| `[env] pass = ["LANG", "COLORTERM"]` | Copies these two variables from your shell. |

### 2. Describe the project

In the project's root directory, create `hamster-ball.toml`:

```toml
extends = ["agent/kiro"]
```

`extends` pulls in a preset: the paths and hosts the agent itself needs.
Use `agent/kiro`, `agent/pi`, `agent/claude` or `agent/opencode`.
Add more settings here as the project needs them (see [Configuration](04-configuration.md)).

`hb` uses the first `hamster-ball.toml` it finds in the current directory or above it.
If there is none, it stops with an error.
It never uses the current directory as a fallback.

### 3. Look at what you are granting

```sh
hb explain
```

This prints every effective rule and the file it came from.
Read it once.
To see why one path can or cannot be reached:

```sh
hb explain --path ~/.ssh/id_rsa
```

### 4. Approve the project

```sh
hb approve
```

`hb` shows the project root, the files covered, and everything the project adds beyond your base.
Type `y` to approve.
The approval is tied to the exact bytes of the config.
If anyone edits the file, `hb run` asks again.

This step needs a real terminal. There is no `--yes` flag.

### 5. Run the agent

```sh
hb run -- "$(command -v kiro-cli)" chat
```

Everything after `--` is the command to run.
The agent starts inside the ball.
When it exits, `hb` cleans up and exits with the agent's exit code.

`$(command -v kiro-cli)` is shell syntax that expands to kiro-cli's full path.
The ball has a short `PATH`, which is the list of directories searched for programs, so it often cannot find a program by name.
Use the full path, as above, or list the program in `[env] tools`.

## If something fails

Run with logs on, to see what was refused:

```sh
hb run --log-denials --log-proxy -- "$(command -v kiro-cli)" chat
```

- `hb: denied: ...` lines are files or services the sandbox refused.
- `hb: proxy: refused host:443 not_allowed` lines are hosts the proxy refused. Add the host to `[net] allow` if you trust it.

The macOS denial log is not complete, so do not turn every line into a rule without testing.
For more, see [Troubleshooting](07-reference.md#troubleshooting).

Also run `hb doctor` once per project.
It lists secret-looking files the guard does not cover, git hooks the floor does not protect, and other things `hb` cannot see.

## Using hb with an agent

An agent runs the same way as any program: put `hb run --` in front of it.
What differs is what each agent needs, and that is what its preset provides.

| Agent | Preset | Command | You still add |
|---|---|---|---|
| kiro-cli | `agent/kiro` | `hb run -- "$(command -v kiro-cli)" chat` | Nothing. |
| pi | `agent/pi` | `hb run -- "$(command -v pi)"` | Your model provider's host, or the loopback port of a gateway on your machine, and its CA file if the gateway uses a private CA. |
| claude | `agent/claude` | `hb run -- ~/.local/bin/claude` | A credential hook in your base config (see below). |
| opencode | `agent/opencode` | `hb run -- "$(command -v opencode)"` | Hosts for any MCP servers you use. |
| Any other command | none | `hb run -- <command>` | Whatever it reads, writes and contacts. |

Each preset file in [`presets/agent/`](../presets/agent) opens with a note on what was measured, what is denied and harmless, and what is not proven.

### pi

pi has no model host in its preset, because the provider is yours.
For a gateway on your machine, add the port to your project config:

```toml
extends = ["agent/pi"]

[net]
loopback_ports = [18089]
```

For a remote gateway, add its host to `[net] allow`.
If it uses a private certificate authority, add `[tls] extra_ca_files = ["~/path/to/ca.pem"]`.

### claude on Bedrock

claude needs AWS credentials, and the ball cannot reach `~/.aws` or your credential tool.
A hook in your base config runs the tool on the host and hands the agent a short-lived file.

```toml
# ~/.config/hamster-ball/base.toml
[hooks.pre_run.bedrock]
command = ["~/ai-coding/credential-process", "--profile", "my-profile"]
format  = "aws_credential_process"
profile = "my-profile"
```

Then add `extends = ["agent/claude"]` to the project and run `hb run -- ~/.local/bin/claude`.
Measured on one machine, claude took about 20 seconds longer to start.
It waits for two helper programs from its settings that cannot run inside the ball.
The credentials last as long as your tool says (about 11 hours for the one measured), so start a new run after that.

### opencode

opencode's MCP servers are not part of the preset.
Declare each one with `[mcp.<name>]` (see [Configuration](04-configuration.md#mcpname-mcp-servers)).
Run opencode once outside `hb` after you install or update it, so it can install its default plugin, which needs the network.

### A command that is not an agent

`hb run` works for any program.
A build is a good example, because it shows how little a program has by default:

```sh
hb run -- cargo test
```

This will not work until you give `cargo` what it needs.
Start with the project config below, run it, and use the logs to see what is still missing.

```toml
[fs]
write = ["."]
read  = ["~/.cargo/registry", "~/.rustup"]    # downloaded crates and the toolchain

[env]
tools = ["cargo", "rustc"]                    # found on your PATH when hb starts

[net]
allow = ["index.crates.io", "static.crates.io"]   # only needed to download crates
```

The list above is a starting point and has not been tested end to end for every toolchain layout.
Run `hb run --log-denials --log-proxy -- cargo test`, and add only what the logs show is needed.
`cargo build --offline` works without any `[net]` entry once the crates are already downloaded.

Next: [Configuration](04-configuration.md).
For every option of every command, see [Commands](05-commands.md). For worked examples, see [Use cases](06-use-cases.md).
