<!-- ABOUTME: Guide part 1: what hamster-ball is, why to use it, what it builds on, what its parts are, what it protects against. -->
<!-- ABOUTME: Plain-language background for a reader who has not used a sandbox before; no setup steps (see 03-getting-started.md). -->

# 1. Concepts

## What hamster-ball is

An AI coding agent reads files, runs commands and calls the network for you.
The agent runs as you, so it can do anything you can do: read your SSH keys, delete files, send data to any server.

`hb` is a command that starts the agent inside a sandbox called the hamster ball.
You describe the ball in a small file, `hamster-ball.toml`, in your project.
The agent can then read and write what you listed, reach the hosts you listed, and nothing else.


## Why use it

An agent can go wrong in three ways:

1. It makes a mistake, such as deleting the wrong directory.
2. It reads text that tells it to do something harmful. A web page, a file in a repository or a package can carry such text. This is called prompt injection: the agent mistakes text it reads for an instruction.
3. It runs a dependency that is malicious.

You cannot review every command an agent runs.
You can limit what any command is allowed to do.
`hb` does that with rules the operating system enforces, so the limit does not depend on the agent behaving well.

You get:

- One command for every agent. The same `hb run` works for kiro-cli, pi, claude, opencode or any other program.
- One small file per project that says what the agent may touch.
- A base config of your own that applies to every project. A project can add to it and cannot remove anything from it.
- Credentials and secret files kept out of reach by default.
- A record of what the agent was refused, so you can decide whether to allow it.

## What it builds on

`hb` is a single program written in Rust. It uses three things that already exist.

| Piece | What it gives `hb` |
|---|---|
| Seatbelt, the macOS sandbox, reached through `/usr/bin/sandbox-exec` | The enforcement. You give it a profile, which is a list of rules. The kernel refuses reads, writes and connections that the profile does not allow. |
| TOML config files | The description of each ball: which paths, hosts and variables. |
| A proxy that `hb` runs itself | The only way out to the network. A proxy is a go-between program: it receives a request, checks the host against your list, and forwards the request only if the host is on it. |

Other tools use the same Seatbelt mechanism, including Chrome and some agent runtimes.
Apple marks `sandbox-exec` as deprecated, so a future macOS could remove it.
`hb` keeps all Seatbelt use in one module so a replacement could be added later.

`hb` works on macOS only. It was built and measured on macOS 15.7 on Apple silicon.

## The parts

These are the pieces you will meet. Each is explained in [How it works](02-how-it-works.md).

| Part | In one line |
|---|---|
| The ball | The sandbox the agent runs in. It exists for one run. |
| The floor | Deny rules built into `hb` that always apply. No config file can remove one. It is the lowest layer that everything else sits on. |
| The base config | Your own file, `~/.config/hamster-ball/base.toml`. It applies to every project. |
| Presets | Ready-made config fragments, such as `agent/kiro`, that you pull in with `extends = ["agent/kiro"]` in your project config. |
| The project config | `hamster-ball.toml` in the project root. It adds what this project needs. |
| The proxy | A small server `hb` starts for each run. The agent reaches the network only through it. |
| The secrets guard | A rule that hides files like `.env` and `*.pem` inside the project. |
| Approval | You review a project's config once. `hb` runs it only while its bytes are unchanged. |
| Hooks | Programs of yours that `hb` runs on your machine, outside the ball, before the agent starts, for example to fetch a credential. They are not git hooks. |
| `hb ctl` | A narrow channel for the agent to look at and restart containers and launchd jobs you list. A container is a packaged service run by podman or Docker. launchd is the macOS manager of background jobs. |
| `hb warm` | A command that downloads the packages an MCP server needs, so the server can start offline later. An MCP server is a helper program that gives an agent extra tools. |

## What it protects against

Inside the ball the agent cannot do these things.

| Risk | What `hb` does |
|---|---|
| Reading credentials (`~/.ssh`, `~/.aws`, keychains, browser profiles, shell history) | Reads are denied by default. The floor names these paths and denies them. |
| Planting code that your own shell runs later (shell startup files, `~/.local/bin`, `~/.cargo/bin`, git hooks) | These places cannot be written. |
| Sending data to a server you did not name | There is no direct network. The proxy allows only listed hosts. |
| Leaking data through DNS | DNS turns a name into an address, and can carry data out in the names it looks up. The agent cannot resolve names. The proxy does that. |
| Reading `.env` and key files in the project | The secrets guard denies them in every directory the agent may write. |
| Tokens in your shell environment | The environment starts empty. Only the names you list get through. |
| Changing its own limits | `hamster-ball.toml` is read-only inside the ball, and a changed file needs your approval. |
| Using `podman` to reach your files | The agent cannot run `podman`. `hb ctl` is the only channel, and it checks each container first. |
| Starting or stopping your launchd jobs | `launchctl` is blocked unless your own config turns it on. |

## What it does not protect against


- A hostile agent that uses a flaw in macOS itself. For that, use a virtual machine.
- Anything you grant yourself. If you give the agent write access to a directory, it can change it.
- Data sent to a host you allowed. The proxy passes encrypted (HTTPS) traffic through without opening it, so an allowed host can receive anything the agent can read.
- Network use by containers you start yourself. Podman on macOS cannot limit that.
- Secrets with unusual names. The guard matches common names. `hb doctor` lists look-alikes, and you can add patterns.
- A process the agent hides on purpose. If `hb` is force-killed, its cleanup process ends what it can find, but it cannot promise to catch every process an agent starts and then detaches. See [how it works](02-how-it-works.md).
- Other operating systems.

The full threat model is section 2 of the [design](https://github.com/dmrolfs/hamster-ball/blob/main/ref/Hamster-Ball-Design.md).

## Glossary

| Term | Meaning |
|---|---|
| Agent | A program that uses an AI model to read files, run commands and call the network for you. |
| Ball | The sandbox `hb` builds around one run. It exists until the agent ends. |
| Profile | The list of rules that Seatbelt enforces. `hb` writes one for each run. |
| Seatbelt | The macOS sandbox mechanism. `sandbox-exec` runs a program under a profile of Seatbelt rules. |
| Floor | The deny rules built into `hb`. |
| Base config | Your own `~/.config/hamster-ball/base.toml`. |
| Project config | `hamster-ball.toml` in the project root. |
| Preset | A reusable config fragment, named in `extends`. |
| Proxy | The go-between program that forwards the agent's network requests after checking the host. |
| Secrets guard | The rule that hides files like `.env` and `*.pem` inside the project. |
| Approval | Your recorded OK of a project config's exact contents, made with `hb approve`. |
| TLS | The encryption used by HTTPS. Some networks re-sign it, which is why `[tls]` settings exist. |
| TOML | The plain-text config format `hb` uses. |
| Hook | A program of yours that `hb` runs before the agent starts. |
| Session directory | A private temporary directory made for one run and removed at the end. |
| Symlink | A path that points to another path, like a shortcut. |
| MCP server | A helper program that gives an agent extra tools. |
| Container | A packaged service run by podman or Docker. |
| launchd | The macOS manager of background jobs. |
| Broker | The small server inside `hb` that answers `hb ctl` requests. |

Next: [How it works](02-how-it-works.md).
