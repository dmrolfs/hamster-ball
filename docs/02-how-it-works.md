<!-- ABOUTME: Guide part 2: the pieces of hb, what happens during one run, and what it means to be inside the ball. -->
<!-- ABOUTME: Explains mechanism in plain words; the exact rules are in the configuration and reference documents. -->

# 2. How it works

## The big picture

When you type `hb run -- <agent>`, `hb` does three jobs.

1. It works out what the agent may do, from your config files and the rules built into `hb`.
2. It prepares the things the agent needs from outside: a proxy for the network, a private working directory, and any credentials you set up.
3. It starts the agent under a Seatbelt profile (the rule list for the macOS sandbox) that allows exactly that, and cleans up when the agent ends.

```
 your shell
    |
    |  hb run -- kiro-cli chat
    v
 +--------------------------- hb (on your machine, outside the ball) ---------------------------+
 |  reads config  ->  checks approval  ->  builds the profile  ->  starts proxy and broker  |
 +------------------------------------------------+---------------------------------------------+
                                                  |
                                                  |  sandbox-exec with the generated profile
                                                  v
                           +----------------- the ball -----------------+
                           |  the agent and every program it starts     |
                           |  reads and writes only granted paths       |
                           |  reaches the network only via the proxy    |
                           +--------+------------------------+----------+
                                    |                        |
                          proxy on 127.0.0.1         hb ctl socket (only if [ctl] is set)
                          (allowlist of hosts)       (fixed container and launchd actions)
```

Key to the diagram:

- The broker is the small server inside `hb` that answers `hb ctl` requests.
- The proxy is the go-between program that forwards the agent's network requests after checking the host.
- `127.0.0.1` is the address of your own machine.

Everything above the ball runs as you, on your machine, outside the sandbox.
Everything in the ball runs under the profile.

## What "inside the ball" means

A process is inside the ball if the sandbox profile applies to it.
`hb` starts the agent under the profile, and every process the agent starts inherits it.
A shell the agent opens, a compiler it runs and a tool it downloads are all inside.
A process cannot take the profile off or start a program outside it.

Being inside the ball means:

- Files. The process can read and write only paths the profile allows. Everything else is refused by the kernel, with an error such as "Operation not permitted". A path on the floor is refused even if a config file grants it.
- Network. The process cannot open a connection to any address except the proxy port (and loopback ports you listed). It cannot look up names itself.
- Environment. It starts with almost no environment variables. `HOME`, `PATH`, `TMPDIR`, `TERM`, the proxy variables and the names you passed are there. Your shell's other variables are not.
- Programs. It runs with a short `PATH`: `/usr/bin:/bin:/usr/sbin:/sbin`, plus the directories of programs you list in `[env] tools`.
- Host services. It cannot use `open`, `sudo`, `launchctl`, the clipboard tools or Apple Events. Its terminal output is filtered, so it cannot send control codes that change your terminal or type into your shell.

An agent is in the ball when you start it with `hb run`.
An agent that you start without `hb` is not in a ball, whatever its own settings say.
A program that the agent starts is in the ball because its parent is.
The same goes for any other app you start with `hb run`.

You, in your own terminal, are outside the ball.
You can read the project, run `hb` and approve configs.
The agent cannot do these things for itself.

## The pieces

### The floor

The floor is a list of rules compiled into `hb`.
It denies the places an agent should never reach: SSH keys, cloud credentials, keychains, browser profiles, shell history, container sockets.
It also denies writes to places where planted code would run later as you: shell startup files, `~/.gitconfig`, program directories on your `PATH`, git hooks.
Deny always beats allow, and no config file can remove a floor rule.
`hb explain` prints the rules that apply to your machine.

### Config layers

Config comes from four layers, listed here from the bottom up. A later layer is read after the earlier ones and can add to what they allow. Nothing in a later layer can remove a deny from an earlier one, and a deny from any layer beats an allow from any layer:

| Layer | Where it comes from | Who can change it |
|---|---|---|
| Floor | Compiled into `hb` | Nobody |
| Base | `~/.config/hamster-ball/base.toml` | You |
| Presets | Built in (`agent/kiro` and others) or yours | Whoever owns the preset file |
| Project | `hamster-ball.toml` in the project root | You and the agent, so it needs approval |

A project can grant more access than the base, but it cannot remove a deny from the base or the floor.
Settings that run code on your machine, such as hooks, are accepted only from your own files.
See [Configuration](04-configuration.md).

### The profile

`hb` turns the merged config into a Seatbelt profile and runs the agent with `sandbox-exec`.
The profile starts from "deny everything" and then allows only what the config grants.
Paths are resolved to their real locations first, because Seatbelt matches real paths and not symlinks (a symlink is a path that points to another path, like a shortcut).
You can print the exact profile with `hb profile`.

### The proxy

`hb` starts a small proxy on `127.0.0.1` for each run, on a random port, with a random credential.
The profile lets the agent connect to that port and nothing else.
`hb` sets `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` so tools use it.

For each request the proxy checks the host against your `net.allow` list and the port against the list entry.
It resolves the name itself and connects to the address it checked, so a name that later points to `127.0.0.1` or a cloud metadata address is refused.
It never opens encrypted traffic and keeps no headers or bodies.
A refused request gets a `403` with a short code, such as `not_allowed`.

### The secrets guard

Below every directory the agent may write, files named `.env`, `.env.*`, `*secret*.yaml`, `*.pem`, `*.key` and `*.p12` cannot be read, changed or deleted.
Their names stay visible, so `ls` works and tools do not fail on a missing directory entry.
Templates such as `.env.example` stay editable.
Files that git tracks are skipped, because the agent can already read them with `git show`.
`hb doctor` lists the tracked ones and look-alikes the patterns miss.

### Approval

The agent can write the project directory, so it could change `hamster-ball.toml` to give itself more access.
To prevent that, `hb run` runs a project config only if you approved its exact bytes with `hb approve`.
Any change, in any byte, asks again.
The file is also read-only inside the ball.

### Hooks and credentials

A hook is a program you name in your base config.
`hb` runs it on the host before the agent starts, with a scrubbed environment and a time limit.
It can produce a credential file, such as a short-lived AWS credential, that the agent gets instead of your real credential tool.
The agent never sees `~/.aws` or the tool that fetches the credential.

### `hb ctl`

Agents often need to see why a service is down and restart it.
They cannot run `podman` directly, because a container can mount your whole home directory.
`hb ctl` is a narrow channel for this.
A broker listens on a private socket.
The agent runs `hb ctl ps`, `hb ctl logs NAME`, `hb ctl restart NAME` and a few more.
The broker runs a fixed command for each one, only on containers and launchd jobs you listed, and only after checking that the container is safe to touch.
See [Use cases](06-use-cases.md) and [Commands](05-commands.md).

### MCP servers and `hb warm`

Agents start MCP servers with `uvx` or `npx`, which download packages at start.
Inside the ball no package registry is reachable.
You run `hb warm` once, outside the ball, and it downloads each server's packages into a cache that belongs to `hb`.
After that, `hb run` puts launchers for `uvx` and `npx` first on the agent's `PATH`, and they start servers from that cache with no network.

## What happens during one run

1. Find the project. `hb` looks for `hamster-ball.toml` in the current directory and each directory above it, and uses the first one. If there is none, it stops.
2. Load and merge. It reads your base config, the presets named in `extends` and the project file, and merges them under the floor.
3. Check approval. If the project config has not been approved, it stops with exit code 78 (the code `hb` uses for this case) and runs nothing.
4. Prepare. It scans for secret files, runs your hooks, starts the proxy, creates a private session directory, and, if `[ctl]` is set, checks each listed container and starts the broker.
5. Start the agent. It builds the profile and runs the agent under `sandbox-exec`. When you are at a terminal, the agent gets its own pseudo-terminal (a pty, a virtual terminal that `hb` controls).
6. Supervise. It forwards signals, filters the terminal output, and writes denial and proxy logs if you asked for them.
7. Clean up. When the agent ends, `hb` stops the proxy and broker, removes the session directory and exits with the agent's exit code. A separate small process also cleans up if `hb` itself is force-killed (SIGKILL, a signal that a program cannot catch).

If `hb` is force-killed, that small process ends what the agent started. It does its best, and does not promise to find everything:

- It keeps track of the agent's processes and of the processes they start, including ones that leave the agent's process group or outlive their parent. Each is ended with a polite stop request first, then a forced stop after a short wait. Before it signals any process it checks that the process is still the same one it recorded (same number, same start time), so a number that macOS has handed to an unrelated program is left alone.
- Right after, it looks once more for leftovers it missed. It looks for processes that carry this run's secret marker in their environment, and for processes still using the run's private directory.
- It can miss a process that was started in a rapid chain of "start another process, then exit", because that race can be lost. It can miss a process that clears its own environment, and a macOS system tool that has left the private directory and closed its files there. It does not touch processes of other users.
- Already-tracked members remain owned after their leader exits.
  Once the leader has been reaped, its group number alone cannot identify additional members safely, so those need independent token or directory evidence.
- Recovery retains the process identity captured before reading that evidence, then checks it again before adoption and before signalling.
  A directory holder born during the identity snapshot may be missed in that pass.
  An unreadable directory can also hide a holder from `lsof` without a warning.
- Known processes receive SIGKILL before the last recovery sweep.
  Deadlines are checked between operations; an individual stalled OS call or scheduler pause can still delay cleanup.
- The final identity check and signal are separate syscalls.
  The remaining race is unlikely but unbounded in time, not closed.
  Cleanup failures are not durably reported after `hb` dies.

Stopping a dedicated virtual machine also stops its guest processes; merely running inside one does not guarantee teardown.

## Where things live

| What | Where |
|---|---|
| Your base config | `~/.config/hamster-ball/base.toml` |
| Your own presets | `~/.config/hamster-ball/presets/<name>.toml` |
| Approvals | `~/.local/state/hamster-ball/approvals/` |
| `hb warm` stamps | `~/.local/state/hamster-ball/warm/` |
| Offline package cache (sealed generations; a run uses its own copy) | `~/.cache/hamster-ball/`. `hb` never deletes it; see [moving to cache generations, and freeing space](05-commands.md#moving-to-cache-generations-and-freeing-space) |
| The session directory | A new private directory under your temp directory, removed at exit, or by the next `hb run` if `hb` was killed (only when its process has gone). It is the agent's `TMPDIR`. |

The floor hides the config and state directories from the agent.

Next: [Getting started](03-getting-started.md).
