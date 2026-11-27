<!-- ABOUTME: Guide part 5: every hb command and option, what it prints and what it changes. -->
<!-- ABOUTME: Taken from `hb --help` and the command's own help; flags and wording match the program. -->

# 5. Commands

```
hb init
hb explain [--format text|json] [--show-args] [--path PATH]
hb approve [--revoke]
hb run [--log-denials] [--log-proxy] [--no-proxy-summary] [--] COMMAND...
hb profile
hb doctor
hb warm [--timeout SECS] [--log-denials] [--log-proxy] [NAME...]
hb ctl ps [NAME]                                      (inside the ball only)
hb ctl logs NAME [--tail N]
hb ctl stats|start|stop|restart NAME
hb ctl launchd status|kickstart|restart LABEL
```

`hb --help` lists the commands. `hb <command> --help` gives the details of one.
`hb --version` prints the version.

Every command except `hb init` and `hb ctl` needs to find a project: it walks up from the current directory to the first `hamster-ball.toml`.
If there is none, it stops with an error and exit code 1.

The `hb <word>` form is not a shorthand for `hb run -- <word>`.
A typo of a command would otherwise run a program with that name.
If you want a short form, use a shell alias: `alias hbr='hb run --'`.

## `hb init`

Creates `~/.config/hamster-ball/base.toml` from a commented template. It never overwrites an existing file.

The template contains `[fs] write = ["."]`, `[tls] system_trust = true`, `[env] pass = ["LANG", "COLORTERM"]`, and commented examples for the other settings.
If `~/.gitconfig` or `~/.config/git` exist, it adds read grants for them.
Git fails every command if it cannot read its own config.

## `hb explain`

Shows every effective rule and the file it came from.
It runs nothing and needs no approval.

| Option | Meaning |
|---|---|
| `--format text` | Readable output. This is the default. |
| `--format json` | The same content as JSON, for scripts and bug reports. |
| `--show-args` | Show MCP server and hook arguments, instead of only counting them. Values of `env.set` are never shown. |
| `--path PATH` | Answer one question about one path: can it be read, written or connected to, and by which rule. A relative path is relative to the project root. |

The report has these parts: the files used (a later file takes precedence), each setting with the file and line that gave it, the floor rules that apply to your machine, skipped grants, and warnings.

`--path` covers the merged config and the floor only.
It does not include the system allows or the secrets guard.
The answer looks like this:

```
path /Users/you/.ssh/id_rsa
  read      denied_by_floor by floor rule ssh [deny_read_write]
  write     denied_by_floor by floor rule ssh [deny_read_write]
  connect   not_granted
```

Warnings you may see include `project_not_granted` (no grant covers the project), `grant_shadowed_by_floor` (a grant the floor overrides), `git_config_unreadable` and `not_approved`.

## `hb approve`

Reviews this project's config and records your approval.

```
Approve this config? Type `approve 3fa9c2` to approve:
```

It shows the project root, each file with a short digest, and what the project adds beyond your base.
It accepts only the words `approve` and the six-digit code shown with that question, typed at a terminal.
The code is new for every question, and anything typed before the question appeared is discarded, so a pasted or queued answer cannot approve a config you did not read.
A plain `y` or `yes` does nothing.
The code stops answers that were typed, pasted or queued before the question appeared.
It does not stop a program that can read your terminal's screen and send it input (for example one that owns the terminal's master side, or one that can drive your terminal emulator or tmux).
Agents that `hb` runs have their own terminal and cannot do either by default; a program outside the sandbox can.
There is no `--yes`.

| Option | Meaning |
|---|---|
| `--revoke` | Takes the approval back. Needs no terminal. |

An approval covers exact bytes.
Any change to the project file or to a file it extends from inside the project asks again.
The records are kept in `~/.local/state/hamster-ball/approvals/`.

## `hb run`

Runs a command in the ball and exits with its status.

```sh
hb run [OPTIONS] [--] COMMAND...
```

The `--` before the command is optional.
Everything after the command name belongs to the command.
Put `hb`'s own options before the command.

| Option | Meaning |
|---|---|
| `--log-denials` | Show what the sandbox denied during the run. |
| `--log-proxy` | Show every connection the proxy handled: host, port, whether it was allowed, and byte counts. |
| `--no-proxy-summary` | Do not end the run with a warning that the proxy refused connections. The warning is also left out when `--log-denials` already shows them. |

Both log options print live when stderr is redirected, and after the command ends when it is a terminal, so an interactive screen is not corrupted.
Each shows at most 1000 lines.
The macOS denial log is incomplete.
Use it as a hint and test before turning a line into a rule.

What `hb run` needs:

- A project config that is approved. If not, it exits with code 78 and runs nothing.
- The command on the ball's short `PATH`, or given by full path.
- A grant over the project directory. `hb run` warns before starting if there is none.

What it does, in order, is in [How it works](02-how-it-works.md#what-happens-during-one-run).

`hb run` cannot start inside another sandbox.
macOS cannot nest them, so `hb` stops with a clear message.

The exit status is the command's own status.
When the command is killed by a signal, the status is `128 + signal`.
When the command ends with INT, TERM, HUP or KILL, `hb` cleans up and raises the same signal on itself, so a calling shell sees a signalled child.

## `hb profile`

Prints the Seatbelt profile and its parameters for this project.

The proxy parameter is a placeholder, because each run's proxy listens on a random port chosen at start.
Use it to see exactly what the sandbox allows.
You can also run a command by hand with the printed profile and `sandbox-exec`.

## `hb doctor`

Reports what `hb` cannot fully see.
It prints names and the one flagged argument. It never prints file contents or values.
It always exits with 0.

| Section | What it lists |
|---|---|
| secrets guard | The directories the guard covers, whether the dependency exemption is on, and how many directories are pinned. |
| tracked files | Files the guard would deny, but which git tracks. The agent can read them with `git show`. |
| look-alike files | Files that look like secrets but no pattern guards: `.netrc`, `id_rsa`, `*.tfvars`, `*.tfstate`, and files with `token`, `password` or `api key` in the name. Add `fs.deny_read` for those you want guarded. |
| launchd environment | Secret-looking variable names in your launchd environment. The agent can read them only if `system.launchctl` is on. |
| git | Repositories below a write grant (other than the project's own and the ones above it), git hook managers (`.husky`, `.githooks`, `lefthook`, `.pre-commit-config.yaml`), and `core.hooksPath` from the project's git config. The floor protects the project's own `.git/hooks` and `.git/config` only. |
| system proxy | The proxy, PAC and auto-discovery settings your Mac has switched on. `hb` connects directly and does not follow them. It also says whether the agent can read them, which depends on `tls.system_trust`. |
| MCP servers | `uvx` and `npx` servers that were never warmed, use a moving version tag, use an unpinned git source, or whose launcher is missing from `[env] tools`. |

Run it once per project, and again when the project changes.

## `hb warm`

Fills `hb`'s offline cache for the MCP servers the project declares.
It is the only command that may reach the package registries.

```sh
hb warm                         # every uvx or npx server
hb warm time fetch              # only these
hb warm --timeout 600 serena    # give a slow server more time
```

| Option | Meaning |
|---|---|
| `NAME...` | The servers to warm. None means every server whose command is `uvx` or `npx`. |
| `--timeout SECS` | Seconds each server gets to answer before it is stopped. The default is 300. |
| `--log-denials` | Show what the sandbox denied while each server started. |
| `--log-proxy` | Show every connection the proxy handled. |

For each server, `hb warm` starts it once, in the same ball a run uses, with only the package registries (and the server's `warm_net`) reachable.
It waits for the server to answer an MCP `initialize` request.
If that works, it records a stamp and the cache is ready.

It needs an approved config and refuses to run inside a ball.
The cache is `~/.cache/hamster-ball/`, kept apart from your own `~/.cache/uv` and `~/.npm`.

## `hb ctl`

Works inside the ball only.
A broker on a private socket answers.
Outside a run that has a `[ctl]` section, `hb ctl` says so and exits with code 2.

### Containers

```sh
hb ctl ps                          # the containers in scope, with state
hb ctl logs NAME [--tail N]        # the last lines of a log, at most 2000
hb ctl stats NAME                  # one CPU and memory sample
hb ctl start NAME
hb ctl stop NAME
hb ctl restart NAME
```

`NAME` must be a container that your `[ctl]` section lists, by name or by label.
There is no `run`, `exec`, `build`, `rm`, `cp` or `compose`.
Output is capped at 20 KB.
`start` and `restart` also need the safety checks to pass and a podman machine that shares only the project.
See [Use cases](06-use-cases.md#let-the-agent-restart-a-container).

### launchd jobs

```sh
hb ctl launchd status LABEL        # state, pid, run count and last exit code
hb ctl launchd kickstart LABEL     # start a loaded job that is not running
hb ctl launchd restart LABEL       # stop the job's process and start it again
```

`LABEL` must be in `[ctl] launchd`, which only your own files can set.
`status` shows four fields.
It never shows the job's environment, which can hold secrets.

### Exit codes of `hb ctl`

| Code | Meaning |
|---|---|
| 0 | The request worked. |
| 1 | The broker refused it or it failed. The reason is printed. |
| 2 | There is no broker: this run has no `[ctl]` section, or you are not inside the ball. |

## Exit codes of every command

| Code | Meaning |
|---|---|
| 0 | Success. `hb explain` with warnings is still 0. |
| 1 | A config, load, floor, hook or run-start error. It prints the cause chain. |
| 2 | A usage error, or `hb ctl` with no broker. |
| 78 | The project's config is not approved. Nothing was run. |
| other | `hb run`: the command's own exit code, or `128 + signal`. |

Next: [Use cases](06-use-cases.md).
