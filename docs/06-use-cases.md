<!-- ABOUTME: Guide part 6: common situations, each with what to run, what you will see and what happens underneath. -->
<!-- ABOUTME: Output shown was captured from real runs; where a case was not run end to end, the text says so. -->

# 6. Use cases

Each case has three parts: what you want, what to run, and what is happening.
The cases assume the setup in [Getting started](03-getting-started.md): `hb init` has made your base config, the project has a `hamster-ball.toml`, and you have run `hb approve`.
Without an approval, `hb run` exits with code 78 and runs nothing.

## See the sandbox work

You want to be sure the ball does what it says.
This is a good first check after install.

```sh
hb run -- /bin/sh -c 'echo hi > made.txt && echo wrote-ok; cat ~/.ssh/id_rsa; cat .env; cat .env.example; touch ~/.zshrc'
```

Set up first: the project grants itself with `write = ["."]` (your base config from `hb init` does this), and it holds a `.env` and a `.env.example` containing `TOKEN=`.
This is what a captured run printed (the home directory was a test one):

```
wrote-ok
cat: .../home/.ssh/id_rsa: Operation not permitted
cat: .env: Operation not permitted
TOKEN=
touch: .../home/.zshrc: Operation not permitted
```

What happens:

- `made.txt` was written because the project is granted for writing.
- `~/.ssh/id_rsa` is refused because `.ssh` is on the floor, which denies reads and writes.
- `.env` is refused by the secrets guard. `ls` still lists it, so tools do not break.
- `.env.example` is a template, so it can be read and edited. The `TOKEN=` line in the output is its content.
- `~/.zshrc` is refused because shell startup files are write-denied. A planted line there would run outside the ball the next time you open a terminal.

## See what the agent's environment holds

```sh
hb run -- env
```

A captured run printed only these names: `HOME`, `PATH`, `TMPDIR`, `TERM`, `PWD`, `SHLVL`, `HB_SESSION`, and the proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` and their lowercase forms, plus `NO_PROXY`).
Your shell's variables, such as `AWS_ACCESS_KEY_ID` or `GITHUB_TOKEN`, are not there.

`PATH` was `/usr/bin:/bin:/usr/sbin:/sbin`.
The proxy URL holds a random credential that lasts for that run only.

To pass a variable, name it:

```toml
[env]
pass = ["LANG", "RUST_LOG"]
```

## Allow a host

The agent needs a download from `example.com`. You see a refusal:

```sh
hb run --log-proxy -- /usr/bin/curl -sS https://example.com
```

```
hb: proxy: refused example.com:443 not_allowed (example.com is not on the allowlist )
curl: (56) CONNECT tunnel failed, response 403
```

What happens: the agent sent its request to the proxy, and the proxy checked the host against `net.allow`.
It was not there, so the proxy answered `403` with the code `not_allowed`.
Tools show this as a failed connection, for example `CONNECT tunnel failed, response 403`.

Add the host to the project config, then approve the changed file and run again:

```toml
[net]
allow = ["example.com"]
```

```sh
hb approve
hb run -- /usr/bin/curl -sS https://example.com
```

Other refusal codes you may see:

| Code | Meaning | Fix |
|---|---|---|
| `not_allowed` | The host is not listed. | Add it to `[net] allow`. |
| `port_not_allowed` | The host is listed on another port. | Add `host:port`. |
| `internal_address` | The name resolves to a private or tunnel address. | Add the host to `net.internal_hosts` in your base config. |
| `ip_literal` | The request used an IP address. | Use a name. |
| `unresolved`, `unreachable`, `timed_out` | The name or route is wrong. | Check the same host with `curl` outside the ball. |

## Prove that the network is closed

```sh
hb run -- /bin/sh -c "curl -sS -m 5 --noproxy '*' https://example.com; nslookup example.com"
```

A captured run printed `curl: (6) Could not resolve host: example.com` and `isc_socket_bind: unexpected error` from `nslookup`.
A program that ignores the proxy settings has no way out.
Direct connections and direct DNS both fail.

## Connect to a database you started yourself

The agent should run tests against Postgres on port 5432, started outside the ball.

```toml
[net]
loopback_ports = [5432]
```

The profile allows the agent to connect to that one port on `127.0.0.1`, directly and not through the proxy.
Other loopback ports stay closed.
`hb run` warns at start if nothing is listening on a listed port.

## Review a project you did not write

You cloned a repository that has its own `hamster-ball.toml`.

```sh
cd the-repo
hb explain          # read every rule and where it came from
hb approve          # shows what the project adds beyond your base
```

`hb approve` lists what the project grants that your base does not, and includes what any presets it names grant.
Read it before typing `y`.
If you decline, `hb run` will not start, and nothing runs.

Later, a `git pull` changes `hamster-ball.toml`.
The next `hb run` stops with exit code 78 and asks you to approve again.
This is the protection against a changed file giving the agent more access.

## Run claude on Bedrock

See [Getting started](03-getting-started.md#claude-on-bedrock) for the hook and command.
What happens:

1. `hb` runs your credential tool on the host with a scrubbed environment.
2. It reads the tool's JSON and writes an AWS `config` and `credentials` pair, mode 0600, into the session directory.
3. It sets `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` to those files.
4. claude, inside the ball, uses them to reach Bedrock. It cannot read `~/.aws` or run your tool.
5. When the run ends, the files are removed.

## Use MCP servers offline

Your agent starts MCP servers with `uvx` and `npx`.

1. Declare them, and list the launchers:

   ```toml
   [env]
   tools = ["uvx", "npx", "node"]

   [mcp.time]
   command = "uvx"
   args    = ["mcp-server-time"]

   [mcp.sequential-thinking]
   command = "npx"
   args    = ["-y", "@modelcontextprotocol/server-sequential-thinking"]
   ```

2. Warm the cache once, outside the ball:

   ```sh
   hb approve
   hb warm
   ```

3. Run the agent as usual. Your project config also needs `extends = ["agent/kiro"]`, as in [Getting started](03-getting-started.md):

   ```sh
   hb run -- "$(command -v kiro-cli)" chat
   ```

`hb warm` starts each server once in a ball where only the package registries are reachable, and keeps what it downloaded in `~/.cache/hamster-ball`.
`hb run` then puts `uvx` and `npx` launchers first on the agent's `PATH`.
They add `--offline` and point to that cache, so the server starts with no network.

If you change a server's arguments, run `hb warm` again.
If you did not warm a server, `hb run` says so before it starts: `warning: mcp server X has not been warmed (or its command changed): run hb warm`.

Pin the versions.
`hb doctor` flags `@latest` and unpinned git sources, because they change on the next `hb warm`.

## Let the agent restart a container

The agent needs to see why a service is down and restart it.
It cannot run `podman`, so you give it `hb ctl`.

### 1. List what the agent may touch

```toml
# ~/.config/hamster-ball/base.toml or the project config
[ctl]
containers = ["app-db"]
# or every container with a label:
# label = "com.docker.compose.project=myapp"
```

Use the names that `podman ps -a` shows.

### 2. Use it from inside the ball

Start the agent as usual (the project config extends `agent/kiro`):

```sh
hb run -- "$(command -v kiro-cli)" chat
```

The agent can then run these commands in its shell:

```sh
hb ctl ps
hb ctl logs app-db --tail 100
hb ctl restart app-db      # needs the project-only podman machine of step 5; ps and logs work without it
```

An example of a refusal (the container name is an example):

```
hb ctl: myapp-server-0 was not found
```

(A container that is not in scope, or that does not exist, is not found.)

`hb ctl` is a program inside the ball, and it talks to a broker that `hb` started on a private socket.
The broker checks the request against your list, inspects the container, and runs a fixed `podman` command.
The agent never gets `podman` itself.

### 3. What `hb` checks first

Before it touches a container, `hb` inspects it and refuses if:

- It is privileged, or uses the host's process, network, IPC or user namespaces.
- It has added capabilities, devices or `volumes_from`.
- A bind mount is not a real file or directory inside the project. A symlink anywhere in the path is refused.
- A volume is not a plain local volume.

A container that fails these checks gets a warning when `hb run` starts, and `hb ctl` will not start or restart it in that run.

The mounted directories, and the directories above them as far as the agent can write, cannot be renamed, deleted or linked by the agent.
That stops the agent from swapping a mount for a link and then asking for a restart.
The files inside stay writable.
A single file that is itself a mount cannot be saved by "write a temp file and rename". Edit it in place.

### 4. Why `start` and `restart` need a project-only podman machine

A process inside a container is not under the sandbox.
If it runs project code that the agent can edit, it can swap its own mount for a link to any directory the podman machine shares.
This was measured.
Your default machine shares `/Users`, `/private` and `/var/folders`, so a link from a container to your SSH keys would work.

So `hb` allows `start` and `restart` only when every directory the active machine shares is the project or inside it.
If the machine shares more, `hb` says so when the run starts and refuses those two operations.
`ps`, `logs`, `stats` and `stop` still work.
`hb` never changes your machine.

### 5. Create a project-only machine

Only one podman machine runs at a time.
A second machine, beside your existing one, keeps its images and containers.

```sh
podman machine stop                                    # stops the one that is running
podman machine init hb-myproj --cpus 6 --memory 8192 \
  --volume /path/to/project:/path/to/project --now     # the same path on both sides, and no other --volume
podman system connection default hb-myproj             # podman and hb use this machine now
```

The new machine starts empty.
Pull or build what the project needs.

To go back:

```sh
podman machine stop hb-myproj
podman machine start podman-machine-default
podman system connection default podman-machine-default
```

Notes:

- The shared directory must be the project root or inside it. A project that sits inside a wider share is refused. A scratch project under a shared repository, for example, is refused.
- `podman machine init` with no name fails while `podman-machine-default` exists. Give the new machine a name.
- `podman machine rm` deletes a machine's images, containers and volumes.
- A container started on one machine does not exist on the other.

This was run end to end on a real machine: with a project-only machine active and the project root equal to the share, `hb ctl restart` restarted a container, and `hb run` printed no machine warning.
On the default machine, from a project narrower than the share, `restart` was refused with the exact `podman machine init` command to fix it, and `ps` worked.

### 6. Restart a launchd job

```toml
# your base config only
[ctl]
launchd = ["homebrew.mxcl.postgresql@16"]
```

```sh
hb ctl launchd status homebrew.mxcl.postgresql@16
hb ctl launchd restart homebrew.mxcl.postgresql@16
```

`status` shows the state, the process number, the run count and the last exit code, and nothing else.
`hb` never returns the job's environment, which can hold secrets.
The job runs outside the ball, as you, so restarting it runs whatever it is set up to run.

## Find out why the agent cannot do something

1. Run with logs on:

   ```sh
   hb run --log-denials --log-proxy -- <command>
   ```

2. Ask why a path is or is not reachable:

   ```sh
   hb explain --path ~/work/shared-fixtures
   ```

   A path under a floor rule shows `denied_by_floor` and the rule name. A path with no grant shows `not_granted`.

3. Look at the rules and where they came from:

   ```sh
   hb explain
   ```

4. Print the profile:

   ```sh
   hb profile
   ```

Do not turn every denial line into a grant.
The macOS denial log is not complete, and many denials are harmless probes.
Add what the agent needs to do its job, and test again.

## Check a project for exposures

```sh
hb doctor
```

It reports secret-looking files the guard does not cover, files git tracks that the guard would deny, secret-looking launchd variable names, git hooks the floor does not protect, the proxy settings your Mac has on, and MCP servers that cannot start offline.
Act on what you want to change.

- For a file that looks like a secret, add `fs.deny_read = ["path/to/file"]`.
- For a repository below the project, add `fs.deny_write = ["path/to/repo/.git/hooks", "path/to/repo/.git/config"]`.
  A captured run showed both writes and a rename of the hooks directory refused, while a repository left unlisted stayed writable.
  The alternative is to run git in that directory yourself.
  A hook planted there runs outside the ball, as you, the next time you run git.

Next: [Reference](07-reference.md).
