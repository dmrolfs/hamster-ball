<!-- ABOUTME: Guide part 8: the optional terminal supervisor, hb-supervise, for running several agents from one terminal. -->
<!-- ABOUTME: What it shows, what its keys do, what it does and does not protect, which agents were tried, and its known limits. -->

# 8. The supervisor

`hb-supervise` is an optional program.
It starts several `hb run` sessions and shows them in one terminal.
You see each session's state, what the sandbox denied, and what the proxy allowed or refused.
You type to one agent at a time.

You do not need it to use `hb`.
Each session is still an ordinary `hb run` with its own sandbox, approval and cleanup.
The supervisor does not enforce anything.
It only starts sessions and shows what they report.

## Install

A default build does not include it, so ordinary `hb` builds do not compile its terminal libraries.

```sh
cargo install --locked --path . --features supervise
```

This installs `hb` and `hb-supervise` into the same directory.
Keep them together: the supervisor starts the `hb` that sits beside it.
It needs Rust 1.88 or newer, like `hb`.

## Start it

Run `hb-supervise` in a terminal at least 60 columns wide and 15 rows high.
It opens in Overview mode with an empty list.

Press `n` to start a session.
The form asks for a project directory and a command, such as `claude`.
The directory defaults to where you started the supervisor, and the command to the last one used for that directory.
`hb` checks them, so a wrong directory or a missing command shows `hb`'s own message in the form.

A project that you have not approved yet shows as `Approve`, and nothing runs.
Press `a` to review the config.
The review runs `hb approve` in your terminal while the other sessions carry on.
Nothing is typed for you, and starting the session again checks approval again.

You can run up to 8 sessions at once.
A ninth is refused with a message, and nothing starts.

## The screen

```
┌ Sessions ────────────────┐┌ keys: to the supervisor · Running · shopfront · claude · /work/shopfront ┐
│> 1 shopfront Running     ││ (the agent's terminal)                                                   │
│  2 billing   Approve     ││                                                                          │
│  3 docs      Exited 0    ││                                                                          │
├──────────────────────────┤│                                                                          │
│ Denials (3) │ Proxy (12) ││                                                                          │
└──────────────────────────┘└──────────────────────────────────────────────────────────────────────────┘
 OVERVIEW  Enter interact · n new · s stop · r restart · a approve · Tab switch · ? help · q quit
```

- The list shows each session as words, not only colour: `Starting`, `Approve`, `Running`, `Stopping`, `Exited 0`, `Failed`, `Lost`.
  A number after a state is how many denials you have not looked at.
- The title above the agent's terminal starts with where your keys go, then the state.
  The project path and command come last, and a long or odd path is cut and shown with escapes, so it cannot push those words out.
- The bottom bar names the current mode.
- Below 100 columns or 24 rows it shows one panel at a time, and `Tab` or `Shift-Tab` switches.
  Below 60 by 15 it shows only the list and asks for a bigger terminal.
- `NO_COLOR` removes all colour.
  The words stay.

## Keys

Overview mode, where keys belong to the supervisor:

| Key | What it does |
|---|---|
| `j` `k`, arrows | Select a session |
| `1` to `8` | Jump to a session |
| `Enter` | Type to the selected session |
| `n` | Start a session |
| `s` | Stop the selected session (asks first, naming it) |
| `r` | Restart it as a new run (asks first, naming it) |
| `a` | Review approval for a session that is waiting for it |
| `Tab` | Switch between Denials and Proxy |
| `?` | Help |
| `q` | Quit; if sessions are running, asks first, then stops them all |

Only `y` confirms a question.
Any other key cancels it.

Interact mode, where every key goes to the agent:

| Key | What it does |
|---|---|
| `Ctrl-g` | Return to Overview at once |
| `Ctrl-g` then `Ctrl-g` | Send one `Ctrl-g` to the agent, and stay in Interact |
| `Ctrl-Alt-g` | Goes to the agent as it is |
| any other key | Goes to the agent unchanged |

Pasted text reaches the agent with its paste markers, only when the agent asked for them.

If an agent stops while you are typing to it, the screen goes back to Overview and says so.
Your next keys do nothing until you press `Esc` or `Ctrl-g`.
Without that pause, the end of a sentence you were typing could restart, quit or start a session.

## What it protects

- Status cannot be forged by an agent.
  The state words come from `hb` over a private channel, not from the agent's terminal.
  An agent can print anything it likes, but it appears only inside its own pane.
- The agent cannot reach the channel.
  `hb` closes every inherited descriptor at start and keeps only its own copy, which no child receives.
  The variable that names it, `HB_SUPERVISOR_FD`, is left out of every child's environment.
- What an agent prints cannot act on your terminal.
  Clipboard writes, window titles and bells are counted and not performed.
  The emulator never answers a terminal query, so nothing can make your terminal type into an agent.
  Direction overrides and invisible format characters are replaced with a placeholder before they are drawn.
- Your terminal is put back after a normal exit, an error, a panic, and `SIGTERM`, `SIGHUP` or `SIGQUIT`, which also stop every session.
  `Ctrl-C` is a key for the agent while you type to it, so it does not end the supervisor.
  During an approval review it cancels the review and nothing else.
- If the supervisor goes away, every session stops.
  `SIGKILL` of the supervisor closes the channel, and each `hb` takes that as a stop.
- Denials are information.
  There is no "allow this" action.

## What it does not protect

- It is not a second sandbox.
  An agent is confined by its own `hb` and the Seatbelt profile, exactly as in `hb run`.
- A stopped supervisor is not noticed while the channel stays open and quiet.
  `SIGSTOP`, or a job stopped with `Ctrl-Z`, leaves sessions running under their own `hb`, and they keep running.
  `SIGSTOP` and `SIGKILL` also cannot restore your terminal; run `reset` if it is left raw.
- A restart or stop ends the agent and what it started in its group.
  It cannot prove that something that left the group, or was started by a program that ended first, is gone.
  The report `cleanup: complete` means the agent exited and `hb` finished its normal teardown.
  It does not mean every process or file is gone.
- Cleanup of a process that leaves its session on purpose has the limits described for `hb run`.
  See [Reference](07-reference.md).
- Output the agent produces while nothing reads your terminal is dropped once a stop begins.
  It is not kept for later.
- Each session's scrollback is sized when it starts: at most 10,000 lines, fewer for a wide window, for about 8 MiB.
  Widening your window later keeps that line count, so the memory grows in proportion.
  The agent cannot resize it.
  Older lines are dropped.

## Which agents were tried

Each was started in an empty directory with no prompt sent, so no request went to any model.
The check was that its screen drew, that typed text and a resize reached it, and that it ended when asked.
macOS 15 on Apple silicon, from a terminal that is not itself sandboxed.

| Agent | Version | Result |
|---|---|---|
| claude | 2.1.328 | Works. Starts on a trust menu; the check moved the selection and did not answer it. |
| pi | 1.7.0 | Works. Sets the window title twice at start, which is counted and not shown. |
| kiro-cli | 3.6.2 | Works. Starts on a trust menu, like claude. |
| opencode | 2.4.2 | Works, with one difference: it redraws a status line every few seconds with no input, about 700 to 900 bytes in two seconds. Version 1.2.0 sent nothing until it was touched and took about 5 seconds to start. |

These are observations of those versions on this machine.
They do not cover a model's answers, a long session, or any other terminal program.
A newer agent can behave differently; the opt-in check that produced this table is `HB_SUPERVISE_AGENTS=1 cargo test --all-features --test supervise_agents -- --nocapture --test-threads=1`.

## Terminals

The supervisor was driven through a pseudo-terminal in its tests and by hand in a macOS terminal.
Mouse input to an agent is passed through only as far as those tests proved.
It does not attach to sessions that were started somewhere else, keep sessions after it ends, restart sessions by itself, or let you drive two agents at once.

## Reading a session that ended

| Shown | Meaning |
|---|---|
| `Exited 0` | The agent ended with that status and `hb` finished its normal teardown. |
| `Exited` with an alert | It ended, and cleanup was not confirmed. Restart is refused until that is settled. |
| `Failed` | `hb` could not start it. The reason is shown in the pane. |
| `Lost` | The channel broke before the session reported its end. |

A restart waits until the old agent has ended.
It never runs two copies of one session at the same time.
