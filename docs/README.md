<!-- ABOUTME: Index of the hamster-ball guide: what each document covers and the order to read them in. -->
<!-- ABOUTME: The guide explains `hb` to a new user; the top-level README is the short version and ref/ holds the design. -->

# The hamster-ball guide

`hb` runs an AI coding agent inside a sandbox on macOS.
Three names are used throughout:

- hamster-ball is the project.
- `hb` is its command.
- The ball is the sandbox that `hb` builds around one run.

The agent works freely inside the ball and can reach only what you allow.

This guide explains what `hb` is, how it works, how to use it and how to configure it.
It is written for someone who has not seen the tool before.

## Read in this order

| # | Document | Read it to learn |
|---|---|---|
| 1 | [Concepts](01-concepts.md) | What hamster-ball is, why you would use it, what it builds on, and what it protects against |
| 2 | [How it works](02-how-it-works.md) | The parts of `hb`, what happens during a run, and what "inside the ball" means for an agent |
| 3 | [Getting started](03-getting-started.md) | Install, first config, first run, and how to use it with kiro-cli, pi, claude and opencode |
| 4 | [Configuration](04-configuration.md) | The config files, how they combine, and every setting |
| 5 | [Commands](05-commands.md) | Every `hb` command and option |
| 6 | [Use cases](06-use-cases.md) | Common situations: what to run, and what happens underneath |
| 7 | [Reference](07-reference.md) | Exit codes, files, environment variables, the floor, limits and troubleshooting |

## Where to start

- To try it, read [Getting started](03-getting-started.md).
- To understand what you are trusting, read [Concepts](01-concepts.md) and [How it works](02-how-it-works.md).
- To fix something that does not work, go to [Troubleshooting](07-reference.md#troubleshooting).

## Other documents

- [README](https://github.com/dmrolfs/hamster-ball/blob/main/README.md): the short version, with the same material in one page.
- [Design](https://github.com/dmrolfs/hamster-ball/blob/main/ref/Hamster-Ball-Design.md): the full design, every measurement and the numbered decision log (D1 to D90).
- [Presets](https://github.com/dmrolfs/hamster-ball/blob/main/presets/README.md): how to write an agent preset and check it against the real agent.

## Terms

Short definitions are in the [glossary](01-concepts.md#glossary).

## A note on what is measured

Statements in this guide that say "measured" come from runs on a real machine (macOS 15.7, Apple silicon).
The design document lists each one with its evidence.
Anything not measured is said to be unverified.
