# Lonca

<p align="center">
  <a href="https://selcukgural.github.io/lonca/"><img src="https://selcukgural.github.io/lonca/img/lonca-banner.svg" alt="Lonca: agents lease symbols and propose; the daemon decides, signs and logs; the merge queue builds and tests; trunk stays plain Git; lonca-audit replays every decision" width="100%"></a>
</p>

[![crates.io](https://img.shields.io/crates/v/lonca.svg)](https://crates.io/crates/lonca)
[![lonca-client on docs.rs](https://img.shields.io/docsrs/lonca-client?label=docs.rs%20lonca-client)](https://docs.rs/lonca-client)
[![Licence](https://img.shields.io/crates/l/lonca.svg)](LICENSE)

**Agent-native, Git-compatible version control.**

Lonca (Turkish: the craft guild — written rules, masters and apprentices,
inspection before anything reaches the market) is a version control system
designed for repositories where many AI agents and a few humans work at the
same time. Content stays plain Git, so GitHub and every Git tool keep
working. What changes is everything around it: who may do what, how
concurrent work merges, and how every action is recorded and checked.

Everything else is on the site: **<https://selcukgural.github.io/lonca/>**.

> Status: **0.2.2** ([release notes](https://selcukgural.github.io/lonca/docs/release-notes)).
> Every phase of the design is implemented and tested, and a log written by
> any 0.x release stays readable by every later one. 0.x is one machine: one
> developer with many agents
> ([scope](https://selcukgural.github.io/lonca/docs/guide#scope-of-0x)).

## Works with Claude Code

Claude Code is the harness Lonca is built and checked against, live, before
every release. Start a session with `--harness claude-code`, run `claude` in
its workspace, and every hook event and Lonca's MCP tools are already wired
to the daemon:

<p align="center">
  <img src="https://selcukgural.github.io/lonca/img/claude-code-loop.svg" alt="Claude Code's hook events (SessionStart, PreToolUse, PostToolUse, Stop) and Lonca's MCP tools, each carried to the daemon by lonca hook or lonca mcp" width="100%">
</p>

| Harness | Support |
|---|---|
| **Claude Code** | **Full**: every hook, the MCP server, the hardened and isolated levels |
| Codex, Gemini CLI, OpenCode | Profiles included; full support is coming. Isolated today under `lonca run` |
| IDE agents (Copilot, Cursor, JetBrains AI) | Planned; any MCP client can use `lonca mcp` today |

How it works, step by step:
[Lonca with Claude Code](https://selcukgural.github.io/lonca/docs/guide/claude-code).

In use: [imece](https://github.com/selcukgural/imece), a terminal for many
coding agents, runs every worker as a Lonca session.

## Install

macOS (arm64, x86_64) and Linux (x86_64, arm64):

```sh
curl -fsSL https://selcukgural.github.io/lonca/install.sh | sh   # ~/.local/bin
brew tap selcukgural/lonca                                       # or Homebrew,
brew trust --formula selcukgural/lonca/lonca                     # (Homebrew 7+)
brew install lonca
cargo install --locked lonca lonca-audit                         # or crates.io, Rust 1.90+
```

These install cooperative mode. Hardened mode, checking a download, upgrade
and uninstall: [Install](https://selcukgural.github.io/lonca/docs/guide/install).

## Quick start

```sh
lonca daemon &                       # the gatekeeper (~/.lonca)
lonca human keygen ayse              # or: --secure-enclave
lonca init demo --import ~/src/myproject
lonca session start --repo demo --agent claude --paths 'src/**' \
      --task T-142 --ttl 2h --workspace ~/ws/claude-1 --harness claude-code
lonca doctor                         # what a first run trips over
cd ~/ws/claude-1 && claude           # the agent, hooks and MCP set up
```

The agent leases the symbols it edits and proposes; you review, approve and
audit. The whole walk-through is the
[quick start](https://selcukgural.github.io/lonca/docs/guide/quick-start).

## Crates

Most people want the command: `cargo install --locked lonca` (and
`lonca-audit` for the auditor). Every crate has the workspace's version;
only `lonca-client` is meant to be depended on, and the internal crates'
APIs have no stability promise.

| Crate | What it is |
|---|---|
| [`lonca`](https://crates.io/crates/lonca) | The `lonca` command: daemon, workspaces, approvals, harness hook, MCP server |
| [`lonca-audit`](https://crates.io/crates/lonca-audit) ([docs](https://docs.rs/lonca-audit)) | The independent auditor, `lonca-audit verify` |
| [`lonca-client`](https://crates.io/crates/lonca-client) ([docs](https://docs.rs/lonca-client)) | Client of the daemon socket: what harnesses and runners depend on |
| [`lonca-net`](https://crates.io/crates/lonca-net) ([docs](https://docs.rs/lonca-net)) | Loopback CONNECT proxy that asks a gate about every connection |
| [`lonca-core`](https://crates.io/crates/lonca-core) ([docs](https://docs.rs/lonca-core)) | Change ids, the signed operation log, keys, the Git store |
| [`lonca-policy`](https://crates.io/crates/lonca-policy) ([docs](https://docs.rs/lonca-policy)) | The pure `decide()`, state replay, Cedar policies, human signatures |
| [`lonca-symbols`](https://crates.io/crates/lonca-symbols) ([docs](https://docs.rs/lonca-symbols)) | tree-sitter symbols, facts and the structural merge |
| [`lonca-verify`](https://crates.io/crates/lonca-verify) ([docs](https://docs.rs/lonca-verify)) | Sandboxed build and test runs, recorded as evidence |
| [`lonca-daemon`](https://crates.io/crates/lonca-daemon) ([docs](https://docs.rs/lonca-daemon)) | The single writer: decide, sign, log, apply |

## Documentation

- [The site](https://selcukgural.github.io/lonca/): guides, the protocol,
  release notes, the OWASP review and cryptography.
- [docs/design.md](docs/design.md) (Turkish) and
  [docs/decisions.md](docs/decisions.md): the design, and every decision
  and deviation from it with its reasons. [SECURITY.md](SECURITY.md) to
  report a vulnerability.

## License

Apache-2.0. See [LICENSE](LICENSE).
