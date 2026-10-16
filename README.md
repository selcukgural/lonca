# Lonca

**Agent-native, Git-compatible version control.**

Lonca (Turkish: the craft guild — written rules, masters and apprentices,
inspection before anything reaches the market) is a version control system
designed for repositories where many AI agents and a few humans work at the
same time. Content stays plain Git, so GitHub and every Git tool keep
working. What changes is everything around it: who may do what, how
concurrent work merges, and how every action is recorded and checked.

> Status: early prototype (v0.1). Every phase of the design is implemented
> and tested, but it has not been used on real projects yet. See
> [Limitations](#limitations).

## Why

Git and its forges assume every writer is a person. Agents usually work with
a person's token, are invisible in the history, have far more rights than
their task needs, and can force-push, delete or change permissions with no
reviewable trail. Lonca's answer has four parts:

- **One deterministic gatekeeper.** Agents never write to the repository.
  They propose; a daemon decides with a pure function of the log, the
  request, recorded evidence, time and the repository's policy.
- **Capabilities, not accounts.** A session gets narrow, expiring rights
  (paths, symbols, operations, size limits). Rights can only be narrowed
  when handed to sub-agents, and revoking a session revokes everything
  derived from it.
- **Symbol leases and a structural merge queue.** Agents lease the
  functions and types they edit. Twenty agents can change twenty functions
  of one file in parallel; every merged state is verified before it
  becomes trunk.
- **A signed, hash-chained operation log that anyone can replay.** Every
  operation — allowed, denied or escalated — is in the log, which travels
  with `git push`. An independent auditor replays every decision,
  recomputes every fact and merge, and catches forgeries even when they
  are signed with the daemon's own key.

AI is used where it helps and never where integrity depends on it: an
advisor summarizes changes and flags risks for human reviewers, with no
authority.

## How it works

```
 agents (MCP, CLI)          humans (CLI, signatures)
         │                            │
         └──── Unix socket ───────────┘
                     │
   ┌─────────────────▼─────────────────────┐
   │ lonca daemon — the only writer        │
   │ sessions · capabilities · Cedar policy│
   │ leases · merge queue · provenance     │
   │ decide() — pure, replayable           │
   └──────┬─────────────────────────┬──────┘
          │ jobs        attestations│ allowed ops
   ┌──────▼──────────┐   ┌──────────▼───────────────┐
   │ verifier        │   │ Git object store         │
   │ sandboxed build │   │ refs/heads/main          │
   │ and tests       │   │ refs/lonca/oplog (chain) │
   └─────────────────┘   │ refs/lonca/policy        │
                         └──────────┬───────────────┘
                                    │ git push
                         ┌──────────▼───────────────┐
                         │ GitHub / any Git remote  │◄── lonca-audit (CI)
                         └──────────────────────────┘
```

- **Proposal.** An agent submits its workspace changes with a *claim*: the
  symbols it says it changed. Lonca computes the *facts* from the Git
  objects with tree-sitter (Rust, Python, TypeScript/TSX, JavaScript, C#,
  Go); any mismatch is refused. Every touched symbol must be leased.
- **Taint.** Hooks in the agent's harness report every tool call; a network
  proxy sees every outbound connection of sandboxed commands. A session that
  reads external content (a web page, an issue, another MCP server) is
  tainted: its changes need a human, and it may not touch build scripts,
  CI or lockfiles at all.
- **Integration.** The merge queue rebases each proposal onto trunk with a
  symbol-level three-way merge (different symbols never conflict, the same
  symbol does), runs the configured build and tests in a sandbox with no
  network, and only then moves trunk.
- **Policy.** `refs/lonca/policy` holds `lonca.toml` (limits) and
  `policy.cedar` (rules). Rules can deny or escalate to one or more human
  approvals. Evaluation errors deny.
- **Humans** sign their operations. With `--secure-enclave` the key lives
  in the Mac's Secure Enclave and every signature needs Touch ID or the
  password, so an agent running as you can not approve on your behalf.

## Quick start (cooperative mode)

```sh
cargo build --release
export PATH="$PWD/target/release:$PATH"

lonca daemon &                       # the gatekeeper (~/.lonca)
lonca human keygen ayse              # or: --secure-enclave
lonca init demo --import ~/src/myproject

# Give an agent a session and a workspace.
lonca session start --repo demo --agent claude --paths 'src/**' \
      --task T-142 --ttl 2h --workspace ~/ws/claude-1
```

In the agent's workspace (directly or through the MCP server):

```sh
cd ~/ws/claude-1
lonca symbols src/billing.rs                 # lease ids
lonca lease acquire 'src/billing.rs#Client.charge' -i "rate limiting"
# ... edit ...
lonca diff                                   # facts of the local change
lonca propose -i "rate limit charge" --edits 'src/billing.rs#Client.charge'
lonca sync                                   # after integration
```

Humans review and operate:

```sh
lonca status --repo demo
lonca pending --repo demo
lonca advise <change> --repo demo            # AI advisory (ANTHROPIC_API_KEY)
lonca approve 17 --repo demo
lonca undo 23 --repo demo                    # compensating operation
lonca revert --actor agent:claude --since-seq 40 --repo demo   # dry run
lonca push git@github.com:me/myproject.git --repo demo
lonca-audit verify ~/.lonca/repos/demo.git
```

For Claude Code, add the MCP server in the agent's workspace
(`claude mcp add lonca -- lonca mcp`) and install the hooks (see below). At
session start the hook tells the agent Lonca's rules.

## Observation levels

| Mode | Agents run | Store bypass | Observation bypass | Setup |
|---|---|---|---|---|
| Cooperative | as you | detected (hash chain, auditor) | none: sessions count as unobserved → every change needs a human | none |
| Hardened | as you, harness hooks and sandbox locked | prevented (daemon is a separate system user) | from the harness: prevented; from outside: detected | `sudo packaging/macos/install-hardened.sh` |
| Isolated | in a container/OS sandbox | prevented | prevented | your container runtime |

The hardened installers (macOS launchd, Linux systemd) create the `_lonca`
system user, install root-owned binaries, lock Claude Code's hooks and
sandbox through managed settings and route sandboxed network traffic
through Lonca's proxy. They never edit sudoers; read their advice about
sudo's credential cache. `--render DIR` shows the generated files without
installing anything.

## Repository layout

| Crate | Role |
|---|---|
| `lonca-core` | Git object store (gitoxide), change ids (jj-compatible), keys, operation log |
| `lonca-policy` | State fold, decision function, Cedar policy, human signatures |
| `lonca-symbols` | tree-sitter symbols, facts, structural merge, integration |
| `lonca-verify` | Sandboxed build/test evidence (Seatbelt, bubblewrap) |
| `lonca-daemon` | Gatekeeper service, socket server, hooks, network proxy |
| `lonca-audit` | Independent auditor (`lonca-audit` binary) |
| `lonca-cli` | `lonca` command, workspaces, Claude Code hook, MCP server, advisor |

Design: [docs/design.md](docs/design.md) (Turkish). Decisions and their
reasons: [docs/decisions.md](docs/decisions.md).

## Limitations

- Prototype. Not yet used on real projects; formats may change.
- One daemon per machine, one sequencer per repository. A team server is
  designed for, not built.
- Symbol extraction covers six languages; other files are leased whole.
  Signature changes are detected and must be declared, but their callers
  are not analyzed; the merge queue's tests are what catch broken callers.
- Verification needs `bubblewrap` on Linux to be sandboxed.
- Redaction is logical: content is withheld by the daemon, objects are not
  yet purged from Git history.
- Creating a Secure Enclave key needs an interactive session; it could not
  be exercised in automated tests (signature format is tested).
- The advisor has been tested against a fake API only.

## License

Apache-2.0. See [LICENSE](LICENSE).
