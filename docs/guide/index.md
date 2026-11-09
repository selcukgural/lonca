# What Lonca is

Lonca (Turkish: the craft guild — written rules, masters and apprentices,
inspection before anything reaches the market) is a version control system
for repositories where many AI agents and a few humans work at the same
time. Content stays plain Git, so GitHub and every Git tool keep working.
What changes is everything around it: who may do what, how concurrent work
merges, and how every action is recorded and checked.

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

AI is used where it helps and never where integrity depends on it: the
decision function, the gatekeeper and the auditor have no AI, network or
randomness in them.

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
  objects with tree-sitter (Rust, Python, TypeScript and TSX, JavaScript,
  C#, Go, Java, Kotlin, C, C++, Ruby, PHP, Swift; other files are leased
  whole); any mismatch is refused. Every touched symbol must be leased.
- **Taint.** Hooks in the agent's harness report every tool call; a network
  proxy sees every outbound connection of sandboxed commands. A session that
  reads external content (a web page, an issue, another MCP server) is
  tainted: its changes need a human, and it may not touch build scripts,
  CI or lockfiles at all.
- **Integration.** The merge queue rebases each proposal onto trunk with a
  symbol-level three-way merge (different symbols never conflict, the same
  symbol does), runs the configured build and tests in a sandbox with no
  network, and only then moves trunk. See [Verification](verification.md).
- **Policy.** `refs/lonca/policy` holds `lonca.toml` (limits) and
  `policy.cedar` (rules). Rules can deny or escalate to one or more human
  approvals. Evaluation errors deny. A repository starts from a
  [profile](profiles.md).
- **Humans** sign their operations. With `--secure-enclave` the key lives
  in the Mac's Secure Enclave and every signature needs Touch ID or the
  password, so an agent running as you can not approve on your behalf. See
  [Working as a human](humans.md).

Each of these is explained on its own in [Concepts](concepts.md).

## Observation levels

| Mode | Agents run | Store bypass | Observation bypass | Setup |
|---|---|---|---|---|
| Cooperative | as you | detected (hash chain, auditor) | none: sessions count as unobserved → every change needs a human | none |
| Hardened | as you, harness hooks and sandbox locked | prevented (daemon is a separate system user) | from the harness: prevented; from outside: detected | `sudo ./install-hardened.sh --bin .` from a release archive |
| Isolated | in a container/OS sandbox | prevented | prevented | your container runtime |

The hardened installers (macOS launchd, Linux systemd) create the `_lonca`
system user, install root-owned binaries, lock Claude Code's hooks and
sandbox through managed settings and route sandboxed network traffic
through Lonca's proxy. They name the daemon's uid in a root-owned file, and
the hook, the MCP server and the CLI refuse to send a token to any other
process on the socket.

## Scope of 0.x

One machine, one daemon, one developer with many agents. Claude Code is the
harness whose hooks are checked in every release
([Lonca with Claude Code](claude-code.md)); other harnesses are profiles of
data ([Running agents](runners.md)). A team server is designed
for, not built. A log written by any 0.x release stays readable, verifiable
and auditable by every later release.

## Limitations

- Used on one real project so far: [imece](https://github.com/selcukgural/imece)
  runs its agents on Lonca, by the same developer.
- One daemon per machine, one sequencer per repository.
- Symbol extraction covers thirteen languages, and Markdown, TOML, JSON
  and YAML files are split into sections; other files are leased whole. Signature changes are detected and must be declared, but their
  callers are not analyzed: the merge queue's tests are what catch broken
  callers.
- Verification needs `bubblewrap` on Linux to be sandboxed.
- Redaction is logical: content is withheld by the daemon, objects are not
  yet purged from Git history.
- Creating a Secure Enclave key needs an interactive session; it could not
  be exercised in automated tests (the signature format is tested).
- The advisor has been tested against a fake API only.

The design (in Turkish) is
[docs/design.md](https://github.com/selcukgural/lonca/blob/main/docs/design.md);
every decision and its reasons are in
[docs/decisions.md](https://github.com/selcukgural/lonca/blob/main/docs/decisions.md).
