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

Humans review and operate. Every human command signs in by itself when
it needs to (`lonca human login` does it up front, `--ttl 8h` for a
longer session); a file key never prompts, a Secure Enclave key prompts
once per session:

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
through Lonca's proxy. They name the daemon's uid in a root-owned file, and
the hook, the MCP server and the CLI refuse to send a token to any other
process on the socket. They never edit sudoers; `lonca doctor` tells you
when sudo asks for no password. `--render DIR` shows the generated files
without installing anything.

A hardened daemon starts each new repository from the hardened profile and
does not start without a sandbox. See
[docs/guide/profiles.md](docs/guide/profiles.md).

Repositories created in cooperative mode move with their history: stop
the cooperative daemon, restore each store into the hardened daemon
(`lonca restore`, below), and run `lonca daemon-key recover --repo <name>`
as an enrolled human. The same command continues a repository whose
`daemon.key` was lost; `lonca daemon-key rotate` replaces a key that is
still there. See [docs/decisions.md](docs/decisions.md), "Daemon keys".

## Checking a setup

`lonca doctor` shows what most first runs trip over: which mode is running,
the socket and the daemon, Claude Code's managed settings, the sandbox, `git`
and `lsof`, and for each repository whether your human can act on it and
whether its log verifies. Each line passes, warns or fails with what to do
about it; a failure exits 1. `--json` is for scripts. It prints no token, no
key and no path to one, and a Secure Enclave key is never prompted for: log
in first.

## Backup, restore and moving to another machine

A repository is its bare store: trunk, the operation log, the policy and
every proposal are refs of one Git repository, so a backup is a Git bundle
and a restore is a fetch.

```sh
lonca backup --out /Volumes/usb/lonca     # one bundle per repository
lonca restore demo --from /Volumes/usb/lonca/demo-000412.bundle
lonca daemon-key recover --repo demo      # only if this daemon's key is new
lonca-audit verify ~/.lonca/repos/demo.git
```

- **What is backed up:** the bundle written by the daemon (every ref, at
  one point of the log), or the remote `lonca push` sends trunk, the log,
  policy and proposals to. A pushed remote is a complete backup and is
  audited in CI; `lonca backup` also works offline and before any push.
- **What is not:** the daemon key (`daemon.key`; a restore on another key
  is continued with `lonca daemon-key recover`, which every auditor sees),
  session token hashes (`tokens.json`; sessions in a restored log need new
  tokens, that is new sessions), freeze flags, the verifier's scratch
  directory and agent workspaces (`lonca session start` recreates them).
  Human keys live in `~/.config/lonca/humans`, not in the daemon's home:
  back up file keys separately; a Secure Enclave key never leaves its Mac,
  so set a recovery key (`lonca human recovery-key --out`) and keep it off
  the machine.
- **A restore never replaces a repository.** The log is append-only; a
  restore over a longer log would be the rewrite the auditor exists to
  catch. Move the broken store away first (as the daemon's user) or audit
  the backup elsewhere. The name must be the one the log was created
  under, because human signatures bind it.
- **Permissions:** the daemon writes bundles with mode 0640 into
  `~/.lonca/backups` (hardened mode: `/Library/Lonca/backups` or
  `/var/lib/lonca-backups`, readable by group `lonca`). A restored store
  belongs to the daemon's user; the source must be readable by it.
- **Verify a backup without restoring it:**
  `git init --bare x.git && git -C x.git fetch demo-000412.bundle
  '+refs/*:refs/*' && lonca-audit verify x.git`.

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

## Documentation

- [docs/protocol.md](docs/protocol.md): the daemon's protocol for
  runners and other clients (methods, credentials, shapes, error codes,
  the CLI's `--json` outputs and exit codes).
- [docs/guide/runners.md](docs/guide/runners.md): running agents on
  Lonca (Claude Code hooks, the MCP entry, scratch directories, taint).
- [docs/guide/humans.md](docs/guide/humans.md): working as a human, from
  a Lonca workspace or from a git checkout (`lonca fetch`,
  `lonca propose --commit`).
- [docs/guide/profiles.md](docs/guide/profiles.md): the settings a
  repository starts from, and what each set protects against.
- [docs/guide/verification.md](docs/guide/verification.md): build and
  test commands, their environment and sandbox, starters per language.
- [docs/decisions.md](docs/decisions.md): decisions and deviations from
  the design ([docs/design.md](docs/design.md), Turkish).
- [docs/security/owasp.md](docs/security/owasp.md): Lonca against the
  OWASP lists and an ASVS 5.0 Level 2 checklist;
  [docs/crypto.md](docs/crypto.md): keys, algorithms and secrets.

## License

Apache-2.0. See [LICENSE](LICENSE).
