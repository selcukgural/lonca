# Quick start

Cooperative mode, on one machine. [Install](install.md) first.

## A repository and an agent's session

```sh
lonca daemon &                       # the gatekeeper (~/.lonca)
lonca human keygen ayse              # or: --secure-enclave
lonca init demo --import ~/src/myproject

# Give an agent a session and a workspace, set up for Claude Code.
lonca session start --repo demo --agent claude --paths 'src/**' \
      --task T-142 --ttl 2h --workspace ~/ws/claude-1 --harness claude-code
```

`--harness claude-code` writes the MCP server and the hooks into the
workspace (`.mcp.json`, `.claude/settings.local.json`); start Claude Code
there and the hook tells the agent Lonca's rules at session start. For other
harnesses and for runners that start many workers, see
[Running agents](runners.md#setting-up-a-harness).

## What the agent does

In the agent's workspace, directly or through the MCP server (`lonca mcp`):

```sh
cd ~/ws/claude-1
lonca symbols src/billing.rs                 # lease ids
lonca lease acquire 'src/billing.rs#Client.charge' -i "rate limiting"
# ... edit ...
lonca diff                                   # facts of the local change
lonca propose -i "rate limit charge" --edits 'src/billing.rs#Client.charge'
lonca sync                                   # after integration
```

## What you do

Humans review and operate. Every human command signs in by itself when it
needs to (`lonca human login` does it up front, `--ttl 8h` for a longer
session); a file key never prompts, a Secure Enclave key or a security key prompts once per
session:

```sh
lonca status --repo demo
lonca pending --repo demo
lonca advise <change> --repo demo            # AI advisory (ANTHROPIC_API_KEY)
lonca approve 17 --repo demo
lonca undo 23 --repo demo                    # compensating operation
lonca revert --actor agent:claude --since-seq 40 --repo demo   # dry run
lonca push git@github.com:me/myproject.git --repo demo
lonca-audit verify ~/.lonca/repos/demo.git  # cooperative mode's store
```

`~/.lonca/repos/` is where a cooperative daemon keeps its stores. A
hardened daemon's home (`/Library/Lonca/home`, `/var/lib/lonca`) is
readable by its user only: audit a pushed remote or a backup bundle there
(see "Backup and moving" below).

Your own edits go through the daemon too, from a Lonca workspace or from a
Git checkout: see [Working as a human](humans.md). Reading, approving and
undoing agents' changes: [Reviewing agents' work](reviewing.md).

## Checking it

`lonca doctor` shows which mode is running, the socket and the daemon,
Claude Code's managed settings, the sandbox, `git` and `lsof`, and for each
repository whether your human can act on it and whether its log verifies.
Each line passes, warns or fails with what to do about it; `--json` is for
scripts. [Troubleshooting](troubleshooting.md) goes through each check and
the common denials.

The auditor checks a repository wherever it is, a pushed remote in CI
included: it replays every decision and recomputes every fact and merge.
A ready workflow is
[docs/ci/lonca-audit.yml](https://github.com/selcukgural/lonca/blob/main/docs/ci/lonca-audit.yml).

## Backup and moving

A repository is its bare store, so a backup is a Git bundle and a restore
is a fetch:

```sh
lonca backup --out /Volumes/usb/lonca     # one bundle per repository
lonca restore demo --from /Volumes/usb/lonca/demo-000412.bundle
lonca daemon-key recover --repo demo      # only if this daemon's key is new
lonca-audit verify ~/.lonca/repos/demo.git  # cooperative; restore prints the path
```

On a hardened daemon `lonca restore` says to verify the source instead,
since the store it wrote is not yours to read; it holds the same log.

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
  belongs to the daemon's user; the source must be readable by it. A
  hardened daemon reads a source only in its backups or its import
  directory.
- **Verify a backup without restoring it:**
  `git init --bare x.git && git -C x.git fetch demo-000412.bundle
  '+refs/*:refs/*' && lonca-audit verify x.git`.

The same `lonca daemon-key recover` continues a repository whose
`daemon.key` was lost; `lonca daemon-key rotate` replaces a key that is
still there (the reasons are in
[docs/decisions.md](https://github.com/selcukgural/lonca/blob/main/docs/decisions.md),
"Daemon keys"). Lost keys, rotation and a lost Mac: [Recovery](recovery.md). Moving cooperative repositories into a hardened install is
in [Install](install.md#hardened-mode).
