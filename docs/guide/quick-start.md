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
session); a file key never prompts, a Secure Enclave key prompts once per
session:

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

Your own edits go through the daemon too, from a Lonca workspace or from a
Git checkout: see [Working as a human](humans.md).

## Checking it

`lonca doctor` shows which mode is running, the socket and the daemon,
Claude Code's managed settings, the sandbox, `git` and `lsof`, and for each
repository whether your human can act on it and whether its log verifies.
Each line passes, warns or fails with what to do about it; `--json` is for
scripts.

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
lonca-audit verify ~/.lonca/repos/demo.git
```

Human keys live in `~/.config/lonca/humans`, not in the daemon's home: back
up file keys separately; a Secure Enclave key never leaves its Mac, so set a
recovery key (`lonca human recovery-key --out`) and keep it off the machine.
What a backup holds and what it does not is in
[the README](https://github.com/selcukgural/lonca#backup-restore-and-moving-to-another-machine).
