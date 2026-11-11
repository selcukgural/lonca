# Troubleshooting

Start with `lonca doctor`; then find the reason or the error you got below.
A denial is an answer, not a failure: the operation is in the log with its
reasons, and the reasons say what to do.

## `lonca doctor`

```text
Doctor summary (lonca 0.2.3):

[✓] Mode: cooperative: the daemon runs as you
[✓] Daemon
    ✓ socket: /Users/ayse/.lonca/lonca.sock belongs to the daemon
    ✓ daemon: version 0.2.3, protocol 1
[!] Hooks
    ! no managed settings at /Library/Application Support/ClaudeCode/managed-settings.json
      → sessions count as unobserved until the hardened installer has run
[✓] Sandbox: seatbelt
[✓] Tools
    ✓ git: found
    ✓ lsof: found
[✓] Human
    ✓ human: ayse
    ✓ security events: none in the last 24 hours
[✓] Repository demo
    ✓ log: 6 entries verify
    ✓ human: ayse is enrolled

! Doctor found issues in 1 category.
```

The checks are grouped, each group marked with its worst check (`✓`, `!`
for a warning, `✗` for a failure), and anything that does not pass says
what to do on the line under it (`→`). A warning leaves the exit code 0, a
failure makes it 1; `--json` gives `{"ok", "mode", "checks"}`. Colour only on
a terminal, never with `NO_COLOR` or `TERM=dumb`. Nothing in it prompts: with a
Secure Enclave key or a security key and no live session it asks you to run
`lonca human login` first.

| Check | Not passing | What to do |
|---|---|---|
| `mode` | `/Library/Lonca/daemon.toml` or `/etc/lonca/daemon.toml` is not root-owned, or is writable by others | Run the hardened installer again. The CLI refuses to send a token until it is fixed. |
| `socket` | no socket | Start `lonca daemon`, or set `LONCA_SOCKET` to where it listens. |
| `socket` | it belongs to another user | Someone else's process listens there. Run the hardened installer again; do not work around it. |
| `daemon` | it does not answer | Restart the daemon; its output says why it stopped. |
| `daemon` | `protocol N, this CLI speaks M` (fail), or another version (warn) | Use the same release for the CLI and the daemon. After an upgrade, restart the daemon. |
| `hooks` | not locked by managed settings | Cooperative: a warning, sessions count as unobserved. Hardened: a failure, run the installer again. |
| `sandbox` | none found | Install `bubblewrap` (Linux). Without it verification runs unsandboxed; a hardened daemon refuses to start. |
| `sudo` | runs without a password (hardened only) | An agent running as you could use it: set `Defaults timestamp_timeout=0`, or work from a non-admin account. Sessions count as unobserved until then. |
| `git` | not on `PATH` | Install git. |
| `lsof` | not on `PATH` | Install lsof; without it network use can not be attributed to a session. |
| `human` | no identity | `lonca human keygen <name>`. |
| `human` | could not open a session | `lonca human whoami`; maybe no repository knows this human yet (`lonca init`, or ask an enrolled human to `lonca human enroll` you). |
| `security events` | a freeze, an integrity alarm, a write behind the daemon's back, a failed reconcile in the last day | Read the daemon's `security.log` and `lonca log` for the entries. |
| `log <repo>` | does not verify, or ends before the daemon's head | Run `lonca-audit verify` on the store or a pushed copy, and freeze the repository until you know why. |
| `human <repo>` | not enrolled | An enrolled human runs `lonca human enroll`. |
| `human <repo>` | a file key where the repository requires presence | `lonca human rotate --secure-enclave --repo <repo>` (Mac) or `--security-key` (a FIDO security key). |
| `presence` | the key is in hardware and the program that signs with it is missing | Put `lonca-se` next to `lonca` (Secure Enclave), or install OpenSSH 8.2 or later (security key). With a file key the line only says what this machine could use. |
| `settings <repo>` | below the hardened profile, on a hardened install | A human changes them with `lonca policy set` ([Profiles](profiles.md)). |
| `frozen <repo>` | frozen | Find out why (`lonca log`), then `lonca unfreeze "<reason>"`. |

## Denials

`lonca` prints `#SEQ deny: <reasons>` and exits 1. The common ones, by what
caused them:

### The lease

| Reason | What to do |
|---|---|
| `lease_missing:<symbol>` | Lease it (`lonca lease acquire`), then propose again. `lonca lease needed` lists what the local changes need and who holds it. |
| `lease_held:<symbol>:<session>:<intent>` | Another session holds it. Wait (`lonca lease interest`, or the `lease_interest` tool), settle it with `negotiate`, or work on something else. |
| `lease_expired`, `not_own_lease`, `unknown_lease_set` | The set is gone or not yours: acquire again. |
| `lease_hold_limit` | Held past `leases.max_hold_minutes` while someone waits: finish, or let it go and acquire again. |
| `lease_reserved:<session>`, `lease_wanted:<session>` | Freed and reserved for that session, or that session waits first. The answer's `details` say until when. |
| `lease_free` | An interest in something nobody holds: acquire it instead. |
| `intent_required` | Say what you are doing and why (`-i`). |
| `shared_off` | `shared` leases are off in this repository. |
| `created_since_base:<path>` | Trunk created that file after your base: `lonca sync`, then lease and propose. |
| `key_not_reserved:<dir>#<key>` | A new file in a keyed directory needs its key: `lonca lease acquire '<dir>#<dir>' --kind insert --name <key>` (or `--name next`, then rename the file to the key it gives). |
| `key_taken:<dir>#<key>` | Another file has that key, in your tree or on trunk since your base: `lonca sync`, reserve `next` and rename the file. |
| `key_unreadable:<path>` | The file's name has no key the directory's pattern reads (`[paths.keyed]` in `lonca.toml`): name it as the others are. |
| `not_keyed:<dir>`, `key_required:<symbol>`, `invalid_key:<dir>#<key>` | A `<dir>` lease is an `insert` with keys, on a directory `[paths.keyed]` names; a number key has no leading zero. |
| `key_container:<dir>#<dir>` | A keyed directory is leased only as its container, written as it is, `<dir>` included: `lonca lease acquire '<dir>#<dir>' --kind insert --name <key>`. `lonca status` lists the keyed directories. |

### The proposal

| Reason | What to do |
|---|---|
| `claim_mismatch:<field>` | The claim differs from what Lonca computed. `lonca diff` (or the `preview` tool) prints the facts: copy them into the claim. |
| `stale_trunk`, `unknown_base` | `lonca sync`, then propose again. |
| `scope_path:<path>`, `scope_symbol:<symbol>`, `scope_op:<op>` | Outside the session's scope. Leave that file alone, or a human starts a session with a wider scope (`--continue <dir> --widen` keeps the workspace). |
| `scope_max_files`, `scope_max_lines` | Too big for the session: split the change. |
| `unobserved_critical_path`, `tainted_critical_path`, `unhooked_critical_path` | A critical path (`Cargo.toml`, `.github/**`, `CLAUDE.md`, …) from a session that is not fully observed. See [Every change waits for me](#every-change-waits-for-me-and-agents-can-not-touch-cargotoml). |
| `verification_quota:session`, `verification_quota:day` | Past `[quota]`. The session's does not come back; the day's does at midnight UTC. |

### The session or the repository

| Reason | What to do |
|---|---|
| `session_ended`, `session_inactive`, `unknown_session`, `session_ttl` | The session is over. A human continues the workspace: `lonca session start --continue <dir>`. |
| `session_continued`, `continue_child_session`, `scope_widening:<what>` | That continuation is refused: a session is continued once, a child session is not continued, a wider scope needs `--widen`. |
| `continue_other_workspace` | A session is continued in the directory it was started in. One started before Lonca 0.2.4, or whose directory was moved, can not be: start a new session in a new workspace. |
| `workspace_in_use`, `invalid_workspace` | Another live session works in that directory, in one inside it or around it; or the path is not an absolute, plain directory path. Use another directory, or continue or end the session that is there. |
| `frozen:<reason>` | A human unfreezes it once the reason is dealt with. |
| `already_approved` | You approved this one already; it waits for another human. |
| `nothing_pending` | That sequence number does not wait for approval (approved, rejected or withdrawn meanwhile). |

### A human signature

| Reason | What to do |
|---|---|
| `presence_required` | The repository accepts only keys that prove presence: `lonca human rotate --secure-enclave` (Mac) or `--security-key` (a FIDO security key). |
| `not_enrolled`, `unknown_human` | That key is not enrolled in this repository. |
| `stale_human_signature` | The signature is older than 10 minutes or more than a minute ahead: check the clock. |
| `bad_human_signature`, `bad_nonce`, `nonce_reused` | The request was refused as signed. Run the command again; if it repeats, report it. |

Anything else is a policy rule's id or a key operation's reason: the rule
is in `lonca policy show`. All codes: `docs/protocol.md`, "Reason codes".

## Errors

An error means the request never reached the log.

| Error | What to do |
|---|---|
| `unauthenticated: unknown session token: …` | The agent's session ended, expired or got a new token. A human continues the workspace (`lonca session start --continue`). Restart `lonca mcp` after that, so it reads the new token. |
| `unauthenticated: login failed: …` | No enrolled key of that human verifies the signature: wrong `--as`, or the key was rotated on another machine. |
| `forbidden` | A token of the wrong kind or for another repository, or a human the repository does not know. |
| `rate_limited` | The session (with the sessions made from it) is past `[sessions] ops_per_minute`. The message says when to try again. |
| `busy`, `closed` | Send it again. |
| `foreign_key` | The repository is on a daemon key this daemon does not hold: `lonca daemon-key recover --repo <name>`, or, when your key was lost with it, `lonca human recover --repo <name> --recovery-key <file>` ([Recovery](recovery.md#a-lost-mac)). |
| `integrity` | The log does not verify or replay. Do not write to the store; audit it and restore from a backup or a pushed remote. |
| `unsupported` | A log format or symbol engine this daemon does not know: upgrade the daemon. |
| `redacted` (on `lonca fetch`) | A redacted blob is in trunk's history; Git needs whole objects. Work from a Lonca workspace. |

## Common situations

### Every change waits for me, and agents can not touch `Cargo.toml`

That is cooperative mode: nothing can prove what an agent running as you
did, so its sessions are `unobserved`, every change escalates
(`unobserved_session`), and a change to a critical path is denied
(`unobserved_critical_path`) with nobody to ask. Three ways out:

- If you do read every change, let critical paths escalate instead of
  being denied: `unobserved_critical = "escalate"` under `[observation]`,
  set with `lonca policy set`
  ([Running agents](runners.md#critical-paths-in-cooperative-mode)). Do not
  set `unobserved_is_tainted = false`: the review goes with the denial.
- Install hardened mode, where Claude Code's hooks and sandbox are locked
  and sessions are observed ([Install](install.md#hardened-mode)).
- Run the agent under `lonca run`, which gives the session `isolated` in a
  sandbox Lonca owns ([Running agents](runners.md#any-agent-in-a-sandbox)).

### Changes integrate without any build or tests

No `build` or `test` command is set in `[verification]`, so nothing checks
that the code compiles: a file the grammar can not read waits for a person,
whether it is a mistake or syntax newer than the grammar
([Languages](languages.md)). Set them with
`lonca policy set`; with
`verification.required = true` a change can not land without them
([Verification](verification.md)).

### A change stays queued

`lonca status` shows the queue. The daemon's worker takes the head of the
queue (one change, or `[queue] batch_size` of them), and each check can take
up to `verification.timeout_seconds`. If nothing moves, `lonca queue` wakes the worker; the daemon's output
says what it is doing.

### A change is `conflicted` or `rejected`

`lonca change <id> --evidence` says which symbols conflicted or which check
failed, with its log. The agent syncs, fixes and proposes again
([Reviewing agents' work](reviewing.md#after-approval)).

### A session is `unhooked`, or never bound

`status` shows `unhooked` when a call to `lonca mcp` came without the
harness's hook event before it: a flag, a setting or a new version skipped
the hooks. The session is tainted for good. Fix the harness's settings and
start a new session. A session started without `--harness` stays
`unobserved` on any machine
([Running agents](runners.md#observation-levels)).

### Touch ID, or a touch, on every command

Each command opened a session of its own because none was live. `lonca human
login --ttl 8h` opens one for the day (at most 24 hours).

### `lonca init` refuses a file key

A hardened repository requires presence, and a file key would lock itself
out of everything after the first entry. Use `lonca human keygen <name>
--secure-enclave` (Mac) or `--security-key` (a FIDO security key), or with
neither, `lonca init <repo> --without-presence`
([Profiles](profiles.md#presence)).

### A security key does not sign

`ssh-keygen could not be run`: a security key signs through OpenSSH 8.2 or
later; install it, or name one with `LONCA_SSH_KEYGEN` (the `ssh-keygen` of
macOS has no FIDO support built in; Homebrew's has). `ssh-keygen did not
sign`: the key was not touched in time or is not plugged in. A denial
`bad_human_signature` with a key that was touched: the key was made with
`no-touch-required`, or for another application than `ssh:lonca`; make one
with `lonca human keygen --security-key`.

### The daemon will not start

- **Socket path too long.** Unix socket paths are limited to about 100
  bytes. Use a shorter `LONCA_HOME`, or set `LONCA_SOCKET`.
- **No sandbox** on a hardened install: install `bubblewrap`, or start it
  with `--allow-unsandboxed` and accept that verification is unsandboxed.
- **A repository does not verify**: the daemon refuses to open a log whose
  chain or key switches do not replay, and says which. Audit it with
  `lonca-audit verify`; restore it from a backup or a pushed remote
  ([Recovery](recovery.md)).
