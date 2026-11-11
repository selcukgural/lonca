# Concepts

The words the rest of the guide uses, and how the parts fit. Each section
ends where another page goes deeper.

## The repository and its log

A repository lives in the daemon's store (`~/.lonca/repos/<name>.git` in
cooperative mode): a bare Git repository whose refs are trunk
(`refs/heads/main`), the policy (`refs/lonca/policy`), every proposal, and
the **operation log** (`refs/lonca/oplog`).

Every request that changes something becomes one entry in the log, with a
sequence number (`#12`), the actor (`human:ayse`, `agent:claude/ses_…`,
`daemon`), the operation and the decision: `allow`, `deny` or `escalate`.
Denied requests are logged too, so the log is also the record of what was
tried. Each entry is signed by the daemon and names the hash of the one
before it; a human's operations carry the human's signature as well.

- **Only the daemon writes.** It decides with `decide()`, a pure function of
  the log so far, the request and the policy, signs the entry, appends it
  and only then applies it (moves trunk, records a lease). Nobody else
  writes the store, and a ref that changes behind its back is restored or
  freezes the repository (`[integrity] on_unmediated`).
- **Nothing is rewritten.** An undo is a new operation that compensates for
  an old one (see [Reviewing agents' work](reviewing.md#undoing)).
- **Anyone can check it.** `lonca-audit verify` replays every decision and
  recomputes every fact and merge from the objects. The log travels with
  `lonca push`, so a remote can be audited in CI.

`lonca log --repo demo` lists the entries; `lonca status --repo demo` shows
the state they add up to.

## Humans

A human is a name with a key, **enrolled** in a repository: the one who runs
`lonca init` is enrolled by it, others by an enrolled human
(`lonca human enroll`). Humans start sessions, approve, change the policy and
answer incidents; agents can do none of that.

- A **file key** (`lonca human keygen ayse`) is a file in
  `~/.config/lonca/humans`. Anything running as you can sign with it, agents
  included.
- A **Secure Enclave key** (`--secure-enclave`, macOS) never leaves the
  Mac, and every signature needs Touch ID or the password.
- A **security key** (`--security-key`, a FIDO key through OpenSSH, on
  Linux too) never leaves the device, and every signature needs a touch.
  A repository with `approvals.require_presence = true` accepts only these
  two kinds of key ([Profiles](profiles.md#presence)).
- A **human session** (`lonca human login`, one hour by default) lets reads
  and prepared operations go without signing each time; every human command
  opens one by itself when it needs it.

Keys are rotated, revoked and recovered with signed operations:
[Recovery](recovery.md).

## Sessions and capabilities

An agent never has a key or an account. A human gives it a **session**:

```sh
lonca session start --repo demo --agent claude --paths 'src/**' \
      --task T-142 --ttl 2h --workspace ~/ws/claude-1 --harness claude-code
```

The session is a **capability**: what it may do, for how long, written into
the log. Its **scope** is the paths it may change (`--paths`), optionally
the symbols (`--symbols`), the size of one change (`--max-files`,
`--max-lines`) and directories outside the workspace it may write notes to
(`--scratch`). A request outside the scope is denied (`scope_path:<path>`,
`scope_max_lines`, …). A session ends at its TTL (at most
`sessions.max_ttl_minutes`, 8 hours by default), when the agent ends it, or
when a human revokes it.

- **The token.** `session start` returns a token once and writes it to the
  workspace (`.lonca/session`, mode 0600). The daemon keeps only its hash.
- **The workspace** is a directory with trunk's files where the agent edits.
  `lonca sync` brings trunk in, `lonca propose` sends the local changes.
- **Child sessions.** An agent can hand part of its work to a sub-agent with
  `cap.attenuate`: a child session whose scope is the same or narrower, never
  wider, under the same agent name. Revoking a session revokes every session made from it.
- **Continuing.** A session can not be extended. A human continues its
  workspace under a new session with `lonca session start --continue <dir>`:
  the session that was started in `<dir>`, which the log records, and
  nothing a file in the directory says
  ([Running agents](runners.md#a-worker-that-outlives-its-session)).

### Observation and taint

What the daemon knows about a session decides how much it trusts the
session's changes. The **observation level** says how much of the agent's
activity Lonca sees: `unobserved`, `hooks`, `hooks_sandbox` or `isolated`.
In cooperative mode every session is `unobserved`, and an unobserved
session is treated as tainted: each of its changes waits for a human.

A session is **tainted** when content from outside entered it: a web fetch,
a shell command that reached the network, another MCP server, a read of an
untrusted path (`[taint]` and `[paths] untrusted` in `lonca.toml` say which;
`Vendor/x.c` is `vendor/x.c` to these lists, as it is to macOS).
A tainted session's changes need a human, and it may not touch **critical
paths** at all (`[paths] critical`: build scripts, CI, lockfiles, agent
instructions such as `CLAUDE.md`). A taint never goes away for that session.

The levels, the harnesses and the hooks are in
[Running agents](runners.md#observation-levels); the modes are in
[What Lonca is](index.md#observation-levels).

## Symbols and leases

Lonca parses source files with tree-sitter and names their **symbols**:
`src/billing.rs#Client.charge`. Markdown, TOML, JSON and YAML files are split
into sections (`README.md#Install.Linux`); a file no parser reads is one
symbol, `path#<file>`. `lonca symbols <file>` lists the ids, and
[Languages](languages.md) says which languages are leased by symbol, what
of their newest syntax is not read yet, and what a file with such syntax
keeps.

Before an agent changes a symbol, it **leases** it:

```sh
lonca lease acquire 'src/billing.rs#Client.charge' -i "rate limiting"
```

- **Kinds.** `edit` changes a symbol's body; `insert` adds members to a type
  or a file (with `names`, the names it will add); `rename` renames or
  deletes it. `shared`, where the policy turns it on, lets several sessions
  edit one symbol and joins their edits line by line
  ([Verification](verification.md#shared-leases)).
- **Sets.** One acquire is one **lease set** (`lse_…`), all or nothing, with
  an intent and a TTL (at most `leases.max_ttl_minutes`, 30 by default).
  `lonca mcp` renews the sets while the agent runs; when the agent stops
  sending heartbeats they are free `leases.heartbeat_timeout_ms` later
  (5 minutes).
- **Conflicts.** Two sessions can not hold leases on one symbol, or on a
  symbol and one inside it (`Client` and `Client.charge`), unless both are
  `shared`. Two `insert` leases go together unless they reserve the same
  name in one container. A refused acquire says who holds the symbol, why
  and until when.
- **Waiting.** `lonca lease interest` queues for symbols someone else
  holds. When they are freed, the oldest interest gets them reserved for a
  minute (`leases.reservation_ms`). Agents can also settle a lease between
  themselves with `negotiate`.
- **Pinned.** A proposal pins the lease items it needs until the change
  leaves the queue, past their TTL; integration releases them.

Twenty agents can change twenty functions of one file at once: different
symbols never conflict, at lease time or at merge time.

### Keyed directories

Some files get their meaning from a key in their name, and the key must be
unique in their directory: a Flyway migration `V12__add_users.sql`, a Django
one `0012_add_users.py`, golang-migrate's `000012_add_users.up.sql`, a
numbered decision record. Two such files with different names and one key
conflict in meaning, and Git sees two unrelated paths. `lonca.toml` names
these directories and how to read the key from a file name:

```toml
[paths.keyed]
"db/migration" = '^V(\d+)__'                             # Flyway
"app/migrations" = '^(\d+)_'                             # Django
"docs/adr" = { pattern = '^([a-z-]+)\.md$', compare = "text" }
```

The pattern is a regular expression on the file name alone (not the path)
whose one group is the key; it never backtracks, so it reads every name in
time linear in its length. Keys compare as numbers by default (`12` and
`012` are one key); `compare = "text"` takes them as written. Only files
directly in the directory have keys.

- **Reserve the key.** An agent that adds such a file reserves its key with
  an `insert` lease on the directory, `db/migration#<dir>`, with the key in
  `names`, beside the `edit` on the new file's `path#<file>`. `next` asks
  for the number after the highest key on trunk or reserved by anyone, and
  the answer says which (`keys`):

  ```sh
  lonca lease acquire 'db/migration#<dir>' --kind insert --name next -i "users table"
  # lease set lse_…
  # keys db/migration#<dir>: 13
  ```

  Two sessions can not reserve one key. `lonca lease needed` and `preview`
  list the key a new file needs, and `lonca status` (the `status` tool) lists
  the keyed directories, for agents that have no `lonca.toml`.
- **At proposal.** A file an agent adds there needs its key reserved by its
  session (`key_not_reserved:db/migration#12`), its name must have a key
  (`key_unreadable:<path>`), and no other file may have it: in the change's
  own tree, or among what trunk got since its base
  (`key_taken:db/migration#12`). The key leases go with the change until it
  leaves the queue.
- **At integration.** The merged tree is checked again, for everyone's
  changes, a person's too: a change that would leave two files with one key
  is `conflicted` and names the key (`db/migration#12`), whatever the
  verification commands do. A clash trunk already had stops nobody. The
  auditor recomputes it.

Renaming and deleting existing files there are what they are elsewhere: a
rename adds a file, whose key is reserved as any other's, and a rule in
`policy.cedar` keeps agents from deleting them
([an example](policies.md#examples)).

## Proposals and changes

An agent (or a human) **proposes** the local changes of its workspace with a
**claim**: an intent, and the symbols it says it edited, added, deleted or
whose signature it changed.

```sh
lonca diff                                       # the facts, as Lonca sees them
lonca propose -i "rate limit charge" --edits 'src/billing.rs#Client.charge'
```

The daemon computes the **facts** from the Git objects. A claim that differs
from the facts is denied (`claim_mismatch:<field>`); every symbol the facts
touch must be leased by the session (`lease_missing:<symbol>`). An allowed
proposal becomes a **change** with a **change id**: 32 letters from `k` to
`z` (`kksuonzltktqystoounzkurnmrvyqxsx`). Lists print its first 12.

A change has a **status**:

| Status | Meaning |
|---|---|
| `pending` | waiting for human approval (`lonca pending`) |
| `queued` | in the merge queue |
| `integrated` | on trunk; `commit` is the trunk commit |
| `conflicted` | the merge onto trunk met another change in the same symbols |
| `rejected` | a human declined it, or integration failed; `reasons` say why |
| `withdrawn` | taken back, or replaced by a newer proposal of the same workspace |

and a **provenance**: `human` (a human proposed it), `clean` (a session
that was observed and not tainted), `tainted`, `unobserved`, or `reviewed`
(a human approved it).

A workspace has one change waiting for review at a time: proposing again
replaces it (`replaces:<change>`), so the reviewer sees the latest version.

## The merge queue

An allowed change is **queued**. The daemon's worker takes the head of the
queue and:

1. merges it onto current trunk with a symbol-level three-way merge: changes
   to different symbols never conflict, changes to the same symbol do
   (`conflicted`, with the symbols named);
2. runs the repository's checks on the merged tree, in a sandbox with no
   network: `build`, `test`, the extended check for a change that alters a
   signature, and the named checks the change owes;
3. moves trunk only when they pass. A failure is `rejected` with
   `verification_failed:<check>`, and the evidence (exit code, duration,
   the tail of the log, the toolchain it ran with) is in the log.

`[queue] batch_size` above 1 verifies several changes as one and bisects a
failure. Each check's result is recorded as evidence and never recomputed;
the merge itself is recomputed by the auditor. Commands, sandbox, quotas and
named checks: [Verification](verification.md).

## Policy and approvals

`refs/lonca/policy` holds two files, and only a human changes them
(`lonca policy set --config lonca.toml --policy policy.cedar`):

- `lonca.toml`: limits and settings (lease TTLs, critical paths, taint
  rules, verification commands, how many humans a policy change needs).
- `policy.cedar`: rules in [Cedar](https://www.cedarpolicy.com/). Each
  request is checked once per operation and once per file. A `forbid` rule
  denies; a `forbid` with `@escalate` turns the request into an approval
  request instead, and `@approvals("2")` asks for two humans. An evaluation
  error denies. What a rule can see, examples, and `lonca policy check`,
  which shows what a new policy would have decided differently before it
  is set: [Writing policies](policies.md).

A repository starts from a [profile](profiles.md). The cooperative one
allows what no rule forbids and ships rules such as: agents may not delete
migrations, a change under `auth/` needs two humans, a change of more than
50 files or 2000 lines needs one.

An operation is **escalated** when a rule says so, when its session is
unobserved or tainted (`unobserved_session`, `tainted_session`), or when an
unobserved session touches a critical path and the policy says to escalate
instead of deny. It then waits, with the number of approvals it needs
(`approvals=1`), until enough enrolled humans approve it or one rejects it.
With fewer enrolled humans than a rule asks for, all of them are enough
(`approvals.cap_to_enrolled_humans`). A human approves an operation once,
and an approval is a signed entry like any other. The day-to-day of it:
[Reviewing agents' work](reviewing.md).

## Freezing

`lonca freeze "<reason>"` stops all work on a repository: every operation
is denied with `frozen:<reason>` except `unfreeze`, another `freeze`, and
the key operations of [Recovery](recovery.md), which stay possible so that
an incident can be answered. `lonca unfreeze "<reason>"` resumes it.
