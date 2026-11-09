# Reviewing agents' work

What a person does day to day on a repository where agents work: see what
waits, read it, approve or reject it, and take back what should not have
landed. The words are explained in [Concepts](concepts.md). Every command
here signs in by itself; with a Secure Enclave key, `lonca human login --ttl
8h` at the start of the day asks for Touch ID once.

## What is going on

```sh
lonca status --repo demo
```

```text
repo   demo
trunk  64743ee9b3a587440aa98592b019d8645c42459c
queue  0 change(s)
unparsed files: one lease a file
sessions:
  ses_ca2252ef9a7bd4f7 claude [unobserved] task=T-1
leases:
  lse_99b57cb9461c9984 ses_ca2252ef9a7bd4f7 599s "rate limit charge" src/lib.rs#charge(edit) [pinned to 1 change(s)]
pending approvals: 1 (lonca pending)
```

The sessions with their level (and taint, if any), who leases what and why,
the queue, and how much waits for you. `FROZEN <reason>` and `BELOW
HARDENED` lines appear when they apply. `--json` gives everything, the
changes with their status included.

## What waits for you

```sh
lonca pending --repo demo
```

```text
#3 change.propose agent:claude/ses_ca2252ef9a7bd4f7 change kksuonzltktq "charge adds two" [0/1] ["unobserved_session","approvals=1"]
```

Each line is an escalated operation: its sequence number (what `approve`
and `reject` take), the operation, who asked, the change and its intent,
approvals so far out of those needed, and the reasons it escalated. The
reasons say what to look for:

| Reason | What it means for the review |
|---|---|
| `unobserved_session` | Nothing observed the agent (every session in cooperative mode). Read the change as you would an unknown contributor's. |
| `tainted_session` | Content from outside entered the session. The agent may have been told what to write by a web page or an issue. |
| `critical_path:<path>` | The change touches a build script, CI, a lockfile or agent instructions. These run code or steer every later agent. |
| `unobserved_write:<path>` | A file changed that no observed tool wrote. |
| `unread_file:<path>` | A file that parsed before no longer parses, so its symbols can not be checked. |
| `signature_change:<symbol>` | A signature changed; callers are not analysed, the tests are what catch them. `affected_lease:<session>:<set>` names sessions working on code that mentions it. |
| a rule's id, e.g. `auth`, `blast-radius` | A rule of `policy.cedar` with `@escalate` matched. |

A proposal pending on a workspace is replaced when the agent proposes again
(`replaces:<change>`): approve the newest one.

## Reading a change

`pending` prints the first 12 letters of a change id; `diff` and `change`
take the whole id, which `lonca pending --json` and `lonca status --json`
give.

```sh
lonca diff kksuonzltktqystoounzkurnmrvyqxsx --repo demo      # the diff, computed by the daemon
lonca change kksuonzltktqystoounzkurnmrvyqxsx --repo demo    # claim, facts, status, provenance
lonca advise kksuonzltktqystoounzkurnmrvyqxsx --repo demo    # optional, see below
```

- `diff` lists each file with the lines added and removed, then the unified
  diff between the change's base and its commit. Redacted files are named,
  not shown.
- `change` prints the record as JSON: the agent's **claim** and Lonca's
  **facts** (they match, or the proposal would have been denied), its status,
  `runs` (the checks the merge queue will run for it) and `checks` (named
  checks humans asked for).
- `advise` asks Claude for a summary and risk flags
  (`ANTHROPIC_API_KEY`, or `ant auth`). It has no authority: it decides
  nothing and is not logged. It reads text the agent wrote, so treat what it
  says as one more opinion.

What a review catches that the checks do not: a change that does something
other than its intent, new network or process calls, tests weakened to
pass (`tests.deleted`, `tests.skipped` in the facts), secrets, and changes to
files that instruct agents.

## Approving and rejecting

```sh
lonca approve 3 --repo demo --note "looks right"
lonca approve 3 --repo demo --also api,e2e         # it must pass these named checks too
lonca reject 8 --repo demo --reason "refund must stay a - 1: see ticket T-9"
```

- An approval is a signed entry. When it is the last one needed, the
  operation is released (`allow: released`) and a proposal joins the merge
  queue. Approval is not integration: the change is still merged onto trunk
  and verified, and it can still end `conflicted` or `rejected`.
- `--also` names checks from `verification.checks` the change must pass
  before it lands, for this change only. An agent can neither add a command
  nor drop a check: only a human's approval names them
  ([Verification](verification.md#checks-a-change-owes-by-name)).
- `reject --reason` declines it. The agent reads the reason in its
  `events` and in `change_status` (`rejected: <reason>`), so say what to fix.
  The change ends `rejected`; the agent fixes, syncs and proposes again.
- Something you can not decide now can wait: a pending operation does not
  expire. Its session may end or expire meanwhile, and the proposal still
  integrates when approved; revoking the session withdraws it.

## After approval

```sh
lonca change kksuonzltktqystoounzkurnmrvyqxsx --repo demo --evidence
lonca log --repo demo
```

`--evidence` prints each check of the last integration attempt: result,
exit code, duration, sandbox, and the tail of its log. The log shows the
`approve` entry, then `change.integrate` by `daemon`:

```text
3 change.propose    escalate agent:claude/ses_ca2252ef9a7bd4f7  unobserved_session, approvals=1
4 approve           allow   human:ayse                         released
5 change.integrate  allow   daemon
```

- **Conflicted**: another change to the same symbols landed first. The
  agent syncs, resolves and proposes again; nothing for you until then.
- **Rejected with `verification_failed:<check>`**: the build or the tests
  failed on the merged tree. The evidence has the log
  ([Verification](verification.md#reading-a-failure)).
- To bring it into your own checkout: `lonca fetch` and merge
  `refs/lonca/trunk` ([Working as a human](humans.md)).

## Undoing

Nothing is deleted from the log; an undo is a new operation that
compensates for an old one.

```sh
lonca undo 5 --repo demo                                     # one operation
lonca revert --actor agent:claude --since-seq 40 --repo demo # plan: what it would undo
lonca revert --actor agent:claude --since-seq 40 --repo demo --apply
```

What `undo SEQ` does depends on the operation:

| Operation | Undo |
|---|---|
| `change.integrate`, a batch, `import.external` | a human change that takes its edits back out of current trunk, merged with what came after; refused, naming the files, where that merge fails |
| `change.propose` | withdraws the change |
| `lease.acquire` | releases the set |
| `session.start`, `cap.attenuate` | revokes the session and every session made from it |
| `policy.update` | sets the policy back to the one before it |
| `freeze` | unfreezes |

`revert` plans the undo of what one actor did since a sequence number (its
integrated changes, newest first, its lease sets and the sub-sessions it
made) and prints the plan; `--apply` submits it, going on past a step that is
refused and naming it. The actor is `agent:<name>` (every session of that
agent), `agent:<name>/<session>`, a session id, or `human:<name>`.

## Stopping an agent, stopping everything

```sh
lonca session revoke ses_ca2252ef9a7bd4f7 --repo demo --reason "task done"
lonca freeze "suspicious push from T-1" --repo demo
lonca unfreeze "checked: false alarm" --repo demo
```

- `session revoke` ends a session and every session made from it, and
  withdraws what they have in flight. Its token stops working at once.
- `freeze` stops all work on the repository, yours included: everything but
  `unfreeze` and the key operations is denied with `frozen:<reason>`, so
  revoke what you need to revoke after unfreezing, or before freezing.
- `redact BLOB --reason` withholds a blob (a leaked secret, personal data)
  from every reader. It is logical: the daemon stops serving it, the object
  stays in the store's Git history. Rotate the secret as well.

## Keeping a record

- `lonca log --repo demo --json --from N` follows the log; `lonca doctor`
  verifies every repository's chain up to the daemon's head.
- `lonca push <remote> --repo demo` sends trunk, the log and the policy to a
  Git remote, where `lonca-audit verify` runs in CI
  ([docs/ci/lonca-audit.yml](https://github.com/selcukgural/lonca/blob/main/docs/ci/lonca-audit.yml)).
- When something is wrong: [Troubleshooting](troubleshooting.md). When a key
  is lost: [Recovery](recovery.md).
