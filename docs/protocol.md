# Daemon protocol

What a client of the Lonca daemon (a runner such as imece, `lonca-cli`,
an MCP bridge) needs to know, and nothing it does not. The daemon's
crates are not an interface: a client speaks this protocol over the
socket and copies nothing from `crates/`.

**Protocol number: 1.** `ping` returns it as `protocol`. It goes up when
a shape changes in a way a client must know about: a field removed or
renamed, a type changed, an error code changed, a method removed. Adding
a field, a method or a reason code does not change it. A client checks
the number once and refuses to run against one it was not written for.
Each number is explained at the end of this document.

What a client may rely on: every field named in this document, with the
type given. Fields not named here may appear and may go away. Reason
codes are listed at the end; new ones may appear, so a client treats an
unknown reason as "denied for a reason it can show but not interpret".

## Wire format

A Unix socket (`$LONCA_SOCKET`, else `$LONCA_HOME/lonca.sock`, else
`~/.lonca/lonca.sock`). One JSON object per line in each direction; a
request line is at most 96 MiB (`MAX_LINE`), base64 file contents
included. Requests on one connection are answered in order. The client
chooses `id`; the response repeats it.

```json
{"id": 1, "method": "status", "repo": "demo", "token": "lonca_h_…", "params": {}}
{"id": 1, "ok": true, "result": {…}}
{"id": 2, "ok": false, "error": {"code": "unauthenticated", "message": "…"}}
```

- `repo` (string, optional): the repository, where the method has one.
  With an agent token it is the token's repository and may be left out.
- `token` (string, optional): an agent session token (`lonca_…`) or a
  human session token (`lonca_h_…`). Never logged by the daemon; never
  put it in a log, a URL or an error message either.
- `params` (object): the method's parameters; `{}` when it has none.

Errors have a stable `code` and a `message` for people. A line that is
not a request answers `{"id": 0, "ok": false, "error": {"code":
"invalid", …}}`.

## Verifying the daemon

Your client checks the daemon before it sends anything, the token above
all. The rules are in `docs/decisions.md`, "Clients verify the daemon"; a
runner that speaks to the socket itself must do the same:

1. Read `daemon_uid` from `/Library/Lonca/daemon.toml` (macOS) or
   `/etc/lonca/daemon.toml`. No file: expect your own uid. A file that is
   not root-owned, or is writable by others: refuse.
2. The socket is a socket, not a link, and belongs to that uid. With a
   file, its directory belongs to that uid or root, and is not writable by
   group or others.
3. After connecting, `getpeereid` / `SO_PEERCRED` says that uid.

## Credentials

Every method requires one of these (the table in `docs/decisions.md`,
"Daemon authentication", is the same list; a test keeps both equal to
the code).

| Credential | Meaning |
|---|---|
| public | nothing |
| login | a presence signature inside the request |
| agent | an agent session token; `repo`, if given, must be the token's |
| human | a human session whose key is enrolled in `repo` |
| any human | a human session enrolled in at least one repository |
| bootstrap | *any human*, or nothing while the daemon serves no repository yet |
| read | *agent* (for the token's repository) or *human* |
| any | any live token |

Without a token: `unauthenticated`. A token of the wrong kind, for
another repository, or for a human the repository does not know:
`forbidden`. Unknown, ended and expired tokens: `unauthenticated`. An
unknown method: `unknown_method`, whatever the token.

## Common shapes

- **id** (string): 40 hex digits, a Git object id (`GitId`).
- **change id** (string): 32 letters `k`–`z`, the "reverse hex" of
  Jujutsu (`ChangeId`).
- **time**: milliseconds since the Unix epoch, as an integer (`*_ms`).
- **actor** (string label): `human:<name>`, `agent:<name>/<session>` or
  `daemon`. In log entries and change records the actor is an object:
  `{"kind": "human", "name"}`, `{"kind": "agent", "name", "session"}` or
  `{"kind": "daemon"}`.
- **decision**: `{"outcome": "allow" | "deny" | "escalate", "reasons":
  [string]}`. Reasons are machine-readable codes, sometimes with a
  `:` suffix (`lease_missing:src/a.rs#f`).
- **logged** (the result of a method that appends to the log):
  `{"seq": integer, "decision": decision}`, plus the fields the method
  adds. A denied operation is still logged and still answers `ok: true`
  with `outcome: "deny"`; only a request that never reached the log is
  an error.
- **file change**: `{"path": string, "content_b64": string | null,
  "mode": "regular" | "executable" | "symlink" | "submodule" | null}`;
  `content_b64: null` deletes the file.
- **scope**: `{"paths": [glob], "symbols": [string] | null, "ops":
  [op kind], "max_files": integer | null, "max_lines": integer | null,
  "scratch": [absolute path]}`. `scratch` (optional, at most 8) names
  directories outside the workspace the agent may write to: writes
  there are allowed and not observed, reads there do not taint, nothing
  there can be proposed. A child scope may keep or drop them, not add.
- **lease item**: `{"symbol": "path#Qualified.name", "kind": "edit" |
  "insert" | "rename"}`; for `insert` the symbol is the container
  (`path#Type` or `path#<file>`). Markdown, TOML, JSON and YAML files
  have sections as symbols (`README.md#Install.Linux`,
  `Cargo.toml#dependencies.serde`); adding to the end of a Markdown section
  is the addition `path#Section.<append>`, which takes an `insert` lease on
  the section. A file that does not parse is `path#<file>`.
- **claim**: `{"intent": string, "edits": [symbol], "adds": [symbol],
  "deletes": [symbol], "deleted_files": [path], "signature_changes":
  [symbol], "tests": {"added", "modified", "deleted", "skipped"},
  "revert_of": change id | null}`. Missing fields default to empty.
- **facts**: what Lonca computed from the objects: the claim's fields
  plus `added_files`, `modified_files`, `import_only_files`,
  `lines_added`, `lines_removed`.
- **human signature**: `{"human": string, "nonce": string (16–128
  chars), "issued_ms": time, "sig": hex}`. For operations the signed
  bytes are the canonical JSON of `{"purpose": "lonca-human-intent-v1",
  "repo", "op", "nonce", "issued_ms"}`; for logins of `{"purpose":
  "lonca-human-login-v1", "repo": string | null, "human", "ttl_ms",
  "nonce", "issued_ms"}`. Canonical JSON: keys sorted, no whitespace,
  UTF-8. Ed25519 signatures are 64 bytes hex; Secure Enclave (`p256-se`)
  signatures are DER-encoded ECDSA P-256 over SHA-256, hex. A signature
  is good for ten minutes, with one minute of clock skew.
- **op**: an operation object, `{"op": "<kind>", …fields}`. The kinds
  and their fields are the operation log's and are listed under
  `log`.

## Methods

### `ping`

*public.* `params: {}`.

```json
{"version": "0.1.0", "protocol": 1, "daemon_key": hex, "next_key": hex | null}
```

`daemon_key` is the Ed25519 public key the daemon signs log entries
with; `next_key` is set during a key rotation.

### `human.login`

*login.* Opens a human session.

```json
{"sig": human signature, "ttl_ms": integer | null}
```

`repo` on the request names the repository whose enrolment verifies the
key; without it every repository the daemon serves is tried. The
signature is over the login intent above, with the same `repo` (or
`null`) and `ttl_ms`; the client must send the `ttl_ms` it signed
(default 3 600 000, at most 86 400 000). Result:

```json
{"token": "lonca_h_…", "human": string, "expires_ms": time}
```

The session is tied to the key, not to a repository: it is accepted
wherever that key is enrolled and ends everywhere when the key is
rotated, revoked or recovered. A session can read, prepare and run the
queue; every write still needs a signature by the same human. Errors:
`unauthenticated` (no enrolled key verifies, stale or replayed
signature, bad nonce), `invalid` (`ttl_ms` out of range).

### `human.logout`

*public, but acts only on the token it carries.* `params: {}`. Ends the
human session: `{"ended": true}`. An agent token: `forbidden`; a token
the daemon does not know: `unauthenticated`.

### `whoami`

*any.* `params: {}`. For an agent token:

```json
{"repo": string, "actor": "agent:<name>/<session>", "session": record | null}
```

where the record is the session as the log replays it (`id`, `agent`,
`model`, `task`, `parent`, `scope`, `created_ms`, `expires_ms`,
`level`, `taint`, `ended`, …). For a human session:

```json
{"actor": "human:<name>", "human": string, "key": hex, "repos": [string]}
```

`repos` are the repositories the session is enrolled in (foreign ones
included).

### `repo.list`

*any human.* `params: {}`. `[string]`: the repositories this daemon
signs for and the session is enrolled in. Repositories on another
daemon key (foreign, waiting for `daemon.recover`) are not listed.

### `repo.prepare_init`

*bootstrap.*

```json
{"repo": string, "human": string, "human_key": {"alg": "ed25519" | "p256-se", "public": hex},
 "import_from": string | null, "branch": string | null}
```

Names: letters, digits, `.`, `_`, `-`, at most 64. `import_from` is a
remote the daemon fetches `branch` (default `main`) from: an absolute
path, `https://`, `ssh://` or `user@host:path`. Result `{"op": op,
"warnings": [string], "large_files": [{"path", "size"}], "tree_bytes":
integer}`: the `repo.init` operation to sign, and what a workspace of
this tree will meet (files above the change cap, a tree above one
page). Errors: `invalid`, `conflict` (the repository exists), `git`
(the fetch failed).

### `repo.init`

*bootstrap.* `{"op": op, "sig": human signature}` with the operation
from `repo.prepare_init`, unchanged. Result: logged. With a human
session, the signer must be the session's human (`forbidden`
otherwise). Errors: `invalid` (not prepared by this daemon), `denied`
(the signature or policy refused; nothing was logged).

### `repo.restore`

*bootstrap.* `{"repo": string, "from": string}`: creates the repository
from a backup bundle, a bare store or a remote Lonca pushed to. Result:

```json
{"repo": string, "seq": integer, "head_hash": hex, "daemon_key": hex, "foreign": boolean}
```

`foreign: true` means the log is on another daemon's key and waits for
`daemon.recover`. Errors: `conflict` (exists), `invalid` (no log, or a
backup of another name), `integrity` (the log does not verify), `git`.

### `repo.backup`

*human.* `params: {}`. Writes a Git bundle of every ref:

```json
{"repo": string, "path": string, "seq": integer, "head_hash": hex, "daemon_key": hex}
```

### `daemon.prepare_rotate`

*any human.* `params: {}`. `{"key": hex, "repos": [string]}`: the next
daemon key and the repositories still on the current one; each moves
with a signed `daemon.rotate` through `human.submit`.

### `status`

*read.* `params: {}`.

```json
{
  "repo": string, "trunk": id, "policy": id, "frozen": string | null,
  "queue": [change id], "next_seq": integer, "head_hash": hex, "now_ms": time,
  "daemon_key": hex,
  "humans": {"<name>": {"alg": string, "public": hex, "recovery": hex | null}},
  "sessions": [session], "leases": [lease], "changes": [change], "pending": [pending]
}
```

- **session**: `{"id", "agent", "task", "parent": string | null,
  "level": "unobserved" | "hooks" | "hooks_sandbox" | "isolated",
  "taint": string | null, "active": boolean, "expires_ms": time,
  "last_seen_ms": time | null, "continued_from": string | null,
  "continued_by": string | null}`. `last_seen_ms` is the last heartbeat;
  `null` means none yet. `continued_from` and `continued_by` link the
  sessions of one workspace; `parent` is a capability's origin.
- **detail**: `{"code", "symbol", "needed_kind": lease kind,
  "holder_session": string | null, "holder_agent": string | null,
  "intent": string | null, "expires_ms": time | null, "set": string |
  null, "pinned_to": change id | null}`. What stands between a client
  and a lease: derived from the state when the daemon answers, never
  logged. `expires_ms` is `null` for a pinned item, which does not
  expire; wait for `pinned_to` to leave the queue. `code` is
  `lease_held`, `lease_missing`, `held_by_you` or `free`; the holder's
  fields are set when someone holds the symbol.
- **lease**: `{"set", "session", "items": [lease item], "intent",
  "expires_ms", "pinned": [{"change": change id, "items": [lease
  item]}]}`; only what is held now. `items` are the set's live items:
  past `expires_ms`, or once the session is gone, only the pinned ones.
- **change**: `{"change": change id, "actor": label, "status": change
  status, "provenance": "human" | "clean" | "tainted" | "unobserved" |
  "reviewed", "commit": id, "base": id, "intent": string, "created_ms":
  time, "version": integer, "paths": [path]}`. `paths` are the files the
  change touches (added, modified, deleted). Change status:
  `{"status": "pending", "seq"}`, `{"status": "queued"}`, `{"status":
  "integrated", "commit": id}`, `{"status": "conflicted", "symbols":
  [symbol]}`, `{"status": "rejected", "reasons": [string]}` or
  `{"status": "withdrawn"}`.
- **pending**: an operation waiting for approval. `{"seq": integer,
  "created_ms": time, "actor": label, "op": op kind, "reasons":
  [string], "approvals": [human name], "required": integer, "change":
  change id | null, "base": id | null, "intent": string | null,
  "agent": string | null, "task": string | null, "paths": [path]}`.
  `change`, `base` and `intent` are set for a `change.propose`;
  `agent` and `task` when the actor is an agent session. One `status`
  call fills a review list.

`next_seq` is the sequence number the next entry will get, so a client
sees whether anything was logged since its last read without calling
`log`.

### `log`

*read.*

```json
{"from": integer, "limit": integer | null, "wait_ms": integer | null}
```

Entries with `seq >= from`, at most `limit`. With `wait_ms` and no entry
past `from`, the daemon holds the request (not its lock) until an entry
arrives or the time runs out (capped at 30 000), then answers; an empty
array means the time ran out. A client follows the log with one open
request: `from = next_seq`, `wait_ms = 30000`, repeat. Each entry:

```json
{"entry": {"format": integer, "seq": integer, "prev": hex, "time_ms": time,
           "actor": actor, "op": op, "evidence": [attestation], "facts": facts | null,
           "symbols_engine": integer | null, "decision": decision,
           "human": human signature | null},
 "hash": hex, "sig": hex}
```

Operation kinds (`op.op`) and their fields:

| kind | fields |
|---|---|
| `repo.init` | `repo`, `daemon_key`, `human`, `human_key`, `policy`, `trunk` |
| `human.enroll` / `human.rotate` / `human.recovery_key` / `human.recover` | `human`, `key` |
| `human.revoke` | `human`, `reason` |
| `daemon.rotate` / `daemon.recover` | `key` |
| `policy.update` | `policy` (id) |
| `session.start` | `session`, `agent`, `model`, `task`, `scope`, `expires_ms` |
| `session.bind` | `session`, `checks`, `level` |
| `session.end` / `cap.revoke` / `taint` | `session`, `reason` |
| `cap.attenuate` | `parent`, `child`, `agent`, `scope`, `expires_ms`, `leases` (when not empty) |
| `lease.acquire` | `set`, `items`, `intent`, `ttl_ms` |
| `lease.release` | `set` |
| `lease.renew` | `set`, `ttl_ms` |
| `lease.interest` | `items`, `intent` |
| `change.propose` | `change`, `commit`, `base`, `claim` |
| `change.withdraw` | `change` |
| `change.integrate` | `change`, `trunk_before`, `merged` (id or null), `conflicts` |
| `approve` | `target_seq`, `note` |
| `reject` | `target_seq`, `reason` (1–4096 bytes; the requester reads it) |
| `observe` | `session`, `events` |
| `import.external` | `remote`, `commit`, `trunk_before` |
| `import.unmediated` | `refname`, `found`, `expected` |
| `bridge.push` | `remote`, `oplog_seq`, `oplog_hash` |
| `freeze` / `unfreeze` | `reason` |
| `negotiate` | `thread`, `to_session`, `message` |
| `redact` | `blob`, `reason` |

An attestation: `{"check": "syntax" | "scope" | "claim_diff" | "merge"
| "build" | "tests" | "test_integrity", "result": "pass" | "fail" |
"error" | "skipped", "subject_tree": id, "details": {string: string},
"env": hex, "log": id | null, "producer": string}`.

### `tree`

*read.* `{"commit": id, "with_content": boolean, "paths": [path] |
null}`. The files of a commit:

```json
[{"path": string, "mode": file mode, "blob": id, "size": integer, "content_b64": string | null}]
```

`size` is the blob's size in bytes (0 for a submodule). `content_b64`
is set with `with_content`, except for submodules and redacted blobs;
the whole answer is one line (`MAX_LINE`), so for a tree of any size
fetch the manifest without contents and page them with `blobs`.

### `blobs`

*read.* `{"commit": id, "paths": [path]}`. One page of contents, the
same shape as `tree` with `content_b64` set (null for a submodule or a
redacted blob). Every path must be in the commit's tree (`not_found`
otherwise: a page never mixes commits). The page must fit the line cap
once encoded: the budget is three quarters of `MAX_LINE` (72 MiB) of
base64; a page over it, or a single file over it, is `too_large` with
the file named. Size pages from `tree`'s `size` field: base64 of `n`
bytes is `ceil(n / 3) * 4`. `lonca-cli` does this in `fetch`
(`LONCA_FETCH_BUDGET` lowers the budget for tests).

### `change.get`

*read.* `{"change": change id}`. The change record:

```json
{"change", "actor": actor, "commit", "base", "claim", "facts", "status",
 "provenance", "proposed_seq", "created_ms", "version",
 "integrate_seq": integer | null, "integrate_decision": decision | null,
 "evidence": [{"check": check kind, "result": "pass" | "fail" | "error" | "skipped",
               "exit": integer | null, "duration_ms": integer | null, "attempts": integer | null,
               "sandbox": string | null, "error": string | null, "details": {string: string},
               "log": string | null, "log_truncated": boolean}]}
```

`evidence` are the checks of the change's last `change.integrate`
entry (empty before one); `log` is the tail of the check's output
(32 KiB at most, `log_truncated` when cut), null for a redacted or
missing log. `not_found` for an unknown change.

### `change.diff`

*read.* `{"change": change id, "format": "unified" | null}`.

```json
{"change", "base": id, "commit": id, "format": "unified",
 "files": [{"path", "status": "added" | "modified" | "deleted",
            "added": integer | null, "removed": integer | null,
            "symbols": {"edits": [symbol], "adds": [symbol], "deletes": [symbol], "signature_changes": [symbol]}}],
 "redacted": [path], "diff": string, "truncated": boolean}
```

The unified diff between the change's base and commit, computed by the
daemon in the store. Files whose blob on either side is redacted are
left out of `files` and `diff` and listed in `redacted`. `added` and
`removed` are line counts (null for binary files). `diff` is cut at
2 MiB on a line boundary, `truncated` says so. Not logged.

### `trunk.bundle`

*read.* `{"have": [id]}`. A Git bundle of trunk (`refs/heads/main`) for
a git checkout, thin against the commits in `have` that the store knows
(others are ignored):

```json
{"trunk": id, "bundle_b64": string, "bytes": integer, "thin": boolean, "up_to_date": boolean}
```

`git fetch <bundle> +refs/heads/main:refs/lonca/trunk` applies it. With
`up_to_date` the checkout already has trunk and the bundle is empty:
point the ref at `trunk`.
Errors: `redacted` (a redacted blob is among the objects; git needs
whole objects, work from a workspace), `too_large` (the bundle does not
fit one page; fetch from a closer point).

### `trunk.distance`

*read.* `{"base": id}`. `{"trunk": id, "base": id, "behind": integer |
null}`: how many integrations trunk has had since `base` was trunk;
null when it never was.

### `human.prepare_change`

*human.*

```json
{"base": id, "files": [file change], "change": change id | null,
 "author": string, "intent": string, "revert_of": change id | null}
```

Builds the commit of a human change on `base` and computes its facts.
Result: `{"op": op (change.propose), "facts": facts, "syntax_errors":
[string]}`. Submit the operation, unchanged, through `human.submit`.

### `human.prepare_policy`

*human.* `{"config": string (lonca.toml), "policy": string (Cedar)}`.
Writes the policy commit; `{"op": op (policy.update)}`. `invalid` when
the files do not parse.

### `human.prepare_import`

*human.* `{"remote": string, "branch": string | null}`. Fetches the
branch; `{"op": op (import.external)}`. Errors: `up_to_date`,
`not_fast_forward` (the branch does not contain trunk), `git`.

### `human.prepare_push`

*human.* `{"remote": string}`. `{"op": op (bridge.push)}`.

### `human.submit`

*human* (a `human.recover` operation needs no session: its recovery-key
signature is the credential). `{"op": op, "sig": human signature}`.
Any human operation: the prepared ones above, `session.start`,
`cap.revoke`, `approve`, `reject`, `freeze`, `unfreeze`, `redact`, the
key operations, `daemon.rotate`, `daemon.recover`. The signer must be the
session's human. Result: logged, plus:

- `session.start`, allowed: `"token"`, the agent's session token.
  Returned once; give it to the agent, never log it.
- `bridge.push`, allowed: `"push"`, git's porcelain output.

Errors: `invalid` (the operation does not fit: a `repo.init` here, a
rotation to a key the daemon does not hold), `not_fast_forward`,
`foreign_key` (the repository waits for `daemon.recover`), `denied` for
a recovery the log refused, `git`.

### `lease.acquire`

*agent.* `{"set": string | null, "items": [lease item], "intent":
string, "ttl_ms": integer}`. Logged, plus `"set"`: the lease set's id
(generated when not given). Denied with
`lease_held:<symbol>:<session>:<intent>` when another session holds an
item, a pinned one included. The intent is free text and comes last, so
read `"details"` instead of splitting the reason: [detail], one per held
item however many requested items run into it, empty when nothing is
in the way.

### `lease.release`

*agent.* `{"set": string}`. Logged. Items pinned to a change in flight
stay until the change leaves the queue; the rest of the set ends.

### `lease.renew`

*agent.* `{"set": string, "ttl_ms": integer | null}` (default 600 000).
Logged. An expired set is removed from the state by the next log entry,
so a late renew is denied with `lease_expired` or `unknown_lease_set`;
both mean: acquire again. A set held for `leases.max_hold_minutes` or
longer is denied with `lease_hold_limit` while another session wants
it (it was denied an overlapping `lease.acquire` within the last
`leases.max_ttl_minutes`): stop renewing, propose or release; the set
runs out by its TTL.

### `lease.interest`

*agent.* `{"items": [lease item], "intent": string | null}`. Say you are
waiting for symbols another session holds. Nothing is held and nothing
waits. When what conflicts is freed, the oldest interest gets a
reservation for `leases.reservation_ms`: `status.reservations`, an
`events` entry, and until `until_ms` every other session's `lease.acquire`
is denied `lease_reserved:<session>`. An unused window passes to the next
interest. Logged, plus `"details"` as for `lease.acquire`. Denied
`lease_free` for what nobody holds (acquire it) and `interest_exists` when
the session already waits for it.

### `events`

*agent.* `{"from": integer | null}`, a sequence number. Read-only.

```json
{"events": [event], "next": integer}
```

Pass `next` as the next `from`. An event has a `kind`:
`integrated` (`seq`, `change`), `conflicted` (`seq`, `change`,
`conflicts`), `failed` (`seq`, `change`, `reasons`: verification refused
it), `approved` (`seq`, `target_seq`), `rejected` (`seq`,
`target_seq`, `reason`), `message` (`seq`, `thread`, `from`),
`lease_received` (`seq`, `set`, `from`), and `reserved` (`items`,
`until_ms`), which is the state now and is reported on every call while
it lasts.

### `change.propose`

*agent.* `{"change": change id | null, "base": id, "files": [file
change], "claim": claim}`. Builds the commit on `base`, computes the
facts, decides. Logged, plus `"change"`, `"commit"`, `"facts"`,
`"syntax_errors"`, `"details"` ([detail], one per lease the proposal
lacks: `lease_missing` with the holder if there is one). `outcome: "escalate"` means the change waits for a
human (`status.pending`); `"allow"` means it is queued and the merge
queue integrates it (`status.changes[].status`). A denied change is
logged with its reasons (`claim_mismatch:edits`, `lease_missing:…`,
`scope_path:…`, …).

### `change.withdraw`

*agent.* `{"change": change id}`. Logged.

### `facts.preview`

*agent.* `{"base": id, "files": [file change]}`. The facts a proposal
would have, without logging: `{"facts": facts, "syntax_errors":
[string], "leases": [detail], "acquire": [lease item]}`. `leases` says
where each lease the facts need stands: `held_by_you`, `free`, or one
`lease_held` per holder. `acquire` is the free ones, ready for
`lease.acquire`.

### `negotiate`

*agent.* `{"thread": string, "to_session": string, "message":
{"type": "claim" | "yield" | "counter" | "accept" | "decline", …}}`
(`claim`: `symbols`, `reason`; `yield`: `set`, `to`; `counter` and
`decline`: `note`). Logged. `yield` with `to` (which must be `to_session`)
moves the set to that session in this entry; without it the set is freed.
Denied `yield_to_another_session`, `lease_pinned`, `lease_expired`,
`scope_path:<path>`.

### `cap.attenuate`

*agent.* `{"agent": string, "scope": scope, "expires_ms": time, "leases":
[string] | null}`. A child session with a narrower scope. `leases` hands
lease sets to it until it ends; they go back to the parent then. Logged,
plus `"session"` and `"token"` when allowed.

### `session.end`

*agent.* `params: {}`. Ends the agent's own session; its token stops
working. Logged.

### `session.heartbeat`

*agent.* `params: {}`. The session is alive. Logged as an `observe`
entry. From the first heartbeat on, the session's leases hold only
while it goes on: `timeout_ms` after the last one they are free, and a
later heartbeat does not bring them back. A session that never sent one
lives by its TTL alone. Pinned items ignore the timeout. Result:
`{"seq", "decision", "now_ms": time, "timeout_ms": integer,
"max_ttl_ms": integer, "leases": [{"set", "expires_ms"}]}`: the caller's
own leases, on the daemon's clock. Send one every `timeout_ms / 3`.
`lonca mcp` does, and renews what is about to run out. A session that
has ended or expired gets the error `session_inactive`, and nothing is
logged; stop beating.

### `hook.event`

*agent.* A harness hook event: `{"hook_event_name": string,
"tool_name": string | null, "tool_input": object, "cwd": string | null,
"workspace": absolute path}`. Result `{"decision": "allow" | "deny" |
"ask", "reason": string}`. Observations are logged as `observe`
entries.

### `hook.bind`

*agent.* `{"harness": string, "harness_session": string,
"sudo_without_password": boolean, "workspace": absolute path | null}`.
Logged, plus `"level"` (observation level), `"notes"` ([string]) and
`"scratch"` ([absolute path], the session's scratch roots from the log).

### `queue.run`

*any human.* `params: {}`. Drains every merge queue now;
`{"integrated": integer}`. The daemon's worker does this on its own
within two seconds of a proposal; the call is for tests and scripts.

## Error codes

| code | meaning |
|---|---|
| `invalid` | the request does not fit: bad params, missing `repo`, a value out of range |
| `unauthenticated` | no token, or one that is unknown, ended or expired; a login that did not verify |
| `forbidden` | a token of the wrong kind, for another repository, or not enrolled; a signature by another human |
| `session_inactive` | `session.heartbeat` of a session that has ended or expired; nothing is logged |
| `unknown_method` | not in the table |
| `not_found` | no such repository or change; a path not in the commit (`blobs`) |
| `too_large` | a `blobs` page, or one file, does not fit the line cap |
| `conflict` | the repository exists |
| `denied` | a signed operation the log refused before anything was written (`repo.init`, recoveries) |
| `foreign_key` | the repository is on another daemon key |
| `up_to_date`, `not_fast_forward` | import conditions |
| `git` | the git subprocess failed; the message is its stderr |
| `integrity` | the log does not verify or replay |
| `unsupported` | a log format or engine this daemon does not know |
| `internal` | an I/O or JSON error in the daemon |

## Reason codes

The `reasons` of a decision. The ones a runner acts on:

- `lease_missing:<symbol>`, `lease_held:<symbol>:<session>:<intent>`,
  `lease_expired`, `invalid_lease_set`, `unknown_lease_set`,
  `not_own_lease`: acquire or renew the lease, then propose again.
- `lease_hold_limit`: the set has been held too long and someone is
  waiting; finish or let it run out, then acquire again.
- `lease_reserved:<session>`: freed and held for that session for a
  moment; `details` says until when. `lease_free`: nobody holds it, acquire
  instead of waiting.
- `claim_mismatch:<field>` (`edits`, `adds`, `deletes`, `deleted_files`,
  `signature_changes`, `tests`): the claim does not match the facts;
  `facts.preview` says what the facts are.
- `scope_path:<path>`, `scope_symbol:<symbol>`, `scope_op:<op>`,
  `scope_max_files`, `scope_max_lines`: outside the session's scope.
- `stale_trunk`, `unknown_base`: propose on the current trunk.
- `unobserved_write:<path>`, `tainted_session`, `tainted_critical_path`,
  `critical_path:<path>`, `unobserved_session`: escalated to a human.
- `verification_failed:<check>`, `verification_error:<check>`,
  `merge_conflict`, `conflict:<symbol>`: the integration failed; the
  change's status says more.
- `session_ended`, `session_inactive`, `unknown_session`,
  `session_ttl`: the session is over; start a new one, or continue the
  workspace (`lonca session start --continue`).
- `session_continued`, `continue_child_session`,
  `scope_widening:<what>`: this continuation is refused; see "CLI for
  runners".
- `frozen:<reason>`: the repository is frozen; a human unfreezes it.
- `bad_human_signature`, `stale_human_signature`, `bad_nonce`,
  `nonce_reused`, `presence_required`, `not_enrolled`,
  `unknown_human`: the signature was refused.

Everything else is a policy or key-management reason; show it.

## CLI for runners

Where the daemon has no call of its own, a runner drives `lonca`:
creating a repository or a workspace is the CLI's work (`init`,
`session start`, `workspace create`), and so are `sync`, `propose` from a
workspace, `lease` from a shell, `human login`.
These commands take `--json` and print one JSON object (or array) on
stdout; nothing else goes to stdout then. Human-readable output has the
same facts, nothing more. **No token is ever printed**, in either form.

Exit codes:

| code | meaning |
|---|---|
| 0 | done; a proposal that waits for a human (`escalate`) is done too |
| 1 | the daemon refused: an error code, or a logged decision with `outcome: deny`; stderr has `code: message` (`denied: claim_mismatch:edits`). A denial exits 1 on every command, with or without `--json`. `doctor`: a check failed |
| 2 | the daemon is unreachable, or answered something that is not the protocol |
| 3 | usage, and everything that never reached the daemon (no workspace, no local changes, no key) |

`--json` shapes:

- `session start --json`: `{"session", "workspace": absolute path,
  "expires_ms", "paths": [glob], "scratch": [absolute path], "seq",
  "decision"}`. The agent's token is in `<workspace>/.lonca/session`
  (0600), nowhere else. `--scratch DIR` (repeatable) names a directory
  outside the workspace for the agent's notes and logs; see
  `docs/guide/runners.md`.
- `session start --continue DIR [--widen] --json`: the same, with
  `"continues": old session id` (`null` for a plain start). The new
  session takes over `DIR`: files, base, manifest and the change it
  proposed stay, the old session ends, its token stops working. Taint,
  observation level and what was seen written carry over; leases do not,
  except that items pinned to a change in flight pass to the new session.
  `--paths` wider than the old session's is denied
  (`scope_widening:<what>`) without `--widen`. See `docs/guide/runners.md`.
- `session end --json` (in the agent's workspace): `{"session", "seq",
  "decision"}`.
- `session heartbeat --json` (in the agent's workspace): `{"session",
  "seq", "timeout_ms", "leases"}`. A session that has ended or expired
  exits 1 (`session_inactive`, or `unauthenticated` once its token is
  gone) with nothing on stdout.
- `sync --json`: `{"base_before": id, "base_after": id, "updated":
  [path], "merged": [path], "conflicts": [{"path", "trunk_copy",
  "symbols": [symbol]}]}`. In a conflict the `symbols` keep the local text
  and every other change of trunk comes in; a file with no symbol merge, or
  whose code outside symbols trunk changed, stays local as a whole.
  Trunk's version is in `trunk_copy` (`<path>.trunk`) for reading: it is
  never a local change and the next sync removes it.
- `propose --json`: `{"change", "commit", "seq", "decision", "status":
  "queued" | "pending" | "denied", "details": [detail]}`. `denied` also
  exits 1. `details` is empty for a human's proposal, which needs no
  lease.
- `lease acquire --json`, `lease release <set> --json` and `lease renew
  <set> --json` (in the agent's workspace): `{"seq", "decision", "set",
  "details": [detail]}`. A denied `acquire`'s `set` names nothing; read
  `details` for who holds what.
- `lease interest SYMBOL… --json`: the same shape; `set` is `null`.
- `events --from N --json`: the `events` result.
- `init --json`: `{"repo", "trunk", "seq", "decision", "warnings":
  [string]}`. The warnings are those of `repo.prepare_init`; with
  `--json` they are not repeated on stderr.
- `workspace create --json`: `{"workspace": absolute path, "repo",
  "base"}`.
- `pending --json`: the `pending` array of `status`.
- `approve <seq> --json` and `reject <seq> --reason … --json`:
  `{"seq", "target_seq", "change": change id | null, "decision"}`;
  `seq` is the decision's own entry. A rejected change reads
  `{"status": "rejected", "reasons": ["rejected: <reason>"]}` in
  `change.get` and `status.changes`.
- `human login --json`: `{"human", "expires_ms", "session_file",
  "repos"}`.
- `human whoami --json`: `{"human", "alg", "public"}` (local, no
  daemon).
- `status --json`: the `status` result, pretty-printed.
- `doctor --json`: `{"ok": boolean, "mode": "cooperative" | "hardened" |
  null, "checks": [{"name", "level": "pass" | "warn" | "fail", "detail",
  "hint": string | null}]}`. A failed check exits 1 after the output and a
  warning leaves `ok` true. It writes nothing to the log and shows no
  token, no key and no path to one. Names: `mode`, `socket`, `daemon`,
  `hooks`, `sandbox`, `git`, `lsof`, `human`; per repository `log <repo>`,
  `human <repo>`, `frozen <repo>`.

**The human session file is an interface.** `lonca human login` keeps
the session at `$LONCA_HUMANS/<name>.session`, else
`~/.config/lonca/humans/<name>.session`, mode 0600, as `{"token",
"expires_ms"}`. A runner that speaks to the socket itself may read the
token from there and send it as `token`; when the daemon answers
`unauthenticated` (expired, or the daemon restarted on another home)
or `forbidden` after a key change, it runs `lonca human login --json`
again, which needs no prompt for a file key and one Touch ID for a
Secure Enclave key, and reads the file again. Every `lonca` human
command does the same by itself. The file is readable by anything
running as the developer: it opens reads and prepares only; every write
still needs a signature.

## Protocol numbers

- **1** (2026-11): this document. Additions since, same number:
  `scope.scratch`, `hook.bind.scratch`, `session start --scratch`
  (#78); `tree[].size`, `blobs`, `repo.prepare_init.warnings` (#79);
  `change.diff`, `change.get.evidence` (#80); the `reject` operation
  (#81); `trunk.bundle`, `trunk.distance` (#83); sections as symbols
  (#46); `--json` on `lease`,
  `init` and `workspace create`, `details` in `propose --json`, and a
  denial exits 1 on every command (#97); `continues` on `session.start`,
  `session start --continue`, `status.sessions[].continued_from` and
  `continued_by`, `session.heartbeat` refused when the session is over,
  and `session_inactive` from every `lonca mcp` tool after that (#98).
  `ping.protocol`; `status.pending`
  entries carry `change`, `base`, `intent`, `agent`, `task`,
  `created_ms` and `paths`; `status.changes` entries carry `base`,
  `created_ms`, `version` and `paths`; `log` takes `wait_ms`. Every
  request authenticated (`docs/decisions.md`, "Daemon authentication").
