# Daemon protocol

What a client of the Lonca daemon (a runner such as imece, `lonca-cli`,
an MCP bridge) needs to know, and nothing it does not. The daemon's
crates are not an interface: a client speaks this protocol over the
socket and copies nothing from `crates/`, except the one crate made for
it. `lonca-client` (Rust) holds the request and response types and this
number (`PROTOCOL`), the socket client with the checks of "Verifying the
daemon", framing, an optional timeout and typed errors
(`ErrorKind::is_transient` for `rate_limited`, `busy`, `closed`), and the
reader of the human session file. No store, no policy, no daemon code. A
change of the protocol number is a major version of the crate (while it is
0.x, a minor one); pin an exact version.

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
`~/.lonca/lonca.sock`). One JSON object per line in each direction.
Requests on one connection are answered in order. The client chooses
`id`; the response repeats it.

A request line is at most 64 KiB. The methods that carry files or a list
the repository decides the length of may send up to 96 MiB (`MAX_LINE`),
base64 file contents included: `tree`, `blobs`, `human.prepare_change`,
`human.prepare_policy`, `human.submit`, `lease.acquire`, `lease.interest`,
`change.propose`, `facts.preview`, `session.end`, `hook.event`,
`hook.input` and `hook.stop`. In such a line `method`, `token` and, for a
human session, `repo` come before `params`: the daemon reads the first
64 KiB to decide whether to hold the rest. A JSON map that sorts its keys
puts `token` after `params`, which only matters past 64 KiB. A line
refused for its length is read to its end and answered with `too_large`;
the connection goes on.

A connection that sends nothing for 15 minutes is closed. So is the
longest-quiet connection when the daemon is full (1 024 connections, 512
of one uid, less when it has few file descriptors). Either way the
connection's last line is `{"id": 0, "ok": false, "error": {"code":
"closed", …}}`: the daemon did not read anything sent after it, so open a
new connection and send the request again. A line must arrive within
60 seconds of its first byte (`timeout`, and the connection closes), and a
response must be read within 60 seconds. A request being answered is
never cut. When every connection is answering one, a new connection gets
`busy` and closes; so does a long line when 192 MiB of them are already
held, without the connection closing. Both can be sent again.

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
- **`path#Type.<def>`**: a type's own text (fields, header, for Rust the
  `impl` headers), apart from its methods. `path#Type` is the whole type and
  covers it. Facts report it from symbol engine 3 on; the MCP tool `symbols`
  gives it as `def`.
- **`path#Name(key)`**: a symbol that shares its name with others in the
  file, from symbol engine 6 on: `Client.Charge(int,int)`, `P.x[setter]`,
  `S.From(u8).from`. A symbol alone with its name has no key, and an id can
  hold spaces, so take ids from `symbols` or `preview` and do not build them.
  From log format 13 `path#Name` covers each `path#Name(key)`, in leases and
  in scopes, and the key reaches only its own symbol. What nothing tells
  apart is numbered in file order: `init~2`.
- **`unparsed_files`** in facts, from symbol engine 8: text files changed that
  no parser reads, each also a `path#<file>` in `edits`. Under
  `[leases] unparsed_files = "optimistic"` they need no lease, and
  `facts.preview` lists them in `no_lease`. `status` has the setting as
  `unparsed_files`.
  From engine 9 only edits of lines are listed: the mode stays and is that of a
  plain file, no NUL, and at least half of the old text's lines stay.
- **`unread_files`** in facts, from log format 16: files that a grammar read
  until this change and can not read after it, or that a change adds and it can
  not read. Such a proposal escalates with the reason `unread_file:<path>`. From
  symbol engine 17 this holds for every language with a grammar; before it, a
  parse error in Rust, Python, TypeScript, JavaScript, C# or Go failed the
  `syntax` check instead. The error may be syntax newer than the grammar, so
  `syntax_errors` in an answer is a note, not a refusal.
  From symbol engine 18 a file with a parse error on both sides of a change
  keeps the symbols the error is not in: when the rest of the file (what was
  not read, the definitions it is in, the code outside definitions) has the
  same lines on both sides, the facts name those symbols as for any file and
  `unparsed_files` does not list it. Otherwise it is an edit of `path#<file>`
  as before.
- **`affected`** and **`affected_more`** in facts, from log format 18: symbols
  of the base that mention by name what the change gives a new signature, renames
  or deletes, at most 1000, and how many more there were. A guess, not a call
  graph. A proposal's `decision.reasons` then hold `signature_change:<symbol>`
  and `affected_lease:<session>:<set>`, and the sessions named get a
  `symbols_changed` event.
- **`renames`** in facts, from symbol engine 7: `[[old, new]]`, symbols that
  go on under another name. A renamed one is also in `deletes` and `adds`, so
  a claim is what it was, and one with new parameters in `edits`. A `rename`
  lease on the old name covers it. Once integrated, the old name and the new
  one conflict in leases.
- **lease item**: `{"symbol": "path#Qualified.name", "kind": "edit" |
  "insert" | "rename" | "shared"}`; `shared` only where the policy has
  `[leases] shared = true` (else `shared_off`, see
  `docs/guide/verification.md`, "Shared leases"); for `insert` the symbol is the container
  (`path#Type` or `path#<file>`). An `insert` may add `"names": [string]`, the
  bare names of the members it adds (log format 22): two inserts into one
  container whose names meet conflict, and an addition that is none of them is
  `lease_missing`; names on another kind are `names_need_insert`, malformed
  ones `invalid_names`; adding a name another session reserved is
  `name_reserved:<symbol>:<session>`. A file a change adds needs `edit` (or
  `rename`) on its `path#<file>`, and one trunk created after the change's base
  is `created_since_base:<path>` (sync first). A keyed directory
  (`[paths.keyed]`, log format 29) is the container `dir#<dir>`: an
  `insert` on it reserves keys in `names` (numbers without a leading zero,
  or text), and `lease.acquire` resolves each `next` there to the number
  after the highest key on trunk or reserved, answering `"keys":
  {"dir#<dir>": [key]}`. Anything else on a `<dir>` is `not_keyed:<dir>`,
  `key_required:<symbol>` or `invalid_key:<dir>#<key>`, and any other symbol
  of a keyed directory's path is `key_container:<dir>#<dir>`; `status` lists
  the keyed directories as `"keyed": {"dir": "dir#<dir>"}`. A file a proposal adds
  there needs its key reserved (`key_not_reserved:<dir>#<key>`), a name the
  pattern reads (`key_unreadable:<path>`), and a key no other file has
  (`key_taken:<dir>#<key>`; facts carry `taken_keys` for the proposal's own
  tree); an integration that would leave two files with one key is
  conflicted on `<dir>#<key>`. A lease detail of a free
  `insert` carries the `names` to reserve. Markdown, TOML, JSON and YAML files
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
  signatures are DER-encoded ECDSA P-256 over SHA-256, hex. A security
  key's signature (`sk-p256`, `sk-ed25519`) is the hex of the SSHSIG blob
  `ssh-keygen -Y sign -n lonca` prints inside its armor (OpenSSH's
  PROTOCOL.sshsig and PROTOCOL.u2f): version 1, the enrolled key with the
  application `ssh:lonca`, namespace `lonca`, an empty reserved field,
  `sha512` or `sha256`, and a signature whose flags have "user present"
  set; any other blob, or a byte more, is `bad_human_signature`. A
  signature is good for ten minutes, with one minute of clock skew.
- **human key**: `{"alg", "public": lowercase hex}`. `ed25519`: a file
  key, 32 bytes. `p256-se`: a Secure Enclave key, a SEC1 point. `sk-p256`:
  a FIDO security key, the 65-byte uncompressed SEC1 point. `sk-ed25519`:
  a FIDO security key, 32 bytes. The last three prove presence; the two
  `sk-` kinds exist from log format 28.
- **op**: an operation object, `{"op": "<kind>", …fields}`. The kinds
  and their fields are the operation log's and are listed under
  `log`.

## Methods

### `ping`

*public.* `params: {}`.

```json
{"version": "0.1.0", "protocol": 1, "daemon_key": hex, "next_key": hex | null, "proxy": "host:port" | null,
 "hardened": boolean, "refused": {"busy": integer, "evicted": integer, "idle": integer, "slow": integer, "too_large": integer, "rate_limited": integer}}
```

`daemon_key` is the Ed25519 public key the daemon signs log entries
with; `next_key` is set during a key rotation; `proxy` is where the
daemon's network proxy listens, null when none runs. `hardened` is true
for a daemon of a hardened install (its uid named in the root-owned
`daemon.toml`): a harness reads it at start instead of guessing from
files. Whether its own hooks are the locked ones shows after the first
hook, as the session's level (`status`). `refused` counts,
since the daemon started, what its limits turned away: none of that is in
any log.

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

### `session.where`

*public.* `{"path": absolute path | null, "harness": string | null,
"fields": {string: string}}`. Where the log places a session: the live one
whose `session.bind` named the harness session found in `fields` (read with
`harness`'s profile), else the root session whose workspace is `path` or
holds it, a live one before an ended one, the last started first. Result
`{"repo", "session", "workspace": absolute path | null, "active": boolean,
"continued_by": session id | null, "by": "harness" | "path"}`, or `{}` when
the log knows none. No file of the workspace is read for it.

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
{"repo": string, "human": string, "human_key": human key,
 "import_from": string | null, "branch": string | null,
 "profile": "cooperative" | "hardened" | null, "without_presence": boolean}
```

Names: letters, digits, `.`, `_`, `-`, at most 64. `import_from` is a
remote the daemon fetches `branch` (default `main`) from: an absolute
path, `https://`, `ssh://` or `user@host:path`; a local path outside the
daemon home (its backups excepted) and, where the daemon was given
`--local-root`, under one of those, or `forbidden`. A daemon given
`--import-dir` also reads a Git bundle directly in that directory (a
regular file, not a link), from a copy of its own; anything else below
it is `forbidden`, and so is a push there. Result `{"op": op,
"warnings": [string], "large_files": [{"path", "size"}], "tree_bytes":
integer, "profile": "cooperative" | "hardened"}`: the `repo.init` operation
to sign, what a workspace of this tree will meet (files above the change
cap, a tree above one page), and the profile the policy starts from
(default: `hardened` on a hardened daemon, else `cooperative`). A hardened
profile refuses a key that can not prove presence unless
`without_presence` is true, and that word goes with no other profile.
Errors: `invalid`, `conflict` (the repository exists), `git` (the fetch
failed).

### `repo.init`

*bootstrap.* `{"op": op, "sig": human signature}` with the operation
from `repo.prepare_init`, unchanged. Result: logged. With a human
session, the signer must be the session's human (`forbidden`
otherwise). Errors: `invalid` (not prepared by this daemon), `denied`
(the signature or policy refused; nothing was logged).

### `repo.restore`

*bootstrap.* `{"repo": string, "from": string}`: creates the repository
from a backup bundle, a bare store or a remote Lonca pushed to; `from`
follows the rules of `import_from` above. Result:

```json
{"repo": string, "seq": integer, "head_hash": hex, "daemon_key": hex, "foreign": boolean, "path": string}
```

`path` is the new store (from 0.2.1), where `lonca-audit verify` reads it;
on a hardened daemon only the daemon's user can. `foreign: true` means the log is on another daemon's key and waits for
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
  "repo": string, "trunk": id, "policy": id, "policy_checks": [check name] | null,
  "frozen": string | null,
  "queue": [change id], "next_seq": integer, "head_hash": hex, "now_ms": time,
  "verification_day_ms": integer,
  "daemon_key": hex, "below_hardened": [string],
  "humans": {"<name>": {"alg": string, "public": hex, "recovery": hex | null}},
  "sessions": [session], "leases": [lease], "changes": [change], "pending": [pending]
}
```

- **policy_checks**: the names of the checks the policy in force defines
  (`verification.checks`), sorted: the names `approve.checks` accepts, so a
  client can refuse a misspelt one before the approval does
  (`unknown_check:<name>`). Names only, never a command. `null` when the
  policy can not be read, as `runs`.
- **below_hardened**: what this repository's policy leaves below the hardened
  profile, on a hardened daemon. Always empty on a cooperative one.
- **verification_day_ms**: milliseconds of verification in the UTC day of
  `now_ms`, for `[quota] day_seconds`.

- **session**: `{"id", "agent", "task", "parent": string | null,
  "level": "unobserved" | "hooks" | "hooks_sandbox" | "isolated",
  "workspace": absolute path | null,
  "taint": string | null, "active": boolean, "expires_ms": time,
  "last_seen_ms": time | null, "verification_ms": integer,
  "continued_from": string | null,
  "continued_by": string | null, "unproposed": {"paths": [path], "total":
  integer, "rounds": integer, "seen_ms": time} | null, "bound_ms": time |
  null, "last_hook_ms": time | null, "unhooked": {"tool": string, "seen_ms":
  time} | null}`. `verification_ms` is
  what the session's line has used of `[quota] session_seconds`: the session,
  those it was made from or continues, and theirs. `last_seen_ms` is
  the last heartbeat; `null` means none yet. `continued_from` and
  `continued_by` link the sessions of one workspace, and `workspace` is the
  directory its `session.start` named (`null` before log format 30); `parent` is a
  capability's origin. `unproposed` is what the workspace held the last time
  the session stopped or ended, with no standing proposal carrying it:
  `paths` names at most 32 of `total` files, and `rounds` counts the stops
  since the last proposal. A stop or end that found nothing gives `"paths":
  [], "total": 0, "rounds": 0`. `null` means no report since the session
  began or last proposed (it expired, or ended without `files`), so a client
  can tell "ended clean" from "nobody said". It is the client's report, not
  a check: only a proposal proves delivery. `bound_ms` is when the session's
  hook sent `hook.bind` (a child's is its parent's); `null` means it never
  did. `last_hook_ms` is when the last hook event of the session came, since
  the daemon started; `null` after a restart until the next one.
  `unhooked` is the first call to `lonca mcp` whose before-tool event never
  came: the harness is not running the session's hooks (see `mcp.call`). It
  taints the session and drops its level to `unobserved` for good. A client
  that wants observed workers stops a session with `bound_ms` `null` or with
  `unhooked`.
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
  time, "version": integer, "paths": [path], "checks": [check name],
  "runs": [check] | null}`. `paths` are the files the
  change touches (added, modified, deleted). `checks` are the named checks
  humans asked of it at approval (`approve.checks`); a later version keeps
  them. `runs` is what the merge queue will run for it under the policy in
  force, by the words of its evidence and denials: `build`, `tests`,
  `extended` (`on_signature_change`, for a change that reaches others), then
  each named check it owes, asked or named for one of its paths by
  `verification.checks_by_path`; `null` when the policy can not be read.
  Change status:
  `{"status": "pending", "seq"}`, `{"status": "queued"}`, `{"status":
  "integrated", "commit": id}`, `{"status": "conflicted", "symbols":
  [symbol]}`, `{"status": "rejected", "reasons": [string]}` or
  `{"status": "withdrawn"}`.
- **pending**: an operation waiting for approval. `{"seq": integer,
  "created_ms": time, "actor": label, "op": op kind, "reasons":
  [string], "approvals": [human name], "required": integer, "change":
  change id | null, "base": id | null, "intent": string | null,
  "agent": string | null, "task": string | null, "paths": [path],
  "checks": [check name], "runs": [check] | null}`.
  `change`, `base` and `intent` are set for a `change.propose`;
  `agent` and `task` when the actor is an agent session. `checks` are the
  named checks the approvals so far asked for; `runs` is the change's
  `runs` (above), what it owes before the yes, and `null` for an operation
  that is not a change. One `status` call fills a review list.

`next_seq` is the sequence number the next entry will get, so a client
sees whether anything was logged since its last read without calling
`log`.

### `log`

*read.*

```json
{"from": integer, "limit": integer | null, "wait_ms": integer | null}
```

Entries with `seq >= from`, at most `limit`, and never more than 1 000,
also with no `limit`: to read a longer log, ask again from the seq after
the last entry until the answer is empty. With `wait_ms` and no entry
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
| `human.enroll` / `human.rotate` / `human.recovery_key` / `human.recover` | `human`, `key` (a human key) |
| `human.revoke` | `human`, `reason` |
| `daemon.rotate` | `key` |
| `daemon.recover` | `key`, `recover`: `{"human", "key": human key}` or absent. With it, the human's recovery key signs, and the entry also replaces that human's key (log format 27) |
| `policy.update` | `policy` (id) |
| `session.start` | `session`, `agent`, `model`, `task`, `scope`, `expires_ms`, `continues`, `harness`, `workspace` (absolute path, links resolved; log format 30) |
| `session.bind` | `session`, `checks`, `level` |
| `session.isolate` | `session`, `sandbox`, `profile` (SHA-256 of the sandbox's definition) |
| `session.end` / `cap.revoke` / `taint` | `session`, `reason` |
| `cap.attenuate` | `parent`, `child`, `agent`, `scope`, `expires_ms`, `leases` (when not empty) |
| `lease.acquire` | `set`, `items`, `intent`, `ttl_ms` |
| `lease.release` | `set` |
| `lease.renew` | `set`, `ttl_ms` |
| `lease.interest` | `items`, `intent` |
| `change.propose` | `change`, `commit`, `base`, `claim` |
| `change.withdraw` | `change` |
| `change.integrate` | `change`, `trunk_before`, `merged` (id or null), `conflicts` |
| `change.integrate_batch` | `trunk_before`, `merged` (`[change, commit]` in queue order; the last is trunk's new head), from format 17 |
| `approve` | `target_seq`, `note`, `checks` (when not empty; from format 25) |
| `reject` | `target_seq`, `reason` (1–4096 bytes; the requester reads it) |
| `observe` | `session`, `events` |
| `import.external` | `remote`, `commit`, `trunk_before` |
| `import.unmediated` | `refname`, `found`, `expected` |
| `bridge.push` | `remote`, `oplog_seq`, `oplog_hash` |
| `freeze` / `unfreeze` | `reason` |
| `negotiate` | `thread`, `to_session`, `message` |
| `redact` | `blob`, `reason` |

`approve.checks` names checks of `verification.checks` the change owes from
then on, sorted, each once, at most 32; only on a pending `change.propose`
(`checks_not_a_change`), only names the policy in force defines
(`unknown_check:<name>`), otherwise `invalid_checks`. Only a human signs an
approval, so an agent can neither add a command nor drop a check.

An attestation: `{"check": "syntax" | "scope" | "claim_diff" | "merge"
| "build" | "tests" | "test_integrity" | "extended" | "named", "result": "pass" | "fail" |
"error" | "skipped", "subject_tree": id, "details": {string: string},
"env": hex, "log": id | null, "producer": string}`. A `named` check
carries its name in `details.name`. The `syntax` check passes
from symbol engine 17 on, and names in `details.unread` the files a grammar
could not read: a mistake, or syntax newer than the grammar.

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
 "provenance", "proposed_seq", "created_ms", "version", "checks": [check name],
 "runs": [check] | null,
 "integrate_seq": integer | null, "integrate_decision": decision | null,
 "evidence": [{"check": check kind, "result": "pass" | "fail" | "error" | "skipped",
               "exit": integer | null, "duration_ms": integer | null, "attempts": integer | null,
               "sandbox": string | null, "error": string | null,
               "env": string, "environment": [{"command", "output": string | null, "error": string | null}],
               "details": {string: string},
               "log": string | null, "log_truncated": boolean}]}
```

`evidence` are the checks of the change's last `change.integrate`
entry (empty before one); `duration_ms` covers every attempt; `log` is the tail of the check's output
(32 KiB at most, `log_truncated` when cut), null for a redacted or
missing log. `env` is the digest of the environment the check ran in
(`tree-sitter` for `syntax`); `environment` lists, in order, each
`verification.identify` command of that run with the first line of its
output and, when it failed, how (`"exit 127"`, `"timeout"`): the
`env.<n>.command`, `.output` and `.error` of `details`
([Verification](guide/verification.md#the-environment-the-evidence-names)).
It is empty for evidence from before `identify`. `not_found` for an
unknown change.

### `change.resolve`

*read.* `{"prefix": string}`. The whole id of the one change whose id
starts with `prefix`: `{"change": change id}`. `prefix` is 4 to 32 letters
`k`–`z` (`invalid` otherwise); `not_found` when no change starts with it,
`invalid` too when several do (the message names the first five). `pending`
and `log` show 12 letters; the CLI's `diff`, `change` and `advise` resolve
an id shorter than 32 letters with this.

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
`not_fast_forward` (the branch does not contain trunk), `git`, `forbidden`
(a local path the daemon may not read, see `repo.prepare_init`).

### `human.prepare_push`

*human.* `{"remote": string}`. `{"op": op (bridge.push)}`. The push runs
when the signed operation is submitted and allowed, after the entry is
logged; `human.submit` then adds `"push"` (git's porcelain output), or
fails with `git` while the entry stands.

### `human.prepare_isolate`

*human.* `{"session": string, "base": commit}`. What a sandbox for the
session is built from: `{"scratch": [string], "proxy": "host:port" | null,
"home": string, "base_known": boolean, "harness": string | null, "setup":
object | null}`. The scratch roots are the log's, never a workspace file's;
`proxy` is `null` when the daemon runs none; `home` is the daemon's directory,
which the sandbox closes; `base_known` says whether `base` was ever trunk;
`harness` is the name the session started with, and `setup` that harness's
setup in the policy, as `harness.setup` gives it. Errors: `not_found`.

### `human.submit`

*human* (a `human.recover` operation, and a `daemon.recover` with
`recover`, need no session: their recovery-key signature is the
credential). `{"op": op, "sig": human signature,
"workspace": string | null}`. `workspace` goes with `session.isolate`:
the absolute path connections through the proxy are attributed by, not
logged. Only the human who started a session can isolate it, only before
anything has used it (`session_used`: a heartbeat, an observation, a lease,
a change, a child, a continuation), and not a capability's child, which
takes its level from its parent.
Any human operation: the prepared ones above, `session.start`,
`cap.revoke`, `approve`, `reject`, `freeze`, `unfreeze`, `redact`, the
key operations, `daemon.rotate`, `daemon.recover`. The signer must be the
session's human. Result: logged, plus:

- `session.start`, allowed: `"token"`, the agent's session token.
  Returned once; give it to the agent, never log it.
- `session.isolate`, allowed: `"token"`, the session's new token. The old
  one stops at this entry.
- `bridge.push`, allowed: `"push"`, git's porcelain output.

Errors: `invalid` (the operation does not fit: a `repo.init` here, a
rotation to a key the daemon does not hold), `not_fast_forward`,
`foreign_key` (the repository waits for `daemon.recover`), `denied` for
a recovery the log refused, `git`. A denied operation that came with no
session (`human.recover`) is `forbidden` with the reasons, and is not
logged.

### `lease.acquire`

*agent.* `{"set": string | null, "items": [lease item], "intent":
string, "ttl_ms": integer}`. Logged, plus `"set"`: the lease set's id
(generated when not given). `intent` says what the agent is doing and why,
and is required: blank is denied `intent_required`. Denied with
`lease_held:<symbol>:<session>:<intent>` when another session holds an
item, a pinned one included, and `lease_wanted:<session>` when a waiting
interest goes first. The intent is free text and comes last, so
read `"details"` instead of splitting the reason: [detail], one per held
item however many requested items run into it, empty when nothing is
in the way. `"advice"` says the same in a sentence for a model: who is on
it, and to settle it with `negotiate` or wait with `lease.interest`; `null`
when nothing is in the way. Answers with `details` of holders carry it too:
`change.propose`, `facts.preview`.

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

*agent.* `{"items": [lease item], "intent": string}`. Say you are
waiting for symbols another session holds. Nothing is held and nothing
waits. `intent` is required, as for `lease.acquire`. For
`leases.interest_block_ms` from then (`status.interests[].blocks_until_ms`)
other sessions' new leases that conflict with it are denied
`lease_wanted:<session>`, and their `details` carry code `lease_wanted`, the
waiter, its intent and that time as `expires_ms`; what a session already holds
or has reserved is not new. After that the interest stays in line.
When what conflicts is freed, the oldest interest gets a
reservation for `leases.reservation_ms`: `status.reservations`, an
`events` entry, and until `until_ms` every other session's `lease.acquire`
is denied `lease_reserved:<session>`. An unused window passes to the next
interest. Logged, plus `"details"` as for `lease.acquire`. Denied
`lease_free` for what nobody holds or waits for (acquire it) and
`interest_exists` when the session already waits for it.

### `events`

*agent.* `{"from": integer | null}`, a sequence number. Read-only.

```json
{"events": [event], "next": integer}
```

Pass `next` as the next `from`. An event has a `kind`:
`integrated` (`seq`, `change`), `conflicted` (`seq`, `change`,
`conflicts`), `failed` (`seq`, `change`, `reasons`: verification refused
it), `approved` (`seq`, `target_seq`), `rejected` (`seq`,
`target_seq`, `reason`), `message` (`seq`, `thread`, `from`, `message`: what
it says, as sent to `negotiate`; `from` is the `to_session` of an answer),
`lease_received` (`seq`, `set`, `from`), `symbols_changed` (`seq`, `change`,
`from`, `sets`, `symbols`), and `reserved` (`items`,
`until_ms`), which is the state now and is reported on every call while
it lasts.

### `inbox`

*agent.* `params: {}`. What other sessions want of the caller and it has
not been told: `{"events": [event], "text": string | null}`, of the kinds
`message`, `lease_received`, `symbols_changed` and `reserved`, once each. `text` is that for a
model, with a message cut at 600 characters and marked as another agent's
words. `lonca mcp` calls this after every tool and adds `text` to the answer
as a second content item; a hook gets it through `hook.input`. An agent is not
told what it read with `events`. What was told is kept in the daemon's memory,
so after a restart it may be told again. Nothing is logged. For the rest of
what happened, `events`.

### `events.watch`

*human.* What happened to the agent sessions this human started, for a
runner that wakes an idle agent instead of polling. Read-only and never
logged; it marks nothing as told, so the agent still hears all of it
through `inbox` and its tools' answers. A runner needs no agent token for
it: the human session it started the sessions with is enough.

```json
{"from": integer | null, "sessions": [string] | null,
 "reserved": [string], "wait_ms": integer | null}
```

- `from`: `next` of the last answer. Left out: from now on, nothing older.
- `sessions`: only these, each one this human started (another human's
  session, or one never started, is `forbidden`, with the same message).
  Left out: every session this human started that can still act, as it
  stands each time the daemon looks.
- `reserved`: `reserved` of the last answer.
- `wait_ms`: with nothing to report, the daemon holds the request (not its
  lock) until something comes or the time runs out (capped at 30 000), as
  `log` does. A new entry wakes it at once; the clock (a reservation, an
  expiry) is looked at every 2 s.

```json
{"events": [{"session", "kind", "seq"?, "change"?, "from"?,
             "reservation"?, "until_ms"?}],
 "next": integer, "reserved": [string],
 "ended": [{"session", "reason"}]}
```

Each event names the session it is for and its `kind`, the same kinds as
`events`: `integrated`, `conflicted`, `failed` and `symbols_changed` with
`change`; `approved`, `rejected`; `message` and `lease_received` with
`from`, the session that sent it; each of those with `seq`, its entry.
Never what was written: a message's words, its thread, the reasons and
the conflicts are the agent's to read (`inbox`, `events`), not the
runner's. `reserved` events have no `seq` but a `reservation` name and
`until_ms`: a reservation is the state, not an entry. The answer's
`reserved` lists every reservation the watched sessions hold now; passed
back, those are not reported again, and one that lapses and comes back is.
`ended` lists the sessions named in `sessions` that can not act any more,
with the reason they were ended with or `expired`; while there is one the
call returns at once, so drop it from `sessions`.

A runner loop: `{"from": status.next_seq, "wait_ms": 30000}`, then the
same with `from = next` and `reserved = reserved` of each answer; for
each event, wake that session's agent (it reads the news itself). The
`lonca-client` crate has it as `Client::watch` and `Watch::after`; a shell
runner has `lonca events --watch --follow --json`. A waiting request is a
connection like any other and counts against the daemon's connection
limits.

### `change.propose`

*agent.* `{"change": change id | null, "base": id, "files": [file
change], "claim": claim}`. Builds the commit on `base`, computes the
facts, decides. Logged, plus `"change"`, `"commit"`, `"facts"`,
`"syntax_errors"`, `"details"` ([detail], one per lease the proposal
lacks: `lease_missing` with the holder if there is one). `outcome: "escalate"` means the change waits for a
human (`status.pending`); `"allow"` means it is queued and the merge
queue integrates it (`status.changes[].status`). A denied change is
logged with its reasons (`claim_mismatch:edits`, `lease_missing:…`,
`scope_path:…`, …). An agent's proposal that is not denied replaces the
changes of its workspace (its session and the sessions it continues) that
wait for a human: each is `withdrawn` in the same entry and named in the
reasons as `replaces:<change>`. A queued change stays.

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
[string] | null}`. A child session with a narrower scope. `agent` is the
caller's own agent name (`child_agent_name:<name>` otherwise, from log
format 31): a child is the same agent to the policy and to a reviewer.
`leases` hands
lease sets to it until it ends, expires or misses its heartbeat; they go
back to the parent then, with the time they had, if the parent is still
there (on expiry and heartbeat from log format 23). Only the child renews
them while it holds them. Logged, plus `"session"` and `"token"` when
allowed.

### `session.end`

*agent.* `{"files": [local file] | null}`. Ends the agent's own session;
its token stops working. Logged. `files` are the workspace's local changes,
as for `hook.stop`: what no standing proposal carries is recorded for
`status`, and the result adds `"unproposed"` ([path]) and
`"unproposed_total"` (integer), both empty when nothing was left, which is
recorded too. Without `files` nothing is recorded.

### `session.rotate`

*agent.* `params: {}`. A new token for the caller's session: `{"token":
string}`. The token the request carried stops working at once. Not logged.
Refused (`forbidden`) for an isolated session, whose token `lonca run`
holds. A client that rotates writes the new token where it keeps the old
one; `lonca session rotate` does that for a workspace.

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
logged; once the daemon has swept its token (within seconds), the error is
`unauthenticated`. Either way, stop beating.

### `hook.event`

*agent.* A harness hook event: `{"hook_event_name": string,
"tool_name": string | null, "tool_input": object, "cwd": string | null,
"workspace": absolute path, "harness": "claude-code" | "codex" |
"gemini" | null}`. The event name is always `PreToolUse` or `PostToolUse`;
the tool name is the harness's own. No harness means Claude Code; one
Lonca does not know is denied. Result `{"decision": "allow" | "deny" |
"ask", "reason": string}`. Observations are logged as `observe`
entries.

### `hook.input`

*agent.* What a hook program got from its harness, untouched:
`{"harness": string, "input": object, "workspace": absolute path, "real":
absolute path | null}`. `real` is `workspace` with its links resolved: when
the session's `session.start` named a workspace and this is another, the
request is `invalid`. The daemon reads `input` with the harness's profile from the policy
(`docs/guide/runners.md`, "Any other harness"). A harness without a
profile, or an event it does not have, is `invalid`. A session start gives
`{"phase": "session_start", "session": string, "context": template,
"tool_prefix": string}`: call `hook.bind`, then fill `{context}`, naming the
tools with `tool_prefix`. A stop gives `{"phase": "stop"}`: call `hook.stop`.
A tool call gives what `hook.event` gives, plus `"output"` on a denial: the
answer in the harness's shape. After a tool call on a harness with
`tool_context`, `"output"` is what `inbox` has for the session, as that
answer, and it is then told. No news, no `"output"`.

### `hook.bind`

*agent.* `{"harness": string, "harness_session": string,
"sudo_without_password": boolean, "workspace": absolute path | null}`.
Logged, plus `"level"` (the level the session stands at after this request),
`"notes"` ([string]) and `"scratch"` ([absolute path], the session's scratch roots
from the log). A level is read only when `harness` is the one in the session's
`session.start`, and it can not rise once a bind has set it: such a bind is denied
(`bind_raises_level`) and `"level"` is what stood.

### `hook.stop`

*agent.* The agent is about to finish its turn. `{"harness": string,
"files": [local file]}`, where a **local file** is `{"path": path, "entry":
{"mode": string, "blob": id} | null}`: one local change, `null` for a
deletion. The daemon compares them with the session's standing proposals
(pending, queued or integrated, from this session and those it continues)
and answers `{"unproposed": [path], "total": integer, "round": integer,
"limit": integer}`, plus `"output"`, the answer that sends the agent back in
the harness's shape, while `round` is within `[sessions] stop_rounds`.
Without `output` the turn ends. A harness with no stop event is `invalid`.
A report goes in the log as an `unproposed` observation when it says
something new; a clean report is new once after the session began or
proposed. It is a reminder and a record, not a check: the client
computes `files`.

### `mcp.call`

*agent.* `{"tool": string}`. `lonca mcp` sends it before it runs one of its
tools, by the name in `tools/list` (lowercase, digits and `_`, at most 64
bytes; any other is `invalid`). On a harness whose profile says its
before-tool event covers MCP tools (`events.before_tool_mcp`, only Claude
Code's for now), that event came first, through `hook.event` or
`hook.input`, unless the session's hooks are not running. The daemon takes
one event of that tool from the session's, oldest first; an event waits ten
minutes at most. A call with none marks the session `unhooked`: an
`unhooked` observation in the log (once per session) and an `unhooked`
security event. Nothing is refused here, but the session is tainted from
then on (`unhooked_session`, `unhooked_critical_path`). Answers `{"checked":
boolean, "hooked": boolean | null}`; `checked` is false, and nothing is
compared, for an isolated session, one with no harness named and one whose
harness has no such event. For ten seconds after the daemon starts, a call
of a session older than the daemon with no event is not a miss: the event
may have gone to the daemon before.
Not counted against `[sessions] ops_per_minute`.

### `harness.setup`

*agent.* `{"harness": string}`. Gives `{"setup": object | null}`: the
`setup` part of the harness's profile from the policy, holes unfilled, or
`null` for a harness with no profile, which still gets the rules and the MCP
server. Not logged.

### `security.events`

*any human.* `{"since_ms": time | null}` (default: one day ago). What the
daemon's security log holds since then, of the repositories the human is
enrolled in and of none: `{"since_ms", "counts": {kind: integer}, "events":
[{"time_ms", "kind", "repo"?, "session"?, "method"?, "uid"?, "code"?,
"detail"?}]}`, the latest 100. The kinds are listed in `docs/decisions.md`
("Security events outside the log"); new ones may appear. No event holds a
token, a request or file contents.

### `queue.run`

*any human.* `params: {}`. Wakes the daemon's worker, which drains the
merge queues; `{"integrated": 0, "woken": true}`. The answer does not
wait for it: follow `status`. The worker also does this on its own within
two seconds of a proposal. `integrated` was the count when the call ran
the queue itself, and stays 0 under protocol 1.

## Error codes

| code | meaning |
|---|---|
| `invalid` | the request does not fit: bad params, missing `repo`, a value out of range |
| `unauthenticated` | no token, or one that is unknown, ended or expired, or whose session expired (every method but `session.heartbeat` and `session.end`); a login that did not verify |
| `forbidden` | a token of the wrong kind, for another repository, or not enrolled; a signature by another human |
| `not_in_sandbox` | an isolated session's token, on an agent request that came from outside a sandbox; the session is tainted. `session.heartbeat` and `session.end` are exempt |
| `session_inactive` | `session.heartbeat` of a session that has ended or expired; nothing is logged |
| `unknown_method` | not in the table |
| `not_found` | no such repository or change; a path not in the commit (`blobs`) |
| `too_large` | a request line over its method's limit; a `blobs` page, or one file, does not fit the line cap |
| `invalid` | parameters that do not read, or do not fit the method. Also an operation whose JSON, with its human signature, is past 64 KiB: the message names the operation and its size; nothing is logged. Shorten its text and lists, or split it |
| `rate_limited` | the session and those made from it are past `[sessions] ops_per_minute`; nothing is logged, and the message says when to try again. `session.end` and the methods that write nothing to the log are exempt |
| `busy` | no room for this connection or long line; nothing ran, send it again |
| `verifying` | `change.withdraw` of a change whose checks are running; nothing is logged. Send it again once they end, if the change is still queued |
| `closed` | id 0: the connection was closed while quiet; nothing sent after this ran, send it again on a new connection |
| `timeout` | id 0: the request line took too long; the connection closes |
| `conflict` | the repository exists |
| `denied` | a signed operation the log refused before anything was written (`repo.init`, recoveries) |
| `foreign_key` | the repository is on another daemon key |
| `up_to_date`, `not_fast_forward` | import conditions |
| `git` | the git subprocess failed (the message is its stderr), or ran past its time limit and was stopped |
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
  moment; `details` says until when. `lease_wanted:<session>`: that session
  waits for something that conflicts and goes first; `details` says what for
  and until when, so settle it with `negotiate` or get in line. `lease_free`:
  nobody holds it, acquire instead of waiting.
- `intent_required`: a lease or an interest with a blank `intent`. Say what
  you are doing and why.
- `claim_mismatch:<field>` (`edits`, `adds`, `deletes`, `deleted_files`,
  `signature_changes`, `tests`): the claim does not match the facts;
  `facts.preview` says what the facts are.
- `scope_path:<path>`, `scope_symbol:<symbol>`, `scope_op:<op>`,
  `scope_max_files`, `scope_max_lines`: outside the session's scope.
- `stale_trunk`, `unknown_base`: propose on the current trunk.
- `replaces:<change>`, on an allowed or escalated proposal: that change of
  the same workspace was waiting for a human and is `withdrawn` now; the
  new one holds its edits. Approve the new one.
- `unobserved_write:<path>`, `tainted_session`, `tainted_critical_path`,
  `critical_path:<path>`, `unobserved_session`: escalated to a human.
  `unhooked_session` and `unhooked_critical_path` are a taint's, for a
  session whose hooks did not run (`status.sessions[].unhooked`): start a
  new session in a harness that runs them.
- `verification_failed:<check>`, `verification_error:<check>`,
  `verification_missing:<check>`, `merge_conflict`, `conflict:<symbol>`:
  the integration failed; the change's status says more. `<check>` is
  `build`, `tests`, `extended` or the name of a named check the change owed
  (`runs`); a named check is owed whether or not `verification.required`
  is set.
- `verification_quota:session`, `verification_quota:day`: past `[quota]`;
  on a proposal nothing is queued, on an integration the checks did not run.
  The session's quota does not come back; the day's does at midnight UTC.
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
  `"continues": old session id` (`null` for a plain start). The old
  session is the one the log places in `DIR`, not one a file there names.
  The new session takes over `DIR`: files, base, manifest and the change it
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
  "symbols": [symbol]}]}`. In a conflict both sides stand in the file between `<<<<<<< local <tag>`,
  `======= <tag>` and `>>>>>>> trunk <tag>`, a symbol whole or by lines, and every
  other change of trunk comes in. `propose` refuses while any of the three stands
  in a changed file, and a later sync reports the conflict again.
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
- `events --watch [--from N] [--session S,…] [--reserved R,…] [--wait SECONDS]
  --json`, as a human: the `events.watch` result, after at most `--wait`
  seconds (30 by default). With `--follow`, one call after another: one
  JSON object per line for each event, and `{"session", "kind": "ended",
  "reason"}` for a named session that ended; it stops when stdout is
  closed or every named session has ended.
- `init --json`: `{"repo", "trunk", "seq", "decision", "warnings":
  [string], "profile"}`. The warnings are those of `repo.prepare_init`; with
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
  `human <repo>`, `frozen <repo>`. Without `--json` the same checks are
  grouped under headings as `flutter doctor` does (`[✓] Mode`, `[✗] Daemon`,
  `[!] Repository demo`), with what to do under each problem and a last
  line that counts the categories with issues; that line replaces the
  `check(s) failed` on stderr. Colour only on a terminal, and not with
  `NO_COLOR` set or `TERM=dumb`. The text is for people; scripts read
  `--json`.

**The human session file is an interface.** `lonca human login` keeps
the session at `$LONCA_HUMANS/<name>.session`, else
`~/.config/lonca/humans/<name>.session`, mode 0600, as `{"token",
"expires_ms"}`. Read it only if it is a regular file (not a link) of your
own user that group and others can neither read nor write
(`lonca_client::session::read_session` checks this; `lonca` itself does
not use a file that fails it, and the login that follows writes it back as
0600). A runner that speaks to the socket itself may read the
token from there and send it as `token`; when the daemon answers
`unauthenticated` (expired, or the daemon restarted on another home)
or `forbidden` after a key change, it runs `lonca human login --json`
again, which needs no prompt for a file key and one Touch ID for a
Secure Enclave key, and reads the file again. Every `lonca` human
command does the same by itself. The file is readable by anything
running as the developer: it opens reads and prepares only; every write
still needs a signature.

- `harness setup <name> [--print] --json`, in a workspace: `{"harness",
  "known": boolean, "written": [path], "files": {path: text}, "flags":
  [string], "env": {name: value}, "note": string, "rules": string, "mcp":
  {"command", "args", "cwd", "env"}}`. `--print` writes nothing. A file the
  repository has, a local file or a symlink at a target is refused, and
  nothing is written; the files of `setup` are never a local change.
- `session start --harness <name> --json`: the same report as `"setup"`. If
  the setup fails, the session has started: the error names it. The name goes in
  the signed `session.start`, and it is what a level is read for: a session with
  none is `unobserved`. `--no-setup` names it and writes nothing, and `"setup"` is
  `null`.
- `rules`: the rules as text, with neutral tool names.

MCP tools: an argument a tool does not take is refused with `invalid` by a
tool that changes something, with the tool's input schema as `"expected"`. A
tool that only reads runs and adds `"warnings": [string]` and `"expected"`. A `propose` denied
for `claim_mismatch:<field>` adds `"claim_mismatch": [{"field", "claimed",
"facts"}]`.

## Protocol numbers

- **1** (2026-11): this document. Additions since, same number:
  `scope.scratch`, `hook.bind.scratch`, `session start --scratch`
  (#78); `tree[].size`, `blobs`, `repo.prepare_init.warnings` (#79);
  `change.diff`, `change.get.evidence` (#80); the `reject` operation
  (#81); `trunk.bundle`, `trunk.distance` (#83); `profile` and
  `without_presence` on `repo.prepare_init`, `status.below_hardened` (#54);
  sections as symbols
  (#46); `--json` on `lease`,
  `init` and `workspace create`, `details` in `propose --json`, and a
  denial exits 1 on every command (#97); `continues` on `session.start`,
  `session start --continue`, `status.sessions[].continued_from` and
  `continued_by`, `session.heartbeat` refused when the session is over,
  and `session_inactive` from every `lonca mcp` tool after that (#98);
  `hook.stop`, `phase: "stop"` in `hook.input`, `files` on `session.end` and
  `status.sessions[].unproposed` (#121); `inbox`, `message` on a `message`
  event, `advice` on `lease.acquire`, `change.propose` and `facts.preview`,
  `"output"` after a tool call in `hook.input`; `lease_wanted` and
  `intent_required`, `status.interests[].blocks_until_ms`. A blank `intent`
  on `lease.acquire` or `lease.interest`, accepted before, is now denied.
  `ping.protocol`; `status.pending`
  entries carry `change`, `base`, `intent`, `agent`, `task`,
  `created_ms` and `paths`; `status.changes` entries carry `base`,
  `created_ms`, `version` and `paths`; `log` takes `wait_ms`. Every
  request authenticated (`docs/decisions.md`, "Daemon authentication").
  `harness` on `session.start` and `status.sessions[]`; `hook.bind` reads a level
  only for that harness, and a session started without one is `unobserved`, where
  before the request's name was enough. `mcp.call`, `status.sessions[].bound_ms`,
  `last_hook_ms` and `unhooked`, and the reasons `unhooked_session` and
  `unhooked_critical_path` (#190). `checks` on `approve` (log format 25),
  `checks` and `runs` on `status.changes[]`, `status.pending[]` and
  `change.get`, the attestation kind `named`, and the reasons
  `unknown_check:<name>`, `invalid_checks` and `checks_not_a_change` (#191).
  The `lonca-client` crate (#192).
  `change.resolve`; `recover` on `daemon.recover` (log format 27); the
  human key kinds `sk-p256` and `sk-ed25519` and their signatures (log
  format 28). `events.watch` and `lonca events --watch` (#262).
  `env` and `environment` on `change.get.evidence[]` (#263).
