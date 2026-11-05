# Decisions

Phase 0 decisions and the choices made while building v0.1, with reasons.
The design document ([design.md](design.md), Turkish) describes intent;
this file records what was decided and where the implementation departs
from the design.

## Phase 0

| Topic | Decision | Why |
|---|---|---|
| Language | Rust | gitoxide, tree-sitter, Cedar, jj and Mergiraf all live in the Rust ecosystem; a small trusted core with no runtime. |
| Storage | Git object format via gitoxide (`gix`), own core | The operation log is the security core: it must be small, linear, signed and ours. jj's operation log has different semantics (a DAG of view snapshots that allows concurrent operations) and jj-lib is pre-1.0. Network transport for push/fetch uses the `git` binary; the trusted part never depends on it. |
| Change id | 16 random bytes in a `change-id` commit header, "reverse hex" (`z`..`k`) | Identical to Jujutsu (verified against jj's source), so jj users see the same ids. |
| License | Apache-2.0 | Patent grant; same as jj. |
| Name | Lonca | Craft guild: written rules (policy), master/journeyman/apprentice (delegation), inspection (verification). |

## Implementation choices

- **Capabilities are daemon-side records, not Biscuit tokens.** With a
  single sequencer, offline verification buys nothing, and bearer tokens
  would have to be kept out of the log. A session token is random, only its
  SHA-256 is stored, and it never enters the log. The design property is
  kept: scopes can only narrow (`scope_within`), and revocation cascades.
- **Policy is Cedar, fail-closed.** Cedar skips a policy whose evaluation
  errors; for a `forbid` rule that would mean "allow". Lonca treats any
  evaluation error as a denial. `@escalate` turns a forbid into a human
  approval, `@approvals("N")` sets how many.
- **Decision vs. evidence.** `decide()` is pure; its inputs are the state
  (a fold of the log), the request, recorded facts and attestations, the
  daemon's timestamp and the policy commit in force. Build and test results
  are attestations recorded in the log and never recomputed. Facts and
  merges are deterministic and the auditor recomputes them.
- **Structural merge is Lonca's own.** Mergiraf's license (GPL) does not fit
  an Apache-2.0 project. The merge applies the incoming side's symbol-level
  changes to trunk's text; module-level edits fall back to a line merge;
  every merged file of a supported language must parse.
- **Rust `impl` blocks** are containers named `impl:Type` whose members are
  named `Type.method`, so a lease on `Type` covers every method.
- **Leases never wait.** Acquisition is all-or-nothing and returns the
  holder and intent on conflict; there is no hold-and-wait, so no deadlock.
- **Unobserved means tainted.** Sessions start unobserved; only a harness
  bind whose checks the daemon verifies itself raises the level. Unobserved
  sessions are treated like tainted ones unless the policy says otherwise.
- **Observation/effect consistency.** A file a session changed but no
  observed tool wrote (and no shell ran) escalates the change and taints the
  session.
- **Network attribution** uses `lsof` to find the connecting process's
  working directory. When it can not (other users, missing `lsof`), every
  proxied session is tainted.
- **Human presence** uses a Swift helper with CryptoKit's Secure Enclave
  P-256 keys (no keychain entitlement needed); `approvals.require_presence`
  rejects file-key signatures.
- **Undo is always compensating.** Integrated changes are reverted by a new
  change through the queue; the log is never edited.
- **Redaction is logical.** The daemon withholds redacted blobs; purging
  them from Git history (and from remotes) is not implemented.
- **The auditor shares the decision code.** It is a separate binary and
  process, and in CI it runs on separate infrastructure, but it uses the
  same `decide()`; a bug there would be shared. An independent
  re-implementation remains an open question.
- **The advisor** calls `claude-opus-5-5` with structured output and
  server-side refusal fallbacks, under a daily call budget reserved before
  each request. Its output never reaches a decision.

## Log format versions

Every operation entry carries a `format` version, covered by its digest and
the daemon signature (`crates/lonca-core/src/oplog.rs`).

- **Version 0** is every entry written before the field existed. The field
  is left out of their encoding, so their bytes, hashes and signatures are
  unchanged and existing logs verify as they are.
- **Version 1** is version 0 with the field written out.
- **Version 2** adds `symbols_engine` (below).
- **Version 3** adds the human key operations (`human.rotate`,
  `human.revoke`, `human.recovery_key`, `human.recover`; see "Human keys").
- **Version 4** adds the daemon key operations (`daemon.rotate`,
  `daemon.recover`; see "Daemon keys").
- **Version 5** adds `scope.scratch` on `session.start` and
  `cap.attenuate` (see "Scratch roots and taint policy"). The field is
  left out of the encoding when empty, so every earlier entry keeps its
  bytes; an entry that names a root needs format 5.
- **Version 6** adds `reject` (see "Reject, and a pending proposal whose
  session ends").
- An entry of an older format can not contain an operation type that a
  later version added; the chain check refuses one that does.
- The daemon writes only the current version; a log written by an older
  release continues with current entries after an upgrade.
- **Refusal.** Decoding reads the version before anything else. A version
  newer than the build knows is refused (`unsupported: ... upgrade lonca`)
  by the daemon, which then does not start, and by the auditor. The version
  never decreases along the chain; a decrease is an integrity failure.
- **When the version changes.** Any change to what an entry can contain or
  mean: a new operation type, a new or renamed field, a changed encoding,
  or a changed meaning of a recorded value. Additions that an old reader
  would silently drop count too, because the old reader would then compute
  a different digest.
- **Compatibility during 0.x.** A log written by any 0.x release stays
  readable, verifiable and auditable by every later release. The decoding
  path of an old version is never removed. Each version gets a golden log
  (`crates/lonca-daemon/tests/fixtures/oplog-vN.bundle`) written once by the
  release that introduced it and checked by CI forever after: the head hash
  is pinned, every entry must re-encode to its stored bytes, and the deep
  audit must pass. Fixtures are never regenerated. Before 1.0 this policy
  will be reviewed; dropping a version would need a migration that
  preserves the old log as evidence.
- **Not covered:** the semantics of the symbol engine; see the next section.

## Symbol engine versions

The auditor recomputes the facts of every proposal and the merge of every
integration from the Git objects. Extraction, facts and the merge are
therefore part of the log's meaning, but they change more often than the
entry format, so they have their own version
(`crates/lonca-symbols/src/engine.rs`).

- **Recorded per entry.** `change.propose` and `change.integrate` entries
  carry `symbols_engine`, the version that computed their facts or merge.
  From format 2 on it is present on exactly those entries; an entry of an
  older format has none and means engine 0. Engine 0 is the engine of
  v0.1.
- **Recomputed with the recorded version.** `facts_of` and `integrate` take
  the version as a parameter. The daemon passes the current one; the
  auditor passes the one in the entry. A version the build does not know is
  refused: the daemon does not start and the auditor reports an `engine`
  finding.
- **What is an engine change.** Anything that changes the output of
  extraction, facts or the merge for some input: a new rule, a fixed gap,
  a changed symbol name, and also an update of a tree-sitter grammar or of
  `similar`/`diffy` that changes their output. Such a change adds a new
  version; the old code stays in the crate behind the version switch,
  frozen.
- **Frozen output.** `crates/lonca-symbols/tests/engine.rs` pins, for each
  engine version and each supported language, the extracted symbols, the
  facts of both sides and the three-way merge of a small corpus
  (`tests/engine/v<N>/`). The golden logs pin the same through the whole
  daemon and auditor. A failing snapshot is never edited; it means the
  change needs a new engine version. A dependency update that fails it
  must wait until its output is the old version's or a new version is
  added.
- **Compatibility during 0.x** is the same as for the format: every engine
  version that ever wrote an entry stays recomputable by every later
  release.

## Human keys

A human key can be replaced, withdrawn and recovered (design §5.4). All
four operations are human operations; agents and the daemon can not
request them, and a policy can escalate them like any other operation.

- **`human.rotate`** replaces the signer's own key, signed with the current
  key (with presence when the policy requires it). Only the human can
  rotate their key.
- **`human.revoke`** withdraws a human's key and recovery key. Any enrolled
  human can request it, also for themself, with a reason. The last
  enrolled human can not be revoked: nobody could sign afterwards. A
  revoked name can be enrolled again, with a new key.
- **Recovery when the only key is lost.** A single developer has no second
  human to revoke and re-enrol them, and a Secure Enclave key dies with its
  Mac. Decided: a **recovery key**, registered with
  `human.recovery_key` (signed with the current key) and kept off the
  machine (`lonca human recovery-key --out` writes it where the user
  says, e.g. a USB stick or a password manager). `human.recover` is signed
  with the recovery key and installs a new key. The recovery key signs
  nothing else, is used up by the recovery, and is the one signature that
  does not need presence even under `require_presence`, because the key
  that has presence is the one that was lost. That makes the recovery key
  as strong as the key it replaces: anyone holding it can take over the
  human once. Hence off the machine, single use, and the cascade below so
  that a recovery is visible and ends everything that was running. The
  alternative, a signature plus a waiting period (#19), needs a key that
  is not lost, so it does not cover this case; it remains planned for
  policy changes.
- **Cascade.** Rotation, revocation and recovery all end everything the
  human set in motion: every session they started and every session
  derived from it (capabilities, leases, queued and pending proposals,
  queued verification), their own changes in flight, the operations they
  requested that wait for approval, and the approvals they gave to other
  pending operations. Negotiations end because both sides need an active
  session. The daemon drops the tokens of every ended session, and also
  refuses a token whose session has ended if one is left over. Rotation
  cascades too: it may be a response to a suspected compromise, and "the
  key changed" should mean nothing signed or started under the old key is
  still moving.
- **History stays valid.** Entries signed before a rotation, revocation or
  recovery remain valid: the auditor replays every decision with the
  state, and so the keys, in force at that point.
- **Keys are never reused.** A key that was rotated away, used up or
  revoked is retired and refused by every later key operation and by
  `human.enroll`. A new key must also differ from every key in use
  (primary or recovery), and the key operations check that it is a
  well-formed key of its algorithm (lowercase hex, a valid Ed25519 or
  P-256 point), so a rotation can not lock a human out. `human.enroll`
  keeps its older, looser check: tightening it could change the replay of
  existing logs.
- **Escalated key operations are checked again on release.** A policy may
  send a key operation to approval. The approval that releases it denies
  the release if the operation would now revoke the last human, or if its
  new key has meanwhile become someone's key.
- **Frozen repositories** still accept the key operations: replacing or
  withdrawing a key is how a human answers an incident, and recovery is
  the only way back in when the key that would unfreeze is lost.
- **CLI.** `lonca human rotate|recover --repo a,b` takes every repository
  the human is enrolled in, because the local key is shared between them.
  The new key waits next to the current one (`<name>.next.key|se`) and is
  installed only after every repository accepted it; a rerun skips the
  repositories that already use it. The old key file is kept as
  `<name>.key.retired-<ms>`.

## Daemon keys

The daemon key signs every entry; `repo.init` names it. Before this, a
lost `daemon.key` (disk failure, reinstall, a new machine) ended the
repository's log, and so did moving to hardened mode, where the key
belongs to `_lonca`.

- **`daemon.rotate {key}`** moves a repository to a new daemon key. The
  entry is signed by the old key and carries a human signature (presence
  when the policy requires it); every later entry is signed by the new key.
  The daemon only accepts a rotation to the key it prepared
  (`daemon.prepare_rotate`), so a typo can not end the log.
- **`daemon.recover {key}`** re-anchors a repository whose daemon key this
  daemon does not hold: the key is lost, or the store was copied from
  another daemon. The entry is signed by the new key, because the old one
  is gone, and by a human. The daemon decides it before writing it and
  writes nothing if it is refused: a refused recovery could not be signed
  by the key in force. Every session ends, since the daemon that held
  their tokens is gone; what they proposed keeps its decision and its
  place in the queue, as after `session.end`. A rotation keeps sessions:
  the daemon and its tokens (stored as hashes) stay.
- **Who.** Any enrolled human; agents and the daemon can not request
  either. Both work in a frozen repository, like the human key
  operations. Unlike `human.recover`, a daemon recovery has no presence
  exemption: the human signs with their own key.
- **No waiting for approval.** A recovery is signed by the new key, so it
  can not sit in the log as pending while the old key signs on; a
  rotation follows the same rule. A policy rule that escalates either is
  turned into a denial (`not_escalatable:<rule>`); `forbid` rules still
  deny. Requiring several humans for a key switch would need several
  signatures on one entry; that is open (with #19).
- **Keys** are valid Ed25519 points in lowercase hex, never the key in
  force, a retired daemon key or a human key.
- **Verification.** `verify_chain` follows the key through every allowed
  switch: a rotation is checked against the old key, a recovery against
  the key it installs. That alone would let anyone who can write the store
  forge a recovery onto their own key, append entries, and rotate back to
  the daemon's key. So the daemon decides every key switch again when it
  opens a repository (`lonca_policy::chain::replay_checked`) and refuses
  to start if one does not replay; the auditor reports such a switch as a
  `daemon_key` finding and lists every switch it saw. A human key holder
  can still re-anchor a log on a key of their choice: that is what
  recovery is, and the switch is in the log for every auditor to see.
- **Files.** `daemon.prepare_rotate` creates `daemon.next.key` next to
  `daemon.key`. While some repositories are on each, the daemon signs each
  repository with the key its log is on, and new repositories get the
  next key. When no repository uses the current key, the old secret is
  deleted and the next key takes its place. A crash between the two steps
  leaves only the next key, which is then used as the current one. The
  old secret is deleted rather than kept: the entries it signed stay
  verifiable through its public key in the log, and nothing may be signed
  with it again.
- **A repository on another key** (`foreign_key`) accepts nothing but
  `daemon.recover`; the daemon still starts, and lists it at startup.
- **Mode change (cooperative to hardened).** The hardened daemon gets a
  copy of each store (for example `git clone --mirror` of the cooperative
  store or of a pushed remote into its `repos/`, as `_lonca`) and runs
  with its own new key; then `lonca daemon-key recover --repo a,b` as an
  enrolled human. The cooperative key lived where the developer's account
  could write, so it is not carried over; recovery retires it. Stop the
  cooperative daemon first: it still holds its key and would go on
  writing to its own copy, which then differs from the hardened one.
- **CLI.** `lonca daemon-key rotate [--repo a,b]` (default: every
  repository still on the current key; rerun to resume) and
  `lonca daemon-key recover --repo a,b`. The Touch ID prompt names the
  first 16 hex digits of the new key, as `lonca daemon` prints its key.

## Backup and restore

Everything a repository is lives in its bare store under the daemon's home:
trunk, the operation log, the policy and every proposal are refs of one
Git repository. So the backup format is a Git bundle and the restore is a
fetch; no second format, and plain `git` can read a backup.

- **`repo.backup`** (`lonca backup`) writes `git bundle create --all` of
  the store into the backups directory, under the daemon's lock so the
  bundle is the store at one point of the log, named
  `<repo>-<seq>.bundle`. It is a read, like `log` or `tree`, and is not
  logged. In hardened mode the home is unreadable for the developer, so
  the bundles go to a directory of their own (`--backups`, group
  `lonca`, dir 0750, files 0640) and `lonca backup --out` copies them
  wherever the developer wants.
- **`lonca push` is the other backup.** It sends trunk, the log, policy and
  proposals; the remote is a complete, CI-audited copy. A restore accepts
  it as a source. The bundle exists for the offline case and for what was
  never pushed.
- **`repo.restore`** (`lonca restore <name> --from <bundle|dir|url>`)
  creates `repos/<name>.git`, fetches `refs/heads/*` and `refs/lonca/*`
  from the source, and opens the store like any other at startup: the
  chain must verify, every key switch must replay, the symbol engine
  must be known. If anything fails the directory is removed. Then
  `reconcile()` puts trunk and policy where the log says; a copy taken
  between appending an entry and applying it is repaired that way,
  without an `import.unmediated` entry, because the found trunk is in the
  log's history.
- **A restore never replaces a repository.** Not an initialised one, not a
  foreign one, not a prepared one, not a directory that merely exists.
  The log is append-only, and a restore over a longer log would be the
  rewrite the auditor and the remote anchor exist to catch. The human
  moves the old store away as the daemon's user; the tooling does not
  delete stores.
- **The name is the log's.** `repo.init` records the name and human
  signatures bind it (`intent_bytes(repo, ...)`), so a store restored under
  another name could not accept any human operation. The restore refuses
  the mismatch and names the right name.
- **Keys do not travel with the data.** A restore into the daemon that
  made the backup (same `daemon.key`) is live at once. Into another
  daemon it comes back foreign and waits for `daemon.recover`, signed by
  an enrolled human: the switch is in the log for every auditor. The
  daemon key is therefore not part of a backup, and a lost key is not a
  lost repository. Human keys are the human's (`~/.config/lonca/humans`);
  a Secure Enclave key can not be backed up, which is what the recovery
  key is for ("Human keys").
- **Not restored:** session token hashes (the sessions in the log stay
  active until they expire or are revoked, but nobody holds their tokens;
  `daemon.recover` ends them anyway), freeze flags (run the auditor
  again), scratch and workspaces.
- **Not done:** scheduled backups (a launchd/cron line calling
  `lonca backup` is enough), pruning of the backups directory, and a
  bundle reader in `lonca-audit` (the auditor stays free of the `git`
  binary; verify a bundle by fetching it into a bare store first).

## Daemon authentication

Who may connect is decided by the socket (its mode, group and the uid
list). That tells the daemon nothing about who is calling: in both modes
agents run as the developer's uid. So every method now names the
credential it needs, the dispatcher checks it before the handler runs,
and a method that is not in the table does not exist (issue #51, OWASP
A01/A07, zero trust: every request authenticated).

| Method | Credential | What it does |
|---|---|---|
| `ping` | public | version and daemon key |
| `human.login` | login | opens a human session from a presence signature |
| `human.logout` | public | ends the human session whose token it carries |
| `whoami` | any | who the token is |
| `repo.list` | any human | the repositories the session is enrolled in |
| `repo.prepare_init` | bootstrap | writes the genesis objects; may `git fetch` |
| `repo.init` | bootstrap | submits the signed genesis |
| `repo.restore` | bootstrap | fetches a backup into a new store |
| `repo.backup` | human | writes a bundle of the repository |
| `daemon.prepare_rotate` | any human | creates the next daemon key |
| `status` | read | repository state |
| `log` | read | the operation log |
| `tree` | read | files of a commit, sizes; contents on request |
| `blobs` | read | one page of file contents of a commit |
| `change.get` | read | one change record, with the evidence of its last integration |
| `change.diff` | read | the unified diff of a change, redaction applied |
| `trunk.bundle` | read | a Git bundle of trunk for a checkout, thin against what it has |
| `trunk.distance` | read | how far a former trunk commit is behind |
| `human.prepare_change` | human | builds a commit for a human change |
| `human.prepare_policy` | human | writes a policy commit |
| `human.prepare_import` | human | `git fetch` from a remote |
| `human.prepare_push` | human | the push operation to sign |
| `human.submit` | human | a signed human operation; `human.recover` alone needs no session |
| `lease.acquire` | agent | |
| `lease.release` | agent | |
| `lease.renew` | agent | |
| `change.propose` | agent | |
| `change.withdraw` | agent | |
| `facts.preview` | agent | |
| `negotiate` | agent | |
| `cap.attenuate` | agent | |
| `session.end` | agent | |
| `hook.event` | agent | |
| `hook.bind` | agent | |
| `queue.run` | any human | drains every merge queue now |

Credentials, from `Cred` in `service.rs` (the table above is checked
against it by a test):

- **public**: nothing.
- **login**: a presence signature inside the request.
- **agent**: an agent session token; the repository is the token's, and a
  `repo` on the request that names another one is refused (`forbidden`).
- **human**: a human session whose key is enrolled in the request's
  repository.
- **any human**: a human session enrolled in at least one repository.
- **bootstrap**: *any human*, or no credential while the daemon serves no
  repository. The first `lonca init` (or `lonca restore` on a new
  machine) has no key to be checked against; the socket is the only
  guard then, as it was for everything before. Once one repository
  exists, creating another needs a human enrolled somewhere, and a new
  human is enrolled by an existing one (`lonca human enroll`).
- **read**: *agent* (for the token's repository) or *human*.
- **any**: any live token.

Without a token: `unauthenticated`. With a token of the wrong kind, for
another repository, or for a human the repository does not know:
`forbidden`. Unknown, ended and expired tokens: `unauthenticated`.

- **Human sessions.** `human.login` carries a signature over a
  `LoginIntent` (its own purpose string, so a login signature can not
  pass as an operation signature or the other way round, plus the
  human's name, the session length, a nonce and the time). The daemon
  verifies it with the key the named repository holds for that human;
  without a repository, with every key the daemon's repositories hold
  for the name. Freshness is checked like any human signature (ten
  minutes, one minute of skew), and a nonce opens one session. The
  session is tied to the *key*, not to a repository: it is accepted
  wherever that key is enrolled, and a rotation, revocation or recovery
  ends it everywhere at once, because the check is made against the
  current state on every request. Default length one hour, at most 24
  (`--ttl`). The token is returned once; the daemon stores its SHA-256
  like an agent token, and never logs it. Logins are not entries of the
  operation log: a session writes nothing, every write still needs a
  signature over the operation, and the human of the session must be
  the signer (`forbidden` otherwise), so a session can not be used to
  submit someone else's signed operation. One exception: a
  `human.recover` submission needs no session, because the key that
  would open one is the key that was lost; its recovery-key signature is
  the credential, checked by `decide()` like any other.
- **Interrupted key changes.** A rotation or recovery that stopped
  halfway leaves the new key waiting next to the current one; some
  repositories already know only the new key. The CLI therefore signs in
  with the current key and, if that fails, with the waiting one.
- **Agent reads go through the agent's token.** `status`, `log`, `tree`
  and `change.get` answer an agent only for its own repository. Leaving
  the token out no longer reads anything. The reads are still not
  logged; making them observations (design §5.10) is left for the
  provenance work.
- **CLI.** `lonca human login [--repo] [--ttl]` opens a session and keeps
  the token in `~/.config/lonca/humans/<name>.session` (0600); every
  human command logs in by itself when there is no session or the
  daemon refuses the one it has, so a file key never prompts and a
  Secure Enclave key prompts once per session rather than once per
  `lonca status`. `lonca human logout` ends it. The file is readable by
  anything running as the developer, agents included: that is why the
  session is short, and why it can only read, prepare and run the queue,
  never sign.
- **Not done:** a separate human socket in hardened mode (the issue's
  optional point), logged reads, and a sweep of expired sessions beyond
  the one done at each login (#53).

## Runner-facing protocol

A runner (imece first) talks to the daemon over the socket and must not
read Lonca's crates to learn the shapes. `docs/protocol.md` is the
contract (issue #76): the wire format, every method with its credential,
params, result and error codes, the reason codes a runner acts on. A
test keeps its method list equal to `METHODS` and its stated number
equal to `PROTOCOL`.

- **Protocol number** in `ping`. It goes up when a client must know:
  a field removed or renamed, a type or error code changed, a method
  removed. Additions do not move it, so a client written against
  number N keeps working on every later daemon that still answers N,
  and the document's last section says what each number changed.
- **`status` fills a review list.** A pending entry names the change,
  its base, intent, agent, task, when it was proposed and the files it
  touches; a change entry carries its base, time, version and files.
  All of it comes from state the log replays (`Pending.time_ms`,
  `ChangeRecord.created_ms` are the entry times), nothing is read from
  the store, and the reads stay unlogged.
- **`log` waits.** `wait_ms` holds a `log` request with nothing past
  `from` until an entry arrives or the time runs out (30 s cap). The
  request waits on a condition variable, not on the daemon's lock:
  every path that appends signals it, and the waiter also re-checks
  every 250 ms, so a signal missed by a future path costs a quarter
  second, never the entry. One open request replaces a timer.
- **CLI for runners (#77).** The commands a runner drives take `--json`
  and print one object on stdout, the same facts the prose has; exit
  codes tell the daemon's refusal (1) from an unreachable daemon (2)
  and from client-side failures (3, including usage, which clap would
  have reported as 2). A denied decision is an error for the CLI
  (`denied: <reasons>`, exit 1) on the runner-driven commands
  (`propose`, `approve`, `session start|end`), while the key-management
  commands keep collecting denials per repository as before. The human
  session file is documented as an interface, since a runner that talks
  to the socket directly reuses it. No token in any output.

## A git checkout as the human client

With Lonca underneath imece, trunk lives in the store and the person's
git checkout, where they commit, run their IDE and push to GitHub,
becomes a client of it (#83). Before, a checkout could follow trunk only
by fetching from the store directly, impossible in hardened mode and
blind to redaction, and a commit made there had no path into Lonca.

- **`lonca fetch`** brings trunk into the checkout as `refs/lonca/trunk`
  through the daemon: `trunk.bundle` makes a Git bundle of
  `refs/heads/main`, thin against the commits the checkout says it has
  (`refs/lonca/trunk` and `HEAD`, when they are in the store), and the
  client runs `git fetch <bundle>`. The person merges or resets as with
  any remote. The bundle must fit one page; after an `init --import`
  from the same checkout the first fetch is already thin. A bundle
  carries whole objects, so when a redacted blob is among what it would
  carry the daemon refuses (`redacted`, with the paths) and the person
  works from a workspace: redaction and a git checkout do not mix.
  A git remote helper (`git-remote-lonca`) was considered and left for
  later: the bundle needs nothing installed on the git side.
- **`lonca propose --commit REV`** from a checkout proposes everything
  the commit changes against its merge base with the last fetched trunk
  as a human change (`human.prepare_change` with the files, `human.submit`
  with the signature; the base is a commit that was trunk, so a stale
  base merges structurally in the queue like any proposal). Several
  commits ahead of trunk are one proposal; the intent defaults to the
  commit's subject. Symlinks and submodules are refused.
- **`trunk.distance`** says how many integrations lie between a commit
  that once was trunk and trunk now (`State.trunk_line`, every trunk
  commit in order, replayed from the log), so a client shows `↓N` without
  walking the log; `lonca fetch` prints it for the previous
  `refs/lonca/trunk`.
- The checkout remembers its repository in git config (`lonca.repo`),
  set by the first `--repo`. `docs/guide/humans.md` describes the human's
  two modes: a Lonca workspace, or a git checkout with `fetch` and
  `propose --commit`.

## Verification environment

The verifier cleared the environment except `PATH`, so `cargo` under
rustup failed in 25 ms and the only way to verify a Rust crate was to
write the developer's home paths into the signed policy (#82). Now
`[verification] env_passthrough` names variables copied from the
daemon's environment at run time and `env` sets fixed values; both are
policy data, signed, deny by default. Names that change what runs or
where code is loaded from (`PATH`, `LD_PRELOAD`, `DYLD_*`,
`RUSTC_WRAPPER`, `RUSTFLAGS`, `NODE_OPTIONS`, `PYTHONPATH`, `GIT_*`,
`LONCA_*`, …; `FORBIDDEN_ENV` in `config.rs`) are refused at policy
load (`env_forbidden:NAME`), and the verifier skips them again if a
policy object ever carries one. The sandbox profile is unchanged. The
log of every check starts with the sandbox and the names that were
set, never a value. `docs/guide/verification.md` has the environment
and a starter block per language. Not done: the hardened profile
pinning the list (#54), resource limits (#59).

## Reject, and a pending proposal whose session ends

The only human decision on an escalated operation was `approve`; a
declined proposal stayed pending for good, held its leases and kept
appearing in every review list (#81).

- **`reject { target_seq, reason }`** is a human operation like
  `approve`, signed and logged, never agent-grantable, escalatable by
  policy like any other. It needs a pending target (`nothing_pending`)
  and a reason, 1 to 4096 bytes (`reason_required`,
  `reason_too_long`). Effect: the operation leaves the pending set; a
  proposal becomes `rejected` with `rejected: <reason>` as its reason,
  leaves the queue, and the lease sets of its session that cover a
  symbol it changed are released, so the symbols are free for the next
  attempt, by that session or another. The reason is data for the
  requester (`change.get`, the MCP `change_status` tool, `lonca
  pending`); Lonca never interprets it. `lonca reject SEQ --reason …`.
- **A pending proposal outlives its session's expiry.** The commit is
  in the store and the session is only its provenance, so a proposal
  escalated before the session expired stays in the pending set and an
  approval after the expiry still releases and integrates it (the
  session's level and taint at proposal time are what the decision
  recorded). The same holds for a session its agent *ended*
  (`session.end`): the work is done and waits for the human. A session
  a human *revoked* (`cap.revoke`, or a key change that ends everything
  the human set in motion) withdraws its pending and queued proposals,
  as before: a revocation is a decision about the work, expiry and a
  normal end are not. `status.pending` carries `agent` and `task`, and
  `status.sessions[].active` says whether the proposer is still around.

## Diff and evidence through the daemon

A reviewer needs the diff and the verification evidence of a pending
proposal; until #80 both came from the store with the reviewer's own
git, which hardened mode denies and which bypassed redaction.
`change.diff` runs git in the store between the change's base and
commit (the daemon already uses the git binary for fetch, push and
bundles; the trusted core does not), leaves out and names every file
whose blob on either side is redacted, adds per-file counts and the
symbol facts by file, and caps the text (2 MiB, `truncated`).
`change.get` carries `evidence`: the checks of the change's last
`change.integrate` entry with result, exit, duration, sandbox and the
tail of the log blob (32 KiB), redacted blobs left out, found by
reading the log back (one scan per call; the change record does not
yet remember the entry). Both are reads and are not logged; `lonca diff
CHANGE` and `lonca change CHANGE --evidence` print them, and the MCP
`change_status` tool shows a worker its own failed build log.

## Tree paging

A workspace was one `tree` call with every file's content in one JSON
line, so a repository whose tracked bytes exceed the line cap (96 MiB)
could be imported but never worked on (#79). Now `tree` returns the
manifest with sizes, and `blobs` returns the contents of named files of
one commit as a page; the client sizes pages from the manifest to stay
under the page budget (three quarters of the line cap, encoded). A page
never mixes commits: `blobs` names the commit and refuses a path that is
not in its tree. A file that alone does not fit a page is refused by
name (`too_large`), as is a page that would overflow; the client refuses
the file before asking. `repo.prepare_init` reports files above the
change cap (`changes.max_file_bytes` of the default policy) and a tree
above one page, and `lonca init` prints them as warnings, so the limit
is met at import, not at the first session. Not done: a per-file cap on
import, and a "not materialised" class of paths (Git LFS style), which
is what a repository with large media needs; the warning names the
files to move out.

## Scratch roots and taint policy

A runner's worker keeps notes, logs and throwaway files outside its
workspace (imece: `--add-dir` to a scratch directory) and reads the web
and its own MCP tools. Before #78 the first was denied and the second
tainted the session for good, closing every critical path to it.

- **Scratch roots** are part of the session's scope
  (`session start --scratch DIR`, repeatable; `Scope.scratch`, log
  format 5), so the auditor sees them and a child session can keep or
  drop them, never add one (`scope_widening:scratch:…`). A root is an
  absolute, normalized directory, at most eight per session
  (`scope_invalid:scratch:…`). The hook translation checks the workspace
  first, so a root inside the workspace exempts nothing; the CLI refuses
  one that overlaps the workspace. Under a root, writes are allowed and
  not observed (they are not facts and can not be proposed: proposals
  come from the workspace tree), reads are observed and not external.
  The hook program names the roots in its SessionStart text, taking them
  from the daemon's `hook.bind` answer, never from a file in the
  workspace, which an agent could edit; shell commands that mention
  `.lonca/` are denied for the same reason.
- **What taints is policy data.** `[taint]` in `lonca.toml`: `fetch`
  (web fetches and searches), `shell_network` (curl, ssh, git fetch,
  …), `mcp_servers` (an allow-list of servers whose tools do not
  taint; every other server's tools do; Lonca's own never do). Defaults
  keep the old behaviour. Reads of untrusted paths and of files outside
  the workspace and the roots always taint. The daemon's hook
  translation reads the policy when it sets `external` on an
  observation; `decide()` sees only the result and stays pure. A policy
  update that turns taint off does not clean a session already tainted.
- **The runner document** `docs/guide/runners.md` says what a runner
  installs and runs: the hooks block, the MCP entry, the environment,
  how the hook finds the workspace, what SessionStart injects, and what
  to do when a worker ends.

## Mutation testing

Passing tests do not show that they would catch a flipped `>=` or a
`decide()` arm replaced with `Ok(Allow)`. Mutation testing measures that.

- **Tool: cargo-mutants** (27.1.0, pinned with `--locked` and an explicit
  version). It needs no code changes or annotations, reads
  `.cargo/mutants.toml`, and supports `--in-diff` for PRs and `--shard` for
  splitting a full run.
- **Whole-workspace tests per mutant** (`test_workspace = true`). Much of
  the safety-critical code is tested from other crates: `lonca-audit` only
  from `lonca-daemon/tests/audit.rs`, `chain.rs`/`state.rs` mainly from
  `lonca-policy/tests/decide.rs`, `lonca-core` from everything above it.
  Per-package testing would report those as survivors. A workspace test
  run is about 10 s, so the cost is acceptable. cargo-mutants has no
  per-crate test list, so this is one setting for all crates.
- **Timeouts** come from the measured baseline: `timeout_multiplier = 5`,
  `minimum_test_timeout = 60` s. A mutant that hangs the daemon or a
  socket test ends as a timeout, which counts as caught.
- **Exclusion policy.** `exclude_re` lists only mutants shown to be
  equivalent (no test could tell them apart from the original) or
  irrelevant (text that no caller reads), each with a comment giving the
  reason. Nothing in `decide.rs`, `chain.rs`, `state.rs`, `oplog.rs`,
  `canonical.rs`, `changeid.rs` or `keys.rs` is excluded without review.
  A surviving mutant is otherwise killed with a test. "Hard to test" is
  not a reason to exclude.
- **Tests are hermetic under mutation.** cargo-mutants runs copies of the
  tree in parallel. Tests use their own temp dirs, `127.0.0.1:0` ports and
  short socket paths; the CLI tests point `HOME` and `LONCA_HOME` into
  their temp dir and drop the developer's `ANTHROPIC_*` variables, so a
  mutant cannot write to the real home or reach the real API.
- **Not nextest.** Not installed by default and not needed for speed:
  the workspace test run is dominated by two ~1.3 s binaries.

## Open questions (carried from the design)

- Team server: one sequencer per repository works for one machine; a
  shared server needs remote authentication and per-user rate limits.
- Redaction in published history.
- Precise caller analysis for signature changes (LSP or compiler).
- Running the base test suite against changed tests ("test integrity"
  currently escalates deleted or skipped tests; it does not rerun suites).
- Harness levels for agents other than Claude Code (Codex, Cursor, ...).
- Whether `sudo -n true` reuses a credential cache from the agent's shell
  (to be measured on a real install).
