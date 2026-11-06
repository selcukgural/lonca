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
  named `Type.method`, so a lease on `Type` covers every method. The block's
  own text belongs to `Type.<def>` from engine 3 (see "Symbol engine
  versions").
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
- **Version 7** changes what entries mean for leases and adds nothing to
  them: a proposal pins its leases, and every entry prunes dead lease
  sets (see "Pinned leases"). Entries of older formats do neither, so an
  old log replays to the state and the decisions it always had.
- **Version 8** again adds no field: a heartbeat keeps a session's leases
  alive and its absence ends them, a denied acquire registers interest,
  and a renewal has a hold limit (see "Lease liveness").
- **Version 9** adds `continues` on `session.start` (see "Continuing a
  session"). The field is left out of the encoding when empty, so every
  earlier entry keeps its bytes; an entry that names a session needs
  format 9.
- **Version 10** adds `lease.interest`, `to` on a yield and `leases` on
  `cap.attenuate` (see "The lease queue"). The fields are left out of the
  encoding when empty.
- **Version 11** adds the `unproposed` observation (see "Stopping with
  unproposed work").
- **Version 12** adds no field: a lease or an interest needs an intent, and
  a waiting interest stops new leases that conflict with it (see "The lease
  queue"). Older entries need no intent and their interests stop nobody.
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
- **Engine 1** adds sections for Markdown, TOML, JSON and YAML (see
  "Sections of files without a grammar"). For everything else its output is
  engine 0's, and `tests/engine/v1/` holds the same cases with the same
  snapshots to prove it.
- **Engine 2** compares code exactly. Up to engine 1, the code outside
  symbols, the own text of containers and the imports were compared as
  text with whitespace collapsed, and a symbol's position was not compared
  at all. From engine 2:
  - Code outside symbols and a container's own text are compared as the
    tree-sitter tree with the text of its tokens
    (`extract.rs`, `exact_text`). Layout does not count. Indentation that
    means something is in the tree, and whitespace inside strings and
    comments is in the token. This needs nothing per language, so a new
    grammar gets it for free.
  - Symbols or imports that change order are edits: order can matter, and
    a merge in place can not express it. The merge leaves such a file to
    the line merge, where it merges or is `<file>` in `conflicts`.
  - A symbol merge that brought nothing of `theirs` into a file that
    differs goes to the line merge too. So a change only of layout between
    symbols is applied, not dropped, or reported as a conflict.
- **Engine 3** tells a type's definition from its members (issue #41). Up
  to engine 2, changing a struct's fields or a class header took a lease on
  `Type`, which covers every method and refuses every `insert` on the type,
  so one agent on a field stopped all the others. Besides, a lease on
  `impl:Type` overlapped nothing named `Type.method`, and the merge then
  refused what the leases had allowed, but only when the header was the
  later of the two changes.
  - `Type.<def>` is the type's own text: the header, fields, decorators,
    class-level statements and, for Rust, every `impl` header of the type.
    Containers have one, and so do declarations whose members stand beside
    them, like a Rust `struct` or a Go `type` (`TYPE_KINDS` in `extract.rs`).
    `Type` itself keeps its meaning, the whole type, and covers `Type.<def>`.
  - **No new log format, and leases are decided as before.** By name
    `Type.<def>` is already a member of `Type`, so `covers` and
    `leases_conflict` give the right answer as they stand: it overlaps
    neither `Type.method` nor `insert Type`. Only the facts changed, and they
    are recorded with their engine. `impl:Type` stays out of the hierarchy,
    because changing `ancestors` would change old decisions in a replay.
  - **One name for one change.** `Sym::changed_unit` is what facts report
    and what the merge conflicts on, so they can not drift apart.
    `crates/lonca-daemon/tests/type_defs.rs` holds them together for every
    two changes in five languages: what the merge refuses, the leases have
    refused first, and what can be held at once merges into both changes.
    The reverse does not hold on purpose: a struct and an `impl` header are
    one unit for a lease, and the merge could take them apart.
  - **The merge does not depend on the order of the queue.** A container
    changed on both sides takes `t`'s own text when `o`'s is unchanged, by
    running the same walk the other way round and replacing the container.
    Own text changed the same way on both sides is no conflict. Own text
    changed two ways is a conflict on `Type.<def>`, and the members still
    merge, so a sync brings in everything else.
  - **An `impl` taken out** has no lease that reaches its members, so facts
    report its members as deletes and `Type` as an edit, instead of a delete
    of `impl:Type`.
  - **An addition must come through.** Where a new member goes in a
    container with no member to stand beside is found in the text, and a
    string or a comment can fool it while the file still parses. So from
    engine 3 a symbol merge whose result lacks a symbol either side added
    goes to the line merge, and in a sync the file stays local.
  - **Layout of the container comes from `t`** when the walk runs the other
    way round: blank lines or line endings that `o` changed around its
    members are not kept, as for any text the comparison calls layout.
  - **A moved `impl` is its type**, for the same reason as one taken out.
    Moves go to the line merge, which can still conflict on nearby lines.
  - **Scopes.** Facts of engine 3 and later check `Type.<def>` as `Type`, and
    the literal name also matches. `Type` reaches it, which from this engine
    includes the `impl` headers that used to be `impl:Type`. `Type.*`, the
    members, did not reach the type's own text and still does not. This takes
    `symbols_engine` as an input of `decide()`, because before engine 3
    `T.<def>` in facts can only be a document section called `<def>`, and
    old entries must replay as decided. A lease request has no engine and is
    checked as it always was: a session scoped to exactly `Type` leases
    `Type`, the whole type.

- **Engine 4** compares where code stands among symbols. `exact_text` leaves
  symbols out, so code that changed places with a symbol read the same on
  both sides, though order can matter between statements as much as between
  symbols.
  - `exact_text` notes where each symbol and import stood (`Spot`), and
    `shifted` compares each piece of code with the names in front of it,
    counting only names both sides have. So adding or removing a symbol moves
    nothing, and two symbols side by side that swap are engine 2's rule, not
    this one's. This needs nothing per language.
  - Imports are named by their order, not their text, so a changed import
    or a repeated one is still a place.
  - Facts report such a change as an edit of `<module>`, or of `Type.<def>`
    inside a container, so it needs the lease of that code.
  - **A move is a change of that code.** Moved on one side with the code
    untouched on the other, it goes to the line merge, where it merges or is
    `<file>` in `conflicts`. Moved on one side and changed or moved otherwise
    on the other, it is a conflict on `<module>` or `Type.<def>`: the line
    merge sees a move as a deletion and an insertion, so it would bring back
    what `o` deleted or write the statement twice. A sync leaves such a file
    local.
  - **A symbol merge and a line merge are held to one check** (`holds_up` in
    `merge.rs`): the result has what the sides added and not what they
    deleted, and each side's code stands where that side put it among its
    symbols. Failing it, a symbol merge goes to the line merge, and a line
    merge is `<file>` in `conflicts`. So a text insert in the wrong place can
    not pass for a merge because the file still parses.
  - A new symbol goes beside the code it stood next to: behind `app = Flask()`
    if that is where its side put it, not after the symbol before that.
  - **What this does not see.** A symbol renamed while code moves past it is
    no anchor in the facts, so the move is not reported, though the merge
    keeps it; and adding a duplicate renumbers `name~2`, which reads as a
    move. Both wait for stable ids (#44), and the second only costs a lease.

- **Engine 5** reads declarations that hold others (issue #47). Up to engine
  4 such code was one symbol or none: an edit of `Y` in a Go `const (...)` was
  an edit of `X`, and a function under `if TYPE_CHECKING:` could only be
  changed under a lease on `<module>`. `parse_at` takes the engine, and
  `parse` is the current one.
  - **What became symbols.** One per spec in a Go group with parentheses, one
    per declarator in a C# field with several, what stands in a Rust
    `extern` block, a Rust macro call at item level (`m!`, then `m!~2`),
    `exports.X =` and `module.exports.X =`, the methods and function-valued
    keys of `module.exports = { … }`. A declaration without parentheses, or
    with one declarator, stays whole. A Go spec with several names
    (`const X, Y = 1, 2`) is named after the first, and `const o = { a() {} }`
    stays one leaf: only an object that is exported lists symbols.
  - **Python blocks.** A top-level `if` or `try` whose blocks hold nothing but
    definitions, a comment or `pass`, with at least one definition, gives
    symbols named as if they stood at the top level. Anything else in any of
    its blocks, an import or a nested block included, and it stays code. This
    is on purpose narrow: an import has one place in the merge, and a block
    with statements can not be told apart from what they do. The same name in
    two branches is `f` and `f~2`.
  - **A symbol knows what holds it** (`Sym.holder`). The merge places a new
    symbol only beside one of its own holder, on a side where that one stands
    in the same kind of holder, and a holder's edge counts as code between
    neighbours. Nothing to stand beside goes to the line merge. Without this a
    new function behind a Go group could land inside it, and one for `else:`
    in the `if` branch. It also fixes C# namespaces, where a new class could
    land in the namespace before it. The same definition added to two blocks
    is a conflict, not one addition.
  - **Separators go with the member.** A list with commas (`Holder.joined`) has
    its commas left out of `exact_text`, so a member added or removed is no
    change of `Type.<def>` or `<module>`. So a change of only a trailing comma
    has no facts, like any layout. The merge adds the separator the new member
    has in `t` and removes one with a deleted member. Both are measured to the
    next element of the list in the tree (`Sym.around`), not the next symbol:
    `VERSION: 1` between two methods is no separator. A member that stops being
    in a list, as in `int a, b;` to `int a;`, is a change of shape and of the
    code around it.
  - **A symbol merge writes code of one side or the other** (`holds_up`). The
    code outside symbols and every container's own text must equal `o`'s or
    `t`'s, and no merge, by lines either, may bring a name neither side has.
    Failing it, a symbol merge goes to the line merge, and a line merge is
    `<file>` in `conflicts`. So a text operation in the wrong place can not
    drop or copy code that nobody touched. Two parts of a partial type each
    getting a member `x` are caught this way.
  - **Numbers in blocks.** `f~2` counts from the top of the file, so when code
    moved in a file with a numbered name in a block, the name may mean another
    definition. Such a file goes to the line merge.
  - **A holder stays in the compared code.** A block with one member has that
    member's span, and `exact_text` used to cut it with the member, so a second
    member changed the code around it. So adding a method to a Python class
    with one method was a `Type.<def>` edit. From this engine it is an add.
  - **Comments.** A comment attaches only when no blank line stands under it.
    Otherwise it is code: `<module>`, or `Type.<def>` in a type. A licence or
    section header is no longer the next symbol's. An attribute or a decorator
    attaches across a blank line, because it is part of what follows, also
    with a comment that stands apart behind it. A comment behind code on its
    line is never about what follows: it belongs to a leaf symbol that ends
    there, and otherwise it is code. In a list with separators the comma stands
    between, so it is code there too.
  - **TS method decorators** attach to the method, as a field's already did.
  - **C# partial types.** A later `partial` part of a type in the same file
    keeps its own name (`C~2`) but works like a Rust `impl`: its members are
    `C.N`, overloads across parts get one id each, and its header is
    `C.<def>`. Parts in other files stay unrelated, because a symbol id is per
    file, and so do parts in two namespaces, which are two types. A new part
    is an add of `C~2`, as a new `impl` is an add of `impl:C`.
  - **What this does not see.** A const in a Go `iota` group means what its
    place says, so a spec added in the middle changes the ones after it with
    no fact about them; verification catches that, as for any change between
    symbols (design §5.8). Names by order (`f~2`, `m!~2`) wait for #44.
    Deleting the last two members of a list, or a member between what `o`
    changed on one line, is refused by the line merge though the leases allow
    it: nothing is lost, and such a change goes back to the agent.

## Harness profiles

Which harnesses Lonca can read is data, not code (issue #109). A profile
says what a harness calls its events, where the parts of an event are, what
its tools do and how it wants an answer. Three come with Lonca
(`crates/lonca-policy/src/harnesses.toml`); `[harnesses.<name>]` in
`lonca.toml` adds or replaces one.

- **In the signed policy, read by the daemon.** What a tool counts as decides
  what taints a session, so it can not come from a file an agent can write,
  or from the hook program's environment. `hook.input` takes the raw event
  and the daemon does the reading, so a root-owned hook program stays the
  same for every harness.
- **Replay does not need them.** Observations are logged as they were made;
  a profile changes what future events mean, like `[taint]`.
- **What stays out of reach of a profile:** a harness that can not run a
  command before a tool call can not be observed at all. It still works
  through `lonca mcp` or the CLI, unobserved. How far a harness can be locked
  (managed settings, sandbox) is checked per harness and exists for Claude
  Code only; that is issue #21.

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

## Stopping with unproposed work

Nothing reaches the repository until an agent proposes it, and an agent can
stop first: seen live with Codex and with OpenCode, where the person who
started it read "done" and the work stayed in the workspace (issue #121).

- **The stop event is data.** `events.stop` and `stop_deny` in a profile, both
  or neither. A harness with no such event is unchanged, and `lonca session
  end` still records what was left.
- **The client reports, the daemon compares.** Only the client sees the
  workspace, so `hook.stop` sends `(path, mode, blob)` of each local change,
  and the daemon checks them against the commits of the session's standing
  proposals. A changed file stays a local change until `sync`, so "there are
  local changes" would not do. A proposal of the session it continues counts,
  another session's does not, and a rejected, withdrawn or conflicted change
  delivered nothing.
- **In the log, as an observation.** `status` must tell "stopped" from "done"
  after a restart, so the mark comes from the fold, like everything else
  `status` says. A report is written only when it says something new, so an
  agent that stops for ever can not fill the log.
- **The count is of stops without progress.** A proposal that stands clears
  it, because a long session may stop many times and deliver each time. A
  denied proposal does not, so an agent that can not propose still ends.
- **A failure ends the turn.** Tool hooks fail closed; this one must not. A
  harness reads exit status 2 on its stop event as "go on", so a daemon that
  is down would keep an agent going with nobody counting. Stop hooks run
  with `--fail-open`, and nothing depends on them: this is a reminder, not a
  control. The agent's own hooks can be skipped, so the absence of a mark
  proves nothing; a proposal is the only evidence of delivery.
- **A proposal that a sync merged is reported.** After `sync` a file holds
  the merge, which differs from the pending proposal, so the agent is told
  to propose again. It costs a round, and #107 makes the new proposal
  replace the old one.

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
| `lease.interest` | agent | |
| `events` | agent | |
| `inbox` | agent | |
| `change.propose` | agent | |
| `change.withdraw` | agent | |
| `facts.preview` | agent | |
| `negotiate` | agent | |
| `cap.attenuate` | agent | |
| `session.end` | agent | |
| `session.heartbeat` | agent | |
| `hook.event` | agent | |
| `hook.input` | agent | |
| `hook.bind` | agent | |
| `hook.stop` | agent | |
| `harness.setup` | agent | |
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

## Pinned leases

A lease was checked when a change was proposed and forgotten after that
(#38). A proposal escalated to a human outlived its TTL, the next agent
leased the same symbol and did work that was certain to conflict; and
integration released nothing, so symbols stayed blocked until the TTL
ran out.

- **Pin.** A proposal that is allowed or escalated pins the items of its
  session that its facts need (the same rule as `lease_missing`:
  `symbols::lease_needs`) to the change. A pinned item does not expire,
  survives the end or expiry of its session, can not be released or
  yielded by its holder, and conflicts for every other session. Its
  holder still holds it, so it can propose on top of its own change. The
  rest of the set keeps its TTL. `status.leases[].pinned` shows pins.
- **Unpin.** When the change leaves the queue: integrated, conflicted,
  rejected, failed verification, withdrawn. A revocation (`cap.revoke`,
  a human's key change) drops the sets, pins included, because it
  withdraws the work; `session.end` and a daemon recovery leave the work
  standing, so the pins stay with it. A change that conflicted or failed
  verification, or was withdrawn, gives the item back to the TTL of its
  set: the holder may sync and propose again if the set is alive, and
  past the TTL the item is free. A human's `reject` also releases the
  sets that cover what the change touched, as before.
- **`leases.release_on_integrate`** (default `true`): integration
  releases the pinned items. With `false` they go back to the TTL of
  their set. `State::apply` has no policy, so the switch is carried in
  the decision (`leases_kept`), like `approvals=N`, and the auditor
  recomputes it. An item that another change of the session still needs
  stays pinned to that one.
- **Pruning.** Every entry from format 7 on first removes the lease sets
  that are dead at its time: expired or with a dead session. Only the
  pinned items of such a set stay, until their change leaves. Pruning
  runs before the entry's own effects and uses only the entry's time.
  One effect: a renew of an expired set is usually `unknown_lease_set`
  rather than `lease_expired`, and a set id is free again once pruned.
- **Why a format version.** No field changed, but pins and pruning
  change later decisions: an old log in which a second session leased a
  symbol under a change in flight must still replay as allowed. Pins and
  pruning apply to entries of format 7 and later. A change proposed
  before the upgrade stays unpinned.
- **A worker's view.** After its change integrates a worker leases again
  before editing the same symbols; a `lease_release` on a set that was
  released this way answers `unknown_lease_set`.

## Lease liveness

The design says a lease is freed when its holder drops, but nothing
measured that: an agent that crashed kept its symbols for the TTL, MCP
agents could not renew at all, and renewing had no limit (#39).

- **Heartbeats are log entries.** `session.heartbeat` writes an `observe`
  entry with `ObsKind::Heartbeat`; `decide()` adds
  `heartbeat_timeout=<ms>` to its decision, and `State::apply` records
  when and for how long. The policy value is in the decision because the
  fold has no policy; the auditor recomputes it, like `approvals=N`. Both
  times are entry times, so liveness replays.
- **A session that started beating must go on.** Its leases are alive
  only while `now - seen <= timeout`. A session with no heartbeat yet
  lives by the TTL as before, so a hook-only worker needs nothing new.
- **A lost lease stays lost.** The prune at the start of every entry
  removes a lost session's sets before the entry's own effect, so a late
  heartbeat records the session and revives nothing. Otherwise a session
  that came back would hold a symbol someone else took in the meantime.
- **`lonca mcp` beats and renews.** A thread on its own connection beats
  every `timeout / 3` and renews sets that would not outlast two more
  beats. The process ends when the harness closes stdin, which is what
  makes a crashed agent's leases free: the signal is the harness, not
  the model, so a long turn holds its leases and a dead one does not.
  The `lease_renew` tool is there for a longer TTL.
  `lonca session heartbeat` serves a runner that does not use `lonca mcp`.
- **Pins win.** A pinned item ignores the timeout: the work is in the
  queue, whoever proposed it.
- **Hold limit.** `leases.max_hold_minutes` (default 120) limits what
  renewing can do, not what a lease is: past it a renewal is denied with
  `lease_hold_limit`, but only while another session wants the set, and
  otherwise it is allowed. Time is counted from `acquired_ms`; a new set
  over symbols the session already holds keeps the old time, so a fresh
  id does not start the hold again.
- **Interest**, until `lease.interest` exists (#42), is a denied
  `lease.acquire`: every reason `lease_held:`, not a scope or item error,
  so a session can not hold back work it may not do. It counts for
  `leases.max_ttl_minutes` after the denial and only while the session
  that asked is active: a session still waiting asks again.
- **Why a format version.** Heartbeats, interest and the limit change
  later decisions; they apply to entries of format 8 and later. Interest
  recorded in the state stays a derived value and is never an input from
  a client.
- **Limits are positive**: `parse` refuses `heartbeat_timeout_ms` or
  `max_hold_minutes` at or below zero.

## Lease details and agent ergonomics

`lease_held:<symbol>:<session>:<intent>` can not be parsed, because the
intent is free text, and it says nothing of when the lease ends;
`lease_missing:<symbol>` does not say which kind is needed (#48).

- **Reasons stay; details are added.** `Decision::reasons` are logged and
  replayed, so they do not change. `lease.acquire` and `change.propose`
  also answer `details`, built by `crates/lonca-policy/src/details.rs`
  from the state after the decision. They are never logged and never an
  input of `decide()`, so no log format changes, and they carry session
  ids and intents, which every client may read anyway, never a token.
- **One rule.** `details::lease_report` uses `symbols::lease_needs`, the
  rule behind `lease_missing` and pinning. `facts.preview` answers it as
  `leases`, with the free ones as `acquire`, ready for `lease.acquire`.
  It adds nothing to the log: a worker can ask as often as it likes.
- **`needed_kind` is the weakest kind that will do** (`edit` for an edit,
  `insert` for an addition, `rename` for a deletion), which conflicts
  with the fewest others.
- **A pinned item has `expires_ms: null` and `pinned_to`.** There is no
  time to wait for: the client watches the change.
- **Partial release is the MCP server's**, not an operation: it acquires
  what stays under a new set for the time the old one had left, then
  releases the old one. Acquiring first means nothing is free in between
  and a refusal changes nothing. A new set over held symbols keeps the
  hold time (see "Lease liveness"). Pinned items stay in the old set.
- **MCP failures** are `{code, message, details}` as JSON text with
  `isError`: the daemon's error code, or `invalid` for what the server
  itself refused. A denied decision is not a failure: it is a logged
  result, with `decision` and `details`.

## Clients verify the daemon

The daemon checked its peer's uid; no client checked the daemon. The hook,
the MCP server and the CLI take the socket path from the environment, so any
process answering there received the session token and decided what the hook
allowed (#52, design §3.3, measure 2).

- **`Client::connect` is the only way to a client, and it checks.** Before
  connecting: the path is a socket, not a link, and belongs to the daemon's
  uid; in hardened mode its directory belongs to the daemon or root and
  nobody else can write it. After connecting and before a byte is sent:
  `getpeereid` / `SO_PEERCRED` says the daemon's uid. The peer check is the
  one that counts, because a file can change between the look and the
  connect.
- **Which uid.** The installers write `daemon_uid = N` to
  `/Library/Lonca/daemon.toml` or `/etc/lonca/daemon.toml`, root-owned, in a
  root-owned directory, writable by nobody else. No file means cooperative:
  the current uid. A file in any other state is an error, never a fallback
  to cooperative mode, or replacing it would choose the daemon.
- **Cooperative mode defends nothing here**, and says so: a fake daemon of
  the same account passes. It runs as the developer; there is no boundary
  between the two.
- **`LONCA_SOCKET` stays.** The environment is the agent's to set, and that
  is why it is not what is trusted: pointed anywhere, the peer must still
  be the daemon's uid.
- **The test seam is `LONCA_TEST_DAEMON_UID`**, read only in a debug build,
  `cfg!(debug_assertions)`. A debug build also ignores the machine's file,
  so the tests stay hermetic on a machine with a hardened install. A
  release build reads the file alone: a variable an agent can set must not
  name the daemon.
- **Failure.** Exit 2 on the CLI, as for an unreachable daemon; the hook
  blocks (fails closed). A hardened install from before this change has no
  file, so its clients expect their own uid and refuse the daemon until
  the installer runs again.
- **Not done:** comparing the daemon's public key from `ping` with the one
  pinned in `repo.init`. It is optional in the issue: the uid check already
  stops a process of another account, and the key would only add a
  defence against the daemon's own account.

## Continuing a session

A worker outlives `sessions.max_ttl_minutes` in ordinary use, with work
in its workspace, and a session can not be extended (#98). Renewing would
let one token live for ever and go against #53; a human's act at the
boundary keeps the session bounded.

- **`session.start` with `continues: {session, widen}`**, from `lonca
  session start --continue DIR`. It is a start, with its signature and
  every check of a start, and these on top: the old session is known
  (`unknown_session`), a root session (`continue_child_session`, because a
  child's scope and lifetime are its parent's), not continued before
  (`session_continued`: a workspace never has two live sessions), and the
  new scope is within the old one (`scope_widening:<what>`) unless the
  human passed `--widen`, which is in the log and in the Touch ID prompt.
  The CLI refuses a directory that is not itself a workspace, a human's
  workspace, and a workspace of another repository, before asking for a
  signature.
- **The old session ends in the same entry**, alive or not, with `continued
  by <new>`, and the daemon drops its token. The workspace's files, base,
  manifest and `submitted` stay; only `.lonca/session` and the session id
  in `workspace.json` change.
- **What is known of the files goes with them:** taint, observation level,
  `writes` and `shell_seen`. A new session on the same files must not clear
  a taint, because the workspace may hold what the tainted session wrote.
  `writes` has to come along for the edit to be proposable at all: under
  a bound session a changed file nobody saw written is
  `unobserved_write`. A later `hook.bind` sets the level as it does for
  any session, and a file an unobserved session wrote is still not in
  `writes`, so binding hooks does not launder it.
- **Leases end, pins pass on.** The old session's sets end as at any
  session end (#39: a lost lease stays lost), and `lease_needed` tells the
  worker what to lease again. What is pinned stays with its change (#38),
  but the set's holder becomes the new session. The issue left the pins
  with the old session; then the worker could not propose on top of its
  own pending change, because the diff includes that change's edits and
  every one of them would be `lease_missing`. Same reason the pin's holder
  "can propose on top of its own change".
- **`continued_from`, not `parent`.** The issue says the old session is
  recorded as `parent`, but a parent's end ends its children and
  `session_active` walks parents, so the new session would be dead on
  arrival. `continued_from` / `continued_by` record the link, and
  `status.sessions` shows both.
- **The chain is one worker's work.** The new session may withdraw what its
  predecessors proposed. `cap.revoke` of any session in the chain walks
  back through `continued_from` and withdraws the work of all of them,
  pins included: a revocation is a decision about the work, and a
  revocation of the new session must not leave the old one's change
  queued. Walking forward is not needed, because an older session's own
  in-flight work is what a revocation of it reaches.
- **A heartbeat of an inactive session** is refused `session_inactive` and
  writes nothing, so a client that does not stop can not fill the log.
  `lonca mcp` stops beating on that answer, or on `unauthenticated` (the
  token is gone), and every later tool result is `{code:
  "session_inactive", message, details: []}`. A connection failure is not
  that: the daemon may come back, and the server keeps trying.
- **If the CLI dies** between the entry and writing the token, the
  workspace keeps the old token and the continuation can not be repeated
  (`session_continued`). The window is one file write; the way out is a new
  session and a new workspace, and the log says what happened.
## Critical paths: what instructs an agent

`paths.critical` covered what runs code or defines CI. An agent-native
repository has a second kind of path: once `CLAUDE.md` or `.mcp.json` reaches
trunk, every agent reads it after its next `sync`, which is a persistent
prompt injection or a new tool server (#55). Tooling that runs on checkout,
on build or in an editor (`.cargo/config.toml`, `.envrc`, `.vscode/**`,
`.devcontainer/**`) belongs with them, and so do the runner's scripts in
`.imece/**`, which run in a worker's workspace. All of it now needs a human
approval, and a tainted session may not touch it.

- **Policy data, for new repositories.** The list is part of the default
  `lonca.toml`. An existing repository's `lonca.toml` changes only through
  a signed `policy.update`: see `docs/release-notes.md`.
- **Names, not globs.** The pattern language has `**/name`, `**/*.ext`,
  `dir/**` and exact paths, and nothing else: `**/Gemfile*` would be a
  literal that never matches, which is a critical path nobody is told is
  open. Variants are spelled out (`**/docker-compose.yml`,
  `**/docker-compose.yaml`, `**/compose.yml`, `**/compose.yaml`). Extending
  the language changes what recorded policies mean, so it would need a log
  format; `Dockerfile.prod` and `docker-compose.override.yml` stay out
  until something needs that.
- **Only a bare file name is matched at any depth** (`**/CLAUDE.md`). A
  pattern with a directory in it is from the root: `.claude/**` does not
  match `sub/.claude/x`, and `.cargo/config.toml` does not match
  `sub/.cargo/config.toml`, though Cargo reads that one. `**/.cargo/config.toml`
  would not help: it is a literal that never matches.
- **A `lonca.toml` without `critical` keeps the old list.** `Paths::default()`
  is frozen, the one default that differs from the shipped file, because a
  log is replayed under its policy: a key that silently grew would turn a
  recorded `allow` into an integrity failure when the daemon opens the
  repository. Such a repository updates its policy like any other.
- **`the_default_critical_list_does_not_shrink`** names a path for every
  family, so a pattern that is removed, or that can not match, fails.
- **`paths.untrusted` is unchanged.** Design §5.10 names imported issue text
  as an example, but nothing imports issue text yet, so there is no path
  to list. The hardened profile (#54) starts from this list.

## Setting up a harness

`lonca harness setup <name>` and `session start --harness` do what the
profile's `setup` says: files to write, or flags and environment for a runner.
Issue #110; no log format, the daemon only reads the policy.

- **A profile, not code.** Holes `{rules}`, `{socket}`, `{workspace}` go
  through each file format's own writer, so nothing in a path or the rules
  changes a file's structure. A harness described in the policy gets setup with
  no new Lonca, and any file format it reads, a plugin included: OpenCode has
  no command hooks, and a text file bridging its plugin API to `lonca hook` was
  enough.
- **What setup writes is never a local change.** `generated` in
  `.lonca/workspace.json`, like `trunk_copies`. It covers only paths the
  repository does not have, so editing that list can hide nothing from a
  proposal. A file trunk brings later takes the generated one's place.
- **It writes only what is free.** A repository file, a local file, a symlink
  anywhere on the path and `.lonca/` are refused before anything is written:
  `--continue` runs it in a directory an agent has had, and a human's process
  must not follow its links. A harness with its own file tracked uses
  `--print`.
- **Flags where files do nothing.** Codex skips a project's `.codex/` until a
  person trusts the directory, and a new workspace is never trusted, so its
  setup is flags. Its hooks also need a person's review by hash, or a flag
  named dangerous that a runner must choose for itself: Lonca does not add
  it. Gemini needs `GEMINI_CLI_TRUST_WORKSPACE`, in `env`.
- **Cooperative.** Generated hooks live where the agent can write. They do not
  raise the observation level; that takes managed settings (#21).
- **One text of the rules** (`harness::rules`), neutral in `lonca rules`, MCP
  `instructions` and setup, with the harness's tool names in the hook.
- **Arguments a tool does not take.** Ignoring one left a model repeating a
  call that could not work: two models sent a claim as `symbols`, Lonca saw an
  empty claim and denied it, and each retry was a log entry. A tool that
  changes something now refuses the call; a tool that only reads runs and
  warns. Both send the tool's schema back, and every argument says what it is
  for: the names alone were what the models guessed from. `symbols` is not mapped to `edits`: a claim is the
  agent's own statement, and guessing it would remove the check.
- **Tool annotations.** A tool counts as destructive until `mcp.rs` lists it,
  so a new tool asks by default.

## The lease queue

Leases never wait, and that stays. But an agent that was denied had to poll
`status`, the fastest poller won, a yield could be taken by a third session
before the counterparty that negotiated for it, and a parent had to release
a symbol and race everyone to hand it to a sub-agent (#42).

- **`lease.interest {items, intent}`** is a request to be next. It holds
  nothing and nobody waits on it. From format 12 it does stop others for a
  limited time (below), so two sessions that each hold something and wait for
  the other's type deny each other's widening until the cap ends it. It takes the `lease.acquire` right, on the same scope and symbols as an acquire,
  and it needs something to wait for: an interest in a free symbol is refused
  (`lease_free`), or it would be a way to reserve anything. A session waits
  for overlapping items once (`interest_exists`).
- **When what conflicts is gone, the oldest interest gets a reservation** for
  `leases.reservation_ms` (default 60 s). In that window another session's
  acquire is `lease_reserved:<session>`. Age is the interest's sequence number.
  Interests are served whole: one blocked item keeps the whole interest
  waiting, as an acquire is all or nothing.
- **The window opens at an entry.** Time frees a set too, and nothing is
  written when it does, so the fold settles reservations at the start of each
  entry, from that entry's time. `decide()` calls the same pure function
  (`State::reservations_at`) for the same time, so it sees what the fold of
  that entry will record, and nothing reads a clock. The value of
  `reservation_ms` reaches the fold through the decision
  (`reservation_ms=N`), like `approvals=N`.
- **A window that is not used passes on**, to the next interest, with its own
  window. A session that ended, expired or stopped beating leaves the queue
  and gives its window up. A reservation is consumed by the acquire, and an
  interest registered this way also counts as someone wanting the set, for
  `leases.max_hold_minutes`.
- **A yield with `to`** moves the set in that entry, so nobody can step in
  between. `to` must be the `to_session` of the message, whose scope must cover
  the set. The set is a new hold for the receiver. A yield without `to` frees
  the set as before, and the queue serves it.
- **`cap.attenuate` with `leases`** hands sets to the child. The child holds
  them until it ends, and then they go back to the parent if the parent is
  still there. A revocation of the parent reaches the child and the sets. Only
  whole sets move, which is less than the issue's "or a subset of their
  items": a worker that wants part of a set releases the rest first.
- **A set that moves is whole, alive and unpinned** (`lease_pinned`,
  `lease_expired`): a pin stays with its change. Both handovers check
  `scope.paths` only, like a lease's own scope check would on the path; symbol
  patterns of the receiver are not re-checked.
- **`events {from}`** is the inbox: a change integrated, conflicted or failed
  in verification, approved or rejected, a message, a lease received, a
  reservation. A failed integration is logged as a denial, so the inbox reads
  those entries too. It is derived from
  the log and the state for the caller and never written, so the single-writer
  rule holds. Changes of earlier sessions of the workspace count as the
  caller's. A notification of a signature change is left to #43, which needs it.
- **No gate on the format.** A log without interests has no reservations, so
  older entries replay untouched. Format 12 gates what follows.
- **A waiting interest goes first, for a while (format 12).** Before, a wide
  interest starved: while `Type` was wanted, small leases inside it were still
  granted, one after another, and the reservation came only once nothing was
  held. Now, for `leases.interest_block_ms` (default 10 minutes) from its entry,
  an interest denies other sessions' new leases that conflict with it
  (`lease_wanted:<session>`). `decide()` has no tree, so `path#Type` and
  `path#func` look the same, and it needs none: an interest in something held
  stopped others anyway, so the rule only changes anything where the interest
  is wider than what is held. It reaches further than a lease could, since a
  lease on `Type` would be denied while a member is held, but an agent could
  lease the free members one by one, and it needs something to wait for and
  the same scope. The cap reaches the fold through the decision
  (`interest_block_ms=N`), and an interest of an older format has
  `blocks_until_ms` 0.
- **The cap is per held set, not per interest.** An independent review broke a
  cap per interest: a waiter leased a free member, which ended its interest, and
  registered again; child sessions took turns. So the first interest that runs
  into a set writes its end on the set (`stop_until_ms`), and no later interest
  that runs into that set, or into an older interest, goes past it, whoever
  registers it. A new set over what the session holds keeps it, like
  `acquired_ms`, and also keeps who wanted the set (format 12), which closes a
  way past `max_hold_minutes` as well. A leased part of what is waited for does
  not end the interest. After the cap the interest stays in line without the
  right, and small leases are possible again until that set is gone: the wide
  change gets ten minutes of priority per holder, not a guarantee.
- **What it does not stop.** What the session holds, exactly as held: a
  `lease_release` with items acquires the rest under a new set first. What is
  reserved for it, or inside that: a reservation is a turn, and a younger
  interest does not take it back. An older interest of the session that
  conflicts with it: age goes first. Everyone else is stopped, the holder of what
  is waited for included: it keeps what it has and can finish, but it can not
  widen. It reads who waits, and why, and they settle it with `negotiate`.
- **An interest can line up behind one.** What an interest stops counts as
  something to wait for, so it is not `lease_free`, and it is not served while
  an older one stops it.
- **Every lease says why (format 12).** `decide()` can not tell a wide lease
  from a small one by the string, apart from `rename` and `<file>`/`<module>`.
  Computing the width in the daemon from trunk and recording it for the auditor
  was the other way; a required non-empty `intent` on every `lease.acquire` and
  `lease.interest` is simpler, and the reason already reaches the second agent
  through `details.intent` (`intent_required`). For a wide change or a delete,
  the rules and the tool's text ask why it needs that much and for the issue
  number. That part is asked, not checked: no fixed form of a reference fits
  every project.

## Sections of files without a grammar

Any change to a file with no grammar was an edit of `path#<file>`, an
exclusive lease on the whole file, and the merge was by lines: only one agent
at a time could touch `README.md`, `CHANGELOG.md` or `Cargo.toml`, exactly the
files many parallel tasks touch together (#46).

- **Sections** (`crates/lonca-symbols/src/sections.rs`), by engine 1:
  Markdown by heading (`README.md#Install.Linux`); TOML by table and key
  (`Cargo.toml#dependencies.serde`, `bin[0].name`); JSON by top-level member,
  and one level into `dependencies`, `devDependencies`,
  `optionalDependencies`, `peerDependencies` and `scripts`; YAML by key and
  one level down. They use the `.` hierarchy of symbols, so a lease on a
  section covers what is in it, and adding one takes an `insert` lease on its
  container. A `.` or `#` in a heading or key becomes `-`.
- **Fail closed.** A file that does not parse, repeats a name, has one
  section, or is not plainly what it should be has no sections: whole-file
  edit and line merge, as before. A change no section shows (the space
  between JSON members) is a whole-file edit too. A merge whose result no
  longer parses is a `<file>` conflict.
- **The merge** takes each section from the side that changed it. Both sides
  changing one is a conflict on that section. It keeps ours' order, and what
  only theirs added follows what it followed there. JSON has no sections to
  concatenate, so members are joined with the file's own separator, which is
  what keeps the commas right.
- **Appending, by rule and not by list.** The issue proposed
  `leases.append_files`. A policy value can not reach the merge: `integrate`
  and `facts_of` take only the engine, and the auditor must recompute them from
  the log. Instead, in Markdown, a section that only grew at its end is an
  addition (`path#Section.<append>`, an `insert` lease on the section), and two
  such additions merge, ours first. Any other change to the section is an
  edit, and conflicts as one. TOML, JSON and YAML have keys, so there an
  addition is a new key.
- **Critical paths are unaffected:** `Cargo.toml` still needs its human
  approval, however small the section.
- **Clients** read the same sections: `sync` and the undo merge use the
  current engine, and the `symbols` MCP tool lists sections as symbols.

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

## A workspace is a git repository (#111)

An agent's workspace has a `.git` with one commit of its base, because agents
and tools expect one: `codex exec` refuses a plain directory, and `git diff` is
how an agent reviews its own work.

- **Lonca never runs `git` on it and never reads a file in it.** The agent can
  write `.git/config`, and `lonca sync` can run outside the agent's sandbox: an
  MCP server does. A `git` process there would run `core.fsmonitor`, a
  `reference-transaction` hook, a promisor remote's transport and so on, with
  Lonca's rights. `-c` overrides would be a list of what we thought of, so
  `.git` is written in-process: loose objects through `LooseObjects`, which
  opens no repository, and an index from `index_of`. `checkout.rs` runs `git`,
  so `repo_name` refuses a workspace.
- **This departs from the issue:** it asked for a warning and a plain directory
  on a machine with no `git`. Nothing here needs `git`, so that case is gone.
- **Every write goes through `wsfs`**, so a symlink anywhere in `.git` stops it
  and a race can not steer it. `gix` writes objects by path, so a sync writes
  them to a private temporary directory and copies them in. The first base skips
  that copy: the directory is new and no agent has its token yet, and at 10,000
  files the copy took 4 s instead of 1.5 s. A sync that can not
  write `.git` goes through with `git_warning`: `.git` is a convenience and
  `changes()` does not depend on it.
- **One commit, no parent, not trunk's commit.** Trunk's history is not in the
  workspace, and a symlink is a regular file there, so its tree may differ from
  trunk's. Local commits leave the branch at a sync; their content stays in the
  files.
- **The index has zero stats**, so the first `git status` hashes every file. A
  stat taken at write time could call a locally edited file clean.
- **`.git/info/attributes` turns off line-end, ident and filter handling**: the
  file on disk is the blob, the same comparison `changes()` makes.
- **Only sessions.** A person who wants git uses a checkout (humans guide).
- **Cost:** about 1.5 s per 10,000 small files at `session start` (one loose
  object each), about 100 ms for a sync that brings no new blobs. `--no-git`
  skips it.

## What a critical path costs (#103)

`[observation] unobserved_critical` and `[taint] critical` say what a change to
a critical path costs a session nobody fully observes: `deny` or `escalate`.

- **The default stays `deny`.** Opening one is a signed policy update, so the
  choice is in the log.
- **Two words, not one**, since a taint is a stronger claim than a missing
  observation. A session in both states needs both open. The denial reasons
  are unchanged for today's policies, because replay compares them: a session
  in both states denied by default says `tainted_critical_path` alone.
- **`unobserved_is_tainted = false` is not the same thing**, and stays as it
  was: it drops the review with the denial.
- **No log format.** Nothing an entry means changes: a policy with neither key
  decides as before, and a release that does not know the keys refuses the
  policy (`deny_unknown_fields`) rather than deciding differently.

## Workspace paths are opened one component at a time

An agent can write its workspace, and the `lonca` that reads or writes it may
hold more rights: an MCP server runs outside the agent's sandbox. All workspace
file access goes through `wsfs`.

- **`openat` with `O_NOFOLLOW` per component**, from the root. Checking with
  `lstat` and then opening leaves a gap an agent with a shell can race. `rustix`
  gives this with no `unsafe`; it was already in the tree. Unix only, like the
  daemon's socket.
- **A symlink at a tracked path is an error, not a deletion.** Calling it deleted
  would propose a change nobody made. A symlink outside the manifest stays
  ignored, as before.
- **`wsfs` checks the path too.** `workspace.json` is the agent's to edit, so
  `manifest` and `trunk_copies` are not trusted: `..` and absolute paths are
  refused where they are used.
- **A write goes to a temporary name and renames**, so a symlink at the name is
  replaced, not followed, and the mode is set with `fchmod`, past the umask.
- **A read refuses what is not one plain file**: anything with another hard link
  (it may be a file from outside), and more than `MAX_LINE`, which no request
  could carry anyway and which a sparse file could otherwise fake.
- **`.gitignore` and `.ignore` are read the same way**, by a short walker in
  `workspace.rs`: the `ignore` crate's walker opens them by path, so one could be
  a symlink or a FIFO. Its `gitignore` matcher is still used. A symlinked ignore
  file counts for nothing.
- **Names that are not UTF-8 are refused**, not sent under a lossy name.
- **`.lonca` is matched with ASCII case folded** everywhere (`is_workspace_metadata`):
  on macOS `.LONCA/session` is `.lonca/session`.

## A negotiation reaches the other side

Negotiation was in the log and nowhere else. The rules named `negotiate`, but
nothing told the receiver: it had to call `events`, the rules never said so,
and the event held only a thread and a sender, not what was said. So a claim
reached nobody, even an agent that asked.

- **The event carries the message.** The text was logged all along.
- **News finds the agent.** Two ways in, no vendor needed for the first:
  `lonca mcp` adds it to the answer of every tool, and a hook adds it after any
  tool call on a harness with `tool_context` in its profile. The hook is
  for the case that matters: the holder is editing and calls no tool of Lonca's
  for minutes. Claude Code and Codex document `additionalContext` for this event,
  Gemini CLI for `AfterTool`. OpenCode's plugin has no such way in, so it hears
  at its next Lonca tool.
- **Only what another session wants of you is pushed**: messages, leases handed
  over, reservations. An integration is not worth an interruption, and pushing
  it would teach agents to skim the news.
- **The cursor is in the daemon's memory, not the log.** It decides nothing, an
  entry per delivery would grow the log with every tool call, and a restart
  costs one repeated line. It is shared, so a hook and the MCP server do not
  both tell. A reservation is matched by its items: until an entry fixes it,
  its `until_ms` moves with the clock.
- **A message is another agent's words.** It reaches a model's context, so it
  goes out as the JSON it came in, cut, and under a line saying it is no
  instruction from the user or the repository. Taint already spreads at send.
- **A denial speaks.** `advice` is derived from `details` and never logged. It
  uses the neutral tool names: the daemon does not know which harness asks.
- **`events` from `next` found no approval of an older request**: the requester
  was looked up in the entries from `from` on. The whole log is read now, and
  `inbox` reads only its tail, since its kinds need no lookup.
- **Seen working (2026-11-06).** A session claimed a lease while a model held it
  and worked: Claude Code on haiku through the hook, Codex 0.165 on a local qwen
  through the hook (the rollout shows the news as a developer message), OpenCode
  2.2 on the same model through `lonca mcp`. All three answered in the thread.
  Gemini CLI has had no run: its shape comes from its reference, not from a model.
- **Limits.** An agent whose turn has ended hears nothing until something runs
  it; this reaches a working agent. A model chooses when to answer: the local
  one finished its own edits first.

The rounds of a thread are a limit with nothing behind it: step 3 of the ladder
in the design (a policy) does not exist, and `negotiation_exhausted` is only a
denial. The rules send the agent to what is free and to say what is left in its
final answer, for a person.

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
