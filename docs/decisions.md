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
- **Network attribution** uses `lsof` to find the connecting process and
  `ps` for what it descends from (it was the process's working directory
  until 0.2.3; see "Whose connection it is"). When it can not (other
  users, missing `lsof`), every proxied session is tainted.
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
- **Version 13** adds no field: `path#Name` stands for every `path#Name(key)`
  (see "Symbol engine versions", engine 6). In older entries they are two
  symbols.
- **Version 14** adds `renames` to facts, left out of the encoding when empty
  (see "Symbol engine versions", engine 7).
- **Version 15** adds `unparsed_files` to facts, left out of the encoding when
  empty (see "Symbol engine versions", engine 8).
- **Version 16** adds `unread_files` to facts, which escalates a proposal (see
  "Symbol engine versions", engine 10 and "The language table"). Older entries have
  none, so nothing is gated on the format.
- **Version 17** adds `change.integrate_batch` (see "Batches in the merge queue").
- **Version 18** adds `affected` and `affected_more` to facts, left out of the
  encoding when empty, and a proposal reports the lease sets they reach (see
  "Signature changes"). Older entries report none and replay as they were.
- **Version 19** adds `session.isolate` (see "Isolated mode: `lonca run` (#115)").
- **Version 20** adds `harness` to `session.start`, left out of the encoding when
  absent, and holds `session.bind` to it (see "Naming the harness"). Older entries
  replay as they were.
- **Version 21** adds the lease kind `shared` (see "Shared leases (#112)"). An
  acquire or an interest with a `shared` item needs it.
- **Version 22** adds `names` to a lease item, left out of the encoding when
  empty, and makes a change that adds a file need an exclusive lease on its
  `path#<file>` (see "Insert leases (#45)"). An acquire or an interest with
  names needs it. Older entries replay as they were.
- **Version 23** gives a set delegated to a child back to the parent when the
  child expires or stops beating, with no new field (see "A delegated lease
  comes back (#40)").
- **Version 24** adds the `unhooked` observation (see "A session whose hooks do
  not run (#190)"). An `observe` with one needs it.
- **Version 25** adds `checks` to `approve`, left out of the encoding when
  empty (see "Checks a change owes, chosen per change (#191)"). An approval
  that names one needs it.
- **Version 26** adds no field: an agent's proposal that is not denied
  withdraws the pending changes of its workspace (see "A newer proposal
  replaces the pending one (#107)"). Older entries replay as they were.
- **Version 27** adds `recover` on `daemon.recover`: signed with a human's
  recovery key, it also replaces that human's key (see "Daemon keys", "A
  lost Mac"). Left out of the encoding when absent, so earlier recoveries
  keep their bytes; one that has it needs format 27.
- **Version 28** adds no field: a human key may be of the kinds `sk-p256`
  and `sk-ed25519` (see "Human keys", "Security keys (#17)"), and
  `human.enroll` checks the form of the key as the other key operations
  do. Before it such a key is `invalid_key` and signs nothing, and an
  enrolment keeps its looser check, so older entries replay as they were.
- **Version 29** adds keyed directories (see "Keyed directories"): key
  leases on a `dir#<dir>`, `taken_keys` in facts. Older entries replay as
  they were.
- **Version 30** adds `workspace` on `session.start` (see "Where a session
  works is in the log"). Left out of the encoding when absent, so earlier
  starts keep their bytes. From it on a continuation names the workspace
  of the session it continues, a directory holds one live session, and a
  continuation starts `unobserved`; entries of older formats do none of
  it and replay to the state they always had.
- **Version 31** holds a `cap.attenuate` to its parent's agent name (see
  "A child session is its parent's agent"). No field changes. Entries of
  older formats, where the child's name was free, replay as they were.
- **Version 32** matches `[paths] critical` and `checks_by_path` with case
  folded (see "A path that forbids is read with its case folded"). No
  field changes. Entries of older formats, where the spelling was matched,
  replay as they were.
- **Version 34** carries a taint, an `unhooked` mark and a lowered level
  from a session to the sessions made from it (see "What enters a session
  enters its children"). No field changes. Entries of older formats, where
  a child took them once at its making, replay as they were.
- **Version 33** holds a human signature to the log it was made for (see
  "A human signature is for one log"): `at` in the signature, left out of
  the encoding when absent, so earlier entries keep their bytes. Entries
  of older formats, whose signatures name no entry, replay as they were.
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
    move. From engine 6 only exact duplicates have a number; renames wait for
    the rest of #44.

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
    `VERSION: 1` between two methods is no separator. A new member is placed
    only beside a symbol right next to it, since order against `...base` can
    decide what a key means; otherwise lines place it. A member that stops being
    in a list, as in `int a, b;` to `int a;`, is a change of shape and of the
    code around it.
  - **A merge writes code of one side or the other** (`holds_up`). The code
    outside symbols and every container's own text must equal `o`'s or `t`'s,
    because code both sides changed is a conflict before this, and no merge
    may bring a name neither side has. Failing it, a symbol merge goes to the
    line merge, and a line merge is `<file>` in `conflicts`. So a text operation in the wrong place can not
    drop or copy code that nobody touched. Two parts of a partial type each
    getting a member `x` are caught this way.
  - **Numbers in blocks.** `f~2` counts from the top of the file, so a name
    that came to stand in another block can make the same number another
    definition, also with as many of the name as before. So when any side
    changes which group and block each numbered name stands in
    (`Holder.block`), the file goes to the line merge, after the checks that
    make code changed on both sides a conflict.
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
    between, so it is code there too. Where such a comment starts is layout
    (`Sym.tail`), because `gofmt` realigns it when a longer line comes.
  - **TS method decorators** attach to the method, as a field's already did.
  - **C# partial types.** A later `partial` part of a type in the same file
    keeps its own name (`C~2`) but works like a Rust `impl`: its members are
    `C.N`, overloads across parts get one id each, and its header is
    `C.<def>`. Parts in other files stay unrelated, because a symbol id is per
    file, and so do parts in two different namespaces, which are two types. A
    namespace written twice is one namespace. A new part is an add of `C~2`, as
    a new `impl` is an add of `impl:C`.
  - **What this does not see.** A const in a Go `iota` group means what its
    place says, so a spec added in the middle changes the ones after it with
    no fact about them; verification catches that, as for any change between
    symbols (design §5.8). Names by order (`f~2`, `m!~2`) stay for what has
    no key from engine 6 on: exact duplicates, macro calls, partial types.
    Deleting the last two members of a list, or the last symbols of one, and a
    deletion that takes the blank line under a comment, are refused by the line
    merge though the leases allow it: nothing is lost, and such a change goes
    back to the agent. A new symbol beside one that `o` moved to another block
    of the same kind follows it.

- **Engine 6** tells symbols of one name apart by what they take (issue #44).
  Up to engine 5 the second `Charge` was `Charge~2`, by its place in the file,
  so an overload added in front of it renumbered the rest: facts reported
  edits nobody made, and two sessions could hold one overload under two names.
  - **Only a shared name has a key.** A symbol alone with its name is that
    name, in every language, so a change of its parameters is the edit it
    always was and ids stay short. Once a file has two definitions of a name
    with something to tell them apart, every one of them has a key, the first
    included: anything else depends on which came first.
  - **The key.** `(int,string)`: for each parameter its type, with its
    modifiers (`ref int`, `number?`), else its name, as Python has none. A name
    or a default can change with the same symbol, so neither is in a key that
    has a type. In front go what else an overload can differ by: how many type
    parameters (`G(<2>)`), a C# conversion's type, an explicit interface
    (`M(IA)`), TypeScript's `static`. `[setter]`, `[get]`, `[destructor]`: such
    a symbol is named by that word, in the syntax (`get v()`) or hung on the
    name (`@x.setter`); `@f.register` says nothing about which overload this
    is, so it goes by its parameters. A Rust `impl` takes the arguments of its
    trait and type, `impl:S.From(u8)`, and a trait's members follow:
    `S.From(u8).from`. It all comes from field and node names that hold across
    grammars, `parameters`, `type`, `name`, `pattern`, not from a table per
    language. A `.` in a key is written `::`, so that a `.` always separates
    the levels of a name. A key stops at 200 bytes: it is written in every
    lease and fact that names its symbol, and what differs past that is
    numbered.
  - **Versions read together.** Facts and merges need one name for one symbol,
    and a second overload appears in only one of the versions. So they read
    all versions with the names any of them needs a key for
    (`parse_together`): a merged text too, through the same set (`parse_keyed`).
    Names depend on a parent's name, so the set is found in rounds, with a pass
    that only counts; it ends with the depth of the file. Only a name shared
    within one version has a key: a union across versions would give every
    change of parameters a new id.
  - **A change of parameters.** A keyed symbol that changes them has a new
    name on that side. `align` gives it the name it has in the base, which
    keeps it an edit plus a `signature_change` on the name a lease was taken
    on, and two changes of one overload a conflict instead of two new methods.
    A lost and a gained symbol pair only under one bare name, in one block,
    behind the same symbol both sides have, and neither may stand anywhere else
    in the other version. Elsewhere one is gone and the other new: pairing them
    regardless reported what stood between them, and a deletion could come
    undone. In one place the closest texts pair, then source order; past 64
    comparisons only source order, in linear time, so that a file sets no
    price. Texts can mislead: with like bodies, one overload deleted and one
    changed pair by order, and the wrong pair can then pass a delete on the
    other side in one queue order. Containers are not paired, because their
    members hang on the key.
  - **A merge is read by origin.** Each symbol of a result came from a side, and
    its text finds its pair there, then the order of the base, not its place in
    the result. A key twice in one place that no side has twice is refused
    (`key_twice`), because each copy would pass as a symbol that changed: both
    sides giving `M(int)` and `M(long)` the key `M(bool)`, or one giving and the
    other adding it, whether the key is new or the base has it. In another block or in an
    `impl` for other type arguments both are valid and merge. The parts of a
    `partial` type are one place, and so are two `cfg` variants of a function,
    which a merge can not tell from a duplicate: that one is refused though it
    would compile, and it goes back to the agent. A namespace written twice is
    two places here, so two types of one key in it merge and fail to compile.
    A side that does not parse has no symbols, and its line merge is held to
    nothing of this.
  - **What is left to a number.** Exact duplicates (`init()` in Go), macro
    calls, partial types, `impl` blocks of one type and the members of generic
    inherent impls (`W.new`, `W.new~2`, because a type's members do not hang on
    the impl): nothing but the order tells them apart, so a block added above
    the first reads as a change of what the blocks hold. `numbers_hold` guards their blocks, and when
    both sides changed how many there are the line merge decides
    (`counts_hold`): neither side's `~2` says which one is meant.
  - **The `;` behind a member of a TypeScript class is the member's.** It is a
    sibling in the tree, so it stayed in the class's own text, and adding a
    field or an overload signature was an edit of `<def>`.
- **A name stands for all its symbols (format 13).** A session on an older
  base can see one `Charge` where the trunk has two, and has it as `Charge`,
  while another has `Charge(string)`. `decide()` has no tree, so what relates
  the two is in the strings: `Name` covers `Name(key)`, part by part
  (`S.From.from` covers `S.From(u8).from`). The session with the bare name holds
  all of them, which is wider than it knows and never less than it needs. A
  scope on a name reaches its keyed symbols, and a key in a scope only that one
  symbol. Log format 13 gates all of this, in `decide()` by `Ctx.format` and in
  the fold by `State.symbol_keys`, because in older entries `a.md#Setup` and
  `a.md#Setup(old)` are two headings. A new overload needs a lease on the type
  or file around it, not on its namesakes.
  - **Files with sections have no keys.** A heading can hold a `(`, and a scope
    on `Setup` must not reach `Setup(old)`. `names_are_headings` keeps the
    extensions; a test keeps them equal to `Format::detect`.
  - **Everything that compares names by hand follows.** The revert count takes
    `Name` and `Name(key)` for one symbol, and Cedar's `context.symbols` holds
    the bare ids as well, so that a rule on `path#C.M` does not stop matching
    when a second overload arrives. An `insert` on `S.From` meets a lease on
    `S.From(u8)`: `stands_for`, one level, because members of it are free for
    an insert as a type's are.
  - **`decide()` reads `state.symbol_keys` throughout.** It is set by the fold,
    so the first entry of format 13 in an old log is decided by the old rules
    as a whole. Mixing `Ctx.format` and the state let that one entry pass a
    reservation that any later entry would have stopped.
  - **What this does not do.** A lease on `Charge(string)` does not cover the
    fact `Charge` once the other overload is gone from the base: the session is
    told `lease_missing` and takes the name, and nobody else can hold that.
    Two sides that each add a first overload to a name conflict on
    it, since neither version has two. A scope on `C.M` can not be narrowed to
    `C.M(int)` with `cap.attenuate`: narrowing has no file to tell a heading
    from a key by, so this stays refused. A key with `*` in it can not be
    written as a scope; leases and facts are fine, and `C.M*` reaches it.

- **Engine 7** says what was renamed (issue #44, its rest). A rename was a
  delete and an add, so a session that had the old name and one that has the
  new one held one symbol, and only the merge found out.
  - **What counts.** A deleted and an added symbol of one list, of one shape,
    that are the same with the name left out, recursive calls included, or
    alike by at least 0.8, word by word. The number is engine data: it decides
    facts. A type also needs half its members in both, because two shells say
    nothing. Past 64 comparisons in one list a rename stays a delete and an add.
    `impl` blocks are not renamed, since they stand for their type, so a Rust
    type's rename also takes a lease for its new `impl`, as `lease_needed` says.
    A move to another type or file is not detected: both names must have one
    owner, which one list does not promise, as Go methods stand beside the
    types. A guess there would let a rename lease on one type reach another. So
    a Go type renamed along with a method's name reads as a rename of the type
    and a delete and an add of the method: its old name follows to `U.Old`, and
    what goes into the renamed type needs no lease of its own.
  - **Facts.** `renames: [[old, new]]`, beside the `deletes` and `adds` that
    stay. So `Claim` does not change and no client has to, and an auditor of
    an old log has nothing new to read. A change of parameters that `align`
    paired is in `renames` too, though it stays an edit: the old key and the
    new one are one symbol, and no string says that.
  - **Leases.** A `rename` lease on the old name covers the whole change: the
    new name needs no lease on its container, and `lease_needs` asks again that
    the two have one, so that this rests on no fact alone.
  - **What the issue proposed and this does not do.** It proposed resolving
    lease items against the trunk and recording the trunk in the set. That
    takes a tree in `decide()` or a value the daemon computes and the auditor
    recomputes. The integrated facts already say all of it, so the fold keeps
    them (`State.renames`, with where in `trunk_line` each starts) and names are
    compared as they are and as they are called on the trunk
    (`State.conflict`). A session on an older base asks for a name a lease on
    the new one meets, and a proposal from an older base has its facts mapped by
    the renames that base had not seen. A member follows its type. A name taken
    again (an addition, a new key, a file deleted or written anew) is that new
    symbol: it starts no chain, for a lease or for a proposal, so nothing holds
    it by the name it left behind. A symbol already on its way passes it, so `a`
    to `b` to `c` holds after a new `b`; a symbol that was then deleted ends what
    led to it. A bare `C.M` does not reach an overload that went on as `C.N`: the
    overload left behind has that bare name again, and it would wait for `C.N`
    for good. So a session that holds `C.M` from where it stood alone and one
    that holds `C.N` meet only in the merge. An external import has no facts, so a name it takes stays
    linked to the rename, and two sessions on those names wait for each other
    until one lets go: safe, and rare enough to leave.
  - **The merge** leaves a symbol `t` renamed where `o` has it, instead of a
    delete here and an add there, and what `t` added behind it stays behind it:
    the order of definitions can be what the code needs. If `t` moved anything
    among the symbols of that list, renamed ones included, these are the delete
    and the add they always were, so that the order is `t`'s.
    An edit of what the other side renamed is a conflict, as is a delete of it
    or a second name for it: `o` deleted, `t` renamed, or both renamed
    differently, each conflict on the old name. The edit does not follow the name.
  - **What this does not do.** A rename does not change the code that calls the
    symbol, so a caller is what verification finds (design §5.8). The list of
    tests counts a renamed test as deleted and added, and escalates: renaming
    a test and gutting it can not be told apart from outside.

- **Engine 8** lists the files no parser reads (issue #113): `unparsed_files` in
  facts, text on both sides with neither symbols nor sections. A file added or
  deleted, a change of mode and bytes that are no text are not listed, because
  a line merge decides nothing about them. The list is in facts, not worked out
  from an extension in `decide()`, so that a new language changes it in one place.
  - **`[leases] unparsed_files`**, `"file"` by default, `"optimistic"` by a signed
    policy. Under `optimistic` an edit of a listed file needs no lease: the line
    merge at integration decides, an overlap is `conflicted`, and verification
    runs on the result as always. It waives the lease and nothing else: scopes
    hold, and deleting such a file takes its `rename` lease.
  - **The issue had the value travel in decision reasons.** The fold does not need
    it: `pin` uses `lease_needs` as it is, so a lease someone did take is pinned,
    and with none there is nothing to pin. `decide()` has the policy of the entry,
    so replay holds.
  - **A lease someone holds on such a file does not stop another's edit.** It is
    no use to anyone under `optimistic`, and the merge is what decides.

- **Engine 9** has two parts.
  - **What engine 8 lists narrows to edits of lines:** the mode stays and is that
    of a plain file, neither text holds a NUL, and at least half of the old text's
    lines stay. Anything else keeps the file's lease. A link's target is no edit
    of lines, and a change that takes away most of a file does what deleting it
    does. The half is a line drawn, not a proof: it can not tell a rewrite from an
    edit, and it does not try to.
  - **Lines merge by `lines.rs`.** Changes are compared over `reach`, everywhere
    they could stand with the same result, because among equal lines a diff can
    only guess which line a change took. A conflict costs a look, a wrong guess
    costs a side's work. Compared with `git merge-file` on generated inputs, Java-
    shaped files gave the same result on each of 4000. Files of mostly equal lines
    conflict more often than git does, and in rare cases merge where git conflicts
    or place a line elsewhere among equal lines, with both sides' changes in. The
    same line added at one place by both is one change, and comes in once.
- **A conflict is written out.** `lonca sync` brings in the rest of trunk and
  leaves both sides between `<<<<<<< local` and `>>>>>>> trunk`: a symbol whole when
  both sides have it by that name, else by lines, which show a deletion, a rename
  and a change of key alike. The file is then the agent's to settle.
  - **A proposal goes by the text, not by a list of paths.** The markers carry a tag
    of the workspace, kept in `conflict_tag` while any stand, and `propose` looks for
    each of the three in every changed file: a new name settles nothing, half a
    conflict settled is not settled, and a line of the file that merely reads like a
    marker is the file's. A later sync reports the conflict again.
  - **It lives in the client.** The daemon sees a file. An agent that writes such
    text on purpose can land it, as it can land any other bad text.
  - **A move is the one thing this shows badly:** the moved copy comes in beside the
    conflict, so keeping the local side leaves the code twice. The facts of the next
    proposal list it as added. `lines.rs` is the one core for this and for the merge
    at integration.

- **Engine 10** reads Java, Kotlin, C, C++, Ruby, PHP and Swift. Each is an entry
  in the language table with `since = 10`: engine 9 and older still see their
  files as text, and old entries recompute as they were.

- **Engine 11** gives every declaration a signature and lists what mentions
  the names a change takes away (issue #43; see "Signature changes").
  - Up to engine 10 only what has a `body` had a signature, and that was the
    text in front of it. So a trait method, a field, a type alias or a change
    of a struct's fields was no change of signature.
  - Now a container has its header, a declaration whose body is the type (a
    Rust `struct`, an `enum`) all of it, and anything else without a body the
    declaration in front of its value. For a function held by a name that is
    in front of the function's body, so `const h = (a) => {...}` keeps what it
    takes. The fields of a value (`VALUE_FIELDS`) hold across grammars, as
    `TYPE_KINDS` do. Comments are left out of every signature.
  - The type of `int a, b` stands in the class's own text, so neither field
    changes: the signature change is `C.<def>`. Each item's signature holds what
    stands in front of the first item, not of itself, so a list stays linear.
- **Engine 12** reads symbols down to a depth (`MAX_LEVELS`, 32).
  - Names grow with the depth, and every walk over symbols goes down with it:
    cost and stack both follow how deep a file nests, not how long it is. A
    limit keeps all of them bounded at one place.
  - What stands below the last level is text of the symbol around it. That
    symbol is a leaf: it keeps its name, its definition and the signature of
    its header, the merge takes it as one unit and a change in it is a change
    of `T.<def>`. Levels with no name of their own, such as a C# `namespace`,
    count.
    `describe`s have the same limit: past it a test keeps its place among the
    last ones read, and a skip still reaches it.
  - The walks over the syntax tree (`exact_text`, `blocks`, `find_descendant`,
    `js_tests`, `comments_in`) have stacks of their own, at every engine,
    because a tree can be as deep as a file is long. The comments behind code
    are found in one pass over a level. Their output is the same, and the
    frozen snapshots pin that.
  - The merge remembers the walks of `around_theirs` that met a conflict. Its
    caller walks the same members again after one, so each level would cost
    two of the level below. A walk depends only on what it is given, so this
    changes no output, at any engine.
  - Up to engine 11 symbols have no limit, so that entries are recomputed as
    they were written. Only the auditor reads at those engines, and an entry
    exists only if the daemon got through its file.
- **Engine 13** reads a file up to a size (`MAX_READ`, 2 MiB) and its names up
  to a total (`MAX_NAMES`, 16 MiB).
  - A file past `MAX_READ` on any side of a comparison goes by its lines, as a
    file no grammar reads: an edit of `<file>`, listed in `unparsed_files`, and
    a line merge. That holds for sections too, and the verifier's syntax check
    leaves such a file alone, so a long generated file is not refused. What
    people write stays far below this, and what a merge costs grows with it: a
    merge of a 2 MiB file takes seconds.
  - A name holds the names around it, so a long name over many members costs
    their product while the file costs only their sum, and so does a signature
    that repeats what a list has in front of its items. `MAX_NAMES` counts the
    names and signatures read so far; what is left past it is text of what is
    around it, as with `MAX_LEVELS`, and test names of JavaScript stop there as
    well. Files that are read stay far below it.
  - Both limits depend only on the text, so the auditor gets the same answer.
- **Engine 14** joins by lines a symbol both sides changed, where the caller
  says it may (`Joins`): one held `shared` (see "Shared leases (#112)"). With
  nothing to join its output is engine 13's. The cases under
  `tests/engine/v14/` with a `joins` file pin what it joins.
- **Engine 15** fixes what the merge's property tests found (#40,
  `crates/lonca-symbols/tests/merge_props.rs`). Every case of v14 has the same
  output in v15; `rust-gaps` and `python-already` are new.
  - **A change `ours` already has merges into `ours`.** When the symbol merge
    finds every change of `theirs` in `ours` already, nothing of `theirs`
    comes through, and the merge went to the lines in case `theirs` changed
    something only lines show. When `ours` had also added something where
    `theirs` added the same, the lines met and the file was a conflict. Now,
    where the line merge fails, `ours` is the merge. Code outside symbols that
    only `theirs` changed never gets here: it goes to the lines before the
    walk, as it did. What can be lost is a change of layout only that meets
    the lines of `ours`.
  - **A deletion takes the wider gap.** A deleted symbol took the whitespace in
    front of it, so the first one of a file or of a container left the blank
    line behind it at the top: a merge neither side wrote, and one a format
    check fails. A run of symbols deleted next to each other now goes as one,
    with the gap around it that holds more line breaks, the one in front on a
    tie, and never a gap another edit goes into. A symbol in a list or one
    that holds its line end goes as before.
  - **No blank line at the top that no side has.** An addition behind a symbol
    the other side deleted can go to the end of what is left, with the gap
    it had in front; when nothing is left in front of it, a merged file
    starting with a blank line loses it unless `ours` or `theirs` starts so.
  - **Known limit, every engine:** when the two sides together delete every
    symbol of a file and add none, there is nothing to hold the result to,
    and the file is a conflict.
    Engines before 13 read everything, as they always did.
- **Engine 16** parses within a budget of work. A grammar can take far more
  work, and memory, than its file is long: the Kotlin grammar found by the
  fuzzer (#15) grew past 3 GB in half a minute on 1.2 KB, and one agent
  proposing such a file took the daemon down.
  - A parse may take `PARSE_BASE` (256) steps and one more for every
    `PARSE_BYTES_PER_STEP` (4) bytes, and never more than `PARSE_MAX` (8192).
    A step is one call of tree-sitter's progress callback, which it makes after
    a fixed count of parse actions (100 in tree-sitter 0.27): it counts work,
    not time, so the auditor stops where the daemon stopped. A change of that
    count in tree-sitter is a new engine, as any grammar update is.
  - The numbers come from 38,790 source files of every language read (the
    cargo registry, node modules, Homebrew, local projects): none took more
    than 0.034 steps per byte, and 11 of them, all generated and over 1 MB,
    more than 8192. Deeply nested C++ templates, the densest valid code found,
    take 0.16. The Kotlin input stops at about 330 steps, in under half a
    second; at `PARSE_MAX` such an input costs about 10 s and 270 MB a parse.
  - A text past its budget goes as one past `MAX_READ` does: its file goes by
    its lines on every side of a comparison or merge, and the verifier's
    syntax check leaves it alone, so a strict language does not refuse a long
    generated file. `Lang::parse_at` stops at the budget on every path, the
    scan of what mentions a removed name too.
- **Engine 17** takes a parse error in any language as the grammar's (#246).
  A grammar is older than its language: the C# grammar in the build
  (tree-sitter-c-sharp 0.23.5) gives a parse error for C# 14's extension
  blocks, `c?.X = 1` and `operator +=`, and for C# 13's `allows ref struct`.
  Rust, Python, TypeScript, TSX, JavaScript, C# and Go were strict, so the
  syntax check refused valid code until a release brought a newer grammar.
  From this engine they go the way the seven of engine 10 always went (see
  "The language table"): the syntax check passes the file, it merges by its
  lines, and a proposal that leaves unreadable a file that read, or adds one,
  escalates with `unread_file:<path>`.
  - The table says it as data: `strict_until = 17` on those seven entries, and
    `Lang::is_strict_at(engine)`. Engines 0 to 16 recompute as they did.
  - The price: a real syntax error in these languages is no longer refused by
    Lonca. A person sees it, and the repository's `build` and `test` commands
    where it has them. No setting brings the refusal back: a repository's own
    compiler is the better judge of its language's version.
  - A file is parsed once more to tell whether it is within its budget, so
    what a file costs at most doubles.
  - Engines before 16 parse as they did, without a budget, so that entries are
    recomputed as they were written. The auditor reads at those engines only
    an entry, and an entry exists only if its daemon got through its files.
- **Engine 18** keeps, in a file with a parse error, the symbols the error is
  not in. Up to 17 one piece of syntax the grammar did not know cost the file
  every symbol: one extension block in a C# file of fifty methods, and the
  file was leased whole, so the agents on it waited for each other. Leases per
  symbol are what keeps agents from blocking each other, and a grammar is
  always behind its language (C# 14 was not in a release of its grammar a year
  after the language's), so the gap has to cost little instead of being
  chased with grammar updates.
  - tree-sitter goes on after what it can not read and marks it (an `ERROR`
    node, or a token it assumed). `Parsed.errors` has those places, and a
    symbol none of them touches was read whole (`reads_whole`). `read_parts`
    gives the outermost such symbols, a container with an error giving its
    members instead, and the **rest**: the file without them, as lines with
    their indentation and without blank lines.
  - The rule is in the facts only. Both sides of a change have a parse error
    and the same rest: the change is compared as those symbols, with every
    fact a file that reads gets (edits, adds, deletes, signatures, order,
    tests), and the file is in neither `unparsed_files` nor `unread_files`.
    Anything else is what it was: an edit of `<file>`. So a change to the
    unread part, to a definition it is in, to imports or to code outside
    definitions takes the file's lease, and a file that stops or starts being
    read is compared whole and escalates as before.
  - Why the rest must be the same, and not only the error: where a grammar
    stopped, a boundary can be wrong. Of the 29 unread samples of the corpus,
    Kotlin's guard condition ends the function before its body, Go's generic
    method is no symbol at all, and C#'s extension block ends the class one
    brace early. In each of them the misread text is in the rest, so changing
    it is a change of the file; a symbol is trusted only when the grammar read
    it from start to end.
  - The merge is unchanged: a file with a parse error on any side merges by
    its lines and is not held to its symbols. Two agents with leases on
    different methods merge unless their lines touch, and a conflict there is
    named `<file>`. Mentions of a removed name are still not looked for in
    such a file.
  - `[leases] unparsed_files = "optimistic"` let any line edit of such a file
    go without a lease; a change inside read symbols now needs theirs, as in
    any file that reads.
  - `lonca symbols` and the MCP `symbols` tool mark what was not read
    (`not read`, `partly read`; `unread: true`).
  - Decided with it (2026-11-10): no grammar is copied or updated ahead of its
    release to close a gap, and no language is added, until somebody asks.
- **Engine 19** names four kinds of definition that their grammar read and no
  rule named (issue #251), so each can be leased by itself and a change to it
  is no longer a change of the code around it. They are rules of the table,
  gated by `since = 19` (`ENGINE_MORE_DEFS`); every case of v18 gives the same
  output under v19.
  - **Python's `type Pair[T] = ...`** (3.12) is named by the first identifier of
    its `left`, and is a type, as a TypeScript `type` alias is: its signature is
    the whole statement, so a change to what it stands for lists the code that
    mentions it in `affected`, and its edits are `Pair.<def>`.
  - **A C++ `concept`** is read through `template <...>` as a class template is,
    and is a type as `using X = ...` is: the whole definition is its
    signature. Read as a plain declaration, `concept Small = sizeof(T) <= 8;`
    had a signature that stopped at `<=`, where the value of the comparison
    starts.
  - **A type declared in a class or struct** (`struct promise_type { ... };`,
    `enum class State { ... };`) is a member with members of its own:
    `Task.promise_type.get`. A wrapper reads the `type` of a
    `field_declaration` that has no declarator. Wrappers have `since` and
    `without` for it: without the condition `struct node *next;`, a field of a
    type declared elsewhere, would read as that type and lose the field, and
    `struct { int a; } anon;` stays the field `anon`.
  - **A Swift `macro`** (5.9) is named by its first `simple_identifier`, behind
    its attributes, and told from another of its name by its parameters, as a
    `func` is. Its signature keeps `= #externalMacro(...)`: an expansion
    depends on which type implements the macro, so a change there lists the
    code that uses it.
- **Engine 20** counts what a grammar reads, and sees a blank line in what it
  did not read.
  - **A parse has a budget of bytes read.** Engine 16's steps count parse
    actions. A grammar's scanner is code of its own and can read as far as it
    likes for one token: Swift's looks for the end of a comment from every
    `/*`, and with none it reads to the end of the file each time. A file of
    nothing but `/*` took 4.7 s at 40 KB and 81 s at 200 KB, under the single
    writer, before the steps ran out; `MAX_READ` allows ten times that length
    and the time grows with its square.
  - The text now goes to tree-sitter in pieces of `READ_CHUNK` (4096) bytes
    and every piece it asks for is counted, again each time it comes back for
    one. A parse may be handed `READ_BASE` (1 MiB) and `READ_PER_BYTE` (64)
    times its length (`read_budget`); past that the file ends there for the
    grammar, the parse is `None`, and the file goes by its lines as one past
    the steps does. It counts bytes, not time, so the auditor stops where the
    daemon stopped; the count depends on the piece size and on how tree-sitter
    fetches, so a change of either is a new engine.
  - The numbers come from 31,577 source files (Python's standard library,
    Homebrew's Ruby, node modules, this workspace and crates of the registry):
    the most any was handed is 26.3 times its length (a Python file of 28 KB),
    and the files over 1 MB under twice. The `/*` file is handed 35,000 times
    its length at 40 KB. With the budget the worst input found costs 0.3 s at
    `MAX_READ`.
  - A text handed in pieces parses as the same text handed whole, steps
    included (`a_text_handed_in_pieces_parses_as_the_whole_text`), and all 56
    cases of v19 give the same output under v20. Engines before 20 are handed
    the text whole and count nothing, as they did: the auditor reads at those
    engines only an entry, and its daemon got through the file.
  - **The rest of a partly read file is its text.** Engine 18 compared the
    rest (the file without the symbols that were read) "without blank lines"
    and without the ends of lines. What a grammar did not read may be a text
    of several lines, where both are content: such a change gave no fact at
    all, so it needed no lease and showed in no review of the facts. From 20
    the rest is the lines as they stand; only the blank lines that touch a
    symbol taken out are left out (`beside`), since they come and go with it:
    adding a method behind a blank line is still an add and nothing else.
  - **Two scanners read a byte as a `char`,** which is signed on x86-64 and
    macOS and unsigned on Linux on ARM, so one file gave two trees by the
    target Lonca was built for, and an auditor on one could not recompute
    what a daemon on the other signed. Ruby's kept a heredoc's word as bytes
    and compared them with characters: a word with a letter from U+0080 to
    U+00FF (`É`, `Ö`, `ç`) never ended its heredoc where `char` is signed, and
    everything behind it was the heredoc. Swift's read back the number of `#`
    of a raw string from four `char`s: from 128 on it came back as another
    number there. Both read the byte as unsigned now, in our copies (`lonca:`
    in `scanner.c`), which is what the scanners meant and what Linux on ARM
    always did.
  - That fix is not held to engine 20: the build has one copy of each scanner,
    and what the old engines gave for such a file was never one answer. An
    entry about a Ruby file with such a heredoc word, or a Swift file with a
    raw string of 128 `#`, written by a build for x86-64 or macOS, is
    recomputed differently now. None is known; `lonca-audit` names the entry
    if one exists.
  - **What is a space or a letter is not asked of the C library.** The
    scanners of Ruby, Swift, JavaScript, TypeScript, Rust, C#, C++, Kotlin and
    PHP call `iswspace`, `iswalpha`, `iswalnum`, `iswdigit`, `iswupper`,
    `iswlower` and `iswxdigit`. macOS and glibc answer for ASCII only in the C
    locale, which is the one a process has that never calls `setlocale`; musl,
    which both Linux release archives are built with, answers from Unicode
    whatever the locale. So `let a = 1` with an ideographic space (U+3000)
    behind it and a function on the next line had the function as a symbol on
    the Linux archives and not on macOS; 7 of 21 files written to try it
    differed, in six languages (run on musl, glibc and macOS).
  - On Linux the symbol engine now brings those seven functions itself
    (`crates/lonca-symbols/c/wctype.c`, ASCII only), linked whole into every
    binary that has the engine, so the scanners get them in place of the C
    library's: on musl and on glibc, with any locale. ASCII, because macOS can
    not be given another answer: its header compiles the classes into the
    scanner as a look-up in the current locale, and the grammars from
    crates.io are built with the flags their own crates choose. So **nothing
    in a process with the symbol engine calls `setlocale`**; `tests/classes.rs`
    holds every code point to ASCII's classes on the build it runs on and
    nine files to their trees, and acceptance A42 runs on every release
    archive.
  - The price: a space or a letter past ASCII is none to a scanner, also
    where the language says it is one (JavaScript takes U+3000 for a space).
    Such a file has a parse error on every build now, and from engine 18
    that costs the definition it is in, not the file. Inside strings and
    comments nothing changes: the scanners do not look there.
  - Not held to an engine either, for the same reason as the two scanners:
    an entry about such a file written by a Linux archive is recomputed as
    macOS always read it.
  - It widens the one exception of "Grammar updates": a scanner fault that
    makes a parse depend on the build target is fixed in our copy, as one a
    file can abort or overread with is. Upstream has both as they were
    (read 2026-11-11).
- **The cost of a merge grows with the file**, in every engine. Going through a
  list for each symbol, node or change made a merge of 300 KB take minutes.
  What did that now has a look-up (`Cuts`, `Namespaces`, `neighbours`,
  `names_of_both`), and each is held to the plain walk it replaced by a test.
  Their output is the walk's, so no engine changed for them: the frozen corpus
  and the golden logs still pass, and v13 of the corpus is v12's.

## Batches in the merge queue

With `[queue] batch_size` above 1 (default 1, as before; at most 64) the worker
merges the changes at the head of the queue on top of each other and verifies the
result (issue #49). Ten changes in batches of five verify twice.

- **Only the tip is verified, and trunk moves straight to it.** The promise that
  every state that enters trunk was verified on that state holds as it stands: the
  commits inside a batch are in history and were never trunk, so they are no base
  for a proposal and appear in no trunk line. The owner chose this over verifying
  each state, which keeps the same words at the cost of the CPU batches are for.
- **One log entry integrates a batch.** With one entry per change a crash between
  them would leave the log naming a trunk nobody verified, and `reconcile()` would
  restore it. `change.integrate_batch` is all or nothing, and each change in it has
  the commit it merged to, for `undo` and for the auditor, which recomputes them in
  order and checks that the evidence is of the tip's tree.
- **A failure halves the batch.** A prefix of half the size is tried next, down to a
  change alone, which goes the way it always did, so a failing one is logged as
  before. What a failed batch leaves stays in the queue in its order. This finds
  a prefix that passes, not the longest: a bad fifth change lands two, and the next
  pass goes on from there. A conflict ends a batch, and so does a change that can
  not be merged or verified at all: the changes ahead of it do not wait for it. What
  decides that a tip passed is the code `decide()` uses, so a batch that would be
  denied is not logged.
- **A change is the proposal it was when work on it began.** While the worker verifies
  off the lock a change can be withdrawn and proposed again with the same id. Its
  commit and base are compared too before anything is logged.
- **A path that would be both a file and a directory is a conflict** on that file:
  two changes can each be fine and leave it, no tree can hold it, and with no entry to
  record it the queue would stop there. No older entry can hold such a case, since
  none could be written, so this takes no engine.
- **With batches on, a tree that passed is not verified again.** The daemon keeps the
  checks that passed by repository, tree and verification settings, in memory, for
  the last 256 trees and for an hour at most: what a check ran on is more than its
  tree, and a toolchain can change under a daemon that runs on. So this trades some
  of that for the runs bisection would repeat, which is why `batch_size = 1` keeps
  none and verifies everything as before. A failure is not kept, since it may have
  been the machine. What is reused is logged again with `reused = true` in its
  details. Syntax is always checked: it depends on what changed.
- **`undo` of a batch** is one revert of all of it, from the trunk before it to its
  tip, naming its last change in `revert_of`. Only the batch whole was verified, so a
  tree between two of its changes may fail, and two reverts could leave trunk there:
  the worker takes the first alone, and the second is refused after the command has
  said it is done. So an undo goes whole or, when a later change is in the way, not at
  all. `revert-storm` counts it once, over every symbol it touched, because one person
  undid one entry. It is one change to the limits too, so a batch larger than
  `max_files` can not be undone in one step. `lonca revert --actor` takes back only
  that actor's changes, each its own revert as it is outside a batch, and goes on past
  a refused one.

## The language table

What a language's syntax means to the symbol engine is data (issue #114):
`crates/lonca-symbols/src/languages.toml` says which grammar reads which
extension and which nodes are definitions, imports, attachments, groups and
tests. `extract.rs` has no arm per language any more, and `Lang` is a handle on
a table entry, not an enum.

- **The table is part of the engine.** The auditor recomputes from it, so it is
  built in with `include_str!`, never taken from a policy or a file beside the
  binary, and a change to what it says about a language that shipped is a new
  engine with the rule gated by `since`. A new language has `since` of its own:
  `Lang::detect_at(engine, path)` leaves it unread by older engines, so an old
  entry's facts come out as they were.
- **A rule's `how` is mostly data, and a few are shapes.** `leaf`, `members`,
  `inner` and the like work for any grammar. `implementation`, `macro_call`,
  `assigned`, `function_pair`, `blocks` and `object_set_to` are syntax one family
  has, written once as code and chosen by the table. They are named for the
  syntax, not the language, so another grammar can use them.
- **The grammar is the hard limit.** A tree-sitter grammar is compiled code, so
  `lang::grammar` has one line per grammar and a new grammar needs a release.
  Loading them at run time (WebAssembly, never native code from a policy) needs a
  design for pinning them, because a grammar's hash would become part of the
  engine. Until then `[leases] unparsed_files` covers every language with none.
- **Ruby's grammar is our own copy** (`crates/lonca-tree-sitter-ruby`, 2026-11-10).
  The fuzzer's `parse` target found that tree-sitter-ruby 0.23.1, the last on
  crates.io, aborts the process on a heredoc word longer than 255 characters:
  its scanner saved the length in one byte and asserted when reading the state
  back, and `cc` builds C with assertions on. A state of exactly 1025 bytes also
  wrote one byte past tree-sitter's buffer and failed tree-sitter's own
  assertion. Any Ruby file an agent proposed took the daemon down, and any entry
  carrying one the auditor. Upstream fixed both (`ad907a69`, March 2026) and has
  not released it, a `[patch]` does not reach `cargo install lonca`, and a git
  dependency is refused (`deny.toml`), so the grammar is copied into the
  workspace and published with it. The fix is its own, smaller than upstream's:
  a long word is written as a 0 (no heredoc word is empty) and its length in two
  bytes, the bound counts every byte, and the reader stops at the end of the
  state instead of asserting. Every state the old scanner saved and read back
  correctly is saved in the same bytes and dropped at the same size, so every
  file it parsed parses the same, and this is no new engine: it applies to every
  engine version, since the old engines' output on these files was an abort.
  The other grammars' scanners were read for the same mistake (C#, C++ and
  Python assert, unreachably). When upstream releases a fixed version, going back
  is a grammar update like any other: a new engine if its output differs.
- **Swift's grammar is our own copy too** (`crates/lonca-tree-sitter-swift`,
  2026-11-10), by the rule below ("Grammars are not chased": a read or write
  past a buffer is copied with the smallest fix). tree-sitter-swift 0.7.4, the
  last on crates.io, read past a string when a file ended in a compiler
  directive (`#if`, `#elseif`, `#else`, `#endif`): the scanner compared the end
  of input, a 0, with the 0 that ends the directive's name and took it for
  another matching character. AddressSanitizer reports a global-buffer-overflow
  in `find_possible_compiler_directive`; without it the read is the first byte
  of the next string in the binary, which stops the loop, so we found no build
  in which it faults. It is still a read past a buffer on any file an agent
  proposes, in the daemon and in the auditor. Upstream fixed it in `0c5444e`
  (2026-10-10) and has not released it; the copy is 0.7.4 with that change
  alone, not upstream's later commits to `switch` cases. The byte read never
  changed the result (a directive that had matched in full stayed the match
  whatever the byte was), so every file parses the same and this is no new
  engine. The fuzzer runs without a sanitizer (`-s none`) and could not see
  it; a regression input of a file ending in a directive is in
  `fuzz/regressions/parse/`. Going back to tree-sitter-swift when 0.7.5 is
  released is a grammar update like any other.
- **`strict_until` says what a parse error means.** For a language that shipped
  before the table it meant the file is wrong, and verification failed it, up to
  engine 17 (`strict_until = 17`); from there on, and for the seven of engine 10
  from their start, the error may be the grammar's, as with Kotlin's on a
  member and `}` on one line, a C macro, or syntax newer than the grammar. Such a
  file counts as one no parser
  reads: the syntax check passes it, the merge goes by lines and facts list it, so
  it does no worse than with no grammar at all (from engine 18 it does better:
  the symbols the error is not in stay, see "Symbol engine versions"). `syntax_errors` still reports it.
  Only a file the grammar could not read before counts. No file gets there unseen:
  a proposal that leaves unreadable a file that read until then, by a syntax error
  or by bytes that are no text, or that adds such a file, is listed in `unread_files`
  (log format 16) and escalates, as `tests_weakened` does. From then on facts can not
  see into the file, its symbols need no lease under `optimistic` and a deleted test
  does not show, so a person has to agree. An edit also takes the `<file>` lease.
  Valid code the grammar can not read goes through the same door, which is the price
  of the rule. At integration a trunk that reads must still read: a proposal on an
  older base that did not is a conflict unless the result reads. A repair on such
  a base has no facts to go by, and a person agreed to that base once.
  Strictness decides facts and merges, so changing it for a language is a new
  engine, which is why it is written as the engine it ends at.
- **`.h` goes to the C++ grammar,** which reads nearly all of C, and a file it can
  not read falls back as above.
- **Limits of the first entries:** declarations of several names go by the first
  (`int a = 1, b = 2;`, Swift's `var b, c` and `case a, b`). In Ruby `private def`
  is part of the class's text and `class A::B` keeps its `::`. A PHP function's
  signature leaves out `function`. Reopened Ruby classes and Swift extensions of
  one type are numbered, and a C++ method defined outside its class is `C.m`, the
  same name as its declaration in the class, so in one file they are `~2`, and in
  a namespace it keeps the namespace in its name where the class does not. A
  forward declaration is no symbol. Tests are found by markers in the table: C and
  C++ share the rule for `TEST(..)`.
- **Engine 10 also holds a merge to what all three sides have:** a symbol or an
  import in base, ours and theirs must be in the result, which is what catches a
  merge that loses text in a way that still parses. A name with a number, or one
  that has a numbered sibling, is left out: the number moves with its siblings.
- **Heuristics that hold across grammars stay in the code:** `TYPE_KINDS`,
  `is_verbatim`, and the names `parameters` and `type_parameters` in a key.
- **A word the table gets wrong would read as a kind that never comes,** so a
  test checks every kind and field in it against the grammars that use it.

- **What each grammar does not read is a file, held by a test** (#247). A
  grammar is older than its language, and until now the gap showed only when an
  agent's valid code came back unread. `crates/lonca-symbols/tests/corpus/` has
  a few lines of each piece of syntax that the recent versions of every language
  of the table brought (`<language>/<version>-<feature>.<ext>`, each with a
  definition in it), and `tests/corpus.rs` reads them with the current engine.
  - `known.txt` is what came out: the symbols of each sample, or `error` and the
    line where the grammar stopped. The test writes it (`LONCA_CORPUS=write`)
    and fails when it differs, so a grammar update shows as a diff of that list,
    a gap can not open unseen, and one that closes has to be written down.
  - A sample has one new thing in it. Where a first sample did not read, it was
    cut down until the line of the error was the feature's: C#'s list patterns
    read and a slice with a subpattern (`.. var rest`) does not; C23's
    `enum e : int` reads and `enum e : unsigned char` does not.
  - "Reads" means symbols too: a sample that reads and gives no symbol fails.
    A definition that is read and gets no symbol of its own is named in
    `corpus.toml` (`no_symbol`), and the test fails once it is one, until the
    entry goes. The first run had three (Python's `type` statement, a C++
    concept, a Swift macro); engine 19 named them, and the list is empty.
  - The page of the guide (`docs/guide/languages.md`) ends with the same list as
    a table, written and checked by the same test, so the site can not say
    something else than the build does.
  - The samples were compiled where a compiler was at hand (Rust, Python,
    TypeScript, JavaScript, C#, Go, Java, C, C++, Swift). Not compiled: Kotlin,
    PHP and Ruby (written from their documentation), and C++26's contracts and
    reflection (no compiler here has them yet).
  - This is not `tests/engine/`: that one freezes what old engines gave and is
    never edited; this one says what the current engine reads and is rewritten
    with every grammar update. Titles and the grammar's crate are data
    (`corpus.toml`), the version is read from `Cargo.lock`, and a language of the
    table with no samples fails the test.
  - Found by the first run (2026-11-10, engine 17), 29 of 210 samples not read:
    Rust `unsafe extern`; Python type parameter defaults and `lazy import`;
    TypeScript variance annotations, `export type *` and `import defer`; six in
    C# 11 to 14; Go generic methods; Java 25's module imports and flexible
    constructor bodies; three in Kotlin 2.1 and 2.2; four in C23; seven in
    C++20 to 26. Nothing was found in TSX, JavaScript, Ruby, PHP and Swift.
    Closing them is the grammar round (#248; "Grammar updates" below).

## Grammar updates (#248)

A grammar update is the only way a language's new syntax reaches the symbols,
and nobody watched the grammars: an update happened when someone thought of
it. It is a routine now, with a table that a script writes and steps a pull
request has to show.

- **Where every grammar stands is one command.** `.github/scripts/grammars.sh`
  prints, for the library and each of the thirteen grammar crates (fourteen
  grammars: TypeScript's crate has TSX too), the version in `Cargo.lock`, the
  newest on crates.io, the newest tag upstream and what upstream has past that
  tag. It reads crates.io and the GitHub API and sends nothing of this
  repository. The table of 2026-11-10:

| Crate | In the build | crates.io | Upstream tag | Upstream past the tag |
| --- | --- | --- | --- | --- |
| `lonca-tree-sitter-ruby` | 0.2.2 (our copy) | 0.23.1 (2024-11-11) | v0.23.1 | commits: 4; changed: src/scanner.c |
| `lonca-tree-sitter-swift` | 0.2.2 (our copy) | 0.7.4 (2026-10-04) | 0.7.4 | commits: 7; changed: grammar.js, src/scanner.c |
| `tree-sitter` | 0.27.1 | 0.27.2 (2026-11-07) | v0.27.2 | - |
| `tree-sitter-c` | 0.24.2 | 0.24.2 (2026-04-22) | v0.24.2 | nothing |
| `tree-sitter-c-sharp` | 0.23.5 | 0.23.5 (2026-04-14) | v0.23.5 | commits: 5; changed: grammar.js, src/scanner.c |
| `tree-sitter-cpp` | 0.23.4 | 0.23.4 (2024-11-11) | v0.23.4 | commits: 41; changed: grammar.js |
| `tree-sitter-go` | 0.25.0 | 0.25.0 (2025-08-29) | v0.25.0 | commits: 2, none to the grammar |
| `tree-sitter-java` | 0.23.5 | 0.23.5 (2024-12-21) | v0.23.5 | commits: 6, none to the grammar |
| `tree-sitter-javascript` | 0.25.0 | 0.25.0 (2025-09-01) | v0.25.0 | commits: 2, none to the grammar |
| `tree-sitter-kotlin-ng` | 1.1.0 | 1.1.0 (2025-01-09) | v1.1.0 | commits: 1, none to the grammar |
| `tree-sitter-php` | 0.25.1 | 0.25.1 (2026-10-06) | v0.25.1 | nothing |
| `tree-sitter-python` | 0.25.0 | 0.25.0 (2025-09-11) | v0.25.0 | commits: 1; changed: grammar.js |
| `tree-sitter-rust` | 0.24.2 | 0.24.2 (2026-03-27) | v0.24.2 | nothing |
| `tree-sitter-typescript` | 0.23.2 | 0.23.2 (2024-11-11) | v0.23.2 | commits: 5, none to the grammar |

- **What a grammar update's pull request shows.** Dependabot proposes the
  bump (weekly, a week after the release); a person may do it sooner. Before
  it merges, the pull request says:
  1. The corpus diff: `LONCA_CORPUS=write cargo test -p lonca-symbols --test
     corpus`, then `git diff` of `known.txt` and of the table in
     `docs/guide/languages.md`. Every line that moved is named: a gap closed,
     a gap opened, a symbol that changed.
  2. The pinned engines: `cargo test -p lonca-symbols --test engine` and the
     golden logs (`cargo test --workspace`) pass with no snapshot edited.
  3. The `parse` fuzz target on the new grammar, five minutes locally or
     `gh workflow run fuzz.yml --ref <branch> -f targets=parse,merge`.
  4. The grammar's scanner, if it has one and it changed: read for what
     Ruby's did (a length kept in fewer bytes than it can have, an `assert`
     on input).
  5. Whether it is a new engine, by the rule below.
  6. The release notes, and the table above written again by the script.
- **A grammar that reads differently is a new engine, and that is not solved
  yet.** The build has one copy of each grammar crate, so every engine reads
  with it. An update where nothing of steps 1 and 2 moves is no new engine and
  merges as a dependency update. One where the corpus list moves is not safe
  even with the pinned engines green: facts are recomputed by the auditor, so
  an old entry about a file the old grammar could not read would be
  recomputed with one that can, and no longer equal what was signed. Keeping
  it equal takes both grammars in the build, the old one for the old engines,
  or another answer; none is built. Such an update waits and is talked
  through when it comes.
- **Grammars are not chased (decided 2026-11-10).** When upstream is ahead
  of crates.io we wait for the release: no grammar is copied into the
  workspace to close a gap in syntax, and no language is added, until
  somebody asks for it; then it is decided for that case. The gap is made
  cheap instead: from engine 18 a file with syntax its grammar does not read
  keeps every symbol the unread part is not in ("Symbol engine versions").
  The one exception stays Ruby's: a fault a file can cause (an abort, a read
  or write past a buffer) that upstream has fixed and not released is copied
  with the smallest fix. Since engine 20 it also holds for a fault that makes
  a parse depend on the target it was built for ("Symbol engine versions"),
  fixed upstream or not: the copies were there already.
- **The first round (2026-11-10) updated nothing, and closed none of the 29
  gaps of the corpus list:** every grammar crate is at its newest release.
  What stands behind:
  - `tree-sitter` 0.27.1, with 0.27.2 three days old: left to Dependabot's
    week. Tried here: the pinned engines and the corpus list do not move.
  - C#: upstream has C# 14 (extension blocks, compound assignment operators,
    slice subpatterns) since 2026-06-02 and no release; a release was asked
    for on 2026-10-09 (tree-sitter-c-sharp issue 443). It changes the tree of
    code that reads today too (a bare `..` in a list pattern becomes a node),
    so its release will be a new engine.
  - C++: 41 commits since 0.23.4 of November 2024 (modules, deducing `this`,
    reflection, expansion statements), releases asked for since 2025-11.
  - Swift: three fixes since 0.7.4 (2026-10-04), in the scanner and in
    `switch` cases; the author releases every few months. The scanner's fix
    is a read past a string, and our copy has it (above); the two to
    `switch` cases wait for the release.
  - Python: one commit, a supertype and no syntax. Ruby: our copy has what
    upstream's unreleased commit fixes.
  - Rust, TypeScript, Go, Java, Kotlin and C have gaps in the corpus list
    that upstream does not read either. Kotlin's grammar
    (`tree-sitter-kotlin-ng`) has had no grammar change since January 2025.
  - What upstream's unreleased C# and C++ would close was read from their
    grammar sources, not measured: they were not built here.

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
  kept its older, looser check until log format 28, which tightened it
  for new entries only; entries before it replay under the loose check.
- **Escalated key operations are checked again on release.** A policy may
  send a key operation to approval. The approval that releases it denies
  the release if the operation would now revoke the last human, or if its
  new key has meanwhile become someone's key.
- **Frozen repositories** still accept the key operations: replacing or
  withdrawing a key is how a human answers an incident, and recovery is
  the only way back in when the key that would unfreeze is lost.
- **CLI.** `lonca human rotate|recover --repo a,b` takes every repository
  the human is enrolled in, because the local key is shared between them.
  The new key waits next to the current one (`<name>.next.key|se|sk`) and is
  installed only after every repository accepted it; a rerun skips the
  repositories that already use it. The old key file is kept as
  `<name>.key.retired-<ms>`.

### Security keys (#17)

Design §5.4 asks for a FIDO2 security key where there is no Secure
Enclave. Decided 2026-11-10:

- **OpenSSH is the helper.** `ssh-keygen -t ecdsa-sk|ed25519-sk -O
  application=ssh:lonca` makes the credential and `ssh-keygen -Y sign -n
  lonca` signs, with a touch each time. Lonca links no USB, HID or FIDO
  library: the core and the gatekeeper stay free of device code, the
  program that talks to the device is one the distribution already ships
  and patches, and a key works wherever OpenSSH's does. The alternative, a
  helper of our own on libfido2, would be a second implementation of what
  `ssh-keygen` does, with its own packaging on every distribution.
- **Lonca only verifies**, in pure Rust in `human.rs` (`sk`): the SSHSIG
  blob (PROTOCOL.sshsig) and the signature a security key makes
  (PROTOCOL.u2f). The human key is the raw public key (`sk-p256`: the
  65-byte uncompressed point; `sk-ed25519`: 32 bytes); the signature is the
  blob in hex. Everything in the blob is checked and nothing is skipped:
  version 1, the enrolled key and no other, the application `ssh:lonca`,
  the namespace `lonca`, an empty reserved field, `sha512` or `sha256`,
  minimal `mpint`s, no byte after the end. So a signature has one
  encoding, which the fuzz target `signature` holds the reader to.
- **Presence is the device's "user present" flag**, which is part of what
  it signs. A signature without it is `bad_human_signature` whether or not
  the repository requires presence: a key made with OpenSSH's
  `no-touch-required` is not a way to sign here. `ssh-keygen -Y verify`
  accepts such a signature; this is the one place Lonca is stricter than
  OpenSSH, and the test `openssh_agrees` pins both answers.
- **The application is Lonca's own** (`ssh:lonca`), so a key made for
  logins does not sign Lonca operations, nor the other way round. One
  namespace serves operations and logins: what is signed names its own
  purpose, as with the other kinds of key.
- **A kind of key is what the enrolling human says it is.** The log does
  not check an attestation that a key lives in hardware, for `sk-*` as for
  `p256-se`. `human::ALGS` is the one list of kinds: name, whether its
  signatures prove presence, first log format, the form of its public key
  and its verifier. `decide()`, the daemon's `repo.prepare_init` and
  `lonca doctor` ask it; a new kind is a row there and a log format.
- **The key shows nothing.** Touch ID names the operation; a security key
  blinks. `lonca` prints what the touch is for before it asks. A process
  running as the human can start a signature of its own and hope for the
  touch (threat model, "Humans and approvals"); the signature it gets is
  for one operation, logged, with a nonce.
- **CLI.** `lonca human keygen|rotate|recover --security-key[=ecdsa|ed25519]`;
  the handle is `<humans>/<name>.sk`, with no passphrase: it signs nothing
  without the device, and a passphrase prompt on every signature would
  train the hand that the touch is meant to slow. `LONCA_SSH_KEYGEN` names
  the program. `lonca doctor` reports under `presence` what the human's
  key proves and what the machine could use.
- **How it was verified.** The project has no security key yet. The tests
  build blobs field by field from the two OpenSSH documents, pin two
  signatures byte for byte, and where `ssh-keygen` is installed ask it
  (`-Y verify`, OpenSSH 10.5 at the time) to accept what the verifier
  accepts. The CLI is tested end to end against a software stand-in for
  `ssh-keygen`. `LONCA_SK_CHECK=<dir>` runs the verifier over a key and a
  signature made by a physical device; that run is still owed.

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
- **A lost Mac** (log format 27). The daemon key and the human's key were
  on one machine, so after a restore neither `human.recover` (the daemon
  can not sign for the log) nor a plain `daemon.recover` (no human key
  left) is possible. `daemon.recover {key, recover: {human, key}}` is the
  way back with the recovery key alone: signed by the new daemon key and
  by that human's recovery key, it re-anchors the log and installs the
  human's new key, with the effects of both operations (every session
  ends; the old key and the recovery key are retired). It is decided like
  `human.recover`: only the human's own recovery key signs it, with the
  same presence exemption, and the new human key is checked like any new
  key. Like `human.recover` it needs no session; refused, it writes
  nothing. A recovery key now carries the power any enrolled human key
  already has here: whoever holds it and a copy of the log can re-anchor
  that copy on a daemon of their own. That fork is visible to every
  auditor of the original, and the same file already lets its holder
  replace the human's key on the live daemon, so the recovery key stays
  what it was: keep it off the machine, and replace it after use.
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
- **A clean report is kept (issue #189).** It used to clear the mark, so a
  clean stop and no report both read `null`, and a client deciding whether a
  dead session's workspace could go had to ask with a live token. Now it
  leaves `total: 0` and `rounds: 0`; `null` is "nobody said since the session
  began or last proposed". It costs one entry per proposal at most, since an
  unchanged report is not written. No log format: the fold changed, not a
  decision, and an older log's clean reports now read as clean too.
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
  to propose again. It costs a round; the new proposal replaces the old
  one (#107).
- **OpenCode is sent back from `experimental.idle` (issue #124).** It has no stop
  hook, and watching for `session.execution.succeeded` was too late: the event says
  the turn is over, `opencode run` left at once with the prompt unanswered, and the
  mark stayed. The runner fires this hook before it decides, and a message waiting
  in the session's inbox after it means another step. OpenCode's own goal feature
  goes on the same way. The hook sends a `synthetic` message, as goal does, since
  these are not a person's words. It leaves out a session with a `parentID`, and one
  waiting for a subagent: both have stopped nothing. The name is experimental; losing
  it costs the reminder, not a control, as above.
- **`opencode run` is not stuck, it is reading.** It reads stdin to its end before it
  starts, so an open pipe holds it with no output: `</dev/null` ran 5 of 5, an open
  pipe stalled 3 of 3, and closing the pipe at 12 s let it finish at 15. Neither
  Lonca's setup nor the provider plays a part, and a directory with no Lonca stalled
  too. `lonca run` passes stdin on, so a command it runs waits the same way; that stays
  as it is, since a command may need the input, and the guide says `</dev/null`.
- **Tool names of OpenCode 2.2.5.** Its `patch` and `subagent` were unknown tools, and
  so tainted. `apply_patch` and `task` stay for older versions.
- **Seen working (2026-11-07).** OpenCode 2.2.5 on a free model, told to edit and
  stop: it said done, was sent back, leased, proposed, and the next stop was clean,
  both plain and under `lonca run` (`level: isolated`, log order: `unproposed`,
  `lease.acquire`, `change.propose`, `session.end`). A subagent's edit sent only its
  parent back.

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
| `session.where` | public | the session the log places at a path, or the one a harness's session is bound to |
| `log.head` | public | the number and hash of the last entry of a repository's log, for a human signature to name |
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
| `change.resolve` | read | the whole id of the one change a prefix names |
| `trunk.bundle` | read | a Git bundle of trunk for a checkout, thin against what it has |
| `trunk.distance` | read | how far a former trunk commit is behind |
| `human.prepare_change` | human | builds a commit for a human change |
| `human.prepare_policy` | human | writes a policy commit |
| `human.prepare_import` | human | `git fetch` from a remote |
| `human.prepare_push` | human | the push operation to sign |
| `human.prepare_isolate` | human | what a sandbox is built from: scratch roots and proxy |
| `human.submit` | human | a signed human operation; what the recovery key signs needs no session |
| `lease.acquire` | agent | |
| `lease.release` | agent | |
| `lease.renew` | agent | |
| `lease.interest` | agent | |
| `events` | agent | |
| `inbox` | agent | |
| `events.watch` | human | what happened to the sessions the human started, held until something did; marks nothing as told |
| `change.propose` | agent | |
| `change.withdraw` | agent | |
| `facts.preview` | agent | |
| `negotiate` | agent | |
| `cap.attenuate` | agent | |
| `session.end` | agent | |
| `session.rotate` | agent | a new token for the caller's session; the old one stops |
| `session.heartbeat` | agent | |
| `hook.event` | agent | |
| `hook.input` | agent | |
| `hook.bind` | agent | |
| `hook.stop` | agent | |
| `mcp.call` | agent | `lonca mcp` names the tool it runs; a call with no hook event marks the session |
| `harness.setup` | agent | |
| `queue.run` | any human | drains every merge queue now |
| `security.events` | any human | the security log of the last day, of the human's repositories |

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
  submit someone else's signed operation. One exception: what the
  recovery key signs (`human.recover`, and `daemon.recover` with
  `recover`) needs no session, because the key that would open one is the
  key that was lost; its recovery-key signature is the credential, checked
  by `decide()` like any other.
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
  The CLI refuses a directory that is not itself a workspace, one the log
  places no session in, and a workspace of another repository, before
  asking for a signature. From format 30 the session to continue is the
  log's ("Where a session works is in the log").
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
  still there. From log format 23 the same holds when the child expires or
  misses its heartbeat (see "A delegated lease comes back (#40)"). A
  revocation of the parent reaches the child and the sets. Only
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
the file before asking. `tree` asked for contents (`with_content`, which
Lonca's client does not send) is held to the same page since 2026-11-11:
it used to read and encode every blob of the commit and meet the line cap
afterwards, so the daemon held the repository in memory to refuse it. The
sizes are added up before a blob is read. `repo.prepare_init` reports files above the
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

## CI runs on every pull request

The tests (`ci.yml`: Ubuntu, macOS and the bubblewrap `sandbox` job) run on
every pull request to main, every merge to main, a pushed `v*` tag, and on
demand; a newer push to the same pull request cancels its older run. The
main ruleset requires the three jobs (`test (ubuntu-latest)`,
`test (macos-latest)`, `sandbox`, from GitHub Actions) as status checks, so a
pull request merges only once they are green, and `gh pr merge --auto` waits
for them. The branch need not be up to date with main first (no strict
policy): a rebase per merge would cost a full run each time. Mutation
testing is not in CI at all (since 2026-11-11, "Mutation testing").
`cargo-deny`, CodeQL and zizmor still run on pull requests and block nothing.

History: from 2026-11-08 (#172) to 2026-11-09 the tests too ran only for a
release. That went further than asked: the decision was to take the
mutants, not the tests, off pull requests. It is reverted here.

## Mutation testing

Passing tests do not show that they would catch a flipped `>=` or a
`decide()` arm replaced with `Ok(Allow)`. Mutation testing measures that.

- **By hand only (2026-11-11, user's decision).** Nothing runs mutants any
  more: `mutants.yml`, its runner action, `mutants-gate.sh`, the list of
  gated files with its list of exclusions, and `lonca-mutants` are gone, and
  no rule asks for a run after a change to a given file. We run
  `cargo mutants` locally, on a file or a diff, when a change calls for it
  (CLAUDE.md has the commands). `.cargo/mutants.toml` stays: its timeouts
  and its reasoned exclusions are what a run by hand needs. Even on demand
  the workflow was a habit, run after every change to a gated file, and it
  waited on a runner for what a local run on one file tells in minutes. The
  bullets below are the history: the on-demand workflow of 2026-11-09 and
  the gate of #35.
- **Tool: cargo-mutants** (27.1.0, pinned with `--locked` and an explicit
  version). It needs no code changes or annotations, reads
  `.cargo/mutants.toml`, and supports `--shard` for splitting a full run.
- **On demand, on the gated files' changes only; it gates nothing
  (2026-11-09, user's decision).** `mutants.yml` runs only when started by
  hand. It mutates the gated files (below) and only what changed in them
  since the last `v*` tag, each mutant against the whole workspace. No
  release, pull request or merge waits for it. Before this, every release
  and every night ran the whole workspace in 20 shards: 5,669 mutants at
  about 60 s of build and 90 s of tests each, some 180 hours of runner time,
  and shards hit the six-hour limit so a run never finished and blocked
  0.2.2. What it bought did not pay for that: of 47 commits that answered
  mutants, nearly all only added tests (about 23,000 lines under `tests/`),
  and the behaviour they changed was minor (the CLI inventing a session
  expiry the daemon left out, a merge corner). The real bugs of the same
  weeks (SIGPIPE panics, the proxy's `::1`, the parser's blow-up, the review
  findings) came from use, fuzzing and review. Mutants are kept where a
  silently weakened test would hurt most, the trust model, and there the
  diff since the last release is small (31 mutants for 0.2.1..main, minutes
  of runner time). Measured and rejected as not enough on their own: no
  debug info (no faster to rebuild), running fast tests first (about 40 %
  off the test half), two stages with results kept (#147's setup). Given
  up: a test weakened outside the diff, or a callee change that stops a
  test reaching a gated function, goes unseen until someone runs
  cargo-mutants on that code. `lonca-mutants`, which kept the PR stages'
  results, has no caller in CI.
- **`nextest` runs the tests of a mutant** (`test_tool`), still the whole
  workspace. `cargo test` goes crate by crate, so a mutant in `lonca-symbols`
  waited for the daemon's and the CLI's tests before its own could catch it.
  nextest stops at the first failure, so only a survivor pays for a full run.
  Doctests do not run with it. The only ones are the README examples of
  `lonca-client` and `lonca-net` (their crate docs, `include_str!`), which
  `cargo test --workspace` in `ci.yml` runs; they show usage and kill no
  mutant, the crates' own tests do.
- **Timeouts** are at least `minimum_test_timeout = 600` s, three times a
  workspace test run on CI. A timeout counts as caught, so a shorter limit lets
  a survivor on a busy runner pass as caught; 300 s was one and a half times a
  real run, though it was written as five. The limit can not come from the
  measured baseline: with `--in-diff` it runs `--package` of the changed crates
  while each mutant runs `--workspace`, so a PR on one crate measured ~1 s and
  got the old minimum of 60 s. A mutant in `lonca-symbols` was then cut off in
  the daemon's tests, before its own, and counted as caught with no test having
  looked at it. A mutant that hangs the daemon or a socket test ends as a
  timeout, which counts as caught, so a shard with more timeouts than caught
  mutants fails.
- **Exclusion policy.** `exclude_re` lists only mutants shown to be
  equivalent (no test could tell them apart from the original) or
  irrelevant (text that no caller reads), each with a comment giving the
  reason. Nothing in `decide.rs`, `chain.rs`, `state.rs`, `oplog.rs`,
  `canonical.rs`, `changeid.rs` or `keys.rs` is excluded without review.
  A surviving mutant is otherwise killed with a test. "Hard to test" is
  not a reason to exclude.
- **The gate on the trust model's files (#35).** `.cargo/mutants-gated.txt`
  lists the files that hold the trust model: `decide.rs`, `chain.rs`,
  `state.rs` and `human.rs` of `lonca-policy`; `oplog.rs`, `canonical.rs`,
  `changeid.rs`, `keys.rs`, `paths.rs` and `keyed.rs` (keyed directories,
  #261) of `lonca-core`; all of
  `lonca-audit`; `merge.rs` and `integrate.rs` of `lonca-symbols`. They are the
  only files `mutants.yml` mutates. A timeout counts as caught, but in a
  gated file it fails: it is a
  loop no test ends or a test too slow to tell, and either hides whether the
  mutant was found. Every exclusion in a gated file is listed by name
  (path and mutant, no line) in `.cargo/mutants-gated-exclusions.txt`; the
  run's `exclusions` job compares that list with what
  `cargo mutants --list` with and without the config tells apart, so a new
  regex that happens to hide a gated mutant fails until it is listed, and
  the listing shows in review: CODEOWNERS names an owner for `.cargo/` and
  `.github/`, so a change to the config, either list or the script asks for
  that owner's review. The `score` job
  prints each crate's score and the gated files' from all shards in the
  run's summary. The issue asked for the gate on the PR job and for a floor
  under the scores of `lonca-policy` and `lonca-core`; the PR job is gone
  (mutants run only on demand), and with no survivor allowed in the gated
  files a floor below 100 % checks nothing more.
- **Tests are hermetic under mutation.** cargo-mutants runs copies of the
  tree in parallel. Tests use their own temp dirs, `127.0.0.1:0` ports and
  short socket paths; the CLI tests point `HOME` and `LONCA_HOME` into
  their temp dir and drop the developer's `ANTHROPIC_*` variables, so a
  mutant cannot write to the real home or reach the real API.

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

## Signature changes

A change can break code it never touches. Facts found some of that, and nothing
came of it (issue #43).

- **What is a change of signature:** see engine 11. All declarations count, public
  or not: visibility is a matter of each language, and the mistake to prefer is one
  more notice.
- **`affected` is a guess, and says so.** Facts list the symbols of the base that
  mention by name what the change gives a new signature, renames or deletes.
  Tree-sitter, no resolver, so the auditor recomputes it and a language needs no
  rules of scope: a mention of `run` may be another `run`, and a call through a
  variable or a macro mentions nothing. Precise analysis is still a later phase.
- **A mention** is a token that names something: `identifier` in its kind, or
  `names` in the language table (`constant` in Ruby, `name` in PHP). Comments,
  strings and imports are none. A declaration of the name is one: an implementation
  of a trait method has to follow it, and telling that from an unrelated `run` takes
  a resolver. It is reported as the unit a lease names: the innermost symbol,
  `Type.<def>` for a type's own text, `<module>` for code outside symbols.
- **A name is looked for as code writes it.** `constructors` in the table are reached
  by their type (`__init__`, `constructor`, `initialize`, `__construct`, `init`), and
  `marks` are what a name has around its token (`$a` is `a`, Ruby's `x=` is `x`,
  Swift's `` `class` `` is `class`). An operator is no name anyone can search for.
- **A file that can not be read for symbols counts whole.** One with a parse error,
  over 1 MiB or not UTF-8 is `path#<file>` if it holds the name as a word: otherwise
  a grammar's gap would read as "nothing mentions this", and the change would owe
  nothing and tell nobody.
- **What the change touches itself is left out**, and so are what it deletes, the
  members of that and deleted files: its author looked at those, and leases keep
  anyone else out of them. By name without keys, since one file can tell two
  symbols of a name apart on one side only. So a sibling overload of a changed
  symbol is left out too.
- **Cost.** A change that takes a name away reads the blobs of every source file
  of the base tree, under the daemon's lock, and parses only those that hold a name
  as a word (Aho-Corasick, so the number of names does not matter). Any other change
  reads nothing more.
- **Facts are capped at 1000** symbols, sorted, because they are in the log.
  `affected_more` says how many fell off, the decision repeats it, and
  `affects_others` is then true, since nobody can say it is false. Holders past the
  cap are not told.
- **The decision says who holds it.** `signature_change:<symbol>` and
  `affected_lease:<session>:<set>` for each active set of another session with an
  `edit` or `rename` item that overlaps an affected symbol. An `insert` lease holds
  no code. Facts come from the objects alone; who holds what comes from the state,
  so it belongs in `decide()` and the replay checks it. Cedar sees
  `context.signature_changes` and `context.affects_others`.
- **The holder hears at the proposal, not at the integration.** That is when
  a person or an agent can still answer, and an escalated proposal counts. Being
  told is derived from the log like every other event (`symbols_changed`), and
  pushed like a message: the agent is working on code that may stop compiling. Symbol
  names are written by another agent, so they go out as JSON, cut, under the same
  warning. A lease taken after the proposal hears nothing, and neither does code
  added to trunk after the change's base: verification on the merged tree is what
  stands behind both.
- **`on_signature_change`, not `full_on_signature_change`.** The issue asked for a
  switch that runs the full suite. The queue already runs all of `test` for every
  change, so a switch would have nothing to turn on. What a project can want is a
  command too slow for every change, so that is what it sets. It runs for a change
  with a signature change or with something affected, a batch owes it when one
  member does, `decide()` holds the queue to it (`verification_missing:extended`
  under `required`), and the cached runs of a batch are kept apart because the
  settings a run is keyed on differ. A policy from before the key has none, so
  old entries replay as they were.
- **Limits.** A deleted type's members are not looked for, only its name, which
  whoever uses them nearly always mentions; a deleted file's are. Files no grammar
  reads are not searched. A top-level `var a, b int` or C `int a, b;` that changes
  type is an edit of `<module>` or of the first name alone, not of the others. The
  modifiers in front of `public int a, b` are not in the fields' signatures. A value
  nested deeper than one declarator stays in the signature (C# `int a = 1;`,
  Kotlin), and a Rust macro call is all signature: both err towards one notice more.

## Isolated mode: `lonca run` (#115)

`lonca run --session ID -- <any command>` runs the command in a sandbox Lonca
builds. The session gets `level: isolated`, which needs nothing from a harness:
no hook, no settings file, no vendor.

- **A new operation, not `session.bind`.** The issue had `session.bind` with
  `level: isolated`, but `bind` is a daemon operation whose level is computed
  from what a hook reported. The daemon can not see a sandbox, and an agent must
  not be able to say it is in one, so the claim is a human's: `session.isolate`
  (log format 19), signed by the human who started the session, naming the kind
  of sandbox and the SHA-256 of its definition. That digest is evidence, like an
  attestation: it records what was vouched for and nothing recomputes it.
- **The level goes with a new token.** An allowed `session.isolate` replaces the
  token. The one in `.lonca/session` may have been seen by anything that ran
  before, so it stops there; the new one goes to a file outside the workspace,
  and only the sandbox is told where (`LONCA_TOKEN_FILE`).
- **The level ends with the sandbox, and starts with a clean slate.** The session
  ends when the command does, and `session start --continue` does not inherit
  `isolated`, though it inherits every other level: what continues has not been
  shown to run in a sandbox. A hook inside the sandbox can not lower the level:
  `hook.bind` answers without logging, and `decide()` refuses a `session.bind` on
  such a session. Only a session nothing has used can be isolated (`session_used`:
  a heartbeat, an observation, a lease, a change, a child, a continuation), since
  whatever it did before was done outside. So a run takes a new session in a new
  workspace.
- **Work from outside can not pass for the sandbox's.** `lonca run` compares the
  workspace with the commit it stands on as the daemon has it, ignored files
  included, and that commit must have been trunk; scratch roots must be empty.
  Nothing the workspace says about itself counts: `--session` is required although
  `workspace.json` names it, and the scratch roots come from the log
  (`human.prepare_isolate`), since an edited list, or a link in place of a root,
  would widen the sandbox. A scratch root that is not what the log says stops the run.
- **What a comparison can not read is written afresh.** Contents say nothing of a file's
  mode, attributes or dates, and `.git` and `.lonca` can not be compared with a commit
  (Lonca reads nothing in `.git`). So once the daemon has allowed the run, everything in
  the workspace is deleted and written again from what it says: the commit's files, a
  new `.git`, a `workspace.json` that keeps only the repository, session, base, scratch
  roots from the log and whether there is a `.git`, and no `.lonca/session`. Not before:
  whether a session may be isolated is decided at `human.submit`, and a refused run must
  leave a used workspace as it was. By then the files were found equal to the commit
  and the session unused, so what goes is what nothing relied on, a branch left in
  `.git` included. Lonca does this outside the sandbox, as `lonca sync` writes, and
  deleting follows no link. If it fails the run stops and the session ends.
- **What stops a run, rather than being deleted.** Anything in `.lonca` but its files,
  an empty directory (a name holds as much as a file), a name that is no UTF-8, and a
  `.git` where `workspace.json` says none belongs. That last word is the workspace's;
  changing it gets the `.git` deleted, and no content in.
- **A generated file is the setup's, not the list's.** `generated` in `workspace.json`
  once decided what the comparison skipped. Now only files the setup of the harness
  named at `session start --harness` writes stay listed, and they are written over from
  the policy (`human.prepare_isolate` gives both, so a human needs no agent token); any
  other counts as a difference. So a harness set up by hand with no name stops a run:
  `--harness` is what the human signs. A file `--no-setup` kept out stays out.
- **Nothing of the sandbox outlives its command.** On Linux the pid namespace ends with
  the command. On macOS a process that forked twice and called `setsid` is in no group
  a signal reaches, and it could go on writing the workspace with its token dead. So
  each profile allows a Mach name only that run uses, nothing provides it, and when
  the command has ended the launcher asks of every process whether its profile allows
  that name (`sandbox_check`), kills those that do, and asks again until none is left,
  before the session ends. A path can not be the mark: asked from outside, it answers
  no even for what the profile allows (macOS 27.2, measured). Also asked of a second
  name, because a sandbox that allows every Mach name answers yes to any. A sandboxed
  process can not take the mark off: `sandbox-exec` in the profile fails. Three gaps
  stay. A chain of processes that each fork and exit at once is gone before a signal
  lands (measured): the launcher gives up after about 3 s and says how many would not
  end. Such a process has a dead token and writes only a workspace whose session is
  over, and a later run refuses that workspace. If the launcher itself is killed nothing
  sweeps, where Linux has `--die-with-parent`. If `sandbox_check` stops answering, what
  was left runs on, as it did before this.
- **Not covered.** Something still running outside can write the workspace after the
  check, and attributes of the workspace's own directory stay. That is §3.1 of the
  design: one account, harder and visible.
- **The profile refuses by default.** The verifier's profile allows everything
  and closes a list, which is right for a project's own build. This one is for a
  hostile process: on macOS `(allow default)` would leave Launch Services and
  launchd open, and they start processes outside the sandbox. Tested by trying:
  `launchctl submit`, `osascript` and `security list-keychains` fail, while `claude`,
  `codex`, `opencode`, `node`, `python3`, `git` and `cargo` run.
- **Reading is closed by default too.** Only the system's own directories open by
  themselves. A list of known secrets misses the `.env` of another project, and other
  workspaces hold session tokens. What the command needs comes back by name: `PATH`,
  the program's own directory, and `--read`; none of these follow a link under a
  tree the agent can write. Lonca's stores, the daemon's directory and human keys
  stay closed, and a `--read` or scratch root that overlaps them is refused. `HOME`
  and `TMPDIR` are the run's own, and are gone afterwards; a harness that wants its
  state kept is pointed at a scratch root with `--env`.
- **Pipes, not the terminal.** The command leads a session of its own and holds three
  pipes the launcher carries, and no other descriptor. With the terminal it could
  push text into the shell that started it (`TIOCSTI`), or read what is typed next,
  and inherited descriptors are ways out no sandbox rule sees. Ctrl-C reaches it
  through the launcher. A full-screen harness needs a relayed pseudo-terminal, which
  this does not do: use its non-interactive mode.
- **Effects need no hook.** `unobserved_write` compares what hooks saw with the
  diff, so it is off at this level. The workspace against its base is what
  happened, and every check on a proposal runs as usual.
- **The agent's own host.** All of the agent's traffic goes through the proxy, its
  calls to its model included, and any connection taints. So
  `observation.agent_hosts` names hosts that are part of the agent: logged, not
  tainting, allowed even under `network = "deny"`. Exact names only. No log format,
  since the proxy decides this and the observation records it. A model's API is a
  channel out to that vendor, under any account the agent has a key for: naming a
  host is accepting that.
- **Linux has no loopback to share.** bubblewrap's `--unshare-net` leaves the agent
  no route to the proxy, so a small relay runs inside (`lonca __relay`) and the
  launcher carries each connection over a Unix socket. On macOS the profile allows
  the proxy's port.
- **Loopback on macOS is the human's to open.** Harnesses listen on it: OpenCode
  runs a local server and talks to it. Seatbelt can not tell a command's own
  listener from the machine's (measured: with the rule, a connection to a service
  outside the sandbox goes through), and some of those services do work outside the
  sandbox; on this machine that was OpenCode's own server. So `--loopback` is off
  by default, and using it changes the digest and the sandbox's name in the log,
  `seatbelt-loopback`. Unix sockets under the writable trees work either way. On
  Linux the sandbox has a loopback of its own.
- **`ps` reports nothing on macOS.** A sandboxed process can not start a setuid
  program, and programs that walk their process tree stop at that. `(with
  no-sandbox)` would let it out, but `ps` outside reads the environment of every
  process of the user, and a copy without the bit is killed for its signature. So
  a `ps` that exits 0 with no output comes first on `PATH`.
- **Requiring it.** Cedar sees `context.observation`, and now `context.task`, so a
  policy can ask for a sandbox by path or by task. No new key was needed.
- **Not built.** A container backend, which is one more `Sandbox` arm. `sandbox-exec`
  is deprecated by Apple and still ships.

## An isolated token works in its sandbox

`session.isolate` puts a token in a sandbox, and a token can be copied. So for an
isolated session the daemon asks the operating system about whoever sent an agent
request: `sandbox_check` on macOS, a pid namespace below its own on Linux. From
outside it answers `not_in_sandbox` and taints the session once, so nothing it does
integrates alone and the log says why.

- **`session.heartbeat` and `session.end` are exempt.** The launcher sends them from
  outside, and neither reads nor changes the repository.
- **Reading is held too.** The check ran for the methods only an agent may
  call, so a copied token still read the repository from outside (`status`,
  `log`, `tree`, `blobs`, `change.get`, `change.diff`, `trunk.bundle`,
  `whoami`) with nothing on the session's record. It now runs for every
  method a session's token opens. A method that needs no token (`ping`,
  `session.where`) answers a token's holder what it answers anybody.
- **A process that exited reads as sandboxed** on macOS, and it can leave its
  connection to a child, so it must also be seen alive after the answer. A zombie
  counts as gone: it has no path.
- **What this shows.** That the peer is in a sandbox, not in this one. As §3.1 of
  the design says of everything on one user account, the aim is not to make going
  around it impossible but harder and visible. It ends the plain cases: a token left
  in a file, a helper started outside by accident.
- **`sandbox_check` is not a public API.** It has been stable for years, and it
  fails closed: if it goes away, isolated sessions stop working and the taint shows.
- **Hardened mode is not measured.** A daemon of another user may not be allowed to
  ask. That also fails closed.

## The verifier runs in the jail

The merge queue runs a change's own tests, so a sandboxed agent's code came out of
its sandbox there, under a profile written for a project's trusted build: everything
allowed, a list closed, reads open on Linux. A verifier is only as strong as `lonca
run` if it is the same sandbox, so it now is: `Jail`, with no socket and no proxy.

- **This changes what existing policies do.** Builds could read the whole machine,
  and now read the system and `PATH`. A rustup toolchain under the home directory
  needs a new line, `verification.read`. It is a policy key because a change to what
  tests can read is a policy change. It fails loudly, at the first build, and the
  check stays `fail`, so nothing integrates unverified.
- **`env_passthrough` opens directories, but not `HOME`.** A policy that passes
  `CARGO_HOME=/opt/cargo` has said what it uses. `HOME` is passed for its name, so
  that tools find `~`; opening it would undo the point.
- **`TMPDIR` is the sandbox's**, even when listed in `env_passthrough`. Nothing
  else can be written, and the shared temp directories are closed.
- **No log format.** The check is evidence and its entry looks as it did.

## Harness levels

Which observation level other harnesses can reach was open since the design (§10, issue
#21). The answer, for these versions on 2026-11-07:

| Harness | Level with hooks | Evidence |
|---|---|---|
| Claude Code | H2, `hooks_sandbox` | Its documentation of 2026-10-16: managed settings, `onFailure: block`, a locked sandbox. No failure run like Codex's, and the effect of `allowManagedHooksOnly` is still to be tested (design §10) |
| Codex 0.167 | H0, `unobserved` | Run: a `PreToolUse` hook that exited 1, was killed, timed out or printed garbage let the tool run, 4 of 4. Only exit 2 blocked |
| Gemini CLI 0.67 | H0, `unobserved` | Source: `hooksConfig.disabled` merges as a union, so a project's settings turn a system hook off. All hooks stop in an untrusted folder. No setting keeps only the system's hooks |
| OpenCode 2.2 | H0, `unobserved` | Docs: a policy can deny a plugin, not require one, and "settings alone cannot stop users from adding" them. The plugin runs inside the harness |
| Cursor and others | not looked at | |

- **What H1 asks is that the hook blocks, also when it fails.** Lonca's own hook exits 2
  when it can not reach the daemon, so a healthy hook program fails closed anywhere.
  What it can not do is answer for a hook that was killed or timed out, and that is what
  Claude Code's `onFailure: block` covers. Codex's `requirements.toml` can make hooks
  managed-only (`allow_managed_hooks_only`), and its documentation calls hooks a
  guardrail, "not a complete enforcement boundary"; the run shows why. So a root-owned
  setup would not change the answer, and none was tried.
- **The way for these harnesses is `lonca run`.** It asks nothing of the harness and gives
  `isolated`, which is above H2. Hooks there still deliver news and the stop.
- **A level is data.** `locked` in a profile says which file to read, in which format, and
  what must hold in it, so a harness that gains these guarantees needs a table, not a
  release. It replaces a `harness == "claude-code"` in the daemon. The checks moved over
  with these changes, each stricter: a value in `excludedCommands` that is not a list no
  longer counts as empty, a hook group with a field other than `hooks` and `matcher`, or
  a `matcher` that is not `*` or empty, no longer counts as every tool, and the digest
  is of a file that passed. What stays in code is the shape of a hook group and that a
  Lonca hook names `lonca` and `hook`: a harness with another shape needs a change here.
- **A table that says nothing proves nothing.** An empty `sandbox` is no sandbox, and a
  `locked` is refused with no `hook_lists`, no `hooks` or no absolute `file`, and with a
  list of nothing but `is = "empty"`, which holds for a key nobody wrote.
- **A profile with no table keeps the built-in one.** `lonca harness show` and a signed
  copy is how a repository changes tool names, and before tables a level hung on the
  name alone. So it is the one part of a profile that does not go with the rest.
- **The file is checked before it is read.** A path can now come from a signed policy. A
  FIFO would hold the daemon's lock for every repository, so it must pass as root's
  first, be a regular file, and only 1 MiB of it is read.
- **A new built-in table needs a run.** A level relaxes approval, so `built_in()` has one
  for Claude Code alone, from before this rule, and a test says so.

## Naming the harness

A level says what a machine guarantees for one harness, so the name is part of the
claim. It comes from the human who starts the session, in the signed `session.start`
(`--harness`, log format 20), like the scope and the task. Only an entry of this
format can carry it, and what is signed shows it: "start agent a on src/**, under
claude-code".

- **The table is the named harness's.** `hook.bind` still says what the hook was told
  it is. A name that differs from the session's, and a session with none, read no
  table: the level is `unobserved`, with a note, and the report goes in the log as it
  came. So a session with no `--harness` is `unobserved` on any machine. That is the
  default a human opts out of, and it costs an existing setup one flag.
- **`decide()` holds the daemon to it.** From format 20 a level above `unobserved` for
  another harness than the session's is denied (`bind_other_harness`), so the auditor
  checks the rule on replay.
- **A bound level stays or falls** (`bind_raises_level`). The first report is the
  hook's, sent at the harness's start before the agent has run. A report after it can
  say the machine got better, but it comes from someone holding the session's token.
  A fix to the managed settings takes effect in a new session.
- **A child stands where its parent stands.** It takes the harness and `bound` along
  with the level: it is the one session an agent can make, and nobody signed for it.
- **A continuation reports afresh.** It is signed, so its harness binds as a new
  session does, and it keeps the old session's harness unless it names another. What
  was known of the files stays: taint and `writes` go along whatever it reports.
- **`--no-setup` names without writing.** A harness locked by an administrator has its
  hooks already, and the repository may track files setup would refuse to touch.
- **The name is a human's word.** The daemon can not see what runs on the token, and
  a person who names one harness and starts another gets the level of the first.
- **`sudo_without_password` is still the hook's report**, since only that process can
  try it. A level can not rise past the first report, so what stands is the report
  sent when the harness started.

## What a level reads in the file

- **The proxy's port is the daemon's own.** `is = "proxy_port"` compares the value with
  where this daemon's proxy listens, so a sandbox pointed at another port does not count
  as Lonca's. A daemon with no proxy has no such port, and the check holds for nobody:
  nothing watches that network. `is = "number"` stays for a value with no such meaning,
  and for tables already signed. `ping` says where the proxy is, for `lonca doctor`.
- **Every program, not one.** Each Lonca hook in each list must have its program out of
  a user's reach. A harness runs them all, so the weakest one decides.

## A session whose hooks do not run (#190)

Hooks are how Lonca sees a session, and the daemon took for granted that a harness runs
the ones it was given. A harness that skips them, by a flag, a setting or a later
version, still reaches `lonca mcp` with a valid token, and Lonca heard nothing and held
nothing against it. A client can check what its harness prints (imece waits for
`SessionStart`), but that proves the settings were read, not that `PreToolUse` fires for
each tool. Only the daemon sees both ends of a call to its own tools.

- **The proof is a pair.** `lonca mcp` names each tool before it runs it (`mcp.call`). On
  a harness whose before-tool event covers MCP tools, that event came first: the hook
  blocks the call until the daemon answers it, so the order is certain, and the daemon
  takes one event of that tool from the session's, oldest first. By name and order, not by
  a digest of the input: a harness may reshape the input between the two (Claude Code's
  `updatedInput`), and parallel calls of one tool are interchangeable anyway.
- **In memory, a miss in the log.** Each event would be an entry if the pairs were
  logged, and the log does not grow with tool calls. So events wait in the daemon (ten
  minutes, 64 per session), and only a miss is written: an `unhooked` observation, once
  per session, log format 24. From there it is the fold's, like a taint: replayed, audited,
  and still there after a restart.
- **A miss is a taint with a word of its own.** The fold taints the session (if nothing
  did before), drops it to `unobserved` and keeps the first tool. `decide()` says
  `unhooked_session` and `unhooked_critical_path` where it would say the taint's words, and
  `[taint] critical` decides a critical path, since the session is tainted. Nothing it did
  since its last proof can be taken as seen. A child made after the mark has it, as it runs
  in the same harness; a continuation reports afresh but keeps the taint, like any other.
- **Nothing is refused at the call.** The mark changes what the session's next operations
  get. Refusing the call would add little: the tools that matter are decided anyway, and
  a read-only tool refused would only hide the mark from the agent's runner.
- **Only where a run showed it.** `events.before_tool_mcp` in a profile says the event
  fires for MCP tools; it is on for Claude Code only (`PreToolUse` with matcher `*` covers
  `mcp__lonca__*`). A harness that skips the event for MCP tools would taint every session,
  so a profile is held to it only when it says so, like a `locked` table. A session with
  no harness named, or isolated by `lonca run`, is not checked: the first is `unobserved`
  already, the second is seen by its sandbox.
- **A session that never bound** is `unobserved`, which the shipped policy treats as
  tainted (`[observation] unobserved_is_tainted`), and with Claude Code its first call is
  a miss too. `status.sessions[].bound_ms` says whether it bound; `last_hook_ms` when the
  daemon last heard its hooks (in memory, so `null` after a restart).
- **A restart forgets the events.** The hook blocks its call until answered, so only a
  restart between the two loses one, and `lonca mcp` reconnects within seconds. For ten
  seconds after a start a call with no event, of a session older than the daemon, is not
  a miss. A miss is still possible if a
  person takes over ten minutes to allow a Lonca tool; Lonca's setup allows them
  (`permissions.allow`), so that takes a setting of the person's own.
- **What it can not see.** An agent that never calls `lonca mcp` (it edits and runs
  `lonca propose` from a shell the harness does not hook) is not caught by this, only by
  the rest: an unbound session is `unobserved`, and a proposal of files no hook saw written
  escalates (`unobserved_write`).

## What one client can not do to the others (#50)

The daemon is the single writer for every repository on the machine, and a hook
that gets no answer blocks its tool call. So the socket has limits, in
`crates/lonca-daemon/src/limits.rs`. All of them sit in front of the writer: a
request they refuse was never logged, so `decide()` and a replay never see it.
What they refuse is counted in `ping` as `refused`.

- **A full daemon lets the newcomer in.** There are at most 1 024 connections, 512
  of one uid, and half the file descriptors at most (the daemon asks for 4 096; a
  launchd job starts with 256). Past a cap the connection that has been quiet
  longest gives up its place, of the same uid if that uid is the one over. A
  refusal would let anyone who fills the table shut every hook out; this way
  connections that do nothing can not keep anyone out. Only requests being
  answered are never cut, and only when all of them are does a new connection get
  `busy`. Threads stay one per connection: the cap bounds them, and blocking
  code stays simple.
- **Deadlines for the whole, not per read.** A line gets 60 seconds from its first
  byte and a response 60 seconds, each set again before every read and write with
  the time left, so a byte at a time buys nothing. A connection may be quiet for 15
  minutes between requests.
- **A closed connection says so.** `lonca mcp` holds a connection through a whole
  agent turn, so it will meet the idle close. Sending a request again after an
  unexplained end of stream could run it twice, so the daemon's last line is
  `closed` on id 0, written before anything of a later request is read, and a
  thread that loses its place before it starts a request does not run it. `Client`
  sends again once on `closed`, or when the write itself finds the connection
  gone. A bare end of stream stays an error.
- **Line length is decided from the line's first 64 KiB.** The method is inside the
  JSON, so the first 64 KiB are parsed as far as they go; only a method in
  `LONG_LINES` with a live token goes past them. No token before `params`, no long
  line: otherwise anyone who can open the socket could have 96 MiB held for a
  minute, per connection. Lonca's client writes `token` first, and a client that
  sorts its keys can still send up to 64 KiB. Long lines also share a budget of
  192 MiB, which bounds what the daemon holds whatever the connections. The list
  is wider than the three methods #50 named, because `hook.input` carries a
  harness's tool input with a whole file in it, and `tree`, `blobs`,
  `human.submit`, `session.end` and `hook.stop` carry lists the repository sizes.
  `human.submit` with `human.recover`, which needs no session, stays under 64 KiB.
- **The session rate is not a decision.** `[sessions] ops_per_minute` (600) is a
  token bucket that holds one minute's worth, read from the signed policy and kept
  in the daemon's memory. It could have been a rule in `decide()` on logged times,
  but then every refusal would be an entry, and the point is that the log does not
  grow. A restart fills the buckets. Sessions made with `cap.attenuate` spend from
  their root's bucket, or children would multiply the rate. `session.end` is exempt
  so a session over its rate can still stop, as is whatever writes nothing to the
  log. The hook fails closed on `rate_limited`, which is what a flood should meet.
- **`queue.run` wakes the worker.** It held a thread for as long as a merge, build
  and test took, beside the worker. Now one thread merges. The result's `integrated`
  stays, as 0, because removing it would raise the protocol number for a field no
  client reads.
- **`log` has a page**, of 1 000 entries, with or without a `limit`, and reads from
  `from` rather than the whole log. `lonca log` and `lonca doctor` read on in pages,
  so a long log still prints whole.

## Secure by default (#54)

The defaults suit a first run on a laptop, and a hardened install used to keep them
and print advice. A repository now starts from a **profile**: `lonca init --profile
cooperative|hardened`. docs/guide/profiles.md lists what each one sets.

- **A hardened daemon starts hardened repositories.** The installers do not run
  `lonca init`, so "the installers' default" can only live in the daemon, which
  reads the same root-owned file as its clients. `--profile cooperative` still works
  there: it is a human's word, and `status` and `doctor` go on saying so.
- **A file key is refused by a hardened profile, not silently let through.**
  `require_presence` is judged by the policy in force, so genesis passes with any key
  and the very next human signature is `presence_required`, for good: the policy
  update that could undo it needs presence too. Linux has no presence key yet (#17).
  Weakening the profile to fit the key would be silent, so `repo.prepare_init` refuses
  and names `--without-presence`, which leaves that one setting off and shows up in
  `below_hardened` from then on. It goes with the hardened profile only.
- **The list is of what an agent does.** `change.*`, `lease.*`, `negotiate`,
  `cap.attenuate`, `cap.revoke`, `session.end` and the three `file.*` actions: what
  `agent_grantable()` allows and an agent's own lifecycle, and a test holds the list
  to that. Humans keep a blanket `permit`: every op of theirs carries a signature and
  a list would only lock them out of an op it forgot, the policy update included.
- **`below_hardened` asks the policy, it does not read it.** An action nobody could
  have listed is evaluated for an agent; if it passes, the rules are open however they
  are spelled. A `when` that reads a context key this request lacks evaluates to an
  error, so such a rule is not seen. It is a warning, not a boundary.
- **`verification.required` with no command checks nothing**, so that is on the list
  too, and a fresh hardened repository shows it until a human sets `build` or `test`.
- **A hardened daemon does not start without a sandbox**; `--allow-unsandboxed` lets
  it, says so at each start, and `doctor` fails on it. On a cooperative daemon a missing
  sandbox stays a warning, now at start as well, naming each repository whose
  `require_sandbox` means its changes will end in `unsandboxed_verification`.
- **The installers' advice became checks**: `below_hardened` for presence, a `doctor`
  check on hardened installs for a sudo that asks for nothing, and the Linux installer
  stops without bubblewrap, since the service would not start.

## How a verification ends (#59)

Design §5.9 asks for time and memory limits. What a command can do to the
queue, and what it is held to, stands like this:

- **A session, killed whichever way it ends.** A command starts as a session,
  and its group is killed on a normal exit too, not only on a timeout: a
  background process that kept the output open used to hold the run past its
  timeout for good, and the queue behind it. A group alone is not enough: its
  leader can move to another group of the session, and a session's leader can
  not. The exit is seen with `WNOWAIT`, so the leader stays a zombie until the
  last kill and the group's id can not pass to anyone else. Waiting for the
  leader has a limit as well. On macOS the sweep of `lonca run` follows, by a
  mark in the jail; `sweep.rs` moved to `lonca-verify` for that.
- **A pass can not stand on what is still running.** If the sweep leaves
  something, the check is an error whatever the command exited with. It can
  still change the tree the evidence is about.
- **Output is one pipe**, read non-blocking, keeping only `OUTPUT_TAIL`. Two
  pipes can not tell which came first, and a failure reads best in order. One
  second after the kill reading stops, whoever still holds the pipe. With no
  sandbox that is all that can be done about a process that left the group, and
  the result is the command's own.
- **Limits are `setrlimit`, with no way to raise one**: the value is read in the
  parent and clamped, and one that can not be set fails the spawn, so a command
  does not run without its limits. They hold per process, or per account for
  `limit_processes`. A cgroup would hold the whole tree, but it needs a
  delegated hierarchy that a plain install does not have.
- **Time has one limit by default, `timeout_seconds`.** `RLIMIT_CPU` adds up a
  process's threads, so any useful figure fails an ordinary test run on a large
  machine, as a plain failure against the change.
- **Memory stays off by default.** `RLIMIT_AS` counts what is reserved, and the
  JVM, Go and Node reserve far more than they use. So the design's memory limit
  is a key a repository can set on Linux, not a default.
- **`limit_address_bytes` holds on Linux only.** macOS refuses it below what a
  process maps at its start, which fails every spawn. `limit_processes` was
  Linux only too, until it learned to leave the account its share: see "What
  a command may take of the machine".
- **`path` is in the policy, empty by default**, and the hardened profile leaves
  it so: what a build needs on `PATH` differs by machine, and a wrong value only
  makes it fail. What must not depend on `PATH`, `/bin/sh` and the sandbox's
  own program, is absolute already.

## What a command may take of the machine

What #59 left open: a command bounded per process and by time could still
fill the disk the stores are on, fork up to the account's limit on macOS, and
fill memory the kernel charges to no process, and it outlived a daemon that
died. None of it needs a log format: evidence is recorded, not recomputed.

- **The disk is to keep `keep_free_bytes` free**, 1 GiB by default. A limit
  on what a command writes would need its files counted, a walk of its tree
  every look; the free space of the disk is one system call, and it is what
  the stores and their log need. The verifier looks at every turn of its watch
  (20 ms) and stops the command below it, as an error `disk_space`, and does
  not start one below it. The disk of the scratch directory is asked, the
  one the command writes: it is beside the stores. A disk that can not be
  asked counts as full. A machine already low on space fails its checks as
  errors until it is not; 0 turns it off. It is a look, not a quota: parallel
  preallocation (`fallocate`, `F_PREALLOCATE`) can take more than 1 GiB
  between two looks. A quota would need the file system's own, per user or
  per project, which a plain install does not set up.
- **Under bubblewrap `/tmp` and `/dev/shm` are the run's directories**, not
  memory file systems: what is written there counts against the disk and goes
  with the run. The rest of `/dev`, a memory file system too, is read-only;
  POSIX semaphores and shared memory live in `/dev/shm` and keep working.
  `lonca run` keeps its `tmpfs` and `/dev`, since that sandbox's definition
  is what a human signed.
- **A run's directory goes whatever the command did to it.** Removal first
  gives every directory back its owner's `rwx` and, on macOS, clears the
  flags an owner may set (`uchg`): a directory left behind would keep its
  disk space from every later run.
- **The account keeps 256 processes**: `RLIMIT_NPROC` is set to the policy's
  figure, but never above the most the account may have, less 256. That
  figure is the limit in force, and on macOS `kern.maxprocperuid` as well,
  which holds an account whatever its limit says. The limit counts the
  account, so this is the one way to leave room for the person at the
  machine, and for the daemon, whatever the command forks; that is why it now
  holds on macOS too. A count of the account at the start would add the
  command's share to it, but it would also count whatever the person starts
  meanwhile against the command.
- **On Linux the command goes first when memory runs out**: its processes
  start with `oom_score_adj` 1000, which any process may raise for itself.
  That is not a limit: a cgroup would be one, and needs a delegated
  hierarchy a plain install does not have. It is what keeps the kernel from
  picking the daemon. macOS compresses and swaps rather than kill, and has no
  such setting for a process to give itself.
- **A daemon that starts ends what an earlier one left.** Under Seatbelt or
  with no sandbox a command outlives the daemon, and, being a session of its
  own, also launchd's kill of the job's group. Before it verifies, a daemon
  that holds the lock on its home (`daemon.lock`) sweeps the sandbox of each
  `verify-*` directory left in its scratch directory, by the mark the name
  gives, and removes it. The socket is not enough to know no other daemon
  runs on the home, since `LONCA_SOCKET` can put a second one elsewhere; one
  that does not get the lock starts as before and leaves the directories. With no sandbox nothing tells the
  processes, so only the directories go. A guardian process that outlives the
  daemon to end the command was not taken: it is one more program to keep
  out of the command's reach, for the time between a death and a restart,
  which launchd keeps short for the hardened install.

## What verification may cost (#59)

Design §5.9 asks for a verification quota per session and for everything,
past which no proposal is taken. `[quota] session_seconds` and `day_seconds`,
both 0 (off) by default.

- **Time by the clock, not CPU time.** The design says CPU minutes. A command's
  CPU time can be read only for what its leader waited for: what leaves the
  group or runs in another process is not counted, so it would be the agent's
  own code deciding what it is charged. The time a run held the queue is what
  the queue loses, nothing in the run can hide it, and the log has it already
  as `duration_ms`, in old entries too. A run's CPU time is at most its clock
  time times the cores.
- **Recorded, never recomputed.** The state adds up the `duration_ms` of every
  integration's evidence, so the auditor's replay reads the same numbers. A
  check the cache answered (`reused`) costs nothing. `duration_ms` now covers
  every attempt of a retried check; it was the last one, so a check that
  failed slowly and passed fast would have hidden the rest.
- **A run costs whatever came of it.** A failure took its time too.
- **The first session of a line pays**: what it was made from and what it
  continues, so neither a child nor a continuation starts over. One run of a
  batch is shared evenly by its changes. A human's change pays only the day.
- **Past a quota a proposal is denied** (`verification_quota:session` or
  `:day`), not escalated, **and what the session queued earlier is rejected
  without a run.** The daemon asks the same question before it starts a run,
  and `decide()` refuses such an integration even with a pass in its evidence.
  Without that a session could queue many proposals before its first run is
  logged and overrun the quota by all of them; this way it overruns by the one
  run that crosses it.
- **The day is the UTC day of the entry's time.** A burst around midnight can
  use two days' worth. A sliding window would keep a list of runs in the
  state; one counter is enough for a ceiling.
- **The daemon looks at the quota before the merge and logs after it.** If
  midnight or a wider policy came between, the change goes through the checks
  instead of being logged with no evidence, which `required = false` would let
  through.
- **No log format.** A policy that predates the keys can not hold them (unknown
  keys are refused), so old entries decide as before. A human changes the
  quota with `policy.update`, which no quota holds. A day spent by agents also
  stops a human's proposal; the way out is the policy, or the next day.
- **A run that is not logged costs nothing, so an agent can not end one.**
  While a change's checks run, its agent's `change.withdraw` is refused with
  `verifying` and nothing is logged; withdrawing a change mid-run and
  proposing it again would otherwise verify for ever at no cost. Human
  operations are not held back. A run can still end unlogged when trunk or
  the policy changes under it, which only a human does.
- **Not counted**: the syntax check, and the runs of a batch's bisection that
  are never logged: at most log2 of `batch_size` for each logged run, none at
  the default size of 1. With batches a quota holds to within a factor of 1 +
  log2 `batch_size`. A batch's run is split evenly, and what the division
  leaves (under one millisecond per change) is not charged to a session.
- **A table of its own**, not `[verification]`: the verifier's cache is keyed
  by a digest of that table, and a quota does not change what a run proves.

## Shared leases (#112)

A symbol has one `edit` holder, so two agents in one long method take turns.
Most of their edits would not touch the same lines. The lease kind `shared`
lets several sessions hold a symbol at once, and the merge joins their changes
to it line by line.

- **Off unless the repository verifies every merge.** `[leases] shared = true`
  is refused at policy load without `verification.required = true` and a
  `build` or `test` command, and `decide()` refuses a `shared` item
  (`shared_off`) unless both hold, in an acquire or an interest. Two edits that
  do not share a line can still break each other; what catches that is the
  checks on the merged tree, so the kind can not exist without them.
- **`shared` goes with `shared` only.** Against `edit` or `rename` on the
  symbol, on what holds it, or on what it holds, it conflicts as an `edit`
  would, in both orders, so `edit` keeps meaning exclusive. Against an
  `insert` it is an `edit`.
- **A body, not a signature.** A `shared` lease covers a symbol in `edits`. A
  change of its signature still needs `edit` or `rename`: what calls it can
  not be merged by lines. Deletes and renames are as before.
- **Log format 21.** An old reader would take `shared` for an unknown kind, so
  the chain check refuses one in an older entry.
- **The merge (engine 14).** A symbol both sides changed is joined by
  lines when the change being integrated pinned a `shared` item covering it,
  and no move of trunk since its base changed it under any other kind: an
  integration records in the state what its facts change (edits, signature
  changes, deletes, renamed names) that no `shared` pin of it covers, and an
  import from outside counts as changing everything. In a batch, the members
  in front count too. Nothing is joined under a policy without `shared`
  leases, whatever was pinned. All of it comes from the replayed state and
  the policy in force, so the auditor recomputes the same merge and the log
  carries nothing new. The daemon merges and verifies without its lock, so before it
  logs it reads what may be joined again; a policy that changed under the run
  sends the change back through the merge (a batch's head goes alone). An
  edit that an exclusive pin of the same change also covers was made under
  that one, whatever `shared` item the session holds besides.
- **What a join must hold to.** Lines both sides changed, or lines next to
  each other, stay a conflict naming the symbol. The result must parse and
  keep what the symbol merge keeps (`holds_up`); a joined result that does not
  is a conflict naming the joined symbol, not the file. A type whose members
  are symbols is merged member by member as before; a Rust struct's fields are
  its own text, so they are joined.
- **Recorded state grows with trunk.** One record per integration that
  changed something exclusively; a lookup reads only the records since the
  change's base.

## Insert leases (#45)

An `insert` lease is shared: several agents add to one type or file at once.
It said nothing of what they would add, so two agents adding `Client.throttle`
both did the work and the second met a conflict in the merge. A new file
needed no lease at all, and two agents creating one path got a merge of two
files neither wrote.

- **Reserved names.** A lease item has `names`, for `insert` only
  (`names_need_insert`): the bare names of the members it adds, `throttle`
  and not `Client.throttle(int)`. Two inserts into one container (by name or
  by a keyed name it stands for) conflict when their names meet, and so do
  two on nested containers when the outer one reserves the member the inner
  one is or is in: `Client` reserved in `path#<file>` holds what goes into
  `path#Client`. Without names an insert reserves nothing and meets no other
  insert at lease time, as before.
- **A reserved name is its holder's.** A proposal that adds a symbol another
  session reserved is denied (`name_reserved:<symbol>:<session>`) whatever
  lease covers it: an unnamed insert, or a `rename` whose new name it is. The
  reservation lasts while the lease does, and while the change it is pinned
  to is in the queue.
- **Deny by default.** With names, an addition under the item must be one of
  them by its name alone, so `throttle(int)` and `throttle~2` are `throttle`;
  any other is `lease_missing` on the container. The name is that of the
  member of the item's container the addition is or is in, so reserving a new
  type `Limiter` on `path#<file>` brings `Limiter.new` with it, and so does
  reserving an existing type's name: `decide()` does not know which exist.
  A heading is its own name. A name has no key, number, `.`, `#`, `<`, path or
  brackets, no space at either end, at most 128 bytes and 64 names to an item
  (`invalid_names`). Additions of `<module>`, `<def>` or a Markdown `<append>`
  can not be named: an unnamed insert covers them.
- **The tools ask by name.** `lease_needed` and `facts.preview` offer a free
  insert with the names the change adds (`names` on the detail, merged per
  container in `acquire`), and a name taken shows who reserved it. A partial
  release by symbol releases a named item too.
- **A new file takes its path exclusively.** The issue proposed an `insert` on
  the new `path#<file>` that conflicts with a second one while the path does
  not exist. `decide()` does not know what trunk holds, and the daemon would
  have to write that into the entry for the auditor to check. An exclusive
  lease does the same with what is there: from format 22 an added file needs
  `edit` or `rename` on `path#<file>`, which two sessions can not hold, and
  which is pinned to the change until it leaves the queue. An insert does
  not do. `leases.unparsed_files = "optimistic"` frees edits, not creation. A
  person needs no lease, as before, so two creations of one path can still
  meet in the merge when one is a person's.
- **Nor after the other lands.** A lease is exclusive only while held: an
  agent that wrote the path from an older base could lease it once the first
  creation integrated, and its file would be merged with trunk's as if from
  nothing. The state records the files each integration created
  (`State::created`), and an agent's proposal that adds a path trunk created
  after its base is denied (`created_since_base:<path>`): it syncs, and the
  file is then an edit. An import from outside records nothing, so a path it
  brought is not caught.
- **The order of additions at one place is the queue's, last nearest.** The
  design said lease order. The merge places a new symbol right behind the
  neighbour it has in the base, so of several additions behind one symbol the
  one integrated last stands nearest to it, and the first furthest. It is
  deterministic and the auditor recomputes it from the log; lease order would
  make the merge read the lease state for no gain in what compiles. The test
  is `additions_at_one_place_stand_in_the_order_written_down`
  (`crates/lonca-symbols/src/merge.rs`).
- **Log format 22.** An old reader would drop `names` and compute another
  digest, so the chain check refuses names in an older entry. The new-file
  rules are gated on the entry's format in `decide()` and in pinning.

## A delegated lease comes back (#40)

The lease tests of #40 found that a set handed to a child went back to the
parent only when the child ended or was revoked. A child that ran out of time
or stopped beating took the set with it: the set was dead, and whoever asked
next got it, ahead of the parent that had handed it over for a while.

- **The parent holds it the moment the child is gone.** `State::holder` is the
  session a set names, unless that is a child that expired or missed its
  heartbeat and the parent that gave it can still act; then it is the parent.
  Every reader asks it: who a lease meets, whose it is to renew, release or
  hand on, what a proposal may use, what details and `status` show. The set
  keeps its own end; the child's renewals count.
- **The next entry moves it.** Pruning at each entry gives such sets to their
  holder before it drops dead ones, so the state says what the decisions
  already used. Between the child's end and that entry nothing differs: the
  parent can renew or release the set that still names the child.
- **One level.** A set goes to the session it was delegated from. A set handed
  on again names the second parent; if that one is gone too, the set ends, as
  it did when sessions ended.
- **Log format 23**, with no new field. `State::gives_back` is set from the
  format of the entries before, after the entry's own pruning, so the entry
  that reaches format 23 is decided and applied by the same rule. Older logs
  replay as they were.

## Unsafe code, panics and overflow (#61)

A panic in the daemon stops the single writer, and so every repository: a
denial of service. Bad input must become a denial or an error.

- **Unsafe code is refused** by `[workspace.lints.rust] unsafe_code = "deny"`
  in every crate, and crates with no FFI at all (`lonca-core`, `lonca-policy`,
  `lonca-audit`, `lonca-symbols`, `lonca-net`, `lonca-mutants`)
  `#![forbid(unsafe_code)]`. The libc calls live in modules that say
  `#![allow(unsafe_code)]` and give a `// SAFETY:` reason on every block:
  `lonca-daemon/src/sys.rs` (uid, peer credentials, descriptor limit, group
  lookup), `lonca-daemon/src/peer_other.rs` (macOS sandbox questions),
  `lonca-verify/src/process.rs` and `sweep.rs` (process control) and
  `lonca-cli/src/sys.rs` (sessions, signals). A test that sets the
  environment allows it on that test alone. Unsafe code anywhere else does
  not compile.
- **Groups are looked up with `getgrnam_r`.** `getgrnam` returns static
  storage shared by every thread.
- **The release profile checks overflow** (`overflow-checks = true`). Where a
  number comes from a request or a policy, `decide()` and the state use
  `saturating_*` / `checked_*`: policy minutes saturate when turned into
  milliseconds (so a check against them fails closed), `bridge.push`'s
  `oplog_seq + 1` is checked, and ends of leases and sessions saturate. A
  number at the end of its type is denied, not a panic
  (`extreme_numbers_are_denied_without_a_panic`). Nothing that could be
  reached by a log before this changes: those numbers never overflowed, so
  old logs replay as they were.
- **Panic lints on the trusted core.** `lonca-core`, `lonca-policy` and
  `lonca-audit` warn on `unwrap_used`, `expect_used` and `indexing_slicing`
  (CI runs clippy with `-D warnings`, so they fail it); `clippy.toml` lets
  tests panic. Indexing became `get`, `first` and `split_first`; an
  `expect` that holds by construction (constant policy and profiles, the
  OS random source, serializing Lonca's own types) stays with an
  `#[allow(..., reason = ...)]` that says why.
- Not done: a `cargo geiger` report of unsafe code in dependencies.

## Keys at rest (#62)

- **A key file is private to its user or it is not loaded.** `KeyPair::load`
  and `load_or_create` take the uid of the loading process and refuse a key
  that is a link, belongs to another uid, or gives group or others any access;
  the error names the mode and the fix. This holds for the daemon's keys and
  for human file keys. A recovery key is loaded with `load_carried`: it is
  often on a USB stick whose file system shows every file as readable, so only
  its owner is checked and an open mode is a warning.
- **The daemon home must belong to the daemon** (`Home::ensure`), or whoever
  owns it could replace the key, the tokens and the stores.
- **One secret per key in memory.** `KeyPair` holds an `Arc<SigningKey>`;
  `SigningKey` zeroizes on drop, and what was read from or written to disk
  passes through `Zeroizing` buffers.
- The inventory of algorithms, keys and secrets is `docs/crypto.md`.

## Session tokens: expiry, sweep, rotation (#53)

A token used to work for reads, `facts.preview` and the hooks until its
session ended or was revoked, however long ago the session had expired,
and `tokens.json` kept it for good.

- **An agent token works while its session does.** The token entry stores
  the session's end (`expires_ms`, from its log entry; entries written
  before have none and go by the log). A request with a token whose session
  is past its end, or under a parent that ended or expired, is refused with
  `unauthenticated`, for every method but `session.heartbeat` (which refuses
  such a session itself with `session_inactive`, unlogged) and `session.end`.
  An expired session's end is still denied by `decide()`, and its token goes
  then.
- **Swept**: when the daemon starts, at each human login and every round of
  the worker (at most two seconds apart), every token that no longer works
  leaves `tokens.json`: human sessions past their end, agent sessions past
  theirs or that the log says are over, tokens of repositories the daemon no
  longer serves.
- **`session.rotate`** gives the caller a new token for its session, and the
  old one is gone in the same write. Revocation finds a rotated token like
  any other: it goes by session. An isolated session can not rotate: its
  token belongs to `lonca run`'s launcher, which beats with it. **Not
  logged**, a deviation from the issue: the log never holds tokens or their
  issuing (`session.start` records the session, not the token), and a new
  token for the same session changes nothing a decision reads. It is a
  security event for #56. `lonca session rotate` calls it from a workspace
  and writes the new token where the old one was read.
- **A change that did not reach the file is not done.** `tokens.json` is
  what a restarted daemon knows, and a write of it can fail (a full disk).
  A token taken away (logout, a session's end, the sweep) used to be gone
  in memory while the file kept it; asked again, the daemon found nothing
  to take, wrote nothing and said yes, and the token worked once more
  after a restart. Now the caller is still told of the failure, the token
  stays away in memory (the safe side), and the file is written at the
  next call that takes anything away, whether it finds something to take
  or not: `lonca human logout` again, or the worker's sweep within two
  seconds. The other way round, a token that could not be written is not
  kept in memory either, and a rotation whose write fails leaves the old
  token working (it used to lock the session out until a restart).
- **Clients read the token afresh.** `lonca mcp` reads the workspace's token
  before every tool call and every heartbeat, so a rotation or a revocation
  takes effect at once; a hook is a new process each time.

## The daemon's git (#57)

The daemon starts `git` for fetches (init, import, restore), pushes (the
bridge) and a few plumbing reads. It used to inherit the daemon's whole
environment and read the system's and the user's git configuration; in
cooperative mode that is the developer's, which an agent running as the
developer can write. A `url.<x>.insteadOf` there changed which remote the
daemon fetched from.

- **A clean environment** (`crates/lonca-daemon/src/gitcmd.rs`): the child
  starts from nothing and gets `PATH`, `SSH_AUTH_SOCK` (so a cooperative
  daemon pushes over SSH as the developer's own `git push` would), `LANG`,
  `LC_ALL` and `TMPDIR`; then `HOME=<daemon home>/git-home`,
  `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`,
  `GIT_ALLOW_PROTOCOL=file:https:ssh`, `GIT_LITERAL_PATHSPECS=1` (a
  repository path given to git is that file and never a pattern: a file may
  be called `:!src/a.rs` or `src/*`), and `-c core.hooksPath=/dev/null -c
  credential.interactive=never`. `GIT_CONFIG_*`, `GIT_SSH_COMMAND`, `GIT_DIR`
  and the rest do not reach it. **Credentials** for HTTPS remotes go in
  `<daemon home>/git-home/.gitconfig`, a file of the daemon's user: that is
  the only configuration besides the store's own.
- **A time limit**: one git command runs at most `Settings::git_timeout`
  (10 minutes), in a process group of its own, which is killed whole when the
  time is up (ssh and the remote helpers with it). The error is `git`, "did
  not finish within … s".
- **No push under the lock.** `bridge.push` is logged under the service lock
  as before; the push itself runs after the lock is let go, so a slow remote
  holds up nobody. `human.prepare_import` already fetched outside it. The
  fetches of `repo.prepare_init` and `repo.restore` still run under the lock,
  bounded by the time limit: they create a repository and happen once.
- **Local-path remotes** must exist and lie outside the daemon home, apart
  from its backups directory: the stores of other repositories, the key and
  the tokens are there, and git would read them with the daemon's rights (a
  human of one repository could import another's store). The path is
  resolved first, so a link to the home is refused too. `lonca daemon
  --local-root DIR` (repeatable) narrows them to those directories and the
  backups; a hardened daemon starts with none, so it reads only its backups
  unless given one. Refused: `forbidden`.
- **Branches** to fetch pass Lonca's own test and then `git check-ref-format
  --branch`.

## Every ref is the log's (#58)

`reconcile()` held only trunk and the policy ref to the log. A write behind
the daemon's back to anything else went unnoticed: a proposal's ref (which
the bridge pushed), the log's own ref while the daemon ran, a new branch or
tag.

- **One rule for the daemon and the auditor** (`lonca_policy::refs::check`):
  `refs/heads/main` and `refs/lonca/policy` name what the log says;
  `refs/lonca/changes/<change>/<seq>` must be the ref of the
  `change.propose` entry at `seq` (any decision: the ref is written before
  the entry), naming its commit, and every such entry's ref must be there;
  `refs/lonca/import/initial` and `refs/lonca/incoming` are staging refs
  whose content no decision reads; any other name is unknown. `State` keeps
  the proposals by sequence number (`proposed`, derived, read by no
  decision), so no log format changes.
- **The daemon undoes and logs.** Each write is an `import.unmediated` entry
  (`found`, `expected`: `None` for a ref that should not exist or was
  deleted); a ref that names the wrong thing is put back, an unknown one
  deleted, a missing proposal ref restored if its commit is still there.
  `integrity.on_unmediated = "freeze"` freezes the repository as well; the
  default restores only.
- **The log's ref** must name the head the daemon appends to. Moved, it is
  put back first (an append checks it), the move is logged, and the
  repository is **always frozen**, as for the policy ref.
- **A proposal ref past the end of the log** was written before an entry
  that never came (the daemon stopped in between). The daemon removes it
  without a word; the auditor reports it, since from outside it is also what
  a log cut short looks like.
- **A ref the daemon left behind is its own.** An entry is appended, then
  its ref is moved; a daemon that stops between the two finds the ref one
  step back at its next start. For the trunk that was always moved on
  quietly (any commit of the log's history). The policy's ref was not: the
  policy from before a `policy.update` read as a write behind the daemon's
  back, which always freezes, so a crash at the wrong moment froze the
  repository; and a daemon stopped between `repo.init` and its two refs
  started with a new repository already frozen. Now quiet as well: the
  policy from just before a `policy.update` **while that entry is the
  log's last**, and either ref missing while `repo.init` is the only
  entry. `State::policy_before` holds the former policy with the entry's
  number (derived, not serialized, read by no decision). The policy's ref
  stays held more closely than the trunk's: the old policy under it once
  anything else has been logged is a write, logged and frozen for.
- **The bridge pushes what the log has**: trunk, the log, the policy and
  the ref of every logged proposal, named one by one (500 per `git push`),
  instead of `refs/lonca/changes/*`.
- **The auditor**, with `check_refs` (the default), applies the rule to
  `refs/lonca/*`; `--all-refs` holds every ref to it, for the daemon's own
  store or a remote nothing but Lonca pushes to. A CI clone also has its
  remote's branches and tags, so the example workflow keeps the default.

## The advisor reads agent text and a human reads it (#63)

`lonca advise` stays outside every decision; this hardens both of its ends.

- **Framing.** The change and its diff go to the model as one JSON document,
  so nothing in them can end a field early, between two delimiter lines
  named by a fresh random tag that the data does not contain (`framed`). The
  system prompt says that everything between them is data, including text
  that looks like the end of it. Before, `<change>…</change><diff>…</diff>`
  could be closed by a diff that contained `</diff>`.
- **Output for a terminal.** Every string of the advice keeps only newlines
  and tabs among control characters, so no ANSI escape survives; C1 controls
  and bidi controls go too; a field keeps at most 4 000 characters and a list
  50 items; a risk or severity outside the schema reads `unknown`
  (`printable`, `clean`). The model may echo what the diff carried.
- **Provenance.** The advice is labelled: `"provenance": "tainted"` in
  `--json`, and a line saying it is derived from what an agent wrote on the
  terminal. If advice is ever stored or shown to agents it carries that
  label.
- **The budget fails closed.** A ledger that does not parse refuses the call
  (and is left as it is); it is written whole (temp file and rename). The lock
  file records pid and time; a lock older than 10 s was left by a crash and
  is broken, and a live one that does not go away says who holds it.
- **https only**: `ANTHROPIC_BASE_URL` must be `https://`, or `http://` to
  `127.0.0.1`, `localhost` or `[::1]` (a test server), so the key never
  travels in clear text.

## What the proxy lets through (#64)

The proxy decided by host alone: `CONNECT` reached any port, a session
could hold any number of connections and move any number of bytes, and
`allow_private_network` opened the cloud metadata addresses with the rest.

- **Ports**: `[observation] allow_ports` (default `[80, 443]`). The gate
  refuses another port before anything is resolved.
- **Hosts**: `allow_hosts = [{ host, taint }]` lets a host through under
  `network = "deny"` and says whether it taints; `host` is an exact name or
  `*.suffix` for the names below the suffix (not the suffix). Validated when
  the policy is parsed: lowercase names only, a suffix with a dot.
  `agent_hosts` stays as it was (pass, no taint). Order: agent host, then the
  first rule, then `network`.
- **Metadata always denied** in `lonca-net` (`is_metadata`): 169.254.169.254,
  169.254.170.2, 169.254.170.23, 100.100.100.200, fd00:ec2::254 and their
  mapped forms, whatever the gate says.
- **Caps**: per session `max_connections` (16) open at once and `max_bytes`
  (1 GiB) moved while the daemon runs, counted for every session a
  connection is attributed to; the proxy reports each chunk to the gate
  (`Gate::carried`) and cuts the tunnel when a budget is spent. Globally the
  proxy serves at most 256 connections at once (`MAX_CONNECTIONS`, answered
  503). The counts are memory only: they are no decision.
- **On the record**: each attempt is an observation of every session it is
  attributed to before the verdict, refused or not, as before; the host
  carries `:port` when the port is not 80 or 443. No new log field.
- **Attribution fallback** is counted (`proxy_unattributed` in `status`,
  `PROXY …` in `lonca status`).
- **A client is not waited for** (0.2.4): the whole request head has 10 s
  (408, before the gate is asked), and a tunnel through which nothing
  moves either way for 10 minutes is cut (`lonca_net::Limits`,
  `Outcome::Idle`). There was a limit of 30 s on each read and none in
  all, so a client sending a byte now and then kept one of the 256 places.
  Constants, not policy: nothing a repository does needs a slower client.

## Security events outside the log (#56)

The operation log records every decided operation. Much of what an attacker
tries never reaches a decision, and nothing told anyone of a freeze.

- **`<home>/security.log`**: one JSON object per line, mode 0600, written by
  the daemon around decisions, never inside `decide()`
  (`crates/lonca-daemon/src/security.rs`). Fields: `time_ms`, `kind`, and as
  they apply `repo`, `session`, `method`, `uid`, `code`, `detail`. **Never a
  token, a request body or file contents**: the fields are fixed, `detail` is
  at most 300 characters with control characters replaced, and anything
  shaped like a Lonca token is masked (`lonca_[token]`).
- **Kinds**: `refused_peer` (a uid the socket does not serve),
  `auth_failure` (`unauthenticated`, `forbidden`), `oversized_request` (a
  line past its method's limit), `malformed_request` (not a request),
  `rate_limited`, `outside_sandbox` (an isolated token used outside its
  sandbox), `hook_denied` (a hook refused a tool call: the tool and the
  reason), `reconcile_error`, `unmediated_import` (the ref), `freeze`,
  `integrity_alarm` (the auditor's freeze flag), `taint` (the daemon tainted
  a session), `sudo_without_password` (a bind whose hook reports it),
  `token_rotated` (`session.rotate`, #53), `unhooked` (a call to `lonca mcp`
  with no hook event before it: the tool, #190), `misnamed_tunnel` (a
  tunnel through the proxy cut for the server name its client asked for:
  both names; see "A tunnel is for the host it was asked for"). Entries the daemon appends
  (`freeze`, `import.unmediated`, `taint`, `unhooked`) are taken from the repository and
  written after the request, or by the worker within two seconds.
- **Kept**: past 8 MiB the file moves to `security.log.1`, replacing the one
  there, so about 16 MiB, the latest events, are kept. Some kinds any
  caller can cause as often as it likes (a line that is no request, a bad
  token: 16 MiB of them takes seconds), and they used to push out
  everything else, a freeze or a taint included. So the latest 256 events
  of every kind stay, whatever comes after them (`KEEP_OF_KIND`): at a
  rotation those the two files would no longer hold are written first in
  the new `security.log.1`. A kind pushes out its own older events and no
  other kind's. A line that is not an event of a known kind is not
  carried. A daemon that stops in the middle of a rotation may leave the
  events of one file in both until the next. The log is
  the daemon's, like the stores: a backup does not carry it, and an
  uninstall removes it with the home.
- **Told at once**: a `freeze` or an `integrity_alarm` runs a notification
  on a thread of its own, killed after 10 s: the desktop's (`osascript` on
  macOS, `notify-send` on Linux) for `lonca daemon`, or `--notify-command
  PROGRAM`, which gets the event as one JSON line on stdin (a webhook or a
  pager, outside the core); `--no-notify` for none. A hardened daemon runs as
  its own user, with no desktop of its own: there `lonca status` (`FROZEN`)
  and `--notify-command` are what reach a human. Tests and the in-process
  daemon default to none.
- **For a human**: `security.events` (any human, default the last day):
  counts by kind and the latest 100 events, of the repositories the human is
  enrolled in and of none. `lonca doctor` sums it up and warns on a freeze,
  an integrity alarm, an unmediated import or a reconcile error.
- **Errors on security paths are said**: `reconcile_all` used to drop a
  failed `reconcile()` (`let _ =`); it is a `reconcile_error` now. Not done:
  integrity of the managed settings and the hook binary between binds (a
  bind checks them), metrics beyond these counts.

## CI and the repository's own settings (#60)

CI is the auditor's separate infrastructure (design §5.13), so what may change
it and what it runs are part of the trust model.

- **main takes pull requests only.** The ruleset adds `pull_request` (no
  approvals required: there is one maintainer) to its deletion and
  force-push rules, so a direct push to main is refused. Since 2026-11-09
  it also requires the `ci.yml` jobs as status checks ("CI runs on every
  pull request"); from 2026-11-08 to then it required none. `cargo-deny`,
  CodeQL and zizmor run on pull requests and block nothing.
- **A release is a tag on main, and a tag stays where it was put.**
  `release.yml` ran on any `v*` tag: a tag on a commit that was never on
  main, pushed with a token that may write contents, became attested
  archives, and its published draft went to crates.io. Since 2026-11-12
  the `on-main` job asks GitHub how the tagged commit stands to main
  (`compare/main...<sha>`: `behind` or `identical`), and the `draft` job,
  the only one that can write or attest, needs it; `registries.yml` asks
  the same before anything is packaged. Two tag rulesets for `v*`: no
  update and no deletion, for anybody (a tag can not be moved between the
  draft and its publishing, which would send crates.io another source than
  the attested archives were built from); creation by a repository
  administrator only, so no workflow's token tags a release. Not set: a
  required reviewer on the `release` environment. With one maintainer it
  is the same person's second click, and a token that can push a tag and
  publish a release can approve a deployment too.
- **CODEOWNERS** names the owner of `.github/`, `deny.toml`,
  `rust-toolchain.toml`, `packaging/`, `lonca-core`, `lonca-policy`,
  `lonca-audit` and `SECURITY.md`; review by the owner is asked, not
  required.
- **A pinned toolchain**: `rust-toolchain.toml` names the exact version
  (1.99.1, with clippy and rustfmt), here and in every CI job (`rustup
  toolchain install` reads it). It is raised by hand in a pull request of its
  own; Dependabot does not bump it.
- **Ubuntu packages come through one script**, `.github/scripts/apt-install.sh`
  (bubblewrap in `ci.yml`, age in `fuzz.yml`, musl-tools in `release.yml`). The
  runner's apt mirrors are all names under ubuntu.com; on 2026-11-11 they did
  not resolve on the runners for hours and the required `sandbox` job could
  not start, on every pull request. The script adds kernel.org's mirror
  after them, so apt asks it only when the others fail. A mirror can not
  change a package: apt checks what it gets against the archive's signed
  index, whoever served it.
- **Actions**: the repository allows GitHub's own actions and five others by
  name (`EmbarkStudios/cargo-deny-action`, `ossf/scorecard-action`,
  `taiki-e/install-action`, `zizmorcore/zizmor-action`, and
  `rust-lang/crates-io-auth-action` for trusted publishing, see "Releases and
  install paths"), each pinned by commit as the repository already required.
- **zizmor** (`.github/workflows/zizmor.yml`, version pinned) checks the
  workflows where they change and fails on anything above `low`; today it
  reports one `low` (the self-repository syntax of the mutants runner).
- **SBOM**: a `v*` tag builds a CycloneDX bill of materials of every crate
  (`cargo cyclonedx`, pinned) in `release.yml` and attaches it to the
  release (`lonca-sbom.cdx.tar.gz`, listed in `SHA256SUMS`).
- **CodeQL for Rust** was on already (default setup, actions and rust).
- **Not adopted: `cargo vet`.** The trusted core pulls in gix, cedar-policy
  and the tree-sitter grammars; vetting them by hand is more than one
  maintainer can keep up, and an unmaintained audit set is worse than none.
  `cargo-deny` (advisories, licenses, crates.io only) and Dependabot's
  seven-day cooldown stay the defence; reconsider with a second maintainer
  or imported audits.

## A harness's environment in a run (#187)

`lonca run` starts the command with almost nothing of the caller's environment
and with a `HOME` and `TMPDIR` of its own, so a harness that needs something
more did not start, and the person had to know which names it reads. Claude
Code on macOS exits on `mkdir /tmp/claude-<uid>`: it makes that directory
whatever `TMPDIR` says, and the shared `/tmp` is closed.

- **What a harness needs in a run is data in its profile.** `setup.run_env`
  is a table like `setup.env`, read only by `lonca run`, with two more holes:
  `{home}` and `{tmp}`, the sandbox's own. `claude-code` sets
  `CLAUDE_CODE_TMPDIR = "{tmp}"`. Not `env`: `lonca harness setup` prints `env`
  for a harness outside any sandbox, where Claude Code's own temp directory is
  right and a `CLAUDE_CONFIG_DIR` would lose the person's login.
- **A run applies the named harness's `env` too.** It is what the harness must
  start with (Gemini's `GEMINI_CLI_TRUST_WORKSPACE`), and the profile is the one
  `session start --harness` named, from the signed policy. Order, later wins:
  the kept variables, the profile's `env`, its `run_env`, the person's `--env`,
  then what the run holds itself (`PATH`, `HOME`, `TMPDIR`, `LONCA_*`, the
  proxy). A profile's `LONCA_*` is skipped: the run sets its own.
- **Names are checked twice.** A policy whose profile names a variable that
  changes what a program loads (the `--env` and verification list) is refused
  when it is read; `run_env` may not name `LONCA_*` either. `lonca run` checks
  again before the sandbox starts, since the setup reaches it over the socket.
- **Holes are filled in one pass.** A path that holds `{tmp}` is not filled
  again.
- **No `CLAUDE_CONFIG_DIR`.** With the run's own `HOME`, Claude Code writes its
  settings to `$HOME/.claude`, deleted with the run. A scratch root would keep
  them, but every run takes a new session whose scratch roots must be empty.
  Measured with Claude Code 2.1.319 on macOS: with the profile, `claude -p`
  starts and answers "Not logged in"; with `--env CLAUDE_CODE_TMPDIR=/tmp` it
  exits on the `mkdir` again.
- **The login stays the person's to give.** The Keychain and `~/.claude` stay
  closed; `--env CLAUDE_CODE_OAUTH_TOKEN` (from `claude setup-token`) or
  `--env ANTHROPIC_API_KEY` brings a credential in. Lonca reads no credential
  for a harness. Not measured: a run with a token, and which hosts besides
  `api.anthropic.com` Claude Code reaches; each would taint under
  `network = "taint"`.

## Checks a change owes, chosen per change (#191)

A card of imece's says how its work is accepted ("`cargo test -p api`
passes"), and in a Lonca workspace only the merge queue runs commands, from
`[verification]`. So a card's check had nowhere to run, and a human approved
without knowing whether it would.

- **The commands stay in the signed policy; only which of them a change owes
  is chosen per change.** `verification.checks` names commands
  (`api = "cargo test --offline -p api"`), with the sandbox, environment,
  limits and timeout of `build` and `test`. A name is `[a-z0-9_-]`, 1 to 32
  long, at most 32 of them, and not a word Lonca uses for its own checks
  (`build`, `test`, `tests`, `extended`, `syntax`, `scope`, `claim_diff`,
  `merge`, `test_integrity`), because the name goes into the same denial
  words: `verification_failed:api`, `verification_missing:api`.
- **A human names them at approval, never the agent.** `approve` carries
  `checks` (log format 25, signed with the approval; `lonca approve SEQ
  --also api,e2e`). Only on a pending proposal (`checks_not_a_change`), only
  names the policy in force defines (`unknown_check:<name>`), sorted and each
  once (`invalid_checks`): the CLI sorts. The Touch ID prompt names them.
  With two approvals needed, each one's names count.
- **What was asked stays asked.** The names go on the change record and a
  later version of the change keeps them, so an agent can not drop a check by
  proposing again after a rejection. Nothing takes one away; a human who
  wants less rejects or withdraws.
- **The policy can name one for a path, so nobody has to remember.**
  `verification.checks_by_path = { "api/**" = ["api"] }` (patterns as in
  `paths.critical`, names checked against `checks` at load). This answers the
  issue's second question, and it covers proposals no human approves at all.
- **Not at `session start`.** The issue's other option, a set fixed when the
  session starts, is left out: `session.start` is signed by a human too, but a
  card's check is about one change, and the approval is the moment the human
  sees what the change is. A runner that wants a check on every change of a
  task can name it for the paths of that task in the policy.
- **A named check a change owes is owed with or without `required`.** Someone
  asked for it by name; `required = false` stays what it was for `build` and
  `test`. `require_sandbox` holds named evidence like the others.
- **Evidence is the kind `named`, with the name in `details.name`.** One new
  kind instead of a kind per name keeps `CheckKind` closed. The verifier runs
  the named checks after `build`, `test` and `on_signature_change`, in name
  order, and a failure skips the rest, as before.
- **A policy that drops a check a queued change owes leaves the change unable
  to land.** `for_change` keeps the name with no command, the verifier runs
  nothing for it, and the integration is denied `verification_missing:<name>`.
  Quietly forgetting what a human asked for would be worse.
- **The review list says what will run before the yes.** `status.changes[]`,
  `status.pending[]` and `change.get` carry `checks` (asked) and `runs`
  (`build`, `tests`, `extended`, then the named checks owed, under the policy
  in force). `decide()` reads what is owed from the change record and the
  entry's policy, so the auditor recomputes it like any other decision.

## A client crate for harnesses (#192)

imece talks to the daemon as a client of its socket and kept its own copy of
the protocol, with a job that watched our commits for changes to it.
`lonca-client` makes that copy a dependency.

- **What is in it is what a client needs.** The request and response types
  (`protocol`, moved from the daemon, which re-exports it), `PROTOCOL` (the
  daemon re-exports it too), the socket client and the daemon checks
  (`client`, `trust`, moved), the two libc calls they make (`sys`:
  `current_uid`, `peer_uid`), and the human session file (`session`). No
  store, no policy, no daemon code: a client is never a second writer.
- **`lonca-core` without its store.** The types a request carries (`Op`,
  `Claim`, `GitId`, `ChangeId`, ...) are in `lonca-core`, which also holds the
  Git store (gitoxide). The store and the log kept in it (`Store`, `OpLog`)
  are the default feature `store`; `GitId`, `FileMode`, `FileEntry` and
  `FileMap` moved to `objects` and need no Git library. `GitId::parse` checks
  40 hex digits itself; a test holds it to what gix accepts and gives.
  `lonca-client` depends on `lonca-core` without default features: 54 crates,
  no gix, no Cedar.
- **`repo.prepare_init` stays the daemon's.** Its `profile` is a policy type.
  A client that creates repositories sends that request as JSON.
- **Typed errors keep the code.** `CallError` is still the daemon's
  `{code, message}`; `kind()` reads it as `ErrorKind` (`#[non_exhaustive]`,
  `Other` for a code this version does not know), and `is_transient()` is
  true for `rate_limited`, `busy` and `closed`: nothing ran, send it again.
  Two kinds are the client's own: `io` (the connection failed, or the answer
  was not one) and `timed_out`.
- **A timeout drops the connection.** `Client::set_timeout` holds both the
  write and the wait for the answer. Past it the request may have run, so it
  is not transient, and the late answer must not be read as the next
  request's: the next call opens a new connection. An answer whose id is
  neither the request's nor 0 is refused the same way. Default: no timeout,
  because `log` may wait 30 seconds by design.
- **The test override is opt-in.** `Trust::load` reads
  `LONCA_TEST_DAEMON_UID` only in a debug build with the feature `test-env`,
  which the daemon and the CLI turn on for their tests. A harness's debug
  build does not get it by depending on the crate.
- **The session file is read as `lonca` left it.** A regular file (opened
  with `O_NOFOLLOW`, checked on the open file), owned by the current user,
  with no group or other bits, at most 64 KiB. `lonca` uses the same reader,
  so a file someone loosened is not used, and its writer now sets 0600 on an
  old file too (the mode on `open` counts only for a new one).
- **Semver.** A protocol number change is a major version (0.x: minor);
  fields added to a shape are not. It is published with the rest of the
  workspace (see "Releases and install paths").

## Releases and install paths (#7, #8)

There was no release: the quick start built from source, and only
`lonca-net` 0.1.0 was on crates.io (Kule's sandbox proxy). 0.2.0 is the first
release (roadmap M2).

- **One version for the workspace.** Every crate takes `version`, `edition`,
  `rust-version`, `license`, `repository` and `homepage` from the workspace,
  and the internal dependencies name the same version. A release bumps one
  line (and those dependency lines). `lonca-net` jumps from 0.1.2 to 0.2.0
  with the rest.
- **Every crate is published but `lonca-mutants`.** The CLI's package is
  `lonca` (the name was free), so `cargo install --locked lonca` gives the
  `lonca` binary; its directory stays `crates/lonca-cli`. `lonca-audit` is
  its own crate and binary (`cargo install --locked lonca-audit`): the
  auditor is meant to run elsewhere (design §5.13). The libraries are on
  crates.io because the binaries need them there, and because Kule depends
  on `lonca-core` and `lonca-net` (by git revision until now) and imece is
  to take `lonca-client`; of those only
  `lonca-client` and `lonca-net` are an API kept stable on purpose (0.x:
  a minor version may break).
- **MSRV 1.90**, what the dependencies ask (`tree-sitter` 0.27 asks 1.90,
  `cedar-policy` 4.14 1.89), checked with `cargo +1.90 check --workspace
  --all-targets --locked`. Builds and CI still use the pinned toolchain.
- **A tag drafts the release; a person publishes it.** `release.yml` builds
  `lonca` and `lonca-audit` for macOS arm64 and x86_64 and Linux x86_64 and
  arm64. Linux builds are static (musl), so any distribution runs them. The
  archives carry the hardened install scripts (`sudo ./install-hardened.sh
  --bin .`) and, on macOS, `lonca-se`. `SHA256SUMS`, the SBOM and a build
  provenance attestation per archive go with them; the notes are the
  version's section of `docs/release-notes.md` (`## X.Y.Z`), and a tag with
  none fails. `ci.yml` runs on the same tag, and the
  maintainer publishes the draft only when it is green: the binaries are
  built before the tests have passed, but nobody downloads them until then.
- **`lonca-se` is signed ad hoc**, as `build-lonca-se.sh` does. CryptoKit's
  Secure Enclave keys need no keychain entitlement, so no Developer ID is
  needed for them to work. A file downloaded with `curl` carries no
  quarantine flag, so Gatekeeper does not stop it; one downloaded by a
  browser does, and `xattr -d com.apple.quarantine` lifts it. Notarization
  waits until someone asks for a browser download.
- **crates.io by trusted publishing.** Publishing the draft starts
  `registries.yml`: a job with no token packages and builds every crate
  (`cargo publish --workspace --dry-run`, which runs build scripts), then a
  job in the `release` environment (tags `v*` only) exchanges its OIDC token
  for a crates.io token that lives for that job and uploads with
  `--no-verify`, building nothing. No registry token is stored. Trusted
  publishing needs the crate to exist, so 0.2.0 of each new crate is
  published by hand (`docs/release-checklist.md`); the workflow is off until
  the repository variable `PUBLISH_CRATES` is `true`.
- **Homebrew from a tap of its own,** `selcukgural/homebrew-lonca`
  (`brew tap selcukgural/lonca`, then `brew install lonca`). The tap's
  workflow reads the latest published release, verifies every archive's
  attestation against `release.yml` of this repository, writes the formula
  from `SHA256SUMS` and commits it with its own token. This repository
  holds no token for the tap, and a draft or pre-release never reaches it.
  The docs show the tap and the short name as two steps (0.2.1) rather than
  the one-line `brew install selcukgural/lonca/lonca`: that one works but
  is easily shortened to a plain `brew install lonca`, which without the
  tap finds no formula. That form needs homebrew-core, whose notability
  bar (stars, forks, watchers, a formula built from source) is far above
  this repository today. Homebrew 7 loads a formula from a tap that is not
  its own only after `brew trust --formula selcukgural/lonca/lonca`
  (found 2026-11-10 with imece's tap, a copy of this one); the docs show
  that step between the two. The tap's own test in CI passed without it.
- **`install.sh`** (served by the site, `website/static/install.sh`) picks
  the archive for the machine, checks it against `SHA256SUMS` and installs
  the binaries in `~/.local/bin`, over HTTPS only.
- **The site** (`website/`, English, Docusaurus as imece and Kule have it)
  is built from `docs/` itself: the guide, the protocol, cryptography, the
  OWASP review and the release notes, so a page reads the same on GitHub.
  `design.md` (Turkish) and `decisions.md` are linked on GitHub instead.
  `docs.yml` builds it on pull requests (a broken link or anchor fails, and
  so does a guide page missing from the sidebar) and publishes it from main
  to https://selcukgural.github.io/lonca/, with `install.sh`. The build sees
  no credential and runs no npm script.
- **Every install path is cooperative mode.** Homebrew, `install.sh` and
  `cargo install` put the binaries where the developer's account can write,
  which hardened mode forbids (the invariant). Hardened mode installs from
  the unpacked archive with its script, which copies them root-owned.

## Hardened mode in the field (#10)

The hardened installers had only been run with `--render`. The 0.2.0
Linux archive (`aarch64-unknown-linux-musl`) was installed for real with
`sudo` on Debian 12 under systemd (a podman container with systemd as
PID 1, a developer account in group `sudo` with a password). macOS has
not been installed for real yet: it writes the managed settings every
Claude Code session on the machine reads, so it waits for a machine set
aside for it.

What held: the user, the group, root-owned binaries, a 0700 store the
developer can not list, a 0660 socket of the daemon's user, `daemon.toml`,
the managed settings, `lonca doctor` all green, a session, a backup the
developer can read and audit, and `lonca hook` binding the session at
`hooks_sandbox` from the managed settings alone. What broke, and what was
done:

- **No way in for a project's history.** A hardened daemon reads local
  paths only in its backups directory, and the developer can not write
  there, so `lonca init --import ~/src/x` and `lonca restore` from a
  cooperative backup were both `forbidden`. The installers now make an
  import directory (`/Library/Lonca/import`, `/var/lib/lonca-import`;
  root, group `lonca`, mode 3770) and start the daemon with
  `--import-dir`. Anything running as the developer can write it, agents
  included, so git never reads it: the daemon opens a regular file
  directly in it with `O_NOFOLLOW | O_NONBLOCK`, checks the bundle header,
  copies it into `<home>/imports` (0700) and fetches from the copy, which
  goes when the fetch is done (a daemon killed meanwhile empties
  `imports` at its next start). A link swapped in after the check, a
  FIFO, a hard link (macOS lets anyone link a file they can reach but not
  read), a repository directory whose `objects/info/alternates` names a
  store in the daemon home, a file in a subdirectory: none reaches git. A
  bundle above 4 GiB is refused before a byte is copied (a sparse file
  costs its writer nothing and the copy would write it out), and the copy
  of `repo.prepare_init` runs before the service lock, so nobody waits
  for it. A push there is refused; the import directory is read only.
  What the human imports is still what they sign, as from any directory
  of theirs: an agent can replace the bundle before the human runs
  `init`, as it could edit `~/src/x` before.
- **A hardened daemon refuses `--local-root`.** Git is given such a path
  as it is, so through a directory the developer can write it could be
  pointed back at the daemon home after the check. The installers never
  passed it; now `lonca daemon` does not start with it on a hardened
  install, and bundles come through the import directory only.
- **An upgrade left the old daemon running.** Running the Linux
  installer again replaced `/opt/lonca/bin/lonca` and called `systemctl
  enable --now`, which does not restart a running service: the old daemon
  went on from a deleted file. Both installers now are the upgrade path:
  they stop the daemon before the binaries are replaced, start it again,
  wait for the new socket (the macOS one outlives its daemon, so it is
  removed first), and print the version that runs. Stores, key and
  backups stay; `lonca doctor` checks the rest.
- **Linux had no uninstaller.** `packaging/linux/uninstall-hardened.sh`
  mirrors the macOS one (`--purge` also removes the stores, backups,
  imports and the user); both archives carry it.
- **Linux can not meet the hardened profile's presence.** There is no
  key that proves it there, so `lonca init` needs `--without-presence`;
  the installer says so now instead of pointing at the Secure Enclave.

**sudo's credential cache, measured** (sudo 1.9.13, Debian's default
`timestamp_type=tty`): after `sudo -v` on a terminal, a child process
that still has that terminal as its controlling terminal runs `sudo -n
true` without a password, even with stdin redirected from `/dev/null`; a
process detached from it (`setsid`) is asked. Claude Code's tool shells
have no controlling terminal (`tty` says "not a tty", `ps` shows `??`;
measured on macOS 27.2), so they can not reuse a cache the developer's
terminal holds. The hook runs `sudo -n true` the same way the harness
runs the agent's commands, so its answer is the agent's reach: run under
Claude Code it says "asks for a password" while `lonca doctor` in the
terminal right after `sudo -v` warns. A harness that keeps the terminal
for its tool processes gets the cache and the warning with it. macOS
1.9.17 has the same default; its own measurement waits for the macOS
install.

**Questions from the harness side** (imece starts each worker with
`lonca hook` in `--settings`):

1. Claude Code's documentation says `allowManagedHooksOnly` blocks user,
   project, local and plugin hooks; it does not say what happens to hooks
   given with `--settings`. Not measured: it needs root-managed settings
   and a live Claude Code run, which waits for the macOS install. Until
   then a harness that passes its own on a hardened machine may see
   `lonca hook` run twice per tool call.
2. Yes: with the managed settings and a session started by the human with
   `--harness claude-code`, the managed `lonca hook` binds the session at
   `hooks_sandbox` with nothing from the harness (measured above).
3. `ping` now says `hardened` (true for a daemon whose uid the root-owned
   `daemon.toml` names). Whether the harness's own hooks are the locked
   ones shows after the first hook, as the session's level in `status`;
   #190 makes a session that never bound visible.

## A newer proposal replaces the pending one (#107)

A workspace proposes all it has, so a second proposal while the first waited
for a human held the first one's edits. Both stayed pending: approving the
second landed both edits and left the first waiting, and approving the first
afterwards integrated a commit with nothing new in it. The agent had no way
to take the first back over MCP, and imece turned the older ones down with a
signed `reject` each, one Touch ID per older proposal.

- **The proposal withdraws them, in the same entry.** An agent's
  `change.propose` that is allowed or escalated withdraws every change of
  its workspace that is `pending`: the old one reads `withdrawn`, leaves
  `status.pending` and can no longer be approved. The decision names each
  with `replaces:<change>` among its reasons, so the agent and the person
  see it. `State::replaced_by` gives the set to both `decide()` and the
  state, so the reasons and the effect can not differ.
- **The workspace is the session's line.** The session that proposes and
  the sessions it continues (`session start --continue`): those took over
  one workspace. A child of `cap.attenuate` has a workspace of its own and
  is left alone, as is another session's work.
- **Only what waits for a human.** A queued change is already accepted and
  lands; the newer one lands after it with what is left. It is not
  withdrawn. A denied proposal withdraws nothing, and a human's proposal
  has no workspace and replaces nothing.
- **The leases follow the work.** The new proposal pins what it needs from
  its session's sets, which include the items pinned to the old one, before
  the old one is withdrawn; what only the old one needed goes back to the
  TTL of its set. A pin that kept a set alive past its session's end passes
  to the new change the same way.
- **Not a new status.** The issue asked for `withdrawn` or a `superseded`
  naming the successor. `withdrawn` is what a runner already handles, and
  the successor is in the newer decision's reasons; a new status would be a
  protocol change for every client.
- **Log format 26**, with no new field. From it the entry means more, so
  older entries replay as they were: two pending proposals stay two.

## A closed stdout ends a command quietly (#207)

`lonca status | head` panicked: Rust ignores SIGPIPE, so `println!` meets
`EPIPE` and panics. `unsafe` is denied in the workspace, so the signal
handler stays as it is and the CLI writes through `out!`/`outln!`
(`crates/lonca-cli/src/out.rs`).

- **The command runs to its end.** After the first `BrokenPipe` the rest
  of the output is dropped, but the command is not cut off: `keys rotate`
  prints each repository as it goes, and stopping between two of them
  would leave some on the old key. Nothing the CLI prints streams for
  ever, so finishing costs little. Then the exit status is the command's:
  0 when it succeeded, like `rg`, not 141 like a shell's SIGPIPE, so a
  `set -o pipefail` script reading the first lines does not fail.
- **Any other write error is reported.** A full disk under a redirect is
  output lost that the reader wanted: the command still ends, and then says
  `lonca: writing to stdout: ...` and exits 3.
- **The MCP server ends quietly** when its client hangs up: an error that
  only says the pipe closed exits 0, without a message.
- **The hook fails closed.** Its answer is the decision; a harness that can
  not read it must not see a silent success. A failed write is handled as
  any other hook failure: exit 2 and a message on stderr, or exit 0 under
  `--fail-open` (the stop hook).

## Trying a policy before it is set (#13)

`lonca policy check` decides every entry of the log again with a candidate
policy and lists the decisions that would change
(`lonca_policy::whatif::compare`). Guide: `docs/guide/policies.md`.

- **In the CLI, not the daemon.** It reads the log with `log` pages and the
  files in force with `status`, `tree` and `blobs`, and runs `decide()`
  itself, as `lonca doctor` replays the log. No method, no protocol change,
  and a long log replayed does not hold the daemon's lock. It needs a human
  login because `policy show` does: the policy is the humans' to change.
- **One entry at a time, on the real state.** Each entry is decided with
  the candidate on the state the log had before it, and the log's own
  decision is applied afterwards. Following the candidate's decisions
  instead would be a different history, which `decide()` can not build: a
  change denied early has no later integration to decide, and the merges
  and evidence after it were computed for the history that happened. The
  answer is "these requests would be treated differently", and the guide
  says so.
- **The whole decision is compared**, outcome and reasons, like the
  auditor: a request denied by another rule, or escalated with a different
  approval count, is a change a reviewer wants to see.
- **Lockouts are warned of, not refused.** Cedar evaluates humans too, and
  undoing a policy is a `policy.update`. A candidate that denies an
  enrolled human `policy.update`, `unfreeze`, `approve`, `reject` or a key
  operation (`WAYS_OUT`) can leave no way back, so the check names each one
  it would deny, asked as `decide()` asks it now. Escalating one is fine.
  `policy.update` itself does not refuse such a policy: that would be a
  rule of `decide()` and a log format, and a repository may mean it (a
  frozen archive). Not built: refusing it in `policy set`.
- **Exit code 0** whatever the differences: the check informs a human,
  and a script reads `--json`. A file that does not parse exits 3, as any
  error that never reached the daemon.

## Fuzzing (#15)

Seven libFuzzer targets over the inputs that cross a trust boundary; how to
run them and what each holds: `docs/fuzzing.md`.

- **The checks are a workspace crate, the fuzzer is not.** What a target
  holds is a function in `crates/lonca-fuzz` (`publish = false`); `fuzz/` is
  a cargo-fuzz project with its own workspace and lock file, whose targets
  only call those functions. So `cargo test --workspace` runs every seed and
  every kept crash on stable, clippy and fmt see the checks, and libFuzzer's
  C++ build stays out of every other build. The crate is left out of
  mutants: it is test code, held by the inputs it runs.
- **Stable, no sanitizer.** cargo-fuzz runs with `-s none` on the toolchain
  of `rust-toolchain.toml`. Only AddressSanitizer needs a nightly; it
  instruments Rust, which denies `unsafe`, and not the C grammars, which
  cargo-fuzz builds without it. A second, nightly toolchain to pin and raise
  would buy little.
- **Properties, not only panics.** The canonical form of an entry is a fixed
  point; the auditor and the merge give the same answer twice; under the
  current engine sides that parse never merge into a file that does not;
  after any socket traffic the log audits clean and the daemon opens again.
  Facts and merges are recomputed by whoever audits, so a result that
  depends on more than its input is a fault even without a crash.
- **A socket input runs on a fresh copy** of a repository built once per
  process (a human change, two bound agent sessions, leases, integrated
  and denied proposals, a policy change), so a crash is reproduced by its
  input alone. Markers in the input stand for the tokens; the fuzzer can not
  sign a human operation, and remotes on disk are refused, so it never
  reaches the network or files outside the copy.
- **Not on pull requests**, a deviation from the issue, kept from "CI runs
  for a release": every night on main and on demand, which the release
  checklist does before tagging. On a `v*` tag too (user, 2026-11-09:
  every release runs the fuzzer, never skipped), green before the draft is
  published. The corpus lives in the Actions cache, and a release run
  restoring a cache is what zizmor's `cache-poisoning` refuses, so on a tag
  the cache step is skipped (`if: github.ref_type != 'tag'`) and the
  targets start from their seeds. zizmor does not read the `if:`; its
  finding is ignored on that line, and the workflow publishes nothing.
- **What it finds is not published.** The repository and its logs are
  public, and a crash input is an exploit until fixed. The log names the
  target and the kind (`crash`, `timeout`, `oom`); the input and output are
  uploaded encrypted with age to the maintainer's key
  (`fuzz/crash-recipient.txt`). A fixed crash goes to
  `fuzz/regressions/<target>/`.
- **Git ids are read as written.** The first run found that a `GitId` took
  any string from JSON and `short()` cut it by bytes. JSON now gives one
  only as Lonca writes it, 40 lowercase hex digits (`TryFrom<String>`); no
  log or request of Lonca's holds another, and an entry decoded never
  changes on the way, so its hash does not either.
- **Not covered by a target:** `lonca mcp` and `lonca hook` read their input
  in the CLI, as the agent's own process; what they pass on crosses the
  boundary at the daemon (`hook.input`, `mcp.call`, every request), which
  `request` fuzzes.

## Acceptance tests (2026-11-10)

A release is accepted when it does, for the people who install it, what the
guides say; `cargo test` proves the parts, mostly against a daemon inside
the test process, and never runs the archives a release ships. The
acceptance tests (`docs/acceptance.md`, `acceptance/`) close that gap.

- **A catalogue and scenarios.** Each criterion has an id, one sentence a
  user would recognise, and the scenario that proves it. `acceptance/run.sh
  --check` fails when the catalogue and the scenarios' `criterion` lines
  disagree, so a criterion can not be listed and unproved, or proved and
  unlisted. Criteria that need a model, an account or hardware CI lacks are
  manual (M01, M02: the live harness runs and the install paths of the
  release checklist); what nobody checks yet is listed under "Not covered
  yet", so the gap is written down rather than implied.
- **Shell, not Rust.** A scenario is the commands a user types, run against
  any directory of binaries: a debug build, a release build, an unpacked
  archive. A Rust test would link the daemon or depend on a build of the
  same package; a script sees only the binaries and what they print. Bash
  3.2 (macOS's), with a small helper library; no network, no model.
- **Every pull request.** The `test` jobs of `ci.yml` run them on the
  binaries `cargo test` just built, so they are required checks and can not
  drift for a release to find. They take seconds.
- **Every release, mechanically.** `release.yml` runs them on the unpacked
  archives of macOS arm64 and Linux x86_64 and arm64, and the draft job
  needs those jobs: without a green run there is no draft to publish. The
  x86_64 macOS archive is not run (Apple silicon runners may not have
  Rosetta); it is the arm64 code built for another target.
- **Kept with the change.** Every pull request that adds, changes or
  removes user-visible behaviour adds, changes or removes its criterion in
  the same pull request. A criterion is never skipped or weakened to get a
  release out: the code is fixed, or the criterion changed in a pull
  request that says why the promise changed.
- **Found on the way:** `lonca-audit` had no `--version`, so a script could
  not check that the auditor it runs is the release it installed; it has
  one now (`lonca-audit X.Y.Z`, as `lonca --version`).
- **Found by the first release run:** on the static Linux archives
  `lonca-audit verify` replayed every recorded decision as a denial
  ("recursion limit reached"), on 0.2.0 to 0.2.2 too. Cedar fails an
  evaluation when less than 100 KiB of stack seem left, and musl reports a
  main thread's stack as only what is mapped so far; the daemon decides on
  worker threads, the auditor and the CLI on the main one. So a Cedar
  outcome depended on the thread and the libc, which `decide()` may not:
  every evaluation now runs on a 4 MiB stack of its own (`stacker::grow`,
  the crate Cedar already uses), whoever calls it. A test evaluates on a
  96 KiB thread. The glibc and macOS builds `ci.yml` runs could not show
  it; only the shipped archives did.

## Keyed directories (#261)

A user running Claude Code and Codex side by side found that, past ordinary
text conflicts, the only collision left was two agents taking one Flyway
version: `V12__a.sql` and `V12__b.sql` are two paths to Git and to the
merge, and both landed unless a check happened to run the migrations.

- **Data, not tools.** `[paths.keyed]` in `lonca.toml` names a directory
  and a pattern that reads a key from a file name; there is no Flyway or
  Django arm. The pattern is a `regex` crate expression, which compiles to
  automata and never backtracks: linear in the name, the same answer on
  every machine, bounded (200 characters, a 1 MiB automaton, 64
  directories, exactly one group). Matching is on the file name, and only
  a file directly in the directory has a key.
- **Numbers by default.** Every tool named in the issue numbers its files,
  and `12` and `012` are one migration to them, so keys compare as numbers
  unless `compare = "text"`. A lease writes a number without a leading zero,
  so two reservations of one key are one string and `names_meet` needs no
  change.
- **A key is a reserved name.** The directory is a container, `dir#<dir>`,
  and an `insert` on it reserves keys in `names` as an insert on a type
  reserves member names; conflicts, interests, reservations and pins work
  as they do for names. Anything else on a `<dir>` is refused (deny by
  default): another kind, no keys, a directory the policy does not name, a
  key the directory would not write. So is any other symbol of a keyed
  directory's path (`key_container`): the first live run had Claude lease
  `db/migration#db/migration` and `db/migration#migration`, which were
  allowed, reserved nothing, and left it believing it held the key. `status`
  lists the keyed directories, since an agent has no `lonca.toml`. This came
  before any release with format 29, so it is part of format 29.
- **`next` is the daemon's.** `decide()` can not read trunk's tree, so the
  daemon resolves `next` before deciding: one past the highest key on trunk
  and in every live reservation, written into the operation. The log
  records the number, and the replay decides the same.
- **Checked twice.** At proposal (format 29): every file an agent adds to a
  keyed directory needs its key reserved by its session, a name the pattern
  reads, and a key no other file has. "Other file" is the proposal's own
  tree, which the facts report as `taken_keys` (computed with the policy in
  force, and recomputed by the auditor with the policy at the entry), and
  the files trunk created since its base, from the state. At integration,
  for every change, a person's too: a merged tree with two files of one key
  that the trunk before it did not have is a conflict on `dir#key`, beside
  the file/directory clash. Only new clashes count, so a repository that
  already has two `V1` files is not stopped.
- **Pins without the policy.** `State::apply` has no policy, so it can not
  read keys; a proposal pins every key item of its session on a directory
  it adds files to. A key reserved and not used goes with the change too,
  and integration releases it.
- **Renames and deletes stay with the rules.** A rename adds a file, whose
  key is reserved like any other; keeping agents from deleting or rewriting
  migrations is a `policy.cedar` rule (the guide has one), not a built-in
  (decided with the user, 2026-11-10).
- **A run that started under another policy is done again.** The merge
  reads the keyed directories of the policy it began under, and the auditor
  those of the policy at the entry: the daemon logs an integration only if
  the policy's digest is the same when it does.

## A runner waits for events (#262)

A runner that starts several agents wants to wake an idle one when
something it cares about happens: a lease handed to it, an interest now
reserved for it, its change integrated, conflicted or refused, a message.
`inbox` rides on the agent's next tool call, which an idle agent never
makes, and `events` is a poll that marks what it returns as told, so a
runner polling with the agent's token took the news out of the agent's own
inbox.

- **Who waits: the human (option A of the issue).** `events.watch` takes
  the human session the runner started the sessions with, and looks at the
  sessions whose `root_human` is that human: every live one, or those named
  in `sessions`. The other option, the agents' tokens in the runner, would
  have put every token in one more process and made the runner hold ten
  credentials for ten agents. A runner already holds the human session (it
  ran `session start`); no new identity was needed. A session of another
  human and one never started are refused with one message, so the call
  says nothing about which sessions exist.
- **Never told, never the words.** The call keeps no state for the watcher
  and moves nothing in `Told`: the agent hears everything through `inbox`
  as before. A watcher gets the kind, the entry, the change and the sending
  session; never a message's text, its thread, the reasons or the
  conflicts. Those are another agent's words, and they belong in the
  agent's context, marked as such, not in a runner that may pass them on.
- **Stateless reservations.** A reservation is the state, with no entry
  of its own, and it lasts. Each is named by a hash of its session and
  items; the answer lists every name held now, the caller passes that list
  back, and a name it passed is not reported again. One that lapses and
  comes back is reported again, which is right: it is a new window.
- **Waiting as `log` waits.** The request is held, the daemon's lock is
  not; `notify_appended` wakes it, and the clock is looked at every
  `LOG_POLL_MS` (2 s), since a reservation or an expiry needs no entry.
  The same 30 s cap. A waiting request is a connection like any other and
  counts against the limits of #50; it is not throttled (a human is not).
- **An ended session ends the wait.** A session named in `sessions` that can
  not act any more comes back at once in `ended`, with its reason, so a
  runner does not wait on something that will never come. Without
  `sessions`, an ended session is simply no longer watched.
- Read-only: no log entry, no `decide()` change, no log format, and the
  protocol number stays 1 (a method added). `lonca events --watch` gives
  it to shell runners, `--follow` as one JSON line per event;
  `lonca_client::Client::watch` and `Watch::after` to Rust ones.

## Evidence names its environment (#263)

`Attestation.env` was documented as a digest of "sandbox profile, commands,
tool versions", but the verifier hashed the sandbox name and the command
only. Two passes of one command under different compilers carried one
`env`, so neither a reviewer nor the auditor could tell that the toolchain
changed, or whether the queue ran what CI runs.

- **Recorded, not run in.** The issue is about saying which environment
  produced a result; running checks in a container image, pulling images or
  any network stays out. A runner that wants CI's image makes its commands
  run in it, and `identify` names it.
- **`identify` is policy.** The commands that name the toolchain come from
  the signed policy, like the checks (at most 8, 1024 bytes each). They run
  once per verification, before the checks, in the same sandbox, tree,
  environment and `PATH` (a `rust-toolchain.toml` in the tree picks the
  same toolchain for both), for at most 10 seconds each. A failing or slow
  one is recorded and never fails a check: it is evidence about evidence.
  Of its output only the first 4 KiB is kept (`Running::keep_head`; the
  rest is read and dropped, so a full pipe never holds it): the checks keep
  the end of theirs, where a failure shows, but a toolchain names itself
  at the start, and a chatty command's tail would otherwise decide both the
  line and the digest.
- **What the digest holds.** Length-prefixed parts: the sandbox, the
  command, and an identity of the run (the `PATH`, the policy's `env` names
  and values, which are in the signed policy anyway, the passed-through
  names the daemon had, and each identify command with how it ended and its
  output). Passed-through values never: they may be secrets, so where an
  identify command prints one it becomes `***` before the digest and the
  lines.
- **Readable lines in `details`.** `env.<n>.command`, `.output` (the first
  non-empty line, 200 characters, control characters as `?`) and `.error`
  on every check of the run, skipped ones too, so a person sees
  `rustc 1.91.0` and not only a hash. `change.get` gathers them as
  `environment`, `lonca change --evidence` prints them.
- **No log format change.** `Attestation` keeps its fields: `env` is a
  string and `details` a map, and neither is ever recomputed. Entries from
  before hold the old digest and no lines; they replay and audit as they
  did. The first integration after an upgrade has a new digest, which the
  auditor notes once.
- **The auditor notes, never finds.** It can not recompute evidence, so a
  changed `env` is no fault. `Report.env_changes` lists each check (by its
  evidence name: `build`, `tests`, `extended` or a named check's name) whose
  `env` differs from the last entry that ran it, with both sequence numbers;
  `lonca-audit verify` prints one line each, beside the daemon key switches.
  Every entry with evidence counts, denied attempts too: each says what ran.
- **Reused evidence.** A tree verified within the hour is not run again
  (`VERIFIED_FOR_MS`); its evidence, identify lines included, is that run's.
  The cache key is a digest of the whole `[verification]`, so a new
  `identify` list runs again.

## Where a session works is in the log

Format 30. Until it, the only record of which session a directory belonged
to was `.lonca/workspace.json` in that directory, and an agent writes its
own workspace. The hook, `session start --continue` and a human's commands
all read it. What a session's own directory says about the session is no
longer asked.

- **`session.start` names `workspace`**: an absolute, normalized path with
  its links resolved by the CLI (`invalid_workspace` otherwise; the rules
  are a scratch root's). It is in the signed entry, so it is the human's
  word, as `harness` is. A session started without one has none: it is not
  continued and no hook is placed by its directory. Children stand in
  their parent's.
- **One directory, one live session** (`workspace_in_use`): a start in a
  directory that is, holds or lies in the workspace of a live root session
  is refused, the session it continues excepted.
- **A session is continued where it was started**
  (`continue_other_workspace`). `lonca session start --continue DIR` asks
  the daemon which session the log places in `DIR` (`session.where`) and
  names that one; the id in the directory's file is not read. A session
  from before format 30 has no workspace in the log and can not be
  continued: start a new one. So can not a workspace that was moved.
- **A continuation starts `unobserved`.** It kept its predecessor's level
  until its harness reported; a level is now what a bind of this session
  showed. Taint, writes and `shell_seen` go along as before. Entries of
  older formats replay as they were.
- **`session.where` is public.** It is the question of a program that has
  no token it can trust: a hook whose workspace file does not read, a
  human's command in a directory. It answers with a session id, its
  repository, workspace and whether it is live, for a path or for a
  harness's own session id (`session.bind` records it as
  `harness_session`). None of that opens anything; any socket peer learns
  which directories have sessions.
- **The hook asks before it stands aside.** `lonca hook` did nothing where
  it found no agent workspace. It now asks `session.where` first, with the
  directory and the short strings of its input (the daemon reads the
  harness's session id out of them with the profile). A live session
  there, or bound to that harness session: the hook goes on as that
  session's from the logged directory, and if that directory's metadata
  does not read as the session's, the tool call is blocked. With no daemon
  to ask it stands aside only where no `.lonca/workspace.json` is above
  it. `hook.input` carries the resolved root (`real`), and the daemon
  refuses one that is not the session's logged workspace. (`hook.bind`
  no longer places network use by a directory at all: "Whose connection
  it is".)
- **A human's command in an agent's workspace is refused** when the file
  there names no session (`sync`, `diff`, `propose`, `status` without
  `--repo`), and commands that take the repository from the workspace take
  the log's where the log places a session. A directory once used by an
  agent's session is not reused for a human's workspace.

## A child session is its parent's agent

Format 31. `cap.attenuate` carries an `agent` for the child, and until this
format it was any well-formed name. But the policy knows an agent by its
name and nothing else (`Lonca::Agent::"<name>"`), and a name is also what a
human reads beside a pending change. A child with a name of its own stood
outside every rule written for its parent, and inside those written for the
name it took.

- **`agent` must be the parent's** (`child_agent_name:<the parent's>`). A
  child is the same agent with less: narrower scope, no longer life, the
  parent's level and harness, and now its name. Sessions are told apart by
  their ids and by `parent`, as before.
- **Why not another principal for Cedar.** Evaluating a child as its root
  session's agent would keep the rules whole, but leave the name a human
  sees in `pending` to the agent. One name, given by the human who started
  the root session, is the simpler rule.
- **The field stays** in the request and the entry: older entries keep
  their bytes and replay as they were, and nothing in the protocol changes
  shape.

## A path that forbids is read with its case folded

Format 32. A scope is a list of what a session may touch, and a spelling it
does not list is refused. `[paths] critical`, `[paths] untrusted`,
`checks_by_path` and a `forbid` on `context.path` are the other kind: lists
of what is *not* free, and they matched the spelling. macOS opens
`Build.rs` as `build.rs`, `.Cargo/config.toml` as `.cargo/config.toml` and
`Vendor/x.c` as `vendor/x.c`, so a tainted session wrote a build script by
changing a letter, and a read under `vendor/` did not taint.

- **These lists read a path as such a file system does**
  (`lonca_core::paths::folded`), pattern and path alike, on every platform:
  a repository is checked out on a Mac sooner or later, and one answer
  everywhere is what a replay needs. Scopes and leases stay exact.
- **The table is Lonca's own**, not the standard library's: `decide()` is
  replayed, and what it answers may not move with a Unicode version. ASCII
  letters are lowered; the characters such file systems read as ASCII
  letters are written as those (the Kelvin sign, the long s, the Latin
  ligatures, the sharp s); what HFS+ leaves out of a name is left out.
  Letters outside ASCII stand as written: a pattern `Çekirdek/**` matches
  that spelling only, and says so in the guide. Folding too much makes a
  path critical that was not, never the other way.
- **Cedar gets `context.folded`** beside `context.path` on the `file.*`
  actions. `like` can not fold, and folding `context.path` itself would
  silently stop every rule written with a capital (`*Cargo.lock`). A rule
  that forbids by name reads `context.folded` with a lower-case pattern;
  the shipped policy and the guide's examples do. A rule that allows by
  name (`!(context.path like "docs/*")`) was never open.
- **`untrusted` folds without a format**: the hook records what a read
  brought in once, and nothing recomputes it. `critical` and
  `checks_by_path` are in `decide()`, so entries before format 32 replay
  as they were decided.
- **`context.folded` is there in every format.** `lonca policy check`
  tries a candidate policy on the entries of the log, each at its own
  format; a key that began at 32 would make every older file request a
  `policy_error` for the first policy that reads it. The one log this
  replays differently is one whose policy read `context.folded` before it
  existed: every file request of that policy was an error and a denial, so
  no policy that was in use did.
- **Not done:** refusing a new path that differs from an existing one only
  in case. It needs the tree in `decide()`, and what it would add is a rule
  about a directory a pattern does not name.

## A human signature is for one log

Format 33. A human signed the repository's name, the operation, a nonce and
a time. Nothing in that says which log: an `approve` names its target by
number, and the freshness check reads the entry's own time. Whoever holds
the daemon key (in cooperative mode an agent can read it) could write the
log again from an earlier entry, put another proposal at the approved
number, and carry the signature over; a second repository of the same name
with the same key enrolled took it too. The chain verified and the auditor
replayed it.

- **A signature names the head its signer saw**: `at`, the number and hash
  of the last entry (`log.head`), inside the signed bytes
  (`lonca-human-intent-v2`). `decide()` refuses a signature that names no
  entry, an entry this log does not have, or an `approve` or `reject` of
  an entry later than the one it names. A hash covers everything before
  it, the genesis included: the log a signature holds in is the one its
  signer was shown, up to that entry.
- **Why the head and not the target's hash.** Every signed operation gets
  the same rule, not only the two that name an entry: a policy update or
  an enrolment is not moved to another log either. And the head says the
  signer could have seen the target; a hash of the target alone does not
  bind what stood between.
- **Why not `prev`.** The entry that takes the signature is rarely the
  next one: agents append while a person reads and touches. So the state
  keeps the hashes of the entries a live signature could name
  (`State::seen`): those of the last eleven minutes (`MAX_AGE_MS` +
  `MAX_SKEW_MS`) and the one before them, the head for as long as nothing
  followed it.
- **What it does not stop.** A log rewritten after the entry a signature
  names keeps that signature where it was: it is still for what it
  approved. Replacing the log wholesale is the auditor's question
  ("lonca-audit verify has no anchor" is its own item).
- **`log.head` is public.** A recovery is signed by someone who has no
  session, for a repository whose daemon key may be gone (`foreign`), and
  a hash says nothing of the log's content.
- **A genesis and a login name no entry**: there is no log yet, and a
  login is not an entry.
- **The signer asks the daemon it submits to.** A daemon that lies about
  the head gets a signature it can not use in the real log.

## What enters a session enters its children

Format 34. A child made with `cap.attenuate` copied its parent's level,
taint and `unhooked` mark at that moment and went its own way. The parent
keeps the child's token: it asked for it. So a session made a child while
clean, read the web, and went on leasing and proposing as the child, whose
record said nothing had entered it. In an isolated session that is a change
with no human; at any level it is a critical path that escalates instead of
being refused.

- **`taint`, an external `observe`, an `unhooked` tool and a `session.bind`
  reach every session below the one they name**, live or not, in the same
  entry: the taint as `inherited: <reason>`, the mark as it is, the level
  as the lower of the two. The state carries it, so `decide()` reads one
  session as before.
- **Down only.** A child's taint does not rise to its parent: the parent
  gave the child less, and what a child reads the parent's harness reports
  for the parent when it comes back as a tool result. (Session trees made
  by one harness process answer for each other at the proxy already.)
- **A level only falls this way.** A parent bound higher again does not
  lift a child; nobody vouched for the child since.
- **Why in `apply` and not a walk in `decide()`.** Every reader of a
  session (the policy context, `status`, a reviewer's `pending`) then sees
  the same thing, and no check can forget to walk.

## The macOS sandbox reads programs, not what services keep

The Seatbelt profile opened `/usr` and `/opt` whole: that is where the
programs are, Homebrew's included. Homebrew also keeps the data
directories of local databases under `var` and the configuration of
services under `etc`, passwords among them, readable by the user and so by
an agent's code in a sandbox that was meant to see none of the user's data.

- **`/opt/homebrew/var`, `/opt/homebrew/etc`, `/usr/local/var` and
  `/usr/local/etc` are closed**, after the system's trees open, except the
  certificate stores a TLS library reads (`etc/openssl*`,
  `etc/ca-certificates`). A `read` of the policy comes later in the
  profile and opens what it names. A list of what to open under `/opt`
  instead (`bin`, `lib`, `Cellar`, …) would miss whatever a formula puts
  elsewhere, and a build would fail for no reason a person could find.
- **`trustd` only where there is a way out.** A sandbox with no network
  has no certificate to judge; verification no longer may ask it. An
  isolated session may: its TLS goes through the proxy, and the native
  libraries verify with it. What `trustd` fetches on its own is a limit in
  the threat model, unmeasured.
- **Shared memory and semaphores stay open by any name.** Programs choose
  the names (`multiprocessing`, test runners); a prefix per run can not be
  given to them, and closing them breaks the suites the sandbox exists to
  run. Written down as a limit of macOS; Linux has a `/dev/shm` per run.
- **A test runs the real `sandbox-exec`** with the profile: nothing else
  reads its regular expression.

## Text for a terminal

A person approves from what `pending`, `diff` and `status` show, and most
of that text is an agent's: an intent, a path, the lines of a file, the
reason of a denial that quotes another agent. A terminal obeys escape
sequences, carriage returns and bidirectional controls, so such text could
redraw the list it was part of.

- **One place writes** (`crates/lonca-cli/src/out.rs`). Everything the CLI
  prints for a person goes through `out!`, `outln!` or `errln!`, and they
  pass the finished text through `lonca_core::terminal::printable`. A
  command can not forget to clean a field, because no command cleans one,
  and clippy refuses `println!` and `eprintln!` in the CLI
  (`print_stdout`, `print_stderr`, denied in `main.rs`).
  `lonca-audit` does the same for its report.
- **Written out, not dropped.** `\u{1b}`, `\r`, `\u{202e}`: the reviewer
  sees that something was there. Newlines and tabs stay. All of C0 but
  those two, DEL, C1, the bidi controls and U+2028/2029.
- **Always, not only on a terminal.** Output piped to a pager reaches a
  terminal too. A program reads `--json`, which has the text as it is: a
  JSON string has no raw control character.
- **What writes as it is**: `doctor`'s own colours (`write_painted`; what
  it shows from elsewhere is cleaned before it is painted), the hook's and
  the MCP server's JSON, and the output of the command `lonca run` runs,
  which is that command's terminal.
- **Not refused at the source.** Intents and paths may still hold these
  characters in the log: refusing them is a rule of `decide()` and a log
  format, and what shows them is the place that must be right either way.
  A program that shows Lonca's JSON to a person has the same duty.

## One value of the policy from the command line

`lonca policy set --value sessions.ops_per_minute=1200` (and the same on
`policy check`). Changing one number used to mean `policy show`, two files
cut out of its output, an editor and `policy set` with both.

- **Any key, not one flag per setting** (`KEY=VALUE`, the table and the
  name). A flag for the rate would be the first of thirty; the keys are
  data the policy already names, and `lonca.toml` refuses the ones it does
  not have.
- **The file is edited in place, by line** (`lonca_policy::edit`). The
  file in force is a person's, with their comments, and writing it out
  again from its values would drop them. No TOML editing crate: after the
  line is changed, both texts are read as TOML and the new one must be the
  old one with that key set and nothing else different. What the line
  edit can not place (a value over several lines, a key written with dots
  or quotes) fails that comparison and is refused with where to go:
  an editor and `--config`.
- **In the CLI, not the daemon.** It reads the files in force, edits, and
  sends `human.prepare_policy` as before: no method, no protocol change,
  and what is signed is a whole policy, as always.
- **The value is TOML when it reads as TOML, a string otherwise**, so
  `observation.network=deny` needs no quotes inside quotes. `"12"` is the
  way to say a string of digits.

## A request's own work is done without the lock

The daemon has one lock for its state, and the single writer is whoever
holds it. Three methods kept it through work whose length their caller
decides, so one session could stop every other answer, for every
repository (private advisory, 2026-11-11): `facts.preview` built and
parsed a commit of up to 64 MiB under it, `events` read the whole log,
and `trunk.bundle` ran git for up to its 600 s. None of the three is
counted against a session's rate.

- **`facts.preview`** takes the store and the policy, lets the lock go,
  builds its commit (since then in a store of its own: "The stores' disk
  keeps room for the log") and reads the facts, and takes the lock again for who
  holds which lease now. The session is asked for again then: it may have
  ended meanwhile. The policy is the one from before the work, like a
  proposal's facts would be if the policy changed a moment later.
- **`events`** copies the state and its next sequence number, lets the
  lock go, reads the log and leaves out what was appended since: the
  answer is the log as it stood, and `next` is where the next call
  starts, so nothing is told twice or skipped.
- **`trunk.bundle`** makes the bundle without the lock and then asks
  whether `refs/heads/main` is still the trunk it read before; if not it
  makes it again, three times, then `busy`. Trunk only moves forward, so
  a ref that is the same after is the same throughout.
- **A proposal still holds the lock** while its commit is built and read:
  it is the writer, and its place in the log is what the lock gives it.
  The session rate bounds that. `repo.prepare_init` and `repo.restore`
  fetch under it as before ("No push under the lock").
- **Tested for the preview** (`a_long_preview_does_not_hold_the_daemon`:
  a status request is answered while a ten-second preview runs; before, it
  waited 9.5 s). The other two have no test of the lock itself: nothing in
  them can be made slow from a test without a hook in the daemon that
  exists for the test. Their answers are tested as before.

## What a caller adds to the log is bounded

The log keeps every entry for good, the refused ones too: that is what
makes it a record. So whatever a caller can put in an entry, and however
often, is what the store's disk and every replay pay for. Three ways were
open (private advisory, 2026-11-11).

- **An entry's operation and its human signature take 64 KiB at most**
  (`MAX_OP_BYTES`, `RepoHandle::op_fits`), asked before anything is decided,
  signed or written to the store. An operation's free text and lists came in
  on lines of up to 96 MiB, and the limits the policy has on them
  (`leases.max_items`, `intent_too_long`) are decisions: the refused entry
  was logged whole. Past the limit the answer is `invalid`, with the
  operation's name, its size and what to do, and nothing is logged. 64 KiB
  is what a line that may not be long holds; the policy's own limits (64
  lease items, 200 files) fit many times over.
- **Not a rule of `decide()`.** It would need a log format, and it would be
  the wrong place: a size refused by `decide()` is again an entry. Like the
  session rate, it is the daemon declining to write; the auditor has
  nothing to recompute, and an older log with a longer entry still replays.
- **The daemon's merge results are let past it** (`change.integrate`,
  `change.integrate_batch`). Their conflicts and merged lists are as long
  as the repository makes them, and a refusal there would leave the queue
  with a change it can never finish. Facts and evidence are not counted
  either: the daemon computes them, from files the policy already bounds.
  Everything else the daemon writes for a caller is held to it, `observe`
  too: a hook event with a path past it is an error, which the hook answers
  by blocking.
- **A submission that needs no session is decided before it is logged.**
  `human.recover` comes in on its signature alone, so anyone who can open
  the socket could send one, each a denied entry. Now a denial there is
  `forbidden`, which the security log records (it rotates), and no entry.
  A signed-in human's denied operation is still an entry: the session says
  who asked, and a reviewer reads that record. An escalated recovery is
  logged as before; an escalation comes after a signature that verifies.
- **The proxy records at the session's rate.** Every connection through it
  is an `observe` entry for each session it counts against, and nothing
  bounded how many a minute. They now spend from a bucket of
  `sessions.ops_per_minute` per session, apart from the one for the
  session's own operations, so a build that opens many connections does
  not stop its agent's requests. Past it a connection is refused and not
  recorded, which keeps the rule that nothing goes through the proxy
  without being on the record. Not a new policy key: the number already
  says how fast one session may grow the log.
- **The rate has a ceiling the policy can not lift**, 6 000 a minute
  (`MAX_OPS_PER_MINUTE`, ten times the default; user's rule 2026-11-11: a
  limit somebody sets is not trusted to be a safe one). The rate is now what
  bounds the log's growth, and a policy could set it to four thousand
  million. A new policy above the ceiling is refused, when it is prepared
  and again when it is submitted (`PolicyBundle::parse_new`). One already
  in force is not refused, since a repository whose policy does not read
  does not open, and a policy can only be replaced through one that does:
  it counts as the ceiling (`Sessions::rate`).
- **What is left.** A session at its rate with entries at the limit still
  grows the log, by what the policy allows it; and a proposal's files are
  objects in the store whatever the log says: "The stores' disk keeps room
  for the log", below.

## The stores' disk keeps room for the log

What a caller sends as files was written to the repository's store before
anything was decided, and nothing asked how much room the disk had left
(private advisory, 2026-11-11). The store is on the disk the log is on: once
it is full no entry can be appended, so no lease, no merge, and no freeze or
revocation either, for every repository of that daemon.

- **A preview's objects are not the store's.** `facts.preview` built its
  commit in the store: up to 64 MiB of blobs a call that no ref names, from
  a method no rate counts and no entry records, and nothing ever removed
  them. It now builds in a store of its own in the scratch directory
  (`Store::beside`: its objects directory names the repository's as a Git
  alternate, so the base is read and nothing is copied), and that directory
  goes when the preview has answered, refused or not. A daemon that stopped
  in the middle of one leaves a `preview-*` directory; the next removes it
  at its start, with the verifier's left-overs. Throttling the preview was
  the other way: it would have spent the rate a session's operations need,
  and a rate bounds a minute, not a disk.
- **Below 1 GiB free nothing a caller sends is written** (`KEEP_FREE_BYTES`,
  `Service::room`): `change.propose`, `facts.preview`,
  `human.prepare_change` and `human.prepare_policy` answer `disk_space`
  before a blob is written, and nothing is logged. A proposal's objects stay
  whatever is decided of it (a refused one is a record too), so the disk is
  asked before, not after. The log itself is not held to it: the floor is
  there so that entries can go on, and a session's heartbeat, a freeze or a
  revocation needs kilobytes. A disk that can not be asked counts as full,
  as for the verifier.
- **A number in the code, not a policy key.** The policy is a file in the
  store it would protect, each repository has its own while the disk is one,
  and a floor somebody can set to nothing is not one (the rule of
  `MAX_OPS_PER_MINUTE`). 1 GiB is `[verification] keep_free_bytes`' default:
  the two guard the same disk, and below it no proposal could be verified
  anyway. Tests set it through `Settings::keep_free`.
- **A look, not a quota.** Proposals are written one at a time under the
  lock, so each sees what the last left; previews run beside them, each up
  to 64 MiB for as long as it takes, bounded by the connections.
- **What is left.** A session can still take the disk down to the floor
  with proposals: 64 MiB each, at its rate, each one an entry that names
  it. Then proposals are refused for everyone until a human frees space,
  and ending the session gives nothing back: the log is append-only, and
  what its entries name stays. Nothing tells a human that the floor was
  reached except the refusals themselves. What a human fetches
  (`repo.init --import`, `repo.restore`, `human.prepare_import`) is git's
  to write and is not asked about.

## A path is where its links lead

The hooks placed a tool's path inside or outside the workspace by its text:
`.` and `..` folded away, the result compared with the workspace's path
(private advisory, 2026-11-11). A symbolic link in the workspace was a way
out nobody saw: a write through it was an inside write, a read through it
an inside read that did not taint.

- **The hook program resolves, the daemon places.** The daemon reads the
  event with the profile of the signed policy, so only it knows which
  fields are paths; and it often can not see the workspace (another
  account in hardened mode). So `hook.input` first answers `"phase":
  "resolve"` with the paths the call names, the workspace and the scratch
  roots, and `lonca hook` sends the request again with where each really
  is. One more round on the socket for a file tool; nothing is logged in
  the first. The hook program is as trusted as before: it already says
  which workspace this is.
- **Walked as the kernel walks** (`lonca_client::real_path`): link by link,
  `..` leaving the link's target and not its name, which is why the daemon
  asks about the text unfolded. What does not exist yet is kept as named;
  a link to nothing is followed, since a write through it creates the
  file there. `std::fs::canonicalize` fails on both.
- **What nobody resolved is outside**: a loop, a directory that does not
  open, a path past the 1024 one call is resolved for (`MAX_RESOLVED`),
  the workspace itself left out. A write there is denied, a read is
  external.
- **An older hook program is refused, not believed.** The first answer
  carries a denial in the harness's shape, which a program that does not
  know the phase passes on. Reading its paths by their text would have
  kept the hole for whoever kept the old program.
- **`hook.event` without `real` places by the text**, as before: its
  caller is a harness integration that has read the event itself and can
  resolve (`real`), and the tests and runners that send plain paths go on.
  Said in `docs/protocol.md`.
- **What a link to a workspace file writes is that file**: recorded under
  its own name, so a proposal of it is an observed write, and `.lonca/`
  and the `untrusted` patterns hold whatever names the file.
- **A look at the time of the call.** A link made or turned between the
  hook's answer and the tool's write is not seen; an agent with a shell
  nothing holds can write anywhere without a link. At `hooks_sandbox` the
  sandbox holds the shell to the workspace, and the link is what took the
  file tools past it: that is what this closes. Shell commands are still
  not read for paths.
- **Names are compared as written.** On a file system that folds case a
  path in another case is, at worst, outside; patterns and case are their
  own question.

## Whose connection it is

The proxy charged a connection (log entry, taint, `max_connections`,
`max_bytes`, the recording rate) to the session in whose workspace the
connecting process had its working directory, and to every sandboxed
session when it stood in none. A process chooses where it stands: a
command of one session that entered another's workspace first was
recorded for the other alone, and fetched without its own taint.

- **By descent, not by directory.** A session is known by the processes
  it was bound from: the daemon reads the peer of the socket request
  (`LOCAL_PEERPID`, `SO_PEERCRED`) at an allowed `hook.bind` (the hook the
  harness ran) and at `session.isolate` (`lonca run`, which then starts
  the command), and keeps that process with everything above it, each as
  number and start time (`ps -A -o pid= -o ppid= -o lstart=`), so a number
  used again is another process. A connecting process (`lsof`, as before)
  is followed up the same way, and the sessions it meets nearest answer
  (`lineage::answering`): a command under harness A meets A at the
  harness, and B, started from the same shell, only at the shell.
- **Fail closed, as before.** Sessions that meet it at the same process
  answer together. A process whose parents ended is given to the system's
  first process (or a reaper above the harnesses): it meets every session
  there, so all of them answer, its own among them. A session nothing
  places (after a daemon restart, or bound from no process the daemon
  could read) answers for every connection. No process named (`lsof` or
  `ps` missing, another account's process in hardened mode) is everyone's,
  counted in `proxy_unattributed`, which now also counts a process that
  descends from nothing any session was bound from.
- **A bind adds and never takes away.** An agent holds its session's
  token and can send `hook.bind` itself, from wherever it likes. Lines
  are only added (processes that ended fall out); with more than 8 the
  session is placed by none and answers for everything. A refused bind
  adds nothing.
- **A child answers with its parents.** What a session made by
  `cap.attenuate` fetches, the session it came from can read: the
  connection is on both records.
- **The directory is not used.** `"workspace"` in `hook.bind` and in
  `human.submit` (with `session.isolate`) is still accepted and says
  nothing; no protocol number for a field that is ignored.
- **What stays.** A session can still make the others answer with it (a
  command that leaves its parents is everyone's), so it can taint them
  and spend their connections and bytes, at the price of its own; any
  process of the account can do the same. Telling such a process from a
  session's own needs an identity the process can not drop, which one
  account does not give. Harnesses that run several sessions in one
  process tree answer together. A process that gets another program to
  connect for it (a helper outside its own descent) is that program's.

## A tunnel is for the host it was asked for

The proxy decided by the host a client asked for (`CONNECT host:port`, or
the target of a plain request), resolved it, and relayed whatever came. An
address often serves many names (a content network, a shared host), and
which of them answers is said by the client again, further in: the server
name of its TLS hello, or the `Host` header. A command let through for one
allowed host could so reach any other name at that host's addresses, and
the log said the allowed one.

- **The server name is the host.** For a `CONNECT` to a name, what the
  client sends first is held back until it is known not to be TLS, or to
  be a TLS client's first message (`lonca_net::hello`, read from the clear
  bytes, across records, 64 KiB at most). A name in it that is not the
  host (case and a last dot aside) ends the tunnel before a byte of the
  client's reaches the host (`Outcome::Misnamed`); so does a first message
  that can not be read to its end or names a server twice. No name at all
  passes: it chooses nothing. The other direction is not held, so a server
  that speaks first is heard.
- **An address is an address.** A tunnel asked for by address (`CONNECT
  10.0.0.5:443`) is not held to a name: the policy let the address
  through, with whatever it serves.
- **A plain request names its host once, and is alone.** Its `Host` header
  has to be the target's host and port; another, a second one, a folded
  header line or a line that is no header is answered 400 before the gate
  is asked. What follows a request on its connection is relayed unread,
  so the head goes on with `Connection: close` (the client's `Connection`,
  `Proxy-Connection` and `Keep-Alive` are dropped): a server that follows
  HTTP reads no second request. A client that sends requests for several
  hosts over one proxy connection now gets each on its own; they used to
  go to the first one's host.
- **In `lonca-net`, for every gate.** It is the same promise as connecting
  to the address that was checked, and needs nothing a gate knows. A gate
  that serves a tunnel itself (`Gate::relay`) gets it before this and is on
  its own.
- **What stays.** Inside TLS the proxy reads nothing: a client that says
  the allowed name in its hello and another in the `Host` header of the
  request within is not seen, and is refused or served as the host's own
  front end decides. An encrypted client hello (ECH) hides the inner name
  by design; it is let through as long as the name outside is the host's,
  since browsers send the extension on every connection, real or not. TLS
  that starts later on a connection (`STARTTLS`) is not looked for. The
  client is not told why a tunnel ended: after `200` there is no place to
  say it.
- **Encrypted hellos stay let through** (decided 2026-11-11). Refusing
  every hello with the extension would close the inner name and take the
  network from every browser in a sandbox; it was weighed and left.
- **A cut tunnel is a security event** (decided 2026-11-11). The log has
  the attempt under the host that was let through, which is what the
  session asked the proxy for; that the client then asked the server for
  another name was written nowhere. The proxy tells its gate
  (`Gate::misnamed`, with the name, or none for a hello that can not be
  read), and the daemon writes `misnamed_tunnel` to `security.log` for
  every session the connection counts against: the host and port of the
  tunnel and the first 128 characters of the name asked for. A session
  can cause one per connection, and connections come at
  `sessions.ops_per_minute`; they push out their own kind only. It
  taints nothing and freezes nothing: the connection was already an
  observation, and nothing of it reached the host.

## The hook that is checked is the hook that runs

A session is `hooks` or `hooks_sandbox` when the administrator's settings
name Lonca's hook for every tool and the hook's program is out of a
user's reach (`hook_binary_protected`). Two ways the check said yes to a
program a user could replace:

- **The command's first word was the program.** `/usr/bin/env lonca
  hook` passed on `env`, which then finds `lonca` by the user's `PATH`;
  `/bin/sh -c …` and `…/lonca hook; other` passed the same way. A hook's
  command now has to be `<path>/lonca` followed by plain words (letters,
  digits and `/._-=:,+@`, single spaces): nothing a shell would work out,
  no other program in front. A path with a space in it does not pass;
  the installers use none.
- **A path was checked as named.** Owner and mode were read through
  links, the directories only along the name: a link in root's directory
  to root's file in a directory anybody can write passed, and the file
  could be replaced there. The path is now also checked where its links
  lead (`canonicalize`), file and every directory above it; the same for
  the managed settings file itself.

Both fail closed: a settings file that passed before and does not now
gives `unobserved` and a note in `lonca doctor`. What the hardened
installers write passes unchanged.

## Open questions (carried from the design)

- Team server: one sequencer per repository works for one machine; a
  shared server needs remote authentication and per-user rate limits.
- Redaction in published history.
- Precise caller analysis for signature changes (LSP or compiler).
- Running the base test suite against changed tests ("test integrity"
  currently escalates deleted or skipped tests; it does not rerun suites).
- Harness levels for agents other than Claude Code (Codex, Cursor, ...).
- A real hardened install on macOS (Linux was measured; see "Hardened
  mode in the field").
