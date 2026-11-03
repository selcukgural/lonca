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
