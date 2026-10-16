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
