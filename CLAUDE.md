# Lonca

Agent-native, Git-compatible version control in Rust. Design: `docs/design.md`
(Turkish) — read it before changing behaviour. Decisions and deviations from
the design: `docs/decisions.md`.

## Invariants (never break these)

- The core, the gatekeeper and `decide()` have no AI, network or randomness
  dependency. `decide()` is a pure function; every input (time included) is
  in the operation entry. Evidence (build/test results) is recorded, never
  recomputed; facts and merges are deterministic and recomputed by the
  auditor.
- Every write goes through the daemon's single writer: decide, sign, append
  to `refs/lonca/oplog`, then apply. Never write repository refs directly
  except in `reconcile()` (restoring what the log says).
- The operation log is append-only. Undo is a compensating operation.
- Agents hold no long-lived keys; session tokens are stored only as hashes
  and never logged. Deny by default: unknown operation types, scopes and
  paths are refused; Cedar evaluation errors deny.
- Hardened mode: daemon, hook program and stores never live where the
  developer's account can write.

## Working on the code

```sh
cargo test --workspace          # ~110 tests, includes real sandbox and socket tests
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
cargo deny check                # advisories, licenses, crates.io only (deny.toml)
```

- Every decision scenario test ends with a replay of its log
  (`assert_replay`); keep that pattern for new operation types.
- A new operation type needs: `ops.rs` (Op, OpKind, as_str), `decide.rs`
  (who may request it, per-op checks), `state.rs` (effects), and the
  auditor's deep checks if it carries recomputable data.
- Unix socket paths are limited to ~100 bytes; tests use short temp dirs or
  `LONCA_SOCKET`.
