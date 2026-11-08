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
cargo test --workspace          # ~880 tests, includes real sandbox and socket tests
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

## Mutation testing

cargo-mutants checks that the tests would catch a wrong `>=`, a dropped `!`
or a `decide()` arm replaced with `Ok(Allow)`. Config: `.cargo/mutants.toml`
(whole-workspace tests per mutant, timeouts); policy: `docs/decisions.md`.

```sh
cargo install --locked cargo-mutants@27.1.0 cargo-nextest@0.9.151
cargo mutants --list -p lonca-policy        # what would be mutated
cargo mutants -p lonca-policy -j 4          # one crate
```

- Results are in `mutants.out/`: `missed.txt` lists survivors (tests still
  pass with the mutant: a gap), `timeout.txt` hangs (counted as caught, so
  read it: many mean the tests never ran, and CI fails a shard with more
  timeouts than caught), `unviable.txt` mutants that do not compile
  (ignored), `caught.txt` the rest; `diff/` has each mutant as a patch.
- A new survivor in a security-critical file (`decide.rs`, `chain.rs`,
  `state.rs`, `oplog.rs`, `canonical.rs`, `changeid.rs`, `keys.rs`, the
  auditor, the merge) is fixed with a test, or listed in `exclude_re` with
  a written reason why it is equivalent.
- `exclude_re` and `--re` do not filter "delete field … from struct"
  mutants (cargo-mutants 27.1.0); use file globs or a test.
- Tests must stay hermetic: own temp dir, `127.0.0.1:0` ports, short socket
  paths, no writes to `$HOME`. Parallel jobs (`-j`) run copies at once.
- CI (`.github/workflows/mutants.yml`) runs mutants only for a release:
  on a pushed `v*` tag, and on demand (`gh workflow run mutants.yml --ref
  main`, before tagging). The whole workspace runs in 20 shards
  (`full k/20`); any survivor fails its shard and is listed in the run's
  summary and in the `mutants-full-<k>` artifact (`missed.txt`). Survivors
  are fixed before the release. No mutants run before a push or on a PR.

## CI

The tests (`ci.yml`: `test (ubuntu-latest)`, `test (macos-latest)`,
`sandbox`) and the mutants run only for a release: on a pushed `v*` tag, and
on demand before tagging (`gh workflow run ci.yml --ref main`). Pull requests
and merges to main run neither, and the main ruleset requires no check.
`cargo-deny` and CodeQL still run on pull requests; they block nothing.
A PR is merged as soon as it is opened (`gh pr merge --merge`): with no
required check GitHub refuses `--auto` ("clean status").
