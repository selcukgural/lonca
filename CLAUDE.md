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

## Mutation testing

cargo-mutants checks that the tests would catch a wrong `>=`, a dropped `!`
or a `decide()` arm replaced with `Ok(Allow)`. Config: `.cargo/mutants.toml`
(whole-workspace tests per mutant, timeouts); policy: `docs/decisions.md`.

```sh
cargo install --locked cargo-mutants@27.1.0
cargo mutants --list -p lonca-policy        # what would be mutated
cargo mutants -p lonca-policy -j 4          # one crate
git diff main -- crates > /tmp/git.diff && cargo mutants --in-diff /tmp/git.diff -j 4
```

- Results are in `mutants.out/`: `missed.txt` lists survivors (tests still
  pass with the mutant: a gap), `timeout.txt` hangs (counted as caught),
  `unviable.txt` mutants that do not compile (ignored), `caught.txt` the
  rest; `diff/` has each mutant as a patch.
- For a PR, run `--in-diff` over the whole diff against its base. Do not
  narrow it with `-f`, because survivors in other files are missed.
- A new survivor in a security-critical file (`decide.rs`, `chain.rs`,
  `state.rs`, `oplog.rs`, `canonical.rs`, `changeid.rs`, `keys.rs`, the
  auditor, the merge) is fixed with a test, or listed in `exclude_re` with
  a written reason why it is equivalent.
- `exclude_re` and `--re` do not filter "delete field … from struct"
  mutants (cargo-mutants 27.1.0); use file globs or a test.
- Tests must stay hermetic: own temp dir, `127.0.0.1:0` ports, short socket
  paths, no writes to `$HOME`. Parallel jobs (`-j`) run copies at once.
- CI (`.github/workflows/mutants.yml`): on every PR the mutants in the
  diff against the base branch run over six shards (`mutants k/6`), each
  failing on any survivor, and the `mutants` job that the ruleset
  requires fails if any shard did; a PR waits for it. Survivors are in
  the `mutants-diff-<k>` artifacts (`missed.txt`). Every night at 02:00 UTC,
  if main changed, and on demand, the whole workspace runs in 20 shards
  (`full k/20`). That run blocks nothing; any survivor fails its shard and
  is listed in the run's summary.
- Before the day's first piece of work, look at the last night's run
  (`gh run list --workflow=mutants.yml --event schedule --limit 1`). If it
  found survivors, fix those first.
- Every PR is opened with auto-merge (`gh pr merge --auto --merge`); it
  lands once every required check, mutants included, is green.
