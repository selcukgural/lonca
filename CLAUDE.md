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
- `lonca-client` is what harnesses depend on: protocol types, socket
  client, daemon checks, session file. It must not pull in the store or
  the policy (`cargo tree -p lonca-client -e normal` has no gix, no
  cedar); `lonca-core` builds without its store
  (`cargo clippy -p lonca-core -p lonca-client --no-default-features`).
  A protocol number change is a major version of it.
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
- The gated files (`.cargo/mutants-gated.txt`: `decide.rs`, `chain.rs`,
  `state.rs`, `human.rs`, `oplog.rs`, `canonical.rs`, `changeid.rs`,
  `keys.rs`, `paths.rs`, the auditor, the merge) may have no missed and no
  timed-out mutant. A survivor there is fixed with a test, or listed in
  `exclude_re` with a written reason why it is equivalent and added to
  `.cargo/mutants-gated-exclusions.txt`
  (`.github/scripts/mutants-gate.sh exclusions --write`; plain `exclusions`
  checks, in seconds). A new operation type (`ops.rs`, `decide.rs`,
  `state.rs`, the auditor) arrives with tests that kill its mutants.
- `exclude_re` and `--re` do not filter "delete field … from struct"
  mutants (cargo-mutants 27.1.0); use file globs or a test.
- Tests must stay hermetic: own temp dir, `127.0.0.1:0` ports, short socket
  paths, no writes to `$HOME`. Parallel jobs (`-j`) run copies at once.
- CI (`.github/workflows/mutants.yml`) runs only on demand and blocks
  nothing: no release, PR or merge waits for it (decided 2026-11-09,
  docs/decisions.md). It mutates only the gated files, only what changed in
  them since the last `v*` tag, each mutant against the whole workspace
  (minutes, not hours). Run it after changing a gated file:
  `gh workflow run mutants.yml --ref main` (`-f base=<tag>` for another
  base). A survivor or a gated timeout makes the run red; `exclusions`
  fails on an unlisted exclusion in a gated file. Elsewhere, run
  cargo-mutants locally on what you changed when it is worth it.

## Fuzzing

Eight cargo-fuzz targets (`entry`, `replay`, `request`, `hook`, `parse`,
`merge`, `policy`, `signature`); what each holds and how to run it: `docs/fuzzing.md`.

```sh
cargo install --locked cargo-fuzz@0.13.2
cd fuzz && cargo fuzz run -s none <target> corpus/<target> seeds/<target> -- -max_total_time=300
```

- The checks live in `crates/lonca-fuzz`; `fuzz/` (own workspace and lock)
  only wraps them. `-s none` on the pinned stable: no nightly.
- A fixed crash's input goes to `fuzz/regressions/<target>/`; `cargo test`
  runs every seed and regression. An unfixed one stays out of the repo, PRs
  and issues. CI (`fuzz.yml`: nightly, on demand and on a `v*` tag; not on PRs)
  uploads what it finds encrypted to `fuzz/crash-recipient.txt`; the key is
  `~/.config/lonca/fuzz-crashes.age-key`.
- A new target: a module with `check(&[u8])`, `TARGETS`, a `[[bin]]` and its
  file in `fuzz/`, seeds in `write_seeds`, the list in `fuzz.yml`'s `plan` job.
  One target on demand: `gh workflow run fuzz.yml --ref main -f targets=parse`.

## CI

The tests (`ci.yml`: `test (ubuntu-latest)`, `test (macos-latest)`,
`sandbox`) run on every pull request, every merge to main, a pushed `v*`
tag, and on demand (`gh workflow run ci.yml --ref main`). Only the mutants
run on demand alone (see "Mutation testing"). The main ruleset requires a
pull request (no direct push) and those three jobs as status checks. `cargo-deny`, CodeQL and zizmor (workflow changes)
run on pull requests; they block nothing. The toolchain is pinned in
`rust-toolchain.toml`; Actions are GitHub's own plus five named ones
(docs/decisions.md, "CI and the repository's own settings").
A `v*` tag also runs `release.yml` (binaries, SHA256SUMS, SBOM,
attestations, a *draft* release) and `fuzz.yml`, green before the draft is
published; publishing the draft runs
`registries.yml` (crates.io). Steps: `docs/release-checklist.md`. The CLI's
package is `lonca` (`-p lonca`, directory `crates/lonca-cli`); every crate
shares the workspace version.
A PR is opened with `gh pr merge <n> --merge --auto`: it merges itself
once the three jobs are green, and stays open (visible) until then.
