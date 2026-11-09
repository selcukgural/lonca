# Fuzzing

Lonca reads bytes from parties it does not trust: an agent in its sandbox
writes requests to the daemon's socket, hooks report what tools were asked
to do, anyone who can write a store can hand the auditor a log, and every
file a proposal carries goes through the symbol engine and the merge. Tests
check the inputs someone thought of; a fuzzer looks for the ones nobody did.
[libFuzzer](https://llvm.org/docs/LibFuzzer.html), through
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), mutates saved inputs,
keeps those that reach new code, and stops at the first panic, hang or
runaway allocation.

## Targets

Each target is a function of bytes in `crates/lonca-fuzz` that panics when
what it checks does not hold.

| Target | Input | Holds |
|---|---|---|
| `entry` | one stored log entry (`op.json`) | what decodes comes back unchanged from its canonical form, which is a fixed point (two readers can not hash one entry two ways) |
| `replay` | log entries, one JSON line each, chained and signed by the target | the auditor reports on any log, deciding every entry again and recomputing facts and merges, and finds the same twice |
| `request` | up to 16 daemon request lines, on a fresh copy of a repository that has seen work | every line gets an answer with its id; afterwards the log audits clean (deep, every ref) and the daemon opens again |
| `hook` | a built-in harness and a hook event | every event gets a verdict a harness reads; the bytes also read as that harness's locked settings |
| `parse` | a file kind (each language of `languages.toml`, the section formats, plain text), an engine version, two versions of a file | symbols stand inside the file on character boundaries, sections add up to the file, facts come out |
| `merge` | file kind, engine, base, ours and theirs | the same answer twice; a conflict names something; under the current engine, sides that parse never merge into a file that does not |
| `policy` | `lonca.toml` and `policy.cedar` | what loads loads the same again; `lonca policy check` (every entry decided again, lockouts) works on it |

In `request`, `$HUMAN`, `$AGENT`, `$AGENT2`, `$WS` and `$TRUNK` stand for
the template's tokens, the agents' workspace and trunk, so the fuzzer gets
past authentication. It can not sign a human operation, so nothing it sends
pushes, fetches or imports; remotes on disk are refused anyway.

Where an input holds several texts they are cut at NUL bytes; a first byte
that chooses (a file kind, a harness) wraps around the list.

## Running it

```sh
cargo install --locked cargo-fuzz@0.13.2
cd fuzz
cargo fuzz run -s none merge corpus/merge seeds/merge -- -max_total_time=600
```

`-s none` builds without a sanitizer, with the compiler of
`rust-toolchain.toml`: only AddressSanitizer needs a nightly, and it
instruments Rust code, which denies `unsafe` here (the tree-sitter grammars
are C, built without it either way). Panics, overflow checks, hangs and
memory blowups are found without it. `-max_len=65536 -timeout=30
-rss_limit_mb=2048` are what CI uses.

A failure writes the input to `fuzz/artifacts/<target>/`. To see it fail
again: `cargo fuzz run -s none <target> fuzz/artifacts/<target>/<file>`.

## Every crash becomes a test

`fuzz/seeds/<target>/` are the starting inputs, written by
`cargo test -p lonca-fuzz --test inputs -- --ignored write_seeds` from the
template repository, the symbol engine's corpus and the shipped policies.
When a crash is fixed, its input goes to `fuzz/regressions/<target>/`.
`cargo test --workspace` runs every seed and every regression through its
target (`crates/lonca-fuzz/tests/inputs.rs`), on stable and with no fuzzer.

Keep a crash out of the repository, issues and pull request text until it
is fixed: the input is the exploit.

## CI

`.github/workflows/fuzz.yml` runs every target every night on main (30
minutes each) and on demand (10 minutes each, or
`gh workflow run fuzz.yml --ref main -f seconds=N`), which the release
checklist does before tagging. Pull requests and tags do not run it. Each
target keeps its corpus in the Actions cache, which a release run must not
restore, so a tag does not run it.

The repository is public, so the log says only which target found what
(`crash`, `timeout`, `oom`). The input and the fuzzer's output are uploaded
as `fuzz-<target>`, encrypted with [age](https://age-encryption.org) to the
key in `fuzz/crash-recipient.txt`. With the private key:

```sh
gh run download <run> -n fuzz-<target>
age -d -i ~/.config/lonca/fuzz-crashes.age-key fuzz-<target>.tar.gz.age | tar xz
```

## Adding a target

A module in `crates/lonca-fuzz/src` with `pub fn check(data: &[u8])`, a line
in `TARGETS`, a `[[bin]]` in `fuzz/Cargo.toml` with its two-line file in
`fuzz/fuzz_targets/`, seeds in `write_seeds`, and the target in the matrix
of `fuzz.yml`. `every_target_has_a_binary` checks the first three agree.
