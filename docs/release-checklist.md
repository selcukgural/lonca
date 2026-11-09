# Release checklist

## Before tagging

1. `rust-toolchain.toml`: is a newer stable out? Raise it in a pull request of
   its own, with the clippy fixes it needs, before the release.
2. Run `ci.yml`, `mutants.yml` and `fuzz.yml` on main (`gh workflow run
   ci.yml --ref main`, `gh workflow run mutants.yml --ref main`,
   `gh workflow run fuzz.yml --ref main`); all green. A fuzz failure's
   input is encrypted (docs/fuzzing.md): fix it before the release.
3. Try the four builds: `gh workflow run release.yml --ref main` (builds
   only, drafts nothing).
4. Review `docs/security/owasp.md`: every row still true, every gap still has
   an open issue.
5. MSRV: `cargo +<rust-version> check --workspace --all-targets --locked`
   with the workspace's `rust-version`; raise it if a dependency asks more.

## Releasing

1. In a pull request: the workspace `version` in `Cargo.toml` and every
   internal dependency's `version = "…"` set to the new version
   (`cargo build` updates `Cargo.lock`), and `## Unreleased` in
   `docs/release-notes.md` renamed `## X.Y.Z (YYYY-MM-DD)`, with a new empty
   `## Unreleased` above it. Merge it.
2. Tag main and push the tag: `git tag -a vX.Y.Z -m "Lonca X.Y.Z"`, `git
   push origin vX.Y.Z`. `release.yml` drafts the release; `ci.yml` and
   `mutants.yml` run on the tag.
3. Both green, and the draft has four archives, `SHA256SUMS` and
   `lonca-sbom.cdx.tar.gz`: check one archive with `gh attestation verify
   lonca-aarch64-apple-darwin.tar.gz --repo selcukgural/lonca`.
4. crates.io. A crate that is not on crates.io yet is published by hand
   from the tag, by its owner, in dependency order:
   `git checkout vX.Y.Z && cargo publish --workspace --exclude lonca-mutants
   --locked`. Then on crates.io, for each new crate: Settings → Trusted
   Publishing → GitHub, `selcukgural/lonca`, workflow `registries.yml`,
   environment `release`. When every crate has it, set the repository
   variable `PUBLISH_CRATES` to `true` (`gh variable set PUBLISH_CRATES
   --body true`); from then on step 5 publishes them.
5. Publish the draft (`gh release edit vX.Y.Z --draft=false`).
   `registries.yml` publishes the crates (when `PUBLISH_CRATES` is on).
6. Homebrew: `gh workflow run update.yml --repo selcukgural/homebrew-lonca`
   (it also runs every day). Then, on a machine that has the tap,
   `brew update && brew upgrade selcukgural/lonca/lonca`, and
   `lonca --version` says X.Y.Z. `brew update` is needed: brew refreshes a
   tap's clone by itself only about once a day, and until then `brew info`
   still shows the old version. On a machine without the tap,
   `brew tap selcukgural/lonca` and `brew install lonca`.
7. `curl -fsSL https://selcukgural.github.io/lonca/install.sh | sh` installs
   the new version on a clean machine or account.

What CI can not check, because it needs model access, follows.

## A live run per harness

For Claude Code, Codex and any other built-in profile, with a real daemon:

1. `lonca session start --repo demo --agent <a> --paths 'src/**' --workspace
   <dir> --harness <name> --json`.
2. Start the harness in the workspace with what `setup` reports. Give it a
   small task in a prompt that does not name Lonca.
3. It must lease, propose, and reach `integrated` after approval. `lonca diff`
   in the workspace must not list the generated files.
4. Run two harnesses on one file, on different symbols: both integrate.
5. Have it stop early (a prompt that asks only for the edit, or a small local
   model): the stop event must send it back, and the run must reach
   `propose`. `lonca status` must show no `unproposed work` for it.

A harness whose profile has moved on gets a new fixture in
`crates/lonca-policy/tests/harness-setup/`. Write down in the release notes a
harness that could not be run.
