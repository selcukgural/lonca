# Release checklist

What CI can not check, because it needs model access.

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
