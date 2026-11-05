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

A harness whose profile has moved on gets a new fixture in
`crates/lonca-policy/tests/harness-setup/`. Write down in the release notes a
harness that could not be run.
