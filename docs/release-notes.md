# Release notes

## Unreleased

### Existing repositories: new critical paths (#55)

The default `paths.critical` now covers agent instruction and tool
configuration files: `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.mcp.json`,
`.claude/**`, `.cursor/**`, `.codex/**`, `.cargo/config.toml`, `.envrc`,
`.vscode/**`, `.devcontainer/**`, `Dockerfile`, `.imece/**` and more; the list
is in `crates/lonca-policy/src/config.rs`.

This applies to new repositories. An existing repository keeps the
`lonca.toml` on its `refs/lonca/policy`, which changes only through a signed
`policy.update`, so **until you update it, agents can still change these files
without a human**. The same goes for a `lonca.toml` that does not set
`critical`. To adopt the list, merge it into your `lonca.toml` and run:

```sh
lonca policy show --repo NAME        # the current lonca.toml and policy.cedar
lonca policy set --repo NAME --config lonca.toml --policy policy.cedar
```

The reasons are in `docs/decisions.md`, "Critical paths: what instructs an
agent".
