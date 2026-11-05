# Release notes

## Unreleased

### Hooks for any harness (#109)

`lonca hook --harness <name>` reads a harness's events and tools from a
profile. Claude Code, Codex and Gemini CLI come built in; `[harnesses.<name>]`
in `lonca.toml` adds another or replaces one, with no new Lonca
(`docs/guide/runners.md`, "Any other harness"). A hook event the harness does
not have now exits 2. Tools Lonca does not know taint the session by default:
if a runner uses one that reads nothing from outside, list it in
`[taint] safe_tools` or set `unknown_tools = false` with a signed policy
update. `.gemini/**` joins the default `paths.critical`; existing repositories
keep their policy until they update it.

### Symbol engine 2: code is compared exactly

Changes that engine 1 did not see outside symbols, inside a class's own text
or in the order of symbols and imports are now facts: they need a lease, a
claim and a merge like any other edit. A runner that claimed nothing for such
a file gets `claim_mismatch`; `facts.preview`, `lease_needed` and
`propose --accept-facts` say what to claim. Moving a function reports the
symbols that changed place. Old log entries are recomputed with the engine
they recorded.

### Hardened installs: run the installer again (#52)

Clients now check the daemon's uid against a root-owned `daemon.toml`. A
hardened install from before this change has no such file, so its clients
expect their own uid and refuse the daemon until the installer has run again.

### Markdown, TOML, JSON and YAML have sections (#46)

From symbol engine 1 a change to one of these files is a change to its
sections (`README.md#Install.Linux`, `Cargo.toml#dependencies.serde`), not to
`path#<file>`. A runner that claims `path#<file>` for such a file gets
`claim_mismatch`; `facts.preview`, `lease_needed` and `propose --accept-facts`
say what to claim and lease. A lease on `path#<file>` still covers every
section. Old log entries are recomputed with the engine they recorded.

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
