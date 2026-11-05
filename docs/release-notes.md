# Release notes

## Unreleased

### A critical path can wait for a person instead of being refused (#103)

An unobserved or tainted session was denied any change to `[paths] critical`,
with no way to ask anyone, so a cooperative worker could not add a dependency.
`[observation] unobserved_critical` and `[taint] critical` take `deny` (the
default) or `escalate`, separately, through a signed policy update. A policy
that uses them can not be read by an older release.

### An agent that stops with unproposed work is told so (#121)

An agent could edit, say "done" and stop, with the work left in its workspace.
Now a harness's stop event sends it back with what is unproposed and what to
do next, up to `[sessions] stop_rounds` times (3). After that `status` lists
the session under `unproposed work`, so a runner can tell "stopped" from
"done". `lonca session end` records the same for a harness with no stop event.
Claude Code, Codex, Gemini CLI and OpenCode have it, through `lonca harness
setup`; for your own profile, `events.stop` and `stop_deny`.

Log format 11: this release can read older logs, older releases refuse a log
it has written to.

### OpenCode, and fixing a harness before Lonca does

OpenCode joins the built-in profiles, tested with 2.2. It has no command hooks,
so setup writes a plugin that calls `lonca hook`. `lonca harness show <name>`
prints a built-in profile as a table for `lonca.toml`, where it replaces the
built-in one when a harness changes before Lonca has.

### Rules and setup for every harness (#110)

`lonca harness setup <name>` and `session start --harness <name>` give a
harness the rules, the MCP server and the hooks, from its profile; `--print`
writes nothing and shows the flags. `lonca rules` prints the rules, and MCP
`instructions` now carry all of them. MCP tools have annotations. A tool that
changes something refuses an argument it does not take, where before it ignored
it; a tool that only reads runs and warns. A denied `propose` says what was
claimed and what Lonca computed.

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
