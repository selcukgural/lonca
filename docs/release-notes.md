# Release notes

## Unreleased

### Shared leases

A new lease kind, `shared`: several agents can hold one symbol at once, where a signed
policy has `[leases] shared = true`, which needs `verification.required = true` and a `build`
or `test` command. `edit` and `rename` stay exclusive and conflict with it. It covers a body,
not a signature. When two holders change one function, the merge (symbol engine 14) joins
their lines; lines both changed are `conflicted`, naming the function. Log format 21. See
`docs/guide/verification.md`, "Shared leases".

### A quota on verification

`[quota] session_seconds` and `day_seconds` cap the time verification may take for a session
(with the sessions made from it or continuing it) and for the repository in a UTC day. Past
either, a proposal is denied with `verification_quota:session` or `:day`, and what the session
queued before is rejected without a run. Both are 0, off, by default. An agent's
`change.withdraw` of a change whose checks are running is refused with `verifying`. `duration_ms` in the
evidence now covers every attempt of a retried check. `status` shows `verification_ms` per
session and `verification_day_ms`. See `docs/guide/verification.md`, "Quota".

### Nothing of a verification outlives it

A build or test command now runs as a session whose process group is killed when it ends,
however it ends, so in a sandbox a test can no longer leave a server running, and a background
process that keeps the output open no longer holds the queue. A check out of time is an error
with evidence and the next change goes on. The log keeps the last 64 KiB of stdout and stderr as
they were written. The program a command runs directly can not make a process group of its own.

Each process of a command now has limits, **in existing repositories too, since a `lonca.toml`
without the keys takes the defaults**: `limit_processes` 16384 (Linux), `limit_file_bytes` 8 GiB,
`limit_open_files` 4096. `limit_cpu_seconds` and `limit_address_bytes` (Linux) are off unless set.
`path` sets the commands' `PATH`. See `docs/guide/verification.md`, "Limits".

### Limits on the socket

One client can no longer tie the daemon up. Connections are capped (the longest-quiet one makes
room), a quiet connection closes after 15 minutes, and a request line has 60 seconds to arrive. A
request line is at most 64 KiB, or 96 MiB for the methods that carry files, and a long line must
name `method` and `token` before `params`. A session and those made from it get `[sessions]
ops_per_minute`, 600 by default; past it requests are `rate_limited` and the log does not grow.
`queue.run` now only wakes the worker, `log` answers at most 1 000 entries, and `ping` counts
what was refused. See `docs/protocol.md`.

### A level reads the proxy's port and every hook

A harness table can now say `is = "proxy_port"`: the value must be the port the daemon's
own proxy listens on, and with no proxy running the check does not hold. The built-in
Claude Code table uses it for `httpProxyPort`, so the managed settings and `--proxy` must
agree; the hardened installers already write the same port to both. Every Lonca hook in
every list must now have its program in root-owned directories. `ping` returns `proxy`.

### A session names its harness (log format 20)

`session start --harness <name>` now puts the name in what you sign, and an observation
level is read only for that harness. A session started without it is `unobserved` on any
machine, so a hardened setup must add the flag; `--no-setup` names the harness and writes
nothing in the workspace. Once set, a level can not rise for the rest of the session.
`status` lists each session's harness.

### Batches in the merge queue (log format 17)

`[queue] batch_size` in a signed policy, default 1, verifies the changes at the head of the queue
as one and bisects a failure: `change.integrate_batch` integrates them with one entry, and trunk
moves straight to the verified tip. A tree that passed is not verified again while the daemon runs.

### Seven more languages (symbol engine 10)

Java, Kotlin, C, C++, Ruby, PHP and Swift have symbols: leases, merges and facts by method, and
field where the language has them. What a language means is now a table,
`crates/lonca-symbols/src/languages.toml`. A file one of these grammars can not read gets what a
file with no grammar gets: a line merge, listed under `unparsed_files`, and no syntax failure.
A proposal that leaves a file unreadable that read before, or adds one, escalates (`unread_files`,
log format 16): facts can not see into it after that.

### Files no parser reads can be shared (symbol engine 8, log format 15)

With `[leases] unparsed_files = "optimistic"` in a signed policy, an edit of a text file
with no grammar and no sections (Java, Kotlin, C, Ruby, shell, ...) needs no lease: the
line merge at integration decides, and a real overlap is `conflicted`. The default stays
`"file"`, one `<file>` lease and one agent at a time. `status` shows the setting, and
`preview` and `lease_needed` list such files under `no_lease`.

Only an edit of lines goes without a lease: a change of mode or of a link, text with a NUL and a
change that takes away more than half of a file keep the file's lease (symbol engine 9). Lines
now merge by their own rules, and a change among equal lines is a conflict rather than a guess.
`lonca status` and `lonca lease needed` say what the setting does.

After a conflict `lonca sync` brings in the rest of trunk and leaves both sides in the file
between `<<<<<<< local` and `>>>>>>> trunk`, a symbol whole or by lines where there is no symbol.
`propose` refuses while any marker stands in a changed file, and a later sync reports the conflict
again. A conflicting symbol used to keep the local text with nothing to show what trunk did to it.

### Renames are tracked (symbol engine 7, log format 14)

Facts now have `renames: [[old, new]]`: a deleted and an added symbol in one list whose
code is the same with the name left out, or at least 80% alike. A `rename` lease on the
old name is all such a change needs. Once it lands, a lease on the old name and one on the
new name conflict, so a session on an older base and one on the trunk can not hold one
symbol under two names, also after an overload's parameters changed. A proposal from an
older base is checked against leases by either name. The merge keeps a renamed symbol in
its place. `deletes` and `adds` stay, so claims do not change.

### Overloads keep their identity (symbol engine 6, log format 13)

Symbols that share a name are now told apart by what they take, not by their place
in the file: `Client.Charge(int,int)`, `P.x[setter]`, `V.v[get]`,
`impl:S.From(u8)`, instead of `Charge~2`. An overload added above another renames
nothing, so nobody is told to lease a symbol they did not touch. A symbol alone with
its name has no key. Exact duplicates such as Go's `init()` keep `~2`.

`path#Name` now stands for every symbol of that name, in leases and scopes: a lease
on `Client.Charge` conflicts with one on `Client.Charge(int)`, so two sessions can
not hold one overload under two names. A `;` behind a TypeScript class member belongs
to the member, so adding a field is an add, not an edit of `<def>`.

**For clients:** symbol ids can now hold `(`, `)`, `[`, `]`, `,` and spaces: quote them
in a shell, and take them from `symbols` or `preview` instead of building them.
`--edits` and the like split on commas outside brackets only. Entries already in a
log keep their recorded engine and meaning.

### More of a file can be leased on its own (symbol engine 5)

Each spec in a Go `const (...)`, `var (...)` or `type (...)` group is now a symbol,
and so is each declarator of a C# `int a, b;`, what stands in a Rust `extern` block,
a Rust macro call at item level (`m!`), JavaScript `exports.x =`,
`module.exports.x =` and the methods of `module.exports = { … }`, and functions in a
Python top-level `if` or `try` that holds only definitions. Two agents can now work
in one such group at once. A TypeScript method's decorators belong to the method.
The members of a second `partial class C` in a file are `C.x`, not `C~2.x`.

A comment with a blank line under it no longer belongs to the next symbol: it is code
of the file or the type, so editing a licence or a section header needs `<module>`
(or `Type.<def>`), not a lease on an unrelated symbol. Adding a method to a Python
class with one method is now an add, not an edit of the class. New symbols stay in
the group, block or namespace they were written in when merged. Entries already in
a log keep their recorded engine.

### A wide change gets its turn, and every lease says why (log format 12)

A waiting `lease.interest` now goes first: for `leases.interest_block_ms`
(default 10 minutes) other sessions can not take a new lease that conflicts with
it, so small leases do not keep a change to a whole type or file waiting while
what stands in its way finishes. The denial is `lease_wanted:<session>`, and it
says who waits, and why; `lease_needed` reports it too. The time counts per held
set, however many sessions wait. After it the interest stays in line without
stopping anyone.

`lease.acquire` and `lease.interest` now need an `intent`; a blank one is denied
`intent_required`, and `lonca lease acquire` and `lonca lease interest` need
`--intent`. **A client of its own that sent a blank intent has to send one now.**
For a wide change, a rename or a delete, the rules ask why it needs that much and
for the issue number. The rules now also say to read `status` before leasing.

### Agents can reach each other

A message sent with `negotiate` now reaches the agent it is for. It arrives with
the answer of any `lonca mcp` tool, and on Claude Code, Codex and Gemini CLI after
any tool call, while that agent is editing. `events` carries what the message
says, which it did not before. A lease denial says in a sentence who is on it and
to settle it between you (`advice`). `events` from `next` now finds the approval of
a request older than `from`. A runner of its own can take the same news from the
new `inbox` method. A profile of your own in `[harnesses.<name>]` needs
`tool_context` to get the after-tool way in.

### Code that changes places among symbols is a change (symbol engine 4)

A statement moved past a function or a method now shows in the facts, as an
edit of `<module>` or of `Type.<def>`, and takes that lease. The merge treats it
like a moved symbol: it goes to the line merge, which brings it in or reports a
conflict. Copy claims from `preview` as before.

### A type's fields and header can be leased apart from its methods (#41)

`path#Type.<def>` is a type's own text: a struct's fields, a class header, its
decorators and class-level statements, and for Rust every `impl` header. One
agent can hold it while others edit methods and add new ones, in Rust, Go,
Python, TypeScript and C#, and all of them integrate, in whatever order they
reach the queue. Facts now report `Type.<def>` where they said `Type`, and an
`impl` that is taken out as an edit of `Type` plus deletes of its members
(symbol engine 3), so copy claims from `preview` as before. A lease on `Type`
still covers all of it, and old logs audit as they did. `symbols` shows the id
as `def`. A lease on `impl:Type` no longer covers what facts report for that
block: lease `Type.<def>`.

### A workspace holds regular files

A symlink at a tracked path, or on the way to one, now stops `lonca diff`,
`propose` and `sync` with an error naming it. Replace it with a file, or restore
the directory, and run it again. Paths in `.lonca/workspace.json` must stay
inside the workspace.

### An agent's workspace is a git repository (#111)

`session start` now gives the workspace a `.git` with one commit of its base, so
`git status` and `git diff` work and `codex exec` no longer needs
`--skip-git-repo-check`. `lonca sync` moves it with the base. A commit there
stays there: only `propose` delivers, and the rules say so. Lonca writes `.git`
itself and never runs `git` on it, since the agent can change its config.
`--no-git` keeps a plain directory; a person's workspace stays plain. `lonca
fetch` and `propose --commit` now refuse to run inside a workspace.

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
