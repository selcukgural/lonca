# Release notes

## Unreleased

### A check's log does not hold a passed value

The output of a build or test command is kept as the check's log, which the
proposing agent reads back and `lonca push` carries. A value passed to the
commands with `env_passthrough` is now written `***` wherever it turns up
in a log (directories such as `HOME` stay readable). This catches a tool
that prints its environment, not a test written to tell: the guide now says
plainly that what the verification sandbox can read, the proposing agent
can read, and its Node starter no longer opens `~/.npmrc`. If your
`lonca.toml` passes a token or opens a credentials file for the checks,
take it out and install dependencies before the checks run.

### A session's directory is in the log

`lonca session start` now records the workspace directory in the signed
`session.start` entry (log format 30), and Lonca asks the log, not the
directory's own `.lonca/workspace.json`, which session works where:

- `lonca hook` no longer stands aside when that file is missing, unreadable
  or names no session. It asks the daemon; in a live session's directory,
  or under the harness session a live session is bound to, a tool call is
  blocked until the workspace reads as that session's again.
- `lonca session start --continue DIR` continues the session that was
  started in `DIR`. Two sessions can not be started in one directory, or in
  directories inside each other, while the first is live
  (`workspace_in_use`).
- A continued session starts at `unobserved` until its own harness has
  reported; it used to keep its predecessor's level until then.
- A human's `sync`, `diff` or `propose` in a directory the log gives to an
  agent's session is refused.

**Upgrading.** A session started with 0.2.3 or earlier has no directory in
the log and can not be continued (`continue_other_workspace`): propose or
copy what its workspace holds, and start a new session in a new directory.
The daemon and `lonca hook` are upgraded together, as always; the new
socket method is `session.where` (public).

### The reviewer's diff takes file names literally

A file may have a name that git reads as a pattern, such as `src/*` or
`:!src/billing.rs`. `lonca diff <change>` (the socket's `change.diff`) now
shows such a file as itself, and every other changed file beside it: the
daemon's git takes each path as the file it names
(`GIT_LITERAL_PATHSPECS=1`). What is integrated was never affected, only
the text shown for review.

### A human signature is for one log

A human signature covered the repository's name, the operation, a nonce and
a time, and an `approve` named its target by number. From log format 33 it
also names the last entry of the log its signer saw (`at`, from the new
public socket method `log.head`), and the daemon refuses one that names no
entry (`unanchored_human_signature`), an entry the log does not have
(`human_signature_of_another_log`) or an approval of something that came
after it (`signed_before_its_target`). An approval can no longer be carried
to another proposal in a log written again with the daemon's key, or to
another repository of the same name.

**Upgrading.** `lonca` and the daemon are upgraded together, as always: an
older `lonca` signs without `at` and is refused. A program of your own that
signs human operations must ask `log.head` and sign the
`lonca-human-intent-v2` bytes (docs/protocol.md, "human signature").

### A critical path is critical in any case

macOS opens `Build.rs` as `build.rs`. `[paths] critical`, `[paths]
untrusted` and `checks_by_path` matched a path by its spelling, so a change
to `crates/x/Build.rs` or `.Cargo/config.toml` was not critical, and a read
of `Vendor/lib.c` did not taint. From log format 32 these lists read a path
with its case folded, on every platform. A policy rule that forbids by name
should read the new `context.folded` with a lower-case pattern
(`context.folded like "*cargo.lock"`): `context.path` is the path as
written, as before. Look at your own `policy.cedar` for `forbid` rules on
`context.path`; the shipped ones are changed in new repositories only.

### A child session has its parent's agent name

The policy knows an agent by its name (`Lonca::Agent::"docs-bot"`), and a
reviewer reads that name in `pending`. A child session made with
`cap.attenuate` is the same agent with a narrower scope, and from log
format 31 it has the same name: an `agent` other than the parent's is
refused (`child_agent_name:<name>`), so a rule on a name holds for every
session made from that agent's. Nothing Lonca ships calls `cap.attenuate`
with another name; a runner that does must send the parent's.

### What an agent wrote is shown, not obeyed, by your terminal

`lonca` and `lonca-audit` now write out control characters in everything
they print for a person: an escape is shown as `\u{1b}`, a carriage return
as `\r`, a text direction override as `\u{202e}`. An intent, a path, a
line of a diff or the text of a denial can no longer move the cursor, clear
a line or hide text on the reviewer's screen. Newlines and tabs are kept;
`--json` output is unchanged. A CRLF file's lines end in a visible `\r` in
`lonca diff`.

### A connection belongs to the session that made it

The proxy used to put a connection on the record of the session in whose
workspace the connecting command stood. It now goes by the processes the
command descends from: the harness that ran the session's hook, or `lonca
run`.

- A command that enters another session's directory before it connects is
  still its own session's: that one is tainted and pays the connection, not
  the other.
- A command that outlives the process that started it (`nohup … &` and its
  parent gone) is charged to every session the proxy serves, its own among
  them. Before, that happened only when it also stood outside every
  workspace.
- A session made from another with `cap.attenuate` answers together with
  the one it came from.
- After the daemon restarts, every session answers for every connection
  until its harness starts again (the hook binds at session start). `lsof`
  and `ps` are needed to tell sessions apart, as `lsof` was.
- The proxy waits 10 seconds for a request and closes a tunnel through
  which nothing has moved for 10 minutes.

For `lonca-net` users: `Limits`, `spawn_with` and `serve_with` are new,
`Outcome::Idle` is a new variant, and `peer_cwd` is replaced by `peer_pid`.

### A connection through the proxy is for the host it was asked for

An address often serves many names. The proxy now holds a connection to
the one it let through:

- A TLS client that asks the proxy for one host and the server for another
  (a server name that is not the `CONNECT` host) has its tunnel closed
  before a byte of it reaches the host. To the command this is a
  connection dropped during the handshake. A tunnel asked for by address
  is not held to a name.
- A plain `http://` request whose `Host` header is not its URL's host and
  port is answered `400`. Each plain request now goes to the host on its
  own connection (`Connection: close`); requests for several hosts over
  one proxy connection used to reach the first one's host.
- Inside TLS nothing is read, as before: the `Host` header of an HTTPS
  request is the server's to check.

`lonca-net`: `Outcome::Misnamed` is new (an `Outcome` match needs an arm
for it), and the `hello` module reads a TLS client's server name.

### The security log keeps the latest of every kind

`security.log` rotates at 8 MiB and keeps two files. Events that any
caller can cause without end (a line that is no request, a bad token) used
to push everything older out of both, a freeze or a session's taint
included. The latest 256 events of each kind now stay through every
rotation, whatever comes after them; `security.log.1` begins with those
that would otherwise be gone. Nothing changes in the format of a line.

### A daemon that stops in the middle of a policy update does not freeze

The daemon appends an entry and then moves the ref it is about. Stopped
between the two by a crash or a power cut during `lonca policy set`, it
took its own half-done work for a write behind its back at the next start
and froze the repository (`refs/lonca/policy changed outside Lonca`); the
same for a `lonca init` cut short. Both are now finished quietly at the
start, as a trunk left one step back always was. A policy ref changed at
any other time is still put back, logged and frozen for.

### An isolated session's token reads nothing from outside its sandbox

A token of a `lonca run` session used outside the sandbox was refused
(`not_in_sandbox`) and the session tainted, but only for the methods an
agent alone may call. The reading methods (`status`, `log`, `tree`,
`blobs`, `change.get`, `change.diff`, `trunk.bundle`, `whoami`) went
through from anywhere. They are now held the same way. Nothing changes for
a command inside the sandbox, for a human session, or for a session that
is not isolated.

### The hook that is checked is the hook that runs

For the `hooks` and `hooks_sandbox` levels the daemon checks that the hook
program named in the administrator's settings is out of a user's reach.
Two commands passed that should not have:

- one that starts another program which then finds `lonca` itself
  (`/usr/bin/env lonca hook`, `/bin/sh -c …`), or carries shell syntax. A
  hook's command has to be `<path>/lonca` and plain words;
- a path whose link leads to a file in a directory anybody can write. A
  path is now checked as named and where its links lead.

Settings written by the hardened installers pass as before. If yours were
written by hand and the level drops to `unobserved`, `lonca doctor` says
which of the two it is.

### A logout that could not be saved is saved at the next try

When the daemon could not write its token file (a full disk), `lonca human
logout` reported the failure, and a second try reported success without
writing anything: the session came back after a daemon restart, until it
expired. A failed write is now made up at the next call, the worker's own
within two seconds included. A `lonca session rotate` whose write fails
leaves the old token working instead of locking the session out.

### One entry of the log has a size, and the proxy a rate

The log keeps every entry, so what goes into one is now bounded before it
is written:

- An operation whose JSON, with its human signature, is past 64 KiB is
  refused as `invalid` and not logged; the message names the operation and
  its size. In practice this is a very long intent or list: write a shorter
  one, or lease and propose in smaller parts.
- `lonca human recover` with a key that is not the repository's recovery
  key for that human is refused as `forbidden` and is in the security log
  (`lonca doctor` counts its events), no longer an entry of the operation
  log.
- Connections through the proxy are recorded at `sessions.ops_per_minute`
  for a session, counted apart from its own operations. Past that a
  connection is refused until the minute has room again.

### One value of the policy from the command line

```sh
lonca policy set --repo demo --value sessions.ops_per_minute=1200
```

sets that one value in the policy in force and leaves the rest of
`lonca.toml` as it is, comments too; `lonca policy check --value` shows
first what it would have decided differently. Any key of `lonca.toml`
works, more than one `--value` at a time, and `--config` and `--policy`
are now each optional (a file left out is the one in force).

`sessions.ops_per_minute` may be 6000 at most. A policy that sets more is
refused; if yours already has more, it counts as 6000.

### `tree` with contents is one page

For programs that speak the protocol: `tree` with `with_content: true`
answers `too_large` when the contents are past one page (three quarters
of the line limit, as for `blobs`), instead of reading the whole commit
first. Ask without contents and page them with `blobs`, as `lonca` does.

### The stores' disk keeps room for the log

- `lonca facts` (the socket's `facts.preview`) no longer leaves the files
  it was sent in the repository's store: they are written beside it and
  removed with the answer. They used to stay for good.
- While the disk of the daemon's home has less than 1 GiB free, the files
  of a proposal or a preview are not written (`change.propose`,
  `facts.preview`, `human.prepare_change`, `human.prepare_policy`): the
  answer is the new error `disk_space`, and nothing is logged. Leases,
  approvals, merges of what is already proposed, freezes and revocations
  go on; that is what the room is kept for. Free space on that disk to
  propose again. The number is not a policy key.

### A path is where its links lead

`lonca hook` now says where the files of a tool call really are before the
daemon places them inside or outside the workspace. Until now a path was
placed by its text, so a symbolic link in the workspace was not seen:

- A write through a link that leads out of the workspace (`h/.zshrc`, with
  `h` a link to your home directory) is denied, as any outside write, and
  the refusal names both paths. A read through one is recorded as the
  outside read it is, and taints the session as the policy says.
- A link to a workspace file is that file: a write through it is recorded
  under the file's own name, and `.lonca/` stays closed whatever names it.
- A path that does not resolve (a loop of links, a directory the hook can
  not look into) is outside.

The daemon and `lonca hook` are upgraded together: a 0.2.3 `lonca hook`
with this daemon has every file tool refused ("this hook program is older
than its daemon"). A program that calls `hook.input` itself answers the new
`"phase": "resolve"`; one that calls `hook.event` can send `real`
(`docs/protocol.md`; `lonca_client::real_path`). Shell commands are not
read for paths, as before.

### Symbol engine 20: a parse is held to what it reads

- A grammar's scanner can read to the end of the file for every token, and
  no parse action counts that: a Swift file of nothing but `/*` kept the
  daemon busy for 81 seconds at 200 KB. From engine 20 the bytes a grammar
  is handed are counted too (1 MiB and 64 times the file's length; code
  people write takes at most 27 times). A file past it goes by its lines, as
  one past the steps of engine 16 does.
- In a file with syntax its grammar does not read, a blank line or the end
  of a line that changed in the unread part is now a change of the file. It
  was no change at all, though the unread part may be a text of several
  lines.
- Ruby's and Swift's scanners gave a different tree by the machine Lonca was
  built for: a Ruby heredoc whose word has a letter such as `É`, `Ö` or `ç`
  ended only on Linux on ARM, and a Swift raw string of 128 or more `#` ended
  only there. Our copies read the same on every target now.

- What is a space or a letter to a grammar was asked of the C library, and
  the Linux archives (musl) answered from Unicode where macOS answers for
  ASCII: a TypeScript function behind a line ending in an ideographic space
  (U+3000) was a symbol on Linux and not on macOS. Lonca's Linux builds now
  bring ASCII's answers themselves, so a file has the same symbols
  everywhere.

Entries of older engines are recomputed as they were written, with two
exceptions, which `lonca-audit` would name: a Ruby or Swift file of the
third kind in a log written on x86-64 or macOS, and a file of the fourth
kind in a log written by a Linux archive. Both are read now as the other
builds always read them.

## 0.2.3 (2026-11-11)

### A runner can wait for news instead of polling

A runner that drives several agents can now wake an idle one as soon as
something happens to its session, with one open request and the human
session it started the agents with
([#262](https://github.com/selcukgural/lonca/issues/262)):

```sh
lonca events --watch --follow --json --repo demo
# {"session":"ses_…","kind":"lease_received","seq":41,"from":"ses_…"}
```

One line per event: a change integrated, conflicted or refused, an approval
or rejection, a message or a lease handed over, an interest now reserved. The
runner sees the kind, the session and the change, never what another agent
wrote, and watching marks nothing as read: the agent is still told through
its tools. The socket method is `events.watch`; `lonca-client` has
`Client::watch`. [Running agents](guide/runners.md#waking-an-idle-agent) has
the details.

### Evidence names the toolchain it ran with

A check's evidence carried a digest of its sandbox and command only, so a
pass under one compiler looked the same as a pass under another
([#263](https://github.com/selcukgural/lonca/issues/263)). `identify` in
`[verification]` lists commands whose output names the environment:

```toml
[verification]
identify = ["rustc --version", "cargo --version"]
```

They run once before the checks, in the same sandbox, and each check's
`env` becomes a digest of the sandbox, the command, the `PATH`, the
policy's fixed values, the names passed through (never their values) and
what the identify commands printed (the first 4 KiB of it). Their first
lines are in the evidence: `lonca change CHANGE --evidence` prints them,
`change.get` returns them as `environment`, and `lonca-audit verify` notes every check whose environment
changed since it last ran. A failing identify command does not fail a
check. No log format change; the first integration after the upgrade is
noted once, since its digest holds more.
[Verification](guide/verification.md#the-environment-the-evidence-names)
has examples for Rust, Node and an image digest.

### Keyed directories: two agents can not take one migration version

Flyway's `V12__add_users.sql`, Django's `0012_add_users.py` and the like get
their meaning from a key in their name, and Git saw two files with one key
as two unrelated paths ([#261](https://github.com/selcukgural/lonca/issues/261)).
Name such directories in `lonca.toml`:

```toml
[paths.keyed]
"db/migration" = '^V(\d+)__'
```

An agent reserves the key before adding the file, with an `insert` lease on
the directory (`lonca lease acquire 'db/migration#<dir>' --kind insert
--name next` takes the next free number and says which). A new file there
without its key reserved, with a key another file has, or with a name the
pattern does not read is refused, and two changes that would land one key
are `conflicted` at integration, naming it, whatever the checks run.
[Concepts](guide/concepts.md#keyed-directories) has the details. Log format
29; an older `lonca` refuses a log that has reached it.

### `lonca-audit` on Linux verifies again

On the Linux archives of 0.2.0 to 0.2.2, `lonca-audit verify` reported a
`FINDING ... replay gives Deny ["policy_error:... recursion limit reached"]`
for every decision in the log and failed, on logs that were fine. The
daemon's decisions were right; the auditor's replay of them was not: on the
static (musl) build, Cedar believed the main thread's stack nearly full and
failed every evaluation. Each policy evaluation now runs on a stack of its
own, so it gives the same outcome on every platform. Run `lonca-audit
verify` again with 0.2.3 on a log that failed. The macOS archives and
`cargo install` builds on glibc Linux were not affected.

### Acceptance tests gate every release

Every release is now checked, before its draft exists, by acceptance tests
run on the archives it ships: a daemon started from them in a fresh home,
then what the guides tell a user to do, from `lonca init --import` to
leases, proposals, approval, undo, push, backup and restore, the hooks and
the MCP server, and `lonca-audit` catching an edited log. The criteria are
in [docs/acceptance.md](https://github.com/selcukgural/lonca/blob/main/docs/acceptance.md);
every pull request runs them too.

### `lonca-audit --version`

`lonca-audit --version` (or `-V`) prints `lonca-audit X.Y.Z`, as `lonca
--version` does, so a script can check that the auditor it runs is the
release it installed.

### Symbol engine 19: four definitions get symbols of their own

Python's `type Pair[T] = ...`, a C++ `concept`, a type declared inside a C++
class or struct (`Task.promise_type`), and a Swift `macro` were read by
their grammar and still gave no symbol: a change to one counted as a change
to the code around it, and nobody could lease it by itself. From engine 19
each is a symbol. A change to what a type alias or a concept stands for, or
to the type that implements a macro, is a signature change and lists the
code that mentions it. Entries of older engines are recomputed as they were
written.

### A verification leaves the machine its share

A build or test command could fill the disk the stores are on, fork up to the account's limit on
macOS, and outlive a daemon that died. Now, **in existing repositories too, since a `lonca.toml`
without the key takes the default**:

- `keep_free_bytes` (1 GiB): a command is stopped once the disk of the daemon's stores has less
  free, looked at every 20 ms, and does not start below it; the check is an error with
  `error = disk_space`. Under bubblewrap the command's `/tmp` and `/dev/shm` are on that disk, no
  longer in memory, and the rest of `/dev` is read-only. A run's directory is removed whatever
  the command did to its permissions.
- `limit_processes` holds on macOS too, and on both systems the account keeps 256 processes of
  the most it may have, so a command that forks without end leaves room for the person at the
  machine and for the daemon.
- On Linux the command's processes are the first the kernel ends when memory runs out.
- A daemon that starts, and holds the lock on its home, ends what the verifications of an
  earlier one left running in their sandboxes, and removes their directories.

Memory as a whole is still not bounded, so a command can keep the machine busy until
`timeout_seconds`.

See `docs/guide/verification.md`, "Limits", and `docs/decisions.md`, "What a command may take of
the machine".

### Symbol engine 18: new syntax costs one definition, not the file

Leases per symbol are what lets several agents work on one file. Until now
one piece of syntax the grammar did not know took that away for the whole
file: it was leased whole and merged by its lines. From engine 18 a file
with a parse error keeps every definition the error is not in. A change
inside those needs their leases only, and its facts name them (edits, added
and deleted methods, signature changes, deleted tests). A change to the
unread part, to a definition it is in, or to code outside definitions is
still a change of the file and needs `path#<file>`.

`lonca symbols` marks what was not read, and the `symbols` tool has
`unread: true` on it. The file still merges by its lines. With
`[leases] unparsed_files = "optimistic"`, a change inside read symbols of
such a file now needs their leases. Entries of older engines are recomputed
as they were written.

[Languages](guide/languages.md) now starts with the list of what is leased
by symbol: fourteen languages, and sections of Markdown, TOML, JSON and
YAML. Another language, or a newer grammar, is added when somebody asks.

### Symbol engine 17: new syntax is not refused

A grammar is older than its language. Lonca's C# grammar, for one, does not
read C# 14's extension blocks, and until now a change with such code in a
Rust, Python, TypeScript, JavaScript, C# or Go file failed the syntax check
as if it were a mistake ([#246](https://github.com/selcukgural/lonca/issues/246)).
From engine 17 a parse error in any language means that the grammar could
not read the file, as it already did for Java, Kotlin, C, C++, Ruby, PHP and
Swift: the change is not refused, the file merges by its lines, and a
proposal that leaves a file unreadable, or adds one, waits for a person with
the reason `unread_file:<path>`.

What this costs: a real syntax error in those six languages is no longer
stopped by Lonca itself. Set `build` and `test` in `[verification]` so that
your compiler is the judge. Entries of older engines are recomputed as they
were written.

### Languages: what each grammar reads

A new page of the guide, [Languages](guide/languages.md), says for each
language which grammar this build has, which versions' syntax was tried and
what is known not to be read yet, and what a file with such syntax goes
through ([#247](https://github.com/selcukgural/lonca/issues/247)). The table
on it is written by a test from 210 small samples, so it can not drift from
the build: 29 of them are not read today, among them C# 14's extension
blocks, Java 25's module imports, Kotlin's guard conditions and C++23's
deducing `this`. None of this is refused (engine 17, above), and only the
definition with such syntax in it loses its symbol (engine 18, above).

### Ruby's and Swift's grammars: two scanner faults fixed in our own copies

Two grammar scanners could be made to misbehave by a file an agent
proposes, and both are fixed upstream but not released. tree-sitter-ruby
0.23.1 aborted the process on a heredoc word longer than 255 characters,
which took the daemon down. tree-sitter-swift 0.7.4 read past a string when
a file ended in `#if`, `#elseif`, `#else` or `#endif`; no build we tried
faulted on it, but a read past a buffer is not left in the daemon. Lonca
now builds both from copies with that one fault fixed and nothing else
(`lonca-tree-sitter-ruby`, `lonca-tree-sitter-swift`, two new crates), so
every file parses as before and no engine changes. When upstream releases,
Lonca goes back to the released grammar (docs/decisions.md).

### Presence on Linux: FIDO security keys

A human's key can now live on a FIDO security key, so a hardened repository
no longer needs `--without-presence` on Linux
([#17](https://github.com/selcukgural/lonca/issues/17)):

```sh
lonca human keygen ayse --security-key      # touch the key when it blinks
lonca human rotate --repo demo --security-key
```

The key signs through OpenSSH (`ssh-keygen`, 8.2 or later with FIDO
support); Lonca itself only verifies, and carries no USB or FIDO code.
Every signature needs a touch, and one the device made without a touch is
refused. `lonca doctor` has a `presence` line: what your key proves and what
the machine could use. Two new kinds of human key, `sk-p256` and
`sk-ed25519`, and log format 28; `human.enroll` now checks the form of a
key as a rotation does. Older logs replay as they were, and an older
`lonca` refuses a log that has reached format 28.

The verifier agrees with OpenSSH 10.5's own (`ssh-keygen -Y verify`) and the
command line is tested against a software stand-in for the device. Signing
with a physical key has not been exercised by the project yet: see
[Profiles](guide/profiles.md#presence) and the
[threat model](security/threat-model.md#humans-and-approvals) for what a
security key does and does not show.

### A recording of two agents on one file

The README, the home page and the [quick start](guide/quick-start.md) show a
terminal recording: two agents lease different methods of one file, a lease
that is held and a write outside a session's paths are refused, a human
approves, both changes merge and `lonca-audit` verifies the log. It is
recorded from the released binaries by
[docs/demo/demo.sh](https://github.com/selcukgural/lonca/blob/main/docs/demo/demo.sh),
which anyone can run: it uses a home of its own and nothing in it is canned.

### The site names the release, and a page for Claude Code

The site said nothing of which release it described, and the install guide's
examples still named 0.2.0. The version now comes from the workspace's
`Cargo.toml` when the site is built and shows in the navigation bar and on the
home page, and the examples name 0.2.2. A new page,
[Lonca with Claude Code](guide/claude-code.md), says what each hook event and
MCP tool does for a Claude Code session, how far each observation level goes,
and where the other harnesses stand. The home page and the README have
diagrams of the same.

### What the verifier's limits do not cover, said

[Verification](guide/verification.md#limits) and the limitations on
[What Lonca is](guide/index.md#limitations) now say what the per-process
limits leave open: a command's total disk in the scratch directory, its
memory as a whole and, on macOS, its number of processes. Bounds for these
are planned.

### A threat model

[Threat model](security/threat-model.md) gathers in one English page what was
spread over the design and the decisions: the assets, who Lonca defends
against, what each mode prevents and what it only detects, what the auditor
does not catch, the known limits and what is out of scope.

### Homebrew 7 asks to trust the tap

Homebrew 7 refuses a formula from a tap that is not its own until it is
trusted. The README, the [install guide](guide/install.md#homebrew) and the
site now put `brew trust --formula selcukgural/lonca/lonca` between
`brew tap` and `brew install`; an older Homebrew needs no such step.

### Live runs for this release

Claude Code 2.1 (haiku), as `docs/release-checklist.md` asks, on the
binaries of this release: a session leased, proposed and integrated after
approval, and `lonca diff` listed no generated file; two sessions at once on
one file, on different symbols, both integrated; one asked only for an edit
was sent back by the stop hook, proposed, and left no unproposed work. A
fourth, asked for a Flyway migration in a keyed `db/migration`, reserved
the next key (`V2`) before writing it and integrated it.
`lonca-audit verify` passed on the log. **Not run: Codex and OpenCode**, for
the reason given under 0.2.2; their harness profiles have not changed since
0.2.1.

## 0.2.2 (2026-11-09)

### `lonca doctor` reads like `flutter doctor`

The text form was one flat, colourless line per check. It now groups the
checks under headings (`[✓] Mode`, `[✗] Daemon`, `[!] Hooks`, `Tools`,
`Human`, `Repository <repo>`), each marked with its worst check, says what
to do under each problem, and ends with how many categories have issues.
Colour only on a terminal, never with `NO_COLOR` or `TERM=dumb`. `--json`
is unchanged; in text mode the summary line replaces `check(s) failed` on
stderr, and the exit code is still 1 (#227).

### `session start` into a full directory starts nothing

`lonca session start --workspace DIR` with a `DIR` that is not empty was
refused only after the daemon had started the session: the log had an
`allow`, and `status` listed an active session whose token nobody held
until its TTL ran out (#223). The directory is now checked first, and
anything that fails after the session started (making the workspace,
writing its token) ends that session again.

### Symbol engine 16: a parse within a budget

A tree-sitter grammar can take far more work and memory than a file is
long: the fuzzer found a short Kotlin file that took gigabytes, so a
proposal holding one could take the daemon down. From engine 16 a parse
stops after a budget of work that grows with the file's length (256 steps
and one per 4 bytes, at most 8192), counted in parse actions and not in
time, so the auditor gets the same answer. A file past it goes by its lines,
as one over 2 MiB does: code people write stays far below it. Entries of
older engines are recomputed as they were written.

### Fuzzing

The parsers and the merge are fuzzed (`docs/fuzzing.md`): stored log
entries, whole logs as the auditor reads them, daemon requests, hook
events, the symbol engine, the three-way merge, and repository
configuration and policy. Every saved input runs under `cargo test`. A git
id in a request or a log entry is now refused unless it is 40 lowercase
hex digits, as Lonca writes them. A C or C++ file with a broken scoped name
such as `a:::b` no longer makes the symbol engine panic: the request that
read it got no answer, and the connection was dropped. Such a name now has
one scope per `::`, read from the left.

### `lonca policy check`, and a guide to writing policies

`lonca policy check --policy policy.cedar` (or `--config`, or both) tries
a policy before `lonca policy set`: it decides every entry of the log again
with it and lists the decisions that would change, writing nothing. It also
warns when the new policy would deny an enrolled human a way back, such as
`policy.update`, `unfreeze` or `approve`. The new
[Writing policies](guide/policies.md) page lists what a Cedar rule sees
(principals, actions, every context key), what `@escalate` and
`@approvals` do, why an evaluation error denies, and examples.

### A lost Mac comes back with the recovery key

When the Mac is lost, the daemon's key and your Secure Enclave key go with
it. A repository restored onto a new daemon then accepted only
`daemon.recover`, signed with an enrolled human's key, so the recovery key
alone could not bring it back. Now `lonca human recover` does it: on a
restored repository it sends a `daemon.recover` signed with the recovery
key, which moves the repository onto the new daemon and installs your new
key in one entry (log format 27). Every session ends; the recovery key is
used up. See [Recovery](guide/recovery.md#a-lost-mac).

### Short change ids work

`lonca pending` and `lonca log` show the first 12 letters of a change id,
but `lonca diff`, `lonca change` and `lonca advise` refused them
("invalid change id"). They now take any 4 or more letters that name one
change; when several changes start with them the answer lists those. The
daemon has a new read method for it, `change.resolve`.

### `undo` and `revert` read the whole log

The daemon answers `log` a page at a time (1000 entries), and `lonca undo`
and `lonca revert` read only the first page. On a longer log `revert`
planned nothing after entry 999 and said "nothing to revert", and
`undo` of a `policy.update` past entry 1000 put back the last policy of the
first page instead of the one before it. Both now read every page.

### More of the guide

New pages: [Concepts](guide/concepts.md),
[Reviewing agents' work](guide/reviewing.md),
[Troubleshooting](guide/troubleshooting.md) and
[Recovery](guide/recovery.md).

### Live runs for this release

Claude Code 2.1 (haiku), as `docs/release-checklist.md` asks: a session
leased, proposed and integrated after approval, and `lonca diff` listed no
generated file; two sessions at once on one file, on different symbols, both
integrated; one that stopped without proposing was sent back by the stop
hook, proposed, and left no unproposed work. `lonca-audit verify` passed on
the log. **Not run: Codex 0.167 and OpenCode 2.2.** Their free models on
Ollama's cloud are retired and the local one was not used. No harness
profile has changed since 0.2.1; Codex last ran live before 0.2.0 (Codex
0.165), with Claude Code on one file, and both integrated.

## 0.2.1 (2026-11-09)

Its tests ran on Ubuntu, macOS and in the bubblewrap sandbox; as for
0.2.0, the mutation run did not gate it (docs/decisions.md, "Mutation
testing"), and its survivors are fixed in a later 0.2.x.

### Auditing a restore on a hardened install

`lonca restore` ended with `Audit it: lonca-audit verify
<home>/repos/demo.git`, a placeholder, and on a hardened install a store
the developer can not read. Now it prints the store's real path (the
daemon's `repo.restore` result has a new `path`), or on a hardened daemon
how to verify the source it was restored from. `lonca-audit` names
"permission denied" for a path it can not read instead of "does not appear
to be a git repository", and points at verifying a backup bundle. The quick
start says which store path is the cooperative one.

### A closed pipe no longer panics the CLI

`lonca status | head`, `lonca log | grep -q ...` and the like ended in a
panic (`failed printing to stdout: Broken pipe`). Now the command finishes,
drops the output no one reads, and exits as it would have (0 on success).
Another write error on stdout (a full disk) is reported and exits 3. The
hook blocks the call (exit 2) when the harness can not read its answer,
unless it runs with `--fail-open`. See `docs/decisions.md`, "A closed stdout
ends a command quietly (#207)".

### A newer proposal replaces the pending one

A workspace that proposed again while its first proposal waited for a
human had two pending changes, the second holding the first's edits:
approving both landed the work twice, the second time as an empty commit.
Now the newer proposal withdraws the older in the same entry and names it
in its reasons (`replaces:<change>`). The older reads `withdrawn`, leaves
`status.pending` and can not be approved; its pinned leases pass to the
newer. A queued change is left to land. Log format 26; older logs replay as
they were. See `docs/decisions.md`, "A newer proposal replaces the pending
one (#107)".

### Hardened mode, installed for real on Linux

The Linux installer ran for real with `sudo` (Debian 12, systemd), and what
broke is fixed. A hardened install has an import directory
(`/Library/Lonca/import`, `/var/lib/lonca-import`) where you leave a Git
bundle for `lonca init --import` or `lonca restore`: before, a hardened
daemon could read neither a project of yours nor a cooperative backup. The
daemon copies the bundle before git reads it (`lonca daemon --import-dir`).
Running a newer archive's installer is the upgrade: it stops the daemon,
replaces the binaries and starts it again (on Linux the old daemon kept
running before). Linux has `uninstall-hardened.sh` too. `ping` says
`hardened`. A hardened daemon no longer starts with `--local-root`. macOS has not been installed for real yet. See
`docs/decisions.md`, "Hardened mode in the field (#10)".

### `status` names the policy's checks

`status` has `policy_checks`: the names of the named checks the policy in
force defines (`verification.checks`), sorted, `null` when the policy can
not be read. A runner can refuse a check name nobody defined when it is
written, not at the human's yes. Names only; a check's command never
reaches a client. The protocol number stays 1: a field was added.

### Crates and Homebrew

Every published crate has a README on crates.io; `lonca-client` and
`lonca-net` show it on docs.rs as well, with an example that is compiled
as a test. Homebrew is shown as `brew tap selcukgural/lonca`, then
`brew install lonca`, so the short name works for `brew upgrade lonca`
too. The repository's README is a short front page; what it held is on
the site (backups in the quick start, limitations on "What Lonca is").

## 0.2.0 (2026-11-08)

The first release. Its tests ran on Ubuntu, macOS and in the bubblewrap
sandbox; the mutation run did not gate it (docs/decisions.md, "Mutation
testing"), and what it finds afterwards is fixed in 0.2.x.

### Releases: prebuilt binaries, crates.io and Homebrew

The first release with prebuilt binaries: `lonca` and `lonca-audit` for macOS
(arm64, x86_64) and Linux (x86_64, arm64, static), with `lonca-se` on macOS,
checksums, a CycloneDX SBOM and a build provenance attestation per archive
(`gh attestation verify lonca-<target>.tar.gz --repo selcukgural/lonca`).
Install with `curl -fsSL https://selcukgural.github.io/lonca/install.sh | sh`,
`brew install selcukgural/lonca/lonca` or `cargo install --locked lonca`;
every crate of the workspace is on crates.io at the same version. The CLI's
package is now `lonca` (was `lonca-cli`), and the minimum Rust is 1.90. Each
archive carries the hardened install scripts. See `docs/decisions.md`,
"Releases and install paths (#7, #8)".

### A client crate for harnesses

`lonca-client` is what a harness or runner needs to talk to the daemon, and nothing else: the
protocol's request and response types and `PROTOCOL`, the socket client with the daemon checks
(socket owner, peer uid, the hardened config), framing, an optional timeout (past it the call
fails `timed_out` and the connection is dropped, since the request may have run), typed errors
that tell `rate_limited`, `busy` and `closed` apart (`is_transient`), and the human session file
reader, which refuses a link, another user's file or one others can read. It depends on
`lonca-core` without its Git store, which is now the default feature `store`. A protocol number
change is a major version of the crate (0.x: minor). `lonca` no longer uses a session file
others can read, and a login writes an old file back as 0600. See `docs/decisions.md`, "A
client crate for harnesses (#192)".

### Checks a change owes, named per change

`[verification]` takes named commands, `checks = { api = "cargo test --offline -p api" }`,
which run only for a change that owes them: a human names them when approving
(`lonca approve SEQ --also api,e2e`, signed in `approve`, log format 25), or
`checks_by_path = { "api/**" = ["api"] }` does for a path. They run in the queue's sandbox
after build and test, a failure rejects with `verification_failed:<name>`, and a check owed
is owed even with `required = false`. A new version of the change keeps them.
`status.changes[]`, `status.pending[]` and `change.get` add `checks` (asked) and `runs`
(what the queue will run). See `docs/decisions.md`, "Checks a change owes, chosen per
change (#191)".

### A session whose hooks do not run is marked and tainted

`lonca mcp` now tells the daemon which tool it runs (`mcp.call`). On Claude Code, whose
`PreToolUse` fires for MCP tools too, the hook's event must come first; a call with none
means the harness is not running the session's hooks, and the session is marked
`unhooked`: logged once, a security event, tainted, `unobserved` from then on. What it
proposes waits for a person (`unhooked_session`) and a critical path is refused
(`unhooked_critical_path`). `status.sessions[]` adds `bound_ms`, `last_hook_ms` and
`unhooked`, so a runner can stop a session the daemon has not seen. Log format 24. Other
harnesses are checked once a run shows the same (`events.before_tool_mcp` in a profile).
See `docs/decisions.md`, "A session whose hooks do not run (#190)".

### A clean stop is on the record

`status.sessions[].unproposed` was `null` both for a session that stopped or ended with nothing
left and for one that never reported, so a runner could not tell a workspace safe to remove
without a live token. A clean report now reads `{"paths": [], "total": 0, "rounds": 0, …}`, and
`null` means nobody said since the session began or last proposed. `lonca status` lists only
sessions that left work, as before. See `docs/decisions.md`, "Stopping with unproposed work"
(#189).

### Merge: a change already in trunk, and deletions at the top

Symbol engine 15. A change whose every edit trunk already has merges into trunk unchanged; it
used to be a conflict on the file when trunk had also added something at the same place. A
function or method deleted at the top of a file or of a class no longer leaves a blank line
there, which a format check in verification would refuse. Found by the new merge property tests.
Older entries are recomputed with the engine they name. See `docs/decisions.md`, "Symbol engine
versions", Engine 15.

### A delegated lease comes back when the child expires

A lease set handed to a child session with `cap.attenuate` went back to the parent only when the
child ended. Now it goes back as well when the child's time runs out or it misses its heartbeat,
with the time the set had, if the parent is still there; until now it ended, and another session
could take it first. Log format 23. See `docs/decisions.md`, "A delegated lease comes back (#40)".

### Insert leases reserve names; a new file needs its path

An `insert` lease item can list the names of the members it adds (`"names"`, `lonca lease
acquire --kind insert --name throttle`). Two inserts into one container that reserve one name
conflict, an addition outside the reserved names is denied with `lease_missing`, and adding a
name another session reserved is denied with `name_reserved`, whatever lease covers it. An insert
without names otherwise works as before; `lease_needed` now offers inserts with the names the
change adds. A change that adds a file now needs an `edit` lease on its `path#<file>`, so two
agents can not create one path; until now a new file needed no lease. A path trunk created
after the change's base is `created_since_base`: sync first. The agent rules say all of this.
Additions at one place are merged in queue order, the last integrated nearest to its neighbour.
Log format 22. See `docs/decisions.md`, "Insert leases (#45)".

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
