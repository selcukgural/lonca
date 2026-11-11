# Running agents on Lonca

What a runner (imece, a CI job, a script) installs and runs so that a
worker's session is observed by Lonca and its changes go through the
daemon. Leases, claims and the merge queue work the same for any agent
that can reach `lonca mcp` or the `lonca` command; the hooks below add
observation. The steps use Claude Code (the short version, with what each
hook does for it: [Lonca with Claude Code](claude-code.md)); "Other
harnesses" lists what differs. The daemon's protocol is `docs/protocol.md`; this
page is the harness side.

## One worker, step by step

1. **A session and a workspace.** As a human (a human session is opened
   by itself, see `docs/protocol.md`, "CLI for runners"):

   ```sh
   lonca session start --repo demo --agent claude --paths 'src/**' \
         --task T-142 --ttl 2h --workspace /work/claude-1 \
         --scratch /work/claude-1-scratch --json
   ```

   The workspace holds the files of trunk and `.lonca/workspace.json`;
   `.lonca/session` holds the agent's token (0600). It is a git repository
   as well (see "Git in a workspace"). The scratch directory is where the worker keeps notes, logs
   and throwaway files: writes there are allowed and are not facts,
   nothing there can be proposed. It must lie outside the workspace.
   The roots are recorded in the session's scope in the log.
2. **Claude Code in the workspace.** Start it with the workspace as
   `cwd` and, if the worker gets a scratch directory, `--add-dir` for
   it. Give it the settings below (hooks) and the MCP entry.
3. **The worker works.** The SessionStart hook injects Lonca's rules;
   `lonca mcp` offers `lease_acquire`, `lease_renew`, `preview`,
   `propose`, `sync`, `status`, `negotiate`, …; every tool call goes
   through `lonca hook`. While it runs it sends heartbeats and renews
   the worker's lease sets, so a turn longer than the TTL keeps its
   leases; when the harness dies, so does `lonca mcp`, and the leases are
   free `leases.heartbeat_timeout_ms` later (5 minutes by default). A
   runner that does not use `lonca mcp` calls `lonca session heartbeat`
   every third of that, or lives by the TTL (`lonca lease renew`).
4. **The worker is done.** Its `propose` leaves a change that is queued
   (`allow`) or waiting for a human (`escalate`, in `status.pending`
   and `lonca pending --json`). If the worker proposes again while the
   first waits, the new change replaces it: the first is `withdrawn` and
   the answer names it (`replaces:<change>`), so there is one change to
   approve. The person approves (`lonca approve
   <seq> --json`) or, for now, lets it be; the merge queue integrates
   it and verifies. A card's own acceptance check is a named check of the
   policy (`verification.checks`): the person adds it with `--also
   <name>`, or the policy names it for the card's paths
   (`checks_by_path`); `runs` in the pending entry says what will run
   (docs/guide/verification.md, "Checks a change owes by name"). The worker syncs (`lonca sync`) after integration.
   The leases the change needed stay pinned to it until then, past
   their TTL, and integration releases them: to edit the same symbols
   again the worker leases them again.
5. **The worker ends.** In the workspace, `lonca session end --json`
   ends the session and its token. A session a runner forgets expires
   at its TTL; `lonca session revoke <id>` ends one from outside.

## Git in a workspace

`session start` makes the workspace a repository with one commit, `lonca base
<trunk commit>`, on `main`, so `git status`, `git diff` and tools that want a
repository work. Lonca writes it without running `git`, so no `git` is needed
and your git config plays no part. There is no remote and no hook; `.lonca/`
and the files `lonca harness setup` wrote are excluded.

- `git diff` shows the local edits, the same as `lonca diff` until the agent
  commits. `lonca sync` moves the repository to the new base: `main`, `HEAD` and
  the index. What was committed or staged is then a local edit again, and a
  branch is left behind, but no file changes. A sync that can not do this (the
  agent replaced part of `.git`) still syncs and says so: `git_warning` with
  `--json`, a warning otherwise.
- A workspace holds regular files. A symlink at a tracked path, or on the way
  to one, stops `diff`, `propose` and `sync` with an error naming it; other
  symlinks are ignored.
- A commit is local. `lonca propose` sends what differs from the base, whether
  it was committed or not, and nothing is proposed from `.git`.
- `git clean -x` removes `.lonca/` as well: that ends the workspace.
- `--no-git` keeps a plain directory. Setting it up costs about 1.5 s per
  10,000 files; a workspace left by an older Lonca stays plain when continued.

An agent can write to `.git`, so treat its config as you would that of a
repository you cloned from a stranger: a `git` command you run in there, outside
the agent's sandbox, runs what that config says. `lonca fetch` and `propose
--commit` refuse to run in a workspace for this reason, and `lonca sync` never
reads it.

## How much a session may send

A session may send the log `sessions.ops_per_minute` operations a minute (600
by default, shared with the sessions made from it). Past that a request is
`rate_limited`, nothing is logged, and the message says when to try again. A
connection that stays quiet is closed with a `closed` line; `docs/protocol.md`,
"Wire format", has what a client does then.

## A worker that outlives its session

A session has a TTL (`sessions.max_ttl_minutes`, 8 hours by default) and
can not be extended; a worker that sleeps overnight goes on under a new
one. When the session is over, `lonca session heartbeat` exits 1 and
`lonca mcp` stops beating and answers every tool with `{"code":
"session_inactive", ...}`. Continuing is a human's act, signed like a
start:

```sh
lonca session start --repo demo --agent claude --paths 'src/**' \
      --continue /work/claude-1 --json
```

- The workspace stays as it is: files, base, manifest, and the change it
  proposed. `sync`, `diff` and `propose` go on where they stood. The
  session token in `.lonca/session` is replaced; restart `lonca mcp` so
  it reads the new one.
- A session that is still alive ends in the same step, so one workspace
  never has two live sessions. A session can be continued once.
- **Taint carries over**, with what was seen written, because the
  workspace may hold what the tainted session wrote. A fresh directory is
  the only clean start. The observation level does not: the new session is
  `unobserved` until its own harness reports, and a continued session can
  not become `isolated`.
- **The session continued is the one started in that directory**, as the
  log has it. A directory that was moved, or a session started before
  Lonca 0.2.4, can not be continued.
- **Leases do not**, and the worker leases again; `lease_needed` says
  what. Items pinned to a change in flight stay pinned to it and pass to
  the new session, so the worker can sync and propose on top of it, and
  `change.withdraw` it. A proposal by the new session replaces the
  pending one of the old, as it would its own.
- `--paths` wider than the old session's is refused unless the human
  adds `--widen`, which the prompt and the log both show. Pass
  `--scratch` again if the worker needs its scratch roots; they are part
  of the scope.
- Revoking any session of the chain withdraws what all of them have in
  flight.

## Any agent, in a sandbox

`lonca run` holds any command in a sandbox Lonca builds. It needs no hook and
nothing from the harness, and the session gets `level: isolated`:

```sh
lonca session start --repo demo --agent worker --paths 'src/**' \
      --workspace /work/w1 --scratch /work/w1-scratch --json
cd /work/w1
lonca run --session ses_… --env CLAUDE_CODE_OAUTH_TOKEN -- claude -p "fix the bug"
# OpenCode, which runs a private server here and listens on loopback:
lonca run --session ses_… --loopback --env PWD=$PWD -- \
      opencode run --standalone -m <model> "fix the bug" </dev/null
```

You sign for the sandbox, so run it yourself or give it to something that holds
your key, never to the agent. The exit code is the command's. The session ends
with the command, and what was left unproposed is on the record and printed. Each
run takes a new session in a new workspace: a session something has already used, or
a workspace that differs from its commit, is refused. That covers ignored files, empty
directories and anything of yours in `.lonca`. Files of `lonca harness setup` count only
for the harness you named with `session start --harness`. A run that goes ahead then
deletes all of the workspace and writes it again, `.git` too, so a branch left there is
gone and nothing left in it reaches the sandbox. A refused run changes nothing.

The command's stdin is a pipe from yours, never your terminal. A command that reads
stdin to its end before it starts waits for you with no output, as `opencode run`
does. Give it `</dev/null`. The same goes for a runner that starts one with an open
pipe.

Inside, the command:

| | |
|---|---|
| writes | the workspace, the scratch roots, a `HOME` and `TMPDIR` of its own, which are deleted at the end |
| reads | the system's directories, the workspace, the directories on `PATH`, its own program, and `--read PATH` |
| can not read | your home directory, other workspaces, shared temp directories, Lonca's stores and keys, even with `--read` |
| reaches | `lonca`'s socket and the proxy, nothing else: no DNS, no other socket, no Keychain |
| keeps | none of your environment but `PATH`, locale, `TERM`, `USER`; the harness's `env` and `run_env` from its profile (below) and `--env NAME` or `--env NAME=VALUE` add to it, yours over the profile's |
| has | three pipes for its streams, no terminal: use the harness's non-interactive mode |

- Nothing the command starts outlives it, a daemon that left its session included.
- Use `lonca` inside as anywhere else, it is on `PATH`: `lonca mcp`, `lonca propose`,
  and hooks if the harness has them. `LONCA_WORKSPACE`, `LONCA_SOCKET` and
  `LONCA_TOKEN_FILE` are set for it. `.lonca/session` is gone when the run begins.
- Your tools usually need more than `PATH`: `--read ~/.rustup --env RUSTUP_HOME`.
  A harness that keeps state in its home directory will start empty; point it at a
  scratch root with `--env`.
- The harness named with `session start --harness` gets the environment its profile
  sets for a run: `claude-code` gets `CLAUDE_CODE_TMPDIR` set to the sandbox's
  `TMPDIR`, since Claude Code makes `/tmp/claude-<uid>` whatever `TMPDIR` says and
  exits when the sandbox keeps it out of `/tmp`. What the run sets itself (`PATH`,
  `HOME`, `TMPDIR`, `LONCA_*`, the proxy) stays the run's.
- Its login does not come in. Claude Code keeps it in your home directory and, on
  macOS, the Keychain, both closed to the sandbox, so `claude -p` answers "Not logged
  in". Give it a credential with `--env`: `claude setup-token` prints a long-lived
  token for a subscription, passed as `CLAUDE_CODE_OAUTH_TOKEN`; an API key goes as
  `ANTHROPIC_API_KEY`. Its settings start empty in the run's own `HOME`.
- With no sandbox on the machine it stops; it never runs the command bare. macOS has
  `sandbox-exec`; on Linux install bubblewrap. Ubuntu 24.04 also needs
  `kernel.apparmor_restrict_unprivileged_userns=0`.

**The network.** Every connection goes through the daemon's proxy and is logged, and
any of them taints the session, so its changes wait for a human. That includes the
agent talking to its own model. Name that host in the policy, and it is logged but
taints nothing, under `network = "deny"` as well:

```toml
[observation]
agent_hosts = ["api.anthropic.com"]
```

A harness that listens on loopback (OpenCode runs a local server) needs `--loopback`
on macOS. Seatbelt can not tell its listener from the machine's, so every local
service opens with it, and one that runs things for its caller is a way out of the
sandbox. On Linux the sandbox has a loopback of its own and the flag does nothing.
The log shows it: `sandbox: seatbelt-loopback`.

This is a channel to that vendor under any key the agent can find, so name only what
the agent needs. A daemon started with `--no-proxy` leaves the sandbox with no
network at all. A model on this machine (`ollama`) also needs
`allow_private_network = true`.

The proxy holds every connection to the policy:

```toml
[observation]
# Destination ports; anything else is refused before it is resolved.
allow_ports = [80, 443]
# Hosts that pass even under network = "deny", each saying whether it taints.
# An exact name, or "*.suffix" for every name below the suffix (not the
# suffix itself). The first rule that matches counts.
allow_hosts = [
  { host = "registry.npmjs.org", taint = false },
  { host = "*.crates.io", taint = true },
]
# Per session: connections open at once, and bytes moved through the proxy
# (both ways) while the daemon runs. Past the bytes a connection is cut.
max_connections = 16
max_bytes = 1073741824
```

A local model on port 11434 needs that port in `allow_ports` too. Cloud metadata
addresses (`169.254.169.254`, `fd00:ec2::254` and the like) are never reachable,
`allow_private_network` or not. Every attempt is in the log, refused or not, with
the port when it is not 80 or 443 (`"host": "localhost:11434"`). When the daemon
can not tell which process opened a connection (`lsof` gave no answer), every
session the proxy serves answers for it; `lonca status` says how often that
happened since the daemon started (`PROXY …`, `proxy_unattributed` in `--json`).

**Requiring it.** Cedar sees the level, so a policy can ask for a sandbox by path or
by task:

```cedar
@id("auth-in-a-sandbox")
forbid(principal is Lonca::Agent, action == Lonca::Action::"file.modify", resource)
when { context.path like "src/auth/*" && context.observation != "isolated" };
```

## Setting up a harness

The short way, for any harness with a profile:

```sh
lonca session start --repo demo --agent worker --paths 'src/**' \
      --workspace /work/w1 --harness claude-code --json
```

or `lonca harness setup <name>` inside a workspace. It gives the harness the
rules, the MCP server with its socket and workspace, approval of Lonca's own
tools, and the hooks.

| Harness | What setup does |
|---|---|
| `claude-code` | Writes `.mcp.json` and `.claude/settings.local.json`. `--print` gives `--mcp-config` and `--settings`. |
| `codex` | Writes nothing: start it with the flags. Codex skips `.codex/` in a directory no person has trusted. |
| `gemini` | Writes `.gemini/settings.json`; start it with the printed `env`. |
| `opencode` | Writes `opencode.json`, its rules and a plugin that calls `lonca hook`. Its `execute` tool runs code and taints, so changes need a person. Tested with OpenCode 2.2. |

- `--print` writes nothing and shows the flags, environment and files, for a
  runner that keeps the workspace clean or a repository that tracks one of
  these files. `--json` has all of it.
- These files are never a local change, in no `diff` and no proposal. A file
  the repository has, a local file or a symlink at a target stops the setup
  before anything is written.
- Codex's hooks need a person's review with `/hooks`, or
  `--dangerously-bypass-hook-trust`, which also runs any other hook left
  unreviewed: your choice, and Lonca does not add it. Without them the rules
  and the MCP server still work. In a `--no-git` workspace, add
  `--skip-git-repo-check`.
- A name with no profile gets the rules and how to start `lonca mcp`, for you
  to put where that harness reads them. `lonca rules` prints the rules
  anywhere.
- Generated hooks are cooperative: the agent can edit them, and they do not
  raise the observation level.

## Claude Code settings

Hooks, in the settings file the runner gives the worker (`settings.json`
of the project, or managed settings in hardened mode; the hardened
installers write these for you):

```json
{
  "hooks": {
    "SessionStart": [{"matcher": "*", "hooks": [{"type": "command", "command": "lonca hook", "onFailure": "block"}]}],
    "PreToolUse":   [{"matcher": "*", "hooks": [{"type": "command", "command": "lonca hook", "onFailure": "block"}]}],
    "PostToolUse":  [{"matcher": "*", "hooks": [{"type": "command", "command": "lonca hook", "onFailure": "block"}]}]
  }
}
```

- `matcher` is `*` (or absent): every tool. A tool Lonca does not know
  is observed, not blocked, and taints the session (`[taint]
  unknown_tools`, `safe_tools`).
- `onFailure: block`: when the hook can not reach the daemon it exits
  2 and the tool call is blocked (fail closed). Without it an
  unreachable daemon would let everything through unobserved.
- The command is `lonca hook` on the worker's `PATH`, or an absolute
  path. In hardened mode it must be the root-owned binary; the
  observation level (`hook.bind`) is `hooks_sandbox` only when the
  settings are managed, hooks-only, and the sandbox is locked, and the
  session was started with `--harness claude-code`.

The MCP server, in `.mcp.json` of the workspace or via
`claude mcp add lonca -- lonca mcp`:

```json
{"mcpServers": {"lonca": {"command": "lonca", "args": ["mcp"]}}}
```

Environment both need: `LONCA_SOCKET` (else `$LONCA_HOME/lonca.sock`,
else `~/.lonca/lonca.sock`). Nothing else: the hook and the MCP server
find the workspace from `cwd` (upwards to the first
`.lonca/workspace.json`) and read the token from `.lonca/session`.
Outside a workspace, or in a human workspace, the hook does nothing.

## Other harnesses

Lonca knows no harness in its code: `lonca hook --harness <name>` hands
the event to the daemon, which reads it with that harness's **profile**.
Profiles for Claude Code, Codex, Gemini CLI and OpenCode come with Lonca
(`crates/lonca-policy/src/harnesses.toml`). Use the same four events:

| | Claude Code | Codex | Gemini CLI |
|---|---|---|---|
| Events | `SessionStart`, `PreToolUse`, `PostToolUse` | the same | `SessionStart`, `BeforeTool`, `AfterTool` |
| Stop event | `Stop` | `Stop` | `AfterAgent` |
| Command | `lonca hook` | `lonca hook --harness codex` | `lonca hook --harness gemini` |

An event the named harness does not have exits 2, so a hook set up for the
wrong harness blocks instead of watching nothing. `onFailure: block` is
Claude Code's: check what yours does when a hook fails.

The stop event is the exception: give it `--fail-open`. Harnesses read exit
status 2 there as "go on", so without the flag a daemon that is down would
keep an agent working for ever. `lonca harness setup` writes it for you.

### An agent that stops with unproposed work

Nothing reaches the repository until it is proposed, and an agent can say
"done" first. On the stop event `lonca hook` sends the workspace's local
changes to the daemon. If no standing proposal carries them, the agent is
told what is unproposed and what to do next, and goes on.

That happens `[sessions] stop_rounds` times in a row (3 by default; a proposal
that stands starts over, and 0 only records), so an agent that can not
propose still ends. Then `status` lists the session under `unproposed work`,
and `status.sessions[].unproposed` has the files: read this to tell "stopped"
from "done". A clean stop or end leaves `total: 0` there, and `null` means the
session never said (it expired, or ended without its files). `lonca session end` records the same, for a harness with no
stop event.

A mark means work was left. Its absence proves nothing: only a proposal does.

OpenCode has no stop event of its own. Its plugin answers from the session hook
`experimental.idle`, which is the last moment of a turn: what the hook adds keeps the
turn going, so `opencode run` stays open until the agent has proposed. Seen working
with OpenCode 2.2.5. The name says experimental: if OpenCode drops it, an agent ends
its turn as on a harness with no stop event, and `lonca session end` still records
what was left. A subagent's work is its parent's to deliver, so only the parent is
sent back.

### Observation levels

| Harness | Level with hooks | Why |
|---|---|---|
| Claude Code | `hooks_sandbox` with its managed settings | Hooks only an administrator sets, and a failure blocks |
| Codex 0.167 | `unobserved` | A hook that crashes or times out lets the tool run |
| Gemini CLI 0.67 | `unobserved` | A project's settings can turn a system hook off |
| OpenCode 2.2 | `unobserved` | Hooks are a plugin, and settings can not require one |

`unobserved` changes wait for a human. **Any harness gets `isolated` under `lonca run`,
with no hook at all.** That is the way to run these three without a person approving
everything; see "Any agent, in a sandbox". The reasons are in `docs/decisions.md`,
"Harness levels".

**Name the harness when you start the session.** A level is read only for the one in
`session start --harness <name>`, which you sign; without it the session is `unobserved`
on any machine. Where an administrator keeps the hooks, add `--no-setup` to name it and
write nothing in the workspace:

```sh
lonca session start --repo demo --agent claude --paths 'src/**' \
  --workspace /work/w1 --harness claude-code --no-setup
```

Once set, a level stays or falls for the rest of the session. If the first report was
low, because of the settings or because `sudo` needed no password, fix that and start a
new session (`--continue` keeps the workspace).

**A harness without hooks is unobserved, whatever it is.** A session whose hook never
sent `hook.bind` stays `unobserved`. And where the daemon can tell, it checks that the
hooks keep running: Claude Code fires `PreToolUse` for MCP tools too, so each call to
`lonca mcp` must come after its event. One that does not marks the session `unhooked`
(a flag, a setting or a new version skipped the hooks): it is tainted, `unobserved` for
good, what it proposes waits for a person (`unhooked_session`) and a critical path is
refused (`unhooked_critical_path`). `status.sessions[]` has `bound_ms` (`null`: never
bound), `last_hook_ms` and `unhooked`; a runner that wants observed workers stops a
session with either of the first two missing or with the mark, and starts it again in a
harness that runs its hooks.

A level comes from a `locked` table in the profile: a file only root can write and what
must hold in it. A harness gets one when it can be shown that its hooks hold, also when
they fail. The table is part of a whole profile (start from `lonca harness show <name>`);
a profile of yours with no table keeps the built-in one:

```toml
[harnesses.acme.locked]
file = { macos = "/Library/Application Support/Acme/managed.toml", linux = "/etc/acme/managed.toml" }
format = "toml"                      # or "json"
# Each list, as a JSON pointer, needs a Lonca hook for every tool: a group of `hooks`,
# with a `command`, and at most a `matcher` of "*". Every such hook's program must be
# root-owned as well.
hook_lists = ["/hooks/before", "/hooks/after"]
# What a Lonca hook must say besides its command, if a harness needs it to block.
hook_fields = { on_error = "block" }
# What makes these hooks the only ones. This list and `sandbox` each need a check a
# value must pass: "empty" holds for a key nobody wrote.
hooks = [{ at = "/managed_hooks_only", equals = true }]
# What locks the shell sandbox, with its network through Lonca's proxy. Leave it out
# and the level stops at `hooks`.
sandbox = [
  { at = "/sandbox/enabled", equals = true },
  { at = "/sandbox/proxy_port", is = "proxy_port" },   # where the daemon's proxy listens
  { at = "/sandbox/excluded", is = "empty" },    # missing or an empty list
]
```

The answer of `hook.bind` has notes for what did not hold; `lonca doctor` shows the same
for the built-in tables, not for one in a repository's policy.

### Any other harness

A harness that can run a command with a JSON event on stdin needs no new
Lonca, only a table in `lonca.toml`, set with `lonca policy set`. It lives
in the signed policy because what a tool counts as decides what taints a
session; an agent can not choose it.

```toml
[harnesses.acme]
events = { session_start = "begin", before_tool = "about_to", after_tool = "did" }
# Where the parts are in its JSON; these are the defaults.
fields = { event = "hook_event_name", tool = "tool_name", input = "tool_input", cwd = "cwd", session = "session_id" }
# What it wants back. {reason} and {context} are filled in.
deny = { allowed = false, why = "{reason}" }
context = { say = "{context}" }
# Optional: the answer to a finished tool call that adds to the context.
tool_context = { say = "{context}" }
# How it names MCP tools; these are the defaults (mcp__server__tool).
mcp_prefix = "mcp__"
mcp_separator = "__"
# Add `before_tool_mcp = true` to `events` only once a run has shown that
# `before_tool` fires for MCP tools as well: then a call to `lonca mcp` with no
# such event before it marks the session `unhooked`.

[harnesses.acme.tools]
open = { kind = "read", fields = ["path"] }
save = { kind = "write", fields = ["path"] }
patch = { kind = "write", fields = ["text"], headers = ["+++ "] }
run = { kind = "shell", fields = ["line"] }
get = { kind = "fetch", fields = ["url"] }
find = { kind = "search" }
plan = { kind = "inert" }

[harnesses.acme.setup]
# Arguments for a runner: text, or { file = "..." } for a file's text.
flags = ["--config", { file = ".acme/config.json" }]
note = "What a person has to know."

[harnesses.acme.setup.env]
LONCA_SOCKET = "{socket}"

# Besides env, only inside `lonca run`: {home} and {tmp} are the sandbox's own.
[harnesses.acme.setup.run_env]
ACME_CACHE = "{tmp}/acme"

# format is json, toml or text. {rules}, {socket} and {workspace} are filled in.
[[harnesses.acme.setup.files]]
path = ".acme/config.json"
format = "json"
content = { server = { command = "lonca", args = ["mcp"], cwd = "{workspace}" } }
```

`kind` is `read`, `write`, `shell`, `fetch`, `search` or `inert`. `fields`
are tried in order. `env` and `run_env` name no variable that changes what a
program loads (`PATH`, `LD_*`, `DYLD_*`, `NODE_OPTIONS` and the like, as for
`--env`); `run_env` names none of Lonca's own either. `headers` are for a tool whose paths are inside a text.
`events.stop` and `stop_deny`, the answer that sends the agent back with
`{reason}` filled in, are optional and go together. `tool_context` is how news
from other agents reaches one that is busy editing; without it the news waits
for its next tool of `lonca mcp`.
A tool not in the table is observed and taints (`[taint] unknown_tools`).
The same table replaces a built-in profile, as a whole, for a harness that has
moved on faster than Lonca: no new release is needed. `lonca harness show
<name>` prints the built-in one as a table to start from; change what moved
and sign it with `lonca policy set`. It holds for that repository until you
remove it. Profiles are not files beside the program, because what a tool
counts as decides what taints a session, and an agent running as your account
could rewrite such a file. A harness with plugins instead of commands fits too: a
`text` file in `setup` can be the plugin that calls `lonca hook` and turns exit
status 2 or a `deny` answer into its own refusal. A harness with no hooks at all still works through
`lonca mcp` or the CLI, unobserved.

## What the hooks do

- **SessionStart**: `hook.bind` reports how locked the harness is and
  gets back the observation level and the session's scratch roots;
  the hook injects a context block that names the repository, the
  session, the level, the scratch directory and the rules (lease before
  editing, propose with the symbols changed, sync after integration).
- **PreToolUse**: writes outside the workspace and the scratch roots
  are denied, as are writes to `.lonca/` and shell commands that
  mention Lonca's own files (`.lonca/`, the socket, keys, settings).
  Reads, fetches, shell commands and other MCP tools are observed and,
  depending on `[taint]` in `lonca.toml`, may taint the session.
- **PostToolUse**: writes inside the workspace are recorded; a
  proposal that changes a file no observed tool wrote is denied or
  escalated (`unobserved_write:<path>`).
- **No hook at all**: a call to `lonca mcp` with no `PreToolUse` before it
  marks the session `unhooked`, which taints it (see "Observation levels").

Taint means: the session read content from outside (a web page, an
untrusted path, another MCP server). Its changes need a human's
approval and, unless the policy says otherwise, may not touch critical
paths. The repository decides what
taints (`[taint] fetch`, `shell_network`, `mcp_servers`); a runner
whose workers must read the web sets `fetch = false` and lists its own
MCP server, and keeps the human approval as the control.

### Critical paths in cooperative mode

In cooperative mode every session is `unobserved`: hooks from `--settings`
are not proof, since the agent could have changed them. So every change waits
for a person, and a change to `[paths] critical` (`Cargo.toml`, `package.json`,
`.github/**`, ...) is denied outright, `unobserved_critical_path`, with nobody
to ask. A worker can not add a dependency.

If a person really does review every change, say so in the signed policy:

```toml
[observation]
unobserved_critical = "escalate"
```

The change is then pending with `critical_path:<path>` and integrates once
approved. Do not use `unobserved_is_tainted = false` for this: the denial goes,
but so does the review, and changes integrate with nobody looking.

`[taint] critical` is the same word for tainted sessions, and it is separate: a
taint says content from outside really did enter the session, so it stays
`deny` unless you decide otherwise. A session that is both needs both words
open. Set `critical = "escalate"` only if whoever approves reads those changes
knowing the worker may have been told what to write.

## Waking an idle agent

An agent hears what other sessions want of it with the answer of its next
tool call. An agent that is idle, waiting on an interest or on the queue,
makes no call, so the runner wakes it. The runner waits with the human
session it started its agents with, no agent token needed:

```sh
lonca events --watch --follow --json --repo demo
# {"session":"s2","kind":"lease_received","seq":41,"from":"s1"}
# {"session":"s1","kind":"reserved","reservation":"9c0f…","until_ms":…}
# {"session":"s3","kind":"integrated","seq":44,"change":"…"}
```

One line per event, for every session this human started (`--session
s1,s2` for some of them): a change `integrated`, `conflicted` or `failed`,
a request `approved` or `rejected`, a `message` or a lease handed over
(`lease_received`) from another session, a change of another session that
touches what it holds (`symbols_changed`), and an interest of its that is
now `reserved` for it. For each line, wake that agent (resume it, or send
it a turn such as "Lonca has news for you; read your inbox"): it reads the
news itself, with what the other agent wrote, through its tools. The runner
gets the kind, the session and the change, never the words; and watching
marks nothing as read, so the agent is told all the same.

A named session that ended or expired comes as `{"kind": "ended",
"reason"}` and is no longer watched. A runner in Rust uses
`lonca_client::Client::watch`; the socket method is `events.watch`
(`docs/protocol.md`).

## Reading results

- `lonca lease needed --json` in a workspace (the `lease_needed` MCP
  tool): the leases the local diff needs, who holds them, and `acquire`,
  the free ones as items for `lease_acquire`.
- The `symbols` MCP tool lists a file's symbols, and the sections of
  Markdown, TOML, JSON and YAML files, so two workers can edit one
  `README.md` under different headings. `lease_needed` names them.
- `details` in a `lease.acquire` or `change.propose` answer: who holds
  what, their intent, the expiry or the change it is pinned to. Read
  these instead of parsing `decision.reasons`.
- `lonca status --json` (agent token or human session): sessions with
  their level and taint, leases, changes with their status, pending
  entries with change, intent, agent, task, time and files.
- `lonca log --json --from N`, or the daemon's `log` with `wait_ms`,
  to follow the log with one open request.
- Exit codes and `--json` shapes: `docs/protocol.md`, "CLI for
  runners".
