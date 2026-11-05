# Running agents on Lonca

What a runner (imece, a CI job, a script) installs and runs so that a
worker's session is observed by Lonca and its changes go through the
daemon. Leases, claims and the merge queue work the same for any agent
that can reach `lonca mcp` or the `lonca` command; the hooks below add
observation. The steps use Claude Code; "Other harnesses" lists what
differs. The daemon's protocol is `docs/protocol.md`; this
page is the harness side.

## One worker, step by step

1. **A session and a workspace.** As a human (a human session is opened
   by itself, see `docs/protocol.md`, "CLI for runners"):

   ```sh
   lonca session start --repo demo --agent claude --paths 'src/**' \
         --task T-142 --ttl 2h --workspace /work/claude-1 \
         --scratch /work/claude-1-scratch --json
   ```

   The workspace is a plain directory with the files of trunk and
   `.lonca/workspace.json`; `.lonca/session` holds the agent's token
   (0600). The scratch directory is where the worker keeps notes, logs
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
   and `lonca pending --json`). The person approves (`lonca approve
   <seq> --json`) or, for now, lets it be; the merge queue integrates
   it and verifies. The worker syncs (`lonca sync`) after integration.
   The leases the change needed stay pinned to it until then, past
   their TTL, and integration releases them: to edit the same symbols
   again the worker leases them again.
5. **The worker ends.** In the workspace, `lonca session end --json`
   ends the session and its token. A session a runner forgets expires
   at its TTL; `lonca session revoke <id>` ends one from outside.

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
- **Taint carries over**, with the observation level and what was seen
  written, because the workspace may hold what the tainted session
  wrote. A fresh directory is the only clean start.
- **Leases do not**, and the worker leases again; `lease_needed` says
  what. Items pinned to a change in flight stay pinned to it and pass to
  the new session, so the worker can sync and propose on top of it, and
  `change.withdraw` it.
- `--paths` wider than the old session's is refused unless the human
  adds `--widen`, which the prompt and the log both show. Pass
  `--scratch` again if the worker needs its scratch roots; they are part
  of the scope.
- Revoking any session of the chain withdraws what all of them have in
  flight.

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
  and the MCP server still work. Add `--skip-git-repo-check`.
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
  settings are managed, hooks-only, and the sandbox is locked.

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
from "done". `lonca session end` records the same, for a harness with no
stop event.

A mark means work was left. Its absence proves nothing: only a proposal does.

Only Claude Code has a locked setup so far (`hook.bind` gives
`hooks_sandbox` with its managed settings). Other harnesses are
`unobserved`, so their changes wait for a human.

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
# How it names MCP tools; these are the defaults (mcp__server__tool).
mcp_prefix = "mcp__"
mcp_separator = "__"

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

# format is json, toml or text. {rules}, {socket} and {workspace} are filled in.
[[harnesses.acme.setup.files]]
path = ".acme/config.json"
format = "json"
content = { server = { command = "lonca", args = ["mcp"], cwd = "{workspace}" } }
```

`kind` is `read`, `write`, `shell`, `fetch`, `search` or `inert`. `fields`
are tried in order. `headers` are for a tool whose paths are inside a text.
`events.stop` and `stop_deny`, the answer that sends the agent back with
`{reason}` filled in, are optional and go together.
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

Taint means: the session read content from outside (a web page, an
untrusted path, another MCP server). Its changes need a human's
approval and may not touch critical paths. The repository decides what
taints (`[taint] fetch`, `shell_network`, `mcp_servers`); a runner
whose workers must read the web sets `fetch = false` and lists its own
MCP server, and keeps the human approval as the control.

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
