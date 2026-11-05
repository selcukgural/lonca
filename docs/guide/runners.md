# Running agents on Lonca

What a runner (imece, a CI job, a script) installs and runs so that a
worker's Claude Code session is observed by Lonca and its changes go
through the daemon. The daemon's protocol is `docs/protocol.md`; this
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

- `matcher` is `*` (or absent): every tool. Lonca ignores what it does
  not know and never blocks a tool it does not understand.
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
