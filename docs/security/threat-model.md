# Threat model

What Lonca protects, from whom, and where it only detects what it can not
prevent. It describes 0.2.x: one machine, one daemon, one developer with many
agents. The design behind it is §3 of
[design.md](https://github.com/selcukgural/lonca/blob/main/docs/design.md)
(Turkish); each limit below links to where it is decided. Keys and algorithms
are in [Cryptography](../crypto.md), the OWASP mapping in
[OWASP review](owasp.md).

Keep it current: a change that makes a line here untrue changes the line in
the same pull request, as for the OWASP review.

## Assets

| Asset | Where | What losing it means |
|---|---|---|
| Trunk | `refs/heads/main` of the daemon's store | code that nobody allowed, or that skipped verification, becomes the project |
| The operation log | `refs/lonca/oplog`, hash-chained, every entry signed by the daemon | the record of who did what, and the input every decision and audit is replayed from |
| The policy | `refs/lonca/policy` (`lonca.toml`, `policy.cedar`), changed only by human operations | the rules every decision applies |
| Human keys | Secure Enclave, a FIDO security key, or a file under `~/.config/lonca/humans` | whoever signs as a human approves, changes the policy and manages keys |
| The daemon key | `<home>/daemon.key` | whoever holds it can append entries the chain accepts |
| Session tokens | given once to the agent's harness; the daemon keeps a SHA-256 | whoever holds one acts as that session, within its capability |
| The developer's secrets | the developer's files, keys of other services | Lonca keeps them out of its sandboxes; outside them it does not own them |

## Who Lonca defends against

- **The agent** is the main adversary. It can be wrong, hallucinate, reach
  beyond its task, or be taken over by text it read (prompt injection). In
  cooperative and hardened mode it runs under the developer's account.
- **Outside content** is hostile: web pages, issues, another MCP server's
  answers, text in dependencies. It reaches Lonca through an agent that read
  it, which is what taint tracks.
- **Code under verification.** The merge queue builds and tests what agents
  wrote, dependencies included. It runs in a sandbox with no network.
- **Another local user** may reach the socket only as its mode, group and
  uid list allow, and every method checks a credential on top of that.
- **A network peer.** Lonca listens on no network port: the daemon speaks over
  a Unix socket, and its proxy listens on loopback. It talks out to Git
  remotes (`lonca push`, imports), to the hosts a policy allows through the
  proxy, and, for the advisor only, to the Claude API. What a remote sends is
  checked like any other input before it reaches the store.
- **Lonca's own supply chain:** crates.io only, advisories and licences
  checked, Actions pinned, releases with provenance attestations and an SBOM
  ([OWASP review](owasp.md#cicd-security-top-10)).

The **human** is trusted but shares the machine with the agents, so
everything a human approves is shown by the daemon, not written by an agent.
Presence (Touch ID, a touch on a security key) proves that a person touched
the key; it does not prove that they read what they approved. The rule for
people is: never approve a system prompt an agent asked you for.

## Modes

Three modes answer one fact: on a single machine an agent that runs as the
developer can do anything the developer's account can. Only an operating
system boundary stops that, and each mode puts the boundary somewhere else.

| | Cooperative | Hardened | Isolated (`lonca run`) |
|---|---|---|---|
| Agent runs | as you | as you, with the harness's hooks and sandbox locked by root | in a sandbox Lonca builds |
| Daemon, store, keys | your account | a system user of their own (`_lonca` / `lonca`) | as the install's |
| Session level | `unobserved` | `hooks_sandbox` with Claude Code, `unobserved` with others | `isolated` |
| Setup | none | `install-hardened.sh` from a release archive | the install's, plus a sandbox per run |

What each mode does about each threat:

| Threat | Cooperative | Hardened | Isolated |
|---|---|---|---|
| An operation outside the agent's capability, scope, lease or quota | prevented: `decide()` | prevented | prevented |
| A change no one verified reaching trunk | prevented when the policy requires verification | prevented (`verification.required`) | prevented, as hardened |
| Writing the store or its refs directly | detected: `reconcile()` restores or freezes, the auditor reports | prevented: the store belongs to the daemon's user | prevented |
| Signing as a human | prevented with a Secure Enclave key or a security key; with a file key the agent can read it | prevented where the human has a key that proves presence (required); not with `--without-presence`, see [limits](#humans-and-approvals) | prevented: human keys are closed to the sandbox |
| Reading outside content, then changing code | every change waits for a human, since `unobserved` counts as tainted | prevented from inside the harness (taint: the change waits for a human); from a process started outside it, detected | prevented: all traffic goes through the proxy and taints |
| Touching build scripts, CI, lockfiles, agent instructions | refused to unobserved and tainted sessions | refused to tainted sessions | refused to tainted sessions |
| Replacing the daemon, the hook program or the harness settings | possible: they are the developer's files; sessions stay `unobserved` | prevented: root-owned, clients check the daemon's uid | prevented |
| Changing the workspace's own record (`.lonca/workspace.json`) to leave the session, or to be continued as another | no gain: every change waits for a human anyway | prevented: which session works in a directory is in the log (format 30); the hook asks it and blocks tools while the record does not read, and `--continue` names the log's session | prevented: the level does not rest on hooks |
| Writing outside the workspace, or reading outside content untainted, through a symbolic link made inside it | no gain: every change waits for a human anyway, and nothing holds the agent's shell | prevented for the harness's file tools: the hook resolves a path's links before the daemon places it, at the time of the call; a link swapped between the hook and the write is the sandbox's to stop, as every shell command is | prevented: the sandbox, not the hooks, holds the files |
| Taking another agent's name to leave a policy rule, or to be read as that agent in a review | prevented: only a human names an agent (`session.start`); a child session has its parent's name (format 31) | prevented | prevented |
| Redrawing what a reviewer reads (escape sequences, carriage returns or bidi controls in an intent, a path, a file's lines or a denial's text) | prevented in Lonca's own output: `lonca` and `lonca-audit` write such characters out (`\u{1b}`, `\r`) instead of sending them to the terminal; JSON output escapes them as JSON does, so a program that shows it must do the same | prevented, as cooperative | prevented, as cooperative |
| Having another session answer for a connection (standing in its workspace), or making it answer too | no gain: every change waits for a human anyway | prevented for the first: a connection is charged by the processes it descends from, not where it stands. Detected for the second: a command that leaves its harness is charged to every session, its own among them, so it can taint and slow the others but not stay clean | prevented and detected, as hardened |
| Reaching a host that is not allowed through one that is (another server name or `Host` header at an address the allowed host shares) | possible: nothing holds the agent's network to the proxy, and every change waits for a human anyway | prevented for the TLS server name and for plain requests: the proxy ends a tunnel whose client asks for another name (a `misnamed_tunnel` security event), and answers 400 to a plain request for another host. Not seen: the `Host` header inside TLS (the allowed host's front end decides), an encrypted client hello's inner name, TLS begun later on a connection | prevented, as hardened |
| Using a session token outside where it was given | possible | possible (tokens are bearer tokens) | refused and detected, for reading the repository as for changing it: the request is answered `not_in_sandbox` and the session is tainted |
| Pushing an event out of the security log with a flood of others (lines that are no request, bad tokens) | prevented across kinds: the latest 256 events of each kind stay through every rotation, so a freeze or a taint is not lost under another kind's flood. Within one kind the older are lost: 257 refusals push out the first | prevented, as cooperative | prevented, as cooperative |
| Exhausting the daemon through the socket | bounded: connection, line, rate and byte limits | bounded | bounded |
| Keeping the proxy's connections (a request that never ends, tunnels that carry nothing) | bounded: 10 s for a request's head, 10 minutes for a silent tunnel, 256 at once; a session's own are held to `observation.max_connections`. A local process that keeps sending can still hold places, and what it opens is charged to every session it can not be told from | bounded | bounded |
| Filling the disk the log is on with files (proposals, previews) | bounded: a preview's files are removed with its answer; below 1 GiB free no caller's files are written, and the log goes on. A session can still take the disk down to that with proposals, each one an entry naming it; proposals are then refused until a human frees space | bounded | bounded |
| Filling the log, which keeps every entry (long text in an operation, refused submissions with no session, connections through the proxy) | bounded: an entry's operation takes 64 KiB at most, asked before it is signed; a denied submission that needs no session is not logged; a session's operations and its proxy connections are each held to `sessions.ops_per_minute`, which no policy can set above 6000 | bounded | bounded |

Cooperative mode is honest about what it is: it records and detects, and
every change waits for a person. It is right for trying Lonca and for work
where you watch every change. Hardened mode is what the boundary is for.
Isolated mode is the strongest, and the only full answer to prompt injection.

### Cooperative mode in detail

The daemon's key and a human's file key are files the agent's account can
read. Lonca's hooks refuse tools that touch them, but in this mode the hooks
are the agent's to edit, and nothing beneath them holds. Whoever holds the
daemon key can append entries the chain accepts. The auditor still replays
every decision, so a forged entry passes only if `decide()` would have
allowed it; but evidence (a build or test result) is recorded, not
recomputed, so it can be forged with the key. A human operation needs a
human signature, so with a key that proves presence the policy, approvals and keys
stay out of an agent's reach. A log rewritten after it was pushed no longer
extends the remote's copy.

### Hardened mode in detail

The installers create the daemon's system user, install root-owned binaries,
write Claude Code's managed settings (hooks only an administrator sets, each
blocking on failure, its sandbox required, network through Lonca's proxy) and
name the daemon's uid in a root-owned `daemon.toml`. The hook, the MCP server
and the CLI refuse to give a token to any other process on the socket, so a
daemon started by an agent gets nothing. The daemon reads the managed
settings when a session starts and grants `hooks_sandbox` only when they
hold ([Lonca with Claude Code](../guide/claude-code.md#how-much-is-proven)).

## Trust boundaries

- **The daemon's single writer.** Every write is decided, signed, appended to
  the log and only then applied. Nothing else writes the store; a ref that
  changes behind its back is restored, and a moved log or policy ref
  freezes the repository.
- **`decide()`** is a pure function of the log, the request, recorded
  evidence, time and the policy. It has no AI, network or randomness, so the
  auditor can replay it. Unknown operation types, scopes and paths are
  refused; a Cedar evaluation error denies.
- **The socket.** Every method names the credential it needs, and a method
  not in the table does not exist
  ([decisions](https://github.com/selcukgural/lonca/blob/main/docs/decisions.md#daemon-authentication)).
- **The operating system user** (hardened): the daemon, its store and its key
  belong to a user the developer's account can not write.
- **The sandbox** (isolated sessions and verification): Seatbelt on macOS,
  bubblewrap on Linux, reads and writes closed by default, network only
  through the proxy (agents) or none (verification).
- **The remote and its auditor.** `lonca push` carries the log; `lonca-audit
  verify` in CI replays it on a machine the agents never touched.

## What the auditor catches, and what it does not

`lonca-audit verify` replays every decision, recomputes every fact and merge
from the Git objects, follows every key switch and holds every ref to the
log. It catches an entry the rules would have denied, even one signed with
the daemon's own key, and a ref the log does not explain.

It does not catch:

- **A bug the daemon and the auditor share.** Both use the same `decide()`.
  An independent implementation is an open question
  (`docs/decisions.md`; [#18](https://github.com/selcukgural/lonca/issues/18)
  is closed).
- **False evidence.** Build and test results are recorded as the daemon saw
  them; a replay can not run them again.
- **Entries the rules allow, written by whoever holds the daemon key**, which
  in cooperative mode includes the agent (above).

## Known limits

### One account

- **Hardened makes going around Lonca harder and visible, not impossible.** A
  process started outside the harness, by the developer at an agent's request
  or one left running earlier, can still change the workspace or read outside
  content. What it writes is caught when proposed (`unobserved_write`
  escalates); what it reads is not seen.
- **A harness's own bugs** are outside Lonca. Claude Code is the harness
  whose guarantees are checked in every release; Codex, Gemini CLI and
  OpenCode can not lock their hooks and stay `unobserved`, and reach
  `isolated` with `lonca run`
  ([decisions](https://github.com/selcukgural/lonca/blob/main/docs/decisions.md#harness-levels)).
  Whether `allowManagedHooksOnly` also blocks hooks given with `--settings`
  is not measured yet.
- **The harness name is a human's word.** The level is read from the
  managed settings of the harness the human named at `session start
  --harness`. The daemon can not see what runs with the token: a person who
  names one harness and starts another gets the level of the first.
- **sudo.** An admin account whose sudo asks for no password, or still holds
  a cached password for a process the agent shares, has no boundary at all.
  The hook tries `sudo -n true` when the harness starts and a session that
  succeeds is `unobserved`; a level never rises after that first report.
  Claude Code's tool shells have no controlling terminal, so they can not
  use a cache the developer's terminal holds (measured on Linux,
  [decisions](https://github.com/selcukgural/lonca/blob/main/docs/decisions.md#hardened-mode-in-the-field-10)).
- **Hardened mode has been installed for real on Linux only.** The macOS
  installer writes managed settings that every Claude Code session on the
  machine reads, so its field test waits for a machine set aside for it.

### Humans and approvals

- **Presence on Linux needs a security key.** A FIDO security key signs
  through OpenSSH (`lonca human keygen --security-key`) and proves presence
  there. Without one, a hardened repository on Linux is initialised
  `--without-presence`, and a human's file key is readable by the agents
  running as that human.
- **A security key shows nothing.** Touch ID names the operation in its
  dialog; a security key only blinks, and what the touch approves is the
  line `lonca` prints before it. A process running as the human that asks
  for a signature at the moment a touch is expected can have its own
  request touched instead. The signature still covers one operation, the
  daemon logs it, and it can not be replayed.
- **A kind of key is a claim.** The log records `p256-se` or `sk-p256` as
  the enrolling human named it, and checks the device's "user present"
  flag on a security key's signatures; it does not check an attestation
  that the key lives in hardware. Whoever enrolls a software key under
  those names has lied to their own repository.
- **Security keys were verified against OpenSSH, not yet against a
  device.** The verifier agrees with `ssh-keygen -Y verify` of OpenSSH
  10.5 on signatures in the security-key format; signing with a physical
  key through `lonca` has not been exercised by the project yet.
- **A two-signature rule is not a two-person rule.** An operation that
  waits for approval (`[approvals] policy_updates` above 1, an `@escalate`
  on a human's operation) is released by `approve` signatures, and the one
  who asked for it may give one: only a second approval by the same human
  is refused (`already_approved`). It asks for a second, deliberate
  signature, with presence where the policy requires it; it does not show
  that two people agreed. The count is capped at the number of enrolled
  humans; a signature plus a waiting period for a single developer is
  [#19](https://github.com/selcukgural/lonca/issues/19).
- **The recovery key** can replace the human's key, and with a copy of the
  log re-anchor that copy on a daemon of its own. Keep it off the machine and
  replace it after use ([Recovery](../guide/recovery.md)).
- **A human session file** is readable by anything running as the
  developer. A session can read, prepare and run the queue, never sign, and
  lasts an hour by default.

### Isolated sessions

- **A session token is a bearer token.** For an isolated session the daemon
  asks the operating system whether the caller is in a sandbox; that shows a
  sandbox, not this one. It ends the plain cases (a token left in a file, a
  helper started outside by accident).
- **On macOS a chain of processes that each fork and exit at once** can
  outlive the sweep at the end of a run. Such a process holds a dead token,
  and a later run refuses the workspace it can still write. If the launcher
  itself is killed, nothing sweeps.
- **`sandbox_check` is not a public macOS API**, and `sandbox-exec` is
  deprecated. Both fail closed: if either goes away, isolated sessions stop
  working and say so. Whether a hardened daemon may ask about another user's
  process is not measured; that also fails closed.

### Verification

- **Limits hold per process, and the machine keeps a share.** A command is
  stopped when the disk of the stores falls below `keep_free_bytes`, a look
  every 20 ms that a burst of preallocation can outrun; the account keeps 256
  processes whatever a command forks; on Linux the kernel ends the command
  before the daemon when memory runs out. Memory as a whole and the processes
  up to that share are bounded only by `timeout_seconds`, so a hostile test
  can still keep the machine busy until then
  ([Verification](../guide/verification.md#limits)). Run verification only
  for build and test commands you would run yourself.
- **Tests are code.** A tainted session can not touch build scripts, CI or
  lockfiles, but a repository's own tests run as written, without network.

### The repository

- **Redaction is logical.** The daemon withholds a blob, but the object stays
  in Git history and in remotes that already have it
  ([#22](https://github.com/selcukgural/lonca/issues/22)).
- **Git object ids are SHA-1.** The log rests on SHA-256 and Ed25519, and the
  auditor recomputes from the objects it is given
  ([Cryptography](../crypto.md#algorithms)).
- **One machine.** One daemon per machine, one sequencer per repository; a
  team server with remote authentication is
  [#20](https://github.com/selcukgural/lonca/issues/20).
- **The daemon key is a file** on every platform; no keychain, Secure Enclave
  or TPM holds it yet.

## Out of scope

- root, the kernel, firmware and anyone with physical access;
- an administrator who knowingly types their password for an agent;
- the security of Git hosts, model providers and the harnesses themselves;
- secrets outside Lonca's sandboxes: in cooperative and hardened mode the
  agent reads what the developer's account reads, unless the harness's own
  sandbox closes it.

No one outside has reviewed Lonca yet; an external review of the trusted core
before 1.0 is [#23](https://github.com/selcukgural/lonca/issues/23). To
report a vulnerability, see
[SECURITY.md](https://github.com/selcukgural/lonca/blob/main/SECURITY.md).
