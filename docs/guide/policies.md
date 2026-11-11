# Writing policies

A repository's rules are two files on `refs/lonca/policy`: `lonca.toml`
(limits and switches, commented where it ships) and `policy.cedar`, rules
in [Cedar](https://www.cedarpolicy.com/) with a few annotations of
Lonca's. This page is about `policy.cedar`: what a rule can see, what it
can do, and how to try one before it is in force. Where a repository's
first rules come from: [Profiles](profiles.md).

## The round trip

```sh
lonca policy show --repo demo              # both files as they are in force
# copy them into lonca.toml and policy.cedar, edit
lonca policy check --repo demo --policy policy.cedar
lonca policy set --repo demo --config lonca.toml --policy policy.cedar
```

`lonca policy check` writes nothing. It parses the files, then decides
every entry of the log again with them and lists the decisions that would
come out different:

```
   41 change.propose    agent:claude/s-7f3a
      was    allow
      would  escalate policy:charge-needs-review, approvals=1
1 of 212 entries would be decided differently
```

Give `--config`, `--policy` or both; a file left out is taken from the
policy in force. `--json` prints the same as `{entries, differences,
lockouts}`. A file that does not parse is refused with Cedar's message
(exit code 3).

Each entry is decided alone, on the state the log really had before it.
The check does not follow consequences: a change the new policy would have
denied is still integrated when the entries after it are decided. Read the
list as "these requests would have been treated differently", not as an
alternative history.

`lonca policy set` signs a `policy.update`. It takes as many humans as
`[approvals] policy_updates` of the policy in force says, the one who sets
it included (above 1, the others approve it), and it can be undone
(`lonca undo <seq>`), which is a `policy.update` too.

## How a request meets the rules

Lonca decides in three steps, and Cedar is the last:

1. **Who may ask at all.** Signatures, enrolled humans, live sessions, the
   operations a session was granted. No rule changes these.
2. **Per-operation checks.** Scope, leases, the claim against the facts,
   evidence, and the built-in escalations: a tainted or unobserved
   session's change, a critical path, weakened tests, a write nobody
   observed. They are set in `lonca.toml`, not here.
3. **Cedar.** Each request a human or an agent makes is evaluated once,
   under the operation's name. A `change.propose` is evaluated once per
   file it adds, modifies or deletes (`file.add`, `file.modify`,
   `file.delete`, with the file's path) and once as `change.propose` with
   numbers about the whole change. The daemon's own entries (integrations,
   observations, taints) are not evaluated.

A rule can refuse or escalate what steps 1 and 2 let through; it can not
let through what they refuse. Across everything a request meets, a denial
wins over an escalation, and an escalation over an allow.

## What a rule sees

**Principal.** `Lonca::Human::"<name>"` for an enrolled human,
`Lonca::Agent::"<agent>"` for an agent, named as at `lonca session start
--agent`. A child session (`cap.attenuate`) has its parent's name, so a
rule on a name holds for every session made from that agent's. There are
no groups and no attributes on them: `principal in`
matches nothing, so list names (`principal == Lonca::Agent::"claude"`) or
use the type (`principal is Lonca::Agent`).

**Action.** `Lonca::Action::"<name>"`:

| Who asks | Actions |
|---|---|
| per file of a change, anyone | `file.add`, `file.modify`, `file.delete` |
| agents | `change.propose`, `change.withdraw`, `lease.acquire`, `lease.release`, `lease.renew`, `lease.interest`, `negotiate`, `cap.attenuate`, `cap.revoke`, `session.end` |
| humans | `change.propose`, `change.withdraw`, `lease.release`, `session.start`, `session.isolate`, `session.end`, `cap.revoke`, `approve`, `reject`, `policy.update`, `freeze`, `unfreeze`, `redact`, `import.external`, `bridge.push`, `human.enroll`, `human.rotate`, `human.revoke`, `human.recovery_key`, `human.recover`, `daemon.rotate`, `daemon.recover` |

**Resource.** Always `Lonca::Repo::"repo"`; leave it as `resource`.

**Context.** Every request has:

| Key | Type | What it is |
|---|---|---|
| `tainted` | Bool | the session is tainted (content from outside entered it); false for a human |
| `observation` | String | `"unobserved"`, `"hooks"`, `"hookssandbox"`, `"isolated"`; `"none"` for a human |
| `task` | String | the session's `--task`, `""` without one or for a human |

`file.add`, `file.modify` and `file.delete` add:

| Key | Type | What it is |
|---|---|---|
| `path` | String | the file, relative to the repository root |

`change.propose` adds:

| Key | Type | What it is |
|---|---|---|
| `files` | Long | files the change touches |
| `lines` | Long | lines added plus lines removed |
| `critical` | Bool | it touches a path of `[paths] critical` |
| `symbols` | Set of String | the symbols it edits, adds or deletes, as `path#Name`, with a bare id too where a name has a key (`src/a.rs#C.M` beside `src/a.rs#C.M(int)`) |
| `signature_changes` | Long | symbols whose signature it changes |
| `affects_others` | Bool | another session holds a lease on something it affects |
| `recent_reverts` | Long | reverts of the same symbols within `[reverts] window_minutes` |
| `is_revert` | Bool | the change reverts another |
| `tests_deleted`, `tests_skipped` | Long | tests the change deletes or skips |

A key that a request does not have is an error, and an error denies (see
below). A rule that reads `context.path` must therefore be limited to the
`file.*` actions in its scope, or test `context has path` first.

## What a rule does

```cedar
// Lonca's annotations: @id names the rule in reasons, @escalate turns a
// forbid into a wait for humans, @approvals says how many.
@id("lockfiles-need-two")
@escalate("dependencies")
@approvals("2")
forbid(principal is Lonca::Agent, action in [Lonca::Action::"file.add", Lonca::Action::"file.modify", Lonca::Action::"file.delete"], resource)
when { context.path like "*Cargo.lock" || context.path like "*package-lock.json" };
```

- **`permit`** lets a request through this step; with no `permit` that
  matches, the request is denied with `policy_default_deny:<action>`. The
  cooperative profile opens with `permit(principal, action, resource);`
  and forbids what it must; the hardened one lists what agents may do.
- **`forbid`** denies, with the reason `policy:<id>`. Give every rule an
  `@id`: without one, the reason is Cedar's own name for it
  (`policy:policy2`), which moves when a rule is added above.
- **`@escalate("<label>")`** on a `forbid` makes the request wait for
  human approval instead (`lonca pending`, `lonca approve`). The label is
  for the reader; the reason is still `policy:<id>`. When a denying rule
  and an escalating rule both match, the request is denied.
- **`@approvals("N")`**, `N` from 1 to 9, sets how many humans must
  approve; the largest of the matching rules counts. With fewer enrolled
  humans, all of them are enough while `[approvals]
  cap_to_enrolled_humans` is on (the reasons then say `approvals_capped`).
  Anything else is refused when the policy is parsed.
- **Errors deny.** Cedar skips a rule that fails to evaluate; for a
  `forbid` that would mean "allow", so Lonca denies the request instead,
  with `policy_error:…`. A wrong type, a missing context key or an
  overflow all count.

`like` takes `*` for any run of characters, `/` included: `"auth/*"`
matches `auth/a.rs` and `auth/x/b.rs`, not `src/auth/a.rs`.

## Examples

Keep agents out of a directory altogether:

```cedar
@id("no-agents-in-infra")
forbid(principal is Lonca::Agent, action in [Lonca::Action::"file.add", Lonca::Action::"file.modify", Lonca::Action::"file.delete"], resource)
when { context.path like "infra/*" };
```

A function that needs a human, wherever the change comes from:

```cedar
@id("charge-needs-review")
@escalate("payments")
forbid(principal is Lonca::Agent, action == Lonca::Action::"change.propose", resource)
when { context.symbols.contains("src/billing.rs#charge") };
```

Only a sandboxed session may touch authentication code (see
[Running agents](runners.md) for the levels):

```cedar
@id("auth-in-a-sandbox")
forbid(principal is Lonca::Agent, action == Lonca::Action::"file.modify", resource)
when { context.path like "src/auth/*" && context.observation != "isolated" };
```

A tainted session may not propose anything large, and an unobserved one
may not delete files:

```cedar
@id("tainted-stays-small")
forbid(principal is Lonca::Agent, action == Lonca::Action::"change.propose", resource)
when { context.tainted && (context.files > 5 || context.lines > 200) };

@id("unobserved-deletes-nothing")
forbid(principal is Lonca::Agent, action == Lonca::Action::"file.delete", resource)
when { context.observation == "unobserved" };
```

Agents add migrations but never delete or rewrite one that exists (the
directory's keys are in `[paths.keyed]`, see
[Keyed directories](concepts.md#keyed-directories)):

```cedar
@id("migrations-stay")
forbid(principal is Lonca::Agent, action in [Lonca::Action::"file.modify", Lonca::Action::"file.delete"], resource)
when { context.path like "db/migration/*" };
```

Deleted tests are refused instead of escalated (Lonca escalates them on
its own):

```cedar
@id("tests-stay")
forbid(principal is Lonca::Agent, action == Lonca::Action::"change.propose", resource)
when { context.tests_deleted > 0 || context.tests_skipped > 0 };
```

One agent may only work on the task it was started for:

```cedar
@id("docs-bot-on-docs")
forbid(principal == Lonca::Agent::"docs-bot", action in [Lonca::Action::"file.add", Lonca::Action::"file.modify", Lonca::Action::"file.delete"], resource)
when { !(context.path like "docs/*") };
```

## Do not lock yourself out

Humans are evaluated too, and the way back from a bad policy is a
`policy.update`. A policy that denies humans `policy.update` can not be
changed back, and one that denies `unfreeze`, `approve` or the key
operations can leave a repository stuck. `lonca policy check` warns of
each such action it would deny an enrolled human:

```
warning: human:ayse could no longer request policy.update (policy_default_deny:policy.update)
```

Escalate these instead of denying them, and keep a `permit` for humans
(the hardened profile has `permit(principal is Lonca::Human, action,
resource);`). A rule that reads a context key on every action, such as
`forbid(principal, action, resource) when { context.path like "x/*" };`,
denies every request that has no path, `policy.update` included: the
check reports it as a `policy_error`.
