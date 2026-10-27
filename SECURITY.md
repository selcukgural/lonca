# Security policy

Lonca is an early prototype (v0.1). Security fixes go to the latest commit
on `main`; there are no maintained release branches yet.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a
security problem.

Report it privately through GitHub instead:
[Report a vulnerability](https://github.com/selcukgural/lonca/security/advisories/new)
(the repository's Security tab → "Report a vulnerability").

Include what you can of:

- the affected crate and commit,
- what an attacker can do and under which conditions (for example a
  compromised agent, a local user, or a network peer),
- steps or a test that reproduces it.

You should get an answer within a week. Once a fix is ready, it is
published together with a GitHub security advisory that credits you,
unless you would rather stay anonymous.

## Scope

Of particular interest are anything that lets an agent get around the
gatekeeper or `decide()`, writes that skip the operation log, changes to
the log that the auditor does not catch, session-token leaks, and escapes
from the sandbox or the hardened mode.
