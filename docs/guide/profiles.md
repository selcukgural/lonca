# Profiles: what a repository starts from

`lonca init` writes a repository's first policy (`lonca.toml` and
`policy.cedar`, on `refs/lonca/policy`) from a profile:

```sh
lonca init demo                       # the install's own profile
lonca init demo --profile cooperative
lonca init demo --profile hardened
```

On a hardened install a repository starts hardened. Everywhere else it starts
cooperative. A profile is only where a repository starts: afterwards the policy
is what the log says, and a human changes it with `lonca policy set`
([Writing policies](policies.md)).

| Setting | Cooperative | Hardened | What it protects against |
|---|---|---|---|
| `approvals.require_presence` | `false` | `true` | Anything running as you, agents included, signing with a file key. |
| `verification.required` | `false` | `true` | A change landing without the checks you configured. |
| `verification.require_sandbox` | `false` | `true` | A change landing on evidence from commands run with your account's reach. |
| `observation.network` | `"taint"` | `"deny"` | Sandboxed commands reaching a host nobody named. |
| `policy.cedar` | a blanket `permit` plus rules that forbid | agents get a list, plus the same rules | An action nobody thought of, including one a later version adds. |

Cooperative trusts the account you work in: it records and detects. Hardened is
what the boundary of a hardened install is for. The profile by itself draws no
boundary: on a cooperative daemon it tightens the rules, and an agent running as
you can still reach the daemon's files. What each mode prevents
and what it only detects is the [threat model](../security/threat-model.md).

## After a hardened init

- **Set the commands.** `verification.required` asks for the commands the policy
  names, and a new repository names none. Until `build` or `test` is set nothing
  runs; `status` and `lonca doctor` say so. See [verification.md](verification.md).
- **Name your agent's hosts.** With `network = "deny"`, a harness that talks to its
  model through the proxy needs that host in `observation.agent_hosts`.

## Presence

A hardened repository accepts human signatures only from a key that proves
presence: a Secure Enclave key on a Mac, or a FIDO security key anywhere
OpenSSH can use one (Linux included):

```sh
lonca human keygen <name> --secure-enclave   # Touch ID or the password
lonca human keygen <name> --security-key     # a touch on the key
```

A security key signs through `ssh-keygen` (OpenSSH 8.2 or later, built with
FIDO support; `LONCA_SSH_KEYGEN` names another one, such as Homebrew's on a
Mac). `--security-key` makes an ECDSA credential, which every FIDO and U2F
key has; `--security-key ed25519` asks for Ed25519, on FIDO2 keys that have
it. The file `<name>.sk` next to your other keys is the credential's handle:
it signs nothing without the device. The key only blinks, so `lonca` prints
what the touch is for on the line before; a key made with OpenSSH's
`no-touch-required` signs nothing here. `lonca doctor` says under
`presence` what your key proves and what this machine could use.

`lonca init` refuses a file key here, because the repository's first entry would
lock that key out of everything after it, the policy update that could undo it
included. On a machine with neither kind of key, say so:

```sh
lonca init demo --without-presence
```

That leaves `require_presence` off and the rest of the profile on, and `status` and
`lonca doctor` go on reporting it.

## What a hardened install checks

`lonca status` prints `BELOW HARDENED` and `lonca doctor` warns for each repository
that falls short of the table above. A cooperative install says nothing, since those
are its defaults. `doctor` on a hardened install also fails with no sandbox and warns
about a sudo that asks for no password.

A hardened daemon does not start without a sandbox. `lonca daemon --allow-unsandboxed`
starts it anyway, says so at each start, and verification then runs with no sandbox;
in a repository with `require_sandbox = true` its changes end in
`unsandboxed_verification`. The Linux installer takes the same flag and writes it into
the service.
