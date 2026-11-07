# Verification: build and test commands

The merge queue runs the repository's build and test commands on the
merged tree, in a sandbox, and records the results as evidence in the
operation log. The commands and their environment come from
`[verification]` in `lonca.toml` (the signed policy), so a change to
them is a policy change.

```toml
[verification]
build = "cargo build --offline"
test = "cargo test --offline"
required = true
require_sandbox = false
timeout_seconds = 900
retries = 0
env_passthrough = ["HOME", "CARGO_HOME", "RUSTUP_HOME"]
env = { CARGO_NET_OFFLINE = "true" }
read = ["~/.cargo/registry", "~/.cargo/bin", "~/.rustup"]
```

## A change that reaches other code

`on_signature_change` is a command for what is too slow to run for every
change. The queue adds it for a change that alters a signature, or that
renames or deletes something other code mentions, and for a batch with
such a change in it:

```toml
on_signature_change = "cargo test --offline --workspace --all-features"
```

Its result is the check `extended`. It fails a change like `build` and
`test` do, and with `required = true` a change that owes it can not land
without a pass.

## The environment the commands see

The verifier clears the environment and sets:

- `PATH`: the daemon's own.
- `HOME`: a fresh, empty directory inside the work directory (writable).
- `LANG=C.UTF-8`, `LONCA_VERIFY=1`.

Nothing else, unless the policy says so:

- `env_passthrough`: names copied from the daemon's environment at run
  time; a name the daemon does not have is skipped. Note that `HOME` in
  the list replaces the scratch home with the daemon user's real home
  (in hardened mode that is `_lonca`'s home, not yours).
- `env`: fixed values.

Deny by default: a name not listed does not pass. Names that could
change *what* runs or where code is loaded from are refused when the
policy is set (`lonca.toml: verification: env_forbidden:NAME`): `PATH`,
`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `RUSTC`, `RUSTC_WRAPPER`,
`RUSTFLAGS`, `CARGO_BUILD_RUSTC*`, `CARGO_TARGET_*_RUNNER|LINKER`,
`NODE_OPTIONS`, `NODE_PATH`, `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5OPT`,
`RUBYOPT`, `GOFLAGS`, `GIT_*`, `BASH_ENV`, `ENV`, `SHELLOPTS`, `IFS`,
`LONCA_*`.

Every check's log starts with the sandbox and the names that were set
(never a value), so a failure explains itself:

```
lonca verify: sandbox seatbelt, env PATH HOME TMPDIR LANG LONCA_VERIFY CARGO_HOME RUSTUP_HOME
```

## The sandbox

macOS: Seatbelt (`sandbox-exec`); Linux: bubblewrap when installed;
else none (`require_sandbox = true` refuses a change verified without one,
with `unsandboxed_verification`, and a hardened daemon does not start
without a sandbox; see [profiles.md](profiles.md)).

A change's tests are the agent's code, so they run in the same sandbox as
`lonca run` (`docs/guide/runners.md`), with no way out at all: no network,
no socket. They write only the tree, a scratch `HOME` and `TMPDIR`. They read
the system's directories and those on `PATH`. **Everything else is closed,
your home directory included**, until the policy names it:

```toml
read = ["~/.cargo/registry", "~/.cargo/bin", "~/.rustup", "/opt/toolchain"]
```

Paths are absolute, or `~/path` for the home of the daemon's user. A directory
passed through `env_passthrough` opens the same way, so `CARGO_HOME=/opt/cargo`
needs no line here; `HOME` does not, since that would open everything in it.
What holds or lies in Lonca's stores stays closed whatever is named, and a path
that does not exist is passed over. `TMPDIR` is always the sandbox's own.

Name what a build needs and no more. `~/.cargo` as a whole also opens
`~/.cargo/credentials.toml` to the code under test.

So a build must find its toolchain in what it can read, and must write only
under the tree or `TMPDIR`. Caches it would write to (`~/.cargo/registry`,
`~/.npm`, `GOCACHE`) are read-only inside the sandbox: warm them outside (run
the build once as the daemon's user), build offline, or point the cache at the
scratch home (see below).

## Starters

**Rust (rustup).** `cargo` under rustup needs `HOME`, `RUSTUP_HOME` and
`CARGO_HOME` to pick a toolchain; without them it fails at once with
"could not choose a version of cargo". Dependencies must be in the
registry cache already (`cargo fetch` outside the sandbox) because the
sandbox has no network.

```toml
build = "cargo build --offline"
test = "cargo test --offline"
env_passthrough = ["HOME", "CARGO_HOME", "RUSTUP_HOME", "RUSTUP_TOOLCHAIN"]
read = ["~/.cargo/registry", "~/.cargo/bin", "~/.rustup"]
```

**Node.** `npm`/`pnpm` read `~/.npmrc` and write to `~/.npm`; install
dependencies outside (`npm ci`) and commit the lock file; run the
scripts offline.

```toml
build = "npm run build --offline"
test = "npm test --offline"
env_passthrough = ["HOME", "NODE_ENV"]
read = ["~/.npmrc", "~/.npm", "~/.nvm"]
```

**Go.** The module cache (`GOMODCACHE`) and build cache (`GOCACHE`) are
read-only in the sandbox; fill them outside (`go mod download`) and set
`GOFLAGS=-mod=mod` is refused (it changes what runs), so use
`-mod=readonly` on the command line.

```toml
build = "go build -mod=readonly ./..."
test = "go test -mod=readonly ./..."
env_passthrough = ["HOME", "GOPATH", "GOMODCACHE", "GOCACHE", "GOROOT"]
```

**Python.** A virtualenv inside the repository is readable; its
interpreter and packages are what runs. `PYTHONPATH` is refused;
activate by path.

```toml
test = ".venv/bin/python -m pytest -q"
env_passthrough = ["HOME", "VIRTUAL_ENV"]
env = { PYTHONDONTWRITEBYTECODE = "1" }
```

## Reading a failure

`lonca change CHANGE --evidence` prints each check with its result,
exit code, duration, sandbox and the tail of its log; the MCP
`change_status` tool gives a worker the same. The first line of the
log is the environment header above.
