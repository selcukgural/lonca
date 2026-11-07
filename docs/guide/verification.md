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

- `PATH`: the daemon's own, or `path` from the policy, a list of absolute
  directories, which must then hold everything the commands call:
  `path = ["/usr/local/bin", "/usr/bin", "/bin"]`.
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

## How a command ends

A command that runs out of `timeout_seconds` is an error with the evidence
`error = timeout`, and the queue goes on with the next change. What a command
leaves running ends with it, whichever way it ends, as far as this reaches:

- It starts as a session of its own, and its process group is killed when the
  command exits or runs out of time. So start what a test needs in the test,
  and end it there. As the leader of that session, a program the command runs
  directly can not move to a process group of its own: `setpgid` gets `EPERM`.
- Under bubblewrap the sandbox goes with the command and takes all of it.
- Under Seatbelt what left the group is found by its sandbox and ended too. If
  something of it would not end, the evidence says `left_running`, and the check
  is an error even if the command exited 0.
- With no sandbox, a process that left the group can not be reached. It holds
  nothing up: output is read for one more second, and the result is the
  command's own. This is one more reason for `require_sandbox`.

If the daemon itself is killed, a command under bubblewrap goes with it. Under
Seatbelt or with no sandbox it runs on to its own end, with nothing timing it;
the change is verified again when the daemon is back.

The log keeps the last 64 KiB of stdout and stderr, as they were written. If
the command itself is killed by a signal, the evidence has `exit = signal` and
the number in `signal`. Under bubblewrap it has the exit code 128 + that number
instead. A process further down shows only in what the command makes of it: a
limit that ends a compiler reads as the build's own failure, so look in the log.

## Limits

```toml
limit_cpu_seconds = 0           # RLIMIT_CPU
limit_address_bytes = 0         # RLIMIT_AS, Linux only
limit_processes = 16384         # RLIMIT_NPROC, Linux only
limit_file_bytes = 8589934592   # RLIMIT_FSIZE
limit_open_files = 4096         # RLIMIT_NOFILE
```

`0` means no limit. A limit the daemon runs under already is never raised.

- CPU time, address space, file size and open files hold for each process, not
  for a command as a whole. The only limit on the whole is `timeout_seconds`.
- `limit_cpu_seconds` adds up all the threads of a process, so a test run on 32
  cores uses an hour of it in two minutes. That is why it is off. Past it Linux
  kills a process. macOS sends `SIGXCPU`, which ends it unless it handles that,
  and then only `timeout_seconds` does.
- `limit_file_bytes`: past it the writer gets `SIGXFSZ`, which ends it. One that
  ignores the signal gets `EFBIG`, "File too large", from the write.
- `limit_processes` counts every process and thread of the account, not of the
  command, so set it above what the daemon's user runs anyway. A fork past it
  fails with `EAGAIN`; root is not held to it. It is not applied on macOS, where
  the daemon usually shares the account of the person at the machine.
- `limit_address_bytes` is off because runtimes reserve far more than they use:
  the JVM, Go and Node fail under any figure that stops anything. macOS refuses
  every figure below what a process maps at its start, so it is not applied
  there.

## Quota

```toml
[quota]
session_seconds = 0   # per session, with those made from it or continuing it
day_seconds = 0       # per repository and UTC day
```

`0` means no limit. What counts is the time a check ran by the clock, every
attempt of a retried one, as `duration_ms` in the log; a check the cache
answered costs nothing, a failed one costs what it took. A batch's run is
shared by its changes.

Past a quota a proposal is denied with `verification_quota:session` or
`verification_quota:day`, and a change the session queued before is rejected
without running its checks. While a change's checks run, its agent can not
withdraw it (`verifying`). The run that crosses the quota finishes. `lonca
status --json` shows what each session has used (`verification_ms`) and what
the day has (`verification_day_ms`). A human raises a quota with a policy
update; a day spent by agents also stops a human's proposals until then.

## Shared leases

```toml
[leases]
shared = true

[verification]
required = true
test = "cargo test --offline"
```

With these, an agent may lease a symbol with the kind `shared` (`lonca lease
acquire path#Type.method --kind shared`), and other agents may hold it
`shared` too. `edit` and `rename` stay exclusive: they meet every `shared`
holder, and a `shared` lease meets them. A `shared` lease covers changes to
the body; a change of the signature needs `edit`. `leases.shared` is refused
without `required = true` and a `build` or `test` command, and a `shared` item
is refused (`shared_off`) where the policy does not have it.

When two holders change the same function, the second to integrate is merged
line by line with the first: lines both changed, or lines next to each other,
are a conflict naming the function, and so is a result that does not parse.
A change on trunk since its base made under any other kind (or by a human,
or imported) is not joined with. The checks run on the merged tree, and they
are what makes this safe: two changes that touch different lines can still
break each other.

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
