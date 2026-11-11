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
identify = ["rustc --version", "cargo --version"]
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

## Checks a change owes by name

`checks` names commands that run only for a change that owes them. A human
names them when approving (`lonca approve SEQ --also api,e2e`), or the policy
does for the paths a change touches:

```toml
checks = { api = "cargo test --offline -p api", e2e = "npm run e2e" }
checks_by_path = { "api/**" = ["api"] }
```

They run after `build`, `test` and `on_signature_change`, in name order, with
the same sandbox, environment, limits and timeout, and their evidence is the
check `named` with the name in `details.name`. A check a change owes must pass
even with `required = false`: someone asked for it. A failure rejects the
change with `verification_failed:<name>` and the output tail, like a failed
test. Only names in `checks` can be asked for (`unknown_check:<name>`), and an
agent can not ask for any: approving is a human's signature. Names are
`[a-z0-9_-]`, at most 32 characters, and not a built-in check's word (`build`,
`tests`, ...).

What a change will run is in `status` (`changes[].runs`, `pending[].runs`) and
`change.get` before anyone says yes; `checks` lists what humans asked for. A
later version of the change still owes them.

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

**What the commands can read, the agent that proposed the change can
read.** The commands are the change's own code (its tests, its build
script), and their output is the check's log: a blob in the store that the
agent reads back (`lonca status`, `change_status`) and that `lonca push`
carries to the remote. Lonca writes `***` over a value of `env_passthrough`
that turns up in a log as it is (a directory, such as `HOME`, is left
readable), which catches what a tool prints by accident. It can not catch
a command that means to tell: a test may print a token backwards, or the
content of a file under `read`. So pass and open nothing an agent may not
see: no registry token in `env_passthrough`, no `~/.npmrc` or
`~/.cargo/credentials.toml` under `read`. Install dependencies before, as
yourself, and let the checks run offline on what is there.

## The environment the evidence names

A check's result is only worth as much as the environment it ran in: a
pass with one compiler says little of another. Evidence is recorded and
never run again, so it says what produced it. Each check's evidence
carries `env`, a digest of:

- the sandbox and the check's command;
- the commands' `PATH` and the policy's `env` names and values;
- the names of `env_passthrough` the daemon had, never their values (they
  may be secrets);
- each `identify` command, how it ended, and what it printed.

`identify` lists commands whose output names the toolchain, from the
signed policy like the checks:

```toml
[verification]
# Rust: rust-toolchain.toml in the tree picks the toolchain, and the
# commands run in the tree, so this is the one the checks use.
identify = ["rustc --version", "cargo --version"]
# Node:
# identify = ["node --version", "npm --version"]
# A runner whose tools come from an image, run as CI runs it: the image
# writes its digest into a file the commands may read.
# identify = ["cat /etc/ci-image-digest"]
```

They run once per verification, before the checks, in the same sandbox,
directory, environment and `PATH`, for at most 10 seconds each (or
`timeout_seconds`, if that is shorter). At most 8, each at most 1024
bytes. Only the first 4 KiB of what one prints counts, for the digest and
for the line: a toolchain names itself at the start. One that fails or
times out does not fail the checks: the evidence says how it ended. A value passed through never reaches the evidence: where
an identify command prints one, it stands as `***` in both the digest and
the lines. Do not name a command that prints a secret of its own.

Each check's `details` also keep what a person reads: the command, the
first line of its output (200 characters at most, control characters as
`?`), and how it failed, if it did:

```
env.0.command = "rustc --version"
env.0.output  = "rustc 1.91.0 (f8297e351 2025-10-28)"
env.1.command = "node --version"
env.1.output  = ""
env.1.error   = "exit 127"
```

The same command in the same environment gives the same `env`; a new
compiler, another `PATH` or another fixed value gives another.
`lonca-audit verify` notes every check whose `env` differs from the last
time it ran (`env  12 tests  changed since 7`), and `lonca change CHANGE
--evidence` prints it. A note, not a finding: a new toolchain is no fault,
but a reviewer can see when one came in, and whether the queue ran what CI
runs. Evidence from before `identify` (0.2.x) digests the sandbox and the
command only, so the first integration after an upgrade is noted once.

Running the checks inside a container image is not Lonca's to do: a runner
that wants CI's image makes `build` and `test` run inside it, and
`identify` says which image it was.

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
Seatbelt or with no sandbox it runs on, with nothing timing it, until the
daemon starts again: then, before it verifies anything, the daemon ends what
an earlier run left in its sandboxes and removes their directories, and the
change is verified again. Only the daemon that holds the lock on its home
(`daemon.lock`) does this: a second daemon on the same home says so and
leaves them. The hardened install's launchd job restarts the
daemon on its own. With no sandbox nothing tells which processes were the
command's, so only the directories go.

The log keeps the last 64 KiB of stdout and stderr, as they were written. If
the command itself is killed by a signal, the evidence has `exit = signal` and
the number in `signal`. Under bubblewrap it has the exit code 128 + that number
instead. A process further down shows only in what the command makes of it: a
limit that ends a compiler reads as the build's own failure, so look in the log.

## Limits

```toml
limit_cpu_seconds = 0           # RLIMIT_CPU
limit_address_bytes = 0         # RLIMIT_AS, Linux only
limit_processes = 16384         # RLIMIT_NPROC
limit_file_bytes = 8589934592   # RLIMIT_FSIZE
limit_open_files = 4096         # RLIMIT_NOFILE
keep_free_bytes = 1073741824    # free space the disk keeps
```

`0` means no limit. A limit the daemon runs under already is never raised.

- CPU time, address space, file size and open files hold for each process, not
  for a command as a whole. What holds the whole is `timeout_seconds` and
  `keep_free_bytes`.
- `limit_cpu_seconds` adds up all the threads of a process, so a test run on 32
  cores uses an hour of it in two minutes. That is why it is off. Past it Linux
  kills a process. macOS sends `SIGXCPU`, which ends it unless it handles that,
  and then only `timeout_seconds` does.
- `limit_file_bytes`: past it the writer gets `SIGXFSZ`, which ends it. One that
  ignores the signal gets `EFBIG`, "File too large", from the write.
- `limit_processes` counts every process of the account (on Linux every
  thread), not of the command, so set it above what the daemon's user runs
  anyway. Whatever it says, the account keeps 256 processes of the most it
  may have: its own limit, and on macOS `kern.maxprocperuid` too. So a command
  that forks without end can not take the last of them from the person at the
  machine, or from the daemon. A fork past it fails with `EAGAIN`; root is not
  held to it.
- `keep_free_bytes`: the disk the command writes to, the one of the daemon's
  stores and their logs, should keep this much free. The verifier looks at it
  every 20 ms while the command runs; below it the command is stopped and the
  check is an error with `error = disk_space`, and a command does not start on
  a disk that is below it already. It holds the command as a whole, all its
  files together, and its `/tmp` and `/dev/shm`: under bubblewrap those are
  directories of the run on that disk, not memory, and the rest of `/dev` is
  read-only. It is a look, not a quota: a command that preallocates large
  files in parallel (`fallocate`) can take more than the margin between two
  looks. With no sandbox a command can write anywhere, and only that disk is
  watched. A run's directory is removed when it ends, also what the command
  closed with `chmod` or, on macOS, `chflags`.
- `limit_address_bytes` is off because runtimes reserve far more than they use:
  the JVM, Go and Node fail under any figure that stops anything. macOS refuses
  every figure below what a process maps at its start, so it is not applied
  there.
- **Memory** as a whole has no limit. On Linux the command's processes are
  the first the kernel ends when memory runs out (`oom_score_adj` 1000), so the
  daemon is not the one that goes. On macOS the system compresses and swaps
  instead.

So a command can still keep the machine busy until `timeout_seconds` ends it:
a fork bomb runs up to its limit, and memory fills up to what the system gives.
Run verification only for build and test commands you would run yourself.
A tainted session can not touch build scripts, CI or lockfiles, but a
repository's own tests are code like any other.

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

**Node.** `npm`/`pnpm` write to `~/.npm`; install dependencies outside
(`npm ci`) and commit the lock file; run the scripts offline. `~/.npmrc`
is not opened: it is where a registry token lives, and what a check can
read its log can tell (see "The environment the commands see").

```toml
build = "npm run build --offline"
test = "npm test --offline"
env_passthrough = ["HOME", "NODE_ENV"]
read = ["~/.npm", "~/.nvm"]
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
exit code, duration, sandbox, the environment it ran in and the tail of
its log; the MCP `change_status` tool gives a worker the same. The first
line of the log is the environment header above:

```
tests: fail (exit 101, 48210 ms, sandbox seatbelt)
  environment 3f2a9c1d0e4b
    rustc --version: rustc 1.91.0 (f8297e351 2025-10-28)
    cargo --version: cargo 1.91.0 (ea2d97820 2025-10-10)
  lonca verify: sandbox seatbelt, env PATH HOME TMPDIR LANG LONCA_VERIFY CARGO_HOME RUSTUP_HOME
  ...
```
