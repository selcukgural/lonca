# Lonca

[![crates.io](https://img.shields.io/crates/v/lonca.svg)](https://crates.io/crates/lonca)
[![lonca-client on docs.rs](https://img.shields.io/docsrs/lonca-client?label=docs.rs%20lonca-client)](https://docs.rs/lonca-client)
[![Licence](https://img.shields.io/crates/l/lonca.svg)](LICENSE)

**Agent-native, Git-compatible version control.**

Lonca (Turkish: the craft guild — written rules, masters and apprentices,
inspection before anything reaches the market) is a version control system
designed for repositories where many AI agents and a few humans work at the
same time. Content stays plain Git, so GitHub and every Git tool keep
working. What changes is everything around it: who may do what, how
concurrent work merges, and how every action is recorded and checked.

Everything else is on the site: **<https://selcukgural.github.io/lonca/>**
([why and how it works](https://selcukgural.github.io/lonca/docs/guide),
the guides, the protocol, the release notes).

> Status: 0.2, the first release. Every phase of the design is implemented
> and tested; formats are versioned, and a log written by any 0.x release
> stays readable by every later one. Not yet used on real projects: see the
> [scope and limitations](https://selcukgural.github.io/lonca/docs/guide#scope-of-0x).

## Install

macOS (arm64, x86_64) and Linux (x86_64, arm64):

```sh
curl -fsSL https://selcukgural.github.io/lonca/install.sh | sh   # ~/.local/bin
```

```sh
brew tap selcukgural/lonca                                       # Homebrew
brew install lonca
```

```sh
cargo install --locked lonca lonca-audit                         # crates.io, Rust 1.90+
```

These install cooperative mode. Hardened mode (the daemon as its own system
user, the harness's hooks and sandbox locked), checking a download, upgrade
and uninstall: [Install](https://selcukgural.github.io/lonca/docs/guide/install).

## Quick start

```sh
lonca daemon &                       # the gatekeeper (~/.lonca)
lonca human keygen ayse              # or: --secure-enclave
lonca init demo --import ~/src/myproject
lonca session start --repo demo --agent claude --paths 'src/**' \
      --task T-142 --ttl 2h --workspace ~/ws/claude-1
lonca doctor                         # what a first run trips over
```

The agent leases the symbols it edits and proposes; you review, approve and
audit. The whole walk-through is the
[quick start](https://selcukgural.github.io/lonca/docs/guide/quick-start).

## Crates

Most people want the command: `cargo install --locked lonca` (and
`lonca-audit` for the auditor). Every crate has the workspace's version;
only `lonca-client` is meant to be depended on, and the internal crates'
APIs have no stability promise.

| Crate | What it is |
|---|---|
| [`lonca`](https://crates.io/crates/lonca) | The `lonca` command: daemon, workspaces, approvals, harness hook, MCP server |
| [`lonca-audit`](https://crates.io/crates/lonca-audit) ([docs](https://docs.rs/lonca-audit)) | The independent auditor, `lonca-audit verify` |
| [`lonca-client`](https://crates.io/crates/lonca-client) ([docs](https://docs.rs/lonca-client)) | Client of the daemon socket: what harnesses and runners depend on |
| [`lonca-net`](https://crates.io/crates/lonca-net) ([docs](https://docs.rs/lonca-net)) | Loopback CONNECT proxy that asks a gate about every connection |
| [`lonca-core`](https://crates.io/crates/lonca-core) ([docs](https://docs.rs/lonca-core)) | Change ids, the signed operation log, keys, the Git store |
| [`lonca-policy`](https://crates.io/crates/lonca-policy) ([docs](https://docs.rs/lonca-policy)) | The pure `decide()`, state replay, Cedar policies, human signatures |
| [`lonca-symbols`](https://crates.io/crates/lonca-symbols) ([docs](https://docs.rs/lonca-symbols)) | tree-sitter symbols, facts and the structural merge |
| [`lonca-verify`](https://crates.io/crates/lonca-verify) ([docs](https://docs.rs/lonca-verify)) | Sandboxed build and test runs, recorded as evidence |
| [`lonca-daemon`](https://crates.io/crates/lonca-daemon) ([docs](https://docs.rs/lonca-daemon)) | The single writer: decide, sign, log, apply |

## Documentation

- [The site](https://selcukgural.github.io/lonca/): what Lonca is, install,
  quick start, guides for humans, profiles, runners and verification.
- [docs/protocol.md](docs/protocol.md): the daemon's protocol for runners
  and other clients.
- [docs/design.md](docs/design.md) (Turkish) and
  [docs/decisions.md](docs/decisions.md): the design, and every decision
  and deviation from it with its reasons.
- [docs/release-notes.md](docs/release-notes.md),
  [SECURITY.md](SECURITY.md),
  [docs/security/owasp.md](docs/security/owasp.md),
  [docs/crypto.md](docs/crypto.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
