# Install

Lonca runs on macOS (arm64, x86_64) and Linux (x86_64, arm64). Every way
below installs **cooperative mode**: the binaries live where your account
can write. For hardened mode, see [below](#hardened-mode).

## The installer

```sh
curl -fsSL https://selcukgural.github.io/lonca/install.sh | sh
```

It downloads the release archive for your machine from
[GitHub releases](https://github.com/selcukgural/lonca/releases), checks it
against the release's `SHA256SUMS` (nothing is installed when it does not
match), puts `lonca`, `lonca-audit` and, on macOS, `lonca-se` (the Secure
Enclave helper) in `~/.local/bin`, and adds that directory to your shell's
`PATH` once. Running it again updates.

| Setting | Meaning |
|---|---|
| `LONCA_VERSION=0.2.0` | a version instead of the latest |
| `LONCA_INSTALL_DIR=DIR` | where the binaries go (default `~/.local/bin`) |
| `LONCA_NO_MODIFY_PATH=1` | never touch a shell startup file |

Read it before you run it:
[install.sh](https://github.com/selcukgural/lonca/blob/main/website/static/install.sh).

## Homebrew

```sh
brew install selcukgural/lonca/lonca
```

The tap ([selcukgural/homebrew-lonca](https://github.com/selcukgural/homebrew-lonca))
takes the same release archives. Its formula is written by a workflow that
checks every archive's checksum and attestation before committing it.

## crates.io

```sh
cargo install --locked lonca lonca-audit
```

Builds from source; needs Rust 1.90 or later. The Secure Enclave helper is
Swift and is not built by `cargo install`: on a Mac, build it with
`packaging/macos/build-lonca-se.sh` from a checkout, or set `LONCA_SE` to
its path. The libraries are on crates.io too; `lonca-client` is the one a
harness or runner needs to talk to the daemon.

## Checking a download

Every archive on the releases page has a build provenance attestation,
signed in the release workflow on the release tag:

```sh
gh attestation verify lonca-aarch64-apple-darwin.tar.gz --repo selcukgural/lonca
```

Each release also carries a CycloneDX SBOM (`lonca-sbom.cdx.tar.gz`).

## Hardened mode

Hardened mode runs the daemon as its own system user, with root-owned
binaries, so nothing running as you (agents included) can write the store,
the key or the binaries. Unpack the release archive for your machine and run
the installer it carries, as root:

```sh
mkdir lonca-0.2.0
tar -xzf lonca-aarch64-apple-darwin.tar.gz -C lonca-0.2.0
cd lonca-0.2.0
sudo ./install-hardened.sh --bin .
```

`--render DIR` writes the generated files (launchd or systemd unit, managed
Claude Code settings) to `DIR` without installing anything. On macOS,
`uninstall-hardened.sh` removes it again. A repository created in
cooperative mode moves over with its history; see
[the README](https://github.com/selcukgural/lonca#observation-levels).

## After installing

```sh
lonca daemon &
lonca doctor
```

`lonca doctor` shows what most first runs trip over: which mode is running,
the socket and the daemon, Claude Code's managed settings, the sandbox,
`git` and `lsof`, and for each repository whether your human can act on it
and whether its log verifies. Then follow the [quick start](quick-start.md).

## Uninstall

Installer: `rm ~/.local/bin/lonca ~/.local/bin/lonca-audit
~/.local/bin/lonca-se` and the `# lonca` lines it added to your shell's
startup file. Homebrew: `brew uninstall lonca`. The daemon's state in
`~/.lonca` and your human keys in `~/.config/lonca/humans` are yours:
`lonca backup` before removing them.
