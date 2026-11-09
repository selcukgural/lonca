#!/bin/sh
# Lonca's installer: puts the prebuilt lonca for this machine on PATH.
#
#   curl -fsSL https://selcukgural.github.io/lonca/install.sh | sh
#
# It downloads the release archive for this system (macOS or Linux, x86_64
# or arm64) from https://github.com/selcukgural/lonca/releases, checks it
# against the release's SHA256SUMS (nothing is installed when it does not
# match), puts `lonca`, `lonca-audit` and on macOS `lonca-se` (the Secure
# Enclave helper, which lonca finds next to itself) in ~/.local/bin and,
# when that is not on PATH yet, adds it in your shell's startup file once.
# Running it again updates.
#
# This is cooperative mode: the binaries live where your account can write.
# For hardened mode, unpack the archive and run `sudo ./install-hardened.sh
# --bin .` from it instead (docs/guide/install.md, "Hardened mode").
#
# Settings, from the environment:
#   LONCA_VERSION=0.2.2      a version instead of the latest
#   LONCA_INSTALL_DIR=DIR    where lonca goes (default: ~/.local/bin)
#   LONCA_NO_MODIFY_PATH=1   never touch a startup file
#   LONCA_DOWNLOAD_URL=URL   where the release files are (a mirror, or a
#                            file:// directory)
#
# Uninstall: rm ~/.local/bin/lonca ~/.local/bin/lonca-audit
# ~/.local/bin/lonca-se (and the "# lonca" lines it added). The daemon's
# state in ~/.lonca is yours: `lonca backup` before removing it.
#
# Everything runs from `main` at the very end, so a download cut short
# runs nothing.

set -eu

REPO="https://github.com/selcukgural/lonca"

say() {
    printf 'lonca: %s\n' "$*"
}

die() {
    printf 'lonca: %s\n' "$*" >&2
    exit 1
}

has() {
    command -v "$1" >/dev/null 2>&1
}

# The release target this machine runs: its CPU and system as Rust names
# them. Linux builds are static (musl), so any distribution takes them.
target() {
    os=$(uname -s)
    arch=$(uname -m)
    case "$os" in
        Darwin) os=apple-darwin ;;
        Linux) os=unknown-linux-musl ;;
        *) die "lonca runs on macOS and Linux; this is $os" ;;
    esac
    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        arm64 | aarch64) arch=aarch64 ;;
        *) die "no lonca build for $arch; build from source: $REPO" ;;
    esac
    # A shell under Rosetta on Apple silicon says x86_64: the native build
    # is the one to have (and the only one the Secure Enclave helper is
    # tested on).
    if [ "$os" = apple-darwin ] && [ "$arch" = x86_64 ] &&
        [ "$(sysctl -n sysctl.proc_translated 2>/dev/null || true)" = 1 ]; then
        arch=aarch64
    fi
    printf '%s-%s\n' "$arch" "$os"
}

# Fetches $1 to the file $2, over HTTPS only (a mirror given in
# LONCA_DOWNLOAD_URL may also be a local directory).
download() {
    if has curl; then
        proto='=https'
        if [ -n "${LONCA_DOWNLOAD_URL:-}" ]; then
            proto='=https,file'
        fi
        curl --proto "$proto" --proto-redir '=https' --tlsv1.2 \
            --fail --silent --show-error --location --retry 3 \
            --output "$2" "$1" || die "could not download $1"
    elif has wget; then
        wget --https-only --quiet --output-document="$2" "$1" ||
            die "could not download $1"
    else
        die "curl or wget is needed to download lonca"
    fi
}

sha256() {
    if has sha256sum; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif has shasum; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    else
        die "sha256sum or shasum is needed to check the download"
    fi
}

# The line that puts $1 on PATH in the startup file of the person's shell,
# and that file, as "FILE|LINE". `$PATH` is written as it is, for the shell
# to expand when it starts.
# shellcheck disable=SC2016
path_line() {
    case "$(basename "${SHELL:-sh}")" in
        zsh)
            printf '%s|export PATH="%s:$PATH"\n' "${ZDOTDIR:-$HOME}/.zshrc" "$1"
            ;;
        bash)
            # macOS terminals open login shells, which read .bash_profile.
            if [ "$(uname -s)" = Darwin ]; then
                rc="$HOME/.bash_profile"
            else
                rc="$HOME/.bashrc"
            fi
            printf '%s|export PATH="%s:$PATH"\n' "$rc" "$1"
            ;;
        fish)
            printf '%s|fish_add_path "%s"\n' \
                "${XDG_CONFIG_HOME:-$HOME/.config}/fish/conf.d/lonca.fish" "$1"
            ;;
        *)
            printf '%s|export PATH="%s:$PATH"\n' "$HOME/.profile" "$1"
            ;;
    esac
}

# Puts $1 (in the unpacked archive) at $2/$3: next to the old one, then
# moved over it, so a running daemon keeps its file and no half-written one
# is ever on PATH.
place() {
    cp "$1" "$2/.$3.new"
    chmod 755 "$2/.$3.new"
    mv -f "$2/.$3.new" "$2/$3"
}

main() {
    for tool in uname tar mkdir chmod cp mv rm grep cut basename mktemp; do
        has "$tool" || die "$tool is needed"
    done
    target=$(target)
    archive="lonca-$target.tar.gz"
    if [ -n "${LONCA_DOWNLOAD_URL:-}" ]; then
        base="${LONCA_DOWNLOAD_URL%/}"
    elif [ -n "${LONCA_VERSION:-}" ]; then
        base="$REPO/releases/download/v${LONCA_VERSION#v}"
    else
        base="$REPO/releases/latest/download"
    fi
    dir="${LONCA_INSTALL_DIR:-$HOME/.local/bin}"

    tmp=$(mktemp -d 2>/dev/null || mktemp -d -t lonca)
    trap 'rm -rf "$tmp"' EXIT
    trap 'exit 1' INT TERM HUP

    say "downloading $archive (${LONCA_VERSION:-latest})"
    download "$base/$archive" "$tmp/$archive"
    download "$base/SHA256SUMS" "$tmp/SHA256SUMS"
    want=$(grep "  $archive\$" "$tmp/SHA256SUMS" | cut -d ' ' -f 1 || true)
    [ -n "$want" ] || die "SHA256SUMS lists no $archive"
    got=$(sha256 "$tmp/$archive")
    [ "$got" = "$want" ] ||
        die "$archive does not match its SHA256SUMS (got $got, want $want); nothing installed"

    mkdir "$tmp/x"
    tar -xzf "$tmp/$archive" -C "$tmp/x" || die "could not unpack $archive"
    for b in lonca lonca-audit; do
        [ -f "$tmp/x/$b" ] || die "$archive holds no $b"
    done
    mkdir -p "$dir"
    place "$tmp/x/lonca-audit" "$dir" lonca-audit
    if [ -f "$tmp/x/lonca-se" ]; then
        place "$tmp/x/lonca-se" "$dir" lonca-se
    fi
    # lonca last: it is what a later step, or the person, checks for.
    place "$tmp/x/lonca" "$dir" lonca
    version=$("$dir/lonca" --version) || die "the installed $dir/lonca does not run"
    say "installed $version at $dir/lonca"

    case ":$PATH:" in
        *":$dir:"*)
            first=$(command -v lonca || true)
            if [ -n "$first" ] && [ "$first" != "$dir/lonca" ]; then
                say "note: $first comes first on PATH; remove it or put $dir before it"
            fi
            ;;
        *)
            if [ "${LONCA_NO_MODIFY_PATH:-}" = 1 ]; then
                say "$dir is not on PATH; add it to use lonca by name"
            else
                spec=$(path_line "$dir")
                rc=${spec%%|*}
                line=${spec#*|}
                if ! grep -qsF "$line" "$rc"; then
                    mkdir -p "${rc%/*}"
                    printf '\n# lonca\n%s\n' "$line" >>"$rc"
                    say "added $dir to PATH in $rc"
                fi
                say "open a new terminal, or run: $line"
            fi
            ;;
    esac

    say "next: lonca daemon &   then   lonca doctor   (quick start: $REPO#quick-start-cooperative-mode)"
}

main "$@"
