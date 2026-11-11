#!/bin/sh
# Lonca hardened install for macOS (sertleştirilmiş iş birlikçi mod).
#
#   sudo packaging/macos/install-hardened.sh [--bin DIR]   install
#   .../install-hardened.sh --check-source [--bin DIR]     say whether this
#                                                          script and the
#                                                          binaries are root's
#                                                          alone, as an install
#                                                          requires; no sudo
#   sudo .../install-hardened.sh --unprotected-source      install a build of
#                                                          your own from your
#                                                          checkout all the same
#   packaging/macos/install-hardened.sh --render DIR [--dev-uid N] [--daemon-uid N]
#                                                          write the generated
#                                                          files to DIR only
#
# Run it again from a newer archive to upgrade: it stops the daemon, replaces
# the binaries and the generated files, and starts it again. The stores, the
# key and the backups stay. uninstall-hardened.sh removes the install.
#
# What it does (design §3.3):
#   - creates the system user _lonca and the group lonca (the developer joins it)
#   - installs lonca, lonca-audit and lonca-se root-owned in /Library/Lonca/bin
#   - keeps daemon state in /Library/Lonca/home, owned by _lonca, mode 0700:
#     agents running as the developer can not read the key or write the stores
#   - writes `lonca backup` bundles to /Library/Lonca/backups, readable by
#     group lonca, so the developer can copy them off the machine
#   - reads Git bundles the developer leaves in /Library/Lonca/import, for
#     `lonca init --import` and `lonca restore`, and nothing else of theirs
#   - runs the daemon from launchd as _lonca; its socket accepts the
#     developer's uid only
#   - names the daemon's uid in /Library/Lonca/daemon.toml, root-owned: clients
#     refuse any other process on the socket
#   - installs Claude Code managed settings: Lonca hooks for every tool,
#     managed hooks only, hook failures block, sandbox locked to the Lonca
#     network proxy
#
# It never edits sudoers. Read the printed advice about sudo's credential cache.
set -eu
# Run with sudo, this is root: nothing it runs is found by a name in the
# caller's PATH, where a file of the developer's account may stand first.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH

PREFIX=/Library/Lonca
BIN_DIR=$PREFIX/bin
HOME_DIR=$PREFIX/home
RUN_DIR=$PREFIX/run
BACKUP_DIR=$PREFIX/backups
IMPORT_DIR=$PREFIX/import
SOCKET=$RUN_DIR/lonca.sock
DAEMON_CONFIG=$PREFIX/daemon.toml
PLIST=/Library/LaunchDaemons/dev.lonca.daemon.plist
MANAGED_DIR="/Library/Application Support/ClaudeCode"
MANAGED="$MANAGED_DIR/managed-settings.json"
PROXY_PORT=8471
LABEL=dev.lonca.daemon

src_bin=""
unprotected=""
check_only=""
render=""
dev_uid=""
daemon_uid=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) src_bin=$2; shift 2 ;;
        --render) render=$2; shift 2 ;;
        --check-source) check_only=1; shift ;;
        --unprotected-source) unprotected=1; shift ;;
        --dev-uid) dev_uid=$2; shift 2 ;;
        --daemon-uid) daemon_uid=$2; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

plist() {
    cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>UserName</key><string>_lonca</string>
  <key>GroupName</key><string>lonca</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_DIR/lonca</string>
    <string>daemon</string>
    <string>--home</string><string>$HOME_DIR</string>
    <string>--backups</string><string>$BACKUP_DIR</string>
    <string>--socket-mode</string><string>660</string>
    <string>--socket-group</string><string>lonca</string>
    <string>--allow-uid</string><string>$1</string>
    <string>--proxy</string><string>127.0.0.1:$PROXY_PORT</string>
    <string>--import-dir</string><string>$IMPORT_DIR</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>LONCA_SOCKET</key><string>$SOCKET</string>
    <key>PATH</key><string>/usr/bin:/bin:/usr/sbin:/sbin</string>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>$HOME_DIR/daemon.log</string>
  <key>Umask</key><integer>63</integer>
</dict>
</plist>
EOF
}

# Clients read this before they trust the socket (docs/decisions.md,
# "Clients verify the daemon"): root-owned, like the binaries.
daemon_toml() {
    cat <<EOF
# The daemon runs as this uid. A client refuses any other process on the socket.
daemon_uid = $1
EOF
}

managed_settings() {
    cat <<EOF
{
  "allowManagedHooksOnly": true,
  "env": { "LONCA_SOCKET": "$SOCKET" },
  "hooks": {
    "SessionStart": [{ "hooks": [{ "type": "command", "command": "$BIN_DIR/lonca hook", "onFailure": "block" }] }],
    "PreToolUse":  [{ "matcher": "*", "hooks": [{ "type": "command", "command": "$BIN_DIR/lonca hook", "onFailure": "block" }] }],
    "PostToolUse": [{ "matcher": "*", "hooks": [{ "type": "command", "command": "$BIN_DIR/lonca hook", "onFailure": "block" }] }]
  },
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false,
    "excludedCommands": [],
    "network": { "httpProxyPort": $PROXY_PORT },
    "filesystem": { "denyRead": ["~/.ssh", "~/.aws", "~/.gnupg", "~/.config/gh", "~/.config/lonca"] }
  }
}
EOF
}

if [ -n "$render" ]; then
    mkdir -p "$render"
    plist "${dev_uid:-501}" > "$render/$LABEL.plist"
    managed_settings > "$render/managed-settings.json"
    daemon_toml "${daemon_uid:-0}" > "$render/daemon.toml"
    echo "rendered $render/$LABEL.plist and $render/managed-settings.json"
    exit 0
fi

# Is "$1" root's alone: owned by root and written by nobody else, it and
# every directory above it?
roots_alone() {
    p=$1
    while :; do
        [ ! -L "$p" ] || return 1
        st=$(stat -f '%u %Lp' "$p") || return 1
        [ "${st% *}" = 0 ] || return 1
        [ $((0${st#* } & 022)) = 0 ] || return 1
        [ "$p" != / ] || return 0
        p=$(dirname "$p")
    done
}

here=$(cd "$(dirname "$0")" && pwd -P)
src_bin=${src_bin:-"$here/../../target/release"}
src_bin=$(cd "$src_bin" 2>/dev/null && pwd -P) || { echo "no directory $src_bin" >&2; exit 1; }
# What root installs and then runs is taken from files root alone can
# change. An archive unpacked in the developer's account is a place every
# program of that account writes: an agent that ran there before this
# install could have replaced a binary, or this script.
open=""
for f in "$here/$(basename "$0")" "$here/uninstall-hardened.sh" "$src_bin/lonca" "$src_bin/lonca-audit" "$src_bin/lonca-se"; do
    [ -e "$f" ] || continue
    roots_alone "$f" || open="$open
  $f"
done
if [ -n "$open" ]; then
    if [ -n "$unprotected" ]; then
        echo "WARNING: installing from files that are not root's alone (--unprotected-source):$open" >&2
    else
        cat >&2 <<EOF
These are not root's alone (owned by root and written by nobody else, with
every directory above them):$open
Whatever runs as you could have changed them, and they are about to be
installed and run as root and as the daemon. Copy the archive to a place of
root's, check that copy, and unpack and install from there:
    sudo install -d -m 0755 /usr/local/lonca-release
    sudo cp lonca-<target>.tar.gz /usr/local/lonca-release/
    gh attestation verify /usr/local/lonca-release/lonca-<target>.tar.gz --repo selcukgural/lonca
    sudo tar -xzf /usr/local/lonca-release/lonca-<target>.tar.gz --no-same-owner -C /usr/local/lonca-release
    sudo /usr/local/lonca-release/install-hardened.sh --bin /usr/local/lonca-release
(without gh: shasum -a 256 on the copy, against SHA256SUMS of the release page).
A build of your own from a checkout: --unprotected-source.
EOF
        exit 1
    fi
fi
if [ -n "$check_only" ]; then
    echo "the source is root's alone: $here, $src_bin"
    exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
dev_user=${SUDO_USER:-}
[ -n "$dev_user" ] && [ "$dev_user" != root ] || { echo "run with sudo from the developer's account" >&2; exit 1; }
dev_uid=$(id -u "$dev_user")
for b in lonca lonca-audit; do
    [ -x "$src_bin/$b" ] || { echo "missing $src_bin/$b (cargo build --release)" >&2; exit 1; }
done

free_id() {
    # First free id in 280..299 for both users and groups.
    i=280
    while [ $i -lt 300 ]; do
        if ! dscl . -list /Users UniqueID | awk '{print $2}' | grep -qx "$i" &&
           ! dscl . -list /Groups PrimaryGroupID | awk '{print $2}' | grep -qx "$i"; then
            echo $i; return
        fi
        i=$((i + 1))
    done
    echo "no free id in 280..299" >&2; exit 1
}

if ! dscl . -read /Groups/lonca >/dev/null 2>&1; then
    gid=$(free_id)
    dscl . -create /Groups/lonca
    dscl . -create /Groups/lonca PrimaryGroupID "$gid"
    dscl . -create /Groups/lonca RealName "Lonca"
fi
gid=$(dscl . -read /Groups/lonca PrimaryGroupID | awk '{print $2}')
if ! dscl . -read /Users/_lonca >/dev/null 2>&1; then
    uid=$(free_id)
    dscl . -create /Users/_lonca
    dscl . -create /Users/_lonca UniqueID "$uid"
    dscl . -create /Users/_lonca PrimaryGroupID "$gid"
    dscl . -create /Users/_lonca UserShell /usr/bin/false
    dscl . -create /Users/_lonca NFSHomeDirectory /var/empty
    dscl . -create /Users/_lonca RealName "Lonca daemon"
    dscl . -create /Users/_lonca IsHidden 1
fi
# An upgrade: the old daemon stops before its binaries are replaced.
upgrade=""
if [ -e "$PLIST" ]; then
    upgrade=1
    launchctl bootout system "$PLIST" 2>/dev/null || true
fi

dseditgroup -o edit -a "$dev_user" -t user lonca
dseditgroup -o edit -a _lonca -t user lonca

install -d -o root -g wheel -m 0755 "$PREFIX" "$BIN_DIR"
install -d -o _lonca -g lonca -m 0700 "$HOME_DIR"
install -d -o _lonca -g lonca -m 0750 "$RUN_DIR" "$BACKUP_DIR"
# Group lonca writes, the setgid bit gives each file that group, the sticky
# bit keeps one from removing another's file.
install -d -o root -g lonca -m 3770 "$IMPORT_DIR"
for b in lonca lonca-audit lonca-se; do
    if [ -x "$src_bin/$b" ]; then
        install -o root -g wheel -m 0755 "$src_bin/$b" "$BIN_DIR/$b"
    fi
done
# The uninstaller stays where root alone writes: it is run with sudo too.
if [ -f "$here/uninstall-hardened.sh" ]; then
    install -o root -g wheel -m 0755 "$here/uninstall-hardened.sh" "$PREFIX/uninstall-hardened.sh"
fi

daemon_toml "$(id -u _lonca)" > "$DAEMON_CONFIG"
chown root:wheel "$DAEMON_CONFIG"
chmod 0644 "$DAEMON_CONFIG"

plist "$dev_uid" > "$PLIST"
chown root:wheel "$PLIST"
chmod 0644 "$PLIST"

install -d -o root -g wheel -m 0755 "$MANAGED_DIR"
if [ -e "$MANAGED" ] && ! grep -q "$BIN_DIR/lonca hook" "$MANAGED"; then
    managed_settings > "$MANAGED.lonca"
    chown root:wheel "$MANAGED.lonca"; chmod 0644 "$MANAGED.lonca"
    echo "NOTE: $MANAGED already exists; merge $MANAGED.lonca into it by hand."
else
    managed_settings > "$MANAGED"
    chown root:wheel "$MANAGED"; chmod 0644 "$MANAGED"
fi

launchctl bootout system "$PLIST" 2>/dev/null || true
# The old daemon's socket outlives it: gone, the wait below sees the new one.
rm -f "$SOCKET"
launchctl bootstrap system "$PLIST"
i=0
while [ ! -S "$SOCKET" ] && [ $i -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
    echo "the daemon did not start: see $HOME_DIR/daemon.log (sudo cat)" >&2
    exit 1
fi
version=$("$BIN_DIR/lonca" --version)
done_word=installed
[ -n "$upgrade" ] && done_word=upgraded

cat <<EOF

$version $done_word, running as _lonca.
  socket:  $SOCKET   (export LONCA_SOCKET=$SOCKET in your shell profile)
  state:   $HOME_DIR (unreadable for your account)
  backups: $BACKUP_DIR (lonca backup; readable by group lonca)
  imports: $IMPORT_DIR (leave Git bundles here)
  hooks:   $MANAGED

Log out and in again (or run 'newgrp lonca') so your account joins group lonca.

A new repository starts from the hardened profile, which asks for human
signatures with user presence:
    $BIN_DIR/lonca human keygen --secure-enclave <name>
To bring a project's history along, bundle it into the import directory
first (the daemon reads the file through group lonca):
    git -C ~/src/project bundle create $IMPORT_DIR/project.bundle main
    $BIN_DIR/lonca init <repo> --import $IMPORT_DIR/project.bundle
A repository of a cooperative daemon comes the same way: 'lonca backup', copy
the bundle into $IMPORT_DIR, 'lonca restore <repo> --from <that file>'.

'$BIN_DIR/lonca doctor' checks the rest: repositories below the hardened
profile, and a sudo that asks for no password (design §3.3), for which add
    Defaults:$dev_user timestamp_timeout=0
with 'sudo visudo', or use a non-admin account for daily work.
EOF
