#!/bin/sh
# Lonca hardened install for macOS (sertleştirilmiş iş birlikçi mod).
#
#   sudo packaging/macos/install-hardened.sh [--bin DIR]   install
#   packaging/macos/install-hardened.sh --render DIR [--dev-uid N]
#                                                          write the generated
#                                                          files to DIR only
#
# What it does (design §3.3):
#   - creates the system user _lonca and the group lonca (the developer joins it)
#   - installs lonca, lonca-audit and lonca-se root-owned in /Library/Lonca/bin
#   - keeps daemon state in /Library/Lonca/home, owned by _lonca, mode 0700:
#     agents running as the developer can not read the key or write the stores
#   - runs the daemon from launchd as _lonca; its socket accepts the
#     developer's uid only
#   - installs Claude Code managed settings: Lonca hooks for every tool,
#     managed hooks only, hook failures block, sandbox locked to the Lonca
#     network proxy
#
# It never edits sudoers. Read the printed advice about sudo's credential cache.
set -eu

PREFIX=/Library/Lonca
BIN_DIR=$PREFIX/bin
HOME_DIR=$PREFIX/home
RUN_DIR=$PREFIX/run
SOCKET=$RUN_DIR/lonca.sock
PLIST=/Library/LaunchDaemons/dev.lonca.daemon.plist
MANAGED_DIR="/Library/Application Support/ClaudeCode"
MANAGED="$MANAGED_DIR/managed-settings.json"
PROXY_PORT=8471
LABEL=dev.lonca.daemon

src_bin=""
render=""
dev_uid=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) src_bin=$2; shift 2 ;;
        --render) render=$2; shift 2 ;;
        --dev-uid) dev_uid=$2; shift 2 ;;
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
    <string>--socket-mode</string><string>660</string>
    <string>--socket-group</string><string>lonca</string>
    <string>--allow-uid</string><string>$1</string>
    <string>--proxy</string><string>127.0.0.1:$PROXY_PORT</string>
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
    echo "rendered $render/$LABEL.plist and $render/managed-settings.json"
    exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
dev_user=${SUDO_USER:-}
[ -n "$dev_user" ] && [ "$dev_user" != root ] || { echo "run with sudo from the developer's account" >&2; exit 1; }
dev_uid=$(id -u "$dev_user")
here=$(cd "$(dirname "$0")" && pwd)
src_bin=${src_bin:-"$here/../../target/release"}
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
dseditgroup -o edit -a "$dev_user" -t user lonca
dseditgroup -o edit -a _lonca -t user lonca

install -d -o root -g wheel -m 0755 "$PREFIX" "$BIN_DIR"
install -d -o _lonca -g lonca -m 0700 "$HOME_DIR"
install -d -o _lonca -g lonca -m 0750 "$RUN_DIR"
for b in lonca lonca-audit lonca-se; do
    if [ -x "$src_bin/$b" ]; then
        install -o root -g wheel -m 0755 "$src_bin/$b" "$BIN_DIR/$b"
    fi
done

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
launchctl bootstrap system "$PLIST"

cat <<EOF

Lonca daemon installed and started as _lonca.
  socket:  $SOCKET   (export LONCA_SOCKET=$SOCKET in your shell profile)
  state:   $HOME_DIR (unreadable for your account)
  hooks:   $MANAGED

Log out and in again (or run 'newgrp lonca') so your account joins group lonca.

sudo advice (design §3.3): an agent running as you can use a cached sudo
credential. Either use a non-admin account for daily work, or add
    Defaults:$dev_user timestamp_timeout=0
with 'sudo visudo'. Lonca marks sessions as unobserved while 'sudo -n true'
succeeds for you.

Human signatures with user presence:
    $BIN_DIR/lonca human keygen --secure-enclave <name>
and set approvals.require_presence = true in the repository policy.
EOF
