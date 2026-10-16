#!/bin/sh
# Lonca hardened install for Linux (systemd).
#
#   sudo packaging/linux/install-hardened.sh [--bin DIR]
#   packaging/linux/install-hardened.sh --render DIR [--dev-uid N]
#
# Same layout as the macOS installer: a lonca system user owns the daemon's
# state, binaries are root-owned, the socket admits the developer's uid only,
# and Claude Code's managed settings lock hooks and sandbox (bubblewrap).
set -eu

PREFIX=/opt/lonca
BIN_DIR=$PREFIX/bin
HOME_DIR=/var/lib/lonca
SOCKET=/run/lonca/lonca.sock
UNIT=/etc/systemd/system/lonca.service
MANAGED=/etc/claude-code/managed-settings.json
PROXY_PORT=8471

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

unit() {
    cat <<EOF
[Unit]
Description=Lonca daemon (agent-native version control gatekeeper)
After=network.target

[Service]
User=lonca
Group=lonca
Environment=LONCA_SOCKET=$SOCKET
RuntimeDirectory=lonca
RuntimeDirectoryMode=0750
StateDirectory=lonca
StateDirectoryMode=0700
UMask=0077
ExecStart=$BIN_DIR/lonca daemon --home $HOME_DIR --socket-mode 660 --socket-group lonca --allow-uid $1 --proxy 127.0.0.1:$PROXY_PORT
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$HOME_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
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
    unit "${dev_uid:-1000}" > "$render/lonca.service"
    managed_settings > "$render/managed-settings.json"
    echo "rendered $render/lonca.service and $render/managed-settings.json"
    exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
dev_user=${SUDO_USER:-}
[ -n "$dev_user" ] && [ "$dev_user" != root ] || { echo "run with sudo from the developer's account" >&2; exit 1; }
dev_uid=$(id -u "$dev_user")
here=$(cd "$(dirname "$0")" && pwd)
src_bin=${src_bin:-"$here/../../target/release"}
[ -x "$src_bin/lonca" ] || { echo "missing $src_bin/lonca (cargo build --release)" >&2; exit 1; }
command -v bwrap >/dev/null || echo "WARNING: bubblewrap (bwrap) is not installed; verification will run unsandboxed"

getent group lonca >/dev/null || groupadd --system lonca
getent passwd lonca >/dev/null || useradd --system --gid lonca --home-dir "$HOME_DIR" --shell /usr/sbin/nologin lonca
usermod -a -G lonca "$dev_user"

install -d -o root -g root -m 0755 "$PREFIX" "$BIN_DIR"
for b in lonca lonca-audit; do
    [ -x "$src_bin/$b" ] && install -o root -g root -m 0755 "$src_bin/$b" "$BIN_DIR/$b"
done
unit "$dev_uid" > "$UNIT"
chmod 0644 "$UNIT"
install -d -o root -g root -m 0755 /etc/claude-code
if [ -e "$MANAGED" ] && ! grep -q "$BIN_DIR/lonca hook" "$MANAGED"; then
    managed_settings > "$MANAGED.lonca"
    echo "NOTE: $MANAGED already exists; merge $MANAGED.lonca into it by hand."
else
    managed_settings > "$MANAGED"
    chmod 0644 "$MANAGED"
fi
systemctl daemon-reload
systemctl enable --now lonca.service
echo "Lonca installed. export LONCA_SOCKET=$SOCKET; log out and in to join group lonca."
echo "sudo advice: use 'Defaults:$dev_user timestamp_timeout=0' or a non-sudo account for agents."
