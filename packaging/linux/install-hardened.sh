#!/bin/sh
# Lonca hardened install for Linux (systemd).
#
#   sudo packaging/linux/install-hardened.sh [--bin DIR] [--allow-unsandboxed]
#   packaging/linux/install-hardened.sh --render DIR [--dev-uid N] [--daemon-uid N]
#
# Run it again from a newer archive to upgrade: it stops the daemon, replaces
# the binaries and the generated files, and starts it again. The stores, the
# key and the backups stay. uninstall-hardened.sh removes the install.
#
# Same layout as the macOS installer: a lonca system user owns the daemon's
# state, binaries are root-owned, the socket admits the developer's uid only,
# /etc/lonca/daemon.toml tells clients the daemon's uid, and Claude Code's
# managed settings lock hooks and sandbox (bubblewrap). The daemon does not
# start without bubblewrap unless --allow-unsandboxed says it may.
# /var/lib/lonca-import is where the developer leaves Git bundles for
# `lonca init --import` and `lonca restore`: the daemon reads none of the
# developer's other directories, and the developer can write none of its.
set -eu

PREFIX=/opt/lonca
BIN_DIR=$PREFIX/bin
HOME_DIR=/var/lib/lonca
BACKUP_DIR=/var/lib/lonca-backups
IMPORT_DIR=/var/lib/lonca-import
SOCKET=/run/lonca/lonca.sock
DAEMON_CONFIG_DIR=/etc/lonca
DAEMON_CONFIG=$DAEMON_CONFIG_DIR/daemon.toml
UNIT=/etc/systemd/system/lonca.service
MANAGED=/etc/claude-code/managed-settings.json
PROXY_PORT=8471

src_bin=""
render=""
dev_uid=""
daemon_uid=""
unsandboxed=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) src_bin=$2; shift 2 ;;
        --render) render=$2; shift 2 ;;
        --dev-uid) dev_uid=$2; shift 2 ;;
        --daemon-uid) daemon_uid=$2; shift 2 ;;
        --allow-unsandboxed) unsandboxed=" --allow-unsandboxed"; shift ;;
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
ExecStart=$BIN_DIR/lonca daemon --home $HOME_DIR --backups $BACKUP_DIR --socket-mode 660 --socket-group lonca --allow-uid $1 --proxy 127.0.0.1:$PROXY_PORT --import-dir $IMPORT_DIR$unsandboxed
Restart=always
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$HOME_DIR $BACKUP_DIR
PrivateTmp=true

[Install]
WantedBy=multi-user.target
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
    unit "${dev_uid:-1000}" > "$render/lonca.service"
    managed_settings > "$render/managed-settings.json"
    daemon_toml "${daemon_uid:-0}" > "$render/daemon.toml"
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
# The places the verifier looks in, and no others: PATH is no root's word.
if [ -z "$unsandboxed" ] && [ ! -x /usr/bin/bwrap ] && [ ! -x /bin/bwrap ] && [ ! -x /usr/local/bin/bwrap ]; then
    echo "bubblewrap (bwrap) is not installed: the daemon would not start. Install it, or pass --allow-unsandboxed." >&2
    exit 1
fi

upgrade=""
[ -e "$UNIT" ] && upgrade=1

getent group lonca >/dev/null || groupadd --system lonca
getent passwd lonca >/dev/null || useradd --system --gid lonca --home-dir "$HOME_DIR" --shell /usr/sbin/nologin lonca
usermod -a -G lonca "$dev_user"

install -d -o root -g root -m 0755 "$PREFIX" "$BIN_DIR"
# An upgrade: the old daemon stops just before its binaries are replaced,
# so none keeps running from a deleted file.
if systemctl is-active --quiet lonca.service; then
    systemctl stop lonca.service
fi
install -d -o lonca -g lonca -m 0750 "$BACKUP_DIR"
# Group lonca writes, the setgid bit gives each file that group, the sticky
# bit keeps one from removing another's file.
install -d -o root -g lonca -m 3770 "$IMPORT_DIR"
for b in lonca lonca-audit; do
    [ -x "$src_bin/$b" ] && install -o root -g root -m 0755 "$src_bin/$b" "$BIN_DIR/$b"
done
install -d -o root -g root -m 0755 "$DAEMON_CONFIG_DIR"
daemon_toml "$(id -u lonca)" > "$DAEMON_CONFIG"
chown root:root "$DAEMON_CONFIG"
chmod 0644 "$DAEMON_CONFIG"
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
systemctl enable lonca.service
systemctl restart lonca.service
i=0
while [ ! -S "$SOCKET" ] && [ $i -lt 40 ]; do
    sleep 0.25
    i=$((i + 1))
done
if [ ! -S "$SOCKET" ]; then
    echo "the daemon did not start: journalctl -u lonca.service" >&2
    exit 1
fi
version=$("$BIN_DIR/lonca" --version)
done_word=installed
[ -n "$upgrade" ] && done_word=upgraded

cat <<EOF

$version $done_word, running as lonca.
  socket:  $SOCKET   (export LONCA_SOCKET=$SOCKET in your shell profile)
  state:   $HOME_DIR (unreadable for your account)
  backups: $BACKUP_DIR (lonca backup; readable by group lonca)
  imports: $IMPORT_DIR (leave Git bundles here)
  hooks:   $MANAGED

Log out and in again (or run 'newgrp lonca') so your account joins group lonca.

A new repository starts from the hardened profile, which asks for human
signatures with user presence. Linux has no key that proves it, so say so:
    $BIN_DIR/lonca init <repo> --without-presence
To bring a project's history along, bundle it into the import directory
first (the daemon reads the file through group lonca):
    git -C ~/src/project bundle create $IMPORT_DIR/project.bundle main
    $BIN_DIR/lonca init <repo> --without-presence --import $IMPORT_DIR/project.bundle
A repository of a cooperative daemon comes the same way: 'lonca backup', copy
the bundle into $IMPORT_DIR, 'lonca restore <repo> --from <that file>'.

'$BIN_DIR/lonca doctor' checks the rest: repositories below the hardened
profile, and a sudo that asks for no password (design §3.3), for which add
    Defaults:$dev_user timestamp_timeout=0
with 'sudo visudo', or use a non-sudo account for daily work.
EOF
