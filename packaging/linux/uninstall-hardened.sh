#!/bin/sh
# Removes the hardened install of packaging/linux/install-hardened.sh.
#
#   sudo ./uninstall-hardened.sh            keep the stores, backups, imports
#   sudo ./uninstall-hardened.sh --purge    remove them too, and the lonca user
#
# Repository stores in /var/lib/lonca, backups in /var/lib/lonca-backups and
# bundles in /var/lib/lonca-import are kept unless --purge is given: a later
# install continues them. Take a `lonca backup` first and copy it off the
# machine before purging.
set -eu
# Run with sudo, this is root: nothing it runs is found by a name in the
# caller's PATH, where a file of the developer's account may stand first.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
purge=0
case "${1:-}" in
    "") ;;
    --purge) purge=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

UNIT=/etc/systemd/system/lonca.service
MANAGED=/etc/claude-code/managed-settings.json
BIN_DIR=/opt/lonca/bin

systemctl disable --now lonca.service 2>/dev/null || true
rm -f "$UNIT"
systemctl daemon-reload
# Only the file the installer wrote: settings merged by hand stay.
if [ -e "$MANAGED" ] && grep -q "$BIN_DIR/lonca hook" "$MANAGED"; then
    rm -f "$MANAGED"
fi
rm -f "$MANAGED.lonca"
rmdir /etc/claude-code 2>/dev/null || true
rm -rf /opt/lonca
# Left behind, it would hold every later client to a daemon that is gone.
rm -f /etc/lonca/daemon.toml
rmdir /etc/lonca 2>/dev/null || true
if [ $purge = 1 ]; then
    rm -rf /var/lib/lonca /var/lib/lonca-backups /var/lib/lonca-import
    userdel lonca 2>/dev/null || true
    groupdel lonca 2>/dev/null || true
fi
if [ $purge = 1 ]; then
    echo "Lonca removed, including repository stores, backups and imports."
else
    echo "Lonca removed. Stores, backups and imports are kept in /var/lib/lonca*."
fi
