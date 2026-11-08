#!/bin/sh
# Removes the hardened install of install-hardened.sh.
#
#   sudo ./uninstall-hardened.sh            keep the stores, backups, imports
#   sudo ./uninstall-hardened.sh --purge    remove them too, and the _lonca user
#
# Repository stores in /Library/Lonca/home, backups in /Library/Lonca/backups
# and bundles in /Library/Lonca/import are kept unless --purge is given.
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
purge=0
case "${1:-}" in
    "") ;;
    --purge) purge=1 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
esac
PLIST=/Library/LaunchDaemons/dev.lonca.daemon.plist
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
MANAGED="/Library/Application Support/ClaudeCode/managed-settings.json"
if [ -e "$MANAGED" ] && grep -q "/Library/Lonca/bin/lonca hook" "$MANAGED"; then
    rm -f "$MANAGED"
fi
rm -f "$MANAGED.lonca"
rm -rf /Library/Lonca/bin /Library/Lonca/run
# Left behind, it would hold every later client to a daemon that is gone.
rm -f /Library/Lonca/daemon.toml
if [ $purge = 1 ]; then
    rm -rf /Library/Lonca
    dscl . -delete /Users/_lonca 2>/dev/null || true
    dscl . -delete /Groups/lonca 2>/dev/null || true
fi
if [ $purge = 1 ]; then
    echo "Lonca removed, including repository stores, backups and imports."
else
    echo "Lonca removed. Stores, backups and imports are kept in /Library/Lonca."
fi
