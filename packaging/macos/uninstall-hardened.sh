#!/bin/sh
# Removes the hardened install. Repository stores in /Library/Lonca/home are
# kept unless --purge is given.
set -eu
[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
purge=0
[ "${1:-}" = "--purge" ] && purge=1
PLIST=/Library/LaunchDaemons/dev.lonca.daemon.plist
launchctl bootout system "$PLIST" 2>/dev/null || true
rm -f "$PLIST"
MANAGED="/Library/Application Support/ClaudeCode/managed-settings.json"
if [ -e "$MANAGED" ] && grep -q "/Library/Lonca/bin/lonca hook" "$MANAGED"; then
    rm -f "$MANAGED"
fi
rm -rf /Library/Lonca/bin /Library/Lonca/run
if [ $purge = 1 ]; then
    rm -rf /Library/Lonca
    dscl . -delete /Users/_lonca 2>/dev/null || true
    dscl . -delete /Groups/lonca 2>/dev/null || true
fi
echo "Lonca removed$( [ $purge = 1 ] && echo ' (including repository stores)' )."
