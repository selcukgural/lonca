#!/bin/sh
# Holds a file to the SHA-256 its build job reported: same-archive.sh <file> <sha256>
#
# In release.yml an archive travels between jobs as an artifact, found again
# by its name. Another job of the run could put a file of that name there;
# the digest comes from the build job's own outputs, which no other job
# writes.
set -eu
file=$1
want=$2
[ -n "$want" ] || { echo "no digest was reported for $file" >&2; exit 1; }
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$file" | cut -d ' ' -f 1)
else
    got=$(shasum -a 256 "$file" | cut -d ' ' -f 1)
fi
if [ "$got" != "$want" ]; then
    echo "$file is not what its build made: sha256 $got, built $want" >&2
    exit 1
fi
echo "$file is what its build made ($got)"
