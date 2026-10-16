#!/bin/sh
# Builds the Secure Enclave signing helper next to the lonca binary.
#   packaging/macos/build-lonca-se.sh [output-dir]   (default: target/release)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
out=${1:-"$here/../../target/release"}
mkdir -p "$out"
swiftc -O "$here/lonca-se/main.swift" -o "$out/lonca-se"
# Ad-hoc signature; sign with your Developer ID for distribution.
codesign -s - -f "$out/lonca-se"
echo "built $out/lonca-se"
