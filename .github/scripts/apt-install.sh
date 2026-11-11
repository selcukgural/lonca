#!/usr/bin/env bash
# Installs Ubuntu packages on a GitHub runner: apt-install.sh [--update] <package>...
#
# The runner's apt reads its mirrors from /etc/apt/apt-mirrors.txt, and all of
# them are names under ubuntu.com. On 2026-11-11 none of them resolved on the
# runners for hours and every job that installs a package failed. So one mirror
# outside ubuntu.com is added, after the others: apt asks it only when they
# fail. What it serves is checked like theirs, against the archive's signed
# index.
set -euo pipefail

mirrors=/etc/apt/apt-mirrors.txt
fallback=https://mirrors.edge.kernel.org/ubuntu/
if [ -f "$mirrors" ] && ! grep -qF "$fallback" "$mirrors"; then
  printf '%s\tpriority:9\n' "$fallback" | sudo tee -a "$mirrors" >/dev/null
fi
if [ "${1:-}" = "--update" ]; then
  shift
  sudo apt-get -o Acquire::Retries=3 update
fi
sudo apt-get -o Acquire::Retries=3 install -y "$@"
