#!/usr/bin/env bash
# Records docs/demo/demo.sh and writes the GIF the README shows.
# Needs asciinema 3 and agg (brew install asciinema agg), and the released
# `lonca` and `lonca-audit` on PATH.
#
#   docs/demo/record.sh               # website/static/img/lonca-demo.gif
#
# The cast is written to $TMPDIR and is not kept in the repository; the GIF
# is. Record again when a command the demo runs changes what it prints.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
cast="${TMPDIR:-/tmp}/lonca-demo.cast"
gif="$root/website/static/img/lonca-demo.gif"

asciinema rec --overwrite --headless --window-size 100x30 --quiet \
    --title "Lonca: two agents, one file" \
    --command "$root/docs/demo/demo.sh" "$cast"
agg --quiet --font-size 16 --theme asciinema --speed 1.5 --fps-cap 15 \
    --idle-time-limit 3 --last-frame-duration 6 "$cast" "$gif"
echo "$gif"
