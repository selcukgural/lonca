#!/usr/bin/env bash
# The mutation gate (#35; docs/decisions.md, "Mutation testing").
#
#   mutants-gate.sh exclusions [--write]
#       Lists what `.cargo/mutants.toml` excludes in a gated file
#       (`.cargo/mutants-gated.txt`) and compares it with
#       `.cargo/mutants-gated-exclusions.txt`. Fails on any difference;
#       `--write` rewrites the list instead. Needs cargo-mutants, builds
#       nothing (`cargo mutants --list`, a few seconds).
#   mutants-gate.sh results DIR...
#       Reads the `mutants.out` directories of a run (one per shard) and
#       prints the score of each crate and of the gated files as Markdown.
#       Fails if a gated file has a missed or a timed-out mutant.
#
# Mutant names are `path:line:col: what`; the gate compares `path: what`.
set -euo pipefail
export LC_ALL=C

root=$(git rev-parse --show-toplevel)
gated_list="$root/.cargo/mutants-gated.txt"
expected="$root/.cargo/mutants-gated-exclusions.txt"

# Mutant names on stdin, those in a gated file on stdout.
in_gated() {
  awk 'NR == FNR {
         if ($0 !~ /^#/ && NF) g[++n] = $1
         next
       }
       {
         p = $0
         sub(/:.*/, "", p)
         for (i = 1; i <= n; i++) {
           dir = substr(g[i], length(g[i])) == "/"
           if (p == g[i] || (dir && index(p, g[i]) == 1)) { print; break }
         }
       }' "$gated_list" -
}

# `path:line:col: what` to `path: what`.
unplaced() {
  sed -E 's/^([^:]+):[0-9]+:[0-9]+: /\1: /'
}

exclusions() {
  local tmp
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  (cd "$root" && cargo mutants --list) | unplaced | sort > "$tmp/kept"
  (cd "$root" && cargo mutants --list --no-config) | unplaced | sort > "$tmp/all"
  comm -13 "$tmp/kept" "$tmp/all" | in_gated > "$tmp/excluded"
  if [ "${1:-}" = "--write" ]; then
    { sed -n '/^#/p' "$expected"; cat "$tmp/excluded"; } > "$tmp/new"
    mv "$tmp/new" "$expected"
    echo "wrote $(wc -l < "$tmp/excluded" | tr -d ' ') exclusions to $expected"
    return
  fi
  grep -v '^#' "$expected" | sed '/^$/d' | sort > "$tmp/listed"
  if ! diff -u --label listed --label excluded "$tmp/listed" "$tmp/excluded"; then
    echo "::error::the exclusions in gated files differ from .cargo/mutants-gated-exclusions.txt:"
    echo "an exclusion there needs a reason in .cargo/mutants.toml and a line in the list"
    return 1
  fi
  echo "exclusions in gated files: $(wc -l < "$tmp/excluded" | tr -d ' '), all listed"
}

results() {
  [ $# -gt 0 ] || { echo "usage: $0 results DIR..." >&2; return 2; }
  local tmp kind d
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' RETURN
  for kind in caught missed timeout unviable; do
    for d in "$@"; do
      [ -f "$d/$kind.txt" ] && cat "$d/$kind.txt"
    done | sed '/^$/d' > "$tmp/$kind"
    in_gated < "$tmp/$kind" > "$tmp/gated-$kind"
  done
  echo "| crate | caught | timeout | missed | unviable | score |"
  echo "|---|---:|---:|---:|---:|---:|"
  for kind in caught missed timeout unviable; do
    sed -E 's#^crates/([^/]+)/.*#\1#' "$tmp/$kind" | sed "s/\$/ $kind/"
  done | awk '
    { n[$1, $2]++; crates[$1] = 1 }
    function row(name, c, t, m, u) {
      s = c + t + m
      printf "| %s | %d | %d | %d | %d | %s |\n", name, c, t, m, u, s ? sprintf("%.1f %%", 100 * (c + t) / s) : "-"
    }
    END {
      k = 0
      for (c in crates) names[++k] = c
      for (i = 1; i <= k; i++) for (j = i + 1; j <= k; j++) if (names[j] < names[i]) { x = names[i]; names[i] = names[j]; names[j] = x }
      for (i = 1; i <= k; i++) { c = names[i]; row(c, n[c, "caught"], n[c, "timeout"], n[c, "missed"], n[c, "unviable"]) }
    }'
  local gc gt gm gu
  gc=$(wc -l < "$tmp/gated-caught" | tr -d ' '); gt=$(wc -l < "$tmp/gated-timeout" | tr -d ' ')
  gm=$(wc -l < "$tmp/gated-missed" | tr -d ' '); gu=$(wc -l < "$tmp/gated-unviable" | tr -d ' ')
  awk -v c="$gc" -v t="$gt" -v m="$gm" -v u="$gu" 'BEGIN {
    s = c + t + m
    printf "| **gated files** | %d | %d | %d | %d | %s |\n", c, t, m, u, s ? sprintf("%.1f %%", 100 * (c + t) / s) : "-"
  }'
  if [ "$gm" -gt 0 ] || [ "$gt" -gt 0 ]; then
    echo
    echo "Missed or timed out in a gated file (a timeout there is a loop no test ends, or a test too slow to tell):"
    echo '```'
    cat "$tmp/gated-missed" "$tmp/gated-timeout"
    echo '```'
    echo "::error::the gated files have $gm missed and $gt timed-out mutants" >&2
    return 1
  fi
}

case "${1:-}" in
  exclusions) shift; exclusions "$@" ;;
  results) shift; results "$@" ;;
  *) echo "usage: $0 exclusions [--write] | results DIR..." >&2; exit 2 ;;
esac
