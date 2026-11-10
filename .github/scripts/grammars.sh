#!/usr/bin/env bash
# Where every grammar of the build stands (#248; docs/decisions.md,
# "Grammar updates").
#
#   grammars.sh
#       Prints a Markdown table: each grammar crate of `Cargo.lock`, its
#       version there, the newest on crates.io, the newest tag upstream, and
#       what upstream has past that tag (commits, and which of them touch the
#       grammar or its scanner). A grammar copied into the workspace
#       (`crates/lonca-tree-sitter-<x>`) is compared as `tree-sitter-<x>`.
#
# Reads only: crates.io and the GitHub API (`gh`, logged in or GH_TOKEN),
# and needs `jq`. Nothing of this repository is sent.
set -euo pipefail
export LC_ALL=C

root=$(git rev-parse --show-toplevel)

# `name version` of every grammar in the lock file, the core library first.
locked() {
  awk '$1 == "name" { gsub(/"/, "", $3); name = $3 }
       $1 == "version" && name ~ /^(lonca-)?tree-sitter(-|$)/ {
         gsub(/"/, "", $3)
         if (name != "tree-sitter-language") print name, $3
       }' "$root/Cargo.lock" | sort
}

crate() {
  curl -fsS -A "grammars.sh" "https://crates.io/api/v1/crates/$1"
}

echo "| Crate | In the build | crates.io | Upstream tag | Upstream past the tag |"
echo "| --- | --- | --- | --- | --- |"
locked | while read -r name version; do
  upstream=${name#lonca-}
  info=$(crate "$upstream")
  newest=$(jq -r '.crate.max_stable_version' <<<"$info")
  released=$(jq -r --arg v "$newest" \
    '.versions[] | select(.num == $v) | .created_at[:10]' <<<"$info")
  repo=$(jq -r '.crate.repository' <<<"$info" | sed -E 's#https://github.com/##; s#(\.git|/)$##')
  # The newest tag that is a plain version, with or without a `v`.
  tag=$(gh api "repos/$repo/tags?per_page=100" --jq \
    '[.[].name | select(test("^v?[0-9]+\\.[0-9]+\\.[0-9]+$"))][0] // ""')
  branch=$(gh api "repos/$repo" --jq .default_branch)
  if [ -z "$tag" ]; then
    past="no version tag"
  else
    past=$(gh api "repos/$repo/compare/$tag...$branch" --jq '
      ([.files[]?.filename
        | select(test("(^|/)(grammar\\.js|scanner\\.cc?)$|^common/"))]
       | unique | join(", ")) as $touched
      | if .ahead_by == 0 then "nothing"
        elif $touched == "" then "commits: \(.ahead_by), none to the grammar"
        else "commits: \(.ahead_by); changed: \($touched)" end')
    # The library's main branch is its next version, not fixes to this one.
    [ "$name" != tree-sitter ] || past="-"
  fi
  [ "$name" = "$upstream" ] || version="$version (our copy)"
  echo "| \`$name\` | $version | $newest ($released) | ${tag:-none} | $past |"
  sleep 1
done
