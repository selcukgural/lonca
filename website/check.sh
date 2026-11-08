#!/usr/bin/env bash
# The site's own check, run by .github/workflows/docs.yml before the build:
# every page in docs/guide is in the sidebar, so a new guide page can not be
# left off the site. (Broken links and anchors fail the build itself.)
set -euo pipefail
cd "$(dirname "$0")/.."

fail=0
while IFS= read -r f; do
  id=${f#docs/}
  id=${id%.md}
  grep -q "id: '$id'" website/sidebars.js || {
    printf 'not in website/sidebars.js: %s\n' "$f" >&2
    fail=1
  }
done < <(find docs/guide -type f -name '*.md' | sort)

[ "$fail" -eq 0 ] || exit 1
echo "website/check.sh: ok"
