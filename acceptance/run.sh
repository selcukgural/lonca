#!/usr/bin/env bash
# Lonca's acceptance tests: what a user does with the released binaries,
# end to end, against real `lonca daemon` processes. The criteria and the
# rules for keeping them are in docs/acceptance.md.
#
#   acceptance/run.sh                          # target/release, every scenario
#   acceptance/run.sh --bin target/debug       # another build
#   acceptance/run.sh --bin ./unpacked 03 05   # some scenarios (by prefix)
#   acceptance/run.sh --check                  # catalogue and scenarios agree
#
# --version X.Y.Z is the version the binaries must say (default: the
# workspace's, from Cargo.toml). --keep keeps every scenario's home; a
# failed one's is always kept. ACC_TMP is where homes go (default /tmp:
# Unix socket paths must stay short).
#
# Exit status: 0 when every criterion passed, 1 otherwise, 2 on usage.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(dirname "$here")
bin="$root/target/release"
version=""
keep=""
check_only=""
picks=()

usage() {
    sed -n '2,16s/^# \{0,1\}//p' "$0" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
    --bin)
        [ $# -ge 2 ] || usage
        bin="$2"
        shift 2
        ;;
    --version)
        [ $# -ge 2 ] || usage
        version="$2"
        shift 2
        ;;
    --keep)
        keep=1
        shift
        ;;
    --check)
        check_only=1
        shift
        ;;
    -h | --help) usage ;;
    -*) usage ;;
    *)
        picks+=("$1")
        shift
        ;;
    esac
done

# The catalogue (docs/acceptance.md) and the scenarios claim the same
# criteria: every automated row `| Annn | ... | scenario |` is proved by a
# `criterion Annn` line in that scenario, and no scenario proves a criterion
# the catalogue lacks. Manual rows (Mnnn) are not scripted.
check_catalogue() {
    local doc="$root/docs/acceptance.md" bad=0
    local listed claimed
    listed=$(sed -n 's/^| \(A[0-9][0-9]*\) | .* | `\([0-9a-z-]*\)` |$/\1 \2/p' "$doc" | sort)
    claimed=$(cd "$here/scenarios" && grep -o '^criterion A[0-9][0-9]*' -- *.sh |
        sed 's/^\(.*\)\.sh:criterion \(A[0-9]*\)$/\2 \1/' | sort)
    if [ -z "$listed" ]; then
        echo "check: docs/acceptance.md lists no automated criterion" >&2
        return 1
    fi
    local dup
    dup=$(printf '%s\n' "$listed" | cut -d' ' -f1 | uniq -d)
    if [ -n "$dup" ]; then
        echo "check: listed twice in docs/acceptance.md: $dup" >&2
        bad=1
    fi
    dup=$(printf '%s\n' "$claimed" | cut -d' ' -f1 | uniq -d)
    if [ -n "$dup" ]; then
        echo "check: proved twice by the scenarios: $dup" >&2
        bad=1
    fi
    local only
    only=$(comm -23 <(printf '%s\n' "$listed") <(printf '%s\n' "$claimed"))
    if [ -n "$only" ]; then
        echo "check: in docs/acceptance.md but no scenario proves it there:" >&2
        printf '  %s\n' "$only" >&2
        bad=1
    fi
    only=$(comm -13 <(printf '%s\n' "$listed") <(printf '%s\n' "$claimed"))
    if [ -n "$only" ]; then
        echo "check: proved by a scenario but not in docs/acceptance.md (or under another scenario):" >&2
        printf '  %s\n' "$only" >&2
        bad=1
    fi
    [ "$bad" -eq 0 ] && echo "check: $(printf '%s\n' "$listed" | wc -l | tr -d ' ') criteria, catalogue and scenarios agree"
    return "$bad"
}

if [ -n "$check_only" ]; then
    check_catalogue
    exit $?
fi
check_catalogue || exit 1

bin=$(cd "$bin" 2>/dev/null && pwd) || {
    echo "acceptance: no such directory: $bin (build: cargo build --release -p lonca -p lonca-audit)" >&2
    exit 2
}
for b in lonca lonca-audit; do
    [ -x "$bin/$b" ] || {
        echo "acceptance: $bin/$b is missing" >&2
        exit 2
    }
done
if [ -z "$version" ]; then
    version=$(sed -n 's/^version = "\(.*\)"$/\1/p' "$root/Cargo.toml" | head -n 1)
fi

tmp=$(mktemp -d "${ACC_TMP:-/tmp}/la.XXXXXX")
echo "acceptance: $bin (expecting $version), homes in $tmp"

passed=0
failed=0
failures=""
for script in "$here"/scenarios/*.sh; do
    name=$(basename "$script" .sh)
    if [ ${#picks[@]} -gt 0 ]; then
        hit=""
        for p in "${picks[@]}"; do
            case "$name" in "$p"*) hit=1 ;; esac
        done
        [ -n "$hit" ] || continue
    fi
    home="$tmp/${name%%-*}"
    mkdir "$home"
    start=$(date +%s)
    echo "== $name"
    if ACC_BIN="$bin" ACC_HOME="$home" ACC_VERSION="$version" ACC_LIB="$here/lib.sh" \
        bash "$script" >"$home.log" 2>&1; then
        sed 's/^/   /' "$home.log" | grep -E '^   +A[0-9]+ ' || true
        echo "   pass ($(($(date +%s) - start)) s)"
        passed=$((passed + 1))
        [ -n "$keep" ] || rm -rf -- "${tmp:?}/${name%%-*}" "${tmp:?}/${name%%-*}.log"
    else
        sed 's/^/   /' "$home.log"
        echo "   FAILED; its home: $home"
        failed=$((failed + 1))
        failures="$failures $name"
    fi
done

if [ $((passed + failed)) -eq 0 ]; then
    echo "acceptance: no scenario matches: ${picks[*]:-}" >&2
    exit 2
fi
if [ "$failed" -eq 0 ]; then
    [ -n "$keep" ] || rmdir "$tmp" 2>/dev/null || true
    echo "acceptance: $passed scenario(s) passed"
    exit 0
fi
echo "acceptance: $failed of $((passed + failed)) scenario(s) failed:$failures"
exit 1
