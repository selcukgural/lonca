# Sourced by every acceptance scenario (docs/acceptance.md). A scenario is a
# user's session with the released binaries: it runs in a home of its own
# ($ACC_HOME, made by run.sh), starts its own `lonca daemon` processes, and
# stops them when it ends. It reads nothing of the developer's account.
#
# Portable to the bash 3.2 macOS ships: no associative arrays, no ${x,,}.
set -euo pipefail

: "${ACC_BIN:?run scenarios through acceptance/run.sh}"
: "${ACC_HOME:?run scenarios through acceptance/run.sh}"

export PATH="$ACC_BIN:$PATH"
export HOME="$ACC_HOME"
export LC_ALL=C GIT_PAGER=cat PAGER=cat GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0
# Nothing of the caller's Lonca, Claude or XDG setup leaks in.
for v in $(compgen -e); do
    case "$v" in
    LONCA_* | XDG_* | ANTHROPIC_* | GIT_DIR | GIT_WORK_TREE | GIT_INDEX_FILE) unset "$v" ;;
    esac
done
cd "$HOME"
git config --global user.name ayse
git config --global user.email ayse@example.com
git config --global init.defaultBranch main

STORE="$HOME/.lonca/repos"
OUT=""
CRITERION="(setup)"
DAEMONS=""

stop_daemons() {
    local p
    for p in $DAEMONS; do
        kill "$p" 2>/dev/null || true
    done
    for p in $DAEMONS; do
        wait "$p" 2>/dev/null || true
    done
}
trap stop_daemons EXIT

say() { printf '%s\n' "$*"; }

# The criterion the following checks prove; its id is in docs/acceptance.md.
criterion() {
    CRITERION="$1"
    say "  $1 $2"
}

fail() {
    say "FAIL $CRITERION: $*" >&2
    if [ -n "$OUT" ]; then
        printf '%s\n' "$OUT" | sed 's/^/    | /' >&2
    fi
    exit 1
}

# A crash is never an answer, whatever the command was expected to do.
no_panic() {
    if grep -q "panicked at" <<<"$OUT"; then
        fail "a panic: $*"
    fi
}

# `ok CMD...`: CMD succeeds. Its stdout and stderr are in $OUT.
ok() {
    local rc=0
    OUT=$("$@" 2>&1) || rc=$?
    no_panic "$@"
    [ "$rc" -eq 0 ] || fail "exit $rc, expected success: $*"
}

# `refused CMD...`: CMD is refused (exit 1, Lonca's denial), not crashed and
# not a usage error.
refused() {
    exits 1 "$@"
}

# `exits N CMD...`: CMD exits with status N.
exits() {
    local want="$1" rc=0
    shift
    OUT=$("$@" 2>&1) || rc=$?
    no_panic "$@"
    [ "$rc" -eq "$want" ] || fail "exit $rc, expected $want: $*"
}

# `has ERE`: $OUT matches the extended regular expression.
has() {
    grep -Eq -- "$1" <<<"$OUT" || fail "output does not match /$1/"
}

# `lacks ERE`: $OUT does not match it.
lacks() {
    if grep -Eq -- "$1" <<<"$OUT"; then
        fail "output matches /$1/"
    fi
}

# The sequence number Lonca printed first ("#7 escalate: ...").
seq_of() {
    sed -n 's/^#\([0-9][0-9]*\) .*/\1/p' <<<"$OUT" | head -n 1
}

# The change id a propose printed ("change <id>").
change_of() {
    sed -n 's/^change \([a-z]*\)$/\1/p' <<<"$OUT" | head -n 1
}

# `eventually DESC CMD...`: CMD succeeds within 20 s (the merge queue works
# in the background).
eventually() {
    local desc="$1" i
    shift
    for i in $(seq 1 200); do
        if OUT=$("$@" 2>&1); then
            return 0
        fi
        sleep 0.1
    done
    fail "not within 20 s: $desc"
}

# `start_daemon [ARGS...]`: a cooperative daemon in the background, ready
# when it returns. Without --home it uses ~/.lonca, as a user's would.
start_daemon() {
    local log
    log="$HOME/daemon-$(date +%s)-$RANDOM.log"
    lonca daemon --no-proxy "$@" >"$log" 2>&1 &
    local pid=$!
    DAEMONS="$DAEMONS $pid"
    local i
    for i in $(seq 1 200); do
        if grep -q "listening on" "$log"; then
            return 0
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            OUT=$(cat "$log")
            fail "the daemon exited"
        fi
        sleep 0.1
    done
    OUT=$(cat "$log")
    fail "the daemon did not listen within 20 s"
}

# A Git project to import: one Rust file with a type and two methods.
make_project() {
    local dir="$1"
    mkdir -p "$dir/src"
    cat >"$dir/src/billing.rs" <<'RUST'
pub struct Client {
    pub balance: i64,
}

impl Client {
    pub fn charge(&mut self, amount: i64) -> bool {
        if amount > self.balance {
            return false;
        }
        self.balance -= amount;
        true
    }

    pub fn refund(&mut self, amount: i64) {
        self.balance += amount;
    }
}
RUST
    echo "# shop" >"$dir/README.md"
    git -C "$dir" init -q
    git -C "$dir" add -A
    git -C "$dir" commit -q -m "billing"
}

# The usual start: a daemon, a human `ayse` and repository `demo` imported
# from ~/src/shop.
standard_setup() {
    start_daemon
    ok lonca human keygen ayse
    make_project "$HOME/src/shop"
    ok lonca init demo --import "$HOME/src/shop"
}

# `edit FILE PERL-EXPR`: an in-place edit, as an agent's editor would make.
edit() {
    perl -pi -e "$2" "$1"
}

# `trunk_file PATH [REPO]`: the file as trunk has it, from the store.
trunk_file() {
    git -C "$STORE/${2:-demo}.git" show "main:$1"
}
