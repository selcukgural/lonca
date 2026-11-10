#!/usr/bin/env bash
# The demo in the README: two agents on one file, a lease that is held, a
# write outside a session's paths, approval, and the audit.
#
# Every line of output is what the installed `lonca` and `lonca-audit` print;
# nothing is canned. It runs in a home of its own (LONCA_DEMO_HOME, default
# /tmp/lonca-demo, which must not exist) and touches nothing else. The
# daemon it starts is stopped when it ends.
#
#   docs/demo/demo.sh                 # watch it
#   docs/demo/record.sh               # record it (asciinema, agg)
#
# DEMO_FAST=1 drops the typing and the pauses (a check that it still runs).
set -euo pipefail

DEMO_HOME="${LONCA_DEMO_HOME:-/tmp/lonca-demo}"
mkdir "$DEMO_HOME" || {
    echo "demo: $DEMO_HOME exists; remove it or set LONCA_DEMO_HOME" >&2
    exit 1
}
export HOME="$DEMO_HOME" LC_ALL=C GIT_PAGER=cat PAGER=cat
unset LONCA_HOME LONCA_SOCKET LONCA_HUMANS LONCA_HUMAN LONCA_BACKUPS \
    LONCA_WORKSPACE LONCA_TOKEN_FILE

DAEMON=""
trap '[ -n "$DAEMON" ] && kill "$DAEMON" 2>/dev/null || true' EXIT

# A project to import: one file, one type, two methods.
mkdir -p "$HOME/src/shop/src"
cd "$HOME/src/shop"
cat > src/billing.rs <<'RUST'
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
echo "# shop" > README.md
git init -q -b main .
git add -A
git -c user.name=ayse -c user.email=ayse@example.com commit -q -m "billing"
cd "$HOME"

pause() { [ -n "${DEMO_FAST:-}" ] || sleep "$1"; }

prompt() {
    local dir="${PWD/#$HOME/\~}"
    printf '\033[1;34m%s\033[0m \033[1m$\033[0m ' "$dir"
}

typed() {
    local text="$1" i
    for ((i = 0; i < ${#text}; i++)); do
        printf '%s' "${text:i:1}"
        pause 0.025
    done
}

# A comment, typed at the prompt.
note() {
    prompt
    printf '\033[2m'
    typed "# $1"
    printf '\033[0m\n'
    pause 0.8
}

# A command, typed and run. A refusal (exit 1) is part of the demo.
run() {
    prompt
    typed "$1"
    pause 0.4
    printf '\n'
    eval "$1" || true
    pause "${2:-1.2}"
}

clear
note "The gatekeeper, a human, and a repository imported from Git."
run 'lonca daemon &' 1.5
DAEMON=$!
run 'lonca human keygen ayse'
run 'lonca init demo --import ~/src/shop'

note "Two agents, each with a session and a workspace of its own."
run "lonca session start --repo demo --agent claude --paths 'src/**' --workspace ~/ws/claude"
run "lonca session start --repo demo --agent codex --paths 'src/**' --workspace ~/ws/codex"

note "claude leases the method it will edit."
run 'cd ~/ws/claude' 0.3
run 'lonca symbols src/billing.rs'
run "lonca lease acquire 'src/billing.rs#Client.charge' -i 'reject bad amounts'"

note "codex wants the same method: refused. Another one in the same file is free."
run 'cd ~/ws/codex' 0.3
run "lonca lease acquire 'src/billing.rs#Client.charge' -i 'logging'" 3
run "lonca lease acquire 'src/billing.rs#Client.refund' -i 'refund guard'"

note "codex edits its method, and a file outside its paths."
run "perl -pi -e 's/\\+= amount/+= amount.max(0)/' src/billing.rs" 0.5
run 'echo "# shop, by codex" > README.md' 0.5
run "lonca propose -i 'safer refund' --edits 'src/billing.rs#Client.refund'" 3
run 'git checkout -q README.md' 0.5
run "lonca propose -i 'safer refund' --edits 'src/billing.rs#Client.refund'" 2

note "claude edits and proposes too."
run 'cd ~/ws/claude' 0.3
run "perl -pi -e 's/amount > self/amount <= 0 || amount > self/' src/billing.rs" 0.5
run "lonca propose -i 'safer charge' --edits 'src/billing.rs#Client.charge'" 2

note "The human reviews. Both changes merge: same file, different methods."
run 'cd' 0.3
run 'lonca pending --repo demo' 2.5
run 'lonca approve 7 --repo demo'
run 'lonca approve 8 --repo demo'
run "git -C ~/.lonca/repos/demo.git log --format='%h %an: %s' main" 2.5

note "Every decision is in a signed log. The auditor replays all of it."
run 'lonca log --repo demo | tail -n 5' 2.5
run 'lonca-audit verify ~/.lonca/repos/demo.git' 4
