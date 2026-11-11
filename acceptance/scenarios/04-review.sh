# What a human does to agents' work: reject, undo, freeze, read its diff; and
# a human's own change from a plain git checkout.
source "$ACC_LIB"
standard_setup
ok lonca session start --repo demo --agent claude --paths 'src/**' --workspace "$HOME/ws/claude"
cd "$HOME/ws/claude"
ok lonca lease acquire 'src/billing.rs#Client.charge' -i 'reject bad amounts'
trunk_has() { trunk_file src/billing.rs | grep -q -- "$1"; }
trunk_lacks() { ! trunk_has "$1"; }

criterion A12 "a rejected proposal does not land and its agent reads the reason"
edit src/billing.rs 's/amount > self/amount < 0 || amount > self/'
ok lonca propose -i 'negative amounts' --edits 'src/billing.rs#Client.charge'
proposal=$(seq_of)
cd "$HOME"
ok lonca reject "$proposal" --reason "zero is bad too" --repo demo
cd "$HOME/ws/claude"
ok lonca events
has '"kind":"rejected".*"target_seq":'"$proposal"',"reason":"zero is bad too"'
if trunk_has 'amount < 0'; then fail "a rejected change is in trunk"; fi
ok lonca pending --repo demo
lacks "^#$proposal "

criterion A13 "undo is a compensating change: trunk goes back, the log only grows"
git checkout -q src/billing.rs
ok lonca lease acquire 'src/billing.rs#Client.charge' -i 'reject bad amounts, zero included'
edit src/billing.rs 's/amount > self/amount <= 0 || amount > self/'
ok lonca propose -i 'safer charge' --edits 'src/billing.rs#Client.charge'
proposal=$(seq_of)
cd "$HOME"
ok lonca approve "$proposal" --repo demo
approval=$(seq_of)
eventually "the change in trunk" trunk_has 'amount <= 0 || amount > self'
ok lonca log --repo demo
integrate=$(sed -n 's/^\([0-9][0-9]*\) change\.integrate .*allow.*/\1/p' <<<"$OUT" | tail -n 1)
[ -n "$integrate" ] || fail "no change.integrate in the log"
before="$OUT"
ok lonca undo "$integrate" --repo demo
eventually "trunk back" trunk_lacks 'amount <= 0'
ok lonca log --repo demo
case "$OUT" in "$before"*) ;; *) fail "the log before the undo is not a prefix of the log after it" ;; esac
[ "$OUT" != "$before" ] || fail "undo appended nothing"
exits 3 lonca undo "$approval" --repo demo
has 'can not be undone automatically'

criterion A14 "a frozen repository refuses agents' work with the reason; unfreeze resumes it"
ok lonca freeze --repo demo "release check"
cd "$HOME/ws/claude"
refused lonca lease acquire 'src/billing.rs#Client.refund' -i 'while frozen'
has 'frozen:release check'
cd "$HOME"
ok lonca unfreeze --repo demo "done"
cd "$HOME/ws/claude"
ok lonca lease acquire 'src/billing.rs#Client.refund' -i 'after the freeze'

criterion A15 "a human's git checkout: fetch trunk, commit, propose the commit, it lands"
cd "$HOME/src/shop"
ok lonca fetch --repo demo
has '^refs/lonca/trunk -> '
git merge -q --ff-only refs/lonca/trunk || fail "trunk does not fast-forward the checkout"
echo "# shop, by ayse" >README.md
git commit -qam "readme"
ok lonca propose --commit HEAD
readme_in_trunk() { [ "$(trunk_file README.md)" = "# shop, by ayse" ]; }
eventually "the human's commit in trunk" readme_in_trunk
ok lonca fetch
[ "$(git rev-parse refs/lonca/trunk)" = "$(git -C "$STORE/demo.git" rev-parse main)" ] ||
    fail "refs/lonca/trunk is not trunk"

criterion A36 "the reviewer's diff shows every changed file, also beside files whose names are git patterns"
cd "$HOME/ws/claude"
ok lonca session end
cd "$HOME"
ok lonca session start --repo demo --agent codex --paths '**' --workspace "$HOME/ws/codex"
cd "$HOME/ws/codex"
ok lonca lease acquire 'src/billing.rs#Client.refund' ':!src/billing.rs#<file>' 'src/*#<file>' -i 'refund guard'
edit src/billing.rs 's/\+= amount/+= amount.max(0)/'
mkdir ':!src'
echo "not a pattern" >':!src/billing.rs'
echo "not a pattern" >'src/*'
ok lonca propose -i 'refund guard' --accept-facts
ok lonca diff "$(change_of)" --repo demo
has '^\+.*amount\.max\(0\)'
has '^\+\+\+ b/:!src/billing\.rs$'
has '^\+\+\+ b/src/\*$'
