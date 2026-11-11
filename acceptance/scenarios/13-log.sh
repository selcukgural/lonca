# What one caller can add to the log is bounded.
source "$ACC_LIB"
standard_setup
ok lonca session start --repo demo --agent claude --paths 'src/**' --workspace "$HOME/ws/claude"
cd "$HOME/ws/claude"

entries() {
    ok lonca log --repo demo --json
    grep -o '"seq":' <<<"$OUT" | wc -l | tr -d ' '
}

criterion A38 "an operation longer than a log entry holds is refused with its size and what to do, and is not logged; a shorter one goes on"
edit src/billing.rs 's/\+= amount/+= amount.max(0)/'
ok lonca lease acquire 'src/billing.rs#Client.refund' -i 'refund guard'
before=$(entries)
long=$(head -c 70000 /dev/zero | tr '\0' 'x')
refused lonca propose -i "$long" --edits 'src/billing.rs#Client.refund'
has 'change\.propose is [0-9]+ bytes; an entry of the log holds 65536'
has 'Shorten its text and lists, or split it'
[ "$(entries)" = "$before" ] || fail "the refused proposal is in the log"
ok lonca propose -i 'safer refund' --edits 'src/billing.rs#Client.refund'
[ "$(entries)" = "$((before + 1))" ] || fail "the proposal that fits is not one entry"

criterion A39 "policy set --value changes one line of the policy in force, the change takes effect, and a rate past the ceiling is refused"
cd "$HOME"
ok lonca policy show --repo demo
printf '%s\n' "$OUT" >"$HOME/policy.before"
has '^ops_per_minute = 600$'
ok lonca policy set --repo demo --value sessions.ops_per_minute=4
has '^sessions\.ops_per_minute: 600 -> 4$'
ok lonca policy show --repo demo
printf '%s\n' "$OUT" >"$HOME/policy.after"
changed=$(diff "$HOME/policy.before" "$HOME/policy.after" | grep -c '^[<>]' || true)
[ "$changed" = 2 ] || fail "more than one line of the policy changed"
has '^ops_per_minute = 4$'
has '^# What a session, with the sessions made from it, may send the log in a$'
refused lonca policy set --repo demo --value sessions.ops_per_minute=6001
has 'the most is 6000'
exits 3 lonca policy set --repo demo --value ops_per_minute=5
refused lonca policy set --repo demo --value sessions.ops_a_minute=5
ok lonca policy show --repo demo
has '^ops_per_minute = 4$'
# The new rate is in force: a fresh session has four operations a minute.
ok lonca session start --repo demo --agent codex --paths 'src/**' --workspace "$HOME/ws/codex"
cd "$HOME/ws/codex"
limited=0
for i in 1 2 3 4 5 6; do
    OUT=$(lonca lease acquire "src/billing.rs#Client.charge" -i "try $i" 2>&1) || true
    if grep -q 'rate_limited' <<<"$OUT"; then limited=1; fi
done
[ "$limited" = 1 ] || fail "six operations in a row at four a minute, and none was rate_limited"
