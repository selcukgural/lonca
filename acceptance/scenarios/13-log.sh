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
