# Two agents on one file: leases, paths, review, merge, sync, session end.
source "$ACC_LIB"
standard_setup

criterion A05 "a session gets a workspace: a git repository with trunk's files"
ok lonca session start --repo demo --agent claude --paths 'src/**' --workspace "$HOME/ws/claude"
has '^session ses_[0-9a-f]+; workspace '
ok lonca session start --repo demo --agent codex --paths 'src/**' --workspace "$HOME/ws/codex"
for w in claude codex; do
    [ -f "$HOME/ws/$w/src/billing.rs" ] || fail "$w has no src/billing.rs"
    git -C "$HOME/ws/$w" rev-parse --git-dir >/dev/null || fail "$w is not a git repository"
done

criterion A06 "symbols lists a file's methods as lease ids"
cd "$HOME/ws/claude"
ok lonca symbols src/billing.rs
has '^  Client\.charge$'
has '^  Client\.refund$'

criterion A07 "a leased symbol is refused to another agent, naming holder and intent; another symbol of the file is free"
ok lonca lease acquire 'src/billing.rs#Client.charge' -i 'reject bad amounts'
has '^lease set lse_'
cd "$HOME/ws/codex"
refused lonca lease acquire 'src/billing.rs#Client.charge' -i 'logging'
has 'lease_held:src/billing.rs#Client.charge'
has 'claude \(session ses_[0-9a-f]+\) is on src/billing.rs#Client.charge: "reject bad amounts"'
ok lonca lease acquire 'src/billing.rs#Client.refund' -i 'refund guard'

criterion A08 "a proposal with a file outside the session's paths is refused and never pending"
edit src/billing.rs 's/\+= amount/+= amount.max(0)/'
echo "# shop, by codex" >README.md
refused lonca propose -i 'safer refund' --edits 'src/billing.rs#Client.refund'
has 'scope_path:README.md'
denied=$(seq_of)
ok lonca pending --repo demo
lacks "^#$denied "
git checkout -q README.md

criterion A09 "an unobserved session's proposal waits for a human; both agents' changes to one file land"
ok lonca propose -i 'safer refund' --edits 'src/billing.rs#Client.refund'
has 'escalate: unobserved_session'
refund=$(seq_of)
cd "$HOME/ws/claude"
edit src/billing.rs 's/amount > self/amount <= 0 || amount > self/'
ok lonca propose -i 'safer charge' --edits 'src/billing.rs#Client.charge'
charge=$(seq_of)
cd "$HOME"
ok lonca pending --repo demo
has "^#$refund change.propose agent:codex/"
has "^#$charge change.propose agent:claude/"
trunk_has() { trunk_file src/billing.rs | grep -q -- "$1"; }
if trunk_has 'amount.max(0)'; then fail "integrated before approval"; fi
ok lonca approve "$refund" --repo demo
ok lonca approve "$charge" --repo demo
eventually "refund in trunk" trunk_has 'amount.max(0)'
eventually "charge in trunk" trunk_has 'amount <= 0 || amount > self'
ok lonca pending --repo demo
lacks '^#'

criterion A10 "sync brings trunk into a workspace"
cd "$HOME/ws/codex"
ok lonca sync
grep -q 'amount <= 0 || amount > self' src/billing.rs || fail "codex did not get claude's change"

criterion A37 "what an agent wrote is shown on the terminal, never obeyed: control characters in an intent or a file are written out"
ctl=$'tidy\e[2K\e[1A\r#1 change.propose human:ayse'
ok lonca lease acquire 'src/billing.rs#Client.refund' -i "$ctl"
edit src/billing.rs 's/(amount\.max\(0\);)/$1 \/\/ \e[8mhidden\r/'
ok lonca propose -i "$ctl" --accept-facts
tidy=$(seq_of)
change=$(change_of)
cd "$HOME/ws/claude"
refused lonca lease acquire 'src/billing.rs#Client.refund' -i 'mine now'
has 'lease_held:src/billing.rs#Client.refund'
lacks $'[\e\r]'
cd "$HOME"
ok lonca pending --repo demo
lacks $'[\e\r]'
has "^#$tidy change.propose agent:codex/.*tidy\\\\u\\{1b\\}\\[2K\\\\u\\{1b\\}\\[1A\\\\r#1 change.propose human:ayse"
[ "$(grep -c '^#' <<<"$OUT")" = 1 ] || fail "one pending entry is not one line"
ok lonca diff "$change" --repo demo
lacks $'[\e\r]'
has '^\+.*// \\u\{1b\}\[8mhidden\\r$'
ok lonca status --repo demo
lacks $'[\e\r]'
ok lonca reject "$tidy" --reason "no" --repo demo
cd "$HOME/ws/codex"

criterion A11 "an ended session's token is refused"
ok lonca session end
refused lonca lease acquire 'src/billing.rs#Client.charge' -i 'after the end'
has 'unknown session token'
