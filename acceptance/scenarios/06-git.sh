# A Lonca repository on a plain Git remote.
source "$ACC_LIB"
standard_setup
ok lonca session start --repo demo --agent claude --paths 'src/**' --workspace "$HOME/ws/claude"
cd "$HOME/ws/claude"
ok lonca lease acquire 'src/billing.rs#Client.charge' -i 'reject bad amounts'
edit src/billing.rs 's/amount > self/amount <= 0 || amount > self/'
ok lonca propose -i 'safer charge' --edits 'src/billing.rs#Client.charge'
proposal=$(seq_of)
cd "$HOME"
ok lonca approve "$proposal" --repo demo
landed() { trunk_file src/billing.rs | grep -q 'amount <= 0'; }
eventually "the change in trunk" landed

criterion A19 "push sends trunk, log and policy; a plain git clone gets trunk and the remote audits"
git init -q --bare "$HOME/remote.git"
ok lonca push "$HOME/remote.git" --repo demo
for ref in refs/heads/main refs/lonca/oplog refs/lonca/policy; do
    git -C "$HOME/remote.git" rev-parse -q --verify "$ref" >/dev/null ||
        fail "the remote has no $ref"
done
git clone -q "$HOME/remote.git" "$HOME/clone" || fail "git clone"
grep -q 'amount <= 0' "$HOME/clone/src/billing.rs" || fail "the clone lacks the change"
ok lonca-audit verify "$HOME/remote.git"
has '^ok$'

criterion A20 "lonca-audit compare accepts the published log and catches a local log rewound after the push"
ok lonca-audit compare "$STORE/demo.git" "$HOME/remote.git"
cp -R "$HOME/remote.git" "$HOME/rewound.git"
first=$(git -C "$HOME/rewound.git" rev-list --max-parents=0 refs/lonca/oplog)
git -C "$HOME/rewound.git" update-ref refs/lonca/oplog "$first"
exits 1 lonca-audit compare "$HOME/rewound.git" "$HOME/remote.git"
lacks '^ok' 
