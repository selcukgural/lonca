# The auditor replays the log and catches what was changed behind it.
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

criterion A16 "lonca-audit verify passes on the store and doctor says the log verifies"
ok lonca-audit verify "$STORE/demo.git"
has '^ok$'
ok lonca-audit verify "$STORE/demo.git" --json
ok lonca doctor --json
has '"name":"log demo","level":"pass","detail":"[0-9]+ entries verify"'

criterion A17 "an edited log entry fails the audit"
cp -R "$STORE/demo.git" "$HOME/edited.git"
(
    cd "$HOME/edited.git"
    blob=$(git cat-file -p refs/lonca/oplog:op.json |
        sed 's/"time_ms":\([0-9]*\)/"time_ms":1\1/' | git hash-object -w --stdin)
    tree=$(printf '100644 blob %s\top.json\n' "$blob" | git mktree)
    commit=$(git log -1 --format=%B refs/lonca/oplog |
        git commit-tree "$tree" -p refs/lonca/oplog~1)
    git update-ref refs/lonca/oplog "$commit"
)
exits 1 lonca-audit verify "$HOME/edited.git"
has 'FINDING +chain +integrity: op [0-9]+: hash does not match content'
has '^FAILED$'

criterion A18 "trunk moved behind the log's back fails the audit"
cp -R "$STORE/demo.git" "$HOME/moved.git"
git -C "$HOME/moved.git" update-ref refs/heads/main refs/heads/main~1
exits 1 lonca-audit verify "$HOME/moved.git"
has 'FINDING +ref +refs/heads/main is .*the log says'
