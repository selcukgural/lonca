# Evidence names the toolchain its checks ran with, and the auditor notes a
# check that ran with another one.
source "$ACC_LIB"
# What the daemon has in its environment and the policy passes to the checks.
export SHOP_TOKEN=tok-acc-123456
standard_setup
mkdir -p "$HOME/tools"
tools=$(cd "$HOME/tools" && pwd -P)
tool_version() {
    printf '#!/bin/sh\necho "shoptool %s (stable)"\n' "$1" >"$tools/shoptool"
    chmod +x "$tools/shoptool"
}
tool_version 1.0
ok lonca policy show --repo demo
mkdir -p "$HOME/policy"
printf '%s\n' "$OUT" | awk -v d="$HOME/policy" '
    /^==> lonca.toml <==$/ { f = d "/lonca.toml"; next }
    /^==> policy.cedar <==$/ { f = d "/policy.cedar"; next }
    { print > f }'
TOOLS="$tools" perl -0pi -e '
    s|^# test = "cargo test --offline"$|test = "echo token \$SHOP_TOKEN; test -f src/billing.rs"|m or die "test";
    s|^env_passthrough = \[\]$|env_passthrough = ["SHOP_TOKEN"]|m or die "passthrough";
    s|^path = \[\]$|path = ["$ENV{TOOLS}", "/usr/bin", "/bin"]|m or die "path";
    s|^identify = \[\]$|identify = ["shoptool --version", "no-such-tool --version"]|m or die "identify";
' "$HOME/policy/lonca.toml"
ok lonca policy set --repo demo --config "$HOME/policy/lonca.toml" --policy "$HOME/policy/policy.cedar"
ok lonca session start --repo demo --agent claude --paths 'src/**' --workspace "$HOME/ws/claude"
trunk_has() { trunk_file src/billing.rs | grep -q -- "$1"; }

# `land INTENT PERL-EXPR`: the agent's change to Client.charge, approved,
# in trunk; its change id in $change.
land() {
    cd "$HOME/ws/claude"
    ok lonca sync
    ok lonca lease acquire 'src/billing.rs#Client.charge' -i "$1"
    edit src/billing.rs "$2"
    ok lonca propose -i "$1" --edits 'src/billing.rs#Client.charge'
    local proposal
    proposal=$(seq_of)
    change=$(change_of)
    [ -n "$change" ] || fail "no change id in: $OUT"
    cd "$HOME"
    ok lonca approve "$proposal" --repo demo
}

criterion A32 "the evidence of an integrated change names the toolchain its checks ran with, and a failing identify command fails no check"
land 'reject bad amounts' 's/amount > self/amount <= 0 || amount > self/'
eventually "the change in trunk" trunk_has 'amount <= 0 || amount > self'
ok lonca change "$change" --repo demo --evidence
has '^tests: pass \(exit 0,'
has '^  environment [0-9a-f]{12}$'
has '^    shoptool --version: shoptool 1\.0 \(stable\)$'
has '^    no-such-tool --version: error: exit 127'
ok lonca change "$change" --repo demo
has '"environment": \['
ok lonca-audit verify "$STORE/demo.git"
lacks '^env '
has '^ok$'

criterion A33 "lonca-audit verify notes a check that ran with another toolchain than the last time, and still passes"
tool_version 2.0
land 'cap a single charge' 's/amount <= 0 \|\| amount > self/amount <= 0 || amount > 10_000 || amount > self/'
eventually "the second change in trunk" trunk_has 'amount > 10_000'
ok lonca change "$change" --repo demo --evidence
has '^    shoptool --version: shoptool 2\.0 \(stable\)$'
ok lonca-audit verify "$STORE/demo.git"
has '^env +[0-9]+ tests +changed since [0-9]+$'
has '^ok$'

criterion A45 "a value passed to the checks is not in a check's log: the agent that proposed the change reads *** there"
ok lonca change "$change" --repo demo --evidence
has '^  token \*\*\*$'
lacks 'tok-acc-123456'
