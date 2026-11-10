# Backup, verification of a bundle, and a restore onto another daemon.
source "$ACC_LIB"
standard_setup
ok lonca session start --repo demo --agent claude --paths 'src/**' --workspace "$HOME/ws/claude"
trunk=$(git -C "$STORE/demo.git" rev-parse main)
oplog=$(git -C "$STORE/demo.git" rev-parse refs/lonca/oplog)

criterion A21 "backup writes one bundle per repository, private to the daemon's user, and the bundle audits"
ok lonca backup --out "$HOME/usb"
has '^demo: .*demo-[0-9]+\.bundle \(operations 0\.\.=[0-9]+, head [0-9a-f]+\)'
bundle=$(ls "$HOME"/usb/demo-*.bundle)
[ -f "$bundle" ] || fail "no bundle in --out"
ls "$HOME"/.lonca/backups/demo-*.bundle >/dev/null || fail "no bundle in the daemon's backups"
mode=$(ls -l "$bundle" | cut -c1-10)
[ "$mode" = "-rw-r-----" ] || fail "bundle mode $mode, expected -rw-r-----"
git init -q --bare "$HOME/x.git"
git -C "$HOME/x.git" fetch -q "$bundle" '+refs/*:refs/*' || fail "fetch from the bundle"
ok lonca-audit verify "$HOME/x.git"
has '^ok$'

criterion A22 "a restore never replaces an existing repository"
refused lonca restore demo --from "$bundle"
has 'a restore never replaces a repository'

criterion A23 "a restore onto a new daemon gives the same trunk and log, and work continues after daemon-key recover"
start_daemon --home "$HOME/second"
export LONCA_SOCKET="$HOME/second/lonca.sock"
ok lonca restore demo --from "$bundle"
[ "$(git -C "$HOME/second/repos/demo.git" rev-parse main)" = "$trunk" ] ||
    fail "restored trunk differs"
[ "$(git -C "$HOME/second/repos/demo.git" rev-parse refs/lonca/oplog)" = "$oplog" ] ||
    fail "restored log differs"
ok lonca daemon-key recover --repo demo
ok lonca session start --repo demo --agent codex --paths 'src/**' --workspace "$HOME/ws/codex"
ok lonca-audit verify "$HOME/second/repos/demo.git"
has '^ok$'
