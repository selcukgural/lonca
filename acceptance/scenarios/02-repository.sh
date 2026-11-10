# A human and a repository imported from Git.
source "$ACC_LIB"
start_daemon

criterion A03 "a human key is made and becomes the default identity"
ok lonca human keygen ayse
has '^ayse: ed25519 [0-9a-f]{64}'
[ -f "$HOME/.config/lonca/humans/ayse.key" ] || fail "no key file"
ok lonca human whoami
has '^ayse: ed25519 [0-9a-f]{64}'

criterion A04 "init --import keeps the branch: trunk is the imported commit"
make_project "$HOME/src/shop"
head=$(git -C "$HOME/src/shop" rev-parse HEAD)
ok lonca init demo --import "$HOME/src/shop"
has '^#0 allow'
[ "$(git -C "$STORE/demo.git" rev-parse main)" = "$head" ] || fail "trunk is not $head"
ok lonca status --repo demo
has "^trunk +$head"
refused lonca init demo
has 'exists'
