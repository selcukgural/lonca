# Keyed directories: a migration's version is reserved like a name, so two
# agents can not take one, and two changes that would land one are a
# conflict.
source "$ACC_LIB"
standard_setup
ok lonca policy show --repo demo
mkdir -p "$HOME/policy"
printf '%s\n' "$OUT" | awk -v d="$HOME/policy" '
    /^==> lonca.toml <==$/ { f = d "/lonca.toml"; next }
    /^==> policy.cedar <==$/ { f = d "/policy.cedar"; next }
    { print > f }'
cat >>"$HOME/policy/lonca.toml" <<'TOML'

[paths.keyed]
"db/migration" = '^V(\d+)__'
TOML
ok lonca policy set --repo demo --config "$HOME/policy/lonca.toml" --policy "$HOME/policy/policy.cedar"
for a in claude codex; do
    ok lonca session start --repo demo --agent "$a" --paths 'db/**' --workspace "$HOME/ws/$a"
done

criterion A27 "next reserves the next free key of a keyed directory, and another agent can not take it"
cd "$HOME/ws/claude"
ok lonca lease acquire 'db/migration#<dir>' --kind insert --name next -i 'users table'
has '^keys db/migration#<dir>: 1$'
cd "$HOME/ws/codex"
refused lonca lease acquire 'db/migration#<dir>' --kind insert --name 1 -i 'orders table'
has 'lease_held:db/migration#<dir>'
ok lonca lease acquire 'db/migration#<dir>' --kind insert --name next -i 'orders table'
has '^keys db/migration#<dir>: 2$'

criterion A28 "a new file in a keyed directory needs its key reserved, and lands with it"
mkdir -p db/migration
echo 'create table orders (id int);' >db/migration/V1__orders.sql
ok lonca lease acquire 'db/migration/V1__orders.sql#<file>' -i 'orders table'
refused lonca propose -i 'orders table' --accept-facts
has 'key_not_reserved:db/migration#1'
rm db/migration/V1__orders.sql
echo 'create table orders (id int);' >db/migration/V2__orders.sql
ok lonca lease acquire 'db/migration/V2__orders.sql#<file>' -i 'orders table'
ok lonca propose -i 'orders table' --accept-facts
orders=$(seq_of)
cd "$HOME/ws/claude"
mkdir -p db/migration
echo 'create table users (id int);' >db/migration/V1__users.sql
ok lonca lease acquire 'db/migration/V1__users.sql#<file>' -i 'users table'
ok lonca propose -i 'users table' --accept-facts
users=$(seq_of)
cd "$HOME"
ok lonca approve "$orders" --repo demo
ok lonca approve "$users" --repo demo
in_trunk() { trunk_file "$1" >/dev/null 2>&1; }
eventually "orders in trunk" in_trunk db/migration/V2__orders.sql
eventually "users in trunk" in_trunk db/migration/V1__users.sql

criterion A29 "a key a file on trunk has is refused, and two changes that land one key conflict"
cd "$HOME/ws/codex"
ok lonca sync
ok lonca lease acquire 'db/migration#<dir>' --kind insert --name next -i 'more orders'
has '^keys db/migration#<dir>: 3$'
echo 'alter table orders add total int;' >db/migration/V01__more_orders.sql
ok lonca lease acquire 'db/migration/V01__more_orders.sql#<file>' -i 'more orders'
refused lonca propose -i 'more orders' --accept-facts
has 'key_taken:db/migration#1'
rm db/migration/V01__more_orders.sql
echo 'alter table orders add total int;' >db/migration/V3__more_orders.sql
ok lonca lease acquire 'db/migration/V3__more_orders.sql#<file>' -i 'more orders'
ok lonca propose -i 'more orders' --accept-facts
agent=$(seq_of)
cd "$HOME/src/shop"
ok lonca fetch --repo demo
git merge -q --ff-only refs/lonca/trunk || fail "trunk does not fast-forward the checkout"
echo 'select 3;' >db/migration/V3__by_hand.sql
git add db/migration/V3__by_hand.sql
git commit -q -m 'a migration by hand'
ok lonca propose --commit HEAD
cd "$HOME"
eventually "the person's V3 in trunk" in_trunk db/migration/V3__by_hand.sql
ok lonca approve "$agent" --repo demo
conflicted() {
    ok lonca log --repo demo
    grep -q 'conflict:db/migration#3' <<<"$OUT"
}
eventually "the agent's V3 conflicted on the key" conflicted
in_trunk db/migration/V3__more_orders.sql && fail "two files with key 3 in trunk"
ok lonca-audit verify "$STORE/demo.git"
