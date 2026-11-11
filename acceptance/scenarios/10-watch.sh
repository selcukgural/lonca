# A runner wakes an idle agent: `lonca events --watch` with the human session.
source "$ACC_LIB"
standard_setup

session_of() {
    sed -n 's/^session \(ses_[0-9a-f]*\);.*/\1/p' <<<"$OUT" | head -n 1
}
ok lonca session start --repo demo --agent claude --paths 'src/**' --workspace "$HOME/ws/claude"
claude=$(session_of)
ok lonca session start --repo demo --agent codex --paths 'src/**' --workspace "$HOME/ws/codex"
codex=$(session_of)
cd "$HOME/ws/claude"
ok lonca lease acquire 'src/billing.rs#Client.charge' -i 'reject bad amounts'
set=$(sed -n 's/^lease set \(lse_[0-9a-f]*\).*/\1/p' <<<"$OUT" | head -n 1)
[ -n "$set" ] || fail "no lease set in: $OUT"

criterion A30 "a runner's lonca events --watch wakes on a lease handed over between two sessions, and the agent is still told"
cd "$HOME"
ok lonca status --repo demo --json
from=$(sed -n 's/.*"next_seq": *\([0-9][0-9]*\).*/\1/p' <<<"$OUT" | head -n 1)
[ -n "$from" ] || fail "no next_seq in status"
lonca events --watch --json --repo demo --session "$codex" --from "$from" --wait 20 \
    >"$HOME/watch.out" 2>&1 &
watcher=$!
sleep 1
kill -0 "$watcher" 2>/dev/null || { OUT=$(cat "$HOME/watch.out"); fail "the watcher did not wait"; }
cd "$HOME/ws/claude"
yield='{"thread":"t1","to_session":"'"$codex"'","message":{"type":"yield","set":"'"$set"'","to":"'"$codex"'"}}'
mcp() {
    printf '%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"negotiate","arguments":'"$yield"'}}' |
        lonca mcp
}
ok mcp
has '\\"outcome\\": \\"allow\\"'
wait "$watcher" || { OUT=$(cat "$HOME/watch.out"); fail "the watcher failed"; }
OUT=$(cat "$HOME/watch.out")
no_panic
has '"kind":"lease_received"'
has '"session":"'"$codex"'"'
has '"from":"'"$claude"'"'
lacks '"thread"'
cd "$HOME/ws/codex"
ok lonca events
has '"kind":"lease_received"'
has "\"set\":\"$set\""

criterion A31 "lonca events --watch --follow prints a line per event and stops when every named session has ended"
cd "$HOME"
lonca events --watch --follow --json --repo demo --session "$codex" --from "$from" --wait 20 \
    >"$HOME/follow.out" 2>&1 &
follower=$!
sleep 1
cd "$HOME/ws/codex"
ok lonca session end
for i in $(seq 1 200); do
    kill -0 "$follower" 2>/dev/null || break
    sleep 0.1
done
if kill -0 "$follower" 2>/dev/null; then
    kill "$follower"
    OUT=$(cat "$HOME/follow.out")
    fail "--follow did not stop when its session ended"
fi
wait "$follower" || { OUT=$(cat "$HOME/follow.out"); fail "--follow failed"; }
OUT=$(cat "$HOME/follow.out")
no_panic
has '^\{"session":"'"$codex"'","kind":"lease_received",'
has '^\{"session":"'"$codex"'","kind":"ended","reason":"'
