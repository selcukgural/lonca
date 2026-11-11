# Which session works in a directory is the log's word, not the directory's.
source "$ACC_LIB"
standard_setup
ws="$HOME/ws/cc"
ok lonca session start --repo demo --agent cc --paths 'src/**' --workspace "$ws" --harness claude-code
mine=$(sed -n 's/^session \(ses_[0-9a-f]*\);.*/\1/p' <<<"$OUT")
[ -n "$mine" ] || fail "no session id"
cd "$ws"

hook() {
    printf '%s' "$1" | lonca hook
}
event() {
    printf '{"hook_event_name":"PreToolUse","session_id":"%s","cwd":"%s","tool_name":"Write","tool_input":{"file_path":"%s"}}' "$1" "$2" "$3"
}

criterion A34 "the hook asks the log where its session is: a workspace record moved away blocks, and the hook follows its harness session out of the workspace"
ok hook '{"hook_event_name":"SessionStart","session_id":"h1","cwd":"'"$ws"'"}'
ok hook "$(event h1 "$ws" "$ws/src/new.rs")"
lacks 'deny'
mv .lonca/workspace.json .lonca/moved
exits 2 hook "$(event h1 "$ws" "$ws/src/new.rs")"
has "workspace of session $mine"
exits 2 hook "$(event h1 "$ws/src" "$ws/src/new.rs")"
mv .lonca/moved .lonca/workspace.json
ok hook "$(event h1 "$ws" "$ws/src/new.rs")"
lacks 'deny'
# Its harness session elsewhere is still this session.
ok hook "$(event h1 "$HOME" "$HOME/elsewhere.md")"
has 'writes outside the workspace are not allowed'
# Another harness session, in a directory no session was started in.
ok hook "$(event h2 "$HOME/src" "$HOME/src/x.md")"
[ -z "$OUT" ] || fail "the hook answered where Lonca has no session"

criterion A35 "--continue takes the session from the log; one directory holds one live session; a human does not propose from an agent's workspace"
ok lonca session start --repo demo --agent other --paths 'src/**' --workspace "$HOME/ws/other"
other=$(sed -n 's/^session \(ses_[0-9a-f]*\);.*/\1/p' <<<"$OUT")
refused lonca session start --repo demo --agent third --paths 'src/**' --workspace "$ws/sub"
has 'workspace_in_use'
edit .lonca/workspace.json "s/$mine/$other/"
grep -q "$other" .lonca/workspace.json || fail "the record was not edited"
ok lonca session start --repo demo --agent cc --paths 'src/**' --continue "$ws"
has "^continues $mine\$"
edit src/billing.rs 's/\+= amount/+= amount.max(0)/'
edit .lonca/workspace.json 's/"session": *"ses_[0-9a-f]+"/"session": null/'
grep -Eq '"session": *null' .lonca/workspace.json || fail "the record was not edited"
exits 3 lonca propose -i 'guard the amount'
has 'is the workspace of agent session ses_'
