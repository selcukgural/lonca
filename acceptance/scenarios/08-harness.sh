# What a harness gets: its settings, the hook and the MCP server.
source "$ACC_LIB"
standard_setup
ok lonca session start --repo demo --agent cc --paths 'src/**' --workspace "$HOME/ws/cc" --harness claude-code
ws="$HOME/ws/cc"
cd "$ws"

criterion A24 "--harness claude-code writes the MCP server and hooks into the workspace"
has 'wrote \.mcp\.json'
has 'wrote \.claude/settings\.local\.json'
grep -q '"command": "lonca"' .mcp.json || fail ".mcp.json does not run lonca"
grep -q '"mcp"' .mcp.json || fail ".mcp.json does not run lonca mcp"
for event in SessionStart PreToolUse PostToolUse; do
    grep -q "\"$event\"" .claude/settings.local.json || fail "no $event hook"
done
grep -q '"command": "lonca hook"' .claude/settings.local.json || fail "hooks do not run lonca hook"

hook() {
    printf '%s' "$1" | lonca hook
}

criterion A25 "the hook tells the agent the rules at session start and denies writes outside the workspace"
ok hook '{"hook_event_name":"SessionStart","session_id":"h1","cwd":"'"$ws"'"}'
has '"hookEventName":"SessionStart"'
has 'governed by Lonca \(repository demo, session ses_[0-9a-f]+'
ok hook '{"hook_event_name":"PreToolUse","session_id":"h1","cwd":"'"$ws"'","tool_name":"Write","tool_input":{"file_path":"'"$HOME"'/elsewhere.md"}}'
has '"permissionDecision":"deny"'
has 'writes outside the workspace are not allowed'
ok hook '{"hook_event_name":"PreToolUse","session_id":"h1","cwd":"'"$ws"'","tool_name":"Write","tool_input":{"file_path":"'"$ws"'/src/new.rs"}}'
lacks 'deny'

criterion A40 "a link in the workspace is no way out of it: a write through it is denied, a link to the workspace's own directory is not"
mkdir -p "$HOME/outside"
ln -s "$HOME/outside" "$ws/h"
ln -s src "$ws/alias"
ok hook '{"hook_event_name":"PreToolUse","session_id":"h1","cwd":"'"$ws"'","tool_name":"Write","tool_input":{"file_path":"h/.zshrc"}}'
has '"permissionDecision":"deny"'
has 'writes outside the workspace are not allowed \(.*/ws/cc/h/\.zshrc is .*/outside/\.zshrc\)'
ok hook '{"hook_event_name":"PreToolUse","session_id":"h1","cwd":"'"$ws"'/src","tool_name":"Write","tool_input":{"file_path":"../alias/../h/x"}}'
has '"permissionDecision":"deny"'
ok hook '{"hook_event_name":"PreToolUse","session_id":"h1","cwd":"'"$ws"'","tool_name":"Write","tool_input":{"file_path":"alias/new.rs"}}'
lacks 'deny'
rm "$ws/h" "$ws/alias"

criterion A26 "lonca mcp answers initialize with the version and lists the agent's tools; lonca rules prints the rules"
mcp() {
    printf '%s\n' \
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
        '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' | lonca mcp
}
ok mcp
has '"serverInfo":\{"name":"lonca","version":"'"$ACC_VERSION"'"\}'
for tool in status symbols lease_acquire lease_release propose sync events; do
    has '"name":"'"$tool"'"'
done
ok lonca rules
has 'governed by Lonca'
