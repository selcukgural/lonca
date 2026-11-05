//! Harness profiles: what Lonca needs to know about an agent harness, as
//! data. Which events it sends, what its tools do, and how it wants an answer.
//! A new harness is a table in `lonca.toml`, not a change to Lonca, as long as
//! it can run a command with a JSON event on stdin.
//!
//! The profiles are read by the daemon, from the signed policy. What a tool
//! counts as decides what taints a session, so an agent must not be able to
//! choose it.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const BUILT_IN: &str = include_str!("harnesses.toml");

static PROFILES: LazyLock<BTreeMap<String, Profile>> =
    LazyLock::new(|| toml::from_str(BUILT_IN).expect("built-in harness profiles parse"));

/// The profiles that come with Lonca.
pub fn built_in() -> &'static BTreeMap<String, Profile> {
    &PROFILES
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub events: Events,
    #[serde(default)]
    pub fields: Fields,
    /// The answer that refuses a tool call; `{reason}` is filled in.
    pub deny: Value,
    /// The answer that adds to the session's context; `{context}` is filled in.
    pub context: Value,
    /// How the harness names an MCP tool: prefix, server, separator, tool.
    #[serde(default = "default_mcp_prefix")]
    pub mcp_prefix: String,
    #[serde(default = "default_mcp_separator")]
    pub mcp_separator: String,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolRule>,
}

fn default_mcp_prefix() -> String {
    "mcp__".into()
}

fn default_mcp_separator() -> String {
    "__".into()
}

/// The harness's names for the events Lonca uses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Events {
    pub session_start: String,
    pub before_tool: String,
    pub after_tool: String,
}

/// Where the event's parts are in the JSON on stdin.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Fields {
    pub event: String,
    pub tool: String,
    pub input: String,
    pub cwd: String,
    pub session: String,
}

impl Default for Fields {
    fn default() -> Self {
        Self {
            event: "hook_event_name".into(),
            tool: "tool_name".into(),
            input: "tool_input".into(),
            cwd: "cwd".into(),
            session: "session_id".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolKind {
    Read,
    Write,
    Shell,
    Fetch,
    Search,
    /// Touches neither the repository nor the outside world.
    Inert,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRule {
    pub kind: ToolKind,
    /// The input fields holding its value, first present wins. A string
    /// is one value, an array several.
    #[serde(default)]
    pub fields: Vec<String>,
    /// For a tool whose paths are inside a text (a patch): the line prefixes
    /// that name them.
    #[serde(default)]
    pub headers: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    SessionStart,
    BeforeTool,
    AfterTool,
}

impl Profile {
    /// The event this name stands for; `None` for a name this harness does
    /// not send, which means the hook is set up for another harness.
    pub fn event_of(&self, name: &str) -> Option<Event> {
        let e = &self.events;
        [
            (&e.session_start, Event::SessionStart),
            (&e.before_tool, Event::BeforeTool),
            (&e.after_tool, Event::AfterTool),
        ]
        .into_iter()
        .find_map(|(n, event)| (n == name).then_some(event))
    }
}

/// `template` with `{key}` replaced in every string.
pub fn render(template: &Value, key: &str, text: &str) -> Value {
    let hole = format!("{{{key}}}");
    match template {
        Value::String(s) => Value::String(s.replace(&hole, text)),
        Value::Array(a) => Value::Array(a.iter().map(|v| render(v, key, text)).collect()),
        Value::Object(m) => {
            let filled = m.iter().map(|(k, v)| (k.clone(), render(v, key, text)));
            Value::Object(filled.collect())
        }
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_built_in_profiles_parse_and_every_edit_tool_names_its_field() {
        for name in ["claude-code", "codex", "gemini"] {
            let p = built_in().get(name).unwrap_or_else(|| panic!("{name}"));
            for (tool, rule) in &p.tools {
                let needs = matches!(
                    rule.kind,
                    ToolKind::Read | ToolKind::Write | ToolKind::Shell | ToolKind::Fetch
                );
                assert_eq!(rule.fields.is_empty(), !needs, "{name} {tool}");
            }
        }
    }

    #[test]
    fn events_are_found_by_the_harness_s_names() {
        let gemini = &built_in()["gemini"];
        assert_eq!(gemini.event_of("SessionStart"), Some(Event::SessionStart));
        assert_eq!(gemini.event_of("BeforeTool"), Some(Event::BeforeTool));
        assert_eq!(gemini.event_of("AfterTool"), Some(Event::AfterTool));
        assert_eq!(gemini.event_of("PreToolUse"), None);
        assert_eq!(built_in()["codex"].event_of("BeforeTool"), None);
    }

    #[test]
    fn a_template_is_filled_at_any_depth_and_only_where_it_has_a_hole() {
        let t = json!({"a": {"b": ["x {reason} y", 1]}, "c": "{other}", "d": true});
        let want = json!({"a": {"b": ["x no y", 1]}, "c": "{other}", "d": true});
        assert_eq!(render(&t, "reason", "no"), want);
    }

    #[test]
    fn a_profile_with_a_word_lonca_does_not_know_is_refused() {
        let good = "events = { session_start = \"a\", before_tool = \"b\", after_tool = \"c\" }\ndeny = {}\ncontext = {}\n";
        let p: Profile = toml::from_str(good).unwrap();
        assert_eq!(p.mcp_prefix, "mcp__");
        assert_eq!(p.mcp_separator, "__");
        assert_eq!(p.fields.event, "hook_event_name");
        assert!(toml::from_str::<Profile>(&format!("{good}typo = 1\n")).is_err());
        let bad = format!("{good}[tools]\nx = {{ kind = \"exec\" }}\n");
        assert!(toml::from_str::<Profile>(&bad).is_err(), "unknown kind");
    }
}
