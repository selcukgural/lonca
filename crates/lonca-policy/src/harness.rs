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
    /// The answer that sends an agent back instead of letting it stop;
    /// `{reason}` is filled in. Comes with `events.stop`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_deny: Option<Value>,
    /// How the harness names an MCP tool: prefix, server, separator, tool.
    #[serde(default = "default_mcp_prefix")]
    pub mcp_prefix: String,
    #[serde(default = "default_mcp_separator")]
    pub mcp_separator: String,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolRule>,
    /// What a workspace needs for this harness to get the rules, the MCP
    /// server and the hooks.
    #[serde(default)]
    pub setup: Setup,
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
    /// The agent is about to finish its turn. A harness that has no such
    /// event goes without.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<String>,
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
    Stop,
}

impl Profile {
    /// The event this name stands for; `None` for a name this harness does
    /// not send, which means the hook is set up for another harness.
    pub fn event_of(&self, name: &str) -> Option<Event> {
        let e = &self.events;
        [
            (Some(&e.session_start), Event::SessionStart),
            (Some(&e.before_tool), Event::BeforeTool),
            (Some(&e.after_tool), Event::AfterTool),
            (e.stop.as_ref(), Event::Stop),
        ]
        .into_iter()
        .find_map(|(n, event)| (n? == name).then_some(event))
    }

    /// `events.stop` and `stop_deny` mean nothing apart: an event with no
    /// answer could tell an agent nothing.
    pub fn check(&self) -> Result<(), String> {
        if self.events.stop.is_some() != self.stop_deny.is_some() {
            return Err("events.stop and stop_deny go together".into());
        }
        Ok(())
    }

    /// What this harness puts before the name of a tool of `lonca mcp`.
    pub fn tool_prefix(&self) -> String {
        format!("{}lonca{}", self.mcp_prefix, self.mcp_separator)
    }
}

/// What `lonca harness setup` does for a harness. Every string may hold
/// `{rules}`, `{socket}` and `{workspace}`.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Setup {
    /// Files to write into the workspace, for a harness that reads them there.
    #[serde(default)]
    pub files: Vec<SetupFile>,
    /// The arguments that do the same with nothing written, for a runner, and
    /// for a harness that ignores files in a directory it does not trust.
    #[serde(default)]
    pub flags: Vec<Flag>,
    /// Environment the harness must start with.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// What a person has to know or do that Lonca can not.
    #[serde(default)]
    pub note: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupFile {
    pub path: String,
    pub format: Format,
    pub content: Value,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Json,
    Toml,
    /// `content` is the text of the file.
    Text,
}

/// One command line argument.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged, deny_unknown_fields)]
pub enum Flag {
    Text(String),
    /// The text of one of the setup's files, for a harness that takes a
    /// file's content as an argument.
    File {
        file: String,
    },
}

/// A setup with its holes filled in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Filled {
    /// Relative path and text.
    pub files: BTreeMap<String, String>,
    pub flags: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub note: String,
}

impl Setup {
    /// Fills the holes. Text goes through each format's own writer, so
    /// nothing in a path or in the rules can change a file's structure.
    pub fn fill(&self, rules: &str, socket: &str, workspace: &str) -> Result<Filled, String> {
        let holes = [
            ("workspace", workspace),
            ("socket", socket),
            ("rules", rules),
        ];
        let value = |v: &Value| holes.iter().fold(v.clone(), |v, (k, t)| render(&v, k, t));
        let string = |s: &str| match value(&Value::String(s.to_string())) {
            Value::String(s) => s,
            _ => unreachable!("render keeps a string a string"),
        };
        let mut files = BTreeMap::new();
        for f in &self.files {
            files.insert(f.path.clone(), f.format.write(&value(&f.content))?);
        }
        let flags = self.flags.iter().map(|flag| match flag {
            Flag::Text(s) => Ok(string(s)),
            Flag::File { file } => files
                .get(file)
                .cloned()
                .ok_or_else(|| format!("a flag names {file}, which the setup does not write")),
        });
        Ok(Filled {
            flags: flags.collect::<Result<_, String>>()?,
            files,
            env: self
                .env
                .iter()
                .map(|(k, v)| (k.clone(), string(v)))
                .collect(),
            note: string(&self.note),
        })
    }
}

impl Format {
    fn write(self, content: &Value) -> Result<String, String> {
        let text = match self {
            Format::Json => serde_json::to_string_pretty(content).map_err(|e| e.to_string())?,
            Format::Toml => toml::to_string(content).map_err(|e| e.to_string())?,
            Format::Text => content
                .as_str()
                .ok_or("the content of a text file is a string")?
                .to_string(),
        };
        Ok(format!("{}\n", text.trim_end()))
    }
}

const RULES: &str = "\
- Before editing a function, method or type, lease it: {tool}lease_acquire with symbols like \"src/file.rs#Type.method\" ({tool}symbols lists them).
{where}
- {tool}lease_needed says which leases your local changes need and who holds them.
- Check your changes with {tool}preview, then submit with {tool}propose. Its arguments are `intent` (what you did and why, in a sentence) and, each copied from `facts` in what preview reports: `edits` (existing symbols whose body you changed), `adds` (symbols you added), `deletes` (symbols you deleted), `deleted_files` (files you deleted), `signature_changes` (symbols whose signature you changed), `tests` (test counts: added, modified, deleted, skipped). There is no other argument: symbols go in those lists by what happened to them. A claim that differs from the facts is denied (claim_mismatch:<field>).
- After your change integrates, run {tool}sync before continuing. Integration releases the leases the change needed: lease a symbol again before editing it again.
- If a symbol is leased by another agent, ask it with {tool}negotiate or wait.
- Editing a file is not delivering it: nothing reaches the repository until you propose it.
- Reading untrusted paths or files outside this workspace taints the session; whether web fetches, network commands and other MCP servers do is the repository's policy ([taint] in lonca.toml). Tainted changes need human review.";

/// The most names of files [`stop_message`] writes out.
const STOP_MESSAGE_PATHS: usize = 20;

/// What an agent is told when it stops with work nobody proposed.
pub fn stop_message(tool_prefix: &str, paths: &[String], total: u64) -> String {
    let shown = paths.iter().take(STOP_MESSAGE_PATHS);
    let mut files = shown.map(String::as_str).collect::<Vec<_>>().join(", ");
    let named = paths.len().min(STOP_MESSAGE_PATHS) as u64;
    if total > named {
        files.push_str(&format!(" and {} more", total - named));
    }
    format!(
        "Lonca: this workspace has changes that are not in a standing proposal, so they have not reached the repository: {files}. Run {p}lease_needed and lease what it lists, check with {p}preview, then submit with {p}propose. If you can not, say why in your final answer.",
        p = tool_prefix
    )
}

/// Lonca's rules for an agent, from the one text every harness gets.
/// `about` follows "governed by Lonca", `tool_prefix` goes before each tool's
/// name (empty for the neutral names), `scratch` are the session's roots.
pub fn rules(about: &str, tool_prefix: &str, scratch: &[&str]) -> String {
    let where_to_write = if scratch.is_empty() {
        "- Edit files only inside this workspace.".to_string()
    } else {
        format!(
            "- Edit files only inside this workspace. Notes, logs and throwaway files go to your scratch directory ({}); nothing there is part of the repository or of a proposal.",
            scratch.join(", ")
        )
    };
    let body = RULES
        .replace("{tool}", tool_prefix)
        .replace("{where}", &where_to_write);
    format!("This workspace is governed by Lonca{about}.\n{body}")
}

/// A built-in profile as a `[harnesses.<name>]` table for `lonca.toml`. A
/// profile there replaces the built-in one as a whole, so this is where a
/// change of a harness starts that Lonca has not caught up with.
pub fn built_in_table(name: &str) -> Option<Result<String, String>> {
    let profile = built_in().get(name)?;
    let harnesses = BTreeMap::from([(name, profile)]);
    let table = BTreeMap::from([("harnesses", harnesses)]);
    Some(toml::to_string(&table).map_err(|e| e.to_string()))
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
        for name in ["claude-code", "codex", "gemini", "opencode"] {
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
    fn a_built_in_table_is_the_same_profile_when_a_policy_reads_it() {
        for (name, profile) in built_in() {
            let text = built_in_table(name).unwrap().unwrap();
            let config: crate::config::Config = toml::from_str(&text).unwrap();
            assert_eq!(&config.harnesses[name], profile, "{name}");
        }
        assert!(built_in_table("nobody").is_none());
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
    fn every_built_in_profile_has_a_stop_event_and_its_answer() {
        let names = [
            ("claude-code", "Stop"),
            ("codex", "Stop"),
            ("gemini", "AfterAgent"),
            ("opencode", "stop"),
        ];
        for (harness, stop) in names {
            let p = &built_in()[harness];
            assert_eq!(p.event_of(stop), Some(Event::Stop), "{harness}");
            p.check().unwrap();
            let answer = p.stop_deny.as_ref().unwrap();
            assert!(render(answer, "reason", "R").to_string().contains('R'));
        }
    }

    #[test]
    fn a_harness_with_no_stop_event_has_no_stop() {
        let mut p = built_in()["codex"].clone();
        p.events.stop = None;
        p.stop_deny = None;
        p.check().unwrap();
        assert_eq!(p.event_of("Stop"), None);
        assert_eq!(p.event_of("SessionStart"), Some(Event::SessionStart));
    }

    #[test]
    fn a_stop_event_and_its_answer_come_together() {
        let mut p = built_in()["codex"].clone();
        p.stop_deny = None;
        assert!(p.check().unwrap_err().contains("go together"));
        let mut p = built_in()["codex"].clone();
        p.events.stop = None;
        assert!(p.check().is_err());
    }

    #[test]
    fn the_stop_message_names_files_and_what_to_do_with_the_harness_s_tools() {
        let paths: Vec<String> = (0..25).map(|i| format!("f{i}")).collect();
        let m = stop_message("mcp__lonca__", &paths[..2], 2);
        assert!(
            m.contains("repository: f0, f1. Run mcp__lonca__lease_needed"),
            "{m}"
        );
        assert!(m.contains("mcp__lonca__preview") && m.contains("mcp__lonca__propose"));

        // Twenty names at most, and the rest is a number: of what the log
        // listed, and of what it did not.
        let m = stop_message("", &paths, 25);
        assert!(m.contains("f19 and 5 more."), "{m}");
        assert!(!m.contains("f20"), "{m}");
        let m = stop_message("", &paths[..3], 40);
        assert!(m.contains("f2 and 37 more."), "{m}");
        let m = stop_message("", &paths[..20], 20);
        assert!(m.contains("f19. Run"), "{m}");
    }

    #[test]
    fn a_template_is_filled_at_any_depth_and_only_where_it_has_a_hole() {
        let t = json!({"a": {"b": ["x {reason} y", 1]}, "c": "{other}", "d": true});
        let want = json!({"a": {"b": ["x no y", 1]}, "c": "{other}", "d": true});
        assert_eq!(render(&t, "reason", "no"), want);
    }

    #[test]
    fn the_rules_are_one_text_with_each_harness_s_tool_names() {
        let neutral = rules("", "", &[]);
        assert!(neutral.starts_with("This workspace is governed by Lonca.\n"));
        assert!(neutral.contains("lease it: lease_acquire with"));
        assert!(!neutral.contains("mcp_") && !neutral.contains('{'.to_string().as_str()));
        assert!(neutral.contains("- Edit files only inside this workspace.\n"));

        let claude = rules(
            " (repository r)",
            &built_in()["claude-code"].tool_prefix(),
            &[],
        );
        assert!(claude.starts_with("This workspace is governed by Lonca (repository r).\n"));
        assert_eq!(
            claude
                .replace(" (repository r)", "")
                .replace("mcp__lonca__", ""),
            neutral
        );
        assert!(claude.contains("mcp__lonca__propose"));
        assert!(rules("", &built_in()["gemini"].tool_prefix(), &[]).contains("mcp_lonca_propose"));

        let scratch = rules("", "", &["/a", "/b"]);
        assert!(scratch.contains("your scratch directory (/a, /b);"));
    }

    fn setup(toml: &str) -> Setup {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn a_file_is_written_by_its_format_so_a_hole_can_not_change_its_structure() {
        let tricky = "a\"b\nc = 1";
        let s = setup(
            r#"
            [[files]]
            path = "a.json"
            format = "json"
            content = { x = "{workspace}" }
            [[files]]
            path = "a.toml"
            format = "toml"
            content = { x = "{workspace}" }
            [[files]]
            path = "a.txt"
            format = "text"
            content = "{rules}"
        "#,
        );
        let f = s.fill("the rules", "/s", tricky).unwrap();
        let json: Value = serde_json::from_str(&f.files["a.json"]).unwrap();
        assert_eq!(json["x"], tricky);
        let toml: Value = toml::from_str(&f.files["a.toml"]).unwrap();
        assert_eq!(toml, json!({"x": tricky}));
        assert_eq!(f.files["a.txt"], "the rules\n");
    }

    #[test]
    fn a_text_file_with_no_text_is_refused() {
        let s = setup("[[files]]\npath = \"a\"\nformat = \"text\"\ncontent = 1\n");
        let e = s.fill("", "", "").unwrap_err();
        assert!(e.contains("is a string"), "{e}");
    }

    #[test]
    fn flags_env_and_note_are_filled_and_a_flag_can_hold_a_file() {
        let s = setup(
            r#"
            flags = ["--dir={workspace}", "--mcp", { file = "m.json" }, "--r", "{rules}"]
            env = { SOCK = "{socket}" }
            note = "in {workspace}"
            [[files]]
            path = "m.json"
            format = "json"
            content = { s = "{socket}" }
        "#,
        );
        let f = s.fill("R", "/s", "/w").unwrap();
        let file = "{\n  \"s\": \"/s\"\n}\n";
        assert_eq!(f.flags, ["--dir=/w", "--mcp", file, "--r", "R"]);
        assert_eq!(f.env["SOCK"], "/s");
        assert_eq!(f.note, "in /w");
        assert_eq!(f.files["m.json"], file);

        let bad = setup("flags = [{ file = \"nope\" }]\n");
        assert!(bad.fill("", "", "").unwrap_err().contains("nope"));
        assert!(toml::from_str::<Setup>("flags = [{ typo = \"x\" }]\n").is_err());
        assert!(toml::from_str::<Setup>("typo = 1\n").is_err());
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
