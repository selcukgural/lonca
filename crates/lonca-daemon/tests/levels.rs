//! What a session's observation level rests on (issue #21): what a harness's
//! profile says must hold in the file an administrator keeps. No table, no
//! level, whatever the file says.

mod common;
use common::*;

use lonca_core::ops::Op;

fn bind(e: &mut Env, token: &str, harness: &str) -> Value {
    let p = json!({"harness": harness, "harness_session": "h", "sudo_without_password": false});
    e.ok("hook.bind", None, Some(token), p)
}

/// A repository that replaced a harness's tool names keeps its level.
#[test]
fn a_profile_with_no_table_keeps_the_built_in_one() {
    let mut e = Env::new();
    e.init(None);
    let t = e.session("s1", &["src/**"]);
    e.bind(&t);
    let table = r#"
[harnesses.claude-code]
events = { session_start = "SessionStart", before_tool = "PreToolUse", after_tool = "PostToolUse" }
deny = { why = "{reason}" }
context = { say = "{context}" }
"#;
    let config = format!("{}\n{table}", lonca_policy::config::DEFAULT_CONFIG);
    let p = json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY});
    let prep = e.ok("human.prepare_policy", Some("demo"), None, p);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    assert_eq!(bind(&mut e, &t, "claude-code")["level"], "hooks_sandbox");
}

const LOCKED: &str = r#"
[harnesses.codex.locked]
file = { linux = "/nowhere", macos = "/nowhere" }
format = "json"
hook_lists = ["/hooks/PreToolUse", "/hooks/PostToolUse"]
hooks = [{ at = "/allow_managed_hooks_only", equals = true }]
"#;

#[test]
fn a_table_in_the_signed_policy_gives_a_harness_its_level() {
    let mut e = Env::new();
    e.init(None);
    let t = e.session("s1", &["src/**"]);
    let hook = json!([{"hooks": [{"command": "/usr/bin/lonca hook"}]}]);
    let file = json!({
        "allow_managed_hooks_only": true,
        "hooks": {"PreToolUse": hook, "PostToolUse": hook},
    });
    let path = e.settings.managed_settings.clone().unwrap();
    std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();

    // The same file, read for a harness with no table.
    let r = bind(&mut e, &t, "codex");
    assert_eq!(r["level"], "unobserved", "{r}");
    assert_eq!(r["notes"], json!(["no locked profile for harness codex"]));

    let table = lonca_policy::harness::built_in_table("codex")
        .unwrap()
        .unwrap();
    let config = format!("{}\n{table}{LOCKED}", lonca_policy::config::DEFAULT_CONFIG);
    let p = json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY});
    let prep = e.ok("human.prepare_policy", Some("demo"), None, p);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");

    // Hooks only: the table says nothing that locks a sandbox.
    let r = bind(&mut e, &t, "codex");
    assert_eq!(r["level"], "hooks", "{r}");

    let mut open = file.clone();
    open["allow_managed_hooks_only"] = json!(false);
    std::fs::write(&path, serde_json::to_vec(&open).unwrap()).unwrap();
    let r = bind(&mut e, &t, "codex");
    assert_eq!(r["level"], "unobserved", "{r}");
    assert!(
        r["notes"].to_string().contains("allow_managed_hooks_only"),
        "{r}"
    );
}
