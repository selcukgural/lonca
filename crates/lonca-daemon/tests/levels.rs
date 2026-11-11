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
    let t = e.session_under("s1", &["src/**"], Some("codex"));
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
    let t2 = e.session_under("s2", &["src/**"], Some("codex"));
    let r = bind(&mut e, &t2, "codex");
    assert_eq!(r["level"], "hooks", "{r}");

    let mut open = file.clone();
    open["allow_managed_hooks_only"] = json!(false);
    std::fs::write(&path, serde_json::to_vec(&open).unwrap()).unwrap();
    let r = bind(&mut e, &t2, "codex");
    assert_eq!(r["level"], "unobserved", "{r}");
    assert!(
        r["notes"].to_string().contains("allow_managed_hooks_only"),
        "{r}"
    );
}

/// The table is the one the human named, whatever the request calls itself.
#[test]
fn a_level_is_read_for_the_harness_the_session_started_under() {
    let mut e = Env::new();
    e.init(None);
    let locked = e.session("locked", &["src/**"]);
    e.bind(&locked);

    let t = e.session_under("s1", &["src/**"], Some("codex"));
    let r = bind(&mut e, &t, "claude-code");
    assert_eq!(r["level"], "unobserved", "{r}");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(
        r["notes"],
        json!(["the session was started for codex, not claude-code"])
    );
    let t = e.session_under("s2", &["src/**"], None);
    let r = bind(&mut e, &t, "claude-code");
    assert_eq!(r["level"], "unobserved", "{r}");
    assert_eq!(
        r["notes"],
        json!(["the session was started with no harness named"])
    );

    let st = e.ok("status", Some("demo"), None, json!({}));
    let of = |id: &str| {
        let s = st["sessions"].as_array().unwrap().iter();
        s.clone().find(|s| s["id"] == id).unwrap()["harness"].clone()
    };
    assert_eq!(of("s1"), "codex");
    assert_eq!(of("s2"), Value::Null);
}

/// A sandbox that sends its traffic anywhere but this daemon's proxy is not
/// one Lonca sees through, whatever else the file locks.
#[test]
fn a_sandbox_on_another_port_is_not_locked_for_lonca() {
    let mut e = Env::new();
    e.init(None);
    let locked = e.session("locked", &["src/**"]);
    e.bind(&locked);
    assert_eq!(
        e.ok("ping", None, None, json!({}))["proxy"],
        "127.0.0.1:8471"
    );

    let file = e.settings.managed_settings.clone().unwrap();
    let mut settings: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    settings["sandbox"]["network"]["httpProxyPort"] = json!(9000);
    std::fs::write(&file, serde_json::to_vec(&settings).unwrap()).unwrap();

    let t = e.session("s1", &["src/**"]);
    let r = bind(&mut e, &t, "claude-code");
    assert_eq!(r["level"], "hooks", "{r}");
    let notes = r["notes"].as_array().unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().unwrap().contains("httpProxyPort")),
        "{r}"
    );
}

/// A first report that says the machine is open is not taken back by a
/// second that says it is shut, and the answer is the level that stands.
#[test]
fn a_session_that_bound_low_stays_low() {
    let mut e = Env::new();
    e.init(None);
    let locked = e.session("locked", &["src/**"]);
    e.bind(&locked);

    let t = e.session("s1", &["src/**"]);
    let sudo = |open| json!({"harness": "claude-code", "harness_session": "h", "sudo_without_password": open});
    let r = e.ok("hook.bind", None, Some(&t), sudo(true));
    assert_eq!(r["level"], "unobserved", "{r}");
    let r = e.ok("hook.bind", None, Some(&t), sudo(false));
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert_eq!(
        r["decision"]["reasons"],
        json!(["bind_raises_level"]),
        "{r}"
    );
    assert_eq!(r["level"], "unobserved", "{r}");
}

/// `lonca session start --continue` with no `--harness` goes on under the
/// one it had.
#[test]
fn a_continuation_binds_under_the_harness_it_took_over() {
    let mut e = Env::new();
    e.init(None);
    let old = e.session_in("s1", &["src/**"], "/ws/s1");
    e.bind(&old);
    let r = e.continue_session("s2", "s1", &["src/**"]);
    let t = r["token"].as_str().unwrap().to_string();
    // The level is not handed on: this session's own harness reports.
    let st = e.ok("status", Some("demo"), None, json!({}));
    let all = st["sessions"].as_array().unwrap();
    let s2 = all.iter().find(|s| s["id"] == "s2").unwrap();
    assert_eq!(s2["level"], "unobserved", "{s2}");
    assert_eq!(s2["workspace"], "/ws/s1");
    assert_eq!(bind(&mut e, &t, "claude-code")["level"], "hooks_sandbox");
}

/// `session.where`: the log's answer to "which session is here", asked
/// without a token and without reading the directory.
#[test]
fn the_log_says_which_session_a_directory_or_a_harness_session_belongs_to() {
    let mut e = Env::new();
    e.init(None);
    let asked = |e: &mut Env, p: Value| e.anon("session.where", None, None, p).unwrap();
    assert_eq!(asked(&mut e, json!({"path": "/ws/s1"})), json!({}));

    let t = e.session_in("s1", &["src/**"], "/ws/s1");
    e.session("plain", &["src/**"]);
    let r = asked(&mut e, json!({"path": "/ws/s1/src/deep"}));
    assert_eq!(
        (&r["session"], &r["repo"], &r["workspace"], &r["by"]),
        (
            &json!("s1"),
            &json!("demo"),
            &json!("/ws/s1"),
            &json!("path")
        ),
        "{r}"
    );
    assert_eq!(r["active"], true);
    // Around it, beside it, and what is no path: nothing.
    for path in ["/ws", "/ws/s10", "/", "ws/s1", "/ws/s1/../s1"] {
        assert_eq!(asked(&mut e, json!({"path": path})), json!({}), "{path}");
    }

    // By the harness's own session, once a bind has named it, wherever
    // the harness stands; an empty name is nobody's.
    let fields = |id: &str| json!({"path": "/tmp", "harness": "claude-code", "fields": {"session_id": id, "cwd": "/tmp"}});
    assert_eq!(asked(&mut e, fields("h1")), json!({}));
    e.bind(&t);
    let r = asked(&mut e, fields("h1"));
    assert_eq!(
        (&r["session"], &r["by"]),
        (&json!("s1"), &json!("harness")),
        "{r}"
    );
    assert_eq!(asked(&mut e, fields("h2")), json!({}));
    assert_eq!(asked(&mut e, fields("")), json!({}));
    let other = json!({"harness": "nobody", "fields": {"session_id": "h1"}});
    assert_eq!(asked(&mut e, other), json!({}));

    // The session a hook's request comes from works where the log says.
    let input = json!({"hook_event_name": "PreToolUse", "session_id": "h1", "cwd": "/ws/s1",
                       "tool_name": "Read", "tool_input": {"file_path": "/ws/s1/src/lib.rs"}});
    let at = |ws: &str, real: Value| json!({"harness": "claude-code", "input": input, "workspace": ws, "real": real});
    e.ok("hook.input", None, Some(&t), at("/ws/s1", json!("/ws/s1")));
    e.ok(
        "hook.input",
        None,
        Some(&t),
        at("/link/s1", json!("/ws/s1")),
    );
    for p in [
        at("/ws/s1/sub", json!("/ws/s1/sub")),
        at("/ws/other", Value::Null),
    ] {
        let (code, _) = e.anon("hook.input", None, Some(&t), p).unwrap_err();
        assert_eq!(code, "invalid");
    }

    // Ended, it is still the directory's last session, and no longer live;
    // its continuation is found first.
    e.ok("session.end", None, Some(&t), json!({}));
    let r = asked(&mut e, json!({"path": "/ws/s1"}));
    assert_eq!(
        (&r["session"], &r["active"]),
        (&json!("s1"), &json!(false)),
        "{r}"
    );
    assert_eq!(
        asked(&mut e, fields("h1")),
        json!({}),
        "a bind of a session that is over"
    );
    let c = e.continue_session("s2", "s1", &["src/**"]);
    assert_eq!(c["decision"]["outcome"], "allow", "{c}");
    let r = asked(&mut e, json!({"path": "/ws/s1"}));
    assert_eq!(
        (&r["session"], &r["active"]),
        (&json!("s2"), &json!(true)),
        "{r}"
    );
}
