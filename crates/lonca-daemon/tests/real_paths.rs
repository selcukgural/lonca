//! A tool's path is placed by where it really is: the daemon asks the hook
//! program, which sees the workspace, and a link in the workspace is no way
//! out of it.

mod common;
use common::*;

use lonca_core::ops::ObsKind;

fn repo() -> (Env, String) {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let mut op = e.session_op("s1", &["src/**"], None);
    if let Op::SessionStart {
        workspace, scope, ..
    } = &mut op
    {
        *workspace = Some("/ws".into());
        scope.scratch = vec!["/scratch".into()];
    }
    let token = e.human(op)["token"].as_str().unwrap().to_string();
    e.bind(&token);
    (e, token)
}

fn call(phase: &str, tool: &str, path: &str) -> Value {
    let input = json!({"hook_event_name": phase, "session_id": "h1", "cwd": "/ws/src",
        "tool_name": tool, "tool_input": {"file_path": path}});
    json!({"harness": "claude-code", "input": input, "workspace": "/ws", "real": "/ws"})
}

fn taint(e: &mut Env) -> Value {
    let st = e.ok("status", Some("demo"), None, json!({}));
    let sessions = st["sessions"].as_array().unwrap();
    sessions.iter().find(|s| s["id"] == "s1").unwrap()["taint"].clone()
}

fn observed(e: &Env) -> Vec<(ObsKind, bool)> {
    let log = OpLog::new(&e.store()).read_all().unwrap();
    let events = log.iter().filter_map(|o| match &o.entry.op {
        Op::Observe { events, .. } => Some(events.clone()),
        _ => None,
    });
    events.flatten().map(|o| (o.kind, o.external)).collect()
}

#[test]
fn the_daemon_asks_where_a_calls_paths_are_and_logs_nothing_until_told() {
    let (mut e, t) = repo();
    let seq = e.ok("status", Some("demo"), None, json!({}))["next_seq"].clone();
    let p = call("PreToolUse", "Write", "../h/.zshrc");
    let r = e.ok("hook.input", None, Some(&t), p.clone());
    assert_eq!(r["phase"], "resolve", "{r}");
    assert_eq!(
        r["paths"],
        json!(["/ws", "/scratch", "/ws/src/../h/.zshrc"])
    );
    // A hook program that knows no such phase reads a refusal.
    assert_eq!(r["decision"], "deny", "{r}");
    let out = &r["output"]["hookSpecificOutput"];
    assert_eq!(out["permissionDecision"], "deny", "{r}");
    let reason = out["permissionDecisionReason"].as_str().unwrap();
    assert!(reason.contains("older than its daemon"), "{reason}");
    assert_eq!(
        e.ok("status", Some("demo"), None, json!({}))["next_seq"],
        seq
    );
    assert!(observed(&e).is_empty());

    // Asked again the same way, the same answer: nothing is remembered.
    let r = e.ok("hook.input", None, Some(&t), p);
    assert_eq!(r["phase"], "resolve", "{r}");

    // A call with no path is answered at once.
    let mut shell = call("PreToolUse", "Bash", "");
    shell["input"]["tool_input"] = json!({"command": "ls"});
    let r = e.ok("hook.input", None, Some(&t), shell);
    assert_eq!(r["decision"], "allow", "{r}");
    assert!(r.get("phase").is_none(), "{r}");
}

#[test]
fn a_link_in_the_workspace_is_no_way_out_of_it() {
    let (mut e, t) = repo();
    let home = [("/ws/src/../h/.zshrc", "/home/dev/.zshrc")];

    // Where its text says: a workspace file, allowed, nothing to log.
    let r = e.hook_input(&t, call("PreToolUse", "Write", "../h/.zshrc"), &[]);
    assert_eq!(r["decision"], "allow", "{r}");
    assert!(observed(&e).is_empty());
    assert_eq!(taint(&mut e), Value::Null);

    // Through a link to the home directory: refused in the harness's shape,
    // recorded with where it would have landed, and the session is tainted.
    let r = e.hook_input(&t, call("PreToolUse", "Write", "../h/.zshrc"), &home);
    assert_eq!(r["decision"], "deny", "{r}");
    let reason = r["output"]["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert_eq!(
        reason,
        "lonca: writes outside the workspace are not allowed (/ws/h/.zshrc is /home/dev/.zshrc)"
    );
    let path = "/home/dev/.zshrc".to_string();
    assert_eq!(observed(&e), [(ObsKind::Write { path }, true)]);
    assert_ne!(taint(&mut e), Value::Null);
    let events = e.ok("security.events", None, None, json!({}));
    let denied = events["events"].as_array().unwrap().iter();
    let denied: Vec<&Value> = denied.filter(|x| x["kind"] == "hook_denied").collect();
    assert_eq!(denied.len(), 1, "{events}");

    let audit = lonca_audit::audit(&e.store(), lonca_audit::Options::default()).unwrap();
    assert!(audit.ok(), "{:#?}", audit.findings);
}

#[test]
fn a_read_through_a_link_is_a_read_of_what_it_leads_to() {
    let (mut e, t) = repo();
    let notes = [("/ws/src/notes.md", "/home/dev/notes.md")];
    let r = e.hook_input(&t, call("PreToolUse", "Read", "notes.md"), &notes);
    assert_eq!(r["decision"], "allow", "{r}");
    let path = "/home/dev/notes.md".to_string();
    assert_eq!(observed(&e), [(ObsKind::Read { path }, true)]);
    assert_ne!(taint(&mut e), Value::Null);
}

#[test]
fn a_write_through_a_link_to_a_workspace_file_is_that_files() {
    let (mut e, t) = repo();
    let alias = [("/ws/alias/lib.rs", "/ws/src/lib.rs")];
    let r = e.hook_input(&t, call("PostToolUse", "Edit", "/ws/alias/lib.rs"), &alias);
    assert_eq!(r["decision"], "allow", "{r}");
    let path = "src/lib.rs".to_string();
    assert_eq!(observed(&e), [(ObsKind::Write { path }, false)]);

    // A path the hook program could not resolve is left out: outside.
    let mut p = call("PreToolUse", "Write", "/ws/src/lib.rs");
    p["paths"] = json!({"/ws": "/ws", "/scratch": "/scratch"});
    let r = e.ok("hook.input", None, Some(&t), p);
    assert_eq!(r["decision"], "deny", "{r}");
    assert!(
        r["reason"]
            .as_str()
            .unwrap()
            .ends_with("(/ws/src/lib.rs: where it really is was not found)"),
        "{r}"
    );
}
