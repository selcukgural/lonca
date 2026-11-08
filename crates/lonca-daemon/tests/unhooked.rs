//! A session whose hooks do not run (#190): `lonca mcp` names each tool it
//! runs (`mcp.call`), and on a harness whose before-tool event covers MCP
//! tools that event must have come first.

mod common;
use common::*;

use lonca_core::oplog::OpLog;
use lonca_daemon::hooked::START_GRACE_MS;
use lonca_daemon::security::{Event, kind};

const EDITED: &str =
    "pub fn charge(a: u64) -> u64 {\n    a\n}\n\npub fn refund(a: u64) -> u64 {\n    0\n}\n";

/// The harness's before-tool event for a tool of `lonca mcp`.
fn pre(e: &mut Env, token: &str, tool: &str) {
    let ws = e.root.join("ws");
    let p = json!({"hook_event_name": "PreToolUse", "tool_name": format!("mcp__lonca__{tool}"),
                   "tool_input": {}, "workspace": ws});
    let r = e.ok("hook.event", None, Some(token), p);
    assert_eq!(r["decision"], "allow", "{r}");
}

fn call(e: &mut Env, token: &str, tool: &str) -> Value {
    e.ok("mcp.call", None, Some(token), json!({"tool": tool}))
}

fn session_of(e: &mut Env, id: &str) -> Value {
    let st = e.ok("status", Some("demo"), None, json!({}));
    let all = st["sessions"].as_array().unwrap();
    all.iter().find(|s| s["id"] == id).unwrap().clone()
}

fn next_seq(e: &mut Env) -> u64 {
    e.ok("status", Some("demo"), None, json!({}))["next_seq"]
        .as_u64()
        .unwrap()
}

fn security(e: &Env) -> Vec<Event> {
    let text = std::fs::read_to_string(e.root.join("home/security.log")).unwrap_or_default();
    let all = text
        .lines()
        .map(|l| serde_json::from_str::<Event>(l).unwrap());
    all.filter(|x| x.kind == kind::UNHOOKED).collect()
}

/// A repository, a bound session `s1` and the daemon past its first moments.
fn repo() -> (Env, GitId, String) {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    e.advance(START_GRACE_MS);
    (e, base, token)
}

#[test]
fn a_call_after_its_event_is_hooked_and_writes_nothing() {
    let (mut e, _, t) = repo();
    // The test clock ticks once a request: times are compared, not named.
    let fresh = session_of(&mut e, "s1");
    let bound = fresh["bound_ms"].as_i64().unwrap();
    assert!(bound <= e.now() - START_GRACE_MS, "{fresh}");
    let seq = next_seq(&mut e);
    pre(&mut e, &t, "lease_acquire");
    pre(&mut e, &t, "propose");
    assert_eq!(
        call(&mut e, &t, "propose"),
        json!({"checked": true, "hooked": true})
    );
    assert_eq!(call(&mut e, &t, "lease_acquire")["hooked"], true);
    assert_eq!(next_seq(&mut e), seq, "a match is not logged");
    let s = session_of(&mut e, "s1");
    assert!(s["unhooked"].is_null(), "{s}");
    assert_eq!(s["level"], "hooks_sandbox");
    let heard = s["last_hook_ms"].as_i64().unwrap();
    assert!(heard > bound + START_GRACE_MS && heard < e.now(), "{s}");
    assert!(security(&e).is_empty());
}

/// The whole of the mark: logged once, a security event, tainted, no longer
/// observed, and what the session proposes goes to a human under its own
/// word. A restart and the auditor read it from the log.
#[test]
fn a_call_with_no_event_marks_the_session_once_and_taints_it() {
    let (mut e, base, t) = repo();
    pre(&mut e, &t, "lease_acquire");
    let seq = next_seq(&mut e);
    let r = call(&mut e, &t, "propose");
    assert_eq!(
        r,
        json!({"checked": true, "hooked": false}),
        "another tool's event is no proof"
    );
    assert_eq!(next_seq(&mut e), seq + 1);
    let s = session_of(&mut e, "s1");
    assert_eq!(s["unhooked"]["tool"], "propose");
    let seen = s["unhooked"]["seen_ms"].as_i64().unwrap();
    assert!(seen > e.now() - 10 && seen < e.now(), "{s}");
    assert_eq!(s["level"], "unobserved");
    assert_eq!(s["taint"], "unhooked: propose ran without its hook event");
    let events = security(&e);
    assert_eq!(events.len(), 1, "{events:?}");
    assert_eq!(events[0].session.as_deref(), Some("s1"));
    assert_eq!(events[0].detail, "propose");

    // Once: a second miss, and a matched call, add nothing.
    e.advance(1000);
    assert_eq!(call(&mut e, &t, "status")["hooked"], false);
    pre(&mut e, &t, "status");
    assert_eq!(call(&mut e, &t, "status")["hooked"], true);
    assert_eq!(next_seq(&mut e), seq + 1);
    assert_eq!(security(&e).len(), 1);
    assert_eq!(
        session_of(&mut e, "s1")["unhooked"]["seen_ms"],
        json!(seen),
        "the first stays"
    );

    e.wrote(&t, "src/lib.rs");
    e.lease(&t, "src/lib.rs#refund");
    let r = e.propose(
        &t,
        &base,
        vec![file("src/lib.rs", EDITED)],
        &["src/lib.rs#refund"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let reasons = r["decision"]["reasons"].as_array().unwrap();
    assert!(reasons.contains(&json!("unhooked_session")), "{r}");
    assert!(!reasons.contains(&json!("tainted_session")), "{r}");

    e.reopen();
    let s = session_of(&mut e, "s1");
    assert_eq!(s["unhooked"]["tool"], "propose");
    assert!(
        s["last_hook_ms"].is_null(),
        "a restart forgets what it heard"
    );
    let audit = lonca_audit::audit(&e.store(), lonca_audit::Options::default()).unwrap();
    assert!(audit.ok(), "{:#?}", audit.findings);
    let log = OpLog::new(&e.store()).read_all().unwrap();
    assert!(
        log.iter()
            .all(|o| o.entry.format == lonca_core::oplog::FORMAT_CURRENT || o.entry.seq == 0)
    );
}

/// A harness that never ran `hook.bind` never ran its hooks either.
#[test]
fn a_session_that_never_bound_is_unhooked_at_its_first_call() {
    let (mut e, _, _) = repo();
    let t = e.session("s2", &["src/**"]);
    let s = session_of(&mut e, "s2");
    assert!(
        s["bound_ms"].is_null() && s["last_hook_ms"].is_null(),
        "{s}"
    );
    assert_eq!(call(&mut e, &t, "lease_needed")["hooked"], false);
    assert_eq!(session_of(&mut e, "s2")["unhooked"]["tool"], "lease_needed");
}

/// No harness named, or one whose event skips MCP tools: nothing to prove.
#[test]
fn only_a_harness_known_to_hook_its_mcp_calls_is_checked() {
    let (mut e, _, _) = repo();
    for (id, harness) in [
        ("s-none", None),
        ("s-codex", Some("codex")),
        ("s-oc", Some("opencode")),
    ] {
        let t = e.session_under(id, &["src/**"], harness);
        let seq = next_seq(&mut e);
        assert_eq!(
            call(&mut e, &t, "propose"),
            json!({"checked": false, "hooked": null}),
            "{id}"
        );
        assert_eq!(next_seq(&mut e), seq, "{id}");
        assert!(session_of(&mut e, id)["unhooked"].is_null(), "{id}");
    }
}

/// Right after a start the daemon has heard nothing yet: an event that went
/// to the daemon before it is not a miss.
#[test]
fn a_fresh_daemon_waits_a_moment_before_it_marks() {
    let (mut e, _, t) = repo();
    e.reopen();
    assert_eq!(call(&mut e, &t, "propose")["hooked"], true);
    e.advance(START_GRACE_MS - 100);
    assert_eq!(call(&mut e, &t, "propose")["hooked"], true);
    assert!(session_of(&mut e, "s1")["unhooked"].is_null());
    e.advance(100);
    assert_eq!(call(&mut e, &t, "propose")["hooked"], false);
    assert!(session_of(&mut e, "s1")["unhooked"].is_object());

    // A session that began under this daemon sent it every event.
    e.reopen();
    let t2 = e.session("s2", &["src/**"]);
    e.bind(&t2);
    assert_eq!(call(&mut e, &t2, "propose")["hooked"], false);
}

#[test]
fn an_event_waits_for_its_call_ten_minutes() {
    let (mut e, _, t) = repo();
    pre(&mut e, &t, "propose");
    e.advance(lonca_daemon::hooked::PENDING_MS + 1);
    assert_eq!(call(&mut e, &t, "propose")["hooked"], false);
}

/// Another session's event proves nothing for this one, and a denied tool
/// call never comes, so its event does not wait.
#[test]
fn an_event_counts_for_its_own_session_and_an_allowed_call() {
    let (mut e, _, t1) = repo();
    let t2 = e.session("s2", &["src/**"]);
    e.bind(&t2);
    pre(&mut e, &t2, "propose");
    assert_eq!(call(&mut e, &t1, "propose")["hooked"], false);
    assert_eq!(call(&mut e, &t2, "propose")["hooked"], true);
    assert!(session_of(&mut e, "s2")["unhooked"].is_null());
}

#[test]
fn a_tool_name_is_checked_before_anything() {
    let (mut e, _, t) = repo();
    for bad in ["", "Propose", "lease-acquire", "a b", &"a".repeat(65)] {
        let (code, _) = e
            .call("mcp.call", None, Some(&t), json!({"tool": bad}))
            .unwrap_err();
        assert_eq!(code, "invalid", "{bad:?}");
    }
    assert!(session_of(&mut e, "s1")["unhooked"].is_null());
}

/// A child made after the mark runs in the same harness: it is unhooked and
/// tainted too. A continuation reports afresh but keeps the taint.
#[test]
fn a_child_inherits_the_mark_and_a_continuation_the_taint() {
    let (mut e, _, t) = repo();
    call(&mut e, &t, "propose");
    let scope = json!({"paths": ["src/**"], "symbols": null, "ops": ["lease.acquire"],
                       "max_files": null, "max_lines": null});
    let expires = e.now() + 60_000;
    let child = e.ok(
        "cap.attenuate",
        None,
        Some(&t),
        json!({"agent": "sub", "scope": scope, "expires_ms": expires, "leases": []}),
    );
    let id = child["session"].as_str().unwrap().to_string();
    let c = session_of(&mut e, &id);
    assert_eq!(c["unhooked"]["tool"], "propose", "{c}");
    assert_eq!(c["level"], "unobserved");
    assert!(
        c["bound_ms"].is_number(),
        "it stands where its parent stands"
    );

    e.ok("session.end", None, Some(&t), json!({}));
    let r = e.continue_session("s3", "s1", &["src/**"]);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let s = session_of(&mut e, "s3");
    assert!(s["unhooked"].is_null() && s["bound_ms"].is_null(), "{s}");
    assert!(s["taint"].as_str().unwrap().contains("unhooked"), "{s}");
}
