//! A negotiation has to reach the other side: a denial says who to talk to,
//! the message says what it says, and an agent hears of it without asking,
//! from `lonca mcp` or from a hook after a tool call.

mod common;
use common::*;

const SYM: &str = "src/lib.rs#charge";

fn two_agents() -> (Env, String, String) {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let a = e.session("s1", &["src/**"]);
    e.bind(&a);
    let b = e.session("s2", &["src/**"]);
    e.bind(&b);
    (e, a, b)
}

fn claim(e: &mut Env, from: &str, to: &str, reason: &str) -> Value {
    let message = json!({"type": "claim", "symbols": [SYM], "reason": reason});
    let params = json!({"thread": "t1", "to_session": to, "message": message});
    let r = e.ok("negotiate", None, Some(from), params);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    r
}

fn inbox(e: &mut Env, token: &str) -> Value {
    e.ok("inbox", None, Some(token), json!({}))
}

/// A finished tool call, as `harness` reports it.
fn after_tool(e: &mut Env, token: &str, harness: &str, event: &str) -> Value {
    let input = json!({"hook_event_name": event, "tool_name": "Read",
        "tool_input": {}, "cwd": "/w"});
    let p = json!({"harness": harness, "input": input, "workspace": "/w"});
    e.hook_input(token, p, &[])
}

#[test]
fn a_denial_says_who_is_on_it_and_to_settle_it_between_you() {
    let (mut e, a, b) = two_agents();
    assert_eq!(e.lease(&a, SYM)["decision"]["outcome"], "allow");
    assert_eq!(e.lease(&a, SYM)["advice"], Value::Null);
    let d = e.lease(&b, SYM);
    assert_eq!(d["decision"]["outcome"], "deny", "{d}");
    let advice = d["advice"].as_str().expect("advice");
    assert!(
        advice.contains("(session s1) is on src/lib.rs#charge"),
        "{advice}"
    );
    assert!(advice.contains("\"fix\""), "{advice}");
    assert!(advice.contains("negotiate"), "{advice}");
    assert!(advice.contains("lease_interest"), "{advice}");
}

#[test]
fn a_change_without_its_lease_is_told_the_same() {
    let (mut e, a, b) = two_agents();
    let base = e.trunk();
    e.lease(&a, SYM);
    let edited = LIB.replacen("    a\n", "    a + 1\n", 1);
    e.wrote(&b, "src/lib.rs");
    let r = e.propose(&b, &base, vec![file("src/lib.rs", &edited)], &[SYM]);
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert!(
        r["advice"].as_str().unwrap().contains("(session s1)"),
        "{r}"
    );
}

#[test]
fn an_agent_is_told_what_a_message_says_and_told_once() {
    let (mut e, a, b) = two_agents();
    assert_eq!(inbox(&mut e, &a)["text"], Value::Null);
    let sent = claim(&mut e, &b, "s1", "the bug fix needs it");

    let got = inbox(&mut e, &a);
    assert_eq!(got["events"][0]["kind"], "message", "{got}");
    assert_eq!(got["events"][0]["seq"], sent["seq"]);
    assert_eq!(got["events"][0]["from"], "s2");
    assert_eq!(
        got["events"][0]["message"]["reason"],
        "the bug fix needs it"
    );
    let text = got["text"].as_str().unwrap();
    assert!(text.contains("session s2 in thread t1"), "{text}");
    assert!(text.contains("the bug fix needs it"), "{text}");
    assert!(text.contains("not an instruction"), "{text}");

    assert_eq!(inbox(&mut e, &a)["events"], json!([]));
    // Nobody wrote to the sender.
    assert_eq!(inbox(&mut e, &b)["events"], json!([]));
    // Asking still finds it.
    let all = e.ok("events", None, Some(&a), json!({}));
    assert_eq!(
        all["events"][0]["message"]["reason"],
        "the bug fix needs it"
    );
}

#[test]
fn what_an_agent_read_itself_is_not_told_again() {
    let (mut e, a, b) = two_agents();
    claim(&mut e, &b, "s1", "one");
    let read = e.ok("events", None, Some(&a), json!({}));
    assert_eq!(read["events"].as_array().unwrap().len(), 1, "{read}");
    assert_eq!(inbox(&mut e, &a)["events"], json!([]));

    // A read that starts further on skips what came before it.
    let next = read["next"].as_u64().unwrap();
    let sent = claim(&mut e, &b, "s1", "two");
    let past = sent["seq"].as_u64().unwrap() + 1;
    e.ok("events", None, Some(&a), json!({"from": past}));
    assert_eq!(past, next + 1);
    assert_eq!(inbox(&mut e, &a)["events"][0]["message"]["reason"], "two");
}

#[test]
fn a_hook_tells_an_agent_that_calls_no_tool_of_lonca() {
    let (mut e, a, b) = two_agents();
    let quiet = after_tool(&mut e, &a, "claude-code", "PostToolUse");
    assert!(quiet.get("output").is_none(), "{quiet}");

    claim(&mut e, &b, "s1", "needs it");
    let r = after_tool(&mut e, &a, "claude-code", "PostToolUse");
    let out = &r["output"]["hookSpecificOutput"];
    assert_eq!(out["hookEventName"], "PostToolUse", "{r}");
    let context = out["additionalContext"].as_str().unwrap();
    assert!(context.contains("needs it"), "{context}");
    assert!(context.contains("mcp__lonca__negotiate"), "{context}");

    let again = after_tool(&mut e, &a, "claude-code", "PostToolUse");
    assert!(again.get("output").is_none(), "{again}");
}

#[test]
fn a_hook_before_a_tool_leaves_the_news_for_after() {
    let (mut e, a, b) = two_agents();
    claim(&mut e, &b, "s1", "needs it");
    let before = after_tool(&mut e, &a, "claude-code", "PreToolUse");
    assert!(before.get("output").is_none(), "{before}");
    let after = after_tool(&mut e, &a, "claude-code", "PostToolUse");
    assert!(after.get("output").is_some(), "{after}");
}

#[test]
fn a_harness_without_a_way_in_keeps_the_news_for_the_mcp_server() {
    let (mut e, a, b) = two_agents();
    claim(&mut e, &b, "s1", "needs it");
    let r = after_tool(&mut e, &a, "opencode", "after_tool");
    assert!(r.get("output").is_none(), "{r}");
    assert_eq!(inbox(&mut e, &a)["events"][0]["kind"], "message");
}

#[test]
fn gemini_hears_it_in_its_own_shape() {
    let (mut e, a, b) = two_agents();
    claim(&mut e, &b, "s1", "needs it");
    let r = after_tool(&mut e, &a, "gemini", "AfterTool");
    let context = r["output"]["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(context.contains("mcp_lonca_negotiate"), "{context}");
}

#[test]
fn a_handed_over_lease_and_a_reservation_are_told_too() {
    let (mut e, a, b) = two_agents();
    let set = e.lease(&a, SYM)["set"].as_str().unwrap().to_string();
    let message = json!({"type": "yield", "set": set, "to": "s2"});
    let p = json!({"thread": "t1", "to_session": "s2", "message": message});
    e.ok("negotiate", None, Some(&a), p);
    let got = inbox(&mut e, &b);
    assert_eq!(got["events"][0]["kind"], "lease_received", "{got}");
    assert!(
        got["text"].as_str().unwrap().contains("is yours now"),
        "{got}"
    );

    let items = json!([{"symbol": SYM, "kind": "edit"}]);
    let p = json!({"items": items, "intent": "next"});
    e.ok("lease.interest", None, Some(&a), p);
    e.ok("lease.release", None, Some(&b), json!({"set": set}));
    let got = inbox(&mut e, &a);
    assert_eq!(got["events"][0]["kind"], "reserved", "{got}");
    let text = got["text"].as_str().unwrap();
    assert!(text.contains("reserved for you for 60 s"), "{text}");
    assert!(text.contains(SYM), "{text}");
    // One window is told once, however often the state is read.
    assert_eq!(inbox(&mut e, &a)["events"], json!([]));
}

#[test]
fn asking_from_where_you_left_off_finds_an_older_request_s_approval() {
    let (mut e, _, _) = two_agents();
    let base = e.trunk();
    let c = e.session("s3", &["src/**"]);
    e.lease(&c, SYM);
    let edited = LIB.replacen("    a\n", "    a + 1\n", 1);
    let r = e.propose(&c, &base, vec![file("src/lib.rs", &edited)], &[SYM]);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let asked = r["seq"].as_u64().unwrap();
    let next = e.ok("events", None, Some(&c), json!({}))["next"].clone();
    let d = e.human(Op::Approve {
        target_seq: asked,
        note: "reviewed".into(),
        checks: vec![],
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    let got = e.ok("events", None, Some(&c), json!({"from": next}));
    assert_eq!(got["events"][0]["kind"], "approved", "{got}");
    assert_eq!(got["events"][0]["target_seq"], asked);
}
