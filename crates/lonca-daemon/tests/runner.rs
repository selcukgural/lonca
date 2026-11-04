//! What a runner (imece) reads: the protocol number, a review list
//! from one `status`, and a `log` that waits for the next entry
//! (issue #76).

mod common;
use common::*;

use lonca_daemon::service::PROTOCOL;
use std::time::Instant;

#[test]
fn ping_states_the_protocol_number() {
    let mut e = Env::new();
    let p = e.anon("ping", None, None, json!({})).unwrap();
    assert_eq!(p["protocol"], PROTOCOL);
    assert_eq!(p["protocol"], 1);
    assert_eq!(p["version"], env!("CARGO_PKG_VERSION"));
}

/// A tainted agent proposes; the escalated entry in `status.pending`
/// says whose change it is, on which base, with what intent, since
/// when and touching which files.
#[test]
fn a_pending_entry_fills_a_review_list() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(
        vec![file("src/lib.rs", LIB), file("notes.md", "a\n")],
        "seed",
    );
    e.svc.process_all();
    let base = e.trunk();
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    e.ok(
        "hook.event",
        None,
        Some(&token),
        json!({"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": "https://evil.example/issue"}, "workspace": e.root.join("ws")}),
    );
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, "src/lib.rs#refund");
    let new = LIB.replace(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        "pub fn refund(a: u64) -> u64 {\n    0\n",
    );
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &new)],
        &["src/lib.rs#refund"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let seq = r["seq"].as_u64().unwrap();
    let change = r["change"].clone();
    let entry = &e.ok("log", Some("demo"), None, json!({"from": seq, "limit": 1}))[0]["entry"];

    let st = e.ok("status", Some("demo"), None, json!({}));
    let pending = st["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "{st}");
    let p = &pending[0];
    assert_eq!(p["seq"], seq);
    assert_eq!(p["op"], "change.propose");
    assert_eq!(p["change"], change);
    assert_eq!(p["base"], json!(base));
    assert_eq!(p["intent"], "agent change");
    assert_eq!(p["agent"], "bot-s1");
    assert_eq!(p["task"], "T-1");
    assert_eq!(p["actor"], "agent:bot-s1/s1");
    assert_eq!(p["created_ms"], entry["time_ms"]);
    assert_eq!(p["paths"], json!(["src/lib.rs"]));
    assert_eq!(p["required"].as_u64().unwrap(), 1);
    assert_eq!(p["approvals"], json!([]));
    assert!(
        p["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "tainted_session"),
        "{p}"
    );
    // The change record says the same about base, time and files.
    let c = st["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["change"] == change)
        .unwrap();
    assert_eq!(c["base"], json!(base));
    assert_eq!(c["created_ms"], entry["time_ms"]);
    assert_eq!(c["paths"], json!(["src/lib.rs"]));
    assert_eq!(c["version"], 1);
    assert_eq!(c["status"]["status"], "pending");
    assert_eq!(st["next_seq"], seq + 1);
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["created_ms"], entry["time_ms"]);

    // The human's own seed change: no agent, no task; its files listed.
    let seed = st["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["intent"] == "seed")
        .unwrap();
    assert_eq!(seed["paths"], json!(["notes.md", "src/lib.rs"]));
    assert_eq!(seed["status"]["status"], "integrated");

    // A pending operation that is not a change carries nulls, not junk.
    e.human(Op::Approve {
        target_seq: seq,
        note: "ok".into(),
    });
    assert!(
        e.ok("status", Some("demo"), None, json!({}))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn log_waits_for_the_next_entry_and_gives_up_on_time() {
    let mut e = Env::new();
    e.init(None);
    let next = e.ok("status", Some("demo"), None, json!({}))["next_seq"]
        .as_u64()
        .unwrap();
    // Entries exist: back at once, however long the wait.
    let t = Instant::now();
    let ops = e.ok(
        "log",
        Some("demo"),
        None,
        json!({"from": 0, "wait_ms": 5000}),
    );
    assert_eq!(ops.as_array().unwrap().len() as u64, next);
    assert!(t.elapsed().as_millis() < 1000);
    // Nothing past `from`: the request is held for the time asked, then empty.
    let t = Instant::now();
    let ops = e.ok(
        "log",
        Some("demo"),
        None,
        json!({"from": next, "wait_ms": 300}),
    );
    assert_eq!(ops, json!([]));
    let held = t.elapsed().as_millis();
    assert!((250..3000).contains(&held), "held {held} ms");
    // Without a wait: empty at once.
    let t = Instant::now();
    assert_eq!(
        e.ok("log", Some("demo"), None, json!({"from": next})),
        json!([])
    );
    assert!(t.elapsed().as_millis() < 200);
    // A negative wait is no wait; the cap itself is pinned with the
    // document in the service's unit tests.
    let t = Instant::now();
    assert_eq!(
        e.ok(
            "log",
            Some("demo"),
            None,
            json!({"from": next, "wait_ms": -5})
        ),
        json!([])
    );
    assert!(t.elapsed().as_millis() < 200);

    // An entry appended from another thread ends the wait early.
    let svc = e.svc.clone();
    let token = e.login().unwrap();
    let body = e.sign(&Op::Freeze { reason: "x".into() });
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let r = svc.handle(Request {
            id: 99,
            method: "human.submit".into(),
            repo: Some("demo".into()),
            token: Some(token),
            params: body,
        });
        assert!(r.ok, "{:?}", r.error);
    });
    let t = Instant::now();
    let ops = e.ok(
        "log",
        Some("demo"),
        None,
        json!({"from": next, "wait_ms": 20_000}),
    );
    let waited = t.elapsed().as_millis();
    writer.join().unwrap();
    assert_eq!(ops.as_array().unwrap().len(), 1, "{ops}");
    assert_eq!(ops[0]["entry"]["op"]["op"], "freeze");
    assert_eq!(ops[0]["entry"]["seq"], next);
    assert!(
        waited < 5000,
        "waited {waited} ms for an entry that came after 200"
    );
}
