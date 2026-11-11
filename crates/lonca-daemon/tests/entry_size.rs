//! What a caller can add to the log is bounded: an operation past
//! `MAX_OP_BYTES` is refused before it is decided or signed, a denied
//! submission that needed no session leaves no entry, and the proxy records
//! connections at the session's rate.

mod common;
use common::*;

use lonca_daemon::repo::MAX_OP_BYTES;

fn next_seq(e: &mut Env) -> u64 {
    let s = e.ok("status", Some("demo"), None, json!({}));
    s["next_seq"].as_u64().unwrap()
}

/// A refused request left no trace: the log audits as it would without it.
fn assert_audits(e: &Env) {
    let audit = lonca_audit::audit(&e.store(), lonca_audit::Options::default()).unwrap();
    assert!(audit.ok(), "{:#?}", audit.findings);
}

/// A freeze signed by the human, with a reason of `len` bytes.
fn freeze(e: &Env, len: usize) -> Value {
    e.sign(&Op::Freeze {
        reason: "z".repeat(len),
    })
}

/// What an entry counts of a submission: its operation and its signature.
fn counted(body: &Value) -> usize {
    serde_json::to_vec(&body["op"]).unwrap().len() + serde_json::to_vec(&body["sig"]).unwrap().len()
}

#[test]
fn an_operation_at_the_limit_is_logged_and_one_byte_more_is_not() {
    let mut e = Env::new();
    e.init(None);
    let room = MAX_OP_BYTES - counted(&freeze(&e, 0));
    let before = next_seq(&mut e);

    let over = freeze(&e, room + 1);
    assert_eq!(counted(&over), MAX_OP_BYTES + 1);
    let (code, message) = e
        .call("human.submit", Some("demo"), None, over)
        .unwrap_err();
    assert_eq!(code, "invalid");
    assert!(
        message.contains("freeze")
            && message.contains(&format!("{} bytes", MAX_OP_BYTES + 1))
            && message.contains("Shorten"),
        "{message}"
    );
    assert_eq!(next_seq(&mut e), before, "a refused size is not an entry");

    let at = freeze(&e, room);
    assert_eq!(counted(&at), MAX_OP_BYTES);
    let r = e.ok("human.submit", Some("demo"), None, at);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(next_seq(&mut e), before + 1);
    assert_audits(&e);
}

/// What the policy counts is a decision, and a refused decision is logged
/// whole: the size is asked before it.
#[test]
fn a_long_list_the_policy_would_deny_is_not_logged_either() {
    let mut e = Env::new();
    e.init(None);
    let t = e.session("s1", &["src/**"]);
    let before = next_seq(&mut e);
    let items: Vec<LeaseItem> = (0..2_000)
        .map(|i| LeaseItem {
            symbol: format!("src/billing.rs#a_symbol_with_a_long_name_{i}"),
            kind: LeaseKind::Edit,
            names: Vec::new(),
        })
        .collect();
    let p = json!({"items": items, "intent": "all of it", "ttl_ms": 600_000});
    let (code, _) = e.call("lease.acquire", None, Some(&t), p).unwrap_err();
    assert_eq!(code, "invalid");
    assert_eq!(next_seq(&mut e), before);
}

#[test]
fn a_proposal_with_a_megabyte_of_intent_is_refused_unlogged() {
    let mut e = Env::new();
    e.init(None);
    let t = e.session("s1", &["src/**"]);
    let base = e.trunk();
    let before = next_seq(&mut e);
    let claim = Claim {
        intent: "y".repeat(1 << 20),
        edits: vec!["src/billing.rs#charge".into()],
        ..Default::default()
    };
    let files = vec![file(
        "src/billing.rs",
        "pub fn charge(a: u64) -> u64 {\n    a + 1\n}\n",
    )];
    let p = json!({"base": base, "files": files, "claim": claim});
    let (code, message) = e.call("change.propose", None, Some(&t), p).unwrap_err();
    assert_eq!(code, "invalid");
    assert!(message.contains("change.propose"), "{message}");
    assert_eq!(next_seq(&mut e), before);
    assert_audits(&e);
}

#[test]
fn a_hook_event_with_a_path_past_the_limit_is_not_an_observation() {
    let mut e = Env::new();
    e.init(None);
    let t = e.session("s1", &["src/**"]);
    e.bind(&t);
    let ws = e.root.join("ws");
    let before = next_seq(&mut e);
    let path = ws.join("a".repeat(MAX_OP_BYTES));
    let p = json!({"hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_input": {"file_path": path}, "workspace": ws});
    let (code, _) = e.call("hook.event", None, Some(&t), p).unwrap_err();
    assert_eq!(code, "invalid");
    assert_eq!(next_seq(&mut e), before);
    // An event of ordinary size is still heard.
    e.wrote(&t, "src/billing.rs");
    assert_eq!(next_seq(&mut e), before + 1);
}

/// `human.recover` comes in on its signature alone. Denied, it is in the
/// security log and not in the operation log; allowed, it is an entry.
#[test]
fn a_denied_recovery_with_no_session_leaves_no_entry() {
    let mut e = Env::new();
    e.init(None);
    let rec = KeyPair::generate();
    e.human(Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: rec.public_hex(),
        },
    });
    let fresh = KeyPair::generate();
    let op = Op::HumanRecover {
        human: "ayse".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: fresh.public_hex(),
        },
    };
    let before = next_seq(&mut e);
    for _ in 0..5 {
        let sig = sign_ed25519(&KeyPair::generate(), "ayse", "demo", &op, e.now());
        let (code, message) = e
            .anon(
                "human.submit",
                Some("demo"),
                None,
                json!({"op": op, "sig": sig}),
            )
            .unwrap_err();
        assert_eq!(code, "forbidden");
        assert!(message.contains("not logged"), "{message}");
    }
    assert_eq!(next_seq(&mut e), before, "five refusals, no entry");
    let events = e.ok("security.events", None, None, json!({}));
    let refused = events["events"].as_array().unwrap().iter();
    let refused = refused.filter(|x| x["method"] == "human.submit" && x["code"] == "forbidden");
    assert_eq!(refused.count(), 5, "{events}");

    let sig = sign_ed25519(&rec, "ayse", "demo", &op, e.now());
    let r = e
        .anon(
            "human.submit",
            Some("demo"),
            None,
            json!({"op": op, "sig": sig}),
        )
        .unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    e.human = fresh;
    assert_eq!(next_seq(&mut e), before + 1);
    assert_audits(&e);
}

/// A human with a session still has a denied operation logged: that record
/// is what a reviewer reads, and the session says who asked.
#[test]
fn a_denied_operation_of_a_signed_in_human_is_still_logged() {
    let mut e = Env::new();
    e.init(None);
    let before = next_seq(&mut e);
    let op = Op::Unfreeze {
        reason: "nothing is frozen".into(),
    };
    let r = e.human(op);
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert_eq!(next_seq(&mut e), before + 1);
}

fn with_rate(e: &mut Env, rate: u32) {
    let policy = lonca_policy::config::DEFAULT_POLICY;
    let config = format!("[sessions]\nops_per_minute = {rate}\n");
    let p = json!({"config": config, "policy": policy});
    let prep = e.ok("human.prepare_policy", Some("demo"), None, p);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
}

#[test]
fn the_proxy_records_connections_at_the_sessions_rate_and_refuses_the_rest() {
    let mut e = Env::new();
    e.init(None);
    with_rate(&mut e, 3);
    let t = e.session("s1", &["src/**"]);
    e.bind(&t);
    let before = next_seq(&mut e);
    let mut peer = 40_000u16;
    let mut connect = |e: &Env| {
        peer += 1;
        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], peer));
        let v = e.svc.proxy_connect(None, "example.org", 443, addr);
        e.svc.proxy_finished(addr);
        v
    };
    for _ in 0..3 {
        let v = connect(&e);
        assert!(v.allow, "{}", v.reason);
    }
    assert_eq!(
        next_seq(&mut e),
        before + 3,
        "each one let through is on record"
    );
    for _ in 0..10 {
        let v = connect(&e);
        assert!(!v.allow);
        assert!(v.reason.contains("sessions.ops_per_minute"), "{}", v.reason);
    }
    assert_eq!(
        next_seq(&mut e),
        before + 3,
        "what is refused for the rate is not"
    );
    // The session's own operations have their own count.
    let r = e.ok("session.heartbeat", None, Some(&t), json!({}));
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    // A third of a minute gives one connection back at three a minute.
    e.advance(20_000);
    assert!(connect(&e).allow);
    assert!(!connect(&e).allow);
    assert_audits(&e);
}
