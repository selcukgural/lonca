//! A runner waits for what it should wake an agent for (issue #262):
//! `events.watch`, with the human session it started its agents with.
//! Read-only, never logged, never told: the agent's `inbox` keeps its news.

mod common;
use common::*;

use lonca_daemon::protocol::Response;
use std::time::{Duration, Instant};

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

fn next_seq(e: &mut Env) -> u64 {
    e.ok("status", Some("demo"), None, json!({}))["next_seq"]
        .as_u64()
        .unwrap()
}

fn watch(e: &mut Env, params: Value) -> Value {
    e.ok("events.watch", Some("demo"), None, params)
}

/// `events.watch` from another thread, as a runner on its own connection.
fn waiter(svc: &Arc<Service>, token: &str, params: Value) -> std::thread::JoinHandle<Response> {
    let svc = svc.clone();
    let token = token.to_string();
    std::thread::spawn(move || {
        svc.handle(Request {
            id: 77,
            method: "events.watch".into(),
            repo: Some("demo".into()),
            token: Some(token),
            params,
        })
    })
}

fn kinds(answer: &Value) -> Vec<(String, String)> {
    let events = answer["events"].as_array().unwrap();
    let pair = |e: &Value| {
        let s = e["session"].as_str().unwrap().to_string();
        (s, e["kind"].as_str().unwrap().to_string())
    };
    events.iter().map(pair).collect()
}

fn yield_to(e: &mut Env, from: &str, to: &str, set: &str) {
    let message = json!({"type": "yield", "set": set, "to": to});
    let p = json!({"thread": "t1", "to_session": to, "message": message});
    let r = e.ok("negotiate", None, Some(from), p);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

#[test]
fn a_waiter_wakes_on_a_handover_and_lets_others_work_meanwhile() {
    let (mut e, a, b) = two_agents();
    let set = e.lease(&a, SYM)["set"].as_str().unwrap().to_string();
    let from = next_seq(&mut e);
    let token = e.login().unwrap();
    let t = Instant::now();
    let w = waiter(
        &e.svc,
        &token,
        json!({"from": from, "sessions": ["s2"], "wait_ms": 20_000}),
    );
    std::thread::sleep(Duration::from_millis(200));
    // Another client leases meanwhile: answered, and the waiter, which has
    // nothing for s2 in that entry, goes on waiting.
    let r = e.lease(&b, "src/lib.rs#refund");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    std::thread::sleep(Duration::from_millis(100));
    assert!(!w.is_finished(), "a lease of s2's own woke it");
    yield_to(&mut e, &a, "s2", &set);
    let got = w.join().unwrap();
    let waited = t.elapsed().as_millis();
    assert!(got.ok, "{:?}", got.error);
    let got = got.result;
    let s2 = |k: &str| ("s2".to_string(), k.to_string());
    assert_eq!(
        kinds(&got),
        vec![s2("lease_received"), s2("message")],
        "{got}"
    );
    assert_eq!(got["events"][0]["from"], "s1");
    assert_eq!(got["next"].as_u64().unwrap(), next_seq(&mut e));
    // Signalled, not polled: under the 2 s poll slice after 300 ms of sleep.
    assert!(waited < 1_800, "waited {waited} ms");
}

#[test]
fn a_watcher_takes_nothing_from_the_inbox_and_never_reads_the_words() {
    let (mut e, a, b) = two_agents();
    let from = next_seq(&mut e);
    let message = json!({"type": "claim", "symbols": [SYM], "reason": "SECRET-WORDS-1729"});
    let p = json!({"thread": "t-hidden", "to_session": "s2", "message": message});
    e.ok("negotiate", None, Some(&a), p);

    let got = watch(&mut e, json!({"from": from}));
    assert_eq!(kinds(&got), vec![("s2".into(), "message".into())], "{got}");
    let said = got.to_string();
    assert!(!said.contains("SECRET-WORDS-1729"), "{said}");
    assert!(!said.contains("t-hidden"), "{said}");
    // Watched twice, and the agent is still told, once.
    watch(&mut e, json!({"from": from}));
    let inbox = e.ok("inbox", None, Some(&b), json!({}));
    assert_eq!(inbox["events"][0]["kind"], "message", "{inbox}");
    assert!(
        inbox["text"]
            .as_str()
            .unwrap()
            .contains("SECRET-WORDS-1729")
    );
}

#[test]
fn an_integration_names_the_change_and_its_session() {
    let (mut e, a, _b) = two_agents();
    let base = e.trunk();
    e.wrote(&a, "src/lib.rs");
    e.lease(&a, SYM);
    let edited = LIB.replacen("    a\n", "    a + 1\n", 1);
    let r = e.propose(&a, &base, vec![file("src/lib.rs", &edited)], &[SYM]);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let from = next_seq(&mut e);
    e.svc.process_all();
    let got = watch(&mut e, json!({"from": from, "wait_ms": 5_000}));
    assert_eq!(
        kinds(&got),
        vec![("s1".into(), "integrated".into())],
        "{got}"
    );
    assert_eq!(got["events"][0]["change"], r["change"]);
    assert!(got["events"][0]["seq"].as_u64().unwrap() >= from);
}

#[test]
fn a_reservation_is_reported_once_while_it_lasts() {
    let (mut e, a, b) = two_agents();
    let set = e.lease(&b, SYM)["set"].as_str().unwrap().to_string();
    let items = json!([{"symbol": SYM, "kind": "edit"}]);
    e.ok(
        "lease.interest",
        None,
        Some(&a),
        json!({"items": items, "intent": "next"}),
    );
    let from = next_seq(&mut e);
    e.ok("lease.release", None, Some(&b), json!({"set": set}));
    let got = watch(&mut e, json!({"from": from}));
    let reserved: Vec<&Value> = got["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "reserved")
        .collect();
    assert_eq!(reserved.len(), 1, "{got}");
    assert_eq!(reserved[0]["session"], "s1");
    assert!(reserved[0]["seq"].is_null(), "{got}");
    assert!(reserved[0]["until_ms"].as_i64().unwrap() > e.now());
    let id = reserved[0]["reservation"].clone();
    assert_eq!(got["reserved"], json!([id]));

    // Passed back, it is known: the wait runs its time and ends empty, and
    // the reservation is still listed.
    let next = got["next"].clone();
    let t = Instant::now();
    let again = watch(
        &mut e,
        json!({"from": next, "reserved": [id], "wait_ms": 300}),
    );
    assert!(t.elapsed().as_millis() >= 250);
    assert_eq!(again["events"], json!([]), "{again}");
    assert_eq!(again["reserved"], json!([id]));
    // Without it, it is reported again: the watcher keeps no state.
    let fresh = watch(&mut e, json!({"from": next}));
    assert_eq!(fresh["events"][0]["reservation"], id);
    // The agent is told as well: nothing was taken from its inbox.
    let inbox = e.ok("inbox", None, Some(&a), json!({}));
    assert_eq!(inbox["events"][0]["kind"], "reserved", "{inbox}");
}

#[test]
fn from_now_on_nothing_older_and_an_empty_wait_runs_its_time() {
    let (mut e, a, _b) = two_agents();
    let p = json!({"thread": "t1", "to_session": "s2",
        "message": {"type": "claim", "symbols": [SYM], "reason": "old"}});
    e.ok("negotiate", None, Some(&a), p);
    let t = Instant::now();
    let got = watch(&mut e, json!({"wait_ms": 300}));
    let held = t.elapsed().as_millis();
    assert_eq!(got["events"], json!([]), "{got}");
    assert_eq!(got["next"].as_u64().unwrap(), next_seq(&mut e));
    assert!((250..3_000).contains(&held), "held {held} ms");
    // No wait, nothing new: at once.
    let t = Instant::now();
    let got = watch(&mut e, json!({"from": got["next"]}));
    assert_eq!(got["events"], json!([]));
    assert!(t.elapsed().as_millis() < 200);
    // Entries that are nobody's it watches end no wait.
    let from = next_seq(&mut e);
    let token = e.login().unwrap();
    let w = waiter(&e.svc, &token, json!({"from": from, "wait_ms": 600}));
    e.human(Op::Freeze { reason: "x".into() });
    let got = w.join().unwrap().result;
    assert_eq!(got["events"], json!([]), "{got}");
    assert!(got["next"].as_u64().unwrap() > from);
}

#[test]
fn an_ended_session_ends_the_wait_with_its_reason() {
    let (mut e, _a, _b) = two_agents();
    let from = next_seq(&mut e);
    let token = e.login().unwrap();
    let w = waiter(
        &e.svc,
        &token,
        json!({"from": from, "sessions": ["s1", "s2"], "wait_ms": 20_000}),
    );
    std::thread::sleep(Duration::from_millis(200));
    let r = e.human(Op::SessionEnd {
        session: "s1".into(),
        reason: "runner stopped it".into(),
    });
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let got = w.join().unwrap().result;
    assert_eq!(
        got["ended"],
        json!([{"session": "s1", "reason": "ended: runner stopped it"}]),
        "{got}"
    );
    // While it is named, every call ends at once.
    let t = Instant::now();
    let again = watch(
        &mut e,
        json!({"from": got["next"], "sessions": ["s1", "s2"], "wait_ms": 5_000}),
    );
    assert!(t.elapsed().as_millis() < 500);
    assert_eq!(again["ended"][0]["session"], "s1");
    // Without a list, an ended session is simply not watched.
    let got = watch(&mut e, json!({"from": again["next"], "wait_ms": 100}));
    assert_eq!(got["ended"], json!([]));

    // An expired one says so: it takes no entry.
    e.advance(3_600_000);
    let got = watch(&mut e, json!({"sessions": ["s2"], "wait_ms": 5_000}));
    assert_eq!(
        got["ended"],
        json!([{"session": "s2", "reason": "expired"}]),
        "{got}"
    );
}

#[test]
fn only_a_human_watches_and_only_its_own_sessions() {
    let (mut e, a, _b) = two_agents();
    // An agent token is refused: a runner watches with the human session.
    let r = e.call("events.watch", None, Some(&a), json!({}));
    assert_eq!(r.unwrap_err().0, "forbidden");
    // No token at all.
    let r = e.anon("events.watch", Some("demo"), None, json!({}));
    assert_eq!(r.unwrap_err().0, "unauthenticated");

    let bora = KeyPair::generate();
    e.human(Op::HumanEnroll {
        human: "bora".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: bora.public_hex(),
        },
    });
    let sig = sign_login_ed25519(&bora, "bora", None, 3_600_000, e.now());
    let tb = e
        .anon("human.login", None, None, json!({"sig": sig}))
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    // Ayşe's session and one that never was get the same refusal.
    for named in ["s1", "nope"] {
        let r = e.anon(
            "events.watch",
            Some("demo"),
            Some(&tb),
            json!({"sessions": [named]}),
        );
        let (code, msg) = r.unwrap_err();
        assert_eq!(code, "forbidden");
        assert_eq!(msg, format!("session {named} is not one you started"));
    }
    // Watching everything of its own, Bora sees nothing of Ayşe's agents.
    let p = json!({"thread": "t1", "to_session": "s2",
        "message": {"type": "claim", "symbols": [SYM], "reason": "x"}});
    e.ok("negotiate", None, Some(&a), p);
    let got = e
        .anon("events.watch", Some("demo"), Some(&tb), json!({"from": 0}))
        .unwrap();
    assert_eq!(got["events"], json!([]), "{got}");
    // Ayşe does.
    let got = watch(&mut e, json!({"from": 0}));
    assert!(
        kinds(&got).contains(&("s2".into(), "message".into())),
        "{got}"
    );
    // Nothing of this was logged.
    let before = next_seq(&mut e);
    watch(&mut e, json!({"from": 0}));
    assert_eq!(next_seq(&mut e), before);
}

#[test]
fn an_approval_of_a_request_older_than_from_is_found() {
    let (mut e, _, _) = two_agents();
    let base = e.trunk();
    let c = e.session("s3", &["src/**"]);
    e.lease(&c, SYM);
    let edited = LIB.replacen("    a\n", "    a + 1\n", 1);
    let r = e.propose(&c, &base, vec![file("src/lib.rs", &edited)], &[SYM]);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let asked = r["seq"].as_u64().unwrap();
    let from = next_seq(&mut e);
    let d = e.human(Op::Approve {
        target_seq: asked,
        note: "reviewed".into(),
        checks: vec![],
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    let got = watch(&mut e, json!({"from": from, "sessions": ["s3"]}));
    assert_eq!(kinds(&got)[0], ("s3".into(), "approved".into()), "{got}");
    assert_eq!(got["events"][0]["seq"], d["seq"]);
}
