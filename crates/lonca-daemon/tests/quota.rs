//! The verification quota (issue #59): past it a session proposes nothing
//! more, and what it queued is rejected without a run.

mod common;
use common::*;

use std::sync::atomic::Ordering;

use lonca_audit::{Options, audit};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY};
use serde_json::{Value, json};

const DAY: i64 = 86_400_000;

/// A repository whose test takes a little over a second, under `quota`.
fn repo(quota: (&str, &str)) -> Env {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let config = DEFAULT_CONFIG
        .replace("# test = \"cargo test --offline\"", "test = \"sleep 1.1\"")
        .replace(quota.0, quota.1);
    assert!(config.contains(quota.1));
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    e
}

/// A bound session that may edit `charge` and `refund`.
fn agent(e: &mut Env, id: &str) -> String {
    let token = e.session(id, &["src/**"]);
    e.bind(&token);
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, "src/lib.rs#charge");
    e.lease(&token, "src/lib.rs#refund");
    token
}

/// `token` proposes `charge` returning `text`.
fn propose(e: &mut Env, token: &str, text: &str) -> Value {
    let base = e.trunk();
    let files = vec![file("src/lib.rs", &LIB.replacen("    a\n", text, 1))];
    e.propose(token, &base, files, &["src/lib.rs#charge"])
}

/// `token` proposes `refund` returning 0: no conflict with `charge`.
fn refund(e: &mut Env, token: &str) -> Value {
    let base = e.trunk();
    let at = LIB.find("refund").unwrap();
    let text = format!(
        "{}{}",
        &LIB[..at],
        LIB[at..].replacen("    a\n", "    0\n", 1)
    );
    e.propose(
        token,
        &base,
        vec![file("src/lib.rs", &text)],
        &["src/lib.rs#refund"],
    )
}

fn get(e: &mut Env, change: &Value) -> Value {
    e.ok("change.get", Some("demo"), None, json!({"change": change}))
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

#[test]
fn past_the_session_quota_the_queue_rejects_without_a_run() {
    let mut e = repo(("session_seconds = 0", "session_seconds = 1"));
    let token = agent(&mut e, "s1");
    let first = propose(&mut e, &token, "    a * 2\n");
    let second = refund(&mut e, &token);
    let runs = e.svc.verification_runs();
    assert_eq!(e.svc.process_all(), 2);
    assert_eq!(e.svc.verification_runs(), runs + 1, "the second never ran");
    assert_eq!(
        get(&mut e, &first["change"])["status"]["status"],
        "integrated"
    );
    let c = get(&mut e, &second["change"]);
    assert_eq!(c["status"]["status"], "rejected");
    assert_eq!(
        c["status"]["reasons"],
        json!(["verification_quota:session"])
    );
    assert_eq!(c["evidence"], json!([]));

    // Its lease went with the integration; the quota is said all the same.
    let r = propose(&mut e, &token, "    a * 4\n");
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    let quota = json!("verification_quota:session");
    assert_eq!(r["decision"]["reasons"][0], quota, "{r}");
    let status = e.ok("status", Some("demo"), None, json!({}));
    let spent = status["sessions"][0]["verification_ms"].as_u64().unwrap();
    assert!(spent >= 1100, "{status}");
    assert!(status["verification_day_ms"].as_u64().unwrap() >= spent);
    // Another session has a quota of its own.
    let other = agent(&mut e, "s2");
    let r = propose(&mut e, &other, "    a * 5\n");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    audited(&e);
}

/// The day ends between the look at the quota and the entry: what was not
/// run is not logged as if it had been, it goes through the checks.
#[test]
fn a_change_held_back_at_midnight_is_verified_after_it() {
    let mut e = repo(("day_seconds = 0", "day_seconds = 1"));
    let token = agent(&mut e, "s1");
    let first = propose(&mut e, &token, "    a * 2\n");
    let second = refund(&mut e, &token);
    assert!(e.svc.process_one("demo").unwrap().is_some());
    assert_eq!(
        get(&mut e, &first["change"])["status"]["status"],
        "integrated"
    );
    let runs = e.svc.verification_runs();
    // Every reading of the clock moves it a millisecond. The queue reads it
    // once to batch, once before the merge and once after: the last is
    // midnight.
    let midnight = (e.now() / DAY + 1) * DAY;
    e.clock.store(midnight - 2, Ordering::SeqCst);
    let done = e.svc.process_one("demo").unwrap().expect("an entry");
    assert!(done.entry.time_ms >= midnight);
    assert_eq!(e.svc.verification_runs(), runs + 1, "it ran after all");
    let c = get(&mut e, &second["change"]);
    assert_eq!(c["status"]["status"], "integrated", "{c}");
    assert_eq!(c["evidence"][1]["result"], "pass", "{c}");
    audited(&e);
}

/// A run that ended unlogged would cost nothing: while it runs, its change
/// can not be withdrawn by the agent.
#[test]
fn a_change_under_its_checks_can_not_be_withdrawn() {
    let mut e = repo(("session_seconds = 0", "session_seconds = 60"));
    let token = agent(&mut e, "s1");
    let r = propose(&mut e, &token, "    a * 2\n");
    let runs = e.svc.verification_runs();
    let svc = e.svc.clone();
    let queue = std::thread::spawn(move || svc.process_all());
    let started = std::time::Instant::now();
    while e.svc.verification_runs() == runs {
        assert!(started.elapsed().as_secs() < 30, "the run never started");
        std::thread::yield_now();
    }
    let withdraw = json!({"change": r["change"]});
    let err = e.call("change.withdraw", None, Some(&token), withdraw.clone());
    assert_eq!(err.unwrap_err().0, "verifying");
    assert_eq!(queue.join().unwrap(), 1);
    assert_eq!(get(&mut e, &r["change"])["status"]["status"], "integrated");
    let status = e.ok("status", Some("demo"), None, json!({}));
    assert!(status["sessions"][0]["verification_ms"].as_u64().unwrap() >= 1100);
    // Out of the queue, it is the log's decision again.
    let r = e
        .call("change.withdraw", None, Some(&token), withdraw)
        .unwrap();
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
}

/// A batch stops in front of a change past its quota; that change is
/// rejected alone, unrun, and the one behind it is verified.
#[test]
fn a_batch_stops_in_front_of_a_change_past_its_quota() {
    let mut e = repo(("session_seconds = 0", "session_seconds = 1"));
    let s1 = agent(&mut e, "s1");
    let first = propose(&mut e, &s1, "    a * 2\n");
    let held = refund(&mut e, &s1);
    let s2 = e.session("s2", &["src/**"]);
    e.bind(&s2);
    e.wrote(&s2, "src/new.rs");
    e.lease(&s2, "src/new.rs#<file>");
    let base = e.trunk();
    let files = [file("src/new.rs", "pub fn new() {}\n")];
    let facts = e.ok(
        "facts.preview",
        None,
        Some(&s2),
        json!({"base": base, "files": files}),
    );
    let claim = lonca_core::ops::Claim {
        intent: "add new.rs".into(),
        adds: serde_json::from_value(facts["facts"]["adds"].clone()).unwrap(),
        ..Default::default()
    };
    let args = json!({"base": base, "files": files, "claim": claim});
    let other = e.ok("change.propose", None, Some(&s2), args);
    assert_eq!(other["decision"]["outcome"], "allow", "{other}");
    assert!(e.svc.process_one("demo").unwrap().is_some());
    assert_eq!(
        get(&mut e, &first["change"])["status"]["status"],
        "integrated"
    );

    // Batches from here on: `held` is past its session's quota.
    let config = DEFAULT_CONFIG
        .replace("# test = \"cargo test --offline\"", "test = \"sleep 1.1\"")
        .replace("session_seconds = 0", "session_seconds = 1")
        .replace("batch_size = 1", "batch_size = 2");
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let runs = e.svc.verification_runs();
    assert_eq!(e.svc.process_all(), 2);
    assert_eq!(e.svc.verification_runs(), runs + 1, "only the other ran");
    let c = get(&mut e, &held["change"]);
    assert_eq!(
        c["status"]["reasons"],
        json!(["verification_quota:session"])
    );
    assert_eq!(
        get(&mut e, &other["change"])["status"]["status"],
        "integrated"
    );
    let log = lonca_core::oplog::OpLog::new(&e.store())
        .read_all()
        .unwrap();
    let batched = log
        .iter()
        .any(|o| matches!(o.entry.op, lonca_core::ops::Op::ChangeIntegrateBatch { .. }));
    assert!(!batched, "no batch was logged");
    audited(&e);
}
