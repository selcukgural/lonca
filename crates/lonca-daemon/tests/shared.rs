//! Shared leases (issue #112): two agents hold one function `shared`, and
//! the merge joins their lines; lines both changed are `conflicted`, naming
//! the function. Every merge is verified, and the auditor recomputes it.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::GitId;
use lonca_core::oplog::OpLog;
use lonca_core::ops::Op;
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY};
use lonca_symbols::engine::ENGINE_SHARED;
use serde_json::{Value, json};

const PATH: &str = "src/lib.rs";
const TOTAL: &str = "src/lib.rs#total";

/// One function, its lines far enough apart that changes to two of them do
/// not touch.
fn seed() -> String {
    let lines: String = (0..8).map(|i| format!("    let a{i} = {i};\n")).collect();
    format!("pub fn total() -> u64 {{\n{lines}    a0 + a2 + a4 + a6\n}}\n")
}

fn edited(text: &str, line: usize, to: &str) -> String {
    let from = format!("    let a{line} = {line};\n");
    assert!(text.contains(&from), "{line}");
    text.replace(&from, &format!("    let a{line} = {to};\n"))
}

fn policy(e: &mut Env, shared: bool, batch_size: u32) {
    let config = DEFAULT_CONFIG
        .replace("shared = false", &format!("shared = {shared}"))
        .replace("required = false", "required = true")
        .replace("# test = \"cargo test --offline\"", "test = \"true\"")
        .replace("batch_size = 1", &format!("batch_size = {batch_size}"));
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    let r = e.human(op);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

/// A repository with `total`, last changed by a human: that change made the
/// base, so it is not one since the base.
fn repo(batch_size: u32) -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    policy(&mut e, true, batch_size);
    let r = e.human_change(vec![file(PATH, &seed())], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let r = e.human_change(vec![file(PATH, &edited(&seed(), 7, "70"))], "a7");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    (e, base)
}

/// The text of the base: `seed` with the human's change.
fn base_text() -> String {
    edited(&seed(), 7, "70")
}

/// A session that holds `total` shared.
fn agent(e: &mut Env, name: &str) -> String {
    let t = e.session(name, &["src/**"]);
    e.bind(&t);
    e.wrote(&t, PATH);
    let items = json!([{"symbol": TOTAL, "kind": "shared"}]);
    let r = e.ok(
        "lease.acquire",
        None,
        Some(&t),
        json!({"items": items, "intent": "a line of total", "ttl_ms": 600_000}),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    t
}

fn propose(e: &mut Env, token: &str, base: &GitId, text: &str) -> Value {
    let r = e.propose(token, base, vec![file(PATH, text)], &[TOTAL]);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    r
}

fn status_of(e: &mut Env, r: &Value) -> Value {
    let s = e.ok(
        "change.get",
        Some("demo"),
        None,
        json!({"change": r["change"]}),
    );
    s["status"].clone()
}

fn trunk_text(e: &mut Env) -> String {
    let head = e.trunk();
    let text = e.store().read_file(&head, PATH).unwrap().unwrap();
    String::from_utf8(text).unwrap()
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

/// The engine of every integration since the repository began.
fn engines(e: &Env) -> Vec<Option<u32>> {
    let log = OpLog::new(&e.store()).read_all().unwrap();
    let merges = log.iter().filter(|o| {
        matches!(
            o.entry.op,
            Op::ChangeIntegrate { .. } | Op::ChangeIntegrateBatch { .. }
        )
    });
    merges.map(|o| o.entry.symbols_engine).collect()
}

#[test]
fn two_agents_in_one_function_on_different_lines_both_integrate() {
    let (mut e, base) = repo(1);
    let (a, b) = (agent(&mut e, "a"), agent(&mut e, "b"));
    let first = propose(&mut e, &a, &base, &edited(&base_text(), 1, "10"));
    let second = propose(&mut e, &b, &base, &edited(&base_text(), 5, "50"));
    assert_eq!(e.svc.process_all(), 2);
    for r in [&first, &second] {
        assert_eq!(status_of(&mut e, r)["status"], "integrated");
    }
    let both = edited(&edited(&base_text(), 1, "10"), 5, "50");
    assert_eq!(trunk_text(&mut e), both);
    assert!(engines(&e).iter().all(|n| *n >= Some(ENGINE_SHARED)));
    audited(&e);
}

#[test]
fn the_same_lines_are_a_conflict_naming_the_function() {
    let (mut e, base) = repo(1);
    let (a, b) = (agent(&mut e, "a"), agent(&mut e, "b"));
    let first = propose(&mut e, &a, &base, &edited(&base_text(), 3, "30"));
    let second = propose(&mut e, &b, &base, &edited(&base_text(), 3, "31"));
    assert_eq!(e.svc.process_all(), 2);
    assert_eq!(status_of(&mut e, &first)["status"], "integrated");
    let late = status_of(&mut e, &second);
    assert_eq!(late["status"], "conflicted", "{late}");
    assert_eq!(late["symbols"], json!([TOTAL]));
    assert_eq!(trunk_text(&mut e), edited(&base_text(), 3, "30"));
    audited(&e);
}

/// What changed the function since the base under no `shared` lease, here a
/// human's change, is not joined with.
#[test]
fn an_exclusive_change_since_the_base_is_not_joined() {
    let (mut e, base) = repo(1);
    let a = agent(&mut e, "a");
    let r = e.human_change(vec![file(PATH, &edited(&base_text(), 1, "10"))], "a1");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let late = propose(&mut e, &a, &base, &edited(&base_text(), 5, "50"));
    assert_eq!(e.svc.process_all(), 1);
    let late = status_of(&mut e, &late);
    assert_eq!(late["status"], "conflicted", "{late}");
    assert_eq!(late["symbols"], json!([TOTAL]));
    audited(&e);
}

/// A policy that stops shared leases stops what they would have joined.
#[test]
fn without_shared_leases_in_the_policy_nothing_is_joined() {
    let (mut e, base) = repo(1);
    let (a, b) = (agent(&mut e, "a"), agent(&mut e, "b"));
    let first = propose(&mut e, &a, &base, &edited(&base_text(), 1, "10"));
    let second = propose(&mut e, &b, &base, &edited(&base_text(), 5, "50"));
    policy(&mut e, false, 1);
    assert_eq!(e.svc.process_all(), 2);
    assert_eq!(status_of(&mut e, &first)["status"], "integrated");
    assert_eq!(status_of(&mut e, &second)["status"], "conflicted");
    audited(&e);
}

/// A batch joins each member onto the ones in front of it, and the
/// auditor does the same.
#[test]
fn a_batch_joins_its_members() {
    let (mut e, base) = repo(3);
    let (a, b, c) = (agent(&mut e, "a"), agent(&mut e, "b"), agent(&mut e, "c"));
    let changes = [
        propose(&mut e, &a, &base, &edited(&base_text(), 1, "10")),
        propose(&mut e, &b, &base, &edited(&base_text(), 3, "30")),
        propose(&mut e, &c, &base, &edited(&base_text(), 5, "50")),
    ];
    assert_eq!(e.svc.process_all(), 3);
    for r in &changes {
        assert_eq!(status_of(&mut e, r)["status"], "integrated");
    }
    let log = OpLog::new(&e.store()).read_all().unwrap();
    let batch = log.iter().filter_map(|o| match &o.entry.op {
        Op::ChangeIntegrateBatch { merged, .. } => Some(merged.len()),
        _ => None,
    });
    assert_eq!(batch.collect::<Vec<_>>(), [3]);
    let all = edited(&edited(&edited(&base_text(), 1, "10"), 3, "30"), 5, "50");
    assert_eq!(trunk_text(&mut e), all);
    audited(&e);
}
