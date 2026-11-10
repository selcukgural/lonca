//! Keyed directories (#261): a migration's version is reserved like a
//! member's name, `next` finds the free one, a key another file has is
//! refused, and two changes that land one key each are `conflicted` at
//! integration whatever the checks run. The auditor recomputes it all.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::GitId;
use lonca_core::ops::{Claim, Facts, LeaseItem, LeaseKind};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY};
use serde_json::{Value, json};

const DIR: &str = "db/migration";
const KEYS: &str = "db/migration#<dir>";

fn keyed(e: &mut Env) {
    let config = format!(
        "{DEFAULT_CONFIG}\n[paths.keyed]\n\"{DIR}\" = '^V(\\d+)__'\n\
         \"docs/adr\" = {{ pattern = '^([a-z]+)-', compare = \"text\" }}\n"
    );
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

/// A repository with `V1__init.sql` and `V2__users.sql` on trunk.
fn repo() -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    keyed(&mut e);
    let seed = vec![
        file(&format!("{DIR}/V1__init.sql"), "create table a (id int);\n"),
        file(
            &format!("{DIR}/V2__users.sql"),
            "create table users (id int);\n",
        ),
    ];
    let r = e.human_change(seed, "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    (e, base)
}

fn agent(e: &mut Env, name: &str) -> String {
    let t = e.session(name, &["db/**", "docs/**"]);
    e.bind(&t);
    t
}

fn acquire(e: &mut Env, token: &str, items: Vec<LeaseItem>) -> Value {
    e.ok(
        "lease.acquire",
        None,
        Some(token),
        json!({"items": items, "intent": "a migration", "ttl_ms": 600_000}),
    )
}

fn item(symbol: &str, kind: LeaseKind, names: &[&str]) -> LeaseItem {
    LeaseItem {
        symbol: symbol.into(),
        kind,
        names: names.iter().map(|n| n.to_string()).collect(),
    }
}

fn claim_of(f: &Facts) -> Claim {
    Claim {
        intent: "a migration".into(),
        edits: f.edits.clone(),
        adds: f.adds.clone(),
        deletes: f.deletes.clone(),
        deleted_files: f.deleted_files.clone(),
        signature_changes: f.signature_changes.clone(),
        tests: f.tests.clone(),
        revert_of: None,
    }
}

/// Writes `path`, asks preview what it is, and proposes it with that claim.
fn propose_file(e: &mut Env, token: &str, base: &GitId, path: &str) -> (Value, Value) {
    e.wrote(token, path);
    let files = vec![file(path, "alter table users add name text;\n")];
    let preview = e.ok(
        "facts.preview",
        None,
        Some(token),
        json!({"base": base, "files": files}),
    );
    let facts: Facts = serde_json::from_value(preview["facts"].clone()).unwrap();
    let r = e.ok(
        "change.propose",
        None,
        Some(token),
        json!({"base": base, "files": files, "claim": claim_of(&facts)}),
    );
    (preview, r)
}

fn status_of(e: &mut Env, change: &Value) -> Value {
    e.ok("change.get", Some("demo"), None, json!({"change": change}))["status"].clone()
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

fn reasons(r: &Value) -> Vec<String> {
    let list = r["decision"]["reasons"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    list.iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

#[test]
fn next_reserves_the_number_after_trunk_and_every_reservation() {
    let (mut e, _) = repo();
    let a = agent(&mut e, "a");
    let b = agent(&mut e, "b");
    let r = acquire(&mut e, &a, vec![item(KEYS, LeaseKind::Insert, &["next"])]);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(r["keys"], json!({KEYS: ["3"]}), "{r}");
    let r = acquire(
        &mut e,
        &b,
        vec![item(KEYS, LeaseKind::Insert, &["next", "next"])],
    );
    assert_eq!(r["keys"], json!({KEYS: ["4", "5"]}), "{r}");
    // The log holds the numbers, and status names where keys are reserved.
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert!(!s.to_string().contains("\"next\""), "{s}");
    assert_eq!(
        s["keyed"],
        json!({DIR: KEYS, "docs/adr": "docs/adr#<dir>"}),
        "{s}"
    );
    // `next` has no order in a text directory, and is no key elsewhere.
    let r = e.call(
        "lease.acquire",
        None,
        Some(&a),
        json!({"items": [item("docs/adr#<dir>", LeaseKind::Insert, &["next"])], "intent": "x", "ttl_ms": 60_000}),
    );
    assert!(r.is_err(), "{r:?}");
    let r = e.call(
        "lease.acquire",
        None,
        Some(&a),
        json!({"items": [item("db/x.sql#<file>", LeaseKind::Insert, &["next"])], "intent": "x", "ttl_ms": 60_000}),
    );
    assert!(r.is_err(), "{r:?}");
    audited(&e);
}

#[test]
fn preview_asks_for_the_key_and_a_proposal_without_it_is_refused() {
    let (mut e, base) = repo();
    let a = agent(&mut e, "a");
    let path = format!("{DIR}/V3__names.sql");
    acquire(
        &mut e,
        &a,
        vec![item(&format!("{path}#<file>"), LeaseKind::Edit, &[])],
    );
    let (preview, r) = propose_file(&mut e, &a, &base, &path);
    let want = json!({"symbol": KEYS, "kind": "insert", "names": ["3"]});
    let acquire_list = preview["acquire"].as_array().unwrap();
    assert!(acquire_list.contains(&want), "{preview}");
    assert!(
        reasons(&r).contains(&format!("key_not_reserved:{DIR}#3")),
        "{r}"
    );
    let missing = r["details"].as_array().unwrap();
    assert!(
        missing
            .iter()
            .any(|d| d["symbol"] == KEYS && d["code"] == "lease_missing"),
        "{r}"
    );
    let got = acquire(&mut e, &a, vec![item(KEYS, LeaseKind::Insert, &["3"])]);
    assert_eq!(got["decision"]["outcome"], "allow", "{got}");
    let (preview, r) = propose_file(&mut e, &a, &base, &path);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert!(
        preview["leases"]
            .as_array()
            .unwrap()
            .iter()
            .any(|d| d["symbol"] == KEYS && d["code"] == "held_by_you"),
        "{preview}"
    );
    assert_eq!(e.svc.process_all(), 1);
    assert_eq!(status_of(&mut e, &r["change"])["status"], "integrated");
    audited(&e);
}

#[test]
fn a_key_a_file_of_the_tree_has_is_taken() {
    let (mut e, base) = repo();
    let a = agent(&mut e, "a");
    let path = format!("{DIR}/V02__more_users.sql");
    acquire(
        &mut e,
        &a,
        vec![
            item(&format!("{path}#<file>"), LeaseKind::Edit, &[]),
            item(KEYS, LeaseKind::Insert, &["2"]),
        ],
    );
    let (preview, r) = propose_file(&mut e, &a, &base, &path);
    assert_eq!(preview["facts"]["taken_keys"], json!([format!("{DIR}#2")]));
    assert!(reasons(&r).contains(&format!("key_taken:{DIR}#2")), "{r}");
    audited(&e);
}

/// A person's change needs no lease, so two changes can each bring key 3:
/// the second to integrate is `conflicted`, naming the key, though no check
/// is set that would run the migrations.
#[test]
fn two_changes_that_land_one_key_conflict_at_integration() {
    let (mut e, base) = repo();
    let human = e.human_change(
        vec![file(&format!("{DIR}/V3__by_hand.sql"), "select 1;\n")],
        "by hand",
    );
    assert_eq!(human["decision"]["outcome"], "allow", "{human}");
    let a = agent(&mut e, "a");
    let path = format!("{DIR}/V3__by_agent.sql");
    acquire(
        &mut e,
        &a,
        vec![
            item(&format!("{path}#<file>"), LeaseKind::Edit, &[]),
            item(KEYS, LeaseKind::Insert, &["3"]),
        ],
    );
    let (_, r) = propose_file(&mut e, &a, &base, &path);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 2);
    let late = status_of(&mut e, &r["change"]);
    assert_eq!(late["status"], "conflicted", "{late}");
    assert_eq!(late["symbols"], json!([format!("{DIR}#3")]), "{late}");
    let head = e.trunk();
    let by_agent = e.store().read_file(&head, &path).unwrap();
    assert!(by_agent.is_none());
    audited(&e);
}

/// A clash trunk already had is nobody's new conflict: changes elsewhere,
/// and to other keys, still land.
#[test]
fn a_clash_already_on_trunk_stops_no_other_change() {
    let mut e = Env::new();
    e.init(None);
    let seed = vec![
        file(&format!("{DIR}/V1__a.sql"), "select 1;\n"),
        file(&format!("{DIR}/V1__b.sql"), "select 2;\n"),
    ];
    let r = e.human_change(seed, "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    keyed(&mut e);
    let base = e.trunk();
    let a = agent(&mut e, "a");
    let path = format!("{DIR}/V2__c.sql");
    acquire(
        &mut e,
        &a,
        vec![
            item(&format!("{path}#<file>"), LeaseKind::Edit, &[]),
            item(KEYS, LeaseKind::Insert, &["2"]),
        ],
    );
    let (_, r) = propose_file(&mut e, &a, &base, &path);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    assert_eq!(status_of(&mut e, &r["change"])["status"], "integrated");
    audited(&e);
}
