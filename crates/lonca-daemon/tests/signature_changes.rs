//! A change that reaches code it does not touch (issue #43): the sessions
//! holding that code hear of it, and the queue runs what the policy keeps
//! for such changes.

mod common;
use common::*;

use lonca_audit::{Options, audit};

use lonca_core::oplog::OpEntry;
use lonca_core::ops::{CheckKind, CheckResult, Claim};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY};
use serde_json::{Value, json};

const TESTS: &str = "# test = \"cargo test --offline\"";
const EXTENDED: &str =
    "# on_signature_change = \"cargo test --offline --workspace --all-features\"";

const LIB: &str = "pub fn f(a: u8) -> u8 {\n    a\n}\n";
const NEW_LIB: &str = "pub fn f(a: u16) -> u16 {\n    a\n}\n";
const BODY_LIB: &str = "pub fn f(a: u8) -> u8 {\n    a + 1\n}\n";
const USES: &str = "pub fn g() -> u8 {\n    f(1)\n}\n\npub fn other() {}\n";

fn repo(batch: u32, extended: &str) -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    let config = DEFAULT_CONFIG
        .replace("batch_size = 1", &format!("batch_size = {batch}"))
        .replace("required = false", "required = true")
        .replace(TESTS, "test = \"true\"")
        .replace(EXTENDED, &format!("on_signature_change = \"{extended}\""));
    assert!(config.contains(extended));
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let files = vec![file("src/lib.rs", LIB), file("src/uses.rs", USES)];
    let r = e.human_change(files, "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    (e, base)
}

fn agent(e: &mut Env, name: &str, path: &str) -> String {
    let t = e.session(name, &["src/**"]);
    e.bind(&t);
    e.wrote(&t, path);
    t
}

/// A session of `name` proposing `text` as `src/lib.rs`, with what preview
/// reports as its claim.
fn change_lib(e: &mut Env, name: &str, base: &GitId, text: &str) -> Value {
    let t = agent(e, name, "src/lib.rs");
    e.lease(&t, "src/lib.rs#f");
    let files = [file("src/lib.rs", text)];
    let args = json!({"base": base, "files": files});
    let facts = e.ok("facts.preview", None, Some(&t), args)["facts"].clone();
    let claim = Claim {
        intent: "change f".into(),
        edits: serde_json::from_value(facts["edits"].clone()).unwrap(),
        signature_changes: serde_json::from_value(facts["signature_changes"].clone()).unwrap(),
        ..Default::default()
    };
    let args = json!({"base": base, "files": files, "claim": claim});
    e.ok("change.propose", None, Some(&t), args)
}

fn last(e: &Env, kind: &str) -> OpEntry {
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let found = ops.into_iter().rev().map(|o| o.entry);
    let mut found = found.filter(|e| e.op.kind().as_str() == kind);
    found.next().unwrap()
}

fn checks(e: &OpEntry) -> Vec<CheckKind> {
    e.evidence.iter().map(|a| a.check).collect()
}

fn events(e: &mut Env, token: &str) -> Vec<Value> {
    let r = e.ok("events", None, Some(token), json!({"from": 0}));
    r["events"].as_array().unwrap().to_vec()
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

/// The scenario of the issue: A changes what `f` takes while B holds `g`,
/// which calls `f`.
#[test]
fn the_holder_of_a_caller_hears_and_the_queue_runs_more() {
    let (mut e, base) = repo(1, "true");
    let b = agent(&mut e, "b", "src/uses.rs");
    let set = e.lease(&b, "src/uses.rs#g")["set"]
        .as_str()
        .unwrap()
        .to_string();
    let c = agent(&mut e, "c", "src/uses.rs");
    e.lease(&c, "src/uses.rs#other");

    let r = change_lib(&mut e, "a", &base, NEW_LIB);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let entry = last(&e, "change.propose");
    let facts = entry.facts.as_ref().unwrap();
    assert_eq!(facts.signature_changes, ["src/lib.rs#f"]);
    assert_eq!(facts.affected, ["src/uses.rs#g"]);
    let held = format!("affected_lease:b:{set}");
    assert_eq!(
        entry.decision.reasons,
        ["signature_change:src/lib.rs#f".to_string(), held]
    );

    let told = e.ok("inbox", None, Some(&b), json!({}));
    assert!(told.to_string().contains("symbols_changed"), "{told}");
    let heard = events(&mut e, &b);
    let heard: Vec<&Value> = heard
        .iter()
        .filter(|x| x["kind"] == "symbols_changed")
        .collect();
    assert_eq!(heard.len(), 1, "{heard:?}");
    assert_eq!(heard[0]["sets"], json!([set]));
    assert_eq!(heard[0]["symbols"], json!(["src/lib.rs#f"]));
    assert_eq!(heard[0]["change"], r["change"]);
    let quiet = events(&mut e, &c);
    let quiet = quiet.iter().all(|x| x["kind"] != "symbols_changed");
    assert!(quiet, "a lease on something else");

    assert_eq!(e.svc.process_all(), 1);
    let entry = last(&e, "change.integrate");
    assert!(entry.decision.is_allow(), "{:?}", entry.decision);
    assert_eq!(
        checks(&entry),
        [CheckKind::Syntax, CheckKind::Tests, CheckKind::Extended]
    );
    audited(&e);
}

#[test]
fn a_change_of_a_body_reaches_nobody() {
    let (mut e, base) = repo(1, "false");
    let b = agent(&mut e, "b", "src/uses.rs");
    e.lease(&b, "src/uses.rs#g");
    let r = change_lib(&mut e, "a", &base, BODY_LIB);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let entry = last(&e, "change.propose");
    assert!(entry.decision.reasons.is_empty(), "{:?}", entry.decision);
    assert!(
        events(&mut e, &b)
            .iter()
            .all(|x| x["kind"] != "symbols_changed")
    );
    assert_eq!(e.svc.process_all(), 1);
    let entry = last(&e, "change.integrate");
    assert!(
        entry.decision.is_allow(),
        "the command that fails did not run"
    );
    assert_eq!(checks(&entry), [CheckKind::Syntax, CheckKind::Tests]);
    audited(&e);
}

#[test]
fn a_failure_of_what_runs_more_refuses_the_change() {
    let (mut e, base) = repo(1, "false");
    let trunk = e.trunk();
    change_lib(&mut e, "a", &base, NEW_LIB);
    e.svc.process_all();
    let entry = last(&e, "change.integrate");
    assert!(!entry.decision.is_allow());
    let reasons = &entry.decision.reasons;
    assert!(reasons[0] == "verification_failed:extended", "{reasons:?}");
    let result = entry.evidence.last().unwrap();
    assert_eq!(result.check, CheckKind::Extended);
    assert_eq!(result.result, CheckResult::Fail);
    assert_eq!(e.trunk(), trunk);
    audited(&e);
}

fn add_file(e: &mut Env, base: &GitId) {
    let t = agent(e, "z", "src/new.txt");
    e.lease(&t, "src/new.txt#<file>");
    let claim = Claim {
        intent: "add a file".into(),
        ..Default::default()
    };
    let files = [file("src/new.txt", "text\n")];
    let args = json!({"base": base, "files": files, "claim": claim});
    let r = e.ok("change.propose", None, Some(&t), args);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

/// One member of a batch owes it, and only the batch can pay.
#[test]
fn a_batch_owes_what_one_of_its_changes_owes() {
    let (mut e, base) = repo(2, "true");
    change_lib(&mut e, "a", &base, NEW_LIB);
    add_file(&mut e, &base);
    assert_eq!(e.svc.process_all(), 2);
    let entry = last(&e, "change.integrate_batch");
    assert!(entry.decision.is_allow(), "{:?}", entry.decision);
    assert_eq!(
        checks(&entry),
        [CheckKind::Syntax, CheckKind::Tests, CheckKind::Extended]
    );
    audited(&e);
}

#[test]
fn a_batch_that_owes_nothing_pays_nothing() {
    let (mut e, base) = repo(2, "false");
    change_lib(&mut e, "a", &base, BODY_LIB);
    add_file(&mut e, &base);
    assert_eq!(e.svc.process_all(), 2);
    let entry = last(&e, "change.integrate_batch");
    assert!(entry.decision.is_allow(), "{:?}", entry.decision);
    assert_eq!(checks(&entry), [CheckKind::Syntax, CheckKind::Tests]);
    audited(&e);
}

/// A failing change splits the batch, and the one that owes nothing lands.
#[test]
fn a_batch_that_fails_what_it_owes_is_halved() {
    let (mut e, base) = repo(2, "false");
    add_file(&mut e, &base);
    change_lib(&mut e, "a", &base, NEW_LIB);
    e.svc.process_all();
    let entry = last(&e, "change.integrate");
    let reasons = &entry.decision.reasons;
    assert!(reasons[0] == "verification_failed:extended", "{reasons:?}");
    audited(&e);
}
