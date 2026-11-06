//! A symbol that goes on under another name (issue #44): the change needs a
//! lease on the old name only, and a session that still has the old name
//! meets a session that has the new one.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::GitId;
use lonca_core::ops::{Claim, LeaseItem, LeaseKind};
use serde_json::{Value, json};

const PATH: &str = "src/pay.py";
const SEED: &str =
    "def charge(card):\n    pay(card)\n    log(card)\n\n\ndef other():\n    return 1\n";
const RENAMED: &str =
    "def bill(card):\n    pay(card)\n    log(card)\n\n\ndef other():\n    return 1\n";

fn seeded(text: &str) -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    let r = e.human_change(vec![file(PATH, text)], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    (e, base)
}

fn agent(e: &mut Env, name: &str) -> String {
    let t = e.session(name, &["src/**"]);
    e.bind(&t);
    e.wrote(&t, PATH);
    t
}

fn lease(e: &mut Env, token: &str, symbol: &str, kind: LeaseKind) -> Value {
    let items = vec![LeaseItem {
        symbol: format!("{PATH}#{symbol}"),
        kind,
    }];
    let args = json!({"items": items, "intent": "work", "ttl_ms": 600_000});
    e.ok("lease.acquire", None, Some(token), args)["decision"].clone()
}

fn id(name: &str) -> String {
    format!("{PATH}#{name}")
}

fn propose(e: &mut Env, token: &str, base: &GitId, text: &str, claim: Claim) -> Value {
    let files = vec![file(PATH, text)];
    let args = json!({"base": base, "files": files, "claim": claim});
    e.ok("change.propose", None, Some(token), args)
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

/// `charge` becomes `bill` on the trunk, with one lease.
fn rename_on_trunk(e: &mut Env, base: &GitId) {
    let t = agent(e, "renamer");
    let d = lease(e, &t, "charge", LeaseKind::Rename);
    assert_eq!(d["outcome"], "allow", "{d}");
    let claim = Claim {
        intent: "a better name".into(),
        adds: vec![id("bill")],
        deletes: vec![id("charge")],
        ..Default::default()
    };
    let r = propose(e, &t, base, RENAMED, claim);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(r["facts"]["renames"], json!([[id("charge"), id("bill")]]));
    assert_eq!(e.svc.process_all(), 1);
}

#[test]
fn a_rename_needs_a_rename_lease_on_the_old_name_and_nothing_else() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let head = e.trunk();
    let text = e.store().read_file(&head, PATH).unwrap().unwrap();
    assert_eq!(String::from_utf8(text).unwrap(), RENAMED);
    audited(&e);
}

#[test]
fn an_edit_lease_is_not_enough_for_a_rename() {
    let (mut e, base) = seeded(SEED);
    let t = agent(&mut e, "editor");
    let d = lease(&mut e, &t, "charge", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let claim = Claim {
        intent: "a better name".into(),
        adds: vec![id("bill")],
        deletes: vec![id("charge")],
        ..Default::default()
    };
    let r = propose(&mut e, &t, &base, RENAMED, claim);
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    let why = r["decision"]["reasons"].to_string();
    assert!(why.contains("lease_missing:src/pay.py#charge"), "{why}");
}

#[test]
fn the_old_name_and_the_new_one_are_one_symbol() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let (old, trunk) = (agent(&mut e, "old"), agent(&mut e, "trunk"));
    let d = lease(&mut e, &old, "charge", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let d = lease(&mut e, &trunk, "bill", LeaseKind::Edit);
    assert_eq!(d["outcome"], "deny", "{d}");
    let d = lease(&mut e, &trunk, "other", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    audited(&e);
}

/// A session on the older base has the symbol as `charge` in its facts and
/// may hold it as `bill`.
#[test]
fn a_fact_of_an_older_base_is_covered_by_the_new_name() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let t = agent(&mut e, "behind");
    let d = lease(&mut e, &t, "bill", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let claim = Claim {
        intent: "log less".into(),
        edits: vec![id("charge")],
        ..Default::default()
    };
    let r = propose(
        &mut e,
        &t,
        &base,
        &SEED.replace("log(card)", "note(card)"),
        claim,
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    audited(&e);
}

/// A name taken again is that new symbol for whoever asks now.
#[test]
fn a_name_taken_again_is_free_of_the_rename() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let head = e.trunk();
    let again = format!("{RENAMED}\n\ndef charge(x):\n    return x\n");
    let t = agent(&mut e, "adder");
    let d = lease(&mut e, &t, "<file>", LeaseKind::Insert);
    assert_eq!(d["outcome"], "allow", "{d}");
    let claim = Claim {
        intent: "a new one".into(),
        adds: vec![id("charge")],
        ..Default::default()
    };
    let r = propose(&mut e, &t, &head, &again, claim);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let (a, b) = (agent(&mut e, "a"), agent(&mut e, "b"));
    let d = lease(&mut e, &a, "charge", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let d = lease(&mut e, &b, "bill", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    audited(&e);
}

/// New parameters of an overload: the old key and the new one are one
/// symbol, which no string says.
#[test]
fn a_key_changed_on_the_trunk_is_one_symbol_with_the_old_key() {
    const CS: &str = "src/pay.cs";
    let seed = "class C\n{\n    void M(string card)\n    {\n        A();\n    }\n\n    void M(int a, int b)\n    {\n        B();\n    }\n}\n";
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file(CS, seed)], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let r = e.human_change(
        vec![file(CS, &seed.replace("string card", "CardId card"))],
        "typed",
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);

    let (old, trunk) = (
        e.session("old", &["src/**"]),
        e.session("trunk", &["src/**"]),
    );
    let item = |symbol: &str| {
        vec![LeaseItem {
            symbol: format!("{CS}#C.{symbol}"),
            kind: LeaseKind::Edit,
        }]
    };
    let acquire = |e: &mut Env, token: &str, symbol: &str| {
        let args = json!({"items": item(symbol), "intent": "work", "ttl_ms": 600_000});
        e.ok("lease.acquire", None, Some(token), args)["decision"]["outcome"].clone()
    };
    assert_eq!(acquire(&mut e, &old, "M(string)"), "allow");
    assert_eq!(acquire(&mut e, &trunk, "M(CardId)"), "deny");
    assert_eq!(acquire(&mut e, &trunk, "M(int,int)"), "allow");
    audited(&e);
}
