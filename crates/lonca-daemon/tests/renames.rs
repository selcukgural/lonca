//! A symbol that goes on under another name (issue #44): the change needs a
//! lease on the old name only, and a session that still has the old name
//! meets a session that has the new one.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::GitId;
use lonca_core::ops::{Claim, LeaseItem, LeaseKind};
use lonca_daemon::protocol::FileChange;
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

/// Two names of one change: `C.M(long)` went away, and `C.M(int)` took that
/// key. Holding one says nothing about the other.
#[test]
fn a_key_taken_back_by_a_change_of_parameters_is_free_of_the_rename() {
    const CS: &str = "src/pay.cs";
    let seed = "class C\n{\n    void M(int a)\n    {\n        A();\n        A1();\n    }\n\n    void M(long a)\n    {\n        B();\n        B1();\n        B2();\n    }\n\n    void M(string a)\n    {\n        S();\n    }\n}\n";
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file(CS, seed)], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let wide = seed.replace("void M(long a)", "void Wide(long a)");
    e.human_change(vec![file(CS, &wide)], "a name");
    assert_eq!(e.svc.process_all(), 1);
    let taken = wide.replace("void M(int a)", "void M(long a)");
    e.human_change(vec![file(CS, &taken)], "a key");
    assert_eq!(e.svc.process_all(), 1);
    let (x, y) = (e.session("x", &["src/**"]), e.session("y", &["src/**"]));
    let acquire = |e: &mut Env, token: &str, name: &str| {
        let items = vec![LeaseItem {
            symbol: format!("{CS}#C.{name}"),
            kind: LeaseKind::Edit,
        }];
        let args = json!({"items": items, "intent": "work", "ttl_ms": 600_000});
        e.ok("lease.acquire", None, Some(token), args)["decision"]["outcome"].clone()
    };
    assert_eq!(acquire(&mut e, &x, "M(long)"), "allow");
    assert_eq!(acquire(&mut e, &y, "Wide"), "allow");
    audited(&e);
}

/// A method follows its renamed type, though it stands beside it: a Go
/// method by its receiver.
#[test]
fn a_method_follows_its_type() {
    const GO: &str = "src/pay.go";
    let seed = "package p\n\ntype T struct {\n\ta int\n\tb int\n}\n\nfunc (t T) Old(a int) int {\n\treturn a\n}\n";
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file(GO, seed)], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let new = seed.replace("type T ", "type U ").replace("(t T)", "(t U)");
    let r = e.human_change(vec![file(GO, &new)], "a name");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let (old, trunk) = (
        e.session("old", &["src/**"]),
        e.session("trunk", &["src/**"]),
    );
    let acquire = |e: &mut Env, token: &str, name: &str| {
        let items = vec![LeaseItem {
            symbol: format!("{GO}#{name}"),
            kind: LeaseKind::Edit,
        }];
        let args = json!({"items": items, "intent": "work", "ttl_ms": 600_000});
        e.ok("lease.acquire", None, Some(token), args)["decision"]["outcome"].clone()
    };
    assert_eq!(acquire(&mut e, &old, "T.Old"), "allow");
    assert_eq!(acquire(&mut e, &trunk, "U.Old"), "deny");
    audited(&e);
}

/// A file written anew has none of the old names' symbols.
#[test]
fn a_file_deleted_and_written_again_is_free_of_its_renames() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let r = e.human_change(
        vec![FileChange {
            path: PATH.into(),
            content_b64: None,
            mode: None,
        }],
        "gone",
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    e.human_change(vec![file(PATH, SEED)], "back");
    assert_eq!(e.svc.process_all(), 1);
    let (a, b) = (agent(&mut e, "a"), agent(&mut e, "b"));
    let d = lease(&mut e, &a, "charge", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let d = lease(&mut e, &b, "bill", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
}

/// A lease on a symbol the name was taken from reaches only that symbol: a
/// proposal from before the rename needs the name as it is now.
#[test]
fn a_lease_on_the_new_name_does_not_reach_who_took_the_old_one() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let again = format!("{RENAMED}\n\ndef charge(card):\n    pay(card)\n    log(card)\n");
    e.human_change(vec![file(PATH, &again)], "a new one");
    assert_eq!(e.svc.process_all(), 1);
    let t = agent(&mut e, "y");
    let d = lease(&mut e, &t, "bill", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let claim = Claim {
        intent: "edit".into(),
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
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
}

/// The lease a proposal from an older base rests on is pinned to it, by
/// whichever name it is held.
#[test]
fn a_proposal_from_an_older_base_pins_the_new_name() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let t = agent(&mut e, "behind");
    let items = vec![LeaseItem {
        symbol: id("bill"),
        kind: LeaseKind::Edit,
    }];
    let args = json!({"items": items, "intent": "work", "ttl_ms": 600_000});
    let set = e.ok("lease.acquire", None, Some(&t), args)["set"].clone();
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
    e.ok("lease.release", None, Some(&t), json!({ "set": set }));
    let other = agent(&mut e, "other");
    let d = lease(&mut e, &other, "bill", LeaseKind::Edit);
    assert_eq!(d["outcome"], "deny", "{d}");
}

/// What was renamed and then deleted leads nowhere: a new symbol of that
/// name is free of the old name.
#[test]
fn a_symbol_deleted_after_its_rename_ends_the_chain() {
    let (mut e, base) = seeded(SEED);
    rename_on_trunk(&mut e, &base);
    let gone = "def other():\n    return 1\n";
    e.human_change(vec![file(PATH, gone)], "gone");
    assert_eq!(e.svc.process_all(), 1);
    let back = format!("{gone}\n\ndef bill(x):\n    return x\n");
    e.human_change(vec![file(PATH, &back)], "new");
    assert_eq!(e.svc.process_all(), 1);
    let (a, b) = (agent(&mut e, "a"), agent(&mut e, "b"));
    let d = lease(&mut e, &a, "charge", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let d = lease(&mut e, &b, "bill", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
}

/// The overload that stays has the bare name again, and a rename of its
/// namesake is no reason to wait.
#[test]
fn the_overload_left_behind_a_rename_is_free_of_it() {
    const CS: &str = "src/pay.cs";
    let seed = "class C\n{\n    void M(int a)\n    {\n        A();\n    }\n\n    void M(string s)\n    {\n        B();\n        B1();\n    }\n}\n";
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file(CS, seed)], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let renamed = seed.replace("void M(string s)", "void N(string s)");
    e.human_change(vec![file(CS, &renamed)], "a name");
    assert_eq!(e.svc.process_all(), 1);
    let (x, y) = (e.session("x", &["src/**"]), e.session("y", &["src/**"]));
    let acquire = |e: &mut Env, token: &str, name: &str| {
        let items = vec![LeaseItem {
            symbol: format!("{CS}#C.{name}"),
            kind: LeaseKind::Edit,
        }];
        let args = json!({"items": items, "intent": "work", "ttl_ms": 600_000});
        e.ok("lease.acquire", None, Some(token), args)["decision"]["outcome"].clone()
    };
    assert_eq!(acquire(&mut e, &y, "N"), "allow");
    assert_eq!(acquire(&mut e, &x, "M"), "allow");
    audited(&e);
}
