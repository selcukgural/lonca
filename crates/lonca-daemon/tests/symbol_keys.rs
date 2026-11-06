//! Symbols of one name (issue #44): an overload added above another renames
//! neither, and a session on an older base can not hold the same symbol as a
//! session on the trunk under another name.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::GitId;
use lonca_core::ops::{Claim, LeaseItem, LeaseKind};

const PATH: &str = "src/client.cs";
const SEED: &str =
    "class Client\n{\n    public void Charge(string card)\n    {\n        Pay(card);\n    }\n}\n";
const OVERLOAD: &str =
    "    public void Charge(int a, int b)\n    {\n        Pay(a + b);\n    }\n\n";
const FIRST: &str = "    public void Charge(string card)";

fn with_overload() -> String {
    SEED.replacen(FIRST, &format!("{OVERLOAD}{FIRST}"), 1)
}

fn seeded() -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    let r = e.human_change(vec![file(PATH, SEED)], "seed");
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

fn lease(e: &mut Env, token: &str, symbol: &str, kind: LeaseKind) -> serde_json::Value {
    let items = vec![LeaseItem {
        symbol: format!("{PATH}#{symbol}"),
        kind,
    }];
    let args = serde_json::json!({"items": items, "intent": "work", "ttl_ms": 600_000});
    e.ok("lease.acquire", None, Some(token), args)["decision"].clone()
}

/// The overload comes in with an insert lease on the class, and what it
/// adds is one symbol: nobody needs a lease on the one that was there.
fn add_overload(e: &mut Env, base: &GitId) {
    let t = agent(e, "adder");
    let d = lease(e, &t, "Client", LeaseKind::Insert);
    assert_eq!(d["outcome"], "allow", "{d}");
    let claim = Claim {
        intent: "second overload".into(),
        adds: vec![format!("{PATH}#Client.Charge(int,int)")],
        ..Default::default()
    };
    let files = vec![file(PATH, &with_overload())];
    let args = serde_json::json!({"base": base, "files": files, "claim": claim});
    let r = e.ok("change.propose", None, Some(&t), args);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
}

/// An edit of the first overload, written against `base`, whose name for it
/// is `name`.
fn edit_first(e: &mut Env, token: &str, base: &GitId, name: &str) -> serde_json::Value {
    let text = match *base == e.trunk() {
        true => with_overload(),
        false => SEED.to_string(),
    };
    let claim = Claim {
        intent: "log the card".into(),
        edits: vec![format!("{PATH}#{name}")],
        ..Default::default()
    };
    let files = vec![file(
        PATH,
        &text.replace("Pay(card);", "Log(card);\n        Pay(card);"),
    )];
    let args = serde_json::json!({"base": base, "files": files, "claim": claim});
    e.ok("change.propose", None, Some(token), args)
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

#[test]
fn a_session_on_an_old_base_and_one_on_the_trunk_can_not_share_a_symbol() {
    let (mut e, old_base) = seeded();
    add_overload(&mut e, &old_base);
    let (old, trunk) = (agent(&mut e, "old"), agent(&mut e, "trunk"));

    let d = lease(&mut e, &old, "Client.Charge", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let d = lease(&mut e, &trunk, "Client.Charge(string)", LeaseKind::Edit);
    assert_eq!(d["outcome"], "deny", "{d}");
    let why = d["reasons"].to_string();
    assert!(
        why.contains("lease_held:src/client.cs#Client.Charge:old"),
        "{why}"
    );

    // The old session's change lands on the symbol it means.
    let r = edit_first(&mut e, &old, &old_base, "Client.Charge");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let head = e.trunk();
    let text = e.store().read_file(&head, PATH).unwrap().unwrap();
    let text = String::from_utf8(text).unwrap();
    assert!(text.contains("Pay(a + b);"), "{text}");
    assert!(text.contains("Log(card);\n        Pay(card);"), "{text}");
    audited(&e);
}

#[test]
fn the_other_way_around_the_trunk_holds_and_the_old_base_waits() {
    let (mut e, old_base) = seeded();
    add_overload(&mut e, &old_base);
    let (old, trunk) = (agent(&mut e, "old"), agent(&mut e, "trunk"));
    let d = lease(&mut e, &trunk, "Client.Charge(string)", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let d = lease(&mut e, &old, "Client.Charge", LeaseKind::Edit);
    assert_eq!(d["outcome"], "deny", "{d}");
    // The other overload is free for whoever has it by its key.
    let d = lease(&mut e, &old, "Client.Charge(int,int)", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");

    let head = e.trunk();
    let r = edit_first(&mut e, &trunk, &head, "Client.Charge(string)");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    audited(&e);
}

/// With engine 5 the insert above renumbered the first overload, so its
/// session was told to lease what it had not touched.
#[test]
fn an_edit_on_the_trunk_needs_a_lease_only_on_its_own_overload() {
    let (mut e, old_base) = seeded();
    add_overload(&mut e, &old_base);
    let t = agent(&mut e, "editor");
    let d = lease(&mut e, &t, "Client.Charge(string)", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let other = agent(&mut e, "other");
    let d = lease(&mut e, &other, "Client.Charge(int,int)", LeaseKind::Edit);
    assert_eq!(d["outcome"], "allow", "{d}");
    let head = e.trunk();
    let r = edit_first(&mut e, &t, &head, "Client.Charge(string)");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    audited(&e);
}
