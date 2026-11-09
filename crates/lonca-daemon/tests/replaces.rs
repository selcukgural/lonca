//! A workspace's newer proposal replaces its pending one (issue #107): a
//! workspace proposes all it has, so two pending changes of one workspace
//! would be the same work twice, and approving both would land it twice.

mod common;
use common::*;

use lonca_audit::{Options, audit};

const SYM: &str = "src/lib.rs#refund";

/// A tainted session's workspace: its token.
fn tainted(e: &mut Env) -> String {
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    let fetch = json!({"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": "https://example.com/card"}, "workspace": e.root.join("ws")});
    e.ok("hook.event", None, Some(&token), fetch);
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, SYM);
    token
}

fn refund(body: &str) -> String {
    LIB.replace(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        &format!("pub fn refund(a: u64) -> u64 {{\n    {body}\n"),
    )
}

fn status_of(e: &mut Env, change: &Value) -> Value {
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    rec["status"]["status"].clone()
}

/// The issue's scenario: two proposals, the first still pending. The
/// second names the first in `replaces:`, the first is withdrawn and out
/// of `status.pending`, the lease is pinned to the second, and one
/// approval lands the work once.
#[test]
fn the_newer_proposal_replaces_the_pending_one_and_lands_once() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    let token = tainted(&mut e);

    let r1 = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &refund("0"))],
        &[SYM],
    );
    assert_eq!(r1["decision"]["outcome"], "escalate", "{r1}");
    let (seq1, c1) = (r1["seq"].as_u64().unwrap(), r1["change"].clone());
    let none = r1["decision"]["reasons"].to_string();
    assert!(!none.contains("replaces:"), "{r1}");

    let r2 = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &refund("1"))],
        &[SYM],
    );
    assert_eq!(r2["decision"]["outcome"], "escalate", "{r2}");
    let (seq2, c2) = (r2["seq"].as_u64().unwrap(), r2["change"].clone());
    let named = format!("replaces:{}", c1.as_str().unwrap());
    let reasons = r2["decision"]["reasons"].as_array().unwrap();
    assert!(reasons.iter().any(|r| r.as_str() == Some(&named)), "{r2}");

    assert_eq!(status_of(&mut e, &c1), "withdrawn");
    let st = e.ok("status", Some("demo"), None, json!({}));
    let pending: Vec<u64> = st["pending"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["seq"].as_u64().unwrap())
        .collect();
    assert_eq!(pending, [seq2], "{st}");
    let pinned: Vec<Value> = st["leases"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|l| l["pinned"].as_array().unwrap().clone())
        .map(|p| p["change"].clone())
        .collect();
    assert_eq!(pinned, std::slice::from_ref(&c2), "{st}");

    let old = e.human(Op::Approve {
        target_seq: seq1,
        note: String::new(),
        checks: vec![],
    });
    assert_eq!(old["decision"]["outcome"], "deny", "{old}");
    let new = e.human(Op::Approve {
        target_seq: seq2,
        note: String::new(),
        checks: vec![],
    });
    assert_eq!(new["decision"]["outcome"], "allow", "{new}");
    assert_eq!(e.svc.process_all(), 1);
    assert_eq!(e.svc.process_all(), 0, "nothing left to land");
    assert_eq!(status_of(&mut e, &c2), "integrated");
    assert_eq!(status_of(&mut e, &c1), "withdrawn");
    let repo = e.root.join("home/repos/demo.git");
    let trunk = e.trunk();
    let text = git(&repo, &["show", &format!("{}:src/lib.rs", trunk.0)]);
    assert_eq!(text, refund("1").trim_end());

    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}
