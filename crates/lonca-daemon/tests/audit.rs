//! The auditor against real daemon logs, and against forgeries made by an
//! insider who holds the daemon key (so every signature still verifies).

mod common;
use common::*;

use lonca_audit::{Options, audit, compare};
use lonca_core::oplog::{GENESIS_PREV, OpEntry};
use lonca_core::ops::{Decision, Outcome as Out};

/// A repository with integrations, a denial, an escalation, a conflict and
/// a policy change.
fn busy_repo() -> Env {
    let mut e = Env::new();
    e.init(None);
    e.human_change(
        vec![file("src/lib.rs", LIB), file("notes.md", "a\n")],
        "seed",
    );
    e.svc.process_all();
    let base = e.trunk();
    let t1 = e.session("s1", &["src/**"]);
    let t2 = e.session("s2", &["src/**"]);
    for t in [&t1, &t2] {
        e.bind(t);
        e.wrote(t, "src/lib.rs");
    }
    e.lease(&t1, "src/lib.rs#charge");
    e.lease(&t2, "src/lib.rs#refund");
    e.propose(
        &t1,
        &base,
        vec![file(
            "src/lib.rs",
            &LIB.replacen("    a\n", "    a + 1\n", 1),
        )],
        &["src/lib.rs#charge"],
    );
    let refund = LIB.replace(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        "pub fn refund(a: u64) -> u64 {\n    0\n",
    );
    e.propose(
        &t2,
        &base,
        vec![file("src/lib.rs", &refund)],
        &["src/lib.rs#refund"],
    );
    // Denied: claim does not match.
    e.propose(
        &t2,
        &base,
        vec![file("src/lib.rs", &refund)],
        &["src/lib.rs#charge"],
    );
    e.svc.process_all();
    // A human conflicting with an integrated agent change.
    let stale = LIB.replacen("    a\n", "    a + 9\n", 1);
    let prep = e.ok(
        "human.prepare_change",
        Some("demo"),
        None,
        json!({"base": base, "files": [file("src/lib.rs", &stale)], "author": "ayse", "intent": "late"}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    e.human(op);
    e.svc.process_all();
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": lonca_policy::config::DEFAULT_CONFIG.replace("max_rounds = 4", "max_rounds = 6"), "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    e.human(op);
    e
}

fn key(e: &Env) -> KeyPair {
    KeyPair::load(&e.root.join("home/daemon.key")).unwrap()
}

/// Copies the store, lets `edit` change entries, re-chains and re-signs
/// everything with the daemon key and writes the forged log.
fn forge(e: &Env, name: &str, edit: impl Fn(&mut Vec<OpEntry>)) -> Store {
    let src = e.root.join("home/repos/demo.git");
    let dst = e.root.join(name);
    git(
        &e.root,
        &[
            "clone",
            "-q",
            "--mirror",
            src.to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    );
    let store = Store::open(&dst).unwrap();
    let mut entries: Vec<OpEntry> = OpLog::new(&store)
        .read_all()
        .unwrap()
        .into_iter()
        .map(|o| o.entry)
        .collect();
    edit(&mut entries);
    git(
        &e.root,
        &[
            "--git-dir",
            dst.to_str().unwrap(),
            "update-ref",
            "-d",
            "refs/lonca/oplog",
        ],
    );
    let k = key(e);
    let mut prev = GENESIS_PREV.to_string();
    let mut head = None;
    for mut entry in entries {
        entry.prev = prev;
        let signed = SignedOp::sign(entry, &k);
        prev = signed.hash.clone();
        head = Some(OpLog::new(&store).append(&signed, head.as_ref()).unwrap());
    }
    store
}

fn kinds(r: &lonca_audit::Report) -> Vec<String> {
    r.findings.iter().map(|f| f.kind.clone()).collect()
}

#[test]
fn real_logs_audit_clean_locally_and_after_push() {
    let mut e = busy_repo();
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
    assert!(r.skipped.is_empty(), "{:#?}", r.skipped);
    let s = e.ok("status", Some("demo"), None, json!({}));
    let statuses: Vec<String> = s["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["status"]["status"].as_str().unwrap().to_string())
        .collect();
    assert!(
        statuses.contains(&"conflicted".to_string())
            && statuses.contains(&"integrated".to_string())
    );

    let remote = e.root.join("remote.git");
    git(&e.root, &["init", "-q", "--bare", remote.to_str().unwrap()]);
    let prep = e.ok(
        "human.prepare_push",
        Some("demo"),
        None,
        json!({"remote": remote}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    e.human(op);
    let pushed = Store::open(&remote).unwrap();
    let r = audit(&pushed, Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

#[test]
fn forged_decision_is_caught_even_with_a_valid_signature() {
    let e = busy_repo();
    let forged = forge(&e, "forged-decision.git", |entries| {
        let denied = entries
            .iter_mut()
            .find(|x| x.decision.outcome == Out::Deny)
            .expect("a denial");
        denied.decision = Decision::allow();
    });
    let r = audit(
        &forged,
        Options {
            deep: true,
            check_refs: false,
        },
    )
    .unwrap();
    assert!(
        kinds(&r).contains(&"decision".to_string()),
        "{:#?}",
        r.findings
    );
}

#[test]
fn forged_facts_are_caught() {
    let e = busy_repo();
    let forged = forge(&e, "forged-facts.git", |entries| {
        let p = entries
            .iter_mut()
            .find(|x| matches!(x.op, Op::ChangePropose { .. }) && x.actor.session().is_some())
            .unwrap();
        // Hide that the change touched a symbol, and claim the same.
        let f = p.facts.as_mut().unwrap();
        f.edits.clear();
        if let Op::ChangePropose { claim, .. } = &mut p.op {
            claim.edits.clear();
        }
    });
    let r = audit(
        &forged,
        Options {
            deep: true,
            check_refs: false,
        },
    )
    .unwrap();
    assert!(
        kinds(&r).contains(&"facts".to_string()),
        "{:#?}",
        r.findings
    );
    // A shallow audit can not see this: it trusts recorded facts.
    let shallow = audit(
        &forged,
        Options {
            deep: false,
            check_refs: false,
        },
    )
    .unwrap();
    assert!(!kinds(&shallow).contains(&"facts".to_string()));
}

#[test]
fn forged_merge_is_caught() {
    let e = busy_repo();
    let store = e.store();
    let trunk = e.svc.handle(Request {
        id: 1,
        method: "status".into(),
        repo: Some("demo".into()),
        token: None,
        params: json!({}),
    });
    let trunk: GitId = serde_json::from_value(trunk.result["trunk"].clone()).unwrap();
    let forged = forge(&e, "forged-merge.git", |entries| {
        let i = entries
            .iter_mut()
            .find(|x| {
                matches!(
                    &x.op,
                    Op::ChangeIntegrate {
                        merged: Some(_),
                        ..
                    }
                ) && x.decision.outcome == Out::Allow
            })
            .unwrap();
        if let Op::ChangeIntegrate { merged, .. } = &mut i.op {
            *merged = Some(trunk.clone());
        }
    });
    let _ = store;
    let r = audit(
        &forged,
        Options {
            deep: true,
            check_refs: false,
        },
    )
    .unwrap();
    assert!(
        kinds(&r).contains(&"merge".to_string()),
        "{:#?}",
        r.findings
    );
}

#[test]
fn auditor_flag_freezes_the_repository() {
    let mut e = Env::new();
    e.init(None);
    let flag = e.svc.home.freeze_flag("demo");
    std::fs::create_dir_all(flag.parent().unwrap()).unwrap();
    std::fs::write(&flag, "audit: decision mismatch at 7").unwrap();
    e.svc.reconcile_all();
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(s["frozen"], "audit: decision mismatch at 7");
    assert!(!flag.exists());
    let token = e.call("human.submit", Some("demo"), None, {
        let op = Op::SessionStart {
            session: "s9".into(),
            agent: "bot".into(),
            model: None,
            task: "t".into(),
            scope: Scope {
                paths: vec!["**".into()],
                symbols: None,
                ops: vec![OpKind::LeaseAcquire],
                max_files: None,
                max_lines: None,
            },
            expires_ms: e.now() + 60_000,
        };
        e.sign(&op)
    });
    assert_eq!(
        token.unwrap()["decision"]["outcome"],
        "deny",
        "frozen repositories refuse new work"
    );
}

#[test]
fn unsigned_tampering_breaks_the_chain() {
    let e = busy_repo();
    let dst = e.root.join("tampered.git");
    git(
        &e.root,
        &[
            "clone",
            "-q",
            "--mirror",
            e.root.join("home/repos/demo.git").to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    );
    let store = Store::open(&dst).unwrap();
    let mut ops = OpLog::new(&store).read_all().unwrap();
    ops[3].entry.time_ms += 1;
    let r = lonca_audit::audit_ops(&store, &ops, Options::default());
    assert_eq!(kinds(&r), vec!["chain".to_string()]);
}

#[test]
fn rewriting_published_history_is_detected() {
    let mut e = busy_repo();
    let remote = e.root.join("remote.git");
    git(&e.root, &["init", "-q", "--bare", remote.to_str().unwrap()]);
    let prep = e.ok(
        "human.prepare_push",
        Some("demo"),
        None,
        json!({"remote": remote}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    e.human(op);
    let published = OpLog::new(&Store::open(&remote).unwrap())
        .read_all()
        .unwrap();
    let local = OpLog::new(&e.store()).read_all().unwrap();
    assert!(compare(&local, &published).is_empty());
    // An insider rewrites an old entry locally after the push.
    let forged = forge(&e, "rewritten.git", |entries| {
        entries[2].decision.reasons.push("edited".into())
    });
    let rewritten = OpLog::new(&forged).read_all().unwrap();
    let f = compare(&rewritten, &published);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0].seq, Some(2));
}
