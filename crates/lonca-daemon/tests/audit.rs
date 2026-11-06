//! The auditor against real daemon logs, and against forgeries made by an
//! insider who holds the daemon key (so every signature still verifies).

mod common;
use common::*;

use lonca_audit::{Options, audit, compare};
use lonca_core::oplog::{GENESIS_PREV, OpEntry};
use lonca_core::ops::{Decision, Outcome as Out};

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
    let mut e = busy_repo();
    let store = e.store();
    let trunk = e.trunk();
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

/// What a batch says it verified has to be there, and of what trunk became.
#[test]
fn a_batch_with_no_evidence_or_another_tree_is_caught() {
    let mut e = Env::new();
    e.init(None);
    let config = lonca_policy::config::DEFAULT_CONFIG.replace("batch_size = 1", "batch_size = 2");
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    e.human_change(vec![file("src/a", "a\n")], "a");
    e.human_change(vec![file("src/b", "b\n")], "b");
    assert_eq!(e.svc.process_all(), 2);
    let the_batch = |entries: &mut Vec<OpEntry>| -> usize {
        let is_batch = |x: &OpEntry| matches!(x.op, Op::ChangeIntegrateBatch { .. });
        entries.iter().position(is_batch).expect("a batch")
    };
    let deep = |store: &Store| {
        let options = Options {
            deep: true,
            check_refs: false,
        };
        audit(store, options).unwrap()
    };
    let none = forge(&e, "none", |entries| {
        let at = the_batch(entries);
        entries[at].evidence.clear();
    });
    assert!(
        kinds(&deep(&none)).contains(&"merge".to_string()),
        "no evidence"
    );
    let other = forge(&e, "other", |entries| {
        let at = the_batch(entries);
        entries[at].evidence[0].subject_tree = GitId::of_blob(b"another");
    });
    assert!(
        kinds(&deep(&other)).contains(&"merge".to_string()),
        "another tree"
    );
    // The tip is right and the tree verified, the commit before it is not
    // what the merge comes to.
    let inner = forge(&e, "inner", |entries| {
        let at = the_batch(entries);
        let Op::ChangeIntegrateBatch { merged, .. } = &mut entries[at].op else {
            unreachable!("a batch");
        };
        merged[0].1 = merged[1].1.clone();
    });
    let inner = deep(&inner);
    let recorded = |f: &lonca_audit::Finding| f.kind == "merge" && f.detail.contains("recorded");
    assert!(inner.findings.iter().any(recorded), "{:?}", inner.findings);
    // A commit this copy does not have proves nothing either way.
    let shallow = forge(&e, "shallow", |entries| {
        let at = the_batch(entries);
        let Op::ChangeIntegrateBatch { trunk_before, .. } = &mut entries[at].op else {
            unreachable!("a batch");
        };
        *trunk_before = GitId::of_blob(b"not here");
    });
    let shallow = deep(&shallow);
    assert!(!kinds(&shallow).contains(&"merge".to_string()));
    let merge = |f: &lonca_audit::Finding| f.kind == "merge";
    assert!(shallow.skipped.iter().any(merge), "{:?}", shallow.skipped);
    let good = forge(&e, "good", |_| {});
    assert!(kinds(&deep(&good)).is_empty());
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
                scratch: vec![],
            },
            expires_ms: e.now() + 60_000,
            continues: None,
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
