//! Every ref of a store is held to the log (issue #58): a write behind the
//! daemon's back to any of them is logged as `import.unmediated` and undone
//! by `reconcile()`, and the auditor finds it on its own.

mod common;
use common::*;

use lonca_audit::{Options, Report, audit};

fn update_ref(e: &Env, args: &[&str]) {
    let store = e.store();
    let mut all = vec!["--git-dir", store.path().to_str().unwrap(), "update-ref"];
    all.extend(args);
    git(&e.root, &all);
}

fn unmediated(e: &Env) -> Vec<(String, Option<GitId>, Option<GitId>)> {
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    ops.into_iter()
        .filter_map(|o| match o.entry.op {
            Op::ImportUnmediated {
                refname,
                found,
                expected,
            } => Some((refname, found, expected)),
            _ => None,
        })
        .collect()
}

fn audit_all(store: &Store) -> Report {
    let opts = Options {
        deep: true,
        check_refs: true,
        all_refs: true,
    };
    audit(store, opts).unwrap()
}

fn ref_findings(r: &Report) -> Vec<String> {
    r.findings
        .iter()
        .filter(|f| f.kind == "ref")
        .map(|f| f.detail.clone())
        .collect()
}

/// A copy of the store as it is now, for the auditor to see what the daemon
/// has not reconciled yet.
fn snapshot(e: &Env, name: &str) -> Store {
    let dst = e.root.join(name);
    let src = e.store();
    git(
        &e.root,
        &[
            "clone",
            "-q",
            "--mirror",
            src.path().to_str().unwrap(),
            dst.to_str().unwrap(),
        ],
    );
    Store::open(&dst).unwrap()
}

fn proposals(e: &Env) -> Vec<(String, GitId)> {
    e.store().refs_with_prefix("refs/lonca/changes/").unwrap()
}

#[test]
fn a_busy_repository_holds_only_refs_the_log_has() {
    let e = busy_repo();
    assert!(!proposals(&e).is_empty());
    e.svc.reconcile_all();
    assert!(unmediated(&e).is_empty(), "{:?}", unmediated(&e));
    let r = audit_all(&e.store());
    assert!(r.ok(), "{:#?}", r.findings);
}

#[test]
fn an_unknown_change_ref_is_logged_and_removed() {
    let mut e = busy_repo();
    let trunk = e.trunk();
    update_ref(&e, &["refs/lonca/changes/x/1", &trunk.0]);
    let seen = snapshot(&e, "seen.git");
    let found = ref_findings(&audit_all(&seen));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("refs/lonca/changes/x/1"), "{found:?}");
    // The default auditor looks under refs/lonca/ too.
    assert_eq!(
        ref_findings(&audit(&seen, Options::default()).unwrap()).len(),
        1
    );

    e.svc.reconcile_all();
    assert_eq!(
        unmediated(&e),
        [("refs/lonca/changes/x/1".to_string(), Some(trunk), None)]
    );
    assert_eq!(e.store().ref_get("refs/lonca/changes/x/1").unwrap(), None);
    let r = audit_all(&e.store());
    assert!(r.ok(), "{:#?}", r.findings);
}

#[test]
fn a_new_branch_is_logged_and_removed() {
    let mut e = busy_repo();
    let trunk = e.trunk();
    update_ref(&e, &["refs/heads/other", &trunk.0]);
    let seen = snapshot(&e, "seen.git");
    let found = ref_findings(&audit_all(&seen));
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("refs/heads/other"), "{found:?}");
    // Outside refs/lonca/ only with --all-refs: a clone has its remotes'.
    assert!(audit(&seen, Options::default()).unwrap().ok());

    e.svc.reconcile_all();
    assert_eq!(
        unmediated(&e),
        [("refs/heads/other".to_string(), Some(trunk), None)]
    );
    assert_eq!(e.store().ref_get("refs/heads/other").unwrap(), None);
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert!(
        s["frozen"].is_null(),
        "restore, not freeze, by default: {s}"
    );
    let r = audit_all(&e.store());
    assert!(r.ok(), "{:#?}", r.findings);
}

#[test]
fn a_moved_operation_log_is_put_back_logged_and_frozen() {
    let mut e = busy_repo();
    let store = e.store();
    let head = store.ref_get("refs/lonca/oplog").unwrap().unwrap();
    let parent = store.read_commit(&head).unwrap().parents[0].clone();
    update_ref(&e, &["refs/lonca/oplog", &parent.0]);
    e.svc.reconcile_all();
    let logged = unmediated(&e);
    assert_eq!(
        logged,
        [(
            "refs/lonca/oplog".to_string(),
            Some(parent),
            Some(head.clone())
        )]
    );
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert!(
        s["frozen"].as_str().unwrap().contains("refs/lonca/oplog"),
        "{s}"
    );
    let now = e.store().ref_get("refs/lonca/oplog").unwrap().unwrap();
    assert_ne!(now, head, "the entries were appended on top of the head");
    let r = audit_all(&e.store());
    assert!(r.ok(), "{:#?}", r.findings);
}

/// Cut back to before the last proposal, the log no longer has that
/// proposal's ref: the auditor sees the cut on its own.
#[test]
fn the_auditor_sees_a_log_cut_short() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let t = e.session("s1", &["src/**"]);
    e.bind(&t);
    e.wrote(&t, "src/lib.rs");
    e.lease(&t, "src/lib.rs#charge");
    let r = e.propose(
        &t,
        &base,
        vec![file(
            "src/lib.rs",
            &LIB.replacen("    a\n", "    a + 1\n", 1),
        )],
        &["src/lib.rs#charge"],
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let store = e.store();
    let head = store.ref_get("refs/lonca/oplog").unwrap().unwrap();
    let parent = store.read_commit(&head).unwrap().parents[0].clone();
    update_ref(&e, &["refs/lonca/oplog", &parent.0]);
    let found = ref_findings(&audit(&snapshot(&e, "cut.git"), Options::default()).unwrap());
    assert!(
        found.iter().any(|f| f.contains("past the end of the log")),
        "{found:?}"
    );
}

#[test]
fn a_changed_or_missing_proposal_ref_is_put_back() {
    let e = busy_repo();
    let (first, commit) = proposals(&e)[0].clone();
    let (second, other) = proposals(&e)[1].clone();
    assert_ne!(commit, other);
    update_ref(&e, &[&first, &other.0]);
    update_ref(&e, &["-d", &second]);
    let found = ref_findings(&audit_all(&snapshot(&e, "seen.git")));
    assert_eq!(found.len(), 2, "{found:?}");

    e.svc.reconcile_all();
    let mut logged = unmediated(&e);
    logged.sort();
    let mut want = vec![
        (first.clone(), Some(other.clone()), Some(commit.clone())),
        (second.clone(), None, Some(other.clone())),
    ];
    want.sort();
    assert_eq!(logged, want);
    assert_eq!(e.store().ref_get(&first).unwrap(), Some(commit));
    assert_eq!(e.store().ref_get(&second).unwrap(), Some(other));
    let r = audit_all(&e.store());
    assert!(r.ok(), "{:#?}", r.findings);
}

/// The ref a proposal writes before its entry: if the daemon stops in
/// between, the next start removes it, and nothing is logged.
#[test]
fn a_proposal_ref_that_was_never_logged_goes_quietly() {
    let mut e = busy_repo();
    let trunk = e.trunk();
    let next = e.ok("status", Some("demo"), None, json!({}))["next_seq"]
        .as_u64()
        .unwrap();
    let name = format!("refs/lonca/changes/{}/{next}", ChangeId::random());
    update_ref(&e, &[&name, &trunk.0]);
    e.reopen();
    assert!(unmediated(&e).is_empty());
    assert_eq!(e.store().ref_get(&name).unwrap(), None);
}

/// The bridge pushes the proposals the log has, and nothing else.
#[test]
fn a_push_carries_only_the_refs_the_log_has() {
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
    let r = e.human(op);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let pushed = Store::open(&remote).unwrap();
    let mut theirs = pushed.refs_with_prefix("refs/lonca/changes/").unwrap();
    let mut ours = proposals(&e);
    theirs.sort();
    ours.sort();
    assert_eq!(theirs, ours);
    let r = audit_all(&pushed);
    assert!(r.ok(), "{:#?}", r.findings);
}
