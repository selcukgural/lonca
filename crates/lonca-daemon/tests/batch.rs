//! The merge queue in batches (issue #49): the merged result of the changes
//! at the head is verified once, a failure is bisected, and a tree that
//! passed is not verified again. One log entry integrates a batch, so trunk
//! never stands at a state nothing verified.

mod common;
use common::*;

use lonca_audit::{Options, audit};

use lonca_core::ops::{CheckKind, Claim};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY};
use serde_json::{Value, json};

const TESTS: &str = "# test = \"cargo test --offline\"";

/// A repository whose test fails when a file called `bad` is in the tree.
fn repo(batch: u32) -> (Env, GitId) {
    repo_with(batch, "test ! -e src/bad")
}

fn repo_with(batch: u32, test: &str) -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    let config = DEFAULT_CONFIG
        .replace("batch_size = 1", &format!("batch_size = {batch}"))
        .replace("required = false", "required = true")
        .replace(TESTS, &format!("test = \"{test}\""));
    assert!(config.contains(test));
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let r = e.human_change(vec![file("src/seed", "seed\n")], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    (e, base)
}

/// An agent adding `path`, queued.
fn add(e: &mut Env, base: &GitId, name: &str, path: &str) -> Value {
    add_text(e, base, name, path, "text\n")
}

fn add_text(e: &mut Env, base: &GitId, name: &str, path: &str, text: &str) -> Value {
    let t = e.session(name, &["src/**"]);
    e.bind(&t);
    e.wrote(&t, path);
    let claim = Claim {
        intent: format!("add {path}"),
        ..Default::default()
    };
    let lease = e.lease(&t, &format!("{path}#<file>"));
    let _ = lease;
    let files = [file(path, text)];
    let r = e.ok(
        "facts.preview",
        None,
        Some(&t),
        json!({"base": base, "files": files}),
    );
    let claim = Claim {
        adds: r["facts"]["adds"].as_array().map_or(vec![], |a| {
            a.iter().map(|s| s.as_str().unwrap().to_string()).collect()
        }),
        ..claim
    };
    let args = json!({"base": base, "files": files, "claim": claim});
    let r = e.ok("change.propose", None, Some(&t), args);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    r
}

fn status_of(e: &mut Env, change: &Value) -> Value {
    let c = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    c["status"].clone()
}

fn entries(e: &Env) -> Vec<Op> {
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    ops.into_iter().map(|o| o.entry.op).collect()
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

fn batches(e: &Env) -> Vec<usize> {
    let ops = entries(e);
    let sizes = ops.iter().filter_map(|op| match op {
        Op::ChangeIntegrateBatch { merged, .. } => Some(merged.len()),
        _ => None,
    });
    sizes.collect()
}

#[test]
fn ten_changes_in_batches_of_five_verify_twice() {
    let (mut e, base) = repo(5);
    let runs = e.svc.verification_runs();
    let changes: Vec<Value> = (0..10)
        .map(|i| add(&mut e, &base, &format!("a{i}"), &format!("src/f{i}"))["change"].clone())
        .collect();
    assert_eq!(e.svc.process_all(), 10, "changes, not entries");
    assert_eq!(e.svc.verification_runs() - runs, 2);
    assert_eq!(batches(&e), [5, 5]);
    for change in &changes {
        assert_eq!(status_of(&mut e, change)["status"], "integrated");
    }
    let head = e.trunk();
    for i in 0..10 {
        let path = format!("src/f{i}");
        assert!(e.store().read_file(&head, &path).unwrap().is_some(), "{i}");
    }
    audited(&e);
}

/// Bisection finds the bad one, the others land in queue order, and a
/// failure is logged as it always was.
#[test]
fn a_bad_change_is_found_and_the_others_land_in_order() {
    let (mut e, base) = repo(4);
    let paths = ["src/a", "src/b", "src/bad", "src/c"];
    let changes: Vec<Value> = (0..4)
        .map(|i| add(&mut e, &base, &format!("a{i}"), paths[i])["change"].clone())
        .collect();
    e.svc.process_all();
    assert_eq!(batches(&e), [2], "the prefix in front of it");
    let of = |e: &mut Env, i: usize| status_of(e, &changes[i])["status"].clone();
    assert_eq!(of(&mut e, 0), "integrated");
    assert_eq!(of(&mut e, 1), "integrated");
    assert_eq!(of(&mut e, 2), "rejected");
    assert_eq!(of(&mut e, 3), "integrated");
    let head = e.trunk();
    let store = e.store();
    assert!(store.read_file(&head, "src/bad").unwrap().is_none());
    assert!(store.read_file(&head, "src/c").unwrap().is_some());
    audited(&e);
}

/// What is left after a conflict is left to the queue as ever.
#[test]
fn a_conflict_ends_a_batch() {
    let (mut e, base) = repo(4);
    let one = add(&mut e, &base, "a", "src/a")["change"].clone();
    let two = add(&mut e, &base, "b", "src/b")["change"].clone();
    let same = add_text(&mut e, &base, "c", "src/a", "other\n")["change"].clone();
    let last = add(&mut e, &base, "d", "src/d")["change"].clone();
    e.svc.process_all();
    assert_eq!(batches(&e), [2], "up to the conflict");
    assert_eq!(status_of(&mut e, &one)["status"], "integrated");
    assert_eq!(status_of(&mut e, &two)["status"], "integrated");
    assert_eq!(status_of(&mut e, &last)["status"], "integrated");
    assert_ne!(status_of(&mut e, &same)["status"], "integrated");
    audited(&e);
}

/// The commits inside a batch were never trunk: no base, and only the tip's
/// tree was verified.
#[test]
fn a_commit_inside_a_batch_was_never_trunk() {
    let (mut e, base) = repo(2);
    add(&mut e, &base, "a", "src/a");
    add(&mut e, &base, "b", "src/b");
    assert_eq!(e.svc.process_all(), 2);
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let o = ops
        .iter()
        .rev()
        .find(|o| matches!(o.entry.op, Op::ChangeIntegrateBatch { .. }));
    let o = o.expect("a batch");
    let Op::ChangeIntegrateBatch { merged, .. } = &o.entry.op else {
        unreachable!();
    };
    let inner = merged[0].1.clone();
    let tip = merged[1].1.clone();
    assert_eq!(e.trunk(), tip);
    let tree = e.store().read_commit(&tip).unwrap().tree;
    assert!(o.entry.evidence.iter().all(|a| a.subject_tree == tree));
    let t = e.session("c", &["src/**"]);
    e.bind(&t);
    e.wrote(&t, "src/c");
    let claim = Claim {
        intent: "from inside".into(),
        ..Default::default()
    };
    let args = json!({"base": inner, "files": [file("src/c", "c\n")], "claim": claim});
    let r = e.ok("change.propose", None, Some(&t), args);
    assert!(r["decision"].to_string().contains("unknown_base"), "{r}");
}

/// A tree that passed is not verified again: what is logged is what passed.
#[test]
fn a_tree_that_passed_is_not_verified_again() {
    let (mut e, _) = repo(2);
    let seed = "seed\n";
    let change = |e: &mut Env, text: &str| {
        let r = e.human_change(vec![file("src/seed", text)], "edit");
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        assert_eq!(e.svc.process_all(), 1);
    };
    change(&mut e, "two\n");
    let runs = e.svc.verification_runs();
    change(&mut e, seed);
    assert_eq!(e.svc.verification_runs(), runs, "the tree of the seed");
    change(&mut e, "three\n");
    assert_eq!(e.svc.verification_runs(), runs + 1);
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let tests = |o: &&lonca_core::oplog::SignedOp| {
        o.entry.evidence.iter().any(|a| a.check == CheckKind::Tests)
    };
    assert_eq!(ops.iter().filter(tests).count(), 4, "logged each time");
    let reused = |o: &&lonca_core::oplog::SignedOp| {
        let tests = o
            .entry
            .evidence
            .iter()
            .filter(|a| a.check == CheckKind::Tests);
        tests.into_iter().any(|a| a.details.contains_key("reused"))
    };
    assert_eq!(
        ops.iter().filter(reused).count(),
        1,
        "and marked when reused"
    );
    audited(&e);
}

/// With one change at a time everything is verified, as before.
#[test]
fn the_default_verifies_every_tree() {
    let (mut e, _) = repo(1);
    let change = |e: &mut Env, text: &str| {
        e.human_change(vec![file("src/seed", text)], "edit");
        e.svc.process_all();
    };
    change(&mut e, "two\n");
    let runs = e.svc.verification_runs();
    change(&mut e, "seed\n");
    assert_eq!(e.svc.verification_runs(), runs + 1);
}

/// What a check ran on is more than its tree, so a result does not last.
#[test]
fn a_result_is_kept_for_an_hour() {
    let (mut e, _) = repo(2);
    let change = |e: &mut Env, text: &str| {
        e.human_change(vec![file("src/seed", text)], "edit");
        e.svc.process_all();
    };
    let hour = 3_600_000;
    change(&mut e, "two\n");
    change(&mut e, "seed\n");
    let runs = e.svc.verification_runs();
    e.clock.fetch_add(hour - 60_000, Ordering::SeqCst);
    change(&mut e, "two\n");
    assert_eq!(e.svc.verification_runs(), runs, "still known");
    e.clock.fetch_add(60_000, Ordering::SeqCst);
    change(&mut e, "seed\n");
    assert_eq!(e.svc.verification_runs(), runs + 1, "gone at the hour");
}

/// Withdrawn and proposed again while the worker verifies: the same id, other
/// content. What lands is the new proposal, or nothing yet.
#[test]
fn a_proposal_replaced_during_verification_is_not_logged() {
    for batch in [1, 2] {
        let (mut e, base) = repo_with(batch, "sleep 1");
        if batch > 1 {
            add(&mut e, &base, "a", "src/a");
        }
        let t = e.session("b", &["src/**"]);
        e.bind(&t);
        e.wrote(&t, "src/b");
        e.lease(&t, "src/b#<file>");
        let propose = |e: &mut Env, text: &str, change: Option<&Value>| {
            let claim = Claim {
                intent: "b".into(),
                ..Default::default()
            };
            let mut args = json!({"base": base, "files": [file("src/b", text)], "claim": claim});
            if let Some(change) = change {
                args["change"] = change.clone();
            }
            e.ok("change.propose", None, Some(&t), args)
        };
        let old = propose(&mut e, "old\n", None)["change"].clone();
        let svc = e.svc.clone();
        let worker = std::thread::spawn(move || svc.process_all());
        std::thread::sleep(std::time::Duration::from_millis(400));
        let id: ChangeId = serde_json::from_value(old.clone()).unwrap();
        e.human(Op::ChangeWithdraw { change: id });
        let r = propose(&mut e, "new\n", Some(&old));
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        worker.join().unwrap();
        e.svc.process_all();
        let head = e.trunk();
        let text = e.store().read_file(&head, "src/b").unwrap().unwrap();
        assert_eq!(text, b"new\n", "batch {batch}");
        audited(&e);
    }
}

/// A file where another change makes a directory: a conflict on the second,
/// whichever way the queue runs, and the queue goes on.
#[test]
fn a_path_that_is_both_file_and_directory_is_a_conflict() {
    for batch in [1, 2] {
        let (mut e, base) = repo(batch);
        let one = add(&mut e, &base, "a", "src/x")["change"].clone();
        let two = add(&mut e, &base, "b", "src/x/y")["change"].clone();
        let next = add(&mut e, &base, "c", "src/z")["change"].clone();
        e.svc.process_all();
        assert_eq!(status_of(&mut e, &one)["status"], "integrated");
        assert_eq!(status_of(&mut e, &two)["status"], "conflicted");
        let symbols = status_of(&mut e, &two)["symbols"].clone();
        assert_eq!(symbols, json!(["src/x#<file>"]));
        assert_eq!(status_of(&mut e, &next)["status"], "integrated");
        audited(&e);
    }
}

/// A failure is no result to keep: it may have been the machine.
#[test]
fn a_failed_tree_is_verified_again() {
    let (mut e, base) = repo(2);
    let change = add(&mut e, &base, "a", "src/bad")["change"].clone();
    let runs = e.svc.verification_runs();
    e.svc.process_all();
    assert_eq!(status_of(&mut e, &change)["status"], "rejected");
    assert_eq!(e.svc.verification_runs(), runs + 1);
    let again = add(&mut e, &base, "b", "src/bad")["change"].clone();
    e.svc.process_all();
    assert_eq!(status_of(&mut e, &again)["status"], "rejected");
    assert_eq!(e.svc.verification_runs(), runs + 2);
}

/// Each agent hears of its own change, as from a change alone.
#[test]
fn a_batch_tells_each_session_of_its_change() {
    let (mut e, base) = repo(2);
    let tokens: Vec<String> = ["a", "b"]
        .into_iter()
        .map(|name| {
            let t = e.session(name, &["src/**"]);
            e.bind(&t);
            t
        })
        .collect();
    let mut changes = Vec::new();
    for (i, t) in tokens.iter().enumerate() {
        let path = format!("src/f{i}");
        e.wrote(t, &path);
        e.lease(t, &format!("{path}#<file>"));
        let claim = Claim {
            intent: "add".into(),
            ..Default::default()
        };
        let args = json!({"base": base, "files": [file(&path, "x\n")], "claim": claim});
        let r = e.ok("change.propose", None, Some(t), args);
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        changes.push(r["change"].clone());
    }
    assert_eq!(e.svc.process_all(), 2);
    for (i, t) in tokens.iter().enumerate() {
        let r = e.ok("events", None, Some(t), json!({"from": 0}));
        let kinds = r["events"].as_array().unwrap();
        let mine = kinds.iter().filter(|k| k["kind"] == "integrated");
        let heard: Vec<&Value> = mine.map(|k| &k["change"]).collect();
        assert_eq!(heard, [&changes[i]], "{r}");
    }
}

#[test]
fn the_default_is_one_change_at_a_time() {
    let (mut e, base) = repo(1);
    add(&mut e, &base, "a", "src/a");
    add(&mut e, &base, "b", "src/b");
    assert_eq!(e.svc.process_all(), 2);
    assert_eq!(batches(&e), [0usize; 0]);
}
