//! Golden operation logs: one frozen log per format version, written by the
//! release that introduced that version. Every later build must still read,
//! verify, replay and audit them (docs/decisions.md, "Log format versions").
//!
//! A fixture is never regenerated. To add one for a new format version:
//!
//! ```sh
//! LONCA_GOLDEN_OUT=$PWD/crates/lonca-daemon/tests/fixtures/oplog-vN.bundle \
//!   cargo test -p lonca-daemon --test golden -- --ignored write_golden_log
//! ```
//!
//! then add a test below that pins its head hash.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::canonical::canonical_bytes;
use lonca_core::oplog::{FORMAT_CURRENT, FORMAT_LEGACY};
use lonca_symbols::engine::ENGINE_CURRENT;
use std::collections::BTreeSet;

const LEDGER_RS: &str = "pub struct Ledger {\n    total: u64,\n}\n\nimpl Ledger {\n    pub fn add(&mut self, v: u64) {\n        self.total += v;\n    }\n\n    pub fn total(&self) -> u64 {\n        self.total\n    }\n}\n";
const LEDGER_PY: &str = "import os\n\n\nclass Ledger:\n    def add(self, v):\n        self.total += v\n\n    def total(self):\n        return self.total\n";

/// `busy_repo` plus lease release, session end, freeze and unfreeze, and
/// human changes to methods in Rust and Python, so the facts and merges in
/// the log depend on more of the symbol engine (qualified member names,
/// imports, signatures).
fn golden_repo() -> Env {
    let mut e = busy_repo();
    e.human_change(
        vec![
            file("src/ledger.rs", LEDGER_RS),
            file("app/ledger.py", LEDGER_PY),
        ],
        "ledger",
    );
    e.svc.process_all();
    e.human_change(
        vec![
            file(
                "src/ledger.rs",
                &LEDGER_RS.replace(
                    "self.total += v;",
                    "self.total = self.total.saturating_add(v);",
                ),
            ),
            file(
                "app/ledger.py",
                &LEDGER_PY
                    .replace("import os\n", "import os\nimport sys\n")
                    .replace("def add(self, v):", "def add(self, v, note):"),
            ),
        ],
        "ledger methods",
    );
    e.svc.process_all();
    let t = e.session("s3", &["notes.md"]);
    let set = e.lease(&t, "notes.md#<file>")["set"]
        .as_str()
        .expect("lease set")
        .to_string();
    e.ok("lease.release", None, Some(&t), json!({ "set": set }));
    e.ok("session.end", None, Some(&t), json!({}));
    e.human(Op::Freeze {
        reason: "golden".into(),
    });
    e.human(Op::Unfreeze {
        reason: "golden".into(),
    });
    human_keys(&mut e);
    daemon_keys(&mut e);
    scratch_roots(&mut e);
    rejection(&mut e);
    pins(&mut e);
    liveness(&mut e);
    continuation(&mut e);
    queue(&mut e);
    e
}

/// From format 10: an interest gets the freed set, a yield moves a set in
/// one entry, a delegated set comes back when the child ends.
fn queue(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let a = e.session("s16", &["queue.md"]);
    let b = e.session("s17", &["queue.md"]);
    let item = json!([{"symbol": "queue.md#<file>", "kind": "edit"}]);
    let set = e.lease(&a, "queue.md#<file>")["set"].clone();
    allowed(e.ok(
        "lease.interest",
        None,
        Some(&b),
        json!({"items": item, "intent": "next"}),
    ));
    allowed(e.ok("lease.release", None, Some(&a), json!({ "set": set })));
    let set = e.lease(&b, "queue.md#<file>");
    allowed(set.clone());
    let set = set["set"].clone();
    allowed(e.ok(
        "negotiate",
        None,
        Some(&b),
        json!({"thread": "q1", "to_session": "s16",
               "message": {"type": "yield", "set": set, "to": "s16"}}),
    ));
    let scope = json!({"paths": ["queue.md"], "symbols": null, "ops": ["lease.release"],
                       "max_files": null, "max_lines": null});
    let expires = e.now() + 600_000;
    let child = e.ok(
        "cap.attenuate",
        None,
        Some(&a),
        json!({"agent": "sub", "scope": scope, "expires_ms": expires, "leases": [set]}),
    );
    allowed(child.clone());
    allowed(e.ok(
        "session.end",
        None,
        Some(child["token"].as_str().expect("token")),
        json!({}),
    ));
}

/// From format 9: a session with a change in flight is continued; the
/// pin passes on, a human approves, integration releases it.
fn continuation(e: &mut Env) {
    e.human_change(vec![file("cont.md", "first\n")], "continued file");
    e.svc.process_all();
    let base = e.trunk();
    let a = e.session("s14", &["cont.md"]);
    e.lease(&a, "cont.md#<file>");
    let r = e.propose(
        &a,
        &base,
        vec![file("cont.md", "continued\n")],
        &["cont.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let seq = r["seq"].as_u64().expect("seq");
    let c = e.continue_session("s15", "s14", &["cont.md"]);
    assert_eq!(c["decision"]["outcome"], "allow", "{c}");
    let d = e.human(Op::Approve {
        target_seq: seq,
        note: "golden".into(),
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    e.svc.process_all();
}

/// From format 8: a session beats and stops, its lease goes at the
/// timeout; a denied acquire is on record as interest.
fn liveness(e: &mut Env) {
    let a = e.session("s12", &["pins.md"]);
    let b = e.session("s13", &["pins.md"]);
    e.lease(&a, "pins.md#<file>");
    let r = e.ok("session.heartbeat", None, Some(&a), json!({}));
    assert_eq!(r["decision"]["reasons"][0], "heartbeat_timeout=300000");
    assert_eq!(e.lease(&b, "pins.md#<file>")["decision"]["outcome"], "deny");
    e.advance(300_001);
    assert_eq!(
        e.lease(&b, "pins.md#<file>")["decision"]["outcome"],
        "allow"
    );
}

/// From format 7: a proposal pins its lease past the TTL, the human
/// approves, integration releases it; a lease set nobody renewed is pruned.
fn pins(e: &mut Env) {
    let base = e.trunk();
    let a = e.session("s10", &["notes.md", "pins.md"]);
    let b = e.session("s11", &["notes.md"]);
    e.lease(&a, "notes.md#<file>");
    e.lease(&a, "pins.md#<file>");
    let r = e.propose(
        &a,
        &base,
        vec![file("notes.md", "pinned\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    e.advance(601_000);
    assert_eq!(
        e.lease(&b, "notes.md#<file>")["decision"]["outcome"],
        "deny"
    );
    let d = e.human(Op::Approve {
        target_seq: r["seq"].as_u64().expect("seq"),
        note: "golden".into(),
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    e.svc.process_all();
    assert_eq!(
        e.lease(&b, "notes.md#<file>")["decision"]["outcome"],
        "allow"
    );
}

/// From format 6: an unobserved session proposes, a human rejects it with
/// a reason, the session proposes again and the human approves.
fn rejection(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let base = e.trunk();
    let t = e.session("s9", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");
    let r = e.propose(
        &t,
        &base,
        vec![file("notes.md", "golden\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    allowed(e.human(Op::Reject {
        target_seq: r["seq"].as_u64().expect("seq"),
        reason: "golden: say more".into(),
    }));
    e.lease(&t, "notes.md#<file>");
    let r = e.propose(
        &t,
        &base,
        vec![file("notes.md", "golden, more\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    allowed(e.human(Op::Approve {
        target_seq: r["seq"].as_u64().expect("seq"),
        note: "golden".into(),
    }));
    e.svc.process_all();
}

/// From format 5: a session whose scope names scratch roots, a child
/// session narrowed to one of them, and an observation from each.
fn scratch_roots(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let start = Op::SessionStart {
        session: "s8".into(),
        agent: "bot-s8".into(),
        model: None,
        task: "T-8".into(),
        scope: Scope {
            paths: vec!["notes.md".into()],
            symbols: None,
            ops: vec![OpKind::LeaseAcquire, OpKind::CapAttenuate],
            max_files: None,
            max_lines: None,
            scratch: vec!["/tmp/golden/scratch".into(), "/tmp/golden/logs".into()],
        },
        expires_ms: e.now() + 3_600_000,
        continues: None,
    };
    let r = e.human(start);
    allowed(r.clone());
    let t = r["token"].as_str().expect("token").to_string();
    let r = e.ok(
        "cap.attenuate",
        None,
        Some(&t),
        json!({"agent": "bot-s8-child", "scope": {"paths": ["notes.md"], "symbols": null, "ops": ["lease.acquire"], "max_files": null, "max_lines": null, "scratch": ["/tmp/golden/logs"]}, "expires_ms": e.now() + 60_000}),
    );
    allowed(r.clone());
    let ws = e.root.join("ws");
    e.ok(
        "hook.event",
        None,
        Some(&t),
        json!({"hook_event_name": "PostToolUse", "tool_name": "Write", "tool_input": {"file_path": "/tmp/golden/scratch/notes.txt"}, "workspace": ws}),
    );
    e.ok(
        "hook.event",
        None,
        Some(&t),
        json!({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/tmp/golden/logs/run.log"}, "workspace": ws}),
    );
}

/// From format 4: the daemon key is rotated, a session starts, then the
/// key is lost and a human recovers the log onto a new daemon key, which
/// ends the session; one more entry follows under the new key.
fn daemon_keys(e: &mut Env) {
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let next = e.ok("daemon.prepare_rotate", None, None, json!({}))["key"]
        .as_str()
        .expect("key")
        .to_string();
    allowed(e.human(Op::DaemonRotate { key: next }));
    let t = e.session("s6", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");
    std::fs::remove_file(e.root.join("home/daemon.key")).unwrap();
    e.reopen();
    let key = e.ok("ping", None, None, json!({}))["daemon_key"]
        .as_str()
        .expect("key")
        .to_string();
    allowed(e.human(Op::DaemonRecover { key }));
    e.session("s7", &["notes.md"]);
}

/// From format 3: a second human with a session, then ayse sets a recovery
/// key, rotates, recovers and revokes the second human.
fn human_keys(e: &mut Env) {
    let key = |k: &KeyPair| HumanKey {
        alg: "ed25519".into(),
        public: k.public_hex(),
    };
    let allowed = |r: Value| assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let bora = KeyPair::generate();
    allowed(e.human(Op::HumanEnroll {
        human: "bora".into(),
        key: key(&bora),
    }));
    let start = Op::SessionStart {
        session: "s4".into(),
        agent: "bot-s4".into(),
        model: None,
        task: "T-4".into(),
        scope: Scope {
            paths: vec!["notes.md".into()],
            symbols: None,
            ops: vec![OpKind::LeaseAcquire],
            max_files: None,
            max_lines: None,
            scratch: vec![],
        },
        expires_ms: e.now() + 3_600_000,
        continues: None,
    };
    let body = json!({"op": start, "sig": sign_ed25519(&bora, "bora", "demo", &start, e.now())});
    // Bora submits on bora's own session (logins are not log entries).
    let sig = sign_login_ed25519(&bora, "bora", None, 3_600_000, e.now());
    let bora_session = e
        .anon(
            "human.login",
            None,
            None,
            json!({"sig": sig, "ttl_ms": 3_600_000}),
        )
        .unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    allowed(
        e.anon("human.submit", Some("demo"), Some(&bora_session), body)
            .unwrap(),
    );
    let t = e.session("s5", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");

    let rec = KeyPair::generate();
    allowed(e.human(Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: key(&rec),
    }));
    let rotated = KeyPair::generate();
    allowed(e.human(Op::HumanRotate {
        human: "ayse".into(),
        key: key(&rotated),
    }));
    e.human = rotated;
    let recovered = KeyPair::generate();
    let op = Op::HumanRecover {
        human: "ayse".into(),
        key: key(&recovered),
    };
    let body = json!({"op": op, "sig": sign_ed25519(&rec, "ayse", "demo", &op, e.now())});
    allowed(e.ok("human.submit", Some("demo"), None, body));
    e.human = recovered;
    allowed(e.human(Op::HumanRevoke {
        human: "bora".into(),
        reason: "golden".into(),
    }));
}

#[test]
#[ignore = "writes a new fixture; run by hand when the log format version changes"]
fn write_golden_log() {
    let out = std::env::var("LONCA_GOLDEN_OUT").expect("set LONCA_GOLDEN_OUT");
    let out = std::path::absolute(out).unwrap();
    assert!(!out.exists(), "fixtures are never overwritten: {out:?}");
    let e = golden_repo();
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
    let repo = e.root.join("home/repos/demo.git");
    git(
        &repo,
        &["bundle", "create", "-q", out.to_str().unwrap(), "--all"],
    );
    eprintln!("wrote {out:?}, head hash {}", r.head_hash);
}

/// Unpacks a fixture bundle into a fresh bare repository.
fn load(name: &str) -> (tempfile::TempDir, Store) {
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("r.git");
    git(
        dir.path(),
        &["init", "-q", "--bare", repo.to_str().unwrap()],
    );
    git(
        &repo,
        &["fetch", "-q", bundle.to_str().unwrap(), "+refs/*:refs/*"],
    );
    let store = Store::open(&repo).unwrap();
    (dir, store)
}

/// Reads, verifies, replays and deeply audits a golden log, and checks that
/// re-encoding every entry reproduces the stored bytes.
fn check_golden(name: &str, head_hash: &str, format: u32) -> Vec<SignedOp> {
    let (_dir, store) = load(name);
    let log = OpLog::new(&store);
    let ops = log.read_all().unwrap();
    assert_eq!(verify_chain(&ops).unwrap(), head_hash, "{name}: head hash");

    let mut cur = log.head().unwrap();
    while let Some(c) = cur {
        let stored = store.read_file(&c, "op.json").unwrap().unwrap();
        let op = log.read_at(&c).unwrap();
        assert_eq!(op.entry.format, format, "{name}: op {}", op.entry.seq);
        assert_eq!(
            canonical_bytes(&op),
            stored,
            "{name}: op {} re-encodes differently",
            op.entry.seq
        );
        cur = store.read_commit(&c).unwrap().parents.into_iter().next();
    }

    let r = audit(&store, Options::default()).unwrap();
    assert!(r.ok(), "{name}: {:#?}", r.findings);
    assert!(r.skipped.is_empty(), "{name}: {:#?}", r.skipped);
    ops
}

#[test]
fn golden_v0_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v0.bundle",
        "d71753b35ca99db8c7a3b748b4d99567793467d4f96dcc421cc70a5fa6a3fe63",
        FORMAT_LEGACY,
    );
    let kinds: BTreeSet<&str> = ops.iter().map(|o| o.entry.op.kind().as_str()).collect();
    for k in [
        "repo.init",
        "policy.update",
        "session.start",
        "session.bind",
        "session.end",
        "lease.acquire",
        "lease.release",
        "change.propose",
        "change.integrate",
        "observe",
        "freeze",
        "unfreeze",
    ] {
        assert!(kinds.contains(k), "fixture lacks {k}: {kinds:?}");
    }
}

#[test]
fn golden_v1_log_still_verifies_replays_and_audits() {
    check_golden(
        "oplog-v1.bundle",
        "3761c7aefd055c300110e1277b8461d9fee782de8aba3c4591275023860a88e5",
        1,
    );
}

#[test]
fn golden_v2_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v2.bundle",
        "ec816526807edc4243261b1cdd649ec847509488fc86e921adcdcd0b29b66af1",
        2,
    );
    assert!(
        ops.iter()
            .filter(|o| o.entry.uses_symbols_engine())
            .all(|o| o.entry.symbols_engine == Some(0)),
        "v2 entries record symbol engine 0"
    );
}

#[test]
fn golden_v3_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v3.bundle",
        "9d6b940cf79c0872bf8bff2e3a0b61e805f8ebb31c5ce3f70419de44d92b2e33",
        3,
    );
    let kinds: BTreeSet<&str> = ops.iter().map(|o| o.entry.op.kind().as_str()).collect();
    for k in [
        "human.enroll",
        "human.recovery_key",
        "human.rotate",
        "human.recover",
        "human.revoke",
    ] {
        assert!(kinds.contains(k), "fixture lacks {k}: {kinds:?}");
    }
    assert!(
        ops.iter()
            .filter(|o| o.entry.op.kind().as_str().starts_with("human."))
            .all(|o| o.entry.decision.is_allow()),
        "the key operations in the fixture are allowed"
    );
}

#[test]
fn golden_v4_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v4.bundle",
        "bdda8f61008981ccab907c4aa6d156621bb4dcca57b992229ffbccebf7aa7a5f",
        4,
    );
    let switches: Vec<&str> = ops
        .iter()
        .filter(|o| o.entry.switches_daemon_key().is_some())
        .map(|o| o.entry.op.kind().as_str())
        .collect();
    assert_eq!(switches, ["daemon.rotate", "daemon.recover"]);
    // Three daemon keys signed it: genesis, rotation, recovery.
    let (_dir, store) = load("oplog-v4.bundle");
    let r = audit(&store, Options::default()).unwrap();
    assert_eq!(r.key_switches.len(), 2);
    assert_ne!(r.key_switches[0].key, r.key_switches[1].key);
}

/// A scope with scratch roots needs format 5: an older entry carrying one
/// is refused by the chain check, like an operation type from a later
/// format.
#[test]
fn scratch_roots_in_an_old_format_entry_are_refused() {
    let mut e = Env::new();
    e.init(None);
    let start = Op::SessionStart {
        session: "s1".into(),
        agent: "bot".into(),
        model: None,
        task: "T".into(),
        scope: Scope {
            paths: vec!["src/**".into()],
            symbols: None,
            ops: vec![OpKind::LeaseAcquire],
            max_files: None,
            max_lines: None,
            scratch: vec!["/tmp/s".into()],
        },
        expires_ms: e.now() + 60_000,
        continues: None,
    };
    assert_eq!(e.human(start)["decision"]["outcome"], "allow");
    assert!(*formats(&e).last().unwrap() >= 5);
    rewrite_log(&e, |entries| {
        for x in entries.iter_mut() {
            x.format = 4;
        }
    });
    let err = match open_service(&e) {
        Ok(_) => panic!("a format 4 entry with scratch roots was accepted"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("session.start needs log format 5"), "{err}");
}

/// `reject` needs format 6: an older entry carrying one is refused.
#[test]
fn a_reject_in_an_old_format_entry_is_refused() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("notes.md", "a\n")], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let t = e.session("s1", &["notes.md"]);
    e.lease(&t, "notes.md#<file>");
    let r = e.propose(
        &t,
        &base,
        vec![file("notes.md", "b\n")],
        &["notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let d = e.human(Op::Reject {
        target_seq: r["seq"].as_u64().unwrap(),
        reason: "no".into(),
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    assert!(*formats(&e).last().unwrap() >= 6);
    rewrite_log(&e, |entries| {
        for x in entries.iter_mut() {
            x.format = 5;
        }
    });
    let err = match open_service(&e) {
        Ok(_) => panic!("a format 5 entry with a reject was accepted"),
        Err(e) => e.to_string(),
    };
    assert!(err.contains("reject needs log format 6"), "{err}");
}

#[test]
fn golden_v6_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v6.bundle",
        "f2acaf21486501f40f99312aa5e9c287880bf13ec6cd19eb990be4cc3ec0d60c",
        6,
    );
    let rejects: Vec<&str> = ops
        .iter()
        .filter_map(|o| match &o.entry.op {
            Op::Reject { reason, .. } if o.entry.decision.is_allow() => Some(reason.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(rejects, ["golden: say more"]);
    let (_dir, store) = load("oplog-v6.bundle");
    let state = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    let rejected = state
        .changes
        .values()
        .filter(|c| matches!(c.status, lonca_policy::state::ChangeStatus::Rejected { .. }))
        .count();
    assert_eq!(rejected, 1);
    assert!(state.pending.is_empty());
}

#[test]
fn golden_v7_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v7.bundle",
        "a12aac062cca0b4ea0bc8bd18b94a36be15c1822b3ce65f53d2a3749cf572282",
        7,
    );
    let (_dir, store) = load("oplog-v7.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    // The set that outlived its TTL is pruned, the pin left with the change.
    assert_eq!(s.leases.len(), 1, "{:?}", s.leases);
    let (set, lease) = s.leases.iter().next().unwrap();
    assert_eq!(lease.session, "s11", "{set}");
    assert!(lease.pins.is_empty());
    assert!(s.queue.is_empty());
    assert!(ops.iter().any(|o| o.entry.format == 7));
}

#[test]
fn golden_v8_log_still_verifies_replays_and_audits() {
    check_golden(
        "oplog-v8.bundle",
        "79046d371007a8b39e9434318f28ea1bfe3d7d1782a7ab7b95bac1f57d420083",
        8,
    );
    let (_dir, store) = load("oplog-v8.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    let beat = s.sessions["s12"].heartbeat.expect("heartbeat recorded");
    assert_eq!(beat.timeout_ms, 300_000);
    assert!(s.sessions["s13"].heartbeat.is_none());
    let holders: Vec<&str> = s.leases.values().map(|l| l.session.as_str()).collect();
    assert_eq!(holders, ["s11", "s13"]);
}

#[test]
fn golden_v9_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v9.bundle",
        "daa7ce053bda8c6360435f9e13faf3ffc8fe7901f3fbe2f08b472c57f25933bd",
        9,
    );
    let continued: Vec<_> = ops
        .iter()
        .filter_map(|o| match &o.entry.op {
            Op::SessionStart {
                session,
                continues: Some(c),
                ..
            } => Some((session.as_str(), c.session.as_str(), c.widen)),
            _ => None,
        })
        .collect();
    assert_eq!(continued, [("s15", "s14", false)]);
    let (_dir, store) = load("oplog-v9.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    assert_eq!(s.sessions["s14"].ended.as_deref(), Some("continued by s15"));
    assert_eq!(s.sessions["s14"].continued_by.as_deref(), Some("s15"));
    assert_eq!(s.sessions["s15"].continued_from.as_deref(), Some("s14"));
    assert!(s.sessions["s15"].ended.is_none());
}

#[test]
fn golden_v10_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v10.bundle",
        "b2c546223ec30380f0f8b3824c237c944f7430e058d81fd025997f3f9e471f45",
        10,
    );
    let kinds: BTreeSet<&str> = ops.iter().map(|o| o.entry.op.kind().as_str()).collect();
    assert!(kinds.contains("lease.interest"), "{kinds:?}");
    let (_dir, store) = load("oplog-v10.bundle");
    let s = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    assert!(s.interests.is_empty(), "served");
    assert!(s.reservations.is_empty(), "consumed");
    let queue: Vec<_> = s.leases.values().filter(|l| l.session == "s16").collect();
    assert_eq!(queue.len(), 1, "yielded to s16, delegated, given back");
    assert_eq!(queue[0].delegated_from, None);
}

#[test]
fn golden_v5_log_still_verifies_replays_and_audits() {
    let ops = check_golden(
        "oplog-v5.bundle",
        "fa1d0352acbfae3e47ec30f79d357055dccbd4326a1d989effd789f24655fa76",
        5,
    );
    // The scratch roots are in the log, in order, and the child kept one.
    let scratches: Vec<Vec<String>> = ops
        .iter()
        .filter_map(|o| match &o.entry.op {
            Op::SessionStart { scope, .. } | Op::CapAttenuate { scope, .. }
                if !scope.scratch.is_empty() =>
            {
                Some(scope.scratch.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        scratches,
        [
            vec!["/tmp/golden/scratch".to_string(), "/tmp/golden/logs".into()],
            vec!["/tmp/golden/logs".to_string()]
        ]
    );
    // The read under a scratch root was observed and did not taint.
    let (_dir, store) = load("oplog-v5.bundle");
    let state = lonca_policy::state::State::replay(&OpLog::new(&store).read_all().unwrap());
    assert!(state.sessions["s8"].taint.is_none());
}

fn open_service(e: &Env) -> lonca_core::Result<Arc<Service>> {
    Service::open(
        Home::new(e.root.join("home")),
        e.settings.clone(),
        Arc::new(|| T0),
    )
}

fn formats(e: &Env) -> Vec<u32> {
    OpLog::new(&e.store())
        .read_all()
        .unwrap()
        .iter()
        .map(|o| o.entry.format)
        .collect()
}

#[test]
fn an_upgraded_daemon_continues_a_v0_log_with_current_entries() {
    let mut e = busy_repo();
    // The log as an older lonca wrote it.
    rewrite_log(&e, |entries| {
        for x in entries.iter_mut() {
            x.format = FORMAT_LEGACY;
            x.symbols_engine = None;
        }
    });
    let old = formats(&e).len();
    let store = e.store();
    let head = OpLog::new(&store).head().unwrap().unwrap();
    let bytes = store.read_file(&head, "op.json").unwrap().unwrap();
    assert!(
        !String::from_utf8(bytes).unwrap().contains("\"format\""),
        "v0 entries carry no format field"
    );

    e.reopen();
    e.human_change(vec![file("notes.md", "b\n")], "after upgrade");
    e.svc.process_all();
    let f = formats(&e);
    assert!(f.len() > old);
    assert!(f[..old].iter().all(|&v| v == FORMAT_LEGACY), "{f:?}");
    assert!(f[old..].iter().all(|&v| v == FORMAT_CURRENT), "{f:?}");

    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
    // The daemon still opens the mixed log.
    e.reopen();
}

#[test]
fn daemon_and_auditor_refuse_a_format_they_do_not_know() {
    let e = busy_repo();
    rewrite_log(&e, |entries| {
        entries.last_mut().unwrap().format = FORMAT_CURRENT + 1;
    });
    let refused = |r: lonca_core::Error| {
        assert!(
            matches!(&r, lonca_core::Error::Unsupported(m) if m.contains("upgrade lonca")),
            "{r}"
        );
    };
    refused(open_service(&e).err().expect("daemon refuses the log"));
    refused(audit(&e.store(), Options::default()).expect_err("auditor refuses"));
}

#[test]
fn a_format_downgrade_along_the_chain_is_refused() {
    let e = busy_repo();
    rewrite_log(&e, |entries| {
        entries.last_mut().unwrap().format = FORMAT_LEGACY;
    });
    let err = open_service(&e).err().expect("daemon refuses the log");
    assert!(err.to_string().contains("log format goes back"), "{err}");
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == "chain" && f.detail.contains("log format goes back")),
        "{:#?}",
        r.findings
    );
}

#[test]
fn the_daemon_records_the_symbol_engine_on_proposals_and_integrations() {
    let e = busy_repo();
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let mut used = 0;
    for o in &ops {
        let x = &o.entry;
        if x.uses_symbols_engine() {
            used += 1;
            assert_eq!(x.symbols_engine, Some(ENGINE_CURRENT), "op {}", x.seq);
        } else {
            assert_eq!(x.symbols_engine, None, "op {}", x.seq);
        }
    }
    assert!(used >= 4, "busy_repo proposes and integrates");
}

#[test]
fn daemon_and_auditor_refuse_a_symbol_engine_they_do_not_know() {
    let e = busy_repo();
    rewrite_log(&e, |entries| {
        let x = entries
            .iter_mut()
            .find(|x| matches!(x.op, Op::ChangeIntegrate { .. }))
            .unwrap();
        x.symbols_engine = Some(ENGINE_CURRENT + 1);
    });
    let err = open_service(&e).err().expect("daemon refuses the log");
    assert!(
        matches!(&err, lonca_core::Error::Unsupported(m) if m.contains("symbol engine")),
        "{err}"
    );
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(
        r.findings
            .iter()
            .any(|f| f.kind == "engine" && f.detail.contains("upgrade lonca")),
        "{:#?}",
        r.findings
    );
}
