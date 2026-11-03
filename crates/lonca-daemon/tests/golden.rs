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
    e
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
        },
        expires_ms: e.now() + 3_600_000,
    };
    let body = json!({"op": start, "sig": sign_ed25519(&bora, "bora", "demo", &start, e.now())});
    allowed(e.ok("human.submit", Some("demo"), None, body));
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
