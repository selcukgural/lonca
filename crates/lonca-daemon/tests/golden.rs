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
use std::collections::BTreeSet;

/// `busy_repo` plus lease release, session end, freeze and unfreeze.
fn golden_repo() -> Env {
    let mut e = busy_repo();
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
    e
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
