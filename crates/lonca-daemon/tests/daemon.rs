//! End-to-end tests of the daemon through its request handler (and once
//! through the real Unix socket).

mod common;
use common::*;

#[test]
fn phase_one_criterion_end_to_end() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();

    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, "src/lib.rs#charge");
    let new = LIB.replacen("    a\n", "    a * 2\n", 1);
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &new)],
        &["src/lib.rs#charge"],
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let trunk = e.trunk();
    assert_ne!(trunk, base);
    let store = e.store();
    assert_eq!(
        store.read_file(&trunk, "src/lib.rs").unwrap().unwrap(),
        new.as_bytes()
    );
    let info = store.read_commit(&trunk).unwrap();
    assert_eq!(info.parents, vec![base.clone()], "linear history");
    assert!(info.header("change-id").is_some() && info.header("lonca-session") == Some("s1"));

    // Out of scope: refused, and the refusal is in the log.
    e.wrote(&token, "docs/x.md");
    let r = e.call("lease.acquire", None, Some(&token), json!({"items": [{"symbol": "docs/x.md#<file>", "kind": "edit"}], "intent": "x", "ttl_ms": 1000})).unwrap();
    assert_eq!(r["decision"]["outcome"], "deny");
    let denied_seq = r["seq"].as_u64().unwrap();
    let ops = OpLog::new(&store).read_all().unwrap();
    assert_eq!(
        ops[denied_seq as usize].entry.decision.outcome,
        Outcome::Deny
    );
    verify_chain(&ops).unwrap();

    // Push trunk and the log to a plain Git remote.
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
    assert_eq!(git(&remote, &["rev-parse", "refs/heads/main"]), trunk.0);
    let remote_store = Store::open(&remote).unwrap();
    let remote_ops = OpLog::new(&remote_store).read_all().unwrap();
    verify_chain(&remote_ops).unwrap();
    assert!(
        matches!(remote_ops.last().unwrap().entry.op, Op::BridgePush { .. }),
        "the anchor itself is pushed"
    );
    // Plain git sees the change id header, like jj writes it.
    let raw = git(&remote, &["cat-file", "-p", &trunk.0]);
    assert!(raw.lines().any(|l| l.starts_with("change-id ")), "{raw}");
}

#[test]
fn restart_rebuilds_state_and_keeps_tokens() {
    let mut e = Env::new();
    e.init(None);
    let token = e.session("s1", &["src/**"]);
    e.lease(&token, "src/lib.rs#charge");
    let before = e.ok("status", Some("demo"), None, json!({}));
    e.reopen();
    let after = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(before["next_seq"], after["next_seq"]);
    assert_eq!(before["head_hash"], after["head_hash"]);
    assert_eq!(after["leases"].as_array().unwrap().len(), 1);
    let who = e.ok("whoami", None, Some(&token), json!({}));
    assert_eq!(who["actor"], "agent:bot-s1/s1");

    // Leases and sessions expire on the daemon's clock, across restarts too.
    e.advance(11 * 60_000);
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert!(s["leases"].as_array().unwrap().is_empty());
    e.advance(60 * 60_000);
    let r = e.call("lease.acquire", None, Some(&token), json!({"items": [{"symbol": "src/a.rs#f", "kind": "edit"}], "intent": "x", "ttl_ms": 1000})).unwrap();
    assert_eq!(r["decision"]["reasons"][0], "session_inactive");
}

#[test]
fn refs_changed_behind_the_daemon_are_logged_and_restored() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("a.txt", "one\n")], "seed");
    e.svc.process_all();
    let trunk = e.trunk();
    let store = e.store();
    let blob = store.write_blob(b"evil\n").unwrap();
    let mut files = lonca_core::FileMap::new();
    files.insert(
        "a.txt".into(),
        lonca_core::FileEntry {
            mode: lonca_core::FileMode::Regular,
            blob,
        },
    );
    let tree = store.write_tree(&files).unwrap();
    let evil = store
        .write_commit(&lonca_core::store::CommitSpec {
            tree,
            parents: vec![trunk.clone()],
            author_name: "x".into(),
            author_email: "x@y".into(),
            time_ms: 0,
            message: "sneaky\n".into(),
            headers: vec![],
        })
        .unwrap();
    git(
        &e.root,
        &[
            "--git-dir",
            store.path().to_str().unwrap(),
            "update-ref",
            "refs/heads/main",
            &evil.0,
        ],
    );
    e.svc.reconcile_all();
    assert_eq!(
        store.ref_get("refs/heads/main").unwrap(),
        Some(trunk.clone()),
        "restored"
    );
    let ops = OpLog::new(&store).read_all().unwrap();
    assert!(
        ops.iter().any(
            |o| matches!(&o.entry.op, Op::ImportUnmediated { found: Some(f), .. } if *f == evil)
        )
    );

    // Touching the policy ref also freezes the repository.
    git(
        &e.root,
        &[
            "--git-dir",
            store.path().to_str().unwrap(),
            "update-ref",
            "refs/lonca/policy",
            &evil.0,
        ],
    );
    e.svc.reconcile_all();
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert!(s["frozen"].as_str().unwrap().contains("refs/lonca/policy"));
}

#[test]
fn tainted_session_goes_through_a_human_then_integrates() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    let ws = e.root.join("ws");
    let v = e.ok(
        "hook.event",
        None,
        Some(&token),
        json!({"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": "https://evil.example/issue"}, "workspace": ws}),
    );
    assert_eq!(v["decision"], "allow");
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, "src/lib.rs#refund");
    let new = LIB.replace(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        "pub fn refund(a: u64) -> u64 {\n    0\n",
    );
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &new)],
        &["src/lib.rs#refund"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    assert_eq!(e.svc.process_all(), 0, "nothing integrates before review");
    let seq = r["seq"].as_u64().unwrap();
    let r = e.human(Op::Approve {
        target_seq: seq,
        note: "reviewed".into(),
    });
    assert!(
        r["decision"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "released")
    );
    assert_eq!(e.svc.process_all(), 1);
    let trunk = e.trunk();
    assert_eq!(
        e.store().read_file(&trunk, "src/lib.rs").unwrap().unwrap(),
        new.as_bytes()
    );
}

#[test]
fn changes_by_different_agents_merge_and_same_symbol_conflicts() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let a = e.session("a", &["src/**"]);
    let b = e.session("b", &["src/**"]);
    for t in [&a, &b] {
        e.bind(t);
        e.wrote(t, "src/lib.rs");
    }
    e.lease(&a, "src/lib.rs#charge");
    e.lease(&b, "src/lib.rs#refund");
    let va = LIB.replacen("    a\n", "    a + 1\n", 1);
    let vb = LIB.replace(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        "pub fn refund(a: u64) -> u64 {\n    a - 1\n",
    );
    e.propose(
        &a,
        &base,
        vec![file("src/lib.rs", &va)],
        &["src/lib.rs#charge"],
    );
    e.propose(
        &b,
        &base,
        vec![file("src/lib.rs", &vb)],
        &["src/lib.rs#refund"],
    );
    assert_eq!(e.svc.process_all(), 2);
    let merged = String::from_utf8(
        e.store()
            .read_file(&e.trunk(), "src/lib.rs")
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert!(
        merged.contains("a + 1") && merged.contains("a - 1"),
        "{merged}"
    );

    // A human edits charge directly while the agent's change on charge is in flight.
    let base2 = e.trunk();
    e.lease(&a, "src/lib.rs#charge");
    let agent_version = merged.replace("a + 1", "a + 2");
    let r = e.propose(
        &a,
        &base2,
        vec![file("src/lib.rs", &agent_version)],
        &["src/lib.rs#charge"],
    );
    let change: ChangeId = serde_json::from_value(r["change"].clone()).unwrap();
    // Integrate the human change first by withdrawing nothing: queue order is
    // FIFO, so propose the human change on a fresh base and process later.
    let human_version = merged.replace("a + 1", "a + 3");
    e.human_change(vec![file("src/lib.rs", &human_version)], "human fix");
    e.svc.process_all();
    let st = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(
        st["status"]["status"], "integrated",
        "agent change first (FIFO)"
    );
    let s = e.ok("status", Some("demo"), None, json!({}));
    let human_change = s["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["intent"] == "human fix")
        .unwrap();
    assert_eq!(human_change["status"]["status"], "conflicted");
    assert_eq!(human_change["status"]["symbols"][0], "src/lib.rs#charge");
}

#[test]
fn failing_verification_rejects_and_keeps_trunk() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(
        vec![
            file("src/lib.rs", LIB),
            file("check.sh", "grep -q 'a \\* 2' src/lib.rs\n"),
        ],
        "seed",
    );
    e.svc.process_all();
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "# test = \"cargo test --offline\"",
        "test = \"sh check.sh\"",
    );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");

    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, "src/lib.rs#charge");
    let base = e.trunk();
    let bad = LIB.replacen("    a\n", "    a * 3\n", 1);
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &bad)],
        &["src/lib.rs#charge"],
    );
    let change = r["change"].clone();
    e.svc.process_all();
    assert_eq!(e.trunk(), base);
    let c = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(c["status"]["status"], "rejected");
    assert!(
        c["status"]["reasons"][0]
            .as_str()
            .unwrap()
            .starts_with("verification_failed:tests")
    );

    let good = LIB.replacen("    a\n", "    a * 2\n", 1);
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &good)],
        &["src/lib.rs#charge"],
    );
    assert_eq!(r["decision"]["outcome"], "allow");
    e.svc.process_all();
    assert_ne!(e.trunk(), base);
}

#[test]
fn import_existing_repository_and_fast_forward_pulls() {
    let mut e = Env::new();
    let up = e.root.join("upstream");
    std::fs::create_dir_all(&up).unwrap();
    git(&up, &["init", "-q", "-b", "main"]);
    git(&up, &["config", "user.email", "t@t"]);
    git(&up, &["config", "user.name", "t"]);
    std::fs::write(up.join("README.md"), "hello\n").unwrap();
    git(&up, &["add", "."]);
    git(&up, &["commit", "-q", "-m", "first"]);
    e.init(Some(up.to_str().unwrap()));
    let trunk = e.trunk();
    assert_eq!(trunk.0, git(&up, &["rev-parse", "HEAD"]));

    std::fs::write(up.join("README.md"), "hello again\n").unwrap();
    git(&up, &["commit", "-q", "-am", "second"]);
    let prep = e.ok(
        "human.prepare_import",
        Some("demo"),
        None,
        json!({"remote": up}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    assert_eq!(e.trunk().0, git(&up, &["rev-parse", "HEAD"]));

    // Remotes that could run commands are refused.
    for bad in [
        "ext::sh -c touch% /tmp/x",
        "--upload-pack=touch /tmp/x",
        "relative/path",
    ] {
        assert!(
            e.call(
                "human.prepare_import",
                Some("demo"),
                None,
                json!({"remote": bad})
            )
            .is_err(),
            "{bad}"
        );
    }
}

#[test]
fn agents_can_not_forge_human_operations_or_use_other_tokens() {
    let mut e = Env::new();
    e.init(None);
    let token = e.session("s1", &["src/**"]);
    assert!(
        e.call("whoami", None, Some("lonca_not_a_token"), json!({}))
            .is_err()
    );
    // A signature by a key that is not enrolled.
    let op = Op::Freeze { reason: "x".into() };
    let fake = KeyPair::generate();
    let body = json!({"op": op, "sig": sign_ed25519(&fake, "ayse", "demo", &op, e.now())});
    let r = e.ok("human.submit", Some("demo"), None, body);
    assert_eq!(r["decision"]["outcome"], "deny");
    assert_eq!(r["decision"]["reasons"][0], "bad_human_signature");
    // Revocation kills the token.
    e.human(Op::CapRevoke {
        session: "s1".into(),
        reason: "done".into(),
    });
    assert_eq!(
        e.call("whoami", None, Some(&token), json!({}))
            .unwrap_err()
            .0,
        "unauthenticated"
    );
}

#[test]
fn real_socket_round_trip() {
    let e = Env::new();
    let sock = e.root.join("home/lonca.sock");
    let listener = lonca_daemon::server::bind(&sock).unwrap();
    let svc = e.svc.clone();
    std::thread::spawn(move || lonca_daemon::server::serve(listener, svc));
    let mut c = lonca_daemon::Client::connect(&sock).unwrap();
    let r = c.call("ping", json!({})).unwrap();
    assert_eq!(r["daemon_key"], e.svc.public_key());
    assert_eq!(
        c.call("nope", json!({})).unwrap_err().0.code,
        "unknown_method"
    );
    assert!(
        lonca_daemon::server::bind(&sock).is_err(),
        "second daemon refused"
    );
}
