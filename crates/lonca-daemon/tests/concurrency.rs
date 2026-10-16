//! Phase 2 criterion: twenty agents work on different functions of the same
//! file at the same time, over the real socket. No update may be lost and
//! every trunk state must have passed verification.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::ops::{CheckKind, CheckResult};

const AGENTS: usize = 20;

fn source() -> String {
    let mut s = String::new();
    for i in 0..AGENTS {
        s.push_str(&format!(
            "pub fn f{i}(x: u64) -> u64 {{\n    x + {i}\n}}\n\n"
        ));
    }
    s
}

#[test]
fn twenty_agents_one_file_no_lost_updates() {
    let mut e = Env::new();
    e.init(None);
    // Verification: the merged file must still define every original function.
    let config = lonca_policy::config::DEFAULT_CONFIG
        .replace("required = false", "required = true")
        .replace(
            "# test = \"cargo test --offline\"",
            "test = \"test $(grep -c '^pub fn f' src/lib.rs) -eq 20\"",
        );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    e.human_change(vec![file("src/lib.rs", &source())], "twenty functions");
    e.svc.process_all();
    let base = e.trunk();

    let tokens: Vec<String> = (0..AGENTS)
        .map(|i| {
            let t = e.session(&format!("a{i}"), &["src/**"]);
            e.bind(&t);
            e.wrote(&t, "src/lib.rs");
            t
        })
        .collect();

    let sock = e.root.join("s");
    let listener = lonca_daemon::server::bind(&sock).unwrap();
    let svc = e.svc.clone();
    std::thread::spawn(move || lonca_daemon::server::serve(listener, svc));
    let worker = e.svc.spawn_worker();
    drop(worker);

    let started = std::time::Instant::now();
    let handles: Vec<_> = tokens
        .into_iter()
        .enumerate()
        .map(|(i, token)| {
            let sock = sock.clone();
            let base = base.clone();
            std::thread::spawn(move || {
                let mut c = lonca_daemon::Client::connect(&sock).unwrap();
                c.token = Some(token);
                let items = json!([
                    {"symbol": format!("src/lib.rs#f{i}"), "kind": "edit"},
                    {"symbol": "src/lib.rs#<file>", "kind": "insert"}
                ]);
                let r = c
                    .call(
                        "lease.acquire",
                        json!({"items": items, "intent": format!("agent {i}"), "ttl_ms": 600_000}),
                    )
                    .unwrap();
                assert_eq!(r["decision"]["outcome"], "allow", "agent {i}: {r}");
                let mut text =
                    source().replace(&format!("    x + {i}\n"), &format!("    x * {i} + 1\n"));
                text.push_str(&format!("pub fn new{i}() -> u64 {{\n    {i}\n}}\n"));
                let claim = Claim {
                    intent: format!("agent {i}"),
                    edits: vec![format!("src/lib.rs#f{i}")],
                    adds: vec![format!("src/lib.rs#new{i}")],
                    ..Default::default()
                };
                let r = c
                    .call(
                        "change.propose",
                        json!({"base": base, "files": [file("src/lib.rs", &text)], "claim": claim}),
                    )
                    .unwrap();
                assert_eq!(r["decision"]["outcome"], "allow", "agent {i}: {r}");
                serde_json::from_value::<ChangeId>(r["change"].clone()).unwrap()
            })
        })
        .collect();
    let changes: Vec<ChangeId> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Wait for the worker to drain the queue.
    for _ in 0..600 {
        let s = e.ok("status", Some("demo"), None, json!({}));
        if s["queue"].as_array().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!("20 proposals integrated in {:?}", started.elapsed());

    for (i, ch) in changes.iter().enumerate() {
        let c = e.ok("change.get", Some("demo"), None, json!({"change": ch}));
        assert_eq!(c["status"]["status"], "integrated", "agent {i}: {c}");
    }
    let trunk = e.trunk();
    let text =
        String::from_utf8(e.store().read_file(&trunk, "src/lib.rs").unwrap().unwrap()).unwrap();
    for i in 0..AGENTS {
        assert!(
            text.contains(&format!("    x * {i} + 1\n")),
            "edit of agent {i} lost"
        );
        assert!(
            text.contains(&format!("pub fn new{i}() -> u64")),
            "addition of agent {i} lost"
        );
    }
    let parsed = lonca_symbols::parse(lonca_symbols::Lang::Rust, &text);
    assert!(!parsed.has_error);
    assert_eq!(parsed.syms.len(), 2 * AGENTS);

    // Every integration carries passing syntax and test evidence.
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let integrations: Vec<_> = ops
        .iter()
        .filter(|o| matches!(o.entry.op, Op::ChangeIntegrate { .. }))
        .collect();
    assert_eq!(
        integrations
            .iter()
            .filter(|o| o.entry.decision.is_allow())
            .count(),
        AGENTS + 1
    );
    for o in integrations
        .iter()
        .filter(|o| o.entry.actor == lonca_core::ops::Actor::Daemon && o.entry.decision.is_allow())
    {
        for k in [CheckKind::Syntax, CheckKind::Tests] {
            let a = o
                .entry
                .evidence
                .iter()
                .find(|a| a.check == k)
                .unwrap_or_else(|| panic!("op {} lacks {k:?}", o.entry.seq));
            assert_eq!(a.result, CheckResult::Pass);
        }
    }
    // Linear history: 20 agent commits on top of the seed.
    let store = e.store();
    let mut n = 0;
    let mut cur = Some(trunk);
    while let Some(c) = cur {
        let info = store.read_commit(&c).unwrap();
        assert!(info.parents.len() <= 1);
        cur = info.parents.into_iter().next();
        n += 1;
    }
    assert_eq!(n, AGENTS + 2, "initial + seed + 20");

    let r = audit(&store, Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}
