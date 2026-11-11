//! Every request is authenticated (issue #51): no anonymous reads,
//! prepares or queue runs; agent tokens read their own repository only;
//! human sessions come from a presence signature and follow the key.

mod common;
use common::*;

use lonca_core::canonical::sha256_hex;
use lonca_daemon::service::{HUMAN_SESSION_DEFAULT_MS, HUMAN_SESSION_MAX_MS};

fn code(r: Result<Value, (String, String)>) -> String {
    r.map(|v| format!("ok: {v}")).unwrap_err().0
}

fn login_as(
    e: &mut Env,
    key: &KeyPair,
    human: &str,
    repo: Option<&str>,
) -> Result<Value, (String, String)> {
    let sig = sign_login_ed25519(key, human, repo, HUMAN_SESSION_DEFAULT_MS, e.now());
    e.anon("human.login", repo, None, json!({"sig": sig}))
}

#[test]
fn without_a_token_nothing_but_ping_answers() {
    let mut e = Env::new();
    e.init(None);
    let trunk = e.trunk();
    let anon = [
        ("status", json!({})),
        ("log", json!({})),
        ("tree", json!({"commit": trunk, "with_content": true})),
        ("change.get", json!({"change": ChangeId::random()})),
        ("human.prepare_import", json!({"remote": "/nowhere"})),
        (
            "human.prepare_change",
            json!({"base": trunk, "files": [], "author": "ayse"}),
        ),
        ("human.prepare_policy", json!({"config": "", "policy": ""})),
        ("human.prepare_push", json!({"remote": "/nowhere"})),
        ("repo.backup", json!({})),
        ("queue.run", json!({})),
        ("repo.list", json!({})),
        ("daemon.prepare_rotate", json!({})),
        ("whoami", json!({})),
    ];
    for (m, p) in anon {
        assert_eq!(
            code(e.anon(m, Some("demo"), None, p)),
            "unauthenticated",
            "{m}"
        );
    }
    let op = Op::Freeze { reason: "x".into() };
    let body = e.sign(&op);
    assert_eq!(
        code(e.anon("human.submit", Some("demo"), None, body)),
        "unauthenticated"
    );
    // Recovery is the one submission that goes in on its signature alone:
    // the key that would sign in is the lost one. A bad signature is
    // denied by decide(), like before, and leaves no entry: whoever can
    // open the socket could send one.
    let rec = KeyPair::generate();
    e.human(Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: rec.public_hex(),
        },
    });
    let fresh = KeyPair::generate();
    let op = Op::HumanRecover {
        human: "ayse".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: fresh.public_hex(),
        },
    };
    let forged = json!({"op": op, "sig": sign_ed25519(&KeyPair::generate(), "ayse", "demo", &op, e.now(), e.head("demo"))});
    let (c, why) = e
        .anon("human.submit", Some("demo"), None, forged)
        .unwrap_err();
    assert_eq!(c, "forbidden");
    assert!(why.contains("bad_human_signature"), "{why}");
    let body =
        json!({"op": op, "sig": sign_ed25519(&rec, "ayse", "demo", &op, e.now(), e.head("demo"))});
    let r = e.anon("human.submit", Some("demo"), None, body).unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    e.human = fresh;
    // Not even a denied entry was logged for the unauthenticated submit.
    let log = e.ok("log", Some("demo"), None, json!({}));
    assert!(
        log.as_array()
            .unwrap()
            .iter()
            .all(|o| o["entry"]["op"]["kind"] != "freeze"),
        "{log}"
    );
    assert!(e.anon("ping", None, None, json!({})).is_ok());
    // A second repository can not be prepared anonymously once one exists.
    let key = HumanKey {
        alg: "ed25519".into(),
        public: e.human.public_hex(),
    };
    let params = json!({"repo": "other", "human": "ayse", "human_key": key});
    assert_eq!(
        code(e.anon("repo.prepare_init", None, None, params.clone())),
        "unauthenticated"
    );
    assert_eq!(
        code(e.anon(
            "repo.restore",
            None,
            None,
            json!({"repo": "other", "from": "/nowhere"})
        )),
        "unauthenticated"
    );
    // With the human's session it can.
    let prep = e.ok("repo.prepare_init", None, None, params);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    let body = json!({"op": op, "sig": sign_ed25519(&e.human, "ayse", "other", &op, e.now(), e.head("other"))});
    let r = e.ok("repo.init", None, None, body);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let mut list = e.ok("repo.list", None, None, json!({}));
    list.as_array_mut().unwrap().sort_by_key(|v| v.to_string());
    assert_eq!(list, json!(["demo", "other"]));
}

#[test]
fn an_agent_token_reads_its_own_repository_only() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let trunk = e.trunk();
    let token = e.session("s1", &["src/**"]);
    // Own repository: with or without naming it.
    let s = e.ok("status", None, Some(&token), json!({}));
    assert_eq!(s["repo"], "demo");
    let s = e.ok("status", Some("demo"), Some(&token), json!({}));
    assert_eq!(s["repo"], "demo");
    assert!(
        e.ok("log", None, Some(&token), json!({}))
            .as_array()
            .is_some()
    );
    let files = e.ok("tree", None, Some(&token), json!({"commit": trunk}));
    assert_eq!(files[0]["path"], "src/lib.rs");
    // Another repository, existing or not, is forbidden the same way.
    for other in ["other", "no-such-repo"] {
        for (m, p) in [
            ("status", json!({})),
            ("log", json!({})),
            ("tree", json!({"commit": trunk})),
            ("change.get", json!({"change": ChangeId::random()})),
        ] {
            assert_eq!(
                code(e.anon(m, Some(other), Some(&token), p)),
                "forbidden",
                "{m} on {other}"
            );
        }
    }
    // Human methods are not for agents, however the repository is named.
    for (m, p) in [
        ("human.prepare_push", json!({"remote": "/nowhere"})),
        ("repo.backup", json!({})),
        ("queue.run", json!({})),
        ("repo.list", json!({})),
        (
            "repo.prepare_init",
            json!({"repo": "x", "human": "ayse", "human_key": {"alg": "ed25519", "public": e.human.public_hex()}}),
        ),
        ("daemon.prepare_rotate", json!({})),
    ] {
        assert_eq!(
            code(e.anon(m, Some("demo"), Some(&token), p)),
            "forbidden",
            "{m}"
        );
    }
    let op = Op::Freeze { reason: "x".into() };
    let body = e.sign(&op);
    assert_eq!(
        code(e.anon("human.submit", Some("demo"), Some(&token), body)),
        "forbidden"
    );
    assert_eq!(
        code(e.anon("human.logout", None, Some(&token), json!({}))),
        "forbidden"
    );
    assert!(e.anon("whoami", None, Some(&token), json!({})).is_ok());
}

#[test]
fn a_human_session_opens_with_a_presence_signature_and_follows_the_key() {
    let mut e = Env::new();
    e.init(None);
    let key = e.human.clone();

    // Wrong key, wrong name, wrong repository, stale, replayed, too long.
    let stranger = KeyPair::generate();
    let r = login_as(&mut e, &stranger, "ayse", Some("demo")).unwrap_err();
    assert_eq!(r.0, "unauthenticated", "{r:?}");
    assert_eq!(
        code(login_as(&mut e, &key, "bora", Some("demo"))),
        "unauthenticated"
    );
    assert_eq!(
        code(login_as(&mut e, &key, "ayse", Some("other"))),
        "unauthenticated"
    );
    assert_eq!(
        code(login_as(&mut e, &key, "ayse/..", None)),
        "unauthenticated"
    );
    let sig = sign_login_ed25519(
        &key,
        "ayse",
        None,
        HUMAN_SESSION_DEFAULT_MS,
        e.now() - 11 * 60_000,
    );
    let r = e
        .anon("human.login", None, None, json!({"sig": sig}))
        .unwrap_err();
    assert_eq!(
        r,
        ("unauthenticated".into(), "stale_human_signature".into())
    );
    let sig = sign_login_ed25519(&key, "ayse", None, HUMAN_SESSION_MAX_MS + 1, e.now());
    assert_eq!(
        code(e.anon(
            "human.login",
            None,
            None,
            json!({"sig": sig, "ttl_ms": HUMAN_SESSION_MAX_MS + 1})
        )),
        "invalid"
    );
    let sig = sign_login_ed25519(&key, "ayse", None, 0, e.now());
    assert_eq!(
        code(e.anon("human.login", None, None, json!({"sig": sig, "ttl_ms": 0}))),
        "invalid"
    );
    // The signature of a login is not an operation signature.
    let sig = sign_login_ed25519(
        &key,
        "ayse",
        Some("demo"),
        HUMAN_SESSION_DEFAULT_MS,
        e.now(),
    );
    let op = Op::Freeze { reason: "x".into() };
    let r = e.ok(
        "human.submit",
        Some("demo"),
        None,
        json!({"op": op, "sig": sig}),
    );
    assert_eq!(r["decision"]["reasons"][0], "bad_human_signature", "{r}");

    // A good login, named repository or not; the token is a hash on disk.
    let sig = sign_login_ed25519(
        &key,
        "ayse",
        Some("demo"),
        HUMAN_SESSION_DEFAULT_MS,
        e.now(),
    );
    let r = e.ok(
        "human.login",
        Some("demo"),
        None,
        json!({"sig": sig.clone()}),
    );
    let t = r["token"].as_str().unwrap().to_string();
    assert!(t.starts_with("lonca_h_"), "{t}");
    assert_eq!(r["human"], "ayse");
    assert_eq!(
        r["expires_ms"].as_i64().unwrap(),
        e.now() - 1 + HUMAN_SESSION_DEFAULT_MS
    );
    let tokens = std::fs::read_to_string(e.root.join("home/tokens.json")).unwrap();
    assert!(
        !tokens.contains(&t) && tokens.contains(&sha256_hex(t.as_bytes())),
        "{tokens}"
    );
    // Replaying the same signature does not open a second session, now
    // or at any point while the signature is still fresh.
    assert_eq!(
        code(e.anon(
            "human.login",
            Some("demo"),
            None,
            json!({"sig": sig.clone()})
        )),
        "unauthenticated"
    );
    e.advance(9 * 60_000 + 30_000);
    let r = e
        .anon(
            "human.login",
            Some("demo"),
            None,
            json!({"sig": sig.clone()}),
        )
        .unwrap_err();
    assert_eq!(r.1, "login signature already used", "{r:?}");
    e.advance(60_000 + 1);
    let r = e
        .anon("human.login", Some("demo"), None, json!({"sig": sig}))
        .unwrap_err();
    assert_eq!(r.1, "stale_human_signature", "{r:?}");
    let who = e.ok("whoami", None, Some(&t), json!({}));
    assert_eq!(who["actor"], "human:ayse");
    assert_eq!(who["repos"], json!(["demo"]));
    let trunk = e.trunk();
    assert!(e.anon("status", Some("demo"), Some(&t), json!({})).is_ok());
    assert!(e.anon("log", Some("demo"), Some(&t), json!({})).is_ok());
    assert!(
        e.anon("tree", Some("demo"), Some(&t), json!({"commit": trunk}))
            .is_ok()
    );
    assert_eq!(code(e.anon("status", None, Some(&t), json!({}))), "invalid");
    assert_eq!(
        code(e.anon("status", Some("other"), Some(&t), json!({}))),
        "forbidden"
    );
    assert_eq!(
        code(e.anon(
            "lease.acquire",
            None,
            Some(&t),
            json!({"items": [], "intent": "x", "ttl_ms": 1})
        )),
        "forbidden"
    );
    assert_eq!(
        code(e.anon("whoami", None, Some("lonca_h_nope"), json!({}))),
        "unauthenticated"
    );

    // A session submits only what its own human signed.
    let bora = KeyPair::generate();
    e.human(Op::HumanEnroll {
        human: "bora".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: bora.public_hex(),
        },
    });
    let op = Op::Freeze { reason: "x".into() };
    let by_bora =
        json!({"op": op, "sig": sign_ed25519(&bora, "bora", "demo", &op, e.now(), e.head("demo"))});
    assert_eq!(
        code(e.anon("human.submit", Some("demo"), Some(&t), by_bora.clone())),
        "forbidden"
    );
    let tb = login_as(&mut e, &bora, "bora", None).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let r = e
        .anon("human.submit", Some("demo"), Some(&tb), by_bora)
        .unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");

    // Expiry ends it; logout ends it; a rotated key ends it everywhere.
    e.advance(HUMAN_SESSION_DEFAULT_MS);
    assert_eq!(
        code(e.anon("status", Some("demo"), Some(&t), json!({}))),
        "unauthenticated"
    );
    let t = login_as(&mut e, &key, "ayse", None).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(e.anon("status", Some("demo"), Some(&t), json!({})).is_ok());
    assert_eq!(
        e.anon("human.logout", None, Some(&t), json!({})).unwrap(),
        json!({"ended": true})
    );
    assert_eq!(
        code(e.anon("human.logout", None, Some(&t), json!({}))),
        "unauthenticated"
    );
    assert_eq!(
        code(e.anon("status", Some("demo"), Some(&t), json!({}))),
        "unauthenticated"
    );
    assert_eq!(
        code(e.anon("human.logout", None, None, json!({}))),
        "invalid"
    );
    let t = login_as(&mut e, &key, "ayse", None).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    let fresh = KeyPair::generate();
    e.human(Op::HumanRotate {
        human: "ayse".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: fresh.public_hex(),
        },
    });
    assert_eq!(
        code(e.anon("status", Some("demo"), Some(&t), json!({}))),
        "forbidden"
    );
    assert_eq!(
        code(e.anon("repo.list", None, Some(&t), json!({}))),
        "forbidden"
    );
    assert_eq!(
        code(login_as(&mut e, &key, "ayse", None)),
        "unauthenticated"
    );
    let t = login_as(&mut e, &fresh, "ayse", None).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    assert!(e.anon("status", Some("demo"), Some(&t), json!({})).is_ok());
    // The session survives a daemon restart, like agent tokens.
    e.reopen();
    assert!(e.anon("status", Some("demo"), Some(&t), json!({})).is_ok());
}

#[test]
fn a_fresh_daemon_bootstraps_without_a_session_and_then_closes() {
    let mut e = Env::new();
    assert_eq!(
        e.anon("repo.list", None, None, json!({})).unwrap_err().0,
        "unauthenticated"
    );
    let key = HumanKey {
        alg: "ed25519".into(),
        public: e.human.public_hex(),
    };
    // Preparing (not initializing) a repository is not yet a repository.
    let prep = e
        .anon(
            "repo.prepare_init",
            None,
            None,
            json!({"repo": "demo", "human": "ayse", "human_key": key.clone()}),
        )
        .unwrap();
    let prep2 = e.anon(
        "repo.prepare_init",
        None,
        None,
        json!({"repo": "demo", "human": "ayse", "human_key": key}),
    );
    assert!(prep2.is_ok(), "{prep2:?}");
    let op: Op = serde_json::from_value(prep2.unwrap()["op"].clone()).unwrap();
    let _ = prep;
    let body = json!({"op": op, "sig": sign_ed25519(&e.human, "ayse", "demo", &op, e.now(), e.head("demo"))});
    assert_eq!(
        e.anon("repo.init", None, None, body).unwrap()["decision"]["outcome"],
        "allow"
    );
    // Closed now.
    assert_eq!(
        code(e.anon("repo.init", None, None, json!({"op": Op::Freeze { reason: "x".into() }, "sig": e.sign(&Op::Freeze { reason: "x".into() })["sig"]}))),
        "unauthenticated"
    );
}

/// A human signature names the head of the log (`log.head`, which anyone
/// may ask), and one that names none, or an entry of another log, is a
/// recorded denial.
#[test]
fn a_signature_names_the_head_of_the_log() {
    let mut e = Env::new();
    e.init(None);
    let head = e.anon("log.head", Some("demo"), None, json!({})).unwrap();
    let at: LogPoint = serde_json::from_value(head["at"].clone()).unwrap();
    let status = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(json!(at.seq + 1), status["next_seq"]);
    assert_eq!(json!(at.hash), status["head_hash"]);
    assert_eq!(
        code(e.anon("log.head", Some("nowhere"), None, json!({}))),
        "not_found"
    );

    let op = Op::Freeze { reason: "x".into() };
    let reasons = |e: &mut Env, at: Option<LogPoint>| {
        let sig = sign_ed25519(&e.human, "ayse", "demo", &op, e.now(), at);
        let r = e.ok(
            "human.submit",
            Some("demo"),
            None,
            json!({"op": op, "sig": sig}),
        );
        assert_eq!(r["decision"]["outcome"], "deny", "{r}");
        r["decision"]["reasons"].clone()
    };
    assert_eq!(reasons(&mut e, None), json!(["unanchored_human_signature"]));
    let elsewhere = LogPoint {
        seq: at.seq,
        hash: "0".repeat(64),
    };
    assert_eq!(
        reasons(&mut e, Some(elsewhere)),
        json!(["human_signature_of_another_log"])
    );
    // The head moved by those two denials; the one asked for now holds.
    let r = e.human(op.clone());
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}
