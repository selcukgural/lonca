//! Human key rotation, revocation and recovery through the daemon: the
//! tokens of every ended session stop working, and the log still audits.

mod common;
use common::*;

use lonca_audit::{Options, audit};

fn file_key(k: &KeyPair) -> HumanKey {
    HumanKey {
        alg: "ed25519".into(),
        public: k.public_hex(),
    }
}

fn refused(e: &mut Env, token: &str) -> String {
    let err = e.call("whoami", None, Some(token), json!({})).unwrap_err();
    assert_eq!(err.0, "unauthenticated", "{err:?}");
    err.1
}

/// Sessions (by id) that still have a token on disk.
fn sessions_with_tokens(e: &Env) -> Vec<String> {
    let text = std::fs::read_to_string(e.root.join("home/tokens.json")).unwrap();
    let map: serde_json::Map<String, Value> = serde_json::from_str(&text).unwrap();
    map.values()
        .map(|v| v["session"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn rotation_and_recovery_end_tokens_and_the_log_audits() {
    let mut e = Env::new();
    e.init(None);
    let t1 = e.session("s1", &["src/**"]);
    e.ok("whoami", None, Some(&t1), json!({}));

    let new = KeyPair::generate();
    let r = e.human(Op::HumanRotate {
        human: "ayse".into(),
        key: file_key(&new),
    });
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    refused(&mut e, &t1);
    assert!(sessions_with_tokens(&e).is_empty());
    // The old key is refused from now on.
    let r = e.human(Op::Freeze { reason: "x".into() });
    assert_eq!(r["decision"]["reasons"][0], "bad_human_signature");
    e.human = new;

    let t2 = e.session("s2", &["src/**"]);
    let rec = KeyPair::generate();
    let r = e.human(Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: file_key(&rec),
    });
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let newer = KeyPair::generate();
    let op = Op::HumanRecover {
        human: "ayse".into(),
        key: file_key(&newer),
    };
    let body = json!({"op": op, "sig": sign_ed25519(&rec, "ayse", "demo", &op, e.now())});
    let r = e.ok("human.submit", Some("demo"), None, body);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    refused(&mut e, &t2);
    e.human = newer;
    e.session("s3", &["src/**"]);
    assert_eq!(sessions_with_tokens(&e), ["s3"]);

    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
    e.reopen();
    refused(&mut e, &t2);
}

#[test]
fn a_revocation_released_by_approval_drops_the_tokens() {
    let mut e = Env::new();
    e.init(None);
    let policy = format!(
        "{}\n@id(\"revoke-reviewed\")\n@escalate(\"revoke\")\n\
         forbid(principal, action == Lonca::Action::\"cap.revoke\", resource);\n",
        lonca_policy::config::DEFAULT_POLICY
    );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": lonca_policy::config::DEFAULT_CONFIG, "policy": policy}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let t1 = e.session("s1", &["src/**"]);
    let r = e.human(Op::CapRevoke {
        session: "s1".into(),
        reason: "done".into(),
    });
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    assert_eq!(sessions_with_tokens(&e), ["s1"]);
    let seq = r["seq"].as_u64().expect("seq");
    let r = e.human(Op::Approve {
        target_seq: seq,
        note: String::new(),
    });
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert!(sessions_with_tokens(&e).is_empty());
    refused(&mut e, &t1);
}

#[test]
fn a_leftover_token_of_an_ended_session_is_refused() {
    let mut e = Env::new();
    e.init(None);
    let t1 = e.session("s1", &["src/**"]);
    let tokens = e.root.join("home/tokens.json");
    let saved = std::fs::read(&tokens).unwrap();
    e.human(Op::CapRevoke {
        session: "s1".into(),
        reason: "done".into(),
    });
    // Even if the token survived (a crash between the log and the token
    // file), the ended session does not accept it.
    std::fs::write(&tokens, saved).unwrap();
    e.reopen();
    assert_eq!(sessions_with_tokens(&e), ["s1"]);
    assert_eq!(refused(&mut e, &t1), "session ended");
}
