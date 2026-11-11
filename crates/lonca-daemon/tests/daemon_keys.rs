//! Daemon key rotation and recovery through the daemon: the key files in
//! the home, repositories on different keys while a rotation is under way,
//! a repository whose daemon key is lost, and a forged key switch.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::oplog::OpEntry;
use lonca_core::ops::Actor;
use lonca_policy::chain::{Chain, Submission};
use lonca_policy::config::PolicyBundle;
use lonca_policy::state::State;

fn home(e: &Env) -> Home {
    Home::new(e.root.join("home"))
}

fn public_at(p: &Path) -> String {
    KeyPair::load(p, lonca_daemon::sys::current_uid())
        .unwrap()
        .public_hex()
}

fn init_repo(e: &mut Env, repo: &str) {
    let key = HumanKey {
        alg: "ed25519".into(),
        public: e.human.public_hex(),
    };
    let prep = e.ok(
        "repo.prepare_init",
        None,
        None,
        json!({"repo": repo, "human": "ayse", "human_key": key}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    let sig = sign_ed25519(&e.human, "ayse", repo, &op, e.now(), e.head(repo));
    let r = e.ok("repo.init", None, None, json!({"op": op, "sig": sig}));
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

fn submit_to(e: &mut Env, repo: &str, op: Op) -> Result<Value, (String, String)> {
    let sig = sign_ed25519(&e.human, "ayse", repo, &op, e.now(), e.head(repo));
    e.call(
        "human.submit",
        Some(repo),
        None,
        json!({"op": op, "sig": sig}),
    )
}

fn daemon_key_of(e: &mut Env, repo: &str) -> String {
    let s = e.ok("status", Some(repo), None, json!({}));
    s["daemon_key"].as_str().unwrap().to_string()
}

fn store_of(e: &Env, repo: &str) -> Store {
    Store::open(&e.root.join(format!("home/repos/{repo}.git"))).unwrap()
}

fn log_len(e: &Env) -> usize {
    OpLog::new(&e.store()).read_all().unwrap().len()
}

#[test]
fn a_rotation_moves_every_repository_then_replaces_the_key_file() {
    let mut e = Env::new();
    e.init(None);
    init_repo(&mut e, "other");
    let t1 = e.session("s1", &["src/**"]);
    let h = home(&e);
    let old = public_at(&h.key_path());

    let prep = e.ok("daemon.prepare_rotate", None, None, json!({}));
    let next = prep["key"].as_str().unwrap().to_string();
    assert_eq!(prep["repos"], json!(["demo", "other"]));
    assert_eq!(public_at(&h.next_key_path()), next);
    // Preparing again resumes with the same key.
    let again = e.ok("daemon.prepare_rotate", None, None, json!({}));
    assert_eq!(again["key"], json!(next));

    // Only to the prepared key.
    let elsewhere = Op::DaemonRotate {
        key: KeyPair::generate().public_hex(),
    };
    let err = submit_to(&mut e, "demo", elsewhere).unwrap_err();
    assert_eq!(err.0, "invalid", "{err:?}");

    let r = submit_to(&mut e, "demo", Op::DaemonRotate { key: next.clone() }).unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(daemon_key_of(&mut e, "demo"), next);
    assert_eq!(daemon_key_of(&mut e, "other"), old);
    // Sessions go on after a rotation, and the next entry is signed by
    // the new key.
    e.ok("whoami", None, Some(&t1), json!({}));
    e.lease(&t1, "src/lib.rs#charge");
    let ping = e.ok("ping", None, None, json!({}));
    assert_eq!(ping["daemon_key"], json!(old));
    assert_eq!(ping["next_key"], json!(next));
    let prep = e.ok("daemon.prepare_rotate", None, None, json!({}));
    assert_eq!(prep["repos"], json!(["other"]));

    // A restart in the middle opens each repository with its own key.
    e.reopen();
    e.ok("whoami", None, Some(&t1), json!({}));
    let r = submit_to(&mut e, "other", Op::DaemonRotate { key: next.clone() }).unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");

    // No repository is on the old key: the next key is the key now and
    // the old secret is gone.
    assert_eq!(public_at(&h.key_path()), next);
    assert!(!h.next_key_path().exists());
    let ping = e.ok("ping", None, None, json!({}));
    assert_eq!(ping["daemon_key"], json!(next));
    assert_eq!(ping["next_key"], Value::Null);
    e.reopen();
    e.lease(&t1, "src/lib.rs#refund");
    init_repo(&mut e, "third");
    assert_eq!(daemon_key_of(&mut e, "third"), next);

    for repo in ["demo", "other"] {
        let r = audit(&store_of(&e, repo), Options::default()).unwrap();
        assert!(r.ok(), "{repo}: {:#?}", r.findings);
        assert_eq!(r.key_switches.len(), 1, "{repo}");
        assert_eq!(r.key_switches[0].kind, "daemon.rotate");
        assert_eq!(r.key_switches[0].key, next);
        assert_eq!(r.key_switches[0].actor, "human:ayse");
    }
}

#[test]
fn a_crash_between_the_two_renames_keeps_the_next_key() {
    let mut e = Env::new();
    e.init(None);
    let h = home(&e);
    let next = e.ok("daemon.prepare_rotate", None, None, json!({}))["key"]
        .as_str()
        .unwrap()
        .to_string();
    let r = submit_to(&mut e, "demo", Op::DaemonRotate { key: next.clone() }).unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(public_at(&h.key_path()), next);
    // As if the daemon had stopped after deleting the old key but before
    // renaming the next one.
    std::fs::rename(h.key_path(), h.next_key_path()).unwrap();
    e.reopen();
    assert_eq!(public_at(&h.key_path()), next);
    assert!(!h.next_key_path().exists());
    assert_eq!(daemon_key_of(&mut e, "demo"), next);
}

#[test]
fn a_repository_whose_daemon_key_is_lost_is_recovered_by_a_human() {
    let mut e = Env::new();
    e.init(None);
    let t1 = e.session("s1", &["src/**"]);
    let h = home(&e);
    let old = public_at(&h.key_path());

    // A new machine: the stores came back from a remote, the key did not.
    std::fs::remove_file(h.key_path()).unwrap();
    e.reopen();
    let new = public_at(&h.key_path());
    assert_ne!(new, old);
    let err = e.call("status", Some("demo"), None, json!({})).unwrap_err();
    assert_eq!(err.0, "foreign_key", "{err:?}");
    assert!(
        err.1.contains("lonca daemon-key recover --repo demo"),
        "{err:?}"
    );
    let err = e.call("whoami", None, Some(&t1), json!({})).unwrap_err();
    assert_eq!(err.0, "unauthenticated", "{err:?}");
    let err = e
        .call(
            "repo.prepare_init",
            None,
            None,
            json!({"repo": "demo", "human": "ayse", "human_key": {"alg": "ed25519", "public": e.human.public_hex()}}),
        )
        .unwrap_err();
    assert_eq!(err.0, "conflict", "{err:?}");
    let err = submit_to(&mut e, "demo", Op::Freeze { reason: "x".into() }).unwrap_err();
    assert_eq!(err.0, "foreign_key", "{err:?}");

    // Refused without a log entry: another key than this daemon's, a
    // signature by a stranger.
    let before = log_len(&e);
    let other = Op::DaemonRecover {
        key: KeyPair::generate().public_hex(),
        recover: None,
    };
    let err = submit_to(&mut e, "demo", other).unwrap_err();
    assert_eq!(err.0, "invalid", "{err:?}");
    let op = Op::DaemonRecover {
        key: new.clone(),
        recover: None,
    };
    let forged = sign_ed25519(
        &KeyPair::generate(),
        "ayse",
        "demo",
        &op,
        e.now(),
        e.head("demo"),
    );
    let err = e
        .call(
            "human.submit",
            Some("demo"),
            None,
            json!({"op": op, "sig": forged}),
        )
        .unwrap_err();
    assert_eq!(err.0, "denied", "{err:?}");
    assert!(err.1.contains("bad_human_signature"), "{err:?}");
    assert_eq!(log_len(&e), before);

    let r = submit_to(&mut e, "demo", op).unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(daemon_key_of(&mut e, "demo"), new);
    let st = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(st["sessions"][0]["active"], json!(false), "{st}");
    e.human(Op::Freeze { reason: "x".into() });
    // Recovering a repository this daemon holds the key of is refused.
    let again = Op::DaemonRecover {
        key: KeyPair::generate().public_hex(),
        recover: None,
    };
    let err = submit_to(&mut e, "demo", again).unwrap_err();
    assert!(err.1.contains("use `lonca daemon-key rotate`"), "{err:?}");

    e.reopen();
    assert_eq!(daemon_key_of(&mut e, "demo"), new);
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
    assert_eq!(r.key_switches.len(), 1);
    assert_eq!(r.key_switches[0].kind, "daemon.recover");
}

/// The attack `replay_checked` exists for: with write access to the store
/// but no human key, re-anchor the log on your own key with a forged
/// recovery, append what you like, and rotate back to the daemon's key.
#[test]
fn a_forged_key_switch_in_the_store_stops_the_daemon_and_fails_the_audit() {
    let mut e = Env::new();
    e.init(None);
    let daemon = public_at(&home(&e).key_path());
    let store = e.store();
    let ops = OpLog::new(&store).read_all().unwrap();
    let attacker = KeyPair::generate();
    let policy = PolicyBundle::default_bundle();
    let mut state = State::replay(&ops);
    let mut head = OpLog::new(&store).head().unwrap();
    for op in [
        Op::DaemonRecover {
            key: attacker.public_hex(),
            recover: None,
        },
        Op::DaemonRotate {
            key: daemon.clone(),
        },
    ] {
        let t = state.last_time_ms + 1;
        let mut sub = Submission::new(
            Actor::Human {
                name: "ayse".into(),
            },
            op.clone(),
        );
        sub.human = Some(sign_ed25519(
            &attacker,
            "ayse",
            "demo",
            &op,
            t,
            e.head("demo"),
        ));
        let mut entry: OpEntry = Chain::from_state(attacker.clone(), state.clone())
            .prepare(sub, t, &policy)
            .entry;
        assert!(!entry.decision.is_allow());
        entry.decision = lonca_core::ops::Decision::allow();
        let signed = SignedOp::sign(entry, &attacker);
        head = Some(append_raw(&store, &signed, head.as_ref()));
        state.apply(&signed);
    }
    let ops = OpLog::new(&store).read_all().unwrap();
    assert!(verify_chain(&ops).is_ok(), "the chain alone accepts it");

    let opened = Service::open(home(&e), e.settings.clone(), Arc::new(|| T0));
    match opened {
        Ok(_) => panic!("the daemon opened a forged key switch"),
        Err(err) => assert!(
            err.to_string().contains("daemon.recover is not authorised"),
            "{err}"
        ),
    }
    let r = audit(&store, Options::default()).unwrap();
    let kinds: Vec<&str> = r.findings.iter().map(|f| f.kind.as_str()).collect();
    assert_eq!(kinds, ["daemon_key", "daemon_key"], "{:#?}", r.findings);
}

#[test]
fn a_genesis_prepared_before_the_rotation_ended_is_prepared_again() {
    let mut e = Env::new();
    e.init(None);
    let human_key = HumanKey {
        alg: "ed25519".into(),
        public: e.human.public_hex(),
    };
    let params = json!({"repo": "late", "human": "ayse", "human_key": human_key});
    let prep = e.ok("repo.prepare_init", None, None, params.clone());
    let stale: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    let next = e.ok("daemon.prepare_rotate", None, None, json!({}))["key"]
        .as_str()
        .unwrap()
        .to_string();
    let r = submit_to(&mut e, "demo", Op::DaemonRotate { key: next.clone() }).unwrap();
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert!(!home(&e).next_key_path().exists(), "rotation finished");

    // The prepared genesis named the deleted key.
    let sig = sign_ed25519(&e.human, "ayse", "late", &stale, e.now(), e.head("late"));
    let err = e
        .call("repo.init", None, None, json!({"op": stale, "sig": sig}))
        .unwrap_err();
    assert_eq!(err.0, "invalid", "{err:?}");
    init_repo(&mut e, "late");
    assert_eq!(daemon_key_of(&mut e, "late"), next);
    e.reopen();
    assert_eq!(daemon_key_of(&mut e, "late"), next);
}
