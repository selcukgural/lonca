//! What a repository starts from, and what a hardened install says about
//! one that stands below it (issue #54).

mod common;
use common::*;

use lonca_daemon::repo::RepoHandle;
use lonca_daemon::service::sandbox_at_start;
use lonca_policy::config::PolicyBundle;
use lonca_verify::Sandbox;

fn file_key(e: &Env) -> HumanKey {
    HumanKey {
        alg: "ed25519".into(),
        public: e.human.public_hex(),
    }
}

fn presence_key(e: &Env) -> HumanKey {
    HumanKey {
        alg: "p256-se".into(),
        public: e.human.public_hex(),
    }
}

fn prepare(e: &mut Env, key: HumanKey, extra: Value) -> Result<Value, (String, String)> {
    let mut params = json!({"repo": "demo", "human": "ayse", "human_key": key});
    params
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    e.anon("repo.prepare_init", None, None, params)
}

/// The policy a prepared init would start the repository from.
fn prepared_policy(e: &Env, prep: &Value) -> PolicyBundle {
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    let Op::RepoInit { policy, .. } = op else {
        panic!("not an init: {op:?}")
    };
    let store = Store::open(&e.root.join("home/repos/demo.git")).unwrap();
    RepoHandle::load_policy(&store, &policy).unwrap()
}

fn hardened_env() -> Env {
    let mut e = Env::new();
    e.settings.hardened = true;
    e.reopen();
    e
}

fn code(r: Result<Value, (String, String)>) -> String {
    r.map(|v| format!("ok: {v}")).unwrap_err().0
}

#[test]
fn a_cooperative_daemon_starts_cooperative_repositories() {
    let mut e = Env::new();
    let key = file_key(&e);
    let prep = prepare(&mut e, key, json!({})).unwrap();
    assert_eq!(prep["profile"], "cooperative");
    let p = prepared_policy(&e, &prep);
    assert!(!p.config.verification.required);
    assert!(!p.config.approvals.require_presence);
}

#[test]
fn a_hardened_daemon_starts_hardened_repositories() {
    let mut e = hardened_env();
    let key = presence_key(&e);
    let prep = prepare(&mut e, key, json!({})).unwrap();
    assert_eq!(prep["profile"], "hardened");
    let p = prepared_policy(&e, &prep);
    assert!(p.config.approvals.require_presence);
    assert_eq!(p.config.observation.network, "deny");
}

#[test]
fn a_human_can_ask_for_either_profile_on_either_daemon() {
    let mut e = hardened_env();
    let key = file_key(&e);
    let prep = prepare(&mut e, key, json!({"profile": "cooperative"})).unwrap();
    assert_eq!(prep["profile"], "cooperative");

    let mut e = Env::new();
    let key = presence_key(&e);
    let prep = prepare(&mut e, key, json!({"profile": "hardened"})).unwrap();
    assert_eq!(prep["profile"], "hardened");
    assert!(prepared_policy(&e, &prep).config.approvals.require_presence);
}

/// The file key would be locked out by the repository's own first entry.
#[test]
fn a_key_that_can_not_prove_presence_is_told_before_anything_is_made() {
    let mut e = hardened_env();
    let key = file_key(&e);
    let (c, m) = prepare(&mut e, key.clone(), json!({})).unwrap_err();
    assert_eq!(c, "invalid");
    assert!(m.contains("--without-presence"), "{m}");
    assert!(!e.root.join("home/repos/demo.git").exists());

    let prep = prepare(&mut e, key, json!({"without_presence": true})).unwrap();
    assert_eq!(prep["profile"], "hardened");
    let p = prepared_policy(&e, &prep);
    assert!(!p.config.approvals.require_presence);
    assert!(p.config.verification.require_sandbox);
}

#[test]
fn leaving_presence_off_means_nothing_in_a_cooperative_repository() {
    let mut e = Env::new();
    let key = file_key(&e);
    let params = json!({"without_presence": true});
    let (c, m) = prepare(&mut e, key, params).unwrap_err();
    assert_eq!(c, "invalid");
    assert!(m.contains("hardened profile"), "{m}");
}

#[test]
fn an_unknown_profile_is_refused() {
    let mut e = Env::new();
    let key = file_key(&e);
    let r = prepare(&mut e, key, json!({"profile": "open"}));
    assert_eq!(code(r), "invalid");
}

#[test]
fn only_a_hardened_daemon_reports_what_falls_short() {
    let mut e = Env::new();
    e.init(None);
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(s["below_hardened"], json!([]));

    e.settings.hardened = true;
    e.reopen();
    let s = e.ok("status", Some("demo"), None, json!({}));
    let below = s["below_hardened"].as_array().unwrap();
    assert_eq!(below.len(), 6, "{below:?}");
    assert_eq!(below[0], "approvals.require_presence");
}

#[test]
fn a_repository_that_needs_a_sandbox_is_named_at_the_start() {
    let mut e = Env::new();
    e.init(None);
    let bare: [String; 0] = [];
    assert_eq!(e.svc.sandbox_warnings(Sandbox::None), bare);

    let key = file_key(&e);
    let params = json!({
        "repo": "tight", "human": "ayse", "human_key": key,
        "profile": "hardened", "without_presence": true,
    });
    let prep = e.ok("repo.prepare_init", None, None, params);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    let sig = sign_ed25519(&e.human, "ayse", "tight", &op, e.now());
    let body = json!({"op": op, "sig": sig});
    e.ok("repo.init", None, None, body);

    let warned = e.svc.sandbox_warnings(Sandbox::None);
    assert_eq!(warned.len(), 1, "{warned:?}");
    assert!(
        warned[0].starts_with("tight requires a sandbox"),
        "{warned:?}"
    );
    assert!(warned[0].contains("unsandboxed_verification"), "{warned:?}");
    assert_eq!(e.svc.sandbox_warnings(Sandbox::Seatbelt), bare);
    assert_eq!(e.svc.sandbox_warnings(Sandbox::Bubblewrap), bare);
}

#[test]
fn a_hardened_daemon_does_not_start_without_a_sandbox_unless_told() {
    let e = sandbox_at_start(true, Sandbox::None, false).unwrap_err();
    assert!(e.contains("--allow-unsandboxed"), "{e}");
    let told = sandbox_at_start(true, Sandbox::None, true)
        .unwrap()
        .unwrap();
    assert!(told.starts_with("--allow-unsandboxed"), "{told}");
    let said = sandbox_at_start(false, Sandbox::None, false)
        .unwrap()
        .unwrap();
    assert!(said.contains("unsandboxed"), "{said}");
    for hardened in [true, false] {
        for sandbox in [Sandbox::Seatbelt, Sandbox::Bubblewrap] {
            assert_eq!(sandbox_at_start(hardened, sandbox, false), Ok(None));
            assert_eq!(sandbox_at_start(hardened, sandbox, true), Ok(None));
        }
    }
}
