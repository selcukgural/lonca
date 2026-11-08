//! The life of a session token (issue #53): it stops working when its
//! session expires and leaves `tokens.json`; `session.rotate` replaces it;
//! revocation reaches a rotated token.

mod common;
use common::*;

use lonca_core::canonical::sha256_hex;

fn code(r: Result<Value, (String, String)>) -> String {
    r.map(|v| format!("ok: {v}")).unwrap_err().0
}

fn stored(e: &Env, token: &str) -> bool {
    let text = std::fs::read_to_string(e.root.join("home/tokens.json")).unwrap();
    text.contains(&sha256_hex(token.as_bytes()))
}

fn workspace(e: &Env) -> Value {
    json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "src/lib.rs"},
        "workspace": e.root.join("ws"),
    })
}

#[test]
fn an_expired_session_can_do_nothing_and_its_token_is_swept() {
    let mut e = Env::new();
    e.init(None);
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    let t = Some(token.as_str());
    e.ok("status", None, t, json!({}));
    assert!(stored(&e, &token));

    // The session's lifetime is an hour (`session_op`).
    e.advance(3_600_000);
    for (method, params) in [
        ("status", json!({})),
        ("log", json!({})),
        ("whoami", json!({})),
        ("facts.preview", json!({"base": null, "files": []})),
        ("hook.event", workspace(&e)),
        ("session.rotate", json!({})),
    ] {
        let r = e.call(method, None, t, params);
        assert_eq!(code(r.clone()), "unauthenticated", "{method}: {r:?}");
    }
    let r = e.call("session.heartbeat", None, t, json!({}));
    assert_eq!(code(r), "session_inactive");

    // Swept when the daemon starts again (and by its worker, every round).
    e.reopen();
    assert!(!stored(&e, &token));
    let r = e.call("session.heartbeat", None, t, json!({}));
    assert_eq!(code(r), "unauthenticated");
}

#[test]
fn a_session_end_after_expiry_takes_the_token_with_it() {
    let mut e = Env::new();
    e.init(None);
    let token = e.session("s1", &["src/**"]);
    e.advance(3_600_000);
    let r = e.ok("session.end", None, Some(&token), json!({}));
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert!(!stored(&e, &token));
}

#[test]
fn a_rotated_token_replaces_the_old_one_and_is_never_logged() {
    let mut e = Env::new();
    e.init(None);
    let old = e.session("s1", &["src/**"]);
    let r = e.ok("session.rotate", None, Some(&old), json!({}));
    let new = r["token"].as_str().unwrap().to_string();
    assert!(new.starts_with("lonca_") && new != old);
    assert_eq!(
        code(e.call("status", None, Some(&old), json!({}))),
        "unauthenticated"
    );
    let who = e.ok("whoami", None, Some(&new), json!({}));
    assert_eq!(who["session"]["id"], "s1", "{who}");
    assert!(!stored(&e, &old) && stored(&e, &new));

    let log = e.ok("log", Some("demo"), None, json!({})).to_string();
    let tokens = std::fs::read_to_string(e.root.join("home/tokens.json")).unwrap();
    for text in [&log, &tokens] {
        assert!(!text.contains(&old) && !text.contains(&new));
    }
    if let Ok(daemon_log) = std::fs::read_to_string(e.root.join("home/daemon.log")) {
        assert!(!daemon_log.contains(&old) && !daemon_log.contains(&new));
    }
}

#[test]
fn revocation_reaches_rotated_tokens_of_the_session_and_its_children() {
    let mut e = Env::new();
    e.init(None);
    let parent = e.session("s1", &["src/**"]);
    let scope = json!({"paths": ["src/**"], "symbols": null, "ops": ["lease.release"],
                       "max_files": null, "max_lines": null});
    let child = e.ok(
        "cap.attenuate",
        None,
        Some(&parent),
        json!({"agent": "sub", "scope": scope, "expires_ms": e.now() + 60_000, "leases": []}),
    );
    let child = child["token"].as_str().unwrap().to_string();
    let rotate = |e: &mut Env, t: &str| {
        let r = e.ok("session.rotate", None, Some(t), json!({}));
        r["token"].as_str().unwrap().to_string()
    };
    let parent = rotate(&mut e, &parent);
    let child = rotate(&mut e, &child);
    e.ok("status", None, Some(&child), json!({}));
    e.human(Op::CapRevoke {
        session: "s1".into(),
        reason: "done".into(),
    });
    for t in [&parent, &child] {
        assert_eq!(
            code(e.call("status", None, Some(t), json!({}))),
            "unauthenticated"
        );
        assert!(!stored(&e, t));
    }
}
