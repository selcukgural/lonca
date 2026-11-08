//! Security events outside the operation log (issue #56): what never
//! reaches a decision is still written down, a freeze reaches a human at
//! once, and no event holds a token or file contents.

mod common;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::time::Duration;

use common::*;
use lonca_daemon::limits::{Limits, SHORT_LINE};
use lonca_daemon::security::{Event, Notify, kind};
use lonca_daemon::server::{Access, serve_with};

fn served_with(e: &Env, access: Access) -> PathBuf {
    let sock = e.root.join("s");
    let listener: UnixListener = lonca_daemon::server::bind(&sock).unwrap();
    let svc = e.svc.clone();
    std::thread::spawn(move || serve_with(listener, svc, access, Limits::default()));
    sock
}

fn events(e: &Env) -> Vec<Event> {
    let text = std::fs::read_to_string(e.root.join("home/security.log")).unwrap_or_default();
    text.lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn of_kind(e: &Env, k: &str) -> Vec<Event> {
    events(e).into_iter().filter(|x| x.kind == k).collect()
}

fn send_line(sock: &Path, line: &[u8]) -> String {
    let mut s = UnixStream::connect(sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(line).unwrap();
    let mut answer = String::new();
    let _ = BufReader::new(s).read_line(&mut answer);
    answer
}

/// Waits a little for an event written by another thread.
fn eventually(e: &Env, k: &str, n: usize) -> Vec<Event> {
    for _ in 0..200 {
        let found = of_kind(e, k);
        if found.len() >= n {
            return found;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    of_kind(e, k)
}

#[test]
fn a_refused_peer_a_bad_token_and_an_oversized_line_are_one_event_each() {
    let mut e = Env::new();
    e.init(None);
    let me = lonca_daemon::sys::current_uid();
    let sock = served_with(
        &e,
        Access {
            allowed_uids: Some(vec![me.wrapping_add(1)]),
            ..Access::default()
        },
    );
    let _ = UnixStream::connect(&sock).map(|mut s| {
        let _ = s.write_all(b"{\"id\":1,\"method\":\"ping\"}\n");
        let _ = s.read_line_lossy();
    });
    let refused = eventually(&e, kind::REFUSED_PEER, 1);
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert_eq!(refused[0].uid, Some(me));

    // Served to this uid from here on.
    std::fs::remove_file(&sock).unwrap();
    let sock = served_with(&e, Access::default());
    // The harness's own logins before the first repository were refused.
    let before = of_kind(&e, kind::AUTH_FAILURE).len();
    let token = format!("lonca_{}", "ab".repeat(32));
    let bad =
        format!(r#"{{"id":2,"method":"status","repo":"demo","token":"{token}","params":{{}}}}"#);
    assert!(send_line(&sock, format!("{bad}\n").as_bytes()).contains("unauthenticated"));
    let auth = of_kind(&e, kind::AUTH_FAILURE);
    assert_eq!(auth.len(), before + 1, "{auth:?}");
    let last = auth.last().unwrap();
    assert_eq!(last.method.as_deref(), Some("status"));
    assert_eq!(last.code.as_deref(), Some("unauthenticated"));

    // A method that may not send a long line, with file content in it.
    let content = base64_of("the secret contents of a file ".repeat(10_000).as_bytes());
    let long = format!(r#"{{"id":3,"method":"status","params":{{"content":"{content}"}}}}"#);
    assert!(long.len() > SHORT_LINE);
    assert!(send_line(&sock, format!("{long}\n").as_bytes()).contains("too_large"));
    let big = eventually(&e, kind::OVERSIZED, 1);
    assert_eq!(big.len(), 1, "{big:?}");

    assert!(send_line(&sock, b"{not json\n").contains("invalid"));
    assert_eq!(eventually(&e, kind::MALFORMED, 1).len(), 1);

    // Nothing that was sent is in the log: not the token, not the content.
    let text = std::fs::read_to_string(e.root.join("home/security.log")).unwrap();
    assert!(
        !text.contains(&token) && !text.contains(&"ab".repeat(32)),
        "{text}"
    );
    assert!(!text.contains(&content[..64]), "no file content");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(e.root.join("home/security.log")).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }
}

fn base64_of(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

trait ReadLossy {
    fn read_line_lossy(&mut self) -> String;
}

impl ReadLossy for UnixStream {
    fn read_line_lossy(&mut self) -> String {
        let mut line = String::new();
        let _ = BufReader::new(self).read_line(&mut line);
        line
    }
}

/// A freeze runs the notify command with the event, and the security
/// events of a day are there for a human (`lonca doctor` reads them).
#[test]
fn a_freeze_is_told_at_once_and_summed_up_for_a_human() {
    let mut e = Env::new();
    let told = e.root.join("told.jsonl");
    let script = e.root.join("notify.sh");
    std::fs::write(&script, format!("#!/bin/sh\ncat >> {}\n", told.display())).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    e.settings.notify = Notify::Command(script);
    e.reopen();
    e.init(None);
    e.human(Op::Freeze {
        reason: "checking the alarm".into(),
    });
    let mut said = String::new();
    for _ in 0..300 {
        said = std::fs::read_to_string(&told).unwrap_or_default();
        if said.ends_with('\n') {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let event: Event = serde_json::from_str(said.lines().next().unwrap()).unwrap();
    assert_eq!(event.kind, kind::FREEZE);
    assert_eq!(event.repo.as_deref(), Some("demo"));
    assert!(event.detail.contains("checking the alarm"));
    let r = e.ok("security.events", None, None, json!({}));
    assert_eq!(r["counts"]["freeze"], 1, "{r}");
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert!(s["frozen"].as_str().unwrap().contains("checking the alarm"));
}

/// A ref moved behind the daemon's back, a hook refusal and a new token
/// are events; the operation log has the first as before.
#[test]
fn unmediated_writes_hook_refusals_and_rotations_are_events() {
    let mut e = Env::new();
    e.init(None);
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    let ws = e.root.join("ws");
    let r = e.ok(
        "hook.event",
        None,
        Some(&token),
        json!({"hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": "cat ~/.lonca/daemon.key"}, "workspace": ws}),
    );
    assert_eq!(r["decision"], "deny", "{r}");
    let denied = of_kind(&e, kind::HOOK_DENIED);
    assert_eq!(denied.len(), 1, "{denied:?}");
    assert!(denied[0].detail.starts_with("Bash: "), "{denied:?}");

    e.ok("session.rotate", None, Some(&token), json!({}));
    assert_eq!(of_kind(&e, kind::TOKEN_ROTATED).len(), 1);

    let trunk = e.trunk();
    let store = e.store();
    git(
        &e.root,
        &[
            "--git-dir",
            store.path().to_str().unwrap(),
            "update-ref",
            "refs/heads/other",
            &trunk.0,
        ],
    );
    e.svc.reconcile_all();
    // `reconcile_all` runs outside a request: the worker hands its events on.
    e.ok("status", Some("demo"), None, json!({}));
    let moved = of_kind(&e, kind::UNMEDIATED);
    assert_eq!(moved.len(), 1, "{moved:?}");
    assert_eq!(moved[0].detail, "refs/heads/other");
    let all = e.ok("security.events", None, None, json!({}));
    assert_eq!(all["counts"]["unmediated_import"], 1, "{all}");
}

/// Every kind the daemon writes is one the decisions name.
#[test]
fn the_kinds_are_documented() {
    let doc = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/decisions.md"),
    )
    .unwrap();
    for k in kind::ALL {
        assert!(
            doc.contains(&format!("`{k}`")),
            "{k} is not in docs/decisions.md"
        );
    }
}
