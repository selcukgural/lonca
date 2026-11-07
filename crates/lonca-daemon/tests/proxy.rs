//! The network proxy: attribution, tainting, private-address refusal and
//! policy denial.

mod common;
use common::*;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use lonca_core::ops::{Op, OpKind, Scope};

fn bind_with_workspace(e: &mut Env, token: &str, workspace: &Path) {
    e.bind(token);
    let r = e.ok(
        "hook.bind",
        None,
        Some(token),
        json!({"harness": "claude-code", "harness_session": "h", "sudo_without_password": false, "workspace": workspace}),
    );
    assert_eq!(r["level"], "hooks_sandbox");
}

fn start_proxy(e: &Env) -> u16 {
    let l = lonca_daemon::proxy::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let svc = e.svc.clone();
    std::thread::spawn(move || lonca_daemon::proxy::serve(l, svc));
    port
}

/// A tiny upstream that answers one line.
fn upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            let _ = s.write_all(b"hello from upstream\n");
        }
    });
    port
}

fn connect(proxy: u16, target: &str) -> (String, String) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    write!(s, "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").unwrap();
    let mut r = BufReader::new(s);
    let mut status = String::new();
    r.read_line(&mut status).unwrap();
    let mut rest = String::new();
    let _ = r.read_to_string(&mut rest);
    (status.trim().to_string(), rest)
}

fn set_policy(e: &mut Env, config: &str) {
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
}

fn taints(e: &mut Env) -> Value {
    let s = e.ok("status", Some("demo"), None, json!({}));
    s["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (x["id"].as_str().unwrap().to_string(), x["taint"].clone()))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

#[test]
fn proxy_attributes_connections_to_the_workspace_that_made_them() {
    let mut e = Env::new();
    e.init(None);
    let proxy = start_proxy(&e);
    let up = upstream();
    let t1 = e.session("s1", &["src/**"]);
    let t2 = e.session("s2", &["src/**"]);
    let ws1 = e.root.join("ws1");
    let ws2 = e.root.join("ws2");
    std::fs::create_dir_all(&ws1).unwrap();
    std::fs::create_dir_all(&ws2).unwrap();
    bind_with_workspace(&mut e, &t1, &ws1);
    bind_with_workspace(&mut e, &t2, &ws2);
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "allow_private_network = false",
        "allow_private_network = true",
    );
    set_policy(&mut e, &config);

    // A process in s1's workspace opens a tunnel, like a sandboxed `curl`.
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{proxy}; printf 'CONNECT 127.0.0.1:{up} HTTP/1.1\\r\\n\\r\\n' >&3; cat <&3"
    );
    let out = Command::new("/bin/bash")
        .arg("-c")
        .arg(&script)
        .current_dir(&ws1)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("200 Connection established") && text.contains("hello from upstream"),
        "{text}"
    );

    let t = taints(&mut e);
    assert!(t["s1"].as_str().unwrap().contains("fetch 127.0.0.1"), "{t}");
    if Command::new("lsof").arg("-v").output().is_ok() {
        assert!(
            t["s2"].is_null(),
            "only the session that made the connection is tainted: {t}"
        );
    } else {
        assert!(
            !t["s2"].is_null(),
            "without attribution every proxied session is tainted"
        );
    }
}

#[test]
fn proxy_refuses_without_sessions_private_targets_and_denied_networks() {
    let mut e = Env::new();
    e.init(None);
    let proxy = start_proxy(&e);
    let up = upstream();

    let (status, _) = connect(proxy, &format!("127.0.0.1:{up}"));
    assert!(status.contains("403"), "nobody uses the proxy: {status}");

    let t1 = e.session("s1", &["src/**"]);
    let ws = e.root.join("ws");
    bind_with_workspace(&mut e, &t1, &ws);
    let (status, body) = connect(proxy, &format!("127.0.0.1:{up}"));
    assert!(
        status.contains("403") && body.contains("private"),
        "private targets by default: {status} {body}"
    );
    assert!(
        !taints(&mut e)["s1"].is_null(),
        "the attempt itself is observed"
    );

    let config = lonca_policy::config::DEFAULT_CONFIG
        .replace(
            "allow_private_network = false",
            "allow_private_network = true",
        )
        .replace("network = \"taint\"", "network = \"deny\"");
    set_policy(&mut e, &config);
    let (status, body) = connect(proxy, &format!("127.0.0.1:{up}"));
    assert!(
        status.contains("403") && body.contains("denied by repository policy"),
        "{status} {body}"
    );
}

// ---------------------------------------------------------------- isolated sessions

fn isolate_op(session: &str) -> Op {
    Op::SessionIsolate {
        session: session.into(),
        sandbox: "seatbelt".into(),
        profile: "ab".repeat(32),
    }
}

/// `lonca run`'s step: the session is isolated and has a new token.
fn isolate(e: &mut Env, session: &str, workspace: &Path) -> String {
    let mut body = e.sign(&isolate_op(session));
    body["workspace"] = json!(workspace);
    let r = e.ok("human.submit", Some("demo"), None, body);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    r["token"].as_str().unwrap().to_string()
}

#[test]
fn isolating_replaces_the_token_and_only_a_human_can_do_it() {
    let mut e = Env::new();
    e.init(None);
    let old = e.session("s1", &["src/**"]);
    let ws = e.root.join("ws1");
    std::fs::create_dir_all(&ws).unwrap();

    // Not with the agent's own token.
    let body = e.sign(&isolate_op("s1"));
    let refused = e
        .call("human.submit", Some("demo"), Some(&old), body)
        .unwrap_err();
    assert_eq!(refused.0, "forbidden", "{refused:?}");

    let new = isolate(&mut e, "s1", &ws);
    assert_ne!(new, old);
    let dead = e
        .call("session.heartbeat", None, Some(&old), json!({}))
        .unwrap_err();
    assert_eq!(dead.0, "unauthenticated", "{dead:?}");
    e.ok("session.heartbeat", None, Some(&new), json!({}));
}

#[test]
fn a_hook_in_a_sandbox_changes_nothing_and_logs_nothing() {
    let mut e = Env::new();
    e.init(None);
    e.session("s1", &["src/**"]);
    let ws = e.root.join("ws1");
    std::fs::create_dir_all(&ws).unwrap();
    let token = isolate(&mut e, "s1", &ws);
    e.in_sandbox = true;
    let before = e.store().ref_get("refs/lonca/oplog").unwrap();
    let r = e.ok(
        "hook.bind",
        None,
        Some(&token),
        json!({"harness": "codex", "harness_session": "h", "sudo_without_password": true}),
    );
    assert_eq!(r["level"], "isolated", "{r}");
    assert_eq!(r["scratch"], json!([]), "{r}");
    assert_eq!(e.store().ref_get("refs/lonca/oplog").unwrap(), before);
}

#[test]
fn what_a_sandbox_is_built_from_comes_from_the_log() {
    let mut e = Env::new();
    e.init(None);
    let trunk = e.trunk();
    let scratch = e.root.join("scratch").display().to_string();
    let mut scope = Scope {
        paths: vec!["src/**".into()],
        symbols: None,
        ops: vec![OpKind::ChangePropose],
        max_files: None,
        max_lines: None,
        scratch: vec![scratch.clone()],
    };
    scope.paths.sort();
    let expires_ms = e.now() + 60_000;
    let start = Op::SessionStart {
        session: "s1".into(),
        agent: "a".into(),
        model: None,
        task: String::new(),
        scope,
        expires_ms,
        continues: None,
        harness: None,
    };
    e.human(start);
    let r = e.ok(
        "human.prepare_isolate",
        Some("demo"),
        None,
        json!({"session": "s1", "base": trunk}),
    );
    assert_eq!(r["scratch"], json!([scratch]), "{r}");
    assert_eq!(r["proxy"], e.settings.proxy.clone().unwrap(), "{r}");
    assert_eq!(r["base_known"], true, "{r}");
    assert_eq!(r["harness"], Value::Null, "{r}");
    assert_eq!(r["setup"], Value::Null, "{r}");
    assert_eq!(
        r["home"].as_str(),
        Some(e.root.join("home").to_str().unwrap()),
        "{r}"
    );
    let elsewhere = lonca_core::GitId::of_blob(b"not a commit of this log");
    let r = e.ok(
        "human.prepare_isolate",
        Some("demo"),
        None,
        json!({"session": "s1", "base": elsewhere}),
    );
    assert_eq!(r["base_known"], false, "{r}");
    let missing = e
        .call(
            "human.prepare_isolate",
            Some("demo"),
            None,
            json!({"session": "nobody", "base": trunk}),
        )
        .unwrap_err();
    assert_eq!(missing.0, "not_found", "{missing:?}");
}

/// A tunnel opened from `cwd`, as a command in a sandbox would.
fn tunnel_from(cwd: &Path, proxy: u16, target: &str) -> String {
    let script = format!(
        "exec 3<>/dev/tcp/127.0.0.1/{proxy}; printf 'CONNECT {target} HTTP/1.1\\r\\n\\r\\n' >&3; cat <&3"
    );
    let out = Command::new("/bin/bash")
        .arg("-c")
        .arg(&script)
        .current_dir(cwd)
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn an_isolated_session_is_watched_through_the_proxy() {
    let mut e = Env::new();
    e.init(None);
    let proxy = start_proxy(&e);
    let up = upstream();
    e.session("s1", &["src/**"]);
    let ws = e.root.join("ws1");
    std::fs::create_dir_all(&ws).unwrap();
    isolate(&mut e, "s1", &ws);
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "allow_private_network = false",
        "allow_private_network = true",
    );
    set_policy(&mut e, &config);

    // From anywhere: whoever uses the proxy, the isolated session answers
    // for it when the connection can not be attributed.
    let elsewhere = e.root.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    for cwd in [&elsewhere, &ws] {
        let out = tunnel_from(cwd, proxy, &format!("127.0.0.1:{up}"));
        assert!(out.contains("hello from upstream"), "{out}");
    }
    let t = taints(&mut e);
    assert!(t["s1"].as_str().unwrap().contains("fetch 127.0.0.1"), "{t}");
}

#[test]
fn the_agents_own_host_is_recorded_and_taints_nothing_even_where_the_network_is_closed() {
    let mut e = Env::new();
    e.init(None);
    let proxy = start_proxy(&e);
    let up = upstream();
    e.session("s1", &["src/**"]);
    let ws = e.root.join("ws1");
    std::fs::create_dir_all(&ws).unwrap();
    isolate(&mut e, "s1", &ws);
    let config = lonca_policy::config::DEFAULT_CONFIG
        .replace(
            "allow_private_network = false",
            "allow_private_network = true",
        )
        .replace("network = \"taint\"", "network = \"deny\"")
        .replace("agent_hosts = []", "agent_hosts = [\"127.0.0.1\"]");
    set_policy(&mut e, &config);

    let out = tunnel_from(&ws, proxy, &format!("127.0.0.1:{up}"));
    assert!(out.contains("hello from upstream"), "{out}");
    let refused = tunnel_from(&ws, proxy, &format!("localhost:{up}"));
    assert!(!refused.contains("hello from upstream"), "{refused}");
    assert!(refused.contains("403"), "{refused}");

    let t = taints(&mut e);
    assert!(
        t["s1"].as_str().unwrap().contains("fetch localhost"),
        "the host the policy does not name taints: {t}"
    );
    let log = e.ok("log", Some("demo"), None, json!({}));
    let text = log.to_string();
    assert!(
        text.contains(r#""host":"127.0.0.1"#),
        "on the record: {text}"
    );
}

#[test]
fn a_session_that_is_over_answers_for_no_connection() {
    let mut e = Env::new();
    e.init(None);
    let proxy = start_proxy(&e);
    let up = upstream();
    e.session("s1", &["src/**"]);
    let ws = e.root.join("ws1");
    std::fs::create_dir_all(&ws).unwrap();
    let token = isolate(&mut e, "s1", &ws);
    e.ok("session.end", None, Some(&token), json!({}));
    for cwd in [&ws, &e.root] {
        let out = tunnel_from(cwd, proxy, &format!("127.0.0.1:{up}"));
        assert!(!out.contains("hello from upstream"), "{out}");
        assert!(out.contains("no Lonca session"), "{out}");
    }
}

fn taint_of(e: &mut Env) -> Value {
    taints(e)["s1"].clone()
}

#[test]
fn an_isolated_token_works_in_a_sandbox_only() {
    let mut e = Env::new();
    e.init(None);
    let human = e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    assert_eq!(human["decision"]["outcome"], "allow");
    e.session("s1", &["src/**"]);
    let ws = e.root.join("ws1");
    std::fs::create_dir_all(&ws).unwrap();
    let token = isolate(&mut e, "s1", &ws);

    e.in_sandbox = true;
    let held = e.lease(&token, "src/lib.rs#charge");
    assert_eq!(held["decision"]["outcome"], "allow", "{held}");
    assert!(taint_of(&mut e).is_null());

    e.in_sandbox = false;
    // What `lonca run` does from outside goes through and costs nothing.
    e.ok("session.heartbeat", None, Some(&token), json!({}));
    assert!(taint_of(&mut e).is_null());

    let refused = e
        .call(
            "lease.release",
            None,
            Some(&token),
            json!({"set": "nothing", "items": null}),
        )
        .unwrap_err();
    assert_eq!(refused.0, "not_in_sandbox", "{refused:?}");
    let reason = taint_of(&mut e);
    assert!(
        reason.as_str().unwrap().contains("outside its sandbox"),
        "{reason}"
    );

    // Once on the record: a loop outside does not fill the log.
    let before = e.store().ref_get("refs/lonca/oplog").unwrap();
    let again = e
        .call("hook.stop", None, Some(&token), json!({"files": []}))
        .unwrap_err();
    assert_eq!(again.0, "not_in_sandbox", "{again:?}");
    assert_eq!(e.store().ref_get("refs/lonca/oplog").unwrap(), before);

    // The end of the run comes from outside too.
    e.ok("session.end", None, Some(&token), json!({}));
}

#[test]
fn a_session_that_is_not_isolated_is_used_from_anywhere() {
    let mut e = Env::new();
    e.init(None);
    let token = e.session("s1", &["src/**"]);
    let r = e.call(
        "lease.release",
        None,
        Some(&token),
        json!({"set": "nothing", "items": null}),
    );
    assert_ne!(r.err().map(|x| x.0).as_deref(), Some("not_in_sandbox"));
    assert!(taint_of(&mut e).is_null());
}
