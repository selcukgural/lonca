//! The network proxy: attribution, tainting, private-address refusal and
//! policy denial.

mod common;
use common::*;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

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
