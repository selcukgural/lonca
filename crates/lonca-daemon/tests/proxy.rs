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

/// `config` with the proxy open to `port` too (tests serve on loopback
/// ports that are not 80 or 443).
fn open_to(config: &str, port: u16) -> String {
    let opened = config.replace(
        "allow_ports = [80, 443]",
        &format!("allow_ports = [80, 443, {port}]"),
    );
    assert_ne!(opened, config);
    opened
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

/// What stands for a harness: a process a session is bound from, whose
/// commands descend from it.
struct Harness {
    child: std::process::Child,
    out: BufReader<std::process::ChildStdout>,
}

impl Harness {
    fn start() -> Harness {
        Harness::under(&mut Command::new("/bin/bash"))
    }

    fn under(shell: &mut Command) -> Harness {
        use std::process::Stdio;
        let mut child = shell
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        Harness { child, out }
    }

    fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Runs `script` in a process of its own below the harness and gives
    /// what it printed.
    fn run(&mut self, script: &str) -> String {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "( {script} )\necho; echo harness-done").unwrap();
        let mut text = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(self.out.read_line(&mut line).unwrap(), 0, "{text}");
            if line.trim() == "harness-done" {
                return text;
            }
            text.push_str(&line);
        }
    }

    /// A tunnel opened by a command of the harness, like a sandboxed `curl`.
    fn tunnel(&mut self, proxy: u16, target: &str) -> String {
        self.run(&tunnel_script(proxy, target))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn tunnel_script(proxy: u16, target: &str) -> String {
    format!(
        "exec 3<>/dev/tcp/127.0.0.1/{proxy}; printf 'CONNECT {target} HTTP/1.1\\r\\n\\r\\n' >&3; cat <&3"
    )
}

/// Whether the daemon can name the process of a connection here.
fn processes_are_named() -> bool {
    Command::new("lsof").arg("-v").output().is_ok()
        && lonca_daemon::lineage::Table::read().is_some()
}

/// Two sessions, each bound from a harness of its own, and a proxy open to
/// an upstream on loopback.
fn two_harnesses(e: &mut Env) -> (u16, u16, Harness, Harness, String) {
    e.init(None);
    let proxy = start_proxy(e);
    let up = upstream();
    let t1 = e.session("s1", &["src/**"]);
    let t2 = e.session("s2", &["src/**"]);
    let (h1, h2) = (Harness::start(), Harness::start());
    e.peer_pid = Some(h1.pid());
    e.bind(&t1);
    e.peer_pid = Some(h2.pid());
    e.bind(&t2);
    e.peer_pid = None;
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "allow_private_network = false",
        "allow_private_network = true",
    );
    set_policy(e, &open_to(&config, up));
    (proxy, up, h1, h2, t1)
}

#[test]
fn a_connection_is_charged_to_the_session_whose_harness_made_it() {
    let mut e = Env::new();
    let (proxy, up, mut h1, _h2, _) = two_harnesses(&mut e);

    let text = h1.tunnel(proxy, &format!("127.0.0.1:{up}"));
    assert!(
        text.contains("200 Connection established") && text.contains("hello from upstream"),
        "{text}"
    );

    let t = taints(&mut e);
    assert!(t["s1"].as_str().unwrap().contains("fetch 127.0.0.1"), "{t}");
    if processes_are_named() {
        assert!(
            t["s2"].is_null(),
            "only the session that made the connection is tainted: {t}"
        );
        assert_eq!(e.svc.proxy_unattributed(), 0);
    } else {
        assert!(
            !t["s2"].is_null(),
            "without attribution every proxied session is tainted"
        );
    }
}

#[test]
fn where_a_process_stands_says_nothing_of_whose_it_is() {
    let mut e = Env::new();
    let (proxy, up, mut h1, _h2, _) = two_harnesses(&mut e);
    // The other session's workspace, as the hook reported it at its bind
    // and as `lonca run` would: a command of s1 goes there first.
    let theirs = e.root.join("ws2");
    std::fs::create_dir_all(&theirs).unwrap();
    let script = tunnel_script(proxy, &format!("127.0.0.1:{up}"));
    let text = h1.run(&format!("cd {} && {script}", theirs.display()));
    assert!(text.contains("hello from upstream"), "{text}");

    let t = taints(&mut e);
    assert!(
        t["s1"]
            .as_str()
            .is_some_and(|x| x.contains("fetch 127.0.0.1")),
        "the session that fetched is tainted wherever its command stood: {t}"
    );
    if processes_are_named() {
        assert!(t["s2"].is_null(), "{t}");
    }
}

#[test]
fn a_command_that_leaves_its_harness_is_charged_to_every_session() {
    let mut e = Env::new();
    let (proxy, up, mut h1, _h2, _) = two_harnesses(&mut e);
    // The command's parent ends before it connects: nothing ties it to
    // its harness any more, so it can not be told from the other's.
    let out = e.root.join("left.out");
    let script = tunnel_script(proxy, &format!("127.0.0.1:{up}"));
    h1.run(&format!(
        "( sleep 0.5; {script} > {out} 2>&1; echo over >> {out} ) > /dev/null 2>&1 &",
        out = out.display()
    ));
    for _ in 0..500 {
        let text = std::fs::read_to_string(&out).unwrap_or_default();
        if text.contains("over") {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let text = std::fs::read_to_string(&out).unwrap_or_default();
    assert!(text.contains("hello from upstream"), "{text}");

    let t = taints(&mut e);
    assert!(!t["s1"].is_null() && !t["s2"].is_null(), "{t}");
}

#[test]
fn a_session_answers_for_what_one_made_from_it_fetches() {
    let mut e = Env::new();
    let (proxy, up, _h1, _h2, t1) = two_harnesses(&mut e);
    let expires = e.now() + 60_000;
    let scope = Scope {
        paths: vec!["src/**".into()],
        symbols: None,
        ops: vec![OpKind::ChangePropose],
        max_files: None,
        max_lines: None,
        scratch: vec![],
    };
    let r = e.ok(
        "cap.attenuate",
        None,
        Some(&t1),
        json!({"agent": "bot-s1", "scope": scope, "expires_ms": expires}),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let child = r["token"].as_str().unwrap().to_string();
    // The child is bound from a harness of its own: its commands are
    // nearer to it than to the session it was made from.
    let mut below = Harness::start();
    e.peer_pid = Some(below.pid());
    e.ok(
        "hook.bind",
        None,
        Some(&child),
        json!({"harness": "claude-code", "harness_session": "h1", "sudo_without_password": false}),
    );
    e.peer_pid = None;
    let text = below.tunnel(proxy, &format!("127.0.0.1:{up}"));
    assert!(text.contains("hello from upstream"), "{text}");

    let t = taints(&mut e);
    let tainted: Vec<&String> = t
        .as_object()
        .unwrap()
        .iter()
        .filter(|(_, v)| !v.is_null())
        .map(|(k, _)| k)
        .collect();
    assert!(tainted.iter().any(|k| *k == "s1"), "{t}");
    assert!(tainted.len() >= 2, "the child and its parent: {t}");
    if processes_are_named() {
        assert!(t["s2"].is_null(), "{t}");
    }
}

#[test]
fn a_session_never_bound_itself_is_known_by_the_one_it_was_made_from() {
    let mut e = Env::new();
    let (proxy, up, mut h1, mut h2, t1) = two_harnesses(&mut e);
    let expires = e.now() + 60_000;
    let scope = Scope {
        paths: vec!["src/**".into()],
        symbols: None,
        ops: vec![OpKind::ChangePropose],
        max_files: None,
        max_lines: None,
        scratch: vec![],
    };
    let r = e.ok(
        "cap.attenuate",
        None,
        Some(&t1),
        json!({"agent": "bot-s1", "scope": scope, "expires_ms": expires}),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    if !processes_are_named() {
        return;
    }
    // What the other harness fetches is not the child's, nor its parent's.
    h2.tunnel(proxy, &format!("127.0.0.1:{up}"));
    let t = taints(&mut e);
    let tainted = |t: &Value| {
        let all = t.as_object().unwrap().iter();
        let mut ids: Vec<String> = all
            .filter(|(_, v)| !v.is_null())
            .map(|(k, _)| k.clone())
            .collect();
        ids.sort();
        ids
    };
    assert_eq!(tainted(&t), ["s2"], "{t}");
    // What its parent's harness fetches is both's: nothing tells them apart.
    h1.tunnel(proxy, &format!("127.0.0.1:{up}"));
    let t = taints(&mut e);
    assert_eq!(tainted(&t).len(), 3, "{t}");
}

#[test]
fn a_session_below_the_sandbox_level_answers_for_its_own_once_bound() {
    let mut e = Env::new();
    let (proxy, up, _h1, _h2, _) = two_harnesses(&mut e);
    let t3 = e.session("s3", &["src/**"]);
    let mut h3 = Harness::start();
    e.peer_pid = Some(h3.pid());
    let other =
        json!({"harness": "another", "harness_session": "h3", "sudo_without_password": false});
    let r = e.ok("hook.bind", None, Some(&t3), other);
    e.peer_pid = None;
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_ne!(r["level"], "hooks_sandbox", "{r}");
    h3.tunnel(proxy, &format!("127.0.0.1:{up}"));
    let t = taints(&mut e);
    assert!(!t["s3"].is_null(), "{t}");
    if processes_are_named() {
        assert!(t["s1"].is_null() && t["s2"].is_null(), "{t}");
    }
}

#[test]
fn a_refused_bind_places_no_session() {
    let mut e = Env::new();
    let (proxy, up, _h1, _h2, _) = two_harnesses(&mut e);
    // A third session, bound first by something that is not its harness,
    // from no process the daemon was told of.
    let t3 = e.session("s3", &["src/**"]);
    let other =
        json!({"harness": "another", "harness_session": "h3", "sudo_without_password": false});
    let r = e.ok("hook.bind", None, Some(&t3), other);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    // A later bind may not raise its level: refused, and the process it
    // came from is not what the session is known by.
    let mut h3 = Harness::start();
    e.peer_pid = Some(h3.pid());
    let own =
        json!({"harness": "claude-code", "harness_session": "h3", "sudo_without_password": false});
    let r = e.ok("hook.bind", None, Some(&t3), own);
    e.peer_pid = None;
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    h3.tunnel(proxy, &format!("127.0.0.1:{up}"));
    let t = taints(&mut e);
    // So its command is nobody's own, and those the proxy serves answer.
    assert!(t["s3"].is_null(), "{t}");
    assert!(!t["s1"].is_null() && !t["s2"].is_null(), "{t}");
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
        status.contains("403") && body.contains(&format!("port {up}")),
        "only ports 80 and 443 by default: {status} {body}"
    );
    let config = lonca_policy::config::DEFAULT_CONFIG.to_string();
    set_policy(&mut e, &open_to(&config, up));
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
    set_policy(&mut e, &open_to(&config, up));
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
        workspace: None,
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
    set_policy(&mut e, &open_to(&config, up));

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
fn an_isolated_session_is_known_by_the_launcher_that_asked() {
    let mut e = Env::new();
    e.init(None);
    let proxy = start_proxy(&e);
    let up = upstream();
    e.session("s1", &["src/**"]);
    let t2 = e.session("s2", &["src/**"]);
    // `lonca run` asks for the sandbox and then starts the command in it.
    let (mut run, h2) = (Harness::start(), Harness::start());
    e.peer_pid = Some(run.pid());
    let ws = e.root.join("ws1");
    isolate(&mut e, "s1", &ws);
    e.peer_pid = Some(h2.pid());
    e.bind(&t2);
    e.peer_pid = None;
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "allow_private_network = false",
        "allow_private_network = true",
    );
    set_policy(&mut e, &open_to(&config, up));

    let out = run.tunnel(proxy, &format!("127.0.0.1:{up}"));
    assert!(out.contains("hello from upstream"), "{out}");
    let t = taints(&mut e);
    assert!(!t["s1"].is_null(), "{t}");
    if processes_are_named() {
        assert!(t["s2"].is_null(), "{t}");
    }
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
    set_policy(&mut e, &open_to(&config, up));

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

// ---------------------------------------------------------------- limits (#64)

/// A session bound in `ws` and a proxy, under `config` opened to `up`.
fn proxied(e: &mut Env, config: &str, up: u16) -> (u16, PathBuf) {
    e.init(None);
    let proxy = start_proxy(e);
    let t = e.session("s1", &["src/**"]);
    let ws = e.root.join("ws1");
    std::fs::create_dir_all(&ws).unwrap();
    bind_with_workspace(e, &t, &ws);
    set_policy(e, &open_to(config, up));
    (proxy, ws)
}

fn private_ok() -> String {
    lonca_policy::config::DEFAULT_CONFIG.replace(
        "allow_private_network = false",
        "allow_private_network = true",
    )
}

#[test]
fn only_allowed_ports_and_never_a_metadata_address() {
    let mut e = Env::new();
    let up = upstream();
    let (proxy, _) = proxied(&mut e, &private_ok(), up);
    // Refused by the port alone: nothing is resolved or connected.
    let (status, body) = connect(proxy, "example.com:25");
    assert!(
        status.contains("403") && body.contains("port 25"),
        "{status} {body}"
    );
    let log = e.ok("log", Some("demo"), None, json!({})).to_string();
    assert!(
        log.contains(r#""host":"example.com:25""#),
        "the attempt is on record: {log}"
    );
    // Open to every private address, still never the metadata services.
    for target in [
        "169.254.169.254:80",
        "[fd00:ec2::254]:80",
        "[::ffff:169.254.169.254]:80",
    ] {
        let (status, body) = connect(proxy, target);
        assert!(
            status.contains("403") && body.contains("metadata"),
            "{target}: {status} {body}"
        );
    }
    let (status, _) = connect(proxy, &format!("127.0.0.1:{up}"));
    assert!(status.contains("200"), "{status}");
}

/// Accepts connections and holds them until the other side closes.
fn holding_upstream() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for s in l.incoming().flatten() {
            std::thread::spawn(move || {
                let mut s = s;
                let _ = std::io::copy(&mut s, &mut std::io::sink());
            });
        }
    });
    port
}

fn open_tunnel(proxy: u16, target: &str) -> (TcpStream, String) {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).unwrap();
    write!(s, "CONNECT {target} HTTP/1.1\r\n\r\n").unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut status = String::new();
    r.read_line(&mut status).unwrap();
    (s, status)
}

#[test]
fn a_session_holds_so_many_connections_at_once() {
    let mut e = Env::new();
    let up = holding_upstream();
    let config = private_ok().replace("max_connections = 16", "max_connections = 2");
    let (proxy, _) = proxied(&mut e, &config, up);
    let target = format!("127.0.0.1:{up}");
    let (a, status) = open_tunnel(proxy, &target);
    assert!(status.contains("200"), "{status}");
    let (_b, status) = open_tunnel(proxy, &target);
    assert!(status.contains("200"), "{status}");
    let (third, said) = connect(proxy, &target);
    assert!(
        third.contains("403") && said.contains("connections open"),
        "{third} {said}"
    );
    // One closes: there is room again.
    drop(a);
    let mut room = false;
    for _ in 0..100 {
        let (_c, status) = open_tunnel(proxy, &target);
        if status.contains("200") {
            room = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(room, "a closed connection gives its place back");
}

#[test]
fn a_session_past_its_bytes_is_cut_and_refused() {
    let mut e = Env::new();
    let up = upstream();
    let config = private_ok().replace("max_bytes = 1073741824", "max_bytes = 10");
    let (proxy, _) = proxied(&mut e, &config, up);
    let target = format!("127.0.0.1:{up}");
    let (status, rest) = connect(proxy, &target);
    assert!(status.contains("200"), "{status}");
    assert!(
        !rest.contains("hello from upstream"),
        "cut before 20 bytes passed: {rest}"
    );
    let (status, body) = connect(proxy, &target);
    assert!(
        status.contains("403") && body.contains("max_bytes"),
        "{status} {body}"
    );
}

#[test]
fn an_allowed_host_passes_a_closed_network_and_says_whether_it_taints() {
    let mut e = Env::new();
    let up = upstream();
    let config = private_ok()
        .replace("network = \"taint\"", "network = \"deny\"")
        .replace(
            "allow_hosts = []",
            r#"allow_hosts = [{ host = "127.0.0.1", taint = false }, { host = "localhost", taint = true }]"#,
        );
    let (proxy, ws) = proxied(&mut e, &config, up);
    let out = tunnel_from(&ws, proxy, &format!("127.0.0.1:{up}"));
    assert!(out.contains("hello from upstream"), "{out}");
    assert!(taints(&mut e)["s1"].is_null(), "a rule with taint = false");
    let out = tunnel_from(&ws, proxy, &format!("localhost:{up}"));
    assert!(out.contains("hello from upstream"), "{out}");
    assert!(
        taints(&mut e)["s1"]
            .as_str()
            .unwrap()
            .contains("fetch localhost"),
        "a rule with taint = true"
    );
    let status = e.ok("status", Some("demo"), None, json!({}));
    assert!(status["proxy_unattributed"].is_u64(), "{status}");
}
