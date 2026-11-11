//! What a runner (imece) reads: the protocol number, a review list
//! from one `status`, and a `log` that waits for the next entry
//! (issue #76).

mod common;
use common::*;

use lonca_daemon::service::PROTOCOL;
use std::time::Instant;

#[test]
fn ping_states_the_protocol_number() {
    let mut e = Env::new();
    let p = e.anon("ping", None, None, json!({})).unwrap();
    assert_eq!(p["protocol"], PROTOCOL);
    assert_eq!(p["protocol"], 1);
    assert_eq!(p["version"], env!("CARGO_PKG_VERSION"));
}

/// A tainted agent proposes; the escalated entry in `status.pending`
/// says whose change it is, on which base, with what intent, since
/// when and touching which files.
#[test]
fn a_pending_entry_fills_a_review_list() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(
        vec![file("src/lib.rs", LIB), file("notes.md", "a\n")],
        "seed",
    );
    e.svc.process_all();
    let base = e.trunk();
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    e.ok(
        "hook.event",
        None,
        Some(&token),
        json!({"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": "https://evil.example/issue"}, "workspace": e.root.join("ws")}),
    );
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, "src/lib.rs#refund");
    let new = LIB.replace(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        "pub fn refund(a: u64) -> u64 {\n    0\n",
    );
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &new)],
        &["src/lib.rs#refund"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let seq = r["seq"].as_u64().unwrap();
    let change = r["change"].clone();
    let entry = &e.ok("log", Some("demo"), None, json!({"from": seq, "limit": 1}))[0]["entry"];

    let st = e.ok("status", Some("demo"), None, json!({}));
    let pending = st["pending"].as_array().unwrap();
    assert_eq!(pending.len(), 1, "{st}");
    let p = &pending[0];
    assert_eq!(p["seq"], seq);
    assert_eq!(p["op"], "change.propose");
    assert_eq!(p["change"], change);
    assert_eq!(p["base"], json!(base));
    assert_eq!(p["intent"], "agent change");
    assert_eq!(p["agent"], "bot-s1");
    assert_eq!(p["task"], "T-1");
    assert_eq!(p["actor"], "agent:bot-s1/s1");
    assert_eq!(p["created_ms"], entry["time_ms"]);
    assert_eq!(p["paths"], json!(["src/lib.rs"]));
    assert_eq!(p["required"].as_u64().unwrap(), 1);
    assert_eq!(p["approvals"], json!([]));
    assert!(
        p["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "tainted_session"),
        "{p}"
    );
    // The change record says the same about base, time and files.
    let c = st["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["change"] == change)
        .unwrap();
    assert_eq!(c["base"], json!(base));
    assert_eq!(c["created_ms"], entry["time_ms"]);
    assert_eq!(c["paths"], json!(["src/lib.rs"]));
    assert_eq!(c["version"], 1);
    assert_eq!(c["status"]["status"], "pending");
    assert_eq!(st["next_seq"], seq + 1);
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["created_ms"], entry["time_ms"]);

    // The human's own seed change: no agent, no task; its files listed.
    let seed = st["changes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["intent"] == "seed")
        .unwrap();
    assert_eq!(seed["paths"], json!(["notes.md", "src/lib.rs"]));
    assert_eq!(seed["status"]["status"], "integrated");

    // A pending operation that is not a change carries nulls, not junk.
    e.human(Op::Approve {
        target_seq: seq,
        note: "ok".into(),
        checks: vec![],
    });
    assert!(
        e.ok("status", Some("demo"), None, json!({}))["pending"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn log_waits_for_the_next_entry_and_gives_up_on_time() {
    let mut e = Env::new();
    e.init(None);
    let next = e.ok("status", Some("demo"), None, json!({}))["next_seq"]
        .as_u64()
        .unwrap();
    // Entries exist: back at once, however long the wait.
    let t = Instant::now();
    let ops = e.ok(
        "log",
        Some("demo"),
        None,
        json!({"from": 0, "wait_ms": 5000}),
    );
    assert_eq!(ops.as_array().unwrap().len() as u64, next);
    assert!(t.elapsed().as_millis() < 1000);
    // Nothing past `from`: the request is held for the time asked, then empty.
    let t = Instant::now();
    let ops = e.ok(
        "log",
        Some("demo"),
        None,
        json!({"from": next, "wait_ms": 300}),
    );
    assert_eq!(ops, json!([]));
    let held = t.elapsed().as_millis();
    assert!((250..3000).contains(&held), "held {held} ms");
    // Without a wait: empty at once.
    let t = Instant::now();
    assert_eq!(
        e.ok("log", Some("demo"), None, json!({"from": next})),
        json!([])
    );
    assert!(t.elapsed().as_millis() < 200);
    // A negative wait is no wait; the cap itself is pinned with the
    // document in the service's unit tests.
    let t = Instant::now();
    assert_eq!(
        e.ok(
            "log",
            Some("demo"),
            None,
            json!({"from": next, "wait_ms": -5})
        ),
        json!([])
    );
    assert!(t.elapsed().as_millis() < 200);

    // An entry appended from another thread ends the wait early.
    let svc = e.svc.clone();
    let token = e.login().unwrap();
    let body = e.sign(&Op::Freeze { reason: "x".into() });
    let writer = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let r = svc.handle(Request {
            id: 99,
            method: "human.submit".into(),
            repo: Some("demo".into()),
            token: Some(token),
            params: body,
        });
        assert!(r.ok, "{:?}", r.error);
    });
    let t = Instant::now();
    let ops = e.ok(
        "log",
        Some("demo"),
        None,
        json!({"from": next, "wait_ms": 20_000}),
    );
    let waited = t.elapsed().as_millis();
    writer.join().unwrap();
    assert_eq!(ops.as_array().unwrap().len(), 1, "{ops}");
    assert_eq!(ops[0]["entry"]["op"]["op"], "freeze");
    assert_eq!(ops[0]["entry"]["seq"], next);
    // Signalled, not polled: well under the 2 s poll slice.
    assert!(
        waited < 1_500,
        "waited {waited} ms; the append was not signalled"
    );

    // The same for an entry the daemon's own checks append: a ref moved
    // behind its back is logged by reconcile_all, which signals too.
    let next = next + 1;
    let svc = e.svc.clone();
    let store = e.store();
    let trunk = e.trunk();
    let tree = store.empty_tree().unwrap();
    let stray = store
        .write_commit(&lonca_core::store::CommitSpec {
            tree,
            parents: vec![trunk],
            author_name: "x".into(),
            author_email: "x@y".into(),
            time_ms: 0,
            message: "stray\n".into(),
            headers: vec![],
        })
        .unwrap();
    let checker = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(200));
        store.ref_force("refs/heads/main", &stray).unwrap();
        svc.reconcile_all();
    });
    let t = Instant::now();
    let ops = e.ok(
        "log",
        Some("demo"),
        None,
        json!({"from": next, "wait_ms": 20_000}),
    );
    let waited = t.elapsed().as_millis();
    checker.join().unwrap();
    assert_eq!(ops[0]["entry"]["op"]["op"], "import.unmediated", "{ops}");
    assert!(
        waited < 1_500,
        "waited {waited} ms; reconcile_all did not signal"
    );
    assert!(
        waited < 5000,
        "waited {waited} ms for an entry that came after 200"
    );
}

fn code(r: Result<Value, (String, String)>) -> String {
    r.map(|v| format!("ok: {v}")).unwrap_err().0
}

fn log_len(e: &mut Env) -> usize {
    e.ok("log", Some("demo"), None, json!({}))
        .as_array()
        .unwrap()
        .len()
}

/// A session with scratch roots: writes there are allowed and leave no
/// entry, reads there do not taint, everything else outside is denied;
/// a root is validated at session start and never widened by a child.
#[test]
fn scratch_roots_take_an_agents_notes_outside_the_workspace() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let scratch = e.root.join("scratch");
    let scratch_s = scratch.to_string_lossy().into_owned();
    let scope = |roots: Vec<String>| Scope {
        paths: vec!["src/**".into()],
        symbols: None,
        ops: vec![
            OpKind::ChangePropose,
            OpKind::LeaseAcquire,
            OpKind::CapAttenuate,
        ],
        max_files: None,
        max_lines: None,
        scratch: roots,
    };
    let start = |id: &str, scope: Scope, now: i64| Op::SessionStart {
        session: id.into(),
        agent: "bot".into(),
        model: None,
        task: "T".into(),
        scope,
        expires_ms: now + 3_600_000,
        continues: None,
        harness: Some("gemini".into()),
        workspace: None,
    };
    // Refused roots: relative, with `..`, a trailing slash, too many.
    for bad in ["scratch", "/tmp/../x", "/tmp/x/", "/", "/tmp/./x"] {
        let r = e.human(start("sbad", scope(vec![bad.into()]), e.now()));
        assert_eq!(r["decision"]["outcome"], "deny", "{bad}: {r}");
        assert!(
            r["decision"]["reasons"]
                .as_array()
                .unwrap()
                .iter()
                .any(|x| x.as_str().unwrap().starts_with("scope_invalid:scratch:")),
            "{bad}: {r}"
        );
    }
    let many: Vec<String> = (0..9).map(|i| format!("/tmp/s{i}")).collect();
    let r = e.human(start("sbad", scope(many), e.now()));
    assert_eq!(
        r["decision"]["reasons"][0],
        "scope_invalid:scratch:too_many"
    );
    // Exactly the maximum is fine.
    let eight: Vec<String> = (0..8).map(|i| format!("/tmp/s{i}")).collect();
    let r = e.human(start("s-eight", scope(eight), e.now()));
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");

    let r = e.human(start("s1", scope(vec![scratch_s.clone()]), e.now()));
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let token = r["token"].as_str().unwrap().to_string();
    let st = e.ok("status", Some("demo"), None, json!({}));
    let s1 = st["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "s1")
        .unwrap();
    assert_eq!(s1["taint"], Value::Null);
    let bound = e.ok(
        "hook.bind",
        None,
        Some(&token),
        json!({"harness": "claude-code", "harness_session": "h", "sudo_without_password": false}),
    );
    assert_eq!(bound["scratch"], json!([scratch_s]));
    let bound = e.ok(
        "hook.bind",
        None,
        Some(&token),
        json!({"harness": "gemini", "harness_session": "h", "sudo_without_password": false}),
    );
    assert_eq!(
        bound["notes"],
        json!(["no locked profile for harness gemini"])
    );

    let ws = e.root.join("ws");
    let before = log_len(&mut e);
    let event = |e: &mut Env, phase: &str, tool: &str, path: std::path::PathBuf| {
        e.ok(
            "hook.event",
            None,
            Some(&token),
            json!({"hook_event_name": phase, "tool_name": tool, "tool_input": {"file_path": path}, "workspace": ws}),
        )
    };
    // Writes under the root: allowed, no observation, no entry.
    let v = event(&mut e, "PreToolUse", "Write", scratch.join("notes.md"));
    assert_eq!(v["decision"], "allow", "{v}");
    event(&mut e, "PostToolUse", "Write", scratch.join("notes.md"));
    assert_eq!(log_len(&mut e), before, "scratch writes are not facts");
    // A read there: observed, not external, no taint.
    event(&mut e, "PreToolUse", "Read", scratch.join("notes.md"));
    assert_eq!(log_len(&mut e), before + 1);
    let st = e.ok("status", Some("demo"), None, json!({}));
    let s1 = st["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "s1")
        .unwrap();
    assert_eq!(s1["taint"], Value::Null, "{s1}");
    // Outside both roots: denied, observed, and the session is tainted.
    let elsewhere = e.root.join("elsewhere.txt");
    let v = event(&mut e, "PreToolUse", "Write", elsewhere);
    assert_eq!(v["decision"], "deny");
    let st = e.ok("status", Some("demo"), None, json!({}));
    let s1 = st["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "s1")
        .unwrap();
    assert!(s1["taint"].is_string(), "{s1}");

    // A child may keep a root or drop it, not add one.
    let expires = e.now() + 60_000;
    let child =
        |roots: Vec<String>| json!({"agent": "bot", "scope": scope(roots), "expires_ms": expires});
    let r = e.ok(
        "cap.attenuate",
        None,
        Some(&token),
        child(vec![format!("{scratch_s}/sub")]),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let r = e.ok(
        "cap.attenuate",
        None,
        Some(&token),
        child(vec!["/tmp/other".into()]),
    );
    assert_eq!(
        r["decision"]["reasons"][0], "scope_widening:scratch:/tmp/other",
        "{r}"
    );
    let r = e.ok("cap.attenuate", None, Some(&token), child(vec![]));
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

/// `[taint]` in lonca.toml says what taints: with fetches, network
/// commands and an allow-listed MCP server switched off, a session that
/// did all three stays clean; by default each of them taints.
#[test]
fn the_taint_policy_is_repository_data() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let ws = e.root.join("ws");
    let calls = [
        ("WebFetch", json!({"url": "https://docs.rs/serde"})),
        ("Bash", json!({"command": "curl https://docs.rs"})),
        ("mcp__imece__send", json!({})),
    ];
    let taint_of = |e: &mut Env, id: &str| {
        let st = e.ok("status", Some("demo"), None, json!({}));
        let s = st["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["id"] == id)
            .unwrap()
            .clone();
        s["taint"].clone()
    };
    let t = e.session("s1", &["src/**"]);
    for (tool, input) in &calls {
        e.ok("hook.event", None, Some(&t), json!({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input, "workspace": ws}));
    }
    assert!(taint_of(&mut e, "s1").is_string(), "default taints");

    let config = lonca_policy::config::DEFAULT_CONFIG
        .replace("fetch = true", "fetch = false")
        .replace("shell_network = true", "shell_network = false")
        .replace("mcp_servers = []", "mcp_servers = [\"imece\"]");
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let t = e.session("s2", &["src/**"]);
    for (tool, input) in &calls {
        e.ok("hook.event", None, Some(&t), json!({"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": input, "workspace": ws}));
    }
    assert_eq!(taint_of(&mut e, "s2"), Value::Null);
    // Another server still taints; so does a file outside the workspace.
    e.ok("hook.event", None, Some(&t), json!({"hook_event_name": "PreToolUse", "tool_name": "mcp__github__get_issue", "tool_input": {}, "workspace": ws}));
    assert!(taint_of(&mut e, "s2").is_string());
    let t = e.session("s3", &["src/**"]);
    e.ok("hook.event", None, Some(&t), json!({"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": "/etc/hosts"}, "workspace": ws}));
    assert!(taint_of(&mut e, "s3").is_string());
    // An unknown key in [taint] does not parse.
    let bad =
        lonca_policy::config::DEFAULT_CONFIG.replace("fetch = true", "fetch = true\nweb = false");
    assert!(
        lonca_policy::config::PolicyBundle::parse(&bad, lonca_policy::config::DEFAULT_POLICY)
            .is_err()
    );
}

/// `tree` carries sizes; `blobs` pages contents of one commit and
/// refuses what does not fit a page or belong to the commit.
#[test]
fn trees_are_fetched_in_pages() {
    use lonca_daemon::service::page_budget;
    let mut e = Env::new();
    e.init(None);
    let big = "x".repeat(3000);
    e.human_change(
        vec![
            file("a.txt", "aaa\n"),
            file("big.bin", &big),
            file("edge.bin", &"e".repeat(2304)),
            file("src/lib.rs", LIB),
        ],
        "seed",
    );
    e.svc.process_all();
    let trunk = e.trunk();
    let manifest = e.ok("tree", Some("demo"), None, json!({"commit": trunk}));
    let sizes: Vec<(String, u64)> = manifest
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["path"].as_str().unwrap().to_string(),
                f["size"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(sizes[0], ("a.txt".into(), 4));
    assert_eq!(sizes[1], ("big.bin".into(), 3000));
    assert!(manifest[0]["content_b64"].is_null());

    let page = e.ok(
        "blobs",
        Some("demo"),
        None,
        json!({"commit": trunk, "paths": ["a.txt", "src/lib.rs"]}),
    );
    assert_eq!(page[0]["path"], "a.txt");
    assert_eq!(page[0]["content_b64"], b64("aaa\n"));
    assert_eq!(page[1]["size"], LIB.len());
    assert_eq!(page.as_array().unwrap().len(), 2);
    let err = e
        .call(
            "blobs",
            Some("demo"),
            None,
            json!({"commit": trunk, "paths": ["nope.txt"]}),
        )
        .unwrap_err();
    assert_eq!(err.0, "not_found", "{err:?}");
    let err = e
        .call(
            "blobs",
            Some("demo"),
            None,
            json!({"commit": trunk, "paths": []}),
        )
        .unwrap_err();
    assert_eq!(err.0, "invalid");
    // The same path at an earlier commit, where it does not exist yet.
    let genesis = e.ok("log", Some("demo"), None, json!({"from": 0, "limit": 1}))[0]["entry"]["op"]
        ["trunk"]
        .clone();
    let err = e
        .call(
            "blobs",
            Some("demo"),
            None,
            json!({"commit": genesis, "paths": ["a.txt"]}),
        )
        .unwrap_err();
    assert_eq!(err.0, "not_found", "{err:?}");

    // A daemon with a small line cap: a page over the budget is refused,
    // a file over it is refused by name, two small files fit.
    let settings = Settings {
        line_cap: 4096,
        proxy: None,
        ..e.settings.clone()
    };
    let budget = page_budget(4096);
    assert_eq!(budget, 3072);
    let c = e.clock.clone();
    let small = Service::open(
        Home::new(e.root.join("home")),
        settings,
        Arc::new(move || c.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap();
    let token = e.human_token.clone().unwrap();
    let call = |method: &str, params: Value| {
        let r = small.handle(Request {
            id: 1,
            method: method.into(),
            repo: Some("demo".into()),
            token: Some(token.clone()),
            params,
        });
        if r.ok {
            Ok(r.result)
        } else {
            Err(r.error.map(|e| (e.code, e.message)).unwrap())
        }
    };
    let err = call("blobs", json!({"commit": trunk, "paths": ["big.bin"]})).unwrap_err();
    assert_eq!(err.0, "too_large", "{err:?}");
    assert!(err.1.contains("big.bin is 3000 bytes"), "{err:?}");
    let ok = call(
        "blobs",
        json!({"commit": trunk, "paths": ["a.txt", "src/lib.rs"]}),
    )
    .unwrap();
    assert_eq!(ok.as_array().unwrap().len(), 2);
    let many: Vec<String> = (0..40).map(|_| "src/lib.rs".to_string()).collect();
    let err = call("blobs", json!({"commit": trunk, "paths": many})).unwrap_err();
    assert_eq!(err.0, "too_large");
    assert!(err.1.contains("fewer files"), "{err:?}");
    // A file that encodes to exactly the budget (2304 bytes -> 3072) fits;
    // one byte more in the page does not.
    let ok = call("blobs", json!({"commit": trunk, "paths": ["edge.bin"]})).unwrap();
    assert_eq!(ok[0]["size"], 2304);
    let err = call(
        "blobs",
        json!({"commit": trunk, "paths": ["edge.bin", "a.txt"]}),
    )
    .unwrap_err();
    assert_eq!(err.0, "too_large", "{err:?}");

    // A redacted blob: listed with its size, never with its content.
    let a_blob = manifest[0]["blob"].as_str().unwrap().to_string();
    e.human(Op::Redact {
        blob: GitId::parse(&a_blob).unwrap(),
        reason: "secret".into(),
    });
    let page = e.ok(
        "blobs",
        Some("demo"),
        None,
        json!({"commit": trunk, "paths": ["a.txt", "src/lib.rs"]}),
    );
    assert_eq!(page[0]["path"], "a.txt");
    assert_eq!(page[0]["size"], 4);
    assert_eq!(page[0]["content_b64"], Value::Null, "{page}");
    assert!(page[1]["content_b64"].is_string());

    // Importing a tree with a file above the change cap says so.
    let up = e.root.join("up.git");
    git(&e.root, &["init", "-q", "--bare", up.to_str().unwrap()]);
    let work = e.root.join("work");
    git(&e.root, &["init", "-q", work.to_str().unwrap()]);
    std::fs::write(work.join("huge.bin"), vec![b'z'; 2 * 1024 * 1024 + 1]).unwrap();
    // Exactly the cap is not above it.
    std::fs::write(work.join("exact.bin"), vec![b'y'; 2 * 1024 * 1024]).unwrap();
    std::fs::write(work.join("small.txt"), "s\n").unwrap();
    git(&work, &["add", "."]);
    git(
        &work,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "x",
        ],
    );
    git(&work, &["branch", "-M", "main"]);
    git(&work, &["push", "-q", up.to_str().unwrap(), "main"]);
    let key = HumanKey {
        alg: "ed25519".into(),
        public: e.human.public_hex(),
    };
    let prep = e.ok(
        "repo.prepare_init",
        None,
        None,
        json!({"repo": "media", "human": "ayse", "human_key": key, "import_from": up}),
    );
    assert_eq!(prep["large_files"][0]["path"], "huge.bin");
    assert_eq!(prep["large_files"].as_array().unwrap().len(), 1, "{prep}");
    assert_eq!(prep["tree_bytes"].as_u64().unwrap(), 4 * 1024 * 1024 + 3);
    let warnings = prep["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .starts_with("huge.bin is 2097153 bytes, above the change cap")
    );

    // Under the small line cap the same tree is more than one page; a
    // tree that encodes to exactly the page budget is not.
    let prep = call(
        "repo.prepare_init",
        json!({"repo": "media-small", "human": "ayse", "human_key": key.clone(), "import_from": up}),
    )
    .unwrap();
    let warnings: Vec<&str> = prep["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        warnings.iter().any(|w| w.contains("more than one page")),
        "{warnings:?}"
    );
    let up2 = e.root.join("up2.git");
    git(&e.root, &["init", "-q", "--bare", up2.to_str().unwrap()]);
    let work2 = e.root.join("work2");
    git(&e.root, &["init", "-q", work2.to_str().unwrap()]);
    std::fs::write(work2.join("page.bin"), vec![b'p'; 2304]).unwrap();
    git(&work2, &["add", "."]);
    git(
        &work2,
        &[
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "-m",
            "x",
        ],
    );
    git(&work2, &["branch", "-M", "main"]);
    git(&work2, &["push", "-q", up2.to_str().unwrap(), "main"]);
    let prep = call(
        "repo.prepare_init",
        json!({"repo": "page-exact", "human": "ayse", "human_key": key, "import_from": up2}),
    )
    .unwrap();
    assert_eq!(prep["tree_bytes"], 2304);
    assert_eq!(prep["warnings"], json!([]), "{prep}");
}

/// A path is a path to git too: a file whose name is pathspec magic
/// (`:!src/lib.rs`, "everything but") or a glob (`src/*`) takes no other
/// file out of the reviewer's diff and adds none to its own.
#[test]
fn a_diff_takes_every_path_literally() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let token = e.session("s1", &["**"]);
    e.bind(&token);
    let magic = [":!src/lib.rs", ":(exclude)src/lib.rs", "src/*"];
    for path in magic.iter().chain(&["src/lib.rs"]) {
        e.wrote(&token, path);
    }
    e.lease(&token, "src/lib.rs#charge");
    for path in magic {
        e.lease(&token, &format!("{path}#<file>"));
    }
    let new = LIB.replacen("    a\n", "    a * 2\n", 1);
    let mut files = vec![file("src/lib.rs", &new)];
    files.extend(magic.iter().map(|p| file(p, "one\n")));
    let r = e.propose(&token, &base, files, &["src/lib.rs#charge"]);
    assert_ne!(r["decision"]["outcome"], "deny", "{r}");

    let d = e.ok(
        "change.diff",
        Some("demo"),
        None,
        json!({"change": r["change"]}),
    );
    let diff = d["diff"].as_str().unwrap();
    assert!(diff.contains("+    a * 2"), "{diff}");
    let files = d["files"].as_array().unwrap();
    assert_eq!(files.len(), 4, "{d}");
    for f in files {
        let (added, removed) = if f["path"] == "src/lib.rs" {
            (1, 1)
        } else {
            (1, 0)
        };
        assert_eq!(
            (f["added"].as_u64(), f["removed"].as_u64()),
            (Some(added), Some(removed)),
            "{f}"
        );
        assert!(
            diff.contains(&format!("b/{}", f["path"].as_str().unwrap())),
            "{diff}"
        );
    }
}

/// The diff and the evidence of a change come from the daemon: files
/// with counts and symbols, redaction applied, a cap, and the checks of
/// the last integration with their log tails.
#[test]
fn a_reviewer_gets_the_diff_and_the_evidence_from_the_daemon() {
    use lonca_daemon::service::DIFF_CAP_BYTES;
    let mut e = Env::new();
    e.init(None);
    e.human_change(
        vec![
            file("src/lib.rs", LIB),
            file("notes.md", "a\nb\n"),
            file(
                "check.sh",
                "yes 'BUILD BROKEN' | head -c 40000; grep -q 'a \\* 2' src/lib.rs\n",
            ),
        ],
        "seed",
    );
    e.svc.process_all();
    let base = e.trunk();
    let token = e.session("s1", &["src/**", "notes.md"]);
    e.bind(&token);
    e.wrote(&token, "src/lib.rs");
    e.wrote(&token, "notes.md");
    e.lease(&token, "src/lib.rs#charge");
    e.lease(&token, "notes.md#<file>");
    let new = LIB.replacen("    a\n", "    a * 2\n", 1);
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &new), file("notes.md", "a\nc\n")],
        &["src/lib.rs#charge", "notes.md#<file>"],
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let change = r["change"].clone();

    let d = e.ok("change.diff", Some("demo"), None, json!({"change": change}));
    assert_eq!(d["format"], "unified");
    assert_eq!(d["base"], json!(base));
    assert_eq!(d["truncated"], false);
    let files = d["files"].as_array().unwrap();
    assert_eq!(files.len(), 2, "{d}");
    assert_eq!(files[0]["path"], "notes.md");
    assert_eq!(files[0]["status"], "modified");
    assert_eq!(
        (files[0]["added"].as_u64(), files[0]["removed"].as_u64()),
        (Some(1), Some(1))
    );
    assert_eq!(files[1]["path"], "src/lib.rs");
    assert_eq!(files[1]["symbols"]["edits"], json!(["src/lib.rs#charge"]));
    let diff = d["diff"].as_str().unwrap();
    assert!(
        diff.contains("--- a/src/lib.rs") && diff.contains("+    a * 2") && diff.contains("-b\n+c"),
        "{diff}"
    );
    assert_eq!(
        code(e.call(
            "change.diff",
            Some("demo"),
            None,
            json!({"change": change, "format": "side-by-side"})
        )),
        "invalid"
    );
    assert_eq!(
        code(e.call(
            "change.diff",
            Some("demo"),
            None,
            json!({"change": ChangeId::random()})
        )),
        "not_found"
    );
    // `pending` shows 12 letters; they name the change.
    let whole = change.as_str().unwrap();
    for typed in [&whole[..12], &whole[..4], whole] {
        let r = e.ok(
            "change.resolve",
            Some("demo"),
            None,
            json!({"prefix": typed}),
        );
        assert_eq!(r, json!({"change": whole}), "{typed}");
    }
    for typed in ["zyx", "ABCD", "abcd", ""] {
        let r = e.call(
            "change.resolve",
            Some("demo"),
            None,
            json!({"prefix": typed}),
        );
        assert_eq!(code(r), "invalid", "{typed}");
    }
    let other = ChangeId::random().to_string();
    let r = e.call(
        "change.resolve",
        Some("demo"),
        None,
        json!({"prefix": &other[..12]}),
    );
    assert_eq!(code(r), "not_found");
    assert!(
        e.anon(
            "change.resolve",
            None,
            Some(&token),
            json!({"prefix": &whole[..12]})
        )
        .is_ok()
    );
    assert_eq!(
        code(e.anon(
            "change.resolve",
            Some("other"),
            Some(&token),
            json!({"prefix": &whole[..12]})
        )),
        "forbidden"
    );
    // An agent reads the diff of its own repository only.
    assert!(
        e.anon("change.diff", None, Some(&token), json!({"change": change}))
            .is_ok()
    );
    assert_eq!(
        code(e.anon(
            "change.diff",
            Some("other"),
            Some(&token),
            json!({"change": change})
        )),
        "forbidden"
    );

    // Before any integration there is no evidence; the test command then
    // fails and its output is in the evidence.
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["evidence"], json!([]));
    assert_eq!(rec["integrate_seq"], Value::Null);
    let config = lonca_policy::config::DEFAULT_CONFIG
        .replace(
            "# test = \"cargo test --offline\"",
            "test = \"sh check.sh\"",
        )
        .replace(
            "\nidentify = []\n",
            "\nidentify = [\"echo toolchain 1.2.3\", \"exit 4\"]\n",
        );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    // The queued change integrates under the new policy: the check passes
    // (a * 2 is there) and the log says BUILD BROKEN anyway.
    e.svc.process_all();
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["status"]["status"], "integrated", "{rec}");
    let ev = rec["evidence"].as_array().unwrap();
    let tests = ev
        .iter()
        .find(|a| a["check"] == "tests")
        .expect("tests check");
    assert_eq!(tests["result"], "pass");
    assert_eq!(tests["exit"], 0);
    assert!(
        tests["log"].as_str().unwrap().contains("BUILD BROKEN"),
        "{tests}"
    );
    // 40 KB of output: the tail is kept, 32 KiB of it, and it says so.
    assert_eq!(tests["log_truncated"], true, "{tests}");
    assert_eq!(tests["log"].as_str().unwrap().len(), 32 * 1024);
    assert!(tests["sandbox"].is_string());
    // The environment it ran in: a digest, and what identify printed.
    assert_eq!(tests["env"].as_str().unwrap().len(), 64, "{tests}");
    assert_eq!(
        tests["environment"],
        json!([
            {"command": "echo toolchain 1.2.3", "output": "toolchain 1.2.3", "error": null},
            {"command": "exit 4", "output": "", "error": "exit 4"},
        ])
    );
    assert!(rec["integrate_seq"].as_u64().is_some());
    assert_eq!(rec["integrate_decision"]["outcome"], "allow");
    let first_integrate = rec["integrate_seq"].as_u64().unwrap();

    // A failing check: result fail, exit 1, the output kept.
    let base = e.trunk();
    e.wrote(&token, "src/lib.rs");
    e.lease(&token, "src/lib.rs#charge");
    let bad = new.replacen("    a * 2\n", "    a * 3\n", 1);
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &bad)],
        &["src/lib.rs#charge"],
    );
    let failing = r["change"].clone();
    e.svc.process_all();
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": failing}));
    assert_eq!(rec["status"]["status"], "rejected", "{rec}");
    let tests = rec["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["check"] == "tests")
        .unwrap()
        .clone();
    assert_eq!(tests["result"], "fail");
    assert_eq!(tests["exit"], 1);
    assert!(tests["log"].as_str().unwrap().contains("BUILD BROKEN"));
    assert_eq!(rec["integrate_decision"]["outcome"], "deny");

    // A redacted log blob is withheld: null, not its tail.
    let seq = first_integrate;
    let entry = e.ok("log", Some("demo"), None, json!({"from": seq, "limit": 1}));
    let log_blob = entry[0]["entry"]["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["check"] == "tests")
        .unwrap()["log"]
        .as_str()
        .unwrap()
        .to_string();
    e.human(Op::Redact {
        blob: GitId::parse(&log_blob).unwrap(),
        reason: "the log leaked a secret".into(),
    });
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    let tests = rec["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["check"] == "tests")
        .unwrap()
        .clone();
    assert_eq!(tests["log"], Value::Null, "{tests}");
    assert_eq!(tests["log_truncated"], false);
    assert_eq!(tests["result"], "pass");

    // Redaction: a redacted blob's file is out of the diff and named.
    let trunk = e.trunk();
    let st = e.ok("tree", Some("demo"), None, json!({"commit": trunk}));
    let notes_blob = st
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "notes.md")
        .unwrap()["blob"]
        .as_str()
        .unwrap()
        .to_string();
    e.human(Op::Redact {
        blob: GitId::parse(&notes_blob).unwrap(),
        reason: "secret".into(),
    });
    let d = e.ok("change.diff", Some("demo"), None, json!({"change": change}));
    assert_eq!(d["redacted"], json!(["notes.md"]));
    assert_eq!(d["files"].as_array().unwrap().len(), 1);
    assert!(!d["diff"].as_str().unwrap().contains("notes.md"));

    // A diff over the cap is cut on a line boundary and says so: two
    // files under the per-file cap whose diff together is over it.
    let big: String = (0..35_000)
        .map(|i| format!("line {i:08} {}\n", "x".repeat(20)))
        .collect();
    assert!(big.len() < 2 * 1024 * 1024 && 2 * big.len() > DIFF_CAP_BYTES);
    let base = e.trunk();
    for path in ["src/big1.rs", "src/big2.rs"] {
        e.wrote(&token, path);
        e.lease(&token, &format!("{path}#<file>"));
    }
    let r = e.propose(
        &token,
        &base,
        vec![file("src/big1.rs", &big), file("src/big2.rs", &big)],
        &[],
    );
    assert_ne!(r["decision"]["outcome"], "deny", "{r}");
    let d = e.ok(
        "change.diff",
        Some("demo"),
        None,
        json!({"change": r["change"]}),
    );
    assert_eq!(d["truncated"], true);
    let text = d["diff"].as_str().unwrap();
    assert!(text.len() <= DIFF_CAP_BYTES && text.ends_with('\n'));
    assert_eq!(d["files"][0]["added"], 35_000);
    assert_eq!(d["files"][1]["path"], "src/big2.rs");
}

/// Propose, reject with a reason, read the reason; the leases are free,
/// the pending list empty; the next proposal integrates after approval.
/// A proposal outlives its session's expiry; an ended session withdraws.
#[test]
fn a_rejection_carries_its_reason_to_the_worker_and_frees_the_leases() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    // Unobserved session: every proposal escalates.
    let token = e.session("s1", &["src/**"]);
    e.lease(&token, "src/lib.rs#charge");
    // A second lease set, on a symbol the change does not touch, outlives
    // the rejection; only the covering set is released.
    let other = e.lease(&token, "src/lib.rs#refund")["set"].clone();
    let new = LIB.replacen("    a\n", "    a * 2\n", 1);
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &new)],
        &["src/lib.rs#charge"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let seq = r["seq"].as_u64().unwrap();
    let change = r["change"].clone();

    // A human change queued meanwhile is not the rejection's business.
    let r = e.human_change(vec![file("notes.md", "queued\n")], "queued");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let d = e.human(Op::Reject {
        target_seq: seq,
        reason: "charge must not double; see the spec".into(),
    });
    assert_eq!(d["decision"]["outcome"], "allow", "{d}");
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["status"]["status"], "rejected");
    assert_eq!(
        rec["status"]["reasons"],
        json!(["rejected: charge must not double; see the spec"])
    );
    let st = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(st["pending"], json!([]));
    assert_eq!(st["leases"].as_array().unwrap().len(), 1, "{st}");
    assert_eq!(st["leases"][0]["set"], other);
    assert_eq!(st["leases"][0]["items"][0]["symbol"], "src/lib.rs#refund");
    assert_eq!(st["queue"].as_array().unwrap().len(), 1, "{st}");
    assert_eq!(e.svc.process_all(), 1, "the queued change integrates");

    // The worker reads the reason, fixes, leases again, proposes again.
    e.lease(&token, "src/lib.rs#charge");
    let fixed = LIB.replacen("    a\n", "    a + 1\n", 1);
    let r = e.propose(
        &token,
        &base,
        vec![file("src/lib.rs", &fixed)],
        &["src/lib.rs#charge"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate");
    let seq2 = r["seq"].as_u64().unwrap();
    // Reject needs a reason, a pending target, and a human.
    let d = e.human(Op::Reject {
        target_seq: seq,
        reason: "late".into(),
    });
    assert_eq!(d["decision"]["reasons"][0], "nothing_pending");
    let d = e.human(Op::Reject {
        target_seq: seq2,
        reason: "".into(),
    });
    assert_eq!(d["decision"]["reasons"][0], "reason_required");
    let r = e.call(
        "human.submit",
        Some("demo"),
        Some(&token),
        e.sign(&Op::Reject {
            target_seq: seq2,
            reason: "x".into(),
        }),
    );
    assert_eq!(r.unwrap_err().0, "forbidden");

    // The session expires before the human decides: still approvable.
    e.advance(3_600_001);
    let st = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(st["sessions"][0]["active"], false);
    assert_eq!(st["pending"][0]["seq"], seq2);
    let d = e.human(Op::Approve {
        target_seq: seq2,
        note: "ok".into(),
        checks: vec![],
    });
    assert!(
        d["decision"]["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x == "released"),
        "{d}"
    );
    assert_eq!(e.svc.process_all(), 1);
    assert_eq!(
        e.store()
            .read_file(&e.trunk(), "src/lib.rs")
            .unwrap()
            .unwrap(),
        fixed.as_bytes()
    );

    // A session ended by its agent leaves its proposal for the human; a
    // session revoked by a human takes it with it.
    let base = e.trunk();
    let t2 = e.session("s2", &["src/**"]);
    e.lease(&t2, "src/lib.rs#refund");
    let r = e.propose(
        &t2,
        &base,
        vec![file(
            "src/lib.rs",
            &fixed.replacen(
                "pub fn refund(a: u64) -> u64 {\n    a\n",
                "pub fn refund(a: u64) -> u64 {\n    0\n",
                1,
            ),
        )],
        &["src/lib.rs#refund"],
    );
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    e.ok("session.end", None, Some(&t2), json!({}));
    let rec = e.ok(
        "change.get",
        Some("demo"),
        None,
        json!({"change": r["change"]}),
    );
    assert_eq!(rec["status"]["status"], "pending");
    assert_eq!(
        e.ok("status", Some("demo"), None, json!({}))["pending"][0]["seq"],
        r["seq"]
    );
    // What the ended session proposed still holds its symbols, past the
    // TTL of the lease, and status says why.
    let t3 = e.session("s3", &["src/**"]);
    e.advance(601_000);
    let denied = e.lease(&t3, "src/lib.rs#refund");
    assert_eq!(denied["decision"]["outcome"], "deny", "{denied}");
    let leases = e.ok("status", Some("demo"), None, json!({}))["leases"].clone();
    assert_eq!(leases.as_array().unwrap().len(), 1, "{leases}");
    assert_eq!(leases[0]["session"], "s2");
    assert_eq!(leases[0]["items"][0]["symbol"], "src/lib.rs#refund");
    assert_eq!(leases[0]["pinned"][0]["change"], r["change"], "{leases}");
    assert_eq!(leases[0]["pinned"][0]["items"], leases[0]["items"]);
    e.lease(&t3, "src/lib.rs#charge");
    let r3 = e.propose(
        &t3,
        &base,
        vec![file(
            "src/lib.rs",
            &fixed.replacen("    a + 1\n", "    a + 2\n", 1),
        )],
        &["src/lib.rs#charge"],
    );
    assert_eq!(r3["decision"]["outcome"], "escalate", "{r3}");
    e.human(Op::CapRevoke {
        session: "s3".into(),
        reason: "done".into(),
    });
    let rec = e.ok(
        "change.get",
        Some("demo"),
        None,
        json!({"change": r3["change"]}),
    );
    assert_eq!(rec["status"]["status"], "withdrawn");
    let pending = e.ok("status", Some("demo"), None, json!({}))["pending"].clone();
    assert_eq!(pending.as_array().unwrap().len(), 1, "{pending}");
    assert_eq!(pending[0]["seq"], r["seq"]);
}

/// Trunk reaches a git checkout as a bundle through the daemon, thin
/// against what the checkout has; redacted history is refused; the
/// distance of an old trunk is counted from the log.
#[test]
fn a_checkout_fetches_trunk_as_a_bundle_and_learns_how_far_behind_it_is() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let t0 = e.trunk();
    let r = e.ok("trunk.bundle", Some("demo"), None, json!({}));
    assert_eq!(r["trunk"], json!(t0));
    assert_eq!(r["thin"], false);
    assert_eq!(r["up_to_date"], false);
    let same = e.ok("trunk.bundle", Some("demo"), None, json!({"have": [t0]}));
    assert_eq!(same["up_to_date"], true);
    assert_eq!(same["bytes"], 0);
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(r["bundle_b64"].as_str().unwrap())
        .unwrap();
    assert_eq!(bytes.len() as u64, r["bytes"].as_u64().unwrap());
    let bundle = e.root.join("t.bundle");
    std::fs::write(&bundle, &bytes).unwrap();
    let co = e.root.join("co");
    git(&e.root, &["init", "-q", co.to_str().unwrap()]);
    git(
        &co,
        &[
            "fetch",
            "-q",
            bundle.to_str().unwrap(),
            "+refs/heads/main:refs/lonca/trunk",
        ],
    );
    assert_eq!(git(&co, &["rev-parse", "refs/lonca/trunk"]), t0.to_string());
    assert_eq!(
        git(&co, &["show", "refs/lonca/trunk:src/lib.rs"]),
        LIB.trim_end()
    );

    // Three more integrations: a thin bundle against t0 is smaller and
    // brings the checkout up; t0 is three behind, t1 two, trunk zero.
    for i in 1..=3 {
        e.human_change(
            vec![file(&format!("n{i}.md"), &format!("note {i}\n"))],
            "more",
        );
        e.svc.process_all();
    }
    let t3 = e.trunk();
    let full = e.ok("trunk.bundle", Some("demo"), None, json!({}))["bytes"]
        .as_u64()
        .unwrap();
    let r = e.ok(
        "trunk.bundle",
        Some("demo"),
        None,
        json!({"have": [t0, GitId::parse(&"0".repeat(40)).unwrap()]}),
    );
    assert_eq!(r["thin"], true);
    assert!(r["bytes"].as_u64().unwrap() < full, "{r}");
    std::fs::write(
        &bundle,
        base64::engine::general_purpose::STANDARD
            .decode(r["bundle_b64"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    git(
        &co,
        &[
            "fetch",
            "-q",
            bundle.to_str().unwrap(),
            "+refs/heads/main:refs/lonca/trunk",
        ],
    );
    assert_eq!(git(&co, &["rev-parse", "refs/lonca/trunk"]), t3.to_string());
    assert!(git(&co, &["ls-tree", "--name-only", "refs/lonca/trunk"]).contains("n3.md"));
    let d = e.ok("trunk.distance", Some("demo"), None, json!({"base": t0}));
    assert_eq!(d["behind"], 3);
    assert_eq!(d["trunk"], json!(t3));
    let st = e.ok("log", Some("demo"), None, json!({}));
    let t1 = st
        .as_array()
        .unwrap()
        .iter()
        .find_map(|o| {
            (o["entry"]["op"]["op"] == "change.integrate"
                && o["entry"]["op"]["merged"] != json!(t0)
                && o["entry"]["decision"]["outcome"] == "allow")
                .then(|| o["entry"]["op"]["merged"].clone())
        })
        .unwrap();
    assert_eq!(
        e.ok("trunk.distance", Some("demo"), None, json!({"base": t1}))["behind"],
        2
    );
    assert_eq!(
        e.ok("trunk.distance", Some("demo"), None, json!({"base": t3}))["behind"],
        0
    );
    assert_eq!(
        e.ok(
            "trunk.distance",
            Some("demo"),
            None,
            json!({"base": GitId::parse(&"1".repeat(40)).unwrap()})
        )["behind"],
        Value::Null
    );

    // A daemon with a tiny line cap refuses a bundle that does not fit
    // one page, by size.
    let settings = Settings {
        line_cap: 256,
        proxy: None,
        ..e.settings.clone()
    };
    let c = e.clock.clone();
    let small = Service::open(
        Home::new(e.root.join("home")),
        settings,
        Arc::new(move || c.fetch_add(1, Ordering::SeqCst)),
    )
    .unwrap();
    let token = e.human_token.clone().unwrap();
    let r = small.handle(Request {
        id: 1,
        method: "trunk.bundle".into(),
        repo: Some("demo".into()),
        token: Some(token),
        params: json!({"have": [t0]}),
    });
    let err = r.error.expect("refused");
    assert_eq!(err.code, "too_large", "{}", err.message);
    assert!(
        err.message.contains("more than one page"),
        "{}",
        err.message
    );

    // A redacted blob on trunk's history: no bundle.
    let files = e.ok("tree", Some("demo"), None, json!({"commit": t3}));
    let blob = files
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["path"] == "n2.md")
        .unwrap()["blob"]
        .as_str()
        .unwrap()
        .to_string();
    e.human(Op::Redact {
        blob: GitId::parse(&blob).unwrap(),
        reason: "secret".into(),
    });
    let err = e
        .call("trunk.bundle", Some("demo"), None, json!({}))
        .unwrap_err();
    assert_eq!(err.0, "redacted", "{err:?}");
    assert!(err.1.contains("n2.md"), "{err:?}");
    // Thin against a point past the redacted object: still refused, the
    // object is in the history the bundle carries.
    let err = e
        .call("trunk.bundle", Some("demo"), None, json!({"have": [t0]}))
        .unwrap_err();
    assert_eq!(err.0, "redacted");
}

/// A heartbeat is logged, recorded and answered with what a client needs:
/// the timeout, the longest TTL, its own leases on the daemon's clock.
#[test]
fn a_heartbeat_keeps_leases_and_stopping_frees_them() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let a = e.session("a", &["src/**"]);
    let b = e.session("b", &["src/**"]);
    let set = e.lease(&a, "src/lib.rs#charge")["set"].clone();
    e.lease(&b, "src/lib.rs#refund");
    let session = |e: &mut Env, id: &str| {
        let s = e.ok("status", Some("demo"), None, json!({}));
        let all = s["sessions"].as_array().unwrap();
        all.iter().find(|x| x["id"] == id).unwrap().clone()
    };
    assert_eq!(session(&mut e, "a")["last_seen_ms"], Value::Null);

    let before = e.ok("status", Some("demo"), None, json!({}))["next_seq"].clone();
    let r = e.ok("session.heartbeat", None, Some(&a), json!({}));
    assert_eq!(r["seq"], before);
    assert_eq!(r["decision"]["outcome"], "allow");
    assert_eq!(r["decision"]["reasons"][0], "heartbeat_timeout=300000");
    assert_eq!(r["timeout_ms"], 300_000);
    assert_eq!(r["max_ttl_ms"], 1_800_000);
    let now = r["now_ms"].as_i64().unwrap();
    assert!(now > 0);
    assert_eq!(
        r["leases"].as_array().unwrap().len(),
        1,
        "only its own: {r}"
    );
    assert_eq!(r["leases"][0]["set"], set);
    let left = r["leases"][0]["expires_ms"].as_i64().unwrap() - now;
    assert!(left > 590_000 && left < 600_000, "{left}");
    assert_eq!(session(&mut e, "a")["last_seen_ms"], now);

    e.advance(300_001);
    let free = e.lease(&b, "src/lib.rs#charge");
    assert_eq!(free["decision"]["outcome"], "allow", "{free}");
    let r = e.ok("session.heartbeat", None, Some(&a), json!({}));
    assert_eq!(r["leases"], json!([]));

    // A human session has no heartbeat, and no token has none.
    assert_eq!(
        e.call("session.heartbeat", Some("demo"), None, json!({}))
            .unwrap_err()
            .0,
        "forbidden"
    );
    assert_eq!(
        e.anon("session.heartbeat", Some("demo"), None, json!({}))
            .unwrap_err()
            .0,
        "unauthenticated"
    );
}

/// A denial says who holds what, as data: the intent is quoted, however
/// many colons it has, each held item appears once, and nothing of this
/// reaches the log.
#[test]
fn a_denied_lease_carries_details_and_the_log_entry_stays_as_it_was() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let a = e.session("a", &["src/**"]);
    let b = e.session("b", &["src/**"]);
    let intent = "fix: the \"charge\": rounding";
    let item = |symbol: &str, kind: &str| json!({"symbol": symbol, "kind": kind});
    let got = e.ok(
        "lease.acquire",
        None,
        Some(&a),
        json!({"items": [item("src/lib.rs#charge", "edit")], "intent": intent, "ttl_ms": 600_000}),
    );
    assert_eq!(got["details"], json!([]), "{got}");
    let set = got["set"].clone();
    let expires = e.ok("status", Some("demo"), None, json!({}))["leases"][0]["expires_ms"].clone();

    // Two requested items run into one held item: one detail.
    let r = e.ok(
        "lease.acquire",
        None,
        Some(&b),
        json!({"items": [item("src/lib.rs#charge", "edit"), item("src/lib.rs#<file>", "edit")],
               "intent": "mine", "ttl_ms": 600_000}),
    );
    assert_eq!(r["decision"]["outcome"], "deny");
    let details = r["details"].as_array().unwrap();
    assert_eq!(details.len(), 1, "{r}");
    let d = &details[0];
    assert_eq!(d["code"], "lease_held");
    assert_eq!(d["symbol"], "src/lib.rs#charge");
    assert_eq!(d["needed_kind"], "edit");
    assert_eq!(d["holder_session"], "a");
    assert_eq!(d["holder_agent"], "bot-a");
    assert_eq!(d["intent"], intent);
    assert_eq!(d["expires_ms"], expires);
    assert_eq!(d["set"], set);
    assert_eq!(d["pinned_to"], Value::Null);
    assert!(!r.to_string().contains(&a) && !r.to_string().contains(&b));

    // The entry has the old reasons and no trace of the details.
    let seq = r["seq"].as_u64().unwrap();
    let logged = e.ok("log", Some("demo"), None, json!({"from": seq, "limit": 1}));
    let entry = &logged[0]["entry"];
    assert_eq!(
        entry["decision"]["reasons"][0],
        format!("lease_held:src/lib.rs#charge:a:{intent}")
    );
    assert_eq!(entry["decision"]["reasons"].as_array().unwrap().len(), 1);
    assert!(!entry.to_string().contains("details"), "{entry}");
    assert!(!entry.to_string().contains("holder_session"));
    let report = lonca_audit::audit(&e.store(), lonca_audit::Options::default()).unwrap();
    assert!(report.ok(), "{:#?}", report.findings);
}

/// A proposal lacking a lease is told which kind it needed and who holds
/// it; `facts.preview` says the same before anyone proposes.
#[test]
fn a_proposal_and_a_preview_say_which_leases_are_missing() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let a = e.session("a", &["src/**"]);
    let b = e.session("b", &["src/**"]);
    e.lease(&a, "src/lib.rs#charge");
    let both = LIB
        .replacen("    a\n", "    a + 1\n", 1)
        .replacen("    a\n", "    a + 2\n", 1)
        + "\npub fn extra() {}\n";
    let files = vec![file("src/lib.rs", &both)];
    let p = e.ok(
        "facts.preview",
        None,
        Some(&b),
        json!({"base": base, "files": files}),
    );
    let by = |list: &Value, symbol: &str| {
        let all = list.as_array().unwrap();
        all.iter().find(|d| d["symbol"] == symbol).unwrap().clone()
    };
    let leases = p["leases"].clone();
    assert_eq!(leases.as_array().unwrap().len(), 3, "{p}");
    let charge = by(&leases, "src/lib.rs#charge");
    assert_eq!(charge["code"], "lease_held");
    assert_eq!(charge["holder_session"], "a");
    assert_eq!(by(&leases, "src/lib.rs#refund")["code"], "free");
    let file_lease = by(&leases, "src/lib.rs#<file>");
    assert_eq!(file_lease["code"], "free");
    assert_eq!(file_lease["needed_kind"], "insert");
    assert_eq!(
        p["acquire"],
        json!([
            {"symbol": "src/lib.rs#<file>", "kind": "insert", "names": ["extra"]},
            {"symbol": "src/lib.rs#refund", "kind": "edit"},
        ])
    );

    let claim = Claim {
        intent: "both".into(),
        edits: vec!["src/lib.rs#charge".into(), "src/lib.rs#refund".into()],
        adds: vec!["src/lib.rs#extra".into()],
        ..Default::default()
    };
    let r = e.ok(
        "change.propose",
        None,
        Some(&b),
        json!({"base": base, "files": files, "claim": claim}),
    );
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    let details = r["details"].clone();
    assert_eq!(details.as_array().unwrap().len(), 3, "{r}");
    assert!(
        details
            .as_array()
            .unwrap()
            .iter()
            .all(|d| d["code"] == "lease_missing")
    );
    assert_eq!(by(&details, "src/lib.rs#charge")["holder_session"], "a");
    assert_eq!(
        by(&details, "src/lib.rs#refund")["holder_session"],
        Value::Null
    );

    // Holding the leases, the report says so and the proposal has no details.
    let t = e.session("c", &["src/**"]);
    e.lease(&t, "src/lib.rs#refund");
    let one = LIB.replacen(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        "pub fn refund(a: u64) -> u64 {\n    0\n",
        1,
    );
    let files = vec![file("src/lib.rs", &one)];
    let p = e.ok(
        "facts.preview",
        None,
        Some(&t),
        json!({"base": base, "files": files}),
    );
    assert_eq!(p["leases"][0]["code"], "held_by_you");
    assert_eq!(p["acquire"], json!([]));
    let r = e.propose(&t, &base, files, &["src/lib.rs#refund"]);
    assert_ne!(r["decision"]["outcome"], "deny", "{r}");
    assert_eq!(r["details"], json!([]));
}

/// A pinned item has no expiry to wait for: details name the change.
#[test]
fn details_of_a_pinned_item_name_the_change_not_a_time() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let a = e.session("a", &["src/**"]);
    let b = e.session("b", &["src/**"]);
    e.lease(&a, "src/lib.rs#charge");
    let new = LIB.replacen("    a\n", "    a + 1\n", 1);
    let p = e.propose(
        &a,
        &base,
        vec![file("src/lib.rs", &new)],
        &["src/lib.rs#charge"],
    );
    assert_eq!(p["decision"]["outcome"], "escalate", "{p}");
    let r = e.lease(&b, "src/lib.rs#charge");
    assert_eq!(r["details"][0]["pinned_to"], p["change"], "{r}");
    assert_eq!(r["details"][0]["expires_ms"], Value::Null);
}

/// A session that is over is told so, and its heartbeat writes nothing:
/// a client that goes on beating must not fill the log (issue #98).
#[test]
fn an_expired_session_can_not_beat() {
    let mut e = Env::new();
    e.init(None);
    let a = e.session("a", &["src/**"]);
    e.ok("session.heartbeat", None, Some(&a), json!({}));
    let before = log_len(&mut e);
    e.advance(3_600_001);
    let r = e.call("session.heartbeat", None, Some(&a), json!({}));
    assert_eq!(code(r), "session_inactive");
    assert_eq!(log_len(&mut e), before);
}

/// The old token stops at the continuation, the status tells both ends
/// of it, and the entry names what it continues.
#[test]
fn a_continuation_replaces_the_token_of_the_session_it_ends() {
    let mut e = Env::new();
    e.init(None);
    let a = e.session_in("a", &["src/**"], "/ws/a");
    let r = e.continue_session("b", "a", &["src/**"]);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let b = r["token"].as_str().unwrap().to_string();
    assert_ne!(a, b);

    let old = e.call("session.heartbeat", None, Some(&a), json!({}));
    assert_eq!(code(old), "unauthenticated");
    e.ok("session.heartbeat", None, Some(&b), json!({}));

    let s = e.ok("status", Some("demo"), None, json!({}));
    let all = s["sessions"].as_array().unwrap();
    let session = |id: &str| all.iter().find(|x| x["id"] == id).unwrap();
    assert_eq!(session("a")["active"], false);
    assert_eq!(session("a")["continued_by"], "b");
    assert_eq!(session("a")["continued_from"], Value::Null);
    assert_eq!(session("b")["active"], true);
    assert_eq!(session("b")["continued_from"], "a");
    assert_eq!(session("b")["continued_by"], Value::Null);

    // A refused continuation changes nothing: the old token still works.
    let r = e.continue_session("c", "b", &["docs/**"]);
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert_eq!(r["token"], Value::Null);
    e.ok("session.heartbeat", None, Some(&b), json!({}));
}

/// The queue through the daemon: an interest, its reservation in `status`
/// and `events`, details that say whose it is (issue #42).
#[test]
fn the_oldest_interest_gets_the_freed_set_and_hears_of_it() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let a = e.session("a", &["src/**"]);
    let b = e.session("b", &["src/**"]);
    let c = e.session("c", &["src/**"]);
    let sym = "src/lib.rs#charge";
    let item = json!([{"symbol": sym, "kind": "edit"}]);
    let set = e.lease(&a, sym)["set"].clone();

    let free = e.ok(
        "lease.interest",
        None,
        Some(&a),
        json!({"items": [{"symbol": "src/lib.rs#refund", "kind": "edit"}], "intent": "next"}),
    );
    assert_eq!(free["decision"]["reasons"][0], "lease_free", "{free}");
    let r = e.ok(
        "lease.interest",
        None,
        Some(&b),
        json!({"items": item, "intent": "next"}),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(r["decision"]["reasons"][0], "reservation_ms=60000");
    assert_eq!(r["details"][0]["holder_session"], "a", "{r}");
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(s["interests"][0]["session"], "b", "{s}");
    assert_eq!(s["interests"][0]["intent"], "next");
    assert_eq!(s["interests"][0]["seq"], r["seq"]);
    assert_eq!(s["reservations"], json!([]));

    e.ok("lease.release", None, Some(&a), json!({ "set": set }));
    let d = e.lease(&c, sym);
    assert_eq!(d["decision"]["outcome"], "deny", "{d}");
    assert_eq!(d["decision"]["reasons"][0], "lease_reserved:b");
    assert_eq!(d["details"][0]["code"], "lease_reserved", "{d}");
    assert_eq!(d["details"][0]["holder_session"], "b");
    assert_eq!(d["details"][0]["holder_agent"], "bot-b");
    assert_eq!(d["details"][0]["symbol"], sym);
    let s = e.ok("status", Some("demo"), None, json!({}));
    let until = s["reservations"][0]["until_ms"].as_i64().unwrap();
    assert_eq!(s["reservations"][0]["session"], "b", "{s}");
    assert_eq!(until, d["details"][0]["expires_ms"].as_i64().unwrap());

    let inbox = e.ok("events", None, Some(&b), json!({}));
    assert_eq!(inbox["events"][0]["kind"], "reserved", "{inbox}");
    assert_eq!(inbox["events"][0]["until_ms"], until);
    assert_eq!(inbox["next"], s["next_seq"]);
    let theirs = e.ok("events", None, Some(&c), json!({}));
    assert_eq!(theirs["events"], json!([]), "{theirs}");
    assert_eq!(
        code(e.call("events", Some("demo"), None, json!({}))),
        "forbidden"
    );

    let got = e.lease(&b, sym);
    assert_eq!(got["decision"]["outcome"], "allow", "{got}");
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(s["reservations"], json!([]));
    assert_eq!(s["interests"], json!([]));
}

/// What happened to a session's changes and messages, from `from` on.
#[test]
fn the_inbox_is_derived_from_the_log() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let a = e.session("a", &["src/**"]);
    let b = e.session("b", &["src/**"]);
    let sym = "src/lib.rs#charge";
    e.lease(&a, sym);
    let proposed = e.propose(
        &a,
        &base,
        vec![file(
            "src/lib.rs",
            &LIB.replacen("    a\n", "    a * 3\n", 1),
        )],
        &[sym],
    );
    assert_eq!(proposed["decision"]["outcome"], "escalate", "{proposed}");
    let seq = proposed["seq"].as_u64().unwrap();
    e.human(Op::Reject {
        target_seq: seq,
        reason: "say more".into(),
    });
    let inbox = e.ok("events", None, Some(&a), json!({}));
    let rejected = &inbox["events"][0];
    assert_eq!(rejected["kind"], "rejected", "{inbox}");
    assert_eq!(rejected["target_seq"], seq);
    assert_eq!(rejected["reason"], "say more");

    let next = inbox["next"].clone();
    let later = e.ok("events", None, Some(&a), json!({ "from": next }));
    assert_eq!(later["events"], json!([]), "{later}");

    e.ok(
        "negotiate",
        None,
        Some(&a),
        json!({"thread": "t", "to_session": "b",
               "message": {"type": "counter", "note": "hello"}}),
    );
    let mine = e.ok("events", None, Some(&b), json!({ "from": next }));
    assert_eq!(mine["events"][0]["kind"], "message", "{mine}");
    assert_eq!(mine["events"][0]["from"], "a");
    assert_eq!(mine["events"][0]["thread"], "t");
}

/// Two agents, one manifest and one changelog, no whole-file lease
/// (issue #46). A `Cargo.toml` would behave the same, with a human on top:
/// it is a critical path, which only observed sessions can propose to.
#[test]
fn two_agents_add_to_a_manifest_and_a_changelog_at_once() {
    const MANIFEST: &str = "[package]\nname = \"x\"\n\n[dependencies]\nserde = \"1\"\n";
    const LOG: &str = "# Changes\n\n- first\n\n# Older\n\n- zero\n";
    let mut e = Env::new();
    e.init(None);
    e.human_change(
        vec![file("deps.toml", MANIFEST), file("CHANGELOG.md", LOG)],
        "seed",
    );
    e.svc.process_all();
    let base = e.trunk();
    let a = e.session("a", &["**"]);
    let b = e.session("b", &["**"]);
    let items = json!([
        {"symbol": "deps.toml#dependencies", "kind": "insert"},
        {"symbol": "CHANGELOG.md#Changes", "kind": "insert"},
    ]);
    for t in [&a, &b] {
        let got = e.ok(
            "lease.acquire",
            None,
            Some(t),
            json!({"items": items, "intent": "add", "ttl_ms": 600_000}),
        );
        assert_eq!(got["decision"]["outcome"], "allow", "{got}");
    }
    let change = |dep: &str, line: &str| {
        vec![
            file("deps.toml", &format!("{MANIFEST}{dep} = \"1\"\n")),
            file(
                "CHANGELOG.md",
                &LOG.replace("- first\n", &format!("- first\n{line}\n")),
            ),
        ]
    };
    let propose = |e: &mut Env, t: &str, dep: &str, line: &str| {
        let claim = Claim {
            intent: "add".into(),
            adds: vec![
                "CHANGELOG.md#Changes.<append>".into(),
                format!("deps.toml#dependencies.{dep}"),
            ],
            ..Default::default()
        };
        let r = e.ok(
            "change.propose",
            None,
            Some(t),
            json!({"base": base, "files": change(dep, line), "claim": claim}),
        );
        assert_ne!(r["decision"]["outcome"], "deny", "{r}");
        r["seq"].as_u64().unwrap()
    };
    let first = propose(&mut e, &a, "anyhow", "- a");
    let second = propose(&mut e, &b, "clap", "- b");
    for seq in [first, second] {
        let d = e.human(Op::Approve {
            target_seq: seq,
            note: String::new(),
            checks: vec![],
        });
        assert_eq!(d["decision"]["outcome"], "allow", "{d}");
        e.svc.process_all();
    }
    let trunk = e.trunk();
    let store = e.store();
    let read = |path: &str| {
        let blob = store.commit_files(&trunk).unwrap()[path].blob.clone();
        String::from_utf8(store.read_blob(&blob).unwrap()).unwrap()
    };
    assert_eq!(
        read("deps.toml"),
        format!("{MANIFEST}clap = \"1\"\nanyhow = \"1\"\n"),
    );
    assert_eq!(
        read("CHANGELOG.md"),
        "# Changes\n\n- first\n- a\n- b\n\n# Older\n\n- zero\n"
    );
    let report = lonca_audit::audit(&store, lonca_audit::Options::default()).unwrap();
    assert!(report.ok(), "{:#?}", report.findings);
}

/// The agent a wide interest stops reads who it is and what it is for, and
/// an acquire of what the session already has says nothing of it.
#[test]
fn a_new_lease_stopped_by_a_waiting_interest_hears_why() {
    let mut e = Env::new();
    e.init(None);
    let [a, b, c] = ["a", "b", "c"].map(|s| e.session(s, &["src/**"]));
    let (member, whole) = ("src/lib.rs#Ledger.add", "src/lib.rs#Ledger");
    e.lease(&a, member);
    let r = e.ok(
        "lease.interest",
        None,
        Some(&b),
        json!({"items": [{"symbol": whole, "kind": "edit"}], "intent": "split Ledger, #7"}),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let s = e.ok("status", Some("demo"), None, json!({}));
    let until = s["interests"][0]["blocks_until_ms"].as_i64().unwrap();
    assert!(until > e.now() + 500_000, "{s}");

    let d = e.lease(&c, "src/lib.rs#Ledger.total");
    assert_eq!(d["decision"]["reasons"][0], "lease_wanted:b", "{d}");
    assert_eq!(d["details"][0]["code"], "lease_wanted", "{d}");
    assert_eq!(d["details"][0]["symbol"], whole);
    assert_eq!(d["details"][0]["needed_kind"], "edit");
    assert_eq!(d["details"][0]["holder_session"], "b");
    assert_eq!(d["details"][0]["holder_agent"], "bot-b");
    assert_eq!(d["details"][0]["intent"], "split Ledger, #7");
    assert_eq!(d["details"][0]["expires_ms"], until);
    let advice = d["advice"].as_str().unwrap();
    assert!(
        advice.contains("is waiting for src/lib.rs#Ledger"),
        "{advice}"
    );
    assert!(advice.contains("split Ledger, #7"), "{advice}");

    // What a partial release keeps.
    let kept = e.lease(&a, member);
    assert_eq!(kept["decision"]["outcome"], "allow", "{kept}");
    assert_eq!(kept["details"], json!([]), "{kept}");
    assert_eq!(kept["advice"], Value::Null, "{kept}");
}
