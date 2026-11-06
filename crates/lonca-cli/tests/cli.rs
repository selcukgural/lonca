//! The `lonca` binary against an in-process daemon on a real socket.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Output, Stdio};

use lonca_daemon::{Home, Service, Settings};
use serde_json::json;

struct Env {
    _dir: tempfile::TempDir,
    root: PathBuf,
    sock: PathBuf,
}

impl Env {
    fn new() -> Env {
        let dir = tempfile::Builder::new().prefix("lc").tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let sock = root.join("s");
        start_daemon(&root, &root.join("home"), &sock);
        Env {
            _dir: dir,
            root,
            sock,
        }
    }

    fn cmd(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_lonca"));
        // Hermetic: nothing reaches the developer's home or API key, even
        // under a mutant that ignores an override (cargo-mutants runs these).
        c.current_dir(cwd)
            .args(args)
            .env("HOME", self.root.join("user"))
            .env("LONCA_HOME", self.root.join("lonca-home"))
            .env("LONCA_SOCKET", &self.sock)
            .env("LONCA_HUMANS", self.root.join("humans"))
            .env("LONCA_ADVISOR_LEDGER", self.root.join("ledger.json"))
            .env_remove("LONCA_HUMAN")
            .env_remove("LONCA_WORKSPACE")
            .env_remove("LONCA_SE")
            .env_remove("LONCA_TEST_DAEMON_UID")
            .env_remove("LONCA_ADVISOR_DAILY_CALLS")
            .env_remove("ANTHROPIC_API_KEY")
            .env_remove("ANTHROPIC_AUTH_TOKEN")
            .env_remove("ANTHROPIC_BASE_URL");
        c
    }

    fn run(&self, cwd: &Path, args: &[&str]) -> String {
        let out = self.cmd(cwd, args).output().unwrap();
        assert!(
            out.status.success(),
            "lonca {args:?}\nstdout: {}\nstderr: {}",
            text(&out.stdout),
            text(&out.stderr)
        );
        text(&out.stdout)
    }

    fn hook(&self, cwd: &Path, input: &str) -> Output {
        self.hook_as(cwd, input, &["hook"])
    }

    fn hook_as(&self, cwd: &Path, input: &str, args: &[&str]) -> Output {
        use std::io::Write;
        let mut child = self
            .cmd(cwd, args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    /// Waits for the background worker to drain the queue.
    fn settle(&self) {
        for _ in 0..100 {
            let s = self.run(&self.root, &["status", "--repo", "demo", "--json"]);
            let v: serde_json::Value = serde_json::from_str(&s).unwrap();
            if v["queue"].as_array().is_some_and(|q| q.is_empty()) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("queue did not drain");
    }
}

/// An in-process daemon on `home`, serving `sock`.
fn start_daemon(root: &Path, home: &Path, sock: &Path) {
    let settings = Settings {
        managed_settings: root.join("managed.json"),
        require_root_settings: false,
        git: "git".into(),
        line_cap: lonca_daemon::protocol::MAX_LINE,
    };
    let svc = Service::open(Home::new(home), settings, lonca_daemon::system_clock()).unwrap();
    let listener = lonca_daemon::server::bind(sock).unwrap();
    svc.spawn_worker();
    std::thread::spawn(move || lonca_daemon::server::serve(listener, svc));
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

/// `lonca mcp` over stdio: one JSON-RPC line each way.
struct Mcp {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Mcp {
    fn start(e: &Env, ws: &Path) -> Mcp {
        let mut child = e
            .cmd(ws, &["mcp"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut m = Mcp {
            child,
            stdin,
            stdout,
            next_id: 0,
        };
        m.request("initialize", json!({"protocolVersion": "2025-06-18"}));
        m
    }

    fn request(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let req = json!({"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params});
        writeln!(self.stdin, "{req}").unwrap();
        let mut line = String::new();
        self.stdout.read_line(&mut line).unwrap();
        let resp: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(resp["id"], self.next_id, "{resp}");
        resp["result"].clone()
    }

    /// Calls a tool; the text after its answer, if any.
    fn news(&mut self, name: &str, args: serde_json::Value) -> Option<String> {
        let r = self.request("tools/call", json!({"name": name, "arguments": args}));
        r["content"][1]["text"].as_str().map(String::from)
    }

    /// Calls a tool; the first value says whether it is an MCP error.
    fn tool(&mut self, name: &str, args: serde_json::Value) -> (bool, serde_json::Value) {
        let r = self.request("tools/call", json!({"name": name, "arguments": args}));
        let body = r["content"][0]["text"].as_str().unwrap();
        let value = serde_json::from_str(body).unwrap_or_else(|_| json!(body));
        (r["isError"] == true, value)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A repository with one seeded file and an agent session in `ws`.
fn agent_workspace(e: &Env) -> PathBuf {
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::create_dir_all(hws.join("src")).unwrap();
    std::fs::write(
        hws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    assert!(e.run(&hws, &["propose", "-i", "seed"]).contains("allow"));
    e.settle();
    e.run(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            "ws",
        ],
    );
    r.join("ws")
}

#[test]
fn agent_workflow_through_the_cli() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));

    // A human seeds the repository from a human workspace.
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::create_dir_all(hws.join("src")).unwrap();
    std::fs::write(
        hws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    std::fs::write(hws.join(".gitignore"), "target/\n").unwrap();
    std::fs::create_dir_all(hws.join("target")).unwrap();
    std::fs::write(hws.join("target/junk"), "ignored").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "seed"]).contains("allow"));
    e.settle();

    let out = e.run(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            "ws",
        ],
    );
    assert!(out.contains("session ses_"), "{out}");
    let ws = r.join("ws");
    assert!(ws.join("src/lib.rs").exists());
    assert!(
        !ws.join("target").exists(),
        "ignored files were never proposed"
    );

    // Hooks: unknown directories pass through; writes outside are denied.
    let o = e.hook(r, r#"{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"/etc/hosts"},"cwd":"/"}"#);
    assert!(o.status.success() && o.stdout.is_empty());
    let input = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"file_path":"/etc/hosts"}},"cwd":"{}"}}"#,
        ws.display()
    );
    let o = e.hook(&ws, &input);
    assert!(
        text(&o.stdout).contains("\"permissionDecision\":\"deny\""),
        "{}",
        text(&o.stdout)
    );

    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund() {}\n",
    )
    .unwrap();
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#charge"]);
    e.run(
        &ws,
        &[
            "lease",
            "acquire",
            "-i",
            "fix",
            "src/lib.rs#<file>",
            "--kind",
            "insert",
        ],
    );
    let out = e.run(&ws, &["propose", "-i", "double", "--accept-facts"]);
    // The session tried to write outside the workspace: it is tainted.
    assert!(
        out.contains("escalate") && out.contains("tainted_session"),
        "{out}"
    );
    let seq: String = out
        .trim_start_matches('#')
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    // The review list names the change and its intent.
    let pending = e.run(r, &["pending", "--repo", "demo"]);
    assert!(
        pending.contains(&format!("#{seq} change.propose agent:claude/"))
            && pending.contains(" change ")
            && pending.contains(" \"double\" ["),
        "{pending}"
    );
    assert!(
        e.run(r, &["approve", &seq, "--repo", "demo"])
            .contains("released")
    );
    e.settle();
    let out = e.run(&ws, &["sync"]);
    assert!(out.contains("0 conflicts"), "{out}");
    let out = e.run(&hws, &["sync"]);
    assert!(out.contains("0 conflicts"), "{out}");
    assert!(
        std::fs::read_to_string(hws.join("src/lib.rs"))
            .unwrap()
            .contains("a * 2")
    );

    let log = e.run(r, &["log", "--repo", "demo"]);
    assert!(
        log.contains("change.integrate") && log.contains("approve"),
        "{log}"
    );

    // Daemon down: the hook fails closed.
    let mut c = e.cmd(&ws, &["hook"]);
    c.env("LONCA_SOCKET", r.join("nope"));
    use std::io::Write;
    let mut child = c
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let input = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":"x"}},"cwd":"{}"}}"#,
        ws.display()
    );
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(
        o.status.code(),
        Some(2),
        "blocks when the daemon is unreachable"
    );
}

/// A one-shot fake Messages API that records the request it got.
fn fake_claude(reply: &'static str) -> (u16, std::thread::JoinHandle<String>) {
    use std::io::{BufRead, BufReader, Read, Write};
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = std::thread::spawn(move || {
        let (s, _) = l.accept().unwrap();
        let mut r = BufReader::new(s.try_clone().unwrap());
        let mut head = String::new();
        let mut len = 0usize;
        loop {
            let mut line = String::new();
            r.read_line(&mut line).unwrap();
            if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                len = v.trim().parse().unwrap();
            }
            head.push_str(&line);
            if line == "\r\n" {
                break;
            }
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).unwrap();
        let mut s = s;
        write!(s, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}", reply.len()).unwrap();
        format!("{head}{}", String::from_utf8_lossy(&body))
    });
    (port, h)
}

#[test]
fn advisor_sends_the_diff_and_prints_structured_advice() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    e.run(r, &["init", "demo"]);
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::write(
        hws.join("lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n",
    )
    .unwrap();
    e.run(&hws, &["propose", "-i", "double charge"]);
    e.settle();
    let s: serde_json::Value =
        serde_json::from_str(&e.run(r, &["status", "--repo", "demo", "--json"])).unwrap();
    let change = s["changes"][0]["change"].as_str().unwrap().to_string();

    const REPLY: &str = r#"{"model":"claude-opus-5-5","stop_reason":"end_turn","content":[{"type":"text","text":"{\"summary\":\"Doubles charge.\",\"risk\":\"medium\",\"flags\":[{\"severity\":\"medium\",\"where\":\"lib.rs#charge\",\"issue\":\"Changes billing amounts.\"}],\"review_focus\":[\"callers of charge\"]}"}]}"#;
    let (port, server) = fake_claude(REPLY);
    let mut c = e.cmd(r, &["advise", &change, "--repo", "demo"]);
    c.env("ANTHROPIC_BASE_URL", format!("http://127.0.0.1:{port}"))
        .env("ANTHROPIC_API_KEY", "test-key")
        .env("LONCA_ADVISOR_LEDGER", r.join("ledger.json"));
    let out = c.output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let printed = text(&out.stdout);
    assert!(
        printed.contains("informational only")
            && printed.contains("risk: medium")
            && printed.contains("lib.rs#charge"),
        "{printed}"
    );
    let request = server.join().unwrap().to_ascii_lowercase();
    assert!(request.contains("x-api-key: test-key"));
    assert!(request.contains("anthropic-version: 2023-06-01"));
    assert!(request.contains("server-side-fallback-2026-07-01"));
    assert!(request.contains("+    a * 2"), "the diff is sent");
    assert!(request.contains("\"json_schema\""));
}

fn status_json(e: &Env) -> serde_json::Value {
    serde_json::from_str(&e.run(&e.root, &["status", "--repo", "demo", "--json"])).unwrap()
}

/// The public key `human whoami` prints for the default human.
fn whoami(e: &Env) -> String {
    let out = e.run(&e.root, &["human", "whoami"]);
    out.split_whitespace().last().unwrap().to_string()
}

#[test]
fn human_keys_rotate_recover_and_revoke_through_the_cli() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    let first = whoami(&e);

    // A recovery key, written where the user chooses.
    let rec = r.join("usb/rec.key");
    let out = e.run(
        r,
        &[
            "human",
            "recovery-key",
            "--repo",
            "demo",
            "--out",
            rec.to_str().unwrap(),
        ],
    );
    assert!(out.contains("move it off this machine"), "{out}");
    assert!(status_json(&e)["humans"]["ayse"]["recovery"].is_string());
    // Running it again skips the repository that already has the key.
    let rec_args = [
        "human",
        "recovery-key",
        "--repo",
        "demo",
        "--out",
        rec.to_str().unwrap(),
    ];
    assert!(e.run(r, &rec_args).contains("demo: already set"));

    // Rotation: an interrupted run leaves the new key waiting and the old
    // one in use; rerunning it skips the repository that already took it.
    let cut = e
        .cmd(
            r,
            &["human", "rotate", "--repo", "demo", "--repo", "nosuch"],
        )
        .output()
        .unwrap();
    assert!(!cut.status.success());
    assert_eq!(whoami(&e), first);
    assert!(r.join("humans/ayse.next.key").exists());
    let out = e.run(r, &["human", "rotate", "--repo", "demo"]);
    assert!(out.contains("demo: already uses the new key"), "{out}");
    let second = whoami(&e);
    assert_ne!(first, second);
    assert_eq!(status_json(&e)["humans"]["ayse"]["public"], second.as_str());
    assert!(!r.join("humans/ayse.next.key").exists());
    let retired: Vec<_> = std::fs::read_dir(r.join("humans"))
        .unwrap()
        .filter_map(|d| d.ok())
        .filter(|d| {
            d.file_name()
                .to_string_lossy()
                .starts_with("ayse.key.retired-")
        })
        .collect();
    assert_eq!(retired.len(), 1);

    // The machine is lost: recover from the recovery key alone.
    std::fs::remove_dir_all(r.join("humans")).unwrap();
    let recover = |more: &[&str]| {
        let mut args = vec![
            "human",
            "recover",
            "--repo",
            "demo",
            "--recovery-key",
            rec.to_str().unwrap(),
            "--as",
            "ayse",
        ];
        args.extend_from_slice(more);
        e.cmd(r, &args).output().unwrap()
    };
    assert!(!recover(&["--repo", "nosuch"]).status.success());
    let out = recover(&[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = text(&out.stdout);
    assert!(out.contains("demo: already recovered"), "{out}");
    assert!(out.contains("recovered."), "{out}");
    let third = whoami(&e);
    assert_ne!(third, second);
    let st = status_json(&e);
    assert_eq!(st["humans"]["ayse"]["public"], third.as_str());
    assert!(st["humans"]["ayse"]["recovery"].is_null(), "used up");
    // A second recovery with the same key is refused.
    let again = e
        .cmd(
            r,
            &[
                "human",
                "recover",
                "--repo",
                "demo",
                "--recovery-key",
                rec.to_str().unwrap(),
            ],
        )
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(
        text(&again.stdout).contains("no_recovery_key"),
        "{}",
        text(&again.stdout)
    );
    std::fs::remove_file(r.join("humans/ayse.next.key")).unwrap();

    // Another human is enrolled and then revoked.
    let out = e.run(r, &["human", "keygen", "bora"]);
    let bora = out
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .nth(2)
        .unwrap()
        .to_string();
    let enroll = [
        "human", "enroll", "bora", "--alg", "ed25519", "--public", &bora, "--repo", "demo", "--as",
        "ayse",
    ];
    assert!(e.run(r, &enroll).contains("allow"));
    let revoke = [
        "human", "revoke", "bora", "--repo", "demo", "--reason", "left", "--as", "ayse",
    ];
    assert!(e.run(r, &revoke).contains("allow"));
    // `keygen bora` made bora the default identity; revoked, bora can not
    // even read. Ayse can.
    let out = e.cmd(r, &["status", "--repo", "demo"]).output().unwrap();
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("login failed"),
        "{}",
        text(&out.stderr)
    );
    let st: serde_json::Value =
        serde_json::from_str(&e.run(r, &["status", "--repo", "demo", "--json", "--as", "ayse"]))
            .unwrap();
    assert!(st["humans"]["bora"].is_null());

    // Bad names never reach a file path.
    let bad = e
        .cmd(r, &["human", "rotate", "--repo", "demo", "--as", "../x"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
}

/// A stand-in for the `lonca-se` helper: one P-256 key made by `openssl`
/// plays every Secure Enclave key. `keygen` and `public` print its SEC1
/// point; `sign` signs stdin (ECDSA over SHA-256, DER) without asking
/// for Touch ID. Returns the script and the public key (hex).
#[cfg(unix)]
fn fake_se(e: &Env) -> (PathBuf, String) {
    use std::os::unix::fs::PermissionsExt;
    let pem = e.root.join("fake-se.pem");
    let out = Command::new("openssl")
        .args([
            "ecparam",
            "-name",
            "prime256v1",
            "-genkey",
            "-noout",
            "-out",
        ])
        .arg(&pem)
        .output()
        .expect("openssl");
    assert!(out.status.success(), "{}", text(&out.stderr));
    let der = Command::new("openssl")
        .args(["ec", "-pubout", "-outform", "DER", "-in"])
        .arg(&pem)
        .output()
        .unwrap();
    assert!(der.status.success(), "{}", text(&der.stderr));
    // SubjectPublicKeyInfo ends with the 65-byte uncompressed point.
    let point = &der.stdout[der.stdout.len() - 65..];
    assert_eq!(point[0], 4);
    let public = point.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let p = e.root.join("fake-se");
    let script = format!(
        "#!/bin/sh\n\
         case \"$1\" in\n\
         keygen) echo blob > \"$2\" && echo {public} ;;\n\
         public) test -f \"$2\" || {{ echo \"no key $2\" >&2; exit 1; }}; echo {public} ;;\n\
         sign) test -f \"$2\" || {{ echo \"no key $2\" >&2; exit 1; }}; \
         openssl dgst -sha256 -sign {} | od -An -v -tx1 | tr -d ' \\n' ;;\n\
         *) echo \"unsupported: $1\" >&2; exit 1 ;;\n\
         esac\n",
        pem.display()
    );
    std::fs::write(&p, script).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    (p, public)
}

#[cfg(unix)]
#[test]
fn secure_enclave_keys_through_a_fake_helper() {
    let e = Env::new();
    let r = &e.root;
    let (se, public) = fake_se(&e);
    let run_se = |args: &[&str]| {
        let out = e.cmd(r, args).env("LONCA_SE", &se).output().unwrap();
        assert!(
            out.status.success(),
            "lonca {args:?}\nstdout: {}\nstderr: {}",
            text(&out.stdout),
            text(&out.stderr)
        );
        text(&out.stdout)
    };

    // A file key rotated to a Secure Enclave key: the next key is created
    // by the helper, accepted by the repository and installed.
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    let out = run_se(&["human", "rotate", "--repo", "demo", "--secure-enclave"]);
    assert!(out.contains("allow"), "{out}");
    // The session opened with the file key died with the rotation; the
    // next read signs in again, through the helper (Touch ID for real).
    let st: serde_json::Value =
        serde_json::from_str(&run_se(&["status", "--repo", "demo", "--json"])).unwrap();
    assert_eq!(st["humans"]["ayse"]["alg"], "p256-se");
    assert_eq!(st["humans"]["ayse"]["public"], public);
    assert!(r.join("humans/ayse.se").exists());
    assert!(!r.join("humans/ayse.key").exists());
    let out = run_se(&["human", "whoami"]);
    assert_eq!(out.trim(), format!("ayse: p256-se {public}"));
    // Without the helper there is no way to sign in.
    let out = e
        .cmd(r, &["human", "logout"])
        .env("LONCA_SE", &se)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let out = e.cmd(r, &["status", "--repo", "demo"]).output().unwrap();
    assert!(!out.status.success());
    assert!(
        text(&out.stderr).contains("lonca-se helper not found"),
        "{}",
        text(&out.stderr)
    );
    let out = run_se(&["human", "login", "--ttl", "30m"]);
    assert!(
        out.contains("ayse: signed in for 30m") && out.contains("enrolled in: demo"),
        "{out}"
    );

    // A new Secure Enclave identity prints the helper's public key.
    let out = run_se(&["human", "keygen", "bora", "--secure-enclave"]);
    assert!(
        out.starts_with(&format!("bora: p256-se {public}\n")),
        "{out}"
    );
}

#[test]
fn daemon_keys_rotate_and_move_to_another_daemon_through_the_cli() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    e.run(r, &["init", "demo"]);
    e.run(r, &["init", "other"]);
    let key_of = |sock: &Path, repo: &str| -> String {
        let out = e
            .cmd(r, &["status", "--repo", repo, "--json"])
            .env("LONCA_SOCKET", sock)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", text(&out.stderr));
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["daemon_key"].as_str().unwrap().to_string()
    };
    let old = key_of(&e.sock, "demo");

    let out = e.run(r, &["daemon-key", "rotate", "--repo", "demo"]);
    assert!(out.contains("demo: #"), "{out}");
    assert!(out.contains("still on the old daemon key: other"), "{out}");
    let out = e.run(r, &["daemon-key", "rotate", "--repo", "demo,other"]);
    assert!(
        out.contains("demo: already uses the new daemon key"),
        "{out}"
    );
    assert!(out.contains("other: #"), "{out}");
    assert!(out.contains("the daemon signs with"), "{out}");
    let first = key_of(&e.sock, "other");
    assert_ne!(first, old);
    assert_eq!(key_of(&e.sock, "demo"), first);
    // Without --repo: every repository still on the current key.
    let out = e.run(r, &["daemon-key", "rotate"]);
    assert!(out.contains("demo: #") && out.contains("other: #"), "{out}");
    assert!(out.contains("the daemon signs with"), "{out}");
    let new = key_of(&e.sock, "demo");
    assert!(new != first && new != old);

    // Another daemon (as when moving to hardened mode) gets a copy of the
    // store and continues it on its own key.
    let home2 = r.join("home2");
    std::fs::create_dir_all(home2.join("repos")).unwrap();
    let copy = std::process::Command::new("git")
        .args(["clone", "-q", "--mirror"])
        .arg(r.join("home/repos/demo.git"))
        .arg(home2.join("repos/demo.git"))
        .output()
        .unwrap();
    assert!(copy.status.success(), "{}", text(&copy.stderr));
    let sock2 = r.join("s2");
    start_daemon(r, &home2, &sock2);
    let recover = e
        .cmd(r, &["daemon-key", "recover", "--repo", "demo"])
        .env("LONCA_SOCKET", &sock2)
        .output()
        .unwrap();
    assert!(
        recover.status.success(),
        "{}{}",
        text(&recover.stdout),
        text(&recover.stderr)
    );
    assert!(text(&recover.stdout).contains("recovered onto daemon key"));
    let moved = key_of(&sock2, "demo");
    assert_ne!(moved, new);
    let again = e
        .cmd(r, &["daemon-key", "recover", "--repo", "demo"])
        .env("LONCA_SOCKET", &sock2)
        .output()
        .unwrap();
    assert!(!again.status.success());
    assert!(text(&again.stdout).contains("use `lonca daemon-key rotate`"));
}

#[test]
fn backup_and_restore_through_the_cli() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    e.run(r, &["init", "demo"]);
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::create_dir_all(hws.join("src")).unwrap();
    std::fs::write(hws.join("src/lib.rs"), "pub fn charge() {}\n").unwrap();
    e.run(&hws, &["propose", "-i", "seed"]);
    e.settle();
    let head = status_json(&e)["head_hash"].as_str().unwrap().to_string();

    // Every repository, then one copied out.
    let out = e.run(r, &["backup"]);
    let bundle = r.join("home/backups/demo-000002.bundle");
    assert!(
        out.contains(&format!(
            "demo: {} (operations 0..=2, head {})",
            bundle.display(),
            &head[..16]
        )),
        "{out}"
    );
    assert!(bundle.exists());
    let out = e.run(r, &["backup", "--repo", "demo", "--out", "off-site"]);
    let copy = r.join("off-site/demo-000002.bundle");
    assert!(out.contains(&format!("demo: {}", copy.display())), "{out}");
    assert_eq!(
        std::fs::read(&copy).unwrap(),
        std::fs::read(&bundle).unwrap()
    );

    // The same daemon never replaces its repository.
    let o = e
        .cmd(
            r,
            &["restore", "demo", "--from", "off-site/demo-000002.bundle"],
        )
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(
        text(&o.stderr).contains("never replaces"),
        "{}",
        text(&o.stderr)
    );

    // Another machine: a new daemon without the key.
    let home2 = r.join("home2");
    let sock2 = r.join("s2");
    start_daemon(r, &home2, &sock2);
    let run2 =
        |args: &[&str]| -> Output { e.cmd(r, args).env("LONCA_SOCKET", &sock2).output().unwrap() };
    let o = run2(&["restore", "demo", "--from", "off-site/demo-000002.bundle"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let out = text(&o.stdout);
    assert!(out.contains("restored operations 0..=2"), "{out}");
    assert!(
        out.contains("lonca daemon-key recover --repo demo"),
        "{out}"
    );
    let o = run2(&["status", "--repo", "demo"]);
    assert!(!o.status.success());
    assert!(
        text(&o.stderr).contains("foreign_key"),
        "{}",
        text(&o.stderr)
    );
    let o = run2(&["daemon-key", "recover", "--repo", "demo"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let o = run2(&["status", "--repo", "demo", "--json"]);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let v: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["trunk"], status_json(&e)["trunk"]);
    assert_eq!(v["next_seq"], serde_json::json!(4));

    // The round trip audits, key switch included.
    let store = lonca_core::Store::open(&home2.join("repos/demo.git")).unwrap();
    let rep = lonca_audit::audit(
        &store,
        lonca_audit::Options {
            deep: true,
            check_refs: true,
        },
    )
    .unwrap();
    assert!(rep.ok(), "{:#?}", rep.findings);
    assert_eq!(rep.key_switches.len(), 1);
    assert_eq!(rep.key_switches[0].kind, "daemon.recover");
}

/// The kept human session: reused while it is good, renewed when it is
/// about to expire, never used for another name, ended by logout, and
/// the daemon holds one token hash per live session.
#[test]
fn the_human_session_file_is_reused_renewed_and_ended() {
    let e = Env::new();
    let r = &e.root;
    let human_tokens = || -> usize {
        let text = std::fs::read_to_string(r.join("home/tokens.json")).unwrap_or_default();
        let map: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&text).unwrap_or_default();
        map.values().filter(|v| v["human"].is_string()).count()
    };
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    let session = r.join("humans/ayse.session");
    assert!(!session.exists(), "init bootstraps without a session");
    // Two reads, one session: the file is written once and reused.
    e.run(r, &["status", "--repo", "demo"]);
    assert!(session.exists());
    let first = std::fs::read_to_string(&session).unwrap();
    e.run(r, &["status", "--repo", "demo"]);
    assert_eq!(std::fs::read_to_string(&session).unwrap(), first);
    assert_eq!(human_tokens(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&session).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // A command about no repository in particular (the queue) reuses the
    // same session: it is enrolled somewhere, which is all that is asked.
    e.run(r, &["queue"]);
    e.run(r, &["queue"]);
    assert_eq!(human_tokens(), 1);
    assert_eq!(std::fs::read_to_string(&session).unwrap(), first);
    // A session about to expire (under the 30 s margin) is renewed.
    e.run(r, &["human", "login", "--ttl", "20s"]);
    assert_eq!(human_tokens(), 2);
    let short = std::fs::read_to_string(&session).unwrap();
    e.run(r, &["status", "--repo", "demo"]);
    assert_ne!(std::fs::read_to_string(&session).unwrap(), short);
    assert_eq!(human_tokens(), 3);
    // An expired file is replaced, not sent.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&session).unwrap()).unwrap();
    v["expires_ms"] = serde_json::json!(1);
    std::fs::write(&session, v.to_string()).unwrap();
    e.run(r, &["status", "--repo", "demo"]);
    let renewed: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&session).unwrap()).unwrap();
    assert!(renewed["expires_ms"].as_i64().unwrap() > 1);
    assert_eq!(human_tokens(), 4);
    // Another name never rides on this session: bora has no key.
    std::fs::copy(&session, r.join("humans/bora.session")).unwrap();
    let out = e
        .cmd(r, &["status", "--repo", "demo", "--as", "bora"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("no key for bora"),
        "{}",
        text(&out.stderr)
    );
    // A file whose token the daemon no longer knows is replaced.
    let mut v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&session).unwrap()).unwrap();
    v["token"] = serde_json::json!("lonca_h_0000");
    std::fs::write(&session, v.to_string()).unwrap();
    e.run(r, &["status", "--repo", "demo"]);
    assert_eq!(human_tokens(), 5);
    // Logout ends the session at the daemon and forgets the file; twice is fine.
    e.run(r, &["human", "logout"]);
    assert!(!session.exists());
    assert_eq!(human_tokens(), 4, "the live one was revoked");
    e.run(r, &["human", "logout"]);
    // A humans directory that is not a directory: logout reports it
    // (`--as`, so that the identity lookup is not what fails).
    let out = e
        .cmd(r, &["human", "logout", "--as", "ayse"])
        .env("LONCA_HUMANS", r.join("home/tokens.json"))
        .output()
        .unwrap();
    assert!(!out.status.success(), "{}", text(&out.stdout));
    assert!(
        text(&out.stderr).contains("ayse.session"),
        "{}",
        text(&out.stderr)
    );
}

/// What a runner reads: `--json` on the commands it drives, and exit
/// codes that tell a refusal (1) from a missing daemon (2) and from a
/// usage error (3). No token in any output (issue #77).
#[test]
fn runner_outputs_are_json_and_exit_codes_tell_failures_apart() {
    let e = Env::new();
    let r = &e.root;
    let parse = |s: &str| -> serde_json::Value {
        serde_json::from_str(s.trim()).unwrap_or_else(|err| panic!("{err}: {s}"))
    };
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));

    let who = parse(&e.run(r, &["human", "whoami", "--json"]));
    assert_eq!(who["human"], "ayse");
    assert_eq!(who["alg"], "ed25519");
    let login = parse(&e.run(r, &["human", "login", "--json", "--ttl", "2h"]));
    assert_eq!(login["human"], "ayse");
    assert_eq!(login["repos"], serde_json::json!(["demo"]));
    let session_file = PathBuf::from(login["session_file"].as_str().unwrap());
    assert!(
        session_file.ends_with("humans/ayse.session"),
        "{session_file:?}"
    );
    let kept: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&session_file).unwrap()).unwrap();
    let human_token = kept["token"].as_str().unwrap().to_string();
    assert!(human_token.starts_with("lonca_h_"));
    assert_eq!(kept["expires_ms"], login["expires_ms"]);

    // Seed from a human workspace.
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::create_dir_all(hws.join("src")).unwrap();
    std::fs::write(
        hws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    let seed = parse(&e.run(&hws, &["propose", "-i", "seed", "--json"]));
    assert_eq!(seed["status"], "queued", "{seed}");
    assert_eq!(seed["decision"]["outcome"], "allow");
    assert!(seed["change"].as_str().unwrap().len() == 32);
    e.settle();

    let started = parse(&e.run(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            "ws",
            "--json",
        ],
    ));
    assert!(
        started["session"].as_str().unwrap().starts_with("ses_"),
        "{started}"
    );
    assert_eq!(started["workspace"].as_str(), r.join("ws").to_str());
    assert_eq!(started["paths"], serde_json::json!(["src/**"]));
    assert_eq!(started["decision"]["outcome"], "allow");
    assert!(started["expires_ms"].as_i64().unwrap() > 0);
    let ws = r.join("ws");
    let agent_token = std::fs::read_to_string(ws.join(".lonca/session")).unwrap();
    assert!(!started.to_string().contains(agent_token.trim()));
    assert!(!login.to_string().contains(&human_token));

    // A wrong claim: refused, exit 1, the reason on stderr; JSON says denied.
    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n",
    )
    .unwrap();
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#charge"]);
    let out = e
        .cmd(
            &ws,
            &[
                "propose",
                "-i",
                "wrong",
                "--edits",
                "src/lib.rs#nothing",
                "--json",
            ],
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("denied: ") && text(&out.stderr).contains("claim_mismatch"),
        "{}",
        text(&out.stderr)
    );
    let denied = parse(&text(&out.stdout));
    assert_eq!(denied["status"], "denied");
    assert_eq!(denied["decision"]["outcome"], "deny");

    // The right claim from an unobserved session waits for a human.
    let proposed = parse(&e.run(
        &ws,
        &["propose", "-i", "double", "--accept-facts", "--json"],
    ));
    assert_eq!(proposed["status"], "pending", "{proposed}");
    let seq = proposed["seq"].as_u64().unwrap();
    let pending = parse(&e.run(r, &["pending", "--repo", "demo", "--json"]));
    assert_eq!(pending[0]["seq"], seq);
    assert_eq!(pending[0]["change"], proposed["change"]);
    assert_eq!(pending[0]["intent"], "double");
    assert_eq!(pending[0]["agent"], "claude");
    let approved = parse(&e.run(
        r,
        &["approve", &seq.to_string(), "--repo", "demo", "--json"],
    ));
    assert_eq!(approved["target_seq"], seq);
    assert_eq!(approved["change"], proposed["change"]);
    assert!(approved["seq"].as_u64().unwrap() > seq);
    assert_eq!(approved["decision"]["outcome"], "allow", "{approved}");
    e.settle();

    // The human edited the same line meanwhile: one conflict, trunk's copy beside it.
    std::fs::write(
        hws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 3\n}\n",
    )
    .unwrap();
    let synced = parse(&e.run(&hws, &["sync", "--json"]));
    assert_ne!(synced["base_before"], synced["base_after"]);
    assert_eq!(
        synced["conflicts"],
        serde_json::json!([{
            "path": "src/lib.rs",
            "trunk_copy": "src/lib.rs.trunk",
            "symbols": ["src/lib.rs#charge"],
        }]),
        "{synced}"
    );
    assert!(hws.join("src/lib.rs.trunk").exists());
    let synced = parse(&e.run(&ws, &["sync", "--json"]));
    assert_eq!(synced["conflicts"], serde_json::json!([]));

    let ended = parse(&e.run(&ws, &["session", "end", "--json"]));
    assert_eq!(ended["session"], started["session"]);
    assert_eq!(ended["decision"]["outcome"], "allow");

    // Exit codes: 2 without a daemon, 3 for usage, 0 for help.
    let out = e
        .cmd(r, &["status", "--repo", "demo"])
        .env("LONCA_SOCKET", r.join("nope"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("cannot reach the Lonca daemon"));
    let out = e.cmd(r, &["no-such-command"]).output().unwrap();
    assert_eq!(out.status.code(), Some(3));
    let out = e.cmd(r, &["propose", "-i", "x"]).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(3),
        "no workspace: {}",
        text(&out.stderr)
    );
    let out = e.cmd(r, &["--help"]).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    // A refused request that never became a log entry is also 1: here
    // the login against a repository that does not know the human.
    let out = e
        .cmd(r, &["status", "--repo", "other", "--as", "ayse"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("human.login: unauthenticated: login failed"),
        "{}",
        text(&out.stderr)
    );
}

/// The runner document's settings: a SessionStart event through
/// `lonca hook` injects the rules and the scratch directory; writes to
/// the scratch directory pass, writes elsewhere are denied (issue #78).
#[test]
fn a_worker_with_a_scratch_directory_through_the_documented_hooks() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    let scratch = r.join("claude-1-scratch");
    let started: serde_json::Value = serde_json::from_str(&e.run(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            "claude-1",
            "--scratch",
            scratch.to_str().unwrap(),
            "--json",
        ],
    ))
    .unwrap();
    let scratch = scratch.canonicalize().unwrap();
    assert_eq!(
        started["scratch"],
        serde_json::json!([scratch.to_string_lossy()])
    );
    let ws = r.join("claude-1");
    // A scratch directory inside its own workspace is refused.
    let out = e
        .cmd(
            r,
            &[
                "session",
                "start",
                "--repo",
                "demo",
                "--agent",
                "c",
                "--paths",
                "src/**",
                "--workspace",
                "w2",
                "--scratch",
                "w2/notes",
            ],
        )
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("overlaps the workspace"));

    // The events as Claude Code sends them under the documented hooks block.
    let start = format!(
        r#"{{"hook_event_name":"SessionStart","session_id":"h1","cwd":"{}"}}"#,
        ws.display()
    );
    let o = e.hook(&ws, &start);
    assert!(o.status.success(), "{}", text(&o.stderr));
    let out: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    let context = out["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap();
    assert!(
        context.contains("governed by Lonca (repository demo"),
        "{context}"
    );
    assert!(
        context.contains(&scratch.to_string_lossy().to_string()),
        "{context}"
    );
    assert!(context.contains("[taint]"), "{context}");
    let write = |path: &std::path::Path| {
        format!(
            r#"{{"hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{{"file_path":"{}"}},"cwd":"{}"}}"#,
            path.display(),
            ws.display()
        )
    };
    let o = e.hook(&ws, &write(&scratch.join("notes.md")));
    assert!(
        o.status.success() && o.stdout.is_empty(),
        "{}",
        text(&o.stdout)
    );
    let o = e.hook(&ws, &write(&r.join("elsewhere.md")));
    assert!(
        text(&o.stdout).contains("\"permissionDecision\":\"deny\""),
        "{}",
        text(&o.stdout)
    );
    let o = e.hook(&ws, &write(&ws.join("src/new.rs")));
    assert!(o.status.success() && o.stdout.is_empty());
}

/// A repository larger than one fetch page gets a workspace and syncs
/// after a large file lands, and `init --import` warns about files above
/// the change cap (issue #79). The page budget is lowered through
/// `LONCA_FETCH_BUDGET`.
#[test]
fn large_trees_are_fetched_in_pages_and_import_warns() {
    let e = Env::new();
    let r = &e.root;
    // A Git repository to import: one file above the 2 MiB change cap.
    let work = r.join("work");
    std::fs::create_dir_all(work.join("src")).unwrap();
    std::fs::write(work.join("huge.bin"), vec![b'h'; 2 * 1024 * 1024 + 1]).unwrap();
    std::fs::write(
        work.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    for i in 0..6 {
        std::fs::write(work.join(format!("d{i}.txt")), "d".repeat(900)).unwrap();
    }
    let g = |args: &[&str]| {
        let o = Command::new("git")
            .current_dir(&work)
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", text(&o.stderr));
    };
    g(&["init", "-q", "-b", "main"]);
    g(&["add", "."]);
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-m",
        "x",
    ]);
    e.run(r, &["human", "keygen", "ayse"]);
    let out = e
        .cmd(r, &["init", "demo", "--import", work.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("warning: huge.bin is 2097153 bytes, above the change cap"),
        "{}",
        text(&out.stderr)
    );

    // With --json the warning is data: nothing outside the JSON on stdout,
    // nothing as text on stderr.
    let args = [
        "init",
        "imported",
        "--import",
        work.to_str().unwrap(),
        "--json",
    ];
    let out = e.cmd(r, &args).output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(
        text(&out.stdout).lines().count(),
        1,
        "{}",
        text(&out.stdout)
    );
    let init = parse(&text(&out.stdout));
    assert_eq!(init["repo"], "imported");
    let warnings = init["warnings"].as_array().unwrap();
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .starts_with("huge.bin is 2097153 bytes"),
        "{init}"
    );
    assert!(
        !text(&out.stderr).contains("warning"),
        "{}",
        text(&out.stderr)
    );

    // Pages of at most 2000 encoded bytes: the workspace still comes whole.
    let budget = |c: &mut Command| {
        c.env("LONCA_FETCH_BUDGET", "2000");
    };
    let mut c = e.cmd(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            "ws",
            "--json",
        ],
    );
    budget(&mut c);
    let o = c.output().unwrap();
    // huge.bin alone is above the page: named, and the workspace is refused.
    assert!(!o.status.success());
    assert!(
        text(&o.stderr).contains("huge.bin is 2097153 bytes, more than one fetch page holds"),
        "{}",
        text(&o.stderr)
    );
    // Without the oversize file the pages work.
    std::fs::remove_file(work.join("huge.bin")).unwrap();
    g(&["add", "."]);
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-m",
        "drop",
    ]);
    e.run(r, &["human", "keygen", "ayse"]);
    let out = e
        .cmd(r, &["init", "demo2", "--import", work.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        !text(&out.stderr).contains("warning"),
        "{}",
        text(&out.stderr)
    );
    let mut c = e.cmd(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo2",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            "ws2",
            "--json",
        ],
    );
    budget(&mut c);
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", text(&o.stderr));
    let ws = r.join("ws2");
    for i in 0..6 {
        assert_eq!(
            std::fs::read_to_string(ws.join(format!("d{i}.txt")))
                .unwrap()
                .len(),
            900
        );
    }
    assert!(ws.join("src/lib.rs").exists());

    // A human adds a 1500-byte file to trunk; the agent syncs in pages.
    e.run(r, &["workspace", "create", "hws", "--repo", "demo2"]);
    let hws = r.join("hws");
    std::fs::write(hws.join("notes.md"), "n".repeat(1500)).unwrap();
    assert!(e.run(&hws, &["propose", "-i", "notes"]).contains("allow"));
    for _ in 0..100 {
        let s = e.run(r, &["status", "--repo", "demo2", "--json"]);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        if v["queue"].as_array().is_some_and(|q| q.is_empty()) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let mut c = e.cmd(&ws, &["sync", "--json"]);
    budget(&mut c);
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", text(&o.stderr));
    let synced: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(
        synced["updated"],
        serde_json::json!(["notes.md"]),
        "{synced}"
    );
    assert_eq!(
        std::fs::read_to_string(ws.join("notes.md")).unwrap().len(),
        1500
    );
}

/// `lonca diff CHANGE` and `lonca change CHANGE --evidence` read through
/// the daemon (issue #80).
#[test]
fn diff_and_evidence_of_a_change_through_the_cli() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::create_dir_all(hws.join("src")).unwrap();
    std::fs::write(
        hws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    std::fs::write(hws.join("check.sh"), "echo checked; exit 0\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "seed"]).contains("allow"));
    e.settle();
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "# test = \"cargo test --offline\"",
        "test = \"sh check.sh\"",
    );
    std::fs::write(r.join("lonca.toml"), config).unwrap();
    std::fs::write(r.join("policy.cedar"), lonca_policy::config::DEFAULT_POLICY).unwrap();
    assert!(
        e.run(
            r,
            &[
                "policy",
                "set",
                "--repo",
                "demo",
                "--config",
                "lonca.toml",
                "--policy",
                "policy.cedar"
            ]
        )
        .contains("allow")
    );
    e.run(&hws, &["sync"]);
    std::fs::write(
        hws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n",
    )
    .unwrap();
    let out = e.run(&hws, &["propose", "-i", "double", "--json"]);
    let proposed: serde_json::Value = serde_json::from_str(&out).unwrap();
    let change = proposed["change"].as_str().unwrap().to_string();
    e.settle();
    let diff = e.run(r, &["diff", &change, "--repo", "demo"]);
    assert!(diff.contains("modified  +1 -1 src/lib.rs"), "{diff}");
    assert!(diff.contains("+    a * 2"), "{diff}");
    assert!(!diff.contains("[diff truncated]"), "{diff}");
    let ev = e.run(r, &["change", &change, "--repo", "demo", "--evidence"]);
    assert!(ev.contains("tests: pass (exit 0,"), "{ev}");
    assert!(ev.contains("  checked"), "{ev}");
    assert!(!ev.contains("[log tail]"), "{ev}");
    let j: serde_json::Value =
        serde_json::from_str(&e.run(r, &["diff", &change, "--repo", "demo", "--json"])).unwrap();
    assert_eq!(j["files"][0]["status"], "modified");
}

/// `lonca reject SEQ --reason …` declines a pending proposal; the worker
/// reads the reason in the change's status (issue #81).
#[test]
fn a_human_rejects_through_the_cli_and_the_reason_reaches_the_worker() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::create_dir_all(hws.join("src")).unwrap();
    std::fs::write(
        hws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    assert!(e.run(&hws, &["propose", "-i", "seed"]).contains("allow"));
    e.settle();
    e.run(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            "ws",
        ],
    );
    let ws = r.join("ws");
    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n",
    )
    .unwrap();
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#charge"]);
    let p: serde_json::Value = serde_json::from_str(&e.run(
        &ws,
        &["propose", "-i", "double", "--accept-facts", "--json"],
    ))
    .unwrap();
    assert_eq!(p["status"], "pending");
    let status = e.run(r, &["status", "--repo", "demo"]);
    assert!(
        status.contains("src/lib.rs#charge(edit) [pinned to 1 change(s)]"),
        "{status}"
    );
    let seq = p["seq"].as_u64().unwrap().to_string();
    let out = e
        .cmd(r, &["reject", &seq, "--repo", "demo", "--reason", ""])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        text(&out.stderr).contains("reason_required"),
        "{}",
        text(&out.stderr)
    );
    let rejected: serde_json::Value = serde_json::from_str(&e.run(
        r,
        &[
            "reject",
            &seq,
            "--repo",
            "demo",
            "--reason",
            "double is wrong, add one",
            "--json",
        ],
    ))
    .unwrap();
    assert_eq!(rejected["target_seq"].as_u64().unwrap().to_string(), seq);
    assert_eq!(rejected["change"], p["change"]);
    assert_eq!(rejected["decision"]["outcome"], "allow");
    let rec: serde_json::Value = serde_json::from_str(&e.run(
        r,
        &["change", p["change"].as_str().unwrap(), "--repo", "demo"],
    ))
    .unwrap();
    assert_eq!(rec["status"]["status"], "rejected");
    assert_eq!(
        rec["status"]["reasons"][0],
        "rejected: double is wrong, add one"
    );
    assert_eq!(
        e.run(r, &["pending", "--repo", "demo", "--json"]).trim(),
        "[]"
    );
    // The lease is free again: the worker leases, fixes and proposes.
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#charge"]);
    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a + 1\n}\n",
    )
    .unwrap();
    let p: serde_json::Value = serde_json::from_str(&e.run(
        &ws,
        &["propose", "-i", "add one", "--accept-facts", "--json"],
    ))
    .unwrap();
    assert_eq!(p["status"], "pending", "{p}");
}

/// A git checkout as the human's client: `lonca fetch` brings trunk in
/// through the daemon, `lonca propose --commit` sends a commit out, and
/// a commit on a stale base merges (issue #83). The store is never opened.
#[test]
fn a_git_checkout_fetches_and_proposes_through_the_daemon() {
    let e = Env::new();
    let r = &e.root;
    let co = r.join("co");
    std::fs::create_dir_all(co.join("src")).unwrap();
    std::fs::write(
        co.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    std::fs::write(co.join("README.md"), "demo\n").unwrap();
    let g = |args: &[&str]| -> String {
        let o = Command::new("git")
            .current_dir(&co)
            .args(args)
            .output()
            .unwrap();
        assert!(o.status.success(), "git {args:?}: {}", text(&o.stderr));
        text(&o.stdout).trim().to_string()
    };
    g(&["init", "-q", "-b", "main"]);
    g(&["add", "."]);
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-m",
        "first",
    ]);
    let first = g(&["rev-parse", "HEAD"]);
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(
        e.run(r, &["init", "demo", "--import", co.to_str().unwrap()])
            .contains("allow")
    );

    // Fetch: refs/lonca/trunk is the imported commit, the store untouched.
    let f: serde_json::Value =
        serde_json::from_str(&e.run(&co, &["fetch", "--repo", "demo", "--json"])).unwrap();
    assert_eq!(f["trunk"], first);
    assert_eq!(f["bytes"], 0, "the checkout already had the commit: {f}");
    assert_eq!(g(&["rev-parse", "refs/lonca/trunk"]), first);
    assert_eq!(g(&["config", "--get", "lonca.repo"]), "demo");
    let st: serde_json::Value =
        serde_json::from_str(&e.run(r, &["status", "--repo", "demo", "--json"])).unwrap();
    assert_eq!(st["trunk"], first);

    // A commit proposed from the checkout integrates with the same tree.
    std::fs::write(
        co.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n",
    )
    .unwrap();
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-am",
        "double charge",
    ]);
    let p: serde_json::Value =
        serde_json::from_str(&e.run(&co, &["propose", "--commit", "HEAD", "-i", "", "--json"]))
            .unwrap();
    assert_eq!(p["status"], "queued", "{p}");
    assert_eq!(p["base"], first);
    e.settle();
    let f: serde_json::Value = serde_json::from_str(&e.run(&co, &["fetch", "--json"])).unwrap();
    assert_eq!(f["behind"], 1);
    assert_eq!(
        g(&["rev-parse", "refs/lonca/trunk^{tree}"]),
        g(&["rev-parse", "HEAD^{tree}"])
    );
    let c: serde_json::Value = serde_json::from_str(&e.run(
        r,
        &["change", p["change"].as_str().unwrap(), "--repo", "demo"],
    ))
    .unwrap();
    assert_eq!(
        c["claim"]["intent"], "double charge",
        "the commit subject is the intent"
    );
    assert_eq!(c["status"]["status"], "integrated");
    g(&["reset", "-q", "--hard", "refs/lonca/trunk"]);

    // Meanwhile trunk moves (a workspace change); a commit on the stale
    // base still merges structurally.
    e.run(r, &["workspace", "create", "hws", "--repo", "demo"]);
    let hws = r.join("hws");
    std::fs::write(hws.join("README.md"), "demo, now with notes\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "notes"]).contains("allow"));
    e.settle();
    std::fs::write(co.join("src/lib.rs"), "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n").unwrap();
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-am",
        "refund",
    ]);
    let p: serde_json::Value =
        serde_json::from_str(&e.run(&co, &["propose", "--commit", "HEAD", "--json"])).unwrap();
    assert_eq!(p["status"], "queued", "{p}");
    e.settle();
    let c: serde_json::Value = serde_json::from_str(&e.run(
        r,
        &["change", p["change"].as_str().unwrap(), "--repo", "demo"],
    ))
    .unwrap();
    assert_eq!(c["status"]["status"], "integrated", "{c}");
    let f: serde_json::Value = serde_json::from_str(&e.run(&co, &["fetch", "--json"])).unwrap();
    assert_eq!(f["behind"], 2);
    assert_eq!(
        g(&["show", "refs/lonca/trunk:README.md"]),
        "demo, now with notes"
    );
    assert!(g(&["show", "refs/lonca/trunk:src/lib.rs"]).contains("refund"));
    // Nothing to propose: already in trunk after a reset.
    g(&["reset", "-q", "--hard", "refs/lonca/trunk"]);
    let out = e
        .cmd(&co, &["propose", "--commit", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("already in trunk"),
        "{}",
        text(&out.stderr)
    );

    // File modes travel: an executable stays executable; symlinks and
    // submodules are refused by name.
    std::fs::write(co.join("run.sh"), "#!/bin/sh\necho hi\n").unwrap();
    g(&["add", "run.sh"]);
    g(&["update-index", "--chmod=+x", "run.sh"]);
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-m",
        "script",
    ]);
    let p: serde_json::Value =
        serde_json::from_str(&e.run(&co, &["propose", "--commit", "HEAD", "--json"])).unwrap();
    assert_eq!(p["status"], "queued", "{p}");
    e.settle();
    e.run(&co, &["fetch"]);
    assert!(
        g(&["ls-tree", "refs/lonca/trunk", "run.sh"]).starts_with("100755"),
        "mode kept"
    );
    g(&["reset", "-q", "--hard", "refs/lonca/trunk"]);
    std::os::unix::fs::symlink("README.md", co.join("link")).unwrap();
    g(&["add", "link"]);
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-m",
        "link",
    ]);
    let out = e
        .cmd(&co, &["propose", "--commit", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("link: symlinks are not proposed"),
        "{}",
        text(&out.stderr)
    );
    g(&["reset", "-q", "--hard", "refs/lonca/trunk"]);
    // A gitlink entry without a real submodule is enough to be refused.
    g(&[
        "update-index",
        "--add",
        "--cacheinfo",
        &format!("160000,{first},vendor/dep"),
    ]);
    g(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@t",
        "commit",
        "-q",
        "-m",
        "submodule",
    ]);
    let out = e
        .cmd(&co, &["propose", "--commit", "HEAD"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("vendor/dep: submodules are not proposed"),
        "{}",
        text(&out.stderr)
    );
}

/// Over the MCP stdio loop: the worker renews a set by a tool call, and
/// the server reports the session alive with no call at all.
#[test]
fn an_mcp_worker_renews_its_lease_and_the_server_beats_for_it() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let mut mcp = Mcp::start(&e, &ws);

    let tools = mcp.request("tools/list", json!({}));
    let names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"lease_renew"), "{names:?}");

    let (err, got) = mcp.tool(
        "lease_acquire",
        json!({"symbols": ["src/lib.rs#charge"], "intent": "work", "ttl_minutes": 5}),
    );
    assert!(!err, "{got}");
    assert_eq!(got["decision"]["outcome"], "allow", "{got}");
    let set = got["set"].as_str().unwrap().to_string();
    let expires = || status_json(&e)["leases"][0]["expires_ms"].as_i64().unwrap();
    let before = expires();

    let (err, renewed) = mcp.tool("lease_renew", json!({"set": set, "ttl_minutes": 20}));
    assert!(!err, "{renewed}");
    assert_eq!(renewed["decision"]["outcome"], "allow", "{renewed}");
    assert!(expires() >= before + 15 * 60_000);

    let (err, kept) = mcp.tool("lease_renew", json!({"set": set}));
    assert!(!err, "{kept}");
    let default = expires();
    assert!(default < before + 15 * 60_000, "ten minutes from now");

    let (_, denied) = mcp.tool("lease_renew", json!({"set": set, "ttl_minutes": 999}));
    assert_eq!(denied["decision"]["outcome"], "deny", "{denied}");
    assert_eq!(denied["decision"]["reasons"][0], "lease_ttl");
    assert_eq!(expires(), default);

    let mut seen = serde_json::Value::Null;
    for _ in 0..100 {
        seen = status_json(&e)["sessions"][0]["last_seen_ms"].clone();
        if !seen.is_null() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(seen.is_i64(), "no heartbeat from lonca mcp");

    let out = e.run(&ws, &["session", "heartbeat", "--json"]);
    let beat: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(beat["timeout_ms"], 300_000, "{beat}");
    assert_eq!(beat["leases"][0]["set"], set.as_str());
    assert!(beat["seq"].is_u64());
    assert!(e.run(&ws, &["session", "heartbeat"]).contains("allow"));
}

/// Mixed kinds in one set, what the local diff needs, a partial release
/// and a failure, all over the MCP stdio loop.
#[test]
fn mcp_leases_mixed_kinds_says_what_is_needed_and_releases_part_of_a_set() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let mut mcp = Mcp::start(&e, &ws);

    let (_, none) = mcp.tool("lease_needed", json!({}));
    assert_eq!(
        none,
        json!({"changes": 0, "leases": [], "acquire": [], "advice": null, "no_lease": []})
    );

    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n\npub fn extra() {}\n",
    )
    .unwrap();
    let (err, needed) = mcp.tool("lease_needed", json!({}));
    assert!(!err, "{needed}");
    assert_eq!(needed["changes"], 1);
    assert_eq!(
        needed["acquire"],
        json!([
            {"symbol": "src/lib.rs#<file>", "kind": "insert"},
            {"symbol": "src/lib.rs#charge", "kind": "edit"},
        ])
    );
    let out = e.run(&ws, &["lease", "needed", "--json"]);
    let cli: serde_json::Value = serde_json::from_str(out.trim()).unwrap();
    assert_eq!(cli, needed);
    assert!(
        e.run(&ws, &["lease", "needed"])
            .contains("edit src/lib.rs#charge: free")
    );

    // What lease_needed says goes straight into lease_acquire, all or nothing.
    let (err, got) = mcp.tool(
        "lease_acquire",
        json!({"items": needed["acquire"], "intent": "both"}),
    );
    assert!(!err, "{got}");
    assert_eq!(got["decision"]["outcome"], "allow", "{got}");
    let set = got["set"].as_str().unwrap().to_string();
    let (_, needed) = mcp.tool("lease_needed", json!({}));
    assert_eq!(needed["acquire"], json!([]));
    assert_eq!(needed["leases"][0]["code"], "held_by_you");

    // Part of the set goes, the rest stays for the time it had left.
    let expires = status_json(&e)["leases"][0]["expires_ms"].as_i64().unwrap();
    let (err, part) = mcp.tool(
        "lease_release",
        json!({"set": set, "items": [{"symbol": "src/lib.rs#charge", "kind": "edit"}]}),
    );
    assert!(!err, "{part}");
    assert_eq!(part["decision"]["outcome"], "allow", "{part}");
    assert_eq!(
        part["kept"],
        json!([{"symbol": "src/lib.rs#<file>", "kind": "insert"}])
    );
    let leases = status_json(&e)["leases"].clone();
    assert_eq!(leases.as_array().unwrap().len(), 1, "{leases}");
    assert_eq!(leases[0]["set"], part["set"]);
    assert_eq!(leases[0]["items"], part["kept"]);
    assert_eq!(leases[0]["intent"], "both");
    let left = expires - leases[0]["expires_ms"].as_i64().unwrap();
    assert!(left.abs() < 60_000, "{left}");

    // The last item: nothing is kept, no new set.
    let new_set = part["set"].as_str().unwrap().to_string();
    let (err, last) = mcp.tool(
        "lease_release",
        json!({"set": new_set, "items": [{"symbol": "src/lib.rs#<file>", "kind": "insert"}]}),
    );
    assert!(!err, "{last}");
    assert_eq!(last["set"], serde_json::Value::Null);
    assert_eq!(status_json(&e)["leases"], json!([]));

    // Failures are JSON with a code.
    let (err, body) = mcp.tool(
        "lease_release",
        json!({"set": "nope", "items": [{"symbol": "src/lib.rs#charge", "kind": "edit"}]}),
    );
    assert!(err);
    assert_eq!(body["code"], "invalid", "{body}");
    assert_eq!(body["details"], json!([]));
    assert!(body["message"].as_str().unwrap().contains("nope"));
    // A whole-set release of an unknown set stays a logged denial.
    let (err, denied) = mcp.tool("lease_release", json!({"set": "nope"}));
    assert!(!err);
    assert_eq!(denied["decision"]["reasons"][0], "unknown_lease_set");
}

/// Runs `lonca` and expects a refusal: exit 1, the reason on stderr,
/// and on stdout what the command printed (its JSON, if it was asked for).
fn refused(e: &Env, cwd: &Path, args: &[&str], reason: &str) -> String {
    let out = e.cmd(cwd, args).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "{args:?}: {}",
        text(&out.stderr)
    );
    let stderr = text(&out.stderr);
    assert!(
        stderr.contains("denied: ") && stderr.contains(reason),
        "{stderr}"
    );
    text(&out.stdout)
}

fn parse(s: &str) -> serde_json::Value {
    serde_json::from_str(s.trim()).unwrap_or_else(|err| panic!("{err}: {s}"))
}

/// The contract of #77 on the commands it left out (issue #97).
#[test]
fn lease_commands_exit_one_on_denial_and_speak_json() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    let second = [
        "session",
        "start",
        "--repo",
        "demo",
        "--agent",
        "codex",
        "--paths",
        "src/**",
        "--workspace",
        "ws2",
    ];
    e.run(r, &second);
    let ws2 = r.join("ws2");

    let held = parse(&e.run(
        &ws,
        &[
            "lease",
            "acquire",
            "src/lib.rs#charge",
            "-i",
            "doubling",
            "--json",
        ],
    ));
    assert_eq!(held["decision"]["outcome"], "allow", "{held}");
    assert_eq!(held["details"], json!([]));
    assert!(held["seq"].as_u64().unwrap() > 0, "{held}");
    let set = held["set"].as_str().unwrap().to_string();
    assert!(set.starts_with("lse_"), "{held}");

    // Denied: JSON on stdout says who stands in the way, stderr the reason.
    let args = [
        "lease",
        "acquire",
        "-i",
        "fix",
        "src/lib.rs#charge",
        "--json",
    ];
    let denied = parse(&refused(&e, &ws2, &args, "lease_held:src/lib.rs#charge"));
    assert_eq!(denied["decision"]["outcome"], "deny");
    let d = &denied["details"][0];
    assert_eq!(d["code"], "lease_held", "{denied}");
    assert_eq!(d["holder_agent"], "claude");
    assert_eq!(d["intent"], "doubling");
    assert_eq!(d["set"], set.as_str());
    assert_eq!(d["pinned_to"], serde_json::Value::Null);
    // Without --json the denial exits the same way and names no set.
    let args = ["lease", "acquire", "-i", "fix", "src/lib.rs#charge"];
    let out = refused(&e, &ws2, &args, "lease_held");
    assert!(!out.contains("lease set"), "{out}");

    // Somebody else's set can be neither renewed nor released.
    refused(&e, &ws2, &["lease", "renew", &set], "not_own_lease");
    let args = ["lease", "release", &set, "--json"];
    let denied = parse(&refused(&e, &ws2, &args, "not_own_lease"));
    assert_eq!(denied["set"], set.as_str());
    assert_eq!(denied["decision"]["outcome"], "deny");
    assert_eq!(denied["details"], json!([]));

    // Allowed: exit 0, the set they were given, and the text form too.
    let renewed = parse(&e.run(&ws, &["lease", "renew", &set, "--json"]));
    assert_eq!(renewed["set"], set.as_str());
    assert_eq!(renewed["decision"]["outcome"], "allow", "{renewed}");
    assert!(e.run(&ws, &["lease", "renew", &set]).contains("allow"));

    // A proposal without its lease names the symbol and the kind.
    let edited = "pub fn charge(a: u64) -> u64 {\n    a\n}\n\npub fn refund(a: u64) -> u64 {\n    a * 2\n}\n";
    std::fs::write(ws2.join("src/lib.rs"), edited).unwrap();
    let args = ["propose", "-i", "x", "--accept-facts", "--json"];
    let denied = parse(&refused(&e, &ws2, &args, "lease_missing"));
    assert_eq!(denied["status"], "denied");
    let d = &denied["details"][0];
    assert_eq!(d["code"], "lease_missing", "{denied}");
    assert_eq!(d["symbol"], "src/lib.rs#refund");
    assert_eq!(d["needed_kind"], "edit");

    // The held symbol, pinned to a change in flight: the detail says so.
    let doubled = "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n";
    std::fs::write(ws.join("src/lib.rs"), doubled).unwrap();
    let args = ["propose", "-i", "double", "--accept-facts", "--json"];
    let proposed = parse(&e.run(&ws, &args));
    assert_eq!(proposed["status"], "pending", "{proposed}");
    assert_eq!(proposed["details"], json!([]));
    let args = [
        "lease",
        "acquire",
        "-i",
        "fix",
        "src/lib.rs#charge",
        "--json",
    ];
    let denied = parse(&refused(&e, &ws2, &args, "lease_held"));
    assert_eq!(denied["details"][0]["pinned_to"], proposed["change"]);

    // A set nobody pinned goes with an answer in JSON too.
    let got = parse(&e.run(
        &ws2,
        &[
            "lease",
            "acquire",
            "-i",
            "fix",
            "src/lib.rs#refund",
            "--json",
        ],
    ));
    let free = got["set"].as_str().unwrap();
    let released = parse(&e.run(&ws2, &["lease", "release", free, "--json"]));
    assert_eq!(released["set"], free);
    assert_eq!(released["decision"]["outcome"], "allow", "{released}");
    assert_eq!(released["seq"], got["seq"].as_u64().unwrap() + 1);
    assert_eq!(status_json(&e)["leases"].as_array().unwrap().len(), 1);
}

/// Every command that signs reports a denial in its exit code, not only
/// the ones a runner drives (issue #97).
#[test]
fn a_human_operation_that_is_denied_exits_one() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    let args = [
        "session", "revoke", "ses_nope", "--repo", "demo", "--reason", "x",
    ];
    refused(&e, r, &args, "unknown_session");

    // Undoing a lease that is gone: the compensating release is refused.
    let got = parse(&e.run(
        &ws,
        &[
            "lease",
            "acquire",
            "-i",
            "fix",
            "src/lib.rs#charge",
            "--json",
        ],
    ));
    let seq = got["seq"].as_u64().unwrap().to_string();
    e.run(&ws, &["lease", "release", got["set"].as_str().unwrap()]);
    let args = ["undo", &seq, "--repo", "demo"];
    refused(&e, r, &args, "unknown_lease_set");

    // Revert goes on past a refused step and ends with the refusal.
    let args = [
        "revert",
        "--actor",
        "agent:claude",
        "--apply",
        "--repo",
        "demo",
    ];
    let out = refused(&e, r, &args, "unknown_lease_set");
    assert!(out.contains(&format!("#{seq} (release lease set")), "{out}");
    assert!(out.contains("not undone"), "{out}");
}

/// `workspace create --json` and `init --json` for a runner setting up a
/// project (issue #97).
#[test]
fn a_workspace_is_created_with_json() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    let init = parse(&e.run(r, &["init", "demo", "--json"]));
    assert_eq!(init["repo"], "demo");
    assert_eq!(init["decision"]["outcome"], "allow", "{init}");
    assert_eq!(init["seq"], 0, "{init}");
    assert_eq!(init["warnings"], json!([]));
    let status = status_json(&e);
    assert_eq!(init["trunk"], status["trunk"]);

    let args = ["workspace", "create", "w1", "--repo", "demo", "--json"];
    let w = parse(&e.run(r, &args));
    assert_eq!(w["workspace"].as_str(), r.join("w1").to_str());
    assert_eq!(w["repo"], "demo");
    assert_eq!(w["base"], status["trunk"]);
    assert!(r.join("w1/.lonca").is_dir());
}

/// A fake daemon on a socket: whatever reaches it is kept.
fn fake_daemon(sock: &Path) -> std::sync::Arc<std::sync::Mutex<Vec<u8>>> {
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let kept = seen.clone();
    let listener = std::os::unix::net::UnixListener::bind(sock).unwrap();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            use std::io::Read;
            let mut buf = [0u8; 4096];
            let Ok(mut conn) = conn else { return };
            let _ = conn.set_read_timeout(Some(std::time::Duration::from_millis(100)));
            while let Ok(n) = conn.read(&mut buf) {
                if n == 0 {
                    break;
                }
                kept.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        }
    });
    seen
}

fn current_uid() -> u32 {
    lonca_daemon::trust::current_uid()
}

/// `LONCA_SOCKET` pointing at a process that is not the daemon: the hook
/// blocks the call, the CLI and the MCP server stop, and the token never
/// leaves the workspace (issue #52).
#[test]
fn a_fake_daemon_gets_no_token_and_the_hook_blocks() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let fake = e.root.join("f");
    let seen = fake_daemon(&fake);
    let other = (current_uid() + 1).to_string();
    let run = |args: &[&str], input: &[u8]| {
        let mut child = e
            .cmd(&ws, args)
            .env("LONCA_SOCKET", &fake)
            .env("LONCA_TEST_DAEMON_UID", &other)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().unwrap()
    };

    let input = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{{"file_path":"x"}},"cwd":"{}"}}"#,
        ws.display()
    );
    let o = run(&["hook"], input.as_bytes());
    assert_eq!(o.status.code(), Some(2), "fails closed");
    let stderr = text(&o.stderr);
    assert!(stderr.contains("nothing was sent"), "{stderr}");
    assert!(!stderr.contains("is `lonca daemon` running"), "{stderr}");

    let o = run(&["session", "heartbeat", "--json"], b"");
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    let o = run(&["mcp"], b"");
    assert_ne!(o.status.code(), Some(0), "{}", text(&o.stderr));
    std::thread::sleep(std::time::Duration::from_millis(50));
    assert_eq!(seen.lock().unwrap().as_slice(), b"", "not a byte");
}

/// With the uid the file names, a hardened client talks to its daemon; the
/// socket's directory is what it asks of it beyond a cooperative client.
#[test]
fn a_hardened_client_trusts_the_daemon_it_was_told_of() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let me = current_uid().to_string();
    let run = |e: &Env| {
        e.cmd(&ws, &["session", "heartbeat"])
            .env("LONCA_TEST_DAEMON_UID", &me)
            .output()
            .unwrap()
    };
    let o = run(&e);
    assert!(o.status.success(), "{}", text(&o.stderr));

    use std::os::unix::fs::PermissionsExt;
    let open = std::fs::Permissions::from_mode(0o777);
    std::fs::set_permissions(&e.root, open).unwrap();
    let o = run(&e);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o.stderr));
    assert!(
        text(&o.stderr).contains("writable by others"),
        "{}",
        text(&o.stderr)
    );
}

fn session_args<'a>(paths: &'a str, extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec![
        "session", "start", "--repo", "demo", "--agent", "claude", "--paths", paths,
    ];
    args.extend_from_slice(extra);
    args
}

/// A worker outlives its session: a human continues the workspace and the
/// edit goes on from where it stood (issue #98).
#[test]
fn an_expired_sessions_edit_lands_under_its_continuation() {
    let e = Env::new();
    agent_workspace(&e);
    let r = &e.root;
    e.run(
        r,
        &session_args("src/**", &["--workspace", "w1", "--ttl", "1s"]),
    );
    let w1 = r.join("w1");
    let edited = "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n";
    std::fs::write(w1.join("src/lib.rs"), edited).unwrap();
    let meta = |w: &Path| parse(&std::fs::read_to_string(w.join(".lonca/workspace.json")).unwrap());
    let before = meta(&w1);
    let first = before["session"].as_str().unwrap().to_string();
    let old_token = std::fs::read_to_string(w1.join(".lonca/session")).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1100));

    // The session is over, and it hears so.
    let args = ["lease", "acquire", "-i", "fix", "src/lib.rs#charge"];
    refused(&e, &w1, &args, "session_inactive");
    let out = e
        .cmd(&w1, &["session", "heartbeat", "--json"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("session_inactive"),
        "{}",
        text(&out.stderr)
    );
    assert_eq!(text(&out.stdout), "");

    let args = session_args("src/**", &["--continue", "w1", "--json"]);
    let c = parse(&e.run(r, &args));
    let second = c["session"].as_str().unwrap().to_string();
    assert_ne!(second, first);
    assert_eq!(c["continues"], first.as_str());
    assert_eq!(c["workspace"].as_str(), w1.to_str());
    assert_eq!(c["decision"]["outcome"], "allow", "{c}");

    // Files, base and manifest stayed; session and token did not.
    assert_eq!(
        std::fs::read_to_string(w1.join("src/lib.rs")).unwrap(),
        edited
    );
    let after = meta(&w1);
    assert_eq!(after["session"], second.as_str());
    assert_eq!(after["base"], before["base"]);
    assert_eq!(after["manifest"], before["manifest"]);
    let token = std::fs::read_to_string(w1.join(".lonca/session")).unwrap();
    assert_ne!(token, old_token);
    assert!(!c.to_string().contains(token.trim()));

    let held = e.run(
        &w1,
        &[
            "lease",
            "acquire",
            "-i",
            "fix",
            "src/lib.rs#charge",
            "--json",
        ],
    );
    assert_eq!(parse(&held)["decision"]["outcome"], "allow", "{held}");
    let args = ["propose", "-i", "double", "--accept-facts", "--json"];
    let proposed = parse(&e.run(&w1, &args));
    assert_eq!(proposed["status"], "pending", "{proposed}");
    let seq = proposed["seq"].as_u64().unwrap().to_string();
    e.run(r, &["approve", &seq, "--repo", "demo"]);
    e.settle();
    let s = status_json(&e);
    let mut changes = s["changes"].as_array().unwrap().iter();
    let change = changes.find(|c| c["change"] == proposed["change"]).unwrap();
    assert_eq!(change["status"]["status"], "integrated", "{change}");

    // Text form says what it continued.
    let args = session_args("src/**", &["--continue", "w1"]);
    let out = e.run(r, &args);
    assert!(out.contains(&format!("continues {second}")), "{out}");
}

#[test]
fn continuing_a_live_session_leaves_one_session_and_a_pending_change_stands() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#charge"]);
    let args = ["propose", "-i", "double", "--accept-facts", "--json"];
    let proposed = parse(&e.run(&ws, &args));
    assert_eq!(proposed["status"], "pending", "{proposed}");
    let old_token = std::fs::read_to_string(ws.join(".lonca/session")).unwrap();

    let args = session_args("src/**", &["--continue", "ws", "--json"]);
    let c = parse(&e.run(r, &args));
    let s = status_json(&e);
    let all = s["sessions"].as_array().unwrap().iter();
    let active: Vec<_> = all.filter(|x| x["active"] == true).collect();
    assert_eq!(active.len(), 1, "{s}");
    assert_eq!(active[0]["id"], c["session"]);
    assert_eq!(s["pending"][0]["change"], proposed["change"]);
    assert_eq!(s["leases"][0]["session"], c["session"], "{s}");
    assert_eq!(
        s["leases"][0]["pinned"][0]["change"], proposed["change"],
        "{s}"
    );

    // The old token is refused; the workspace works on the new one.
    let heart = e.cmd(&ws, &["session", "heartbeat"]).output().unwrap();
    assert!(heart.status.success(), "{}", text(&heart.stderr));
    let keep = std::fs::read_to_string(ws.join(".lonca/session")).unwrap();
    std::fs::write(ws.join(".lonca/session"), &old_token).unwrap();
    let out = e.cmd(&ws, &["session", "heartbeat"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    std::fs::write(ws.join(".lonca/session"), keep).unwrap();

    // On top of the pending change: an edit of another symbol.
    let synced = parse(&e.run(&ws, &["sync", "--json"]));
    assert_eq!(synced["conflicts"], json!([]));
    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund(a: u64) -> u64 {\n    a * 3\n}\n",
    )
    .unwrap();
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#refund"]);
    let args = ["propose", "-i", "more", "--accept-facts", "--json"];
    let next = parse(&e.run(&ws, &args));
    assert_eq!(next["status"], "pending", "{next}");
}

#[test]
fn continuing_is_refused_without_a_workspace_of_the_repository_or_a_plain_scope() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    let fails = |args: Vec<&str>, code: i32, says: &str| {
        let out = e.cmd(r, &args).output().unwrap();
        let stderr = text(&out.stderr);
        assert_eq!(out.status.code(), Some(code), "{args:?}: {stderr}");
        assert!(stderr.contains(says), "{stderr}");
    };

    // A wider scope is refused, and leaves the old session running.
    let args = session_args("src/**,docs/**", &["--continue", "ws"]);
    fails(args, 1, "scope_widening:path:docs/**");
    assert!(
        e.cmd(&ws, &["session", "heartbeat"])
            .output()
            .unwrap()
            .status
            .success()
    );
    // Asked for plainly, it goes through.
    let args = session_args("src/**,docs/**", &["--continue", "ws", "--widen", "--json"]);
    let c = parse(&e.run(r, &args));
    assert_eq!(c["paths"], json!(["src/**", "docs/**"]));

    // No workspace, a subdirectory of one, a human's, another repository's.
    std::fs::create_dir_all(r.join("plain")).unwrap();
    fails(
        session_args("src/**", &["--continue", "plain"]),
        3,
        "is not a Lonca workspace",
    );
    fails(
        session_args("src/**", &["--continue", "ws/src"]),
        3,
        "is not a Lonca workspace",
    );
    fails(
        session_args("src/**", &["--continue", "hws"]),
        3,
        "is a human workspace",
    );
    e.run(r, &["init", "other"]);
    let mut args = session_args("src/**", &["--continue", "ws"]);
    args[3] = "other";
    fails(args, 3, "is a workspace of repository demo, not other");

    // Usage: one of the two, and --widen only with --continue.
    let usage = |args: &[&str]| e.cmd(r, args).output().unwrap().status.code();
    assert_eq!(usage(&session_args("src/**", &[])), Some(3));
    let args = session_args("src/**", &["--continue", "ws", "--workspace", "x"]);
    assert_eq!(usage(&args), Some(3));
    assert_eq!(
        usage(&session_args("src/**", &["--workspace", "x", "--widen"])),
        Some(3)
    );
}

/// A tainted session's workspace stays tainted through the CLI.
#[test]
fn a_continuation_is_tainted_when_the_session_it_continues_was() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    // Scope is what the workspace was given; a file no hook saw is what
    // taints an observed session, so the taint comes from a hook event.
    let event = json!({
        "hook_event_name": "PreToolUse", "tool_name": "WebFetch",
        "tool_input": {"url": "https://example.com/"}, "cwd": ws,
    });
    let out = e.hook(&ws, &event.to_string());
    assert_ne!(out.status.code(), None);
    let tainted = |e: &Env, id: &serde_json::Value| {
        let s = status_json(e);
        let mut all = s["sessions"].as_array().unwrap().iter();
        all.find(|x| x["id"] == *id).unwrap()["taint"].clone()
    };
    let meta = parse(&std::fs::read_to_string(ws.join(".lonca/workspace.json")).unwrap());
    let old = tainted(&e, &meta["session"]);
    assert!(
        old.is_string(),
        "the hook did not taint: {}",
        status_json(&e)
    );

    let args = session_args("src/**", &["--continue", "ws", "--json"]);
    let c = parse(&e.run(r, &args));
    assert_eq!(tainted(&e, &c["session"]), old);
}

/// A session that is over stops `lonca mcp`'s heartbeat, and its next
/// tool result says so in the shape of every failure.
#[test]
fn the_mcp_server_stops_beating_and_tells_the_worker_the_session_ended() {
    let e = Env::new();
    agent_workspace(&e);
    let r = &e.root;
    e.run(
        r,
        &session_args("src/**", &["--workspace", "w1", "--ttl", "1s"]),
    );
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let mut mcp = Mcp::start(&e, &r.join("w1"));
    let mut said = None;
    for _ in 0..100 {
        let (err, body) = mcp.tool("preview", json!({}));
        if err && body["code"] == "session_inactive" {
            said = Some(body);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let body = said.expect("the worker was never told");
    assert!(
        body["message"].as_str().unwrap().contains("--continue"),
        "{body}"
    );
    assert_eq!(body["details"], json!([]));
    // Any tool: the session is over for all of them.
    let (err, again) = mcp.tool("status", json!({}));
    assert!(err, "{again}");
    assert_eq!(again["code"], "session_inactive");
}

/// A change of an earlier session is still the workspace's for the worker.
#[test]
fn mcp_status_shows_the_change_the_workspace_proposed_under_its_old_session() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    std::fs::write(
        ws.join("src/lib.rs"),
        "pub fn charge(a: u64) -> u64 {\n    a * 2\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n",
    )
    .unwrap();
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#charge"]);
    let args = ["propose", "-i", "double", "--accept-facts", "--json"];
    let proposed = parse(&e.run(&ws, &args));
    e.run(r, &session_args("src/**", &["--continue", "ws"]));
    let mut mcp = Mcp::start(&e, &ws);
    let (err, st) = mcp.tool("status", json!({}));
    assert!(!err, "{st}");
    assert_eq!(st["your_changes"][0]["change"], proposed["change"], "{st}");
}

fn checks(report: &serde_json::Value, name: &str) -> serde_json::Value {
    let all = report["checks"].as_array().unwrap();
    all.iter()
        .find(|c| c["name"] == name)
        .unwrap_or_else(|| panic!("no {name}: {report}"))
        .clone()
}

/// One command that shows what is wrong, as data, and leaks nothing
/// (issue #9).
#[test]
fn doctor_reports_the_setup_and_no_secrets() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    e.run(&ws, &["session", "heartbeat"]);
    let missing = r.join("no-settings.json");
    let args = [
        "doctor",
        "--json",
        "--managed-settings",
        missing.to_str().unwrap(),
    ];
    let out = e
        .cmd(r, &args)
        .env("PATH", std::env::var_os("PATH").unwrap())
        .output()
        .unwrap();
    let stdout = text(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{stdout}{}", text(&out.stderr));
    let report = parse(&stdout);
    assert_eq!(report["ok"], true, "{report}");
    assert_eq!(report["mode"], "cooperative");
    assert_eq!(checks(&report, "mode")["level"], "pass");
    assert_eq!(checks(&report, "socket")["level"], "pass");
    assert_eq!(checks(&report, "daemon")["level"], "pass");
    let hooks = checks(&report, "hooks");
    assert_eq!(hooks["level"], "warn", "cooperative: {report}");
    assert!(hooks["hint"].as_str().unwrap().contains("unobserved"));
    assert_eq!(checks(&report, "human")["detail"], "ayse");
    let log = checks(&report, "log demo");
    assert_eq!(log["level"], "pass", "{report}");
    assert!(log["detail"].as_str().unwrap().contains("entries verify"));
    assert_eq!(checks(&report, "human demo")["level"], "pass");

    // No token of any kind, no key, and no path to where they live.
    let session = std::fs::read_to_string(r.join("humans/ayse.session")).unwrap();
    let human_token = parse(&session)["token"].as_str().unwrap().to_string();
    let agent_token = std::fs::read_to_string(ws.join(".lonca/session")).unwrap();
    assert!(!stdout.contains(&human_token), "{stdout}");
    assert!(!stdout.contains(agent_token.trim()), "{stdout}");
    assert!(!stdout.contains("/humans"), "{stdout}");

    // In text, the same facts; a frozen repository is a warning.
    e.run(r, &["freeze", "hold on", "--repo", "demo"]);
    let args = ["doctor", "--managed-settings", missing.to_str().unwrap()];
    let out = e.run(r, &args);
    assert!(out.contains("pass  log demo:"), "{out}");
    assert!(out.contains("warn  frozen demo: hold on"), "{out}");
    assert!(out.contains("warn  hooks:"), "{out}");
}

/// A failing check does not stop the others, and the exit code says so.
#[test]
fn doctor_fails_without_a_daemon_and_says_what_to_do() {
    let e = Env::new();
    let r = &e.root;
    let out = e
        .cmd(r, &["doctor", "--json"])
        .env("LONCA_SOCKET", r.join("nope"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("check(s) failed"),
        "{}",
        text(&out.stderr)
    );
    let report = parse(&text(&out.stdout));
    assert_eq!(report["ok"], false);
    let socket = checks(&report, "socket");
    assert_eq!(socket["level"], "fail");
    assert!(socket["hint"].as_str().unwrap().contains("lonca daemon"));
    assert_eq!(checks(&report, "daemon")["level"], "fail");
    assert_eq!(checks(&report, "sandbox")["name"], "sandbox");
    assert_eq!(checks(&report, "git")["name"], "git");

    // Not a hardened daemon, on a client told to expect one: the settings
    // and the socket both fail.
    let e = Env::new();
    agent_workspace(&e);
    let other = (current_uid() + 1).to_string();
    let out = e
        .cmd(&e.root, &["doctor", "--json"])
        .env("LONCA_TEST_DAEMON_UID", &other)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", text(&out.stderr));
    let report = parse(&text(&out.stdout));
    assert_eq!(report["mode"], "hardened");
    assert_eq!(checks(&report, "socket")["level"], "fail");
    assert_eq!(checks(&report, "hooks")["level"], "fail");
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["name"] != "human")
    );
}

/// A human who has not logged in, or who no repository knows.
#[test]
fn doctor_says_when_it_can_not_look_at_repositories() {
    let e = Env::new();
    let r = &e.root;
    agent_workspace(&e);
    let run = |e: &Env, human: &str| {
        let out = e
            .cmd(r, &["doctor", "--json"])
            .env("LONCA_HUMAN", human)
            .output()
            .unwrap();
        parse(&text(&out.stdout))
    };
    let stranger = run(&e, "nobody");
    let human = checks(&stranger, "human");
    assert_eq!(human["level"], "warn", "{stranger}");
    assert!(human["detail"].as_str().unwrap().contains("nobody"));
    assert!(!stranger.to_string().contains("/humans"), "{stranger}");

    let no_home = e
        .cmd(r, &["doctor", "--json"])
        .env("LONCA_HUMANS", r.join("empty"))
        .output()
        .unwrap();
    let report = parse(&text(&no_home.stdout));
    assert_eq!(checks(&report, "human")["detail"], "no human identity");
}

/// A repository that asks for what this human's key can not give.
#[test]
fn doctor_warns_of_a_file_key_in_a_repository_that_requires_presence() {
    let e = Env::new();
    let r = &e.root;
    agent_workspace(&e);
    let shown = e.run(r, &["policy", "show", "--repo", "demo"]);
    let (_, rest) = shown.split_once("==> lonca.toml <==\n").unwrap();
    let (config, policy) = rest.split_once("==> policy.cedar <==\n").unwrap();
    let config = config.replace("require_presence = false", "require_presence = true");
    std::fs::write(r.join("c.toml"), config.trim_end()).unwrap();
    std::fs::write(r.join("p.cedar"), policy.trim_end()).unwrap();
    let args = [
        "policy", "set", "--repo", "demo", "--config", "c.toml", "--policy", "p.cedar",
    ];
    assert!(e.run(r, &args).contains("allow"));

    let out = e.cmd(r, &["doctor", "--json"]).output().unwrap();
    let report = parse(&text(&out.stdout));
    let human = checks(&report, "human demo");
    assert_eq!(human["level"], "warn", "{report}");
    assert!(
        human["detail"]
            .as_str()
            .unwrap()
            .contains("requires presence")
    );
}

/// `lease interest` and `events` on the CLI and over MCP (issue #42).
#[test]
fn a_worker_waits_for_a_lease_and_hears_when_it_is_free() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    e.run(r, &session_args("src/**", &["--workspace", "w2"]));
    let w2 = r.join("w2");
    let sym = "src/lib.rs#charge";
    let held = parse(&e.run(&ws, &["lease", "acquire", "-i", "fix", sym, "--json"]));
    let set = held["set"].as_str().unwrap();

    let args = [
        "lease",
        "interest",
        "-i",
        "fix",
        "src/lib.rs#refund",
        "--json",
    ];
    let free = parse(&refused(&e, &w2, &args, "lease_free"));
    assert_eq!(free["decision"]["outcome"], "deny");

    let mut mcp = Mcp::start(&e, &w2);
    let (err, waiting) = mcp.tool(
        "lease_interest",
        json!({"symbols": [sym], "intent": "next"}),
    );
    assert!(!err, "{waiting}");
    assert_eq!(waiting["decision"]["outcome"], "allow", "{waiting}");
    assert_eq!(waiting["details"][0]["code"], "lease_held");

    e.run(&ws, &["lease", "release", set]);
    e.run(&ws, &["session", "heartbeat"]);
    let (err, inbox) = mcp.tool("events", json!({}));
    assert!(!err, "{inbox}");
    assert_eq!(inbox["events"][0]["kind"], "reserved", "{inbox}");
    let next = inbox["next"].as_u64().unwrap();

    let cli = parse(&e.run(&w2, &["events", "--json"]));
    assert_eq!(cli["events"], inbox["events"]);
    let text_form = e.run(&w2, &["events", "--from", &next.to_string()]);
    assert!(text_form.contains("reserved"), "{text_form}");
    assert!(text_form.contains(&format!("next {next}")), "{text_form}");

    let (err, got) = mcp.tool("lease_acquire", json!({"symbols": [sym], "intent": "mine"}));
    assert!(!err, "{got}");
    assert_eq!(got["decision"]["outcome"], "allow", "{got}");
    let (_, inbox) = mcp.tool("events", json!({"from": next}));
    assert_eq!(inbox["events"], json!([]), "{inbox}");

    // The text form of an interest prints the decision.
    let args = ["lease", "interest", "-i", "fix", sym];
    let out = e.cmd(&ws, &args).output().unwrap();
    assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains("allow"), "{}", text(&out.stdout));
}

const TWO_FNS: &str =
    "pub fn charge(a: u64) -> u64 {\n    a\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n";

/// A human's change from a workspace, integrated, the workspace synced.
fn land(e: &Env, hws: &Path, intent: &str) {
    e.run(hws, &["propose", "-i", intent]);
    e.settle();
    e.run(hws, &["sync"]);
}

/// Sync merges what both sides edited, and leaves what only one side still
/// has to a human: a file deleted here or on trunk is a conflict, however
/// cleanly the text would merge (issue #46 moved this code under test).
#[test]
fn sync_merges_two_edits_and_refuses_a_file_only_one_side_has() {
    let e = Env::new();
    agent_workspace(&e);
    let r = &e.root;
    let hws = r.join("hws");
    let f = |name: &str| format!("pub fn {name}() {{}}\n");
    std::fs::write(hws.join("src/two.rs"), f("two")).unwrap();
    std::fs::write(hws.join("src/three.rs"), f("three")).unwrap();
    land(&e, &hws, "seed");
    e.run(r, &["workspace", "create", "h2", "--repo", "demo"]);
    let h2 = r.join("h2");

    // Here: another function edited, one file deleted, one grown.
    let refund = TWO_FNS.replace(
        "refund(a: u64) -> u64 {\n    a",
        "refund(a: u64) -> u64 {\n    a + 1",
    );
    std::fs::write(h2.join("src/lib.rs"), &refund).unwrap();
    std::fs::remove_file(h2.join("src/two.rs")).unwrap();
    std::fs::write(h2.join("src/three.rs"), f("three") + &f("more")).unwrap();
    // On trunk: one function edited, the deleted file grown, the grown one
    // deleted.
    let charge = TWO_FNS.replace(
        "charge(a: u64) -> u64 {\n    a",
        "charge(a: u64) -> u64 {\n    a * 2",
    );
    std::fs::write(hws.join("src/lib.rs"), &charge).unwrap();
    std::fs::write(hws.join("src/two.rs"), f("two") + &f("extra")).unwrap();
    std::fs::remove_file(hws.join("src/three.rs")).unwrap();
    land(&e, &hws, "trunk moves");

    let synced = parse(&e.run(&h2, &["sync", "--json"]));
    assert_eq!(synced["merged"], json!(["src/lib.rs"]), "{synced}");
    let conflicts = synced["conflicts"].as_array().unwrap();
    let paths: Vec<&str> = conflicts
        .iter()
        .map(|c| c["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["src/three.rs", "src/two.rs"], "{synced}");
    let merged = std::fs::read_to_string(h2.join("src/lib.rs")).unwrap();
    assert!(
        merged.contains("a * 2") && merged.contains("a + 1"),
        "{merged}"
    );
    // Trunk's version is beside the deleted file; nothing is resurrected.
    assert!(!h2.join("src/two.rs").exists());
    let side = std::fs::read_to_string(h2.join("src/two.rs.trunk")).unwrap();
    assert!(side.contains("extra"), "{side}");
    assert!(!h2.join("src/three.rs.trunk").exists(), "trunk has none");
    let kept = std::fs::read_to_string(h2.join("src/three.rs")).unwrap();
    assert!(kept.contains("more"), "{kept}");
}

/// One conflicting symbol holds back only that symbol: the rest of trunk's
/// changes to the file come in, so nothing of theirs looks like a local edit.
#[test]
fn sync_around_a_conflict_keeps_only_the_conflicting_symbol_local() {
    let e = Env::new();
    agent_workspace(&e);
    let r = &e.root;
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    e.run(r, &["workspace", "create", "h2", "--repo", "demo"]);
    let h2 = r.join("h2");
    let set = |from: &str, to: &str| TWO_FNS.replace(from, to);
    std::fs::write(
        h2.join("src/lib.rs"),
        set(
            "charge(a: u64) -> u64 {\n    a",
            "charge(a: u64) -> u64 {\n    a + 1",
        ),
    )
    .unwrap();
    let trunk = set(
        "charge(a: u64) -> u64 {\n    a",
        "charge(a: u64) -> u64 {\n    a * 2",
    )
    .replace(
        "refund(a: u64) -> u64 {\n    a",
        "refund(a: u64) -> u64 {\n    a * 3",
    );
    std::fs::write(hws.join("src/lib.rs"), &trunk).unwrap();
    land(&e, &hws, "trunk moves");

    let synced = parse(&e.run(&h2, &["sync", "--json"]));
    assert_eq!(
        synced["conflicts"],
        json!([{
            "path": "src/lib.rs",
            "trunk_copy": "src/lib.rs.trunk",
            "symbols": ["src/lib.rs#charge"],
        }]),
        "{synced}"
    );
    let kept = std::fs::read_to_string(h2.join("src/lib.rs")).unwrap();
    assert!(kept.contains("a + 1"), "ours: {kept}");
    assert!(kept.contains("a * 2"), "theirs: {kept}");
    assert!(kept.contains("a * 3"), "the rest of trunk: {kept}");
    assert!(h2.join("src/lib.rs.trunk").exists());

    let refused = fails(&e, &h2, &["propose", "-i", "too soon", "--accept-facts"]);
    assert!(
        refused.contains("conflict not settled in src/lib.rs"),
        "{refused}"
    );

    // Trunk's next change is elsewhere: the conflict stays open and in view.
    std::fs::write(hws.join("src/lib.rs"), trunk.replace("a * 3", "a * 4")).unwrap();
    land(&e, &hws, "trunk moves again");
    let shown = e.run(&h2, &["sync"]);
    assert!(shown.contains("1 conflicts"), "{shown}");
    assert!(h2.join("src/lib.rs.trunk").exists());
    let kept = std::fs::read_to_string(h2.join("src/lib.rs")).unwrap();
    assert!(kept.contains("<<<<<<< local"), "{kept}");
    assert!(kept.contains("a + 1") && kept.contains("a * 4"), "{kept}");

    // Settled, it goes as any change does, and the rest of trunk is safe.
    let settled = settle(&kept, "pub fn charge(a: u64) -> u64 {\n    a * 2 + 1\n}\n");
    std::fs::write(h2.join("src/lib.rs"), &settled).unwrap();
    land(&e, &h2, "settle charge");
    e.run(&hws, &["sync"]);
    let landed = std::fs::read_to_string(hws.join("src/lib.rs")).unwrap();
    assert!(
        landed.contains("a * 2 + 1") && landed.contains("a * 4"),
        "{landed}"
    );
    let meta = std::fs::read_to_string(h2.join(".lonca/workspace.json")).unwrap();
    assert_eq!(parse(&meta)["conflict_tag"], json!(null));
}

/// Each harness gets a refusal in the shape it honours, and a hook set up
/// for the wrong harness says so instead of watching nothing.
#[test]
fn hooks_speak_each_harness() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let event = |name: &str, tool: &str, path: &str| {
        json!({
            "hook_event_name": name, "tool_name": tool, "cwd": ws,
            "tool_input": {"file_path": path, "command": format!("*** Update File: {path}")},
        })
        .to_string()
    };
    let gemini = ["hook", "--harness", "gemini"];
    let codex = ["hook", "--harness", "codex"];

    let o = e.hook_as(
        &ws,
        &event("BeforeTool", "write_file", "/etc/hosts"),
        &gemini,
    );
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out = parse(&text(&o.stdout));
    assert_eq!(out["decision"], "deny", "{out}");
    assert!(
        out["reason"].as_str().unwrap().contains("/etc/hosts"),
        "{out}"
    );
    let o = e.hook_as(
        &ws,
        &event("BeforeTool", "write_file", "src/lib.rs"),
        &gemini,
    );
    assert!(o.stdout.is_empty(), "{}", text(&o.stdout));

    let o = e.hook_as(
        &ws,
        &event("PreToolUse", "apply_patch", "/etc/hosts"),
        &codex,
    );
    let out = parse(&text(&o.stdout));
    let deny = &out["hookSpecificOutput"];
    assert_eq!(deny["permissionDecision"], "deny", "{out}");
    assert_eq!(deny["hookEventName"], "PreToolUse");

    for (input, args) in [
        (event("BeforeTool", "Write", "src/lib.rs"), &["hook"][..]),
        (event("BeforeTool", "Bash", "x"), &codex[..]),
        (event("PreToolUse", "write_file", "x"), &gemini[..]),
        (event("AfterTool", "Write", "x"), &["hook"][..]),
        (event("PostToolUse", "write_file", "x"), &gemini[..]),
    ] {
        let o = e.hook_as(&ws, &input, args);
        assert_eq!(o.status.code(), Some(2), "{input}");
        assert!(
            text(&o.stderr).contains("hook event"),
            "{}",
            text(&o.stderr)
        );
    }
    let o = e.hook_as(
        &ws,
        &event("PreToolUse", "Bash", "x"),
        &["hook", "--harness", "cursor"],
    );
    assert_eq!(o.status.code(), Some(2));
    assert!(text(&o.stderr).contains("unknown harness cursor"));

    let bind =
        json!({"hook_event_name": "SessionStart", "session_id": "h1", "cwd": ws}).to_string();
    let o = e.hook_as(&ws, &bind, &gemini);
    let out = parse(&text(&o.stdout));
    assert_eq!(out["hookSpecificOutput"]["hookEventName"], "SessionStart");
    let log = parse(&e.run(&e.root, &["log", "--repo", "demo", "--json", "--from", "1"]));
    assert!(log.to_string().contains("\"harness\":\"gemini\""), "{log}");
}

/// A harness Lonca has never heard of: one signed policy update, no new
/// Lonca, and its events, tools and answers work.
#[test]
fn a_harness_described_in_the_policy_needs_no_new_lonca() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = &e.root;
    let table = r#"
[harnesses.acme]
events = { session_start = "begin", before_tool = "about_to", after_tool = "did" }
fields = { event = "what", tool = "with", input = "args", cwd = "dir", session = "run" }
deny = { allowed = false, why = "{reason}" }
context = { say = "{context}" }

[harnesses.acme.tools]
save = { kind = "write", fields = ["target"] }
"#;
    let bundle = |dir: &Path| {
        let cfg = dir.join("lonca.toml");
        let pol = dir.join("policy.cedar");
        let c = format!("{}{table}", lonca_policy::config::DEFAULT_CONFIG);
        std::fs::write(&cfg, c).unwrap();
        std::fs::write(&pol, lonca_policy::config::DEFAULT_POLICY).unwrap();
        (cfg, pol)
    };
    let acme = ["hook", "--harness", "acme"];
    let event = |what: &str, target: &str| {
        json!({"what": what, "with": "save", "args": {"target": target}, "dir": ws, "run": "r1"})
            .to_string()
    };
    let o = e.hook_as(&ws, &event("about_to", "/etc/hosts"), &acme);
    assert_eq!(o.status.code(), Some(2), "no profile yet");

    let (cfg, pol) = bundle(r);
    let (cfg, pol) = (cfg.to_str().unwrap(), pol.to_str().unwrap());
    e.run(
        r,
        &[
            "policy", "set", "--repo", "demo", "--config", cfg, "--policy", pol,
        ],
    );

    let o = e.hook_as(&ws, &event("about_to", "/etc/hosts"), &acme);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out = parse(&text(&o.stdout));
    assert_eq!(out["allowed"], false, "{out}");
    assert!(out["why"].as_str().unwrap().contains("/etc/hosts"), "{out}");
    let o = e.hook_as(&ws, &event("did", "src/lib.rs"), &acme);
    assert!(o.status.success() && o.stdout.is_empty());
    let o = e.hook_as(&ws, &event("begin", ""), &acme);
    let out = parse(&text(&o.stdout));
    assert!(out["say"].as_str().unwrap().contains("Lonca"), "{out}");
    let log = parse(&e.run(r, &["log", "--repo", "demo", "--json", "--from", "1"]));
    let log = log.to_string();
    assert!(
        log.contains("\"harness\":\"acme\"") && log.contains("\"r1\""),
        "{log}"
    );
}

/// Undoing a change that a later one built on takes out that change alone.
#[test]
fn undo_reverses_a_change_under_a_later_one_in_the_same_file() {
    let e = Env::new();
    agent_workspace(&e);
    let r = &e.root;
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    let charge = TWO_FNS.replace(
        "charge(a: u64) -> u64 {\n    a",
        "charge(a: u64) -> u64 {\n    a * 2",
    );
    std::fs::write(hws.join("src/lib.rs"), &charge).unwrap();
    land(&e, &hws, "double");
    let log = parse(&e.run(r, &["log", "--repo", "demo", "--json"]));
    let mut entries = log.as_array().unwrap().iter();
    let integrated = entries
        .rfind(|o| o["entry"]["op"]["op"] == "change.integrate")
        .unwrap()["entry"]["seq"]
        .as_u64()
        .unwrap()
        .to_string();
    let both = charge.replace(
        "refund(a: u64) -> u64 {\n    a",
        "refund(a: u64) -> u64 {\n    a + 1",
    );
    std::fs::write(hws.join("src/lib.rs"), &both).unwrap();
    land(&e, &hws, "refund");

    e.run(r, &["undo", &integrated, "--repo", "demo"]);
    e.settle();
    e.run(&hws, &["sync"]);
    let now = std::fs::read_to_string(hws.join("src/lib.rs")).unwrap();
    assert!(!now.contains("a * 2"), "{now}");
    assert!(now.contains("a + 1"), "{now}");
}

/// One text of the rules reaches a worker by every road, and the hook's has
/// the harness's own tool names.
#[test]
fn the_rules_are_one_text_on_every_road() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let rules = e.run(&ws, &["rules"]);
    assert!(rules.contains("lease it: lease_acquire with"), "{rules}");

    let mut mcp = Mcp::start(&e, &ws);
    let init = mcp.request("initialize", json!({"protocolVersion": "2025-06-18"}));
    assert_eq!(init["instructions"].as_str().unwrap(), rules.trim_end());
    let tools = mcp.request("tools/list", json!({}));
    let tools = tools["tools"].as_array().unwrap();
    assert!(tools.iter().all(|t| t["annotations"].is_object()));

    let start = json!({"hook_event_name": "SessionStart", "session_id": "h1", "cwd": ws});
    let start = start.to_string();
    let cases = [("claude-code", "mcp__lonca__"), ("gemini", "mcp_lonca_")];
    for (harness, prefix) in cases {
        let o = e.hook_as(&ws, &start, &["hook", "--harness", harness]);
        let out: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
        let context = out["hookSpecificOutput"]["additionalContext"].as_str();
        let context = context.unwrap().replace(prefix, "");
        let (_, body) = rules.split_once('\n').unwrap();
        assert!(context.ends_with(body.trim_end()), "{harness}: {context}");
    }
}

/// What setup writes reaches the harness and never the repository.
#[test]
fn a_harness_is_set_up_from_its_profile_and_its_files_are_never_a_change() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let setup = ["harness", "setup", "claude-code", "--json"];
    let r = parse(&e.run(&ws, &setup));
    assert_eq!(r["known"], true);
    assert_eq!(
        r["written"],
        json!([".claude/settings.local.json", ".mcp.json"])
    );
    let read = |p: &str| std::fs::read_to_string(ws.join(p)).unwrap();
    let mcp: serde_json::Value = serde_json::from_str(&read(".mcp.json")).unwrap();
    let server = &mcp["mcpServers"]["lonca"];
    assert_eq!(server["env"]["LONCA_SOCKET"], e.sock.to_str().unwrap());
    assert_eq!(server["env"]["LONCA_WORKSPACE"], ws.to_str().unwrap());

    assert_eq!(
        e.run(&ws, &setup),
        e.run(&ws, &setup),
        "running it again is fine"
    );
    assert!(!e.run(&ws, &["diff"]).contains(".mcp.json"));
    let lib =
        read("src/lib.rs").replace("    a\n}\n\npub fn refund", "    a + 1\n}\n\npub fn refund");
    std::fs::write(ws.join("src/lib.rs"), lib).unwrap();
    e.run(
        &ws,
        &[
            "lease",
            "acquire",
            "src/lib.rs#charge",
            "--kind",
            "edit",
            "-i",
            "x",
        ],
    );
    let out = e.run(
        &ws,
        &["propose", "-i", "charge", "--edits", "src/lib.rs#charge"],
    );
    // The session may touch only src/**: a file of setup's here would be refused.
    assert!(out.contains("escalate: unobserved_session"), "{out}");
    let change = parse(&e.run(&e.root, &["status", "--repo", "demo", "--json"]));
    assert!(!change.to_string().contains(".mcp.json"), "{change}");
}

/// A harness whose setup is flags writes nothing, a name with no profile
/// still gets the rules and the server, and `--print` leaves the workspace
/// alone.
#[test]
fn flags_for_a_runner_and_the_rules_for_a_harness_lonca_does_not_know() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = parse(&e.run(&ws, &["harness", "setup", "codex", "--json"]));
    assert_eq!(r["written"], json!([]));
    let flags: Vec<&str> = r["flags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect();
    let cwd = format!("mcp_servers.lonca.cwd={}", ws.display());
    assert!(flags.contains(&cwd.as_str()), "{flags:?}");
    let rules = flags
        .iter()
        .find(|f| f.starts_with("developer_instructions="));
    assert!(
        rules
            .unwrap()
            .contains("nothing reaches the repository until you propose")
    );
    let text = e.run(&ws, &["harness", "setup", "codex"]);
    assert!(text.contains("LONCA_SOCKET="), "{text}");
    assert!(
        text.contains("-c mcp_servers.lonca.command=lonca"),
        "{text}"
    );

    let printed = e.run(&ws, &["harness", "setup", "claude-code", "--print"]);
    assert!(printed.contains("--mcp-config"), "{printed}");
    assert!(printed.contains("--- .mcp.json\n{"), "{printed}");
    assert!(!ws.join(".mcp.json").exists());

    let r = parse(&e.run(&ws, &["harness", "setup", "cursor", "--json"]));
    assert_eq!(r["known"], false);
    assert_eq!(r["written"], json!([]));
    assert_eq!(r["mcp"]["args"], json!(["mcp"]));
    assert_eq!(r["mcp"]["env"]["LONCA_WORKSPACE"], ws.to_str().unwrap());
    assert!(r["rules"].as_str().unwrap().contains("lease_acquire"));
    let text = e.run(&ws, &["harness", "setup", "cursor"]);
    assert!(text.contains("no profile for harness cursor"), "{text}");
    assert!(text.contains("\"command\": \"lonca\""), "{text}");
}

/// `session start --harness` leaves a workspace ready; a file of the
/// repository at the same path is not overwritten, and the runner hears why;
/// a file trunk brings later takes the generated one's place and counts.
#[test]
fn session_start_sets_up_and_the_repository_s_own_files_win() {
    let e = Env::new();
    agent_workspace(&e);
    let r = &e.root;
    let start = |dir: &str, harness: &str| {
        e.cmd(
            r,
            &[
                "session",
                "start",
                "--repo",
                "demo",
                "--agent",
                "a",
                "--paths",
                "**",
                "--workspace",
                dir,
                "--harness",
                harness,
                "--json",
            ],
        )
        .output()
        .unwrap()
    };
    let o = start("ws2", "gemini");
    assert!(o.status.success(), "{}", text(&o.stderr));
    let out: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(out["setup"]["written"], json!([".gemini/settings.json"]));
    let ws2 = r.join("ws2");
    assert!(ws2.join(".gemini/settings.json").exists());

    let o = start("ws4", "claude-code");
    assert!(o.status.success(), "{}", text(&o.stderr));

    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    std::fs::create_dir_all(hws.join(".gemini")).unwrap();
    std::fs::write(hws.join(".gemini/settings.json"), "{}\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "theirs"]).contains("allow"));
    e.settle();

    // Trunk moving past what setup wrote does not make it a local change.
    let ws4 = r.join("ws4");
    e.run(&ws4, &["sync"]);
    let diff = e.run(&ws4, &["diff"]);
    assert!(diff.contains("no local changes"), "{diff}");

    e.run(&ws2, &["sync"]);
    let body = std::fs::read_to_string(ws2.join(".gemini/settings.json")).unwrap();
    assert_eq!(body, "{}\n", "trunk's file is the repository's");
    std::fs::write(ws2.join(".gemini/settings.json"), "{\"mine\":1}\n").unwrap();
    assert!(e.run(&ws2, &["diff"]).contains(".gemini/settings.json"));

    let o = start("ws3", "gemini");
    assert!(!o.status.success());
    let err = text(&o.stderr);
    assert!(
        err.contains("its setup failed") && err.contains("file of the repository"),
        "{err}"
    );
    assert!(err.contains("--print"), "{err}");
}

/// An argument the tool does not take: a read runs and says so, a change does
/// not run, and a claim in the right place that is wrong says how.
#[test]
fn a_tool_call_with_an_argument_it_does_not_take() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let lib = std::fs::read_to_string(ws.join("src/lib.rs")).unwrap();
    std::fs::write(ws.join("src/lib.rs"), lib.replace("    a\n", "    a + 1\n")).unwrap();
    let mut mcp = Mcp::start(&e, &ws);

    let (failed, status) = mcp.tool("status", json!({"verbose": true}));
    assert!(!failed, "{status}");
    let warning = status["warnings"][0].as_str().unwrap();
    assert!(
        warning.starts_with("status has no argument `verbose`"),
        "{warning}"
    );
    assert_eq!(status["expected"]["type"], "object", "{status}");
    let (_, plain) = mcp.tool("status", json!({}));
    assert_eq!(plain.get("warnings"), None);
    assert_eq!(plain.get("expected"), None);

    let log = || parse(&e.run(&e.root, &["log", "--repo", "demo", "--json"]));
    let before = log().as_array().unwrap().len();
    let (failed, body) = mcp.tool(
        "propose",
        json!({"intent": "x", "symbols": ["src/lib.rs#charge"]}),
    );
    assert!(failed, "{body}");
    assert_eq!(body["code"], "invalid", "{body}");
    assert!(
        body["expected"]["properties"]["edits"]["description"].is_string(),
        "{body}"
    );
    let (failed, body) = mcp.tool("lease_acquire", json!({"intent": "x", "lease": 1}));
    assert!(failed, "{body}");
    assert_eq!(
        log().as_array().unwrap().len(),
        before,
        "neither call reached the log"
    );

    let (failed, body) = mcp.tool(
        "propose",
        json!({"intent": "x", "edits": ["src/lib.rs#nope"]}),
    );
    assert!(!failed, "{body}");
    assert_eq!(body["decision"]["outcome"], "deny", "{body}");
    let gap = &body["claim_mismatch"][0];
    assert_eq!(gap["field"], "edits", "{body}");
    assert_eq!(gap["claimed"], json!(["src/lib.rs#nope"]), "{body}");
    assert_eq!(gap["facts"], body["facts"]["edits"], "{body}");
}

/// A person fixes a harness that moved on: the built-in profile, as a table,
/// is the start.
#[test]
fn a_built_in_profile_is_printed_for_the_policy() {
    let e = Env::new();
    let table = e.run(&e.root, &["harness", "show", "opencode"]);
    assert!(table.contains("[harnesses.opencode"), "{table}");
    assert!(table.contains(".opencode/plugins/lonca.js"), "{table}");
    let o = e
        .cmd(&e.root, &["harness", "show", "nobody"])
        .output()
        .unwrap();
    assert!(!o.status.success());
    assert!(text(&o.stderr).contains("no built-in profile for harness nobody"));
}

/// OpenCode from its built-in profile: what setup writes stays out of the
/// diff, and a refusal comes in the shape the plugin reads.
#[test]
fn opencode_is_set_up_from_its_built_in_profile() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let r = parse(&e.run(&ws, &["harness", "setup", "opencode", "--json"]));
    assert_eq!(r["known"], true);
    let written = [
        ".opencode/lonca-rules.md",
        ".opencode/plugins/lonca.js",
        "opencode.json",
    ];
    assert_eq!(r["written"], json!(written));
    let rules = std::fs::read_to_string(ws.join(".opencode/lonca-rules.md")).unwrap();
    assert!(rules.contains("`edits` ("), "{rules}");
    assert!(e.run(&ws, &["diff"]).contains("no local changes"));
    let event = json!({
        "hook_event_name": "before_tool", "tool_name": "write", "cwd": ws,
        "tool_input": {"path": "/etc/hosts"},
    });
    let o = e.hook_as(&ws, &event.to_string(), &["hook", "--harness", "opencode"]);
    let out: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert!(
        out["deny"]
            .as_str()
            .unwrap()
            .contains("outside the workspace"),
        "{out}"
    );
}

/// An agent that stops with work nobody proposed, through the documented
/// hook (issue #121). A daemon that is down must end the turn: exit status 2
/// would tell the harness to go on, for ever.
#[test]
fn a_stop_with_unproposed_work_goes_back_to_the_agent_and_a_failure_ends_the_turn() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    let start = [
        "session",
        "start",
        "--repo",
        "demo",
        "--agent",
        "claude",
        "--paths",
        "**",
        "--workspace",
        "w1",
    ];
    e.run(r, &start);
    let ws = r.join("w1");
    let stop = format!(
        r#"{{"hook_event_name":"Stop","session_id":"h1","cwd":"{}"}}"#,
        ws.display()
    );

    // Nothing local: the turn ends, with no answer.
    let o = e.hook(&ws, &stop);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), "");

    std::fs::write(ws.join("new.rs"), "pub fn f() {}\n").unwrap();
    let o = e.hook(&ws, &stop);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    let out: serde_json::Value = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(out["decision"], "block", "{out}");
    let reason = out["reason"].as_str().unwrap();
    assert!(reason.contains("new.rs"), "{reason}");

    let status = e.run(&ws, &["status"]);
    assert!(status.contains("unproposed work:"), "{status}");
    assert!(
        status.contains("1 file(s) after 1 stop(s): new.rs"),
        "{status}"
    );

    // Daemon down: with the flag the stop passes, without it the hook blocks.
    let down = |args: &[&str]| {
        use std::io::Write;
        let mut c = e.cmd(&ws, args);
        c.env("LONCA_SOCKET", r.join("nope"));
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stop.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let o = down(&["hook", "--fail-open"]);
    assert_eq!(o.status.code(), Some(0), "{}", text(&o.stderr));
    assert_eq!(text(&o.stdout), "");
    assert!(!text(&o.stderr).is_empty(), "the failure is reported");
    assert_eq!(down(&["hook"]).status.code(), Some(2));

    // `session end` puts it on the record for a harness with no stop event.
    let out = e.run(&ws, &["session", "end", "--json"]);
    let ended: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(ended["unproposed"], serde_json::json!(["new.rs"]), "{out}");
    assert_eq!(ended["unproposed_total"], 1);
    let status = e.run(r, &["status", "--repo", "demo"]);
    assert!(status.contains("new.rs"), "ended, still shown: {status}");
}

/// A deleted file is local work too, and `session end` says so in words.
#[test]
fn session_end_says_when_work_was_left_behind() {
    let e = Env::new();
    let r = &e.root;
    e.run(r, &["human", "keygen", "ayse"]);
    assert!(e.run(r, &["init", "demo"]).contains("allow"));
    let start = [
        "session",
        "start",
        "--repo",
        "demo",
        "--agent",
        "claude",
        "--paths",
        "**",
        "--workspace",
        "w1",
    ];
    e.run(r, &start);
    let ws = r.join("w1");
    let out = e.run(&ws, &["session", "end"]);
    assert!(!out.contains("left unproposed"), "{out}");

    e.run(
        r,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "**",
            "--workspace",
            "w2",
        ],
    );
    let ws = r.join("w2");
    std::fs::write(ws.join("new.rs"), "x\n").unwrap();
    let out = e.run(&ws, &["session", "end"]);
    assert!(out.contains("left unproposed: 1 file(s)"), "{out}");
}

/// `git` in a workspace as a tool there runs it, with none of the
/// developer's config.
fn git_in(dir: &Path, args: &[&str]) -> String {
    let o = Command::new("git")
        .current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()
        .unwrap();
    assert!(o.status.success(), "git {args:?}: {}", text(&o.stderr));
    text(&o.stdout).trim_end().to_string()
}

const CHARGE: &str = "pub fn charge(a: u64) -> u64 {\n    a\n}\n";
const REFUND: &str = "pub fn refund(a: u64) -> u64 {\n    a\n}\n";

#[test]
fn an_agents_workspace_is_a_repository_that_means_what_lonca_diff_means() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    assert_eq!(git_in(&ws, &["status", "--porcelain"]), "");
    assert_eq!(git_in(&ws, &["diff"]), "");
    assert!(ws.join(".lonca/session").exists());
    assert_eq!(
        git_in(&ws, &["check-ignore", ".lonca/session"]),
        ".lonca/session"
    );

    // An edit: both tools see it.
    let edited = CHARGE.replace("    a\n", "    a + 1\n");
    std::fs::write(ws.join("src/lib.rs"), format!("{edited}\n{REFUND}")).unwrap();
    assert_eq!(git_in(&ws, &["diff", "--name-only"]), "src/lib.rs");
    assert!(git_in(&ws, &["diff"]).contains("+    a + 1"));
    let facts = e.run(&ws, &["diff"]);
    assert!(facts.contains("src/lib.rs#charge"), "{facts}");

    // A local commit: git has nothing left to show, Lonca sees the same
    // edit, and that edit is what a proposal sends.
    git_in(&ws, &["commit", "-qam", "checkpoint"]);
    assert_eq!(git_in(&ws, &["diff"]), "");
    assert_eq!(e.run(&ws, &["diff"]), facts);
    e.run(&ws, &["lease", "acquire", "-i", "fix", "src/lib.rs#charge"]);
    let out = e.run(&ws, &["propose", "-i", "bump", "--accept-facts"]);
    assert!(out.contains("escalate"), "{out}");
    let seq: String = out
        .trim_start_matches('#')
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    let r = &e.root;
    assert!(
        e.run(r, &["approve", &seq, "--repo", "demo"])
            .contains("released")
    );
    e.settle();
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    let trunk = std::fs::read_to_string(hws.join("src/lib.rs")).unwrap();
    assert_eq!(trunk, format!("{edited}\n{REFUND}"));
    assert!(!hws.join(".git").exists() && !hws.join("config").exists());
}

#[test]
fn a_sync_moves_the_repository_and_keeps_only_local_edits_in_git_diff() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    // The agent edits one symbol.
    let mine = CHARGE.replace("    a\n", "    a + 1\n");
    std::fs::write(ws.join("src/lib.rs"), format!("{mine}\n{REFUND}")).unwrap();
    let before = git_in(&ws, &["rev-parse", "HEAD"]);

    // Trunk moves: a new file, and the other symbol of the same file.
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    let theirs = REFUND.replace("    a\n", "    a - 1\n");
    std::fs::write(hws.join("src/lib.rs"), format!("{CHARGE}\n{theirs}")).unwrap();
    std::fs::write(hws.join("src/new.rs"), "pub fn fresh() {}\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "more"]).contains("allow"));
    e.settle();

    let report = parse(&e.run(&ws, &["sync", "--json"]));
    assert_eq!(report["merged"], json!(["src/lib.rs"]), "{report}");
    assert_eq!(report["git_warning"], json!(null), "{report}");
    assert_ne!(git_in(&ws, &["rev-parse", "HEAD"]), before);
    assert_eq!(git_in(&ws, &["status", "--porcelain"]), " M src/lib.rs");
    let diff = git_in(&ws, &["diff"]);
    assert!(diff.contains("+    a + 1"), "{diff}");
    assert!(
        !diff.contains("a - 1\n+"),
        "trunk's edit is not local: {diff}"
    );
    assert!(git_in(&ws, &["show", "HEAD:src/lib.rs"]).contains("a - 1"));
    assert!(git_in(&ws, &["ls-files"]).contains("src/new.rs"));
    git_in(&ws, &["fsck", "--strict"]);

    // A conflict: the file holds both sides, the trunk copy is no git change.
    let clash = CHARGE.replace("    a\n", "    a + 2\n");
    e.run(&hws, &["sync"]);
    std::fs::write(hws.join("src/lib.rs"), format!("{clash}\n{theirs}")).unwrap();
    assert!(e.run(&hws, &["propose", "-i", "clash"]).contains("allow"));
    e.settle();
    let report = parse(&e.run(&ws, &["sync", "--json"]));
    assert_eq!(report["conflicts"][0]["path"], "src/lib.rs", "{report}");
    assert!(ws.join("src/lib.rs.trunk").exists());
    assert_eq!(git_in(&ws, &["status", "--porcelain"]), " M src/lib.rs");
    let diff = git_in(&ws, &["diff"]);
    assert!(
        diff.contains("+<<<<<<< local") && diff.contains("+    a + 1"),
        "{diff}"
    );
}

#[test]
fn a_tampered_repository_does_not_stop_a_sync_and_says_so() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    let hws = r.join("hws");
    std::fs::write(hws.join("src/new.rs"), "pub fn fresh() {}\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "more"]).contains("allow"));
    e.settle();

    std::fs::rename(ws.join(".git/refs"), r.join("elsewhere")).unwrap();
    std::os::unix::fs::symlink(r.join("elsewhere"), ws.join(".git/refs")).unwrap();
    let out = e.cmd(&ws, &["sync"]).output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stderr).contains("warning: .git still shows the old base"));
    assert!(ws.join("src/new.rs").exists());
    assert!(e.run(&ws, &["diff"]).contains("no local changes"));
}

#[test]
fn a_plain_workspace_stays_plain_and_a_workspace_of_lonca_is_no_checkout() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    // `lonca fetch` and `propose --commit` run git, so never in here.
    for args in [
        &["fetch", "--repo", "demo"][..],
        &["propose", "--commit", "HEAD", "--repo", "demo"],
    ] {
        let out = e.cmd(&ws, args).output().unwrap();
        assert!(!out.status.success(), "{args:?}");
        assert!(
            text(&out.stderr).contains("this is a Lonca workspace"),
            "{args:?}"
        );
    }
    assert!(
        !std::fs::read_to_string(ws.join(".git/config"))
            .unwrap()
            .contains("[lonca]")
    );

    let mut args = session_args("src/**", &["--workspace", "plain", "--no-git"]);
    args.push("--json");
    assert_eq!(parse(&e.run(&r, &args))["decision"]["outcome"], "allow");
    assert!(r.join("plain/src/lib.rs").exists());
    assert!(!r.join("plain/.git").exists());
    let hws = r.join("hws");
    assert!(!hws.join(".git").exists(), "a person's workspace is plain");
    std::fs::write(hws.join("src/new.rs"), "pub fn fresh() {}\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "more"]).contains("allow"));
    e.settle();
    let report = parse(&e.run(&r.join("plain"), &["sync", "--json"]));
    assert_eq!(report["updated"], json!(["src/new.rs"]), "{report}");
    assert_eq!(report["git_warning"], json!(null), "{report}");
    assert!(!r.join("plain/.git").exists());

    // Refused with --continue: that workspace already is what it is.
    let mut args = session_args("src/**", &["--continue", "plain", "--no-git"]);
    args.push("--json");
    let out = e.cmd(&r, &args).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn harness_setup_files_are_no_change_for_git_either() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    e.run(&ws, &["harness", "setup", "claude-code"]);
    assert!(ws.join(".mcp.json").exists());
    assert_eq!(git_in(&ws, &["status", "--porcelain"]), "");
}

/// Runs `lonca` and hands back its stderr, having checked that it failed.
fn fails(e: &Env, cwd: &Path, args: &[&str]) -> String {
    let out = e.cmd(cwd, args).output().unwrap();
    assert!(!out.status.success(), "{args:?}: {}", text(&out.stdout));
    text(&out.stderr)
}

/// Lonca can hold more rights than the agent, so what the agent left in its
/// workspace must not steer a read or a write out of it.
#[test]
fn a_directory_symlink_can_not_steer_a_sync_out_of_the_workspace() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    let out = r.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::rename(ws.join("src"), r.join("src-aside")).unwrap();
    std::os::unix::fs::symlink(&out, ws.join("src")).unwrap();

    std::fs::write(hws.join("src/new.rs"), "pub fn fresh() {}\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "more"]).contains("allow"));
    e.settle();
    let err = fails(&e, &ws, &["sync"]);
    assert!(err.contains("src is a symlink"), "{err}");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);

    // Put back, the same sync goes through.
    std::fs::remove_file(ws.join("src")).unwrap();
    std::fs::rename(r.join("src-aside"), ws.join("src")).unwrap();
    assert!(e.run(&ws, &["sync"]).contains("0 conflicts"));
    assert!(ws.join("src/new.rs").exists());
}

/// The same for a directory no tracked file is under, which only the write
/// itself can catch.
#[test]
fn a_new_directory_of_trunk_is_not_written_through_a_symlink() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    let out = r.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::os::unix::fs::symlink(&out, ws.join("newdir")).unwrap();
    std::fs::create_dir_all(hws.join("newdir")).unwrap();
    std::fs::write(hws.join("newdir/x.rs"), "pub fn fresh() {}\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "more"]).contains("allow"));
    e.settle();
    let err = fails(&e, &ws, &["sync"]);
    assert!(err.contains("newdir is a symlink"), "{err}");
    assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
}

#[test]
fn a_symlink_at_a_tracked_path_sends_nothing_from_outside_the_workspace() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    let secret = r.join("secret");
    std::fs::write(&secret, "pub fn hidden() {}\n").unwrap();
    std::fs::remove_file(ws.join("src/lib.rs")).unwrap();
    std::os::unix::fs::symlink(&secret, ws.join("src/lib.rs")).unwrap();
    for args in [&["diff"][..], &["propose", "-i", "x", "--accept-facts"]] {
        let err = fails(&e, &ws, args);
        assert!(err.contains("src/lib.rs: lib.rs is a symlink"), "{err}");
        assert!(!err.contains("hidden"), "{err}");
    }

    // The same for a directory on the way to it, and for a tool's argument.
    std::fs::remove_file(ws.join("src/lib.rs")).unwrap();
    std::fs::remove_dir(ws.join("src")).unwrap();
    let out = r.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("lib.rs"), "pub fn hidden() {}\n").unwrap();
    std::os::unix::fs::symlink(&out, ws.join("src")).unwrap();
    assert!(fails(&e, &ws, &["diff"]).contains("src is a symlink"));
    let mut mcp = Mcp::start(&e, &ws);
    let (is_error, reply) = mcp.tool("symbols", json!({"path": "src/lib.rs"}));
    assert!(is_error, "{reply}");
    assert!(!reply.to_string().contains("hidden"), "{reply}");
}

/// `workspace.json` is the agent's to edit, so its paths are not trusted.
#[test]
fn paths_in_workspace_metadata_can_not_leave_the_workspace() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    let victim = r.join("victim");
    std::fs::write(&victim, "mine\n").unwrap();
    let edit = |change: &dyn Fn(&mut serde_json::Value)| {
        let at = ws.join(".lonca/workspace.json");
        let mut meta: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&at).unwrap()).unwrap();
        change(&mut meta);
        std::fs::write(&at, serde_json::to_vec(&meta).unwrap()).unwrap();
    };

    // A manifest entry would be read and proposed.
    edit(&|m| {
        let lib = m["manifest"]["src/lib.rs"].clone();
        m["manifest"]["../victim"] = lib;
    });
    let err = fails(&e, &ws, &["diff"]);
    assert!(err.contains("not a path inside the workspace"), "{err}");
    edit(&|m| {
        m["manifest"].as_object_mut().unwrap().remove("../victim");
    });

    // A trunk copy would be deleted at the next sync.
    edit(&|m| m["trunk_copies"] = json!(["../victim"]));
    std::fs::write(hws.join("src/new.rs"), "pub fn fresh() {}\n").unwrap();
    assert!(e.run(&hws, &["propose", "-i", "more"]).contains("allow"));
    e.settle();
    let err = fails(&e, &ws, &["sync"]);
    assert!(err.contains("not a path inside the workspace"), "{err}");
    assert_eq!(std::fs::read_to_string(&victim).unwrap(), "mine\n");
}

#[test]
fn a_symlink_at_the_workspace_metadata_is_not_followed() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    let elsewhere = r.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::rename(ws.join(".lonca/session"), r.join("token")).unwrap();
    std::fs::write(elsewhere.join("note"), "a secret file\n").unwrap();
    std::os::unix::fs::symlink(elsewhere.join("note"), ws.join(".lonca/session")).unwrap();
    assert!(fails(&e, &ws, &["sync"]).contains("session is a symlink"));
    std::fs::remove_file(ws.join(".lonca/session")).unwrap();
    std::fs::rename(r.join("token"), ws.join(".lonca/session")).unwrap();

    // workspace.json, and the directory they live in.
    let moved = elsewhere.join("workspace.json");
    std::fs::rename(ws.join(".lonca/workspace.json"), &moved).unwrap();
    std::os::unix::fs::symlink(&moved, ws.join(".lonca/workspace.json")).unwrap();
    assert!(fails(&e, &ws, &["sync"]).contains("not inside a Lonca workspace"));
    std::fs::remove_file(ws.join(".lonca/workspace.json")).unwrap();
    std::fs::rename(&moved, ws.join(".lonca/workspace.json")).unwrap();
    std::fs::rename(ws.join(".lonca"), r.join("meta-aside")).unwrap();
    std::os::unix::fs::symlink(r.join("meta-aside"), ws.join(".lonca")).unwrap();
    assert!(fails(&e, &ws, &["sync"]).contains("not inside a Lonca workspace"));
}

/// `lonca fetch` runs git, so a broken workspace.json must not let it in.
#[test]
fn a_workspace_with_unreadable_metadata_is_still_no_checkout() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    std::fs::write(ws.join(".lonca/workspace.json"), "not json").unwrap();
    let err = fails(&e, &ws, &["fetch", "--repo", "demo"]);
    assert!(err.contains("this is a Lonca workspace"), "{err}");
}

/// workspace.json names the human whose key files a command opens.
#[test]
fn a_human_name_in_workspace_metadata_can_not_name_another_path() {
    let e = Env::new();
    let r = e.root.clone();
    let ws = agent_workspace(&e);
    let at = r.join("hws/.lonca/workspace.json");
    let keep = std::fs::read(&at).unwrap();
    for bad in ["../other", ".hidden", "a/b"] {
        let mut meta: serde_json::Value = serde_json::from_slice(&keep).unwrap();
        meta["human"] = json!(bad);
        std::fs::write(&at, serde_json::to_vec(&meta).unwrap()).unwrap();
        let err = fails(&e, &r.join("hws"), &["sync"]);
        assert!(err.contains("bad human name"), "{bad}: {err}");
    }
    assert!(ws.exists());
}

/// Files come out with their modes under any umask.
#[test]
fn modes_in_a_workspace_do_not_depend_on_the_umask() {
    use std::os::unix::fs::PermissionsExt;
    let e = Env::new();
    let r = e.root.clone();
    agent_workspace(&e);
    let hws = r.join("hws");
    e.run(&hws, &["sync"]);
    let script = hws.join("run.sh");
    std::fs::write(&script, "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(e.run(&hws, &["propose", "-i", "script"]).contains("allow"));
    e.settle();

    let args = session_args("src/**", &["--workspace", "strict"]);
    let start = e.cmd(&r, &args);
    let mut wrapped = Command::new("sh");
    wrapped
        .current_dir(&r)
        .arg("-c")
        .arg("umask 077; exec \"$@\"")
        .arg("sh")
        .arg(start.get_program())
        .args(start.get_args());
    for (key, value) in start.get_envs() {
        match value {
            Some(v) => wrapped.env(key, v),
            None => wrapped.env_remove(key),
        };
    }
    let out = wrapped.output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let mode = |p: &str| {
        let meta = std::fs::metadata(r.join("strict").join(p)).unwrap();
        meta.permissions().mode() & 0o777
    };
    assert_eq!(mode("src/lib.rs"), 0o644);
    assert_eq!(mode("run.sh"), 0o755);
    assert_eq!(mode(".lonca/session"), 0o600);
}

/// `symbols` gives the id of a type's own text, for the tool and the command.
#[test]
fn symbols_give_the_definition_of_a_type() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let src = "pub struct S;\n\nimpl S {\n    pub fn m() {}\n}\n\npub fn f() {}\n";
    std::fs::write(ws.join("src/types.rs"), src).unwrap();
    let mut mcp = Mcp::start(&e, &ws);
    let (is_error, reply) = mcp.tool("symbols", json!({"path": "src/types.rs"}));
    assert!(!is_error, "{reply}");
    let def = |id: &str| {
        let id = format!("src/types.rs#{id}");
        let list = reply["symbols"].as_array().unwrap().iter();
        let mut found = list.filter(|s| s["id"] == id.as_str());
        found.next().unwrap()["def"].clone()
    };
    assert_eq!(def("S"), "src/types.rs#S.<def>");
    assert_eq!(def("impl:S"), "src/types.rs#S.<def>");
    assert_eq!(def("S.m"), serde_json::Value::Null);
    assert_eq!(def("f"), serde_json::Value::Null);
    let listed = e.run(&ws, &["symbols", "src/types.rs"]);
    assert!(listed.contains("S  (definition: S.<def>)"), "{listed}");
    assert!(listed.contains("impl:S  (definition: S.<def>)"), "{listed}");
    assert!(listed.lines().any(|l| l == "f"), "{listed}");
}

#[test]
fn mcp_tells_an_agent_what_another_one_asked_with_the_answer_of_any_tool() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    e.run(&e.root, &session_args("src/**", &["--workspace", "w2"]));
    let w2 = e.root.join("w2");
    let sym = "src/lib.rs#refund";

    let mut mcp = Mcp::start(&e, &ws);
    let (_, held) = mcp.tool("lease_acquire", json!({"symbols": [sym], "intent": "mine"}));
    assert_eq!(held["decision"]["outcome"], "allow", "{held}");
    assert_eq!(mcp.news("status", json!({})), None);

    let mut other = Mcp::start(&e, &w2);
    let (_, denied) = other.tool("lease_acquire", json!({"symbols": [sym], "intent": "too"}));
    assert_eq!(denied["decision"]["outcome"], "deny", "{denied}");
    let mine = denied["details"][0]["holder_session"].as_str().unwrap();
    assert!(
        denied["advice"].as_str().unwrap().contains(mine),
        "{denied}"
    );
    let args = ["lease", "acquire", sym, "--intent", "too"];
    let out = e.cmd(&w2, &args).output().unwrap();
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("Settle it between you"), "{said}");

    let (err, sent) = other.tool(
        "negotiate",
        json!({"thread": "t1", "to_session": mine,
               "message": {"type": "claim", "symbols": ["src/lib.rs#charge"], "reason": "needs it"}}),
    );
    assert!(!err, "{sent}");

    let news = mcp.news("status", json!({})).expect("the news");
    assert!(news.contains("in thread t1"), "{news}");
    assert!(news.contains("needs it"), "{news}");
    assert_eq!(mcp.news("status", json!({})), None);
}

/// The command line asks for the reason itself, before the daemon would.
#[test]
fn a_lease_on_the_command_line_needs_an_intent() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    for sub in ["acquire", "interest"] {
        let args = ["lease", sub, "src/lib.rs#charge"];
        let out = e.cmd(&ws, &args).output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success());
        assert!(err.contains("--intent"), "{err}");
    }
}

/// `lease_release` with items acquires the rest under a new set: a session
/// waiting for them does not get in the way of what the holder keeps.
#[test]
fn a_partial_release_goes_through_while_another_session_waits() {
    let e = Env::new();
    let ws = agent_workspace(&e);
    let second = [
        "session",
        "start",
        "--repo",
        "demo",
        "--agent",
        "codex",
        "--paths",
        "src/**",
        "--workspace",
        "ws2",
    ];
    e.run(&e.root, &second);
    let ws2 = e.root.join("ws2");
    let mut mcp = Mcp::start(&e, &ws);
    let items = json!([
        {"symbol": "src/lib.rs#charge", "kind": "edit"},
        {"symbol": "src/lib.rs#refund", "kind": "edit"},
    ]);
    let (err, got) = mcp.tool("lease_acquire", json!({"items": items, "intent": "both"}));
    assert!(!err, "{got}");
    let set = got["set"].as_str().unwrap().to_string();
    let args = [
        "lease",
        "interest",
        "-i",
        "fix",
        "src/lib.rs#charge",
        "--json",
    ];
    let waits = parse(&e.run(&ws2, &args));
    assert_eq!(waits["decision"]["outcome"], "allow", "{waits}");

    let (err, part) = mcp.tool(
        "lease_release",
        json!({"set": set, "items": [{"symbol": "src/lib.rs#refund", "kind": "edit"}]}),
    );
    assert!(!err, "{part}");
    assert_eq!(part["decision"]["outcome"], "allow", "{part}");
    assert_eq!(part["kept"][0]["symbol"], "src/lib.rs#charge");
}

fn unparsed_optimistic(e: &Env) {
    let r = &e.root;
    let shown = e.run(r, &["policy", "show", "--repo", "demo"]);
    let (_, rest) = shown.split_once("==> lonca.toml <==\n").unwrap();
    let (config, policy) = rest.split_once("==> policy.cedar <==\n").unwrap();
    let open = config.replace(
        "unparsed_files = \"file\"",
        "unparsed_files = \"optimistic\"",
    );
    assert_ne!(open, config);
    std::fs::write(r.join("c.toml"), open.trim_end()).unwrap();
    std::fs::write(r.join("p.cedar"), policy.trim_end()).unwrap();
    let args = [
        "policy", "set", "--repo", "demo", "--config", "c.toml", "--policy", "p.cedar",
    ];
    assert!(e.run(r, &args).contains("allow"));
}

fn unparsed_agent(e: &Env, name: &str) -> PathBuf {
    e.run(
        &e.root,
        &[
            "session",
            "start",
            "--repo",
            "demo",
            "--agent",
            "claude",
            "--paths",
            "src/**",
            "--workspace",
            name,
        ],
    );
    e.root.join(name)
}

/// An unobserved session is escalated: a human approves, as in the workflow
/// test above.
fn unparsed_land(e: &Env, ws: &Path, intent: &str) -> String {
    let out = e.run(ws, &["propose", "-i", intent, "--accept-facts"]);
    if out.contains("escalate") {
        let seq: String = out
            .trim_start_matches('#')
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        e.run(&e.root, &["approve", &seq, "--repo", "demo"]);
    }
    e.settle();
    out
}

const MAIN: &str = "src/Main.zig";

fn numbered() -> String {
    (0..40).map(|i| format!("    int a{i} = {i};\n")).collect()
}

fn line(s: &str, i: usize, to: &str) -> String {
    s.replace(&format!("a{i} = {i};"), &format!("a{i} = {to};"))
}

/// Three agents on a file of forty lines, under `optimistic`.
fn three_agents(e: &Env) -> [PathBuf; 3] {
    agent_workspace(e);
    unparsed_optimistic(e);
    let hws = e.root.join("hws");
    e.run(&hws, &["sync"]);
    std::fs::write(hws.join(MAIN), numbered()).unwrap();
    land(e, &hws, "seed");
    ["wa", "wb", "wc"].map(|name| unparsed_agent(e, name))
}

fn trunk_text(e: &Env) -> String {
    let hws = e.root.join("hws");
    e.run(&hws, &["sync"]);
    std::fs::read_to_string(hws.join(MAIN)).unwrap()
}

/// `text` with the conflict settled by `settled`, markers gone.
fn settle(text: &str, settled: &str) -> String {
    let (head, rest) = text.split_once("<<<<<<< local").unwrap();
    let (_, tail) = rest.split_once(">>>>>>> trunk").unwrap();
    let (_, tail) = tail.split_once('\n').unwrap();
    format!("{head}{settled}{tail}")
}

/// What trunk gained elsewhere comes in, what meets is written out, and
/// nothing can be proposed until it is settled.
#[test]
fn a_conflict_in_an_unparsed_file_keeps_what_others_landed() {
    let e = Env::new();
    let [a, b, c] = three_agents(&e);
    let seed = numbered();
    std::fs::write(c.join(MAIN), line(&seed, 30, "3000")).unwrap();
    unparsed_land(&e, &c, "line 30");
    std::fs::write(a.join(MAIN), line(&seed, 10, "1000")).unwrap();
    unparsed_land(&e, &a, "line 10");
    std::fs::write(b.join(MAIN), line(&seed, 10, "2000")).unwrap();
    unparsed_land(&e, &b, "line 10 too");

    e.run(&b, &["sync", "--json"]);
    let local = std::fs::read_to_string(b.join(MAIN)).unwrap();
    assert!(local.contains("a30 = 3000;"), "trunk comes in: {local}");
    assert!(local.contains("a10 = 1000;"), "their side: {local}");
    assert!(local.contains("a10 = 2000;"), "our side: {local}");
    let refused = fails(&e, &b, &["propose", "-i", "too soon", "--accept-facts"]);
    assert!(
        refused.contains("conflict not settled in src/Main.zig"),
        "{refused}"
    );

    let settled = settle(&local, "    int a10 = 1500;\n");
    std::fs::write(b.join(MAIN), &settled).unwrap();
    unparsed_land(&e, &b, "settle line 10");
    let trunk = trunk_text(&e);
    assert!(trunk.contains("a10 = 1500;"), "{trunk}");
    assert!(trunk.contains("a30 = 3000;"), "{trunk}");
}

/// A line next to another's is shown, so it is not taken back unseen.
#[test]
fn a_neighbours_line_is_seen_and_kept() {
    let e = Env::new();
    let [a, b, _] = three_agents(&e);
    let seed = numbered();
    std::fs::write(a.join(MAIN), line(&seed, 10, "1000")).unwrap();
    unparsed_land(&e, &a, "line 10");
    std::fs::write(b.join(MAIN), line(&seed, 9, "900")).unwrap();
    unparsed_land(&e, &b, "line 9");

    e.run(&b, &["sync", "--json"]);
    let local = std::fs::read_to_string(b.join(MAIN)).unwrap();
    assert!(local.contains("a10 = 1000;"), "{local}");
    let both = "    int a9 = 900;\n    int a10 = 1000;\n";
    std::fs::write(b.join(MAIN), settle(&local, both)).unwrap();
    unparsed_land(&e, &b, "both lines");
    let trunk = trunk_text(&e);
    assert!(trunk.contains(both), "{trunk}");
}

/// All of another's hunk is in view, not the line that met it alone.
#[test]
fn all_of_a_change_that_meets_is_shown() {
    let e = Env::new();
    let [a, b, _] = three_agents(&e);
    let seed = numbered();
    let three = line(&line(&line(&seed, 10, "1000"), 11, "1100"), 12, "1200");
    std::fs::write(a.join(MAIN), &three).unwrap();
    unparsed_land(&e, &a, "lines 10 to 12");
    std::fs::write(b.join(MAIN), line(&seed, 10, "2000")).unwrap();
    unparsed_land(&e, &b, "line 10");

    e.run(&b, &["sync", "--json"]);
    let local = std::fs::read_to_string(b.join(MAIN)).unwrap();
    for shown in ["a10 = 2000;", "a10 = 1000;", "a11 = 1100;", "a12 = 1200;"] {
        assert!(local.contains(shown), "{shown}: {local}");
    }
}

/// A conflict stays open through a sync with nothing to do with it.
#[test]
fn a_second_sync_keeps_an_open_conflict() {
    let e = Env::new();
    let [a, b, c] = three_agents(&e);
    let seed = numbered();
    std::fs::write(a.join(MAIN), line(&seed, 10, "1000")).unwrap();
    unparsed_land(&e, &a, "line 10");
    std::fs::write(b.join(MAIN), line(&seed, 10, "2000")).unwrap();
    unparsed_land(&e, &b, "line 10 too");
    e.run(&b, &["sync", "--json"]);

    std::fs::write(c.join(MAIN), line(&seed, 35, "3500")).unwrap();
    unparsed_land(&e, &c, "line 35");
    let synced = parse(&e.run(&b, &["sync", "--json"]));
    assert_eq!(synced["conflicts"][0]["path"], MAIN, "{synced}");
    let copy = std::fs::read_to_string(b.join("src/Main.zig.trunk")).unwrap();
    assert!(copy.contains("a35 = 3500;"), "{copy}");
    let local = std::fs::read_to_string(b.join(MAIN)).unwrap();
    assert!(local.contains("a35 = 3500;"), "{local}");
    assert!(local.contains("a10 = 1000;"), "{local}");
    let refused = fails(&e, &b, &["propose", "-i", "too soon", "--accept-facts"]);
    assert!(refused.contains("conflict not settled"), "{refused}");
}

/// One conflict in `src/Main.zig`, left open in the second workspace, and
/// the text there.
fn an_open_conflict(e: &Env) -> (PathBuf, String) {
    let [a, b, _] = three_agents(e);
    let seed = numbered();
    std::fs::write(a.join(MAIN), line(&seed, 10, "1000")).unwrap();
    unparsed_land(e, &a, "line 10");
    std::fs::write(b.join(MAIN), line(&seed, 10, "2000")).unwrap();
    unparsed_land(e, &b, "line 10 too");
    e.run(&b, &["sync", "--json"]);
    let local = std::fs::read_to_string(b.join(MAIN)).unwrap();
    (b, local)
}

const TOO_SOON: [&str; 4] = ["propose", "-i", "too soon", "--accept-facts"];

/// The markers go with the text, not with the path.
#[test]
fn a_new_name_does_not_settle_a_conflict() {
    let e = Env::new();
    let (b, local) = an_open_conflict(&e);
    std::fs::remove_file(b.join(MAIN)).unwrap();
    std::fs::write(b.join("src/Renamed.zig"), &local).unwrap();
    let refused = fails(&e, &b, &TOO_SOON);
    assert!(
        refused.contains("conflict not settled in src/Renamed.zig"),
        "{refused}"
    );
}

/// Each marker counts: taking out one leaves the others.
#[test]
fn every_marker_has_to_go() {
    for kept in ["=======", ">>>>>>> trunk"] {
        let e = Env::new();
        let (b, local) = an_open_conflict(&e);
        let without: Vec<&str> = local
            .lines()
            .filter(|l| !l.starts_with(if kept == "=======" { "<<<" } else { "===" }))
            .collect();
        std::fs::write(b.join(MAIN), without.join("\n") + "\n").unwrap();
        let refused = fails(&e, &b, &TOO_SOON);
        assert!(refused.contains("conflict not settled"), "{refused}");
    }
}

/// A line of the file itself that reads like a marker is the file's.
#[test]
fn a_file_may_hold_what_reads_like_a_marker() {
    let e = Env::new();
    let [a, b, _] = three_agents(&e);
    let seed = numbered().replace("    int a30 = 30;\n", "<<<<<<< local\n=======\n");
    let hws = e.root.join("hws");
    std::fs::write(hws.join(MAIN), &seed).unwrap();
    land(&e, &hws, "a file with such lines");
    e.run(&a, &["sync"]);
    e.run(&b, &["sync"]);
    std::fs::write(a.join(MAIN), line(&seed, 10, "1000")).unwrap();
    unparsed_land(&e, &a, "line 10");
    std::fs::write(b.join(MAIN), line(&seed, 10, "2000")).unwrap();
    unparsed_land(&e, &b, "line 10 too");
    e.run(&b, &["sync", "--json"]);
    let local = std::fs::read_to_string(b.join(MAIN)).unwrap();
    let (head, rest) = local.split_once("<<<<<<< local ").unwrap();
    let (_, tail) = rest.split_once(">>>>>>> trunk ").unwrap();
    let (_, tail) = tail.split_once('\n').unwrap();
    std::fs::write(b.join(MAIN), format!("{head}    int a10 = 1500;\n{tail}")).unwrap();
    unparsed_land(&e, &b, "settled");
    assert!(trunk_text(&e).contains("a10 = 1500;"));
}

fn a_batch_landed(e: &Env) -> (u64, Vec<PathBuf>) {
    agent_workspace(e);
    let r = &e.root;
    let shown = e.run(r, &["policy", "show", "--repo", "demo"]);
    assert!(shown.contains("batch_size = 1"), "{shown}");
    let cfg = lonca_policy::config::DEFAULT_CONFIG
        .replace("batch_size = 1", "batch_size = 2")
        .replace("# test = \"cargo test --offline\"", "test = \"sleep 2\"");
    std::fs::write(r.join("c.toml"), cfg).unwrap();
    std::fs::write(r.join("p.cedar"), lonca_policy::config::DEFAULT_POLICY).unwrap();
    e.run(
        r,
        &[
            "policy", "set", "--repo", "demo", "--config", "c.toml", "--policy", "p.cedar",
        ],
    );
    let mut wss = Vec::new();
    for w in ["w1", "w2", "w3"] {
        e.run(r, &["workspace", "create", w, "--repo", "demo"]);
        wss.push(r.join(w));
    }
    for (i, w) in wss.iter().enumerate() {
        std::fs::write(w.join(format!("src/f{i}.txt")), "hello\n").unwrap();
        e.run(w, &["propose", "-i", "add"]);
    }
    e.settle();
    let log = parse(&e.run(r, &["log", "--repo", "demo", "--json"]));
    let batch = log
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["entry"]["op"]["op"] == "change.integrate_batch")
        .expect("a batch");
    (batch["entry"]["seq"].as_u64().unwrap(), wss)
}

fn undo_claims(e: &Env) -> Vec<serde_json::Value> {
    let log = parse(&e.run(&e.root, &["log", "--repo", "demo", "--json"]));
    log.as_array()
        .unwrap()
        .iter()
        .filter(|o| {
            o["entry"]["op"]["op"] == "change.propose"
                && o["entry"]["op"]["claim"]["intent"]
                    .as_str()
                    .is_some_and(|i| i.starts_with("Undo"))
        })
        .map(|o| o["entry"]["op"]["claim"].clone())
        .collect()
}

/// `undo` of a batch is a revert of each change in it, so that what counts
/// reverts counts them.
#[test]
fn undoing_a_batch_reverts_each_change() {
    let e = Env::new();
    let (seq, _) = a_batch_landed(&e);
    e.run(&e.root, &["undo", &seq.to_string(), "--repo", "demo"]);
    e.settle();
    let claims = undo_claims(&e);
    assert_eq!(claims.len(), 2, "{claims:?}");
    assert!(
        claims.iter().all(|c| !c["revert_of"].is_null()),
        "{claims:?}"
    );
}
