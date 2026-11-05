//! The `lonca` binary against an in-process daemon on a real socket.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use lonca_daemon::{Home, Service, Settings};

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
        use std::io::Write;
        let mut child = self
            .cmd(cwd, &["hook"])
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
    e.run(&ws, &["lease", "acquire", "src/lib.rs#charge"]);
    e.run(
        &ws,
        &["lease", "acquire", "src/lib.rs#<file>", "--kind", "insert"],
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
    e.run(&ws, &["lease", "acquire", "src/lib.rs#charge"]);
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
        serde_json::json!([{"path": "src/lib.rs", "trunk_copy": "src/lib.rs.trunk"}]),
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
    e.run(&ws, &["lease", "acquire", "src/lib.rs#charge"]);
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
    e.run(&ws, &["lease", "acquire", "src/lib.rs#charge"]);
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
