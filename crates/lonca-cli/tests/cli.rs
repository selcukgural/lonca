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
        let settings = Settings {
            managed_settings: root.join("managed.json"),
            require_root_settings: false,
            git: "git".into(),
        };
        let svc = Service::open(
            Home::new(root.join("home")),
            settings,
            lonca_daemon::system_clock(),
        )
        .unwrap();
        let listener = lonca_daemon::server::bind(&sock).unwrap();
        svc.spawn_worker();
        std::thread::spawn(move || lonca_daemon::server::serve(listener, svc));
        Env {
            _dir: dir,
            root,
            sock,
        }
    }

    fn cmd(&self, cwd: &Path, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_lonca"));
        c.current_dir(cwd)
            .args(args)
            .env("LONCA_SOCKET", &self.sock)
            .env("LONCA_HUMANS", self.root.join("humans"))
            .env_remove("LONCA_HUMAN")
            .env_remove("LONCA_WORKSPACE");
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
