//! A daemon home with one repository that has seen some work: a human
//! change, two agent sessions bound to their hooks, leases, two proposals
//! integrated and one denied, and a policy change. Built once per process;
//! the request target runs each input on a copy of it, the replay target
//! reads its objects and starts from its log.
//!
//! The daemon never runs a human operation the fuzzer could not sign, so
//! nothing here pushes, fetches or reads outside the copy: remotes on disk
//! are refused (`local_roots` is empty) and there is no import directory.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, OnceLock};

use base64::Engine;
use lonca_client::protocol::{FileChange, Request};
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{OpLog, SignedOp};
use lonca_core::ops::{Claim, LeaseItem, LeaseKind, Op, OpKind, Scope};
use lonca_core::{GitId, Store};
use lonca_daemon::{Home, Service, Settings};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY};
use lonca_policy::human::{sign_ed25519, sign_login_ed25519};
use serde_json::{Value, json};
use zeroize::Zeroizing;

pub const REPO: &str = "demo";
const HUMAN: &str = "ayse";
const T0: i64 = 1_760_000_000_000;

pub const LIB: &str =
    "pub fn charge(a: u64) -> u64 {\n    a\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n";

/// The hook settings `hook.bind` reads: hooks and sandbox locked.
const MANAGED: &str = r#"{"allowManagedHooksOnly": true,
 "hooks": {
  "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "/usr/bin/lonca hook", "onFailure": "block"}]}],
  "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "/usr/bin/lonca hook", "onFailure": "block"}]}]},
 "sandbox": {"enabled": true, "failIfUnavailable": true, "allowUnsandboxedCommands": false, "network": {"httpProxyPort": 8471}}}"#;

pub struct Template {
    _dir: tempfile::TempDir,
    pub root: PathBuf,
    /// The clock when the template was done: a copy goes on from here, so
    /// time never goes back along its log.
    pub time_ms: i64,
    pub human_token: String,
    pub agent_tokens: [String; 2],
    pub trunk: GitId,
    /// The log, as the daemon wrote it.
    pub log: Vec<SignedOp>,
}

/// The settings of a daemon whose home is under `root`.
pub fn settings(root: &Path) -> Settings {
    Settings {
        managed_settings: Some(root.join("managed-settings.json")),
        require_root_settings: false,
        git: "git".into(),
        git_timeout: std::time::Duration::from_secs(10),
        local_roots: Some(vec![]),
        import_dir: None,
        line_cap: lonca_client::protocol::MAX_LINE,
        proxy: Some("127.0.0.1:8471".into()),
        hardened: false,
        ..Settings::default()
    }
}

/// A daemon on the home under `root`, its clock at `clock`, one millisecond
/// on with every reading.
pub fn open(root: &Path, clock: &Arc<AtomicI64>) -> Arc<Service> {
    let c = clock.clone();
    let svc = Service::open(
        Home::new(root.join("home")),
        settings(root),
        Arc::new(move || c.fetch_add(1, Ordering::SeqCst)),
    );
    svc.unwrap_or_else(|e| panic!("the daemon does not open: {e}"))
}

pub fn store(root: &Path) -> Store {
    let path = root.join("home/repos").join(format!("{REPO}.git"));
    Store::open(&path).unwrap_or_else(|e| panic!("no store: {e}"))
}

pub fn get() -> &'static Template {
    static T: OnceLock<Template> = OnceLock::new();
    T.get_or_init(build)
}

struct Builder {
    svc: Arc<Service>,
    clock: Arc<AtomicI64>,
    key: KeyPair,
    token: Option<String>,
    id: u64,
}

impl Builder {
    fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn call(&mut self, method: &str, token: Option<&str>, params: Value) -> Value {
        self.id += 1;
        // An agent's token names its repository; a human's request names it.
        let human = token.is_none() && method != "human.login" && !method.starts_with("repo.");
        let repo = human.then(|| REPO.into());
        let token = token.map(str::to_string).or_else(|| self.token.clone());
        let req = Request {
            id: self.id,
            method: method.into(),
            repo,
            token,
            params,
        };
        let r = self.svc.handle(req);
        match r.error {
            None => r.result,
            Some(e) => panic!("template: {method}: {} {}", e.code, e.message),
        }
    }

    fn signed(&self, op: &Op) -> Value {
        json!({"op": op, "sig": sign_ed25519(&self.key, HUMAN, REPO, op, self.now())})
    }

    fn prepared(&mut self, method: &str, params: Value) -> Value {
        let prep = self.call(method, None, params);
        let op: Op = serde_json::from_value(prep["op"].clone())
            .unwrap_or_else(|e| panic!("template: {method} gave no op: {e}"));
        let body = self.signed(&op);
        self.call("human.submit", None, body)
    }

    fn trunk(&mut self) -> GitId {
        let s = self.call("status", None, json!({}));
        serde_json::from_value(s["trunk"].clone()).unwrap_or_else(|e| panic!("trunk: {e}"))
    }

    fn session(&mut self, id: &str) -> String {
        let op = Op::SessionStart {
            session: id.into(),
            agent: format!("bot-{id}"),
            model: None,
            task: "T-1".into(),
            scope: Scope {
                paths: vec!["src/**".into(), "docs/**".into()],
                symbols: None,
                ops: vec![
                    OpKind::ChangePropose,
                    OpKind::LeaseAcquire,
                    OpKind::LeaseRelease,
                    OpKind::Negotiate,
                    OpKind::CapAttenuate,
                ],
                max_files: None,
                max_lines: None,
                scratch: vec![],
            },
            expires_ms: self.now() + 3_600_000,
            continues: None,
            harness: Some("claude-code".into()),
        };
        let body = self.signed(&op);
        let r = self.call("human.submit", None, body);
        let token = r["token"]
            .as_str()
            .unwrap_or_else(|| panic!("no token: {r}"));
        token.to_string()
    }
}

fn file(path: &str, text: &str) -> FileChange {
    FileChange {
        path: path.into(),
        content_b64: Some(base64::engine::general_purpose::STANDARD.encode(text)),
        mode: None,
    }
}

fn build() -> Template {
    let dir = tempfile::Builder::new()
        .prefix("lonca-fuzz-")
        .tempdir()
        .unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let root = dir.path().canonicalize().unwrap_or_else(|e| panic!("{e}"));
    std::fs::create_dir_all(root.join("ws")).unwrap_or_else(|e| panic!("{e}"));
    std::fs::write(root.join("managed-settings.json"), MANAGED).unwrap_or_else(|e| panic!("{e}"));
    let clock = Arc::new(AtomicI64::new(T0));
    let mut b = Builder {
        svc: open(&root, &clock),
        clock,
        key: KeyPair::from_secret(Zeroizing::new([7; 32])),
        token: None,
        id: 0,
    };
    // The first repository is made with no session: no human is known yet.
    let human_key = json!({"alg": "ed25519", "public": b.key.public_hex()});
    let prep = b.call(
        "repo.prepare_init",
        None,
        json!({"repo": REPO, "human": HUMAN, "human_key": human_key, "import_from": null}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap_or_else(|e| panic!("{e}"));
    let body = b.signed(&op);
    b.call("repo.init", None, body);
    let ttl = 24 * 3_600_000;
    let sig = sign_login_ed25519(&b.key, HUMAN, None, ttl, b.now());
    let login = b.call("human.login", None, json!({"sig": sig, "ttl_ms": ttl}));
    let human_token = login["token"].as_str().unwrap_or_default().to_string();
    b.token = Some(human_token.clone());

    let base = b.trunk();
    let files = [
        file("src/lib.rs", LIB),
        file("src/app.py", "def main():\n    return 1\n"),
        file("docs/notes.md", "# Notes\n\n## One\n\na\n"),
        file("config.toml", "[a]\nx = 1\n"),
    ];
    b.prepared(
        "human.prepare_change",
        json!({"base": base, "files": files, "author": HUMAN, "intent": "seed"}),
    );
    b.svc.process_all();

    let base = b.trunk();
    let agents = [b.session("s1"), b.session("s2")];
    let ws = root.join("ws");
    for (t, sym) in agents
        .iter()
        .zip(["src/lib.rs#charge", "src/lib.rs#refund"])
    {
        let harness = json!({"harness": "claude-code", "harness_session": "h1", "sudo_without_password": false});
        b.call("hook.bind", Some(t), harness);
        let event = json!({"hook_event_name": "PostToolUse", "tool_name": "Edit",
            "tool_input": {"file_path": ws.join("src/lib.rs")}, "workspace": ws});
        b.call("hook.event", Some(t), event);
        let items = [LeaseItem {
            symbol: sym.into(),
            kind: LeaseKind::Edit,
            names: vec![],
        }];
        b.call(
            "lease.acquire",
            Some(t),
            json!({"items": items, "intent": "fix", "ttl_ms": 3_600_000}),
        );
    }
    let propose = |b: &mut Builder, t: &str, text: &str, edits: &str| {
        let claim = Claim {
            intent: "agent change".into(),
            edits: vec![edits.into()],
            ..Default::default()
        };
        let files = [file("src/lib.rs", text)];
        b.call(
            "change.propose",
            Some(t),
            json!({"base": base, "files": files, "claim": claim}),
        );
    };
    let charge = LIB.replacen("    a\n", "    a + 1\n", 1);
    let refund = LIB.replace(
        "refund(a: u64) -> u64 {\n    a\n",
        "refund(a: u64) -> u64 {\n    0\n",
    );
    propose(&mut b, &agents[0], &charge, "src/lib.rs#charge");
    propose(&mut b, &agents[1], &refund, "src/lib.rs#refund");
    // Denied: the claim names the other symbol.
    propose(&mut b, &agents[1], &refund, "src/lib.rs#charge");
    b.svc.process_all();
    let config = DEFAULT_CONFIG.replace("max_rounds = 4", "max_rounds = 6");
    b.prepared(
        "human.prepare_policy",
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let trunk = b.trunk();
    let log = OpLog::new(&store(&root))
        .read_all()
        .unwrap_or_else(|e| panic!("{e}"));
    Template {
        time_ms: b.now() + 1000,
        _dir: dir,
        root,
        human_token,
        agent_tokens: agents,
        trunk,
        log,
    }
}

/// Copies the template's files to `to`, modes included: the daemon refuses
/// a key or a home anyone else could read.
pub fn copy_to(to: &Path) {
    copy_dir(&get().root, to).unwrap_or_else(|e| panic!("copying the template: {e}"));
}

fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        let (src, dst) = (entry.path(), to.join(entry.file_name()));
        let kind = entry.file_type()?;
        if kind.is_dir() {
            copy_dir(&src, &dst)?;
        } else if kind.is_symlink() {
            std::os::unix::fs::symlink(std::fs::read_link(&src)?, &dst)?;
        } else {
            std::fs::copy(&src, &dst)?;
        }
    }
    std::fs::set_permissions(to, std::fs::metadata(from)?.permissions())
}
