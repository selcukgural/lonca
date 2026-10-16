//! Shared harness: a daemon driven through its request handler with a
//! controllable clock and a file-key human.
#![allow(dead_code, unused_imports)]

pub use std::path::{Path, PathBuf};
pub use std::process::Command;
pub use std::sync::Arc;
pub use std::sync::atomic::{AtomicI64, Ordering};

pub use base64::Engine;
pub use lonca_core::keys::KeyPair;
pub use lonca_core::oplog::{OpLog, SignedOp, verify_chain};
pub use lonca_core::ops::{Claim, HumanKey, LeaseItem, LeaseKind, Op, OpKind, Outcome, Scope};
pub use lonca_core::{ChangeId, GitId, Store};
pub use lonca_daemon::protocol::{FileChange, Request};
pub use lonca_daemon::{Home, Service, Settings};
pub use lonca_policy::human::sign_ed25519;
pub use serde_json::{Value, json};

pub const T0: i64 = 1_760_000_000_000;

pub struct Env {
    pub _dir: tempfile::TempDir,
    pub root: PathBuf,
    pub svc: Arc<Service>,
    pub clock: Arc<AtomicI64>,
    pub human: KeyPair,
    pub settings: Settings,
    pub next_id: u64,
}

pub fn b64(s: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(s)
}

pub fn file(path: &str, text: &str) -> FileChange {
    FileChange {
        path: path.into(),
        content_b64: Some(b64(text)),
        mode: None,
    }
}

pub fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

pub const LIB: &str =
    "pub fn charge(a: u64) -> u64 {\n    a\n}\n\npub fn refund(a: u64) -> u64 {\n    a\n}\n";

impl Env {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let clock = Arc::new(AtomicI64::new(T0));
        let settings = Settings {
            managed_settings: root.join("managed-settings.json"),
            require_root_settings: false,
            git: "git".into(),
        };
        let svc = Self::open_service(&root, &settings, &clock);
        Env {
            _dir: dir,
            root,
            svc,
            clock,
            human: KeyPair::generate(),
            settings,
            next_id: 1,
        }
    }

    pub fn open_service(root: &Path, settings: &Settings, clock: &Arc<AtomicI64>) -> Arc<Service> {
        let c = clock.clone();
        Service::open(
            Home::new(root.join("home")),
            settings.clone(),
            Arc::new(move || c.fetch_add(1, Ordering::SeqCst)),
        )
        .unwrap()
    }

    pub fn reopen(&mut self) {
        self.svc = Self::open_service(&self.root, &self.settings, &self.clock);
    }

    pub fn now(&self) -> i64 {
        self.clock.load(Ordering::SeqCst)
    }

    pub fn advance(&self, ms: i64) {
        self.clock.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn call(
        &mut self,
        method: &str,
        repo: Option<&str>,
        token: Option<&str>,
        params: Value,
    ) -> Result<Value, (String, String)> {
        self.next_id += 1;
        let r = self.svc.handle(Request {
            id: self.next_id,
            method: method.into(),
            repo: repo.map(String::from),
            token: token.map(String::from),
            params,
        });
        if r.ok {
            Ok(r.result)
        } else {
            Err(r.error.map(|e| (e.code, e.message)).unwrap())
        }
    }

    pub fn ok(
        &mut self,
        method: &str,
        repo: Option<&str>,
        token: Option<&str>,
        params: Value,
    ) -> Value {
        self.call(method, repo, token, params)
            .unwrap_or_else(|e| panic!("{method}: {e:?}"))
    }

    pub fn sign(&self, op: &Op) -> Value {
        json!({"op": op, "sig": sign_ed25519(&self.human, "ayse", "demo", op, self.now())})
    }

    pub fn human(&mut self, op: Op) -> Value {
        let body = self.sign(&op);
        self.ok("human.submit", Some("demo"), None, body)
    }

    pub fn init(&mut self, import_from: Option<&str>) {
        let key = HumanKey {
            alg: "ed25519".into(),
            public: self.human.public_hex(),
        };
        let prep = self.ok(
            "repo.prepare_init",
            None,
            None,
            json!({"repo": "demo", "human": "ayse", "human_key": key, "import_from": import_from}),
        );
        let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
        let body = self.sign(&op);
        let r = self.ok("repo.init", None, None, body);
        assert_eq!(r["decision"]["outcome"], "allow");
    }

    pub fn trunk(&mut self) -> GitId {
        let s = self.ok("status", Some("demo"), None, json!({}));
        serde_json::from_value(s["trunk"].clone()).unwrap()
    }

    pub fn human_change(&mut self, files: Vec<FileChange>, intent: &str) -> Value {
        let base = self.trunk();
        let prep = self.ok(
            "human.prepare_change",
            Some("demo"),
            None,
            json!({"base": base, "files": files, "author": "ayse", "intent": intent}),
        );
        let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
        self.human(op)
    }

    pub fn session(&mut self, id: &str, paths: &[&str]) -> String {
        let op = Op::SessionStart {
            session: id.into(),
            agent: format!("bot-{id}"),
            model: None,
            task: "T-1".into(),
            scope: Scope {
                paths: paths.iter().map(|p| p.to_string()).collect(),
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
            },
            expires_ms: self.now() + 3_600_000,
        };
        let r = self.human(op);
        r["token"].as_str().expect("token").to_string()
    }

    /// Writes managed settings that lock hooks and sandbox, then binds.
    pub fn bind(&mut self, token: &str) {
        let settings = json!({
            "allowManagedHooksOnly": true,
            "hooks": {
                "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "/usr/bin/lonca hook", "onFailure": "block"}]}],
                "PostToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "/usr/bin/lonca hook", "onFailure": "block"}]}]
            },
            "sandbox": {"enabled": true, "failIfUnavailable": true, "allowUnsandboxedCommands": false, "network": {"httpProxyPort": 8471}}
        });
        std::fs::write(
            &self.settings.managed_settings,
            serde_json::to_vec(&settings).unwrap(),
        )
        .unwrap();
        let r = self.ok("hook.bind", None, Some(token), json!({"harness": "claude-code", "harness_session": "h1", "sudo_without_password": false}));
        assert_eq!(r["level"], "hooks_sandbox", "{r}");
    }

    pub fn wrote(&mut self, token: &str, path: &str) {
        let ws = self.root.join("ws");
        self.ok(
            "hook.event",
            None,
            Some(token),
            json!({"hook_event_name": "PostToolUse", "tool_name": "Edit", "tool_input": {"file_path": ws.join(path)}, "workspace": ws}),
        );
    }

    pub fn lease(&mut self, token: &str, sym: &str) -> Value {
        let items = vec![LeaseItem {
            symbol: sym.into(),
            kind: LeaseKind::Edit,
        }];
        self.ok(
            "lease.acquire",
            None,
            Some(token),
            json!({"items": items, "intent": "fix", "ttl_ms": 600_000}),
        )
    }

    pub fn propose(
        &mut self,
        token: &str,
        base: &GitId,
        files: Vec<FileChange>,
        edits: &[&str],
    ) -> Value {
        let claim = Claim {
            intent: "agent change".into(),
            edits: edits.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        self.ok(
            "change.propose",
            None,
            Some(token),
            json!({"base": base, "files": files, "claim": claim}),
        )
    }

    pub fn store(&self) -> Store {
        Store::open(&self.root.join("home/repos/demo.git")).unwrap()
    }
}
