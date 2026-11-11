//! Shared harness: a daemon driven through its request handler with a
//! controllable clock and a file-key human.
//!
//! A call made with `token: None` goes out with the human's session
//! (opened by `human.login` when the first request needs it, and again
//! when the daemon refuses it: expiry, a reopened home, a rotated key).
//! `anon` sends a request with no token at all.
#![allow(dead_code, unused_imports)]

pub use std::path::{Path, PathBuf};
pub use std::process::Command;
pub use std::sync::Arc;
pub use std::sync::atomic::{AtomicI64, Ordering};

pub use base64::Engine;
pub use lonca_core::keys::KeyPair;
pub use lonca_core::oplog::{OpLog, SignedOp, verify_chain};
pub use lonca_core::ops::{
    Claim, Continuation, HumanKey, LeaseItem, LeaseKind, Op, OpKind, Outcome, Scope,
};
pub use lonca_core::{ChangeId, GitId, Store};
pub use lonca_daemon::protocol::{FileChange, Request};
pub use lonca_daemon::{Home, Service, Settings};
pub use lonca_policy::human::{sign_ed25519, sign_login_ed25519};
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
    /// The human session used for calls made without a token.
    pub human_token: Option<String>,
    /// What the operating system would say of the caller.
    pub in_sandbox: bool,
    /// The process requests come from, as the daemon's socket would say.
    pub peer_pid: Option<u32>,
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
            managed_settings: Some(root.join("managed-settings.json")),
            require_root_settings: false,
            git: "git".into(),
            line_cap: lonca_daemon::protocol::MAX_LINE,
            proxy: Some("127.0.0.1:8471".into()),
            hardened: false,
            ..Settings::default()
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
            human_token: None,
            in_sandbox: false,
            peer_pid: None,
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

    /// One request with exactly this token (or none).
    pub fn anon(
        &mut self,
        method: &str,
        repo: Option<&str>,
        token: Option<&str>,
        params: Value,
    ) -> Result<Value, (String, String)> {
        self.next_id += 1;
        let in_sandbox = self.in_sandbox;
        let request = Request {
            id: self.next_id,
            method: method.into(),
            repo: repo.map(String::from),
            token: token.map(String::from),
            params,
        };
        let pid = self.peer_pid;
        let peer = lonca_daemon::Peer {
            in_sandbox: &|| in_sandbox,
            pid: &|| pid,
        };
        let r = self.svc.handle_from(request, &peer);
        if r.ok {
            Ok(r.result)
        } else {
            Err(r.error.map(|e| (e.code, e.message)).unwrap())
        }
    }

    /// A request; without a token, the human session stands in.
    pub fn call(
        &mut self,
        method: &str,
        repo: Option<&str>,
        token: Option<&str>,
        params: Value,
    ) -> Result<Value, (String, String)> {
        if token.is_some() {
            return self.anon(method, repo, token, params);
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            let t = match &self.human_token {
                Some(t) => Some(t.clone()),
                None => self.login().ok(),
            };
            let r = self.anon(method, repo, t.as_deref(), params.clone());
            // Expired, or the key it was opened with was rotated away:
            // open a new session with the current key and try once more.
            match &r {
                Err((code, _))
                    if (code == "unauthenticated" || code == "forbidden")
                        && t.is_some()
                        && attempts < 2 =>
                {
                    self.human_token = None;
                }
                _ => return r,
            }
        }
    }

    /// Opens a human session for `ayse` with the harness key, valid for
    /// a day, the daemon's maximum.
    pub fn login(&mut self) -> Result<String, (String, String)> {
        let ttl = 24 * 3_600_000;
        let sig = sign_login_ed25519(&self.human, "ayse", None, ttl, self.now());
        let r = self.anon(
            "human.login",
            None,
            None,
            json!({"sig": sig, "ttl_ms": ttl}),
        )?;
        let t = r["token"].as_str().expect("token").to_string();
        self.human_token = Some(t.clone());
        Ok(t)
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

    /// A session under Claude Code, the harness [`Env::bind`] locks.
    pub fn session(&mut self, id: &str, paths: &[&str]) -> String {
        self.session_under(id, paths, Some("claude-code"))
    }

    pub fn session_under(&mut self, id: &str, paths: &[&str], harness: Option<&str>) -> String {
        let mut op = self.session_op(id, paths, None);
        if let Op::SessionStart { harness: named, .. } = &mut op {
            *named = harness.map(str::to_string);
        }
        let r = self.human(op);
        r["token"].as_str().expect("token").to_string()
    }

    /// A session that takes over the workspace of `old`.
    pub fn continue_session(&mut self, id: &str, old: &str, paths: &[&str]) -> Value {
        let continues = Some(Continuation {
            session: old.into(),
            widen: false,
        });
        let mut op = self.session_op(id, paths, continues);
        // Where `old` was started, or the directory it is given now: a
        // session of these tests starts without one.
        let st = self.ok("status", Some("demo"), None, json!({}));
        let all = st["sessions"].as_array().cloned().unwrap_or_default();
        let held = all.iter().find(|s| s["id"] == old);
        let held = held.and_then(|s| s["workspace"].as_str().map(str::to_string));
        if let Op::SessionStart { workspace, .. } = &mut op {
            *workspace = held;
        }
        self.human(op)
    }

    /// A session started in a directory of its own, as the CLI starts one.
    pub fn session_in(&mut self, id: &str, paths: &[&str], dir: &str) -> String {
        let mut op = self.session_op(id, paths, None);
        if let Op::SessionStart { workspace, .. } = &mut op {
            *workspace = Some(dir.to_string());
        }
        let r = self.human(op);
        r["token"].as_str().expect("token").to_string()
    }

    pub fn session_op(&self, id: &str, paths: &[&str], continues: Option<Continuation>) -> Op {
        Op::SessionStart {
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
                scratch: vec![],
            },
            expires_ms: self.now() + 3_600_000,
            continues,
            harness: Some("claude-code".into()),
            workspace: None,
        }
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
            self.settings.managed_settings.as_ref().unwrap(),
            serde_json::to_vec(&settings).unwrap(),
        )
        .unwrap();
        let r = self.ok("hook.bind", None, Some(token), json!({"harness": "claude-code", "harness_session": "h1", "sudo_without_password": false}));
        assert_eq!(r["level"], "hooks_sandbox", "{r}");
    }

    /// `hook.input` as `lonca hook` sends it: asked where the call's paths
    /// really are, it answers with `real` (a path it does not name is
    /// where its text says) and asks again.
    pub fn hook_input(&mut self, token: &str, mut params: Value, real: &[(&str, &str)]) -> Value {
        let r = self.ok("hook.input", None, Some(token), params.clone());
        if r["phase"] != "resolve" {
            return r;
        }
        let asked = r["paths"].as_array().unwrap().iter();
        let paths: std::collections::BTreeMap<&str, &str> = asked
            .map(|p| p.as_str().unwrap())
            .map(|p| (p, real.iter().find(|(k, _)| *k == p).map_or(p, |(_, v)| *v)))
            .collect();
        params["paths"] = json!(paths);
        self.ok("hook.input", None, Some(token), params)
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
            names: Vec::new(),
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

/// A repository with integrations, a denial, an escalation, a conflict and
/// a policy change.
pub fn busy_repo() -> Env {
    let mut e = Env::new();
    e.init(None);
    e.human_change(
        vec![file("src/lib.rs", LIB), file("notes.md", "a\n")],
        "seed",
    );
    e.svc.process_all();
    let base = e.trunk();
    let t1 = e.session("s1", &["src/**"]);
    let t2 = e.session("s2", &["src/**"]);
    for t in [&t1, &t2] {
        e.bind(t);
        e.wrote(t, "src/lib.rs");
    }
    e.lease(&t1, "src/lib.rs#charge");
    e.lease(&t2, "src/lib.rs#refund");
    e.propose(
        &t1,
        &base,
        vec![file(
            "src/lib.rs",
            &LIB.replacen("    a\n", "    a + 1\n", 1),
        )],
        &["src/lib.rs#charge"],
    );
    let refund = LIB.replace(
        "pub fn refund(a: u64) -> u64 {\n    a\n",
        "pub fn refund(a: u64) -> u64 {\n    0\n",
    );
    e.propose(
        &t2,
        &base,
        vec![file("src/lib.rs", &refund)],
        &["src/lib.rs#refund"],
    );
    // Denied: claim does not match.
    e.propose(
        &t2,
        &base,
        vec![file("src/lib.rs", &refund)],
        &["src/lib.rs#charge"],
    );
    e.svc.process_all();
    // A human conflicting with an integrated agent change.
    let stale = LIB.replacen("    a\n", "    a + 9\n", 1);
    let prep = e.ok(
        "human.prepare_change",
        Some("demo"),
        None,
        json!({"base": base, "files": [file("src/lib.rs", &stale)], "author": "ayse", "intent": "late"}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    e.human(op);
    e.svc.process_all();
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": lonca_policy::config::DEFAULT_CONFIG.replace("max_rounds = 4", "max_rounds = 6"), "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    e.human(op);
    e
}

/// Appends a signed entry the way `OpLog::append` does, but without its
/// format check, so tests can write entries the daemon never would.
pub fn append_raw(store: &Store, op: &SignedOp, head: Option<&GitId>) -> GitId {
    use lonca_core::store::{CommitSpec, FileEntry, FileMap, FileMode};
    let blob = store
        .write_blob(&lonca_core::canonical::canonical_bytes(op))
        .unwrap();
    let mut files = FileMap::new();
    files.insert(
        "op.json".into(),
        FileEntry {
            mode: FileMode::Regular,
            blob,
        },
    );
    let tree = store.write_tree(&files).unwrap();
    let commit = store
        .write_commit(&CommitSpec {
            tree,
            parents: head.into_iter().cloned().collect(),
            author_name: "lonca".into(),
            author_email: "daemon@lonca.invalid".into(),
            time_ms: op.entry.time_ms,
            message: format!("lonca op {}\n", op.entry.seq),
            headers: vec![],
        })
        .unwrap();
    store.ref_cas("refs/lonca/oplog", &commit, head).unwrap();
    commit
}

/// Rewrites the daemon's log in place: `edit` changes the entries, then
/// everything is re-chained and re-signed with the daemon key (an insider
/// with the key, or a log written by an older lonca).
pub fn rewrite_log(e: &Env, edit: impl Fn(&mut Vec<lonca_core::oplog::OpEntry>)) {
    let store = e.store();
    let mut entries: Vec<_> = OpLog::new(&store)
        .read_all()
        .unwrap()
        .into_iter()
        .map(|o| o.entry)
        .collect();
    edit(&mut entries);
    let repo = e.root.join("home/repos/demo.git");
    git(&repo, &["update-ref", "-d", "refs/lonca/oplog"]);
    let key = KeyPair::load(
        &e.root.join("home/daemon.key"),
        lonca_daemon::sys::current_uid(),
    )
    .unwrap();
    let mut prev = lonca_core::oplog::GENESIS_PREV.to_string();
    let mut head = None;
    for mut entry in entries {
        entry.prev = prev;
        let signed = SignedOp::sign(entry, &key);
        prev = signed.hash.clone();
        head = Some(append_raw(&store, &signed, head.as_ref()));
    }
}
