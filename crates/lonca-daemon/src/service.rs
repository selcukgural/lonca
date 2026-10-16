//! Request handling: authentication, the single writer, side effects and
//! the merge queue.

use std::collections::{BTreeMap, VecDeque};
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use lonca_core::canonical::random_id;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{OpLog, SignedOp};
use lonca_core::ops::{Actor, BindChecks, Claim, Op};
use lonca_core::store::CommitSpec;
use lonca_core::{ChangeId, Error, GitId, Result, Store};
use lonca_policy::chain::Submission;
use lonca_policy::decide::level_for;
use lonca_symbols::integrate::{facts_of, integrate};
use lonca_verify::Verifier;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::home::{Home, Tokens};
use crate::hooks;
use crate::protocol::*;
use crate::repo::{HUMAN_HEADER, POLICY_REF, RepoHandle, SESSION_HEADER, TRUNK_REF};

pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

pub fn system_clock() -> Clock {
    Arc::new(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0)
    })
}

#[derive(Clone, Debug)]
pub struct Settings {
    /// Claude Code managed settings inspected by `hook.bind`.
    pub managed_settings: PathBuf,
    /// Require managed settings and the hook program to be root-owned.
    pub require_root_settings: bool,
    pub git: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            managed_settings: hooks::default_managed_settings(),
            require_root_settings: true,
            git: "git".into(),
        }
    }
}

type Hr = std::result::Result<Value, (String, String)>;

fn fail<T>(code: &str, msg: impl Into<String>) -> std::result::Result<T, (String, String)> {
    Err((code.into(), msg.into()))
}

fn from_err(e: Error) -> (String, String) {
    let code = match e {
        Error::Invalid(_) => "invalid",
        Error::Conflict(_) => "conflict",
        Error::Integrity(_) => "integrity",
        Error::Git(_) | Error::Io(_) | Error::Json(_) => "internal",
    };
    (code.into(), e.to_string())
}

trait OrFail<T> {
    fn or_fail(self) -> std::result::Result<T, (String, String)>;
}

impl<T> OrFail<T> for Result<T> {
    fn or_fail(self) -> std::result::Result<T, (String, String)> {
        self.map_err(from_err)
    }
}

fn params<T: DeserializeOwned>(v: &Value) -> std::result::Result<T, (String, String)> {
    serde_json::from_value(v.clone()).map_err(|e| ("invalid".into(), format!("params: {e}")))
}

fn logged(op: &SignedOp) -> Value {
    json!({"seq": op.entry.seq, "decision": op.entry.decision})
}

struct Inner {
    repos: BTreeMap<String, RepoHandle>,
    tokens: Tokens,
    prepared: BTreeMap<String, Op>,
}

pub struct Service {
    pub home: Home,
    key: KeyPair,
    clock: Clock,
    verifier: Verifier,
    settings: Settings,
    inner: Mutex<Inner>,
    wake: (Mutex<u64>, Condvar),
}

impl Service {
    pub fn open(home: Home, settings: Settings, clock: Clock) -> Result<Arc<Self>> {
        home.ensure()?;
        let key = home.load_key()?;
        let tokens = Tokens::load(&home.tokens_path())?;
        let mut repos = BTreeMap::new();
        for entry in std::fs::read_dir(home.repos())? {
            let path = entry?.path();
            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".git"))
            else {
                continue;
            };
            let r = RepoHandle::open(name, &path, key.clone())?;
            repos.insert(name.to_string(), r);
        }
        let svc = Arc::new(Self {
            verifier: Verifier::new(home.scratch()),
            home,
            key,
            clock,
            settings,
            inner: Mutex::new(Inner {
                repos,
                tokens,
                prepared: BTreeMap::new(),
            }),
            wake: (Mutex::new(0), Condvar::new()),
        });
        {
            let mut inner = svc.lock();
            let now = svc.now();
            for r in inner.repos.values_mut() {
                if r.initialized() {
                    Self::reconcile(r, now)
                        .map_err(|e| Error::Integrity(format!("{}: {}", e.0, e.1)))?;
                }
            }
        }
        Ok(svc)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    pub fn public_key(&self) -> String {
        self.key.public_hex()
    }

    fn notify_queue(&self) {
        let (m, c) = &self.wake;
        *m.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        c.notify_all();
    }

    pub fn handle(&self, req: Request) -> Response {
        match self.dispatch(&req) {
            Ok(v) => Response::ok(req.id, v),
            Err((code, msg)) => Response::err(req.id, &code, msg),
        }
    }

    fn dispatch(&self, req: &Request) -> Hr {
        let p = &req.params;
        match req.method.as_str() {
            "ping" => {
                Ok(json!({"version": env!("CARGO_PKG_VERSION"), "daemon_key": self.public_key()}))
            }
            "repo.list" => Ok(json!(self.lock().repos.keys().collect::<Vec<_>>())),
            "repo.prepare_init" => self.prepare_init(params(p)?),
            "repo.init" => self.init(params(p)?),
            "status" => self.status(req),
            "log" => self.log(req, params(p)?),
            "tree" => self.tree(req, params(p)?),
            "change.get" => self.change_get(req, params(p)?),
            "whoami" => self.whoami(req),
            "human.prepare_change" => self.prepare_change(req, params(p)?),
            "human.prepare_policy" => self.prepare_policy(req, params(p)?),
            "human.prepare_import" => self.prepare_import(req, params(p)?),
            "human.prepare_push" => self.prepare_push(req, params(p)?),
            "human.submit" => self.human_submit(req, params(p)?),
            "lease.acquire" => self.lease_acquire(req, params(p)?),
            "lease.release" => {
                let s: SetRef = params(p)?;
                self.agent_op(req, |_| Ok(Op::LeaseRelease { set: s.set.clone() }))
            }
            "lease.renew" => {
                let s: SetRef = params(p)?;
                let ttl = s.ttl_ms.unwrap_or(10 * 60_000);
                self.agent_op(req, |_| {
                    Ok(Op::LeaseRenew {
                        set: s.set.clone(),
                        ttl_ms: ttl,
                    })
                })
            }
            "change.propose" => self.propose(req, params(p)?),
            "change.withdraw" => {
                let c: ChangeRef = params(p)?;
                self.agent_op(req, |_| Ok(Op::ChangeWithdraw { change: c.change }))
            }
            "facts.preview" => self.facts_preview(req, params(p)?),
            "negotiate" => {
                let n: Negotiate = params(p)?;
                self.agent_op(req, |_| {
                    Ok(Op::Negotiate {
                        thread: n.thread.clone(),
                        to_session: n.to_session.clone(),
                        message: n.message.clone(),
                    })
                })
            }
            "cap.attenuate" => self.attenuate(req, params(p)?),
            "session.end" => self.agent_end(req),
            "hook.event" => self.hook_event(req, params(p)?),
            "hook.bind" => self.hook_bind(req, params(p)?),
            "queue.run" => Ok(json!({"integrated": self.process_all()})),
            m => fail("unknown_method", format!("unknown method {m}")),
        }
    }

    fn repo_name(req: &Request) -> std::result::Result<String, (String, String)> {
        req.repo
            .clone()
            .ok_or_else(|| ("invalid".into(), "missing repo".into()))
    }

    fn repo<'a>(
        inner: &'a mut Inner,
        name: &str,
    ) -> std::result::Result<&'a mut RepoHandle, (String, String)> {
        match inner.repos.get_mut(name) {
            Some(r) if r.initialized() => Ok(r),
            _ => fail("not_found", format!("no repository {name}")),
        }
    }

    /// Resolves an agent token to (repo, actor).
    fn agent(
        inner: &Inner,
        req: &Request,
    ) -> std::result::Result<(String, Actor), (String, String)> {
        let Some(token) = req.token.as_deref() else {
            return fail("unauthenticated", "missing session token");
        };
        let Some(e) = inner.tokens.lookup(token).cloned() else {
            return fail("unauthenticated", "unknown session token");
        };
        let Some(r) = inner.repos.get(&e.repo) else {
            return fail("unauthenticated", "token for unknown repository");
        };
        let Some(s) = r.chain.state.sessions.get(&e.session) else {
            return fail("unauthenticated", "unknown session");
        };
        Ok((
            e.repo,
            Actor::Agent {
                name: s.agent.clone(),
                session: e.session,
            },
        ))
    }

    /// Repo name from the token if present, else from the request.
    fn read_repo(inner: &Inner, req: &Request) -> std::result::Result<String, (String, String)> {
        if req.token.is_some() {
            return Ok(Self::agent(inner, req)?.0);
        }
        Self::repo_name(req)
    }

    // ---------------------------------------------------------------- init

    fn prepare_init(&self, p: PrepareInit) -> Hr {
        if !lonca_policy::decide::valid_token(&p.repo, 64)
            || !lonca_policy::decide::valid_token(&p.human, 64)
        {
            return fail(
                "invalid",
                "repository and human names: letters, digits, '.', '_', '-'",
            );
        }
        let mut inner = self.lock();
        if inner.repos.get(&p.repo).is_some_and(|r| r.initialized()) {
            return fail("conflict", format!("repository {} exists", p.repo));
        }
        let now = self.now();
        if !inner.repos.contains_key(&p.repo) {
            let path = self.home.repo_path(&p.repo);
            let r = if path.exists() {
                RepoHandle::open(&p.repo, &path, self.key.clone())
            } else {
                RepoHandle::create(&p.repo, &path, self.key.clone())
            }
            .or_fail()?;
            inner.repos.insert(p.repo.clone(), r);
        }
        let r = inner.repos.get_mut(&p.repo).expect("inserted");
        let trunk = match &p.import_from {
            Some(src) => {
                let branch = p.branch.clone().unwrap_or_else(|| "main".into());
                validate_remote(src)?;
                validate_branch(&branch)?;
                git(
                    &self.settings.git,
                    r.store.path(),
                    &[
                        "fetch",
                        "--no-tags",
                        "--",
                        src,
                        &format!("+{branch}:refs/lonca/import/initial"),
                    ],
                )?;
                r.store
                    .ref_get("refs/lonca/import/initial")
                    .or_fail()?
                    .ok_or(("invalid".into(), "import fetched nothing".into()))?
            }
            None => {
                let tree = r.store.empty_tree().or_fail()?;
                r.store
                    .write_commit(&CommitSpec {
                        tree,
                        parents: vec![],
                        author_name: p.human.clone(),
                        author_email: format!("{}@humans.lonca.invalid", p.human),
                        time_ms: now,
                        message: "lonca: initial commit\n".into(),
                        headers: vec![],
                    })
                    .or_fail()?
            }
        };
        let policy = r.write_default_policy(now).or_fail()?;
        let op = Op::RepoInit {
            repo: p.repo.clone(),
            daemon_key: self.public_key(),
            human: p.human,
            human_key: p.human_key,
            policy,
            trunk,
        };
        inner.prepared.insert(p.repo, op.clone());
        Ok(json!({"op": op}))
    }

    fn init(&self, p: HumanSubmit) -> Hr {
        let Op::RepoInit {
            repo,
            human,
            trunk,
            policy,
            ..
        } = &p.op
        else {
            return fail("invalid", "expected repo.init");
        };
        let mut inner = self.lock();
        if inner.prepared.get(repo) != Some(&p.op) {
            return fail(
                "invalid",
                "this init was not prepared by this daemon; call repo.prepare_init",
            );
        }
        let now = self.now();
        let r = inner.repos.get_mut(repo).expect("prepared repos exist");
        let mut sub = Submission::new(
            Actor::Human {
                name: human.clone(),
            },
            p.op.clone(),
        );
        sub.human = Some(p.sig);
        let dry = r.dry_run(sub.clone(), now).or_fail()?;
        if !dry.entry.decision.is_allow() {
            return fail("denied", dry.entry.decision.reasons.join(", "));
        }
        let op = r.submit(sub, now).or_fail()?;
        r.store.ref_cas(TRUNK_REF, trunk, None).or_fail()?;
        r.store.ref_cas(POLICY_REF, policy, None).or_fail()?;
        inner.prepared.remove(repo);
        Ok(logged(&op))
    }

    // ---------------------------------------------------------------- reads

    fn status(&self, req: &Request) -> Hr {
        let mut inner = self.lock();
        let name = Self::read_repo(&inner, req)?;
        let now = self.now();
        let r = Self::repo(&mut inner, &name)?;
        let s = &r.chain.state;
        let sessions: Vec<Value> = s
            .sessions
            .values()
            .map(|x| {
                json!({
                    "id": x.id, "agent": x.agent, "task": x.task, "parent": x.parent, "level": x.level,
                    "taint": x.taint, "active": s.session_active(&x.id, now), "expires_ms": x.expires_ms,
                })
            })
            .collect();
        let leases: Vec<Value> = s
            .active_leases(now)
            .map(|l| json!({"set": l.set, "session": l.session, "items": l.items, "intent": l.intent, "expires_ms": l.expires_ms}))
            .collect();
        let changes: Vec<Value> = s
            .changes
            .values()
            .map(|c| json!({"change": c.change, "actor": c.actor.label(), "status": c.status, "provenance": c.provenance, "commit": c.commit, "intent": c.claim.intent}))
            .collect();
        let pending: Vec<Value> = s
            .pending
            .values()
            .map(|p| json!({"seq": p.seq, "actor": p.actor.label(), "op": p.op.kind().as_str(), "reasons": p.reasons, "approvals": p.approvals, "required": p.required}))
            .collect();
        Ok(json!({
            "repo": s.repo, "trunk": s.trunk, "policy": s.policy, "frozen": s.frozen, "queue": s.queue,
            "sessions": sessions, "leases": leases, "changes": changes, "pending": pending,
            "next_seq": s.next_seq, "head_hash": s.head_hash, "now_ms": now,
        }))
    }

    fn log(&self, req: &Request, q: LogQuery) -> Hr {
        let mut inner = self.lock();
        let name = Self::read_repo(&inner, req)?;
        let r = Self::repo(&mut inner, &name)?;
        let store = r.store.clone();
        drop(inner);
        let ops = OpLog::new(&store).read_all().or_fail()?;
        let limit = q.limit.unwrap_or(u64::MAX) as usize;
        let out: Vec<&SignedOp> = ops.iter().skip(q.from as usize).take(limit).collect();
        Ok(json!(out))
    }

    fn tree(&self, req: &Request, q: TreeQuery) -> Hr {
        let mut inner = self.lock();
        let name = Self::read_repo(&inner, req)?;
        let r = Self::repo(&mut inner, &name)?;
        let store = r.store.clone();
        let redacted = r.chain.state.redacted.clone();
        drop(inner);
        let files = store.commit_files(&q.commit).or_fail()?;
        let mut out = Vec::new();
        for (path, e) in files {
            if let Some(only) = &q.paths
                && !only.contains(&path)
            {
                continue;
            }
            let content_b64 = if q.with_content
                && e.mode != lonca_core::FileMode::Submodule
                && !redacted.contains(&e.blob)
            {
                Some(
                    base64::engine::general_purpose::STANDARD
                        .encode(store.read_blob(&e.blob).or_fail()?),
                )
            } else {
                None
            };
            out.push(TreeFile {
                path,
                mode: e.mode,
                blob: e.blob,
                content_b64,
            });
        }
        Ok(json!(out))
    }

    fn change_get(&self, req: &Request, c: ChangeRef) -> Hr {
        let mut inner = self.lock();
        let name = Self::read_repo(&inner, req)?;
        let r = Self::repo(&mut inner, &name)?;
        match r.chain.state.changes.get(&c.change) {
            Some(rec) => Ok(json!(rec)),
            None => fail("not_found", "unknown change"),
        }
    }

    fn whoami(&self, req: &Request) -> Hr {
        let inner = self.lock();
        let (repo, actor) = Self::agent(&inner, req)?;
        let r = inner.repos.get(&repo).expect("checked");
        let s = r
            .chain
            .state
            .sessions
            .get(actor.session().unwrap_or_default());
        Ok(json!({"repo": repo, "actor": actor.label(), "session": s}))
    }

    // ---------------------------------------------------------------- humans

    fn prepare_change(&self, req: &Request, p: PrepareChange) -> Hr {
        let name = Self::repo_name(req)?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        let now = self.now();
        let change = p.change.unwrap_or_else(ChangeId::random);
        let max = r.policy().or_fail()?.config.changes.max_file_bytes;
        let commit = r
            .build_change_commit(
                &p.base,
                &p.files,
                change,
                &p.author,
                &format!("{}@humans.lonca.invalid", p.author),
                (HUMAN_HEADER, &p.author),
                &p.intent,
                now,
                max,
            )
            .or_fail()?;
        let a = facts_of(&r.store, &p.base, &commit).or_fail()?;
        let f = &a.facts;
        let claim = Claim {
            intent: p.intent,
            edits: f.edits.clone(),
            adds: f.adds.clone(),
            deletes: f.deletes.clone(),
            deleted_files: f.deleted_files.clone(),
            signature_changes: f.signature_changes.clone(),
            tests: f.tests.clone(),
            revert_of: p.revert_of,
        };
        let op = Op::ChangePropose {
            change,
            commit,
            base: p.base,
            claim,
        };
        Ok(json!({"op": op, "facts": a.facts, "syntax_errors": a.syntax_errors}))
    }

    fn prepare_policy(&self, req: &Request, p: PreparePolicy) -> Hr {
        let name = Self::repo_name(req)?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        let parent = r.chain.state.policy.clone();
        let commit = r
            .write_policy(&p.config, &p.policy, parent.as_ref(), self.now())
            .or_fail()?;
        Ok(json!({"op": Op::PolicyUpdate { policy: commit }}))
    }

    fn prepare_import(&self, req: &Request, p: PrepareRemote) -> Hr {
        let name = Self::repo_name(req)?;
        validate_remote(&p.remote)?;
        let branch = p.branch.unwrap_or_else(|| "main".into());
        validate_branch(&branch)?;
        let store = {
            let mut inner = self.lock();
            Self::repo(&mut inner, &name)?.store.clone()
        };
        git(
            &self.settings.git,
            store.path(),
            &[
                "fetch",
                "--no-tags",
                "--",
                &p.remote,
                &format!("+{branch}:refs/lonca/incoming"),
            ],
        )?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        let commit = r
            .store
            .ref_get("refs/lonca/incoming")
            .or_fail()?
            .ok_or(("invalid".into(), "nothing fetched".into()))?;
        let trunk = r.chain.state.trunk.clone().expect("initialized");
        if commit == trunk {
            return fail("up_to_date", "trunk already contains the remote branch");
        }
        if !is_ancestor(&r.store, &trunk, &commit).or_fail()? {
            return fail(
                "not_fast_forward",
                "the remote branch does not contain trunk; diverged history is not imported",
            );
        }
        Ok(json!({"op": Op::ImportExternal { remote: p.remote, commit, trunk_before: trunk }}))
    }

    fn prepare_push(&self, req: &Request, p: PrepareRemote) -> Hr {
        let name = Self::repo_name(req)?;
        validate_remote(&p.remote)?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        let s = &r.chain.state;
        Ok(
            json!({"op": Op::BridgePush { remote: p.remote, oplog_seq: s.next_seq - 1, oplog_hash: s.head_hash.clone() }}),
        )
    }

    fn human_submit(&self, req: &Request, p: HumanSubmit) -> Hr {
        let name = Self::repo_name(req)?;
        let mut guard = self.lock();
        let inner = &mut *guard;
        let now = self.now();
        let r = Self::repo(inner, &name)?;
        Self::reconcile(r, now)?;
        let mut sub = Submission::new(
            Actor::Human {
                name: p.sig.human.clone(),
            },
            p.op.clone(),
        );
        sub.human = Some(p.sig);
        match &p.op {
            Op::RepoInit { .. } => return fail("invalid", "use repo.init"),
            Op::ChangePropose {
                change,
                commit,
                base,
                ..
            } => {
                r.check_proposal(commit, base, *change).or_fail()?;
                sub.facts = Some(facts_of(&r.store, base, commit).or_fail()?.facts);
            }
            Op::PolicyUpdate { policy } => {
                RepoHandle::load_policy(&r.store, policy).or_fail()?;
            }
            Op::ImportExternal {
                commit,
                trunk_before,
                ..
            } if !is_ancestor(&r.store, trunk_before, commit).or_fail()? => {
                return fail("not_fast_forward", "import must contain trunk");
            }
            _ => {}
        }
        let old_policy = r.chain.state.policy.clone();
        let seq = r.chain.state.next_seq;
        if let Op::ChangePropose { change, commit, .. } = &p.op {
            r.store
                .ref_cas(&format!("refs/lonca/changes/{change}/{seq}"), commit, None)
                .or_fail()?;
        }
        let op = r.submit(sub, now).or_fail()?;
        let mut out = logged(&op);
        if !op.entry.decision.is_allow() {
            if op.entry.decision.outcome == lonca_core::ops::Outcome::Escalate {
                self.notify_queue();
            }
            return Ok(out);
        }
        match &op.entry.op {
            Op::SessionStart { session, .. } => {
                let token = inner.tokens.issue(&name, session).or_fail()?;
                out["token"] = json!(token);
            }
            Op::PolicyUpdate { policy } => {
                let r = Self::repo(inner, &name)?;
                r.store
                    .ref_cas(POLICY_REF, policy, old_policy.as_ref())
                    .or_fail()?;
            }
            Op::ImportExternal {
                commit,
                trunk_before,
                ..
            } => {
                let r = Self::repo(inner, &name)?;
                r.store
                    .ref_cas(TRUNK_REF, commit, Some(trunk_before))
                    .or_fail()?;
            }
            Op::BridgePush { remote, .. } => {
                let r = Self::repo(inner, &name)?;
                let pushed = git(
                    &self.settings.git,
                    r.store.path(),
                    &[
                        "push",
                        "--porcelain",
                        "--",
                        remote,
                        "refs/heads/main:refs/heads/main",
                        "refs/lonca/oplog:refs/lonca/oplog",
                        "refs/lonca/policy:refs/lonca/policy",
                        "refs/lonca/changes/*:refs/lonca/changes/*",
                    ],
                )?;
                out["push"] = json!(pushed);
            }
            Op::CapRevoke { session, .. } | Op::SessionEnd { session, .. } => {
                Self::revoke_tokens(inner, &name, session)?;
            }
            Op::Approve { .. } | Op::ChangePropose { .. } => self.notify_queue(),
            _ => {}
        }
        Ok(out)
    }

    fn revoke_tokens(
        inner: &mut Inner,
        repo: &str,
        root: &str,
    ) -> std::result::Result<(), (String, String)> {
        let r = Self::repo(inner, repo)?;
        let ended: Vec<String> = r
            .chain
            .state
            .sessions
            .values()
            .filter(|s| s.ended.is_some() && r.chain.state.descends_from(&s.id, root))
            .map(|s| s.id.clone())
            .collect();
        inner.tokens.revoke_sessions(repo, &ended).or_fail()
    }

    // ---------------------------------------------------------------- agents

    /// Runs one agent operation built by `make`.
    fn agent_op(
        &self,
        req: &Request,
        make: impl FnOnce(&Actor) -> std::result::Result<Op, (String, String)>,
    ) -> Hr {
        let mut guard = self.lock();
        let (repo, actor) = Self::agent(&guard, req)?;
        let op = make(&actor)?;
        let now = self.now();
        let r = Self::repo(&mut guard, &repo)?;
        Self::reconcile(r, now)?;
        let signed = r.submit(Submission::new(actor, op), now).or_fail()?;
        Ok(logged(&signed))
    }

    fn lease_acquire(&self, req: &Request, p: LeaseAcquire) -> Hr {
        let set = p.set.clone().unwrap_or_else(|| random_id("lse"));
        let mut out = self.agent_op(req, |_| {
            Ok(Op::LeaseAcquire {
                set: set.clone(),
                items: p.items.clone(),
                intent: p.intent.clone(),
                ttl_ms: p.ttl_ms,
            })
        })?;
        out["set"] = json!(set);
        Ok(out)
    }

    fn propose(&self, req: &Request, p: ProposeChange) -> Hr {
        let mut guard = self.lock();
        let (repo, actor) = Self::agent(&guard, req)?;
        let now = self.now();
        let r = Self::repo(&mut guard, &repo)?;
        Self::reconcile(r, now)?;
        let session = actor.session().expect("agent").to_string();
        let change = p.change.unwrap_or_else(ChangeId::random);
        let max = r.policy().or_fail()?.config.changes.max_file_bytes;
        let commit = r
            .build_change_commit(
                &p.base,
                &p.files,
                change,
                &actor.label(),
                &format!("{session}@agents.lonca.invalid"),
                (SESSION_HEADER, &session),
                &p.claim.intent,
                now,
                max,
            )
            .or_fail()?;
        let analysis = facts_of(&r.store, &p.base, &commit).or_fail()?;
        let seq = r.chain.state.next_seq;
        r.store
            .ref_cas(&format!("refs/lonca/changes/{change}/{seq}"), &commit, None)
            .or_fail()?;
        let mut sub = Submission::new(
            actor,
            Op::ChangePropose {
                change,
                commit: commit.clone(),
                base: p.base,
                claim: p.claim,
            },
        );
        sub.facts = Some(analysis.facts.clone());
        let op = r.submit(sub, now).or_fail()?;
        let unobserved = op
            .entry
            .decision
            .reasons
            .iter()
            .any(|x| x.starts_with("unobserved_write:"));
        if unobserved
            && r.chain
                .state
                .sessions
                .get(&session)
                .is_some_and(|s| s.taint.is_none())
        {
            let t = Op::Taint {
                session: session.clone(),
                reason: "changed files that no observed tool wrote".into(),
            };
            r.submit(Submission::new(Actor::Daemon, t), now).or_fail()?;
        }
        if op.entry.decision.is_allow() {
            self.notify_queue();
        }
        let mut out = logged(&op);
        out["change"] = json!(change);
        out["commit"] = json!(commit);
        out["facts"] = json!(analysis.facts);
        out["syntax_errors"] = json!(analysis.syntax_errors);
        Ok(out)
    }

    fn facts_preview(&self, req: &Request, p: FactsPreview) -> Hr {
        let mut guard = self.lock();
        let (repo, actor) = Self::agent(&guard, req)?;
        let r = Self::repo(&mut guard, &repo)?;
        let max = r.policy().or_fail()?.config.changes.max_file_bytes;
        let change = ChangeId::random();
        let commit = r
            .build_change_commit(
                &p.base,
                &p.files,
                change,
                &actor.label(),
                "preview@lonca.invalid",
                ("lonca-preview", "1"),
                "",
                self.now(),
                max,
            )
            .or_fail()?;
        let a = facts_of(&r.store, &p.base, &commit).or_fail()?;
        Ok(json!({"facts": a.facts, "syntax_errors": a.syntax_errors}))
    }

    fn attenuate(&self, req: &Request, p: Attenuate) -> Hr {
        let child = random_id("ses");
        let mut guard = self.lock();
        let (repo, actor) = Self::agent(&guard, req)?;
        let parent = actor.session().expect("agent").to_string();
        let now = self.now();
        let inner = &mut *guard;
        let r = Self::repo(inner, &repo)?;
        let op = Op::CapAttenuate {
            parent,
            child: child.clone(),
            agent: p.agent,
            scope: p.scope,
            expires_ms: p.expires_ms,
        };
        let signed = r.submit(Submission::new(actor, op), now).or_fail()?;
        let mut out = logged(&signed);
        if signed.entry.decision.is_allow() {
            out["session"] = json!(child);
            out["token"] = json!(inner.tokens.issue(&repo, &child).or_fail()?);
        }
        Ok(out)
    }

    fn agent_end(&self, req: &Request) -> Hr {
        let mut guard = self.lock();
        let (repo, actor) = Self::agent(&guard, req)?;
        let session = actor.session().expect("agent").to_string();
        let now = self.now();
        let inner = &mut *guard;
        let r = Self::repo(inner, &repo)?;
        let op = Op::SessionEnd {
            session: session.clone(),
            reason: "ended by agent".into(),
        };
        let signed = r.submit(Submission::new(actor, op), now).or_fail()?;
        if signed.entry.decision.is_allow() {
            Self::revoke_tokens(inner, &repo, &session)?;
        }
        Ok(logged(&signed))
    }

    // ---------------------------------------------------------------- hooks

    fn hook_event(&self, req: &Request, ev: HookEvent) -> Hr {
        let mut guard = self.lock();
        let (repo, actor) = Self::agent(&guard, req)?;
        let session = actor.session().expect("agent").to_string();
        let now = self.now();
        let r = Self::repo(&mut guard, &repo)?;
        if !std::path::Path::new(&ev.workspace).is_absolute() {
            return fail("invalid", "workspace must be an absolute path");
        }
        let policy = r.policy().or_fail()?;
        let (events, verdict) = hooks::translate(&ev, &policy);
        if !events.is_empty() {
            r.submit(
                Submission::new(Actor::Daemon, Op::Observe { session, events }),
                now,
            )
            .or_fail()?;
        }
        Ok(json!(verdict))
    }

    fn hook_bind(&self, req: &Request, b: HookBind) -> Hr {
        let mut guard = self.lock();
        let (repo, actor) = Self::agent(&guard, req)?;
        let session = actor.session().expect("agent").to_string();
        let now = self.now();
        let r = Self::repo(&mut guard, &repo)?;
        let ins = if b.harness == "claude-code" {
            hooks::inspect_claude_code(
                &self.settings.managed_settings,
                self.settings.require_root_settings,
            )
        } else {
            hooks::Inspection {
                notes: vec![format!("unknown harness {}", b.harness)],
                ..Default::default()
            }
        };
        let checks = BindChecks {
            harness: b.harness,
            harness_session: b.harness_session,
            managed_hooks: ins.managed_hooks,
            locked_sandbox: ins.locked_sandbox,
            sudo_without_password: b.sudo_without_password,
            config_digest: ins.config_digest,
            hook_binary_protected: ins.hook_binary_protected,
        };
        let level = level_for(&checks);
        let signed = r
            .submit(
                Submission::new(
                    Actor::Daemon,
                    Op::SessionBind {
                        session,
                        checks,
                        level,
                    },
                ),
                now,
            )
            .or_fail()?;
        let mut out = logged(&signed);
        out["level"] = json!(level);
        out["notes"] = json!(ins.notes);
        Ok(out)
    }

    // ---------------------------------------------------------------- integrity

    /// Compares refs with the log. A ref the daemon itself left behind
    /// (crash between log append and ref update) is moved forward silently;
    /// anything else is recorded as `import.unmediated` and undone.
    fn reconcile(r: &mut RepoHandle, now: i64) -> std::result::Result<(), (String, String)> {
        let state = &r.chain.state;
        let (Some(trunk), Some(policy)) = (state.trunk.clone(), state.policy.clone()) else {
            return Ok(());
        };
        let on = r.policy().or_fail()?.config.integrity.on_unmediated.clone();
        for (refname, expected, history) in [(TRUNK_REF, trunk, true), (POLICY_REF, policy, false)]
        {
            let found = r.store.ref_get(refname).or_fail()?;
            if found.as_ref() == Some(&expected) {
                continue;
            }
            let recovering = history
                && found
                    .as_ref()
                    .is_some_and(|f| r.chain.state.trunk_history.contains(f));
            if !recovering {
                let op = Op::ImportUnmediated {
                    refname: refname.into(),
                    found: found.clone(),
                    expected: Some(expected.clone()),
                };
                r.submit(Submission::new(Actor::Daemon, op), now)
                    .or_fail()?;
                if on == "freeze" || refname == POLICY_REF {
                    let reason = format!("{refname} changed outside Lonca");
                    if r.chain.state.frozen.is_none() {
                        r.submit(Submission::new(Actor::Daemon, Op::Freeze { reason }), now)
                            .or_fail()?;
                    }
                }
            }
            r.store.ref_force(refname, &expected).or_fail()?;
        }
        Ok(())
    }

    /// Checks refs of every repository (run periodically).
    pub fn reconcile_all(&self) {
        let now = self.now();
        let mut inner = self.lock();
        for r in inner.repos.values_mut().filter(|r| r.initialized()) {
            let _ = Self::reconcile(r, now);
            // The auditor's only write: a flag file asking for a freeze.
            let flag = self.home.freeze_flag(&r.name);
            if let Ok(text) = std::fs::read_to_string(&flag) {
                let reason: String = text.chars().filter(|c| !c.is_control()).take(200).collect();
                let reason = if reason.is_empty() {
                    "auditor finding".to_string()
                } else {
                    reason
                };
                if r.chain.state.frozen.is_none()
                    && r.submit(Submission::new(Actor::Daemon, Op::Freeze { reason }), now)
                        .is_err()
                {
                    continue;
                }
                let _ = std::fs::remove_file(&flag);
            }
        }
    }

    // ---------------------------------------------------------------- queue

    /// Integrates the head of one repository's queue. Merging and
    /// verification run without the lock; the result is only logged if the
    /// queue head and trunk are unchanged.
    pub fn process_one(&self, repo: &str) -> Result<Option<SignedOp>> {
        let (store, change, commit, base, trunk, vcfg) = {
            let mut inner = self.lock();
            let Some(r) = inner.repos.get_mut(repo).filter(|r| r.initialized()) else {
                return Ok(None);
            };
            if r.chain.state.frozen.is_some() {
                return Ok(None);
            }
            let Some(change) = r.chain.state.queue.first().copied() else {
                return Ok(None);
            };
            let rec = &r.chain.state.changes[&change];
            let (commit, base) = (rec.commit.clone(), rec.base.clone());
            let trunk = r.chain.state.trunk.clone().expect("initialized");
            let vcfg = r.policy()?.config.verification.clone();
            (r.store.clone(), change, commit, base, trunk, vcfg)
        };
        let integ = integrate(&store, &base, &trunk, &commit)?;
        let mut evidence = Vec::new();
        if let Some(m) = &integ.merged {
            let tree = store.read_commit(m)?.tree;
            evidence.push(
                self.verifier
                    .syntax(&store, &integ.files, &integ.touched, &tree)?,
            );
            evidence.extend(self.verifier.run(&store, &integ.files, &tree, &vcfg)?);
        }
        let mut inner = self.lock();
        let r = inner.repos.get_mut(repo).expect("exists");
        if r.chain.state.queue.first() != Some(&change)
            || r.chain.state.trunk.as_ref() != Some(&trunk)
        {
            return Ok(None);
        }
        let op = Op::ChangeIntegrate {
            change,
            trunk_before: trunk.clone(),
            merged: integ.merged.clone(),
            conflicts: integ.conflicts,
        };
        let mut sub = Submission::new(Actor::Daemon, op);
        sub.evidence = evidence;
        let signed = r.submit(sub, self.now())?;
        if signed.entry.decision.is_allow()
            && let Some(m) = &integ.merged
        {
            r.store.ref_cas(TRUNK_REF, m, Some(&trunk))?;
        }
        Ok(Some(signed))
    }

    /// Drains every queue. Returns the number of integration attempts.
    pub fn process_all(&self) -> usize {
        let names: Vec<String> = self.lock().repos.keys().cloned().collect();
        let mut n = 0;
        let mut work: VecDeque<String> = names.into();
        while let Some(name) = work.pop_front() {
            match self.process_one(&name) {
                Ok(Some(_)) => {
                    n += 1;
                    work.push_back(name);
                }
                Ok(None) => {}
                Err(e) => eprintln!("lonca: queue {name}: {e}"),
            }
        }
        n
    }

    /// Background worker: drains queues when woken, and checks refs.
    pub fn spawn_worker(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let svc = self.clone();
        std::thread::spawn(move || {
            let mut seen = 0;
            loop {
                svc.process_all();
                svc.reconcile_all();
                let (m, c) = &svc.wake;
                let guard = m.lock().unwrap_or_else(|e| e.into_inner());
                if *guard == seen {
                    let (g, _) = c
                        .wait_timeout(guard, Duration::from_secs(2))
                        .unwrap_or_else(|e| e.into_inner());
                    seen = *g;
                } else {
                    seen = *guard;
                }
            }
        })
    }
}

/// Remotes: absolute paths, https://, ssh:// or scp-like `user@host:path`.
/// `ext::` and other transports that run commands are refused, as is
/// anything that could be read as an option.
fn validate_remote(r: &str) -> std::result::Result<(), (String, String)> {
    let ok_scheme = r.starts_with("https://") || r.starts_with("ssh://") || r.starts_with('/');
    let scp_like = !r.contains("://") && r.contains('@') && r.contains(':') && !r.starts_with('/');
    if r.starts_with('-')
        || r.contains("::")
        || r.chars().any(char::is_control)
        || !(ok_scheme || scp_like)
    {
        return fail(
            "invalid",
            "remote must be an absolute path, https://, ssh:// or user@host:path",
        );
    }
    Ok(())
}

fn validate_branch(b: &str) -> std::result::Result<(), (String, String)> {
    let ok = !b.is_empty()
        && !b.starts_with('-')
        && !b.contains("..")
        && b.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '_' | '-' | '.'));
    if ok {
        Ok(())
    } else {
        fail("invalid", "invalid branch name")
    }
}

fn git(
    bin: &str,
    git_dir: &std::path::Path,
    args: &[&str],
) -> std::result::Result<String, (String, String)> {
    let out = Command::new(bin)
        .arg("--git-dir")
        .arg(git_dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ALLOW_PROTOCOL", "file:https:ssh")
        .output()
        .map_err(|e| ("internal".to_string(), format!("git: {e}")))?;
    if !out.status.success() {
        return fail(
            "git",
            String::from_utf8_lossy(&out.stderr).trim().to_string(),
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Is `ancestor` reachable from `commit` through parents?
pub fn is_ancestor(store: &Store, ancestor: &GitId, commit: &GitId) -> Result<bool> {
    let mut seen = std::collections::BTreeSet::new();
    let mut todo = vec![commit.clone()];
    while let Some(c) = todo.pop() {
        if &c == ancestor {
            return Ok(true);
        }
        if !seen.insert(c.clone()) || seen.len() > 1_000_000 {
            continue;
        }
        todo.extend(store.read_commit(&c)?.parents);
    }
    Ok(false)
}
