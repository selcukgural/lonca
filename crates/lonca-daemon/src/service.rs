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
use lonca_core::ops::{Actor, BindChecks, Claim, HumanKey, Op};
use lonca_core::store::CommitSpec;
use lonca_core::{ChangeId, Error, GitId, Result, Store};
use lonca_policy::chain::Submission;
use lonca_policy::decide::{level_for, valid_token};
use lonca_policy::human::{MAX_AGE_MS, MAX_SKEW_MS, check_fresh, verify_login};
use lonca_symbols::engine::ENGINE_CURRENT;
use lonca_symbols::integrate::{facts_of, integrate};
use lonca_verify::Verifier;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::home::{Home, TokenEntry, Tokens};
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

/// The runner-facing protocol number (`docs/protocol.md`). It goes up
/// when a shape changes in a way a client must know about; adding a
/// field does not count.
pub const PROTOCOL: u32 = 1;

/// Longest a `log` request with `wait_ms` is held.
pub const LOG_WAIT_MAX_MS: i64 = 30_000;
/// How often a held `log` request re-checks the log on its own, in case
/// an appending path forgot to signal. Long on purpose: the signal is
/// what makes the request return at once.
pub const LOG_POLL_MS: u64 = 2_000;

/// Length of a human session when `human.login` names none.
pub const HUMAN_SESSION_DEFAULT_MS: i64 = 60 * 60 * 1000;
/// The longest human session a login may ask for.
pub const HUMAN_SESSION_MAX_MS: i64 = 24 * 60 * 60 * 1000;
/// How long a login nonce is remembered: as long as a signature can be
/// fresh (its age plus the clock skew allowed), so a replay inside that
/// window is refused and nothing older needs remembering.
pub const LOGIN_NONCE_WINDOW_MS: i64 = MAX_AGE_MS + MAX_SKEW_MS;

/// What a request must carry before its method runs. Deny by default: a
/// method not in [`METHODS`] does not exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cred {
    /// Nothing.
    Public,
    /// A presence signature inside the request (`human.login`).
    Login,
    /// An agent session token; the repository is the token's.
    Agent,
    /// A human session whose key is enrolled in the request's repository.
    Human,
    /// A human session whose key is enrolled in at least one repository.
    AnyHuman,
    /// `AnyHuman`, or nothing while the daemon serves no repository yet
    /// (the first `lonca init` or `lonca restore`): there is no key to
    /// check against, and the socket is the only guard, as it was.
    Bootstrap,
    /// `Agent` (for the token's repository) or `Human`.
    Read,
    /// Any live token, agent or human.
    Any,
}

impl Cred {
    /// The name used in `docs/decisions.md`.
    pub fn name(self) -> &'static str {
        match self {
            Cred::Public => "public",
            Cred::Login => "login",
            Cred::Agent => "agent",
            Cred::Human => "human",
            Cred::AnyHuman => "any human",
            Cred::Bootstrap => "bootstrap",
            Cred::Read => "read",
            Cred::Any => "any",
        }
    }
}

/// Every method the daemon answers and what it requires. The table in
/// `docs/decisions.md` ("Daemon authentication") repeats it; a test keeps
/// the two equal.
pub const METHODS: &[(&str, Cred)] = &[
    ("ping", Cred::Public),
    ("human.login", Cred::Login),
    ("human.logout", Cred::Public),
    ("whoami", Cred::Any),
    ("repo.list", Cred::AnyHuman),
    ("repo.prepare_init", Cred::Bootstrap),
    ("repo.init", Cred::Bootstrap),
    ("repo.restore", Cred::Bootstrap),
    ("repo.backup", Cred::Human),
    ("daemon.prepare_rotate", Cred::AnyHuman),
    ("status", Cred::Read),
    ("log", Cred::Read),
    ("tree", Cred::Read),
    ("change.get", Cred::Read),
    ("human.prepare_change", Cred::Human),
    ("human.prepare_policy", Cred::Human),
    ("human.prepare_import", Cred::Human),
    ("human.prepare_push", Cred::Human),
    ("human.submit", Cred::Human),
    ("lease.acquire", Cred::Agent),
    ("lease.release", Cred::Agent),
    ("lease.renew", Cred::Agent),
    ("change.propose", Cred::Agent),
    ("change.withdraw", Cred::Agent),
    ("facts.preview", Cred::Agent),
    ("negotiate", Cred::Agent),
    ("cap.attenuate", Cred::Agent),
    ("session.end", Cred::Agent),
    ("hook.event", Cred::Agent),
    ("hook.bind", Cred::Agent),
    ("queue.run", Cred::AnyHuman),
];

/// Who sent a request, as far as its token says.
#[derive(Clone, Debug)]
enum Caller {
    Anonymous,
    Agent {
        repo: String,
        actor: Actor,
    },
    /// A human session: the name and the public key it was opened with.
    Human {
        human: String,
        key: String,
    },
}

/// A request that passed its method's credential check.
struct Auth {
    caller: Caller,
    /// The repository the request acts on, when the method has one.
    repo: Option<String>,
}

impl Auth {
    fn repo(&self) -> std::result::Result<String, (String, String)> {
        self.repo
            .clone()
            .ok_or_else(|| ("invalid".into(), "missing repo".into()))
    }

    /// A human session may only submit what its own human signed.
    fn same_human(&self, signer: &str) -> std::result::Result<(), (String, String)> {
        match &self.caller {
            Caller::Human { human, .. } if human != signer => fail(
                "forbidden",
                format!("a session of {human} can not submit a signature by {signer}"),
            ),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyVerdict {
    pub allow: bool,
    pub allow_private: bool,
    pub reason: String,
}

fn fail<T>(code: &str, msg: impl Into<String>) -> std::result::Result<T, (String, String)> {
    Err((code.into(), msg.into()))
}

fn from_err(e: Error) -> (String, String) {
    let code = match e {
        Error::Invalid(_) => "invalid",
        Error::Conflict(_) => "conflict",
        Error::Integrity(_) => "integrity",
        Error::Unsupported(_) => "unsupported",
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

/// The daemon's signing keys. During a rotation some repositories are on
/// the current key and some on the next one.
struct DaemonKeys {
    current: KeyPair,
    next: Option<KeyPair>,
}

impl DaemonKeys {
    /// The key new repositories and recoveries use.
    fn for_new(&self) -> &KeyPair {
        self.next.as_ref().unwrap_or(&self.current)
    }

    fn all(&self) -> Vec<&KeyPair> {
        std::iter::once(self.for_new())
            .chain(self.next.as_ref().map(|_| &self.current))
            .collect()
    }
}

struct Inner {
    keys: DaemonKeys,
    repos: BTreeMap<String, RepoHandle>,
    /// Repositories whose log is on a daemon key this daemon does not hold.
    /// They accept nothing but `daemon.recover`.
    foreign: BTreeMap<String, RepoHandle>,
    tokens: Tokens,
    /// Nonces of recent logins, so a login signature opens one session.
    login_nonces: BTreeMap<String, i64>,
    prepared: BTreeMap<String, Op>,
    /// (repo, session) -> workspace root, as reported at bind time.
    workspaces: BTreeMap<(String, String), PathBuf>,
}

pub struct Service {
    pub home: Home,
    clock: Clock,
    verifier: Verifier,
    settings: Settings,
    inner: Mutex<Inner>,
    wake: (Mutex<u64>, Condvar),
    /// Bumped whenever a log may have grown; `log` with `wait_ms` sleeps
    /// on it.
    appended: (Mutex<()>, Condvar),
}

impl Service {
    pub fn open(home: Home, settings: Settings, clock: Clock) -> Result<Arc<Self>> {
        home.ensure()?;
        let (current, next) = home.load_keys()?;
        let keys = DaemonKeys { current, next };
        let tokens = Tokens::load(&home.tokens_path())?;
        let mut repos = BTreeMap::new();
        let mut foreign = BTreeMap::new();
        for entry in std::fs::read_dir(home.repos())? {
            let path = entry?.path();
            let Some(name) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".git"))
            else {
                continue;
            };
            let r = RepoHandle::open(name, &path, &keys.all())?;
            if r.foreign() {
                eprintln!(
                    "lonca: repository {name} is on another daemon key; \
                     recover it with `lonca daemon-key recover --repo {name}`"
                );
                foreign.insert(name.to_string(), r);
            } else {
                repos.insert(name.to_string(), r);
            }
        }
        let svc = Arc::new(Self {
            verifier: Verifier::new(home.scratch()),
            home,
            clock,
            settings,
            inner: Mutex::new(Inner {
                keys,
                repos,
                foreign,
                tokens,
                login_nonces: BTreeMap::new(),
                prepared: BTreeMap::new(),
                workspaces: BTreeMap::new(),
            }),
            wake: (Mutex::new(0), Condvar::new()),
            appended: (Mutex::new(()), Condvar::new()),
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
            svc.promote_if_done(&mut inner)?;
        }
        Ok(svc)
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn now(&self) -> i64 {
        (self.clock)()
    }

    /// The daemon's current key.
    pub fn public_key(&self) -> String {
        self.lock().keys.current.public_hex()
    }

    /// The key of an unfinished rotation.
    pub fn next_key(&self) -> Option<String> {
        self.lock().keys.next.as_ref().map(KeyPair::public_hex)
    }

    /// Ends a rotation once no initialized repository uses the current key:
    /// the next key becomes the current one and the old secret is deleted.
    fn promote_if_done(&self, inner: &mut Inner) -> Result<()> {
        let Some(next) = inner.keys.next.clone() else {
            return Ok(());
        };
        let current = inner.keys.current.public_hex();
        if inner
            .repos
            .values()
            .any(|r| r.initialized() && r.chain.public_key() == current)
        {
            return Ok(());
        }
        self.home.promote_next_key()?;
        inner.keys = DaemonKeys {
            current: next.clone(),
            next: None,
        };
        // A prepared genesis named the old key: it must be prepared again.
        for r in inner.repos.values_mut().filter(|r| !r.initialized()) {
            r.chain.set_key(next.clone());
            inner.prepared.remove(&r.name);
        }
        Ok(())
    }

    fn notify_queue(&self) {
        let (m, c) = &self.wake;
        *m.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        c.notify_all();
    }

    /// Wakes `log` requests waiting for an entry. Called after anything
    /// that may have appended; a missed call costs a waiter at most one
    /// poll slice ([`LOG_POLL_MS`]), never the entry. The waiter re-reads
    /// the log's state under the lock, so the signal carries no value.
    fn notify_appended(&self) {
        let (m, c) = &self.appended;
        let _held = m.lock().unwrap_or_else(|e| e.into_inner());
        c.notify_all();
    }

    pub fn handle(&self, req: Request) -> Response {
        let r = match self.dispatch(&req) {
            Ok(v) => Response::ok(req.id, v),
            Err((code, msg)) => Response::err(req.id, &code, msg),
        };
        if !matches!(
            req.method.as_str(),
            "ping" | "status" | "log" | "tree" | "change.get" | "whoami" | "repo.list"
        ) {
            self.notify_appended();
        }
        r
    }

    fn dispatch(&self, req: &Request) -> Hr {
        let p = &req.params;
        let Some(&(_, cred)) = METHODS.iter().find(|(m, _)| *m == req.method) else {
            return fail("unknown_method", format!("unknown method {}", req.method));
        };
        // The one human operation that needs no session: the key that
        // would open one is the key that was lost. The recovery-key
        // signature is checked by decide(), like any signature.
        let cred = if req.method == "human.submit" && p["op"]["op"] == "human.recover" {
            Cred::Public
        } else {
            cred
        };
        let auth = self.authorize(req, cred)?;
        match req.method.as_str() {
            "ping" => Ok(json!({
                "version": env!("CARGO_PKG_VERSION"),
                "protocol": PROTOCOL,
                "daemon_key": self.public_key(),
                "next_key": self.next_key(),
            })),
            "human.login" => self.login(req, params(p)?),
            "human.logout" => self.logout(req),
            "daemon.prepare_rotate" => self.prepare_rotate(),
            "repo.list" => self.repo_list(&auth),
            "repo.prepare_init" => self.prepare_init(params(p)?),
            "repo.init" => self.init(&auth, params(p)?),
            "repo.backup" => self.backup(&auth),
            "repo.restore" => self.restore(params(p)?),
            "status" => self.status(&auth),
            "log" => self.log(&auth, params(p)?),
            "tree" => self.tree(&auth, params(p)?),
            "change.get" => self.change_get(&auth, params(p)?),
            "whoami" => self.whoami(&auth),
            "human.prepare_change" => self.prepare_change(&auth, params(p)?),
            "human.prepare_policy" => self.prepare_policy(&auth, params(p)?),
            "human.prepare_import" => self.prepare_import(&auth, params(p)?),
            "human.prepare_push" => self.prepare_push(&auth, params(p)?),
            "human.submit" => self.human_submit(&auth, params(p)?),
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
        if let Some(r) = inner.foreign.get(name) {
            return fail(
                "foreign_key",
                format!(
                    "repository {name} is on daemon key {}, which this daemon does not hold; \
                     recover it with `lonca daemon-key recover --repo {name}`",
                    r.chain.state.daemon_key.get(..16).unwrap_or_default()
                ),
            );
        }
        match inner.repos.get_mut(name) {
            Some(r) if r.initialized() => Ok(r),
            _ => fail("not_found", format!("no repository {name}")),
        }
    }

    /// Resolves the request's token. A token that is unknown, ended or
    /// expired is refused; no token is `Anonymous`, and the method's
    /// credential decides whether that is enough.
    fn caller(
        inner: &Inner,
        req: &Request,
        now: i64,
    ) -> std::result::Result<Caller, (String, String)> {
        let Some(token) = req.token.as_deref() else {
            return Ok(Caller::Anonymous);
        };
        match inner.tokens.lookup(token).cloned() {
            None => fail("unauthenticated", "unknown session token"),
            Some(TokenEntry::Agent { repo, session }) => {
                let Some(r) = inner.repos.get(&repo) else {
                    return fail("unauthenticated", "token for unknown repository");
                };
                let Some(s) = r.chain.state.sessions.get(&session) else {
                    return fail("unauthenticated", "unknown session");
                };
                if s.ended.is_some() {
                    return fail("unauthenticated", "session ended");
                }
                Ok(Caller::Agent {
                    repo,
                    actor: Actor::Agent {
                        name: s.agent.clone(),
                        session,
                    },
                })
            }
            Some(TokenEntry::Human {
                human,
                key,
                expires_ms,
            }) => {
                if expires_ms <= now {
                    return fail("unauthenticated", "human session expired");
                }
                Ok(Caller::Human { human, key })
            }
        }
    }

    /// Resolves an agent token to (repo, actor).
    fn agent(
        inner: &Inner,
        req: &Request,
        now: i64,
    ) -> std::result::Result<(String, Actor), (String, String)> {
        match Self::caller(inner, req, now)? {
            Caller::Agent { repo, actor } => Ok((repo, actor)),
            Caller::Human { .. } => fail("forbidden", "an agent session token is required"),
            Caller::Anonymous => fail("unauthenticated", "missing session token"),
        }
    }

    /// Is this human, with this key, enrolled in the repository? Foreign
    /// repositories count: `daemon.recover` is a human operation there.
    fn enrolled(inner: &Inner, human: &str, key: &str, repo: &str) -> bool {
        inner
            .repos
            .get(repo)
            .or_else(|| inner.foreign.get(repo))
            .and_then(|r| r.chain.state.humans.get(human))
            .is_some_and(|k| k.public == key)
    }

    /// The repositories a human session is enrolled in.
    fn enrolled_repos(inner: &Inner, human: &str, key: &str) -> Vec<String> {
        inner
            .repos
            .keys()
            .chain(inner.foreign.keys())
            .filter(|r| Self::enrolled(inner, human, key, r))
            .cloned()
            .collect()
    }

    /// No repository yet: nothing to check a human against.
    fn bootstrap(inner: &Inner) -> bool {
        inner.repos.values().all(|r| !r.initialized()) && inner.foreign.is_empty()
    }

    /// Checks the request's token against what the method requires and
    /// settles which repository the request acts on.
    fn authorize(&self, req: &Request, cred: Cred) -> std::result::Result<Auth, (String, String)> {
        let inner = self.lock();
        let caller = Self::caller(&inner, req, self.now())?;
        const AGENT: &str = "an agent session token is required";
        const HUMAN: &str = "a human session is required (lonca human login)";
        const EITHER: &str =
            "a session token is required: an agent's, or a human session (lonca human login)";
        let repo = match (cred, &caller) {
            (Cred::Public | Cred::Login, _) => req.repo.clone(),
            (Cred::Any, Caller::Anonymous) => return fail("unauthenticated", EITHER),
            (Cred::Any, Caller::Human { .. }) => req.repo.clone(),
            (Cred::Agent | Cred::Read | Cred::Any, Caller::Agent { repo, .. }) => {
                if req.repo.as_ref().is_some_and(|r| r != repo) {
                    return fail("forbidden", "this session token is for another repository");
                }
                Some(repo.clone())
            }
            (Cred::Agent, Caller::Human { .. }) => return fail("forbidden", AGENT),
            (Cred::Agent, Caller::Anonymous) => return fail("unauthenticated", AGENT),
            (Cred::Human | Cred::Read, Caller::Human { human, key }) => {
                let name = Self::repo_name(req)?;
                if !Self::enrolled(&inner, human, key, &name) {
                    return fail(
                        "forbidden",
                        format!("this human session is not enrolled in repository {name}"),
                    );
                }
                Some(name)
            }
            (Cred::Read, Caller::Anonymous) => return fail("unauthenticated", EITHER),
            (Cred::Human | Cred::AnyHuman | Cred::Bootstrap, Caller::Agent { .. }) => {
                return fail("forbidden", HUMAN);
            }
            (Cred::AnyHuman | Cred::Bootstrap, Caller::Human { human, key }) => {
                if Self::enrolled_repos(&inner, human, key).is_empty() {
                    return fail(
                        "forbidden",
                        "this human session is not enrolled in any repository",
                    );
                }
                req.repo.clone()
            }
            (Cred::Bootstrap, Caller::Anonymous) if Self::bootstrap(&inner) => req.repo.clone(),
            (Cred::Human | Cred::AnyHuman | Cred::Bootstrap, Caller::Anonymous) => {
                return fail("unauthenticated", HUMAN);
            }
        };
        Ok(Auth { caller, repo })
    }

    // ---------------------------------------------------------------- human sessions

    /// Opens a human session: the signature must verify with the key the
    /// named repository (or, without one, any repository) holds for the
    /// human. The token is returned once and stored as a hash.
    fn login(&self, req: &Request, p: HumanLogin) -> Hr {
        let ttl = p.ttl_ms.unwrap_or(HUMAN_SESSION_DEFAULT_MS);
        if ttl <= 0 || ttl > HUMAN_SESSION_MAX_MS {
            return fail(
                "invalid",
                format!("ttl_ms must be between 1 and {HUMAN_SESSION_MAX_MS}"),
            );
        }
        let now = self.now();
        check_fresh(&p.sig, now).map_err(|e| ("unauthenticated".to_string(), e.to_string()))?;
        let mut guard = self.lock();
        let inner = &mut *guard;
        inner
            .login_nonces
            .retain(|_, issued| *issued >= now - LOGIN_NONCE_WINDOW_MS);
        if inner.login_nonces.contains_key(&p.sig.nonce) {
            return fail("unauthenticated", "login signature already used");
        }
        let human = &p.sig.human;
        let repo = req.repo.as_deref();
        let mut keys: Vec<HumanKey> = Vec::new();
        if valid_token(human, 64) {
            let handles = inner.repos.values().chain(inner.foreign.values());
            for r in handles.filter(|r| repo.is_none_or(|n| n == r.name)) {
                if let Some(k) = r.chain.state.humans.get(human)
                    && !keys.contains(k)
                {
                    keys.push(k.clone());
                }
            }
        }
        let Some(key) = keys
            .iter()
            .find(|k| verify_login(k, repo, ttl, &p.sig, now).is_ok())
        else {
            return fail(
                "unauthenticated",
                "login failed: no enrolled key of that human verifies this signature",
            );
        };
        inner
            .login_nonces
            .insert(p.sig.nonce.clone(), p.sig.issued_ms);
        inner.tokens.sweep_expired(now).or_fail()?;
        let expires_ms = now + ttl;
        let token = inner
            .tokens
            .issue_human(human, &key.public, expires_ms)
            .or_fail()?;
        Ok(json!({"token": token, "human": human, "expires_ms": expires_ms}))
    }

    /// Ends the human session whose token the request carries. Agents end
    /// theirs with `session.end`, which is logged.
    fn logout(&self, req: &Request) -> Hr {
        let Some(token) = req.token.as_deref() else {
            return fail("invalid", "missing token");
        };
        let mut inner = self.lock();
        if matches!(inner.tokens.lookup(token), Some(TokenEntry::Agent { .. })) {
            return fail("forbidden", "agents end their session with session.end");
        }
        inner.tokens.revoke(token).or_fail()?;
        Ok(json!({"ended": true}))
    }

    /// The repositories the human session is enrolled in and this daemon
    /// signs for. Foreign ones wait for `daemon.recover` and are not
    /// listed, as before.
    fn repo_list(&self, auth: &Auth) -> Hr {
        let Caller::Human { human, key } = &auth.caller else {
            return fail("forbidden", "a human session is required");
        };
        let inner = self.lock();
        let repos: Vec<&String> = inner
            .repos
            .keys()
            .filter(|r| Self::enrolled(&inner, human, key, r))
            .collect();
        Ok(json!(repos))
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
        let mut guard = self.lock();
        let inner = &mut *guard;
        if inner.repos.get(&p.repo).is_some_and(|r| r.initialized())
            || inner.foreign.contains_key(&p.repo)
        {
            return fail("conflict", format!("repository {} exists", p.repo));
        }
        let now = self.now();
        if !inner.repos.contains_key(&p.repo) {
            let path = self.home.repo_path(&p.repo);
            let r = if path.exists() {
                RepoHandle::open(&p.repo, &path, &inner.keys.all())
            } else {
                RepoHandle::create(&p.repo, &path, inner.keys.for_new().clone())
            }
            .or_fail()?;
            inner.repos.insert(p.repo.clone(), r);
        }
        let r = inner.repos.get_mut(&p.repo).expect("inserted");
        r.chain.set_key(inner.keys.for_new().clone());
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
            daemon_key: r.chain.public_key(),
            human: p.human,
            human_key: p.human_key,
            policy,
            trunk,
        };
        inner.prepared.insert(p.repo, op.clone());
        Ok(json!({"op": op}))
    }

    fn init(&self, auth: &Auth, p: HumanSubmit) -> Hr {
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
        auth.same_human(&p.sig.human)?;
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

    fn status(&self, auth: &Auth) -> Hr {
        let name = auth.repo()?;
        let mut inner = self.lock();
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
            .map(|c| {
                json!({
                    "change": c.change, "actor": c.actor.label(), "status": c.status, "provenance": c.provenance,
                    "commit": c.commit, "base": c.base, "intent": c.claim.intent, "created_ms": c.created_ms,
                    "version": c.version, "paths": touched_paths(&c.facts),
                })
            })
            .collect();
        // One call fills a review list: what the operation is, whose, on
        // which change, since when, touching what.
        let pending: Vec<Value> = s
            .pending
            .values()
            .map(|p| {
                let session = p.actor.session().and_then(|id| s.sessions.get(id));
                let (change, base, intent) = match &p.op {
                    Op::ChangePropose {
                        change, base, claim, ..
                    } => (Some(*change), Some(base.clone()), Some(claim.intent.clone())),
                    _ => (None, None, None),
                };
                json!({
                    "seq": p.seq, "created_ms": p.time_ms, "actor": p.actor.label(), "op": p.op.kind().as_str(),
                    "reasons": p.reasons, "approvals": p.approvals, "required": p.required,
                    "change": change, "base": base, "intent": intent,
                    "agent": session.map(|x| &x.agent), "task": session.map(|x| &x.task),
                    "paths": p.facts.as_ref().map(touched_paths).unwrap_or_default(),
                })
            })
            .collect();
        // Public keys only: which key each human signs with, and the
        // recovery key if one is set.
        let humans: serde_json::Map<String, Value> = s
            .humans
            .iter()
            .map(|(n, k)| {
                (
                    n.clone(),
                    json!({"alg": k.alg, "public": k.public, "recovery": s.recovery.get(n).map(|r| &r.public)}),
                )
            })
            .collect();
        Ok(json!({
            "repo": s.repo, "trunk": s.trunk, "policy": s.policy, "frozen": s.frozen, "queue": s.queue,
            "humans": humans, "sessions": sessions, "leases": leases, "changes": changes, "pending": pending,
            "next_seq": s.next_seq, "head_hash": s.head_hash, "now_ms": now, "daemon_key": s.daemon_key,
        }))
    }

    /// The log from `from`. With `wait_ms` and nothing past `from`, the
    /// request is held (not the lock) until an entry arrives or the time
    /// runs out, so a client follows the log with one open request.
    fn log(&self, auth: &Auth, q: LogQuery) -> Hr {
        let name = auth.repo()?;
        let wait = q.wait_ms.unwrap_or(0).clamp(0, LOG_WAIT_MAX_MS);
        let deadline = std::time::Instant::now() + Duration::from_millis(wait as u64);
        let store = loop {
            let mut inner = self.lock();
            let r = Self::repo(&mut inner, &name)?;
            if r.chain.state.next_seq > q.from {
                break r.store.clone();
            }
            drop(inner);
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() {
                return Ok(json!([]));
            }
            let (m, c) = &self.appended;
            let held = m.lock().unwrap_or_else(|e| e.into_inner());
            let _ = c
                .wait_timeout(held, left.min(Duration::from_millis(LOG_POLL_MS)))
                .unwrap_or_else(|e| e.into_inner());
        };
        let ops = OpLog::new(&store).read_all().or_fail()?;
        let limit = q.limit.unwrap_or(u64::MAX) as usize;
        let out: Vec<&SignedOp> = ops.iter().skip(q.from as usize).take(limit).collect();
        Ok(json!(out))
    }

    fn tree(&self, auth: &Auth, q: TreeQuery) -> Hr {
        let name = auth.repo()?;
        let mut inner = self.lock();
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

    fn change_get(&self, auth: &Auth, c: ChangeRef) -> Hr {
        let name = auth.repo()?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        match r.chain.state.changes.get(&c.change) {
            Some(rec) => Ok(json!(rec)),
            None => fail("not_found", "unknown change"),
        }
    }

    fn whoami(&self, auth: &Auth) -> Hr {
        let inner = self.lock();
        match &auth.caller {
            Caller::Agent { repo, actor } => {
                let r = inner.repos.get(repo).expect("checked");
                let s = r
                    .chain
                    .state
                    .sessions
                    .get(actor.session().unwrap_or_default());
                Ok(json!({"repo": repo, "actor": actor.label(), "session": s}))
            }
            Caller::Human { human, key } => Ok(json!({
                "actor": Actor::Human { name: human.clone() }.label(),
                "human": human,
                "key": key,
                "repos": Self::enrolled_repos(&inner, human, key),
            })),
            Caller::Anonymous => fail("unauthenticated", "missing session token"),
        }
    }

    // ---------------------------------------------------------------- humans

    fn prepare_change(&self, auth: &Auth, p: PrepareChange) -> Hr {
        let name = auth.repo()?;
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
        let a = facts_of(&r.store, ENGINE_CURRENT, &p.base, &commit).or_fail()?;
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

    fn prepare_policy(&self, auth: &Auth, p: PreparePolicy) -> Hr {
        let name = auth.repo()?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        let parent = r.chain.state.policy.clone();
        let commit = r
            .write_policy(&p.config, &p.policy, parent.as_ref(), self.now())
            .or_fail()?;
        Ok(json!({"op": Op::PolicyUpdate { policy: commit }}))
    }

    fn prepare_import(&self, auth: &Auth, p: PrepareRemote) -> Hr {
        let name = auth.repo()?;
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

    fn prepare_push(&self, auth: &Auth, p: PrepareRemote) -> Hr {
        let name = auth.repo()?;
        validate_remote(&p.remote)?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        let s = &r.chain.state;
        Ok(
            json!({"op": Op::BridgePush { remote: p.remote, oplog_seq: s.next_seq - 1, oplog_hash: s.head_hash.clone() }}),
        )
    }

    // ---------------------------------------------------------------- backup, restore

    /// Writes a Git bundle of the repository, every ref included (trunk,
    /// the operation log, policy, proposals), into the backups directory.
    /// Under the lock, so the bundle is the store at one point of the log.
    /// Not logged: a backup is a read, like `log` or `tree`.
    fn backup(&self, auth: &Auth) -> Hr {
        let name = auth.repo()?;
        let dir = self.home.backups();
        std::fs::create_dir_all(&dir).map_err(|e| from_err(e.into()))?;
        set_mode(&dir, 0o750)?;
        let mut inner = self.lock();
        let r = Self::repo(&mut inner, &name)?;
        let seq = r.chain.state.next_seq - 1;
        let file = dir.join(format!("{name}-{seq:06}.bundle"));
        let tmp = dir.join(format!("{name}-{seq:06}.bundle.tmp"));
        git(
            &self.settings.git,
            r.store.path(),
            &["bundle", "create", "-q", &tmp.to_string_lossy(), "--all"],
        )?;
        set_mode(&tmp, 0o640)?;
        std::fs::rename(&tmp, &file).map_err(|e| from_err(e.into()))?;
        Ok(json!({
            "repo": name,
            "path": file,
            "seq": seq,
            "head_hash": r.chain.state.head_hash,
            "daemon_key": r.chain.state.daemon_key,
        }))
    }

    /// Creates a repository from a backup: a bundle, a bare store or a
    /// remote Lonca pushed to. Trunk, the operation log, policy and
    /// proposals are fetched; the log must verify and replay, else nothing
    /// is kept. A store whose log is on another daemon key comes back
    /// foreign, to be continued with `daemon.recover`. An existing
    /// repository is never replaced: the log is append-only, and a restore
    /// over it would be the rewrite the auditor exists to catch.
    fn restore(&self, p: Restore) -> Hr {
        if !lonca_policy::decide::valid_token(&p.repo, 64) {
            return fail(
                "invalid",
                "repository names: letters, digits, '.', '_', '-'",
            );
        }
        validate_remote(&p.from)?;
        let mut guard = self.lock();
        let inner = &mut *guard;
        let path = self.home.repo_path(&p.repo);
        if inner.repos.contains_key(&p.repo) || inner.foreign.contains_key(&p.repo) || path.exists()
        {
            return fail(
                "conflict",
                format!(
                    "repository {} exists; a restore never replaces a repository. \
                     Move its store away (as the daemon's user) or restore under another name",
                    p.repo
                ),
            );
        }
        let fetched = Store::init_bare(&path).or_fail().and_then(|store| {
            git(
                &self.settings.git,
                store.path(),
                &[
                    "fetch",
                    "-q",
                    "--no-tags",
                    "--",
                    &p.from,
                    "+refs/heads/*:refs/heads/*",
                    "+refs/lonca/*:refs/lonca/*",
                ],
            )?;
            let r = RepoHandle::open(&p.repo, &path, &inner.keys.all()).or_fail()?;
            if !r.initialized() {
                return fail("invalid", "the source has no operation log");
            }
            // Human signatures bind the name the log was created under.
            if r.chain.state.repo != p.repo {
                return fail(
                    "invalid",
                    format!(
                        "the source is a backup of repository {}; restore it under that name",
                        r.chain.state.repo
                    ),
                );
            }
            Ok(r)
        });
        let mut r = match fetched {
            Ok(r) => r,
            Err(e) => {
                let _ = std::fs::remove_dir_all(&path);
                return Err(e);
            }
        };
        let foreign = r.foreign();
        let out = json!({
            "repo": p.repo,
            "seq": r.chain.state.next_seq - 1,
            "head_hash": r.chain.state.head_hash,
            "daemon_key": r.chain.state.daemon_key,
            "foreign": foreign,
        });
        if foreign {
            inner.foreign.insert(p.repo, r);
        } else {
            // A backup taken between appending an entry and applying it has
            // a trunk behind its log; the log says what trunk is.
            Self::reconcile(&mut r, self.now())?;
            inner.repos.insert(p.repo, r);
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- daemon keys

    /// Starts (or resumes) a rotation: creates the next key and lists the
    /// repositories still on the current one. Each of them moves with a
    /// human-signed `daemon.rotate` naming the next key.
    fn prepare_rotate(&self) -> Hr {
        let mut guard = self.lock();
        let inner = &mut *guard;
        if inner.keys.next.is_none() {
            inner.keys.next = Some(self.home.load_or_create_next_key().or_fail()?);
        }
        let next = inner.keys.for_new().clone();
        let current = inner.keys.current.public_hex();
        let repos: Vec<&String> = inner
            .repos
            .iter()
            .filter(|(_, r)| r.initialized() && r.chain.public_key() == current)
            .map(|(n, _)| n)
            .collect();
        Ok(json!({"key": next.public_hex(), "repos": repos}))
    }

    /// Re-anchors a foreign repository on this daemon's key. Nothing is
    /// logged unless the recovery is allowed: the entry is signed by the
    /// new key, which the log only accepts for an allowed recovery.
    fn daemon_recover(&self, name: &str, p: HumanSubmit) -> Hr {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let now = self.now();
        let Some(r) = inner.foreign.get_mut(name) else {
            if inner.repos.get(name).is_some_and(|r| r.initialized()) {
                return fail(
                    "invalid",
                    format!(
                        "this daemon holds the key of repository {name}; \
                         use `lonca daemon-key rotate`"
                    ),
                );
            }
            return fail("not_found", format!("no repository {name}"));
        };
        let key = inner.keys.for_new().clone();
        if p.op.daemon_key_switch() != Some(key.public_hex().as_str()) {
            return fail(
                "invalid",
                format!(
                    "a recovery here must name this daemon's key {}",
                    key.public_hex()
                ),
            );
        }
        r.chain.set_key(key);
        let mut sub = Submission::new(
            Actor::Human {
                name: p.sig.human.clone(),
            },
            p.op,
        );
        sub.human = Some(p.sig);
        let dry = r.dry_run(sub.clone(), now).or_fail()?;
        if !dry.entry.decision.is_allow() {
            return fail("denied", dry.entry.decision.reasons.join(", "));
        }
        let op = r.submit(sub, now).or_fail()?;
        let mut r = inner.foreign.remove(name).expect("present");
        Self::reconcile(&mut r, now)?;
        inner.repos.insert(name.to_string(), r);
        Self::revoke_ended_tokens(inner, name)?;
        Ok(logged(&op))
    }

    fn human_submit(&self, auth: &Auth, p: HumanSubmit) -> Hr {
        let name = auth.repo()?;
        auth.same_human(&p.sig.human)?;
        if matches!(p.op, Op::DaemonRecover { .. }) {
            return self.daemon_recover(&name, p);
        }
        let mut guard = self.lock();
        let inner = &mut *guard;
        let now = self.now();
        let next = inner.keys.next.clone();
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
                sub.facts = Some(
                    facts_of(&r.store, ENGINE_CURRENT, base, commit)
                        .or_fail()?
                        .facts,
                );
                sub.symbols_engine = Some(ENGINE_CURRENT);
            }
            Op::PolicyUpdate { policy } => {
                RepoHandle::load_policy(&r.store, policy).or_fail()?;
            }
            // Only to a key this daemon holds: anything else would end the
            // log, since nobody could sign the next entry.
            Op::DaemonRotate { key }
                if next.as_ref().map(KeyPair::public_hex).as_ref() != Some(key) =>
            {
                return fail("invalid", "rotate to the key from daemon.prepare_rotate");
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
            // Key operations end every session of the human; an approval
            // may release an operation that ends sessions.
            Op::HumanRotate { .. } | Op::HumanRevoke { .. } | Op::HumanRecover { .. } => {
                Self::revoke_ended_tokens(inner, &name)?;
            }
            Op::Approve { .. } => {
                Self::revoke_ended_tokens(inner, &name)?;
                self.notify_queue();
            }
            Op::DaemonRotate { .. } => {
                let r = Self::repo(inner, &name)?;
                r.chain.set_key(next.expect("checked above"));
                self.promote_if_done(inner).or_fail()?;
            }
            Op::ChangePropose { .. } => self.notify_queue(),
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

    /// Drops the token of every ended session of a repository.
    fn revoke_ended_tokens(
        inner: &mut Inner,
        repo: &str,
    ) -> std::result::Result<(), (String, String)> {
        let r = Self::repo(inner, repo)?;
        let ended: Vec<String> = r
            .chain
            .state
            .sessions
            .values()
            .filter(|s| s.ended.is_some())
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
        let now = self.now();
        let (repo, actor) = Self::agent(&guard, req, now)?;
        let op = make(&actor)?;
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
        let now = self.now();
        let (repo, actor) = Self::agent(&guard, req, now)?;
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
        let analysis = facts_of(&r.store, ENGINE_CURRENT, &p.base, &commit).or_fail()?;
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
        sub.symbols_engine = Some(ENGINE_CURRENT);
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
        let now = self.now();
        let (repo, actor) = Self::agent(&guard, req, now)?;
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
                now,
                max,
            )
            .or_fail()?;
        let a = facts_of(&r.store, ENGINE_CURRENT, &p.base, &commit).or_fail()?;
        Ok(json!({"facts": a.facts, "syntax_errors": a.syntax_errors}))
    }

    fn attenuate(&self, req: &Request, p: Attenuate) -> Hr {
        let child = random_id("ses");
        let mut guard = self.lock();
        let now = self.now();
        let (repo, actor) = Self::agent(&guard, req, now)?;
        let parent = actor.session().expect("agent").to_string();
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
        let now = self.now();
        let (repo, actor) = Self::agent(&guard, req, now)?;
        let session = actor.session().expect("agent").to_string();
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
        let now = self.now();
        let (repo, actor) = Self::agent(&guard, req, now)?;
        let session = actor.session().expect("agent").to_string();
        let r = Self::repo(&mut guard, &repo)?;
        if !std::path::Path::new(&ev.workspace).is_absolute() {
            return fail("invalid", "workspace must be an absolute path");
        }
        let policy = r.policy().or_fail()?;
        let scratch = r
            .chain
            .state
            .sessions
            .get(&session)
            .map(|s| s.scope.scratch.clone())
            .unwrap_or_default();
        let (events, verdict) = hooks::translate(&ev, &policy, &scratch);
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
        let now = self.now();
        let (repo, actor) = Self::agent(&guard, req, now)?;
        let session = actor.session().expect("agent").to_string();
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
                        session: session.clone(),
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
        // The roots the hook program names at SessionStart: from the log,
        // never from a file the agent could edit.
        out["scratch"] = json!(
            r.chain
                .state
                .sessions
                .get(&session)
                .map(|s| s.scope.scratch.clone())
                .unwrap_or_default()
        );
        if let Some(ws) = b
            .workspace
            .filter(|w| std::path::Path::new(w).is_absolute())
        {
            let session = signed.entry.op.clone();
            if let Op::SessionBind { session, .. } = session {
                guard.workspaces.insert((repo, session), PathBuf::from(ws));
            }
        }
        Ok(out)
    }

    // ---------------------------------------------------------------- network

    /// Records an outbound connection seen by the Lonca proxy and decides
    /// whether to let it through. `cwd` is the working directory of the
    /// connecting process when it could be determined; the connection is
    /// attributed to the sessions whose workspace contains it, otherwise to
    /// every session routed through the proxy (fail closed).
    pub fn proxy_connect(&self, cwd: Option<&std::path::Path>, host: &str) -> ProxyVerdict {
        let now = self.now();
        let mut guard = self.lock();
        let inner = &mut *guard;
        let mut matched: Vec<(String, String)> = match cwd {
            Some(c) => inner
                .workspaces
                .iter()
                .filter(|(_, root)| c.starts_with(root))
                .map(|(k, _)| k.clone())
                .collect(),
            None => vec![],
        };
        let attributed = !matched.is_empty();
        if !attributed {
            for (name, r) in inner.repos.iter().filter(|(_, r)| r.initialized()) {
                let s = &r.chain.state;
                for x in s.sessions.values() {
                    if x.level == lonca_core::ops::ObservationLevel::HooksSandbox
                        && s.session_active(&x.id, now)
                    {
                        matched.push((name.clone(), x.id.clone()));
                    }
                }
            }
        }
        if matched.is_empty() {
            return ProxyVerdict {
                allow: false,
                allow_private: false,
                reason: "no Lonca session uses this proxy".into(),
            };
        }
        let mut allow = true;
        let mut allow_private = true;
        for (repo, session) in &matched {
            let Some(r) = inner.repos.get_mut(repo) else {
                continue;
            };
            let Ok(policy) = r.policy() else {
                allow = false;
                continue;
            };
            allow &= policy.config.observation.network == "taint";
            allow_private &= policy.config.observation.allow_private_network;
            let ev = lonca_core::ops::Observation {
                phase: lonca_core::ops::Phase::Pre,
                kind: lonca_core::ops::ObsKind::Fetch {
                    host: host.to_string(),
                },
                external: true,
            };
            if r.submit(
                Submission::new(
                    Actor::Daemon,
                    Op::Observe {
                        session: session.clone(),
                        events: vec![ev],
                    },
                ),
                now,
            )
            .is_err()
            {
                allow = false;
            }
        }
        let reason = if allow {
            String::new()
        } else {
            "network access is denied by repository policy".into()
        };
        drop(guard);
        self.notify_appended();
        ProxyVerdict {
            allow,
            allow_private,
            reason,
        }
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
        let before: Vec<u64> = inner
            .repos
            .values()
            .map(|r| r.chain.state.next_seq)
            .collect();
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
        let after: Vec<u64> = inner
            .repos
            .values()
            .map(|r| r.chain.state.next_seq)
            .collect();
        drop(inner);
        if before != after {
            self.notify_appended();
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
        let integ = integrate(&store, ENGINE_CURRENT, &base, &trunk, &commit)?;
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
        sub.symbols_engine = Some(ENGINE_CURRENT);
        let signed = r.submit(sub, self.now())?;
        if signed.entry.decision.is_allow()
            && let Some(m) = &integ.merged
        {
            r.store.ref_cas(TRUNK_REF, m, Some(&trunk))?;
        }
        drop(inner);
        self.notify_appended();
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

/// The files a change touches, as its facts say: added, modified and
/// deleted, sorted, each once.
fn touched_paths(f: &lonca_core::ops::Facts) -> Vec<String> {
    let mut paths: Vec<String> = f
        .added_files
        .iter()
        .chain(&f.modified_files)
        .chain(&f.deleted_files)
        .cloned()
        .collect();
    paths.sort();
    paths.dedup();
    paths
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

#[cfg(unix)]
fn set_mode(p: &std::path::Path, mode: u32) -> std::result::Result<(), (String, String)> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
        .map_err(|e| from_err(e.into()))
}

#[cfg(not(unix))]
fn set_mode(_p: &std::path::Path, _mode: u32) -> std::result::Result<(), (String, String)> {
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The rows of the method table in docs/decisions.md.
    fn documented_methods() -> BTreeMap<String, String> {
        let doc = include_str!("../../../docs/decisions.md");
        let section = doc
            .split("\n## ")
            .find(|s| s.starts_with("Daemon authentication"))
            .expect("a Daemon authentication section");
        section
            .lines()
            .filter_map(|l| l.strip_prefix("| `"))
            .map(|l| {
                let (method, rest) = l.split_once("` | ").expect("| `method` | cred |");
                let cred = rest.split(" |").next().unwrap_or_default().trim();
                (method.to_string(), cred.to_string())
            })
            .collect()
    }

    /// `docs/protocol.md` is the runner's contract: every method has a
    /// `### \`method\`` section, nothing else does, and the number it
    /// states is the one `ping` returns. The number is pinned here so a
    /// change to it is a conscious one, made with a note in the document.
    #[test]
    fn the_protocol_doc_lists_every_method_and_states_the_number() {
        let doc = include_str!("../../../docs/protocol.md");
        let sections: Vec<&str> = doc
            .lines()
            .filter_map(|l| l.strip_prefix("### `"))
            .map(|l| l.trim_end_matches('`'))
            .collect();
        for (m, _) in METHODS {
            assert!(
                sections.contains(m),
                "{m} has no section in docs/protocol.md"
            );
        }
        assert_eq!(sections.len(), METHODS.len(), "{sections:?}");
        assert_eq!(PROTOCOL, 1);
        assert!(
            doc.contains(&format!("**Protocol number: {PROTOCOL}.**")),
            "docs/protocol.md must state the current protocol number"
        );
        assert!(doc.contains(&format!("\n- **{PROTOCOL}** (")));
        assert!(doc.contains("capped at 30 000") && LOG_WAIT_MAX_MS == 30_000);
    }

    #[test]
    fn the_decisions_doc_lists_every_method_with_its_credential() {
        let documented = documented_methods();
        for (m, c) in METHODS {
            assert_eq!(
                documented.get(*m).map(String::as_str),
                Some(c.name()),
                "{m} in docs/decisions.md"
            );
        }
        assert_eq!(documented.len(), METHODS.len(), "{documented:?}");
    }

    /// Every method in the table has a handler, and nothing outside the
    /// table does. Without a token the handler is reached only by public
    /// and bootstrap methods; the rest answer `unauthenticated`.
    #[test]
    fn every_listed_method_is_dispatched_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let svc = Service::open(
            Home::new(dir.path().join("h")),
            Settings {
                managed_settings: dir.path().join("m.json"),
                require_root_settings: false,
                git: "git".into(),
            },
            Arc::new(|| 1_760_000_000_000),
        )
        .unwrap();
        let call = |method: &str, token: Option<&str>| {
            let r = svc.handle(Request {
                id: 1,
                method: method.into(),
                repo: Some("demo".into()),
                token: token.map(String::from),
                params: json!({}),
            });
            r.error.map(|e| e.code).unwrap_or_default()
        };
        for (m, cred) in METHODS {
            let code = call(m, None);
            assert_ne!(code, "unknown_method", "{m}");
            match cred {
                Cred::Public | Cred::Login | Cred::Bootstrap => {
                    assert_ne!(code, "unauthenticated", "{m}: {code}")
                }
                _ => assert_eq!(code, "unauthenticated", "{m}: {code}"),
            }
            // A token nobody issued is refused before any handler runs.
            assert_eq!(call(m, Some("lonca_nobody")), "unauthenticated", "{m}");
        }
        assert_eq!(call("admin.everything", None), "unknown_method");
        assert_eq!(call("", None), "unknown_method");
    }

    /// The session constants are what the document says; a wrong operator
    /// in one would change every session's length.
    #[test]
    fn session_constants_are_what_the_document_says() {
        assert_eq!(HUMAN_SESSION_DEFAULT_MS, 3_600_000);
        assert_eq!(HUMAN_SESSION_MAX_MS, 86_400_000);
        assert_eq!(LOGIN_NONCE_WINDOW_MS, 660_000);
        assert_eq!(LOGIN_NONCE_WINDOW_MS, MAX_AGE_MS + MAX_SKEW_MS);
    }

    #[test]
    fn every_error_keeps_its_message_under_a_stable_code() {
        let cases = [
            (Error::Invalid("a".into()), "invalid", "invalid: a"),
            (Error::Conflict("b".into()), "conflict", "conflict: b"),
            (Error::Integrity("c".into()), "integrity", "integrity: c"),
            (
                Error::Unsupported("op 3: log format 9".into()),
                "unsupported",
                "unsupported: op 3: log format 9",
            ),
            (Error::Git("d".into()), "internal", "git: d"),
            (Error::Io(std::io::Error::other("e")), "internal", "io: e"),
        ];
        for (err, code, msg) in cases {
            assert_eq!(from_err(err), (code.to_string(), msg.to_string()));
        }
        let json = serde_json::from_str::<Value>("{").unwrap_err();
        assert_eq!(from_err(Error::Json(json)).0, "internal");
    }
}
