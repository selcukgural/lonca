//! The decision function.
//!
//! `decide` is pure: its inputs are the state before the operation, the
//! request, the facts and evidence recorded with it, the time the daemon
//! assigned and the policy in force. The same inputs always produce the same
//! decision, so the auditor can replay every entry of the log.
//!
//! Order of evaluation:
//! 1. hard invariants that no policy can change (who may do what at all),
//! 2. per-operation checks (scope, leases, claim vs facts, taint, evidence),
//! 3. the Cedar policy of the repository.
//!
//! Any denial wins over escalations; escalations win over allow.

use std::collections::BTreeSet;

use lonca_core::oplog::{
    FORMAT_AFFECTED, FORMAT_ISOLATE, FORMAT_LEASE_INTENT, FORMAT_LEASE_LIVENESS,
    FORMAT_SESSION_HARNESS,
};
use lonca_core::ops::OpKind;
use lonca_core::ops::{
    Actor, Attestation, BindChecks, CheckKind, CheckResult, Continuation, Decision, ENGINE_DEFS,
    Facts, HumanKey, HumanSignature, LeaseItem, LeaseKind, MAX_UNPROPOSED_PATHS, NegotiationMsg,
    ObsKind, Observation, ObservationLevel, Op, Outcome, Scope,
};
use lonca_core::paths::{
    path_matches, path_pattern_within, symbol_matches, symbol_pattern_within,
    validate_path_pattern, validate_repo_path, validate_symbol_pattern,
};

use crate::config::{CRITICAL_ESCALATE, CVal, CedarOutcome, PolicyBundle, Quota, Verification};
use crate::state::{
    AFFECTED_LEASE, ActiveLease, ChangeStatus, HEARTBEAT_TIMEOUT, INTEREST_BLOCK, LEASES_KEPT,
    RELEASED, RESERVATION_WINDOW, Session, State,
};
use crate::symbols;

pub struct Ctx<'a> {
    /// The format of the entry: what a recorded operation means.
    pub format: u32,
    pub time_ms: i64,
    pub policy: &'a PolicyBundle,
    pub facts: Option<&'a Facts>,
    pub evidence: &'a [Attestation],
    /// The symbol engine that computed `facts`: what their names mean.
    pub symbols_engine: Option<u32>,
}

#[derive(Default)]
struct Verdict {
    deny: Vec<String>,
    escalate: Vec<String>,
    approvals: u32,
    info: Vec<String>,
}

impl Verdict {
    fn deny(&mut self, r: impl Into<String>) {
        push_unique(&mut self.deny, r.into());
    }

    fn escalate(&mut self, r: impl Into<String>, approvals: u32) {
        push_unique(&mut self.escalate, r.into());
        self.approvals = self.approvals.max(approvals);
    }

    fn cedar(&mut self, out: CedarOutcome) {
        match out {
            CedarOutcome::Allow => {}
            CedarOutcome::Deny(rs) => rs.into_iter().for_each(|r| self.deny(r)),
            CedarOutcome::Escalate { rules, approvals } => {
                rules.into_iter().for_each(|r| self.escalate(r, approvals))
            }
        }
    }

    fn finish(self, enrolled_humans: usize, cap: bool) -> Decision {
        if !self.deny.is_empty() {
            return Decision {
                outcome: Outcome::Deny,
                reasons: self.deny,
            };
        }
        if !self.escalate.is_empty() {
            let mut reasons = self.escalate;
            reasons.extend(self.info);
            let mut n = self.approvals.max(1);
            if cap && n as usize > enrolled_humans {
                n = enrolled_humans.max(1) as u32;
                reasons.push("approvals_capped".into());
            }
            reasons.push(format!("approvals={n}"));
            return Decision {
                outcome: Outcome::Escalate,
                reasons,
            };
        }
        Decision {
            outcome: Outcome::Allow,
            reasons: self.info,
        }
    }
}

fn push_unique(v: &mut Vec<String>, r: String) {
    if !v.contains(&r) {
        v.push(r);
    }
}

fn is_daemon_op(op: &Op) -> bool {
    matches!(
        op,
        Op::ChangeIntegrate { .. }
            | Op::ChangeIntegrateBatch { .. }
            | Op::Observe { .. }
            | Op::Taint { .. }
            | Op::SessionBind { .. }
            | Op::ImportUnmediated { .. }
            | Op::Freeze { .. }
    )
}

fn is_human_op(op: &Op) -> bool {
    matches!(
        op,
        Op::HumanEnroll { .. }
            | Op::HumanRotate { .. }
            | Op::HumanRevoke { .. }
            | Op::HumanRecoveryKey { .. }
            | Op::HumanRecover { .. }
            | Op::DaemonRotate { .. }
            | Op::DaemonRecover { .. }
            | Op::PolicyUpdate { .. }
            | Op::SessionStart { .. }
            | Op::SessionIsolate { .. }
            | Op::SessionEnd { .. }
            | Op::CapRevoke { .. }
            | Op::LeaseRelease { .. }
            | Op::ChangePropose { .. }
            | Op::ChangeWithdraw { .. }
            | Op::Approve { .. }
            | Op::Reject { .. }
            | Op::ImportExternal { .. }
            | Op::BridgePush { .. }
            | Op::Freeze { .. }
            | Op::Unfreeze { .. }
            | Op::Redact { .. }
    )
}

/// The human and daemon key operations. They stay possible in a frozen
/// repository: replacing or withdrawing a key is how a human answers an
/// incident, and the only way back in when the key that would unfreeze is
/// lost.
fn is_key_op(op: &Op) -> bool {
    matches!(
        op,
        Op::HumanRotate { .. }
            | Op::HumanRevoke { .. }
            | Op::HumanRecoveryKey { .. }
            | Op::HumanRecover { .. }
            | Op::DaemonRotate { .. }
            | Op::DaemonRecover { .. }
    )
}

/// What a lease request and an interest in one have in common.
fn check_lease_request(
    s: &Session,
    items: &[LeaseItem],
    intent: &str,
    ctx: &Ctx,
    keys: bool,
    v: &mut Verdict,
) {
    if items.is_empty() || items.len() > ctx.policy.config.leases.max_items {
        v.deny("lease_item_count");
    }
    if ctx.format >= FORMAT_LEASE_INTENT && intent.trim().is_empty() {
        v.deny("intent_required");
    }
    if intent.len() > 500 {
        v.deny("intent_too_long");
    }
    if items.iter().any(LeaseItem::is_shared) && !ctx.policy.config.shared_leases() {
        v.deny("shared_off");
    }
    for item in items {
        let Some((path, name)) = symbols::split(&item.symbol) else {
            v.deny(format!("invalid_symbol:{}", item.symbol));
            continue;
        };
        if validate_repo_path(path).is_err() || name.is_empty() {
            v.deny(format!("invalid_symbol:{}", item.symbol));
            continue;
        }
        if !s.scope.paths.iter().any(|p| path_matches(p, path)) {
            v.deny(format!("scope_path:{path}"));
        }
        if let Some(pats) = &s.scope.symbols {
            // Who may change a name may change every symbol of that name.
            let bare = keys.then(|| symbols::bare(&item.symbol));
            let bare = bare.as_deref().unwrap_or(name);
            let ok = if name.starts_with('<') {
                pats.iter().any(|p| p == "*")
            } else {
                pats.iter()
                    .any(|p| symbol_matches(p, name) || symbol_matches(p, bare))
            };
            if !ok {
                v.deny(format!("scope_symbol:{}", item.symbol));
            }
        }
    }
}

/// A set moves whole, while it is alive, unpinned (a pin stays with its
/// change), and only to a session whose scope covers what is in it.
fn check_handover(state: &State, own: &str, set: &str, scope: &Scope, t: i64, v: &mut Verdict) {
    let Some(l) = state.leases.get(set).filter(|l| l.session == own) else {
        v.deny("not_own_lease");
        return;
    };
    if !l.pins.is_empty() {
        v.deny("lease_pinned");
    }
    if !state.active_leases(t).any(|h| h.lease.set == set) {
        v.deny("lease_expired");
    }
    for item in &l.items {
        let path = symbols::split(&item.symbol).map(|(path, _)| path);
        let path = path.unwrap_or_default();
        if !scope.paths.iter().any(|p| path_matches(p, path)) {
            v.deny(format!("scope_path:{path}"));
        }
    }
}

fn check_yield(
    state: &State,
    own: &str,
    set: &str,
    to: Option<&str>,
    to_session: &str,
    t: i64,
    v: &mut Verdict,
) {
    let Some(to) = to else {
        if state.leases.get(set).map(|l| l.session.as_str()) != Some(own) {
            v.deny("not_own_lease");
        }
        return;
    };
    if to != to_session {
        v.deny("yield_to_another_session");
    }
    match state.sessions.get(to) {
        Some(receiver) => check_handover(state, own, set, &receiver.scope, t, v),
        None => v.deny("unknown_session"),
    }
}

/// A session can be continued once, by one successor, and only a session
/// a human started: a child's scope and lifetime are its parent's.
fn check_continuation(state: &State, c: &Continuation, scope: &Scope, v: &mut Verdict) {
    let Some(old) = state.sessions.get(&c.session) else {
        v.deny("unknown_session");
        return;
    };
    if old.parent.is_some() {
        v.deny("continue_child_session");
    }
    if old.continued_by.is_some() {
        v.deny("session_continued");
    }
    if !c.widen
        && let Err(e) = scope_within(scope, &old.scope)
    {
        v.deny(format!("scope_widening:{e}"));
    }
}

/// An Ed25519 public key as the daemon writes it: 32 bytes, lowercase hex,
/// a valid point.
pub fn valid_daemon_key(k: &str) -> bool {
    valid_human_key(&HumanKey {
        alg: "ed25519".into(),
        public: k.to_string(),
    })
}

/// A key a human can sign with: a known algorithm and a public key in the
/// form that algorithm uses (lowercase hex). Stricter than the check
/// `human.enroll` has always made, so a rotation can not lock a human out
/// with a key nothing can sign for.
pub fn valid_human_key(k: &HumanKey) -> bool {
    if k.public != k.public.to_ascii_lowercase() {
        return false;
    }
    let Ok(bytes) = hex::decode(&k.public) else {
        return false;
    };
    match k.alg.as_str() {
        "ed25519" => <[u8; 32]>::try_from(bytes.as_slice())
            .ok()
            .is_some_and(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).is_ok()),
        "p256-se" => p256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes).is_ok(),
        _ => false,
    }
}

/// Checks a key that a key operation adds.
fn check_new_key(state: &State, k: &HumanKey, v: &mut Verdict) {
    if !valid_human_key(k) {
        v.deny("invalid_key");
    } else if state.key_known(&k.public) {
        v.deny("key_reused");
    }
}

pub fn valid_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

/// Whether anything on the record came from a session or was left to it.
fn session_used(state: &State, s: &Session) -> bool {
    s.level == ObservationLevel::Isolated
        || s.heartbeat.is_some()
        || s.taint.is_some()
        || s.shell_seen
        || !s.writes.is_empty()
        || s.continued_from.is_some()
        || state.leases.values().any(|l| l.session == s.id)
        || state
            .changes
            .values()
            .any(|c| c.actor.session() == Some(s.id.as_str()))
        || state
            .sessions
            .values()
            .any(|c| c.parent.as_ref() == Some(&s.id))
}

/// A SHA-256 digest as the log writes it: 64 lowercase hex digits.
fn valid_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Observation level implied by the checks a harness hook reported.
pub fn level_for(c: &BindChecks) -> ObservationLevel {
    if !c.managed_hooks || !c.hook_binary_protected || c.sudo_without_password {
        ObservationLevel::Unobserved
    } else if c.locked_sandbox {
        ObservationLevel::HooksSandbox
    } else {
        ObservationLevel::Hooks
    }
}

/// How many scratch roots a scope may name.
pub const MAX_SCRATCH_ROOTS: usize = 8;

/// Longest reason of a `reject` (bytes): the text a worker reads.
pub const MAX_REJECT_REASON: usize = 4096;

/// A scratch root: an absolute, normalized directory path (no `..`, no
/// `.`, no empty component, no trailing slash), at most 1024 bytes, no
/// control characters.
pub fn valid_scratch_root(p: &str) -> bool {
    p.starts_with('/')
        && p.len() <= 1024
        && !p.ends_with('/')
        && !p.chars().any(char::is_control)
        && p[1..]
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != "..")
}

fn validate_scope(scope: &Scope, v: &mut Verdict) {
    if scope.paths.is_empty() {
        v.deny("scope_invalid:no_paths");
    }
    for p in &scope.paths {
        if validate_path_pattern(p).is_err() {
            v.deny(format!("scope_invalid:path:{p}"));
        }
    }
    for s in scope.symbols.iter().flatten() {
        if validate_symbol_pattern(s).is_err() {
            v.deny(format!("scope_invalid:symbol:{s}"));
        }
    }
    if scope.ops.is_empty() {
        v.deny("scope_invalid:no_ops");
    }
    if scope.scratch.len() > MAX_SCRATCH_ROOTS {
        v.deny("scope_invalid:scratch:too_many");
    }
    for s in &scope.scratch {
        if !valid_scratch_root(s) {
            v.deny(format!("scope_invalid:scratch:{s}"));
        }
    }
    for k in &scope.ops {
        if !k.agent_grantable() {
            v.deny(format!("scope_invalid:not_grantable:{}", k.as_str()));
        }
    }
}

/// Every right in `inner` is also in `outer` (capabilities only narrow).
pub fn scope_within(inner: &Scope, outer: &Scope) -> Result<(), String> {
    for p in &inner.paths {
        if !outer.paths.iter().any(|o| path_pattern_within(p, o)) {
            return Err(format!("path:{p}"));
        }
    }
    for s in &inner.scratch {
        if !outer
            .scratch
            .iter()
            .any(|o| s == o || s.starts_with(&format!("{o}/")))
        {
            return Err(format!("scratch:{s}"));
        }
    }
    match (&inner.symbols, &outer.symbols) {
        (_, None) => {}
        (None, Some(_)) => return Err("symbols:unrestricted".into()),
        (Some(i), Some(o)) => {
            for s in i {
                if !o.iter().any(|x| symbol_pattern_within(s, x)) {
                    return Err(format!("symbol:{s}"));
                }
            }
        }
    }
    for k in &inner.ops {
        if !outer.ops.contains(k) {
            return Err(format!("op:{}", k.as_str()));
        }
    }
    for (name, i, o) in [
        ("max_files", inner.max_files, outer.max_files),
        ("max_lines", inner.max_lines, outer.max_lines),
    ] {
        if let Some(o) = o
            && i.is_none_or(|i| i > o)
        {
            return Err(name.into());
        }
    }
    Ok(())
}

/// Two lease items can not be held by different sessions at the same time.
/// `shared` goes with `shared` only: against an `insert` it is an `edit`.
pub fn leases_conflict(a: &LeaseItem, b: &LeaseItem, keys: bool) -> bool {
    use LeaseKind::*;
    match (a.kind, b.kind) {
        (Insert, Insert) | (Shared, Shared) => false,
        (Insert, _) => {
            symbols::covers(&b.symbol, &a.symbol, keys)
                || (keys && symbols::stands_for(&a.symbol, &b.symbol))
        }
        (_, Insert) => {
            symbols::covers(&a.symbol, &b.symbol, keys)
                || (keys && symbols::stands_for(&b.symbol, &a.symbol))
        }
        _ => symbols::overlaps(&a.symbol, &b.symbol, keys),
    }
}

fn check_name(k: CheckKind) -> &'static str {
    match k {
        CheckKind::Syntax => "syntax",
        CheckKind::Scope => "scope",
        CheckKind::ClaimDiff => "claim_diff",
        CheckKind::Merge => "merge",
        CheckKind::Build => "build",
        CheckKind::Tests => "tests",
        CheckKind::TestIntegrity => "test_integrity",
        CheckKind::Extended => "extended",
    }
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v.dedup();
    v
}

fn session_context(state: &State, actor: &Actor, format: u32) -> Vec<(&'static str, CVal)> {
    let (tainted, level, task) = match actor.session().and_then(|s| state.sessions.get(s)) {
        Some(s) => (
            s.taint.is_some(),
            format!("{:?}", s.level).to_lowercase(),
            s.task.clone(),
        ),
        None => (false, "none".into(), String::new()),
    };
    let mut context = vec![
        ("tainted", CVal::Bool(tainted)),
        ("observation", CVal::Str(level)),
    ];
    // Old entries replay as they were: `context has task` was false.
    if format >= FORMAT_ISOLATE {
        context.push(("task", CVal::Str(task)));
    }
    context
}

pub fn decide(
    state: &State,
    actor: &Actor,
    op: &Op,
    human: Option<&HumanSignature>,
    ctx: &Ctx,
) -> Decision {
    let t = ctx.time_ms;
    let cfg = &ctx.policy.config;

    if state.next_seq == 0 {
        let Op::RepoInit {
            repo,
            human: owner,
            human_key,
            ..
        } = op
        else {
            return Decision::deny("not_initialized");
        };
        let Actor::Human { name } = actor else {
            return Decision::deny("genesis_needs_human");
        };
        if name != owner {
            return Decision::deny("genesis_actor_mismatch");
        }
        if !valid_token(repo, 64) || !valid_token(owner, 64) {
            return Decision::deny("invalid_name");
        }
        let Some(sig) = human else {
            return Decision::deny("missing_human_signature");
        };
        if let Err(e) = crate::human::verify(human_key, repo, op, sig, t) {
            return Decision::deny(e);
        }
        return Decision::allow();
    }
    if matches!(op, Op::RepoInit { .. }) {
        return Decision::deny("already_initialized");
    }
    if t < state.last_time_ms {
        return Decision::deny("time_backwards");
    }
    if let Some(reason) = &state.frozen
        && !matches!(
            op,
            Op::Unfreeze { .. } | Op::Observe { .. } | Op::Taint { .. } | Op::Freeze { .. }
        )
        && !is_key_op(op)
    {
        return Decision::deny(format!("frozen:{reason}"));
    }

    // 1. Who may request this at all.
    match actor {
        Actor::Daemon => {
            if !is_daemon_op(op) {
                return Decision::deny(format!("not_a_daemon_op:{}", op.kind().as_str()));
            }
            if human.is_some() {
                return Decision::deny("unexpected_human_signature");
            }
        }
        Actor::Human { name } => {
            let recover = matches!(op, Op::HumanRecover { .. });
            if !state.humans.contains_key(name) {
                return Decision::deny("unknown_human");
            }
            // A recovery is signed with the recovery key, everything else
            // with the human's current key.
            let key = if recover {
                state.recovery.get(name)
            } else {
                state.humans.get(name)
            };
            let Some(key) = key else {
                return Decision::deny("no_recovery_key");
            };
            let Some(sig) = human else {
                return Decision::deny("missing_human_signature");
            };
            if &sig.human != name {
                return Decision::deny("signature_human_mismatch");
            }
            if state.nonces.contains(&sig.nonce) {
                return Decision::deny("nonce_reused");
            }
            if let Err(e) = crate::human::verify(key, &state.repo, op, sig, t) {
                return Decision::deny(e);
            }
            // The recovery key is the one signature without presence: the
            // Secure Enclave key it replaces is bound to a lost machine.
            if cfg.approvals.require_presence && key.alg != "p256-se" && !recover {
                return Decision::deny("presence_required");
            }
            if !is_human_op(op) {
                return Decision::deny(format!("not_a_human_op:{}", op.kind().as_str()));
            }
        }
        Actor::Agent { name, session } => {
            if human.is_some() {
                return Decision::deny("unexpected_human_signature");
            }
            let Some(s) = state.sessions.get(session) else {
                return Decision::deny("unknown_session");
            };
            if &s.agent != name {
                return Decision::deny("session_agent_mismatch");
            }
            if !state.session_active(session, t) {
                return Decision::deny("session_inactive");
            }
            let own_lifecycle = matches!(op, Op::SessionEnd { .. } | Op::CapRevoke { .. });
            if !own_lifecycle {
                let k = op.kind();
                if !k.agent_grantable() {
                    return Decision::deny(format!("not_grantable:{}", k.as_str()));
                }
                // Waiting for a lease takes the right to acquire it.
                let k = match k {
                    OpKind::LeaseInterest => OpKind::LeaseAcquire,
                    k => k,
                };
                if !s.scope.ops.contains(&k) {
                    return Decision::deny(format!("scope_op:{}", k.as_str()));
                }
            }
        }
    }

    // 2. Per-operation checks.
    let mut v = Verdict::default();
    match op {
        Op::RepoInit { .. } => unreachable!("handled above"),
        Op::HumanEnroll { human: who, key } => {
            if !valid_token(who, 64) {
                v.deny("invalid_name");
            }
            if state.humans.contains_key(who) {
                v.deny("already_enrolled");
            }
            if !matches!(key.alg.as_str(), "ed25519" | "p256-se")
                || hex::decode(&key.public).is_err()
            {
                v.deny("invalid_key");
            }
            if state.retired_keys.contains(&key.public) {
                v.deny("key_reused");
            }
        }
        Op::HumanRotate { human: who, key }
        | Op::HumanRecoveryKey { human: who, key }
        | Op::HumanRecover { human: who, key } => {
            if actor.label() != format!("human:{who}") {
                v.deny("not_own_key");
            }
            check_new_key(state, key, &mut v);
        }
        Op::DaemonRotate { key } | Op::DaemonRecover { key } => {
            if !valid_daemon_key(key) {
                v.deny("invalid_key");
            } else if *key == state.daemon_key
                || state.retired_daemon_keys.contains(key)
                || state.key_known(key)
            {
                v.deny("key_reused");
            }
        }
        Op::HumanRevoke { human: who, reason } => {
            if !state.humans.contains_key(who) {
                v.deny("not_enrolled");
            } else if state.humans.len() == 1 {
                v.deny("last_human");
            }
            if reason.trim().is_empty() {
                v.deny("reason_required");
            }
            if reason.len() > 500 {
                v.deny("reason_too_long");
            }
        }
        Op::PolicyUpdate { .. } => {
            let n = cfg.approvals.policy_updates;
            if n > 1 {
                v.escalate("policy_update", n - 1);
            }
        }
        Op::SessionStart {
            session,
            agent,
            task,
            scope,
            expires_ms,
            continues,
            harness,
            ..
        } => {
            if !valid_token(session, 64) || !valid_token(agent, 64) {
                v.deny("invalid_name");
            }
            if harness.as_ref().is_some_and(|h| !valid_token(h, 64)) {
                v.deny("invalid_harness");
            }
            if state.sessions.contains_key(session) {
                v.deny("session_exists");
            }
            if task.len() > 200 {
                v.deny("task_too_long");
            }
            validate_scope(scope, &mut v);
            if *expires_ms <= t || *expires_ms - t > cfg.sessions.max_ttl_minutes * 60_000 {
                v.deny("session_ttl");
            }
            if let Some(c) = continues {
                check_continuation(state, c, scope, &mut v);
            }
        }
        Op::SessionBind {
            session,
            checks,
            level,
        } => {
            if !state.session_active(session, t) {
                v.deny("session_inactive");
            }
            if *level != level_for(checks) {
                v.deny("bind_level_mismatch");
            }
            let s = state.sessions.get(session);
            // A hook in a sandbox must not take the session's level from it.
            if s.is_some_and(|s| s.level == ObservationLevel::Isolated) {
                v.deny("session_isolated");
            }
            if ctx.format >= FORMAT_SESSION_HARNESS {
                // A level is read for the harness a human named, and whoever
                // asks has a token: the checks must be for that harness.
                let named = s.and_then(|s| s.harness.as_ref());
                if *level > ObservationLevel::Unobserved && named != Some(&checks.harness) {
                    v.deny("bind_other_harness");
                }
                // The first report is the hook's, before the agent has run.
                if s.is_some_and(|s| s.bound && *level > s.level) {
                    v.deny("bind_raises_level");
                }
            }
        }
        Op::SessionIsolate {
            session,
            sandbox,
            profile,
        } => {
            match state.sessions.get(session) {
                None => v.deny("unknown_session"),
                // A sandbox is vouched for by the one who started what runs
                // in it; a child takes its level from its parent.
                Some(s) if s.parent.is_some() => v.deny("session_is_a_child"),
                Some(s) if !matches!(actor, Actor::Human { name } if *name == s.root_human) => {
                    v.deny("not_own_session")
                }
                // Whatever this session did so far was done outside.
                Some(s) if session_used(state, s) => v.deny("session_used"),
                Some(_) => {}
            }
            if !state.session_active(session, t) {
                v.deny("session_inactive");
            }
            if !valid_token(sandbox, 32) || sandbox == "none" {
                v.deny("invalid_sandbox");
            }
            if !valid_digest(profile) {
                v.deny("invalid_profile");
            }
        }
        Op::SessionEnd { session, .. } | Op::CapRevoke { session, .. } => {
            match state.sessions.get(session) {
                None => v.deny("unknown_session"),
                Some(s) if s.ended.is_some() && matches!(op, Op::SessionEnd { .. }) => {
                    v.deny("session_ended")
                }
                Some(_) => {}
            }
            if let Some(own) = actor.session()
                && !state.descends_from(session, own)
            {
                v.deny("not_own_session");
            }
        }
        Op::CapAttenuate {
            parent,
            child,
            agent,
            scope,
            expires_ms,
            leases,
        } => {
            let own = actor.session().unwrap_or_default();
            if parent != own {
                v.deny("not_own_session");
            }
            for set in leases {
                check_handover(state, own, set, scope, t, &mut v);
            }
            if !valid_token(child, 64) || !valid_token(agent, 64) {
                v.deny("invalid_name");
            }
            if state.sessions.contains_key(child) {
                v.deny("session_exists");
            }
            validate_scope(scope, &mut v);
            if let Some(p) = state.sessions.get(parent) {
                if let Err(e) = scope_within(scope, &p.scope) {
                    v.deny(format!("scope_widening:{e}"));
                }
                if *expires_ms > p.expires_ms || *expires_ms <= t {
                    v.deny("session_ttl");
                }
            }
        }
        Op::LeaseAcquire {
            set,
            items,
            intent,
            ttl_ms,
        } => {
            let own = actor.session().unwrap_or_default();
            let s = &state.sessions[own];
            if !valid_token(set, 64) || state.leases.contains_key(set) {
                v.deny("invalid_lease_set");
            }
            if *ttl_ms <= 0 || *ttl_ms > cfg.leases.max_ttl_minutes * 60_000 {
                v.deny("lease_ttl");
            }
            check_lease_request(s, items, intent, ctx, state.symbol_keys, &mut v);
            if let Some(holder) = state.reserved_against(own, items, t) {
                v.deny(format!("lease_reserved:{holder}"));
            }
            for i in state.wanted_against(own, items, t) {
                v.deny(format!("lease_wanted:{}", i.session));
            }
            for held in state.active_leases(t) {
                if held.lease.session == own {
                    continue;
                }
                for a in items {
                    for b in &held.items {
                        if state.conflict(a, b) {
                            v.deny(format!(
                                "lease_held:{}:{}:{}",
                                b.symbol, held.lease.session, held.lease.intent
                            ));
                        }
                    }
                }
            }
        }
        Op::LeaseInterest { items, intent } => {
            let own = actor.session().unwrap_or_default();
            check_lease_request(
                &state.sessions[own],
                items,
                intent,
                ctx,
                state.symbol_keys,
                &mut v,
            );
            // Nothing to wait for means nothing to hold: an interest in a
            // free symbol would be a way to reserve it.
            if !state.taken(own, items, t) {
                v.deny("lease_free");
            }
            if state.waiting(own, items) {
                v.deny("interest_exists");
            }
            v.info
                .push(format!("{RESERVATION_WINDOW}{}", cfg.leases.reservation_ms));
            if ctx.format >= FORMAT_LEASE_INTENT {
                v.info
                    .push(format!("{INTEREST_BLOCK}{}", cfg.leases.interest_block_ms));
            }
        }
        Op::LeaseRelease { set } => match state.leases.get(set) {
            None => v.deny("unknown_lease_set"),
            Some(l) => {
                if let Some(own) = actor.session()
                    && !state.descends_from(&l.session, own)
                {
                    v.deny("not_own_lease");
                }
            }
        },
        Op::LeaseRenew { set, ttl_ms } => match state.leases.get(set) {
            None => v.deny("unknown_lease_set"),
            Some(l) => {
                let liveness = ctx.format >= FORMAT_LEASE_LIVENESS;
                if Some(l.session.as_str()) != actor.session() {
                    v.deny("not_own_lease");
                }
                if l.expires_ms <= t || (liveness && state.session_lost(&l.session, t)) {
                    v.deny("lease_expired");
                }
                if *ttl_ms <= 0 || *ttl_ms > cfg.leases.max_ttl_minutes * 60_000 {
                    v.deny("lease_ttl");
                }
                // Interest is a denied acquire, retried at least as often
                // as the longest TTL.
                if liveness
                    && t - l.acquired_ms >= cfg.leases.max_hold_minutes * 60_000
                    && state.contended(l, t, cfg.leases.max_ttl_minutes * 60_000)
                {
                    v.deny("lease_hold_limit");
                }
            }
        },
        Op::ChangePropose {
            change,
            base,
            claim,
            ..
        } => propose(state, actor, *change, base, claim, ctx, &mut v),
        Op::ChangeWithdraw { change } => match state.changes.get(change) {
            None => v.deny("unknown_change"),
            Some(c) => {
                if !matches!(
                    c.status,
                    ChangeStatus::Queued | ChangeStatus::Pending { .. }
                ) {
                    v.deny("change_not_in_flight");
                }
                if let Some(own) = actor.session()
                    && !c
                        .actor
                        .session()
                        .is_some_and(|s| state.descends_from(s, own) || state.continues(own, s))
                {
                    v.deny("not_own_change");
                }
            }
        },
        Op::ChangeIntegrate {
            change,
            trunk_before,
            merged,
            conflicts,
        } => {
            match state.changes.get(change) {
                None => v.deny("unknown_change"),
                Some(c) if c.status != ChangeStatus::Queued => v.deny("change_not_queued"),
                Some(_) => {}
            }
            if state.queue.first() != Some(change) {
                v.deny("not_queue_head");
            }
            if state.trunk.as_ref() != Some(trunk_before) {
                v.deny("stale_trunk");
            }
            match merged {
                None => {
                    v.deny("merge_conflict");
                    for c in conflicts {
                        v.deny(format!("conflict:{c}"));
                    }
                }
                Some(_) => {
                    if !conflicts.is_empty() {
                        v.deny("conflicts_with_merge");
                    }
                    verify_evidence(state, [change], ctx, &mut v);
                    check_quota(state, [change], ctx, &mut v);
                    // `State::apply` has no policy: the switch travels in
                    // the decision.
                    if !cfg.leases.release_on_integrate {
                        v.info.push(LEASES_KEPT.into());
                    }
                }
            }
        }
        Op::ChangeIntegrateBatch {
            trunk_before,
            merged,
        } => {
            let size = cfg.queue.batch_size as usize;
            if merged.len() < 2 || merged.len() > size {
                v.deny("batch_size");
            }
            let changes = merged.iter().map(|(change, _)| change);
            if !changes.eq(state.queue.iter().take(merged.len())) {
                v.deny("not_queue_head");
            }
            if state.trunk.as_ref() != Some(trunk_before) {
                v.deny("stale_trunk");
            }
            let changes = merged.iter().map(|(change, _)| change);
            verify_evidence(state, changes, ctx, &mut v);
            let changes = merged.iter().map(|(change, _)| change);
            check_quota(state, changes, ctx, &mut v);
            if !cfg.leases.release_on_integrate {
                v.info.push(LEASES_KEPT.into());
            }
        }
        Op::Approve { target_seq, note } => match state.pending.get(target_seq) {
            None => v.deny("nothing_pending"),
            Some(p) => {
                if let Actor::Human { name } = actor
                    && p.approvals.contains(name)
                {
                    v.deny("already_approved");
                }
                if note.len() > 500 {
                    v.deny("note_too_long");
                }
                if p.approvals.len() as u32 + 1 >= p.required {
                    v.info.push(RELEASED.into());
                    // A released key operation takes effect now: recheck
                    // what may have changed since it was requested.
                    match &p.op {
                        Op::HumanRevoke { human: who, .. }
                            if state.humans.len() == 1 && state.humans.contains_key(who) =>
                        {
                            v.deny("last_human")
                        }
                        Op::HumanRotate { key, .. }
                        | Op::HumanRecoveryKey { key, .. }
                        | Op::HumanRecover { key, .. }
                            if state.key_known(&key.public) =>
                        {
                            v.deny("key_reused")
                        }
                        _ => {}
                    }
                }
            }
        },
        Op::Reject { target_seq, reason } => {
            if !state.pending.contains_key(target_seq) {
                v.deny("nothing_pending");
            }
            if reason.trim().is_empty() {
                v.deny("reason_required");
            }
            if reason.len() > MAX_REJECT_REASON {
                v.deny("reason_too_long");
            }
        }
        Op::Observe { session, events } => {
            if !state.sessions.contains_key(session) {
                v.deny("unknown_session");
            }
            if events.len() > 256 {
                v.deny("too_many_events");
            }
            let listed = |e: &Observation| match &e.kind {
                ObsKind::Unproposed { paths, .. } => paths.len(),
                _ => 0,
            };
            if events.iter().map(listed).any(|n| n > MAX_UNPROPOSED_PATHS) {
                v.deny("too_many_events");
            }
            // `State::apply` has no policy: the timeout travels in the
            // decision and the auditor recomputes it.
            if ctx.format >= FORMAT_LEASE_LIVENESS
                && events.iter().any(|e| e.kind == ObsKind::Heartbeat)
            {
                let timeout = cfg.leases.heartbeat_timeout_ms;
                v.info.push(format!("{HEARTBEAT_TIMEOUT}{timeout}"));
            }
        }
        Op::Taint { session, .. } => {
            if !state.sessions.contains_key(session) {
                v.deny("unknown_session");
            }
        }
        Op::ImportExternal { trunk_before, .. } => {
            if state.trunk.as_ref() != Some(trunk_before) {
                v.deny("stale_trunk");
            }
        }
        Op::ImportUnmediated { .. } | Op::Freeze { .. } => {}
        Op::Unfreeze { .. } => {
            if state.frozen.is_none() {
                v.deny("not_frozen");
            }
        }
        Op::BridgePush {
            oplog_seq,
            oplog_hash,
            ..
        } => {
            if *oplog_seq + 1 != state.next_seq || *oplog_hash != state.head_hash {
                v.deny("stale_anchor");
            }
        }
        Op::Negotiate {
            thread,
            to_session,
            message,
        } => {
            let own = actor.session().unwrap_or_default();
            if to_session == own || !state.session_active(to_session, t) {
                v.deny("invalid_counterparty");
            }
            match state.threads.get(thread) {
                Some(th) => {
                    let pair = [th.a.as_str(), th.b.as_str()];
                    if !(pair.contains(&own) && pair.contains(&to_session.as_str())) {
                        v.deny("not_thread_participant");
                    }
                    if th.closed {
                        v.deny("thread_closed");
                    }
                    if th.rounds >= cfg.negotiation.max_rounds {
                        v.deny("negotiation_exhausted");
                    }
                }
                None => {
                    if !valid_token(thread, 64) {
                        v.deny("invalid_name");
                    }
                }
            }
            if let NegotiationMsg::Yield { set, to } = message {
                check_yield(state, own, set, to.as_deref(), to_session, t, &mut v);
            }
        }
        Op::Redact { blob, reason } => {
            if state.redacted.contains(blob) {
                v.deny("already_redacted");
            }
            if reason.trim().is_empty() {
                v.deny("reason_required");
            }
        }
    }

    // 3. Repository policy. Changes are evaluated per file inside `propose`.
    if !matches!(actor, Actor::Daemon) && !matches!(op, Op::ChangePropose { .. }) {
        let ctxv = session_context(state, actor, ctx.format);
        v.cedar(ctx.policy.evaluate(actor, op.kind().as_str(), ctxv));
    }
    // A daemon key switch can not wait for approval: a recovery is signed
    // by the new key, so it can not sit in the log as pending while the old
    // key signs on, and a rotation follows the same rule.
    if op.daemon_key_switch().is_some() {
        for r in std::mem::take(&mut v.escalate) {
            v.deny(format!("not_escalatable:{r}"));
        }
    }
    v.finish(state.humans.len(), cfg.approvals.cap_to_enrolled_humans)
}

fn verify_evidence<'a>(
    state: &State,
    changes: impl IntoIterator<Item = &'a lonca_core::ChangeId>,
    ctx: &Ctx,
    v: &mut Verdict,
) {
    let mut records = changes.into_iter().filter_map(|c| state.changes.get(c));
    let reaches = records.any(|c| c.facts.reaches_others());
    let owed = ctx.policy.config.verification.for_change(reaches);
    for problem in evidence_problems(&owed, ctx.evidence) {
        v.deny(problem);
    }
}

fn check_quota<'a>(
    state: &State,
    changes: impl IntoIterator<Item = &'a lonca_core::ChangeId>,
    ctx: &Ctx,
    v: &mut Verdict,
) {
    for c in changes.into_iter().filter_map(|c| state.changes.get(c)) {
        let quota = &ctx.policy.config.quota;
        for problem in quota_problems(state, &c.actor, ctx.time_ms, quota) {
            v.deny(problem);
        }
    }
}

/// The quotas `actor` is past at `time_ms`. Also what the daemon asks before
/// it starts a verification: what is past a quota is not run.
pub fn quota_problems(state: &State, actor: &Actor, time_ms: i64, quota: &Quota) -> Vec<String> {
    let past = |limit: u64, spent: u64| limit > 0 && spent >= limit.saturating_mul(1000);
    let mut problems = Vec::new();
    if let Some(session) = actor.session()
        && past(quota.session_seconds, state.session_spent(session))
    {
        problems.push("verification_quota:session".to_string());
    }
    if past(quota.day_seconds, state.day_spent(time_ms)) {
        problems.push("verification_quota:day".to_string());
    }
    problems
}

/// What is wrong with `evidence` under `vc`. Also what the daemon asks before
/// it logs a batch, so that a batch that would be denied is split instead.
pub fn evidence_problems(vc: &Verification, evidence: &[Attestation]) -> Vec<String> {
    let mut problems = Vec::new();
    for a in evidence {
        match a.result {
            CheckResult::Fail => {
                problems.push(format!("verification_failed:{}", check_name(a.check)))
            }
            CheckResult::Error => {
                problems.push(format!("verification_error:{}", check_name(a.check)))
            }
            CheckResult::Pass | CheckResult::Skipped => {}
        }
        if vc.require_sandbox
            && matches!(
                a.check,
                CheckKind::Build | CheckKind::Tests | CheckKind::Extended
            )
            && a.details.get("sandbox").is_none_or(|s| s == "none")
        {
            problems.push("unsandboxed_verification".to_string());
        }
    }
    if vc.required {
        let passed = |k: CheckKind| {
            let mut all = evidence.iter();
            all.any(|a| a.check == k && a.result == CheckResult::Pass)
        };
        if vc.build.is_some() && !passed(CheckKind::Build) {
            problems.push("verification_missing:build".to_string());
        }
        if vc.test.is_some() && !passed(CheckKind::Tests) {
            problems.push("verification_missing:tests".to_string());
        }
        if vc.on_signature_change.is_some() && !passed(CheckKind::Extended) {
            problems.push("verification_missing:extended".to_string());
        }
    }
    problems
}

/// The lease sets of other sessions that hold what `f` lists as affected, as
/// (session, set). `Insert` holds no code. A lease may have the name trunk
/// has now, and `f` the one its base had.
fn affected_holders(
    state: &State,
    actor: &Actor,
    f: &Facts,
    base: &lonca_core::GitId,
    t: i64,
) -> Vec<(String, String)> {
    let keys = state.symbol_keys;
    let reaches = |item: &&LeaseItem| {
        let met = |a: &String| {
            symbols::overlaps(&item.symbol, a, keys)
                || symbols::overlaps(&item.symbol, &state.renamed_to(a, Some(base)), keys)
        };
        item.kind != LeaseKind::Insert && f.affected.iter().any(met)
    };
    let own = |l: &ActiveLease| {
        let me = actor.session();
        me.is_some_and(|s| state.continues(s, &l.lease.session))
    };
    let held = state.active_leases(t).filter(|l| !own(l));
    let held = held.filter(|l| l.items.iter().copied().any(|i| reaches(&i)));
    held.map(|l| (l.lease.session.clone(), l.lease.set.clone()))
        .collect()
}

fn propose(
    state: &State,
    actor: &Actor,
    change: lonca_core::ChangeId,
    base: &lonca_core::GitId,
    claim: &lonca_core::ops::Claim,
    ctx: &Ctx,
    v: &mut Verdict,
) {
    let t = ctx.time_ms;
    let policy = ctx.policy;
    let cfg = &policy.config;
    let Some(f) = ctx.facts else {
        v.deny("missing_facts");
        return;
    };
    for problem in quota_problems(state, actor, t, &cfg.quota) {
        v.deny(problem);
    }
    if !state.trunk_history.contains(base) {
        v.deny("unknown_base");
    }
    if let Some(existing) = state.changes.get(&change) {
        match existing.status {
            ChangeStatus::Conflicted { .. }
            | ChangeStatus::Rejected { .. }
            | ChangeStatus::Withdrawn => {
                if existing.actor.label() != actor.label() {
                    v.deny("change_owned_by_other");
                }
            }
            _ => v.deny("change_in_flight"),
        }
    }
    for (name, claimed, actual) in [
        ("edits", &claim.edits, &f.edits),
        ("adds", &claim.adds, &f.adds),
        ("deletes", &claim.deletes, &f.deletes),
        ("deleted_files", &claim.deleted_files, &f.deleted_files),
        (
            "signature_changes",
            &claim.signature_changes,
            &f.signature_changes,
        ),
    ] {
        if sorted(claimed) != sorted(actual) {
            v.deny(format!("claim_mismatch:{name}"));
        }
    }
    if claim.tests != f.tests {
        v.deny("claim_mismatch:tests");
    }
    if let Some(r) = claim.revert_of
        && !state.changes.contains_key(&r)
    {
        v.deny("unknown_revert_target");
    }
    let files: BTreeSet<&String> = f
        .added_files
        .iter()
        .chain(&f.modified_files)
        .chain(&f.deleted_files)
        .collect();
    if files.is_empty() {
        v.deny("empty_change");
    }
    if files.len() > cfg.changes.max_files as usize {
        v.deny("too_many_files");
    }
    let critical: Vec<&String> = files
        .iter()
        .copied()
        .filter(|p| policy.is_critical(p))
        .collect();

    match actor {
        Actor::Daemon => v.deny("not_a_daemon_op:change.propose"),
        Actor::Human { .. } => {}
        Actor::Agent { session, .. } => {
            let s = &state.sessions[session];
            for p in &files {
                if !s.scope.paths.iter().any(|pat| path_matches(pat, p)) {
                    v.deny(format!("scope_path:{p}"));
                }
            }
            if s.scope.max_files.is_some_and(|m| files.len() > m as usize) {
                v.deny("scope_max_files");
            }
            if s.scope
                .max_lines
                .is_some_and(|m| f.lines_added + f.lines_removed > m)
            {
                v.deny("scope_max_lines");
            }
            let touched: BTreeSet<&String> = f
                .edits
                .iter()
                .chain(&f.adds)
                .chain(&f.deletes)
                .chain(&f.signature_changes)
                .collect();
            if let Some(pats) = &s.scope.symbols {
                for sym in &touched {
                    let name = symbols::split(sym).map(|(_, n)| n).unwrap_or(sym);
                    // Who may change a type's own text keeps that right
                    // now that facts call it `Type.<def>`. `Type.*`, the
                    // members, did not reach it and does not.
                    let defs = ctx.symbols_engine.is_some_and(|v| v >= ENGINE_DEFS);
                    let of = symbols::def_of(name).filter(|_| defs);
                    let of = of.unwrap_or(name);
                    let bare = state.symbol_keys.then(|| symbols::bare(sym));
                    let bare = bare.as_deref();
                    let bare = bare.map(|b| symbols::def_of(b).filter(|_| defs).unwrap_or(b));
                    let bare = bare.unwrap_or(of);
                    let ok = if name.starts_with('<') {
                        pats.iter().any(|p| p == "*")
                    } else {
                        pats.iter()
                            .any(|p| p == name || symbol_matches(p, of) || symbol_matches(p, bare))
                    };
                    if !ok {
                        v.deny(format!("scope_symbol:{sym}"));
                    }
                }
            }

            let held: Vec<ActiveLease> = state
                .active_leases(t)
                .filter(|l| l.lease.session == *session)
                .collect();
            let mine: Vec<&LeaseItem> = held.iter().flat_map(|l| l.items.iter().copied()).collect();
            for need in symbols::lease_needs_under(f, cfg.leases.unparsed_files) {
                if !mine.iter().any(|l| state.covers_need(&need, l, Some(base))) {
                    v.deny(format!("lease_missing:{}", need.symbol));
                }
            }

            let unobserved =
                s.level == ObservationLevel::Unobserved && cfg.observation.unobserved_is_tainted;
            if s.taint.is_some() || unobserved {
                // Each state answers for itself: opening one word leaves a
                // session in the other state refused. Only the known word
                // opens; `PolicyBundle::parse` refuses any other.
                let open = |word: &str| word == CRITICAL_ESCALATE;
                if !critical.is_empty() {
                    if s.taint.is_some() && !open(&cfg.taint.critical) {
                        v.deny("tainted_critical_path");
                    } else if unobserved && !open(&cfg.observation.unobserved_critical) {
                        v.deny("unobserved_critical_path");
                    }
                }
                v.escalate(
                    if s.taint.is_some() {
                        "tainted_session"
                    } else {
                        "unobserved_session"
                    },
                    1,
                );
            }
            for p in &critical {
                v.escalate(format!("critical_path:{p}"), 1);
            }
            if f.tests.deleted > 0 || f.tests.skipped > 0 {
                v.escalate("tests_weakened", 1);
            }
            for p in &f.unread_files {
                v.escalate(format!("unread_file:{p}"), 1);
            }
            // Observation/effect consistency: a file the session changed but
            // never wrote through an observed tool, with no shell activity
            // that could explain it.
            // In a sandbox nothing reports tool calls: the workspace against
            // its base is what happened.
            if matches!(
                s.level,
                ObservationLevel::Hooks | ObservationLevel::HooksSandbox
            ) && !s.shell_seen
            {
                for p in &files {
                    if !s.writes.contains(*p) {
                        v.escalate(format!("unobserved_write:{p}"), 1);
                    }
                }
            }
        }
    }

    let mut base_ctx = session_context(state, actor, ctx.format);
    for (action, list) in [
        ("file.add", &f.added_files),
        ("file.modify", &f.modified_files),
        ("file.delete", &f.deleted_files),
    ] {
        for p in list {
            let mut c = base_ctx.clone();
            c.push(("path", CVal::Str(p.clone())));
            v.cedar(policy.evaluate(actor, action, c));
        }
    }
    let window = cfg.reverts.window_minutes * 60_000;
    let mine: BTreeSet<&String> = f.edits.iter().chain(&f.deletes).chain(&f.adds).collect();
    // A revert of `Name` is one of `Name(key)`, and the other way around,
    // and it follows the symbol to its new name.
    let reverted = |s: &String| {
        let same = |s: &String| {
            mine.contains(s)
                || (state.symbol_keys
                    && mine
                        .iter()
                        .any(|m| symbols::stands_for(s, m) || symbols::stands_for(m, s)))
        };
        same(s) || same(&state.renamed_to(s, None))
    };
    let recent_reverts = state
        .reverts
        .iter()
        .filter(|(at, syms)| t - at <= window && syms.iter().any(reverted))
        .count() as i64;
    // A policy names a symbol as a person does: by its name, too.
    let bare_ids = mine.iter().filter(|_| state.symbol_keys).filter_map(|s| {
        let (path, _) = symbols::split(s)?;
        Some(format!("{path}#{}", symbols::bare(s)))
    });
    let named: BTreeSet<String> = bare_ids.chain(mine.iter().map(|s| s.to_string())).collect();
    if ctx.format >= FORMAT_AFFECTED {
        let held = affected_holders(state, actor, f, base, t);
        let changed = f.signature_changes.iter();
        v.info
            .extend(changed.map(|s| format!("signature_change:{s}")));
        let sets = held.iter();
        v.info
            .extend(sets.map(|(s, set)| format!("{AFFECTED_LEASE}{s}:{set}")));
        if f.affected_more > 0 {
            v.info.push(format!("affected_more:{}", f.affected_more));
        }
        base_ctx.extend([
            (
                "signature_changes",
                CVal::Long(f.signature_changes.len() as i64),
            ),
            (
                "affects_others",
                CVal::Bool(!held.is_empty() || f.affected_more > 0),
            ),
        ]);
    }
    base_ctx.extend([
        ("files", CVal::Long(files.len() as i64)),
        (
            "lines",
            CVal::Long((f.lines_added + f.lines_removed) as i64),
        ),
        ("recent_reverts", CVal::Long(recent_reverts)),
        ("is_revert", CVal::Bool(claim.revert_of.is_some())),
        ("tests_deleted", CVal::Long(f.tests.deleted as i64)),
        ("tests_skipped", CVal::Long(f.tests.skipped as i64)),
        ("critical", CVal::Bool(!critical.is_empty())),
        ("symbols", CVal::StrSet(named.into_iter().collect())),
    ]);
    v.cedar(policy.evaluate(actor, "change.propose", base_ctx));
}
