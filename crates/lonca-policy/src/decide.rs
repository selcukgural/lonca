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

use lonca_core::ops::{
    Actor, Attestation, BindChecks, CheckKind, CheckResult, Decision, Facts, HumanSignature,
    LeaseItem, LeaseKind, NegotiationMsg, ObservationLevel, Op, Outcome, Scope,
};
use lonca_core::paths::{
    path_matches, path_pattern_within, symbol_matches, symbol_pattern_within,
    validate_path_pattern, validate_repo_path, validate_symbol_pattern,
};

use crate::config::{CVal, CedarOutcome, PolicyBundle};
use crate::state::{ChangeStatus, RELEASED, State};
use crate::symbols;

pub struct Ctx<'a> {
    pub time_ms: i64,
    pub policy: &'a PolicyBundle,
    pub facts: Option<&'a Facts>,
    pub evidence: &'a [Attestation],
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
            | Op::PolicyUpdate { .. }
            | Op::SessionStart { .. }
            | Op::SessionEnd { .. }
            | Op::CapRevoke { .. }
            | Op::LeaseRelease { .. }
            | Op::ChangePropose { .. }
            | Op::ChangeWithdraw { .. }
            | Op::Approve { .. }
            | Op::ImportExternal { .. }
            | Op::BridgePush { .. }
            | Op::Freeze { .. }
            | Op::Unfreeze { .. }
            | Op::Redact { .. }
    )
}

pub fn valid_token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
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
pub fn leases_conflict(a: &LeaseItem, b: &LeaseItem) -> bool {
    use LeaseKind::*;
    match (a.kind, b.kind) {
        (Insert, Insert) => false,
        (Insert, _) => symbols::covers(&b.symbol, &a.symbol),
        (_, Insert) => symbols::covers(&a.symbol, &b.symbol),
        _ => symbols::overlaps(&a.symbol, &b.symbol),
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
    }
}

fn sorted(v: &[String]) -> Vec<String> {
    let mut v = v.to_vec();
    v.sort();
    v.dedup();
    v
}

fn session_context(state: &State, actor: &Actor) -> Vec<(&'static str, CVal)> {
    let (tainted, level) = match actor.session().and_then(|s| state.sessions.get(s)) {
        Some(s) => (s.taint.is_some(), format!("{:?}", s.level).to_lowercase()),
        None => (false, "none".into()),
    };
    vec![
        ("tainted", CVal::Bool(tainted)),
        ("observation", CVal::Str(level)),
    ]
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
            let Some(key) = state.humans.get(name) else {
                return Decision::deny("unknown_human");
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
            ..
        } => {
            if !valid_token(session, 64) || !valid_token(agent, 64) {
                v.deny("invalid_name");
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
        } => {
            let own = actor.session().unwrap_or_default();
            if parent != own {
                v.deny("not_own_session");
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
            if items.is_empty() || items.len() > cfg.leases.max_items {
                v.deny("lease_item_count");
            }
            if *ttl_ms <= 0 || *ttl_ms > cfg.leases.max_ttl_minutes * 60_000 {
                v.deny("lease_ttl");
            }
            if intent.len() > 500 {
                v.deny("intent_too_long");
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
                    let ok = if name.starts_with('<') {
                        pats.iter().any(|p| p == "*")
                    } else {
                        pats.iter().any(|p| symbol_matches(p, name))
                    };
                    if !ok {
                        v.deny(format!("scope_symbol:{}", item.symbol));
                    }
                }
            }
            for held in state.active_leases(t).filter(|l| l.session != own) {
                for a in items {
                    for b in &held.items {
                        if leases_conflict(a, b) {
                            v.deny(format!(
                                "lease_held:{}:{}:{}",
                                b.symbol, held.session, held.intent
                            ));
                        }
                    }
                }
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
                if Some(l.session.as_str()) != actor.session() {
                    v.deny("not_own_lease");
                }
                if l.expires_ms <= t {
                    v.deny("lease_expired");
                }
                if *ttl_ms <= 0 || *ttl_ms > cfg.leases.max_ttl_minutes * 60_000 {
                    v.deny("lease_ttl");
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
                        .is_some_and(|s| state.descends_from(s, own))
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
                    verify_evidence(ctx, &mut v);
                }
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
                }
            }
        },
        Op::Observe { session, events } => {
            if !state.sessions.contains_key(session) {
                v.deny("unknown_session");
            }
            if events.len() > 256 {
                v.deny("too_many_events");
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
            if let NegotiationMsg::Yield { set } = message
                && state.leases.get(set).map(|l| l.session.as_str()) != Some(own)
            {
                v.deny("not_own_lease");
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
        let ctxv = session_context(state, actor);
        v.cedar(ctx.policy.evaluate(actor, op.kind().as_str(), ctxv));
    }
    v.finish(state.humans.len(), cfg.approvals.cap_to_enrolled_humans)
}

fn verify_evidence(ctx: &Ctx, v: &mut Verdict) {
    let vc = &ctx.policy.config.verification;
    for a in ctx.evidence {
        match a.result {
            CheckResult::Fail => v.deny(format!("verification_failed:{}", check_name(a.check))),
            CheckResult::Error => v.deny(format!("verification_error:{}", check_name(a.check))),
            CheckResult::Pass | CheckResult::Skipped => {}
        }
        if vc.require_sandbox
            && matches!(a.check, CheckKind::Build | CheckKind::Tests)
            && a.details.get("sandbox").is_none_or(|s| s == "none")
        {
            v.deny("unsandboxed_verification");
        }
    }
    if vc.required {
        let passed = |k: CheckKind| {
            ctx.evidence
                .iter()
                .any(|a| a.check == k && a.result == CheckResult::Pass)
        };
        if vc.build.is_some() && !passed(CheckKind::Build) {
            v.deny("verification_missing:build");
        }
        if vc.test.is_some() && !passed(CheckKind::Tests) {
            v.deny("verification_missing:tests");
        }
    }
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
                    let ok = if name.starts_with('<') {
                        pats.iter().any(|p| p == "*")
                    } else {
                        pats.iter().any(|p| symbol_matches(p, name))
                    };
                    if !ok {
                        v.deny(format!("scope_symbol:{sym}"));
                    }
                }
            }

            let mine: Vec<&LeaseItem> = state
                .active_leases(t)
                .filter(|l| l.session == *session)
                .flat_map(|l| l.items.iter())
                .collect();
            let held = |kinds: &[LeaseKind], sym: &str| {
                mine.iter()
                    .any(|l| kinds.contains(&l.kind) && symbols::covers(&l.symbol, sym))
            };
            for sym in f.edits.iter().chain(&f.signature_changes) {
                if !held(&[LeaseKind::Edit, LeaseKind::Rename], sym) {
                    v.deny(format!("lease_missing:{sym}"));
                }
            }
            for sym in &f.deletes {
                if !held(&[LeaseKind::Rename], sym) {
                    v.deny(format!("lease_missing:{sym}"));
                }
            }
            for sym in &f.adds {
                let Some(c) = symbols::container(sym) else {
                    continue;
                };
                if !held(&[LeaseKind::Insert, LeaseKind::Edit, LeaseKind::Rename], &c) {
                    v.deny(format!("lease_missing:{c}"));
                }
            }
            for p in &f.deleted_files {
                if !held(&[LeaseKind::Rename], &symbols::file_symbol(p)) {
                    v.deny(format!("lease_missing:{}", symbols::file_symbol(p)));
                }
            }

            let unobserved =
                s.level == ObservationLevel::Unobserved && cfg.observation.unobserved_is_tainted;
            if s.taint.is_some() || unobserved {
                if !critical.is_empty() {
                    v.deny(if s.taint.is_some() {
                        "tainted_critical_path"
                    } else {
                        "unobserved_critical_path"
                    });
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
            // Observation/effect consistency: a file the session changed but
            // never wrote through an observed tool, with no shell activity
            // that could explain it.
            if s.level >= ObservationLevel::Hooks && !s.shell_seen {
                for p in &files {
                    if !s.writes.contains(*p) {
                        v.escalate(format!("unobserved_write:{p}"), 1);
                    }
                }
            }
        }
    }

    let mut base_ctx = session_context(state, actor);
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
    let recent_reverts = state
        .reverts
        .iter()
        .filter(|(at, syms)| t - at <= window && syms.iter().any(|s| mine.contains(s)))
        .count() as i64;
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
        ("symbols", CVal::StrSet(mine.into_iter().cloned().collect())),
    ]);
    v.cedar(policy.evaluate(actor, "change.propose", base_ctx));
}
