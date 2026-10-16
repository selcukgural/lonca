//! Repository state as a pure fold over the operation log.
//!
//! `State::apply` never reads the clock, the store or the policy: everything
//! it needs is in the operation entry. Replaying the same log always gives
//! the same state, which is what lets the auditor re-check every decision.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ChangeId;
use lonca_core::GitId;
use lonca_core::oplog::{GENESIS_PREV, SignedOp};
use lonca_core::ops::{
    Actor, Claim, Facts, HumanKey, LeaseItem, NegotiationMsg, ObsKind, ObservationLevel, Op, Outcome, Scope,
};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Session {
    pub id: String,
    pub agent: String,
    pub model: Option<String>,
    pub task: String,
    pub parent: Option<String>,
    pub root_human: String,
    pub scope: Scope,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub level: ObservationLevel,
    pub taint: Option<String>,
    pub ended: Option<String>,
    pub writes: BTreeSet<String>,
    pub shell_seen: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct LeaseSet {
    pub set: String,
    pub session: String,
    pub items: Vec<LeaseItem>,
    pub intent: String,
    pub expires_ms: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChangeStatus {
    /// Waiting for human approval (escalated at `seq`).
    Pending { seq: u64 },
    Queued,
    Integrated { commit: GitId },
    Conflicted { symbols: Vec<String> },
    Rejected { reasons: Vec<String> },
    Withdrawn,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Human,
    Clean,
    Tainted,
    Unobserved,
    /// Tainted or unobserved, then approved by a human.
    Reviewed,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChangeRecord {
    pub change: ChangeId,
    pub actor: Actor,
    pub commit: GitId,
    pub base: GitId,
    pub claim: Claim,
    pub facts: Facts,
    pub status: ChangeStatus,
    pub provenance: Provenance,
    pub proposed_seq: u64,
    pub version: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Pending {
    pub seq: u64,
    pub actor: Actor,
    pub op: Op,
    pub facts: Option<Facts>,
    pub reasons: Vec<String>,
    pub required: u32,
    pub approvals: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Thread {
    pub id: String,
    pub a: String,
    pub b: String,
    pub rounds: u32,
    pub closed: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct State {
    pub repo: String,
    pub daemon_key: String,
    pub humans: BTreeMap<String, HumanKey>,
    pub policy: Option<GitId>,
    pub trunk: Option<GitId>,
    pub trunk_history: BTreeSet<GitId>,
    pub sessions: BTreeMap<String, Session>,
    pub leases: BTreeMap<String, LeaseSet>,
    pub changes: BTreeMap<ChangeId, ChangeRecord>,
    pub queue: Vec<ChangeId>,
    pub pending: BTreeMap<u64, Pending>,
    pub nonces: BTreeSet<String>,
    pub frozen: Option<String>,
    /// (time, symbols) of integrated reverts, for revert-rate rules.
    pub reverts: Vec<(i64, Vec<String>)>,
    pub threads: BTreeMap<String, Thread>,
    pub redacted: BTreeSet<GitId>,
    pub anchors: Vec<(String, u64, String)>,
    /// Sequence number the next entry must carry.
    pub next_seq: u64,
    pub head_hash: String,
    pub last_time_ms: i64,
}

/// Required approvals are carried in the decision as `approvals=N`.
pub fn approvals_from(reasons: &[String]) -> u32 {
    reasons
        .iter()
        .filter_map(|r| r.strip_prefix("approvals="))
        .filter_map(|n| n.parse().ok())
        .max()
        .unwrap_or(1)
}

pub const RELEASED: &str = "released";

impl State {
    pub fn new() -> Self {
        Self { head_hash: GENESIS_PREV.into(), last_time_ms: i64::MIN, ..Default::default() }
    }

    pub fn replay(ops: &[SignedOp]) -> Self {
        let mut s = Self::new();
        for op in ops {
            s.apply(op);
        }
        s
    }

    pub fn session_active(&self, id: &str, now_ms: i64) -> bool {
        let mut cur = Some(id);
        while let Some(sid) = cur {
            let Some(s) = self.sessions.get(sid) else { return false };
            if s.ended.is_some() || now_ms >= s.expires_ms {
                return false;
            }
            cur = s.parent.as_deref();
        }
        true
    }

    /// `child` is `ancestor` or was (transitively) created from it.
    pub fn descends_from(&self, child: &str, ancestor: &str) -> bool {
        let mut cur = Some(child);
        while let Some(sid) = cur {
            if sid == ancestor {
                return true;
            }
            cur = self.sessions.get(sid).and_then(|s| s.parent.as_deref());
        }
        false
    }

    pub fn active_leases(&self, now_ms: i64) -> impl Iterator<Item = &LeaseSet> {
        self.leases
            .values()
            .filter(move |l| l.expires_ms > now_ms && self.session_active(&l.session, now_ms))
    }

    fn descendants(&self, root: &str) -> Vec<String> {
        self.sessions
            .keys()
            .filter(|id| self.descends_from(id, root))
            .cloned()
            .collect()
    }

    pub fn apply(&mut self, s: &SignedOp) {
        let e = &s.entry;
        self.next_seq = e.seq + 1;
        self.head_hash = s.hash.clone();
        self.last_time_ms = e.time_ms;
        if let Some(h) = &e.human {
            self.nonces.insert(h.nonce.clone());
        }
        match e.decision.outcome {
            Outcome::Allow => self.effects(&e.actor, &e.op, e.facts.as_ref(), e.seq, e.time_ms, &e.decision.reasons, false),
            Outcome::Escalate => {
                if let Op::ChangePropose { change, commit, base, claim } = &e.op {
                    self.record_change(&e.actor, *change, commit, base, claim, e.facts.clone().unwrap_or_default(), e.seq, ChangeStatus::Pending { seq: e.seq }, false);
                }
                self.pending.insert(
                    e.seq,
                    Pending {
                        seq: e.seq,
                        actor: e.actor.clone(),
                        op: e.op.clone(),
                        facts: e.facts.clone(),
                        reasons: e.decision.reasons.clone(),
                        required: approvals_from(&e.decision.reasons),
                        approvals: BTreeSet::new(),
                    },
                );
            }
            Outcome::Deny => {
                // A failed integration still moves the change out of the queue.
                if let Op::ChangeIntegrate { change, merged, conflicts, .. } = &e.op {
                    if let Some(c) = self.changes.get_mut(change) {
                        c.status = if merged.is_none() {
                            ChangeStatus::Conflicted { symbols: conflicts.clone() }
                        } else {
                            ChangeStatus::Rejected { reasons: e.decision.reasons.clone() }
                        };
                    }
                    self.queue.retain(|q| q != change);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn record_change(
        &mut self,
        actor: &Actor,
        change: ChangeId,
        commit: &GitId,
        base: &GitId,
        claim: &Claim,
        facts: Facts,
        seq: u64,
        status: ChangeStatus,
        reviewed: bool,
    ) {
        let provenance = match actor {
            Actor::Human { .. } => Provenance::Human,
            _ if reviewed => Provenance::Reviewed,
            Actor::Agent { session, .. } => match self.sessions.get(session) {
                Some(s) if s.taint.is_some() => Provenance::Tainted,
                Some(s) if s.level == ObservationLevel::Unobserved => Provenance::Unobserved,
                _ => Provenance::Clean,
            },
            Actor::Daemon => Provenance::Clean,
        };
        let version = self.changes.get(&change).map(|c| c.version + 1).unwrap_or(1);
        self.changes.insert(
            change,
            ChangeRecord {
                change,
                actor: actor.clone(),
                commit: commit.clone(),
                base: base.clone(),
                claim: claim.clone(),
                facts,
                status,
                provenance,
                proposed_seq: seq,
                version,
            },
        );
    }

    fn end_sessions(&mut self, root: &str, reason: &str, withdraw: bool) {
        for id in self.descendants(root) {
            if let Some(s) = self.sessions.get_mut(&id)
                && s.ended.is_none() {
                    s.ended = Some(reason.to_string());
                }
            self.leases.retain(|_, l| l.session != id);
            if withdraw {
                let owned: Vec<ChangeId> = self
                    .changes
                    .values()
                    .filter(|c| c.actor.session() == Some(id.as_str()))
                    .filter(|c| matches!(c.status, ChangeStatus::Queued | ChangeStatus::Pending { .. }))
                    .map(|c| c.change)
                    .collect();
                for ch in owned {
                    if let Some(c) = self.changes.get_mut(&ch) {
                        c.status = ChangeStatus::Withdrawn;
                    }
                    self.queue.retain(|q| *q != ch);
                }
                self.pending.retain(|_, p| p.actor.session() != Some(id.as_str()));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn effects(
        &mut self,
        actor: &Actor,
        op: &Op,
        facts: Option<&Facts>,
        seq: u64,
        time_ms: i64,
        reasons: &[String],
        reviewed: bool,
    ) {
        match op {
            Op::RepoInit { repo, daemon_key, human, human_key, policy, trunk } => {
                self.repo = repo.clone();
                self.daemon_key = daemon_key.clone();
                self.humans.insert(human.clone(), human_key.clone());
                self.policy = Some(policy.clone());
                self.trunk = Some(trunk.clone());
                self.trunk_history.insert(trunk.clone());
            }
            Op::HumanEnroll { human, key } => {
                self.humans.insert(human.clone(), key.clone());
            }
            Op::PolicyUpdate { policy } => self.policy = Some(policy.clone()),
            Op::SessionStart { session, agent, model, task, scope, expires_ms } => {
                let root_human = match actor {
                    Actor::Human { name } => name.clone(),
                    _ => String::new(),
                };
                self.sessions.insert(
                    session.clone(),
                    Session {
                        id: session.clone(),
                        agent: agent.clone(),
                        model: model.clone(),
                        task: task.clone(),
                        parent: None,
                        root_human,
                        scope: scope.clone(),
                        created_ms: time_ms,
                        expires_ms: *expires_ms,
                        level: ObservationLevel::Unobserved,
                        taint: None,
                        ended: None,
                        writes: BTreeSet::new(),
                        shell_seen: false,
                    },
                );
            }
            Op::SessionBind { session, level, .. } => {
                if let Some(s) = self.sessions.get_mut(session) {
                    s.level = *level;
                }
            }
            Op::SessionEnd { session, reason } => self.end_sessions(session, &format!("ended: {reason}"), false),
            Op::CapAttenuate { parent, child, agent, scope, expires_ms } => {
                if let Some(p) = self.sessions.get(parent).cloned() {
                    self.sessions.insert(
                        child.clone(),
                        Session {
                            id: child.clone(),
                            agent: agent.clone(),
                            model: p.model.clone(),
                            task: p.task.clone(),
                            parent: Some(parent.clone()),
                            root_human: p.root_human.clone(),
                            scope: scope.clone(),
                            created_ms: time_ms,
                            expires_ms: *expires_ms,
                            level: p.level,
                            taint: p.taint.as_ref().map(|t| format!("inherited: {t}")),
                            ended: None,
                            writes: BTreeSet::new(),
                            shell_seen: false,
                        },
                    );
                }
            }
            Op::CapRevoke { session, reason } => self.end_sessions(session, &format!("revoked: {reason}"), true),
            Op::LeaseAcquire { set, items, intent, ttl_ms } => {
                if let Some(session) = actor.session() {
                    self.leases.insert(
                        set.clone(),
                        LeaseSet {
                            set: set.clone(),
                            session: session.to_string(),
                            items: items.clone(),
                            intent: intent.clone(),
                            expires_ms: time_ms + ttl_ms,
                        },
                    );
                }
            }
            Op::LeaseRelease { set } => {
                self.leases.remove(set);
            }
            Op::LeaseRenew { set, ttl_ms } => {
                if let Some(l) = self.leases.get_mut(set) {
                    l.expires_ms = time_ms + ttl_ms;
                }
            }
            Op::ChangePropose { change, commit, base, claim } => {
                self.record_change(actor, *change, commit, base, claim, facts.cloned().unwrap_or_default(), seq, ChangeStatus::Queued, reviewed);
                self.queue.retain(|q| q != change);
                self.queue.push(*change);
            }
            Op::ChangeWithdraw { change } => {
                if let Some(c) = self.changes.get_mut(change) {
                    if let ChangeStatus::Pending { seq } = c.status {
                        self.pending.remove(&seq);
                    }
                    c.status = ChangeStatus::Withdrawn;
                }
                self.queue.retain(|q| q != change);
            }
            Op::ChangeIntegrate { change, merged, .. } => {
                let Some(merged) = merged else { return };
                self.trunk = Some(merged.clone());
                self.trunk_history.insert(merged.clone());
                if let Some(c) = self.changes.get_mut(change) {
                    c.status = ChangeStatus::Integrated { commit: merged.clone() };
                    if c.claim.revert_of.is_some() {
                        let mut syms = c.facts.edits.clone();
                        syms.extend(c.facts.deletes.iter().cloned());
                        syms.extend(c.facts.adds.iter().cloned());
                        self.reverts.push((time_ms, syms));
                    }
                }
                self.queue.retain(|q| q != change);
            }
            Op::Approve { target_seq, .. } => {
                let Actor::Human { name } = actor else { return };
                let Some(p) = self.pending.get_mut(target_seq) else { return };
                p.approvals.insert(name.clone());
                if reasons.iter().any(|r| r == RELEASED) {
                    let p = self.pending.remove(target_seq).expect("present");
                    self.effects(&p.actor, &p.op, p.facts.as_ref(), p.seq, time_ms, &[], true);
                }
            }
            Op::Observe { session, events } => {
                if let Some(s) = self.sessions.get_mut(session) {
                    for ev in events {
                        match &ev.kind {
                            ObsKind::Write { path } => {
                                s.writes.insert(path.clone());
                            }
                            ObsKind::Shell { .. } => s.shell_seen = true,
                            _ => {}
                        }
                        if ev.external && s.taint.is_none() {
                            s.taint = Some(format!("observed external {}", describe(&ev.kind)));
                        }
                    }
                }
            }
            Op::Taint { session, reason } => {
                if let Some(s) = self.sessions.get_mut(session)
                    && s.taint.is_none() {
                        s.taint = Some(reason.clone());
                    }
            }
            Op::ImportExternal { commit, .. } => {
                self.trunk = Some(commit.clone());
                self.trunk_history.insert(commit.clone());
            }
            Op::ImportUnmediated { .. } => {}
            Op::BridgePush { remote, oplog_seq, oplog_hash } => {
                self.anchors.push((remote.clone(), *oplog_seq, oplog_hash.clone()));
            }
            Op::Freeze { reason } => self.frozen = Some(reason.clone()),
            Op::Unfreeze { .. } => self.frozen = None,
            Op::Negotiate { thread, to_session, message } => {
                let Some(from) = actor.session().map(str::to_string) else { return };
                let t = self.threads.entry(thread.clone()).or_insert_with(|| Thread {
                    id: thread.clone(),
                    a: from.clone(),
                    b: to_session.clone(),
                    rounds: 0,
                    closed: false,
                });
                t.rounds += 1;
                if matches!(message, NegotiationMsg::Accept | NegotiationMsg::Decline { .. }) {
                    t.closed = true;
                }
                if let NegotiationMsg::Yield { set } = message {
                    self.leases.remove(set);
                }
                let sender_taint = self.sessions.get(&from).and_then(|s| s.taint.clone());
                if let (Some(t), Some(r)) = (sender_taint, self.sessions.get_mut(to_session))
                    && r.taint.is_none() {
                        r.taint = Some(format!("negotiation from tainted session {from}: {t}"));
                    }
            }
            Op::Redact { blob, .. } => {
                self.redacted.insert(blob.clone());
            }
        }
    }
}

fn describe(k: &ObsKind) -> String {
    match k {
        ObsKind::Read { path } => format!("read {path}"),
        ObsKind::Write { path } => format!("write {path}"),
        ObsKind::Shell { program, .. } => format!("shell {program}"),
        ObsKind::Fetch { host } => format!("fetch {host}"),
        ObsKind::Mcp { tool } => format!("mcp {tool}"),
        ObsKind::Other { tool } => format!("tool {tool}"),
        ObsKind::Heartbeat => "heartbeat".into(),
    }
}
