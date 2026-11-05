//! Repository state as a pure fold over the operation log.
//!
//! `State::apply` never reads the clock, the store or the policy: everything
//! it needs is in the operation entry. Replaying the same log always gives
//! the same state, which is what lets the auditor re-check every decision.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ChangeId;
use lonca_core::GitId;
use lonca_core::oplog::{FORMAT_LEASE_LIVENESS, FORMAT_LEASE_PINS, GENESIS_PREV, SignedOp};
use lonca_core::ops::{
    Actor, Claim, Facts, HumanKey, LeaseItem, NegotiationMsg, ObsKind, ObservationLevel, Op,
    Outcome, Scope,
};
use serde::Serialize;

use crate::decide::leases_conflict;
use crate::symbols;

/// When a session last reported itself alive, and for how long that holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Heartbeat {
    pub seen_ms: i64,
    pub timeout_ms: i64,
}

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
    /// `None` until the first heartbeat: such a session lives by its TTL.
    pub heartbeat: Option<Heartbeat>,
    /// The session whose workspace this one took over. Not a `parent`: a
    /// parent's end ends its children, and this session outlives that one.
    pub continued_from: Option<String>,
    /// The session that took this one's workspace over.
    pub continued_by: Option<String>,
    /// Work its workspace held the last time it stopped, until a proposal
    /// or a clean stop.
    pub unproposed: Option<Unproposed>,
}

/// What a session left behind, as reported when it stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unproposed {
    /// At most `MAX_UNPROPOSED_PATHS` of `total`.
    pub paths: Vec<String>,
    pub total: u64,
    /// Reports since the last proposal or clean stop: how many times the
    /// session stopped with this work.
    pub rounds: u32,
    pub seen_ms: i64,
}

#[derive(Clone, Debug, Serialize)]
pub struct LeaseSet {
    pub set: String,
    pub session: String,
    pub items: Vec<LeaseItem>,
    pub intent: String,
    pub expires_ms: i64,
    /// Items pinned to a change in flight: they do not expire, their holder
    /// can not release them, and they conflict for every other session
    /// until the change leaves the queue. Always a subset of `items`.
    pub pins: BTreeMap<ChangeId, Vec<LeaseItem>>,
    /// Since when the session has held these symbols, without a gap.
    pub acquired_ms: i64,
    /// Sessions denied by this set, with the time of their last try.
    pub interest: BTreeMap<String, i64>,
    /// The session this set goes back to when its holder ends: it was
    /// delegated with `cap.attenuate`.
    pub delegated_from: Option<String>,
}

/// A session waiting for what others hold. It holds nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Interest {
    pub session: String,
    pub items: Vec<LeaseItem>,
    pub intent: String,
    /// `leases.reservation_ms` when it was registered: the fold has no
    /// policy, and the decision carries it.
    pub window_ms: i64,
}

/// For a while after a set is freed, only `session` can acquire `items`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Reservation {
    pub session: String,
    pub items: Vec<LeaseItem>,
    pub until_ms: i64,
}

impl LeaseSet {
    pub fn pinned(&self, item: &LeaseItem) -> bool {
        self.pins.values().any(|items| items.contains(item))
    }
}

/// What of a lease set is held at a moment: everything while the set is
/// alive, afterwards only what is pinned.
#[derive(Clone, Debug)]
pub struct ActiveLease<'a> {
    pub lease: &'a LeaseSet,
    pub items: Vec<&'a LeaseItem>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ChangeStatus {
    /// Waiting for human approval (escalated at `seq`).
    Pending {
        seq: u64,
    },
    Queued,
    Integrated {
        commit: GitId,
    },
    Conflicted {
        symbols: Vec<String>,
    },
    Rejected {
        reasons: Vec<String>,
    },
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
    /// Time of the entry that proposed this version.
    pub created_ms: i64,
    pub version: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Pending {
    pub seq: u64,
    /// Time of the escalated entry.
    pub time_ms: i64,
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
    /// Recovery keys of enrolled humans (`human.recovery_key`).
    pub recovery: BTreeMap<String, HumanKey>,
    /// Public keys that were rotated away, used up or revoked. They are
    /// never accepted again.
    pub retired_keys: BTreeSet<String>,
    /// Daemon keys that were rotated away or replaced by a recovery.
    pub retired_daemon_keys: BTreeSet<String>,
    pub policy: Option<GitId>,
    pub trunk: Option<GitId>,
    pub trunk_history: BTreeSet<GitId>,
    /// Every trunk commit in order, genesis first: how far a base is
    /// behind is its distance from the end.
    pub trunk_line: Vec<GitId>,
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
    /// Waiting sessions by the sequence number of their request: the
    /// oldest is served first.
    pub interests: BTreeMap<u64, Interest>,
    pub reservations: Vec<Reservation>,
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
/// On an integration's decision: `leases.release_on_integrate` is off, the
/// items pinned to the change go back to the TTL of their set.
pub const LEASES_KEPT: &str = "leases_kept";
/// On a heartbeat's decision, followed by `leases.heartbeat_timeout_ms`.
pub const HEARTBEAT_TIMEOUT: &str = "heartbeat_timeout=";
/// On a `lease.interest` decision: `leases.reservation_ms`.
pub const RESERVATION_WINDOW: &str = "reservation_ms=";

impl State {
    pub fn new() -> Self {
        Self {
            head_hash: GENESIS_PREV.into(),
            last_time_ms: i64::MIN,
            ..Default::default()
        }
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
            let Some(s) = self.sessions.get(sid) else {
                return false;
            };
            if s.ended.is_some() || now_ms >= s.expires_ms {
                return false;
            }
            cur = s.parent.as_deref();
        }
        true
    }

    /// `session` and the sessions it continues, newest first.
    fn lineage(&self, session: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = Some(session.to_string());
        while let Some(id) = cur {
            cur = self
                .sessions
                .get(&id)
                .and_then(|s| s.continued_from.clone());
            out.push(id);
        }
        out
    }

    /// `session` is `earlier`, or took over its workspace.
    pub fn continues(&self, session: &str, earlier: &str) -> bool {
        self.lineage(session).iter().any(|s| s == earlier)
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

    /// The session has reported heartbeats and stopped: it dropped out.
    pub fn session_lost(&self, id: &str, now_ms: i64) -> bool {
        let beat = self.sessions.get(id).and_then(|s| s.heartbeat);
        beat.is_some_and(|h| now_ms - h.seen_ms > h.timeout_ms)
    }

    fn lease_alive(&self, l: &LeaseSet, now_ms: i64) -> bool {
        l.expires_ms > now_ms
            && self.session_active(&l.session, now_ms)
            && !self.session_lost(&l.session, now_ms)
    }

    /// Another active session asked for what `l` holds in the last
    /// `window_ms`.
    pub fn contended(&self, l: &LeaseSet, now_ms: i64, window_ms: i64) -> bool {
        l.interest
            .iter()
            .any(|(s, at)| now_ms - at <= window_ms && self.session_active(s, now_ms))
    }

    pub fn active_leases(&self, now_ms: i64) -> impl Iterator<Item = ActiveLease<'_>> {
        self.leases.values().filter_map(move |l| {
            let alive = self.lease_alive(l, now_ms);
            let items: Vec<&LeaseItem> = l.items.iter().filter(|i| alive || l.pinned(i)).collect();
            (!items.is_empty()).then_some(ActiveLease { lease: l, items })
        })
    }

    /// A session that can still act: not ended, not expired, still beating.
    fn session_present(&self, id: &str, now_ms: i64) -> bool {
        self.session_active(id, now_ms) && !self.session_lost(id, now_ms)
    }

    fn held_against(&self, session: &str, items: &[LeaseItem], now_ms: i64) -> bool {
        self.active_leases(now_ms)
            .filter(|h| h.lease.session != session)
            .any(|h| {
                h.items
                    .iter()
                    .any(|b| items.iter().any(|a| leases_conflict(a, b)))
            })
    }

    /// The reservations in force at `now_ms`, with the interests they serve.
    /// The window of one that ran out is over for its session, and the next
    /// interest gets its own. Pure, and a function of the entry's time, so
    /// `decide()` sees what the fold of the same entry will record.
    fn settled(&self, now_ms: i64) -> (Vec<Reservation>, Vec<u64>) {
        let mut out: Vec<Reservation> = self
            .reservations
            .iter()
            .filter(|r| r.until_ms > now_ms && self.session_present(&r.session, now_ms))
            .cloned()
            .collect();
        let mut served = Vec::new();
        for (seq, i) in &self.interests {
            let reserved = |r: &Reservation| {
                r.session != i.session
                    && r.items
                        .iter()
                        .any(|b| i.items.iter().any(|a| leases_conflict(a, b)))
            };
            if self.session_present(&i.session, now_ms)
                && !self.held_against(&i.session, &i.items, now_ms)
                && !out.iter().any(reserved)
            {
                out.push(Reservation {
                    session: i.session.clone(),
                    items: i.items.clone(),
                    until_ms: now_ms + i.window_ms,
                });
                served.push(*seq);
            }
        }
        (out, served)
    }

    pub fn held_or_reserved(&self, session: &str, items: &[LeaseItem], now_ms: i64) -> bool {
        self.held_against(session, items, now_ms)
            || self.reserved_against(session, items, now_ms).is_some()
    }

    /// `session` already waits for something that overlaps `items`.
    pub fn waiting(&self, session: &str, items: &[LeaseItem]) -> bool {
        self.interests.values().any(|i| {
            i.session == session
                && i.items.iter().any(|b| {
                    items
                        .iter()
                        .any(|a| symbols::overlaps(&a.symbol, &b.symbol))
                })
        })
    }

    pub fn reservations_at(&self, now_ms: i64) -> Vec<Reservation> {
        self.settled(now_ms).0
    }

    /// Another session's reservation stands in the way of `items`.
    pub fn reserved_against(
        &self,
        session: &str,
        items: &[LeaseItem],
        now_ms: i64,
    ) -> Option<String> {
        self.reservations_at(now_ms)
            .into_iter()
            .find(|r| {
                r.session != session
                    && r.items
                        .iter()
                        .any(|b| items.iter().any(|a| leases_conflict(a, b)))
            })
            .map(|r| r.session)
    }

    fn settle_reservations(&mut self, now_ms: i64) {
        let (reservations, served) = self.settled(now_ms);
        self.reservations = reservations;
        for seq in served {
            self.interests.remove(&seq);
        }
        let gone: Vec<u64> = self
            .interests
            .iter()
            .filter(|(_, i)| !self.session_present(&i.session, now_ms))
            .map(|(seq, _)| *seq)
            .collect();
        for seq in gone {
            self.interests.remove(&seq);
        }
    }

    /// What was waited for is in hand.
    fn acquired(&mut self, session: &str, items: &[LeaseItem]) {
        let overlaps = |theirs: &[LeaseItem]| {
            theirs.iter().any(|b| {
                items
                    .iter()
                    .any(|a| symbols::overlaps(&a.symbol, &b.symbol))
            })
        };
        self.reservations
            .retain(|r| r.session != session || !overlaps(&r.items));
        self.interests
            .retain(|_, i| i.session != session || !overlaps(&i.items));
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
        let pins = e.format >= FORMAT_LEASE_PINS;
        if pins {
            self.prune_leases(e.time_ms);
        }
        self.settle_reservations(e.time_ms);
        // What the proposal is decided on: its session's leases at this
        // moment. A release by approval changes nothing, the pins are there.
        if pins
            && e.decision.outcome != Outcome::Deny
            && let Op::ChangePropose { change, .. } = &e.op
            && let Some(session) = e.actor.session()
        {
            self.pin(session, *change, e.facts.as_ref(), e.time_ms);
        }
        // A proposal that stands is progress: the next stop starts over. An
        // agent that can only get denied keeps counting, and ends.
        if e.decision.outcome != Outcome::Deny
            && matches!(e.op, Op::ChangePropose { .. })
            && let Some(s) = e.actor.session().and_then(|s| self.sessions.get_mut(s))
        {
            s.unproposed = None;
        }
        match e.decision.outcome {
            Outcome::Allow => self.effects(
                &e.actor,
                &e.op,
                e.facts.as_ref(),
                e.seq,
                e.time_ms,
                &e.decision.reasons,
                false,
            ),
            Outcome::Escalate => {
                if let Op::ChangePropose {
                    change,
                    commit,
                    base,
                    claim,
                } = &e.op
                {
                    self.record_change(
                        &e.actor,
                        *change,
                        commit,
                        base,
                        claim,
                        e.facts.clone().unwrap_or_default(),
                        e.seq,
                        e.time_ms,
                        ChangeStatus::Pending { seq: e.seq },
                        false,
                    );
                }
                self.pending.insert(
                    e.seq,
                    Pending {
                        seq: e.seq,
                        time_ms: e.time_ms,
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
                if let Op::ChangeIntegrate {
                    change,
                    merged,
                    conflicts,
                    ..
                } = &e.op
                {
                    if let Some(c) = self.changes.get_mut(change) {
                        c.status = if merged.is_none() {
                            ChangeStatus::Conflicted {
                                symbols: conflicts.clone(),
                            }
                        } else {
                            ChangeStatus::Rejected {
                                reasons: e.decision.reasons.clone(),
                            }
                        };
                    }
                    self.queue.retain(|q| q != change);
                    self.unpin(*change, false);
                }
                // Refused for holding nothing but what others hold: this
                // session is waiting for them.
                if let Op::LeaseAcquire { items, .. } = &e.op
                    && let Some(session) = e.actor.session()
                    && e.format >= FORMAT_LEASE_LIVENESS
                    && e.decision
                        .reasons
                        .iter()
                        .all(|r| r.starts_with("lease_held:"))
                {
                    self.register_interest(session, items, e.time_ms);
                }
            }
        }
    }

    fn register_interest(&mut self, session: &str, items: &[LeaseItem], now_ms: i64) {
        let conflicts = |held: &ActiveLease| {
            let mine = || items.iter();
            held.items
                .iter()
                .any(|b| mine().any(|a| leases_conflict(a, b)))
        };
        let sets = self.active_leases(now_ms);
        let sets = sets.filter(|h| h.lease.session != session && conflicts(h));
        let sets: Vec<String> = sets.map(|h| h.lease.set.clone()).collect();
        for set in sets {
            if let Some(l) = self.leases.get_mut(&set) {
                l.interest.insert(session.to_string(), now_ms);
            }
        }
    }

    /// Pins the items of the session that the facts need to the change.
    fn pin(&mut self, session: &str, change: ChangeId, facts: Option<&Facts>, now_ms: i64) {
        let needs = facts.map(symbols::lease_needs).unwrap_or_default();
        let pinned: Vec<(String, Vec<LeaseItem>)> = self
            .active_leases(now_ms)
            .filter(|l| l.lease.session == session)
            .map(|l| {
                let items = l.items.iter().copied();
                let items = items.filter(|i| needs.iter().any(|n| n.covered_by(i)));
                (l.lease.set.clone(), items.cloned().collect())
            })
            .collect();
        for (set, items) in pinned {
            if !items.is_empty()
                && let Some(l) = self.leases.get_mut(&set)
            {
                l.pins.insert(change, items);
            }
        }
    }

    /// The change left the queue. Its items are released, or go back to
    /// the TTL of their set; an item another change still needs stays.
    fn unpin(&mut self, change: ChangeId, release: bool) {
        for l in self.leases.values_mut() {
            let Some(items) = l.pins.remove(&change) else {
                continue;
            };
            if release {
                let released = |i: &LeaseItem| items.contains(i) && !l.pinned(i);
                let kept = l.items.iter().filter(|i| !released(i));
                l.items = kept.cloned().collect();
            }
        }
        self.leases.retain(|_, l| !l.items.is_empty());
    }

    /// Ends a lease set as far as anyone can: pinned items stay until
    /// their change leaves the queue, and then nothing is left of the set.
    fn release_set(&mut self, set: &str, now_ms: i64) {
        let Some(l) = self.leases.get_mut(set) else {
            return;
        };
        if l.pins.is_empty() {
            self.leases.remove(set);
            return;
        }
        let kept = l.items.iter().filter(|i| l.pinned(i)).cloned().collect();
        l.items = kept;
        l.expires_ms = l.expires_ms.min(now_ms);
    }

    /// Removes what is dead at `now_ms`, so that the active leases stay few.
    fn prune_leases(&mut self, now_ms: i64) {
        let dead: Vec<String> = self
            .leases
            .values()
            .filter(|l| !self.lease_alive(l, now_ms))
            .map(|l| l.set.clone())
            .collect();
        for set in dead {
            self.release_set(&set, now_ms);
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
        time_ms: i64,
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
        let version = self
            .changes
            .get(&change)
            .map(|c| c.version + 1)
            .unwrap_or(1);
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
                created_ms: time_ms,
                version,
            },
        );
    }

    /// `withdraw` is a decision about the work: what the sessions proposed
    /// leaves the queue and every lease goes, pins included. Without it the
    /// work stands, so what it pinned stays until the change leaves.
    fn end_sessions(&mut self, root: &str, reason: &str, withdraw: bool, now_ms: i64) {
        for id in self.descendants(root) {
            if let Some(s) = self.sessions.get_mut(&id)
                && s.ended.is_none()
            {
                s.ended = Some(reason.to_string());
            }
            self.give_back(&id, now_ms);
            if withdraw {
                self.leases.retain(|_, l| l.session != id);
            } else {
                let sets = self.leases.values().filter(|l| l.session == id);
                let sets: Vec<String> = sets.map(|l| l.set.clone()).collect();
                for set in sets {
                    self.release_set(&set, now_ms);
                }
            }
            if withdraw {
                let owned: Vec<ChangeId> = self
                    .changes
                    .values()
                    .filter(|c| c.actor.session() == Some(id.as_str()))
                    .filter(|c| {
                        matches!(
                            c.status,
                            ChangeStatus::Queued | ChangeStatus::Pending { .. }
                        )
                    })
                    .map(|c| c.change)
                    .collect();
                for ch in owned {
                    if let Some(c) = self.changes.get_mut(&ch) {
                        c.status = ChangeStatus::Withdrawn;
                    }
                    self.queue.retain(|q| *q != ch);
                    // A continuation holds its pins now: its sets are not
                    // among the ones dropped above.
                    self.unpin(ch, false);
                }
                self.pending
                    .retain(|_, p| p.actor.session() != Some(id.as_str()));
            }
        }
    }

    /// `old` ends and `new` goes on with its work. Leases end with the
    /// session as they always do, so a set is left only for its pinned
    /// items, and those pass to `new`: the change stays what they are
    /// pinned to, and `new` can propose on top of it.
    fn hand_over(&mut self, old: &str, new: &str, now_ms: i64) {
        self.end_sessions(old, &format!("continued by {new}"), false, now_ms);
        for l in self.leases.values_mut().filter(|l| l.session == old) {
            l.session = new.to_string();
        }
        if let Some(s) = self.sessions.get_mut(old) {
            s.continued_by = Some(new.to_string());
        }
    }

    /// What `id` holds by delegation goes back to a parent that can use it.
    fn give_back(&mut self, id: &str, now_ms: i64) {
        let delegated: Vec<(String, String)> = self
            .leases
            .values()
            .filter(|l| l.session == id)
            .filter_map(|l| Some((l.set.clone(), l.delegated_from.clone()?)))
            .filter(|(_, parent)| self.session_present(parent, now_ms))
            .collect();
        for (set, parent) in delegated {
            if let Some(l) = self.leases.get_mut(&set) {
                l.session = parent;
                l.delegated_from = None;
            }
        }
    }

    /// Ends everything a human set in motion (design §5.4): every session
    /// they started and everything derived from it (capabilities, leases,
    /// proposals, queued work, negotiations; the daemon drops the tokens),
    /// their own changes in flight, the operations they requested that wait
    /// for approval, and the approvals they gave to others. Entries they
    /// signed earlier stay valid history.
    fn end_human(&mut self, human: &str, reason: &str, now_ms: i64) {
        let roots: Vec<String> = self
            .sessions
            .values()
            .filter(|s| s.root_human == human)
            .map(|s| s.id.clone())
            .collect();
        for id in roots {
            self.end_sessions(&id, reason, true, now_ms);
        }
        let is_human = |a: &Actor| matches!(a, Actor::Human { name } if name == human);
        let owned: Vec<ChangeId> = self
            .changes
            .values()
            .filter(|c| is_human(&c.actor))
            .filter(|c| {
                matches!(
                    c.status,
                    ChangeStatus::Queued | ChangeStatus::Pending { .. }
                )
            })
            .map(|c| c.change)
            .collect();
        for ch in owned {
            if let Some(c) = self.changes.get_mut(&ch) {
                c.status = ChangeStatus::Withdrawn;
            }
            self.queue.retain(|q| *q != ch);
        }
        self.pending.retain(|_, p| !is_human(&p.actor));
        for p in self.pending.values_mut() {
            p.approvals.remove(human);
        }
    }

    fn retire(&mut self, key: Option<HumanKey>) {
        if let Some(k) = key {
            self.retired_keys.insert(k.public);
        }
    }

    /// Whether a public key is, or ever was, a key of some human.
    pub fn key_known(&self, public: &str) -> bool {
        self.retired_keys.contains(public)
            || self
                .humans
                .values()
                .chain(self.recovery.values())
                .any(|k| k.public == public)
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
            Op::RepoInit {
                repo,
                daemon_key,
                human,
                human_key,
                policy,
                trunk,
            } => {
                self.repo = repo.clone();
                self.daemon_key = daemon_key.clone();
                self.humans.insert(human.clone(), human_key.clone());
                self.policy = Some(policy.clone());
                self.trunk = Some(trunk.clone());
                self.trunk_history.insert(trunk.clone());
                self.trunk_line.push(trunk.clone());
            }
            Op::HumanEnroll { human, key } => {
                self.humans.insert(human.clone(), key.clone());
            }
            Op::HumanRotate { human, key } => {
                self.end_human(
                    human,
                    &format!("revoked: key of human:{human} rotated"),
                    time_ms,
                );
                let old = self.humans.insert(human.clone(), key.clone());
                self.retire(old);
            }
            Op::HumanRevoke { human, reason } => {
                self.end_human(
                    human,
                    &format!("revoked: human:{human} revoked: {reason}"),
                    time_ms,
                );
                let old = self.humans.remove(human);
                self.retire(old);
                let old = self.recovery.remove(human);
                self.retire(old);
            }
            Op::HumanRecoveryKey { human, key } => {
                let old = self.recovery.insert(human.clone(), key.clone());
                self.retire(old);
            }
            Op::HumanRecover { human, key } => {
                self.end_human(human, &format!("revoked: human:{human} recovered"), time_ms);
                let old = self.humans.insert(human.clone(), key.clone());
                self.retire(old);
                let old = self.recovery.remove(human);
                self.retire(old);
            }
            Op::DaemonRotate { key } => {
                let old = std::mem::replace(&mut self.daemon_key, key.clone());
                self.retired_daemon_keys.insert(old);
            }
            Op::DaemonRecover { key } => {
                // The daemon that held the session tokens is gone (or is
                // being replaced): every session ends. What they proposed
                // keeps its decision, like after `session.end`.
                let roots: Vec<String> = self
                    .sessions
                    .values()
                    .filter(|s| s.parent.is_none())
                    .map(|s| s.id.clone())
                    .collect();
                for id in roots {
                    self.end_sessions(&id, "revoked: daemon key recovered", false, time_ms);
                }
                let old = std::mem::replace(&mut self.daemon_key, key.clone());
                self.retired_daemon_keys.insert(old);
            }
            Op::PolicyUpdate { policy } => self.policy = Some(policy.clone()),
            Op::SessionStart {
                session,
                agent,
                model,
                task,
                scope,
                expires_ms,
                continues,
            } => {
                let root_human = match actor {
                    Actor::Human { name } => name.clone(),
                    _ => String::new(),
                };
                // What is known of the workspace's files goes with them.
                let old = continues.as_ref();
                let old = old.and_then(|c| self.sessions.get(&c.session)).cloned();
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
                        level: old
                            .as_ref()
                            .map_or(ObservationLevel::Unobserved, |o| o.level),
                        taint: old.as_ref().and_then(|o| o.taint.clone()),
                        ended: None,
                        writes: old.as_ref().map(|o| o.writes.clone()).unwrap_or_default(),
                        shell_seen: old.as_ref().is_some_and(|o| o.shell_seen),
                        heartbeat: None,
                        continued_from: old.as_ref().map(|o| o.id.clone()),
                        continued_by: None,
                        unproposed: None,
                    },
                );
                if let Some(old) = old {
                    self.hand_over(&old.id, session, time_ms);
                }
            }
            Op::SessionBind { session, level, .. } => {
                if let Some(s) = self.sessions.get_mut(session) {
                    s.level = *level;
                }
            }
            Op::SessionEnd { session, reason } => {
                self.end_sessions(session, &format!("ended: {reason}"), false, time_ms)
            }
            Op::CapAttenuate {
                parent,
                child,
                agent,
                scope,
                expires_ms,
                leases,
            } => {
                for set in leases {
                    if let Some(l) = self.leases.get_mut(set) {
                        l.session = child.clone();
                        l.delegated_from = Some(parent.clone());
                    }
                }
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
                            heartbeat: None,
                            continued_from: None,
                            continued_by: None,
                            unproposed: None,
                        },
                    );
                }
            }
            Op::CapRevoke { session, reason } => {
                // A revocation is about the work, and the earlier sessions
                // of a continued workspace did part of it.
                for id in self.lineage(session) {
                    self.end_sessions(&id, &format!("revoked: {reason}"), true, time_ms);
                }
            }
            Op::LeaseAcquire {
                set,
                items,
                intent,
                ttl_ms,
            } => {
                if let Some(session) = actor.session() {
                    // A new set over what the session holds continues the
                    // hold: a fresh id does not reset the limit.
                    let overlapping = self.active_leases(time_ms).filter(|h| {
                        h.lease.session == session
                            && h.items.iter().any(|b| {
                                items
                                    .iter()
                                    .any(|a| symbols::overlaps(&a.symbol, &b.symbol))
                            })
                    });
                    let acquired_ms = overlapping
                        .map(|h| h.lease.acquired_ms)
                        .min()
                        .unwrap_or(time_ms);
                    self.leases.insert(
                        set.clone(),
                        LeaseSet {
                            set: set.clone(),
                            session: session.to_string(),
                            items: items.clone(),
                            intent: intent.clone(),
                            expires_ms: time_ms + ttl_ms,
                            pins: BTreeMap::new(),
                            acquired_ms,
                            interest: BTreeMap::new(),
                            delegated_from: None,
                        },
                    );
                    self.acquired(session, items);
                }
            }
            Op::LeaseInterest { items, intent } => {
                if let Some(session) = actor.session() {
                    let window_ms = reasons
                        .iter()
                        .find_map(|r| r.strip_prefix(RESERVATION_WINDOW))
                        .and_then(|n| n.parse().ok())
                        .unwrap_or_default();
                    self.interests.insert(
                        seq,
                        Interest {
                            session: session.to_string(),
                            items: items.clone(),
                            intent: intent.clone(),
                            window_ms,
                        },
                    );
                    self.register_interest(session, items, time_ms);
                }
            }
            Op::LeaseRelease { set } => self.release_set(set, time_ms),
            Op::LeaseRenew { set, ttl_ms } => {
                if let Some(l) = self.leases.get_mut(set) {
                    l.expires_ms = time_ms + ttl_ms;
                }
            }
            Op::ChangePropose {
                change,
                commit,
                base,
                claim,
            } => {
                self.record_change(
                    actor,
                    *change,
                    commit,
                    base,
                    claim,
                    facts.cloned().unwrap_or_default(),
                    seq,
                    time_ms,
                    ChangeStatus::Queued,
                    reviewed,
                );
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
                self.unpin(*change, false);
            }
            Op::ChangeIntegrate { change, merged, .. } => {
                let Some(merged) = merged else { return };
                self.trunk = Some(merged.clone());
                self.trunk_history.insert(merged.clone());
                self.trunk_line.push(merged.clone());
                if let Some(c) = self.changes.get_mut(change) {
                    c.status = ChangeStatus::Integrated {
                        commit: merged.clone(),
                    };
                    if c.claim.revert_of.is_some() {
                        let mut syms = c.facts.edits.clone();
                        syms.extend(c.facts.deletes.iter().cloned());
                        syms.extend(c.facts.adds.iter().cloned());
                        self.reverts.push((time_ms, syms));
                    }
                }
                self.queue.retain(|q| q != change);
                self.unpin(*change, !reasons.iter().any(|r| r == LEASES_KEPT));
            }
            Op::Approve { target_seq, .. } => {
                let Actor::Human { name } = actor else { return };
                let Some(p) = self.pending.get_mut(target_seq) else {
                    return;
                };
                p.approvals.insert(name.clone());
                if reasons.iter().any(|r| r == RELEASED) {
                    let p = self.pending.remove(target_seq).expect("present");
                    self.effects(&p.actor, &p.op, p.facts.as_ref(), p.seq, time_ms, &[], true);
                }
            }
            // A human declines: the operation leaves the pending set; a
            // proposal is rejected with the reason, and the lease sets of
            // its session that cover what it changed are released, so the
            // symbols are free for the next attempt (by it or by others).
            Op::Reject { target_seq, reason } => {
                let Some(p) = self.pending.remove(target_seq) else {
                    return;
                };
                if let Op::ChangePropose { change, .. } = &p.op {
                    let symbols: Vec<String> = self
                        .changes
                        .get(change)
                        .map(|c| {
                            c.facts
                                .edits
                                .iter()
                                .chain(&c.facts.adds)
                                .chain(&c.facts.deletes)
                                .chain(&c.facts.signature_changes)
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default();
                    if let Some(c) = self.changes.get_mut(change) {
                        c.status = ChangeStatus::Rejected {
                            reasons: vec![format!("rejected: {reason}")],
                        };
                    }
                    self.queue.retain(|q| q != change);
                    self.unpin(*change, false);
                    if let Some(session) = p.actor.session() {
                        let covers = |l: &LeaseSet| {
                            l.items
                                .iter()
                                .any(|i| symbols.iter().any(|s| symbols::covers(&i.symbol, s)))
                        };
                        let sets = self.leases.values();
                        let sets = sets.filter(|l| l.session == session && covers(l));
                        let sets: Vec<String> = sets.map(|l| l.set.clone()).collect();
                        for set in sets {
                            self.release_set(&set, time_ms);
                        }
                    }
                }
            }
            Op::Observe { session, events } => {
                let timeout = reasons
                    .iter()
                    .find_map(|r| r.strip_prefix(HEARTBEAT_TIMEOUT))
                    .and_then(|n| n.parse().ok());
                if let Some(s) = self.sessions.get_mut(session) {
                    if let Some(timeout_ms) = timeout {
                        s.heartbeat = Some(Heartbeat {
                            seen_ms: time_ms,
                            timeout_ms,
                        });
                    }
                    for ev in events {
                        match &ev.kind {
                            ObsKind::Write { path } => {
                                s.writes.insert(path.clone());
                            }
                            ObsKind::Shell { .. } => s.shell_seen = true,
                            ObsKind::Unproposed { paths, total } => {
                                let rounds = s.unproposed.as_ref().map_or(0, |u| u.rounds);
                                s.unproposed = (*total > 0).then(|| Unproposed {
                                    paths: paths.clone(),
                                    total: *total,
                                    rounds: rounds.saturating_add(1),
                                    seen_ms: time_ms,
                                });
                            }
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
                    && s.taint.is_none()
                {
                    s.taint = Some(reason.clone());
                }
            }
            Op::ImportExternal { commit, .. } => {
                self.trunk = Some(commit.clone());
                self.trunk_history.insert(commit.clone());
                self.trunk_line.push(commit.clone());
            }
            Op::ImportUnmediated { .. } => {}
            Op::BridgePush {
                remote,
                oplog_seq,
                oplog_hash,
            } => {
                self.anchors
                    .push((remote.clone(), *oplog_seq, oplog_hash.clone()));
            }
            Op::Freeze { reason } => self.frozen = Some(reason.clone()),
            Op::Unfreeze { .. } => self.frozen = None,
            Op::Negotiate {
                thread,
                to_session,
                message,
            } => {
                let Some(from) = actor.session().map(str::to_string) else {
                    return;
                };
                let t = self
                    .threads
                    .entry(thread.clone())
                    .or_insert_with(|| Thread {
                        id: thread.clone(),
                        a: from.clone(),
                        b: to_session.clone(),
                        rounds: 0,
                        closed: false,
                    });
                t.rounds += 1;
                if matches!(
                    message,
                    NegotiationMsg::Accept | NegotiationMsg::Decline { .. }
                ) {
                    t.closed = true;
                }
                match message {
                    NegotiationMsg::Yield { set, to: None } => self.release_set(set, time_ms),
                    NegotiationMsg::Yield { set, to: Some(to) } => {
                        if let Some(l) = self.leases.get_mut(set) {
                            l.session = to.clone();
                            l.acquired_ms = time_ms;
                            l.interest.clear();
                            l.delegated_from = None;
                        }
                    }
                    _ => {}
                }
                let sender_taint = self.sessions.get(&from).and_then(|s| s.taint.clone());
                if let (Some(t), Some(r)) = (sender_taint, self.sessions.get_mut(to_session))
                    && r.taint.is_none()
                {
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
        ObsKind::Unproposed { total, .. } => format!("{total} unproposed file(s)"),
    }
}

impl State {
    /// How many integrations trunk has had since `base` was trunk; `None`
    /// when `base` was never trunk.
    pub fn behind(&self, base: &GitId) -> Option<usize> {
        self.trunk_line
            .iter()
            .rposition(|t| t == base)
            .map(|i| self.trunk_line.len() - 1 - i)
    }
}
