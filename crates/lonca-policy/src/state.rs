//! Repository state as a pure fold over the operation log.
//!
//! `State::apply` never reads the clock, the store or the policy: everything
//! it needs is in the operation entry. Replaying the same log always gives
//! the same state, which is what lets the auditor re-check every decision.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ChangeId;
use lonca_core::GitId;
use lonca_core::oplog::{
    FORMAT_LEASE_INTENT, FORMAT_LEASE_LIVENESS, FORMAT_LEASE_PINS, FORMAT_SYMBOL_KEYS,
    GENESIS_PREV, SignedOp,
};
use lonca_core::ops::{
    Actor, Claim, Facts, HumanKey, LeaseItem, NegotiationMsg, ObsKind, ObservationLevel, Op,
    Outcome, Scope,
};
use serde::Serialize;

use crate::decide::leases_conflict;
use crate::symbols::{self, LeaseNeed};

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
    /// Set by the first interest that runs into this set: no interest that
    /// runs into it stops new leases past this time, so the cap of
    /// `leases.interest_block_ms` is per set, not per interest.
    pub stop_until_ms: Option<i64>,
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
    /// Until when no other session can take a new lease that conflicts
    /// with `items`. Zero for an interest of an older format: it stops
    /// nobody.
    pub blocks_until_ms: i64,
}

/// For a while after a set is freed, only `session` can acquire `items`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Reservation {
    pub session: String,
    pub items: Vec<LeaseItem>,
    pub until_ms: i64,
}

/// A symbol that goes on under another name, from an integrated change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Renamed {
    /// Where the new name starts, in `trunk_line`.
    pub line: usize,
    pub old: String,
    pub new: String,
    /// A symbol took the old name again here: from that trunk on, the old
    /// name is that symbol.
    pub reused: Option<usize>,
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
    /// The log reached [`FORMAT_SYMBOL_KEYS`]: a name stands for every
    /// symbol of that name.
    pub symbol_keys: bool,
    /// Every trunk commit in order, genesis first: how far a base is
    /// behind is its distance from the end.
    pub trunk_line: Vec<GitId>,
    /// What integrated changes renamed, oldest first.
    pub renames: Vec<Renamed>,
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
/// On a `lease.interest` decision: `leases.interest_block_ms`.
pub const INTEREST_BLOCK: &str = "interest_block_ms=";

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

    /// What `symbol` is called on the trunk. With `base`, only by the renames
    /// that trunk had not seen. A name taken again is that new symbol, so it
    /// starts no chain, though a chain that passed it goes on: what was
    /// renamed before the name was taken stays on its way.
    pub fn renamed_to(&self, symbol: &str, base: Option<&GitId>) -> String {
        let line = base.and_then(|b| self.trunk_line.iter().rposition(|t| t == b));
        let later = |r: &&Renamed| line.is_none_or(|at| r.line > at);
        let mut name = symbol.to_string();
        let mut moved = false;
        for r in self.renames.iter().filter(later) {
            if r.reused.is_some() && !moved {
                continue;
            }
            if let Some(member) = name.strip_prefix(r.old.as_str())
                && (member.is_empty() || member.starts_with('.'))
            {
                name = format!("{}{member}", r.new);
                moved = true;
            }
        }
        name
    }

    /// Every name `item` reaches on the trunk: its own, and those of what its
    /// name stands for, since `C.M` holds an overload that became `C.N`.
    fn renamed_items(&self, item: &LeaseItem) -> Vec<LeaseItem> {
        let named = |symbol: String| LeaseItem {
            symbol,
            kind: item.kind,
        };
        let mut out = vec![named(self.renamed_to(&item.symbol, None))];
        let stood_for = self.renames.iter().filter(|r| {
            let live = r.reused.is_none();
            live && self.symbol_keys && symbols::stands_for(&item.symbol, &r.old)
        });
        out.extend(stood_for.map(|r| named(self.renamed_to(&r.old, None))));
        out
    }

    /// `a` and `b` can not be held by two sessions, as they are named or as
    /// they are called on the trunk: a session on an older base has a symbol
    /// by its old name.
    pub fn conflict(&self, a: &LeaseItem, b: &LeaseItem) -> bool {
        let keys = self.symbol_keys;
        if leases_conflict(a, b, keys) {
            return true;
        }
        if self.renames.is_empty() {
            return false;
        }
        let (a, b) = (self.renamed_items(a), self.renamed_items(b));
        a.iter()
            .any(|x| b.iter().any(|y| leases_conflict(x, y, keys)))
    }

    /// Something in `a` conflicts with something in `b`.
    fn clash(&self, a: &[LeaseItem], b: &[LeaseItem]) -> bool {
        a.iter().any(|x| b.iter().any(|y| self.conflict(x, y)))
    }

    /// `item` covers `need`, by the name in the facts or by what that is
    /// called now. A change from an older base has the old name.
    pub fn covers_need(&self, need: &LeaseNeed, item: &LeaseItem, base: Option<&GitId>) -> bool {
        let keys = self.symbol_keys;
        let renamed = LeaseNeed {
            symbol: self.renamed_to(&need.symbol, base),
            kinds: need.kinds,
        };
        need.covered_by(item, keys) || renamed.covered_by(item, keys)
    }

    /// Notes what an integrated change renamed and which names it took
    /// again: its additions, its new keys, and every name of a file it
    /// deleted or wrote from nothing.
    fn record_renames(&mut self, facts: &Facts) {
        let line = self.trunk_line.len().saturating_sub(1);
        let keys = self.symbol_keys;
        let new_names = facts.renames.iter().map(|[_, new]| new);
        let taken: Vec<&String> = facts.adds.iter().chain(new_names).collect();
        let files: Vec<&String> = facts
            .deleted_files
            .iter()
            .chain(&facts.added_files)
            .collect();
        for r in self.renames.iter_mut().filter(|r| r.reused.is_none()) {
            let path = symbols::split(&r.old).map(|(path, _)| path);
            let again =
                |name: &&String| r.old == **name || (keys && symbols::stands_for(&r.old, name));
            if taken.iter().any(|n| again(n)) || files.iter().any(|f| Some(f.as_str()) == path) {
                r.reused = Some(line);
            }
        }
        for [old, new] in &facts.renames {
            self.renames.push(Renamed {
                line,
                old: old.clone(),
                new: new.clone(),
                reused: None,
            });
        }
    }

    fn held_against(&self, session: &str, items: &[LeaseItem], now_ms: i64) -> bool {
        self.active_leases(now_ms)
            .filter(|h| h.lease.session != session)
            .any(|h| {
                h.items
                    .iter()
                    .any(|b| items.iter().any(|a| self.conflict(a, b)))
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
                        .any(|b| i.items.iter().any(|a| self.conflict(a, b)))
            };
            let mut older = self.interests.range(..seq).map(|(_, o)| o);
            if self.session_present(&i.session, now_ms)
                && !self.held_against(&i.session, &i.items, now_ms)
                && !out.iter().any(reserved)
                && !older.any(|o| self.stops(o, &i.session, &i.items, now_ms))
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

    /// `interest`, of another session, stands in the way of new leases on
    /// `items` at `now_ms`.
    fn stops(&self, interest: &Interest, session: &str, items: &[LeaseItem], now_ms: i64) -> bool {
        interest.session != session
            && interest.blocks_until_ms > now_ms
            && self.session_present(&interest.session, now_ms)
            && self.clash(&interest.items, items)
    }

    /// Of `items`, what `session` does not have yet: neither held (a partial
    /// release acquires the rest again) nor reserved for it.
    pub fn new_items(&self, session: &str, items: &[LeaseItem], now_ms: i64) -> Vec<LeaseItem> {
        let keys = self.symbol_keys;
        let reservations = self.reservations_at(now_ms);
        let reserved = |i: &LeaseItem| {
            let mut mine = reservations.iter().filter(|r| r.session == session);
            mine.any(|r| {
                r.items
                    .iter()
                    .any(|b| symbols::covers(&b.symbol, &i.symbol, keys))
            })
        };
        let new = items
            .iter()
            .filter(|i| !self.holds(session, i, now_ms) && !reserved(i));
        new.cloned().collect()
    }

    /// The waiting interests of other sessions that stop new leases on
    /// `items`, oldest first. An interest that has its reservation at
    /// `now_ms` is not here: it is a reservation now.
    pub fn wanted_against(
        &self,
        session: &str,
        items: &[LeaseItem],
        now_ms: i64,
    ) -> Vec<&Interest> {
        let new = self.new_items(session, items, now_ms);
        let served = self.settled(now_ms).1;
        // An interest goes first over those younger than it, so a younger
        // one does not stop it.
        let behind = |seq: &u64, i: &Interest| {
            let mut older = self.interests.range(..seq).map(|(_, o)| o);
            older.any(|o| o.session == session && self.clash(&o.items, &i.items))
        };
        let waiting = self.interests.iter();
        let waiting = waiting.filter(|(seq, _)| !served.contains(seq));
        let stopping =
            waiting.filter(|(seq, i)| self.stops(i, session, &new, now_ms) && !behind(seq, i));
        stopping.map(|(_, i)| i).collect()
    }

    /// Something other sessions have or are first in line for conflicts
    /// with `items`: there is something to wait for.
    pub fn taken(&self, session: &str, items: &[LeaseItem], now_ms: i64) -> bool {
        self.held_against(session, items, now_ms)
            || self.reserved_against(session, items, now_ms).is_some()
            || !self.wanted_against(session, items, now_ms).is_empty()
    }

    /// `session` holds exactly `item` at `now_ms`.
    pub fn holds(&self, session: &str, item: &LeaseItem, now_ms: i64) -> bool {
        self.active_leases(now_ms)
            .any(|h| h.lease.session == session && h.items.contains(&item))
    }

    /// `session` already waits for something that overlaps `items`.
    pub fn waiting(&self, session: &str, items: &[LeaseItem]) -> bool {
        let keys = self.symbol_keys;
        self.interests.values().any(|i| {
            i.session == session
                && i.items.iter().any(|b| {
                    items
                        .iter()
                        .any(|a| symbols::overlaps(&a.symbol, &b.symbol, keys))
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
                        .any(|b| items.iter().any(|a| self.conflict(a, b)))
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

    /// What was waited for is in hand. Part of it does not end the wait of
    /// an interest of format 12 on: it keeps its place, and its session can
    /// not register a new one to start the cap again.
    fn acquired(&mut self, session: &str, items: &[LeaseItem]) {
        let keys = self.symbol_keys;
        let overlaps = |theirs: &[LeaseItem]| {
            theirs.iter().any(|b| {
                items
                    .iter()
                    .any(|a| symbols::overlaps(&a.symbol, &b.symbol, keys))
            })
        };
        self.reservations
            .retain(|r| r.session != session || !overlaps(&r.items));
        let in_hand = |i: &Interest| {
            if i.blocks_until_ms == 0 {
                return overlaps(&i.items);
            }
            let covered = |b: &LeaseItem| {
                let mut got = items.iter();
                got.any(|a| symbols::covers(&a.symbol, &b.symbol, keys))
            };
            i.items.iter().all(covered)
        };
        self.interests
            .retain(|_, i| i.session != session || !in_hand(i));
    }

    /// When an interest in `items` stops stopping others, at most `limit`:
    /// nothing that runs into the same set or an older interest goes past
    /// what they got, so a line of interests does not stretch the cap. Sets
    /// that had no such time get this one.
    fn block_end(&mut self, session: &str, items: &[LeaseItem], now_ms: i64, limit: i64) -> i64 {
        let sets: Vec<&LeaseSet> = self
            .active_leases(now_ms)
            .filter(|h| h.lease.session != session)
            .filter(|h| {
                h.items
                    .iter()
                    .any(|b| items.iter().any(|a| self.conflict(a, b)))
            })
            .map(|h| h.lease)
            .collect();
        let names: Vec<String> = sets.iter().map(|l| l.set.clone()).collect();
        let earlier = sets.iter().filter_map(|l| l.stop_until_ms);
        let older = self
            .interests
            .values()
            .filter(|i| self.clash(&i.items, items));
        let older = older.map(|i| i.blocks_until_ms);
        let end = earlier.chain(older).fold(limit, i64::min);
        for set in names {
            if let Some(l) = self.leases.get_mut(&set) {
                l.stop_until_ms.get_or_insert(end);
            }
        }
        end
    }

    /// A new set over what the session holds goes on being wanted, as its
    /// hold goes on: a fresh id resets neither the hold limit nor the cap.
    fn carry_wanted(&mut self, set: &str, now_ms: i64) {
        let keys = self.symbol_keys;
        let Some(new) = self.leases.get(set) else {
            return;
        };
        let overlapping = |h: &ActiveLease| {
            h.lease.session == new.session
                && h.lease.set != set
                && h.items.iter().any(|b| {
                    let mut items = new.items.iter();
                    items.any(|a| symbols::overlaps(&a.symbol, &b.symbol, keys))
                })
        };
        let mut interest = BTreeMap::new();
        let mut stop_until_ms = None;
        for h in self.active_leases(now_ms).filter(overlapping) {
            for (session, at) in &h.lease.interest {
                let last = interest.entry(session.clone()).or_insert(*at);
                *last = (*last).max(*at);
            }
            stop_until_ms = stop_until_ms.into_iter().chain(h.lease.stop_until_ms).min();
        }
        if let Some(l) = self.leases.get_mut(set) {
            l.interest = interest;
            l.stop_until_ms = stop_until_ms;
        }
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
        self.symbol_keys = e.format >= FORMAT_SYMBOL_KEYS;
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
            Outcome::Allow => {
                self.effects(
                    &e.actor,
                    &e.op,
                    e.facts.as_ref(),
                    e.seq,
                    e.time_ms,
                    &e.decision.reasons,
                    false,
                );
                if let Op::LeaseAcquire { set, .. } = &e.op
                    && e.format >= FORMAT_LEASE_INTENT
                {
                    self.carry_wanted(set, e.time_ms);
                }
            }
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
                        .all(|r| r.starts_with("lease_held:") || r.starts_with("lease_wanted:"))
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
                .any(|b| mine().any(|a| self.conflict(a, b)))
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
                let items = items.filter(|i| needs.iter().any(|n| self.covers_need(n, i, None)));
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
        let keys = self.symbol_keys;
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
                                    .any(|a| symbols::overlaps(&a.symbol, &b.symbol, keys))
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
                            stop_until_ms: None,
                            delegated_from: None,
                        },
                    );
                    self.acquired(session, items);
                }
            }
            Op::LeaseInterest { items, intent } => {
                if let Some(session) = actor.session() {
                    let value = |key: &str| -> Option<i64> {
                        let found = reasons.iter().find_map(|r| r.strip_prefix(key));
                        found.and_then(|n| n.parse().ok())
                    };
                    let block = value(INTEREST_BLOCK);
                    let end = block.map(|ms| time_ms + ms);
                    let end = end.map(|e| self.block_end(session, items, time_ms, e));
                    self.interests.insert(
                        seq,
                        Interest {
                            session: session.to_string(),
                            items: items.clone(),
                            intent: intent.clone(),
                            window_ms: value(RESERVATION_WINDOW).unwrap_or_default(),
                            blocks_until_ms: end.unwrap_or_default(),
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
                    let facts = c.facts.clone();
                    if c.claim.revert_of.is_some() {
                        let mut syms = facts.edits.clone();
                        syms.extend(facts.deletes.iter().cloned());
                        syms.extend(facts.adds.iter().cloned());
                        self.reverts.push((time_ms, syms));
                    }
                    self.record_renames(&facts);
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
                        let now: Vec<String> =
                            symbols.iter().map(|s| self.renamed_to(s, None)).collect();
                        let covers = |l: &LeaseSet| {
                            l.items.iter().any(|i| {
                                let all = symbols.iter().chain(&now);
                                all.into_iter().any(|s| symbols::covers(&i.symbol, s, keys))
                            })
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
                            l.stop_until_ms = None;
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
