//! What a client reads to recover from a lease denial, or to avoid one.
//!
//! `Decision::reasons` are logged and replayed, so they stay short strings.
//! These details are derived from the state after the decision: they are
//! never logged and never an input of `decide()`. Free text (the intent) is
//! a field of its own, so nobody has to split a string to find it.

use std::collections::BTreeSet;

use lonca_core::ChangeId;
use lonca_core::ops::{Facts, LeaseItem, LeaseKind};
use serde::Serialize;

use crate::decide::leases_conflict;
use crate::state::{ActiveLease, State};
use crate::symbols;

pub const LEASE_HELD: &str = "lease_held";
pub const LEASE_MISSING: &str = "lease_missing";
/// The session holds what a change needs.
pub const HELD_BY_YOU: &str = "held_by_you";
/// Nobody holds it: it can be acquired.
pub const FREE: &str = "free";

/// One symbol, the kind that is needed, and who stands in the way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Detail {
    pub code: &'static str,
    pub symbol: String,
    pub needed_kind: LeaseKind,
    pub holder_session: Option<String>,
    pub holder_agent: Option<String>,
    pub intent: Option<String>,
    /// When the holder's set runs out; `None` for a pinned item, which
    /// does not expire: wait for `pinned_to` instead.
    pub expires_ms: Option<i64>,
    pub set: Option<String>,
    pub pinned_to: Option<ChangeId>,
}

impl Detail {
    fn free(code: &'static str, symbol: &str, needed_kind: LeaseKind) -> Self {
        Self {
            code,
            symbol: symbol.to_string(),
            needed_kind,
            holder_session: None,
            holder_agent: None,
            intent: None,
            expires_ms: None,
            set: None,
            pinned_to: None,
        }
    }

    fn held(state: &State, by: &ActiveLease, item: &LeaseItem, needed_kind: LeaseKind) -> Self {
        let l = by.lease;
        let pin = l.pins.iter().find(|(_, items)| items.contains(item));
        Self {
            code: LEASE_HELD,
            symbol: item.symbol.clone(),
            needed_kind,
            holder_session: Some(l.session.clone()),
            holder_agent: state.sessions.get(&l.session).map(|s| s.agent.clone()),
            intent: Some(l.intent.clone()),
            expires_ms: pin.is_none().then_some(l.expires_ms),
            set: Some(l.set.clone()),
            pinned_to: pin.map(|(change, _)| *change),
        }
    }
}

/// What other sessions hold that conflicts with `wanted`, one entry per
/// held item however many of `wanted` run into it.
pub fn lease_held(state: &State, session: &str, wanted: &[LeaseItem], now_ms: i64) -> Vec<Detail> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for held in state.active_leases(now_ms) {
        if held.lease.session == session {
            continue;
        }
        for a in wanted {
            for b in held.items.iter().filter(|b| leases_conflict(a, b)) {
                if seen.insert((held.lease.set.clone(), b.symbol.clone())) {
                    out.push(Detail::held(state, &held, b, a.kind));
                }
            }
        }
    }
    out
}

/// Every lease the facts need, and where it stands: `held_by_you`, `free`,
/// or one `lease_held` per holder.
pub fn lease_report(state: &State, session: &str, facts: &Facts, now_ms: i64) -> Vec<Detail> {
    let leases: Vec<ActiveLease> = state
        .active_leases(now_ms)
        .filter(|l| l.lease.session == session)
        .collect();
    let mine = || leases.iter().flat_map(|l| l.items.iter().copied());
    let mut out = Vec::new();
    for need in symbols::lease_needs(facts) {
        let kind = need.kinds[0];
        if mine().any(|i| need.covered_by(i)) {
            out.push(Detail::free(HELD_BY_YOU, &need.symbol, kind));
            continue;
        }
        let item = LeaseItem {
            symbol: need.symbol.clone(),
            kind,
        };
        let blockers = lease_held(state, session, std::slice::from_ref(&item), now_ms);
        if blockers.is_empty() {
            out.push(Detail::free(FREE, &need.symbol, kind));
        }
        out.extend(blockers);
    }
    out
}

/// The leases a refused proposal lacks, with whoever holds them.
pub fn lease_missing(state: &State, session: &str, facts: &Facts, now_ms: i64) -> Vec<Detail> {
    let report = lease_report(state, session, facts, now_ms);
    let missing = report.into_iter().filter(|d| d.code != HELD_BY_YOU);
    missing
        .map(|d| Detail {
            code: LEASE_MISSING,
            ..d
        })
        .collect()
}

/// What to pass to `lease.acquire` for what a report says is free.
pub fn to_acquire(report: &[Detail]) -> Vec<LeaseItem> {
    let free = report.iter().filter(|d| d.code == FREE);
    let items = free.map(|d| LeaseItem {
        symbol: d.symbol.clone(),
        kind: d.needed_kind,
    });
    items.collect::<BTreeSet<_>>().into_iter().collect()
}
