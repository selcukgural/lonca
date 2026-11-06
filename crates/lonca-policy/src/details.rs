//! What a client reads to recover from a lease denial, or to avoid one.
//!
//! `Decision::reasons` are logged and replayed, so they stay short strings.
//! These details are derived from the state after the decision: they are
//! never logged and never an input of `decide()`. Free text (the intent) is
//! a field of its own, so nobody has to split a string to find it.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ChangeId;
use lonca_core::ops::{Facts, LeaseItem, LeaseKind};
use serde::Serialize;

use crate::decide::leases_conflict;
use crate::state::{ActiveLease, State};
use crate::symbols;

pub const LEASE_HELD: &str = "lease_held";
pub const LEASE_RESERVED: &str = "lease_reserved";
/// Nobody holds it, but a session is waiting for it and goes first.
pub const LEASE_WANTED: &str = "lease_wanted";
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
            for b in held
                .items
                .iter()
                .filter(|b| leases_conflict(a, b, state.symbol_keys))
            {
                if seen.insert((held.lease.set.clone(), b.symbol.clone())) {
                    out.push(Detail::held(state, &held, b, a.kind));
                }
            }
        }
    }
    out
}

/// The reservations of other sessions in the way of `wanted`.
pub fn lease_reserved(
    state: &State,
    session: &str,
    wanted: &[LeaseItem],
    now_ms: i64,
) -> Vec<Detail> {
    let reservations = state.reservations_at(now_ms);
    let theirs = reservations.iter().filter(|r| r.session != session);
    let mut out = Vec::new();
    for r in theirs {
        for a in wanted {
            for b in r
                .items
                .iter()
                .filter(|b| leases_conflict(a, b, state.symbol_keys))
            {
                out.push(Detail {
                    holder_session: Some(r.session.clone()),
                    holder_agent: state.sessions.get(&r.session).map(|s| s.agent.clone()),
                    expires_ms: Some(r.until_ms),
                    ..Detail::free(LEASE_RESERVED, &b.symbol, a.kind)
                });
            }
        }
    }
    out
}

/// The waiting interests of other sessions that stop `wanted`, with what
/// they said they need it for. `expires_ms` is when they stop stopping it.
pub fn lease_wanted(
    state: &State,
    session: &str,
    wanted: &[LeaseItem],
    now_ms: i64,
) -> Vec<Detail> {
    let new = state.new_items(session, wanted, now_ms);
    let mut out = Vec::new();
    for i in state.wanted_against(session, wanted, now_ms) {
        for a in &new {
            for b in i
                .items
                .iter()
                .filter(|b| leases_conflict(a, b, state.symbol_keys))
            {
                out.push(Detail {
                    holder_session: Some(i.session.clone()),
                    holder_agent: state.sessions.get(&i.session).map(|s| s.agent.clone()),
                    intent: Some(i.intent.clone()),
                    expires_ms: Some(i.blocks_until_ms),
                    ..Detail::free(LEASE_WANTED, &b.symbol, a.kind)
                });
            }
        }
    }
    out
}

/// Every lease the facts need, and where it stands: `held_by_you`, `free`,
/// or one `lease_held` per holder and one `lease_wanted` per session that
/// goes first.
pub fn lease_report(state: &State, session: &str, facts: &Facts, now_ms: i64) -> Vec<Detail> {
    let leases: Vec<ActiveLease> = state
        .active_leases(now_ms)
        .filter(|l| l.lease.session == session)
        .collect();
    let mine = || leases.iter().flat_map(|l| l.items.iter().copied());
    let mut out = Vec::new();
    for need in symbols::lease_needs(facts) {
        let kind = need.kinds[0];
        if mine().any(|i| need.covered_by(i, state.symbol_keys)) {
            out.push(Detail::free(HELD_BY_YOU, &need.symbol, kind));
            continue;
        }
        let item = LeaseItem {
            symbol: need.symbol.clone(),
            kind,
        };
        let wanted = std::slice::from_ref(&item);
        let mut blockers = lease_held(state, session, wanted, now_ms);
        blockers.extend(lease_wanted(state, session, wanted, now_ms));
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
            code: if d.code == LEASE_WANTED {
                LEASE_WANTED
            } else {
                LEASE_MISSING
            },
            ..d
        })
        .collect()
}

/// One holder in plain words.
fn holder_sentence(session: &str, of: &[&Detail]) -> String {
    let symbols: Vec<&str> = of.iter().map(|d| d.symbol.as_str()).collect();
    let symbols = symbols.join(", ");
    let agent = of[0].holder_agent.as_deref().unwrap_or("Another agent");
    let intent = of.iter().find_map(|d| d.intent.as_deref());
    let mut out = match intent {
        Some(intent) if of[0].code == LEASE_WANTED => format!(
            "{agent} (session {session}) is waiting for {symbols} and goes first: {intent:?}."
        ),
        Some(intent) => format!("{agent} (session {session}) is on {symbols}: {intent:?}."),
        None => format!("{symbols} is reserved for {agent} (session {session})."),
    };
    if of.iter().any(|d| d.pinned_to.is_some()) {
        out.push_str(" Part of it belongs to a change in the merge queue and frees when that change leaves the queue.");
    }
    out
}

/// A denial in plain words: who is on it, and to settle it between you. Free
/// text from `details`, so it is derived and never logged, like them. `None`
/// when nobody stands in the way.
pub fn advice(details: &[Detail]) -> Option<String> {
    let mut holders: BTreeMap<(&str, bool), Vec<&Detail>> = BTreeMap::new();
    for d in details {
        if let Some(session) = &d.holder_session {
            let key = (session.as_str(), d.code == LEASE_WANTED);
            holders.entry(key).or_default().push(d);
        }
    }
    if holders.is_empty() {
        return None;
    }
    let mut out: Vec<String> = holders
        .iter()
        .map(|((session, _), of)| holder_sentence(session, of))
        .collect();
    out.push("Do not edit these. Settle it between you: tell that agent what you need and why with negotiate, to_session as above. Or lease_interest puts you next. Go on with other work meanwhile.".into());
    Some(out.join(" "))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn held(symbol: &str, session: &str) -> Detail {
        Detail {
            holder_session: Some(session.into()),
            holder_agent: Some("bot".into()),
            intent: Some("fix".into()),
            ..Detail::free(LEASE_HELD, symbol, LeaseKind::Edit)
        }
    }

    #[test]
    fn nobody_in_the_way_is_no_advice() {
        assert_eq!(advice(&[]), None);
        let free = Detail::free(FREE, "a.rs#f", LeaseKind::Edit);
        assert_eq!(advice(&[free]), None);
    }

    #[test]
    fn each_holder_is_named_once_with_what_it_holds() {
        let text = advice(&[
            held("a.rs#f", "s1"),
            held("a.rs#g", "s1"),
            held("a.rs#h", "s2"),
        ]);
        let text = text.unwrap();
        assert!(
            text.contains("bot (session s1) is on a.rs#f, a.rs#g: \"fix\"."),
            "{text}"
        );
        assert!(text.contains("bot (session s2) is on a.rs#h"), "{text}");
        assert_eq!(text.matches("Settle it between you").count(), 1, "{text}");
        assert!(!text.contains("merge queue"), "{text}");
    }

    #[test]
    fn who_waits_is_told_apart_from_who_holds() {
        let wanted = Detail {
            code: LEASE_WANTED,
            ..held("a.rs#Type", "s1")
        };
        let text = advice(&[held("a.rs#f", "s1"), wanted]).unwrap();
        assert!(text.contains("is on a.rs#f: \"fix\"."), "{text}");
        assert!(
            text.contains("is waiting for a.rs#Type and goes first: \"fix\"."),
            "{text}"
        );
    }

    #[test]
    fn a_reservation_and_a_pin_are_said_for_what_they_are() {
        let reserved = Detail {
            holder_session: Some("s1".into()),
            ..Detail::free(LEASE_RESERVED, "a.rs#f", LeaseKind::Edit)
        };
        let text = advice(&[reserved]).unwrap();
        assert!(
            text.contains("a.rs#f is reserved for Another agent (session s1)."),
            "{text}"
        );

        let pinned = Detail {
            pinned_to: Some(ChangeId::random()),
            ..held("a.rs#g", "s1")
        };
        let text = advice(&[held("a.rs#f", "s1"), pinned]).unwrap();
        assert!(text.contains("merge queue"), "{text}");
    }
}
