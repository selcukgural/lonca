//! What a client reads to recover from a lease denial, or to avoid one.
//!
//! `Decision::reasons` are logged and replayed, so they stay short strings.
//! These details are derived from the state after the decision: they are
//! never logged and never an input of `decide()`. Free text (the intent) is
//! a field of its own, so nobody has to split a string to find it.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ChangeId;
use lonca_core::keyed::KeyedDirs;
use lonca_core::oplog::FORMAT_CURRENT;
use lonca_core::ops::{Facts, LeaseItem, LeaseKind};
use serde::Serialize;

use crate::config::UnparsedFiles;
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
    /// For a free `insert`: the names to reserve for what the change adds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
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
            names: Vec::new(),
        }
    }

    fn held(state: &State, by: &ActiveLease, item: &LeaseItem, needed_kind: LeaseKind) -> Self {
        let l = by.lease;
        let pin = l.pins.iter().find(|(_, items)| items.contains(item));
        Self {
            code: LEASE_HELD,
            symbol: item.symbol.clone(),
            needed_kind,
            holder_session: Some(by.holder.to_string()),
            holder_agent: state.sessions.get(by.holder).map(|s| s.agent.clone()),
            intent: Some(state.intent_for_agents(by.holder, &l.intent).to_string()),
            expires_ms: pin.is_none().then_some(l.expires_ms),
            set: Some(l.set.clone()),
            pinned_to: pin.map(|(change, _)| *change),
            names: Vec::new(),
        }
    }
}

/// What other sessions hold that conflicts with `wanted`, one entry per
/// held item however many of `wanted` run into it.
pub fn lease_held(state: &State, session: &str, wanted: &[LeaseItem], now_ms: i64) -> Vec<Detail> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for held in state.active_leases(now_ms) {
        if held.holder == session {
            continue;
        }
        for a in wanted {
            for b in held.items.iter().filter(|b| state.conflict(a, b)) {
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
            for b in r.items.iter().filter(|b| state.conflict(a, b)) {
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
            for b in i.items.iter().filter(|b| state.conflict(a, b)) {
                out.push(Detail {
                    holder_session: Some(i.session.clone()),
                    holder_agent: state.sessions.get(&i.session).map(|s| s.agent.clone()),
                    intent: Some(state.intent_for_agents(&i.session, &i.intent).to_string()),
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
pub fn lease_report(
    state: &State,
    session: &str,
    facts: &Facts,
    unparsed: UnparsedFiles,
    now_ms: i64,
) -> Vec<Detail> {
    let leases: Vec<ActiveLease> = state
        .active_leases(now_ms)
        .filter(|l| l.holder == session)
        .collect();
    let mine = || leases.iter().flat_map(|l| l.items.iter().copied());
    let mut out = Vec::new();
    for need in symbols::lease_needs_under(facts, unparsed, FORMAT_CURRENT) {
        let Some(&kind) = need.kinds.first() else {
            continue;
        };
        if mine().any(|i| state.covers_need(&need, i, None)) {
            out.push(Detail::free(HELD_BY_YOU, &need.symbol, kind));
            continue;
        }
        // What the change adds is asked for by name, so a name another
        // session reserved shows who did.
        let names: Vec<String> = symbols::reserved_name(&need).into_iter().collect();
        let item = LeaseItem {
            symbol: need.symbol.clone(),
            kind,
            names: names.clone(),
        };
        let wanted = std::slice::from_ref(&item);
        let mut blockers = lease_held(state, session, wanted, now_ms);
        blockers.extend(lease_wanted(state, session, wanted, now_ms));
        if blockers.is_empty() {
            out.push(Detail {
                names,
                ..Detail::free(FREE, &need.symbol, kind)
            });
        }
        out.extend(blockers);
    }
    out
}

/// The keys the files a change adds to keyed directories need: per file an
/// `insert` on its directory's `dir#<dir>` with its key in `names`, and
/// where it stands, as [`lease_report`] says it of symbols.
pub fn key_report(
    state: &State,
    session: &str,
    facts: &Facts,
    keyed: &KeyedDirs,
    now_ms: i64,
) -> Vec<Detail> {
    let mine: Vec<LeaseItem> = state
        .active_leases(now_ms)
        .filter(|l| l.holder == session)
        .flat_map(|l| l.items.into_iter().cloned())
        .collect();
    let mut out = Vec::new();
    for path in &facts.added_files {
        let Some((d, name)) = keyed.of(path) else {
            continue;
        };
        let Some(key) = d.key_of(name) else {
            continue;
        };
        let item = LeaseItem {
            symbol: d.container(),
            kind: LeaseKind::Insert,
            names: vec![key.clone()],
        };
        let held = |i: &LeaseItem| {
            i.kind == LeaseKind::Insert && i.symbol == item.symbol && i.names.contains(&key)
        };
        if mine.iter().any(held) {
            out.push(Detail::free(HELD_BY_YOU, &item.symbol, LeaseKind::Insert));
            continue;
        }
        let wanted = std::slice::from_ref(&item);
        let mut blockers = lease_held(state, session, wanted, now_ms);
        blockers.extend(lease_wanted(state, session, wanted, now_ms));
        if blockers.is_empty() {
            out.push(Detail {
                names: item.names.clone(),
                ..Detail::free(FREE, &item.symbol, LeaseKind::Insert)
            });
        }
        out.extend(blockers);
    }
    out
}

/// The leases a refused proposal lacks, with whoever holds them.
pub fn lease_missing(
    state: &State,
    session: &str,
    facts: &Facts,
    unparsed: UnparsedFiles,
    now_ms: i64,
) -> Vec<Detail> {
    let report = lease_report(state, session, facts, unparsed, now_ms);
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
    let first = of.first();
    let agent = first
        .and_then(|d| d.holder_agent.as_deref())
        .unwrap_or("Another agent");
    let intent = of.iter().find_map(|d| d.intent.as_deref());
    let mut out = match intent {
        Some(intent) if first.is_some_and(|d| d.code == LEASE_WANTED) => format!(
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

/// What to pass to `lease.acquire` for what a report says is free: one item
/// per symbol and kind, with every name the additions under it take. One
/// addition no name stands for leaves the item unnamed, which covers all.
pub fn to_acquire(report: &[Detail]) -> Vec<LeaseItem> {
    let mut items: BTreeMap<(String, LeaseKind), Option<BTreeSet<String>>> = BTreeMap::new();
    for d in report.iter().filter(|d| d.code == FREE) {
        let key = (d.symbol.clone(), d.needed_kind);
        let names = items.entry(key).or_insert_with(|| Some(BTreeSet::new()));
        match (names.as_mut(), d.names.is_empty()) {
            (Some(_), true) => *names = None,
            (Some(set), false) => set.extend(d.names.iter().cloned()),
            (None, _) => {}
        }
    }
    let items = items.into_iter().map(|((symbol, kind), names)| LeaseItem {
        symbol,
        kind,
        names: names.unwrap_or_default().into_iter().collect(),
    });
    items.collect()
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

    /// A free insert is offered with the names the additions under it take;
    /// one addition no name stands for leaves it unnamed.
    #[test]
    fn a_free_insert_is_offered_with_the_names_it_needs() {
        let free = |symbol: &str, kind, names: &[&str]| Detail {
            names: names.iter().map(|n| n.to_string()).collect(),
            ..Detail::free(FREE, symbol, kind)
        };
        let report = [
            free("a.rs#T", LeaseKind::Insert, &["m"]),
            free("a.rs#T", LeaseKind::Insert, &["n"]),
            free("a.rs#T", LeaseKind::Insert, &["m"]),
            free("a.rs#<file>", LeaseKind::Insert, &["f"]),
            free("a.rs#<file>", LeaseKind::Insert, &[]),
            free("a.rs#<file>", LeaseKind::Insert, &["g"]),
            free("a.rs#g", LeaseKind::Edit, &[]),
            held("a.rs#U", "s"),
        ];
        let item = |symbol: &str, kind, names: &[&str]| LeaseItem {
            symbol: symbol.into(),
            kind,
            names: names.iter().map(|n| n.to_string()).collect(),
        };
        assert_eq!(
            to_acquire(&report),
            [
                item("a.rs#<file>", LeaseKind::Insert, &[]),
                item("a.rs#T", LeaseKind::Insert, &["m", "n"]),
                item("a.rs#g", LeaseKind::Edit, &[]),
            ]
        );
    }
}
