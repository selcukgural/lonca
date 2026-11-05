//! A session's inbox: what happened that it should know of, derived from the
//! log and the state. Nothing is written for it, so the single writer stays
//! the only way into the log, and `decide()` never reads it.

use lonca_core::ChangeId;
use lonca_core::oplog::SignedOp;
use lonca_core::ops::{LeaseItem, NegotiationMsg, Op};
use serde::Serialize;

use crate::state::State;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Event {
    /// A change of this session (or the workspace's earlier ones) landed.
    Integrated { seq: u64, change: ChangeId },
    /// It did not: the merge conflicted.
    Conflicted {
        seq: u64,
        change: ChangeId,
        conflicts: Vec<String>,
    },
    /// It merged, and the decision refused it: failed verification.
    Failed {
        seq: u64,
        change: ChangeId,
        reasons: Vec<String>,
    },
    /// A human approved it, or said why not.
    Approved { seq: u64, target_seq: u64 },
    Rejected {
        seq: u64,
        target_seq: u64,
        reason: String,
    },
    /// Another session wrote to this one.
    Message {
        seq: u64,
        thread: String,
        from: Option<String>,
    },
    /// A lease set is this session's now, from a yield or a delegation.
    LeaseReceived {
        seq: u64,
        set: String,
        from: Option<String>,
    },
    /// Freed and held for this session until `until_ms`. Not from the log:
    /// it is the state now, so it is reported however far `from` is.
    Reserved {
        items: Vec<LeaseItem>,
        until_ms: i64,
    },
}

fn own_change(state: &State, session: &str, change: &ChangeId) -> bool {
    let by = state.changes.get(change).and_then(|c| c.actor.session());
    by.is_some_and(|s| state.continues(session, s))
}

/// The session a request in the log came from, when one did.
fn requester(ops: &[SignedOp], first: u64, target_seq: u64) -> Option<&str> {
    let i = target_seq.checked_sub(first)? as usize;
    ops.get(i)?.entry.actor.session()
}

/// The events of `session` in `ops`, which start at sequence `ops[0]`, then
/// what the state holds for it at `now_ms`.
pub fn for_session(state: &State, session: &str, ops: &[SignedOp], now_ms: i64) -> Vec<Event> {
    let first = ops.first().map_or(0, |o| o.entry.seq);
    let mine = |target_seq: u64| {
        requester(ops, first, target_seq).is_some_and(|s| state.continues(session, s))
    };
    let mut out = Vec::new();
    for o in ops {
        let e = &o.entry;
        let seq = e.seq;
        // A failed integration is logged as a denial: that is the news.
        if let Op::ChangeIntegrate {
            change,
            merged,
            conflicts,
            ..
        } = &e.op
        {
            if own_change(state, session, change) {
                let change = *change;
                out.push(match (merged, e.decision.is_allow()) {
                    (None, _) => Event::Conflicted {
                        seq,
                        change,
                        conflicts: conflicts.clone(),
                    },
                    (Some(_), true) => Event::Integrated { seq, change },
                    (Some(_), false) => Event::Failed {
                        seq,
                        change,
                        reasons: e.decision.reasons.clone(),
                    },
                });
            }
            continue;
        }
        if !e.decision.is_allow() {
            continue;
        }
        let sender = e.actor.session().map(String::from);
        match &e.op {
            Op::Approve { target_seq, .. } if mine(*target_seq) => out.push(Event::Approved {
                seq,
                target_seq: *target_seq,
            }),
            Op::Reject { target_seq, reason } if mine(*target_seq) => out.push(Event::Rejected {
                seq,
                target_seq: *target_seq,
                reason: reason.clone(),
            }),
            Op::Negotiate {
                thread,
                to_session,
                message,
            } if to_session == session => {
                if let NegotiationMsg::Yield { set, to: Some(_) } = message {
                    out.push(Event::LeaseReceived {
                        seq,
                        set: set.clone(),
                        from: sender.clone(),
                    });
                }
                out.push(Event::Message {
                    seq,
                    thread: thread.clone(),
                    from: sender,
                });
            }
            Op::CapAttenuate { child, leases, .. } if child == session => {
                for set in leases {
                    out.push(Event::LeaseReceived {
                        seq,
                        set: set.clone(),
                        from: sender.clone(),
                    });
                }
            }
            _ => {}
        }
    }
    let reserved = state.reservations_at(now_ms);
    let reserved = reserved.into_iter().filter(|r| r.session == session);
    out.extend(reserved.map(|r| Event::Reserved {
        items: r.items,
        until_ms: r.until_ms,
    }));
    out
}
