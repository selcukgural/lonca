//! What another policy would have decided: every entry of a log decided
//! again with a candidate policy, and the decisions that come out different.
//!
//! Each entry is decided on the state the log really had before it, so the
//! answer is "which of these requests would this policy have treated
//! differently", one request at a time. It does not follow the consequences:
//! a change the candidate would have denied is still integrated in the state
//! the next entries are decided on. Nothing is written; `lonca policy check`
//! uses it before `lonca policy set`.

use lonca_core::oplog::{FORMAT_CURRENT, SignedOp};
use lonca_core::ops::{Actor, Decision};
use serde::Serialize;

use crate::config::{CedarOutcome, PolicyBundle};
use crate::decide::{Ctx, decide, session_context};
use crate::state::State;

/// What a human must keep being able to request: change the policy back,
/// unfreeze, answer what waits for them, replace a key. A policy that
/// denies one of them can leave no way back (undoing a policy is itself a
/// `policy.update`). Escalating one is fine: it still happens.
pub const WAYS_OUT: [&str; 8] = [
    "policy.update",
    "unfreeze",
    "approve",
    "reject",
    "human.rotate",
    "human.recover",
    "daemon.rotate",
    "daemon.recover",
];

/// One entry the candidate decides differently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Difference {
    pub seq: u64,
    pub time_ms: i64,
    /// The operation, as `OpKind::as_str` names it.
    pub op: String,
    /// The requester, as `Actor::label` writes it.
    pub actor: String,
    /// What the log says.
    pub recorded: Decision,
    /// What the candidate decides.
    pub candidate: Decision,
}

/// One of [`WAYS_OUT`] the candidate denies an enrolled human.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Lockout {
    pub human: String,
    pub action: String,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Comparison {
    /// Entries decided again: the whole log.
    pub entries: u64,
    pub differences: Vec<Difference>,
    /// Ways out the candidate would close, for the humans enrolled at the
    /// end of the log.
    pub lockouts: Vec<Lockout>,
}

/// Decides every entry of `ops` (a whole log, from genesis) again with
/// `candidate` and lists those whose decision would change, in log order.
pub fn compare(ops: &[SignedOp], candidate: &PolicyBundle) -> Comparison {
    let mut state = State::new();
    let mut out = Comparison::default();
    for op in ops {
        let e = &op.entry;
        let d = decide(
            &state,
            &e.actor,
            &e.op,
            e.human.as_ref(),
            &Ctx {
                format: e.format,
                time_ms: e.time_ms,
                policy: candidate,
                facts: e.facts.as_ref(),
                evidence: &e.evidence,
                symbols_engine: e.symbols_engine,
            },
        );
        if d != e.decision {
            out.differences.push(Difference {
                seq: e.seq,
                time_ms: e.time_ms,
                op: e.op.kind().as_str().into(),
                actor: e.actor.label(),
                recorded: e.decision.clone(),
                candidate: d,
            });
        }
        out.entries += 1;
        state.apply(op);
    }
    out.lockouts = lockouts(&state, candidate);
    out
}

/// Each of [`WAYS_OUT`] the candidate's rules deny an enrolled human, asked
/// as `decide()` asks them now.
pub fn lockouts(state: &State, candidate: &PolicyBundle) -> Vec<Lockout> {
    let mut out = Vec::new();
    for name in state.humans.keys() {
        let human = Actor::Human { name: name.clone() };
        for action in WAYS_OUT {
            let context = session_context(state, &human, FORMAT_CURRENT);
            if let CedarOutcome::Deny(reasons) = candidate.evaluate(&human, action, context) {
                out.push(Lockout {
                    human: name.clone(),
                    action: action.into(),
                    reasons,
                });
            }
        }
    }
    out
}
