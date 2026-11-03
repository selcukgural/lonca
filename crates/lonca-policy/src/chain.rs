//! The single-writer sequencer: decide, sign, apply.
//!
//! The daemon persists each prepared entry to the store before committing it
//! to memory, so a failed write never leaves memory ahead of the log.

use std::sync::Arc;

use lonca_core::keys::KeyPair;
use lonca_core::oplog::{FORMAT_CURRENT, OpEntry, SignedOp};
use lonca_core::ops::{Actor, Attestation, Facts, HumanSignature, Op};
use lonca_core::{Error, GitId, Result};

use crate::config::PolicyBundle;
use crate::decide::{Ctx, decide};
use crate::state::State;

#[derive(Clone, Debug)]
pub struct Submission {
    pub actor: Actor,
    pub op: Op,
    pub human: Option<HumanSignature>,
    pub facts: Option<Facts>,
    /// Symbol engine version that computed `facts` or the merge; set by the
    /// daemon on proposals and integrations.
    pub symbols_engine: Option<u32>,
    pub evidence: Vec<Attestation>,
}

impl Submission {
    pub fn new(actor: Actor, op: Op) -> Self {
        Self {
            actor,
            op,
            human: None,
            facts: None,
            symbols_engine: None,
            evidence: vec![],
        }
    }
}

pub struct Chain {
    pub state: State,
    key: KeyPair,
}

impl Chain {
    pub fn new(key: KeyPair) -> Self {
        Self {
            state: State::new(),
            key,
        }
    }

    pub fn from_ops(key: KeyPair, ops: &[SignedOp]) -> Self {
        Self::from_state(key, State::replay(ops))
    }

    pub fn from_state(key: KeyPair, state: State) -> Self {
        Self { state, key }
    }

    /// The key this sequencer signs with.
    pub fn public_key(&self) -> String {
        self.key.public_hex()
    }

    /// Signs with `key` from now on: after an allowed `daemon.rotate`, or
    /// for a repository that has no entries yet.
    pub fn set_key(&mut self, key: KeyPair) {
        self.key = key;
    }

    /// Entry time: the wall clock, but never earlier than the previous entry.
    pub fn entry_time(&self, wall_ms: i64) -> i64 {
        wall_ms.max(self.state.last_time_ms)
    }

    pub fn prepare(&self, sub: Submission, time_ms: i64, policy: &PolicyBundle) -> SignedOp {
        let decision = decide(
            &self.state,
            &sub.actor,
            &sub.op,
            sub.human.as_ref(),
            &Ctx {
                time_ms,
                policy,
                facts: sub.facts.as_ref(),
                evidence: &sub.evidence,
            },
        );
        let entry = OpEntry {
            format: FORMAT_CURRENT,
            seq: self.state.next_seq,
            prev: self.state.head_hash.clone(),
            time_ms,
            actor: sub.actor,
            op: sub.op,
            evidence: sub.evidence,
            facts: sub.facts,
            symbols_engine: sub.symbols_engine,
            decision,
            human: sub.human,
        };
        SignedOp::sign(entry, &self.key)
    }

    pub fn commit(&mut self, op: &SignedOp) {
        self.state.apply(op);
    }
}

/// Replays a log whose chain verified (`verify_chain`) and decides every
/// daemon key switch again with the state and policy before it.
///
/// `verify_chain` follows the daemon key through every allowed
/// `daemon.rotate` and `daemon.recover`, but it can not tell whether the
/// human signature that authorised the switch is real. Without this check,
/// anyone who can write the store could re-anchor the log on their own key
/// with a forged recovery, sign whatever they like, and rotate back to the
/// daemon's key. `policy_at(None)` is the shipped default policy.
pub fn replay_checked(
    ops: &[SignedOp],
    mut policy_at: impl FnMut(Option<&GitId>) -> Result<Arc<PolicyBundle>>,
) -> Result<State> {
    let mut state = State::new();
    for op in ops {
        let e = &op.entry;
        if e.switches_daemon_key().is_some() {
            let policy = policy_at(state.policy.as_ref())?;
            let d = decide(
                &state,
                &e.actor,
                &e.op,
                e.human.as_ref(),
                &Ctx {
                    time_ms: e.time_ms,
                    policy: &policy,
                    facts: e.facts.as_ref(),
                    evidence: &e.evidence,
                },
            );
            if d != e.decision {
                return Err(Error::Integrity(format!(
                    "op {}: {} is not authorised (replay gives {:?} {:?})",
                    e.seq,
                    e.op.kind().as_str(),
                    d.outcome,
                    d.reasons
                )));
            }
        }
        state.apply(op);
    }
    Ok(state)
}
