//! The single-writer sequencer: decide, sign, apply.
//!
//! The daemon persists each prepared entry to the store before committing it
//! to memory, so a failed write never leaves memory ahead of the log.

use lonca_core::keys::KeyPair;
use lonca_core::oplog::{OpEntry, SignedOp};
use lonca_core::ops::{Actor, Attestation, Facts, HumanSignature, Op};

use crate::config::PolicyBundle;
use crate::decide::{Ctx, decide};
use crate::state::State;

#[derive(Clone, Debug)]
pub struct Submission {
    pub actor: Actor,
    pub op: Op,
    pub human: Option<HumanSignature>,
    pub facts: Option<Facts>,
    pub evidence: Vec<Attestation>,
}

impl Submission {
    pub fn new(actor: Actor, op: Op) -> Self {
        Self { actor, op, human: None, facts: None, evidence: vec![] }
    }
}

pub struct Chain {
    pub state: State,
    key: KeyPair,
}

impl Chain {
    pub fn new(key: KeyPair) -> Self {
        Self { state: State::new(), key }
    }

    pub fn from_ops(key: KeyPair, ops: &[SignedOp]) -> Self {
        Self { state: State::replay(ops), key }
    }

    pub fn public_key(&self) -> String {
        self.key.public_hex()
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
            &Ctx { time_ms, policy, facts: sub.facts.as_ref(), evidence: &sub.evidence },
        );
        let entry = OpEntry {
            seq: self.state.next_seq,
            prev: self.state.head_hash.clone(),
            time_ms,
            actor: sub.actor,
            op: sub.op,
            evidence: sub.evidence,
            facts: sub.facts,
            decision,
            human: sub.human,
        };
        SignedOp::sign(entry, &self.key)
    }

    pub fn commit(&mut self, op: &SignedOp) {
        self.state.apply(op);
    }
}
