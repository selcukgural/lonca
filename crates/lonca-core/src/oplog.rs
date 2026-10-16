//! The operation log: an append-only, hash-chained, signed list of every
//! operation, stored as a chain of Git commits on `refs/lonca/oplog` so that
//! it travels with `git push`.
//!
//! The chain does not rely on Git's SHA-1: every entry carries the SHA-256 of
//! the previous entry, and the daemon signs the SHA-256 of each entry.

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_bytes, digest_of};
use crate::error::{Error, Result};
use crate::keys::{KeyPair, verify_hex};
use crate::ops::{Actor, Attestation, Decision, Facts, HumanSignature, Op};
use crate::store::{CommitSpec, FileEntry, FileMap, FileMode, GitId, Store};

pub const OPLOG_REF: &str = "refs/lonca/oplog";
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const OP_FILE: &str = "op.json";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpEntry {
    pub seq: u64,
    pub prev: String,
    /// Assigned by the daemon; never decreases along the chain.
    pub time_ms: i64,
    pub actor: Actor,
    pub op: Op,
    pub evidence: Vec<Attestation>,
    pub facts: Option<Facts>,
    pub decision: Decision,
    pub human: Option<HumanSignature>,
}

impl OpEntry {
    pub fn digest(&self) -> String {
        digest_of(self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedOp {
    pub entry: OpEntry,
    pub hash: String,
    pub sig: String,
}

impl SignedOp {
    pub fn sign(entry: OpEntry, key: &KeyPair) -> Self {
        let hash = entry.digest();
        let sig = key.sign_hex(hash.as_bytes());
        Self { entry, hash, sig }
    }

    pub fn verify(&self, daemon_key: &str) -> Result<()> {
        if self.entry.digest() != self.hash {
            return Err(Error::Integrity(format!("op {}: hash does not match content", self.entry.seq)));
        }
        if !verify_hex(daemon_key, self.hash.as_bytes(), &self.sig) {
            return Err(Error::Integrity(format!("op {}: bad daemon signature", self.entry.seq)));
        }
        Ok(())
    }
}

pub struct OpLog<'a> {
    store: &'a Store,
}

impl<'a> OpLog<'a> {
    pub fn new(store: &'a Store) -> Self {
        Self { store }
    }

    pub fn head(&self) -> Result<Option<GitId>> {
        self.store.ref_get(OPLOG_REF)
    }

    /// Appends one signed entry. `expected_head` must be the current head
    /// commit (compare-and-swap), so two writers can never interleave.
    pub fn append(&self, op: &SignedOp, expected_head: Option<&GitId>) -> Result<GitId> {
        let blob = self.store.write_blob(&canonical_bytes(op))?;
        let mut files = FileMap::new();
        files.insert(OP_FILE.into(), FileEntry { mode: FileMode::Regular, blob });
        let tree = self.store.write_tree(&files)?;
        let commit = self.store.write_commit(&CommitSpec {
            tree,
            parents: expected_head.into_iter().cloned().collect(),
            author_name: "lonca".into(),
            author_email: "daemon@lonca.invalid".into(),
            time_ms: op.entry.time_ms,
            message: format!(
                "lonca op {} {} {:?}\n\nactor: {}\n",
                op.entry.seq,
                op.entry.op.kind().as_str(),
                op.entry.decision.outcome,
                op.entry.actor
            ),
            headers: vec![],
        })?;
        self.store.ref_cas(OPLOG_REF, &commit, expected_head)?;
        Ok(commit)
    }

    pub fn read_at(&self, commit: &GitId) -> Result<SignedOp> {
        let bytes = self
            .store
            .read_file(commit, OP_FILE)?
            .ok_or_else(|| Error::Integrity(format!("oplog commit {} has no {OP_FILE}", commit.short())))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// All entries, oldest first.
    pub fn read_all(&self) -> Result<Vec<SignedOp>> {
        let mut out = Vec::new();
        let mut cur = self.head()?;
        while let Some(c) = cur {
            out.push(self.read_at(&c)?);
            let info = self.store.read_commit(&c)?;
            if info.parents.len() > 1 {
                return Err(Error::Integrity(format!("oplog commit {} is a merge", c.short())));
            }
            cur = info.parents.into_iter().next();
        }
        out.reverse();
        Ok(out)
    }
}

/// Checks sequence numbers, the hash chain, signatures and time order.
/// The daemon key is taken from the genesis `repo.init` entry.
pub fn verify_chain(ops: &[SignedOp]) -> Result<String> {
    let Some(first) = ops.first() else {
        return Err(Error::Integrity("empty operation log".into()));
    };
    let daemon_key = match &first.entry.op {
        Op::RepoInit { daemon_key, .. } => daemon_key.clone(),
        _ => return Err(Error::Integrity("first operation is not repo.init".into())),
    };
    let mut prev = GENESIS_PREV.to_string();
    let mut last_time = i64::MIN;
    for (i, op) in ops.iter().enumerate() {
        if op.entry.seq != i as u64 {
            return Err(Error::Integrity(format!("expected seq {i}, found {}", op.entry.seq)));
        }
        if op.entry.prev != prev {
            return Err(Error::Integrity(format!("op {i}: broken hash chain")));
        }
        if op.entry.time_ms < last_time {
            return Err(Error::Integrity(format!("op {i}: time goes backwards")));
        }
        op.verify(&daemon_key)?;
        prev = op.hash.clone();
        last_time = op.entry.time_ms;
    }
    Ok(prev)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{Decision, HumanKey};

    fn genesis(key: &KeyPair, store: &Store) -> OpEntry {
        let tree = store.empty_tree().unwrap();
        OpEntry {
            seq: 0,
            prev: GENESIS_PREV.into(),
            time_ms: 1000,
            actor: Actor::Human { name: "ayse".into() },
            op: Op::RepoInit {
                repo: "demo".into(),
                daemon_key: key.public_hex(),
                human: "ayse".into(),
                human_key: HumanKey { alg: "ed25519".into(), public: "00".into() },
                policy: tree.clone(),
                trunk: tree,
            },
            evidence: vec![],
            facts: None,
            decision: Decision::allow(),
            human: None,
        }
    }

    fn next(prev: &SignedOp, time_ms: i64) -> OpEntry {
        OpEntry {
            seq: prev.entry.seq + 1,
            prev: prev.hash.clone(),
            time_ms,
            actor: Actor::Daemon,
            op: Op::Freeze { reason: "test".into() },
            evidence: vec![],
            facts: None,
            decision: Decision::allow(),
            human: None,
        }
    }

    #[test]
    fn append_read_verify() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let log = OpLog::new(&store);

        let g = SignedOp::sign(genesis(&key, &store), &key);
        let h0 = log.append(&g, None).unwrap();
        let o1 = SignedOp::sign(next(&g, 2000), &key);
        log.append(&o1, Some(&h0)).unwrap();

        let all = log.read_all().unwrap();
        assert_eq!(all, vec![g.clone(), o1.clone()]);
        assert_eq!(verify_chain(&all).unwrap(), o1.hash);

        // A writer with a stale head cannot append.
        let o2 = SignedOp::sign(next(&o1, 3000), &key);
        assert!(log.append(&o2, Some(&h0)).is_err());
    }

    #[test]
    fn tampering_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(genesis(&key, &store), &key);
        let o1 = SignedOp::sign(next(&g, 2000), &key);

        let mut edited = o1.clone();
        edited.entry.decision = Decision::deny("rewritten");
        assert!(verify_chain(&[g.clone(), edited]).is_err(), "content change");

        let mut resigned = o1.clone();
        resigned.entry.time_ms = 5000;
        let forged = SignedOp::sign(resigned.entry, &KeyPair::generate());
        assert!(verify_chain(&[g.clone(), forged]).is_err(), "other key");

        let backwards = SignedOp::sign(next(&g, 500), &key);
        assert!(verify_chain(&[g.clone(), backwards]).is_err(), "time");

        let skipped = SignedOp::sign(OpEntry { seq: 2, ..next(&g, 2000) }, &key);
        assert!(verify_chain(&[g, skipped]).is_err(), "seq gap");
    }
}
