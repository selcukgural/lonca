//! The operation log: an append-only, hash-chained, signed list of every
//! operation, stored as a chain of Git commits on `refs/lonca/oplog` so that
//! it travels with `git push`.
//!
//! The chain does not rely on Git's SHA-1: every entry carries the SHA-256 of
//! the previous entry, and the daemon signs the SHA-256 of each entry.
//!
//! Every entry carries a format version (`docs/decisions.md`, "Log format
//! versions"). Entries are never rewritten, so every version ever written
//! stays readable; a version this build does not know is refused.

use serde::{Deserialize, Serialize};

use crate::canonical::{canonical_bytes, digest_of};
use crate::error::{Error, Result};
use crate::keys::{KeyPair, verify_hex};
use crate::ops::{Actor, Attestation, Decision, Facts, HumanSignature, Op};
use crate::store::{CommitSpec, FileEntry, FileMap, FileMode, GitId, Store};

pub const OPLOG_REF: &str = "refs/lonca/oplog";
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const OP_FILE: &str = "op.json";

/// Entries written before the format field existed. The field is left out of
/// their encoding, so their bytes, hashes and signatures are unchanged.
pub const FORMAT_LEGACY: u32 = 0;
/// The format this build writes. Version 1 is version 0 with the field
/// written out; version 2 adds `symbols_engine`; version 3 adds the human
/// key operations; version 4 adds the daemon key operations.
pub const FORMAT_CURRENT: u32 = 4;
/// The first format whose `change.propose` and `change.integrate` entries
/// record the symbol engine version.
pub const FORMAT_SYMBOLS_ENGINE: u32 = 2;
/// The first format with `human.rotate`, `human.revoke`,
/// `human.recovery_key` and `human.recover`.
pub const FORMAT_HUMAN_KEYS: u32 = 3;
/// The first format with `daemon.rotate` and `daemon.recover`.
pub const FORMAT_DAEMON_KEYS: u32 = 4;

fn is_legacy(format: &u32) -> bool {
    *format == FORMAT_LEGACY
}

/// Refuses a format this build can not read.
pub fn check_format(seq: u64, format: u32) -> Result<()> {
    if format > FORMAT_CURRENT {
        return Err(Error::Unsupported(format!(
            "op {seq}: log format {format} is newer than this build of lonca knows \
             (up to {FORMAT_CURRENT}); upgrade lonca"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpEntry {
    /// Entry format version, covered by the digest and the signature.
    #[serde(default, skip_serializing_if = "is_legacy")]
    pub format: u32,
    pub seq: u64,
    pub prev: String,
    /// Assigned by the daemon; never decreases along the chain.
    pub time_ms: i64,
    pub actor: Actor,
    pub op: Op,
    pub evidence: Vec<Attestation>,
    pub facts: Option<Facts>,
    /// Version of the symbol engine that computed this entry's facts or
    /// merge. Present exactly on `change.propose` and `change.integrate`
    /// entries from format 2 on; absent means version 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbols_engine: Option<u32>,
    pub decision: Decision,
    pub human: Option<HumanSignature>,
}

impl OpEntry {
    pub fn digest(&self) -> String {
        digest_of(self)
    }

    /// Whether this entry's facts or merge come from the symbol engine.
    pub fn uses_symbols_engine(&self) -> bool {
        matches!(
            self.op,
            Op::ChangePropose { .. } | Op::ChangeIntegrate { .. }
        )
    }

    /// The first format that can contain this entry's operation type.
    pub fn min_format(&self) -> u32 {
        match self.op {
            Op::HumanRotate { .. }
            | Op::HumanRevoke { .. }
            | Op::HumanRecoveryKey { .. }
            | Op::HumanRecover { .. } => FORMAT_HUMAN_KEYS,
            Op::DaemonRotate { .. } | Op::DaemonRecover { .. } => FORMAT_DAEMON_KEYS,
            _ => FORMAT_LEGACY,
        }
    }

    /// The symbol engine version the auditor must recompute with, for
    /// entries that use the engine.
    pub fn engine(&self) -> Option<u32> {
        self.uses_symbols_engine()
            .then(|| self.symbols_engine.unwrap_or(0))
    }

    /// The daemon key in force after this entry, if the entry switched it:
    /// an allowed `daemon.rotate` or `daemon.recover`.
    pub fn switches_daemon_key(&self) -> Option<&str> {
        self.op
            .daemon_key_switch()
            .filter(|_| self.decision.is_allow())
    }

    /// The daemon key that must have signed this entry, given the key in
    /// force before it. An allowed `daemon.recover` is signed by the key it
    /// installs, because the old key is gone; every other entry, a rotation
    /// included, by the key in force.
    pub fn signer<'a>(&'a self, in_force: &'a str) -> &'a str {
        match (&self.op, self.switches_daemon_key()) {
            (Op::DaemonRecover { .. }, Some(new)) => new,
            _ => in_force,
        }
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
            return Err(Error::Integrity(format!(
                "op {}: hash does not match content",
                self.entry.seq
            )));
        }
        if !verify_hex(daemon_key, self.hash.as_bytes(), &self.sig) {
            return Err(Error::Integrity(format!(
                "op {}: bad daemon signature",
                self.entry.seq
            )));
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
        if op.entry.format != FORMAT_CURRENT {
            return Err(Error::Invalid(format!(
                "op {}: refusing to append log format {} (this build writes {FORMAT_CURRENT})",
                op.entry.seq, op.entry.format
            )));
        }
        let blob = self.store.write_blob(&canonical_bytes(op))?;
        let mut files = FileMap::new();
        files.insert(
            OP_FILE.into(),
            FileEntry {
                mode: FileMode::Regular,
                blob,
            },
        );
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
        let bytes = self.store.read_file(commit, OP_FILE)?.ok_or_else(|| {
            Error::Integrity(format!("oplog commit {} has no {OP_FILE}", commit.short()))
        })?;
        decode(&bytes)
    }

    /// All entries, oldest first.
    pub fn read_all(&self) -> Result<Vec<SignedOp>> {
        let mut out = Vec::new();
        let mut cur = self.head()?;
        while let Some(c) = cur {
            out.push(self.read_at(&c)?);
            let info = self.store.read_commit(&c)?;
            if info.parents.len() > 1 {
                return Err(Error::Integrity(format!(
                    "oplog commit {} is a merge",
                    c.short()
                )));
            }
            cur = info.parents.into_iter().next();
        }
        out.reverse();
        Ok(out)
    }
}

/// Decodes a stored entry. The format version is read first, so an entry
/// from a newer lonca is refused as such rather than as a decoding or hash
/// error.
pub fn decode(bytes: &[u8]) -> Result<SignedOp> {
    #[derive(Deserialize)]
    struct Probe {
        entry: ProbeEntry,
    }
    #[derive(Deserialize)]
    struct ProbeEntry {
        #[serde(default)]
        format: u32,
        #[serde(default)]
        seq: u64,
    }
    let probe: Probe = serde_json::from_slice(bytes)?;
    check_format(probe.entry.seq, probe.entry.format)?;
    Ok(serde_json::from_slice(bytes)?)
}

/// Checks sequence numbers, the hash chain, signatures, time order and
/// format versions (known, and never decreasing along the chain).
/// The daemon key is taken from the genesis `repo.init` entry and follows
/// every allowed `daemon.rotate` and `daemon.recover`.
///
/// This checks who signed each entry, not whether a key switch was
/// authorised: that needs the human keys in force, so the daemon
/// (`lonca_policy::chain::replay_checked`) and the auditor decide every
/// switch again.
pub fn verify_chain(ops: &[SignedOp]) -> Result<String> {
    let Some(first) = ops.first() else {
        return Err(Error::Integrity("empty operation log".into()));
    };
    let mut daemon_key = match &first.entry.op {
        Op::RepoInit { daemon_key, .. } => daemon_key.clone(),
        _ => return Err(Error::Integrity("first operation is not repo.init".into())),
    };
    let mut prev = GENESIS_PREV.to_string();
    let mut last_time = i64::MIN;
    let mut last_format = FORMAT_LEGACY;
    for (i, op) in ops.iter().enumerate() {
        check_format(op.entry.seq, op.entry.format)?;
        if op.entry.format < last_format {
            return Err(Error::Integrity(format!(
                "op {i}: log format goes back from {last_format} to {}",
                op.entry.format
            )));
        }
        let wants_engine =
            op.entry.format >= FORMAT_SYMBOLS_ENGINE && op.entry.uses_symbols_engine();
        if op.entry.symbols_engine.is_some() != wants_engine {
            return Err(Error::Integrity(format!(
                "op {i}: symbols_engine must be {} in a format {} {} entry",
                if wants_engine { "present" } else { "absent" },
                op.entry.format,
                op.entry.op.kind().as_str()
            )));
        }
        if op.entry.format < op.entry.min_format() {
            return Err(Error::Integrity(format!(
                "op {i}: {} needs log format {} or later, found {}",
                op.entry.op.kind().as_str(),
                op.entry.min_format(),
                op.entry.format
            )));
        }
        if op.entry.seq != i as u64 {
            return Err(Error::Integrity(format!(
                "expected seq {i}, found {}",
                op.entry.seq
            )));
        }
        if op.entry.prev != prev {
            return Err(Error::Integrity(format!("op {i}: broken hash chain")));
        }
        if op.entry.time_ms < last_time {
            return Err(Error::Integrity(format!("op {i}: time goes backwards")));
        }
        op.verify(op.entry.signer(&daemon_key))?;
        if let Some(new) = op.entry.switches_daemon_key() {
            daemon_key = new.to_string();
        }
        prev = op.hash.clone();
        last_time = op.entry.time_ms;
        last_format = op.entry.format;
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
            format: FORMAT_CURRENT,
            seq: 0,
            prev: GENESIS_PREV.into(),
            time_ms: 1000,
            actor: Actor::Human {
                name: "ayse".into(),
            },
            op: Op::RepoInit {
                repo: "demo".into(),
                daemon_key: key.public_hex(),
                human: "ayse".into(),
                human_key: HumanKey {
                    alg: "ed25519".into(),
                    public: "00".into(),
                },
                policy: tree.clone(),
                trunk: tree,
            },
            evidence: vec![],
            facts: None,
            symbols_engine: None,
            decision: Decision::allow(),
            human: None,
        }
    }

    fn next(prev: &SignedOp, time_ms: i64) -> OpEntry {
        OpEntry {
            format: FORMAT_CURRENT,
            seq: prev.entry.seq + 1,
            prev: prev.hash.clone(),
            time_ms,
            actor: Actor::Daemon,
            op: Op::Freeze {
                reason: "test".into(),
            },
            evidence: vec![],
            facts: None,
            symbols_engine: None,
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
        assert!(
            verify_chain(&[g.clone(), edited]).is_err(),
            "content change"
        );

        let mut resigned = o1.clone();
        resigned.entry.time_ms = 5000;
        let forged = SignedOp::sign(resigned.entry, &KeyPair::generate());
        assert!(verify_chain(&[g.clone(), forged]).is_err(), "other key");

        let backwards = SignedOp::sign(next(&g, 500), &key);
        assert!(verify_chain(&[g.clone(), backwards]).is_err(), "time");

        let skipped = SignedOp::sign(
            OpEntry {
                seq: 2,
                ..next(&g, 2000)
            },
            &key,
        );
        assert!(verify_chain(&[g, skipped]).is_err(), "seq gap");
    }

    #[test]
    fn format_is_encoded_and_signed_except_for_legacy_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let current = genesis(&key, &store);
        let legacy = OpEntry {
            format: FORMAT_LEGACY,
            ..current.clone()
        };
        let enc = |e: &OpEntry| String::from_utf8(canonical_bytes(e)).unwrap();
        assert!(enc(&legacy).starts_with("{\"seq\":0,"), "{}", enc(&legacy));
        assert!(
            enc(&current).starts_with(&format!("{{\"format\":{FORMAT_CURRENT},\"seq\":0,")),
            "{}",
            enc(&current)
        );
        assert_ne!(legacy.digest(), current.digest(), "format is in the digest");

        // Changing the format of a signed entry breaks its signature.
        let mut edited = SignedOp::sign(current, &key);
        edited.entry.format = FORMAT_LEGACY;
        assert!(edited.verify(&key.public_hex()).is_err());

        // A legacy entry round-trips to the same bytes.
        let signed = SignedOp::sign(legacy, &key);
        let bytes = canonical_bytes(&signed);
        let back = decode(&bytes).unwrap();
        assert_eq!(back, signed);
        assert_eq!(canonical_bytes(&back), bytes);
    }

    #[test]
    fn unknown_formats_are_refused_before_decoding() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(genesis(&key, &store), &key);
        let mut v: serde_json::Value = serde_json::from_slice(&canonical_bytes(&g)).unwrap();
        v["entry"]["format"] = (FORMAT_CURRENT + 1).into();
        // A newer lonca may also have changed the shape of other fields.
        v["entry"]["op"] = serde_json::json!({"type": "from.the.future"});
        let bytes = serde_json::to_vec(&v).unwrap();
        match decode(&bytes) {
            Err(Error::Unsupported(m)) => assert!(
                m.contains(&format!("op 0: log format {}", FORMAT_CURRENT + 1)),
                "{m}"
            ),
            other => panic!("expected Unsupported, got {other:?}"),
        }

        let future = SignedOp::sign(
            OpEntry {
                format: FORMAT_CURRENT + 1,
                ..genesis(&key, &store)
            },
            &key,
        );
        assert!(matches!(
            verify_chain(std::slice::from_ref(&future)),
            Err(Error::Unsupported(_))
        ));
        assert!(matches!(
            OpLog::new(&store).append(&future, None),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn formats_may_rise_along_the_chain_but_never_fall() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let with = |e: OpEntry, format| OpEntry { format, ..e };
        let g = SignedOp::sign(with(genesis(&key, &store), FORMAT_LEGACY), &key);
        let o1 = SignedOp::sign(with(next(&g, 2000), FORMAT_LEGACY), &key);
        let o2 = SignedOp::sign(with(next(&o1, 3000), FORMAT_CURRENT), &key);
        assert_eq!(
            verify_chain(&[g.clone(), o1.clone(), o2.clone()]).unwrap(),
            o2.hash
        );

        let back = SignedOp::sign(with(next(&o2, 4000), FORMAT_LEGACY), &key);
        let err = verify_chain(&[g, o1, o2, back]).unwrap_err();
        assert!(
            err.to_string().contains("op 3: log format goes back"),
            "{err}"
        );
    }

    #[test]
    fn the_symbols_engine_is_recorded_exactly_on_proposals_and_integrations() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(genesis(&key, &store), &key);
        let tree = store.empty_tree().unwrap();
        let integrate = |prev: &SignedOp, format, symbols_engine| OpEntry {
            format,
            symbols_engine,
            op: Op::ChangeIntegrate {
                change: crate::ChangeId::random(),
                trunk_before: tree.clone(),
                merged: None,
                conflicts: vec![],
            },
            ..next(prev, 2000)
        };
        let ok = |e: OpEntry| verify_chain(&[g.clone(), SignedOp::sign(e, &key)]);

        let recorded = integrate(&g, FORMAT_CURRENT, Some(7));
        assert_eq!(recorded.engine(), Some(7));
        assert!(ok(recorded).is_ok());
        assert!(ok(integrate(&g, FORMAT_CURRENT, None)).is_err(), "missing");
        let other = OpEntry {
            symbols_engine: Some(0),
            ..next(&g, 2000)
        };
        assert_eq!(other.engine(), None);
        assert!(ok(other).is_err(), "on an op that uses no engine");

        // Before format 2 the field did not exist; absent means engine 0.
        let old = SignedOp::sign(with_format(genesis(&key, &store), 1), &key);
        let v1 = |e| verify_chain(&[old.clone(), SignedOp::sign(e, &key)]);
        let legacy = integrate(&old, 1, None);
        assert_eq!(legacy.engine(), Some(0));
        assert!(v1(legacy).is_ok());
        assert!(v1(integrate(&old, 1, Some(0))).is_err());
    }

    #[test]
    fn human_key_operations_need_format_3() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let k = || HumanKey {
            alg: "ed25519".into(),
            public: "01".into(),
        };
        let ops = [
            Op::HumanRotate {
                human: "ayse".into(),
                key: k(),
            },
            Op::HumanRevoke {
                human: "ayse".into(),
                reason: "lost".into(),
            },
            Op::HumanRecoveryKey {
                human: "ayse".into(),
                key: k(),
            },
            Op::HumanRecover {
                human: "ayse".into(),
                key: k(),
            },
        ];
        for op in ops {
            let at = |format| OpEntry {
                format,
                op: op.clone(),
                ..next(&g, 2000)
            };
            assert_eq!(at(FORMAT_HUMAN_KEYS).min_format(), FORMAT_HUMAN_KEYS);
            let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(format), &key)]);
            assert!(chain(FORMAT_HUMAN_KEYS).is_ok(), "{op:?}");
            let err = chain(FORMAT_HUMAN_KEYS - 1).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("{} needs log format 3", op.kind().as_str())),
                "{err}"
            );
        }
        assert_eq!(next(&g, 2000).min_format(), FORMAT_LEGACY);
    }

    #[test]
    fn daemon_key_operations_need_format_4() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 3), &key);
        // Denied, so the key in force signs them and nothing switches.
        for op in [
            Op::DaemonRotate { key: "01".into() },
            Op::DaemonRecover { key: "01".into() },
        ] {
            let at = |format| OpEntry {
                format,
                op: op.clone(),
                decision: Decision::deny("test"),
                ..next(&g, 2000)
            };
            assert_eq!(at(FORMAT_DAEMON_KEYS).min_format(), FORMAT_DAEMON_KEYS);
            let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(format), &key)]);
            assert!(chain(FORMAT_DAEMON_KEYS).is_ok(), "{op:?}");
            let err = chain(FORMAT_DAEMON_KEYS - 1).unwrap_err();
            assert!(
                err.to_string()
                    .contains(&format!("{} needs log format 4", op.kind().as_str())),
                "{err}"
            );
        }
    }

    /// An entry of `op` after `prev`, signed by `by`.
    fn switch(prev: &SignedOp, op: Op, decision: Decision, by: &KeyPair) -> SignedOp {
        SignedOp::sign(
            OpEntry {
                op,
                decision,
                ..next(prev, prev.entry.time_ms + 1)
            },
            by,
        )
    }

    fn signed_by_error(ops: &[SignedOp]) -> String {
        verify_chain(ops).unwrap_err().to_string()
    }

    #[test]
    fn the_daemon_key_follows_rotations() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let (old, new) = (KeyPair::generate(), KeyPair::generate());
        let g = SignedOp::sign(genesis(&old, &store), &old);
        let rotate = Op::DaemonRotate {
            key: new.public_hex(),
        };
        // The rotation itself is signed by the old key, what follows by the
        // new one.
        let r = switch(&g, rotate.clone(), Decision::allow(), &old);
        assert_eq!(
            r.entry.switches_daemon_key(),
            Some(new.public_hex().as_str())
        );
        let after = SignedOp::sign(next(&r, 3000), &new);
        assert_eq!(
            verify_chain(&[g.clone(), r.clone(), after.clone()]).unwrap(),
            after.hash
        );
        let stale = SignedOp::sign(next(&r, 3000), &old);
        assert!(
            signed_by_error(&[g.clone(), r.clone(), stale]).contains("op 2: bad daemon signature")
        );
        let later = SignedOp::sign(next(&after, 4000), &old);
        assert!(
            signed_by_error(&[g.clone(), r, after, later]).contains("op 3: bad daemon signature")
        );
        let by_new = switch(&g, rotate.clone(), Decision::allow(), &new);
        assert!(signed_by_error(&[g.clone(), by_new]).contains("op 1: bad daemon signature"));

        // A denied rotation switches nothing.
        let denied = switch(&g, rotate, Decision::deny("x"), &old);
        assert_eq!(denied.entry.switches_daemon_key(), None);
        let after = SignedOp::sign(next(&denied, 3000), &old);
        assert!(verify_chain(&[g.clone(), denied.clone(), after]).is_ok());
        let after = SignedOp::sign(next(&denied, 3000), &new);
        assert!(signed_by_error(&[g, denied, after]).contains("op 2: bad daemon signature"));
    }

    #[test]
    fn a_recovery_is_signed_by_the_key_it_installs() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let (old, new) = (KeyPair::generate(), KeyPair::generate());
        let g = SignedOp::sign(genesis(&old, &store), &old);
        let recover = Op::DaemonRecover {
            key: new.public_hex(),
        };
        let r = switch(&g, recover.clone(), Decision::allow(), &new);
        assert_eq!(r.entry.signer(&old.public_hex()), new.public_hex());
        let after = SignedOp::sign(next(&r, 3000), &new);
        assert!(verify_chain(&[g.clone(), r.clone(), after]).is_ok());
        let stale = SignedOp::sign(next(&r, 3000), &old);
        assert!(signed_by_error(&[g.clone(), r, stale]).contains("op 2: bad daemon signature"));

        let by_old = switch(&g, recover.clone(), Decision::allow(), &old);
        assert!(signed_by_error(&[g.clone(), by_old]).contains("op 1: bad daemon signature"));
        // A denied recovery is an ordinary entry of the key in force.
        let denied = switch(&g, recover, Decision::deny("x"), &old);
        assert_eq!(denied.entry.signer(&old.public_hex()), old.public_hex());
        assert!(verify_chain(&[g, denied]).is_ok());
    }

    fn with_format(e: OpEntry, format: u32) -> OpEntry {
        OpEntry { format, ..e }
    }
}
