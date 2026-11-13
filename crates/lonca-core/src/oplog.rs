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

#[cfg(feature = "store")]
use crate::canonical::canonical_bytes;
use crate::canonical::digest_of;
use crate::error::{Error, Result};
use crate::keys::{KeyPair, verify_hex};
#[cfg(feature = "store")]
use crate::objects::{FileEntry, FileMap, FileMode, GitId};
use crate::ops::{
    Actor, Attestation, Decision, Facts, HumanSignature, LeaseItem, NegotiationMsg, ObsKind, Op,
};
#[cfg(feature = "store")]
use crate::store::{CommitInfo, CommitSpec, Reader, Store};
use crate::threads;

pub const OPLOG_REF: &str = "refs/lonca/oplog";
pub const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";
#[cfg(feature = "store")]
const OP_FILE: &str = "op.json";

/// Entries written before the format field existed. The field is left out of
/// their encoding, so their bytes, hashes and signatures are unchanged.
pub const FORMAT_LEGACY: u32 = 0;
/// The format this build writes. Version 1 is version 0 with the field
/// written out; version 2 adds `symbols_engine`; version 3 adds the human
/// key operations; version 4 adds the daemon key operations; version 5
/// adds `scope.scratch` on `session.start` and `cap.attenuate`; version 6
/// adds `reject`; version 7 changes what `change.propose` means for
/// leases (they are pinned to the change) and prunes dead lease sets;
/// version 8 gives heartbeats and denied acquires a meaning for leases;
/// version 9 lets a `session.start` continue an earlier session; version 10
/// adds `lease.interest`, `to` on a yield and `leases` on `cap.attenuate`;
/// version 11 adds the `unproposed` observation; version 12 makes a lease
/// say why and lets a waiting interest go first; version 13 lets a name
/// stand for every symbol of that name; version 14 adds `renames` to facts
/// and follows them in leases; version 15 adds `unparsed_files` to facts;
/// version 16 adds `unread_files`; version 17 adds `change.integrate_batch`;
/// version 18 adds `affected` to facts and reports who holds it; version 19
/// adds `session.isolate`; version 20 adds `harness` to `session.start`, and
/// a level rests on it; version 21 adds the lease kind `shared`; version 22
/// adds reserved `names` to an `insert` and makes a new file need a lease;
/// version 23 gives a delegated lease back to the parent when the child
/// expires or stops beating, as when it ends; version 24 adds the
/// `unhooked` observation, which taints a session; version 25 adds named
/// `checks` to `approve`; version 26 makes an agent's proposal withdraw the
/// pending changes of its workspace; version 27 lets a recovery key sign a
/// `daemon.recover` (`recover`); version 28 accepts human keys on FIDO
/// security keys (`sk-p256`, `sk-ed25519`); version 29 adds keyed
/// directories; version 30 adds `workspace` to `session.start`, makes a
/// continuation name the workspace of the session it continues, and starts
/// it unobserved; version 31 gives a child session its parent's agent
/// name; version 32 matches `critical` and `checks_by_path` patterns with
/// case folded; version 33 holds a human signature to the log it was made
/// for (`at`); version 34 carries a taint, an unhooked tool and a lowered
/// level from a session to the sessions made from it; version 35 decides a
/// pending operation again when it is released, and keeps a tainted
/// session's lease intent out of another session's denial.
pub const FORMAT_CURRENT: u32 = 35;
/// The first format whose `change.propose` and `change.integrate` entries
/// record the symbol engine version.
pub const FORMAT_SYMBOLS_ENGINE: u32 = 2;
/// The first format with `human.rotate`, `human.revoke`,
/// `human.recovery_key` and `human.recover`.
pub const FORMAT_HUMAN_KEYS: u32 = 3;
/// The first format with `daemon.rotate` and `daemon.recover`.
pub const FORMAT_DAEMON_KEYS: u32 = 4;
/// The first format whose session scopes may name scratch roots.
pub const FORMAT_SCRATCH: u32 = 5;
/// The first format with `reject`.
pub const FORMAT_REJECT: u32 = 6;
/// The first format whose entries pin leases to the changes they propose
/// and prune dead lease sets. No new field: the meaning of existing entries
/// changes, so a replay must apply it to these entries and no older ones.
pub const FORMAT_LEASE_PINS: u32 = 7;
/// The first format in which a heartbeat keeps a session's leases alive
/// (and its absence ends them), a denied acquire registers interest and
/// `leases.max_hold_minutes` limits a renewal. No new field, again.
pub const FORMAT_LEASE_LIVENESS: u32 = 8;
/// The first format in which a `session.start` may continue a session.
pub const FORMAT_SESSION_CONTINUE: u32 = 9;
/// The first format with `lease.interest`, a yield to a session and lease
/// sets carried by `cap.attenuate`.
pub const FORMAT_LEASE_QUEUE: u32 = 10;
/// The first format with the `unproposed` observation.
pub const FORMAT_UNPROPOSED: u32 = 11;
/// The first format in which a lease or an interest needs an intent and a
/// waiting interest stops new leases that conflict with it. No new field.
pub const FORMAT_LEASE_INTENT: u32 = 12;
/// The first format in which `path#Name` covers `path#Name(key)`, in leases
/// and in scopes. No new field.
pub const FORMAT_SYMBOL_KEYS: u32 = 13;
/// The first format with `renames` in facts. Older entries have none, so
/// nothing is gated on it.
pub const FORMAT_RENAMES: u32 = 14;
/// The first format with `unparsed_files` in facts. Older entries have none,
/// so nothing is gated on it.
pub const FORMAT_UNPARSED: u32 = 15;
/// The first format with `unread_files` in facts. Older entries have none,
/// so nothing is gated on it.
pub const FORMAT_UNREAD: u32 = 16;
/// The first format with `change.integrate_batch`.
pub const FORMAT_BATCH: u32 = 17;
/// The first format with `affected` in facts, and whose proposals report the
/// lease sets it reaches. Older entries report none and replay as they were.
pub const FORMAT_AFFECTED: u32 = 18;
/// The first format with `session.isolate`.
pub const FORMAT_ISOLATE: u32 = 19;
/// The first format with `harness` on `session.start`. From here a
/// `session.bind` is held to it, and can not raise a level already bound.
/// Older entries replay as they were.
pub const FORMAT_SESSION_HARNESS: u32 = 20;
/// The first format with the lease kind `shared`.
pub const FORMAT_SHARED_LEASES: u32 = 21;
/// The first format with reserved `names` on an `insert` item. From here a
/// change that adds a file needs an exclusive lease on its `path#<file>`.
/// Older entries replay as they were.
pub const FORMAT_INSERT_NAMES: u32 = 22;
/// The first format in which a lease set delegated to a child session goes
/// back to the parent that gave it when the child expires or stops beating,
/// and not only when it ends or is revoked. No new field: older entries
/// replay as they were.
pub const FORMAT_GIVE_BACK: u32 = 23;
/// The first format with the `unhooked` observation: a call to `lonca mcp`
/// whose before-tool event never came. From here it taints the session.
pub const FORMAT_UNHOOKED: u32 = 24;
/// The first format with named `checks` on `approve`: the checks of
/// `verification.checks` a change owes. Evidence of them is `named`.
pub const FORMAT_NAMED_CHECKS: u32 = 25;
/// The first format in which an agent's `change.propose` that is not denied
/// withdraws the pending changes of its workspace: those of its session and
/// of the sessions it continues that wait for a human. The decision names
/// each with `replaces:<change>`. No new field: older entries replay as they
/// were.
pub const FORMAT_REPLACES: u32 = 26;
/// The first format with `recover` on `daemon.recover`: signed with a
/// human's recovery key, it also replaces that human's lost key, so a
/// lost Mac (daemon key and Secure Enclave key both gone) is recovered
/// with the recovery key alone.
pub const FORMAT_RECOVERY_DAEMON: u32 = 27;
/// The first format that accepts a human key on a FIDO security key
/// (`sk-p256`, `sk-ed25519`), whose signatures prove presence. No new
/// field: before it, such a key is `invalid_key`, as it always was.
pub const FORMAT_SECURITY_KEYS: u32 = 28;
/// The first format with keyed directories (#261): an `insert` lease on a
/// `dir#<dir>` reserves keys, a proposal's added files there need theirs, a
/// proposal pins the key leases of the directories it adds files to, and
/// facts may name `taken_keys`; a keyed directory's path takes no other
/// symbol than its `<dir>`. Before it, a `<dir>` lease was one on any
/// container. Older entries replay as they were.
pub const FORMAT_KEYED: u32 = 29;
/// The first format with `workspace` on `session.start`: the directory a
/// session works in is in the log. From it on a session is continued only
/// in the workspace it was started in, no directory holds two sessions at
/// once, and a continuation starts at `unobserved` whatever its
/// predecessor reached. Older entries replay as they were.
pub const FORMAT_WORKSPACE: u32 = 30;
/// The first format in which a `cap.attenuate` names its parent's agent:
/// a child session is the same agent with less, so what the policy says of
/// an agent by name holds for every session made from that agent's. Before
/// it the child's agent name was the parent's choice. Older entries replay
/// as they were.
pub const FORMAT_CHILD_AGENT: u32 = 31;
/// The first format in which `[paths] critical` and `checks_by_path`
/// patterns match a path with case folded (`lonca_core::paths::folded`):
/// a file system that folds case opens `Build.rs` as `build.rs`. Before it
/// the patterns matched the spelling. Older entries replay as they were.
pub const FORMAT_FOLDED_PATHS: u32 = 32;
/// The first format in which a human signature names the head of the log
/// its signer saw (`HumanSignature::at`), and `decide()` refuses one that
/// names none, names an entry this log does not have, or approves or
/// rejects an entry later than the one it names. Before it a signature
/// held for any log of a repository of that name, for ten minutes. Older
/// entries replay as they were.
pub const FORMAT_ANCHORED: u32 = 33;
/// The first format in which what enters a session enters its children
/// that already exist: a taint (`taint`, an external `observe`), an
/// `unhooked` mark, and a level lowered by a bind or by an unhooked tool.
/// Before it a child took these once, when it was made. Older entries
/// replay as they were.
pub const FORMAT_TAINT_REACHES: u32 = 34;
/// The first format in which the approval that releases a pending
/// operation checks again what the operation itself was checked for when
/// it was asked (a name enrolled meanwhile, a session or a lease set of
/// that id, a lease someone else took), a `human.enroll` refuses any key
/// the log has known and not only a retired one, and `lease_held:` does
/// not carry the intent of a holder that is tainted. Older entries replay
/// as they were.
pub const FORMAT_RELEASE_RECHECK: u32 = 35;

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
            Op::ChangePropose { .. } | Op::ChangeIntegrate { .. } | Op::ChangeIntegrateBatch { .. }
        )
    }

    /// The first format that can contain this entry's operation type.
    pub fn min_format(&self) -> u32 {
        match self.op {
            Op::HumanRotate { .. }
            | Op::HumanRevoke { .. }
            | Op::HumanRecoveryKey { .. }
            | Op::HumanRecover { .. } => FORMAT_HUMAN_KEYS,
            Op::DaemonRecover {
                recover: Some(_), ..
            } => FORMAT_RECOVERY_DAEMON,
            Op::DaemonRotate { .. } | Op::DaemonRecover { .. } => FORMAT_DAEMON_KEYS,
            Op::Reject { .. } => FORMAT_REJECT,
            Op::Approve { ref checks, .. } if !checks.is_empty() => FORMAT_NAMED_CHECKS,
            Op::ChangeIntegrateBatch { .. } => FORMAT_BATCH,
            Op::SessionIsolate { .. } => FORMAT_ISOLATE,
            Op::LeaseAcquire { ref items, .. } | Op::LeaseInterest { ref items, .. }
                if items.iter().any(|i| !i.names.is_empty()) =>
            {
                FORMAT_INSERT_NAMES
            }
            Op::LeaseAcquire { ref items, .. } | Op::LeaseInterest { ref items, .. }
                if items.iter().any(LeaseItem::is_shared) =>
            {
                FORMAT_SHARED_LEASES
            }
            Op::Observe { ref events, .. }
                if events
                    .iter()
                    .any(|e| matches!(e.kind, ObsKind::Unhooked { .. })) =>
            {
                FORMAT_UNHOOKED
            }
            Op::Observe { ref events, .. }
                if events
                    .iter()
                    .any(|e| matches!(e.kind, ObsKind::Unproposed { .. })) =>
            {
                FORMAT_UNPROPOSED
            }
            Op::LeaseInterest { .. }
            | Op::Negotiate {
                message: NegotiationMsg::Yield { to: Some(_), .. },
                ..
            } => FORMAT_LEASE_QUEUE,
            Op::CapAttenuate { ref leases, .. } if !leases.is_empty() => FORMAT_LEASE_QUEUE,
            Op::SessionStart {
                harness: Some(_), ..
            } => FORMAT_SESSION_HARNESS,
            Op::SessionStart {
                continues: Some(_), ..
            } => FORMAT_SESSION_CONTINUE,
            Op::SessionStart { ref scope, .. } | Op::CapAttenuate { ref scope, .. }
                if !scope.scratch.is_empty() =>
            {
                FORMAT_SCRATCH
            }
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

/// The log in a store.
#[cfg(feature = "store")]
pub struct OpLog<'a> {
    store: &'a Store,
}

#[cfg(feature = "store")]
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
        Ok(Self::entry_at(&self.store.reader(), commit)?.0)
    }

    /// The entry of `commit` and the commit itself, read once for both its
    /// tree and its parent.
    fn entry_at(reader: &Reader, commit: &GitId) -> Result<(SignedOp, CommitInfo)> {
        let info = reader.read_commit(commit)?;
        Ok((Self::entry_in(reader, commit, &info.tree)?, info))
    }

    /// The entry in `tree`, the tree of the log's `commit`.
    fn entry_in(reader: &Reader, commit: &GitId, tree: &GitId) -> Result<SignedOp> {
        let files = reader.read_tree(tree)?;
        let Some(file) = files.get(OP_FILE) else {
            let commit = commit.short();
            return Err(Error::Integrity(format!(
                "oplog commit {commit} has no {OP_FILE}"
            )));
        };
        decode(&reader.read_blob(&file.blob)?)
    }

    /// All entries, oldest first.
    pub fn read_all(&self) -> Result<Vec<SignedOp>> {
        let found = self.walk_all()?;
        Ok(found.into_iter().map(|(_, op)| op).collect())
    }

    /// The whole log, each entry with the commit it is in: what
    /// `walk_from(0)` gives, entry or error, with the entries of a long log
    /// read on several threads. For a daemon's start and an audit; a
    /// request reads with [`OpLog::walk_from`], on its own thread.
    pub fn walk_all(&self) -> Result<Vec<(GitId, SignedOp)>> {
        self.walk_all_on(None)
    }

    /// [`OpLog::walk_all`] on `threads` threads, or as many as the log is
    /// worth. The commits are a chain, so they are followed first, to the
    /// first one that does not read or is a merge; the entries in them are
    /// then read side by side. The error is the one the walk from the head
    /// meets first: an entry that does not read comes before whatever
    /// stopped the commits further down.
    fn walk_all_on(&self, threads: Option<usize>) -> Result<Vec<(GitId, SignedOp)>> {
        let mut commits: Vec<(GitId, GitId)> = Vec::new();
        let mut stopped = None;
        let mut cur = self.head()?;
        let reader = self.store.reader();
        while let Some(c) = cur.take() {
            let info = match reader.read_commit(&c) {
                Ok(info) => info,
                Err(e) => {
                    stopped = Some(e);
                    break;
                }
            };
            if info.parents.len() > 1 {
                // Its own entry is read first, as on the walk.
                stopped = Some(Error::Integrity(format!(
                    "oplog commit {} is a merge",
                    c.short()
                )));
            } else {
                cur = info.parents.into_iter().next();
            }
            commits.push((c, info.tree));
        }
        let threads = threads.unwrap_or_else(|| threads::worth(commits.len()));
        let entries = threads::in_order(&commits, threads, |part| {
            let reader = self.store.reader();
            let read = |(commit, tree): &(GitId, GitId)| Self::entry_in(&reader, commit, tree);
            part.iter().map(read).collect()
        });
        let mut out = Vec::with_capacity(commits.len());
        for ((commit, _), entry) in commits.into_iter().zip(entries) {
            out.push((commit, entry?));
        }
        if let Some(e) = stopped {
            return Err(e);
        }
        out.reverse();
        Ok(out)
    }

    /// The entries from sequence `seq` on, oldest first. The log is walked
    /// from its head, so this costs what it returns, however long the log.
    pub fn read_from(&self, seq: u64) -> Result<Vec<SignedOp>> {
        let found = self.walk_from(seq)?;
        Ok(found.into_iter().map(|(_, op)| op).collect())
    }

    /// [`OpLog::read_from`], each entry with the commit it is in.
    pub fn walk_from(&self, seq: u64) -> Result<Vec<(GitId, SignedOp)>> {
        let mut out = Vec::new();
        let mut cur = self.head()?;
        let reader = self.store.reader();
        while let Some(c) = cur {
            let (op, info) = Self::entry_at(&reader, &c)?;
            if op.entry.seq < seq {
                break;
            }
            if info.parents.len() > 1 {
                return Err(Error::Integrity(format!(
                    "oplog commit {} is a merge",
                    c.short()
                )));
            }
            cur = info.parents.into_iter().next();
            out.push((c, op));
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
    // An entry this build reads says its format itself. One it does not
    // read is asked for its format alone, which is what tells why.
    if let Ok(op) = serde_json::from_slice::<SignedOp>(bytes) {
        check_format(op.entry.seq, op.entry.format)?;
        return Ok(op);
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
    verify_chain_on(ops, threads::worth(ops.len()))
}

/// [`verify_chain`] with the hashes and signatures checked on `threads`
/// threads. What it answers does not depend on the number: every entry is
/// asked the same question as on one thread, and the answers are read in
/// the log's order, so the first entry that fails anything is the one
/// reported, with what it failed first.
fn verify_chain_on(ops: &[SignedOp], threads: usize) -> Result<String> {
    let Some(first) = ops.first() else {
        return Err(Error::Integrity("empty operation log".into()));
    };
    let daemon_key = match &first.entry.op {
        Op::RepoInit { daemon_key, .. } => daemon_key,
        _ => return Err(Error::Integrity("first operation is not repo.init".into())),
    };
    let mut signed = signed_by(ops, daemon_key, threads).into_iter();
    let mut prev = GENESIS_PREV.to_string();
    let mut last_time = i64::MIN;
    let mut last_format = FORMAT_LEGACY;
    for (i, op) in ops.iter().enumerate() {
        let signed = signed.next().unwrap_or(Ok(()));
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
        signed?;
        prev = op.hash.clone();
        last_time = op.entry.time_ms;
        last_format = op.entry.format;
    }
    Ok(prev)
}

/// What [`SignedOp::verify`] says of every entry, in the log's order, with
/// the daemon key that must have signed it: `first_key` followed through
/// every allowed switch before the entry. For the entries up to the first
/// one that fails a check of the chain this is the key `verify_chain`
/// holds there, and it reads no answer past that entry.
fn signed_by(ops: &[SignedOp], first_key: &str, threads: usize) -> Vec<Result<()>> {
    let mut key = first_key;
    let mut signed = Vec::with_capacity(ops.len());
    for op in ops {
        signed.push((op, op.entry.signer(key)));
        if let Some(new) = op.entry.switches_daemon_key() {
            key = new;
        }
    }
    threads::in_order(&signed, threads, |part| {
        part.iter().map(|(op, key)| op.verify(key)).collect()
    })
}

#[cfg(test)]
#[cfg(feature = "store")]
mod tests {
    use super::*;
    use crate::ChangeId;
    use crate::ops::{Continuation, Decision, HumanKey, LeaseKind, Scope};
    use std::collections::BTreeSet;

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
    fn continuing_a_session_needs_format_9() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let start = |continues| Op::SessionStart {
            session: "s".into(),
            agent: "bot".into(),
            model: None,
            task: String::new(),
            scope: Scope {
                paths: vec!["**".into()],
                symbols: None,
                ops: vec![],
                max_files: None,
                max_lines: None,
                scratch: vec![],
            },
            expires_ms: 9000,
            continues,
            harness: None,
            workspace: None,
        };
        let plain = OpEntry {
            format: FORMAT_LEGACY,
            op: start(None),
            ..next(&g, 2000)
        };
        assert_eq!(plain.min_format(), FORMAT_LEGACY);
        let at = |format| OpEntry {
            format,
            op: start(Some(Continuation {
                session: "old".into(),
                widen: false,
            })),
            ..next(&g, 2000)
        };
        assert_eq!(at(9).min_format(), FORMAT_SESSION_CONTINUE);
        let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(format), &key)]);
        assert!(chain(9).is_ok());
        let err = chain(8).unwrap_err();
        assert!(err.to_string().contains("needs log format 9"), "{err}");
    }

    /// A harness needs its format whatever else the start carries.
    #[test]
    fn a_named_harness_needs_format_20() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let start = |continues: Option<Continuation>, scratch: Vec<String>| Op::SessionStart {
            session: "s".into(),
            agent: "bot".into(),
            model: None,
            task: String::new(),
            scope: Scope {
                paths: vec!["**".into()],
                symbols: None,
                ops: vec![],
                max_files: None,
                max_lines: None,
                scratch,
            },
            expires_ms: 9000,
            continues,
            harness: Some("codex".into()),
            workspace: None,
        };
        let continued = Continuation {
            session: "old".into(),
            widen: false,
        };
        for op in [
            start(None, vec![]),
            start(Some(continued), vec![]),
            start(None, vec!["/tmp/x".into()]),
        ] {
            let at = |format| OpEntry {
                format,
                op: op.clone(),
                ..next(&g, 2000)
            };
            assert_eq!(at(20).min_format(), FORMAT_SESSION_HARNESS, "{op:?}");
            let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(format), &key)]);
            assert!(chain(20).is_ok());
            let err = chain(19).unwrap_err();
            assert!(err.to_string().contains("needs log format 20"), "{err}");
        }
    }

    /// A `shared` item needs its format, in an acquire or an interest, among
    /// other items or alone; the other kinds keep theirs.
    #[test]
    fn a_shared_lease_needs_format_21() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let items = |kinds: &[LeaseKind]| -> Vec<LeaseItem> {
            let item = |&kind| LeaseItem {
                symbol: "a.rs#f".into(),
                kind,
                names: Vec::new(),
            };
            kinds.iter().map(item).collect()
        };
        let acquire = |items| Op::LeaseAcquire {
            set: "l".into(),
            items,
            intent: "x".into(),
            ttl_ms: 1000,
        };
        let interest = |items| Op::LeaseInterest {
            items,
            intent: "x".into(),
        };
        let at = |op: &Op, format| OpEntry {
            format,
            op: op.clone(),
            ..next(&g, 2000)
        };
        let shared = [LeaseKind::Edit, LeaseKind::Shared];
        for op in [
            acquire(items(&shared)),
            acquire(items(&[LeaseKind::Shared])),
            interest(items(&shared)),
        ] {
            assert_eq!(at(&op, 21).min_format(), FORMAT_SHARED_LEASES, "{op:?}");
            let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(&op, format), &key)]);
            assert!(chain(21).is_ok(), "{op:?}");
            let err = chain(20).unwrap_err();
            assert!(err.to_string().contains("needs log format 21"), "{err}");
        }
        let others = [LeaseKind::Edit, LeaseKind::Insert, LeaseKind::Rename];
        assert_eq!(at(&acquire(items(&others)), 2).min_format(), FORMAT_LEGACY);
        assert_eq!(
            at(&interest(items(&others)), 10).min_format(),
            FORMAT_LEASE_QUEUE
        );
    }

    /// Reserved names need their format, in an acquire or an interest, and
    /// come before `shared` in what an entry needs.
    #[test]
    fn reserved_names_need_format_22() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let named = LeaseItem {
            names: vec!["throttle".into()],
            ..LeaseItem::new("a.rs#T", LeaseKind::Insert)
        };
        let shared = LeaseItem::new("a.rs#f", LeaseKind::Shared);
        let acquire = |items| Op::LeaseAcquire {
            set: "l".into(),
            items,
            intent: "x".into(),
            ttl_ms: 1000,
        };
        let interest = |items| Op::LeaseInterest {
            items,
            intent: "x".into(),
        };
        let at = |op: &Op, format| OpEntry {
            format,
            op: op.clone(),
            ..next(&g, 2000)
        };
        for op in [
            acquire(vec![named.clone()]),
            acquire(vec![shared.clone(), named.clone()]),
            interest(vec![named.clone()]),
        ] {
            assert_eq!(at(&op, 22).min_format(), FORMAT_INSERT_NAMES, "{op:?}");
            let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(&op, format), &key)]);
            assert!(chain(22).is_ok(), "{op:?}");
            let err = chain(21).unwrap_err();
            assert!(err.to_string().contains("needs log format 22"), "{err}");
        }
        let unnamed = acquire(vec![LeaseItem::new("a.rs#T", LeaseKind::Insert)]);
        assert_eq!(at(&unnamed, 2).min_format(), FORMAT_LEGACY);
        // No names, no field: the bytes of an older item.
        let bytes = serde_json::to_string(&LeaseItem::new("a.rs#T", LeaseKind::Insert)).unwrap();
        assert_eq!(bytes, r#"{"symbol":"a.rs#T","kind":"insert"}"#);
    }

    #[test]
    fn the_lease_queue_needs_format_10() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let scope = Scope {
            paths: vec!["**".into()],
            symbols: None,
            ops: vec![],
            max_files: None,
            max_lines: None,
            scratch: vec![],
        };
        let attenuate = |leases| Op::CapAttenuate {
            parent: "p".into(),
            child: "c".into(),
            agent: "bot".into(),
            scope: scope.clone(),
            expires_ms: 9000,
            leases,
        };
        let negotiate = |to| Op::Negotiate {
            thread: "t".into(),
            to_session: "s".into(),
            message: NegotiationMsg::Yield {
                set: "l".into(),
                to,
            },
        };
        let at = |op: &Op, format| OpEntry {
            format,
            op: op.clone(),
            ..next(&g, 2000)
        };
        for op in [
            Op::LeaseInterest {
                items: vec![],
                intent: String::new(),
            },
            negotiate(Some("s".into())),
            attenuate(vec!["l".into()]),
        ] {
            assert_eq!(at(&op, 10).min_format(), FORMAT_LEASE_QUEUE, "{op:?}");
            let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(&op, format), &key)]);
            assert!(chain(10).is_ok(), "{op:?}");
            let err = chain(9).unwrap_err();
            assert!(err.to_string().contains("needs log format 10"), "{err}");
        }
        for op in [negotiate(None), attenuate(vec![])] {
            assert_eq!(at(&op, 2).min_format(), FORMAT_LEGACY, "{op:?}");
        }
    }

    #[test]
    fn isolating_a_session_needs_its_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let op = Op::SessionIsolate {
            session: "s".into(),
            sandbox: "seatbelt".into(),
            profile: "ab".repeat(32),
        };
        let at = |format| OpEntry {
            format,
            op: op.clone(),
            ..next(&g, 2000)
        };
        assert_eq!(at(FORMAT_ISOLATE).min_format(), FORMAT_ISOLATE);
        let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(format), &key)]);
        assert!(chain(FORMAT_ISOLATE).is_ok());
        let err = chain(FORMAT_ISOLATE - 1).unwrap_err();
        let needs = format!("needs log format {FORMAT_ISOLATE}");
        assert!(err.to_string().contains(&needs), "{err}");
    }

    #[test]
    fn a_batch_needs_its_format() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let tip = GitId::of_blob(b"tip");
        let op = Op::ChangeIntegrateBatch {
            trunk_before: tip.clone(),
            merged: vec![(ChangeId::random(), tip)],
        };
        let at = |format| OpEntry {
            format,
            op: op.clone(),
            symbols_engine: Some(1),
            ..next(&g, 2000)
        };
        assert_eq!(at(FORMAT_BATCH).min_format(), FORMAT_BATCH);
        let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(format), &key)]);
        assert!(chain(FORMAT_BATCH).is_ok());
        let err = chain(FORMAT_BATCH - 1).unwrap_err();
        let needs = format!("needs log format {FORMAT_BATCH}");
        assert!(err.to_string().contains(&needs), "{err}");
    }

    #[test]
    fn the_unproposed_observation_needs_format_11() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let observe = |kind| Op::Observe {
            session: "s".into(),
            events: vec![crate::ops::Observation {
                phase: crate::ops::Phase::Post,
                kind,
                external: false,
            }],
        };
        let at = |op: &Op, format| OpEntry {
            format,
            op: op.clone(),
            ..next(&g, 2000)
        };
        let report = observe(ObsKind::Unproposed {
            paths: vec![],
            total: 0,
        });
        assert_eq!(at(&report, 11).min_format(), FORMAT_UNPROPOSED);
        let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(&report, format), &key)]);
        assert!(chain(11).is_ok());
        let err = chain(10).unwrap_err();
        assert!(err.to_string().contains("needs log format 11"), "{err}");
        assert_eq!(
            at(&observe(ObsKind::Heartbeat), 2).min_format(),
            FORMAT_LEGACY
        );
    }

    #[test]
    fn the_unhooked_observation_needs_format_24() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let observe = |kinds: Vec<ObsKind>| Op::Observe {
            session: "s".into(),
            events: kinds
                .into_iter()
                .map(|kind| crate::ops::Observation {
                    phase: crate::ops::Phase::Pre,
                    kind,
                    external: false,
                })
                .collect(),
        };
        let at = |op: &Op, format| OpEntry {
            format,
            op: op.clone(),
            ..next(&g, 2000)
        };
        let unhooked = || ObsKind::Unhooked {
            tool: "propose".into(),
        };
        let mark = observe(vec![unhooked()]);
        assert_eq!(at(&mark, 24).min_format(), FORMAT_UNHOOKED);
        // With an older kind beside it, the newer one decides.
        let unproposed = ObsKind::Unproposed {
            paths: vec![],
            total: 0,
        };
        let both = observe(vec![unproposed, unhooked()]);
        assert_eq!(at(&both, 24).min_format(), FORMAT_UNHOOKED);
        let chain = |format| verify_chain(&[g.clone(), SignedOp::sign(at(&mark, format), &key)]);
        assert!(chain(24).is_ok());
        let err = chain(23).unwrap_err();
        assert!(err.to_string().contains("needs log format 24"), "{err}");
    }

    #[test]
    fn named_checks_on_an_approval_need_format_25() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 2), &key);
        let approve = |checks: &[&str]| Op::Approve {
            target_seq: 1,
            note: String::new(),
            checks: checks.iter().map(|c| c.to_string()).collect(),
        };
        let at = |op: Op, format| OpEntry {
            format,
            op,
            ..next(&g, 2000)
        };
        assert_eq!(at(approve(&["api"]), 25).min_format(), FORMAT_NAMED_CHECKS);
        // Without checks an approval is what it always was.
        assert_eq!(at(approve(&[]), 2).min_format(), FORMAT_LEGACY);
        let chain = |format| {
            let e = SignedOp::sign(at(approve(&["api"]), format), &key);
            verify_chain(&[g.clone(), e])
        };
        assert!(chain(25).is_ok());
        let err = chain(24).unwrap_err();
        assert!(err.to_string().contains("needs log format 25"), "{err}");
        // Old approvals keep their bytes: no `checks` key at all.
        let text = serde_json::to_string(&approve(&[])).unwrap();
        assert!(!text.contains("checks"), "{text}");
    }

    #[test]
    fn a_recovery_key_on_a_daemon_recovery_needs_format_27() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let g = SignedOp::sign(with_format(genesis(&key, &store), 4), &key);
        let recover = |with: bool| Op::DaemonRecover {
            key: "01".into(),
            recover: with.then(|| crate::ops::Recovery {
                human: "ayse".into(),
                key: crate::ops::HumanKey {
                    alg: "ed25519".into(),
                    public: "02".into(),
                },
            }),
        };
        // Denied, so the key in force signs it.
        let at = |op: Op, format| OpEntry {
            format,
            op,
            decision: Decision::deny("x"),
            ..next(&g, 2000)
        };
        assert_eq!(at(recover(true), 27).min_format(), FORMAT_RECOVERY_DAEMON);
        assert_eq!(at(recover(false), 4).min_format(), FORMAT_DAEMON_KEYS);
        let chain =
            |format| verify_chain(&[g.clone(), SignedOp::sign(at(recover(true), format), &key)]);
        assert!(chain(27).is_ok());
        let err = chain(26).unwrap_err();
        assert!(err.to_string().contains("needs log format 27"), "{err}");
        // Old recoveries keep their bytes: no `recover` key at all.
        let text = serde_json::to_string(&recover(false)).unwrap();
        assert!(!text.contains("\"recover\""), "{text}");
        assert!(recover(true).signed_by_recovery_key());
        assert!(!recover(false).signed_by_recovery_key());
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
            Op::DaemonRecover {
                key: "01".into(),
                recover: None,
            },
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
            recover: None,
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

    /// A log's commit made by hand: `tree` as its tree, on `parents`.
    fn commit_of(store: &Store, tree: GitId, parents: &[&GitId]) -> GitId {
        let spec = CommitSpec {
            tree,
            parents: parents.iter().map(|p| (*p).clone()).collect(),
            author_name: "lonca".into(),
            author_email: "daemon@lonca.invalid".into(),
            time_ms: 1000,
            message: "by hand".into(),
            headers: vec![],
        };
        store.write_commit(&spec).unwrap()
    }

    fn tree_with(store: &Store, name: &str, bytes: &[u8]) -> GitId {
        let mut files = FileMap::new();
        let blob = store.write_blob(bytes).unwrap();
        let mode = FileMode::Regular;
        files.insert(name.into(), FileEntry { mode, blob });
        store.write_tree(&files).unwrap()
    }

    /// The whole log is read on several threads at a daemon's start and by
    /// an audit. It must be what the walk from the head gives: the same
    /// entries with the same commits, or the error that walk meets first.
    #[test]
    fn the_whole_log_reads_as_the_walk_from_its_head_does() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let key = KeyPair::generate();
        let log = OpLog::new(&store);
        assert_eq!(log.walk_all().unwrap(), vec![]);

        let mut ops = vec![SignedOp::sign(genesis(&key, &store), &key)];
        let mut heads = vec![log.append(&ops[0], None).unwrap()];
        for i in 1..30 {
            ops.push(SignedOp::sign(next(&ops[i - 1], 1000 + i as i64), &key));
            heads.push(log.append(&ops[i], heads.last()).unwrap());
        }
        let said = |r: Result<Vec<(GitId, SignedOp)>>| match r {
            Ok(found) => Ok(found),
            Err(e) => Err(e.to_string()),
        };
        let same = |what: &str| {
            let walk = said(log.walk_from(0));
            for threads in [1, 2, 3, 7, 64] {
                let all = said(log.walk_all_on(Some(threads)));
                assert_eq!(all, walk, "{what}, {threads} threads");
            }
            assert_eq!(said(log.walk_all()), walk, "{what}");
            walk
        };
        let whole = same("whole").unwrap();
        let want: Vec<_> = heads.iter().cloned().zip(ops.iter().cloned()).collect();
        assert_eq!(whole, want);
        assert_eq!(log.read_all().unwrap(), ops);

        // Damage, built on top of the log from its entry `at`: every kind
        // the walk can meet, alone and two at once, nearer the head or
        // further from it.
        let good = |parent: &GitId, n: usize| {
            let mut head = parent.clone();
            for _ in 0..n {
                let tree = store.read_commit(&heads[3]).unwrap().tree;
                head = commit_of(&store, tree, &[&head]);
            }
            head
        };
        let no_file = |parent: &GitId| {
            let tree = tree_with(&store, "other.json", b"{}");
            commit_of(&store, tree, &[parent])
        };
        let no_json = |parent: &GitId| {
            let tree = tree_with(&store, OP_FILE, b"not json");
            commit_of(&store, tree, &[parent])
        };
        let newer = |parent: &GitId| {
            let entry = br#"{"entry":{"format":4000000,"seq":7}}"#;
            commit_of(&store, tree_with(&store, OP_FILE, entry), &[parent])
        };
        let merge = |parent: &GitId| {
            let tree = store.read_commit(&heads[3]).unwrap().tree;
            commit_of(&store, tree, &[parent, &heads[0]])
        };
        // A merge whose own entry does not read: the entry is said first.
        let merge_no_file = |parent: &GitId| {
            let tree = tree_with(&store, "other.json", b"{}");
            commit_of(&store, tree, &[parent, &heads[0]])
        };
        type Damage<'a> = &'a dyn Fn(&GitId) -> GitId;
        let kinds: [(&str, Damage); 5] = [
            ("no file", &no_file),
            ("no json", &no_json),
            ("newer", &newer),
            ("merge", &merge),
            ("merge, no file", &merge_no_file),
        ];
        let head = heads.last().unwrap().clone();
        let set = |to: &GitId| {
            let now = log.head().unwrap();
            store.ref_cas(OPLOG_REF, to, now.as_ref()).unwrap();
        };
        let mut errors = BTreeSet::new();
        for (name, first) in kinds {
            for gap in [0, 1, 5] {
                let one = good(&first(&good(&heads[20], gap)), gap);
                set(&one);
                errors.insert(same(&format!("{name}, {gap} above")).unwrap_err());
                for (other, second) in kinds {
                    let two = good(&second(&good(&one, gap)), gap);
                    set(&two);
                    let e = same(&format!("{other} over {name}, {gap} apart"));
                    errors.insert(e.unwrap_err());
                }
            }
        }
        // Each kind was the one reported somewhere.
        let reported = |part: &str| errors.iter().any(|e| e.contains(part));
        assert!(reported("has no op.json"), "{errors:?}");
        assert!(reported("is a merge"), "{errors:?}");
        assert!(reported("json: "), "{errors:?}");
        assert!(reported("format 4000000"), "{errors:?}");

        // A commit that is not there: the entries above it are read first.
        set(&head);
        let lost = store.path().join("objects");
        let id = heads[10].0.clone();
        let file = lost.join(&id[..2]).join(&id[2..]);
        std::fs::remove_file(&file).unwrap();
        let store = Store::open(store.path()).unwrap();
        let log = OpLog::new(&store);
        let walk = log.walk_from(0).map_err(|e| e.to_string());
        assert!(walk.is_err());
        for threads in [1, 2, 7] {
            let all = log.walk_all_on(Some(threads)).map_err(|e| e.to_string());
            assert_eq!(all, walk, "{threads} threads");
        }
    }

    /// The signatures of a long log are checked on several threads. What
    /// `verify_chain` says must not depend on how many: the same head, or
    /// the same first entry with the same words, wherever the damage is and
    /// however many entries are damaged.
    #[test]
    fn the_answer_does_not_depend_on_the_threads() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::init_bare(&dir.path().join("r.git")).unwrap();
        let (k0, k1, k2) = (
            KeyPair::generate(),
            KeyPair::generate(),
            KeyPair::generate(),
        );
        let mut log = vec![SignedOp::sign(genesis(&k0, &store), &k0)];
        let mut key = &k0;
        for i in 1..40 {
            let prev = log.last().unwrap();
            let op = match i {
                10 => {
                    let rotate = Op::DaemonRotate {
                        key: k1.public_hex(),
                    };
                    let op = switch(prev, rotate, Decision::allow(), key);
                    key = &k1;
                    op
                }
                20 => {
                    let recover = Op::DaemonRecover {
                        key: k2.public_hex(),
                        recover: None,
                    };
                    key = &k2;
                    switch(prev, recover, Decision::allow(), key)
                }
                _ => SignedOp::sign(next(prev, prev.entry.time_ms + 1), key),
            };
            log.push(op);
        }
        let said = |ops: &[SignedOp], threads| match verify_chain_on(ops, threads) {
            Ok(head) => format!("ok {head}"),
            Err(e) => e.to_string(),
        };
        let same = |ops: &[SignedOp], what: &str| -> String {
            let one = said(ops, 1);
            for threads in [0, 2, 3, 7, 40, 64] {
                assert_eq!(said(ops, threads), one, "{what}, {threads} threads");
            }
            one
        };
        assert_eq!(same(&log, "whole"), format!("ok {}", log[39].hash));

        let other = KeyPair::generate();
        let forged = |ops: &mut [SignedOp], i: usize| {
            ops[i] = SignedOp::sign(ops[i].entry.clone(), &other);
        };
        let edited = |ops: &mut [SignedOp], i: usize| {
            ops[i].entry.decision = Decision::deny("rewritten");
        };
        let unchained = |ops: &mut [SignedOp], i: usize| {
            ops[i].entry.prev = "f".repeat(64);
        };
        for i in 0..log.len() {
            let mut ops = log.clone();
            forged(&mut ops, i);
            let e = same(&ops, &format!("forged {i}"));
            assert!(e.contains(&format!("op {i}: bad daemon signature")), "{e}");

            let mut ops = log.clone();
            edited(&mut ops, i);
            let e = same(&ops, &format!("edited {i}"));
            assert!(e.contains(&format!("op {i}: hash does not match")), "{e}");

            // Two entries damaged: the first is the one named, whatever
            // each of them fails and whichever thread reads it.
            for j in [0, 9, 10, 11, 19, 20, 21, 39] {
                if i == j {
                    continue;
                }
                let first = i.min(j);
                let mut ops = log.clone();
                forged(&mut ops, i);
                unchained(&mut ops, j);
                let e = same(&ops, &format!("forged {i}, unchained {j}"));
                assert!(e.starts_with(&format!("integrity: op {first}: ")), "{e}");
                let mut ops = log.clone();
                edited(&mut ops, i);
                forged(&mut ops, j);
                let e = same(&ops, &format!("edited {i}, forged {j}"));
                assert!(e.starts_with(&format!("integrity: op {first}: ")), "{e}");
            }
        }
        // Past a key switch that was taken out, the key in force is the
        // one before it, on every thread.
        let mut ops = log.clone();
        ops[10].entry.decision = Decision::deny("x");
        ops[10] = SignedOp::sign(ops[10].entry.clone(), &k0);
        let e = same(&ops, "rotation denied");
        assert!(e.contains("op 11: "), "{e}");
    }

    fn with_format(e: OpEntry, format: u32) -> OpEntry {
        OpEntry { format, ..e }
    }
}
