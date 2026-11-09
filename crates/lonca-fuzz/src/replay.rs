//! A whole log, as the auditor reads one from a repository it was handed.
//!
//! An input is up to [`MAX_ENTRIES`] log entries (`OpEntry`), one JSON line
//! each. They are numbered, chained and signed with a key of the target's,
//! which the first entry names if it is a `repo.init`, so that the fuzzer
//! reaches what comes after the signature checks: `decide()` again for
//! every entry, the replayed state, and the facts and merges recomputed
//! from the template's objects. Whatever the log says, the auditor reports;
//! it never panics.

use lonca_audit::{Options, audit_ops};
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{GENESIS_PREV, OpEntry, SignedOp};
use lonca_core::ops::Op;
use zeroize::Zeroizing;

use crate::template;

pub const MAX_ENTRIES: usize = 64;

pub fn key() -> KeyPair {
    KeyPair::from_secret(Zeroizing::new([9; 32]))
}

/// The entries of `data`, as a chain signed by [`key`].
pub fn chain(data: &[u8]) -> Vec<SignedOp> {
    let key = key();
    let text = String::from_utf8_lossy(data);
    let entries = text
        .lines()
        .filter_map(|l| serde_json::from_str::<OpEntry>(l).ok());
    let mut prev = GENESIS_PREV.to_string();
    let mut ops = Vec::new();
    for (seq, mut entry) in entries.take(MAX_ENTRIES).enumerate() {
        entry.seq = seq as u64;
        entry.prev = prev;
        if let (0, Op::RepoInit { daemon_key, .. }) = (seq, &mut entry.op) {
            *daemon_key = key.public_hex();
        }
        let op = SignedOp::sign(entry, &key);
        prev = op.hash.clone();
        ops.push(op);
    }
    ops
}

pub fn check(data: &[u8]) {
    let ops = chain(data);
    let store = template::store(&template::get().root);
    let opts = Options {
        deep: true,
        check_refs: false,
        all_refs: false,
    };
    let first = audit_ops(&store, &ops, opts);
    // Facts, merges and decisions are pure: a second reading finds the same.
    let second = audit_ops(&store, &ops, opts);
    assert_eq!(
        first.findings, second.findings,
        "the auditor changed its mind"
    );
    assert_eq!(first.skipped, second.skipped);
}
