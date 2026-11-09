//! One stored log entry (`refs/lonca/oplog`, `op.json`), as the daemon and
//! the auditor read it back.
//!
//! An entry's hash is the SHA-256 of its canonical form, recomputed by
//! whoever reads it. So what decodes must come back from its canonical form
//! as the same entry, and that form must be a fixed point: otherwise two
//! readers could hash one entry two ways.

use lonca_core::canonical::canonical_bytes;
use lonca_core::oplog::{self, SignedOp, verify_chain};

pub fn check(data: &[u8]) {
    let Ok(op) = oplog::decode(data) else {
        return;
    };
    let bytes = canonical_bytes(&op);
    let again: SignedOp = match oplog::decode(&bytes) {
        Ok(again) => again,
        Err(e) => panic!("the canonical form of a decoded entry does not decode: {e}"),
    };
    assert_eq!(again, op, "an entry changes through its canonical form");
    assert_eq!(
        canonical_bytes(&again),
        bytes,
        "the canonical form is no fixed point"
    );
    assert_eq!(again.entry.digest(), op.entry.digest());

    // What readers ask of an entry before they trust it.
    let e = &op.entry;
    let _ = (e.min_format(), e.engine(), e.uses_symbols_engine());
    let in_force = e.switches_daemon_key().unwrap_or("");
    let _ = op.verify(e.signer(in_force));
    let _ = verify_chain(std::slice::from_ref(&op));
}
