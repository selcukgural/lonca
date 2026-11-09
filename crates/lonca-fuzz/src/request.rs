//! Lines on the daemon's socket, from anyone who can reach it: an agent in
//! its sandbox, a human, or neither.
//!
//! An input is up to [`MAX_LINES`] request lines, run in order on a fresh
//! copy of the template (`template.rs`), so a crash is reproduced by its
//! input alone. `$HUMAN`, `$AGENT`, `$AGENT2` in a line stand for the
//! template's session tokens, `$WS` for the agents' workspace and `$TRUNK`
//! for trunk, so that the fuzzer gets past authentication; a human
//! operation still needs a signature it can not make.
//!
//! Whatever was asked, the daemon must answer each line with its id, its
//! log must still audit clean (deep, every ref held to the log), and it must
//! open again on its home.

use std::sync::Arc;
use std::sync::atomic::AtomicI64;

use lonca_audit::{Options, audit};
use lonca_client::protocol::Request;
use lonca_daemon::limits::head_of;

use crate::template;

pub const MAX_LINES: usize = 16;

/// A line with the template's tokens and names in place of their markers.
pub fn fill(line: &str, root: &std::path::Path) -> String {
    let t = template::get();
    let ws = root.join("ws");
    line.replace("$HUMAN", &t.human_token)
        .replace("$AGENT2", &t.agent_tokens[1])
        .replace("$AGENT", &t.agent_tokens[0])
        .replace("$WS", &ws.to_string_lossy())
        .replace("$TRUNK", &t.trunk.to_string())
}

pub fn check(data: &[u8]) {
    let t = template::get();
    let dir = tempfile::Builder::new()
        .prefix("lonca-fuzz-")
        .tempdir()
        .unwrap_or_else(|e| panic!("no temp dir: {e}"));
    let root = dir.path().canonicalize().unwrap_or_else(|e| panic!("{e}"));
    template::copy_to(&root);
    let clock = Arc::new(AtomicI64::new(t.time_ms));
    let svc = template::open(&root, &clock);
    let text = String::from_utf8_lossy(data);
    for line in text.lines().take(MAX_LINES) {
        let line = fill(line, &root);
        // What a long line is let in by, read before the rest arrives.
        let _ = head_of(line.as_bytes());
        let Ok(req) = serde_json::from_str::<Request>(&line) else {
            continue;
        };
        let id = req.id;
        let r = svc.handle(req);
        assert_eq!(r.id, id, "an answer to another request");
        assert_eq!(r.ok, r.error.is_none(), "an answer both ok and not");
        if let Err(e) = serde_json::to_string(&r) {
            panic!("an answer that does not serialize: {e}");
        }
    }
    svc.process_all();
    drop(svc);

    let report = audit(
        &template::store(&root),
        Options {
            deep: true,
            check_refs: true,
            all_refs: true,
        },
    );
    match report {
        Ok(r) => assert!(r.ok(), "the log no longer audits clean: {:?}", r.findings),
        Err(e) => panic!("the log can not be read: {e}"),
    }
    let _again = template::open(&root, &clock);
}
