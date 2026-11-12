//! Timings of the decision function and the fold on large states. Nothing
//! here asserts a time: they print, and are run by hand
//! (`cargo test --release -p lonca-policy --test perf -- --ignored --nocapture`).

use lonca_core::canonical::nonce;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::SignedOp;
use lonca_core::ops::*;
use lonca_core::{ChangeId, GitId};
use std::sync::Arc;
use std::time::Instant;

use lonca_policy::chain::{Chain, Submission};
use lonca_policy::config::{PolicyBundle, UnparsedFiles};
use lonca_policy::details::lease_report;
use lonca_policy::human::intent_bytes;
use lonca_policy::state::Renamed;

const REPO: &str = "demo";
const T0: i64 = 1_760_000_000_000;
const MIN: i64 = 60_000;

fn gid(n: usize) -> GitId {
    GitId(format!("{n:040x}"))
}

struct H {
    chain: Chain,
    policy: Arc<PolicyBundle>,
    key: KeyPair,
    now: i64,
}

impl H {
    fn new() -> Self {
        let mut h = H {
            chain: Chain::new(KeyPair::generate()),
            policy: Arc::new(PolicyBundle::default_bundle()),
            key: KeyPair::generate(),
            now: T0,
        };
        let op = Op::RepoInit {
            repo: REPO.into(),
            daemon_key: h.chain.public_key(),
            human: "ayse".into(),
            human_key: HumanKey {
                alg: "ed25519".into(),
                public: h.key.public_hex(),
            },
            policy: gid(1),
            trunk: gid(2),
        };
        assert!(h.human(op).entry.decision.is_allow());
        h
    }

    fn prepare(&mut self, sub: Submission) -> SignedOp {
        self.now += 1;
        self.chain.prepare(sub, self.now, &self.policy)
    }

    fn submit(&mut self, sub: Submission) -> SignedOp {
        let op = self.prepare(sub);
        self.chain.commit(&op);
        op
    }

    fn human(&mut self, op: Op) -> SignedOp {
        let s = &self.chain.state;
        let at = s.next_seq.checked_sub(1).map(|seq| LogPoint {
            seq,
            hash: s.head_hash.clone(),
        });
        let nonce = nonce();
        let issued_ms = self.now + 1;
        let sig = self
            .key
            .sign_hex(&intent_bytes(REPO, &op, &nonce, issued_ms, at.as_ref()));
        let mut sub = Submission::new(
            Actor::Human {
                name: "ayse".into(),
            },
            op,
        );
        sub.human = Some(HumanSignature {
            human: "ayse".into(),
            nonce,
            issued_ms,
            sig,
            at,
        });
        self.submit(sub)
    }

    fn start(&mut self, session: &str) {
        let op = Op::SessionStart {
            session: session.into(),
            agent: format!("bot-{session}"),
            model: None,
            task: "T-1".into(),
            scope: Scope {
                paths: vec!["src/**".into()],
                symbols: None,
                ops: vec![
                    OpKind::ChangePropose,
                    OpKind::LeaseAcquire,
                    OpKind::LeaseInterest,
                    OpKind::CapAttenuate,
                ],
                max_files: None,
                max_lines: None,
                scratch: vec![],
            },
            expires_ms: self.now + 120 * MIN,
            continues: None,
            harness: Some("claude-code".into()),
            workspace: Some(format!("/ws/{session}")),
        };
        let d = self.human(op).entry.decision;
        assert!(d.is_allow(), "{d:?}");
    }

    fn agent(&self, session: &str, op: Op) -> Submission {
        Submission::new(
            Actor::Agent {
                name: format!("bot-{session}"),
                session: session.into(),
            },
            op,
        )
    }
}

/// A trunk of `len` commits, as that many integrations would leave it.
fn long_trunk(h: &mut H, len: usize, renames: usize) {
    let s = &mut h.chain.state;
    for i in 0..len {
        let id = gid(1000 + i);
        s.trunk_history.insert(id.clone());
        s.trunk_line.push(id);
    }
    for i in 0..renames {
        s.renames.push(Renamed {
            line: 1 + i * len.max(1) / renames.max(1),
            old: format!("src/old{i}.rs#gone{i}"),
            new: format!("src/old{i}.rs#here{i}"),
            reused: None,
        });
    }
}

fn proposal(needs: usize, base: GitId) -> (Op, Facts) {
    let edits: Vec<String> = (0..needs)
        .map(|i| format!("src/f{}.rs#fn{i}", i % 150))
        .collect();
    let facts = Facts {
        modified_files: (0..150.min(needs))
            .map(|i| format!("src/f{i}.rs"))
            .collect(),
        edits: edits.clone(),
        lines_added: 2,
        lines_removed: 1,
        ..Default::default()
    };
    let claim = Claim {
        intent: "test".into(),
        edits,
        adds: vec![],
        deletes: vec![],
        deleted_files: vec![],
        signature_changes: vec![],
        tests: facts.tests.clone(),
        revert_of: None,
    };
    let op = Op::ChangePropose {
        change: ChangeId::random(),
        commit: gid(7),
        base,
        claim,
    };
    (op, facts)
}

/// `decide()` for a proposal, by the length of trunk, what the proposal
/// touches and where its base is.
#[test]
#[ignore = "a timing, run by hand"]
fn a_proposal_by_trunk_length_and_base() {
    println!("trunk  renames  needs  items  base     decide_ms  denied");
    for (trunk, renames, needs, sets) in [
        (100, 0, 100, 1),
        (10_000, 0, 100, 1),
        (10_000, 0, 5_000, 1),
        (10_000, 100, 5_000, 1),
        (100_000, 0, 5_000, 1),
    ] {
        let mut h = H::new();
        h.start("s1");
        for set in 0..sets {
            let items = (0..64)
                .map(|i| LeaseItem {
                    symbol: format!("src/other{set}.rs#held{i}"),
                    kind: LeaseKind::Edit,
                    names: vec![],
                })
                .collect();
            let lease = Op::LeaseAcquire {
                set: format!("set{set}"),
                items,
                intent: "work".into(),
                ttl_ms: 10 * MIN,
            };
            let sub = h.agent("s1", lease);
            let d = h.submit(sub).entry.decision;
            assert!(d.is_allow(), "{d:?}");
        }
        long_trunk(&mut h, trunk, renames);
        let head = h.chain.state.trunk_line.last().unwrap().clone();
        let oldest = h.chain.state.trunk_line[0].clone();
        for (name, base) in [("head", head), ("oldest", oldest), ("unknown", gid(9))] {
            let (op, facts) = proposal(needs, base);
            let mut sub = h.agent("s1", op);
            sub.facts = Some(facts);
            sub.symbols_engine = Some(0);
            let started = Instant::now();
            let op = h.prepare(sub);
            let ms = started.elapsed().as_secs_f64() * 1000.0;
            let denied = op.entry.decision.reasons.len();
            println!(
                "{trunk:<6} {renames:<8} {needs:<6} {:<6} {name:<8} {ms:<10.1} {denied}",
                sets * 64
            );
        }
    }
}

/// The fold of one observation, by how many sessions the log ever had.
#[test]
#[ignore = "a timing, run by hand"]
fn an_observation_by_sessions_ever_started() {
    println!("sessions  per_observe_us");
    for sessions in [10, 1_000, 10_000] {
        let mut h = H::new();
        h.start("s1");
        let one = h.chain.state.sessions["s1"].clone();
        for i in 0..sessions {
            let mut s = one.clone();
            s.id = format!("old{i}");
            h.chain.state.sessions.insert(s.id.clone(), s);
        }
        let rounds = 200;
        let started = Instant::now();
        for i in 0..rounds {
            let op = Op::Observe {
                session: "s1".into(),
                events: vec![Observation {
                    phase: Phase::Post,
                    kind: ObsKind::Write {
                        path: format!("src/a{i}.rs"),
                    },
                    external: false,
                }],
            };
            let op = h.prepare(Submission::new(Actor::Daemon, op));
            assert!(op.entry.decision.is_allow());
            h.chain.commit(&op);
        }
        let us = started.elapsed().as_secs_f64() * 1e6 / rounds as f64;
        println!("{sessions:<9} {us:.0}");
    }
}

/// `decide()` and the fold of one `lease.acquire`, by what other sessions
/// hold and how many renames trunk has had.
#[test]
#[ignore = "a timing, run by hand"]
fn a_lease_by_held_items_and_renames() {
    println!("holders  held_items  renames  decide_ms  commit_ms  outcome");
    for (holders, renames) in [(5, 0), (50, 0), (50, 50), (50, 500), (200, 500)] {
        let mut h = H::new();
        for s in 0..holders {
            let id = format!("h{s}");
            h.start(&id);
            let items = (0..64)
                .map(|i| LeaseItem {
                    symbol: format!("src/held{s}.rs#item{i}"),
                    kind: LeaseKind::Edit,
                    names: vec![],
                })
                .collect();
            let lease = Op::LeaseAcquire {
                set: format!("set{s}"),
                items,
                intent: "work".into(),
                ttl_ms: 10 * MIN,
            };
            let sub = h.agent(&id, lease);
            let d = h.submit(sub).entry.decision;
            assert!(d.is_allow(), "{d:?}");
        }
        h.start("s1");
        long_trunk(&mut h, 1_000, renames);
        let items = (0..64)
            .map(|i| LeaseItem {
                symbol: format!("src/mine.rs#item{i}"),
                kind: LeaseKind::Edit,
                names: vec![],
            })
            .collect();
        let lease = Op::LeaseAcquire {
            set: "mine".into(),
            items,
            intent: "work".into(),
            ttl_ms: 10 * MIN,
        };
        let sub = h.agent("s1", lease);
        let started = Instant::now();
        let op = h.prepare(sub);
        let decide = started.elapsed().as_secs_f64() * 1000.0;
        let started = Instant::now();
        h.chain.commit(&op);
        let commit = started.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{holders:<8} {:<11} {renames:<8} {decide:<10.2} {commit:<10.2} {:?}",
            holders * 64,
            op.entry.decision.outcome
        );
    }
}

/// A lease and the report of what a proposal still needs, by how many
/// sessions wait in line for something else.
#[test]
#[ignore = "a timing, run by hand"]
fn a_lease_by_waiting_interests() {
    println!("holders  waiting  decide_ms  report_needs  report_ms  outcome  details");
    for (holders, waiting) in [(50, 0), (50, 10), (50, 50), (200, 200)] {
        let mut h = H::new();
        for s in 0..holders {
            let id = format!("h{s}");
            h.start(&id);
            let items = (0..64)
                .map(|i| LeaseItem {
                    symbol: format!("src/held{s}.rs#item{i}"),
                    kind: LeaseKind::Edit,
                    names: vec![],
                })
                .collect();
            let lease = Op::LeaseAcquire {
                set: format!("set{s}"),
                items,
                intent: "work".into(),
                ttl_ms: 10 * MIN,
            };
            let sub = h.agent(&id, lease);
            let d = h.submit(sub).entry.decision;
            assert!(d.is_allow(), "{d:?}");
        }
        for w in 0..waiting {
            let id = format!("w{w}");
            h.start(&id);
            let wait = Op::LeaseInterest {
                items: vec![LeaseItem {
                    symbol: format!("src/held{}.rs#item{}", w % holders, w / holders),
                    kind: LeaseKind::Edit,
                    names: vec![],
                }],
                intent: "waiting".into(),
            };
            let sub = h.agent(&id, wait);
            let d = h.submit(sub).entry.decision;
            assert!(d.is_allow(), "{d:?}");
        }
        assert_eq!(h.chain.state.interests.len(), waiting);
        h.start("s1");
        let items = (0..64)
            .map(|i| LeaseItem {
                symbol: format!("src/mine.rs#item{i}"),
                kind: LeaseKind::Edit,
                names: vec![],
            })
            .collect();
        let lease = Op::LeaseAcquire {
            set: "mine".into(),
            items,
            intent: "work".into(),
            ttl_ms: 10 * MIN,
        };
        let sub = h.agent("s1", lease);
        let started = Instant::now();
        let op = h.prepare(sub);
        let decide = started.elapsed().as_secs_f64() * 1000.0;
        let needs = 200;
        let (_, facts) = proposal(needs, gid(2));
        let started = Instant::now();
        let report = lease_report(&h.chain.state, "s1", &facts, UnparsedFiles::File, h.now + 1);
        let reported = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(report.len(), needs);
        println!(
            "{holders:<8} {waiting:<8} {decide:<10.2} {needs:<13} {reported:<10.1} {:<8?} {}",
            op.entry.decision.outcome,
            report.len()
        );
    }
}
