//! Scenario tests for the decision function. Every scenario ends by
//! replaying its log and checking that each recorded decision is reproduced.

use lonca_core::canonical::nonce;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{FORMAT_CURRENT, SignedOp, verify_chain};
use lonca_core::ops::*;
use lonca_core::{ChangeId, GitId};
use std::sync::Arc;

use lonca_policy::chain::{Chain, Submission, replay_checked};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY, PolicyBundle};
use lonca_policy::decide::{Ctx, decide};
use lonca_policy::human::intent_bytes;
use lonca_policy::state::{ChangeStatus, Provenance, State};

const REPO: &str = "demo";
const T0: i64 = 1_760_000_000_000;
use lonca_core::ops::MAX_UNPROPOSED_PATHS;

const MIN: i64 = 60_000;

fn gid(c: char) -> GitId {
    GitId(std::iter::repeat_n(c, 40).collect())
}

struct H {
    chain: Chain,
    policy: Arc<PolicyBundle>,
    humans: Vec<(String, KeyPair)>,
    now: i64,
    log: Vec<SignedOp>,
}

impl H {
    fn new() -> Self {
        Self::with_policy(PolicyBundle::default_bundle())
    }

    fn with_policy(policy: PolicyBundle) -> Self {
        let mut h = H {
            chain: Chain::new(KeyPair::generate()),
            policy: Arc::new(policy),
            humans: vec![("ayse".into(), KeyPair::generate())],
            now: T0,
            log: vec![],
        };
        let op = Op::RepoInit {
            repo: REPO.into(),
            daemon_key: h.chain.public_key(),
            human: "ayse".into(),
            human_key: HumanKey {
                alg: "ed25519".into(),
                public: h.humans[0].1.public_hex(),
            },
            policy: gid('a'),
            trunk: gid('b'),
        };
        let d = h.human("ayse", op);
        assert!(d.is_allow(), "{d:?}");
        h
    }

    fn sign(&self, name: &str, op: &Op) -> HumanSignature {
        let key = &self.humans.iter().find(|(n, _)| n == name).unwrap().1;
        self.sign_with(key, name, op)
    }

    fn sign_with(&self, key: &KeyPair, name: &str, op: &Op) -> HumanSignature {
        let nonce = nonce();
        let issued_ms = self.now + 1;
        HumanSignature {
            human: name.into(),
            nonce: nonce.clone(),
            issued_ms,
            sig: key.sign_hex(&intent_bytes(REPO, op, &nonce, issued_ms)),
        }
    }

    fn submit(&mut self, mut sub: Submission) -> Decision {
        self.now += 1;
        // Like the daemon: proposals and integrations record the symbol
        // engine (here the facts are written by hand, nominally engine 0).
        if matches!(
            sub.op,
            Op::ChangePropose { .. } | Op::ChangeIntegrate { .. }
        ) {
            sub.symbols_engine = Some(0);
        }
        let op = self.chain.prepare(sub, self.now, &self.policy);
        self.chain.commit(&op);
        self.log.push(op.clone());
        op.entry.decision
    }

    fn human(&mut self, name: &str, op: Op) -> Decision {
        let sig = self.sign(name, &op);
        let mut sub = Submission::new(Actor::Human { name: name.into() }, op);
        sub.human = Some(sig);
        self.submit(sub)
    }

    /// Submits `op` as `name`, signed with `key` (whatever key that is).
    fn human_with(&mut self, key: &KeyPair, name: &str, op: Op) -> Decision {
        let sig = self.sign_with(key, name, &op);
        let mut sub = Submission::new(Actor::Human { name: name.into() }, op);
        sub.human = Some(sig);
        self.submit(sub)
    }

    /// Enrolls `name` with a new file key (signed by ayse).
    fn enroll(&mut self, name: &str) {
        let key = KeyPair::generate();
        let d = self.human(
            "ayse",
            Op::HumanEnroll {
                human: name.into(),
                key: file_key(&key),
            },
        );
        assert!(d.is_allow(), "{d:?}");
        self.use_key(name, key);
    }

    /// The key the harness signs with for `name` from now on.
    fn use_key(&mut self, name: &str, key: KeyPair) {
        self.humans.retain(|(n, _)| n != name);
        self.humans.push((name.into(), key));
    }

    fn human_change(&mut self, name: &str, op: Op, facts: Facts) -> Decision {
        let sig = self.sign(name, &op);
        let mut sub = Submission::new(Actor::Human { name: name.into() }, op);
        sub.human = Some(sig);
        sub.facts = Some(facts);
        self.submit(sub)
    }

    fn agent(&mut self, session: &str, op: Op) -> Decision {
        self.agent_facts(session, op, None)
    }

    fn agent_facts(&mut self, session: &str, op: Op, facts: Option<Facts>) -> Decision {
        let agent = self
            .chain
            .state
            .sessions
            .get(session)
            .map(|s| s.agent.clone())
            .unwrap_or("bot".into());
        let mut sub = Submission::new(
            Actor::Agent {
                name: agent,
                session: session.into(),
            },
            op,
        );
        sub.facts = facts;
        self.submit(sub)
    }

    fn daemon(&mut self, op: Op, evidence: Vec<Attestation>) -> Decision {
        let mut sub = Submission::new(Actor::Daemon, op);
        sub.evidence = evidence;
        self.submit(sub)
    }

    fn start(&mut self, session: &str, paths: &[&str]) {
        self.start_as("ayse", session, paths);
    }

    fn start_as(&mut self, human: &str, session: &str, paths: &[&str]) {
        let op = self.start_op(session, paths, None);
        let d = self.human(human, op);
        assert!(d.is_allow(), "{d:?}");
    }

    /// `session` takes over the workspace of `old`.
    fn continue_as(&mut self, session: &str, old: &str, paths: &[&str], widen: bool) -> Decision {
        let continues = Some(Continuation {
            session: old.into(),
            widen,
        });
        let op = self.start_op(session, paths, continues);
        self.human("ayse", op)
    }

    fn start_op(&self, session: &str, paths: &[&str], continues: Option<Continuation>) -> Op {
        Op::SessionStart {
            session: session.into(),
            agent: format!("bot-{session}"),
            model: Some("test-model".into()),
            task: "T-1".into(),
            scope: Scope {
                paths: paths.iter().map(|p| p.to_string()).collect(),
                symbols: None,
                ops: vec![
                    OpKind::ChangePropose,
                    OpKind::ChangeWithdraw,
                    OpKind::LeaseAcquire,
                    OpKind::LeaseRelease,
                    OpKind::LeaseRenew,
                    OpKind::Negotiate,
                    OpKind::CapAttenuate,
                ],
                max_files: None,
                max_lines: None,
                scratch: vec![],
            },
            expires_ms: self.now + 120 * MIN,
            continues,
        }
    }

    /// Start a session and bind it as observed by locked hooks + sandbox.
    fn start_observed(&mut self, session: &str, paths: &[&str]) {
        self.start_observed_as("ayse", session, paths);
    }

    fn start_observed_as(&mut self, human: &str, session: &str, paths: &[&str]) {
        self.start_as(human, session, paths);
        let checks = BindChecks {
            harness: "claude-code".into(),
            harness_session: format!("h-{session}"),
            managed_hooks: true,
            locked_sandbox: true,
            sudo_without_password: false,
            config_digest: "cfg".into(),
            hook_binary_protected: true,
        };
        let d = self.daemon(
            Op::SessionBind {
                session: session.into(),
                checks,
                level: ObservationLevel::HooksSandbox,
            },
            vec![],
        );
        assert!(d.is_allow(), "{d:?}");
    }

    fn wrote(&mut self, session: &str, path: &str) {
        let d = self.daemon(
            Op::Observe {
                session: session.into(),
                events: vec![Observation {
                    phase: Phase::Post,
                    kind: ObsKind::Write { path: path.into() },
                    external: false,
                }],
            },
            vec![],
        );
        assert!(d.is_allow(), "{d:?}");
    }

    fn lease(&mut self, session: &str, set: &str, items: &[(&str, LeaseKind)]) -> Decision {
        self.agent(
            session,
            Op::LeaseAcquire {
                set: set.into(),
                items: items
                    .iter()
                    .map(|(s, k)| LeaseItem {
                        symbol: s.to_string(),
                        kind: *k,
                    })
                    .collect(),
                intent: format!("work on {set}"),
                ttl_ms: 10 * MIN,
            },
        )
    }

    fn propose(&mut self, session: &str, change: ChangeId, facts: Facts) -> Decision {
        let claim = claim_of(&facts);
        self.propose_claim(session, change, facts, claim)
    }

    fn propose_claim(
        &mut self,
        session: &str,
        change: ChangeId,
        facts: Facts,
        claim: Claim,
    ) -> Decision {
        let base = self.chain.state.trunk.clone().unwrap();
        self.agent_facts(
            session,
            Op::ChangePropose {
                change,
                commit: gid('c'),
                base,
                claim,
            },
            Some(facts),
        )
    }

    /// The key the harness signs with for `name`.
    fn key_of(&self, name: &str) -> KeyPair {
        self.humans
            .iter()
            .find(|(n, _)| n == name)
            .unwrap()
            .1
            .clone()
    }

    /// A rotation as the daemon does it: signed by the key in force; if it
    /// is allowed, the new key signs from the next entry on.
    fn rotate_daemon(&mut self, name: &str, new: &KeyPair) -> Decision {
        let d = self.human(name, daemon_rotate(new));
        if d.is_allow() {
            self.chain.set_key(new.clone());
        }
        d
    }

    /// A recovery as the daemon does it: decided first, and logged (signed
    /// by the new key) only if allowed.
    fn recover_daemon_with(
        &mut self,
        signer: &KeyPair,
        name: &str,
        op: Op,
        new: &KeyPair,
    ) -> Decision {
        let sig = self.sign_with(signer, name, &op);
        let mut sub = Submission::new(Actor::Human { name: name.into() }, op);
        sub.human = Some(sig);
        let t = self.now + 1;
        let signed =
            Chain::from_state(new.clone(), self.chain.state.clone()).prepare(sub, t, &self.policy);
        if signed.entry.decision.is_allow() {
            self.now = t;
            self.chain.set_key(new.clone());
            self.chain.commit(&signed);
            self.log.push(signed.clone());
        }
        signed.entry.decision
    }

    /// Replays the whole log: chain integrity plus every decision, and the
    /// daemon's own check of the daemon key switches.
    fn assert_replay(&self) {
        verify_chain(&self.log).expect("chain verifies");
        replay_checked(&self.log, |_| Ok(self.policy.clone())).expect("key switches replay");
        let mut state = State::new();
        for op in &self.log {
            let e = &op.entry;
            let d = decide(
                &state,
                &e.actor,
                &e.op,
                e.human.as_ref(),
                &Ctx {
                    format: e.format,
                    time_ms: e.time_ms,
                    policy: &self.policy,
                    facts: e.facts.as_ref(),
                    evidence: &e.evidence,
                },
            );
            assert_eq!(
                d,
                e.decision,
                "replay of op {} ({})",
                e.seq,
                e.op.kind().as_str()
            );
            state.apply(op);
        }
    }
}

fn file_key(k: &KeyPair) -> HumanKey {
    HumanKey {
        alg: "ed25519".into(),
        public: k.public_hex(),
    }
}

fn edit(sym: &str) -> Facts {
    let path = sym.split('#').next().unwrap().to_string();
    Facts {
        edits: vec![sym.into()],
        modified_files: vec![path],
        lines_added: 2,
        lines_removed: 1,
        ..Default::default()
    }
}

fn claim_of(f: &Facts) -> Claim {
    Claim {
        intent: "test".into(),
        edits: f.edits.clone(),
        adds: f.adds.clone(),
        deletes: f.deletes.clone(),
        deleted_files: f.deleted_files.clone(),
        signature_changes: f.signature_changes.clone(),
        tests: f.tests.clone(),
        revert_of: None,
    }
}

fn denied_with(d: &Decision, prefix: &str) -> bool {
    d.outcome == Outcome::Deny && d.reasons.iter().any(|r| r.starts_with(prefix))
}

fn pass(check: CheckKind) -> Attestation {
    Attestation {
        check,
        result: CheckResult::Pass,
        subject_tree: gid('d'),
        details: [("sandbox".to_string(), "seatbelt".to_string())].into(),
        env: "env".into(),
        log: None,
        producer: "test".into(),
    }
}

#[test]
fn genesis_once_and_only_signed() {
    let mut h = H::new();
    let again = h.human(
        "ayse",
        Op::RepoInit {
            repo: REPO.into(),
            daemon_key: "00".into(),
            human: "ayse".into(),
            human_key: HumanKey {
                alg: "ed25519".into(),
                public: "00".into(),
            },
            policy: gid('a'),
            trunk: gid('b'),
        },
    );
    assert!(denied_with(&again, "already_initialized"));

    // Genesis without a valid signature is refused.
    let mut chain = Chain::new(KeyPair::generate());
    let op = Op::RepoInit {
        repo: REPO.into(),
        daemon_key: chain.public_key(),
        human: "ayse".into(),
        human_key: HumanKey {
            alg: "ed25519".into(),
            public: KeyPair::generate().public_hex(),
        },
        policy: gid('a'),
        trunk: gid('b'),
    };
    let entry = chain.prepare(
        Submission::new(
            Actor::Human {
                name: "ayse".into(),
            },
            op,
        ),
        T0,
        &h.policy,
    );
    assert!(denied_with(
        &entry.entry.decision,
        "missing_human_signature"
    ));
    chain.commit(&entry);
    assert!(
        chain.state.repo.is_empty(),
        "denied genesis changes nothing"
    );
    h.assert_replay();
}

#[test]
fn propose_needs_leases_and_matching_claim() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let sym = "src/billing.rs#Client.charge";
    h.wrote("s1", "src/billing.rs");

    let c = ChangeId::random();
    assert!(denied_with(
        &h.propose("s1", c, edit(sym)),
        "lease_missing:src/billing.rs#Client.charge"
    ));

    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());

    let mut lying = claim_of(&edit(sym));
    lying.edits = vec!["src/billing.rs#Client.refund".into()];
    assert!(denied_with(
        &h.propose_claim("s1", c, edit(sym), lying),
        "claim_mismatch:edits"
    ));

    let d = h.propose("s1", c, edit(sym));
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(h.chain.state.queue, vec![c]);
    assert_eq!(h.chain.state.changes[&c].provenance, Provenance::Clean);

    // The same change can not be proposed twice while in flight.
    assert!(denied_with(
        &h.propose("s1", c, edit(sym)),
        "change_in_flight"
    ));
    h.assert_replay();
}

#[test]
fn scope_paths_and_ops_are_enforced() {
    let mut h = H::new();
    h.start_observed("s1", &["src/billing/**"]);
    h.wrote("s1", "src/auth.rs");
    assert!(denied_with(
        &h.lease("s1", "l1", &[("src/auth.rs#login", LeaseKind::Edit)]),
        "scope_path:src/auth.rs"
    ));

    // Operations that no capability can grant are refused before anything else.
    let d = h.agent("s1", Op::PolicyUpdate { policy: gid('e') });
    assert!(denied_with(&d, "not_grantable:policy.update"));
    let d = h.agent(
        "s1",
        Op::Approve {
            target_seq: 1,
            note: String::new(),
        },
    );
    assert!(denied_with(&d, "not_grantable:approve"));
    h.assert_replay();
}

#[test]
fn leases_are_exclusive_all_or_nothing_and_expire() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    h.start_observed("s2", &["src/**"]);
    h.start_observed("s3", &["src/**"]);
    let f = "src/a.rs#Client.charge";
    let g = "src/a.rs#Client.refund";

    assert!(h.lease("s1", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let d = h.lease("s2", "l2", &[(g, LeaseKind::Edit), (f, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{f}:s1:")), "{d:?}");
    assert!(
        !h.chain.state.leases.contains_key("l2"),
        "nothing granted on conflict"
    );

    // Different functions in the same file and type: fine.
    assert!(h.lease("s2", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    // Adding members to the type does not conflict with editing members.
    assert!(
        h.lease("s3", "l3", &[("src/a.rs#Client", LeaseKind::Insert)])
            .is_allow()
    );
    // But editing the whole type conflicts with both members.
    assert!(denied_with(
        &h.lease("s3", "l4", &[("src/a.rs#Client", LeaseKind::Edit)]),
        "lease_held"
    ));

    h.now += 11 * MIN;
    assert!(
        h.lease("s3", "l4", &[("src/a.rs#Client", LeaseKind::Edit)])
            .is_allow(),
        "expired leases free up"
    );
    h.assert_replay();
}

#[test]
fn integration_moves_trunk_and_failures_leave_the_queue() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    h.wrote("s1", "src/a.rs");
    h.wrote("s1", "src/b.rs");
    assert!(
        h.lease(
            "s1",
            "l1",
            &[
                ("src/a.rs#f", LeaseKind::Edit),
                ("src/b.rs#g", LeaseKind::Edit)
            ]
        )
        .is_allow()
    );
    let c1 = ChangeId::random();
    let c2 = ChangeId::random();
    assert!(h.propose("s1", c1, edit("src/a.rs#f")).is_allow());
    assert!(h.propose("s1", c2, edit("src/b.rs#g")).is_allow());

    let trunk = h.chain.state.trunk.clone().unwrap();
    let not_head = h.daemon(
        Op::ChangeIntegrate {
            change: c2,
            trunk_before: trunk.clone(),
            merged: Some(gid('e')),
            conflicts: vec![],
        },
        vec![],
    );
    assert!(denied_with(&not_head, "not_queue_head"));

    let ok = h.daemon(
        Op::ChangeIntegrate {
            change: c1,
            trunk_before: trunk.clone(),
            merged: Some(gid('e')),
            conflicts: vec![],
        },
        vec![pass(CheckKind::Build), pass(CheckKind::Tests)],
    );
    assert!(ok.is_allow(), "{ok:?}");
    assert_eq!(h.chain.state.trunk, Some(gid('e')));
    assert_eq!(
        h.chain.state.changes[&c1].status,
        ChangeStatus::Integrated { commit: gid('e') }
    );

    let mut failing = pass(CheckKind::Tests);
    failing.result = CheckResult::Fail;
    let bad = h.daemon(
        Op::ChangeIntegrate {
            change: c2,
            trunk_before: gid('e'),
            merged: Some(gid('f')),
            conflicts: vec![],
        },
        vec![failing],
    );
    assert!(denied_with(&bad, "verification_failed:tests"));
    assert!(h.chain.state.queue.is_empty());
    assert!(matches!(
        h.chain.state.changes[&c2].status,
        ChangeStatus::Rejected { .. }
    ));
    assert_eq!(h.chain.state.trunk, Some(gid('e')), "trunk unchanged");
    h.assert_replay();
}

#[test]
fn tainted_sessions_need_review_and_never_touch_critical_paths() {
    let mut h = H::new();
    h.start_observed("s1", &["**"]);
    h.wrote("s1", "src/a.rs");
    h.wrote("s1", "Cargo.toml");
    assert!(
        h.lease(
            "s1",
            "l1",
            &[
                ("src/a.rs#f", LeaseKind::Edit),
                ("Cargo.toml#<file>", LeaseKind::Edit)
            ]
        )
        .is_allow()
    );
    let d = h.daemon(
        Op::Observe {
            session: "s1".into(),
            events: vec![Observation {
                phase: Phase::Post,
                kind: ObsKind::Fetch {
                    host: "evil.example".into(),
                },
                external: true,
            }],
        },
        vec![],
    );
    assert!(d.is_allow());
    assert!(h.chain.state.sessions["s1"].taint.is_some());

    let critical = ChangeId::random();
    assert!(denied_with(
        &h.propose("s1", critical, edit("Cargo.toml#<file>")),
        "tainted_critical_path"
    ));

    let c = ChangeId::random();
    let d = h.propose("s1", c, edit("src/a.rs#f"));
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(d.reasons.contains(&"tainted_session".to_string()));
    assert!(h.chain.state.queue.is_empty());
    let seq = match h.chain.state.changes[&c].status {
        ChangeStatus::Pending { seq } => seq,
        ref s => panic!("{s:?}"),
    };

    // An agent can not approve; a human can.
    let d = h.agent(
        "s1",
        Op::Approve {
            target_seq: seq,
            note: String::new(),
        },
    );
    assert!(denied_with(&d, "not_grantable:approve"));
    let d = h.human(
        "ayse",
        Op::Approve {
            target_seq: seq,
            note: "read it".into(),
        },
    );
    assert!(
        d.is_allow() && d.reasons.contains(&"released".to_string()),
        "{d:?}"
    );
    assert_eq!(h.chain.state.queue, vec![c]);
    assert_eq!(h.chain.state.changes[&c].provenance, Provenance::Reviewed);
    h.assert_replay();
}

#[test]
fn unobserved_sessions_are_treated_as_tainted() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    assert!(
        h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    let d = h.propose("s1", ChangeId::random(), edit("src/a.rs#f"));
    assert_eq!(d.outcome, Outcome::Escalate);
    assert!(d.reasons.contains(&"unobserved_session".to_string()));

    // Bind claims must match the checks: sudo without password means unobserved.
    let checks = BindChecks {
        harness: "claude-code".into(),
        harness_session: "x".into(),
        managed_hooks: true,
        locked_sandbox: true,
        sudo_without_password: true,
        config_digest: "c".into(),
        hook_binary_protected: true,
    };
    let d = h.daemon(
        Op::SessionBind {
            session: "s1".into(),
            checks,
            level: ObservationLevel::HooksSandbox,
        },
        vec![],
    );
    assert!(denied_with(&d, "bind_level_mismatch"));
    h.assert_replay();
}

#[test]
fn writes_nobody_observed_escalate() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    assert!(
        h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    let d = h.propose("s1", ChangeId::random(), edit("src/a.rs#f"));
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(d.reasons.contains(&"unobserved_write:src/a.rs".to_string()));
    h.assert_replay();
}

#[test]
fn attenuation_only_narrows_and_revocation_cascades() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let narrow = Scope {
        paths: vec!["src/billing/**".into()],
        symbols: None,
        ops: vec![OpKind::LeaseAcquire, OpKind::ChangePropose],
        max_files: Some(5),
        max_lines: None,
        scratch: vec![],
    };
    let attenuate = |child: &str, scope: Scope, exp: i64| Op::CapAttenuate {
        parent: "s1".into(),
        child: child.into(),
        agent: "sub".into(),
        scope,
        expires_ms: exp,
        leases: vec![],
    };
    let exp = h.now + 60 * MIN;
    let wide = Scope {
        paths: vec!["**".into()],
        ..narrow.clone()
    };
    assert!(denied_with(
        &h.agent("s1", attenuate("c1", wide, exp)),
        "scope_widening:path:**"
    ));
    let more_ops = Scope {
        ops: vec![OpKind::LeaseAcquire, OpKind::PolicyUpdate],
        ..narrow.clone()
    };
    assert!(denied_with(
        &h.agent("s1", attenuate("c1", more_ops, exp)),
        "scope_invalid:not_grantable"
    ));
    let longer = h.now + 500 * MIN;
    assert!(denied_with(
        &h.agent("s1", attenuate("c1", narrow.clone(), longer)),
        "session_ttl"
    ));
    assert!(h.agent("s1", attenuate("c1", narrow, exp)).is_allow());

    // The child works, then the parent's capability is revoked.
    h.wrote("c1", "src/billing/a.rs");
    assert!(
        h.lease("c1", "lc", &[("src/billing/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    let c = ChangeId::random();
    assert!(h.propose("c1", c, edit("src/billing/a.rs#f")).is_allow());
    assert!(
        h.human(
            "ayse",
            Op::CapRevoke {
                session: "s1".into(),
                reason: "done".into()
            }
        )
        .is_allow()
    );
    assert!(h.chain.state.sessions["c1"].ended.is_some());
    assert!(!h.chain.state.leases.contains_key("lc"));
    assert_eq!(h.chain.state.changes[&c].status, ChangeStatus::Withdrawn);
    assert!(h.chain.state.queue.is_empty());
    assert!(denied_with(
        &h.lease("c1", "lc2", &[("src/billing/a.rs#g", LeaseKind::Edit)]),
        "session_inactive"
    ));

    // Agents can only end their own subtree.
    h.start_observed("s2", &["src/**"]);
    h.start_observed("s3", &["src/**"]);
    assert!(denied_with(
        &h.agent(
            "s2",
            Op::CapRevoke {
                session: "s3".into(),
                reason: "x".into()
            }
        ),
        "not_own_session"
    ));
    h.assert_replay();
}

#[test]
fn humans_can_not_request_agent_and_daemon_operations() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let observe = Op::Observe {
        session: "s1".into(),
        events: vec![],
    };
    let d = h.human("ayse", observe);
    assert!(denied_with(&d, "not_a_human_op:observe"), "{d:?}");
    h.assert_replay();
}

#[test]
fn human_signatures_can_not_be_replayed_or_forged() {
    let mut h = H::new();
    let op = Op::Freeze { reason: "x".into() };
    let sig = h.sign("ayse", &op);
    let mut sub = Submission::new(
        Actor::Human {
            name: "ayse".into(),
        },
        op.clone(),
    );
    sub.human = Some(sig.clone());
    assert!(h.submit(sub.clone()).is_allow());
    // Freeze is still accepted while frozen, so the second attempt reaches
    // the nonce check.
    assert!(denied_with(&h.submit(sub), "nonce_reused"));
    // Same nonce again (after unfreezing) is still a replay.
    assert!(
        h.human("ayse", Op::Unfreeze { reason: "y".into() })
            .is_allow()
    );
    let mut replay = Submission::new(
        Actor::Human {
            name: "ayse".into(),
        },
        op.clone(),
    );
    replay.human = Some(sig.clone());
    assert!(denied_with(&h.submit(replay), "nonce_reused"));

    // A signature over a different operation does not verify.
    let mut forged = Submission::new(
        Actor::Human {
            name: "ayse".into(),
        },
        Op::Freeze {
            reason: "other".into(),
        },
    );
    forged.human = Some(HumanSignature {
        nonce: nonce(),
        ..sig.clone()
    });
    assert!(denied_with(&h.submit(forged), "bad_human_signature"));

    // Old signatures expire.
    h.now += 30 * MIN;
    let mut stale = Submission::new(
        Actor::Human {
            name: "ayse".into(),
        },
        op,
    );
    stale.human = Some(HumanSignature {
        nonce: nonce(),
        ..sig
    });
    assert!(denied_with(&h.submit(stale), "stale_human_signature"));
    h.assert_replay();
}

#[test]
fn frozen_repository_refuses_work() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    assert!(
        h.daemon(
            Op::Freeze {
                reason: "audit mismatch".into()
            },
            vec![]
        )
        .is_allow()
    );
    assert!(denied_with(
        &h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)]),
        "frozen:audit mismatch"
    ));
    assert!(denied_with(
        &h.human(
            "ayse",
            Op::SessionEnd {
                session: "s1".into(),
                reason: "x".into()
            }
        ),
        "frozen"
    ));
    assert!(
        h.human(
            "ayse",
            Op::Unfreeze {
                reason: "checked".into()
            }
        )
        .is_allow()
    );
    assert!(
        h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    h.assert_replay();
}

#[test]
fn policy_rules_deny_and_escalate_with_approval_counts() {
    let mut h = H::new();
    h.start_observed("s1", &["**"]);
    h.wrote("s1", "migrations/001.sql");
    h.wrote("s1", "auth/login.rs");
    assert!(
        h.lease(
            "s1",
            "l1",
            &[
                ("migrations/001.sql#<file>", LeaseKind::Rename),
                ("auth/login.rs#check", LeaseKind::Edit)
            ]
        )
        .is_allow()
    );
    let del = Facts {
        deleted_files: vec!["migrations/001.sql".into()],
        lines_removed: 3,
        ..Default::default()
    };
    assert!(denied_with(
        &h.propose("s1", ChangeId::random(), del),
        "policy:migrations-no-agent-delete"
    ));

    // One enrolled human: the two-human rule is capped to one approval.
    let d = h.propose("s1", ChangeId::random(), edit("auth/login.rs#check"));
    assert_eq!(d.outcome, Outcome::Escalate);
    assert!(d.reasons.contains(&"approvals_capped".to_string()));
    assert!(d.reasons.contains(&"approvals=1".to_string()));

    // With a second human enrolled, it needs both.
    let bora = KeyPair::generate();
    let enroll = Op::HumanEnroll {
        human: "bora".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: bora.public_hex(),
        },
    };
    assert!(h.human("ayse", enroll).is_allow());
    h.humans.push(("bora".into(), bora));
    let c = ChangeId::random();
    let d = h.propose("s1", c, edit("auth/login.rs#check"));
    assert!(d.reasons.contains(&"approvals=2".to_string()), "{d:?}");
    let ChangeStatus::Pending { seq } = h.chain.state.changes[&c].status else {
        panic!()
    };
    let first = h.human(
        "ayse",
        Op::Approve {
            target_seq: seq,
            note: String::new(),
        },
    );
    assert!(first.is_allow() && !first.reasons.contains(&"released".to_string()));
    assert!(denied_with(
        &h.human(
            "ayse",
            Op::Approve {
                target_seq: seq,
                note: String::new()
            }
        ),
        "already_approved"
    ));
    let second = h.human(
        "bora",
        Op::Approve {
            target_seq: seq,
            note: String::new(),
        },
    );
    assert!(second.reasons.contains(&"released".to_string()));
    assert_eq!(h.chain.state.changes[&c].status, ChangeStatus::Queued);
    h.assert_replay();
}

#[test]
fn negotiation_yields_leases_spreads_taint_and_is_bounded() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    h.start_observed("s2", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("s1", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(denied_with(
        &h.lease("s2", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));

    let msg = |to: &str, m: NegotiationMsg| Op::Negotiate {
        thread: "t1".into(),
        to_session: to.into(),
        message: m,
    };
    assert!(
        h.agent(
            "s2",
            msg(
                "s1",
                NegotiationMsg::Claim {
                    symbols: vec![f.into()],
                    reason: "bug fix".into()
                }
            )
        )
        .is_allow()
    );
    // s1 can only yield its own lease.
    assert!(denied_with(
        &h.agent(
            "s2",
            msg(
                "s1",
                NegotiationMsg::Yield {
                    set: "l1".into(),
                    to: None,
                }
            )
        ),
        "not_own_lease"
    ));
    assert!(
        h.agent(
            "s1",
            msg(
                "s2",
                NegotiationMsg::Yield {
                    set: "l1".into(),
                    to: None,
                }
            )
        )
        .is_allow()
    );
    assert!(h.lease("s2", "l2", &[(f, LeaseKind::Edit)]).is_allow());

    // A tainted sender taints the receiver.
    h.start_observed("s3", &["src/**"]);
    assert!(
        h.daemon(
            Op::Taint {
                session: "s3".into(),
                reason: "read external issue".into()
            },
            vec![]
        )
        .is_allow()
    );
    let note = |n: &str| NegotiationMsg::Counter { note: n.into() };
    let op = Op::Negotiate {
        thread: "t2".into(),
        to_session: "s1".into(),
        message: note("hi"),
    };
    assert!(h.agent("s3", op).is_allow());
    assert!(
        h.chain.state.sessions["s1"]
            .taint
            .as_deref()
            .unwrap()
            .contains("negotiation from tainted session s3")
    );

    // Threads are bounded.
    for i in 1..4 {
        let (from, to) = if i % 2 == 1 {
            ("s1", "s3")
        } else {
            ("s3", "s1")
        };
        let op = Op::Negotiate {
            thread: "t2".into(),
            to_session: to.into(),
            message: note("again"),
        };
        assert!(h.agent(from, op).is_allow(), "round {i}");
    }
    let op = Op::Negotiate {
        thread: "t2".into(),
        to_session: "s1".into(),
        message: note("more"),
    };
    assert!(denied_with(&h.agent("s3", op), "negotiation_exhausted"));
    h.assert_replay();
}

#[test]
fn weakened_tests_and_critical_paths_need_a_human() {
    let mut h = H::new();
    h.start_observed("s1", &["**"]);
    h.wrote("s1", "src/a.rs");
    h.wrote("s1", "Cargo.toml");
    assert!(
        h.lease(
            "s1",
            "l1",
            &[
                ("src/a.rs#tests", LeaseKind::Edit),
                ("Cargo.toml#<file>", LeaseKind::Edit)
            ]
        )
        .is_allow()
    );
    let mut f = edit("src/a.rs#tests");
    f.tests.skipped = 1;
    let d = h.propose("s1", ChangeId::random(), f);
    assert!(
        d.outcome == Outcome::Escalate && d.reasons.contains(&"tests_weakened".to_string()),
        "{d:?}"
    );
    let d = h.propose("s1", ChangeId::random(), edit("Cargo.toml#<file>"));
    assert!(
        d.reasons.contains(&"critical_path:Cargo.toml".to_string()),
        "{d:?}"
    );
    h.assert_replay();
}

#[test]
fn humans_propose_without_leases_but_claims_still_must_match() {
    let mut h = H::new();
    let f = edit("src/a.rs#f");
    let base = h.chain.state.trunk.clone().unwrap();
    let c = ChangeId::random();
    let op = Op::ChangePropose {
        change: c,
        commit: gid('c'),
        base: base.clone(),
        claim: claim_of(&f),
    };
    assert!(h.human_change("ayse", op, f.clone()).is_allow());
    let mut wrong = claim_of(&f);
    wrong.edits.clear();
    let op = Op::ChangePropose {
        change: ChangeId::random(),
        commit: gid('c'),
        base,
        claim: wrong,
    };
    assert!(denied_with(
        &h.human_change("ayse", op, f),
        "claim_mismatch:edits"
    ));
    h.assert_replay();
}

#[test]
fn policy_without_permit_denies_everything_for_agents() {
    let strict = PolicyBundle::parse(
        DEFAULT_CONFIG,
        "forbid(principal, action, resource) when { false };",
    )
    .unwrap();
    let mut h = H::with_policy(PolicyBundle::default_bundle());
    h.start_observed("s1", &["src/**"]);
    h.policy = Arc::new(strict);
    assert!(denied_with(
        &h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)]),
        "policy_default_deny"
    ));
    assert!(PolicyBundle::parse(DEFAULT_CONFIG, DEFAULT_POLICY).is_ok());
}

#[test]
fn presence_can_be_required_for_human_signatures() {
    let strict = PolicyBundle::parse(
        &DEFAULT_CONFIG.replace("require_presence = false", "require_presence = true"),
        DEFAULT_POLICY,
    )
    .unwrap();
    let mut h = H::new();
    h.policy = Arc::new(strict);
    let d = h.human("ayse", Op::Freeze { reason: "x".into() });
    assert!(denied_with(&d, "presence_required"), "{d:?}");

    // A Secure Enclave (P-256) key satisfies it.
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let public = hex::encode(sk.verifying_key().to_sec1_point(false).as_bytes());
    h.policy = Arc::new(PolicyBundle::default_bundle());
    let enroll = Op::HumanEnroll {
        human: "cem".into(),
        key: HumanKey {
            alg: "p256-se".into(),
            public,
        },
    };
    assert!(h.human("ayse", enroll).is_allow());
    h.policy = Arc::new(
        PolicyBundle::parse(
            &DEFAULT_CONFIG.replace("require_presence = false", "require_presence = true"),
            DEFAULT_POLICY,
        )
        .unwrap(),
    );
    let op = Op::Freeze { reason: "y".into() };
    let nonce = nonce();
    let issued = h.now + 1;
    let sig: p256::ecdsa::Signature = sk.sign(&intent_bytes(REPO, &op, &nonce, issued));
    let mut sub = Submission::new(Actor::Human { name: "cem".into() }, op);
    sub.human = Some(HumanSignature {
        human: "cem".into(),
        nonce,
        issued_ms: issued,
        sig: hex::encode(sig.to_der().as_bytes()),
    });
    let d = h.submit(sub);
    assert!(d.is_allow(), "{d:?}");
}

fn rotate(name: &str, key: &KeyPair) -> Op {
    Op::HumanRotate {
        human: name.into(),
        key: file_key(key),
    }
}

fn revoke(name: &str, reason: &str) -> Op {
    Op::HumanRevoke {
        human: name.into(),
        reason: reason.into(),
    }
}

fn approve(seq: u64) -> Op {
    Op::Approve {
        target_seq: seq,
        note: String::new(),
    }
}

fn pending_seq(h: &H, c: ChangeId) -> u64 {
    let ChangeStatus::Pending { seq } = h.chain.state.changes[&c].status else {
        panic!("{:?}", h.chain.state.changes[&c].status)
    };
    seq
}

#[test]
fn rotation_replaces_the_key_and_ends_what_the_human_set_in_motion() {
    let mut h = H::new();
    h.enroll("bora");
    let old = h.humans[0].1.clone();

    // ayse's session with a lease and a queued change, a change of her own,
    // and an approval she gave to bora's session.
    h.start_observed("s1", &["src/**"]);
    h.wrote("s1", "src/a.rs");
    assert!(
        h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    let c1 = ChangeId::random();
    assert!(h.propose("s1", c1, edit("src/a.rs#f")).is_allow());
    let c2 = ChangeId::random();
    let f2 = edit("docs/x.md#<file>");
    let own = Op::ChangePropose {
        change: c2,
        commit: gid('c'),
        base: h.chain.state.trunk.clone().unwrap(),
        claim: claim_of(&f2),
    };
    assert!(h.human_change("ayse", own, f2).is_allow());
    h.start_observed_as("bora", "s2", &["**"]);
    h.wrote("s2", "auth/login.rs");
    assert!(
        h.lease("s2", "l2", &[("auth/login.rs#check", LeaseKind::Edit)])
            .is_allow()
    );
    let c3 = ChangeId::random();
    let d = h.propose("s2", c3, edit("auth/login.rs#check"));
    assert!(d.reasons.contains(&"approvals=2".to_string()), "{d:?}");
    let seq = pending_seq(&h, c3);
    assert!(h.human("ayse", approve(seq)).is_allow());

    // Only the human may rotate their own key, and only to a fresh, valid one.
    let new = KeyPair::generate();
    assert!(denied_with(
        &h.human("bora", rotate("ayse", &new)),
        "not_own_key"
    ));
    assert!(denied_with(
        &h.human("ayse", rotate("ayse", &old)),
        "key_reused"
    ));
    let bora_key = h.humans[1].1.clone();
    assert!(denied_with(
        &h.human("ayse", rotate("ayse", &bora_key)),
        "key_reused"
    ));
    for public in [
        new.public_hex().to_uppercase(),
        new.public_hex()[2..].to_string(),
        "zz".repeat(32),
    ] {
        let bad = Op::HumanRotate {
            human: "ayse".into(),
            key: HumanKey {
                alg: "ed25519".into(),
                public,
            },
        };
        assert!(denied_with(&h.human("ayse", bad), "invalid_key"));
    }
    let unknown_alg = Op::HumanRotate {
        human: "ayse".into(),
        key: HumanKey {
            alg: "rsa".into(),
            public: new.public_hex(),
        },
    };
    assert!(denied_with(&h.human("ayse", unknown_alg), "invalid_key"));
    // Agents and the daemon can not touch keys.
    assert!(denied_with(
        &h.agent("s1", rotate("ayse", &new)),
        "not_grantable:human.rotate"
    ));
    assert!(denied_with(
        &h.daemon(rotate("ayse", &new), vec![]),
        "not_a_daemon_op"
    ));

    assert!(h.human("ayse", rotate("ayse", &new)).is_allow());
    let st = &h.chain.state;
    assert_eq!(st.humans["ayse"], file_key(&new));
    assert!(st.retired_keys.contains(&old.public_hex()));
    assert!(
        st.sessions["s1"]
            .ended
            .as_deref()
            .unwrap()
            .contains("rotated")
    );
    assert!(!st.leases.contains_key("l1"));
    assert_eq!(st.changes[&c1].status, ChangeStatus::Withdrawn);
    assert_eq!(st.changes[&c2].status, ChangeStatus::Withdrawn);
    assert!(st.queue.is_empty());
    // bora's work goes on, without ayse's approval.
    assert!(st.sessions["s2"].ended.is_none());
    assert!(st.leases.contains_key("l2"));
    assert!(st.pending[&seq].approvals.is_empty());

    // The old key no longer signs; the new one does, and the old key can
    // never come back.
    assert!(denied_with(
        &h.human_with(&old, "ayse", Op::Freeze { reason: "x".into() }),
        "bad_human_signature"
    ));
    h.use_key("ayse", new.clone());
    assert!(h.human("ayse", approve(seq)).is_allow());
    let released = h.human("bora", approve(seq));
    assert!(released.reasons.contains(&"released".to_string()));
    assert!(denied_with(
        &h.human("ayse", rotate("ayse", &old)),
        "key_reused"
    ));
    let enroll_old = Op::HumanEnroll {
        human: "cem".into(),
        key: file_key(&old),
    };
    assert!(denied_with(&h.human("ayse", enroll_old), "key_reused"));
    // Signatures made with the old key stay valid history.
    h.assert_replay();
}

#[test]
fn revocation_by_another_human_cascades_and_is_final() {
    let mut h = H::new();
    h.enroll("bora");
    let bora = h.humans[1].1.clone();
    let rec = KeyPair::generate();
    let set_rec = Op::HumanRecoveryKey {
        human: "bora".into(),
        key: file_key(&rec),
    };
    assert!(h.human("bora", set_rec).is_allow());

    h.start_observed("s1", &["src/**"]);
    h.start_observed_as("bora", "s2", &["src/**"]);
    let narrow = Scope {
        paths: vec!["src/b/**".into()],
        symbols: None,
        ops: vec![OpKind::LeaseAcquire],
        max_files: None,
        max_lines: None,
        scratch: vec![],
    };
    let child = Op::CapAttenuate {
        parent: "s2".into(),
        child: "s2c".into(),
        agent: "sub".into(),
        scope: narrow,
        expires_ms: h.now + 60 * MIN,
        leases: vec![],
    };
    assert!(h.agent("s2", child).is_allow());
    assert!(
        h.lease("s2c", "l2", &[("src/b/x.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    let talk = |to: &str| Op::Negotiate {
        thread: "t1".into(),
        to_session: to.into(),
        message: NegotiationMsg::Counter { note: "hi".into() },
    };
    assert!(h.agent("s1", talk("s2")).is_allow());

    assert!(denied_with(
        &h.human("ayse", revoke("cem", "x")),
        "not_enrolled"
    ));
    assert!(denied_with(
        &h.human("ayse", revoke("bora", "  ")),
        "reason_required"
    ));
    assert!(denied_with(
        &h.human("ayse", revoke("bora", &"x".repeat(501))),
        "reason_too_long"
    ));
    // 500 bytes is still a valid reason.
    let at_limit = h.human("ayse", revoke("cem", &"x".repeat(500)));
    assert!(denied_with(&at_limit, "not_enrolled"), "{at_limit:?}");
    assert!(!denied_with(&at_limit, "reason_too_long"), "{at_limit:?}");
    assert!(denied_with(
        &h.agent("s1", revoke("bora", "x")),
        "not_grantable:human.revoke"
    ));

    assert!(h.human("ayse", revoke("bora", "laptop stolen")).is_allow());
    let st = &h.chain.state;
    assert!(!st.humans.contains_key("bora"));
    assert!(!st.recovery.contains_key("bora"));
    assert!(st.retired_keys.contains(&bora.public_hex()));
    assert!(st.retired_keys.contains(&rec.public_hex()));
    for s in ["s2", "s2c"] {
        assert!(
            st.sessions[s]
                .ended
                .as_deref()
                .unwrap()
                .contains("human:bora revoked: laptop stolen"),
            "{s}"
        );
    }
    assert!(st.sessions["s1"].ended.is_none());
    assert!(st.leases.is_empty());

    // Nothing of bora's works any more.
    assert!(denied_with(
        &h.human("bora", Op::Freeze { reason: "x".into() }),
        "unknown_human"
    ));
    let recover = Op::HumanRecover {
        human: "bora".into(),
        key: file_key(&KeyPair::generate()),
    };
    assert!(denied_with(
        &h.human_with(&rec, "bora", recover),
        "unknown_human"
    ));
    assert!(denied_with(
        &h.agent("s1", talk("s2")),
        "invalid_counterparty"
    ));
    assert!(denied_with(
        &h.lease("s2c", "l3", &[("src/b/y.rs#f", LeaseKind::Edit)]),
        "session_inactive"
    ));

    // Re-enrolment needs a new key.
    let again = |k: &KeyPair| Op::HumanEnroll {
        human: "bora".into(),
        key: file_key(k),
    };
    assert!(denied_with(&h.human("ayse", again(&bora)), "key_reused"));
    let fresh = KeyPair::generate();
    assert!(h.human("ayse", again(&fresh)).is_allow());

    // The last human can not be revoked, not even by themself.
    h.use_key("bora", fresh);
    assert!(h.human("bora", revoke("ayse", "left the team")).is_allow());
    assert!(denied_with(
        &h.human("bora", revoke("bora", "x")),
        "last_human"
    ));
    h.assert_replay();
}

#[test]
fn a_lost_key_is_recovered_once_with_the_recovery_key() {
    let mut h = H::new();
    h.enroll("bora");
    let old = h.humans[0].1.clone();
    let rec = KeyPair::generate();
    let new = KeyPair::generate();
    let recover = |k: &KeyPair| Op::HumanRecover {
        human: "ayse".into(),
        key: file_key(k),
    };
    let set_rec = |k: &KeyPair| Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: file_key(k),
    };
    assert!(denied_with(
        &h.human_with(&rec, "ayse", recover(&new)),
        "no_recovery_key"
    ));
    assert!(denied_with(&h.human("bora", set_rec(&rec)), "not_own_key"));
    assert!(denied_with(&h.human("ayse", set_rec(&old)), "key_reused"));
    assert!(h.human("ayse", set_rec(&rec)).is_allow());
    assert_eq!(h.chain.state.recovery["ayse"], file_key(&rec));
    // Replacing the recovery key retires the old one.
    let rec2 = KeyPair::generate();
    assert!(h.human("ayse", set_rec(&rec2)).is_allow());
    assert!(h.chain.state.retired_keys.contains(&rec.public_hex()));
    assert!(denied_with(
        &h.human_with(&rec, "ayse", recover(&new)),
        "bad_human_signature"
    ));
    let rec = rec2;

    h.start_observed("s1", &["src/**"]);
    assert!(
        h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    // The recovery key signs only recoveries, and not for someone else.
    assert!(denied_with(
        &h.human_with(&rec, "ayse", Op::Freeze { reason: "x".into() }),
        "bad_human_signature"
    ));
    let for_bora = Op::HumanRecover {
        human: "bora".into(),
        key: file_key(&new),
    };
    assert!(denied_with(
        &h.human_with(&rec, "ayse", for_bora),
        "not_own_key"
    ));
    assert!(denied_with(
        &h.human_with(&rec, "ayse", recover(&rec)),
        "key_reused"
    ));
    // The current key can not stand in for the recovery key.
    assert!(denied_with(
        &h.human_with(&old, "ayse", recover(&new)),
        "bad_human_signature"
    ));

    assert!(h.human_with(&rec, "ayse", recover(&new)).is_allow());
    let st = &h.chain.state;
    assert_eq!(st.humans["ayse"], file_key(&new));
    assert!(!st.recovery.contains_key("ayse"));
    assert!(st.retired_keys.contains(&old.public_hex()));
    assert!(st.retired_keys.contains(&rec.public_hex()));
    assert!(
        st.sessions["s1"]
            .ended
            .as_deref()
            .unwrap()
            .contains("recovered")
    );
    assert!(st.leases.is_empty());

    // Used up: a second recovery with the same key fails.
    let newer = KeyPair::generate();
    assert!(denied_with(
        &h.human_with(&rec, "ayse", recover(&newer)),
        "no_recovery_key"
    ));
    assert!(denied_with(
        &h.human_with(&old, "ayse", Op::Freeze { reason: "x".into() }),
        "bad_human_signature"
    ));
    h.use_key("ayse", new);
    assert!(
        h.human("ayse", Op::Freeze { reason: "x".into() })
            .is_allow()
    );
    h.assert_replay();
}

#[test]
fn key_operations_work_in_a_frozen_repository() {
    let mut h = H::new();
    h.enroll("bora");
    assert!(
        h.daemon(
            Op::Freeze {
                reason: "incident".into()
            },
            vec![]
        )
        .is_allow()
    );
    let rec = KeyPair::generate();
    let set_rec = Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: file_key(&rec),
    };
    assert!(h.human("ayse", set_rec).is_allow());
    assert!(h.human("ayse", revoke("bora", "incident")).is_allow());
    let new = KeyPair::generate();
    assert!(h.human("ayse", rotate("ayse", &new)).is_allow());
    h.use_key("ayse", new);
    // The key that would unfreeze is lost: recover, then unfreeze.
    let newer = KeyPair::generate();
    let recover = Op::HumanRecover {
        human: "ayse".into(),
        key: file_key(&newer),
    };
    assert!(h.human_with(&rec, "ayse", recover).is_allow());
    h.use_key("ayse", newer);
    let start = Op::SessionStart {
        session: "s1".into(),
        agent: "bot".into(),
        model: None,
        task: "T".into(),
        scope: Scope {
            paths: vec!["**".into()],
            symbols: None,
            ops: vec![OpKind::LeaseAcquire],
            max_files: None,
            max_lines: None,
            scratch: vec![],
        },
        expires_ms: h.now + 60 * MIN,
        continues: None,
    };
    assert!(denied_with(&h.human("ayse", start), "frozen:incident"));
    assert!(
        h.human(
            "ayse",
            Op::Unfreeze {
                reason: "ok".into()
            }
        )
        .is_allow()
    );
    h.assert_replay();
}

#[test]
fn revocation_can_need_approval_and_applies_when_released() {
    let policy = PolicyBundle::parse(
        DEFAULT_CONFIG,
        &format!(
            "{DEFAULT_POLICY}\n@id(\"revoke-needs-two\")\n@escalate(\"revoke\")\n@approvals(\"2\")\n\
             forbid(principal, action == Lonca::Action::\"human.revoke\", resource);\n"
        ),
    )
    .unwrap();
    let mut h = H::with_policy(policy);
    h.enroll("bora");
    h.enroll("cem");
    h.start_observed_as("bora", "s2", &["src/**"]);
    let d = h.human("ayse", revoke("bora", "left"));
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(h.chain.state.humans.contains_key("bora"));
    let seq = h.chain.state.next_seq - 1;
    assert!(h.human("ayse", approve(seq)).is_allow());
    let released = h.human("cem", approve(seq));
    assert!(released.reasons.contains(&"released".to_string()));
    assert!(!h.chain.state.humans.contains_key("bora"));
    assert!(h.chain.state.sessions["s2"].ended.is_some());
    h.assert_replay();
}

#[test]
fn presence_does_not_block_recovery() {
    let mut h = H::new();
    let rec = KeyPair::generate();
    let set_rec = Op::HumanRecoveryKey {
        human: "ayse".into(),
        key: file_key(&rec),
    };
    assert!(h.human("ayse", set_rec).is_allow());
    h.policy = Arc::new(
        PolicyBundle::parse(
            &DEFAULT_CONFIG.replace("require_presence = false", "require_presence = true"),
            DEFAULT_POLICY,
        )
        .unwrap(),
    );
    let new = KeyPair::generate();
    assert!(denied_with(
        &h.human("ayse", rotate("ayse", &new)),
        "presence_required"
    ));

    // Recover onto a Secure Enclave (P-256) key; a malformed one is refused.
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::from_slice(&[11u8; 32]).unwrap();
    let public = hex::encode(sk.verifying_key().to_sec1_point(false).as_bytes());
    let se = |public: String| Op::HumanRecover {
        human: "ayse".into(),
        key: HumanKey {
            alg: "p256-se".into(),
            public,
        },
    };
    let mut broken = public.clone();
    broken.replace_range(2..4, if &public[2..4] == "00" { "01" } else { "00" });
    assert!(denied_with(
        &h.human_with(&rec, "ayse", se(format!("05{}", &public[2..]))),
        "invalid_key"
    ));
    assert!(denied_with(
        &h.human_with(&rec, "ayse", se(broken)),
        "invalid_key"
    ));
    let d = h.human_with(&rec, "ayse", se(public));
    assert!(d.is_allow(), "{d:?}");

    let op = Op::Freeze { reason: "y".into() };
    let nonce = nonce();
    let issued = h.now + 1;
    let sig: p256::ecdsa::Signature = sk.sign(&intent_bytes(REPO, &op, &nonce, issued));
    let mut sub = Submission::new(
        Actor::Human {
            name: "ayse".into(),
        },
        op,
    );
    sub.human = Some(HumanSignature {
        human: "ayse".into(),
        nonce,
        issued_ms: issued,
        sig: hex::encode(sig.to_der().as_bytes()),
    });
    let d = h.submit(sub);
    assert!(d.is_allow(), "{d:?}");
    // The policy changed mid-test, so the log is not replayed here (as in
    // `presence_can_be_required_for_human_signatures`).
}

#[test]
fn a_released_key_operation_is_checked_again() {
    let policy = PolicyBundle::parse(
        DEFAULT_CONFIG,
        &format!(
            "{DEFAULT_POLICY}\n@id(\"keys-reviewed\")\n@escalate(\"keys\")\n\
             forbid(principal, action in [Lonca::Action::\"human.revoke\", Lonca::Action::\"human.rotate\"], resource);\n"
        ),
    )
    .unwrap();
    let mut h = H::with_policy(policy);
    h.enroll("bora");
    h.enroll("cem");
    // ayse asks to revoke herself; meanwhile bora and cem are revoked.
    assert_eq!(
        h.human("ayse", revoke("ayse", "leaving")).outcome,
        Outcome::Escalate
    );
    let own = h.chain.state.next_seq - 1;
    for who in ["bora", "cem"] {
        assert_eq!(
            h.human("ayse", revoke(who, "left")).outcome,
            Outcome::Escalate
        );
        let seq = h.chain.state.next_seq - 1;
        assert!(h.human("ayse", approve(seq)).is_allow());
    }
    assert_eq!(h.chain.state.humans.len(), 1);
    assert!(denied_with(&h.human("ayse", approve(own)), "last_human"));
    assert!(h.chain.state.humans.contains_key("ayse"));

    // A rotation whose key was taken while it waited is refused on release.
    h.enroll("bora");
    let new = KeyPair::generate();
    assert_eq!(
        h.human("bora", rotate("bora", &new)).outcome,
        Outcome::Escalate
    );
    let seq = h.chain.state.next_seq - 1;
    let enroll = Op::HumanEnroll {
        human: "cem".into(),
        key: file_key(&new),
    };
    assert!(h.human("ayse", enroll).is_allow());
    assert!(denied_with(&h.human("ayse", approve(seq)), "key_reused"));
    let new2 = KeyPair::generate();
    assert_eq!(
        h.human("bora", rotate("bora", &new2)).outcome,
        Outcome::Escalate
    );
    let seq = h.chain.state.next_seq - 1;
    assert!(h.human("ayse", approve(seq)).is_allow());
    assert_eq!(h.chain.state.humans["bora"], file_key(&new2));
    h.assert_replay();
}

fn daemon_rotate(key: &KeyPair) -> Op {
    Op::DaemonRotate {
        key: key.public_hex(),
    }
}

fn daemon_recover(key: &KeyPair) -> Op {
    Op::DaemonRecover {
        key: key.public_hex(),
    }
}

#[test]
fn a_human_rotates_the_daemon_key_and_the_new_key_signs_on() {
    let mut h = H::new();
    h.enroll("bora");
    h.start_observed("s1", &["src/**"]);
    let old = h.chain.state.daemon_key.clone();
    let new = KeyPair::generate();

    assert!(denied_with(
        &h.agent("s1", daemon_rotate(&new)),
        "not_grantable:daemon.rotate"
    ));
    assert!(denied_with(
        &h.daemon(daemon_rotate(&new), vec![]),
        "not_a_daemon_op:daemon.rotate"
    ));
    // A valid Ed25519 point in lowercase hex, and never a key in use or
    // used before.
    let public = new.public_hex();
    assert_ne!(public, public.to_uppercase());
    for (key, why) in [
        ("zz".repeat(32), "invalid_key"),
        (public.to_uppercase(), "invalid_key"),
        (public[2..].to_string(), "invalid_key"),
        (old.clone(), "key_reused"),
        (h.key_of("bora").public_hex(), "key_reused"),
    ] {
        let d = h.human("ayse", Op::DaemonRotate { key: key.clone() });
        assert!(denied_with(&d, why), "{key}: {d:?}");
        assert_eq!(h.chain.state.daemon_key, old);
    }

    // Any enrolled human may rotate it.
    let d = h.rotate_daemon("bora", &new);
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(h.chain.state.daemon_key, public);
    assert!(h.chain.state.retired_daemon_keys.contains(&old));
    // The daemon keeps its tokens, so sessions go on.
    assert!(h.chain.state.session_active("s1", h.now));
    assert!(
        h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    // A retired key never comes back.
    assert!(denied_with(
        &h.human("ayse", Op::DaemonRotate { key: old }),
        "key_reused"
    ));
    let newer = KeyPair::generate();
    assert!(h.rotate_daemon("ayse", &newer).is_allow());
    assert!(denied_with(
        &h.human("ayse", daemon_rotate(&new)),
        "key_reused"
    ));
    h.assert_replay();
}

#[test]
fn a_lost_daemon_key_is_recovered_with_a_human_signature() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let sym = "src/billing.rs#Client.charge";
    h.wrote("s1", "src/billing.rs");
    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert!(h.propose("s1", c, edit(sym)).is_allow());
    let old = h.chain.state.daemon_key.clone();
    let new = KeyPair::generate();
    let ayse = h.key_of("ayse");

    // Refusals are not logged: a forged signature, an unknown human, the
    // key in force, and agents.
    let seq = h.chain.state.next_seq;
    let stranger = KeyPair::generate();
    let tries = [
        (
            &stranger,
            "ayse",
            daemon_recover(&new),
            "bad_human_signature",
        ),
        (&stranger, "mallory", daemon_recover(&new), "unknown_human"),
        (
            &ayse,
            "ayse",
            Op::DaemonRecover { key: old.clone() },
            "key_reused",
        ),
    ];
    for (signer, name, op, why) in tries {
        let d = h.recover_daemon_with(signer, name, op, &new);
        assert!(denied_with(&d, why), "{why}: {d:?}");
    }
    assert!(denied_with(
        &h.agent("s1", daemon_recover(&new)),
        "not_grantable:daemon.recover"
    ));
    assert_eq!(h.chain.state.next_seq, seq + 1, "only the agent's try");

    let d = h.recover_daemon_with(&ayse, "ayse", daemon_recover(&new), &new);
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(h.chain.state.daemon_key, new.public_hex());
    assert!(h.chain.state.retired_daemon_keys.contains(&old));
    // The daemon that held the tokens is gone: every session ends, and
    // what they proposed keeps its place in the queue.
    assert_eq!(
        h.chain.state.sessions["s1"].ended.as_deref(),
        Some("revoked: daemon key recovered")
    );
    // Its lease is pinned to the queued change, nothing else is left.
    assert_eq!(h.chain.state.leases.len(), 1);
    assert!(
        h.chain
            .state
            .leases
            .values()
            .all(|l| l.pins.contains_key(&c))
    );
    assert_eq!(h.chain.state.queue, vec![c]);
    let trunk = h.chain.state.trunk.clone().unwrap();
    let d = h.daemon(
        Op::ChangeIntegrate {
            change: c,
            trunk_before: trunk,
            merged: Some(gid('e')),
            conflicts: vec![],
        },
        vec![pass(CheckKind::Build), pass(CheckKind::Tests)],
    );
    assert!(d.is_allow(), "{d:?}");
    // Recovery onto a key used before is refused like a rotation.
    let d = h.recover_daemon_with(&ayse, "ayse", Op::DaemonRecover { key: old }, &new);
    assert!(denied_with(&d, "key_reused"), "{d:?}");
    h.assert_replay();
}

#[test]
fn a_forged_daemon_key_switch_is_caught_by_the_replay() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let daemon = h.chain.state.daemon_key.clone();
    let attacker = KeyPair::generate();
    // Someone who can write the store but holds no human key: a recovery
    // onto their own key with a forged signature and a recorded allow,
    // entries of their own, then a "rotation" back to the daemon's key.
    let forge = |h: &H, op: Op, at: i64, prev: &SignedOp| {
        let sig = h.sign_with(&attacker, "ayse", &op);
        let mut sub = Submission::new(
            Actor::Human {
                name: "ayse".into(),
            },
            op,
        );
        sub.human = Some(sig);
        let mut state = State::replay(&h.log);
        if prev.entry.seq + 1 != state.next_seq {
            state.apply(prev);
        }
        let mut e = Chain::from_state(attacker.clone(), state)
            .prepare(sub, at, &h.policy)
            .entry;
        assert!(!e.decision.is_allow());
        e.decision = Decision::allow();
        SignedOp::sign(e, &attacker)
    };
    let last = h.log.last().unwrap().clone();
    let recover = forge(&h, daemon_recover(&attacker), h.now + 1, &last);
    let back = forge(
        &h,
        Op::DaemonRotate {
            key: daemon.clone(),
        },
        h.now + 2,
        &recover,
    );
    let mut log = h.log.clone();
    log.extend([recover.clone(), back]);
    // The chain alone accepts it, and ends on the daemon's key.
    assert!(verify_chain(&log).is_ok());
    assert_eq!(State::replay(&log).daemon_key, daemon);
    let err = replay_checked(&log, |_| Ok(h.policy.clone())).unwrap_err();
    assert!(
        err.to_string().contains(&format!(
            "op {}: daemon.recover is not authorised",
            recover.entry.seq
        )),
        "{err}"
    );
    h.assert_replay();
}

#[test]
fn daemon_key_switches_can_not_wait_for_approval() {
    let policy = PolicyBundle::parse(
        DEFAULT_CONFIG,
        &format!(
            "{DEFAULT_POLICY}\n@id(\"daemon-keys-need-two\")\n@escalate(\"daemon-keys\")\n@approvals(\"2\")\n\
             forbid(principal, action in [Lonca::Action::\"daemon.rotate\", Lonca::Action::\"daemon.recover\"], resource);\n"
        ),
    )
    .unwrap();
    let mut h = H::with_policy(policy);
    let old = h.chain.state.daemon_key.clone();
    let new = KeyPair::generate();
    let d = h.rotate_daemon("ayse", &new);
    assert_eq!(d.outcome, Outcome::Deny, "{d:?}");
    assert!(
        d.reasons.iter().any(|r| r.starts_with("not_escalatable:")),
        "{d:?}"
    );
    let ayse = h.key_of("ayse");
    let d = h.recover_daemon_with(&ayse, "ayse", daemon_recover(&new), &new);
    assert!(denied_with(&d, "not_escalatable:"), "{d:?}");
    assert_eq!(h.chain.state.daemon_key, old);
    assert!(h.chain.state.pending.is_empty());
    h.assert_replay();
}

#[test]
fn daemon_keys_change_in_a_frozen_repository_and_need_presence_when_required() {
    let mut h = H::new();
    assert!(
        h.daemon(
            Op::Freeze {
                reason: "incident".into()
            },
            vec![]
        )
        .is_allow()
    );
    let new = KeyPair::generate();
    assert!(h.rotate_daemon("ayse", &new).is_allow());
    let newer = KeyPair::generate();
    let ayse = h.key_of("ayse");
    assert!(
        h.recover_daemon_with(&ayse, "ayse", daemon_recover(&newer), &newer)
            .is_allow()
    );
    assert!(h.chain.state.frozen.is_some());
    h.assert_replay();

    // Unlike `human.recover`, a daemon recovery has no exemption from
    // presence: the human's own key signs it.
    h.policy = Arc::new(
        PolicyBundle::parse(
            &DEFAULT_CONFIG.replace("require_presence = false", "require_presence = true"),
            DEFAULT_POLICY,
        )
        .unwrap(),
    );
    let last = KeyPair::generate();
    assert!(denied_with(
        &h.rotate_daemon("ayse", &last),
        "presence_required"
    ));
    assert!(denied_with(
        &h.recover_daemon_with(&ayse, "ayse", daemon_recover(&last), &last),
        "presence_required"
    ));
}

#[test]
fn scratch_roots_are_plain_absolute_directories() {
    use lonca_policy::decide::valid_scratch_root;
    for ok in [
        "/a",
        "/work/claude-1-scratch",
        "/x/y.z",
        &format!("/{}", "a".repeat(1023)),
    ] {
        assert!(valid_scratch_root(ok), "{ok}");
    }
    for bad in [
        "",
        "/",
        "a",
        "a/b",
        "/a/",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/a\x01b",
        &format!("/{}", "a".repeat(1024)),
    ] {
        assert!(!valid_scratch_root(bad), "{bad:?}");
    }
}
fn reject(seq: u64, reason: &str) -> Op {
    Op::Reject {
        target_seq: seq,
        reason: reason.into(),
    }
}

/// A human rejects an escalated proposal with a reason: the proposal is
/// rejected, its leases on what it changed are released, the pending set
/// is empty. Only humans may, only pending targets, only with a reason.
#[test]
fn a_human_rejects_an_escalated_proposal_with_a_reason() {
    let mut h = H::new();
    h.start_observed("s1", &["**"]);
    h.wrote("s1", "auth/login.rs");
    h.wrote("s1", "src/a.rs");
    assert!(
        h.lease(
            "s1",
            "l1",
            &[
                ("auth/login.rs#check", LeaseKind::Edit),
                ("src/a.rs#f", LeaseKind::Edit)
            ]
        )
        .is_allow()
    );
    let c = ChangeId::random();
    let d = h.propose("s1", c, edit("auth/login.rs#check"));
    assert_eq!(d.outcome, Outcome::Escalate);
    let seq = pending_seq(&h, c);

    let d = h.agent("s1", reject(seq, "no"));
    assert!(
        d.outcome == Outcome::Deny && d.reasons.iter().any(|r| r == "not_grantable:reject"),
        "{d:?}"
    );
    assert!(denied_with(
        &h.human("ayse", reject(seq, "   ")),
        "reason_required"
    ));
    assert!(denied_with(
        &h.human("ayse", reject(seq, &"x".repeat(4097))),
        "reason_too_long"
    ));
    assert!(denied_with(
        &h.human("ayse", reject(seq + 7, "no")),
        "nothing_pending"
    ));
    assert!(h.chain.state.pending.contains_key(&seq));

    let d = h.human("ayse", reject(seq, "wrong approach: use the token cache"));
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(
        h.chain.state.changes[&c].status,
        ChangeStatus::Rejected {
            reasons: vec!["rejected: wrong approach: use the token cache".into()]
        }
    );
    assert!(h.chain.state.pending.is_empty());
    assert!(!h.chain.state.queue.contains(&c));
    // The lease set covered a symbol of the change: released. Approving or
    // rejecting it again finds nothing.
    assert!(h.chain.state.leases.is_empty());
    assert!(denied_with(
        &h.human("ayse", approve(seq)),
        "nothing_pending"
    ));
    assert!(denied_with(
        &h.human("ayse", reject(seq, "again")),
        "nothing_pending"
    ));
    // The session goes on: a new lease and a new proposal.
    assert!(
        h.lease("s1", "l2", &[("auth/login.rs#check", LeaseKind::Edit)])
            .is_allow()
    );
    let c2 = ChangeId::random();
    assert_eq!(
        h.propose("s1", c2, edit("auth/login.rs#check")).outcome,
        Outcome::Escalate
    );
    let d = h.human("ayse", approve(pending_seq(&h, c2)));
    assert!(d.reasons.contains(&"released".to_string()), "{d:?}");
    assert_eq!(h.chain.state.changes[&c2].status, ChangeStatus::Queued);
    h.assert_replay();
}

// ------------------------------------------------------------- lease pins

fn integrate(h: &mut H, change: ChangeId, merged: Option<GitId>, conflicts: &[&str]) -> Decision {
    let trunk_before = h.chain.state.trunk.clone().unwrap();
    h.daemon(
        Op::ChangeIntegrate {
            change,
            trunk_before,
            merged,
            conflicts: conflicts.iter().map(|c| c.to_string()).collect(),
        },
        vec![pass(CheckKind::Build), pass(CheckKind::Tests)],
    )
}

fn release(set: &str) -> Op {
    Op::LeaseRelease { set: set.into() }
}

/// The symbols held at the harness's clock by `session`.
fn held(h: &H, session: &str) -> Vec<String> {
    let mut out: Vec<String> = h
        .chain
        .state
        .active_leases(h.now + 1)
        .filter(|l| l.lease.session == session)
        .flat_map(|l| l.items.into_iter().map(|i| i.symbol.clone()))
        .collect();
    out.sort();
    out
}

/// The scenario of the design: the lease outlives its TTL while the human
/// thinks, nobody else can take the symbol, and integration frees it.
#[test]
fn a_pinned_lease_outlives_its_ttl_until_the_change_integrates() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
    assert_eq!(h.chain.state.leases["l1"].pins[&c].len(), 1);

    h.now += 11 * MIN;
    let d = h.lease("b", "l2", &[(f, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{f}:a:")), "{d:?}");
    assert!(!h.chain.state.leases.contains_key("l2"));
    // The holder can not free it by hand either.
    assert!(h.agent("a", release("l1")).is_allow());
    assert_eq!(held(&h, "a"), [f]);
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));

    assert!(h.human("ayse", approve(pending_seq(&h, c))).is_allow());
    assert_eq!(h.chain.state.changes[&c].status, ChangeStatus::Queued);
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    assert!(integrate(&mut h, c, Some(gid('e')), &[]).is_allow());
    assert!(h.chain.state.leases.is_empty());
    assert!(h.lease("b", "l2", &[(f, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

/// Only what the change needs is pinned; the rest of the set keeps its
/// TTL, can be released, and can be renewed.
#[test]
fn integration_releases_the_pinned_items_and_the_rest_keeps_its_ttl() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.wrote("a", "src/a.rs");
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    assert!(
        h.lease("a", "l1", &[(f, LeaseKind::Edit), (g, LeaseKind::Edit)])
            .is_allow()
    );
    let c = ChangeId::random();
    assert!(h.propose("a", c, edit(f)).is_allow());
    let l = &h.chain.state.leases["l1"];
    assert_eq!(l.pins[&c].len(), 1);
    assert_eq!(l.pins[&c][0].symbol, f);
    let expires = l.expires_ms;
    assert!(integrate(&mut h, c, Some(gid('e')), &[]).is_allow());
    let l = &h.chain.state.leases["l1"];
    assert_eq!(l.items.len(), 1);
    assert_eq!(l.items[0].symbol, g);
    assert!(l.pins.is_empty());
    assert_eq!(l.expires_ms, expires);
    h.now += 11 * MIN;
    assert_eq!(held(&h, "a"), Vec::<String>::new());
    h.assert_replay();
}

/// An item two changes need stays until the last of them leaves.
#[test]
fn an_item_two_changes_need_stays_until_both_have_left() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.wrote("a", "src/a.rs");
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let (c1, c2) = (ChangeId::random(), ChangeId::random());
    assert!(h.propose("a", c1, edit(f)).is_allow());
    assert!(h.propose("a", c2, edit(f)).is_allow());
    assert!(integrate(&mut h, c1, Some(gid('e')), &[]).is_allow());
    assert_eq!(held(&h, "a"), [f]);
    assert!(h.chain.state.leases["l1"].pins.contains_key(&c2));
    assert!(integrate(&mut h, c2, Some(gid('f')), &[]).is_allow());
    assert!(h.chain.state.leases.is_empty());
    h.assert_replay();
}

/// `leases.release_on_integrate = false`: the item goes back to the TTL
/// of its set, and the holder goes on working on it.
#[test]
fn release_on_integrate_can_be_turned_off() {
    let config = DEFAULT_CONFIG.replace(
        "release_on_integrate = true",
        "release_on_integrate = false",
    );
    let mut h = H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap());
    h.start_observed("a", &["src/**"]);
    h.wrote("a", "src/a.rs");
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert!(h.propose("a", c, edit(f)).is_allow());
    let d = integrate(&mut h, c, Some(gid('e')), &[]);
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(d.reasons, ["leases_kept"]);
    assert!(h.chain.state.leases["l1"].pins.is_empty());
    assert_eq!(held(&h, "a"), [f]);
    h.now += 11 * MIN;
    assert_eq!(held(&h, "a"), Vec::<String>::new());
    h.assert_replay();
}

/// A conflicted change unpins: the item is the holder's again for what
/// is left of the TTL, so it can sync and propose; then it runs out.
#[test]
fn a_conflicted_change_unpins_and_the_ttl_goes_on() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    h.wrote("a", "src/a.rs");
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert!(h.propose("a", c, edit(f)).is_allow());
    assert!(denied_with(
        &integrate(&mut h, c, None, &[f]),
        "merge_conflict"
    ));
    assert!(matches!(
        h.chain.state.changes[&c].status,
        ChangeStatus::Conflicted { .. }
    ));
    let l = &h.chain.state.leases["l1"];
    assert!(l.pins.is_empty());
    assert_eq!(l.items.len(), 1, "unpinned, not released");
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    h.now += 11 * MIN;
    assert!(h.lease("b", "l2", &[(f, LeaseKind::Edit)]).is_allow());
    h.assert_replay();

    // Past the TTL of the set the pin was all that held the item.
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
    h.now += 11 * MIN;
    assert!(h.human("ayse", approve(pending_seq(&h, c))).is_allow());
    assert!(denied_with(
        &integrate(&mut h, c, None, &[f]),
        "merge_conflict"
    ));
    assert!(h.lease("b", "l2", &[(f, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

/// Withdrawing, rejecting and revoking all free what was pinned.
#[test]
fn every_way_out_of_the_queue_unpins() {
    let f = "src/a.rs#f";
    let setup = || {
        let mut h = H::new();
        h.start("a", &["src/**"]);
        h.start_observed("b", &["src/**"]);
        assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
        let c = ChangeId::random();
        assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
        h.now += 11 * MIN;
        (h, c)
    };
    let free = |h: &mut H| {
        assert!(h.lease("b", "l2", &[(f, LeaseKind::Edit)]).is_allow());
        assert!(!h.chain.state.leases.contains_key("l1"));
        h.assert_replay();
    };

    let (mut h, c) = setup();
    assert!(h.agent("a", Op::ChangeWithdraw { change: c }).is_allow());
    assert!(h.chain.state.leases["l1"].pins.is_empty());
    free(&mut h);

    let (mut h, c) = setup();
    assert!(h.human("ayse", reject(pending_seq(&h, c), "no")).is_allow());
    free(&mut h);

    let (mut h, c) = setup();
    assert!(
        h.human(
            "ayse",
            Op::CapRevoke {
                session: "a".into(),
                reason: "off".into()
            }
        )
        .is_allow()
    );
    assert_eq!(h.chain.state.changes[&c].status, ChangeStatus::Withdrawn);
    free(&mut h);
}

/// A session that ends or expires leaves its work waiting for the human;
/// the pins stay with the work, the rest of the sets goes.
#[test]
fn pins_outlive_the_end_of_their_session() {
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    for ended in [true, false] {
        let mut h = H::new();
        h.start("a", &["src/**"]);
        h.start_observed("b", &["src/**"]);
        assert!(
            h.lease("a", "l1", &[(f, LeaseKind::Edit), (g, LeaseKind::Edit)])
                .is_allow()
        );
        let unrelated = "src/b.rs#other";
        assert!(
            h.lease("b", "other", &[(unrelated, LeaseKind::Edit)])
                .is_allow()
        );
        let c = ChangeId::random();
        assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
        if ended {
            let end = Op::SessionEnd {
                session: "a".into(),
                reason: "done".into(),
            };
            assert!(h.agent("a", end).is_allow());
            // At once, and only for that session.
            assert_eq!(h.chain.state.leases["l1"].items.len(), 1);
            assert_eq!(h.chain.state.leases["other"].items.len(), 1);
            assert_eq!(held(&h, "b"), [unrelated]);
        } else {
            h.now += 121 * MIN;
            h.start_observed("b2", &["src/**"]);
        }
        let other = if ended { "b" } else { "b2" };
        assert!(denied_with(
            &h.lease(other, "l2", &[(f, LeaseKind::Edit)]),
            "lease_held"
        ));
        assert!(h.lease(other, "l3", &[(g, LeaseKind::Edit)]).is_allow());
        assert_eq!(h.chain.state.leases["l1"].items.len(), 1);
        assert!(h.human("ayse", approve(pending_seq(&h, c))).is_allow());
        assert!(integrate(&mut h, c, Some(gid('e')), &[]).is_allow());
        assert!(!h.chain.state.leases.contains_key("l1"));
        assert!(h.lease(other, "l2", &[(f, LeaseKind::Edit)]).is_allow());
        h.assert_replay();
    }
}

/// A yield gives up what its holder may give up, and no more.
#[test]
fn a_yield_can_not_give_away_a_pinned_item() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    h.wrote("a", "src/a.rs");
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    assert!(
        h.lease("a", "l1", &[(f, LeaseKind::Edit), (g, LeaseKind::Edit)])
            .is_allow()
    );
    let c = ChangeId::random();
    assert!(h.propose("a", c, edit(f)).is_allow());
    let d = h.agent(
        "a",
        Op::Negotiate {
            thread: "t1".into(),
            to_session: "b".into(),
            message: NegotiationMsg::Yield {
                set: "l1".into(),
                to: None,
            },
        },
    );
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(held(&h, "a"), [f]);
    assert!(h.lease("b", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    assert!(denied_with(
        &h.lease("b", "l3", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    h.assert_replay();
}

/// A session whose TTL ran out still holds what it pinned: it can build
/// on its own change, and nothing else of the set.
#[test]
fn a_pinned_item_counts_as_held_by_its_holder() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    assert!(
        h.lease("a", "l1", &[(f, LeaseKind::Edit), (g, LeaseKind::Edit)])
            .is_allow()
    );
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
    h.now += 11 * MIN;
    assert_eq!(held(&h, "a"), [f]);
    assert_eq!(
        h.propose("a", ChangeId::random(), edit(f)).outcome,
        Outcome::Escalate
    );
    assert!(denied_with(
        &h.propose("a", ChangeId::random(), edit(g)),
        &format!("lease_missing:{g}")
    ));
    h.assert_replay();
}

/// Each need pins the items that satisfy it: a deletion's rename lease,
/// the insert lease of a container, the file lease of a deleted file; not
/// an item of the wrong kind or of another session.
#[test]
fn pins_follow_the_lease_rules_of_the_facts() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("o", &["src/**"]);
    h.wrote("a", "src/a.rs");
    h.wrote("a", "src/b.rs");
    h.wrote("a", "src/c.rs");
    let (del, cont, dfile) = ("src/a.rs#d", "src/a.rs#T", "src/c.rs#<file>");
    assert!(
        h.lease(
            "a",
            "l1",
            &[
                (del, LeaseKind::Rename),
                (cont, LeaseKind::Insert),
                (dfile, LeaseKind::Rename),
                ("src/b.rs#other", LeaseKind::Edit),
            ]
        )
        .is_allow()
    );
    assert!(
        h.lease("a", "l2", &[("src/b.rs#e", LeaseKind::Insert)])
            .is_allow()
    );
    assert!(
        h.lease("o", "l3", &[("src/a.rs#T", LeaseKind::Insert)])
            .is_allow()
    );
    let c = ChangeId::random();
    let f = Facts {
        deletes: vec![del.into()],
        adds: vec!["src/a.rs#T.m".into()],
        deleted_files: vec!["src/c.rs".into()],
        modified_files: vec!["src/a.rs".into()],
        lines_added: 1,
        ..Default::default()
    };
    assert!(h.propose("a", c, f).is_allow());
    let s = &h.chain.state;
    let mut pinned: Vec<&str> = s.leases["l1"].pins[&c]
        .iter()
        .map(|i| i.symbol.as_str())
        .collect();
    pinned.sort();
    assert_eq!(pinned, [cont, del, dfile]);
    assert!(s.leases["l2"].pins.is_empty(), "no need of this set");
    assert!(s.leases["l3"].pins.is_empty(), "another session's");
    h.assert_replay();
}

/// Expired sets leave the state with the next entry, whatever the entry,
/// and a replay arrives at the same leases.
#[test]
fn expired_sets_are_pruned_and_replay_gives_the_same_state() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    h.now += 10 * MIN - 2;
    assert!(
        h.lease("b", "l2", &[("src/a.rs#g", LeaseKind::Edit)])
            .is_allow()
    );
    assert!(h.chain.state.leases.contains_key("l1"), "one ms left");
    h.now += 1;
    assert!(h.lease("b", "l3", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(!h.chain.state.leases.contains_key("l1"));
    // A denied entry prunes as well, and a set id is free again.
    h.now += 11 * MIN;
    assert!(denied_with(
        &h.agent("a", release("nope")),
        "unknown_lease_set"
    ));
    assert!(h.chain.state.leases.is_empty());
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let replayed = State::replay(&h.log);
    assert_eq!(
        replayed.leases.keys().collect::<Vec<_>>(),
        h.chain.state.leases.keys().collect::<Vec<_>>()
    );
    h.assert_replay();
}

/// A set whose session expired goes the same way as an expired one.
#[test]
fn sets_of_dead_sessions_are_pruned() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    let renew = Op::LeaseRenew {
        set: "l1".into(),
        ttl_ms: 30 * MIN,
    };
    assert!(
        h.lease("a", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    h.now += 9 * MIN;
    assert!(h.agent("a", renew.clone()).is_allow());
    for _ in 0..3 {
        h.now += 29 * MIN;
        assert!(h.agent("a", renew.clone()).is_allow());
    }
    assert!(h.chain.state.leases["l1"].expires_ms > h.now + 25 * MIN);
    h.now += 25 * MIN;
    h.start_observed("b", &["src/**"]);
    assert!(h.chain.state.leases.is_empty(), "session a is over");
    h.assert_replay();
}

/// The meaning changed with format 7: an older entry pins nothing and
/// prunes nothing, so an old log replays to what it always did.
#[test]
fn entries_of_an_older_format_neither_pin_nor_prune() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(
        h.lease("a", "l2", &[("src/a.rs#g", LeaseKind::Edit)])
            .is_allow()
    );
    assert_eq!(
        h.propose("a", ChangeId::random(), edit(f)).outcome,
        Outcome::Escalate
    );
    h.now += 11 * MIN;
    assert!(denied_with(
        &h.agent("a", release("nope")),
        "unknown_lease_set"
    ));
    let mut old = h.log.clone();
    assert!(old.iter().all(|o| o.entry.format >= 7));
    for o in &mut old {
        o.entry.format = 6;
    }
    let s = State::replay(&old);
    assert_eq!(s.leases.len(), 2, "not pruned");
    assert!(s.leases.values().all(|l| l.pins.is_empty()), "not pinned");
    assert_eq!(s.active_leases(h.now).count(), 0);
    h.assert_replay();
}

// ---------------------------------------------------------------- liveness

fn renew(set: &str, ttl_ms: i64) -> Op {
    Op::LeaseRenew {
        set: set.into(),
        ttl_ms,
    }
}

fn heartbeat(h: &mut H, session: &str) -> Decision {
    h.daemon(
        Op::Observe {
            session: session.into(),
            events: vec![Observation {
                phase: Phase::Pre,
                kind: ObsKind::Heartbeat,
                external: false,
            }],
        },
        vec![],
    )
}

fn unproposed(h: &mut H, session: &str, paths: Vec<String>, total: u64) -> Decision {
    h.daemon(
        Op::Observe {
            session: session.into(),
            events: vec![Observation {
                phase: Phase::Post,
                kind: ObsKind::Unproposed { paths, total },
                external: false,
            }],
        },
        vec![],
    )
}

/// What a session left: counted by the fold, cleared by a proposal or a
/// clean report, and bounded in size.
#[test]
fn a_session_s_unproposed_work_is_on_the_record_until_it_is_gone() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let mark = |h: &H| h.chain.state.sessions["s1"].unproposed.clone();
    assert_eq!(mark(&h), None);

    let d = unproposed(&mut h, "s1", vec!["src/a.rs".into()], 3);
    assert!(d.is_allow(), "{d:?}");
    let m = mark(&h).unwrap();
    assert_eq!(
        (m.paths.as_slice(), m.total, m.rounds),
        (&["src/a.rs".to_string()][..], 3, 1)
    );
    assert_eq!(m.seen_ms, h.now);
    unproposed(&mut h, "s1", vec![], 2);
    let m = mark(&h).unwrap();
    assert_eq!((m.paths.len(), m.total, m.rounds), (0, 2, 2));
    // Nothing is tainted by it, and nothing else of the session changes.
    assert_eq!(h.chain.state.sessions["s1"].taint, None);

    unproposed(&mut h, "s1", vec![], 0);
    assert_eq!(mark(&h), None);
    unproposed(&mut h, "s1", vec![], 1);
    assert_eq!(mark(&h).unwrap().rounds, 1, "the count starts over");

    let full = vec!["x".to_string(); MAX_UNPROPOSED_PATHS];
    assert!(unproposed(&mut h, "s1", full.clone(), 99).is_allow());
    let over = vec!["x".to_string(); MAX_UNPROPOSED_PATHS + 1];
    let d = unproposed(&mut h, "s1", over, 99);
    assert!(denied_with(&d, "too_many_events"), "{d:?}");
    assert_eq!(mark(&h).unwrap().paths.len(), MAX_UNPROPOSED_PATHS);
    h.assert_replay();
}

/// Renewing: your own live set, up to the longest TTL, and nothing else.
#[test]
fn renewal_is_for_the_holder_of_a_live_set_within_the_ttl() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());

    h.now += 9 * MIN;
    assert!(h.agent("a", renew("l1", 30 * MIN)).is_allow());
    assert_eq!(h.chain.state.leases["l1"].expires_ms, h.now + 30 * MIN);

    let d = h.agent("b", renew("l1", 10 * MIN));
    assert!(denied_with(&d, "not_own_lease"), "{d:?}");
    let d = h.agent("a", renew("l1", 30 * MIN + 1));
    assert!(denied_with(&d, "lease_ttl"), "{d:?}");
    for ttl in [0, -1] {
        assert!(denied_with(&h.agent("a", renew("l1", ttl)), "lease_ttl"));
    }
    assert!(denied_with(
        &h.agent("a", renew("nope", 10 * MIN)),
        "unknown_lease_set"
    ));

    // The first entry after the end still finds the set; it is refused
    // and pruned, and then there is nothing to renew.
    h.now = h.chain.state.leases["l1"].expires_ms - 1;
    assert!(denied_with(
        &h.agent("a", renew("l1", MIN)),
        "lease_expired"
    ));
    assert!(!h.chain.state.leases.contains_key("l1"));
    assert!(denied_with(
        &h.agent("a", renew("l1", MIN)),
        "unknown_lease_set"
    ));
    h.assert_replay();
}

/// The holder stops reporting: at the timeout, not before, the lease is
/// free. A session that comes back finds what it held gone.
#[test]
fn a_silent_holder_loses_its_lease_at_the_heartbeat_timeout() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let d = heartbeat(&mut h, "a");
    assert_eq!(d.reasons, ["heartbeat_timeout=300000"]);
    let seen = h.now;
    assert_eq!(h.chain.state.sessions["a"].heartbeat.unwrap().seen_ms, seen);

    // Exactly at the timeout it still holds: submit adds one ms.
    h.now = seen + 5 * MIN - 1;
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    h.now = seen + 5 * MIN;
    assert!(h.lease("b", "l2", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(!h.chain.state.leases.contains_key("l1"), "pruned");

    assert!(heartbeat(&mut h, "a").is_allow());
    assert_eq!(held(&h, "a"), Vec::<String>::new());
    assert_eq!(held(&h, "b"), [f]);
    assert!(denied_with(
        &h.agent("a", renew("l1", MIN)),
        "unknown_lease_set"
    ));
    h.assert_replay();
}

/// A session that comes back before anyone prunes it finds nothing either:
/// a beat after the timeout does not raise the dead, or two sessions could
/// hold one symbol.
#[test]
fn a_late_heartbeat_does_not_revive_a_lease() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(heartbeat(&mut h, "a").is_allow());
    h.now += 6 * MIN;
    assert!(denied_with(
        &h.agent("a", renew("l1", MIN)),
        "lease_expired"
    ));
    h.assert_replay();

    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(heartbeat(&mut h, "a").is_allow());
    h.now += 6 * MIN;
    assert!(heartbeat(&mut h, "a").is_allow());
    assert!(h.chain.state.leases.is_empty());
    h.assert_replay();
}

/// Beats keep the session alive past the timeout; the TTL still applies,
/// and sessions that never beat are not affected.
#[test]
fn heartbeats_extend_liveness_not_the_ttl() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("quiet", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(h.lease("quiet", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    for _ in 0..3 {
        assert!(heartbeat(&mut h, "a").is_allow());
        h.now += 4 * MIN;
        assert_eq!(held(&h, "a").len() + held(&h, "quiet").len(), {
            if h.now - T0 < 10 * MIN { 2 } else { 0 }
        });
    }
    assert!(h.lease("b", "l3", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(h.lease("b", "l4", &[(g, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

/// Pinned items ignore the timeout while their change is in flight.
#[test]
fn a_pinned_item_ignores_the_heartbeat_timeout() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    assert!(
        h.lease("a", "l1", &[(f, LeaseKind::Edit), (g, LeaseKind::Edit)])
            .is_allow()
    );
    assert!(heartbeat(&mut h, "a").is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
    h.now += 6 * MIN;
    assert_eq!(held(&h, "a"), [f]);
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    assert!(h.lease("b", "l3", &[(g, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

/// A policy with a hold limit that fits in a session of two hours.
fn short_hold() -> H {
    let config = DEFAULT_CONFIG.replace("max_hold_minutes = 120", "max_hold_minutes = 60");
    H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap())
}

/// Holds `l1` on `f` for 55 minutes as session `a`, and returns the time
/// it was acquired.
fn hold(h: &mut H, f: &str) -> i64 {
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let start = h.now;
    for minutes in [9, 30, 55] {
        h.now = start + minutes * MIN;
        assert!(h.agent("a", renew("l1", 30 * MIN)).is_allow());
    }
    start
}

/// The hold limit bites only when someone else is asking.
#[test]
fn renewal_past_the_hold_limit_is_refused_while_another_session_wants_the_set() {
    let mut h = short_hold();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    let start = hold(&mut h, f);
    // Past the limit with nobody waiting: renewed.
    h.now = start + 61 * MIN;
    assert!(h.agent("a", renew("l1", 30 * MIN)).is_allow());

    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    assert_eq!(
        h.chain.state.leases["l1"]
            .interest
            .keys()
            .collect::<Vec<_>>(),
        ["b"]
    );
    let expires = h.chain.state.leases["l1"].expires_ms;
    h.now += MIN;
    let d = h.agent("a", renew("l1", 30 * MIN));
    assert!(denied_with(&d, "lease_hold_limit"), "{d:?}");
    assert_eq!(h.chain.state.leases["l1"].expires_ms, expires, "unchanged");

    // The set runs out and the session that asked gets it.
    h.now = expires;
    assert!(h.lease("b", "l2", &[(f, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

#[test]
fn the_hold_limit_starts_exactly_at_the_limit() {
    let mut h = short_hold();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    let start = hold(&mut h, f);
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    h.now = start + 60 * MIN - 2;
    assert!(h.agent("a", renew("l1", 30 * MIN)).is_allow());
    h.now = start + 60 * MIN - 1;
    assert!(denied_with(
        &h.agent("a", renew("l1", 30 * MIN)),
        "lease_hold_limit"
    ));
    h.assert_replay();
}

/// Interest fades: a session that stopped asking, or stopped existing,
/// holds nobody back.
#[test]
fn interest_fades_with_time_and_with_the_session_that_asked() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    let asked = h.now;
    let l = h.chain.state.leases["l1"].clone();
    let window = 30 * MIN;
    assert!(h.chain.state.contended(&l, asked + window, window));
    assert!(!h.chain.state.contended(&l, asked + window + 1, window));
    let end = Op::SessionEnd {
        session: "b".into(),
        reason: "gave up".into(),
    };
    assert!(h.agent("b", end).is_allow());
    assert!(!h.chain.state.contended(&l, asked + 1, window));
    h.assert_replay();
}

/// Only a denial for what others hold is interest: a session outside its
/// scope, or a denial for another reason, does not block anyone.
#[test]
fn only_a_denial_for_a_held_symbol_registers_interest() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("narrow", &["docs/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(
        h.lease("a", "own", &[("src/b.rs#g", LeaseKind::Edit)])
            .is_allow()
    );
    let d = h.lease("narrow", "l2", &[(f, LeaseKind::Edit)]);
    assert!(denied_with(&d, "scope_path"), "{d:?}");
    assert!(h.chain.state.leases["l1"].interest.is_empty());
    let d = h.lease(
        "b",
        "l3",
        &[(f, LeaseKind::Edit), ("src/c.rs#h", LeaseKind::Insert)],
    );
    assert!(denied_with(&d, "lease_held"), "{d:?}");
    let s = &h.chain.state;
    assert!(s.leases["l1"].interest.contains_key("b"));
    assert!(s.leases["own"].interest.is_empty(), "no conflict there");
    h.assert_replay();
}

/// A fresh set over what the session already holds does not start the
/// hold again.
#[test]
fn a_new_set_over_held_symbols_continues_the_hold() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let start = h.now;
    h.now += 5 * MIN;
    assert!(h.lease("a", "l2", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(h.lease("a", "l3", &[(g, LeaseKind::Edit)]).is_allow());
    let s = &h.chain.state;
    assert_eq!(s.leases["l2"].acquired_ms, start);
    assert_eq!(s.leases["l3"].acquired_ms, h.now);
    h.assert_replay();
}

/// The meaning changed with format 8: an older heartbeat keeps nothing
/// alive, an older denial registers no interest, and an older renewal
/// has no hold limit. Replaying the same entries as format 7 proves it.
#[test]
fn entries_of_an_older_format_know_no_liveness() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(denied_with(
        &h.lease("b", "l2", &[(f, LeaseKind::Edit)]),
        "lease_held"
    ));
    assert!(heartbeat(&mut h, "a").is_allow());
    let mut old = h.log.clone();
    for o in &mut old {
        assert_eq!(o.entry.format, FORMAT_CURRENT);
        o.entry.format = 7;
        if matches!(o.entry.op, Op::Observe { .. }) {
            o.entry.decision.reasons.clear();
        }
    }
    let s = State::replay(&old);
    assert!(s.leases["l1"].interest.is_empty());
    let late_ms = h.now + 1000 * MIN;
    assert!(!s.session_lost("a", late_ms));
    // decide() with the entry's format: no hold limit, no timeout reason.
    let bundle = PolicyBundle::default_bundle();
    let ctx = |format, time_ms| Ctx {
        format,
        time_ms,
        policy: &bundle,
        facts: None,
        evidence: &[],
    };
    let actor = Actor::Agent {
        name: "bot-a".into(),
        session: "a".into(),
    };
    let mut held_long = h.chain.state.clone();
    let l = held_long.leases.get_mut("l1").unwrap();
    l.acquired_ms -= 500 * MIN;
    let t = h.now + 1;
    let op = renew("l1", MIN);
    assert!(denied_with(
        &decide(&held_long, &actor, &op, None, &ctx(8, t)),
        "lease_hold_limit"
    ));
    assert!(decide(&held_long, &actor, &op, None, &ctx(7, t)).is_allow());
    held_long.sessions.get_mut("a").unwrap().heartbeat = Some(lonca_policy::state::Heartbeat {
        seen_ms: t - 6 * MIN,
        timeout_ms: 5 * MIN,
    });
    held_long.leases.get_mut("l1").unwrap().interest.clear();
    assert!(denied_with(
        &decide(&held_long, &actor, &op, None, &ctx(8, t)),
        "lease_expired"
    ));
    assert!(decide(&held_long, &actor, &op, None, &ctx(7, t)).is_allow());
    h.assert_replay();
}

#[test]
fn liveness_limits_must_be_positive() {
    for bad in ["heartbeat_timeout_ms = 300000", "max_hold_minutes = 120"] {
        let (name, _) = bad.split_once(" = ").unwrap();
        for value in ["0", "-1"] {
            let config = DEFAULT_CONFIG.replace(bad, &format!("{name} = {value}"));
            let err = PolicyBundle::parse(&config, DEFAULT_POLICY).err().unwrap();
            assert!(err.contains("must be positive"), "{err}");
        }
    }
    assert!(
        PolicyBundle::parse(
            &DEFAULT_CONFIG
                .replace("max_hold_minutes = 120", "max_hold_minutes = 1")
                .replace("heartbeat_timeout_ms = 300000", "heartbeat_timeout_ms = 1"),
            DEFAULT_POLICY
        )
        .is_ok()
    );
}

// ------------------------------------------------------- continued sessions

fn taint(session: &str) -> Op {
    Op::Taint {
        session: session.into(),
        reason: "read the web".into(),
    }
}

/// What is known of the workspace's files goes with them: a new session
/// on the same files clears nothing (issue #98).
#[test]
fn a_continuation_inherits_taint_level_and_writes_and_starts_alive() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.wrote("a", "src/a.rs");
    let shell = Op::Observe {
        session: "a".into(),
        events: vec![Observation {
            phase: Phase::Pre,
            kind: ObsKind::Shell {
                program: "ls".into(),
                digest: "d".into(),
            },
            external: false,
        }],
    };
    assert!(h.daemon(shell, vec![]).is_allow());
    assert!(h.daemon(taint("a"), vec![]).is_allow());
    h.now += 121 * MIN;
    assert!(!h.chain.state.session_active("a", h.now));
    assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());

    let s = &h.chain.state;
    let (old, new) = (&s.sessions["a"], &s.sessions["b"]);
    assert_eq!(new.taint.as_deref(), Some("read the web"));
    assert_eq!(new.level, old.level);
    assert_ne!(new.level, ObservationLevel::Unobserved);
    assert_eq!(new.writes, old.writes);
    assert!(new.writes.contains("src/a.rs"));
    assert_eq!(new.shell_seen, old.shell_seen);
    assert!(new.shell_seen);
    assert_eq!(new.continued_from.as_deref(), Some("a"));
    assert_eq!(new.continued_by, None);
    assert_eq!(new.parent, None, "not a child: it outlives the old session");
    assert_eq!(old.continued_by.as_deref(), Some("b"));
    assert_eq!(old.ended.as_deref(), Some("continued by b"));
    assert!(s.session_active("b", h.now));
    assert!(s.continues("b", "a"));
    assert!(!s.continues("a", "b"));
    h.assert_replay();
}

/// A session that was never tainted or bound stays so: nothing is
/// invented for the continuation.
#[test]
fn a_clean_unobserved_session_continues_clean_and_unobserved() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());
    let new = &h.chain.state.sessions["b"];
    assert_eq!(new.taint, None);
    assert_eq!(new.level, ObservationLevel::Unobserved);
    assert!(new.writes.is_empty());
    assert!(!new.shell_seen);
    // A plain start has none of it.
    h.start("c", &["src/**"]);
    let c = &h.chain.state.sessions["c"];
    assert_eq!((&c.continued_from, &c.continued_by), (&None, &None));
    h.assert_replay();
}

#[test]
fn a_live_session_ends_with_its_continuation_and_its_leases_end_with_it() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start("other", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());

    let s = &h.chain.state;
    assert!(!s.session_active("a", h.now));
    assert!(s.session_active("b", h.now));
    assert!(s.leases.is_empty(), "a lease is not carried");
    let d = h.lease("a", "l2", &[(f, LeaseKind::Edit)]);
    assert!(denied_with(&d, "session_inactive"), "{d:?}");
    assert!(h.lease("b", "l3", &[(f, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

#[test]
fn continuing_is_refused_for_what_is_not_a_single_root_session_in_scope() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let d = h.continue_as("b", "nope", &["src/**"], false);
    assert!(denied_with(&d, "unknown_session"), "{d:?}");

    // Wider than the old session: only when the human asks for it.
    let d = h.continue_as("b", "a", &["src/**", "docs/**"], false);
    assert!(denied_with(&d, "scope_widening:path:docs/**"), "{d:?}");
    assert!(h.chain.state.session_active("a", h.now), "nothing happened");
    assert!(!h.chain.state.sessions.contains_key("b"));

    // Narrower needs nothing.
    assert!(h.continue_as("b", "a", &["src/a/**"], false).is_allow());
    // A wide one is logged as such.
    assert!(h.continue_as("c", "b", &["src/**"], true).is_allow());
    assert_eq!(h.chain.state.sessions["c"].scope.paths, ["src/**"]);

    // One successor: a workspace never has two live sessions.
    let d = h.continue_as("d", "b", &["src/a/**"], false);
    assert!(denied_with(&d, "session_continued"), "{d:?}");
    assert!(h.chain.state.session_active("c", h.now));

    // A child's scope and lifetime are its parent's.
    h.start("p", &["src/**"]);
    let attenuate = Op::CapAttenuate {
        parent: "p".into(),
        child: "kid".into(),
        agent: "bot".into(),
        scope: h.chain.state.sessions["p"].scope.clone(),
        expires_ms: h.now + 10 * MIN,
        leases: vec![],
    };
    assert!(h.agent("p", attenuate).is_allow());
    let d = h.continue_as("e", "kid", &["src/**"], false);
    assert!(denied_with(&d, "continue_child_session"), "{d:?}");
    h.assert_replay();
}

/// The change in flight stays what it was; its pins pass to the session
/// that goes on, which can propose on top of it and take it back.
#[test]
fn a_pending_change_keeps_its_pin_and_the_continuation_holds_it() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start("other", &["src/**"]);
    let (f, g) = ("src/a.rs#f", "src/a.rs#g");
    let both = [(f, LeaseKind::Edit), (g, LeaseKind::Edit)];
    assert!(h.lease("a", "l1", &both).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
    assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());

    assert!(matches!(
        h.chain.state.changes[&c].status,
        ChangeStatus::Pending { .. }
    ));
    let l = &h.chain.state.leases["l1"];
    assert_eq!(l.session, "b");
    assert_eq!(l.pins[&c].len(), 1);
    assert_eq!(
        l.items.len(),
        1,
        "what was not pinned ended with the session"
    );
    assert_eq!(held(&h, "b"), [f]);
    let d = h.lease("other", "l2", &[(f, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{f}:b:")), "{d:?}");
    assert!(h.lease("other", "l3", &[(g, LeaseKind::Edit)]).is_allow());

    // On top of it: the same symbol, no new lease.
    let c2 = ChangeId::random();
    assert_eq!(h.propose("b", c2, edit(f)).outcome, Outcome::Escalate);
    assert!(h.chain.state.leases["l1"].pins.contains_key(&c2));

    // The continuation may take back what its workspace proposed, and an
    // outsider may not.
    let withdraw = Op::ChangeWithdraw { change: c };
    let d = h.agent("other", withdraw.clone());
    assert!(denied_with(&d, "not_own_change"), "{d:?}");
    assert!(h.agent("b", withdraw).is_allow());
    assert_eq!(h.chain.state.changes[&c].status, ChangeStatus::Withdrawn);
    assert!(h.chain.state.leases["l1"].pins.contains_key(&c2));
    assert!(h.human("ayse", approve(pending_seq(&h, c2))).is_allow());
    assert!(integrate(&mut h, c2, Some(gid('e')), &[]).is_allow());
    assert!(!h.chain.state.leases.contains_key("l1"));
    h.assert_replay();
}

/// A session goes on only in the direction of its continuation.
#[test]
fn the_earlier_session_can_not_take_back_the_continuations_change() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());
    assert!(h.lease("b", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("b", c, edit(f)).outcome, Outcome::Escalate);
    h.start("x", &["src/**"]);
    let d = h.agent("x", Op::ChangeWithdraw { change: c });
    assert!(denied_with(&d, "not_own_change"), "{d:?}");
    h.assert_replay();
}

/// A revocation is about the work, whichever session of it is named, and
/// it leaves no pin behind.
#[test]
fn revoking_either_session_withdraws_the_work_and_frees_the_pin() {
    for revoked in ["a", "b"] {
        let mut h = H::new();
        h.start("a", &["src/**"]);
        h.start("other", &["src/**"]);
        let f = "src/a.rs#f";
        assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
        let c = ChangeId::random();
        assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
        assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());
        let revoke = Op::CapRevoke {
            session: revoked.into(),
            reason: "no".into(),
        };
        assert!(h.human("ayse", revoke).is_allow());

        let s = &h.chain.state;
        assert_eq!(s.changes[&c].status, ChangeStatus::Withdrawn, "{revoked}");
        assert!(s.pending.is_empty(), "{revoked}");
        let pins: Vec<_> = s.leases.values().flat_map(|l| l.pins.keys()).collect();
        assert!(pins.is_empty(), "{revoked}: {pins:?}");
        let d = h.lease("other", "l2", &[(f, LeaseKind::Edit)]);
        assert!(d.is_allow(), "{revoked}: {d:?}");
        h.assert_replay();
    }
}

/// Revoking the continuation takes back the chain, however long it is.
#[test]
fn a_revocation_reaches_every_earlier_session_of_the_workspace() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(f)).outcome, Outcome::Escalate);
    assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());
    assert!(h.continue_as("d", "b", &["src/**"], false).is_allow());
    assert_eq!(held(&h, "d"), [f], "pins pass along the chain");
    let revoke = Op::CapRevoke {
        session: "d".into(),
        reason: "no".into(),
    };
    assert!(h.human("ayse", revoke).is_allow());
    assert_eq!(h.chain.state.changes[&c].status, ChangeStatus::Withdrawn);
    assert!(!h.chain.state.session_active("d", h.now));
    h.assert_replay();
}

// ------------------------------------------------------- agent config paths

/// What instructs or configures an agent goes the way of what runs code: a
/// human approves it, and a tainted session does not touch it (issue #55).
#[test]
fn agent_instructions_and_tool_config_are_critical() {
    for path in [
        "CLAUDE.md",
        "crates/x/CLAUDE.md",
        ".mcp.json",
        ".cargo/config.toml",
        ".claude/settings.json",
        ".imece/check",
        ".lonca/workspace.json",
    ] {
        let mut h = H::new();
        h.start_observed("s1", &["**"]);
        h.wrote("s1", path);
        let sym = format!("{path}#<file>");
        assert!(h.lease("s1", "l1", &[(&sym, LeaseKind::Edit)]).is_allow());
        let d = h.propose("s1", ChangeId::random(), edit(&sym));
        assert_eq!(d.outcome, Outcome::Escalate, "{path}: {d:?}");
        assert!(
            d.reasons.contains(&format!("critical_path:{path}")),
            "{path}: {d:?}"
        );

        let taint = Op::Taint {
            session: "s1".into(),
            reason: "read the web".into(),
        };
        assert!(h.daemon(taint, vec![]).is_allow());
        let d = h.propose("s1", ChangeId::random(), edit(&sym));
        assert!(denied_with(&d, "tainted_critical_path"), "{path}: {d:?}");
        h.assert_replay();
    }
}

// -------------------------------------------------------- the lease queue

fn interest(h: &mut H, session: &str, sym: &str) -> Decision {
    let op = Op::LeaseInterest {
        items: vec![LeaseItem {
            symbol: sym.into(),
            kind: LeaseKind::Edit,
        }],
        intent: "waiting".into(),
    };
    h.agent(session, op)
}

const F: &str = "src/a.rs#f";

fn three_sessions() -> H {
    let mut h = H::new();
    for s in ["a", "b", "c"] {
        h.start(s, &["src/**"]);
    }
    h
}

/// The oldest interest is served: what was a race for the fastest poller
/// is a queue (issue #42).
#[test]
fn a_freed_lease_goes_to_the_oldest_interest_for_a_window() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    h.now += MIN;
    assert!(interest(&mut h, "c", F).is_allow());
    assert_eq!(h.chain.state.interests.len(), 2);
    assert!(h.chain.state.leases.len() == 1, "interest holds nothing");

    assert!(h.agent("a", release("l1")).is_allow());
    assert!(h.chain.state.reservations.is_empty(), "no entry since");
    // The window opens at the next entry, whoever writes it.
    let d = h.lease("c", "l2", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_reserved:b"), "{d:?}");
    let until = h.log.last().unwrap().entry.time_ms + 60_000;
    assert_eq!(
        h.chain.state.reservations,
        [lonca_policy::state::Reservation {
            session: "b".into(),
            items: vec![LeaseItem {
                symbol: F.into(),
                kind: LeaseKind::Edit
            }],
            until_ms: until,
        }]
    );
    assert_eq!(h.chain.state.interests.len(), 1, "c still waits");

    // One millisecond before the window closes it still holds.
    h.now = until - 3;
    let d = h.lease("c", "l2", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_reserved:b"), "{d:?}");
    assert_eq!(h.log.last().unwrap().entry.time_ms, until - 2);

    assert!(h.lease("b", "l3", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.chain.state.reservations.is_empty());
    // What b waited for is in hand; c goes on waiting behind it.
    let waiting: Vec<&str> = h
        .chain
        .state
        .interests
        .values()
        .map(|i| i.session.as_str())
        .collect();
    assert_eq!(waiting, ["c"]);
    h.assert_replay();
}

/// A window that nobody used passes to the next in the queue.
#[test]
fn a_window_that_ran_out_passes_on() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    assert!(interest(&mut h, "c", F).is_allow());
    assert!(h.agent("a", release("l1")).is_allow());
    let d = h.lease("c", "l2", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_reserved:b"), "{d:?}");

    // The entry at the very end of the window is past it.
    let until = h.chain.state.reservations[0].until_ms;
    h.now = until - 1;
    assert!(h.lease("c", "l2", &[(F, LeaseKind::Edit)]).is_allow());
    assert_eq!(h.log.last().unwrap().entry.time_ms, until);
    h.now += MIN;
    assert!(h.agent("c", release("l2")).is_allow());
    assert!(h.lease("b", "l3", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.chain.state.interests.is_empty());
    h.assert_replay();
}

/// A lease that expires serves the queue too: time alone frees a set, and
/// the window opens at the first entry after that.
#[test]
fn an_expired_lease_serves_the_queue_at_the_next_entry() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    h.now += 11 * MIN;
    let d = h.lease("c", "l2", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_reserved:b"), "{d:?}");
    assert_eq!(h.chain.state.reservations[0].until_ms, h.now + 60_000);
    assert!(h.lease("b", "l3", &[(F, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

/// A session that went away waits for nothing and blocks nobody.
#[test]
fn an_ended_session_leaves_the_queue_and_gives_up_its_window() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    assert!(interest(&mut h, "c", F).is_allow());
    let end = Op::SessionEnd {
        session: "b".into(),
        reason: "done".into(),
    };
    assert!(h.agent("b", end).is_allow());
    assert_eq!(
        h.chain.state.interests.len(),
        2,
        "settled at the next entry"
    );
    assert!(h.agent("a", release("l1")).is_allow());
    assert_eq!(h.chain.state.interests.len(), 1, "b has left the queue");
    assert!(h.lease("c", "l2", &[(F, LeaseKind::Edit)]).is_allow());

    // A reservation of a session that ended stands in nobody's way.
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    assert!(h.agent("a", release("l1")).is_allow());
    let d = h.lease("c", "l2", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_reserved:b"), "{d:?}");
    let end = Op::SessionEnd {
        session: "b".into(),
        reason: "done".into(),
    };
    assert!(h.agent("b", end).is_allow());
    assert!(h.lease("c", "l2", &[(F, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

#[test]
fn an_interest_needs_something_to_wait_for_and_the_right_to_acquire() {
    let mut h = three_sessions();
    let d = interest(&mut h, "b", F);
    assert!(denied_with(&d, "lease_free"), "{d:?}");
    assert!(h.chain.state.interests.is_empty());

    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(
        denied_with(&interest(&mut h, "a", F), "lease_free"),
        "own set"
    );
    assert!(interest(&mut h, "b", F).is_allow());
    let d = interest(&mut h, "b", F);
    assert!(denied_with(&d, "interest_exists"), "{d:?}");

    // Waiting behind a reservation is waiting too.
    assert!(h.agent("a", release("l1")).is_allow());
    assert!(interest(&mut h, "c", F).is_allow());

    // Scope and shape, as for an acquire.
    let d = interest(&mut h, "c", "docs/a.md#<file>");
    assert!(denied_with(&d, "scope_path:docs"), "{d:?}");
    let d = interest(&mut h, "c", "src/a.rs");
    assert!(denied_with(&d, "invalid_symbol"), "{d:?}");
    let empty = Op::LeaseInterest {
        items: vec![],
        intent: String::new(),
    };
    let d = h.agent("c", empty);
    assert!(denied_with(&d, "lease_item_count"), "{d:?}");
    let long = Op::LeaseInterest {
        items: vec![LeaseItem {
            symbol: "src/b.rs#g".into(),
            kind: LeaseKind::Edit,
        }],
        intent: "x".repeat(501),
    };
    let d = h.agent("c", long);
    assert!(denied_with(&d, "intent_too_long"), "{d:?}");

    let mut no_acquire = H::new();
    let mut op = no_acquire.start_op("s", &["src/**"], None);
    if let Op::SessionStart { scope, .. } = &mut op {
        scope.ops.retain(|k| *k != OpKind::LeaseAcquire);
    }
    assert!(no_acquire.human("ayse", op).is_allow());
    let d = interest(&mut no_acquire, "s", F);
    assert!(denied_with(&d, "scope_op:lease.acquire"), "{d:?}");
    h.assert_replay();
}

/// An interest counts as someone wanting the set, for the hold limit.
#[test]
fn an_interest_holds_back_a_renewal_past_the_limit() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    assert!(h.chain.state.leases["l1"].interest.contains_key("b"));
    h.assert_replay();
}

fn msg_to(to: &str, thread: &str, set: &str, target: Option<&str>) -> Op {
    Op::Negotiate {
        thread: thread.into(),
        to_session: to.into(),
        message: NegotiationMsg::Yield {
            set: set.into(),
            to: target.map(String::from),
        },
    }
}

/// With `to` a yield is a handover in one entry: nobody can step between.
#[test]
fn a_yield_to_a_session_moves_the_set_at_once() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "c", F).is_allow());
    h.now += MIN;
    let d = h.agent("a", msg_to("b", "t1", "l1", Some("b")));
    assert!(d.is_allow(), "{d:?}");
    let l = &h.chain.state.leases["l1"];
    assert_eq!(l.session, "b");
    assert_eq!(l.acquired_ms, h.now, "a new hold");
    assert!(l.interest.is_empty());
    let d = h.lease("c", "l2", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_held"), "{d:?}");
    assert_eq!(held(&h, "b"), [F]);
    h.assert_replay();
}

#[test]
fn a_yield_goes_only_to_the_counterparty_with_a_scope_that_covers_it() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start("b", &["src/**"]);
    h.start("narrow", &["docs/**"]);
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    let d = h.agent("a", msg_to("b", "t1", "l1", Some("narrow")));
    assert!(denied_with(&d, "yield_to_another_session"), "{d:?}");
    let d = h.agent("a", msg_to("narrow", "t2", "l1", Some("narrow")));
    assert!(denied_with(&d, "scope_path:src/a.rs"), "{d:?}");
    let d = h.agent("b", msg_to("a", "t3", "l1", Some("a")));
    assert!(denied_with(&d, "not_own_lease"), "{d:?}");

    // What is pinned stays with its change; a set that ran out has nothing
    // left to give.
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(F)).outcome, Outcome::Escalate);
    let d = h.agent("a", msg_to("b", "t4", "l1", Some("b")));
    assert!(denied_with(&d, "lease_pinned"), "{d:?}");
    h.assert_replay();

    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start("b", &["src/**"]);
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    h.now += 10 * MIN;
    let d = h.agent("a", msg_to("b", "t1", "l1", Some("b")));
    assert!(denied_with(&d, "lease_expired"), "{d:?}");
    h.assert_replay();
}

fn child_op(h: &H, parent: &str, child: &str, leases: &[&str]) -> Op {
    let mut scope = h.chain.state.sessions[parent].scope.clone();
    scope.paths = vec!["src/**".into()];
    Op::CapAttenuate {
        parent: parent.into(),
        child: child.into(),
        agent: "sub".into(),
        scope,
        expires_ms: h.now + 10 * MIN,
        leases: leases.iter().map(|s| s.to_string()).collect(),
    }
}

/// A lease handed to a sub-agent is the sub-agent's while it lasts, and
/// comes back without a race.
#[test]
fn a_delegated_lease_comes_back_when_the_child_ends() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    let op = child_op(&h, "a", "kid", &["l1"]);
    assert!(h.agent("a", op).is_allow());
    let l = &h.chain.state.leases["l1"];
    assert_eq!(l.session, "kid");
    assert_eq!(l.delegated_from.as_deref(), Some("a"));
    assert_eq!(held(&h, "kid"), [F]);
    let d = h.lease("b", "l2", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_held"), "{d:?}");

    let end = Op::SessionEnd {
        session: "kid".into(),
        reason: "done".into(),
    };
    assert!(h.agent("kid", end).is_allow());
    let l = &h.chain.state.leases["l1"];
    assert_eq!(l.session, "a");
    assert_eq!(l.delegated_from, None);
    assert_eq!(held(&h, "a"), [F]);
    h.assert_replay();
}

/// Revoking the parent takes everything derived from it; revoking only
/// the child gives the lease back.
#[test]
fn a_revocation_cascades_over_delegated_leases() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    let op = child_op(&h, "a", "kid", &["l1"]);
    assert!(h.agent("a", op).is_allow());
    let revoke = Op::CapRevoke {
        session: "a".into(),
        reason: "no".into(),
    };
    assert!(h.human("ayse", revoke).is_allow());
    assert!(
        h.chain.state.leases.is_empty(),
        "{:?}",
        h.chain.state.leases
    );
    assert!(h.lease("b", "l2", &[(F, LeaseKind::Edit)]).is_allow());
    h.assert_replay();

    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    let op = child_op(&h, "a", "kid", &["l1"]);
    assert!(h.agent("a", op).is_allow());
    let revoke = Op::CapRevoke {
        session: "kid".into(),
        reason: "no".into(),
    };
    assert!(h.human("ayse", revoke).is_allow());
    assert_eq!(h.chain.state.leases["l1"].session, "a");
    h.assert_replay();
}

#[test]
fn a_delegation_needs_the_parents_own_live_set_within_the_childs_scope() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    let op = child_op(&h, "b", "kid", &["l1"]);
    let d = h.agent("b", op);
    assert!(denied_with(&d, "not_own_lease"), "{d:?}");

    let mut narrow = child_op(&h, "a", "kid", &["l1"]);
    if let Op::CapAttenuate { scope, .. } = &mut narrow {
        scope.paths = vec!["src/other/**".into()];
    }
    let d = h.agent("a", narrow);
    assert!(denied_with(&d, "scope_path:src/a.rs"), "{d:?}");
    assert_eq!(h.chain.state.leases["l1"].session, "a");
    h.assert_replay();
}

fn acquire_for(h: &mut H, set: &str, ttl_ms: i64) -> Decision {
    let op = Op::LeaseAcquire {
        set: set.into(),
        items: vec![LeaseItem {
            symbol: F.into(),
            kind: LeaseKind::Edit,
        }],
        intent: "ttl".into(),
        ttl_ms,
    };
    h.agent("a", op)
}

/// The bounds of a lease's TTL, on both sides of each.
#[test]
fn a_lease_ttl_is_positive_and_within_the_maximum() {
    let mut h = three_sessions();
    let max = 30 * MIN;
    for ttl in [0, -1, max + 1] {
        let d = acquire_for(&mut h, "l1", ttl);
        assert!(denied_with(&d, "lease_ttl"), "{ttl}: {d:?}");
    }
    assert!(acquire_for(&mut h, "l1", max).is_allow());
    assert!(acquire_for(&mut h, "l2", 1).is_allow());
    h.assert_replay();
}

/// The inbox reports what happened to the session's own work, its earlier
/// sessions' included, and nobody else's.
#[test]
fn an_integration_is_news_for_the_workspace_that_proposed_it() {
    use lonca_policy::events::{Event, for_session};
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("a", c, edit(F)).outcome, Outcome::Escalate);
    assert!(h.continue_as("a2", "a", &["src/**"], false).is_allow());
    let approved = pending_seq(&h, c);
    assert!(h.human("ayse", approve(approved)).is_allow());
    assert!(integrate(&mut h, c, Some(gid('e')), &[]).is_allow());
    let integrated = h.log.last().unwrap().entry.seq;

    let events = |h: &H, s: &str| for_session(&h.chain.state, s, &h.log, h.now);
    let want = vec![
        Event::Approved {
            seq: integrated - 1,
            target_seq: approved,
        },
        Event::Integrated {
            seq: integrated,
            change: c,
        },
    ];
    assert_eq!(events(&h, "a"), want);
    assert_eq!(events(&h, "a2"), want, "the workspace's earlier session");
    assert_eq!(events(&h, "b"), []);

    let g = "src/a.rs#g";
    assert!(h.lease("a2", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    let c2 = ChangeId::random();
    assert_eq!(h.propose("a2", c2, edit(g)).outcome, Outcome::Escalate);
    assert!(h.human("ayse", approve(pending_seq(&h, c2))).is_allow());
    let d = integrate(&mut h, c2, None, &["src/a.rs#g"]);
    assert!(denied_with(&d, "merge_conflict"), "{d:?}");
    let conflicted = h.log.last().unwrap().entry.seq;
    assert_eq!(
        events(&h, "a2").last(),
        Some(&Event::Conflicted {
            seq: conflicted,
            change: c2,
            conflicts: vec!["src/a.rs#g".into()],
        })
    );

    // It merged and the decision refused it: not a conflict, not a landing.
    assert!(h.lease("a2", "l3", &[(g, LeaseKind::Edit)]).is_allow());
    let c3 = ChangeId::random();
    assert_eq!(h.propose("a2", c3, edit(g)).outcome, Outcome::Escalate);
    assert!(h.human("ayse", approve(pending_seq(&h, c3))).is_allow());
    let d = integrate(&mut h, c3, Some(gid('f')), &["x"]);
    assert!(denied_with(&d, "conflicts_with_merge"), "{d:?}");
    let failed = h.log.last().unwrap().entry.seq;
    assert_eq!(
        events(&h, "a2").last(),
        Some(&Event::Failed {
            seq: failed,
            change: c3,
            reasons: vec!["conflicts_with_merge".into()],
        })
    );
    assert_eq!(events(&h, "b"), [], "not news for anyone else");
    h.assert_replay();
}

/// A yield and a delegation arrive as leases received; the message of a
/// yield arrives too.
#[test]
fn a_lease_handed_over_is_in_the_inbox() {
    use lonca_policy::events::{Event, for_session};
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.agent("a", msg_to("b", "t1", "l1", Some("b"))).is_allow());
    let seq = h.log.last().unwrap().entry.seq;
    let got = for_session(&h.chain.state, "b", &h.log, h.now);
    assert_eq!(
        got,
        [
            Event::LeaseReceived {
                seq,
                set: "l1".into(),
                from: Some("a".into()),
            },
            Event::Message {
                seq,
                thread: "t1".into(),
                from: Some("a".into()),
            },
        ]
    );
    let op = child_op(&h, "b", "kid", &["l1"]);
    assert!(h.agent("b", op).is_allow());
    let seq = h.log.last().unwrap().entry.seq;
    assert_eq!(
        for_session(&h.chain.state, "kid", &h.log, h.now),
        [Event::LeaseReceived {
            seq,
            set: "l1".into(),
            from: Some("b".into()),
        }]
    );
    // From the middle of the log, the sequence numbers stay right.
    let tail = &h.log[seq as usize..];
    assert_eq!(for_session(&h.chain.state, "b", tail, h.now), []);
    h.assert_replay();
}

/// A reservation stands in the way of what conflicts with it, and of
/// nothing else: two freed symbols serve two sessions at once.
#[test]
fn reservations_of_different_symbols_do_not_stand_in_each_others_way() {
    let mut h = three_sessions();
    h.start("d", &["src/**"]);
    let g = "src/a.rs#g";
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.lease("c", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    assert!(interest(&mut h, "d", g).is_allow());
    assert!(h.agent("a", release("l1")).is_allow());
    assert!(h.agent("c", release("l2")).is_allow());
    let holders: Vec<String> = h
        .chain
        .state
        .reservations_at(h.now)
        .into_iter()
        .map(|r| r.session)
        .collect();
    assert_eq!(holders, ["b", "d"]);
    assert!(h.lease("d", "l3", &[(g, LeaseKind::Edit)]).is_allow());
    assert_eq!(h.chain.state.reservations.len(), 1, "b's stands");
    assert_eq!(h.chain.state.reservations[0].session, "b");
    assert!(h.lease("b", "l4", &[(F, LeaseKind::Edit)]).is_allow());
    h.assert_replay();
}

fn start_with_symbols(h: &mut H, session: &str, symbols: &[&str]) {
    let mut op = h.start_op(session, &["src/**"], None);
    if let Op::SessionStart { scope, .. } = &mut op {
        scope.symbols = Some(symbols.iter().map(|s| s.to_string()).collect());
    }
    assert!(h.human("ayse", op).is_allow());
}

/// What a lease request asks for, the same for an acquire and an interest.
#[test]
fn a_lease_names_a_valid_symbol_inside_the_sessions_symbols() {
    let mut h = H::new();
    h.start("a", &["**"]);
    for bad in ["src/a.rs#", "../a.rs#f", "src/a.rs"] {
        let d = h.lease("a", "l", &[(bad, LeaseKind::Edit)]);
        assert!(denied_with(&d, "invalid_symbol"), "{bad}: {d:?}");
    }

    start_with_symbols(&mut h, "some", &["Client.*"]);
    let inside = "src/a.rs#Client.charge";
    assert!(
        h.lease("some", "l1", &[(inside, LeaseKind::Edit)])
            .is_allow()
    );
    let d = h.lease("some", "l2", &[("src/a.rs#other", LeaseKind::Edit)]);
    assert!(denied_with(&d, "scope_symbol:src/a.rs#other"), "{d:?}");
    // A pseudo-symbol is more than any name: only `*` reaches it.
    let d = h.lease("some", "l3", &[("src/a.rs#<file>", LeaseKind::Insert)]);
    assert!(denied_with(&d, "scope_symbol:"), "{d:?}");

    start_with_symbols(&mut h, "all", &["*"]);
    let d = h.lease("all", "l4", &[("src/b.rs#<file>", LeaseKind::Insert)]);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// The bounds of a lease request, on both sides of each.
#[test]
fn a_lease_request_may_be_as_long_as_the_limits_and_no_longer() {
    let request = |h: &mut H, set: &str, n: usize, intent: usize| {
        let items = (0..n).map(|i| LeaseItem {
            symbol: format!("src/{set}.rs#f{i}"),
            kind: LeaseKind::Edit,
        });
        let op = Op::LeaseAcquire {
            set: set.into(),
            items: items.collect(),
            intent: "x".repeat(intent),
            ttl_ms: 10 * MIN,
        };
        h.agent("a", op)
    };
    let mut h = three_sessions();
    let d = request(&mut h, "many", 65, 1);
    assert!(denied_with(&d, "lease_item_count"), "{d:?}");
    assert!(request(&mut h, "many", 64, 1).is_allow());
    let d = request(&mut h, "long", 1, 501);
    assert!(denied_with(&d, "intent_too_long"), "{d:?}");
    assert!(request(&mut h, "long", 1, 500).is_allow());
    assert!(request(&mut h, "one", 1, 0).is_allow());
    h.assert_replay();
}
