//! Scenario tests for the decision function. Every scenario ends by
//! replaying its log and checking that each recorded decision is reproduced.

use lonca_core::canonical::nonce;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{SignedOp, verify_chain};
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
        let op = Op::SessionStart {
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
        };
        let d = self.human(human, op);
        assert!(d.is_allow(), "{d:?}");
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
        &h.agent("s2", msg("s1", NegotiationMsg::Yield { set: "l1".into() })),
        "not_own_lease"
    ));
    assert!(
        h.agent("s1", msg("s2", NegotiationMsg::Yield { set: "l1".into() }))
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
    assert!(h.chain.state.leases.is_empty());
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
