//! Scenario tests for the decision function. Every scenario ends by
//! replaying its log and checking that each recorded decision is reproduced.

use lonca_core::canonical::random_id;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{SignedOp, verify_chain};
use lonca_core::ops::*;
use lonca_core::{ChangeId, GitId};
use lonca_policy::chain::{Chain, Submission};
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
    policy: PolicyBundle,
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
            policy,
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
        let nonce = random_id("nonce");
        let issued_ms = self.now + 1;
        HumanSignature {
            human: name.into(),
            nonce: nonce.clone(),
            issued_ms,
            sig: key.sign_hex(&intent_bytes(REPO, op, &nonce, issued_ms)),
        }
    }

    fn submit(&mut self, sub: Submission) -> Decision {
        self.now += 1;
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
            },
            expires_ms: self.now + 120 * MIN,
        };
        let d = self.human("ayse", op);
        assert!(d.is_allow(), "{d:?}");
    }

    /// Start a session and bind it as observed by locked hooks + sandbox.
    fn start_observed(&mut self, session: &str, paths: &[&str]) {
        self.start(session, paths);
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

    /// Replays the whole log: chain integrity plus every decision.
    fn assert_replay(&self) {
        verify_chain(&self.log).expect("chain verifies");
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
        nonce: random_id("nonce"),
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
        nonce: random_id("nonce"),
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
    h.policy = strict;
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
    h.policy = strict;
    let d = h.human("ayse", Op::Freeze { reason: "x".into() });
    assert!(denied_with(&d, "presence_required"), "{d:?}");

    // A Secure Enclave (P-256) key satisfies it.
    use p256::ecdsa::signature::Signer;
    let sk = p256::ecdsa::SigningKey::from_slice(&[9u8; 32]).unwrap();
    let public = hex::encode(sk.verifying_key().to_sec1_point(false).as_bytes());
    h.policy = PolicyBundle::default_bundle();
    let enroll = Op::HumanEnroll {
        human: "cem".into(),
        key: HumanKey {
            alg: "p256-se".into(),
            public,
        },
    };
    assert!(h.human("ayse", enroll).is_allow());
    h.policy = PolicyBundle::parse(
        &DEFAULT_CONFIG.replace("require_presence = false", "require_presence = true"),
        DEFAULT_POLICY,
    )
    .unwrap();
    let op = Op::Freeze { reason: "y".into() };
    let nonce = random_id("nonce");
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
