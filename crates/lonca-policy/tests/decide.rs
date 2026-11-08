//! Scenario tests for the decision function. Every scenario ends by
//! replaying its log and checking that each recorded decision is reproduced.

use lonca_core::canonical::nonce;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{
    FORMAT_AFFECTED, FORMAT_CURRENT, FORMAT_GIVE_BACK, FORMAT_INSERT_NAMES, FORMAT_SYMBOL_KEYS,
    SignedOp, verify_chain,
};
use lonca_core::ops::*;
use lonca_core::{ChangeId, GitId};
use std::collections::BTreeSet;
use std::sync::Arc;

use lonca_policy::chain::{Chain, Submission, replay_checked};
use lonca_policy::config::{
    CVal, CedarOutcome, DEFAULT_CONFIG, DEFAULT_POLICY, PolicyBundle, Profile, Quota,
    UnparsedFiles, Verification,
};
use lonca_policy::decide::{Ctx, decide, evidence_problems, quota_problems, scope_within};
use lonca_policy::human::intent_bytes;
use lonca_policy::state::{ChangeStatus, Provenance, Renamed, State};

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
    /// The symbol engine proposals record.
    engine: u32,
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
            engine: 0,
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
            Op::ChangePropose { .. } | Op::ChangeIntegrate { .. } | Op::ChangeIntegrateBatch { .. }
        ) {
            sub.symbols_engine = Some(self.engine);
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
            harness: Some("claude-code".into()),
        }
    }

    /// Start a session and bind it as observed by locked hooks + sandbox.
    fn start_observed(&mut self, session: &str, paths: &[&str]) {
        self.start_observed_as("ayse", session, paths);
    }

    fn start_observed_as(&mut self, human: &str, session: &str, paths: &[&str]) {
        self.start_as(human, session, paths);
        self.bind_observed(session);
    }

    /// Binds a started session as observed by locked hooks + sandbox.
    fn bind_observed(&mut self, session: &str) {
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
                        names: Vec::new(),
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
                    symbols_engine: e.symbols_engine,
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
            checks: vec![],
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
            checks: vec![],
        },
    );
    assert!(denied_with(&d, "not_grantable:approve"));
    let d = h.human(
        "ayse",
        Op::Approve {
            target_seq: seq,
            note: "read it".into(),
            checks: vec![],
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
            checks: vec![],
        },
    );
    assert!(first.is_allow() && !first.reasons.contains(&"released".to_string()));
    assert!(denied_with(
        &h.human(
            "ayse",
            Op::Approve {
                target_seq: seq,
                note: String::new(),
                checks: vec![],
            }
        ),
        "already_approved"
    ));
    let second = h.human(
        "bora",
        Op::Approve {
            target_seq: seq,
            note: String::new(),
            checks: vec![],
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

/// The list of the hardened policy is what an agent can ever be granted,
/// plus the end of its own session; the rest is refused by no rule at all.
#[test]
fn a_hardened_policy_lists_what_agents_do_and_nothing_else() {
    let (config, policy) = Profile::Hardened.files(true);
    let hardened = PolicyBundle::parse(&config, &policy).unwrap();
    let agent = Actor::Agent {
        name: "a".into(),
        session: "s1".into(),
    };
    let human = Actor::Human {
        name: "ayse".into(),
    };
    // What a proposal is asked with; the rules read these.
    let allowed = |who: &Actor, action: &str| {
        let context = vec![
            ("path", CVal::Str("src/a.rs".into())),
            ("recent_reverts", CVal::Long(0)),
            ("files", CVal::Long(1)),
            ("lines", CVal::Long(1)),
        ];
        hardened.evaluate(who, action, context) == CedarOutcome::Allow
    };
    let kinds = [
        OpKind::RepoInit,
        OpKind::HumanEnroll,
        OpKind::HumanRotate,
        OpKind::HumanRevoke,
        OpKind::HumanRecoveryKey,
        OpKind::HumanRecover,
        OpKind::DaemonRotate,
        OpKind::DaemonRecover,
        OpKind::PolicyUpdate,
        OpKind::SessionStart,
        OpKind::SessionBind,
        OpKind::SessionIsolate,
        OpKind::SessionEnd,
        OpKind::CapAttenuate,
        OpKind::CapRevoke,
        OpKind::LeaseAcquire,
        OpKind::LeaseRelease,
        OpKind::LeaseRenew,
        OpKind::LeaseInterest,
        OpKind::ChangePropose,
        OpKind::ChangeWithdraw,
        OpKind::ChangeIntegrate,
        OpKind::ChangeIntegrateBatch,
        OpKind::Approve,
        OpKind::Reject,
        OpKind::Observe,
        OpKind::Taint,
        OpKind::ImportExternal,
        OpKind::ImportUnmediated,
        OpKind::BridgePush,
        OpKind::Freeze,
        OpKind::Unfreeze,
        OpKind::Negotiate,
        OpKind::Redact,
    ];
    for k in kinds {
        let own = matches!(k, OpKind::SessionEnd | OpKind::CapRevoke);
        let want = k.agent_grantable() || own;
        assert_eq!(allowed(&agent, k.as_str()), want, "{}", k.as_str());
        assert!(allowed(&human, k.as_str()), "{}", k.as_str());
    }
    for action in ["file.add", "file.modify", "file.delete"] {
        assert!(allowed(&agent, action), "{action}");
    }
    assert!(matches!(
        hardened.evaluate(&agent, "lonca.unlisted", vec![]),
        CedarOutcome::Deny(r) if r == ["policy_default_deny:lonca.unlisted"]
    ));
    assert!(
        PolicyBundle::default_bundle()
            .evaluate(&agent, "lonca.unlisted", vec![])
            .eq(&CedarOutcome::Allow)
    );
}

#[test]
fn an_agent_works_under_the_hardened_policy() {
    let (config, policy) = Profile::Hardened.files(false);
    let mut h = H::with_policy(PolicyBundle::parse(&config, &policy).unwrap());
    h.start_observed("s1", &["src/**"]);
    let sym = "src/billing.rs#Client.charge";
    h.wrote("s1", "src/billing.rs");
    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    let d = h.propose("s1", c, edit(sym));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
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
        checks: vec![],
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
        harness: None,
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

/// What a session left: counted by the fold, cleared by a proposal, set to
/// "nothing" by a clean report, and bounded in size.
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

    // A clean report is kept, not dropped: `None` would read as "never
    // reported" (#189). The count starts over.
    h.now += 5;
    unproposed(&mut h, "s1", vec![], 0);
    let m = mark(&h).unwrap();
    assert_eq!((m.paths.len(), m.total, m.rounds), (0, 0, 0));
    assert_eq!(m.seen_ms, h.now);
    unproposed(&mut h, "s1", vec![], 1);
    assert_eq!(mark(&h).unwrap().rounds, 1, "the count starts over");
    unproposed(&mut h, "s1", vec![], 0);
    unproposed(&mut h, "s1", vec![], 0);
    assert_eq!(mark(&h).unwrap().rounds, 0, "clean twice is still clean");

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
        symbols_engine: None,
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
    for bad in [
        "heartbeat_timeout_ms = 300000",
        "max_hold_minutes = 120",
        "interest_block_ms = 600000",
    ] {
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
                .replace("interest_block_ms = 600000", "interest_block_ms = 1")
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

// ----------------------------------------------- what a critical path costs

/// The shipped policy with the two words of issue #103.
fn critical_config(unobserved: &str, tainted: &str) -> String {
    DEFAULT_CONFIG
        .replace(
            "unobserved_critical = \"deny\"",
            &format!("unobserved_critical = \"{unobserved}\""),
        )
        .replace(
            "\ncritical = \"deny\"",
            &format!("\ncritical = \"{tainted}\""),
        )
}

fn critical_words(unobserved: &str, tainted: &str) -> PolicyBundle {
    PolicyBundle::parse(&critical_config(unobserved, tainted), DEFAULT_POLICY).unwrap()
}

/// A session, observed or not, that has leased Cargo.toml and may be tainted.
fn at_cargo_toml(policy: PolicyBundle, observed: bool, tainted: bool) -> H {
    let mut h = H::with_policy(policy);
    if observed {
        h.start_observed("s1", &["**"]);
        h.wrote("s1", "Cargo.toml");
    } else {
        h.start("s1", &["**"]);
    }
    let sym = "Cargo.toml#<file>";
    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
    if tainted {
        let taint = Op::Taint {
            session: "s1".into(),
            reason: "read the web".into(),
        };
        assert!(h.daemon(taint, vec![]).is_allow());
    }
    h
}

fn propose_cargo_toml(h: &mut H) -> (ChangeId, Decision) {
    let c = ChangeId::random();
    let d = h.propose("s1", c, edit("Cargo.toml#<file>"));
    (c, d)
}

#[test]
fn an_open_repository_lets_an_unobserved_critical_change_wait_for_a_human() {
    let mut h = at_cargo_toml(critical_words("escalate", "deny"), false, false);
    let (c, d) = propose_cargo_toml(&mut h);
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    for reason in ["critical_path:Cargo.toml", "unobserved_session"] {
        assert!(d.reasons.contains(&reason.to_string()), "{d:?}");
    }
    assert!(h.chain.state.queue.is_empty(), "nothing lands by itself");
    let ChangeStatus::Pending { seq } = h.chain.state.changes[&c].status else {
        panic!("{:?}", h.chain.state.changes[&c].status);
    };
    let approve = Op::Approve {
        target_seq: seq,
        note: "read it".into(),
        checks: vec![],
    };
    let d = h.human("ayse", approve);
    assert!(d.is_allow() && d.reasons.contains(&"released".to_string()));
    assert_eq!(h.chain.state.queue, vec![c]);
    assert_eq!(h.chain.state.changes[&c].provenance, Provenance::Reviewed);
    h.assert_replay();
}

#[test]
fn the_shipped_policy_denies_a_critical_path_to_both_kinds_of_session() {
    let mut h = at_cargo_toml(PolicyBundle::default_bundle(), false, false);
    let (_, d) = propose_cargo_toml(&mut h);
    assert!(denied_with(&d, "unobserved_critical_path"), "{d:?}");
    h.assert_replay();
    let mut h = at_cargo_toml(PolicyBundle::default_bundle(), true, true);
    let (_, d) = propose_cargo_toml(&mut h);
    assert!(denied_with(&d, "tainted_critical_path"), "{d:?}");
    h.assert_replay();
    // Words spelled out as the default mean the default.
    let mut h = at_cargo_toml(critical_words("deny", "deny"), false, false);
    assert!(denied_with(
        &propose_cargo_toml(&mut h).1,
        "unobserved_critical_path"
    ));
    h.assert_replay();
}

#[test]
fn opening_one_word_does_not_open_the_other() {
    // Tainted and observed: only the tainted word counts.
    let mut h = at_cargo_toml(critical_words("escalate", "deny"), true, true);
    assert!(denied_with(
        &propose_cargo_toml(&mut h).1,
        "tainted_critical_path"
    ));
    h.assert_replay();
    let mut h = at_cargo_toml(critical_words("deny", "escalate"), true, true);
    let (_, d) = propose_cargo_toml(&mut h);
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(d.reasons.contains(&"tainted_session".to_string()), "{d:?}");
    assert!(d.reasons.contains(&"critical_path:Cargo.toml".to_string()));
    h.assert_replay();

    // Unobserved and clean: only the unobserved word counts.
    let mut h = at_cargo_toml(critical_words("deny", "escalate"), false, false);
    assert!(denied_with(
        &propose_cargo_toml(&mut h).1,
        "unobserved_critical_path"
    ));
    h.assert_replay();

    // Both at once: each has to be open.
    let mut h = at_cargo_toml(critical_words("escalate", "deny"), false, true);
    assert!(denied_with(
        &propose_cargo_toml(&mut h).1,
        "tainted_critical_path"
    ));
    h.assert_replay();
    let mut h = at_cargo_toml(critical_words("deny", "escalate"), false, true);
    assert!(denied_with(
        &propose_cargo_toml(&mut h).1,
        "unobserved_critical_path"
    ));
    h.assert_replay();
    let mut h = at_cargo_toml(critical_words("escalate", "escalate"), false, true);
    assert_eq!(propose_cargo_toml(&mut h).1.outcome, Outcome::Escalate);
    h.assert_replay();
}

fn unhook(h: &mut H, session: &str, tool: &str) -> Decision {
    h.daemon(
        Op::Observe {
            session: session.into(),
            events: vec![Observation {
                phase: Phase::Pre,
                kind: ObsKind::Unhooked { tool: tool.into() },
                external: false,
            }],
        },
        vec![],
    )
}

/// A session whose hooks did not run (#190) is a tainted one with a word of
/// its own: the taint's setting decides a critical path, and its level drops
/// to unobserved for good.
#[test]
fn an_unhooked_session_is_tainted_and_says_why() {
    let mut h = at_cargo_toml(PolicyBundle::default_bundle(), true, false);
    assert_eq!(
        h.chain.state.sessions["s1"].level,
        ObservationLevel::HooksSandbox
    );
    let d = unhook(&mut h, "s1", "propose");
    assert!(d.is_allow(), "{d:?}");
    let s = &h.chain.state.sessions["s1"];
    assert_eq!(s.level, ObservationLevel::Unobserved);
    assert_eq!(
        s.taint.as_deref(),
        Some("unhooked: propose ran without its hook event")
    );
    let mark = s.unhooked.clone().unwrap();
    assert_eq!((mark.tool.as_str(), mark.seen_ms), ("propose", h.now));
    let (_, d) = propose_cargo_toml(&mut h);
    assert!(denied_with(&d, "unhooked_critical_path"), "{d:?}");
    assert!(!denied_with(&d, "tainted_critical_path"), "{d:?}");
    // The first mark stays.
    h.now += 5;
    assert!(unhook(&mut h, "s1", "status").is_allow());
    assert_eq!(h.chain.state.sessions["s1"].unhooked, Some(mark));
    h.assert_replay();

    // Both words open: a human decides, told why.
    let mut h = at_cargo_toml(critical_words("escalate", "escalate"), true, false);
    unhook(&mut h, "s1", "propose");
    let (_, d) = propose_cargo_toml(&mut h);
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(d.reasons.contains(&"unhooked_session".to_string()), "{d:?}");
    assert!(d.reasons.contains(&"critical_path:Cargo.toml".to_string()));
    for other in ["tainted_session", "unobserved_session"] {
        assert!(!d.reasons.contains(&other.to_string()), "{d:?}");
    }
    h.assert_replay();

    // Tainted before: the taint keeps its reason, the word is the mark's.
    let mut h = at_cargo_toml(PolicyBundle::default_bundle(), true, true);
    unhook(&mut h, "s1", "propose");
    let s = &h.chain.state.sessions["s1"];
    assert_eq!(s.taint.as_deref(), Some("read the web"));
    assert!(s.unhooked.is_some());
    assert!(denied_with(
        &propose_cargo_toml(&mut h).1,
        "unhooked_critical_path"
    ));
    h.assert_replay();

    // Only a session the log knows.
    let mut h = H::new();
    assert!(denied_with(
        &unhook(&mut h, "nobody", "propose"),
        "unknown_session"
    ));
}

/// The daemon sends no mark for a sandbox; one in the log leaves the level.
#[test]
fn a_mark_does_not_lower_an_isolated_session() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    assert!(h.human("ayse", isolate("s1")).is_allow());
    assert!(unhook(&mut h, "s1", "propose").is_allow());
    let s = &h.chain.state.sessions["s1"];
    assert_eq!(s.level, ObservationLevel::Isolated);
    assert!(s.unhooked.is_some() && s.taint.is_some());
    h.assert_replay();
}

/// An observed, clean session pays only the human's review, whatever the
/// words say: they are about sessions nobody fully observes.
#[test]
fn the_words_change_nothing_for_an_observed_clean_session() {
    let mut h = at_cargo_toml(critical_words("deny", "deny"), true, false);
    let (_, d) = propose_cargo_toml(&mut h);
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(!d.reasons.contains(&"unobserved_session".to_string()));
    h.assert_replay();
}

#[test]
fn a_word_nobody_defined_is_refused_when_the_policy_is_read() {
    for (unobserved, tainted, key) in [
        ("open", "deny", "observation.unobserved_critical"),
        ("deny", "allow", "taint.critical"),
        ("", "deny", "observation.unobserved_critical"),
        ("Escalate", "deny", "observation.unobserved_critical"),
    ] {
        let config = critical_config(unobserved, tainted);
        let e = PolicyBundle::parse(&config, DEFAULT_POLICY).err().unwrap();
        assert!(
            e.contains(&format!("{key} must be deny or escalate")),
            "{e}"
        );
    }
}

// -------------------------------------------------------- the lease queue

fn interest(h: &mut H, session: &str, sym: &str) -> Decision {
    let op = Op::LeaseInterest {
        items: vec![LeaseItem {
            symbol: sym.into(),
            kind: LeaseKind::Edit,
            names: Vec::new(),
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
                kind: LeaseKind::Edit,
                names: Vec::new()
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

const TYPE: &str = "src/a.rs#Type";
const MEMBER_A: &str = "src/a.rs#Type.a";
const MEMBER_B: &str = "src/a.rs#Type.b";

fn acquire_intent(set: &str, sym: &str, intent: &str) -> Op {
    Op::LeaseAcquire {
        set: set.into(),
        items: vec![LeaseItem {
            symbol: sym.into(),
            kind: LeaseKind::Edit,
            names: Vec::new(),
        }],
        intent: intent.into(),
        ttl_ms: 10 * MIN,
    }
}

/// a holds one member, b waits for the whole type.
fn wide_interest() -> H {
    let mut h = three_sessions();
    assert!(
        h.lease("a", "l1", &[(MEMBER_A, LeaseKind::Edit)])
            .is_allow()
    );
    assert!(interest(&mut h, "b", TYPE).is_allow());
    h
}

/// Whoever holds a lease on something says why, so the agent it stops can
/// read it.
#[test]
fn a_lease_and_an_interest_need_an_intent() {
    let mut h = three_sessions();
    for empty in ["", " \n\t"] {
        let d = h.agent("a", acquire_intent("l1", F, empty));
        assert!(denied_with(&d, "intent_required"), "{d:?}");
    }
    assert!(h.agent("a", acquire_intent("l1", F, "x")).is_allow());
    let empty = Op::LeaseInterest {
        items: vec![LeaseItem {
            symbol: F.into(),
            kind: LeaseKind::Edit,
            names: Vec::new(),
        }],
        intent: " ".into(),
    };
    let d = h.agent("b", empty);
    assert!(denied_with(&d, "intent_required"), "{d:?}");
    h.assert_replay();
}

/// The hole this closes: small leases kept coming while a wide change
/// waited, and the wide change never got its turn.
#[test]
fn a_waiting_interest_stops_new_leases_that_conflict_with_it() {
    let mut h = wide_interest();
    let d = h.lease("c", "l2", &[(MEMBER_B, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_wanted:b"), "{d:?}");
    assert_eq!(d.reasons.len(), 1, "{d:?}");
    let d = h.lease("c", "l2", &[(TYPE, LeaseKind::Insert)]);
    assert!(denied_with(&d, "lease_wanted:b"), "{d:?}");
    // The one in its way too: it has what it has, and no more.
    let d = h.lease("a", "l2", &[(MEMBER_B, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_wanted:b"), "{d:?}");
    // The waiter is not stopped by itself, only by what is held.
    assert!(
        h.lease("b", "l3", &[(MEMBER_B, LeaseKind::Edit)])
            .is_allow()
    );
    assert_eq!(h.chain.state.interests.len(), 1, "b keeps its place");
    let d = interest(&mut h, "b", TYPE);
    assert!(denied_with(&d, "interest_exists"), "{d:?}");
    let other = [("src/a.rs#Other.a", LeaseKind::Edit)];
    assert!(h.lease("c", "l4", &other).is_allow());
    h.assert_replay();
}

/// The cap is per set: however many sessions take turns waiting, in a relay
/// or a stack, nobody is stopped longer than the first one stopped them.
#[test]
fn a_line_of_interests_does_not_stretch_the_cap() {
    let mut h = wide_interest();
    let since = h.log.last().unwrap().entry.time_ms;
    let until = since + 600_000;
    h.now = since + 5 * MIN;
    assert!(h.agent("a", renew("l1", 10 * MIN)).is_allow());
    assert!(interest(&mut h, "c", "src/a.rs#<file>").is_allow());
    let ends = |h: &H| -> Vec<i64> {
        let i = h.chain.state.interests.values();
        i.map(|i| i.blocks_until_ms).collect()
    };
    assert_eq!(ends(&h), [until, until]);
    assert_eq!(h.chain.state.leases["l1"].stop_until_ms, Some(until));
    // The set remembers it when those who waited are gone.
    for s in ["b", "c"] {
        let end = Op::SessionEnd {
            session: s.into(),
            reason: "done".into(),
        };
        assert!(h.human("ayse", end).is_allow());
    }
    h.start("d", &["src/**"]);
    assert!(interest(&mut h, "d", TYPE).is_allow());
    assert_eq!(ends(&h), [until]);
    h.assert_replay();
}

/// The first interest in a set: its own time, and the set takes it.
#[test]
fn an_interest_with_nothing_ahead_gets_the_whole_cap() {
    let mut h = wide_interest();
    let since = h.log.last().unwrap().entry.time_ms;
    assert!(
        h.lease("c", "l2", &[("src/b.rs#g", LeaseKind::Edit)])
            .is_allow()
    );
    h.now = since + 5 * MIN;
    assert!(interest(&mut h, "a", "src/b.rs#g").is_allow());
    let time = h.log.last().unwrap().entry.time_ms;
    assert_eq!(
        h.chain.state.leases["l2"].stop_until_ms,
        Some(time + 600_000)
    );
    h.assert_replay();
}

/// The older interest goes first, whatever the younger one asks for.
#[test]
fn a_younger_interest_does_not_stop_an_older_one() {
    let mut h = wide_interest();
    assert!(interest(&mut h, "c", "src/a.rs#<file>").is_allow());
    let b_goes_on = [(MEMBER_B, LeaseKind::Edit)];
    assert!(h.lease("b", "l2", &b_goes_on).is_allow());
    let d = h.lease("c", "l3", &[("src/a.rs#Type.c", LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_wanted:b"), "{d:?}");
    // Older in something else gives no place in this line.
    let d = h.lease("a", "l3", &[("src/a.rs#Other.a", LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_wanted:c"), "{d:?}");
    h.assert_replay();
}

/// A new set over what is held stays wanted, as it stays held: a fresh id
/// gets past neither the hold limit nor the cap.
#[test]
fn a_new_set_over_what_is_held_stays_wanted() {
    let mut h = wide_interest();
    let until = h.chain.state.leases["l1"].stop_until_ms;
    assert!(until.is_some());
    assert!(
        h.lease("a", "l2", &[(MEMBER_A, LeaseKind::Edit)])
            .is_allow()
    );
    assert!(h.agent("a", release("l1")).is_allow());
    let l = &h.chain.state.leases["l2"];
    assert!(l.interest.contains_key("b"), "{l:?}");
    assert_eq!(l.stop_until_ms, until);
    h.assert_replay();
    // A set of its own, with nothing in common, starts clean.
    let other = [("src/b.rs#g", LeaseKind::Edit)];
    assert!(h.lease("a", "l3", &other).is_allow());
    let l = &h.chain.state.leases["l3"];
    assert!(l.interest.is_empty() && l.stop_until_ms.is_none(), "{l:?}");
    // In an older format the new set started clean, and replays so.
    let mut old = h.log.clone();
    for o in &mut old {
        o.entry.format = 11;
        o.entry
            .decision
            .reasons
            .retain(|r| !r.starts_with("interest_block_ms="));
    }
    let s = State::replay(&old);
    assert!(s.leases["l2"].interest.is_empty());
}

/// `lease_needed` says what an acquire would say.
#[test]
fn a_stopped_lease_is_not_reported_free() {
    let h = wide_interest();
    let t = h.now + 1;
    let state = &h.chain.state;
    let report =
        lonca_policy::details::lease_report(state, "c", &edit(MEMBER_B), UnparsedFiles::File, t);
    assert_eq!(report.len(), 1, "{report:?}");
    assert_eq!(report[0].code, "lease_wanted");
    assert_eq!(report[0].symbol, TYPE);
    assert_eq!(lonca_policy::details::to_acquire(&report), []);
    let missing =
        lonca_policy::details::lease_missing(state, "c", &edit(MEMBER_B), UnparsedFiles::File, t);
    assert_eq!(missing[0].code, "lease_wanted");
    let held =
        lonca_policy::details::lease_missing(state, "c", &edit(MEMBER_A), UnparsedFiles::File, t);
    let codes: Vec<&str> = held.iter().map(|d| d.code).collect();
    assert_eq!(codes, ["lease_missing", "lease_wanted"], "{held:?}");
}

/// The right to stop others has a time cap, from the interest's own entry:
/// a waiter that never gets its turn does not stop a file for good.
#[test]
fn an_interest_stops_others_for_a_limited_time_and_stays_in_line() {
    let mut h = wide_interest();
    let since = h.log.last().unwrap().entry.time_ms;
    let reasons = &h.log.last().unwrap().entry.decision.reasons;
    assert_eq!(
        reasons,
        &["reservation_ms=60000", "interest_block_ms=600000"]
    );
    let until = since + 600_000;
    assert_eq!(
        h.chain
            .state
            .interests
            .values()
            .next()
            .unwrap()
            .blocks_until_ms,
        until
    );

    // a stays on it, so b goes on waiting.
    h.now = since + 5 * MIN;
    assert!(h.agent("a", renew("l1", 10 * MIN)).is_allow());
    h.now = until - 2;
    let d = h.lease("c", "l2", &[(MEMBER_B, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_wanted:b"), "{d:?}");
    assert_eq!(h.log.last().unwrap().entry.time_ms, until - 1);
    // The next entry is at `until`.
    assert!(
        h.lease("c", "l2", &[(MEMBER_B, LeaseKind::Edit)])
            .is_allow()
    );
    assert_eq!(h.log.last().unwrap().entry.time_ms, until);
    assert_eq!(h.chain.state.interests.len(), 1, "still in line");
    h.assert_replay();
}

#[test]
fn an_interest_of_a_session_that_ended_stops_nobody() {
    let mut h = wide_interest();
    assert!(
        h.human(
            "ayse",
            Op::SessionEnd {
                session: "b".into(),
                reason: "done".into(),
            }
        )
        .is_allow()
    );
    assert!(
        h.lease("c", "l2", &[(MEMBER_B, LeaseKind::Edit)])
            .is_allow()
    );
    h.assert_replay();
}

/// What the session already has is no new lease: `lease_release` with items
/// acquires the rest under a new set first.
#[test]
fn a_partial_release_is_not_stopped_by_an_interest() {
    let mut h = three_sessions();
    let both = [(MEMBER_A, LeaseKind::Edit), (MEMBER_B, LeaseKind::Edit)];
    assert!(h.lease("a", "l1", &both).is_allow());
    assert!(interest(&mut h, "b", TYPE).is_allow());
    assert!(
        h.lease("a", "l2", &[(MEMBER_A, LeaseKind::Edit)])
            .is_allow()
    );
    h.assert_replay();
}

/// A reservation is a turn: a younger interest in the same symbol does not
/// take it back. Inside a wider reservation the same; outside it, the
/// younger interest counts.
#[test]
fn a_reservation_is_not_stopped_by_a_younger_interest() {
    let mut h = wide_interest();
    assert!(interest(&mut h, "c", TYPE).is_allow());
    assert!(h.agent("a", release("l1")).is_allow());
    // An entry opens b's window, and its interest has become a reservation.
    let other = [("src/b.rs#g", LeaseKind::Edit)];
    assert!(h.lease("a", "l9", &other).is_allow());
    assert_eq!(h.chain.state.reservations[0].session, "b");
    let beyond = [("src/a.rs#<file>", LeaseKind::Edit)];
    let d = h.lease("b", "l2", &beyond);
    assert!(denied_with(&d, "lease_wanted:c"), "{d:?}");
    assert!(
        h.lease("b", "l2", &[(MEMBER_A, LeaseKind::Edit)])
            .is_allow()
    );
    h.assert_replay();
}

/// In line behind a wide interest: there is something to wait for, and the
/// wide one goes first until its time is over.
#[test]
fn an_interest_lines_up_behind_a_wide_one() {
    let mut h = wide_interest();
    let since = h.log.last().unwrap().entry.time_ms;
    assert!(interest(&mut h, "c", MEMBER_B).is_allow());
    assert!(h.chain.state.reservations.is_empty());
    let d = interest(&mut h, "c", "src/a.rs#Other.a");
    assert!(denied_with(&d, "lease_free"), "{d:?}");
    // Nobody holds what c waits for, and a new entry serves it only once
    // b no longer goes first.
    h.now = since + 5 * MIN;
    assert!(h.agent("a", renew("l1", 10 * MIN)).is_allow());
    h.now = since + 600_000 - 2;
    assert!(h.agent("a", renew("l1", 10 * MIN)).is_allow());
    assert_eq!(h.log.last().unwrap().entry.time_ms, since + 600_000 - 1);
    assert!(h.chain.state.reservations.is_empty(), "b goes first");
    assert!(h.agent("a", renew("l1", 10 * MIN)).is_allow());
    assert_eq!(h.log.last().unwrap().entry.time_ms, since + 600_000);
    assert_eq!(h.chain.state.reservations[0].session, "c");
    h.assert_replay();
}

/// A denial by a holder and by a waiter still counts as wanting the holder's
/// set, for the hold limit.
#[test]
fn a_denial_by_a_holder_and_a_waiter_counts_for_the_hold_limit() {
    let mut h = wide_interest();
    let both = [(MEMBER_A, LeaseKind::Edit), (MEMBER_B, LeaseKind::Edit)];
    let d = h.lease("c", "l2", &both);
    assert!(denied_with(&d, "lease_held:"), "{d:?}");
    assert!(denied_with(&d, "lease_wanted:b"), "{d:?}");
    assert!(h.chain.state.leases["l1"].interest.contains_key("c"));
    h.assert_replay();
}

/// Entries of format 11 mean what they meant: no intent needed, and an
/// interest stops nobody.
#[test]
fn entries_of_an_older_format_need_no_intent_and_stop_nobody() {
    let h = wide_interest();
    let mut old = h.log.clone();
    for o in &mut old {
        o.entry.format = 11;
        o.entry
            .decision
            .reasons
            .retain(|r| !r.starts_with("interest_block_ms="));
    }
    let s = State::replay(&old);
    let i = s.interests.values().next().unwrap();
    assert_eq!(i.blocks_until_ms, 0);
    assert_eq!(i.window_ms, 60_000);

    let bundle = PolicyBundle::default_bundle();
    let t = h.now + 1;
    let ctx = |format| Ctx {
        format,
        time_ms: t,
        policy: &bundle,
        facts: None,
        evidence: &[],
        symbols_engine: None,
    };
    let actor = Actor::Agent {
        name: "bot-c".into(),
        session: "c".into(),
    };
    let op = acquire_intent("l2", MEMBER_B, "");
    let d = decide(&s, &actor, &op, None, &ctx(12));
    assert!(denied_with(&d, "intent_required"), "{d:?}");
    assert!(decide(&s, &actor, &op, None, &ctx(11)).is_allow());
    let op = Op::LeaseInterest {
        items: vec![LeaseItem {
            symbol: MEMBER_A.into(),
            kind: LeaseKind::Edit,
            names: Vec::new(),
        }],
        intent: "w".into(),
    };
    let d = decide(&s, &actor, &op, None, &ctx(11));
    assert_eq!(d.reasons, ["reservation_ms=60000"]);
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
            names: Vec::new(),
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

/// A child whose time runs out gives a delegated set back as one that ends
/// does (log format 23): the parent holds it at once, before any entry
/// moves it, and keeps the time it had.
#[test]
fn a_delegated_lease_comes_back_when_the_child_expires() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.agent("a", renew("l1", 30 * MIN)).is_allow());
    let until = h.chain.state.leases["l1"].expires_ms;
    assert!(h.agent("a", child_op(&h, "a", "kid", &["l1"])).is_allow());
    // `child_op` gives the child ten minutes; the next entry is just past.
    h.now += 10 * MIN - 1;
    assert_eq!(
        h.chain.state.leases["l1"].session, "kid",
        "nothing moved yet"
    );
    let d = h.lease("b", "lb", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{F}:a:")), "{d:?}");
    let l = &h.chain.state.leases["l1"];
    assert_eq!(l.session, "a");
    assert_eq!((l.delegated_from.as_deref(), l.expires_ms), (None, until));
    assert_eq!(held(&h, "a"), [F]);
    let d = h.agent("kid", renew("l1", 10 * MIN));
    assert!(denied_with(&d, "session_inactive"), "{d:?}");
    assert!(h.agent("a", renew("l1", 10 * MIN)).is_allow());
    h.assert_replay();
}

/// The parent may renew or release what its expired child had at the first
/// entry after, when the set still names the child.
#[test]
fn the_parent_acts_on_a_set_of_an_expired_child_before_it_moves() {
    for op in [renew("l1", 10 * MIN), release("l1")] {
        let mut h = three_sessions();
        assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
        assert!(h.agent("a", renew("l1", 30 * MIN)).is_allow());
        assert!(h.agent("a", child_op(&h, "a", "kid", &["l1"])).is_allow());
        h.now += 10 * MIN - 1;
        assert_eq!(h.chain.state.leases["l1"].session, "kid");
        let d = h.agent("a", op.clone());
        assert!(d.is_allow(), "{op:?}: {d:?}");
        h.assert_replay();
    }
}

/// A child that stops beating gives a delegated set back too.
#[test]
fn a_delegated_lease_comes_back_when_the_child_stops_beating() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.agent("a", child_op(&h, "a", "kid", &["l1"])).is_allow());
    assert!(heartbeat(&mut h, "kid").is_allow());
    let d = h.lease("b", "lb", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{F}:kid:")), "{d:?}");
    // The default heartbeat timeout is five minutes.
    h.now += 5 * MIN + 1;
    let d = h.lease("b", "lb", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{F}:a:")), "{d:?}");
    assert_eq!(h.chain.state.leases["l1"].session, "a");
    h.assert_replay();
}

/// A parent that is gone too has nothing to take back: the set ends.
#[test]
fn a_delegated_lease_ends_when_the_parent_is_gone_too() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.agent("a", child_op(&h, "a", "kid", &["l1"])).is_allow());
    assert!(heartbeat(&mut h, "a").is_allow());
    assert!(heartbeat(&mut h, "kid").is_allow());
    h.now += 5 * MIN + 1;
    let d = h.lease("b", "lb", &[(F, LeaseKind::Edit)]);
    assert!(d.is_allow(), "{d:?}");
    assert!(!h.chain.state.leases.contains_key("l1"));
    h.assert_replay();
}

/// Before format 23 a set of an expired child ended with it. Replaying the
/// entries as format 22 keeps that decision.
#[test]
fn before_the_format_an_expired_child_takes_its_lease_with_it() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.agent("a", renew("l1", 30 * MIN)).is_allow());
    assert!(h.agent("a", child_op(&h, "a", "kid", &["l1"])).is_allow());
    assert!(h.chain.state.gives_back);
    let mut old = h.log.clone();
    for o in &mut old {
        assert_eq!(o.entry.format, FORMAT_CURRENT);
        o.entry.format = FORMAT_GIVE_BACK - 1;
    }
    let s = State::replay(&old);
    assert!(!s.gives_back);
    let t = h.now + 10 * MIN;
    let bundle = PolicyBundle::default_bundle();
    let ctx = |format| Ctx {
        format,
        time_ms: t,
        policy: &bundle,
        facts: None,
        evidence: &[],
        symbols_engine: None,
    };
    let actor = Actor::Agent {
        name: "bot-b".into(),
        session: "b".into(),
    };
    let op = Op::LeaseAcquire {
        set: "lb".into(),
        items: vec![item(F)],
        intent: "take".into(),
        ttl_ms: 10 * MIN,
    };
    let old_format = FORMAT_GIVE_BACK - 1;
    assert!(decide(&s, &actor, &op, None, &ctx(old_format)).is_allow());
    let now = decide(&h.chain.state, &actor, &op, None, &ctx(FORMAT_CURRENT));
    assert!(denied_with(&now, &format!("lease_held:{F}:a:")), "{now:?}");
    assert_eq!(h.chain.state.holder(&s.leases["l1"], t), "a");
    assert_eq!(s.holder(&s.leases["l1"], t), "kid");
}

fn acquire_for(h: &mut H, set: &str, ttl_ms: i64) -> Decision {
    let op = Op::LeaseAcquire {
        set: set.into(),
        items: vec![LeaseItem {
            symbol: F.into(),
            kind: LeaseKind::Edit,
            names: Vec::new(),
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

    let events = |h: &H, s: &str| for_session(&h.chain.state, s, &h.log, 0, h.now);
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
    let got = for_session(&h.chain.state, "b", &h.log, 0, h.now);
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
                message: NegotiationMsg::Yield {
                    set: "l1".into(),
                    to: Some("b".into()),
                },
            },
        ]
    );
    let op = child_op(&h, "b", "kid", &["l1"]);
    assert!(h.agent("b", op).is_allow());
    let seq = h.log.last().unwrap().entry.seq;
    assert_eq!(
        for_session(&h.chain.state, "kid", &h.log, 0, h.now),
        [Event::LeaseReceived {
            seq,
            set: "l1".into(),
            from: Some("b".into()),
        }]
    );
    // From the middle of the log, the sequence numbers stay right.
    assert_eq!(for_session(&h.chain.state, "b", &h.log, seq, h.now), []);
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

/// A session that saw a symbol alone has it by its name, one that sees
/// others of that name has it by its key: the same symbol, one holder.
#[test]
fn a_name_stands_for_every_symbol_of_that_name() {
    let mut h = H::new();
    h.start("old-base", &["src/**"]);
    h.start("trunk", &["src/**"]);
    let (name, one, other) = ("src/a.cs#C.M", "src/a.cs#C.M(int)", "src/a.cs#C.M(string)");
    assert!(
        h.lease("old-base", "l1", &[(name, LeaseKind::Edit)])
            .is_allow()
    );
    for keyed in [one, other] {
        let d = h.lease("trunk", "l2", &[(keyed, LeaseKind::Edit)]);
        assert!(
            denied_with(&d, &format!("lease_held:{name}:old-base:")),
            "{d:?}"
        );
    }
    assert!(h.agent("old-base", release("l1")).is_allow());
    assert!(h.lease("trunk", "l3", &[(one, LeaseKind::Edit)]).is_allow());
    let d = h.lease("old-base", "l4", &[(name, LeaseKind::Edit)]);
    assert!(
        denied_with(&d, &format!("lease_held:{one}:trunk:")),
        "{d:?}"
    );
    assert!(
        h.lease("old-base", "l5", &[(other, LeaseKind::Edit)])
            .is_allow()
    );
    h.assert_replay();
}

/// A lease by the name reaches a keyed fact, and a key reaches only its own.
#[test]
fn a_keyed_fact_is_covered_by_its_name() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let (name, one, other) = ("src/a.cs#C.M", "src/a.cs#C.M(int)", "src/a.cs#C.M(string)");
    assert!(h.lease("a", "l1", &[(one, LeaseKind::Edit)]).is_allow());
    h.wrote("a", "src/a.cs");
    let d = h.propose("a", ChangeId::random(), edit(other));
    assert!(denied_with(&d, &format!("lease_missing:{other}")), "{d:?}");
    assert!(h.lease("a", "l2", &[(name, LeaseKind::Edit)]).is_allow());
    let d = h.propose("a", ChangeId::random(), edit(other));
    assert!(!denied_with(&d, "lease_missing"), "{d:?}");
    h.assert_replay();
}

/// Scopes go by the name: who may change a name may change each symbol of
/// it, and a key in a scope reaches that symbol only.
#[test]
fn a_scope_on_a_name_reaches_its_keyed_symbols() {
    let mut h = H::new();
    let one = "src/a.cs#C.M(int)";
    let inner = "src/a.rs#S.From(u8).from";
    start_with_symbols(&mut h, "name", &["C.M", "S.From.from"]);
    assert!(h.lease("name", "l1", &[(one, LeaseKind::Edit)]).is_allow());
    assert!(
        h.lease("name", "l2", &[(inner, LeaseKind::Edit)])
            .is_allow()
    );
    h.wrote("name", "src/a.cs");
    let d = h.propose("name", ChangeId::random(), edit(one));
    assert!(!denied_with(&d, "scope_symbol"), "{d:?}");

    start_with_symbols(&mut h, "key", &["C.M(int)"]);
    let (other, wide) = ("src/a.cs#C.M(string)", "src/a.cs#C.M");
    for symbol in [other, wide] {
        let d = h.lease("key", "l3", &[(symbol, LeaseKind::Edit)]);
        assert!(denied_with(&d, &format!("scope_symbol:{symbol}")), "{d:?}");
    }
    h.wrote("key", "src/b.cs");
    let d = h.propose("key", ChangeId::random(), edit("src/b.cs#C.M(string)"));
    assert!(
        denied_with(&d, "scope_symbol:src/b.cs#C.M(string)"),
        "{d:?}"
    );
    let d = h.propose("key", ChangeId::random(), edit("src/b.cs#C.M(int)"));
    assert!(!denied_with(&d, "scope_symbol"), "{d:?}");
    h.assert_replay();
}

/// An insert into a name meets a lease on one of its symbols, as it does on
/// that symbol's own name.
#[test]
fn an_insert_into_a_name_meets_its_keyed_symbols() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.start("b", &["src/**"]);
    let held = "src/a.rs#S.From(u8)";
    assert!(h.lease("a", "l1", &[(held, LeaseKind::Edit)]).is_allow());
    for wide in ["src/a.rs#S.From", held] {
        let d = h.lease("b", "l2", &[(wide, LeaseKind::Insert)]);
        assert!(denied_with(&d, &format!("lease_held:{held}:a:")), "{d:?}");
    }
    let other = "src/a.rs#S.From(u16)";
    assert!(h.lease("b", "l3", &[(other, LeaseKind::Insert)]).is_allow());
    assert!(h.agent("a", release("l1")).is_allow());
    assert!(
        h.lease("a", "l4", &[("src/a.rs#S.From", LeaseKind::Insert)])
            .is_allow()
    );
    let d = h.lease("b", "l5", &[(held, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_held:src/a.rs#S.From:a:"), "{d:?}");
    h.assert_replay();
}

/// In a document a `(` is part of the heading.
#[test]
fn a_heading_is_not_a_name_with_a_key() {
    let mut h = H::new();
    start_with_symbols(&mut h, "doc", &["Setup"]);
    let heading = "docs/a.md#Setup(old)";
    h.start("other", &["docs/**"]);
    let op = h.start_op("scoped", &["docs/**"], None);
    let mut op = op;
    if let Op::SessionStart { scope, .. } = &mut op {
        scope.symbols = Some(vec!["Setup".into()]);
    }
    assert!(h.human("ayse", op).is_allow());
    let d = h.lease("scoped", "l1", &[(heading, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("scope_symbol:{heading}")), "{d:?}");
    let d = h.lease("other", "l2", &[(heading, LeaseKind::Edit)]);
    assert!(d.is_allow(), "{d:?}");
    let name = ("docs/a.md#Setup", LeaseKind::Edit);
    assert!(h.lease("scoped", "l3", &[name]).is_allow(), "two headings");
    h.wrote("scoped", "docs/a.md");
    let d = h.propose("scoped", ChangeId::random(), edit(heading));
    assert!(denied_with(&d, &format!("scope_symbol:{heading}")), "{d:?}");
    h.assert_replay();
}

/// What was reverted by a name counts for its keyed symbols and the other
/// way around, and not for another overload. The state is written by hand,
/// so this one does not replay.
#[test]
fn a_revert_of_a_name_counts_for_its_keyed_symbols() {
    let storm_since = |ago: i64, reverted: &str, edited: &str, keys: bool| {
        let mut h = H::new();
        h.start("a", &["src/**"]);
        assert!(h.lease("a", "l", &[(edited, LeaseKind::Edit)]).is_allow());
        h.wrote("a", "src/a.cs");
        let at = h.now - ago;
        h.chain.state.symbol_keys = keys;
        h.chain.state.reverts = vec![(at, vec![reverted.to_string()]); 3];
        let d = h.propose("a", ChangeId::random(), edit(edited));
        d.reasons.iter().any(|r| r.contains("revert-storm"))
    };
    let storm = |reverted: &str, edited: &str, keys: bool| storm_since(0, reverted, edited, keys);
    let (name, one) = ("src/a.cs#C.M", "src/a.cs#C.M(int)");
    assert!(storm(one, one, true));
    assert!(storm(name, one, true));
    assert!(storm(one, name, true));
    assert!(!storm("src/a.cs#C.M(string)", one, true));
    assert!(!storm(name, one, false));
    assert!(!storm(one, name, false));
    // The default window is five minutes.
    assert!(storm_since(4 * MIN, one, one, true));
    assert!(!storm_since(6 * MIN, one, one, true));
}

/// A revert follows the symbol: it counts under the old name and the new.
#[test]
fn a_revert_counts_by_either_name() {
    let storm = |reverted: &str, edited: &str| {
        let mut h = H::new();
        h.start("a", &["src/**"]);
        assert!(h.lease("a", "l", &[(edited, LeaseKind::Edit)]).is_allow());
        h.wrote("a", "src/a.py");
        let at = h.now;
        h.chain.state.renames = vec![renamed(1, "src/a.py#old", "src/a.py#new", None)];
        h.chain.state.reverts = vec![(at, vec![reverted.to_string()]); 3];
        let d = h.propose("a", ChangeId::random(), edit(edited));
        d.reasons.iter().any(|r| r.contains("revert-storm"))
    };
    assert!(storm("src/a.py#old", "src/a.py#new"));
    assert!(storm("src/a.py#old", "src/a.py#old"));
    assert!(!storm("src/a.py#other", "src/a.py#new"));
}

/// `context.critical` says what it says.
#[test]
fn a_policy_reads_whether_a_change_is_critical() {
    let rule = r#"
@id("no-critical")
forbid(principal is Lonca::Agent, action == Lonca::Action::"change.propose", resource)
when { context.critical };
"#;
    let source = format!("{DEFAULT_POLICY}\n{rule}");
    for (path, denied) in [("src/a.rs", false), (".github/workflows/x.yml", true)] {
        let policy = PolicyBundle::parse(DEFAULT_CONFIG, &source).unwrap();
        let mut h = H::with_policy(policy);
        h.start("a", &["**"]);
        let symbol = format!("{path}#<file>");
        let lease = [(symbol.as_str(), LeaseKind::Edit)];
        assert!(h.lease("a", "l", &lease).is_allow());
        h.wrote("a", path);
        let d = h.propose("a", ChangeId::random(), edit(&symbol));
        assert_eq!(
            denied_with(&d, "policy:no-critical"),
            denied,
            "{path}: {d:?}"
        );
    }
}

/// A rule that names a symbol goes on working when it gets a key.
#[test]
fn a_policy_on_a_name_reaches_its_keyed_symbols() {
    let rule = r#"
@id("no-charge")
forbid(principal is Lonca::Agent, action == Lonca::Action::"change.propose", resource)
when { context.symbols.contains("src/a.cs#C.M") };
"#;
    let source = format!("{DEFAULT_POLICY}\n{rule}");
    for (symbol, denied) in [("src/a.cs#C.M(int)", true), ("src/a.cs#C.N(int)", false)] {
        let policy = PolicyBundle::parse(DEFAULT_CONFIG, &source).unwrap();
        let mut h = H::with_policy(policy);
        h.start("a", &["src/**"]);
        assert!(h.lease("a", "l", &[(symbol, LeaseKind::Edit)]).is_allow());
        h.wrote("a", "src/a.cs");
        let d = h.propose("a", ChangeId::random(), edit(symbol));
        assert_eq!(denied_with(&d, "policy:no-charge"), denied, "{d:?}");
        h.assert_replay();
    }
}

fn renamed(line: usize, old: &str, new: &str, reused: Option<usize>) -> Renamed {
    Renamed {
        line,
        old: old.into(),
        new: new.into(),
        reused,
    }
}

/// What a symbol is called now, from a state written by hand.
#[test]
fn a_name_follows_its_renames() {
    let (first, second) = (gid('1'), gid('2'));
    let mut s = State::new();
    s.trunk_line = vec![gid('0'), first.clone(), second.clone()];
    s.renames = vec![
        renamed(1, "a#m", "a#n", None),
        renamed(2, "a#n", "a#o", None),
        renamed(2, "a#T", "a#U", None),
        renamed(1, "a#gone", "a#kept", Some(2)),
    ];
    assert_eq!(s.renamed_to("a#m", None), "a#o", "a chain");
    assert_eq!(s.renamed_to("a#T.x", None), "a#U.x", "a member");
    assert_eq!(s.renamed_to("a#T", None), "a#U");
    assert_eq!(s.renamed_to("a#Tx", None), "a#Tx", "a longer name");
    assert_eq!(s.renamed_to("a#z", None), "a#z");
    assert_eq!(s.renamed_to("a#gone", None), "a#gone", "the name is taken");

    let old_base = gid('0');
    assert_eq!(
        s.renamed_to("a#gone", Some(&old_base)),
        "a#gone",
        "and stays so"
    );
    assert_eq!(
        s.renamed_to("a#m", Some(&old_base)),
        "a#o",
        "both are later"
    );
    assert_eq!(s.renamed_to("a#m", Some(&first)), "a#m", "that base had it");
    assert_eq!(s.renamed_to("a#n", Some(&first)), "a#o");
    assert_eq!(s.renamed_to("a#n", Some(&second)), "a#n");
}

/// a to b to c, and then a new `b`: `a` is on its way to `c`, `b` is new.
#[test]
fn a_chain_goes_on_past_a_name_taken_again() {
    let mut s = State::new();
    s.renames = vec![
        renamed(1, "a#a", "a#b", None),
        renamed(2, "a#b", "a#c", Some(3)),
    ];
    assert_eq!(s.renamed_to("a#a", None), "a#c");
    assert_eq!(s.renamed_to("a#b", None), "a#b");
}

fn item(symbol: &str) -> LeaseItem {
    LeaseItem {
        symbol: symbol.into(),
        kind: LeaseKind::Edit,
        names: Vec::new(),
    }
}

/// Taken twice: a name that went on as `d` and was taken again says nothing
/// of the symbol that took it, for a base from before either.
#[test]
fn a_name_taken_again_starts_no_chain_from_an_older_base() {
    let base = gid('0');
    let mut s = State::new();
    s.trunk_line = vec![base.clone(), gid('1'), gid('2'), gid('3')];
    s.renames = vec![
        renamed(1, "a#a", "a#d", Some(2)),
        renamed(3, "a#a", "a#f", None),
    ];
    assert_eq!(s.renamed_to("a#a", Some(&base)), "a#a");
    assert_eq!(s.renamed_to("a#a", None), "a#a");
}

/// Two entries for one file: the lease by the old name and the lease by the
/// new one are one symbol, and a name is not held by what left it.
#[test]
fn a_lease_meets_its_symbol_by_either_name() {
    let mut s = State::new();
    s.symbol_keys = true;
    s.renames = vec![
        renamed(1, "a.cs#C.M(string)", "a.cs#C.N", None),
        renamed(1, "a.cs#C.P(long)", "a.cs#C.Q", Some(2)),
    ];
    assert!(s.conflict(&item("a.cs#C.M(string)"), &item("a.cs#C.N")));
    assert!(s.conflict(&item("a.cs#C.N"), &item("a.cs#C.M(string)")));
    assert!(
        !s.conflict(&item("a.cs#C.M"), &item("a.cs#C.N")),
        "the one left"
    );
    assert!(!s.conflict(&item("a.cs#C.M(int)"), &item("a.cs#C.N")));
    assert!(
        !s.conflict(&item("a.cs#C.P(long)"), &item("a.cs#C.Q")),
        "taken again"
    );
    s.renames.clear();
    assert!(!s.conflict(&item("a.cs#C.M(string)"), &item("a.cs#C.N")));
}

fn on_unparsed(file: &str) -> Facts {
    Facts {
        unparsed_files: vec![file.into()],
        ..edit(&format!("{file}#<file>"))
    }
}

fn optimistic() -> H {
    let config = DEFAULT_CONFIG.replace(
        "unparsed_files = \"file\"",
        "unparsed_files = \"optimistic\"",
    );
    H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap())
}

/// By default a file no parser reads is one lease, and the same goes for
/// what the facts do not call such a file under `optimistic`.
#[test]
fn a_file_no_parser_reads_takes_a_lease_unless_the_policy_says_otherwise() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    h.wrote("a", "src/A.java");
    let d = h.propose("a", ChangeId::random(), on_unparsed("src/A.java"));
    assert!(denied_with(&d, "lease_missing:src/A.java#<file>"), "{d:?}");
    h.assert_replay();

    let mut h = optimistic();
    h.start("a", &["src/**"]);
    h.wrote("a", "src/A.java");
    let d = h.propose("a", ChangeId::random(), on_unparsed("src/A.java"));
    assert_eq!(d.reasons, ["unobserved_session", "approvals=1"], "{d:?}");
    h.wrote("a", "src/a.bin");
    let d = h.propose("a", ChangeId::random(), edit("src/a.bin#<file>"));
    assert!(denied_with(&d, "lease_missing:src/a.bin#<file>"), "{d:?}");
    h.wrote("a", "src/a.rs");
    let d = h.propose("a", ChangeId::random(), edit("src/a.rs#f"));
    assert!(denied_with(&d, "lease_missing:src/a.rs#f"), "{d:?}");
    h.assert_replay();
}

fn batched() -> H {
    let config = DEFAULT_CONFIG.replace("batch_size = 1", "batch_size = 3");
    H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap())
}

/// Three changes of observed sessions, queued in this order.
fn three_queued(h: &mut H) -> [ChangeId; 3] {
    ["a", "b", "c"].map(|session| {
        let file = format!("src/{session}.rs");
        h.start_observed(session, &["src/**"]);
        let symbol = format!("{file}#f");
        let set = format!("l{session}");
        assert!(
            h.lease(session, &set, &[(&symbol, LeaseKind::Edit)])
                .is_allow()
        );
        h.wrote(session, &file);
        let change = ChangeId::random();
        assert!(h.propose(session, change, edit(&symbol)).is_allow());
        change
    })
}

fn batch(h: &mut H, merged: &[(ChangeId, GitId)], evidence: Vec<Attestation>) -> Decision {
    let trunk_before = h.chain.state.trunk.clone().unwrap();
    let op = Op::ChangeIntegrateBatch {
        trunk_before,
        merged: merged.to_vec(),
    };
    h.daemon(op, evidence)
}

/// A required check is met by a pass of that check, and by nothing else.
#[test]
fn a_required_check_needs_a_pass_of_its_own() {
    let required = Verification {
        build: Some("build".into()),
        test: Some("test".into()),
        required: true,
        ..Verification::default()
    };
    let missing = |vc: &Verification, evidence: &[Attestation]| -> Vec<String> {
        let problems = evidence_problems(vc, evidence);
        let is_missing = |p: &String| p.starts_with("verification_missing");
        problems.into_iter().filter(is_missing).collect()
    };
    let (build, tests) = (CheckKind::Build, CheckKind::Tests);
    let failed = |check| Attestation {
        result: CheckResult::Fail,
        ..pass(check)
    };
    let (no_build, no_tests) = ("verification_missing:build", "verification_missing:tests");
    assert_eq!(missing(&required, &[pass(build), pass(tests)]), [""; 0]);
    assert_eq!(missing(&required, &[]), [no_build, no_tests]);
    assert_eq!(missing(&required, &[pass(tests)]), [no_build]);
    assert_eq!(missing(&required, &[pass(build)]), [no_tests]);
    assert_eq!(
        missing(&required, &[failed(build), pass(tests)]),
        [no_build]
    );
    assert_eq!(
        missing(&required, &[pass(build), failed(tests)]),
        [no_tests]
    );
    let optional = Verification {
        required: false,
        ..required.clone()
    };
    assert_eq!(missing(&optional, &[]), [""; 0]);
    let build_only = Verification {
        test: None,
        ..required.clone()
    };
    assert_eq!(missing(&build_only, &[pass(build)]), [""; 0]);
}

/// A batch is the head of the queue, in order, within the policy's size, on
/// this trunk, with the evidence a single change would need.
#[test]
fn a_batch_is_held_to_what_one_change_is() {
    let mut h = batched();
    let [a, b, c] = three_queued(&mut h);
    let good = || vec![pass(CheckKind::Build), pass(CheckKind::Tests)];
    let (x, y, z) = (gid('e'), gid('f'), gid('a'));

    let d = batch(&mut h, &[(a, x.clone())], good());
    assert!(denied_with(&d, "batch_size"), "one is no batch: {d:?}");
    let four = [
        (a, x.clone()),
        (b, y.clone()),
        (c, z.clone()),
        (ChangeId::random(), gid('b')),
    ];
    let d = batch(&mut h, &four, good());
    assert!(denied_with(&d, "batch_size"), "{d:?}");
    let d = batch(&mut h, &[(b, x.clone()), (a, y.clone())], good());
    assert!(denied_with(&d, "not_queue_head"), "{d:?}");
    let d = batch(&mut h, &[(b, x.clone()), (c, y.clone())], good());
    assert!(denied_with(&d, "not_queue_head"), "{d:?}");
    let op = Op::ChangeIntegrateBatch {
        trunk_before: gid('c'),
        merged: vec![(a, x.clone()), (b, y.clone())],
    };
    assert!(denied_with(&h.daemon(op, good()), "stale_trunk"));
    let mut failing = pass(CheckKind::Tests);
    failing.result = CheckResult::Fail;
    let failing = vec![failing];
    let d = batch(&mut h, &[(a, x.clone()), (b, y.clone())], failing);
    assert!(denied_with(&d, "verification_failed:tests"), "{d:?}");
    assert_eq!(h.chain.state.queue, [a, b, c], "nothing moved");
    h.assert_replay();
}

/// One entry moves trunk to the tip: the commit inside it never was trunk,
/// and the leases of every change in it are free.
#[test]
fn a_batch_moves_trunk_to_its_tip_alone() {
    let mut h = batched();
    let [a, b, c] = three_queued(&mut h);
    let (x, y) = (gid('e'), gid('f'));
    let good = vec![pass(CheckKind::Build), pass(CheckKind::Tests)];
    let d = batch(&mut h, &[(a, x.clone()), (b, y.clone())], good);
    assert!(d.is_allow(), "{d:?}");
    let state = &h.chain.state;
    assert_eq!(state.trunk.as_ref(), Some(&y));
    assert!(state.trunk_history.contains(&y));
    assert!(!state.trunk_history.contains(&x), "never trunk");
    assert_eq!(state.queue, [c]);
    let integrated = |commit: &GitId| ChangeStatus::Integrated {
        commit: commit.clone(),
    };
    assert_eq!(state.changes[&a].status, integrated(&x));
    assert_eq!(state.changes[&b].status, integrated(&y));
    assert!(held(&h, "a").is_empty());
    assert!(held(&h, "b").is_empty());
    assert_eq!(held(&h, "c"), ["src/c.rs#f"]);
    h.assert_replay();
}

/// A file a grammar stopped reading takes a person's word, whatever else
/// the proposal holds.
#[test]
fn a_file_that_stops_reading_escalates() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let lease = [("src/A.java#<file>", LeaseKind::Edit)];
    assert!(h.lease("a", "l1", &lease).is_allow());
    h.wrote("a", "src/A.java");
    let facts = Facts {
        unread_files: vec!["src/A.java".into()],
        ..edit("src/A.java#<file>")
    };
    let d = h.propose("a", ChangeId::random(), facts);
    assert!(
        d.reasons.iter().any(|r| r == "unread_file:src/A.java"),
        "{d:?}"
    );
    assert!(!d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// `optimistic` waives a lease and nothing else: a scope still holds, and so
/// does a deleted file.
#[test]
fn an_optimistic_file_stays_inside_the_scope() {
    let mut h = optimistic();
    h.start("a", &["src/**"]);
    h.wrote("a", "docs/A.java");
    let d = h.propose("a", ChangeId::random(), on_unparsed("docs/A.java"));
    assert!(denied_with(&d, "scope_path:docs/A.java"), "{d:?}");
    let gone = Facts {
        deleted_files: vec!["src/A.java".into()],
        unparsed_files: vec!["src/A.java".into()],
        ..Default::default()
    };
    h.wrote("a", "src/A.java");
    let d = h.propose("a", ChangeId::random(), gone);
    assert!(denied_with(&d, "lease_missing:src/A.java#<file>"), "{d:?}");
    h.assert_replay();
}

/// The meaning changed with format 13: in older entries two names are two
/// symbols whatever they look like.
#[test]
fn entries_of_an_older_format_know_no_keys() {
    let mut h = H::new();
    h.start("a", &["src/**"]);
    let (name, keyed) = ("src/a.cs#C.M", "src/a.cs#C.M(int)");
    h.start("b", &["src/**"]);
    assert!(h.lease("a", "l1", &[(keyed, LeaseKind::Edit)]).is_allow());
    assert!(h.chain.state.symbol_keys);
    let mut old = h.log.clone();
    for o in &mut old {
        o.entry.format = FORMAT_SYMBOL_KEYS - 1;
    }
    let state = State::replay(&old);
    assert!(!state.symbol_keys);
    let ctx = |format| Ctx {
        format,
        time_ms: h.now + 1,
        policy: &h.policy,
        facts: None,
        evidence: &[],
        symbols_engine: None,
    };
    let op = Op::LeaseAcquire {
        set: "l2".into(),
        items: vec![LeaseItem {
            symbol: name.into(),
            kind: LeaseKind::Edit,
            names: Vec::new(),
        }],
        ttl_ms: 60_000,
        intent: "work".into(),
    };
    let actor = Actor::Agent {
        name: "bot-b".into(),
        session: "b".into(),
    };
    let allowed = |s: &State, format| decide(s, &actor, &op, None, &ctx(format)).is_allow();
    assert!(allowed(&state, FORMAT_SYMBOL_KEYS - 1));
    assert!(!allowed(&h.chain.state, FORMAT_SYMBOL_KEYS));
    h.assert_replay();
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
            names: Vec::new(),
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
    assert!(request(&mut h, "one", 1, 1).is_allow());
    let d = request(&mut h, "none", 1, 0);
    assert!(denied_with(&d, "intent_required"), "{d:?}");
    h.assert_replay();
}

/// A type's definition is a member of the type: it stands beside its
/// methods and beside what is added to the type, and inside the whole type.
#[test]
fn a_definition_is_held_apart_from_the_members_of_its_type() {
    let mut h = H::new();
    for s in ["def", "method", "add", "other"] {
        h.start_observed(s, &["src/**"]);
    }
    let (def, method, ty) = ("src/a.rs#T.<def>", "src/a.rs#T.m", "src/a.rs#T");
    assert!(h.lease("def", "l1", &[(def, LeaseKind::Edit)]).is_allow());
    assert!(
        h.lease("method", "l2", &[(method, LeaseKind::Edit)])
            .is_allow()
    );
    assert!(h.lease("add", "l3", &[(ty, LeaseKind::Insert)]).is_allow());
    // A second holder of the definition, and the whole type, are refused.
    let d = h.lease("other", "l4", &[(def, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{def}:def:")), "{d:?}");
    let d = h.lease("other", "l5", &[(ty, LeaseKind::Edit)]);
    assert!(denied_with(&d, "lease_held"), "{d:?}");

    // A change of the definition needs it, not a member's lease.
    h.wrote("method", "src/a.rs");
    let d = h.propose("method", ChangeId::random(), edit(def));
    assert!(denied_with(&d, &format!("lease_missing:{def}")), "{d:?}");
    h.wrote("def", "src/a.rs");
    let d = h.propose("def", ChangeId::random(), edit(def));
    assert!(d.is_allow(), "{d:?}");

    // The whole type covers its definition.
    let whole = "src/b.rs#U";
    assert!(
        h.lease("other", "l6", &[(whole, LeaseKind::Edit)])
            .is_allow()
    );
    h.wrote("other", "src/b.rs");
    let d = h.propose("other", ChangeId::random(), edit("src/b.rs#U.<def>"));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// A scope that names a type still reaches its own text in the facts, one
/// that names a method or the members does not, and the name itself is
/// enough. Before engine 3 the same text is a document section and old
/// entries must replay as they were decided.
#[test]
fn a_definition_in_the_facts_is_inside_the_scope_of_its_type() {
    let mut h = H::new();
    h.engine = 3;
    let scopes = [("type", "T"), ("method", "T.m"), ("members", "T.*")];
    for (i, (session, scope)) in scopes.into_iter().enumerate() {
        start_with_symbols(&mut h, session, &[scope]);
        let held = if i == 0 { "src/a.rs#T" } else { "src/a.rs#T.m" };
        let held = held.replace("a.rs", &format!("{i}.rs"));
        let set = format!("l{i}");
        let d = h.lease(session, &set, &[(&held, LeaseKind::Edit)]);
        assert!(d.is_allow(), "{d:?}");
    }
    let propose = |h: &mut H, session: &str, name: &str| {
        let path = format!("src/{name}.rs");
        h.wrote(session, &path);
        let def = format!("{path}#T.<def>");
        (h.propose(session, ChangeId::random(), edit(&def)), def)
    };
    let (d, _) = propose(&mut h, "type", "0");
    assert!(!format!("{d:?}").contains("scope_symbol"), "{d:?}");
    for (session, file) in [("method", "1"), ("members", "2")] {
        let (d, def) = propose(&mut h, session, file);
        assert!(denied_with(&d, &format!("scope_symbol:{def}")), "{d:?}");
    }

    start_with_symbols(&mut h, "literal", &["T.<def>"]);
    let held = ("src/3.rs#T.<def>", LeaseKind::Edit);
    assert!(h.lease("literal", "l3", &[held]).is_allow());
    let (d, _) = propose(&mut h, "literal", "3");
    assert!(!format!("{d:?}").contains("scope_symbol"), "{d:?}");

    h.engine = 2;
    start_with_symbols(&mut h, "old-type", &["T"]);
    start_with_symbols(&mut h, "old-members", &["T.*"]);
    let held = ("src/4.rs#T", LeaseKind::Edit);
    assert!(h.lease("old-type", "l4", &[held]).is_allow());
    let (d, def) = propose(&mut h, "old-type", "4");
    assert!(denied_with(&d, &format!("scope_symbol:{def}")), "{d:?}");
    let held = ("src/5.rs#T.<def>", LeaseKind::Edit);
    assert!(h.lease("old-members", "l5", &[held]).is_allow());
    let (d, _) = propose(&mut h, "old-members", "5");
    assert!(!format!("{d:?}").contains("scope_symbol"), "{d:?}");
    h.assert_replay();
}

/// Facts of a change to `src/a.rs#f` whose callers are `affected`.
fn reaching(affected: &[&str]) -> Facts {
    let mut f = edit("src/a.rs#f");
    f.signature_changes = vec!["src/a.rs#f".into()];
    f.affected = affected.iter().map(|s| s.to_string()).collect();
    f
}

/// `a` holds `f`, and `b` holds `item` of `src/b.rs`.
fn one_holder(item: &str, kind: LeaseKind) -> H {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    assert!(
        h.lease("a", "la", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    assert!(h.lease("b", "lb", &[(item, kind)]).is_allow());
    h.wrote("a", "src/a.rs");
    h
}

const HOLDER: &str = "affected_lease:b:lb";

#[test]
fn a_lease_on_what_is_affected_is_in_the_decision() {
    for (item, kind, affected) in [
        ("src/b.rs#g", LeaseKind::Edit, "src/b.rs#g"),
        ("src/b.rs#g", LeaseKind::Rename, "src/b.rs#g"),
        ("src/b.rs#<file>", LeaseKind::Edit, "src/b.rs#g"),
        ("src/b.rs#T", LeaseKind::Edit, "src/b.rs#T.m"),
        ("src/b.rs#T.m", LeaseKind::Edit, "src/b.rs#T"),
    ] {
        let mut h = one_holder(item, kind);
        let d = h.propose("a", ChangeId::random(), reaching(&[affected]));
        assert!(d.is_allow(), "{d:?}");
        assert_eq!(
            d.reasons,
            ["signature_change:src/a.rs#f", HOLDER],
            "{item} and {affected}"
        );
        h.assert_replay();
    }
}

#[test]
fn a_lease_elsewhere_or_for_new_code_is_not() {
    for (item, kind) in [
        ("src/b.rs#other", LeaseKind::Edit),
        ("src/c.rs#g", LeaseKind::Edit),
        ("src/b.rs#<file>", LeaseKind::Insert),
    ] {
        let mut h = one_holder(item, kind);
        let d = h.propose("a", ChangeId::random(), reaching(&["src/b.rs#g"]));
        assert_eq!(d.reasons, ["signature_change:src/a.rs#f"], "{item}");
        h.assert_replay();
    }
}

#[test]
fn ones_own_lease_is_no_news() {
    let mut h = one_holder("src/b.rs#other", LeaseKind::Edit);
    let items = [("src/b.rs#g", LeaseKind::Edit)];
    assert!(h.lease("a", "lc", &items).is_allow());
    let d = h.propose("a", ChangeId::random(), reaching(&["src/b.rs#g"]));
    assert_eq!(d.reasons, ["signature_change:src/a.rs#f"]);
    h.assert_replay();
}

#[test]
fn a_lease_that_ended_is_no_holder() {
    let mut h = one_holder("src/b.rs#g", LeaseKind::Edit);
    let set = Op::LeaseRelease { set: "lb".into() };
    assert!(h.agent("b", set).is_allow());
    let d = h.propose("a", ChangeId::random(), reaching(&["src/b.rs#g"]));
    assert_eq!(d.reasons, ["signature_change:src/a.rs#f"]);
    h.assert_replay();
}

/// A lease has the name trunk has now, and a change from an older base the
/// one that base had.
#[test]
fn a_lease_under_the_new_name_is_a_holder() {
    let mut h = one_holder("src/b.rs#g", LeaseKind::Edit);
    let base = h.chain.state.trunk.clone().unwrap();
    let line = h.chain.state.trunk_line.len();
    let moved = renamed(line, "src/b.rs#old", "src/b.rs#g", None);
    h.chain.state.renames.push(moved);
    h.chain.state.trunk_history.insert(gid('e'));
    h.chain.state.trunk_line.push(gid('e'));
    h.chain.state.trunk = Some(gid('e'));
    let facts = reaching(&["src/b.rs#old"]);
    let op = Op::ChangePropose {
        change: ChangeId::random(),
        commit: gid('c'),
        base,
        claim: claim_of(&facts),
    };
    let d = h.agent_facts("a", op, Some(facts));
    assert!(d.reasons.iter().any(|r| r == HOLDER), "{d:?}");
}

#[test]
fn what_was_left_out_of_the_list_is_said() {
    let mut h = one_holder("src/b.rs#g", LeaseKind::Edit);
    let mut facts = reaching(&["src/b.rs#other"]);
    facts.affected_more = 7;
    let d = h.propose("a", ChangeId::random(), facts);
    assert_eq!(
        d.reasons,
        ["signature_change:src/a.rs#f", "affected_more:7"]
    );
    h.assert_replay();
}

#[test]
fn a_policy_can_escalate_on_what_a_change_reaches() {
    for (rule, affected, more, escalated) in [
        ("context.signature_changes > 0", "src/b.rs#other", 0, true),
        ("context.signature_changes > 1", "src/b.rs#other", 0, false),
        ("context.affects_others", "src/b.rs#g", 0, true),
        ("context.affects_others", "src/b.rs#other", 0, false),
        ("context.affects_others", "src/b.rs#other", 1, true),
    ] {
        let policy = format!(
            "{DEFAULT_POLICY}\n@id(\"reach\")\n@escalate(\"reach\")\nforbid(principal is Lonca::Agent, action == Lonca::Action::\"change.propose\", resource)\nwhen {{ {rule} }};\n"
        );
        let policy = PolicyBundle::parse(DEFAULT_CONFIG, &policy).unwrap();
        let mut h = H::with_policy(policy);
        h.start_observed("a", &["src/**"]);
        h.start_observed("b", &["src/**"]);
        assert!(
            h.lease("a", "la", &[("src/a.rs#f", LeaseKind::Edit)])
                .is_allow()
        );
        assert!(
            h.lease("b", "lb", &[("src/b.rs#g", LeaseKind::Edit)])
                .is_allow()
        );
        h.wrote("a", "src/a.rs");
        let mut facts = reaching(&[affected]);
        facts.affected_more = more;
        let d = h.propose("a", ChangeId::random(), facts);
        assert_eq!(d.is_allow(), !escalated, "{rule} with {affected}: {d:?}");
        h.assert_replay();
    }
}

/// A verification that a change owes is met by a pass of it, and a change
/// that owes none owes none.
#[test]
fn what_runs_more_is_owed_by_a_change_that_reaches_others() {
    let vc = Verification {
        on_signature_change: Some("more".into()),
        required: true,
        ..Verification::default()
    };
    assert!(vc.on_signature_change.is_some());
    let missing = ["verification_missing:extended".to_string()];
    assert_eq!(
        evidence_problems(&vc.for_change(true, &BTreeSet::new()), &[]),
        missing
    );
    assert!(evidence_problems(&vc.for_change(false, &BTreeSet::new()), &[]).is_empty());
    let passed = [pass(CheckKind::Extended)];
    assert!(evidence_problems(&vc.for_change(true, &BTreeSet::new()), &passed).is_empty());
    let optional = Verification {
        required: false,
        ..vc.clone()
    };
    assert!(evidence_problems(&optional.for_change(true, &BTreeSet::new()), &[]).is_empty());
    let bare = Verification {
        require_sandbox: true,
        ..vc
    };
    let mut unsandboxed = pass(CheckKind::Extended);
    unsandboxed.details.clear();
    let problems = evidence_problems(&bare.for_change(true, &BTreeSet::new()), &[unsandboxed]);
    assert_eq!(problems, ["unsandboxed_verification"]);
}

fn extended_policy() -> PolicyBundle {
    let config = DEFAULT_CONFIG
        .replace("batch_size = 1", "batch_size = 3")
        .replace("required = false", "required = true")
        .replace(
            "# on_signature_change = \"cargo test --offline --workspace --all-features\"",
            "on_signature_change = \"more\"",
        );
    PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap()
}

#[test]
fn the_decision_holds_the_queue_to_what_a_change_owes() {
    for (evidence, owed) in [(vec![], false), (vec![pass(CheckKind::Extended)], true)] {
        let mut h = H::with_policy(extended_policy());
        h.start_observed("a", &["src/**"]);
        let items = [("src/a.rs#f", LeaseKind::Edit)];
        assert!(h.lease("a", "la", &items).is_allow());
        h.wrote("a", "src/a.rs");
        let change = ChangeId::random();
        assert!(h.propose("a", change, reaching(&[])).is_allow());
        let trunk_before = h.chain.state.trunk.clone().unwrap();
        let op = Op::ChangeIntegrate {
            change,
            trunk_before,
            merged: Some(gid('e')),
            conflicts: vec![],
        };
        let d = h.daemon(op, evidence);
        assert_eq!(d.is_allow(), owed, "{d:?}");
        assert_eq!(denied_with(&d, "verification_missing:extended"), !owed);
        h.assert_replay();
    }
}

#[test]
fn the_decision_holds_a_batch_to_what_a_member_owes() {
    let mut h = H::with_policy(extended_policy());
    for (session, facts) in [("a", edit("src/a.rs#f")), ("b", reaching(&[]))] {
        h.start_observed(session, &["src/**"]);
        let set = format!("l{session}");
        let held = if session == "a" {
            "src/a.rs#f"
        } else {
            "src/a.rs#g"
        };
        assert!(
            h.lease(session, &set, &[(held, LeaseKind::Edit)])
                .is_allow()
        );
        h.wrote(session, "src/a.rs");
        let mut facts = facts;
        if session == "b" {
            facts = edit("src/a.rs#g");
            facts.signature_changes = vec!["src/a.rs#g".into()];
        }
        assert!(h.propose(session, ChangeId::random(), facts).is_allow());
    }
    let queued: Vec<ChangeId> = h.chain.state.queue.clone();
    let merged = [(queued[0], gid('e')), (queued[1], gid('f'))];
    let d = batch(&mut h, &merged, vec![]);
    assert!(denied_with(&d, "verification_missing:extended"), "{d:?}");
    let d = batch(&mut h, &merged, vec![pass(CheckKind::Extended)]);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// An entry of an older format replays to what it decided.
#[test]
fn before_the_format_a_proposal_reports_nobody() {
    let h = one_holder("src/b.rs#g", LeaseKind::Edit);
    let facts = reaching(&["src/b.rs#g"]);
    let claim = claim_of(&facts);
    let op = Op::ChangePropose {
        change: ChangeId::random(),
        commit: gid('e'),
        base: h.chain.state.trunk.clone().unwrap(),
        claim,
    };
    let actor = Actor::Agent {
        name: h.chain.state.sessions["a"].agent.clone(),
        session: "a".into(),
    };
    let decided = |format: u32| {
        decide(
            &h.chain.state,
            &actor,
            &op,
            None,
            &Ctx {
                format,
                time_ms: h.now,
                policy: &h.policy,
                facts: Some(&facts),
                evidence: &[],
                symbols_engine: Some(0),
            },
        )
    };
    assert!(decided(FORMAT_CURRENT).reasons.iter().any(|r| r == HOLDER));
    assert!(decided(FORMAT_AFFECTED - 1).reasons.is_empty());
}

// ---------------------------------------------------------------- session.isolate

fn isolate(session: &str) -> Op {
    Op::SessionIsolate {
        session: session.into(),
        sandbox: "seatbelt".into(),
        profile: "ab".repeat(32),
    }
}

#[test]
fn a_sandbox_is_vouched_for_by_the_human_who_started_the_session() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    let d = h.agent("s1", isolate("s1"));
    assert!(denied_with(&d, "not_grantable:session.isolate"), "{d:?}");
    let d = h.daemon(isolate("s1"), vec![]);
    assert!(denied_with(&d, "not_a_daemon_op:session.isolate"), "{d:?}");
    assert_eq!(
        h.chain.state.sessions["s1"].level,
        ObservationLevel::Unobserved
    );

    let d = h.human("ayse", isolate("nobody"));
    assert!(denied_with(&d, "unknown_session"), "{d:?}");
    let d = h.human("ayse", isolate("s1"));
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(
        h.chain.state.sessions["s1"].level,
        ObservationLevel::Isolated
    );
    h.assert_replay();
}

#[test]
fn an_isolated_session_is_not_refused_for_what_only_hooks_could_see() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    assert!(h.human("ayse", isolate("s1")).is_allow());
    assert!(
        h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    let d = h.propose("s1", ChangeId::random(), edit("src/a.rs#f"));
    assert_eq!(d.outcome, Outcome::Allow, "{d:?}");
    h.assert_replay();
}

#[test]
fn isolation_needs_a_session_that_is_alive_and_a_well_formed_word() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    let bad = |sandbox: &str, profile: String| Op::SessionIsolate {
        session: "s1".into(),
        sandbox: sandbox.into(),
        profile,
    };
    let good = "ab".repeat(32);
    for name in ["", "a b", &"x".repeat(33)] {
        let d = h.human("ayse", bad(name, good.clone()));
        assert!(denied_with(&d, "invalid_sandbox"), "{name}: {d:?}");
    }
    for digest in [
        "ab".repeat(31),
        "AB".repeat(32),
        "xy".repeat(32),
        "ab".repeat(33),
    ] {
        let d = h.human("ayse", bad("seatbelt", digest.clone()));
        assert!(denied_with(&d, "invalid_profile"), "{digest}: {d:?}");
    }
    let longest = bad(&"x".repeat(32), "ab".repeat(32));
    h.start("s2", &["src/**"]);
    let d = h.human(
        "ayse",
        Op::SessionEnd {
            session: "s2".into(),
            reason: "done".into(),
        },
    );
    assert!(d.is_allow(), "{d:?}");
    let d = h.human("ayse", isolate("s2"));
    assert!(denied_with(&d, "session_inactive"), "{d:?}");
    assert!(h.human("ayse", longest).is_allow());
    h.assert_replay();
}

#[test]
fn a_hook_does_not_take_a_sandbox_level_away() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    assert!(h.human("ayse", isolate("s1")).is_allow());
    let checks = BindChecks {
        harness: "codex".into(),
        harness_session: "x".into(),
        managed_hooks: false,
        locked_sandbox: false,
        sudo_without_password: false,
        config_digest: String::new(),
        hook_binary_protected: false,
    };
    let d = h.daemon(
        Op::SessionBind {
            session: "s1".into(),
            checks,
            level: ObservationLevel::Unobserved,
        },
        vec![],
    );
    assert!(denied_with(&d, "session_isolated"), "{d:?}");
    assert_eq!(
        h.chain.state.sessions["s1"].level,
        ObservationLevel::Isolated
    );
    h.assert_replay();
}

/// What a hook of `harness` reports on a machine that locks it.
fn bind(session: &str, harness: &str, level: ObservationLevel) -> Op {
    let locked = level > ObservationLevel::Unobserved;
    Op::SessionBind {
        session: session.into(),
        checks: BindChecks {
            harness: harness.into(),
            harness_session: "x".into(),
            managed_hooks: locked,
            locked_sandbox: level == ObservationLevel::HooksSandbox,
            sudo_without_password: false,
            config_digest: String::new(),
            hook_binary_protected: locked,
        },
        level,
    }
}

#[test]
fn a_level_rests_on_the_harness_the_human_named() {
    let mut h = H::new();
    let start = |h: &mut H, id: &str, harness: Option<&str>| {
        let mut op = h.start_op(id, &["src/**"], None);
        if let Op::SessionStart { harness: named, .. } = &mut op {
            *named = harness.map(str::to_string);
        }
        assert!(h.human("ayse", op).is_allow());
    };
    start(&mut h, "s1", Some("codex"));
    let up = bind("s1", "claude-code", ObservationLevel::HooksSandbox);
    assert!(denied_with(&h.daemon(up, vec![]), "bind_other_harness"));
    assert_eq!(
        h.chain.state.sessions["s1"].level,
        ObservationLevel::Unobserved
    );
    // Nobody named one: nothing can be read for it.
    start(&mut h, "s2", None);
    let up = bind("s2", "claude-code", ObservationLevel::Hooks);
    assert!(denied_with(&h.daemon(up, vec![]), "bind_other_harness"));

    // A report of nothing needs no vouching, and is on the record.
    let low = bind("s2", "claude-code", ObservationLevel::Unobserved);
    assert!(h.daemon(low, vec![]).is_allow());
    assert!(h.chain.state.sessions["s2"].bound);

    let up = bind("s1", "codex", ObservationLevel::Hooks);
    assert!(h.daemon(up, vec![]).is_allow());
    assert_eq!(h.chain.state.sessions["s1"].level, ObservationLevel::Hooks);
    h.assert_replay();
}

#[test]
fn a_session_s_harness_must_be_a_name() {
    let mut h = H::new();
    let mut op = h.start_op("s1", &["src/**"], None);
    if let Op::SessionStart { harness, .. } = &mut op {
        *harness = Some("no/such name".into());
    }
    assert!(denied_with(&h.human("ayse", op), "invalid_harness"));
    h.assert_replay();
}

#[test]
fn a_bound_level_stays_or_falls() {
    let mut h = H::new();
    let code = "claude-code";
    h.start("s1", &["src/**"]);
    assert!(!h.chain.state.sessions["s1"].bound);
    // The first report sets it, from below.
    let first = bind("s1", code, ObservationLevel::Hooks);
    assert!(h.daemon(first, vec![]).is_allow());
    let up = bind("s1", code, ObservationLevel::HooksSandbox);
    assert!(denied_with(&h.daemon(up, vec![]), "bind_raises_level"));
    let same = bind("s1", code, ObservationLevel::Hooks);
    assert!(h.daemon(same, vec![]).is_allow());
    let down = bind("s1", code, ObservationLevel::Unobserved);
    assert!(h.daemon(down, vec![]).is_allow());
    assert_eq!(
        h.chain.state.sessions["s1"].level,
        ObservationLevel::Unobserved
    );
    let back = bind("s1", code, ObservationLevel::Hooks);
    assert!(denied_with(&h.daemon(back, vec![]), "bind_raises_level"));
    h.assert_replay();
}

/// A session of its own is what an agent can make: it starts where its
/// parent stands.
#[test]
fn a_child_can_not_bind_its_way_past_its_parent() {
    let mut h = H::new();
    let code = "claude-code";
    h.start("s1", &["src/**"]);
    let attenuate = |parent: &str, child: &str| Op::CapAttenuate {
        parent: parent.into(),
        child: child.into(),
        agent: "bot".into(),
        scope: Scope {
            paths: vec!["src/**".into()],
            symbols: None,
            ops: vec![OpKind::ChangePropose],
            max_files: None,
            max_lines: None,
            scratch: vec![],
        },
        expires_ms: h.now + MIN,
        leases: vec![],
    };
    let early = attenuate("s1", "early");
    let low = attenuate("s1", "low");
    assert!(h.agent("s1", early).is_allow());
    let child = &h.chain.state.sessions["early"];
    assert_eq!(child.harness.as_deref(), Some(code));
    assert!(!child.bound);
    let up = bind("early", code, ObservationLevel::Hooks);
    assert!(h.daemon(up, vec![]).is_allow());

    let first = bind("s1", code, ObservationLevel::Unobserved);
    assert!(h.daemon(first, vec![]).is_allow());
    assert!(h.agent("s1", low).is_allow());
    assert!(h.chain.state.sessions["low"].bound);
    let up = bind("low", code, ObservationLevel::Hooks);
    assert!(denied_with(&h.daemon(up, vec![]), "bind_raises_level"));
    h.assert_replay();
}

/// A continuation is signed: its harness reports afresh, and what was known
/// of the files stays known whatever it says.
#[test]
fn a_continuation_keeps_the_harness_unless_it_names_one() {
    let mut h = H::new();
    let code = "claude-code";
    h.start("s1", &["src/**"]);
    let first = bind("s1", code, ObservationLevel::Unobserved);
    assert!(h.daemon(first, vec![]).is_allow());

    let c = |session: &str| {
        Some(Continuation {
            session: session.into(),
            widen: false,
        })
    };
    let mut op = h.start_op("s2", &["src/**"], c("s1"));
    if let Op::SessionStart { harness, .. } = &mut op {
        *harness = None;
    }
    assert!(h.human("ayse", op).is_allow());
    let s2 = &h.chain.state.sessions["s2"];
    assert_eq!(s2.harness.as_deref(), Some(code));
    assert!(!s2.bound);
    let up = bind("s2", code, ObservationLevel::Hooks);
    assert!(h.daemon(up, vec![]).is_allow());

    let mut op = h.start_op("s3", &["src/**"], c("s2"));
    if let Op::SessionStart { harness, .. } = &mut op {
        *harness = Some("codex".into());
    }
    assert!(h.human("ayse", op).is_allow());
    let s3 = &h.chain.state.sessions["s3"];
    assert_eq!(s3.harness.as_deref(), Some("codex"));
    h.assert_replay();
}

#[test]
fn a_session_that_continues_an_isolated_one_has_shown_nothing() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    assert!(h.human("ayse", isolate("s1")).is_allow());
    let op = h.start_op(
        "s2",
        &["src/**"],
        Some(Continuation {
            session: "s1".into(),
            widen: false,
        }),
    );
    let d = h.human("ayse", op);
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(
        h.chain.state.sessions["s2"].level,
        ObservationLevel::Unobserved
    );
    h.assert_replay();
}

#[test]
fn another_human_can_not_vouch_and_a_child_takes_its_level_from_its_parent() {
    let mut h = H::new();
    h.enroll("bora");
    h.start("s1", &["src/**"]);
    let d = h.human("bora", isolate("s1"));
    assert!(denied_with(&d, "not_own_session"), "{d:?}");
    assert!(h.human("ayse", isolate("s1")).is_allow());
    let scope = h.chain.state.sessions["s1"].scope.clone();
    let child = Op::CapAttenuate {
        parent: "s1".into(),
        child: "s1c".into(),
        agent: "sub".into(),
        scope,
        expires_ms: h.now + 60 * MIN,
        leases: vec![],
    };
    assert!(h.agent("s1", child).is_allow());
    assert_eq!(
        h.chain.state.sessions["s1c"].level,
        ObservationLevel::Isolated
    );
    let d = h.human("ayse", isolate("s1c"));
    assert!(denied_with(&d, "session_is_a_child"), "{d:?}");
    h.assert_replay();
}

#[test]
fn policy_can_ask_for_a_sandbox_by_path_and_by_task() {
    let rule = format!(
        "{DEFAULT_POLICY}\n@id(\"sandbox\")\n\
         forbid(principal is Lonca::Agent, action, resource)\n\
         when {{ context has path && context.path like \"src/auth/*\" \
         && context has observation && context.observation != \"isolated\" }};\n\
         @id(\"task\")\n\
         forbid(principal is Lonca::Agent, action, resource)\n\
         when {{ context has path && context has task && context.task == \"T-1\" \
         && context.observation != \"isolated\" }};\n"
    );
    let policy = PolicyBundle::parse(&PolicyBundle::default_bundle().config_text, &rule).unwrap();
    let mut h = H::with_policy(policy);
    h.start("s1", &["src/**"]);
    h.start_observed("s2", &["src/**"]);
    for s in ["s1", "s2"] {
        let set = format!("l-{s}");
        let auth = format!("src/auth/{s}.rs#f");
        let other = format!("src/{s}.rs#f");
        let items = [
            (auth.as_str(), LeaseKind::Edit),
            (other.as_str(), LeaseKind::Edit),
        ];
        assert!(h.lease(s, &set, &items).is_allow());
        let d = h.propose(s, ChangeId::random(), edit(&auth));
        assert!(denied_with(&d, "policy:sandbox"), "{s}: {d:?}");
        let d = h.propose(s, ChangeId::random(), edit(&other));
        assert!(denied_with(&d, "policy:task"), "{s}: {d:?}");
        assert!(!denied_with(&d, "policy:sandbox"), "{s}: {d:?}");
    }
    h.start("s3", &["src/**"]);
    assert!(h.human("ayse", isolate("s3")).is_allow());
    let auth = "src/auth/s3.rs#f";
    assert!(h.lease("s3", "l3", &[(auth, LeaseKind::Edit)]).is_allow());
    let d = h.propose("s3", ChangeId::random(), edit(auth));
    assert_ne!(d.outcome, Outcome::Deny, "{d:?}");
    h.assert_replay();
}

/// A policy from before format 19 that asks `context has task` reads false.
#[test]
fn old_entries_have_no_task_in_their_context() {
    let rule = format!(
        "{DEFAULT_POLICY}\n@id(\"task\")\n\
         forbid(principal is Lonca::Agent, action == Lonca::Action::\"lease.acquire\", resource)\n\
         when {{ context has task }};\n"
    );
    let policy = PolicyBundle::parse(DEFAULT_CONFIG, &rule).unwrap();
    let mut h = H::with_policy(policy);
    h.start("s1", &["src/**"]);
    let d = h.lease("s1", "l1", &[("src/a.rs#f", LeaseKind::Edit)]);
    assert!(denied_with(&d, "policy:task"), "{d:?}");
}

#[test]
fn only_a_session_nothing_has_used_can_be_isolated() {
    let used = |h: &mut H| {
        let d = h.human("ayse", isolate("s1"));
        assert!(denied_with(&d, "session_used"), "{d:?}");
        h.assert_replay();
    };
    let start = || {
        let mut h = H::new();
        h.start("s1", &["src/**"]);
        h
    };

    let mut h = start();
    assert!(h.human("ayse", isolate("s1")).is_allow());
    used(&mut h);

    let mut h = start();
    let event = |kind, external| Op::Observe {
        session: "s1".into(),
        events: vec![Observation {
            phase: Phase::Post,
            kind,
            external,
        }],
    };
    assert!(
        h.daemon(event(ObsKind::Heartbeat, false), vec![])
            .is_allow()
    );
    used(&mut h);

    let mut h = start();
    h.wrote("s1", "src/a.rs");
    used(&mut h);

    let mut h = start();
    let fetch = ObsKind::Fetch { host: "x".into() };
    assert!(h.daemon(event(fetch, true), vec![]).is_allow());
    used(&mut h);

    let mut h = start();
    let shell = ObsKind::Shell {
        program: "ls".into(),
        digest: "d".into(),
    };
    assert!(h.daemon(event(shell, false), vec![]).is_allow());
    used(&mut h);

    let mut h = start();
    let lease = [("src/a.rs#f", LeaseKind::Edit)];
    assert!(h.lease("s1", "l1", &lease).is_allow());
    used(&mut h);

    let mut h = start();
    assert!(h.lease("s1", "l1", &lease).is_allow());
    let d = h.propose("s1", ChangeId::random(), edit("src/a.rs#f"));
    assert_ne!(d.outcome, Outcome::Deny, "{d:?}");
    used(&mut h);

    let mut h = start();
    let scope = h.chain.state.sessions["s1"].scope.clone();
    let child = Op::CapAttenuate {
        parent: "s1".into(),
        child: "c".into(),
        agent: "sub".into(),
        scope,
        expires_ms: h.now + 60 * MIN,
        leases: vec![],
    };
    assert!(h.agent("s1", child).is_allow());
    used(&mut h);

    let mut h = start();
    let d = h.continue_as("s2", "s1", &["src/**"], false);
    assert!(d.is_allow(), "{d:?}");
    let d = h.human("ayse", isolate("s2"));
    assert!(denied_with(&d, "session_used"), "{d:?}");
    h.assert_replay();
}

#[test]
fn none_is_no_sandbox() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    let op = Op::SessionIsolate {
        session: "s1".into(),
        sandbox: "none".into(),
        profile: "ab".repeat(32),
    };
    let d = h.human("ayse", op);
    assert!(denied_with(&d, "invalid_sandbox"), "{d:?}");
    h.assert_replay();
}

#[test]
fn what_another_session_did_says_nothing_of_this_one() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    h.start("other", &["src/**"]);
    h.wrote("other", "src/a.rs");
    let lease = [("src/a.rs#f", LeaseKind::Edit)];
    assert!(h.lease("other", "l1", &lease).is_allow());
    let d = h.propose("other", ChangeId::random(), edit("src/a.rs#f"));
    assert_ne!(d.outcome, Outcome::Deny, "{d:?}");
    assert!(h.human("ayse", isolate("s1")).is_allow());
    h.assert_replay();
}

#[test]
fn a_change_alone_says_a_session_was_used() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    assert!(h.human("ayse", isolate("s1")).is_allow());
    h.start("s2", &["src/**"]);
    let change = ChangeId::random();
    let lease = [("src/a.rs#f", LeaseKind::Edit)];
    assert!(h.lease("s2", "l2", &lease).is_allow());
    h.wrote("s2", "src/a.rs");
    assert_ne!(
        h.propose("s2", change, edit("src/a.rs#f")).outcome,
        Outcome::Deny
    );
    h.chain.state.leases.clear();
    let mut s = h.chain.state.sessions["s2"].clone();
    s.writes.clear();
    s.taint = None;
    h.chain.state.sessions.insert("s2".into(), s);
    let d = h.human("ayse", isolate("s2"));
    assert!(denied_with(&d, "session_used"), "{d:?}");
}

// ------------------------------------------------------ verification quota

const DAY: i64 = 86_400_000;

fn with_quota(session: u64, day: u64) -> H {
    H::with_policy(quota_policy(DEFAULT_CONFIG, session, day))
}

fn quota_policy(config: &str, session: u64, day: u64) -> PolicyBundle {
    let config = config
        .replace(
            "session_seconds = 0",
            &format!("session_seconds = {session}"),
        )
        .replace("day_seconds = 0", &format!("day_seconds = {day}"));
    PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap()
}

/// A check that took `ms`, as the verifier writes it.
fn took(ms: &str) -> Attestation {
    let mut a = pass(CheckKind::Tests);
    a.details.insert("duration_ms".into(), ms.into());
    a
}

/// `session` (observed) leases `symbol`, writes its file and proposes an
/// edit of it.
fn queue_edit(h: &mut H, session: &str, symbol: &str) -> (ChangeId, Decision) {
    lease_and_write(h, session, symbol);
    let change = ChangeId::random();
    (change, h.propose(session, change, edit(symbol)))
}

fn lease_and_write(h: &mut H, session: &str, symbol: &str) {
    let set: String = symbol.chars().filter(char::is_ascii_alphanumeric).collect();
    let d = h.lease(session, &set, &[(symbol, LeaseKind::Edit)]);
    assert!(d.is_allow(), "{d:?}");
    h.wrote(session, symbol.split('#').next().unwrap());
}

/// The head of the queue, integrated as `tip` with `evidence`.
fn verified(h: &mut H, change: ChangeId, tip: char, evidence: Vec<Attestation>) -> Decision {
    let trunk_before = h.chain.state.trunk.clone().unwrap();
    let op = Op::ChangeIntegrate {
        change,
        trunk_before,
        merged: Some(gid(tip)),
        conflicts: vec![],
    };
    h.daemon(op, evidence)
}

fn refused_for(d: &Decision, quota: &str) {
    assert_eq!(d.outcome, Outcome::Deny, "{d:?}");
    assert_eq!(d.reasons, [format!("verification_quota:{quota}")], "{d:?}");
}

#[test]
fn a_session_past_its_verification_quota_proposes_nothing_more() {
    let mut h = with_quota(2, 0);
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let (c1, d) = queue_edit(&mut h, "a", "src/a.rs#f");
    assert!(d.is_allow(), "{d:?}");
    assert!(verified(&mut h, c1, 'e', vec![took("1500"), took("499")]).is_allow());
    assert_eq!(h.chain.state.session_spent("a"), 1999);
    // A millisecond under the quota is under it.
    let (c2, d) = queue_edit(&mut h, "a", "src/a.rs#g");
    assert!(d.is_allow(), "{d:?}");
    let (c3, d) = queue_edit(&mut h, "b", "src/b.rs#f");
    assert!(d.is_allow(), "{d:?}");
    assert!(verified(&mut h, c2, 'f', vec![took("1")]).is_allow());
    let (_, d) = queue_edit(&mut h, "a", "src/a.rs#h");
    refused_for(&d, "session");
    // Every session pays its own.
    assert!(verified(&mut h, c3, '1', vec![took("1999")]).is_allow());
    let (_, d) = queue_edit(&mut h, "b", "src/b.rs#g");
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(h.chain.state.day_spent(h.now), 3999);
    h.assert_replay();
}

#[test]
fn what_is_queued_past_the_quota_is_rejected() {
    let mut h = with_quota(1, 0);
    h.start_observed("a", &["src/**"]);
    let (c1, _) = queue_edit(&mut h, "a", "src/a.rs#f");
    let (c2, d) = queue_edit(&mut h, "a", "src/a.rs#g");
    assert!(d.is_allow(), "{d:?}");
    assert!(verified(&mut h, c1, 'e', vec![took("1000")]).is_allow());
    // Even with a pass: a run past the quota stands for nothing.
    let d = verified(&mut h, c2, 'f', vec![pass(CheckKind::Tests)]);
    refused_for(&d, "session");
    let s = &h.chain.state;
    let reasons = vec!["verification_quota:session".to_string()];
    assert_eq!(s.changes[&c2].status, ChangeStatus::Rejected { reasons });
    assert!(s.queue.is_empty());
    h.assert_replay();
}

#[test]
fn a_run_costs_what_it_took_failed_or_not_and_a_cached_one_nothing() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    let (c1, _) = queue_edit(&mut h, "a", "src/a.rs#f");
    let failed = Attestation {
        result: CheckResult::Fail,
        ..took("700")
    };
    let mut cached = took("5000");
    cached.details.insert("reused".into(), "true".into());
    let unread = [took("soon"), took("-4"), pass(CheckKind::Build)];
    let mut evidence = vec![failed, cached];
    evidence.extend(unread);
    let d = verified(&mut h, c1, 'e', evidence);
    assert!(denied_with(&d, "verification_failed:tests"), "{d:?}");
    assert_eq!(h.chain.state.session_spent("a"), 700);
    assert_eq!(h.chain.state.day_spent(h.now), 700);
    // No quota by default, however long it takes.
    let (c2, _) = queue_edit(&mut h, "a", "src/a.rs#g");
    let huge = took(&u64::MAX.to_string());
    assert!(verified(&mut h, c2, 'f', vec![huge.clone(), huge]).is_allow());
    assert_eq!(h.chain.state.session_spent("a"), u64::MAX);
    let (_, d) = queue_edit(&mut h, "a", "src/a.rs#h");
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

#[test]
fn the_day_quota_is_the_repositorys_and_starts_over_at_midnight() {
    let midnight = (T0 / DAY + 1) * DAY;
    let mut h = with_quota(0, 3);
    h.now = midnight - 30 * MIN;
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let (c1, _) = queue_edit(&mut h, "a", "src/a.rs#f");
    let (c2, d) = queue_edit(&mut h, "b", "src/b.rs#f");
    assert!(d.is_allow(), "{d:?}");
    assert!(verified(&mut h, c1, 'e', vec![took("3000")]).is_allow());
    assert_eq!(h.chain.state.session_spent("b"), 0);
    // `b` used nothing, but the day is spent.
    refused_for(&verified(&mut h, c2, 'f', vec![]), "day");
    let human = Actor::Human {
        name: "ayse".into(),
    };
    let quota = Quota {
        session_seconds: 1,
        day_seconds: 3,
    };
    let s = &h.chain.state;
    let agent = |session: &str| Actor::Agent {
        name: "bot".into(),
        session: session.into(),
    };
    let day = vec!["verification_quota:day".to_string()];
    let both = vec!["verification_quota:session".to_string(), day[0].clone()];
    assert_eq!(quota_problems(s, &human, h.now, &quota), day);
    assert_eq!(quota_problems(s, &agent("b"), h.now, &quota), day);
    assert_eq!(quota_problems(s, &agent("a"), h.now, &quota), both);
    assert_eq!(quota_problems(s, &agent("a"), midnight, &quota), &both[..1]);
    h.now = midnight - 5 * MIN;
    lease_and_write(&mut h, "b", "src/b.rs#g");
    // The entry takes the next millisecond: the last of the day.
    h.now = midnight - 2;
    refused_for(
        &h.propose("b", ChangeId::random(), edit("src/b.rs#g")),
        "day",
    );
    let d = h.propose("b", ChangeId::random(), edit("src/b.rs#g"));
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(h.chain.state.day_spent(h.now), 0);
    assert_eq!(h.chain.state.day_spent(midnight - 1), 3000);
    h.assert_replay();
}

#[test]
fn sessions_made_from_or_continuing_a_session_pay_with_it() {
    let mut h = with_quota(2, 0);
    h.start_observed("a", &["src/**"]);
    let attenuate = Op::CapAttenuate {
        parent: "a".into(),
        child: "kid".into(),
        agent: "bot".into(),
        scope: h.chain.state.sessions["a"].scope.clone(),
        expires_ms: h.now + 10 * MIN,
        leases: vec![],
    };
    assert!(h.agent("a", attenuate).is_allow());
    let (c1, d) = queue_edit(&mut h, "kid", "src/a.rs#f");
    assert!(d.is_allow(), "{d:?}");
    assert!(verified(&mut h, c1, 'e', vec![took("2000")]).is_allow());
    let s = &h.chain.state;
    assert_eq!((s.payer("kid"), s.payer("a")), ("a", "a"));
    assert_eq!(s.session_spent("a"), 2000);
    let (_, d) = queue_edit(&mut h, "a", "src/a.rs#g");
    refused_for(&d, "session");
    assert!(h.continue_as("b", "a", &["src/**"], false).is_allow());
    let (_, d) = queue_edit(&mut h, "b", "src/a.rs#h");
    refused_for(&d, "session");
    assert!(h.continue_as("c", "b", &["src/**"], false).is_allow());
    assert_eq!(h.chain.state.payer("c"), "a");
    h.assert_replay();
}

#[test]
fn a_batch_is_one_run_and_its_changes_share_it() {
    let config = DEFAULT_CONFIG.replace("batch_size = 1", "batch_size = 3");
    let mut h = H::with_policy(quota_policy(&config, 1, 0));
    let [a, b, c] = three_queued(&mut h);
    let (d, _) = queue_edit(&mut h, "a", "src/a.rs#g");
    let (e, _) = queue_edit(&mut h, "b", "src/b.rs#g");
    let merged = [(a, gid('e')), (b, gid('f')), (c, gid('1'))];
    assert!(batch(&mut h, &merged, vec![took("3002")]).is_allow());
    let s = &h.chain.state;
    let paid: Vec<u64> = ["a", "b", "c"].map(|x| s.session_spent(x)).into();
    assert_eq!(paid, [1000; 3]);
    assert_eq!(s.day_spent(h.now), 3002);
    // One change past the quota refuses the batch, and nothing moves.
    let d2 = batch(&mut h, &[(d, gid('2')), (e, gid('3'))], vec![]);
    refused_for(&d2, "session");
    assert_eq!(h.chain.state.queue, [d, e]);
    h.assert_replay();
}

/// `leases.shared` on, with what makes it acceptable: every merge verified.
fn shared_policy() -> PolicyBundle {
    let config = DEFAULT_CONFIG
        .replace("shared = false", "shared = true")
        .replace("required = false", "required = true")
        .replace("# test = \"cargo test --offline\"", "test = \"t\"");
    PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap()
}

#[test]
fn shared_needs_the_repository_to_verify_every_merge() {
    let on = |from: &str, to: &str| DEFAULT_CONFIG.replace(from, to);
    let shared = on("shared = false", "shared = true");
    let required = shared.replace("required = false", "required = true");
    let blank = required.replace("# test = \"cargo test --offline\"", "test = \"  \"");
    for config in [&shared, &required, &blank] {
        let Err(err) = PolicyBundle::parse(config, DEFAULT_POLICY) else {
            panic!("allowed: {config}");
        };
        assert!(err.contains("leases.shared needs"), "{err}");
    }
    let built = required.replace("# build = \"cargo build --offline\"", "build = \"b\"");
    assert!(PolicyBundle::parse(&built, DEFAULT_POLICY).is_ok());
    assert!(shared_policy().config.shared_leases());
    assert!(!PolicyBundle::default_bundle().config.shared_leases());
}

#[test]
fn a_shared_lease_is_refused_where_the_repository_does_not_allow_it() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let f = "src/a.rs#f";
    let d = h.lease("a", "la", &[(f, LeaseKind::Shared)]);
    assert!(denied_with(&d, "shared_off"), "{d:?}");
    // An interest in it too: it would stop others for what can never be held.
    assert!(h.lease("b", "lb", &[(f, LeaseKind::Edit)]).is_allow());
    let d = h.agent(
        "a",
        Op::LeaseInterest {
            items: vec![LeaseItem {
                symbol: f.into(),
                kind: LeaseKind::Shared,
                names: Vec::new(),
            }],
            intent: "wait".into(),
        },
    );
    assert!(denied_with(&d, "shared_off"), "{d:?}");
    // The other kinds are as they were.
    let d = h.lease("a", "la", &[("src/a.rs#g", LeaseKind::Edit)]);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

#[test]
fn shared_holders_share_and_edit_stays_exclusive() {
    let mut h = H::with_policy(shared_policy());
    for s in ["a", "b", "c", "d"] {
        h.start_observed(s, &["src/**"]);
    }
    let f = "src/a.rs#Client.charge";
    let g = "src/a.rs#Client.refund";
    assert!(h.lease("a", "la", &[(f, LeaseKind::Shared)]).is_allow());
    assert!(h.lease("b", "lb", &[(f, LeaseKind::Shared)]).is_allow());
    // An exclusive kind on it, or on what holds it, meets both holders.
    for (sym, kind) in [
        (f, LeaseKind::Edit),
        (f, LeaseKind::Rename),
        ("src/a.rs#Client", LeaseKind::Edit),
        ("src/a.rs#<file>", LeaseKind::Rename),
    ] {
        let d = h.lease("c", "lc", &[(sym, kind)]);
        assert!(denied_with(&d, &format!("lease_held:{f}:a:")), "{d:?}");
        assert!(denied_with(&d, &format!("lease_held:{f}:b:")), "{d:?}");
    }
    // Against an insert, shared is an edit: a new member of the type is no
    // part of `charge`, and a new member of `charge` is.
    let d = h.lease("c", "lc", &[("src/a.rs#Client", LeaseKind::Insert)]);
    assert!(d.is_allow(), "{d:?}");
    let d = h.lease("d", "ld", &[(f, LeaseKind::Insert)]);
    assert!(denied_with(&d, &format!("lease_held:{f}:a:")), "{d:?}");
    // And an edit held first keeps shared out.
    assert!(h.lease("d", "ld", &[(g, LeaseKind::Edit)]).is_allow());
    let d = h.lease("a", "la2", &[(g, LeaseKind::Shared)]);
    assert!(denied_with(&d, &format!("lease_held:{g}:d:")), "{d:?}");
    // A shared lease on the type is shared with one on its member.
    let d = h.lease("b", "lb2", &[("src/a.rs#Client", LeaseKind::Shared)]);
    assert!(denied_with(&d, &format!("lease_held:{g}:d:")), "{d:?}");
    assert!(!denied_with(&d, &format!("lease_held:{f}")), "{d:?}");
    h.assert_replay();
}

#[test]
fn a_shared_lease_covers_a_body_and_not_a_signature() {
    let mut h = H::with_policy(shared_policy());
    h.start_observed("a", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(h.lease("a", "la", &[(f, LeaseKind::Shared)]).is_allow());
    h.wrote("a", "src/a.rs");
    let d = h.propose("a", ChangeId::random(), reaching(&[]));
    assert!(denied_with(&d, &format!("lease_missing:{f}")), "{d:?}");
    let change = ChangeId::random();
    let d = h.propose("a", change, edit(f));
    assert!(d.is_allow(), "{d:?}");
    // What the change needs is pinned to it, shared or not.
    let pinned = &h.chain.state.leases["la"].pins[&change];
    assert_eq!(
        pinned.iter().map(|i| i.kind).collect::<Vec<_>>(),
        [LeaseKind::Shared]
    );
    h.assert_replay();
}

/// What engine 14 may join, as the daemon and the auditor read it from the
/// state: what the change pinned `shared`, less what trunk changed since its
/// base under anything else.
#[test]
fn what_an_integration_may_join_comes_from_the_state() {
    let mut h = H::with_policy(shared_policy());
    let config = shared_policy().config;
    let (f, g, del) = ("src/a.rs#f", "src/a.rs#g", "src/a.rs#h");
    for s in ["a", "b", "c"] {
        h.start_observed(s, &["src/**"]);
    }
    // A human's edit of `f` made the base: it is not since the base.
    let human = ChangeId::random();
    let op = Op::ChangePropose {
        change: human,
        commit: gid('c'),
        base: h.chain.state.trunk.clone().unwrap(),
        claim: claim_of(&edit(f)),
    };
    assert!(h.human_change("ayse", op, edit(f)).is_allow());
    assert!(integrate(&mut h, human, Some(gid('1')), &[]).is_allow());
    let exclusive = &h.chain.state.exclusive;
    assert_eq!(exclusive.last().unwrap().symbols, Some(vec![f.to_string()]));

    assert!(h.lease("a", "la", &[(f, LeaseKind::Shared)]).is_allow());
    assert!(h.lease("b", "lb", &[(f, LeaseKind::Shared)]).is_allow());
    let items = [(g, LeaseKind::Edit), (del, LeaseKind::Rename)];
    assert!(h.lease("c", "lc", &items).is_allow());
    for s in ["a", "b", "c"] {
        h.wrote(s, "src/a.rs");
    }
    let [ca, cb, cc] = [(); 3].map(|_| ChangeId::random());
    // In the queue: `a`'s, `c`'s, then `b`'s, which is the one asked about.
    assert!(h.propose("a", ca, edit(f)).is_allow());
    let mut other = edit(g);
    other.deletes = vec![del.into()];
    assert!(h.propose("c", cc, other).is_allow());
    assert!(h.propose("b", cb, edit(f)).is_allow());

    let joins = |h: &H, before: &[ChangeId]| h.chain.state.joins(cb, before, &config);
    assert!(joins(&h, &[]).allows(f));
    assert!(!joins(&h, &[]).allows(g), "not pinned shared");
    assert!(joins(&h, &[ca]).allows(f), "shared in front of it");
    assert!(joins(&h, &[cc]).allows(f));
    // In front of it in a batch, `c`'s change says what `a`'s may join.
    let by_a = |before: &[ChangeId]| h.chain.state.joins(ca, before, &config);
    assert!(by_a(&[]).allows(f));
    assert_eq!(h.chain.state.exclusive_of(cc), [g, del]);
    assert!(h.chain.state.exclusive_of(ca).is_empty());

    // Shared on trunk leaves nothing behind; an edit and a delete do.
    let records = h.chain.state.exclusive.len();
    assert!(integrate(&mut h, ca, Some(gid('2')), &[]).is_allow());
    assert_eq!(h.chain.state.exclusive.len(), records);
    assert!(joins(&h, &[]).allows(f));
    let d = integrate(&mut h, cc, Some(gid('3')), &[]);
    assert!(d.is_allow(), "{d:?}");
    let last = h.chain.state.exclusive.last().unwrap();
    assert_eq!(last.symbols, Some(vec![g.to_string(), del.to_string()]));
    assert!(joins(&h, &[]).allows(f));

    // Not under a policy without shared leases.
    let off = PolicyBundle::default_bundle().config;
    assert!(!h.chain.state.joins(cb, &[], &off).allows(f));
    // Nor across what came from outside: it could have changed anything.
    let trunk_before = h.chain.state.trunk.clone().unwrap();
    let import = Op::ImportExternal {
        remote: "origin".into(),
        commit: gid('4'),
        trunk_before,
    };
    assert!(h.human("ayse", import).is_allow());
    assert_eq!(h.chain.state.exclusive.last().unwrap().symbols, None);
    assert!(!joins(&h, &[]).allows(f));
    // What came from outside before the base is in the base.
    h.start_observed("d", &["src/**"]);
    assert!(h.lease("d", "ld", &[(f, LeaseKind::Shared)]).is_allow());
    h.wrote("d", "src/a.rs");
    let cd = ChangeId::random();
    assert!(h.propose("d", cd, edit(f)).is_allow());
    assert!(h.chain.state.joins(cd, &[], &config).allows(f));
    h.assert_replay();
}

/// A session's own leases do not meet: one that holds `f` both `shared` and
/// `edit` changed it under `edit`, and no later change joins with that.
#[test]
fn an_edit_under_an_exclusive_pin_is_exclusive_whatever_else_is_pinned() {
    let mut h = H::with_policy(shared_policy());
    h.start_observed("a", &["src/**"]);
    let f = "src/a.rs#f";
    assert!(
        h.lease("a", "la", &[("src/a.rs#<file>", LeaseKind::Shared)])
            .is_allow()
    );
    assert!(h.lease("a", "lb", &[(f, LeaseKind::Edit)]).is_allow());
    h.wrote("a", "src/a.rs");
    let change = ChangeId::random();
    assert!(h.propose("a", change, edit(f)).is_allow());
    let pinned = |set: &str| h.chain.state.leases[set].pins[&change].len();
    assert_eq!([pinned("la"), pinned("lb")], [1, 1]);
    assert_eq!(h.chain.state.exclusive_of(change), [f]);
    h.assert_replay();
}

// ------------------------------------------------- bounds and both sides
//
// Each check below is held at its edge and on each side of an `||`, so a
// `>` that became `>=` or an `||` that became `&&` is noticed.

fn scope(symbols: Option<&[&str]>, max_files: Option<u32>, max_lines: Option<u32>) -> Scope {
    Scope {
        paths: vec!["src/**".into()],
        symbols: symbols.map(|s| s.iter().map(|x| x.to_string()).collect()),
        ops: vec![OpKind::ChangePropose],
        max_files,
        max_lines,
        scratch: vec![],
    }
}

#[test]
fn a_narrower_scope_keeps_within_symbols_and_counts() {
    let outer = scope(Some(&["Client.*"]), Some(5), Some(100));
    assert_eq!(
        scope_within(&scope(Some(&["Client.charge"]), Some(5), Some(100)), &outer),
        Ok(())
    );
    assert_eq!(
        scope_within(&scope(Some(&["Other.*"]), Some(5), Some(100)), &outer),
        Err("symbol:Other.*".into())
    );
    assert_eq!(
        scope_within(&scope(None, Some(5), Some(100)), &outer),
        Err("symbols:unrestricted".into())
    );
    let counts =
        |files, lines| scope_within(&scope(None, files, lines), &scope(None, Some(5), Some(100)));
    assert_eq!(counts(Some(4), Some(99)), Ok(()));
    assert_eq!(counts(Some(5), Some(100)), Ok(()));
    assert_eq!(counts(Some(6), Some(100)), Err("max_files".into()));
    assert_eq!(counts(Some(5), Some(101)), Err("max_lines".into()));
    assert_eq!(counts(None, Some(100)), Err("max_files".into()));
    assert_eq!(counts(Some(5), None), Err("max_lines".into()));
    let open = scope(None, None, None);
    assert_eq!(scope_within(&scope(None, Some(9), None), &open), Ok(()));
}

#[test]
fn genesis_refuses_a_bad_repository_name_with_a_good_owner() {
    let policy = PolicyBundle::default_bundle();
    let key = KeyPair::generate();
    let op = Op::RepoInit {
        repo: "no spaces".into(),
        daemon_key: key.public_hex(),
        human: "ayse".into(),
        human_key: file_key(&key),
        policy: gid('a'),
        trunk: gid('b'),
    };
    let d = decide(
        &State::new(),
        &Actor::Human {
            name: "ayse".into(),
        },
        &op,
        None,
        &Ctx {
            format: FORMAT_CURRENT,
            time_ms: T0,
            policy: &policy,
            facts: None,
            evidence: &[],
            symbols_engine: None,
        },
    );
    assert_eq!(d, Decision::deny("invalid_name"));
}

#[test]
fn an_enrolled_key_must_be_hex_whatever_its_algorithm() {
    let mut h = H::new();
    let op = Op::HumanEnroll {
        human: "cem".into(),
        key: HumanKey {
            alg: "ed25519".into(),
            public: "not hex".into(),
        },
    };
    assert!(denied_with(&h.human("ayse", op), "invalid_key"));
    h.assert_replay();
}

#[test]
fn a_policy_update_asks_one_human_fewer_than_it_needs() {
    let config = DEFAULT_CONFIG
        .replace("policy_updates = 1", "policy_updates = 3")
        .replace(
            "cap_to_enrolled_humans = true",
            "cap_to_enrolled_humans = false",
        );
    let mut h = H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap());
    let d = h.human("ayse", Op::PolicyUpdate { policy: gid('e') });
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(d.reasons.contains(&"policy_update".to_string()), "{d:?}");
    assert!(d.reasons.contains(&"approvals=2".to_string()), "{d:?}");
    let pending = h.chain.state.pending.values().next().unwrap();
    assert_eq!(pending.required, 2);
    h.assert_replay();
}

#[test]
fn a_session_start_is_held_to_its_names_task_and_lifetime() {
    let mut h = H::new();
    let mut op = h.start_op("s1", &["src/**"], None);
    let Op::SessionStart { agent, .. } = &mut op else {
        unreachable!()
    };
    *agent = "no spaces".into();
    assert!(denied_with(&h.human("ayse", op), "invalid_name"));

    let with_task = |h: &H, session: &str, len: usize| {
        let mut op = h.start_op(session, &["src/**"], None);
        let Op::SessionStart { task, .. } = &mut op else {
            unreachable!()
        };
        *task = "t".repeat(len);
        op
    };
    let op = with_task(&h, "s2", 201);
    assert!(denied_with(&h.human("ayse", op), "task_too_long"));
    let op = with_task(&h, "s2", 200);
    let d = h.human("ayse", op);
    assert!(d.is_allow(), "{d:?}");

    // The entry's time is one past `now`; the longest life is 480 minutes.
    let living = |h: &H, session: &str, ms: i64| {
        let mut op = h.start_op(session, &["src/**"], None);
        let Op::SessionStart { expires_ms, .. } = &mut op else {
            unreachable!()
        };
        *expires_ms = h.now + 1 + ms;
        op
    };
    let op = living(&h, "s3", 480 * MIN + 1);
    assert!(denied_with(&h.human("ayse", op), "session_ttl"));
    let op = living(&h, "s3", 480 * MIN);
    let d = h.human("ayse", op);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

#[test]
fn a_session_ends_once() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    let end = || Op::SessionEnd {
        session: "s1".into(),
        reason: "done".into(),
    };
    assert!(h.human("ayse", end()).is_allow());
    assert!(denied_with(&h.human("ayse", end()), "session_ended"));
    h.assert_replay();
}

#[test]
fn a_child_session_is_named_well_and_may_live_as_long_as_its_parent() {
    let mut h = three_sessions();
    let mut op = child_op(&h, "a", "kid", &[]);
    let Op::CapAttenuate { agent, .. } = &mut op else {
        unreachable!()
    };
    *agent = "no spaces".into();
    assert!(denied_with(&h.agent("a", op), "invalid_name"));

    let mut op = child_op(&h, "a", "kid", &[]);
    let Op::CapAttenuate { expires_ms, .. } = &mut op else {
        unreachable!()
    };
    *expires_ms = h.chain.state.sessions["a"].expires_ms + 1;
    assert!(denied_with(&h.agent("a", op), "session_ttl"));
    let mut op = child_op(&h, "a", "kid", &[]);
    let Op::CapAttenuate { expires_ms, .. } = &mut op else {
        unreachable!()
    };
    *expires_ms = h.chain.state.sessions["a"].expires_ms;
    let d = h.agent("a", op);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

#[test]
fn a_lease_set_name_is_used_once() {
    let mut h = three_sessions();
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    let d = h.lease("a", "l1", &[("src/a.rs#g", LeaseKind::Edit)]);
    assert!(denied_with(&d, "invalid_lease_set"), "{d:?}");
    h.assert_replay();
}

/// A session acquiring something else keeps its reservation; another
/// session's stays too.
#[test]
fn a_reservation_outlives_a_lease_on_something_else() {
    let mut h = three_sessions();
    h.start("d", &["src/**"]);
    let g = "src/a.rs#g";
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.lease("c", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    assert!(interest(&mut h, "b", F).is_allow());
    assert!(interest(&mut h, "d", g).is_allow());
    assert!(h.agent("a", release("l1")).is_allow());
    assert!(h.agent("c", release("l2")).is_allow());
    assert!(
        h.lease("d", "l3", &[("src/b.rs#h", LeaseKind::Edit)])
            .is_allow()
    );
    let holders: Vec<&str> = h
        .chain
        .state
        .reservations
        .iter()
        .map(|r| r.session.as_str())
        .collect();
    assert_eq!(holders, ["b", "d"]);
    h.assert_replay();
}

/// An unobserved session's proposal waits for a human and says where it
/// came from; the human's note has a length limit.
#[test]
fn an_unobserved_proposal_is_marked_and_approved_with_a_short_note() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    let sym = "src/a.rs#f";
    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    let d = h.propose("s1", c, edit(sym));
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert_eq!(h.chain.state.changes[&c].provenance, Provenance::Unobserved);

    let seq = pending_seq(&h, c);
    let note = |len: usize| Op::Approve {
        target_seq: seq,
        note: "n".repeat(len),
        checks: vec![],
    };
    assert!(denied_with(&h.human("ayse", note(501)), "note_too_long"));
    let d = h.human("ayse", note(500));
    assert!(d.reasons.contains(&"released".to_string()), "{d:?}");
    assert_eq!(h.chain.state.changes[&c].status, ChangeStatus::Queued);
    h.assert_replay();
}

#[test]
fn a_tainted_proposal_is_marked_tainted() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let taint = Op::Taint {
        session: "s1".into(),
        reason: "read a web page".into(),
    };
    assert!(h.daemon(taint, vec![]).is_allow());
    let sym = "src/a.rs#f";
    h.wrote("s1", "src/a.rs");
    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("s1", c, edit(sym)).outcome, Outcome::Escalate);
    assert_eq!(h.chain.state.changes[&c].provenance, Provenance::Tainted);
    h.assert_replay();
}

#[test]
fn a_reason_may_be_as_long_as_the_limit() {
    let mut h = H::new();
    h.start("s1", &["src/**"]);
    let sym = "src/a.rs#f";
    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    assert_eq!(h.propose("s1", c, edit(sym)).outcome, Outcome::Escalate);
    let seq = pending_seq(&h, c);
    let d = h.human("ayse", reject(seq, &"x".repeat(4096)));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// Proposed again after a withdrawal, a change is its next version; a
/// withdrawal takes only that change off the queue, and a change off the
/// queue is not integrated.
#[test]
fn a_withdrawn_change_leaves_the_queue_and_comes_back_as_its_next_version() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    h.wrote("s1", "src/a.rs");
    h.wrote("s1", "src/b.rs");
    let (f, g) = ("src/a.rs#f", "src/b.rs#g");
    assert!(
        h.lease("s1", "l1", &[(f, LeaseKind::Edit), (g, LeaseKind::Edit)])
            .is_allow()
    );
    let (c1, c2) = (ChangeId::random(), ChangeId::random());
    assert!(h.propose("s1", c1, edit(f)).is_allow());
    assert!(h.propose("s1", c2, edit(g)).is_allow());
    assert_eq!(h.chain.state.changes[&c1].version, 1);
    assert_eq!(h.chain.state.queue, [c1, c2]);
    let d = h.agent("s1", Op::ChangeWithdraw { change: c1 });
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(h.chain.state.queue, [c2]);
    // Only a queued change is integrated.
    let d = integrate(&mut h, c1, Some(gid('f')), &[]);
    assert!(denied_with(&d, "change_not_queued"), "{d:?}");
    let d = h.propose("s1", c1, edit(f));
    assert!(d.is_allow(), "{d:?}");
    assert_eq!(h.chain.state.changes[&c1].version, 2);
    assert_eq!(h.chain.state.queue, [c2, c1]);
    h.assert_replay();
}

#[test]
fn an_observation_holds_up_to_256_events() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    let observe = |n: usize| Op::Observe {
        session: "s1".into(),
        events: (0..n)
            .map(|i| Observation {
                phase: Phase::Post,
                kind: ObsKind::Write {
                    path: format!("src/f{i}.rs"),
                },
                external: false,
            })
            .collect(),
    };
    assert!(denied_with(
        &h.daemon(observe(257), vec![]),
        "too_many_events"
    ));
    let d = h.daemon(observe(256), vec![]);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

#[test]
fn a_push_anchors_at_the_head_by_number_and_hash() {
    let mut h = H::new();
    let push = |h: &H, hash: String| Op::BridgePush {
        remote: "origin".into(),
        oplog_seq: h.chain.state.next_seq - 1,
        oplog_hash: hash,
    };
    let op = push(&h, "0".repeat(64));
    let d = h.human("ayse", op);
    assert!(denied_with(&d, "stale_anchor"), "{d:?}");
    let op = push(&h, h.chain.state.head_hash.clone());
    let d = h.human("ayse", op);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

#[test]
fn only_its_two_sessions_talk_in_a_thread() {
    let mut h = H::new();
    for s in ["s1", "s2", "s3"] {
        h.start_observed(s, &["src/**"]);
    }
    let say = |to: &str| Op::Negotiate {
        thread: "t1".into(),
        to_session: to.into(),
        message: NegotiationMsg::Counter { note: "hi".into() },
    };
    assert!(h.agent("s1", say("s2")).is_allow());
    assert!(denied_with(
        &h.agent("s3", say("s2")),
        "not_thread_participant"
    ));
    assert!(denied_with(
        &h.agent("s3", say("s1")),
        "not_thread_participant"
    ));
    h.assert_replay();
}

#[test]
fn an_unsandboxed_check_is_one_that_ran_with_none() {
    let vc = Verification {
        require_sandbox: true,
        ..Verification::default()
    };
    let mut none = pass(CheckKind::Build);
    none.details.insert("sandbox".into(), "none".into());
    assert_eq!(
        evidence_problems(&vc, &[none]),
        ["unsandboxed_verification"]
    );
    assert!(evidence_problems(&vc, &[pass(CheckKind::Build)]).is_empty());
}

#[test]
fn a_change_may_have_as_many_files_as_the_config_allows() {
    let config = DEFAULT_CONFIG.replace("max_files = 200", "max_files = 3");
    let mut h = H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap());
    let files = |n: usize| Facts {
        modified_files: (0..n).map(|i| format!("src/f{i}.rs")).collect(),
        lines_added: 1,
        ..Default::default()
    };
    let propose = |h: &mut H, facts: Facts| {
        let op = Op::ChangePropose {
            change: ChangeId::random(),
            commit: gid('c'),
            base: h.chain.state.trunk.clone().unwrap(),
            claim: claim_of(&facts),
        };
        h.human_change("ayse", op, facts)
    };
    let d = propose(&mut h, files(4));
    assert!(denied_with(&d, "too_many_files"), "{d:?}");
    let d = propose(&mut h, files(3));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// A session's own limits on files and lines hold at their edge.
#[test]
fn a_scope_limits_files_and_lines_to_its_edge() {
    let mut h = H::new();
    let mut op = h.start_op("s1", &["src/**"], None);
    let Op::SessionStart { scope, .. } = &mut op else {
        unreachable!()
    };
    scope.max_files = Some(2);
    scope.max_lines = Some(10);
    assert!(h.human("ayse", op).is_allow());
    let bind = Op::SessionBind {
        session: "s1".into(),
        checks: BindChecks {
            harness: "claude-code".into(),
            harness_session: "h-s1".into(),
            managed_hooks: true,
            locked_sandbox: true,
            sudo_without_password: false,
            config_digest: "cfg".into(),
            hook_binary_protected: true,
        },
        level: ObservationLevel::HooksSandbox,
    };
    assert!(h.daemon(bind, vec![]).is_allow());
    let syms = ["src/a.rs#f", "src/b.rs#g", "src/c.rs#h"];
    for s in syms {
        h.wrote("s1", s.split('#').next().unwrap());
    }
    let items: Vec<(&str, LeaseKind)> = syms.iter().map(|s| (*s, LeaseKind::Edit)).collect();
    assert!(h.lease("s1", "l1", &items).is_allow());
    let facts = |n: usize, added: u32, removed: u32| Facts {
        edits: syms[..n].iter().map(|s| s.to_string()).collect(),
        modified_files: syms[..n]
            .iter()
            .map(|s| s.split('#').next().unwrap().to_string())
            .collect(),
        lines_added: added,
        lines_removed: removed,
        ..Default::default()
    };
    let d = h.propose("s1", ChangeId::random(), facts(3, 1, 1));
    assert!(denied_with(&d, "scope_max_files"), "{d:?}");
    let d = h.propose("s1", ChangeId::random(), facts(2, 6, 5));
    assert!(denied_with(&d, "scope_max_lines"), "{d:?}");
    let d = h.propose("s1", ChangeId::random(), facts(2, 6, 4));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// The policy sees the lines added and removed together.
#[test]
fn the_blast_radius_counts_lines_added_and_removed() {
    let mut h = H::new();
    h.start_observed("s1", &["src/**"]);
    h.start_observed("s2", &["src/**"]);
    let (f, g) = ("src/a.rs#f", "src/b.rs#g");
    h.wrote("s1", "src/a.rs");
    h.wrote("s2", "src/b.rs");
    assert!(h.lease("s1", "l1", &[(f, LeaseKind::Edit)]).is_allow());
    assert!(h.lease("s2", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    let lines = |sym: &str, added: u32, removed: u32| Facts {
        lines_added: added,
        lines_removed: removed,
        ..edit(sym)
    };
    let d = h.propose("s1", ChangeId::random(), lines(f, 2001, 0));
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    assert!(
        d.reasons.contains(&"policy:blast-radius".to_string()),
        "{d:?}"
    );
    let d = h.propose("s2", ChangeId::random(), lines(g, 1000, 1000));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// Text outside any symbol (`<file>`, `<imports>`) is in a scope only
/// when the scope names every symbol.
#[test]
fn only_a_scope_of_every_symbol_reaches_text_outside_symbols() {
    let mut h = H::new();
    for (session, symbols) in [("s1", "*"), ("s2", "f")] {
        let mut op = h.start_op(session, &["src/**"], None);
        let Op::SessionStart { scope, .. } = &mut op else {
            unreachable!()
        };
        scope.symbols = Some(vec![symbols.into()]);
        assert!(h.human("ayse", op).is_allow());
    }
    let (a, b) = ("src/a.rs#<file>", "src/b.rs#<file>");
    assert!(h.lease("s1", "l1", &[(a, LeaseKind::Edit)]).is_allow());
    let d = h.propose("s1", ChangeId::random(), edit(a));
    assert!(!denied_with(&d, "scope_symbol"), "{d:?}");
    let d = h.propose("s2", ChangeId::random(), edit(b));
    assert!(denied_with(&d, &format!("scope_symbol:{b}")), "{d:?}");
    h.assert_replay();
}

// ---------------------------------------------------------------- insert names (#45)

/// An `insert` on `container` that reserves `names`.
fn insert_named(h: &mut H, session: &str, set: &str, container: &str, names: &[&str]) -> Decision {
    h.agent(
        session,
        Op::LeaseAcquire {
            set: set.into(),
            items: vec![named_item(container, LeaseKind::Insert, names)],
            intent: format!("add to {container}"),
            ttl_ms: 10 * MIN,
        },
    )
}

fn named_item(symbol: &str, kind: LeaseKind, names: &[&str]) -> LeaseItem {
    LeaseItem {
        symbol: symbol.into(),
        kind,
        names: names.iter().map(|n| n.to_string()).collect(),
    }
}

fn adds(syms: &[&str]) -> Facts {
    let path = syms[0].split('#').next().unwrap().to_string();
    Facts {
        adds: syms.iter().map(|s| s.to_string()).collect(),
        modified_files: vec![path],
        lines_added: 3,
        ..Default::default()
    }
}

fn new_file(path: &str) -> Facts {
    Facts {
        added_files: vec![path.into()],
        lines_added: 3,
        ..Default::default()
    }
}

#[test]
fn two_inserts_that_reserve_one_name_in_one_container_conflict() {
    let mut h = H::new();
    for s in ["a", "b", "c", "d", "e"] {
        h.start_observed(s, &["src/**"]);
    }
    let c = "src/a.rs#Client";
    assert!(insert_named(&mut h, "a", "la", c, &["throttle"]).is_allow());
    let d = insert_named(&mut h, "b", "lb", c, &["retry", "throttle"]);
    assert!(denied_with(&d, &format!("lease_held:{c}:a:")), "{d:?}");
    // Who was refused may wait for it.
    let wait = Op::LeaseInterest {
        items: vec![named_item(c, LeaseKind::Insert, &["throttle"])],
        intent: "wait".into(),
    };
    assert!(h.agent("b", wait).is_allow());
    // Other names, an insert that names nothing, another container: free.
    assert!(insert_named(&mut h, "c", "lc", c, &["retry"]).is_allow());
    assert!(h.lease("c", "lc2", &[(c, LeaseKind::Insert)]).is_allow());
    let file = "src/a.rs#<file>";
    assert!(insert_named(&mut h, "d", "ld", file, &["throttle"]).is_allow());
    let other = "src/b.rs#Client";
    assert!(insert_named(&mut h, "d", "ld2", other, &["throttle"]).is_allow());
    // A name stands for the keyed container.
    let keyed = "src/a.rs#S.From(u8)";
    assert!(insert_named(&mut h, "d", "ld3", keyed, &["from"]).is_allow());
    let d = insert_named(&mut h, "e", "le", "src/a.rs#S.From", &["from"]);
    assert!(denied_with(&d, &format!("lease_held:{keyed}:d:")), "{d:?}");
    // An exclusive lease on the container still meets every insert.
    let d = h.lease("e", "le", &[(c, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{c}:a:")), "{d:?}");
    h.assert_replay();
}

#[test]
fn an_addition_outside_the_reserved_names_is_refused() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    let c = "src/a.rs#Client";
    assert!(insert_named(&mut h, "a", "la", c, &["throttle"]).is_allow());
    h.wrote("a", "src/a.rs");
    let d = h.propose("a", ChangeId::random(), adds(&["src/a.rs#Client.retry"]));
    assert!(denied_with(&d, &format!("lease_missing:{c}")), "{d:?}");
    let both = adds(&["src/a.rs#Client.throttle", "src/a.rs#Client.retry"]);
    let d = h.propose("a", ChangeId::random(), both);
    assert!(denied_with(&d, &format!("lease_missing:{c}")), "{d:?}");
    // By its name alone: a key or a number is still that name.
    for added in [
        "src/a.rs#Client.throttle",
        "src/a.rs#Client.throttle(int)",
        "src/a.rs#Client.throttle~2",
    ] {
        let change = ChangeId::random();
        let d = h.propose("a", change, adds(&[added]));
        assert!(d.is_allow(), "{added}: {d:?}");
        assert!(h.agent("a", Op::ChangeWithdraw { change }).is_allow());
    }
    h.assert_replay();
}

#[test]
fn a_reserved_type_brings_its_members_and_nothing_else() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    let file = "src/a.rs#<file>";
    assert!(insert_named(&mut h, "a", "la", file, &["Limiter"]).is_allow());
    h.wrote("a", "src/a.rs");
    // Something else at the top, or a member of a type it did not name.
    for added in ["src/a.rs#helper", "src/a.rs#Client.x"] {
        let d = h.propose("a", ChangeId::random(), adds(&[added]));
        assert!(denied_with(&d, "lease_missing:"), "{added}: {d:?}");
    }
    let change = ChangeId::random();
    let new_type = adds(&["src/a.rs#Limiter", "src/a.rs#Limiter.new"]);
    let d = h.propose("a", change, new_type);
    assert!(d.is_allow(), "{d:?}");
    let pinned = &h.chain.state.leases["la"].pins[&change];
    assert_eq!(pinned, &[named_item(file, LeaseKind::Insert, &["Limiter"])]);
    h.assert_replay();
}

#[test]
fn a_new_file_needs_its_path_exclusively() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.start_observed("b", &["src/**"]);
    let (path, file) = ("src/new.rs", "src/new.rs#<file>");
    h.wrote("a", path);
    let d = h.propose("a", ChangeId::random(), new_file(path));
    assert!(denied_with(&d, &format!("lease_missing:{file}")), "{d:?}");
    // An insert is shared, so it does not make a path anyone's.
    assert!(h.lease("a", "li", &[(file, LeaseKind::Insert)]).is_allow());
    let d = h.propose("a", ChangeId::random(), new_file(path));
    assert!(denied_with(&d, &format!("lease_missing:{file}")), "{d:?}");
    assert!(h.lease("a", "la", &[(file, LeaseKind::Edit)]).is_allow());
    let change = ChangeId::random();
    assert!(h.propose("a", change, new_file(path)).is_allow());
    assert_eq!(
        h.chain.state.leases["la"].pins[&change],
        [LeaseItem::new(file, LeaseKind::Edit)]
    );
    // Whoever else would create it is refused, by either kind.
    for kind in [LeaseKind::Edit, LeaseKind::Insert] {
        let d = h.lease("b", "lb", &[(file, kind)]);
        assert!(denied_with(&d, &format!("lease_held:{file}:a:")), "{d:?}");
    }
    h.assert_replay();
}

#[test]
fn reserved_names_are_for_an_insert_and_must_be_names() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    let c = "src/a.rs#Client";
    for kind in [LeaseKind::Edit, LeaseKind::Rename] {
        let d = h.agent(
            "a",
            Op::LeaseAcquire {
                set: "la".into(),
                items: vec![named_item(c, kind, &["x"])],
                intent: "x".into(),
                ttl_ms: 10 * MIN,
            },
        );
        assert!(denied_with(&d, &format!("names_need_insert:{c}")), "{d:?}");
    }
    let many: Vec<String> = (0..65).map(|i| format!("n{i}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let long = "x".repeat(129);
    for names in [
        &[""][..],
        &["a.b"],
        &["x(int)"],
        &["x~2"],
        &[" a"],
        &["<def>"],
        &["a#b"],
        &[long.as_str()],
        &many,
    ] {
        let d = insert_named(&mut h, "a", "la", c, names);
        assert!(
            denied_with(&d, &format!("invalid_names:{c}")),
            "{names:?}: {d:?}"
        );
    }
    let most: Vec<String> = (0..64).map(|i| format!("n{i}")).collect();
    let most: Vec<&str> = most.iter().map(String::as_str).collect();
    let longest = "x".repeat(128);
    assert!(insert_named(&mut h, "a", "la", c, &most).is_allow());
    assert!(insert_named(&mut h, "a", "lb", c, &[longest.as_str(), "_ok"]).is_allow());
    h.assert_replay();
}

/// Before format 22 a new file needed no lease, and replays as it was.
#[test]
fn before_the_format_a_new_file_needs_no_lease() {
    let mut h = H::new();
    h.start_observed("a", &["src/**"]);
    h.wrote("a", "src/new.rs");
    let facts = new_file("src/new.rs");
    let op = Op::ChangePropose {
        change: ChangeId::random(),
        commit: gid('e'),
        base: h.chain.state.trunk.clone().unwrap(),
        claim: claim_of(&facts),
    };
    let actor = Actor::Agent {
        name: h.chain.state.sessions["a"].agent.clone(),
        session: "a".into(),
    };
    let decided = |format: u32| {
        decide(
            &h.chain.state,
            &actor,
            &op,
            None,
            &Ctx {
                format,
                time_ms: h.now,
                policy: &h.policy,
                facts: Some(&facts),
                evidence: &[],
                symbols_engine: Some(0),
            },
        )
    };
    let d = decided(FORMAT_CURRENT);
    assert!(denied_with(&d, "lease_missing:src/new.rs#<file>"), "{d:?}");
    let d = decided(FORMAT_INSERT_NAMES - 1);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// Reserving a member of a file reserves what goes into it: two named
/// inserts on nested containers can not both cover one addition.
#[test]
fn a_reservation_holds_what_goes_into_the_member_it_names() {
    let mut h = H::new();
    for s in ["a", "b"] {
        h.start_observed(s, &["src/**"]);
    }
    let file = "src/a.rs#<file>";
    assert!(insert_named(&mut h, "a", "la", file, &["Client"]).is_allow());
    let d = insert_named(&mut h, "b", "lb", "src/a.rs#Client", &["throttle"]);
    assert!(denied_with(&d, &format!("lease_held:{file}:a:")), "{d:?}");
    let d = insert_named(&mut h, "b", "lb", "src/a.rs#Server", &["throttle"]);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// A name another session reserved is its own: not under an unnamed
/// insert, and not as the new name of a rename.
#[test]
fn a_reserved_name_is_not_added_by_anyone_else() {
    let mut h = H::new();
    for s in ["a", "b"] {
        h.start_observed(s, &["src/**"]);
    }
    let c = "src/a.rs#Client";
    assert!(insert_named(&mut h, "a", "la", c, &["throttle"]).is_allow());
    assert!(h.lease("b", "lb", &[(c, LeaseKind::Insert)]).is_allow());
    let old = "src/a.rs#Client.old";
    assert!(h.lease("b", "lb2", &[(old, LeaseKind::Rename)]).is_allow());
    h.wrote("b", "src/a.rs");
    let taken = "src/a.rs#Client.throttle";
    let reason = format!("name_reserved:{taken}:a");
    let d = h.propose("b", ChangeId::random(), adds(&[taken]));
    assert!(denied_with(&d, &reason), "{d:?}");
    let d = h.propose(
        "b",
        ChangeId::random(),
        adds(&["src/a.rs#Client.throttle(int)"]),
    );
    assert!(denied_with(&d, "name_reserved:"), "{d:?}");
    let renamed = Facts {
        deletes: vec![old.into()],
        adds: vec![taken.into()],
        renames: vec![[old.into(), taken.into()]],
        modified_files: vec!["src/a.rs".into()],
        lines_added: 1,
        lines_removed: 1,
        ..Default::default()
    };
    let d = h.propose("b", ChangeId::random(), renamed);
    assert!(denied_with(&d, &reason), "{d:?}");
    // Another name is free, and the one who reserved it adds it.
    let d = h.propose("b", ChangeId::random(), adds(&["src/a.rs#Client.retry"]));
    assert!(d.is_allow(), "{d:?}");
    h.wrote("a", "src/a.rs");
    let d = h.propose("a", ChangeId::random(), adds(&[taken]));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// A path trunk got after the change's base would be merged with the new
/// file as if from nothing: the agent syncs first.
#[test]
fn a_file_created_since_the_base_is_refused_until_a_sync() {
    let mut h = H::new();
    for s in ["a", "b"] {
        h.start_observed(s, &["src/**"]);
    }
    let (path, file) = ("src/new.rs", "src/new.rs#<file>");
    let old_base = h.chain.state.trunk.clone().unwrap();
    assert!(h.lease("a", "la", &[(file, LeaseKind::Edit)]).is_allow());
    h.wrote("a", path);
    let change = ChangeId::random();
    assert!(h.propose("a", change, new_file(path)).is_allow());
    assert!(integrate(&mut h, change, Some(gid('n')), &[]).is_allow());
    assert!(h.lease("b", "lb", &[(file, LeaseKind::Edit)]).is_allow());
    h.wrote("b", path);
    let facts = new_file(path);
    let stale = Op::ChangePropose {
        change: ChangeId::random(),
        commit: gid('c'),
        base: old_base,
        claim: claim_of(&facts),
    };
    let d = h.agent_facts("b", stale, Some(facts.clone()));
    assert!(
        denied_with(&d, &format!("created_since_base:{path}")),
        "{d:?}"
    );
    // From the trunk that has it, it is no longer new; nor is another path.
    let d = h.propose("b", ChangeId::random(), facts);
    assert!(!denied_with(&d, "created_since_base"), "{d:?}");
    h.assert_replay();
}

// ------------------------------------------------- lease kinds by nesting (#40)

/// Which two kinds held by two sessions meet, for a symbol `a` and a
/// symbol `b` that `a` is or holds. Rows are `a`'s kind and columns `b`'s,
/// in the order edit, insert, rename, shared: `X` meets, `.` does not.
const SAME: [&str; 4] = ["XXXX", "X.XX", "XXXX", "XXX."];
/// `a` holds `b`, however deep: an insert into `a` is no part of `b`, and
/// anything but an insert on `a` is all of it.
const HOLDS: [&str; 4] = ["XXXX", "....", "XXXX", "XXX."];
const APART: [&str; 4] = ["....", "....", "....", "...."];

const KINDS: [LeaseKind; 4] = [
    LeaseKind::Edit,
    LeaseKind::Insert,
    LeaseKind::Rename,
    LeaseKind::Shared,
];

/// Every pair of kinds over a symbol, its container, its container's
/// container and its file, its sibling and a symbol of another file; each
/// asked in both orders, since whoever comes first holds.
#[test]
fn lease_kinds_meet_by_what_holds_what() {
    let cases: [(&str, &str, [&str; 4]); 7] = [
        ("src/a.rs#Outer", "src/a.rs#Outer", SAME),
        ("src/a.rs#Outer", "src/a.rs#Outer.Inner", HOLDS),
        ("src/a.rs#Outer", "src/a.rs#Outer.Inner.m", HOLDS),
        ("src/a.rs#<file>", "src/a.rs#Outer.Inner.m", HOLDS),
        ("src/a.rs#<file>", "src/a.rs#<file>", SAME),
        ("src/a.rs#Outer.Inner.m", "src/a.rs#Outer.Inner.n", APART),
        ("src/a.rs#Outer", "src/b.rs#Outer", APART),
    ];
    for (a, b, table) in cases {
        for (row, ka) in KINDS.iter().enumerate() {
            for (col, kb) in KINDS.iter().enumerate() {
                let meets = table[row].as_bytes()[col] == b'X';
                for a_first in [true, false] {
                    let mut h = H::with_policy(shared_policy());
                    h.start_observed("sa", &["src/**"]);
                    h.start_observed("sb", &["src/**"]);
                    let ((first, s1, k1), (second, s2, k2)) = if a_first {
                        ((a, "sa", *ka), (b, "sb", *kb))
                    } else {
                        ((b, "sb", *kb), (a, "sa", *ka))
                    };
                    assert!(h.lease(s1, "l1", &[(first, k1)]).is_allow());
                    let d = h.lease(s2, "l2", &[(second, k2)]);
                    let case = format!("{ka:?} {a} / {kb:?} {b}, a first: {a_first}");
                    if meets {
                        let held = format!("lease_held:{first}:{s1}:");
                        assert!(denied_with(&d, &held), "{case}: {d:?}");
                    } else {
                        assert!(d.is_allow(), "{case}: {d:?}");
                    }
                    h.assert_replay();
                }
            }
        }
    }
}

/// A rename of a container meets an insert into it and into anything in it;
/// an insert into the file does not meet a rename of what is in the file.
#[test]
fn a_rename_meets_inserts_into_what_it_renames() {
    let mut h = H::new();
    for s in ["a", "b", "c", "d"] {
        h.start_observed(s, &["src/**"]);
    }
    let ty = "src/a.rs#Client";
    assert!(h.lease("a", "la", &[(ty, LeaseKind::Rename)]).is_allow());
    for (s, into) in [("b", ty), ("c", "src/a.rs#Client.Inner")] {
        let d = h.lease(s, "lx", &[(into, LeaseKind::Insert)]);
        assert!(denied_with(&d, &format!("lease_held:{ty}:a:")), "{d:?}");
    }
    let d = h.lease("d", "ld", &[("src/a.rs#<file>", LeaseKind::Insert)]);
    assert!(d.is_allow(), "{d:?}");
    // Released, the type takes inserts again.
    assert!(h.agent("a", release("la")).is_allow());
    assert!(h.lease("b", "lb", &[(ty, LeaseKind::Insert)]).is_allow());
    h.assert_replay();
}

/// A child and its parent hold apart: neither takes what the other holds.
/// A delegated set is renewed by the child that has it, and goes back to
/// the parent with the time the child gave it.
#[test]
fn a_child_renews_what_it_was_given_and_holds_apart_from_its_parent() {
    let mut h = three_sessions();
    let g = "src/a.rs#g";
    assert!(h.lease("a", "l1", &[(F, LeaseKind::Edit)]).is_allow());
    assert!(h.lease("a", "l2", &[(g, LeaseKind::Edit)]).is_allow());
    assert!(h.agent("a", child_op(&h, "a", "kid", &["l1"])).is_allow());

    let d = h.lease("kid", "k1", &[(g, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{g}:a:")), "{d:?}");
    let d = h.lease("a", "l3", &[(F, LeaseKind::Rename)]);
    assert!(denied_with(&d, &format!("lease_held:{F}:kid:")), "{d:?}");
    let d = h.lease("kid", "k1", &[("src/a.rs#h", LeaseKind::Edit)]);
    assert!(d.is_allow(), "the child's own lease: {d:?}");

    let d = h.agent("a", renew("l1", 10 * MIN));
    assert!(denied_with(&d, "not_own_lease"), "{d:?}");
    h.now += 5 * MIN;
    assert!(h.agent("kid", renew("l1", 10 * MIN)).is_allow());
    let until = h.now + 10 * MIN;
    assert_eq!(h.chain.state.leases["l1"].expires_ms, until);
    let d = h.agent("kid", renew("l2", 10 * MIN));
    assert!(denied_with(&d, "not_own_lease"), "{d:?}");

    let end = Op::SessionEnd {
        session: "kid".into(),
        reason: "done".into(),
    };
    assert!(h.agent("kid", end).is_allow());
    let l = &h.chain.state.leases["l1"];
    assert_eq!((l.session.as_str(), l.expires_ms), ("a", until));
    assert!(
        !h.chain.state.leases.contains_key("k1"),
        "the child's own set ends with it"
    );
    assert!(h.agent("a", renew("l1", 10 * MIN)).is_allow());
    let d = h.lease("b", "lb", &[(F, LeaseKind::Edit)]);
    assert!(denied_with(&d, &format!("lease_held:{F}:a:")), "{d:?}");
    h.assert_replay();
}

// ---------------------------------------------------------- extreme values

/// Numbers at the ends of their types, in a request or in a policy, become
/// denials: the single writer must never panic on them (#61). Tests build
/// with overflow checks, as the release profile does.
#[test]
fn extreme_numbers_are_denied_without_a_panic() {
    let mut h = H::new();
    for (session, ms) in [("s1", i64::MIN), ("s2", i64::MAX), ("s3", 0)] {
        let mut op = h.start_op(session, &["src/**"], None);
        let Op::SessionStart { expires_ms, .. } = &mut op else {
            unreachable!()
        };
        *expires_ms = ms;
        assert!(denied_with(&h.human("ayse", op), "session_ttl"), "{ms}");
    }
    let op = Op::BridgePush {
        remote: "origin".into(),
        oplog_seq: u64::MAX,
        oplog_hash: h.chain.state.head_hash.clone(),
    };
    assert!(denied_with(&h.human("ayse", op), "stale_anchor"));

    h.start_observed("s4", &["src/**"]);
    for ttl_ms in [i64::MIN, i64::MAX] {
        let op = Op::LeaseAcquire {
            set: "l1".into(),
            items: vec![LeaseItem {
                symbol: "src/a.rs#f".into(),
                kind: LeaseKind::Edit,
                names: Vec::new(),
            }],
            intent: "work".into(),
            ttl_ms,
        };
        assert!(denied_with(&h.agent("s4", op), "lease_ttl"), "{ttl_ms}");
    }
    assert!(
        h.lease("s4", "l1", &[("src/a.rs#f", LeaseKind::Edit)])
            .is_allow()
    );
    for ttl_ms in [i64::MIN, i64::MAX] {
        assert!(denied_with(
            &h.agent("s4", renew("l1", ttl_ms)),
            "lease_ttl"
        ));
    }
    h.assert_replay();
}

/// A policy whose minutes do not fit in milliseconds saturates: the
/// longest life is then as long as an `i64` goes, and nothing overflows.
#[test]
fn policy_minutes_too_large_saturate() {
    let config = DEFAULT_CONFIG
        .replace(
            "max_ttl_minutes = 480",
            &format!("max_ttl_minutes = {}", i64::MAX),
        )
        .replace(
            "max_ttl_minutes = 30",
            &format!("max_ttl_minutes = {}", i64::MAX),
        )
        .replace(
            "max_hold_minutes = 120",
            &format!("max_hold_minutes = {}", i64::MAX),
        )
        .replace(
            "window_minutes = 5",
            &format!("window_minutes = {}", i64::MAX),
        );
    let mut h = H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap());
    let mut op = h.start_op("s1", &["src/**"], None);
    let Op::SessionStart { expires_ms, .. } = &mut op else {
        unreachable!()
    };
    *expires_ms = i64::MAX;
    let d = h.human("ayse", op);
    assert!(d.is_allow(), "{d:?}");
    h.bind_observed("s1");
    let op = Op::LeaseAcquire {
        set: "l1".into(),
        items: vec![LeaseItem {
            symbol: "src/a.rs#f".into(),
            kind: LeaseKind::Edit,
            names: Vec::new(),
        }],
        intent: "work".into(),
        ttl_ms: i64::MAX,
    };
    let d = h.agent("s1", op);
    assert!(d.is_allow(), "{d:?}");
    let d = h.agent("s1", renew("l1", i64::MAX));
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

// ------------------------------------------------------------ named checks

/// `api` and `e2e`, and `e2e` for every path under `src/web/`.
fn named_checks_policy() -> PolicyBundle {
    let config = DEFAULT_CONFIG
        .replace(
            "checks = {}",
            "checks = { api = \"api-cmd\", e2e = \"e2e-cmd\" }",
        )
        .replace(
            "checks_by_path = {}",
            "checks_by_path = { \"src/web/**\" = [\"e2e\"] }",
        );
    PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap()
}

fn named(name: &str, result: CheckResult) -> Attestation {
    let mut a = pass(CheckKind::Named);
    a.result = result;
    a.details.insert("name".into(), name.into());
    a
}

fn approve_with(seq: u64, checks: &[&str]) -> Op {
    Op::Approve {
        target_seq: seq,
        note: String::new(),
        checks: checks.iter().map(|c| c.to_string()).collect(),
    }
}

fn integrate_named(h: &mut H, change: ChangeId, evidence: Vec<Attestation>) -> Decision {
    let op = Op::ChangeIntegrate {
        change,
        trunk_before: h.chain.state.trunk.clone().unwrap(),
        merged: Some(gid('e')),
        conflicts: vec![],
    };
    h.daemon(op, evidence)
}

/// An unobserved session's proposal of `sym`, waiting for a human.
fn waiting(h: &mut H, session: &str, sym: &str) -> (ChangeId, u64) {
    h.start(session, &["src/**"]);
    let set = format!("l{session}");
    assert!(h.lease(session, &set, &[(sym, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    let d = h.propose(session, c, edit(sym));
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    (c, pending_seq(h, c))
}

/// What a human names at approval the change owes: missing, failed and
/// passed, by name, with `required = false`.
#[test]
fn a_check_named_at_approval_is_owed_by_the_change() {
    let mut h = H::with_policy(named_checks_policy());
    let (c, seq) = waiting(&mut h, "s1", "src/a.rs#f");
    let d = h.human("ayse", approve_with(seq, &["api"]));
    assert!(d.reasons.contains(&"released".to_string()), "{d:?}");
    let rec = &h.chain.state.changes[&c];
    assert_eq!(rec.checks, BTreeSet::from(["api".to_string()]));
    let vc = &h.policy.config.verification;
    assert_eq!(rec.owed_checks(vc), BTreeSet::from(["api".to_string()]));
    let d = integrate_named(&mut h, c, vec![]);
    assert!(denied_with(&d, "verification_missing:api"), "{d:?}");
    assert_eq!(d.reasons.len(), 1, "{d:?}");
    h.assert_replay();

    let mut h = H::with_policy(named_checks_policy());
    let (c, seq) = waiting(&mut h, "s1", "src/a.rs#f");
    assert!(h.human("ayse", approve_with(seq, &["api"])).is_allow());
    let failed = vec![named("api", CheckResult::Fail)];
    let d = integrate_named(&mut h, c, failed);
    assert!(denied_with(&d, "verification_failed:api"), "{d:?}");
    // A pass of another check does not stand for it.
    let mut h = H::with_policy(named_checks_policy());
    let (c, seq) = waiting(&mut h, "s1", "src/a.rs#f");
    assert!(h.human("ayse", approve_with(seq, &["api"])).is_allow());
    let other = vec![named("e2e", CheckResult::Pass), pass(CheckKind::Tests)];
    let d = integrate_named(&mut h, c, other);
    assert!(denied_with(&d, "verification_missing:api"), "{d:?}");
    h.assert_replay();

    let mut h = H::with_policy(named_checks_policy());
    let (c, seq) = waiting(&mut h, "s1", "src/a.rs#f");
    assert!(h.human("ayse", approve_with(seq, &["api"])).is_allow());
    let d = integrate_named(&mut h, c, vec![named("api", CheckResult::Pass)]);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// Without a name, a change owes no named check.
#[test]
fn a_plain_approval_owes_no_named_check() {
    let mut h = H::with_policy(named_checks_policy());
    let (c, seq) = waiting(&mut h, "s1", "src/a.rs#f");
    assert!(h.human("ayse", approve_with(seq, &[])).is_allow());
    assert!(h.chain.state.changes[&c].checks.is_empty());
    assert!(integrate_named(&mut h, c, vec![]).is_allow());
    h.assert_replay();
}

/// The approval is held to the policy in force and to a proposal.
#[test]
fn an_approval_names_known_checks_of_a_proposal_once_each() {
    let mut h = H::with_policy(named_checks_policy());
    let (c, seq) = waiting(&mut h, "s1", "src/a.rs#f");
    for (checks, word) in [
        (&["zz"][..], "unknown_check:zz"),
        (&["e2e", "api"][..], "invalid_checks"),
        (&["api", "api"][..], "invalid_checks"),
        (&["build"][..], "unknown_check:build"),
    ] {
        let d = h.human("ayse", approve_with(seq, checks));
        assert!(denied_with(&d, word), "{checks:?}: {d:?}");
    }
    let many: Vec<String> = (0..33).map(|i| format!("c{i:02}")).collect();
    let many: Vec<&str> = many.iter().map(String::as_str).collect();
    let d = h.human("ayse", approve_with(seq, &many));
    assert!(d.reasons.contains(&"invalid_checks".to_string()), "{d:?}");
    // 32 is as many as one approval may name: unknown, but not too many.
    let d = h.human("ayse", approve_with(seq, &many[..32]));
    assert!(denied_with(&d, "unknown_check:c00"), "{d:?}");
    assert!(!d.reasons.contains(&"invalid_checks".to_string()), "{d:?}");
    // Nothing denied changed the pending proposal.
    assert!(h.chain.state.pending[&seq].checks.is_empty());
    let d = h.human("ayse", approve_with(seq, &["api", "e2e"]));
    assert!(d.is_allow(), "{d:?}");
    let both = BTreeSet::from(["api".to_string(), "e2e".to_string()]);
    assert_eq!(h.chain.state.changes[&c].checks, both);
    h.assert_replay();

    // A policy update is not a change: it has nothing to run.
    let config = DEFAULT_CONFIG
        .replace("policy_updates = 1", "policy_updates = 2")
        .replace("checks = {}", "checks = { api = \"api-cmd\" }");
    let mut h = H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap());
    h.enroll("bora");
    let d = h.human("ayse", Op::PolicyUpdate { policy: gid('e') });
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    let seq = *h.chain.state.pending.keys().next().unwrap();
    let d = h.human("bora", approve_with(seq, &["api"]));
    assert!(denied_with(&d, "checks_not_a_change"), "{d:?}");
    assert_eq!(d.reasons.len(), 1, "{d:?}");
    assert!(h.human("bora", approve_with(seq, &[])).is_allow());
    h.assert_replay();
}

/// With two approvals needed, each one's checks count, the first's too.
#[test]
fn every_approval_adds_its_checks() {
    let mut h = H::with_policy(named_checks_policy());
    let bora = KeyPair::generate();
    let enroll = Op::HumanEnroll {
        human: "bora".into(),
        key: file_key(&bora),
    };
    assert!(h.human("ayse", enroll).is_allow());
    h.humans.push(("bora".into(), bora));
    h.start_observed("s1", &["**"]);
    h.wrote("s1", "auth/login.rs");
    let sym = "auth/login.rs#check";
    assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
    let c = ChangeId::random();
    let d = h.propose("s1", c, edit(sym));
    assert!(d.reasons.contains(&"approvals=2".to_string()), "{d:?}");
    let seq = pending_seq(&h, c);
    let first = h.human("ayse", approve_with(seq, &["api"]));
    assert!(
        !first.reasons.contains(&"released".to_string()),
        "{first:?}"
    );
    let api = BTreeSet::from(["api".to_string()]);
    assert_eq!(h.chain.state.pending[&seq].checks, api);
    assert!(h.chain.state.changes[&c].checks.is_empty(), "not yet");
    let second = h.human("bora", approve_with(seq, &["e2e"]));
    assert!(
        second.reasons.contains(&"released".to_string()),
        "{second:?}"
    );
    let both = BTreeSet::from(["api".to_string(), "e2e".to_string()]);
    assert_eq!(h.chain.state.changes[&c].checks, both);
    h.assert_replay();
}

/// A new version of the change owes what the earlier one was asked: the
/// agent can not shed a check by proposing again.
#[test]
fn a_new_version_still_owes_the_checks_asked_before() {
    let mut h = H::with_policy(named_checks_policy());
    let (c, seq) = waiting(&mut h, "s1", "src/a.rs#f");
    assert!(h.human("ayse", approve_with(seq, &["api"])).is_allow());
    let d = integrate_named(&mut h, c, vec![]);
    assert!(denied_with(&d, "verification_missing:api"), "{d:?}");
    // Rejected, it is proposed again, and approved with nothing named.
    let version = h.chain.state.changes[&c].version;
    let d = h.propose("s1", c, edit("src/a.rs#f"));
    assert_eq!(d.outcome, Outcome::Escalate, "{d:?}");
    let seq = pending_seq(&h, c);
    assert!(h.human("ayse", approve_with(seq, &[])).is_allow());
    let rec = &h.chain.state.changes[&c];
    assert!(rec.version > version, "{rec:?}");
    assert_eq!(rec.checks, BTreeSet::from(["api".to_string()]));
    let d = integrate_named(&mut h, c, vec![]);
    assert!(denied_with(&d, "verification_missing:api"), "{d:?}");
    h.assert_replay();
}

/// `checks_by_path` names what a change owes without anyone asking, on a
/// proposal no human sees; other paths owe nothing.
#[test]
fn the_policy_names_the_checks_a_path_owes() {
    for (sym, owed) in [("src/web/page.rs#f", true), ("src/a.rs#f", false)] {
        let mut h = H::with_policy(named_checks_policy());
        h.start_observed("s1", &["src/**"]);
        let path = sym.split('#').next().unwrap();
        h.wrote("s1", path);
        assert!(h.lease("s1", "l1", &[(sym, LeaseKind::Edit)]).is_allow());
        let c = ChangeId::random();
        assert!(h.propose("s1", c, edit(sym)).is_allow());
        let vc = h.policy.config.verification.clone();
        let want: BTreeSet<String> = owed.then(|| "e2e".to_string()).into_iter().collect();
        assert_eq!(h.chain.state.changes[&c].owed_checks(&vc), want, "{sym}");
        let d = integrate_named(&mut h, c, vec![]);
        assert_eq!(
            denied_with(&d, "verification_missing:e2e"),
            owed,
            "{sym}: {d:?}"
        );
        assert_eq!(d.is_allow(), !owed, "{sym}: {d:?}");
        h.assert_replay();
    }
}

/// A batch owes what each member owes.
#[test]
fn a_batch_owes_the_checks_of_every_member() {
    let config = DEFAULT_CONFIG
        .replace("batch_size = 1", "batch_size = 3")
        .replace("checks = {}", "checks = { e2e = \"e2e-cmd\" }")
        .replace(
            "checks_by_path = {}",
            "checks_by_path = { \"src/web/**\" = [\"e2e\"] }",
        );
    let mut h = H::with_policy(PolicyBundle::parse(&config, DEFAULT_POLICY).unwrap());
    for (session, sym) in [("a", "src/a.rs#f"), ("b", "src/web/b.rs#g")] {
        h.start_observed(session, &["src/**"]);
        h.wrote(session, sym.split('#').next().unwrap());
        let set = format!("l{session}");
        assert!(h.lease(session, &set, &[(sym, LeaseKind::Edit)]).is_allow());
        assert!(h.propose(session, ChangeId::random(), edit(sym)).is_allow());
    }
    let queued = h.chain.state.queue.clone();
    let merged = [(queued[0], gid('e')), (queued[1], gid('f'))];
    let d = batch(&mut h, &merged, vec![]);
    assert!(denied_with(&d, "verification_missing:e2e"), "{d:?}");
    let d = batch(&mut h, &merged, vec![named("e2e", CheckResult::Pass)]);
    assert!(d.is_allow(), "{d:?}");
    h.assert_replay();
}

/// What named evidence comes to, alone: an error and a missing sandbox
/// count as for build and test, and a name the policy no longer defines
/// can not be met.
#[test]
fn named_evidence_is_held_like_the_built_in_checks() {
    let vc = Verification {
        checks: [("api".to_string(), "api-cmd".to_string())].into(),
        require_sandbox: true,
        ..Verification::default()
    };
    let api = BTreeSet::from(["api".to_string()]);
    let owed = vc.for_change(false, &api);
    assert!(evidence_problems(&owed, &[named("api", CheckResult::Pass)]).is_empty());
    let errored = [named("api", CheckResult::Error)];
    assert_eq!(
        evidence_problems(&owed, &errored),
        ["verification_error:api", "verification_missing:api"]
    );
    let mut bare = named("api", CheckResult::Pass);
    bare.details.remove("sandbox");
    assert_eq!(
        evidence_problems(&owed, &[bare]),
        ["unsandboxed_verification"]
    );
    // Owing nothing named, the policy's checks are not owed.
    assert!(evidence_problems(&vc.for_change(false, &BTreeSet::new()), &[]).is_empty());
    // A skipped one does not pass.
    let skipped = [named("api", CheckResult::Skipped)];
    assert_eq!(
        evidence_problems(&owed, &skipped),
        ["verification_missing:api"]
    );
    // A name on other evidence does not rename it.
    let mut tests = named("api", CheckResult::Fail);
    tests.check = CheckKind::Tests;
    let problems = evidence_problems(&vc.for_change(false, &BTreeSet::new()), &[tests]);
    assert_eq!(problems, ["verification_failed:tests"]);
    // Named evidence with no name is "named" in a denial.
    let mut nameless = named("api", CheckResult::Fail);
    nameless.details.remove("name");
    let problems = evidence_problems(&vc.for_change(false, &BTreeSet::new()), &[nameless]);
    assert_eq!(problems, ["verification_failed:named"]);
    let gone = BTreeSet::from(["gone".to_string()]);
    let owed = vc.for_change(false, &gone);
    assert_eq!(owed.checks["gone"], "");
    let fake = [named("gone", CheckResult::Fail)];
    let problems = evidence_problems(&owed, &fake);
    assert_eq!(
        problems,
        ["verification_failed:gone", "verification_missing:gone"]
    );
}
