//! The independent auditor ("the gatekeeper's gatekeeper").
//!
//! Reads a repository (the daemon's store, a pushed remote or a CI checkout)
//! without writing to it and checks that:
//! 1. the operation log is an unbroken, correctly signed hash chain whose
//!    time never goes backwards;
//! 2. every decision is reproduced by the decision function from the state
//!    before it and the policy in force at that point;
//! 3. every recorded fact set equals the facts recomputed from the Git
//!    objects, and every merged commit equals the recomputed merge;
//! 4. trunk and policy refs equal the replayed state;
//! 5. (`compare`) a pushed log is a prefix of the local one, so history that
//!    was published can not be rewritten unnoticed.
//!
//! It contains no AI and calls no network.

use std::collections::BTreeMap;
use std::sync::Arc;

use lonca_core::oplog::{OpLog, SignedOp, verify_chain};
use lonca_core::ops::Op;
use lonca_core::{GitId, Result, Store};
use lonca_policy::config::{CONFIG_FILE, POLICY_FILE, PolicyBundle};
use lonca_policy::decide::{Ctx, decide};
use lonca_policy::state::State;
use lonca_symbols::integrate::{facts_of, integrate};
use serde::Serialize;

pub const TRUNK_REF: &str = "refs/heads/main";
pub const POLICY_REF: &str = "refs/lonca/policy";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub seq: Option<u64>,
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub ops: u64,
    pub head_hash: String,
    pub findings: Vec<Finding>,
    /// Rechecks skipped because objects were missing (e.g. a shallow clone).
    pub skipped: Vec<Finding>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.findings.is_empty()
    }

    fn find(&mut self, seq: Option<u64>, kind: &str, detail: impl Into<String>) {
        self.findings.push(Finding {
            seq,
            kind: kind.into(),
            detail: detail.into(),
        });
    }

    fn skip(&mut self, seq: u64, kind: &str, detail: impl Into<String>) {
        self.skipped.push(Finding {
            seq: Some(seq),
            kind: kind.into(),
            detail: detail.into(),
        });
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Recompute facts and merges (slower, needs every object).
    pub deep: bool,
    /// Compare trunk/policy refs with the replayed state.
    pub check_refs: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            deep: true,
            check_refs: true,
        }
    }
}

fn load_policy(store: &Store, commit: &GitId) -> std::result::Result<PolicyBundle, String> {
    let read = |f: &str| -> std::result::Result<String, String> {
        let bytes = store
            .read_file(commit, f)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("missing {f}"))?;
        String::from_utf8(bytes).map_err(|_| format!("{f} is not UTF-8"))
    };
    PolicyBundle::parse(&read(CONFIG_FILE)?, &read(POLICY_FILE)?)
}

pub fn audit(store: &Store, opts: Options) -> Result<Report> {
    let ops = OpLog::new(store).read_all()?;
    Ok(audit_ops(store, &ops, opts))
}

pub fn audit_ops(store: &Store, ops: &[SignedOp], opts: Options) -> Report {
    let mut rep = Report {
        ops: ops.len() as u64,
        ..Default::default()
    };
    match verify_chain(ops) {
        Ok(h) => rep.head_hash = h,
        Err(e) => {
            rep.find(None, "chain", e.to_string());
            return rep;
        }
    }
    let default_policy = Arc::new(PolicyBundle::default_bundle());
    let mut policies: BTreeMap<GitId, Arc<PolicyBundle>> = BTreeMap::new();
    let mut state = State::new();
    for op in ops {
        let e = &op.entry;
        let policy = match &state.policy {
            None => default_policy.clone(),
            Some(id) => match policies.get(id) {
                Some(p) => p.clone(),
                None => match load_policy(store, id) {
                    Ok(p) => {
                        let p = Arc::new(p);
                        policies.insert(id.clone(), p.clone());
                        p
                    }
                    Err(err) => {
                        rep.find(
                            Some(e.seq),
                            "policy",
                            format!("policy {} unreadable: {err}", id.short()),
                        );
                        return rep;
                    }
                },
            },
        };
        if opts.deep {
            recheck_objects(store, &state, op, &mut rep);
        }
        let d = decide(
            &state,
            &e.actor,
            &e.op,
            e.human.as_ref(),
            &Ctx {
                time_ms: e.time_ms,
                policy: &policy,
                facts: e.facts.as_ref(),
                evidence: &e.evidence,
            },
        );
        if d != e.decision {
            rep.find(
                Some(e.seq),
                "decision",
                format!(
                    "{}: recorded {:?} {:?}, replay gives {:?} {:?}",
                    e.op.kind().as_str(),
                    e.decision.outcome,
                    e.decision.reasons,
                    d.outcome,
                    d.reasons
                ),
            );
        }
        state.apply(op);
    }
    if opts.check_refs {
        for (name, want) in [(TRUNK_REF, &state.trunk), (POLICY_REF, &state.policy)] {
            match store.ref_get(name) {
                Ok(found) if found.as_ref() == want.as_ref() => {}
                Ok(found) => rep.find(
                    None,
                    "ref",
                    format!("{name} is {found:?}, the log says {want:?}"),
                ),
                Err(err) => rep.find(None, "ref", format!("{name}: {err}")),
            }
        }
    }
    rep
}

fn recheck_objects(store: &Store, state: &State, op: &SignedOp, rep: &mut Report) {
    let e = &op.entry;
    match &e.op {
        Op::ChangePropose { base, commit, .. } => {
            if !store.has_object(commit) || !store.has_object(base) {
                rep.skip(e.seq, "facts", "proposal objects not present");
                return;
            }
            match facts_of(store, base, commit) {
                Ok(a) if Some(&a.facts) == e.facts.as_ref() => {}
                Ok(a) => rep.find(
                    Some(e.seq),
                    "facts",
                    format!("recorded facts differ from recomputed {:?}", a.facts),
                ),
                Err(err) => rep.find(Some(e.seq), "facts", err.to_string()),
            }
        }
        Op::ChangeIntegrate {
            change,
            trunk_before,
            merged,
            conflicts,
        } => {
            let Some(rec) = state.changes.get(change) else {
                return;
            };
            if !store.has_object(&rec.commit) || !store.has_object(trunk_before) {
                rep.skip(e.seq, "merge", "integration objects not present");
                return;
            }
            match integrate(store, &rec.base, trunk_before, &rec.commit) {
                Ok(i) => {
                    if &i.merged != merged || &i.conflicts != conflicts {
                        rep.find(
                            Some(e.seq),
                            "merge",
                            format!(
                                "recorded {merged:?} {conflicts:?}, recomputed {:?} {:?}",
                                i.merged, i.conflicts
                            ),
                        );
                    }
                }
                Err(err) => rep.find(Some(e.seq), "merge", err.to_string()),
            }
        }
        _ => {}
    }
}

/// Checks that `published` is a prefix of `local`: everything that was
/// pushed is still in the local log, unchanged.
pub fn compare(local: &[SignedOp], published: &[SignedOp]) -> Vec<Finding> {
    let mut out = Vec::new();
    if published.len() > local.len() {
        out.push(Finding {
            seq: Some(local.len() as u64),
            kind: "anchor".into(),
            detail: format!(
                "published log has {} entries, local only {}",
                published.len(),
                local.len()
            ),
        });
    }
    for (l, p) in local.iter().zip(published) {
        if l.hash != p.hash {
            out.push(Finding {
                seq: Some(p.entry.seq),
                kind: "anchor".into(),
                detail: "local history differs from what was published".into(),
            });
            break;
        }
    }
    out
}
