//! The independent auditor ("the gatekeeper's gatekeeper").
//!
//! Reads a repository (the daemon's store, a pushed remote or a CI checkout)
//! without writing to it and checks that:
//! 1. the operation log is an unbroken, correctly signed hash chain whose
//!    time never goes backwards;
//! 2. every decision is reproduced by the decision function from the state
//!    before it and the policy in force at that point;
//! 3. every recorded fact set equals the facts recomputed from the Git
//!    objects, and every merged commit equals the recomputed merge, both
//!    with the symbol engine version recorded in the entry;
//! 4. every daemon key switch (`daemon.rotate`, `daemon.recover`) was
//!    authorised: its decision replays as allowed, so a forged human
//!    signature can not move the log to another key;
//! 5. trunk and policy refs equal the replayed state;
//! 6. (`compare`) a pushed log is a prefix of the local one, so history that
//!    was published can not be rewritten unnoticed.
//!
//! It contains no AI and calls no network.

#![forbid(unsafe_code)]
// The trusted core: a panic in the single writer stops every repository,
// so bad input must become an error or a denial (clippy.toml lets tests panic).
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::sync::Arc;

use lonca_core::oplog::{OpLog, SignedOp, verify_chain};
use lonca_core::ops::Op;
use lonca_core::{ChangeId, GitId, Result, Store};
use lonca_policy::config::{CONFIG_FILE, Config, POLICY_FILE, PolicyBundle};
use lonca_policy::decide::{Ctx, decide};
use lonca_policy::state::State;
use lonca_symbols::engine;
use lonca_symbols::integrate::{facts_of, integrate_joining};
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
    /// Every daemon key switch along the log, for the reader to see.
    pub key_switches: Vec<KeySwitch>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeySwitch {
    pub seq: u64,
    /// `daemon.rotate` or `daemon.recover`.
    pub kind: String,
    /// Who requested it (`human:<name>`).
    pub actor: String,
    pub key: String,
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
    /// Compare the refs with the replayed state: trunk, policy, every
    /// proposal's ref, and no name under `refs/lonca/` the daemon never
    /// writes.
    pub check_refs: bool,
    /// Hold every ref to that, not only Lonca's: for the daemon's own store,
    /// or a remote nothing but Lonca pushes to. A clone has its remotes'
    /// branches and tags as well, which are not the log's.
    pub all_refs: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            deep: true,
            check_refs: true,
            all_refs: false,
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
        let engine_known = match e.engine().map(engine::check) {
            Some(Err(err)) => {
                rep.find(Some(e.seq), "engine", err.to_string());
                false
            }
            _ => true,
        };
        if opts.deep && engine_known {
            recheck_objects(store, &state, &policy.config, op, &mut rep);
        }
        let d = decide(
            &state,
            &e.actor,
            &e.op,
            e.human.as_ref(),
            &Ctx {
                format: e.format,
                time_ms: e.time_ms,
                policy: &policy,
                facts: e.facts.as_ref(),
                evidence: &e.evidence,
                symbols_engine: e.symbols_engine,
            },
        );
        if let Some(key) = e.switches_daemon_key() {
            rep.key_switches.push(KeySwitch {
                seq: e.seq,
                kind: e.op.kind().as_str().into(),
                actor: e.actor.label(),
                key: key.into(),
            });
        }
        if d != e.decision {
            let kind = if e.op.daemon_key_switch().is_some() {
                "daemon_key"
            } else {
                "decision"
            };
            rep.find(
                Some(e.seq),
                kind,
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
        check_other_refs(store, &state, opts.all_refs, &mut rep);
    }
    rep
}

/// The refs besides trunk and policy, as the daemon's `reconcile()` holds
/// them (`lonca_policy::refs`). A proposal's ref past the end of the log is
/// reported too: the log was cut short, or the daemon stopped between
/// writing the ref and logging the proposal (it removes such a ref when it
/// starts).
fn check_other_refs(store: &Store, state: &State, all: bool, rep: &mut Report) {
    use lonca_policy::refs::{RefCheck, check, missing_changes};
    let refs = match store.refs_with_prefix(if all { "refs/" } else { "refs/lonca/" }) {
        Ok(r) => r,
        Err(err) => return rep.find(None, "ref", format!("listing refs: {err}")),
    };
    let present = refs.iter().map(|(n, _)| n.clone()).collect();
    for (name, found) in &refs {
        if name == TRUNK_REF || name == POLICY_REF {
            continue;
        }
        let said = match check(state, name, found) {
            RefCheck::Fine => continue,
            RefCheck::Differs(want) => format!("{name} is {found}, the log says {want:?}"),
            RefCheck::NotLogged => {
                format!("{name} names a proposal past the end of the log")
            }
            RefCheck::Unknown => format!("{name} ({found}) is no ref the log has"),
        };
        rep.find(None, "ref", said);
    }
    for (name, commit) in missing_changes(state, &present) {
        rep.find(
            None,
            "ref",
            format!("{name} is missing; the log says {commit}"),
        );
    }
}

/// Recomputes facts and merges. `state` is the one before `op`: what a merge
/// may join comes from it, as it did in the daemon.
fn recheck_objects(store: &Store, state: &State, config: &Config, op: &SignedOp, rep: &mut Report) {
    let e = &op.entry;
    let engine = e.engine().unwrap_or(engine::ENGINE_CURRENT);
    match &e.op {
        Op::ChangePropose { base, commit, .. } => {
            if !store.has_object(commit) || !store.has_object(base) {
                rep.skip(e.seq, "facts", "proposal objects not present");
                return;
            }
            match facts_of(store, engine, base, commit) {
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
            let joins = state.joins(*change, &[], config);
            let may_join = |s: &str| joins.allows(s);
            match integrate_joining(
                store,
                engine,
                &rec.base,
                trunk_before,
                &rec.commit,
                &may_join,
            ) {
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
        Op::ChangeIntegrateBatch {
            trunk_before,
            merged,
        } => {
            let mut trunk = trunk_before.clone();
            let members: Vec<ChangeId> = merged.iter().map(|(c, _)| *c).collect();
            for (k, (change, commit)) in merged.iter().enumerate() {
                let Some(rec) = state.changes.get(change) else {
                    return;
                };
                if !store.has_object(&rec.commit) || !store.has_object(&trunk) {
                    rep.skip(e.seq, "merge", "integration objects not present");
                    return;
                }
                let joins = state.joins(*change, members.get(..k).unwrap_or_default(), config);
                let may_join = |s: &str| joins.allows(s);
                match integrate_joining(store, engine, &rec.base, &trunk, &rec.commit, &may_join) {
                    Ok(i) if i.merged.as_ref() == Some(commit) => {}
                    Ok(i) => {
                        let found = format!("recorded {commit:?}, recomputed {:?}", i.merged);
                        rep.find(Some(e.seq), "merge", found);
                        return;
                    }
                    Err(err) => {
                        rep.find(Some(e.seq), "merge", err.to_string());
                        return;
                    }
                }
                trunk = commit.clone();
            }
            // What was verified is the tip, which is what trunk became.
            match store.read_commit(&trunk) {
                Ok(tip)
                    if !e.evidence.is_empty()
                        && e.evidence.iter().all(|a| a.subject_tree == tip.tree) => {}
                Ok(_) => rep.find(Some(e.seq), "merge", "evidence of another tree".to_string()),
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
