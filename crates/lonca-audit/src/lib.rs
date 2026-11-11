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
//! It also notes, without finding fault, every daemon key switch and every
//! check that ran in another environment than the last time it ran.
//!
//! It contains no AI and calls no network.

#![forbid(unsafe_code)]
// The trusted core: a panic in the single writer stops every repository,
// so bad input must become an error or a denial (clippy.toml lets tests panic).
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::sync::Arc;

use lonca_core::keyed::KeyedDirs;
use lonca_core::oplog::{FORMAT_KEYED, OpLog, SignedOp, verify_chain};
use lonca_core::ops::{Attestation, Op};
use lonca_core::{ChangeId, GitId, Result, Store};
use lonca_policy::config::{CONFIG_FILE, Config, POLICY_FILE, PolicyBundle};
use lonca_policy::decide::{Ctx, decide, evidence_name};
use lonca_policy::state::State;
use lonca_symbols::engine;
use lonca_symbols::integrate::{facts_keyed, integrate_joining};
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
    /// The hash of the first entry: what names this log among all logs.
    /// It covers the repository's name, its first daemon key and its
    /// owner's key, so a log made with other keys has another.
    pub genesis_hash: String,
    pub findings: Vec<Finding>,
    /// Rechecks skipped because objects were missing (e.g. a shallow clone).
    pub skipped: Vec<Finding>,
    /// Every daemon key switch along the log, for the reader to see.
    pub key_switches: Vec<KeySwitch>,
    /// Every check whose environment changed since it last ran, for the
    /// reader to see: evidence is recorded, never recomputed, so a new
    /// toolchain is no fault, only worth knowing.
    pub env_changes: Vec<EnvChange>,
}

/// A check whose `env` digest differs from the one it had at the last
/// entry that ran it: another toolchain, `PATH`, sandbox or command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EnvChange {
    pub seq: u64,
    /// `build`, `tests`, `extended`, or a named check's name.
    pub check: String,
    /// The entry where it last ran.
    pub since: u64,
}

/// The checks of each entry's evidence, in log order, whose environment
/// differs from the last entry that had them.
pub fn env_changes<'a>(
    entries: impl IntoIterator<Item = (u64, &'a [Attestation])>,
) -> Vec<EnvChange> {
    let mut last: BTreeMap<&str, (u64, &str)> = BTreeMap::new();
    let mut out = Vec::new();
    for (seq, evidence) in entries {
        for a in evidence {
            let check = evidence_name(a);
            if let Some((since, env)) = last.insert(check, (seq, &a.env))
                && env != a.env
            {
                out.push(EnvChange {
                    seq,
                    check: check.to_string(),
                    since,
                });
            }
        }
    }
    out
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

/// What the reader already knows of the log, from somewhere the log's
/// writer can not reach. A log proves that it is whole and that its
/// daemon key signed it; which log it is, and that it is not an older
/// state of itself, only something outside it can say.
#[derive(Clone, Debug, Default)]
pub struct Anchor {
    /// The hash of the first entry (`genesis:` in a report).
    pub genesis: Option<String>,
    /// The hash of an entry the log had before (`head:` of an earlier
    /// report): the log must still have it.
    pub extends: Option<String>,
}

impl Anchor {
    /// Why `ops`, a chain that verified, is not the log this names.
    fn mismatch(&self, ops: &[SignedOp]) -> Option<String> {
        let genesis = ops.first().map(|o| o.hash.as_str()).unwrap_or_default();
        if let Some(want) = &self.genesis
            && want != genesis
        {
            return Some(format!(
                "this is another log: its genesis is {genesis}, not {want}"
            ));
        }
        if let Some(want) = &self.extends
            && !ops.iter().any(|o| o.hash == *want)
        {
            return Some(format!(
                "the log does not have entry {want}: it was replaced, or taken back to before it"
            ));
        }
        None
    }
}

pub fn audit(store: &Store, opts: Options) -> Result<Report> {
    audit_anchored(store, opts, &Anchor::default())
}

/// [`audit`] of a log that must be the one `anchor` names.
pub fn audit_anchored(store: &Store, opts: Options, anchor: &Anchor) -> Result<Report> {
    let ops = OpLog::new(store).read_all()?;
    Ok(audit_ops_anchored(store, &ops, opts, anchor))
}

pub fn audit_ops(store: &Store, ops: &[SignedOp], opts: Options) -> Report {
    audit_ops_anchored(store, ops, opts, &Anchor::default())
}

pub fn audit_ops_anchored(
    store: &Store,
    ops: &[SignedOp],
    opts: Options,
    anchor: &Anchor,
) -> Report {
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
    rep.genesis_hash = ops.first().map(|o| o.hash.clone()).unwrap_or_default();
    // Before anything of the log is replayed or recomputed: a log that is
    // not the expected one is somebody else's input, and old symbol
    // engines have no bounds on what they are asked to read.
    if let Some(why) = anchor.mismatch(ops) {
        rep.find(None, "anchor", why);
        return rep;
    }
    rep.env_changes = env_changes(
        ops.iter()
            .map(|o| (o.entry.seq, o.entry.evidence.as_slice())),
    );
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
    // `PolicyBundle::parse` compiled these when the policy came in.
    let keyed = config.paths.keyed_dirs().unwrap_or_default();
    let none = KeyedDirs::default();
    // Facts name taken keys from format 29 on.
    let facts_keys = if e.format >= FORMAT_KEYED {
        &keyed
    } else {
        &none
    };
    match &e.op {
        Op::ChangePropose { base, commit, .. } => {
            if !store.has_object(commit) || !store.has_object(base) {
                rep.skip(e.seq, "facts", "proposal objects not present");
                return;
            }
            match facts_keyed(store, engine, base, commit, facts_keys) {
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
                &keyed,
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
                match integrate_joining(
                    store,
                    engine,
                    &rec.base,
                    &trunk,
                    &rec.commit,
                    &may_join,
                    &keyed,
                ) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use lonca_core::ops::{CheckKind, CheckResult};

    fn check(kind: CheckKind, name: Option<&str>, env: &str) -> Attestation {
        Attestation {
            check: kind,
            result: CheckResult::Pass,
            subject_tree: GitId::of_blob(b"tree"),
            details: name
                .map(|n| ("name".to_string(), n.to_string()))
                .into_iter()
                .collect(),
            env: env.into(),
            log: None,
            producer: "test".into(),
        }
    }

    #[test]
    fn a_check_in_another_environment_than_its_last_run_is_noted() {
        let build = |env| check(CheckKind::Build, None, env);
        let tests = |env| check(CheckKind::Tests, None, env);
        let api = |env| check(CheckKind::Named, Some("api"), env);
        let e3 = [build("a"), tests("t")];
        let e5 = [build("a"), tests("t2"), api("x")];
        let e6: [Attestation; 0] = [];
        let e8 = [build("b"), api("y")];
        let e9 = [build("b"), check(CheckKind::Named, Some("e2e"), "y")];
        let entries: [(u64, &[Attestation]); 5] =
            [(3, &e3), (5, &e5), (6, &e6), (8, &e8), (9, &e9)];
        let note = |seq, check: &str, since| EnvChange {
            seq,
            check: check.into(),
            since,
        };
        assert_eq!(
            env_changes(entries),
            [note(5, "tests", 3), note(8, "build", 5), note(8, "api", 5)]
        );
        assert!(env_changes([(1, &e3[..]), (2, &e3[..])]).is_empty());
        // The last run, not the first: back to "a" after "b" is a change too.
        let back = [build("a")];
        let notes = env_changes([(1, &e3[..]), (2, &e8[..]), (4, &back[..])]);
        assert_eq!(notes, [note(2, "build", 1), note(4, "build", 2)]);
    }
}
