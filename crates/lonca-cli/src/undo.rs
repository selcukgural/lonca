//! Undo: the log is never rewritten; every undo is a new, compensating
//! operation that goes through the Gatekeeper like any other.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, bail};
use base64::Engine;
use lonca_core::oplog::{OpEntry, SignedOp};
use lonca_core::ops::Op;
use lonca_core::{ChangeId, GitId};
use lonca_daemon::Client;
use lonca_daemon::protocol::{FileChange, TreeFile};
use lonca_symbols::engine::ENGINE_CURRENT;
use serde_json::json;

use crate::ctx::call;
use crate::workspace::{fetch, fill, listed};

/// Entries from `from`, at most `limit` of them (all with `None`). The
/// daemon answers a page at a time, so a longer log takes several requests:
/// one alone would plan a revert from the first page and undo a policy
/// update to a policy older than the one before it.
fn ops(c: &mut Client, from: u64, limit: Option<u64>) -> Result<Vec<SignedOp>> {
    entries(from, limit, crate::LOG_PAGE, |from, limit| {
        let page = call(c, "log", json!({"from": from, "limit": limit}))?;
        Ok(page.as_array().cloned().unwrap_or_default())
    })
}

fn entries(
    from: u64,
    limit: Option<u64>,
    page: u64,
    fetch: impl FnMut(u64, u64) -> Result<Vec<serde_json::Value>>,
) -> Result<Vec<SignedOp>> {
    let pages = crate::log_pages(from, limit, page, fetch)?;
    let entries = pages.into_iter().map(serde_json::from_value);
    Ok(entries.collect::<Result<_, _>>()?)
}

fn trunk(c: &mut Client) -> Result<GitId> {
    Ok(serde_json::from_value(
        call(c, "status", json!({}))?["trunk"].clone(),
    )?)
}

fn decode(f: Option<&TreeFile>) -> Option<Vec<u8>> {
    f.and_then(|f| f.content_b64.as_ref())
        .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok())
}

/// Files that turn `after` back into `before` on top of current trunk.
fn reverse_range(
    c: &mut Client,
    before: &GitId,
    after: &GitId,
) -> Result<(GitId, Vec<FileChange>)> {
    let t = trunk(c)?;
    // What each commit has, by path; contents only of what differs.
    let by_path = |files: Vec<TreeFile>| -> BTreeMap<String, TreeFile> {
        files.into_iter().map(|f| (f.path.clone(), f)).collect()
    };
    let mut b = by_path(listed(c, before, None)?);
    let mut a = by_path(listed(c, after, None)?);
    let changed: BTreeSet<String> = b
        .keys()
        .chain(a.keys())
        .filter(|p| b.get(*p).map(|f| &f.blob) != a.get(*p).map(|f| &f.blob))
        .cloned()
        .collect();
    fill(
        c,
        before,
        b.values_mut().filter(|f| changed.contains(&f.path)),
    )?;
    fill(
        c,
        after,
        a.values_mut().filter(|f| changed.contains(&f.path)),
    )?;
    let now = by_path(fetch(c, &t, Some(changed.iter().cloned().collect()))?);
    let get = |v: &BTreeMap<String, TreeFile>, p: &str| v.get(p).cloned();
    let mut out = Vec::new();
    let mut conflicts = Vec::new();
    for p in &changed {
        let (bf, af, nf) = (get(&b, p), get(&a, p), get(&now, p));
        let (bt, at, nt) = (
            decode(bf.as_ref()),
            decode(af.as_ref()),
            decode(nf.as_ref()),
        );
        let target: Option<Vec<u8>> = match (&bt, &at, &nt) {
            // Trunk still has exactly what the operation produced: restore.
            (_, _, n) if n == &at => bt.clone(),
            (Some(bv), Some(av), Some(nv)) => {
                let s = |x: &Vec<u8>| String::from_utf8(x.clone()).ok();
                match (s(av), s(nv), s(bv)) {
                    (Some(av), Some(nv), Some(bv)) => {
                        match lonca_symbols::merge::merge_text_at(ENGINE_CURRENT, p, &av, &nv, &bv)
                        {
                            Ok(m) => Some(m.into_bytes()),
                            Err(_) => {
                                conflicts.push(p.clone());
                                continue;
                            }
                        }
                    }
                    _ => {
                        conflicts.push(p.clone());
                        continue;
                    }
                }
            }
            _ => {
                conflicts.push(p.clone());
                continue;
            }
        };
        if target == nt {
            continue;
        }
        out.push(FileChange {
            path: p.clone(),
            content_b64: target.map(|t| base64::engine::general_purpose::STANDARD.encode(t)),
            mode: bf.map(|f| f.mode),
        });
    }
    if !conflicts.is_empty() {
        bail!(
            "later changes conflict with the undo in: {}",
            conflicts.join(", ")
        );
    }
    Ok((t, out))
}

fn revert_change(
    c: &mut Client,
    human: &str,
    repo: &str,
    before: &GitId,
    after: &GitId,
    change: Option<ChangeId>,
    what: &str,
) -> Result<()> {
    let (base, files) = reverse_range(c, before, after)?;
    if files.is_empty() {
        outln!("nothing to undo: trunk no longer contains {what}");
        return Ok(());
    }
    let prep = call(
        c,
        "human.prepare_change",
        json!({"base": base, "files": files, "author": human, "intent": format!("Undo {what}"), "revert_of": change}),
    )?;
    crate::submit(c, human, repo, serde_json::from_value(prep["op"].clone())?)?;
    Ok(())
}

/// The compensating operation for `seq`, submitted as `human`.
pub fn undo(c: &mut Client, human: &str, repo: &str, seq: u64) -> Result<()> {
    let target = ops(c, seq, Some(1))?
        .into_iter()
        .next()
        .context("no such operation")?;
    if !target.entry.decision.is_allow() {
        bail!("operation {seq} was not allowed; there is nothing to undo");
    }
    match &target.entry.op {
        Op::ChangeIntegrate {
            change,
            trunk_before,
            merged: Some(m),
            ..
        } => revert_change(
            c,
            human,
            repo,
            trunk_before,
            m,
            Some(*change),
            &format!("change {}", change.short()),
        ),
        Op::ImportExternal {
            commit,
            trunk_before,
            remote,
        } => revert_change(
            c,
            human,
            repo,
            trunk_before,
            commit,
            None,
            &format!("import from {remote}"),
        ),
        Op::ChangePropose { change, .. } => {
            crate::submit(c, human, repo, Op::ChangeWithdraw { change: *change })?;
            Ok(())
        }
        Op::LeaseAcquire { set, .. } => {
            crate::submit(c, human, repo, Op::LeaseRelease { set: set.clone() })?;
            Ok(())
        }
        Op::SessionStart { session, .. } | Op::CapAttenuate { child: session, .. } => {
            crate::submit(
                c,
                human,
                repo,
                Op::CapRevoke {
                    session: session.clone(),
                    reason: format!("undo of operation {seq}"),
                },
            )?;
            Ok(())
        }
        Op::Freeze { .. } => {
            crate::submit(
                c,
                human,
                repo,
                Op::Unfreeze {
                    reason: format!("undo of operation {seq}"),
                },
            )?;
            Ok(())
        }
        Op::PolicyUpdate { .. } => {
            // The policy before this update: the last policy-defining
            // operation that precedes it.
            let earlier = ops(c, 0, Some(seq))?;
            let previous = earlier
                .iter()
                .rev()
                .find_map(|o| match (&o.entry.op, o.entry.decision.is_allow()) {
                    (Op::PolicyUpdate { policy }, true) | (Op::RepoInit { policy, .. }, true) => {
                        Some(policy.clone())
                    }
                    _ => None,
                })
                .context("no earlier policy")?;
            let files = fetch(c, &previous, None)?;
            let text = |name: &str| -> Result<String> {
                let f = files
                    .iter()
                    .find(|f| f.path == name)
                    .context("policy file missing")?;
                Ok(String::from_utf8(decode(Some(f)).unwrap_or_default())?)
            };
            let prep = call(
                c,
                "human.prepare_policy",
                json!({"config": text("lonca.toml")?, "policy": text("policy.cedar")?}),
            )?;
            crate::submit(c, human, repo, serde_json::from_value(prep["op"].clone())?)?;
            Ok(())
        }
        Op::ChangeIntegrateBatch {
            trunk_before,
            merged,
        } => {
            // One revert of all of it: the batch was verified whole, so a tree
            // between two of its changes may fail, and the worker would take
            // one revert without the other.
            let (last, tip) = merged.last().context("a batch of no changes")?;
            let names: Vec<String> = merged.iter().map(|(change, _)| change.short()).collect();
            let what = format!("changes {}", names.join(", "));
            revert_change(c, human, repo, trunk_before, tip, Some(*last), &what)
        }
        other => bail!("{} can not be undone automatically", other.kind().as_str()),
    }
}

fn matches_actor(label: &str, session: Option<&str>, want: &str) -> bool {
    label == want || label.starts_with(&format!("{want}/")) || session == Some(want)
}

/// A change of a batch: the commit in front of it, the one it came to, and
/// which it was.
type BatchStep = (GitId, GitId, ChangeId);

/// What the changes of `mine` in a batch came to, each from the commit in
/// front of it: an actor's changes, and no others of its batch.
fn steps_of(
    trunk_before: &GitId,
    merged: &[(ChangeId, GitId)],
    mine: &BTreeSet<ChangeId>,
) -> Vec<BatchStep> {
    let befores = std::iter::once(trunk_before).chain(merged.iter().map(|(_, commit)| commit));
    let steps = befores.zip(merged);
    let steps = steps.filter(|(_, (change, _))| mine.contains(change));
    steps
        .map(|(before, (change, commit))| (before.clone(), commit.clone(), *change))
        .collect()
}

/// An operation to undo, what it is in words and, for a change of a batch,
/// what it came to, which is not all of its entry.
type Planned = (u64, String, Option<BatchStep>);

/// What `actor` did since `since`, the last first.
fn plan_of(all: &[OpEntry], actor: &str, since: u64) -> Vec<Planned> {
    let mut mine: BTreeSet<ChangeId> = BTreeSet::new();
    let mut plan: Vec<Planned> = Vec::new();
    for e in all {
        let by_actor = matches_actor(&e.actor.label(), e.actor.session(), actor);
        if by_actor && let Op::ChangePropose { change, .. } = &e.op {
            mine.insert(*change);
        }
        if e.seq < since || !e.decision.is_allow() {
            continue;
        }
        match &e.op {
            Op::ChangeIntegrate {
                change,
                merged: Some(_),
                ..
            } if mine.contains(change) => {
                plan.push((
                    e.seq,
                    format!("revert integrated change {}", change.short()),
                    None,
                ));
            }
            Op::ChangeIntegrateBatch {
                trunk_before,
                merged,
            } => {
                for step in steps_of(trunk_before, merged, &mine) {
                    let what = format!("revert integrated change {}", step.2.short());
                    plan.push((e.seq, what, Some(step)));
                }
            }
            Op::LeaseAcquire { set, .. } if by_actor => {
                plan.push((e.seq, format!("release lease set {set}"), None))
            }
            Op::CapAttenuate { child, .. } if by_actor => {
                plan.push((e.seq, format!("revoke sub-session {child}"), None))
            }
            _ => {}
        }
    }
    plan.reverse();
    plan
}

/// Plans (and with `apply` executes) undoing what `actor` did since `since`.
pub fn revert(
    c: &mut Client,
    human: &str,
    repo: &str,
    actor: &str,
    since: u64,
    apply: bool,
) -> Result<()> {
    let all: Vec<OpEntry> = ops(c, 0, None)?.into_iter().map(|o| o.entry).collect();
    let plan = plan_of(&all, actor, since);
    if plan.is_empty() {
        outln!("nothing to revert for {actor} since #{since}");
        return Ok(());
    }
    for (seq, what, _) in &plan {
        outln!("#{seq}: {what}");
    }
    if !apply {
        outln!("(dry run; pass --apply to submit these compensating operations)");
        return Ok(());
    }
    // One refused step does not stop the others; the command still ends
    // with the refusal, so a runner sees it in the exit code.
    let mut first_failure = None;
    for (seq, what, of_batch) in plan {
        let done = match of_batch {
            None => undo(c, human, repo, seq),
            Some((before, after, change)) => {
                let label = format!("change {}", change.short());
                revert_change(c, human, repo, &before, &after, Some(change), &label)
            }
        };
        if let Err(e) = done {
            outln!("#{seq} ({what}) not undone: {e:#}");
            first_failure.get_or_insert(e);
        }
    }
    first_failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod batch_tests {
    use super::*;
    use lonca_core::ops::{Actor, Claim, Decision, Scope};

    fn entry(seq: u64, actor: Actor, op: Op) -> OpEntry {
        OpEntry {
            format: 1,
            seq,
            prev: String::new(),
            time_ms: 0,
            actor,
            op,
            evidence: vec![],
            facts: None,
            symbols_engine: None,
            decision: Decision::allow(),
            human: None,
        }
    }

    /// A log longer than a page is read whole, and a range ends where it
    /// was asked to: the daemon never answers more than a page.
    #[test]
    fn the_log_is_read_past_the_first_page() {
        let log: Vec<serde_json::Value> = (0..5)
            .map(|seq| {
                let op = Op::Freeze {
                    reason: format!("r{seq}"),
                };
                let entry = entry(seq, Actor::Daemon, op);
                let signed = SignedOp {
                    entry,
                    hash: String::new(),
                    sig: String::new(),
                };
                serde_json::to_value(signed).unwrap()
            })
            .collect();
        let daemon = |from: u64, limit: u64| {
            let end = (from + limit.min(2)).min(log.len() as u64);
            Ok(log[from.min(end) as usize..end as usize].to_vec())
        };
        let seqs = |ops: Vec<SignedOp>| ops.iter().map(|o| o.entry.seq).collect::<Vec<_>>();
        assert_eq!(seqs(entries(0, None, 2, daemon).unwrap()), [0, 1, 2, 3, 4]);
        assert_eq!(seqs(entries(0, Some(3), 2, daemon).unwrap()), [0, 1, 2]);
        assert_eq!(seqs(entries(4, Some(1), 2, daemon).unwrap()), [4]);
        let bad = |from: u64, _| {
            Ok(vec![json!({"no": "entry"})]
                .into_iter()
                .take((from == 0).into())
                .collect())
        };
        assert!(entries(0, None, 2, bad).is_err());
    }

    /// Only `ann`'s: of two sessions alike, of a batch with `bob`'s change.
    #[test]
    fn a_revert_plans_only_what_its_actor_did() {
        let id = |c: &[u8]| GitId::of_blob(c);
        let (trunk, one, two) = (id(b"t"), id(b"1"), id(b"2"));
        let (a, b) = (ChangeId::random(), ChangeId::random());
        let agent = |name: &str| Actor::Agent {
            name: name.into(),
            session: format!("ses_{name}"),
        };
        let propose = |change| Op::ChangePropose {
            change,
            commit: id(b"c"),
            base: trunk.clone(),
            claim: Claim::default(),
        };
        let lease = |set: &str| Op::LeaseAcquire {
            set: set.into(),
            items: vec![],
            intent: "fix".into(),
            ttl_ms: 1,
        };
        let cap = |child: &str| Op::CapAttenuate {
            parent: "p".into(),
            child: child.into(),
            agent: "x".into(),
            scope: Scope {
                paths: vec![],
                symbols: None,
                ops: vec![],
                max_files: None,
                max_lines: None,
                scratch: vec![],
            },
            expires_ms: 1,
            leases: vec![],
        };
        let merged = vec![(a, one.clone()), (b, two.clone())];
        let batch = Op::ChangeIntegrateBatch {
            trunk_before: trunk.clone(),
            merged,
        };
        let all = [
            entry(0, agent("ann"), propose(a)),
            entry(1, agent("bob"), propose(b)),
            entry(2, agent("ann"), lease("mine")),
            entry(3, agent("bob"), lease("theirs")),
            entry(4, agent("ann"), cap("my_child")),
            entry(5, agent("bob"), cap("their_child")),
            entry(6, Actor::Daemon, batch),
        ];
        let plan = plan_of(&all, "agent:ann", 0);
        let seqs: Vec<u64> = plan.iter().map(|p| p.0).collect();
        assert_eq!(seqs, [6, 4, 2], "{plan:?}");
        assert_eq!(plan[0].2, Some((trunk.clone(), one, a)));
        assert_eq!(plan[1].1, "revoke sub-session my_child");
        assert_eq!(plan[2].1, "release lease set mine");
        assert_eq!(plan_of(&all, "agent:ann", 3).len(), 2);
    }

    #[test]
    fn a_batch_gives_back_only_the_changes_asked_for() {
        let id = |c: &[u8]| GitId::of_blob(c);
        let (trunk, one, two, three) = (id(b"t"), id(b"1"), id(b"2"), id(b"3"));
        let (a, b, c) = (ChangeId::random(), ChangeId::random(), ChangeId::random());
        let merged = [(a, one.clone()), (b, two.clone()), (c, three.clone())];
        let steps = |mine: &[ChangeId]| steps_of(&trunk, &merged, &mine.iter().copied().collect());
        assert_eq!(steps(&[]), []);
        assert_eq!(steps(&[a]), [(trunk.clone(), one.clone(), a)]);
        assert_eq!(steps(&[b]), [(one.clone(), two.clone(), b)]);
        assert_eq!(steps(&[c, a]), [(trunk.clone(), one, a), (two, three, c)]);
    }
}
