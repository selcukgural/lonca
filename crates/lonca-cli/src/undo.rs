//! Undo: the log is never rewritten; every undo is a new, compensating
//! operation that goes through the Gatekeeper like any other.

use std::collections::BTreeSet;

use anyhow::{Context, Result, bail};
use base64::Engine;
use lonca_core::oplog::SignedOp;
use lonca_core::ops::Op;
use lonca_core::{ChangeId, GitId};
use lonca_daemon::Client;
use lonca_daemon::protocol::{FileChange, TreeFile};
use lonca_symbols::engine::ENGINE_CURRENT;
use serde_json::json;

use crate::ctx::call;
use crate::workspace::fetch;

fn ops(c: &mut Client, from: u64, limit: Option<u64>) -> Result<Vec<SignedOp>> {
    Ok(serde_json::from_value(call(
        c,
        "log",
        json!({"from": from, "limit": limit}),
    )?)?)
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
    let b = fetch(c, before, None)?;
    let a = fetch(c, after, None)?;
    let changed: BTreeSet<String> = b
        .iter()
        .chain(&a)
        .map(|f| f.path.clone())
        .filter(|p| {
            b.iter().find(|f| &f.path == p).map(|f| &f.blob)
                != a.iter().find(|f| &f.path == p).map(|f| &f.blob)
        })
        .collect();
    let now = fetch(c, &t, Some(changed.iter().cloned().collect()))?;
    let get = |v: &[TreeFile], p: &str| v.iter().find(|f| f.path == p).cloned();
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
        println!("nothing to undo: trunk no longer contains {what}");
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
            // Each its own revert, the last first: a revert names one change.
            let every = merged.iter().map(|(change, _)| *change).collect();
            for (before, after, change) in steps_of(trunk_before, merged, &every).iter().rev() {
                let what = format!("change {}", change.short());
                revert_change(c, human, repo, before, after, Some(*change), &what)?;
            }
            Ok(())
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

/// Plans (and with `apply` executes) undoing what `actor` did since `since`.
pub fn revert(
    c: &mut Client,
    human: &str,
    repo: &str,
    actor: &str,
    since: u64,
    apply: bool,
) -> Result<()> {
    let all = ops(c, 0, None)?;
    let mut mine: BTreeSet<ChangeId> = BTreeSet::new();
    // With what a change of a batch came to, which is not all of its entry.
    let mut plan: Vec<(u64, String, Option<BatchStep>)> = Vec::new();
    for o in &all {
        let e = &o.entry;
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
    if plan.is_empty() {
        println!("nothing to revert for {actor} since #{since}");
        return Ok(());
    }
    for (seq, what, _) in &plan {
        println!("#{seq}: {what}");
    }
    if !apply {
        println!("(dry run; pass --apply to submit these compensating operations)");
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
            println!("#{seq} ({what}) not undone: {e:#}");
            first_failure.get_or_insert(e);
        }
    }
    first_failure.map_or(Ok(()), Err)
}

#[cfg(test)]
mod batch_tests {
    use super::*;

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
