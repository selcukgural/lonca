//! Deterministic integration of a proposed change onto trunk.
//!
//! The merged commit copies the proposal's author, time, message and
//! headers and has the current trunk as its only parent, so history stays
//! linear and the auditor can recompute the exact same commit id. When the
//! proposal was made on the current trunk, the merged commit *is* the
//! proposal commit.
//!
//! Both entry points take the symbol engine version (see [`crate::engine`]):
//! the daemon passes the current one, the auditor the one in the entry.

use std::collections::BTreeSet;

use lonca_core::keyed::KeyedDirs;
use lonca_core::store::CommitSpec;
use lonca_core::{FileMap, GitId, Result, Store};

use crate::engine;
use crate::facts::{Analysis, FILE, analyze};
use crate::merge::{Joins, merge3_joining, no_joins};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Integration {
    pub merged: Option<GitId>,
    pub conflicts: Vec<String>,
    pub files: FileMap,
    /// Paths whose content differs between trunk and the merged tree.
    pub touched: Vec<String>,
}

pub fn integrate(
    store: &Store,
    engine: u32,
    base: &GitId,
    trunk: &GitId,
    change: &GitId,
) -> Result<Integration> {
    let none = KeyedDirs::default();
    integrate_joining(store, engine, base, trunk, change, &no_joins, &none)
}

/// [`integrate`], joining by lines the symbols `joins` names, under the
/// keyed directories of the policy in force.
pub fn integrate_joining(
    store: &Store,
    engine: u32,
    base: &GitId,
    trunk: &GitId,
    change: &GitId,
    joins: Joins,
    keyed: &KeyedDirs,
) -> Result<Integration> {
    engine::check(engine)?;
    let base_files = store.commit_files(base)?;
    let ours = store.commit_files(trunk)?;
    let theirs = store.commit_files(change)?;
    let read = |id: &GitId| store.read_blob(id);
    let write = |b: &[u8]| store.write_blob(b);
    let r = merge3_joining(engine, &base_files, &ours, &theirs, &read, &write, joins)?;
    if !r.conflicts.is_empty() {
        return Ok(Integration {
            merged: None,
            conflicts: r.conflicts,
            files: ours,
            touched: vec![],
        });
    }
    // Two changes can each be fine and leave a path both a file and a
    // directory, which no tree can hold: that is their conflict, and without
    // this no entry could record it, so the queue would stop here.
    let clashes = file_and_directory(&r.files);
    if !clashes.is_empty() {
        return Ok(Integration {
            merged: None,
            conflicts: clashes,
            files: ours,
            touched: vec![],
        });
    }
    // Two files with one key in a keyed directory: each change was fine,
    // the two together are not, whatever the checks run. Only what this
    // change brings: a clash trunk already had stops nobody.
    let clashes = new_key_clashes(keyed, &ours, &r.files);
    if !clashes.is_empty() {
        return Ok(Integration {
            merged: None,
            conflicts: clashes,
            files: ours,
            touched: vec![],
        });
    }
    let tree = store.write_tree(&r.files)?;
    let info = store.read_commit(change)?;
    let merged = store.write_commit(&CommitSpec {
        tree,
        parents: vec![trunk.clone()],
        author_name: info.author_name,
        author_email: info.author_email,
        time_ms: info.time_ms,
        message: info.message,
        headers: info.headers,
    })?;
    let paths: BTreeSet<&String> = ours.keys().chain(r.files.keys()).collect();
    let touched = paths
        .into_iter()
        .filter(|p| ours.get(*p) != r.files.get(*p))
        .cloned()
        .collect();
    Ok(Integration {
        merged: Some(merged),
        conflicts: vec![],
        files: r.files,
        touched,
    })
}

/// The keys, as `dir#key`, that two files of `after` share in a keyed
/// directory and no two files of `before` did.
pub fn new_key_clashes(keyed: &KeyedDirs, before: &FileMap, after: &FileMap) -> Vec<String> {
    if keyed.is_empty() {
        return vec![];
    }
    let had = keyed.clashes(before.keys().map(String::as_str));
    let now = keyed.clashes(after.keys().map(String::as_str));
    now.difference(&had).cloned().collect()
}

/// Files that other files stand under, as conflicts.
fn file_and_directory(files: &FileMap) -> Vec<String> {
    let parents = files.keys().flat_map(|path| {
        let cuts = path.match_indices('/').map(|(at, _)| &path[..at]);
        cuts.collect::<Vec<_>>()
    });
    let clashes: BTreeSet<&str> = parents.filter(|p| files.contains_key(*p)).collect();
    clashes.iter().map(|p| format!("{p}#{FILE}")).collect()
}

/// Facts of a proposal: its commit against its base.
pub fn facts_of(store: &Store, engine: u32, base: &GitId, commit: &GitId) -> Result<Analysis> {
    engine::check(engine)?;
    let b = store.commit_files(base)?;
    let n = store.commit_files(commit)?;
    analyze(engine, &b, &n, &|id| store.read_blob(id))
}

/// [`facts_of`], with the keys its added files share with another file of
/// its tree under the keyed directories of the policy in force.
pub fn facts_keyed(
    store: &Store,
    engine: u32,
    base: &GitId,
    commit: &GitId,
    keyed: &KeyedDirs,
) -> Result<Analysis> {
    let mut a = facts_of(store, engine, base, commit)?;
    if !keyed.is_empty() && !a.facts.added_files.is_empty() {
        let n = store.commit_files(commit)?;
        a.facts.taken_keys = keyed.taken(&a.facts.added_files, n.keys().map(String::as_str));
    }
    Ok(a)
}
