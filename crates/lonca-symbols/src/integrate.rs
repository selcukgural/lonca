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

use lonca_core::store::CommitSpec;
use lonca_core::{FileMap, GitId, Result, Store};

use crate::engine;
use crate::facts::{Analysis, FILE, analyze};
use crate::merge::merge3;

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
    engine::check(engine)?;
    let base_files = store.commit_files(base)?;
    let ours = store.commit_files(trunk)?;
    let theirs = store.commit_files(change)?;
    let read = |id: &GitId| store.read_blob(id);
    let write = |b: &[u8]| store.write_blob(b);
    let r = merge3(engine, &base_files, &ours, &theirs, &read, &write)?;
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
