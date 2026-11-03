//! Frozen output of every symbol engine version.
//!
//! The auditor recomputes facts and merges from old log entries with the
//! engine version recorded in each entry, so a version's output must never
//! change. For every case under `tests/engine/v<N>/<case>/` (a `base`, an
//! `ours` (trunk) and a `theirs` (proposal) file of one language) this test
//! pins the extracted symbols of each file, the facts of both sides against
//! the base, and the three-way merge, in `expected.json`.
//!
//! A failure here means extraction, facts or the merge changed, possibly
//! through a tree-sitter grammar or diff library update. Do not edit
//! `expected.json`: add a new engine version instead (`src/engine.rs`,
//! docs/decisions.md "Symbol engine versions"). A case without
//! `expected.json` gets one written and the test fails until it is reviewed
//! and committed.

use std::path::{Path, PathBuf};

use lonca_core::{FileEntry, FileMap, FileMode, Store};
use lonca_symbols::engine::{ENGINES_KNOWN, check};
use lonca_symbols::{Lang, Sym, analyze, merge3, parse};
use serde_json::{Value, json};

/// Rebuilds objects with their keys in sorted order. A workspace build turns
/// on serde_json's `preserve_order` (through cedar-policy), which would
/// otherwise make the snapshot depend on how the crate was built.
fn sorted(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            let m: std::collections::BTreeMap<String, Value> =
                m.into_iter().map(|(k, v)| (k, sorted(v))).collect();
            Value::Object(m.into_iter().collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(sorted).collect()),
        v => v,
    }
}

fn sym_json(s: &Sym) -> Value {
    json!({
        "name": s.name,
        "span": [s.start, s.def_start, s.end],
        "own": s.own,
        "signature": s.signature,
        "is_test": s.is_test,
        "skipped": s.skipped,
        "container": s.container,
        "children": s.children.iter().map(sym_json).collect::<Vec<_>>(),
    })
}

fn parsed_json(lang: Lang, src: &str) -> Value {
    let p = parse(lang, src);
    json!({
        "syms": p.syms.iter().map(sym_json).collect::<Vec<_>>(),
        "imports": p.imports,
        "has_error": p.has_error,
        "residual": p.residual,
        "js_tests": p.js_tests.iter().map(|t| json!({"name": t.name, "text": t.text, "skipped": t.skipped})).collect::<Vec<_>>(),
    })
}

fn side(dir: &Path, stem: &str) -> (String, String) {
    let file = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.file_stem().and_then(|s| s.to_str()) == Some(stem))
        .unwrap_or_else(|| panic!("{dir:?} has no {stem}.*"));
    let ext = file.extension().unwrap().to_str().unwrap().to_string();
    (ext, std::fs::read_to_string(file).unwrap())
}

fn run_case(engine: u32, dir: &Path) -> Value {
    check(engine).unwrap();
    let (ext, base) = side(dir, "base");
    let (_, ours) = side(dir, "ours");
    let (_, theirs) = side(dir, "theirs");
    let path = format!("src/sample.{ext}");
    let lang = Lang::detect(&path).unwrap_or_else(|| panic!("no language for {path}"));

    let tmp = tempfile::tempdir().unwrap();
    let store = Store::init_bare(&tmp.path().join("r.git")).unwrap();
    let map = |text: &str| {
        let mut m = FileMap::new();
        m.insert(
            path.clone(),
            FileEntry {
                mode: FileMode::Regular,
                blob: store.write_blob(text.as_bytes()).unwrap(),
            },
        );
        m
    };
    let (b, o, t) = (map(&base), map(&ours), map(&theirs));
    let read = |id: &lonca_core::GitId| store.read_blob(id);
    let write = |bytes: &[u8]| store.write_blob(bytes);
    let facts = |n: &FileMap| {
        let a = analyze(&b, n, &read).unwrap();
        json!({"facts": a.facts, "syntax_errors": a.syntax_errors})
    };
    let merged = merge3(&b, &o, &t, &read, &write).unwrap();
    let merged_text = merged
        .files
        .get(&path)
        .map(|e| String::from_utf8(store.read_blob(&e.blob).unwrap()).unwrap());
    json!({
        "path": path,
        "symbols": {
            "base": parsed_json(lang, &base),
            "ours": parsed_json(lang, &ours),
            "theirs": parsed_json(lang, &theirs),
        },
        "facts": {"ours": facts(&o), "theirs": facts(&t)},
        "merge": {"conflicts": merged.conflicts, "text": merged_text},
    })
}

fn cases(engine: u32) -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tests/engine/v{engine}"));
    let mut out: Vec<PathBuf> = std::fs::read_dir(&root)
        .unwrap_or_else(|e| panic!("{root:?}: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .collect();
    out.sort();
    out
}

#[test]
fn every_engine_version_reproduces_its_frozen_output() {
    let mut written = Vec::new();
    let mut changed = Vec::new();
    for &engine in ENGINES_KNOWN {
        let cases = cases(engine);
        assert!(!cases.is_empty(), "engine {engine} has no cases");
        for dir in cases {
            let got = serde_json::to_string_pretty(&sorted(run_case(engine, &dir))).unwrap() + "\n";
            let file = dir.join("expected.json");
            match std::fs::read_to_string(&file) {
                Ok(want) if want == got => {}
                Ok(_) => changed.push(dir.clone()),
                Err(_) => {
                    std::fs::write(&file, got).unwrap();
                    written.push(file);
                }
            }
        }
    }
    assert!(
        changed.is_empty(),
        "symbol engine output changed for {changed:?}; add a new engine version instead"
    );
    assert!(
        written.is_empty(),
        "wrote new snapshots, review and commit them: {written:?}"
    );
}

#[test]
fn every_language_has_a_case_for_the_current_engine() {
    let current = *ENGINES_KNOWN.last().unwrap();
    let exts: Vec<String> = cases(current).iter().map(|d| side(d, "base").0).collect();
    for ext in ["rs", "py", "ts", "tsx", "js", "cs", "go"] {
        assert!(exts.iter().any(|e| e == ext), "no .{ext} case: {exts:?}");
    }
}
