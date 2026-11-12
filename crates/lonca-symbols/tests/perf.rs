//! Timings of reading, facts and merges by file size, against the cost of
//! one tree-sitter parse of the same text. Nothing here asserts a time:
//! they print, and are run by hand
//! (`cargo test --release -p lonca-symbols --test perf -- --ignored --nocapture`).

use lonca_core::{FileEntry, FileMap, FileMode, GitId};
use lonca_symbols::engine::ENGINE_CURRENT;
use lonca_symbols::merge::merge_text_at;
use lonca_symbols::{Lang, analyze, parse_at};
use std::collections::BTreeMap;
use std::time::Instant;

/// A Rust file of `functions` functions; `changed` have another body.
fn source(functions: usize, changed: &[usize]) -> String {
    let mut out = String::from("use std::collections::BTreeMap;\n\n");
    for i in 0..functions {
        let k = if changed.contains(&i) { 7 } else { 1 };
        out.push_str(&format!(
            "/// Number {i}.\npub fn item_{i}(input: &BTreeMap<String, u64>, by: u64) -> u64 {{\n    \
             let mut total = {k};\n    for (name, value) in input {{\n        if name.len() as u64 > by {{\n            \
             total += value * {i};\n        }}\n    }}\n    total\n}}\n\n"
        ));
    }
    out
}

fn ms(rounds: u32, mut f: impl FnMut()) -> f64 {
    let started = Instant::now();
    for _ in 0..rounds {
        f();
    }
    started.elapsed().as_secs_f64() * 1000.0 / f64::from(rounds)
}

fn tree(files: &[(&str, &str)]) -> (FileMap, BTreeMap<GitId, Vec<u8>>) {
    let mut map = FileMap::new();
    let mut blobs = BTreeMap::new();
    for (path, text) in files {
        let blob = GitId::of_blob(text.as_bytes());
        blobs.insert(blob.clone(), text.as_bytes().to_vec());
        let mode = FileMode::Regular;
        map.insert(path.to_string(), FileEntry { mode, blob });
    }
    (map, blobs)
}

#[test]
#[ignore = "a timing, run by hand"]
fn reading_facts_and_merges_by_file_size() {
    let e = ENGINE_CURRENT;
    let lang = Lang::detect_at(e, "src/a.rs").unwrap();
    println!(
        "lines  kb    one_parse  tree_walk  parse_at  facts_added  facts_modified  merge_symbols  merge_same_edit   (ms)"
    );
    for functions in [50, 400, 1500] {
        let base = source(functions, &[]);
        let ours = source(functions, &[3]);
        let theirs = source(functions, &[functions - 2]);
        let rounds = if functions > 400 { 5 } else { 20 };
        let one = ms(rounds, || {
            assert!(lang.parse_at(e, &base).is_some());
        });
        let read = ms(rounds, || {
            assert!(!parse_at(e, lang, &base).has_error);
        });
        // What `Namespaces::of` costs: every node, its children collected.
        let parsed = lang.parse_at(e, &base).unwrap();
        let walk = ms(rounds, || {
            let mut stack = vec![parsed.root_node()];
            let mut seen = 0usize;
            while let Some(n) = stack.pop() {
                seen += usize::from(n.kind().ends_with("namespace_declaration"));
                let parts: Vec<_> = n.children(&mut n.walk()).collect();
                stack.extend(parts.into_iter().rev());
            }
            assert_eq!(seen, 0);
        });
        let (empty, _) = tree(&[]);
        let (b, mut blobs) = tree(&[("src/a.rs", &base)]);
        let (o, more) = tree(&[("src/a.rs", &ours)]);
        blobs.extend(more);
        let get = |id: &GitId| Ok(blobs[id].clone());
        let added = ms(rounds, || {
            analyze(e, &empty, &b, &get).unwrap();
        });
        let modified = ms(rounds, || {
            let a = analyze(e, &b, &o, &get).unwrap();
            assert_eq!(a.facts.edits.len(), 1);
        });
        let merged = ms(rounds, || {
            merge_text_at(e, "src/a.rs", &base, &ours, &theirs).unwrap();
        });
        // Both sides made the same edit: the symbol merge has it already
        // and the file goes by its lines.
        let same = ms(rounds, || {
            merge_text_at(e, "src/a.rs", &base, &ours, &ours).unwrap();
        });
        println!(
            "{:<6} {:<5} {one:<10.2} {walk:<10.2} {read:<9.2} {added:<12.2} {modified:<15.2} {merged:<14.2} {same:.2}",
            base.lines().count(),
            base.len() / 1024,
        );
    }
}
