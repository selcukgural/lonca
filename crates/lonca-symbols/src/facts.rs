//! Facts: what a change actually does, computed from two trees.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ops::Facts;
use lonca_core::{FileMap, GitId, Result};

use crate::extract::{Parsed, Sym, parse};
use crate::lang::Lang;

const FILE: &str = "<file>";
const MODULE: &str = "<module>";
const IMPORTS: &str = "<imports>";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Analysis {
    pub facts: Facts,
    /// Files in the new tree that a supported parser rejects.
    pub syntax_errors: Vec<String>,
}

fn sym_id(path: &str, name: &str) -> String {
    format!("{path}#{name}")
}

fn line_counts(old: &str, new: &str) -> (u32, u32) {
    let diff = similar::TextDiff::from_lines(old, new);
    let mut added = 0u32;
    let mut removed = 0u32;
    for op in diff.ops() {
        for change in diff.iter_changes(op) {
            match change.tag() {
                similar::ChangeTag::Insert => added += 1,
                similar::ChangeTag::Delete => removed += 1,
                similar::ChangeTag::Equal => {}
            }
        }
    }
    (added, removed)
}

fn count_lines(s: &str) -> u32 {
    s.lines().count() as u32
}

pub fn analyze(base: &FileMap, new: &FileMap, read: &dyn Fn(&GitId) -> Result<Vec<u8>>) -> Result<Analysis> {
    let mut f = Facts::default();
    let mut syntax_errors = Vec::new();
    let paths: BTreeSet<&String> = base.keys().chain(new.keys()).collect();
    for path in paths {
        let lang = Lang::detect(path);
        match (base.get(path), new.get(path)) {
            (None, None) => {}
            (None, Some(n)) => {
                f.added_files.push(path.clone());
                let bytes = read(&n.blob)?;
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    f.lines_added += count_lines(text);
                    if let Some(lang) = lang {
                        let p = parse(lang, text);
                        if p.has_error {
                            syntax_errors.push(path.clone());
                        }
                        f.tests.added += p.tests(text).len() as u32;
                    }
                }
            }
            (Some(b), None) => {
                f.deleted_files.push(path.clone());
                let bytes = read(&b.blob)?;
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    f.lines_removed += count_lines(text);
                    if let Some(lang) = lang {
                        f.tests.deleted += parse(lang, text).tests(text).len() as u32;
                    }
                }
            }
            (Some(b), Some(n)) => {
                if b == n {
                    continue;
                }
                f.modified_files.push(path.clone());
                if b.blob == n.blob {
                    // Only the mode changed (e.g. made executable).
                    f.edits.push(sym_id(path, FILE));
                    continue;
                }
                let (old, new_bytes) = (read(&b.blob)?, read(&n.blob)?);
                let (Ok(old), Ok(newt)) = (std::str::from_utf8(&old), std::str::from_utf8(&new_bytes)) else {
                    f.edits.push(sym_id(path, FILE));
                    continue;
                };
                let (a, r) = line_counts(old, newt);
                f.lines_added += a;
                f.lines_removed += r;
                let Some(lang) = lang else {
                    f.edits.push(sym_id(path, FILE));
                    continue;
                };
                let pb = parse(lang, old);
                let pn = parse(lang, newt);
                if pn.has_error {
                    syntax_errors.push(path.clone());
                }
                if pb.has_error || pn.has_error {
                    f.edits.push(sym_id(path, FILE));
                    continue;
                }
                compare_file(path, &pb, old, &pn, newt, &mut f);
            }
        }
    }
    for v in [
        &mut f.edits,
        &mut f.adds,
        &mut f.deletes,
        &mut f.added_files,
        &mut f.deleted_files,
        &mut f.modified_files,
        &mut f.signature_changes,
        &mut f.import_only_files,
    ] {
        v.sort();
        v.dedup();
    }
    syntax_errors.sort();
    Ok(Analysis { facts: f, syntax_errors })
}

fn compare_file(path: &str, pb: &Parsed, old: &str, pn: &Parsed, new: &str, f: &mut Facts) {
    diff_level(path, &pb.syms, old, &pn.syms, new, f);
    if pb.residual != pn.residual {
        f.edits.push(sym_id(path, MODULE));
    }
    let bi: BTreeSet<String> = pb.import_texts(old).into_iter().collect();
    let ni: BTreeSet<String> = pn.import_texts(new).into_iter().collect();
    if bi != ni {
        if bi.is_subset(&ni) {
            f.import_only_files.push(path.to_string());
        } else {
            f.edits.push(sym_id(path, IMPORTS));
        }
    }
    let bt = pb.tests(old);
    let nt = pn.tests(new);
    for (name, (text, skipped)) in &nt {
        match bt.get(name) {
            None => f.tests.added += 1,
            Some((btext, bskipped)) => {
                if btext != text {
                    f.tests.modified += 1;
                }
                if *skipped && !bskipped {
                    f.tests.skipped += 1;
                }
            }
        }
    }
    f.tests.deleted += bt.keys().filter(|k| !nt.contains_key(*k)).count() as u32;
}

fn by_name(syms: &[Sym]) -> BTreeMap<&str, &Sym> {
    syms.iter().map(|s| (s.name.as_str(), s)).collect()
}

fn diff_level(path: &str, bs: &[Sym], old: &str, ns: &[Sym], new: &str, f: &mut Facts) {
    let bm = by_name(bs);
    let nm = by_name(ns);
    for n in ns {
        match bm.get(n.name.as_str()) {
            None => f.adds.push(sym_id(path, &n.name)),
            Some(b) => {
                if b.text(old) == n.text(new) {
                    continue;
                }
                if b.container && n.container {
                    if b.own != n.own {
                        f.edits.push(sym_id(path, &n.name));
                    }
                    diff_level(path, &b.children, old, &n.children, new, f);
                } else {
                    f.edits.push(sym_id(path, &n.name));
                }
                if let (Some(bs), Some(ns)) = (&b.signature, &n.signature)
                    && bs != ns {
                        f.signature_changes.push(sym_id(path, &n.name));
                    }
            }
        }
    }
    for b in bs {
        if !nm.contains_key(b.name.as_str()) {
            f.deletes.push(sym_id(path, &b.name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lonca_core::{FileEntry, FileMode};
    use std::collections::HashMap;

    struct Mem(HashMap<String, Vec<u8>>);

    impl Mem {
        fn put(&mut self, text: &str) -> GitId {
            let id = GitId(lonca_core::canonical::sha256_hex(text.as_bytes())[..40].to_string());
            self.0.insert(id.0.clone(), text.as_bytes().to_vec());
            id
        }
    }

    fn tree(mem: &mut Mem, files: &[(&str, &str)]) -> FileMap {
        files
            .iter()
            .map(|(p, t)| (p.to_string(), FileEntry { mode: FileMode::Regular, blob: mem.put(t) }))
            .collect()
    }

    fn run(base: &[(&str, &str)], new: &[(&str, &str)]) -> Analysis {
        let mut mem = Mem(HashMap::new());
        let b = tree(&mut mem, base);
        let n = tree(&mut mem, new);
        analyze(&b, &n, &|id| Ok(mem.0[&id.0].clone())).unwrap()
    }

    const BASE: &str = "use std::io;\n\npub struct Client;\n\nimpl Client {\n    pub fn charge(&self, a: u64) -> u64 {\n        a\n    }\n\n    pub fn refund(&self) {}\n}\n\n#[test]\nfn charges() {}\n";

    #[test]
    fn body_edit_is_one_symbol() {
        let new = BASE.replace("        a\n", "        a + 1\n");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]);
        assert_eq!(a.facts.edits, vec!["src/a.rs#Client.charge"]);
        assert!(a.facts.signature_changes.is_empty());
        assert_eq!(a.facts.modified_files, vec!["src/a.rs"]);
        assert_eq!((a.facts.lines_added, a.facts.lines_removed), (1, 1));
    }

    #[test]
    fn signature_add_delete_and_imports() {
        let new = BASE
            .replace("charge(&self, a: u64)", "charge(&self, a: u64, b: u64)")
            .replace("    pub fn refund(&self) {}\n", "    pub fn void(&self) {}\n")
            .replace("use std::io;\n", "use std::io;\nuse std::fmt;\n");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]);
        assert_eq!(a.facts.edits, vec!["src/a.rs#Client.charge"]);
        assert_eq!(a.facts.signature_changes, vec!["src/a.rs#Client.charge"]);
        assert_eq!(a.facts.adds, vec!["src/a.rs#Client.void"]);
        assert_eq!(a.facts.deletes, vec!["src/a.rs#Client.refund"]);
        assert_eq!(a.facts.import_only_files, vec!["src/a.rs"]);
    }

    #[test]
    fn module_level_and_import_removal() {
        let new = BASE.replace("use std::io;\n", "").replace("pub struct Client;", "pub struct Client;\nstatic X: u8 = 1;");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]);
        assert!(a.facts.edits.contains(&"src/a.rs#<imports>".to_string()));
        assert!(a.facts.adds.contains(&"src/a.rs#X".to_string()));
    }

    #[test]
    fn tests_deleted_and_skipped() {
        let skipped = BASE.replace("#[test]\nfn charges", "#[test]\n#[ignore]\nfn charges");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &skipped)]);
        assert_eq!(a.facts.tests.skipped, 1);
        assert_eq!(a.facts.tests.modified, 1);
        let removed = BASE.replace("#[test]\nfn charges() {}\n", "");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &removed)]);
        assert_eq!(a.facts.tests.deleted, 1);
        assert_eq!(a.facts.deletes, vec!["src/a.rs#charges"]);
    }

    #[test]
    fn files_added_deleted_unsupported_and_broken() {
        let a = run(
            &[("README.md", "hello\n"), ("old.rs", "fn x() {}\n")],
            &[("README.md", "hello world\n"), ("new.rs", "fn y( {\n")],
        );
        assert_eq!(a.facts.edits, vec!["README.md#<file>"]);
        assert_eq!(a.facts.added_files, vec!["new.rs"]);
        assert_eq!(a.facts.deleted_files, vec!["old.rs"]);
        assert_eq!(a.syntax_errors, vec!["new.rs"]);
    }

    #[test]
    fn deterministic() {
        let new = BASE.replace("        a\n", "        a * 2\n");
        assert_eq!(run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]), run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]));
    }
}
