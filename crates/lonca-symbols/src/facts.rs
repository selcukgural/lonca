//! Facts: what a change actually does, computed from two trees.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ops::Facts;
use lonca_core::{FileMap, GitId, Result};

use crate::engine::{ENGINE_EXACT, ENGINE_SECTIONS};
use crate::extract::{Parsed, Sym, moved, parse};
use crate::lang::Lang;
use crate::sections::{APPEND, Format, Section, appended, sections};

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

pub fn analyze(
    engine: u32,
    base: &FileMap,
    new: &FileMap,
    read: &dyn Fn(&GitId) -> Result<Vec<u8>>,
) -> Result<Analysis> {
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
                let (Ok(old), Ok(newt)) =
                    (std::str::from_utf8(&old), std::str::from_utf8(&new_bytes))
                else {
                    f.edits.push(sym_id(path, FILE));
                    continue;
                };
                let (a, r) = line_counts(old, newt);
                f.lines_added += a;
                f.lines_removed += r;
                let Some(lang) = lang else {
                    let by_section = (engine >= ENGINE_SECTIONS)
                        .then(|| Format::detect(path))
                        .flatten()
                        .is_some_and(|format| compare_sections(path, format, old, newt, &mut f));
                    if !by_section {
                        f.edits.push(sym_id(path, FILE));
                    }
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
                compare_file(engine, path, (&pb, old), (&pn, newt), &mut f);
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
    Ok(Analysis {
        facts: f,
        syntax_errors,
    })
}

/// The sections that differ, or `false` for a file to treat whole: one
/// that has no sections, or whose sections do not show what changed.
fn compare_sections(path: &str, format: Format, old: &str, new: &str, f: &mut Facts) -> bool {
    let (Some(bs), Some(ns)) = (sections(format, old), sections(format, new)) else {
        return false;
    };
    let text = |list: &[Section], name: &str| {
        let found = list.iter().find(|s| s.name == name);
        found.map(|s| s.text.clone())
    };
    let before = f.edits.len() + f.adds.len() + f.deletes.len();
    for n in &ns {
        match text(&bs, &n.name) {
            None => f.adds.push(sym_id(path, &n.name)),
            Some(b) if b == n.text => {}
            Some(b) if format == Format::Markdown && appended(&b, &n.text).is_some() => {
                f.adds.push(sym_id(path, &format!("{}.{APPEND}", n.name)));
            }
            Some(_) => f.edits.push(sym_id(path, &n.name)),
        }
    }
    let gone = bs.iter().filter(|b| text(&ns, &b.name).is_none());
    f.deletes.extend(gone.map(|b| sym_id(path, &b.name)));
    f.edits.len() + f.adds.len() + f.deletes.len() > before
}

fn compare_file(
    engine: u32,
    path: &str,
    (pb, old): (&Parsed, &str),
    (pn, new): (&Parsed, &str),
    f: &mut Facts,
) {
    diff_level(engine, path, (&pb.syms, old), (&pn.syms, new), f);
    if pb.residual_at(engine) != pn.residual_at(engine) {
        f.edits.push(sym_id(path, MODULE));
    }
    let (bl, nl) = (pb.import_texts(old), pn.import_texts(new));
    let lists: [Vec<&str>; 2] = [&bl, &nl].map(|l| l.iter().map(String::as_str).collect());
    if engine >= ENGINE_EXACT && !moved(&lists[0], &lists[1]).is_empty() {
        f.edits.push(sym_id(path, IMPORTS));
    }
    let bi: BTreeSet<String> = bl.into_iter().collect();
    let ni: BTreeSet<String> = nl.into_iter().collect();
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

fn diff_level(
    engine: u32,
    path: &str,
    (bs, old): (&[Sym], &str),
    (ns, new): (&[Sym], &str),
    f: &mut Facts,
) {
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
                    if b.own_at(engine) != n.own_at(engine) {
                        f.edits.push(sym_id(path, &n.name));
                    }
                    let (bc, nc) = (&b.children[..], &n.children[..]);
                    diff_level(engine, path, (bc, old), (nc, new), f);
                } else {
                    f.edits.push(sym_id(path, &n.name));
                }
                if let (Some(bs), Some(ns)) = (&b.signature, &n.signature)
                    && bs != ns
                {
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
    if engine >= ENGINE_EXACT {
        let [a, b]: [Vec<&str>; 2] = [bs, ns].map(|l| l.iter().map(|s| s.name.as_str()).collect());
        for name in moved(&a, &b) {
            f.edits.push(sym_id(path, &name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section_facts(engine: u32, path: &str, old: &str, new: &str) -> Facts {
        let map = |text: &str| {
            let mut m = FileMap::new();
            m.insert(
                path.to_string(),
                lonca_core::FileEntry {
                    mode: lonca_core::FileMode::Regular,
                    blob: GitId::of_blob(text.as_bytes()),
                },
            );
            m
        };
        let (old, new) = (old.to_string(), new.to_string());
        let (o, n) = (old.clone(), new.clone());
        let read = move |id: &GitId| {
            let text = if *id == GitId::of_blob(o.as_bytes()) {
                &o
            } else {
                &n
            };
            Ok(text.clone().into_bytes())
        };
        analyze(engine, &map(&old), &map(&new), &read)
            .unwrap()
            .facts
    }

    #[test]
    fn engine_1_reads_sections_and_engine_0_the_whole_file() {
        let old = "# A\nx\n# B\ny\n";
        let new = "# A\nX\n# B\ny\n# C\nz\n";
        let f = section_facts(1, "n.md", old, new);
        assert_eq!(f.edits, ["n.md#A"]);
        assert_eq!(f.adds, ["n.md#C"]);
        let f = section_facts(1, "n.md", new, old);
        assert_eq!(f.deletes, ["n.md#C"]);
        let f = section_facts(0, "n.md", old, new);
        assert_eq!(f.edits, ["n.md#<file>"]);
        assert_eq!(f.adds, Vec::<String>::new());
    }

    #[test]
    fn only_markdown_grows_by_appending() {
        let f = section_facts(1, "n.md", "# A\nx\n# B\ny\n", "# A\nx\nmore\n# B\ny\n");
        assert_eq!(f.adds, ["n.md#A.<append>"]);
        assert_eq!(f.edits, Vec::<String>::new());
        let f = section_facts(1, "c.toml", "a = 1\nb = 2\n", "a = 12\nb = 2\n");
        assert_eq!(f.edits, ["c.toml#a"]);
        assert_eq!(f.adds, Vec::<String>::new());
    }

    /// Fail closed: anything that can not be read by sections is one edit.
    #[test]
    fn a_file_without_sections_is_edited_whole() {
        let edit = |path, old, new| section_facts(1, path, old, new).edits;
        assert_eq!(edit("n.md", "plain\n", "other\n"), ["n.md#<file>"]);
        assert_eq!(
            edit("c.toml", "a = 1\nb = 2\n", "a = \n"),
            ["c.toml#<file>"]
        );
        assert_eq!(
            edit("c.toml", "a = \n", "a = 1\nb = 2\n"),
            ["c.toml#<file>"]
        );
        assert_eq!(edit("n.txt", "a\n", "b\n"), ["n.txt#<file>"]);
        // Only what no section shows: the space between JSON members.
        let (old, new) = ("{\"a\": 1, \"b\": 2}\n", "{\"a\": 1,\n \"b\": 2}\n");
        assert_eq!(edit("c.json", old, new), ["c.json#<file>"]);
    }
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
            .map(|(p, t)| {
                (
                    p.to_string(),
                    FileEntry {
                        mode: FileMode::Regular,
                        blob: mem.put(t),
                    },
                )
            })
            .collect()
    }

    fn run(base: &[(&str, &str)], new: &[(&str, &str)]) -> Analysis {
        let mut mem = Mem(HashMap::new());
        let b = tree(&mut mem, base);
        let n = tree(&mut mem, new);
        analyze(0, &b, &n, &|id| Ok(mem.0[&id.0].clone())).unwrap()
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
            .replace(
                "    pub fn refund(&self) {}\n",
                "    pub fn void(&self) {}\n",
            )
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
        let new = BASE.replace("use std::io;\n", "").replace(
            "pub struct Client;",
            "pub struct Client;\nstatic X: u8 = 1;",
        );
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

    fn facts_at(engine: u32, old: &str, new: &str, path: &str) -> Facts {
        let mut mem = Mem(HashMap::new());
        let b = tree(&mut mem, &[(path, old)]);
        let n = tree(&mut mem, &[(path, new)]);
        analyze(engine, &b, &n, &|id| Ok(mem.0[&id.0].clone()))
            .unwrap()
            .facts
    }

    #[test]
    fn from_engine_2_a_block_or_string_change_outside_symbols_is_an_edit() {
        let old = "X = \"a  b\"\nif X:\n    a = 1\n    b = 2\n";
        for new in [
            old.replace("a  b", "a b"),
            old.replace("    b = 2", "b = 2"),
        ] {
            assert_eq!(
                facts_at(2, old, &new, "m.py").edits,
                ["m.py#<module>"],
                "{new}"
            );
            assert!(facts_at(1, old, &new, "m.py").edits.is_empty(), "{new}");
        }
        let spaced = old.replace("a = 1", "a  =  1");
        assert!(
            facts_at(2, old, &spaced, "m.py").edits.is_empty(),
            "layout is no edit"
        );
    }

    #[test]
    fn from_engine_2_a_block_change_in_a_class_is_an_edit_of_the_class() {
        let old = "class C:\n    x = \"a  b\"\n\n    def m(self):\n        pass\n";
        let new = old.replace("a  b", "a b");
        assert_eq!(facts_at(2, old, &new, "m.py").edits, ["m.py#C"]);
        assert!(facts_at(1, old, &new, "m.py").edits.is_empty());
    }

    #[test]
    fn from_engine_2_moved_symbols_and_imports_are_edits() {
        let old = "import a\nimport b\n\ndef f():\n    pass\n\ndef g():\n    pass\n";
        let new = "import a\nimport b\n\ndef g():\n    pass\n\ndef f():\n    pass\n";
        assert_eq!(facts_at(2, old, new, "m.py").edits, ["m.py#f", "m.py#g"]);
        assert!(facts_at(1, old, new, "m.py").edits.is_empty());
        let new = old.replace("import a\nimport b", "import b\nimport a");
        assert_eq!(facts_at(2, old, &new, "m.py").edits, ["m.py#<imports>"]);
        assert!(facts_at(1, old, &new, "m.py").edits.is_empty());
    }

    #[test]
    fn a_method_moved_inside_its_class_is_an_edit_of_the_method() {
        let old = "class C:\n    def f(self):\n        pass\n\n    def g(self):\n        pass\n";
        let new = "class C:\n    def g(self):\n        pass\n\n    def f(self):\n        pass\n";
        assert_eq!(
            facts_at(2, old, new, "m.py").edits,
            ["m.py#C.f", "m.py#C.g"]
        );
    }

    #[test]
    fn deterministic() {
        let new = BASE.replace("        a\n", "        a * 2\n");
        assert_eq!(
            run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]),
            run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)])
        );
    }
}
