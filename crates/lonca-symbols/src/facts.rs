//! Facts: what a change actually does, computed from two trees.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ops::Facts;
use lonca_core::{FileMap, GitId, Result};

#[cfg(test)]
use crate::engine::ENGINE_KEYS;
use crate::engine::{ENGINE_EXACT, ENGINE_PLACES, ENGINE_SECTIONS};
use crate::extract::{Parsed, Sym, align, moved, parse_at, parse_together, shifted};
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
                        let p = parse_at(engine, lang, text);
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
                        f.tests.deleted += parse_at(engine, lang, text).tests(text).len() as u32;
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
                let [pb, mut pn] = parse_together(engine, lang, [old, newt]);
                align(&pb, &mut pn);
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
    let places = engine >= ENGINE_PLACES && shifted(pb.placed(), pn.placed());
    if places || pb.residual_at(engine) != pn.residual_at(engine) {
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
                if b.same(old, n, new) {
                    continue;
                }
                let unit = sym_id(path, &b.changed_unit(n, engine));
                if b.container && n.container {
                    let places = engine >= ENGINE_PLACES && shifted(b.placed(), n.placed());
                    if places || b.own_at(engine) != n.own_at(engine) {
                        f.edits.push(unit.clone());
                    }
                    let (bc, nc) = (&b.children[..], &n.children[..]);
                    diff_level(engine, path, (bc, old), (nc, new), f);
                } else {
                    f.edits.push(unit.clone());
                }
                if let (Some(bs), Some(ns)) = (&b.signature, &n.signature)
                    && bs != ns
                {
                    f.signature_changes.push(unit);
                }
            }
        }
    }
    for b in bs {
        if nm.contains_key(b.name.as_str()) {
            continue;
        }
        match b.impl_of(engine) {
            // No lease on an `impl` reaches the members named after its
            // type, so the type is what stands for the block.
            Some(ty) => {
                f.edits.push(sym_id(path, ty));
                let members = b.children.iter().map(|c| sym_id(path, &c.name));
                f.deletes.extend(members);
            }
            None => f.deletes.push(sym_id(path, &b.name)),
        }
    }
    if engine >= ENGINE_EXACT {
        let [a, b]: [Vec<&str>; 2] = [bs, ns].map(|l| l.iter().map(|s| s.name.as_str()).collect());
        for name in moved(&a, &b) {
            let ty = nm.get(name.as_str()).and_then(|s| s.impl_of(engine));
            f.edits.push(sym_id(path, ty.unwrap_or(&name)));
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

    /// A type's own text is `Type.<def>` from engine 3, in every list that
    /// names it, and older engines keep the name they recorded.
    #[test]
    fn engine_3_reports_the_definition_of_a_type() {
        let (old, new) = (
            "struct S<T> {\n    a: T,\n}\n",
            "struct S<U> {\n    a: U,\n}\n",
        );
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S.<def>"]);
        assert_eq!(f.signature_changes, ["a.rs#S.<def>"]);
        let f = section_facts(2, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S"]);
        assert_eq!(f.signature_changes, ["a.rs#S"]);

        let (old, new) = ("class A:\n    x = 1\n", "class A:\n    x = 2\n");
        assert_eq!(section_facts(3, "a.py", old, new).edits, ["a.py#A.<def>"]);
        assert_eq!(section_facts(2, "a.py", old, new).edits, ["a.py#A"]);

        let f = section_facts(3, "a.rs", "fn f(a: u8) {}\n", "fn f(a: u16) {}\n");
        assert_eq!(f.edits, ["a.rs#f"]);
        assert_eq!(f.signature_changes, ["a.rs#f"]);
    }

    /// Each row: a file, what stands above the symbol that was there, and
    /// the name a second symbol of that name gives it. The new one is an
    /// addition and nothing else, wherever it landed.
    #[test]
    fn a_symbol_added_in_front_of_another_of_its_name_renames_nothing() {
        let rows = [
            (
                "a.cs",
                "class C {\n    void Charge(string s) {\n        A();\n    }\n}\n",
                "    void Charge(int a, int b) {\n        B();\n    }\n",
                "    void Charge(string s) {",
                "a.cs#C.Charge(int,int)",
            ),
            (
                "a.ts",
                "class C {\n  m(a: string) {\n    x();\n  }\n}\n",
                "  m(a: number): void;\n",
                "  m(a: string) {",
                "a.ts#C.m(number)",
            ),
            (
                "a.py",
                "class P:\n    @x.setter\n    def x(self, v):\n        pass\n",
                "    @property\n    def x(self):\n        return 1\n\n",
                "    @x.setter",
                "a.py#P.x(self)",
            ),
        ];
        for (path, old, above, at, added) in rows {
            let new = old.replacen(at, &format!("{above}{at}"), 1);
            let f = section_facts(ENGINE_KEYS, path, old, &new);
            assert_eq!(f.adds, [added], "{path}");
            assert!(f.edits.is_empty(), "{path}: {:?}", f.edits);
            assert!(f.deletes.is_empty(), "{path}: {:?}", f.deletes);
            // The number of engine 5 is what this replaces.
            let f = section_facts(ENGINE_KEYS - 1, path, old, &new);
            assert!(!f.edits.is_empty() || f.adds != [added], "{path}");
        }
    }

    #[test]
    fn a_trait_impl_added_in_front_of_another_renames_nothing() {
        let (first, second) = (
            "impl From<u8> for S {\n    fn from(v: u8) -> S {\n        S\n    }\n}\n",
            "impl From<u16> for S {\n    fn from(v: u16) -> S {\n        S\n    }\n}\n",
        );
        let new = format!("{second}{first}");
        let f = section_facts(ENGINE_KEYS, "a.rs", first, &new);
        assert_eq!(f.adds, ["a.rs#impl:S.From(u16)"]);
        assert!(f.edits.is_empty(), "{:?}", f.edits);
        assert!(f.deletes.is_empty(), "{:?}", f.deletes);
    }

    /// Facts name a symbol as `base` does when the edit gives it a new key,
    /// or a lease on it would not reach its own change.
    #[test]
    fn a_change_of_parameters_is_an_edit_of_the_symbol() {
        let old = "class C {\n    void M(int a) { A(); }\n    void M(string s) { B(); }\n}\n";
        let new = old.replace("M(int a)", "M(long a)");
        let f = section_facts(ENGINE_KEYS, "a.cs", old, &new);
        assert_eq!(f.edits, ["a.cs#C.M(int)"]);
        assert_eq!(f.signature_changes, ["a.cs#C.M(int)"]);
        assert!(f.adds.is_empty() && f.deletes.is_empty(), "{f:?}");
    }

    /// One symbol of a name has no key while it is alone, so the change of
    /// its parameters is what it always was.
    #[test]
    fn a_symbol_alone_with_its_name_keeps_it_through_a_change_of_parameters() {
        let f = section_facts(
            ENGINE_KEYS,
            "a.cs",
            "class C {\n    void M(int a) {}\n}\n",
            "class C {\n    void M(long a) {}\n}\n",
        );
        assert_eq!(f.edits, ["a.cs#C.M"]);
        assert_eq!(f.signature_changes, ["a.cs#C.M"]);
    }

    /// Only a second symbol of the name brings the key, and the edit of the
    /// first in the same change is reported on the first.
    #[test]
    fn an_overload_added_beside_an_edit_of_the_first() {
        let old = "class C {\n    void M(int a) { A(); }\n}\n";
        let new = "class C {\n    void M(string s) { B(); }\n    void M(int a) { C(); }\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.cs", old, new);
        assert_eq!(f.edits, ["a.cs#C.M(int)"]);
        assert_eq!(f.adds, ["a.cs#C.M(string)"]);
        assert!(f.deletes.is_empty(), "{f:?}");
    }

    #[test]
    fn a_test_that_gets_an_overload_is_not_a_deleted_test() {
        let old = "class T {\n    [Fact] void A(int x) {}\n}\n";
        let new = "class T {\n    void A(string s) {}\n    [Fact] void A(int x) {}\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.cs", old, new);
        assert_eq!(f.tests.deleted, 0);
        assert_eq!(f.tests.added, 0);
    }

    /// A `;` that stands behind a member is the member's, not the class's.
    #[test]
    fn a_member_with_its_semicolon_is_an_addition() {
        let old = "class C {\n  a: number;\n}\n";
        let new = "class C {\n  a: number;\n  b: string;\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.ts", old, new);
        assert_eq!(f.adds, ["a.ts#C.b"]);
        assert!(f.edits.is_empty(), "{:?}", f.edits);
        let f = section_facts(ENGINE_KEYS - 1, "a.ts", old, new);
        assert_eq!(f.edits, ["a.ts#C.<def>"]);
    }

    /// Exact duplicates have nothing to tell them apart but their order.
    #[test]
    fn exact_duplicates_stay_numbered() {
        let old = "package p\nfunc init() {}\n";
        let new = "package p\nfunc init() {\n\tx()\n}\nfunc init() {}\n";
        let f = section_facts(ENGINE_KEYS, "a.go", old, new);
        assert_eq!(f.adds, ["a.go#init~2"]);
    }

    /// Each row: an edit is reported on the symbol that changed, where
    /// engine 4 reports it on a neighbour or on the whole file's code.
    #[test]
    fn engine_5_reports_an_edit_on_the_right_symbol() {
        let rows = [
            (
                "a.go",
                "package p\nconst (\n\tX = 1\n\tY = 2\n)\n",
                "Y = 2",
                "Y = 3",
                "a.go#Y",
                "a.go#X",
            ),
            (
                "a.go",
                "package p\ntype (\n\tA struct{}\n\tB struct{}\n)\n",
                "B struct{}",
                "B struct{ n int }",
                "a.go#B.<def>",
                "a.go#A.<def>",
            ),
            (
                "a.go",
                "package p\nvar (\n\ta = 1\n\tb = 2\n)\n",
                "b = 2",
                "b = 3",
                "a.go#b",
                "a.go#a",
            ),
            (
                "a.cs",
                "class C { int a, b; }\n",
                "b;",
                "b = 1;",
                "a.cs#C.b",
                "a.cs#C.a",
            ),
            (
                "a.ts",
                "class C {\n  @A()\n  m() {}\n}\n",
                "@A()",
                "@B()",
                "a.ts#C.m",
                "a.ts#C.<def>",
            ),
            (
                "a.js",
                "module.exports.run = function () {};\n",
                "{}",
                "{ x(); }",
                "a.js#run",
                "a.js#<module>",
            ),
            (
                "a.js",
                "exports.run = () => 1;\n",
                "1",
                "2",
                "a.js#run",
                "a.js#<module>",
            ),
            (
                "a.js",
                "module.exports = {\n  a() {},\n  b() {},\n};\n",
                "b() {}",
                "b() { x(); }",
                "a.js#b",
                "a.js#<module>",
            ),
            (
                "a.py",
                "if A:\n    def f():\n        return 1\n",
                "return 1",
                "return 2",
                "a.py#f",
                "a.py#<module>",
            ),
            (
                "a.py",
                "try:\n    def f():\n        return 1\nexcept E:\n    def f():\n        return 2\n",
                "return 2",
                "return 3",
                "a.py#f~2",
                "a.py#<module>",
            ),
            (
                "a.rs",
                "extern \"C\" {\n    fn f(a: u8);\n}\n",
                "a: u8",
                "a: u16",
                "a.rs#f",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "m!(1);\nm!(2);\n",
                "(2)",
                "(3)",
                "a.rs#m!~2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "// section\n\nfn f() {}\n",
                "section",
                "part",
                "a.rs#<module>",
                "a.rs#f",
            ),
            (
                "a.py",
                "# licence\n\nimport os\n",
                "licence",
                "notice",
                "a.py#<module>",
                "a.py#<imports>",
            ),
            (
                "a.cs",
                "partial class C { int a; }\npartial class C { int b; }\n",
                "int b",
                "long b",
                "a.cs#C.b",
                "a.cs#C~2.b",
            ),
        ];
        for (path, old, from, to, now, before) in rows {
            let new = old.replace(from, to);
            let edits = |engine| section_facts(engine, path, old, &new).edits;
            assert_eq!(edits(5), [now], "{old}");
            assert_eq!(edits(4), [before], "{old}");
        }
    }

    /// An addition or a removal in a group is of one name, and the group's
    /// own lines are code.
    #[test]
    fn a_group_changes_by_its_members() {
        let old = "package p\nconst (\n\tX = 1\n)\n";
        let f = section_facts(5, "a.go", old, &old.replace("X = 1\n", "X = 1\n\tY = 2\n"));
        assert_eq!(f.adds, ["a.go#Y"]);
        assert!(f.edits.is_empty(), "{f:?}");
        let f = section_facts(5, "a.go", &old.replace("X = 1\n", "X = 1\n\tY = 2\n"), old);
        assert_eq!(f.deletes, ["a.go#Y"]);
        let f = section_facts(5, "a.go", old, &old.replace("const", "var"));
        assert_eq!(f.edits, ["a.go#<module>"]);

        // Out of its group, a spec is still found among the code around it.
        let old = "package p\nconst (\n\tA = 1\n\tB = 2\n)\nconst (\n\tC = 3\n)\n";
        let new = "package p\nconst (\n\tA = 1\n)\nconst (\n\tB = 2\n\tC = 3\n)\n";
        assert_eq!(section_facts(5, "a.go", old, new).edits, ["a.go#<module>"]);

        // A block holding one member reads as one holding two.
        let old = "if A:\n    def m():\n        return 1\n";
        let new = format!("{old}\n    def n():\n        return 2\n");
        let f = section_facts(5, "a.py", old, &new);
        assert_eq!((f.adds, f.edits), (vec!["a.py#n".to_string()], vec![]));
        let f = section_facts(5, "a.py", &new, old);
        assert_eq!((f.deletes, f.edits), (vec!["a.py#n".to_string()], vec![]));
        let old = "class A:\n    def m(self):\n        return 1\n";
        let new = format!("{old}\n    def n(self):\n        return 2\n");
        let f = section_facts(5, "a.py", old, &new);
        assert_eq!((f.adds, f.edits), (vec!["a.py#A.n".to_string()], vec![]));
        let f = section_facts(4, "a.py", old, &new);
        assert_eq!(f.edits, ["a.py#A.<def>"]);

        // In a list with separators, the separators go with the member.
        let old = "class C { int a, b; }\n";
        let f = section_facts(5, "a.cs", old, "class C { int a, b, c; }\n");
        assert_eq!((f.adds, f.edits), (vec!["a.cs#C.c".to_string()], vec![]));
        let old = "module.exports = {\n  a() {},\n  b() {},\n};\n";
        let f = section_facts(5, "a.js", old, "module.exports = {\n  b() {},\n};\n");
        assert_eq!((f.deletes, f.edits), (vec!["a.js#a".to_string()], vec![]));

        // A list changes shape: the type's own text says so.
        let old = "class C { int a, b; }\n";
        let f = section_facts(5, "a.cs", old, "class C { int a; }\n");
        assert_eq!(f.deletes, ["a.cs#C.b"]);
        assert!(f.edits.contains(&"a.cs#C.<def>".to_string()), "{f:?}");
    }

    #[test]
    fn a_trailing_comment_is_part_of_its_symbol_but_its_spacing_is_not() {
        let old = "package p\n\nconst (\n\tA = 1  // a\n\tB = 20 // b\n)\n";
        let new = "package p\n\nconst (\n\tA = 1   // a\n\tB = 20  // b\n\tC = 300 // c\n)\n";
        let f = section_facts(5, "a.go", old, new);
        assert_eq!((f.adds, f.edits), (vec!["a.go#C".to_string()], vec![]));
        let f = section_facts(5, "a.go", old, &old.replace("// a", "// first"));
        assert_eq!(f.edits, ["a.go#A"]);
    }

    /// A header of several lines ends at the blank line under it.
    #[test]
    fn a_comment_of_several_lines_stands_apart_as_one() {
        let rows = [
            (
                "a.rs",
                "//! one\n//! two\n\nfn f() {}\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "//! one\n//! two\n\nuse a::b;\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/// one\n/// two\n\nfn f() {}\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/// one\n// two\n\nfn f() {}\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/* a */ /* b */\n\nfn f() {}\n",
                "b",
                "c",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/// one\n/// two\nfn f() {}\n",
                "two",
                "2",
                "a.rs#f",
            ),
            (
                "a.cs",
                "class C\n{\n    #region R\n    /// one\n    /// two\n    void M() { }\n    #endregion\n}\n",
                "two",
                "2",
                "a.cs#C.M",
            ),
            (
                "a.cs",
                "class C\n{\n    #region R\n    // about\n    int a;\n    #endregion\n}\n",
                "about",
                "on",
                "a.cs#C.a",
            ),
        ];
        for (path, old, from, to, want) in rows {
            let f = section_facts(5, path, old, &old.replace(from, to));
            assert_eq!(f.edits, [want], "{old}");
        }
    }

    /// A file that goes takes its tests with it.
    #[test]
    fn a_deleted_file_counts_its_tests() {
        let text = "#[test]\nfn a() {}\n\n#[test]\nfn b() {}\n";
        let entry = lonca_core::FileEntry {
            mode: lonca_core::FileMode::Regular,
            blob: GitId::of_blob(text.as_bytes()),
        };
        let old = FileMap::from([("a.rs".to_string(), entry)]);
        let read = |_: &GitId| Ok(text.as_bytes().to_vec());
        let f = analyze(5, &old, &FileMap::new(), &read).unwrap().facts;
        assert_eq!(f.tests.deleted, 2);
        assert_eq!(f.deleted_files, ["a.rs"]);
    }

    /// A part of a partial type stands in for the type, as an `impl` does.
    #[test]
    fn a_partial_part_taken_out_is_an_edit_of_its_type() {
        let old = "partial class C { int a; }\npartial class C { int b; }\n";
        let f = section_facts(5, "a.cs", old, "partial class C { int a; }\n");
        assert_eq!(f.edits, ["a.cs#C"]);
        assert_eq!(f.deletes, ["a.cs#C.b"]);
    }

    /// Code that changes places among symbols is a change of that code.
    #[test]
    fn code_that_changed_places_is_an_edit_from_engine_4() {
        let old = "a = 1\n\ndef f():\n    return 1\n\nprint(a)\n";
        let new = "a = 1\n\nprint(a)\n\ndef f():\n    return 1\n";
        assert_eq!(section_facts(4, "a.py", old, new).edits, ["a.py#<module>"]);
        assert_eq!(
            section_facts(3, "a.py", old, new).edits,
            Vec::<String>::new()
        );

        let old = "class A:\n    x = g()\n\n    def m(self):\n        return 1\n";
        let new = "class A:\n    def m(self):\n        return 1\n\n    x = g()\n";
        assert_eq!(section_facts(4, "a.py", old, new).edits, ["a.py#A.<def>"]);
        assert_eq!(
            section_facts(3, "a.py", old, new).edits,
            Vec::<String>::new()
        );

        // A new symbol between two statements moves neither.
        let old = "x = 1\ny = 2\n";
        let new = "x = 1\ndef f(): pass\ny = 2\n";
        let f = section_facts(4, "a.py", old, new);
        assert_eq!(f.edits, Vec::<String>::new());
        assert_eq!(f.adds, ["a.py#f"]);
    }

    /// A move goes to the line merge, which sees the members of the block.
    #[test]
    fn an_impl_that_moves_is_its_type() {
        let old = "impl S {\n    fn a() {}\n}\n\nfn f() {}\n";
        let new = "fn f() {}\n\nimpl S {\n    fn a() {}\n}\n";
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S", "a.rs#f"]);
        let f = section_facts(2, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#f", "a.rs#impl:S"]);
    }

    #[test]
    fn an_impl_taken_out_is_its_type_and_its_members() {
        let old = "struct S;\n\nimpl S {\n    fn a() {}\n}\n\nimpl R for S {\n    fn b() {}\n}\n";
        let new = "struct S;\n\nimpl R for S {\n    fn b() {}\n}\n";
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S"]);
        assert_eq!(f.deletes, ["a.rs#S.a"]);
        let f = section_facts(2, "a.rs", old, new);
        assert_eq!(f.edits, Vec::<String>::new());
        assert_eq!(f.deletes, ["a.rs#impl:S"]);

        let new = "struct S;\n\nimpl S {\n    fn a() {}\n}\n";
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S"]);
        assert_eq!(f.deletes, ["a.rs#S.R.b"]);
        // A class taken out is a delete of the class, as it always was.
        let f = section_facts(3, "a.py", "class A:\n    x = 1\n\nb = 2\n", "b = 2\n");
        assert_eq!(f.deletes, ["a.py#A"]);
        assert_eq!(f.edits, Vec::<String>::new());
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
