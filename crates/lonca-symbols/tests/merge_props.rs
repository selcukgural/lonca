//! Property tests of the merge (#40). Its promise (`src/merge.rs`): changes
//! to different symbols never conflict, the same symbol always does, and
//! nothing is dropped. Here a base file of functions is edited at random by
//! two sides, for every language with a grammar, and the merge is held to:
//!
//! - disjoint symbols merge, and the facts of the result against the base are
//!   those of both sides together, each symbol with the text its side wrote;
//! - symbols both sides changed apart are the conflicts, exactly;
//! - merging a change into what already has it changes nothing;
//! - what merges parses.
//!
//! The runs are seeded, so a run is the same everywhere, and nothing is
//! written to disk. A case one of them shrinks to is kept as a test of its
//! own in `src/merge.rs` (`tests::found`), with the engine that fixed it.

use std::collections::BTreeSet;

use lonca_core::{FileEntry, FileMap, FileMode, GitId};
use lonca_symbols::engine::ENGINE_CURRENT;
use lonca_symbols::merge::merge_text_at;
use lonca_symbols::{Lang, Sym, analyze, parse_at};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed, TestCaseError, TestRunner};

/// How a language writes a file of functions that return a number.
struct Shape {
    path: &'static str,
    /// Before the first function and after the last.
    head: &'static str,
    tail: &'static str,
    /// What the names stand in: `C.` for a member of `C`.
    owner: &'static str,
    /// One function, `{n}` its name and `{v}` its number.
    def: &'static str,
}

const SHAPES: &[Shape] = &[
    Shape {
        path: "src/a.rs",
        head: "",
        tail: "",
        owner: "",
        def: "fn {n}() -> i32 {\n    {v}\n}\n",
    },
    Shape {
        path: "src/b.rs",
        head: "struct C;\n\nimpl C {\n",
        tail: "}\n",
        owner: "C.",
        def: "    fn {n}(&self) -> i32 {\n        {v}\n    }\n",
    },
    Shape {
        path: "a.py",
        head: "",
        tail: "",
        owner: "",
        def: "def {n}():\n    return {v}\n",
    },
    Shape {
        path: "b.py",
        head: "class C:\n",
        tail: "",
        owner: "C.",
        def: "    def {n}(self):\n        return {v}\n",
    },
    Shape {
        path: "a.ts",
        head: "",
        tail: "",
        owner: "",
        def: "function {n}(): number {\n  return {v};\n}\n",
    },
    Shape {
        path: "b.ts",
        head: "class C {\n",
        tail: "}\n",
        owner: "C.",
        def: "  {n}(): number {\n    return {v};\n  }\n",
    },
    Shape {
        path: "a.tsx",
        head: "",
        tail: "",
        owner: "",
        def: "function {n}() {\n  return <b>{v}</b>;\n}\n",
    },
    Shape {
        path: "a.js",
        head: "",
        tail: "",
        owner: "",
        def: "function {n}() {\n  return {v};\n}\n",
    },
    Shape {
        path: "A.cs",
        head: "class C\n{\n",
        tail: "}\n",
        owner: "C.",
        def: "    int {n}()\n    {\n        return {v};\n    }\n",
    },
    Shape {
        path: "a.go",
        head: "package p\n\n",
        tail: "",
        owner: "",
        def: "func {n}() int {\n\treturn {v}\n}\n",
    },
    Shape {
        path: "C.java",
        head: "class C {\n",
        tail: "}\n",
        owner: "C.",
        def: "    int {n}() {\n        return {v};\n    }\n",
    },
    Shape {
        path: "a.kt",
        head: "",
        tail: "",
        owner: "",
        def: "fun {n}(): Int {\n    return {v}\n}\n",
    },
    Shape {
        path: "a.c",
        head: "",
        tail: "",
        owner: "",
        def: "int {n}(void) {\n    return {v};\n}\n",
    },
    Shape {
        path: "a.cpp",
        head: "",
        tail: "",
        owner: "",
        def: "int {n}() {\n    return {v};\n}\n",
    },
    Shape {
        path: "a.rb",
        head: "",
        tail: "",
        owner: "",
        def: "def {n}\n  {v}\nend\n",
    },
    Shape {
        path: "a.php",
        head: "<?php\n\n",
        tail: "",
        owner: "",
        def: "function {n}() {\n    return {v};\n}\n",
    },
    Shape {
        path: "a.swift",
        head: "",
        tail: "",
        owner: "",
        def: "func {n}() -> Int {\n    return {v}\n}\n",
    },
];

/// What a new function returns: unlike what any function of the base does,
/// so that a deletion and an addition are not taken for a rename.
const ADDED: &str = "1 + 2 + 3 + 4 + 5 + 6 + 7 + 8 + 9 + 10 + 11 + 12 + 13 + 14";

impl Shape {
    fn def(&self, name: &str, value: u32) -> String {
        self.def_of(name, &value.to_string())
    }

    fn added(&self, name: &str) -> String {
        self.def_of(name, ADDED)
    }

    fn def_of(&self, name: &str, value: &str) -> String {
        self.def.replace("{n}", name).replace("{v}", value)
    }

    fn id(&self, name: &str) -> String {
        format!("{}#{}{name}", self.path, self.owner)
    }

    fn lang(&self) -> Lang {
        Lang::detect(self.path).expect("a language")
    }
}

/// What one side does to a function of the base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Touch {
    Keep,
    /// A new number, never the base's.
    Edit(u32),
    Delete,
}

/// One side: a touch per function of the base, and new functions by where
/// they go in (before the base function of that index, or at the end).
#[derive(Clone, Debug)]
struct Side {
    touches: Vec<Touch>,
    adds: Vec<(usize, String)>,
}

const BASE_VALUE: u32 = 1000;

fn base_name(i: usize) -> String {
    format!("f{i}")
}

/// The base: `n` functions, `f{i}` returning `1000 + i`.
fn base_text(shape: &Shape, n: usize) -> String {
    let side = Side {
        touches: vec![Touch::Keep; n],
        adds: vec![],
    };
    side_text(shape, &side)
}

fn side_text(shape: &Shape, side: &Side) -> String {
    let mut defs = Vec::new();
    let n = side.touches.len();
    for at in 0..=n {
        for (_, name) in side.adds.iter().filter(|(p, _)| *p == at) {
            defs.push(shape.added(name));
        }
        let value = match side.touches.get(at) {
            None | Some(Touch::Delete) => continue,
            Some(Touch::Keep) => BASE_VALUE + at as u32,
            Some(Touch::Edit(v)) => *v,
        };
        defs.push(shape.def(&base_name(at), value));
    }
    format!("{}{}{}", shape.head, defs.join("\n"), shape.tail)
}

/// A side's touches over `n` functions, at most one function of `owned` it
/// does not own, and new functions named with `tag`.
fn side(n: usize, owned: Vec<bool>, edits: Vec<Option<u32>>, adds: Vec<usize>, tag: &str) -> Side {
    let touches = (0..n)
        .map(|i| match (owned[i], edits[i]) {
            (false, _) => Touch::Keep,
            (true, Some(v)) => Touch::Edit(v),
            (true, None) => Touch::Delete,
        })
        .collect();
    let adds = adds
        .into_iter()
        .enumerate()
        .map(|(k, at)| (at.min(n), format!("{tag}{k}")))
        .collect();
    Side { touches, adds }
}

/// Two sides that touch different functions: each function is left alone,
/// or edited or deleted by exactly one of them.
fn disjoint() -> impl Strategy<Value = (usize, Side, Side)> {
    (1usize..8).prop_flat_map(|n| {
        let owner = prop::collection::vec(0u8..3, n);
        let edits = || prop::collection::vec(prop::option::weighted(0.7, 1u32..999), n);
        let adds = || prop::collection::vec(0usize..=n, 0..3);
        (Just(n), owner, edits(), edits(), adds(), adds()).prop_map(|(n, owner, eo, et, ao, at)| {
            let o = side(n, owner.iter().map(|w| *w == 1).collect(), eo, ao, "o");
            let t = side(n, owner.iter().map(|w| *w == 2).collect(), et, at, "t");
            (n, o, t)
        })
    })
}

/// Two sides that also change some functions both, apart: edits to two
/// numbers, or an edit against a delete. The indices of those come back.
fn overlapping() -> impl Strategy<Value = (usize, Side, Side, BTreeSet<usize>)> {
    (
        disjoint(),
        any::<prop::sample::Index>(),
        prop::collection::vec((0u8..3, 1u32..999), 1..4),
    )
        .prop_map(|((n, mut o, mut t), _, both)| {
            let mut hit = BTreeSet::new();
            for (k, (how, v)) in both.into_iter().enumerate() {
                let i = (k * 3 + v as usize) % n;
                let (a, b) = match how {
                    0 => (Touch::Edit(v), Touch::Edit(v + 1000)),
                    1 => (Touch::Edit(v), Touch::Delete),
                    _ => (Touch::Delete, Touch::Edit(v)),
                };
                o.touches[i] = a;
                t.touches[i] = b;
                hit.insert(i);
            }
            (n, o, t, hit)
        })
}

fn config() -> Config {
    Config {
        cases: 48,
        rng_seed: RngSeed::Fixed(40),
        failure_persistence: None,
        ..Config::default()
    }
}

/// Runs `test` over `strategy` for every shape, naming the shape that fails.
fn for_every_shape<S: Strategy>(
    strategy: S,
    test: impl Fn(&Shape, S::Value) -> Result<(), TestCaseError>,
) where
    S::Value: std::fmt::Debug,
{
    for shape in SHAPES {
        let mut runner = TestRunner::new(config());
        if let Err(e) = runner.run(&strategy, |v| test(shape, v)) {
            panic!("{}: {e}", shape.path);
        }
    }
}

/// Facts of `new` against `old`: edits, adds and deletes, by id.
fn facts(shape: &Shape, old: &str, new: &str) -> [BTreeSet<String>; 3] {
    let blob = |k: char| GitId(std::iter::repeat_n(k, 40).collect());
    let map = |id: GitId| {
        FileMap::from([(
            shape.path.to_string(),
            FileEntry {
                mode: FileMode::Regular,
                blob: id,
            },
        )])
    };
    let read = |id: &GitId| -> lonca_core::Result<Vec<u8>> {
        Ok(if *id == blob('a') { old } else { new }.as_bytes().to_vec())
    };
    let a = analyze(ENGINE_CURRENT, &map(blob('a')), &map(blob('b')), &read).expect("facts");
    let set = |v: Vec<String>| v.into_iter().collect::<BTreeSet<_>>();
    [set(a.facts.edits), set(a.facts.adds), set(a.facts.deletes)]
}

fn flatten<'a>(syms: &'a [Sym], out: &mut Vec<&'a Sym>) {
    for s in syms {
        out.push(s);
        flatten(&s.children, out);
    }
}

/// The text of each function in `text`, by its name without the owner.
fn functions(shape: &Shape, text: &str) -> Result<Vec<(String, String)>, TestCaseError> {
    let parsed = parse_at(ENGINE_CURRENT, shape.lang(), text);
    prop_assert!(!parsed.has_error, "does not parse:\n{text}");
    let mut all = Vec::new();
    flatten(&parsed.syms, &mut all);
    let mut out = Vec::new();
    for s in all {
        if let Some(name) = s.name.strip_prefix(shape.owner)
            && !name.contains('.')
            && !name.starts_with('<')
            && name != "C"
        {
            out.push((name.to_string(), s.text(text).trim().to_string()));
        }
    }
    out.sort();
    Ok(out)
}

/// What `side` makes of the function `i` of the base, or of an added name.
fn expected(shape: &Shape, o: &Side, t: &Side) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for i in 0..o.touches.len() {
        let value = match (o.touches[i], t.touches[i]) {
            (Touch::Delete, _) | (_, Touch::Delete) => continue,
            (Touch::Edit(v), _) | (_, Touch::Edit(v)) => v,
            (Touch::Keep, Touch::Keep) => BASE_VALUE + i as u32,
        };
        out.push((
            base_name(i),
            shape.def(&base_name(i), value).trim().to_string(),
        ));
    }
    for (_, name) in o.adds.iter().chain(&t.adds) {
        out.push((name.clone(), shape.added(name).trim().to_string()));
    }
    out.sort();
    out
}

fn ids(shape: &Shape, names: impl IntoIterator<Item = String>) -> BTreeSet<String> {
    names.into_iter().map(|n| shape.id(&n)).collect()
}

/// The facts a side's changes should have.
fn side_facts(shape: &Shape, s: &Side) -> [BTreeSet<String>; 3] {
    let picked = |want: fn(Touch) -> bool| {
        let i = (0..s.touches.len()).filter(|i| want(s.touches[*i]));
        ids(shape, i.map(base_name))
    };
    [
        picked(|t| matches!(t, Touch::Edit(_))),
        ids(shape, s.adds.iter().map(|(_, n)| n.clone())),
        picked(|t| t == Touch::Delete),
    ]
}

/// The layout the sides keep: one line break at the end, no blank line at
/// the start, after a container opens or before it closes, never two in a
/// row.
fn tidy(shape: &Shape, text: &str) -> Result<(), TestCaseError> {
    let bad = |what: &str| TestCaseError::fail(format!("{what}:\n{text}"));
    if text.starts_with(['\n', ' ']) {
        return Err(bad("starts with a gap"));
    }
    if text.contains("\n\n\n") {
        return Err(bad("two blank lines in a row"));
    }
    if !text.ends_with('\n') || text.ends_with("\n\n") {
        return Err(bad("does not end with one line break"));
    }
    if !shape.head.is_empty()
        && !shape.head.ends_with("\n\n")
        && text.contains(&format!("{}\n", shape.head))
    {
        return Err(bad("a blank line after the container opens"));
    }
    if !shape.tail.is_empty() && text.contains(&format!("\n\n{}", shape.tail)) {
        return Err(bad("a blank line before the container closes"));
    }
    Ok(())
}

fn merge(shape: &Shape, b: &str, o: &str, t: &str) -> Result<String, Vec<String>> {
    merge_text_at(ENGINE_CURRENT, shape.path, b, o, t)
}

#[test]
fn disjoint_changes_merge_into_both_sides_facts() {
    for_every_shape(disjoint(), |shape, (n, o, t)| {
        let b = base_text(shape, n);
        let (os, ts) = (side_text(shape, &o), side_text(shape, &t));
        // The generator says what each side does; the facts must agree.
        prop_assert_eq!(facts(shape, &b, &os), side_facts(shape, &o));
        prop_assert_eq!(facts(shape, &b, &ts), side_facts(shape, &t));
        // Two sides that delete every function between them leave nothing
        // to hold the merge to, and it is a conflict on the file: a limit
        // of `holds_up` in every engine, written down in docs/decisions.md.
        if expected(shape, &o, &t).is_empty() {
            return Ok(());
        }
        let merged = match merge(shape, &b, &os, &ts) {
            Ok(m) => m,
            Err(c) => {
                return Err(TestCaseError::fail(format!(
                    "conflicts {c:?}\nbase:\n{b}\nours:\n{os}\ntheirs:\n{ts}"
                )));
            }
        };
        let [oe, oa, od] = side_facts(shape, &o);
        let [te, ta, td] = side_facts(shape, &t);
        let union = [&oe | &te, &oa | &ta, &od | &td];
        prop_assert_eq!(facts(shape, &b, &merged), union, "merged:\n{}", merged);
        prop_assert_eq!(
            functions(shape, &merged)?,
            expected(shape, &o, &t),
            "merged:\n{}",
            merged
        );
        if !os.trim().is_empty() || !ts.trim().is_empty() {
            tidy(shape, &merged)?;
        }
        Ok(())
    });
}

#[test]
fn symbols_changed_on_both_sides_are_exactly_the_conflicts() {
    for_every_shape(overlapping(), |shape, (n, o, t, hit)| {
        let b = base_text(shape, n);
        let (os, ts) = (side_text(shape, &o), side_text(shape, &t));
        let want = ids(shape, hit.iter().map(|i| base_name(*i)));
        match merge(shape, &b, &os, &ts) {
            Ok(m) => Err(TestCaseError::fail(format!(
                "merged without {want:?}:\n{m}\nbase:\n{b}\nours:\n{os}\ntheirs:\n{ts}"
            ))),
            Err(c) => {
                let got: BTreeSet<String> = c.into_iter().collect();
                prop_assert_eq!(got, want, "base:\n{}\nours:\n{}\ntheirs:\n{}", b, os, ts);
                Ok(())
            }
        }
    });
}

#[test]
fn a_change_merged_again_changes_nothing() {
    for_every_shape(disjoint(), |shape, (n, o, t)| {
        let b = base_text(shape, n);
        let (os, ts) = (side_text(shape, &o), side_text(shape, &t));
        prop_assert_eq!(merge(shape, &b, &os, &os), Ok(os.clone()));
        prop_assert_eq!(merge(shape, &b, &b, &ts), Ok(ts.clone()));
        let Ok(m) = merge(shape, &b, &os, &ts) else {
            return Ok(());
        };
        prop_assert_eq!(merge(shape, &b, &m, &ts), Ok(m.clone()), "theirs again");
        prop_assert_eq!(merge(shape, &b, &m, &os), Ok(m.clone()), "ours again");
        Ok(())
    });
}

/// Every language with a grammar has a shape here.
#[test]
fn every_language_has_a_shape() {
    for ext in [
        "rs", "py", "ts", "tsx", "js", "cs", "go", "java", "kt", "c", "cpp", "rb", "php", "swift",
    ] {
        let has = SHAPES.iter().any(|s| s.path.ends_with(&format!(".{ext}")));
        assert!(has, "no shape for .{ext}");
    }
    for shape in SHAPES {
        let text = base_text(shape, 3);
        let names: Vec<String> = functions(shape, &text)
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, ["f0", "f1", "f2"], "{}:\n{text}", shape.path);
    }
}
