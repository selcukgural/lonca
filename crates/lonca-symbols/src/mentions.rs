//! Which symbols mention a name.
//!
//! A heuristic on purpose: pure tree-sitter, so that the auditor recomputes
//! it, and by name alone, so that it knows no language's rules of scope. A
//! mention of `run` may mean another `run`, and a call through a variable or
//! a macro mentions nothing. See `docs/decisions.md`, "Signature changes".

use std::collections::BTreeSet;

use aho_corasick::{AhoCorasick, MatchKind};
use lonca_core::ops::{DEF, names_are_headings};
use lonca_core::{Error, FileMap, FileMode, GitId, Result};
use tree_sitter::Node;

use crate::extract::{Parsed, Sym, parse_at};
use crate::facts::{FILE, MODULE};
use crate::lang::{Lang, Rules};

/// The most symbols facts list as affected. A name like `new` is mentioned
/// everywhere, and facts are in the log.
pub(crate) const MAX_AFFECTED: usize = 1000;

/// A file past this is read by no one, and parsing it costs the most.
const MAX_FILE_BYTES: usize = 1 << 20;

/// One part of a name as code writes it: no key or number, no scope in front
/// of it, none of the language's marks around it.
fn spelled<'a>(part: &'a str, rules: Option<&Rules>) -> Option<&'a str> {
    let end = part.find(['(', '[', '~']).unwrap_or(part.len());
    let mut used = part[..end].rsplit("::").next()?;
    for mark in rules.iter().flat_map(|r| &r.marks) {
        used = used.trim_start_matches(mark.as_str());
        used = used.trim_end_matches(mark.as_str());
    }
    let word = used.chars().any(|c| c.is_alphanumeric() || c == '_');
    (word && !used.starts_with('<')).then_some(used)
}

/// `symbol` as path and name. A path can hold a `#` and so can a name, as
/// Rust's `r#type` does: the path is the first that means something here.
fn split_symbol(engine: u32, symbol: &str) -> Option<(&str, &str)> {
    let splits = symbol.match_indices('#').map(|(at, _)| at);
    let splits = splits.map(|at| (&symbol[..at], &symbol[at + 1..]));
    let known = |(path, _): &(&str, &str)| {
        names_are_headings(path) || Lang::detect_at(engine, path).is_some()
    };
    splits.clone().find(known).or(splits.clone().next())
}

/// The names code uses for `symbol`: its last part, for `Type.<def>` the
/// type, and for a constructor the type too. None for a heading or a part of
/// a file that is no declaration.
pub(crate) fn used_names(engine: u32, symbol: &str) -> Vec<&str> {
    let Some((path, name)) = split_symbol(engine, symbol) else {
        return vec![];
    };
    if names_are_headings(path) {
        return vec![];
    }
    let rules = Lang::detect_at(engine, path).map(Lang::rules);
    let mut parts = name.rsplit('.');
    let last = parts.next().filter(|last| *last != DEF);
    let Some(own) = last
        .or_else(|| parts.next())
        .and_then(|p| spelled(p, rules))
    else {
        return vec![];
    };
    let constructor = rules.is_some_and(|r| r.constructors.iter().any(|c| c == own));
    let of_type = parts.next().filter(|_| constructor);
    let of_type = of_type.and_then(|p| spelled(p, rules));
    std::iter::once(own).chain(of_type).collect()
}

/// `symbol` with no keys or numbers in it: what is one declaration however
/// a file with more of that name happens to tell them apart.
pub(crate) fn bare(symbol: &str) -> String {
    let (path, name) = symbol.split_once('#').unwrap_or(("", symbol));
    let cut = |part: &str| part[..part.find(['(', '[', '~']).unwrap_or(part.len())].to_string();
    let parts: Vec<String> = name.split('.').map(cut).collect();
    format!("{path}#{}", parts.join("."))
}

/// The symbol `at` stands in, innermost first.
fn holder(syms: &[Sym], at: usize) -> Option<&Sym> {
    let s = syms.iter().find(|s| s.start <= at && at < s.end)?;
    holder(&s.children, at).or(Some(s))
}

fn tokens<'t>(root: Node<'t>, wanted: &mut impl FnMut(Node<'t>)) {
    let mut cursor = root.walk();
    loop {
        let node = cursor.node();
        if node.child_count() == 0 {
            wanted(node);
        }
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

/// What in `src` mentions `names`, or `false` for a file that can not be read
/// for it. A declaration of the name counts: what implements a trait method
/// has to follow it, and telling that from an unrelated one takes a resolver.
fn in_file(
    engine: u32,
    lang: Lang,
    path: &str,
    src: &str,
    names: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) -> bool {
    // Read for its symbols and for its tokens: one parse.
    let _parses = crate::lang::remember();
    let Parsed {
        syms,
        imports,
        has_error,
        ..
    } = parse_at(engine, lang, src);
    let tree = lang.parse_at(engine, src).filter(|_| !has_error);
    let Some(tree) = tree else { return false };
    let kinds = &lang.rules().names;
    tokens(tree.root_node(), &mut |n| {
        let kind = n.kind();
        let at = n.start_byte();
        if !(kind.contains("identifier") || kinds.iter().any(|k| k == kind))
            || !names.contains(&src[at..n.end_byte()])
            || imports.iter().any(|(s, e)| *s <= at && at < *e)
        {
            return;
        }
        let name = holder(&syms, at).map_or(MODULE.to_string(), |s| s.changed_unit(s, engine));
        out.insert(format!("{path}#{name}"));
    });
    true
}

/// A byte that is part of a name. What is not ASCII can be, or can be a BOM
/// or a space: parsing tells, so such a neighbour does not rule a word out.
fn in_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// The bytes hold one of the names as a word of its own.
fn holds_a_word(search: &AhoCorasick, bytes: &[u8]) -> bool {
    search.find_iter(bytes).any(|m| {
        let before = m.start().checked_sub(1).map(|i| bytes[i]);
        let after = bytes.get(m.end());
        !before.is_some_and(in_word) && !after.is_some_and(|b| in_word(*b))
    })
}

/// The symbols of the files in `base` that mention one of `names`. A file
/// must hold one of them as a word to be parsed at all, so most are only read.
/// One that does and can not be read for symbols counts as a whole.
pub(crate) fn mentions(
    engine: u32,
    base: &FileMap,
    names: &BTreeSet<String>,
    read: &dyn Fn(&GitId) -> Result<Vec<u8>>,
) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    if names.is_empty() {
        return Ok(out);
    }
    let mut search = AhoCorasick::builder();
    search.match_kind(MatchKind::LeftmostLongest);
    let search = search.build(names);
    let search = search.map_err(|e| Error::Invalid(e.to_string()))?;
    for (path, entry) in base {
        let Some(lang) = Lang::detect_at(engine, path) else {
            continue;
        };
        if !matches!(entry.mode, FileMode::Regular | FileMode::Executable) {
            continue;
        }
        let bytes = read(&entry.blob)?;
        if !holds_a_word(&search, &bytes) {
            continue;
        }
        let text = std::str::from_utf8(&bytes).ok();
        let text = text.filter(|_| bytes.len() <= MAX_FILE_BYTES);
        let read_it = text.is_some_and(|src| in_file(engine, lang, path, src, names, &mut out));
        if !read_it {
            out.insert(format!("{path}#{FILE}"));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use lonca_core::FileEntry;

    use super::*;
    use crate::engine::ENGINE_CURRENT;

    const NAMES: &[&str] = &["f"];

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|n| n.to_string()).collect()
    }

    fn found(path: &str, src: &str, list: &[&str]) -> Vec<String> {
        let lang = Lang::detect(path).unwrap();
        let mut out = BTreeSet::new();
        in_file(ENGINE_CURRENT, lang, path, src, &names(list), &mut out);
        out.into_iter().collect()
    }

    #[test]
    fn a_name_is_its_last_part_as_code_writes_it() {
        for (symbol, used) in [
            ("a.rs#f", vec!["f"]),
            ("a.rs#T.m", vec!["m"]),
            ("a.rs#T.<def>", vec!["T"]),
            ("a.rs#T.m(int)", vec!["m"]),
            ("a.py#P.x[setter]", vec!["x"]),
            ("a.rs#T.m~2", vec!["m"]),
            ("a.cpp#ns::T::m", vec!["m"]),
            ("a.php#C.$a", vec!["a"]),
            ("a.rb#C.x=", vec!["x"]),
            ("a.rb#C.valid?", vec!["valid?"]),
            ("a.rb#C.+", vec![]),
            ("a.rb#C.>=", vec![]),
            ("a.swift#C.`class`", vec!["class"]),
            ("C#/a.php#C.$a", vec!["a"]),
            ("a.rs#r#type", vec!["r#type"]),
            ("a.rs#<file>", vec![]),
            ("a.rs#<module>", vec![]),
            ("a.rs#T.<module>", vec![]),
            ("a.md#Title", vec![]),
            ("no symbol", vec![]),
        ] {
            assert_eq!(used_names(ENGINE_CURRENT, symbol), used, "{symbol}");
        }
    }

    #[test]
    fn a_constructor_is_called_by_its_type() {
        for (symbol, used) in [
            ("a.py#C.__init__", vec!["__init__", "C"]),
            ("a.ts#C.constructor", vec!["constructor", "C"]),
            ("a.rb#C.initialize", vec!["initialize", "C"]),
            ("a.php#C.__construct", vec!["__construct", "C"]),
            ("a.swift#C.init", vec!["init", "C"]),
            ("a.kt#C.constructor", vec!["constructor", "C"]),
            ("a.py#constructor", vec!["constructor"]),
            ("a.rs#C.init", vec!["init"]),
            ("a.py#__init__", vec!["__init__"]),
        ] {
            assert_eq!(used_names(ENGINE_CURRENT, symbol), used, "{symbol}");
        }
    }

    #[test]
    fn a_name_without_keys_is_one_declaration() {
        assert_eq!(bare("a.cs#C.M(int)"), "a.cs#C.M");
        assert_eq!(bare("a.cs#C(x).M[g]~2"), "a.cs#C.M");
        assert_eq!(bare("a.rs#f"), "a.rs#f");
        assert_eq!(bare("f"), "#f");
    }

    #[test]
    fn every_language_finds_a_caller() {
        for (path, src, name, caller) in [
            ("a.rs", "fn g() { f(); }\n", "f", "a.rs#g"),
            ("a.py", "def g():\n    f()\n", "f", "a.py#g"),
            ("a.ts", "function g() { f(); }\n", "f", "a.ts#g"),
            ("a.tsx", "function g() { f(); }\n", "f", "a.tsx#g"),
            ("a.js", "function g() { f(); }\n", "f", "a.js#g"),
            (
                "a.cs",
                "class C { int g() { return f(); } }\n",
                "f",
                "a.cs#C.g",
            ),
            ("a.go", "package p\nfunc g() { f() }\n", "f", "a.go#g"),
            (
                "a.java",
                "class C { int g() { return f(); } }\n",
                "f",
                "a.java#C.g",
            ),
            ("a.kt", "fun g() { f() }\n", "f", "a.kt#g"),
            ("a.c", "int g(void) { return f(); }\n", "f", "a.c#g"),
            ("a.cpp", "int g() { return f(); }\n", "f", "a.cpp#g"),
            ("a.rb", "def g\n  f()\nend\n", "f", "a.rb#g"),
            ("a.rb", "def g\n  F.new\nend\n", "F", "a.rb#g"),
            ("a.php", "<?php\nfunction g() { f(); }\n", "f", "a.php#g"),
            ("a.swift", "func g() { f() }\n", "f", "a.swift#g"),
        ] {
            assert_eq!(found(path, src, &[name]), [caller], "{path}: {src}");
        }
    }

    /// An import or a symbol ends where it ends: code right behind it is not
    /// in it, and code anywhere else is not either.
    #[test]
    fn where_an_import_or_a_symbol_ends_is_exact() {
        assert_eq!(
            found("a.ts", "function g() {}f();\n", NAMES),
            ["a.ts#<module>"]
        );
        let src = "import a from \"b\";f();\n";
        assert_eq!(found("a.ts", src, NAMES), ["a.ts#<module>"]);
        let src = "use m::a;\n\nfn g() { f(); }\n";
        assert_eq!(found("a.rs", src, NAMES), ["a.rs#g"]);
    }

    #[test]
    fn a_method_and_a_field_are_mentions_too() {
        let src = "fn g(c: C) { c.f(); c.h.x(); }\n";
        assert_eq!(found("a.rs", src, &["f"]), ["a.rs#g"]);
        assert_eq!(found("a.rs", src, &["h"]), ["a.rs#g"]);
        assert_eq!(found("a.rs", src, &["C"]), ["a.rs#g"]);
    }

    #[test]
    fn words_that_only_look_like_the_name_are_not_mentions() {
        let src = "// f\nfn g() { let a = \"f\"; /* f */ }\nfn ff() {}\n";
        assert!(found("a.rs", src, NAMES).is_empty());
    }

    #[test]
    fn an_import_is_not_a_mention_and_code_outside_symbols_is() {
        assert!(found("a.py", "from m import f\n", NAMES).is_empty());
        assert_eq!(found("a.py", "f()\n", NAMES), ["a.py#<module>"]);
        assert!(found("a.rs", "use m::f;\n", NAMES).is_empty());
    }

    /// What implements a method follows it, and a wrapper calls it.
    #[test]
    fn a_declaration_of_the_name_is_a_mention() {
        let src = "impl R for S {\n    fn f(&self) {}\n}\n";
        assert_eq!(found("a.rs", src, NAMES), ["a.rs#S.R.f"]);
        let src = "impl W {\n    fn f(&self) {\n        self.i.f(1)\n    }\n}\n";
        assert_eq!(found("a.rs", src, NAMES), ["a.rs#W.f"]);
    }

    #[test]
    fn a_mention_is_of_the_innermost_symbol_a_lease_can_name() {
        let src = "struct S { a: T }\nimpl U { fn m() { T::new(); } }\n";
        assert_eq!(found("a.rs", src, &["T"]), ["a.rs#S.<def>", "a.rs#U.m"]);
        let src = "class C:\n    a = f()\n    def m(self):\n        return f()\n";
        assert_eq!(found("a.py", src, NAMES), ["a.py#C.<def>", "a.py#C.m"]);
    }

    #[test]
    fn a_file_with_errors_has_no_symbols_to_name() {
        let mut out = BTreeSet::new();
        let lang = Lang::detect("a.rs").unwrap();
        let src = "fn g() { f(; }\n";
        let read = in_file(ENGINE_CURRENT, lang, "a.rs", src, &names(NAMES), &mut out);
        assert!(!read);
        assert!(out.is_empty());
    }

    fn scan(files: &[(&str, FileMode, Vec<u8>)], list: &[&str]) -> (Vec<String>, u32) {
        let mut base = FileMap::new();
        let mut blobs = Vec::new();
        for (path, mode, bytes) in files {
            let blob = GitId::of_blob(bytes);
            blobs.push((blob.clone(), bytes.clone()));
            base.insert(path.to_string(), FileEntry { blob, mode: *mode });
        }
        let reads = Cell::new(0);
        let read = |id: &GitId| {
            reads.set(reads.get() + 1);
            let hit = blobs.iter().find(|(b, _)| b == id);
            Ok(hit.unwrap().1.clone())
        };
        let out = mentions(ENGINE_CURRENT, &base, &names(list), &read).unwrap();
        (out.into_iter().collect(), reads.get())
    }

    #[test]
    fn only_what_can_be_source_code_is_read() {
        let call = b"fn g() { f(); }\n".to_vec();
        let (out, _) = scan(&[("a.rs", FileMode::Regular, call.clone())], NAMES);
        assert_eq!(out, ["a.rs#g"]);
        let (out, _) = scan(&[("a.rs", FileMode::Executable, call.clone())], NAMES);
        assert_eq!(out, ["a.rs#g"]);
        let (out, _) = scan(&[("a.rs", FileMode::Symlink, call.clone())], NAMES);
        assert!(out.is_empty());
        let (out, reads) = scan(&[("a.txt", FileMode::Regular, call.clone())], NAMES);
        assert!(out.is_empty());
        assert_eq!(reads, 0);
        let (out, reads) = scan(&[("a.rs", FileMode::Regular, call.clone())], &[]);
        assert!(out.is_empty());
        assert_eq!(reads, 0);
        let (out, _) = scan(&[("a.rs", FileMode::Regular, call)], &["h"]);
        assert!(out.is_empty());
    }

    /// What can not be read for symbols may well call it: the whole file
    /// counts, so nobody is told that nothing does.
    #[test]
    fn a_file_that_holds_the_name_and_can_not_be_read_counts_whole() {
        let broken = b"fn g() { f(; }\n".to_vec();
        let (out, _) = scan(&[("a.rs", FileMode::Regular, broken)], NAMES);
        assert_eq!(out, ["a.rs#<file>"]);
        let not_text = b"fn g() { f(); } // \xff\n".to_vec();
        let (out, _) = scan(&[("a.rs", FileMode::Regular, not_text)], NAMES);
        assert_eq!(out, ["a.rs#<file>"]);
        let nothing = b"fn g() { h(; }\n".to_vec();
        let (out, _) = scan(&[("a.rs", FileMode::Regular, nothing)], NAMES);
        assert!(out.is_empty());
    }

    #[test]
    fn a_name_inside_a_longer_word_is_nothing() {
        let mut search = AhoCorasick::builder();
        search.match_kind(MatchKind::LeftmostLongest);
        let search = search.build(["f", "ff"]).unwrap();
        for (text, holds) in [
            ("f", true),
            ("(f)", true),
            ("ff", true),
            ("x ff y", true),
            ("ffx", false),
            ("xf", false),
            ("x_f", false),
            ("éf", true),
            ("fé", true),
            ("\u{feff}f", true),
            ("g", false),
            ("xf f", true),
        ] {
            assert_eq!(holds_a_word(&search, text.as_bytes()), holds, "{text}");
        }
    }

    #[test]
    fn a_huge_file_is_left_out_at_exactly_the_limit() {
        let padded = |len: usize| {
            let mut src = b"fn g() { f(); }\n".to_vec();
            src.resize(len, b'\n');
            src
        };
        let scanned = |len| scan(&[("a.rs", FileMode::Regular, padded(len))], NAMES).0;
        assert_eq!(scanned(MAX_FILE_BYTES), ["a.rs#g"]);
        assert_eq!(scanned(MAX_FILE_BYTES + 1), ["a.rs#<file>"]);
    }
}
