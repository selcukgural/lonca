//! Which symbols mention a name.
//!
//! A heuristic on purpose: pure tree-sitter, so that the auditor recomputes
//! it, and by name alone, so that it knows no language's rules of scope. A
//! mention of `run` may mean another `run`, and a call through a variable or
//! a macro mentions nothing. See `docs/decisions.md`, "Signature changes".

use std::collections::BTreeSet;

use aho_corasick::AhoCorasick;
use lonca_core::ops::{DEF, names_are_headings};
use lonca_core::{Error, FileMap, FileMode, GitId, Result};
use tree_sitter::Node;

use crate::extract::{Parsed, Sym, parse_at};
use crate::facts::MODULE;
use crate::lang::Lang;

/// The most symbols facts list as affected. A name like `new` is mentioned
/// everywhere, and facts are in the log.
pub(crate) const MAX_AFFECTED: usize = 1000;

/// A file past this is read by no one, and parsing it costs the most.
const MAX_FILE_BYTES: usize = 1 << 20;

/// The name code uses for `symbol`: its last part with no key or number, or
/// for `Type.<def>` the type's. Nothing for a heading or a part of a file
/// that is no declaration.
pub(crate) fn used_name(symbol: &str) -> Option<&str> {
    let (path, name) = symbol.split_once('#')?;
    if names_are_headings(path) {
        return None;
    }
    last_name(name)
}

fn last_name(name: &str) -> Option<&str> {
    let mut parts = name.rsplit('.');
    let last = parts.next()?;
    let last = if last == DEF { parts.next()? } else { last };
    let end = last.find(['(', '[', '~']).unwrap_or(last.len());
    let used = last[..end].rsplit("::").next()?;
    (!used.is_empty() && !used.starts_with('<')).then_some(used)
}

/// The symbol `at` stands in, innermost first.
fn holder(syms: &[Sym], at: usize) -> Option<&Sym> {
    let s = syms.iter().find(|s| s.start <= at && at < s.end)?;
    holder(&s.children, at).or(Some(s))
}

/// What a lease on the text at a place in `s` has to name.
fn unit(s: &Sym, engine: u32) -> String {
    s.changed_unit(s, engine)
}

/// `s` declares `name`: the name in its own header is no mention.
fn declares(s: &Sym, name: &str) -> bool {
    let own = last_name(&s.name) == Some(name);
    own || s.def_of.as_deref().and_then(last_name) == Some(name)
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

fn in_file(
    engine: u32,
    lang: Lang,
    path: &str,
    src: &str,
    names: &BTreeSet<String>,
    out: &mut BTreeSet<String>,
) {
    let Parsed {
        syms,
        imports,
        has_error,
        ..
    } = parse_at(engine, lang, src);
    let tree = lang.parse(src).filter(|_| !has_error);
    let Some(tree) = tree else { return };
    let kinds = &lang.rules().names;
    tokens(tree.root_node(), &mut |n| {
        let kind = n.kind();
        let at = n.start_byte();
        let text = &src[at..n.end_byte()];
        if !(kind.contains("identifier") || kinds.iter().any(|k| k == kind))
            || !names.contains(text)
            || imports.iter().any(|(s, e)| *s <= at && at < *e)
        {
            return;
        }
        let name = match holder(&syms, at) {
            Some(s) if declares(s, text) => return,
            Some(s) => unit(s, engine),
            None => MODULE.to_string(),
        };
        out.insert(format!("{path}#{name}"));
    });
}

/// The symbols of the files in `base` that mention one of `names`. A file
/// must hold one of them as bytes to be parsed at all, so most are only read.
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
    let search = AhoCorasick::new(names).map_err(|e| Error::Invalid(e.to_string()))?;
    for (path, entry) in base {
        let Some(lang) = Lang::detect_at(engine, path) else {
            continue;
        };
        if !matches!(entry.mode, FileMode::Regular | FileMode::Executable) {
            continue;
        }
        let bytes = read(&entry.blob)?;
        if bytes.len() > MAX_FILE_BYTES || !search.is_match(&bytes) {
            continue;
        }
        if let Ok(src) = std::str::from_utf8(&bytes) {
            in_file(engine, lang, path, src, names, &mut out);
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
    fn a_name_is_its_last_part_with_no_key_or_number() {
        for (symbol, name) in [
            ("a.rs#f", Some("f")),
            ("a.rs#T.m", Some("m")),
            ("a.rs#T.<def>", Some("T")),
            ("a.rs#T.m(int)", Some("m")),
            ("a.py#P.x[setter]", Some("x")),
            ("a.rs#T.m~2", Some("m")),
            ("a.cpp#ns::T::m", Some("m")),
            ("a.rs#<file>", None),
            ("a.rs#<module>", None),
            ("a.md#Title", None),
            ("no symbol", None),
        ] {
            assert_eq!(used_name(symbol), name, "{symbol}");
        }
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

    #[test]
    fn a_declaration_does_not_mention_itself() {
        assert!(found("a.rs", "fn f() {}\n", NAMES).is_empty());
        assert!(found("a.rs", "struct T { a: u8 }\n", &["T"]).is_empty());
        assert!(found("a.rs", "impl T { }\n", &["T"]).is_empty());
        let other = "impl U { fn f() {} }\n";
        assert!(found("a.rs", other, NAMES).is_empty());
    }

    #[test]
    fn a_mention_is_of_the_innermost_symbol_a_lease_can_name() {
        let src = "struct S { a: T }\nimpl U { fn m() { T::new(); } }\n";
        assert_eq!(found("a.rs", src, &["T"]), ["a.rs#S.<def>", "a.rs#U.m"]);
        let src = "class C:\n    a = f()\n    def m(self):\n        return f()\n";
        assert_eq!(found("a.py", src, NAMES), ["a.py#C.<def>", "a.py#C.m"]);
    }

    #[test]
    fn a_file_with_errors_is_not_read() {
        assert!(found("a.rs", "fn g() { f(; }\n", NAMES).is_empty());
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
        let not_text = b"fn g() { f(); } // \xff\n".to_vec();
        let (out, _) = scan(&[("a.rs", FileMode::Regular, not_text)], NAMES);
        assert!(out.is_empty());
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
        assert!(scanned(MAX_FILE_BYTES + 1).is_empty());
    }
}
