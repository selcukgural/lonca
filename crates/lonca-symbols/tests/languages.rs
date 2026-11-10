//! What each language of engine 10 is for: agents on different methods of one
//! file. A language is one row here, as it is one entry in the table.

use std::collections::BTreeMap;

use lonca_core::ops::Facts;
use lonca_core::{FileEntry, FileMap, FileMode, GitId};
use lonca_symbols::engine::{ENGINE_CURRENT, ENGINE_LENIENT, ENGINE_MORE_DEFS, ENGINE_PARTIAL};
use lonca_symbols::merge::merge_text_at;
use lonca_symbols::{Lang, analyze, parse, parse_at};

struct Row {
    path: &'static str,
    /// The text of a method called `name`, with `body` in it.
    method: fn(&str, &str) -> String,
    /// The file around its methods.
    file: fn(&str) -> String,
    /// What a method's id starts with.
    owner: &'static str,
}

const ROWS: [Row; 7] = [
    Row {
        path: "a/C.java",
        method: |n, b| format!("    int {n}(int x) {{\n        return x + {b};\n    }}\n\n"),
        file: |m| format!("package app;\n\nclass C {{\n{m}}}\n"),
        owner: "C.",
    },
    Row {
        path: "a/C.kt",
        method: |n, b| format!("    fun {n}(x: Int): Int {{\n        return x + {b}\n    }}\n\n"),
        file: |m| format!("package app\n\nclass C {{\n{m}}}\n"),
        owner: "C.",
    },
    Row {
        path: "a/c.c",
        method: |n, b| format!("int {n}(int x) {{\n    return x + {b};\n}}\n\n"),
        file: |m| format!("#include <stdio.h>\n\n{m}"),
        owner: "",
    },
    Row {
        path: "a/c.cpp",
        method: |n, b| format!("    int {n}(int x) {{\n        return x + {b};\n    }}\n\n"),
        file: |m| format!("#include <vector>\n\nclass C {{\npublic:\n{m}}};\n"),
        owner: "C.",
    },
    Row {
        path: "a/c.rb",
        method: |n, b| format!("  def {n}(x)\n    x + {b}\n  end\n\n"),
        file: |m| format!("require \"json\"\n\nclass C\n{m}end\n"),
        owner: "C.",
    },
    Row {
        path: "a/c.php",
        method: |n, b| {
            format!("    public function {n}($x) {{\n        return $x + {b};\n    }}\n\n")
        },
        file: |m| format!("<?php\n\nclass C {{\n{m}}}\n"),
        owner: "C.",
    },
    Row {
        path: "a/C.swift",
        method: |n, b| {
            format!("    func {n}(x: Int) -> Int {{\n        return x + {b}\n    }}\n\n")
        },
        file: |m| format!("import Foundation\n\nclass C {{\n{m}}}\n"),
        owner: "C.",
    },
];

impl Row {
    fn methods(&self, n: usize) -> String {
        (0..n)
            .map(|i| (self.method)(&format!("m{i}"), &format!("v{i}w")))
            .collect()
    }

    fn base(&self, n: usize) -> String {
        (self.file)(&self.methods(n))
    }

    fn id(&self, name: &str) -> String {
        format!("{}#{}{name}", self.path, self.owner)
    }
}

fn facts_of(engine: u32, path: &str, old: Option<&[u8]>, new: Option<&[u8]>) -> Facts {
    let map = |bytes: Option<&[u8]>| -> FileMap {
        let entry = |text: &[u8]| FileEntry {
            mode: FileMode::Regular,
            blob: GitId::of_blob(text),
        };
        let one = bytes.map(|text| (path.to_string(), entry(text)));
        one.into_iter()
            .collect::<BTreeMap<_, _>>()
            .into_iter()
            .collect()
    };
    let texts: Vec<&[u8]> = [old, new].into_iter().flatten().collect();
    let read = |id: &GitId| {
        let found = texts.iter().find(|t| GitId::of_blob(t) == *id);
        Ok(found.map(|t| t.to_vec()).unwrap_or_default())
    };
    analyze(engine, &map(old), &map(new), &read).unwrap().facts
}

fn facts(engine: u32, path: &str, old: &str, new: &str) -> Facts {
    facts_of(engine, path, Some(old.as_bytes()), Some(new.as_bytes()))
}

#[test]
fn methods_are_symbols_with_no_syntax_error() {
    for row in ROWS {
        let lang = Lang::detect(row.path).unwrap();
        assert!(!lang.is_strict_at(ENGINE_CURRENT), "{}", row.path);
        let p = parse(lang, &row.base(3));
        assert!(!p.has_error, "{}", row.path);
        let mut names = Vec::new();
        fn walk(syms: &[lonca_symbols::Sym], out: &mut Vec<String>) {
            for s in syms {
                out.push(s.name.clone());
                walk(&s.children, out);
            }
        }
        walk(&p.syms, &mut names);
        for i in 0..3 {
            let want = format!("{}m{i}", row.owner);
            assert!(names.contains(&want), "{}: {want} in {names:?}", row.path);
        }
    }
}

#[test]
fn an_edit_names_its_method_and_older_engines_see_a_file() {
    for row in ROWS {
        let base = row.base(3);
        let new = base.replace("v1w", "v1w + 1");
        let f = facts(ENGINE_CURRENT, row.path, &base, &new);
        assert_eq!(f.edits, [row.id("m1")], "{}", row.path);
        assert!(f.unparsed_files.is_empty(), "{}", row.path);
        let old = facts(9, row.path, &base, &new);
        assert_eq!(old.edits, [format!("{}#<file>", row.path)], "{}", row.path);
        assert_eq!(old.unparsed_files, [row.path], "{}", row.path);
    }
}

#[test]
fn twenty_agents_on_one_file() {
    for row in ROWS {
        let base = row.base(20);
        let merge = |o: &str, t: &str| merge_text_at(ENGINE_CURRENT, row.path, &base, o, t);
        let mut trunk = base.clone();
        for i in 0..20 {
            let edited = row
                .methods(20)
                .replace(&format!("v{i}w"), &format!("e{i}w"));
            let added = (row.method)(&format!("n{i}"), "0");
            let theirs = (row.file)(&format!("{edited}{added}"));
            trunk = merge(&trunk, &theirs).unwrap_or_else(|c| panic!("{}, {i}: {c:?}", row.path));
        }
        assert!(
            !parse(Lang::detect(row.path).unwrap(), &trunk).has_error,
            "{trunk}"
        );
        for i in 0..20 {
            assert!(trunk.contains(&format!("e{i}w")), "{}: edit {i}", row.path);
            let added = (row.method)(&format!("n{i}"), "0");
            assert!(trunk.contains(&added), "{}: add {i}", row.path);
        }
    }
}

#[test]
fn two_edits_of_one_method_conflict_on_it() {
    for row in ROWS {
        let base = row.base(3);
        let (o, t) = (base.replace("v1w", "o"), base.replace("v1w", "t"));
        let conflicts = merge_text_at(ENGINE_CURRENT, row.path, &base, &o, &t).unwrap_err();
        assert_eq!(conflicts, [row.id("m1")], "{}", row.path);
    }
}

/// Bytes a parser has no answer for are no reason to refuse or to conflict:
/// these languages fall back to what a file with no grammar gets.
#[test]
fn what_a_grammar_can_not_read_is_a_file_with_no_grammar() {
    let path = "a.kt";
    let unread = "class C { fun f() = 1 }\n\nval a = 1\n\nval b = 2\n\nval c = 3\n";
    let lang = Lang::detect(path).unwrap();
    assert!(
        parse(lang, unread).has_error,
        "the grammar changed: pick another"
    );
    let (o, t) = (
        unread.replace("a = 1", "a = 10"),
        unread.replace("c = 3", "c = 30"),
    );
    let merged = merge_text_at(ENGINE_CURRENT, path, unread, &o, &t).unwrap();
    assert!(
        merged.contains("a = 10") && merged.contains("c = 30"),
        "{merged}"
    );
    // What the error is not in keeps its name; up to engine 17 the file had
    // none left.
    let f = facts(ENGINE_CURRENT, path, unread, &o);
    assert_eq!(f.edits, ["a.kt#a"]);
    assert!(f.unparsed_files.is_empty());
    let f = facts(ENGINE_PARTIAL - 1, path, unread, &o);
    assert_eq!(f.edits, ["a.kt#<file>"]);
    assert_eq!(f.unparsed_files, ["a.kt"]);
    let (one, other) = (
        unread.replace("a = 1", "a = 2"),
        unread.replace("a = 1", "a = 3"),
    );
    let conflicts = merge_text_at(ENGINE_CURRENT, path, unread, &one, &other).unwrap_err();
    assert_eq!(conflicts, ["a.kt#<file>"]);
}

/// What a language reads it holds a line merge to, as any language does: one
/// side moved a method and the other deleted it, and it must not come back.
#[test]
fn a_file_that_reads_is_held_to_what_it_says() {
    let (fa, fb) = ("def a\n  1\nend\n\n", "def b\n  2\nend\n\n");
    let fc = "def c\n  x = 1\n  y = 2\n  z = 3\n  x\nend\n\n";
    let fd = "def d\n  4\nend\n";
    let b = format!("{fa}{fb}{fc}{fd}");
    let t = format!("{fa}{fc}{fb}{fd}");
    let o = format!("{fa}{fc}{fd}");
    let merged = merge_text_at(ENGINE_CURRENT, "a.rb", &b, &o, &t);
    assert_eq!(merged, Err(vec!["a.rb#<file>".to_string()]));
}

/// A preprocessor line ends with its own line end. Taking or adding around
/// it must leave each line on its own: a joined line can still parse, as the
/// rest of a `#define`.
#[test]
fn preprocessor_lines_stay_lines() {
    let at = |path: &str, b: &str, o: &str, t: &str, want: &str| {
        let merged = merge_text_at(ENGINE_CURRENT, path, b, o, t).unwrap();
        assert_eq!(merged, want, "{path}");
    };
    let f = "int f(void) {\n    return 1;\n}\n";
    let g = f.replace("return 1", "return 2");

    // Each with trunk's edit of `f` below it.
    let defines = "#define A 1\n#define B 2\n#define C 3\n\n";
    let gone = "#define A 1\n#define C 3\n\n";
    let (b, o, t, want) = (
        format!("{defines}{f}"),
        format!("{defines}{g}"),
        format!("{gone}{f}"),
        format!("{gone}{g}"),
    );
    at("a.c", &b, &o, &t, &want);

    let macros = "#define A(x) (x)\n#define B(x) (x)\n#define C(x) (x)\n\n";
    let gone = "#define A(x) (x)\n#define C(x) (x)\n\n";
    let (b, o, t, want) = (
        format!("{macros}{f}"),
        format!("{macros}{g}"),
        format!("{gone}{f}"),
        format!("{gone}{g}"),
    );
    at("a.c", &b, &o, &t, &want);

    let guard = "#ifndef A_H\n#define A_H\n#include <a.h>\n#include <b.h>\n\n";
    let gone = "#ifndef A_H\n#define A_H\n#include <b.h>\n\n";
    let (b, o, t, want) = (
        format!("{guard}{f}#endif\n"),
        format!("{guard}{g}#endif\n"),
        format!("{gone}{f}#endif\n"),
        format!("{gone}{g}#endif\n"),
    );
    at("a.h", &b, &o, &t, &want);

    let behind = "int x; // note\n#define N 1\nint y;\n\n";
    let gone = "int x; // note\nint y;\n\n";
    let (b, o, t, want) = (
        format!("{behind}{f}"),
        format!("{behind}{g}"),
        format!("{gone}{f}"),
        format!("{gone}{g}"),
    );
    at("a.c", &b, &o, &t, &want);

    // Something added between two of them.
    let two = "#define A 1\n#define B 2\n\n";
    let added = "#define A 1\n\nint h(void) {\n    return 3;\n}\n#define B 2\n\n";
    let (b, o, t) = (
        format!("{two}{f}"),
        format!("{two}{g}"),
        format!("{added}{f}"),
    );
    let merged = merge_text_at(ENGINE_CURRENT, "a.c", &b, &o, &t).unwrap();
    assert!(merged.contains("}\n#define B 2\n"), "{merged}");
    assert!(
        merged.contains("return 2") && merged.contains("return 3"),
        "{merged}"
    );

    // An include added behind another, in front of a line that is none.
    let (b, o) = ("#include <a.h>\nint x;\n", "#include <a.h>\nint y;\n");
    let t = "#include <a.h>\n#include <b.h>\nint x;\n";
    at("a.c", b, o, t, "#include <a.h>\n#include <b.h>\nint y;\n");
}

/// What only a mistake of the merge would lose: all three sides have it.
#[test]
fn what_all_three_sides_have_stays() {
    let b =
        "#include <a.h>\n\nint f(void) {\n    return 1;\n}\n\nint g(void) {\n    return 2;\n}\n";
    let o = b.replace("return 1", "return 10");
    let t = b.replace("return 2", "return 20");
    let merged = merge_text_at(ENGINE_CURRENT, "a.c", b, &o, &t).unwrap();
    assert!(
        merged.contains("<a.h>") && merged.contains("return 10"),
        "{merged}"
    );
    assert!(merged.contains("return 20"), "{merged}");
}

/// A file that read stops being one nobody can see into only by a person's
/// word: the change is listed, and a file with no grammar it does not become.
#[test]
fn a_side_that_breaks_a_file_that_read_is_listed() {
    let path = "a.java";
    let b = "class C {\n    void a() {\n    }\n\n    @Test\n    void t() {\n    }\n}\n";
    assert!(!parse(Lang::detect(path).unwrap(), b).has_error);
    let no_test = "class C {\n    void a() {\n    }\n}\n@@@\n";
    assert!(parse(Lang::detect(path).unwrap(), no_test).has_error);
    let f = facts(ENGINE_CURRENT, path, b, no_test);
    assert_eq!(f.unread_files, [path], "{f:?}");
    assert!(f.unparsed_files.is_empty(), "{f:?}");
    assert_eq!(f.edits, ["a.java#<file>"], "{f:?}");

    // Staying unread, and being repaired, is no such change.
    let next = no_test.replace("@@@", "@@@ @@@");
    assert!(
        facts(ENGINE_CURRENT, path, no_test, &next)
            .unread_files
            .is_empty()
    );
    assert!(
        facts(ENGINE_CURRENT, path, no_test, b)
            .unread_files
            .is_empty()
    );
    // A language that was strict had the syntax check for it.
    let rust = |engine| facts(engine, "a.rs", "fn a() {}\n", "fn a( {\n").unread_files;
    assert!(rust(ENGINE_LENIENT - 1).is_empty());
    assert_eq!(rust(ENGINE_LENIENT), ["a.rs"]);
}

/// A number follows the order of a name, so numbered siblings can change
/// places with no symbol lost: the merge of lines stands.
#[test]
fn numbered_names_do_not_hold_a_merge_back() {
    let b = "if X:\n    def f():\n        return 1\nelse:\n    def f():\n        return 2\n\n\ndef g():\n    return 3\n";
    let o = b.replacen(
        "def f():\n        return 1",
        "def h():\n        return 1",
        1,
    );
    let t = b.replacen(
        "def f():\n        return 2",
        "def i():\n        return 2",
        1,
    );
    let want = o.replacen(
        "def f():\n        return 2",
        "def i():\n        return 2",
        1,
    );
    assert_eq!(
        merge_text_at(ENGINE_CURRENT, "a.py", b, &o, &t).as_deref(),
        Ok(want.as_str())
    );

    let b = "#ifdef X\nint f(void) {\n    return 1;\n}\n#else\nint f(void) {\n    return 2;\n}\n#endif\n\nint g(void) {\n    return 3;\n}\n";
    let o = b.replacen(
        "int f(void) {\n    return 1",
        "int h(void) {\n    return 1",
        1,
    );
    let t = b.replacen(
        "int f(void) {\n    return 2",
        "int i(void) {\n    return 2",
        1,
    );
    let want = o.replacen(
        "int f(void) {\n    return 2",
        "int i(void) {\n    return 2",
        1,
    );
    assert_eq!(
        merge_text_at(ENGINE_CURRENT, "a.c", b, &o, &t).as_deref(),
        Ok(want.as_str())
    );
}

/// However a file comes to be one nothing reads, a person has agreed.
#[test]
fn no_file_becomes_unread_unseen() {
    let at = |old: Option<&[u8]>, new: Option<&[u8]>| {
        facts_of(ENGINE_CURRENT, "a.java", old, new).unread_files
    };
    let (good, bad) = ("class C {\n}\n".as_bytes(), "class C {\n@@@\n".as_bytes());
    let bytes = b"class C {\n}\n// \xff\n".as_slice();
    assert_eq!(at(Some(good), Some(bytes)), ["a.java"], "bytes");
    assert_eq!(at(None, Some(bad)), ["a.java"], "added broken");
    assert_eq!(at(None, Some(bytes)), ["a.java"], "added as bytes");
    assert!(at(None, Some(good)).is_empty(), "added and read");
    assert!(at(Some(bad), Some(bytes)).is_empty(), "unread already");
    assert!(at(Some(bytes), Some(bad)).is_empty(), "unread already");
    assert!(at(Some(good), None).is_empty(), "deleted");
    let rust = |engine| facts_of(engine, "a.rs", None, Some(bad)).unread_files;
    assert!(
        rust(ENGINE_LENIENT - 1).is_empty(),
        "the syntax check had a strict language"
    );
    assert_eq!(rust(ENGINE_LENIENT), ["a.rs"], "and now no language is");
    let f = facts_of(ENGINE_CURRENT, "a.zig", None, Some(bad));
    assert!(f.unread_files.is_empty(), "no grammar to stop reading");
}

/// A stale base that does not read is no way to break a trunk that does.
#[test]
fn a_base_that_does_not_read_can_not_break_a_trunk_that_does() {
    let path = "a.java";
    let trunk = "class C {\n    int a = 1;\n\n\n\n\n    int b = 2;\n}\n";
    let base = trunk.replace("int b = 2;", "@@@");
    let side = base.replace("int a = 1;", "int a = 2; %%%");
    let conflict = Err(vec!["a.java#<file>".to_string()]);
    assert_eq!(
        merge_text_at(ENGINE_CURRENT, path, &base, trunk, &side),
        conflict
    );
    // Nothing reads before or after: lines decide.
    let o = base.replace("int a = 1;", "int a = 3;\n@@@");
    let t = base.replace("@@@", "@@@ @@@");
    assert!(merge_text_at(ENGINE_CURRENT, path, &base, &o, &t).is_ok());
    // The side repairs the file: the result reads, and it lands.
    let repaired = trunk.replace("int a = 1;", "int a = 1;\n    int c = 3;");
    let merged = merge_text_at(ENGINE_CURRENT, path, &base, trunk, &repaired);
    assert_eq!(merged.as_deref(), Ok(repaired.as_str()));
}

/// The same with blocks or definitions of one name that a side takes away.
#[test]
fn siblings_of_one_name_can_go_on_either_side() {
    let both = |path: &str, b: &str, o: &str, t: &str, want: &str| {
        for (x, y) in [(o, t), (t, o)] {
            let merged = merge_text_at(ENGINE_CURRENT, path, b, x, y);
            assert_eq!(merged.as_deref(), Ok(want), "{path}");
        }
    };
    let e = |n: u32| format!("extension C {{\n    func m{n}() {{\n        x{n}()\n    }}\n}}\n\n");
    let keep = "func k() {\n    w()\n}\n\n";
    let b = format!("{}{keep}{}{keep}{}func z() {{\n}}\n", e(1), e(2), e(3));
    let (o, t) = (b.replace(&e(3), ""), b.replace(&e(2), ""));
    both("a.swift", &b, &o, &t, &o.replace(&e(2), ""));

    let b = "class C {\n    void m();\n    void m() const;\n\n    void n();\n};\n\nvoid C::m() {\n    a();\n}\n\nvoid k() {\n    z();\n}\n\nvoid C::m() const {\n    b();\n}\n";
    let o = b.replace("    void m() const;\n", "");
    let t = b.replace("void C::m() const {\n    b();\n}\n", "");
    both(
        "a.cpp",
        b,
        &o,
        &t,
        &o.replace("void C::m() const {\n    b();\n}\n", ""),
    );
}

/// An unread file is listed for what a file with no grammar is, and no more.
#[test]
fn an_unread_file_keeps_its_lease_for_what_is_no_edit_of_lines() {
    let path = "a.kt";
    let unread = "class C { fun f() = 1 }\n\nval a = 1\n\nval b = 2\n";
    assert_eq!(
        facts(ENGINE_CURRENT, path, unread, "").unparsed_files,
        [""; 0]
    );
    let cut = "class C { fun f() = 1 }\n";
    assert_eq!(
        facts(ENGINE_CURRENT, path, unread, cut).unparsed_files,
        [""; 0]
    );
}

/// Valid code a grammar can not read lands when nobody else is on the file.
#[test]
fn an_unreadable_side_lands_alone_and_conflicts_with_company() {
    let path = "a.kt";
    let b = "class C {\n    fun f() = 1\n}\n\nval a = 1\n";
    let t = format!("{b}\nclass D {{ fun g() = 1 }}\n");
    assert_eq!(
        merge_text_at(ENGINE_CURRENT, path, b, b, &t).as_deref(),
        Ok(t.as_str())
    );
    let o = b.replace("a = 1", "a = 2");
    assert_eq!(
        merge_text_at(ENGINE_CURRENT, path, b, &o, &t),
        Err(vec!["a.kt#<file>".to_string()])
    );
}

/// A language that was strict took a parse error for a mistake, up to the
/// engine that takes it for the grammar's in every language.
#[test]
fn a_language_is_strict_up_to_the_engine_that_is_not() {
    let path = "a.rs";
    let broken = "fn a( {\n\nfn b() {}\n\nfn z() {}\n\nfn last() {}\n";
    let lang = Lang::detect(path).unwrap();
    assert!(lang.is_strict_at(ENGINE_LENIENT - 1));
    assert!(!lang.is_strict_at(ENGINE_LENIENT));
    let o = broken.replace("fn b", "fn c");
    let t = broken.replace("fn last", "fn end");
    let before = facts(ENGINE_LENIENT - 1, path, broken, &o);
    assert!(before.unparsed_files.is_empty(), "{before:?}");
    assert!(merge_text_at(ENGINE_LENIENT - 1, path, broken, &o, &t).is_err());
    let after = facts(ENGINE_LENIENT, path, broken, &o);
    assert_eq!(after.unparsed_files, [path], "{after:?}");
    let merged = merge_text_at(ENGINE_LENIENT, path, broken, &o, &t).unwrap();
    assert_eq!(merged, o.replace("fn last", "fn end"));
}

/// Code that read and now does not takes a person's word in every language:
/// the grammar may be older than the syntax.
#[test]
fn every_language_lists_a_file_that_stops_reading() {
    for (path, good, bad) in [
        ("a.rs", "fn a() {}\n", "fn a( {\n"),
        ("a.py", "def a():\n    pass\n", "def a(:\n    pass\n"),
        ("a.ts", "function a() {}\n", "function a( {\n"),
        ("a.tsx", "function a() {}\n", "function a( {\n"),
        ("a.js", "function a() {}\n", "function a( {\n"),
        ("a.cs", "class C {}\n", "class C {\n"),
        (
            "a.go",
            "package a\n\nfunc a() {}\n",
            "package a\n\nfunc a( {\n",
        ),
    ] {
        let before = facts(ENGINE_LENIENT - 1, path, good, bad);
        assert!(before.unread_files.is_empty(), "{path}: {before:?}");
        let after = facts(ENGINE_LENIENT, path, good, bad);
        assert_eq!(after.unread_files, [path], "{path}");
        let added = facts_of(ENGINE_LENIENT, path, None, Some(bad.as_bytes()));
        assert_eq!(added.unread_files, [path], "{path}");
        let added = facts_of(ENGINE_LENIENT - 1, path, None, Some(bad.as_bytes()));
        assert!(added.unread_files.is_empty(), "{path}");
    }
}

/// An overload added in front of another changes no name: languages that
/// have them read a key by parameters, each in its grammar's own way.
#[test]
fn an_overload_added_in_front_leaves_the_other_alone() {
    for (path, one, other, id) in [
        (
            "a.java",
            "    int f(int a) { return 1; }\n",
            "    int f(long a) { return 2; }\n",
            "C.f(long)",
        ),
        (
            "a.kt",
            "    fun f(a: Int): Int { return 1 }\n\n",
            "    fun f(a: Long): Int { return 2 }\n\n",
            "C.f(a: Long)",
        ),
        (
            "a.cpp",
            "    int f(int a) { return 1; }\n",
            "    int f(long a) { return 2; }\n",
            "C.f(long)",
        ),
        (
            "a.swift",
            "    func f(a: Int) -> Int { return 1 }\n",
            "    func f(a: Int64) -> Int { return 2 }\n",
            "C.f(a: Int64)",
        ),
    ] {
        let open = if path == "a.cpp" {
            "class C {\npublic:\n"
        } else {
            "class C {\n"
        };
        let shut = if path == "a.cpp" { "};\n" } else { "}\n" };
        let (old, new) = (
            format!("{open}{one}{shut}"),
            format!("{open}{other}{one}{shut}"),
        );
        let f = facts(ENGINE_CURRENT, path, &old, &new);
        assert_eq!(f.adds, [format!("{path}#{id}")], "{path}: {f:?}");
        assert!(f.edits.is_empty(), "{path}: {f:?}");
    }
}

/// The table's other shapes, in the files they come from.
#[test]
fn what_each_language_has_of_its_own() {
    let names = |path: &str, text: &str| {
        let mut out = Vec::new();
        fn walk(syms: &[lonca_symbols::Sym], out: &mut Vec<(String, bool, bool)>) {
            for s in syms {
                out.push((s.name.clone(), s.is_test, s.skipped));
                walk(&s.children, out);
            }
        }
        let p = parse(Lang::detect(path).unwrap(), text);
        walk(&p.syms, &mut out);
        (out, p.imports.len(), p.js_tests)
    };
    let has = |list: &[(String, bool, bool)], name: &str, test: bool, skip: bool| {
        assert!(
            list.iter().any(|s| *s == (name.to_string(), test, skip)),
            "{name}: {list:?}"
        );
    };

    let (s, imports, _) = names(
        "a.java",
        "import a.B;\nclass C {\n  int x = 1, y = 2;\n  enum E { A; int f() { return 1; } }\n  @Test\n  @Disabled\n  void t() {}\n  C() {}\n}\n",
    );
    assert_eq!(imports, 1);
    for name in ["C.x", "C.E.A", "C.E.f", "C.C"] {
        has(&s, name, false, false);
    }
    has(&s, "C.t", true, true);

    let (s, imports, _) = names(
        "a.kt",
        "import a.B\nenum class E {\n    A,\n    B;\n\n    fun f() = 1\n}\nclass C {\n    companion object {\n        fun make() = 1\n    }\n\n    constructor()\n\n    val v = 1\n\n    @Test\n    fun t() {\n    }\n}\ntypealias S = String\n",
    );
    assert_eq!(imports, 1);
    for name in ["E.A", "E.B", "E.f", "C.make", "C.constructor", "C.v", "S"] {
        has(&s, name, false, false);
    }
    has(&s, "C.t", true, false);

    let (s, imports, _) = names(
        "a.c",
        "#include <a.h>\n#define N 1\nstruct P { int x; };\ntypedef int I;\nenum K { A };\nint *ptr(void);\nvoid (*h(int s))(int) { return 0; }\n#ifdef X\nint only(void) { return 1; }\n#else\nint other(void) { return 2; }\n#endif\n",
    );
    assert_eq!(imports, 1);
    for name in ["N", "P", "P.x", "I", "K", "ptr", "h", "only", "other"] {
        has(&s, name, false, false);
    }

    let (s, imports, _) = names(
        "a.h",
        "#include <a.h>\nusing std::x;\nnamespace n {\ntemplate <typename T> class C {\n  operator bool() const;\n  int& ref();\n};\n}\nextern \"C\" { int e(void); }\nint C::f() { return 1; }\nTEST(S, N) {}\nTEST(S, DISABLED_M) {}\n",
    );
    assert_eq!(imports, 2);
    for name in ["C", "C.ref", "e", "C.f"] {
        has(&s, name, false, false);
    }
    has(&s, "C.operator bool() const", false, false);
    has(&s, "TEST(S,N)", true, false);

    has(&s, "TEST(S,DISABLED_M)", true, true);

    // A method of a template is a method of the name, and a declaration in
    // front of a type is no symbol of it.
    let (s, _, _) = names(
        "b.cpp",
        "class B;\ntemplate <typename T> class B {\n  void m();\n};\ntemplate <typename T> void B<T>::n() {}\nextern \"C\" int one(int);\n",
    );
    for name in ["B", "B.m", "B.n", "one"] {
        has(&s, name, false, false);
    }

    // A scope inside type arguments is no scope of the name.
    let (s, _, _) = names(
        "c.cpp",
        "template <> void f<a::b>(int x) {}\nvoid Box<c::d>::g() {}\nvoid operator<(int a, int b) {}\n",
    );
    for name in ["f<a::b>", "Box.g", "operator<"] {
        has(&s, name, false, false);
    }

    let (s, imports, calls) = names(
        "a.rb",
        "require \"a\"\nputs 1\nclass C\n  N = 1\n  def self.m; end\n  class << self\n    def o; end\n  end\n  def test_t; skip; end\nend\ndescribe \"d\" do\n  it \"i\" do\n  end\n  xit \"x\" do\n  end\nend\n",
    );
    assert_eq!(imports, 1);
    for name in ["C.N", "C.self.m", "C.o"] {
        has(&s, name, false, false);
    }
    has(&s, "C.test_t", true, true);

    // `load` on something is a call like any other, and goes with the code.
    let (_, imports, _) = names("c.rb", "load \"a.rb\"\nConfig.load(\"b.yml\")\n");
    assert_eq!(imports, 1);
    let calls: Vec<(&str, bool)> = calls.iter().map(|t| (t.name.as_str(), t.skipped)).collect();
    assert_eq!(calls, [("d > i", false), ("d > x", true)]);

    // A skipped group skips what stands in it, however deep.
    let (_, _, calls) = names(
        "b.rb",
        "xdescribe \"d\" do\n  context \"c\" do\n    it \"i\" do\n    end\n  end\nend\n",
    );
    let calls: Vec<(&str, bool)> = calls.iter().map(|t| (t.name.as_str(), t.skipped)).collect();
    assert_eq!(calls, [("d > c > i", true)]);

    let (s, imports, _) = names(
        "a.php",
        "<?php\nuse A\\B;\nnamespace N {\nclass C {\n  const K = 1;\n  private int $p = 1;\n  function testT() {}\n  #[Test]\n  function m() { $this->markTestSkipped(); }\n}\nenum E: string { case R = 'r'; }\ntrait T { function f() {} }\nfunction g() {}\n}\n",
    );
    assert_eq!(imports, 1);
    for name in ["C.K", "C.$p", "E.R", "T.f", "g"] {
        has(&s, name, false, false);
    }
    has(&s, "C.testT", true, false);
    has(&s, "C.m", true, true);

    let (s, imports, _) = names(
        "a.swift",
        "import A\nclass C {\n  init(a: Int) {}\n  deinit {}\n  subscript(i: Int) -> Int { return i }\n  var v: Int { return 1 }\n  func testT() {}\n  @Test(.disabled) func m() {}\n}\nextension C {\n  func more() {}\n}\nprotocol P {\n  func f()\n  var n: Int { get }\n}\nenum E { case a }\ntypealias S = String\n",
    );
    assert_eq!(imports, 1);
    for name in [
        "C.init",
        "C.deinit",
        "C.subscript",
        "C.v",
        "C.more",
        "extension:C",
        "P.f",
        "P.n",
        "E.a",
        "S",
    ] {
        has(&s, name, false, false);
    }
    has(&s, "C.testT", true, false);
    has(&s, "C.m", true, true);
}

/// The definitions of engine 19: read by their grammar before it, they were
/// text of the code around them.
#[test]
fn definitions_of_their_own_from_their_engine_on() {
    let names = |engine: u32, path: &str, text: &str| {
        fn walk(syms: &[lonca_symbols::Sym], out: &mut Vec<String>) {
            for s in syms {
                out.push(s.name.clone());
                walk(&s.children, out);
            }
        }
        let p = parse_at(engine, Lang::detect(path).unwrap(), text);
        assert!(!p.has_error, "{path}");
        let mut out = Vec::new();
        walk(&p.syms, &mut out);
        out
    };
    let cases: [(&str, &str, &[&str], &[&str]); 4] = [
        (
            "a.py",
            "type Pair[T] = tuple[T, T]\ntype N = int\n\ndef f(): pass\n",
            &["Pair", "N", "f"],
            &["f"],
        ),
        (
            "a.cpp",
            "template <typename T>\nconcept Small = sizeof(T) <= 8;\nint f();\n",
            &["Small", "f"],
            &["f"],
        ),
        (
            "a.swift",
            "@attached(member)\nmacro AddInit() = #externalMacro(module: \"M\", type: \"A\")\nfunc f() {}\n",
            &["AddInit", "f"],
            &["f"],
        ),
        // A type declared in a class is a member with members; a field of a
        // type declared elsewhere stays a field, and so does one of a type
        // with no name.
        (
            "b.cpp",
            "struct Task {\n  struct promise_type {\n    int get();\n  };\n  struct node *next;\n  struct { int a; } anon;\n  enum class E { A };\n  class Later;\n};\n",
            &[
                "Task",
                "Task.promise_type",
                "Task.promise_type.get",
                "Task.next",
                "Task.anon",
                "Task.E",
            ],
            &["Task", "Task.next", "Task.anon"],
        ),
    ];
    for (path, text, now, before) in cases {
        assert_eq!(names(ENGINE_MORE_DEFS, path, text), now, "{path}");
        assert_eq!(names(ENGINE_MORE_DEFS - 1, path, text), before, "{path}");
    }
}
