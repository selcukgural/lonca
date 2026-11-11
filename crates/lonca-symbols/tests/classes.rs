//! A parse is a function of the file, not of the C library a build has.
//!
//! The grammars' scanners ask the C library what is a space, a letter or a
//! digit. musl answers from Unicode, glibc and macOS (in the C locale) know
//! ASCII only, so these files gave one tree on Lonca's Linux builds and
//! another on macOS. The trees here are the ones every build gives now.

#![allow(unsafe_code)]

use lonca_symbols::Lang;

unsafe extern "C" {
    fn iswspace(c: u32) -> i32;
    fn iswalnum(c: u32) -> i32;
    fn iswalpha(c: u32) -> i32;
    fn iswupper(c: u32) -> i32;
    fn iswlower(c: u32) -> i32;
    fn iswdigit(c: u32) -> i32;
    fn iswxdigit(c: u32) -> i32;
}

/// Every code point, as this build's classes take it against ASCII's.
#[test]
fn the_classes_are_those_of_ascii() {
    let ascii = |c: u32| char::from_u32(c).filter(char::is_ascii);
    for c in (0..0x11_0000u32).filter(|c| !(0xd800..0xe000).contains(c)) {
        let a = ascii(c);
        let is = |f: fn(&char) -> bool| a.as_ref().is_some_and(f);
        // SAFETY: the functions of `<wctype.h>` take any value.
        let got = unsafe {
            [
                iswspace(c),
                iswalnum(c),
                iswalpha(c),
                iswupper(c),
                iswlower(c),
                iswdigit(c),
                iswxdigit(c),
            ]
        };
        let want = [
            is(|x| x.is_ascii_whitespace() || *x == '\u{b}'),
            is(char::is_ascii_alphanumeric),
            is(char::is_ascii_alphabetic),
            is(char::is_ascii_uppercase),
            is(char::is_ascii_lowercase),
            is(char::is_ascii_digit),
            is(char::is_ascii_hexdigit),
        ];
        assert_eq!(got.map(|x| x != 0), want, "U+{c:04X}");
    }
}

/// Files with a space or a letter past ASCII where a scanner looks at it,
/// and the trees they have on every build. The first seven had another tree
/// on musl, where U+3000 was a space and U+00E9 a letter.
const FILES: &[(&str, &str, &str)] = &[
    (
        "a.rb",
        "x = <<\u{e9}\n body\n\u{e9}\nclass Foo\nend\n",
        "(program (assignment left: (identifier) (ERROR) right: (identifier)) (identifier) (identifier) (class name: (constant)))",
    ),
    (
        "a.js",
        "let a = 1\u{3000}\nlet b = 2\n",
        "(program (lexical_declaration (variable_declarator name: (identifier) value: (number)) (MISSING \";\")) (lexical_declaration (variable_declarator name: (identifier) value: (number))))",
    ),
    (
        "b.js",
        "a\u{3000}\n++b\n",
        "(program (expression_statement (update_expression argument: (identifier)) (MISSING \";\")) (expression_statement (identifier)))",
    ),
    (
        "a.ts",
        "let a = 1\u{3000}\nfunction f() {}\n",
        "(program (lexical_declaration (variable_declarator name: (identifier) (ERROR (number)) value: (function_expression name: (identifier) parameters: (formal_parameters) body: (statement_block)))))",
    ),
    (
        "a.swift",
        "let a\u{3000}= 1\nfunc f() {}\n",
        "(source_file (property_declaration (value_binding_pattern) name: (pattern bound_identifier: (simple_identifier)) (ERROR (UNEXPECTED 12288)) value: (integer_literal)) (function_declaration name: (simple_identifier) body: (function_body)))",
    ),
    (
        "b.swift",
        "let x = a\u{3000}+b\nlet y = a +\u{3000}b\n",
        "(source_file (property_declaration (value_binding_pattern) name: (pattern bound_identifier: (simple_identifier)) value: (additive_expression lhs: (simple_identifier) (ERROR (UNEXPECTED 12288)) rhs: (simple_identifier))) (property_declaration (value_binding_pattern) name: (pattern bound_identifier: (simple_identifier)) value: (simple_identifier)) (ERROR (UNEXPECTED 12288)))",
    ),
    (
        "b.kt",
        "val a = 1\u{3000}\nfun f() {}\n",
        "(source_file (property_declaration (variable_declaration (identifier)) (number_literal)))",
    ),
    (
        "a.cs",
        "class A { string s = $\"{a\u{3000}}\"; }\n",
        "(compilation_unit (ERROR name: (identifier) (predefined_type) (identifier) (interpolation_start) (interpolation_brace) (ERROR) (string_literal_content)))",
    ),
    (
        "b.php",
        "<?php\n$a\u{3000}= 1;\nfunction f() {}\n",
        "(program (php_tag) (expression_statement (assignment_expression left: (variable_name (name)) right: (integer))) (function_definition name: (name) parameters: (formal_parameters) body: (compound_statement)))",
    ),
];

#[test]
fn a_file_has_one_tree_whatever_the_c_library() {
    for (path, text, tree) in FILES {
        let lang = Lang::detect(path).unwrap();
        let got = lang.parse(text).unwrap().root_node().to_sexp();
        assert_eq!(got, *tree, "{path}");
    }
}
