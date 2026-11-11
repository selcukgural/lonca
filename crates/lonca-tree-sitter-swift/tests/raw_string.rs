//! The scanner saves how many `#` opened the raw string it is in, in four
//! bytes. Upstream 0.7.4 read them back as `char`: where that is signed
//! (x86-64, macOS) a count of 128 or more came back with every higher bit
//! set, and the string never ended; where it is unsigned (Linux on ARM) it
//! came back as it was.

use tree_sitter::{Parser, Tree};

fn parse(text: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&lonca_tree_sitter_swift::LANGUAGE.into())
        .unwrap();
    parser.parse(text, None).unwrap()
}

fn raw(hashes: usize) -> String {
    let h = "#".repeat(hashes);
    format!("let s = {h}\"one \\{h}(two) three\"{h}\nfunc after() {{}}\n")
}

#[test]
fn a_raw_string_of_many_hashes_ends_where_it_ends() {
    let few = parse(&raw(3)).root_node().to_sexp();
    assert!(few.contains("function_declaration"), "{few}");
    assert!(few.contains("interpolat"), "{few}");
    for hashes in [1, 127, 128, 129, 255, 256, 300] {
        let tree = parse(&raw(hashes));
        let root = tree.root_node();
        assert!(!root.has_error(), "{hashes}: {}", root.to_sexp());
        assert_eq!(root.to_sexp(), few, "{hashes}");
    }
}
