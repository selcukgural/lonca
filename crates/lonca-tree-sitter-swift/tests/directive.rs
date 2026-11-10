//! A file that ends in a compiler directive. Upstream 0.7.4 read the byte
//! after the directive's name there (AddressSanitizer: global-buffer-overflow
//! in `find_possible_compiler_directive`); the parse itself did not depend on
//! that byte, so these trees are the ones 0.7.4 built.

use tree_sitter::{Parser, Tree};

fn parse(text: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&lonca_tree_sitter_swift::LANGUAGE.into())
        .unwrap();
    parser.parse(text, None).unwrap()
}

#[test]
fn a_directive_at_the_end_of_the_file() {
    for (text, tree) in [
        ("#if", "(source_file (ERROR))"),
        ("#elseif", "(source_file (ERROR))"),
        ("#else", "(source_file (directive))"),
        ("#endif", "(source_file (directive))"),
        ("#", "(source_file (ERROR))"),
    ] {
        assert_eq!(parse(text).root_node().to_sexp(), tree, "{text:?}");
    }
}

#[test]
fn directives_before_the_end_parse_as_before() {
    let text = "#if DEBUG\nlet a = 1\n#elseif TEST\nlet a = 2\n#else\nlet a = 3\n#endif\n";
    let tree = parse(text);
    let root = tree.root_node();
    assert!(!root.has_error(), "{}", root.to_sexp());
    // The same text without its last newline ends in a directive.
    let trimmed = parse(text.trim_end());
    assert!(
        !trimmed.root_node().has_error(),
        "{}",
        trimmed.root_node().to_sexp()
    );
}
