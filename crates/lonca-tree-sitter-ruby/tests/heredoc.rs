//! The scanner saves open heredocs in a state of at most 1024 bytes, which
//! tree-sitter hands back before the next token. Upstream 0.23.1 cut a word's
//! length to a byte, and reading such a state back aborted the process; a
//! state of exactly 1025 bytes went one byte past the buffer.

use tree_sitter::{Node, Parser, Tree};

fn parse(text: &str) -> Tree {
    let mut parser = Parser::new();
    parser
        .set_language(&lonca_tree_sitter_ruby::LANGUAGE.into())
        .unwrap();
    parser.parse(text, None).unwrap()
}

fn count(node: Node, kind: &str) -> usize {
    let mut cursor = node.walk();
    let below: usize = node.children(&mut cursor).map(|c| count(c, kind)).sum();
    below + usize::from(node.kind() == kind)
}

fn heredoc(word: &str) -> String {
    format!("x = <<~\"{word}\"\n  body\n{word}\nputs x\n")
}

#[test]
fn a_word_longer_than_a_byte_is_read_back() {
    for len in [1, 254, 255, 256, 300, 511, 512, 1000] {
        let word = "w".repeat(len);
        let tree = parse(&heredoc(&word));
        let root = tree.root_node();
        assert!(
            !root.has_error(),
            "a heredoc word of {len}: {}",
            root.to_sexp()
        );
        assert_eq!(count(root, "heredoc_body"), 1, "a heredoc word of {len}");
    }
}

#[test]
fn a_word_that_runs_to_the_end_of_the_file() {
    for len in [255, 256, 2000] {
        let text = format!("x = <<\"{}", "f".repeat(len));
        parse(&text);
    }
}

/// Four heredocs open at once, their words as long as the state can hold,
/// one byte either way.
#[test]
fn open_heredocs_up_to_the_end_of_the_state() {
    // Two bytes of counts, then four bytes and the word for each heredoc:
    // 2 + 4 * 4 + words = 1025 when the words add up to 1007.
    for total in 1000..=1012 {
        let base = total / 4;
        let lens = [base, base, base, total - 3 * base];
        let words: Vec<String> = lens
            .iter()
            .zip(['a', 'b', 'c', 'd'])
            .map(|(&n, c)| c.to_string().repeat(n))
            .collect();
        let opens: Vec<String> = words.iter().map(|w| format!("<<{w}")).collect();
        let bodies: String = words.iter().map(|w| format!("text\n{w}\n")).collect();
        let text = format!("foo({})\n{bodies}bar\n", opens.join(", "));
        parse(&text);
    }
}

#[test]
fn ruby_without_long_heredocs_parses_cleanly() {
    let text = "class A < B\n  def f(x)\n    <<~EOS\n      #{x}\n    EOS\n  end\nend\n";
    let tree = parse(text);
    assert!(
        !tree.root_node().has_error(),
        "{}",
        tree.root_node().to_sexp()
    );
}

/// A word is kept as bytes. Upstream compared a byte from 0x80 up with the
/// character it came from as a `char`, which is negative where `char` is
/// signed (x86-64, macOS) and not where it is unsigned (Linux on ARM): the
/// heredoc ended on one and ran to the end of the file on the other.
#[test]
fn a_word_with_a_letter_past_ascii_ends_its_heredoc() {
    for word in ["\u{c9}OF", "SQL\u{d6}", "\u{80}", "\u{ff}x\u{e7}"] {
        let text = format!("X = <<~\"{word}\"\n  body\n{word}\nclass Foo\n  def bar; end\nend\n");
        let tree = parse(&text);
        let root = tree.root_node();
        assert!(!root.has_error(), "{word}: {}", root.to_sexp());
        assert_eq!(count(root, "heredoc_end"), 1, "{word}");
        assert!(root.to_sexp().contains("(class name:"), "{word}");
        assert_eq!(count(root, "method"), 1, "{word}");
    }
}
