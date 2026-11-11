# lonca-tree-sitter-ruby

The [tree-sitter Ruby grammar](https://github.com/tree-sitter/tree-sitter-ruby)
0.23.1, as published on crates.io, with two fixes in its external scanner
(`src/scanner.c`, the lines marked `lonca:`):

- a heredoc word longer than 255 characters had its length cut to a byte when
  the scanner saved its state, and reading the state back failed an
  assertion, which aborts the process;
- the bound on the saved state let the last byte of a heredoc past the
  buffer tree-sitter gives the scanner.

Upstream fixed both in `ad907a69` (March 2026), with a different encoding,
and has not released it. This crate saves every state the old scanner saved
correctly in exactly the same bytes, so the parse of every file it read
without failing is unchanged.

The second: a heredoc's word is kept as bytes and was compared with the
characters of the text as `char`s. A byte from 0x80 up is negative where
`char` is signed (x86-64, macOS), so a word with a letter from U+0080 to
U+00FF never ended its heredoc there, and did where `char` is unsigned
(Linux on ARM). The byte is read as unsigned now, on every target. Upstream
has this one still. Lonca's symbol engine (`lonca-symbols`) uses it
in place of `tree-sitter-ruby`; Lonca's decision record says when it goes back.

```rust
let mut parser = tree_sitter::Parser::new();
parser.set_language(&lonca_tree_sitter_ruby::LANGUAGE.into()).unwrap();
```

The grammar is MIT licensed (`LICENSE`), as upstream.
