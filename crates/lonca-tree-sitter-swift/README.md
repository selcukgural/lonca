# lonca-tree-sitter-swift

The [tree-sitter Swift grammar](https://github.com/alex-pinkus/tree-sitter-swift)
0.7.4, as published on crates.io, with one fix in its external scanner
(`src/scanner.c`, the lines marked `lonca:`):

- when a file ended in a compiler directive (`#if`, `#elseif`, `#else`,
  `#endif`), the scanner compared the end of input, a 0, with the 0 that ends
  the directive's name, took it for one more matching character and read the
  byte after the string. AddressSanitizer reports a global-buffer-overflow.

Upstream fixed it in `0c5444e` (October 2026), with the same change, and has
not released it. The byte read never changed the result (a directive that had
matched in full was kept whatever the byte was), so the parse of every file is
unchanged. Lonca's symbol engine (`lonca-symbols`) uses this crate in place of
`tree-sitter-swift`; Lonca's decision record says when it goes back.

```rust
let mut parser = tree_sitter::Parser::new();
parser.set_language(&lonca_tree_sitter_swift::LANGUAGE.into()).unwrap();
```

The grammar is MIT licensed (`LICENSE`), as upstream.
