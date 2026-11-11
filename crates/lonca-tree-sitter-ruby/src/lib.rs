//! The tree-sitter Ruby grammar 0.23.1 with its heredoc serialization fixed
//! and a heredoc's word read the same on every target (README.md). [`LANGUAGE`] goes to a tree-sitter `Parser`:
//!
//! ```
//! let mut parser = tree_sitter::Parser::new();
//! parser
//!     .set_language(&lonca_tree_sitter_ruby::LANGUAGE.into())
//!     .unwrap();
//! let tree = parser.parse("def hello(name)\n  puts name\nend\n", None).unwrap();
//! assert!(!tree.root_node().has_error());
//! ```
// The grammar is C: one foreign function, which returns a pointer to a
// static `TSLanguage` the generated parser defines.
#![allow(unsafe_code)]

use tree_sitter_language::LanguageFn;

unsafe extern "C" {
    fn tree_sitter_ruby() -> *const ();
}

/// The tree-sitter [`LanguageFn`] for this grammar.
// SAFETY: `tree_sitter_ruby` is the generated parser's entry point, takes
// nothing and returns a pointer to static data, as `from_raw` requires.
pub const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_ruby) };

/// The grammar's `node-types.json`.
pub const NODE_TYPES: &str = include_str!("node-types.json");

/// The grammar's syntax highlighting query.
pub const HIGHLIGHTS_QUERY: &str = include_str!("../queries/highlights.scm");

/// The grammar's local-variable query.
pub const LOCALS_QUERY: &str = include_str!("../queries/locals.scm");

/// The grammar's symbol tagging query.
pub const TAGS_QUERY: &str = include_str!("../queries/tags.scm");
