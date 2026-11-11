//! The tree-sitter Swift grammar 0.7.4 with a read past a string in its
//! external scanner fixed, and a long raw string read the same on every
//! target (README.md). [`LANGUAGE`] goes to a tree-sitter
//! `Parser`:
//!
//! ```
//! let mut parser = tree_sitter::Parser::new();
//! parser
//!     .set_language(&lonca_tree_sitter_swift::LANGUAGE.into())
//!     .unwrap();
//! let tree = parser.parse("func hello(name: String) {\n    print(name)\n}\n", None).unwrap();
//! assert!(!tree.root_node().has_error());
//! ```
// The grammar is C: one foreign function, which returns a pointer to a
// static `TSLanguage` the generated parser defines.
#![allow(unsafe_code)]

use tree_sitter_language::LanguageFn;

unsafe extern "C" {
    fn tree_sitter_swift() -> *const ();
}

/// The tree-sitter [`LanguageFn`] for this grammar.
// SAFETY: `tree_sitter_swift` is the generated parser's entry point, takes
// nothing and returns a pointer to static data, as `from_raw` requires.
pub const LANGUAGE: LanguageFn = unsafe { LanguageFn::from_raw(tree_sitter_swift) };

/// The grammar's `node-types.json`.
pub const NODE_TYPES: &str = include_str!("node-types.json");

/// The grammar's syntax highlighting query.
pub const HIGHLIGHTS_QUERY: &str = include_str!("../queries/highlights.scm");

/// The grammar's injection query.
pub const INJECTIONS_QUERY: &str = include_str!("../queries/injections.scm");

/// The grammar's local-variable query.
pub const LOCALS_QUERY: &str = include_str!("../queries/locals.scm");

/// The grammar's symbol tagging query.
pub const TAGS_QUERY: &str = include_str!("../queries/tags.scm");
