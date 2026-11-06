//! Symbols, facts and structural merge.
//!
//! Everything here is a pure function of file contents, so the daemon and
//! the auditor compute exactly the same facts and merges.

pub mod engine;
pub mod extract;
pub mod facts;
pub mod integrate;
pub mod lang;
pub mod lines;
pub mod merge;
pub mod sections;

pub use extract::{Pair, Parsed, Spot, Sym, align, parse, parse_at, parse_together};
pub use facts::{Analysis, analyze};
pub use lang::Lang;
pub use lonca_core::ops::DEF;
pub use merge::{MergeResult, merge3};
