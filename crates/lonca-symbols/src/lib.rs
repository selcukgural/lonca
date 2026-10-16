//! Symbols, facts and structural merge.
//!
//! Everything here is a pure function of file contents, so the daemon and
//! the auditor compute exactly the same facts and merges.

pub mod extract;
pub mod facts;
pub mod lang;
pub mod merge;

pub use extract::{Parsed, Sym, parse};
pub use facts::{Analysis, analyze};
pub use lang::Lang;
pub use merge::{MergeResult, merge3};
