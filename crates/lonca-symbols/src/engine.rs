//! Versions of the symbol engine.
//!
//! The auditor recomputes the facts of every proposal and the merge of every
//! integration from the Git objects, so an entry's facts must be reproduced
//! by the same code that produced them. Each `change.propose` and
//! `change.integrate` entry records the engine version it used
//! (`OpEntry::symbols_engine`); the daemon writes [`ENGINE_CURRENT`] and the
//! auditor recomputes with the version in the entry.
//!
//! Any change to what extraction, facts or the merge produce, including a
//! tree-sitter grammar or diff library update that changes their output,
//! is a new engine version. The old version stays in the crate, frozen: its
//! output is pinned by `tests/engine.rs` and by the golden logs. See
//! `docs/decisions.md`, "Symbol engine versions".

use lonca_core::{Error, Result};

/// The engine this build writes. Version 0 is the engine of every entry
/// written before versions were recorded; version 1 adds the sections of
/// Markdown, TOML, JSON and YAML files; version 2 compares code exactly;
/// version 3 tells a type's definition from its members; version 4 compares
/// where code stands among symbols; version 5 reads the members of grouped
/// declarations and blocks; version 6 tells symbols of one name apart by
/// what they take instead of by their order; version 7 reports renames;
/// version 8 reports the files no parser reads; version 9 lists among them
/// only a change that is an edit of lines, and merges lines by their own
/// rules; version 10 reads Java, Kotlin, C, C++, Ruby, PHP and Swift; version
/// 11 gives every declaration a signature and lists what mentions the names a
/// change takes away; version 12 reads symbols down to a depth; version 13
/// reads a file up to a size, and its names up to a total.
pub const ENGINE_CURRENT: u32 = 13;

/// The first engine with sections.
pub const ENGINE_SECTIONS: u32 = 1;

/// The first engine that compares the structure and tokens of code outside
/// symbols instead of its text with the whitespace collapsed, and that
/// treats a change of order as a change.
pub const ENGINE_EXACT: u32 = 2;

pub use lonca_core::ops::ENGINE_DEFS;

/// The first engine that treats code that changed places among the symbols
/// around it as a change.
pub const ENGINE_PLACES: u32 = 4;

/// The first engine that reads symbols inside grouped declarations and
/// blocks, attaches a comment only across no blank line, and keeps one name
/// per member of a C# `partial` type.
pub const ENGINE_GROUPS: u32 = 5;

/// The first engine that names symbols of one name by their parameters, so
/// that one added in front of another renames neither.
pub const ENGINE_KEYS: u32 = 6;

/// The first engine whose facts say which deleted symbol goes on as which
/// new one.
pub const ENGINE_RENAMES: u32 = 7;

/// The first engine whose facts list the text files no parser reads.
pub const ENGINE_UNPARSED: u32 = 8;

/// The first engine that does not list a change of what a file is, or one
/// that leaves nothing of it, among the files no parser reads.
pub const ENGINE_LINE_EDITS: u32 = 9;

/// The first engine that merges lines with [`crate::lines`], where a change
/// among equal lines meets all of them.
pub const ENGINE_LINE_MERGE: u32 = 9;

/// The first engine that reads the languages with `since = 10`, and that
/// holds a merge to the symbols and imports all three sides have.
pub const ENGINE_LANGUAGES: u32 = 10;

/// The first engine with a signature for every declaration, and with
/// `affected` in facts.
pub const ENGINE_SIGNATURES: u32 = 11;

/// The first engine that reads symbols and tests down to a depth only, and
/// leaves what stands deeper as text of what is around it.
pub const ENGINE_LEVELS: u32 = 12;

/// The first engine with [`MAX_READ`] and a limit on the text of names.
pub const ENGINE_LIMITS: u32 = 13;

/// The longest file read for symbols or sections. A longer one goes by its
/// lines, as a file no grammar reads: what people write stays far below this,
/// and what a merge costs grows with it.
pub const MAX_READ: usize = 2 << 20;

/// `engine` reads a file of `len` bytes for symbols or sections.
pub fn reads_size(engine: u32, len: usize) -> bool {
    engine < ENGINE_LIMITS || len <= MAX_READ
}

/// Every engine version this build can recompute.
pub const ENGINES_KNOWN: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];

/// Refuses an engine version this build can not recompute.
pub fn check(engine: u32) -> Result<()> {
    if ENGINES_KNOWN.contains(&engine) {
        Ok(())
    } else {
        Err(Error::Unsupported(format!(
            "symbol engine {engine} is not known to this build of lonca \
             (knows {ENGINES_KNOWN:?}); upgrade lonca"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_is_read_up_to_its_size_from_the_engine_of_the_limit() {
        assert!(reads_size(ENGINE_LIMITS, MAX_READ));
        assert!(!reads_size(ENGINE_LIMITS, MAX_READ + 1));
        assert!(reads_size(ENGINE_LIMITS - 1, MAX_READ + 1));
    }

    #[test]
    fn current_is_known_and_others_are_refused() {
        assert!(check(ENGINE_CURRENT).is_ok());
        assert!(ENGINES_KNOWN.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ENGINES_KNOWN.last(), Some(&ENGINE_CURRENT));
        assert!(matches!(
            check(ENGINE_CURRENT + 1),
            Err(Error::Unsupported(m)) if m.contains("upgrade lonca")
        ));
        assert!(check(u32::MAX).is_err());
    }
}
