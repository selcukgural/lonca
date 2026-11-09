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

use crate::lang::Lang;

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
/// reads a file up to a size, and its names up to a total; version 14 joins
/// by lines a symbol both sides changed, where the caller says it may;
/// version 15 takes ours as the merge when it already has every change of
/// theirs, and deletes a symbol with the wider of the gaps around it; version
/// 16 parses a file within a budget of steps.
pub const ENGINE_CURRENT: u32 = 16;

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

/// The first engine that joins by lines a symbol both sides changed, where
/// [`crate::merge::Joins`] says it may: one held `shared`.
pub const ENGINE_SHARED: u32 = 14;

/// The first engine that takes ours as the merge when the symbol merge finds
/// every change of theirs in it already and the lines of the two meet: the
/// line merge would call that a conflict.
pub const ENGINE_ALREADY: u32 = 15;

/// The first engine that deletes a symbol with the gap around it that holds
/// more line breaks, so that the first of a file or of a container does not
/// leave a blank line behind.
pub const ENGINE_GAPS: u32 = 15;

/// The longest file read for symbols or sections. A longer one goes by its
/// lines, as a file no grammar reads: what people write stays far below this,
/// and what a merge costs grows with it.
pub const MAX_READ: usize = 2 << 20;

/// `engine` reads a file of `len` bytes for symbols or sections.
pub fn reads_size(engine: u32, len: usize) -> bool {
    engine < ENGINE_LIMITS || len <= MAX_READ
}

/// The first engine that parses within [`parse_budget`]: a grammar can take
/// far more work, and memory, than its file is long, and stops there.
pub const ENGINE_BUDGET: u32 = 16;

/// The steps every parse may take, whatever its length.
pub const PARSE_BASE: u64 = 256;

/// The bytes of a file that earn one more step.
pub const PARSE_BYTES_PER_STEP: u64 = 4;

/// The most steps a parse may take.
pub const PARSE_MAX: u64 = 8192;

/// The steps a parse of `len` bytes may take. A step is one check of
/// tree-sitter's progress callback, which it makes after a fixed count of
/// parse actions (100 in tree-sitter 0.27): it counts work, not time, so the
/// auditor stops where the daemon stopped. Code people write takes under a
/// tenth of a step per byte and stays below [`PARSE_MAX`] up to about 200 KB.
pub fn parse_budget(len: usize) -> u64 {
    let len = u64::try_from(len).unwrap_or(u64::MAX);
    PARSE_BASE
        .saturating_add(len / PARSE_BYTES_PER_STEP)
        .min(PARSE_MAX)
}

/// `engine` reads `text` with `lang` for symbols: it is within
/// [`MAX_READ`], and the grammar gets through it within [`parse_budget`]. A
/// text it does not read goes by its lines, as a file no grammar reads.
pub fn reads_text(engine: u32, lang: Lang, text: &str) -> bool {
    reads_size(engine, text.len())
        && (engine < ENGINE_BUDGET || lang.parse_at(engine, text).is_some())
}

/// [`reads_text`] for the bytes of a file; text that is not UTF-8 is not
/// parsed, so only its size counts.
pub fn reads_bytes(engine: u32, lang: Lang, bytes: &[u8]) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(text) => reads_text(engine, lang, text),
        Err(_) => reads_size(engine, bytes.len()),
    }
}

/// Every engine version this build can recompute.
pub const ENGINES_KNOWN: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

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
    fn a_text_is_read_within_its_size_and_its_budget() {
        let rust = Lang::named("rust");
        let large = crate::lang::past_budget("fn a() {}\n");
        assert!(reads_text(ENGINE_BUDGET, rust, "fn a() {}\n"));
        assert!(!reads_text(ENGINE_BUDGET, rust, &large));
        assert!(reads_text(ENGINE_BUDGET - 1, rust, &large));
        let long = "/".repeat(MAX_READ + 1);
        assert!(!reads_text(ENGINE_BUDGET, rust, &long));
        assert!(!reads_text(ENGINE_BUDGET - 1, rust, &long));
        assert!(reads_bytes(ENGINE_BUDGET, rust, b"fn a() {}\n"));
        assert!(!reads_bytes(ENGINE_BUDGET, rust, large.as_bytes()));
        assert!(reads_bytes(ENGINE_BUDGET, rust, b"\xff fn"));
        let mut bad = vec![0xff];
        bad.resize(MAX_READ + 1, b' ');
        assert!(!reads_bytes(ENGINE_BUDGET, rust, &bad));
    }

    #[test]
    fn a_parse_takes_steps_by_its_length_up_to_the_most() {
        assert_eq!(parse_budget(0), PARSE_BASE);
        assert_eq!(parse_budget(3), PARSE_BASE);
        assert_eq!(parse_budget(4), PARSE_BASE + 1);
        assert_eq!(parse_budget(4000), PARSE_BASE + 1000);
        let full = usize::try_from((PARSE_MAX - PARSE_BASE) * PARSE_BYTES_PER_STEP).unwrap();
        assert_eq!(parse_budget(full - 4), PARSE_MAX - 1);
        assert_eq!(parse_budget(full), PARSE_MAX);
        assert_eq!(parse_budget(full + 4), PARSE_MAX);
        assert_eq!(parse_budget(usize::MAX), PARSE_MAX);
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
