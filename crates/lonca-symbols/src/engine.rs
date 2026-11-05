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
/// version 3 tells a type's definition from its members.
pub const ENGINE_CURRENT: u32 = 3;

/// The first engine with sections.
pub const ENGINE_SECTIONS: u32 = 1;

/// The first engine that compares the structure and tokens of code outside
/// symbols instead of its text with the whitespace collapsed, and that
/// treats a change of order as a change.
pub const ENGINE_EXACT: u32 = 2;

/// The first engine in which a type's own text is the unit `Type.<def>`,
/// apart from its members.
pub const ENGINE_DEFS: u32 = 3;

/// Every engine version this build can recompute.
pub const ENGINES_KNOWN: &[u32] = &[0, 1, 2, 3];

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
