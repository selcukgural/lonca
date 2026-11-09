//! A file the symbol engine reads: any text, under any engine version the
//! auditor may still be asked to run.
//!
//! The first byte picks the file kind: a language of `languages.toml` (read
//! here as data, so a new language is fuzzed without a change), a format the
//! engine cuts into sections, or plain text. The second picks the engine.
//! The rest is an old and a new version of the file, cut at NUL. Symbols
//! must stand inside their file on character boundaries, sections must add
//! up to the file, and the facts between the two versions must come out.
//! An engine without a parse budget sees only texts the budget lets through
//! ([`bounded`]).

use std::sync::OnceLock;

use lonca_core::{FileEntry, FileMap, FileMode, GitId};
use lonca_symbols::engine::{ENGINE_BUDGET, ENGINES_KNOWN};
use lonca_symbols::sections::{Format, sections};
use lonca_symbols::{Lang, Sym, analyze, parse_at};
use serde::Deserialize;

use crate::{choice, pick, texts};

/// What the engine cuts into sections; JSON is joined, not concatenated.
const SECTION_FILES: &[&str] = &["md", "markdown", "toml", "json", "yml", "yaml"];

/// One file name for every extension the engine knows, and one it does not.
pub fn paths() -> &'static [String] {
    static P: OnceLock<Vec<String>> = OnceLock::new();
    P.get_or_init(|| {
        #[derive(Deserialize)]
        struct Table {
            language: Vec<Language>,
        }
        #[derive(Deserialize)]
        struct Language {
            extensions: Vec<String>,
        }
        let table: Table = toml::from_str(include_str!("../../lonca-symbols/src/languages.toml"))
            .unwrap_or_else(|e| panic!("languages.toml: {e}"));
        let languages = table.language.into_iter().flat_map(|l| l.extensions);
        let others = SECTION_FILES.iter().chain(&["txt"]).map(|e| e.to_string());
        languages
            .chain(others)
            .map(|e| format!("src/f.{e}"))
            .collect()
    })
}

/// A blob id standing in for the `n`th text.
pub fn blob(n: u8) -> GitId {
    GitId(format!("{n:040x}"))
}

/// The file kind, the engine and what is left, from the first two bytes.
pub fn header(data: &[u8]) -> Option<(&'static str, u32, &[u8])> {
    let (c, rest) = choice(data)?;
    let (e, rest) = choice(rest)?;
    let path = pick(paths(), c)?;
    Some((path.as_str(), *pick(ENGINES_KNOWN, e)?, rest))
}

/// `engine` gets through every text of `path` in bounded work. Engines
/// before [`ENGINE_BUDGET`] parse without a budget, and a grammar can take
/// without end on a short text; such an engine is fuzzed only on texts the
/// budget lets through. The auditor runs it on an entry only, and the daemon
/// that wrote the entry got through its files.
pub fn bounded(engine: u32, path: &str, texts: &[&str]) -> bool {
    let within = |lang: Lang| {
        texts
            .iter()
            .all(|t| lang.parse_at(ENGINE_BUDGET, t).is_some())
    };
    engine >= ENGINE_BUDGET || Lang::detect_at(engine, path).is_none_or(within)
}

fn in_bounds(syms: &[Sym], src: &str) {
    for s in syms {
        let ok = |i: usize| i <= src.len() && src.is_char_boundary(i);
        assert!(
            s.start <= s.def_start && s.def_start <= s.end && ok(s.start) && ok(s.end),
            "symbol {} at {}..{} (def {}) in a file of {} bytes",
            s.name,
            s.start,
            s.def_start,
            s.end,
            src.len()
        );
        in_bounds(&s.children, src);
    }
}

pub fn check(data: &[u8]) {
    let Some((path, engine, rest)) = header(data) else {
        return;
    };
    let [old, new] = texts::<2>(rest);
    if !bounded(engine, path, &[&old, &new]) {
        return;
    }
    if let Some(lang) = Lang::detect_at(engine, path) {
        for text in [&old, &new] {
            let parsed = parse_at(engine, lang, text);
            in_bounds(&parsed.syms, text);
            for &(start, end) in &parsed.imports {
                assert!(
                    start <= end && end <= text.len(),
                    "import at {start}..{end}"
                );
            }
        }
    }
    if let Some(format) = Format::detect(path).filter(|&f| f != Format::Json) {
        for text in [&old, &new] {
            if let Some(cut) = sections(format, text) {
                let joined: String = cut.iter().map(|s| s.text.as_str()).collect();
                assert_eq!(
                    &joined, text,
                    "the sections of a {format:?} file are not the file"
                );
            }
        }
    }
    let entry = |n| FileEntry {
        mode: FileMode::Regular,
        blob: blob(n),
    };
    let (mut base, mut next) = (FileMap::new(), FileMap::new());
    base.insert(path.to_string(), entry(1));
    next.insert(path.to_string(), entry(2));
    let read = |id: &GitId| {
        let text = if *id == blob(1) { &old } else { &new };
        Ok(text.as_bytes().to_vec())
    };
    let _ = analyze(engine, &base, &next, &read);
    let _ = analyze(engine, &FileMap::new(), &next, &read);
}
