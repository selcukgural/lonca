//! The structural merge of one file: base, ours (trunk) and theirs (a
//! proposal), under any engine version.
//!
//! The first two bytes pick the file kind and the engine (`parse::header`);
//! the rest is the three texts, cut at NUL. Each merge must give the same
//! answer twice, as the auditor recomputes it, and a conflict must name
//! something. Under the current engine a merge of three sides that read
//! must read too: it may conflict, but never succeed into a file the
//! grammar can not read.

use lonca_symbols::engine::ENGINE_CURRENT;
use lonca_symbols::merge::{marked_around_conflicts, merge_around_conflicts, merge_text_at};
use lonca_symbols::{Lang, parse_at};

use crate::parse::header;
use crate::texts;

pub fn check(data: &[u8]) {
    let Some((path, engine, rest)) = header(data) else {
        return;
    };
    let [b, o, t] = texts::<3>(rest);
    let merged = merge_text_at(engine, path, &b, &o, &t);
    assert_eq!(
        merged,
        merge_text_at(engine, path, &b, &o, &t),
        "the merge changed its mind"
    );
    if let Err(conflicts) = &merged {
        assert!(!conflicts.is_empty(), "a conflict that names nothing");
    }
    if let (Ok(text), Some(lang)) = (&merged, Lang::detect_at(engine, path))
        && engine == ENGINE_CURRENT
    {
        let reads = |s: &str| !parse_at(engine, lang, s).has_error;
        if reads(&b) && reads(&o) && reads(&t) {
            assert!(
                reads(text),
                "sides that read merged into a file that does not"
            );
        }
    }
    let around = merge_around_conflicts(engine, path, &b, &o, &t);
    assert_eq!(around, merge_around_conflicts(engine, path, &b, &o, &t));
    let _ = marked_around_conflicts(engine, path, [&b, &o, &t], "trunk");
}
