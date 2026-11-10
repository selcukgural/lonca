//! What each grammar does with the recent syntax of its language.
//!
//! A grammar is older than its language, so the gap is always at the new
//! end. `tests/corpus/<language>/<version>-<feature>.<ext>` holds a few
//! lines of each feature of a language's recent versions, every one with a
//! definition in it. This test reads them all and compares what came out
//! with `tests/corpus/known.txt`: whether the grammar read the sample, and
//! the symbols it gave. A grammar update that closes or opens a gap, or
//! moves a symbol, fails here until the list says so; so does a sample that
//! reads and gives no symbol. Where a sample reads and a definition in it
//! still comes out as no symbol, `tests/corpus/corpus.toml` says so
//! (`no_symbol`), and this test holds that entry to be true as well.
//!
//! The same list is the table at the end of `docs/guide/languages.md`.
//!
//! After adding a sample or updating a grammar, write both again and read
//! the diff:
//!
//! ```sh
//! LONCA_CORPUS=write cargo test -p lonca-symbols --test corpus
//! ```

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use lonca_symbols::engine::{ENGINE_CURRENT, reads_text};
use lonca_symbols::{Lang, Sym, parse};
use serde::Deserialize;

/// What a person calls a language and where its grammar comes from:
/// `tests/corpus/corpus.toml`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct About {
    title: String,
    /// The crate of the grammar, as `Cargo.lock` names it.
    #[serde(rename = "crate")]
    krate: String,
    /// The grammar's version, where the crate's own is not it.
    version: Option<String>,
    /// Definitions that a sample has and that come out as no symbol, by the
    /// sample's file: what the grammar reads and the table does not name yet.
    #[serde(default)]
    no_symbol: BTreeMap<String, Vec<String>>,
}

struct Sample {
    file: String,
    version: String,
    feature: String,
    /// The symbols the grammar gave, or the line where it stopped reading.
    symbols: Result<Vec<String>, usize>,
}

struct Language {
    lang: Lang,
    about: About,
    grammar: String,
    samples: Vec<Sample>,
}

const GUIDE_HEADING: &str = "## What each grammar reads";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn workspace(path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

/// The versions of every package in `Cargo.lock`.
fn locked() -> BTreeMap<String, Vec<String>> {
    #[derive(Deserialize)]
    struct Lock {
        package: Vec<Package>,
    }
    #[derive(Deserialize)]
    struct Package {
        name: String,
        version: String,
    }
    let text = std::fs::read_to_string(workspace("Cargo.lock")).unwrap();
    let lock: Lock = toml::from_str(&text).unwrap();
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for p in lock.package {
        out.entry(p.name).or_default().push(p.version);
    }
    out
}

/// `1.82` before `1.100`, and `9` before `10`.
fn version_key(version: &str) -> Vec<u64> {
    let parts = version.split('.');
    parts
        .map(|p| p.parse().unwrap_or_else(|_| panic!("version {version}")))
        .collect()
}

fn names(syms: &[Sym], out: &mut Vec<String>) {
    for s in syms {
        out.push(s.name.clone());
        names(&s.children, out);
    }
}

/// The line of the first thing the grammar could not read.
fn error_line(lang: Lang, text: &str) -> usize {
    let tree = lang.parse(text).unwrap();
    let mut cursor = tree.walk();
    loop {
        let node = cursor.node();
        if node.is_error() || node.is_missing() {
            return node.start_position().row + 1;
        }
        // Down to where the error is, then on in the order of the text.
        if node.has_error() && cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            assert!(cursor.goto_parent(), "an error with no node");
        }
    }
}

fn sample(lang: Lang, path: &Path) -> Sample {
    let file = path.file_name().unwrap().to_str().unwrap().to_string();
    let (stem, ext) = file
        .rsplit_once('.')
        .unwrap_or_else(|| panic!("{path:?}: no extension"));
    assert_eq!(
        Lang::detect(&file),
        Some(lang),
        "{path:?}: .{ext} is not a file of {lang:?}"
    );
    let (version, feature) = stem
        .split_once('-')
        .unwrap_or_else(|| panic!("{path:?}: not <version>-<feature>.{ext}"));
    version_key(version);
    let text = std::fs::read_to_string(path).unwrap();
    assert!(
        reads_text(ENGINE_CURRENT, lang, &text),
        "{path:?}: too large to be parsed"
    );
    let parsed = parse(lang, &text);
    let symbols = if parsed.has_error {
        Err(error_line(lang, &text))
    } else {
        let mut out = Vec::new();
        names(&parsed.syms, &mut out);
        Ok(out)
    };
    let (version, feature) = (version.to_string(), feature.replace('-', " "));
    Sample {
        file,
        version,
        feature,
        symbols,
    }
}

fn corpus() -> Vec<Language> {
    let about = std::fs::read_to_string(root().join("corpus.toml")).unwrap();
    let mut about: BTreeMap<String, About> = toml::from_str(&about).unwrap();
    let locked = locked();
    let mut out = Vec::new();
    for lang in Lang::all() {
        let name = lang.name();
        let about = about
            .remove(name)
            .unwrap_or_else(|| panic!("corpus.toml has no [{name}]"));
        let versions = locked
            .get(&about.krate)
            .unwrap_or_else(|| panic!("Cargo.lock has no {}", about.krate));
        let version = about
            .version
            .clone()
            .unwrap_or_else(|| versions.join(" and "));
        let grammar = format!("{} {version}", about.krate);
        let dir = root().join(name);
        let files = std::fs::read_dir(&dir).unwrap_or_else(|_| panic!("no samples for {name}"));
        let mut samples: Vec<Sample> = files.map(|f| sample(lang, &f.unwrap().path())).collect();
        samples.sort_by_key(|s| (version_key(&s.version), s.file.clone()));
        assert!(!samples.is_empty(), "no samples for {name}");
        out.push(Language {
            lang,
            about,
            grammar,
            samples,
        });
    }
    assert!(
        about.is_empty(),
        "corpus.toml: no such language: {:?}",
        about.keys()
    );
    for dir in std::fs::read_dir(root()).unwrap() {
        let dir = dir.unwrap();
        if dir.file_type().unwrap().is_dir() {
            let name = dir.file_name();
            let known = out.iter().any(|l| l.lang.name() == name);
            assert!(known, "tests/corpus/{name:?} is no language of the table");
        }
    }
    out
}

/// `tests/corpus/known.txt`.
fn known(corpus: &[Language]) -> String {
    let mut out = String::from(
        "# What each grammar does with the samples next to this file: `error` and the\n\
         # line where it could not read one, or the symbols it gave. Written by tests/corpus.rs\n\
         # (LONCA_CORPUS=write); a change here is a change in what Lonca reads.\n",
    );
    for l in corpus {
        write!(out, "\n{}: {}\n", l.lang.name(), l.grammar).unwrap();
        for s in &l.samples {
            match &s.symbols {
                Ok(symbols) => writeln!(out, "  {}: {}", s.file, symbols.join(", ")).unwrap(),
                Err(line) => writeln!(out, "  {}: error at line {line}", s.file).unwrap(),
            }
        }
    }
    out
}

/// `version: feature, feature; version: feature`, in the order of the versions.
fn by_version(found: Vec<(&Sample, String)>) -> String {
    let mut versions: Vec<(&str, Vec<String>)> = Vec::new();
    for (sample, text) in found {
        match versions.last_mut() {
            Some((version, texts)) if *version == sample.version => texts.push(text),
            _ => versions.push((&sample.version, vec![text])),
        }
    }
    let versions: Vec<String> = versions
        .into_iter()
        .map(|(version, texts)| format!("{version}: {}", texts.join(", ")))
        .collect();
    if versions.is_empty() {
        "nothing found".to_string()
    } else {
        versions.join("; ")
    }
}

/// `1.80 to 1.91`, or `23` for a single version.
fn span(samples: &[Sample]) -> String {
    let first = &samples[0].version;
    let last = &samples[samples.len() - 1].version;
    if first == last {
        first.clone()
    } else {
        format!("{first} to {last}")
    }
}

/// The table of the guide page, from its heading to the end of the file.
fn guide(corpus: &[Language]) -> String {
    let mut out = format!(
        "{GUIDE_HEADING}\n\n\
         A test writes this table (`crates/lonca-symbols/tests/corpus.rs`) from\n\
         small samples of the syntax that recent versions of each language\n\
         brought, and fails when the table and the grammars disagree. A version\n\
         in it is the language's (for JavaScript the year of the standard), the\n\
         one that brought the syntax. \"Nothing found\" is about the samples: a\n\
         grammar may still miss something no sample has.\n\n\
         | Language | Files | Grammar | Versions tried | Samples | Not read | Read, with no symbol for |\n\
         |---|---|---|---|---|---|---|\n"
    );
    for l in corpus {
        let extensions: Vec<String> = l
            .lang
            .extensions()
            .iter()
            .map(|e| format!("`.{e}`"))
            .collect();
        let unread = l.samples.iter().filter(|s| s.symbols.is_err());
        let unread = by_version(unread.map(|s| (s, s.feature.clone())).collect());
        let unnamed = l.samples.iter().filter_map(|s| {
            let names: Vec<String> = l
                .about
                .no_symbol
                .get(&s.file)?
                .iter()
                .map(|n| format!("`{n}`"))
                .collect();
            Some((s, format!("{} ({})", s.feature, names.join(", "))))
        });
        let unnamed = by_version(unnamed.collect());
        writeln!(
            out,
            "| {} | {} | {} | {} | {} | {unread} | {unnamed} |",
            l.about.title,
            extensions.join(" "),
            l.grammar,
            span(&l.samples),
            l.samples.len(),
        )
        .unwrap();
    }
    out
}

/// The lines of `now` that `was` does not have, and the other way round.
fn differences(was: &str, now: &str) -> String {
    let mut out = String::new();
    for (mark, from, other) in [('-', was, now), ('+', now, was)] {
        for line in from.lines().filter(|l| !other.lines().any(|o| o == *l)) {
            writeln!(out, "{mark} {line}").unwrap();
        }
    }
    out
}

#[test]
fn every_grammar_reads_what_the_list_says() {
    let corpus = corpus();
    for l in &corpus {
        for s in &l.samples {
            let empty = s.symbols.as_ref().is_ok_and(Vec::is_empty);
            assert!(
                !empty,
                "{}/{} reads and gives no symbol",
                l.lang.name(),
                s.file
            );
        }
        for (file, absent) in &l.about.no_symbol {
            let at = format!("{}/{file}", l.lang.name());
            let sample = l.samples.iter().find(|s| s.file == *file);
            let sample = sample.unwrap_or_else(|| panic!("corpus.toml: no sample {at}"));
            let Ok(symbols) = &sample.symbols else {
                panic!("corpus.toml: {at} is not read at all, so it has no place in no_symbol");
            };
            for name in absent {
                let given = symbols.contains(name);
                assert!(
                    !given,
                    "{at} gives {name} now: take it out of no_symbol in corpus.toml"
                );
            }
        }
    }
    let list = root().join("known.txt");
    let page = workspace("docs/guide/languages.md");
    let text = std::fs::read_to_string(&page).unwrap();
    let (before, table) = text
        .split_once(GUIDE_HEADING)
        .unwrap_or_else(|| panic!("{page:?} has no \"{GUIDE_HEADING}\""));
    let table = format!("{GUIDE_HEADING}{table}");
    let (known, guide) = (known(&corpus), guide(&corpus));
    if std::env::var("LONCA_CORPUS").is_ok_and(|v| v == "write") {
        std::fs::write(&list, &known).unwrap();
        std::fs::write(&page, format!("{before}{guide}")).unwrap();
        return;
    }
    let listed = std::fs::read_to_string(&list).unwrap_or_default();
    let how = "LONCA_CORPUS=write cargo test -p lonca-symbols --test corpus";
    assert!(
        listed == known,
        "tests/corpus/known.txt no longer says what the grammars read:\n{}\
         write it again and review the diff: {how}",
        differences(&listed, &known)
    );
    assert!(
        table == guide,
        "docs/guide/languages.md no longer says what the grammars read:\n{}\
         write it again: {how}",
        differences(&table, &guide)
    );
}
