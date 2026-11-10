//! Facts: what a change actually does, computed from two trees.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::ops::Facts;
use lonca_core::{FileEntry, FileMap, FileMode, GitId, Result};

#[cfg(test)]
use crate::engine::ENGINE_KEYS;
use crate::engine::{
    ENGINE_EXACT, ENGINE_LINE_EDITS, ENGINE_PLACES, ENGINE_RENAMES, ENGINE_SECTIONS,
    ENGINE_SIGNATURES, ENGINE_UNPARSED, reads_bytes, reads_size,
};
use crate::extract::{
    MAX_COMPARED, Parsed, Sym, align, best_pairs, likeness, moved, parse_at, parse_together,
    shifted,
};
use crate::lang::Lang;
use crate::mentions::{MAX_AFFECTED, bare, mentions, used_names};
use crate::sections::{APPEND, Format, Section, appended, sections};

pub(crate) const FILE: &str = "<file>";
pub(crate) const MODULE: &str = "<module>";
const IMPORTS: &str = "<imports>";

/// How alike a deleted and an added symbol must be, their names aside, to be
/// one symbol renamed. A fixed number: it decides facts, and so it is engine
/// data like the rest.
const RENAME_LIKENESS: f32 = 0.8;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Analysis {
    pub facts: Facts,
    /// Files in the new tree that a supported parser rejects.
    pub syntax_errors: Vec<String>,
}

fn sym_id(path: &str, name: &str) -> String {
    format!("{path}#{name}")
}

/// `bytes` are text the grammar of `lang` can read.
fn reads(engine: u32, lang: Lang, bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).is_ok_and(|text| !parse_at(engine, lang, text).has_error)
}

/// A change a line merge can stand in for a lease on: lines of one file that
/// stays what it was. A change of mode or of where a link points is none,
/// bytes with a NUL are no lines, and a change that takes away more than
/// half of a file does what deleting it does.
fn edits_lines(b: &FileEntry, n: &FileEntry, old: &str, new: &str, removed: u32) -> bool {
    let plain = matches!(n.mode, FileMode::Regular | FileMode::Executable);
    let text = !old.contains('\0') && !new.contains('\0');
    let lines = old.lines().count();
    b.mode == n.mode && plain && text && lines > 0 && removed as usize * 2 <= lines
}

fn line_counts(old: &str, new: &str) -> (u32, u32) {
    let diff = similar::TextDiff::from_lines(old, new);
    let mut added = 0u32;
    let mut removed = 0u32;
    for op in diff.ops() {
        for change in diff.iter_changes(op) {
            match change.tag() {
                similar::ChangeTag::Insert => added += 1,
                similar::ChangeTag::Delete => removed += 1,
                similar::ChangeTag::Equal => {}
            }
        }
    }
    (added, removed)
}

fn count_lines(s: &str) -> u32 {
    s.lines().count() as u32
}

pub fn analyze(
    engine: u32,
    base: &FileMap,
    new: &FileMap,
    read: &dyn Fn(&GitId) -> Result<Vec<u8>>,
) -> Result<Analysis> {
    let mut f = Facts::default();
    let mut syntax_errors = Vec::new();
    // What a deleted file held: facts name only the file.
    let mut gone = Vec::new();
    let paths: BTreeSet<&String> = base.keys().chain(new.keys()).collect();
    for path in paths {
        let lang = Lang::detect_at(engine, path);
        match (base.get(path), new.get(path)) {
            (None, None) => {}
            (None, Some(n)) => {
                f.added_files.push(path.clone());
                let bytes = read(&n.blob)?;
                let lang = lang.filter(|&l| reads_bytes(engine, l, &bytes));
                if lang.is_some_and(|l| !l.is_strict_at(engine) && !reads(engine, l, &bytes)) {
                    f.unread_files.push(path.clone());
                }
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    f.lines_added += count_lines(text);
                    if let Some(lang) = lang {
                        let p = parse_at(engine, lang, text);
                        if p.has_error {
                            syntax_errors.push(path.clone());
                        }
                        f.tests.added += p.tests(text).len() as u32;
                    }
                }
            }
            (Some(b), None) => {
                f.deleted_files.push(path.clone());
                let bytes = read(&b.blob)?;
                let lang = lang.filter(|&l| reads_bytes(engine, l, &bytes));
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    f.lines_removed += count_lines(text);
                    if let Some(lang) = lang {
                        let p = parse_at(engine, lang, text);
                        f.tests.deleted += p.tests(text).len() as u32;
                        names_in(path, &p.syms, &mut gone);
                    }
                }
            }
            (Some(b), Some(n)) => {
                if b == n {
                    continue;
                }
                f.modified_files.push(path.clone());
                if b.blob == n.blob {
                    // Only the mode changed (e.g. made executable).
                    f.edits.push(sym_id(path, FILE));
                    continue;
                }
                let (old, new_bytes) = (read(&b.blob)?, read(&n.blob)?);
                let in_size = [&old, &new_bytes].map(|t| reads_size(engine, t.len()));
                let in_size = in_size == [true, true];
                let lang = lang.filter(|&l| {
                    in_size && [&old, &new_bytes].iter().all(|t| reads_bytes(engine, l, t))
                });
                let (Ok(old), Ok(newt)) =
                    (std::str::from_utf8(&old), std::str::from_utf8(&new_bytes))
                else {
                    f.edits.push(sym_id(path, FILE));
                    if lang.is_some_and(|l| !l.is_strict_at(engine) && reads(engine, l, &old)) {
                        f.unread_files.push(path.clone());
                    }
                    continue;
                };
                let (a, r) = line_counts(old, newt);
                f.lines_added += a;
                f.lines_removed += r;
                let Some(lang) = lang else {
                    let format = Format::detect(path);
                    let by_section = (engine >= ENGINE_SECTIONS && in_size)
                        .then_some(format)
                        .flatten()
                        .is_some_and(|format| compare_sections(path, format, old, newt, &mut f));
                    if !by_section {
                        f.edits.push(sym_id(path, FILE));
                    }
                    let listed = engine < ENGINE_LINE_EDITS || edits_lines(b, n, old, newt, r);
                    if format.is_none() && engine >= ENGINE_UNPARSED && listed {
                        f.unparsed_files.push(path.clone());
                    }
                    continue;
                };
                let [pb, mut pn] = parse_together(engine, lang, [old, newt]);
                let pairs = align(&pb, &mut pn);
                if engine >= ENGINE_RENAMES {
                    let ids = pairs.iter();
                    let ids = ids.map(|p| [sym_id(path, &p.base), sym_id(path, &p.side)]);
                    f.renames.extend(ids);
                }
                if pn.has_error {
                    syntax_errors.push(path.clone());
                }
                if pb.has_error || pn.has_error {
                    f.edits.push(sym_id(path, FILE));
                    // A file that read until now takes a person's word: what
                    // comes after it here can be seen by nothing but lines.
                    if !lang.is_strict_at(engine) && !pb.has_error {
                        f.unread_files.push(path.clone());
                    }
                    if !lang.is_strict_at(engine) && pb.has_error && edits_lines(b, n, old, newt, r)
                    {
                        f.unparsed_files.push(path.clone());
                    }
                    continue;
                }
                compare_file(engine, path, (&pb, old), (&pn, newt), &mut f);
            }
        }
    }
    for v in [
        &mut f.edits,
        &mut f.adds,
        &mut f.deletes,
        &mut f.added_files,
        &mut f.deleted_files,
        &mut f.modified_files,
        &mut f.signature_changes,
        &mut f.import_only_files,
        &mut f.unparsed_files,
        &mut f.unread_files,
    ] {
        v.sort();
        v.dedup();
    }
    f.renames.sort();
    syntax_errors.sort();
    if engine >= ENGINE_SIGNATURES {
        let names = taken_away(engine, &f, &gone);
        (f.affected, f.affected_more) = affected(engine, base, &names, &f, read)?;
    }
    Ok(Analysis {
        facts: f,
        syntax_errors,
    })
}

fn names_in(path: &str, syms: &[Sym], out: &mut Vec<String>) {
    for s in syms {
        out.push(sym_id(path, &s.name));
        names_in(path, &s.children, out);
    }
}

/// The names code uses for what a change gives a new signature, renames or
/// deletes, the symbols of deleted files in `gone` among them.
fn taken_away(engine: u32, f: &Facts, gone: &[String]) -> BTreeSet<String> {
    let renamed = f.renames.iter().map(|[old, _]| old);
    let all = f.signature_changes.iter().chain(&f.deletes).chain(renamed);
    let names = all.chain(gone).flat_map(|s| used_names(engine, s));
    names.map(String::from).collect()
}

/// `id` or a container of it is in `list`.
fn within(id: &str, list: &BTreeSet<String>) -> bool {
    let mut name = id;
    loop {
        if list.contains(name) {
            return true;
        }
        match name.rsplit_once('.') {
            Some((outer, _)) if outer.contains('#') => name = outer,
            _ => return false,
        }
    }
}

/// The symbols of `base` that mention `names`, sorted and cut to
/// [`MAX_AFFECTED`], and how many were cut. What the change changes itself
/// was looked at by whoever wrote it, what it deletes is gone with what is
/// in it, and so is a deleted file.
fn affected(
    engine: u32,
    base: &FileMap,
    names: &BTreeSet<String>,
    f: &Facts,
    read: &dyn Fn(&GitId) -> Result<Vec<u8>>,
) -> Result<(Vec<String>, u32)> {
    let mut found = mentions(engine, base, names, read)?;
    let renamed = f.renames.iter().flatten();
    let own: BTreeSet<String> = f.edits.iter().chain(renamed).map(|s| bare(s)).collect();
    let gone: BTreeSet<String> = f.deletes.iter().map(|s| bare(s)).collect();
    let in_deleted_file = |id: &String| {
        let mut files = f.deleted_files.iter();
        files.any(|d| {
            id.strip_prefix(d.as_str())
                .is_some_and(|n| n.starts_with('#'))
        })
    };
    found.retain(|id| {
        let name = bare(id);
        !own.contains(&name) && !within(&name, &gone) && !in_deleted_file(id)
    });
    let more = found.len().saturating_sub(MAX_AFFECTED);
    let kept = found.into_iter().take(MAX_AFFECTED).collect();
    Ok((kept, more as u32))
}

/// The sections that differ, or `false` for a file to treat whole: one
/// that has no sections, or whose sections do not show what changed.
fn compare_sections(path: &str, format: Format, old: &str, new: &str, f: &mut Facts) -> bool {
    let (Some(bs), Some(ns)) = (sections(format, old), sections(format, new)) else {
        return false;
    };
    let first_of = |list: &'_ [Section]| {
        let mut out = BTreeMap::new();
        for s in list {
            out.entry(s.name.clone()).or_insert(s.text.clone());
        }
        out
    };
    let (in_base, in_new) = (first_of(&bs), first_of(&ns));
    let before = f.edits.len() + f.adds.len() + f.deletes.len();
    for n in &ns {
        match in_base.get(&n.name) {
            None => f.adds.push(sym_id(path, &n.name)),
            Some(b) if *b == n.text => {}
            Some(b) if format == Format::Markdown && appended(b, &n.text).is_some() => {
                f.adds.push(sym_id(path, &format!("{}.{APPEND}", n.name)));
            }
            Some(_) => f.edits.push(sym_id(path, &n.name)),
        }
    }
    let gone = bs.iter().filter(|b| !in_new.contains_key(&b.name));
    f.deletes.extend(gone.map(|b| sym_id(path, &b.name)));
    f.edits.len() + f.adds.len() + f.deletes.len() > before
}

fn compare_file(
    engine: u32,
    path: &str,
    (pb, old): (&Parsed, &str),
    (pn, new): (&Parsed, &str),
    f: &mut Facts,
) {
    diff_level(engine, path, (&pb.syms, old), (&pn.syms, new), f);
    let places = engine >= ENGINE_PLACES && shifted(pb.placed(), pn.placed());
    if places || pb.residual_at(engine) != pn.residual_at(engine) {
        f.edits.push(sym_id(path, MODULE));
    }
    let (bl, nl) = (pb.import_texts(old), pn.import_texts(new));
    let lists: [Vec<&str>; 2] = [&bl, &nl].map(|l| l.iter().map(String::as_str).collect());
    if engine >= ENGINE_EXACT && !moved(&lists[0], &lists[1]).is_empty() {
        f.edits.push(sym_id(path, IMPORTS));
    }
    let bi: BTreeSet<String> = bl.into_iter().collect();
    let ni: BTreeSet<String> = nl.into_iter().collect();
    if bi != ni {
        if bi.is_subset(&ni) {
            f.import_only_files.push(path.to_string());
        } else {
            f.edits.push(sym_id(path, IMPORTS));
        }
    }
    let bt = pb.tests(old);
    let nt = pn.tests(new);
    for (name, (text, skipped)) in &nt {
        match bt.get(name) {
            None => f.tests.added += 1,
            Some((btext, bskipped)) => {
                if btext != text {
                    f.tests.modified += 1;
                }
                if *skipped && !bskipped {
                    f.tests.skipped += 1;
                }
            }
        }
    }
    f.tests.deleted += bt.keys().filter(|k| !nt.contains_key(*k)).count() as u32;
}

/// The last part of a name as written in the code.
fn written(name: &str) -> &str {
    let last = name.rsplit('.').next().unwrap_or(name);
    let end = last.find(['(', '[', '~']).filter(|at| *at > 0);
    &last[..end.unwrap_or(last.len())]
}

/// What a name is a member of. One list is not one owner: a Go method stands
/// beside the types, named after its own.
fn owner(name: &str) -> Option<&str> {
    name.rsplit_once('.').map(|(owner, _)| owner)
}

/// `own` with its name left out, also where the body calls it. Whole words
/// only: `d` is not in `def`.
fn nameless(s: &Sym) -> String {
    let name = written(&s.name);
    if name.is_empty() {
        return s.own.clone();
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut out = String::new();
    let mut rest = s.own.as_str();
    while let Some(at) = rest.find(name) {
        let (before, after) = (&rest[..at], &rest[at + name.len()..]);
        let alone = !before.ends_with(is_word) && !after.starts_with(is_word);
        out.push_str(before);
        out.push_str(if alone { "\u{1}" } else { name });
        rest = after;
    }
    out.push_str(rest);
    out
}

/// A type goes on under another name only with its members: two shells say
/// nothing. At least half the members of the larger must be in both.
fn same_members(b: &Sym, n: &Sym) -> bool {
    let names = |s: &Sym| -> BTreeSet<String> {
        s.children
            .iter()
            .map(|c| written(&c.name).to_string())
            .collect()
    };
    let (a, c) = (names(b), names(n));
    2 * a.intersection(&c).count() >= a.len().max(c.len()) && !a.is_empty()
}

/// What in the list `bs` goes on under another name in the list `ns`.
pub(crate) fn renames_between<'s>(engine: u32, bs: &'s [Sym], ns: &'s [Sym]) -> Vec<[&'s str; 2]> {
    if engine < ENGINE_RENAMES {
        return Vec::new();
    }
    let (bm, nm) = (by_name(bs), by_name(ns));
    let open = |s: &&Sym, other: &BTreeMap<&str, &Sym>| {
        !other.contains_key(s.name.as_str()) && s.impl_of(engine).is_none()
    };
    let lost: Vec<&Sym> = bs.iter().filter(|b| open(b, &nm)).collect();
    let gained: Vec<&Sym> = ns.iter().filter(|n| open(n, &bm)).collect();
    renamed(&lost, &gained)
}

/// Which of `lost` goes on as which of `gained`, in one list: what is the
/// same with its name left out, or close to it. Past what can be compared, a
/// rename stays a delete and an add.
fn renamed<'s>(lost: &[&'s Sym], gained: &[&'s Sym]) -> Vec<[&'s str; 2]> {
    if lost.len().saturating_mul(gained.len()) > MAX_COMPARED {
        return Vec::new();
    }
    let like = |b: &&Sym, n: &&Sym| {
        let (x, y) = (nameless(b), nameless(n));
        let shape = b.container == n.container && (!b.container || same_members(b, n));
        let shape = shape && owner(&b.name) == owner(&n.name);
        if shape { likeness(&x, &y) } else { 0.0 }
    };
    let pairs = best_pairs(lost, gained, like, RENAME_LIKENESS);
    let names = pairs.into_iter();
    names
        .map(|(i, j)| [lost[i].name.as_str(), gained[j].name.as_str()])
        .collect()
}

fn by_name(syms: &[Sym]) -> BTreeMap<&str, &Sym> {
    syms.iter().map(|s| (s.name.as_str(), s)).collect()
}

/// `new` gave a member a new signature in the text the type holds itself:
/// `int a, b` has the type of `b` in front of `a`, so `b` reads the same.
fn retyped((old, old_src): (&Sym, &str), (new, new_src): (&Sym, &str)) -> bool {
    let olds = by_name(&old.children);
    new.children.iter().any(|n| {
        let b = olds.get(n.name.as_str());
        b.is_some_and(|b| b.same(old_src, n, new_src) && b.signature != n.signature)
    })
}

fn diff_level(
    engine: u32,
    path: &str,
    (bs, old): (&[Sym], &str),
    (ns, new): (&[Sym], &str),
    f: &mut Facts,
) {
    let bm = by_name(bs);
    let nm = by_name(ns);
    for n in ns {
        match bm.get(n.name.as_str()) {
            None => f.adds.push(sym_id(path, &n.name)),
            Some(b) => {
                if b.same(old, n, new) {
                    continue;
                }
                let unit = sym_id(path, &b.changed_unit(n, engine));
                if b.container && n.container {
                    let places = engine >= ENGINE_PLACES && shifted(b.placed(), n.placed());
                    if places || b.own_at(engine) != n.own_at(engine) {
                        f.edits.push(unit.clone());
                        if engine >= ENGINE_SIGNATURES && retyped((b, old), (n, new)) {
                            f.signature_changes.push(unit.clone());
                        }
                    }
                    let (bc, nc) = (&b.children[..], &n.children[..]);
                    diff_level(engine, path, (bc, old), (nc, new), f);
                } else {
                    f.edits.push(unit.clone());
                }
                if let (Some(bs), Some(ns)) = (&b.signature, &n.signature)
                    && bs != ns
                {
                    f.signature_changes.push(unit);
                }
            }
        }
    }
    for b in bs {
        if nm.contains_key(b.name.as_str()) {
            continue;
        }
        match b.impl_of(engine) {
            // No lease on an `impl` reaches the members named after its
            // type, so the type is what stands for the block.
            Some(ty) => {
                f.edits.push(sym_id(path, ty));
                let members = b.children.iter().map(|c| sym_id(path, &c.name));
                f.deletes.extend(members);
            }
            None => f.deletes.push(sym_id(path, &b.name)),
        }
    }
    let renames = renames_between(engine, bs, ns).into_iter();
    f.renames
        .extend(renames.map(|[b, n]| [sym_id(path, b), sym_id(path, n)]));
    if engine >= ENGINE_EXACT {
        let [a, b]: [Vec<&str>; 2] = [bs, ns].map(|l| l.iter().map(|s| s.name.as_str()).collect());
        for name in moved(&a, &b) {
            let ty = nm.get(name.as_str()).and_then(|s| s.impl_of(engine));
            f.edits.push(sym_id(path, ty.unwrap_or(&name)));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{ENGINE_BUDGET, ENGINE_LIMITS, MAX_READ};
    use crate::lang::past_budget;

    /// `text`, filled to `len` bytes with a comment.
    fn filled(text: &str, len: usize) -> String {
        format!("{text}{}\n", "/".repeat(len - text.len() - 1))
    }

    fn read_of<'t>(texts: &'t [&'t str]) -> impl Fn(&GitId) -> Result<Vec<u8>> + 't {
        |id: &GitId| {
            let found = texts.iter().find(|t| GitId::of_blob(t.as_bytes()) == *id);
            Ok(found.unwrap().as_bytes().to_vec())
        }
    }

    fn one_file(path: &str, text: Option<&str>) -> FileMap {
        let mut m = FileMap::new();
        if let Some(text) = text {
            m.insert(
                path.to_string(),
                lonca_core::FileEntry {
                    mode: lonca_core::FileMode::Regular,
                    blob: GitId::of_blob(text.as_bytes()),
                },
            );
        }
        m
    }

    fn analysis(engine: u32, path: &str, old: Option<&str>, new: Option<&str>) -> Analysis {
        let texts: Vec<&str> = [old, new].into_iter().flatten().collect();
        let (b, n) = (one_file(path, old), one_file(path, new));
        analyze(engine, &b, &n, &read_of(&texts)).unwrap()
    }

    const CODE: &str = "fn a() { 1 }\n\n\n\n\nfn b() { 2 }\n";
    const EDITED: &str = "fn a() { 3 }\n\n\n\n\nfn b() { 2 }\n";
    const BROKEN: &str = "fn a( {\n";

    #[test]
    fn a_change_past_the_limit_is_an_edit_of_the_file_on_either_side() {
        let e = ENGINE_LIMITS;
        let (small, large) = (filled(CODE, MAX_READ), filled(CODE, MAX_READ + 1));
        let (edited, edited_large) = (filled(EDITED, MAX_READ), filled(EDITED, MAX_READ + 1));
        let a = analysis(e, "a.rs", Some(&small), Some(&edited));
        assert_eq!(a.facts.edits, ["a.rs#a"]);
        assert!(a.facts.unparsed_files.is_empty());
        for (old, new) in [
            (&large, &edited),
            (&small, &edited_large),
            (&large, &edited_large),
        ] {
            let a = analysis(e, "a.rs", Some(old), Some(new));
            assert_eq!(a.facts.edits, ["a.rs#<file>"], "{}", old.len());
            assert_eq!(a.facts.unparsed_files, ["a.rs"]);
        }
        let old = analysis(e - 1, "a.rs", Some(&large), Some(&edited_large));
        assert_eq!(old.facts.edits, ["a.rs#a"]);
    }

    #[test]
    fn a_file_added_or_deleted_past_the_limit_has_no_symbols_read() {
        let e = ENGINE_LIMITS;
        let tested = "#[test]\nfn t() {}\n";
        let (small, large) = (filled(tested, MAX_READ), filled(tested, MAX_READ + 1));
        assert_eq!(analysis(e, "a.rs", None, Some(&small)).facts.tests.added, 1);
        assert_eq!(analysis(e, "a.rs", None, Some(&large)).facts.tests.added, 0);
        assert_eq!(
            analysis(e - 1, "a.rs", None, Some(&large))
                .facts
                .tests
                .added,
            1
        );
        assert_eq!(
            analysis(e, "a.rs", Some(&small), None).facts.tests.deleted,
            1
        );
        assert_eq!(
            analysis(e, "a.rs", Some(&large), None).facts.tests.deleted,
            0
        );
        assert_eq!(
            analysis(e - 1, "a.rs", Some(&large), None)
                .facts
                .tests
                .deleted,
            1
        );
    }

    #[test]
    fn what_stands_past_the_limit_is_no_syntax_error() {
        let e = ENGINE_LIMITS;
        let large = filled(BROKEN, MAX_READ + 1);
        let added = analysis(e, "a.rs", None, Some(&large));
        assert!(added.syntax_errors.is_empty());
        let changed = analysis(e, "a.rs", Some(CODE), Some(&large));
        assert!(changed.syntax_errors.is_empty());
        let small = filled(BROKEN, MAX_READ);
        assert_eq!(
            analysis(e, "a.rs", None, Some(&small)).syntax_errors,
            ["a.rs"]
        );
    }

    #[test]
    fn a_file_past_the_parse_budget_goes_by_its_lines() {
        let e = ENGINE_BUDGET;
        let (old, new) = (past_budget(CODE), past_budget(EDITED));
        for (o, n) in [
            (&old, &new),
            (&CODE.to_string(), &new),
            (&old, &EDITED.to_string()),
        ] {
            let a = analysis(e, "a.rs", Some(o), Some(n));
            assert_eq!(a.facts.edits, ["a.rs#<file>"], "{}", o.len());
            assert_eq!(a.facts.unparsed_files, ["a.rs"]);
        }
        assert_eq!(
            analysis(e - 1, "a.rs", Some(&old), Some(&new)).facts.edits,
            ["a.rs#a"]
        );
        let tested = past_budget("#[test]\nfn t() {}\n");
        assert_eq!(
            analysis(e, "a.rs", None, Some(&tested)).facts.tests.added,
            0
        );
        assert_eq!(
            analysis(e - 1, "a.rs", None, Some(&tested))
                .facts
                .tests
                .added,
            1
        );
        assert_eq!(
            analysis(e, "a.rs", Some(&tested), None).facts.tests.deleted,
            0
        );
        assert_eq!(
            analysis(e - 1, "a.rs", Some(&tested), None)
                .facts
                .tests
                .deleted,
            1
        );
        let broken = past_budget(BROKEN);
        assert!(
            analysis(e, "a.rs", None, Some(&broken))
                .syntax_errors
                .is_empty()
        );
        assert_eq!(
            analysis(e - 1, "a.rs", None, Some(&broken)).syntax_errors,
            ["a.rs"]
        );
    }

    #[test]
    fn sections_past_the_limit_are_an_edit_of_the_file() {
        let e = ENGINE_LIMITS;
        let sides = |len, n: u32| filled(&format!("[a]\nx = {n}\n[b]\ny = 2\n# "), len);
        let (old, new) = (sides(MAX_READ, 1), sides(MAX_READ, 3));
        assert_eq!(section_facts(e, "a.toml", &old, &new).edits, ["a.toml#a.x"]);
        for (o, n) in [(MAX_READ + 1, MAX_READ), (MAX_READ, MAX_READ + 1)] {
            let (old, new) = (sides(o, 1), sides(n, 3));
            assert_eq!(
                section_facts(e, "a.toml", &old, &new).edits,
                ["a.toml#<file>"]
            );
        }
    }

    fn section_facts(engine: u32, path: &str, old: &str, new: &str) -> Facts {
        let map = |text: &str| {
            let mut m = FileMap::new();
            m.insert(
                path.to_string(),
                lonca_core::FileEntry {
                    mode: lonca_core::FileMode::Regular,
                    blob: GitId::of_blob(text.as_bytes()),
                },
            );
            m
        };
        let (old, new) = (old.to_string(), new.to_string());
        let (o, n) = (old.clone(), new.clone());
        let read = move |id: &GitId| {
            let text = if *id == GitId::of_blob(o.as_bytes()) {
                &o
            } else {
                &n
            };
            Ok(text.clone().into_bytes())
        };
        analyze(engine, &map(&old), &map(&new), &read)
            .unwrap()
            .facts
    }

    /// A type's own text is `Type.<def>` from engine 3, in every list that
    /// names it, and older engines keep the name they recorded.
    #[test]
    fn engine_3_reports_the_definition_of_a_type() {
        let (old, new) = (
            "struct S<T> {\n    a: T,\n}\n",
            "struct S<U> {\n    a: U,\n}\n",
        );
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S.<def>"]);
        assert_eq!(f.signature_changes, ["a.rs#S.<def>"]);
        let f = section_facts(2, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S"]);
        assert_eq!(f.signature_changes, ["a.rs#S"]);

        let (old, new) = ("class A:\n    x = 1\n", "class A:\n    x = 2\n");
        assert_eq!(section_facts(3, "a.py", old, new).edits, ["a.py#A.<def>"]);
        assert_eq!(section_facts(2, "a.py", old, new).edits, ["a.py#A"]);

        let f = section_facts(3, "a.rs", "fn f(a: u8) {}\n", "fn f(a: u16) {}\n");
        assert_eq!(f.edits, ["a.rs#f"]);
        assert_eq!(f.signature_changes, ["a.rs#f"]);
    }

    /// Each row: a file, what stands above the symbol that was there, and
    /// the name a second symbol of that name gives it. The new one is an
    /// addition and nothing else, wherever it landed.
    #[test]
    fn a_symbol_added_in_front_of_another_of_its_name_renames_nothing() {
        let rows = [
            (
                "a.cs",
                "class C {\n    void Charge(string s) {\n        A();\n    }\n}\n",
                "    void Charge(int a, int b) {\n        B();\n    }\n",
                "    void Charge(string s) {",
                "a.cs#C.Charge(int,int)",
            ),
            (
                "a.ts",
                "class C {\n  m(a: string) {\n    x();\n  }\n}\n",
                "  m(a: number): void;\n",
                "  m(a: string) {",
                "a.ts#C.m(number)",
            ),
            (
                "a.py",
                "class P:\n    @x.setter\n    def x(self, v):\n        pass\n",
                "    @property\n    def x(self):\n        return 1\n\n",
                "    @x.setter",
                "a.py#P.x(self)",
            ),
        ];
        for (path, old, above, at, added) in rows {
            let new = old.replacen(at, &format!("{above}{at}"), 1);
            let f = section_facts(ENGINE_KEYS, path, old, &new);
            assert_eq!(f.adds, [added], "{path}");
            assert!(f.edits.is_empty(), "{path}: {:?}", f.edits);
            assert!(f.deletes.is_empty(), "{path}: {:?}", f.deletes);
            // The number of engine 5 is what this replaces.
            let f = section_facts(ENGINE_KEYS - 1, path, old, &new);
            assert!(!f.edits.is_empty() || f.adds != [added], "{path}");
        }
    }

    #[test]
    fn a_trait_impl_added_in_front_of_another_renames_nothing() {
        let (first, second) = (
            "impl From<u8> for S {\n    fn from(v: u8) -> S {\n        S\n    }\n}\n",
            "impl From<u16> for S {\n    fn from(v: u16) -> S {\n        S\n    }\n}\n",
        );
        let new = format!("{second}{first}");
        let f = section_facts(ENGINE_KEYS, "a.rs", first, &new);
        assert_eq!(f.adds, ["a.rs#impl:S.From(u16)"]);
        assert!(f.edits.is_empty(), "{:?}", f.edits);
        assert!(f.deletes.is_empty(), "{:?}", f.deletes);
    }

    /// Facts name a symbol as `base` does when the edit gives it a new key,
    /// or a lease on it would not reach its own change.
    #[test]
    fn a_change_of_parameters_is_an_edit_of_the_symbol() {
        let old = "class C {\n    void M(int a) { A(); }\n    void M(string s) { B(); }\n}\n";
        let new = old.replace("M(int a)", "M(long a)");
        let f = section_facts(ENGINE_KEYS, "a.cs", old, &new);
        assert_eq!(f.edits, ["a.cs#C.M(int)"]);
        assert_eq!(f.signature_changes, ["a.cs#C.M(int)"]);
        assert!(f.adds.is_empty() && f.deletes.is_empty(), "{f:?}");
    }

    /// Each row: a language, its text, and the name that changes. The code
    /// is the same, recursive calls included, or close to it.
    #[test]
    fn a_rename_is_reported_in_every_language() {
        let rows = [
            (
                "a.rs",
                "struct S;\nimpl S {\n    fn old(&self) -> u8 {\n        self.old() + 1\n    }\n}\n",
                "old",
                "new",
                "a.rs#S.old",
                "a.rs#S.new",
            ),
            (
                "a.py",
                "class C:\n    def old(self, a):\n        return a + 1\n",
                "old",
                "fresh",
                "a.py#C.old",
                "a.py#C.fresh",
            ),
            (
                "a.ts",
                "class C {\n  old(a: number) {\n    return a + 1;\n  }\n}\n",
                "old",
                "fresh",
                "a.ts#C.old",
                "a.ts#C.fresh",
            ),
            (
                "a.js",
                "function old(a) {\n  return a + 1;\n}\n",
                "old",
                "fresh",
                "a.js#old",
                "a.js#fresh",
            ),
            (
                "a.cs",
                "class C {\n    int Old(int a) {\n        return a + 1;\n    }\n}\n",
                "Old",
                "New",
                "a.cs#C.Old",
                "a.cs#C.New",
            ),
            (
                "a.go",
                "package p\n\nfunc (t T) Old(a int) int {\n\treturn a + 1\n}\n",
                "Old",
                "New",
                "a.go#T.Old",
                "a.go#T.New",
            ),
        ];
        for (path, old, from, to, was, is) in rows {
            let new = old.replace(from, to);
            let f = section_facts(ENGINE_RENAMES, path, old, &new);
            assert_eq!(f.renames, [[was.to_string(), is.to_string()]], "{path}");
            assert_eq!(f.deletes, [was], "{path}");
            assert_eq!(f.adds, [is], "{path}");
            // Older engines report the delete and the add alone.
            let f = section_facts(ENGINE_RENAMES - 1, path, old, &new);
            assert!(f.renames.is_empty() && f.deletes == [was], "{path}");
        }
    }

    #[test]
    fn a_rename_can_change_a_little_and_not_a_lot() {
        let old = "class C:\n    def old(self, a, b):\n        one = a + b\n        two = one * a\n        three = two - b\n        four = three * 2\n        return four\n";
        let close = old
            .replace("old", "new")
            .replace("return four", "return four + 1");
        let f = section_facts(ENGINE_RENAMES, "a.py", old, &close);
        assert_eq!(f.renames.len(), 1, "{f:?}");
        let far = "class C:\n    def new(self, a, b):\n        log(a)\n        send(b)\n        return 0\n";
        let f = section_facts(ENGINE_RENAMES, "a.py", old, far);
        assert!(f.renames.is_empty(), "{f:?}");
    }

    /// Among several, the same code wins, and each goes on as one.
    #[test]
    fn renames_pair_by_their_code() {
        let old = "def a():\n    return one()\n\n\ndef b():\n    return two()\n";
        let new = "def d():\n    return two()\n\n\ndef c():\n    return one()\n";
        let f = section_facts(ENGINE_RENAMES, "a.py", old, new);
        let pair = |a: &str, b: &str| [format!("a.py#{a}"), format!("a.py#{b}")];
        assert_eq!(f.renames, [pair("a", "c"), pair("b", "d")]);
    }

    /// A renamed type takes its members along, and an empty shell says
    /// nothing, in a list that holds it.
    #[test]
    fn a_type_is_renamed_with_its_members() {
        let old = "class Old:\n    def m(self):\n        return 1\n\n    def n(self):\n        return 2\n";
        let new = old.replace("Old", "New").replace("return 2", "return 3");
        let f = section_facts(ENGINE_RENAMES, "a.py", old, &new);
        assert_eq!(
            f.renames,
            [["a.py#Old".to_string(), "a.py#New".to_string()]]
        );
        let other = "class New:\n    def x(self):\n        return 1\n\n    def y(self):\n        return 2\n";
        let f = section_facts(ENGINE_RENAMES, "a.py", old, other);
        assert!(f.renames.is_empty(), "{f:?}");
        let f = section_facts(ENGINE_RENAMES, "a.ts", "class A {}\n", "class B {}\n");
        assert!(f.renames.is_empty(), "{f:?}");
    }

    /// Only text that a line merge can take: what reads a file has symbols
    /// or sections, and a binary file has no lines.
    #[test]
    fn the_files_no_parser_reads_are_listed() {
        let at = ENGINE_UNPARSED;
        let f = section_facts(at, "a.java", "class A {}\n", "class B {}\n");
        assert_eq!(f.unparsed_files, ["a.java"]);
        assert_eq!(f.edits, ["a.java#<file>"]);
        let f = section_facts(at, "Makefile", "a:\n", "b:\n");
        assert_eq!(f.unparsed_files, ["Makefile"]);
        for (path, old, new) in [
            ("a.rs", "fn a() {}\n", "fn a() { b(); }\n"),
            ("a.toml", "a = 1\n", "a = 2\n"),
            ("a.md", "# A\n\nx\n", "# A\n\ny\n"),
            ("a.json", "{\"a\": 1", "{\"a\": 2"),
        ] {
            assert!(
                section_facts(at, path, old, new).unparsed_files.is_empty(),
                "{path}"
            );
        }
        let f = section_facts(at - 1, "a.java", "class A {}\n", "class B {}\n");
        assert!(f.unparsed_files.is_empty());
        assert_eq!(f.edits, ["a.java#<file>"]);
    }

    /// Files added or deleted, a change of mode and bytes that are no text
    /// have nothing a line merge decides.
    #[test]
    fn a_file_with_no_lines_to_merge_is_not_listed() {
        let entry = |text: &[u8], mode| lonca_core::FileEntry {
            mode,
            blob: GitId::of_blob(text),
        };
        let one = |e: lonca_core::FileEntry| {
            let mut m = FileMap::new();
            m.insert("a.java".to_string(), e);
            m
        };
        let regular = lonca_core::FileMode::Regular;
        let (text, changed) = (b"a\n".as_slice(), b"b\n".as_slice());
        let (bytes, other) = ([0xff_u8, 0xfe].as_slice(), [0xfd_u8].as_slice());
        let read = |id: &GitId| -> Result<Vec<u8>> {
            let all = [text, changed, bytes, other];
            let found = all.iter().find(|t| GitId::of_blob(t) == *id);
            Ok(found.map(|t| t.to_vec()).unwrap_or_default())
        };
        let facts = |a: &FileMap, b: &FileMap| analyze(ENGINE_UNPARSED, a, b, &read).unwrap().facts;
        let (b, n) = (one(entry(text, regular)), one(entry(changed, regular)));
        assert_eq!(facts(&b, &n).unparsed_files, ["a.java"]);
        let empty = FileMap::new();
        assert!(facts(&empty, &n).unparsed_files.is_empty(), "added");
        assert!(facts(&b, &empty).unparsed_files.is_empty(), "deleted");
        let binary = (one(entry(bytes, regular)), one(entry(other, regular)));
        assert!(
            facts(&binary.0, &binary.1).unparsed_files.is_empty(),
            "bytes"
        );
        let run = one(entry(text, lonca_core::FileMode::Executable));
        assert!(facts(&b, &run).unparsed_files.is_empty(), "mode");
    }

    /// `edits_lines`, with the text that decides it. From engine 9 on; what
    /// engine 8 listed stays listed, for the entries it wrote.
    #[test]
    fn only_an_edit_of_lines_is_listed() {
        use lonca_core::FileMode::{Executable, Regular, Submodule, Symlink};
        let e = |mode, text: &str| lonca_core::FileEntry {
            mode,
            blob: GitId::of_blob(text.as_bytes()),
        };
        let lists = |(from, old): (FileMode, &str), (to, new): (FileMode, &str)| {
            let (b, n) = (e(from, old), e(to, new));
            let removed = line_counts(old, new).1;
            edits_lines(&b, &n, old, new, removed)
        };
        let (two, one_changed) = ("a\nb\n", "a\nc\n");
        assert!(lists((Regular, two), (Regular, one_changed)));
        assert!(lists((Executable, two), (Executable, one_changed)));
        assert!(!lists((Regular, two), (Executable, one_changed)));
        assert!(!lists((Regular, two), (Symlink, one_changed)));
        assert!(!lists((Symlink, two), (Symlink, one_changed)));
        assert!(!lists((Submodule, two), (Submodule, one_changed)));
        assert!(!lists((Regular, "a\0\nb\n"), (Regular, "a\0\nc\n")));
        assert!(!lists((Regular, two), (Regular, "a\0\nb\n")));
        assert!(!lists((Regular, "a\0\nb\n"), (Regular, two)));
        assert!(!lists((Regular, two), (Regular, "")));
        assert!(!lists((Regular, two), (Regular, "x\ny\n")));
        assert!(!lists((Regular, ""), (Regular, two)));
        assert!(lists((Regular, two), (Regular, "a\n")), "half stays");
        let four = "a\nb\nc\nd\n";
        assert!(lists((Regular, four), (Regular, "a\nb\n")));
        assert!(!lists((Regular, four), (Regular, "a\n")), "less than half");
        assert!(!lists((Regular, "a\n"), (Regular, "b\n")), "the one line");
    }

    #[test]
    fn what_a_name_is_written_as() {
        for (name, want) in [
            ("f", "f"),
            ("C.M", "M"),
            ("C.M(int)", "M"),
            ("C.x[setter]", "x"),
            ("C.M~2", "M"),
            ("C.[k]", "[k]"),
            ("C.~D", "~D"),
        ] {
            assert_eq!(written(name), want);
        }
    }

    /// Up to what is compared a rename is found, past it not: `many_new_names`
    /// has nine of each.
    #[test]
    fn eight_new_names_at_once_are_renames() {
        let list = |letter: char| {
            let defs = (0..8).map(|i| format!("def {letter}{i}():\n    return {i}\n\n\n"));
            defs.collect::<String>()
        };
        let f = section_facts(ENGINE_RENAMES, "a.py", &list('a'), &list('b'));
        assert_eq!(f.renames.len(), 8, "{f:?}");
    }

    /// A name with nothing written in it: a JavaScript `1.` is a method name.
    #[test]
    fn a_name_that_ends_in_a_dot_is_compared_and_ends() {
        let old = "class C {\n  1.() {\n    return 1;\n  }\n}\n";
        let new = "class C {\n  fresh() {\n    return 1;\n  }\n}\n";
        let f = section_facts(ENGINE_RENAMES, "a.js", old, new);
        assert_eq!(f.deletes.len(), 1, "{f:?}");
        assert_eq!(f.adds, ["a.js#C.fresh"]);
    }

    /// A Go method stands in the file's list, so one list says nothing about
    /// the owner.
    #[test]
    fn a_method_that_moved_to_another_owner_is_no_rename() {
        let text = |recv: &str, name: &str| {
            format!(
                "package p\n\nfunc {recv}{name}(a int) int {{\n\tx := a + 1\n\ty := x * 2\n\treturn y\n}}\n"
            )
        };
        for (old, new) in [
            (text("(t T) ", "Old"), text("(u U) ", "New")),
            (text("", "Helper"), text("(u U) ", "New")),
            (text("(t T) ", "Old"), text("", "Helper")),
        ] {
            let f = section_facts(ENGINE_RENAMES, "a.go", &old, &new);
            assert!(f.renames.is_empty(), "{f:?}");
            assert_eq!((f.deletes.len(), f.adds.len()), (1, 1), "{f:?}");
        }
        let f = section_facts(
            ENGINE_RENAMES,
            "a.go",
            &text("(t T) ", "Old"),
            &text("(t T) ", "New"),
        );
        assert_eq!(f.renames.len(), 1, "{f:?}");
    }

    /// A function does not turn into a type, and members of a `impl` block
    /// are no rename of the block.
    #[test]
    fn what_is_no_rename() {
        let f = section_facts(
            ENGINE_RENAMES,
            "a.py",
            "def a():\n    pass\n",
            "class a2:\n    pass\n",
        );
        assert!(f.renames.is_empty(), "{f:?}");
        let f = section_facts(
            ENGINE_RENAMES,
            "a.rs",
            "impl A {\n    fn m() {}\n}\n",
            "impl B {\n    fn m() {}\n}\n",
        );
        assert!(
            f.renames.iter().all(|[old, _]| !old.contains("impl:")),
            "{f:?}"
        );
    }

    /// New parameters of an overload are a new name too, for whoever had the
    /// old one, though the change stays an edit.
    #[test]
    fn a_change_of_key_is_recorded_as_a_rename() {
        let old = "class C {\n    void M(int a) { A(); }\n    void M(string s) { B(); }\n}\n";
        let new = old.replace("M(int a)", "M(long a)");
        let f = section_facts(ENGINE_RENAMES, "a.cs", old, &new);
        assert_eq!(f.edits, ["a.cs#C.M(int)"]);
        assert_eq!(
            f.renames,
            [["a.cs#C.M(int)".to_string(), "a.cs#C.M(long)".to_string()]]
        );
        let f = section_facts(ENGINE_KEYS, "a.cs", old, &new);
        assert!(f.renames.is_empty());
    }

    /// Past what is compared a rename is a delete and an add, as it was.
    #[test]
    fn many_new_names_at_once_are_no_renames() {
        let list = |letter: char| {
            let defs = (0..9).map(|i| format!("def {letter}{i}():\n    return {i}\n\n\n"));
            defs.collect::<String>()
        };
        let f = section_facts(ENGINE_RENAMES, "a.py", &list('a'), &list('b'));
        assert!(f.renames.is_empty());
        assert_eq!(f.deletes.len(), 9);
    }

    /// A deletion and an addition in different places are that, not a
    /// change of the first, which would report what stands between them.
    #[test]
    fn symbols_in_different_places_are_no_change_of_parameters() {
        let old = "class C {\n    void M(int a) { A(); }\n    void M(long a) { B(); }\n}\n";
        let new = "class C {\n    void M(long a) { B(); }\n    void M(short a) { X(); }\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.cs", old, new);
        assert_eq!(f.deletes, ["a.cs#C.M(int)"]);
        assert_eq!(f.adds, ["a.cs#C.M(short)"]);
        assert!(f.edits.is_empty(), "{:?}", f.edits);

        let old = "if A:\n    def f(a: int):\n        pass\n    def f(a: str):\n        pass\nelse:\n    def f(a: bool):\n        pass\n";
        let new = "if A:\n    def f(a: str):\n        pass\nelse:\n    def f(a: bool):\n        pass\n    def f(a: bytes):\n        pass\n";
        let f = section_facts(ENGINE_KEYS, "a.py", old, new);
        assert_eq!(f.deletes, ["a.py#f(int)"]);
        assert_eq!(f.adds, ["a.py#f(bytes)"]);
        assert!(f.edits.is_empty(), "{:?}", f.edits);
    }

    /// A group added above renumbers the groups of the file, not this one.
    #[test]
    fn a_block_added_above_leaves_a_change_of_parameters_an_edit() {
        let old = "if A:\n    def f(a: int):\n        pass\n    def f(a: str):\n        pass\n";
        let new = format!(
            "if B:\n    def g():\n        pass\n{}",
            old.replace("a: int", "a: bytes")
        );
        let f = section_facts(ENGINE_KEYS, "a.py", old, &new);
        assert_eq!(f.signature_changes, ["a.py#f(int)"]);
        assert!(f.edits.contains(&"a.py#f(int)".to_string()), "{f:?}");
        assert!(f.deletes.is_empty(), "{f:?}");
    }

    /// A symbol that stands elsewhere in the file did not lose its key, so
    /// it can not be the old name of one that gained one.
    #[test]
    fn a_symbol_that_moved_between_impls_is_not_paired() {
        let old = "impl S {\n    fn f(a: u8) { A(); }\n}\n";
        let new = format!("impl S {{\n    fn f(a: u16) {{ B(); }}\n}}\n{old}");
        let f = section_facts(ENGINE_KEYS, "a.rs", old, &new);
        assert!(f.signature_changes.is_empty(), "{f:?}");
    }

    #[test]
    fn the_closest_text_is_the_one_that_changed() {
        let old = "class C {\n    void M(int a) { Alpha(); Beta(); }\n    void M(string s) { Gamma(s, 1); Delta(s, 2); }\n}\n";
        let new = "class C {\n    void M(long s) { Gamma(s, 3); Delta(s, 2); }\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.cs", old, new);
        assert_eq!(f.edits, ["a.cs#C.M(string)"]);
        assert_eq!(f.deletes, ["a.cs#C.M(int)"]);
    }

    /// One symbol of a name has no key while it is alone, so the change of
    /// its parameters is what it always was.
    #[test]
    fn a_symbol_alone_with_its_name_keeps_it_through_a_change_of_parameters() {
        let f = section_facts(
            ENGINE_KEYS,
            "a.cs",
            "class C {\n    void M(int a) {}\n}\n",
            "class C {\n    void M(long a) {}\n}\n",
        );
        assert_eq!(f.edits, ["a.cs#C.M"]);
        assert_eq!(f.signature_changes, ["a.cs#C.M"]);
    }

    /// Only a second symbol of the name brings the key, and the edit of the
    /// first in the same change is reported on the first.
    #[test]
    fn an_overload_added_beside_an_edit_of_the_first() {
        let old = "class C {\n    void M(int a) { A(); }\n}\n";
        let new = "class C {\n    void M(string s) { B(); }\n    void M(int a) { C(); }\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.cs", old, new);
        assert_eq!(f.edits, ["a.cs#C.M(int)"]);
        assert_eq!(f.adds, ["a.cs#C.M(string)"]);
        assert!(f.deletes.is_empty(), "{f:?}");
    }

    #[test]
    fn a_test_that_gets_an_overload_is_not_a_deleted_test() {
        let old = "class T {\n    [Fact] void A(int x) {}\n}\n";
        let new = "class T {\n    void A(string s) {}\n    [Fact] void A(int x) {}\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.cs", old, new);
        assert_eq!(f.tests.deleted, 0);
        assert_eq!(f.tests.added, 0);
    }

    /// A `;` that stands behind a member is the member's, not the class's.
    #[test]
    fn a_member_with_its_semicolon_is_an_addition() {
        let old = "class C {\n  a: number;\n}\n";
        let new = "class C {\n  a: number;\n  b: string;\n}\n";
        let f = section_facts(ENGINE_KEYS, "a.ts", old, new);
        assert_eq!(f.adds, ["a.ts#C.b"]);
        assert!(f.edits.is_empty(), "{:?}", f.edits);
        let f = section_facts(ENGINE_KEYS - 1, "a.ts", old, new);
        assert_eq!(f.edits, ["a.ts#C.<def>"]);
    }

    /// Exact duplicates have nothing to tell them apart but their order.
    #[test]
    fn exact_duplicates_stay_numbered() {
        let old = "package p\nfunc init() {}\n";
        let new = "package p\nfunc init() {\n\tx()\n}\nfunc init() {}\n";
        let f = section_facts(ENGINE_KEYS, "a.go", old, new);
        assert_eq!(f.adds, ["a.go#init~2"]);
    }

    /// Each row: an edit is reported on the symbol that changed, where
    /// engine 4 reports it on a neighbour or on the whole file's code.
    #[test]
    fn engine_5_reports_an_edit_on_the_right_symbol() {
        let rows = [
            (
                "a.go",
                "package p\nconst (\n\tX = 1\n\tY = 2\n)\n",
                "Y = 2",
                "Y = 3",
                "a.go#Y",
                "a.go#X",
            ),
            (
                "a.go",
                "package p\ntype (\n\tA struct{}\n\tB struct{}\n)\n",
                "B struct{}",
                "B struct{ n int }",
                "a.go#B.<def>",
                "a.go#A.<def>",
            ),
            (
                "a.go",
                "package p\nvar (\n\ta = 1\n\tb = 2\n)\n",
                "b = 2",
                "b = 3",
                "a.go#b",
                "a.go#a",
            ),
            (
                "a.cs",
                "class C { int a, b; }\n",
                "b;",
                "b = 1;",
                "a.cs#C.b",
                "a.cs#C.a",
            ),
            (
                "a.ts",
                "class C {\n  @A()\n  m() {}\n}\n",
                "@A()",
                "@B()",
                "a.ts#C.m",
                "a.ts#C.<def>",
            ),
            (
                "a.js",
                "module.exports.run = function () {};\n",
                "{}",
                "{ x(); }",
                "a.js#run",
                "a.js#<module>",
            ),
            (
                "a.js",
                "exports.run = () => 1;\n",
                "1",
                "2",
                "a.js#run",
                "a.js#<module>",
            ),
            (
                "a.js",
                "module.exports = {\n  a() {},\n  b() {},\n};\n",
                "b() {}",
                "b() { x(); }",
                "a.js#b",
                "a.js#<module>",
            ),
            (
                "a.py",
                "if A:\n    def f():\n        return 1\n",
                "return 1",
                "return 2",
                "a.py#f",
                "a.py#<module>",
            ),
            (
                "a.py",
                "try:\n    def f():\n        return 1\nexcept E:\n    def f():\n        return 2\n",
                "return 2",
                "return 3",
                "a.py#f~2",
                "a.py#<module>",
            ),
            (
                "a.rs",
                "extern \"C\" {\n    fn f(a: u8);\n}\n",
                "a: u8",
                "a: u16",
                "a.rs#f",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "m!(1);\nm!(2);\n",
                "(2)",
                "(3)",
                "a.rs#m!~2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "// section\n\nfn f() {}\n",
                "section",
                "part",
                "a.rs#<module>",
                "a.rs#f",
            ),
            (
                "a.py",
                "# licence\n\nimport os\n",
                "licence",
                "notice",
                "a.py#<module>",
                "a.py#<imports>",
            ),
            (
                "a.cs",
                "partial class C { int a; }\npartial class C { int b; }\n",
                "int b",
                "long b",
                "a.cs#C.b",
                "a.cs#C~2.b",
            ),
        ];
        for (path, old, from, to, now, before) in rows {
            let new = old.replace(from, to);
            let edits = |engine| section_facts(engine, path, old, &new).edits;
            assert_eq!(edits(5), [now], "{old}");
            assert_eq!(edits(4), [before], "{old}");
        }
    }

    /// An addition or a removal in a group is of one name, and the group's
    /// own lines are code.
    #[test]
    fn a_group_changes_by_its_members() {
        let old = "package p\nconst (\n\tX = 1\n)\n";
        let f = section_facts(5, "a.go", old, &old.replace("X = 1\n", "X = 1\n\tY = 2\n"));
        assert_eq!(f.adds, ["a.go#Y"]);
        assert!(f.edits.is_empty(), "{f:?}");
        let f = section_facts(5, "a.go", &old.replace("X = 1\n", "X = 1\n\tY = 2\n"), old);
        assert_eq!(f.deletes, ["a.go#Y"]);
        let f = section_facts(5, "a.go", old, &old.replace("const", "var"));
        assert_eq!(f.edits, ["a.go#<module>"]);

        // Out of its group, a spec is still found among the code around it.
        let old = "package p\nconst (\n\tA = 1\n\tB = 2\n)\nconst (\n\tC = 3\n)\n";
        let new = "package p\nconst (\n\tA = 1\n)\nconst (\n\tB = 2\n\tC = 3\n)\n";
        assert_eq!(section_facts(5, "a.go", old, new).edits, ["a.go#<module>"]);

        // A block holding one member reads as one holding two.
        let old = "if A:\n    def m():\n        return 1\n";
        let new = format!("{old}\n    def n():\n        return 2\n");
        let f = section_facts(5, "a.py", old, &new);
        assert_eq!((f.adds, f.edits), (vec!["a.py#n".to_string()], vec![]));
        let f = section_facts(5, "a.py", &new, old);
        assert_eq!((f.deletes, f.edits), (vec!["a.py#n".to_string()], vec![]));
        let old = "class A:\n    def m(self):\n        return 1\n";
        let new = format!("{old}\n    def n(self):\n        return 2\n");
        let f = section_facts(5, "a.py", old, &new);
        assert_eq!((f.adds, f.edits), (vec!["a.py#A.n".to_string()], vec![]));
        let f = section_facts(4, "a.py", old, &new);
        assert_eq!(f.edits, ["a.py#A.<def>"]);

        // In a list with separators, the separators go with the member.
        let old = "class C { int a, b; }\n";
        let f = section_facts(5, "a.cs", old, "class C { int a, b, c; }\n");
        assert_eq!((f.adds, f.edits), (vec!["a.cs#C.c".to_string()], vec![]));
        let old = "module.exports = {\n  a() {},\n  b() {},\n};\n";
        let f = section_facts(5, "a.js", old, "module.exports = {\n  b() {},\n};\n");
        assert_eq!((f.deletes, f.edits), (vec!["a.js#a".to_string()], vec![]));

        // A list changes shape: the type's own text says so.
        let old = "class C { int a, b; }\n";
        let f = section_facts(5, "a.cs", old, "class C { int a; }\n");
        assert_eq!(f.deletes, ["a.cs#C.b"]);
        assert!(f.edits.contains(&"a.cs#C.<def>".to_string()), "{f:?}");
    }

    #[test]
    fn a_trailing_comment_is_part_of_its_symbol_but_its_spacing_is_not() {
        let old = "package p\n\nconst (\n\tA = 1  // a\n\tB = 20 // b\n)\n";
        let new = "package p\n\nconst (\n\tA = 1   // a\n\tB = 20  // b\n\tC = 300 // c\n)\n";
        let f = section_facts(5, "a.go", old, new);
        assert_eq!((f.adds, f.edits), (vec!["a.go#C".to_string()], vec![]));
        let f = section_facts(5, "a.go", old, &old.replace("// a", "// first"));
        assert_eq!(f.edits, ["a.go#A"]);
    }

    /// A header of several lines ends at the blank line under it.
    #[test]
    fn a_comment_of_several_lines_stands_apart_as_one() {
        let rows = [
            (
                "a.rs",
                "//! one\n//! two\n\nfn f() {}\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "//! one\n//! two\n\nuse a::b;\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/// one\n/// two\n\nfn f() {}\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/// one\n// two\n\nfn f() {}\n",
                "two",
                "2",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/* a */ /* b */\n\nfn f() {}\n",
                "b",
                "c",
                "a.rs#<module>",
            ),
            (
                "a.rs",
                "/// one\n/// two\nfn f() {}\n",
                "two",
                "2",
                "a.rs#f",
            ),
            (
                "a.cs",
                "class C\n{\n    #region R\n    /// one\n    /// two\n    void M() { }\n    #endregion\n}\n",
                "two",
                "2",
                "a.cs#C.M",
            ),
            (
                "a.cs",
                "class C\n{\n    #region R\n    // about\n    int a;\n    #endregion\n}\n",
                "about",
                "on",
                "a.cs#C.a",
            ),
        ];
        for (path, old, from, to, want) in rows {
            let f = section_facts(5, path, old, &old.replace(from, to));
            assert_eq!(f.edits, [want], "{old}");
        }
    }

    /// A file that goes takes its tests with it.
    #[test]
    fn a_deleted_file_counts_its_tests() {
        let text = "#[test]\nfn a() {}\n\n#[test]\nfn b() {}\n";
        let entry = lonca_core::FileEntry {
            mode: lonca_core::FileMode::Regular,
            blob: GitId::of_blob(text.as_bytes()),
        };
        let old = FileMap::from([("a.rs".to_string(), entry)]);
        let read = |_: &GitId| Ok(text.as_bytes().to_vec());
        let f = analyze(5, &old, &FileMap::new(), &read).unwrap().facts;
        assert_eq!(f.tests.deleted, 2);
        assert_eq!(f.deleted_files, ["a.rs"]);
    }

    /// A part of a partial type stands in for the type, as an `impl` does.
    #[test]
    fn a_partial_part_taken_out_is_an_edit_of_its_type() {
        let old = "partial class C { int a; }\npartial class C { int b; }\n";
        let f = section_facts(5, "a.cs", old, "partial class C { int a; }\n");
        assert_eq!(f.edits, ["a.cs#C"]);
        assert_eq!(f.deletes, ["a.cs#C.b"]);
    }

    /// Code that changes places among symbols is a change of that code.
    #[test]
    fn code_that_changed_places_is_an_edit_from_engine_4() {
        let old = "a = 1\n\ndef f():\n    return 1\n\nprint(a)\n";
        let new = "a = 1\n\nprint(a)\n\ndef f():\n    return 1\n";
        assert_eq!(section_facts(4, "a.py", old, new).edits, ["a.py#<module>"]);
        assert_eq!(
            section_facts(3, "a.py", old, new).edits,
            Vec::<String>::new()
        );

        let old = "class A:\n    x = g()\n\n    def m(self):\n        return 1\n";
        let new = "class A:\n    def m(self):\n        return 1\n\n    x = g()\n";
        assert_eq!(section_facts(4, "a.py", old, new).edits, ["a.py#A.<def>"]);
        assert_eq!(
            section_facts(3, "a.py", old, new).edits,
            Vec::<String>::new()
        );

        // A new symbol between two statements moves neither.
        let old = "x = 1\ny = 2\n";
        let new = "x = 1\ndef f(): pass\ny = 2\n";
        let f = section_facts(4, "a.py", old, new);
        assert_eq!(f.edits, Vec::<String>::new());
        assert_eq!(f.adds, ["a.py#f"]);
    }

    /// A move goes to the line merge, which sees the members of the block.
    #[test]
    fn an_impl_that_moves_is_its_type() {
        let old = "impl S {\n    fn a() {}\n}\n\nfn f() {}\n";
        let new = "fn f() {}\n\nimpl S {\n    fn a() {}\n}\n";
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S", "a.rs#f"]);
        let f = section_facts(2, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#f", "a.rs#impl:S"]);
    }

    #[test]
    fn an_impl_taken_out_is_its_type_and_its_members() {
        let old = "struct S;\n\nimpl S {\n    fn a() {}\n}\n\nimpl R for S {\n    fn b() {}\n}\n";
        let new = "struct S;\n\nimpl R for S {\n    fn b() {}\n}\n";
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S"]);
        assert_eq!(f.deletes, ["a.rs#S.a"]);
        let f = section_facts(2, "a.rs", old, new);
        assert_eq!(f.edits, Vec::<String>::new());
        assert_eq!(f.deletes, ["a.rs#impl:S"]);

        let new = "struct S;\n\nimpl S {\n    fn a() {}\n}\n";
        let f = section_facts(3, "a.rs", old, new);
        assert_eq!(f.edits, ["a.rs#S"]);
        assert_eq!(f.deletes, ["a.rs#S.R.b"]);
        // A class taken out is a delete of the class, as it always was.
        let f = section_facts(3, "a.py", "class A:\n    x = 1\n\nb = 2\n", "b = 2\n");
        assert_eq!(f.deletes, ["a.py#A"]);
        assert_eq!(f.edits, Vec::<String>::new());
    }

    #[test]
    fn engine_1_reads_sections_and_engine_0_the_whole_file() {
        let old = "# A\nx\n# B\ny\n";
        let new = "# A\nX\n# B\ny\n# C\nz\n";
        let f = section_facts(1, "n.md", old, new);
        assert_eq!(f.edits, ["n.md#A"]);
        assert_eq!(f.adds, ["n.md#C"]);
        let f = section_facts(1, "n.md", new, old);
        assert_eq!(f.deletes, ["n.md#C"]);
        let f = section_facts(0, "n.md", old, new);
        assert_eq!(f.edits, ["n.md#<file>"]);
        assert_eq!(f.adds, Vec::<String>::new());
    }

    #[test]
    fn only_markdown_grows_by_appending() {
        let f = section_facts(1, "n.md", "# A\nx\n# B\ny\n", "# A\nx\nmore\n# B\ny\n");
        assert_eq!(f.adds, ["n.md#A.<append>"]);
        assert_eq!(f.edits, Vec::<String>::new());
        let f = section_facts(1, "c.toml", "a = 1\nb = 2\n", "a = 12\nb = 2\n");
        assert_eq!(f.edits, ["c.toml#a"]);
        assert_eq!(f.adds, Vec::<String>::new());
    }

    /// Fail closed: anything that can not be read by sections is one edit.
    #[test]
    fn a_file_without_sections_is_edited_whole() {
        let edit = |path, old, new| section_facts(1, path, old, new).edits;
        assert_eq!(edit("n.md", "plain\n", "other\n"), ["n.md#<file>"]);
        assert_eq!(
            edit("c.toml", "a = 1\nb = 2\n", "a = \n"),
            ["c.toml#<file>"]
        );
        assert_eq!(
            edit("c.toml", "a = \n", "a = 1\nb = 2\n"),
            ["c.toml#<file>"]
        );
        assert_eq!(edit("n.txt", "a\n", "b\n"), ["n.txt#<file>"]);
        // Only what no section shows: the space between JSON members.
        let (old, new) = ("{\"a\": 1, \"b\": 2}\n", "{\"a\": 1,\n \"b\": 2}\n");
        assert_eq!(edit("c.json", old, new), ["c.json#<file>"]);
    }
    use lonca_core::{FileEntry, FileMode};
    use std::collections::HashMap;

    struct Mem(HashMap<String, Vec<u8>>);

    impl Mem {
        fn put(&mut self, text: &str) -> GitId {
            let id = GitId(lonca_core::canonical::sha256_hex(text.as_bytes())[..40].to_string());
            self.0.insert(id.0.clone(), text.as_bytes().to_vec());
            id
        }
    }

    fn tree(mem: &mut Mem, files: &[(&str, &str)]) -> FileMap {
        files
            .iter()
            .map(|(p, t)| {
                (
                    p.to_string(),
                    FileEntry {
                        mode: FileMode::Regular,
                        blob: mem.put(t),
                    },
                )
            })
            .collect()
    }

    fn run(base: &[(&str, &str)], new: &[(&str, &str)]) -> Analysis {
        let mut mem = Mem(HashMap::new());
        let b = tree(&mut mem, base);
        let n = tree(&mut mem, new);
        analyze(0, &b, &n, &|id| Ok(mem.0[&id.0].clone())).unwrap()
    }

    fn run_now(base: &[(&str, &str)], new: &[(&str, &str)]) -> Analysis {
        let mut mem = Mem(HashMap::new());
        let b = tree(&mut mem, base);
        let n = tree(&mut mem, new);
        let read = |id: &GitId| Ok(mem.0[&id.0].clone());
        analyze(ENGINE_SIGNATURES, &b, &n, &read).unwrap()
    }

    const BASE: &str = "use std::io;\n\npub struct Client;\n\nimpl Client {\n    pub fn charge(&self, a: u64) -> u64 {\n        a\n    }\n\n    pub fn refund(&self) {}\n}\n\n#[test]\nfn charges() {}\n";

    #[test]
    fn body_edit_is_one_symbol() {
        let new = BASE.replace("        a\n", "        a + 1\n");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]);
        assert_eq!(a.facts.edits, vec!["src/a.rs#Client.charge"]);
        assert!(a.facts.signature_changes.is_empty());
        assert_eq!(a.facts.modified_files, vec!["src/a.rs"]);
        assert_eq!((a.facts.lines_added, a.facts.lines_removed), (1, 1));
    }

    /// What a change of one declaration reports as a change of signature, in
    /// each language, for what had none before engine 11.
    #[test]
    fn every_declaration_has_a_signature() {
        for (path, old, new, changed) in [
            (
                "a.rs",
                "trait R { fn m(&self, x: u8); }\n",
                "trait R { fn m(&self, x: u16); }\n",
                "a.rs#R.m",
            ),
            (
                "a.rs",
                "trait R {}\n",
                "trait R: Clone {}\n",
                "a.rs#R.<def>",
            ),
            (
                "a.rs",
                "pub struct S { pub a: u8 }\n",
                "pub struct S { pub a: u16 }\n",
                "a.rs#S.<def>",
            ),
            (
                "a.rs",
                "pub struct S { a: u8 }\n",
                "pub struct S { pub a: u8 }\n",
                "a.rs#S.<def>",
            ),
            (
                "a.rs",
                "enum E { A }\n",
                "enum E { A, B }\n",
                "a.rs#E.<def>",
            ),
            ("a.rs", "type T = u8;\n", "type T = u16;\n", "a.rs#T.<def>"),
            (
                "a.rs",
                "const C: u8 = 1;\n",
                "const C: u16 = 1;\n",
                "a.rs#C",
            ),
            (
                "a.ts",
                "function f(a: string): void;\n",
                "function f(a: number): void;\n",
                "a.ts#f",
            ),
            (
                "a.ts",
                "export const h = async (a: number) => { return a; };\n",
                "export const h = async (a: string) => { return a; };\n",
                "a.ts#h",
            ),
            (
                "a.ts",
                "interface I { a: string }\n",
                "interface I { a: number }\n",
                "a.ts#I.<def>",
            ),
            (
                "a.ts",
                "type T = string;\n",
                "type T = number;\n",
                "a.ts#T.<def>",
            ),
            (
                "a.ts",
                "class C { x: number = 1; }\n",
                "class C { x: string = 1; }\n",
                "a.ts#C.x",
            ),
            (
                "a.ts",
                "class C {}\n",
                "class C extends B {}\n",
                "a.ts#C.<def>",
            ),
            (
                "a.go",
                "package p\ntype S struct { A int }\n",
                "package p\ntype S struct { A string }\n",
                "a.go#S.<def>",
            ),
            (
                "a.go",
                "package p\ntype I interface { M() }\n",
                "package p\ntype I interface { M(a int) }\n",
                "a.go#I.<def>",
            ),
            (
                "a.cs",
                "class C { public int a; }\n",
                "class C { public long a; }\n",
                "a.cs#C.a",
            ),
            (
                "a.cs",
                "class C { int a, b; }\n",
                "class C { long a, b; }\n",
                "a.cs#C.<def>",
            ),
            (
                "a.cs",
                "class C { public event E Ev; }\n",
                "class C { public event F Ev; }\n",
                "a.cs#C.Ev",
            ),
            (
                "a.cs",
                "class C { public delegate void D(int a); }\n",
                "class C { public delegate void D(long a); }\n",
                "a.cs#C.D",
            ),
            (
                "a.cs",
                "class C { public int P { get; set; } }\n",
                "class C { public long P { get; set; } }\n",
                "a.cs#C.P",
            ),
            (
                "a.java",
                "interface I { void m(int x); }\n",
                "interface I { void m(long x); }\n",
                "a.java#I.m",
            ),
            (
                "a.java",
                "class C { int a = 1; }\n",
                "class C { long a = 1; }\n",
                "a.java#C.a",
            ),
            (
                "a.kt",
                "interface I {\n fun m(x: Int)\n}\n",
                "interface I {\n fun m(x: Long)\n}\n",
                "a.kt#I.m",
            ),
            ("a.c", "int f(int a);\n", "int f(long a);\n", "a.c#f"),
            (
                "a.cpp",
                "class C { int a; };\n",
                "class C { long a; };\n",
                "a.cpp#C.a",
            ),
            (
                "a.php",
                "<?php\nclass C { public int $a = 1; }\n",
                "<?php\nclass C { public string $a = 1; }\n",
                "a.php#C.$a",
            ),
            (
                "a.swift",
                "protocol P { func m(x: Int) }\n",
                "protocol P { func m(x: Long) }\n",
                "a.swift#P.m",
            ),
            (
                "a.py",
                "class C(B):\n    pass\n",
                "class C(D):\n    pass\n",
                "a.py#C.<def>",
            ),
            ("a.rb", "class C < B\nend\n", "class C < D\nend\n", "a.rb#C"),
        ] {
            let f = section_facts(ENGINE_SIGNATURES, path, old, new);
            assert!(
                f.signature_changes.iter().any(|s| s == changed),
                "{old}: {f:?}"
            );
        }
    }

    /// What says nothing about how a declaration is used is no signature
    /// change.
    #[test]
    fn a_value_a_body_or_a_comment_is_no_signature() {
        for (path, old, new) in [
            ("a.rs", "const C: u8 = 1;\n", "const C: u8 = 2;\n"),
            ("a.rs", "static C: u8 = 1;\n", "static C: u8 = 2;\n"),
            ("a.rs", "fn f() { a(); }\n", "fn f() { b(); }\n"),
            (
                "a.rs",
                "struct S { /* one */ a: u8 }\n",
                "struct S { /* two */ a: u8 }\n",
            ),
            (
                "a.rs",
                "fn f(a: u8 /* one */) {}\n",
                "fn f(a: u8 /* two */) {}\n",
            ),
            ("a.rs", "trait R { /* one */ }\n", "trait R { /* two */ }\n"),
            (
                "a.ts",
                "const h = (a: number) => { return 1; };\n",
                "const h = (a: number) => { return 2; };\n",
            ),
            ("a.ts", "const o = { a: 1 };\n", "const o = { a: 2 };\n"),
            (
                "a.js",
                "const h = function (a) { return 1; };\n",
                "const h = function (a) { return 2; };\n",
            ),
            (
                "a.go",
                "package p\nconst C = 1\n",
                "package p\nconst C = 2\n",
            ),
            (
                "a.go",
                "package p\nvar V int = 1\n",
                "package p\nvar V int = 2\n",
            ),
            (
                "a.java",
                "class C { int a = 1; }\n",
                "class C { int a = 2; }\n",
            ),
            (
                "a.php",
                "<?php\nclass C { public int $a = 1; }\n",
                "<?php\nclass C { public int $a = 2; }\n",
            ),
            (
                "a.swift",
                "class C { var a: Int = 1 }\n",
                "class C { var a: Int = 2 }\n",
            ),
            ("a.rb", "class C\n  X = 1\nend\n", "class C\n  X = 2\nend\n"),
        ] {
            let f = section_facts(ENGINE_SIGNATURES, path, old, new);
            assert!(f.signature_changes.is_empty(), "{old}: {f:?}");
            assert!(!f.edits.is_empty(), "{old}: {f:?}");
        }
    }

    const CALLER: &str = "fn g() { f(1); }\nfn h() {}\n";

    #[test]
    fn what_mentions_a_changed_signature_is_affected() {
        let [old, new] = ["fn f(a: u8) {}\n", "fn f(a: u16) {}\n"];
        let a = run_now(
            &[("a.rs", old), ("b.rs", CALLER)],
            &[("a.rs", new), ("b.rs", CALLER)],
        );
        assert_eq!(a.facts.affected, ["b.rs#g"]);
        assert_eq!(a.facts.affected_more, 0);
    }

    #[test]
    fn a_change_of_the_body_affects_nobody() {
        let [old, new] = ["fn f() { a(); }\n", "fn f() { b(); }\n"];
        let a = run_now(
            &[("a.rs", old), ("b.rs", CALLER)],
            &[("a.rs", new), ("b.rs", CALLER)],
        );
        assert!(a.facts.affected.is_empty());
    }

    #[test]
    fn what_mentions_a_deleted_or_renamed_symbol_is_affected() {
        let old = "fn f() {}\nfn k() {}\n";
        let a = run_now(
            &[("a.rs", old), ("b.rs", CALLER)],
            &[("a.rs", "fn k() {}\n"), ("b.rs", CALLER)],
        );
        assert_eq!(a.facts.deletes, ["a.rs#f"]);
        assert_eq!(a.facts.affected, ["b.rs#g"]);

        let old = "fn f() { work(1, 2, 3); }\n";
        let new = "fn e() { work(1, 2, 3); }\n";
        let a = run_now(
            &[("a.rs", old), ("b.rs", CALLER)],
            &[("a.rs", new), ("b.rs", CALLER)],
        );
        assert_eq!(
            a.facts.renames,
            [["a.rs#f".to_string(), "a.rs#e".to_string()]]
        );
        assert_eq!(a.facts.affected, ["b.rs#g"]);
    }

    /// With keys, a change of parameters is a rename and an edit, no delete.
    #[test]
    fn a_rename_alone_counts() {
        let f = Facts {
            renames: vec![["a.py#f(int)".into(), "a.py#f(str)".into()]],
            ..Facts::default()
        };
        assert_eq!(
            taken_away(ENGINE_SIGNATURES, &f, &[])
                .into_iter()
                .collect::<Vec<_>>(),
            ["f"]
        );
    }

    /// The new parameters name it otherwise on one side only.
    #[test]
    fn a_symbol_under_another_key_is_still_the_changes_own() {
        let old = "class C { void M(int a) { } }\n";
        let new = "class C { void M(long a) { } }\n";
        let a = run_now(&[("a.cs", old)], &[("a.cs", new)]);
        assert!(!a.facts.signature_changes.is_empty(), "{:?}", a.facts);
        assert!(a.facts.affected.is_empty(), "{:?}", a.facts);
    }

    #[test]
    fn what_a_deleted_type_held_is_gone_with_it() {
        let old = "class T:\n    def f(self):\n        pass\n    def g(self):\n        self.f()\n\nclass U:\n    pass\n";
        let new = "class U:\n    pass\n";
        let a = run_now(&[("a.py", old)], &[("a.py", new)]);
        assert_eq!(a.facts.deletes, ["a.py#T"]);
        assert!(a.facts.affected.is_empty(), "{:?}", a.facts);
    }

    #[test]
    fn a_container_of_a_name_holds_it_up_to_the_path() {
        let list: BTreeSet<String> = ["a.rs#T".to_string()].into();
        assert!(within("a.rs#T", &list));
        assert!(within("a.rs#T.m", &list));
        assert!(within("a.rs#T.m.n", &list));
        assert!(!within("a.rs#U.m", &list));
        assert!(!within("a.rs#Tx", &list));
        let dotted: BTreeSet<String> = ["x.y".to_string()].into();
        assert!(!within("x.y.rs#f.g", &dotted), "a path is not a container");
    }

    /// Reported only at the level of a tree a parser can follow: this must
    /// not take the daemon down.
    #[test]
    fn a_deep_declaration_does_not_end_the_process() {
        let depth = 20_000;
        let src = format!("type T = {}u8{};\n", "(".repeat(depth), ")".repeat(depth));
        let run = move || section_facts(ENGINE_SIGNATURES, "a.rs", &src, "type T = u16;\n");
        let on_a_daemon_stack = std::thread::Builder::new().stack_size(2 << 20).spawn(run);
        on_a_daemon_stack.unwrap().join().unwrap();
    }

    /// Every item says what stands in front of the first, and no more.
    #[test]
    fn a_long_list_costs_each_item_the_same() {
        let items: Vec<String> = (0..2000).map(|i| format!("a{i}")).collect();
        let src = format!("class C {{ int {}; }}\n", items.join(", "));
        let lang = Lang::detect("a.cs").unwrap();
        let p = parse_at(ENGINE_SIGNATURES, lang, &src);
        let last = p.syms[0].children.last().unwrap();
        assert_eq!(last.signature.as_deref(), Some("int a1999"));
    }

    #[test]
    fn a_file_under_a_path_with_a_hash_is_deleted_like_another() {
        let old = "fn f() {}\nfn g() { f(); }\n";
        let a = run_now(&[("C#/a.rs", old)], &[]);
        assert!(a.facts.affected.is_empty(), "{:?}", a.facts);
    }

    #[test]
    fn a_comment_in_a_list_is_no_signature() {
        let old = "class C { int /* one */ a, b; }\n";
        let new = "class C { int /* two */ a, b; }\n";
        let f = section_facts(ENGINE_SIGNATURES, "a.cs", old, new);
        assert!(f.signature_changes.is_empty(), "{f:?}");
    }

    #[test]
    fn a_constructor_reaches_those_who_call_the_type() {
        for (path, old, new, user, caller) in [
            (
                "a.py",
                "class C:\n    def __init__(self, a):\n        pass\n",
                "class C:\n    def __init__(self, a, b):\n        pass\n",
                "b.py",
                "def g():\n    C(1)\n",
            ),
            (
                "a.ts",
                "class C { constructor(a: number) {} }\n",
                "class C { constructor(a: string) {} }\n",
                "b.ts",
                "function g() { new C(1); }\n",
            ),
            (
                "a.rb",
                "class C\n  def initialize(a)\n    x\n  end\nend\n",
                "class C\n  def initialize(a, b)\n    x\n  end\nend\n",
                "b.rb",
                "def g\n  C.new(1)\nend\n",
            ),
            (
                "a.php",
                "<?php\nclass C { public function __construct(int $a) {} }\n",
                "<?php\nclass C { public function __construct(string $a) {} }\n",
                "b.php",
                "<?php\nfunction g() { new C(1); }\n",
            ),
            (
                "a.swift",
                "class C { init(a: Int) { } }\n",
                "class C { init(a: Long) { } }\n",
                "b.swift",
                "func g() { C(a: 1) }\n",
            ),
        ] {
            let a = run_now(
                &[(path, old), (user, caller)],
                &[(path, new), (user, caller)],
            );
            let caller = format!("{user}#g");
            assert!(a.facts.affected.contains(&caller), "{old}: {:?}", a.facts);
        }
    }

    #[test]
    fn a_marked_name_reaches_those_who_use_it_bare() {
        let old = "<?php\nclass C { public int $a = 1; }\n";
        let new = "<?php\nclass C { public string $a = 1; }\n";
        let user = "<?php\nfunction g($c) { return $c->a; }\n";
        let a = run_now(
            &[("a.php", old), ("b.php", user)],
            &[("a.php", new), ("b.php", user)],
        );
        assert_eq!(a.facts.affected, ["b.php#g"]);
    }

    #[test]
    fn what_a_deleted_file_held_is_gone() {
        let old = "struct T;\nimpl T {\n    fn f() {}\n}\n";
        let caller = "fn g() { T::f(); }\n";
        let a = run_now(&[("a.rs", old), ("b.rs", caller)], &[("b.rs", caller)]);
        assert_eq!(a.facts.affected, ["b.rs#g"]);
        let old = "class C:\n    def f(self):\n        pass\n";
        let caller = "def g(c):\n    c.f()\n";
        let a = run_now(&[("a.py", old), ("b.py", caller)], &[("b.py", caller)]);
        assert_eq!(a.facts.affected, ["b.py#g"]);
    }

    #[test]
    fn what_the_change_touches_itself_is_not_affected() {
        let [old, new] = ["fn f(a: u8) {}\n", "fn f(a: u16) {}\n"];
        let edited = CALLER.replace("f(1)", "f(2)");
        let a = run_now(
            &[("a.rs", old), ("b.rs", CALLER)],
            &[("a.rs", new), ("b.rs", &edited)],
        );
        assert!(a.facts.affected.is_empty(), "{:?}", a.facts);
        let a = run_now(&[("a.rs", old), ("b.rs", CALLER)], &[("a.rs", new)]);
        assert!(a.facts.affected.is_empty(), "{:?}", a.facts);
        let gone = "fn f(a: u8) {}\nfn g() { f(1); }\n";
        let a = run_now(&[("a.rs", gone)], &[("a.rs", "fn f(a: u16) {}\n")]);
        assert!(a.facts.affected.is_empty(), "{:?}", a.facts);
    }

    #[test]
    fn a_list_past_the_limit_says_how_much_it_left_out() {
        let callers = |n: usize| {
            (0..n)
                .map(|i| format!("fn g{i:04}() {{ f(1); }}\n"))
                .collect::<String>()
        };
        let [old, new] = ["fn f(a: u8) {}\n", "fn f(a: u16) {}\n"];
        for (n, kept, more) in [
            (MAX_AFFECTED, MAX_AFFECTED, 0),
            (MAX_AFFECTED + 3, MAX_AFFECTED, 3),
        ] {
            let b = callers(n);
            let a = run_now(
                &[("a.rs", old), ("b.rs", &b)],
                &[("a.rs", new), ("b.rs", &b)],
            );
            assert_eq!(a.facts.affected.len(), kept);
            assert_eq!(a.facts.affected_more, more);
            assert_eq!(a.facts.affected[0], "b.rs#g0000");
        }
    }

    #[test]
    fn engines_before_11_list_nobody() {
        let [old, new] = [
            "fn f(a: u8) {}\nfn g() { f(1); }\n",
            "fn f(a: u16) {}\nfn g() { f(1); }\n",
        ];
        assert_eq!(
            section_facts(ENGINE_SIGNATURES, "a.rs", old, new).affected,
            ["a.rs#g"]
        );
        assert!(
            section_facts(ENGINE_SIGNATURES - 1, "a.rs", old, new)
                .affected
                .is_empty()
        );
    }

    #[test]
    fn signature_add_delete_and_imports() {
        let new = BASE
            .replace("charge(&self, a: u64)", "charge(&self, a: u64, b: u64)")
            .replace(
                "    pub fn refund(&self) {}\n",
                "    pub fn void(&self) {}\n",
            )
            .replace("use std::io;\n", "use std::io;\nuse std::fmt;\n");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]);
        assert_eq!(a.facts.edits, vec!["src/a.rs#Client.charge"]);
        assert_eq!(a.facts.signature_changes, vec!["src/a.rs#Client.charge"]);
        assert_eq!(a.facts.adds, vec!["src/a.rs#Client.void"]);
        assert_eq!(a.facts.deletes, vec!["src/a.rs#Client.refund"]);
        assert_eq!(a.facts.import_only_files, vec!["src/a.rs"]);
    }

    #[test]
    fn module_level_and_import_removal() {
        let new = BASE.replace("use std::io;\n", "").replace(
            "pub struct Client;",
            "pub struct Client;\nstatic X: u8 = 1;",
        );
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]);
        assert!(a.facts.edits.contains(&"src/a.rs#<imports>".to_string()));
        assert!(a.facts.adds.contains(&"src/a.rs#X".to_string()));
    }

    #[test]
    fn tests_deleted_and_skipped() {
        let skipped = BASE.replace("#[test]\nfn charges", "#[test]\n#[ignore]\nfn charges");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &skipped)]);
        assert_eq!(a.facts.tests.skipped, 1);
        assert_eq!(a.facts.tests.modified, 1);
        let removed = BASE.replace("#[test]\nfn charges() {}\n", "");
        let a = run(&[("src/a.rs", BASE)], &[("src/a.rs", &removed)]);
        assert_eq!(a.facts.tests.deleted, 1);
        assert_eq!(a.facts.deletes, vec!["src/a.rs#charges"]);
    }

    #[test]
    fn files_added_deleted_unsupported_and_broken() {
        let a = run(
            &[("README.md", "hello\n"), ("old.rs", "fn x() {}\n")],
            &[("README.md", "hello world\n"), ("new.rs", "fn y( {\n")],
        );
        assert_eq!(a.facts.edits, vec!["README.md#<file>"]);
        assert_eq!(a.facts.added_files, vec!["new.rs"]);
        assert_eq!(a.facts.deleted_files, vec!["old.rs"]);
        assert_eq!(a.syntax_errors, vec!["new.rs"]);
    }

    fn facts_at(engine: u32, old: &str, new: &str, path: &str) -> Facts {
        let mut mem = Mem(HashMap::new());
        let b = tree(&mut mem, &[(path, old)]);
        let n = tree(&mut mem, &[(path, new)]);
        analyze(engine, &b, &n, &|id| Ok(mem.0[&id.0].clone()))
            .unwrap()
            .facts
    }

    #[test]
    fn from_engine_2_a_block_or_string_change_outside_symbols_is_an_edit() {
        let old = "X = \"a  b\"\nif X:\n    a = 1\n    b = 2\n";
        for new in [
            old.replace("a  b", "a b"),
            old.replace("    b = 2", "b = 2"),
        ] {
            assert_eq!(
                facts_at(2, old, &new, "m.py").edits,
                ["m.py#<module>"],
                "{new}"
            );
            assert!(facts_at(1, old, &new, "m.py").edits.is_empty(), "{new}");
        }
        let spaced = old.replace("a = 1", "a  =  1");
        assert!(
            facts_at(2, old, &spaced, "m.py").edits.is_empty(),
            "layout is no edit"
        );
    }

    #[test]
    fn from_engine_2_a_block_change_in_a_class_is_an_edit_of_the_class() {
        let old = "class C:\n    x = \"a  b\"\n\n    def m(self):\n        pass\n";
        let new = old.replace("a  b", "a b");
        assert_eq!(facts_at(2, old, &new, "m.py").edits, ["m.py#C"]);
        assert!(facts_at(1, old, &new, "m.py").edits.is_empty());
    }

    #[test]
    fn from_engine_2_moved_symbols_and_imports_are_edits() {
        let old = "import a\nimport b\n\ndef f():\n    pass\n\ndef g():\n    pass\n";
        let new = "import a\nimport b\n\ndef g():\n    pass\n\ndef f():\n    pass\n";
        assert_eq!(facts_at(2, old, new, "m.py").edits, ["m.py#f", "m.py#g"]);
        assert!(facts_at(1, old, new, "m.py").edits.is_empty());
        let new = old.replace("import a\nimport b", "import b\nimport a");
        assert_eq!(facts_at(2, old, &new, "m.py").edits, ["m.py#<imports>"]);
        assert!(facts_at(1, old, &new, "m.py").edits.is_empty());
    }

    #[test]
    fn a_method_moved_inside_its_class_is_an_edit_of_the_method() {
        let old = "class C:\n    def f(self):\n        pass\n\n    def g(self):\n        pass\n";
        let new = "class C:\n    def g(self):\n        pass\n\n    def f(self):\n        pass\n";
        assert_eq!(
            facts_at(2, old, new, "m.py").edits,
            ["m.py#C.f", "m.py#C.g"]
        );
    }

    #[test]
    fn deterministic() {
        let new = BASE.replace("        a\n", "        a * 2\n");
        assert_eq!(
            run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)]),
            run(&[("src/a.rs", BASE)], &[("src/a.rs", &new)])
        );
    }
}
