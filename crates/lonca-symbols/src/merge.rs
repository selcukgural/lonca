//! Deterministic three-way merge.
//!
//! For supported languages the merge works on symbols: `theirs`' changes
//! relative to `base` (edited, added and deleted symbols, added and removed
//! imports) are applied to `ours`' text. Two changes to the same symbol
//! conflict; changes to different symbols never do, however close together
//! they are. Text the symbol merge can not place (module-level code changed
//! on one side only) falls back to a line-based merge. Unsupported files use
//! the line-based merge directly. Every merged file of a supported language
//! must parse, or it is reported as a conflict.

use std::collections::{BTreeMap, BTreeSet};

use lonca_core::{FileEntry, FileMap, GitId, Result};

use crate::engine::{
    ENGINE_DEFS, ENGINE_EXACT, ENGINE_GROUPS, ENGINE_KEYS, ENGINE_PLACES, ENGINE_SECTIONS,
};
use crate::extract::{
    Holder, Keyed, Pair, Parsed, Placed, Sym, align, key_twice, moved, normalize, parse_keyed,
    read_together, rename_aligned, shifted,
};

/// Code outside symbols as an engine compares it, and its place among them.
type Code<'a> = (&'a str, Placed<'a>);

fn own_code(engine: u32, s: &Sym) -> Code<'_> {
    (s.own_at(engine), s.placed())
}

fn outer_code(engine: u32, p: &Parsed) -> Code<'_> {
    (p.residual_at(engine), p.placed())
}

/// The code differs, in what it says or in where it stands.
fn differs(engine: u32, a: Code, b: Code) -> bool {
    a.0 != b.0 || engine >= ENGINE_PLACES && shifted(a.1, b.1)
}
use crate::facts::renames_between;
use crate::lang::Lang;
use crate::sections::{self, Format};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeResult {
    pub files: FileMap,
    /// Conflicting symbols (`path#name`) or files (`path#<file>`).
    pub conflicts: Vec<String>,
}

pub fn merge3(
    engine: u32,
    base: &FileMap,
    ours: &FileMap,
    theirs: &FileMap,
    read: &dyn Fn(&GitId) -> Result<Vec<u8>>,
    write: &dyn Fn(&[u8]) -> Result<GitId>,
) -> Result<MergeResult> {
    let mut files = FileMap::new();
    let mut conflicts = Vec::new();
    let paths: BTreeSet<&String> = base
        .keys()
        .chain(ours.keys())
        .chain(theirs.keys())
        .collect();
    for path in paths {
        let (b, o, t) = (base.get(path), ours.get(path), theirs.get(path));
        let pick = |e: Option<&FileEntry>, files: &mut FileMap| {
            if let Some(e) = e {
                files.insert(path.clone(), e.clone());
            }
        };
        if o == t || b == t {
            pick(o, &mut files);
            continue;
        }
        if b == o {
            pick(t, &mut files);
            continue;
        }
        let file_conflict = format!("{path}#<file>");
        match (b, o, t) {
            (_, Some(o), Some(t)) => {
                let mode = match b {
                    Some(b) if b.mode == o.mode => t.mode,
                    Some(b) if b.mode == t.mode => o.mode,
                    _ if o.mode == t.mode => o.mode,
                    _ => {
                        conflicts.push(file_conflict);
                        pick(Some(o), &mut files);
                        continue;
                    }
                };
                let base_text = match b {
                    Some(b) => read(&b.blob)?,
                    None => Vec::new(),
                };
                let (ob, tb) = (read(&o.blob)?, read(&t.blob)?);
                let blob = if ob == tb {
                    o.blob.clone()
                } else {
                    let texts = (
                        std::str::from_utf8(&base_text),
                        std::str::from_utf8(&ob),
                        std::str::from_utf8(&tb),
                    );
                    let (Ok(bt), Ok(ot), Ok(tt)) = texts else {
                        conflicts.push(file_conflict);
                        pick(Some(o), &mut files);
                        continue;
                    };
                    match merge_text_at(engine, path, bt, ot, tt) {
                        Ok(text) => write(text.as_bytes())?,
                        Err(c) => {
                            conflicts.extend(c);
                            pick(Some(o), &mut files);
                            continue;
                        }
                    }
                };
                files.insert(path.clone(), FileEntry { mode, blob });
            }
            // Deleted on one side, changed on the other.
            _ => {
                conflicts.push(file_conflict);
                pick(o, &mut files);
            }
        }
    }
    conflicts.sort();
    conflicts.dedup();
    Ok(MergeResult { files, conflicts })
}

/// Merges one file's text with engine 0. `Err` carries the conflicting
/// symbols.
pub fn merge_text(
    path: &str,
    b: &str,
    o: &str,
    t: &str,
) -> std::result::Result<String, Vec<String>> {
    merge_text_at(0, path, b, o, t)
}

/// A merge by sections, when `engine` has them and every side does. `None`
/// leaves the file to the line merge. A result that is no longer the format
/// it was is a conflict: the sections merged, the file did not.
fn section_merge(
    engine: u32,
    path: &str,
    b: &str,
    o: &str,
    t: &str,
) -> Option<std::result::Result<String, Vec<String>>> {
    if engine < ENGINE_SECTIONS {
        return None;
    }
    let format = Format::detect(path)?;
    Some(match sections::merge(format, b, o, t)? {
        Ok(text) if sections::sections(format, &text).is_some() => Ok(text),
        Ok(_) => Err(vec![format!("{path}#<file>")]),
        Err(names) => Err(names.iter().map(|n| format!("{path}#{n}")).collect()),
    })
}

/// Merges one file's text with the given engine.
pub fn merge_text_at(
    engine: u32,
    path: &str,
    b: &str,
    o: &str,
    t: &str,
) -> std::result::Result<String, Vec<String>> {
    if let Some(r) = section_merge(engine, path, b, o, t) {
        return r;
    }
    let file_conflict = || vec![format!("{path}#<file>")];
    let lang = Lang::detect(path);
    if let Some(lang) = lang {
        match symbol_merge(engine, path, lang, b, o, t) {
            Sm::Merged(s) => return Ok(s),
            Sm::Conflict(c) => return Err(c),
            Sm::Fallback => {}
        }
    }
    let merged = diffy::merge(b, o, t).map_err(|_| file_conflict())?;
    if let Some(lang) = lang {
        let (naming, sides) = three_sides(engine, lang, [b, o, t]);
        let [pb, po, pt] = &sides;
        // A side that does not parse has no symbols to hold the merge to,
        // and engines before this check only asked that the result parses.
        let unread = pb.has_error || po.has_error || pt.has_error;
        let engine = if unread || engine < ENGINE_PLACES {
            0
        } else {
            engine
        };
        if !holds_up(engine, path, lang, &merged, &naming, [pb, po, pt], &[]) {
            return Err(file_conflict());
        }
    }
    Ok(merged)
}

/// What is left of a file whose merge has conflicts: every change of `t`
/// applied, except the conflicting symbols, which keep the text of `o`.
/// `None` when the file has no such middle: no symbol merge, code outside
/// symbols changed by `t`, or something moved. Used by a workspace sync, so
/// that a conflict in one symbol does not hold back the rest of the file.
pub fn merge_around_conflicts(
    engine: u32,
    path: &str,
    b: &str,
    o: &str,
    t: &str,
) -> Option<String> {
    let lang = Lang::detect(path)?;
    let (naming, [pb, po, pt]) = three_sides(engine, lang, [b, o, t]);
    if pb.has_error || po.has_error || pt.has_error {
        return None;
    }
    if differs(engine, outer_code(engine, &pb), outer_code(engine, &pt)) {
        return None;
    }
    let mut m = Merger::new(engine, path, b, o, t);
    m.imports(&pb, &po, &pt);
    m.level(&pb.syms, &po.syms, &pt.syms, None);
    if m.moved {
        return None;
    }
    let conflicts = std::mem::take(&mut m.conflicts);
    let sides = [&pb, &po, &pt];
    if !numbers_hold(sides) || (engine >= ENGINE_KEYS && !counts_hold(sides)) {
        return None;
    }
    m.apply()
        .filter(|text| holds_up(engine, path, lang, text, &naming, sides, &conflicts))
}

fn all_names<'s>(syms: &'s [Sym], out: &mut BTreeSet<&'s str>) {
    for s in syms {
        out.insert(&s.name);
        all_names(&s.children, out);
    }
}

/// What the three sides of a merge call things, for reading the result.
#[derive(Default)]
struct Naming {
    keyed: Keyed,
    /// What each side changed the parameters of. A symbol of the result comes
    /// from a side, and that says what it is.
    pairs: Vec<Pair>,
}

/// The three sides of a merge, by one set of names: those of `base`.
fn three_sides(engine: u32, lang: Lang, texts: [&str; 3]) -> (Naming, [Parsed; 3]) {
    let (keyed, [pb, mut po, mut pt]) = read_together(engine, lang, texts);
    let mut pairs = align(&pb, &mut po);
    pairs.extend(align(&pb, &mut pt));
    (Naming { keyed, pairs }, [pb, po, pt])
}

/// Each side's code stands in `m` where that side put it among its symbols.
/// A side is the measure only if `m` has its code and the other side left
/// the places alone.
fn places_kept(engine: u32, [b, o, t]: [Code; 3], m: Code) -> bool {
    let kept = |side: Code, other: Code| {
        side.0 != m.0 || differs(engine, b, other) || !shifted(side.1, m.1)
    };
    kept(o, t) && kept(t, o)
}

fn members_kept(engine: u32, [bs, os, ts]: [&[Sym]; 3], merged: &[Sym]) -> bool {
    let (bm, om, tm) = (by_name(bs), by_name(os), by_name(ts));
    merged.iter().filter(|m| m.container).all(|m| {
        let name = m.name.as_str();
        let (Some(b), Some(o), Some(t)) = (bm.get(name), om.get(name), tm.get(name)) else {
            return true;
        };
        let code = [b, o, t].map(|s| own_code(engine, s));
        places_kept(engine, code, own_code(engine, m))
            && members_kept(engine, [&b.children, &o.children, &t.children], &m.children)
    })
}

/// `text` parses. From [`ENGINE_DEFS`] on it has every symbol a side added,
/// unless that symbol is in `conflicts`: a text insert can land in a string
/// or a comment and still parse, and the addition would be gone. From
/// [`ENGINE_PLACES`] on, also for the line merge, what a side deleted stays
/// deleted and code stands where the sides put it.
fn holds_up(
    engine: u32,
    path: &str,
    lang: Lang,
    text: &str,
    naming: &Naming,
    [pb, po, pt]: [&Parsed; 3],
    conflicts: &[String],
) -> bool {
    let mut merged = parse_keyed(engine, lang, text, &naming.keyed);
    if merged.has_error || key_twice(&merged, [pb, po, pt]) {
        return false;
    }
    rename_aligned(&mut merged, &naming.pairs);
    if engine < ENGINE_DEFS {
        return true;
    }
    let (mut base, mut sides, mut there) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    all_names(&pb.syms, &mut base);
    all_names(&po.syms, &mut sides);
    all_names(&pt.syms, &mut sides);
    all_names(&merged.syms, &mut there);
    let in_conflict = |n: &str| conflicts.contains(&format!("{path}#{n}"));
    if !sides
        .difference(&base)
        .all(|n| there.contains(n) || in_conflict(n))
    {
        return false;
    }
    if engine < ENGINE_PLACES {
        return true;
    }
    let (mut in_o, mut in_t) = (BTreeSet::new(), BTreeSet::new());
    all_names(&po.syms, &mut in_o);
    all_names(&pt.syms, &mut in_t);
    let gone = base
        .iter()
        .filter(|n| !in_o.contains(*n) || !in_t.contains(*n));
    let code = [pb, po, pt].map(|p| outer_code(engine, p));
    let kept = gone
        .into_iter()
        .all(|n| !there.contains(n) || in_conflict(n))
        && places_kept(engine, code, outer_code(engine, &merged))
        && members_kept(engine, [&pb.syms, &po.syms, &pt.syms], &merged.syms);
    if engine < ENGINE_GROUPS {
        return kept;
    }
    let known = |n: &&str| base.contains(n) || sides.contains(n);
    let code_of = |p: &Parsed| p.residual_at(engine).to_string();
    let from_a_side = [po, pt].map(code_of).contains(&code_of(&merged))
        && own_from_a_side(engine, [&po.syms, &pt.syms], &merged.syms);
    kept && there.iter().all(known) && from_a_side
}

/// A merge writes code of one side or the other, never a third: code both
/// sides changed is a conflict before it gets here.
fn own_from_a_side(engine: u32, [os, ts]: [&[Sym]; 2], merged: &[Sym]) -> bool {
    let (om, tm) = (by_name(os), by_name(ts));
    merged.iter().filter(|m| m.container).all(|m| {
        let name = m.name.as_str();
        let (Some(o), Some(t)) = (om.get(name), tm.get(name)) else {
            return true;
        };
        [o, t].iter().any(|s| s.own_at(engine) == m.own_at(engine))
            && own_from_a_side(engine, [&o.children, &t.children], &m.children)
    })
}

/// Which block each name with a number stands in, at any depth.
fn numbered_places(syms: &[Sym], out: &mut BTreeMap<String, Vec<(u32, u32)>>) {
    for s in syms {
        if let Some(h) = s.holder {
            let name = s.name.split('~').next().unwrap_or(&s.name);
            out.entry(name.to_string()).or_default().push(h.block);
        }
        numbered_places(&s.children, out);
    }
}

/// How many of each name a list holds, at any depth, and which are numbered.
fn numbered_counts(syms: &[Sym], out: &mut BTreeMap<String, (u32, bool)>) {
    for s in syms {
        let entry = out.entry(s.stem.clone()).or_default();
        entry.0 += 1;
        entry.1 |= s.stem != s.name;
        numbered_counts(&s.children, out);
    }
}

/// Exact duplicates are told apart by their order only: when both sides
/// took some away, `f~2` of one is not `f~2` of the other, and neither side
/// can say which was removed.
fn counts_hold([pb, po, pt]: [&Parsed; 3]) -> bool {
    let counts = |p: &Parsed| {
        let mut out = BTreeMap::new();
        numbered_counts(&p.syms, &mut out);
        out
    };
    let (b, o, t) = (counts(pb), counts(po), counts(pt));
    let how_many =
        |side: &BTreeMap<String, (u32, bool)>, name: &String| side.get(name).map(|c| c.0);
    let numbered = b.iter().filter(|(_, count)| count.1);
    numbered.into_iter().all(|(name, count)| {
        how_many(&o, name) == Some(count.0) || how_many(&t, name) == Some(count.0)
    })
}

/// A number in a name counts from the top of the file: the same number can
/// be another definition when a name came to stand in another block, even
/// with as many of the name as before.
fn numbers_hold([pb, po, pt]: [&Parsed; 3]) -> bool {
    let places = |p: &Parsed| {
        let mut out = BTreeMap::new();
        numbered_places(&p.syms, &mut out);
        out.retain(|_, list: &mut Vec<_>| list.len() > 1);
        out
    };
    let base = places(pb);
    places(po) == base && places(pt) == base
}

enum Sm {
    Merged(String),
    Conflict(Vec<String>),
    Fallback,
}

struct Edit {
    start: usize,
    end: usize,
    text: String,
    seq: usize,
}

struct Merger<'a> {
    engine: u32,
    path: &'a str,
    b: &'a str,
    o: &'a str,
    t: &'a str,
    edits: Vec<Edit>,
    conflicts: Vec<String>,
    /// `theirs` moved something, which edits in place can not express.
    moved: bool,
}

fn names(syms: &[Sym]) -> Vec<&str> {
    syms.iter().map(|s| s.name.as_str()).collect()
}

fn ws_before(src: &str, pos: usize) -> &str {
    let head = &src[..pos];
    let trimmed = head.trim_end_matches([' ', '\t', '\n', '\r']);
    &head[trimmed.len()..]
}

fn ws_after(src: &str, pos: usize) -> &str {
    let tail = &src[pos..];
    let trimmed = tail.trim_start_matches([' ', '\t', '\n', '\r']);
    &tail[..tail.len() - trimmed.len()]
}

fn by_name(syms: &[Sym]) -> BTreeMap<&str, &Sym> {
    syms.iter().map(|s| (s.name.as_str(), s)).collect()
}

impl<'a> Merger<'a> {
    fn new(engine: u32, path: &'a str, b: &'a str, o: &'a str, t: &'a str) -> Self {
        Merger {
            engine,
            path,
            b,
            o,
            t,
            edits: Vec::new(),
            conflicts: Vec::new(),
            moved: false,
        }
    }

    fn conflict(&mut self, name: &str) {
        self.conflicts.push(format!("{}#{name}", self.path));
    }

    fn insert(&mut self, pos: usize, text: String) {
        let seq = self.edits.len();
        self.edits.push(Edit {
            start: pos,
            end: pos,
            text,
            seq,
        });
    }

    fn replace(&mut self, start: usize, end: usize, text: String) {
        let seq = self.edits.len();
        self.edits.push(Edit {
            start,
            end,
            text,
            seq,
        });
    }

    fn level(&mut self, bs: &[Sym], os: &[Sym], ts: &[Sym], o_container: Option<&Sym>) {
        let (bm, om, tm) = (by_name(bs), by_name(os), by_name(ts));
        let top = o_container.is_none();
        self.note_moves(&names(bs), &names(ts));
        // A symbol `t` renamed stays where `o` has it, unless `t` also moved
        // it among the symbols both have.
        let t_renames = renames_between(self.engine, bs, ts);
        let o_renames = renames_between(self.engine, bs, os);
        // The symbols both have and the renamed ones, in `t`'s names.
        let order = |list: &[Sym]| -> Vec<String> {
            let both =
                |s: &Sym| bm.contains_key(s.name.as_str()) && tm.contains_key(s.name.as_str());
            let as_in_t = |s: &Sym| {
                let pair = t_renames
                    .iter()
                    .find(|[old, new]| *old == s.name || *new == s.name);
                let renamed = pair.map(|[_, new]| new.to_string());
                renamed.or(both(s).then(|| s.name.clone()))
            };
            list.iter().filter_map(as_in_t).collect()
        };
        let mut in_place: BTreeMap<&str, (&str, &Sym)> = BTreeMap::new();
        for [old, new] in t_renames.iter().filter(|_| order(bs) == order(ts)) {
            if let (Some(b_sym), Some(o_sym)) = (bm.get(old), om.get(old))
                && o_sym.same(self.o, b_sym, self.b)
            {
                in_place.insert(new, (old, o_sym));
            }
        }
        // Where `o` has what it gave another name.
        let o_has: BTreeMap<&str, &Sym> = (o_renames.iter())
            .filter_map(|[old, new]| Some((*old, *om.get(new)?)))
            .collect();
        let mut renamed = BTreeSet::new();
        for (i, ts_sym) in ts.iter().enumerate() {
            let name = ts_sym.name.as_str();
            let t_text = ts_sym.text(self.t);
            match bm.get(name) {
                None => {
                    if let Some(o_sym) = om.get(name) {
                        if !o_sym.same(self.o, ts_sym, self.t)
                            || !self.same_block(o_sym, os, ts_sym, ts)
                        {
                            self.conflict(name);
                        }
                        continue;
                    }
                    if let Some((old, o_sym)) = in_place.get(name) {
                        renamed.insert(*old);
                        self.replace(o_sym.start, o_sym.end, t_text.to_string());
                        continue;
                    }
                    // `o` deleted it or called it something else: that can
                    // not be done to it as well.
                    let was = t_renames.iter().find(|[_, new]| *new == name);
                    if let Some([old, _]) = was.filter(|[old, _]| !om.contains_key(old)) {
                        self.conflict(old);
                        continue;
                    }
                    // A new symbol stands next to one of its own group, on
                    // a side where that one is in the same kind of group.
                    let held = ts_sym.holder;
                    let beside = |s: &&Sym| s.holder == held;
                    let shape = |h: Option<Holder>| h.map(|h| (h.kind, h.joined));
                    let anchor = |s: &Sym| {
                        let name = s.name.as_str();
                        let o_sym = om.get(name).copied();
                        let o_sym = o_sym.or(in_place.get(name).map(|(_, o)| *o));
                        let o_sym = o_sym.or(o_has.get(name).copied());
                        o_sym.filter(|o| shape(o.holder) == shape(held))
                    };
                    let (gap_start, gap_end) = ts_sym.around;
                    let sep_before = match (gap_start, ws_before(self.t, ts_sym.start)) {
                        (Some(from), _) => &self.t[from..ts_sym.start],
                        (None, "") if top => "\n\n",
                        (None, "") => "\n",
                        (None, ws) => ws,
                    }
                    .to_string();
                    // In a list, only a symbol right next to it says where
                    // it goes: order against other elements can matter.
                    let touching =
                        |gap: Option<usize>, at: Option<usize>| gap.is_none() || gap == at;
                    let before = ts[..i].iter().rev().find(beside);
                    let after = ts[i + 1..].iter().find(beside);
                    let prev = ts[..i].iter().rev().filter(beside).find_map(anchor);
                    let prev = prev.filter(|_| touching(gap_start, before.map(|p| p.end)));
                    let next = ts[i..].iter().filter(beside).find_map(anchor);
                    let next = next.filter(|_| touching(gap_end, after.map(|a| a.start)));
                    let after_code = self.engine >= ENGINE_PLACES && i > 0 && {
                        let gap = &self.t[ts[i - 1].end..ts_sym.start];
                        let code = gap.trim_matches([' ', '\t', '\n', '\r', ';', ',']);
                        !code.is_empty() || ts[i - 1].holder != held
                    };
                    if let (Some(p), false) = (prev, after_code) {
                        self.insert(p.end, format!("{sep_before}{t_text}"));
                    } else if let Some(n) = next {
                        let sep_after = match (gap_end, ws_after(self.t, ts_sym.end)) {
                            (Some(to), _) => &self.t[ts_sym.end..to],
                            (None, "") if top => "\n\n",
                            (None, "") => "\n",
                            (None, ws) => ws,
                        };
                        self.insert(n.start, format!("{t_text}{sep_after}"));
                    } else if held.is_some() {
                        // Nothing to stand beside: only lines can place it.
                        self.moved = true;
                    } else if let Some(c) = o_container {
                        let body = &self.o[c.start..c.end];
                        let pos = match body.rfind('}') {
                            Some(close) => c.start + body[..close].trim_end().len(),
                            None => c.end,
                        };
                        self.insert(pos, format!("{sep_before}{t_text}"));
                    } else {
                        let pos = self.o.trim_end().len();
                        self.insert(pos, format!("{sep_before}{t_text}"));
                    }
                }
                Some(b_sym) => {
                    if b_sym.same(self.b, ts_sym, self.t) {
                        continue;
                    }
                    let Some(o_sym) = om.get(name) else {
                        self.conflict(name);
                        continue;
                    };
                    if o_sym.same(self.o, ts_sym, self.t) {
                        continue;
                    }
                    if o_sym.same(self.o, b_sym, self.b) {
                        self.replace(o_sym.start, o_sym.end, t_text.to_string());
                        continue;
                    }
                    let unit = b_sym.changed_unit(ts_sym, self.engine);
                    if !(b_sym.container && o_sym.container && ts_sym.container) {
                        self.conflict(&unit);
                        continue;
                    }
                    let defs = self.engine >= ENGINE_DEFS;
                    let [code_b, code_o, code_t] =
                        [*b_sym, *o_sym, ts_sym].map(|s| own_code(self.engine, s));
                    let changed = differs(self.engine, code_b, code_t);
                    if changed && !(defs && !differs(self.engine, code_o, code_t)) {
                        let o_kept = defs && !differs(self.engine, code_b, code_o);
                        if o_kept && code_t.0 == code_b.0 {
                            // Only places: that is the line merge's to do.
                            self.moved = true;
                        } else {
                            if o_kept && self.around_theirs(b_sym, o_sym, ts_sym) {
                                continue;
                            }
                            self.conflict(&unit);
                            if !defs {
                                continue;
                            }
                        }
                    }
                    self.level(
                        &b_sym.children,
                        &o_sym.children,
                        &ts_sym.children,
                        Some(o_sym),
                    );
                }
            }
        }
        for b_sym in bs {
            if tm.contains_key(b_sym.name.as_str()) || renamed.contains(b_sym.name.as_str()) {
                continue;
            }
            if let Some(o_sym) = om.get(b_sym.name.as_str()) {
                if o_sym.same(self.o, b_sym, self.b) {
                    let (start, end) = self.span_to_delete(o_sym);
                    self.replace(start, end, String::new());
                } else {
                    self.conflict(&b_sym.name);
                }
            } else {
                // `t` deleted what `o` renamed: the symbol must not live on.
                let was = |list: &[[&str; 2]]| list.iter().any(|[old, _]| *old == b_sym.name);
                if was(&o_renames) && !was(&t_renames) {
                    self.conflict(&b_sym.name);
                }
            }
        }
    }

    /// The symbols of `o` and of `t` stand in one block: they share a
    /// neighbour, or with none to compare, the file up to the block is the same.
    fn same_block(&self, o: &Sym, os: &[Sym], t: &Sym, ts: &[Sym]) -> bool {
        let others = |s: &Sym, list: &[Sym]| -> BTreeSet<String> {
            let held = list.iter().filter(|x| x.holder == s.holder);
            held.filter(|x| x.name != s.name)
                .map(|x| x.name.clone())
                .collect()
        };
        let (Some(ho), Some(ht)) = (o.holder, t.holder) else {
            return o.holder == t.holder;
        };
        let (a, b) = (others(o, os), others(t, ts));
        if a.is_empty() || b.is_empty() {
            return self.o[..ho.start] == self.t[..ht.start];
        }
        !a.is_disjoint(&b)
    }

    /// What goes with `sym` of `o`: the whitespace in front of it, and in a
    /// list with separators, one separator.
    fn span_to_delete(&self, sym: &Sym) -> (usize, usize) {
        match sym.around {
            (_, Some(next)) => (sym.start, next),
            (Some(prev), None) => (prev, sym.end),
            (None, None) => (sym.start - ws_before(self.o, sym.start).len(), sym.end),
        }
    }

    /// `t` changed the container's own text and `o` only its members. The
    /// result is `t`'s container with the members of both, so the same walk
    /// runs the other way round and replaces the container in `o`. `false`
    /// when the members conflict: nothing is done, and that walk is the
    /// caller's to make, in `o`, so that conflicts keep the text of `o`.
    fn around_theirs(&mut self, b: &Sym, o: &Sym, t: &Sym) -> bool {
        let mut m = Merger::new(self.engine, self.path, self.b, self.t, self.o);
        m.level(&b.children, &t.children, &o.children, Some(t));
        if !m.conflicts.is_empty() {
            return false;
        }
        self.note_moves(&names(&b.children), &names(&t.children));
        self.moved |= m.moved;
        match m.apply_within(t.start, t.end) {
            Some(text) => self.replace(o.start, o.end, text),
            None => self.moved = true,
        }
        true
    }

    fn note_moves(&mut self, base: &[&str], theirs: &[&str]) {
        if self.engine >= ENGINE_EXACT && !moved(base, theirs).is_empty() {
            self.moved = true;
        }
    }

    fn imports(&mut self, pb: &Parsed, po: &Parsed, pt: &Parsed) {
        let norm = |src: &str, spans: &[(usize, usize)]| -> Vec<(String, (usize, usize))> {
            spans
                .iter()
                .map(|&(s, e)| (normalize(&src[s..e]), (s, e)))
                .collect()
        };
        let (bi, oi, ti) = (
            norm(self.b, &pb.imports),
            norm(self.o, &po.imports),
            norm(self.t, &pt.imports),
        );
        let texts: [Vec<&str>; 2] = [&bi, &ti].map(|l| l.iter().map(|(n, _)| n.as_str()).collect());
        self.note_moves(&texts[0], &texts[1]);
        let bset: BTreeSet<&String> = bi.iter().map(|(n, _)| n).collect();
        let oset: BTreeSet<&String> = oi.iter().map(|(n, _)| n).collect();
        let tset: BTreeSet<&String> = ti.iter().map(|(n, _)| n).collect();
        let anchor = oi.last().map(|(_, (_, e))| *e);
        for (n, (s, e)) in &ti {
            if bset.contains(n) || oset.contains(n) {
                continue;
            }
            let text = &self.t[*s..*e];
            match anchor {
                Some(pos) => self.insert(pos, format!("\n{text}")),
                None => self.insert(0, format!("{text}\n")),
            }
        }
        for (n, (s, e)) in &oi {
            if bset.contains(n) && !tset.contains(n) {
                let start = s - ws_before(self.o, *s).len().min(1);
                self.replace(start, *e, String::new());
            }
        }
    }

    fn apply(self) -> Option<String> {
        let end = self.o.len();
        self.apply_within(0, end)
    }

    /// `o` from `from` to `to` with the edits applied, all of them inside.
    fn apply_within(mut self, from: usize, to: usize) -> Option<String> {
        self.edits.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then(a.end.cmp(&b.end))
                .then(a.seq.cmp(&b.seq))
        });
        for w in self.edits.windows(2) {
            if w[1].start < w[0].end {
                return None;
            }
        }
        let mut out = String::with_capacity(to - from);
        let mut pos = from;
        for e in &self.edits {
            out.push_str(&self.o[pos..e.start]);
            out.push_str(&e.text);
            pos = e.end;
        }
        out.push_str(&self.o[pos..to]);
        Some(out)
    }
}

fn symbol_merge(engine: u32, path: &str, lang: Lang, b: &str, o: &str, t: &str) -> Sm {
    let (naming, [pb, po, pt]) = three_sides(engine, lang, [b, o, t]);
    if pb.has_error || po.has_error || pt.has_error {
        return Sm::Fallback;
    }
    let [cb, co, ct] = [&pb, &po, &pt].map(|p| outer_code(engine, p));
    if differs(engine, cb, ct) && differs(engine, co, ct) {
        if !differs(engine, cb, co) {
            return Sm::Fallback;
        }
        return Sm::Conflict(vec![format!("{path}#<module>")]);
    }
    if !numbers_hold([&pb, &po, &pt]) || (engine >= ENGINE_KEYS && !counts_hold([&pb, &po, &pt])) {
        return Sm::Fallback;
    }
    let mut m = Merger::new(engine, path, b, o, t);
    m.imports(&pb, &po, &pt);
    m.level(&pb.syms, &po.syms, &pt.syms, None);
    if !m.conflicts.is_empty() {
        let mut c = m.conflicts;
        c.sort();
        c.dedup();
        return Sm::Conflict(c);
    }
    if m.moved {
        return Sm::Fallback;
    }
    match m.apply() {
        // Nothing of `theirs` came through, though the files differ: only
        // the line merge sees what it changed.
        Some(text) if engine >= ENGINE_EXACT && text == o => Sm::Fallback,
        Some(text) if holds_up(engine, path, lang, &text, &naming, [&pb, &po, &pt], &[]) => {
            Sm::Merged(text)
        }
        _ => Sm::Fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ENGINE_RENAMES;
    use crate::extract::{parse, parse_at};

    const CLASS: &str = "class A:\n    x = 1\n\n    def a(self):\n        return 1\n\n    def b(self):\n        return 2\n\n    def c(self):\n        return 3\n";

    fn class(from: &str, to: &str) -> String {
        assert_eq!(CLASS.matches(from).count(), 1, "{from}");
        CLASS.replace(from, to)
    }

    /// Which side changes the header and which a method does not matter
    /// any more: the queue decides that, not the agents.
    /// Each row: three versions of a file and what the merge gives.
    fn keyed(path: &str, b: &str, o: &str, t: &str) -> std::result::Result<String, Vec<String>> {
        merge_text_at(ENGINE_KEYS, path, b, o, t)
    }

    const CHARGE: &str = "class C {\n    void M(int a) {\n        A();\n    }\n}\n";

    #[test]
    fn an_overload_added_above_does_not_stop_an_edit_of_the_first() {
        let o = CHARGE.replace(
            "    void M(int a)",
            "    void M(string s) {\n        B();\n    }\n\n    void M(int a)",
        );
        let t = CHARGE.replace("A();", "C();");
        let m = keyed("a.cs", CHARGE, &o, &t).unwrap();
        assert!(m.contains("void M(string s) {\n        B();"), "{m}");
        assert!(m.contains("void M(int a) {\n        C();"), "{m}");
        assert_eq!(keyed("a.cs", CHARGE, &t, &o).unwrap(), m);
        // Engine 5 reads the new overload as the first one changed.
        assert!(merge_text_at(ENGINE_KEYS - 1, "a.cs", CHARGE, &o, &t).is_err());
    }

    #[test]
    fn two_changes_of_one_overload_conflict_on_it() {
        let b = "class C {\n    void M(int a) { A(); }\n    void M(string s) { B(); }\n}\n";
        let o = b.replace("M(int a)", "M(long a)");
        let t = b.replace("M(int a)", "M(short a)");
        assert_eq!(
            keyed("a.cs", b, &o, &t),
            Err(vec!["a.cs#C.M(int)".to_string()])
        );
        let t = b.replace("A();", "X();");
        assert_eq!(
            keyed("a.cs", b, &o, &t),
            Err(vec!["a.cs#C.M(int)".to_string()])
        );
    }

    /// One file can hold a key once. The two definitions would both pass as
    /// the symbols of the base that the sides changed.
    #[test]
    fn two_symbols_given_one_key_conflict() {
        let b = "def f(a: int):\n    return 1\n\n\ndef f(a: str):\n    return 2\n";
        let o = b.replace("a: int", "a: bytes");
        let t = b.replace("a: str", "a: bytes");
        assert!(keyed("a.py", b, &o, &t).is_err());
        let b = "class C {\n    void M(int a) { A(); }\n\n    void M(long a) { B(); }\n}\n";
        let o = b.replace("M(int a)", "M(bool a)");
        let t = b.replace("M(long a)", "M(bool a)");
        assert!(keyed("a.cs", b, &o, &t).is_err());
    }

    /// One key is fine twice where the two can not meet: each row gives two
    /// symbols of the base one new key.
    #[test]
    fn one_key_in_two_scopes_merges() {
        let rows = [
            (
                "a.py",
                "if X:\n    def f(a: int):\n        return 1\nelse:\n    def f(a: str):\n        return 2\n",
                ("a: int", "a: bytes"),
                ("a: str", "a: bytes"),
            ),
            (
                "a.rs",
                "impl W<u8> {\n    fn f(a: u8) {}\n}\nimpl W<u16> {\n    fn f(a: u16) {}\n}\n",
                ("a: u8", "a: bool"),
                ("a: u16", "a: bool"),
            ),
        ];
        for (path, b, (ox, oy), (tx, ty)) in rows {
            let (o, t) = (b.replace(ox, oy), b.replace(tx, ty));
            let want = b.replace(ox, oy).replace(tx, ty);
            assert_eq!(
                keyed(path, b, &o, &t).as_deref(),
                Ok(want.as_str()),
                "{path}"
            );
            assert_eq!(
                keyed(path, b, &t, &o).as_deref(),
                Ok(want.as_str()),
                "{path}"
            );
        }
    }

    /// A new key on one side and the same key added elsewhere on the other.
    #[test]
    fn a_new_key_and_an_addition_of_it_in_another_scope_merge() {
        let b = "if X:\n    def f(a: int):\n        return 1\nelse:\n    def f(a: str):\n        return 2\n";
        let o = b.replace("a: int", "a: bytes");
        let t = b.replace(
            "return 2\n",
            "return 2\n    def f(a: bytes):\n        return 3\n",
        );
        for (o, t) in [(&o, &t), (&t, &o)] {
            let m = keyed("a.py", b, o, t).unwrap();
            assert_eq!(m.matches("a: bytes").count(), 2, "{m}");
            assert!(m.contains("return 3") && !m.contains("a: int"), "{m}");
        }
        // In one scope that is the same key twice.
        let b = "class C {\n    void M(int a) { A(); }\n\n    void M(string s) { B(); }\n}\n";
        let o = b.replace("M(int a)", "M(long a)");
        let t = b.replace(
            "void M(string s) { B(); }",
            "void M(string s) { B(); }\n\n    void M(long b) { C(); }",
        );
        assert!(keyed("a.cs", b, &o, &t).is_err());
        assert!(keyed("a.cs", b, &t, &o).is_err());
    }

    /// A key the base already has can land beside itself, too.
    #[test]
    fn a_key_of_the_base_given_to_a_symbol_beside_its_new_namesake_conflicts() {
        let b = "if X:\n    def f(a: short):\n        return 2\nelse:\n    def f(a: long):\n        return 1\n";
        let o = b.replace(
            "return 1\n",
            "return 1\n    def f(a: short):\n        return 9\n",
        );
        let t = b
            .replace("a: short", "a: char")
            .replace("a: long", "a: short");
        assert!(keyed("a.py", b, &o, &t).is_err());
        assert!(keyed("a.py", b, &t, &o).is_err());
    }

    /// What a file has twice already is not the merge's doing.
    #[test]
    fn a_duplicate_of_a_side_does_not_stop_a_merge() {
        let b = "class C {\n    void M(int a) { A(); }\n\n    void M(int b) { B(); }\n\n    void M(string s) {}\n\n    void N() {}\n}\n";
        let o = b.replace("A();", "X();");
        let t = b.replace("void N() {}", "void N() { Y(); }");
        let m = keyed("a.cs", b, &o, &t).unwrap();
        assert!(m.contains("X();") && m.contains("Y();"), "{m}");
    }

    /// One side giving both scopes a key leaves it numbered on that side.
    #[test]
    fn one_side_may_give_one_key_to_two_scopes() {
        let rows = [
            (
                "a.py",
                "if X:\n    def f(a: int):\n        return 1\nelse:\n    def f(a: str):\n        return 2\n\n\ndef k():\n    return 3\n",
                ["a: int", "a: str"],
                "a: bytes",
                ("return 3", "return 4"),
            ),
            (
                "a.rs",
                "impl W<u8> {\n    fn f(a: u8) {}\n}\nimpl W<u16> {\n    fn f(a: u16) {}\n}\n\nfn k() {\n    a();\n}\n",
                ["a: u8", "a: u16"],
                "a: bool",
                ("a();", "b();"),
            ),
        ];
        for (path, b, [first, second], new, (from, to)) in rows {
            let o = b.replace(first, new).replace(second, new);
            let t = b.replace(from, to);
            let want = o.replace(from, to);
            assert_eq!(
                keyed(path, b, &o, &t).as_deref(),
                Ok(want.as_str()),
                "{path}"
            );
            assert_eq!(
                keyed(path, b, &t, &o).as_deref(),
                Ok(want.as_str()),
                "{path}"
            );
        }
    }

    /// With one text for two symbols, the order of the base tells them.
    #[test]
    fn equal_texts_keep_their_order_in_both_queue_orders() {
        let b = "if X:\n    def f(a: int):\n        return 1\nelse:\n    def f(a: str):\n        return 1\n";
        let o = b.replace("a: str", "a: bytes");
        let t = b.replace("a: int", "a: bytes");
        let want = o.replace("a: int", "a: bytes");
        assert_eq!(keyed("a.py", b, &o, &t).as_deref(), Ok(want.as_str()));
        assert_eq!(keyed("a.py", b, &t, &o).as_deref(), Ok(want.as_str()));
    }

    /// The parts of a type are one scope, for all that they are two lists.
    #[test]
    fn one_key_in_two_parts_of_a_type_conflicts() {
        let b = "partial class C {\n    void M(int a) {}\n}\npartial class C {\n    void M(long a) {}\n}\n";
        let o = b.replace("M(int a)", "M(bool a)");
        let t = b.replace("M(long a)", "M(bool a)");
        assert!(keyed("a.cs", b, &o, &t).is_err());
    }

    /// A `~` in a key is no number: these are three overloads.
    #[test]
    fn a_tilde_in_a_key_counts_for_nothing() {
        let b = "function f(a: '~a'): void;\nfunction f(a: '~b'): void;\nfunction f(a: '~c'): void;\nfunction f(a: any) {}\n";
        let o = b.replace("function f(a: '~a'): void;\n", "");
        let t = b.replace("function f(a: '~b'): void;\n", "");
        let m = keyed("a.ts", b, &o, &t).unwrap();
        assert!(
            !m.contains("'~a'") && !m.contains("'~b'") && m.contains("'~c'"),
            "{m}"
        );
    }

    /// `t` deleted the first and changed the second; which it changed is
    /// read from their texts, or the delete of `o` would come undone.
    #[test]
    fn a_change_of_a_symbol_the_other_side_deleted_conflicts_in_both_orders() {
        let b = "class C {\n    void M(int a) { Alpha(); Beta(); }\n\n    void M(string s) { Gamma(s, 1); Delta(s, 2); }\n\n    void N() {}\n}\n";
        let o = b.replace("    void M(string s) { Gamma(s, 1); Delta(s, 2); }\n\n", "");
        let t = b
            .replace("    void M(int a) { Alpha(); Beta(); }\n\n", "")
            .replace("M(string s) { Gamma(s, 1)", "M(long s) { Gamma(s, 3)");
        let want = Err(vec!["a.cs#C.M(string)".to_string()]);
        assert_eq!(keyed("a.cs", b, &o, &t), want);
        assert_eq!(keyed("a.cs", b, &t, &o), want);
    }

    /// What a row says: what it is, the base, both sides, what the result
    /// has and what it has not.
    type Row<'a> = (
        &'a str,
        &'a str,
        String,
        String,
        &'a [&'a str],
        &'a [&'a str],
    );

    /// Each row: changes to different overloads, which the leases allow.
    #[test]
    fn changes_to_different_overloads_merge() {
        let two = "class C {\n    void M(int a) { A(); }\n\n    void M(string s) { B(); }\n}\n";
        let one = "class C {\n    void M(int a) { A(); }\n}\n";
        let add = |text: &str, line: &str| {
            text.replacen("    void M", &format!("    {line}\n\n    void M"), 1)
        };
        let drop_int = two.replace("    void M(int a) { A(); }\n\n", "");
        let drop_string = two.replace("\n\n    void M(string s) { B(); }", "");
        let rows: [Row; 5] = [
            (
                "new one and a delete",
                two,
                add(two, "void M(long a) { X(); }"),
                drop_string.clone(),
                &["M(long a) { X(); }", "M(int a) { A(); }"],
                &["M(string"],
            ),
            (
                "new parameters and a new one",
                two,
                two.replace("M(int a)", "M(long a)"),
                add(two, "void M(short a) { X(); }"),
                &["M(long a) { A(); }", "M(short a) { X(); }", "M(string s)"],
                &["M(int"],
            ),
            (
                "a delete and new parameters",
                two,
                drop_int.clone(),
                two.replace("M(string s)", "M(long s)"),
                &["M(long s) { B(); }"],
                &["M(int", "M(string"],
            ),
            (
                "a first overload and a delete of the only one",
                one,
                one.replace("}\n}", "}\n\n    void M(string s) { B(); }\n}"),
                "class C {\n}\n".to_string(),
                &["M(string s) { B(); }"],
                &["M(int"],
            ),
            (
                "new parameters next to an edit",
                two,
                two.replace("M(int a)", "M(long a)"),
                two.replace("B();", "Y();"),
                &["M(long a) { A(); }", "M(string s) { Y(); }"],
                &["M(int"],
            ),
        ];
        for (what, b, o, t, has, hasnt) in rows {
            for (o, t) in [(&o, &t), (&t, &o)] {
                let m = keyed("a.cs", b, o, t).unwrap_or_else(|c| panic!("{what}: {c:?}"));
                assert!(has.iter().all(|x| m.contains(x)), "{what}\n{m}");
                assert!(!hasnt.iter().any(|x| m.contains(x)), "{what}\n{m}");
            }
        }
    }

    /// Exact duplicates have only their order, so two sides that each took
    /// one away can not be told from two sides that took the same.
    #[test]
    fn duplicates_both_sides_took_from_do_not_merge_by_number() {
        let b = "package p\n\nfunc init() {\n\ta()\n}\n\nfunc init() {\n\tb()\n}\n\nfunc k() {}\n";
        let o = b.replace("func init() {\n\tb()\n}\n\n", "");
        let t = b.replace("func init() {\n\ta()\n}\n\n", "");
        assert!(keyed("a.go", b, &o, &t).is_err());
        assert!(keyed("a.go", b, &t, &o).is_err());
        assert_eq!(merge_around_conflicts(ENGINE_KEYS, "a.go", b, &o, &t), None);
        // One side alone does not stop anything.
        let t = b.replace("func k() {}", "func k() {\n\tc()\n}");
        let m = keyed("a.go", b, &o, &t).unwrap();
        assert!(!m.contains("b()") && m.contains("c()"), "{m}");
    }

    #[test]
    fn a_change_of_parameters_merges_with_another_overload() {
        let b = "class C {\n    void M(int a) { A(); }\n\n    void M(string s) { B(); }\n}\n";
        let o = b.replace("M(int a)", "M(long a)");
        let t = b.replace("B();", "X();");
        let m = keyed("a.cs", b, &o, &t).unwrap();
        assert!(
            m.contains("M(long a) { A(); }") && m.contains("M(string s) { X(); }"),
            "{m}"
        );
        assert_eq!(keyed("a.cs", b, &t, &o).unwrap(), m);
    }

    #[test]
    fn the_members_of_a_trait_impl_follow_its_arguments() {
        let one = "impl From<u8> for S {\n    fn from(v: u8) -> S {\n        S\n    }\n}\n";
        let two = "impl From<u16> for S {\n    fn from(v: u16) -> S {\n        S\n    }\n}\n";
        let o = format!("{two}\n{one}");
        let t = one.replace("        S\n", "        S::new()\n");
        let m = keyed("a.rs", one, &o, &t).unwrap();
        assert!(m.contains("v: u16) -> S {\n        S\n"), "{m}");
        assert!(m.contains("v: u8) -> S {\n        S::new()\n"), "{m}");
    }

    /// Each row: a rename on one side and an edit of another symbol on the
    /// other, in both orders.
    #[test]
    fn a_rename_merges_with_an_edit_of_another_symbol() {
        let rows = [
            (
                "a.rs",
                "fn old() {\n    a();\n}\n\nfn other() {\n    b();\n}\n",
                "old",
                "new",
                "b();",
                "c();",
            ),
            (
                "a.py",
                "def old():\n    a()\n\n\ndef other():\n    b()\n",
                "old",
                "new",
                "b()",
                "c()",
            ),
            (
                "a.ts",
                "function old() {\n  a();\n}\n\nfunction other() {\n  b();\n}\n",
                "old",
                "fresh",
                "b();",
                "c();",
            ),
            (
                "a.js",
                "function old() {\n  a();\n}\n\nfunction other() {\n  b();\n}\n",
                "old",
                "fresh",
                "b();",
                "c();",
            ),
            (
                "a.cs",
                "class C {\n    void Old() { A(); }\n\n    void Other() { B(); }\n}\n",
                "Old",
                "New",
                "B();",
                "C();",
            ),
            (
                "a.go",
                "package p\n\nfunc Old() {\n\ta()\n}\n\nfunc Other() {\n\tb()\n}\n",
                "Old",
                "New",
                "b()",
                "c()",
            ),
        ];
        for (path, b, from, to, edit, edited) in rows {
            let (o, t) = (b.replacen(from, to, 1), b.replace(edit, edited));
            let want = o.replace(edit, edited);
            for (o, t) in [(&o, &t), (&t, &o)] {
                let m = merge_text_at(ENGINE_RENAMES, path, b, o, t);
                assert_eq!(m.as_deref(), Ok(want.as_str()), "{path}");
            }
        }
    }

    /// What `t` wrote behind a renamed symbol stays behind it: the order of
    /// definitions can be what the code needs.
    #[test]
    fn code_added_behind_a_renamed_symbol_stays_behind_it() {
        let b = "class A:\n    pass\n\n\nclass Old:\n    def m(self):\n        return 1\n\n    def n(self):\n        return 2\n\n\ndef last():\n    return 3\n";
        let t = b
            .replace("class Old:", "class New:")
            .replace("def last", "class Child(New):\n    pass\n\n\ndef last");
        let o = b.replace("return 3", "return 4");
        let m = merge_text_at(ENGINE_RENAMES, "a.py", b, &o, &t).unwrap();
        let (new, child) = (m.find("class New").unwrap(), m.find("class Child").unwrap());
        assert!(new < child, "{m}");
        assert!(m.contains("return 4"), "{m}");
    }

    /// A rename and a move are both done, or a conflict, never half.
    #[test]
    fn a_rename_that_also_moved_keeps_the_move() {
        let (a, c, d) = (
            "def a():\n    return 1\n",
            "def c():\n    return 2\n",
            "def d():\n    return 3\n",
        );
        let b = format!("{a}\n\n{c}\n\n{d}");
        let n = a.replace("def a", "def n");
        let t = format!("{c}\n\n{d}\n\n{n}");
        let o = b.replace("return 3", "return 4");
        let m = merge_text_at(ENGINE_RENAMES, "a.py", &b, &o, &t).unwrap();
        assert!(m.find("def d").unwrap() < m.find("def n").unwrap(), "{m}");
        assert!(m.contains("return 4"), "{m}");
    }

    /// Two renamed symbols that changed places: the order is `t`'s, or code
    /// that needs it breaks in silence.
    #[test]
    fn two_renames_that_swapped_keep_their_order() {
        let def = |name: &str, tag: &str| {
            format!(
                "def {name}(f):\n    one = {tag}\n    two = one + 1\n    three = two + 1\n    four = three + 1\n    return four\n"
            )
        };
        let b = format!(
            "{}\n\n{}\n\ndef z():\n    return 1\n",
            def("a", "1"),
            def("b", "2")
        );
        let t = format!(
            "{}\n\n{}\n\ndef z():\n    return 1\n",
            def("y", "2"),
            def("x", "1")
        );
        let o = b.replace("return 1\n", "return 9\n");
        let f = merge_text_at(ENGINE_RENAMES, "a.py", &b, &o, &t).unwrap();
        assert!(f.find("def y").unwrap() < f.find("def x").unwrap(), "{f}");
        assert!(f.contains("return 9"), "{f}");
    }

    /// An addition behind what `o` renamed stays behind it.
    #[test]
    fn an_addition_behind_what_ours_renamed_stays_behind_it() {
        let def = |name: &str, n: u32| {
            format!("def {name}():\n    a = {n}\n    b = a + 1\n    c = b + 1\n    return c\n\n\n")
        };
        let b = format!("{}{}{}", def("base0", 0), def("base1", 1), def("base2", 2));
        let o = format!("{}{}{}", def("base0", 0), def("ro1", 1), def("base2", 2));
        let t = format!(
            "{}{}{}{}",
            def("rt0", 0),
            def("base1", 1),
            def("addt", 7),
            def("base2", 2)
        );
        let m = merge_text_at(ENGINE_RENAMES, "a.py", &b, &o, &t).unwrap();
        assert!(
            m.find("def ro1").unwrap() < m.find("def addt").unwrap(),
            "{m}"
        );
        assert!(
            m.find("def rt0").unwrap() < m.find("def ro1").unwrap(),
            "{m}"
        );
    }

    /// Each row: what one side does, against a rename on the other. Nothing
    /// passes in silence: the symbol can not be gone and alive.
    #[test]
    fn a_rename_conflicts_with_a_delete_or_another_rename() {
        let b = "def old():\n    a()\n    b()\n    c()\n\n\ndef k():\n    return 1\n";
        let rename = |to: &str| b.replace("def old", &format!("def {to}"));
        let k = |text: &str| text.replace("return 1", "return 2");
        let delete = k(&b.replace("def old():\n    a()\n    b()\n    c()\n\n\n", ""));
        let want = Err(vec!["a.py#old".to_string()]);
        for (o, t) in [(rename("new"), delete.clone()), (delete, rename("new"))] {
            assert_eq!(merge_text_at(ENGINE_RENAMES, "a.py", b, &o, &t), want);
        }
        let (o, t) = (rename("fresh"), rename("new"));
        assert_eq!(merge_text_at(ENGINE_RENAMES, "a.py", b, &o, &t), want);
        // The same rename on both sides is one change.
        let (o, t) = (rename("new"), k(&rename("new")));
        assert_eq!(
            merge_text_at(ENGINE_RENAMES, "a.py", b, &o, &t).as_deref(),
            Ok(t.as_str())
        );
    }

    /// An edit of what the other side renamed reaches no symbol.
    #[test]
    fn a_rename_conflicts_with_an_edit_of_the_symbol() {
        let b = "def old():\n    a()\n\n\ndef other():\n    b()\n";
        let o = b.replace("old", "new");
        let t = b.replace("a()", "c()");
        assert_eq!(
            merge_text_at(ENGINE_RENAMES, "a.py", b, &o, &t),
            Err(vec!["a.py#old".to_string()])
        );
    }

    #[test]
    fn a_header_and_a_method_merge_in_either_order() {
        let header = class("class A:", "class A(B):");
        let method = class("return 1", "return 10");
        let both = header.replace("return 1", "return 10");
        let merge = |engine, o, t| merge_text_at(engine, "a.py", CLASS, o, t);
        assert_eq!(merge(3, &header, &method).unwrap(), both);
        assert_eq!(merge(3, &method, &header).unwrap(), both);
        // Engines up to 2 stay as they were: frozen, and only one way round.
        assert_eq!(merge(2, &header, &method).unwrap(), both);
        assert_eq!(merge(2, &method, &header), Err(vec!["a.py#A".to_string()]));
    }

    #[test]
    fn the_same_header_on_both_sides_is_no_conflict() {
        let header = class("class A:", "class A(B):");
        let o = header.replace("return 1", "return 10");
        let t = header.replace("return 2", "return 20");
        let want = o.replace("return 2", "return 20");
        assert_eq!(merge_text_at(3, "a.py", CLASS, &o, &t).unwrap(), want);
        let c = merge_text_at(2, "a.py", CLASS, &o, &t);
        assert_eq!(c, Err(vec!["a.py#A".to_string()]));
    }

    /// The name is the one facts report, and a lease covers.
    #[test]
    fn two_headers_conflict_on_the_definition() {
        let o = class("class A:", "class A(B):").replace("return 1", "return 10");
        let t = class("class A:", "class A(C):").replace("return 2", "return 20");
        let c = merge_text_at(3, "a.py", CLASS, &o, &t);
        assert_eq!(c, Err(vec!["a.py#A.<def>".to_string()]));
    }

    /// A conflict among the members, with a header changed on one side:
    /// the definition is in `conflicts` too, since it did not come through.
    #[test]
    fn a_conflict_around_a_header_names_both() {
        let o = class("return 1", "return 10");
        let t = class("class A:", "class A(B):")
            .replace("return 1", "return 11")
            .replace("return 2", "return 20");
        let c = merge_text_at(3, "a.py", CLASS, &o, &t);
        let want = ["a.py#A.<def>", "a.py#A.a"].map(String::from);
        assert_eq!(c, Err(want.to_vec()));
        // In a sync, what can come in does, and the rest stays local.
        let kept = merge_around_conflicts(3, "a.py", CLASS, &o, &t).unwrap();
        assert_eq!(kept, o.replace("return 2", "return 20"));
        let t = class("class A:", "class A(B):").replace("return 2", "return 20");
        let o = class("class A:", "class A(C):");
        let kept = merge_around_conflicts(3, "a.py", CLASS, &o, &t).unwrap();
        assert_eq!(kept, o.replace("return 2", "return 20"));
    }

    /// Moved members can not be merged in place, on either side.
    #[test]
    fn a_move_beside_a_header_goes_to_the_line_merge() {
        let (a, b) = (
            "    def a(self):\n        return 1\n\n",
            "    def b(self):\n        return 2\n\n",
        );
        let swapped = class(&format!("{a}{b}"), &format!("{b}{a}"));
        let header = class("class A:", "class A(B):");
        let want = swapped.replace("class A:", "class A(B):");
        assert_eq!(
            merge_text_at(3, "a.py", CLASS, &swapped, &header).unwrap(),
            want
        );
        assert_eq!(
            merge_text_at(3, "a.py", CLASS, &header, &swapped).unwrap(),
            want
        );

        let t = swapped.replace("class A:", "class A(B):");
        let edited = class("return 3", "return 30");
        let want = t.replace("return 3", "return 30");
        assert_eq!(merge_text_at(3, "a.py", CLASS, &edited, &t).unwrap(), want);

        // Moved on both sides, and not the same way: the lines say conflict.
        let o = class(&format!("{a}{b}"), &format!("{b}{a}"));
        let (b2, c) = (b.trim_end(), "    def c(self):\n        return 3");
        let t = class(&format!("{b2}\n\n{c}"), &format!("{c}\n\n{b2}"));
        let t = t.replace("class A:", "class A(B):");
        let c = merge_text_at(3, "a.py", CLASS, &o, &t);
        assert_eq!(c, Err(vec!["a.py#<file>".to_string()]));
    }

    /// The place for a new member is found in the text, and text can fool
    /// it: what does not come through as a symbol goes to the line merge.
    #[test]
    fn an_addition_that_lands_in_a_string_or_a_comment_is_not_merged() {
        let b = "class A:\n    \"\"\"Use {x}.\"\"\"\n";
        let o = format!("{b}\n    def m(self):\n        return 1\n");
        let t = b.replace("class A:", "class A(B):");
        let want = o.replace("class A:", "class A(B):");
        assert_eq!(merge_text_at(3, "a.py", b, &o, &t).unwrap(), want);
        assert_eq!(merge_text_at(3, "a.py", b, &t, &o).unwrap(), want);

        let (b, o, t) = (
            "impl S {\n}\n",
            "impl S { // note\n}\n",
            "impl S { fn m() {} }\n",
        );
        let want = Err(vec!["a.rs#<file>".to_string()]);
        assert_eq!(merge_text_at(3, "a.rs", b, o, t), want);
        assert_eq!(merge_text_at(3, "a.rs", b, t, o), want);
        // Engine 2 keeps what it wrote.
        assert_eq!(
            merge_text_at(2, "a.rs", b, o, t).unwrap(),
            "impl S { // note fn m() {}\n}\n"
        );
        // In a sync, such a file stays local as a whole.
        assert_eq!(merge_around_conflicts(3, "a.rs", b, o, t), None);
        assert!(merge_around_conflicts(2, "a.rs", b, o, t).is_some());
    }

    /// An addition in conflict has no place in the middle a sync keeps.
    #[test]
    fn a_sync_keeps_going_past_an_addition_in_conflict() {
        let b = "fn a() {}\n";
        let o = "fn a() {}\n\nfn n() { o(); }\n";
        let t = "fn a() { x(); }\n\nfn n() { t(); }\n";
        let kept = merge_around_conflicts(3, "a.rs", b, o, t).unwrap();
        assert_eq!(kept, "fn a() { x(); }\n\nfn n() { o(); }\n");
        let (o, t) = (b, "fn a() { x(); }\n\nfn n() { t(); }\n");
        let kept = merge_around_conflicts(3, "a.rs", b, o, t).unwrap();
        assert_eq!(kept, t);
    }

    const GROUP: &str = "package p\n\nconst (\n\tA = 1\n\tB = 2\n)\n\nfunc F() {}\n";

    /// Two agents in one `const (...)`: every spec is its own unit, and the
    /// group's parentheses stay where they were.
    #[test]
    fn specs_of_a_go_group_merge_apart() {
        let merge = |o: &str, t: &str| merge_text_at(5, "a.go", GROUP, o, t);
        let (edit_a, edit_b) = (
            GROUP.replace("A = 1", "A = 10"),
            GROUP.replace("B = 2", "B = 20"),
        );
        let both = edit_a.replace("B = 2", "B = 20");
        assert_eq!(merge(&edit_a, &edit_b).unwrap(), both);
        assert_eq!(merge(&edit_b, &edit_a).unwrap(), both);
        let same = merge(&edit_a, &GROUP.replace("A = 1", "A = 11"));
        assert_eq!(same, Err(vec!["a.go#A".to_string()]));
        // Additions beside the same spec, and one beside an edit.
        let add = |n: &str| GROUP.replace("B = 2\n", &format!("B = 2\n\t{n} = 3\n"));
        let m = merge(&add("C"), &add("D")).unwrap();
        assert!(m.contains("\tC = 3\n") && m.contains("\tD = 3\n"), "{m}");
        assert!(!parse_at(5, Lang::Go, &m).has_error, "{m}");
        let want = add("C").replace("A = 1", "A = 10");
        assert_eq!(merge(&edit_a, &add("C")).unwrap(), want);
        // A deleted spec goes with its line.
        let gone = GROUP.replace("\tB = 2\n", "");
        assert_eq!(
            merge(&edit_a, &gone).unwrap(),
            gone.replace("A = 1", "A = 10")
        );
        // Added at the front, it stands before what it stood before.
        let front = GROUP.replace("\tA = 1", "\tZ = 0\n\tA = 1");
        let want = edit_b.replace("\tA = 1", "\tZ = 0\n\tA = 1");
        assert_eq!(merge(&edit_b, &front).unwrap(), want);
        // Engine 4 sees one symbol and refuses.
        let c = merge_text_at(4, "a.go", GROUP, &edit_a, &edit_b);
        assert_eq!(c, Err(vec!["a.go#A".to_string()]));
    }

    /// A new symbol never lands in or out of a group because of a neighbour
    /// on the other side of its edge.
    #[test]
    fn a_new_symbol_stays_on_its_side_of_a_group() {
        let merge = |o: &str, t: &str| merge_text_at(5, "a.go", GROUP, o, t);
        let edit = GROUP.replace("A = 1", "A = 10");
        // New function right after the group: not inside it.
        let t = GROUP.replace(")\n\nfunc F", ")\n\nfunc N() {}\n\nfunc F");
        assert_eq!(merge(&edit, &t).unwrap(), t.replace("A = 1", "A = 10"));
        // New function after the group at the end of the file.
        let b = "package p\n\nconst (\n\tA = 1\n)\n";
        let (o, t) = (
            b.replace("A = 1", "A = 10"),
            format!("{b}\nfunc N() {{}}\n"),
        );
        let m = merge_text_at(5, "a.go", b, &o, &t).unwrap();
        assert_eq!(m, format!("{o}\nfunc N() {{}}\n"));
        // A new spec whose neighbour is gone in `o` has nothing to stand
        // beside, and must not stand beside the function.
        let o = GROUP.replace("\tA = 1\n\tB = 2\n", "");
        let t = GROUP.replace("B = 2\n", "B = 2\n\tC = 3\n");
        assert_eq!(merge(&o, &t), Err(vec!["a.go#<file>".to_string()]));
        // `o` took it out of the group: the same.
        let o = GROUP
            .replace("\tA = 1\n\tB = 2\n", "")
            .replace("const (\n)\n", "const A = 1\n\nconst B = 2\n");
        assert_eq!(merge(&o, &t), Err(vec!["a.go#<file>".to_string()]));
        // A whole new group is new code, for the line merge.
        let t = GROUP.replace("func F", "var (\n\tv = 1\n\tw = 2\n)\n\nfunc F");
        let m = merge(&edit, &t).unwrap();
        assert_eq!(m, t.replace("A = 1", "A = 10"));
    }

    /// A list with separators: what is added or removed brings them along.
    #[test]
    fn a_list_with_separators_keeps_them() {
        let b = "class C {\n    int a, b;\n    void M() { }\n}\n";
        let merge = |o: &str, t: &str| merge_text_at(5, "a.cs", b, o, t);
        let (edit, add) = (
            b.replace("void M() { }", "void M() { X(); }"),
            b.replace("int a, b;", "int a, b, c;"),
        );
        let want = add.replace("void M() { }", "void M() { X(); }");
        assert_eq!(merge(&edit, &add).unwrap(), want);
        let front = b.replace("int a, b;", "int z, a, b;");
        let want = front.replace("void M() { }", "void M() { X(); }");
        assert_eq!(merge(&edit, &front).unwrap(), want);

        let b = "class C { int a, b, c; }\n";
        let merge = |o: &str, t: &str| merge_text_at(5, "a.cs", b, o, t);
        let (o, t) = (b.replace("a,", "a = 1,"), b.replace("a, b, c", "a, c"));
        assert_eq!(merge(&o, &t).unwrap(), "class C { int a = 1, c; }\n");
        let t = b.replace("a, b, c", "a, b");
        assert_eq!(merge(&o, &t).unwrap(), "class C { int a = 1, b; }\n");
        let t = b.replace("a, b, c", "b, c");
        let o = b.replace(", c", ", c = 3");
        assert_eq!(merge(&o, &t).unwrap(), "class C { int b, c = 3; }\n");

        // `module.exports`, added on both sides and with a trailing comma.
        let b = "module.exports = {\n  a() {},\n  b() {},\n};\n";
        let add = |n: &str| b.replace("  b() {},\n", &format!("  b() {{}},\n  {n}() {{}},\n"));
        let m = merge_text_at(5, "a.js", b, &add("c"), &add("d")).unwrap();
        assert!(!parse_at(5, Lang::JavaScript, &m).has_error, "{m}");
        assert_eq!(
            names(&parse_at(5, Lang::JavaScript, &m).syms),
            ["a", "b", "d", "c"],
            "{m}"
        );
        let t = b.replace("  a() {},\n", "");
        let o = b.replace("b() {}", "b() { x(); }");
        let m = merge_text_at(5, "a.js", b, &o, &t).unwrap();
        assert_eq!(m, "module.exports = {\n  b() { x(); },\n};\n");
        // The last one takes the separator before it.
        let b = "module.exports = { a() {}, b() {} };\n";
        let (o, t) = (
            b.replace("a() {}", "a() { x(); }"),
            "module.exports = { a() {} };\n",
        );
        let m = merge_text_at(5, "a.js", b, &o, t).unwrap();
        assert_eq!(m, "module.exports = { a() { x(); } };\n");
    }

    /// Blocks hold what they hold: a neighbour in another branch is no place
    /// for a new definition.
    #[test]
    fn a_new_definition_stays_in_its_block() {
        let b = "if A:\n    def f():\n        return 1\nelse:\n    def g():\n        return 2\n";
        let merge = |o: &str, t: &str| merge_text_at(5, "a.py", b, o, t);
        let edit = b.replace("return 1", "return 10");
        let add = b.replace(
            "else:\n    def g",
            "else:\n    def h():\n        return 3\n\n    def g",
        );
        assert_eq!(
            merge(&edit, &add).unwrap(),
            add.replace("return 1", "return 10")
        );
        let top = format!("def n():\n    return 4\n\n{b}");
        let m = merge(&edit, &top).unwrap();
        assert_eq!(m, top.replace("return 1", "return 10"));
        // An edit under `if`, with a block on each side.
        let other = b.replace("return 2", "return 20");
        let both = edit.replace("return 2", "return 20");
        assert_eq!(merge(&edit, &other).unwrap(), both);
        // A deletion that empties a block can not stay in place.
        let b = "if A:\n    def f():\n        pass\n\ndef g():\n    return 1\n";
        let o = b.replace("return 1", "return 10");
        let t = "if A:\n    pass\n\ndef g():\n    return 1\n";
        assert_eq!(
            merge_text_at(5, "a.py", b, &o, t).unwrap(),
            t.replace("return 1", "return 10")
        );
    }

    /// Up to engine 4 a new class could land in the namespace before it.
    #[test]
    fn a_new_type_stays_in_its_namespace() {
        let b = "namespace A {\n    class C { }\n}\nnamespace B {\n    class D { }\n}\n";
        let t = b.replace("namespace B {\n", "namespace B {\n    class N { }\n");
        let o = b.replace("class D { }", "class D { int x; }");
        let want = o.replace("namespace B {\n", "namespace B {\n    class N { }\n");
        assert_eq!(merge_text_at(5, "a.cs", b, &o, &t).unwrap(), want);
    }

    #[test]
    fn comments_that_stand_apart_merge_as_code() {
        let b = "// section\n\nfn a() {}\n\nfn b() {}\n";
        let (o, t) = (
            b.replace("section", "part"),
            b.replace("fn a() {}", "fn a() { x(); }"),
        );
        let want = o.replace("fn a() {}", "fn a() { x(); }");
        assert_eq!(merge_text_at(5, "a.rs", b, &o, &t).unwrap(), want);
        assert_eq!(merge_text_at(5, "a.rs", b, &t, &o).unwrap(), want);
        let c = merge_text_at(4, "a.rs", b, &o, &t);
        assert_eq!(c, Err(vec!["a.rs#a".to_string()]));
    }

    /// A decorator is the method's: a different one conflicts on the method
    /// and never on the class, and the method beside it is free.
    #[test]
    fn method_decorators_merge_with_their_method() {
        let b = "class C {\n  @A()\n  a() {}\n\n  b() {}\n}\n";
        let merge = |o: &str, t: &str| merge_text_at(5, "a.ts", b, o, t);
        let deco = b.replace("@A()", "@A(1)");
        let body = b.replace("b() {}", "b() { x(); }");
        let want = deco.replace("b() {}", "b() { x(); }");
        assert_eq!(merge(&deco, &body).unwrap(), want);
        assert_eq!(merge(&body, &deco).unwrap(), want);
        let c = merge(&deco, &b.replace("@A()", "@A(2)"));
        assert_eq!(c, Err(vec!["a.ts#C.a".to_string()]));
        let c = merge_text_at(4, "a.ts", b, &deco, &b.replace("@A()", "@A(2)"));
        assert_eq!(c, Err(vec!["a.ts#C.<def>".to_string()]));
    }

    #[test]
    fn the_parts_of_a_partial_type_conflict_as_one_definition() {
        let b = "partial class C { int a; }\npartial class C { int b; }\n";
        let merge = |o: &str, t: &str| merge_text_at(5, "a.cs", b, o, t);
        let (o, t) = (b.replace("int a", "int a1"), b.replace("int b", "int b1"));
        assert_eq!(merge(&o, &t).unwrap(), o.replace("int b", "int b1"));
        let edit = |name: &str| {
            let (a, c) = b.split_once('\n').unwrap();
            format!("{a}\n{}\n", c.replace("partial class C", name))
        };
        let c = merge(&edit("partial class C : I"), &edit("partial class C : J"));
        assert_eq!(c, Err(vec!["a.cs#C.<def>".to_string()]));
    }

    /// Between two symbols of a list can stand what is no symbol. It stays.
    #[test]
    fn a_deletion_in_a_list_takes_only_its_member() {
        let merge = |b: &str, o: &str, t: &str| merge_text_at(5, "a.js", b, o, t).unwrap();
        let b = "module.exports = {\n  a() {},\n  VERSION: 1,\n  b() {},\n};\n";
        let t = b.replace("  a() {},\n", "");
        let o = b.replace("b() {}", "b() { x(); }");
        assert_eq!(merge(b, &o, &t), t.replace("b() {}", "b() { x(); }"));
        let t = b.replace("  b() {},\n", "");
        let o = b.replace("a() {}", "a() { x(); }");
        assert_eq!(merge(b, &o, &t), t.replace("a() {}", "a() { x(); }"));
        for keep in ["helper", "...base", "'s': 1", "[k]: 2", "// section\n"] {
            let sep = if keep.ends_with('\n') { "" } else { "," };
            let b = format!("module.exports = {{\n  a() {{}},\n  {keep}{sep}\n  b() {{}},\n}};\n");
            let t = b.replace("  a() {},\n", "");
            let o = b.replace("b() {}", "b() { x(); }");
            assert_eq!(
                merge(&b, &o, &t),
                t.replace("b() {}", "b() { x(); }"),
                "{keep}"
            );
        }
        // What `o` put there is no less there.
        let b = "module.exports = {\n  a() {},\n  b() {},\n};\n";
        let o = "module.exports = {\n  a() {},\n  KEY: 2,\n  b() { x(); },\n};\n";
        let t = "module.exports = {\n  b() {},\n};\n";
        assert!(merge_text_at(5, "a.js", b, o, t).is_ok_and(|m| m.contains("KEY")));
        let b = "class C\n{\n    int a,\n\n        // section\n\n        b,\n        c;\n}\n";
        let t = b.replace("int a,\n\n        ", "int ");
        let o = b.replace("c;", "c = 3;");
        let m = merge_text_at(5, "a.cs", b, &o, &t).unwrap();
        assert!(m.contains("section"), "{m}");
    }

    #[test]
    fn a_new_member_of_a_list_copies_nothing() {
        let b = "module.exports = {\n  a,\n  b,\n  c() {},\n};\n";
        let o = b.replace("c() {}", "c() { x(); }");
        let t = b.replace("  a,\n", "  n() {},\n  a,\n");
        let m = merge_text_at(5, "a.js", b, &o, &t).unwrap();
        assert_eq!(m.matches("  a,\n").count(), 1, "{m}");
        assert_eq!(m.matches("  b,\n").count(), 1, "{m}");
        assert!(m.contains("n() {}") && m.contains("x();"), "{m}");
        // Between two keys no symbol marks its place: lines can, on lines.
        let b = "module.exports = {\n  a() {},\n  g: 1,\n  h: 2,\n  b() {},\n};\n";
        let o = b.replace("a() {}", "a() { x(); }");
        let t = b.replace("  h: 2", "  n() {},\n  h: 2");
        let want = o.replace("  h: 2", "  n() {},\n  h: 2");
        assert_eq!(merge_text_at(5, "a.js", b, &o, &t).unwrap(), want);
        let b = "module.exports = { a() {}, g: 1, h: 2, b() {} };\n";
        let o = b.replace("a() {}", "a() { x(); }");
        let t = b.replace("h: 2", "n() {}, h: 2");
        let c = Err(vec!["a.js#<file>".to_string()]);
        assert_eq!(merge_text_at(5, "a.js", b, &o, &t), c);
    }

    /// One definition, added to two different blocks, is two changes.
    #[test]
    fn the_same_definition_in_another_block_is_not_the_same_addition() {
        let b = "if A:\n    def a():\n        return 1\nelse:\n    def b():\n        return 2\n";
        let f = "\n\n    def f():\n        return 9\n";
        let o = b.replace("if A:", "if AA:").replace(
            "return 1",
            &format!("return 1{f}").replacen("\n\n", "\n\n", 1),
        );
        let t = b
            .replace("return 1", "return 10")
            .replace("return 2", &format!("return 2{f}"));
        let m = merge_text_at(5, "a.py", b, &o, &t);
        assert!(
            m.is_err() || m.as_ref().unwrap().matches("def f").count() == 2,
            "{m:?}"
        );
        // In the same block it is one addition.
        let t = b.replace("return 1", &format!("return 1{f}"));
        let o = t.replace("if A:", "if AA:");
        assert_eq!(merge_text_at(5, "a.py", b, &o, &t).unwrap(), o);
    }

    /// `f~2` is a number, and code added in front of it changes who that is.
    #[test]
    fn a_numbered_name_in_a_block_does_not_follow_the_number() {
        let b = "if A:\n    def f():\n        return 1\nelse:\n    def f():\n        return 2\n";
        let o = b.replace("else:", "elif B:\n    def f():\n        return 2\nelse:");
        let t = b.replace(
            "else:\n    def f():\n        return 2",
            "else:\n    def f():\n        return 20",
        );
        let want = o.replace(
            "else:\n    def f():\n        return 2",
            "else:\n    def f():\n        return 20",
        );
        assert_eq!(merge_text_at(5, "a.py", b, &o, &t), Ok(want));
    }

    /// A new symbol behind a block or a list stays behind it.
    #[test]
    fn a_new_symbol_does_not_jump_over_a_holder() {
        let b = "def a():\n    pass\n\nif X:\n    def deco():\n        pass\n\ndef z():\n    pass\n\nprint(1)\n";
        let o = b.replace("print(1)", "print(2)");
        let t = b.replace("def z", "@deco\ndef n():\n    pass\n\ndef z");
        let want = o.replace("def z", "@deco\ndef n():\n    pass\n\ndef z");
        assert_eq!(merge_text_at(5, "a.py", b, &o, &t).unwrap(), want);
        let b = "class C\n{\n    void L() { }\n    // keep\n    int a, b;\n    void M() { }\n}\n";
        let o = b.replace("// keep", "// kept");
        let t = b.replace("    void M", "    int c;\n    void M");
        let want = o.replace("    void M", "    int c;\n    void M");
        assert_eq!(merge_text_at(5, "a.cs", b, &o, &t).unwrap(), want);
        let b = "class C\n{\n    void L() { }\n    int a, b;\n    void M() { }\n}\n";
        let o = b.replace("int a, b", "int a = 1, b");
        let t = b.replace("    void M", "    int c;\n    void M");
        let want = o.replace("    void M", "    int c;\n    void M");
        assert_eq!(merge_text_at(5, "a.cs", b, &o, &t).unwrap(), want);
    }

    /// A comment behind code on its line is about that code.
    #[test]
    fn a_trailing_comment_stays_with_its_line() {
        let b = "package p\n\nconst (\n\tA = 1 // first\n\tB = 2 // second\n\tC = 3\n)\n";
        let o = b.replace("A = 1", "A = 10");
        let t = b.replace("\tB = 2 // second\n", "");
        let want = t.replace("A = 1", "A = 10");
        assert_eq!(merge_text_at(5, "a.go", b, &o, &t).unwrap(), want);
        let b = "package p\n\nconst (\n\tA = 1 // first\n)\n";
        let o = b.replace("// first\n", "// first\n\tB = 2\n");
        let t = b.replace("// first\n", "// first\n\tC = 3\n");
        let m = merge_text_at(5, "a.go", b, &o, &t).unwrap();
        assert_eq!(m.matches("first").count(), 1, "{m}");
    }

    /// One member in two parts of a type, with no side having both.
    #[test]
    fn a_name_no_side_has_is_no_merge() {
        let b = "partial class C\n{\n    int a;\n}\n\npartial class C\n{\n    int b;\n}\n";
        let o = b.replace("int a;", "int a;\n    int x;");
        let t = b.replace("int b;", "int b;\n    long x;");
        let c = Err(vec!["a.cs#<file>".to_string()]);
        assert_eq!(merge_text_at(5, "a.cs", b, &o, &t), c);
        assert_eq!(merge_text_at(5, "a.cs", b, &t, &o), c);
    }

    #[test]
    fn a_neighbour_in_another_kind_of_group_is_no_place() {
        let b = "package p\n\nconst (\n\tA = 1\n\tB = 2\n)\n\nvar (\n\tv = 1\n)\n";
        let o = b
            .replace("\tB = 2\n", "")
            .replace("v = 1\n", "v = 1\n\tB = 2\n");
        let t = b.replace("B = 2\n", "B = 2\n\tC = B + 1\n");
        let m = merge_text_at(5, "a.go", b, &o, &t);
        assert!(m.as_ref().is_err() || !m.unwrap().contains("var (\n\tv = 1\n\tB = 2\n\tC"));
    }

    /// Numbers in names do not switch off what the code around them says.
    #[test]
    fn a_numbered_file_still_conflicts_on_its_code() {
        let b = "try:\n    def f():\n        return 1\nexcept E:\n    def f():\n        return 2\n\nprint(1)\n\ndef g():\n    return 3\n\ndef h():\n    return 4\n";
        let o = b
            .replace("print(1)\n\n", "")
            .replace("def h", "print(1)\n\ndef h");
        let moved_on = format!("{}\nprint(1)\n", b.replace("print(1)\n\n", ""));
        let deleted = b.replace("print(1)\n\n", "");
        let c = Err(vec!["a.py#<module>".to_string()]);
        for t in [&moved_on, &deleted] {
            assert_eq!(merge_text_at(5, "a.py", b, &o, t), c, "{t}");
            assert_eq!(merge_text_at(5, "a.py", b, t, &o), c, "{t}");
        }
        // Code that only changed leaves every number as it was.
        let b = "try:\n    def f():\n        return 1\nexcept E:\n    def f():\n        return 2\n";
        let (o, t) = (
            b.replace("except E", "except F"),
            b.replace("return 1", "return 10"),
        );
        let want = o.replace("return 1", "return 10");
        assert_eq!(merge_text_at(5, "a.py", b, &o, &t).unwrap(), want);
        // The other way round the code is `t`'s, and adjacent lines refuse.
        let c = Err(vec!["a.py#<file>".to_string()]);
        assert_eq!(merge_text_at(5, "a.py", b, &t, &o), c);
    }

    /// A number can change meaning with as many of the name as before: what
    /// counts is which block each one stands in.
    #[test]
    fn a_number_is_held_to_its_block() {
        // To lines `o` only wrote a branch in front of the one `t` edited, so
        // that is how it reads: the choice is the line merge's, not a number's.
        let b = "if A:\n    def f():\n        return 1\nelse:\n    def f():\n        return 1\n";
        let o = "if A:\n    pass\nelif B:\n    def f():\n        return 1\nelse:\n    def f():\n        return 1\n";
        let t = b.replacen("return 1", "return 10", 1);
        let want = o.replacen("return 1", "return 10", 1);
        assert_eq!(merge_text_at(5, "a.py", b, o, &t).unwrap(), want);
        assert_eq!(merge_around_conflicts(5, "a.py", b, o, &t), None);
        // One moved to the other block: a new symbol beside it does not follow.
        let b = "if A:\n    def f():\n        return 1\nelse:\n    def f():\n        return 2\n";
        let o = "if A:\n    pass\nelse:\n    def f():\n        return 2\n\n    def f():\n        return 3\n";
        let t = b.replacen(
            "return 1\n",
            "return 1\n\n    def h():\n        return 9\n",
            1,
        );
        let m = merge_text_at(5, "a.py", b, o, &t);
        assert!(
            m.is_err() || m.unwrap().contains("if A:\n    pass\n\n    def h"),
            "{t}"
        );
        // Deeper than the top level, and a block that went with no count to see.
        let b = "mod q {\n    extern \"C\" {\n        fn f();\n    }\n\n    extern \"system\" {\n        fn f();\n    }\n}\n";
        let o = b.replace(
            "    extern \"system\"",
            "    extern \"cdecl\" {\n        fn f();\n    }\n\n    extern \"system\"",
        );
        let t = b.replace(
            "\"system\" {\n        fn f();",
            "\"system\" {\n        fn f(x: u8);",
        );
        let want = o.replace(
            "\"system\" {\n        fn f();",
            "\"system\" {\n        fn f(x: u8);",
        );
        assert_eq!(merge_text_at(5, "a.rs", b, &o, &t).unwrap(), want);
        assert_eq!(merge_around_conflicts(5, "a.rs", b, &o, &t), None);
        let b = "extern \"C\" {\n    fn f();\n}\n\nextern \"D\" {\n    fn f();\n}\n";
        let o = "extern \"Z\" {\n}\n\nextern \"C\" {\n    fn f();\n}\n\nextern \"D\" {\n    fn f();\n}\n";
        let t = b.replace("\"D\" {\n    fn f();", "\"D\" {\n    fn f(x: u8);");
        let m = merge_text_at(5, "a.rs", b, o, &t).unwrap();
        assert!(m.contains("\"D\" {\n    fn f(x: u8);"), "{m}");
    }

    /// The checks at the end of `holds_up`, on text no merge writes now.
    #[test]
    fn a_result_must_hold_code_of_a_side() {
        let side = |text| parse_at(5, Lang::Python, text);
        let b = "x = 1\n\nclass A:\n    y = 1\n\n    class B:\n        z = 1\n";
        let (pb, po, pt) = (
            side(b),
            side(&b.replace("y = 1", "y = 2")),
            side(&b.replace("z = 1", "z = 2")),
        );
        let held = |engine, text: &str| {
            holds_up(
                engine,
                "a.py",
                Lang::Python,
                text,
                &Naming::default(),
                [&pb, &po, &pt],
                &[],
            )
        };
        let fine = b.replace("y = 1", "y = 2").replace("z = 1", "z = 2");
        assert!(held(5, &fine));
        // Code of no side, outside every symbol, in a type and deeper.
        let outer = fine.replace("x = 1", "x = 3");
        let own = fine.replace("y = 2", "y = 3");
        let inner = fine.replace("z = 2", "z = 3");
        for third in [&outer, &own, &inner] {
            assert!(!held(5, third), "{third}");
            assert!(held(4, third), "{third}");
        }
    }

    #[test]
    fn a_third_kind_of_code_is_seen_at_any_depth() {
        let syms = |text: &str| parse_at(5, Lang::Python, text).syms;
        let b = "class A:\n    y = 1\n\n    class B:\n        z = 1\n";
        let (o, t) = (
            syms(&b.replace("y = 1", "y = 2")),
            syms(&b.replace("z = 1", "z = 2")),
        );
        let kept = |text: String| own_from_a_side(5, [&o, &t], &syms(&text));
        assert!(kept(b.replace("y = 1", "y = 2").replace("z = 1", "z = 2")));
        assert!(!kept(b.replace("y = 1", "y = 3")));
        assert!(!kept(b.replace("y = 1", "y = 2").replace("z = 1", "z = 3")));
        // A container one side has not is that side's to add.
        assert!(kept(format!("{b}\nclass N:\n    n = 1\n")));
    }

    /// A symbol that two sides moved apart is two symbols, and no side has
    /// the second.
    #[test]
    fn a_name_no_side_has_stops_a_line_merge_too() {
        let z = "fn z() {}\n\n";
        let b = format!("{z}fn a() {{}}\n\nfn b() {{}}\n\nfn c() {{}}\n\nfn d() {{}}\n");
        let o = b
            .replace(z, "")
            .replace("fn b() {}\n\n", &format!("fn b() {{}}\n\n{z}"));
        let t = format!("{}\n{}", b.replace(z, ""), z.trim_end());
        let t = format!("{t}\n");
        let m = merge_text_at(4, "a.rs", &b, &o, &t);
        assert_eq!(
            m.as_ref().map(|m| m.matches("fn z").count()),
            Ok(2),
            "{m:?}"
        );
        let c = Err(vec!["a.rs#<file>".to_string()]);
        assert_eq!(merge_text_at(5, "a.rs", &b, &o, &t), c);
    }

    /// With nothing around it, a new symbol gets a line of its own: a blank
    /// one between items, none between members.
    #[test]
    fn a_new_symbol_written_on_the_same_line_gets_its_own() {
        let (b, o) = ("fn a() {}\n", "fn a() { x(); }\n");
        let m = merge_text_at(5, "a.rs", b, o, "fn a() {}fn n() {}\n").unwrap();
        assert_eq!(m, "fn a() { x(); }\n\nfn n() {}\n");
        let b = "impl S {\n    fn a() {}\n}\n";
        let o = b.replace("fn a() {}", "fn a() { x(); }");
        let t = b.replace("fn a() {}", "fn a() {}fn n() {}");
        let m = merge_text_at(5, "a.rs", b, &o, &t).unwrap();
        assert_eq!(m, "impl S {\n    fn a() { x(); }\nfn n() {}\n}\n");
        // In front of its neighbour, the same.
        let t = b.replace("fn a() {}", "fn n() {}fn a() {}");
        let m = merge_text_at(5, "a.rs", b, &o, &t).unwrap();
        assert_eq!(m, "impl S {\n    fn n() {}\nfn a() { x(); }\n}\n");
        let (b, o) = ("fn a() {}\n", "fn a() { x(); }\n");
        let m = merge_text_at(5, "a.rs", b, o, "fn n() {}fn a() {}\n").unwrap();
        assert_eq!(m, "fn n() {}\n\nfn a() { x(); }\n");
    }

    #[test]
    fn the_same_addition_needs_the_same_place() {
        // Beside nothing that holds it: one addition.
        let b = "fn a() {}\n\nfn b() {}\n";
        let n = "\nfn n() {}\n";
        let o = format!("{}{n}", b.replace("fn a() {}", "fn a() { x(); }"));
        let t = format!("{}{n}", b.replace("fn b() {}", "fn b() { y(); }"));
        let want = o.replace("fn b() {}", "fn b() { y(); }");
        assert_eq!(merge_text_at(5, "a.rs", b, &o, &t).unwrap(), want);
        // In a block on one side and not on the other: two.
        let b = "def a():\n    return 1\n\nif A:\n    def g():\n        return 2\n";
        let o = b.replace("def a", "def f():\n    return 9\n\ndef a");
        let t = b.replace("    def g", "    def f():\n        return 9\n\n    def g");
        let c = merge_text_at(5, "a.py", b, &o, &t);
        assert!(c.is_err() || c.unwrap().matches("def f").count() == 2);
        // With a neighbour on one side only, the file up to the block decides.
        let b = "if A:\n    pass\n";
        let o = format!("{b}\n    def f():\n        return 9\n");
        let t = format!("{o}\n    def g():\n        return 1\n");
        assert_eq!(merge_text_at(5, "a.py", b, &o, &t).unwrap(), t);
    }

    /// With no neighbour to go by, two empty blocks are not one.
    #[test]
    fn the_same_definition_alone_in_two_blocks_is_two_changes() {
        let b = "def z():\n    return 1\n\nif A:\n    pass\nelse:\n    pass\n";
        let f = "    pass\n\n    def f():\n        return 9\n";
        let o = b.replacen("    pass\n", f, 1).replace("if A:", "if AA:");
        let i = b.rfind("    pass\n").unwrap();
        let t = format!("{}{f}", &b[..i]).replace("return 1", "return 10");
        let m = merge_text_at(5, "a.py", b, &o, &t);
        assert!(
            m.is_err() || m.as_ref().unwrap().matches("def f").count() == 2,
            "{m:?}"
        );
        // The same addition in the same empty block is one addition.
        let t = format!("{}{f}", &b[..i]);
        let m = merge_text_at(5, "a.py", b, &t, &t.clone());
        assert_eq!(m.unwrap(), t);
        let b = "package p\n\nfunc Z() {}\n\nconst (\n)\n\nvar (\n)\n";
        let o = b
            .replace("const (\n", "const (\n\tX = 1\n")
            .replace("Z() {}", "Z() { a() }");
        let t = b
            .replace("var (\n", "var (\n\tX = 1\n")
            .replace("package p", "package q");
        let m = merge_text_at(5, "a.go", b, &o, &t);
        assert!(
            m.is_err() || m.as_ref().unwrap().matches("X = 1").count() == 2,
            "{m:?}"
        );
    }

    /// Where a comment behind code starts is layout, as `gofmt` moves it.
    #[test]
    fn the_space_in_front_of_a_trailing_comment_is_layout() {
        let b = "package p\n\nconst (\n\tA = 1  // a\n\tB = 20 // b\n)\n";
        let o = "package p\n\nconst (\n\tA = 1   // a\n\tB = 20  // b\n\tC = 300 // c\n)\n";
        let t = b.replace("A = 1 ", "A = 10");
        let m = merge_text_at(5, "a.go", b, o, &t).unwrap();
        assert!(m.contains("A = 10") && m.contains("C = 300 // c"), "{m}");
        let m = merge_text_at(5, "a.go", b, &t, o).unwrap();
        assert!(m.contains("A = 10") && m.contains("C = 300 // c"), "{m}");
    }

    /// In a list, order against what is no symbol can matter.
    #[test]
    fn a_new_member_does_not_jump_over_what_is_no_symbol() {
        let b = "module.exports = {\n  ...base,\n  v: 1,\n  c() {},\n};\n";
        let o = b.replace("v: 1", "v: 2");
        let t = b.replace("  ...base", "  n() {},\n  ...base");
        let want = o.replace("  ...base", "  n() {},\n  ...base");
        assert_eq!(merge_text_at(5, "a.js", b, &o, &t).unwrap(), want);
        assert_eq!(merge_text_at(5, "a.js", b, &t, &o).unwrap(), want);
    }

    const MODULE: &str = "a = 1\n\ndef f():\n    return 1\n\nprint(a)\n\ndef g():\n    return 2\n\ndef h():\n    return 3\n\ndef i():\n    return 4\n\ndef j():\n    return 5\n";

    fn moved_print() -> String {
        let t = MODULE.replace(
            "def f():\n    return 1\n\nprint(a)\n",
            "print(a)\n\ndef f():\n    return 1\n",
        );
        assert_ne!(t, MODULE);
        t
    }

    /// A statement moved past a symbol, with an edit beside it: the move
    /// comes through or the merge says so. It is never dropped.
    #[test]
    fn code_that_changed_places_is_not_dropped() {
        let t = moved_print().replace("return 2", "return 20");
        let o = MODULE.replace("return 5", "return 50");
        let want = t.replace("return 5", "return 50");
        assert_eq!(merge_text_at(4, "a.py", MODULE, &o, &t).unwrap(), want);
        // Engine 3 keeps what it wrote.
        let lost = MODULE
            .replace("return 2", "return 20")
            .replace("return 5", "return 50");
        assert_eq!(merge_text_at(3, "a.py", MODULE, &o, &t).unwrap(), lost);

        let (a, b) = (
            "    x = g()\n\n    def m(self):\n        return y\n\n",
            "    def m(self):\n        return y\n\n    x = g()\n\n",
        );
        let base = format!("class A:\n{a}    def n(self):\n        return 1\n");
        let t = base.replace(a, b).replace("return 1", "return 5");
        let o = base.replace("return y", "return z");
        let want = t.replace("return y", "return z");
        assert_eq!(merge_text_at(4, "a.py", &base, &o, &t).unwrap(), want);
        let lost = o.replace("return 1", "return 5");
        assert_eq!(merge_text_at(3, "a.py", &base, &o, &t).unwrap(), lost);
    }

    /// `o` moved the code and `t` took the container: it must not be lost
    /// with the layout of `o`.
    #[test]
    fn code_that_changed_places_beside_a_header_is_not_dropped() {
        let (a, b) = (
            "    x = g()\n\n    def m(self):\n        return y\n\n",
            "    def m(self):\n        return y\n\n    x = g()\n\n",
        );
        let tail = "    def n(self):\n        return 1\n\n    def p(self):\n        return 2\n\n    def q(self):\n        return 3\n";
        let base = format!("class A:\n    w = 1\n\n    v = 2\n\n{a}{tail}");
        let o = base.replace(a, b).replace("return 3", "return 30");
        let t = base.replace("class A:", "class A(B):");
        let want = Err(vec!["a.py#A.<def>".to_string()]);
        assert_eq!(merge_text_at(4, "a.py", &base, &o, &t), want);
        assert_eq!(merge_text_at(4, "a.py", &base, &t, &o), want);
    }

    /// A move is a change of that code: with any other change of it on the
    /// other side, the lines would bring back a deletion or write it twice.
    #[test]
    fn code_changed_on_one_side_and_moved_on_the_other_conflicts() {
        let module = Err(vec!["a.py#<module>".to_string()]);
        let t = moved_print().replace("return 2", "return 20");
        let deleted = MODULE.replace("print(a)\n\n", "");
        assert_eq!(merge_text_at(4, "a.py", MODULE, &deleted, &t), module);
        assert_eq!(merge_text_at(4, "a.py", MODULE, &t, &deleted), module);
        let last = MODULE.replace("print(a)\n\n", "") + "\nprint(a)\n";
        let m = merge_text_at(4, "a.py", MODULE, &moved_print(), &last);
        assert_eq!(m, module);
        // The same move on both sides is no conflict.
        let m = merge_text_at(4, "a.py", MODULE, &moved_print(), &t);
        assert_eq!(m.unwrap(), t);
    }

    #[test]
    fn a_line_merge_keeps_a_symbol_deleted() {
        // `t` moved `b`, `o` deleted it: both take its old lines away.
        let fb = "def b():\n    return 2\n\n";
        let fc = "def c():\n    x = 1\n    y = 2\n    z = 3\n    return x\n\n";
        let (fa, fd) = ("def a():\n    return 1\n\n", "def d():\n    return 4\n");
        let b = format!("{fa}{fb}{fc}{fd}");
        let t = format!("{fa}{fc}{fb}{fd}");
        let o = format!("{fa}{fc}{fd}");
        let want = Err(vec!["a.py#<file>".to_string()]);
        assert_eq!(merge_text_at(4, "a.py", &b, &o, &t), want);
        assert_eq!(merge_text_at(3, "a.py", &b, &o, &t).unwrap(), t);
    }

    /// A repeated import, a renamed symbol: the anchors are gone or the
    /// same, and the code must still stand where the side put it.
    #[test]
    fn code_keeps_its_place_with_no_anchor_to_say_so() {
        let b = "import os\nx = 1\nimport os\n\ndef f():\n    return 1\n\ndef g():\n    return 2\n\ndef h():\n    return 3\n";
        let t = "import os\nimport os\nx = 1\n\ndef f():\n    return 10\n\ndef g():\n    return 2\n\ndef h():\n    return 3\n";
        let o = b.replace("return 3", "return 30");
        let want = t.replace("return 3", "return 30");
        assert_eq!(merge_text_at(4, "a.py", b, &o, t).unwrap(), want);

        let b = "def a():\n    return 1\n\ndef f():\n    return 2\n\nsetup()\n\ndef k():\n    return 3\n\ndef l():\n    return 4\n";
        let t = "def a():\n    return 1\n\nsetup()\n\ndef g():\n    return 2\n\ndef k():\n    return 3\n\ndef l():\n    return 4\n";
        let o = b.replace("return 4", "return 40");
        let want = t.replace("return 4", "return 40");
        assert_eq!(merge_text_at(4, "a.py", b, &o, t).unwrap(), want);
    }

    /// A new symbol goes on the side of the code it stood beside.
    #[test]
    fn an_addition_stays_behind_the_code_it_needs() {
        let b = "def a():\n    return 1\n\napp = Flask()\n\ndef k():\n    return 3\n";
        let route = "@app.route('/')\ndef r():\n    return 2\n";
        let t = b.replace("app = Flask()\n", &format!("app = Flask()\n\n{route}"));
        let o = b.replace("return 1", "return 10");
        let want = t.replace("return 1", "return 10");
        assert_eq!(merge_text_at(4, "a.py", b, &o, &t).unwrap(), want);
        let m = merge_text_at(3, "a.py", b, &o, &t).unwrap();
        assert!(
            m.find("@app").unwrap() < m.find("app = Flask").unwrap(),
            "{m}"
        );

        // With code on both sides and no symbol after it, the end of the file.
        let t = b.replace(
            "def k():\n    return 3\n",
            "def k():\n    return 3\n\nmain()\n\ndef z():\n    return 9\n",
        );
        let want = t.replace("return 1", "return 10");
        assert_eq!(merge_text_at(4, "a.py", b, &o, &t).unwrap(), want);
    }

    /// Two different headers are a conflict on the definition, not a move:
    /// a sync still brings in the members.
    #[test]
    fn a_sync_brings_in_the_members_around_two_headers() {
        let o = class("class A:", "class A(B):");
        let t = class("class A:", "class A(C):").replace("return 2", "return 20");
        let kept = merge_around_conflicts(4, "a.py", CLASS, &o, &t).unwrap();
        assert_eq!(kept, o.replace("return 2", "return 20"));
    }

    /// The same own text on both sides is compared with `o`, so an edit on
    /// each side stays a merge by symbols: their lines touch.
    #[test]
    fn code_in_place_on_both_sides_stays_a_symbol_merge() {
        let b = "class A:\n    def a(self): return 1\n    def b(self): return 2\n";
        let o = b
            .replace("class A:", "class A(B):")
            .replace("return 1", "return 10");
        let t = b
            .replace("class A:", "class A(B):")
            .replace("return 2", "return 20");
        let want = o.replace("return 2", "return 20");
        assert_eq!(merge_text_at(4, "a.py", b, &o, &t).unwrap(), want);

        let b = "x = 1\ndef a(): return 1\ndef b(): return 2\n";
        let o = b.replace("x = 1", "x = 2").replace("return 1", "return 10");
        let t = b.replace("x = 1", "x = 2").replace("return 2", "return 20");
        let want = o.replace("return 2", "return 20");
        assert_eq!(merge_text_at(4, "a.py", b, &o, &t).unwrap(), want);
    }

    /// Symbols added or taken out around code move nothing.
    #[test]
    fn a_symbol_added_beside_code_stays_a_symbol_merge() {
        let b = "x = 1\ndef a(): return 1\ny = 2\ndef b(): return 2\n";
        let o = b.replace("def b(): return 2", "def n(): return 0\ndef b(): return 2");
        let t = b.replace("return 1", "return 10");
        let want = o.replace("return 1", "return 10");
        assert_eq!(merge_text_at(4, "a.py", b, &o, &t).unwrap(), want);
        let other_way = merge_text_at(4, "a.py", b, &t, &o).unwrap();
        assert!(other_way.contains("def n(): return 0\n"), "{other_way}");
        assert!(other_way.contains("return 10"), "{other_way}");
    }

    #[test]
    fn a_sync_leaves_a_file_alone_when_code_changed_places() {
        let t = moved_print().replace("return 2", "return 20");
        let o = MODULE.replace("return 2", "return 21");
        assert_eq!(merge_around_conflicts(4, "a.py", MODULE, &o, &t), None);
        assert!(merge_around_conflicts(3, "a.py", MODULE, &o, &t).is_some());
    }

    /// An `impl` header is the type's definition, and merges like a class's.
    #[test]
    fn an_impl_header_merges_with_its_methods() {
        let b = "struct S;\n\nimpl S {\n    fn a() {}\n\n    fn b() {}\n}\n";
        let t = b.replace("impl S {", "#[cfg(unix)]\nimpl S {");
        let o = b.replace("fn a() {}", "fn a() { x(); }");
        let want = t.replace("fn a() {}", "fn a() { x(); }");
        assert_eq!(merge_text_at(3, "a.rs", b, &o, &t).unwrap(), want);
        assert_eq!(merge_text_at(3, "a.rs", b, &t, &o).unwrap(), want);
        let o = o.replace("impl S {", "#[cfg(windows)]\nimpl S {");
        assert_eq!(
            merge_text_at(3, "a.rs", b, &o, &t),
            Err(vec!["a.rs#S.<def>".to_string()])
        );
        // A struct is a leaf: both sides changing it conflict on the unit.
        let b = "struct S {\n    a: u8,\n}\n";
        let o = "struct S {\n    a: u16,\n}\n";
        let t = "struct S {\n    a: u32,\n}\n";
        let want = |n: &str| Err(vec![format!("a.rs#{n}")]);
        assert_eq!(merge_text_at(3, "a.rs", b, o, t), want("S.<def>"));
        assert_eq!(merge_text_at(2, "a.rs", b, o, t), want("S"));
    }

    #[test]
    fn engine_1_merges_by_sections_and_engine_0_by_lines() {
        let b = "# A\nx\n# B\ny\n";
        let o = "# A\nX\n# B\ny\n";
        let t = "# A\nY\n# B\ny\n";
        assert_eq!(
            merge_text_at(1, "n.md", b, o, t),
            Err(vec!["n.md#A".into()])
        );
        assert_eq!(
            merge_text_at(0, "n.md", b, o, t),
            Err(vec!["n.md#<file>".into()])
        );
        let t = "# A\nx\n# B\nY\n";
        assert_eq!(
            merge_text_at(1, "n.md", b, o, t).unwrap(),
            "# A\nX\n# B\nY\n"
        );
    }

    #[test]
    fn a_file_without_sections_keeps_the_line_merge() {
        let b = "a\nb\nc\nd\ne\n";
        let m = merge_text_at(1, "n.md", b, "A\nb\nc\nd\ne\n", "a\nb\nc\nd\nE\n");
        assert_eq!(m.unwrap(), "A\nb\nc\nd\nE\n");
        assert_eq!(
            merge_text_at(1, "n.md", b, "X\nb\nc\nd\ne\n", "Y\nb\nc\nd\ne\n"),
            Err(vec!["n.md#<file>".into()])
        );
    }

    /// Sections can each be right and the file wrong: a dotted key and a
    /// table of the same name.
    #[test]
    fn a_merged_file_that_no_longer_parses_is_a_conflict() {
        let b = "a = 1\nb = 2\n";
        let o = "a = 1\nb = 2\n[x]\nz = 2\n";
        let t = "a = 1\nb = 2\nx.y = 1\n";
        assert_eq!(
            merge_text_at(1, "c.toml", b, o, t),
            Err(vec!["c.toml#<file>".into()])
        );
    }

    const RS: &str =
        "use std::io;\n\nfn a() {\n    1\n}\nfn b() {\n    2\n}\n\nfn c() {\n    3\n}\n";

    #[test]
    fn adjacent_functions_merge_where_lines_conflict() {
        let b = "fn a() -> u8 { 1 }\nfn b() -> u8 { 2 }\n";
        let o = b.replace("{ 1 }", "{ 10 }");
        let t = b.replace("{ 2 }", "{ 20 }");
        assert!(
            diffy::merge(b, &o, &t).is_err(),
            "line merge conflicts on adjacent lines"
        );
        let m = merge_text("x.rs", b, &o, &t).unwrap();
        assert_eq!(m, "fn a() -> u8 { 10 }\nfn b() -> u8 { 20 }\n");
    }

    #[test]
    fn same_symbol_conflicts() {
        let o = RS.replace("    1\n", "    10\n");
        let t = RS.replace("    1\n", "    11\n");
        assert_eq!(merge_text("x.rs", RS, &o, &t), Err(vec!["x.rs#a".into()]));
        assert_eq!(
            merge_text("x.rs", RS, &o, &o),
            Ok(o.clone()),
            "identical changes merge"
        );
    }

    #[test]
    fn concurrent_appends_keep_both_in_deterministic_order() {
        let o = format!("{RS}\nfn ours() {{}}\n");
        let t = format!("{RS}\nfn theirs() {{}}\n");
        let m = merge_text("x.rs", RS, &o, &t).unwrap();
        let (i, j) = (m.find("fn theirs").unwrap(), m.find("fn ours").unwrap());
        assert!(i < j, "theirs is placed after its anchor, before ours: {m}");
        assert_eq!(merge_text("x.rs", RS, &o, &t), Ok(m));
    }

    #[test]
    fn deletes_apply_or_conflict() {
        let t = RS.replace("fn b() {\n    2\n}\n", "");
        let m = merge_text("x.rs", RS, RS, &t).unwrap();
        assert!(!m.contains("fn b"));
        let o = RS.replace("    2\n", "    22\n");
        assert_eq!(merge_text("x.rs", RS, &o, &t), Err(vec!["x.rs#b".into()]));
        let o2 = RS.replace("    3\n", "    33\n");
        let m = merge_text("x.rs", RS, &o2, &t).unwrap();
        assert!(!m.contains("fn b") && m.contains("33"));
    }

    #[test]
    fn imports_union() {
        let o = RS.replace("use std::io;\n", "use std::io;\nuse std::fmt;\n");
        let t = RS.replace("use std::io;\n", "use std::io;\nuse std::fs;\n");
        let m = merge_text("x.rs", RS, &o, &t).unwrap();
        assert!(
            m.contains("use std::fmt;") && m.contains("use std::fs;"),
            "{m}"
        );
        let both = merge_text("x.rs", RS, &o, &o.clone()).unwrap();
        assert_eq!(both.matches("use std::fmt;").count(), 1);
    }

    #[test]
    fn python_methods_added_to_same_class() {
        let b = "class C:\n    def a(self):\n        return 1\n";
        let o = "class C:\n    def a(self):\n        return 1\n\n    def ours(self):\n        return 2\n";
        let t = "class C:\n    def a(self):\n        return 1\n\n    def theirs(self):\n        return 3\n";
        let m = merge_text("x.py", b, o, t).unwrap();
        assert!(m.contains("def ours") && m.contains("def theirs"), "{m}");
        assert!(!parse(Lang::Python, &m).has_error);
    }

    #[test]
    fn csharp_and_typescript_members() {
        let b = "namespace N\n{\n    class C\n    {\n        int A() { return 1; }\n        int B() { return 2; }\n    }\n}\n";
        let o = b.replace("return 1;", "return 10;");
        let t = b.replace("return 2;", "return 20;");
        let m = merge_text("x.cs", b, &o, &t).unwrap();
        assert!(m.contains("return 10;") && m.contains("return 20;"));

        let b = "export class C {\n  a() { return 1; }\n  b() { return 2; }\n}\n";
        let o = b.replace("return 1;", "return 10;");
        let t = b.replace(
            "  b() { return 2; }\n",
            "  b() { return 2; }\n  c() { return 3; }\n",
        );
        let m = merge_text("x.ts", b, &o, &t).unwrap();
        assert!(
            m.contains("return 10;") && m.contains("c() { return 3; }"),
            "{m}"
        );
    }

    #[test]
    fn unsupported_files_use_line_merge() {
        let b = "a\nb\nc\nd\ne\n";
        let o = "A\nb\nc\nd\ne\n";
        let t = "a\nb\nc\nd\nE\n";
        assert_eq!(
            merge_text("notes.txt", b, o, t),
            Ok("A\nb\nc\nd\nE\n".into())
        );
        assert_eq!(
            merge_text("notes.txt", b, "X\nb\nc\nd\ne\n", "Y\nb\nc\nd\ne\n"),
            Err(vec!["notes.txt#<file>".into()])
        );
    }

    #[test]
    fn module_level_change_on_one_side_falls_back_to_lines() {
        let t = RS.replace("fn c() {", "static X: u8 = 1;\n\nfn c() {");
        let o = RS.replace("    1\n", "    10\n");
        let m = merge_text("x.rs", RS, &o, &t).unwrap();
        assert!(m.contains("static X") && m.contains("    10\n"));
    }

    /// The file parts a symbol merge can not place on its own.
    const ORDER: &str = "use a;\nuse b;\n\nfn x() -> u8 {\n    1\n}\n\n\n\nfn y() -> u8 {\n    2\n}\n\n\n\nfn z() -> u8 {\n    3\n}\n";

    #[test]
    fn from_engine_2_a_move_goes_through_the_line_merge() {
        let f = |n: &str, v: u8| format!("fn {n}() -> u8 {{\n    {v}\n}}\n");
        let parts = [f("v", 1), f("w", 2), f("x", 3), f("y", 4), f("z", 5)];
        let base = parts.join("\n\n\n");
        let moved = [&parts[1], &parts[2], &parts[3], &parts[4], &parts[0]]
            .map(String::as_str)
            .join("\n\n\n");
        let ours = base.replace("    3\n", "    30\n");
        let m = merge_text_at(2, "x.rs", &base, &ours, &moved).unwrap();
        assert!(m.find("fn z").unwrap() < m.find("fn v").unwrap(), "{m}");
        assert!(m.contains("    30\n"), "{m}");
        let m = merge_text_at(1, "x.rs", &base, &ours, &moved).unwrap();
        assert!(
            m.find("fn v").unwrap() < m.find("fn z").unwrap(),
            "engine 1 stays as it was: {m}"
        );
    }

    /// The move is in `theirs` next to an edit that merges in place, so the
    /// symbol merge has something to apply and only the move can send the
    /// file to the line merge.
    #[test]
    fn from_engine_2_a_move_next_to_an_edit_is_not_lost() {
        let f = |n: &str, v: u8| format!("fn {n}() -> u8 {{\n    {v}\n}}\n");
        let parts = [f("v", 1), f("w", 2), f("x", 3), f("y", 4), f("z", 5)];
        let base = parts.join("\n\n\n");
        let moved = [&parts[1], &parts[2], &parts[3], &parts[4], &parts[0]]
            .map(String::as_str)
            .join("\n\n\n")
            .replace("    2\n", "    20\n");
        let ours = base.replace("    4\n", "    40\n");
        let m = merge_text_at(2, "x.rs", &base, &ours, &moved).unwrap();
        assert!(m.find("fn z").unwrap() < m.find("fn v").unwrap(), "{m}");
        assert!(m.contains("    20\n") && m.contains("    40\n"), "{m}");
    }

    /// Only three containers merge member by member: a side where the
    /// symbol is a leaf makes it one conflict, named by the symbol.
    #[test]
    fn a_symbol_that_is_a_container_on_only_some_sides_conflicts_whole() {
        let b = "mod m {\n    fn a() {}\n}\n";
        let t = "mod m {\n    fn a() -> u8 { 1 }\n}\n";
        assert_eq!(
            merge_text_at(2, "x.rs", b, "mod m;\n", t),
            Err(vec!["x.rs#m".into()])
        );
    }

    #[test]
    fn from_engine_2_a_move_inside_a_container_counts_too() {
        let b = "impl C {\n    fn a() {}\n\n\n\n    fn b() {}\n\n\n\n    fn c() {}\n}\n";
        let t = "impl C {\n    fn b() {}\n\n\n\n    fn a() {}\n\n\n\n    fn c() {}\n}\n";
        let o = b.replace("fn c() {}", "fn c() -> u8 { 1 }");
        let m = merge_text_at(2, "x.rs", b, &o, t).unwrap();
        assert!(m.find("fn b").unwrap() < m.find("fn a").unwrap(), "{m}");
        assert!(m.contains("fn c() -> u8"), "{m}");
    }

    #[test]
    fn from_engine_2_imports_keep_their_order() {
        let t = ORDER.replace("use a;\nuse b;\n", "use b;\nuse a;\n");
        let o = ORDER.replace("    3\n", "    30\n");
        let m = merge_text_at(2, "x.rs", ORDER, &o, &t).unwrap();
        assert!(
            m.starts_with("use b;\nuse a;\n") && m.contains("    30\n"),
            "{m}"
        );
        let m = merge_text_at(1, "x.rs", ORDER, &o, &t).unwrap();
        assert!(
            m.starts_with("use a;\nuse b;\n"),
            "engine 1 stays as it was: {m}"
        );
    }

    #[test]
    fn from_engine_2_a_change_only_of_layout_is_not_dropped() {
        let t = ORDER.replace("}\n\n\n\nfn y", "}\n\n\n\n\nfn y");
        let o = ORDER.replace("    3\n", "    30\n");
        let m = merge_text_at(2, "x.rs", ORDER, &o, &t).unwrap();
        assert_eq!(m, t.replace("    3\n", "    30\n"));
        assert_eq!(
            merge_text_at(1, "x.rs", ORDER, &o, &t).unwrap(),
            o,
            "engine 1 drops it"
        );
    }

    #[test]
    fn from_engine_2_a_python_block_change_is_merged_or_a_conflict() {
        let b = "X = 1\nif X:\n    a = 1\n    b = 2\n\n\n\ndef f():\n    return 1\n";
        let t = b.replace("    b = 2", "b = 2");
        let o = b.replace("return 1", "return 2");
        assert_eq!(
            merge_text_at(2, "x.py", b, &o, &t).unwrap(),
            t.replace("return 1", "return 2")
        );
        assert_eq!(
            merge_text_at(1, "x.py", b, &o, &t).unwrap(),
            o,
            "engine 1 drops it"
        );
        let both = b.replace("    b = 2", "    b = 3");
        assert_eq!(
            merge_text_at(2, "x.py", b, &both, &t),
            Err(vec!["x.py#<module>".into()]),
            "both sides changed code outside symbols"
        );
    }

    #[test]
    fn around_a_conflict_the_rest_of_the_file_comes_through() {
        let cases = [
            (
                "x.rs",
                "fn a() -> u8 {\n    1\n}\n\nfn b() -> u8 {\n    2\n}\n",
            ),
            ("x.py", "def a():\n    return 1\n\ndef b():\n    return 2\n"),
            (
                "x.ts",
                "function a() {\n  return 1;\n}\n\nfunction b() {\n  return 2;\n}\n",
            ),
            (
                "x.cs",
                "class C\n{\n    int a() { return 1; }\n    int b() { return 2; }\n}\n",
            ),
            (
                "x.go",
                "package p\n\nfunc a() int {\n\treturn 1\n}\n\nfunc b() int {\n\treturn 2\n}\n",
            ),
        ];
        for (path, b) in cases {
            let edit = |from: &str, to: &str| b.replacen(from, to, 1);
            let mine = edit("1", "10");
            let trunk = edit("1", "11").replacen('2', "22", 1);
            assert!(merge_text_at(2, path, b, &mine, &trunk).is_err(), "{path}");
            let kept = merge_around_conflicts(2, path, b, &mine, &trunk).unwrap();
            assert!(kept.contains("22"), "trunk's other change: {kept}");
            assert!(
                kept.contains("10") && !kept.contains("11"),
                "my symbol: {kept}"
            );
        }
    }

    #[test]
    fn around_a_conflict_nothing_is_guessed() {
        let (b, o) = (
            "X = 1\n\ndef a():\n    return 1\n",
            "X = 1\n\ndef a():\n    return 2\n",
        );
        // Trunk changed code outside symbols.
        let t = "X = 2\n\ndef a():\n    return 3\n";
        assert_eq!(merge_around_conflicts(2, "x.py", b, o, t), None);
        // No symbol merge: unknown language, or a side that does not parse.
        assert_eq!(merge_around_conflicts(2, "x.txt", b, o, o), None);
        for (b2, o2, t2) in [("def (", o, o), (b, "def (", o), (b, o, "def (")] {
            assert_eq!(merge_around_conflicts(2, "x.py", b2, o2, t2), None);
        }
        // Trunk moved something.
        let (b, o) = (
            "def a():\n    pass\n\ndef b():\n    pass\n",
            "def a():\n    return 1\n\ndef b():\n    pass\n",
        );
        let t = "def b():\n    pass\n\ndef a():\n    pass\n";
        assert_eq!(merge_around_conflicts(2, "x.py", b, o, t), None);
    }

    #[test]
    fn around_a_conflict_new_members_still_come_in() {
        let b = "class C {\n    int a;\n}\n";
        let o = "class C {\n    long a;\n}\n";
        let t = "class C {\n    short a;\n    int b;\n}\n";
        let kept = merge_around_conflicts(2, "x.cs", b, o, t).unwrap();
        assert!(kept.contains("long a") && kept.contains("int b"), "{kept}");
    }

    #[test]
    fn twenty_agents_one_file() {
        let mut base = String::new();
        for i in 0..20 {
            base.push_str(&format!(
                "pub fn f{i}(x: u64) -> u64 {{\n    x + {i}\n}}\n\n"
            ));
        }
        let mut trunk = base.clone();
        for i in 0..20 {
            let theirs = format!(
                "{}pub fn new{i}() -> u64 {{\n    {i}\n}}\n",
                base.replace(&format!("    x + {i}\n"), &format!("    x * {i}\n"))
            );
            trunk = merge_text("lib.rs", &base, &trunk, &theirs)
                .unwrap_or_else(|c| panic!("agent {i}: {c:?}"));
        }
        let p = parse(Lang::Rust, &trunk);
        assert!(!p.has_error);
        for i in 0..20 {
            assert!(
                trunk.contains(&format!("    x * {i}\n")),
                "edit {i} survived"
            );
            assert!(
                trunk.contains(&format!("pub fn new{i}()")),
                "add {i} survived"
            );
        }
        assert_eq!(p.syms.len(), 40);
    }
}
