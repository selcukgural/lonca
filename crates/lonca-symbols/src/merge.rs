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

use crate::engine::{ENGINE_DEFS, ENGINE_EXACT, ENGINE_PLACES, ENGINE_SECTIONS};
use crate::extract::{Parsed, Placed, Sym, moved, normalize, parse, shifted};

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
        let [pb, po, pt] = [b, o, t].map(|text| parse(lang, text));
        // A side that does not parse has no symbols to hold the merge to,
        // and engines before this check only asked that the result parses.
        let unread = pb.has_error || po.has_error || pt.has_error;
        let engine = if unread || engine < ENGINE_PLACES {
            0
        } else {
            engine
        };
        if !holds_up(engine, path, lang, &merged, [&pb, &po, &pt], &[]) {
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
    let (pb, po, pt) = (parse(lang, b), parse(lang, o), parse(lang, t));
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
    m.apply()
        .filter(|text| holds_up(engine, path, lang, text, sides, &conflicts))
}

fn all_names<'s>(syms: &'s [Sym], out: &mut BTreeSet<&'s str>) {
    for s in syms {
        out.insert(&s.name);
        all_names(&s.children, out);
    }
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
    [pb, po, pt]: [&Parsed; 3],
    conflicts: &[String],
) -> bool {
    let merged = parse(lang, text);
    if merged.has_error {
        return false;
    }
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
    gone.into_iter()
        .all(|n| !there.contains(n) || in_conflict(n))
        && places_kept(engine, code, outer_code(engine, &merged))
        && members_kept(engine, [&pb.syms, &po.syms, &pt.syms], &merged.syms)
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
        for (i, ts_sym) in ts.iter().enumerate() {
            let name = ts_sym.name.as_str();
            let t_text = ts_sym.text(self.t);
            match bm.get(name) {
                None => {
                    if let Some(o_sym) = om.get(name) {
                        if o_sym.text(self.o) != t_text {
                            self.conflict(name);
                        }
                        continue;
                    }
                    let sep_before = match ws_before(self.t, ts_sym.start) {
                        "" if top => "\n\n",
                        "" => "\n",
                        ws => ws,
                    }
                    .to_string();
                    let prev = ts[..i].iter().rev().find_map(|s| om.get(s.name.as_str()));
                    let next = ts[i + 1..].iter().find_map(|s| om.get(s.name.as_str()));
                    let after_code = self.engine >= ENGINE_PLACES && i > 0 && {
                        let gap = &self.t[ts[i - 1].end..ts_sym.start];
                        !gap.trim_matches([' ', '\t', '\n', '\r', ';', ','])
                            .is_empty()
                    };
                    if let (Some(p), false) = (prev, after_code) {
                        self.insert(p.end, format!("{sep_before}{t_text}"));
                    } else if let Some(n) = next {
                        let sep_after = match ws_after(self.t, ts_sym.end) {
                            "" if top => "\n\n",
                            "" => "\n",
                            ws => ws,
                        };
                        self.insert(n.start, format!("{t_text}{sep_after}"));
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
                    if b_sym.text(self.b) == t_text {
                        continue;
                    }
                    let Some(o_sym) = om.get(name) else {
                        self.conflict(name);
                        continue;
                    };
                    let o_text = o_sym.text(self.o);
                    if o_text == t_text {
                        continue;
                    }
                    if o_text == b_sym.text(self.b) {
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
            if tm.contains_key(b_sym.name.as_str()) {
                continue;
            }
            if let Some(o_sym) = om.get(b_sym.name.as_str()) {
                if o_sym.text(self.o) == b_sym.text(self.b) {
                    let start = o_sym.start - ws_before(self.o, o_sym.start).len();
                    self.replace(start, o_sym.end, String::new());
                } else {
                    self.conflict(&b_sym.name);
                }
            }
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
    let (pb, po, pt) = (parse(lang, b), parse(lang, o), parse(lang, t));
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
        Some(text) if holds_up(engine, path, lang, &text, [&pb, &po, &pt], &[]) => Sm::Merged(text),
        _ => Sm::Fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLASS: &str = "class A:\n    x = 1\n\n    def a(self):\n        return 1\n\n    def b(self):\n        return 2\n\n    def c(self):\n        return 3\n";

    fn class(from: &str, to: &str) -> String {
        assert_eq!(CLASS.matches(from).count(), 1, "{from}");
        CLASS.replace(from, to)
    }

    /// Which side changes the header and which a method does not matter
    /// any more: the queue decides that, not the agents.
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
