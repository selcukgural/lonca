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

use crate::extract::{Parsed, Sym, normalize, parse};
use crate::lang::Lang;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeResult {
    pub files: FileMap,
    /// Conflicting symbols (`path#name`) or files (`path#<file>`).
    pub conflicts: Vec<String>,
}

pub fn merge3(
    base: &FileMap,
    ours: &FileMap,
    theirs: &FileMap,
    read: &dyn Fn(&GitId) -> Result<Vec<u8>>,
    write: &dyn Fn(&[u8]) -> Result<GitId>,
) -> Result<MergeResult> {
    let mut files = FileMap::new();
    let mut conflicts = Vec::new();
    let paths: BTreeSet<&String> = base.keys().chain(ours.keys()).chain(theirs.keys()).collect();
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
                    let texts = (std::str::from_utf8(&base_text), std::str::from_utf8(&ob), std::str::from_utf8(&tb));
                    let (Ok(bt), Ok(ot), Ok(tt)) = texts else {
                        conflicts.push(file_conflict);
                        pick(Some(o), &mut files);
                        continue;
                    };
                    match merge_text(path, bt, ot, tt) {
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

/// Merges one file's text. `Err` carries the conflicting symbols.
pub fn merge_text(path: &str, b: &str, o: &str, t: &str) -> std::result::Result<String, Vec<String>> {
    let file_conflict = || vec![format!("{path}#<file>")];
    let lang = Lang::detect(path);
    if let Some(lang) = lang {
        match symbol_merge(path, lang, b, o, t) {
            Sm::Merged(s) => return Ok(s),
            Sm::Conflict(c) => return Err(c),
            Sm::Fallback => {}
        }
    }
    let merged = diffy::merge(b, o, t).map_err(|_| file_conflict())?;
    if let Some(lang) = lang
        && parse(lang, &merged).has_error {
            return Err(file_conflict());
        }
    Ok(merged)
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
    path: &'a str,
    b: &'a str,
    o: &'a str,
    t: &'a str,
    edits: Vec<Edit>,
    conflicts: Vec<String>,
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

impl Merger<'_> {
    fn conflict(&mut self, name: &str) {
        self.conflicts.push(format!("{}#{name}", self.path));
    }

    fn insert(&mut self, pos: usize, text: String) {
        let seq = self.edits.len();
        self.edits.push(Edit { start: pos, end: pos, text, seq });
    }

    fn replace(&mut self, start: usize, end: usize, text: String) {
        let seq = self.edits.len();
        self.edits.push(Edit { start, end, text, seq });
    }

    fn level(&mut self, bs: &[Sym], os: &[Sym], ts: &[Sym], o_container: Option<&Sym>) {
        let (bm, om, tm) = (by_name(bs), by_name(os), by_name(ts));
        let top = o_container.is_none();
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
                    if let Some(p) = prev {
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
                    let all_containers = b_sym.container && o_sym.container && ts_sym.container;
                    if all_containers && ts_sym.own == b_sym.own {
                        let (bc, oc, tc) = (b_sym.children.clone(), o_sym.children.clone(), ts_sym.children.clone());
                        let o_owned = (*o_sym).clone();
                        self.level(&bc, &oc, &tc, Some(&o_owned));
                    } else {
                        self.conflict(name);
                    }
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

    fn imports(&mut self, pb: &Parsed, po: &Parsed, pt: &Parsed) {
        let norm = |src: &str, spans: &[(usize, usize)]| -> Vec<(String, (usize, usize))> {
            spans.iter().map(|&(s, e)| (normalize(&src[s..e]), (s, e))).collect()
        };
        let (bi, oi, ti) = (norm(self.b, &pb.imports), norm(self.o, &po.imports), norm(self.t, &pt.imports));
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

    fn apply(mut self) -> Option<String> {
        self.edits.sort_by(|a, b| a.start.cmp(&b.start).then(a.end.cmp(&b.end)).then(a.seq.cmp(&b.seq)));
        for w in self.edits.windows(2) {
            if w[1].start < w[0].end {
                return None;
            }
        }
        let mut out = String::with_capacity(self.o.len());
        let mut pos = 0;
        for e in &self.edits {
            out.push_str(&self.o[pos..e.start]);
            out.push_str(&e.text);
            pos = e.end;
        }
        out.push_str(&self.o[pos..]);
        Some(out)
    }
}

fn symbol_merge(path: &str, lang: Lang, b: &str, o: &str, t: &str) -> Sm {
    let (pb, po, pt) = (parse(lang, b), parse(lang, o), parse(lang, t));
    if pb.has_error || po.has_error || pt.has_error {
        return Sm::Fallback;
    }
    if pt.residual != pb.residual && po.residual != pt.residual {
        if po.residual == pb.residual {
            return Sm::Fallback;
        }
        return Sm::Conflict(vec![format!("{path}#<module>")]);
    }
    let mut m = Merger { path, b, o, t, edits: Vec::new(), conflicts: Vec::new() };
    m.imports(&pb, &po, &pt);
    m.level(&pb.syms, &po.syms, &pt.syms, None);
    if !m.conflicts.is_empty() {
        let mut c = m.conflicts;
        c.sort();
        c.dedup();
        return Sm::Conflict(c);
    }
    match m.apply() {
        Some(text) if !parse(lang, &text).has_error => Sm::Merged(text),
        _ => Sm::Fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RS: &str = "use std::io;\n\nfn a() {\n    1\n}\nfn b() {\n    2\n}\n\nfn c() {\n    3\n}\n";

    #[test]
    fn adjacent_functions_merge_where_lines_conflict() {
        let b = "fn a() -> u8 { 1 }\nfn b() -> u8 { 2 }\n";
        let o = b.replace("{ 1 }", "{ 10 }");
        let t = b.replace("{ 2 }", "{ 20 }");
        assert!(diffy::merge(b, &o, &t).is_err(), "line merge conflicts on adjacent lines");
        let m = merge_text("x.rs", b, &o, &t).unwrap();
        assert_eq!(m, "fn a() -> u8 { 10 }\nfn b() -> u8 { 20 }\n");
    }

    #[test]
    fn same_symbol_conflicts() {
        let o = RS.replace("    1\n", "    10\n");
        let t = RS.replace("    1\n", "    11\n");
        assert_eq!(merge_text("x.rs", RS, &o, &t), Err(vec!["x.rs#a".into()]));
        assert_eq!(merge_text("x.rs", RS, &o, &o), Ok(o.clone()), "identical changes merge");
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
        assert!(m.contains("use std::fmt;") && m.contains("use std::fs;"), "{m}");
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
        let t = b.replace("  b() { return 2; }\n", "  b() { return 2; }\n  c() { return 3; }\n");
        let m = merge_text("x.ts", b, &o, &t).unwrap();
        assert!(m.contains("return 10;") && m.contains("c() { return 3; }"), "{m}");
    }

    #[test]
    fn unsupported_files_use_line_merge() {
        let b = "a\nb\nc\nd\ne\n";
        let o = "A\nb\nc\nd\ne\n";
        let t = "a\nb\nc\nd\nE\n";
        assert_eq!(merge_text("notes.txt", b, o, t), Ok("A\nb\nc\nd\nE\n".into()));
        assert_eq!(merge_text("notes.txt", b, "X\nb\nc\nd\ne\n", "Y\nb\nc\nd\ne\n"), Err(vec!["notes.txt#<file>".into()]));
    }

    #[test]
    fn module_level_change_on_one_side_falls_back_to_lines() {
        let t = RS.replace("fn c() {", "static X: u8 = 1;\n\nfn c() {");
        let o = RS.replace("    1\n", "    10\n");
        let m = merge_text("x.rs", RS, &o, &t).unwrap();
        assert!(m.contains("static X") && m.contains("    10\n"));
    }

    #[test]
    fn twenty_agents_one_file() {
        let mut base = String::new();
        for i in 0..20 {
            base.push_str(&format!("pub fn f{i}(x: u64) -> u64 {{\n    x + {i}\n}}\n\n"));
        }
        let mut trunk = base.clone();
        for i in 0..20 {
            let theirs = format!(
                "{}pub fn new{i}() -> u64 {{\n    {i}\n}}\n",
                base.replace(&format!("    x + {i}\n"), &format!("    x * {i}\n"))
            );
            trunk = merge_text("lib.rs", &base, &trunk, &theirs).unwrap_or_else(|c| panic!("agent {i}: {c:?}"));
        }
        let p = parse(Lang::Rust, &trunk);
        assert!(!p.has_error);
        for i in 0..20 {
            assert!(trunk.contains(&format!("    x * {i}\n")), "edit {i} survived");
            assert!(trunk.contains(&format!("pub fn new{i}()")), "add {i} survived");
        }
        assert_eq!(p.syms.len(), 40);
    }
}
