//! Symbol extraction with tree-sitter.
//!
//! A symbol's span includes the attributes, decorators and comments directly
//! in front of it, so that `#[ignore]` or a doc comment counts as part of the
//! function it belongs to. From [`ENGINE_GROUPS`] on, a blank line ends that:
//! a comment that stands apart belongs to the code around it.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use lonca_core::ops::DEF;

use crate::engine::{ENGINE_CURRENT, ENGINE_DEFS, ENGINE_EXACT, ENGINE_GROUPS, ENGINE_KEYS};
use crate::lang::Lang;

/// Declarations with a definition of their own even with no members in the
/// file's tree: a Rust `struct` or a Go `type`, whose methods stand beside
/// them. The names hold across tree-sitter grammars, so a new language needs
/// an entry only for a kind of its own.
const TYPE_KINDS: &[&str] = &[
    "struct_item",
    "enum_item",
    "union_item",
    "type_item",
    "type_declaration",
    "type_spec",
    "type_alias",
    "interface_declaration",
    "type_alias_declaration",
    "enum_declaration",
    "record_declaration",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sym {
    /// Qualified name within the file, e.g. `Client.charge`.
    pub name: String,
    /// The name before its key, for a symbol that shares it with others.
    pub plain: Option<String>,
    /// The name before its number.
    pub stem: String,
    pub start: usize,
    pub end: usize,
    /// Start of the definition itself (after attached attributes/comments).
    pub def_start: usize,
    /// Normalized text excluding children (containers) or the full text (leaves).
    pub own: String,
    /// The same text for containers as [`exact_text`] writes it; empty for
    /// leaves, whose text is compared as it stands.
    pub own_exact: String,
    /// Where the members stood in `own_exact`.
    pub spots: Vec<Spot>,
    /// Normalized declaration header for callables.
    pub signature: Option<String>,
    /// The type whose definition this symbol's own text belongs to: itself,
    /// the type of a Rust `impl` or of an earlier part of a C# `partial`
    /// type, or nothing for what has no members.
    pub def_of: Option<String>,
    /// The declaration or block this symbol stands in, when that is not
    /// simply the level of its siblings.
    pub holder: Option<Holder>,
    /// In a list with separators: where the element before it ends and the
    /// one after it starts, symbol or not.
    pub around: (Option<usize>, Option<usize>),
    /// A comment behind the code on its line: where that code ends and where
    /// the comment starts. What stands between them is layout.
    pub tail: Option<(usize, usize)>,
    pub is_test: bool,
    pub skipped: bool,
    pub container: bool,
    pub children: Vec<Sym>,
}

impl Sym {
    pub fn text<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start..self.end]
    }

    /// The text of `self` in `src` says what `other` says in `other_src`.
    pub fn same(&self, src: &str, other: &Sym, other_src: &str) -> bool {
        self.compared(src) == other.compared(other_src)
    }

    fn compared<'a>(&self, src: &'a str) -> (&'a str, &'a str) {
        match self.tail {
            Some((code, comment)) => (&src[self.start..code], &src[comment..self.end]),
            None => (self.text(src), ""),
        }
    }

    /// This symbol's code and where its members stood in it.
    pub fn placed(&self) -> Placed<'_> {
        (&self.own_exact, &self.spots)
    }

    /// What `engine` compares as this symbol's own text.
    pub fn own_at(&self, engine: u32) -> &str {
        if engine >= ENGINE_EXACT {
            &self.own_exact
        } else {
            &self.own
        }
    }

    /// What a change of this symbol into `new` is a change of: the one name
    /// that facts report and the merge conflicts on, so that a lease covers
    /// the unit the merge works with. A symbol that changed its shape is
    /// changed whole.
    pub fn changed_unit(&self, new: &Sym, engine: u32) -> String {
        match &new.def_of {
            Some(ty)
                if engine >= ENGINE_DEFS
                    && self.def_of == new.def_of
                    && self.container == new.container =>
            {
                format!("{ty}.{DEF}")
            }
            _ => new.name.clone(),
        }
    }

    /// The type of a Rust `impl`: its members are named after the type and
    /// are not its children by name.
    pub fn impl_of(&self, engine: u32) -> Option<&str> {
        let ty = self.def_of.as_deref().filter(|ty| *ty != self.name);
        ty.filter(|_| engine >= ENGINE_DEFS)
    }
}

/// A part of the tree whose members are symbols of the level around it: a
/// grouped declaration, a block, a namespace. Spans are only comparable
/// within one side of a merge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Holder {
    pub kind: u16,
    pub start: usize,
    pub end: usize,
    /// Members are separated by more than whitespace, so a member added or
    /// removed takes the separator with it.
    pub joined: bool,
    /// Which group of the file this is, and which block of that group.
    pub block: (u32, u32),
}

/// Where a symbol or an import stood in what [`exact_text`] wrote, which
/// leaves them out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spot {
    pub at: usize,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsTest {
    pub name: String,
    pub text: String,
    pub skipped: bool,
}

#[derive(Clone, Debug)]
pub struct Parsed {
    pub syms: Vec<Sym>,
    pub imports: Vec<(usize, usize)>,
    pub has_error: bool,
    /// Normalized top-level text outside symbols and imports.
    pub residual: String,
    /// The same code as [`exact_text`] writes it.
    pub residual_exact: String,
    /// Where the symbols and imports stood in `residual_exact`.
    pub spots: Vec<Spot>,
    pub js_tests: Vec<JsTest>,
}

impl Parsed {
    /// What `engine` compares as the code outside symbols and imports.
    pub fn residual_at(&self, engine: u32) -> &str {
        if engine >= ENGINE_EXACT {
            &self.residual_exact
        } else {
            &self.residual
        }
    }

    /// The code outside symbols and where they stood in it.
    pub fn placed(&self) -> Placed<'_> {
        (&self.residual_exact, &self.spots)
    }

    pub fn import_texts(&self, src: &str) -> Vec<String> {
        self.imports
            .iter()
            .map(|(s, e)| normalize(&src[*s..*e]))
            .collect()
    }

    /// Every test symbol (any depth): qualified name -> (text, skipped).
    pub fn tests(&self, src: &str) -> BTreeMap<String, (String, bool)> {
        let mut out = BTreeMap::new();
        fn walk(syms: &[Sym], src: &str, out: &mut BTreeMap<String, (String, bool)>) {
            for s in syms {
                if s.is_test {
                    let (code, comment) = s.compared(src);
                    out.insert(s.name.clone(), (format!("{code}{comment}"), s.skipped));
                }
                walk(&s.children, src, out);
            }
        }
        walk(&self.syms, src, &mut out);
        for t in &self.js_tests {
            out.insert(format!("test:{}", t.name), (t.text.clone(), t.skipped));
        }
        out
    }
}

pub fn normalize(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// [`parse_at`] with the current engine.
pub fn parse(lang: Lang, src: &str) -> Parsed {
    parse_at(ENGINE_CURRENT, lang, src)
}

/// The symbols of `src` as `engine` reads them.
pub fn parse_at(engine: u32, lang: Lang, src: &str) -> Parsed {
    let [p] = read_together(engine, lang, [src]).1;
    p
}

/// Names that more than one definition goes by in a file, with something to
/// tell them apart.
pub type Keyed = BTreeSet<String>;

/// Versions of one file, read with the same names: a symbol is named by its
/// key in all of them when any of them needs that, so that its name does not
/// change with the arrival of a second symbol of that name.
pub fn parse_together<const N: usize>(engine: u32, lang: Lang, texts: [&str; N]) -> [Parsed; N] {
    read_together(engine, lang, texts).1
}

/// [`parse_together`], and the names read with their key, for a text that
/// comes later: [`parse_keyed`].
pub fn read_together<const N: usize>(
    engine: u32,
    lang: Lang,
    texts: [&str; N],
) -> (Keyed, [Parsed; N]) {
    let keyed = keyed_names(engine, lang, &texts);
    let parsed = texts.map(|text| parse_keyed(engine, lang, text, &keyed));
    (keyed, parsed)
}

/// Each round names by key what the last one found to be shared, and that
/// changes the names of its members. It ends with the depth of the file.
fn keyed_names(engine: u32, lang: Lang, texts: &[&str]) -> Keyed {
    let mut keyed = Keyed::new();
    if engine < ENGINE_KEYS {
        return keyed;
    }
    let trees: Vec<_> = texts.iter().map(|t| (lang.parse(t), *t)).collect();
    loop {
        let before = keyed.len();
        for (tree, src) in &trees {
            let Some(tree) = tree else { continue };
            let ex = Extractor::new(engine, lang, src, &keyed, Some(Census::default()));
            ex.level(
                tree.root_node(),
                "",
                &mut Vec::new(),
                None,
                &mut BTreeMap::new(),
                None,
            );
            let census = ex.census.map(RefCell::into_inner).unwrap_or_default();
            let shared = census.into_iter().filter(|(_, keys)| keys.len() > 1);
            let found: Vec<String> = shared.map(|(name, _)| name).collect();
            keyed.extend(found);
        }
        if keyed.len() == before {
            return keyed;
        }
    }
}

/// `src` with the names in `keyed` read by their key.
pub fn parse_keyed(engine: u32, lang: Lang, src: &str, keyed: &Keyed) -> Parsed {
    let Some(tree) = lang.parse(src) else {
        return Parsed {
            syms: vec![],
            imports: vec![],
            has_error: true,
            residual: normalize(src),
            residual_exact: normalize(src),
            spots: vec![],
            js_tests: vec![],
        };
    };
    let root = tree.root_node();
    let ex = Extractor::new(engine, lang, src, keyed, None);
    let mut imports = Vec::new();
    let mut syms = Vec::new();
    ex.level(
        root,
        "",
        &mut syms,
        Some(&mut imports),
        &mut BTreeMap::new(),
        None,
    );
    let mut cut: Vec<(usize, usize)> = syms
        .iter()
        .map(|s| (s.start, s.end))
        .chain(imports.iter().copied())
        .collect();
    cut.sort();
    let residual = normalize(&remove_spans(src, 0, src.len(), &cut));
    // By their order: an import's text can change, its place stays.
    let import_names: Vec<String> = (0..imports.len()).map(|i| format!("import {i}")).collect();
    let import_marks = imports.iter().zip(&import_names);
    let marks: Vec<Mark> = syms
        .iter()
        .map(|s| (s.start, s.end, s.name.as_str()))
        .chain(import_marks.map(|(&(s, e), n)| (s, e, n.as_str())))
        .collect();
    let mut residual_exact = String::new();
    let mut spots = Vec::new();
    let holders = holders_of(&syms);
    exact_text(root, src, &marks, &holders, &mut residual_exact, &mut spots);
    let js_tests = if lang.is_js_family() {
        ex.js_tests(root)
    } else {
        vec![]
    };
    Parsed {
        syms,
        imports,
        has_error: root.has_error(),
        residual,
        residual_exact,
        spots,
        js_tests,
    }
}

fn remove_spans(src: &str, from: usize, to: usize, spans: &[(usize, usize)]) -> String {
    let mut out = String::new();
    let mut pos = from;
    for &(s, e) in spans {
        if s >= pos {
            out.push_str(&src[pos..s]);
            out.push(' ');
        }
        pos = pos.max(e);
    }
    if pos < to {
        out.push_str(&src[pos..to]);
    }
    out
}

/// Node kinds whose text is what they mean, whitespace included. The names
/// hold across tree-sitter grammars, so a new language needs no entry here.
fn is_verbatim(kind: &str) -> bool {
    ["string", "comment", "char", "heredoc", "regex"]
        .iter()
        .any(|k| kind.contains(k))
}

/// A span [`exact_text`] leaves out, and what stands there.
type Mark<'a> = (usize, usize, &'a str);

/// Writes `n` without the parts inside `cut`: its tree, and the text of its
/// tokens, noting in `spots` where each cut part stood. Reformatting leaves
/// this as it was; whatever changes the program does not, because
/// indentation that means something is in the tree and whitespace in a
/// string is in the token. A holder stays, also with one member and so the
/// span of that member, and the commas of a list go with their members: a
/// member added or removed changes no code around it.
fn exact_text(
    n: Node,
    src: &str,
    cut: &[Mark],
    holders: &[Holder],
    out: &mut String,
    spots: &mut Vec<Spot>,
) {
    let (start, end) = (n.start_byte(), n.end_byte());
    let same = |h: &&Holder| h.start == start && h.end == end && h.kind == n.kind_id();
    let holder = holders.iter().find(same);
    let cut_here = cut.iter().find(|&&(s, e, _)| s <= start && end <= e);
    if let (Some(&(.., name)), None) = (cut_here, holder) {
        if spots.last().is_none_or(|last| last.name != name) {
            spots.push(Spot {
                at: out.len(),
                name: name.to_string(),
            });
        }
        return;
    }
    if n.child_count() == 0 || is_verbatim(n.kind()) {
        out.push_str(&src[start..end]);
        out.push('\u{1f}');
        return;
    }
    if n.is_named() {
        out.push_str(n.kind());
        out.push('(');
    }
    let list = holder.is_some_and(|h| h.joined);
    for c in n.children(&mut n.walk()) {
        if !(list && c.kind() == ",") {
            exact_text(c, src, cut, holders, out, spots);
        }
    }
    if n.is_named() {
        out.push(')');
    }
}

/// What `syms` stand in.
fn holders_of(syms: &[Sym]) -> Vec<Holder> {
    syms.iter().filter_map(|s| s.holder).collect()
}

/// A symbol a side gave a new key: what it calls it, what the base calls it,
/// and its text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pair {
    pub side: String,
    /// `side` before its number: one side can give two scopes one key.
    pub stem: String,
    pub base: String,
    pub own: String,
    /// Where it stands in the base.
    pub at: usize,
}

/// How many pairs are compared by their text, at most, in one place. Past it,
/// source order decides: a file can not make the daemon compare forever.
pub(crate) const MAX_COMPARED: usize = 64;

/// A definition of a shared name that lost its old key and one that has a
/// new key are one symbol whose parameters changed, as they are when no
/// other symbol has its name: `side` takes the name `base` has it under, and
/// the change is an edit of that. They must stand in one place among the
/// symbols both have, or one is gone and the other new. Among several there,
/// the closest texts pair, then source order. Containers stay: their members
/// hang on the key. Returns the pairs.
pub fn align(base: &Parsed, side: &mut Parsed) -> Vec<Pair> {
    let [in_base, in_side] = [&base.syms, &side.syms].map(|syms| {
        let mut names = BTreeSet::new();
        each_name(syms, &mut names);
        names
    });
    let mut pairs = Vec::new();
    pair_level(&base.syms, &side.syms, [&in_base, &in_side], &mut pairs);
    let names = pairs.iter().map(|p| (p.side.clone(), p.base.clone()));
    rename(&mut side.syms, &mut side.spots, &names.collect());
    pairs
}

fn each_name(syms: &[Sym], out: &mut BTreeSet<String>) {
    for s in syms {
        out.insert(s.name.clone());
        each_name(&s.children, out);
    }
}

fn each_symbol<'s>(syms: &'s [Sym], out: &mut Vec<&'s Sym>) {
    for s in syms {
        out.push(s);
        each_symbol(&s.children, out);
    }
}

/// A scope, a block in it and a name.
type Seat<'s> = (&'s str, Option<(u32, u32)>, &'s str);

/// The keyed names that stand twice in one place of `syms`.
fn keys_twice<'s>(
    syms: &'s [Sym],
    scope: &'s str,
    seen: &mut BTreeSet<Seat<'s>>,
    out: &mut BTreeSet<(&'s str, &'s str)>,
) {
    for s in syms {
        let block = s.holder.map(|h| h.block);
        if s.plain.is_some() && !seen.insert((scope, block, &s.stem)) {
            out.insert((scope, &s.stem));
        }
        // The parts of a type are one scope, and so are the `impl`s of one
        // type that nothing tells apart.
        let inner = s.def_of.as_deref().filter(|_| s.plain.is_none());
        keys_twice(&s.children, inner.unwrap_or(&s.name), seen, out);
    }
}

/// A key stands twice in one place of `merged` and in no such place of the
/// sides: they gave one key to two symbols, and only one can answer to it.
/// In another block, or in an `impl` for other type arguments, each is valid.
pub fn key_twice(merged: &Parsed, sides: [&Parsed; 3]) -> bool {
    let twice = |p: &'_ Parsed| {
        let mut out = BTreeSet::new();
        keys_twice(&p.syms, "", &mut BTreeSet::new(), &mut out);
        out.into_iter()
            .map(|(scope, name)| (scope.to_string(), name.to_string()))
            .collect::<BTreeSet<_>>()
    };
    let before: Vec<_> = sides.iter().map(|p| twice(p)).collect();
    twice(merged)
        .iter()
        .any(|k| !before.iter().any(|b| b.contains(k)))
}

/// Gives `merged` the names the sides gave its symbols. Each came from a
/// side, so its text finds its pair, and then its place. One the sides call
/// by a key that also went to a pair has a number only for that.
pub fn rename_aligned(merged: &mut Parsed, pairs: &[Pair]) {
    let mut all = Vec::new();
    each_symbol(&merged.syms, &mut all);
    let keyed = |s: &&&Sym| !s.container && pairs.iter().any(|p| p.stem == s.stem);
    let mine: Vec<&Sym> = all.iter().filter(keyed).copied().collect();
    let mut open: Vec<&Pair> = pairs.iter().collect();
    open.sort_by_key(|p| p.at);
    let mut names = BTreeMap::new();
    for s in &mine {
        let same = |p: &&Pair| p.stem == s.stem && p.own == s.own;
        if let Some(at) = open.iter().position(same) {
            names.insert(s.name.clone(), open.remove(at).base.clone());
        }
    }
    for s in mine {
        if !names.contains_key(&s.name) {
            let at = open.iter().position(|p| p.stem == s.stem);
            let name = at.map_or(s.stem.clone(), |at| open.remove(at).base.clone());
            names.insert(s.name.clone(), name);
        }
    }
    rename(&mut merged.syms, &mut merged.spots, &names);
}

fn rename(syms: &mut [Sym], spots: &mut [Spot], names: &BTreeMap<String, String>) {
    for s in syms {
        if let Some(name) = names.get(&s.name).filter(|_| !s.container) {
            for spot in spots.iter_mut().filter(|at| at.name == s.name) {
                spot.name = name.clone();
            }
            s.name = name.clone();
        }
        rename(&mut s.children, &mut s.spots, names);
    }
}

fn pair_level(
    bs: &[Sym],
    ns: &[Sym],
    [in_base, in_side]: [&BTreeSet<String>; 2],
    pairs: &mut Vec<Pair>,
) {
    let mut places: BTreeMap<Place, (Vec<&Sym>, Vec<&Sym>)> = BTreeMap::new();
    for (place, b) in open_ones(bs, in_side) {
        places.entry(place).or_default().0.push(b);
    }
    for (place, n) in open_ones(ns, in_base) {
        places.entry(place).or_default().1.push(n);
    }
    for (b, n) in places.into_values().flat_map(|(l, g)| closest(l, g)) {
        pairs.push(Pair {
            side: n.name.clone(),
            stem: n.stem.clone(),
            base: b.name.clone(),
            own: n.own.clone(),
            at: b.start,
        });
    }
    let by_name: BTreeMap<&str, &Sym> = bs.iter().map(|b| (b.name.as_str(), b)).collect();
    for n in ns {
        if let Some(b) = by_name.get(n.name.as_str()) {
            pair_level(&b.children, &n.children, [in_base, in_side], pairs);
        }
    }
}

/// Where a symbol stands among those both sides have: its bare name, the one
/// in front of it, and its block. Groups count among those that hold this
/// name, since a group added above renumbers the ones of the file.
type Place = (Option<String>, Option<String>, Option<(usize, u32)>);

/// The keyed symbols of `list` that `other` has nowhere.
fn open_ones<'s>(list: &'s [Sym], other: &BTreeSet<String>) -> Vec<(Place, &'s Sym)> {
    let mut groups: BTreeMap<&str, BTreeSet<u32>> = BTreeMap::new();
    for s in list {
        if let (Some(name), Some(h)) = (&s.plain, s.holder) {
            groups.entry(name).or_default().insert(h.block.0);
        }
    }
    let block = |s: &Sym| {
        let name = s.plain.as_deref().unwrap_or_default();
        let held = s.holder.map(|h| h.block)?;
        let rank = groups.get(name)?.range(..held.0).count();
        Some((rank, held.1))
    };
    let mut out = Vec::new();
    let mut behind = None;
    for s in list {
        if other.contains(&s.name) {
            behind = Some(s.name.clone());
        } else if s.plain.is_some() && !s.container {
            out.push(((s.plain.clone(), behind.clone(), block(s)), s));
        }
    }
    out
}

/// How alike two texts are, from 0 to 1, word by word. Layout does not count.
pub(crate) fn likeness(a: &str, b: &str) -> f32 {
    let (a, b): (Vec<&str>, Vec<&str>) = (
        a.split_whitespace().collect(),
        b.split_whitespace().collect(),
    );
    similar::TextDiff::from_slices(&a, &b).ratio()
}

/// Indexes of `lost` and `gained`, each used once, by `like`: the best first,
/// a tie to source order. Nothing under `floor` is a pair.
pub(crate) fn best_pairs<T>(
    lost: &[T],
    gained: &[T],
    like: impl Fn(&T, &T) -> f32,
    floor: f32,
) -> Vec<(usize, usize)> {
    let mut ranked = Vec::new();
    for (i, b) in lost.iter().enumerate() {
        for (j, n) in gained.iter().enumerate() {
            ranked.push((like(b, n), i, j));
        }
    }
    ranked.retain(|r| r.0 >= floor);
    ranked.sort_by(|a, b| b.0.total_cmp(&a.0).then((a.1, a.2).cmp(&(b.1, b.2))));
    let (mut used_l, mut used_g) = (BTreeSet::new(), BTreeSet::new());
    let mut out = Vec::new();
    for (_, i, j) in ranked {
        if !used_l.contains(&i) && !used_g.contains(&j) {
            used_l.insert(i);
            used_g.insert(j);
            out.push((i, j));
        }
    }
    out
}

/// Pairs by likeness.
fn closest<'s>(lost: Vec<&'s Sym>, gained: Vec<&'s Sym>) -> Vec<(&'s Sym, &'s Sym)> {
    if lost.len().saturating_mul(gained.len()) > MAX_COMPARED {
        return lost.into_iter().zip(gained).collect();
    }
    let like = |b: &&Sym, n: &&Sym| likeness(&b.own, &n.own);
    let pairs = best_pairs(&lost, &gained, like, 0.0);
    pairs
        .into_iter()
        .map(|(i, j)| (lost[i], gained[j]))
        .collect()
}

/// Code with the symbols around it left out, and the symbols around it.
pub type Placed<'a> = (&'a str, &'a [Spot]);

/// The code of `text` piece by piece, each with the `common` names in front
/// of it. A name that only one side has does not cut a piece.
fn pieces<'t>(
    (text, spots): Placed<'t>,
    common: &BTreeSet<&str>,
) -> Vec<(BTreeSet<&'t str>, &'t str)> {
    let mut out = Vec::new();
    let (mut before, mut from) = (BTreeSet::new(), 0);
    for s in spots.iter().filter(|s| common.contains(s.name.as_str())) {
        out.push((before.clone(), &text[from..s.at]));
        before.insert(s.name.as_str());
        from = s.at;
    }
    out.push((before, &text[from..]));
    out.retain(|(_, code)| !code.is_empty());
    out
}

/// The same code stands elsewhere among the symbols both sides have. Adding
/// or removing a symbol moves nothing, and neither does symbols changing
/// places with no code between them.
pub(crate) fn shifted(a: Placed, b: Placed) -> bool {
    let names =
        |p: Placed<'_>| -> BTreeSet<String> { p.1.iter().map(|s| s.name.clone()).collect() };
    let (na, nb) = (names(a), names(b));
    let common: BTreeSet<&str> = na.intersection(&nb).map(String::as_str).collect();
    pieces(a, &common) != pieces(b, &common)
}

/// The names both lists hold that do not keep their place among them.
pub(crate) fn moved(old: &[&str], new: &[&str]) -> Vec<String> {
    let in_both = |list: &[&str], other: &[&str]| -> Vec<String> {
        let other: BTreeSet<&str> = other.iter().copied().collect();
        let kept = list.iter().filter(|x| other.contains(**x));
        kept.map(|x| x.to_string()).collect()
    };
    let (a, b) = (in_both(old, new), in_both(new, old));
    let shifted = a.into_iter().zip(b).filter(|(x, y)| x != y);
    shifted.map(|(_, y)| y).collect()
}

struct Def<'t> {
    name: String,
    /// Prefix for members when it differs from `name` (Rust `impl` blocks:
    /// the block is `impl:Client`, its methods are `Client.method`).
    member_prefix: Option<String>,
    /// The type a Rust `impl` is for.
    impl_for: Option<String>,
    /// The node holding nested members, if this is a container.
    members: Option<Node<'t>>,
    /// The function/method body, used to cut the signature.
    body: Option<Node<'t>>,
    /// Where the declaration header starts (after attributes inside the node).
    header_start: usize,
    /// What sets this declaration apart that it does not take as parameters:
    /// the type arguments of a Rust `impl`.
    key: Option<String>,
}

/// The text of a part of a key: `.` separates the levels of a name, and
/// nothing a key holds may look like one.
fn key_text(text: &str) -> String {
    normalize(text).replace(", ", ",").replace('.', "::")
}

/// The longest key. A key is written in every lease and fact that names its
/// symbol; two that differ past this have a number.
const MAX_KEY: usize = 200;

fn key_of<S: AsRef<str>>(parts: impl Iterator<Item = S>) -> Option<String> {
    let parts: Vec<String> = parts.map(|p| key_text(p.as_ref())).collect();
    let mut text = parts.join(",");
    let cut = text.char_indices().map(|(i, _)| i).find(|i| *i >= MAX_KEY);
    text.truncate(cut.unwrap_or(text.len()));
    (!parts.is_empty()).then(|| format!("({text})"))
}

/// What stands between the angle brackets of a type.
fn type_args(ty: &str) -> Option<&str> {
    ty.split_once('<')?.1.trim_end().strip_suffix('>')
}

/// Nodes whose members belong to the level around them.
struct Group<'t> {
    members: Vec<Node<'t>>,
    joined: bool,
}

impl<'t> Group<'t> {
    fn of(members: Vec<Node<'t>>) -> Self {
        Group {
            members,
            joined: false,
        }
    }

    fn joined(member: Node<'t>) -> Self {
        Group {
            members: vec![member],
            joined: true,
        }
    }
}

fn holder_of(n: Node, joined: bool, block: (u32, u32)) -> Holder {
    Holder {
        kind: n.kind_id(),
        start: n.start_byte(),
        end: n.end_byte(),
        joined,
        block,
    }
}

fn named<'t>(n: Node<'t>) -> Vec<Node<'t>> {
    n.named_children(&mut n.walk()).collect()
}

/// The blocks of a Python `if` or `try`, its clauses included.
fn blocks<'t>(n: Node<'t>, out: &mut Vec<Node<'t>>) {
    for c in named(n) {
        match c.kind() {
            "block" => out.push(c),
            _ => blocks(c, out),
        }
    }
}

/// What tells the definitions of each name apart, without a key for one
/// that has none.
type Census = BTreeMap<String, BTreeSet<Option<String>>>;

struct Extractor<'s> {
    engine: u32,
    lang: Lang,
    src: &'s str,
    /// Where each C# type name was first seen: its namespaces.
    scopes: RefCell<BTreeMap<String, String>>,
    groups_seen: Cell<u32>,
    keyed: &'s Keyed,
    /// Set for a round that only counts names.
    census: Option<RefCell<Census>>,
}

impl<'s> Extractor<'s> {
    fn new(
        engine: u32,
        lang: Lang,
        src: &'s str,
        keyed: &'s Keyed,
        census: Option<Census>,
    ) -> Self {
        Extractor {
            engine,
            lang,
            src,
            scopes: RefCell::default(),
            groups_seen: Cell::new(0),
            keyed,
            census: census.map(RefCell::new),
        }
    }

    fn text(&self, n: Node) -> &'s str {
        &self.src[n.start_byte()..n.end_byte()]
    }

    fn field_text(&self, n: Node, field: &str) -> Option<String> {
        n.child_by_field_name(field)
            .map(|c| self.text(c).to_string())
    }

    fn is_attachable(&self, n: Node) -> bool {
        match self.lang {
            Lang::Rust => matches!(
                n.kind(),
                "attribute_item" | "line_comment" | "block_comment"
            ),
            Lang::TypeScript | Lang::Tsx | Lang::JavaScript => {
                n.kind() == "comment" || self.groups() && n.kind() == "decorator"
            }
            Lang::Python | Lang::Go | Lang::CSharp => n.kind() == "comment",
        }
    }

    /// A comment behind other code on its line, maybe behind another such
    /// comment. A comment node can hold its own line end, and so can a
    /// preprocessor line.
    fn trails(&self, n: Node) -> bool {
        let is_comment = |c: Node| c.kind().contains("comment");
        let behind = n.prev_sibling().is_some_and(|p| {
            let (end, start) = (p.end_byte(), n.start_byte());
            let line_ended = self.src[..end].ends_with('\n');
            let gap = self.src.get(end..start);
            !line_ended
                && gap.is_some_and(|g| !g.contains('\n'))
                && (!is_comment(p) || self.trails(p))
        });
        self.groups() && is_comment(n) && behind
    }

    /// Only spaces stand between `sym` and the comment behind it.
    fn ends_at(&self, sym: &Sym, comment: Node) -> bool {
        let gap = self.src.get(sym.end..comment.start_byte());
        gap.is_some_and(|g| g.trim_matches([' ', '\t']).is_empty())
    }

    fn groups(&self) -> bool {
        self.engine >= ENGINE_GROUPS
    }

    /// A blank line stands between a comment and what follows it. A comment
    /// node can hold its own line end, as a Rust doc comment does.
    fn stands_apart(&self, comment: Node, next: Node) -> bool {
        let (end, start) = (comment.end_byte(), next.start_byte());
        let held = self.src[..end].ends_with('\n');
        self.groups()
            && comment.kind().contains("comment")
            && self.src[end..start].matches('\n').count() + usize::from(held) > 1
    }

    fn is_import(&self, n: Node) -> bool {
        match self.lang {
            Lang::Rust => matches!(n.kind(), "use_declaration" | "extern_crate_declaration"),
            Lang::Python => matches!(
                n.kind(),
                "import_statement" | "import_from_statement" | "future_import_statement"
            ),
            Lang::TypeScript | Lang::Tsx | Lang::JavaScript => n.kind() == "import_statement",
            Lang::CSharp => n.kind() == "using_directive",
            Lang::Go => n.kind() == "import_declaration",
        }
    }

    /// Nodes whose members belong to the enclosing level are flattened: their
    /// names do not appear in symbol names. `top` is the file's own level.
    fn group<'t>(&self, n: Node<'t>, top: bool) -> Option<Group<'t>> {
        match (self.lang, n.kind()) {
            (Lang::CSharp, "namespace_declaration") => {
                n.child_by_field_name("body").map(|b| Group::of(vec![b]))
            }
            _ if !self.groups() => None,
            (Lang::Go, "const_declaration" | "type_declaration") => {
                let parens = n.children(&mut n.walk()).any(|c| c.kind() == "(");
                parens.then(|| Group::of(vec![n]))
            }
            (Lang::Go, "var_declaration") => {
                let lists = named(n).into_iter();
                let mut lists = lists.filter(|c| c.kind() == "var_spec_list");
                lists.next().map(|l| Group::of(vec![l]))
            }
            (Lang::CSharp, "field_declaration" | "event_field_declaration") => {
                let decl = find_descendant(n, "variable_declaration")?;
                let parts = named(decl).into_iter();
                let many = parts.filter(|c| c.kind() == "variable_declarator").count() > 1;
                many.then(|| Group::joined(decl))
            }
            (Lang::Rust, "foreign_mod_item") => {
                n.child_by_field_name("body").map(|b| Group::of(vec![b]))
            }
            (Lang::Python, "if_statement" | "try_statement") if top => {
                let mut list = Vec::new();
                blocks(n, &mut list);
                let stated: Vec<Node> = list.iter().flat_map(|b| named(*b)).collect();
                let is_def = |c: &Node| {
                    matches!(
                        c.kind(),
                        "function_definition" | "class_definition" | "decorated_definition"
                    )
                };
                let plain = |c: &Node| matches!(c.kind(), "comment" | "pass_statement");
                let only = stated.iter().all(|c| is_def(c) || plain(c));
                (only && stated.iter().any(is_def)).then(|| Group::of(list))
            }
            (Lang::TypeScript | Lang::Tsx | Lang::JavaScript, "expression_statement") => {
                let set = n
                    .named_child(0)
                    .filter(|c| c.kind() == "assignment_expression")?;
                let left = set.child_by_field_name("left")?;
                let right = set.child_by_field_name("right")?;
                (self.text(left) == "module.exports" && right.kind() == "object")
                    .then(|| Group::joined(right))
            }
            _ => None,
        }
    }

    /// `n` stands in the namespaces where `name` was first seen. Namespaces
    /// are no part of a name, and one can be written twice.
    fn same_scope(&self, name: &str, n: Node) -> bool {
        let mut scope = String::new();
        let mut at = n.parent();
        while let Some(p) = at {
            if p.kind().ends_with("namespace_declaration") {
                scope.push_str(&self.field_text(p, "name").unwrap_or_default());
                scope.push('.');
            }
            at = p.parent();
        }
        let mut scopes = self.scopes.borrow_mut();
        let first = scopes
            .entry(name.to_string())
            .or_insert_with(|| scope.clone());
        *first == scope
    }

    /// A later part of a C# `partial` type.
    fn is_partial(&self, n: Node) -> bool {
        let mut parts = named(n).into_iter();
        self.groups()
            && self.lang == Lang::CSharp
            && parts.any(|c| c.kind() == "modifier" && self.text(c) == "partial")
    }

    /// Unwraps `export ...` and `@decorator def ...` to the definition.
    fn unwrap_def<'t>(&self, n: Node<'t>) -> Node<'t> {
        match (self.lang, n.kind()) {
            (Lang::Python, "decorated_definition") => {
                n.child_by_field_name("definition").unwrap_or(n)
            }
            (Lang::TypeScript | Lang::Tsx | Lang::JavaScript, "export_statement") => {
                n.child_by_field_name("declaration").unwrap_or(n)
            }
            _ => n,
        }
    }

    fn base_type_name(s: &str) -> String {
        let s = s.trim().trim_start_matches('&').trim_start_matches('*');
        let s = s.split('<').next().unwrap_or(s);
        let s = s.rsplit("::").next().unwrap_or(s);
        s.trim().to_string()
    }

    /// A parameter as a key has it: what it takes, and its name only where
    /// nothing says what it takes. A parameter's name can change, and so
    /// can its default, with the same symbol.
    fn parameter_key(&self, p: Node) -> String {
        let field = |f: &str| p.child_by_field_name(f);
        let what = field("type").or(field("name")).or(field("pattern"));
        let text = self.text(what.or(field("left")).unwrap_or(p));
        let modifiers = named(p)
            .into_iter()
            .filter(|c| c.kind().contains("modifier"));
        let mut words: Vec<&str> = modifiers.map(|c| self.text(c)).collect();
        words.push(text.trim_start_matches([':', ' ']));
        // What an overload can differ by in TypeScript: `f(a?: T)`.
        let optional = if p.kind().contains("optional") {
            "?"
        } else {
            ""
        };
        format!("{}{optional}", words.join(" "))
    }

    /// The word that makes `n` one of the accessors of a name: `get` and
    /// `set` in its syntax, or a decorator that hangs it on the name, as
    /// `@x.setter` does. Any other decorator of that form says nothing about
    /// which one this is: `@f.register` overloads go by their parameters.
    fn accessor(&self, n: Node, around: Node, name: &str) -> Option<String> {
        let word = n
            .children(&mut n.walk())
            .find(|c| matches!(c.kind(), "get" | "set"))
            .map(|c| c.kind().to_string());
        word.or_else(|| {
            let decorators = named(around).into_iter();
            let mut decorators = decorators.filter(|c| c.kind() == "decorator");
            decorators.find_map(|d| {
                let text = self.text(d).trim_start_matches('@');
                let (owner, word) = text.split_once('.')?;
                let word = word.trim();
                let accessor = matches!(word, "getter" | "setter" | "deleter");
                (owner == name && accessor).then(|| word.to_string())
            })
        })
    }

    /// What a declaration can differ by besides its parameters: how many
    /// type parameters it has, the type a C# conversion gives, the interface
    /// it implements, `static` in TypeScript. Field and node names hold
    /// across grammars; a grammar without them has nothing to add.
    fn key_prefix(&self, n: Node) -> Vec<String> {
        let mut parts = Vec::new();
        if let Some(list) = n.child_by_field_name("type_parameters") {
            parts.push(format!("<{}>", named(list).len()));
        }
        if n.kind().contains("conversion")
            && let Some(ty) = n.child_by_field_name("type")
        {
            parts.push(self.text(ty).to_string());
        }
        for c in n.children(&mut n.walk()) {
            match c.kind() {
                "static" => parts.push("static".to_string()),
                "explicit_interface_specifier" => {
                    parts.push(self.text(c).trim_end_matches('.').to_string())
                }
                _ => {}
            }
        }
        parts
    }

    /// What tells `n` from other definitions of its name: not its place
    /// among them, which changes when one is added in front of it.
    fn key(&self, n: Node, around: Node, def: &Def) -> Option<String> {
        if let Some(word) = self.accessor(n, around, &def.name) {
            return Some(format!("[{word}]"));
        }
        if n.kind().contains("destructor") {
            return Some("[destructor]".to_string());
        }
        let Some(list) = n.child_by_field_name("parameters") else {
            return def.key.clone();
        };
        let mut parts = self.key_prefix(n);
        for i in 0..list.named_child_count() as u32 {
            let Some(p) = list.named_child(i as _) else {
                continue;
            };
            // C#'s `params` stands in the list with no parameter around it.
            match list.field_name_for_named_child(i) {
                Some("name") => {}
                Some("type") => parts.push(self.text(p).to_string()),
                _ if p.kind().contains("comment") => {}
                _ => parts.push(self.parameter_key(p)),
            }
        }
        match key_of(parts.iter()) {
            None => Some("()".to_string()),
            key => key,
        }
    }

    fn def<'t>(&self, n: Node<'t>) -> Option<Def<'t>> {
        let kind = n.kind();
        let name = |f: &str| self.field_text(n, f);
        let leaf = |name: Option<String>| {
            name.map(|name| Def {
                name,
                member_prefix: None,
                impl_for: None,
                members: None,
                body: n.child_by_field_name("body"),
                header_start: n.start_byte(),
                key: None,
            })
        };
        let container = |name: Option<String>, field: &str| {
            name.map(|name| Def {
                name,
                member_prefix: None,
                impl_for: None,
                members: n.child_by_field_name(field),
                body: None,
                header_start: n.start_byte(),
                key: None,
            })
        };
        match self.lang {
            Lang::Rust => match kind {
                "function_item"
                | "function_signature_item"
                | "struct_item"
                | "enum_item"
                | "union_item"
                | "type_item"
                | "const_item"
                | "static_item"
                | "macro_definition" => leaf(name("name")),
                "macro_invocation" | "expression_statement" if self.groups() => {
                    let call = match kind {
                        "macro_invocation" => n,
                        _ => n
                            .named_child(0)
                            .filter(|c| c.kind() == "macro_invocation")?,
                    };
                    let called = self.field_text(call, "macro")?;
                    leaf(Some(format!("{called}!")))
                }
                "trait_item" => container(name("name"), "body"),
                "mod_item" => {
                    if n.child_by_field_name("body").is_some() {
                        container(name("name"), "body")
                    } else {
                        leaf(name("name"))
                    }
                }
                "impl_item" => {
                    let of_type = name("type")?;
                    let ty = Self::base_type_name(&of_type);
                    let of_trait = name("trait");
                    let full = match &of_trait {
                        Some(tr) => format!("{ty}.{}", Self::base_type_name(tr)),
                        None => ty.clone(),
                    };
                    let mut d = container(Some(format!("impl:{full}")), "body")?;
                    d.member_prefix = Some(full);
                    d.impl_for = Some(ty).filter(|ty| !ty.is_empty());
                    let args = [Some(&of_type), of_trait.as_ref()].into_iter().flatten();
                    d.key = key_of(args.filter_map(|t| type_args(t)));
                    Some(d)
                }
                _ => None,
            },
            Lang::Python => match kind {
                "function_definition" => leaf(name("name")),
                "class_definition" => container(name("name"), "body"),
                _ => None,
            },
            Lang::TypeScript | Lang::Tsx | Lang::JavaScript => match kind {
                "function_declaration"
                | "generator_function_declaration"
                | "function_signature"
                | "method_definition"
                | "method_signature"
                | "abstract_method_signature" => leaf(name("name")),
                "class_declaration" | "abstract_class_declaration" => {
                    container(name("name"), "body")
                }
                "interface_declaration" | "type_alias_declaration" | "enum_declaration" => {
                    leaf(name("name"))
                }
                "internal_module" | "module" => container(name("name"), "body"),
                "public_field_definition" => leaf(name("name")),
                "field_definition" => leaf(name("property")),
                "lexical_declaration" | "variable_declaration" => {
                    let decl = n
                        .named_children(&mut n.walk())
                        .find(|c| c.kind() == "variable_declarator")?;
                    let id = decl.child_by_field_name("name")?;
                    if id.kind() != "identifier" {
                        return None;
                    }
                    leaf(Some(self.text(id).to_string()))
                }
                "expression_statement" if self.groups() => {
                    let set = n
                        .named_child(0)
                        .filter(|c| c.kind() == "assignment_expression")?;
                    let left = set.child_by_field_name("left")?;
                    let object = left.child_by_field_name("object").map(|o| self.text(o));
                    if !matches!(object, Some("exports" | "module.exports")) {
                        return None;
                    }
                    let mut d = leaf(self.field_text(left, "property"))?;
                    d.body = set
                        .child_by_field_name("right")?
                        .child_by_field_name("body");
                    Some(d)
                }
                "pair" => {
                    let key = n.child_by_field_name("key")?;
                    let value = n.child_by_field_name("value")?;
                    let is_fn = matches!(
                        value.kind(),
                        "function_expression" | "arrow_function" | "generator_function"
                    );
                    if key.kind() != "property_identifier" || !is_fn {
                        return None;
                    }
                    let mut d = leaf(Some(self.text(key).to_string()))?;
                    d.body = value.child_by_field_name("body");
                    Some(d)
                }
                _ => None,
            },
            Lang::CSharp => {
                let header_start = n
                    .named_children(&mut n.walk())
                    .find(|c| c.kind() != "attribute_list")
                    .map(|c| c.start_byte())
                    .unwrap_or(n.start_byte());
                let mut d = match kind {
                    "class_declaration"
                    | "struct_declaration"
                    | "interface_declaration"
                    | "record_declaration" => container(name("name"), "body"),
                    "enum_declaration"
                    | "delegate_declaration"
                    | "property_declaration"
                    | "event_declaration" => leaf(name("name")),
                    "method_declaration"
                    | "constructor_declaration"
                    | "destructor_declaration"
                    | "local_function_statement"
                    | "variable_declarator" => leaf(name("name")),
                    "operator_declaration" => leaf(Some(format!(
                        "operator{}",
                        name("operator").unwrap_or_default()
                    ))),
                    "conversion_operator_declaration" => leaf(Some("operator_conversion".into())),
                    "indexer_declaration" => leaf(Some("this".into())),
                    "field_declaration" | "event_field_declaration" => {
                        let decl = find_descendant(n, "variable_declarator")?;
                        let id = decl.child_by_field_name("name").or_else(|| {
                            decl.named_children(&mut decl.walk())
                                .find(|c| c.kind() == "identifier")
                        })?;
                        leaf(Some(self.text(id).to_string()))
                    }
                    _ => None,
                }?;
                d.header_start = header_start;
                Some(d)
            }
            Lang::Go => match kind {
                "function_declaration" | "const_spec" | "var_spec" | "type_spec" | "type_alias" => {
                    leaf(name("name"))
                }
                "method_declaration" => {
                    let recv = n.child_by_field_name("receiver")?;
                    let ty = find_descendant(recv, "type_identifier")?;
                    let m = name("name")?;
                    leaf(Some(format!("{}.{m}", self.text(ty))))
                }
                "type_declaration" => {
                    let spec = n
                        .named_children(&mut n.walk())
                        .find(|c| matches!(c.kind(), "type_spec" | "type_alias"))?;
                    leaf(
                        spec.child_by_field_name("name")
                            .map(|c| self.text(c).to_string()),
                    )
                }
                "const_declaration" | "var_declaration" => {
                    let spec = find_descendant(
                        n,
                        if kind == "const_declaration" {
                            "const_spec"
                        } else {
                            "var_spec"
                        },
                    )?;
                    let id = spec.child_by_field_name("name")?;
                    leaf(Some(self.text(id).to_string()))
                }
                _ => None,
            },
        }
    }

    /// `seen` is shared by the whole file so that names are unique per file.
    fn level(
        &self,
        parent: Node,
        prefix: &str,
        out: &mut Vec<Sym>,
        mut imports: Option<&mut Vec<(usize, usize)>>,
        seen: &mut BTreeMap<String, usize>,
        holder: Option<Holder>,
    ) {
        let mut pending: Option<usize> = None;
        // The first of `pending` that a blank line does not part from it.
        let mut firm: Option<usize> = None;
        let mut before: Option<Node> = None;
        let children: Vec<Node> = parent.named_children(&mut parent.walk()).collect();
        for &child in &children {
            if before.is_some_and(|b| self.stands_apart(b, child)) {
                pending = firm;
            }
            before = Some(child).filter(|c| self.is_attachable(*c));
            if self.trails(child) {
                before = None;
                let joined = holder.is_some_and(|h| h.joined);
                match out.last_mut() {
                    Some(last) if !joined && !last.container && self.ends_at(last, child) => {
                        last.tail = Some((last.end, child.start_byte()));
                        last.end = child.end_byte();
                    }
                    _ => {}
                }
                continue;
            }
            if self.is_attachable(child) {
                pending.get_or_insert(child.start_byte());
                if !child.kind().contains("comment") {
                    firm.get_or_insert(child.start_byte());
                }
                continue;
            }
            let attached = pending.take();
            firm = None;
            if let Some(imports) = imports.as_deref_mut()
                && self.is_import(child)
            {
                imports.push((attached.unwrap_or(child.start_byte()), child.end_byte()));
                continue;
            }
            if let Some(group) = self.group(child, prefix.is_empty()) {
                let nth = self.groups_seen.replace(self.groups_seen.get() + 1);
                for (i, members) in (0u32..).zip(group.members) {
                    let held = self
                        .groups()
                        .then(|| holder_of(members, group.joined, (nth, i)));
                    self.level(members, prefix, out, imports.as_deref_mut(), seen, held);
                }
                continue;
            }
            let def_node = self.unwrap_def(child);
            let Some(def) = self.def(def_node) else {
                continue;
            };
            let start = attached.unwrap_or(child.start_byte());
            let base = if prefix.is_empty() {
                def.name.clone()
            } else {
                format!("{prefix}.{}", def.name)
            };
            let key = (self.engine >= ENGINE_KEYS)
                .then(|| self.key(def_node, child, &def))
                .flatten();
            if let Some(census) = &self.census {
                let mut census = census.borrow_mut();
                census.entry(base.clone()).or_default().insert(key.clone());
            }
            let shared = key.filter(|_| self.keyed.contains(&base));
            let named = match &shared {
                Some(key) => format!("{base}{key}"),
                None => base.clone(),
            };
            let count = seen.entry(named.clone()).or_insert(0);
            *count += 1;
            let same_type = self.same_scope(&base, def_node);
            let part_of = (same_type && self.is_partial(def_node)).then(|| base.clone());
            let qualified = if *count == 1 {
                named.clone()
            } else {
                format!("{named}~{count}")
            };
            let plain = shared.as_ref().map(|_| base);
            let under_prefix = |name: &String| match prefix {
                "" => name.clone(),
                _ => format!("{prefix}.{name}"),
            };
            let mut children_syms = Vec::new();
            if let Some(m) = def.members {
                let member_prefix = match (&part_of, &def.member_prefix) {
                    (Some(whole), _) => whole.clone(),
                    // A trait's members are its own, the type's are shared.
                    (None, Some(p)) if def.impl_for.as_ref() != Some(p) => {
                        under_prefix(&format!("{p}{}", shared.as_deref().unwrap_or_default()))
                    }
                    (None, Some(p)) => under_prefix(p),
                    (None, None) => qualified.clone(),
                };
                self.level(m, &member_prefix, &mut children_syms, None, seen, None);
            }
            if self.census.is_some() {
                continue;
            }
            let is_type = def.members.is_some() || TYPE_KINDS.contains(&def_node.kind());
            let def_of = match (&part_of, &def.impl_for) {
                (Some(whole), _) => Some(whole.clone()),
                (None, Some(ty)) => Some(under_prefix(ty)),
                (None, None) => is_type.then(|| qualified.clone()),
            };
            // The `;` behind a member of a TypeScript class is a sibling, and
            // it comes and goes with that member.
            let closer = child.next_sibling().filter(|c| c.kind() == ";");
            let end = closer
                .filter(|_| self.engine >= ENGINE_KEYS)
                .map_or(child.end_byte(), |c| c.end_byte());
            let around = match holder {
                Some(h) if h.joined => (
                    children
                        .iter()
                        .rev()
                        .map(|c| c.end_byte())
                        .find(|e| *e <= start),
                    children.iter().map(|c| c.start_byte()).find(|s| *s >= end),
                ),
                _ => (None, None),
            };
            let cut: Vec<(usize, usize)> = children_syms.iter().map(|s| (s.start, s.end)).collect();
            let marks = children_syms.iter();
            let marks: Vec<Mark> = marks.map(|s| (s.start, s.end, s.name.as_str())).collect();
            let mut own_exact = String::new();
            let mut spots = Vec::new();
            let own = if def.members.is_some() {
                own_exact.push_str(&self.src[start..child.start_byte()]);
                let mut holders = holders_of(&children_syms);
                let body = def.members.filter(|_| self.groups());
                holders.extend(body.map(|m| holder_of(m, false, (0, 0))));
                exact_text(
                    child,
                    self.src,
                    &marks,
                    &holders,
                    &mut own_exact,
                    &mut spots,
                );
                normalize(&remove_spans(self.src, start, end, &cut))
            } else {
                normalize(&self.src[start..end])
            };
            let signature = def
                .body
                .map(|b| normalize(&self.src[def.header_start..b.start_byte()]));
            let attached = &self.src[start..def.header_start.max(start)];
            let (is_test, skipped) = self.test_markers(&def, def_node, &qualified, attached);
            out.push(Sym {
                name: qualified,
                plain,
                stem: named,
                start,
                end,
                def_start: def_node.start_byte(),
                own,
                own_exact,
                spots,
                signature,
                def_of,
                holder,
                around,
                tail: None,
                is_test,
                skipped,
                container: def.members.is_some(),
                children: children_syms,
            });
        }
    }

    fn test_markers(&self, def: &Def, n: Node, qualified: &str, attached: &str) -> (bool, bool) {
        let leaf_name = qualified.rsplit('.').next().unwrap_or(qualified);
        if def.members.is_some() {
            return (false, false);
        }
        match self.lang {
            Lang::Rust => {
                let is_fn = n.kind() == "function_item";
                let t = is_fn
                    && (attached.contains("#[test")
                        || attached.contains("::test")
                        || attached.contains("#[rstest"));
                (t, t && attached.contains("#[ignore"))
            }
            Lang::Python => {
                let in_test_class = match qualified.rsplit_once('.') {
                    Some((cls, _)) => cls.rsplit('.').next().unwrap_or(cls).starts_with("Test"),
                    None => true,
                };
                let t = n.kind() == "function_definition"
                    && leaf_name.starts_with("test")
                    && in_test_class;
                // Decorators live between the span start and the `def`.
                (t, t && attached.contains("skip"))
            }
            Lang::CSharp => {
                let attrs = &self.src[n.start_byte()..def.header_start];
                let t = [
                    "[Fact",
                    "[Theory",
                    "[Test",
                    "[TestMethod",
                    "[TestCase",
                    "[DataTestMethod",
                    ", Fact",
                    ", Test",
                ]
                .iter()
                .any(|m| attrs.contains(m));
                (t, t && (attrs.contains("Skip") || attrs.contains("Ignore")))
            }
            Lang::Go => {
                let t = n.kind() == "function_declaration" && leaf_name.starts_with("Test");
                (t, t && self.text(n).contains(".Skip("))
            }
            Lang::TypeScript | Lang::Tsx | Lang::JavaScript => (false, false),
        }
    }

    /// `it("..")` / `test("..")` calls, named by their `describe` path.
    fn js_tests(&self, root: Node) -> Vec<JsTest> {
        let mut out = Vec::new();
        self.walk_calls(root, &mut Vec::new(), false, &mut out);
        out
    }

    fn walk_calls(&self, n: Node, path: &mut Vec<String>, skipped: bool, out: &mut Vec<JsTest>) {
        if n.kind() == "call_expression"
            && let Some((callee, modifier)) = self.callee(n)
        {
            let title = n
                .child_by_field_name("arguments")
                .and_then(|a| a.named_children(&mut a.walk()).next())
                .filter(|a| matches!(a.kind(), "string" | "template_string"))
                .map(|a| {
                    self.text(a)
                        .trim_matches(|c| c == '"' || c == '\'' || c == '`')
                        .to_string()
                });
            let skip_here = callee.starts_with('x')
                || matches!(modifier.as_deref(), Some("skip") | Some("todo"));
            if let Some(title) = title {
                match callee.trim_start_matches('x') {
                    "describe" | "context" => {
                        path.push(title);
                        for c in n.named_children(&mut n.walk()) {
                            self.walk_calls(c, path, skipped || skip_here, out);
                        }
                        path.pop();
                        return;
                    }
                    "it" | "test" => {
                        let mut name = path.clone();
                        name.push(title);
                        out.push(JsTest {
                            name: name.join(" > "),
                            text: normalize(self.text(n)),
                            skipped: skipped || skip_here,
                        });
                        return;
                    }
                    _ => {}
                }
            }
        }
        for c in n.named_children(&mut n.walk()) {
            self.walk_calls(c, path, skipped, out);
        }
    }

    fn callee(&self, call: Node) -> Option<(String, Option<String>)> {
        let f = call.child_by_field_name("function")?;
        match f.kind() {
            "identifier" => Some((self.text(f).to_string(), None)),
            "member_expression" => {
                let obj = f.child_by_field_name("object")?;
                let prop = f.child_by_field_name("property")?;
                (obj.kind() == "identifier").then(|| {
                    (
                        self.text(obj).to_string(),
                        Some(self.text(prop).to_string()),
                    )
                })
            }
            _ => None,
        }
    }
}

fn find_descendant<'t>(n: Node<'t>, kind: &str) -> Option<Node<'t>> {
    if n.kind() == kind {
        return Some(n);
    }
    let children: Vec<Node> = n.named_children(&mut n.walk()).collect();
    children.into_iter().find_map(|c| find_descendant(c, kind))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::ENGINE_KEYS;

    fn find<'a>(s: &'a [Sym], name: &str) -> &'a Sym {
        fn walk<'a>(s: &'a [Sym], name: &str) -> Option<&'a Sym> {
            let inner = |x: &'a Sym| walk(&x.children, name);
            s.iter()
                .find(|x| x.name == name)
                .or(s.iter().find_map(inner))
        }
        walk(s, name).unwrap_or_else(|| panic!("no {name}"))
    }

    /// Who has a definition: containers and types, and an `impl` has its
    /// type's, also inside a module and for a trait.
    fn keyed_names_of(path: &str, src: &str) -> Vec<String> {
        fn walk(syms: &[Sym], out: &mut Vec<String>) {
            for s in syms {
                out.push(s.name.clone());
                walk(&s.children, out);
            }
        }
        let parsed = parse(Lang::detect(path).unwrap(), src);
        assert!(!parsed.has_error, "{src}");
        let mut out = Vec::new();
        walk(&parsed.syms, &mut out);
        out
    }

    #[test]
    fn symbols_of_one_name_are_told_apart_by_what_they_take() {
        let src = "class C {\n void M(int a, System.String b = \"x\") {}\n void M(ref int a) {}\n void M(params int[] a) {}\n void M(Dictionary<string, int> d /* map */) {}\n public int this[int i] { get; }\n public int this[string i] { get; }\n public static C operator +(C a, C b) => a;\n public static C operator +(C a, int b) => a;\n C() {}\n C(int a) {}\n}\n";
        assert_eq!(
            keyed_names_of("a.cs", src),
            [
                "C",
                "C.M(int,System::String)",
                "C.M(ref int)",
                "C.M(int[])",
                "C.M(Dictionary<string,int>)",
                "C.this(int)",
                "C.this(string)",
                "C.operator+(C,C)",
                "C.operator+(C,int)",
                "C.C()",
                "C.C(int)",
            ]
        );
        let src = "function f(a: string): void;\nfunction f(a: number, b?: string): void;\nfunction f(a: any) {}\nclass V {\n  get v() { return 1; }\n  set v(x: number) {}\n}\n";
        assert_eq!(
            keyed_names_of("a.ts", src),
            [
                "f(string)",
                "f(number,string?)",
                "f(any)",
                "V",
                "V.v[get]",
                "V.v[set]"
            ]
        );
        let src = "class P:\n    @property\n    def x(self):\n        return 1\n    @x.setter\n    def x(self, v):\n        pass\n    @x.deleter\n    def x(self):\n        pass\n\n@o\ndef f(a: int, b: str = 'x') -> int: ...\ndef f(a, *rest, k=1, **kw): ...\n";
        assert_eq!(
            keyed_names_of("a.py", src),
            [
                "P",
                "P.x(self)",
                "P.x[setter]",
                "P.x[deleter]",
                "f(int,str)",
                "f(a,*rest,k,**kw)",
            ]
        );
        let src = "impl From<u8> for S {\n    fn from(v: u8) {}\n}\nimpl std::convert::From<a::B> for S {\n    fn from(mut v: a::B) {}\n}\nimpl W<u8> {\n    fn new(&self) {}\n}\nimpl W<u16> {\n    fn new(&self) {}\n}\n";
        assert_eq!(
            keyed_names_of("a.rs", src),
            [
                "impl:S.From(u8)",
                "S.From(u8).from",
                "impl:S.From(a::B)",
                "S.From(a::B).from",
                "impl:W(u8)",
                "W.new",
                "impl:W(u16)",
                "W.new~2",
            ]
        );
    }

    /// Each row: two symbols of one name and what tells them apart.
    #[test]
    fn overloads_differ_by_more_than_their_parameters() {
        let rows: [(&str, &str, [&str; 3]); 8] = [
            (
                "a.cs",
                "class C { public static implicit operator int(C c) => 1; public static implicit operator long(C c) => 1; }",
                [
                    "C",
                    "C.operator_conversion(int,C)",
                    "C.operator_conversion(long,C)",
                ],
            ),
            (
                "a.cs",
                "class C { void IA.M() {} void IB.M() {} }",
                ["C", "C.M(IA)", "C.M(IB)"],
            ),
            (
                "a.cs",
                "class C { void G<T>() {} void G<T, U>() {} }",
                ["C", "C.G(<1>)", "C.G(<2>)"],
            ),
            (
                "a.cs",
                "class C { C() {} ~C() {} }",
                ["C", "C.C()", "C.C[destructor]"],
            ),
            (
                "a.ts",
                "class C { static m(a: string) {} m(a: string) {} }",
                ["C", "C.m(static,string)", "C.m(string)"],
            ),
            (
                "a.ts",
                "class C { m(a: number) {} m(a?: number) {} }",
                ["C", "C.m(number)", "C.m(number?)"],
            ),
            (
                "a.py",
                "class C:\n    @f.register\n    def f(self, a: int):\n        pass\n    @f.register\n    def f(self, a: str):\n        pass\n",
                ["C", "C.f(self,int)", "C.f(self,str)"],
            ),
            (
                "a.js",
                "class C { m(a = 1) {} m(b, c) {} }",
                ["C", "C.m(a)", "C.m(b,c)"],
            ),
        ];
        for (path, src, want) in rows {
            assert_eq!(keyed_names_of(path, src), want, "{src}");
        }
    }

    /// A decorator that takes arguments is no accessor, and holds no level.
    #[test]
    fn a_decorator_argument_stays_out_of_a_name() {
        let src = "@f.register(os.PathLike)\ndef f(a):\n    pass\n@f.register(str)\ndef f(b):\n    pass\n";
        assert_eq!(keyed_names_of("a.py", src), ["f(a)", "f(b)"]);
    }

    #[test]
    fn a_long_key_is_cut_and_the_rest_is_numbered() {
        let long = ["int a"; 150].join(", ");
        let src =
            format!("class C {{ void M({long}) {{}} void M({long}, int b) {{}} void M() {{}} }}");
        let names = keyed_names_of("a.cs", &src);
        let keyed = format!("C.M({})", vec!["int"; 50].join(","));
        assert_eq!(keyed.len(), "C.M(".len() + 199 + 1);
        assert_eq!(
            names[1].trim_end_matches([',', ')']),
            keyed.trim_end_matches(')')
        );
        assert_eq!(names[2], format!("{}~2", names[1]));
        assert_eq!(names[3], "C.M()");
    }

    #[test]
    fn a_key_is_cut_between_characters() {
        let long = "ü".repeat(150);
        let key = key_of([long].iter()).unwrap();
        assert!(key.len() <= MAX_KEY + 3, "{}", key.len());
    }

    /// Past what is compared, source order pairs them: the cost of a change
    /// is not the square of a file. Up to it, the texts do.
    #[test]
    fn overloads_pair_by_their_text_up_to_a_limit() {
        let list = |ty: &str, n: usize, reversed: bool| {
            let methods = (0..n).map(|i| {
                let j = if reversed { n - 1 - i } else { i };
                format!("void M({ty}{i} a) {{ Run{j}(); Go{j}(); Do{j}(); }} ")
            });
            let methods = methods.collect::<String>();
            format!("class C {{ {methods}void Z() {{}} }}")
        };
        let first_pair = |n: usize| {
            let (old, new) = (list("A", n, false), list("B", n, true));
            let [a, mut b] = parse_together(ENGINE_KEYS, Lang::CSharp, [&old, &new]);
            let pairs = align(&a, &mut b);
            assert_eq!(pairs.len(), n);
            let first = pairs.iter().find(|p| p.base == "C.M(A0)").unwrap();
            first.side.clone()
        };
        assert_ne!(first_pair(8), "C.M(B0)", "8 x 8 is 64: compared");
        assert_eq!(first_pair(9), "C.M(B0)", "9 x 9 is past it: source order");
    }

    /// A pair is found by its own name and text, whatever another pair has.
    #[test]
    fn a_symbol_of_a_merge_finds_its_own_pair() {
        let src = "def f(a: int):\n    pass\ndef f(a: bytes):\n    pass\ndef g(a: int):\n    pass\ndef g(a: bytes):\n    pass\n";
        let mut merged = parse_at(ENGINE_KEYS, Lang::Python, src);
        let own = merged.syms[1].own.clone();
        let pair = |stem: &str, base: &str, own: String, at| Pair {
            side: stem.into(),
            stem: stem.into(),
            base: base.into(),
            own,
            at,
        };
        let pairs = [
            pair("g(bytes)", "g(old)", own, 0),
            pair("f(bytes)", "f(old)", "other text".into(), 1),
        ];
        rename_aligned(&mut merged, &pairs);
        let names: Vec<&str> = merged.syms.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(names, ["f(int)", "f(old)", "g(int)", "g(old)"]);
    }

    /// A later engine reads names as this one does.
    #[test]
    fn keys_hold_for_later_engines() {
        let src = "class C { void M(int a) {} void M(string s) {} }";
        let [p] = parse_together(ENGINE_KEYS + 1, Lang::CSharp, [src]);
        assert_eq!(p.syms[0].children[0].name, "C.M(int)");
    }

    /// The key is how a symbol is known among others, so nothing that can
    /// change with the same symbol is in it, and nothing that would read as
    /// a level of the name.
    #[test]
    fn a_key_holds_what_the_symbol_takes_and_no_dot() {
        let names = |src: &str| keyed_names_of("a.cs", src);
        let a = names("class C { void M(int a = 1) {} void M(N.T b) {} }");
        let b = names("class C { void M(int z = 2) {} void M(N.T y) {} }");
        assert_eq!(a, b);
        assert_eq!(a, ["C", "C.M(int)", "C.M(N::T)"]);
    }

    /// A symbol alone with its name has no key, in any language.
    #[test]
    fn a_name_with_one_symbol_is_only_the_name() {
        assert_eq!(
            keyed_names_of("a.cs", "class C { void M(int a) {} }"),
            ["C", "C.M"]
        );
        assert_eq!(keyed_names_of("a.py", "def f(a):\n    pass\n"), ["f"]);
    }

    #[test]
    fn exact_duplicates_keep_their_number() {
        let src = "package p\nfunc init() {}\nfunc init() {}\n";
        assert_eq!(keyed_names_of("a.go", src), ["init", "init~2"]);
        let src = "class C { void M(int a) {} void M(int b) {} void M(string s) {} }";
        assert_eq!(
            keyed_names_of("a.cs", src),
            ["C", "C.M(int)", "C.M(int)~2", "C.M(string)"]
        );
    }

    #[test]
    fn engines_before_keys_number_by_order() {
        let src = "class C { void M(int a) {} void M(string s) {} }";
        let names = parse_at(ENGINE_KEYS - 1, Lang::CSharp, src).syms[0]
            .children
            .iter()
            .map(|s| s.name.clone())
            .collect::<Vec<_>>();
        assert_eq!(names, ["C.M", "C.M~2"]);
    }

    /// Every version of a file reads a name the way the one that needs a
    /// key does, and the rest of the code is none the wiser.
    #[test]
    fn versions_read_together_share_their_names() {
        let one = "class C { void M(int a) {} }";
        let two = "class C { void M(string s) {} void M(int a) {} }";
        let [a, b] = parse_together(ENGINE_KEYS, Lang::CSharp, [one, two]);
        assert_eq!(a.syms[0].children[0].name, "C.M(int)");
        assert_eq!(a.syms[0].children[0].plain.as_deref(), Some("C.M"));
        assert_eq!(b.syms[0].children[1].name, "C.M(int)");
        assert_eq!(a.syms[0].spots, b.syms[0].spots[1..]);
        assert_eq!(
            parse_at(ENGINE_KEYS, Lang::CSharp, one).syms[0].children[0].plain,
            None
        );
    }

    #[test]
    fn a_new_key_keeps_the_name_of_the_base() {
        let old = "class C { void M(int a) {} void M(string s) {} void N() {} }";
        let new = "class C { void M(long a) {} void M(string s) {} void N() {} }";
        let [a, mut b] = parse_together(ENGINE_KEYS, Lang::CSharp, [old, new]);
        align(&a, &mut b);
        assert_eq!(a.syms[0].children[0].name, b.syms[0].children[0].name);
        assert_eq!(a.syms[0].spots, b.syms[0].spots);
        // A symbol with no partner stays what it is.
        let new = "class C { void M(long a) {} void M(short s) {} void M(byte b) {} void N() {} }";
        let [a, mut b] = parse_together(ENGINE_KEYS, Lang::CSharp, [old, new]);
        let pairs = align(&a, &mut b);
        assert_eq!(pairs.len(), 2);
        let names: Vec<&str> = b.syms[0].children.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"C.M(byte)") || names.contains(&"C.M(short)"),
            "{names:?}"
        );
    }

    /// Containers keep their name: their members hang on the key.
    #[test]
    fn a_container_is_not_aligned() {
        let old =
            "impl From<u8> for S {\n    fn a() {}\n}\nimpl From<u16> for S {\n    fn a() {}\n}\n";
        let new = old.replace("<u8>", "<u32>");
        let [a, mut b] = parse_together(ENGINE_KEYS, Lang::Rust, [old, &new]);
        align(&a, &mut b);
        assert_eq!(b.syms[0].name, "impl:S.From(u32)");
    }

    #[test]
    fn definitions_belong_to_types() {
        let src = "struct S;\nenum E { A }\ntype T = u8;\nfn f() {}\nconst C: u8 = 1;\n\
                   trait R {}\nimpl S {}\nimpl From<u8> for S {}\n\
                   mod m {\n    struct S;\n    impl S {}\n    impl R for S {}\n}\n";
        let p = parse(Lang::Rust, src);
        for (name, want) in [
            ("S", Some("S")),
            ("E", Some("E")),
            ("T", Some("T")),
            ("R", Some("R")),
            ("f", None),
            ("C", None),
            ("impl:S", Some("S")),
            ("impl:S.From", Some("S")),
            ("m", Some("m")),
            ("m.S", Some("m.S")),
            ("m.impl:S", Some("m.S")),
            ("m.impl:S.R", Some("m.S")),
        ] {
            assert_eq!(find(&p.syms, name).def_of.as_deref(), want, "{name}");
        }
        let g = parse(
            Lang::Go,
            "package p\ntype T struct{}\nfunc (t T) M() {}\nfunc F() {}\n",
        );
        assert_eq!(find(&g.syms, "T").def_of.as_deref(), Some("T"));
        assert_eq!(find(&g.syms, "T.M").def_of, None);
        assert_eq!(find(&g.syms, "F").def_of, None);
    }

    /// One name for one change, and a symbol that changed shape is whole.
    #[test]
    fn a_change_is_of_the_definition_only_for_the_same_shape() {
        let p = parse(Lang::Rust, "struct S;\nfn f() {}\nmod m {}\nimpl S {}\n");
        let [s, f, m, i] = ["S", "f", "m", "impl:S"].map(|n| find(&p.syms, n));
        assert_eq!(s.changed_unit(s, 3), "S.<def>");
        assert_eq!(s.changed_unit(s, 2), "S");
        assert_eq!(f.changed_unit(f, 3), "f");
        assert_eq!(m.changed_unit(m, 3), "m.<def>");
        assert_eq!(i.changed_unit(i, 3), "S.<def>");
        assert_eq!(i.changed_unit(i, 2), "impl:S");
        // Same name, other shape: a `mod m;` and a `mod m {}`.
        let q = parse(Lang::Rust, "mod m;\nfn S() {}\n");
        let (m2, s2) = (find(&q.syms, "m"), find(&q.syms, "S"));
        assert_eq!(m.changed_unit(m2, 3), "m");
        assert_eq!(m2.changed_unit(m, 3), "m");
        assert_eq!(s.changed_unit(s2, 3), "S");
        assert_eq!(s2.changed_unit(s, 3), "S");
        // A `record` with no body is a type and no container.
        let c = parse(Lang::CSharp, "class R { }\n");
        let d = parse(Lang::CSharp, "record R(int A);\n");
        let (cr, dr) = (find(&c.syms, "R"), find(&d.syms, "R"));
        assert_eq!(dr.changed_unit(dr, 3), "R.<def>");
        assert_eq!(cr.changed_unit(dr, 3), "R");
        assert_eq!(dr.changed_unit(cr, 3), "R");
    }

    /// What counts as code changing places, and what does not.
    #[test]
    fn code_shifts_against_symbols_both_sides_have() {
        let py = |src| parse(Lang::Python, src);
        let moved = |a, b| shifted(py(a).placed(), py(b).placed());
        let base = "x = 1\ndef a(): pass\ny = 2\ndef b(): pass\n";
        assert!(!moved(base, base));
        // Past a symbol, in either direction.
        assert!(moved(base, "def a(): pass\nx = 1\ny = 2\ndef b(): pass\n"));
        assert!(moved(base, "x = 1\ndef a(): pass\ndef b(): pass\ny = 2\n"));
        // Symbols around the code changing places move it too.
        assert!(moved(base, "x = 1\ndef b(): pass\ny = 2\ndef a(): pass\n"));
        // Adding or removing a symbol moves nothing.
        assert!(!moved(
            base,
            "x = 1\ndef a(): pass\ndef n(): pass\ny = 2\ndef b(): pass\n"
        ));
        assert!(!moved(base, "x = 1\ny = 2\ndef b(): pass\n"));
        // Symbols side by side changing places have no code between them.
        assert!(!moved(
            "x = 1\ndef a(): pass\ndef b(): pass\n",
            "x = 1\ndef b(): pass\ndef a(): pass\n"
        ));
        // An import is a place too, with its comment or a twin of it.
        assert!(moved("import o\nx = 1\n", "x = 1\nimport o\n"));
        assert!(moved("# a\nimport o\nx = 1\n", "x = 1\n# b\nimport o\n"));
        let twice = "import o\nx = 1\nimport o\ndef f(): pass\n";
        assert!(moved(twice, "import o\nimport o\nx = 1\ndef f(): pass\n"));
        // A comment and its symbol are one: one spot, not two.
        let p = py("# about\n# a\ndef a(): pass\n");
        assert_eq!(p.spots.len(), 1);
        // Inside a container, members are the symbols.
        let cls = |src| parse(Lang::Python, src).syms.remove(0);
        let a = cls("class A:\n    x = 1\n    def a(self): pass\n");
        let b = cls("class A:\n    def a(self): pass\n    x = 1\n");
        assert!(shifted(a.placed(), b.placed()));
        assert!(!shifted(a.placed(), a.placed()));
    }

    /// A type with no plain name has no definition to share.
    #[test]
    fn an_impl_of_a_projected_type_is_its_own_definition() {
        let p = parse(Lang::Rust, "impl R for <T as X>::Y {}\n");
        let i = &p.syms[0];
        assert_eq!(i.def_of.as_ref(), Some(&i.name));
        assert_eq!(i.impl_of(3), None);
    }

    #[test]
    fn only_an_impl_stands_for_another_type() {
        let p = parse(Lang::Rust, "struct S;\nimpl S {}\nfn f() {}\n");
        assert_eq!(find(&p.syms, "impl:S").impl_of(3), Some("S"));
        assert_eq!(find(&p.syms, "impl:S").impl_of(2), None);
        assert_eq!(find(&p.syms, "S").impl_of(3), None);
        assert_eq!(find(&p.syms, "f").impl_of(3), None);
    }

    fn names(p: &Parsed) -> Vec<String> {
        fn walk(s: &[Sym], out: &mut Vec<String>) {
            for x in s {
                out.push(x.name.clone());
                walk(&x.children, out);
            }
        }
        let mut v = Vec::new();
        walk(&p.syms, &mut v);
        v
    }

    #[test]
    fn rust() {
        let src = r#"use std::fmt;

/// Charges money.
#[inline]
pub fn charge(amount: u64) -> u64 { amount }

struct Client { id: u32 }

impl Client {
    pub fn refund(&self) {}
    fn helper(&self) -> u8 { 1 }
}

impl fmt::Display for Client {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { Ok(()) }
}

const LIMIT: u32 = 3;

#[cfg(test)]
mod tests {
    #[test]
    fn works() {}
    #[test]
    #[ignore]
    fn slow() {}
}
"#;
        let p = parse(Lang::Rust, src);
        assert!(!p.has_error);
        assert_eq!(
            names(&p),
            vec![
                "charge",
                "Client",
                "impl:Client",
                "Client.refund",
                "Client.helper",
                "impl:Client.Display",
                "Client.Display.fmt",
                "LIMIT",
                "tests",
                "tests.works",
                "tests.slow"
            ]
        );
        let charge = &p.syms[0];
        assert!(
            charge.text(src).starts_with("/// Charges money."),
            "doc comment and attribute attach"
        );
        assert_eq!(
            charge.signature.as_deref(),
            Some("pub fn charge(amount: u64) -> u64")
        );
        let tests = p.tests(src);
        assert_eq!(tests.len(), 2);
        assert!(!tests["tests.works"].1);
        assert!(tests["tests.slow"].1, "ignored test is skipped");
        assert_eq!(p.imports.len(), 1);
    }

    #[test]
    fn python() {
        let src = "import os\nfrom x import y\n\nCONST = 1\n\n@decorator\ndef top(a):\n    return a\n\nclass TestThing:\n    def test_one(self):\n        pass\n\n    @pytest.mark.skip\n    def test_two(self):\n        pass\n\n    def helper(self):\n        pass\n";
        let p = parse(Lang::Python, src);
        assert!(!p.has_error);
        assert_eq!(
            names(&p),
            vec![
                "top",
                "TestThing",
                "TestThing.test_one",
                "TestThing.test_two",
                "TestThing.helper"
            ]
        );
        assert!(p.syms[0].text(src).starts_with("@decorator"));
        let t = p.tests(src);
        assert_eq!(t.len(), 2);
        assert!(t["TestThing.test_two"].1);
        assert_eq!(p.imports.len(), 2);
        assert!(p.residual.contains("CONST = 1"));
    }

    #[test]
    fn typescript() {
        let src = "import { a } from './a';\n\nexport function charge(x: number): number { return x; }\n\nexport class Client {\n  private id = 1;\n  refund(): void {}\n  static make() { return new Client(); }\n}\n\nconst helper = () => 1;\nexport interface Shape { w: number }\ntype Id = string;\n\ndescribe('Client', () => {\n  it('refunds', () => {});\n  it.skip('slow', () => {});\n});\n";
        let p = parse(Lang::TypeScript, src);
        assert!(!p.has_error);
        assert_eq!(
            names(&p),
            vec![
                "charge",
                "Client",
                "Client.id",
                "Client.refund",
                "Client.make",
                "helper",
                "Shape",
                "Id"
            ]
        );
        let t = p.tests(src);
        assert_eq!(t.len(), 2);
        assert!(t["test:Client > slow"].1);
        assert!(!t["test:Client > refunds"].1);
    }

    #[test]
    fn csharp() {
        let src = "using System;\nusing Xunit;\n\nnamespace Billing\n{\n    public class Client\n    {\n        private int _id;\n        public Client(int id) { _id = id; }\n        public int Charge(int a) => a;\n        public int Charge(int a, int b) => a + b;\n        public string Name { get; set; }\n    }\n\n    public class ClientTests\n    {\n        [Fact]\n        public void Works() { }\n\n        [Fact(Skip = \"slow\")]\n        public void Slow() { }\n    }\n}\n";
        let p = parse(Lang::CSharp, src);
        assert!(!p.has_error, "{src}");
        assert_eq!(
            names(&p),
            vec![
                "Client",
                "Client._id",
                "Client.Client",
                "Client.Charge(int)",
                "Client.Charge(int,int)",
                "Client.Name",
                "ClientTests",
                "ClientTests.Works",
                "ClientTests.Slow"
            ]
        );
        let t = p.tests(src);
        assert_eq!(t.len(), 2);
        assert!(t["ClientTests.Slow"].1);
        assert_eq!(p.imports.len(), 2);
        let charge = &p.syms[0].children[2];
        assert_eq!(
            charge.signature.as_deref(),
            Some("public int Charge(int a)"),
            "arrow bodies are cut too"
        );
    }

    #[test]
    fn go() {
        let src = "package billing\n\nimport \"fmt\"\n\ntype Client struct{ id int }\n\nfunc (c *Client) Charge(a int) int { return a }\n\nfunc New() *Client { return &Client{} }\n\nfunc TestNew(t *testing.T) { t.Skip(\"x\") }\n\nconst Limit = 3\n";
        let p = parse(Lang::Go, src);
        assert!(!p.has_error);
        assert_eq!(
            names(&p),
            vec!["Client", "Client.Charge", "New", "TestNew", "Limit"]
        );
        let t = p.tests(src);
        assert!(t["TestNew"].1);
        assert_eq!(p.imports.len(), 1);
    }

    #[test]
    fn a_name_moved_is_one_that_loses_its_place_among_the_common_ones() {
        let m = |a: &[&str], b: &[&str]| moved(a, b);
        assert_eq!(m(&["a", "b", "c"], &["c", "b", "a"]), ["c", "a"]);
        assert_eq!(m(&["a", "b"], &["b", "a"]), ["b", "a"]);
        assert!(m(&["a", "b"], &["a", "b"]).is_empty());
        // Added and deleted names shift nothing.
        assert!(m(&["a", "b", "c"], &["x", "a", "c", "y"]).is_empty());
        assert!(m(&[], &["a"]).is_empty());
    }

    fn exact(lang: Lang, src: &str) -> String {
        parse(lang, src).residual_exact
    }

    #[test]
    fn exact_text_ignores_layout_and_keeps_what_the_program_means() {
        let py = "X = 1\nif X:\n    a = 1\n    b = 2\n";
        assert_eq!(
            exact(Lang::Python, py),
            exact(Lang::Python, &py.replace("X = 1", "X  =  1"))
        );
        assert_eq!(
            exact(Lang::Python, py),
            exact(Lang::Python, &py.replace("a = 1\n", "a = 1\n\n"))
        );
        // Indentation that means something, and both ends of a block.
        assert_ne!(
            exact(Lang::Python, py),
            exact(Lang::Python, &py.replace("    b = 2", "b = 2"))
        );
        assert_ne!(
            exact(Lang::Python, py),
            exact(Lang::Python, &py.replace("X = 1", "X = 2"))
        );
        // Whitespace in a token, also around an escape inside the string.
        let s = "X = \"a  \\n b\"\n";
        assert_ne!(
            exact(Lang::Python, s),
            exact(Lang::Python, &s.replace("a  ", "a "))
        );
        let r = "const fn f() {}\nstatic S: &str = \"\";\nm!(\"a  b\");\n";
        // Engine 5 reads the macro call as a symbol: its text is compared.
        let old = |src: &str| parse_at(4, Lang::Rust, src).residual_exact;
        assert_ne!(old(r), old(&r.replace("a  b", "a b")));
        let c = "# one  two\nX = 1\n";
        assert_ne!(
            exact(Lang::Python, c),
            exact(Lang::Python, &c.replace("one  two", "one two"))
        );
    }

    #[test]
    fn exact_text_leaves_symbols_and_imports_out() {
        let src = "import os\nX = 1\ndef f():\n    return 1\nY = 2\n";
        let base = exact(Lang::Python, src);
        assert_eq!(
            base,
            exact(Lang::Python, &src.replace("return 1", "return 2"))
        );
        assert_eq!(
            base,
            exact(Lang::Python, &src.replace("import os", "import sys"))
        );
        assert!(base.contains('X') && base.contains('Y'), "{base}");
        assert!(!base.contains("return") && !base.contains("os"), "{base}");
    }

    #[test]
    fn each_engine_reads_its_own_text() {
        let p = parse(
            Lang::Python,
            "class C:\n    x  =  1\n    def m(self):\n        pass\nY  =  2\n",
        );
        assert_eq!(p.residual_at(1), "Y = 2");
        assert_eq!(p.residual_at(2), p.residual_exact);
        assert_ne!(p.residual_exact, p.residual);
        let c = &p.syms[0];
        assert_eq!(c.own_at(1), "class C: x = 1");
        assert_eq!(c.own_at(2), c.own_exact);
        assert!(!c.own_exact.contains("pass"), "{}", c.own_exact);
        assert!(c.own_exact.contains("x"), "{}", c.own_exact);
        assert_eq!(
            c.children[0].own_at(2),
            "",
            "a leaf has no own text to compare"
        );
    }

    #[test]
    fn a_comment_attached_to_a_container_is_part_of_its_own_text() {
        let src = "// one\nimpl C {\n    fn a() {}\n}\n";
        let own = |s: &str| parse(Lang::Rust, s).syms[0].own_exact.clone();
        assert_ne!(own(src), own(&src.replace("one", "two")));
    }

    fn names_at(engine: u32, lang: Lang, src: &str) -> Vec<String> {
        let p = parse_at(engine, lang, src);
        assert!(!p.has_error, "{src}");
        names(&p)
    }

    /// Each row of what engine 4 could not see, and that it still does not.
    #[test]
    fn engine_5_reads_what_engine_4_left_out() {
        let rows: &[(Lang, &str, &[&str], &[&str])] = &[
            (
                Lang::Go,
                "package p\ntype (\n\tA struct{}\n\tB = int\n)\nconst (\n\tX = 1\n\tY = 2\n)\nvar (\n\ta = 1\n\tb = 2\n)\n",
                &["A", "B", "X", "Y", "a", "b"],
                &["A", "X", "a"],
            ),
            (
                Lang::CSharp,
                "class C {\n    int a, b;\n    event E x, y;\n    int one;\n}\n",
                &["C", "C.a", "C.b", "C.x", "C.y", "C.one"],
                &["C", "C.a", "C.x", "C.one"],
            ),
            (
                Lang::JavaScript,
                "exports.a = function () {};\nmodule.exports.b = () => 1;\nthing.c = 1;\nmodule.exports = {\n  d() {},\n  e: function () {},\n  f: () => 1,\n  g: 1,\n  'h': function () {},\n  i,\n};\n",
                &["a", "b", "d", "e", "f"],
                &[],
            ),
            (
                Lang::Python,
                "if TYPE_CHECKING:\n    def a(): pass\nelse:\n    class B: pass\ntry:\n    def c(): pass\nexcept E:\n    pass\nif __name__ == \"__main__\":\n    @d\n    def e(): pass\n",
                &["a", "B", "c", "e"],
                &[],
            ),
            (
                Lang::Rust,
                "extern \"C\" {\n    fn a(x: u8);\n    static B: u8;\n}\nm!(x);\nm! { y }\nn::o!(z);\nmod q {\n    r!();\n}\n",
                &["a", "B", "m!", "m!~2", "n::o!", "q", "q.r!"],
                &["q"],
            ),
        ];
        for (lang, src, new, old) in rows {
            assert_eq!(&names_at(5, *lang, src), new, "{src}");
            assert_eq!(&names_at(4, *lang, src), old, "{src}");
        }
    }

    /// What a block holds decides whether it is read at all.
    #[test]
    fn a_python_block_counts_only_when_it_holds_nothing_but_definitions() {
        let py = |src| names_at(5, Lang::Python, src);
        assert!(py("if A:\n    def a(): pass\n    x = 1\n").is_empty());
        assert!(py("if A:\n    from b import c\n    def a(): pass\n").is_empty());
        assert!(py("if A:\n    def a(): pass\nelse:\n    x = 1\n").is_empty());
        assert!(py("try:\n    def a(): pass\nfinally:\n    close()\n").is_empty());
        assert!(py("if A:\n    pass\n").is_empty());
        // Nested ones stay code, and so does a block inside a class.
        assert!(py("if A:\n    if B:\n        def a(): pass\n").is_empty());
        assert_eq!(
            py("class C:\n    if A:\n        def a(self): pass\n"),
            ["C"]
        );
        // A comment or a `pass` is no statement to worry about.
        let src = "if A:\n    # note\n    def a(): pass\nelse:\n    pass\n";
        assert_eq!(py(src), ["a"]);
        // The same name in two branches keeps one id each, by order.
        let src = "if A:\n    def a(): pass\nelse:\n    def a(): pass\n";
        assert_eq!(py(src), ["a", "a~2"]);
    }

    #[test]
    fn go_declarations_without_parentheses_stay_whole() {
        let src = "package p\ntype T struct{}\nconst X, Y = 1, 2\nvar v = 1\n";
        let p = parse_at(5, Lang::Go, src);
        assert_eq!(names(&p), ["T", "X", "v"]);
        assert_eq!(p.syms[0].holder, None);
        assert!(p.syms[1].text(src).starts_with("const"));
        // In a group, a spec is the symbol and a type keeps its definition.
        let src = "package p\ntype (\n\t// about\n\tT struct{}\n)\n";
        let p = parse_at(5, Lang::Go, src);
        let t = &p.syms[0];
        assert_eq!(t.text(src), "// about\n\tT struct{}");
        assert_eq!(t.def_of.as_deref(), Some("T"));
        assert!(t.holder.is_some_and(|h| !h.joined));
        assert!(p.residual_exact.contains("type"), "{}", p.residual_exact);
    }

    #[test]
    fn a_csharp_field_with_one_declarator_is_the_whole_field() {
        let src = "class C { private int a = 1; }\n";
        let p = parse_at(5, Lang::CSharp, src);
        let a = &p.syms[0].children[0];
        assert_eq!(a.text(src), "private int a = 1;");
        assert_eq!(a.holder, None);
        let src = "class C { private int a = 1, b; }\n";
        let p = parse_at(5, Lang::CSharp, src);
        let c = &p.syms[0];
        assert_eq!(c.children[0].text(src), "a = 1");
        assert_eq!(c.children[1].text(src), "b");
        assert!(c.children[0].holder.is_some_and(|h| h.joined));
        assert!(c.own_exact.contains("private"), "{}", c.own_exact);
    }

    #[test]
    fn exports_keep_their_signature() {
        let src = "exports.a = function (x) { return x; };\nmodule.exports = { b: function (y) { return y; }, c(z) {} };\n";
        let p = parse_at(5, Lang::JavaScript, src);
        let sig = |i: usize| p.syms[i].signature.as_deref();
        assert_eq!(sig(0), Some("exports.a = function (x)"));
        assert_eq!(sig(1), Some("b: function (y)"));
        assert_eq!(sig(2), Some("c(z)"));
        assert!(p.syms[0].holder.is_none());
        assert!(p.syms[1].holder.is_some_and(|h| h.joined));
    }

    #[test]
    fn a_method_decorator_belongs_to_the_method() {
        let src = "class C {\n  @Listen('x')\n  @Other()\n  onX() {}\n\n  @Input() f = 1;\n}\n";
        let p = parse_at(5, Lang::TypeScript, src);
        let m = &p.syms[0].children[0];
        assert!(m.text(src).starts_with("@Listen"), "{}", m.text(src));
        assert_eq!(m.signature.as_deref(), Some("onX()"));
        assert_eq!(m.def_start, src.find("onX").unwrap());
        assert!(!p.syms[0].own_exact.contains("Listen"));
        let p = parse_at(4, Lang::TypeScript, src);
        assert!(p.syms[0].children[0].text(src).starts_with("onX"));
        assert!(p.syms[0].own_exact.contains("Listen"));
    }

    /// Only a comment with no blank line under it is about what follows.
    #[test]
    fn a_comment_attaches_across_no_blank_line() {
        let py = "# licence\n\n# doc\ndef f(): pass\n\n# section\n\ndef g(): pass\n";
        let p = parse_at(5, Lang::Python, py);
        assert_eq!(p.syms[0].text(py), "# doc\ndef f(): pass");
        assert_eq!(p.syms[1].text(py), "def g(): pass");
        assert!(p.residual_exact.contains("# licence"));
        assert!(p.residual_exact.contains("# section"));
        assert!(!p.residual_exact.contains("# doc"));
        assert!(
            parse_at(4, Lang::Python, py).syms[0]
                .text(py)
                .starts_with("# licence")
        );
        // A Rust doc comment holds its own line end.
        let rs = "//! crate\n\n/// doc\nfn f() {}\n\n/// apart\n\nfn g() {}\n";
        let p = parse_at(5, Lang::Rust, rs);
        assert_eq!(p.syms[0].text(rs), "/// doc\nfn f() {}");
        assert_eq!(p.syms[1].text(rs), "fn g() {}");
        // Line ends of another system, and an import.
        let crlf = "// apart\r\n\r\n// doc\r\nfn f() {}\r\n";
        let p = parse_at(5, Lang::Rust, crlf);
        assert_eq!(p.syms[0].text(crlf), "// doc\r\nfn f() {}");
        let py = "# licence\n\nimport os\n# about\nimport sys\n";
        let p = parse_at(5, Lang::Python, py);
        assert_eq!(&py[p.imports[0].0..p.imports[0].1], "import os");
        assert!(py[p.imports[1].0..p.imports[1].1].starts_with("# about"));
        // An attribute is no comment: a blank line does not part it.
        let rs = "#[derive(Debug)]\n\nstruct S;\n";
        let p = parse_at(5, Lang::Rust, rs);
        assert_eq!(p.syms[0].start, 0);
    }

    #[test]
    fn a_comment_behind_code_is_not_about_what_follows() {
        let src = "package p\n\nconst (\n\tA = 1 // first\n\tB = 2\n)\n\nfunc F() {} // done\nfunc G() {}\n";
        let p = parse_at(5, Lang::Go, src);
        assert_eq!(p.syms[0].text(src), "A = 1 // first");
        assert_eq!(p.syms[1].text(src), "B = 2");
        assert_eq!(p.syms[2].text(src), "func F() {} // done");
        assert_eq!(p.syms[3].text(src), "func G() {}");
        // A container's own text ends at the node: the comment is code.
        let src = "class C { } // done\nclass D { }\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(p.syms[1].text(src), "class D { }");
        assert_eq!(p.syms[0].text(src), "class C { }");
        assert!(p.residual_exact.contains("done"), "{}", p.residual_exact);
        // Behind an opening brace or a comma it belongs to nobody.
        let src = "class C { // about\n    int a;\n}\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(p.syms[0].children[0].text(src), "int a;");
        let src = "module.exports = {\n  a() {}, // first\n  b() {},\n};\n";
        let p = parse_at(5, Lang::JavaScript, src);
        assert_eq!(p.syms[0].text(src), "a() {}");
        assert_eq!(p.syms[1].text(src), "b() {}");
        // Engine 4 attaches it to what follows.
        let src = "fn f() {} // done\nfn g() {}\n";
        assert_eq!(
            parse_at(4, Lang::Rust, src).syms[1].text(src),
            "// done\nfn g() {}"
        );
    }

    /// A blank line parts a comment, not an attribute in front of it.
    #[test]
    fn an_attribute_outlives_a_comment_that_stands_apart() {
        let src = "#[test]\n// note\n\nfn t() {}\n";
        let p = parse_at(5, Lang::Rust, src);
        assert_eq!(p.syms[0].start, 0);
        assert!(p.tests(src)["t"].0.starts_with("#[test]"));
        let src = "class C {\n  @A()\n  // note\n\n  m() {}\n}\n";
        let p = parse_at(5, Lang::TypeScript, src);
        assert!(p.syms[0].children[0].text(src).starts_with("@A()"));
    }

    /// What a comment behind code needs: nothing but spaces between. In TS
    /// a field's span stops before its `;`.
    #[test]
    fn a_comment_behind_a_separator_is_not_the_symbols() {
        let src = "class C {\n  a = 1; // semi\n  b = 2;\n}\n";
        let p = parse_at(5, Lang::TypeScript, src);
        assert_eq!(p.syms[0].children[0].text(src), "a = 1");
        assert_eq!(p.syms[0].children[1].text(src), "b = 2");
    }

    #[test]
    fn only_an_object_set_on_module_exports_is_a_list() {
        let js = |src| names_at(5, Lang::JavaScript, src);
        assert_eq!(js("exports.x = { a() {} };\n"), ["x"]);
        assert!(js("other = { a() {} };\n").is_empty());
        assert!(js("module.exports = function () {};\n").is_empty());
    }

    /// `partial` is the word, not any modifier a type has.
    #[test]
    fn a_public_type_twice_is_not_partial() {
        let src = "public class C { int a; }\npublic class C { int b; }\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(find(&p.syms, "C~2").def_of.as_deref(), Some("C~2"));
        assert!(names(&p).contains(&"C~2.b".to_string()));
    }

    /// Two namespaces, two types: only parts in one place are one type.
    #[test]
    fn partial_types_in_two_namespaces_are_two_types() {
        let src = "namespace A { partial class C { int a; } }\nnamespace B { partial class C { int b; } }\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(find(&p.syms, "C~2").def_of.as_deref(), Some("C~2"));
        assert!(names(&p).contains(&"C~2.b".to_string()));
    }

    /// One type written in parts of a type or a namespace written twice.
    #[test]
    fn partial_types_in_one_scope_are_one_type() {
        let src = "partial class A\n{\n    partial class C { int x; }\n}\n\npartial class A\n{\n    partial class C { int y; }\n}\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(find(&p.syms, "A.C~2").def_of.as_deref(), Some("A.C"));
        assert!(names(&p).contains(&"A.C.y".to_string()));
        let src = "namespace N { partial class C { int x; } }\nnamespace N { partial class C { int y; } }\nnamespace M { partial class C { int z; } }\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(find(&p.syms, "C~2").def_of.as_deref(), Some("C"));
        assert_eq!(find(&p.syms, "C~3").def_of.as_deref(), Some("C~3"));
        assert_eq!(names(&p), ["C", "C.x", "C~2", "C.y", "C~3", "C~3.z"]);
        let src = "namespace N;\npartial class C { int x; }\npartial class C { int y; }\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(find(&p.syms, "C~2").def_of.as_deref(), Some("C"));
    }

    #[test]
    fn every_comment_behind_code_stays_behind_it() {
        let src = "fn f() {} /* a */ /* b */\nfn g() {}\n";
        let p = parse_at(5, Lang::Rust, src);
        assert_eq!(p.syms[0].text(src), "fn f() {} /* a */ /* b */");
        assert_eq!(p.syms[1].text(src), "fn g() {}");
    }

    /// Where a test's comment starts is layout here too.
    #[test]
    fn a_test_keeps_its_text_when_its_comment_is_realigned() {
        let a = "#[test]\nfn t() {} // c\n";
        let b = "#[test]\nfn t() {}   // c\n";
        let text = |src| parse_at(5, Lang::Rust, src).tests(src)["t"].0.clone();
        assert_eq!(text(a), text(b));
        assert_ne!(text(a), text(&a.replace("// c", "// d")));
    }

    /// Which block a symbol stands in, counted as the file goes.
    #[test]
    fn a_holder_knows_its_group_and_its_block() {
        let src = "if A:\n    def a(): pass\nelse:\n    def b(): pass\nif B:\n    def c(): pass\n";
        let p = parse_at(5, Lang::Python, src);
        let at: Vec<_> = p.syms.iter().map(|s| s.holder.map(|h| h.block)).collect();
        assert_eq!(at, [Some((0, 0)), Some((0, 1)), Some((1, 0))]);
        let src = "package p\nconst (\n)\nvar (\n\tv = 1\n)\n";
        assert_eq!(
            parse_at(5, Lang::Go, src).syms[0].holder.unwrap().block,
            (1, 0)
        );
    }

    /// One id per member, however many parts a type has in a file.
    #[test]
    fn the_parts_of_a_partial_type_share_its_names() {
        let src = "partial class C { int a; void M() {} }\npartial class C { int b; void M(int x) {} }\nclass D { }\nclass D { int z; }\n";
        assert_eq!(
            names_at(5, Lang::CSharp, src),
            [
                "C", "C.a", "C.M", "C~2", "C.b", "C.M~2", "D", "D~2", "D~2.z"
            ]
        );
        let p = parse_at(5, Lang::CSharp, src);
        let part = find(&p.syms, "C~2");
        assert_eq!(part.def_of.as_deref(), Some("C"));
        assert_eq!(part.impl_of(5), Some("C"));
        assert_eq!(part.changed_unit(part, 5), "C.<def>");
        assert_eq!(find(&p.syms, "C").impl_of(5), None);
        assert_eq!(find(&p.syms, "D~2").def_of.as_deref(), Some("D~2"));
        let old = names_at(4, Lang::CSharp, src);
        assert!(old.contains(&"C~2.b".to_string()), "{old:?}");
        // Inside a namespace or a class, the name stays whole.
        let src = "class A { partial class C { } partial class C { int b; } }\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(find(&p.syms, "A.C~2").def_of.as_deref(), Some("A.C"));
        assert!(names(&p).contains(&"A.C.b".to_string()));
    }

    #[test]
    fn a_namespace_is_a_holder_from_engine_5() {
        let src = "namespace A { class C { } }\nnamespace B { class D { } }\n";
        let at = |engine: u32| parse_at(engine, Lang::CSharp, src).syms[1].holder;
        assert_eq!(at(4), None);
        let held = at(5).unwrap();
        assert_eq!(&src[held.start..held.end], "{ class D { } }");
        assert!(!held.joined);
    }

    #[test]
    fn syntax_errors_are_reported() {
        assert!(parse(Lang::Rust, "fn broken( {").has_error);
        assert!(parse(Lang::Python, "def x(:\n  pass").has_error);
    }
}
