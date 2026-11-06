//! Symbol extraction with tree-sitter.
//!
//! A symbol's span includes the attributes, decorators and comments directly
//! in front of it, so that `#[ignore]` or a doc comment counts as part of the
//! function it belongs to. From [`ENGINE_GROUPS`] on, a blank line ends that:
//! a comment that stands apart belongs to the code around it.

use std::collections::{BTreeMap, BTreeSet};

use tree_sitter::Node;

use lonca_core::ops::DEF;

use crate::engine::{ENGINE_CURRENT, ENGINE_DEFS, ENGINE_EXACT, ENGINE_GROUPS};
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
    pub is_test: bool,
    pub skipped: bool,
    pub container: bool,
    pub children: Vec<Sym>,
}

impl Sym {
    pub fn text<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start..self.end]
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
                    out.insert(s.name.clone(), (s.text(src).to_string(), s.skipped));
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
    let ex = Extractor { engine, lang, src };
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

fn holder_of(n: Node, joined: bool) -> Holder {
    Holder {
        kind: n.kind_id(),
        start: n.start_byte(),
        end: n.end_byte(),
        joined,
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
            k if k.ends_with("_clause") => blocks(c, out),
            _ => {}
        }
    }
}

struct Extractor<'s> {
    engine: u32,
    lang: Lang,
    src: &'s str,
}

impl<'s> Extractor<'s> {
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

    /// A comment behind other code on its line.
    fn trails(&self, n: Node) -> bool {
        let row = n.start_position().row;
        let behind = n
            .prev_sibling()
            .is_some_and(|p| p.end_position().row == row);
        self.groups() && n.kind().contains("comment") && behind
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
            (Lang::CSharp, "file_scoped_namespace_declaration") => Some(Group::of(vec![n])),
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
            (Lang::TypeScript | Lang::Tsx | Lang::JavaScript, "expression_statement") if top => {
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
                    let ty = Self::base_type_name(&name("type")?);
                    let full = match name("trait") {
                        Some(tr) => format!("{ty}.{}", Self::base_type_name(&tr)),
                        None => ty.clone(),
                    };
                    let mut d = container(Some(format!("impl:{full}")), "body")?;
                    d.member_prefix = Some(full);
                    d.impl_for = Some(ty).filter(|ty| !ty.is_empty());
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
                for members in group.members {
                    let held = self.groups().then(|| holder_of(members, group.joined));
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
            let count = seen.entry(base.clone()).or_insert(0);
            *count += 1;
            let earlier = out.iter().find(|s| s.name == base);
            let same_place = earlier.is_some_and(|s| s.holder == holder);
            let part_of = (same_place && self.is_partial(def_node)).then(|| base.clone());
            let qualified = if *count == 1 {
                base
            } else {
                format!("{base}~{count}")
            };
            let under_prefix = |name: &String| match prefix {
                "" => name.clone(),
                _ => format!("{prefix}.{name}"),
            };
            let mut children_syms = Vec::new();
            if let Some(m) = def.members {
                let member_prefix = match (&part_of, &def.member_prefix) {
                    (Some(whole), _) => whole.clone(),
                    (None, Some(p)) => under_prefix(p),
                    (None, None) => qualified.clone(),
                };
                self.level(m, &member_prefix, &mut children_syms, None, seen, None);
            }
            let is_type = def.members.is_some() || TYPE_KINDS.contains(&def_node.kind());
            let def_of = match (&part_of, &def.impl_for) {
                (Some(whole), _) => Some(whole.clone()),
                (None, Some(ty)) => Some(under_prefix(ty)),
                (None, None) => is_type.then(|| qualified.clone()),
            };
            let end = child.end_byte();
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
                holders.extend(body.map(|m| holder_of(m, false)));
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
                "Client.Charge",
                "Client.Charge~2",
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

    /// Two namespaces, two types: only parts in one place are one type.
    #[test]
    fn partial_types_in_two_namespaces_are_two_types() {
        let src = "namespace A { partial class C { int a; } }\nnamespace B { partial class C { int b; } }\n";
        let p = parse_at(5, Lang::CSharp, src);
        assert_eq!(find(&p.syms, "C~2").def_of.as_deref(), Some("C~2"));
        assert!(names(&p).contains(&"C~2.b".to_string()));
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
