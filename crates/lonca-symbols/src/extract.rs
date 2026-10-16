//! Symbol extraction with tree-sitter.
//!
//! A symbol's span includes the attributes, decorators and comments directly
//! in front of it, so that `#[ignore]` or a doc comment counts as part of the
//! function it belongs to.

use std::collections::BTreeMap;

use tree_sitter::Node;

use crate::lang::Lang;

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
    /// Normalized declaration header for callables.
    pub signature: Option<String>,
    pub is_test: bool,
    pub skipped: bool,
    pub container: bool,
    pub children: Vec<Sym>,
}

impl Sym {
    pub fn text<'a>(&self, src: &'a str) -> &'a str {
        &src[self.start..self.end]
    }
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
    pub js_tests: Vec<JsTest>,
}

impl Parsed {
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

pub fn parse(lang: Lang, src: &str) -> Parsed {
    let Some(tree) = lang.parse(src) else {
        return Parsed {
            syms: vec![],
            imports: vec![],
            has_error: true,
            residual: normalize(src),
            js_tests: vec![],
        };
    };
    let root = tree.root_node();
    let ex = Extractor { lang, src };
    let mut imports = Vec::new();
    let mut syms = Vec::new();
    ex.level(
        root,
        "",
        &mut syms,
        Some(&mut imports),
        &mut BTreeMap::new(),
    );
    let mut cut: Vec<(usize, usize)> = syms
        .iter()
        .map(|s| (s.start, s.end))
        .chain(imports.iter().copied())
        .collect();
    cut.sort();
    let residual = normalize(&remove_spans(src, 0, src.len(), &cut));
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

struct Def<'t> {
    name: String,
    /// Prefix for members when it differs from `name` (Rust `impl` blocks:
    /// the block is `impl:Client`, its methods are `Client.method`).
    member_prefix: Option<String>,
    /// The node holding nested members, if this is a container.
    members: Option<Node<'t>>,
    /// The function/method body, used to cut the signature.
    body: Option<Node<'t>>,
    /// Where the declaration header starts (after attributes inside the node).
    header_start: usize,
}

struct Extractor<'s> {
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
            Lang::Python
            | Lang::Go
            | Lang::TypeScript
            | Lang::Tsx
            | Lang::JavaScript
            | Lang::CSharp => n.kind() == "comment",
        }
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

    /// Nodes whose members belong to the enclosing level (namespaces) are
    /// flattened: their names do not appear in symbol names.
    fn transparent_members<'t>(&self, n: Node<'t>) -> Option<Node<'t>> {
        match (self.lang, n.kind()) {
            (Lang::CSharp, "namespace_declaration") => n.child_by_field_name("body"),
            (Lang::CSharp, "file_scoped_namespace_declaration") => Some(n),
            _ => None,
        }
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
                members: None,
                body: n.child_by_field_name("body"),
                header_start: n.start_byte(),
            })
        };
        let container = |name: Option<String>, field: &str| {
            name.map(|name| Def {
                name,
                member_prefix: None,
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
                        None => ty,
                    };
                    let mut d = container(Some(format!("impl:{full}")), "body")?;
                    d.member_prefix = Some(full);
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
                    | "local_function_statement" => leaf(name("name")),
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
                "function_declaration" => leaf(name("name")),
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
    ) {
        let mut pending: Option<usize> = None;
        let children: Vec<Node> = parent.named_children(&mut parent.walk()).collect();
        for child in children {
            if self.is_attachable(child) {
                pending.get_or_insert(child.start_byte());
                continue;
            }
            if let Some(imports) = imports.as_deref_mut()
                && self.is_import(child)
            {
                imports.push((
                    pending.take().unwrap_or(child.start_byte()),
                    child.end_byte(),
                ));
                continue;
            }
            if let Some(members) = self.transparent_members(child) {
                pending = None;
                self.level(members, prefix, out, imports.as_deref_mut(), seen);
                continue;
            }
            let def_node = self.unwrap_def(child);
            let Some(def) = self.def(def_node) else {
                pending = None;
                continue;
            };
            let start = pending.take().unwrap_or(child.start_byte());
            let base = if prefix.is_empty() {
                def.name.clone()
            } else {
                format!("{prefix}.{}", def.name)
            };
            let count = seen.entry(base.clone()).or_insert(0);
            *count += 1;
            let qualified = if *count == 1 {
                base
            } else {
                format!("{base}~{count}")
            };
            let mut children_syms = Vec::new();
            if let Some(m) = def.members {
                let member_prefix = match &def.member_prefix {
                    Some(p) if prefix.is_empty() => p.clone(),
                    Some(p) => format!("{prefix}.{p}"),
                    None => qualified.clone(),
                };
                self.level(m, &member_prefix, &mut children_syms, None, seen);
            }
            let end = child.end_byte();
            let own = if def.members.is_some() {
                let cut: Vec<(usize, usize)> =
                    children_syms.iter().map(|s| (s.start, s.end)).collect();
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
                signature,
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
    fn syntax_errors_are_reported() {
        assert!(parse(Lang::Rust, "fn broken( {").has_error);
        assert!(parse(Lang::Python, "def x(:\n  pass").has_error);
    }
}
