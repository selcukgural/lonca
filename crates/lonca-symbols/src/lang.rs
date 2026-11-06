//! The languages the symbol engine reads.
//!
//! A language is data: `languages.toml` says which grammar reads which file
//! and which nodes are definitions, imports and tests. The one thing that can
//! not be data is the grammar, which is compiled code: see [`grammar`].

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use serde::Deserialize;
use tree_sitter::{Language, Parser, Tree};

/// Every grammar in this build, one line each. A grammar is native code, so
/// it can not come from a table, and a new one needs a release.
fn grammar(name: &str) -> Option<Language> {
    Some(match name {
        "rust" => tree_sitter_rust::LANGUAGE.into(),
        "python" => tree_sitter_python::LANGUAGE.into(),
        "typescript" => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        "tsx" => tree_sitter_typescript::LANGUAGE_TSX.into(),
        "javascript" => tree_sitter_javascript::LANGUAGE.into(),
        "c_sharp" => tree_sitter_c_sharp::LANGUAGE.into(),
        "go" => tree_sitter_go::LANGUAGE.into(),
        "java" => tree_sitter_java::LANGUAGE.into(),
        "kotlin" => tree_sitter_kotlin_ng::LANGUAGE.into(),
        "c" => tree_sitter_c::LANGUAGE.into(),
        "cpp" => tree_sitter_cpp::LANGUAGE.into(),
        "ruby" => tree_sitter_ruby::LANGUAGE.into(),
        "php" => tree_sitter_php::LANGUAGE_PHP.into(),
        "swift" => tree_sitter_swift::LANGUAGE.into(),
        _ => return None,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Table {
    language: Vec<Entry>,
    rules: BTreeMap<String, Rules>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    name: String,
    grammar: String,
    extensions: Vec<String>,
    rules: String,
    /// The first engine that reads this language.
    #[serde(default)]
    since: u32,
    /// Whether a parse error says the file is wrong, and not that the grammar
    /// could not read it.
    #[serde(default = "yes")]
    strict: bool,
}

fn yes() -> bool {
    true
}

/// What a family of grammars means to the engine.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rules {
    /// What counts as part of the definition behind it.
    #[serde(default)]
    pub attached: Vec<Attached>,
    #[serde(default)]
    pub imports: Vec<String>,
    /// Imports that are calls of a method.
    pub import_calls: Option<ImportCalls>,
    /// Kinds that stand in a definition before its header.
    #[serde(default)]
    pub attributes: Vec<String>,
    /// Nodes that hold one definition.
    #[serde(default)]
    pub wrappers: Vec<Wrapper>,
    /// A word that makes a later part of one type.
    pub partial: Option<Partial>,
    /// A body with no field of its own.
    #[serde(default)]
    pub bodies: Vec<String>,
    /// Declarations with a definition of their own, besides `TYPE_KINDS`.
    #[serde(default)]
    pub types: Vec<String>,
    /// Tokens that name something, besides those with `identifier` in
    /// their kind.
    #[serde(default)]
    pub names: Vec<String>,
    /// Parameters a grammar has no `parameters` field for.
    #[serde(default)]
    pub parameters: Vec<Parameters>,
    /// Tests that are calls such as `it("..")`.
    pub call_tests: Option<CallTests>,
    /// What makes a definition a test: any of these.
    #[serde(default)]
    pub tests: Vec<Tests>,
    #[serde(default)]
    pub groups: Vec<GroupRule>,
    #[serde(default)]
    pub defs: Vec<DefRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Attached {
    pub kinds: Vec<String>,
    #[serde(default)]
    pub since: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Wrapper {
    pub kind: String,
    /// The field that holds the definition.
    pub field: Option<String>,
    /// Or its first child of one of these kinds.
    #[serde(default)]
    pub children: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportCalls {
    pub kind: String,
    pub field: String,
    pub names: Vec<String>,
    /// A call on something, with this field, is no import.
    pub receiver: String,
}

/// Where a declaration's parameters stand.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Parameters {
    pub kinds: Vec<String>,
    /// In the first descendant of this kind.
    pub list: Option<String>,
    /// Or in the children of this kind, read as they are written.
    pub item: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CallTests {
    pub call: String,
    pub callee: String,
    pub arguments: String,
    pub name: String,
    pub strings: Vec<String>,
    /// `describe.skip`: a call through this kind of node.
    pub member: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Partial {
    pub kind: String,
    pub word: String,
}

/// Where a test's marks are looked for.
#[derive(Clone, Copy, Debug, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Marked {
    /// What stands in front of the definition, comments included.
    #[default]
    Attached,
    /// The kinds of [`Rules::attributes`] at its start.
    Attributes,
    /// What stands in front of its body.
    Header,
    /// The whole definition.
    Text,
}

/// What makes a definition a test: all that is set in one rule.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Tests {
    #[serde(default)]
    pub kinds: Vec<String>,
    pub name_prefix: Option<String>,
    /// The type around it has this prefix, if there is one.
    pub owner_prefix: Option<String>,
    #[serde(default)]
    pub marks: Vec<String>,
    #[serde(default, rename = "in")]
    pub marks_in: Marked,
    /// What makes a test skipped.
    #[serde(default)]
    pub skips: Vec<String>,
    #[serde(default)]
    pub skips_in: Marked,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupRule {
    pub kinds: Vec<String>,
    #[serde(default)]
    pub since: u32,
    /// Only at the level of the file.
    #[serde(default)]
    pub top: bool,
    pub how: GroupHow,
}

/// Where the members of a group stand.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum GroupHow {
    /// In this field.
    Field(String),
    /// In the node itself, when it has this token.
    Parens(String),
    /// In the node itself.
    Own,
    /// In its first child of this kind.
    Child(String),
    /// In a list of two or more items, joined by separators.
    List { list: String, item: String },
    /// In the blocks of a statement that states nothing but definitions.
    Blocks {
        block: String,
        defs: Vec<String>,
        plain: Vec<String>,
    },
    /// In an object written to `target`.
    ObjectSetTo {
        set: String,
        target: String,
        object: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DefRule {
    pub kinds: Vec<String>,
    #[serde(default)]
    pub since: u32,
    /// Only a node with this token among its children.
    pub token: Option<String>,
    pub how: DefHow,
}

/// How a node names a definition. Most of these are data; the last few are
/// shapes one syntax has, chosen by the table and not by the language.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DefHow {
    /// No members, named by this field.
    Leaf(String),
    Members {
        name: String,
        members: String,
    },
    /// [`DefHow::Members`] when the field is there, else a leaf.
    MembersIfAny {
        name: String,
        members: String,
    },
    /// [`DefHow::Members`] when the field is there, else no definition.
    MembersOnly {
        name: String,
        members: String,
    },
    /// Members in a child of one of these kinds.
    MembersIn {
        name: String,
        kinds: Vec<String>,
    },
    /// Named by a field, when that holds a node of this kind.
    Only {
        field: String,
        only: String,
    },
    /// Named at the end of a chain of `declarator` fields.
    Declared {
        field: String,
        /// Links of the chain with no field to go on by.
        wrapped: Vec<String>,
        /// What separates a scope in a name.
        scope: String,
        /// Where the chain ends, with more fields behind it.
        ends: Vec<String>,
    },
    /// Always this name.
    Fixed(String),
    Prefixed {
        prefix: String,
        field: String,
    },
    /// Named by a node inside it.
    Inner {
        /// A direct child of one of these kinds.
        #[serde(default)]
        child: Vec<String>,
        /// Or the first descendant of one of them.
        #[serde(default)]
        descendant: Vec<String>,
        /// The field of that node with the name, or the node itself.
        field: Option<String>,
        /// A child of that node that names it when the field is not there.
        or_child: Option<String>,
        /// The name is a node of this kind, or this is no definition.
        only: Option<String>,
    },
    /// A function that names the type it is written for: `T.f`.
    MethodOf {
        receiver: String,
        kind: String,
        name: String,
    },
    /// A block of members of a type, or of a trait for a type.
    Implementation {
        of_type: String,
        of_trait: Option<String>,
        members: String,
        prefix: String,
    },
    /// A call of a macro, as a statement too.
    MacroCall {
        call: String,
        field: String,
        suffix: String,
    },
    /// `exports.f = ...`.
    Assigned {
        set: String,
        objects: Vec<String>,
    },
    /// `{ f: function () {} }`.
    FunctionPair {
        key: String,
        values: Vec<String>,
    },
}

static TABLE: LazyLock<Table> = LazyLock::new(|| {
    toml::from_str(include_str!("languages.toml")).expect("languages.toml is part of the build")
});

/// A language of the table.
#[derive(Clone, Copy)]
pub struct Lang {
    entry: &'static Entry,
    rules: &'static Rules,
}

impl PartialEq for Lang {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.entry, other.entry)
    }
}

impl Eq for Lang {}

impl fmt::Debug for Lang {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.entry.name)
    }
}

impl Lang {
    fn of(entry: &'static Entry) -> Lang {
        let rules = &TABLE.rules[&entry.rules];
        Lang { entry, rules }
    }

    /// The language of this name, for code that knows which it wants.
    ///
    /// # Panics
    /// If the table has no such language.
    pub fn named(name: &str) -> Lang {
        let found = TABLE.language.iter().find(|e| e.name == name);
        Lang::of(found.unwrap_or_else(|| panic!("no language {name}")))
    }

    /// The language of a file, as this build's engine reads it.
    pub fn detect(path: &str) -> Option<Lang> {
        Lang::detect_at(crate::engine::ENGINE_CURRENT, path)
    }

    /// The language of a file, as `engine` reads it.
    pub fn detect_at(engine: u32, path: &str) -> Option<Lang> {
        let ext = path.rsplit_once('.')?.1;
        let known = |e: &&Entry| e.since <= engine && e.extensions.iter().any(|x| x == ext);
        TABLE.language.iter().find(known).map(Lang::of)
    }

    pub fn name(self) -> &'static str {
        &self.entry.name
    }

    /// Whether a parse error means the file is wrong. If not, it means that
    /// the grammar could not read the file, which then counts as unread.
    pub fn is_strict(self) -> bool {
        self.entry.strict
    }

    pub(crate) fn rules(self) -> &'static Rules {
        self.rules
    }

    pub fn parse(self, text: &str) -> Option<Tree> {
        let mut p = Parser::new();
        p.set_language(&grammar(&self.entry.grammar)?).ok()?;
        p.parse(text, None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn grammars_of(rules: &str) -> Vec<Language> {
        let using = TABLE.language.iter().filter(|e| e.rules == rules);
        using.map(|e| grammar(&e.grammar).unwrap()).collect()
    }

    fn kinds_of(r: &Rules) -> BTreeSet<&str> {
        let mut out: BTreeSet<&str> = r.imports.iter().map(String::as_str).collect();
        out.extend(r.attached.iter().flat_map(|a| &a.kinds).map(String::as_str));
        out.extend(r.attributes.iter().map(String::as_str));
        for w in &r.wrappers {
            out.insert(&w.kind);
            out.extend(w.children.iter().map(String::as_str));
        }
        out.extend(r.partial.iter().map(|p| p.kind.as_str()));
        out.extend(r.tests.iter().flat_map(|t| &t.kinds).map(String::as_str));
        out.extend(r.bodies.iter().chain(&r.types).map(String::as_str));
        out.extend(r.names.iter().map(String::as_str));
        out.extend(r.import_calls.iter().map(|i| i.kind.as_str()));
        for p in &r.parameters {
            out.extend(p.kinds.iter().map(String::as_str));
            out.extend(p.list.iter().chain(&p.item).map(String::as_str));
        }
        if let Some(t) = &r.call_tests {
            out.extend([t.call.as_str(), t.name.as_str()]);
            out.extend(t.strings.iter().chain(&t.member).map(String::as_str));
        }
        for g in &r.groups {
            out.extend(g.kinds.iter().map(String::as_str));
            match &g.how {
                GroupHow::Field(_) | GroupHow::Parens(_) | GroupHow::Own => {}
                GroupHow::Child(kind) => {
                    out.insert(kind);
                }
                GroupHow::List { list, item } => {
                    out.extend([list.as_str(), item.as_str()]);
                }
                GroupHow::Blocks { block, defs, plain } => {
                    out.insert(block);
                    out.extend(defs.iter().chain(plain).map(String::as_str));
                }
                GroupHow::ObjectSetTo { set, object, .. } => {
                    out.extend([set.as_str(), object.as_str()]);
                }
            }
        }
        for d in &r.defs {
            out.extend(d.kinds.iter().map(String::as_str));
            match &d.how {
                DefHow::Inner {
                    child,
                    descendant,
                    or_child,
                    only,
                    ..
                } => {
                    out.extend(child.iter().chain(descendant).map(String::as_str));
                    out.extend(or_child.iter().chain(only).map(String::as_str));
                }
                DefHow::MembersIn { kinds, .. } => {
                    out.extend(kinds.iter().map(String::as_str));
                }
                DefHow::Only { only, .. } => {
                    out.insert(only);
                }
                DefHow::Declared { wrapped, ends, .. } => {
                    out.extend(wrapped.iter().chain(ends).map(String::as_str));
                }
                DefHow::MethodOf { kind, .. } => {
                    out.insert(kind);
                }
                DefHow::MacroCall { call, .. } => {
                    out.insert(call);
                }
                DefHow::Assigned { set, .. } => {
                    out.insert(set);
                }
                DefHow::FunctionPair { key, values } => {
                    out.insert(key);
                    out.extend(values.iter().map(String::as_str));
                }
                _ => {}
            }
        }
        out
    }

    fn fields_of(r: &Rules) -> BTreeSet<&str> {
        let wrappers = r.wrappers.iter().flat_map(|w| &w.field);
        let mut out: BTreeSet<&str> = wrappers.map(String::as_str).collect();
        if let Some(i) = &r.import_calls {
            out.extend([i.field.as_str(), i.receiver.as_str()]);
        }
        if let Some(t) = &r.call_tests {
            out.extend([t.callee.as_str(), t.arguments.as_str()]);
        }
        for g in &r.groups {
            if let GroupHow::Field(field) = &g.how {
                out.insert(field);
            }
        }
        for d in &r.defs {
            out.extend(match &d.how {
                DefHow::Inner { field, .. } => field.iter().map(String::as_str).collect(),
                DefHow::Leaf(name)
                | DefHow::MembersIn { name, .. }
                | DefHow::Only { field: name, .. }
                | DefHow::Declared { field: name, .. } => vec![name.as_str()],
                DefHow::Members { name, members }
                | DefHow::MembersIfAny { name, members }
                | DefHow::MembersOnly { name, members } => {
                    vec![name.as_str(), members.as_str()]
                }
                DefHow::Prefixed { field, .. } | DefHow::MacroCall { field, .. } => {
                    vec![field.as_str()]
                }
                DefHow::MethodOf { receiver, name, .. } => vec![receiver.as_str(), name.as_str()],
                DefHow::Implementation {
                    of_type,
                    of_trait,
                    members,
                    ..
                } => {
                    let trait_field = of_trait.iter().map(String::as_str);
                    trait_field
                        .chain([of_type.as_str(), members.as_str()])
                        .collect()
                }
                _ => vec![],
            });
        }
        out
    }

    /// A wrong word in the table would read as a kind that never comes.
    #[test]
    fn every_kind_and_field_in_the_table_is_in_a_grammar() {
        for (name, rules) in &TABLE.rules {
            let grammars = grammars_of(name);
            assert!(!grammars.is_empty(), "no language uses the rules {name}");
            for kind in kinds_of(rules) {
                let known = |g: &Language| g.id_for_node_kind(kind, true) != 0;
                assert!(grammars.iter().any(known), "{name}: no kind {kind}");
            }
            for field in fields_of(rules) {
                let known = |g: &Language| g.field_id_for_name(field).is_some();
                assert!(grammars.iter().any(known), "{name}: no field {field}");
            }
        }
    }

    #[test]
    fn every_language_has_a_grammar_and_its_rules() {
        for e in &TABLE.language {
            assert!(grammar(&e.grammar).is_some(), "{}", e.name);
            assert!(TABLE.rules.contains_key(&e.rules), "{}", e.name);
            assert!(Lang::named(&e.name).parse("").is_some(), "{}", e.name);
        }
        assert!(grammar("cobol").is_none());
    }

    #[test]
    fn an_extension_means_one_language() {
        let mut seen = BTreeSet::new();
        for ext in TABLE.language.iter().flat_map(|e| &e.extensions) {
            assert!(seen.insert(ext), "{ext}");
        }
    }

    #[test]
    fn detect_reads_the_extension_after_the_last_dot() {
        let name = |path| Lang::detect(path).map(Lang::name);
        assert_eq!(name("a/b.rs"), Some("rust"));
        assert_eq!(name("a.tar.py"), Some("python"));
        assert_eq!(name("a.rs.txt"), None);
        assert_eq!(name("Makefile"), None);
        assert_eq!(name("rs"), None);
    }

    #[test]
    fn a_language_is_read_from_its_first_engine_on() {
        let late = TABLE.language.iter().max_by_key(|e| e.since).unwrap();
        let path = format!("a.{}", late.extensions[0]);
        assert_eq!(Lang::detect_at(late.since, &path), Some(Lang::of(late)));
        if late.since > 0 {
            assert_eq!(Lang::detect_at(late.since - 1, &path), None);
        }
    }

    #[test]
    #[should_panic(expected = "no language cobol")]
    fn asking_for_a_language_the_table_lacks_is_a_mistake() {
        Lang::named("cobol");
    }

    #[test]
    fn languages_of_one_table_are_told_apart() {
        assert_eq!(Lang::named("rust"), Lang::named("rust"));
        assert_ne!(Lang::named("rust"), Lang::named("go"));
        assert_eq!(format!("{:?}", Lang::named("tsx")), "tsx");
    }
}
