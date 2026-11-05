//! A type's definition apart from its members (`Type.<def>`, issue #41), on
//! the facts, the leases and the merge at once: what one agent changes in a
//! struct or a class header leaves the methods free for the others, and
//! leases never allow work the merge then rejects.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::ops::Facts;
use lonca_core::{FileEntry, FileMap, FileMode};
use lonca_policy::decide::leases_conflict;
use lonca_policy::symbols::lease_needs;
use lonca_symbols::analyze;
use lonca_symbols::engine::ENGINE_CURRENT;
use lonca_symbols::merge::merge_text_at;

/// One agent's change: the base with `from` replaced by `to`.
struct Change {
    name: &'static str,
    from: &'static str,
    to: &'static str,
}

const fn change(name: &'static str, from: &'static str, to: &'static str) -> Change {
    Change { name, from, to }
}

struct Case {
    path: &'static str,
    base: &'static str,
    /// The definition, a method, a new method, then any others.
    changes: &'static [Change],
}

const RUST: Case = Case {
    path: "src/sample.rs",
    base: "pub struct S {\n    a: u32,\n}\n\nimpl S {\n    pub fn one(&self) -> u32 {\n        1\n    }\n\n    pub fn two(&self) -> u32 {\n        2\n    }\n}\n",
    changes: &[
        change("def", "    a: u32,\n", "    a: u32,\n    b: u32,\n"),
        change("one", "        1\n", "        10\n"),
        change(
            "add",
            "        2\n    }\n",
            "        2\n    }\n\n    pub fn three(&self) -> u32 {\n        3\n    }\n",
        ),
        change("two", "        2\n", "        20\n"),
        change(
            "delete",
            "    pub fn two(&self) -> u32 {\n        2\n    }\n",
            "",
        ),
        change("header", "impl S {", "#[cfg(unix)]\nimpl S {"),
        change(
            "no-impl",
            "impl S {\n    pub fn one(&self) -> u32 {\n        1\n    }\n\n    pub fn two(&self) -> u32 {\n        2\n    }\n}\n",
            "",
        ),
    ],
};

const GO: Case = Case {
    path: "src/sample.go",
    base: "package p\n\ntype S struct {\n\ta int\n}\n\nfunc (s S) One() int {\n\treturn 1\n}\n\nfunc (s S) Two() int {\n\treturn 2\n}\n",
    changes: &[
        change("def", "\ta int\n", "\ta int\n\tb int\n"),
        change("one", "\treturn 1\n", "\treturn 10\n"),
        change(
            "add",
            "\treturn 2\n}\n",
            "\treturn 2\n}\n\nfunc (s S) Three() int {\n\treturn 3\n}\n",
        ),
        change("two", "\treturn 2\n", "\treturn 20\n"),
        change("delete", "func (s S) Two() int {\n\treturn 2\n}\n", ""),
    ],
};

const PYTHON: Case = Case {
    path: "src/sample.py",
    base: "class S:\n    limit = 1\n\n    def one(self):\n        return 1\n\n    def two(self):\n        return 2\n",
    changes: &[
        change("def", "class S:\n", "class S(Base):\n"),
        change("one", "        return 1\n", "        return 10\n"),
        change(
            "add",
            "        return 2\n",
            "        return 2\n\n    def three(self):\n        return 3\n",
        ),
        change("two", "        return 2\n", "        return 20\n"),
        change("statement", "    limit = 1\n", "    limit = 2\n"),
        change("delete", "    def two(self):\n        return 2\n", ""),
    ],
};

const TYPESCRIPT: Case = Case {
    path: "src/sample.ts",
    base: "export class S {\n  one(): number {\n    return 1;\n  }\n\n  two(): number {\n    return 2;\n  }\n}\n",
    changes: &[
        change("def", "export class S {", "export class S extends B {"),
        change("one", "    return 1;\n", "    return 10;\n"),
        change(
            "add",
            "    return 2;\n  }\n",
            "    return 2;\n  }\n\n  three(): number {\n    return 3;\n  }\n",
        ),
        change("two", "    return 2;\n", "    return 20;\n"),
        change("delete", "  two(): number {\n    return 2;\n  }\n", ""),
    ],
};

const CSHARP: Case = Case {
    path: "src/sample.cs",
    base: "public class S\n{\n    public int One()\n    {\n        return 1;\n    }\n\n    public int Two()\n    {\n        return 2;\n    }\n}\n",
    changes: &[
        change("def", "public class S\n", "public sealed class S : B\n"),
        change("one", "        return 1;\n", "        return 10;\n"),
        change(
            "add",
            "        return 2;\n    }\n",
            "        return 2;\n    }\n\n    public int Three()\n    {\n        return 3;\n    }\n",
        ),
        change("two", "        return 2;\n", "        return 20;\n"),
        change(
            "delete",
            "    public int Two()\n    {\n        return 2;\n    }\n",
            "",
        ),
    ],
};

const CASES: [Case; 5] = [RUST, GO, PYTHON, TYPESCRIPT, CSHARP];

/// A class with no members to anchor an addition, and text that looks like
/// where the body ends.
const NO_MEMBERS: Case = Case {
    path: "src/plain.py",
    base: "class S:\n    \"\"\"Use {x}.\"\"\"\n",
    changes: &[
        change("def", "class S:\n", "class S(Base):\n"),
        change(
            "add",
            "{x}.\"\"\"\n",
            "{x}.\"\"\"\n\n    def one(self):\n        return 1\n",
        ),
    ],
};

/// Classes in a class: each level has its own definition.
const NESTED: Case = Case {
    path: "src/nested.py",
    base: "class S:\n    class I:\n        def one(self):\n            return 1\n\n        def two(self):\n            return 2\n\n    def three(self):\n        return 3\n",
    changes: &[
        change("outer", "class S:\n", "class S(Base):\n"),
        change("inner", "    class I:\n", "    class I(Base):\n"),
        change("one", "            return 1\n", "            return 10\n"),
        change("two", "            return 2\n", "            return 20\n"),
        change("three", "        return 3\n", "        return 30\n"),
    ],
};

/// A file with an inherent and a trait `impl`: one definition for both.
const TRAIT_IMPL: Case = Case {
    path: "src/traits.rs",
    base: "pub struct S;\n\nimpl S {\n    pub fn one() -> u8 {\n        1\n    }\n}\n\nimpl From<u8> for S {\n    fn from(_: u8) -> Self {\n        S\n    }\n}\n",
    changes: &[
        change("struct", "pub struct S;\n", "pub struct S(u8);\n"),
        change("header", "impl S {", "#[cfg(unix)]\nimpl S {"),
        change(
            "trait-header",
            "impl From<u8> for S {",
            "#[cfg(unix)]\nimpl From<u8> for S {",
        ),
        change("one", "        1\n", "        10\n"),
        change("from", "        S\n", "        S.clone()\n"),
    ],
};

impl Case {
    fn text(&self, c: &Change) -> String {
        assert_eq!(self.base.matches(c.from).count(), 1, "{}", c.name);
        self.base.replace(c.from, c.to)
    }

    fn facts(&self, text: &str) -> Facts {
        let map = |text: &str| {
            let blob = GitId::of_blob(text.as_bytes());
            let entry = FileEntry {
                mode: FileMode::Regular,
                blob,
            };
            FileMap::from([(self.path.to_string(), entry)])
        };
        let read = |id: &GitId| {
            let found = [self.base, text].into_iter();
            let mut found = found.filter(|t| GitId::of_blob(t.as_bytes()) == *id);
            Ok(found.next().unwrap().as_bytes().to_vec())
        };
        analyze(ENGINE_CURRENT, &map(self.base), &map(text), &read)
            .unwrap()
            .facts
    }

    /// The first lease each need names, as `lease_needed` offers them.
    fn leases(&self, facts: &Facts) -> Vec<LeaseItem> {
        let needs = lease_needs(facts).into_iter();
        let item = needs.map(|n| LeaseItem {
            symbol: n.symbol,
            kind: n.kinds[0],
        });
        item.collect()
    }

    fn merge(&self, ours: &str, theirs: &str) -> Result<String, Vec<String>> {
        merge_text_at(ENGINE_CURRENT, self.path, self.base, ours, theirs)
    }
}

fn union(a: &[String], b: &[String]) -> Vec<String> {
    let all: std::collections::BTreeSet<&String> = a.iter().chain(b).collect();
    all.into_iter().cloned().collect()
}

/// For every two changes of every language, in both orders: whatever the
/// merge refuses, the leases have refused first, and what can be held at
/// once merges into exactly the two changes together.
#[test]
fn leases_and_the_merge_agree() {
    let mut free = Vec::new();
    for case in CASES.iter().chain(&[NO_MEMBERS, NESTED, TRAIT_IMPL]) {
        for a in case.changes {
            for b in case.changes {
                if a.name == b.name {
                    continue;
                }
                let (ta, tb) = (case.text(a), case.text(b));
                let (la, lb) = (case.leases(&case.facts(&ta)), case.leases(&case.facts(&tb)));
                let held_apart = !la.iter().any(|x| lb.iter().any(|y| leases_conflict(x, y)));
                let merged = case.merge(&ta, &tb);
                if !held_apart {
                    continue;
                }
                let at = format!("{} {} + {}: {merged:?}", case.path, a.name, b.name);
                let text = merged.unwrap_or_else(|_| panic!("leases allowed it: {at}"));
                let (fa, fb) = (case.facts(&ta), case.facts(&tb));
                let f = case.facts(&text);
                assert_eq!(f.edits, union(&fa.edits, &fb.edits), "{at}");
                assert_eq!(f.adds, union(&fa.adds, &fb.adds), "{at}");
                assert_eq!(f.deletes, union(&fa.deletes, &fb.deletes), "{at}");
                free.push(format!("{} {} {}", case.path, a.name, b.name));
            }
        }
    }
    // The point of the issue: none of these could be held together before.
    for case in &CASES {
        for (a, b) in [("def", "one"), ("def", "add"), ("one", "add")] {
            let pair = format!("{} {a} {b}", case.path);
            assert!(free.contains(&pair), "{pair}: {free:?}");
        }
    }
    for pair in [
        "src/plain.py def add",
        "src/nested.py outer inner",
        "src/nested.py inner one",
        "src/traits.rs header from",
    ] {
        assert!(free.iter().any(|p| p == pair), "{pair}: {free:?}");
    }
}

/// Facts name the definition, and only what the change did.
#[test]
fn facts_name_the_definition() {
    for case in &CASES {
        let id = |name: &str| format!("{}#{name}", case.path);
        let f = case.facts(&case.text(&case.changes[0]));
        assert_eq!(f.edits, [id("S.<def>")], "{}", case.path);
        assert_eq!(f.adds, Vec::<String>::new(), "{}", case.path);
    }
    let rust = |name: &str| {
        let c = RUST.changes.iter().find(|c| c.name == name).unwrap();
        RUST.facts(&RUST.text(c))
    };
    assert_eq!(rust("header").edits, ["src/sample.rs#S.<def>"]);
    // An `impl` taken out takes its members with it, and no lease on the
    // block reaches them: the type stands for it.
    let f = rust("no-impl");
    assert_eq!(f.edits, ["src/sample.rs#S"]);
    assert_eq!(f.deletes, ["src/sample.rs#S.one", "src/sample.rs#S.two"]);
}

fn claim_of(f: &Facts) -> Claim {
    Claim {
        intent: "agent change".into(),
        edits: f.edits.clone(),
        adds: f.adds.clone(),
        deletes: f.deletes.clone(),
        signature_changes: f.signature_changes.clone(),
        ..Default::default()
    }
}

/// Three agents through the daemon, in every order the queue can have: the
/// definition, a method, a new method. All three hold their leases at once
/// and all three integrate, and the auditor recomputes it all.
#[test]
fn three_agents_on_one_type_all_integrate() {
    for case in &CASES {
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut e = Env::new();
            e.init(None);
            let r = e.human_change(vec![file(case.path, case.base)], "seed");
            assert_eq!(r["decision"]["outcome"], "allow", "{r}");
            assert_eq!(e.svc.process_all(), 1);
            let base = e.trunk();
            let agents: Vec<_> = order
                .map(|i| {
                    let c = &case.changes[i];
                    let t = e.session(c.name, &["src/**"]);
                    e.bind(&t);
                    e.wrote(&t, case.path);
                    (t, c)
                })
                .to_vec();
            for (token, c) in &agents {
                let items = case.leases(&case.facts(&case.text(c)));
                let args = json!({"items": items, "intent": c.name, "ttl_ms": 600_000});
                let r = e.ok("lease.acquire", None, Some(token), args);
                let at = format!("{} {}: {r}", case.path, c.name);
                assert_eq!(r["decision"]["outcome"], "allow", "{at}");
            }
            let mut changes = Vec::new();
            for (token, c) in &agents {
                let text = case.text(c);
                let claim = claim_of(&case.facts(&text));
                let files = vec![file(case.path, &text)];
                let args = json!({"base": base, "files": files, "claim": claim});
                let r = e.ok("change.propose", None, Some(token), args);
                let at = format!("{} {}: {r}", case.path, c.name);
                assert_eq!(r["decision"]["outcome"], "allow", "{at}");
                changes.push(r["change"].clone());
            }
            assert_eq!(e.svc.process_all(), 3, "{}", case.path);
            for change in changes {
                let s = e.ok("change.get", Some("demo"), None, json!({"change": change}));
                assert_eq!(s["status"]["status"], "integrated", "{} {s}", case.path);
            }
            let trunk = e.trunk();
            let text = e.store().read_file(&trunk, case.path).unwrap().unwrap();
            let text = String::from_utf8(text).unwrap();
            for c in &case.changes[..3] {
                assert!(text.contains(c.to.trim_end()), "{}\n{text}", c.name);
            }
            let r = audit(&e.store(), Options::default()).unwrap();
            assert!(r.ok(), "{:#?}", r.findings);
        }
    }
}
