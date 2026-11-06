//! Twenty agents on one file in each language of symbol engine 10, through
//! the daemon and the auditor: a lease on a method holds what it should, all
//! integrate, nothing is lost and the log recomputes.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::GitId;
use lonca_core::ops::Claim;
use serde_json::{Value, json};

const AGENTS: usize = 20;

struct Row {
    path: &'static str,
    method: fn(&str, &str) -> String,
    file: fn(&str) -> String,
    /// What holds new members, and what a method's name starts with.
    holder: &'static str,
    owner: &'static str,
}

const ROWS: [Row; 7] = [
    Row {
        path: "src/C.java",
        method: |n, b| format!("    int {n}(int x) {{\n        return x + {b};\n    }}\n\n"),
        file: |m| format!("class C {{\n{m}}}\n"),
        holder: "C",
        owner: "C.",
    },
    Row {
        path: "src/C.kt",
        method: |n, b| format!("    fun {n}(x: Int): Int {{\n        return x + {b}\n    }}\n\n"),
        file: |m| format!("class C {{\n{m}}}\n"),
        holder: "C",
        owner: "C.",
    },
    Row {
        path: "src/c.c",
        method: |n, b| format!("int {n}(int x) {{\n    return x + {b};\n}}\n\n"),
        file: |m| m.to_string(),
        holder: "<file>",
        owner: "",
    },
    Row {
        path: "src/c.cpp",
        method: |n, b| format!("    int {n}(int x) {{\n        return x + {b};\n    }}\n\n"),
        file: |m| format!("class C {{\npublic:\n{m}}};\n"),
        holder: "C",
        owner: "C.",
    },
    Row {
        path: "src/c.rb",
        method: |n, b| format!("  def {n}(x)\n    x + {b}\n  end\n\n"),
        file: |m| format!("class C\n{m}end\n"),
        holder: "C",
        owner: "C.",
    },
    Row {
        path: "src/c.php",
        method: |n, b| {
            format!("    public function {n}($x) {{\n        return $x + {b};\n    }}\n\n")
        },
        file: |m| format!("<?php\n\nclass C {{\n{m}}}\n"),
        holder: "C",
        owner: "C.",
    },
    Row {
        path: "src/C.swift",
        method: |n, b| {
            format!("    func {n}(x: Int) -> Int {{\n        return x + {b}\n    }}\n\n")
        },
        file: |m| format!("class C {{\n{m}}}\n"),
        holder: "C",
        owner: "C.",
    },
];

impl Row {
    fn methods(&self) -> String {
        let one = |i| (self.method)(&format!("m{i}"), &format!("v{i}w"));
        (0..AGENTS).map(one).collect()
    }

    fn id(&self, name: &str) -> String {
        format!("{}#{}{name}", self.path, self.owner)
    }

    fn propose(&self, e: &mut Env, base: &GitId, i: usize) -> Value {
        let t = e.session(&format!("a{i}"), &["src/**"]);
        e.bind(&t);
        e.wrote(&t, self.path);
        let items = json!([
            {"symbol": self.id(&format!("m{i}")), "kind": "edit"},
            {"symbol": format!("{}#{}", self.path, self.holder), "kind": "insert"},
        ]);
        let args = json!({"items": items, "intent": format!("agent {i}"), "ttl_ms": 600_000});
        let r = e.ok("lease.acquire", None, Some(&t), args);
        assert_eq!(r["decision"]["outcome"], "allow", "{}: {r}", self.path);
        let edited = self.methods().replace(&format!("v{i}w"), &format!("e{i}w"));
        let added = (self.method)(&format!("n{i}"), "0");
        let text = (self.file)(&format!("{edited}{added}"));
        let claim = Claim {
            intent: format!("agent {i}"),
            edits: vec![self.id(&format!("m{i}"))],
            adds: vec![self.id(&format!("n{i}"))],
            ..Default::default()
        };
        let args = json!({"base": base, "files": [file(self.path, &text)], "claim": claim});
        e.ok("change.propose", None, Some(&t), args)
    }
}

#[test]
fn twenty_agents_in_each_language() {
    for row in ROWS {
        let mut e = Env::new();
        e.init(None);
        let seed = (row.file)(&row.methods());
        let r = e.human_change(vec![file(row.path, &seed)], "seed");
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        assert_eq!(e.svc.process_all(), 1, "{}", row.path);
        let base = e.trunk();
        for i in 0..AGENTS {
            let r = row.propose(&mut e, &base, i);
            assert_eq!(r["decision"]["outcome"], "allow", "{}, {i}: {r}", row.path);
        }
        assert_eq!(e.svc.process_all(), AGENTS, "{}", row.path);
        let head = e.trunk();
        let text = e.store().read_file(&head, row.path).unwrap().unwrap();
        let text = String::from_utf8(text).unwrap();
        for i in 0..AGENTS {
            assert!(text.contains(&format!("e{i}w")), "{}: edit {i}", row.path);
            assert!(text.contains(&format!("n{i}(")), "{}: add {i}", row.path);
        }
        let report = audit(&e.store(), Options::default()).unwrap();
        assert!(report.ok(), "{}: {:#?}", row.path, report.findings);
    }
}

fn optimistic(e: &mut Env) {
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(
        "unparsed_files = \"file\"",
        "unparsed_files = \"optimistic\"",
    );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    let r = e.human(op);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

/// A lease on a method holds however its neighbour writes the file, and a
/// file that stops reading takes a person's word: after it nothing sees in.
#[test]
fn breaking_a_file_gets_past_no_lease_and_no_person() {
    const PATH: &str = "src/C.java";
    let seed = "class C {\n    int charge() {\n        return 1;\n    }\n\n    int other() {\n        return 2;\n    }\n}\n";
    let mut e = Env::new();
    e.init(None);
    optimistic(&mut e);
    let r = e.human_change(vec![file(PATH, seed)], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    let broken = format!("{}@@@\n", seed.replace("return 1", "return 10"));
    let propose = |e: &mut Env, token: &str, text: &str| {
        let claim = Claim {
            intent: "a change".into(),
            edits: vec![format!("{PATH}#<file>")],
            ..Default::default()
        };
        let args = json!({"base": base, "files": [file(PATH, text)], "claim": claim});
        e.ok("change.propose", None, Some(token), args)
    };

    let holder = e.session("a", &["src/**"]);
    e.bind(&holder);
    let items = json!([{"symbol": format!("{PATH}#C.charge"), "kind": "edit"}]);
    let args = json!({"items": items, "intent": "mine", "ttl_ms": 600_000});
    let r = e.ok("lease.acquire", None, Some(&holder), args);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let set = r["set"].clone();

    let other = e.session("b", &["src/**"]);
    e.bind(&other);
    e.wrote(&other, PATH);
    let r = propose(&mut e, &other, &broken);
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    let preview = e.ok(
        "facts.preview",
        None,
        Some(&other),
        json!({"base": base, "files": [file(PATH, &broken)]}),
    );
    assert_eq!(preview["no_lease"], json!([]), "{preview}");

    // Nobody on it, and with the lease of the file: a person decides.
    e.ok("lease.release", None, Some(&holder), json!({ "set": set }));
    let r = e.lease(&other, &format!("{PATH}#<file>"));
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let r = propose(&mut e, &other, &broken);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    let reasons = r["decision"]["reasons"].to_string();
    assert!(reasons.contains(&format!("unread_file:{PATH}")), "{r}");
}
