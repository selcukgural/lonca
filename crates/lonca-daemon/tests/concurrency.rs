//! Phase 2 criterion: twenty agents work on different functions of the same
//! file at the same time, over the real socket. No update may be lost and
//! every trunk state must have passed verification.
//!
//! The matrix below (#40) does the same for the methods of one type in each
//! of fourteen languages: edits, inserts into the type, a delete, a wider
//! signature, an overload, a lease that runs out and one that is renewed
//! while their changes wait, and agents on an old base that conflict, sync
//! and propose again.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::ops::{CheckKind, CheckResult};

const AGENTS: usize = 20;

fn source() -> String {
    let mut s = String::new();
    for i in 0..AGENTS {
        s.push_str(&format!(
            "pub fn f{i}(x: u64) -> u64 {{\n    x + {i}\n}}\n\n"
        ));
    }
    s
}

#[test]
fn twenty_agents_one_file_no_lost_updates() {
    let mut e = Env::new();
    e.init(None);
    // Verification: the merged file must still define every original function.
    let config = lonca_policy::config::DEFAULT_CONFIG
        .replace("required = false", "required = true")
        .replace(
            "# test = \"cargo test --offline\"",
            "test = \"test $(grep -c '^pub fn f' src/lib.rs) -eq 20\"",
        );
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY}),
    );
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let r = e.human_change(vec![file("src/lib.rs", &source())], "twenty functions");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(
        e.svc.process_all(),
        1,
        "the seed must integrate (verification ran)"
    );
    let base = e.trunk();
    assert!(e.store().read_file(&base, "src/lib.rs").unwrap().is_some());

    let tokens: Vec<String> = (0..AGENTS)
        .map(|i| {
            let t = e.session(&format!("a{i}"), &["src/**"]);
            e.bind(&t);
            e.wrote(&t, "src/lib.rs");
            t
        })
        .collect();

    let sock = e.root.join("s");
    let listener = lonca_daemon::server::bind(&sock).unwrap();
    let svc = e.svc.clone();
    std::thread::spawn(move || lonca_daemon::server::serve(listener, svc));
    let worker = e.svc.spawn_worker();
    drop(worker);

    let started = std::time::Instant::now();
    let handles: Vec<_> = tokens
        .into_iter()
        .enumerate()
        .map(|(i, token)| {
            let sock = sock.clone();
            let base = base.clone();
            std::thread::spawn(move || {
                let mut c = lonca_daemon::Client::connect(&sock).unwrap();
                c.token = Some(token);
                let items = json!([
                    {"symbol": format!("src/lib.rs#f{i}"), "kind": "edit"},
                    {"symbol": "src/lib.rs#<file>", "kind": "insert"}
                ]);
                let r = c
                    .call(
                        "lease.acquire",
                        json!({"items": items, "intent": format!("agent {i}"), "ttl_ms": 600_000}),
                    )
                    .unwrap();
                assert_eq!(r["decision"]["outcome"], "allow", "agent {i}: {r}");
                let mut text =
                    source().replace(&format!("    x + {i}\n"), &format!("    x * {i} + 1\n"));
                text.push_str(&format!("pub fn new{i}() -> u64 {{\n    {i}\n}}\n"));
                let claim = Claim {
                    intent: format!("agent {i}"),
                    edits: vec![format!("src/lib.rs#f{i}")],
                    adds: vec![format!("src/lib.rs#new{i}")],
                    ..Default::default()
                };
                let r = c
                    .call(
                        "change.propose",
                        json!({"base": base, "files": [file("src/lib.rs", &text)], "claim": claim}),
                    )
                    .unwrap();
                assert_eq!(r["decision"]["outcome"], "allow", "agent {i}: {r}");
                serde_json::from_value::<ChangeId>(r["change"].clone()).unwrap()
            })
        })
        .collect();
    let changes: Vec<ChangeId> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    // Wait for the worker to drain the queue.
    for _ in 0..600 {
        let s = e.ok("status", Some("demo"), None, json!({}));
        if s["queue"].as_array().unwrap().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    eprintln!("20 proposals integrated in {:?}", started.elapsed());

    for (i, ch) in changes.iter().enumerate() {
        let c = e.ok("change.get", Some("demo"), None, json!({"change": ch}));
        assert_eq!(c["status"]["status"], "integrated", "agent {i}: {c}");
    }
    let trunk = e.trunk();
    let text =
        String::from_utf8(e.store().read_file(&trunk, "src/lib.rs").unwrap().unwrap()).unwrap();
    for i in 0..AGENTS {
        assert!(
            text.contains(&format!("    x * {i} + 1\n")),
            "edit of agent {i} lost"
        );
        assert!(
            text.contains(&format!("pub fn new{i}() -> u64")),
            "addition of agent {i} lost"
        );
    }
    let parsed = lonca_symbols::parse(lonca_symbols::Lang::named("rust"), &text);
    assert!(!parsed.has_error);
    assert_eq!(parsed.syms.len(), 2 * AGENTS);

    // Every integration carries passing syntax and test evidence.
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let integrations: Vec<_> = ops
        .iter()
        .filter(|o| matches!(o.entry.op, Op::ChangeIntegrate { .. }))
        .collect();
    assert_eq!(
        integrations
            .iter()
            .filter(|o| o.entry.decision.is_allow())
            .count(),
        AGENTS + 1
    );
    for o in integrations
        .iter()
        .filter(|o| o.entry.actor == lonca_core::ops::Actor::Daemon && o.entry.decision.is_allow())
    {
        for k in [CheckKind::Syntax, CheckKind::Tests] {
            let a = o
                .entry
                .evidence
                .iter()
                .find(|a| a.check == k)
                .unwrap_or_else(|| panic!("op {} lacks {k:?}", o.entry.seq));
            assert_eq!(a.result, CheckResult::Pass);
        }
    }
    // Linear history: 20 agent commits on top of the seed.
    let store = e.store();
    let mut n = 0;
    let mut cur = Some(trunk);
    while let Some(c) = cur {
        let info = store.read_commit(&c).unwrap();
        assert!(info.parents.len() <= 1);
        cur = info.parents.into_iter().next();
        n += 1;
    }
    assert_eq!(n, AGENTS + 2, "initial + seed + 20");

    let r = audit(&store, Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

// ------------------------------------------------- one file, every language (#40)

/// How a language writes a type with methods that return a number. Data, so
/// that a language is a row: what the agents do and what is checked is the
/// same for all.
struct Shape {
    path: &'static str,
    head: &'static str,
    tail: &'static str,
    /// One method: `{n}` its name, `{v}` its number.
    method: &'static str,
    /// The same method with one more parameter.
    wider: &'static str,
    /// Two methods of one name, the first returning `{v}`, where the
    /// language has them.
    overloads: Option<&'static str>,
}

const SHAPES: &[Shape] = &[
    Shape {
        path: "src/lib.rs",
        head: "pub struct C;\n\nimpl C {\n",
        tail: "}\n",
        method: "    pub fn {n}(&self) -> i32 {\n        {v}\n    }\n",
        wider: "    pub fn {n}(&self, extra: i32) -> i32 {\n        {v} + extra\n    }\n",
        overloads: None,
    },
    Shape {
        path: "app/c.py",
        head: "class C:\n",
        tail: "",
        method: "    def {n}(self):\n        return {v}\n",
        wider: "    def {n}(self, extra):\n        return {v} + extra\n",
        overloads: None,
    },
    Shape {
        path: "web/c.ts",
        head: "export class C {\n",
        tail: "}\n",
        method: "  {n}(): number {\n    return {v};\n  }\n",
        wider: "  {n}(extra: number): number {\n    return {v} + extra;\n  }\n",
        overloads: Some(
            "  o(a: number): number;\n  o(a: string): number;\n  o(a: number | string): number {\n    return {v};\n  }\n",
        ),
    },
    Shape {
        path: "web/c.tsx",
        head: "export class C {\n",
        tail: "}\n",
        method: "  {n}() {\n    return <b>{v}</b>;\n  }\n",
        wider: "  {n}(extra: number) {\n    return <b>{v} {extra}</b>;\n  }\n",
        overloads: None,
    },
    Shape {
        path: "web/c.js",
        head: "export class C {\n",
        tail: "}\n",
        method: "  {n}() {\n    return {v};\n  }\n",
        wider: "  {n}(extra) {\n    return {v} + extra;\n  }\n",
        overloads: None,
    },
    Shape {
        path: "src/C.cs",
        head: "public class C\n{\n",
        tail: "}\n",
        method: "    public int {n}()\n    {\n        return {v};\n    }\n",
        wider: "    public int {n}(int extra)\n    {\n        return {v} + extra;\n    }\n",
        overloads: Some(
            "    public int o(int a)\n    {\n        return {v};\n    }\n\n    public int o(string a)\n    {\n        return 2;\n    }\n",
        ),
    },
    Shape {
        path: "pkg/c.go",
        head: "package pkg\n\ntype C struct{}\n\n",
        tail: "",
        method: "func (c C) {n}() int {\n\treturn {v}\n}\n",
        wider: "func (c C) {n}(extra int) int {\n\treturn {v} + extra\n}\n",
        overloads: None,
    },
    Shape {
        path: "src/C.java",
        head: "public class C {\n",
        tail: "}\n",
        method: "    public int {n}() {\n        return {v};\n    }\n",
        wider: "    public int {n}(int extra) {\n        return {v} + extra;\n    }\n",
        overloads: Some(
            "    public int o(int a) {\n        return {v};\n    }\n\n    public int o(String a) {\n        return 2;\n    }\n",
        ),
    },
    Shape {
        path: "src/c.kt",
        head: "class C {\n",
        tail: "}\n",
        method: "    fun {n}(): Int {\n        return {v}\n    }\n",
        wider: "    fun {n}(extra: Int): Int {\n        return {v} + extra\n    }\n",
        overloads: Some(
            "    fun o(a: Int): Int {\n        return {v}\n    }\n\n    fun o(a: String): Int {\n        return 2\n    }\n",
        ),
    },
    Shape {
        path: "src/c.c",
        head: "",
        tail: "",
        method: "int {n}(void) {\n    return {v};\n}\n",
        wider: "int {n}(int extra) {\n    return {v} + extra;\n}\n",
        overloads: None,
    },
    Shape {
        path: "src/c.cpp",
        head: "class C {\npublic:\n",
        tail: "};\n",
        method: "    int {n}() {\n        return {v};\n    }\n",
        wider: "    int {n}(int extra) {\n        return {v} + extra;\n    }\n",
        overloads: Some(
            "    int o(int a) {\n        return {v};\n    }\n\n    int o(const char *a) {\n        return 2;\n    }\n",
        ),
    },
    Shape {
        path: "lib/c.rb",
        head: "class C\n",
        tail: "end\n",
        method: "  def {n}\n    {v}\n  end\n",
        wider: "  def {n}(extra)\n    {v} + extra\n  end\n",
        overloads: None,
    },
    Shape {
        path: "src/C.php",
        head: "<?php\n\nclass C\n{\n",
        tail: "}\n",
        method: "    public function {n}()\n    {\n        return {v};\n    }\n",
        wider: "    public function {n}($extra)\n    {\n        return {v} + $extra;\n    }\n",
        overloads: None,
    },
    Shape {
        path: "Sources/C.swift",
        head: "class C {\n",
        tail: "}\n",
        method: "    func {n}() -> Int {\n        return {v}\n    }\n",
        wider: "    func {n}(extra: Int) -> Int {\n        return {v} + extra\n    }\n",
        overloads: Some(
            "    func o(a: Int) -> Int {\n        return {v}\n    }\n\n    func o(a: String) -> Int {\n        return 2\n    }\n",
        ),
    },
];

/// Methods the agents edit, and their numbers in the base, after the first
/// round and after the second.
const EDITED: u32 = 10;
const BASE: u32 = 100;
const FIRST: u32 = 200;
const SECOND: u32 = 300;

/// What one agent does to the file.
#[derive(Clone, Debug)]
enum Task {
    /// Method `m{i}` returns `to` instead of whatever it returned.
    Edit {
        i: u32,
        to: u32,
    },
    /// A new method into the type.
    Add {
        name: &'static str,
    },
    Delete,
    /// Method `s` takes one more parameter.
    Widen,
    /// The first of the overloads returns `to`.
    Overload {
        to: u32,
    },
}

impl Shape {
    fn method(&self, name: &str, value: u32) -> String {
        self.method
            .replace("{n}", name)
            .replace("{v}", &value.to_string())
    }

    fn overloads(&self, value: u32) -> Option<String> {
        self.overloads.map(|o| o.replace("{v}", &value.to_string()))
    }

    fn base(&self) -> String {
        let mut parts: Vec<String> = (0..EDITED)
            .map(|i| self.method(&format!("m{i}"), BASE + i))
            .collect();
        parts.push(self.method("gone", 50));
        parts.push(self.method("s", 60));
        parts.extend(self.overloads(1));
        format!("{}{}{}", self.head, parts.join("\n"), self.tail)
    }

    fn apply(&self, text: &str, task: &Task) -> String {
        let swap = |from: &str, to: &str| {
            assert!(text.contains(from), "{}: no {from:?} in\n{text}", self.path);
            text.replacen(from, to, 1)
        };
        match task {
            Task::Edit { i, to } => {
                let name = format!("m{i}");
                let now = [BASE + i, FIRST + i]
                    .map(|v| self.method(&name, v))
                    .into_iter()
                    .find(|m| text.contains(m.as_str()))
                    .unwrap_or_else(|| panic!("{}: no {name} in\n{text}", self.path));
                swap(&now, &self.method(&name, *to))
            }
            Task::Add { name } => {
                let new = self.method(name, 7);
                match text.rfind(self.tail).filter(|_| !self.tail.is_empty()) {
                    Some(at) => format!("{}\n{new}{}", &text[..at], &text[at..]),
                    None => format!("{text}\n{new}"),
                }
            }
            Task::Delete => swap(&format!("{}\n", self.method("gone", 50)), ""),
            Task::Widen => {
                let wider = self.wider.replace("{n}", "s").replace("{v}", "60");
                swap(&self.method("s", 60), &wider)
            }
            Task::Overload { to } => {
                let o = |v| self.overloads(v).expect("overloads");
                swap(&o(1), &o(*to))
            }
        }
    }

    /// What every task leaves in the file, and what it takes out.
    fn holds(&self, text: &str, tasks: &[Task]) -> Result<(), String> {
        let has = |s: &str| text.contains(s);
        for task in tasks {
            let ok = match task {
                Task::Edit { i, to } => has(&self.method(&format!("m{i}"), *to)),
                Task::Add { name } => has(&self.method(name, 7)),
                Task::Delete => !has("gone"),
                Task::Widen => has(&self.wider.replace("{n}", "s").replace("{v}", "60")),
                Task::Overload { to } => has(&self.overloads(*to).unwrap()),
            };
            if !ok {
                return Err(format!("{task:?} lost"));
            }
        }
        Ok(())
    }
}

/// A session that may also renew its leases.
fn agent(e: &mut Env, id: &str, path: &str) -> String {
    let dir = path.rsplit_once('/').map_or("", |(d, _)| d);
    let mut op = e.session_op(id, &[&format!("{dir}/**")], None);
    if let Op::SessionStart { scope, .. } = &mut op {
        scope.ops.push(OpKind::LeaseRenew);
    }
    let t = e.human(op)["token"].as_str().expect("token").to_string();
    e.bind(&t);
    e.wrote(&t, path);
    t
}

/// One agent's round over the socket: what the change does by the daemon's
/// own facts, the leases those take, the proposal. The change id back.
fn propose_over(
    sock: &Path,
    token: &str,
    path: &str,
    base: &GitId,
    text: &str,
    ttl_ms: i64,
) -> Result<Proposed, String> {
    let mut c = lonca_daemon::Client::connect(sock).map_err(|e| e.to_string())?;
    c.token = Some(token.to_string());
    let mut call = |method: &str, params: Value| -> Result<Value, String> {
        c.call(method, params).map_err(|e| format!("{method}: {e}"))
    };
    let files = json!([file(path, text)]);
    let preview = call("facts.preview", json!({"base": base, "files": files}))?;
    let facts = &preview["facts"];
    let items = preview["acquire"].clone();
    // After a sync the agent still holds what its conflicted change took:
    // nothing is free to take, and nothing is missing.
    let set = if items.as_array().is_some_and(|a| a.is_empty()) {
        let leases = preview["leases"].as_array().cloned().unwrap_or_default();
        if leases.is_empty() || leases.iter().any(|l| l["code"] != "held_by_you") {
            return Err(format!("nothing to take, not all held: {preview}"));
        }
        Value::Null
    } else {
        let r = call(
            "lease.acquire",
            json!({"items": items, "intent": "matrix", "ttl_ms": ttl_ms}),
        )?;
        if r["decision"]["outcome"] != "allow" {
            return Err(format!("lease {items}: {r}"));
        }
        r["set"].clone()
    };
    let list = |k: &str| serde_json::from_value::<Vec<String>>(facts[k].clone()).unwrap();
    let claim = Claim {
        intent: "matrix".into(),
        edits: list("edits"),
        adds: list("adds"),
        deletes: list("deletes"),
        signature_changes: list("signature_changes"),
        ..Default::default()
    };
    let r = call(
        "change.propose",
        json!({"base": base, "files": files, "claim": claim}),
    )?;
    if r["decision"]["outcome"] != "allow" {
        return Err(format!("propose: {r}"));
    }
    let change = serde_json::from_value(r["change"].clone()).map_err(|e| e.to_string())?;
    Ok(Proposed { change, set, items })
}

/// Twenty agents on one file of `shape`'s language, over the socket. Ten
/// edit ten methods of one type at once; one of them lets its lease run out
/// while its change waits, another renews. Then ten more from the first
/// base: two add methods to the type, one deletes a method, one widens a
/// signature, one edits an overload (or adds a third method), and five edit
/// methods the first ten changed: they conflict, sync and propose again.
/// Nothing is lost, the history is linear and the audit passes.
fn twenty_agents_in(shape: &Shape) {
    let mut e = Env::new();
    e.init(None);
    let path = shape.path;
    let seed = shape.base();
    let r = e.human_change(vec![file(path, &seed)], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1, "{path}: the seed");
    let base = e.trunk();
    let sock = e.root.join("s");
    let listener = lonca_daemon::server::bind(&sock).unwrap();
    let svc = e.svc.clone();
    std::thread::spawn(move || lonca_daemon::server::serve(listener, svc));

    let first: Vec<Task> = (0..EDITED)
        .map(|i| Task::Edit { i, to: FIRST + i })
        .collect();
    let tokens: Vec<String> = (0..first.len())
        .map(|i| agent(&mut e, &format!("a{i}"), path))
        .collect();
    let round = |tokens: &[String], tasks: &[Task], base: &GitId, text: &str| {
        let handles: Vec<_> = tokens
            .iter()
            .zip(tasks)
            .enumerate()
            .map(|(i, (token, task))| {
                let (sock, token, base) = (sock.clone(), token.clone(), base.clone());
                let new = shape.apply(text, task);
                let ttl = if i == 0 { 60_000 } else { 600_000 };
                std::thread::spawn(move || propose_over(&sock, &token, path, &base, &new, ttl))
            })
            .collect();
        let out: Vec<Proposed> = handles
            .into_iter()
            .map(|h| h.join().unwrap().unwrap_or_else(|e| panic!("{path}: {e}")))
            .collect();
        out
    };
    let ones = round(&tokens, &first, &base, &seed);

    // While the changes wait: the first agent's lease runs out, and is
    // still its own, pinned to the change; the second agent renews.
    e.advance(120_000);
    let late = agent(&mut e, "late", path);
    let r = e.ok(
        "lease.acquire",
        None,
        Some(&late),
        json!({"items": ones[0].items, "intent": "late", "ttl_ms": 600_000}),
    );
    assert_eq!(r["decision"]["outcome"], "deny", "{path}: {r}");
    let r = e.ok(
        "lease.renew",
        None,
        Some(&tokens[1]),
        json!({"set": ones[1].set, "ttl_ms": 600_000}),
    );
    assert_eq!(r["decision"]["outcome"], "allow", "{path}: {r}");
    assert_eq!(e.svc.process_all(), first.len(), "{path}: first round");
    for (i, p) in ones.iter().enumerate() {
        assert_eq!(
            status(&mut e, &p.change),
            "integrated",
            "{path}: agent a{i}"
        );
    }

    // Ten more, from the first base.
    let fifth = match shape.overloads {
        Some(_) => Task::Overload { to: 9 },
        None => Task::Add { name: "third" },
    };
    let mut second = vec![
        Task::Add { name: "first" },
        Task::Add { name: "second" },
        Task::Delete,
        Task::Widen,
        fifth,
    ];
    second.extend((0..EDITED / 2).map(|i| Task::Edit { i, to: SECOND + i }));
    let tokens: Vec<String> = (0..second.len())
        .map(|i| agent(&mut e, &format!("b{i}"), path))
        .collect();
    let twos = round(&tokens, &second, &base, &seed);
    assert_eq!(e.svc.process_all(), second.len(), "{path}: second round");
    let mut again = Vec::new();
    for (i, (p, task)) in twos.iter().zip(&second).enumerate() {
        let s = status(&mut e, &p.change);
        match task {
            Task::Edit { .. } => {
                assert_eq!(s, "conflicted", "{path}: agent b{i}");
                again.push(i);
            }
            _ => assert_eq!(s, "integrated", "{path}: agent b{i} {task:?}"),
        }
    }
    // A sync: the agent's edit made again on what trunk holds now.
    let trunk = e.trunk();
    let now = read(&e, &trunk, path);
    let tokens: Vec<String> = again.iter().map(|i| tokens[*i].clone()).collect();
    let tasks: Vec<Task> = again.iter().map(|i| second[*i].clone()).collect();
    let threes = round(&tokens, &tasks, &trunk, &now);
    assert_eq!(e.svc.process_all(), tasks.len(), "{path}: after the sync");
    for p in &threes {
        assert_eq!(status(&mut e, &p.change), "integrated", "{path}");
    }

    let trunk = e.trunk();
    let text = read(&e, &trunk, path);
    let kept: Vec<Task> = first
        .into_iter()
        .skip(EDITED as usize / 2)
        .chain(second)
        .collect();
    if let Err(lost) = shape.holds(&text, &kept) {
        panic!("{path}: {lost}:\n{text}");
    }
    let lang = lonca_symbols::Lang::detect(path).unwrap();
    assert!(
        !lonca_symbols::parse(lang, &text).has_error,
        "{path}:\n{text}"
    );
    // Linear: the initial commit, the seed, ten, five, and the five again.
    let store = e.store();
    let (mut n, mut cur) = (0, Some(trunk));
    while let Some(c) = cur {
        let info = store.read_commit(&c).unwrap();
        assert!(info.parents.len() <= 1, "{path}: a merge commit");
        cur = info.parents.into_iter().next();
        n += 1;
    }
    assert_eq!(n, 2 + 10 + 5 + 5, "{path}");
    let r = audit(&store, Options::default()).unwrap();
    assert!(r.ok(), "{path}: {:#?}", r.findings);
}

struct Proposed {
    change: ChangeId,
    set: Value,
    items: Value,
}

fn status(e: &mut Env, change: &ChangeId) -> String {
    let c = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    c["status"]["status"]
        .as_str()
        .unwrap_or_default()
        .to_string()
}

fn read(e: &Env, commit: &GitId, path: &str) -> String {
    String::from_utf8(e.store().read_file(commit, path).unwrap().unwrap()).unwrap()
}

macro_rules! matrix {
    ($($test:ident: $path:literal),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                let shape = SHAPES.iter().find(|s| s.path == $path).expect($path);
                twenty_agents_in(shape);
            }
        )*
        /// Every shape has its test.
        #[test]
        fn every_shape_has_a_matrix_test() {
            let tested = [$($path),*];
            for s in SHAPES {
                assert!(tested.contains(&s.path), "no test for {}", s.path);
            }
        }
    };
}

matrix! {
    twenty_agents_rust: "src/lib.rs",
    twenty_agents_python: "app/c.py",
    twenty_agents_typescript: "web/c.ts",
    twenty_agents_tsx: "web/c.tsx",
    twenty_agents_javascript: "web/c.js",
    twenty_agents_csharp: "src/C.cs",
    twenty_agents_go: "pkg/c.go",
    twenty_agents_java: "src/C.java",
    twenty_agents_kotlin: "src/c.kt",
    twenty_agents_c: "src/c.c",
    twenty_agents_cpp: "src/c.cpp",
    twenty_agents_ruby: "lib/c.rb",
    twenty_agents_php: "src/C.php",
    twenty_agents_swift: "Sources/C.swift",
}

/// A preview is its caller's work, as long as its files are: while one is
/// built and parsed the daemon answers everyone else.
#[test]
fn a_long_preview_does_not_hold_the_daemon() {
    use std::sync::atomic::AtomicBool;
    let mut e = Env::new();
    e.init(None);
    let token = e.session("s1", &["src/**"]);
    let base = e.trunk();
    e.ok("status", Some("demo"), None, json!({}));
    let body: String = (0..12_000)
        .map(|i| format!("pub fn f{i}(a: u64) -> u64 {{\n    a + {i}\n}}\n\n"))
        .collect();
    let files: Vec<FileChange> = (0..4)
        .map(|k| file(&format!("src/big{k}.rs"), &body))
        .collect();
    let svc = e.svc.clone();
    let done = Arc::new(AtomicBool::new(false));
    let told = done.clone();
    let preview = std::thread::spawn(move || {
        let r = svc.handle(Request {
            id: 1,
            method: "facts.preview".into(),
            repo: None,
            token: Some(token),
            params: json!({"base": base, "files": files}),
        });
        told.store(true, Ordering::SeqCst);
        assert!(r.ok, "{:?}", r.error.map(|e| e.message));
        r.result["facts"].is_object()
    });
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(
        !done.load(Ordering::SeqCst),
        "the preview ended too soon to show anything"
    );
    let asked = std::time::Instant::now();
    e.ok("status", Some("demo"), None, json!({}));
    let waited = asked.elapsed();
    assert!(
        !done.load(Ordering::SeqCst),
        "status was answered only when the preview ended ({waited:?})"
    );
    assert!(preview.join().unwrap());
}
