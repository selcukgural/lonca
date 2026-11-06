//! Files no parser reads (issue #113): under `leases.unparsed_files =
//! "optimistic"` agents edit one with no lease, the line merge at integration
//! decides, and a real overlap is `conflicted` with nothing lost.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::GitId;
use lonca_core::ops::Claim;
use lonca_policy::config::DEFAULT_CONFIG;
use lonca_policy::config::DEFAULT_POLICY;
use serde_json::{Value, json};

const PATH: &str = "src/Main.java";

/// Thirty lines with room between them, so that one-line changes do not
/// touch: a change at line `i` is line `i * 4`.
fn seed() -> String {
    (0..100).map(|i| format!("    int a{i} = {i};\n")).collect()
}

fn edited(text: &str, line: usize, to: &str) -> String {
    let from = format!("    int a{line} = {line};\n");
    assert!(text.contains(&from), "{line}");
    text.replace(&from, &format!("    int a{line} = {to};\n"))
}

fn optimistic(e: &mut Env) {
    let config = DEFAULT_CONFIG.replace(
        "unparsed_files = \"file\"",
        "unparsed_files = \"optimistic\"",
    );
    assert_ne!(config, DEFAULT_CONFIG);
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    let r = e.human(op);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
}

fn repo() -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    optimistic(&mut e);
    let r = e.human_change(vec![file(PATH, &seed())], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    (e, base)
}

fn propose(e: &mut Env, name: &str, base: &GitId, text: &str) -> Value {
    let t = e.session(name, &["src/**"]);
    e.bind(&t);
    e.wrote(&t, PATH);
    let claim = Claim {
        intent: "a line".into(),
        edits: vec![format!("{PATH}#<file>")],
        ..Default::default()
    };
    let files = vec![file(PATH, text)];
    e.ok(
        "change.propose",
        None,
        Some(&t),
        json!({"base": base, "files": files, "claim": claim}),
    )
}

fn status_of(e: &mut Env, change: &Value) -> Value {
    let s = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    s["status"].clone()
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

#[test]
fn twenty_agents_on_different_lines_all_integrate() {
    let (mut e, base) = repo();
    let lines: Vec<usize> = (0..20).map(|i| i * 4).collect();
    let mut changes = Vec::new();
    for line in &lines {
        let text = edited(&seed(), *line, "7000");
        let r = propose(&mut e, &format!("a{line}"), &base, &text);
        assert_eq!(r["decision"]["outcome"], "allow", "{r}");
        changes.push(r["change"].clone());
    }
    assert_eq!(e.svc.process_all(), 20);
    for change in &changes {
        assert_eq!(status_of(&mut e, change)["status"], "integrated");
    }
    let head = e.trunk();
    let text = e.store().read_file(&head, PATH).unwrap().unwrap();
    let text = String::from_utf8(text).unwrap();
    for line in &lines {
        assert!(text.contains(&format!("int a{line} = 7000;")), "{line}");
    }
    audited(&e);
}

#[test]
fn an_overlap_is_conflicted_and_nothing_is_lost() {
    let (mut e, base) = repo();
    let first = propose(&mut e, "first", &base, &edited(&seed(), 10, "1000"));
    let second = propose(&mut e, "second", &base, &edited(&seed(), 10, "2000"));
    assert_eq!(e.svc.process_all(), 2);
    assert_eq!(status_of(&mut e, &first["change"])["status"], "integrated");
    let late = status_of(&mut e, &second["change"]);
    assert_eq!(late["status"], "conflicted", "{late}");
    assert_eq!(late["symbols"], json!([format!("{PATH}#<file>")]));
    let head = e.trunk();
    let text = e.store().read_file(&head, PATH).unwrap().unwrap();
    assert!(String::from_utf8(text).unwrap().contains("int a10 = 1000;"));
    audited(&e);
}

#[test]
fn lease_needed_and_status_say_so() {
    let (mut e, base) = repo();
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(s["unparsed_files"], "optimistic");
    let t = e.session("a", &["src/**"]);
    let files = vec![file(PATH, &edited(&seed(), 1, "9"))];
    let r = e.ok(
        "facts.preview",
        None,
        Some(&t),
        json!({"base": base, "files": files}),
    );
    assert_eq!(r["leases"], json!([]), "{r}");
    assert_eq!(r["no_lease"], json!([PATH]), "{r}");
    assert_eq!(r["facts"]["unparsed_files"], json!([PATH]), "{r}");
}

#[test]
fn by_default_status_says_file_and_preview_asks_for_the_lease() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file(PATH, &seed())], "seed");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    let s = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(s["unparsed_files"], "file");
    let t = e.session("a", &["src/**"]);
    let files = vec![file(PATH, &edited(&seed(), 1, "9"))];
    let r = e.ok(
        "facts.preview",
        None,
        Some(&t),
        json!({"base": base, "files": files}),
    );
    assert_eq!(r["no_lease"], json!([]), "{r}");
    assert_eq!(r["leases"][0]["symbol"], format!("{PATH}#<file>"), "{r}");
}
