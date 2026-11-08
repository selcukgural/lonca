//! Files no parser reads (issue #113): under `leases.unparsed_files =
//! "optimistic"` agents edit one with no lease, the line merge at integration
//! decides, and a real overlap is `conflicted` with nothing lost.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::ops::Claim;
use lonca_core::{FileMode, GitId};
use lonca_policy::config::DEFAULT_CONFIG;
use lonca_policy::config::DEFAULT_POLICY;
use serde_json::{Value, json};

const PATH: &str = "src/Main.zig";

/// A hundred lines, so that one-line changes far apart do not touch.
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

/// A proposal of `files` by a new session, and what its lease report says.
fn asked_for(e: &mut Env, base: &GitId, files: Value) -> (Value, Value) {
    let t = e.session("a", &["src/**"]);
    e.bind(&t);
    e.wrote(&t, PATH);
    let args = json!({"base": base, "files": files});
    let preview = e.ok("facts.preview", None, Some(&t), args.clone());
    let claim = Claim {
        intent: "a change".into(),
        edits: vec![format!("{PATH}#<file>")],
        ..Default::default()
    };
    let r = e.ok(
        "change.propose",
        None,
        Some(&t),
        json!({"base": base, "files": args["files"], "claim": claim}),
    );
    (preview, r)
}

fn needs_the_lease(preview: &Value, r: &Value) {
    assert_eq!(preview["no_lease"], json!([]), "{preview}");
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    let reason = format!("lease_missing:{PATH}#<file>");
    assert!(r["decision"].to_string().contains(&reason), "{r}");
}

/// The lease is waived for lines a merge can read, and for nothing that
/// comes along with them.
#[test]
fn a_change_of_mode_takes_the_lease_also_with_an_edit() {
    for mode in [FileMode::Executable, FileMode::Symlink] {
        let (mut e, base) = repo();
        let f = FileChange {
            mode: Some(mode),
            ..file(PATH, &edited(&seed(), 5, "6"))
        };
        let (preview, r) = asked_for(&mut e, &base, json!([f]));
        needs_the_lease(&preview, &r);
    }
}

#[test]
fn a_link_that_points_elsewhere_takes_the_lease() {
    let mut e = Env::new();
    e.init(None);
    optimistic(&mut e);
    let link = |to: &str| FileChange {
        mode: Some(FileMode::Symlink),
        ..file(PATH, to)
    };
    let r = e.human_change(vec![link(&seed())], "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    let changed = link(&edited(&seed(), 5, "6"));
    let (preview, r) = asked_for(&mut e, &base, json!([changed]));
    needs_the_lease(&preview, &r);
}

/// Taking away most of a file's content does what deleting it does, and
/// deleting takes the lease.
#[test]
fn a_file_emptied_or_cut_takes_the_lease() {
    let kept: String = seed().lines().take(49).map(|l| format!("{l}\n")).collect();
    for text in ["", "\n \n", "something else\n", "    int a0 = 0;\n", &kept] {
        let (mut e, base) = repo();
        let (preview, r) = asked_for(&mut e, &base, json!([file(PATH, text)]));
        needs_the_lease(&preview, &r);
    }
}

#[test]
fn text_with_a_nul_is_not_lines_to_merge() {
    let (mut e, base) = repo();
    let text = edited(&seed(), 5, "\0");
    let (preview, r) = asked_for(&mut e, &base, json!([file(PATH, &text)]));
    needs_the_lease(&preview, &r);
}

/// What the agent is told at the proposal says the same as the decision.
#[test]
fn an_allowed_proposal_says_no_lease_was_needed() {
    let (mut e, base) = repo();
    let text = edited(&seed(), 5, "6");
    let (preview, r) = asked_for(&mut e, &base, json!([file(PATH, &text)]));
    assert_eq!(preview["no_lease"], json!([PATH]), "{preview}");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(r["details"], json!([]), "{r}");
    assert_eq!(r["advice"], json!(null), "{r}");
}

/// Creating a file is no edit of one: optimistic or not, the report asks
/// for the path, and does not call the new file free.
#[test]
fn a_new_file_no_parser_reads_still_needs_its_path() {
    let (mut e, base) = repo();
    let t = e.session("a", &["src/**"]);
    let fresh = "src/New.zig";
    let files = vec![file(fresh, "int b = 1;\n")];
    let args = json!({"base": base, "files": files});
    let r = e.ok("facts.preview", None, Some(&t), args);
    assert_eq!(r["no_lease"], json!([]), "{r}");
    assert_eq!(r["leases"][0]["symbol"], format!("{fresh}#<file>"), "{r}");
    assert_eq!(r["leases"][0]["needed_kind"], "edit", "{r}");
    assert_eq!(r["acquire"][0]["kind"], "edit", "{r}");
}
