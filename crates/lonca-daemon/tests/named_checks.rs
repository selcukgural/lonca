//! Checks a change owes, chosen per change from the signed policy (issue
//! #191): a human names them at approval, or the policy does for a path;
//! the queue runs them on the merged tree and the log keeps their evidence.

mod common;
use common::*;

use lonca_audit::{Options, audit};
use lonca_core::ops::{CheckKind, CheckResult};
use lonca_policy::config::{DEFAULT_CONFIG, DEFAULT_POLICY};

const LIB: &str = "pub fn refund(a: u64) -> u64 {\n    a\n}\n\npub fn other() {}\n";

fn repo(checks: &str, by_path: &str) -> (Env, GitId) {
    let mut e = Env::new();
    e.init(None);
    let config = DEFAULT_CONFIG
        .replace("# test = \"cargo test --offline\"", "test = \"true\"")
        .replace("\nchecks = {}\n", &format!("\nchecks = {checks}\n"))
        .replace(
            "\nchecks_by_path = {}\n",
            &format!("\nchecks_by_path = {by_path}\n"),
        );
    assert!(config.contains(checks) && config.contains(by_path));
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let files = vec![file("src/lib.rs", LIB), file("web/page.rs", LIB)];
    let r = e.human_change(files, "seed");
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let base = e.trunk();
    (e, base)
}

/// A tainted session's change of `path`, waiting for a human: its seq and
/// change id.
fn waiting(e: &mut Env, base: &GitId, name: &str, path: &str) -> (u64, Value) {
    let token = e.session(name, &["**"]);
    e.bind(&token);
    let fetch = json!({"hook_event_name": "PreToolUse", "tool_name": "WebFetch", "tool_input": {"url": "https://example.com/card"}, "workspace": e.root.join("ws")});
    e.ok("hook.event", None, Some(&token), fetch);
    e.wrote(&token, path);
    let sym = format!("{path}#refund");
    e.lease(&token, &sym);
    let new = LIB.replace("    a\n", "    0\n");
    let r = e.propose(&token, base, vec![file(path, &new)], &[&sym]);
    assert_eq!(r["decision"]["outcome"], "escalate", "{r}");
    (r["seq"].as_u64().unwrap(), r["change"].clone())
}

fn approve(e: &mut Env, seq: u64, checks: &[&str]) -> Value {
    e.human(Op::Approve {
        target_seq: seq,
        note: "card T-1".into(),
        checks: checks.iter().map(|c| c.to_string()).collect(),
    })
}

fn listed(e: &mut Env, key: &str, field: &str, value: &Value) -> Value {
    let st = e.ok("status", Some("demo"), None, json!({}));
    let all = st[key].as_array().unwrap();
    let found = all.iter().find(|x| &x[field] == value);
    found.cloned().unwrap_or(Value::Null)
}

fn audited(e: &Env) {
    let r = audit(&e.store(), Options::default()).unwrap();
    assert!(r.ok(), "{:#?}", r.findings);
}

/// The issue's scenario: the human approves with `api`, the review list
/// said what would run before, the queue runs it, and the evidence names it.
#[test]
fn a_check_named_at_approval_runs_and_is_on_the_record() {
    let (mut e, base) = repo("{ api = \"test -f src/lib.rs\", e2e = \"exit 5\" }", "{}");
    let st = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(st["policy_checks"], json!(["api", "e2e"]), "{st}");
    assert!(
        !st.to_string().contains("test -f"),
        "a command reached a client: {st}"
    );
    let (seq, change) = waiting(&mut e, &base, "s1", "src/lib.rs");
    let p = listed(&mut e, "pending", "seq", &json!(seq));
    assert_eq!(p["runs"], json!(["tests"]), "{p}");
    assert_eq!(p["checks"], json!([]), "{p}");

    let r = approve(&mut e, seq, &["api"]);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    let c = listed(&mut e, "changes", "change", &change);
    assert_eq!(c["runs"], json!(["tests", "api"]), "{c}");
    assert_eq!(c["checks"], json!(["api"]), "{c}");
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["runs"], json!(["tests", "api"]), "{rec}");
    assert_eq!(rec["checks"], json!(["api"]), "{rec}");

    assert_eq!(e.svc.process_all(), 1);
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["status"]["status"], "integrated", "{rec}");
    let evidence = rec["evidence"].as_array().unwrap();
    let api = evidence.iter().find(|a| a["check"] == "named").unwrap();
    assert_eq!(api["details"]["name"], "api", "{api}");
    assert_eq!(api["result"], "pass");
    assert_eq!(api["exit"], 0);
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let last = &ops.last().unwrap().entry;
    let kinds: Vec<CheckKind> = last.evidence.iter().map(|a| a.check).collect();
    assert_eq!(
        kinds,
        [CheckKind::Syntax, CheckKind::Tests, CheckKind::Named]
    );
    audited(&e);
}

/// A named check that fails rejects the change with its name and its
/// output, as a failed test does.
#[test]
fn a_failing_named_check_rejects_the_change() {
    let (mut e, base) = repo("{ e2e = \"echo e2e went wrong; exit 5\" }", "{}");
    let (seq, change) = waiting(&mut e, &base, "s1", "src/lib.rs");
    let r = approve(&mut e, seq, &["e2e"]);
    assert_eq!(r["decision"]["outcome"], "allow", "{r}");
    assert_eq!(e.svc.process_all(), 1);
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["status"]["status"], "rejected", "{rec}");
    let reasons = rec["integrate_decision"]["reasons"].to_string();
    assert!(reasons.contains("verification_failed:e2e"), "{reasons}");
    let evidence = rec["evidence"].as_array().unwrap();
    let e2e = evidence.iter().find(|a| a["check"] == "named").unwrap();
    assert_eq!(e2e["result"], "fail");
    assert_eq!(e2e["exit"], 5);
    assert!(
        e2e["log"].as_str().unwrap().contains("e2e went wrong"),
        "{e2e}"
    );
    audited(&e);
}

/// An approval can not name what the policy does not define, and the
/// agent can not approve at all.
#[test]
fn an_unknown_check_is_refused_at_approval() {
    let (mut e, base) = repo("{ api = \"true\" }", "{}");
    let (seq, _) = waiting(&mut e, &base, "s1", "src/lib.rs");
    let r = approve(&mut e, seq, &["deploy"]);
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert!(r.to_string().contains("unknown_check:deploy"), "{r}");
    let p = listed(&mut e, "pending", "seq", &json!(seq));
    assert_eq!(p["seq"], seq, "still pending");
    audited(&e);
}

/// `checks_by_path`: what the policy names for a path is owed with nobody
/// asking, and listed before the yes.
#[test]
fn the_policy_names_a_check_for_a_path() {
    let (mut e, base) = repo(
        "{ web = \"test -f web/page.rs\" }",
        "{ \"web/**\" = [\"web\"] }",
    );
    let (seq, change) = waiting(&mut e, &base, "s1", "web/page.rs");
    let p = listed(&mut e, "pending", "seq", &json!(seq));
    assert_eq!(p["runs"], json!(["tests", "web"]), "{p}");
    assert_eq!(p["checks"], json!([]), "nobody asked: {p}");
    assert_eq!(approve(&mut e, seq, &[])["decision"]["outcome"], "allow");
    assert_eq!(e.svc.process_all(), 1);
    let rec = e.ok("change.get", Some("demo"), None, json!({"change": change}));
    assert_eq!(rec["status"]["status"], "integrated", "{rec}");
    let named: Vec<_> = rec["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["check"] == "named")
        .map(|a| (a["details"]["name"].clone(), a["result"].clone()))
        .collect();
    assert_eq!(named, [(json!("web"), json!("pass"))]);
    // A change elsewhere owes nothing named.
    let base = e.trunk();
    let (seq, change) = waiting(&mut e, &base, "s2", "src/lib.rs");
    assert_eq!(approve(&mut e, seq, &[])["decision"]["outcome"], "allow");
    let c = listed(&mut e, "changes", "change", &change);
    assert_eq!(c["runs"], json!(["tests"]), "{c}");
    assert_eq!(e.svc.process_all(), 1);
    let ops = OpLog::new(&e.store()).read_all().unwrap();
    let last = &ops.last().unwrap().entry;
    assert!(last.decision.is_allow(), "{:?}", last.decision);
    let none = last.evidence.iter().all(|a| a.check != CheckKind::Named);
    assert!(none, "{:?}", last.evidence);
    let passed = last.evidence.iter().all(|a| a.result == CheckResult::Pass);
    assert!(passed);
    audited(&e);
}

/// `status` names the checks of the policy in force, sorted, so a runner
/// can refuse a name before the approval does; none defined is `[]`, and a
/// new policy is seen at once.
#[test]
fn status_lists_the_checks_the_policy_in_force_defines() {
    let (mut e, _) = repo("{}", "{}");
    let st = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(st["policy_checks"], json!([]), "{st}");

    // The table form, which comes out the same as the inline one.
    let config = DEFAULT_CONFIG.replace("\nchecks = {}\n", "\n")
        + "\n[verification.checks]\nzeta = \"true\"\napi = \"true\"\n";
    let prep = e.ok(
        "human.prepare_policy",
        Some("demo"),
        None,
        json!({"config": config, "policy": DEFAULT_POLICY}),
    );
    let op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
    let st = e.ok("status", Some("demo"), None, json!({}));
    assert_eq!(st["policy_checks"], json!(["api", "zeta"]), "{st}");

    let token = e.session("s1", &["**"]);
    let st = e.ok("status", Some("demo"), Some(&token), json!({}));
    assert_eq!(st["policy_checks"], json!(["api", "zeta"]), "{st}");
    audited(&e);
}
