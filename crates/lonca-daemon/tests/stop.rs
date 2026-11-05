//! An agent that stops with work nobody proposed (issue #121): it is told,
//! a bounded number of times, and `status` tells "stopped" from "done".

mod common;
use common::*;

use lonca_core::ops::{Claim, ObsKind};
use lonca_core::{FileEntry, FileMode};
use lonca_daemon::protocol::LocalFile;

const EDITED: &str =
    "pub fn charge(a: u64) -> u64 {\n    a\n}\n\npub fn refund(a: u64) -> u64 {\n    0\n}\n";

fn local(path: &str, text: &str) -> LocalFile {
    LocalFile {
        path: path.into(),
        entry: Some(FileEntry {
            mode: FileMode::Regular,
            blob: GitId::of_blob(text.as_bytes()),
        }),
    }
}

fn stop(e: &mut Env, token: &str, files: &[LocalFile]) -> Value {
    let p = json!({"harness": "claude-code", "files": files});
    e.ok("hook.stop", None, Some(token), p)
}

fn status(e: &mut Env) -> Value {
    e.ok("status", Some("demo"), None, json!({}))
}

fn mark(e: &mut Env, session: &str) -> Value {
    let st = status(e);
    let sessions = st["sessions"].as_array().unwrap();
    let s = sessions.iter().find(|s| s["id"] == session).unwrap();
    s["unproposed"].clone()
}

fn next_seq(e: &mut Env) -> u64 {
    status(e)["next_seq"].as_u64().unwrap()
}

fn repo() -> (Env, GitId, String) {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("src/lib.rs", LIB)], "seed");
    e.svc.process_all();
    let base = e.trunk();
    let token = e.session("s1", &["src/**"]);
    e.bind(&token);
    (e, base, token)
}

/// The same policy with one word of `[sessions]` changed.
fn with_config(e: &mut Env, old: &str, new: &str) {
    let config = lonca_policy::config::DEFAULT_CONFIG.replace(old, new);
    assert_ne!(config, lonca_policy::config::DEFAULT_CONFIG, "{old}");
    let p = json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY});
    let prep = e.ok("human.prepare_policy", Some("demo"), None, p);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");
}

#[test]
fn the_stop_event_is_read_with_the_profile_and_answered_in_its_shape() {
    let (mut e, _, t) = repo();
    let ws = e.root.join("ws");
    for (harness, name) in [
        ("claude-code", "Stop"),
        ("codex", "Stop"),
        ("gemini", "AfterAgent"),
        ("opencode", "stop"),
    ] {
        let input = json!({"hook_event_name": name, "session_id": "h"});
        let p = json!({"harness": harness, "input": input, "workspace": ws});
        let r = e.ok("hook.input", None, Some(&t), p);
        assert_eq!(r["phase"], "stop", "{harness}");
    }

    let r = stop(&mut e, &t, &[local("src/lib.rs", EDITED)]);
    assert_eq!(r["output"]["decision"], "block", "{r}");
    let reason = r["output"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("reached the repository: src/lib.rs."),
        "{reason}"
    );
    assert!(reason.contains("mcp__lonca__lease_needed"), "{reason}");

    let p = json!({"harness": "gemini", "files": [local("src/lib.rs", EDITED)]});
    let r = e.ok("hook.stop", None, Some(&t), p);
    assert_eq!(r["output"]["decision"], "deny", "{r}");
    assert!(
        r["output"]["reason"]
            .as_str()
            .unwrap()
            .contains("mcp_lonca_propose"),
        "{r}"
    );
    let p = json!({"harness": "opencode", "files": [local("src/lib.rs", EDITED)]});
    let r = e.ok("hook.stop", None, Some(&t), p);
    assert!(r["output"]["resume"].is_string(), "{r}");
    // No prefix of its own here beyond the server name.
    assert!(
        r["output"]["resume"]
            .as_str()
            .unwrap()
            .contains(" lonca_lease_needed"),
        "{r}"
    );
}

#[test]
fn a_harness_with_no_stop_event_or_no_profile_is_refused() {
    let (mut e, _, t) = repo();
    let p = json!({"harness": "nobody", "files": []});
    let (code, message) = e.call("hook.stop", None, Some(&t), p).unwrap_err();
    assert_eq!(code, "invalid");
    assert!(message.contains("unknown harness nobody"), "{message}");

    let mut table = lonca_policy::harness::built_in_table("codex")
        .unwrap()
        .unwrap();
    table = table.replace("stop = \"Stop\"\n", "").replace(
        "[harnesses.codex.stop_deny]\ndecision = \"block\"\nreason = \"{reason}\"\n",
        "",
    );
    let config = format!("{}\n{table}", lonca_policy::config::DEFAULT_CONFIG);
    let p = json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY});
    let prep = e.ok("human.prepare_policy", Some("demo"), None, p);
    let op: Op = serde_json::from_value(prep["op"].clone()).unwrap();
    assert_eq!(e.human(op)["decision"]["outcome"], "allow");

    let p = json!({"harness": "codex", "files": []});
    let (code, message) = e.call("hook.stop", None, Some(&t), p).unwrap_err();
    assert_eq!(code, "invalid");
    assert!(message.contains("codex has no stop event"), "{message}");
    let input = json!({"hook_event_name": "Stop"});
    let ws = e.root.join("ws");
    let p = json!({"harness": "codex", "input": input, "workspace": ws});
    let (code, _) = e.call("hook.input", None, Some(&t), p).unwrap_err();
    assert_eq!(code, "invalid", "not an event of this profile");
}

#[test]
fn a_policy_with_half_of_a_stop_event_is_refused() {
    let (mut e, _, _) = repo();
    let table = lonca_policy::harness::built_in_table("codex")
        .unwrap()
        .unwrap();
    let half = table.replace("stop = \"Stop\"\n", "");
    let config = format!("{}\n{half}", lonca_policy::config::DEFAULT_CONFIG);
    let p = json!({"config": config, "policy": lonca_policy::config::DEFAULT_POLICY});
    let r = e.call("human.prepare_policy", Some("demo"), None, p);
    let (_, message) = r.unwrap_err();
    assert!(message.contains("harness codex: events.stop"), "{message}");
}

#[test]
fn nothing_local_ends_the_turn_with_no_answer_and_no_entry() {
    let (mut e, _, t) = repo();
    let seq = next_seq(&mut e);
    let r = stop(&mut e, &t, &[]);
    assert!(r.get("output").is_none(), "{r}");
    assert_eq!(r["total"], 0);
    assert_eq!(r["round"], 0);
    assert_eq!(next_seq(&mut e), seq);
    assert!(mark(&mut e, "s1").is_null());
}

/// Rounds end, so an agent that can not propose still stops, and the mark
/// stays. After the last round an unchanged list writes nothing.
#[test]
fn the_round_limit_holds_and_the_session_stays_marked() {
    let (mut e, _, t) = repo();
    let files = [local("src/lib.rs", EDITED)];
    for round in 1..=3 {
        let r = stop(&mut e, &t, &files);
        assert!(r["output"]["reason"].is_string(), "round {round}: {r}");
        assert_eq!(r["round"], round);
        assert_eq!(r["limit"], 3);
        assert_eq!(mark(&mut e, "s1")["rounds"], round);
    }
    let seq = next_seq(&mut e);
    let r = stop(&mut e, &t, &files);
    assert!(r.get("output").is_none(), "{r}");
    assert_eq!(r["round"], 3);
    assert_eq!(r["unproposed"], json!(["src/lib.rs"]));
    assert_eq!(next_seq(&mut e), seq, "an unchanged list is not logged");

    let m = mark(&mut e, "s1");
    assert_eq!(m["paths"], json!(["src/lib.rs"]));
    assert_eq!(m["total"], 1);
    assert!(m["seen_ms"].as_i64().unwrap() > 0);

    // Past the limit the agent is left alone, but the record stays true.
    let files = [local("src/lib.rs", EDITED), local("src/new.rs", "x")];
    let r = stop(&mut e, &t, &files);
    assert!(r.get("output").is_none(), "{r}");
    assert_eq!(next_seq(&mut e), seq + 1, "a changed list is");
    let m = mark(&mut e, "s1");
    assert_eq!(m["paths"], json!(["src/lib.rs", "src/new.rs"]));
    assert_eq!(m["total"], 2);

    // The total alone, or the names alone, are news too.
    let mut files = files.to_vec();
    files.push(local("hidden\nname", "x"));
    stop(&mut e, &t, &files);
    assert_eq!(next_seq(&mut e), seq + 2);
    assert_eq!(mark(&mut e, "s1")["total"], 3);
    let same_count = [
        local("src/lib.rs", EDITED),
        local("src/other.rs", "x"),
        local("hidden\nname", "x"),
    ];
    stop(&mut e, &t, &same_count);
    assert_eq!(next_seq(&mut e), seq + 3);
    assert_eq!(mark(&mut e, "s1")["paths"][1], "src/other.rs");

    // Each report counted once, in order, and the log replays.
    let log = OpLog::new(&e.store()).read_all().unwrap();
    let reports = log.iter().filter(|o| {
        matches!(&o.entry.op, Op::Observe { events, .. }
            if matches!(events[0].kind, ObsKind::Unproposed { .. }))
    });
    assert_eq!(reports.count(), 6);
    let audit = lonca_audit::audit(&e.store(), lonca_audit::Options::default()).unwrap();
    assert!(audit.ok(), "{:#?}", audit.findings);
}

#[test]
fn a_policy_from_before_this_setting_gets_the_same_count_as_a_new_one() {
    use lonca_policy::config::{Config, PolicyBundle};
    let new = PolicyBundle::default_bundle().config.sessions.stop_rounds;
    assert_eq!(new, 3);
    assert_eq!(Config::default().sessions.stop_rounds, new);
}

#[test]
fn the_count_of_rounds_comes_from_the_policy_and_zero_only_records() {
    let (mut e, _, t) = repo();
    with_config(&mut e, "stop_rounds = 3", "stop_rounds = 1");
    let files = [local("src/lib.rs", EDITED)];
    assert!(stop(&mut e, &t, &files)["output"].is_object());
    let r = stop(&mut e, &t, &files);
    assert!(r.get("output").is_none(), "{r}");
    assert_eq!(r["limit"], 1);

    with_config(&mut e, "stop_rounds = 3", "stop_rounds = 0");
    let t2 = e.session("s2", &["src/**"]);
    let r = stop(&mut e, &t2, &files);
    assert!(r.get("output").is_none(), "{r}");
    assert_eq!(r["round"], 0);
    assert_eq!(mark(&mut e, "s2")["paths"], json!(["src/lib.rs"]));
}

/// Proposed files are told apart by their exact content.
#[test]
fn what_a_standing_proposal_carries_is_not_unproposed_and_an_edit_after_it_is() {
    let (mut e, base, t) = repo();
    e.wrote(&t, "src/lib.rs");
    e.lease(&t, "src/lib.rs#refund");
    let r = e.propose(
        &t,
        &base,
        vec![file("src/lib.rs", EDITED)],
        &["src/lib.rs#refund"],
    );
    assert_ne!(r["decision"]["outcome"], "deny", "{r}");

    let seq = next_seq(&mut e);
    let r = stop(&mut e, &t, &[local("src/lib.rs", EDITED)]);
    assert!(r.get("output").is_none(), "pending: {r}");
    assert_eq!(next_seq(&mut e), seq);

    let again = format!("{EDITED}// more\n");
    let r = stop(&mut e, &t, &[local("src/lib.rs", &again)]);
    assert!(r["output"].is_object(), "edited since: {r}");

    // A local mode change is a change, with the same bytes.
    let mut chmod = local("src/lib.rs", EDITED);
    chmod.entry.as_mut().unwrap().mode = FileMode::Executable;
    let r = stop(&mut e, &t, &[chmod]);
    assert_eq!(r["total"], 1, "{r}");
    // A deletion nobody proposed.
    let gone = LocalFile {
        path: "src/lib.rs".into(),
        entry: None,
    };
    assert_eq!(stop(&mut e, &t, &[gone])["total"], 1);
}

#[test]
fn a_change_integrated_and_a_deletion_proposed_count_as_delivered() {
    let (mut e, base, _) = repo();
    e.human_change(vec![file("notes.md", "n\n")], "notes");
    e.svc.process_all();
    let base2 = e.trunk();
    assert_ne!(base, base2);
    let t2 = e.session("s2", &["**"]);
    e.bind(&t2);
    e.wrote(&t2, "notes.md");
    let items = vec![LeaseItem {
        symbol: "notes.md#<file>".into(),
        kind: LeaseKind::Rename,
    }];
    let p = json!({"items": items, "intent": "drop", "ttl_ms": 600_000});
    e.ok("lease.acquire", None, Some(&t2), p);
    let gone = FileChange {
        path: "notes.md".into(),
        content_b64: None,
        mode: None,
    };
    let claim = Claim {
        intent: "drop the notes".into(),
        deleted_files: vec!["notes.md".into()],
        ..Default::default()
    };
    let p = json!({"base": base2, "files": [gone], "claim": claim});
    let r = e.ok("change.propose", None, Some(&t2), p);
    assert_ne!(r["decision"]["outcome"], "deny", "{r}");
    let local_gone = LocalFile {
        path: "notes.md".into(),
        entry: None,
    };
    let queued = stop(&mut e, &t2, std::slice::from_ref(&local_gone));
    assert_eq!(queued["total"], 0, "{queued}");
    e.svc.process_all();
    let st = status(&mut e);
    let changes = st["changes"].as_array().unwrap();
    let dropped = changes.iter().find(|c| c["intent"] == "drop the notes");
    assert_eq!(dropped.unwrap()["status"]["status"], "integrated", "{st}");
    assert_eq!(stop(&mut e, &t2, &[local_gone])["total"], 0);
}

#[test]
fn a_change_that_did_not_stand_delivered_nothing() {
    let (mut e, base, t) = repo();
    e.wrote(&t, "src/lib.rs");
    e.lease(&t, "src/lib.rs#refund");
    let r = e.propose(
        &t,
        &base,
        vec![file("src/lib.rs", EDITED)],
        &["src/lib.rs#refund"],
    );
    let change: ChangeId = serde_json::from_value(r["change"].clone()).unwrap();
    assert_eq!(stop(&mut e, &t, &[local("src/lib.rs", EDITED)])["total"], 0);
    let w = e.human(Op::ChangeWithdraw { change });
    assert_eq!(w["decision"]["outcome"], "allow", "{w}");
    let r = stop(&mut e, &t, &[local("src/lib.rs", EDITED)]);
    assert_eq!(r["total"], 1, "withdrawn: {r}");
}

#[test]
fn another_session_s_proposal_does_not_count_but_the_one_continued_from_does() {
    let (mut e, base, t) = repo();
    e.wrote(&t, "src/lib.rs");
    e.lease(&t, "src/lib.rs#refund");
    e.propose(
        &t,
        &base,
        vec![file("src/lib.rs", EDITED)],
        &["src/lib.rs#refund"],
    );
    let other = e.session("s2", &["src/**"]);
    assert_eq!(
        stop(&mut e, &other, &[local("src/lib.rs", EDITED)])["total"],
        1
    );

    let next = e.continue_session("s3", "s1", &["src/**"]);
    let t3 = next["token"].as_str().unwrap().to_string();
    assert_eq!(
        stop(&mut e, &t3, &[local("src/lib.rs", EDITED)])["total"],
        0
    );
    let again = e.continue_session("s4", "s3", &["src/**"]);
    let t4 = again["token"].as_str().unwrap().to_string();
    assert_eq!(
        stop(&mut e, &t4, &[local("src/lib.rs", EDITED)])["total"],
        0
    );
}

/// A proposal starts the count over; a denied one is no progress, so an
/// agent that can only be denied still runs out of rounds.
#[test]
fn a_proposal_that_stands_starts_over_and_a_denied_one_does_not() {
    let (mut e, base, t) = repo();
    let files = [local("src/lib.rs", EDITED)];
    stop(&mut e, &t, &files);
    stop(&mut e, &t, &files);
    assert_eq!(mark(&mut e, "s1")["rounds"], 2);

    // No lease: denied.
    let r = e.propose(
        &t,
        &base,
        vec![file("src/lib.rs", EDITED)],
        &["src/lib.rs#refund"],
    );
    assert_eq!(r["decision"]["outcome"], "deny", "{r}");
    assert_eq!(mark(&mut e, "s1")["rounds"], 2);

    e.wrote(&t, "src/lib.rs");
    e.lease(&t, "src/lib.rs#refund");
    let r = e.propose(
        &t,
        &base,
        vec![file("src/lib.rs", EDITED)],
        &["src/lib.rs#refund"],
    );
    assert_ne!(r["decision"]["outcome"], "deny", "{r}");
    assert!(mark(&mut e, "s1").is_null(), "the proposal clears the mark");

    let next = [local("src/other.rs", "x")];
    assert_eq!(stop(&mut e, &t, &next)["round"], 1);
}

#[test]
fn another_session_s_proposal_leaves_a_mark_alone() {
    let (mut e, base, t) = repo();
    stop(&mut e, &t, &[local("src/lib.rs", EDITED)]);
    let other = e.session("s2", &["src/**"]);
    e.bind(&other);
    e.wrote(&other, "src/lib.rs");
    e.lease(&other, "src/lib.rs#refund");
    let r = e.propose(
        &other,
        &base,
        vec![file("src/lib.rs", EDITED)],
        &["src/lib.rs#refund"],
    );
    assert_ne!(r["decision"]["outcome"], "deny", "{r}");
    assert_eq!(mark(&mut e, "s1")["rounds"], 1);
}

#[test]
fn a_clean_stop_clears_the_mark_and_the_count() {
    let (mut e, _, t) = repo();
    stop(&mut e, &t, &[local("src/lib.rs", EDITED)]);
    assert!(mark(&mut e, "s1").is_object());
    let seq = next_seq(&mut e);
    stop(&mut e, &t, &[]);
    assert_eq!(next_seq(&mut e), seq + 1, "the clearing is logged");
    assert!(mark(&mut e, "s1").is_null());
    assert_eq!(stop(&mut e, &t, &[local("a", "b")])["round"], 1);
}

#[test]
fn names_unfit_to_show_count_but_are_not_listed_and_the_list_is_capped() {
    let (mut e, _, t) = repo();
    let mut files: Vec<LocalFile> = (0..40).map(|i| local(&format!("f{i:02}"), "x")).collect();
    files.insert(0, local("a\u{202E}b", "x"));
    files.insert(1, local("a\nb", "x"));
    let r = stop(&mut e, &t, &files);
    assert_eq!(r["total"], 42);
    let listed = r["unproposed"].as_array().unwrap();
    assert_eq!(listed.len(), 32);
    assert_eq!(listed[0], "f00");
    assert_eq!(mark(&mut e, "s1")["total"], 42);
    let reason = r["output"]["reason"].as_str().unwrap();
    assert!(reason.contains("f19 and 22 more."), "{reason}");
}

#[test]
fn session_end_records_what_was_left_and_tells_nobody() {
    let (mut e, _, t) = repo();
    let p = json!({"files": [local("src/lib.rs", EDITED)]});
    let r = e.ok("session.end", None, Some(&t), p);
    assert_eq!(r["unproposed"], json!(["src/lib.rs"]));
    assert_eq!(r["unproposed_total"], 1);
    assert!(r.get("output").is_none(), "{r}");
    let m = mark(&mut e, "s1");
    assert_eq!(m["paths"], json!(["src/lib.rs"]));
    assert_eq!(m["rounds"], 1);
}

#[test]
fn a_client_that_sends_no_files_changes_nothing_on_the_record() {
    let (mut e, _, t) = repo();
    stop(&mut e, &t, &[local("src/lib.rs", EDITED)]);
    let r = e.ok("session.end", None, Some(&t), json!({}));
    assert!(r.get("unproposed").is_none(), "{r}");
    assert_eq!(mark(&mut e, "s1")["rounds"], 1);
}

#[test]
fn the_mark_survives_a_restart() {
    let (mut e, _, t) = repo();
    stop(&mut e, &t, &[local("src/lib.rs", EDITED)]);
    e.reopen();
    assert_eq!(mark(&mut e, "s1")["paths"], json!(["src/lib.rs"]));
}
