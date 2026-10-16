//! Redaction withholds content from every reader through the daemon.

mod common;
use common::*;

#[test]
fn redacted_blobs_are_withheld() {
    let mut e = Env::new();
    e.init(None);
    e.human_change(vec![file("config.env", "API_KEY=sk-leaked\n")], "oops");
    e.svc.process_all();
    let trunk = e.trunk();
    let files = e.ok(
        "tree",
        Some("demo"),
        None,
        json!({"commit": trunk, "with_content": true}),
    );
    let blob = files[0]["blob"].as_str().unwrap().to_string();
    assert!(files[0]["content_b64"].is_string());
    let r = e.human(Op::Redact {
        blob: GitId::parse(&blob).unwrap(),
        reason: "leaked key".into(),
    });
    assert_eq!(r["decision"]["outcome"], "allow");
    let files = e.ok(
        "tree",
        Some("demo"),
        None,
        json!({"commit": trunk, "with_content": true}),
    );
    assert!(
        files[0]["content_b64"].is_null(),
        "content withheld after redaction"
    );
}
