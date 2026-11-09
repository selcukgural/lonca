//! The guide's Cedar examples parse, and what docs/guide/policies.md says
//! about errors and lockouts holds.

use lonca_core::ops::Actor;
use lonca_policy::config::{CVal, CedarOutcome, DEFAULT_CONFIG, PolicyBundle};

fn guide(page: &str) -> String {
    let path = format!("{}/../../docs/guide/{page}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn cedar_blocks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(l) = lines.next() {
        if l.trim() == "```cedar" {
            let block: Vec<&str> = lines.by_ref().take_while(|l| l.trim() != "```").collect();
            out.push(block.join("\n"));
        }
    }
    out
}

#[test]
fn every_cedar_example_of_the_guide_parses() {
    let mut n = 0;
    for page in ["policies.md", "runners.md"] {
        for block in cedar_blocks(&guide(page)) {
            let policy = format!("permit(principal, action, resource);\n{block}");
            if let Err(e) = PolicyBundle::parse(DEFAULT_CONFIG, &policy) {
                panic!("{page}: {e}\n{block}");
            }
            n += 1;
        }
    }
    assert!(n >= 8, "{n} examples");
}

/// "A key that a request does not have is an error, and an error denies",
/// for humans too, and `context has` avoids it.
#[test]
fn a_rule_that_reads_a_missing_key_denies_and_has_avoids_it() {
    let human = Actor::Human {
        name: "ayse".into(),
    };
    let ctx = || {
        vec![
            ("tainted", CVal::Bool(false)),
            ("observation", CVal::Str("none".into())),
        ]
    };
    let bad = PolicyBundle::parse(
        DEFAULT_CONFIG,
        "permit(principal, action, resource);\n\
         forbid(principal, action, resource) when { context.path like \"x/*\" };",
    )
    .unwrap();
    match bad.evaluate(&human, "policy.update", ctx()) {
        CedarOutcome::Deny(r) => assert!(r[0].starts_with("policy_error:"), "{r:?}"),
        other => panic!("{other:?}"),
    }
    let good = PolicyBundle::parse(
        DEFAULT_CONFIG,
        "permit(principal, action, resource);\n\
         forbid(principal, action, resource) when { context has path && context.path like \"x/*\" };",
    )
    .unwrap();
    assert_eq!(
        good.evaluate(&human, "policy.update", ctx()),
        CedarOutcome::Allow
    );
}
