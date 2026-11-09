//! A hook event, as the daemon reads it with a harness's profile from the
//! policy: the tool and its input are whatever the agent asked for.
//!
//! The first byte picks the harness among the built-in profiles (data, not
//! a list here); the rest is the event as JSON (`HookEvent`).
//! The same bytes are also read as that harness's locked settings file.
//! Every event gets a verdict the harness understands; none panics.

use std::sync::OnceLock;

use lonca_client::protocol::HookEvent;
use lonca_daemon::hooks::translate;
use lonca_policy::config::PolicyBundle;

use crate::{choice, pick};

const SCRATCH: &str = "/tmp/lonca-fuzz-scratch";

fn policy() -> &'static PolicyBundle {
    static P: OnceLock<PolicyBundle> = OnceLock::new();
    P.get_or_init(PolicyBundle::default_bundle)
}

pub fn check(data: &[u8]) {
    let Some((c, rest)) = choice(data) else {
        return;
    };
    let policy = policy();
    let names: Vec<&String> = lonca_policy::harness::built_in().keys().collect();
    let Some(&name) = pick(&names, c) else {
        return;
    };
    if let Some(locked) = policy.config.locked(name) {
        let _ = locked.parse(rest);
    }
    let Ok(mut ev) = serde_json::from_slice::<HookEvent>(rest) else {
        return;
    };
    if ev.harness.is_none() {
        ev.harness = Some(name.clone());
    }
    let (_, verdict) = translate(&ev, policy, &[SCRATCH.to_string()]);
    assert!(
        ["allow", "deny", "ask"].contains(&verdict.decision.as_str()),
        "a verdict no harness reads: {:?}",
        verdict.decision
    );
}
