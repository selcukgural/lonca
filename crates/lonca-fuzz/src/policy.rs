//! A repository's `lonca.toml` and `policy.cedar`, as a human proposes them
//! (`policy.update`) and as the daemon and the auditor load them from
//! `refs/lonca/policy`; and the trust file a client reads.
//!
//! An input is the configuration and the policy, cut at NUL. What parses
//! must parse again to the same, as every reader loads it anew. A policy
//! that loads is then asked what `lonca policy check` asks of it: every
//! entry of the template's log decided again under it, and whether it locks
//! a human out. A rule that fails to evaluate denies; nothing panics.

use lonca_client::trust::parse_config;
use lonca_policy::config::PolicyBundle;
use lonca_policy::state::State;
use lonca_policy::whatif::{compare, lockouts};

use crate::{template, texts};

pub fn check(data: &[u8]) {
    let [config, policy] = texts::<2>(data);
    let _ = parse_config(&config);
    let first = PolicyBundle::parse(&config, &policy);
    let again = PolicyBundle::parse(&config, &policy);
    assert_eq!(
        first.is_ok(),
        again.is_ok(),
        "a policy that parses only sometimes"
    );
    if let (Ok(a), Ok(b)) = (&first, &again) {
        assert_eq!(
            serde_json::to_value(&a.config).ok(),
            serde_json::to_value(&b.config).ok(),
            "a configuration read two ways"
        );
        let log = &template::get().log;
        let _ = compare(log, a);
        let _ = lockouts(&State::replay(log), a);
    }
}
