//! Policy bundle: `lonca.toml` (limits and switches) plus `policy.cedar`
//! (rules). Both live in the commit that `refs/lonca/policy` points to, never
//! in a code branch.

use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Entities, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression,
};
use lonca_core::canonical::sha256_hex;
use lonca_core::ops::Actor;
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "lonca.toml";
pub const POLICY_FILE: &str = "policy.cedar";

pub const DEFAULT_CONFIG: &str = r#"# Lonca repository configuration. Lives on refs/lonca/policy.

[sessions]
max_ttl_minutes = 480

[leases]
max_ttl_minutes = 30
max_items = 64

[changes]
max_files = 200
max_file_bytes = 2097152

[paths]
# Changes here run code during build/test or define CI: they always need a
# human approval, and tainted sessions may not touch them at all.
critical = [
  ".github/**", ".gitlab-ci.yml", ".lonca/**",
  "**/build.rs", "**/Cargo.toml", "**/Cargo.lock",
  "**/package.json", "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
  "**/Makefile", "**/*.csproj", "**/Directory.Build.props", "**/Directory.Build.targets",
  "**/global.json", "**/NuGet.config", "**/pyproject.toml", "**/setup.py",
]
# Reading these taints a session.
untrusted = ["vendor/**", "third_party/**", "node_modules/**"]

[verification]
# Commands run by the verifier in a sandbox on the merged tree.
# build = "cargo build --offline"
# test = "cargo test --offline"
required = false
require_sandbox = false
timeout_seconds = 900
retries = 0

[observation]
# Sessions that nothing observes are treated like tainted sessions.
unobserved_is_tainted = true

[approvals]
# With fewer enrolled humans than a rule requires, require all of them.
cap_to_enrolled_humans = true
policy_updates = 1

[negotiation]
max_rounds = 4

[reverts]
window_minutes = 5

[integrity]
# What to do when a ref changes behind the daemon's back: "restore" or "freeze".
on_unmediated = "restore"
"#;

pub const DEFAULT_POLICY: &str = r#"// Lonca policy. Requests are allowed unless a rule below forbids them.
// A forbid rule annotated with @escalate turns the request into a human
// approval request instead of a denial; @approvals sets how many humans.
//
// Actions: file.add, file.modify, file.delete (one request per file) and
// one request per operation named like the operation ("change.propose",
// "lease.acquire", ...).

permit(principal, action, resource);

@id("migrations-no-agent-delete")
forbid(principal is Lonca::Agent, action == Lonca::Action::"file.delete", resource)
when { context.path like "migrations/*" };

@id("auth-needs-two-humans")
@escalate("auth")
@approvals("2")
forbid(principal is Lonca::Agent, action in [Lonca::Action::"file.add", Lonca::Action::"file.modify", Lonca::Action::"file.delete"], resource)
when { context.path like "auth/*" || context.path like "*/auth/*" };

@id("revert-storm")
@escalate("revert-storm")
forbid(principal is Lonca::Agent, action == Lonca::Action::"change.propose", resource)
when { context.recent_reverts >= 3 };

@id("blast-radius")
@escalate("blast-radius")
forbid(principal is Lonca::Agent, action == Lonca::Action::"change.propose", resource)
when { context.files > 50 || context.lines > 2000 };
"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
#[derive(Default)]
pub struct Config {
    pub sessions: Sessions,
    pub leases: Leases,
    pub changes: Changes,
    pub paths: Paths,
    pub verification: Verification,
    pub observation: Observation,
    pub approvals: Approvals,
    pub negotiation: Negotiation,
    pub reverts: Reverts,
    pub integrity: Integrity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sessions {
    pub max_ttl_minutes: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Leases {
    pub max_ttl_minutes: i64,
    pub max_items: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Changes {
    pub max_files: u32,
    pub max_file_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Paths {
    pub critical: Vec<String>,
    pub untrusted: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Verification {
    pub build: Option<String>,
    pub test: Option<String>,
    pub required: bool,
    pub require_sandbox: bool,
    pub timeout_seconds: u64,
    pub retries: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Observation {
    pub unobserved_is_tainted: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Approvals {
    pub cap_to_enrolled_humans: bool,
    pub policy_updates: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Negotiation {
    pub max_rounds: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Reverts {
    pub window_minutes: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Integrity {
    pub on_unmediated: String,
}

// Defaults must equal DEFAULT_CONFIG (checked by a test): a key missing from
// lonca.toml behaves like the shipped file.

impl Default for Sessions {
    fn default() -> Self {
        Self {
            max_ttl_minutes: 480,
        }
    }
}

impl Default for Leases {
    fn default() -> Self {
        Self {
            max_ttl_minutes: 30,
            max_items: 64,
        }
    }
}

impl Default for Changes {
    fn default() -> Self {
        Self {
            max_files: 200,
            max_file_bytes: 2_097_152,
        }
    }
}

impl Default for Paths {
    fn default() -> Self {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect();
        Self {
            critical: s(&[
                ".github/**",
                ".gitlab-ci.yml",
                ".lonca/**",
                "**/build.rs",
                "**/Cargo.toml",
                "**/Cargo.lock",
                "**/package.json",
                "**/package-lock.json",
                "**/yarn.lock",
                "**/pnpm-lock.yaml",
                "**/Makefile",
                "**/*.csproj",
                "**/Directory.Build.props",
                "**/Directory.Build.targets",
                "**/global.json",
                "**/NuGet.config",
                "**/pyproject.toml",
                "**/setup.py",
            ]),
            untrusted: s(&["vendor/**", "third_party/**", "node_modules/**"]),
        }
    }
}

impl Default for Verification {
    fn default() -> Self {
        Self {
            build: None,
            test: None,
            required: false,
            require_sandbox: false,
            timeout_seconds: 900,
            retries: 0,
        }
    }
}

impl Default for Observation {
    fn default() -> Self {
        Self {
            unobserved_is_tainted: true,
        }
    }
}

impl Default for Approvals {
    fn default() -> Self {
        Self {
            cap_to_enrolled_humans: true,
            policy_updates: 1,
        }
    }
}

impl Default for Negotiation {
    fn default() -> Self {
        Self { max_rounds: 4 }
    }
}

impl Default for Reverts {
    fn default() -> Self {
        Self { window_minutes: 5 }
    }
}

impl Default for Integrity {
    fn default() -> Self {
        Self {
            on_unmediated: "restore".into(),
        }
    }
}

/// Config path patterns: the capability pattern language plus `**/name` (a
/// file name anywhere) and `**/*.ext` (an extension anywhere).
pub fn config_pattern_matches(pattern: &str, path: &str) -> bool {
    if let Some(rest) = pattern.strip_prefix("**/") {
        let base = path.rsplit('/').next().unwrap_or(path);
        if let Some(ext) = rest.strip_prefix('*') {
            return base.ends_with(ext) && base.len() > ext.len();
        }
        if !rest.contains('/') {
            return base == rest;
        }
    }
    lonca_core::paths::path_matches(pattern, path)
}

#[derive(Clone, Debug)]
pub enum CVal {
    Str(String),
    Long(i64),
    Bool(bool),
    StrSet(Vec<String>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CedarOutcome {
    Allow,
    Deny(Vec<String>),
    Escalate { rules: Vec<String>, approvals: u32 },
}

pub struct PolicyBundle {
    pub config: Config,
    pub cedar: PolicySet,
    pub digest: String,
    pub config_text: String,
    pub policy_text: String,
}

impl PolicyBundle {
    pub fn default_bundle() -> Self {
        Self::parse(DEFAULT_CONFIG, DEFAULT_POLICY).expect("default policy parses")
    }

    pub fn parse(config_text: &str, policy_text: &str) -> Result<Self, String> {
        let config: Config =
            toml::from_str(config_text).map_err(|e| format!("{CONFIG_FILE}: {e}"))?;
        for p in config.paths.critical.iter().chain(&config.paths.untrusted) {
            let ok = p.starts_with("**/") || lonca_core::paths::validate_path_pattern(p).is_ok();
            if !ok {
                return Err(format!("{CONFIG_FILE}: bad path pattern {p:?}"));
            }
        }
        if !matches!(
            config.integrity.on_unmediated.as_str(),
            "restore" | "freeze"
        ) {
            return Err(format!(
                "{CONFIG_FILE}: integrity.on_unmediated must be restore or freeze"
            ));
        }
        let cedar = PolicySet::from_str(policy_text).map_err(|e| format!("{POLICY_FILE}: {e}"))?;
        for p in cedar.policies() {
            if let Some(n) = p.annotation("approvals") {
                match n.parse::<u32>() {
                    Ok(1..=9) => {}
                    _ => {
                        return Err(format!(
                            "{POLICY_FILE}: policy {}: @approvals must be 1..9",
                            p.id()
                        ));
                    }
                }
            }
        }
        let digest = sha256_hex(format!("{config_text}\0{policy_text}").as_bytes());
        Ok(Self {
            config,
            cedar,
            digest,
            config_text: config_text.to_string(),
            policy_text: policy_text.to_string(),
        })
    }

    pub fn is_critical(&self, path: &str) -> bool {
        self.config
            .paths
            .critical
            .iter()
            .any(|p| config_pattern_matches(p, path))
    }

    pub fn is_untrusted(&self, path: &str) -> bool {
        self.config
            .paths
            .untrusted
            .iter()
            .any(|p| config_pattern_matches(p, path))
    }

    /// Evaluates one request. Any evaluation error counts as a denial: a
    /// forbid rule that fails to evaluate must not silently stop applying.
    pub fn evaluate(
        &self,
        principal: &Actor,
        action: &str,
        context: Vec<(&str, CVal)>,
    ) -> CedarOutcome {
        let (ptype, pid) = match principal {
            Actor::Human { name } => ("Lonca::Human", name.as_str()),
            Actor::Agent { name, .. } => ("Lonca::Agent", name.as_str()),
            Actor::Daemon => ("Lonca::Daemon", "daemon"),
        };
        let uid = |t: &str, id: &str| {
            EntityUid::from_type_name_and_id(
                EntityTypeName::from_str(t).expect("valid type"),
                EntityId::new(id),
            )
        };
        let pairs = context.into_iter().map(|(k, v)| {
            let expr = match v {
                CVal::Str(s) => RestrictedExpression::new_string(s),
                CVal::Long(n) => RestrictedExpression::new_long(n),
                CVal::Bool(b) => RestrictedExpression::new_bool(b),
                CVal::StrSet(v) => RestrictedExpression::new_set(
                    v.into_iter().map(RestrictedExpression::new_string),
                ),
            };
            (k.to_string(), expr)
        });
        let ctx = match Context::from_pairs(pairs) {
            Ok(c) => c,
            Err(e) => return CedarOutcome::Deny(vec![format!("policy_error:{e}")]),
        };
        let req = match Request::new(
            uid(ptype, pid),
            uid("Lonca::Action", action),
            uid("Lonca::Repo", "repo"),
            ctx,
            None,
        ) {
            Ok(r) => r,
            Err(e) => return CedarOutcome::Deny(vec![format!("policy_error:{e}")]),
        };
        let resp = Authorizer::new().is_authorized(&req, &self.cedar, &Entities::empty());
        let errors: Vec<String> = resp.diagnostics().errors().map(|e| e.to_string()).collect();
        if !errors.is_empty() {
            return CedarOutcome::Deny(
                errors
                    .into_iter()
                    .map(|e| format!("policy_error:{e}"))
                    .collect(),
            );
        }
        if resp.decision() == cedar_policy::Decision::Allow {
            return CedarOutcome::Allow;
        }
        let reasons: Vec<_> = resp.diagnostics().reason().cloned().collect();
        if reasons.is_empty() {
            return CedarOutcome::Deny(vec![format!("policy_default_deny:{action}")]);
        }
        let mut rules = Vec::new();
        let mut approvals = 1u32;
        let mut all_escalate = true;
        for id in &reasons {
            let policy = self
                .cedar
                .policy(id)
                .expect("reason ids come from this set");
            let name = policy
                .annotation("id")
                .map(str::to_string)
                .unwrap_or_else(|| id.to_string());
            match policy.annotation("escalate") {
                Some(_) => {
                    let n = policy
                        .annotation("approvals")
                        .and_then(|a| a.parse().ok())
                        .unwrap_or(1);
                    approvals = approvals.max(n);
                }
                None => all_escalate = false,
            }
            rules.push(format!("policy:{name}"));
        }
        rules.sort();
        if all_escalate {
            CedarOutcome::Escalate { rules, approvals }
        } else {
            CedarOutcome::Deny(rules)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Actor {
        Actor::Agent {
            name: "bot".into(),
            session: "ses_1".into(),
        }
    }

    #[test]
    fn defaults_parse() {
        let b = PolicyBundle::default_bundle();
        assert_eq!(b.config.leases.max_ttl_minutes, 30);
        assert!(b.is_critical("Cargo.toml"));
        assert!(b.is_critical("crates/x/Cargo.toml"));
        assert!(b.is_critical(".github/workflows/ci.yml"));
        assert!(b.is_critical("app/app.csproj"));
        assert!(!b.is_critical("src/main.rs"));
        assert!(b.is_untrusted("vendor/lib/a.c"));
    }

    #[test]
    fn code_defaults_equal_shipped_file() {
        let shipped: Config = toml::from_str(DEFAULT_CONFIG).unwrap();
        assert_eq!(
            toml::to_string(&shipped).unwrap(),
            toml::to_string(&Config::default()).unwrap()
        );
    }

    #[test]
    fn partial_config_uses_defaults_and_unknown_keys_fail() {
        let b = PolicyBundle::parse("[leases]\nmax_ttl_minutes = 10\n", DEFAULT_POLICY).unwrap();
        assert_eq!(b.config.leases.max_ttl_minutes, 10);
        assert_eq!(b.config.leases.max_items, 64);
        assert_eq!(b.config.sessions.max_ttl_minutes, 480);
        assert!(PolicyBundle::parse("[leases]\nmax_ttl = 10\n", DEFAULT_POLICY).is_err());
    }

    #[test]
    fn forbid_and_escalate() {
        let b = PolicyBundle::default_bundle();
        let file = |p: &str| vec![("path", CVal::Str(p.into()))];
        assert_eq!(
            b.evaluate(&agent(), "file.delete", file("src/a.rs")),
            CedarOutcome::Allow
        );
        assert_eq!(
            b.evaluate(&agent(), "file.delete", file("migrations/001.sql")),
            CedarOutcome::Deny(vec!["policy:migrations-no-agent-delete".into()])
        );
        assert_eq!(
            b.evaluate(&agent(), "file.modify", file("auth/login.rs")),
            CedarOutcome::Escalate {
                rules: vec!["policy:auth-needs-two-humans".into()],
                approvals: 2
            }
        );
        let human = Actor::Human {
            name: "ayse".into(),
        };
        assert_eq!(
            b.evaluate(&human, "file.delete", file("migrations/001.sql")),
            CedarOutcome::Allow
        );
    }

    #[test]
    fn evaluation_error_is_a_denial() {
        // The rule reads context.recent_reverts; leaving it out makes the
        // forbid rule error. That must deny, not silently allow.
        let b = PolicyBundle::default_bundle();
        match b.evaluate(
            &agent(),
            "change.propose",
            vec![("files", CVal::Long(1)), ("lines", CVal::Long(1))],
        ) {
            CedarOutcome::Deny(r) => {
                assert!(r.iter().all(|x| x.starts_with("policy_error:")), "{r:?}")
            }
            other => panic!("expected deny, got {other:?}"),
        }
    }

    #[test]
    fn no_permit_means_default_deny() {
        let b = PolicyBundle::parse(
            DEFAULT_CONFIG,
            "forbid(principal, action, resource) when { false };",
        )
        .unwrap();
        assert!(matches!(
            b.evaluate(&agent(), "lease.acquire", vec![]),
            CedarOutcome::Deny(_)
        ));
    }

    #[test]
    fn config_patterns() {
        assert!(config_pattern_matches("**/Cargo.lock", "Cargo.lock"));
        assert!(config_pattern_matches("**/Cargo.lock", "a/b/Cargo.lock"));
        assert!(!config_pattern_matches("**/Cargo.lock", "a/b/Cargo.locks"));
        assert!(config_pattern_matches("**/*.csproj", "src/App/App.csproj"));
        assert!(!config_pattern_matches("**/*.csproj", ".csproj"));
        assert!(config_pattern_matches(
            ".github/**",
            ".github/workflows/x.yml"
        ));
    }
}
