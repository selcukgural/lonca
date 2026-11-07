//! Policy bundle: `lonca.toml` (limits and switches) plus `policy.cedar`
//! (rules). Both live in the commit that `refs/lonca/policy` points to, never
//! in a code branch.

use std::collections::BTreeMap;
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
# How many times in a row an agent that stops with work nobody proposed is
# told so and sent back, for a harness with a stop event. A proposal starts
# the count over. 0 only records it, for `status`.
stop_rounds = 3

[leases]
max_ttl_minutes = 30
max_items = 64
# A proposal pins the lease items it needs until the change leaves the
# queue. On integration the pinned items are released (true) or go back to
# the TTL of their set (false).
release_on_integrate = true
# A session that has sent a heartbeat keeps its leases only while it goes
# on: this long after the last one they are free. Sessions that never sent
# one live by the TTL alone. Pinned items ignore this.
heartbeat_timeout_ms = 300000
# Past this long a set can not be renewed while another session wants it.
max_hold_minutes = 120
# When a set is freed, the oldest registered interest in it has this long to
# acquire it before anyone else can.
reservation_ms = 60000
# From the moment an interest is registered, no other session can take a new
# lease that conflicts with it for this long, so a wide change is not starved
# by small ones. The interest stays in line after that, without this right.
interest_block_ms = 600000
# A file no parser reads is one lease, `<file>`, and one agent at a time
# ("file"). With "optimistic" it needs no lease: the line merge at integration
# decides, an overlap is `conflicted`, and verification runs on the result.
unparsed_files = "file"

[changes]
max_files = 200
max_file_bytes = 2097152

[paths]
# Changes here run code during build/test, define CI, or instruct and
# configure the agents themselves: they always need a human approval, and
# tainted sessions may not touch them at all. An agent reads CLAUDE.md after
# its next sync, so a change to it is a prompt to every agent that follows.
critical = [
  ".github/**", ".gitlab-ci.yml", ".lonca/**", ".imece/**",
  # Build and packaging.
  "**/build.rs", "**/Cargo.toml", "**/Cargo.lock",
  "**/package.json", "**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
  "**/Makefile", "**/*.csproj", "**/Directory.Build.props", "**/Directory.Build.targets",
  "**/global.json", "**/NuGet.config", "**/pyproject.toml", "**/setup.py",
  "**/go.mod", "**/go.sum", "**/Gemfile", "**/Gemfile.lock", "**/pom.xml",
  "**/build.gradle", "**/build.gradle.kts", "**/conftest.py",
  # Agent instructions and settings.
  "**/CLAUDE.md", "**/AGENTS.md", "**/GEMINI.md", "**/.cursorrules", "**/.windsurfrules",
  "**/.mcp.json", ".claude/**", ".cursor/**", ".codex/**", ".gemini/**",
  # Tooling that runs code on checkout, on build or in an editor.
  ".cargo/config.toml", ".cargo/config", "rust-toolchain", "rust-toolchain.toml",
  "**/.envrc", ".vscode/**", ".devcontainer/**", "**/Dockerfile",
  "**/docker-compose.yml", "**/docker-compose.yaml", "**/compose.yml", "**/compose.yaml",
  "**/.npmrc", "**/.yarnrc", "**/.yarnrc.yml", "**/.pnpmfile.cjs",
  "**/.gitattributes", ".gitmodules",
]
# Reading these taints a session.
untrusted = ["vendor/**", "third_party/**", "node_modules/**"]

[verification]
# Commands run by the verifier in a sandbox on the merged tree.
# build = "cargo build --offline"
# test = "cargo test --offline"
# Also run for a change that alters a signature, or takes away a name
# something else mentions.
# on_signature_change = "cargo test --offline --workspace --all-features"
required = false
require_sandbox = false
timeout_seconds = 900
retries = 0
# The commands run with an empty environment plus PATH, HOME (a scratch
# home), LANG and LONCA_VERIFY. Names listed here are copied from the
# daemon's environment at run time; `env` sets fixed values. Names that
# change what runs (LD_PRELOAD, DYLD_*, RUSTC_WRAPPER, NODE_OPTIONS,
# PYTHONPATH, GIT_*, ...) are refused. See docs/guide/verification.md.
# env_passthrough = ["HOME", "CARGO_HOME", "RUSTUP_HOME", "TMPDIR"]
env_passthrough = []
# env = { CARGO_NET_OFFLINE = "true" }
env = {}

[observation]
# Sessions that nothing observes are treated like tainted sessions.
unobserved_is_tainted = true
# Outbound connections through the Lonca proxy: "taint" lets them through
# and marks the session tainted, "deny" refuses them.
network = "taint"
# Hosts that are part of the agent itself, such as its model's API
# ("api.anthropic.com"). Connections to them are logged, go through whatever
# `network` says, and do not taint the session. Exact names, no wildcards.
agent_hosts = []
# Let sandboxed commands reach loopback, private and link-local addresses.
allow_private_network = false
# What a change to a critical path costs a session nobody fully observes:
# "deny" refuses it, "escalate" makes it wait for a human like any other
# change of that session. Applies while unobserved_is_tainted is on.
unobserved_critical = "deny"

[taint]
# Which observed tool calls mark a session tainted (content from outside
# entered it; tainted changes need human review, and `critical` below says
# whether they may touch critical paths). Reads of untrusted paths and files
# outside the workspace always taint.
# Web fetches and searches.
fetch = true
# Shell commands that reach the network (curl, ssh, git fetch, ...).
shell_network = true
# MCP servers whose tools do not taint (by server name, as in
# `mcp__<server>__<tool>`); every other server's tools do. Lonca's own
# tools never taint.
mcp_servers = []
# Tools Lonca does not know could read anything, so they taint.
unknown_tools = true
# Tools, by the name the harness gives them, that do not.
safe_tools = []
# What a change to a critical path costs a tainted session: "deny" or
# "escalate", as for an unobserved one. Separate, because a taint says more:
# content from outside really did enter the session.
critical = "deny"

[approvals]
# With fewer enrolled humans than a rule requires, require all of them.
cap_to_enrolled_humans = true
policy_updates = 1
# Accept human signatures only from keys that prove presence (Secure
# Enclave + Touch ID or password). File keys can be used by anything that
# runs as the user, agents included. Recommended for hardened installs.
require_presence = false

[negotiation]
max_rounds = 4

[queue]
# Changes at the head of the queue verified as one: the merged result of all
# of them, with a failure bisected. 1 verifies each change on its own.
batch_size = 1

[reverts]
window_minutes = 5

[integrity]
# What to do when a ref changes behind the daemon's back: "restore" or "freeze".
on_unmediated = "restore"

# Harness profiles. Lonca knows claude-code, codex, gemini and opencode; a table
# here adds another or replaces one (docs/guide/runners.md, "Any other harness").
# `lonca harness show <name>` prints a built-in one to start from.
# [harnesses.acme]
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
    pub taint: Taint,
    pub approvals: Approvals,
    pub negotiation: Negotiation,
    pub queue: Queue,
    pub reverts: Reverts,
    pub integrity: Integrity,
    /// Harness profiles of this repository, over the built-in ones.
    pub harnesses: BTreeMap<String, crate::harness::Profile>,
}

impl Config {
    /// The profile of a harness: this repository's, else the built-in one.
    pub fn harness(&self, name: &str) -> Option<&crate::harness::Profile> {
        let built_in = || crate::harness::built_in().get(name);
        self.harnesses.get(name).or_else(built_in)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sessions {
    pub max_ttl_minutes: i64,
    pub stop_rounds: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Leases {
    pub max_ttl_minutes: i64,
    pub max_items: usize,
    /// Integration releases the items pinned to the change; otherwise they
    /// go back to the TTL of their set.
    pub release_on_integrate: bool,
    /// How long after a session's last heartbeat its leases stay alive.
    pub heartbeat_timeout_ms: i64,
    /// How long a set can be held by renewing while another session wants
    /// it.
    pub max_hold_minutes: i64,
    pub reservation_ms: i64,
    /// How long a waiting interest stops new leases that conflict with it.
    pub interest_block_ms: i64,
    /// What an edit of a file no parser reads takes.
    pub unparsed_files: UnparsedFiles,
}

/// `leases.unparsed_files`. Any other word is refused with the policy.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UnparsedFiles {
    /// A lease on `<file>`.
    #[default]
    File,
    /// No lease: the line merge decides.
    Optimistic,
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
    /// Also runs for a change that alters a signature, or that takes away
    /// a name something else mentions: what is too slow for every change.
    pub on_signature_change: Option<String>,
    pub required: bool,
    pub require_sandbox: bool,
    pub timeout_seconds: u64,
    pub retries: u32,
    /// Environment variables copied from the daemon's environment into
    /// the verifier's, by name. Deny by default: nothing else passes.
    pub env_passthrough: Vec<String>,
    /// Environment variables with fixed values.
    pub env: std::collections::BTreeMap<String, String>,
}

impl Verification {
    /// What a change owes: `reaches_others` is what its facts say of it.
    pub fn for_change(&self, reaches_others: bool) -> Self {
        let extended = self.on_signature_change.as_ref();
        Self {
            on_signature_change: extended.filter(|_| reaches_others).cloned(),
            ..self.clone()
        }
    }
}

/// Environment names (exact, or a prefix ending in `*`) that could change
/// what a verification runs or where it loads code from. Refused in both
/// `env_passthrough` and `env` at policy load (`env_forbidden:NAME`).
pub const FORBIDDEN_ENV: &[&str] = &[
    "PATH",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "DYLD_*",
    "RUSTC",
    "RUSTC_WRAPPER",
    "RUSTC_WORKSPACE_WRAPPER",
    "RUSTFLAGS",
    "CARGO_BUILD_RUSTC",
    "CARGO_BUILD_RUSTC_WRAPPER",
    "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
    "CARGO_BUILD_RUSTFLAGS",
    "CARGO_TARGET_*_RUNNER",
    "CARGO_TARGET_*_LINKER",
    "NODE_OPTIONS",
    "NODE_PATH",
    "PYTHONPATH",
    "PYTHONSTARTUP",
    "PERL5OPT",
    "RUBYOPT",
    "GOFLAGS",
    "GIT_*",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "IFS",
    "LONCA_*",
];

/// Why a name is refused, or `None` when it may be passed.
pub fn env_name_forbidden(name: &str) -> bool {
    FORBIDDEN_ENV.iter().any(|pat| match pat.split_once('*') {
        None => *pat == name,
        Some((prefix, suffix)) => {
            name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
        }
    })
}

/// A plausible environment variable name.
pub fn valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.starts_with(|c: char| c.is_ascii_digit())
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// The words of `unobserved_critical` and `[taint] critical`.
pub const CRITICAL_DENY: &str = "deny";
pub const CRITICAL_ESCALATE: &str = "escalate";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Observation {
    pub unobserved_is_tainted: bool,
    pub network: String,
    pub agent_hosts: Vec<String>,
    pub allow_private_network: bool,
    pub unobserved_critical: String,
}

/// Which observations taint a session (`[taint]`). Policy data: the
/// daemon's hook translation reads it when it marks an observation
/// `external`; `decide()` only sees the result.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Taint {
    pub fetch: bool,
    pub shell_network: bool,
    pub mcp_servers: Vec<String>,
    pub unknown_tools: bool,
    pub safe_tools: Vec<String>,
    pub critical: String,
}

impl Taint {
    /// The server part of an MCP tool name, `mcp__<server>__<tool>`.
    pub fn mcp_server(tool: &str) -> Option<&str> {
        tool.strip_prefix("mcp__")?.split("__").next()
    }

    /// Does a call of this MCP tool taint?
    pub fn mcp_taints(&self, tool: &str) -> bool {
        match Self::mcp_server(tool) {
            Some(server) => !self.mcp_servers.iter().any(|s| s == server),
            None => true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Approvals {
    pub cap_to_enrolled_humans: bool,
    pub policy_updates: u32,
    pub require_presence: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Negotiation {
    pub max_rounds: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Queue {
    /// How many changes at the head of the queue are verified as one.
    pub batch_size: u32,
}

/// The most changes one batch can hold: bisection stays short, and one log
/// entry stays small.
pub const MAX_BATCH_SIZE: u32 = 64;

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
// lonca.toml behaves like the shipped file. `paths.critical` is the exception,
// see `Paths::default`.

impl Default for Sessions {
    fn default() -> Self {
        Self {
            max_ttl_minutes: 480,
            stop_rounds: 3,
        }
    }
}

impl Default for Leases {
    fn default() -> Self {
        Self {
            max_ttl_minutes: 30,
            max_items: 64,
            release_on_integrate: true,
            heartbeat_timeout_ms: 300_000,
            max_hold_minutes: 120,
            reservation_ms: 60_000,
            interest_block_ms: 600_000,
            unparsed_files: UnparsedFiles::File,
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
    /// `critical` is frozen at what a `lonca.toml` without the key has always
    /// meant: a log replays under its policy, and a default that grew would
    /// turn a recorded `allow` into an integrity failure. The list for new
    /// repositories is in `DEFAULT_CONFIG`.
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
            on_signature_change: None,
            required: false,
            require_sandbox: false,
            timeout_seconds: 900,
            retries: 0,
            env_passthrough: vec![],
            env: std::collections::BTreeMap::new(),
        }
    }
}

impl Default for Observation {
    fn default() -> Self {
        Self {
            unobserved_is_tainted: true,
            network: "taint".into(),
            agent_hosts: Vec::new(),
            allow_private_network: false,
            unobserved_critical: CRITICAL_DENY.into(),
        }
    }
}

impl Default for Taint {
    fn default() -> Self {
        Self {
            fetch: true,
            shell_network: true,
            mcp_servers: vec![],
            unknown_tools: true,
            safe_tools: vec![],
            critical: CRITICAL_DENY.into(),
        }
    }
}

impl Default for Approvals {
    fn default() -> Self {
        Self {
            cap_to_enrolled_humans: true,
            policy_updates: 1,
            require_presence: false,
        }
    }
}

impl Default for Negotiation {
    fn default() -> Self {
        Self { max_rounds: 4 }
    }
}

impl Default for Queue {
    fn default() -> Self {
        Queue { batch_size: 1 }
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
        for (name, profile) in &config.harnesses {
            profile
                .check()
                .map_err(|e| format!("{CONFIG_FILE}: harness {name}: {e}"))?;
        }
        for p in config.paths.critical.iter().chain(&config.paths.untrusted) {
            let ok = p.starts_with("**/") || lonca_core::paths::validate_path_pattern(p).is_ok();
            if !ok {
                return Err(format!("{CONFIG_FILE}: bad path pattern {p:?}"));
            }
        }
        if !(1..=MAX_BATCH_SIZE).contains(&config.queue.batch_size) {
            return Err(format!(
                "{CONFIG_FILE}: queue.batch_size must be 1..{MAX_BATCH_SIZE}"
            ));
        }
        if !matches!(
            config.integrity.on_unmediated.as_str(),
            "restore" | "freeze"
        ) {
            return Err(format!(
                "{CONFIG_FILE}: integrity.on_unmediated must be restore or freeze"
            ));
        }
        if config.leases.heartbeat_timeout_ms <= 0
            || config.leases.max_hold_minutes <= 0
            || config.leases.reservation_ms <= 0
            || config.leases.interest_block_ms <= 0
        {
            return Err(format!(
                "{CONFIG_FILE}: leases.heartbeat_timeout_ms, leases.max_hold_minutes, \
                 leases.reservation_ms and leases.interest_block_ms must be positive"
            ));
        }
        if !matches!(config.observation.network.as_str(), "taint" | "deny") {
            return Err(format!(
                "{CONFIG_FILE}: observation.network must be taint or deny"
            ));
        }
        // The proxy compares lowercased names, and a wildcard or a stray
        // character here would be a rule that silently never matches.
        if let Some(h) = config.observation.agent_hosts.iter().find(|h| {
            h.is_empty()
                || h.len() > 253
                || !h
                    .bytes()
                    .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'))
        }) {
            return Err(format!(
                "{CONFIG_FILE}: observation.agent_hosts: not a host name: {h}"
            ));
        }
        for (key, word) in [
            (
                "observation.unobserved_critical",
                &config.observation.unobserved_critical,
            ),
            ("taint.critical", &config.taint.critical),
        ] {
            if word != CRITICAL_DENY && word != CRITICAL_ESCALATE {
                return Err(format!("{CONFIG_FILE}: {key} must be deny or escalate"));
            }
        }
        let v = &config.verification;
        for name in v.env_passthrough.iter().chain(v.env.keys()) {
            if !valid_env_name(name) {
                return Err(format!(
                    "{CONFIG_FILE}: verification: bad environment name {name:?}"
                ));
            }
            if env_name_forbidden(name) {
                return Err(format!("{CONFIG_FILE}: verification: env_forbidden:{name}"));
            }
        }
        if v.env_passthrough.len() + v.env.len() > 64 {
            return Err(format!(
                "{CONFIG_FILE}: verification: at most 64 environment names"
            ));
        }
        for value in v.env.values() {
            if value.len() > 4096 || value.chars().any(|c| c == '\0') {
                return Err(format!(
                    "{CONFIG_FILE}: verification: env value too long or has NUL"
                ));
            }
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

    #[test]
    fn agent_hosts_are_plain_lowercase_names() {
        let with = |hosts: &str| {
            let config =
                DEFAULT_CONFIG.replace("agent_hosts = []", &format!("agent_hosts = {hosts}"));
            PolicyBundle::parse(&config, DEFAULT_POLICY).map(|b| b.config.observation.agent_hosts)
        };
        assert_eq!(
            with(r#"["api.example-1.com"]"#).unwrap(),
            ["api.example-1.com"]
        );
        let long = format!("[\"{}\"]", "a".repeat(254));
        assert!(with(&format!("[\"{}\"]", "a".repeat(253))).is_ok());
        for bad in [
            r#"["*.example.com"]"#,
            r#"["API.example.com"]"#,
            r#"[""]"#,
            &long,
        ] {
            let e = with(bad).unwrap_err();
            assert!(e.contains("not a host name"), "{bad}: {e}");
        }
    }

    #[test]
    fn a_batch_size_stays_within_bounds() {
        let with = |size: u32| {
            let line = format!("batch_size = {size}");
            let config = DEFAULT_CONFIG.replace("batch_size = 1", &line);
            PolicyBundle::parse(&config, DEFAULT_POLICY)
        };
        for good in [1, 2, MAX_BATCH_SIZE] {
            assert!(with(good).is_ok(), "{good}");
        }
        for bad in [0, MAX_BATCH_SIZE + 1] {
            let refused = with(bad).err().expect("refused");
            assert!(refused.contains("queue.batch_size"), "{refused}");
        }
    }

    /// One agent at a time on a file no parser reads, unless a policy says
    /// otherwise. Changing this default changes what every repository allows.
    #[test]
    fn an_edit_of_a_file_no_parser_reads_takes_a_lease_by_default() {
        assert_eq!(Leases::default().unparsed_files, UnparsedFiles::File);
        let bundle = PolicyBundle::parse(DEFAULT_CONFIG, DEFAULT_POLICY).unwrap();
        assert_eq!(bundle.config.leases.unparsed_files, UnparsedFiles::File);
        let open = DEFAULT_CONFIG.replace(
            "unparsed_files = \"file\"",
            "unparsed_files = \"optimistic\"",
        );
        assert_ne!(open, DEFAULT_CONFIG);
        let bundle = PolicyBundle::parse(&open, DEFAULT_POLICY).unwrap();
        assert_eq!(
            bundle.config.leases.unparsed_files,
            UnparsedFiles::Optimistic
        );
        let bad = DEFAULT_CONFIG.replace("unparsed_files = \"file\"", "unparsed_files = \"yes\"");
        assert!(PolicyBundle::parse(&bad, DEFAULT_POLICY).is_err());
    }

    /// A default that shrinks does so silently for every new repository,
    /// so each of these has to be taken out here as well. Patterns that
    /// never match are the same failure: every path below must hit.
    #[test]
    fn the_default_critical_list_does_not_shrink() {
        let bundle = PolicyBundle::default_bundle();
        for path in [
            // CI and Lonca's own state.
            ".github/workflows/ci.yml",
            ".github/copilot-instructions.md",
            ".gitlab-ci.yml",
            ".lonca/workspace.json",
            ".lonca/session",
            ".imece/check",
            ".imece/worktree-setup.sh",
            // Build and packaging.
            "build.rs",
            "crates/a/build.rs",
            "Cargo.toml",
            "crates/a/Cargo.toml",
            "Cargo.lock",
            "package.json",
            "web/package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "Makefile",
            "src/App.csproj",
            "Directory.Build.props",
            "Directory.Build.targets",
            "global.json",
            "NuGet.config",
            "pyproject.toml",
            "setup.py",
            "go.mod",
            "svc/go.sum",
            "Gemfile",
            "Gemfile.lock",
            "pom.xml",
            "build.gradle",
            "app/build.gradle.kts",
            "tests/conftest.py",
            // Agent instructions and settings.
            "CLAUDE.md",
            "crates/a/CLAUDE.md",
            "AGENTS.md",
            "GEMINI.md",
            ".cursorrules",
            ".windsurfrules",
            ".mcp.json",
            ".claude/settings.json",
            ".cursor/rules/a.mdc",
            ".codex/config.toml",
            // Tooling that runs code on checkout, on build or in an editor.
            ".cargo/config.toml",
            ".cargo/config",
            "rust-toolchain",
            "rust-toolchain.toml",
            ".envrc",
            ".vscode/tasks.json",
            ".devcontainer/devcontainer.json",
            "Dockerfile",
            "svc/Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            "compose.yml",
            "compose.yaml",
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
            ".pnpmfile.cjs",
            ".gitattributes",
            ".gitmodules",
        ] {
            assert!(bundle.is_critical(path), "{path}");
        }
        for path in ["src/lib.rs", "docs/CLAUDE.txt", "README.md", ".claude"] {
            assert!(!bundle.is_critical(path), "{path}");
        }
    }

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
        let mut shipped: Config = toml::from_str(DEFAULT_CONFIG).unwrap();
        let defaults = Config::default();
        let grown = &shipped.paths.critical;
        assert!(defaults.paths.critical.iter().all(|p| grown.contains(p)));
        shipped.paths.critical = defaults.paths.critical.clone();
        assert_eq!(
            toml::to_string(&shipped).unwrap(),
            toml::to_string(&defaults).unwrap()
        );
    }

    /// See `Paths::default`: a policy that does not name its critical paths
    /// must go on deciding as it did when its log was written.
    #[test]
    fn a_policy_without_critical_paths_keeps_the_old_meaning() {
        let b = PolicyBundle::parse("[leases]\nmax_ttl_minutes = 10\n", DEFAULT_POLICY).unwrap();
        assert!(b.is_critical("Cargo.toml"));
        assert!(!b.is_critical("CLAUDE.md"));
    }

    #[test]
    fn partial_config_uses_defaults_and_unknown_keys_fail() {
        let b = PolicyBundle::parse("[leases]\nmax_ttl_minutes = 10\n", DEFAULT_POLICY).unwrap();
        assert_eq!(b.config.leases.max_ttl_minutes, 10);
        assert_eq!(b.config.leases.max_items, 64);
        assert_eq!(b.config.queue.batch_size, 1, "one change at a time");
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

#[cfg(test)]
mod env_tests {
    use super::*;

    /// The default config with its `env_passthrough` and `env` lines
    /// replaced by the two lines of `verification`.
    fn with(verification: &str) -> Result<PolicyBundle, String> {
        let (pass, env) = verification.trim_end().split_once('\n').expect("two lines");
        let config = DEFAULT_CONFIG
            .replace("env_passthrough = []\n", &format!("{pass}\n"))
            .replace("\nenv = {}\n", &format!("\n{env}\n"));
        assert_ne!(
            config, DEFAULT_CONFIG,
            "the default lines must be there to replace"
        );
        PolicyBundle::parse(&config, DEFAULT_POLICY)
    }

    #[test]
    fn verification_env_is_deny_by_default() {
        let b = PolicyBundle::default_bundle();
        assert!(b.config.verification.env_passthrough.is_empty());
        assert!(b.config.verification.env.is_empty());
        let b = with("env_passthrough = [\"HOME\", \"CARGO_HOME\"]\nenv = { CARGO_NET_OFFLINE = \"true\" }\n").unwrap();
        assert_eq!(
            b.config.verification.env_passthrough,
            ["HOME", "CARGO_HOME"]
        );
        assert_eq!(b.config.verification.env["CARGO_NET_OFFLINE"], "true");
    }

    #[test]
    fn names_that_change_what_runs_are_refused() {
        for name in [
            "PATH",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH",
            "RUSTC",
            "RUSTC_WRAPPER",
            "RUSTFLAGS",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER",
            "CARGO_TARGET_AARCH64_APPLE_DARWIN_LINKER",
            "NODE_OPTIONS",
            "NODE_PATH",
            "PYTHONPATH",
            "PYTHONSTARTUP",
            "PERL5OPT",
            "RUBYOPT",
            "GOFLAGS",
            "GIT_SSH_COMMAND",
            "GIT_DIR",
            "BASH_ENV",
            "ENV",
            "SHELLOPTS",
            "IFS",
            "LONCA_SOCKET",
            "LONCA_VERIFY",
        ] {
            assert!(env_name_forbidden(name), "{name}");
            let err = with(&format!("env_passthrough = [\"{name}\"]\nenv = {{}}\n"))
                .err()
                .expect("refused");
            assert!(
                err.contains(&format!("env_forbidden:{name}")),
                "{name}: {err}"
            );
            let err = with(&format!(
                "env_passthrough = []\nenv = {{ {name} = \"x\" }}\n"
            ))
            .err()
            .expect("refused");
            assert!(
                err.contains(&format!("env_forbidden:{name}")),
                "{name}: {err}"
            );
        }
        for name in [
            "HOME",
            "CARGO_HOME",
            "RUSTUP_HOME",
            "TMPDIR",
            "GOCACHE",
            "GOPATH",
            "VIRTUAL_ENV",
            "CI",
            "GOFLAG",
            "PATHS",
            "LD_PRELOADX",
            // Shorter than the pattern's two halves put together: the
            // prefix and the suffix would have to overlap.
            "CARGO_TARGET_RUNNER",
            "CARGO_TARGET_LINKER",
        ] {
            assert!(!env_name_forbidden(name), "{name}");
        }
        for bad in ["", "1X", "A-B", "A B", "a.b"] {
            assert!(!valid_env_name(bad), "{bad:?}");
        }
        let err = with("env_passthrough = [\"A-B\"]\nenv = {}\n")
            .err()
            .expect("refused");
        assert!(err.contains("bad environment name"), "{err}");
        let many: Vec<String> = (0..65).map(|i| format!("\"V{i}\"")).collect();
        let err = with(&format!(
            "env_passthrough = [{}]\nenv = {{}}\n",
            many.join(", ")
        ))
        .err()
        .expect("refused");
        assert!(err.contains("at most 64"), "{err}");
        // Exactly 64 names, and a value of exactly 4096 bytes, are fine.
        let sixty_four: Vec<String> = (0..64).map(|i| format!("\"V{i}\"")).collect();
        assert!(
            with(&format!(
                "env_passthrough = [{}]\nenv = {{}}\n",
                sixty_four.join(", ")
            ))
            .is_ok()
        );
        assert!(
            with(&format!(
                "env_passthrough = []\nenv = {{ LONG = \"{}\" }}\n",
                "v".repeat(4096)
            ))
            .is_ok()
        );
        let err = with(&format!(
            "env_passthrough = []\nenv = {{ LONG = \"{}\" }}\n",
            "v".repeat(4097)
        ))
        .err()
        .expect("refused");
        assert!(err.contains("too long"), "{err}");
    }
}
