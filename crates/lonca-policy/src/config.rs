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
# What a session, with the sessions made from it, may send the log in a
# minute; a minute's worth may come at once. Past it a request is refused
# with `rate_limited` and the log does not grow.
ops_per_minute = 600

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
# env_passthrough = ["HOME", "CARGO_HOME", "RUSTUP_HOME"]
env_passthrough = []
# env = { CARGO_NET_OFFLINE = "true" }
env = {}
# The commands read the system and the directories on PATH. Anything else
# they need is named here, as an absolute path or ~/path of the daemon's
# user. Lonca's stores stay closed. See docs/guide/verification.md.
# read = ["~/.cargo/registry", "~/.cargo/bin", "~/.rustup"]
read = []
# The commands' PATH, as absolute directories; empty means the daemon's own.
# path = ["/usr/bin", "/bin"]
path = []
# What each process of a command may use; 0 means no limit. A limit the
# daemon runs under already is never raised. Processes and address space
# hold on Linux only. See docs/guide/verification.md.
limit_cpu_seconds = 0
limit_address_bytes = 0
limit_processes = 16384
limit_file_bytes = 8589934592
limit_open_files = 4096

[observation]
# Sessions that nothing observes are treated like tainted sessions.
unobserved_is_tainted = true
# Outbound connections through the Lonca proxy: "taint" lets them through
# and marks the session tainted, "deny" refuses them.
network = "taint"
# Hosts that are part of the agent itself, such as its model's API
# ("api.anthropic.com"). Connections to them are logged, pass even under
# "deny", and do not taint the session. Exact names, no wildcards.
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

/// What a hardened repository changes in [`DEFAULT_CONFIG`]. Each line is
/// there once (checked by a test), so a default that moves is noticed.
const HARDENED_SETTINGS: [(&str, &str); 3] = [
    ("\nrequired = false\n", "\nrequired = true\n"),
    ("\nrequire_sandbox = false\n", "\nrequire_sandbox = true\n"),
    ("\nnetwork = \"taint\"\n", "\nnetwork = \"deny\"\n"),
];
/// Apart from the rest: a machine may have no key that proves presence.
const PRESENCE_SETTING: (&str, &str) = (
    "\nrequire_presence = false\n",
    "\nrequire_presence = true\n",
);

/// What opens [`DEFAULT_POLICY`] and what opens a hardened one. The rules
/// after it are the same.
const OPEN_POLICY: &str = r#"// Lonca policy. Requests are allowed unless a rule below forbids them.
"#;
const OPEN_RULE: &str = "permit(principal, action, resource);\n";
const HARDENED_POLICY_HEAD: &str = r#"// Lonca policy, hardened. An agent may do what is listed here and nothing
// else: an action nobody listed is refused, and that includes one a later
// version of Lonca adds.
"#;
const HARDENED_RULE: &str = r#"permit(principal is Lonca::Human, action, resource);

@id("agent-work")
permit(principal is Lonca::Agent, action in [
  Lonca::Action::"file.add", Lonca::Action::"file.modify", Lonca::Action::"file.delete",
  Lonca::Action::"change.propose", Lonca::Action::"change.withdraw",
  Lonca::Action::"lease.acquire", Lonca::Action::"lease.release",
  Lonca::Action::"lease.renew", Lonca::Action::"lease.interest",
  Lonca::Action::"negotiate", Lonca::Action::"cap.attenuate",
  Lonca::Action::"cap.revoke", Lonca::Action::"session.end"
], resource);
"#;

/// The settings a repository starts from. `Cooperative` suits a first run
/// on a laptop; `Hardened` is what a hardened install's boundary is for.
/// Any other word is refused where it is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Cooperative,
    Hardened,
}

impl Profile {
    pub fn name(self) -> &'static str {
        match self {
            Profile::Cooperative => "cooperative",
            Profile::Hardened => "hardened",
        }
    }

    /// `lonca.toml` and `policy.cedar` of a new repository. Without
    /// `presence` a hardened one leaves `require_presence` off, for a
    /// machine with no key that can prove it.
    pub fn files(self, presence: bool) -> (String, String) {
        if self == Profile::Cooperative {
            return (DEFAULT_CONFIG.to_string(), DEFAULT_POLICY.to_string());
        }
        let mut config = DEFAULT_CONFIG.to_string();
        for (from, to) in HARDENED_SETTINGS {
            config = config.replace(from, to);
        }
        if presence {
            config = config.replace(PRESENCE_SETTING.0, PRESENCE_SETTING.1);
        }
        let policy = DEFAULT_POLICY
            .replace(OPEN_POLICY, HARDENED_POLICY_HEAD)
            .replace(OPEN_RULE, HARDENED_RULE);
        (config, policy)
    }
}

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

    /// How to tell that a harness is locked. A profile with no table of its
    /// own keeps the built-in one: replacing a harness's tool names says
    /// nothing about how an administrator locks it.
    pub fn locked(&self, name: &str) -> Option<&crate::harness::Locked> {
        let built_in = || crate::harness::built_in().get(name)?.locked.as_ref();
        let own = self.harnesses.get(name).and_then(|p| p.locked.as_ref());
        own.or_else(built_in)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Sessions {
    pub max_ttl_minutes: i64,
    pub stop_rounds: u32,
    pub ops_per_minute: u32,
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
    /// Trees the commands may read besides the system's.
    pub read: Vec<String>,
    /// The commands' `PATH`; empty means the daemon's own.
    pub path: Vec<String>,
    /// `RLIMIT_CPU`; each `limit_` key: 0 means no limit. Off by default: it
    /// adds up a process's threads, so a test run on many cores meets it
    /// long before `timeout_seconds`, which is what holds the time.
    pub limit_cpu_seconds: u64,
    /// `RLIMIT_AS`, Linux only. Off by default: runtimes reserve far more
    /// than they use.
    pub limit_address_bytes: u64,
    /// `RLIMIT_NPROC`, Linux only: it counts the account, not the command.
    pub limit_processes: u64,
    /// `RLIMIT_FSIZE`.
    pub limit_file_bytes: u64,
    /// `RLIMIT_NOFILE`.
    pub limit_open_files: u64,
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

/// An entry of `verification.read`: an absolute, normalized path, or one
/// under the home directory of the daemon's user.
pub fn valid_read_path(p: &str) -> bool {
    let absolute = match p.strip_prefix("~/") {
        Some(rest) => format!("/{rest}"),
        None => p.to_string(),
    };
    crate::decide::valid_scratch_root(&absolute)
}

/// An entry of `verification.path`: an absolute, normalized directory that
/// can stand in a `PATH`.
pub fn valid_command_path(p: &str) -> bool {
    crate::decide::valid_scratch_root(p) && !p.contains(':')
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
            ops_per_minute: 600,
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
            read: vec![],
            path: vec![],
            limit_cpu_seconds: 0,
            limit_address_bytes: 0,
            limit_processes: 16384,
            limit_file_bytes: 8 << 30,
            limit_open_files: 4096,
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
        if config.sessions.ops_per_minute == 0 {
            return Err(format!(
                "{CONFIG_FILE}: sessions.ops_per_minute must be positive"
            ));
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
        if v.read.len() > 64 {
            return Err(format!(
                "{CONFIG_FILE}: verification: at most 64 read paths"
            ));
        }
        if let Some(bad) = v.read.iter().find(|p| !valid_read_path(p)) {
            return Err(format!(
                "{CONFIG_FILE}: verification.read: not an absolute path or ~/path: {bad}"
            ));
        }
        if v.path.len() > 64 {
            return Err(format!(
                "{CONFIG_FILE}: verification: at most 64 path entries"
            ));
        }
        if let Some(bad) = v.path.iter().find(|p| !valid_command_path(p)) {
            return Err(format!(
                "{CONFIG_FILE}: verification.path: not an absolute directory: {bad}"
            ));
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

    /// Where this repository stands below the hardened profile, for a
    /// hardened install to say so. A rule is judged by what it does: an
    /// action no rule could have listed must not pass.
    pub fn below_hardened(&self) -> Vec<&'static str> {
        let c = &self.config;
        let v = &c.verification;
        let agent = Actor::Agent {
            name: "agent".into(),
            session: "session".into(),
        };
        let open = self.evaluate(&agent, "lonca.unlisted", vec![]) == CedarOutcome::Allow;
        [
            (!c.approvals.require_presence, "approvals.require_presence"),
            (!v.required, "verification.required"),
            (!v.require_sandbox, "verification.require_sandbox"),
            (
                v.build.is_none() && v.test.is_none(),
                "verification has no build or test command",
            ),
            (c.observation.network != "deny", "observation.network"),
            (open, "policy.cedar permits actions nobody listed"),
        ]
        .into_iter()
        .filter_map(|(below, what)| below.then_some(what))
        .collect()
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

    fn bundle(profile: Profile, presence: bool) -> PolicyBundle {
        let (config, policy) = profile.files(presence);
        PolicyBundle::parse(&config, &policy).unwrap()
    }

    #[test]
    fn the_cooperative_profile_is_the_default() {
        let (config, policy) = Profile::Cooperative.files(true);
        assert_eq!(config, DEFAULT_CONFIG);
        assert_eq!(policy, DEFAULT_POLICY);
        assert_eq!(Profile::Cooperative.name(), "cooperative");
        assert_eq!(Profile::Hardened.name(), "hardened");
        let word = serde_json::from_str::<Profile>("\"open\"");
        assert!(word.is_err(), "an unknown profile is refused");
    }

    #[test]
    fn the_hardened_profile_changes_each_setting_it_names() {
        let c = bundle(Profile::Hardened, true).config;
        assert!(c.approvals.require_presence);
        assert!(c.verification.required);
        assert!(c.verification.require_sandbox);
        assert_eq!(c.observation.network, "deny");

        let c = bundle(Profile::Hardened, false).config;
        assert!(!c.approvals.require_presence);
        assert!(c.verification.required && c.verification.require_sandbox);
    }

    #[test]
    fn each_line_the_hardened_profile_changes_is_there_once() {
        for (from, _) in HARDENED_SETTINGS.into_iter().chain([PRESENCE_SETTING]) {
            assert_eq!(DEFAULT_CONFIG.matches(from).count(), 1, "{from}");
        }
        assert_eq!(DEFAULT_POLICY.matches(OPEN_POLICY).count(), 1);
        assert_eq!(DEFAULT_POLICY.matches(OPEN_RULE).count(), 1);
        let (_, policy) = Profile::Hardened.files(true);
        assert!(!policy.contains(OPEN_RULE), "{policy}");
        assert!(!policy.contains(OPEN_POLICY), "{policy}");
        for rule in ["migrations-no-agent-delete", "auth-needs-two-humans"] {
            assert!(policy.contains(rule), "the rules stay: {rule}");
        }
    }

    #[test]
    fn verification_path_is_absolute_directories_that_fit_a_path() {
        let parse = |paths: &str| {
            let config = DEFAULT_CONFIG.replace("path = []", &format!("path = {paths}"));
            PolicyBundle::parse(&config, DEFAULT_POLICY).map(|b| b.config.verification.path)
        };
        assert_eq!(
            parse(r#"["/usr/bin", "/bin"]"#).unwrap(),
            ["/usr/bin", "/bin"]
        );
        for bad in ["bin", "~/bin", "/usr/bin/", "/usr/../bin", "/a:/b", ""] {
            let e = parse(&format!("[{bad:?}]")).unwrap_err();
            assert!(e.contains("verification.path"), "{bad}: {e}");
        }
        let full = vec!["\"/a\""; 64].join(",");
        assert!(parse(&format!("[{full}]")).is_ok());
        let over = vec!["\"/a\""; 65].join(",");
        assert!(
            parse(&format!("[{over}]"))
                .unwrap_err()
                .contains("at most 64")
        );
    }

    #[test]
    fn below_hardened_names_each_setting_that_falls_short() {
        let cooperative = PolicyBundle::default_bundle();
        assert_eq!(
            cooperative.below_hardened(),
            [
                "approvals.require_presence",
                "verification.required",
                "verification.require_sandbox",
                "verification has no build or test command",
                "observation.network",
                "policy.cedar permits actions nobody listed",
            ]
        );
        let commands = "\nretries = 0\n";
        let (config, policy) = Profile::Hardened.files(true);
        let with = |line: &str| {
            let config = config.replace(commands, &format!("{commands}{line}\n"));
            PolicyBundle::parse(&config, &policy).unwrap()
        };
        let none: [&str; 0] = [];
        assert_eq!(with("build = \"make\"").below_hardened(), none);
        assert_eq!(with("test = \"make test\"").below_hardened(), none);
        assert_eq!(
            bundle(Profile::Hardened, true).below_hardened(),
            ["verification has no build or test command"]
        );
    }

    #[test]
    fn a_session_rate_of_nothing_is_refused() {
        let e = PolicyBundle::parse("[sessions]\nops_per_minute = 0\n", DEFAULT_POLICY);
        assert!(e.err().unwrap().contains("ops_per_minute"));
        let b = PolicyBundle::parse("[sessions]\nops_per_minute = 1\n", DEFAULT_POLICY);
        assert_eq!(b.unwrap().config.sessions.ops_per_minute, 1);
        assert_eq!(Sessions::default().ops_per_minute, 600);
    }

    #[test]
    fn verification_reads_absolute_paths_and_paths_under_the_home() {
        let with = |paths: &str| {
            let config = DEFAULT_CONFIG.replace("read = []", &format!("read = {paths}"));
            PolicyBundle::parse(&config, DEFAULT_POLICY).map(|b| b.config.verification.read)
        };
        let good = with(r#"["/opt/tool", "~/.cargo/bin"]"#).unwrap();
        assert_eq!(good, ["/opt/tool", "~/.cargo/bin"]);
        for bad in [
            r#"["relative"]"#,
            r#"["~"]"#,
            r#"["~other/x"]"#,
            r#"["/a/../b"]"#,
            r#"["~/a/"]"#,
        ] {
            let e = with(bad).unwrap_err();
            assert!(e.contains("verification.read"), "{bad}: {e}");
        }
        let many = serde_json::to_string(&vec!["/a"; 65]).unwrap();
        assert!(with(&many).unwrap_err().contains("at most 64"));
        let most = serde_json::to_string(&vec!["/a"; 64]).unwrap();
        assert!(with(&most).is_ok());
    }

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
