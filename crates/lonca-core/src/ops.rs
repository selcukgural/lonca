//! The operation vocabulary. Every state change in a Lonca repository is one
//! of these, recorded (allowed or not) in the operation log.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::changeid::ChangeId;
use crate::store::GitId;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Actor {
    Human { name: String },
    Agent { name: String, session: String },
    Daemon,
}

impl Actor {
    pub fn label(&self) -> String {
        match self {
            Actor::Human { name } => format!("human:{name}"),
            Actor::Agent { name, session } => format!("agent:{name}/{session}"),
            Actor::Daemon => "daemon".into(),
        }
    }

    pub fn session(&self) -> Option<&str> {
        match self {
            Actor::Agent { session, .. } => Some(session),
            _ => None,
        }
    }

    pub fn is_human(&self) -> bool {
        matches!(self, Actor::Human { .. })
    }
}

impl fmt::Display for Actor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label())
    }
}

/// Operation types. Deserialization rejects anything not listed here, which
/// makes every scope check deny-by-default.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OpKind {
    #[serde(rename = "repo.init")]
    RepoInit,
    #[serde(rename = "human.enroll")]
    HumanEnroll,
    #[serde(rename = "policy.update")]
    PolicyUpdate,
    #[serde(rename = "session.start")]
    SessionStart,
    #[serde(rename = "session.bind")]
    SessionBind,
    #[serde(rename = "session.end")]
    SessionEnd,
    #[serde(rename = "cap.attenuate")]
    CapAttenuate,
    #[serde(rename = "cap.revoke")]
    CapRevoke,
    #[serde(rename = "lease.acquire")]
    LeaseAcquire,
    #[serde(rename = "lease.release")]
    LeaseRelease,
    #[serde(rename = "lease.renew")]
    LeaseRenew,
    #[serde(rename = "change.propose")]
    ChangePropose,
    #[serde(rename = "change.withdraw")]
    ChangeWithdraw,
    #[serde(rename = "change.integrate")]
    ChangeIntegrate,
    #[serde(rename = "approve")]
    Approve,
    #[serde(rename = "observe")]
    Observe,
    #[serde(rename = "taint")]
    Taint,
    #[serde(rename = "import.external")]
    ImportExternal,
    #[serde(rename = "import.unmediated")]
    ImportUnmediated,
    #[serde(rename = "bridge.push")]
    BridgePush,
    #[serde(rename = "freeze")]
    Freeze,
    #[serde(rename = "unfreeze")]
    Unfreeze,
    #[serde(rename = "negotiate")]
    Negotiate,
    #[serde(rename = "redact")]
    Redact,
}

impl OpKind {
    pub fn as_str(self) -> &'static str {
        match self {
            OpKind::RepoInit => "repo.init",
            OpKind::HumanEnroll => "human.enroll",
            OpKind::PolicyUpdate => "policy.update",
            OpKind::SessionStart => "session.start",
            OpKind::SessionBind => "session.bind",
            OpKind::SessionEnd => "session.end",
            OpKind::CapAttenuate => "cap.attenuate",
            OpKind::CapRevoke => "cap.revoke",
            OpKind::LeaseAcquire => "lease.acquire",
            OpKind::LeaseRelease => "lease.release",
            OpKind::LeaseRenew => "lease.renew",
            OpKind::ChangePropose => "change.propose",
            OpKind::ChangeWithdraw => "change.withdraw",
            OpKind::ChangeIntegrate => "change.integrate",
            OpKind::Approve => "approve",
            OpKind::Observe => "observe",
            OpKind::Taint => "taint",
            OpKind::ImportExternal => "import.external",
            OpKind::ImportUnmediated => "import.unmediated",
            OpKind::BridgePush => "bridge.push",
            OpKind::Freeze => "freeze",
            OpKind::Unfreeze => "unfreeze",
            OpKind::Negotiate => "negotiate",
            OpKind::Redact => "redact",
        }
    }

    /// The only operation types a capability can ever grant to an agent.
    /// Everything else (policy, keys, approvals, imports, revocation of
    /// others, redaction, freezing) is reserved for humans or the daemon and
    /// cannot be granted by any policy.
    pub fn agent_grantable(self) -> bool {
        matches!(
            self,
            OpKind::ChangePropose
                | OpKind::ChangeWithdraw
                | OpKind::LeaseAcquire
                | OpKind::LeaseRelease
                | OpKind::LeaseRenew
                | OpKind::Negotiate
                | OpKind::CapAttenuate
        )
    }
}

/// What a session may touch. Patterns use the language in [`crate::paths`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub paths: Vec<String>,
    /// `None`: no symbol restriction beyond `paths`.
    pub symbols: Option<Vec<String>>,
    pub ops: Vec<OpKind>,
    pub max_files: Option<u32>,
    pub max_lines: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationLevel {
    /// Nothing watches the agent. Treated as tainted by default policy.
    Unobserved,
    /// Locked, blocking harness hooks (H1).
    Hooks,
    /// H1 plus a locked shell sandbox whose network goes through the daemon (H2).
    HooksSandbox,
    /// Container / OS sandbox owned by Lonca.
    Isolated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindChecks {
    pub harness: String,
    pub harness_session: String,
    /// Hooks come from root-owned managed settings with managed-only hooks.
    pub managed_hooks: bool,
    /// Shell sandbox enabled, locked, network routed to the Lonca proxy.
    pub locked_sandbox: bool,
    /// `sudo -n true` succeeded without a password.
    pub sudo_without_password: bool,
    /// Hash of the harness configuration that defines the hooks.
    pub config_digest: String,
    /// The hook program and its parent directories are not user-writable.
    pub hook_binary_protected: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseKind {
    /// Exclusive: change the body of one symbol.
    Edit,
    /// Shared: add new members to a container (file or type).
    Insert,
    /// Exclusive: rename or delete a symbol.
    Rename,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeaseItem {
    /// `path#Qualified.name`; for `insert`, the container (`path#Type` or `path#<file>`).
    pub symbol: String,
    pub kind: LeaseKind,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TestDelta {
    pub added: u32,
    pub modified: u32,
    pub deleted: u32,
    /// Tests that gained a skip/ignore marker.
    pub skipped: u32,
}

/// The agent's structured declaration of what its change does. Compared
/// field by field with [`Facts`]; any mismatch rejects the change.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    /// Free text for humans. Never a decision input.
    pub intent: String,
    pub edits: Vec<String>,
    pub adds: Vec<String>,
    pub deletes: Vec<String>,
    pub deleted_files: Vec<String>,
    pub signature_changes: Vec<String>,
    pub tests: TestDelta,
    pub revert_of: Option<ChangeId>,
}

/// What a change actually does, computed by Lonca from the Git objects.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Facts {
    pub edits: Vec<String>,
    pub adds: Vec<String>,
    pub deletes: Vec<String>,
    pub added_files: Vec<String>,
    pub deleted_files: Vec<String>,
    pub modified_files: Vec<String>,
    pub signature_changes: Vec<String>,
    /// Lines changed inside import blocks only (lease-free, merged as sets).
    pub import_only_files: Vec<String>,
    pub tests: TestDelta,
    pub lines_added: u32,
    pub lines_removed: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckKind {
    Syntax,
    Scope,
    ClaimDiff,
    Merge,
    Build,
    Tests,
    TestIntegrity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckResult {
    Pass,
    Fail,
    Error,
    Skipped,
}

/// Evidence produced by a (possibly nondeterministic) check. Recorded in the
/// operation log so that decisions can be replayed without rerunning it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attestation {
    pub check: CheckKind,
    pub result: CheckResult,
    pub subject_tree: GitId,
    pub details: BTreeMap<String, String>,
    /// Digest of the environment: sandbox profile, commands, tool versions.
    pub env: String,
    pub log: Option<GitId>,
    pub producer: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Pre,
    Post,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ObsKind {
    Read {
        path: String,
    },
    Write {
        path: String,
    },
    /// The program name and a digest of the full command; the command text
    /// itself is not logged because it may contain secrets.
    Shell {
        program: String,
        digest: String,
    },
    Fetch {
        host: String,
    },
    Mcp {
        tool: String,
    },
    Other {
        tool: String,
    },
    Heartbeat,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub phase: Phase,
    pub kind: ObsKind,
    /// The observation is outside the workspace or names untrusted content.
    pub external: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NegotiationMsg {
    /// "I need these symbols for this reason."
    Claim {
        symbols: Vec<String>,
        reason: String,
    },
    /// Offer to split work: the sender keeps `mine`, the receiver gets `yours`.
    ProposeSplit {
        mine: Vec<String>,
        yours: Vec<String>,
    },
    /// Give up the named lease set in favour of the receiver.
    Yield {
        set: String,
    },
    Counter {
        note: String,
    },
    Accept,
    Decline {
        note: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanKey {
    /// `ed25519` (file key, no user presence) or `p256-se` (Secure Enclave,
    /// Touch ID or password on every signature).
    pub alg: String,
    pub public: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op")]
pub enum Op {
    #[serde(rename = "repo.init")]
    RepoInit {
        repo: String,
        daemon_key: String,
        human: String,
        human_key: HumanKey,
        policy: GitId,
        trunk: GitId,
    },
    #[serde(rename = "human.enroll")]
    HumanEnroll { human: String, key: HumanKey },
    #[serde(rename = "policy.update")]
    PolicyUpdate { policy: GitId },
    #[serde(rename = "session.start")]
    SessionStart {
        session: String,
        agent: String,
        model: Option<String>,
        task: String,
        scope: Scope,
        expires_ms: i64,
    },
    #[serde(rename = "session.bind")]
    SessionBind {
        session: String,
        checks: BindChecks,
        level: ObservationLevel,
    },
    #[serde(rename = "session.end")]
    SessionEnd { session: String, reason: String },
    #[serde(rename = "cap.attenuate")]
    CapAttenuate {
        parent: String,
        child: String,
        agent: String,
        scope: Scope,
        expires_ms: i64,
    },
    #[serde(rename = "cap.revoke")]
    CapRevoke { session: String, reason: String },
    #[serde(rename = "lease.acquire")]
    LeaseAcquire {
        set: String,
        items: Vec<LeaseItem>,
        intent: String,
        ttl_ms: i64,
    },
    #[serde(rename = "lease.release")]
    LeaseRelease { set: String },
    #[serde(rename = "lease.renew")]
    LeaseRenew { set: String, ttl_ms: i64 },
    #[serde(rename = "change.propose")]
    ChangePropose {
        change: ChangeId,
        commit: GitId,
        base: GitId,
        claim: Claim,
    },
    #[serde(rename = "change.withdraw")]
    ChangeWithdraw { change: ChangeId },
    #[serde(rename = "change.integrate")]
    ChangeIntegrate {
        change: ChangeId,
        trunk_before: GitId,
        /// The merged trunk commit, or `None` when the merge conflicted.
        merged: Option<GitId>,
        conflicts: Vec<String>,
    },
    #[serde(rename = "approve")]
    Approve { target_seq: u64, note: String },
    #[serde(rename = "observe")]
    Observe {
        session: String,
        events: Vec<Observation>,
    },
    #[serde(rename = "taint")]
    Taint { session: String, reason: String },
    #[serde(rename = "import.external")]
    ImportExternal {
        remote: String,
        commit: GitId,
        trunk_before: GitId,
    },
    #[serde(rename = "import.unmediated")]
    ImportUnmediated {
        refname: String,
        found: Option<GitId>,
        expected: Option<GitId>,
    },
    #[serde(rename = "bridge.push")]
    BridgePush {
        remote: String,
        oplog_seq: u64,
        oplog_hash: String,
    },
    #[serde(rename = "freeze")]
    Freeze { reason: String },
    #[serde(rename = "unfreeze")]
    Unfreeze { reason: String },
    #[serde(rename = "negotiate")]
    Negotiate {
        thread: String,
        to_session: String,
        message: NegotiationMsg,
    },
    #[serde(rename = "redact")]
    Redact { blob: GitId, reason: String },
}

impl Op {
    pub fn kind(&self) -> OpKind {
        match self {
            Op::RepoInit { .. } => OpKind::RepoInit,
            Op::HumanEnroll { .. } => OpKind::HumanEnroll,
            Op::PolicyUpdate { .. } => OpKind::PolicyUpdate,
            Op::SessionStart { .. } => OpKind::SessionStart,
            Op::SessionBind { .. } => OpKind::SessionBind,
            Op::SessionEnd { .. } => OpKind::SessionEnd,
            Op::CapAttenuate { .. } => OpKind::CapAttenuate,
            Op::CapRevoke { .. } => OpKind::CapRevoke,
            Op::LeaseAcquire { .. } => OpKind::LeaseAcquire,
            Op::LeaseRelease { .. } => OpKind::LeaseRelease,
            Op::LeaseRenew { .. } => OpKind::LeaseRenew,
            Op::ChangePropose { .. } => OpKind::ChangePropose,
            Op::ChangeWithdraw { .. } => OpKind::ChangeWithdraw,
            Op::ChangeIntegrate { .. } => OpKind::ChangeIntegrate,
            Op::Approve { .. } => OpKind::Approve,
            Op::Observe { .. } => OpKind::Observe,
            Op::Taint { .. } => OpKind::Taint,
            Op::ImportExternal { .. } => OpKind::ImportExternal,
            Op::ImportUnmediated { .. } => OpKind::ImportUnmediated,
            Op::BridgePush { .. } => OpKind::BridgePush,
            Op::Freeze { .. } => OpKind::Freeze,
            Op::Unfreeze { .. } => OpKind::Unfreeze,
            Op::Negotiate { .. } => OpKind::Negotiate,
            Op::Redact { .. } => OpKind::Redact,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allow,
    Deny,
    Escalate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: Outcome,
    /// Machine-readable reason codes such as `lease_missing:src/a.rs#f`.
    pub reasons: Vec<String>,
}

impl Decision {
    pub fn allow() -> Self {
        Self {
            outcome: Outcome::Allow,
            reasons: vec![],
        }
    }

    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Deny,
            reasons: vec![reason.into()],
        }
    }

    pub fn escalate(reason: impl Into<String>) -> Self {
        Self {
            outcome: Outcome::Escalate,
            reasons: vec![reason.into()],
        }
    }

    pub fn is_allow(&self) -> bool {
        self.outcome == Outcome::Allow
    }
}

/// A human's signature over an operation. The signed message is the
/// canonical JSON of [`HumanIntent`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanSignature {
    pub human: String,
    pub nonce: String,
    pub issued_ms: i64,
    pub sig: String,
}

#[derive(Serialize)]
pub struct HumanIntent<'a> {
    pub purpose: &'static str,
    pub repo: &'a str,
    pub op: &'a Op,
    pub nonce: &'a str,
    pub issued_ms: i64,
}

impl<'a> HumanIntent<'a> {
    pub fn new(repo: &'a str, op: &'a Op, nonce: &'a str, issued_ms: i64) -> Self {
        Self {
            purpose: "lonca-human-intent-v1",
            repo,
            op,
            nonce,
            issued_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_op_kind_is_rejected() {
        assert!(serde_json::from_str::<OpKind>("\"change.propose\"").is_ok());
        assert!(serde_json::from_str::<OpKind>("\"admin.everything\"").is_err());
    }

    #[test]
    fn op_kind_names_match_serde() {
        for k in [
            OpKind::RepoInit,
            OpKind::ChangePropose,
            OpKind::LeaseAcquire,
            OpKind::Redact,
            OpKind::SessionBind,
        ] {
            assert_eq!(
                serde_json::to_string(&k).unwrap(),
                format!("\"{}\"", k.as_str())
            );
        }
    }

    #[test]
    fn reserved_ops_are_not_grantable() {
        for k in [
            OpKind::PolicyUpdate,
            OpKind::Approve,
            OpKind::CapRevoke,
            OpKind::Redact,
            OpKind::HumanEnroll,
            OpKind::Freeze,
            OpKind::ImportExternal,
        ] {
            assert!(!k.agent_grantable(), "{k:?}");
        }
    }
}
