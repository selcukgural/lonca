//! The operation vocabulary. Every state change in a Lonca repository is one
//! of these, recorded (allowed or not) in the operation log.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::changeid::ChangeId;
use crate::objects::GitId;

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
    #[serde(rename = "human.rotate")]
    HumanRotate,
    #[serde(rename = "human.revoke")]
    HumanRevoke,
    #[serde(rename = "human.recovery_key")]
    HumanRecoveryKey,
    #[serde(rename = "human.recover")]
    HumanRecover,
    #[serde(rename = "daemon.rotate")]
    DaemonRotate,
    #[serde(rename = "daemon.recover")]
    DaemonRecover,
    #[serde(rename = "policy.update")]
    PolicyUpdate,
    #[serde(rename = "session.start")]
    SessionStart,
    #[serde(rename = "session.bind")]
    SessionBind,
    #[serde(rename = "session.isolate")]
    SessionIsolate,
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
    #[serde(rename = "lease.interest")]
    LeaseInterest,
    #[serde(rename = "change.propose")]
    ChangePropose,
    #[serde(rename = "change.withdraw")]
    ChangeWithdraw,
    #[serde(rename = "change.integrate")]
    ChangeIntegrate,
    #[serde(rename = "change.integrate_batch")]
    ChangeIntegrateBatch,
    #[serde(rename = "approve")]
    Approve,
    #[serde(rename = "reject")]
    Reject,
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
            OpKind::HumanRotate => "human.rotate",
            OpKind::HumanRevoke => "human.revoke",
            OpKind::HumanRecoveryKey => "human.recovery_key",
            OpKind::HumanRecover => "human.recover",
            OpKind::DaemonRotate => "daemon.rotate",
            OpKind::DaemonRecover => "daemon.recover",
            OpKind::PolicyUpdate => "policy.update",
            OpKind::SessionStart => "session.start",
            OpKind::SessionBind => "session.bind",
            OpKind::SessionIsolate => "session.isolate",
            OpKind::SessionEnd => "session.end",
            OpKind::CapAttenuate => "cap.attenuate",
            OpKind::CapRevoke => "cap.revoke",
            OpKind::LeaseAcquire => "lease.acquire",
            OpKind::LeaseRelease => "lease.release",
            OpKind::LeaseRenew => "lease.renew",
            OpKind::LeaseInterest => "lease.interest",
            OpKind::ChangePropose => "change.propose",
            OpKind::ChangeWithdraw => "change.withdraw",
            OpKind::ChangeIntegrate => "change.integrate",
            OpKind::ChangeIntegrateBatch => "change.integrate_batch",
            OpKind::Approve => "approve",
            OpKind::Reject => "reject",
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
                | OpKind::LeaseInterest
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
    /// Absolute directories outside the workspace the agent may write to
    /// (notes, logs, throwaway files). Writes there are allowed and are
    /// not facts; nothing there can be proposed. Left out of the encoding
    /// when empty, so entries without one keep their bytes (format 5).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scratch: Vec<String>,
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
    /// Shared: change the body of a symbol alongside others who hold it
    /// `shared`; the merge joins their lines (log format 21, needs
    /// `leases.shared`).
    Shared,
}

impl LeaseKind {
    pub const ALL: [LeaseKind; 4] = [Self::Edit, Self::Insert, Self::Rename, Self::Shared];

    /// The name in entries and requests.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Edit => "edit",
            Self::Insert => "insert",
            Self::Rename => "rename",
            Self::Shared => "shared",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }
}

impl LeaseItem {
    /// An item with no reserved names.
    pub fn new(symbol: impl Into<String>, kind: LeaseKind) -> Self {
        Self {
            symbol: symbol.into(),
            kind,
            names: Vec::new(),
        }
    }

    pub fn is_shared(&self) -> bool {
        self.kind == LeaseKind::Shared
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LeaseItem {
    /// `path#Qualified.name`; for `insert`, the container (`path#Type` or `path#<file>`).
    pub symbol: String,
    pub kind: LeaseKind,
    /// For `insert` only: the names of the members it adds, bare (no key).
    /// Two inserts into one container whose names meet conflict, and an
    /// addition under this item must be one of them. Empty reserves nothing
    /// and allows any addition. Left out of the encoding when empty, so
    /// entries without names keep their bytes (log format 22).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
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

/// The member of a type that stands for its own text: `Type.<def>` is the
/// header, fields, decorators and class-level statements, and for Rust every
/// `impl` header of the type, without its methods.
pub const DEF: &str = "<def>";

/// A file whose symbols are sections: their names are its headings and keys,
/// written by people, and a `(` in one is only that.
pub fn names_are_headings(path: &str) -> bool {
    let ext = path.rsplit_once('.').map(|(_, ext)| ext);
    matches!(
        ext,
        Some("md" | "markdown" | "toml" | "json" | "yml" | "yaml")
    )
}

/// The first symbol engine whose facts name `Type.<def>`. Before it the same
/// text could only be the heading of a document section.
pub const ENGINE_DEFS: u32 = 3;

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
    /// Symbols that go on under another name: `[old, new]`. A renamed one is
    /// also in `deletes` and `adds`, one with new parameters in `edits`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub renames: Vec<[String; 2]>,
    /// Text files changed that no parser reads, whole-file edits in `edits`.
    /// Under `leases.unparsed_files = "optimistic"` they need no lease.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unparsed_files: Vec<String>,
    /// Files that a grammar read until this change and can not read after
    /// it. From here on facts about them say nothing of their symbols, so a
    /// person has to agree.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unread_files: Vec<String>,
    /// Symbols of the base that mention by name what this change gives a new
    /// signature, renames or deletes, and that it leaves as they are. By name
    /// only: a guess that errs towards too many, never a call graph.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected: Vec<String>,
    /// How many more there were than `affected` holds.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub affected_more: u32,
    /// Keys, as `dir#key`, that a file this change adds to a keyed
    /// directory shares with another file of its tree (`paths.keyed`).
    /// Computed with the policy in force, from format 29.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub taken_keys: Vec<String>,
}

fn is_zero(n: &u32) -> bool {
    *n == 0
}

impl Facts {
    /// This change can break code it did not touch: what depends on a
    /// signature, or something mentions a name it takes away.
    pub fn reaches_others(&self) -> bool {
        !self.signature_changes.is_empty() || !self.affected.is_empty() || self.affected_more > 0
    }
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
    /// `verification.on_signature_change`.
    Extended,
    /// One of `verification.checks`, by the name in `details["name"]`.
    Named,
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
    /// What names the environment the check ran in. For a command, a
    /// digest of the sandbox, the command, its `PATH`, the policy's fixed
    /// values, the names passed through (never their values) and what each
    /// `verification.identify` command printed, whose first lines are in
    /// `details` (`env.<n>.command`, `.output`, `.error`). Entries from
    /// before identify (0.2.x) digest the sandbox and the command only.
    /// `tree-sitter` for the syntax check. Recorded, never recomputed.
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
    /// What the workspace held that no standing proposal of the session
    /// carries, when the agent stopped or ended its session. `paths` lists
    /// at most [`MAX_UNPROPOSED_PATHS`] of `total`; a `total` of 0 says the
    /// work is gone or delivered.
    Unproposed {
        paths: Vec<String>,
        total: u64,
    },
    /// `lonca mcp` ran `tool` and the harness's before-tool event for that
    /// call never reached the daemon: the session's hooks are not running.
    /// `tool` is the MCP tool's name, without the harness's prefix.
    Unhooked {
        tool: String,
    },
}

/// The most paths one [`ObsKind::Unproposed`] names.
pub const MAX_UNPROPOSED_PATHS: usize = 32;

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
    /// Give up the named lease set in favour of the receiver. With `to` the
    /// set moves to that session in this entry, so nobody can take it in
    /// between; without, it is freed.
    Yield {
        set: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        to: Option<String>,
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

/// What a `daemon.recover` signed with a recovery key also does: replace
/// that human's lost key, as `human.recover` does. The recovery key is
/// used up by it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recovery {
    pub human: String,
    pub key: HumanKey,
}

/// A new session taking over the workspace of an earlier one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Continuation {
    pub session: String,
    /// The human asked for a scope wider than the earlier session's.
    pub widen: bool,
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
    /// Replaces the signer's own key. Signed with the current key.
    #[serde(rename = "human.rotate")]
    HumanRotate { human: String, key: HumanKey },
    /// Withdraws a human's keys and everything they set in motion.
    #[serde(rename = "human.revoke")]
    HumanRevoke { human: String, reason: String },
    /// Sets (or replaces) the signer's recovery key, kept off the machine.
    /// Signed with the current key.
    #[serde(rename = "human.recovery_key")]
    HumanRecoveryKey { human: String, key: HumanKey },
    /// Replaces a lost key. Signed with the human's recovery key, which is
    /// used up by it.
    #[serde(rename = "human.recover")]
    HumanRecover { human: String, key: HumanKey },
    /// Replaces the daemon key (Ed25519, hex). Signed by the old daemon key
    /// and by a human; later entries are signed by the new key.
    #[serde(rename = "daemon.rotate")]
    DaemonRotate { key: String },
    /// Re-anchors the log on a new daemon key when the old one is gone (or
    /// belongs to a daemon that is being replaced). Signed by the new key
    /// and by a human: with the human's key, or, with `recover`, with
    /// their recovery key, when the Mac that held both keys is lost (log
    /// format 27).
    #[serde(rename = "daemon.recover")]
    DaemonRecover {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recover: Option<Recovery>,
    },
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
        /// The session whose workspace this one takes over.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        continues: Option<Continuation>,
        /// The harness the human runs the session under. Their word, and the
        /// only one an observation level is read for (format 20).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        harness: Option<String>,
    },
    #[serde(rename = "session.bind")]
    SessionBind {
        session: String,
        checks: BindChecks,
        level: ObservationLevel,
    },
    /// A human's word that the session runs in a sandbox Lonca built: what
    /// gives it `level: isolated`. Never from the agent, and never from the
    /// daemon, which can not see the sandbox: the launcher builds it and the
    /// human who started the session signs for it.
    #[serde(rename = "session.isolate")]
    SessionIsolate {
        session: String,
        /// The kind of sandbox (`seatbelt`, `bwrap`).
        sandbox: String,
        /// SHA-256 of the sandbox's definition, lowercase hex.
        profile: String,
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
        /// Lease sets the parent hands to the child; they come back when
        /// the child ends.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        leases: Vec<String>,
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
    /// Holds nothing: when what conflicts with `items` is freed, the oldest
    /// interest gets a short reservation. Until then, for a limited time,
    /// no new lease can be taken that conflicts with `items`.
    #[serde(rename = "lease.interest")]
    LeaseInterest {
        items: Vec<LeaseItem>,
        intent: String,
    },
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
    /// Changes at the head of the queue, integrated at once. One entry, so
    /// that a crash can not leave trunk at a state nothing verified: the
    /// evidence is of the last commit, and trunk moves straight to it. The
    /// commits before it are in its history and were never trunk.
    #[serde(rename = "change.integrate_batch")]
    ChangeIntegrateBatch {
        trunk_before: GitId,
        /// Each change, in queue order, with the commit it merged to.
        merged: Vec<(ChangeId, GitId)>,
    },
    /// `checks`: named checks of `verification.checks` the change owes from
    /// here on, besides what it owed already; only on a proposal (log
    /// format 25). Sorted, each name once.
    #[serde(rename = "approve")]
    Approve {
        target_seq: u64,
        note: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        checks: Vec<String>,
    },
    /// A human declines an escalated operation; the reason is for the
    /// requester (a worker fixes and proposes again) and is never
    /// interpreted.
    #[serde(rename = "reject")]
    Reject { target_seq: u64, reason: String },
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
            Op::HumanRotate { .. } => OpKind::HumanRotate,
            Op::HumanRevoke { .. } => OpKind::HumanRevoke,
            Op::HumanRecoveryKey { .. } => OpKind::HumanRecoveryKey,
            Op::HumanRecover { .. } => OpKind::HumanRecover,
            Op::DaemonRotate { .. } => OpKind::DaemonRotate,
            Op::DaemonRecover { .. } => OpKind::DaemonRecover,
            Op::PolicyUpdate { .. } => OpKind::PolicyUpdate,
            Op::SessionStart { .. } => OpKind::SessionStart,
            Op::SessionBind { .. } => OpKind::SessionBind,
            Op::SessionIsolate { .. } => OpKind::SessionIsolate,
            Op::SessionEnd { .. } => OpKind::SessionEnd,
            Op::CapAttenuate { .. } => OpKind::CapAttenuate,
            Op::CapRevoke { .. } => OpKind::CapRevoke,
            Op::LeaseAcquire { .. } => OpKind::LeaseAcquire,
            Op::LeaseRelease { .. } => OpKind::LeaseRelease,
            Op::LeaseRenew { .. } => OpKind::LeaseRenew,
            Op::LeaseInterest { .. } => OpKind::LeaseInterest,
            Op::ChangePropose { .. } => OpKind::ChangePropose,
            Op::ChangeWithdraw { .. } => OpKind::ChangeWithdraw,
            Op::ChangeIntegrate { .. } => OpKind::ChangeIntegrate,
            Op::ChangeIntegrateBatch { .. } => OpKind::ChangeIntegrateBatch,
            Op::Approve { .. } => OpKind::Approve,
            Op::Reject { .. } => OpKind::Reject,
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

    /// Whether the human's recovery key signs this operation, not their
    /// current key: `human.recover`, and `daemon.recover` with `recover`.
    pub fn signed_by_recovery_key(&self) -> bool {
        matches!(
            self,
            Op::HumanRecover { .. }
                | Op::DaemonRecover {
                    recover: Some(_),
                    ..
                }
        )
    }

    /// The daemon key this operation installs, if it is a key switch.
    pub fn daemon_key_switch(&self) -> Option<&str> {
        match self {
            Op::DaemonRotate { key } | Op::DaemonRecover { key, .. } => Some(key),
            _ => None,
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

/// What a human signs to open a human session (`human.login`). Its own
/// purpose string keeps a login signature from ever passing as an
/// operation signature, and the other way round.
#[derive(Serialize)]
pub struct LoginIntent<'a> {
    pub purpose: &'static str,
    /// The repository whose enrolment verifies the key; `None` lets the
    /// daemon look in every repository.
    pub repo: Option<&'a str>,
    pub human: &'a str,
    pub ttl_ms: i64,
    pub nonce: &'a str,
    pub issued_ms: i64,
}

impl<'a> LoginIntent<'a> {
    pub fn new(
        repo: Option<&'a str>,
        human: &'a str,
        ttl_ms: i64,
        nonce: &'a str,
        issued_ms: i64,
    ) -> Self {
        Self {
            purpose: "lonca-human-login-v1",
            repo,
            human,
            ttl_ms,
            nonce,
            issued_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names requests use are the names in entries.
    #[test]
    fn lease_kinds_are_named_as_they_are_written() {
        for kind in LeaseKind::ALL {
            let written = serde_json::to_value(kind).unwrap();
            assert_eq!(written, kind.as_str());
            assert_eq!(LeaseKind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(LeaseKind::from_name("Shared"), None);
        assert_eq!(LeaseKind::from_name(""), None);
    }

    #[test]
    fn a_change_reaches_others_by_any_one_of_three() {
        assert!(!Facts::default().reaches_others());
        let signature = Facts {
            signature_changes: vec!["a.rs#f".into()],
            ..Facts::default()
        };
        let mentioned = Facts {
            affected: vec!["a.rs#g".into()],
            ..Facts::default()
        };
        let cut_off = Facts {
            affected_more: 1,
            ..Facts::default()
        };
        assert!(signature.reaches_others());
        assert!(mentioned.reaches_others());
        assert!(cut_off.reaches_others());
    }

    /// Left out when empty, so older entries keep their bytes; kept when not.
    #[test]
    fn what_was_cut_from_affected_is_written_out() {
        let none = serde_json::to_string(&Facts::default()).unwrap();
        assert!(!none.contains("affected"), "{none}");
        let cut_off = Facts {
            affected_more: 3,
            ..Facts::default()
        };
        let text = serde_json::to_string(&cut_off).unwrap();
        assert!(text.contains("\"affected_more\":3"), "{text}");
    }

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
            OpKind::SessionIsolate,
            OpKind::HumanRotate,
            OpKind::HumanRevoke,
            OpKind::HumanRecoveryKey,
            OpKind::HumanRecover,
            OpKind::DaemonRotate,
            OpKind::DaemonRecover,
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
            OpKind::HumanRotate,
            OpKind::HumanRevoke,
            OpKind::HumanRecoveryKey,
            OpKind::HumanRecover,
            OpKind::DaemonRotate,
            OpKind::DaemonRecover,
            OpKind::Freeze,
            OpKind::ImportExternal,
        ] {
            assert!(!k.agent_grantable(), "{k:?}");
        }
    }
}
