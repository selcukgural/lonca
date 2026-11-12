//! Wire protocol: one JSON object per line over a Unix socket
//! (`docs/protocol.md`). The parameters of `repo.prepare_init` are the
//! daemon's (`lonca_daemon::protocol::PrepareInit`): they name a policy
//! profile, and this crate knows no policy.

use std::collections::BTreeMap;
use std::io::{BufRead, Write};

use lonca_core::ops::{Claim, Decision, HumanSignature, LeaseItem, NegotiationMsg, Op, Scope};
use lonca_core::{ChangeId, FileEntry, FileMode, GitId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Largest accepted request line (base64 file contents included).
pub const MAX_LINE: usize = 96 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Request {
    pub id: u64,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// Agent session token or human session token. Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default)]
    pub params: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub result: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn ok(id: u64, result: Value) -> Self {
        Self {
            id,
            ok: true,
            result,
            error: None,
        }
    }

    pub fn err(id: u64, code: &str, message: impl Into<String>) -> Self {
        Self {
            id,
            ok: false,
            result: Value::Null,
            error: Some(ErrorBody {
                code: code.into(),
                message: message.into(),
            }),
        }
    }
}

/// The outcome of a logged operation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Logged {
    pub seq: u64,
    pub decision: Decision,
}

/// One file in a proposed change, relative to the base commit.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    /// `None` deletes the file.
    #[serde(default)]
    pub content_b64: Option<String>,
    #[serde(default)]
    pub mode: Option<FileMode>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HumanSubmit {
    pub op: Op,
    pub sig: HumanSignature,
    /// `session.isolate`: the workspace, which the proxy attributes
    /// connections to. Not logged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace: Option<String>,
}

/// `human.prepare_isolate`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrepareIsolate {
    pub session: String,
    /// The commit the workspace says it stands on.
    pub base: GitId,
}

/// `human.login`: opens a human session. The signature is over a
/// [`lonca_core::ops::LoginIntent`]; `repo` on the request names the
/// repository whose enrolment verifies it, or is left out to try every
/// repository the daemon serves.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HumanLogin {
    pub sig: HumanSignature,
    /// Session length; the daemon has a default and a ceiling.
    #[serde(default)]
    pub ttl_ms: Option<i64>,
}

/// `repo.restore`: a new repository from a backup bundle, a bare store or
/// a remote Lonca pushed to.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Restore {
    pub repo: String,
    pub from: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrepareChange {
    pub base: GitId,
    pub files: Vec<FileChange>,
    #[serde(default)]
    pub change: Option<ChangeId>,
    pub author: String,
    #[serde(default)]
    pub intent: String,
    #[serde(default)]
    pub revert_of: Option<ChangeId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PreparePolicy {
    pub config: String,
    pub policy: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrepareRemote {
    pub remote: String,
    #[serde(default)]
    pub branch: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseAcquire {
    #[serde(default)]
    pub set: Option<String>,
    pub items: Vec<LeaseItem>,
    pub intent: String,
    pub ttl_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SetRef {
    pub set: String,
    #[serde(default)]
    pub ttl_ms: Option<i64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProposeChange {
    #[serde(default)]
    pub change: Option<ChangeId>,
    pub base: GitId,
    pub files: Vec<FileChange>,
    pub claim: Claim,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeRef {
    pub change: ChangeId,
}

/// `security.events`: what the security log holds since `since_ms`
/// (default: the last day).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SecurityEvents {
    #[serde(default)]
    pub since_ms: Option<i64>,
}

/// `trunk.bundle`: a Git bundle of trunk for a checkout, thin against
/// the commits the checkout already has.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrunkBundle {
    #[serde(default)]
    pub have: Vec<GitId>,
}

/// `trunk.distance`: how far a commit that once was trunk is behind.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrunkDistance {
    pub base: GitId,
}

/// `change.resolve`: the whole id of the one change whose id starts with
/// `prefix` (at least 4 letters).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeResolve {
    pub prefix: String,
}

/// `change.diff`: the unified diff of a change, computed by the daemon
/// in the store, with redaction applied and a size cap.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeDiff {
    pub change: ChangeId,
    /// Only `unified` today.
    #[serde(default)]
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Negotiate {
    pub thread: String,
    pub to_session: String,
    pub message: NegotiationMsg,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Attenuate {
    pub agent: String,
    pub scope: Scope,
    pub expires_ms: i64,
    /// Lease sets handed to the child until it ends.
    #[serde(default)]
    pub leases: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseInterest {
    pub items: Vec<LeaseItem>,
    #[serde(default)]
    pub intent: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Events {
    #[serde(default)]
    pub from: u64,
}

/// `events.watch`: a runner waits, with the human session it started its
/// agents with, for something it should wake one of them for. It marks
/// nothing as told: the agent still hears it through `inbox`. Keep the
/// answer's `next` and `reserved` for the next call ([`Watch::after`]).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Watch {
    /// `next` of the last answer. `None`: from now on, nothing older.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<u64>,
    /// Only these sessions, each one this human started. `None`: every
    /// live session this human started, as it is when the daemon looks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sessions: Option<Vec<String>>,
    /// `reserved` of the last answer: reservations already reported.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reserved: Vec<String>,
    /// With nothing new, hold the request this long (the daemon caps it at
    /// 30 seconds) for something to happen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wait_ms: Option<i64>,
}

impl Watch {
    /// The call that goes on from `answer` with the same sessions and wait.
    pub fn after(&self, answer: &Watched) -> Self {
        Self {
            from: Some(answer.next),
            reserved: answer.reserved.clone(),
            ..self.clone()
        }
    }
}

/// The answer to `events.watch`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Watched {
    pub events: Vec<WatchedEvent>,
    /// The `from` of the next call.
    pub next: u64,
    /// Every reservation the watched sessions hold now, reported or not:
    /// the `reserved` of the next call.
    #[serde(default)]
    pub reserved: Vec<String>,
    /// Sessions named in `sessions` that can not act any more. The wait
    /// ends at once while there is one: stop watching it.
    #[serde(default)]
    pub ended: Vec<EndedSession>,
}

/// One thing that happened to a watched session. Never what another agent
/// wrote: the agent reads that itself, with `inbox` or `events`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchedEvent {
    pub session: String,
    /// `integrated`, `conflicted`, `failed`, `approved`, `rejected`,
    /// `message`, `lease_received`, `symbols_changed` or `reserved`; more
    /// may come.
    pub kind: String,
    /// The log entry it comes from; `None` for `reserved`, which is the
    /// state now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change: Option<ChangeId>,
    /// The session that sent a message or handed a lease over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    /// A reservation's name, as it appears in `reserved`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation: Option<String>,
    /// When a reservation runs out unless the session leases it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until_ms: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndedSession {
    pub session: String,
    /// Why: the reason it, or the session it came from, was ended with, or
    /// `expired`.
    pub reason: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactsPreview {
    pub base: GitId,
    pub files: Vec<FileChange>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeQuery {
    pub commit: GitId,
    #[serde(default)]
    pub with_content: bool,
    #[serde(default)]
    pub paths: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TreeFile {
    pub path: String,
    pub mode: FileMode,
    pub blob: GitId,
    /// Blob size in bytes, so a client can page its fetches.
    #[serde(default)]
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_b64: Option<String>,
}

/// `blobs`: the contents of some files of one commit, one page. The
/// client sizes a page from `tree`'s sizes to stay under the line cap.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlobsQuery {
    pub commit: GitId,
    pub paths: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LogQuery {
    #[serde(default)]
    pub from: u64,
    #[serde(default)]
    pub limit: Option<u64>,
    /// With nothing past `from`, hold the request this long (the daemon caps
    /// it at 30 seconds) for an entry to arrive.
    #[serde(default)]
    pub wait_ms: Option<i64>,
}

/// A harness hook event, reduced to what Lonca uses. `hook.input` makes one
/// from what a harness sent; tool names stay the harness's own.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct HookEvent {
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(default)]
    pub cwd: Option<String>,
    /// Absolute path of the workspace root the hook resolved.
    pub workspace: String,
    /// The harness profile to read it with; none means `claude-code`.
    #[serde(default)]
    pub harness: Option<String>,
    /// Where the call's paths really are: a path as the call names it
    /// (from `cwd` when relative, nothing folded) to that path with its
    /// links resolved; the workspace and the scratch roots are in it too.
    /// A path it lacks is outside. `None`: the caller vouches that no path
    /// goes through a link, and each is placed by its text.
    #[serde(default)]
    pub real: Option<BTreeMap<String, String>>,
}

/// `harness.setup`: which harness's setup to read from the policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HarnessSetup {
    pub harness: String,
}

/// What a hook received from its harness, untouched: the daemon reads it with
/// the harness's profile from the policy.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HookInput {
    pub harness: String,
    pub input: Value,
    /// Absolute path of the workspace root the hook resolved.
    pub workspace: String,
    /// That root with its links resolved, as a `session.start` names a
    /// workspace: the daemon holds it against the log's.
    #[serde(default)]
    pub real: Option<String>,
    /// The answer to `"phase": "resolve"`: each path the daemon asked
    /// about to where it really is (`real_path`). A path left out is
    /// outside the workspace.
    #[serde(default)]
    pub paths: Option<BTreeMap<String, String>>,
}

/// One file a workspace differs in from its base, as it would be in a tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalFile {
    pub path: String,
    /// `None`: the file is deleted.
    #[serde(default)]
    pub entry: Option<FileEntry>,
}

/// `hook.stop`: the agent is about to finish its turn, with these changes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HookStop {
    pub harness: String,
    pub files: Vec<LocalFile>,
}

/// `mcp.call`: `lonca mcp` is about to run one of its tools, by the name it
/// has in `tools/list`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct McpCall {
    pub tool: String,
}

/// `session.end`: what the workspace held, when the client knows.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SessionEnd {
    #[serde(default)]
    pub files: Option<Vec<LocalFile>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HookBind {
    pub harness: String,
    pub harness_session: String,
    pub sudo_without_password: bool,
    /// Workspace root; lets the network proxy attribute connections.
    #[serde(default)]
    pub workspace: Option<String>,
}

/// Asks where the log places a session. Needs no token: it is the question
/// of a hook, or of a human's command, that found no workspace file it can
/// trust, and the answer is the log's.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SessionWhere {
    /// An absolute, normalized path: the session whose workspace it is, or
    /// holds it.
    #[serde(default)]
    pub path: Option<String>,
    /// A hook's harness and the short strings at the top of its input: the
    /// session that harness's session is bound to.
    #[serde(default)]
    pub harness: Option<String>,
    #[serde(default)]
    pub fields: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookVerdict {
    /// `allow`, `deny` or `ask`.
    pub decision: String,
    #[serde(default)]
    pub reason: String,
}

/// The bytes of a line as text: themselves when they are UTF-8, which
/// costs no copy, and otherwise with what is not replaced.
pub fn line_text(buf: Vec<u8>) -> String {
    String::from_utf8(buf).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Reads one line of at most `max` bytes. `Ok(None)` at end of stream.
pub fn read_line_limited(r: &mut impl BufRead, max: usize) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    loop {
        let chunk = r.fill_buf()?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() {
                None
            } else {
                Some(line_text(buf))
            });
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&chunk[..i]);
                r.consume(i + 1);
                return Ok(Some(line_text(buf)));
            }
            None => {
                let n = chunk.len();
                buf.extend_from_slice(chunk);
                r.consume(n);
                if buf.len() > max {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "request too large",
                    ));
                }
            }
        }
    }
}

pub fn write_line<T: Serialize>(w: &mut impl Write, v: &T) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(v)?;
    bytes.push(b'\n');
    w.write_all(&bytes)?;
    w.flush()
}
