//! Wire protocol: one JSON object per line over a Unix socket.

use std::io::{BufRead, Write};

use lonca_core::ops::{Claim, Decision, HumanSignature, LeaseItem, NegotiationMsg, Op, Scope};
use lonca_core::{ChangeId, FileMode, GitId};
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrepareInit {
    pub repo: String,
    pub human: String,
    pub human_key: lonca_core::ops::HumanKey,
    /// Import trunk from this Git repository (path or URL).
    #[serde(default)]
    pub import_from: Option<String>,
    #[serde(default)]
    pub branch: Option<String>,
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
    /// With nothing past `from`, hold the request this long (capped at
    /// [`crate::service::LOG_WAIT_MAX_MS`]) for an entry to arrive.
    #[serde(default)]
    pub wait_ms: Option<i64>,
}

/// A harness hook event (Claude Code's hook input, reduced to what Lonca uses).
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookVerdict {
    /// `allow`, `deny` or `ask`.
    pub decision: String,
    #[serde(default)]
    pub reason: String,
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
                Some(String::from_utf8_lossy(&buf).into_owned())
            });
        }
        match chunk.iter().position(|&b| b == b'\n') {
            Some(i) => {
                buf.extend_from_slice(&chunk[..i]);
                r.consume(i + 1);
                return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
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
