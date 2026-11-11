//! One repository: its store, its sequencer and its policy.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use lonca_core::changeid::CHANGE_ID_HEADER;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{OpLog, SignedOp, verify_chain};
use lonca_core::ops::{Actor, HumanSignature, Op};
use lonca_core::store::CommitSpec;
use lonca_core::{ChangeId, Error, FileEntry, FileMap, FileMode, GitId, Result, Store};
use lonca_policy::chain::{Chain, Submission, replay_checked};
use lonca_policy::config::{CONFIG_FILE, POLICY_FILE, PolicyBundle};
use lonca_policy::events::Told;
use lonca_policy::state::State;

use crate::protocol::FileChange;

pub const TRUNK_REF: &str = "refs/heads/main";
pub const POLICY_REF: &str = "refs/lonca/policy";
pub const SESSION_HEADER: &str = "lonca-session";
pub const HUMAN_HEADER: &str = "lonca-human";

/// Total size of one proposal.
pub const MAX_PROPOSAL_BYTES: usize = 64 * 1024 * 1024;

/// The most an entry's operation and human signature take, as JSON. The log
/// keeps every entry for good, the refused ones too, so what a caller can
/// put in one is bounded before it is decided and signed. The lists the
/// policy counts (a lease's items, a change's files) fit many times over.
pub const MAX_OP_BYTES: usize = 64 * 1024;

pub struct RepoHandle {
    pub name: String,
    pub store: Arc<Store>,
    pub chain: Chain,
    pub head: Option<GitId>,
    policy: Option<(GitId, Arc<PolicyBundle>)>,
    /// How far each session has been told what others want of it.
    pub told: BTreeMap<String, Told>,
    /// What each session's hooks were heard saying since the daemon started.
    pub hooked: BTreeMap<String, crate::hooked::Hooked>,
    /// Security events of entries appended since the service last took
    /// them: freezes, unmediated imports, taints ([`crate::security`]).
    pub alarms: Vec<crate::security::Event>,
}

impl RepoHandle {
    pub fn create(name: &str, path: &Path, key: KeyPair) -> Result<Self> {
        let store = Store::init_bare(path)?;
        Ok(Self {
            name: name.into(),
            store: Arc::new(store),
            chain: Chain::new(key),
            head: None,
            policy: None,
            told: BTreeMap::new(),
            hooked: BTreeMap::new(),
            alarms: Vec::new(),
        })
    }

    /// Opens a store and replays its log, deciding every daemon key switch
    /// again. Refuses a log that does not verify. `keys` are the keys this
    /// daemon holds, the one for new repositories first; the repository
    /// signs with the one its log is on. A log on none of them is
    /// [`RepoHandle::foreign`].
    pub fn open(name: &str, path: &Path, keys: &[&KeyPair]) -> Result<Self> {
        let store = Store::open(path)?;
        let log = OpLog::new(&store);
        let ops = log.read_all()?;
        let state = if ops.is_empty() {
            State::new()
        } else {
            verify_chain(&ops)?;
            for op in &ops {
                if let Some(v) = op.entry.engine() {
                    lonca_symbols::engine::check(v).map_err(|e| {
                        Error::Unsupported(format!("repo {name}, op {}: {e}", op.entry.seq))
                    })?;
                }
            }
            replay_checked(&ops, |id| match id {
                None => Ok(Arc::new(PolicyBundle::default_bundle())),
                Some(id) => Self::load_policy(&store, id).map(Arc::new),
            })
            .map_err(|e| Error::Integrity(format!("repo {name}: {e}")))?
        };
        let key = keys
            .iter()
            .find(|k| k.public_hex() == state.daemon_key)
            .unwrap_or(&keys[0]);
        let head = log.head()?;
        Ok(Self {
            name: name.into(),
            store: Arc::new(store),
            chain: Chain::from_state((*key).clone(), state),
            head,
            policy: None,
            told: BTreeMap::new(),
            hooked: BTreeMap::new(),
            alarms: Vec::new(),
        })
    }

    /// The log is on a daemon key this daemon does not hold: another daemon
    /// wrote it, or this daemon's key was lost. Only `daemon.recover` can
    /// continue it.
    pub fn foreign(&self) -> bool {
        self.initialized() && self.chain.state.daemon_key != self.chain.public_key()
    }

    pub fn initialized(&self) -> bool {
        self.chain.state.next_seq > 0
    }

    pub fn load_policy(store: &Store, commit: &GitId) -> Result<PolicyBundle> {
        let read = |f: &str| -> Result<String> {
            let bytes = store.read_file(commit, f)?.ok_or_else(|| {
                Error::Invalid(format!("policy commit {} has no {f}", commit.short()))
            })?;
            String::from_utf8(bytes).map_err(|_| Error::Invalid(format!("{f} is not UTF-8")))
        };
        PolicyBundle::parse(&read(CONFIG_FILE)?, &read(POLICY_FILE)?).map_err(Error::Invalid)
    }

    /// The policy in force. Before genesis, the shipped default.
    pub fn policy(&mut self) -> Result<Arc<PolicyBundle>> {
        let Some(id) = self.chain.state.policy.clone() else {
            return Ok(Arc::new(PolicyBundle::default_bundle()));
        };
        if let Some((cached, b)) = &self.policy
            && *cached == id
        {
            return Ok(b.clone());
        }
        let b = Arc::new(Self::load_policy(&self.store, &id)?);
        self.policy = Some((id, b.clone()));
        Ok(b)
    }

    /// Refuses a submission past [`MAX_OP_BYTES`], before anything is
    /// decided, signed or written. Only the results of the daemon's own
    /// merges are let past it: their length is the repository's, and a
    /// refusal there would leave the queue with a change it can not finish.
    fn fits(sub: &Submission) -> Result<()> {
        Self::op_fits(&sub.actor, &sub.op, sub.human.as_ref())
    }

    /// [`Self::fits`] for the parts of a submission, for a caller that
    /// writes to the store before it submits: asked first, a refusal leaves
    /// nothing behind.
    pub fn op_fits(actor: &Actor, op: &Op, human: Option<&HumanSignature>) -> Result<()> {
        let merged = matches!(
            op,
            Op::ChangeIntegrate { .. } | Op::ChangeIntegrateBatch { .. }
        );
        if merged && *actor == Actor::Daemon {
            return Ok(());
        }
        let signature = match human {
            Some(h) => serde_json::to_vec(h)?.len(),
            None => 0,
        };
        let bytes = serde_json::to_vec(op)?.len() + signature;
        if bytes > MAX_OP_BYTES {
            return Err(Error::Invalid(format!(
                "{} is {bytes} bytes; an entry of the log holds {MAX_OP_BYTES}. \
                 Shorten its text and lists, or split it",
                op.kind().as_str()
            )));
        }
        Ok(())
    }

    /// Decides without logging (used to refuse a bad genesis without
    /// leaving a denied genesis entry behind).
    pub fn dry_run(&mut self, sub: Submission, wall_ms: i64) -> Result<SignedOp> {
        Self::fits(&sub)?;
        let policy = self.policy()?;
        let t = self.chain.entry_time(wall_ms);
        Ok(self.chain.prepare(sub, t, &policy))
    }

    /// Decide, sign, persist, apply.
    pub fn submit(&mut self, sub: Submission, wall_ms: i64) -> Result<SignedOp> {
        Self::fits(&sub)?;
        let policy = self.policy()?;
        let t = self.chain.entry_time(wall_ms);
        let op = self.chain.prepare(sub, t, &policy);
        let commit = OpLog::new(&self.store).append(&op, self.head.as_ref())?;
        self.head = Some(commit);
        self.chain.commit(&op);
        self.alarm(&op);
        Ok(op)
    }

    /// The security event an appended entry is, if any.
    fn alarm(&mut self, op: &SignedOp) {
        use crate::security::{Event, kind};
        let e = &op.entry;
        if !e.decision.is_allow() {
            return;
        }
        let event = |k: &str| Event::new(e.time_ms, k).repo(&self.name);
        let found = match &e.op {
            Op::Freeze { reason } => Some(event(kind::FREEZE).detail(reason)),
            Op::ImportUnmediated { refname, .. } => Some(event(kind::UNMEDIATED).detail(refname)),
            Op::Taint { session, reason } => {
                Some(event(kind::TAINT).session(session).detail(reason))
            }
            Op::Observe { session, events } => events.iter().find_map(|ev| match &ev.kind {
                lonca_core::ops::ObsKind::Unhooked { tool } => {
                    Some(event(kind::UNHOOKED).session(session).detail(tool))
                }
                _ => None,
            }),
            _ => None,
        };
        self.alarms.extend(found);
    }

    pub fn write_policy(
        &self,
        config: &str,
        policy: &str,
        parent: Option<&GitId>,
        time_ms: i64,
    ) -> Result<GitId> {
        PolicyBundle::parse(config, policy).map_err(Error::Invalid)?;
        let mut files = FileMap::new();
        for (name, text) in [(CONFIG_FILE, config), (POLICY_FILE, policy)] {
            files.insert(
                name.into(),
                FileEntry {
                    mode: FileMode::Regular,
                    blob: self.store.write_blob(text.as_bytes())?,
                },
            );
        }
        let tree = self.store.write_tree(&files)?;
        self.store.write_commit(&CommitSpec {
            tree,
            parents: parent.into_iter().cloned().collect(),
            author_name: "lonca".into(),
            author_email: "policy@lonca.invalid".into(),
            time_ms,
            message: "lonca: policy\n".into(),
            headers: vec![],
        })
    }

    /// Applies `changes` to `base` and writes the proposal commit.
    #[allow(clippy::too_many_arguments)]
    pub fn build_change_commit(
        &self,
        base: &GitId,
        changes: &[FileChange],
        change: ChangeId,
        author_name: &str,
        author_email: &str,
        attribution: (&str, &str),
        intent: &str,
        time_ms: i64,
        max_file_bytes: u64,
    ) -> Result<GitId> {
        let base_info = self.store.read_commit(base)?;
        let mut files = self.store.read_tree(&base_info.tree)?;
        let mut total = 0usize;
        let mut seen = std::collections::BTreeSet::new();
        for c in changes {
            lonca_core::paths::validate_repo_path(&c.path)?;
            if lonca_core::paths::is_workspace_metadata(&c.path) {
                return Err(Error::Invalid(
                    ".lonca/ is workspace metadata, not repository content".into(),
                ));
            }
            if !seen.insert(c.path.clone()) {
                return Err(Error::Invalid(format!("{} listed twice", c.path)));
            }
            match &c.content_b64 {
                None => {
                    if files.remove(&c.path).is_none() {
                        return Err(Error::Invalid(format!(
                            "cannot delete missing file {}",
                            c.path
                        )));
                    }
                }
                Some(b64) => {
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .map_err(|e| Error::Invalid(format!("{}: {e}", c.path)))?;
                    if bytes.len() as u64 > max_file_bytes {
                        return Err(Error::Invalid(format!(
                            "{} exceeds {max_file_bytes} bytes",
                            c.path
                        )));
                    }
                    total += bytes.len();
                    if total > MAX_PROPOSAL_BYTES {
                        return Err(Error::Invalid("proposal too large".into()));
                    }
                    let mode = c
                        .mode
                        .or_else(|| files.get(&c.path).map(|e| e.mode))
                        .unwrap_or(FileMode::Regular);
                    if mode == FileMode::Submodule {
                        return Err(Error::Invalid("submodules can not be written".into()));
                    }
                    files.insert(
                        c.path.clone(),
                        FileEntry {
                            mode,
                            blob: self.store.write_blob(&bytes)?,
                        },
                    );
                }
            }
        }
        let tree = self.store.write_tree(&files)?;
        if tree == base_info.tree {
            return Err(Error::Invalid("the change is empty".into()));
        }
        let message = commit_message(intent, change);
        self.store.write_commit(&CommitSpec {
            tree,
            parents: vec![base.clone()],
            author_name: author_name.into(),
            author_email: author_email.into(),
            time_ms,
            message,
            headers: vec![
                (CHANGE_ID_HEADER.into(), change.to_reverse_hex()),
                (attribution.0.into(), attribution.1.into()),
            ],
        })
    }

    /// Checks that `commit` is a proposal for `change` made on `base`.
    pub fn check_proposal(&self, commit: &GitId, base: &GitId, change: ChangeId) -> Result<()> {
        let info = self.store.read_commit(commit)?;
        if info.parents != vec![base.clone()] {
            return Err(Error::Invalid(
                "proposal commit must have the base as its only parent".into(),
            ));
        }
        if info.header(CHANGE_ID_HEADER) != Some(change.to_reverse_hex().as_str()) {
            return Err(Error::Invalid(
                "proposal commit carries another change id".into(),
            ));
        }
        Ok(())
    }
}

/// First line of the intent (control characters removed), then the id.
pub fn commit_message(intent: &str, change: ChangeId) -> String {
    let line: String = intent
        .lines()
        .next()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let line = line.trim();
    let title = if line.is_empty() {
        format!("lonca change {}", change.short())
    } else {
        line.to_string()
    };
    format!("{title}\n")
}
