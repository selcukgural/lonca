//! One repository: its store, its sequencer and its policy.

use std::path::Path;
use std::sync::Arc;

use base64::Engine;
use lonca_core::changeid::CHANGE_ID_HEADER;
use lonca_core::keys::KeyPair;
use lonca_core::oplog::{OpLog, SignedOp, verify_chain};
use lonca_core::ops::Op;
use lonca_core::store::CommitSpec;
use lonca_core::{ChangeId, Error, FileEntry, FileMap, FileMode, GitId, Result, Store};
use lonca_policy::chain::{Chain, Submission};
use lonca_policy::config::{
    CONFIG_FILE, DEFAULT_CONFIG, DEFAULT_POLICY, POLICY_FILE, PolicyBundle,
};

use crate::protocol::FileChange;

pub const TRUNK_REF: &str = "refs/heads/main";
pub const POLICY_REF: &str = "refs/lonca/policy";
pub const SESSION_HEADER: &str = "lonca-session";
pub const HUMAN_HEADER: &str = "lonca-human";

/// Total size of one proposal.
pub const MAX_PROPOSAL_BYTES: usize = 64 * 1024 * 1024;

pub struct RepoHandle {
    pub name: String,
    pub store: Arc<Store>,
    pub chain: Chain,
    pub head: Option<GitId>,
    policy: Option<(GitId, Arc<PolicyBundle>)>,
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
        })
    }

    /// Opens a store and replays its log. Refuses a log that does not
    /// verify or that another daemon key signed.
    pub fn open(name: &str, path: &Path, key: KeyPair) -> Result<Self> {
        let store = Store::open(path)?;
        let log = OpLog::new(&store);
        let ops = log.read_all()?;
        if !ops.is_empty() {
            verify_chain(&ops)?;
            if let Op::RepoInit { daemon_key, .. } = &ops[0].entry.op
                && *daemon_key != key.public_hex()
            {
                return Err(Error::Integrity(format!(
                    "repo {name} was created by another daemon key"
                )));
            }
        }
        let head = log.head()?;
        Ok(Self {
            name: name.into(),
            store: Arc::new(store),
            chain: Chain::from_ops(key, &ops),
            head,
            policy: None,
        })
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

    /// Decides without logging (used to refuse a bad genesis without
    /// leaving a denied genesis entry behind).
    pub fn dry_run(&mut self, sub: Submission, wall_ms: i64) -> Result<SignedOp> {
        let policy = self.policy()?;
        let t = self.chain.entry_time(wall_ms);
        Ok(self.chain.prepare(sub, t, &policy))
    }

    /// Decide, sign, persist, apply.
    pub fn submit(&mut self, sub: Submission, wall_ms: i64) -> Result<SignedOp> {
        let policy = self.policy()?;
        let t = self.chain.entry_time(wall_ms);
        let op = self.chain.prepare(sub, t, &policy);
        let commit = OpLog::new(&self.store).append(&op, self.head.as_ref())?;
        self.head = Some(commit);
        self.chain.commit(&op);
        Ok(op)
    }

    pub fn write_default_policy(&self, time_ms: i64) -> Result<GitId> {
        self.write_policy(DEFAULT_CONFIG, DEFAULT_POLICY, None, time_ms)
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
            if c.path == ".lonca" || c.path.starts_with(".lonca/") {
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
