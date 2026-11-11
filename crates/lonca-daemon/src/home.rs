//! The daemon's home directory.
//!
//! ```text
//! $LONCA_HOME/
//!   daemon.key        ed25519 signing key (0600)
//!   daemon.next.key   the key a rotation in progress moves to (0600)
//!   tokens.json       sha256(token) -> agent session or human session (0600)
//!   lonca.sock        Unix socket
//!   repos/<name>.git  bare Git stores
//!   scratch/          verifier work trees, a preview's objects
//!   backups/          bundles written by `repo.backup` (or $LONCA_BACKUPS)
//! ```
//!
//! In hardened mode the directory belongs to a dedicated system user, so
//! agents running as the developer can not read the key or write the stores.
//! The backups directory is the one place the developer's group may read,
//! so it lives outside the home there (`--backups`).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use lonca_core::canonical::{random_bytes, sha256_hex};
use lonca_core::keys::KeyPair;

use crate::sys::current_uid;
use lonca_core::{Error, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct Home {
    pub root: PathBuf,
    backups: Option<PathBuf>,
}

impl Home {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            backups: None,
        }
    }

    /// `$LONCA_HOME`, else `~/.lonca`; backups in `$LONCA_BACKUPS` if set.
    pub fn from_env() -> Self {
        let home = match std::env::var_os("LONCA_HOME") {
            Some(p) => Self::new(p),
            None => {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                Self::new(home.join(".lonca"))
            }
        };
        match std::env::var_os("LONCA_BACKUPS") {
            Some(p) => home.with_backups(p),
            None => home,
        }
    }

    /// Where `repo.backup` writes its bundles instead of `backups/` in the
    /// home: in hardened mode a directory the developer's group can read.
    pub fn with_backups(mut self, dir: impl Into<PathBuf>) -> Self {
        self.backups = Some(dir.into());
        self
    }

    pub fn backups(&self) -> PathBuf {
        self.backups
            .clone()
            .unwrap_or_else(|| self.root.join("backups"))
    }

    /// Creates the home, or checks the one there: it must belong to this
    /// process's user, and it is closed to everyone else (mode 0700).
    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(self.repos())?;
        owned_by(&self.root, current_uid())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    /// `$LONCA_SOCKET`, else `lonca.sock` in the home. Unix socket paths are
    /// limited to about 100 bytes, so long homes need `LONCA_SOCKET`.
    pub fn socket(&self) -> PathBuf {
        std::env::var_os("LONCA_SOCKET")
            .map(PathBuf::from)
            .unwrap_or_else(|| self.root.join("lonca.sock"))
    }

    pub fn key_path(&self) -> PathBuf {
        self.root.join("daemon.key")
    }

    pub fn repos(&self) -> PathBuf {
        self.root.join("repos")
    }

    pub fn repo_path(&self, name: &str) -> PathBuf {
        self.repos().join(format!("{name}.git"))
    }

    /// The daemon's copies of bundles from the import directory, each
    /// removed after its fetch; emptied at every start.
    pub fn imports(&self) -> PathBuf {
        self.root.join("imports")
    }

    pub fn scratch(&self) -> PathBuf {
        self.root.join("scratch")
    }

    pub fn tokens_path(&self) -> PathBuf {
        self.root.join("tokens.json")
    }

    /// Written by `lonca-audit --freeze-flag` when it finds a problem.
    pub fn freeze_flag(&self, repo: &str) -> PathBuf {
        self.root.join("freeze").join(repo)
    }

    pub fn load_key(&self) -> Result<KeyPair> {
        KeyPair::load_or_create(&self.key_path(), current_uid())
    }

    /// Where a rotation keeps the new key until every repository uses it.
    pub fn next_key_path(&self) -> PathBuf {
        self.root.join("daemon.next.key")
    }

    /// The current key and the key of an unfinished rotation. A crash
    /// between the two steps of [`Home::promote_next_key`] leaves only the
    /// next key; it is the current one then.
    pub fn load_keys(&self) -> Result<(KeyPair, Option<KeyPair>)> {
        let next = self.next_key_path();
        if !self.key_path().exists() && next.exists() {
            fs::rename(&next, self.key_path())?;
        }
        let current = self.load_key()?;
        let next = if next.exists() {
            Some(KeyPair::load(&next, current_uid())?)
        } else {
            None
        };
        Ok((current, next))
    }

    /// The next key, created on first use.
    pub fn load_or_create_next_key(&self) -> Result<KeyPair> {
        KeyPair::load_or_create(&self.next_key_path(), current_uid())
    }

    /// Makes the next key the current one once no repository uses the
    /// current key. The old secret is deleted: the entries it signed stay
    /// verifiable through its public key in the log, and nothing may be
    /// signed with it again.
    pub fn promote_next_key(&self) -> Result<()> {
        fs::remove_file(self.key_path())?;
        fs::rename(self.next_key_path(), self.key_path())?;
        Ok(())
    }
}

/// Refuses a home that another user owns: whoever owns it can replace the
/// key, the tokens and the stores, and a daemon would sign for them.
fn owned_by(root: &Path, uid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = fs::metadata(root)?.uid();
        if owner != uid {
            return Err(Error::Invalid(format!(
                "daemon home {} belongs to uid {owner}, not to this daemon (uid {uid}); \
                 run the daemon as its owner, or give it a home of its own",
                root.display()
            )));
        }
    }
    let _ = (root, uid);
    Ok(())
}

/// What a token stands for. Agent entries predate human sessions and are
/// stored without a tag; the two shapes share no required field, so an
/// untagged enum reads both.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenEntry {
    /// An agent session of one repository. `expires_ms` is the session's
    /// own end, from its log entry; entries written before it was stored
    /// have none, and the log says when they end.
    Agent {
        repo: String,
        session: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_ms: Option<i64>,
    },
    /// A human session (`human.login`): the human proved presence with
    /// `key`, and the session is good wherever that key is enrolled.
    Human {
        human: String,
        key: String,
        expires_ms: i64,
    },
}

/// Session tokens. Only their SHA-256 is stored, never the token itself.
///
/// The file is what a restarted daemon knows, so a change that did not
/// reach it is not done. A token that could not be written is not given
/// out; one that was taken away stays away in memory (the safe side), the
/// caller is told it failed, and the file is written at the next call that
/// takes anything away, whether that one finds something to take or not:
/// asking again is how it gets done.
#[derive(Default)]
pub struct Tokens {
    path: Option<PathBuf>,
    map: BTreeMap<String, TokenEntry>,
    /// Tokens were taken away here that the file may still hold.
    unsaved: bool,
}

impl Tokens {
    pub fn load(path: &Path) -> Result<Self> {
        let map = match fs::read(path) {
            Ok(b) => serde_json::from_slice(&b)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path: Some(path.to_path_buf()),
            map,
            unsaved: false,
        })
    }

    /// A token for an agent session that ends at `expires_ms`.
    pub fn issue(&mut self, repo: &str, session: &str, expires_ms: i64) -> Result<String> {
        self.insert(
            "lonca_",
            TokenEntry::Agent {
                repo: repo.into(),
                session: session.into(),
                expires_ms: Some(expires_ms),
            },
        )
    }

    /// Replaces `old` with a new token for the same session, in one write:
    /// from then on only the new one works. `None` if `old` is unknown.
    ///
    /// If the write fails nothing has changed: the old one still works,
    /// here and after a restart, and the caller holds no other.
    pub fn rotate(&mut self, old: &str) -> Result<Option<String>> {
        let hash = sha256_hex(old.as_bytes());
        let Some(entry) = self.map.remove(&hash) else {
            return Ok(None);
        };
        let prefix = match entry {
            TokenEntry::Agent { .. } => "lonca_",
            TokenEntry::Human { .. } => "lonca_h_",
        };
        match self.insert(prefix, entry.clone()) {
            Ok(new) => Ok(Some(new)),
            Err(e) => {
                self.map.insert(hash, entry);
                Err(e)
            }
        }
    }

    pub fn issue_human(&mut self, human: &str, key: &str, expires_ms: i64) -> Result<String> {
        self.insert(
            "lonca_h_",
            TokenEntry::Human {
                human: human.into(),
                key: key.into(),
                expires_ms,
            },
        )
    }

    fn insert(&mut self, prefix: &str, entry: TokenEntry) -> Result<String> {
        let token = format!("{prefix}{}", hex::encode(random_bytes::<32>()));
        let hash = sha256_hex(token.as_bytes());
        self.map.insert(hash.clone(), entry);
        if let Err(e) = self.save() {
            // Nobody was given it: it is no token.
            self.map.remove(&hash);
            return Err(e);
        }
        Ok(token)
    }

    pub fn lookup(&self, token: &str) -> Option<&TokenEntry> {
        self.map.get(&sha256_hex(token.as_bytes()))
    }

    /// Drops one token (logout). Unknown tokens are not an error.
    pub fn revoke(&mut self, token: &str) -> Result<()> {
        let taken = self.map.remove(&sha256_hex(token.as_bytes())).is_some();
        self.taken(taken)
    }

    /// Writes the file after tokens were taken away, now or at an earlier
    /// call whose write failed.
    fn taken(&mut self, now: bool) -> Result<()> {
        if !now && !self.unsaved {
            return Ok(());
        }
        self.unsaved = true;
        self.save()?;
        self.unsaved = false;
        Ok(())
    }

    pub fn revoke_sessions(&mut self, repo: &str, sessions: &[String]) -> Result<()> {
        let before = self.map.len();
        self.map.retain(|_, e| match e {
            TokenEntry::Agent {
                repo: r, session, ..
            } => !(r == repo && sessions.contains(session)),
            TokenEntry::Human { .. } => true,
        });
        self.taken(self.map.len() != before)
    }

    /// Drops every token that no longer works at `now_ms`: human sessions
    /// past their end, and agent sessions past theirs or that `live` says
    /// are over (ended, expired with a parent, of a repository gone).
    pub fn sweep_expired(&mut self, now_ms: i64, live: impl Fn(&str, &str) -> bool) -> Result<()> {
        let before = self.map.len();
        self.map.retain(|_, e| match e {
            TokenEntry::Agent {
                repo,
                session,
                expires_ms,
            } => expires_ms.is_none_or(|end| end > now_ms) && live(repo, session),
            TokenEntry::Human { expires_ms, .. } => *expires_ms > now_ms,
        });
        self.taken(self.map.len() != before)
    }

    fn save(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let tmp = path.with_extension("tmp");
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(&self.map)?)?;
        f.sync_all()?;
        fs::rename(&tmp, path).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_home_must_belong_to_the_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let home = Home::new(dir.path().join("h"));
        home.ensure().unwrap();
        assert!(owned_by(&home.root, current_uid()).is_ok());
        let e = owned_by(&home.root, current_uid() + 1)
            .unwrap_err()
            .to_string();
        assert!(e.contains("belongs to uid"), "{e}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&home.root).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn tokens_are_stored_as_hashes_and_both_kinds_survive_a_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        // A file written before human sessions existed.
        std::fs::write(
            &path,
            format!(
                "{{\"{}\": {{\"repo\": \"demo\", \"session\": \"s0\"}}}}",
                sha256_hex(b"lonca_old")
            ),
        )
        .unwrap();
        let mut t = Tokens::load(&path).unwrap();
        let a = t.issue("demo", "s1", 5_000).unwrap();
        let h = t.issue_human("ayse", "ab", 2_000).unwrap();
        assert!(a.starts_with("lonca_") && h.starts_with("lonca_h_"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&a) && !text.contains(&h), "{text}");
        let t = Tokens::load(&path).unwrap();
        assert_eq!(
            t.lookup("lonca_old"),
            Some(&TokenEntry::Agent {
                repo: "demo".into(),
                session: "s0".into(),
                expires_ms: None,
            })
        );
        assert_eq!(
            t.lookup(&h),
            Some(&TokenEntry::Human {
                human: "ayse".into(),
                key: "ab".into(),
                expires_ms: 2_000
            })
        );
        let mut t = t;
        t.revoke_sessions("demo", &["s1".into()]).unwrap();
        assert!(t.lookup(&a).is_none() && t.lookup(&h).is_some());
        t.sweep_expired(1_999, |_, _| true).unwrap();
        assert!(t.lookup(&h).is_some());
        t.sweep_expired(2_000, |_, _| true).unwrap();
        assert!(t.lookup(&h).is_none());
        t.revoke("lonca_old").unwrap();
        t.revoke("lonca_old").unwrap();
        assert!(Tokens::load(&path).unwrap().lookup("lonca_old").is_none());
    }

    /// An agent token goes at its session's end, or when the log says the
    /// session is over; one without a stored end only by the log.
    #[test]
    fn a_sweep_drops_agent_tokens_that_no_longer_work() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let mut t = Tokens::load(&path).unwrap();
        let a = t.issue("demo", "s1", 2_000).unwrap();
        let b = t.issue("demo", "s2", 9_000).unwrap();
        t.sweep_expired(1_999, |_, _| true).unwrap();
        assert!(t.lookup(&a).is_some() && t.lookup(&b).is_some());
        t.sweep_expired(2_000, |_, _| true).unwrap();
        assert!(t.lookup(&a).is_none() && t.lookup(&b).is_some());
        t.sweep_expired(2_000, |repo, s| repo == "demo" && s != "s2")
            .unwrap();
        assert!(t.lookup(&b).is_none());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("s1") && !text.contains("s2"), "{text}");
    }

    /// A file that can not be written: its place is taken by a directory.
    fn block(path: &Path) {
        std::fs::create_dir(path.with_extension("tmp")).unwrap();
    }

    fn unblock(path: &Path) {
        std::fs::remove_dir(path.with_extension("tmp")).unwrap();
    }

    #[test]
    fn a_token_taken_away_is_written_when_asked_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let mut t = Tokens::load(&path).unwrap();
        let human = t.issue_human("ayse", "ab", 9_000).unwrap();
        let (a, b) = (
            t.issue("demo", "s1", 9_000).unwrap(),
            t.issue("demo", "s2", 9_000).unwrap(),
        );

        block(&path);
        assert!(t.revoke(&human).is_err(), "the caller hears of it");
        assert!(
            t.lookup(&human).is_none(),
            "and it is gone here all the same"
        );
        assert!(Tokens::load(&path).unwrap().lookup(&human).is_some());
        // Asked again with the file still closed, it fails again.
        assert!(t.revoke(&human).is_err());
        unblock(&path);
        // Asked again, it is done, though there is nothing left to take.
        t.revoke(&human).unwrap();
        assert!(Tokens::load(&path).unwrap().lookup(&human).is_none());

        // The same for sessions, and any later call writes what is owed.
        block(&path);
        assert!(t.revoke_sessions("demo", &["s1".into()]).is_err());
        unblock(&path);
        t.sweep_expired(0, |_, _| true).unwrap();
        let saved = Tokens::load(&path).unwrap();
        assert!(saved.lookup(&a).is_none() && saved.lookup(&b).is_some());
        block(&path);
        assert!(t.sweep_expired(10_000, |_, _| true).is_err());
        unblock(&path);
        t.revoke_sessions("demo", &[]).unwrap();
        assert!(Tokens::load(&path).unwrap().lookup(&b).is_none());
    }

    #[test]
    fn a_token_that_was_not_written_is_no_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let mut t = Tokens::load(&path).unwrap();
        let old = t.issue("demo", "s1", 9_000).unwrap();

        block(&path);
        assert!(t.issue("demo", "s2", 9_000).is_err());
        assert!(t.issue_human("ayse", "ab", 9_000).is_err());
        assert_eq!(t.map.len(), 1, "nothing was kept for them");
        // A rotation that fails leaves the old token working, as the file
        // says and the session knows.
        assert!(t.rotate(&old).is_err());
        assert!(t.lookup(&old).is_some());
        assert_eq!(t.map.len(), 1);
        unblock(&path);
        // Nothing was taken away, so nothing is owed to the file.
        assert!(!t.unsaved);
        let new = t.rotate(&old).unwrap().unwrap();
        let saved = Tokens::load(&path).unwrap();
        assert!(saved.lookup(&old).is_none() && saved.lookup(&new).is_some());
    }

    #[test]
    fn a_rotation_replaces_the_token_in_one_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens.json");
        let mut t = Tokens::load(&path).unwrap();
        let old = t.issue("demo", "s1", 9_000).unwrap();
        let new = t.rotate(&old).unwrap().unwrap();
        assert!(new.starts_with("lonca_") && !new.starts_with("lonca_h_"));
        assert_ne!(new, old);
        let t2 = Tokens::load(&path).unwrap();
        assert!(t2.lookup(&old).is_none());
        assert_eq!(t2.lookup(&new), t.lookup(&new));
        assert!(t.rotate(&old).unwrap().is_none(), "the old one is gone");
        let h = t.issue_human("ayse", "ab", 9_000).unwrap();
        assert!(t.rotate(&h).unwrap().unwrap().starts_with("lonca_h_"));
        t.revoke_sessions("demo", &["s1".into()]).unwrap();
        assert!(
            t.lookup(&new).is_none(),
            "revocation reaches a rotated token"
        );
    }
}
