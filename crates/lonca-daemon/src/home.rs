//! The daemon's home directory.
//!
//! ```text
//! $LONCA_HOME/
//!   daemon.key        ed25519 signing key (0600)
//!   daemon.next.key   the key a rotation in progress moves to (0600)
//!   tokens.json       sha256(token) -> agent session or human session (0600)
//!   lonca.sock        Unix socket
//!   repos/<name>.git  bare Git stores
//!   scratch/          verifier work trees
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

    pub fn ensure(&self) -> Result<()> {
        fs::create_dir_all(self.repos())?;
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
        KeyPair::load_or_create(&self.key_path())
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
            Some(KeyPair::load(&next)?)
        } else {
            None
        };
        Ok((current, next))
    }

    /// The next key, created on first use.
    pub fn load_or_create_next_key(&self) -> Result<KeyPair> {
        KeyPair::load_or_create(&self.next_key_path())
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

/// What a token stands for. Agent entries predate human sessions and are
/// stored without a tag; the two shapes share no required field, so an
/// untagged enum reads both.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum TokenEntry {
    /// An agent session of one repository.
    Agent { repo: String, session: String },
    /// A human session (`human.login`): the human proved presence with
    /// `key`, and the session is good wherever that key is enrolled.
    Human {
        human: String,
        key: String,
        expires_ms: i64,
    },
}

/// Session tokens. Only their SHA-256 is stored, never the token itself.
#[derive(Default)]
pub struct Tokens {
    path: Option<PathBuf>,
    map: BTreeMap<String, TokenEntry>,
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
        })
    }

    pub fn issue(&mut self, repo: &str, session: &str) -> Result<String> {
        self.insert(
            "lonca_",
            TokenEntry::Agent {
                repo: repo.into(),
                session: session.into(),
            },
        )
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
        self.map.insert(sha256_hex(token.as_bytes()), entry);
        self.save()?;
        Ok(token)
    }

    pub fn lookup(&self, token: &str) -> Option<&TokenEntry> {
        self.map.get(&sha256_hex(token.as_bytes()))
    }

    /// Drops one token (logout). Unknown tokens are not an error.
    pub fn revoke(&mut self, token: &str) -> Result<()> {
        if self.map.remove(&sha256_hex(token.as_bytes())).is_some() {
            self.save()?;
        }
        Ok(())
    }

    pub fn revoke_sessions(&mut self, repo: &str, sessions: &[String]) -> Result<()> {
        let before = self.map.len();
        self.map.retain(|_, e| match e {
            TokenEntry::Agent { repo: r, session } => !(r == repo && sessions.contains(session)),
            TokenEntry::Human { .. } => true,
        });
        if self.map.len() != before {
            self.save()?;
        }
        Ok(())
    }

    /// Drops human sessions that have expired by `now_ms`.
    pub fn sweep_expired(&mut self, now_ms: i64) -> Result<()> {
        let before = self.map.len();
        self.map.retain(|_, e| match e {
            TokenEntry::Agent { .. } => true,
            TokenEntry::Human { expires_ms, .. } => *expires_ms > now_ms,
        });
        if self.map.len() != before {
            self.save()?;
        }
        Ok(())
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
        let a = t.issue("demo", "s1").unwrap();
        let h = t.issue_human("ayse", "ab", 2_000).unwrap();
        assert!(a.starts_with("lonca_") && h.starts_with("lonca_h_"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains(&a) && !text.contains(&h), "{text}");
        let t = Tokens::load(&path).unwrap();
        assert_eq!(
            t.lookup("lonca_old"),
            Some(&TokenEntry::Agent {
                repo: "demo".into(),
                session: "s0".into()
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
        t.sweep_expired(1_999).unwrap();
        assert!(t.lookup(&h).is_some());
        t.sweep_expired(2_000).unwrap();
        assert!(t.lookup(&h).is_none());
        t.revoke("lonca_old").unwrap();
        t.revoke("lonca_old").unwrap();
        assert!(Tokens::load(&path).unwrap().lookup("lonca_old").is_none());
    }
}
