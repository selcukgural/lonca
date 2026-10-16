//! The daemon's home directory.
//!
//! ```text
//! $LONCA_HOME/
//!   daemon.key        ed25519 signing key (0600)
//!   tokens.json       sha256(session token) -> session (0600)
//!   lonca.sock        Unix socket
//!   repos/<name>.git  bare Git stores
//!   scratch/          verifier work trees
//! ```
//!
//! In hardened mode the directory belongs to a dedicated system user, so
//! agents running as the developer can not read the key or write the stores.

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
}

impl Home {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `$LONCA_HOME`, else `~/.lonca`.
    pub fn from_env() -> Self {
        match std::env::var_os("LONCA_HOME") {
            Some(p) => Self::new(p),
            None => {
                let home = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("."));
                Self::new(home.join(".lonca"))
            }
        }
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
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenEntry {
    pub repo: String,
    pub session: String,
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
        let token = format!("lonca_{}", hex::encode(random_bytes::<32>()));
        self.map.insert(
            sha256_hex(token.as_bytes()),
            TokenEntry {
                repo: repo.into(),
                session: session.into(),
            },
        );
        self.save()?;
        Ok(token)
    }

    pub fn lookup(&self, token: &str) -> Option<&TokenEntry> {
        self.map.get(&sha256_hex(token.as_bytes()))
    }

    pub fn revoke_sessions(&mut self, repo: &str, sessions: &[String]) -> Result<()> {
        let before = self.map.len();
        self.map
            .retain(|_, e| !(e.repo == repo && sessions.contains(&e.session)));
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
