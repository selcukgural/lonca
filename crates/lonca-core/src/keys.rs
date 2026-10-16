//! Ed25519 keys for the daemon and for (development) human signers.

use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::canonical::random_bytes;
use crate::error::{Error, Result};

#[derive(Clone)]
pub struct KeyPair {
    sk: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        Self {
            sk: SigningKey::from_bytes(&random_bytes::<32>()),
        }
    }

    pub fn from_secret(bytes: [u8; 32]) -> Self {
        Self {
            sk: SigningKey::from_bytes(&bytes),
        }
    }

    /// Loads the key at `path`, creating it (mode 0600) if it does not exist.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            return Self::load(path);
        }
        let key = Self::generate();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(path)?;
        f.write_all(hex::encode(key.sk.to_bytes()).as_bytes())?;
        Ok(key)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)?;
        let bytes =
            hex::decode(text.trim()).map_err(|e| Error::Invalid(format!("key file: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| Error::Invalid("key file: expected 32 bytes".into()))?;
        Ok(Self::from_secret(arr))
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.sk.verifying_key().to_bytes())
    }

    pub fn sign_hex(&self, msg: &[u8]) -> String {
        hex::encode(self.sk.sign(msg).to_bytes())
    }
}

pub fn verify_hex(public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let Ok(pk) = hex::decode(public_hex) else {
        return false;
    };
    let Ok(pk): Result<[u8; 32], _> = pk.try_into() else {
        return false;
    };
    let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
        return false;
    };
    let Ok(sig) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig): Result<[u8; 64], _> = sig.try_into() else {
        return false;
    };
    vk.verify_strict(msg, &Signature::from_bytes(&sig)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let k = KeyPair::generate();
        let sig = k.sign_hex(b"hello");
        assert!(verify_hex(&k.public_hex(), b"hello", &sig));
        assert!(!verify_hex(&k.public_hex(), b"hellO", &sig));
        assert!(!verify_hex(
            &KeyPair::generate().public_hex(),
            b"hello",
            &sig
        ));
    }

    #[test]
    fn key_file_is_private_and_reloads() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("k/daemon.key");
        let a = KeyPair::load_or_create(&p).unwrap();
        let b = KeyPair::load_or_create(&p).unwrap();
        assert_eq!(a.public_hex(), b.public_hex());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
