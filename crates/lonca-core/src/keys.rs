//! Ed25519 keys for the daemon and for (development) human signers.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::Zeroizing;

use crate::canonical::random_bytes;
use crate::error::{Error, Result};

/// An Ed25519 signing key. Clones share one secret, which is wiped from
/// memory when the last of them is dropped (`SigningKey` zeroizes itself).
#[derive(Clone)]
pub struct KeyPair {
    sk: Arc<SigningKey>,
}

/// Group or other may do anything with the file.
const OTHERS_ANY: u32 = 0o077;

/// Refuses a key file that is not a regular file owned by `uid` and closed
/// to group and others. A key anyone else can read is a key anyone else may
/// have signed with; one owned by someone else was put there by them.
#[cfg(unix)]
pub fn check_private(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = fs::symlink_metadata(path)?;
    let shown = path.display();
    if !meta.file_type().is_file() {
        return Err(Error::Invalid(format!(
            "key file {shown} is not a regular file (a link is not followed)"
        )));
    }
    if meta.uid() != uid {
        return Err(Error::Invalid(format!(
            "key file {shown} belongs to uid {}, not to this process (uid {uid}); \
             a key must be created by the account that uses it",
            meta.uid()
        )));
    }
    let mode = meta.mode() & 0o777;
    if mode & OTHERS_ANY != 0 {
        return Err(Error::Invalid(format!(
            "key file {shown} has mode {mode:o}, so others may read it: run `chmod 600 {shown}` \
             if nobody else could have, or make a new key"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn check_private(_: &Path, _: u32) -> Result<()> {
    Ok(())
}

impl KeyPair {
    pub fn generate() -> Self {
        Self::from_secret(Zeroizing::new(random_bytes::<32>()))
    }

    pub fn from_secret(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self {
            sk: Arc::new(SigningKey::from_bytes(&bytes)),
        }
    }

    /// Loads the key at `path`, creating it (mode 0600) if it does not
    /// exist. An existing file is held to [`check_private`].
    pub fn load_or_create(path: &Path, uid: u32) -> Result<Self> {
        if path.exists() {
            return Self::load(path, uid);
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
        let text = Zeroizing::new(hex::encode(key.sk.to_bytes()));
        f.write_all(text.as_bytes())?;
        Ok(key)
    }

    /// Loads the key at `path`, which must be private to `uid`
    /// ([`check_private`]).
    pub fn load(path: &Path, uid: u32) -> Result<Self> {
        check_private(path, uid)?;
        Self::read(path)
    }

    /// Loads a key from wherever it was kept, a USB stick included, whose
    /// file system may show every file as readable by all: only the owner
    /// is checked. Says whether others may read the file, for a warning.
    #[cfg(unix)]
    pub fn load_carried(path: &Path, uid: u32) -> Result<(Self, bool)> {
        use std::os::unix::fs::MetadataExt;
        let open = match check_private(path, uid) {
            Ok(()) => false,
            Err(e) => {
                let meta = fs::symlink_metadata(path)?;
                if !meta.file_type().is_file() || meta.uid() != uid {
                    return Err(e);
                }
                true
            }
        };
        Ok((Self::read(path)?, open))
    }

    /// The secret, read so that no copy of it outlives this call.
    fn read(path: &Path) -> Result<Self> {
        let text = Zeroizing::new(fs::read_to_string(path)?);
        let bytes = Zeroizing::new(
            hex::decode(text.trim()).map_err(|e| Error::Invalid(format!("key file: {e}")))?,
        );
        let mut arr = Zeroizing::new([0u8; 32]);
        if bytes.len() != arr.len() {
            return Err(Error::Invalid("key file: expected 32 bytes".into()));
        }
        arr.copy_from_slice(&bytes);
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
        let uid = owner(dir.path());
        let a = KeyPair::load_or_create(&p, uid).unwrap();
        let b = KeyPair::load_or_create(&p, uid).unwrap();
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

    #[cfg(unix)]
    fn owner(p: &Path) -> u32 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(p).unwrap().uid()
    }

    /// Mode 0644, a link, another owner: each is refused, and the error
    /// says what to do. A carried key is held to its owner only.
    #[cfg(unix)]
    #[test]
    fn a_key_file_must_be_private_to_its_user() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let uid = owner(dir.path());
        let p = dir.path().join("a.key");
        let key = KeyPair::load_or_create(&p, uid).unwrap();
        assert!(KeyPair::load(&p, uid).is_ok());

        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let e = KeyPair::load(&p, uid).err().unwrap().to_string();
        assert!(e.contains("mode 644") && e.contains("chmod 600"), "{e}");
        assert!(KeyPair::load_or_create(&p, uid).is_err());
        let (carried, open) = KeyPair::load_carried(&p, uid).unwrap();
        assert!(open);
        assert_eq!(carried.public_hex(), key.public_hex());
        fs::set_permissions(&p, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(KeyPair::load(&p, uid).is_err(), "group may read");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o602)).unwrap();
        assert!(KeyPair::load(&p, uid).is_err(), "others may write");
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(KeyPair::load(&p, uid).is_ok(), "read-only to its owner");
        let (_, open) = KeyPair::load_carried(&p, uid).unwrap();
        assert!(!open);

        let e = KeyPair::load(&p, uid + 1).err().unwrap().to_string();
        assert!(e.contains(&format!("belongs to uid {uid}")), "{e}");
        assert!(KeyPair::load_carried(&p, uid + 1).is_err());

        let link = dir.path().join("link.key");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        let e = KeyPair::load(&link, uid).err().unwrap().to_string();
        assert!(e.contains("not a regular file"), "{e}");
        assert!(KeyPair::load_carried(&link, uid).is_err());
    }

    #[test]
    fn clones_share_one_secret() {
        let a = KeyPair::generate();
        let b = a.clone();
        assert!(Arc::ptr_eq(&a.sk, &b.sk));
        assert_eq!(a.sign_hex(b"x"), b.sign_hex(b"x"));
    }

    #[test]
    fn a_key_file_holds_32_bytes_of_hex() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("short.key");
        fs::write(&p, "abcd").unwrap();
        assert!(
            KeyPair::read(&p)
                .err()
                .unwrap()
                .to_string()
                .contains("32 bytes")
        );
        fs::write(&p, "zz").unwrap();
        assert!(KeyPair::read(&p).is_err());
        fs::write(&p, format!("{}\n", "11".repeat(32))).unwrap();
        assert!(KeyPair::read(&p).is_ok());
    }
}
