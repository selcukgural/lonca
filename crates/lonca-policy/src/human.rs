//! Verification of human signatures.

use lonca_core::canonical::canonical_bytes;
use lonca_core::keys::verify_hex;
use lonca_core::oplog::{FORMAT_CURRENT, FORMAT_LEGACY, FORMAT_SECURITY_KEYS};
use lonca_core::ops::{HumanIntent, HumanKey, HumanSignature, LoginIntent, Op};

/// How far a signature's `issued_ms` may lie from the daemon's clock.
pub const MAX_AGE_MS: i64 = 10 * 60 * 1000;
pub const MAX_SKEW_MS: i64 = 60 * 1000;
/// Accepted nonce lengths (characters).
pub const NONCE_MIN: usize = 16;
pub const NONCE_MAX: usize = 128;

pub fn intent_bytes(repo: &str, op: &Op, nonce: &str, issued_ms: i64) -> Vec<u8> {
    canonical_bytes(&HumanIntent::new(repo, op, nonce, issued_ms))
}

/// Signs `op` with a file key (development signer: no user presence).
pub fn sign_ed25519(
    key: &lonca_core::keys::KeyPair,
    human: &str,
    repo: &str,
    op: &Op,
    now_ms: i64,
) -> HumanSignature {
    let nonce = lonca_core::canonical::nonce();
    HumanSignature {
        human: human.to_string(),
        sig: key.sign_hex(&intent_bytes(repo, op, &nonce, now_ms)),
        nonce,
        issued_ms: now_ms,
    }
}

/// Verifies the signature on an operation of an entry of log `format`: a
/// kind of key that format does not know verifies nothing.
pub fn verify(
    key: &HumanKey,
    repo: &str,
    op: &Op,
    sig: &HumanSignature,
    now_ms: i64,
    format: u32,
) -> Result<(), &'static str> {
    check_fresh(sig, now_ms)?;
    let msg = intent_bytes(repo, op, &sig.nonce, sig.issued_ms);
    verify_bytes(key, &msg, &sig.sig, format)
}

/// The age and nonce checks every human signature gets, before any key
/// is looked up.
pub fn check_fresh(sig: &HumanSignature, now_ms: i64) -> Result<(), &'static str> {
    if sig.issued_ms > now_ms + MAX_SKEW_MS || sig.issued_ms < now_ms - MAX_AGE_MS {
        return Err("stale_human_signature");
    }
    if sig.nonce.len() < NONCE_MIN || sig.nonce.len() > NONCE_MAX {
        return Err("bad_nonce");
    }
    Ok(())
}

/// What a human signs to open a session: a different purpose string from
/// operation intents, so neither signature can stand in for the other.
pub fn login_bytes(
    repo: Option<&str>,
    human: &str,
    ttl_ms: i64,
    nonce: &str,
    issued_ms: i64,
) -> Vec<u8> {
    canonical_bytes(&LoginIntent::new(repo, human, ttl_ms, nonce, issued_ms))
}

/// Signs a login with a file key (development signer: no user presence).
pub fn sign_login_ed25519(
    key: &lonca_core::keys::KeyPair,
    human: &str,
    repo: Option<&str>,
    ttl_ms: i64,
    now_ms: i64,
) -> HumanSignature {
    let nonce = lonca_core::canonical::nonce();
    HumanSignature {
        human: human.to_string(),
        sig: key.sign_hex(&login_bytes(repo, human, ttl_ms, &nonce, now_ms)),
        nonce,
        issued_ms: now_ms,
    }
}

/// Verifies a login signature against one enrolled key. `sig.human` is
/// the name signed; the caller decides which key that name has.
pub fn verify_login(
    key: &HumanKey,
    repo: Option<&str>,
    ttl_ms: i64,
    sig: &HumanSignature,
    now_ms: i64,
) -> Result<(), &'static str> {
    check_fresh(sig, now_ms)?;
    let msg = login_bytes(repo, &sig.human, ttl_ms, &sig.nonce, sig.issued_ms);
    verify_bytes(key, &msg, &sig.sig, FORMAT_CURRENT)
}

/// A kind of human key: its name in the log, whether a signature made
/// with it proves that a person was there, and the first log format that
/// accepts it.
pub struct Alg {
    pub name: &'static str,
    /// The key lives in hardware that signs only when a person acts
    /// (Touch ID, a touch on a security key). This is what the enrolling
    /// human claims by naming the algorithm: the log can not prove where
    /// a key lives.
    pub presence: bool,
    pub since: u32,
    valid_public: fn(&[u8]) -> bool,
    verify: fn(&str, &[u8], &str) -> bool,
}

/// Every kind of human key. A new kind is a row here (and a log format).
pub const ALGS: &[Alg] = &[
    Alg {
        name: "ed25519",
        presence: false,
        since: FORMAT_LEGACY,
        valid_public: valid_ed25519,
        verify: verify_hex,
    },
    Alg {
        name: "p256-se",
        presence: true,
        since: FORMAT_LEGACY,
        valid_public: valid_p256,
        verify: p256::verify,
    },
    Alg {
        name: sk::P256,
        presence: true,
        since: FORMAT_SECURITY_KEYS,
        valid_public: sk::valid_p256,
        verify: sk::verify_p256,
    },
    Alg {
        name: sk::ED25519,
        presence: true,
        since: FORMAT_SECURITY_KEYS,
        valid_public: valid_ed25519,
        verify: sk::verify_ed25519,
    },
];

/// The kind called `name`, in a log of `format`.
pub fn alg(name: &str, format: u32) -> Option<&'static Alg> {
    ALGS.iter().find(|a| a.name == name && format >= a.since)
}

/// Whether a signature by a key of this kind proves presence.
pub fn proves_presence(name: &str) -> bool {
    ALGS.iter().any(|a| a.name == name && a.presence)
}

/// The names of the kinds that prove presence, for messages.
pub fn presence_algs() -> Vec<&'static str> {
    let with = ALGS.iter().filter(|a| a.presence);
    with.map(|a| a.name).collect()
}

/// A key a human can sign with in a log of `format`: a known kind and a
/// public key in the form that kind uses (lowercase hex).
pub fn valid_key(key: &HumanKey, format: u32) -> bool {
    if key.public != key.public.to_ascii_lowercase() {
        return false;
    }
    let Ok(bytes) = hex::decode(&key.public) else {
        return false;
    };
    alg(&key.alg, format).is_some_and(|a| (a.valid_public)(&bytes))
}

fn valid_ed25519(public: &[u8]) -> bool {
    <[u8; 32]>::try_from(public)
        .ok()
        .is_some_and(|b| ed25519_dalek::VerifyingKey::from_bytes(&b).is_ok())
}

fn valid_p256(public: &[u8]) -> bool {
    ::p256::ecdsa::VerifyingKey::from_sec1_bytes(public).is_ok()
}

fn verify_bytes(
    key: &HumanKey,
    msg: &[u8],
    sig_hex: &str,
    format: u32,
) -> Result<(), &'static str> {
    let ok = alg(&key.alg, format).is_some_and(|a| (a.verify)(&key.public, msg, sig_hex));
    if ok {
        Ok(())
    } else {
        Err("bad_human_signature")
    }
}

pub mod p256 {
    //! ECDSA P-256 signatures as produced by the Secure Enclave helper:
    //! public key in SEC1 (uncompressed, hex), signature in DER (hex), over
    //! SHA-256 of the message.

    pub fn verify(public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
        use ::p256::ecdsa::signature::Verifier;
        use ::p256::ecdsa::{Signature, VerifyingKey};
        let Ok(pk) = hex::decode(public_hex) else {
            return false;
        };
        let Ok(vk) = VerifyingKey::from_sec1_bytes(&pk) else {
            return false;
        };
        let Ok(sig) = hex::decode(sig_hex) else {
            return false;
        };
        let Ok(sig) = Signature::from_der(&sig) else {
            return false;
        };
        vk.verify(msg, &sig).is_ok()
    }
}

pub mod sk {
    //! Signatures made with a FIDO security key through OpenSSH:
    //! `ssh-keygen -t ecdsa-sk|ed25519-sk -O application=ssh:lonca` makes
    //! the key and `ssh-keygen -Y sign -n lonca` signs, with a touch each
    //! time. Lonca only verifies, in pure Rust, so it carries no USB or
    //! FIDO code. The formats are OpenSSH's PROTOCOL.sshsig and
    //! PROTOCOL.u2f.
    //!
    //! A human key of these kinds is the raw public key in hex (SEC1
    //! uncompressed for P-256, 32 bytes for Ed25519). A signature is the
    //! hex of the SSHSIG blob, the bytes inside the armor `ssh-keygen`
    //! prints. Everything in the blob is checked: the key in it is the
    //! enrolled one, made for [`APPLICATION`]; the namespace is
    //! [`NAMESPACE`]; and the authenticator set its "user present" flag
    //! in the data it signed.

    use sha2::{Digest, Sha256, Sha512};

    /// Human key kinds, as written in the log.
    pub const P256: &str = "sk-p256";
    pub const ED25519: &str = "sk-ed25519";
    /// The FIDO application (relying party) the key is made for. A key
    /// made for plain `ssh:` logins does not sign for Lonca, nor this
    /// one for a login.
    pub const APPLICATION: &str = "ssh:lonca";
    /// The SSHSIG namespace of everything a human signs for Lonca; what
    /// is signed says its own purpose (operation or login).
    pub const NAMESPACE: &str = "lonca";
    /// "User present" in the authenticator's flags byte.
    pub const FLAG_USER_PRESENT: u8 = 0x01;

    const MAGIC: &[u8] = b"SSHSIG";
    const VERSION: u32 = 1;
    const KEY_P256: &str = "sk-ecdsa-sha2-nistp256@openssh.com";
    const KEY_ED25519: &str = "sk-ssh-ed25519@openssh.com";
    const CURVE: &str = "nistp256";

    /// Which of the two key types a blob is for.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Kind {
        P256,
        Ed25519,
    }

    impl Kind {
        fn key_type(self) -> &'static str {
            match self {
                Kind::P256 => KEY_P256,
                Kind::Ed25519 => KEY_ED25519,
            }
        }

        /// The human key kind in the log.
        pub fn alg(self) -> &'static str {
            match self {
                Kind::P256 => P256,
                Kind::Ed25519 => ED25519,
            }
        }
    }

    /// The message digest an SSHSIG names.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub enum Hash {
        Sha256,
        Sha512,
    }

    impl Hash {
        fn name(self) -> &'static str {
            match self {
                Hash::Sha256 => "sha256",
                Hash::Sha512 => "sha512",
            }
        }

        fn of(self, msg: &[u8]) -> Vec<u8> {
            match self {
                Hash::Sha256 => Sha256::digest(msg).to_vec(),
                Hash::Sha512 => Sha512::digest(msg).to_vec(),
            }
        }
    }

    /// What the authenticator says about one signature, and the
    /// signature itself (`r || s` for P-256, 64 bytes for both kinds).
    #[derive(Clone, PartialEq, Eq, Debug)]
    pub struct Assertion {
        pub hash: Hash,
        pub flags: u8,
        pub counter: u32,
        pub signature: [u8; 64],
    }

    /// A P-256 public key in the only form accepted here: the 65 bytes
    /// of an uncompressed point, as OpenSSH writes it.
    pub fn valid_p256(public: &[u8]) -> bool {
        public.len() == 65 && ::p256::ecdsa::VerifyingKey::from_sec1_bytes(public).is_ok()
    }

    pub fn verify_p256(public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
        verify(Kind::P256, public_hex, msg, sig_hex)
    }

    pub fn verify_ed25519(public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
        verify(Kind::Ed25519, public_hex, msg, sig_hex)
    }

    fn verify(kind: Kind, public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
        let (Ok(public), Ok(blob)) = (hex::decode(public_hex), hex::decode(sig_hex)) else {
            return false;
        };
        let Some(a) = parse(kind, &public, &blob) else {
            return false;
        };
        if a.flags & FLAG_USER_PRESENT == 0 {
            return false;
        }
        let data = signed_data(msg, a.hash, a.flags, a.counter);
        match kind {
            Kind::P256 => {
                use ::p256::ecdsa::signature::Verifier;
                use ::p256::ecdsa::{Signature, VerifyingKey};
                let Ok(vk) = VerifyingKey::from_sec1_bytes(&public) else {
                    return false;
                };
                let Ok(sig) = Signature::from_slice(&a.signature) else {
                    return false;
                };
                vk.verify(&data, &sig).is_ok()
            }
            Kind::Ed25519 => {
                use ed25519_dalek::{Signature, VerifyingKey};
                let Ok(pk) = <[u8; 32]>::try_from(public.as_slice()) else {
                    return false;
                };
                let Ok(vk) = VerifyingKey::from_bytes(&pk) else {
                    return false;
                };
                vk.verify_strict(&data, &Signature::from_bytes(&a.signature))
                    .is_ok()
            }
        }
    }

    /// The bytes the authenticator signs for `msg`: the application's
    /// hash, its flags and counter, and the hash of what SSHSIG signs.
    pub fn signed_data(msg: &[u8], hash: Hash, flags: u8, counter: u32) -> Vec<u8> {
        let mut tbs = MAGIC.to_vec();
        put(&mut tbs, NAMESPACE.as_bytes());
        put(&mut tbs, b"");
        put(&mut tbs, hash.name().as_bytes());
        put(&mut tbs, &hash.of(msg));
        let mut data = Sha256::digest(APPLICATION.as_bytes()).to_vec();
        data.push(flags);
        data.extend_from_slice(&counter.to_be_bytes());
        data.extend_from_slice(&Sha256::digest(&tbs));
        data
    }

    /// The public key as OpenSSH encodes it (the base64 part of a `.pub`
    /// line, decoded).
    pub fn public_blob(kind: Kind, public: &[u8]) -> Vec<u8> {
        let mut b = vec![];
        put(&mut b, kind.key_type().as_bytes());
        if kind == Kind::P256 {
            put(&mut b, CURVE.as_bytes());
        }
        put(&mut b, public);
        put(&mut b, APPLICATION.as_bytes());
        b
    }

    /// The kind and raw public key in an OpenSSH public key blob, if it
    /// is a security key made for [`APPLICATION`].
    pub fn parse_public_blob(blob: &[u8]) -> Option<(Kind, Vec<u8>)> {
        let mut r = Reader(blob);
        let kind = match r.string()? {
            t if t == KEY_P256.as_bytes() => Kind::P256,
            t if t == KEY_ED25519.as_bytes() => Kind::Ed25519,
            _ => return None,
        };
        if kind == Kind::P256 && r.string()? != CURVE.as_bytes() {
            return None;
        }
        let public = r.string()?.to_vec();
        let app = r.string()?;
        (r.done() && app == APPLICATION.as_bytes()).then_some((kind, public))
    }

    /// The SSHSIG blob for an assertion: the inverse of what `verify`
    /// reads, and what `ssh-keygen -Y sign` prints inside its armor.
    pub fn encode(kind: Kind, public: &[u8], a: &Assertion) -> Vec<u8> {
        let mut inner = vec![];
        match kind {
            Kind::P256 => {
                put(&mut inner, &mpint(&a.signature[..32]));
                put(&mut inner, &mpint(&a.signature[32..]));
            }
            Kind::Ed25519 => inner.extend_from_slice(&a.signature),
        }
        let mut sig = vec![];
        put(&mut sig, kind.key_type().as_bytes());
        put(&mut sig, &inner);
        sig.push(a.flags);
        sig.extend_from_slice(&a.counter.to_be_bytes());

        let mut b = MAGIC.to_vec();
        b.extend_from_slice(&VERSION.to_be_bytes());
        put(&mut b, &public_blob(kind, public));
        put(&mut b, NAMESPACE.as_bytes());
        put(&mut b, b"");
        put(&mut b, a.hash.name().as_bytes());
        put(&mut b, &sig);
        b
    }

    /// Reads an SSHSIG blob made with the enrolled key `public`. `None`
    /// for anything else: another key or application, another namespace,
    /// an unknown hash, a byte too many.
    pub fn parse(kind: Kind, public: &[u8], blob: &[u8]) -> Option<Assertion> {
        let mut r = Reader(blob);
        if r.take(MAGIC.len())? != MAGIC || r.u32()? != VERSION {
            return None;
        }
        if r.string()? != public_blob(kind, public) {
            return None;
        }
        if r.string()? != NAMESPACE.as_bytes() || !r.string()?.is_empty() {
            return None;
        }
        let hash = match r.string()? {
            b"sha256" => Hash::Sha256,
            b"sha512" => Hash::Sha512,
            _ => return None,
        };
        let sig = r.string()?;
        if !r.done() {
            return None;
        }

        let mut r = Reader(sig);
        if r.string()? != kind.key_type().as_bytes() {
            return None;
        }
        let inner = r.string()?;
        let flags = *r.take(1)?.first()?;
        let counter = r.u32()?;
        if !r.done() {
            return None;
        }
        let mut signature = [0u8; 64];
        match kind {
            Kind::P256 => {
                let mut r = Reader(inner);
                let (rr, ss) = (scalar(r.string()?)?, scalar(r.string()?)?);
                if !r.done() {
                    return None;
                }
                signature[..32].copy_from_slice(&rr);
                signature[32..].copy_from_slice(&ss);
            }
            Kind::Ed25519 => signature = inner.try_into().ok()?,
        }
        Some(Assertion {
            hash,
            flags,
            counter,
            signature,
        })
    }

    fn put(out: &mut Vec<u8>, s: &[u8]) {
        // Everything written here is short; a length that did not fit
        // would be written as one no reader accepts.
        let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(s);
    }

    /// A 32-byte scalar as an SSH `mpint`: no leading zeros, and one
    /// zero byte in front when the top bit is set.
    fn mpint(scalar: &[u8]) -> Vec<u8> {
        let first = scalar.iter().position(|b| *b != 0).unwrap_or(scalar.len());
        let digits = scalar.get(first..).unwrap_or_default();
        let mut out = vec![];
        if digits.first().is_some_and(|b| b & 0x80 != 0) {
            out.push(0);
        }
        out.extend_from_slice(digits);
        out
    }

    /// The 32-byte scalar of an `mpint`, which must be written the one
    /// way [`mpint`] writes it: positive and minimal.
    fn scalar(m: &[u8]) -> Option<[u8; 32]> {
        let digits = match m {
            [0, rest @ ..] => rest,
            all => all,
        };
        let mut out = [0u8; 32];
        let pad = 32usize.checked_sub(digits.len())?;
        out.get_mut(pad..)?.copy_from_slice(digits);
        (mpint(&out) == m).then_some(out)
    }

    struct Reader<'a>(&'a [u8]);

    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Option<&'a [u8]> {
            if self.0.len() < n {
                return None;
            }
            let (head, rest) = self.0.split_at(n);
            self.0 = rest;
            Some(head)
        }

        fn u32(&mut self) -> Option<u32> {
            Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
        }

        fn string(&mut self) -> Option<&'a [u8]> {
            let n = self.u32()?;
            self.take(usize::try_from(n).ok()?)
        }

        fn done(&self) -> bool {
            self.0.is_empty()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_login_signature_is_not_an_operation_signature() {
        let kp = lonca_core::keys::KeyPair::generate();
        let key = HumanKey {
            alg: "ed25519".into(),
            public: kp.public_hex(),
        };
        let now = 1_760_000_000_000;
        let login = sign_login_ed25519(&kp, "ayse", Some("demo"), 3_600_000, now);
        assert_eq!(
            verify_login(&key, Some("demo"), 3_600_000, &login, now),
            Ok(())
        );
        // Every field is bound: repo, ttl, name, and the purpose string.
        assert!(verify_login(&key, None, 3_600_000, &login, now).is_err());
        assert!(verify_login(&key, Some("demo"), 3_600_001, &login, now).is_err());
        let mut renamed = login.clone();
        renamed.human = "bora".into();
        assert!(verify_login(&key, Some("demo"), 3_600_000, &renamed, now).is_err());
        let op = Op::Freeze { reason: "x".into() };
        assert_eq!(
            verify(&key, "demo", &op, &login, now, FORMAT_CURRENT),
            Err("bad_human_signature")
        );
        let signed = sign_ed25519(&kp, "ayse", "demo", &op, now);
        assert_eq!(
            verify_login(&key, Some("demo"), 3_600_000, &signed, now),
            Err("bad_human_signature")
        );
        // Freshness is checked before the key.
        assert_eq!(
            verify_login(&key, Some("demo"), 3_600_000, &login, now + MAX_AGE_MS + 1),
            Err("stale_human_signature")
        );
        let mut short = login.clone();
        while short.nonce.len() >= NONCE_MIN {
            short.nonce.pop();
        }
        assert_eq!(
            verify_login(&key, Some("demo"), 3_600_000, &short, now),
            Err("bad_nonce")
        );
        let unknown = HumanKey {
            alg: "rsa".into(),
            public: kp.public_hex(),
        };
        assert_eq!(
            verify_login(&unknown, Some("demo"), 3_600_000, &login, now),
            Err("bad_human_signature")
        );
    }

    /// Freshness at its edges: exactly MAX_AGE old is fresh, one more
    /// millisecond is stale; exactly MAX_SKEW ahead is fresh, one more is
    /// stale; the nonce bounds are inclusive.
    #[test]
    fn freshness_boundaries() {
        let now = 1_760_000_000_000;
        let sig = |issued_ms: i64, nonce_len: usize| HumanSignature {
            human: "ayse".into(),
            nonce: "n".repeat(nonce_len),
            issued_ms,
            sig: String::new(),
        };
        assert_eq!(check_fresh(&sig(now - MAX_AGE_MS, 16), now), Ok(()));
        assert_eq!(
            check_fresh(&sig(now - MAX_AGE_MS - 1, 16), now),
            Err("stale_human_signature")
        );
        assert_eq!(check_fresh(&sig(now + MAX_SKEW_MS, 16), now), Ok(()));
        assert_eq!(
            check_fresh(&sig(now + MAX_SKEW_MS + 1, 16), now),
            Err("stale_human_signature")
        );
        assert_eq!(check_fresh(&sig(now, NONCE_MIN), now), Ok(()));
        assert_eq!(check_fresh(&sig(now, NONCE_MIN - 1), now), Err("bad_nonce"));
        assert_eq!(check_fresh(&sig(now, NONCE_MAX), now), Ok(()));
        assert_eq!(check_fresh(&sig(now, NONCE_MAX + 1), now), Err("bad_nonce"));
        assert_eq!((MAX_AGE_MS, MAX_SKEW_MS), (600_000, 60_000));
    }

    #[test]
    fn p256_software_key_round_trip() {
        use ::p256::ecdsa::signature::Signer;
        use ::p256::ecdsa::{Signature, SigningKey};
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let pk = hex::encode(sk.verifying_key().to_sec1_point(false).as_bytes());
        let msg = b"lonca";
        let sig: Signature = sk.sign(msg);
        let der = hex::encode(sig.to_der().as_bytes());
        assert!(p256::verify(&pk, msg, &der));
        assert!(!p256::verify(&pk, b"other", &der));
    }

    /// Cross-check with a signature made by a real Secure Enclave key
    /// (`LONCA_SE_CHECK=<file with pub hex and DER sig hex lines>`).
    #[test]
    fn p256_secure_enclave_format() {
        let Ok(path) = std::env::var("LONCA_SE_CHECK") else {
            return;
        };
        let text = std::fs::read_to_string(path).unwrap();
        let mut lines = text.lines();
        let (pk, sig) = (lines.next().unwrap(), lines.next().unwrap());
        assert!(p256::verify(pk, b"lonca secure enclave format check", sig));
        assert!(!p256::verify(pk, b"tampered", sig));
    }

    mod sk_keys {
        use super::super::sk::{self, Assertion, Hash, Kind};
        use super::super::*;

        const MSG: &[u8] = b"lonca security key format check";

        /// A software key standing in for the authenticator: the format
        /// is what is tested, and a real device signs the same bytes.
        type Sign = Box<dyn Fn(&[u8]) -> [u8; 64]>;

        fn soft(kind: Kind) -> (Vec<u8>, Sign) {
            match kind {
                Kind::P256 => {
                    use ::p256::ecdsa::signature::Signer;
                    use ::p256::ecdsa::{Signature, SigningKey};
                    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
                    let public = key.verifying_key().to_sec1_point(false).as_bytes().to_vec();
                    let sign = move |data: &[u8]| {
                        let sig: Signature = key.sign(data);
                        <[u8; 64]>::try_from(&sig.to_bytes()[..]).unwrap()
                    };
                    (public, Box::new(sign))
                }
                Kind::Ed25519 => {
                    use ed25519_dalek::{Signer, SigningKey};
                    let key = SigningKey::from_bytes(&[7u8; 32]);
                    let public = key.verifying_key().to_bytes().to_vec();
                    (
                        public,
                        Box::new(move |data: &[u8]| key.sign(data).to_bytes()),
                    )
                }
            }
        }

        fn assertion(kind: Kind, msg: &[u8], hash: Hash, flags: u8, counter: u32) -> Assertion {
            let signature = soft(kind).1(&sk::signed_data(msg, hash, flags, counter));
            Assertion {
                hash,
                flags,
                counter,
                signature,
            }
        }

        fn blob(kind: Kind, a: &Assertion) -> Vec<u8> {
            sk::encode(kind, &soft(kind).0, a)
        }

        fn accepts(kind: Kind, msg: &[u8], blob: &[u8]) -> bool {
            let key = HumanKey {
                alg: kind.alg().into(),
                public: hex::encode(soft(kind).0),
            };
            verify_bytes(&key, msg, &hex::encode(blob), FORMAT_SECURITY_KEYS).is_ok()
        }

        const KINDS: [Kind; 2] = [Kind::P256, Kind::Ed25519];

        #[test]
        fn a_touch_signs_and_nothing_else_does() {
            for kind in KINDS {
                for hash in [Hash::Sha256, Hash::Sha512] {
                    let a = assertion(kind, MSG, hash, 0x01, 42);
                    let good = blob(kind, &a);
                    assert!(accepts(kind, MSG, &good), "{kind:?} {hash:?}");
                    assert!(!accepts(kind, b"another message", &good));
                    assert_eq!(sk::parse(kind, &soft(kind).0, &good), Some(a.clone()));

                    // The counter and the flags are part of what is signed.
                    let other = |flags, counter| Assertion {
                        flags,
                        counter,
                        ..a.clone()
                    };
                    assert!(!accepts(kind, MSG, &blob(kind, &other(0x01, 43))));
                    assert!(!accepts(kind, MSG, &blob(kind, &other(0x05, 42))));
                    // So is the hash the blob names.
                    let renamed = Assertion {
                        hash: match hash {
                            Hash::Sha256 => Hash::Sha512,
                            Hash::Sha512 => Hash::Sha256,
                        },
                        ..a.clone()
                    };
                    assert!(!accepts(kind, MSG, &blob(kind, &renamed)));
                }
                // Touched and verified with a PIN: present too.
                let pin = assertion(kind, MSG, Hash::Sha512, 0x05, 7);
                assert!(accepts(kind, MSG, &blob(kind, &pin)));
                // A key made with `no-touch-required` signs without the
                // flag: a good signature, and no presence.
                for flags in [0x00, 0x04, 0xfe] {
                    let absent = assertion(kind, MSG, Hash::Sha512, flags, 7);
                    assert!(!accepts(kind, MSG, &blob(kind, &absent)), "{flags:#x}");
                }
            }
        }

        #[test]
        fn one_kind_of_key_does_not_sign_for_another() {
            let good = blob(Kind::P256, &assertion(Kind::P256, MSG, Hash::Sha512, 1, 1));
            for (alg, public) in [
                (sk::ED25519, soft(Kind::Ed25519).0),
                (sk::ED25519, soft(Kind::P256).0),
                ("p256-se", soft(Kind::P256).0),
                ("ed25519", soft(Kind::Ed25519).0),
            ] {
                let key = HumanKey {
                    alg: alg.into(),
                    public: hex::encode(public),
                };
                let r = verify_bytes(&key, MSG, &hex::encode(&good), FORMAT_SECURITY_KEYS);
                assert_eq!(r, Err("bad_human_signature"), "{alg}");
            }
            // A Secure Enclave signature is not a security key signature.
            use ::p256::ecdsa::signature::Signer;
            let se = ::p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
            let der: ::p256::ecdsa::Signature = se.sign(MSG);
            assert!(!accepts(Kind::P256, MSG, der.to_der().as_bytes()));
            // Before format 28 the kind does not exist.
            let key = HumanKey {
                alg: sk::P256.into(),
                public: hex::encode(soft(Kind::P256).0),
            };
            let sig = hex::encode(&good);
            assert_eq!(verify_bytes(&key, MSG, &sig, FORMAT_SECURITY_KEYS), Ok(()));
            assert!(verify_bytes(&key, MSG, &sig, FORMAT_SECURITY_KEYS - 1).is_err());
            assert!(!sk::verify_p256("zz", MSG, &sig));
            assert!(!sk::verify_p256(&key.public, MSG, "zz"));
        }

        /// Appends `s` as an SSH string.
        fn put(out: &mut Vec<u8>, s: &[u8]) {
            out.extend_from_slice(&u32::try_from(s.len()).unwrap().to_be_bytes());
            out.extend_from_slice(s);
        }

        /// The parts of a blob, to build wrong ones from.
        struct Parts {
            version: u32,
            key_type: Vec<u8>,
            curve: Vec<u8>,
            public: Vec<u8>,
            application: Vec<u8>,
            namespace: Vec<u8>,
            reserved: Vec<u8>,
            hash: Vec<u8>,
            sig_type: Vec<u8>,
            inner: Vec<u8>,
            flags: u8,
            counter: u32,
            key_tail: Vec<u8>,
            sig_tail: Vec<u8>,
            tail: Vec<u8>,
        }

        impl Parts {
            fn of(kind: Kind) -> Self {
                let a = assertion(kind, MSG, Hash::Sha512, 1, 9);
                let mut inner = vec![];
                let (key_type, curve) = match kind {
                    Kind::P256 => {
                        // Top bits set in both halves would need a zero in
                        // front; these are written as the encoder does.
                        for half in [&a.signature[..32], &a.signature[32..]] {
                            let mut m = half.to_vec();
                            if m[0] & 0x80 != 0 {
                                m.insert(0, 0);
                            }
                            while m.len() > 1 && m[0] == 0 && m[1] & 0x80 == 0 {
                                m.remove(0);
                            }
                            put(&mut inner, &m);
                        }
                        ("sk-ecdsa-sha2-nistp256@openssh.com", "nistp256")
                    }
                    Kind::Ed25519 => {
                        inner = a.signature.to_vec();
                        ("sk-ssh-ed25519@openssh.com", "")
                    }
                };
                Parts {
                    version: 1,
                    key_type: key_type.into(),
                    curve: curve.into(),
                    public: soft(kind).0,
                    application: b"ssh:lonca".to_vec(),
                    namespace: b"lonca".to_vec(),
                    reserved: vec![],
                    hash: b"sha512".to_vec(),
                    sig_type: key_type.into(),
                    inner,
                    flags: 1,
                    counter: 9,
                    key_tail: vec![],
                    sig_tail: vec![],
                    tail: vec![],
                }
            }

            fn blob(&self) -> Vec<u8> {
                let mut key = vec![];
                put(&mut key, &self.key_type);
                if !self.curve.is_empty() {
                    put(&mut key, &self.curve);
                }
                put(&mut key, &self.public);
                put(&mut key, &self.application);
                key.extend_from_slice(&self.key_tail);
                let mut sig = vec![];
                put(&mut sig, &self.sig_type);
                put(&mut sig, &self.inner);
                sig.push(self.flags);
                sig.extend_from_slice(&self.counter.to_be_bytes());
                sig.extend_from_slice(&self.sig_tail);
                let mut b = b"SSHSIG".to_vec();
                b.extend_from_slice(&self.version.to_be_bytes());
                put(&mut b, &key);
                put(&mut b, &self.namespace);
                put(&mut b, &self.reserved);
                put(&mut b, &self.hash);
                put(&mut b, &sig);
                b.extend_from_slice(&self.tail);
                b
            }
        }

        /// The blob is built here field by field, from the OpenSSH
        /// documents and not from the encoder under test; each field
        /// changed alone is refused.
        #[test]
        fn every_field_of_the_blob_is_checked() {
            for kind in KINDS {
                let good = Parts::of(kind);
                assert!(accepts(kind, MSG, &good.blob()), "{kind:?}");
                let a = assertion(kind, MSG, Hash::Sha512, 1, 9);
                assert_eq!(good.blob(), blob(kind, &a), "{kind:?}: the encoder agrees");

                type Edit = fn(&mut Parts);
                let edits: &[(&str, Edit)] = &[
                    ("version", |p| p.version = 2),
                    ("version 0", |p| p.version = 0),
                    ("namespace", |p| p.namespace = b"file".to_vec()),
                    ("no namespace", |p| p.namespace.clear()),
                    ("reserved", |p| p.reserved = b"x".to_vec()),
                    ("hash", |p| p.hash = b"sha1".to_vec()),
                    ("application", |p| p.application = b"ssh:".to_vec()),
                    ("key type", |p| p.key_type = b"ssh-ed25519".to_vec()),
                    ("signature type", |p| p.sig_type = b"ssh-ed25519".to_vec()),
                    ("another key", |p| *p.public.last_mut().unwrap() ^= 1),
                    ("flags", |p| p.flags = 0),
                    ("counter", |p| p.counter += 1),
                    ("after the key", |p| p.key_tail = vec![0]),
                    ("after the signature", |p| p.sig_tail = vec![0]),
                    ("after the blob", |p| p.tail = vec![0]),
                    ("inside the signature", |p| p.inner.push(0)),
                    ("a short signature", |p| {
                        p.inner.pop();
                    }),
                    ("an empty signature", |p| p.inner.clear()),
                ];
                for (what, edit) in edits {
                    let mut p = Parts::of(kind);
                    edit(&mut p);
                    assert!(!accepts(kind, MSG, &p.blob()), "{kind:?}: {what}");
                }
                // Cut anywhere, it is not read past its end.
                let whole = good.blob();
                for n in 0..whole.len() {
                    assert!(!accepts(kind, MSG, &whole[..n]), "{kind:?}: {n} bytes");
                }
                let mut magic = whole.clone();
                magic[0] = b's';
                assert!(!accepts(kind, MSG, &magic));
            }
            let mut p = Parts::of(Kind::P256);
            p.curve = b"nistp384".to_vec();
            assert!(!accepts(Kind::P256, MSG, &p.blob()));
        }

        /// `r` and `s` are SSH mpints: written one way only.
        #[test]
        fn scalars_are_minimal_positive_mpints() {
            let kind = Kind::P256;
            let public = soft(kind).0;
            let with = |r: &[u8], s: &[u8]| {
                let mut p = Parts::of(kind);
                p.inner.clear();
                put(&mut p.inner, r);
                put(&mut p.inner, s);
                sk::parse(kind, &public, &p.blob()).map(|a| a.signature)
            };
            let mut want = [0u8; 64];
            want[31] = 1;
            want[63] = 2;
            assert_eq!(with(&[1], &[2]), Some(want));
            // A top bit needs the zero in front, and gets only that one.
            want[31] = 0x80;
            assert_eq!(with(&[0, 0x80], &[2]), Some(want));
            assert_eq!(with(&[0x80], &[2]), None, "negative");
            assert_eq!(with(&[0, 1], &[2]), None, "a zero too many");
            assert_eq!(with(&[0, 0, 0x80], &[2]), None);
            assert_eq!(with(&[1], &[0, 2]), None);
            // Full width: 32 bytes, or 33 with the zero.
            let full = [0x7f; 32];
            let mut high = vec![0];
            high.extend_from_slice(&[0xff; 32]);
            let got = with(&full, &high).expect("full width");
            assert_eq!((&got[..32], &got[32..]), (&full[..], &[0xff; 32][..]));
            assert_eq!(with(&[0x7f; 33], &[2]), None, "too long");
            let mut long = vec![0];
            long.extend_from_slice(&[0xff; 33]);
            assert_eq!(with(&long, &[2]), None, "too long");
            // Zero is the empty mpint.
            want[31] = 0;
            assert_eq!(with(&[], &[2]), Some(want));
            assert_eq!(with(&[0], &[2]), None);
            // Low scalars survive the round trip through the encoder.
            let mut a = assertion(kind, MSG, Hash::Sha256, 1, 1);
            a.signature = [0; 64];
            a.signature[31] = 0x80;
            a.signature[62] = 1;
            let b = sk::encode(kind, &public, &a);
            assert_eq!(sk::parse(kind, &public, &b), Some(a));
        }

        #[test]
        fn public_keys_have_one_form_each() {
            let key = |alg: &str, public: &[u8]| HumanKey {
                alg: alg.into(),
                public: hex::encode(public),
            };
            let now = FORMAT_SECURITY_KEYS;
            let point = soft(Kind::P256).0;
            let ed = soft(Kind::Ed25519).0;
            assert!(valid_key(&key(sk::P256, &point), now));
            assert!(valid_key(&key(sk::ED25519, &ed), now));
            assert!(valid_key(&key("p256-se", &point), now));
            assert!(valid_key(&key("ed25519", &ed), now));
            // The compressed point a Secure Enclave key may use is not
            // what OpenSSH writes.
            use ::p256::ecdsa::SigningKey;
            let sk7 = SigningKey::from_slice(&[7u8; 32]).unwrap();
            let compressed = sk7.verifying_key().to_sec1_point(true).as_bytes().to_vec();
            assert_eq!(compressed.len(), 33);
            assert!(valid_key(&key("p256-se", &compressed), now));
            assert!(!valid_key(&key(sk::P256, &compressed), now));
            assert!(!sk::valid_p256(&[4u8; 65]), "not on the curve");
            assert!(!valid_key(&key(sk::P256, &ed), now));
            assert!(!valid_key(&key(sk::ED25519, &point), now));
            assert!(!valid_key(&key("ed25519", &point), now));
            assert!(!valid_key(&key("p256-se", &ed), now));
            assert!(!valid_key(&key("rsa", &ed), now));
            // Lowercase hex only.
            let mut upper = key(sk::ED25519, &ed);
            upper.public = upper.public.to_ascii_uppercase();
            assert_ne!(upper.public, hex::encode(&ed));
            assert!(!valid_key(&upper, now));
            upper.public = "zz".into();
            assert!(!valid_key(&upper, now));

            // The kinds of format 28 do not exist before it.
            for (alg, public) in [(sk::P256, &point), (sk::ED25519, &ed)] {
                assert!(!valid_key(&key(alg, public), now - 1), "{alg}");
                assert!(super::super::alg(alg, now - 1).is_none());
                assert!(super::super::alg(alg, now).is_some());
                assert!(super::super::alg(alg, now + 1).is_some());
            }
            assert!(valid_key(&key("ed25519", &ed), FORMAT_LEGACY));
            assert!(valid_key(&key("p256-se", &point), FORMAT_LEGACY));
            assert!(super::super::alg("rsa", now).is_none());

            assert_eq!(presence_algs(), ["p256-se", "sk-p256", "sk-ed25519"]);
            for alg in presence_algs() {
                assert!(proves_presence(alg));
            }
            assert!(!proves_presence("ed25519"));
            assert!(!proves_presence("rsa"));
            assert_eq!((FORMAT_SECURITY_KEYS, FORMAT_CURRENT), (28, 28));
        }

        #[test]
        fn public_key_blobs_round_trip() {
            for kind in KINDS {
                let public = soft(kind).0;
                let blob = sk::public_blob(kind, &public);
                assert_eq!(sk::parse_public_blob(&blob), Some((kind, public.clone())));
                let p = Parts::of(kind);
                let mut by_hand = vec![];
                put(&mut by_hand, &p.key_type);
                if kind == Kind::P256 {
                    put(&mut by_hand, b"nistp256");
                }
                put(&mut by_hand, &public);
                put(&mut by_hand, b"ssh:lonca");
                assert_eq!(blob, by_hand);
                let mut more = blob.clone();
                more.push(0);
                assert_eq!(sk::parse_public_blob(&more), None);
                assert_eq!(sk::parse_public_blob(&blob[..blob.len() - 1]), None);
                // A key made for ssh logins.
                let n = blob.len() - "ssh:lonca".len() - 4;
                let mut login = blob[..n].to_vec();
                put(&mut login, b"ssh:");
                assert_eq!(sk::parse_public_blob(&login), None);
            }
            let mut plain = vec![];
            put(&mut plain, b"ssh-ed25519");
            put(&mut plain, &[7u8; 32]);
            assert_eq!(sk::parse_public_blob(&plain), None);
            // Another type of key in the shape of a security key.
            put(&mut plain, b"ssh:lonca");
            assert_eq!(sk::parse_public_blob(&plain), None);
            let mut curve = vec![];
            put(&mut curve, b"sk-ecdsa-sha2-nistp256@openssh.com");
            put(&mut curve, b"nistp384");
            put(&mut curve, &soft(Kind::P256).0);
            put(&mut curve, b"ssh:lonca");
            assert_eq!(sk::parse_public_blob(&curve), None);
            assert_eq!(
                (Kind::P256.alg(), Kind::Ed25519.alg()),
                ("sk-p256", "sk-ed25519")
            );
        }

        /// Pinned bytes: these two signatures were accepted by OpenSSH
        /// 10.5 (`ssh-keygen -Y verify`), and must verify for ever.
        #[test]
        fn pinned_vectors_verify() {
            for (kind, public, sig) in [
                (Kind::P256, PINNED_P256.0, PINNED_P256.1),
                (Kind::Ed25519, PINNED_ED25519.0, PINNED_ED25519.1),
            ] {
                assert_eq!(hex::encode(soft(kind).0), public);
                let a = assertion(kind, MSG, Hash::Sha512, 1, 42);
                assert_eq!(hex::encode(blob(kind, &a)), sig, "{kind:?}");
                assert!(accepts(kind, MSG, &hex::decode(sig).unwrap()));
            }
        }

        const PINNED_P256: (&str, &str) = (
            "041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3",
            "535348534947000000010000008400000022736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d000000086e6973747032353600000041041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3000000097373683a6c6f6e6361000000056c6f6e636100000000000000067368613531320000007900000022736b2d65636473612d736861322d6e69737470323536406f70656e7373682e636f6d0000004a0000002100b88bd83aa38f08f74b402b851b086954279343ba1c2194f404ea49c217e894cc00000021008c420a324cfc4bde41343888f82cac0d0ac81bf7b765e932ebabc666e0dead7c010000002a",
        );
        const PINNED_ED25519: (&str, &str) = (
            "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
            "535348534947000000010000004f0000001a736b2d7373682d65643235353139406f70656e7373682e636f6d00000020ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c000000097373683a6c6f6e6361000000056c6f6e63610000000000000006736861353132000000670000001a736b2d7373682d65643235353139406f70656e7373682e636f6d000000401cc02a6bb1061449c767abc90c72de21e2f120e277f74fe1b08a9b3323491154e1ef6c5306aa427aa4a82836264deaafe7704cb525e2d7d2c1aec03050a09109010000002a",
        );

        fn armor(blob: &[u8]) -> String {
            use base64::Engine;
            let b64 = base64::engine::general_purpose::STANDARD.encode(blob);
            let lines: Vec<&str> = b64
                .as_bytes()
                .chunks(70)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect();
            format!(
                "-----BEGIN SSH SIGNATURE-----\n{}\n-----END SSH SIGNATURE-----\n",
                lines.join("\n")
            )
        }

        /// What `ssh-keygen -Y verify` says about a blob, or `None` where
        /// there is no ssh-keygen.
        fn openssh_accepts(kind: Kind, msg: &[u8], blob: &[u8]) -> Option<bool> {
            use base64::Engine;
            use std::io::Write;
            use std::process::{Command, Stdio};
            let dir = tempfile::tempdir().unwrap();
            let key_type = match kind {
                Kind::P256 => "sk-ecdsa-sha2-nistp256@openssh.com",
                Kind::Ed25519 => "sk-ssh-ed25519@openssh.com",
            };
            let public = base64::engine::general_purpose::STANDARD
                .encode(sk::public_blob(kind, &soft(kind).0));
            let signers = dir.path().join("signers");
            std::fs::write(&signers, format!("ayse {key_type} {public}\n")).unwrap();
            let sig = dir.path().join("sig");
            std::fs::write(&sig, armor(blob)).unwrap();
            let mut child = Command::new("ssh-keygen")
                .args(["-Y", "verify", "-I", "ayse", "-n", sk::NAMESPACE, "-f"])
                .arg(&signers)
                .arg("-s")
                .arg(&sig)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .ok()?;
            child.stdin.take().unwrap().write_all(msg).unwrap();
            Some(child.wait().unwrap().success())
        }

        /// OpenSSH is the other implementation of this format: where it
        /// is installed, it and this verifier agree on what is signed.
        #[test]
        fn openssh_agrees() {
            let mut checked = 0;
            for kind in KINDS {
                let good = |hash| blob(kind, &assertion(kind, MSG, hash, 1, 42));
                // Without the touch the signature is still a good one, and
                // that is all `-Y verify` asks; presence is Lonca's rule.
                let untouched = blob(kind, &assertion(kind, MSG, Hash::Sha512, 0, 42));
                let other: &[u8] = b"another message";
                for (what, msg, b, ours, theirs) in [
                    ("sha512", MSG, good(Hash::Sha512), true, true),
                    ("sha256", MSG, good(Hash::Sha256), true, true),
                    ("another message", other, good(Hash::Sha512), false, false),
                    ("no touch", MSG, untouched, false, true),
                ] {
                    assert_eq!(accepts(kind, msg, &b), ours, "{kind:?} {what}");
                    let Some(openssh) = openssh_accepts(kind, msg, &b) else {
                        eprintln!("no ssh-keygen: OpenSSH not asked");
                        return;
                    };
                    assert_eq!(openssh, theirs, "ssh-keygen: {kind:?} {what}");
                    checked += 1;
                }
            }
            assert_eq!(checked, 8);
        }

        /// Cross-check with a real security key (`LONCA_SK_CHECK=<dir>`):
        ///
        /// ```sh
        /// ssh-keygen -t ecdsa-sk -O application=ssh:lonca -N "" -f $dir/key
        /// printf 'lonca security key format check' > $dir/message
        /// ssh-keygen -Y sign -f $dir/key -n lonca $dir/message
        /// ```
        #[test]
        fn a_real_security_key() {
            use base64::Engine;
            let Ok(dir) = std::env::var("LONCA_SK_CHECK") else {
                return;
            };
            let dir = std::path::Path::new(&dir);
            let b64 = |s: &str| base64::engine::general_purpose::STANDARD.decode(s).unwrap();
            let line = std::fs::read_to_string(dir.join("key.pub")).unwrap();
            let blob = b64(line.split_whitespace().nth(1).unwrap());
            let (kind, public) = sk::parse_public_blob(&blob).expect("a key for ssh:lonca");
            let armored = std::fs::read_to_string(dir.join("message.sig")).unwrap();
            let body: String = armored
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect();
            let key = HumanKey {
                alg: kind.alg().into(),
                public: hex::encode(public),
            };
            let sig = hex::encode(b64(&body));
            let msg = std::fs::read(dir.join("message")).unwrap();
            assert!(valid_key(&key, FORMAT_SECURITY_KEYS));
            assert_eq!(verify_bytes(&key, &msg, &sig, FORMAT_SECURITY_KEYS), Ok(()));
            assert!(verify_bytes(&key, b"tampered", &sig, FORMAT_SECURITY_KEYS).is_err());
        }
    }
}
