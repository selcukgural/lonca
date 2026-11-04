//! Verification of human signatures.

use lonca_core::canonical::canonical_bytes;
use lonca_core::keys::verify_hex;
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

pub fn verify(
    key: &HumanKey,
    repo: &str,
    op: &Op,
    sig: &HumanSignature,
    now_ms: i64,
) -> Result<(), &'static str> {
    check_fresh(sig, now_ms)?;
    let msg = intent_bytes(repo, op, &sig.nonce, sig.issued_ms);
    verify_bytes(key, &msg, &sig.sig)
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
    verify_bytes(key, &msg, &sig.sig)
}

fn verify_bytes(key: &HumanKey, msg: &[u8], sig_hex: &str) -> Result<(), &'static str> {
    let ok = match key.alg.as_str() {
        "ed25519" => verify_hex(&key.public, msg, sig_hex),
        "p256-se" => crate::human::p256::verify(&key.public, msg, sig_hex),
        _ => false,
    };
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
            verify(&key, "demo", &op, &login, now),
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
}
