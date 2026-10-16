//! Verification of human signatures.

use lonca_core::canonical::canonical_bytes;
use lonca_core::keys::verify_hex;
use lonca_core::ops::{HumanIntent, HumanKey, HumanSignature, Op};

/// How far a signature's `issued_ms` may lie from the daemon's clock.
pub const MAX_AGE_MS: i64 = 10 * 60 * 1000;
pub const MAX_SKEW_MS: i64 = 60 * 1000;

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
    let nonce = lonca_core::canonical::random_id("nonce");
    HumanSignature {
        human: human.to_string(),
        sig: key.sign_hex(&intent_bytes(repo, op, &nonce, now_ms)),
        nonce,
        issued_ms: now_ms,
    }
}

pub fn verify(key: &HumanKey, repo: &str, op: &Op, sig: &HumanSignature, now_ms: i64) -> Result<(), &'static str> {
    if sig.issued_ms > now_ms + MAX_SKEW_MS || sig.issued_ms < now_ms - MAX_AGE_MS {
        return Err("stale_human_signature");
    }
    if sig.nonce.len() < 16 || sig.nonce.len() > 128 {
        return Err("bad_nonce");
    }
    let msg = intent_bytes(repo, op, &sig.nonce, sig.issued_ms);
    let ok = match key.alg.as_str() {
        "ed25519" => verify_hex(&key.public, &msg, &sig.sig),
        "p256-se" => crate::human::p256::verify(&key.public, &msg, &sig.sig),
        _ => false,
    };
    if ok { Ok(()) } else { Err("bad_human_signature") }
}

pub mod p256 {
    //! ECDSA P-256 signatures as produced by the Secure Enclave helper:
    //! public key in SEC1 (uncompressed, hex), signature in DER (hex), over
    //! SHA-256 of the message.

    pub fn verify(public_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
        use ::p256::ecdsa::signature::Verifier;
        use ::p256::ecdsa::{Signature, VerifyingKey};
        let Ok(pk) = hex::decode(public_hex) else { return false };
        let Ok(vk) = VerifyingKey::from_sec1_bytes(&pk) else { return false };
        let Ok(sig) = hex::decode(sig_hex) else { return false };
        let Ok(sig) = Signature::from_der(&sig) else { return false };
        vk.verify(msg, &sig).is_ok()
    }
}
