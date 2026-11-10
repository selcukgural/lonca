//! A human signature made with a FIDO security key: the SSHSIG blob that
//! `ssh-keygen -Y sign` prints, which reaches the daemon in `human.submit`
//! and `human.login` and is read by `lonca_policy::human::sk`.
//!
//! An input is a byte that chooses the kind of key, then the blob. Reading
//! never panics. A blob that reads has one writing: the encoder gives the
//! same bytes back, so one signature can not arrive in two forms. Nothing
//! verifies that does not read, or that the device signed without a touch.
//! The bytes are also read as an OpenSSH public key, with the same rule.

use lonca_policy::human::sk::{self, FLAG_USER_PRESENT, Kind};

use crate::choice;

/// The message the seeds sign.
pub const MESSAGE: &[u8] = b"lonca fuzz";

/// The enrolled key of each kind: the public half of the software key
/// `write_seeds` signs with (seed bytes all 7).
pub const PUBLIC: [(Kind, &str); 2] = [
    (
        Kind::P256,
        "041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc5896e\
         a46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3",
    ),
    (
        Kind::Ed25519,
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
    ),
];

pub fn check(data: &[u8]) {
    let Some((c, blob)) = choice(data) else {
        return;
    };
    let (kind, public_hex) = PUBLIC[usize::from(c) % PUBLIC.len()];
    let public = hex::decode(public_hex).expect("a constant");

    let read = sk::parse(kind, &public, blob);
    if let Some(a) = &read {
        assert_eq!(
            sk::encode(kind, &public, a),
            blob,
            "a signature with two writings"
        );
    }
    let sig = hex::encode(blob);
    let verified = match kind {
        Kind::P256 => sk::verify_p256(public_hex, MESSAGE, &sig),
        Kind::Ed25519 => sk::verify_ed25519(public_hex, MESSAGE, &sig),
    };
    if verified {
        let a = read.expect("verified what it could not read");
        assert_ne!(a.flags & FLAG_USER_PRESENT, 0, "verified without a touch");
    }

    if let Some((kind, public)) = sk::parse_public_blob(blob) {
        assert_eq!(
            sk::public_blob(kind, &public),
            blob,
            "a public key with two writings"
        );
    }
}
