//! Canonical serialization and hashing.
//!
//! Lonca's canonical form is compact JSON produced by `serde_json` from types
//! whose field order is fixed by their declaration and whose maps are
//! `BTreeMap`s. Lonca types never contain floating point numbers, so the
//! encoding is byte-for-byte reproducible on every machine.

use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn canonical_bytes<T: Serialize + ?Sized>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).expect("lonca types always serialize")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn digest_of<T: Serialize + ?Sized>(value: &T) -> String {
    sha256_hex(&canonical_bytes(value))
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).expect("operating system random source");
    buf
}

/// A random identifier such as `ses_3f9a0c1d2e4b5a69`.
pub fn random_id(prefix: &str) -> String {
    format!("{prefix}_{}", hex::encode(random_bytes::<8>()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn map_order_does_not_depend_on_insertion_order() {
        let mut a = BTreeMap::new();
        a.insert("b", 1);
        a.insert("a", 2);
        let mut b = BTreeMap::new();
        b.insert("a", 2);
        b.insert("b", 1);
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        assert_eq!(digest_of(&a), digest_of(&b));
    }

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
