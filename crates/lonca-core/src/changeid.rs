//! Stable change identifiers.
//!
//! A change keeps its id while its commit is rebased by the merge queue. The
//! encoding matches Jujutsu's: 16 bytes written as "reverse hex" (digits
//! `z`..`k`) in a `change-id` commit header, so jj users see the same ids.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::canonical::random_bytes;

pub const CHANGE_ID_HEADER: &str = "change-id";
const REVERSE_HEX: &[u8; 16] = b"zyxwvutsrqponmlk";

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChangeId(pub [u8; 16]);

impl ChangeId {
    pub fn random() -> Self {
        Self(random_bytes())
    }

    pub fn to_reverse_hex(&self) -> String {
        let mut out = String::with_capacity(32);
        for b in self.0 {
            for nibble in [b >> 4, b & 0x0f] {
                if let Some(&c) = REVERSE_HEX.get(usize::from(nibble)) {
                    out.push(char::from(c));
                }
            }
        }
        out
    }

    pub fn from_reverse_hex(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        let (pairs, _) = bytes.as_chunks::<2>();
        for (slot, &[high, low]) in out.iter_mut().zip(pairs) {
            *slot = (value(high)? << 4) | value(low)?;
        }
        Some(Self(out))
    }

    pub fn short(&self) -> String {
        self.to_reverse_hex()[..12].to_string()
    }

    /// Whether this id starts with `prefix` (reverse hex, as people see it).
    pub fn starts_with(&self, prefix: &str) -> bool {
        self.to_reverse_hex().starts_with(prefix)
    }
}

/// The fewest letters a change id prefix may have.
pub const MIN_PREFIX: usize = 4;

/// Whether `s` can be the start of a change id a person typed: at least
/// [`MIN_PREFIX`] and at most 32 letters, all of the reverse-hex alphabet.
pub fn is_prefix(s: &str) -> bool {
    (MIN_PREFIX..=32).contains(&s.len()) && s.bytes().all(|c| value(c).is_some())
}

fn value(c: u8) -> Option<u8> {
    match c {
        b'k'..=b'z' => Some(b'z' - c),
        _ => None,
    }
}

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_reverse_hex())
    }
}

impl fmt::Debug for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChangeId({})", self.to_reverse_hex())
    }
}

impl Serialize for ChangeId {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_reverse_hex())
    }
}

impl<'de> Deserialize<'de> for ChangeId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        ChangeId::from_reverse_hex(&s)
            .ok_or_else(|| serde::de::Error::custom(format!("invalid change id: {s}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let id = ChangeId::random();
        assert_eq!(ChangeId::from_reverse_hex(&id.to_reverse_hex()), Some(id));
    }

    #[test]
    fn matches_jj_alphabet() {
        // 0x00 -> "zz", 0xff -> "kk", 0x1f -> "yk" (same mapping as jj's hex_util).
        let mut bytes = [0u8; 16];
        bytes[1] = 0xff;
        bytes[2] = 0x1f;
        let s = ChangeId(bytes).to_reverse_hex();
        assert_eq!(&s[0..6], "zzkkyk");
    }

    #[test]
    fn short_and_debug_show_the_id() {
        let mut bytes = [0u8; 16];
        bytes[0] = 0x01;
        bytes[5] = 0xab;
        let id = ChangeId(bytes);
        let hex = id.to_reverse_hex();
        assert_eq!(id.short(), "zyzzzzzzzzpo");
        assert_eq!(id.short(), hex[..12]);
        assert_eq!(format!("{id:?}"), format!("ChangeId({hex})"));
    }

    #[test]
    fn prefixes() {
        let id = ChangeId::from_reverse_hex("zyxwvutsrqponmlkzyxwvutsrqponmlk").unwrap();
        assert!(id.starts_with("zyxw"));
        assert!(id.starts_with(&id.to_reverse_hex()));
        assert!(!id.starts_with("zyxk"));
        assert!(!is_prefix("zyx"));
        assert!(is_prefix("zyxw"));
        assert!(is_prefix("kkkk"));
        assert!(is_prefix(&id.to_reverse_hex()));
        assert!(!is_prefix(&format!("{id}z")));
        assert!(!is_prefix("zyxj"));
        assert!(!is_prefix("zyx{"));
        assert!(!is_prefix("ZYXW"));
    }

    #[test]
    fn rejects_forward_hex_and_wrong_length() {
        assert!(ChangeId::from_reverse_hex("0123456789abcdef0123456789abcdef").is_none());
        assert!(ChangeId::from_reverse_hex("zzzz").is_none());
    }
}
