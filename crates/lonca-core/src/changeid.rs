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
            out.push(REVERSE_HEX[(b >> 4) as usize] as char);
            out.push(REVERSE_HEX[(b & 0x0f) as usize] as char);
        }
        out
    }

    pub fn from_reverse_hex(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = (value(bytes[2 * i])? << 4) | value(bytes[2 * i + 1])?;
        }
        Some(Self(out))
    }

    pub fn short(&self) -> String {
        self.to_reverse_hex()[..12].to_string()
    }
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
    fn rejects_forward_hex_and_wrong_length() {
        assert!(ChangeId::from_reverse_hex("0123456789abcdef0123456789abcdef").is_none());
        assert!(ChangeId::from_reverse_hex("zzzz").is_none());
    }
}
