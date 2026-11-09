//! The plain data of the object store: ids, file modes and flattened trees.
//! No Git library: a client of the daemon reads and writes these without
//! the store (feature `store`).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A Git object id in lowercase hex. Read from JSON (a request, a log
/// entry) only as Lonca writes one, 40 lowercase hex digits: anything else
/// is refused there, not found later by whatever looks at it, and what is
/// read is never changed on the way (an entry's hash covers it).
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitId(pub String);

impl TryFrom<String> for GitId {
    type Error = Error;

    fn try_from(s: String) -> Result<Self> {
        let id = Self::parse(&s)?;
        if id.0 != s {
            return Err(Error::Invalid(format!("git id {s:?}: not in lowercase")));
        }
        Ok(id)
    }
}

impl From<GitId> for String {
    fn from(id: GitId) -> String {
        id.0
    }
}

/// Hex digits in a SHA-1 object id, the only kind Lonca stores.
const HEX_LEN: usize = 40;

impl GitId {
    /// A SHA-1 id: 40 hex digits, either case, kept in lowercase.
    pub fn parse(s: &str) -> Result<Self> {
        if s.len() != HEX_LEN || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid(format!(
                "git id {s:?}: not {HEX_LEN} hex digits"
            )));
        }
        Ok(Self(s.to_ascii_lowercase()))
    }

    /// The first ten characters, for people to read.
    pub fn short(&self) -> &str {
        let end = self
            .0
            .char_indices()
            .nth(10)
            .map_or(self.0.len(), |(i, _)| i);
        &self.0[..end]
    }
}

impl fmt::Display for GitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for GitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitId({})", self.short())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileMode {
    Regular,
    Executable,
    Symlink,
    /// A submodule commit; carried through unchanged, never materialized.
    Submodule,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub mode: FileMode,
    pub blob: GitId,
}

/// A flattened tree: repository path -> entry.
pub type FileMap = BTreeMap<String, FileEntry>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_id_is_forty_hex_digits_kept_in_lowercase() {
        let lower = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(GitId::parse(lower).unwrap().0, lower);
        let upper = lower.to_ascii_uppercase();
        assert_eq!(GitId::parse(&upper).unwrap().0, lower);
        for bad in [
            "",
            &lower[..39],
            &format!("{lower}8"),
            &lower.replace('a', "g"),
            &"0".repeat(64),
        ] {
            assert!(GitId::parse(bad).is_err(), "{bad}");
        }
        // Not a byte count: a multi-byte character of the right length.
        let wide = format!("{}é", &lower[..38]);
        assert_eq!(wide.len(), 40);
        assert!(GitId::parse(&wide).is_err());
        assert_eq!(GitId(lower.into()).short(), "0123456789");
        assert_eq!(GitId("abc".into()).short(), "abc");
        assert_eq!(format!("{:?}", GitId(lower.into())), "GitId(0123456789)");
        assert_eq!(GitId(lower.into()).to_string(), lower);
        // Ten characters, not ten bytes: a cut inside one would panic.
        assert_eq!(GitId("ééééééééééé".into()).short(), "éééééééééé");
        assert_eq!(GitId("ab".repeat(8)).short(), "ababababab");
    }

    /// JSON gives a git id only as Lonca writes one, unchanged.
    #[test]
    fn a_git_id_is_read_from_json_only_as_written() {
        let lower = "0123456789abcdef0123456789abcdef01234567";
        let id: GitId = serde_json::from_value(serde_json::json!(lower)).unwrap();
        assert_eq!(id.0, lower);
        assert_eq!(serde_json::to_value(&id).unwrap(), serde_json::json!(lower));
        let upper = lower.to_uppercase();
        for bad in [
            "",
            "abc",
            "ééééééééééééééééééé",
            &format!("{}é", &lower[..38]),
            &upper,
        ] {
            let r = serde_json::from_value::<GitId>(serde_json::json!(bad));
            assert!(r.is_err(), "{bad}");
        }
    }
}
