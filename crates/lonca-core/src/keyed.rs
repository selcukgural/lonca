//! Keyed directories (#261): directories whose files carry a key in their
//! name that no other file there may have. Flyway's `V12__add_users.sql`,
//! Django's `0012_add_users.py`, golang-migrate's `000012_add_users.up.sql`
//! and numbered decision records are such files: two of them with one key
//! conflict in meaning, and Git sees two unrelated paths.
//!
//! The policy names each directory and a pattern that reads the key from a
//! file name (`[paths.keyed]` in `lonca.toml`). The pattern is a regular
//! expression of the `regex` crate, which never backtracks: matching takes
//! time linear in the name and gives the same answer everywhere. Its one
//! capture group is the key.
//!
//! A key is reserved like a member's name: an `insert` lease on the
//! directory's container, `dir#<dir>`, with the key in `names`.

use std::collections::{BTreeMap, BTreeSet};

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// The name of a keyed directory's container: `db/migration#<dir>`.
pub const DIR: &str = "<dir>";

/// Asked for among the names of a lease on `dir#<dir>`, the daemon gives
/// the next free number instead (see [`KeyedDirs::next_key`]); the log
/// records the number.
pub const NEXT: &str = "next";

/// At most this many keyed directories in a policy.
pub const MAX_DIRS: usize = 64;

/// A pattern is at most this long.
pub const MAX_PATTERN: usize = 200;

/// A number key has at most this many digits, so every one is a `u64`.
pub const MAX_DIGITS: usize = 18;

/// A text key is at most this long.
pub const MAX_TEXT: usize = 128;

/// What the compiled automaton of one pattern may take, in bytes.
const SIZE_LIMIT: usize = 1 << 20;

/// How keys compare. `number`: `12` and `012` are one key, and a key is
/// written in a lease without leading zeros. `text`: as written.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Compare {
    #[default]
    Number,
    Text,
}

/// One keyed directory: its path (no trailing `/`) and how its files' names
/// give their keys.
#[derive(Clone, Debug)]
pub struct KeyedDir {
    pub dir: String,
    pub compare: Compare,
    pattern: Regex,
}

impl KeyedDir {
    /// The key of the file `name` (a name, not a path), as a lease writes
    /// it; `None` when the name does not match or what it gives is no key.
    pub fn key_of(&self, name: &str) -> Option<String> {
        let found = self.pattern.captures(name)?.get(1)?.as_str();
        match self.compare {
            Compare::Number => {
                let digits = !found.is_empty() && found.bytes().all(|b| b.is_ascii_digit());
                if !digits || found.len() > MAX_DIGITS {
                    return None;
                }
                let trimmed = found.trim_start_matches('0');
                Some(if trimmed.is_empty() { "0" } else { trimmed }.to_string())
            }
            Compare::Text => valid_text(found).then(|| found.to_string()),
        }
    }

    /// `key` is a key of this directory as a lease must write it: for
    /// numbers, digits without a leading zero.
    pub fn valid_key(&self, key: &str) -> bool {
        match self.compare {
            Compare::Number => {
                let digits = !key.is_empty() && key.bytes().all(|b| b.is_ascii_digit());
                digits && key.len() <= MAX_DIGITS && (key == "0" || !key.starts_with('0'))
            }
            Compare::Text => valid_text(key),
        }
    }

    /// The container whose `insert` leases reserve this directory's keys.
    pub fn container(&self) -> String {
        container(&self.dir)
    }
}

/// `dir#<dir>`.
pub fn container(dir: &str) -> String {
    format!("{dir}#{DIR}")
}

/// What a text key may be: what a reserved name may be, and no `/`.
fn valid_text(key: &str) -> bool {
    let bad = |c: char| c.is_whitespace() || c.is_control() || "#.()[]<>~/\\".contains(c);
    !key.is_empty() && key.len() <= MAX_TEXT && !key.contains(bad)
}

/// The keyed directories of a policy.
#[derive(Clone, Debug, Default)]
pub struct KeyedDirs {
    dirs: BTreeMap<String, KeyedDir>,
}

impl KeyedDirs {
    /// Compiles `(directory, pattern, compare)`. Refused: more than
    /// [`MAX_DIRS`], a directory that is no plain relative path, a pattern
    /// longer than [`MAX_PATTERN`], that does not compile within the size
    /// limit, or that has other than exactly one capture group.
    pub fn new<'a>(
        entries: impl IntoIterator<Item = (&'a str, &'a str, Compare)>,
    ) -> Result<Self, String> {
        let mut dirs = BTreeMap::new();
        for (dir, pattern, compare) in entries {
            if !valid_dir(dir) {
                return Err(format!("paths.keyed: `{dir}` is no directory path"));
            }
            if pattern.len() > MAX_PATTERN {
                return Err(format!("paths.keyed.\"{dir}\": the pattern is too long"));
            }
            let compiled = RegexBuilder::new(pattern)
                .size_limit(SIZE_LIMIT)
                .dfa_size_limit(SIZE_LIMIT)
                .build()
                .map_err(|e| format!("paths.keyed.\"{dir}\": {e}"))?;
            if compiled.captures_len() != 2 {
                return Err(format!(
                    "paths.keyed.\"{dir}\": the pattern needs one capture group, the key"
                ));
            }
            let keyed = KeyedDir {
                dir: dir.to_string(),
                compare,
                pattern: compiled,
            };
            dirs.insert(dir.to_string(), keyed);
        }
        if dirs.len() > MAX_DIRS {
            return Err(format!("paths.keyed: more than {MAX_DIRS} directories"));
        }
        Ok(Self { dirs })
    }

    pub fn is_empty(&self) -> bool {
        self.dirs.is_empty()
    }

    /// The keyed directory `dir`.
    pub fn get(&self, dir: &str) -> Option<&KeyedDir> {
        self.dirs.get(dir)
    }

    /// The keyed directory that holds `path` directly, and the file's name.
    /// A file in a directory under it is not one of its files.
    pub fn of<'p>(&self, path: &'p str) -> Option<(&KeyedDir, &'p str)> {
        let (dir, name) = path.rsplit_once('/')?;
        self.dirs.get(dir).map(|d| (d, name))
    }

    /// The keys, as `dir#key`, that two or more of `paths` have in one keyed
    /// directory.
    pub fn clashes<'p>(&self, paths: impl IntoIterator<Item = &'p str>) -> BTreeSet<String> {
        let mut seen: BTreeMap<String, usize> = BTreeMap::new();
        for path in paths {
            if let Some((d, name)) = self.of(path)
                && let Some(key) = d.key_of(name)
            {
                *seen.entry(format!("{}#{key}", d.dir)).or_default() += 1;
            }
        }
        seen.into_iter()
            .filter(|(_, n)| *n > 1)
            .map(|(k, _)| k)
            .collect()
    }

    /// The keys, as `dir#key`, of the files in `added` that another file of
    /// `tree` (the paths of the tree they are in) has too.
    pub fn taken<'p>(
        &self,
        added: &[String],
        tree: impl IntoIterator<Item = &'p str> + Clone,
    ) -> Vec<String> {
        let mut out = BTreeSet::new();
        for path in added {
            let Some((d, name)) = self.of(path) else {
                continue;
            };
            let Some(key) = d.key_of(name) else {
                continue;
            };
            let same = |other: &str| {
                other != path
                    && self
                        .of(other)
                        .is_some_and(|(o, n)| o.dir == d.dir && o.key_of(n).as_ref() == Some(&key))
            };
            if tree.clone().into_iter().any(same) {
                out.insert(format!("{}#{key}", d.dir));
            }
        }
        out.into_iter().collect()
    }

    /// The number after the highest key that a file of `tree` has in `dir`
    /// or that `reserved` holds; `1` when there is none. `None` for a text
    /// directory, whose keys have no order, or one that is not keyed.
    pub fn next_key<'p>(
        &self,
        dir: &str,
        tree: impl IntoIterator<Item = &'p str>,
        reserved: impl IntoIterator<Item = &'p str>,
    ) -> Option<String> {
        let d = self
            .dirs
            .get(dir)
            .filter(|d| d.compare == Compare::Number)?;
        let in_tree = tree.into_iter().filter_map(|p| {
            let (o, name) = self.of(p)?;
            (o.dir == d.dir).then(|| d.key_of(name)).flatten()
        });
        let held = reserved.into_iter().map(str::to_string);
        let highest = in_tree
            .chain(held)
            .filter_map(|k| k.parse::<u64>().ok())
            .max();
        Some(highest.map_or(1, |h| h.saturating_add(1)).to_string())
    }
}

/// A plain relative directory path: no empty, `.` or `..` part, no leading
/// or trailing `/`, no `\`, `#` or control character.
fn valid_dir(dir: &str) -> bool {
    let bad = |c: char| c.is_control() || c == '\\' || c == '#';
    !dir.is_empty()
        && !dir.contains(bad)
        && dir
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> KeyedDirs {
        KeyedDirs::new([
            ("db/migration", r"^V(\d+)__", Compare::Number),
            ("docs/adr", r"^([a-z]+)-", Compare::Text),
        ])
        .unwrap()
    }

    #[test]
    fn a_key_comes_from_the_name_and_numbers_drop_leading_zeros() {
        let k = dirs();
        let m = k.get("db/migration").unwrap();
        assert_eq!(m.key_of("V12__add_users.sql").as_deref(), Some("12"));
        assert_eq!(m.key_of("V012__add_users.sql").as_deref(), Some("12"));
        assert_eq!(m.key_of("V0__init.sql").as_deref(), Some("0"));
        assert_eq!(m.key_of("V000__init.sql").as_deref(), Some("0"));
        assert_eq!(m.key_of("README.md"), None);
        assert_eq!(m.key_of("V__x.sql"), None);
        assert_eq!(m.key_of(&format!("V{}__x.sql", "1".repeat(19))), None);
        assert_eq!(
            m.key_of(&format!("V{}__x.sql", "1".repeat(18))).as_deref(),
            Some("111111111111111111")
        );
        let adr = k.get("docs/adr").unwrap();
        assert_eq!(adr.key_of("cedar-policy.md").as_deref(), Some("cedar"));
        assert_eq!(adr.key_of("0012-x.md"), None);
    }

    #[test]
    fn a_number_key_that_is_no_digits_is_no_key() {
        let k = KeyedDirs::new([("m", r"^(\w+)_", Compare::Number)]).unwrap();
        let m = k.get("m").unwrap();
        assert_eq!(m.key_of("abc_x.sql"), None);
        assert_eq!(m.key_of("12_x.sql").as_deref(), Some("12"));
    }

    #[test]
    fn a_lease_writes_a_number_without_leading_zeros() {
        let k = dirs();
        let m = k.get("db/migration").unwrap();
        assert!(m.valid_key("12"));
        assert!(m.valid_key("0"));
        assert!(!m.valid_key("012"));
        assert!(!m.valid_key("00"));
        assert!(!m.valid_key(""));
        assert!(!m.valid_key("1a"));
        assert!(m.valid_key(&"9".repeat(18)));
        assert!(!m.valid_key(&"9".repeat(19)));
        let adr = k.get("docs/adr").unwrap();
        assert!(adr.valid_key("cedar"));
        assert!(adr.valid_key("012"));
        assert!(!adr.valid_key("a/b"));
        assert!(!adr.valid_key("a b"));
        assert!(!adr.valid_key(""));
        assert!(!adr.valid_key(&"a".repeat(129)));
        assert!(adr.valid_key(&"a".repeat(128)));
        assert_eq!(m.container(), "db/migration#<dir>");
    }

    #[test]
    fn only_files_directly_in_the_directory_count() {
        let k = dirs();
        let (d, name) = k.of("db/migration/V1__a.sql").unwrap();
        assert_eq!((d.dir.as_str(), name), ("db/migration", "V1__a.sql"));
        assert!(k.of("db/migration/old/V1__a.sql").is_none());
        assert!(k.of("db/V1__a.sql").is_none());
        assert!(k.of("V1__a.sql").is_none());
    }

    #[test]
    fn clashes_name_each_key_two_files_share() {
        let k = dirs();
        let paths = [
            "db/migration/V12__a.sql",
            "db/migration/V012__b.sql",
            "db/migration/V13__c.sql",
            "db/migration/README.md",
            "db/migration/old/V13__d.sql",
            "src/V13__e.sql",
        ];
        let c: Vec<String> = k.clashes(paths).into_iter().collect();
        assert_eq!(c, ["db/migration#12"]);
        assert!(k.clashes(["db/migration/V1__a.sql"]).is_empty());
    }

    #[test]
    fn taken_is_an_added_key_another_file_has() {
        let k = dirs();
        let tree = [
            "db/migration/V11__x.sql",
            "db/migration/V12__a.sql",
            "db/migration/V12__b.sql",
            "db/migration/V13__c.sql",
            "db/migration/old/V14__d.sql",
            "docs/adr/cedar-a.md",
        ];
        let added = |p: &[&str]| p.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(
            k.taken(&added(&["db/migration/V12__b.sql"]), tree),
            ["db/migration#12"]
        );
        assert!(
            k.taken(&added(&["db/migration/V13__c.sql"]), tree)
                .is_empty()
        );
        assert!(
            k.taken(&added(&["db/migration/old/V14__d.sql"]), tree)
                .is_empty()
        );
        assert!(k.taken(&added(&["src/a.rs"]), tree).is_empty());
        assert!(k.taken(&added(&["db/migration/README"]), tree).is_empty());
    }

    #[test]
    fn next_is_one_past_the_highest_in_trunk_or_reserved() {
        let k = dirs();
        let tree = [
            "db/migration/V9__x.sql",
            "db/migration/V10__y.sql",
            "db/migration/old/V40__z.sql",
            "db/V50__w.sql",
        ];
        assert_eq!(k.next_key("db/migration", tree, []).as_deref(), Some("11"));
        assert_eq!(
            k.next_key("db/migration", tree, ["12", "x"]).as_deref(),
            Some("13")
        );
        assert_eq!(
            k.next_key("db/migration", tree, ["3"]).as_deref(),
            Some("11")
        );
        assert_eq!(k.next_key("db/migration", [], []).as_deref(), Some("1"));
        assert_eq!(k.next_key("docs/adr", [], []), None);
        assert_eq!(k.next_key("src", [], []), None);
        let top = format!("db/migration/V{}__x.sql", u64::MAX);
        assert_eq!(
            k.next_key("db/migration", [top.as_str()], []),
            Some("1".into())
        );
    }

    #[test]
    fn a_policy_that_can_not_be_read_is_refused() {
        let one = |dir: &str, p: &str| KeyedDirs::new([(dir, p, Compare::Number)]).map(|_| ());
        assert!(one("db/migration", r"^V(\d+)__").is_ok());
        assert!(one("db/migration", r"^V\d+__").is_err(), "no group");
        assert!(one("db/migration", r"^(V)(\d+)__").is_err(), "two groups");
        assert!(one("db/migration", r"^V(\d+").is_err(), "does not compile");
        assert!(one("db/migration", &"a".repeat(201)).is_err());
        assert!(one("db/migration", &format!("({})", "a".repeat(198))).is_ok());
        assert!(
            one("db/migration", r"^(\w{1000}){1000}$").is_err(),
            "too big"
        );
        for dir in [
            "", "/db", "db/", "db//m", "./db", "db/../m", "db\\m", "db#m",
        ] {
            assert!(one(dir, r"^(\d+)").is_err(), "{dir:?}");
        }
        let many: Vec<String> = (0..=MAX_DIRS).map(|i| format!("d{i}")).collect();
        let entries = many
            .iter()
            .map(|d| (d.as_str(), r"^(\d+)", Compare::Number));
        assert!(KeyedDirs::new(entries).is_err());
        let fits = many[..MAX_DIRS]
            .iter()
            .map(|d| (d.as_str(), r"^(\d+)", Compare::Number));
        assert!(KeyedDirs::new(fits).is_ok());
        assert!(KeyedDirs::default().is_empty());
        assert!(!dirs().is_empty());
    }
}
