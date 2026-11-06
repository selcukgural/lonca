//! Symbol ids and their containment hierarchy.
//!
//! A symbol id is `path#Qualified.name`. Every symbol in a file has the
//! pseudo-symbol `path#<file>` as its outermost container. `path#<module>`
//! (top-level code outside any symbol) and `path#<imports>` (the import
//! block) are children of `path#<file>`. `path#Type.<def>` is the type's own
//! text, a member of `Type` like its methods: a lease on it leaves them free.
//! Symbols that share a name have a key behind it, `path#Client.charge(int)`
//! or `path#P.x[setter]`, and from `FORMAT_SYMBOL_KEYS` on the name alone
//! stands for all of them: that is what `keys` says below. It keeps the
//! lease of a session that saw one such symbol apart from those of sessions
//! that see several.

use lonca_core::ops::{DEF, Facts, LeaseItem, LeaseKind};

pub const FILE: &str = "<file>";
pub const MODULE: &str = "<module>";
pub const IMPORTS: &str = "<imports>";

pub fn split(symbol: &str) -> Option<(&str, &str)> {
    symbol.split_once('#')
}

pub fn file_symbol(path: &str) -> String {
    format!("{path}#{FILE}")
}

/// One part of a name without its key: `Name(key)`, `Name[key]`.
fn plain(part: &str) -> &str {
    match part.find(['(', '[']) {
        Some(at) if at > 0 => &part[..at],
        _ => part,
    }
}

/// `name` with no keys in it: what stands for every symbol it can be.
pub fn bare(name: &str) -> String {
    name.split('.').map(plain).collect::<Vec<_>>().join(".")
}

/// Containers of `symbol`, innermost first, ending with `path#<file>`.
pub fn ancestors(symbol: &str) -> Vec<String> {
    let Some((path, name)) = split(symbol) else {
        return vec![];
    };
    let mut out = Vec::new();
    if name == FILE {
        return out;
    }
    let mut cur = name;
    while let Some(i) = cur.rfind('.') {
        cur = &cur[..i];
        out.push(format!("{path}#{cur}"));
    }
    out.push(file_symbol(path));
    out
}

/// The type whose definition `name` is, for a `Type.<def>`.
pub fn def_of(name: &str) -> Option<&str> {
    name.strip_suffix(DEF)?.strip_suffix('.')
}

/// The container a new symbol is inserted into.
pub fn container(symbol: &str) -> Option<String> {
    ancestors(symbol).into_iter().next()
}

/// `a` is `b` or one of its containers, part by part with or without the
/// key `b` has there.
fn covers_keyed(a: &str, b: &str) -> bool {
    let (Some((path_a, a)), Some((path_b, b))) = (split(a), split(b)) else {
        return false;
    };
    let (mut a, mut b) = (a.split('.'), b.split('.'));
    path_a == path_b && a.all(|x| b.next().is_some_and(|y| x == y || x == plain(y)))
}

/// `a` is `b` or one of its containers.
pub fn covers(a: &str, b: &str, keys: bool) -> bool {
    a == b || ancestors(b).iter().any(|x| x == a) || (keys && covers_keyed(a, b))
}

pub fn overlaps(a: &str, b: &str, keys: bool) -> bool {
    covers(a, b, keys) || covers(b, a, keys)
}

/// One lease a change needs: an item of one of `kinds` covering `symbol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseNeed {
    pub symbol: String,
    pub kinds: &'static [LeaseKind],
}

impl LeaseNeed {
    pub fn covered_by(&self, item: &LeaseItem, keys: bool) -> bool {
        self.kinds.contains(&item.kind) && covers(&item.symbol, &self.symbol, keys)
    }
}

/// What editing or changing a signature takes.
pub const EDIT_KINDS: &[LeaseKind] = &[LeaseKind::Edit, LeaseKind::Rename];
/// What adding a member to a container takes.
pub const ADD_KINDS: &[LeaseKind] = &[LeaseKind::Insert, LeaseKind::Edit, LeaseKind::Rename];
/// What deleting a symbol or a file takes.
pub const DELETE_KINDS: &[LeaseKind] = &[LeaseKind::Rename];

/// The leases the facts of a change need, in the order the proposal
/// reports them: the one rule for `lease_missing` and for pinning.
pub fn lease_needs(f: &Facts) -> Vec<LeaseNeed> {
    let need = |symbol: String, kinds| LeaseNeed { symbol, kinds };
    let edits = f.edits.iter().chain(&f.signature_changes);
    let edits = edits.map(|s| need(s.clone(), EDIT_KINDS));
    let deletes = f.deletes.iter().map(|s| need(s.clone(), DELETE_KINDS));
    let adds = f.adds.iter().filter_map(|s| container(s));
    let adds = adds.map(|c| need(c, ADD_KINDS));
    let files = f.deleted_files.iter().map(|p| file_symbol(p));
    let files = files.map(|s| need(s, DELETE_KINDS));
    edits.chain(deletes).chain(adds).chain(files).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy() {
        assert_eq!(
            ancestors("src/a.rs#Client.charge"),
            vec!["src/a.rs#Client".to_string(), "src/a.rs#<file>".to_string()]
        );
        assert_eq!(
            ancestors("src/a.rs#run"),
            vec!["src/a.rs#<file>".to_string()]
        );
        assert!(ancestors("src/a.rs#<file>").is_empty());
        assert!(covers("src/a.rs#Client", "src/a.rs#Client.charge", false));
        assert!(covers("src/a.rs#<file>", "src/a.rs#<module>", false));
        assert!(!covers("src/a.rs#Client", "src/a.rs#ClientX.charge", false));
        assert!(!covers("src/a.rs#Client", "src/b.rs#Client.charge", false));
        assert!(overlaps("src/a.rs#Client.charge", "src/a.rs#Client", false));
        assert!(!overlaps(
            "src/a.rs#Client.charge",
            "src/a.rs#Client.refund",
            false
        ));
    }

    /// The definition is one more member: the type covers it, and it covers
    /// nothing but itself.
    #[test]
    fn a_definition_is_a_member_of_its_type() {
        let def = "src/a.rs#Client.<def>";
        assert!(covers("src/a.rs#Client", def, false));
        assert!(covers("src/a.rs#<file>", def, false));
        assert!(!overlaps(def, "src/a.rs#Client.charge", false));
        assert!(!covers(def, "src/a.rs#Client", false));
        assert_eq!(def_of("m.Client.<def>"), Some("m.Client"));
        for name in ["Client", "<def>", "Client<def>", "Client.<def>.x"] {
            assert_eq!(def_of(name), None, "{name}");
        }
    }

    /// A name stands for every symbol of that name, so a lease taken where
    /// a symbol was alone meets one taken where it has a key.
    #[test]
    fn a_name_covers_its_keyed_symbols() {
        for (a, b) in [
            ("a.cs#C.M", "a.cs#C.M(int)"),
            ("a.cs#C.M", "a.cs#C.M(int)~2"),
            ("a.py#P.x", "a.py#P.x[setter]"),
            ("a.rs#S.From.from", "a.rs#S.From(u8).from"),
            ("a.rs#S.From(u8).from", "a.rs#S.From(u8).from(a)"),
            ("a.rs#S.From.from(a)", "a.rs#S.From(u8).from(a)"),
            ("a.rs#S.From", "a.rs#S.From(u8).from"),
            ("a.rs#impl:S.From", "a.rs#impl:S.From(u8)"),
            ("a.cs#C.operator<", "a.cs#C.operator<(A,B)"),
            ("a.cs#C", "a.cs#C.M(int)"),
            ("a.cs#<file>", "a.cs#C.M(int)"),
        ] {
            assert!(covers(a, b, true), "{a} {b}");
            assert!(overlaps(a, b, true) && overlaps(b, a, true), "{a} {b}");
            assert!(!covers(b, a, true), "{a} {b}");
        }
        for (a, b) in [
            ("a.cs#C.M(int)", "a.cs#C.M(string)"),
            ("a.cs#C.M(int)", "a.cs#C.M(int)~2"),
            ("a.cs#C.M", "a.cs#C.Mx(int)"),
            ("a.cs#C.M", "a.cs#C~2.M(int)"),
            ("a.cs#C.M", "b.cs#C.M(int)"),
            ("a.cs#C.M", "a.cs#D.M(int)"),
            ("a.cs#C.M.N", "a.cs#C.M(int)"),
            ("no-separator", "a.cs#C.M(int)"),
            ("a.cs#C.M(int)", "no-separator"),
        ] {
            assert!(!overlaps(a, b, true), "{a} {b}");
        }
    }

    /// Entries of the formats before keys keep what they meant.
    #[test]
    fn before_keys_a_name_is_only_itself() {
        assert!(!overlaps("a.md#Setup", "a.md#Setup(old)", false));
        assert!(!overlaps("a.cs#C.M", "a.cs#C.M(int)", false));
        assert!(covers("a.cs#C", "a.cs#C.M(int)", false));
    }

    #[test]
    fn a_bare_name_has_no_keys_at_any_level() {
        for (name, want) in [
            ("C.M(int)", "C.M"),
            ("C.M(int)~2", "C.M"),
            ("S.From(u8).from(a)", "S.From.from"),
            ("P.x[setter]", "P.x"),
            ("C.M", "C.M"),
            ("C.<def>", "C.<def>"),
            ("(odd)", "(odd)"),
            ("C.operator<(A,B)", "C.operator<"),
        ] {
            assert_eq!(bare(name), want);
        }
    }

    /// An overload goes into the type around it, not into its namesakes.
    #[test]
    fn the_container_of_an_overload_is_the_type() {
        assert_eq!(container("a.cs#C.M(int)"), Some("a.cs#C".to_string()));
        assert_eq!(container("a.cs#M(int)"), Some("a.cs#<file>".to_string()));
    }

    #[test]
    fn needs_follow_the_facts_in_proposal_order() {
        let f = Facts {
            edits: vec!["a.rs#f".into()],
            signature_changes: vec!["a.rs#g".into()],
            deletes: vec!["a.rs#h".into()],
            adds: vec!["a.rs#T.m".into(), "no-separator".into()],
            deleted_files: vec!["b.rs".into()],
            ..Default::default()
        };
        let need = |symbol: &str, kinds| LeaseNeed {
            symbol: symbol.into(),
            kinds,
        };
        assert_eq!(
            lease_needs(&f),
            vec![
                need("a.rs#f", EDIT_KINDS),
                need("a.rs#g", EDIT_KINDS),
                need("a.rs#h", DELETE_KINDS),
                need("a.rs#T", ADD_KINDS),
                need("b.rs#<file>", DELETE_KINDS),
            ]
        );
    }
}
