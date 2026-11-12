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

use lonca_core::oplog::FORMAT_INSERT_NAMES;
use lonca_core::ops::{DEF, Facts, LeaseItem, LeaseKind, names_are_headings};

use crate::config::UnparsedFiles;

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

/// `whole` is `part`, or `part` by its name alone, or that name with the
/// number `part` has: `f~2` is what the keys of `f` turn into `f(a)~2`.
fn stands_for_part(whole: &str, part: &str) -> bool {
    let number = part.rsplit_once('~').map(|(_, n)| n);
    let numbered = number.is_some_and(|n| whole == format!("{}~{n}", plain(part)));
    whole == part || whole == plain(part) || numbered
}

/// The name of `symbol` with no keys in it: what stands for every symbol it
/// can be. A heading stays what it is.
pub fn bare(symbol: &str) -> String {
    let (path, name) = split(symbol).unwrap_or(("", symbol));
    if names_are_headings(path) {
        return name.to_string();
    }
    let parts: Vec<&str> = name.split('.').map(plain).collect();
    parts.join(".")
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
    path_a == path_b
        && !names_are_headings(path_a)
        && a.all(|x| b.next().is_some_and(|y| stands_for_part(x, y)))
}

/// `a` is the name of `b` at `b`'s own level: `b` is one of the symbols it
/// stands for, not a member of one.
pub fn stands_for(a: &str, b: &str) -> bool {
    a.matches('.').count() == b.matches('.').count() && covers_keyed(a, b)
}

/// `a` is `b` or one of its containers.
pub fn covers(a: &str, b: &str, keys: bool) -> bool {
    a == b || contains(a, b) || (keys && covers_keyed(a, b))
}

/// `a` is one of the [`ancestors`] of `b`, without making them: the file of
/// `b`, or its name up to one of its dots.
fn contains(a: &str, b: &str) -> bool {
    let Some((path, name)) = split(b) else {
        return false;
    };
    let rest = a.strip_prefix(path).and_then(|r| r.strip_prefix('#'));
    let Some(rest) = rest.filter(|_| name != FILE) else {
        return false;
    };
    let ends_at_a_dot = || name.as_bytes().get(rest.len()) == Some(&b'.');
    rest == FILE || (name.starts_with(rest) && ends_at_a_dot())
}

pub fn overlaps(a: &str, b: &str, keys: bool) -> bool {
    covers(a, b, keys) || covers(b, a, keys)
}

/// One lease a change needs: an item of one of `kinds` covering `symbol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseNeed {
    pub symbol: String,
    pub kinds: &'static [LeaseKind],
    /// For an addition, the symbol added: an `insert` with names covers it
    /// only if it reserved its name.
    pub adds: Option<String>,
}

impl LeaseNeed {
    pub fn new(symbol: String, kinds: &'static [LeaseKind]) -> Self {
        Self {
            symbol,
            kinds,
            adds: None,
        }
    }

    pub fn covered_by(&self, item: &LeaseItem, keys: bool) -> bool {
        self.kinds.contains(&item.kind)
            && covers(&item.symbol, &self.symbol, keys)
            && self.adds.as_ref().is_none_or(|a| reserves(item, a))
    }
}

/// The most names one `insert` item reserves.
pub const MAX_RESERVED_NAMES: usize = 64;

/// A name an `insert` can reserve: one member, bare, with no key, number or
/// path in it. A space may stand inside one, as in a heading.
pub fn valid_reserved_name(name: &str) -> bool {
    let bad =
        |c: char| (c.is_whitespace() && c != ' ') || c.is_control() || "#.()[]<>~/\\".contains(c);
    !name.is_empty() && name.len() <= 128 && name.trim() == name && !name.contains(bad)
}

/// `added` may come in under `item`: it is no `insert`, it reserves no
/// names, or the member of its container that `added` is or is in has one
/// of them, by its name alone. A new type brings its members with it.
pub fn reserves(item: &LeaseItem, added: &str) -> bool {
    if item.kind != LeaseKind::Insert || item.names.is_empty() {
        return true;
    }
    let depth = ancestors(&item.symbol).len();
    name_at(added, depth).is_some_and(|part| item.names.iter().any(|n| *n == part))
}

/// The part of `symbol`'s name at `depth` (0 is the top of the file), by its
/// name alone: no key, no number, except in a heading.
fn name_at(symbol: &str, depth: usize) -> Option<&str> {
    let (path, name) = split(symbol)?;
    let part = name.split('.').nth(depth)?;
    Some(if names_are_headings(path) {
        part
    } else {
        unnumbered(plain(part))
    })
}

/// The name an `insert` on `need`'s container would reserve for the
/// addition it is for: `None` for no addition, or one no name can stand for
/// (`<module>`, `<append>`).
pub fn reserved_name(need: &LeaseNeed) -> Option<String> {
    let added = need.adds.as_deref()?;
    let name = name_at(added, ancestors(&need.symbol).len())?;
    valid_reserved_name(name).then(|| name.to_string())
}

/// A name without the number exact duplicates have: `init~2` is `init`.
fn unnumbered(part: &str) -> &str {
    match part.rsplit_once('~') {
        Some((name, n))
            if !name.is_empty() && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) =>
        {
            name
        }
        _ => part,
    }
}

/// Two `insert` items reserve one name in one container, or one reserves the member of its container that the other's container
/// is or is in: reserving `Client` in a file reserves what goes into it.
pub fn names_meet(a: &LeaseItem, b: &LeaseItem, keys: bool) -> bool {
    if a.names.is_empty() || b.names.is_empty() {
        return false;
    }
    let same = a.symbol == b.symbol
        || (keys && (stands_for(&a.symbol, &b.symbol) || stands_for(&b.symbol, &a.symbol)));
    if same {
        return a.names.iter().any(|n| b.names.contains(n));
    }
    let within = |outer: &LeaseItem, inner: &LeaseItem| {
        covers(&outer.symbol, &inner.symbol, keys) && reserves(outer, &inner.symbol)
    };
    within(a, b) || within(b, a)
}

/// What changing a signature takes: what calls it can not be merged by
/// lines.
pub const EDIT_KINDS: &[LeaseKind] = &[LeaseKind::Edit, LeaseKind::Rename];
/// What editing a body takes.
pub const BODY_KINDS: &[LeaseKind] = &[LeaseKind::Edit, LeaseKind::Rename, LeaseKind::Shared];
/// What adding a member to a container takes.
pub const ADD_KINDS: &[LeaseKind] = &[LeaseKind::Insert, LeaseKind::Edit, LeaseKind::Rename];
/// What deleting a symbol or a file takes.
pub const DELETE_KINDS: &[LeaseKind] = &[LeaseKind::Rename];

/// [`lease_needs`] when `leases.unparsed_files` is `optimistic`: a file no
/// parser reads is left to the line merge.
pub fn lease_needs_under(f: &Facts, unparsed: UnparsedFiles, format: u32) -> Vec<LeaseNeed> {
    let needs = lease_needs(f, format).into_iter();
    let free = |need: &LeaseNeed| {
        unparsed == UnparsedFiles::Optimistic
            && need.kinds == BODY_KINDS
            && f.unparsed_files
                .iter()
                .any(|p| need.symbol == file_symbol(p))
    };
    needs.filter(|need| !free(need)).collect()
}

/// The leases the facts of a change need, in the order the proposal
/// reports them: the one rule for `lease_missing` and for pinning. From
/// [`FORMAT_INSERT_NAMES`] an addition carries its name, and a new file needs
/// its `path#<file>` exclusively: two sessions can not create one path.
pub fn lease_needs(f: &Facts, format: u32) -> Vec<LeaseNeed> {
    let need = LeaseNeed::new;
    let named = format >= FORMAT_INSERT_NAMES;
    let bodies = f.edits.iter().map(|s| need(s.clone(), BODY_KINDS));
    let signatures = f.signature_changes.iter();
    let edits = bodies.chain(signatures.map(|s| need(s.clone(), EDIT_KINDS)));
    let deletes = f.deletes.iter().map(|s| need(s.clone(), DELETE_KINDS));
    // A rename takes a `rename` lease on the old name, and that is all of it
    // while the symbol stays where it was.
    let in_place = |old: &str, new: &str| container(old) == container(new);
    let renamed = |s: &&String| {
        let into = |new: &String| container(s).as_ref() == Some(new);
        f.renames
            .iter()
            .any(|[old, new]| (new == *s && in_place(old, new)) || into(new))
    };
    let adds = f.adds.iter().filter(|s| !renamed(s));
    let adds = adds.filter_map(|s| {
        let adds = named.then(|| s.clone());
        let kinds = ADD_KINDS;
        container(s).map(|symbol| LeaseNeed {
            symbol,
            kinds,
            adds,
        })
    });
    let files = f.deleted_files.iter().map(|p| file_symbol(p));
    let files = files.map(|s| need(s, DELETE_KINDS));
    let created = f.added_files.iter().filter(|_| named);
    let created = created.map(|p| need(file_symbol(p), EDIT_KINDS));
    edits
        .chain(deletes)
        .chain(adds)
        .chain(files)
        .chain(created)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The format before additions carried their names.
    const BEFORE: u32 = FORMAT_INSERT_NAMES - 1;

    /// `contains` answers as the list of ancestors does, for every pair of
    /// short strings over what a symbol id is made of.
    #[test]
    fn a_container_is_found_as_the_ancestors_list_it() {
        let alphabet = ["a", "b", ".", "#", "<file>", "é"];
        let mut all = vec![String::new()];
        for _ in 0..4 {
            let longer = all.iter().flat_map(|s| alphabet.map(|c| format!("{s}{c}")));
            let longer: Vec<String> = longer.collect();
            all.extend(longer);
            all.sort();
            all.dedup();
        }
        for b in &all {
            let listed = ancestors(b);
            for a in &all {
                assert_eq!(contains(a, b), listed.contains(a), "{a:?} of {b:?}");
            }
        }
    }

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
            ("a.py#f~2", "a.py#f(a)~2"),
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
            ("a.py#f~2", "a.py#f(a)"),
            ("a.py#f~2", "a.py#f(a)~3"),
            ("a.md#Setup", "a.md#Setup(old)"),
            ("a.toml#a", "a.toml#a[b]"),
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
        for (id, want) in [
            ("a.cs#C.M(int)", "C.M"),
            ("a.cs#C.M(int)~2", "C.M"),
            ("a.rs#S.From(u8).from(a)", "S.From.from"),
            ("a.py#P.x[setter]", "P.x"),
            ("a.cs#C.M", "C.M"),
            ("a.cs#C.<def>", "C.<def>"),
            ("a.cs#(odd)", "(odd)"),
            ("a.cs#C.operator<(A,B)", "C.operator<"),
            ("a.md#Setup(old)", "Setup(old)"),
            ("no-separator(x)", "no-separator"),
        ] {
            assert_eq!(bare(id), want);
        }
    }

    /// An insert into `S.From` meets what is held of each `S.From(..)`, and
    /// not their members, as an insert into a type does not meet its methods.
    #[test]
    fn a_name_stands_for_its_symbols_at_their_level() {
        assert!(stands_for("a.rs#S.From", "a.rs#S.From(u8)"));
        assert!(!stands_for("a.rs#S.From", "a.rs#S.From(u8).from"));
        assert!(!stands_for("a.rs#S.From(u16)", "a.rs#S.From(u8)"));
        assert!(!stands_for("a.rs#S.From(u8)", "a.rs#S.From"));
    }

    /// An overload goes into the type around it, not into its namesakes.
    #[test]
    fn the_container_of_an_overload_is_the_type() {
        assert_eq!(container("a.cs#C.M(int)"), Some("a.cs#C".to_string()));
        assert_eq!(container("a.cs#M(int)"), Some("a.cs#<file>".to_string()));
    }

    /// What goes into a type under its new name goes with the type.
    #[test]
    fn a_member_of_a_renamed_type_needs_no_more_than_the_type() {
        let f = Facts {
            deletes: vec!["a.go#T".into(), "a.go#T.Old".into()],
            adds: vec!["a.go#U".into(), "a.go#U.Old".into()],
            renames: vec![["a.go#T".into(), "a.go#U".into()]],
            ..Default::default()
        };
        let needs = lease_needs(&f, BEFORE);
        assert!(needs.iter().all(|n| n.kinds == DELETE_KINDS), "{needs:?}");
    }

    /// Facts do not name such a pair, and the lease rule does not rest on it.
    #[test]
    fn a_symbol_renamed_into_another_container_needs_that_container() {
        let f = Facts {
            deletes: vec!["a.go#T.Old".into()],
            adds: vec!["a.go#U.New".into()],
            renames: vec![["a.go#T.Old".into(), "a.go#U.New".into()]],
            ..Default::default()
        };
        let need = |symbol: &str, kinds| LeaseNeed::new(symbol.into(), kinds);
        assert_eq!(
            lease_needs(&f, BEFORE),
            vec![need("a.go#T.Old", DELETE_KINDS), need("a.go#U", ADD_KINDS)]
        );
    }

    #[test]
    fn a_file_no_parser_reads_needs_no_lease_when_optimistic() {
        let f = Facts {
            edits: vec![
                "a.java#<file>".into(),
                "a.bin#<file>".into(),
                "a.rs#f".into(),
            ],
            unparsed_files: vec!["a.java".into(), "b.java".into()],
            deleted_files: vec!["b.java".into()],
            ..Default::default()
        };
        let symbols = |unparsed| -> Vec<String> {
            let needs = lease_needs_under(&f, unparsed, BEFORE).into_iter();
            needs.map(|n| n.symbol).collect()
        };
        assert_eq!(
            symbols(UnparsedFiles::File),
            lease_needs(&f, BEFORE)
                .into_iter()
                .map(|n| n.symbol)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            symbols(UnparsedFiles::Optimistic),
            ["a.bin#<file>", "a.rs#f", "b.java#<file>"]
        );
    }

    #[test]
    fn a_renamed_symbol_needs_only_its_old_name() {
        let f = Facts {
            deletes: vec!["a.rs#T.old".into()],
            adds: vec!["a.rs#T.new".into(), "a.rs#U.other".into()],
            renames: vec![["a.rs#T.old".into(), "a.rs#T.new".into()]],
            ..Default::default()
        };
        let need = |symbol: &str, kinds| LeaseNeed::new(symbol.into(), kinds);
        assert_eq!(
            lease_needs(&f, BEFORE),
            vec![need("a.rs#T.old", DELETE_KINDS), need("a.rs#U", ADD_KINDS)]
        );
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
        let need = |symbol: &str, kinds| LeaseNeed::new(symbol.into(), kinds);
        assert_eq!(
            lease_needs(&f, BEFORE),
            vec![
                need("a.rs#f", BODY_KINDS),
                need("a.rs#g", EDIT_KINDS),
                need("a.rs#h", DELETE_KINDS),
                need("a.rs#T", ADD_KINDS),
                need("b.rs#<file>", DELETE_KINDS),
            ]
        );
    }

    /// From format 22 an addition carries what it adds, and a new file needs
    /// its path exclusively.
    #[test]
    fn additions_carry_their_names_and_new_files_need_their_path() {
        let f = Facts {
            adds: vec!["a.rs#T.m".into()],
            added_files: vec!["n.rs".into()],
            deleted_files: vec!["b.rs".into()],
            ..Default::default()
        };
        let added = LeaseNeed {
            adds: Some("a.rs#T.m".into()),
            ..LeaseNeed::new("a.rs#T".into(), ADD_KINDS)
        };
        assert_eq!(
            lease_needs(&f, FORMAT_INSERT_NAMES),
            vec![
                added,
                LeaseNeed::new("b.rs#<file>".into(), DELETE_KINDS),
                LeaseNeed::new("n.rs#<file>".into(), EDIT_KINDS),
            ]
        );
        assert_eq!(
            lease_needs(&f, BEFORE),
            vec![
                LeaseNeed::new("a.rs#T".into(), ADD_KINDS),
                LeaseNeed::new("b.rs#<file>".into(), DELETE_KINDS),
            ]
        );
        // A new unparsed file is no body: optimistic leaves it its lease.
        let f = Facts {
            added_files: vec!["n.java".into()],
            unparsed_files: vec!["n.java".into()],
            ..Default::default()
        };
        let needs = lease_needs_under(&f, UnparsedFiles::Optimistic, FORMAT_INSERT_NAMES);
        assert_eq!(needs, [LeaseNeed::new("n.java#<file>".into(), EDIT_KINDS)]);
    }

    #[test]
    fn an_insert_with_names_covers_only_what_has_one() {
        let item = |symbol: &str, kind, names: &[&str]| LeaseItem {
            symbol: symbol.into(),
            kind,
            names: names.iter().map(|n| n.to_string()).collect(),
        };
        let file = item("a.rs#<file>", LeaseKind::Insert, &["T", "init"]);
        let t = item("a.rs#T", LeaseKind::Insert, &["m"]);
        for (it, added) in [
            (&file, "a.rs#T"),
            (&file, "a.rs#T.m"),
            (&file, "a.rs#T(u8).m"),
            (&file, "a.rs#init~2"),
            (&file, "a.rs#init(a)~3"),
            (&t, "a.rs#T.m"),
            (&t, "a.rs#T.m(int)"),
            (&t, "a.rs#T.m[setter]"),
            (&t, "a.rs#T.m.inner"),
        ] {
            assert!(reserves(it, added), "{added}");
        }
        for (it, added) in [
            (&file, "a.rs#U"),
            (&file, "a.rs#Tx"),
            (&file, "a.rs#init~"),
            (&file, "a.rs#init~x"),
            (&file, "a.rs#~2"),
            (&t, "a.rs#T.n"),
            (&t, "a.rs#T"),
            (&t, "no-separator"),
        ] {
            assert!(!reserves(it, added), "{added}");
        }
        // Without names, or of another kind, an item reserves nothing.
        assert!(reserves(
            &item("a.rs#T", LeaseKind::Insert, &[]),
            "a.rs#T.n"
        ));
        assert!(reserves(
            &item("a.rs#T", LeaseKind::Edit, &["m"]),
            "a.rs#T.n"
        ));
        // A heading is its own name: a `(` or a `~` in it is part of it.
        let doc = item("d.md#<file>", LeaseKind::Insert, &["Setup"]);
        assert!(reserves(&doc, "d.md#Setup"));
        assert!(!reserves(&doc, "d.md#Setup(old)"));
        assert!(!reserves(&doc, "d.md#Setup~2"));
        let need = LeaseNeed {
            adds: Some("a.rs#T.n".into()),
            ..LeaseNeed::new("a.rs#T".into(), ADD_KINDS)
        };
        assert!(!need.covered_by(&t, true));
        assert!(need.covered_by(&item("a.rs#T", LeaseKind::Insert, &["n"]), true));
        assert!(!need.covered_by(&item("a.rs#U", LeaseKind::Insert, &["n"]), true));
    }

    #[test]
    fn names_meet_in_one_container_or_in_what_one_reserves() {
        let item = |symbol: &str, names: &[&str]| LeaseItem {
            symbol: symbol.into(),
            kind: LeaseKind::Insert,
            names: names.iter().map(|n| n.to_string()).collect(),
        };
        let a = item("a.rs#S.From(u8)", &["from", "x"]);
        assert!(names_meet(&a, &item("a.rs#S.From(u8)", &["x"]), false));
        assert!(names_meet(&a, &item("a.rs#S.From", &["from"]), true));
        assert!(names_meet(&item("a.rs#S.From", &["from"]), &a, true));
        assert!(!names_meet(&a, &item("a.rs#S.From", &["from"]), false));
        assert!(!names_meet(&a, &item("a.rs#S.From(u8)", &["y"]), true));
        assert!(!names_meet(&a, &item("a.rs#S.From(u8)", &[]), true));
        assert!(!names_meet(&a, &item("a.rs#S", &["from"]), true));
        // Reserving a member reserves what goes into it, at any depth.
        let into = item("a.rs#S.From(u8).from", &["z"]);
        assert!(names_meet(&a, &into, true));
        assert!(names_meet(&into, &a, true));
        assert!(!names_meet(
            &a,
            &item("a.rs#S.From(u8).other", &["z"]),
            true
        ));
        let file = item("a.rs#<file>", &["Client"]);
        let client = item("a.rs#Client", &["throttle"]);
        assert!(names_meet(&file, &client, true));
        assert!(names_meet(&client, &file, false));
        assert!(names_meet(&file, &item("a.rs#Client.Inner", &["x"]), true));
        assert!(!names_meet(&file, &item("a.rs#Other", &["throttle"]), true));
        assert!(!names_meet(
            &file,
            &item("b.rs#Client", &["throttle"]),
            true
        ));
        assert!(!names_meet(&file, &item("a.rs#Client", &[]), true));
        assert!(!names_meet(&item("a.rs#<file>", &[]), &client, true));
    }

    #[test]
    fn the_name_to_reserve_is_that_of_the_addition_in_its_container() {
        let need = |container: &str, added: &str| LeaseNeed {
            adds: Some(added.into()),
            ..LeaseNeed::new(container.into(), ADD_KINDS)
        };
        let name = |n: LeaseNeed| reserved_name(&n);
        assert_eq!(name(need("a.rs#T", "a.rs#T.m(int)~2")), Some("m".into()));
        assert_eq!(
            name(need("a.rs#<file>", "a.rs#init~2")),
            Some("init".into())
        );
        let heading = need("d.md#A", "d.md#A.Getting started");
        assert_eq!(name(heading), Some("Getting started".into()));
        assert_eq!(name(need("d.md#A", "d.md#A.<append>")), None);
        assert_eq!(name(need("a.rs#T", "a.rs#T")), None);
        assert_eq!(name(LeaseNeed::new("a.rs#T".into(), ADD_KINDS)), None);
    }

    #[test]
    fn a_reserved_name_is_one_bare_name() {
        for ok in [
            "x",
            "throttle",
            "_",
            "Ünlü",
            "Getting started",
            &"x".repeat(128),
        ] {
            assert!(valid_reserved_name(ok), "{ok}");
        }
        for bad in [
            "",
            "a.b",
            "a#b",
            "f(x)",
            "f[x]",
            "<def>",
            "a>b",
            "f~2",
            "a/b",
            "a\\b",
            " a",
            "a ",
            "a\u{a0}b",
            "a\tb",
            "a\u{7}b",
            &"x".repeat(129),
        ] {
            assert!(!valid_reserved_name(bad), "{bad:?}");
        }
    }
}
