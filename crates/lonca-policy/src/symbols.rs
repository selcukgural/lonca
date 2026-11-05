//! Symbol ids and their containment hierarchy.
//!
//! A symbol id is `path#Qualified.name`. Every symbol in a file has the
//! pseudo-symbol `path#<file>` as its outermost container. `path#<module>`
//! (top-level code outside any symbol) and `path#<imports>` (the import
//! block) are children of `path#<file>`.

use lonca_core::ops::{Facts, LeaseItem, LeaseKind};

pub const FILE: &str = "<file>";
pub const MODULE: &str = "<module>";
pub const IMPORTS: &str = "<imports>";

pub fn split(symbol: &str) -> Option<(&str, &str)> {
    symbol.split_once('#')
}

pub fn file_symbol(path: &str) -> String {
    format!("{path}#{FILE}")
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

/// The container a new symbol is inserted into.
pub fn container(symbol: &str) -> Option<String> {
    ancestors(symbol).into_iter().next()
}

/// `a` is `b` or one of its containers.
pub fn covers(a: &str, b: &str) -> bool {
    a == b || ancestors(b).iter().any(|x| x == a)
}

pub fn overlaps(a: &str, b: &str) -> bool {
    covers(a, b) || covers(b, a)
}

/// One lease a change needs: an item of one of `kinds` covering `symbol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaseNeed {
    pub symbol: String,
    pub kinds: &'static [LeaseKind],
}

impl LeaseNeed {
    pub fn covered_by(&self, item: &LeaseItem) -> bool {
        self.kinds.contains(&item.kind) && covers(&item.symbol, &self.symbol)
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
        assert!(covers("src/a.rs#Client", "src/a.rs#Client.charge"));
        assert!(covers("src/a.rs#<file>", "src/a.rs#<module>"));
        assert!(!covers("src/a.rs#Client", "src/a.rs#ClientX.charge"));
        assert!(!covers("src/a.rs#Client", "src/b.rs#Client.charge"));
        assert!(overlaps("src/a.rs#Client.charge", "src/a.rs#Client"));
        assert!(!overlaps(
            "src/a.rs#Client.charge",
            "src/a.rs#Client.refund"
        ));
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
