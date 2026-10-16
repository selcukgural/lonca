//! Symbol ids and their containment hierarchy.
//!
//! A symbol id is `path#Qualified.name`. Every symbol in a file has the
//! pseudo-symbol `path#<file>` as its outermost container. `path#<module>`
//! (top-level code outside any symbol) and `path#<imports>` (the import
//! block) are children of `path#<file>`.

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
}
