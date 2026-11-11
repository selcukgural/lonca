//! Repository path validation and the path/symbol pattern language used by
//! capabilities and policy.
//!
//! Patterns are deliberately simple so that "is pattern A contained in
//! pattern B" is decidable exactly (capabilities may only be narrowed):
//! - `src/billing/client.ts` matches exactly that path,
//! - `src/billing/**` matches everything below `src/billing/`,
//! - `**` matches every path.

use crate::error::{Error, Result};

/// Rejects anything that is not a clean, relative, forward-slash path.
pub fn validate_repo_path(p: &str) -> Result<()> {
    let bad = |why: &str| Err(Error::Invalid(format!("path {p:?}: {why}")));
    if p.is_empty() {
        return bad("empty");
    }
    if p.len() > 4096 {
        return bad("too long");
    }
    if p.starts_with('/') || p.ends_with('/') {
        return bad("must be relative and name a file");
    }
    if p.contains('\\') || p.contains('\0') {
        return bad("backslash or NUL");
    }
    // Bidi controls make a path display differently from what it is.
    if p.chars().any(|c| matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}')) {
        return bad("bidirectional control character");
    }
    for comp in p.split('/') {
        if comp.is_empty() || comp == "." || comp == ".." {
            return bad("empty, '.' or '..' component");
        }
        if comp.eq_ignore_ascii_case(".git") {
            return bad("'.git' component");
        }
    }
    Ok(())
}

/// Is `p` under a workspace's `.lonca/`? Case is folded: on macOS
/// `.LONCA/session` is that same file.
pub fn is_workspace_metadata(p: &str) -> bool {
    let first = p.split('/').next().unwrap_or_default();
    first.eq_ignore_ascii_case(".lonca")
}

/// A path as a file system that folds case reads it, for the lists that
/// name what is *not* free (`critical`, `untrusted`, `checks_by_path`): on
/// macOS `Build.rs` is `build.rs`, and a list that forbids must not be
/// stepped over by a spelling.
///
/// The table is this function, not the standard library's: `decide()` is
/// replayed, and its answer may not move with a Unicode version. ASCII
/// letters are lowered; the few characters such file systems read as ASCII
/// letters are written as those (the Kelvin sign, the long s, the Latin
/// ligatures, the sharp s); what HFS+ ignores in a name is left out. Every
/// other character stands as written, so a pattern with letters outside
/// ASCII matches its own spelling only. Folding too much only makes more
/// paths critical.
pub fn folded(p: &str) -> String {
    let mut out = String::with_capacity(p.len());
    for c in p.chars() {
        match c {
            '\u{200C}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{206A}'..='\u{206F}'
            | '\u{FEFF}' => {}
            '\u{212A}' => out.push('k'),
            '\u{017F}' => out.push('s'),
            '\u{00DF}' | '\u{1E9E}' => out.push_str("ss"),
            '\u{FB00}' => out.push_str("ff"),
            '\u{FB01}' => out.push_str("fi"),
            '\u{FB02}' => out.push_str("fl"),
            '\u{FB03}' => out.push_str("ffi"),
            '\u{FB04}' => out.push_str("ffl"),
            '\u{FB05}' | '\u{FB06}' => out.push_str("st"),
            '\u{037E}' => out.push(';'),
            '\u{1FEF}' => out.push('`'),
            c => out.push(c.to_ascii_lowercase()),
        }
    }
    out
}

pub fn validate_path_pattern(p: &str) -> Result<()> {
    if p == "**" {
        return Ok(());
    }
    match p.strip_suffix("/**") {
        Some(prefix) => validate_repo_path(prefix),
        None => {
            if p.contains('*') {
                return Err(Error::Invalid(format!(
                    "pattern {p:?}: '*' is only allowed as a trailing '/**'"
                )));
            }
            validate_repo_path(p)
        }
    }
}

pub fn path_matches(pattern: &str, path: &str) -> bool {
    if pattern == "**" {
        return true;
    }
    match pattern.strip_suffix("/**") {
        Some(prefix) => {
            path.len() > prefix.len()
                && path.starts_with(prefix)
                && path.as_bytes().get(prefix.len()) == Some(&b'/')
        }
        None => pattern == path,
    }
}

/// True when every path matched by `inner` is also matched by `outer`.
pub fn path_pattern_within(inner: &str, outer: &str) -> bool {
    if outer == "**" {
        return true;
    }
    if inner == "**" {
        return false;
    }
    match (inner.strip_suffix("/**"), outer.strip_suffix("/**")) {
        (_, None) => inner == outer,
        (Some(i), Some(o)) => i == o || path_matches(outer, i),
        (None, Some(_)) => path_matches(outer, inner),
    }
}

/// Symbol patterns: `Name.member` exactly, or a prefix ending in `*`
/// (`BillingClient.*`, `*`).
pub fn validate_symbol_pattern(p: &str) -> Result<()> {
    let body = p.strip_suffix('*').unwrap_or(p);
    if body.contains('*') || p.is_empty() || p.len() > 512 {
        return Err(Error::Invalid(format!(
            "symbol pattern {p:?}: '*' only at the end"
        )));
    }
    Ok(())
}

pub fn symbol_matches(pattern: &str, symbol: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => symbol.starts_with(prefix),
        None => pattern == symbol,
    }
}

pub fn symbol_pattern_within(inner: &str, outer: &str) -> bool {
    match (inner.strip_suffix('*'), outer.strip_suffix('*')) {
        (_, None) => inner == outer,
        (Some(i), Some(o)) => i.starts_with(o),
        (None, Some(o)) => inner.starts_with(o),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_folds_to_what_a_case_folding_file_system_reads() {
        for (written, read) in [
            ("crates/x/Build.RS", "crates/x/build.rs"),
            (".Cargo/Config.toml", ".cargo/config.toml"),
            ("Cargo.loc\u{212A}", "cargo.lock"),
            ("ta\u{17F}ks.json", "tasks.json"),
            ("Docker\u{FB01}le", "dockerfile"),
            ("Ma\u{DF}", "mass"),
            ("bu\u{200C}ild.rs", "build.rs"),
            ("\u{FEFF}build.rs", "build.rs"),
            ("src/**", "src/**"),
            ("**/*.CSPROJ", "**/*.csproj"),
            // Letters outside ASCII stand as written.
            (
                "\u{C7}ekirdek/\u{130}\u{15E}.rs",
                "\u{C7}ekirdek/\u{130}\u{15E}.rs",
            ),
        ] {
            assert_eq!(folded(written), read, "{written:?}");
        }
    }

    #[test]
    fn workspace_metadata_is_the_first_component_in_any_case() {
        for p in [".lonca", ".lonca/session", ".LONCA/session", ".Lonca/a/b"] {
            assert!(is_workspace_metadata(p), "{p}");
        }
        for p in ["src/.lonca/x", ".lonca2/x", "lonca/x", ""] {
            assert!(!is_workspace_metadata(p), "{p}");
        }
    }

    #[test]
    fn path_validation() {
        assert!(validate_repo_path("src/a.rs").is_ok());
        for bad in [
            "",
            "/etc/passwd",
            "a/../b",
            "a//b",
            ".git/config",
            "a/.GIT/x",
            "a\\b",
            "dir/",
            "a/\u{202E}b",
        ] {
            assert!(
                validate_repo_path(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn a_path_may_be_4096_bytes_long() {
        assert!(validate_repo_path(&"a".repeat(4096)).is_ok());
        assert!(validate_repo_path(&"a".repeat(4097)).is_err());
        let deep = format!("{}/b", "a".repeat(4094));
        assert_eq!(deep.len(), 4096);
        assert!(validate_repo_path(&deep).is_ok());
    }

    #[test]
    fn path_patterns() {
        assert!(path_matches("src/**", "src/a.rs"));
        assert!(path_matches("src/**", "src/x/y.rs"));
        assert!(!path_matches("src/**", "srcx/a.rs"));
        assert!(!path_matches("src/**", "src"));
        assert!(path_matches("src/a.rs", "src/a.rs"));
        assert!(path_matches("**", "anything/at/all"));
        assert!(validate_path_pattern("src/*.rs").is_err());
    }

    #[test]
    fn path_containment() {
        assert!(path_pattern_within("src/billing/**", "src/**"));
        assert!(path_pattern_within("src/billing/a.ts", "src/**"));
        assert!(path_pattern_within("src/**", "src/**"));
        assert!(!path_pattern_within("src/**", "src/billing/**"));
        assert!(!path_pattern_within("**", "src/**"));
        assert!(!path_pattern_within("src/a.ts", "src/b.ts"));
        assert!(path_pattern_within("anything/**", "**"));
    }

    #[test]
    fn symbol_patterns() {
        assert!(symbol_matches("BillingClient.*", "BillingClient.charge"));
        assert!(!symbol_matches("BillingClient.*", "Other.charge"));
        assert!(symbol_pattern_within(
            "BillingClient.charge",
            "BillingClient.*"
        ));
        assert!(symbol_pattern_within("BillingClient.c*", "BillingClient.*"));
        assert!(!symbol_pattern_within(
            "BillingClient.*",
            "BillingClient.charge"
        ));
        assert!(symbol_pattern_within("X", "*"));
        assert!(validate_symbol_pattern("a*b").is_err());
        assert!(validate_symbol_pattern("").is_err());
        assert!(validate_symbol_pattern(&"a".repeat(512)).is_ok());
        assert!(validate_symbol_pattern(&format!("{}*", "a".repeat(511))).is_ok());
        assert!(validate_symbol_pattern(&"a".repeat(513)).is_err());
    }
}
