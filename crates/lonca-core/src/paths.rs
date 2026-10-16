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
        Some(prefix) => path.len() > prefix.len() && path.starts_with(prefix) && path.as_bytes()[prefix.len()] == b'/',
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
        return Err(Error::Invalid(format!("symbol pattern {p:?}: '*' only at the end")));
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
    fn path_validation() {
        assert!(validate_repo_path("src/a.rs").is_ok());
        for bad in ["", "/etc/passwd", "a/../b", "a//b", ".git/config", "a/.GIT/x", "a\\b", "dir/", "a/\u{202E}b"] {
            assert!(validate_repo_path(bad).is_err(), "{bad:?} should be rejected");
        }
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
        assert!(symbol_pattern_within("BillingClient.charge", "BillingClient.*"));
        assert!(symbol_pattern_within("BillingClient.c*", "BillingClient.*"));
        assert!(!symbol_pattern_within("BillingClient.*", "BillingClient.charge"));
        assert!(symbol_pattern_within("X", "*"));
        assert!(validate_symbol_pattern("a*b").is_err());
    }
}
