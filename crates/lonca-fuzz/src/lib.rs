//! What each fuzz target checks (#15, docs/fuzzing.md).
//!
//! Every input that crosses a trust boundary has a target here: one stored
//! log entry, a whole log as the auditor reads it, a line on the daemon's
//! socket, a hook event, a file the symbol engine reads, a three-way merge,
//! a repository's configuration and policy, and a signature made with a
//! security key. A target is a function of
//! bytes that panics when what it checks does not hold; every input the
//! engine accepts must leave it quiet.
//!
//! `fuzz/` (a cargo-fuzz project outside the workspace) hands these
//! functions to libFuzzer; `tests/inputs.rs` runs every saved input, the
//! seeds and each crash kept as a regression, through them with
//! `cargo test`, so a crash once found stays fixed.

#![forbid(unsafe_code)]

pub mod entry;
pub mod hook;
pub mod merge;
pub mod parse;
pub mod policy;
pub mod replay;
pub mod request;
pub mod signature;
pub mod template;

/// What a target is: bytes in, a panic if what it holds does not.
pub type Check = fn(&[u8]);

/// Every target by its name, which is also its directory under
/// `fuzz/seeds/` and `fuzz/regressions/` and its binary in `fuzz/`.
pub const TARGETS: &[(&str, Check)] = &[
    ("entry", entry::check),
    ("hook", hook::check),
    ("merge", merge::check),
    ("parse", parse::check),
    ("policy", policy::check),
    ("replay", replay::check),
    ("request", request::check),
    ("signature", signature::check),
];

/// Where several texts share one input, they are cut at this byte: a NUL,
/// which no text the targets read needs.
pub const CUT: u8 = 0;

/// The first byte, to choose with, and the rest; nothing for no input.
pub fn choice(data: &[u8]) -> Option<(u8, &[u8])> {
    data.split_first().map(|(&c, rest)| (c, rest))
}

/// `data` cut at [`CUT`] into exactly `N` texts: the last takes the rest,
/// and missing ones are empty. Invalid UTF-8 is replaced, as a reader of
/// text would.
pub fn texts<const N: usize>(data: &[u8]) -> [String; N] {
    let mut parts = data.splitn(N, |&b| b == CUT);
    std::array::from_fn(|_| String::from_utf8_lossy(parts.next().unwrap_or(&[])).into_owned())
}

/// One of `items`, by `c`; `None` if there are none.
pub fn pick<T>(items: &[T], c: u8) -> Option<&T> {
    items.get(usize::from(c) % items.len().max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_are_cut_at_nul_and_padded() {
        let [a, b, c] = texts::<3>(b"x\0y\0z\0w");
        assert_eq!((a.as_str(), b.as_str(), c.as_str()), ("x", "y", "z\0w"));
        let [a, b] = texts::<2>(b"only");
        assert_eq!((a.as_str(), b.as_str()), ("only", ""));
        let [a] = texts::<1>(b"\xff");
        assert_eq!(a, "\u{fffd}");
    }

    #[test]
    fn a_choice_wraps_around() {
        assert_eq!(pick(&[1, 2, 3], 4), Some(&2));
        assert_eq!(pick::<u8>(&[], 4), None);
        assert_eq!(choice(b""), None);
        assert_eq!(choice(b"ab"), Some((b'a', &b"b"[..])));
    }
}
