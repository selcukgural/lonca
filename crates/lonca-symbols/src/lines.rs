//! Three-way merge by lines, for what has no symbols or sections.
//!
//! Two changes that meet are a conflict, and so are two that could stand in
//! one place: among repeated lines a diff can only guess which line a change
//! took, and a guess can drop one side's work with no conflict. So changes
//! are compared over [`reach`], everywhere they could stand with the same
//! result, not only where the diff put them.
//!
//! The diff library is part of the symbol engine: an update that changes
//! what this produces is a new engine version.

use std::collections::BTreeSet;
use std::ops::Range;

use similar::{DiffTag, TextDiff};

/// What a conflict's markers start with. `tag` on each marks them as ones
/// a sync wrote, so that a file can hold such a line of its own, and any of
/// the three left behind shows, wherever in a file it ended up.
const OURS: &str = "<<<<<<< local";
const BETWEEN: &str = "=======";
const THEIRS: &str = ">>>>>>> trunk";

#[derive(Clone, Debug, PartialEq, Eq)]
struct Change {
    /// The lines of the base that go.
    at: Range<usize>,
    /// What stands there instead.
    text: String,
}

/// A stretch of the result.
#[derive(Debug, PartialEq, Eq)]
enum Piece {
    Merged(String),
    Conflict { ours: String, theirs: String },
}

/// The lines of `base`, and what `side` changed in them.
fn changes(base: &str, side: &str) -> (Vec<String>, Vec<Change>) {
    let diff = TextDiff::from_lines(base, side);
    let lines = diff.iter_old_slices().map(str::to_string).collect();
    let new: Vec<&str> = diff.iter_new_slices().collect();
    let changed = diff.ops().iter().filter(|op| op.tag() != DiffTag::Equal);
    let change = |op: &similar::DiffOp| Change {
        at: op.old_range(),
        text: new[op.new_range()].concat(),
    };
    (lines, changed.map(change).collect())
}

/// Every place `change` could stand with the same text as the result: lines
/// taken out of a run of equal lines, or added beside lines equal to them.
fn reach(base: &[String], change: &Change) -> Range<usize> {
    let (start, end) = (change.at.start, change.at.end);
    let added: Vec<&str> = change.text.split_inclusive('\n').collect();
    if added.is_empty() {
        let back = (1..=start).take_while(|n| base[start - n] == base[end - n]);
        let on = (0..base.len() - end).take_while(|n| base[start + n] == base[end + n]);
        return start - back.count()..end + on.count();
    }
    if start != end {
        return change.at.clone();
    }
    let last = added.len() - 1;
    let back = (0..start).take_while(|n| base[start - 1 - n] == added[last - n % added.len()]);
    let on = (0..base.len() - start).take_while(|n| base[start + n] == added[n % added.len()]);
    start - back.count()..start + on.count()
}

fn meets(a: &Range<usize>, b: &Range<usize>) -> bool {
    a.start <= b.end && b.start <= a.end
}

/// `base[from..to]` with `changes` in it.
fn applied(base: &[String], from: usize, to: usize, changes: &[&Change]) -> String {
    let mut sorted = changes.to_vec();
    sorted.sort_by_key(|c| (c.at.start, c.at.end));
    let mut out = String::new();
    let mut done = from;
    for c in sorted {
        out.push_str(&base[done..c.at.start].concat());
        out.push_str(&c.text);
        done = c.at.end;
    }
    out.push_str(&base[done..to].concat());
    out
}

fn pieces(b: &str, o: &str, t: &str) -> Vec<Piece> {
    let (base, ours) = changes(b, o);
    let (_, theirs) = changes(b, t);
    let same = |c: &'_ Change| (c.at.start, c.at.end, c.text.clone());
    let mine: BTreeSet<_> = ours.iter().map(same).collect();
    let theirs: Vec<Change> = theirs
        .into_iter()
        .filter(|c| !mine.contains(&same(c)))
        .collect();
    // Each change with its side and its reach, by where that starts.
    let mut all: Vec<(bool, &Change, Range<usize>)> = Vec::new();
    all.extend(ours.iter().map(|c| (true, c, reach(&base, c))));
    all.extend(theirs.iter().map(|c| (false, c, reach(&base, c))));
    all.sort_by_key(|(_, c, reach)| (reach.start, c.at.start, c.at.end));
    let mut out = Vec::new();
    let mut done = 0;
    let mut rest = all.into_iter().peekable();
    while let Some(first) = rest.next() {
        let mut span = first.2.clone();
        let mut near = vec![first];
        while let Some(next) = rest.next_if(|(_, _, r)| meets(r, &span)) {
            span.end = span.end.max(next.2.end);
            near.push(next);
        }
        let of = |side: bool| -> Vec<&Change> {
            let mine = near.iter().filter(|(s, ..)| *s == side);
            mine.map(|(_, c, _)| *c).collect()
        };
        let (mine, other) = (of(true), of(false));
        let from = near
            .iter()
            .map(|(_, c, _)| c.at.start)
            .min()
            .unwrap_or(done);
        let to = near.iter().map(|(_, c, _)| c.at.end).max().unwrap_or(done);
        out.push(Piece::Merged(base[done..from].concat()));
        if mine.is_empty() || other.is_empty() {
            let one: Vec<&Change> = near.iter().map(|(_, c, _)| *c).collect();
            out.push(Piece::Merged(applied(&base, from, to, &one)));
        } else {
            out.push(Piece::Conflict {
                ours: applied(&base, from, to, &mine),
                theirs: applied(&base, from, to, &other),
            });
        }
        done = to;
    }
    out.push(Piece::Merged(base[done..].concat()));
    out
}

/// The merge of `o` and `t` from `b`, if their changes do not meet.
pub fn merge(b: &str, o: &str, t: &str) -> Option<String> {
    let merged = pieces(b, o, t).into_iter().map(|piece| match piece {
        Piece::Merged(text) => Some(text),
        Piece::Conflict { .. } => None,
    });
    merged.collect()
}

/// The merge with what could not be merged written out, both sides between
/// markers. Everything else of both sides is in the text, so settling a
/// conflict takes back nothing that stands outside it.
pub fn with_markers(b: &str, o: &str, t: &str, tag: &str) -> String {
    let render = |piece: Piece| match piece {
        Piece::Merged(text) => text,
        Piece::Conflict { ours, theirs } => conflict_block(&ours, &theirs, tag),
    };
    pieces(b, o, t).into_iter().map(render).collect()
}

/// Both sides of a conflict, each marker on a line of its own.
pub fn conflict_block(ours: &str, theirs: &str, tag: &str) -> String {
    let line_of = |text: &str| match text.is_empty() || text.ends_with('\n') {
        true => text.to_string(),
        false => format!("{text}\n"),
    };
    let (ours, theirs) = (line_of(ours), line_of(theirs));
    format!("{OURS} {tag}\n{ours}{BETWEEN} {tag}\n{theirs}{THEIRS} {tag}\n")
}

/// `text` holds a marker of a conflict tagged `tag`: any of the three, on a
/// line of its own or not, since one can follow a line end of another kind.
pub fn has_markers(text: &str, tag: &str) -> bool {
    [OURS, BETWEEN, THEIRS]
        .iter()
        .any(|m| text.contains(&format!("{m} {tag}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const B: &str = "a\nb\nc\nd\ne\nf\ng\n";

    #[test]
    fn a_change_both_sides_made_counts_once_among_others() {
        let o = "a\nX\nc\nd\nO\nf\ng\n";
        let t = "a\nX\nc\nd\ne\nf\nT\n";
        assert_eq!(merge(B, o, t).as_deref(), Some("a\nX\nc\nd\nO\nf\nT\n"));
        let t = "a\nY\nc\nd\ne\nf\ng\n";
        assert_eq!(merge(B, o, t), None);
    }

    #[test]
    fn changes_apart_merge() {
        let o = "a\nO\nc\nd\ne\nf\ng\n";
        let t = "a\nb\nc\nd\ne\nT\ng\n";
        assert_eq!(merge(B, o, t).as_deref(), Some("a\nO\nc\nd\ne\nT\ng\n"));
        assert_eq!(merge(B, t, o).as_deref(), Some("a\nO\nc\nd\ne\nT\ng\n"));
        let t = "a\nb\nc\nT\ne\nf\ng\n";
        assert_eq!(merge(B, o, t).as_deref(), Some("a\nO\nc\nT\ne\nf\ng\n"));
    }

    #[test]
    fn a_side_alone_is_taken_as_it_is() {
        for text in ["", "x", "x\n", "a\r\nb\r\n", B] {
            assert_eq!(merge(B, B, text).as_deref(), Some(text));
            assert_eq!(merge(B, text, B).as_deref(), Some(text));
            assert_eq!(merge(B, text, text).as_deref(), Some(text));
        }
        assert_eq!(merge("a", "a", "b").as_deref(), Some("b"));
        assert_eq!(merge("", "x\n", "").as_deref(), Some("x\n"));
    }

    /// Lines next to each other are no lines apart.
    #[test]
    fn changes_that_touch_meet() {
        let o = "a\nO\nc\nd\ne\nf\ng\n";
        assert_eq!(merge(B, o, "a\nb\nT\nd\ne\nf\ng\n"), None);
        assert_eq!(merge(B, o, "a\nT\nc\nd\ne\nf\ng\n"), None);
        assert_eq!(merge(B, o, "T\nb\nc\nd\ne\nf\ng\n"), None);
    }

    #[test]
    fn additions_at_one_place_meet() {
        let (o, t) = ("a\nO\nb\nc\nd\ne\nf\ng\n", "a\nT\nb\nc\nd\ne\nf\ng\n");
        assert_eq!(merge(B, o, t), None);
        assert_eq!(merge("", "o\n", "t\n"), None);
    }

    /// One edits a copy of a line and the other takes one out: which copy
    /// is a guess, and the guess must not lose the deletion.
    #[test]
    fn a_change_among_equal_lines_reaches_all_of_them() {
        let b = "retry\nretry\nretry\n";
        assert_eq!(merge(b, "abort\nretry\nretry\n", "retry\nretry\n"), None);
        assert_eq!(merge(b, "retry\nretry\n", "retry\nabort\nretry\n"), None);
    }

    #[test]
    fn what_a_change_reaches() {
        let base: Vec<String> = ["x\n", "l\n", "l\n", "l\n", "y\n"]
            .map(str::to_string)
            .into();
        let reach_of = |at: Range<usize>, text: &str| {
            let c = Change {
                at,
                text: text.to_string(),
            };
            reach(&base, &c)
        };
        assert_eq!(reach_of(2..3, ""), 1..4, "a line out of the run");
        assert_eq!(reach_of(1..2, ""), 1..4);
        assert_eq!(reach_of(3..4, ""), 1..4);
        assert_eq!(reach_of(0..1, ""), 0..1, "a line that is there once");
        assert_eq!(reach_of(4..5, ""), 4..5);
        assert_eq!(reach_of(1..3, ""), 1..4, "two of them");
        assert_eq!(reach_of(2..2, "l\n"), 1..4, "one more of them");
        assert_eq!(reach_of(1..1, "l\n"), 1..4);
        assert_eq!(reach_of(4..4, "l\n"), 1..4);
        assert_eq!(reach_of(1..1, "z\n"), 1..1, "a new line");
        assert_eq!(reach_of(5..5, "y\n"), 4..5, "at the end, like the last");
        assert_eq!(reach_of(0..0, "x\n"), 0..1, "at the start, like the first");
        assert_eq!(reach_of(2..3, "z\n"), 2..3, "a replaced line stays");
        assert_eq!(
            reach_of(2..2, "z\nl\n"),
            1..2,
            "back over its own last line"
        );
        assert_eq!(reach_of(2..2, "l\nz\n"), 2..3, "on over its own first line");
    }

    /// A block added beside a copy of itself reaches over the copy.
    #[test]
    fn a_block_reaches_line_by_line() {
        let base: Vec<String> = ["a\n", "b\n", "a\n", "b\n", "c\n"]
            .map(str::to_string)
            .into();
        let c = Change {
            at: 2..2,
            text: "a\nb\n".to_string(),
        };
        assert_eq!(reach(&base, &c), 0..4);
    }

    /// Everything of both sides stands in the text, in or out of a conflict.
    #[test]
    fn markers_hold_both_sides_and_the_rest_comes_in() {
        let o = "a\nO\nc\nd\ne\nf\ng\n";
        let t = "a\nT\nT2\nd\ne\nT3\ng\n";
        let text = with_markers(B, o, t, "k");
        assert_eq!(
            text,
            "a\n<<<<<<< local k\nO\nc\n======= k\nT\nT2\n>>>>>>> trunk k\nd\ne\nT3\ng\n"
        );
        assert_eq!(with_markers(B, B, t, "k"), t);
    }

    /// Any of the three shows, and nothing but a marker with the tag.
    #[test]
    fn what_counts_as_a_marker() {
        for one in ["<<<<<<< local k", "======= k", ">>>>>>> trunk k"] {
            assert!(has_markers(&format!("a\n{one}\nb\n"), "k"), "{one}");
            assert!(
                has_markers(&format!("a\r{one}\n"), "k"),
                "after a CR: {one}"
            );
        }
        for not_one in [
            "<<<<<<< local\n",
            "=======\n",
            ">>>>>>> trunk m\n",
            "plain\n",
        ] {
            assert!(!has_markers(not_one, "k"), "{not_one}");
        }
    }

    #[test]
    fn a_marker_stands_on_its_own_line() {
        assert_eq!(
            with_markers("a", "o", "t", "k"),
            "<<<<<<< local k\no\n======= k\nt\n>>>>>>> trunk k\n"
        );
        assert_eq!(
            with_markers("a\n", "", "t\n", "k"),
            "<<<<<<< local k\n======= k\nt\n>>>>>>> trunk k\n"
        );
    }

    /// Changes of one side that touch each other are no conflict with
    /// anybody, however near the other side's are.
    #[test]
    fn one_side_never_meets_itself() {
        let o = "O\nO2\nc\nd\ne\nf\ng\n";
        assert_eq!(
            merge(B, o, "a\nb\nc\nd\nT\nf\ng\n").as_deref(),
            Some("O\nO2\nc\nd\nT\nf\ng\n")
        );
    }

    /// The same change on both sides is one change, and a change of the
    /// other side beside it stays apart from it only if it is apart.
    #[test]
    fn the_same_change_on_both_sides_is_taken_once() {
        let o = "a\nS\nc\nd\ne\nf\ng\n";
        let t = "a\nS\nc\nd\ne\nT\ng\n";
        assert_eq!(merge(B, o, t).as_deref(), Some("a\nS\nc\nd\ne\nT\ng\n"));
    }

    /// With distinct lines the result holds every line each side kept or
    /// added, whatever the changes are.
    #[test]
    fn nothing_is_lost_from_distinct_lines() {
        let base: Vec<String> = (0..12).map(|i| format!("l{i}\n")).collect();
        let b = base.concat();
        let mut state = 7u64;
        let mut next = |m: u64| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (state >> 33) % m
        };
        for round in 0..3000 {
            let mut side = |tag: &str| {
                let mut v = base.clone();
                for n in 0..=next(3) {
                    let at = next(v.len() as u64) as usize;
                    match next(3) {
                        0 => {
                            v.remove(at);
                        }
                        1 => v[at] = format!("{tag}{round}.{n}\n"),
                        _ => v.insert(at, format!("{tag}{round}.{n}+\n")),
                    }
                }
                v.concat()
            };
            let (o, t) = (side("o"), side("t"));
            let Some(m) = merge(&b, &o, &t) else { continue };
            let lines: Vec<&str> = m.lines().collect();
            for (one, other) in [(&o, &t), (&t, &o)] {
                for l in one.lines() {
                    let kept_by_other = other.lines().any(|x| x == l);
                    let in_base = base.iter().any(|x| x.trim_end() == l);
                    assert!(
                        lines.contains(&l) || (in_base && !kept_by_other),
                        "{l} lost: b={b:?} o={o:?} t={t:?} m={m:?}"
                    );
                }
            }
        }
    }
}
