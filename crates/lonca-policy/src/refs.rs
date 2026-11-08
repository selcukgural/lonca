//! Which refs a repository may hold, and what the log says each must name.
//! The daemon's `reconcile()` and the auditor ask the same function, so a
//! write behind the daemon's back reads the same to both.

use lonca_core::oplog::OPLOG_REF;
use lonca_core::{ChangeId, GitId};

use crate::state::State;

pub const TRUNK_REF: &str = "refs/heads/main";
pub const POLICY_REF: &str = "refs/lonca/policy";
/// `refs/lonca/changes/<change>/<seq>`: the commit of each proposal.
pub const CHANGES_PREFIX: &str = "refs/lonca/changes/";
/// Where fetches land before a logged operation takes them: an import's
/// first trunk and an incoming branch. Their content is no decision's.
pub const STAGING_REFS: [&str; 2] = ["refs/lonca/import/initial", "refs/lonca/incoming"];

/// What a ref found in the store is, as far as the log goes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefCheck {
    /// It names what the log says (or is a staging ref).
    Fine,
    /// A ref the log has, naming something else; `None` where the log has
    /// no value yet (before genesis).
    Differs(Option<GitId>),
    /// The ref of a proposal past the end of the log: written before its
    /// entry, which never came (the daemon stopped in between).
    NotLogged,
    /// A ref the daemon never writes.
    Unknown,
}

/// The change and sequence number of a proposal's ref.
pub fn change_ref(name: &str) -> Option<(ChangeId, u64)> {
    let rest = name.strip_prefix(CHANGES_PREFIX)?;
    let (change, seq) = rest.split_once('/')?;
    let parsed = (ChangeId::from_reverse_hex(change)?, seq.parse().ok()?);
    // One name per proposal: `07` or `+7` is another ref.
    (change_ref_name(&parsed.0, parsed.1) == name).then_some(parsed)
}

/// The ref of the proposal `change` at `seq`.
pub fn change_ref_name(change: &ChangeId, seq: u64) -> String {
    format!("{CHANGES_PREFIX}{change}/{seq}")
}

/// Checks one ref of the store against `state`. The operation log's own ref
/// is `Fine` here: what it must be is the reader's head, which the state
/// does not hold.
pub fn check(state: &State, name: &str, found: &GitId) -> RefCheck {
    let against = |want: &Option<GitId>| match want {
        Some(w) if w == found => RefCheck::Fine,
        w => RefCheck::Differs(w.clone()),
    };
    match name {
        TRUNK_REF => against(&state.trunk),
        POLICY_REF => against(&state.policy),
        OPLOG_REF => RefCheck::Fine,
        n if STAGING_REFS.contains(&n) => RefCheck::Fine,
        n => match change_ref(n) {
            Some((_, seq)) if seq >= state.next_seq => RefCheck::NotLogged,
            Some((change, seq)) => match state.proposed.get(&seq) {
                Some((c, commit)) if *c == change && commit == found => RefCheck::Fine,
                Some((c, commit)) if *c == change => RefCheck::Differs(Some(commit.clone())),
                _ => RefCheck::Unknown,
            },
            None => RefCheck::Unknown,
        },
    }
}

/// The proposal refs the log has and `present` lacks, with what each must
/// name.
pub fn missing_changes<'a>(
    state: &'a State,
    present: &'a std::collections::BTreeSet<String>,
) -> impl Iterator<Item = (String, &'a GitId)> + 'a {
    state
        .proposed
        .iter()
        .map(|(seq, (change, commit))| (change_ref_name(change, *seq), commit))
        .filter(move |(name, _)| !present.contains(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gid(c: char) -> GitId {
        GitId(std::iter::repeat_n(c, 40).collect())
    }

    #[test]
    fn every_ref_is_known_named_right_or_reported() {
        let c = ChangeId::random();
        let mut s = State {
            trunk: Some(gid('a')),
            policy: Some(gid('b')),
            next_seq: 5,
            ..State::default()
        };
        s.proposed.insert(3, (c, gid('c')));
        assert_eq!(check(&s, TRUNK_REF, &gid('a')), RefCheck::Fine);
        assert_eq!(
            check(&s, TRUNK_REF, &gid('x')),
            RefCheck::Differs(Some(gid('a')))
        );
        assert_eq!(
            check(&s, POLICY_REF, &gid('x')),
            RefCheck::Differs(Some(gid('b')))
        );
        assert_eq!(check(&s, OPLOG_REF, &gid('x')), RefCheck::Fine);
        for staging in STAGING_REFS {
            assert_eq!(check(&s, staging, &gid('x')), RefCheck::Fine);
        }
        let own = change_ref_name(&c, 3);
        assert_eq!(check(&s, &own, &gid('c')), RefCheck::Fine);
        assert_eq!(
            check(&s, &own, &gid('x')),
            RefCheck::Differs(Some(gid('c')))
        );
        assert_eq!(
            check(&s, &change_ref_name(&c, 4), &gid('c')),
            RefCheck::Unknown
        );
        let other = ChangeId::random();
        assert_eq!(
            check(&s, &change_ref_name(&other, 3), &gid('c')),
            RefCheck::Unknown
        );
        assert_eq!(
            check(&s, &change_ref_name(&c, 5), &gid('c')),
            RefCheck::NotLogged
        );
        for unknown in [
            "refs/heads/other",
            "refs/tags/v1",
            "refs/lonca/other",
            "refs/lonca/changes/x/1",
            "refs/lonca/changes/1",
            "refs/notes/commits",
        ] {
            assert_eq!(
                check(&s, unknown, &gid('c')),
                RefCheck::Unknown,
                "{unknown}"
            );
        }
        let before = State::default();
        assert_eq!(
            check(&before, TRUNK_REF, &gid('a')),
            RefCheck::Differs(None)
        );
    }

    #[test]
    fn a_change_ref_parses_back() {
        let c = ChangeId::random();
        assert_eq!(change_ref(&change_ref_name(&c, 7)), Some((c, 7)));
        let name = format!("{CHANGES_PREFIX}{c}/+7");
        assert_eq!(change_ref(&name), None);
        assert_eq!(change_ref(&format!("{CHANGES_PREFIX}{c}/x")), None);
        assert_eq!(change_ref(&format!("{CHANGES_PREFIX}{c}/07")), None);
        assert_eq!(change_ref(&format!("{CHANGES_PREFIX}{c}")), None);
        assert_eq!(change_ref("refs/heads/main"), None);
    }

    #[test]
    fn missing_proposal_refs_are_found() {
        let (a, b) = (ChangeId::random(), ChangeId::random());
        let mut s = State::default();
        s.proposed.insert(1, (a, gid('a')));
        s.proposed.insert(2, (b, gid('b')));
        let present = [change_ref_name(&a, 1)].into_iter().collect();
        let missing: Vec<_> = missing_changes(&s, &present).collect();
        assert_eq!(missing, [(change_ref_name(&b, 2), &gid('b'))]);
    }
}
