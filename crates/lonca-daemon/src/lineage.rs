//! Whose process is this: the processes a process descends from.
//!
//! The proxy charges a connection to a session by this, not by where the
//! connecting process stands: a process chooses its directory, it does not
//! choose its parents. A session is known by the processes it was bound
//! from (the hook program the harness ran, `lonca run` itself), and a
//! connection is its own when the connecting process meets them nearer than
//! it meets any other session's. A process that left its parents (they
//! ended, and the system gave it to another) meets every session where
//! they all meet, so every one of them answers for it.

use std::collections::{BTreeMap, HashMap};
use std::process::Command;

/// One process. Its number is used again once it is gone, so it is told
/// from a later one by when it started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proc {
    pub pid: u32,
    pub started: String,
}

/// How far up a line is followed. Deeper than any real one; a table that
/// loops ends here.
const DEPTH: usize = 64;

/// The processes of this machine at one moment: number, parent and start.
#[derive(Debug, Default)]
pub struct Table(HashMap<u32, (u32, String)>);

impl Table {
    /// Asks `ps`, which answers for every account's processes. `None` when
    /// it can not be run or says nothing.
    pub fn read() -> Option<Table> {
        let out = Command::new("ps")
            .env("LC_ALL", "C")
            .args(["-A", "-o", "pid=", "-o", "ppid=", "-o", "lstart="])
            .output()
            .ok()?;
        let table = Table::parse(&String::from_utf8_lossy(&out.stdout));
        (out.status.success() && !table.0.is_empty()).then_some(table)
    }

    /// Lines of `pid ppid start…`; one that does not read is left out.
    pub fn parse(text: &str) -> Table {
        let row = |l: &str| {
            let mut words = l.split_whitespace();
            let pid = words.next()?.parse::<u32>().ok()?;
            let ppid = words.next()?.parse::<u32>().ok()?;
            let started = words.collect::<Vec<_>>().join(" ");
            (!started.is_empty()).then_some((pid, (ppid, started)))
        };
        Table(text.lines().filter_map(row).collect())
    }

    /// `pid` and what it descends from, nearest first. Empty when there is
    /// no such process.
    pub fn line(&self, pid: u32) -> Vec<Proc> {
        let mut line = Vec::new();
        let mut cur = pid;
        while let Some((parent, started)) = self.0.get(&cur) {
            line.push(Proc {
                pid: cur,
                started: started.clone(),
            });
            if *parent == cur || line.len() == DEPTH {
                break;
            }
            cur = *parent;
        }
        line
    }

    /// Whether `p` is still running.
    pub fn has(&self, p: &Proc) -> bool {
        self.0.get(&p.pid).is_some_and(|(_, s)| *s == p.started)
    }
}

/// How many lines a session is known by. One more and it is known by none:
/// it answers for every connection it can not be told from (a session that
/// keeps binding from new places is not placed by any of them).
pub const MAX_LINES: usize = 8;

/// The lines one session was bound from.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Bound {
    lines: Vec<Vec<Proc>>,
    /// Bound from more places than are kept.
    lost: bool,
}

impl Bound {
    /// Adds `line`. Nothing is ever taken away but processes that ended, so
    /// a bind can add to what a session answers for and never lessen it.
    pub fn add(&mut self, line: Vec<Proc>, now: &Table) {
        if self.lost || line.is_empty() {
            return;
        }
        for l in &mut self.lines {
            l.retain(|p| now.has(p));
        }
        self.lines.push(line);
        let mut kept: Vec<Vec<Proc>> = Vec::new();
        for l in self.lines.drain(..) {
            if !l.is_empty() && !kept.contains(&l) {
                kept.push(l);
            }
        }
        self.lines = kept;
        if self.lines.len() > MAX_LINES {
            self.lines.clear();
            self.lost = true;
        }
    }

    /// Whether anything places this session.
    fn placed(&self) -> bool {
        !self.lost && !self.lines.is_empty()
    }

    /// How many processes up from the connecting one `line` first meets
    /// this session's.
    fn meets(&self, line: &[Proc]) -> Option<usize> {
        line.iter()
            .position(|p| self.lines.iter().any(|l| l.contains(p)))
    }
}

/// Which of `sessions` answer for a connection from the process of `line`,
/// and whether the line told any of them apart from nothing (`false`: the
/// process is unknown, or it descends from nothing a session was bound
/// from, and all of them answer).
///
/// Those that meet the line nearest answer, together when they meet it at
/// the same process; with them every session nothing places.
pub fn answering<K: Ord + Clone>(
    line: Option<&[Proc]>,
    sessions: &BTreeMap<K, Option<&Bound>>,
) -> (Vec<K>, bool) {
    let everyone = || sessions.keys().cloned().collect();
    let Some(line) = line.filter(|l| !l.is_empty()) else {
        return (everyone(), false);
    };
    // Where each session that something places meets the line.
    let met = |b: &Option<&Bound>| b.filter(|b| b.placed())?.meets(line);
    let Some(nearest) = sessions.values().filter_map(met).min() else {
        return (everyone(), false);
    };
    let answers = |b: &Option<&Bound>| match b.filter(|b| b.placed()) {
        Some(b) => b.meets(line) == Some(nearest),
        None => true,
    };
    let who = sessions.iter().filter(|(_, b)| answers(b));
    (who.map(|(k, _)| k.clone()).collect(), true)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A machine: two harnesses under one shell, a third elsewhere.
    ///
    /// ```text
    /// 1 ─ 10 terminal ─ 20 shell ─ 30 harness a ─ 31 hook a
    ///   │                        │              └ 35 shell ─ 36 curl
    ///   │                        └ 40 harness b ─ 41 hook b
    ///   │                                       └ 45 curl
    ///   ├ 50 other terminal ─ 60 harness c ─ 61 hook c
    ///   └ 90 a process whose parents ended
    /// ```
    fn machine() -> Table {
        Table::parse(
            "1 0 Mon Jan 1 00:00:00 2026\n\
             10 1 Mon Jan 1 00:00:10 2026\n\
             20 10 Mon Jan 1 00:00:20 2026\n\
             30 20 Mon Jan 1 00:00:30 2026\n\
             31 30 Mon Jan 1 00:00:31 2026\n\
             35 30 Mon Jan 1 00:00:35 2026\n\
             36 35 Mon Jan 1 00:00:36 2026\n\
             40 20 Mon Jan 1 00:00:40 2026\n\
             41 40 Mon Jan 1 00:00:41 2026\n\
             45 40 Mon Jan 1 00:00:45 2026\n\
             50 1 Mon Jan 1 00:00:50 2026\n\
             60 50 Mon Jan 1 00:01:00 2026\n\
             61 60 Mon Jan 1 00:01:01 2026\n\
             90 1 Mon Jan 1 00:01:30 2026\n",
        )
    }

    fn bound(t: &Table, pids: &[u32]) -> Bound {
        let mut b = Bound::default();
        for pid in pids {
            b.add(t.line(*pid), t);
        }
        b
    }

    fn who(t: &Table, pid: u32, sessions: &[(&'static str, Option<&Bound>)]) -> (String, bool) {
        let map: BTreeMap<&str, Option<&Bound>> = sessions.iter().cloned().collect();
        let line = t.line(pid);
        let (keys, told) = answering(Some(&line), &map);
        (keys.join(","), told)
    }

    #[test]
    fn a_table_is_read_and_followed_up() {
        let t = machine();
        let pids = |pid| t.line(pid).iter().map(|p| p.pid).collect::<Vec<_>>();
        assert_eq!(pids(36), [36, 35, 30, 20, 10, 1]);
        assert_eq!(pids(1), [1]);
        assert_eq!(pids(7), [] as [u32; 0]);
        assert_eq!(t.line(36)[0].started, "Mon Jan 1 00:00:36 2026");
        // A line that does not read is left out, the rest stay.
        let t = Table::parse("x 1 Mon\n5 y Mon\n6 1\n7 1 Mon\n");
        assert_eq!(t.line(7).len(), 1);
        assert!(t.line(5).is_empty() && t.line(6).is_empty());
        // A table that loops ends.
        let t = Table::parse("2 3 a\n3 2 b\n4 4 c\n");
        assert_eq!(t.line(2).len(), DEPTH);
        assert_eq!(t.line(4).len(), 1);
    }

    #[test]
    fn the_real_table_has_this_process_and_its_parent() {
        let Some(t) = Table::read() else {
            return; // no ps here: nothing is told apart, which is tested above
        };
        let line = t.line(std::process::id());
        assert_eq!(line[0].pid, std::process::id());
        assert!(line.len() >= 2, "{line:?}");
        assert!(t.has(&line[1]));
        let later = Proc {
            pid: line[0].pid,
            started: "another time".into(),
        };
        assert!(!t.has(&later));
    }

    #[test]
    fn a_connection_is_of_the_session_it_descends_from() {
        let t = machine();
        let (a, b, c) = (bound(&t, &[31]), bound(&t, &[41]), bound(&t, &[61]));
        let all = [("a", Some(&a)), ("b", Some(&b)), ("c", Some(&c))];
        assert_eq!(who(&t, 36, &all), ("a".into(), true));
        assert_eq!(who(&t, 45, &all), ("b".into(), true));
        // The hook itself and the harness too.
        assert_eq!(who(&t, 61, &all), ("c".into(), true));
        assert_eq!(who(&t, 60, &all), ("c".into(), true));
    }

    #[test]
    fn a_process_that_left_its_parents_is_everyones() {
        let t = machine();
        let (a, b, c) = (bound(&t, &[31]), bound(&t, &[41]), bound(&t, &[61]));
        let all = [("a", Some(&a)), ("b", Some(&b)), ("c", Some(&c))];
        assert_eq!(who(&t, 90, &all), ("a,b,c".into(), true));
        // One that only shares a shell with two of them is theirs.
        let t2 = Table::parse(
            "1 0 x\n10 1 Mon Jan 1 00:00:10 2026\n20 10 Mon Jan 1 00:00:20 2026\n99 20 later\n",
        );
        assert_eq!(who(&t2, 99, &all), ("a,b".into(), true));
    }

    #[test]
    fn a_session_nothing_places_always_answers() {
        let t = machine();
        let (a, b) = (bound(&t, &[31]), Bound::default());
        let all = [("a", Some(&a)), ("b", Some(&b)), ("c", None)];
        assert_eq!(who(&t, 36, &all), ("a,b,c".into(), true));
        // And when nobody is placed, or the process is not known, all do.
        let none = [("b", Some(&b)), ("c", None)];
        assert_eq!(who(&t, 36, &none), ("b,c".into(), false));
        let map: BTreeMap<&str, Option<&Bound>> = all.iter().cloned().collect();
        assert_eq!(answering(None, &map), (vec!["a", "b", "c"], false));
        assert_eq!(answering(Some(&[]), &map), (vec!["a", "b", "c"], false));
        // A process of another machine's making meets nobody.
        let far = Table::parse("7 7 x\n");
        assert_eq!(
            answering(Some(&far.line(7)), &map),
            (vec!["a", "b", "c"], false)
        );
    }

    #[test]
    fn a_number_used_again_is_another_process() {
        let t = machine();
        let (a, b) = (bound(&t, &[31]), bound(&t, &[41]));
        let all = [("a", Some(&a)), ("b", Some(&b))];
        // Harness b ended; its number is a new process under harness a.
        let later = Table::parse(
            "1 0 Mon Jan 1 00:00:00 2026\n\
             10 1 Mon Jan 1 00:00:10 2026\n\
             20 10 Mon Jan 1 00:00:20 2026\n\
             30 20 Mon Jan 1 00:00:30 2026\n\
             40 30 Mon Jan 1 09:00:00 2026\n\
             46 40 Mon Jan 1 09:00:01 2026\n",
        );
        assert_eq!(who(&later, 46, &all), ("a".into(), true));
    }

    #[test]
    fn binding_again_adds_and_never_takes_away() {
        let t = machine();
        let mut a = bound(&t, &[31]);
        // The agent binds its own session from a process that left its
        // parents: the harness is still what the session is known by.
        a.add(t.line(90), &t);
        let b = bound(&t, &[41]);
        let all = [("a", Some(&a)), ("b", Some(&b))];
        assert_eq!(who(&t, 36, &all), ("a".into(), true));
        assert_eq!(who(&t, 45, &all), ("b".into(), true));

        // The same place twice is one line; ended processes fall out of the
        // old ones, so a harness that binds at every start stays small.
        let mut again = bound(&t, &[31, 31]);
        assert_eq!(again.lines.len(), 1);
        let hook_gone = Table::parse(
            "1 0 Mon Jan 1 00:00:00 2026\n\
             10 1 Mon Jan 1 00:00:10 2026\n\
             20 10 Mon Jan 1 00:00:20 2026\n\
             30 20 Mon Jan 1 00:00:30 2026\n\
             32 30 Mon Jan 1 00:02:00 2026\n",
        );
        for _ in 0..20 {
            again.add(hook_gone.line(32), &hook_gone);
        }
        assert_eq!(again.lines.len(), 2, "{again:?}");
        again.add(Vec::new(), &t);
        assert_eq!(again.lines.len(), 2);
    }

    #[test]
    fn bound_from_too_many_places_a_session_is_placed_by_none() {
        let t = machine();
        let mut a = Bound::default();
        let pids = [31, 36, 35, 41, 45, 61, 60, 90];
        assert_eq!(pids.len(), MAX_LINES);
        for pid in pids {
            a.add(t.line(pid), &t);
        }
        let b = bound(&t, &[41]);
        // Placed, and bound from harness b's hook among others: with b.
        assert!(a.placed());
        let all = [("a", Some(&a)), ("b", Some(&b))];
        assert_eq!(who(&t, 41, &all), ("a,b".into(), true));
        a.add(t.line(50), &t);
        assert!(!a.placed() && a.lines.is_empty());
        // Nothing brings it back, and it answers for what is b's alone.
        a.add(t.line(31), &t);
        assert!(!a.placed());
        let all = [("a", Some(&a)), ("b", Some(&b))];
        assert_eq!(who(&t, 45, &all), ("a,b".into(), true));
    }
}
