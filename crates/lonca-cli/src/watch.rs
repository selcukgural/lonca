//! `lonca events --watch`: a runner waits, with its human session, for what
//! it should wake one of its agents for (`events.watch`). Nothing is marked
//! as read and no message text comes: the agent reads that itself.

use anyhow::Result;
use lonca_client::protocol::{EndedSession, Watch, Watched, WatchedEvent};

use crate::ctx;

/// One wait, or with `follow` one after another until the reader goes,
/// every named session has ended, or a call fails.
pub fn run(repo: &str, human: &str, mut w: Watch, follow: bool, as_json: bool) -> Result<()> {
    let mut c = crate::human_client(repo, human)?;
    loop {
        let v = ctx::call(&mut c, "events.watch", serde_json::to_value(&w)?)?;
        let got: Watched = serde_json::from_value(v.clone())?;
        if !follow {
            if as_json {
                return ctx::print_json(&v);
            }
            for e in &got.events {
                outln!("{}", event_line(e));
            }
            for g in &got.ended {
                outln!("{}", ended_line(g));
            }
            outln!("next {}", got.next);
            if !got.reserved.is_empty() {
                outln!("reserved {}", got.reserved.join(","));
            }
            return Ok(());
        }
        for e in &got.events {
            if as_json {
                outln!("{}", serde_json::to_string(e)?);
            } else {
                outln!("{}", event_line(e));
            }
        }
        for g in &got.ended {
            if as_json {
                let line =
                    serde_json::json!({"session": g.session, "kind": "ended", "reason": g.reason});
                outln!("{line}");
            } else {
                outln!("{}", ended_line(g));
            }
        }
        if crate::out::closed() {
            return Ok(());
        }
        w = w.after(&got);
        if let Some(named) = &mut w.sessions {
            named.retain(|s| !got.ended.iter().any(|g| g.session == *s));
            if named.is_empty() {
                return Ok(());
            }
        }
    }
}

/// `s2 lease_received seq 12 from s1`
fn event_line(e: &WatchedEvent) -> String {
    let mut line = format!("{} {}", e.session, e.kind);
    if let Some(seq) = e.seq {
        line.push_str(&format!(" seq {seq}"));
    }
    if let Some(change) = &e.change {
        line.push_str(&format!(" change {change}"));
    }
    if let Some(from) = &e.from {
        line.push_str(&format!(" from {from}"));
    }
    if let Some(r) = &e.reservation {
        line.push_str(&format!(" reservation {r}"));
    }
    if let Some(until) = e.until_ms {
        line.push_str(&format!(" until_ms {until}"));
    }
    line
}

fn ended_line(g: &EndedSession) -> String {
    format!("{} ended: {}", g.session, g.reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_says_what_it_knows_and_nothing_else() {
        let e = WatchedEvent {
            session: "s2".into(),
            kind: "lease_received".into(),
            seq: Some(12),
            change: None,
            from: Some("s1".into()),
            reservation: None,
            until_ms: None,
        };
        assert_eq!(event_line(&e), "s2 lease_received seq 12 from s1");
        let r = WatchedEvent {
            session: "s1".into(),
            kind: "reserved".into(),
            seq: None,
            change: None,
            from: None,
            reservation: Some("ab12".into()),
            until_ms: Some(9),
        };
        assert_eq!(event_line(&r), "s1 reserved reservation ab12 until_ms 9");
        let g = EndedSession {
            session: "s1".into(),
            reason: "expired".into(),
        };
        assert_eq!(ended_line(&g), "s1 ended: expired");
    }
}
