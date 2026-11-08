//! What the daemon heard from a session's hooks, to prove they run (#190).
//!
//! A harness whose before-tool event fires for MCP tools sends one for each
//! call to `lonca mcp` before the call is made. `lonca mcp` says which tool
//! it runs (`mcp.call`), and the daemon takes one event of that tool, in
//! order. A call with none means the hooks are not running. Kept in memory,
//! not in the log: only a miss is written, as an `unhooked` observation.

use std::collections::VecDeque;

/// How long an event waits for its call. Lonca's tools are allowed in the
/// harness's settings, so the call follows at once; an event whose call
/// never came (refused, or the harness gave up) must not stand in for a
/// later call.
pub const PENDING_MS: i64 = 10 * 60_000;

/// Most events one session keeps waiting: a harness calls a few tools at
/// once, not hundreds.
pub const MAX_PENDING: usize = 64;

/// After a start the daemon has heard nothing, so a call of a session older
/// than the daemon, whose event may have gone to the one before, is not taken
/// as a miss for this long. Short: the
/// hook blocks the call until it is answered, so only a restart between the
/// two loses an event, and `lonca mcp` reconnects within seconds.
pub const START_GRACE_MS: i64 = 10_000;

/// The longest tool name a call may give: it goes in the log on a miss.
pub const MAX_TOOL: usize = 64;

#[derive(Clone, Debug, Default)]
pub struct Hooked {
    /// Before-tool events of `lonca mcp`'s tools with no call yet: the tool,
    /// without the harness's prefix, and when.
    pending: VecDeque<(String, i64)>,
    /// When the last hook event of any kind came.
    pub last_ms: Option<i64>,
}

impl Hooked {
    /// Any hook event: the session's hooks are alive.
    pub fn heard(&mut self, now: i64) {
        self.last_ms = Some(now);
    }

    /// A before-tool event for one of `lonca mcp`'s tools.
    pub fn before(&mut self, tool: &str, now: i64) {
        self.heard(now);
        self.expire(now);
        if self.pending.len() >= MAX_PENDING {
            self.pending.pop_front();
        }
        self.pending.push_back((tool.to_string(), now));
    }

    /// Takes the oldest event waiting for `tool`; false when there is none.
    pub fn take(&mut self, tool: &str, now: i64) -> bool {
        self.expire(now);
        match self.pending.iter().position(|(t, _)| t == tool) {
            Some(i) => {
                self.pending.remove(i);
                true
            }
            None => false,
        }
    }

    fn expire(&mut self, now: i64) {
        while self
            .pending
            .front()
            .is_some_and(|(_, at)| now.saturating_sub(*at) > PENDING_MS)
        {
            self.pending.pop_front();
        }
    }

    #[cfg(test)]
    fn waiting(&self) -> Vec<&str> {
        self.pending.iter().map(|(t, _)| t.as_str()).collect()
    }
}

/// A name `lonca mcp` could give: what a tool is called, nothing else.
pub fn valid_tool(tool: &str) -> bool {
    !tool.is_empty()
        && tool.len() <= MAX_TOOL
        && tool
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_takes_one_event_of_its_own_tool_in_order() {
        let mut h = Hooked::default();
        assert!(!h.take("propose", 0), "nothing heard");
        h.before("lease", 1);
        h.before("propose", 2);
        h.before("lease", 3);
        assert!(!h.take("status", 4), "another tool's event is no proof");
        assert!(h.take("lease", 5));
        assert_eq!(h.waiting(), ["propose", "lease"], "the oldest went");
        assert!(h.take("lease", 5) && h.take("propose", 5));
        assert!(!h.take("propose", 5), "one event, one call");
        assert_eq!(h.last_ms, Some(3));
    }

    #[test]
    fn an_event_waits_for_its_call_only_so_long() {
        let mut h = Hooked::default();
        h.before("propose", 1000);
        assert!(h.take("propose", 1000 + PENDING_MS), "at the limit");
        h.before("propose", 1000);
        h.before("lease", 2000);
        assert!(!h.take("propose", 1001 + PENDING_MS), "past it");
        assert!(
            h.take("lease", 1001 + PENDING_MS),
            "a later one still waits"
        );
        h.before("a", 0);
        h.before("b", PENDING_MS + 1);
        assert_eq!(h.waiting(), ["b"], "an event clears what expired");
    }

    #[test]
    fn a_session_keeps_only_so_many_events() {
        let mut h = Hooked::default();
        h.before("first", 0);
        for _ in 1..MAX_PENDING {
            h.before("x", 0);
        }
        assert_eq!(h.waiting().len(), MAX_PENDING);
        h.before("last", 0);
        assert_eq!(h.waiting().len(), MAX_PENDING);
        assert!(!h.take("first", 0), "the oldest made room");
        assert!(h.take("last", 0));
    }

    #[test]
    fn hearing_anything_counts_as_alive() {
        let mut h = Hooked::default();
        assert_eq!(h.last_ms, None);
        h.heard(7);
        assert_eq!(h.last_ms, Some(7));
        assert!(h.waiting().is_empty());
    }

    #[test]
    fn a_tool_is_a_short_lowercase_name() {
        assert!(valid_tool("propose") && valid_tool("change_status") && valid_tool("a1"));
        let long = "a".repeat(MAX_TOOL);
        assert!(valid_tool(&long));
        assert!(!valid_tool(&format!("{long}a")));
        for bad in ["", "Propose", "mcp__lonca__x-y", "a b", "a\n", "ä"] {
            assert!(!valid_tool(bad), "{bad:?}");
        }
    }
}
