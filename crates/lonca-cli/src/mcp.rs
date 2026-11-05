//! `lonca mcp`: a Model Context Protocol server (stdio) for agents working
//! in a Lonca workspace. Tool descriptions are help for the model, not a
//! security boundary: every call is authorized by the daemon from the
//! workspace's session token.

use std::io::{BufRead, Write};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use lonca_core::ops::{Claim, LeaseItem, LeaseKind, NegotiationMsg, TestDelta};
use lonca_daemon::Client;
use serde_json::{Value, json};

use crate::ctx;
use crate::workspace::Workspace;

fn tools() -> Value {
    let s = |props: Value, required: &[&str]| json!({"type": "object", "properties": props, "required": required});
    let list = json!({"type": "array", "items": {"type": "string"}});
    let kind = json!({"type": "string", "enum": ["edit", "insert", "rename"]});
    let items = json!({"type": "array", "items": {
        "type": "object",
        "properties": {"symbol": {"type": "string"}, "kind": kind},
        "required": ["symbol", "kind"],
    }});
    json!([
        {"name": "status", "description": "Repository state: trunk, queue, all active leases (who holds what and why), your session and your changes.", "inputSchema": s(json!({}), &[])},
        {"name": "symbols", "description": "List the symbols of a workspace file with the ids to use for leases and claims (path#Type.method).", "inputSchema": s(json!({"path": {"type": "string", "description": "file path relative to the workspace root"}}), &["path"])},
        {"name": "lease_acquire", "description": "Lease symbols before editing them. All or nothing; never waits. kind: edit (change a body), insert (add members to a type or file), rename (rename/delete). Give items for a set of mixed kinds, or symbols with one kind. To widen what you hold, acquire a second set. A denial has `details`: for each symbol, who holds it, their intent, and when it expires (or the change it is pinned to).", "inputSchema": s(json!({"items": items, "symbols": list, "kind": kind, "intent": {"type": "string"}, "ttl_minutes": {"type": "integer"}}), &["intent"])},
        {"name": "lease_needed", "description": "The leases your local changes need, computed by Lonca: for each symbol the kind needed and whether you hold it, it is free, or who holds it. `acquire` lists the free ones as items for lease_acquire.", "inputSchema": s(json!({}), &[])},
        {"name": "lease_release", "description": "Release a lease set you hold, or only the items you name: the rest stays yours, under a new set id with the time it had left. Items pinned to a change in flight stay until the change leaves the queue; integration releases them without this call.", "inputSchema": s(json!({"set": {"type": "string"}, "items": items}), &["set"])},
        {"name": "lease_renew", "description": "Extend a lease set you hold, for ttl_minutes from now. While this server runs it renews your sets for you, so call this only to ask for a longer TTL. Past the hold limit a renewal is denied (lease_hold_limit) while another session wants the symbols.", "inputSchema": s(json!({"set": {"type": "string"}, "ttl_minutes": {"type": "integer"}}), &["set"])},
        {"name": "preview", "description": "Facts of your local changes as Lonca computes them: symbols edited/added/deleted, signature changes, test changes, files. Use this to write an accurate claim.", "inputSchema": s(json!({}), &[])},
        {"name": "propose", "description": "Submit your local changes. The claim must list exactly the symbols you changed (compare with preview); a mismatch is refused. Integration happens in the merge queue after build/test verification.", "inputSchema": s(json!({
            "intent": {"type": "string"}, "edits": list, "adds": list, "deletes": list, "deleted_files": list, "signature_changes": list,
            "tests": {"type": "object", "properties": {"added": {"type": "integer"}, "modified": {"type": "integer"}, "deleted": {"type": "integer"}, "skipped": {"type": "integer"}}}
        }), &["intent"])},
        {"name": "change_status", "description": "Status of a proposed change (queued, pending review, integrated, conflicted, rejected with reasons: a human's `rejected: ...` reason says what to fix before you sync and propose again), with the evidence of its last integration attempt (build and test logs).", "inputSchema": s(json!({"change": {"type": "string"}}), &["change"])},
        {"name": "sync", "description": "Bring trunk into the workspace, keeping and merging your local edits.", "inputSchema": s(json!({}), &[])},
        {"name": "negotiate", "description": "Message another session about leases: claim, propose_split, yield (give up one of your lease sets), counter, accept, decline. Bounded number of rounds.", "inputSchema": s(json!({"thread": {"type": "string"}, "to_session": {"type": "string"}, "message": {"type": "object", "description": "e.g. {\"type\":\"claim\",\"symbols\":[...],\"reason\":\"...\"} or {\"type\":\"yield\",\"set\":\"lse_...\"}"}}), &["thread", "to_session", "message"])},
    ])
}

const DEFAULT_TTL_MINUTES: i64 = 10;
/// How long the heartbeat waits to try again after a failed call.
const RETRY_BEAT_MS: i64 = 30_000;

/// A tool's `ttl_minutes`, or the default.
fn ttl_ms(args: &Value) -> i64 {
    args["ttl_minutes"].as_i64().unwrap_or(DEFAULT_TTL_MINUTES) * 60_000
}

/// Three chances before the timeout a heartbeat's answer names.
fn beat_interval_ms(beat: &Value) -> i64 {
    beat["timeout_ms"]
        .as_i64()
        .map_or(RETRY_BEAT_MS, |t| (t / 3).max(1_000))
}

/// The TTL an automatic renewal asks for: the default, within the policy.
fn renewal_ttl_ms(beat: &Value) -> i64 {
    let max = beat["max_ttl_ms"].as_i64().unwrap_or(i64::MAX);
    ttl_ms(&Value::Null).min(max)
}

/// The sets of a heartbeat's answer that would run out before the next
/// two beats. A set that has run out is left alone: only a pin holds it.
fn due_for_renewal(beat: &Value, interval_ms: i64) -> Vec<String> {
    let now = beat["now_ms"].as_i64().unwrap_or(0);
    let left = |l: &Value| l["expires_ms"].as_i64().unwrap_or(0) - now;
    beat["leases"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|l| left(l) > 0 && left(l) <= 2 * interval_ms)
        .filter_map(|l| l["set"].as_str().map(String::from))
        .collect()
}

/// One heartbeat; renews what is due. Returns how long to wait.
fn beat(c: &mut Client) -> Result<i64> {
    let r = ctx::call(c, "session.heartbeat", json!({}))?;
    let interval = beat_interval_ms(&r);
    let ttl = renewal_ttl_ms(&r);
    for set in due_for_renewal(&r, interval) {
        // Denied means the hold limit, or the set just ended: the agent
        // finds out when it next uses the lease.
        let _ = ctx::call(c, "lease.renew", json!({"set": set, "ttl_ms": ttl}));
    }
    Ok(interval)
}

/// The heartbeat of this server, on its own connection. It stops with the
/// process, which ends when the harness closes stdin: that is what makes
/// a crashed agent's leases free.
fn keep_alive(mut c: Client) {
    loop {
        let wait = beat(&mut c).unwrap_or(RETRY_BEAT_MS);
        std::thread::sleep(Duration::from_millis(wait as u64));
    }
}

/// `items`, or `symbols` with one `kind` (default edit), or both.
fn requested_items(args: &Value) -> Result<Vec<LeaseItem>> {
    let kind = match args["kind"].as_str().unwrap_or("edit") {
        "edit" => LeaseKind::Edit,
        "insert" => LeaseKind::Insert,
        "rename" => LeaseKind::Rename,
        k => bail!("unknown lease kind {k}"),
    };
    let mut items: Vec<LeaseItem> = match args.get("items") {
        Some(v) => serde_json::from_value(v.clone())?,
        None => vec![],
    };
    let symbols = strings(args, "symbols").into_iter();
    items.extend(symbols.map(|symbol| LeaseItem { symbol, kind }));
    Ok(items)
}

/// What a partial release keeps under a new set: the items not released
/// and not pinned (those stay in the old set until their change leaves).
fn remainder(lease: &Value, released: &[LeaseItem]) -> Result<Vec<LeaseItem>> {
    let items: Vec<LeaseItem> = serde_json::from_value(lease["items"].clone())?;
    let pins = lease["pinned"].as_array().cloned().unwrap_or_default();
    let mut pinned = Vec::new();
    for p in pins {
        pinned.extend(serde_json::from_value::<Vec<LeaseItem>>(
            p["items"].clone(),
        )?);
    }
    if let Some(i) = released.iter().find(|i| !items.contains(i)) {
        bail!("{} ({:?}) is not in this lease set", i.symbol, i.kind);
    }
    let kept = |i: &LeaseItem| !released.contains(i) && !pinned.contains(i);
    Ok(items.into_iter().filter(kept).collect())
}

/// Releases some items of a set: acquires the rest under a new set first,
/// then releases the old one, so nothing is free in between and a refusal
/// changes nothing.
fn release_items(c: &mut Client, set: &str, released: Vec<LeaseItem>) -> Result<Value> {
    let st = ctx::call(c, "status", json!({}))?;
    let leases = st["leases"].as_array().cloned().unwrap_or_default();
    let Some(lease) = leases.iter().find(|l| l["set"] == set) else {
        bail!("unknown lease set {set}");
    };
    let kept = remainder(lease, &released)?;
    let left = lease["expires_ms"].as_i64().unwrap_or(0) - st["now_ms"].as_i64().unwrap_or(0);
    let mut new_set = Value::Null;
    if !kept.is_empty() {
        let intent = &lease["intent"];
        let r = ctx::call(
            c,
            "lease.acquire",
            json!({"items": kept, "intent": intent, "ttl_ms": left}),
        )?;
        if r["decision"]["outcome"] != "allow" {
            return Ok(r);
        }
        new_set = r["set"].clone();
    }
    let mut out = ctx::call(c, "lease.release", json!({"set": set}))?;
    out["set"] = new_set;
    out["kept"] = json!(kept);
    Ok(out)
}

/// The leases the workspace's local changes need, for `lease_needed` and
/// `lonca lease needed`.
pub fn lease_needed(c: &mut Client, ws: &Workspace) -> Result<Value> {
    let changes = ws.changes()?;
    if changes.is_empty() {
        return Ok(json!({"changes": 0, "leases": [], "acquire": []}));
    }
    let r = ctx::call(
        c,
        "facts.preview",
        json!({"base": ws.meta.base, "files": changes}),
    )?;
    Ok(json!({"changes": changes.len(), "leases": r["leases"], "acquire": r["acquire"]}))
}

/// A failed tool call, for the model and for a runner reading it.
fn error_body(e: &anyhow::Error) -> Value {
    match e.downcast_ref::<ctx::MethodError>() {
        Some(m) => json!({"code": m.code, "message": m.message, "details": []}),
        None => json!({"code": "invalid", "message": format!("{e:#}"), "details": []}),
    }
}

struct Server {
    ws: Workspace,
    client: Client,
}

fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

impl Server {
    fn tool(&mut self, name: &str, args: &Value) -> Result<Value> {
        let c = &mut self.client;
        match name {
            "status" => {
                let who = ctx::call(c, "whoami", json!({}))?;
                let st = ctx::call(c, "status", json!({}))?;
                let me = who["actor"].as_str().unwrap_or_default().to_string();
                let mine: Vec<Value> = st["changes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|x| x["actor"] == me.as_str())
                    .collect();
                Ok(
                    json!({"you": who, "trunk": st["trunk"], "your_base": self.ws.meta.base, "frozen": st["frozen"], "queue": st["queue"], "leases": st["leases"], "your_changes": mine}),
                )
            }
            "symbols" => {
                let path = args["path"]
                    .as_str()
                    .ok_or_else(|| anyhow!("path required"))?;
                lonca_core::paths::validate_repo_path(path)?;
                let text = std::fs::read_to_string(self.ws.root.join(path))?;
                let lang = lonca_symbols::Lang::detect(path).ok_or_else(|| {
                    anyhow!("no symbol support for {path}; lease {path}#<file> instead")
                })?;
                let parsed = lonca_symbols::parse(lang, &text);
                let mut out = Vec::new();
                fn walk(path: &str, s: &[lonca_symbols::Sym], out: &mut Vec<Value>) {
                    for x in s {
                        out.push(json!({"id": format!("{path}#{}", x.name), "container": x.container, "test": x.is_test}));
                        walk(path, &x.children, out);
                    }
                }
                walk(path, &parsed.syms, &mut out);
                Ok(
                    json!({"symbols": out, "file": format!("{path}#<file>"), "module": format!("{path}#<module>"), "syntax_error": parsed.has_error}),
                )
            }
            "lease_acquire" => {
                let items = requested_items(args)?;
                let ttl = ttl_ms(args);
                ctx::call(
                    c,
                    "lease.acquire",
                    json!({"items": items, "intent": args["intent"], "ttl_ms": ttl}),
                )
            }
            "lease_needed" => lease_needed(c, &self.ws),
            "lease_release" => match args.get("items") {
                Some(items) => {
                    let set = args["set"].as_str().unwrap_or_default();
                    release_items(c, set, serde_json::from_value(items.clone())?)
                }
                None => ctx::call(c, "lease.release", json!({"set": args["set"]})),
            },
            "lease_renew" => {
                let ttl = ttl_ms(args);
                ctx::call(c, "lease.renew", json!({"set": args["set"], "ttl_ms": ttl}))
            }
            "preview" => {
                let changes = self.ws.changes()?;
                if changes.is_empty() {
                    return Ok(json!({"changes": 0}));
                }
                ctx::call(
                    c,
                    "facts.preview",
                    json!({"base": self.ws.meta.base, "files": changes}),
                )
            }
            "propose" => {
                let changes = self.ws.changes()?;
                if changes.is_empty() {
                    bail!("no local changes");
                }
                let t = &args["tests"];
                let n = |k: &str| t.get(k).and_then(Value::as_u64).unwrap_or(0) as u32;
                let claim = Claim {
                    intent: args["intent"].as_str().unwrap_or_default().into(),
                    edits: strings(args, "edits"),
                    adds: strings(args, "adds"),
                    deletes: strings(args, "deletes"),
                    deleted_files: strings(args, "deleted_files"),
                    signature_changes: strings(args, "signature_changes"),
                    tests: TestDelta {
                        added: n("added"),
                        modified: n("modified"),
                        deleted: n("deleted"),
                        skipped: n("skipped"),
                    },
                    revert_of: None,
                };
                let r = ctx::call(
                    c,
                    "change.propose",
                    json!({"base": self.ws.meta.base, "files": changes, "claim": claim}),
                )?;
                if r["decision"]["outcome"] != "deny" {
                    self.ws.meta.submitted = Some((
                        serde_json::from_value(r["change"].clone())?,
                        serde_json::from_value(r["commit"].clone())?,
                    ));
                    self.ws.save()?;
                }
                Ok(r)
            }
            "change_status" => ctx::call(c, "change.get", json!({"change": args["change"]})),
            "sync" => Ok(serde_json::to_value(self.ws.sync(c)?)?),
            "negotiate" => {
                let msg: NegotiationMsg = serde_json::from_value(args["message"].clone())?;
                ctx::call(
                    c,
                    "negotiate",
                    json!({"thread": args["thread"], "to_session": args["to_session"], "message": msg}),
                )
            }
            other => bail!("unknown tool {other}"),
        }
    }
}

pub fn run() -> Result<()> {
    let ws = Workspace::current()?;
    let mut client = ctx::connect()?;
    client.token = Some(ws.token()?);
    let mut heart = ctx::connect()?;
    heart.token = client.token.clone();
    std::thread::spawn(move || keep_alive(heart));
    let mut server = Server { ws, client };
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = msg.get("id").cloned() else {
            continue;
        }; // notification
        let method = msg["method"].as_str().unwrap_or("");
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": msg["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "lonca", "version": env!("CARGO_PKG_VERSION")},
                "instructions": "Lonca governs this workspace: lease symbols before editing, propose with an exact claim, sync after integration."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or("");
                let args = msg["params"].get("arguments").cloned().unwrap_or(json!({}));
                Ok(match server.tool(name, &args) {
                    Ok(v) => {
                        json!({"content": [{"type": "text", "text": serde_json::to_string_pretty(&v)?}], "isError": false})
                    }
                    Err(e) => {
                        let body = serde_json::to_string_pretty(&error_body(&e))?;
                        json!({"content": [{"type": "text", "text": body}], "isError": true})
                    }
                })
            }
            m => Err(json!({"code": -32601, "message": format!("method not found: {m}")})),
        };
        let resp = match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err(e) => json!({"jsonrpc": "2.0", "id": id, "error": e}),
        };
        writeln!(out, "{}", serde_json::to_string(&resp)?)?;
        out.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        LeaseItem, LeaseKind, beat_interval_ms, due_for_renewal, error_body, remainder,
        renewal_ttl_ms, requested_items, tools, ttl_ms,
    };
    use serde_json::json;

    fn item(symbol: &str, kind: LeaseKind) -> LeaseItem {
        LeaseItem {
            symbol: symbol.into(),
            kind,
        }
    }

    #[test]
    fn items_come_mixed_as_one_kind_or_both() {
        let got = |args| requested_items(&args).unwrap();
        assert_eq!(
            got(json!({"items": [
                {"symbol": "a#f", "kind": "edit"}, {"symbol": "a#<file>", "kind": "insert"}
            ]})),
            [
                item("a#f", LeaseKind::Edit),
                item("a#<file>", LeaseKind::Insert)
            ]
        );
        assert_eq!(
            got(json!({"symbols": ["a#f"]})),
            [item("a#f", LeaseKind::Edit)]
        );
        assert_eq!(
            got(
                json!({"items": [{"symbol": "a#f", "kind": "rename"}], "symbols": ["a#g"], "kind": "insert"})
            ),
            [
                item("a#f", LeaseKind::Rename),
                item("a#g", LeaseKind::Insert)
            ]
        );
        for bad in [
            json!({"symbols": ["a#f"], "kind": "own"}),
            json!({"items": [{"symbol": "a#f", "kind": "own"}]}),
        ] {
            assert!(requested_items(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_partial_release_keeps_the_rest_but_not_what_is_pinned() {
        let (f, g, h) = (
            item("a#f", LeaseKind::Edit),
            item("a#g", LeaseKind::Edit),
            item("a#h", LeaseKind::Edit),
        );
        let lease = json!({
            "items": [f, g, h],
            "pinned": [{"change": "c", "items": [h]}],
        });
        let kept = |released: &LeaseItem| remainder(&lease, std::slice::from_ref(released));
        assert_eq!(kept(&f).unwrap(), vec![g.clone()]);
        assert_eq!(kept(&h).unwrap(), vec![f.clone(), g.clone()]);
        let foreign = item("a#g", LeaseKind::Insert);
        let err = remainder(&lease, &[foreign]).unwrap_err().to_string();
        assert!(err.contains("a#g"), "{err}");
    }

    #[test]
    fn errors_have_a_code_a_message_and_details() {
        let e = anyhow::anyhow!("no local changes");
        assert_eq!(
            error_body(&e),
            json!({"code": "invalid", "message": "no local changes", "details": []})
        );
        let e = anyhow::Error::new(crate::ctx::MethodError {
            method: "lease.renew".into(),
            code: "forbidden".into(),
            message: "no".into(),
        });
        assert_eq!(
            error_body(&e),
            json!({"code": "forbidden", "message": "no", "details": []})
        );
    }

    #[test]
    fn the_heartbeat_beats_three_times_per_timeout_and_at_most_once_a_second() {
        let interval = |timeout_ms: i64| beat_interval_ms(&json!({"timeout_ms": timeout_ms}));
        assert_eq!(interval(300_000), 100_000);
        assert_eq!(interval(3_000), 1_000);
        assert_eq!(interval(2_999), 1_000);
        assert_eq!(interval(1), 1_000);
        assert_eq!(beat_interval_ms(&json!({})), 30_000, "retry");
    }

    #[test]
    fn a_ttl_is_given_in_minutes_and_defaults_to_ten() {
        assert_eq!(ttl_ms(&json!({"ttl_minutes": 3})), 180_000);
        assert_eq!(ttl_ms(&json!({})), 600_000);
    }

    #[test]
    fn an_automatic_renewal_stays_within_the_policy() {
        assert_eq!(renewal_ttl_ms(&json!({"max_ttl_ms": 1_800_000})), 600_000);
        assert_eq!(renewal_ttl_ms(&json!({"max_ttl_ms": 300_000})), 300_000);
        assert_eq!(renewal_ttl_ms(&json!({})), 600_000);
    }

    #[test]
    fn sets_are_renewed_when_two_beats_would_outlast_them() {
        let beat = json!({"now_ms": 1000, "leases": [
            {"set": "over", "expires_ms": 1000},
            {"set": "next", "expires_ms": 1001},
            {"set": "edge", "expires_ms": 3000},
            {"set": "later", "expires_ms": 3001},
        ]});
        assert_eq!(due_for_renewal(&beat, 1000), ["next", "edge"]);
        assert!(due_for_renewal(&json!({}), 1000).is_empty());
    }

    /// The tool list is what a worker's harness sees; every tool the
    /// server dispatches is in it, and change_status tells a worker what
    /// a rejection means for its next step.
    #[test]
    fn the_tool_list_names_every_tool_and_explains_rejection() {
        let tools = tools();
        let names: Vec<&str> = tools
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for n in [
            "status",
            "symbols",
            "lease_acquire",
            "lease_needed",
            "lease_release",
            "lease_renew",
            "preview",
            "propose",
            "change_status",
            "sync",
            "negotiate",
        ] {
            assert!(names.contains(&n), "{n} missing from {names:?}");
        }
        let status = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "change_status")
            .unwrap();
        let d = status["description"].as_str().unwrap();
        assert!(
            d.contains("rejected: ...") && d.contains("sync and propose again"),
            "{d}"
        );
        assert_eq!(
            status["inputSchema"]["required"],
            serde_json::json!(["change"])
        );
    }
}
