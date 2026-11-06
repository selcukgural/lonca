//! `lonca mcp`: a Model Context Protocol server (stdio) for agents working
//! in a Lonca workspace. Tool descriptions are help for the model, not a
//! security boundary: every call is authorized by the daemon from the
//! workspace's session token.

use std::io::{BufRead, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use lonca_core::ops::{Claim, LeaseItem, LeaseKind, NegotiationMsg, TestDelta};
use lonca_daemon::Client;
use lonca_symbols::sections::{Format, sections};
use serde_json::{Value, json};

use crate::workspace::Workspace;
use crate::wsfs;
use crate::{ctx, setup};

/// Tools that change nothing, and tools that take nothing away. Anything
/// else counts as destructive, so a new tool asks until it is listed here.
const READ_ONLY: &[&str] = &[
    "status",
    "symbols",
    "lease_needed",
    "events",
    "preview",
    "change_status",
];
const ADDITIVE: &[&str] = &["lease_acquire", "lease_interest", "lease_renew", "propose"];

/// `tool` with the hints a harness uses to approve it on its own.
fn annotated(mut tool: Value) -> Value {
    let name = tool["name"].as_str().unwrap_or("");
    let read_only = READ_ONLY.contains(&name);
    tool["annotations"] = json!({
        "readOnlyHint": read_only,
        "destructiveHint": !read_only && !ADDITIVE.contains(&name),
        "openWorldHint": false,
    });
    tool
}

fn tools() -> Value {
    let list = tool_list().as_array().cloned().unwrap_or_default();
    Value::Array(list.into_iter().map(annotated).collect())
}

fn tool_list() -> Value {
    let s = |props: Value, required: &[&str]| json!({"type": "object", "properties": props, "required": required});
    let text = |what: &str| json!({"type": "string", "description": what});
    let number = |what: &str| json!({"type": "integer", "description": what});
    let list =
        |what: &str| json!({"type": "array", "items": {"type": "string"}, "description": what});
    let kind = json!({"type": "string", "enum": ["edit", "insert", "rename"], "description": "edit changes a body; insert adds members to a type or file; rename renames or deletes"});
    let items = |what: &str| {
        json!({"type": "array", "description": what, "items": {
            "type": "object",
            "properties": {
                "symbol": text("A symbol id, as `symbols` lists it: path#Type.method"),
                "kind": kind,
            },
            "required": ["symbol", "kind"],
        }})
    };
    let intent = text("In a sentence, what you are doing and why; others read it");
    let lease_intent = text(
        "Required. In a sentence, what you are doing and why: an agent you hold up reads it. For a wide change (a whole type or file, a rename, a delete) say why it needs that much, with the issue number if there is one",
    );
    let set = text("A lease set id (lse_...), from lease_acquire or status");
    let symbols = list("Symbol ids (path#Type.method), all with the same `kind`");
    let ttl = number("Minutes to hold the lease; 10 if not given");
    let path = text("File path relative to the workspace root");
    let claim = |field: &str, what: &str| {
        list(&format!(
            "{what}. Copy `facts.{field}` from what preview reports"
        ))
    };
    json!([
        {"name": "status", "description": "Repository state: trunk, queue, all active leases (who holds what and why), your session and your changes.", "inputSchema": s(json!({}), &[])},
        {"name": "symbols", "description": "List the symbols of a workspace file with the ids to use for leases and claims (path#Type.method). `def` of a type is its own text (fields, header): lease it to leave the methods to others. Symbols that share a name have a key, path#Type.method(int): the name alone holds all of them.", "inputSchema": s(json!({"path": path}), &["path"])},
        {"name": "lease_acquire", "description": "Lease symbols before editing them. All or nothing; never waits. kind: edit (change a body), insert (add members to a type or file), rename (rename/delete). Give items for a set of mixed kinds, or symbols with one kind. To widen what you hold, acquire a second set. A denial has `details`: for each symbol, who holds it or waits for it, their intent, and when it ends (or the change it is pinned to).", "inputSchema": s(json!({"items": items("Symbols with a kind each, for a set of mixed kinds"), "symbols": symbols, "kind": kind, "intent": lease_intent, "ttl_minutes": ttl}), &["intent"])},
        {"name": "lease_needed", "description": "The leases your local changes need, computed by Lonca: for each symbol the kind needed and whether you hold it, it is free, or who holds it. `acquire` lists the free ones as items for lease_acquire. A file under `no_lease` needs none: the merge decides.", "inputSchema": s(json!({}), &[])},
        {"name": "lease_interest", "description": "Say you are waiting for symbols another session holds. It holds nothing and never waits: go on with other work. For a while nobody can take a new lease that conflicts with it, so a wide change is not starved by small ones. When they are freed you get a short reservation (see `events`) and only you can acquire them; the oldest interest goes first. Refused (`lease_free`) for what nobody holds: acquire that.", "inputSchema": s(json!({"items": items("The symbols you are waiting for, with a kind each"), "symbols": symbols, "kind": kind, "intent": lease_intent}), &["intent"])},
        {"name": "events", "description": "What happened that you should know of: a lease reserved for you, a lease handed to you, your change integrated, conflicted, approved or rejected, a message from another session with what it says. Messages and leases also arrive with the answers of your tools. Pass `from` as `next` of the last answer.", "inputSchema": s(json!({"from": number("`next` of the last answer; 0 for all")}), &[])},
        {"name": "lease_release", "description": "Release a lease set you hold, or only the items you name: the rest stays yours, under a new set id with the time it had left. Items pinned to a change in flight stay until the change leaves the queue; integration releases them without this call.", "inputSchema": s(json!({"set": set, "items": items("Only these items; the whole set if not given")}), &["set"])},
        {"name": "lease_renew", "description": "Extend a lease set you hold, for ttl_minutes from now. While this server runs it renews your sets for you, so call this only to ask for a longer TTL. Past the hold limit a renewal is denied (lease_hold_limit) while another session wants the symbols.", "inputSchema": s(json!({"set": set, "ttl_minutes": ttl}), &["set"])},
        {"name": "preview", "description": "Facts of your local changes as Lonca computes them: symbols edited/added/deleted, signature changes, test changes, files. Use this to write an accurate claim.", "inputSchema": s(json!({}), &[])},
        {"name": "propose", "description": "Submit your local changes. Give an `intent` and copy `edits`, `adds`, `deletes`, `deleted_files`, `signature_changes` and `tests` from what preview reports; a claim that differs is denied (claim_mismatch:<field>). Integration happens in the merge queue after build/test verification.", "inputSchema": s(json!({
            "intent": intent,
            "edits": claim("edits", "Existing symbols whose body you changed"),
            "adds": claim("adds", "Symbols you added"),
            "deletes": claim("deletes", "Symbols you deleted"),
            "deleted_files": claim("deleted_files", "Files you deleted"),
            "signature_changes": claim("signature_changes", "Symbols whose signature you changed"),
            "tests": {"type": "object", "description": "Tests changed by count. Copy `facts.tests` from what preview reports", "properties": {
                "added": number("Tests added"), "modified": number("Tests modified"), "deleted": number("Tests deleted"), "skipped": number("Tests skipped"),
            }}
        }), &["intent"])},
        {"name": "change_status", "description": "Status of a proposed change (queued, pending review, integrated, conflicted, rejected with reasons: a human's `rejected: ...` reason says what to fix before you sync and propose again), with the evidence of its last integration attempt (build and test logs).", "inputSchema": s(json!({"change": text("A change id, from propose or status")}), &["change"])},
        {"name": "sync", "description": "Bring trunk into the workspace, keeping and merging your local edits.", "inputSchema": s(json!({}), &[])},
        {"name": "negotiate", "description": "Settle a lease with the agent that holds it: claim, propose_split, yield (give up one of your lease sets), counter, accept, decline. Lonca tells the other agent. Bounded number of rounds.", "inputSchema": s(json!({"thread": text("A name for this conversation, the same in every message of it"), "to_session": text("The session you are writing to, from status or a lease denial"), "message": {"type": "object", "description": "One of {\"type\":\"claim\",\"symbols\":[...],\"reason\":\"...\"}, {\"type\":\"propose_split\",\"mine\":[...],\"yours\":[...]}, {\"type\":\"yield\",\"set\":\"lse_...\",\"to\":\"<to_session>\"}, {\"type\":\"counter\",\"note\":\"...\"}, {\"type\":\"accept\"}, {\"type\":\"decline\",\"note\":\"...\"}. With `to` a yielded set moves to that session at once, without it the set is freed. accept and decline end the thread"}}), &["thread", "to_session", "message"])},
    ])
}

/// A call naming an argument its tool does not take. Ignoring one leaves a
/// model repeating a call that can not work: a claim sent as `symbols` is an
/// empty claim, denied for a reason it can not see. So it gets the tool's
/// schema again, with what each argument is for.
#[derive(Debug)]
struct WrongArgument {
    message: String,
    expected: Value,
}

impl std::fmt::Display for WrongArgument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for WrongArgument {}

fn wrong_argument(list: &Value, tool: &str, args: &Value) -> Option<WrongArgument> {
    let found = list.as_array()?.iter().find(|t| t["name"] == tool)?;
    let known = found["inputSchema"]["properties"].as_object()?;
    let wrong = args.as_object()?.keys().find(|k| !known.contains_key(*k))?;
    Some(WrongArgument {
        message: format!("{tool} has no argument `{wrong}`; `expected` says what it takes"),
        expected: found["inputSchema"].clone(),
    })
}

/// For each `claim_mismatch:<field>` of a denial, what was claimed and what
/// Lonca computed, so that the next call can be the right one.
fn claim_mismatch(args: &Value, answer: &Value) -> Value {
    let reasons = answer["decision"]["reasons"].as_array();
    let fields = reasons
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .filter_map(|reason| reason.strip_prefix("claim_mismatch:"));
    let gaps = fields.map(|field| {
        json!({
            "field": field,
            "claimed": args.get(field).cloned().unwrap_or(json!([])),
            "facts": answer["facts"][field],
        })
    });
    Value::Array(gaps.collect())
}

const DEFAULT_TTL_MINUTES: i64 = 10;
/// What a worker reads after its session is over.
const SESSION_OVER: &str = "this session has ended or expired; a human continues the \
                            workspace with `lonca session start --continue`";
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

/// The sections of a file that has them, as `symbols` lists symbols.
fn section_ids(path: &str, text: &str) -> Option<Vec<Value>> {
    let format = Format::detect(path)?;
    let list = sections(format, text)?.into_iter();
    let ids =
        list.map(|s| json!({"id": format!("{path}#{}", s.name), "container": null, "test": false}));
    Some(ids.collect())
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

/// The daemon says this session is over, not that it could not answer:
/// expired, or ended and its token gone. A worker is told by its next tool
/// result.
fn session_over(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ctx::MethodError>()
        .is_some_and(|m| matches!(m.code.as_str(), "session_inactive" | "unauthenticated"))
}

/// The heartbeat of this server, on its own connection. It stops when the
/// session is over, or with the process, which ends when the harness
/// closes stdin: that is what makes a crashed agent's leases free.
fn keep_alive(mut c: Client, ended: Arc<AtomicBool>) {
    while let Some(wait) = next_beat(beat(&mut c)) {
        std::thread::sleep(Duration::from_millis(wait as u64));
    }
    ended.store(true, Ordering::SeqCst);
}

/// How long to wait after a beat, or `None` when the session is over. A
/// failure that says nothing of the session is tried again.
fn next_beat(beat: Result<i64>) -> Option<i64> {
    match beat {
        Ok(wait) => Some(wait),
        Err(e) if session_over(&e) => None,
        Err(_) => Some(RETRY_BEAT_MS),
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
        return Ok(
            json!({"changes": 0, "leases": [], "acquire": [], "advice": null, "no_lease": []}),
        );
    }
    let r = ctx::call(
        c,
        "facts.preview",
        json!({"base": ws.meta.base, "files": changes}),
    )?;
    Ok(json!({
        "changes": changes.len(), "leases": r["leases"], "acquire": r["acquire"],
        "advice": r["advice"], "no_lease": r["no_lease"],
    }))
}

/// A failed tool call, for the model and for a runner reading it.
fn error_body(e: &anyhow::Error) -> Value {
    if let Some(w) = e.downcast_ref::<WrongArgument>() {
        return json!({"code": "invalid", "message": w.message, "details": [], "expected": w.expected});
    }
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
    /// What other sessions want of this one, for the end of a tool's answer.
    /// A failure here must not cost the answer: the news waits for the next.
    fn news(&mut self) -> Option<String> {
        let inbox = ctx::call(&mut self.client, "inbox", json!({})).ok()?;
        inbox["text"].as_str().map(String::from)
    }

    /// A tool that only reads runs past an argument it does not take and
    /// says so; one that changes something does not run on a call that may
    /// not mean what it says.
    fn tool(&mut self, name: &str, args: &Value) -> Result<Value> {
        let Some(wrong) = wrong_argument(&tools(), name, args) else {
            return self.call_tool(name, args);
        };
        if !READ_ONLY.contains(&name) {
            return Err(wrong.into());
        }
        let mut answer = self.call_tool(name, args)?;
        answer["warnings"] = json!([wrong.message]);
        answer["expected"] = wrong.expected;
        Ok(answer)
    }

    fn call_tool(&mut self, name: &str, args: &Value) -> Result<Value> {
        let c = &mut self.client;
        match name {
            "status" => {
                let who = ctx::call(c, "whoami", json!({}))?;
                let st = ctx::call(c, "status", json!({}))?;
                let me = who["actor"].as_str().unwrap_or_default().to_string();
                // The workspace's change may be an earlier session's.
                let submitted = self.ws.meta.submitted.as_ref();
                let submitted = submitted.map(|(change, _)| json!(change));
                let mine: Vec<Value> = st["changes"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|x| {
                        x["actor"] == me.as_str() || Some(&x["change"]) == submitted.as_ref()
                    })
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
                let local = wsfs::read(&self.ws.root, path)?
                    .ok_or_else(|| anyhow!("no file {path} in this workspace"))?;
                let text = String::from_utf8(local.bytes)?;
                if let Some(list) = section_ids(path, &text) {
                    return Ok(json!({"symbols": list}));
                }
                let lang = lonca_symbols::Lang::detect(path).ok_or_else(|| {
                    anyhow!("no symbol support for {path}; lease {path}#<file> instead")
                })?;
                let parsed = lonca_symbols::parse(lang, &text);
                let mut out = Vec::new();
                fn walk(path: &str, s: &[lonca_symbols::Sym], out: &mut Vec<Value>) {
                    for x in s {
                        out.push(json!({"id": format!("{path}#{}", x.name), "container": x.container, "test": x.is_test, "def": x.def_of.as_ref().map(|t| format!("{path}#{t}.{}", lonca_symbols::DEF))}));
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
            "lease_interest" => {
                let items = requested_items(args)?;
                ctx::call(
                    c,
                    "lease.interest",
                    json!({"items": items, "intent": args["intent"]}),
                )
            }
            "events" => {
                let from = args["from"].as_u64().unwrap_or(0);
                ctx::call(c, "events", json!({"from": from}))
            }
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
                self.ws.check_settled()?;
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
                let mut r = ctx::call(
                    c,
                    "change.propose",
                    json!({"base": self.ws.meta.base, "files": changes, "claim": claim}),
                )?;
                r["claim_mismatch"] = claim_mismatch(args, &r);
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

/// A tool's answer. News from other sessions comes as text of its own, so the
/// answer stays one JSON document for whoever parses it.
fn answer(body: String, news: Option<String>, is_error: bool) -> Value {
    let mut content = vec![json!({"type": "text", "text": body})];
    content.extend(news.map(|text| json!({"type": "text", "text": text})));
    json!({"content": content, "isError": is_error})
}

pub fn run() -> Result<()> {
    let ws = Workspace::current()?;
    let mut client = ctx::connect()?;
    client.token = Some(ws.token()?);
    let mut heart = ctx::connect()?;
    heart.token = client.token.clone();
    let ended = Arc::new(AtomicBool::new(false));
    let beating = ended.clone();
    std::thread::spawn(move || keep_alive(heart, beating));
    let rules = setup::neutral_rules(Some(&ws));
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
                "instructions": rules,
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": tools()})),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap_or("");
                let args = msg["params"].get("arguments").cloned().unwrap_or(json!({}));
                let result = if ended.load(Ordering::SeqCst) {
                    Err(anyhow::Error::new(ctx::MethodError {
                        method: name.to_string(),
                        code: "session_inactive".into(),
                        message: SESSION_OVER.into(),
                    }))
                } else {
                    server.tool(name, &args)
                };
                let news = server.news();
                Ok(match result {
                    Ok(v) => answer(serde_json::to_string_pretty(&v)?, news, false),
                    Err(e) => {
                        let body = serde_json::to_string_pretty(&error_body(&e))?;
                        answer(body, news, true)
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
        ADDITIVE, LeaseItem, LeaseKind, READ_ONLY, RETRY_BEAT_MS, annotated, anyhow,
        beat_interval_ms, claim_mismatch, ctx, due_for_renewal, error_body, next_beat, remainder,
        renewal_ttl_ms, requested_items, section_ids, session_over, tools, ttl_ms, wrong_argument,
    };
    use serde_json::json;

    fn item(symbol: &str, kind: LeaseKind) -> LeaseItem {
        LeaseItem {
            symbol: symbol.into(),
            kind,
        }
    }

    #[test]
    fn a_wrong_argument_comes_back_with_the_tool_s_schema() {
        let list = tools();
        let check = |tool: &str, args| wrong_argument(&list, tool, &args);
        let w = check("propose", json!({"intent": "x", "symbols": ["a#b"]})).unwrap();
        assert!(
            w.message.starts_with("propose has no argument `symbols`"),
            "{w}"
        );
        assert_eq!(w.to_string(), w.message);
        assert_eq!(w.expected["required"], json!(["intent"]));
        let body = error_body(&w.into());
        assert_eq!(body["code"], "invalid");
        assert!(
            body["message"].as_str().unwrap().contains("`symbols`"),
            "{body}"
        );
        let edits = &body["expected"]["properties"]["edits"]["description"];
        assert!(edits.as_str().unwrap().contains("facts.edits"), "{body}");

        assert!(check("propose", json!({"intent": "x", "edits": []})).is_none());
        assert!(check("status", json!({})).is_none());
        assert!(check("status", json!({"x": 1})).is_some());
        assert!(
            check("no_such_tool", json!({"x": 1})).is_none(),
            "named as unknown later"
        );
        assert!(check("status", json!(null)).is_none());
    }

    /// Not every harness shows a model the tool schemas up front; every
    /// harness gives it the rules. So they name what `propose` takes.
    #[test]
    fn the_rules_say_what_each_argument_of_propose_is() {
        let list = tools();
        let propose = list
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "propose");
        let properties = propose.unwrap()["inputSchema"]["properties"].as_object();
        let rules = crate::setup::neutral_rules(None);
        for name in properties.unwrap().keys() {
            assert!(rules.contains(&format!("`{name}` (")), "{name}");
        }
    }

    /// Without a description a name is all a model has, and it guesses.
    #[test]
    fn every_argument_of_every_tool_says_what_it_is_for() {
        for tool in tools().as_array().unwrap() {
            let properties = tool["inputSchema"]["properties"].as_object().unwrap();
            for (name, schema) in properties {
                let about = schema["description"].as_str().unwrap_or("");
                assert!(!about.is_empty(), "{}: {name}", tool["name"]);
            }
        }
    }

    #[test]
    fn a_denied_claim_says_what_was_claimed_and_what_lonca_computed() {
        let answer = json!({
            "decision": {"outcome": "deny", "reasons": ["claim_mismatch:edits", "lease_missing:a#b"]},
            "facts": {"edits": ["a#b"], "adds": []},
        });
        let gaps = claim_mismatch(&json!({"edits": ["a#c"]}), &answer);
        assert_eq!(
            gaps,
            json!([{"field": "edits", "claimed": ["a#c"], "facts": ["a#b"]}])
        );
        let gaps = claim_mismatch(&json!({}), &answer);
        assert_eq!(gaps[0]["claimed"], json!([]));
        assert_eq!(claim_mismatch(&json!({}), &json!({})), json!([]));
    }

    #[test]
    fn a_harness_can_tell_what_a_tool_does_and_a_new_tool_counts_as_destructive() {
        let hints = |name: &str| {
            let a = &annotated(json!({"name": name}))["annotations"];
            (a["readOnlyHint"].clone(), a["destructiveHint"].clone())
        };
        assert_eq!(hints("status"), (json!(true), json!(false)));
        assert_eq!(hints("propose"), (json!(false), json!(false)));
        assert_eq!(hints("sync"), (json!(false), json!(true)));
        assert_eq!(hints("a_new_tool"), (json!(false), json!(true)));
        let list = tools();
        let names: Vec<&str> = list
            .as_array()
            .unwrap()
            .iter()
            .map(|t| {
                assert_eq!(t["annotations"]["openWorldHint"], json!(false));
                t["name"].as_str().unwrap()
            })
            .collect();
        for listed in READ_ONLY.iter().chain(ADDITIVE) {
            assert!(names.contains(listed), "{listed} is not a tool");
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
    fn sections_are_listed_like_symbols() {
        let ids = section_ids("a.md", "# One\nx\n# Two\ny\n").unwrap();
        assert_eq!(ids[1]["id"], "a.md#Two");
        assert_eq!(section_ids("a.md", "plain\n"), None);
        assert_eq!(section_ids("a.rs", "# One\n# Two\n"), None);
    }

    #[test]
    fn only_the_daemons_word_ends_a_session() {
        let said = |code: &str| {
            anyhow::Error::new(ctx::MethodError {
                method: "session.heartbeat".into(),
                code: code.into(),
                message: String::new(),
            })
        };
        assert!(session_over(&said("session_inactive")));
        assert!(session_over(&said("unauthenticated")));
        assert!(!session_over(&said("io")), "the daemon may come back");
        assert!(!session_over(&anyhow!("no answer")));
        assert_eq!(next_beat(Ok(1234)), Some(1234));
        assert_eq!(next_beat(Err(said("session_inactive"))), None);
        assert_eq!(next_beat(Err(said("io"))), Some(RETRY_BEAT_MS));
    }

    #[test]
    fn news_comes_after_the_answer_as_text_of_its_own() {
        let quiet = super::answer("{}".into(), None, false);
        assert_eq!(quiet["content"].as_array().unwrap().len(), 1);
        assert_eq!(quiet["isError"], false);
        let told = super::answer("{}".into(), Some("news".into()), true);
        assert_eq!(told["content"][0]["text"], "{}");
        assert_eq!(told["content"][1]["text"], "news");
        assert_eq!(told["isError"], true);
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
