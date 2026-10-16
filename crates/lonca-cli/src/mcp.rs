//! `lonca mcp`: a Model Context Protocol server (stdio) for agents working
//! in a Lonca workspace. Tool descriptions are help for the model, not a
//! security boundary: every call is authorized by the daemon from the
//! workspace's session token.

use std::io::{BufRead, Write};

use anyhow::{Result, anyhow, bail};
use lonca_core::ops::{Claim, LeaseItem, LeaseKind, NegotiationMsg, TestDelta};
use lonca_daemon::Client;
use serde_json::{Value, json};

use crate::ctx;
use crate::workspace::Workspace;

fn tools() -> Value {
    let s = |props: Value, required: &[&str]| json!({"type": "object", "properties": props, "required": required});
    let list = json!({"type": "array", "items": {"type": "string"}});
    json!([
        {"name": "status", "description": "Repository state: trunk, queue, all active leases (who holds what and why), your session and your changes.", "inputSchema": s(json!({}), &[])},
        {"name": "symbols", "description": "List the symbols of a workspace file with the ids to use for leases and claims (path#Type.method).", "inputSchema": s(json!({"path": {"type": "string", "description": "file path relative to the workspace root"}}), &["path"])},
        {"name": "lease_acquire", "description": "Lease symbols before editing them. All or nothing; never waits. kind: edit (change a body), insert (add members to a type or file), rename (rename/delete). A denial lists who holds the symbol and why.", "inputSchema": s(json!({"symbols": list, "kind": {"type": "string", "enum": ["edit", "insert", "rename"]}, "intent": {"type": "string"}, "ttl_minutes": {"type": "integer"}}), &["symbols", "intent"])},
        {"name": "lease_release", "description": "Release a lease set you hold.", "inputSchema": s(json!({"set": {"type": "string"}}), &["set"])},
        {"name": "preview", "description": "Facts of your local changes as Lonca computes them: symbols edited/added/deleted, signature changes, test changes, files. Use this to write an accurate claim.", "inputSchema": s(json!({}), &[])},
        {"name": "propose", "description": "Submit your local changes. The claim must list exactly the symbols you changed (compare with preview); a mismatch is refused. Integration happens in the merge queue after build/test verification.", "inputSchema": s(json!({
            "intent": {"type": "string"}, "edits": list, "adds": list, "deletes": list, "deleted_files": list, "signature_changes": list,
            "tests": {"type": "object", "properties": {"added": {"type": "integer"}, "modified": {"type": "integer"}, "deleted": {"type": "integer"}, "skipped": {"type": "integer"}}}
        }), &["intent"])},
        {"name": "change_status", "description": "Status of a proposed change (queued, pending review, integrated, conflicted, rejected with reasons).", "inputSchema": s(json!({"change": {"type": "string"}}), &["change"])},
        {"name": "sync", "description": "Bring trunk into the workspace, keeping and merging your local edits.", "inputSchema": s(json!({}), &[])},
        {"name": "negotiate", "description": "Message another session about leases: claim, propose_split, yield (give up one of your lease sets), counter, accept, decline. Bounded number of rounds.", "inputSchema": s(json!({"thread": {"type": "string"}, "to_session": {"type": "string"}, "message": {"type": "object", "description": "e.g. {\"type\":\"claim\",\"symbols\":[...],\"reason\":\"...\"} or {\"type\":\"yield\",\"set\":\"lse_...\"}"}}), &["thread", "to_session", "message"])},
    ])
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
                let kind = match args["kind"].as_str().unwrap_or("edit") {
                    "edit" => LeaseKind::Edit,
                    "insert" => LeaseKind::Insert,
                    "rename" => LeaseKind::Rename,
                    k => bail!("unknown lease kind {k}"),
                };
                let items: Vec<LeaseItem> = strings(args, "symbols")
                    .into_iter()
                    .map(|symbol| LeaseItem { symbol, kind })
                    .collect();
                let ttl = args["ttl_minutes"].as_i64().unwrap_or(10) * 60_000;
                ctx::call(
                    c,
                    "lease.acquire",
                    json!({"items": items, "intent": args["intent"], "ttl_ms": ttl}),
                )
            }
            "lease_release" => ctx::call(c, "lease.release", json!({"set": args["set"]})),
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
                        json!({"content": [{"type": "text", "text": format!("{e:#}")}], "isError": true})
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
