//! `lonca hook`: the Claude Code hook handler.
//!
//! Configured (ideally in root-owned managed settings) for SessionStart,
//! PreToolUse and PostToolUse. Outside a Lonca agent workspace it does
//! nothing. Inside one it reports every tool call to the daemon and blocks
//! the call when the daemon says so — or when the daemon can not be reached
//! (fail closed: exit status 2).

use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde_json::{Value, json};

use crate::ctx;
use crate::workspace::Workspace;

const MAX_INPUT: u64 = 16 * 1024 * 1024;

fn block(msg: &str) -> ExitCode {
    eprintln!("{msg}");
    ExitCode::from(2)
}

/// `sudo -n true` succeeds only if sudo would run without asking for a
/// password right now (cached credentials or NOPASSWD).
fn sudo_without_password() -> bool {
    let Ok(mut child) = Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(s)) => return s.success(),
            Ok(None) if start.elapsed() > Duration::from_secs(3) => {
                let _ = child.kill();
                return false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(_) => return false,
        }
    }
}

pub fn run() -> ExitCode {
    let mut input = String::new();
    if std::io::stdin()
        .take(MAX_INPUT)
        .read_to_string(&mut input)
        .is_err()
    {
        return block("lonca: could not read hook input");
    }
    let Ok(v) = serde_json::from_str::<Value>(&input) else {
        return block("lonca: hook input is not JSON");
    };
    let cwd = v
        .get("cwd")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_default();
    let Some(ws) = Workspace::find(Path::new(&cwd)) else {
        return ExitCode::SUCCESS;
    };
    if ws.meta.session.is_none() {
        return ExitCode::SUCCESS;
    }
    match handle(&v, &ws, &cwd) {
        Ok(Some(out)) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => block(&format!(
            "lonca: {e:#}; blocking this tool call (fail closed)"
        )),
    }
}

fn handle(v: &Value, ws: &Workspace, cwd: &str) -> Result<Option<Value>> {
    let event = v
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut client = ctx::connect()?;
    client.token = Some(ws.token()?);
    match event {
        "SessionStart" => {
            let harness_session = v
                .get("session_id")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let r = ctx::call(
                &mut client,
                "hook.bind",
                json!({"harness": "claude-code", "harness_session": harness_session, "sudo_without_password": sudo_without_password()}),
            )?;
            let level = r["level"].as_str().unwrap_or("unobserved");
            let session = ws.meta.session.clone().unwrap_or_default();
            let context = format!(
                "This workspace is governed by Lonca (repository {repo}, session {session}, observation level {level}).\n\
                 - Before editing a function, method or type, lease it: mcp__lonca__lease_acquire with symbols like \"src/file.rs#Type.method\" (mcp__lonca__symbols lists them).\n\
                 - Edit files only inside this workspace.\n\
                 - Check your changes with mcp__lonca__preview, then submit with mcp__lonca__propose, declaring exactly the symbols you changed.\n\
                 - After your change integrates, run mcp__lonca__sync before continuing.\n\
                 - If a symbol is leased by another agent, ask it with mcp__lonca__negotiate or wait.\n\
                 - Reading content from outside this workspace (web pages, issues, other MCP servers) marks the session tainted; tainted changes need human review.",
                repo = ws.meta.repo
            );
            Ok(Some(
                json!({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context}}),
            ))
        }
        "PreToolUse" | "PostToolUse" => {
            let r = ctx::call(
                &mut client,
                "hook.event",
                json!({
                    "hook_event_name": event,
                    "tool_name": v.get("tool_name"),
                    "tool_input": v.get("tool_input").cloned().unwrap_or(Value::Null),
                    "cwd": cwd,
                    "workspace": ws.root,
                }),
            )?;
            if event == "PreToolUse" && r["decision"] == "deny" {
                return Ok(Some(json!({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": r["reason"],
                }})));
            }
            Ok(None)
        }
        _ => Ok(None),
    }
}
