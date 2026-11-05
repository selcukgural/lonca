//! `lonca hook`: the handler for harness hooks. It knows no harness: the
//! daemon reads each event with the harness's profile (`--harness <name>`).
//!
//! Configured (ideally in root-owned managed settings) for session start and
//! before and after every tool call. Outside a Lonca agent workspace it does
//! nothing. Inside one it reports every tool call to the daemon and blocks
//! the call when the daemon says so — or when the daemon can not be reached
//! (fail closed: exit status 2).
//!
//! The stop event is the exception (`--fail-open`). A harness reads exit
//! status 2 there as "go on", so a daemon that is down would keep an agent
//! working for ever, with no one counting the rounds. Nothing is protected
//! by a stop hook: it reminds, and a failure ends the turn.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use anyhow::Result;
use lonca_daemon::Client;
use lonca_policy::harness::{render, rules};
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

pub fn run(harness: &str, fail_open: bool) -> ExitCode {
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
    // Before the workspace is known there is no policy to ask where a
    // harness keeps this, and a hook runs in the session's directory anyway.
    let cwd = v
        .get("cwd")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_default();
    let Some(ws) = Workspace::find(&cwd) else {
        return ExitCode::SUCCESS;
    };
    if ws.meta.session.is_none() {
        return ExitCode::SUCCESS;
    }
    match handle(harness, &v, &ws) {
        Ok(Some(out)) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) if fail_open => {
            eprintln!("lonca: {e:#}");
            ExitCode::SUCCESS
        }
        Err(e) => block(&format!(
            "lonca: {e:#}; blocking this tool call (fail closed)"
        )),
    }
}

/// Knows no harness: the daemon reads the event with the profile in the
/// signed policy and says what to answer.
fn handle(harness: &str, v: &Value, ws: &Workspace) -> Result<Option<Value>> {
    let mut client = ctx::connect()?;
    client.token = Some(ws.token()?);
    let params = json!({"harness": harness, "input": v, "workspace": ws.root});
    let r = ctx::call(&mut client, "hook.input", params)?;
    if r["phase"] == "session_start" {
        return bind(&mut client, harness, &r, ws).map(Some);
    }
    if r["phase"] == "stop" {
        // Whatever the flags, a stop that fails here ends the turn.
        return Ok(stop(&mut client, harness, ws).unwrap_or_else(|e| {
            eprintln!("lonca: {e:#}");
            None
        }));
    }
    // A refusal, or what the harness should add to the agent's context.
    Ok(Some(r["output"].clone()).filter(|o| !o.is_null()))
}

/// Tells the daemon what the workspace holds; the answer, if there is one,
/// sends the agent back.
fn stop(client: &mut Client, harness: &str, ws: &Workspace) -> Result<Option<Value>> {
    let files = ws.local_files()?;
    let params = json!({"harness": harness, "files": files});
    let r = ctx::call(client, "hook.stop", params)?;
    Ok(r.get("output").cloned())
}

/// Binds the session and answers with Lonca's rules.
fn bind(client: &mut Client, harness: &str, start: &Value, ws: &Workspace) -> Result<Value> {
    let r = ctx::call(
        client,
        "hook.bind",
        json!({
            "harness": harness,
            "harness_session": start["session"],
            "sudo_without_password": sudo_without_password(),
            "workspace": ws.root,
        }),
    )?;
    let level = r["level"].as_str().unwrap_or("unobserved");
    let session = ws.meta.session.clone().unwrap_or_default();
    // The roots come from the daemon's answer (the log), not from
    // the workspace file.
    let scratch: Vec<&str> = r["scratch"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let about = format!(
        " (repository {}, session {session}, observation level {level})",
        ws.meta.repo
    );
    let prefix = start["tool_prefix"].as_str().unwrap_or("");
    let context = rules(&about, prefix, &scratch);
    Ok(render(&start["context"], "context", &context))
}
