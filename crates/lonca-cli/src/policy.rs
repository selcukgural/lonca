//! `lonca policy show` and `lonca policy check`: the policy in force, and
//! what a new one would have decided differently. Neither writes anything.
//! `lonca policy set` signs what [`texts`] and [`with_values`] make.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow};
use base64::Engine;
use lonca_core::GitId;
use lonca_core::oplog::SignedOp;
use lonca_core::ops::{Decision, Outcome};
use lonca_daemon::Client;
use lonca_policy::config::{CONFIG_FILE, POLICY_FILE, PolicyBundle};
use lonca_policy::whatif::{Comparison, compare};
use serde_json::json;

use crate::ctx::call;
use crate::workspace::fetch;

/// The files of the policy in force, each with its text.
pub fn files(c: &mut Client) -> Result<Vec<(String, String)>> {
    let s = call(c, "status", json!({}))?;
    let policy: GitId = serde_json::from_value(s["policy"].clone())?;
    let mut out = Vec::new();
    for f in fetch(c, &policy, None)? {
        let bytes =
            base64::engine::general_purpose::STANDARD.decode(f.content_b64.unwrap_or_default())?;
        out.push((f.path, String::from_utf8_lossy(&bytes).into_owned()));
    }
    Ok(out)
}

/// The candidate: the files given, and the policy in force for the one
/// left out.
fn candidate(
    c: &mut Client,
    config: Option<PathBuf>,
    policy: Option<PathBuf>,
    values: &[String],
) -> Result<PolicyBundle> {
    let (config, policy) = texts(c, config, policy)?;
    let (config, _) = with_values(&config, values)?;
    PolicyBundle::parse_new(&config, &policy).map_err(|e| anyhow!(e))
}

/// `config` with each `KEY=VALUE` of `values` set in place, and a line per
/// value saying what it was and what it is.
pub fn with_values(config: &str, values: &[String]) -> Result<(String, Vec<String>)> {
    use lonca_policy::edit;
    let mut text = config.to_string();
    let mut said = Vec::new();
    for arg in values {
        let (path, value) = edit::assignment(arg).map_err(|e| anyhow!(e))?;
        let name = path.join(".");
        let read = |e: String| anyhow!("{CONFIG_FILE}: {e}");
        let before = edit::get(&text, &path).map_err(read)?;
        text = edit::set(&text, &path, &value).map_err(read)?;
        let before = before.map_or("the default".to_string(), |v| v.to_string());
        said.push(format!("{name}: {before} -> {value}"));
    }
    Ok((text, said))
}

/// The texts of a candidate: the files given, and the policy in force for
/// the one left out.
pub fn texts(
    c: &mut Client,
    config: Option<PathBuf>,
    policy: Option<PathBuf>,
) -> Result<(String, String)> {
    let read = |p: &PathBuf| {
        std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))
    };
    let mut config = config.as_ref().map(read).transpose()?;
    let mut policy = policy.as_ref().map(read).transpose()?;
    if config.is_none() || policy.is_none() {
        for (path, text) in files(c)? {
            if path == CONFIG_FILE {
                config.get_or_insert(text);
            } else if path == POLICY_FILE {
                policy.get_or_insert(text);
            }
        }
    }
    let (Some(config), Some(policy)) = (config, policy) else {
        return Err(anyhow!(
            "the policy in force has no {CONFIG_FILE} or {POLICY_FILE}"
        ));
    };
    Ok((config, policy))
}

fn whole_log(c: &mut Client) -> Result<Vec<SignedOp>> {
    let pages = crate::log_pages(0, None, crate::LOG_PAGE, |from, limit| {
        let page = call(c, "log", json!({"from": from, "limit": limit}))?;
        Ok(page.as_array().cloned().unwrap_or_default())
    })?;
    let entries = pages.into_iter().map(serde_json::from_value);
    Ok(entries.collect::<Result<_, _>>()?)
}

pub fn check(
    c: &mut Client,
    config: Option<PathBuf>,
    policy: Option<PathBuf>,
    values: &[String],
    as_json: bool,
) -> Result<()> {
    let bundle = candidate(c, config, policy, values)?;
    let out = compare(&whole_log(c)?, &bundle);
    if as_json {
        outln!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        print(&out);
    }
    Ok(())
}

fn word(o: Outcome) -> &'static str {
    match o {
        Outcome::Allow => "allow",
        Outcome::Deny => "deny",
        Outcome::Escalate => "escalate",
    }
}

fn line(d: &Decision) -> String {
    if d.reasons.is_empty() {
        return word(d.outcome).into();
    }
    format!("{:<9}{}", word(d.outcome), d.reasons.join(", "))
}

fn print(c: &Comparison) {
    for d in &c.differences {
        outln!("{:>5} {:<17} {}", d.seq, d.op, d.actor);
        outln!("      was    {}", line(&d.recorded));
        outln!("      would  {}", line(&d.candidate));
    }
    match c.differences.len() {
        0 => outln!("no decision of the {} entries would change", c.entries),
        n => outln!("{n} of {} entries would be decided differently", c.entries),
    }
    for l in &c.lockouts {
        outln!(
            "warning: human:{} could no longer request {} ({})",
            l.human,
            l.action,
            l.reasons.join(", ")
        );
    }
    if !c.lockouts.is_empty() {
        outln!(
            "warning: a human who can not change the policy, unfreeze, approve or \
             replace a key may have no way back; escalate these instead of denying them"
        );
    }
}
