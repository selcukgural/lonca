//! Where things are: the daemon socket, human keys, the current workspace.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use lonca_core::keys::KeyPair;
use lonca_core::ops::{HumanSignature, Op};
use lonca_daemon::Client;
use serde_json::Value;

pub fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn lonca_home() -> PathBuf {
    std::env::var_os("LONCA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".lonca"))
}

pub fn socket() -> PathBuf {
    std::env::var_os("LONCA_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| lonca_home().join("lonca.sock"))
}

/// Human keys live with the user, never in the daemon's home.
pub fn humans_dir() -> PathBuf {
    std::env::var_os("LONCA_HUMANS")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".config/lonca/humans"))
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

pub fn connect() -> Result<Client> {
    let s = socket();
    Client::connect(&s).with_context(|| {
        format!(
            "cannot reach the Lonca daemon at {} (is `lonca daemon` running?)",
            s.display()
        )
    })
}

pub fn call(c: &mut Client, method: &str, params: Value) -> Result<Value> {
    c.call(method, params).map_err(|e| anyhow!("{method}: {e}"))
}

pub fn default_human() -> Result<String> {
    if let Ok(h) = std::env::var("LONCA_HUMAN") {
        return Ok(h);
    }
    let f = humans_dir().join("default");
    std::fs::read_to_string(&f)
        .map(|s| s.trim().to_string())
        .with_context(|| "no human identity; run `lonca human keygen <name>` or set LONCA_HUMAN")
}

pub fn human_key_path(name: &str) -> PathBuf {
    humans_dir().join(format!("{name}.key"))
}

pub fn human_key(name: &str) -> Result<KeyPair> {
    let p = human_key_path(name);
    KeyPair::load(&p).map_err(|e| anyhow!("human key {}: {e}", p.display()))
}

pub fn sign(human: &str, repo: &str, op: &Op) -> Result<HumanSignature> {
    let key = human_key(human)?;
    Ok(lonca_policy::human::sign_ed25519(
        &key,
        human,
        repo,
        op,
        now_ms(),
    ))
}

/// Parses `90s`, `30m`, `2h`, `1d` or plain milliseconds.
pub fn duration_ms(s: &str) -> Result<i64> {
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len()));
    let n: i64 = num.parse().with_context(|| format!("bad duration {s:?}"))?;
    let mul = match unit {
        "" | "ms" => 1,
        "s" => 1000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => bail!("bad duration unit in {s:?}"),
    };
    Ok(n * mul)
}

pub fn absolute(p: &Path) -> Result<PathBuf> {
    if p.is_absolute() {
        Ok(p.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(p))
    }
}
