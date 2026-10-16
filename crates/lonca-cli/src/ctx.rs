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

/// Secure Enclave key blob of a human, if they use one.
pub fn se_key_path(name: &str) -> PathBuf {
    humans_dir().join(format!("{name}.se"))
}

/// The `lonca-se` helper: `$LONCA_SE`, else next to this executable.
pub fn se_helper() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("LONCA_SE") {
        return Ok(PathBuf::from(p));
    }
    let exe = std::env::current_exe()?;
    let p = exe.with_file_name("lonca-se");
    if p.exists() {
        Ok(p)
    } else {
        bail!("lonca-se helper not found (build packaging/macos/build-lonca-se.sh or set LONCA_SE)")
    }
}

fn run_helper(args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
    use std::io::Write;
    let mut child = std::process::Command::new(se_helper()?)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(stdin.unwrap_or_default())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("lonca-se: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn se_keygen(name: &str) -> Result<String> {
    let p = se_key_path(name);
    std::fs::create_dir_all(humans_dir())?;
    run_helper(&["keygen", &p.to_string_lossy()], None)
}

/// The public key a human signs with.
pub fn human_public(name: &str) -> Result<lonca_core::ops::HumanKey> {
    let se = se_key_path(name);
    if se.exists() {
        let public = run_helper(&["public", &se.to_string_lossy()], None)?;
        return Ok(lonca_core::ops::HumanKey {
            alg: "p256-se".into(),
            public,
        });
    }
    Ok(lonca_core::ops::HumanKey {
        alg: "ed25519".into(),
        public: human_key(name)?.public_hex(),
    })
}

/// What the Touch ID prompt says: generated from the operation being signed.
pub fn describe(repo: &str, op: &Op) -> String {
    let what = match op {
        Op::RepoInit { .. } => "create the repository".to_string(),
        Op::HumanEnroll { human, .. } => format!("enroll {human} as a human"),
        Op::PolicyUpdate { .. } => "change the repository policy".to_string(),
        Op::SessionStart { agent, scope, .. } => {
            format!("start agent {agent} on {}", scope.paths.join(", "))
        }
        Op::SessionEnd { session, .. } => format!("end session {session}"),
        Op::CapRevoke { session, .. } => format!("revoke session {session}"),
        Op::LeaseRelease { set } => format!("release lease set {set}"),
        Op::ChangePropose { change, .. } => format!("propose change {}", change.short()),
        Op::ChangeWithdraw { change } => format!("withdraw change {}", change.short()),
        Op::Approve { target_seq, .. } => format!("APPROVE operation #{target_seq}"),
        Op::ImportExternal { remote, .. } => format!("import from {remote}"),
        Op::BridgePush { remote, .. } => format!("push to {remote}"),
        Op::Freeze { .. } => "freeze the repository".to_string(),
        Op::Unfreeze { .. } => "unfreeze the repository".to_string(),
        Op::Redact { blob, .. } => format!("redact {}", blob.short()),
        other => other.kind().as_str().to_string(),
    };
    format!("Lonca ({repo}): {what}")
}

pub fn sign(human: &str, repo: &str, op: &Op) -> Result<HumanSignature> {
    let se = se_key_path(human);
    if se.exists() {
        let nonce = lonca_core::canonical::random_id("nonce");
        let issued_ms = now_ms();
        let msg = lonca_policy::human::intent_bytes(repo, op, &nonce, issued_ms);
        let sig = run_helper(
            &["sign", &se.to_string_lossy(), &describe(repo, op)],
            Some(&msg),
        )?;
        return Ok(HumanSignature {
            human: human.to_string(),
            nonce,
            issued_ms,
            sig,
        });
    }
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
