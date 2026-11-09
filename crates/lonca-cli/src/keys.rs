//! `lonca human rotate | recovery-key | recover`: replacing a human's key
//! in every repository they are enrolled in; `lonca daemon-key rotate |
//! recover`: replacing the daemon's key.
//!
//! A rotation or recovery is prepared as a "next" key next to the current
//! one (`<name>.next.key` or `<name>.next.se`). It replaces the current key
//! only after every listed repository has accepted it, so an interrupted
//! run never leaves a key that no repository knows. Rerunning the command
//! skips repositories that already use the next key.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use lonca_core::keys::KeyPair;
use lonca_core::ops::{HumanKey, Op, Recovery};
use lonca_daemon::Client;
use serde_json::json;

use crate::ctx::{self, call};
use crate::sys::current_uid;
use crate::{human_client, human_client_any, print_decision, submit_outcome};

/// The human to act as, checked before it is used in file names.
pub fn name(h: Option<String>) -> Result<String> {
    let name = match h {
        Some(h) => h,
        None => ctx::default_human()?,
    };
    if !lonca_policy::decide::valid_token(&name, 64) {
        bail!("human names: letters, digits, '.', '_', '-'");
    }
    Ok(name)
}

struct NextKey {
    path: PathBuf,
    secure_enclave: bool,
    key: HumanKey,
}

fn next_key(name: &str, secure_enclave: bool) -> Result<NextKey> {
    let dir = ctx::humans_dir();
    let se = dir.join(format!("{name}.next.se"));
    let file = dir.join(format!("{name}.next.key"));
    let (path, other) = if secure_enclave {
        (se, file)
    } else {
        (file, se)
    };
    if other.exists() {
        bail!(
            "an unfinished key change for {name} uses {}; rerun {} --secure-enclave, or delete it",
            other.display(),
            if secure_enclave { "without" } else { "with" }
        );
    }
    let key = if secure_enclave {
        if !path.exists() {
            ctx::se_keygen_at(&path)?;
        }
        HumanKey {
            alg: "p256-se".into(),
            public: ctx::se_public_at(&path)?,
        }
    } else {
        HumanKey {
            alg: "ed25519".into(),
            public: KeyPair::load_or_create(&path, current_uid())?.public_hex(),
        }
    };
    Ok(NextKey {
        path,
        secure_enclave,
        key,
    })
}

/// Moves the current key files aside and the next key into their place.
fn install(name: &str, next: NextKey) -> Result<()> {
    let stamp = ctx::now_ms();
    let dir = ctx::humans_dir();
    for (old, ext) in [
        (ctx::se_key_path(name), "se"),
        (ctx::human_key_path(name), "key"),
    ] {
        if old.exists() {
            let to = dir.join(format!("{name}.{ext}.retired-{stamp}"));
            std::fs::rename(&old, &to)?;
            outln!("old key moved to {}", to.display());
        }
    }
    let dest = if next.secure_enclave {
        ctx::se_key_path(name)
    } else {
        ctx::human_key_path(name)
    };
    std::fs::rename(&next.path, &dest)?;
    let default = dir.join("default");
    if !default.exists() {
        std::fs::write(default, name)?;
    }
    outln!(
        "{name}: {} {} ({})",
        next.key.alg,
        next.key.public,
        dest.display()
    );
    Ok(())
}

/// The public key and recovery key a repository has for `name`.
fn enrolled(c: &mut Client, name: &str) -> Result<(Option<String>, Option<String>)> {
    let st = call(c, "status", json!({}))?;
    let h = &st["humans"][name];
    let s = |v: &serde_json::Value| v.as_str().map(str::to_string);
    Ok((s(&h["public"]), s(&h["recovery"])))
}

fn allowed(repo: &str, r: &serde_json::Value, failed: &mut Vec<String>) {
    if r["decision"]["outcome"] != "allow" {
        failed.push(repo.to_string());
    }
}

pub fn rotate(name: &str, repos: &[String], secure_enclave: bool) -> Result<()> {
    let next = next_key(name, secure_enclave)?;
    let mut failed = vec![];
    for repo in repos {
        let mut c = human_client(repo, name)?;
        if enrolled(&mut c, name)?.0.as_deref() == Some(next.key.public.as_str()) {
            outln!("{repo}: already uses the new key");
            continue;
        }
        out!("{repo}: ");
        let op = Op::HumanRotate {
            human: name.into(),
            key: next.key.clone(),
        };
        allowed(repo, &submit_outcome(&mut c, name, repo, op)?, &mut failed);
    }
    if !failed.is_empty() {
        bail!(
            "not rotated in {}; the current key stays in use and the new one waits at {}. \
             Rerun this command when the reasons above are resolved.",
            failed.join(", "),
            next.path.display()
        );
    }
    install(name, next)?;
    outln!("your sessions ended; changes in flight were withdrawn.");
    Ok(())
}

pub fn recovery_key(name: &str, repos: &[String], out: &Path) -> Result<()> {
    let rk = KeyPair::load_or_create(out, current_uid())?;
    let key = HumanKey {
        alg: "ed25519".into(),
        public: rk.public_hex(),
    };
    let mut failed = vec![];
    for repo in repos {
        let mut c = human_client(repo, name)?;
        if enrolled(&mut c, name)?.1.as_deref() == Some(key.public.as_str()) {
            outln!("{repo}: already set");
            continue;
        }
        out!("{repo}: ");
        let op = Op::HumanRecoveryKey {
            human: name.into(),
            key: key.clone(),
        };
        allowed(repo, &submit_outcome(&mut c, name, repo, op)?, &mut failed);
    }
    if !failed.is_empty() {
        bail!("recovery key not set in {}", failed.join(", "));
    }
    outln!("recovery key for {name}: {}", out.display());
    outln!(
        "move it off this machine now (a password manager or a USB stick). It replaces \
         your key once, without Touch ID; anything that can read it can do the same."
    );
    Ok(())
}

pub fn recover(
    name: &str,
    repos: &[String],
    recovery_key: &Path,
    secure_enclave: bool,
) -> Result<()> {
    let (rk, open) = KeyPair::load_carried(recovery_key, current_uid())
        .map_err(|e| anyhow::anyhow!("recovery key {}: {e}", recovery_key.display()))?;
    if open {
        eprintln!(
            "warning: others may read the recovery key {}; it is spent once this recovery is \
             done, and the new key is private",
            recovery_key.display()
        );
    }
    let next = next_key(name, secure_enclave)?;
    let mut failed = vec![];
    let mut moved = vec![];
    for repo in repos {
        // The key that would open a session is the one that was lost;
        // without one, `human.recover` goes in on its signature alone.
        let mut c = match human_client(repo, name) {
            Ok(c) => c,
            Err(_) => {
                let mut c = ctx::connect()?;
                c.repo = Some(repo.clone());
                c
            }
        };
        if c.token.is_some()
            && enrolled(&mut c, name)?.0.as_deref() == Some(next.key.public.as_str())
        {
            outln!("{repo}: already recovered");
            continue;
        }
        out!("{repo}: ");
        let op = Op::HumanRecover {
            human: name.into(),
            key: next.key.clone(),
        };
        let sig = lonca_policy::human::sign_ed25519(&rk, name, repo, &op, ctx::now_ms());
        let r = match call(&mut c, "human.submit", json!({"op": op, "sig": sig})) {
            // The daemon key went with the Mac too: one entry, signed with
            // the recovery key, moves the repository onto this daemon and
            // replaces the key.
            Err(e) if is_code(&e, "foreign_key") => {
                let op = Op::DaemonRecover {
                    key: daemon_key_for_new(&mut c)?,
                    recover: Some(Recovery {
                        human: name.into(),
                        key: next.key.clone(),
                    }),
                };
                let sig = lonca_policy::human::sign_ed25519(&rk, name, repo, &op, ctx::now_ms());
                match call(&mut c, "human.submit", json!({"op": op, "sig": sig})) {
                    Ok(r) => {
                        moved.push(repo.clone());
                        r
                    }
                    Err(e) => {
                        outln!("{e}");
                        failed.push(repo.clone());
                        continue;
                    }
                }
            }
            r => r?,
        };
        print_decision(&r);
        allowed(repo, &r, &mut failed);
    }
    if !failed.is_empty() {
        bail!(
            "not recovered in {}; the new key waits at {}. Rerun this command when the \
             reasons above are resolved.",
            failed.join(", "),
            next.path.display()
        );
    }
    install(name, next)?;
    if !moved.is_empty() {
        outln!(
            "{} moved onto this daemon's key: every session there ended. Audit them \
             (`lonca-audit verify`) to see the switch.",
            moved.join(", ")
        );
    }
    outln!(
        "recovered. The recovery key is used up: delete {} and set a new one with \
         `lonca human recovery-key`.",
        recovery_key.display()
    );
    Ok(())
}

/// Whether the daemon answered `code`.
fn is_code(e: &anyhow::Error, code: &str) -> bool {
    e.downcast_ref::<ctx::MethodError>()
        .is_some_and(|m| m.code == code)
}

/// The key this daemon puts a repository on: the next one while a rotation
/// is under way, else the current one.
fn daemon_key_for_new(c: &mut Client) -> Result<String> {
    let ping = call(c, "ping", json!({}))?;
    ping["next_key"]
        .as_str()
        .or(ping["daemon_key"].as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("ping: no daemon key in the answer"))
}

fn strings(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// Moves repositories to a new daemon key. The daemon keeps the new key
/// next to the current one and replaces the current one once no repository
/// uses it; until then each repository signs with its own.
pub fn daemon_rotate(name: &str, repos: &[String]) -> Result<()> {
    let mut c = human_client_any(name)?;
    let prep = call(&mut c, "daemon.prepare_rotate", json!({}))?;
    let key = prep["key"].as_str().unwrap_or_default().to_string();
    let repos = if repos.is_empty() {
        strings(&prep["repos"])
    } else {
        repos.to_vec()
    };
    let mut failed = vec![];
    for repo in &repos {
        let mut c = human_client(repo, name)?;
        let st = call(&mut c, "status", json!({}))?;
        if st["daemon_key"].as_str() == Some(key.as_str()) {
            outln!("{repo}: already uses the new daemon key");
            continue;
        }
        out!("{repo}: ");
        let op = Op::DaemonRotate { key: key.clone() };
        allowed(repo, &submit_outcome(&mut c, name, repo, op)?, &mut failed);
    }
    if !failed.is_empty() {
        bail!("not rotated in {}", failed.join(", "));
    }
    // Read-only from here: preparing again would start the next rotation.
    let ping = call(&mut c, "ping", json!({}))?;
    let mut left = vec![];
    if !ping["next_key"].is_null() {
        for repo in strings(&call(&mut c, "repo.list", json!({}))?) {
            let st = call(&mut human_client(&repo, name)?, "status", json!({}))?;
            if st["daemon_key"] == ping["daemon_key"] {
                left.push(repo);
            }
        }
    }
    if left.is_empty() {
        outln!("the daemon signs with {key} now; the old key is deleted.");
    } else {
        outln!(
            "still on the old daemon key: {}. They keep working; rotate them (a human \
             enrolled there signs) to finish.",
            left.join(", ")
        );
    }
    Ok(())
}

/// Re-anchors repositories whose daemon key is lost (or that come from
/// another daemon, e.g. when moving to hardened mode) on this daemon's key.
pub fn daemon_recover(name: &str, repos: &[String]) -> Result<()> {
    let mut c = ctx::connect()?;
    let key = daemon_key_for_new(&mut c)?;
    let mut failed = vec![];
    for repo in repos {
        let mut c = human_client(repo, name)?;
        out!("{repo}: ");
        let op = Op::DaemonRecover {
            key: key.clone(),
            recover: None,
        };
        match submit_outcome(&mut c, name, repo, op) {
            Ok(r) => allowed(repo, &r, &mut failed),
            Err(e) => {
                outln!("{e}");
                failed.push(repo.clone());
            }
        }
    }
    if !failed.is_empty() {
        bail!("not recovered: {}", failed.join(", "));
    }
    outln!(
        "recovered onto daemon key {key}. Every session ended; start new ones. \
         Audit the repositories (`lonca-audit verify`) to see the switch."
    );
    Ok(())
}
