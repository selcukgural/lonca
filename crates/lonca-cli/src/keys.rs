//! `lonca human rotate | recovery-key | recover`: replacing a human's key
//! in every repository they are enrolled in.
//!
//! A rotation or recovery is prepared as a "next" key next to the current
//! one (`<name>.next.key` or `<name>.next.se`). It replaces the current key
//! only after every listed repository has accepted it, so an interrupted
//! run never leaves a key that no repository knows. Rerunning the command
//! skips repositories that already use the next key.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use lonca_core::keys::KeyPair;
use lonca_core::ops::{HumanKey, Op};
use lonca_daemon::Client;
use serde_json::json;

use crate::ctx::{self, call};
use crate::{human_client, print_decision, submit};

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
            public: KeyPair::load_or_create(&path)?.public_hex(),
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
            println!("old key moved to {}", to.display());
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
    println!(
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
        let mut c = human_client(repo)?;
        if enrolled(&mut c, name)?.0.as_deref() == Some(next.key.public.as_str()) {
            println!("{repo}: already uses the new key");
            continue;
        }
        print!("{repo}: ");
        let op = Op::HumanRotate {
            human: name.into(),
            key: next.key.clone(),
        };
        allowed(repo, &submit(&mut c, name, repo, op)?, &mut failed);
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
    println!("your sessions ended; changes in flight were withdrawn.");
    Ok(())
}

pub fn recovery_key(name: &str, repos: &[String], out: &Path) -> Result<()> {
    let rk = KeyPair::load_or_create(out)?;
    let key = HumanKey {
        alg: "ed25519".into(),
        public: rk.public_hex(),
    };
    let mut failed = vec![];
    for repo in repos {
        let mut c = human_client(repo)?;
        if enrolled(&mut c, name)?.1.as_deref() == Some(key.public.as_str()) {
            println!("{repo}: already set");
            continue;
        }
        print!("{repo}: ");
        let op = Op::HumanRecoveryKey {
            human: name.into(),
            key: key.clone(),
        };
        allowed(repo, &submit(&mut c, name, repo, op)?, &mut failed);
    }
    if !failed.is_empty() {
        bail!("recovery key not set in {}", failed.join(", "));
    }
    println!("recovery key for {name}: {}", out.display());
    println!(
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
    let rk = KeyPair::load(recovery_key)
        .map_err(|e| anyhow::anyhow!("recovery key {}: {e}", recovery_key.display()))?;
    let next = next_key(name, secure_enclave)?;
    let mut failed = vec![];
    for repo in repos {
        let mut c = human_client(repo)?;
        if enrolled(&mut c, name)?.0.as_deref() == Some(next.key.public.as_str()) {
            println!("{repo}: already recovered");
            continue;
        }
        print!("{repo}: ");
        let op = Op::HumanRecover {
            human: name.into(),
            key: next.key.clone(),
        };
        let sig = lonca_policy::human::sign_ed25519(&rk, name, repo, &op, ctx::now_ms());
        let r = call(&mut c, "human.submit", json!({"op": op, "sig": sig}))?;
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
    println!(
        "recovered. The recovery key is used up: delete {} and set a new one with \
         `lonca human recovery-key`.",
        recovery_key.display()
    );
    Ok(())
}
