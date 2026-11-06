//! `lonca harness setup`: gives a harness the rules, the MCP server and the
//! hooks. Knows no harness: what to write comes from the profile in the
//! signed policy. A harness with no profile still gets the rules and how to
//! start `lonca mcp`.

use std::fs;

use anyhow::{Context, Result, bail};
use lonca_core::paths::{is_workspace_metadata, validate_repo_path};
use lonca_daemon::Client;
use lonca_policy::harness::{Filled, Setup, rules};
use serde_json::{Value, json};

use crate::ctx;
use crate::workspace::Workspace;
use crate::wsfs;

pub struct Prepared {
    harness: String,
    known: bool,
    filled: Filled,
    rules: String,
    mcp: Value,
}

/// The rules for this workspace, with the neutral tool names.
pub fn neutral_rules(ws: Option<&Workspace>) -> String {
    let scratch = ws.map_or(&[][..], |ws| &ws.meta.scratch_roots);
    let roots: Vec<&str> = scratch.iter().map(String::as_str).collect();
    rules("", "", &roots)
}

/// Reads the harness's setup from the policy and fills it in for `ws`.
pub fn prepare(client: &mut Client, ws: &Workspace, harness: &str) -> Result<Prepared> {
    let r = ctx::call(client, "harness.setup", json!({"harness": harness}))?;
    let setup: Option<Setup> = serde_json::from_value(r["setup"].clone())?;
    let rules = neutral_rules(Some(ws));
    let socket = ctx::socket().to_string_lossy().into_owned();
    let workspace = ws.root.to_string_lossy().into_owned();
    let filled = match &setup {
        Some(s) => s
            .fill(&rules, &socket, &workspace)
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("the setup of harness {harness}"))?,
        None => Filled::default(),
    };
    Ok(Prepared {
        harness: harness.to_string(),
        known: setup.is_some(),
        filled,
        rules,
        mcp: json!({
            "command": "lonca",
            "args": ["mcp"],
            "cwd": workspace,
            "env": {"LONCA_SOCKET": socket, "LONCA_WORKSPACE": workspace},
        }),
    })
}

impl Prepared {
    /// Writes the files and records them as generated, so they are never a
    /// local change. Nothing is written unless all of them can be.
    pub fn write(&self, ws: &mut Workspace) -> Result<Vec<String>> {
        for path in self.filled.files.keys() {
            check_target(ws, path)?;
        }
        let paths: Vec<String> = self.filled.files.keys().cloned().collect();
        for path in &paths {
            if !ws.meta.generated.contains(path) {
                ws.meta.generated.push(path.clone());
            }
        }
        // Listed before written: a crash leaves a name, not a local change.
        ws.save()?;
        for (path, text) in &self.filled.files {
            wsfs::write(&ws.root, path, text.as_bytes(), wsfs::REGULAR)?;
        }
        ws.exclude_from_git()?;
        Ok(paths)
    }

    pub fn report(&self, written: &[String]) -> Value {
        json!({
            "harness": self.harness,
            "known": self.known,
            "written": written,
            "files": self.filled.files,
            "flags": self.filled.flags,
            "env": self.filled.env,
            "note": self.filled.note,
            "rules": self.rules,
            "mcp": self.mcp,
        })
    }

    /// `print`: the caller wrote nothing and wants all of it.
    pub fn print(&self, written: &[String], print: bool) -> Result<()> {
        for path in written {
            println!("wrote {path}");
        }
        if !self.known {
            println!(
                "no profile for harness {}: give it the MCP server and the rules",
                self.harness
            );
            println!("{}", serde_json::to_string_pretty(&self.mcp)?);
            println!("{}", self.rules);
            return Ok(());
        }
        for (key, value) in &self.filled.env {
            println!("{key}={}", shell_quote(value));
        }
        if print || written.is_empty() {
            let flags: Vec<String> = self.filled.flags.iter().map(|f| shell_quote(f)).collect();
            println!("{}", flags.join(" "));
        }
        if print {
            for (path, text) in &self.filled.files {
                print!("--- {path}\n{text}");
            }
        }
        if !self.filled.note.is_empty() {
            eprintln!("{}", self.filled.note);
        }
        Ok(())
    }
}

/// A profile comes from the policy and an agent may have been in the
/// workspace first, so neither decides where a write lands: never over a
/// file of the repository or a local one, never through a symlink, never
/// into workspace metadata.
fn check_target(ws: &Workspace, path: &str) -> Result<()> {
    validate_repo_path(path)?;
    if is_workspace_metadata(path) {
        bail!("refusing to write {path} into workspace metadata");
    }
    let parts: Vec<&str> = path.split('/').collect();
    let hint = "pass what it needs as flags instead: lonca harness setup --print";
    if ws.meta.manifest.contains_key(path) {
        bail!("{path} is a file of the repository; {hint}");
    }
    let mut at = ws.root.clone();
    for part in &parts {
        at.push(part);
        let Ok(meta) = fs::symlink_metadata(&at) else {
            return Ok(()); // nothing there, nor below it
        };
        if meta.file_type().is_symlink() {
            bail!("refusing to write {path}: {} is a symlink", at.display());
        }
    }
    if !ws.meta.generated.iter().any(|p| p == path) {
        bail!("{path} exists and is a local file; {hint}");
    }
    Ok(())
}

/// One argument as a POSIX shell reads it.
fn shell_quote(s: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c);
    if !s.is_empty() && s.chars().all(plain) {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace::Meta;
    use std::collections::BTreeMap;
    use std::path::Path;

    fn ws(root: &Path) -> Workspace {
        let blob = lonca_core::GitId::of_blob(b"x");
        Workspace {
            root: root.to_path_buf(),
            meta: Meta {
                repo: "demo".into(),
                base: blob.clone(),
                session: None,
                human: None,
                manifest: BTreeMap::from([(
                    ".mcp.json".to_string(),
                    (lonca_core::FileMode::Regular, blob),
                )]),
                submitted: None,
                scratch_roots: vec![],
                trunk_copies: vec![],
                conflict_tag: None,
                generated: vec![],
                git: false,
            },
        }
    }

    fn prepared(files: &[(&str, &str)]) -> Prepared {
        let files = files.iter().map(|(p, t)| (p.to_string(), t.to_string()));
        Prepared {
            harness: "acme".into(),
            known: true,
            filled: Filled {
                files: files.collect(),
                ..Filled::default()
            },
            rules: String::new(),
            mcp: Value::Null,
        }
    }

    #[test]
    fn a_target_is_refused_for_what_it_would_touch() {
        let dir = tempfile::tempdir().unwrap();
        let w = ws(dir.path());
        for (path, why) in [
            ("../out", "component"),
            ("/etc/x", "relative"),
            (".git/config", ".git"),
            (".lonca/session", "metadata"),
            (".LONCA/session", "metadata"),
            (".mcp.json", "file of the repository"),
        ] {
            let e = format!("{:#}", check_target(&w, path).unwrap_err());
            assert!(e.contains(why), "{path}: {e}");
        }
        check_target(&w, ".acme/new/settings.json").unwrap();
    }

    #[test]
    fn nothing_is_written_through_a_symlink_or_over_a_local_file() {
        let dir = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let victim = out.path().join("victim");
        fs::write(&victim, "mine").unwrap();
        std::os::unix::fs::symlink(out.path(), dir.path().join("linked")).unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join("leaf")).unwrap();
        fs::write(dir.path().join("local"), "work").unwrap();
        let mut w = ws(dir.path());
        for (path, why) in [
            ("linked/victim", "symlink"),
            ("leaf", "symlink"),
            ("local", "local file"),
        ] {
            let p = prepared(&[("fresh", "x"), (path, "x")]);
            let e = format!("{:#}", p.write(&mut w).unwrap_err());
            assert!(e.contains(why), "{path}: {e}");
            assert!(!dir.path().join("fresh").exists(), "all or nothing");
            assert!(w.meta.generated.is_empty());
        }
        assert_eq!(fs::read_to_string(&victim).unwrap(), "mine");
    }

    #[test]
    fn writing_again_replaces_what_setup_wrote_and_lists_it_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = ws(dir.path());
        let written = prepared(&[(".acme/a.json", "1")]).write(&mut w).unwrap();
        assert_eq!(written, [".acme/a.json"]);
        prepared(&[(".acme/a.json", "2")]).write(&mut w).unwrap();
        assert_eq!(w.meta.generated, [".acme/a.json"]);
        let text = fs::read_to_string(dir.path().join(".acme/a.json")).unwrap();
        assert_eq!(text, "2");
        let saved = Workspace::find(dir.path()).unwrap();
        assert_eq!(saved.meta.generated, [".acme/a.json"]);
    }

    #[test]
    fn an_argument_survives_the_shell() {
        assert_eq!(shell_quote("--flag=a/b.c"), "--flag=a/b.c");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote("$HOME"), "'$HOME'");
    }

    #[test]
    fn neutral_rules_name_the_scratch_of_the_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let mut w = ws(dir.path());
        assert!(!neutral_rules(None).contains("scratch"));
        w.meta.scratch_roots = vec!["/work/s".into()];
        assert!(neutral_rules(Some(&w)).contains("/work/s"));
    }
}
