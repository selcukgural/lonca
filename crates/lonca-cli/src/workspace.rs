//! Workspaces: a plain directory with the files of a base commit, plus
//! `.lonca/workspace.json` (repo, base, manifest) and, for agents,
//! `.lonca/session` (the session token, mode 0600).
//!
//! Symlinks are written as regular files holding their target, so editing a
//! workspace can never reach outside it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use lonca_core::{FileMode, GitId};
use lonca_daemon::Client;
use lonca_daemon::protocol::{FileChange, TreeFile};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::ctx::call;

pub const META_DIR: &str = ".lonca";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Meta {
    pub repo: String,
    pub base: GitId,
    pub session: Option<String>,
    pub human: Option<String>,
    pub manifest: BTreeMap<String, (FileMode, GitId)>,
    /// The last change proposed from this workspace and its commit. Once it
    /// is integrated, files still equal to it are no longer local edits.
    #[serde(default)]
    pub submitted: Option<(lonca_core::ChangeId, GitId)>,
}

pub struct Workspace {
    pub root: PathBuf,
    pub meta: Meta,
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

impl Workspace {
    pub fn find(start: &Path) -> Option<Workspace> {
        let mut cur = Some(start);
        while let Some(dir) = cur {
            let f = dir.join(META_DIR).join("workspace.json");
            if let Ok(bytes) = fs::read(&f) {
                let meta: Meta = serde_json::from_slice(&bytes).ok()?;
                return Some(Workspace {
                    root: dir.to_path_buf(),
                    meta,
                });
            }
            cur = dir.parent();
        }
        None
    }

    pub fn current() -> Result<Workspace> {
        let cwd = std::env::current_dir()?;
        let start = std::env::var_os("LONCA_WORKSPACE")
            .map(PathBuf::from)
            .unwrap_or(cwd);
        Workspace::find(&start)
            .context("not inside a Lonca workspace (no .lonca/workspace.json above this directory)")
    }

    pub fn token(&self) -> Result<String> {
        let t = fs::read_to_string(self.root.join(META_DIR).join("session"))
            .context("this workspace has no agent session")?;
        Ok(t.trim().to_string())
    }

    pub fn save(&self) -> Result<()> {
        let dir = self.root.join(META_DIR);
        fs::create_dir_all(&dir)?;
        let tmp = dir.join("workspace.json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(&self.meta)?)?;
        fs::rename(tmp, dir.join("workspace.json"))?;
        Ok(())
    }

    pub fn write_token(&self, token: &str) -> Result<()> {
        let dir = self.root.join(META_DIR);
        fs::create_dir_all(&dir)?;
        let p = dir.join("session");
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        use std::io::Write;
        opts.open(p)?.write_all(token.as_bytes())?;
        Ok(())
    }

    /// Creates a workspace in `dir` (which must be empty or missing).
    pub fn create(
        client: &mut Client,
        dir: &Path,
        repo: &str,
        session: Option<String>,
        human: Option<String>,
    ) -> Result<Workspace> {
        if dir.exists() && fs::read_dir(dir)?.next().is_some() {
            bail!("{} is not empty", dir.display());
        }
        fs::create_dir_all(dir)?;
        let status = call(client, "status", json!({}))?;
        let base: GitId = serde_json::from_value(status["trunk"].clone())?;
        let files = fetch(client, &base, None)?;
        let mut manifest = BTreeMap::new();
        for f in &files {
            if f.mode == FileMode::Submodule {
                continue;
            }
            write_file(dir, f)?;
            manifest.insert(f.path.clone(), (f.mode, f.blob.clone()));
        }
        let ws = Workspace {
            root: dir.to_path_buf(),
            meta: Meta {
                repo: repo.into(),
                base,
                session,
                human,
                manifest,
                submitted: None,
            },
        };
        ws.save()?;
        fs::write(dir.join(META_DIR).join(".gitignore"), "*\n")?;
        Ok(ws)
    }

    fn read(&self, path: &str) -> Option<Vec<u8>> {
        fs::read(self.root.join(path)).ok()
    }

    fn is_executable(&self, path: &str) -> bool {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::metadata(self.root.join(path))
                .map(|m| m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            false
        }
    }

    /// Local changes against the base, as daemon file changes.
    pub fn changes(&self) -> Result<Vec<FileChange>> {
        let mut out = Vec::new();
        for (path, (mode, blob)) in &self.meta.manifest {
            match self.read(path) {
                None => out.push(FileChange {
                    path: path.clone(),
                    content_b64: None,
                    mode: None,
                }),
                Some(bytes) => {
                    let exec = self.is_executable(path);
                    let new_mode = match mode {
                        FileMode::Regular if exec => Some(FileMode::Executable),
                        FileMode::Executable if !exec => Some(FileMode::Regular),
                        _ => None,
                    };
                    if GitId::of_blob(&bytes) != *blob || new_mode.is_some() {
                        out.push(FileChange {
                            path: path.clone(),
                            content_b64: Some(b64().encode(&bytes)),
                            mode: new_mode.or(Some(*mode)),
                        });
                    }
                }
            }
        }
        let walker = ignore::WalkBuilder::new(&self.root)
            .hidden(false)
            .git_ignore(true)
            .git_global(false)
            .git_exclude(false)
            .require_git(false)
            .filter_entry(|e| !matches!(e.file_name().to_str(), Some(".lonca") | Some(".git")))
            .build();
        for entry in walker {
            let entry = entry?;
            if !entry.file_type().is_some_and(|t| t.is_file()) {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(&self.root)?
                .to_string_lossy()
                .replace('\\', "/");
            if self.meta.manifest.contains_key(&rel) {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let mode = if self.is_executable(&rel) {
                FileMode::Executable
            } else {
                FileMode::Regular
            };
            out.push(FileChange {
                path: rel,
                content_b64: Some(b64().encode(&bytes)),
                mode: Some(mode),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// Brings trunk into the workspace, keeping local edits. Files edited
    /// locally and on trunk are merged with Lonca's structural merge; on a
    /// conflict the local file is kept and trunk's version is written next
    /// to it as `<file>.trunk`.
    pub fn sync(&mut self, client: &mut Client) -> Result<SyncReport> {
        let status = call(client, "status", json!({}))?;
        let trunk: GitId = serde_json::from_value(status["trunk"].clone())?;
        let mut report = SyncReport {
            from: self.meta.base.clone(),
            to: trunk.clone(),
            updated: vec![],
            merged: vec![],
            conflicts: vec![],
        };
        if trunk == self.meta.base {
            return Ok(report);
        }
        let new_files: BTreeMap<String, TreeFile> = fetch(client, &trunk, None)?
            .into_iter()
            .filter(|f| f.mode != FileMode::Submodule)
            .map(|f| (f.path.clone(), f))
            .collect();
        let mut local: BTreeMap<String, FileChange> = self
            .changes()?
            .into_iter()
            .map(|c| (c.path.clone(), c))
            .collect();
        if let Some((change, commit)) = self.meta.submitted.clone() {
            let status = call(client, "change.get", json!({"change": change}))?;
            match status["status"]["status"].as_str().unwrap_or("") {
                "integrated" => {
                    // Edits that went in with the change are not local any more.
                    let proposed: BTreeMap<String, GitId> = fetch(client, &commit, None)?
                        .into_iter()
                        .map(|f| (f.path, f.blob))
                        .collect();
                    local.retain(|path, c| {
                        let mine = c
                            .content_b64
                            .as_ref()
                            .and_then(|b| b64().decode(b).ok())
                            .map(|b| GitId::of_blob(&b));
                        mine.as_ref() != proposed.get(path)
                    });
                    self.meta.submitted = None;
                }
                "queued" | "pending" => {}
                _ => self.meta.submitted = None,
            }
        }
        // Base contents are needed only where both sides changed.
        let both: Vec<String> = local
            .keys()
            .filter(|p| {
                self.meta.manifest.get(*p).map(|(_, b)| b) != new_files.get(*p).map(|f| &f.blob)
            })
            .cloned()
            .collect();
        let base_files: BTreeMap<String, TreeFile> = if both.is_empty() {
            BTreeMap::new()
        } else {
            fetch(client, &self.meta.base, Some(both.clone()))?
                .into_iter()
                .map(|f| (f.path.clone(), f))
                .collect()
        };
        let paths: BTreeSet<String> = self
            .meta
            .manifest
            .keys()
            .chain(new_files.keys())
            .cloned()
            .collect();
        for path in paths {
            let old = self.meta.manifest.get(&path).map(|(_, b)| b.clone());
            let new = new_files.get(&path);
            let mine = local.get(&path);
            if old.as_ref() == new.map(|f| &f.blob) {
                continue; // trunk did not touch it; local edits stay as they are
            }
            match (mine, new) {
                (None, Some(f)) => {
                    write_file(&self.root, f)?;
                    report.updated.push(path.clone());
                }
                (None, None) => {
                    let _ = fs::remove_file(self.root.join(&path));
                    report.updated.push(path.clone());
                }
                (Some(m), new) => {
                    let decode = |s: &Option<String>| -> Vec<u8> {
                        s.as_ref()
                            .and_then(|x| b64().decode(x).ok())
                            .unwrap_or_default()
                    };
                    // Local already equals trunk (typically our own change came back).
                    let same = match (&m.content_b64, new) {
                        (Some(c), Some(f)) => GitId::of_blob(&decode(&Some(c.clone()))) == f.blob,
                        (None, None) => true,
                        _ => false,
                    };
                    if same {
                        continue;
                    }
                    let base_text = base_files
                        .get(&path)
                        .map(|f| decode(&f.content_b64))
                        .unwrap_or_default();
                    let mine_text = decode(&m.content_b64);
                    let trunk_text = new.map(|f| decode(&f.content_b64)).unwrap_or_default();
                    let merged = match (
                        std::str::from_utf8(&base_text),
                        std::str::from_utf8(&mine_text),
                        std::str::from_utf8(&trunk_text),
                    ) {
                        (Ok(b), Ok(o), Ok(t)) if m.content_b64.is_some() && new.is_some() => {
                            lonca_symbols::merge::merge_text(&path, b, o, t).ok()
                        }
                        _ => None,
                    };
                    match merged {
                        Some(text) => {
                            fs::write(self.root.join(&path), text)?;
                            report.merged.push(path.clone());
                        }
                        None => {
                            if let Some(f) = new {
                                let side = TreeFile {
                                    path: format!("{path}.trunk"),
                                    ..f.clone()
                                };
                                write_file(&self.root, &side)?;
                            }
                            report.conflicts.push(path.clone());
                        }
                    }
                }
            }
        }
        self.meta.base = trunk;
        self.meta.manifest = new_files
            .into_iter()
            .map(|(p, f)| (p, (f.mode, f.blob)))
            .collect();
        self.save()?;
        Ok(report)
    }
}

#[derive(Debug, Serialize)]
pub struct SyncReport {
    pub from: GitId,
    pub to: GitId,
    pub updated: Vec<String>,
    pub merged: Vec<String>,
    pub conflicts: Vec<String>,
}

pub fn fetch(
    client: &mut Client,
    commit: &GitId,
    paths: Option<Vec<String>>,
) -> Result<Vec<TreeFile>> {
    let v = call(
        client,
        "tree",
        json!({"commit": commit, "with_content": true, "paths": paths}),
    )?;
    Ok(serde_json::from_value(v)?)
}

fn write_file(root: &Path, f: &TreeFile) -> Result<()> {
    lonca_core::paths::validate_repo_path(&f.path)?;
    if f.path == META_DIR || f.path.starts_with(".lonca/") {
        bail!("refusing to write {} into workspace metadata", f.path);
    }
    let target = root.join(&f.path);
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    // Replace whatever is there (including a symlink) with a regular file.
    let _ = fs::remove_file(&target);
    let bytes = f
        .content_b64
        .as_ref()
        .map(|c| b64().decode(c))
        .transpose()?
        .unwrap_or_default();
    fs::write(&target, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if f.mode == FileMode::Executable {
            0o755
        } else {
            0o644
        };
        fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
    }
    Ok(())
}
