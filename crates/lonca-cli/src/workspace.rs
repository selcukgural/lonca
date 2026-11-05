//! Workspaces: a directory with the files of a base commit, plus
//! `.lonca/workspace.json` (repo, base, manifest) and, for agents,
//! `.lonca/session` (the session token, mode 0600). An agent's workspace is
//! a git repository too (see `gitdir`), for the tools that expect one.
//!
//! Symlinks are written as regular files holding their target, so editing a
//! workspace can never reach outside it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use lonca_core::{FileEntry, FileMode, GitId};
use lonca_daemon::Client;
use lonca_daemon::protocol::{FileChange, LocalFile, TreeFile};
use lonca_symbols::engine::ENGINE_CURRENT;
use lonca_symbols::merge::{merge_around_conflicts, merge_text_at};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::ctx::{self, call};
use crate::gitdir;

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
    /// Scratch roots of the session, for information: the daemon holds
    /// the authoritative list in the log and sends it at `hook.bind`.
    #[serde(default)]
    pub scratch_roots: Vec<String>,
    /// `<file>.trunk` copies the last sync wrote. They are for reading:
    /// never a local change, and gone at the next sync.
    #[serde(default)]
    pub trunk_copies: Vec<String>,
    /// Files `lonca harness setup` wrote: never a local change, and only
    /// ever paths the repository does not have.
    #[serde(default)]
    pub generated: Vec<String>,
    /// The workspace has a `.git` Lonca keeps at the base.
    #[serde(default)]
    pub git: bool,
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

    /// The workspace at `dir` itself, for a new session of `repo` to go on
    /// with. Returns it with the session it was left by.
    pub fn to_continue(dir: &Path, repo: &str) -> Result<(Workspace, String)> {
        let ws = Workspace::find(dir)
            .filter(|ws| ws.root == dir)
            .with_context(|| format!("{} is not a Lonca workspace", dir.display()))?;
        if ws.meta.repo != repo {
            bail!(
                "{} is a workspace of repository {}, not {repo}",
                dir.display(),
                ws.meta.repo
            );
        }
        let Some(session) = ws.meta.session.clone() else {
            bail!(
                "{} is a human workspace: no session to continue",
                dir.display()
            );
        };
        Ok((ws, session))
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

    /// Creates a workspace in `dir` (which must be empty or missing); `git`
    /// makes it a repository as well.
    pub fn create(
        client: &mut Client,
        dir: &Path,
        repo: &str,
        session: Option<String>,
        human: Option<String>,
        git: bool,
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
                scratch_roots: vec![],
                trunk_copies: vec![],
                generated: vec![],
                git,
            },
        };
        ws.save()?;
        fs::write(dir.join(META_DIR).join(".gitignore"), "*\n")?;
        if git {
            gitdir::init(dir)?;
            ws.write_git_base(&files)?;
        }
        Ok(ws)
    }

    /// Moves `.git` to the base. `files` are those whose content it may
    /// not hold yet.
    fn write_git_base<'a>(&self, files: impl IntoIterator<Item = &'a TreeFile>) -> Result<()> {
        let blobs = files
            .into_iter()
            .filter(|f| f.mode != FileMode::Submodule)
            .map(content)
            .collect::<Result<Vec<_>>>()?;
        gitdir::set_base(
            &self.root,
            &self.meta.base,
            &self.meta.manifest,
            blobs.iter().map(Vec::as_slice),
            ctx::now_ms(),
        )?;
        self.exclude_from_git()
    }

    /// Tells `.git` what `changes()` skips.
    pub fn exclude_from_git(&self) -> Result<()> {
        if !self.meta.git {
            return Ok(());
        }
        let skipped = [&self.meta.generated, &self.meta.trunk_copies];
        gitdir::set_excluded(&self.root, skipped.into_iter().flatten())
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
            let known = [&self.meta.trunk_copies, &self.meta.generated];
            if self.meta.manifest.contains_key(&rel) || known.iter().any(|l| l.contains(&rel)) {
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

    /// [`Workspace::changes`] as tree entries, with no content: what the
    /// daemon needs to tell a proposed file from one nobody proposed.
    pub fn local_files(&self) -> Result<Vec<LocalFile>> {
        let local = |c: FileChange| {
            let entry = match c.content_b64 {
                Some(text) => Some(FileEntry {
                    mode: c.mode.unwrap_or(FileMode::Regular),
                    blob: GitId::of_blob(&b64().decode(text)?),
                }),
                None => None,
            };
            Ok(LocalFile {
                path: c.path,
                entry,
            })
        };
        self.changes()?.into_iter().map(local).collect()
    }

    /// Brings trunk into the workspace, keeping local edits. Files edited
    /// locally and on trunk are merged with Lonca's structural merge; on a
    /// conflict everything else of trunk still comes in, the conflicting
    /// symbols keep the local text and trunk's version is written next to
    /// the file as `<file>.trunk`. A file with no symbol merge stays local
    /// as a whole.
    pub fn sync(&mut self, client: &mut Client) -> Result<SyncReport> {
        let status = call(client, "status", json!({}))?;
        let trunk: GitId = serde_json::from_value(status["trunk"].clone())?;
        let mut report = SyncReport {
            from: self.meta.base.clone(),
            to: trunk.clone(),
            updated: vec![],
            merged: vec![],
            conflicts: vec![],
            symbols: vec![],
            git_warning: None,
        };
        if trunk == self.meta.base {
            return Ok(report);
        }
        for copy in std::mem::take(&mut self.meta.trunk_copies) {
            let _ = fs::remove_file(self.root.join(copy));
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
                    let texts = match (
                        std::str::from_utf8(&base_text),
                        std::str::from_utf8(&mine_text),
                        std::str::from_utf8(&trunk_text),
                    ) {
                        (Ok(b), Ok(o), Ok(t)) if m.content_b64.is_some() && new.is_some() => {
                            Some((b, o, t))
                        }
                        _ => None,
                    };
                    let merged =
                        texts.map(|(b, o, t)| merge_text_at(ENGINE_CURRENT, &path, b, o, t));
                    if let Some(Ok(text)) = merged {
                        fs::write(self.root.join(&path), text)?;
                        report.merged.push(path.clone());
                        continue;
                    }
                    if let Some(Err(symbols)) = merged {
                        report.symbols.extend(symbols);
                    }
                    let kept = texts.and_then(|(b, o, t)| {
                        merge_around_conflicts(ENGINE_CURRENT, &path, b, o, t)
                    });
                    if let Some(text) = kept {
                        fs::write(self.root.join(&path), text)?;
                    }
                    if let Some(f) = new {
                        let side = TreeFile {
                            path: format!("{path}.trunk"),
                            ..f.clone()
                        };
                        write_file(&self.root, &side)?;
                        self.meta.trunk_copies.push(side.path);
                    }
                    report.conflicts.push(path.clone());
                }
            }
        }
        let manifest = new_files
            .values()
            .map(|f| (f.path.clone(), (f.mode, f.blob.clone())))
            .collect();
        let held: BTreeSet<&GitId> = self.meta.manifest.values().map(|(_, b)| b).collect();
        let fresh: Vec<&TreeFile> = new_files
            .values()
            .filter(|f| !held.contains(&f.blob))
            .collect();
        // The sync is done once this is saved: a `.git` that has been
        // tampered with costs `git diff` its meaning, and nothing else.
        self.meta.base = trunk;
        self.meta.manifest = manifest;
        // Trunk's file took the place of one that was generated.
        let manifest = &self.meta.manifest;
        self.meta.generated.retain(|p| !manifest.contains_key(p));
        self.save()?;
        report.git_warning = self
            .meta
            .git
            .then(|| self.write_git_base(fresh))
            .and_then(|r| r.err())
            .map(|e| format!("{e:#}"));
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
    /// The symbols in conflict, `path#name`.
    pub symbols: Vec<String>,
    /// `.git` could not follow the new base; the sync itself went through.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_warning: Option<String>,
}

impl SyncReport {
    /// The symbols of `path` in conflict.
    pub fn symbols_of(&self, path: &str) -> Vec<&str> {
        let in_file = |s: &&String| s.split_once('#').is_some_and(|(p, _)| p == path);
        self.symbols
            .iter()
            .filter(in_file)
            .map(String::as_str)
            .collect()
    }
}

/// How many encoded bytes one `blobs` page may carry. `LONCA_FETCH_BUDGET`
/// overrides it (tests); the default is the daemon's page budget for
/// `MAX_LINE`.
pub fn fetch_budget() -> u64 {
    std::env::var("LONCA_FETCH_BUDGET")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| lonca_daemon::service::page_budget(lonca_daemon::protocol::MAX_LINE))
}

fn encoded_len(bytes: u64) -> u64 {
    bytes.div_ceil(3) * 4
}

/// Groups files, in order, into pages whose encoded size stays within
/// `budget`; a page may hold exactly the budget. A file that alone does
/// not fit is an error naming it.
fn plan_pages(files: &[(String, u64)], budget: u64) -> Result<Vec<Vec<String>>> {
    let mut pages: Vec<Vec<String>> = vec![];
    let mut page: Vec<String> = vec![];
    let mut used = 0u64;
    for (path, size) in files {
        let need = encoded_len(*size);
        if need > budget {
            bail!(
                "{path} is {size} bytes, more than one fetch page holds ({budget} encoded); \
                 keep such files out of the repository or raise the cap"
            );
        }
        if used + need > budget && !page.is_empty() {
            pages.push(std::mem::take(&mut page));
            used = 0;
        }
        used += need;
        page.push(path.clone());
    }
    if !page.is_empty() {
        pages.push(page);
    }
    Ok(pages)
}

/// The files of a commit with their contents: the manifest in one call,
/// then the contents in pages that stay under the budget. A file too
/// large for one page is reported by path.
pub fn fetch(
    client: &mut Client,
    commit: &GitId,
    paths: Option<Vec<String>>,
) -> Result<Vec<TreeFile>> {
    let v = call(
        client,
        "tree",
        json!({"commit": commit, "with_content": false, "paths": paths}),
    )?;
    let mut files: Vec<TreeFile> = serde_json::from_value(v)?;
    let sizes: Vec<(String, u64)> = files
        .iter()
        .filter(|f| f.mode != FileMode::Submodule)
        .map(|f| (f.path.clone(), f.size))
        .collect();
    let pages = plan_pages(&sizes, fetch_budget())?;
    let mut contents: BTreeMap<String, Option<String>> = BTreeMap::new();
    for paths in pages {
        let v = call(client, "blobs", json!({"commit": commit, "paths": paths}))?;
        let got: Vec<TreeFile> = serde_json::from_value(v)?;
        for f in got {
            contents.insert(f.path, f.content_b64);
        }
    }
    for f in &mut files {
        if let Some(c) = contents.remove(&f.path) {
            f.content_b64 = c;
        }
    }
    Ok(files)
}

fn content(f: &TreeFile) -> Result<Vec<u8>> {
    let bytes = f
        .content_b64
        .as_ref()
        .map(|c| b64().decode(c))
        .transpose()?;
    Ok(bytes.unwrap_or_default())
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
    fs::write(&target, content(f)?)?;
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

#[cfg(test)]
mod tests {
    use super::{encoded_len, plan_pages};

    #[test]
    fn pages_fill_to_the_budget_in_order_and_refuse_what_never_fits() {
        let f = |n: &str, size: u64| (n.to_string(), size);
        // 750 bytes encode to 1000: two fill a 2000 page exactly, the third
        // starts the next page; a small file after it joins that page.
        let files = [f("a", 750), f("b", 750), f("c", 750), f("d", 3)];
        let pages = plan_pages(&files, 2000).unwrap();
        assert_eq!(
            pages,
            vec![
                vec!["a".to_string(), "b".into()],
                vec!["c".into(), "d".into()]
            ]
        );
        // One byte over the pair: each alone.
        let files = [f("a", 751), f("b", 750)];
        assert_eq!(
            plan_pages(&files, 2000).unwrap(),
            vec![vec!["a".to_string()], vec!["b".into()]]
        );
        // Many small files in one page; an empty list is no page.
        let many: Vec<_> = (0..10).map(|i| f(&i.to_string(), 30)).collect();
        assert_eq!(plan_pages(&many, 2000).unwrap().len(), 1);
        assert!(plan_pages(&[], 2000).unwrap().is_empty());
        // A file that alone exceeds the budget is named.
        let err = plan_pages(&[f("x", 10), f("big.bin", 1501)], 2000).unwrap_err();
        assert!(
            err.to_string().starts_with("big.bin is 1501 bytes"),
            "{err}"
        );
        assert_eq!(
            plan_pages(&[f("edge", 1500)], 2000).unwrap(),
            vec![vec!["edge".to_string()]]
        );
    }

    /// Base64 of n bytes is ceil(n / 3) * 4; the page budget depends on
    /// it, so an under-estimate would ask the daemon for pages it refuses.
    #[test]
    fn encoded_length_is_base64_size() {
        for (bytes, encoded) in [
            (0, 0),
            (1, 4),
            (2, 4),
            (3, 4),
            (4, 8),
            (6, 8),
            (900, 1200),
            (1500, 2000),
        ] {
            assert_eq!(encoded_len(bytes), encoded, "{bytes} bytes");
        }
    }
}
