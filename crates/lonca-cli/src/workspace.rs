//! Workspaces: a directory with the files of a base commit, plus
//! `.lonca/workspace.json` (repo, base, manifest) and, for agents,
//! `.lonca/session` (the session token, mode 0600). An agent's workspace is
//! a git repository too (see `gitdir`), for the tools that expect one.
//!
//! Symlinks are written as regular files holding their target, and every
//! access goes through `wsfs`, so nothing here reaches outside the root.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use base64::Engine;
use ignore::Match;
use ignore::gitignore::{Gitignore, GitignoreBuilder};
use lonca_core::{FileEntry, FileMode, GitId};
use lonca_daemon::Client;
use lonca_daemon::protocol::{FileChange, LocalFile, TreeFile};
use lonca_symbols::engine::ENGINE_CURRENT;
use lonca_symbols::lines;
use lonca_symbols::merge::{marked_around_conflicts, merge_text_at};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::ctx::{self, call};
use crate::{gitdir, wsfs};

pub const META_DIR: &str = ".lonca";

/// What `session start` leaves in `META_DIR`, and all that may stand there.
const META_FILES: [&str; 3] = ["workspace.json", "session", ".gitignore"];

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
    /// What the conflict markers of a sync carry, while any stand. A file
    /// with them must not be proposed, whatever its path has become.
    #[serde(default)]
    pub conflict_tag: Option<String>,
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
        let file = meta_file("workspace.json");
        while let Some(dir) = cur {
            if let Ok(Some(local)) = wsfs::read(dir, &file) {
                let meta: Meta = serde_json::from_slice(&local.bytes).ok()?;
                return Some(Workspace {
                    root: dir.to_path_buf(),
                    meta,
                });
            }
            cur = dir.parent();
        }
        None
    }

    /// Is `start` in a workspace, even one whose metadata no longer reads?
    pub fn encloses(start: &Path) -> bool {
        let file = Path::new(META_DIR).join("workspace.json");
        let there = |dir: &Path| fs::symlink_metadata(dir.join(&file)).is_ok();
        start.ancestors().any(there)
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
    /// with. Which session left it is not read here: the log says.
    pub fn to_continue(dir: &Path, repo: &str) -> Result<Workspace> {
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
        Ok(ws)
    }

    pub fn token(&self) -> Result<String> {
        // In a sandbox, the token is not in the workspace: `lonca run`
        // replaced that one, which outsiders may have seen.
        if let Some(file) = std::env::var_os("LONCA_TOKEN_FILE") {
            let text = fs::read_to_string(&file)
                .with_context(|| format!("token file {}", file.display()))?;
            return Ok(text.trim().to_string());
        }
        let t = wsfs::read(&self.root, &meta_file("session"))?
            .context("this workspace has no agent session")?;
        Ok(String::from_utf8_lossy(&t.bytes).trim().to_string())
    }

    pub fn save(&self) -> Result<()> {
        let meta = serde_json::to_vec_pretty(&self.meta)?;
        wsfs::write(
            &self.root,
            &meta_file("workspace.json"),
            &meta,
            wsfs::REGULAR,
        )
    }

    pub fn write_token(&self, token: &str) -> Result<()> {
        let name = meta_file("session");
        wsfs::write(&self.root, &name, token.as_bytes(), wsfs::SECRET)
    }

    /// Refuses `dir` for a new workspace unless it is missing or empty.
    pub fn check_empty(dir: &Path) -> Result<()> {
        if dir.exists() && fs::read_dir(dir)?.next().is_some() {
            bail!("{} is not empty", dir.display());
        }
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
        Self::check_empty(dir)?;
        fs::create_dir_all(dir)?;
        let status = call(client, "status", json!({}))?;
        let base: GitId = serde_json::from_value(status["trunk"].clone())?;
        let files = fetch(client, &base, None)?;
        let manifest = manifest_of(&files);
        for f in files.iter().filter(|f| f.mode != FileMode::Submodule) {
            write_file(dir, f)?;
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
                conflict_tag: None,
                generated: vec![],
                git,
            },
        };
        ws.save()?;
        ws.write_gitignore()?;
        if git {
            gitdir::init(dir)?;
            let (blobs, time_ms) = (blobs_of(&files)?, ctx::now_ms());
            let contents = blobs.iter().map(Vec::as_slice);
            gitdir::first_base(dir, &ws.meta.base, &ws.meta.manifest, contents, time_ms)?;
            ws.exclude_from_git()?;
        }
        Ok(ws)
    }

    fn write_gitignore(&self) -> Result<()> {
        let name = meta_file(".gitignore");
        wsfs::write(&self.root, &name, b"*\n", wsfs::REGULAR)
    }

    /// Writes the whole workspace afresh from `files`, the base as the
    /// daemon has it: a comparison sees no mode, attribute or date of a
    /// file, nothing in `.git` and `.lonca`. Nothing stands here but the
    /// new, so the token is gone too, and only after a decision to run may
    /// this be called: it takes all there was. The generated files stay
    /// listed, for the caller to write.
    pub fn start_clean(&mut self, files: &[TreeFile]) -> Result<()> {
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            // Neither of these follows a link.
            if entry.file_type()?.is_dir() {
                fs::remove_dir_all(entry.path())?;
            } else {
                fs::remove_file(entry.path())?;
            }
        }
        for f in files.iter().filter(|f| f.mode != FileMode::Submodule) {
            write_file(&self.root, f)?;
        }
        self.meta.manifest = manifest_of(files);
        self.meta.human = None;
        self.meta.submitted = None;
        self.meta.trunk_copies.clear();
        self.meta.conflict_tag = None;
        self.save()?;
        self.write_gitignore()?;
        if self.meta.git {
            gitdir::init(&self.root)?;
            self.write_git_base(files)?;
        }
        Ok(())
    }

    /// Moves `.git` to the base. `files` are those whose content it may
    /// not hold yet.
    fn write_git_base<'a>(&self, files: impl IntoIterator<Item = &'a TreeFile>) -> Result<()> {
        let blobs = blobs_of(files)?;
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

    /// Local changes against the base, as daemon file changes.
    pub fn changes(&self) -> Result<Vec<FileChange>> {
        let mut out = Vec::new();
        self.each_change(&mut |c| {
            out.push(c);
            Ok(())
        })?;
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// Every local change against the base, one at a time: whoever takes
    /// them decides what of a file's content it keeps.
    fn each_change(&self, take: &mut dyn FnMut(FileChange) -> Result<()>) -> Result<()> {
        struct Out<'a>(&'a mut dyn FnMut(FileChange) -> Result<()>);
        impl Out<'_> {
            fn push(&mut self, c: FileChange) -> Result<()> {
                (self.0)(c)
            }
        }
        let mut out = Out(take);
        for (path, (mode, blob)) in &self.meta.manifest {
            match wsfs::read(&self.root, path)? {
                None => out.push(FileChange {
                    path: path.clone(),
                    content_b64: None,
                    mode: None,
                })?,
                Some(local) => {
                    let (bytes, exec) = (local.bytes, local.executable);
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
                        })?;
                    }
                }
            }
        }
        let mut found = Vec::new();
        let mut ignored = IgnoreFiles::new(&self.root);
        walk(&self.root, "", &mut ignored, &mut found)?;
        for rel in found {
            let known = [&self.meta.trunk_copies, &self.meta.generated];
            if self.meta.manifest.contains_key(&rel) || known.iter().any(|l| l.contains(&rel)) {
                continue;
            }
            let Some(local) = wsfs::read(&self.root, &rel)? else {
                continue;
            };
            let mode = if local.executable {
                FileMode::Executable
            } else {
                FileMode::Regular
            };
            out.push(FileChange {
                path: rel,
                content_b64: Some(b64().encode(&local.bytes)),
                mode: Some(mode),
            })?;
        }
        Ok(())
    }

    /// [`Workspace::changes`] as tree entries, with no content: what the
    /// daemon needs to tell a proposed file from one nobody proposed.
    ///
    /// One file's content is held at a time: a workspace may have many
    /// changed files, each as large as a request carries, and whoever asks
    /// this (the launcher at the end of a run) must get to its end.
    pub fn local_files(&self) -> Result<Vec<LocalFile>> {
        let local = |c: FileChange| -> Result<LocalFile> {
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
        let mut out = Vec::new();
        self.each_change(&mut |c| {
            out.push(local(c)?);
            Ok(())
        })?;
        out.sort_by(|a: &LocalFile, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// What differs from `tree`, the files of the commit the workspace was
    /// made from as the daemon has them: everything, ignored files too, and
    /// never by the manifest, a file that can be edited. So does anything in
    /// `.lonca` but its own files, and a `.git` where none belongs. What is
    /// in those files and in a `.git` is not looked at, and files listed as
    /// generated are allowed: [`Workspace::start_clean`] and the setup write
    /// them over.
    pub fn differs_from(&self, tree: &BTreeMap<String, GitId>) -> Result<Vec<String>> {
        let mut found = Vec::new();
        every_file(&self.root, "", &mut found)?;
        let mut out = Vec::new();
        if !self.meta.git && fs::symlink_metadata(self.root.join(".git")).is_ok() {
            out.push(".git".to_string());
        }
        let mut meta = Vec::new();
        every_file(&self.root, META_DIR, &mut meta)?;
        let own = |p: &String| META_FILES.iter().any(|f| *p == meta_file(f));
        out.extend(meta.into_iter().filter(|p| !own(p)));
        for rel in &found {
            if self.meta.generated.contains(rel) {
                continue;
            }
            let same = wsfs::read(&self.root, rel)
                .ok()
                .flatten()
                .map(|local| GitId::of_blob(&local.bytes));
            if same.is_none() || same.as_ref() != tree.get(rel) {
                out.push(rel.clone());
            }
        }
        let found: BTreeSet<&String> = found.iter().collect();
        out.extend(tree.keys().filter(|p| !found.contains(p)).cloned());
        Ok(out)
    }

    /// The changed files that hold markers of a sync.
    fn open_conflicts(&self) -> Result<Vec<String>> {
        let Some(tag) = &self.meta.conflict_tag else {
            return Ok(vec![]);
        };
        let mut open = Vec::new();
        for change in self.changes()? {
            let bytes = change.content_b64.as_ref().map(|c| b64().decode(c));
            let text = bytes.transpose()?.unwrap_or_default();
            if lines::has_markers(&String::from_utf8_lossy(&text), tag) {
                open.push(change.path);
            }
        }
        Ok(open)
    }

    /// Refuses a proposal while a conflict is open: what stands between the
    /// markers is not all the agent's to send.
    pub fn check_settled(&self) -> Result<()> {
        let open = self.open_conflicts()?;
        if open.is_empty() {
            return Ok(());
        }
        bail!(
            "conflict not settled in {}: edit what stands between `<<<<<<< local` \
             and `>>>>>>> trunk`, keeping what both sides need, and take out all three markers",
            open.join(", ")
        )
    }

    /// Brings trunk into the workspace, keeping local edits. Files edited
    /// locally and on trunk are merged with Lonca's structural merge; on a
    /// conflict everything else of trunk still comes in, both sides of what
    /// meets stand between conflict markers, and trunk's version is written
    /// next to the file as `<file>.trunk`. A symbol is written out whole; a
    /// file with no symbol merge goes by lines. Only a file that is no text
    /// stays local as a whole.
    pub fn sync(&mut self, client: &mut Client) -> Result<SyncReport> {
        let status = call(client, "status", json!({}))?;
        let trunk: GitId = serde_json::from_value(status["trunk"].clone())?;
        let new_tag = || self.meta.base.short().to_string();
        let tag = self.meta.conflict_tag.clone().unwrap_or_else(new_tag);
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
            wsfs::remove(&self.root, &copy)?;
        }
        let mut new_files: BTreeMap<String, TreeFile> = listed(client, &trunk, None)?
            .into_iter()
            .filter(|f| f.mode != FileMode::Submodule)
            .map(|f| (f.path.clone(), f))
            .collect();
        let mut local: BTreeMap<String, FileChange> = self
            .changes()?
            .into_iter()
            .map(|c| (c.path.clone(), c))
            .collect();
        // Of trunk's contents, only these are read below: a file trunk
        // changed (written, merged, or new to `.git`), and one edited here
        // (its trunk copy, while a conflict is open in it). The rest of the
        // repository is not downloaded.
        let held = &self.meta.manifest;
        let read = |f: &&mut TreeFile| {
            held.get(&f.path).map(|(_, b)| b) != Some(&f.blob) || local.contains_key(&f.path)
        };
        fill(client, &trunk, new_files.values_mut().filter(read))?;
        if let Some((change, commit)) = self.meta.submitted.clone() {
            let status = call(client, "change.get", json!({"change": change}))?;
            match status["status"]["status"].as_str().unwrap_or("") {
                "integrated" => {
                    // Edits that went in with the change are not local any more.
                    let proposed: BTreeMap<String, GitId> = listed(client, &commit, None)?
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
                    wsfs::remove(&self.root, &path)?;
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
                        wsfs::write(&self.root, &path, text.as_bytes(), unix_mode(m.mode))?;
                        report.merged.push(path.clone());
                        continue;
                    }
                    if let Some(Err(symbols)) = merged {
                        report.symbols.extend(symbols);
                    }
                    let kept = texts.map(|(b, o, t)| {
                        marked_around_conflicts(ENGINE_CURRENT, &path, [b, o, t], &tag)
                            .unwrap_or_else(|| lines::with_markers(b, o, t, &tag))
                    });
                    if let Some(text) = kept {
                        wsfs::write(&self.root, &path, text.as_bytes(), unix_mode(m.mode))?;
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
        self.meta.base = trunk;
        self.meta.manifest = manifest;
        self.meta.conflict_tag = Some(tag);
        let open = self.open_conflicts()?;
        if open.is_empty() {
            self.meta.conflict_tag = None;
        }
        for path in open {
            if report.conflicts.contains(&path) {
                continue;
            }
            if let Some(f) = new_files.get(&path) {
                let side = TreeFile {
                    path: format!("{path}.trunk"),
                    ..f.clone()
                };
                write_file(&self.root, &side)?;
                self.meta.trunk_copies.push(side.path);
            }
            report.conflicts.push(path);
        }
        // The sync is done once this is saved: a `.git` that has been
        // tampered with costs `git diff` its meaning, and nothing else.
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

fn manifest_of(files: &[TreeFile]) -> BTreeMap<String, (FileMode, GitId)> {
    let tracked = files.iter().filter(|f| f.mode != FileMode::Submodule);
    tracked
        .map(|f| (f.path.clone(), (f.mode, f.blob.clone())))
        .collect()
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
    let mut files = listed(client, commit, paths)?;
    fill(client, commit, &mut files)?;
    Ok(files)
}

/// The files of a commit as its tree names them, without their contents.
pub fn listed(
    client: &mut Client,
    commit: &GitId,
    paths: Option<Vec<String>>,
) -> Result<Vec<TreeFile>> {
    let v = call(
        client,
        "tree",
        json!({"commit": commit, "with_content": false, "paths": paths}),
    )?;
    Ok(serde_json::from_value(v)?)
}

/// Reads the contents of `files`, which [`listed`] gave of `commit`, in
/// their order: who needs a few files of a commit does not download it.
pub fn fill<'a>(
    client: &mut Client,
    commit: &GitId,
    files: impl IntoIterator<Item = &'a mut TreeFile>,
) -> Result<()> {
    let files: Vec<&mut TreeFile> = files.into_iter().collect();
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
    for f in files {
        if let Some(c) = contents.remove(&f.path) {
            f.content_b64 = c;
        }
    }
    Ok(())
}

/// The `.gitignore` and `.ignore` of each directory, read through `wsfs`: a
/// walker that opens them by path would follow a symlink, or hang on a FIFO.
/// One that can not be read counts for nothing.
struct IgnoreFiles<'a> {
    root: &'a Path,
    by_dir: BTreeMap<String, Gitignore>,
}

impl<'a> IgnoreFiles<'a> {
    fn new(root: &'a Path) -> Self {
        let by_dir = BTreeMap::new();
        Self { root, by_dir }
    }

    fn rules(&mut self, dir: &str) -> &Gitignore {
        let root = self.root;
        self.by_dir.entry(dir.to_string()).or_insert_with(|| {
            let mut rules = GitignoreBuilder::new(root.join(dir));
            for name in [".gitignore", ".ignore"] {
                let rel = in_dir(dir, name);
                if let Ok(Some(local)) = wsfs::read(root, &rel) {
                    for line in String::from_utf8_lossy(&local.bytes).lines() {
                        let _ = rules.add_line(None, line);
                    }
                }
            }
            rules.build().unwrap_or_else(|_| Gitignore::empty())
        })
    }

    /// Git's answer: the deepest file with a word about `rel` decides.
    fn hides(&mut self, rel: &str, is_dir: bool) -> bool {
        let path = self.root.join(rel);
        let mut dir = rel;
        loop {
            dir = dir.rsplit_once('/').map_or("", |(parent, _)| parent);
            match self.rules(dir).matched(&path, is_dir) {
                Match::Ignore(_) => return true,
                Match::Whitelist(_) => return false,
                Match::None if dir.is_empty() => return false,
                Match::None => {}
            }
        }
    }
}

fn in_dir(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{dir}/{name}")
    }
}

/// The files under `dir` that are not ignored. Symlinks are skipped, and
/// each path found is opened through `wsfs` after this: a directory swapped
/// for a symlink meanwhile gets no further than its names.
/// Every path under `dir` that is no directory, links included, and every
/// directory with nothing in it.
fn every_file(root: &Path, dir: &str, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(root.join(dir))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().map(str::to_string) else {
            bail!("{:?} in {dir:?}: Lonca paths are UTF-8", entry.file_name());
        };
        if dir.is_empty() && (name == META_DIR || name == ".git") {
            continue;
        }
        let rel = match dir {
            "" => name,
            _ => format!("{dir}/{name}"),
        };
        if entry.file_type()?.is_dir() {
            let before = out.len();
            every_file(root, &rel, out)?;
            // A commit has no empty directory, and a name can hold anything.
            if out.len() == before {
                out.push(rel);
            }
        } else {
            out.push(rel);
        }
    }
    Ok(())
}

fn walk(root: &Path, dir: &str, ignored: &mut IgnoreFiles, out: &mut Vec<String>) -> Result<()> {
    for entry in fs::read_dir(root.join(dir))? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("{:?} in {dir:?}: Lonca paths are UTF-8", entry.file_name());
        };
        if matches!(name, META_DIR | ".git") {
            continue;
        }
        let rel = in_dir(dir, name);
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if !ignored.hides(&rel, true) {
                walk(root, &rel, ignored, out)?;
            }
        } else if kind.is_file() && !ignored.hides(&rel, false) {
            out.push(rel);
        }
    }
    Ok(())
}

fn meta_file(name: &str) -> String {
    format!("{META_DIR}/{name}")
}

fn unix_mode(mode: Option<FileMode>) -> u32 {
    match mode {
        Some(FileMode::Executable) => wsfs::EXECUTABLE,
        _ => wsfs::REGULAR,
    }
}

fn blobs_of<'a>(files: impl IntoIterator<Item = &'a TreeFile>) -> Result<Vec<Vec<u8>>> {
    let real = files.into_iter().filter(|f| f.mode != FileMode::Submodule);
    real.map(content).collect()
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
    if lonca_core::paths::is_workspace_metadata(&f.path) {
        bail!("refusing to write {} into workspace metadata", f.path);
    }
    wsfs::write(root, &f.path, &content(f)?, unix_mode(Some(f.mode)))
}

#[cfg(test)]
mod tests {
    use super::{BTreeMap, GitId, Meta, Workspace, encoded_len, plan_pages};
    use std::fs;
    use std::path::Path;

    /// Two names that read the same once made text would hide one of them.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_that_is_no_text_is_not_read_as_one() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(OsStr::from_bytes(b"a\xff")), "x").unwrap();
        let e = super::every_file(dir.path(), "", &mut vec![]).unwrap_err();
        assert!(e.to_string().contains("UTF-8"), "{e}");
    }

    fn workspace(root: &Path) -> Workspace {
        let meta = Meta {
            repo: "demo".into(),
            base: GitId::of_blob(b"base"),
            session: None,
            human: None,
            manifest: BTreeMap::new(),
            submitted: None,
            scratch_roots: vec![],
            trunk_copies: vec![],
            conflict_tag: None,
            generated: vec![],
            git: false,
        };
        let root = root.to_path_buf();
        Workspace { root, meta }
    }

    fn local(root: &Path) -> Vec<String> {
        let changes = workspace(root).changes().unwrap();
        changes.into_iter().map(|c| c.path).collect()
    }

    fn put(root: &Path, files: &[(&str, &str)]) {
        for (path, text) in files {
            let at = root.join(path);
            fs::create_dir_all(at.parent().unwrap()).unwrap();
            fs::write(at, text).unwrap();
        }
    }

    #[test]
    fn ignore_files_mean_what_they_mean_to_git() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        put(
            r,
            &[
                (".gitignore", "*.log\n/build\n!keep.log\n"),
                ("keep.log", "kept"),
                ("drop.log", "gone"),
                ("build/out", "gone"),
                ("src/build/out", "only the root's build is ignored"),
                ("src/.gitignore", "!src-keep.log\nlocal.txt\n"),
                ("src/src-keep.log", "a deeper file wins"),
                ("src/drop.log", "gone"),
                ("src/local.txt", "gone"),
                ("local.txt", "that rule stays in src"),
                ("tools/.ignore", "scratch\n"),
                ("tools/scratch", "gone"),
                (".lonca/session", "never"),
                ("sub/.git/config", "never"),
                (".hidden", "dot files count"),
            ],
        );
        let want = [
            ".gitignore",
            ".hidden",
            "keep.log",
            "local.txt",
            "src/.gitignore",
            "src/build/out",
            "src/src-keep.log",
            "tools/.ignore",
        ];
        assert_eq!(local(r), want);
    }

    #[test]
    fn an_ignore_file_that_is_no_plain_file_counts_for_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let out = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::write(out.path().join("rules"), "visible\n").unwrap();
        std::os::unix::fs::symlink(out.path().join("rules"), r.join(".gitignore")).unwrap();
        put(r, &[("visible", "x")]);
        let fifo = r.join(".ignore");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(made.unwrap().success());
        let changes = workspace(r).changes();
        // The FIFO is not a file to propose, so it stays out; the read of it
        // as an ignore file must not hang either.
        assert_eq!(changes.unwrap().len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_name_that_is_not_utf8_is_refused_rather_than_renamed() {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let name = std::ffi::OsStr::from_bytes(b"bad\xff");
        fs::write(dir.path().join(name), "x").unwrap();
        let e = format!("{:#}", workspace(dir.path()).changes().unwrap_err());
        assert!(e.contains("Lonca paths are UTF-8"), "{e}");
    }

    #[test]
    fn a_backslash_is_part_of_a_name() {
        let dir = tempfile::tempdir().unwrap();
        put(dir.path(), &[("a\\b", "x"), ("..\\up", "x")]);
        assert_eq!(local(dir.path()), ["..\\up", "a\\b"]);
    }

    #[test]
    fn a_workspace_is_seen_even_when_its_metadata_does_not_read() {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        put(r, &[(".lonca/workspace.json", "not json"), ("a/b/c", "x")]);
        assert!(Workspace::find(&r.join("a/b")).is_none());
        assert!(Workspace::encloses(&r.join("a/b")));
        assert!(Workspace::encloses(r));
        let other = tempfile::tempdir().unwrap();
        assert!(!Workspace::encloses(other.path()));
    }

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
