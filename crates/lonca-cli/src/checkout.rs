//! A git checkout as the human's client: trunk comes in through the daemon
//! as `refs/lonca/trunk`, and a commit goes out as a human change. The
//! store is never opened; `git` runs only in the checkout.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use base64::Engine;
use lonca_core::GitId;
use lonca_core::ops::Op;
use lonca_daemon::Client;
use lonca_daemon::protocol::FileChange;
use serde_json::{Value, json};

use crate::ctx::{self, call};
use crate::workspace::Workspace;

pub const TRUNK_REF: &str = "refs/lonca/trunk";

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .with_context(|| format!("git {}", args.join(" ")))?;
    if !out.status.success() {
        bail!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// One `git cat-file --batch` for the blobs of a commit: asked one at a
/// time, so neither pipe fills while the other is not read.
struct Blobs {
    child: std::process::Child,
    ask: std::process::ChildStdin,
    answer: std::io::BufReader<std::process::ChildStdout>,
}

impl Blobs {
    fn of(dir: &Path) -> Result<Self> {
        use std::process::Stdio;
        let mut child = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["cat-file", "--batch"])
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("git cat-file --batch")?;
        let ask = child.stdin.take().context("git cat-file: no stdin")?;
        let answer = child.stdout.take().context("git cat-file: no stdout")?;
        Ok(Self {
            child,
            ask,
            answer: std::io::BufReader::new(answer),
        })
    }

    /// The bytes of the blob `id`.
    fn read(&mut self, id: &str) -> Result<Vec<u8>> {
        use std::io::{BufRead, Read, Write};
        writeln!(self.ask, "{id}")?;
        self.ask.flush()?;
        let mut head = String::new();
        self.answer.read_line(&mut head)?;
        // `<id> blob <size>`, or `<id> missing`.
        let mut fields = head.trim_end().split(' ');
        let (_, kind, size) = (fields.next(), fields.next(), fields.next());
        let size: usize = match (kind, size.and_then(|s| s.parse().ok())) {
            (Some("blob"), Some(size)) => size,
            _ => bail!("{} is not a blob here: {}", id, head.trim_end()),
        };
        let mut bytes = vec![0; size];
        self.answer.read_exact(&mut bytes)?;
        let mut end = [0; 1];
        self.answer.read_exact(&mut end)?;
        Ok(bytes)
    }
}

impl Drop for Blobs {
    fn drop(&mut self) {
        // Its stdin closes with `ask`, which ends it; a wait leaves no
        // process behind when it did not get that far.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn rev(dir: &Path, r: &str) -> Option<GitId> {
    git(
        dir,
        &["rev-parse", "--verify", "-q", &format!("{r}^{{commit}}")],
    )
    .ok()
    .and_then(|s| GitId::parse(&s).ok())
}

/// The repository a checkout belongs to: `--repo`, else the checkout's
/// `lonca.repo` git config (set by the first `lonca fetch --repo`).
pub fn repo_name(dir: &Path, flag: Option<String>) -> Result<String> {
    // An agent's workspace is a repository too, and an agent writes its
    // config: `git` must not run there.
    if Workspace::encloses(dir) {
        bail!("this is a Lonca workspace: use `lonca sync` and `lonca propose`");
    }
    git(dir, &["rev-parse", "--git-dir"])
        .context("not a git checkout; pass --into or cd into one")?;
    if let Some(r) = flag {
        git(dir, &["config", "lonca.repo", &r])?;
        return Ok(r);
    }
    git(dir, &["config", "--get", "lonca.repo"])
        .ok()
        .filter(|s| !s.is_empty())
        .context("pass --repo once; it is remembered in the checkout's git config (lonca.repo)")
}

/// Fetches trunk through the daemon into `refs/lonca/trunk`.
pub fn fetch(c: &mut Client, dir: &Path, repo: &str) -> Result<Value> {
    let previous = rev(dir, TRUNK_REF);
    let have: Vec<GitId> = [previous.clone(), rev(dir, "HEAD")]
        .into_iter()
        .flatten()
        .collect();
    let r = call(c, "trunk.bundle", json!({"have": have}))?;
    let trunk: GitId = serde_json::from_value(r["trunk"].clone())?;
    if r["up_to_date"] == true {
        // The checkout has the commit already: only the ref moves.
        rev(dir, &trunk.to_string()).context("the checkout lacks the trunk commit it claimed")?;
        git(dir, &["update-ref", TRUNK_REF, &trunk.to_string()])?;
    } else {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(r["bundle_b64"].as_str().unwrap_or_default())
            .context("trunk.bundle: bad bundle_b64")?;
        // The whole of trunk, in the temporary directory every user of the
        // machine shares: a file only this user reads (0600), gone when it
        // is dropped.
        use std::io::Write;
        let mut tmp = tempfile::Builder::new()
            .prefix("lonca-trunk-")
            .suffix(".bundle")
            .tempfile()?;
        tmp.write_all(&bytes)?;
        tmp.flush()?;
        git(
            dir,
            &[
                "fetch",
                "-q",
                &tmp.path().to_string_lossy(),
                &format!("+refs/heads/main:{TRUNK_REF}"),
            ],
        )?;
    }
    let got = rev(dir, TRUNK_REF).context("refs/lonca/trunk missing after the fetch")?;
    if got != trunk {
        bail!("fetched {got} but the daemon's trunk is {trunk}");
    }
    // How far the previous trunk ref was behind (0 when it was trunk).
    let behind = match &previous {
        Some(p) => call(c, "trunk.distance", json!({"base": p}))?["behind"].clone(),
        None => Value::Null,
    };
    Ok(json!({
        "repo": repo, "trunk": trunk, "previous": previous, "behind": behind,
        "bytes": r["bytes"], "thin": r["thin"],
    }))
}

/// Proposes a commit of the checkout as a human change: everything it
/// changes against its merge base with the last fetched trunk.
pub fn propose(
    c: &mut Client,
    dir: &Path,
    repo: &str,
    human: &str,
    rev_spec: &str,
    intent: &str,
) -> Result<Value> {
    let commit = rev(dir, rev_spec).with_context(|| format!("{rev_spec} is not a commit here"))?;
    let trunk = rev(dir, TRUNK_REF).context("no refs/lonca/trunk: run `lonca fetch` first")?;
    let base = git(
        dir,
        &["merge-base", &trunk.to_string(), &commit.to_string()],
    )
    .and_then(|s| GitId::parse(&s).map_err(Into::into))
    .with_context(|| format!("{rev_spec} shares no history with trunk"))?;
    if base == commit {
        bail!("{rev_spec} is already in trunk");
    }
    // One `git diff` says what each file is in the commit (its mode and its
    // blob), one `git cat-file --batch` gives the contents: two processes
    // for a commit, not two for each of its files.
    let diff = git(
        dir,
        &[
            "diff",
            "--raw",
            "--no-abbrev",
            "--no-renames",
            "-z",
            &base.to_string(),
            &commit.to_string(),
        ],
    )?;
    // (path, the blob and mode it has in the commit; `None`: deleted)
    let mut changed: Vec<(&str, Option<(&str, lonca_core::FileMode)>)> = Vec::new();
    let mut it = diff.split('\0').filter(|s| !s.is_empty());
    while let (Some(meta), Some(path)) = (it.next(), it.next()) {
        lonca_core::paths::validate_repo_path(path)
            .with_context(|| format!("{path}: not a path Lonca accepts"))?;
        // `:<old mode> <new mode> <old blob> <new blob> <status>`
        let mut fields = meta.trim_start_matches(':').split(' ');
        let (_, mode, _, blob, status) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        );
        let (Some(mode), Some(blob), Some(status)) = (mode, blob, status) else {
            bail!("git diff --raw: {meta:?} is not a line of it");
        };
        if status.starts_with('D') {
            changed.push((path, None));
            continue;
        }
        // The mode first: a symlink or a submodule is refused before any
        // content is read.
        let mode = match mode {
            "100755" => lonca_core::FileMode::Executable,
            "120000" => bail!("{path}: symlinks are not proposed from a checkout"),
            "160000" => bail!("{path}: submodules are not proposed from a checkout"),
            _ => lonca_core::FileMode::Regular,
        };
        changed.push((path, Some((blob, mode))));
    }
    let mut blobs = Blobs::of(dir)?;
    let mut files = Vec::new();
    for (path, now) in changed {
        let Some((blob, mode)) = now else {
            files.push(FileChange {
                path: path.to_string(),
                content_b64: None,
                mode: None,
            });
            continue;
        };
        let bytes = blobs
            .read(blob)
            .with_context(|| format!("git cat-file {commit}:{path}"))?;
        files.push(FileChange {
            path: path.to_string(),
            content_b64: Some(base64::engine::general_purpose::STANDARD.encode(&bytes)),
            mode: Some(mode),
        });
    }
    drop(blobs);
    if files.is_empty() {
        bail!("{rev_spec} changes nothing against trunk");
    }
    let intent = if intent.is_empty() {
        git(dir, &["log", "-1", "--format=%s", &commit.to_string()])?
    } else {
        intent.to_string()
    };
    let params = crate::ctx::WithFiles {
        author: Some(human),
        intent: Some(&intent),
        ..crate::ctx::WithFiles::new(&base, &files)
    };
    let prep = crate::ctx::call_with(c, "human.prepare_change", &params)?;
    let op: Op = serde_json::from_value(prep["op"].clone())?;
    let Op::ChangePropose {
        change,
        commit: built,
        ..
    } = &op
    else {
        bail!("human.prepare_change did not return a change")
    };
    let (change, built) = (*change, built.clone());
    let sig = ctx::sign(c, human, repo, &op)?;
    let mut r = call(c, "human.submit", json!({"op": op, "sig": sig}))?;
    r["change"] = json!(change);
    r["commit"] = json!(built);
    r["base"] = json!(base);
    r["from"] = json!(commit);
    Ok(r)
}
