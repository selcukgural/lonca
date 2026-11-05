//! The `.git` of an agent's workspace: one commit of its base, so `git
//! status` and `git diff` mean "my local edits", and tools that expect a
//! repository find one.
//!
//! The agent can write here, and `lonca sync` may run outside its sandbox
//! (an MCP server does). So Lonca never runs `git` on this directory and
//! never reads a file in it: `core.fsmonitor`, a hook or a filter would run
//! with Lonca's rights. It only replaces the files it owns, which replaces
//! a symlink instead of following it, and writes nothing if a directory it
//! needs is not the real directory it made.
//!
//! No proposal comes from here: `changes()` compares files with the
//! manifest, and a commit or a staged file changes neither.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use lonca_core::store::{CommitSpec, FileEntry, FileMap, LooseObjects, index_of};
use lonca_core::{FileMode, GitId};

const BRANCH: &str = "refs/heads/main";

/// `core.hooksPath` and `commit.gpgsign` keep a person's global config out:
/// "no hooks" holds for the ones they have, and a commit needs no key.
const CONFIG: &str = "\
[core]
\trepositoryformatversion = 0
\tbare = false
\tfilemode = true
\thooksPath = /dev/null
\tfsmonitor = false
\tautocrlf = false
[user]
\tname = lonca
\temail = lonca@localhost
[commit]
\tgpgsign = false
[gc]
\tauto = 0
";

/// Above any `.gitattributes`: Git takes the bytes as they are, the same as
/// `lonca diff`, whatever the repository says about line ends or filters.
const ATTRIBUTES: &str = "* -text -ident -filter -working-tree-encoding\n";

fn git_dir(root: &Path) -> PathBuf {
    root.join(".git")
}

/// Writes `bytes` to `path` by replacing it. `create_new` refuses a symlink
/// left at the temporary name, and the rename takes the place of whatever
/// `path` was without following it.
fn replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let name = path.file_name().context("no file name")?;
    let tmp = path.with_file_name(format!("{}.lonca-tmp", name.to_string_lossy()));
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(bytes)?;
    fs::rename(&tmp, path).with_context(|| format!("replacing {}", path.display()))
}

/// The directories Lonca writes in, or an error if any is not the real
/// directory it made. Object writes land in `objects/<xx>/`, so those count.
fn own_dirs(root: &Path) -> Result<PathBuf> {
    let git = git_dir(root);
    let real = |dir: &Path| -> Result<()> {
        let meta =
            fs::symlink_metadata(dir).with_context(|| format!("looking at {}", dir.display()))?;
        if !meta.is_dir() {
            bail!("{} is not a directory", dir.display());
        }
        Ok(())
    };
    real(&git)?;
    for dir in ["objects", "refs", "refs/heads", "info"] {
        real(&git.join(dir))?;
    }
    for entry in fs::read_dir(git.join("objects"))? {
        real(&entry?.path())?;
    }
    Ok(git)
}

/// Makes `root` a repository with nothing in it yet.
pub fn init(root: &Path) -> Result<()> {
    let git = git_dir(root);
    for dir in ["objects", "refs/heads", "info"] {
        fs::create_dir_all(git.join(dir))?;
    }
    replace(&git.join("config"), CONFIG.as_bytes())?;
    replace(&git.join("info/attributes"), ATTRIBUTES.as_bytes())
}

/// What the base looks like on disk: a symlink is a regular file there, and
/// `git status` has to agree.
fn checked_out(manifest: &BTreeMap<String, (FileMode, GitId)>) -> FileMap {
    let entry = |(path, (mode, blob)): (&String, &(FileMode, GitId))| {
        let mode = match mode {
            FileMode::Symlink => FileMode::Regular,
            other => *other,
        };
        let blob = blob.clone();
        (path.clone(), FileEntry { mode, blob })
    };
    manifest.iter().map(entry).collect()
}

/// Points the repository at `base`: `main`, `HEAD` and the index all move,
/// so anything staged or committed locally is a local edit again. `blobs`
/// are the contents the repository may not have yet.
pub fn set_base<'a>(
    root: &Path,
    base: &GitId,
    manifest: &BTreeMap<String, (FileMode, GitId)>,
    blobs: impl Iterator<Item = &'a [u8]>,
    time_ms: i64,
) -> Result<()> {
    let git = own_dirs(root)?;
    let objects = LooseObjects::at(&git.join("objects"));
    for bytes in blobs {
        objects.write_blob(bytes)?;
    }
    let files = checked_out(manifest);
    let commit = objects.write_commit(&CommitSpec {
        tree: objects.write_tree(&files)?,
        parents: vec![],
        author_name: "lonca".into(),
        author_email: "lonca@localhost".into(),
        time_ms,
        message: format!("lonca base {base}\n"),
        headers: vec![],
    })?;
    replace(&git.join("index"), &index_of(&files)?)?;
    replace(&git.join(BRANCH), format!("{commit}\n").as_bytes())?;
    replace(&git.join("HEAD"), format!("ref: {BRANCH}\n").as_bytes())
}

/// One `.git/info/exclude` line for exactly `path`, or none for a path a
/// line can not hold: that file then shows as untracked, nothing worse.
fn exclude_line(path: &str) -> Option<String> {
    if path.contains('\n') {
        return None;
    }
    let mut line = String::from("/");
    for c in path.chars() {
        if matches!(c, '\\' | '*' | '?' | '[' | ' ') {
            line.push('\\');
        }
        line.push(c);
    }
    Some(line)
}

/// Keeps `.lonca/` and `paths` out of `git status`. They are what
/// `changes()` skips: a local change for neither tool.
pub fn set_excluded<'a>(root: &Path, paths: impl Iterator<Item = &'a String>) -> Result<()> {
    let git = own_dirs(root)?;
    let mut text = String::from("/.lonca/\n");
    for line in paths.filter_map(|p| exclude_line(p)) {
        text.push_str(&line);
        text.push('\n');
    }
    replace(&git.join("info/exclude"), text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// `git` as a tool in the workspace would run it, with no help from a
    /// developer's config.
    fn git(root: &Path, args: &[&str]) -> String {
        let out = Command::new("git")
            .current_dir(root)
            .args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "git {args:?}: {err}");
        String::from_utf8_lossy(&out.stdout).trim_end().to_string()
    }

    fn entry(path: &str, mode: FileMode, text: &str) -> (String, (FileMode, GitId)) {
        (path.to_string(), (mode, GitId::of_blob(text.as_bytes())))
    }

    fn base_id() -> GitId {
        GitId::of_blob(b"trunk")
    }

    /// A repository of `files`, written in the work tree as well.
    fn repo(
        files: &[(&str, FileMode, &str)],
    ) -> (tempfile::TempDir, BTreeMap<String, (FileMode, GitId)>) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut manifest = BTreeMap::new();
        for (path, mode, text) in files {
            let target = root.join(path);
            fs::create_dir_all(target.parent().unwrap()).unwrap();
            fs::write(&target, text).unwrap();
            #[cfg(unix)]
            if *mode == FileMode::Executable {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
            }
            manifest.extend([entry(path, *mode, text)]);
        }
        init(root).unwrap();
        let blobs = files.iter().map(|(_, _, t)| t.as_bytes());
        set_base(root, &base_id(), &manifest, blobs, 1_000_000).unwrap();
        set_excluded(root, [].iter()).unwrap();
        (dir, manifest)
    }

    #[test]
    fn git_reads_what_lonca_wrote_as_a_clean_repository() {
        let (dir, _) = repo(&[
            ("README.md", FileMode::Regular, "hello\n"),
            ("src/lib.rs", FileMode::Regular, "fn a() {}\n"),
            ("src/deep/er.rs", FileMode::Regular, "fn b() {}\n"),
            ("run.sh", FileMode::Executable, "#!/bin/sh\n"),
            // A symlink comes out as a regular file holding its target.
            ("link", FileMode::Symlink, "README.md"),
        ]);
        let root = dir.path();
        assert_eq!(git(root, &["status", "--porcelain"]), "");
        assert_eq!(git(root, &["diff"]), "");
        assert_eq!(git(root, &["rev-parse", "--abbrev-ref", "HEAD"]), "main");
        git(root, &["fsck", "--strict"]);
        let tracked = git(root, &["ls-files", "-s"]);
        assert!(tracked.contains("100755"), "{tracked}");
        assert!(!tracked.contains("120000"), "{tracked}");
        assert_eq!(tracked.lines().count(), 5, "{tracked}");
        let log = git(root, &["log", "--format=%an <%ae> %at %s"]);
        assert_eq!(
            log,
            format!("lonca <lonca@localhost> 1000 lonca base {}", base_id())
        );
        assert_eq!(git(root, &["config", "core.hooksPath"]), "/dev/null");
        assert_eq!(git(root, &["config", "commit.gpgsign"]), "false");
        assert_eq!(git(root, &["config", "user.name"]), "lonca");
    }

    #[test]
    fn git_sees_each_kind_of_local_edit() {
        let (dir, _) = repo(&[
            ("a.txt", FileMode::Regular, "one\n"),
            ("b.txt", FileMode::Regular, "two\n"),
            ("c.txt", FileMode::Regular, "three\n"),
        ]);
        let root = dir.path();
        fs::write(root.join("a.txt"), "changed\n").unwrap();
        fs::remove_file(root.join("b.txt")).unwrap();
        fs::write(root.join("d.txt"), "new\n").unwrap();
        fs::create_dir(root.join(".lonca")).unwrap();
        fs::write(root.join(".lonca/session"), "secret").unwrap();
        let status = git(root, &["status", "--porcelain"]);
        assert_eq!(status, " M a.txt\n D b.txt\n?? d.txt");
        assert!(git(root, &["diff"]).contains("+changed"));
    }

    /// `.gitattributes` could make a checked-out file differ from the blob
    /// with no edit, which `lonca diff` would not call a change.
    #[test]
    fn line_end_and_filter_attributes_do_not_make_a_clean_file_dirty() {
        let (dir, _) = repo(&[
            (
                ".gitattributes",
                FileMode::Regular,
                "* text eol=crlf\n*.bin filter=lfs ident\n",
            ),
            ("lf.txt", FileMode::Regular, "lf only\n"),
            ("crlf.txt", FileMode::Regular, "crlf\r\n"),
            ("x.bin", FileMode::Regular, "$Id$\n"),
        ]);
        assert_eq!(git(dir.path(), &["status", "--porcelain"]), "");
    }

    #[test]
    fn a_new_base_moves_everything_back_to_it_and_keeps_edits_local() {
        let (dir, mut manifest) = repo(&[
            ("mine.txt", FileMode::Regular, "base\n"),
            ("theirs.txt", FileMode::Regular, "base\n"),
            ("staged.txt", FileMode::Regular, "base\n"),
        ]);
        let root = dir.path();
        fs::write(root.join("mine.txt"), "local\n").unwrap();
        git(root, &["commit", "-qam", "my checkpoint"]);
        git(root, &["checkout", "-qb", "elsewhere"]);
        fs::write(root.join("staged.txt"), "staged\n").unwrap();
        git(root, &["add", "staged.txt"]);

        // Trunk changed theirs.txt.
        fs::write(root.join("theirs.txt"), "trunk\n").unwrap();
        manifest.extend([entry("theirs.txt", FileMode::Regular, "trunk\n")]);
        let next = GitId::of_blob(b"next");
        let blobs = [b"trunk\n".as_slice()];
        set_base(root, &next, &manifest, blobs.into_iter(), 2_000_000).unwrap();

        assert_eq!(git(root, &["rev-parse", "--abbrev-ref", "HEAD"]), "main");
        assert_eq!(
            git(root, &["log", "--format=%s"]),
            format!("lonca base {next}")
        );
        assert_eq!(git(root, &["diff", "--name-only"]), "mine.txt\nstaged.txt");
        assert_eq!(git(root, &["diff", "--cached", "--name-only"]), "");
        assert!(git(root, &["show", "HEAD:theirs.txt"]).contains("trunk"));
        git(root, &["fsck", "--strict"]);
    }

    #[test]
    fn nothing_lands_through_a_symlink_or_on_a_directory_that_is_not_ours() {
        let out = tempfile::tempdir().unwrap();
        let victim = out.path().join("victim");
        fs::write(&victim, "mine").unwrap();
        let (dir, manifest) = repo(&[("a.txt", FileMode::Regular, "a\n")]);
        let root = dir.path();
        let git_path = root.join(".git");

        // A file swapped for a symlink is replaced, not written through.
        for name in ["index", "HEAD", "refs/heads/main", "info/exclude"] {
            fs::remove_file(git_path.join(name)).unwrap();
            std::os::unix::fs::symlink(&victim, git_path.join(name)).unwrap();
        }
        set_base(root, &base_id(), &manifest, [].into_iter(), 3_000_000).unwrap();
        set_excluded(root, [].iter()).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "mine");
        assert_eq!(git(root, &["status", "--porcelain"]), "");
        // So is a symlink waiting at the temporary name.
        std::os::unix::fs::symlink(&victim, git_path.join("index.lonca-tmp")).unwrap();
        set_base(root, &base_id(), &manifest, [].into_iter(), 3_000_000).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "mine");

        // A directory swapped for a symlink stops the write.
        for name in ["objects/ab", "objects", "refs/heads", "refs", "info"] {
            let at = git_path.join(name);
            let aside = out.path().join(name.replace('/', "-"));
            if at.exists() {
                fs::rename(&at, &aside).unwrap();
            } else {
                fs::create_dir(&aside).unwrap();
            }
            std::os::unix::fs::symlink(&aside, &at).unwrap();
            let e = set_base(root, &base_id(), &manifest, [].into_iter(), 3_000_000);
            let e = format!("{:#}", e.unwrap_err());
            assert!(e.contains("is not a directory"), "{name}: {e}");
            assert!(set_excluded(root, [].iter()).is_err(), "{name}");
            fs::remove_file(&at).unwrap();
            if !name.starts_with("objects/") {
                fs::rename(&aside, &at).unwrap();
            }
        }

        // `.git` itself, as a symlink, a file or nothing.
        let aside = out.path().join("git");
        fs::rename(&git_path, &aside).unwrap();
        assert!(set_excluded(root, [].iter()).is_err());
        std::os::unix::fs::symlink(&aside, &git_path).unwrap();
        assert!(set_excluded(root, [].iter()).is_err());
        fs::remove_file(&git_path).unwrap();
        fs::write(&git_path, "gitdir: /elsewhere\n").unwrap();
        assert!(set_excluded(root, [].iter()).is_err());
    }

    #[test]
    fn a_config_nobody_should_trust_is_never_read() {
        let (dir, manifest) = repo(&[("a.txt", FileMode::Regular, "a\n")]);
        let root = dir.path();
        let flag = root.join("ran");
        let evil = format!(
            "[core]\n\tfsmonitor = touch {f}\n\thooksPath = {h}\n\trepositoryformatversion = 99\n",
            f = flag.display(),
            h = root.join("hooks").display(),
        );
        fs::write(root.join(".git/config"), evil).unwrap();
        fs::create_dir(root.join("hooks")).unwrap();
        let hook = root.join("hooks/reference-transaction");
        fs::write(&hook, format!("#!/bin/sh\ntouch {}\n", flag.display())).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
        set_base(root, &base_id(), &manifest, [].into_iter(), 4_000_000).unwrap();
        assert!(!flag.exists());
    }

    #[test]
    fn an_exclude_line_means_exactly_one_path() {
        for (path, line) in [
            ("plain.txt", Some("/plain.txt")),
            ("a/b.trunk", Some("/a/b.trunk")),
            ("sp ace ", Some("/sp\\ ace\\ ")),
            ("st*r?[x]", Some("/st\\*r\\?\\[x]")),
            ("back\\slash", Some("/back\\\\slash")),
            ("!bang", Some("/!bang")),
            ("#hash", Some("/#hash")),
            ("two\nlines", None),
        ] {
            assert_eq!(exclude_line(path).as_deref(), line, "{path:?}");
        }
    }

    #[test]
    fn git_honours_the_excluded_paths_and_only_them() {
        let (dir, _) = repo(&[("a.txt", FileMode::Regular, "a\n")]);
        let root = dir.path();
        for name in ["gen.json", "st*r", "sta", "sp ace", "two\nlines"] {
            fs::write(root.join(name), "x").unwrap();
        }
        let paths = ["gen.json", "st*r", "sp ace", "two\nlines"].map(String::from);
        set_excluded(root, paths.iter()).unwrap();
        let status = git(
            root,
            &["-c", "core.quotePath=false", "status", "--porcelain"],
        );
        // `sta` is not hidden by `st*r`, and the name with a newline stays
        // untracked rather than ending up as two patterns.
        assert_eq!(status, "?? sta\n?? \"two\\nlines\"");
        // A second call replaces the list.
        set_excluded(root, [].iter()).unwrap();
        let status = git(root, &["status", "--porcelain"]);
        assert_eq!(status.lines().count(), 5, "{status}");
    }
}
