//! Git-compatible object store (gitoxide).
//!
//! Content is plain Git: blobs, trees and commits that `git` and GitHub
//! understand. Lonca metadata lives in Git objects too, under `refs/lonca/*`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use gix::ObjectId;
use gix::bstr::ByteSlice;
use gix::objs::Write as _;
use gix::objs::tree::{self, EntryKind};
use gix::refs::transaction::PreviousValue;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result, git};
use crate::paths::validate_repo_path;

/// A Git object id in lowercase hex.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct GitId(pub String);

impl GitId {
    pub fn parse(s: &str) -> Result<Self> {
        let oid = ObjectId::from_hex(s.as_bytes())
            .map_err(|e| Error::Invalid(format!("git id {s:?}: {e}")))?;
        Ok(Self(oid.to_string()))
    }

    pub fn oid(&self) -> Result<ObjectId> {
        ObjectId::from_hex(self.0.as_bytes())
            .map_err(|e| Error::Invalid(format!("git id {:?}: {e}", self.0)))
    }

    pub fn short(&self) -> &str {
        &self.0[..self.0.len().min(10)]
    }

    /// The id Git gives `bytes` as a blob (SHA-1 repositories), without
    /// writing anything.
    #[allow(
        clippy::expect_used,
        reason = "compute_hash fails only for a hash kind gix was built without; SHA-1 is always there"
    )]
    pub fn of_blob(bytes: &[u8]) -> Self {
        let oid = gix::objs::compute_hash(gix::hash::Kind::Sha1, gix::objs::Kind::Blob, bytes)
            .expect("hashing a buffer can not fail");
        Self(oid.to_string())
    }
}

impl From<ObjectId> for GitId {
    fn from(id: ObjectId) -> Self {
        Self(id.to_string())
    }
}

impl fmt::Display for GitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for GitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitId({})", self.short())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileMode {
    Regular,
    Executable,
    Symlink,
    /// A submodule commit; carried through unchanged, never materialized.
    Submodule,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub mode: FileMode,
    pub blob: GitId,
}

/// A flattened tree: repository path -> entry.
pub type FileMap = BTreeMap<String, FileEntry>;

#[derive(Clone, Debug)]
pub struct CommitSpec {
    pub tree: GitId,
    pub parents: Vec<GitId>,
    pub author_name: String,
    pub author_email: String,
    pub time_ms: i64,
    pub message: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitInfo {
    pub tree: GitId,
    pub parents: Vec<GitId>,
    pub headers: Vec<(String, String)>,
    pub message: String,
    pub author_name: String,
    pub author_email: String,
    /// Author time in milliseconds (Git stores seconds).
    pub time_ms: i64,
}

impl CommitInfo {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

pub struct Store {
    path: PathBuf,
    repo: gix::ThreadSafeRepository,
}

enum Node {
    File(FileEntry),
    Dir(BTreeMap<String, Node>),
}

impl Store {
    pub fn init_bare(path: &Path) -> Result<Self> {
        gix::init_bare(path).map_err(git)?;
        Self::open(path)
    }

    /// Opens the store without reading global or system Git configuration, so
    /// behaviour does not depend on who runs the daemon.
    pub fn open(path: &Path) -> Result<Self> {
        let repo = gix::open_opts(path, gix::open::Options::isolated()).map_err(git)?;
        Ok(Self {
            path: path.to_path_buf(),
            repo: repo.into_sync(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn local(&self) -> gix::Repository {
        self.repo.to_thread_local()
    }

    pub fn write_blob(&self, bytes: &[u8]) -> Result<GitId> {
        let repo = self.local();
        let id = repo.write_blob(bytes).map_err(git)?;
        Ok(id.detach().into())
    }

    /// The size of a blob without reading it (the object header).
    pub fn blob_size(&self, id: &GitId) -> Result<u64> {
        let repo = self.local();
        let header = repo.find_header(id.oid()?).map_err(git)?;
        Ok(header.size())
    }

    pub fn read_blob(&self, id: &GitId) -> Result<Vec<u8>> {
        let repo = self.local();
        let obj = repo.find_object(id.oid()?).map_err(git)?;
        if obj.kind != gix::object::Kind::Blob {
            return Err(Error::Invalid(format!("{} is not a blob", id.short())));
        }
        Ok(obj.data.clone())
    }

    pub fn has_object(&self, id: &GitId) -> bool {
        let repo = self.local();
        match id.oid() {
            Ok(oid) => repo.has_object(oid),
            Err(_) => false,
        }
    }

    pub fn empty_tree(&self) -> Result<GitId> {
        self.write_tree(&FileMap::new())
    }

    pub fn write_tree(&self, files: &FileMap) -> Result<GitId> {
        let root = nodes(files)?;
        let repo = self.local();
        let write = |tree: gix::objs::Tree| Ok(repo.write_object(tree).map_err(git)?.detach());
        Ok(write_dir(&write, &root)?.into())
    }

    pub fn read_tree(&self, tree: &GitId) -> Result<FileMap> {
        let repo = self.local();
        let mut out = FileMap::new();
        walk(&repo, tree.oid()?, "", &mut out)?;
        Ok(out)
    }

    pub fn commit_files(&self, commit: &GitId) -> Result<FileMap> {
        let info = self.read_commit(commit)?;
        self.read_tree(&info.tree)
    }

    pub fn read_file(&self, commit: &GitId, path: &str) -> Result<Option<Vec<u8>>> {
        let files = self.commit_files(commit)?;
        match files.get(path) {
            Some(e) => Ok(Some(self.read_blob(&e.blob)?)),
            None => Ok(None),
        }
    }

    pub fn write_commit(&self, spec: &CommitSpec) -> Result<GitId> {
        let repo = self.local();
        let id = repo.write_object(commit_of(spec)?).map_err(git)?;
        Ok(id.detach().into())
    }

    pub fn read_commit(&self, id: &GitId) -> Result<CommitInfo> {
        let repo = self.local();
        let obj = repo.find_object(id.oid()?).map_err(git)?;
        if obj.kind != gix::object::Kind::Commit {
            return Err(Error::Invalid(format!("{} is not a commit", id.short())));
        }
        let c = gix::objs::CommitRef::from_bytes(&obj.data, repo.object_hash()).map_err(git)?;
        let author = c.author().map_err(git)?;
        Ok(CommitInfo {
            tree: c.tree().into(),
            parents: c.parents().map(GitId::from).collect(),
            headers: c
                .extra_headers
                .iter()
                .map(|(k, v)| (k.to_str_lossy().into_owned(), v.to_str_lossy().into_owned()))
                .collect(),
            message: c.message.to_str_lossy().into_owned(),
            author_name: author.name.to_str_lossy().into_owned(),
            author_email: author.email.to_str_lossy().into_owned(),
            time_ms: author.time().map_err(git)?.seconds * 1000,
        })
    }

    pub fn ref_get(&self, name: &str) -> Result<Option<GitId>> {
        let repo = self.local();
        match repo.try_find_reference(name).map_err(git)? {
            Some(mut r) => Ok(Some(r.peel_to_id().map_err(git)?.detach().into())),
            None => Ok(None),
        }
    }

    /// Compare-and-swap: `expected == None` means the ref must not exist yet.
    pub fn ref_cas(&self, name: &str, new: &GitId, expected: Option<&GitId>) -> Result<()> {
        let repo = self.local();
        let prev = match expected {
            Some(e) => PreviousValue::MustExistAndMatch(gix::refs::Target::Object(e.oid()?)),
            None => {
                // gix accepts "must not exist" when the ref already holds the
                // new value; Lonca wants a strict create.
                if repo.try_find_reference(name).map_err(git)?.is_some() {
                    return Err(Error::Conflict(format!("ref {name} already exists")));
                }
                PreviousValue::MustNotExist
            }
        };
        repo.reference(name, new.oid()?, prev, "lonca")
            .map_err(|e| Error::Conflict(format!("ref {name}: {e}")))?;
        Ok(())
    }

    /// Unconditional ref update. Only used to restore refs that someone
    /// changed behind the daemon's back.
    pub fn ref_force(&self, name: &str, new: &GitId) -> Result<()> {
        let repo = self.local();
        repo.reference(name, new.oid()?, PreviousValue::Any, "lonca: restore")
            .map_err(git)?;
        Ok(())
    }

    /// Deletes `name` if it still names `expected`. Only used to remove
    /// refs someone wrote behind the daemon's back.
    pub fn ref_delete(&self, name: &str, expected: &GitId) -> Result<()> {
        use gix::refs::transaction::{Change, RefEdit, RefLog};
        let repo = self.local();
        let full: gix::refs::FullName = name
            .try_into()
            .map_err(|e| Error::Invalid(format!("ref {name}: {e}")))?;
        repo.edit_reference(RefEdit {
            change: Change::Delete {
                expected: PreviousValue::MustExistAndMatch(gix::refs::Target::Object(
                    expected.oid()?,
                )),
                log: RefLog::AndReference,
            },
            name: full,
            deref: false,
        })
        .map_err(|e| Error::Conflict(format!("ref {name}: {e}")))?;
        Ok(())
    }

    pub fn refs_with_prefix(&self, prefix: &str) -> Result<Vec<(String, GitId)>> {
        let repo = self.local();
        let platform = repo.references().map_err(git)?;
        let mut out = Vec::new();
        for r in platform.all().map_err(git)? {
            let mut r = r.map_err(git)?;
            let name = r.name().as_bstr().to_str_lossy().into_owned();
            if !name.starts_with(prefix) {
                continue;
            }
            let id = r.peel_to_id().map_err(git)?.detach();
            out.push((name, id.into()));
        }
        out.sort();
        Ok(out)
    }
}

/// An objects directory with no repository around it. Nothing is read from
/// disk: opening a repository would follow its config and `commondir`, which
/// is no good for a directory somebody else can write to.
pub struct LooseObjects {
    store: gix::odb::loose::Store,
}

impl LooseObjects {
    pub fn at(dir: &Path) -> Self {
        Self {
            store: gix::odb::loose::Store::at(dir, gix::hash::Kind::Sha1),
        }
    }

    pub fn write_blob(&self, bytes: &[u8]) -> Result<GitId> {
        let id = self
            .store
            .write_buf(gix::objs::Kind::Blob, bytes)
            .map_err(git)?;
        Ok(id.into())
    }

    pub fn write_tree(&self, files: &FileMap) -> Result<GitId> {
        let write = |tree: gix::objs::Tree| self.store.write(&tree).map_err(git);
        Ok(write_dir(&write, &nodes(files)?)?.into())
    }

    pub fn write_commit(&self, spec: &CommitSpec) -> Result<GitId> {
        let id = self.store.write(&commit_of(spec)?).map_err(git)?;
        Ok(id.into())
    }
}

/// A Git index holding `files`, as the bytes of `.git/index`. Every stat is
/// zero, so Git compares each file by content the first time it looks: a
/// stat taken here could call a locally edited file clean. Files with
/// another mode than regular or executable are refused: an index of this
/// kind describes a checkout, where neither can be.
pub fn index_of(files: &FileMap) -> Result<Vec<u8>> {
    use gix::index::entry::{Flags, Mode, Stat};
    let mut state = gix::index::State::new(gix::hash::Kind::Sha1);
    for (path, entry) in files {
        let mode = match entry.mode {
            FileMode::Regular => Mode::FILE,
            FileMode::Executable => Mode::FILE_EXECUTABLE,
            other => {
                return Err(Error::Invalid(format!(
                    "{path}: no index entry for {other:?}"
                )));
            }
        };
        let id = entry.blob.oid()?;
        state.dangerously_push_entry(
            Stat::default(),
            id,
            Flags::empty(),
            mode,
            path.as_str().into(),
        );
    }
    state.sort_entries();
    let mut out = Vec::new();
    let options = gix::index::write::Options {
        extensions: gix::index::write::Extensions::None,
        skip_hash: false,
    };
    gix::index::File::from_state(state, "index")
        .write_to(&mut out, options)
        .map_err(git)?;
    Ok(out)
}

fn commit_of(spec: &CommitSpec) -> Result<gix::objs::Commit> {
    let sig = gix::actor::Signature {
        name: spec.author_name.as_str().into(),
        email: spec.author_email.as_str().into(),
        time: gix::date::Time {
            seconds: spec.time_ms.div_euclid(1000),
            offset: 0,
        },
    };
    let parents = spec
        .parents
        .iter()
        .map(|p| p.oid())
        .collect::<Result<Vec<_>>>()?;
    Ok(gix::objs::Commit {
        tree: spec.tree.oid()?,
        parents: parents.into_iter().collect(),
        author: sig.clone(),
        committer: sig,
        encoding: None,
        message: spec.message.as_str().into(),
        extra_headers: spec
            .headers
            .iter()
            .map(|(k, v)| (k.as_str().into(), v.as_str().into()))
            .collect(),
    })
}

/// `files` as a tree of directories.
fn nodes(files: &FileMap) -> Result<BTreeMap<String, Node>> {
    let mut root = BTreeMap::new();
    for (path, entry) in files {
        validate_repo_path(path)?;
        let comps: Vec<&str> = path.split('/').collect();
        insert(&mut root, &comps, entry, path)?;
    }
    Ok(root)
}

fn insert(
    dir: &mut BTreeMap<String, Node>,
    comps: &[&str],
    entry: &FileEntry,
    full: &str,
) -> Result<()> {
    let clash = || Error::Invalid(format!("path {full:?} is both a file and a directory"));
    let Some((first, rest)) = comps.split_first() else {
        return Err(Error::Invalid(format!("empty path {full:?}")));
    };
    if rest.is_empty() {
        if let Some(Node::Dir(_)) = dir.get(*first) {
            return Err(clash());
        }
        dir.insert(first.to_string(), Node::File(entry.clone()));
        return Ok(());
    }
    let node = dir
        .entry(first.to_string())
        .or_insert_with(|| Node::Dir(BTreeMap::new()));
    match node {
        Node::Dir(d) => insert(d, rest, entry, full),
        Node::File(_) => Err(clash()),
    }
}

fn write_dir(
    write: &impl Fn(gix::objs::Tree) -> Result<ObjectId>,
    dir: &BTreeMap<String, Node>,
) -> Result<ObjectId> {
    let mut entries = Vec::with_capacity(dir.len());
    for (name, node) in dir {
        let (mode, oid) = match node {
            Node::File(f) => {
                let kind = match f.mode {
                    FileMode::Regular => EntryKind::Blob,
                    FileMode::Executable => EntryKind::BlobExecutable,
                    FileMode::Symlink => EntryKind::Link,
                    FileMode::Submodule => EntryKind::Commit,
                };
                (kind, f.blob.oid()?)
            }
            Node::Dir(d) => (EntryKind::Tree, write_dir(write, d)?),
        };
        entries.push(tree::Entry {
            mode: mode.into(),
            filename: name.as_str().into(),
            oid,
        });
    }
    entries.sort();
    write(gix::objs::Tree { entries })
}

fn walk(repo: &gix::Repository, id: ObjectId, prefix: &str, out: &mut FileMap) -> Result<()> {
    let obj = repo.find_object(id).map_err(git)?;
    if obj.kind != gix::object::Kind::Tree {
        return Err(Error::Invalid(format!("{id} is not a tree")));
    }
    let tree = gix::objs::TreeRef::from_bytes(&obj.data, repo.object_hash()).map_err(git)?;
    for e in tree.entries {
        let name = e
            .filename
            .to_str()
            .map_err(|_| Error::Invalid("non-UTF-8 file name in tree".into()))?;
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        let mode = match e.mode.kind() {
            EntryKind::Tree => {
                walk(repo, e.oid.to_owned(), &path, out)?;
                continue;
            }
            EntryKind::Blob => FileMode::Regular,
            EntryKind::BlobExecutable => FileMode::Executable,
            EntryKind::Link => FileMode::Symlink,
            EntryKind::Commit => FileMode::Submodule,
        };
        out.insert(
            path,
            FileEntry {
                mode,
                blob: e.oid.to_owned().into(),
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let s = Store::init_bare(&dir.path().join("repo.git")).unwrap();
        (dir, s)
    }

    #[test]
    fn short_and_debug_show_ten_digits() {
        let id = GitId("0123456789abcdef0123456789abcdef01234567".into());
        assert_eq!(id.short(), "0123456789");
        assert_eq!(format!("{id:?}"), "GitId(0123456789)");
        assert_eq!(GitId("abc".into()).short(), "abc");
    }

    #[test]
    fn tree_round_trip_with_nested_dirs() {
        let (_d, s) = store();
        let a = s.write_blob(b"fn a() {}\n").unwrap();
        let b = s.write_blob(b"#!/bin/sh\n").unwrap();
        let mut files = FileMap::new();
        files.insert(
            "src/a.rs".into(),
            FileEntry {
                mode: FileMode::Regular,
                blob: a.clone(),
            },
        );
        files.insert(
            "src/nested/deep/x.rs".into(),
            FileEntry {
                mode: FileMode::Regular,
                blob: a,
            },
        );
        files.insert(
            "run.sh".into(),
            FileEntry {
                mode: FileMode::Executable,
                blob: b,
            },
        );
        let tree = s.write_tree(&files).unwrap();
        assert_eq!(s.read_tree(&tree).unwrap(), files);
        // Same content, same id: trees are content addressed.
        assert_eq!(s.write_tree(&files).unwrap(), tree);
    }

    #[test]
    fn rejects_file_and_directory_clash() {
        let (_d, s) = store();
        let a = s.write_blob(b"x").unwrap();
        let mut files = FileMap::new();
        files.insert(
            "a".into(),
            FileEntry {
                mode: FileMode::Regular,
                blob: a.clone(),
            },
        );
        files.insert(
            "a/b".into(),
            FileEntry {
                mode: FileMode::Regular,
                blob: a,
            },
        );
        assert!(s.write_tree(&files).is_err());
    }

    #[test]
    fn commit_headers_and_refs() {
        let (_d, s) = store();
        let tree = s.empty_tree().unwrap();
        let spec = CommitSpec {
            tree: tree.clone(),
            parents: vec![],
            author_name: "Ayşe".into(),
            author_email: "ayse@example.com".into(),
            time_ms: 1_760_000_000_000,
            message: "first\n".into(),
            headers: vec![(
                "change-id".into(),
                "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".into(),
            )],
        };
        let c1 = s.write_commit(&spec).unwrap();
        let info = s.read_commit(&c1).unwrap();
        assert_eq!(info.tree, tree);
        assert_eq!(
            info.header("change-id"),
            Some("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
        );
        assert_eq!(info.author_name, "Ayşe");

        s.ref_cas("refs/heads/main", &c1, None).unwrap();
        assert!(
            s.ref_cas("refs/heads/main", &c1, None).is_err(),
            "must not exist"
        );
        let c2 = s
            .write_commit(&CommitSpec {
                parents: vec![c1.clone()],
                message: "second\n".into(),
                ..spec
            })
            .unwrap();
        assert!(
            s.ref_cas("refs/heads/main", &c2, Some(&c2)).is_err(),
            "stale expectation"
        );
        s.ref_cas("refs/heads/main", &c2, Some(&c1)).unwrap();
        assert_eq!(s.ref_get("refs/heads/main").unwrap(), Some(c2.clone()));
        assert_eq!(s.read_commit(&c2).unwrap().parents, vec![c1.clone()]);
        assert_eq!(
            s.refs_with_prefix("refs/heads/").unwrap(),
            vec![("refs/heads/main".to_string(), c2.clone())]
        );
        assert!(
            s.ref_delete("refs/heads/main", &c1).is_err(),
            "not what it names"
        );
        s.ref_delete("refs/heads/main", &c2).unwrap();
        assert_eq!(s.ref_get("refs/heads/main").unwrap(), None);
        assert!(s.ref_delete("refs/heads/main", &c2).is_err(), "gone");
    }

    #[test]
    fn git_cli_reads_what_we_write() {
        let (_d, s) = store();
        let blob = s.write_blob(b"hello\n").unwrap();
        let mut files = FileMap::new();
        files.insert(
            "docs/readme.md".into(),
            FileEntry {
                mode: FileMode::Regular,
                blob,
            },
        );
        let tree = s.write_tree(&files).unwrap();
        let c = s
            .write_commit(&CommitSpec {
                tree,
                parents: vec![],
                author_name: "a".into(),
                author_email: "a@b".into(),
                time_ms: 0,
                message: "m\n".into(),
                headers: vec![(
                    "change-id".into(),
                    "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk".into(),
                )],
            })
            .unwrap();
        let out = std::process::Command::new("git")
            .args([
                "--git-dir",
                s.path().to_str().unwrap(),
                "show",
                &format!("{c}:docs/readme.md"),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, b"hello\n");
        let fsck = std::process::Command::new("git")
            .args([
                "--git-dir",
                s.path().to_str().unwrap(),
                "fsck",
                "--no-dangling",
            ])
            .output()
            .unwrap();
        assert!(
            fsck.status.success(),
            "{}",
            String::from_utf8_lossy(&fsck.stderr)
        );
    }
}

#[cfg(test)]
mod loose_tests {
    use super::*;

    /// `git` reading a bare repository around the objects.
    fn git(dir: &Path, args: &[&str]) -> String {
        let out = std::process::Command::new("git")
            .arg("--git-dir")
            .arg(dir)
            .args(args)
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "git {args:?}: {err}");
        String::from_utf8_lossy(&out.stdout).trim_end().to_string()
    }

    fn file(mode: FileMode, blob: &GitId) -> FileEntry {
        let blob = blob.clone();
        FileEntry { mode, blob }
    }

    #[test]
    fn objects_written_with_no_repository_are_what_git_reads() {
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("repo.git");
        Store::init_bare(&bare).unwrap();
        let objects = LooseObjects::at(&bare.join("objects"));

        let blob = objects.write_blob(b"hello\n").unwrap();
        assert_eq!(blob, GitId::of_blob(b"hello\n"));
        let files = FileMap::from([
            ("a.txt".to_string(), file(FileMode::Regular, &blob)),
            ("d/run.sh".to_string(), file(FileMode::Executable, &blob)),
        ]);
        let tree = objects.write_tree(&files).unwrap();
        assert_eq!(
            tree,
            Store::open(&bare).unwrap().write_tree(&files).unwrap()
        );
        let spec = CommitSpec {
            tree: tree.clone(),
            parents: vec![],
            author_name: "a".into(),
            author_email: "a@b".into(),
            time_ms: 5_000,
            message: "m\n".into(),
            headers: vec![],
        };
        let commit = objects.write_commit(&spec).unwrap();
        assert_eq!(
            commit,
            Store::open(&bare).unwrap().write_commit(&spec).unwrap()
        );
        let shown = git(&bare, &["show", "--format=%T %an %at", "-s", &commit.0]);
        assert_eq!(shown, format!("{} a 5", tree.0));
        assert_eq!(
            git(&bare, &["show", &format!("{}:d/run.sh", commit.0)]),
            "hello"
        );
    }

    #[test]
    fn a_tree_of_paths_that_can_not_be_a_tree_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let objects = LooseObjects::at(dir.path());
        let blob = GitId::of_blob(b"x");
        let one = |p: &str| FileMap::from([(p.to_string(), file(FileMode::Regular, &blob))]);
        assert!(objects.write_tree(&one(".git/config")).is_err());
        let mut clash = one("a");
        clash.extend(one("a/b"));
        assert!(objects.write_tree(&clash).is_err());
    }

    #[test]
    fn an_index_lists_the_files_in_gits_order_with_their_modes() {
        let dir = tempfile::tempdir().unwrap();
        let bare = dir.path().join("repo.git");
        Store::init_bare(&bare).unwrap();
        let blob = GitId::of_blob(b"x");
        let files = FileMap::from([
            ("a/b".to_string(), file(FileMode::Regular, &blob)),
            ("a.b".to_string(), file(FileMode::Regular, &blob)),
            ("run".to_string(), file(FileMode::Executable, &blob)),
        ]);
        std::fs::write(bare.join("index"), index_of(&files).unwrap()).unwrap();
        let listed = git(&bare, &["ls-files", "--stage"]);
        let want = [
            format!("100644 {} 0\ta.b", blob.0),
            format!("100644 {} 0\ta/b", blob.0),
            format!("100755 {} 0\trun", blob.0),
        ];
        assert_eq!(listed, want.join("\n"));

        for mode in [FileMode::Symlink, FileMode::Submodule] {
            let files = FileMap::from([("x".to_string(), file(mode, &blob))]);
            let e = index_of(&files).unwrap_err().to_string();
            assert!(e.contains("x: no index entry"), "{e}");
        }
    }
}

#[cfg(test)]
mod blob_id_tests {
    use super::*;

    #[test]
    fn of_blob_matches_git() {
        let out = std::process::Command::new("git")
            .args(["hash-object", "--stdin"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut c| {
                use std::io::Write;
                c.stdin.take().unwrap().write_all(b"hello\n")?;
                c.wait_with_output()
            })
            .unwrap();
        assert_eq!(
            GitId::of_blob(b"hello\n").0,
            String::from_utf8_lossy(&out.stdout).trim()
        );
    }
}
