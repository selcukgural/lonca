//! Files of a workspace. An agent can write there, and the `lonca` reading
//! or writing them may hold more rights than the agent: an MCP server runs
//! outside the agent's sandbox. So a path is opened from the root one
//! component at a time, never following a symlink. Checking first and
//! opening after would leave a gap the agent can race.
//!
//! A path may also come from `workspace.json`, which the agent can edit, so
//! it is checked here, where it is used.

use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;

use anyhow::{Context, Result, bail};
use rustix::fs::{
    AtFlags, CWD, FileType, Mode, OFlags, fchmod, fstat, mkdirat, openat, renameat, statat,
    unlinkat,
};
use rustix::io::Errno;

pub const REGULAR: u32 = 0o644;
pub const EXECUTABLE: u32 = 0o755;
pub const SECRET: u32 = 0o600;

/// The most a read returns: no request could carry more, and a sparse file
/// can claim any size.
const MAX_FILE: u64 = lonca_daemon::protocol::MAX_LINE as u64;

const ROOT: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::CLOEXEC);
const DIR: OFlags = ROOT.union(OFlags::NOFOLLOW);
/// NONBLOCK: a FIFO must not hang the reader.
const READ: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
/// EXCL: a symlink at the name is refused, not followed.
const CREATE: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::CLOEXEC);
const EXEC: Mode = Mode::XUSR.union(Mode::XGRP).union(Mode::XOTH);

/// A regular file of the workspace.
pub struct Local {
    pub bytes: Vec<u8>,
    pub executable: bool,
}

/// `rel` split at its last slash, or an error if it could leave the root.
fn split(rel: &str) -> Result<(Vec<&str>, &str)> {
    let mut parts: Vec<&str> = rel.split('/').collect();
    if parts.iter().any(|c| matches!(*c, "" | "." | "..")) {
        bail!("{rel:?} is not a path inside the workspace");
    }
    let leaf = parts.pop().unwrap_or_default();
    Ok((parts, leaf))
}

fn is_symlink(dir: &OwnedFd, name: &str) -> bool {
    statat(dir, name, AtFlags::SYMLINK_NOFOLLOW)
        .is_ok_and(|s| FileType::from_raw_mode(s.st_mode) == FileType::Symlink)
}

/// The error for a failed open of `name`: a symlink is named as one, since
/// the person reading it has something to fix.
fn refused(dir: &OwnedFd, name: &str, rel: &str, e: Errno) -> anyhow::Error {
    if is_symlink(dir, name) {
        return anyhow::anyhow!("{rel}: {name} is a symlink, and a workspace holds regular files");
    }
    anyhow::Error::from(std::io::Error::from(e)).context(format!("opening {rel}"))
}

/// The directory holding `rel`, reached with no symlink on the way. Without
/// `create`, `None` means there is no such directory.
fn parent(root: &Path, rel: &str, dirs: &[&str], create: bool) -> Result<Option<OwnedFd>> {
    // The root is the caller's own: it may well lie behind a symlink.
    let mut dir = openat(CWD, root, ROOT, Mode::empty())
        .with_context(|| format!("opening {}", root.display()))?;
    for name in dirs {
        let mut next = openat(&dir, *name, DIR, Mode::empty());
        if create && matches!(next, Err(Errno::NOENT)) {
            mkdirat(&dir, *name, Mode::from_raw_mode(0o755))
                .map_err(|e| refused(&dir, name, rel, e))?;
            next = openat(&dir, *name, DIR, Mode::empty());
        }
        dir = match next {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::NOTDIR) if !create && !is_symlink(&dir, name) => return Ok(None),
            Err(e) => return Err(refused(&dir, name, rel, e)),
        };
    }
    Ok(Some(dir))
}

/// The file at `rel`, or `None` if nothing there is a file: it is missing,
/// or a directory took its place. A symlink on the way, or anything that is
/// neither, is an error: guessing would propose a deletion nobody made.
pub fn read(root: &Path, rel: &str) -> Result<Option<Local>> {
    read_within(root, rel, MAX_FILE)
}

fn read_within(root: &Path, rel: &str, cap: u64) -> Result<Option<Local>> {
    let (dirs, leaf) = split(rel)?;
    let Some(dir) = parent(root, rel, &dirs, false)? else {
        return Ok(None);
    };
    read_in(&dir, leaf, rel, cap)
}

/// Reads many files of one root. A read alone opens every directory from
/// the root down to its file; of a workspace's files that is most of the
/// work, the same directories opened again for every file in them. This
/// keeps the directories of the last path open and goes on from the part
/// the next path shares with it.
///
/// Every directory it holds was opened from the one above it without
/// following a link, as a read alone opens it, and every file is opened and
/// checked the same way: nothing is reached through a link here that a
/// read alone would refuse. What differs is when a directory was looked
/// up. One that is moved or replaced while its files are read is still
/// read where it was found, to the last of its files in a row, where a
/// read alone would find the new one at the next file. Neither is a
/// picture of one moment; whoever can write the workspace could have put
/// those files there as well.
///
/// It keeps at most [`HELD`] directories below the root: a path can be as
/// deep as its file system lets it, and a process has only so many open
/// files. Deeper than that, the rest is opened for each file, as before.
pub struct Reader<'a> {
    root: &'a Path,
    top: Option<OwnedFd>,
    /// The directories from the root down to where the last file was
    /// looked for, each opened from the one before it.
    below: Vec<(String, OwnedFd)>,
    /// The directory of the last file, when it is deeper than is kept.
    deep: Option<OwnedFd>,
}

/// How many directories below the root a [`Reader`] keeps open.
const HELD: usize = 16;

impl<'a> Reader<'a> {
    pub fn new(root: &'a Path) -> Self {
        Self {
            root,
            top: None,
            below: Vec::new(),
            deep: None,
        }
    }

    /// What [`read`] gives for `rel`.
    pub fn read(&mut self, rel: &str) -> Result<Option<Local>> {
        let (dirs, leaf) = split(rel)?;
        match self.dir(rel, &dirs)? {
            Some(dir) => read_in(dir, leaf, rel, MAX_FILE),
            None => Ok(None),
        }
    }

    /// The directory `dirs` lead to, as [`parent`] finds it; `None` if
    /// there is none.
    fn dir(&mut self, rel: &str, dirs: &[&str]) -> Result<Option<&OwnedFd>> {
        let top = match self.top.take() {
            Some(top) => top,
            // The root is the caller's own: it may well lie behind a symlink.
            None => openat(CWD, self.root, ROOT, Mode::empty())
                .with_context(|| format!("opening {}", self.root.display()))?,
        };
        let top = self.top.insert(top);
        self.deep = None;
        let held = self.below.iter().map(|(name, _)| name.as_str());
        let shared = held
            .zip(dirs)
            .take_while(|(held, dir)| held == *dir)
            .count();
        self.below.truncate(shared);
        for name in dirs.iter().skip(shared) {
            let dir = match &self.deep {
                Some(deep) => deep,
                None => self.below.last().map_or(&*top, |(_, fd)| fd),
            };
            let next = match openat(dir, *name, DIR, Mode::empty()) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => return Ok(None),
                Err(Errno::NOTDIR) if !is_symlink(dir, name) => return Ok(None),
                Err(e) => return Err(refused(dir, name, rel, e)),
            };
            if self.below.len() < HELD && self.deep.is_none() {
                self.below.push((name.to_string(), next));
            } else {
                // Past what is kept: the one before it is closed here.
                self.deep = Some(next);
            }
        }
        Ok(Some(match &self.deep {
            Some(deep) => deep,
            None => self.below.last().map_or(&*top, |(_, fd)| fd),
        }))
    }
}

/// The file `leaf` of the directory `dir`, which is where `rel` is.
fn read_in(dir: &OwnedFd, leaf: &str, rel: &str, cap: u64) -> Result<Option<Local>> {
    let fd = match openat(dir, leaf, READ, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(refused(dir, leaf, rel, e)),
    };
    let stat = fstat(&fd)?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile => {}
        FileType::Directory => return Ok(None),
        _ => bail!("{rel} is not a regular file"),
    }
    // Another name for the file may lie outside the workspace.
    if stat.st_nlink > 1 {
        bail!("{rel} has other hard links, and a workspace holds its own files");
    }
    if stat.st_size as u64 > cap {
        bail!("{rel} is {} bytes, more than Lonca handles", stat.st_size);
    }
    // Room for what `fstat` said, which is within the cap: not grown into.
    let mut bytes = Vec::with_capacity(stat.st_size as usize);
    File::from(fd).take(cap).read_to_end(&mut bytes)?;
    // The count was read after the open: a name linked in from outside
    // and taken away between the two shows one link, on a file that was
    // never the workspace's. What was read is the file this name still
    // is, with no other name, or it is not taken.
    if !still_alone(dir, leaf, &stat) {
        bail!("{rel} changed while it was read, or has other hard links");
    }
    let executable = Mode::from_raw_mode(stat.st_mode).intersects(EXEC);
    Ok(Some(Local { bytes, executable }))
}

/// Is the name `leaf` in `dir` still the file `opened` was, and that file's
/// only name?
fn still_alone(dir: &impl std::os::fd::AsFd, leaf: &str, opened: &rustix::fs::Stat) -> bool {
    match statat(dir, leaf, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(named) => {
            (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino) && named.st_nlink <= 1
        }
        Err(_) => false,
    }
}

/// Writes `rel`, making the directories it needs. The new file replaces
/// whatever is at that name, a symlink included, without following it.
pub fn write(root: &Path, rel: &str, bytes: &[u8], mode: u32) -> Result<()> {
    let (dirs, leaf) = split(rel)?;
    let dir = parent(root, rel, &dirs, true)?.context("no directory after creating it")?;
    let mode = Mode::from_raw_mode(mode as _);
    let tmp = lonca_core::canonical::random_id(".lonca-tmp");
    let fd = openat(&dir, &tmp, CREATE, mode).map_err(|e| refused(&dir, &tmp, rel, e))?;
    let written = fchmod(&fd, mode)
        .map_err(std::io::Error::from)
        .and_then(|()| File::from(fd).write_all(bytes))
        .and_then(|()| renameat(&dir, &tmp, &dir, leaf).map_err(Into::into));
    if written.is_err() {
        let _ = unlinkat(&dir, &tmp, AtFlags::empty());
    }
    written.with_context(|| format!("writing {rel}"))
}

/// Removes `rel` if it is there: a symlink is removed itself, never its
/// target. What can not be removed stays, as a local change.
pub fn remove(root: &Path, rel: &str) -> Result<()> {
    let (dirs, leaf) = split(rel)?;
    if let Some(dir) = parent(root, rel, &dirs, false)? {
        let _ = unlinkat(&dir, leaf, AtFlags::empty());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn root() -> (tempfile::TempDir, tempfile::TempDir) {
        (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap())
    }

    fn text(e: anyhow::Error) -> String {
        format!("{e:#}")
    }

    fn files_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_path_that_could_leave_the_root_is_refused_everywhere() {
        let (dir, out) = root();
        let victim = out.path().join("victim");
        fs::write(&victim, "mine").unwrap();
        let up = format!(
            "../{}/victim",
            out.path().file_name().unwrap().to_string_lossy()
        );
        for rel in [
            up.as_str(),
            "..",
            ".",
            "",
            "a/../b",
            "a//b",
            "/etc/hosts",
            "a/",
            "./a",
        ] {
            let want = "not a path inside the workspace";
            assert!(
                text(read(dir.path(), rel).err().unwrap()).contains(want),
                "{rel}"
            );
            let e = write(dir.path(), rel, b"x", REGULAR).unwrap_err();
            assert!(text(e).contains(want), "{rel}");
            assert!(
                text(remove(dir.path(), rel).unwrap_err()).contains(want),
                "{rel}"
            );
        }
        assert_eq!(fs::read_to_string(&victim).unwrap(), "mine");
    }

    #[test]
    fn reads_tell_a_file_from_nothing_and_from_what_is_not_a_file() {
        let (dir, _out) = root();
        let r = dir.path();
        assert!(read(r, "missing").unwrap().is_none());
        assert!(read(r, "no/such/dir/file").unwrap().is_none());

        fs::create_dir_all(r.join("d/e")).unwrap();
        fs::write(r.join("d/e/plain"), "text").unwrap();
        fs::write(r.join("d/run"), "#!").unwrap();
        fs::set_permissions(r.join("d/run"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(r.join("d/group"), "#!").unwrap();
        fs::set_permissions(r.join("d/group"), fs::Permissions::from_mode(0o654)).unwrap();
        fs::write(r.join("d/other"), "#!").unwrap();
        fs::set_permissions(r.join("d/other"), fs::Permissions::from_mode(0o645)).unwrap();
        let plain = read(r, "d/e/plain").unwrap().unwrap();
        assert_eq!(plain.bytes, b"text");
        assert!(!plain.executable);
        for name in ["d/run", "d/group", "d/other"] {
            assert!(read(r, name).unwrap().unwrap().executable, "{name}");
        }

        // A directory took the file's place, or a file took a directory's.
        assert!(read(r, "d/e").unwrap().is_none());
        assert!(read(r, "d/e/plain/below").unwrap().is_none());

        // A FIFO must not hang the reader.
        let fifo = r.join("fifo");
        let made = std::process::Command::new("mkfifo").arg(&fifo).status();
        assert!(made.unwrap().success());
        let e = text(read(r, "fifo").err().unwrap());
        assert!(e.contains("fifo is not a regular file"), "{e}");
    }

    #[test]
    fn a_read_stops_at_the_cap_by_what_the_file_says_it_is() {
        let (dir, _out) = root();
        let r = dir.path();
        fs::write(r.join("ten"), "0123456789").unwrap();
        assert_eq!(read_within(r, "ten", 10).unwrap().unwrap().bytes.len(), 10);
        let e = text(read_within(r, "ten", 9).err().unwrap());
        assert!(e.contains("ten is 10 bytes"), "{e}");

        let sparse = fs::File::create(r.join("sparse")).unwrap();
        sparse.set_len(MAX_FILE + 1).unwrap();
        assert!(read(r, "sparse").is_err());
    }

    /// The link count is read after the open. A name linked in from
    /// outside and taken away again in between shows one link on a file
    /// that was never the workspace's: what is taken is what the name
    /// still is when the read is over.
    #[test]
    fn a_name_that_was_another_file_while_it_was_read_is_not_taken() {
        let (dir, out) = root();
        let r = dir.path();
        let outside = out.path().join("secret");
        fs::write(&outside, "secret").unwrap();
        fs::hard_link(&outside, r.join("f")).unwrap();
        let at = openat(CWD, r, ROOT, Mode::empty()).unwrap();
        // Opened while it was the outside file; the name goes before the count.
        let fd = openat(&at, "f", READ, Mode::empty()).unwrap();
        fs::remove_file(r.join("f")).unwrap();
        let opened = fstat(&fd).unwrap();
        assert_eq!(opened.st_nlink, 1, "the count alone would take it");
        assert!(!still_alone(&at, "f", &opened), "the name is gone");
        // A file of the workspace's own under that name is another file.
        fs::write(r.join("f"), "mine").unwrap();
        assert!(!still_alone(&at, "f", &opened));
        // Linked in again, it has two names.
        fs::remove_file(r.join("f")).unwrap();
        fs::hard_link(&outside, r.join("f")).unwrap();
        assert!(!still_alone(&at, "f", &opened));
        // A file that stayed what it was is taken.
        fs::write(r.join("own"), "own").unwrap();
        let fd = openat(&at, "own", READ, Mode::empty()).unwrap();
        assert!(still_alone(&at, "own", &fstat(&fd).unwrap()));
        assert_eq!(read(r, "own").unwrap().unwrap().bytes, b"own");
    }

    #[test]
    fn a_file_with_another_name_is_refused() {
        let (dir, out) = root();
        let r = dir.path();
        fs::write(out.path().join("secret"), "secret").unwrap();
        fs::hard_link(out.path().join("secret"), r.join("link")).unwrap();
        let e = text(read(r, "link").err().unwrap());
        assert!(e.contains("link has other hard links"), "{e}");
        // Replacing it leaves the other name as it was.
        write(r, "link", b"mine", REGULAR).unwrap();
        assert_eq!(fs::read(out.path().join("secret")).unwrap(), b"secret");
        assert_eq!(read(r, "link").unwrap().unwrap().bytes, b"mine");
    }

    #[test]
    fn a_read_never_follows_a_symlink() {
        let (dir, out) = root();
        let r = dir.path();
        fs::write(out.path().join("secret"), "secret").unwrap();
        symlink(out.path(), r.join("dir")).unwrap();
        symlink(out.path().join("secret"), r.join("leaf")).unwrap();
        symlink(out.path().join("nothing"), r.join("dangling")).unwrap();
        fs::create_dir(r.join("sub")).unwrap();
        symlink(out.path(), r.join("sub/deep")).unwrap();
        for (rel, name) in [
            ("dir/secret", "dir"),
            ("leaf", "leaf"),
            ("dangling", "dangling"),
            ("sub/deep/secret", "deep"),
            ("leaf/below", "leaf"),
        ] {
            let e = text(read(r, rel).err().expect(rel));
            let want = format!("{rel}: {name} is a symlink");
            assert!(e.contains(&want), "{e}");
        }
    }

    /// What a read says, as words: the bytes and the mode, nothing, or why not.
    fn said(r: Result<Option<Local>>) -> String {
        match r {
            Ok(Some(l)) => format!("{:?} {}", String::from_utf8_lossy(&l.bytes), l.executable),
            Ok(None) => "nothing".into(),
            Err(e) => text(e),
        }
    }

    /// A tree with everything a read can meet in it, and its paths.
    fn everything(r: &Path, out: &Path) -> Vec<&'static str> {
        fs::create_dir_all(r.join("d/e/f")).unwrap();
        fs::create_dir_all(r.join("d/g")).unwrap();
        fs::create_dir_all(r.join("h")).unwrap();
        for (name, body) in [
            ("top", "0"),
            ("d/a", "1"),
            ("d/b", "2"),
            ("d/e/c", "3"),
            ("d/e/f/deep", "4"),
            ("d/g/x", "5"),
            ("h/y", "6"),
        ] {
            fs::write(r.join(name), body).unwrap();
        }
        fs::set_permissions(r.join("d/b"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(out.join("secret"), "secret").unwrap();
        fs::create_dir_all(out.join("far")).unwrap();
        fs::write(out.join("far/inner"), "secret").unwrap();
        symlink(out.join("secret"), r.join("d/link")).unwrap();
        symlink(out.join("far"), r.join("d/away")).unwrap();
        symlink(out.join("far"), r.join("d/e/away")).unwrap();
        fs::hard_link(out.join("secret"), r.join("d/e/hard")).unwrap();
        let made = std::process::Command::new("mkfifo")
            .arg(r.join("d/fifo"))
            .status();
        assert!(made.unwrap().success());
        vec![
            "top",
            "d/a",
            "d/b",
            "d/e/c",
            "d/e/f/deep",
            "d/g/x",
            "h/y",
            // Not there, at every depth, and below what is a file.
            "none",
            "d/none",
            "d/none/none",
            "d/e/f/none",
            "none/d/a",
            "d/a/below",
            "d/e/c/below/more",
            // A directory where a file is asked for.
            "d",
            "d/e",
            "d/e/f",
            // Links, a hard link and a FIFO.
            "d/link",
            "d/away/inner",
            "d/e/away/inner",
            "d/e/hard",
            "d/fifo",
            // No path of a workspace.
            "",
            "d//a",
            "../x",
            "d/../top",
            "/etc/hosts",
            "d/",
        ]
    }

    /// The reader that keeps directories open says of every path what a
    /// read alone says, in any order of the paths: the same bytes, the
    /// same nothing, the same refusal in the same words.
    #[test]
    fn a_reader_says_what_a_read_alone_says() {
        let (dir, out) = root();
        let r = dir.path();
        let paths = everything(r, out.path());
        let alone: Vec<String> = paths.iter().map(|p| said(read(r, p))).collect();
        assert!(
            alone.iter().any(|a| a.contains("is a symlink")),
            "{alone:?}"
        );
        assert!(alone.iter().any(|a| a.contains("other hard links")));
        assert!(alone.iter().any(|a| a.contains("not a regular file")));
        assert!(alone.iter().any(|a| a.contains("not a path inside")));
        assert!(alone.iter().all(|a| !a.contains("secret")), "{alone:?}");

        // Every path after every other one, with one reader for all: what
        // it holds from the path before must not change the answer.
        let mut files = Reader::new(r);
        for (i, first) in paths.iter().enumerate() {
            for (j, second) in paths.iter().enumerate() {
                assert_eq!(said(files.read(first)), alone[i], "{first} before {second}");
                assert_eq!(said(files.read(second)), alone[j], "{second} after {first}");
            }
        }
        // And each path twice in a row, and all of them backwards.
        for (i, p) in paths.iter().enumerate().rev() {
            assert_eq!(said(files.read(p)), alone[i], "{p}");
            assert_eq!(said(files.read(p)), alone[i], "{p} again");
        }

        // A root that is not there is said for every read, and found when
        // it comes to be.
        let later = r.join("later");
        let mut files = Reader::new(&later);
        for _ in 0..2 {
            let (held, one) = (said(files.read("f")), said(read(&later, "f")));
            assert_eq!(held, one);
            assert!(held.contains("opening"), "{held}");
        }
        fs::create_dir(&later).unwrap();
        fs::write(later.join("f"), "now").unwrap();
        assert_eq!(said(files.read("f")), said(read(&later, "f")));
    }

    /// A path deeper than the reader keeps is read as any other, and the
    /// reader holds no more for it: its directories below the sixteenth
    /// are opened for each file, one at a time.
    #[test]
    fn a_reader_keeps_only_so_many_directories() {
        let (dir, out) = root();
        let r = dir.path();
        let deep = |n: usize, leaf: &str| {
            let mut rel: Vec<String> = (0..n).map(|i| format!("d{i}")).collect();
            rel.push(leaf.to_string());
            rel.join("/")
        };
        let mut paths = Vec::new();
        for n in [0, 1, HELD - 1, HELD, HELD + 1, HELD + 2, 3 * HELD] {
            let rel = deep(n, "f");
            fs::create_dir_all(r.join(&rel).parent().unwrap()).unwrap();
            fs::write(r.join(&rel), format!("at {n}")).unwrap();
            paths.extend([rel, deep(n, "none"), deep(n, "none/below")]);
        }
        symlink(out.path(), r.join(deep(HELD + 1, "link"))).unwrap();
        symlink(out.path(), r.join(deep(2 * HELD, "link"))).unwrap();
        paths.push(deep(HELD + 1, "link/x"));
        paths.push(deep(2 * HELD, "link/x"));
        let alone: Vec<String> = paths.iter().map(|p| said(read(r, p))).collect();
        assert_eq!(
            alone.iter().filter(|a| a.contains("is a symlink")).count(),
            2
        );
        let mut files = Reader::new(r);
        for (i, first) in paths.iter().enumerate() {
            for (j, second) in paths.iter().enumerate() {
                assert_eq!(said(files.read(first)), alone[i], "{first}");
                assert!(files.below.len() <= HELD, "{first}");
                assert_eq!(said(files.read(second)), alone[j], "{second} after {first}");
                assert!(files.below.len() <= HELD, "{second}");
            }
        }
    }

    /// What the reader holds is a directory, never a name: one that is
    /// replaced by a link while its files are read is not followed there.
    /// The files still read are those of the directory that was found; a
    /// new reader, like a read alone, refuses the link.
    #[test]
    fn a_directory_replaced_by_a_link_is_never_followed() {
        let (dir, out) = root();
        let r = dir.path();
        fs::create_dir_all(r.join("d/e")).unwrap();
        fs::write(r.join("d/e/a"), "mine a").unwrap();
        fs::write(r.join("d/e/b"), "mine b").unwrap();
        fs::create_dir_all(out.path().join("far/e")).unwrap();
        fs::write(out.path().join("far/e/b"), "secret").unwrap();
        fs::write(out.path().join("far/e/c"), "secret").unwrap();

        let mut files = Reader::new(r);
        assert_eq!(files.read("d/e/a").unwrap().unwrap().bytes, b"mine a");
        // The directory goes elsewhere and a link to the outside takes its
        // name; then the same one level up.
        for (moved, link, to) in [("d/e", "d/e", "far/e"), ("d", "d", "far")] {
            fs::rename(r.join(moved), r.join("kept")).unwrap();
            symlink(out.path().join(to), r.join(link)).unwrap();
            // Held: the directory that was opened, wherever it is now.
            assert_eq!(files.read("d/e/b").unwrap().unwrap().bytes, b"mine b");
            assert!(
                files.read("d/e/c").unwrap().is_none(),
                "only the link has it"
            );
            // Looked up again: the link is refused, by both.
            for fresh in [said(Reader::new(r).read("d/e/b")), said(read(r, "d/e/b"))] {
                assert!(fresh.contains("is a symlink"), "{fresh}");
            }
            // And by the same reader once it has to look the name up.
            assert!(said(files.read("other")).contains("nothing"));
            assert!(said(files.read("d/e/b")).contains("is a symlink"));
            fs::remove_file(r.join(link)).unwrap();
            fs::rename(r.join("kept"), r.join(moved)).unwrap();
            assert_eq!(files.read("d/e/b").unwrap().unwrap().bytes, b"mine b");
        }
        // A file swapped for a link in a directory that is held is refused
        // as ever: the file is opened by its name each time.
        fs::remove_file(r.join("d/e/b")).unwrap();
        symlink(out.path().join("far/e/b"), r.join("d/e/b")).unwrap();
        assert!(said(files.read("d/e/b")).contains("b is a symlink"));
    }

    #[test]
    fn a_write_lands_inside_and_never_through_a_symlink() {
        let (dir, out) = root();
        let r = dir.path();
        write(r, "new/deep/file", b"one", REGULAR).unwrap();
        assert_eq!(fs::read(r.join("new/deep/file")).unwrap(), b"one");
        assert_eq!(files_in(&r.join("new/deep")), ["file"], "no temporary left");

        // A symlink on the way stops it, whatever makes the directory.
        symlink(out.path(), r.join("linked")).unwrap();
        let e = text(write(r, "linked/x", b"no", REGULAR).unwrap_err());
        assert!(e.contains("linked/x: linked is a symlink"), "{e}");
        symlink(out.path().join("nothing"), r.join("dangling")).unwrap();
        let e = text(write(r, "dangling/x", b"no", REGULAR).unwrap_err());
        assert!(e.contains("dangling is a symlink"), "{e}");
        assert!(files_in(out.path()).is_empty());

        // A symlink at the name itself is replaced, and its target stays.
        let victim = out.path().join("victim");
        fs::write(&victim, "mine").unwrap();
        symlink(&victim, r.join("leaf")).unwrap();
        write(r, "leaf", b"two", REGULAR).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "mine");
        let meta = fs::symlink_metadata(r.join("leaf")).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(fs::read(r.join("leaf")).unwrap(), b"two");
    }

    #[test]
    fn a_write_sets_the_mode_it_was_given_and_cleans_up_when_it_fails() {
        let (dir, _out) = root();
        let r = dir.path();
        let mode = |p: &str| fs::metadata(r.join(p)).unwrap().permissions().mode() & 0o777;
        write(r, "a", b"x", REGULAR).unwrap();
        assert_eq!(mode("a"), 0o644);
        write(r, "a", b"y", EXECUTABLE).unwrap();
        assert_eq!(mode("a"), 0o755);
        assert_eq!(fs::read(r.join("a")).unwrap(), b"y");
        write(r, "a", b"z", SECRET).unwrap();
        assert_eq!(mode("a"), 0o600);

        // A directory at the name stays, and so does nothing else.
        fs::create_dir_all(r.join("full/dir/child")).unwrap();
        assert!(write(r, "full/dir", b"x", REGULAR).is_err());
        assert_eq!(files_in(&r.join("full")), ["dir"]);
        // A file where a directory is needed.
        let e = text(write(r, "a/below", b"x", REGULAR).unwrap_err());
        assert!(e.contains("opening a/below"), "{e}");
    }

    #[test]
    fn a_remove_takes_the_link_and_never_goes_through_one() {
        let (dir, out) = root();
        let r = dir.path();
        let victim = out.path().join("victim");
        fs::write(&victim, "mine").unwrap();
        symlink(&victim, r.join("leaf")).unwrap();
        symlink(out.path(), r.join("dir")).unwrap();
        fs::write(r.join("plain"), "x").unwrap();

        remove(r, "plain").unwrap();
        assert!(!r.join("plain").exists());
        remove(r, "leaf").unwrap();
        assert!(fs::symlink_metadata(r.join("leaf")).is_err());
        let e = text(remove(r, "dir/victim").unwrap_err());
        assert!(e.contains("dir is a symlink"), "{e}");
        assert_eq!(fs::read_to_string(&victim).unwrap(), "mine");

        // Nothing there is no error, nor is what can not be removed.
        remove(r, "missing").unwrap();
        remove(r, "no/such/dir").unwrap();
        fs::create_dir(r.join("kept")).unwrap();
        remove(r, "kept").unwrap();
        assert!(r.join("kept").is_dir());
    }
}
