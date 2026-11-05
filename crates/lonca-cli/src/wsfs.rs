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
    let fd = match openat(&dir, leaf, READ, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(e) => return Err(refused(&dir, leaf, rel, e)),
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
    let mut bytes = Vec::new();
    File::from(fd).take(cap).read_to_end(&mut bytes)?;
    let executable = Mode::from_raw_mode(stat.st_mode).intersects(EXEC);
    Ok(Some(Local { bytes, executable }))
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
