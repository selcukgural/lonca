//! The import directory of a hardened install (`lonca daemon --import-dir`):
//! where the developer leaves a Git bundle for `lonca init --import` or
//! `lonca restore`. Anything running as the developer can write there, so
//! git never reads it: the daemon opens a regular file directly inside it,
//! never through a link, and copies it into its own home first. A link
//! swapped in after the check, a FIFO, a directory with `alternates` into
//! the stores: none of them reaches git.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// The largest bundle the daemon copies. A sparse file costs its writer no
/// disk and the copy writes it out in full; a larger history comes from a
/// remote (`https://`, `ssh://`).
pub const MAX_BUNDLE: u64 = 4 << 30;

/// The first line of a Git bundle, by version.
const HEADERS: [&[u8]; 2] = [b"# v2 git bundle\n", b"# v3 git bundle\n"];

/// The daemon's copy of a bundle, removed when dropped.
#[derive(Debug)]
pub struct Copy {
    path: PathBuf,
}

impl Copy {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Copy {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Copies the bundle `name`, directly inside `dir`, to a new file in
/// `into` (the daemon's own, mode 0700), at most `max` bytes. `Err` says
/// why not.
pub fn copy_bundle(
    dir: &Path,
    name: &OsStr,
    into: &Path,
    id: &str,
    max: u64,
) -> Result<Copy, String> {
    let (mut from, len) = open_plain(&dir.join(name))?;
    if len > max {
        return Err(format!(
            "{len} bytes, more than the {max} a bundle may have here: import from a remote"
        ));
    }
    let mut head = Vec::with_capacity(16);
    (&mut from)
        .take(16)
        .read_to_end(&mut head)
        .map_err(|e| format!("can not read it: {e}"))?;
    if !HEADERS.contains(&head.as_slice()) {
        return Err("not a git bundle (`git bundle create`)".into());
    }
    std::fs::create_dir_all(into).map_err(|e| format!("{}: {e}", into.display()))?;
    set_private(into)?;
    let path = into.join(format!("import-{id}.bundle"));
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    // Only a file this call created is removed again.
    let copy = Copy { path };
    // A file that grows after the check is cut at the cap; git refuses
    // the torn bundle.
    let rest = max.saturating_sub(head.len() as u64);
    to.write_all(&head)
        .and_then(|()| std::io::copy(&mut from.take(rest), &mut to))
        .and_then(|_| to.sync_all())
        .map_err(|e| format!("copying it: {e}"))?;
    Ok(copy)
}

/// Opens `path` for reading only if it is a regular file with no other
/// name and its last component is no link; gives its length. Non-blocking,
/// so a FIFO does not hang the open. A hard link is refused because macOS
/// lets anyone link a file they can reach but not read.
fn open_plain(path: &Path) -> Result<(File, u64), String> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) => "a link: leave the file itself".to_string(),
            Some(libc::EACCES) => {
                "the daemon can not read it: make it readable by group lonca (chmod g+r)"
                    .to_string()
            }
            _ => format!("can not open it: {e}"),
        })?;
    let meta = f.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() {
        return Err("not a regular file".into());
    }
    if std::os::unix::fs::MetadataExt::nlink(&meta) > 1 {
        return Err("a hard link: leave a file of its own (cp, not ln)".into());
    }
    Ok((f, meta.len()))
}

fn set_private(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("{}: {e}", dir.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("import");
        let into = t.path().join("home/imports");
        std::fs::create_dir_all(&dir).unwrap();
        (t, dir, into)
    }

    #[test]
    fn a_bundle_is_copied_and_the_copy_goes_with_its_guard() {
        let (_t, dir, into) = dirs();
        for header in HEADERS {
            let mut body = header.to_vec();
            body.extend_from_slice(b"abc refs/heads/main\n\nPACK...");
            std::fs::write(dir.join("x.bundle"), &body).unwrap();
            let copy = copy_bundle(&dir, OsStr::new("x.bundle"), &into, "1", MAX_BUNDLE).unwrap();
            assert_eq!(std::fs::read(copy.path()).unwrap(), body);
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(copy.path()), 0o600);
            assert_eq!(mode(&into), 0o700);
            let path = copy.path().to_path_buf();
            drop(copy);
            assert!(!path.exists());
        }
    }

    #[test]
    fn anything_but_a_plain_bundle_is_refused() {
        let (t, dir, into) = dirs();
        let refused =
            |name: &str| copy_bundle(&dir, OsStr::new(name), &into, "1", MAX_BUNDLE).unwrap_err();
        std::fs::write(dir.join("text"), "# v2 git bundl").unwrap();
        assert!(refused("text").contains("not a git bundle"));
        std::fs::write(dir.join("empty"), "").unwrap();
        assert!(refused("empty").contains("not a git bundle"));
        let secret = t.path().join("secret.bundle");
        std::fs::write(&secret, "# v2 git bundle\n").unwrap();
        std::os::unix::fs::symlink(&secret, dir.join("link.bundle")).unwrap();
        assert!(refused("link.bundle").contains("a link"));
        std::fs::create_dir(dir.join("repo.git")).unwrap();
        assert!(refused("repo.git").contains("not a regular file"));
        let made = std::process::Command::new("mkfifo")
            .arg(dir.join("fifo"))
            .status()
            .unwrap();
        assert!(made.success());
        assert!(refused("fifo").contains("not a regular file"));
        assert!(refused("missing").contains("can not open"));
        std::fs::hard_link(&secret, dir.join("hard.bundle")).unwrap();
        assert!(refused("hard.bundle").contains("a hard link"));
        assert!(!into.exists(), "nothing was copied");
    }

    #[test]
    fn a_bundle_above_the_cap_is_refused_before_a_byte_is_copied() {
        let (_t, dir, into) = dirs();
        let body = b"# v2 git bundle\n0123456789";
        std::fs::write(dir.join("x.bundle"), body).unwrap();
        let n = body.len() as u64;
        let e = copy_bundle(&dir, OsStr::new("x.bundle"), &into, "1", n - 1).unwrap_err();
        assert!(e.contains("more than"), "{e}");
        assert!(!into.exists());
        let copy = copy_bundle(&dir, OsStr::new("x.bundle"), &into, "1", n).unwrap();
        assert_eq!(std::fs::read(copy.path()).unwrap(), body);
    }

    #[test]
    fn an_unreadable_bundle_names_the_group() {
        use std::os::unix::fs::PermissionsExt;
        if running_as_root() {
            return;
        }
        let (_t, dir, into) = dirs();
        let f = dir.join("x.bundle");
        std::fs::write(&f, "# v2 git bundle\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        let e = copy_bundle(&dir, OsStr::new("x.bundle"), &into, "1", MAX_BUNDLE).unwrap_err();
        assert!(e.contains("chmod g+r"), "{e}");
    }

    /// Root reads a 0000 file: the test means nothing then.
    fn running_as_root() -> bool {
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|o| o.stdout.starts_with(b"0\n"))
    }

    #[test]
    fn a_name_already_taken_is_not_overwritten() {
        let (_t, dir, into) = dirs();
        std::fs::write(dir.join("x.bundle"), "# v2 git bundle\n").unwrap();
        std::fs::create_dir_all(&into).unwrap();
        std::fs::write(into.join("import-1.bundle"), "mine").unwrap();
        let e = copy_bundle(&dir, OsStr::new("x.bundle"), &into, "1", MAX_BUNDLE).unwrap_err();
        assert!(e.contains("import-1.bundle"), "{e}");
        assert_eq!(
            std::fs::read(into.join("import-1.bundle")).unwrap(),
            b"mine"
        );
    }
}
