//! Who a client expects on the other end of the daemon socket (design §3.3,
//! measure 2). The daemon checks its peer's uid; this is the other half, so
//! that a process answering on the socket path gets neither a session token
//! nor the last word on what a hook allows.
//!
//! Cooperative mode has no boundary to defend: the daemon runs as the
//! developer, so the current uid is expected and a fake daemon of the same
//! account passes. Hardened mode names the daemon's uid in a root-owned file
//! the installers write; once it exists every client is held to it.

use std::fs::Metadata;
use std::io::{Error, ErrorKind, Result};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

use crate::server::peer_uid;

/// Where the hardened installers name the daemon's uid.
pub const CONFIG: &str = if cfg!(target_os = "macos") {
    "/Library/Lonca/daemon.toml"
} else {
    "/etc/lonca/daemon.toml"
};

/// Group or other may write.
const OTHERS_WRITE: u32 = 0o022;

const ROOT: u32 = 0;

fn refuse(message: String) -> Error {
    Error::new(ErrorKind::PermissionDenied, message)
}

pub fn current_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// `daemon_uid = N`; anything else in the file is ignored.
pub fn parse_config(text: &str) -> Option<u32> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        if key.trim() != "daemon_uid" {
            return None;
        }
        value.trim().parse().ok()
    })
}

fn owned_and_closed(what: &Path, meta: &Metadata, owner: u32) -> Result<()> {
    if meta.uid() != owner || meta.mode() & OTHERS_WRITE != 0 {
        return Err(refuse(format!(
            "{} must belong to uid {owner} and be writable by nobody else",
            what.display()
        )));
    }
    Ok(())
}

/// The uid a config file names. No file is no answer; a file that is not
/// what the installer left is an error, never a fallback to cooperative
/// mode, which would let anyone who can replace it choose the daemon.
fn configured_uid(path: &Path, owner: u32) -> Result<Option<u32>> {
    let meta = match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    if !meta.is_file() {
        return Err(refuse(format!("{} is not a file", path.display())));
    }
    owned_and_closed(path, &meta, owner)?;
    if let Some(parent) = path.parent() {
        owned_and_closed(parent, &std::fs::metadata(parent)?, owner)?;
    }
    let text = std::fs::read_to_string(path)?;
    parse_config(&text)
        .map(Some)
        .ok_or_else(|| refuse(format!("{} names no daemon_uid", path.display())))
}

/// The directory of a hardened socket: its owner is the daemon or root, and
/// nobody else can replace what is in it.
fn safe_socket_dir(expected: u32, dir_uid: u32, mode: u32) -> bool {
    (dir_uid == expected || dir_uid == ROOT) && mode & OTHERS_WRITE == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Trust {
    uid: u32,
    hardened: bool,
}

impl Trust {
    pub fn cooperative() -> Self {
        Self {
            uid: current_uid(),
            hardened: false,
        }
    }

    pub fn hardened(uid: u32) -> Self {
        Self {
            uid,
            hardened: true,
        }
    }

    /// What this machine says. A test build reads its own environment and
    /// never the machine's file: the tests stay hermetic, and the variable
    /// does not exist in a release build, where an agent could set it.
    pub fn load() -> Result<Self> {
        if cfg!(debug_assertions) {
            let uid = std::env::var("LONCA_TEST_DAEMON_UID").ok();
            let uid = uid.and_then(|u| u.parse().ok());
            return Ok(uid.map_or_else(Self::cooperative, Self::hardened));
        }
        let uid = configured_uid(Path::new(CONFIG), ROOT)?;
        Ok(uid.map_or_else(Self::cooperative, Self::hardened))
    }

    /// Before connecting: the socket is one, not a link to something else,
    /// and it belongs to the daemon.
    pub fn check_socket(&self, path: &Path) -> Result<()> {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_socket() {
            return Err(refuse(format!("{} is not a socket", path.display())));
        }
        if meta.uid() != self.uid {
            return Err(refuse(format!(
                "{} belongs to uid {}, expected the daemon's uid {}; nothing was sent",
                path.display(),
                meta.uid(),
                self.uid
            )));
        }
        if self.hardened {
            let dir = path.parent().unwrap_or(Path::new("/"));
            let meta = std::fs::metadata(dir)?;
            if !safe_socket_dir(self.uid, meta.uid(), meta.mode()) {
                return Err(refuse(format!(
                    "{} is writable by others; the socket in it proves nothing",
                    dir.display()
                )));
            }
        }
        Ok(())
    }

    /// After connecting, before a byte is sent: the file can have changed
    /// since it was looked at, the peer's uid can not be faked.
    pub fn check_peer(&self, stream: &UnixStream) -> Result<()> {
        match peer_uid(stream) {
            Some(uid) if uid == self.uid => Ok(()),
            uid => Err(refuse(format!(
                "the process on the socket runs as uid {uid:?}, expected the daemon's uid {}; \
                 nothing was sent",
                self.uid
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    fn chmod(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn denied<T: std::fmt::Debug>(r: Result<T>, says: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains(says), "{e}");
    }

    #[test]
    fn the_config_names_a_number_or_nothing() {
        assert_eq!(parse_config("daemon_uid = 280\n"), Some(280));
        assert_eq!(
            parse_config("# who\n  daemon_uid=7  \nother = 1\n"),
            Some(7)
        );
        assert_eq!(parse_config("other = 1\n"), None);
        assert_eq!(parse_config("my_daemon_uid = 3\n"), None);
        assert_eq!(parse_config("daemon_uid = root\n"), None);
        assert_eq!(parse_config(""), None);
    }

    #[test]
    fn a_config_counts_only_as_the_installer_left_it() {
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o755);
        let me = current_uid();
        let file = dir.path().join("daemon.toml");
        assert_eq!(configured_uid(&file, me).unwrap(), None, "no file");

        std::fs::write(&file, "daemon_uid = 280\n").unwrap();
        chmod(&file, 0o644);
        assert_eq!(configured_uid(&file, me).unwrap(), Some(280));

        denied(configured_uid(&file, me + 1), "must belong to uid");
        for mode in [0o664, 0o646] {
            chmod(&file, mode);
            denied(configured_uid(&file, me), "writable by nobody else");
        }
        chmod(&file, 0o644);
        chmod(dir.path(), 0o775);
        denied(configured_uid(&file, me), "writable by nobody else");
        chmod(dir.path(), 0o755);

        std::fs::write(&file, "something else\n").unwrap();
        denied(configured_uid(&file, me), "names no daemon_uid");

        let link = dir.path().join("link.toml");
        std::fs::remove_file(&file).unwrap();
        std::fs::write(dir.path().join("real"), "daemon_uid = 1\n").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real"), &link).unwrap();
        denied(configured_uid(&link, me), "is not a file");
    }

    #[test]
    fn a_hardened_socket_directory_is_the_daemons_or_roots_alone() {
        assert!(safe_socket_dir(280, 280, 0o750));
        assert!(safe_socket_dir(280, ROOT, 0o755));
        assert!(!safe_socket_dir(280, 501, 0o750), "the developer's");
        assert!(!safe_socket_dir(280, 280, 0o770), "group may write");
        assert!(!safe_socket_dir(280, 280, 0o752), "others may write");
        assert!(!safe_socket_dir(280, ROOT, 0o777));
    }

    #[test]
    fn a_socket_is_checked_before_anything_connects() {
        let dir = tempfile::tempdir().unwrap();
        chmod(dir.path(), 0o700);
        let me = current_uid();
        let sock = dir.path().join("s");
        let missing = Trust::hardened(me).check_socket(&sock).unwrap_err();
        assert_eq!(missing.kind(), ErrorKind::NotFound);

        let _l = UnixListener::bind(&sock).unwrap();
        Trust::cooperative().check_socket(&sock).unwrap();
        Trust::hardened(me).check_socket(&sock).unwrap();
        let other = Trust::hardened(me + 1).check_socket(&sock);
        denied(other, "expected the daemon's uid");

        // The same socket in a directory others may write to: fine for a
        // cooperative client, not for a hardened one.
        chmod(dir.path(), 0o777);
        Trust::cooperative().check_socket(&sock).unwrap();
        denied(
            Trust::hardened(me).check_socket(&sock),
            "writable by others",
        );
        chmod(dir.path(), 0o700);

        let file = dir.path().join("f");
        std::fs::write(&file, "").unwrap();
        denied(Trust::cooperative().check_socket(&file), "is not a socket");
        let link = dir.path().join("l");
        std::os::unix::fs::symlink(&sock, &link).unwrap();
        denied(Trust::cooperative().check_socket(&link), "is not a socket");
    }

    #[test]
    fn the_peer_is_the_daemon_or_nothing_is_sent() {
        let (a, _b) = UnixStream::pair().unwrap();
        let me = current_uid();
        Trust::hardened(me).check_peer(&a).unwrap();
        Trust::cooperative().check_peer(&a).unwrap();
        denied(Trust::hardened(me + 1).check_peer(&a), "nothing was sent");
    }

    #[test]
    fn a_plain_machine_expects_the_current_uid() {
        assert_eq!(
            Trust::cooperative(),
            Trust {
                uid: current_uid(),
                hardened: false
            }
        );
    }
}
