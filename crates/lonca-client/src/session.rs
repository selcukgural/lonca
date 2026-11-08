//! The human session file (`docs/protocol.md`, "The human session file is
//! an interface"): `lonca human login` keeps a human's session token at
//! `<humans>/<name>.session`, mode 0600, as `{"token", "expires_ms"}`.
//!
//! The token opens reads and prepares only; every write still needs the
//! human's signature. It is read only from a file that is what `lonca`
//! left: a regular file of this user that nobody else may read or write.

use std::io::{Error, ErrorKind, Read, Result};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::sys::current_uid;

/// A session file is a token and a time; anything near this size is not one.
const MAX_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanSession {
    pub token: String,
    pub expires_ms: i64,
}

impl HumanSession {
    /// Past its time at `now_ms`; the daemon answers `unauthenticated` then.
    pub fn expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_ms
    }
}

/// Where the session files are: `$LONCA_HUMANS`, else
/// `~/.config/lonca/humans`. `None` with neither set.
pub fn humans_dir() -> Option<PathBuf> {
    humans_dir_from(std::env::var_os("LONCA_HUMANS"), std::env::var_os("HOME"))
}

fn humans_dir_from(
    humans: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Option<PathBuf> {
    let set = |v: Option<std::ffi::OsString>| v.filter(|v| !v.is_empty());
    match set(humans) {
        Some(dir) => Some(PathBuf::from(dir)),
        None => set(home).map(|h| PathBuf::from(h).join(".config/lonca/humans")),
    }
}

/// A human name as `lonca` takes it: letters, digits, `.`, `_`, `-`, not
/// starting with `.`.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `<dir>/<name>.session`; an invalid name is refused, so a name can not
/// lead out of `dir`.
pub fn session_path(dir: &Path, name: &str) -> Result<PathBuf> {
    if !valid_name(name) {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            format!("bad human name {name:?}"),
        ));
    }
    Ok(dir.join(format!("{name}.session")))
}

fn refuse(path: &Path, why: &str) -> Error {
    Error::new(
        ErrorKind::PermissionDenied,
        format!("{}: {why}; not read", path.display()),
    )
}

/// The session at `path`. `Ok(None)` when there is no file: log in
/// (`lonca human login --json`) and read again. A link, a file of another
/// user, or one that group or others may read or write is refused, as is
/// one that is not a session.
pub fn read_session(path: &Path) -> Result<Option<HumanSession>> {
    let mut file = match open_no_follow(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        other => other?,
    };
    // Of the file opened, not of the name: it can not be swapped between.
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(refuse(path, "not a regular file"));
    }
    if meta.uid() != current_uid() {
        return Err(refuse(path, "belongs to another user"));
    }
    if meta.mode() & 0o077 != 0 {
        return Err(refuse(path, "group or others may read or write it"));
    }
    if meta.len() > MAX_BYTES {
        return Err(Error::new(ErrorKind::InvalidData, "not a session file"));
    }
    let mut bytes = Vec::new();
    file.by_ref().take(MAX_BYTES).read_to_end(&mut bytes)?;
    let session: HumanSession = serde_json::from_slice(&bytes)
        .map_err(|e| Error::new(ErrorKind::InvalidData, format!("not a session file: {e}")))?;
    Ok(Some(session))
}

/// Opens `path` for reading without following a link at its end.
fn open_no_follow(path: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    match opts.open(path) {
        // O_NOFOLLOW on a link: ELOOP.
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => Err(refuse(path, "a symbolic link")),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn write(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn refused(r: Result<Option<HumanSession>>, says: &str) {
        let e = r.unwrap_err();
        assert_eq!(e.kind(), ErrorKind::PermissionDenied, "{e}");
        assert!(e.to_string().contains(says), "{e}");
    }

    const GOOD: &str = r#"{"token": "lonca_h_x", "expires_ms": 1000}"#;

    #[test]
    fn a_session_file_is_read_as_lonca_left_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = session_path(dir.path(), "ayse").unwrap();
        assert_eq!(path, dir.path().join("ayse.session"));
        assert_eq!(read_session(&path).unwrap(), None, "no file");
        write(&path, GOOD, 0o600);
        let s = read_session(&path).unwrap().unwrap();
        assert_eq!(s.token, "lonca_h_x");
        assert!(!s.expired(999));
        assert!(s.expired(1000));
        write(&path, GOOD, 0o400);
        assert!(read_session(&path).unwrap().is_some(), "read-only is fine");
    }

    #[test]
    fn a_file_others_can_reach_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ayse.session");
        for mode in [0o640, 0o604, 0o620, 0o602, 0o610, 0o601, 0o666] {
            write(&path, GOOD, mode);
            refused(read_session(&path), "group or others");
        }
    }

    #[test]
    fn a_link_or_a_directory_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        write(&real, GOOD, 0o600);
        let link = dir.path().join("ayse.session");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        refused(read_session(&link), "symbolic link");
        let sub = dir.path().join("bora.session");
        std::fs::create_dir(&sub).unwrap();
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
        refused(read_session(&sub), "not a regular file");
    }

    #[test]
    fn what_is_not_a_session_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ayse.session");
        for text in ["", "{}", r#"{"token": 1, "expires_ms": 2}"#, "not json"] {
            write(&path, text, 0o600);
            let e = read_session(&path).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidData, "{text}: {e}");
        }
        let big = format!(
            r#"{{"token": "{}", "expires_ms": 1}}"#,
            "x".repeat(MAX_BYTES as usize)
        );
        write(&path, &big, 0o600);
        let e = read_session(&path).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidData);
        // At the limit to the byte: read, all of it.
        let frame = r#"{"token": "", "expires_ms": 1}"#.len();
        let token = "x".repeat(MAX_BYTES as usize - frame);
        let just = format!(r#"{{"token": "{token}", "expires_ms": 1}}"#);
        assert_eq!(just.len() as u64, MAX_BYTES);
        write(&path, &just, 0o600);
        assert_eq!(read_session(&path).unwrap().unwrap().token, token);
    }

    /// A FIFO would hold an open for reading until someone writes: it is
    /// opened without waiting, and refused.
    #[test]
    fn a_fifo_is_refused_without_waiting() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ayse.session");
        let made = std::process::Command::new("mkfifo")
            .arg("-m")
            .arg("600")
            .arg(&path)
            .status()
            .unwrap();
        assert!(made.success());
        refused(read_session(&path), "not a regular file");
    }

    #[test]
    fn the_directory_is_the_variable_or_under_home() {
        let os = |s: &str| Some(std::ffi::OsString::from(s));
        let at = |s: &str| Some(PathBuf::from(s));
        assert_eq!(humans_dir_from(os("/h"), os("/home/a")), at("/h"));
        let under = at("/home/a/.config/lonca/humans");
        assert_eq!(humans_dir_from(None, os("/home/a")), under);
        assert_eq!(
            humans_dir_from(os(""), os("/home/a")),
            under,
            "empty is unset"
        );
        assert_eq!(humans_dir_from(None, os("")), None);
        assert_eq!(humans_dir_from(None, None), None);
        let env = |n| std::env::var_os(n);
        assert_eq!(
            humans_dir(),
            humans_dir_from(env("LONCA_HUMANS"), env("HOME"))
        );
        assert!(humans_dir().is_some(), "tests run with HOME set");
    }

    #[test]
    fn a_name_can_not_lead_out_of_the_directory() {
        let dir = Path::new("/h");
        for bad in ["", "../x", "a/b", ".hidden", "a b", "é"] {
            let e = session_path(dir, bad).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::InvalidInput, "{bad}");
        }
        for good in ["ayse", "a.b_c-9", "A"] {
            assert!(session_path(dir, good).is_ok(), "{good}");
        }
    }
}
