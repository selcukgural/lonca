//! Unix socket server: one thread per connection, one JSON line per request.

use std::io::BufReader;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;

use crate::protocol::{MAX_LINE, Request, Response, read_line_limited, write_line};
use crate::service::Service;

/// Longest socket path that fits `sockaddr_un` on every supported platform.
pub const MAX_SOCKET_PATH: usize = 100;

/// Socket access control. In hardened mode the daemon runs as its own
/// system user and lets the developer in through a group and a uid list.
#[derive(Clone, Debug)]
pub struct Access {
    pub mode: u32,
    pub group: Option<u32>,
    /// Peers whose uid is not listed are disconnected. `None`: anyone who
    /// can open the socket file.
    pub allowed_uids: Option<Vec<u32>>,
}

impl Default for Access {
    fn default() -> Self {
        Self {
            mode: 0o600,
            group: None,
            allowed_uids: None,
        }
    }
}

pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    bind_with(path, &Access::default())
}

pub fn bind_with(path: &Path, access: &Access) -> std::io::Result<UnixListener> {
    if path.as_os_str().len() > MAX_SOCKET_PATH {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "socket path {} is longer than {MAX_SOCKET_PATH} bytes; set LONCA_SOCKET to a shorter path",
                path.display()
            ),
        ));
    }
    if path.exists() {
        // A live daemon answers; a stale socket file does not.
        if UnixStream::connect(path).is_ok() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "a Lonca daemon is already running",
            ));
        }
        std::fs::remove_file(path)?;
    }
    let l = UnixListener::bind(path)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(access.mode))?;
    if let Some(gid) = access.group {
        std::os::unix::fs::chown(path, None, Some(gid))?;
    }
    Ok(l)
}

/// The uid of the process on the other end of a Unix socket.
pub fn peer_uid(s: &UnixStream) -> Option<u32> {
    let fd = s.as_raw_fd();
    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: fd is a valid socket for the lifetime of `s`; the out
        // pointers point to live stack variables.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        (rc == 0).then_some(uid)
    }
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: fd is a valid socket; cred/len are live and sized correctly.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        (rc == 0).then_some(cred.uid)
    }
}

/// Resolves a group name or number.
pub fn group_id(name: &str) -> Option<u32> {
    if let Ok(n) = name.parse() {
        return Some(n);
    }
    let c = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam reads a NUL-terminated string and returns a pointer
    // into static storage (or null); we copy the gid out immediately.
    let g = unsafe { libc::getgrnam(c.as_ptr()) };
    if g.is_null() {
        None
    } else {
        Some(unsafe { (*g).gr_gid })
    }
}

pub fn serve(listener: UnixListener, svc: Arc<Service>) {
    serve_with(listener, svc, Access::default())
}

pub fn serve_with(listener: UnixListener, svc: Arc<Service>, access: Access) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        if let Some(allowed) = &access.allowed_uids {
            match peer_uid(&stream) {
                Some(uid) if allowed.contains(&uid) => {}
                _ => continue, // dropped: closes the connection
            }
        }
        let svc = svc.clone();
        std::thread::spawn(move || {
            let _ = handle_conn(stream, &svc);
        });
    }
}

fn handle_conn(stream: UnixStream, svc: &Service) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    while let Some(line) = read_line_limited(&mut reader, MAX_LINE)? {
        if line.trim().is_empty() {
            continue;
        }
        let resp = match serde_json::from_str::<Request>(&line) {
            Ok(req) => svc.handle(req),
            Err(e) => Response::err(0, "invalid", format!("bad request: {e}")),
        };
        write_line(&mut writer, &resp)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_uid_is_ours() {
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        assert_eq!(peer_uid(&a), Some(me));
    }

    #[test]
    fn groups_resolve() {
        assert_eq!(group_id("0"), Some(0));
        assert!(group_id("wheel").is_some() || group_id("root").is_some());
        assert_eq!(group_id("no-such-group-lonca"), None);
    }
}
