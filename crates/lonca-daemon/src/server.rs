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

/// The pid of the process that connected.
#[cfg(target_os = "macos")]
fn peer_pid(s: &UnixStream) -> Option<libc::pid_t> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: fd is a valid socket; pid/len are live and sized correctly.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            &mut pid as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    (rc == 0).then_some(pid)
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn sandbox_check(pid: libc::pid_t, operation: *const libc::c_char, kind: i32, ...) -> i32;
}

/// Whether the process that connected is in a sandbox. Asked of the
/// operating system, since a token says nothing of where it is used.
///
/// A process that has exited also reads as sandboxed, and it can leave its
/// connection to a child, so it must be seen alive after that answer; a
/// zombie has no path. In a sandbox, not in this one: the same user can wrap
/// a process in a sandbox of its own, and nothing on one account can prove
/// otherwise (`docs/design.md` §3.1).
#[cfg(target_os = "macos")]
pub fn peer_in_sandbox(s: &UnixStream) -> bool {
    let Some(pid) = peer_pid(s) else {
        return false;
    };
    let mut path = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: a null operation with no filter asks whether `pid` is
    // sandboxed at all; `path` is live and its size is passed with it.
    unsafe {
        sandbox_check(pid, std::ptr::null(), 0) == 1
            && libc::proc_pidpath(pid, path.as_mut_ptr().cast(), path.len() as u32) > 0
    }
}

/// How many pid namespaces a process of `status`, the text of
/// `/proc/<pid>/status`, lies in, as far as the reader can see.
#[cfg(any(target_os = "linux", test))]
fn pid_namespaces(status: &str) -> usize {
    let line = status.lines().find_map(|l| l.strip_prefix("NSpid:"));
    line.map_or(0, |l| l.split_whitespace().count())
}

/// Linux: whether the process that connected lies in a pid namespace below
/// this one, as bubblewrap's does. See the macOS one for what this shows.
#[cfg(target_os = "linux")]
pub fn peer_in_sandbox(s: &UnixStream) -> bool {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: fd is a valid socket; cred/len are live and sized correctly.
    let rc = unsafe {
        libc::getsockopt(
            s.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    let status = |who: String| std::fs::read_to_string(format!("/proc/{who}/status")).ok();
    match (rc, status(cred.pid.to_string()), status("self".into())) {
        (0, Some(peer), Some(me)) => pid_namespaces(&peer) > pid_namespaces(&me),
        _ => false,
    }
}

/// Elsewhere there is no sandbox for `lonca run` to have made.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn peer_in_sandbox(_: &UnixStream) -> bool {
    false
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
            Ok(req) => svc.handle_from(req, &|| peer_in_sandbox(&writer)),
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
    fn a_test_process_is_in_no_sandbox() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert!(!peer_in_sandbox(&a));
    }

    #[test]
    fn namespaces_are_counted_from_the_status() {
        assert_eq!(pid_namespaces("Name:\tx\nNSpid:\t1234\nNSsid:\t1\n"), 1);
        assert_eq!(pid_namespaces("NSpid:\t1234\t2\n"), 2);
        assert_eq!(pid_namespaces("Name:\tx\n"), 0);
    }

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
