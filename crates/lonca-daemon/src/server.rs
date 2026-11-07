//! Unix socket server: one thread per connection, one JSON line per request.
//! How many, for how long and how long a line: `crate::limits`.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::limits::{Counters, Held, Limits, Registry, Slot, head_of};
use crate::protocol::{Request, Response};
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

#[cfg(not(target_os = "linux"))]
pub use crate::peer_other::peer_in_sandbox;

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

/// How many pid namespaces a process of `status`, the text of
/// `/proc/<pid>/status`, lies in, as far as the reader can see.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn pid_namespaces(status: &str) -> usize {
    let line = status.lines().find_map(|l| l.strip_prefix("NSpid:"));
    line.map_or(0, |l| l.split_whitespace().count())
}

/// Whether the process that connected lies in a pid namespace below this
/// one, as bubblewrap's does: in a sandbox, not in this one. The same user can
/// make such a namespace, and nothing on one account can prove otherwise
/// (`docs/design.md` §3.1).
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
    serve_with(listener, svc, Access::default(), Limits::default())
}

/// How long to wait after a failed `accept`: with no descriptors left it
/// fails at once, every time.
const ACCEPT_PAUSE: Duration = Duration::from_millis(20);

/// `accept` itself never waits for a client, so nothing a client does can
/// stop the next one being let in.
pub fn serve_with(listener: UnixListener, svc: Arc<Service>, access: Access, limits: Limits) {
    let registry = Registry::new(limits);
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            std::thread::sleep(ACCEPT_PAUSE);
            continue;
        };
        let uid = peer_uid(&stream);
        if let Some(allowed) = &access.allowed_uids
            && !uid.is_some_and(|u| allowed.contains(&u))
        {
            continue; // dropped: closes the connection
        }
        let stream = Arc::new(stream);
        // A uid unknown to the system is one more client, not a free pass.
        let Some((slot, evicted)) = registry.admit(uid.unwrap_or(u32::MAX), stream.clone()) else {
            Counters::add(&svc.counters.busy);
            let full = "the daemon has no room for another connection";
            let _ = write_by(&stream, &Response::err(0, "busy", full), ACCEPT_WRITE);
            continue;
        };
        if evicted {
            Counters::add(&svc.counters.evicted);
        }
        let svc = svc.clone();
        let _ = std::thread::Builder::new().spawn(move || {
            let _ = handle_conn(&stream, &slot, &svc);
        });
    }
}

/// A refusal is one short line into an empty buffer, but `accept` must
/// not depend on that.
const ACCEPT_WRITE: Duration = Duration::from_millis(100);

/// What a connection sent next.
enum Incoming {
    Line(String),
    /// The line was read and thrown away; the connection goes on.
    Refused(Response),
    End,
    /// Nothing came in time; `started`: in the middle of a line.
    TimedOut {
        started: bool,
    },
}

/// One line, under the connection's limits. A refused line is read to its
/// end, so the client, still writing, gets to read why.
fn read_request(
    r: &mut BufReader<&UnixStream>,
    held: &mut Held,
    limits: &Limits,
    svc: &Service,
) -> std::io::Result<Incoming> {
    let stream = *r.get_ref();
    let mut buf = Vec::new();
    let mut id = 0;
    let mut long = false;
    let mut refused = None;
    let mut deadline = None;
    loop {
        let wait = deadline.map_or(limits.idle, |d: Instant| {
            d.saturating_duration_since(Instant::now())
        });
        if wait.is_zero() {
            return Ok(Incoming::TimedOut { started: true });
        }
        // Fails only on macOS once the client is gone, and then no read waits:
        // what it wrote before leaving is still there to read.
        let _ = stream.set_read_timeout(Some(wait));
        let chunk = match r.fill_buf() {
            Ok(chunk) => chunk,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                let started = deadline.is_some();
                return Ok(Incoming::TimedOut { started });
            }
            Err(e) => return Err(e),
        };
        if chunk.is_empty() {
            return Ok(match refused {
                Some(why) => Incoming::Refused(why),
                None if buf.is_empty() => Incoming::End,
                None => Incoming::Line(String::from_utf8_lossy(&buf).into_owned()),
            });
        }
        deadline.get_or_insert_with(|| Instant::now() + limits.line);
        let newline = chunk.iter().position(|&b| b == b'\n');
        let n = newline.unwrap_or(chunk.len());
        if refused.is_none() {
            buf.extend_from_slice(&chunk[..n]);
        }
        r.consume(n + usize::from(newline.is_some()));
        if refused.is_none() && buf.len() > limits.short_line {
            if !long {
                let head = head_of(&buf[..limits.short_line]);
                id = head.id;
                match svc.long_line(&head) {
                    Ok(()) => long = true,
                    Err((code, msg)) => refused = Some(Response::err(id, &code, msg)),
                }
            }
            if long && buf.len() > limits.long_line {
                let msg = format!("a request line holds at most {} bytes", limits.long_line);
                refused = Some(Response::err(id, "too_large", msg));
            } else if long && !held.grow(buf.len()) {
                let msg = "too many long requests at once; send it again";
                refused = Some(Response::err(id, "busy", msg));
            }
            if let Some(why) = &refused {
                Counters::add(match why.error.as_ref().map(|e| e.code.as_str()) {
                    Some("busy") => &svc.counters.busy,
                    _ => &svc.counters.too_large,
                });
                buf = Vec::new();
            }
        }
        if newline.is_some() {
            return Ok(match refused {
                Some(why) => Incoming::Refused(why),
                None => Incoming::Line(String::from_utf8_lossy(&buf).into_owned()),
            });
        }
    }
}

/// Writes one line by a deadline for all of it: a client that takes one byte
/// at a time gets no more time than one that takes none.
fn write_by(mut s: &UnixStream, v: &Response, limit: Duration) -> std::io::Result<()> {
    let mut bytes = serde_json::to_vec(v)?;
    bytes.push(b'\n');
    let deadline = Instant::now() + limit;
    let mut left = &bytes[..];
    while !left.is_empty() {
        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return Err(ErrorKind::TimedOut.into());
        }
        let _ = s.set_write_timeout(Some(wait)); // as in `read_request`
        left = &left[s.write(left)?..];
    }
    Ok(())
}

/// The last line of a connection the daemon is closing on a client that may
/// be gone.
fn farewell(stream: &UnixStream, limits: &Limits, code: &str, msg: &str) {
    let _ = write_by(stream, &Response::err(0, code, msg), limits.write);
}

const NOT_READ: &str = "connection closed while quiet; this request was not run, send it again";

fn handle_conn(stream: &UnixStream, slot: &Slot, svc: &Service) -> std::io::Result<()> {
    let limits = slot.limits();
    let mut reader = BufReader::new(stream);
    loop {
        let mut held = slot.hold();
        let resp = match read_request(&mut reader, &mut held, limits, svc)? {
            Incoming::End if slot.evicted() => {
                farewell(stream, limits, "closed", NOT_READ);
                return Ok(());
            }
            Incoming::End => return Ok(()),
            Incoming::TimedOut { started: false } => {
                Counters::add(&svc.counters.idle);
                farewell(stream, limits, "closed", NOT_READ);
                return Ok(());
            }
            Incoming::TimedOut { started: true } => {
                Counters::add(&svc.counters.slow);
                farewell(stream, limits, "timeout", "the request line took too long");
                return Ok(());
            }
            Incoming::Refused(why) => why,
            Incoming::Line(line) if line.trim().is_empty() => continue,
            Incoming::Line(_) if !slot.begin() => {
                farewell(stream, limits, "closed", NOT_READ);
                return Ok(());
            }
            Incoming::Line(line) => match serde_json::from_str::<Request>(&line) {
                Ok(req) => svc.handle_from(req, &|| peer_in_sandbox(stream)),
                Err(e) => Response::err(0, "invalid", format!("bad request: {e}")),
            },
        };
        if let Err(e) = write_by(stream, &resp, limits.write) {
            Counters::add(&svc.counters.slow);
            return Err(e);
        }
        slot.end();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_response_nobody_reads_runs_out_of_time() {
        let (a, _b) = UnixStream::pair().unwrap();
        let big = Response::err(0, "x", "y".repeat(16 * 1024 * 1024));
        let started = Instant::now();
        let e = write_by(&a, &big, Duration::from_millis(100)).unwrap_err();
        assert!(matches!(
            e.kind(),
            ErrorKind::WouldBlock | ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_response_is_a_line() {
        use std::io::Read;
        let (a, mut b) = UnixStream::pair().unwrap();
        write_by(&a, &Response::err(3, "x", "y"), Duration::from_secs(5)).unwrap();
        drop(a);
        let mut text = String::new();
        b.read_to_string(&mut text).unwrap();
        let line = text.strip_suffix('\n').unwrap();
        assert_eq!(serde_json::from_str::<Response>(line).unwrap().id, 3);
    }

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
