//! Where the peer of a socket runs, on what is not Linux. Apart from
//! `server.rs` because mutation testing runs on Linux, where none of this is
//! compiled: `.cargo/mutants.toml` leaves this file out, and the end-to-end
//! tests of `lonca run` hold it on macOS.

use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

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

/// Elsewhere there is no sandbox for `lonca run` to have made.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn peer_in_sandbox(_: &UnixStream) -> bool {
    false
}
